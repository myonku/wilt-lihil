from datetime import datetime
import datetime as dt
import json
import uuid
from lihil import Param, Route, Annotated, status
from lihil.plugins.premier import PremierPlugin
from premier import Throttler
import base64

from src.crypto_utils.crypto import CryptoUtils
from src.services.user_service import UserService
from src.services.secret_key_service import ServerSecretKeyService
from src.repo.redis_manager import SessionDAO
from src.crypto_utils.session_crypto import SessionCryptoUtils
from src.repo.models import Session
from src.api.dto_models import HandShakeInitDTO, EncryptedDataDTO
from src.api.http_errors import InternalError

handshake = Route("handshake", deps=[UserService, SessionDAO])

plugin = PremierPlugin(throttler=Throttler())


@handshake.sub("init").post(plugins=[plugin.fix_window(10, 1)])
async def init_handshake(
    cache: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    init_data: Annotated[HandShakeInitDTO, Param("body")],
) -> Annotated[dict[str, str], status.OK]:
    """初始握手"""
    clientRandomBytes = base64.b64decode(init_data.clientRandom)
    serverRandomBytes = SessionCryptoUtils.generate_random(16)
    session = Session(
        SessionId=session_id,
        CreatedAt=datetime.now(),
        ExpiredAt=datetime.now() + dt.timedelta(hours=1),
        ServerRandom=serverRandomBytes,
        ClientRandom=clientRandomBytes,
    )
    await cache.set_session(session)
    server_public_key = ServerSecretKeyService.get_public_key()
    return {
        "serverPublicKey": server_public_key,
        "serverRandom": base64.b64encode(serverRandomBytes).decode("utf-8"),
    }


@handshake.sub("confirm").post(plugins=[plugin.fix_window(10, 1)])
async def confirm_handshake(
    cache: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    confirm_data: Annotated[EncryptedDataDTO, Param("body")],
) -> Annotated[str, status.OK]:
    """确认请求"""
    session = await cache.get_session(session_id)
    if not session:
        raise InternalError("Session not found")

    encrypted_data = confirm_data.data
    server_private_key = ServerSecretKeyService.get_private_key()
    decrypted = CryptoUtils.decrypt_string_with_private_key(
        encrypted_data, server_private_key
    )
    timestamp, origin_data = CryptoUtils.extract_timestamp(decrypted)
    if not CryptoUtils.validate_timestamp(timestamp):
        raise InternalError("Invalid timestamp")
    data = json.loads(str(origin_data))
    client_random_base64 = data.get("clientRandom")
    if not client_random_base64:
        raise InternalError("Missing clientRandom in data")

    client_random_bytes = base64.b64decode(client_random_base64)

    if not session.ClientRandom or not client_random_bytes == session.ClientRandom:
        raise InternalError("Invalid client data")

    # 生成临时ECDH密钥对（P-256曲线）
    eph_pub, eph_priv = SessionCryptoUtils.generate_ecdh_key_pair()

    session.ServerEcdhPublicKey = eph_pub.encode("utf-8")
    session.ServerEcdhPrivateKey = eph_priv
    session.ExpiredAt = datetime.now() + dt.timedelta(hours=1)

    await cache.set_session(session)

    response_string = json.dumps({"EphPublicKey": eph_pub})
    response_with_timestamp = CryptoUtils.append_timestamp(response_string)
    signature = CryptoUtils.sign_origin_data(
        response_with_timestamp, ServerSecretKeyService.get_private_key()
    )
    signatured_data = CryptoUtils.append_signature(response_with_timestamp, signature)

    return str(signatured_data)


@handshake.sub("establish").post(plugins=[plugin.fix_window(10, 1)])
async def establish_session(
    cache: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    establish_data: Annotated[EncryptedDataDTO, Param("body")],
) -> Annotated[str, status.OK]:
    """建立会话"""
    session = await cache.get_session(session_id)
    if not session:
        raise InternalError("Session not found")

    encrypted_data = establish_data.data
    server_private_key = ServerSecretKeyService.get_private_key()

    decrypted = CryptoUtils.decrypt_string_with_private_key(
        encrypted_data, server_private_key
    )
    timestamp, client_eph_pub = CryptoUtils.extract_timestamp(decrypted)
    if not CryptoUtils.validate_timestamp(timestamp):
        raise InternalError("Invalid timestamp")

    session.ClientEcdhPublicKey = str(client_eph_pub).encode("utf-8")

    server_eph_priv = session.ServerEcdhPrivateKey
    if not server_eph_priv:
        raise InternalError("ECDH keys not found in session")
    pre_master = SessionCryptoUtils.compute_ecdh_shared_secret(
        server_eph_priv, str(client_eph_pub)
    )
    client_random = session.ClientRandom
    if not client_random:
        raise InternalError("Client random not found in session")
    # 生成主密钥（HKDF-SHA256）
    master_key = SessionCryptoUtils.derive_master_secret(
        pre_master, client_random, session.ServerRandom
    )
    new_session_id = str(uuid.uuid4())

    session.MasterKey = master_key
    session.SessionId = new_session_id
    session.CreatedAt = datetime.now()
    session.ExpiredAt = datetime.now() + dt.timedelta(hours=1)

    await cache.set_session(session)

    data_string = json.dumps({"SessionId": new_session_id})
    data_with_timestamp = CryptoUtils.append_timestamp(data_string)

    encrypted_response = SessionCryptoUtils.encrypt_string_with_master_key(
        str(data_with_timestamp), master_key
    )

    return encrypted_response


@handshake.sub("complete").post(plugins=[plugin.fix_window(10, 1)])
async def complete_handshake(
    cache: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    complete_data: Annotated[EncryptedDataDTO, Param("body")],
) -> Annotated[str, status.OK]:
    """最终确认"""
    session = await cache.get_session(session_id)
    if not session or not session.MasterKey:
        raise InternalError("Session not found or not established")

    encrypted_data = complete_data.data
    master_key = session.MasterKey

    decrypted = SessionCryptoUtils.decrypt_string_with_master_key(
        encrypted_data, master_key
    )
    timestamp, origin_data_string = CryptoUtils.extract_timestamp(decrypted)
    if not CryptoUtils.validate_timestamp(timestamp):
        raise InternalError("Invalid timestamp")

    data = json.loads(str(origin_data_string))
    client_random_base64 = data.get("clientRandomA")
    client_session_id = data.get("sessionId")

    if not client_random_base64 or not client_session_id:
        raise InternalError("Missing required fields in data")

    client_random_bytes = base64.b64decode(client_random_base64)
    if (
        client_session_id != session.SessionId
        or not client_random_bytes == session.ClientRandom
    ):
        raise InternalError("Invalid client data")

    response = json.dumps({"status": "ESTABLISHED"})
    response_with_timestamp = CryptoUtils.append_timestamp(response)

    encrypted_response = SessionCryptoUtils.encrypt_string_with_master_key(
        str(response_with_timestamp), master_key
    )

    session.CreatedAt = datetime.now()
    session.ExpiredAt = datetime.now() + dt.timedelta(hours=1)
    await cache.set_session(session)

    return encrypted_response
