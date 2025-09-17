from datetime import datetime
import datetime as dt
import json
import re
from lihil import Param, Route, Annotated, status
from lihil.plugins.premier import PremierPlugin
from premier import Throttler

from src.repo.models import User
from src.crypto_utils.password_hasher import PasswordHasher
from src.crypto_utils.session_crypto import SessionCryptoUtils
from src.api.http_errors import InternalError
from src.services.user_service import UserService
from src.repo.redis_manager import SessionDAO
from src.utils.coder import CustomJSONEncoder, plain_text_decoder

auth = Route("auth", deps=[UserService, SessionDAO])

plugin = PremierPlugin(throttler=Throttler())


@auth.sub("login").post(plugins=[plugin.fix_window(10, 1)])
async def login(
    user_service: UserService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    login_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[str, status.OK]:
    """用户登录"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        login_data, master_key
    )
    if not valid:
        raise InternalError("Invalid timestamp")
    data_json = json.loads(decrypted_data)
    email = data_json.get("email")
    password = data_json.get("password")
    if not email or not password:
        raise InternalError("Email and password are required")
    user_is_valid, user = await user_service.authenticate_user(email, password)
    if user_is_valid and user is not None:
        newest_login_history = await user_service.get_newest_login_history(user.Id)
        await user_service.update_user(
            user.Id,
            last_login_at=(
                newest_login_history.LoginTime if newest_login_history else None
            ),
        )
        await user_service.add_login_history(
            user.Id,
            data_json.get("deviceFingerprint"),
            data_json.get("ipAddress"),
            data_json.get("userAgent"),
        )
        session.UserId = str(user.Id)
        session.CreatedAt = datetime.now()
        session.ExpiredAt = datetime.now() + dt.timedelta(hours=1)
        await session_dao.set_session(session)
    else:
        user = None
    response = {
        "status": "success" if user_is_valid else "error",
        "userId": str(user.Id) if user is not None else None,
    }
    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response, cls=CustomJSONEncoder), session.MasterKey
    )


@auth.sub("register").post(plugins=[plugin.fix_window(5, 1)])
async def register(
    user_service: UserService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    register_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[str, status.OK]:
    """用户注册"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        register_data, master_key
    )
    if not valid:
        raise InternalError("Invalid timestamp")

    data_json = json.loads(decrypted_data)
    email = data_json.get("email")
    password = data_json.get("password")
    public_key = data_json.get("publicKey")

    if not email or not password or not public_key:
        raise InternalError("Email, password and public key are required")

    existing_user = await user_service.get_user_by_email(email)
    if existing_user:
        response = {"status": "error", "message": "Email already exists"}
    else:
        hasher = PasswordHasher()
        password_hash = hasher.hash_password(password)
        print(len(password_hash), password_hash)
        user = User(
            Email=email,
            PasswordHash=password_hash,
            PublicKey=public_key,
            CreatedAt=datetime.now(),
        )
        await user_service.register_user(user)
        response = {"status": "success"}

    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response, cls=CustomJSONEncoder), master_key
    )


@auth.sub("check-email").post(plugins=[plugin.fix_window(10, 1)])
async def check_email(
    user_service: UserService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    check_email_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[str, status.OK]:
    """检查邮箱是否已注册"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        check_email_data, master_key
    )
    if not valid:
        raise InternalError("Invalid timestamp")

    data_json = json.loads(decrypted_data)
    email = data_json.get("email")

    if not email:
        raise InternalError("Email is required")

    if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is None:
        response = {"status": "error", "message": "Invalid email format"}
    else:
        user = await user_service.get_user_by_email(email)
        response = {
            "status": "ok" if not user else "error",
            "message": "User already exists" if user else "",
        }

    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response, cls=CustomJSONEncoder), master_key
    )
