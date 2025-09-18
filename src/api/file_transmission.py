from io import BytesIO
import json
from pathlib import Path
import shutil
import uuid
from lihil import Param, Route, Annotated, status, Form
from lihil.plugins.premier import PremierPlugin
from premier import Throttler
import aiofiles
from uuid import UUID
from starlette.responses import StreamingResponse

from src.services.review_service import ReviewService
from src.crypto_utils.crypto import CryptoUtils
from src.services.user_service import UserService
from src.repo.redis_manager import SessionDAO, UploadSessionDAO
from src.crypto_utils.session_crypto import SessionCryptoUtils
from src.repo.models import ReviewStage, UploadSession
from src.api.dto_models import UploadChunkForm
from src.api.http_errors import InternalError
from src.utils.parser import get_mime_type


download = Route("download", deps=[UserService, SessionDAO, ReviewService])
upload = Route(
    "upload", deps=[UserService, SessionDAO, UploadSessionDAO, ReviewService]
)

TEMP_UPLOAD_ROOT = Path("tempuploads")
TEMP_UPLOAD_ROOT.mkdir(exist_ok=True)

plugin = PremierPlugin(throttler=Throttler())


@upload.sub("init").post(plugins=[plugin.fix_window(10, 1)])
async def init_upload(
    user_service: UserService,
    session_dao: SessionDAO,
    upload_session_dao: UploadSessionDAO,
    upload_init_data: Annotated[str, Param("body", decoder=lambda b: b.decode())],
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> Annotated[str, status.OK]:
    session = await session_dao.get_session(session_id)
    if not session is not None or not session.UserId or not session.MasterKey:
        raise InternalError("Authentication required")
    user = await user_service.get_user_by_id(uuid.UUID(session.UserId))
    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        upload_init_data, session.MasterKey
    )
    data_json = json.loads(decrypted_data)
    if (
        not valid
        or not user
        or not CryptoUtils.verify_data_without_signature(
            data_json.get("SignatureString"), user.PublicKey
        )
    ):
        raise InternalError("Invalid Authentication Info")
    upload_session = UploadSession(TextData=decrypted_data)
    await upload_session_dao.set_session(upload_session)
    return SessionCryptoUtils.append_timestamp_and_encrypt(
        upload_session.Id, session.MasterKey
    )


@upload.sub("confirm").post(plugins=[plugin.fix_window(10, 1)])
async def upload_confirm(
    session_dao: SessionDAO,
    upload_session_dao: UploadSessionDAO,
    confirm_data: Annotated[str, Param("body", decoder=lambda b: b.decode())],
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> Annotated[str, status.OK]:
    """确认上传会话"""
    session = await session_dao.get_session(session_id)
    if not session or not session.MasterKey:
        raise InternalError("Authentication required")

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        confirm_data, session.MasterKey
    )
    if not valid:
        raise InternalError("Invalid timestamp or authentication")

    data_json = json.loads(decrypted_data)
    upload_id = data_json.get("uploadId")
    chunk_num = data_json.get("chunkNum")

    if not upload_id or not chunk_num:
        raise InternalError("Missing uploadId or chunkNum")

    upload_session = await upload_session_dao.get_session(upload_id)
    if not upload_session:
        raise InternalError("No upload session found")

    upload_session.ChunkNums = int(chunk_num)
    await upload_session_dao.set_session(upload_session)

    return "success"


@upload.sub("chunk").post(plugins=[plugin.fix_window(20, 1)])
async def upload_chunk(
    session_dao: SessionDAO,
    upload_session_dao: UploadSessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    upload_id: Annotated[str, Param("header", alias="Upload-Id")],
    chunk_data: Annotated[UploadChunkForm, Form()],
) -> Annotated[str, status.OK]:
    """上传文件分片"""
    session = await session_dao.get_session(session_id)
    upload_session = await upload_session_dao.get_session(upload_id)

    if not session or not upload_session:
        raise InternalError("Invalid session")

    try:
        chunk_index = int(chunk_data.index)
        if (
            upload_session.ChunkNums is not None
            and chunk_index >= upload_session.ChunkNums
        ):
            raise InternalError("Invalid chunk index")

        upload_dir = TEMP_UPLOAD_ROOT / upload_id
        upload_dir.mkdir(exist_ok=True, parents=True)

        chunk_path = upload_dir / f"{chunk_index:06d}.chunk"
        async with aiofiles.open(chunk_path, "wb") as f:
            await f.write(chunk_data.chunk.file.read())

        upload_session.Processed += 1
        await upload_session_dao.set_session(upload_session)
        return "success"

    except ValueError:
        raise InternalError("Invalid chunk index format")
    except Exception as e:
        raise InternalError(f"Chunk upload failed: {str(e)}")


@upload.sub("complete").get(plugins=[plugin.fix_window(10, 1)])
async def complete_upload(
    session_dao: SessionDAO,
    upload_session_dao: UploadSessionDAO,
    review_service: ReviewService,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    upload_id: Annotated[str, Param("header", alias="Upload-Id")],
) -> Annotated[str, status.OK]:
    """完成上传并合并文件"""
    session = await session_dao.get_session(session_id)
    upload_session = await upload_session_dao.get_session(upload_id)

    if not session or not upload_session:
        raise InternalError("Invalid session")

    if upload_session.Processed != upload_session.ChunkNums:
        raise InternalError("Chunk count mismatch")

    upload_dir = TEMP_UPLOAD_ROOT / upload_id
    if not upload_dir.exists():
        raise InternalError("No chunks found for this upload")

    try:
        merged_file_path = upload_dir / "merged_file"
        await merge_chunks(upload_dir, merged_file_path)

        async with aiofiles.open(merged_file_path, "rb") as f:
            file_bytes = await f.read()

        file_hash = CryptoUtils.compute_data_hash(BytesIO(file_bytes))
        data_json = json.loads(upload_session.TextData)
        encrypted_hash = data_json.get("EncryptedDataHash")

        if not encrypted_hash or file_hash != encrypted_hash:
            raise InternalError("Hash validation failed")

        review_stage = ReviewStage(
            PublisherId=uuid.UUID(data_json["PublisherId"]),
            PublisherName=data_json.get("PublisherName"),
            BelongId=uuid.UUID(data_json["BelongId"]),
            Type=data_json["Type"],
            AuthorizedIds=data_json.get("AuthorizedIds", []),
            EncryptedKeys=data_json.get("EncryptedKeys", []),
            PassRecord=[],
            EncryptedData=file_bytes,
            SignatureString=data_json["SignatureString"],
            OriginDataHash=data_json["OriginDataHash"],
            EncryptedDataHash=encrypted_hash,
        )

        await review_service.add_stage_async(review_stage)
        await upload_session_dao.del_session(upload_id)
        shutil.rmtree(upload_dir, ignore_errors=True)

        return "success"
    except Exception as e:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise InternalError(f"Upload completion failed: {str(e)}")


@download.sub("dc").post(plugins=[plugin.fix_window(10, 1)])
async def download_file(
    user_service: UserService,
    review_service: ReviewService,
    session_dao: SessionDAO,
    dc_data: Annotated[str, Param("body", decoder=lambda b: b.decode())],
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> StreamingResponse:
    """下载文件"""
    session = await session_dao.get_session(session_id)
    if not session or not session.MasterKey or not session.UserId:
        raise InternalError("Invalid session")

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        dc_data, session.MasterKey
    )
    if not valid:
        raise InternalError("Invalid timestamp")

    data_json = json.loads(decrypted_data)
    signature = data_json.get("SignatureString")
    stage_id_str = data_json.get("StageId")

    if not signature or not stage_id_str:
        raise InternalError("Missing signature or stageId")

    user = await user_service.get_user_by_id(UUID(session.UserId))
    if not user:
        raise InternalError("User not found")

    signature_is_valid = CryptoUtils.verify_data_without_signature(
        signature, user.PublicKey
    )
    if not signature_is_valid:
        raise InternalError("Invalid signature")

    has_access = await review_service.has_access_right(
        UUID(session.UserId), UUID(stage_id_str)
    )
    if not has_access:
        raise InternalError("Access denied")

    file_data = await review_service.get_file_data(UUID(stage_id_str))
    if not file_data or not file_data.EncryptedData:
        raise InternalError("File data not found")

    try:
        user_index = file_data.AuthorizedIds.index(UUID(session.UserId))
        encrypted_key = file_data.EncryptedKeys[user_index]
    except (ValueError, IndexError):
        raise InternalError("Access key not found")

    file_extension = file_data.Type.lower() if file_data.Type else "bin"

    async def file_iterator(data: bytes, chunk_size: int = 8192):
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]

    response = StreamingResponse(file_iterator(file_data.EncryptedData))
    response.headers["Content-Disposition"] = (
        f'attachment; filename="file.{file_extension}"'
    )
    response.headers["Content-Type"] = get_mime_type(file_extension)
    response.headers["Encrypted-Key"] = encrypted_key
    response.headers["EncryptedDataHash"] = file_data.EncryptedDataHash or ""
    response.headers["OriginDataHash"] = file_data.OriginDataHash or ""
    response.headers["X-File-Size"] = str(len(file_data.EncryptedData))

    return response


async def merge_chunks(chunk_dir: Path, output_path: Path) -> None:
    """合并分片文件"""
    chunk_files = sorted(
        [f for f in chunk_dir.glob("*.chunk") if f.is_file()], key=lambda x: int(x.stem)
    )
    async with aiofiles.open(output_path, "wb") as output_file:
        for chunk_file in chunk_files:
            async with aiofiles.open(chunk_file, "rb") as chunk:
                content = await chunk.read()
                await output_file.write(content)
