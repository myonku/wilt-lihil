import json
from typing import Any
from uuid import UUID
from lihil import Form, Param, Route, Annotated, status
from lihil.plugins.premier import PremierPlugin
from premier import Throttler

from src.api.dto_models import AvatarUploadForm

from src.services.review_service import ReviewService
from src.crypto_utils.session_crypto import SessionCryptoUtils
from src.api.http_errors import InternalError
from src.services.user_service import UserService
from src.repo.redis_manager import SessionDAO
from src.utils.coder import CustomJSONEncoder, plain_text_decoder


user = Route("user", deps=[UserService, SessionDAO, ReviewService])

plugin = PremierPlugin(throttler=Throttler())


@user.sub("allUsers").get(plugins=[plugin.fix_window(10, 1)])
async def get_all_users(
    user_service: UserService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> Annotated[str, status.OK]:
    """获取所有用户"""
    session = await session_dao.get_session(session_id)
    if not session is not None or not session.UserId or not session.MasterKey:
        raise InternalError("Authentication required")
    users = await user_service.get_other_users(UUID(session.UserId))
    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(users, cls=CustomJSONEncoder), session.MasterKey
    )


@user.sub("getUserInfo").post(plugins=[plugin.fix_window(10, 1)])
async def get_user_info(
    user_service: UserService,
    session_dao: SessionDAO,
    request_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> Annotated[str, status.OK]:
    """获取用户信息"""
    session = await session_dao.get_session(session_id)
    if not session or not session.MasterKey:
        raise InternalError("Authentication required")

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request_data, session.MasterKey
    )
    if not valid:
        raise InternalError("Invalid timestamp")
    data_json = json.loads(decrypted_data)
    user_id = data_json.get("userId")
    if not user_id:
        raise InternalError("User ID required")
    user = await user_service.get_user_by_id(UUID(user_id))
    if not user:
        raise InternalError("User not found")
    user_data = {
        "Name": user.Name,
        "Email": user.Email,
        "AlterName": user.AlterName,
        "PhoneNumber": user.PhoneNumber,
        "AccountStatus": user.AccountStatus.name,
        "Role": user.Role.name,
        "LastUpdatePasswordAt": user.LastUpdatePasswordAt,
        "LastUpdateKeyAt": user.LastUpdateKeyAt,
        "CreatedAt": user.CreatedAt,
        "LastLoginAt": user.LastLoginAt,
        "UpdatedAt": user.UpdatedAt,
    }
    encrypted_data = SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(user_data, cls=CustomJSONEncoder), session.MasterKey
    )

    return encrypted_data


@user.sub("getAvatar").get(plugins=[plugin.fix_window(10, 1)])
async def get_avatar(
    file_service: ReviewService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> Annotated[Any, status.OK]:
    """获取用户头像"""
    session = await session_dao.get_session(session_id)
    if not session or not session.UserId:
        raise InternalError("Invalid session")

    profile = await file_service.get_avatar_by_id_async(UUID(session.UserId))

    if profile and profile.Data and profile.Type:
        import base64

        base64_data = base64.b64encode(profile.Data).decode("utf-8")
        return {"status": "success", "data": base64_data, "type": profile.Type}
    else:
        return {"status": "success", "data": "", "type": ""}


@user.sub("updateAvatar").post(plugins=[plugin.fix_window(5, 1)])
async def update_avatar(
    file_service: ReviewService,
    session_dao: SessionDAO,
    request: AvatarUploadForm,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> Annotated[str, status.OK]:
    """更新用户头像"""
    if not request.Avatar or not request.Data or not request.Type:
        raise InternalError("Invalid upload data")

    session = await session_dao.get_session(session_id)
    if not session or not session.MasterKey:
        raise InternalError("Authentication required")

    valid, user_id = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request.Data, session.MasterKey
    )
    if not valid:
        raise InternalError("Invalid timestamp")

    file_bytes = await request.Avatar.read()
    await file_service.update_avatar_async(UUID(user_id), file_bytes, request.Type)

    response = {"status": "success"}
    encrypted_data = SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response, cls=CustomJSONEncoder), session.MasterKey
    )

    return encrypted_data


@user.sub("getAccountInfo").post(plugins=[plugin.fix_window(10, 1)])
async def get_account_info(
    user_service: UserService,
    file_service: ReviewService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> Annotated[str, status.OK]:
    """获取账户信息"""
    session = await session_dao.get_session(session_id)
    if not session or not session.MasterKey:
        raise InternalError("Invalid session")

    user_id = UUID(session.UserId)
    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise InternalError("User does not exist")

    login_count = await user_service.get_login_history_in_week_count(user_id)
    last_history = await user_service.get_last_login_history(user_id)

    last_login_time = last_history.LoginTime if last_history else None
    ip_address = last_history.IPAddress if last_history else ""
    user_agent = last_history.UserAgent if last_history else ""

    last_update_pwd = user.LastUpdatePasswordAt
    recent_submit = await file_service.get_all_flow_stage_by_flow_id(user_id)
    recent_reviews_count = await file_service.get_all_reviews_count_by_user_flows_async(
        user.Id
    )

    device = parse_user_agent(user_agent) if user_agent else ""
    device_info = f"{device} | {ip_address}" if last_history else ""

    state_count = await file_service.get_all_stage_count_by_user_id_async(user_id)
    flow_count = await file_service.get_all_flows_count_by_user_id_async(user_id)

    account_data = {
        "lastLogin": last_login_time,
        "lastLoginDevice": device_info,
        "recentLoginActivity": login_count,
        "recentSubmitStage": recent_submit,
        "lastPasswordUpdate": last_update_pwd,
        "newApprovalResult": recent_reviews_count,
        "finishedWorkflow": flow_count,
        "participatedStage": state_count,
    }
    encrypted_data = SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(account_data, cls=CustomJSONEncoder), session.MasterKey
    )

    return encrypted_data


@user.sub("publicKey").post(plugins=[plugin.fix_window(10, 1)])
async def get_public_key(
    user_service: UserService,
    session_dao: SessionDAO,
    request_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
    session_id: Annotated[str, Param("header", alias="Session-Id")],
) -> Annotated[str, status.OK]:
    """获取用户公钥"""
    session = await session_dao.get_session(session_id)
    if not session or not session.MasterKey:
        raise InternalError("Authentication required")
    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request_data, session.MasterKey
    )
    if not valid:
        raise InternalError("Invalid timestamp")

    data_json = json.loads(decrypted_data)
    user_id = data_json.get("userId")
    if not user_id:
        raise InternalError("User ID required")
    user = await user_service.get_user_by_id(UUID(user_id))
    if not user:
        raise InternalError("User not found")

    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(
            {
                "publicKey": user.PublicKey,
                "userId": user.Id,
                "userName": user.Name,
            },
            cls=CustomJSONEncoder,
        ),
        session.MasterKey,
    )


def parse_user_agent(user_agent: str) -> str:
    """解析用户代理字符串"""
    if "Windows" in user_agent:
        return "Windows"
    elif "Mac" in user_agent:
        return "Mac"
    elif "Linux" in user_agent:
        return "Linux"
    elif "Android" in user_agent:
        return "Android"
    elif "iPhone" in user_agent:
        return "iPhone"
    else:
        return "Unknown Device"
