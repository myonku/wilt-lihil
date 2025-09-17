import json
from typing import Any
from uuid import UUID
from lihil import Param, Route, Annotated, status
from lihil.plugins.premier import PremierPlugin
from premier import Throttler

from src.repo.models import Review, ReviewFlow
from src.services.review_service import ReviewService
from src.crypto_utils.crypto import CryptoUtils
from src.api.http_errors import InternalError
from src.crypto_utils.session_crypto import SessionCryptoUtils
from src.utils.coder import CustomJSONEncoder, plain_text_decoder
from src.services.user_service import UserService
from src.repo.redis_manager import SessionDAO


review = Route("review", deps=[UserService, SessionDAO, ReviewService])

plugin = PremierPlugin(throttler=Throttler())


@review.sub("createFlow").post(plugins=[plugin.fix_window(10, 1)])
async def create_review_flow(
    user_service: UserService,
    review_service: ReviewService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    create_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[Any, status.OK]:
    """创建评审流"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey
    user = (
        await user_service.get_user_by_id(UUID(session.UserId))
        if session.UserId
        else None
    )
    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        create_data, master_key
    )
    if not valid or not user:
        raise InternalError("Invalid timestamp or authentication")

    data_json = json.loads(decrypted_data)
    pubKey = user.PublicKey
    signature_is_valid = CryptoUtils.verify_data_without_signature(
        data_json.get("SignatureString"), pubKey
    )
    response = {"status": "success" if signature_is_valid else "error"}
    if signature_is_valid:
        flow = ReviewFlow(
            Description=data_json.get("Description"),
            PublisherName=user.Name,
            OwnerId=user.Id,
            SignatureString=data_json.get("SignatureString"),
            Title=data_json.get("Title"),
        )
        await review_service.add_flow_async(flow)
    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response, cls=CustomJSONEncoder), session.MasterKey
    )


@review.sub("getFlow").post(plugins=[plugin.fix_window(10, 1)])
async def get_review_flow(
    review_service: ReviewService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    request_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[Any, status.OK]:
    """获取用户的评审流"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    valid, _ = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request_data, master_key
    )
    if not valid or not session.UserId:
        raise InternalError("Invalid timestamp or authentication")

    flows = await review_service.get_flow_by_user_id(UUID(session.UserId))
    response_data = [flow.model_dump() for flow in flows] if flows else []

    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response_data), master_key
    )


@review.sub("getStage").post(plugins=[plugin.fix_window(10, 1)])
async def get_review_stage(
    review_service: ReviewService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    request_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[Any, status.OK]:
    """获取用户的评审阶段"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    valid, _ = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request_data, master_key
    )
    if not valid or not session.UserId:
        raise InternalError("Invalid timestamp or authentication")

    stages = await review_service.get_stage_by_user_id(UUID(session.UserId))
    response_data = [stage.model_dump() for stage in stages] if stages else []

    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response_data, cls=CustomJSONEncoder), master_key
    )


@review.sub("stages").post(plugins=[plugin.fix_window(10, 1)])
async def get_flow_stages(
    review_service: ReviewService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    request_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[Any, status.OK]:
    """根据流程ID获取所有阶段"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request_data, master_key
    )
    if not valid or not session.UserId:
        raise InternalError("Invalid timestamp or authentication")

    flow_id = decrypted_data
    stages = await review_service.get_all_flow_stage_by_flow_id(UUID(flow_id))
    response_data = [stage.model_dump() for stage in stages] if stages else []

    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response_data, cls=CustomJSONEncoder), master_key
    )


@review.sub("reviews").post(plugins=[plugin.fix_window(10, 1)])
async def get_stage_reviews(
    review_service: ReviewService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    request_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[Any, status.OK]:
    """根据阶段ID获取评审记录"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request_data, master_key
    )
    if not valid or not session.UserId:
        raise InternalError("Invalid timestamp or authentication")

    stage_id = decrypted_data
    reviews = await review_service.get_review_by_stage_id(UUID(stage_id))
    response_data = [review.model_dump() for review in reviews] if reviews else []

    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(response_data, cls=CustomJSONEncoder), master_key
    )


@review.sub("addReview").post(plugins=[plugin.fix_window(10, 1)])
async def add_review(
    user_service: UserService,
    review_service: ReviewService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    request_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[None, status.OK]:
    """添加评审记录"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request_data, master_key
    )
    if not valid or not session.UserId:
        raise InternalError("Invalid timestamp or authentication")

    user = await user_service.get_user_by_id(UUID(session.UserId))
    if not user:
        raise InternalError("User not found")

    data_json = json.loads(decrypted_data)
    signature = data_json.get("SignatureString")

    signature_is_valid = CryptoUtils.verify_data_without_signature(
        signature, user.PublicKey
    )
    if not signature_is_valid:
        raise InternalError("签名验证失败")

    review = Review(
        PublisherName=data_json.get("PublisherName"),
        PublisherId=user.Id,
        Content=data_json.get("Content"),
        BelongId=UUID(data_json["BelongId"]),
        FinalBelongId=UUID(data_json["FinalBelongId"]),
        IsPassed=bool(data_json["IsPassed"]),
        SignatureString=signature,
    )
    await review_service.set_stage_record(review.BelongId, review.IsPassed)
    await review_service.add_review(review)

    return


@review.sub("preUpload").post(plugins=[plugin.fix_window(10, 1)])
async def pre_upload(
    user_service: UserService,
    session_dao: SessionDAO,
    session_id: Annotated[str, Param("header", alias="Session-Id")],
    request_data: Annotated[str, Param("body", decoder=plain_text_decoder)],
) -> Annotated[Any, status.OK]:
    """预上传验证"""
    session = await session_dao.get_session(session_id)
    assert session is not None and session.MasterKey is not None
    master_key = session.MasterKey

    if not session.UserId:
        raise InternalError("Invalid authentication")

    user = await user_service.get_user_by_id(UUID(session.UserId))
    valid, decrypted_data = SessionCryptoUtils.decrypt_and_validate_timestamp(
        request_data, master_key
    )
    if not valid or not user:
        raise InternalError("Invalid timestamp or authentication")

    data_json = json.loads(decrypted_data)
    signature = data_json.get("Signature")

    signature_is_valid = CryptoUtils.verify_data_without_signature(
        signature, user.PublicKey
    )
    if not signature_is_valid:
        raise InternalError("Invalid signature")

    authorized_ids = data_json.get("AuthorizedIds", [])
    user_ids = [UUID(id_str) for id_str in authorized_ids]
    pubkeys_dict = await user_service.get_user_pubkeys(user_ids)

    pubkeys_list = [pubkeys_dict.get(user_id, "") for user_id in user_ids]

    return SessionCryptoUtils.append_timestamp_and_encrypt(
        json.dumps(pubkeys_list, cls=CustomJSONEncoder), master_key
    )
