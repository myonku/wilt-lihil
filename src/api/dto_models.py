from datetime import datetime
from uuid import UUID
from lihil import UploadFile
from lihil import Struct as LStruct
from msgspec import Struct
from pydantic import BaseModel


class HandShakeInitDTO(Struct):
    clientRandom: str


class EncryptedDataDTO(Struct):
    data: str


class AvatarUploadForm(LStruct):
    Avatar: UploadFile
    Data: str
    Type: str


def plain_text_decoder(data: bytes) -> str:
    """提供对plain/text类型的请求体解码器"""
    return data.decode("utf-8")
