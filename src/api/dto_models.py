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
