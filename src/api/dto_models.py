from lihil import UploadFile
from lihil import Struct as LStruct
from msgspec import Struct


class HandShakeInitDTO(Struct):
    clientRandom: str


class EncryptedDataDTO(Struct):
    data: str


class AvatarUploadForm(LStruct):
    Avatar: UploadFile
    Data: str
    Type: str


class UploadChunkForm(LStruct):
    chunk: UploadFile
    index: str