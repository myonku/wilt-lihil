from lihil import Struct as LStruct
from msgspec import Struct

class HandShakeDTO:

    class InitData(Struct):
        clientRandom: str

    class ShakeData(Struct):
        data: str

class EncryptedDataDTO(Struct):
    data: str