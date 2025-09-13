import base64
import hashlib
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto import CryptoUtils


class SessionCryptoUtils:
    """用于会话加密的工具类"""

    @staticmethod
    def generate_random(length: int) -> bytes:
        """
        生成随机数
        """
        return os.urandom(length)

    @staticmethod
    def generate_ecdh_key_pair() -> tuple[str, bytes]:
        """
        ECDH临时密钥对生成
        """
        # 使用P-256曲线（与nistP256对应）
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # 导出私钥（PKCS8格式）
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # 导出公钥并转换为PEM格式
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return public_key_pem, private_key_bytes

    @staticmethod
    def compute_ecdh_shared_secret(
        server_private_key: bytes, client_public_key_pem: str
    ) -> bytes:
        """
        预主密钥派生
        """
        server_private = serialization.load_der_private_key(
            server_private_key, password=None, backend=default_backend()
        )
        client_pub_key_der = CryptoUtils.parse_pem(client_public_key_pem, "PUBLIC KEY")

        # 加载客户端公钥
        client_public = serialization.load_der_public_key(
            client_pub_key_der, backend=default_backend()
        )

        # 检查密钥类型是否为EC
        if not isinstance(server_private, ec.EllipticCurvePrivateKey):
            raise TypeError(
                "server_private_key must be an EC private key for ECDH exchange"
            )
        if not isinstance(client_public, ec.EllipticCurvePublicKey):
            raise TypeError(
                "client_public_key must be an EC public key for ECDH exchange"
            )

        # 计算共享密钥（使用SHA256哈希）
        shared_secret = server_private.exchange(ec.ECDH(), client_public)

        # 使用HKDF进行密钥派生（更安全的方式）
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ECDH key derivation",
            backend=default_backend(),
        ).derive(shared_secret)

        return derived_key

    @staticmethod
    def derive_master_secret(
        pre_master_secret: bytes, client_random: bytes, server_random: bytes
    ) -> bytes:
        """
        主密钥派生
        """
        # 1. 拼接随机数和预主密钥
        concat_bytes = client_random + server_random + pre_master_secret

        # 2. SHA-256哈希
        hash_obj = hashlib.sha256(concat_bytes)
        hash_result = hash_obj.digest()

        # 3. 取前32字节作为AES密钥
        return hash_result[:32]

    @staticmethod
    def encrypt_stream_with_symmetric_key(data: bytes, key: bytes) -> bytes:
        """
        加密数据（字节流）- AES-GCM
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt_stream_with_symmetric_key(data: bytes, key: bytes) -> bytes:
        """
        解密数据（字节流）- AES-GCM
        """
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext

    @staticmethod
    def encrypt_string_with_master_key(plaintext: str, master_key: bytes) -> str:
        """
        使用主密钥加密字符串
        """
        plaintext_bytes = plaintext.encode("utf-8")
        encrypted_bytes = SessionCryptoUtils.encrypt_stream_with_symmetric_key(
            plaintext_bytes, master_key
        )
        return base64.b64encode(encrypted_bytes).decode("utf-8")

    @staticmethod
    def decrypt_string_with_master_key(encrypted_base64: str, master_key: bytes) -> str:
        """
        使用主密钥解密字符串
        """
        encrypted_bytes = base64.b64decode(encrypted_base64)
        decrypted_bytes = SessionCryptoUtils.decrypt_stream_with_symmetric_key(
            encrypted_bytes, master_key
        )
        return decrypted_bytes.decode("utf-8")

    @staticmethod
    def decrypt_and_validate_timestamp(
        encrypted_base64: str, master_key: bytes
    ) -> tuple[bool, str]:
        """
        直接解密（主密钥）数据并验证时间戳
        """
        decrypted_string = SessionCryptoUtils.decrypt_string_with_master_key(
            encrypted_base64, master_key
        )
        timestamp, origin_data = CryptoUtils.extract_timestamp_from_string(
            decrypted_string
        )
        is_valid = CryptoUtils.validate_timestamp(timestamp)
        return (is_valid, origin_data)

    @staticmethod
    def append_timestamp_and_encrypt(plaintext: str, master_key: bytes) -> str:
        """
        直接添加时间戳并加密（主密钥）
        """
        data_with_timestamp = CryptoUtils.append_timestamp(plaintext)

        if isinstance(data_with_timestamp, str):
            encrypted_base64 = SessionCryptoUtils.encrypt_string_with_master_key(
                data_with_timestamp, master_key
            )
            return encrypted_base64
        else:
            raise ValueError("添加时间戳后数据不是字符串类型")
