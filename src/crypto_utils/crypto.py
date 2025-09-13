import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import re
from collections.abc import Callable
from typing import Literal
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature


class CryptoUtils:
    """通用加密套件"""

    # 时间戳验证容差（5分钟）
    TIMESTAMP_TOLERANCE = timedelta(minutes=5)

    # region 非对称加密模块
    @staticmethod
    def generate_asymmetric_keys(key_size: int = 4096) -> tuple[str, str]:
        """
        生成RSA密钥对（返回PEM格式）
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

        # 获取私钥PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # 获取公钥PEM
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return public_pem, private_pem

    @staticmethod
    def encrypt_string_with_public_key(plain_text: str, public_key_pem: str) -> str:
        """
        使用公钥加密字符串
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"), backend=default_backend()
        )

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Provided public key is not an RSA public key.")

        encrypted = public_key.encrypt(
            plain_text.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return base64.b64encode(encrypted).decode("utf-8")

    @staticmethod
    def decrypt_string_with_private_key(
        encrypted_text: str, private_key_pem: str
    ) -> str:
        """
        使用私钥解密字符串
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None, backend=default_backend()
        )

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Provided private key is not an RSA private key.")

        encrypted_data = base64.b64decode(encrypted_text)
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return decrypted.decode("utf-8")

    @staticmethod
    def encrypt_stream_with_public_key(
        input_stream, output_stream, public_key_pem: str
    ):
        """
        公钥加密文件流（自动处理分块）
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"), backend=default_backend()
        )

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Provided public key is not an RSA public key.")

        # RSA加密的最大块大小
        max_block_size = (public_key.key_size // 8) - 42

        CryptoUtils._process_asymmetric(
            input_stream,
            output_stream,
            lambda data: public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            ),
            max_block_size,
        )

    @staticmethod
    def decrypt_stream_with_private_key(
        input_stream, output_stream, private_key_pem: str
    ):
        """
        私钥解密文件流
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None, backend=default_backend()
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Provided private key is not an RSA private key.")
        # RSA解密块大小（加密后的块大小）
        block_size = private_key.key_size // 8

        CryptoUtils._process_asymmetric(
            input_stream,
            output_stream,
            lambda data: private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            ),
            block_size,
        )

    # endregion

    # region 对称加密模块
    @staticmethod
    def generate_symmetric_key(
        key_size: Literal[128, 192, 256] = 256,
    ) -> tuple[str, str]:
        """
        生成对称密钥（返回Base64编码）
        """
        import os

        key = os.urandom(key_size // 8)
        iv = os.urandom(16)  # AES IV总是128位（16字节）

        return base64.b64encode(key).decode("utf-8"), base64.b64encode(iv).decode(
            "utf-8"
        )

    @staticmethod
    def encrypt_string_with_symmetric_key(
        plain_text: str, base64_key: str, base64_iv: str
    ) -> str:
        """
        对称加密字符串
        """
        key = base64.b64decode(base64_key)
        iv = base64.b64decode(base64_iv)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # PKCS7填充
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plain_text.encode("utf-8")) + padder.finalize()

        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(encrypted).decode("utf-8")

    @staticmethod
    def decrypt_string_with_symmetric_key(
        encrypted_text: str, base64_key: str, base64_iv: str
    ) -> str:
        """
        对称解密字符串
        """
        key = base64.b64decode(base64_key)
        iv = base64.b64decode(base64_iv)
        encrypted_data = base64.b64decode(encrypted_text)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

        # PKCS7去填充
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted.decode("utf-8")

    @staticmethod
    def encrypt_stream_with_symmetric_key(
        input_stream, output_stream, base64_key: str, base64_iv: str
    ):
        """
        对称加密文件流
        """
        key = base64.b64decode(base64_key)
        iv = base64.b64decode(base64_iv)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        CryptoUtils._process_symmetric(input_stream, output_stream, encryptor)

    @staticmethod
    def decrypt_stream_with_symmetric_key(
        input_stream, output_stream, base64_key: str, base64_iv: str
    ):
        """
        对称解密文件流
        """
        key = base64.b64decode(base64_key)
        iv = base64.b64decode(base64_iv)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        CryptoUtils._process_symmetric(input_stream, output_stream, decryptor)

    # region 核心处理逻辑
    @staticmethod
    def _process_asymmetric(
        input_stream,
        output_stream,
        processor: Callable[[bytes], bytes],
        block_size: int,
    ):
        """
        处理非对称加密/解密的流操作
        """
        while True:
            data = input_stream.read(block_size)
            if not data:
                break

            processed_data = processor(data)
            output_stream.write(processed_data)

    @staticmethod
    def _process_symmetric(input_stream, output_stream, transform):
        """
        处理对称加密/解密的流操作
        """
        # 对于加密，需要添加PKCS7填充
        if (
            hasattr(transform, "mode")
            and hasattr(transform.mode, "name")
            and transform.mode.name == "CBC"
        ):
            # 创建PKCS7填充器
            padder = sym_padding.PKCS7(128).padder()

            # 读取并填充所有数据
            data = input_stream.read()
            padded_data = padder.update(data) + padder.finalize()

            # 加密
            encrypted = transform.update(padded_data) + transform.finalize()
            output_stream.write(encrypted)
        else:
            # 对于解密，直接处理
            data = input_stream.read()
            if data:
                decrypted = transform.update(data) + transform.finalize()

                # 如果是解密，需要去除填充
                if (
                    hasattr(transform, "mode")
                    and hasattr(transform.mode, "name")
                    and transform.mode.name == "CBC"
                ):
                    unpadder = sym_padding.PKCS7(128).unpadder()
                    unpadded_data = unpadder.update(decrypted) + unpadder.finalize()
                    output_stream.write(unpadded_data)
                else:
                    output_stream.write(decrypted)

    # endregion

    # region 密钥辅助方法
    @staticmethod
    def _get_aes_provider(base64_key: str, base64_iv: str) -> Cipher:
        """
        获取AES加密提供者
        """
        key = base64.b64decode(base64_key)
        iv = base64.b64decode(base64_iv)
        return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    @staticmethod
    def parse_pem(pem: str, header: str) -> bytes:
        """
        解析PEM格式的密钥
        """
        clean_pem = re.sub(
            rf"-----BEGIN {header}-----|-----END {header}-----|\n|\r", "", pem
        ).strip()
        return base64.b64decode(clean_pem)

    @staticmethod
    def convert_to_pem(der_bytes: bytes, header: str) -> str:
        """
        将DER格式转换为PEM格式
        """
        base64_data = base64.b64encode(der_bytes).decode("utf-8")
        # 每64个字符插入换行符
        formatted_base64 = "\n".join(
            [base64_data[i : i + 64] for i in range(0, len(base64_data), 64)]
        )
        return f"-----BEGIN {header}-----\n{formatted_base64}\n-----END {header}-----"

    # region 签名功能

    @staticmethod
    def sign_data(data: str | io.IOBase, private_key_pem: str) -> str:
        """
        数据签名（支持字符串/流）
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None, backend=default_backend()
        )

        data_hash = CryptoUtils.compute_data_hash(data)

        # 使用PKCS1v15填充进行签名
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Provided private key is not an RSA private key.")
        signature = private_key.sign(data_hash, padding.PKCS1v15(), hashes.SHA256())

        return base64.b64encode(signature).decode("utf-8")

    @staticmethod
    def verify_data_without_signature(
        data: str | io.IOBase, public_key_pem: str
    ) -> bool:
        """
        直接从签名后数据验证签名
        """
        if isinstance(data, str):
            signature, original_data = CryptoUtils.extract_signature_from_string(data)
            return CryptoUtils.verify_data(original_data, signature, public_key_pem)
        elif hasattr(data, "read"):
            signature, original_data = CryptoUtils.extract_signature_from_stream(data)
            return CryptoUtils.verify_data(original_data, signature, public_key_pem)
        else:
            raise ValueError("不支持的数据格式。")

    @staticmethod
    def verify_data(data: str | io.IOBase, signature: str, public_key_pem: str) -> bool:
        """
        签名验证（支持字符串/流）
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"), backend=default_backend()
        )

        data_hash = CryptoUtils.compute_data_hash(data)
        signature_bytes = base64.b64decode(signature)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Provided public key is not an RSA public key.")
        try:
            # 使用PKCS1v15填充进行验证

            public_key.verify(
                signature_bytes, data_hash, padding.PKCS1v15(), hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def append_signature(data: str | io.IOBase, signature: str) -> str | io.BytesIO:
        """
        将签名附加到字符串或文件流头部，以"|"分隔
        """
        if isinstance(data, str):
            return f"{signature}|{data}"
        elif hasattr(data, "read"):
            return CryptoUtils.append_signature_to_stream(data, signature)
        else:
            raise ValueError("不支持的数据格式。")

    @staticmethod
    def extract_signature(
        data: str | io.IOBase,
    ) -> tuple[str, str | io.BytesIO]:
        """
        从附加了签名的数据中拆分出签名和原始数据
        """
        if isinstance(data, str):
            return CryptoUtils.extract_signature_from_string(data)
        elif hasattr(data, "read"):
            return CryptoUtils.extract_signature_from_stream(data)
        else:
            raise ValueError("不支持的数据格式。")

    # 辅助函数：将签名附加到文件流头部
    @staticmethod
    def append_signature_to_stream(stream: io.IOBase, signature: str) -> io.BytesIO:
        """
        将签名附加到文件流头部
        """
        memory_stream = io.BytesIO()

        # 写入签名和分隔符
        signature_line = f"{signature}|"
        memory_stream.write(signature_line.encode("utf-8"))

        if hasattr(stream, "seek"):
            stream.seek(0)

        if hasattr(stream, "read"):
            chunk = stream.read(8192)
            while chunk:
                memory_stream.write(chunk)
                chunk = stream.read(8192)

        memory_stream.seek(0)
        return memory_stream

    # 辅助函数：从字符串中拆分签名和原始数据
    @staticmethod
    def extract_signature_from_string(data: str) -> tuple[str, str]:
        """
        从字符串中拆分签名和原始数据
        """
        parts = data.split("|", 1)  # 只分割第一个'|'
        if len(parts) != 2:
            raise ValueError("数据格式不正确，无法提取签名。")

        return parts[0], parts[1]

    # 辅助函数：从文件流中拆分签名和原始数据
    @staticmethod
    def extract_signature_from_stream(stream: io.IOBase) -> tuple[str, io.BytesIO]:
        """
        从文件流中拆分签名和原始数据
        """
        if hasattr(stream, "seek"):
            stream.seek(0)

        signature_line = b""
        if hasattr(stream, "readline"):
            signature_line = stream.readline()
        else:
            chunk = b""
            while b"|" not in chunk:
                if hasattr(stream, "read"):
                    byte = stream.read(1)
                    if not byte:
                        break
                    chunk += byte
            signature_line = chunk

        signature_line_str = signature_line.decode("utf-8")
        if "|" not in signature_line_str:
            raise ValueError("数据格式不正确，无法提取签名。")

        signature, remaining = signature_line_str.split("|", 1)

        original_data = io.BytesIO()

        if remaining:
            original_data.write(remaining.encode("utf-8"))

        if hasattr(stream, "read"):
            chunk = stream.read(8192)
            while chunk:
                original_data.write(chunk)
                chunk = stream.read(8192)

        original_data.seek(0)
        return signature, original_data

    # 辅助函数：计算数据的哈希值
    @staticmethod
    def compute_data_hash(data: str | io.IOBase) -> bytes:
        """
        计算数据的SHA256哈希值
        """
        sha256 = hashlib.sha256()

        if isinstance(data, str):
            sha256.update(data.encode("utf-8"))
            return sha256.digest()
        elif hasattr(data, "read"):
            return CryptoUtils.compute_stream_hash(data, sha256)
        else:
            raise ValueError("不支持的数据格式。")

    # 辅助函数：计算流的哈希值
    @staticmethod
    def compute_stream_hash(stream: io.IOBase, hasher: hashlib._Hash) -> bytes:
        """
        计算流的SHA256哈希值
        """
        if hasattr(stream, "seek"):
            stream.seek(0)

        if hasattr(stream, "read"):
            chunk = stream.read(8192)
            while chunk:
                hasher.update(chunk)
                chunk = stream.read(8192)

        return hasher.digest()

    # endregion

    # region 时间戳功能

    @staticmethod
    def generate_timestamp() -> str:
        """
        统一时间戳生成（UTC时间，ISO 8601格式）
        """
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def append_timestamp(data: str | io.IOBase) -> str | io.BytesIO:
        """
        将时间戳附加到字符串或文件流头部，以"|"分隔
        """
        timestamp = CryptoUtils.generate_timestamp()

        if isinstance(data, str):
            return f"{timestamp}|{data}"
        elif hasattr(data, "read"):
            return CryptoUtils.append_timestamp_to_stream(data, timestamp)
        else:
            raise ValueError("不支持的数据格式。")

    @staticmethod
    def extract_timestamp(
        data: str | io.IOBase,
    ) -> tuple[str, str | io.BytesIO]:
        """
        从附加了时间戳的数据中拆分出时间戳和原始数据
        """
        if isinstance(data, str):
            return CryptoUtils.extract_timestamp_from_string(data)
        elif hasattr(data, "read"):
            return CryptoUtils.extract_timestamp_from_stream(data)
        else:
            raise ValueError("不支持的数据格式。")

    # 辅助函数：将时间戳附加到文件流头部
    @staticmethod
    def append_timestamp_to_stream(stream: io.IOBase, timestamp: str) -> io.BytesIO:
        """
        将时间戳附加到文件流头部
        """
        memory_stream = io.BytesIO()

        timestamp_line = f"{timestamp}|"
        memory_stream.write(timestamp_line.encode("utf-8"))

        if hasattr(stream, "seek"):
            stream.seek(0)

        if hasattr(stream, "read"):
            chunk = stream.read(8192)
            while chunk:
                memory_stream.write(chunk)
                chunk = stream.read(8192)

        memory_stream.seek(0)
        return memory_stream

    # 辅助函数：从字符串中拆分时间戳和原始数据
    @staticmethod
    def extract_timestamp_from_string(data: str) -> tuple[str, str]:
        """
        从字符串中拆分时间戳和原始数据
        """
        parts = data.split("|", 1)  # 只分割第一个'|'
        if len(parts) != 2:
            raise ValueError("数据格式不正确，无法提取时间戳。")

        return parts[0], parts[1]

    # 辅助函数：从文件流中拆分时间戳和原始数据
    @staticmethod
    def extract_timestamp_from_stream(stream: io.IOBase) -> tuple[str, io.BytesIO]:
        """
        从文件流中拆分时间戳和原始数据
        """
        if hasattr(stream, "seek"):
            stream.seek(0)

        timestamp_line = b""
        if hasattr(stream, "readline"):
            timestamp_line = stream.readline()
        else:
            chunk = b""
            while b"|" not in chunk:
                if hasattr(stream, "read"):
                    byte = stream.read(1)
                    if not byte:
                        break
                    chunk += byte
            timestamp_line = chunk

        timestamp_line_str = timestamp_line.decode("utf-8")
        if "|" not in timestamp_line_str:
            raise ValueError("数据格式不正确，无法提取时间戳。")

        timestamp, remaining = timestamp_line_str.split("|", 1)

        original_data = io.BytesIO()

        if remaining:
            original_data.write(remaining.encode("utf-8"))

        if hasattr(stream, "read"):
            chunk = stream.read(8192)
            while chunk:
                original_data.write(chunk)
                chunk = stream.read(8192)

        original_data.seek(0)
        return timestamp, original_data

    @staticmethod
    def validate_timestamp(timestamp_string: str) -> bool:
        """
        时间戳验证（带容差检查）
        """
        try:
            # 解析ISO 8601格式的时间戳
            timestamp = datetime.fromisoformat(timestamp_string.replace("Z", "+00:00"))

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            else:
                timestamp = timestamp.astimezone(timezone.utc)

            now = datetime.now(timezone.utc)

            return (
                timestamp > now - CryptoUtils.TIMESTAMP_TOLERANCE
                and timestamp < now + CryptoUtils.TIMESTAMP_TOLERANCE
            )
        except (ValueError, TypeError):
            return False

    # endregion
