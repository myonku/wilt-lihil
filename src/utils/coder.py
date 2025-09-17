import base64
import json
from datetime import datetime, date
from decimal import Decimal
from uuid import UUID
from enum import Enum


class CustomJSONEncoder(json.JSONEncoder):
    """自定义 JSON 编码器，处理常见的数据类型"""

    def default(self, o):
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        elif isinstance(o, UUID):
            return str(o)
        elif isinstance(o, Decimal):
            return float(o)
        elif isinstance(o, Enum):
            return o.value
        elif isinstance(o, bytes):
            return base64.b64encode(o).decode("utf-8")
        elif hasattr(o, "__dict__"):
            return o.__dict__
        else:
            return super().default(o)


def plain_text_decoder(data: bytes) -> str:
    """提供对plain/text类型的请求体解码器"""
    return data.decode("utf-8")
