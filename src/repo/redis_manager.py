from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime
import json
from typing import Any
from redis.asyncio import Redis, from_url

from src.config import ProjectConfig
from src.repo.models import Session


class RedisManager:
    """Redis 连接管理器"""

    def __init__(self):
        self.redis: Redis | None = None
        self.is_initialized: bool = False

    async def is_connected(self) -> bool:
        """检查连接状态"""
        try:
            if self.redis is None:
                return False
            return await self.redis.ping()
        except Exception:
            return False

    async def connect(self, config: ProjectConfig, **kwargs):
        """连接 Redis"""
        if not config.redis:
            raise ConnectionError("Redis配置初始化失败")
        print(f"正在连接Redis: {config.redis.redis_uri}")

        default_kwargs = {
            "encoding": "utf-8",
            "decode_responses": True,
            "max_connections": 20,
            "socket_timeout": 5,
            "socket_connect_timeout": 5,
        }
        default_kwargs.update(kwargs)

        self.redis = from_url(config.redis.redis_uri, **default_kwargs)
        self.is_initialized = True
        print("Redis连接完成")

    async def disconnect(self):
        """关闭连接"""
        if self.redis:
            print("正在关闭Redis连接")
            await self.redis.close()
            self.redis = None
            self.is_initialized = False

    def get_client(self) -> Redis:
        """获取 Redis 客户端"""
        if self.redis is None:
            raise RuntimeError("Redis未初始化")
        return self.redis


class RedisBaseDAO:
    """Redis 基础数据访问对象"""

    def __init__(self, key_prefix: str, redis_manager: RedisManager):
        self.key_prefix = key_prefix
        self.redis_manager = redis_manager

    def _get_key(self, key: str) -> str:
        """生成完整的 Redis key"""
        return f"{self.key_prefix}:{key}"

    async def set(self, key: str, value: Any, expire: int | None = None) -> bool:
        """设置值"""
        client = self.redis_manager.get_client()
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        return await client.set(self._get_key(key), value, ex=expire)

    async def get(self, key: str) -> Any | None:
        """获取值"""
        client = self.redis_manager.get_client()
        value = await client.get(self._get_key(key))
        if value is None:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    async def delete(self, key: str) -> bool:
        """删除键"""
        client = self.redis_manager.get_client()
        return await client.delete(self._get_key(key)) > 0

    async def exists(self, key: str) -> bool:
        """检查键是否存在"""
        client = self.redis_manager.get_client()
        return await client.exists(self._get_key(key)) > 0

    async def expire(self, key: str, seconds: int = 3600) -> bool:
        """设置过期时间"""
        client = self.redis_manager.get_client()
        return await client.expire(self._get_key(key), seconds)

    async def ttl(self, key: str) -> int:
        """获取剩余过期时间"""
        client = self.redis_manager.get_client()
        return await client.ttl(self._get_key(key))


class SessionDAO(RedisBaseDAO):
    def __init__(self, redis_manager: RedisManager):
        super().__init__("user:sessions", redis_manager)

    async def set_session(self, session: Session, expire: int = 3600) -> bool:
        """设置用户会话"""
        now = datetime.now()
        remaining_seconds = int((session.ExpiredAt - now).total_seconds())
        expire_seconds = min(expire, remaining_seconds)

        if expire_seconds <= 0:
            return False

        session_data = json.dumps(session.session_to_dict())
        return await self.set(
            session.SessionId,
            session_data,
            expire,
        )

    async def get_session(self, session_id: str) -> Session | None:
        """获取用户会话"""
        session_data: str | bytes | None = await self.get(session_id)

        if session_data is None:
            return None

        try:
            if isinstance(session_data, (str, bytes)):
                return Session.dict_to_session(json.loads(session_data))
            else:
                return Session.dict_to_session(session_data)
        except (ValueError, AttributeError, ImportError) as e:
            print(f"反序列化Session失败: {e}")
            return None


@asynccontextmanager
async def session_dao(redis_manager: RedisManager) -> AsyncGenerator[SessionDAO, None]:
    yield SessionDAO(redis_manager)
