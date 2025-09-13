from beanie import init_beanie
from pymongo import AsyncMongoClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, AsyncConnection

from config import ProjectConfig


class MongoDB:
    """MongoDB 连接管理器，集成 Beanie ODM"""

    def __init__(self):
        self.client: AsyncMongoClient | None = None
        self.is_initialized: bool = False

    async def is_connected(self) -> bool:
        """检查连接状态"""
        try:
            if self.client is None:
                return False
            await self.client.server_info()
            return True
        except:
            return False

    async def connect(
        self, config: ProjectConfig, document_models: list | None = None
    ):
        """连接数据库并初始化 Beanie"""
        if not config.mongo:
            raise ConnectionError("Mongo配置初始化失败")
        print(f"正在连接MongoDB服务: {config.mongo.mongo_uri}")
        self.client = AsyncMongoClient(config.mongo.mongo_uri)
        if document_models:
            await init_beanie(
                database=self.client[config.mongo.DATABASE],
                document_models=document_models,
            )
            self.is_initialized = True

        print(f"已连接至Mongo数据库: {config.mongo.DATABASE}，Beanie 初始化完成")

    async def disconnect(self):
        """关闭连接"""
        if self.client:
            print("正在关闭MongoDB连接")
            await self.client.close()
            self.is_initialized = False


class MSSQLServer:
    """MSSQL 数据库连接管理器"""

    def __init__(self):
        self.engine: AsyncEngine | None = None
        self.is_initialized: bool = False

    async def is_connected(self) -> bool:
        """检查连接状态"""
        try:
            if self.engine is None:
                return False
            async with self.engine.connect() as conn:
                await conn.get_isolation_level()
            return True
        except Exception:
            return False

    async def connect(self, config: ProjectConfig):
        """连接数据库"""
        if not config.mssql:
            raise ConnectionError("MySQL配置初始化失败")
        print(f"正在连接MSSQLServer数据库: {config.mssql.mssql_uri}")

        self.engine = create_async_engine(
            config.mssql.mssql_uri,
            echo=True,
            future=True,
            pool_size=20,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=1800,
        )

        self.is_initialized = True
        print("SQLServer数据库连接完成")

    async def disconnect(self):
        """关闭连接"""
        if self.engine:
            print("正在关闭MSSQL数据库连接")
            await self.engine.dispose()
            self.engine = None
            self.is_initialized = False

    async def get_connection(self) -> AsyncConnection:
        """获取数据库连接"""
        if self.engine is None:
            raise RuntimeError("数据库引擎未初始化")
        return await self.engine.connect()
