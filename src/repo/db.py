from beanie import init_beanie
from pymongo import AsyncMongoClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, AsyncSession

from src.config import ProjectConfig
from src.repo.models import TableBase


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

    async def connect(self, config: ProjectConfig, document_models: list | None = None):
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
        print(f"已连接至Mongo数据库服务[{config.mongo.DATABASE}]，Beanie 初始化已完成")

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
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            print(f"数据库连接测试失败：{e}")
            return False

    async def connect(
        self,
        config: ProjectConfig,
        echo: bool = True,
        create_if_not_exists: bool = False,
    ):
        """连接数据库"""
        if not config.sqlserver:
            raise ConnectionError("MSSQL配置初始化失败")
        connection_str = config.sqlserver.mssql_uri
        print(f"正在连接MSSQLServer数据库: {connection_str}")

        self.engine = create_async_engine(
            connection_str,
            echo=echo,
            future=True,
            pool_size=20,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=1800,
        )
        if not await self.is_connected():
            raise ConnectionError(f"数据库连接测试失败")
        self.is_initialized = True
        print("SQLServer数据库连接完成")
        if create_if_not_exists and not await self.check_all_tables_exist():
            await self.create_tables()

    async def disconnect(self):
        """关闭连接"""
        if self.engine:
            print("正在关闭MSSQL数据库连接")
            await self.engine.dispose()
            self.engine = None
            self.is_initialized = False

    def get_session(self) -> AsyncSession:
        """获取新的AsyncSession"""
        if self.engine is None:
            raise RuntimeError("数据库引擎未初始化")
        return AsyncSession(self.engine, expire_on_commit=False)

    async def create_tables(self):
        """创建所有数据库表"""
        if self.engine is None:
            raise RuntimeError("数据库引擎未初始化")
        try:
            async with self.engine.begin() as conn:
                print("获取数据库连接成功，开始初始化表:")
                for table_name in TableBase.metadata.tables.keys():
                    print(f"  - {table_name}")
                await conn.run_sync(TableBase.metadata.create_all)

            print("数据库表创建完成")

        except Exception as e:
            print(f"创建表过程中出错: {e}")
            import traceback

            traceback.print_exc()
            raise

    async def check_tables_exist(self, table_name: str = "users") -> bool:
        """检查表是否存在"""
        if self.engine is None:
            return False
        try:
            async with self.engine.connect() as conn:
                result = await conn.execute(
                    text(
                        f"SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '{table_name}'"
                    )
                )
                return bool(result.scalar())
        except Exception as e:
            print(f"检查表存在时出错: {e}")
            return False

    async def check_all_tables_exist(self) -> bool:
        """检查所有定义的表是否存在"""
        if self.engine is None:
            return False
        try:
            async with self.engine.connect() as conn:
                defined_tables = list(TableBase.metadata.tables.keys())
                if not defined_tables:
                    return True
                table_names = ", ".join([f"'{table}'" for table in defined_tables])
                query = text(
                    f"""
                    SELECT COUNT(*) 
                    FROM INFORMATION_SCHEMA.TABLES 
                    WHERE TABLE_NAME IN ({table_names}) 
                    AND TABLE_TYPE = 'BASE TABLE'
                """
                )
                result = await conn.execute(query)
                return result.scalar() == len(defined_tables)
        except Exception as e:
            print(f"检查表存在时出错: {e}")
            return False
