from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from lihil.config import lhl_get_config
from sqlalchemy.ext.asyncio import AsyncConnection
from pymongo import AsyncMongoClient

from src.config import ProjectConfig
from src.repo.db import MongoDB, MSSQLServer
from src.repo.redis_manager import RedisManager


mongo = MongoDB()
mssql = MSSQLServer()
redis = RedisManager()


@asynccontextmanager
async def mongo_connection() -> AsyncGenerator[AsyncMongoClient, None]:
    """原生连接支持，仅用于特殊情况"""
    config = lhl_get_config(ProjectConfig)

    if not await mongo.is_connected():
        if config.mongo is None:
            raise ConnectionError("Mongo配置初始化失败")
        await mongo.connect(config)

    if mongo.client is None:
        raise RuntimeError("MongoDB client is not initialized")

    yield mongo.client


@asynccontextmanager
async def mssql_connection() -> AsyncGenerator[AsyncConnection, None]:
    """原生连接支持，仅用于特殊情况"""
    config = lhl_get_config(ProjectConfig)

    if not await mssql.is_connected():
        if config.sqlserver is None:
            raise ConnectionError("MSSQL配置初始化失败")
        await mssql.connect(config)

    if mssql.engine is None:
        raise RuntimeError("MSSQL engine is not initialized")

    yield mssql.engine.connect()
