from typing import Any, TypeVar
from beanie import Document
from pydantic import BaseModel
from uuid import UUID
from typing import TypeVar, Generic
from sqlalchemy import select, update, delete, insert
import sqlalchemy
from sqlalchemy.exc import SQLAlchemyError
from uuid import UUID

from src.repo.db import MSSQLServer
from src.repo.models import (
    Group,
    LoginHistory,
    Review,
    ReviewFlow,
    ReviewStage,
    TableBase,
    User,
    UserProfile,
)


T = TypeVar("T", bound=Document)
V = TypeVar("V", bound=TableBase)


class MongoBaseDAO:
    """基于 Beanie 的基础数据访问对象"""

    def __init__(self, document_model: type[T]):
        self.model = document_model

    async def get(self, id: UUID) -> Document | None:
        """根据 ID 获取文档"""
        return await self.model.get(id)

    async def get_many(
        self, ids: list[UUID] | None = None, skip: int = 0, limit: int = 100
    ) -> list[Any]:
        """批量查询"""
        query = {}
        if ids:
            query["_id"] = {"$in": ids}

        return await self.model.find(query).skip(skip).limit(limit).to_list()

    async def create(self, document: T) -> T:
        """创建文档"""
        return await document.insert()

    async def update(self, id: UUID, update_data: BaseModel) -> Any:
        """更新文档"""
        document = await self.get(id)
        if document:
            update_dict = update_data.model_dump(exclude_unset=True)
            await document.set(update_dict)
            return document
        return None

    async def delete(self, id: UUID) -> bool:
        """删除文档"""
        document = await self.get(id)
        if document:
            await document.delete()
            return True
        return False


class MSSQLBaseDAO(Generic[V]):
    """基于 SQLAlchemy 的基础数据访问对象"""

    def __init__(self, model: type[V], sql_db: MSSQLServer):
        self.model = model
        self.sql_db = sql_db

    async def _execute(self, sql, **kwargs) -> Any:
        """执行 SQL 语句的通用方法"""
        async with await self.sql_db.get_connection() as conn:
            try:
                result = await conn.execute(sql, **kwargs)
                await conn.commit()
                return result
            except SQLAlchemyError as e:
                await conn.rollback()
                raise e

    async def get(self, id: UUID) -> V | None:
        """根据 ID 获取记录"""
        async with await self.sql_db.get_connection() as conn:
            try:
                sql = select(self.model).where(self.model.Id == id)
                result = await conn.execute(sql)
                return result.scalar_one_or_none()
            except SQLAlchemyError as e:
                await conn.rollback()
                raise e

    async def get_many(
        self,
        ids: list[UUID] | None = None,
        skip: int = 0,
        limit: int = 100,
        **filters,
    ) -> list[V]:
        """批量查询"""
        async with await self.sql_db.get_connection() as conn:
            try:
                sql = select(self.model)

                if ids:
                    sql = sql.where(self.model.Id.in_(ids))

                for key, value in filters.items():
                    if hasattr(self.model, key):
                        sql = sql.where(getattr(self.model, key) == value)

                sql = sql.offset(skip).limit(limit)

                result = await conn.execute(sql)
                return [self.model(**u) for u in result.mappings().fetchall()]
            except SQLAlchemyError as e:
                await conn.rollback()
                raise e

    async def create(self, instance: V) -> UUID:
        """创建记录"""
        async with await self.sql_db.get_connection() as conn:
            try:
                result = await conn.execute(
                    insert(self.model)
                    .values(instance.__dict__)
                    .returning(self.model.Id)
                )
                return result.scalar_one()
            except SQLAlchemyError as e:
                await conn.rollback()
                raise e

    async def update(self, id: UUID, update_data: dict) -> V | None:
        """更新记录"""
        async with await self.sql_db.get_connection() as conn:
            try:
                sql = select(self.model).where(self.model.Id == id)
                result = await conn.execute(sql)
                instance = result.scalar_one_or_none()

                if not instance:
                    return None

                for key, value in update_data.items():
                    if hasattr(instance, key):
                        setattr(instance, key, value)

                await conn.execute(
                    update(self.model).where(self.model.Id == id).values(**update_data)
                )
                return instance
            except SQLAlchemyError as e:
                await conn.rollback()
                raise e

    async def delete(self, id: UUID) -> bool:
        """删除记录"""
        async with await self.sql_db.get_connection() as conn:
            try:
                sql = select(self.model).where(self.model.Id == id)
                result = await conn.execute(sql)
                instance = result.scalar_one_or_none()

                if not instance:
                    return False

                await conn.execute(delete(self.model).where(self.model.Id == id))
                return True
            except SQLAlchemyError as e:
                await conn.rollback()
                raise e

    async def count(self, **filters) -> int:
        """统计记录数量"""
        async with await self.sql_db.get_connection() as conn:
            try:
                sql = select(self.model)
                for key, value in filters.items():
                    if hasattr(self.model, key):
                        sql = sql.where(getattr(self.model, key) == value)

                result = await conn.execute(
                    select(sqlalchemy.func.count()).select_from(sql.subquery())
                )
                return result.scalar_one()
            except SQLAlchemyError as e:
                await conn.rollback()
                raise e


class ReviewFlowDAO(MongoBaseDAO):

    def __init__(self):
        super().__init__(ReviewFlow)


class ReviewStageDAO(MongoBaseDAO):

    def __init__(self):
        super().__init__(ReviewStage)


class ReviewDAO(MongoBaseDAO):

    def __init__(self):
        super().__init__(Review)


class ProfileDAO(MongoBaseDAO):

    def __init__(self):
        super().__init__(UserProfile)


class UserDAO(MSSQLBaseDAO[User]):

    def __init__(self, sql_db: MSSQLServer):
        super().__init__(User, sql_db)


class GroupDAO(MSSQLBaseDAO[Group]):

    def __init__(self, sql_db: MSSQLServer):
        super().__init__(Group, sql_db)


class LoginHistoryDAO(MSSQLBaseDAO[LoginHistory]):

    def __init__(self, sql_db: MSSQLServer):
        super().__init__(LoginHistory, sql_db)
