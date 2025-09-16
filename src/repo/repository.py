from beanie import Document
from pydantic import BaseModel
from uuid import UUID
from typing import TypeVar, Generic, Any
from sqlalchemy import asc, desc, select, update, delete, insert
import sqlalchemy
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
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


class MongoBaseDAO(Generic[T]):
    """基于 Beanie 的基础数据访问对象"""

    def __init__(self, document_model: type[T]):
        self.model = document_model

    async def get(self, id: UUID) -> T | None:
        """根据 ID 获取文档"""
        return await self.model.get(id)

    async def get_many(
        self, ids: list[UUID] | None = None, skip: int = 0, limit: int = 100
    ) -> list[T]:
        """批量查询"""
        query = {}
        if ids:
            query["_id"] = {"$in": ids}

        return await self.model.find(query).skip(skip).limit(limit).to_list()

    async def create(self, document: T) -> T:
        """创建文档"""
        return await document.insert()

    async def update(self, id: UUID, update_data: BaseModel) -> T | None:
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

    async def get_many_by_field(
        self, field_name: str, value: Any, exclude_fields: list[str] | None = None
    ) -> list[T]:
        """根据字段值查询多个文档"""
        query = {field_name: value}
        find_query = await self.model.find(query).to_list()
        docs = []
        for q in find_query:
            doc = self.__project_attr(q, exclude_fields)
            if doc is not None:
                docs.append(doc)
        return docs

    async def get_with_projection(
        self, doc_id: UUID, exclude_fields: list[str] | None = None
    ) -> T | None:
        """根据ID获取文档（带字段排除）"""
        document = await self.model.get(doc_id)
        return self.__project_attr(document, exclude_fields)

    async def find_with_projection(
        self, query: Any, exclude_fields: list[str] | None = None
    ) -> list[T]:
        """根据查询条件查找文档（带字段排除）"""
        find_query = await self.model.find(query).to_list()
        docs = []
        for q in find_query:
            doc = self.__project_attr(q, exclude_fields)
            if doc is not None:
                docs.append(doc)
        return docs

    async def count_documents(self, query: Any) -> int:
        """计算满足查询条件的文档数量"""
        return await self.model.find(query).count()

    def __project_attr(self, document: T | None, exclude_fields: list[str] | None) -> T | None:
        if not document:
            return None
        if not exclude_fields:
            return document
        for field in exclude_fields:
            if hasattr(document, field):
                setattr(document, field, None)
        return document


class MSSQLBaseDAO(Generic[V]):
    """基于 SQLAlchemy 的基础数据访问对象"""

    def __init__(self, model: type[V]):
        self.model = model

    async def get(self, id: UUID, session: AsyncSession) -> V | None:
        """根据 ID 获取记录"""
        try:
            sql = select(self.model).where(self.model.Id == id)
            result = await session.execute(sql)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            await session.rollback()
            raise e

    async def get_many(
        self,
        session: AsyncSession,
        ids: list[UUID] | None = None,
        skip: int = 0,
        limit: int = 100,
        order_by: dict | None = None,
        **filters,
    ) -> list[V]:
        """批量查询"""
        try:
            sql = select(self.model)

            if ids:
                sql = sql.where(self.model.Id.in_(ids))

            for key, value in filters.items():
                if hasattr(self.model, key):
                    sql = sql.where(getattr(self.model, key) == value)

            if order_by:
                order_clauses = []
                for column_name, direction in order_by.items():
                    if hasattr(self.model, column_name):
                        column = getattr(self.model, column_name)
                        if direction.lower() == "desc":
                            order_clauses.append(desc(column))
                        else:
                            order_clauses.append(asc(column))
                if order_clauses:
                    sql = sql.order_by(*order_clauses)
            else:
                sql = sql.order_by(self.model.Id.asc())

            sql = sql.offset(skip).limit(limit)

            result = await session.execute(sql)
            return [self.model(**u) for u in result.mappings().fetchall()]
        except SQLAlchemyError as e:
            await session.rollback()
            raise e

    async def create(self, instance: V, session: AsyncSession) -> UUID:
        """创建记录"""
        try:
            insert_data = {}
            for column in self.model.__table__.columns:
                column_name = column.name
                if hasattr(instance, column_name):
                    value = getattr(instance, column_name)
                    if value is not None:
                        insert_data[column_name] = value

            result = await session.execute(
                insert(self.model).values(**insert_data).returning(self.model.Id)
            )
            created_id = result.scalar_one()

            await session.flush()
            return created_id

        except SQLAlchemyError as e:
            await session.rollback()
            raise e

    async def update(
        self, id: UUID, update_data: dict, session: AsyncSession
    ) -> V | None:
        """更新记录"""
        try:
            sql = select(self.model).where(self.model.Id == id)
            result = await session.execute(sql)
            instance = result.scalar_one_or_none()

            if not instance:
                return None

            valid_update_data = {}
            for key, value in update_data.items():
                if hasattr(self.model, key) and key in self.model.__table__.columns:
                    valid_update_data[key] = value
                    setattr(instance, key, value)

            if valid_update_data:
                await session.execute(
                    update(self.model)
                    .where(self.model.Id == id)
                    .values(**valid_update_data)
                )

            return instance
        except SQLAlchemyError as e:
            await session.rollback()
            raise e

    async def delete(self, id: UUID, session: AsyncSession) -> bool:
        """删除记录"""
        try:
            sql = select(self.model).where(self.model.Id == id)
            result = await session.execute(sql)
            instance = result.scalar_one_or_none()

            if not instance:
                return False

            await session.execute(delete(self.model).where(self.model.Id == id))
            return True
        except SQLAlchemyError as e:
            await session.rollback()
            raise e

    async def count(self, session: AsyncSession, **filters) -> int:
        """统计记录数量"""
        try:
            sql = select(self.model)
            for key, value in filters.items():
                if hasattr(self.model, key):
                    sql = sql.where(getattr(self.model, key) == value)

            result = await session.execute(
                select(sqlalchemy.func.count()).select_from(sql.subquery())
            )
            return result.scalar_one()
        except SQLAlchemyError as e:
            await session.rollback()
            raise e


class ReviewFlowDAO(MongoBaseDAO[ReviewFlow]):

    def __init__(self):
        super().__init__(ReviewFlow)


class ReviewStageDAO(MongoBaseDAO[ReviewStage]):

    def __init__(self):
        super().__init__(ReviewStage)


class ReviewDAO(MongoBaseDAO[Review]):

    def __init__(self):
        super().__init__(Review)


class ProfileDAO(MongoBaseDAO[UserProfile]):

    def __init__(self):
        super().__init__(UserProfile)


class UserDAO(MSSQLBaseDAO[User]):

    def __init__(self):
        super().__init__(User)


class GroupDAO(MSSQLBaseDAO[Group]):

    def __init__(self):
        super().__init__(Group)


class LoginHistoryDAO(MSSQLBaseDAO[LoginHistory]):

    def __init__(self):
        super().__init__(LoginHistory)
