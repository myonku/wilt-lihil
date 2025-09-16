from abc import abstractmethod
import base64
from datetime import datetime
from enum import Enum as PyEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from beanie import Document
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Table
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.orm import relationship, Mapped, mapped_column

from sqlalchemy import MetaData
from sqlalchemy import orm as sa_orm
from sqlalchemy.sql import func

# SQLAlchemy 声明式基类
metadata = MetaData()


class TableBase(sa_orm.DeclarativeBase):
    __abstract__ = True

    metadata = metadata

    gmt_modified = Column(DateTime, server_default=func.now(), onupdate=func.now())
    gmt_created = Column(DateTime, server_default=func.now())

    Id: Any


# MongoDB 文档模型
class ReviewFlow(Document):
    Id: UUID = Field(default_factory=uuid4, alias="_id")
    Title: str
    OwnerId: UUID  # 发起人
    PublisherName: str | None = None
    CreatedAt: datetime = Field(default_factory=datetime.now)
    SignatureString: str  # 发起人签名
    Completed: bool = False
    Description: str | None = None

    @classmethod
    def get_exclude_fields(cls) -> list[str]:
        return [
            "SignatureString",
        ]

    class Settings:
        name = "reviewflow"
        use_state_management = True


class ReviewStage(Document):
    Id: UUID = Field(default_factory=uuid4, alias="_id")
    PublisherId: UUID  # 提交者
    PublisherName: str | None = None
    BelongId: UUID  # 所属审核流程ID
    AuthorizedIds: list[UUID]  # 指定的可访问用户id列表
    EncryptedData: bytes | None = None
    OriginDataHash: str
    EncryptedDataHash: str
    Type: str | None = None  # 文件扩展名
    EncryptedKeys: list[str]
    CreatedAt: datetime = Field(default_factory=datetime.now)
    SignatureString: str  # 提交者签名
    PassRecord: list[bool] | None = None
    Completed: bool = False

    @classmethod
    def get_exclude_fields(cls) -> list[str]:
        return [
            "SignatureString",
            "EncryptedData",
            "AuthorizedIds",
            "EncryptedKeys",
        ]

    class Settings:
        name = "reviewstage"
        use_state_management = True


class Review(Document):
    Id: UUID = Field(default_factory=uuid4, alias="_id")
    PublisherId: UUID  # 发布者
    PublisherName: str | None = None
    BelongId: UUID  # 所属的阶段ID
    FinalBelongId: UUID  # 所属的审核流程ID
    Content: str | None = None
    IsPassed: bool  # 意见标记
    SignatureString: str  # 发布者签名
    CreatedAt: datetime = Field(default_factory=datetime.now)

    @classmethod
    def get_exclude_fields(cls) -> list[str]:
        return [
            "SignatureString",
        ]

    class Settings:
        name = "review"
        use_state_management = True


class UserProfile(Document):
    UserId: UUID = Field(alias="_id")
    Data: bytes | None = None
    Type: str | None = None

    class Settings:
        name = "avatar"
        use_state_management = True


# SQLAlchemy 表模型
class UserRole(PyEnum):
    Admin = 1
    Examiner = 2
    Standard = 3


class AccountStatus(PyEnum):
    Active = 1
    Restricted = 2
    Suspended = 3


# 用户组多对多关联表
user_group_association = Table(
    "user_group_association",
    TableBase.metadata,
    Column("UserId", UNIQUEIDENTIFIER, ForeignKey("users.Id"), primary_key=True),
    Column("GroupId", UNIQUEIDENTIFIER, ForeignKey("groups.Id"), primary_key=True),
)


class Group(TableBase):
    __tablename__ = "groups"

    Id: Mapped[UUID] = mapped_column(UNIQUEIDENTIFIER, primary_key=True, default=uuid4)
    Name: Mapped[str] = mapped_column(String(100), nullable=False)
    Description: Mapped[str | None] = mapped_column(String(500))
    CreatorId: Mapped[UUID] = mapped_column(UNIQUEIDENTIFIER, nullable=False)
    CreatedAt: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    UpdatedAt: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    # 关系
    Users: Mapped[list["User"]] = relationship(
        "User", secondary=user_group_association, back_populates="Groups"
    )


class User(TableBase):
    __tablename__ = "users"

    Id: Mapped[UUID] = mapped_column(UNIQUEIDENTIFIER, primary_key=True, default=uuid4)
    Name: Mapped[str | None] = mapped_column(String(100))
    Email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    AlterName: Mapped[str | None] = mapped_column(String(100))
    PhoneNumber: Mapped[str | None] = mapped_column(String(20))
    PasswordHash: Mapped[str] = mapped_column(String(255), nullable=False)  # argon2哈希
    PublicKey: Mapped[str] = mapped_column(Text, nullable=False)  # 持久公钥
    AccountStatus: Mapped["AccountStatus"] = mapped_column(
        SQLEnum(AccountStatus), default=AccountStatus.Restricted
    )
    Role: Mapped[UserRole] = mapped_column(SQLEnum(UserRole), default=UserRole.Standard)
    LastUpdatePasswordAt: Mapped[datetime | None] = mapped_column(DateTime)
    LastUpdateKeyAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedAt: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    LastLoginAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedAt: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    # 关系
    Groups: Mapped[list["Group"]] = relationship(
        "Group", secondary=user_group_association, back_populates="Users"
    )
    LoginHistories: Mapped[list["LoginHistory"]] = relationship(
        "LoginHistory", back_populates="User"
    )


class LoginHistory(TableBase):
    __tablename__ = "login_histories"

    Id: Mapped[UUID] = mapped_column(UNIQUEIDENTIFIER, primary_key=True, default=uuid4)
    UserId: Mapped[UUID] = mapped_column(
        UNIQUEIDENTIFIER, ForeignKey("users.Id"), nullable=False
    )
    LoginTime: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    DeviceFingerprint: Mapped[str] = mapped_column(
        String(200), nullable=False
    )  # 哈希值
    IPAddress: Mapped[str] = mapped_column(String(45), nullable=False)
    UserAgent: Mapped[str | None] = mapped_column(String(500))

    # 关系
    User: Mapped["User"] = relationship("User", back_populates="LoginHistories")


# 非数据库模型（用于业务逻辑）
class LogRecord(BaseModel):
    StartTime: datetime
    EndTime: datetime | None = None
    UserId: str | None = None
    Path: str
    Status: Literal["Success", "Error"] | None = None
    HttpMethod: str
    ErrorMessage: str | None = None


class Session(BaseModel):
    SessionId: str
    MasterKey: bytes | None = None
    CreatedAt: datetime
    ExpiredAt: datetime
    UserId: str | None = None
    ClientRandom: bytes | None = None  # 16字节随机数
    ServerRandom: bytes  # 16字节随机数
    ServerEcdhPrivateKey: bytes | None = None
    ServerEcdhPublicKey: bytes | None = None
    ClientEcdhPublicKey: bytes | None = None

    def session_to_dict(self) -> dict[str, str]:
        """将 Session 对象转换为可序列化的字典"""
        data = {
            "SessionId": self.SessionId,
            "CreatedAt": self.CreatedAt.isoformat(),
            "ExpiredAt": self.ExpiredAt.isoformat(),
            "UserId": self.UserId,
            "ClientRandom": (
                base64.b64encode(self.ClientRandom).decode("ascii")
                if self.ClientRandom
                else None
            ),
            "ServerRandom": base64.b64encode(self.ServerRandom).decode("ascii"),
            "ServerEcdhPrivateKey": (
                base64.b64encode(self.ServerEcdhPrivateKey).decode("ascii")
                if self.ServerEcdhPrivateKey
                else None
            ),
            "ServerEcdhPublicKey": (
                base64.b64encode(self.ServerEcdhPublicKey).decode("ascii")
                if self.ServerEcdhPublicKey
                else None
            ),
            "ClientEcdhPublicKey": (
                base64.b64encode(self.ClientEcdhPublicKey).decode("ascii")
                if self.ClientEcdhPublicKey
                else None
            ),
            "MasterKey": (
                base64.b64encode(self.MasterKey).decode("ascii")
                if self.MasterKey
                else None
            ),
        }
        return data

    @classmethod
    def dict_to_session(cls, data: dict[str, Any]):
        """从字典创建 Session 对象"""
        client_random = (
            base64.b64decode(data["ClientRandom"]) if data.get("ClientRandom") else None
        )
        server_random = base64.b64decode(data["ServerRandom"])
        server_private_key = (
            base64.b64decode(data["ServerEcdhPrivateKey"])
            if data.get("ServerEcdhPrivateKey")
            else None
        )
        server_public_key = (
            base64.b64decode(data["ServerEcdhPublicKey"])
            if data.get("ServerEcdhPublicKey")
            else None
        )
        client_public_key = (
            base64.b64decode(data["ClientEcdhPublicKey"])
            if data.get("ClientEcdhPublicKey")
            else None
        )
        master_key = (
            base64.b64decode(data["MasterKey"]) if data.get("MasterKey") else None
        )

        created_at = datetime.fromisoformat(data["CreatedAt"])
        expired_at = datetime.fromisoformat(data["ExpiredAt"])

        return cls(
            SessionId=data["SessionId"],
            CreatedAt=created_at,
            ExpiredAt=expired_at,
            UserId=data.get("UserId"),
            ClientRandom=client_random,
            ServerRandom=server_random,
            ServerEcdhPrivateKey=server_private_key,
            ServerEcdhPublicKey=server_public_key,
            ClientEcdhPublicKey=client_public_key,
            MasterKey=master_key,
        )
