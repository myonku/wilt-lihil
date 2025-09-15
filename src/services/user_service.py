from uuid import UUID
from datetime import datetime, timedelta, timezone

from src.repo.repository import UserDAO, GroupDAO, LoginHistoryDAO
from src.repo.models import User, Group, LoginHistory, AccountStatus
from src.crypto_utils.password_hasher import PasswordHasher


class UserService:
    """用户服务类，处理所有用户相关的业务逻辑"""

    def __init__(
        self, user_dao: UserDAO, group_dao: GroupDAO, login_history_dao: LoginHistoryDAO
    ):
        self.user_dao = user_dao
        self.group_dao = group_dao
        self.login_history_dao = login_history_dao

    async def get_other_users(self, user_id: UUID) -> list[User]:
        """获取其他用户（排除自己）"""
        user_exists = await self.user_dao.get(user_id)
        if not user_exists:
            return []

        users = await self.user_dao.get_many(filters={"Id": ("!=", user_id)})
        return users

    async def register_user(self, user_data: dict | User) -> UUID:
        """注册用户"""
        user = User(**user_data) if isinstance(user_data, dict) else user_data
        return await self.user_dao.create(user)

    async def get_user_by_id(self, user_id: UUID) -> User | None:
        """根据ID获取用户"""
        return await self.user_dao.get(user_id)

    async def get_user_by_email(self, email: str) -> User | None:
        """根据邮箱获取用户"""
        users = await self.user_dao.get_many(filters={"Email": email})
        return users[0] if users else None

    async def get_user_by_name(self, username: str) -> User | None:
        """根据用户名获取用户"""
        users = await self.user_dao.get_many(filters={"Name": username})
        return users[0] if users else None

    async def get_user_pubkeys(self, user_ids: list[UUID]) -> dict[UUID, str]:
        """获取多个用户的公钥"""
        if not user_ids:
            return {}

        users = await self.user_dao.get_many(ids=user_ids)
        return {user.Id: user.PublicKey for user in users}

    async def update_user(
        self,
        user_id: UUID,
        name: str | None = None,
        account_status: AccountStatus | None = None,
        last_login_at: datetime | None = None,
        public_key: str | None = None,
        last_update_pwd_at: datetime | None = None,
        last_update_key_at: datetime | None = None,
    ) -> User | None:
        """更新用户信息"""
        update_data = {}

        if name is not None:
            update_data["Name"] = name
        if account_status is not None:
            update_data["AccountStatus"] = account_status
        if last_login_at is not None:
            update_data["LastLoginAt"] = last_login_at
        if public_key is not None:
            update_data["PublicKey"] = public_key
        if last_update_pwd_at is not None:
            update_data["LastUpdatePasswordAt"] = last_update_pwd_at
        if last_update_key_at is not None:
            update_data["LastUpdateKeyAt"] = last_update_key_at

        update_data["UpdatedAt"] = datetime.now(timezone.utc)

        return await self.user_dao.update(user_id, update_data)

    async def authenticate_user(self, email: str, password: str) -> bool:
        """用户认证"""
        user = await self.get_user_by_email(email)
        if not user:
            return False
        hasher = PasswordHasher()
        return hasher.verify_password(
            user.PasswordHash,
            password,
        )

    async def add_login_history(
        self,
        user_id: UUID,
        device_fingerprint: str,
        ip_address: str,
        user_agent: str | None = None,
    ) -> UUID:
        """添加登录历史"""
        login_history = LoginHistory(
            UserId=user_id,
            DeviceFingerprint=device_fingerprint,
            IPAddress=ip_address,
            UserAgent=user_agent,
            LoginTime=datetime.now(timezone.utc),
        )

        return await self.login_history_dao.create(login_history)

    async def get_last_login_history(self, user_id: UUID) -> LoginHistory | None:
        """获取上一次登录历史（跳过最新的一次）"""
        histories = await self.login_history_dao.get_many(
            filters={"UserId": user_id}, order_by={"LoginTime": "desc"}, skip=1, limit=1
        )
        return histories[0] if histories else None

    async def get_newest_login_history(self, user_id: UUID) -> LoginHistory | None:
        """获取最新的登录历史"""
        histories = await self.login_history_dao.get_many(
            filters={"UserId": user_id}, order_by={"LoginTime": "desc"}, limit=1
        )
        return histories[0] if histories else None

    async def get_login_history_in_week(self, user_id: UUID) -> list[LoginHistory]:
        """获取一周内的登录历史"""
        one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)

        histories = await self.login_history_dao.get_many(
            filters={"UserId": user_id, "LoginTime": (">=", one_week_ago)},
            order_by={"LoginTime": "desc"},
        )
        return histories

    async def get_login_history_in_week_count(self, user_id: UUID) -> int:
        """获取一周内的登录次数"""
        one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)

        count = await self.login_history_dao.count(
            UserId=user_id, LoginTime=(">=", one_week_ago)
        )
        return count

    async def get_all_groups(self) -> list[Group]:
        """获取所有组"""
        return await self.group_dao.get_many()

    async def get_group_by_id(self, group_id: UUID) -> Group | None:
        """根据ID获取组"""
        return await self.group_dao.get(group_id)

    async def get_group_by_name(self, group_name: str) -> Group | None:
        """根据名称获取组"""
        groups = await self.group_dao.get_many(filters={"Name": group_name})
        return groups[0] if groups else None

    async def create_group(
        self, name: str, description: str | None, creator_id: UUID
    ) -> UUID:
        """创建组"""
        group = Group(
            Name=name,
            Description=description,
            CreatorId=creator_id,
            CreatedAt=datetime.now(timezone.utc),
            UpdatedAt=datetime.now(timezone.utc),
        )
        return await self.group_dao.create(group)

    async def update_group(
        self,
        group_id: UUID,
        name: str | None = None,
        description: str | None = None,
    ) -> Group | None:
        """更新组信息"""
        update_data = {}

        if name is not None:
            update_data["Name"] = name
        if description is not None:
            update_data["Description"] = description

        update_data["UpdatedAt"] = datetime.now(timezone.utc)

        return await self.group_dao.update(group_id, update_data)

    async def delete_group(self, group_id: UUID) -> bool:
        """删除组"""
        return await self.group_dao.delete(group_id)

    async def add_user_to_group(self, user_id: UUID, group_id: UUID) -> bool:
        """添加用户到组"""
        user = await self.user_dao.get(user_id)
        group = await self.group_dao.get(group_id)

        if not user or not group:
            return False

        if group not in user.Groups:
            user.Groups.append(group)
            await self.user_dao.update(user_id, {"Groups": user.Groups})

        return True

    async def remove_user_from_group(self, user_id: UUID, group_id: UUID) -> bool:
        """从组中移除用户"""
        user = await self.user_dao.get(user_id)
        group = await self.group_dao.get(group_id)

        if not user or not group:
            return False

        if group in user.Groups:
            user.Groups.remove(group)
            await self.user_dao.update(user_id, {"Groups": user.Groups})

        return True

    async def get_users_in_group(self, group_id: UUID) -> list[User]:
        """获取组中的所有用户"""
        group = await self.group_dao.get(group_id)
        if not group:
            return []

        return group.Users
