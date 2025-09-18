from uuid import UUID
from src.repo.models import UserProfile
from src.repo.repository import ProfileDAO


class ProfileService:
    """
    提供面向api接口数据的服务函数封装
    """

    def __init__(
        self,
        profile_dao: ProfileDAO,
    ):
        self.profile_dao = profile_dao

    async def add_avatar_async(self, profile: UserProfile) -> None:
        """添加用户头像"""
        await self.profile_dao.create(profile)

    async def get_avatar_by_id_async(self, user_id: UUID) -> UserProfile | None:
        """根据用户ID获取头像"""
        profiles = await self.profile_dao.get_many_by_field("UserId", user_id)
        return profiles[0] if profiles else None

    async def update_avatar_async(
        self, user_id: UUID, data: bytes | None, file_type: str | None
    ) -> None:
        """更新用户头像"""
        existing_profiles = await self.profile_dao.get_many_by_field("UserId", user_id)

        if existing_profiles:
            profile = existing_profiles[0]
            profile.Data = data
            profile.Type = file_type
            await profile.save()
        else:
            new_profile = UserProfile(_id=user_id, Data=data, Type=file_type)
            await self.profile_dao.create(new_profile)
