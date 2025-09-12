from repo.repository import ProfileDAO


class ProfileService:
    """
    提供面向api接口数据的服务函数封装
    """

    def __init__(
        self,
        profile_dao: ProfileDAO,
    ):
        self.profile_dao = profile_dao

