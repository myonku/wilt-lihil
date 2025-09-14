from src.repo.repository import UserDAO, GroupDAO, LoginHistoryDAO

class UserService:

    def __init__(self, user_dao: UserDAO, group_dao: GroupDAO, login_history_dao: LoginHistoryDAO):
        self.user_dao = user_dao
        self.group_dao = group_dao
        self.login_history_dao = login_history_dao
