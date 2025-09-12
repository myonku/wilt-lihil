from lihil.config import AppConfig, ConfigBase, lhl_read_config


class MongoConfig(ConfigBase, kw_only=True):

    DIALECT: str
    USER: str | None = None
    PORT: int | None = None
    PASSWORD: str | None = None
    HOST: str | None = None
    DATABASE: str
    DIRECTCONNECTION: bool | None = None
    AUTHSOURCE: str | None = None

    @property
    def mongo_uri(self) -> str:
        """生成MongoDB连接URI"""
        user_part = (
            f"{self.USER}:{self.PASSWORD}@" if self.USER and self.PASSWORD else ""
        )
        port_part = f":{self.PORT}" if self.PORT else ""
        host_part = self.HOST or "localhost"
        db_name = self.DATABASE

        params = []
        if self.AUTHSOURCE:
            params.append(f"authSource={self.AUTHSOURCE}")
        if self.DIRECTCONNECTION:
            params.append("directConnection=true")

        query = "?" + "&".join(params) if params else ""

        return f"mongodb://{user_part}{host_part}{port_part}/{db_name}{query}"


class MSSQLConfig(ConfigBase, kw_only=True):

    DIALECT: str
    USER: str
    PORT: int
    PASSWORD: str
    HOST: str
    DATABASE: str
    Trusted_Connection: bool

    @property
    def mssql_uri(self) -> str:
        """生成通用的基本MS SQLServer连接URI"""
        return f"Server={self.HOST};Database={self.DATABASE};User Id={self.USER};Password={self.PASSWORD};Port={self.PORT};Trusted_Connection={self.Trusted_Connection};"


class RedisConfig(ConfigBase, kw_only=True):

    DIALECT: str
    PORT: int
    PASSWORD: str
    HOST: str
    DATABASE: int

    @property
    def redis_uri(self) -> str:
        """生成基本Redis连接字符串"""
        return f"redis://:{self.PASSWORD}@{self.HOST}:{self.PORT}/{self.DATABASE}"


class ProjectConfig(AppConfig, kw_only=True):

    API_VERSION: str = "1"
    mongo: MongoConfig | None = None
    mssql: MSSQLConfig | None = None
    redis: RedisConfig | None = None


def read_config(*config_files: str) -> ProjectConfig:
    app_config = lhl_read_config(
        *config_files, config_type=ProjectConfig, raise_on_not_found=False
    )
    assert app_config
    return app_config
