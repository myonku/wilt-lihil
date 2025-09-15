from lihil.config import AppConfig, ConfigBase, lhl_read_config
import urllib.parse


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
    DATASOURCE: str
    USER: str | None = None
    PORT: int | None = None
    PASSWORD: str | None = None
    HOST: str | None = None
    DATABASE: str
    TRUSTSERVERCERT: bool | None = None
    TRUSTEDCONNECTION: bool | None = None
    ENCRYPT: bool | None = None

    @property
    def mssql_uri(self) -> str:
        """生成通用的基本MS SQLServer连接URI"""
        user_part = (
            f"{self.USER}:{urllib.parse.quote(self.PASSWORD)}@"
            if self.USER and self.PASSWORD
            else ""
        )
        if self.DATASOURCE:
            datasource_part = self.DATASOURCE
        else:
            datasource_part = (
                f"{self.HOST}:{self.PORT}" if self.HOST and self.PORT else ""
            )
        db_name = self.DATABASE

        params = []
        params.append("driver=ODBC Driver 17 for SQL Server")
        if self.TRUSTEDCONNECTION is not None:
            params.append(
                f"Trusted_Connection={'yes' if self.TRUSTEDCONNECTION else 'no'}"
            )
        if self.ENCRYPT is not None:
            params.append(f"Encrypt={'yes' if self.ENCRYPT else 'no'}")
        if self.TRUSTSERVERCERT is not None:
            params.append(
                f"TrustServerCertificate={'yes' if self.TRUSTSERVERCERT else 'no'}"
            )

        query = "?" + "&".join(params) if params else ""
        return f"mssql+aioodbc://{user_part}{datasource_part}/{db_name}{query}"


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
    sqlserver: MSSQLConfig | None = None
    redis: RedisConfig | None = None


def read_config(*config_files: str) -> ProjectConfig:
    app_config = lhl_read_config(
        *config_files, config_type=ProjectConfig, raise_on_not_found=False
    )
    assert app_config
    return app_config
