from . import log_config
from typing import Literal
from lihil import Lihil, Request, Response, Route
from src.config import read_config
from starlette.middleware.cors import CORSMiddleware
from lihil.problems import problem_solver
from repo.factory import (
    mongo,
    mssql,
    redis,
    review_dao,
    review_flow_dao,
    review_stage_dao,
    profile_dao,
    user_dao,
    group_dao,
    login_history_dao,
)
from repo.redis_manager import RedisManager, session_dao
from repo.db import MSSQLServer, MongoDB
from repo.models import Review, ReviewFlow, ReviewStage, UserProfile


@problem_solver
def handle_error(req: Request, exc: Literal[500]) -> Response:
    return Response(f"Internal Error: {str(exc)}", 500)


async def lifespan(app: Lihil):
    config = read_config("settings.toml", ".env")
    if not config.mongo:
        raise ConnectionError("Mongo配置初始化失败")
    if not config.mssql:
        raise ConnectionError("MySQL配置初始化失败")
    if not config.redis:
        raise ConnectionError("Redis配置初始化失败")
    await redis.connect(config.redis.redis_uri)
    await mongo.connect(
        config.mongo.mongo_uri,
        config.mongo.DATABASE,
        [ReviewStage, ReviewFlow, Review, UserProfile],
    )
    await mssql.connect(config.mssql.mssql_uri)
    app.graph.register_singleton(mongo, MongoDB)
    app.graph.register_singleton(mssql, MSSQLServer)
    app.graph.register_singleton(redis, RedisManager)

    yield

    await redis.disconnect()
    await mongo.disconnect()
    await mssql.disconnect()


def app_factory() -> Lihil:
    app_config = read_config("settings.toml", ".env")

    root = Route(
        f"/api/v{app_config.API_VERSION}",
        deps=[
            review_dao,
            review_flow_dao,
            review_stage_dao,
            profile_dao,
            user_dao,
            group_dao,
            login_history_dao,
            session_dao,
        ],
    )
    root.include_subroutes()
    root.sub("health").get(lambda: "ok")

    lhl = Lihil(root, app_config=app_config, lifespan=lifespan)
    lhl.add_middleware(
        lambda app: CORSMiddleware(
            app,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    )
    return lhl


app = app_factory()


if __name__ == "__main__":
    app.run(__file__)
