from . import (
    log_config,
)  # 通过导入启用uvicorn日志，该项目采用了日志中间件，如果只需要接口日志，可以注释该行
from typing import Literal
from lihil import Lihil, Request, Response, Route
from src.config import read_config
from starlette.middleware.cors import CORSMiddleware
from lihil.problems import problem_solver
from src.repo.factory import mongo, mssql, redis, session_dao, upload_session_dao
from src.api.http_errors import InternalError
from src.repo.redis_manager import RedisManager
from src.repo.db import MSSQLServer, MongoDB
from src.repo.models import Review, ReviewFlow, ReviewStage, UserProfile
from src.middlewares.session_middleware import session_middleware_factory
from src.middlewares.logging_middleware import logging_middleware_factory
from src.services.upload_cleanup_service import cleanup_service
from src.api.handshake import handshake
from src.api.auth import auth
from src.api.review import review
from src.api.user import user


@problem_solver
def handle_error(req: Request, exc: Literal[500] | InternalError) -> Response:
    return Response(f"Internal Error: {str(exc)}", 500)


async def lifespan(app: Lihil):
    config = read_config("settings.toml", ".env")

    await redis.connect(config)
    await mssql.connect(config, True, False)
    await mongo.connect(
        config,
        [ReviewStage, ReviewFlow, Review, UserProfile],
    )
    app.graph.register_singleton(mongo, MongoDB)
    app.graph.register_singleton(mssql, MSSQLServer)
    app.graph.register_singleton(redis, RedisManager)
    cleanup_service.start()

    yield

    await cleanup_service.stop()
    await redis.disconnect()
    await mongo.disconnect()
    await mssql.disconnect()


def app_factory() -> Lihil:
    app_config = read_config("settings.toml", ".env")

    root = Route(
        f"/api/v{app_config.API_VERSION}", deps=[session_dao, upload_session_dao]
    )
    root.include_subroutes(handshake, auth, review, user)
    root.sub("health").get(lambda: "ok")

    lhl = Lihil(root, app_config=app_config, lifespan=lifespan)
    lhl.add_middleware(
        [
            lambda app: CORSMiddleware(
                app,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            ),
            logging_middleware_factory,
            session_middleware_factory,
        ]
    )
    return lhl


app = app_factory()


if __name__ == "__main__":
    app.run(__file__)
