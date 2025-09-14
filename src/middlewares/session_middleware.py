from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.requests import Request
from starlette.responses import JSONResponse
from src.repo.redis_manager import SessionDAO


class SessionMiddleware:
    """Session 合法性验证中间件"""

    def __init__(self, app: ASGIApp, session_dao: SessionDAO):
        self.app = app
        self.session_dao = session_dao
        self.session_header = "Session-Id"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        if self._is_open_upath(request):
            await self.app(scope, receive, send)
            return

        session_id = request.headers.get(self.session_header)

        if not session_id:
            response = JSONResponse(
                status_code=401, content={"error": "Session ID is required"}
            )
            await response(scope, receive, send)
            return

        session = await self.session_dao.get_session(session_id)
        if not session:
            response = JSONResponse(
                status_code=401, content={"error": "Session is Invalid!"}
            )
            await response(scope, receive, send)
            return

        scope["session_id"] = session_id

        await self.app(scope, receive, send)

    def _is_open_upath(self, request: Request) -> bool:
        """检查是否是开放路由"""
        path = request.url.path
        return path.endswith(("/health", "/handshake/init", "/favicon.ico"))


def session_middleware_factory(app: ASGIApp) -> ASGIApp:
    """
    Session 中间件工厂

    由于中间件在应用启动时创建，而 SessionDAO 需要 Redis 连接，所以使用延迟初始化的方式
    """

    # 创建一个包装器，在第一次调用时初始化真正的中间件
    class LazySessionMiddleware:
        def __init__(self, app: ASGIApp):
            self.app = app
            self._middleware = None
            self._session_dao = None

        async def __call__(self, scope, receive, send):
            if self._middleware is None:
                # 延迟初始化
                from src.repo.factory import redis

                if not redis.is_initialized:
                    # 如果 Redis 未初始化，跳过 Session 验证
                    await self.app(scope, receive, send)
                    return

                self._session_dao = SessionDAO(redis)
                self._middleware = SessionMiddleware(self.app, self._session_dao)

            await self._middleware(scope, receive, send)

    return LazySessionMiddleware(app)
