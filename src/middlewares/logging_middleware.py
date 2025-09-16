import asyncio
from datetime import datetime
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.requests import Request
from collections.abc import Callable

from src.repo.models import LogRecord
from src.services.log_service import ILogService, TextFileLogService
from src.repo.redis_manager import SessionDAO


class LoggingMiddleware:
    """日志中间件"""

    def __init__(
        self,
        next_app: ASGIApp,
        log_service: ILogService,
        get_session_dao: Callable | None = None,
    ):
        self.next_app = next_app
        self.log_service = log_service
        self.get_session_dao = get_session_dao
        self._session_dao: SessionDAO | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.next_app(scope, receive, send)
            return
        request = Request(scope, receive)

        log_record = LogRecord(
            StartTime=datetime.now(),
            Path=request.url.path,
            HttpMethod=request.method,
            UserId=await self._get_user_id(request),
        )

        try:
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    log_record.Status = (
                        "Error" if message["status"] >= 400 else "Success"
                    )
                await send(message)
            await self.next_app(scope, receive, send_wrapper)
        except Exception as ex:
            log_record.Status = "Error"
            log_record.ErrorMessage = str(ex)
            raise
        finally:
            log_record.EndTime = datetime.now()
            asyncio.create_task(self.log_service.write_log_async(log_record))

    async def _get_user_id(self, request: Request) -> str | None:
        """从请求中获取用户ID"""
        if not self.get_session_dao:
            return None

        session_id = request.headers.get("Session-Id")
        if not session_id:
            return None

        try:
            if self._session_dao is None:
                self._session_dao = await self.get_session_dao()

            if self._session_dao:
                session = await self._session_dao.get_session(session_id)
                return session.UserId if session else None
            return None
        except:
            return None


class LazyLoggingMiddleware:
    """延迟初始化的日志中间件"""

    def __init__(self, app: ASGIApp):
        self.app = app
        self._middleware = None
        self._log_service = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._middleware is None:
            # 延迟初始化日志服务和中间件
            self._log_service = TextFileLogService()

            async def get_session_dao():
                try:
                    from src.repo.factory import redis

                    if redis.is_initialized:
                        return SessionDAO(redis)
                    return None
                except (ImportError, AttributeError):
                    return None

            self._middleware = LoggingMiddleware(
                self.app, self._log_service, get_session_dao
            )

        await self._middleware(scope, receive, send)


def logging_middleware_factory(app: ASGIApp) -> ASGIApp:
    """延迟初始化的日志中间件工厂"""
    return LazyLoggingMiddleware(app)
