from io import BytesIO
from typing import Any
from lihil import Form, Param, Route, Annotated, status
import asyncio
from lihil.plugins.premier import PremierPlugin
from premier import Throttler
from services.user_service import UserService
from repo.redis_manager import RedisManager


auth = Route("auth", deps=[UserService, RedisManager])

plugin = PremierPlugin(throttler=Throttler())

