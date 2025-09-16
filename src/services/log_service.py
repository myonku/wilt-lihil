import asyncio
from datetime import datetime
from pathlib import Path
from abc import ABC, abstractmethod
import pytz

from src.repo.models import LogRecord


class ILogService(ABC):
    """日志服务接口"""

    @abstractmethod
    async def write_log_async(self, log: LogRecord) -> None:
        """写入日志"""
        pass


class TextFileLogService(ILogService):
    """文本文件日志服务"""

    def __init__(self, log_dir: str = "logs/req_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._semaphore = asyncio.Semaphore(1)

    @property
    def log_file_path(self) -> Path:
        """获取当前日志文件路径"""
        return self.log_dir / f"app_{datetime.now().strftime('%Y-%m-%d')}.log"

    async def write_log_async(self, log: LogRecord) -> None:
        """写入日志"""
        log_line = self._format_log_line(log)

        async with self._semaphore:
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")

    def _format_log_line(self, log: LogRecord) -> str:
        """格式化日志行"""
        if log.EndTime:
            duration = (log.EndTime - log.StartTime).total_seconds() * 1000
        else:
            duration = 0

        china_tz = pytz.timezone("Asia/Shanghai")
        if log.StartTime.tzinfo is None:
            StartTime_utc = log.StartTime.replace(tzinfo=pytz.UTC)
        else:
            StartTime_utc = log.StartTime.astimezone(pytz.UTC)

        StartTime_utc8 = StartTime_utc.astimezone(china_tz)

        parts = [
            f"[{StartTime_utc8.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}]",
            f"Method={log.HttpMethod}",
            f"Path={log.Path}",
            f"User={(log.UserId or 'Anonymous')}",
            f"Status={log.Status or 'Unknown'}",
            f"Duration={duration:.2f}ms",
        ]

        if log.ErrorMessage:
            error_msg = log.ErrorMessage.replace('"', "'")
            parts.append(f'Error="{error_msg}"')

        return " | ".join(parts)
