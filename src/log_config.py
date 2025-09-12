from datetime import datetime
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path


def setup_logging() -> logging.Logger:
    """配置日志系统"""
    try:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True, parents=True)

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        log_file = f"{log_dir}/app_{datetime.now().strftime('%Y-%m-%d')}.log"
        file_handler = TimedRotatingFileHandler(
            filename=log_file,
            when="midnight",
            interval=1,
            backupCount=14,
            encoding="utf-8",
        )

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)

        logger.addHandler(file_handler)

        uvicorn_loggers = ["uvicorn", "uvicorn.error", "uvicorn.access"]
        for name in uvicorn_loggers:
            uvicorn_logger = logging.getLogger(name)
            uvicorn_logger.setLevel(logging.INFO)
            uvicorn_logger.addHandler(file_handler)
            uvicorn_logger.propagate = False

        return logger

    except Exception as e:
        print(f"日志配置失败: {str(e)}")
        raise


setup_logging()
