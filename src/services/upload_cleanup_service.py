import asyncio
import logging
import shutil
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class AsyncUploadCleanupService:

    def __init__(
        self,
        temp_upload_root: str = "tempuploads",
        cleanup_interval: int = 600,
        expiration_hours: int = 6,
    ):
        self.temp_upload_root = Path(temp_upload_root)
        self.cleanup_interval = cleanup_interval
        self.expiration_hours = expiration_hours
        self._cleanup_task = None
        self._running = False

        self.temp_upload_root.mkdir(exist_ok=True, parents=True)

    async def clean_expired_uploads(self):
        """异步清理过期的上传文件"""
        try:
            if not self.temp_upload_root.exists():
                return

            current_time = datetime.now()
            cleaned_count = 0

            for upload_dir in self.temp_upload_root.iterdir():
                if upload_dir.is_dir():
                    creation_time = datetime.fromtimestamp(upload_dir.stat().st_ctime)

                    if current_time - creation_time > timedelta(
                        hours=self.expiration_hours
                    ):
                        try:
                            await asyncio.to_thread(shutil.rmtree, upload_dir)
                            cleaned_count += 1
                            logger.info(
                                f"Cleaned expired upload directory: {upload_dir.name}"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to clean directory {upload_dir.name}: {e}"
                            )

            if cleaned_count > 0:
                logger.info(f"Cleaned {cleaned_count} expired upload directories")

        except Exception as e:
            logger.error(f"Error in clean_expired_uploads: {e}")

    async def _cleanup_loop(self):
        """清理循环"""
        while self._running:
            try:
                await self.clean_expired_uploads()
                await asyncio.sleep(self.cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(60)

    def start(self):
        """启动清理服务"""
        if not self._running:
            self._running = True
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Async upload cleanup service started")

    async def stop(self):
        """停止清理服务"""
        if self._running:
            self._running = False
            if self._cleanup_task:
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass
            logger.info("Async upload cleanup service stopped")


cleanup_service = AsyncUploadCleanupService()
