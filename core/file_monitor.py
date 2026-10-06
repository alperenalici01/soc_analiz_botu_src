import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from sqlalchemy.exc import SQLAlchemyError

from core.config import LIVE_LOG_POLL_INTERVAL_SECONDS
from core.ingestion import ingest_log
from core.log_parser import parse_log_line
from models.database import FileCheckpoint, SessionLocal


logger = logging.getLogger(__name__)


def scan_log_file(path: Path) -> Dict[str, int]:
    """Ingest complete new lines from one file and commit its cursor atomically."""
    resolved_path = path.resolve()
    with SessionLocal() as db:
        checkpoint = db.get(FileCheckpoint, str(resolved_path))
        stat = resolved_path.stat()
        file_identity = f"{stat.st_dev}:{stat.st_ino}"
        offset = checkpoint.byte_offset if checkpoint else 0
        line_number = checkpoint.line_number if checkpoint else 0
        if checkpoint and checkpoint.file_identity and checkpoint.file_identity != file_identity:
            logger.warning("Detected rotation of monitored log file %s; restarting at byte 0", resolved_path)
            offset = 0
            line_number = 0
        size = stat.st_size
        if size < offset:
            logger.warning("Detected truncation of monitored log file %s; restarting at byte 0", resolved_path)
            offset = 0
            line_number = 0

        with resolved_path.open("rb") as log_file:
            log_file.seek(offset)
            data = log_file.read()
        complete_length = data.rfind(b"\n") + 1
        if complete_length == 0:
            if checkpoint is None:
                checkpoint = FileCheckpoint(file_path=str(resolved_path), byte_offset=offset)
                db.add(checkpoint)
            checkpoint.byte_offset = offset
            checkpoint.line_number = line_number
            checkpoint.file_identity = file_identity
            db.commit()
            return {"processed": 0, "invalid": 0}

        lines = data[:complete_length].splitlines()
        processed = 0
        invalid = 0
        for current_line_number, raw_bytes in enumerate(lines, start=line_number + 1):
            raw_line = raw_bytes.decode("utf-8", errors="replace").strip()
            if not raw_line:
                continue
            try:
                parsed = parse_log_line(raw_line)
            except (ValueError, TypeError) as error:
                invalid += 1
                logger.warning(
                    "Skipping invalid log entry at line %d in %s: %s",
                    current_line_number,
                    resolved_path,
                    error,
                )
                continue
            ingest_log(db, parsed, raw_line=raw_line, source_file=str(resolved_path))
            processed += 1

        if checkpoint is None:
            checkpoint = FileCheckpoint(file_path=str(resolved_path), byte_offset=0)
            db.add(checkpoint)
        checkpoint.byte_offset = offset + complete_length
        checkpoint.line_number = line_number + len(lines)
        checkpoint.file_identity = file_identity
        db.commit()
        return {"processed": processed, "invalid": invalid}


class LiveLogMonitor:
    def __init__(self, poll_interval_seconds: float = LIVE_LOG_POLL_INTERVAL_SECONDS):
        self.poll_interval_seconds = poll_interval_seconds
        self.path: Path | None = None
        self.task: asyncio.Task | None = None
        self.state = "stopped"
        self.last_scan: str | None = None
        self.processed = 0
        self.invalid = 0
        self.error: str | None = None

    def get_status(self) -> Dict[str, object]:
        active = self.task is not None and not self.task.done()
        return {
            "active": active,
            "state": self.state,
            "file_path": str(self.path) if self.path else None,
            "last_scan": self.last_scan,
            "processed": self.processed,
            "invalid": self.invalid,
            "error": self.error,
            "poll_interval_seconds": self.poll_interval_seconds,
        }

    async def start(self, path: Path) -> Dict[str, object]:
        if self.task is not None and not self.task.done():
            raise RuntimeError("A live log file is already being monitored.")

        self.path = path.resolve(strict=True)
        self.processed = 0
        self.invalid = 0
        self.last_scan = None
        self.error = None
        self.state = "starting"
        self.task = asyncio.create_task(self._watch_file())
        return self.get_status()

    async def stop(self) -> Dict[str, object]:
        task = self.task
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.task = None
        if self.state != "error":
            self.state = "stopped"
        return self.get_status()

    async def _watch_file(self) -> None:
        try:
            while self.path is not None:
                try:
                    result = await asyncio.to_thread(scan_log_file, self.path)
                except (OSError, SQLAlchemyError) as error:
                    logger.exception("Live log scan failed for %s", self.path)
                    self.error = str(error)
                    self.state = "error"
                    return
                self.processed += result["processed"]
                self.invalid += result["invalid"]
                self.last_scan = datetime.now(timezone.utc).isoformat()
                self.state = "running"
                await asyncio.sleep(self.poll_interval_seconds)
        except asyncio.CancelledError:
            self.state = "stopped"
            raise
