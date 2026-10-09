import asyncio
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, TypedDict

from sqlalchemy.exc import SQLAlchemyError

from core.config import LIVE_LOG_POLL_INTERVAL_SECONDS
from core.ingestion import ingest_log
from core.log_parser import parse_log_line
from models.database import FileCheckpoint, SessionLocal


logger = logging.getLogger(__name__)
DB_WRITE_LOCK = threading.Lock()


class FileMonitorStatus(TypedDict):
    file_path: str
    active: bool
    state: str
    last_scan: str | None
    processed: int
    invalid: int
    error: str | None


class LiveMonitorStatus(TypedDict):
    active: bool
    state: str
    file_path: str | None
    file_paths: list[str]
    last_scan: str | None
    processed: int
    invalid: int
    error: str | None
    files: list[FileMonitorStatus]
    poll_interval_seconds: float


@dataclass
class MonitoredFile:
    path: Path
    task: asyncio.Task | None = None
    state: str = "starting"
    last_scan: str | None = None
    processed: int = 0
    invalid: int = 0
    error: str | None = None


def scan_log_file(path: Path) -> Dict[str, int]:
    """Ingest complete new lines from one file and commit its cursor atomically."""
    resolved_path = path.resolve()
    with DB_WRITE_LOCK:
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
        self.files: Dict[str, MonitoredFile] = {}

    def get_status(self) -> LiveMonitorStatus:
        file_statuses = []
        for monitored in self.files.values():
            active = monitored.task is not None and not monitored.task.done()
            file_status: FileMonitorStatus = {
                "file_path": str(monitored.path),
                "active": active,
                "state": monitored.state,
                "last_scan": monitored.last_scan,
                "processed": monitored.processed,
                "invalid": monitored.invalid,
                "error": monitored.error,
            }
            file_statuses.append(file_status)
        active = any(file_status["active"] for file_status in file_statuses)
        states = {file_status["state"] for file_status in file_statuses}
        if "error" in states:
            state = "error"
        elif "starting" in states and active:
            state = "starting"
        elif active:
            state = "running"
        else:
            state = "stopped"
        errors = [
            f"{file_status['file_path']}: {file_status['error']}"
            for file_status in file_statuses
            if file_status["error"]
        ]
        last_scans = [file_status["last_scan"] for file_status in file_statuses if file_status["last_scan"]]
        return {
            "active": active,
            "state": state,
            "file_path": file_statuses[0]["file_path"] if len(file_statuses) == 1 else None,
            "file_paths": [file_status["file_path"] for file_status in file_statuses],
            "last_scan": max(last_scans) if last_scans else None,
            "processed": sum(file_status["processed"] for file_status in file_statuses),
            "invalid": sum(file_status["invalid"] for file_status in file_statuses),
            "error": "; ".join(errors) if errors else None,
            "files": file_statuses,
            "poll_interval_seconds": self.poll_interval_seconds,
        }

    async def start(self, paths: Path | Iterable[Path]) -> LiveMonitorStatus:
        if any(item.task is not None and not item.task.done() for item in self.files.values()):
            raise RuntimeError("A live log file is already being monitored.")

        if isinstance(paths, Path):
            paths = [paths]
        unique_paths = {}
        for path in paths:
            resolved_path = path.resolve(strict=True)
            unique_paths[str(resolved_path)] = resolved_path
        if not unique_paths:
            raise ValueError("At least one log file path is required.")
        self.files = {
            key: MonitoredFile(path=path)
            for key, path in unique_paths.items()
        }
        for monitored in self.files.values():
            monitored.task = asyncio.create_task(self._watch_file(monitored))
        return self.get_status()

    async def stop(self) -> LiveMonitorStatus:
        tasks = [
            monitored.task
            for monitored in self.files.values()
            if monitored.task is not None and not monitored.task.done()
        ]
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        return self.get_status()

    async def _watch_file(self, monitored: MonitoredFile) -> None:
        try:
            while True:
                try:
                    result = await asyncio.to_thread(scan_log_file, monitored.path)
                except (OSError, SQLAlchemyError) as error:
                    logger.exception("Live log scan failed for %s", monitored.path)
                    monitored.error = str(error)
                    monitored.state = "error"
                    return
                monitored.processed += result["processed"]
                monitored.invalid += result["invalid"]
                monitored.last_scan = datetime.now(timezone.utc).isoformat()
                monitored.state = "running"
                await asyncio.sleep(self.poll_interval_seconds)
        except asyncio.CancelledError:
            if monitored.state != "error":
                monitored.state = "stopped"
            raise
