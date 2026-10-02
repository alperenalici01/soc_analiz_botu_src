import logging
from pathlib import Path
from typing import Dict

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


def scan_watch_directory(directory: Path) -> Dict[str, int]:
    directory.mkdir(parents=True, exist_ok=True)
    totals = {"processed": 0, "invalid": 0}
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in {".log", ".jsonl"}:
            result = scan_log_file(path)
            totals["processed"] += result["processed"]
            totals["invalid"] += result["invalid"]
    return totals
