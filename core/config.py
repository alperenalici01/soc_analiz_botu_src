import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "20"))
LOG_POLL_INTERVAL_SECONDS = float(os.getenv("LOG_POLL_INTERVAL_SECONDS", "5"))
LOG_WATCH_DIR = Path(os.getenv("LOG_WATCH_DIR", str(PROJECT_ROOT / "logs")))
if not LOG_WATCH_DIR.is_absolute():
    LOG_WATCH_DIR = PROJECT_ROOT / LOG_WATCH_DIR
LOG_WATCH_DIR = LOG_WATCH_DIR.resolve()

if RATE_LIMIT_WINDOW_SECONDS < 1:
    raise ValueError("RATE_LIMIT_WINDOW_SECONDS must be at least 1")
if RATE_LIMIT_MAX_REQUESTS < 1:
    raise ValueError("RATE_LIMIT_MAX_REQUESTS must be at least 1")
if LOG_POLL_INTERVAL_SECONDS <= 0:
    raise ValueError("LOG_POLL_INTERVAL_SECONDS must be greater than 0")
