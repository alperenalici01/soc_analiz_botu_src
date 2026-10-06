import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "20"))
LIVE_LOG_POLL_INTERVAL_SECONDS = float(os.getenv("LIVE_LOG_POLL_INTERVAL_SECONDS", "1"))

if RATE_LIMIT_WINDOW_SECONDS < 1:
    raise ValueError("RATE_LIMIT_WINDOW_SECONDS must be at least 1")
if RATE_LIMIT_MAX_REQUESTS < 1:
    raise ValueError("RATE_LIMIT_MAX_REQUESTS must be at least 1")
if LIVE_LOG_POLL_INTERVAL_SECONDS <= 0:
    raise ValueError("LIVE_LOG_POLL_INTERVAL_SECONDS must be greater than 0")
