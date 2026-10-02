from datetime import timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from core.config import RATE_LIMIT_WINDOW_SECONDS
from core.rule_engine import analyze_log
from models.database import APILog, SecurityAlert
from models.schemas import APILogCreate


def ingest_log(
    db: Session,
    log_data: APILogCreate,
    raw_line: Optional[str] = None,
    source_file: Optional[str] = None,
) -> Dict[str, Any]:
    timestamp = log_data.timestamp
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    window_start = timestamp - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
    recent_count = (
        db.query(APILog)
        .filter(
            APILog.source_ip == log_data.source_ip,
            APILog.timestamp >= window_start,
            APILog.timestamp <= timestamp,
        )
        .count()
    )
    findings = analyze_log(log_data, recent_request_count=recent_count)
    stored_log = APILog(
        timestamp=timestamp,
        source_ip=log_data.source_ip,
        endpoint=log_data.endpoint,
        http_method=log_data.http_method,
        status_code=log_data.status_code,
        payload_data=log_data.payload_data,
        raw_line=raw_line,
        source_file=source_file,
    )
    db.add(stored_log)
    db.flush()

    alerts: List[Dict[str, Any]] = []
    for alert_type, severity in findings:
        alert = SecurityAlert(
            log_id=stored_log.log_id,
            alert_type=alert_type,
            severity_level=severity,
        )
        db.add(alert)
        alerts.append({"type": alert_type, "severity": severity})
    db.flush()

    return {
        "status": "danger" if alerts else "safe",
        "log_id": stored_log.log_id,
        "alerts": alerts,
        "alert_details": alerts[0] if alerts else None,
    }
