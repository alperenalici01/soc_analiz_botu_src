from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, selectinload

from core import rule_engine
from core.config import PROJECT_ROOT
from core.file_monitor import scan_log_file
from core.ingestion import ingest_log
from core.log_parser import parse_log_line
from models.database import APILog, SecurityAlert, SessionLocal
from models.schemas import APILogCreate, TextLogIngest


router = APIRouter()
DEMO_LOG_PATH = PROJECT_ROOT / "dummy_data" / "server_access.log"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _persist_log(db: Session, log_data: APILogCreate, raw_line: Optional[str] = None):
    result = ingest_log(db, log_data, raw_line=raw_line)
    db.commit()
    return result


@router.post("/analyze-log/")
def process_api_log(log_data: APILogCreate, db: Session = Depends(get_db)):
    result = _persist_log(db, log_data)
    result["message"] = (
        "Tehdit tespit edildi ve veritabanına kaydedildi."
        if result["alerts"]
        else "Log temiz, herhangi bir anormallik bulunmadı."
    )
    return result


@router.post("/ingest-text/")
def ingest_text_logs(request: TextLogIngest, db: Session = Depends(get_db)):
    results = []
    errors = []
    for line_number, raw_line in enumerate(request.content.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            log_data = parse_log_line(raw_line)
        except (ValueError, TypeError) as error:
            errors.append({"line": line_number, "error": str(error)})
            continue
        result = ingest_log(db, log_data, raw_line=raw_line)
        result["log"] = {
            "timestamp": log_data.timestamp.isoformat(),
            "source_ip": log_data.source_ip,
            "endpoint": log_data.endpoint,
            "http_method": log_data.http_method,
            "status_code": log_data.status_code,
            "payload_data": log_data.payload_data,
        }
        results.append(result)
    db.commit()
    return {
        "processed": len(results),
        "threats": sum(1 for result in results if result["alerts"]),
        "results": results,
        "errors": errors,
    }


@router.post("/demo/")
def load_demo_logs():
    if not DEMO_LOG_PATH.is_file():
        raise HTTPException(status_code=404, detail=f"Demo log file not found: {DEMO_LOG_PATH}")
    return scan_log_file(DEMO_LOG_PATH)


@router.get("/logs/")
def get_all_logs(limit: int = Query(default=50, ge=1, le=500), db: Session = Depends(get_db)):
    logs = (
        db.query(APILog)
        .options(selectinload(APILog.alerts))
        .order_by(APILog.timestamp.desc(), APILog.log_id.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "log_id": log.log_id,
            "timestamp": log.timestamp,
            "source_ip": log.source_ip,
            "endpoint": log.endpoint,
            "http_method": log.http_method,
            "status_code": log.status_code,
            "payload_data": log.payload_data,
            "alerts": [
                {
                    "alert_id": alert.alert_id,
                    "alert_type": alert.alert_type,
                    "severity_level": alert.severity_level,
                    "is_resolved": alert.is_resolved,
                }
                for alert in log.alerts
            ],
        }
        for log in logs
    ]


@router.get("/alerts/")
def get_all_alerts(limit: int = Query(default=50, ge=1, le=500), db: Session = Depends(get_db)):
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.alert_id.desc()).limit(limit).all()
    return [
        {
            "alert_id": alert.alert_id,
            "log_id": alert.log_id,
            "alert_type": alert.alert_type,
            "severity_level": alert.severity_level,
            "is_resolved": alert.is_resolved,
        }
        for alert in alerts
    ]


class SignatureCreate(BaseModel):
    signature: str = Field(min_length=1, max_length=200)


@router.get("/rules/")
def get_rules():
    return {
        "signatures": rule_engine.MALICIOUS_SIGNATURES,
        "sql_error_patterns": [pattern.pattern for pattern in rule_engine.SQL_ERROR_PATTERNS],
    }


@router.post("/rules/")
def add_rule(new_sig: SignatureCreate):
    signature = new_sig.signature.strip()
    if not signature:
        raise HTTPException(status_code=422, detail="Signature must not be blank")
    if signature.casefold() not in {item.casefold() for item in rule_engine.MALICIOUS_SIGNATURES}:
        rule_engine.MALICIOUS_SIGNATURES.append(signature)
        return {"status": "success", "message": "Yeni tehdit imzası bu sunucu oturumuna eklendi."}
    return {"status": "info", "message": "Bu imza zaten sistemde mevcut."}
