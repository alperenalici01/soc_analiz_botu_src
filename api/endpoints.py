import csv
import io
from collections import Counter
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload
from fastapi.responses import Response

from core import rule_engine
from core.config import PROJECT_ROOT
from core.file_monitor import LiveLogMonitor, scan_log_file
from core.ingestion import ingest_log
from core.log_parser import parse_log_line
from models.database import APILog, FileCheckpoint, SecurityAlert, SessionLocal
from models.schemas import APILogCreate, LiveLogStart, SecurityAlertResponse, TextLogIngest


router = APIRouter()
DEMO_LOG_PATH = PROJECT_ROOT / "dummy_data" / "server_access.log"
live_log_monitor = LiveLogMonitor()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/live-monitor/status/")
def get_live_monitor_status():
    return live_log_monitor.get_status()


@router.post("/live-monitor/start/")
async def start_live_monitor(request: LiveLogStart):
    requested_paths = request.file_paths or ([request.file_path] if request.file_path else [])
    if not requested_paths:
        raise HTTPException(status_code=422, detail="At least one log file path is required.")
    paths = []
    for requested_path in requested_paths:
        path = Path(requested_path).expanduser()
        if not path.is_absolute():
            raise HTTPException(status_code=422, detail=f"Log file path must be absolute: {path}")
        try:
            path = path.resolve(strict=True)
        except OSError as error:
            raise HTTPException(status_code=404, detail=f"Log file not found: {path}") from error
        if not path.is_file():
            raise HTTPException(status_code=400, detail=f"The selected path is not a file: {path}")
        if path.suffix.lower() not in {".log", ".jsonl", ".txt"}:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported log file extension: {path}. Use .log, .jsonl, or .txt.",
            )
        paths.append(path)
    try:
        return await live_log_monitor.start(paths)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@router.post("/live-monitor/stop/")
async def stop_live_log_monitor():
    return await live_log_monitor.stop()


def _persist_log(db: Session, log_data: APILogCreate, raw_line: Optional[str] = None):
    result = ingest_log(
        db,
        log_data,
        raw_line=raw_line,
        source_file=log_data.source_file,
    )
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
        result = ingest_log(
            db,
            log_data,
            raw_line=raw_line,
            source_file=request.source_file,
        )
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


@router.get("/alerts/", response_model=list[SecurityAlertResponse])
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


def _get_report_data(db: Session, attacker_limit: Optional[int] = 8):
    threat_log_count = (
        db.query(func.count(func.distinct(APILog.log_id)))
        .join(SecurityAlert, SecurityAlert.log_id == APILog.log_id)
        .scalar()
    )
    attacker_query = (
        db.query(
            APILog.source_ip.label("source_ip"),
            func.count(func.distinct(APILog.log_id)).label("count"),
        )
        .join(SecurityAlert, SecurityAlert.log_id == APILog.log_id)
        .filter(APILog.source_ip.isnot(None))
        .group_by(APILog.source_ip)
        .order_by(func.count(func.distinct(APILog.log_id)).desc(), APILog.source_ip.asc())
    )
    if attacker_limit is not None:
        attacker_query = attacker_query.limit(attacker_limit)

    vulnerability_types = (
        db.query(
            func.coalesce(SecurityAlert.alert_type, "Bilinmeyen alarm türü").label("alert_type"),
            func.count(SecurityAlert.alert_id).label("count"),
        )
        .group_by(func.coalesce(SecurityAlert.alert_type, "Bilinmeyen alarm türü"))
        .order_by(func.count(SecurityAlert.alert_id).desc(), SecurityAlert.alert_type.asc())
        .all()
    )
    imported_files = {}
    imported_logs = (
        db.query(APILog)
        .options(selectinload(APILog.alerts))
        .filter(APILog.source_file.isnot(None))
        .order_by(APILog.source_file.asc(), APILog.timestamp.asc(), APILog.log_id.asc())
        .all()
    )
    for log in imported_logs:
        source_file = str(log.source_file)
        report_file = imported_files.setdefault(
            source_file,
            {
                "source_file": source_file,
                "file_name": Path(source_file).name or source_file,
                "total_logs": 0,
                "threat_logs": 0,
                "total_alerts": 0,
                "top_attackers": Counter(),
                "vulnerability_types": Counter(),
                "logs": [],
            },
        )
        report_file["total_logs"] += 1
        report_file["total_alerts"] += len(log.alerts)
        if log.alerts:
            report_file["threat_logs"] += 1
        if log.source_ip is not None and log.alerts:
            report_file["top_attackers"][log.source_ip] += 1
        alerts = []
        for alert in log.alerts:
            alert_type = alert.alert_type or "Bilinmeyen alarm türü"
            report_file["vulnerability_types"][alert_type] += 1
            alerts.append({
                "alert_type": alert_type,
                "severity_level": alert.severity_level,
                "is_resolved": alert.is_resolved,
            })
        report_file["logs"].append({
            "log_id": log.log_id,
            "timestamp": log.timestamp.isoformat(),
            "source_ip": log.source_ip,
            "endpoint": log.endpoint,
            "http_method": log.http_method,
            "status_code": log.status_code,
            "payload_data": log.payload_data,
            "raw_line": log.raw_line,
            "alerts": alerts,
        })
    serialized_files = []
    for report_file in imported_files.values():
        report_file["top_attackers"] = [
            {"source_ip": source_ip, "count": count}
            for source_ip, count in report_file["top_attackers"].most_common()
        ]
        report_file["vulnerability_types"] = [
            {"alert_type": alert_type, "count": count}
            for alert_type, count in report_file["vulnerability_types"].most_common()
        ]
        serialized_files.append(report_file)

    return {
        "total_logs": db.query(func.count(APILog.log_id)).scalar() or 0,
        "threat_logs": threat_log_count or 0,
        "total_alerts": db.query(func.count(SecurityAlert.alert_id)).scalar() or 0,
        "top_attackers": [
            {"source_ip": row.source_ip, "count": row.count}
            for row in attacker_query.all()
        ],
        "vulnerability_types": [
            {"alert_type": row.alert_type, "count": row.count}
            for row in vulnerability_types
        ],
        "imported_files": serialized_files,
    }


@router.get("/reports/")
def get_report(db: Session = Depends(get_db)):
    return _get_report_data(db)


@router.post("/data/reset/")
def reset_test_data(db: Session = Depends(get_db)):
    deleted_checkpoints = db.query(FileCheckpoint).delete(synchronize_session=False)
    deleted_alerts = db.query(SecurityAlert).delete(synchronize_session=False)
    deleted_logs = db.query(APILog).delete(synchronize_session=False)
    db.commit()
    return {
        "deleted_logs": deleted_logs,
        "deleted_alerts": deleted_alerts,
        "deleted_checkpoints": deleted_checkpoints,
        "message": "Log, alarm ve dosya tarama kayıtları silindi. Kullanıcılar ve roller korundu.",
    }


def _safe_csv_cell(value):
    text = str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{text}"
    return text


@router.get("/reports/export.csv")
def get_report_csv(db: Session = Depends(get_db)):
    report = _get_report_data(db, attacker_limit=None)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "Rapor bölümü",
        "Kategori",
        "Değer",
        "Adet",
        "Zaman",
        "Metot",
        "Hedef",
        "Durum kodu",
        "Payload / alarm",
    ])
    writer.writerow(["Özet", "Toplam log", "", report["total_logs"]])
    writer.writerow(["Özet", "Alarm üreten log", "", report["threat_logs"]])
    writer.writerow(["Özet", "Toplam alarm", "", report["total_alerts"]])
    for attacker in report["top_attackers"]:
        writer.writerow([
            "Top Attackers",
            "IP adresi",
            _safe_csv_cell(attacker["source_ip"]),
            attacker["count"],
        ])
    for vulnerability in report["vulnerability_types"]:
        writer.writerow([
            "Zafiyet türleri",
            "Alarm türü",
            _safe_csv_cell(vulnerability["alert_type"]),
            vulnerability["count"],
        ])
    for imported_file in report["imported_files"]:
        for log in imported_file["logs"]:
            writer.writerow([
                "Dosya kayıtları",
                _safe_csv_cell(imported_file["file_name"]),
                _safe_csv_cell(log["source_ip"] or ""),
                log["timestamp"] or "",
                _safe_csv_cell(log["http_method"] or ""),
                _safe_csv_cell(log["endpoint"] or ""),
                log["status_code"] or "",
                _safe_csv_cell(log["payload_data"] or log["raw_line"] or ""),
                _safe_csv_cell("; ".join(alert["alert_type"] for alert in log["alerts"])),
            ])
    return Response(
        content=f"\ufeff{output.getvalue()}",
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="guvenlik-raporu.csv"'},
    )


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
