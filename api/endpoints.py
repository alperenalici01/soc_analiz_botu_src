from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from models.schemas import APILogCreate
from models.database import SessionLocal, APILog, SecurityAlert
from core.rule_engine import analyze_log
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from models.schemas import APILogCreate
from models.database import SessionLocal, APILog, SecurityAlert
from core.rule_engine import analyze_log
import core.rule_engine as rule_engine # Kural listesine erişmek için
from pydantic import BaseModel # Kural ekleme şeması için

# API rotalarımızı yönetecek nesne
router = APIRouter()

# Veritabanı oturumu (session) açmak ve kapatmak için yardımcı fonksiyon
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 1. MEVCUT ROTAMIZ: Yeni gelen logları analiz eder ve veritabanına yazar (POST)
@router.post("/analyze-log/")
def process_api_log(log_data: APILogCreate, db: Session = Depends(get_db)):
    threat_found, threat_type, severity = analyze_log(log_data)

    new_log = APILog(
        timestamp=log_data.timestamp,
        source_ip=log_data.source_ip,
        endpoint=log_data.endpoint,
        http_method=log_data.http_method,
        status_code=log_data.status_code,
        payload_data=log_data.payload_data
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log) 

    if threat_found:
        new_alert = SecurityAlert(
            log_id=new_log.log_id, 
            alert_type=threat_type,
            severity_level=severity
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        
        return {
            "status": "danger",
            "message": "Tehdit tespit edildi ve veritabanına kaydedildi!",
            "alert_details": {
                "alert_id": new_alert.alert_id,
                "type": threat_type,
                "severity": severity
            }
        }

    return {
        "status": "safe",
        "message": "Log temiz, herhangi bir anormallik bulunmadı."
    }

# ---------------------------------------------------------
# YENİ EKLENEN ROTALAR: Arayüzdeki DB Geçmişi Menüsü İçin
# ---------------------------------------------------------

# 2. YENİ ROTA: Tüm log geçmişini getirir (Son 50 kayıt)
@router.get("/logs/")
def get_all_logs(limit: int = 50, db: Session = Depends(get_db)):
    """Arayüzdeki geçmiş kayıtlar tablosu için tüm logları döndürür."""
    # SQLAlchemy ile api_logs tablosundan en yeni kayıtları çekiyoruz
    logs = db.query(APILog).order_by(APILog.timestamp.desc()).limit(limit).all()
    return logs

# 3. YENİ ROTA: Sadece tespit edilen alarmları getirir (Son 50 kayıt)
@router.get("/alerts/")
def get_all_alerts(limit: int = 50, db: Session = Depends(get_db)):
    """Sadece kural motorunun yakaladığı kritik zafiyetleri döndürür."""
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.alert_id.desc()).limit(limit).all()
    return alerts

# --- KURAL MOTORU İÇİN ROTALAR ---

class SignatureCreate(BaseModel):
    signature: str

@router.get("/rules/")
def get_rules():
    """Aktif zararlı payload imzalarını döndürür."""
    return {"signatures": rule_engine.MALICIOUS_SIGNATURES}

@router.post("/rules/")
def add_rule(new_sig: SignatureCreate):
    """Sisteme canlı olarak yeni bir zararlı imza ekler."""
    if new_sig.signature not in rule_engine.MALICIOUS_SIGNATURES:
        rule_engine.MALICIOUS_SIGNATURES.append(new_sig.signature)
        return {"status": "success", "message": "Yeni tehdit imzası başarıyla eklendi."}
    return {"status": "info", "message": "Bu imza zaten sistemde mevcut."}