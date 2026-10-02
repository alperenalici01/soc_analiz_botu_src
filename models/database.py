from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime

# SQLite veritabanı dosyamızın adı (Kodu çalıştırdığımızda proje dizininde otomatik oluşacak)
SQLALCHEMY_DATABASE_URL = "sqlite:///./threat_hunter.db"

# Veritabanı motorunu başlatıyoruz (check_same_thread ayarı SQLite'ın çoklu işlemlerde çökmemesi için gerekli)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# 1. Tablo: Gelen Tüm API Trafiğinin Kaydedildiği Yer (Senin akış şemandaki yapı)
class APILog(Base):
    __tablename__ = "api_logs"

    log_id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String(45), index=True)
    endpoint = Column(String(255))
    http_method = Column(String(10))
    status_code = Column(Integer)
    payload_data = Column(Text, nullable=True)

    # İlişki: Bir logun birden fazla alarmı olabilir
    alerts = relationship("SecurityAlert", back_populates="log")

# 2. Tablo: Sadece Analiz Motorunun Yakaladığı Tehditler
class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    alert_id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("api_logs.log_id"))
    alert_type = Column(String(100))
    severity_level = Column(String(20)) # Kritik, Yüksek, Orta
    is_resolved = Column(Boolean, default=False)

    # İlişki: Bu alarmın hangi log satırından kaynaklandığını gösterir
    log = relationship("APILog", back_populates="alerts")