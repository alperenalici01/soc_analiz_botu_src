from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime
import os

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_hunter.db")

connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args=connect_args
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
    raw_line = Column(Text, nullable=True)
    source_file = Column(String(512), nullable=True, index=True)

    alerts = relationship("SecurityAlert", back_populates="log")

# 2. Tablo: Sadece Analiz Motorunun Yakaladığı Tehditler
class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    alert_id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("api_logs.log_id", ondelete="CASCADE"), nullable=False, index=True)
    alert_type = Column(String(255))
    severity_level = Column(String(20)) # Kritik, Yüksek, Orta
    is_resolved = Column(Boolean, default=False)

    log = relationship("APILog", back_populates="alerts")


class Role(Base):
    __tablename__ = "roles"

    role_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False, unique=True)
    description = Column(String(255), nullable=False)

    users = relationship("User", back_populates="role")


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=True, unique=True)
    role_id = Column(Integer, ForeignKey("roles.role_id"), nullable=False, index=True)

    role = relationship("Role", back_populates="users")


class FileCheckpoint(Base):
    __tablename__ = "file_checkpoints"

    file_path = Column(String(512), primary_key=True)
    byte_offset = Column(Integer, nullable=False, default=0)
    line_number = Column(Integer, nullable=False, default=0)
    file_identity = Column(String(128), nullable=True)


def seed_default_roles():
    with SessionLocal() as db:
        for name, description in (
            ("admin", "Kullanıcı ve sistem yönetimi"),
            ("analyst", "Log ve alarm inceleme"),
            ("viewer", "Salt okunur izleme"),
        ):
            if db.query(Role).filter_by(name=name).first() is None:
                db.add(Role(name=name, description=description))
        db.commit()