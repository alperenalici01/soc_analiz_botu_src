from pydantic import BaseModel
from datetime import datetime
from typing import Optional

# Dışarıdan gelecek API log isteğinin iskeleti
class APILogCreate(BaseModel):
    timestamp: datetime
    source_ip: str
    endpoint: str
    http_method: str
    status_code: int
    payload_data: Optional[str] = ""

# Botun tespit ettiği zafiyetin dışa vurum (yanıt) iskeleti
class SecurityAlertResponse(BaseModel):
    alert_id: int
    log_id: int
    alert_type: str
    severity_level: str
    is_resolved: bool = False

    class Config:
        from_attributes = True # SQLAlchemy (Veritabanı) objelerini otomatik JSON'a çevirmek için gerekli