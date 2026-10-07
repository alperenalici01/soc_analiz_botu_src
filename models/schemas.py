from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

# Dışarıdan gelecek API log isteğinin iskeleti
class APILogCreate(BaseModel):
    timestamp: datetime
    source_ip: str
    endpoint: str
    http_method: str
    status_code: int
    payload_data: Optional[str] = ""
    source_file: Optional[str] = None

# Botun tespit ettiği zafiyetin dışa vurum (yanıt) iskeleti
class SecurityAlertResponse(BaseModel):
    alert_id: int
    log_id: int
    alert_type: str
    severity_level: str
    is_resolved: bool = False


class TextLogIngest(BaseModel):
    content: str
    source_file: Optional[str] = None


class LiveLogStart(BaseModel):
    file_path: Optional[str] = None
    file_paths: list[str] = Field(default_factory=list)