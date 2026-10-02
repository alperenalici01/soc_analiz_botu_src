import re
from typing import List, Tuple
from urllib.parse import unquote

from core.config import RATE_LIMIT_MAX_REQUESTS
from models.schemas import APILogCreate


MALICIOUS_SIGNATURES = [
    "' OR 1=1", "UNION SELECT", "DROP TABLE", "--", "' OR '1'='1",
    "WAITFOR DELAY", "SLEEP(", "EXEC xp_cmdshell",
    "<script>", "javascript:", "onerror=", "onload=", "document.cookie",
    "<img src=", "alert(1)",
    "../", "..\\", "/etc/passwd", "C:\\Windows\\System32", "/etc/shadow",
    "; ls", "| whoami", "&& cat", "$(whoami)", "|| dir",
    "${jndi:", '{"$gt":', '{"$ne":', "<!ENTITY",
]

SQL_ERROR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bsql syntax\b",
        r"\bsyntax error\b",
        r"\bsqlite(?:3)?\.error\b",
        r"\boperationalerror\b",
        r"\bintegrityerror\b",
        r"\bmysql(?: error)?\b",
        r"\bpostgres(?:ql)?(?: error)?\b",
        r"\bora-\d{5}\b",
        r"\bquery failed\b",
        r"\bdatabase exception\b",
    )
]


def analyze_log(
    log: APILogCreate,
    recent_request_count: int = 0,
) -> List[Tuple[str, str]]:
    """Return every deterministic detection and its severity for one log event."""
    findings: List[Tuple[str, str]] = []
    searchable_text = unquote(f"{log.endpoint} {log.payload_data or ''}")
    lower_text = searchable_text.lower()

    if log.status_code == 403:
        findings.append(("403 Forbidden yetkisiz erişim denemesi", "Yüksek"))
    elif log.status_code == 429:
        findings.append(("Rate Limit yanıtı (HTTP 429)", "Orta"))

    if log.http_method.upper() == "POST":
        matched_signature = next(
            (signature for signature in MALICIOUS_SIGNATURES if signature.lower() in lower_text),
            None,
        )
        if matched_signature:
            findings.append((f"Şüpheli POST payload imzası ({matched_signature})", "Kritik"))

    raw_payload = log.payload_data or ""
    if any(pattern.search(raw_payload) for pattern in SQL_ERROR_PATTERNS):
        findings.append(("Başarısız SQL sorgusu / veritabanı hatası", "Yüksek"))

    if recent_request_count + 1 > RATE_LIMIT_MAX_REQUESTS:
        findings.append(("Rate Limit ihlali (IP istek eşiği aşıldı)", "Orta"))

    return findings
