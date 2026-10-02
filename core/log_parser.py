import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit

from models.schemas import APILogCreate


_COMMON_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referrer>[^"]*)" '
    r'"(?P<agent>[^"]*)")?$'
)


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("timestamp must be an ISO-8601 string")
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def parse_log_line(line: str) -> APILogCreate:
    """Parse a structured JSON log or an Apache/Nginx combined access-log line."""
    raw = line.strip()
    if not raw:
        raise ValueError("empty log line")

    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        record = None

    if isinstance(record, dict):
        timestamp = _parse_timestamp(record.get("timestamp", record.get("@timestamp")))
        source_ip = record.get("source_ip", record.get("ip", record.get("client_ip")))
        endpoint = record.get("endpoint", record.get("path", record.get("url")))
        method = record.get("http_method", record.get("method"))
        status = record.get("status_code", record.get("status"))
        payload = record.get("payload_data", record.get("payload", record.get("message", "")))
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload, ensure_ascii=False)
        elif payload is None:
            payload = ""
        if not all((source_ip, endpoint, method)) or status is None:
            raise ValueError("JSON log needs source_ip, endpoint, http_method and status_code")
        return APILogCreate(
            timestamp=timestamp,
            source_ip=str(source_ip),
            endpoint=str(endpoint),
            http_method=str(method).upper(),
            status_code=int(status),
            payload_data=str(payload),
        )

    match = _COMMON_LOG_PATTERN.match(raw)
    if not match:
        raise ValueError("unsupported format; use JSON Lines or Apache/Nginx combined access logs")

    timestamp = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
    timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    target = match.group("target")
    parsed_target = urlsplit(target)
    endpoint = parsed_target.path or "/"
    payload = unquote(parsed_target.query)
    if match.group("agent"):
        payload = f"{payload} {match.group('agent')}".strip()
    return APILogCreate(
        timestamp=timestamp,
        source_ip=match.group("ip"),
        endpoint=endpoint,
        http_method=match.group("method"),
        status_code=int(match.group("status")),
        payload_data=payload,
    )
