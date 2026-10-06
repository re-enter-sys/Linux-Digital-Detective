import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.timeline.events import Event


# ------------------------------------------------------------------
# Common Apache/Nginx access log format
# ------------------------------------------------------------------

ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<source_ip>\S+)\s+'
    r'\S+\s+'
    r'\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+'
    r'(?P<path>\S+)'
    r'(?:\s+(?P<protocol>HTTP/\d(?:\.\d)?))?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
    r'$'
)


# ------------------------------------------------------------------
# Suspicious web activity
# ------------------------------------------------------------------

WEB_RULES = (
    (
        "WEB_PATH_TRAVERSAL",
        re.compile(
            r"\.\./|"
            r"\.\.%2f|"
            r"%2e%2e|"
            r"%252e%252e",
            re.IGNORECASE,
        ),
        "HIGH",
        "Potential path traversal attempt",
    ),
    (
        "WEB_SENSITIVE_FILE",
        re.compile(
            r"/etc/passwd|"
            r"/etc/shadow|"
            r"\.env(?:\b|$)|"
            r"\.git/config|"
            r"wp-config\.php",
            re.IGNORECASE,
        ),
        "HIGH",
        "Request targeted a potentially sensitive file",
    ),
    (
        "WEB_ADMIN_PROBING",
        re.compile(
            r"/admin(?:/|$)|"
            r"/administrator(?:/|$)|"
            r"/login(?:/|$)|"
            r"/wp-admin(?:/|$)|"
            r"/phpmyadmin(?:/|$)",
            re.IGNORECASE,
        ),
        "MEDIUM",
        "Request targeted an administrative or authentication endpoint",
    ),
    (
        "WEB_SCANNER",
        re.compile(
            r"sqlmap|"
            r"nikto|"
            r"nmap|"
            r"masscan|"
            r"gobuster|"
            r"dirbuster|"
            r"wpscan",
            re.IGNORECASE,
        ),
        "HIGH",
        "Request contains a known security scanning tool identifier",
    ),
    (
        "WEB_COMMAND_INJECTION",
        re.compile(
            r";\s*(?:id|whoami|uname|cat|curl|wget)\b|"
            r"\|\s*(?:id|whoami|uname|cat|curl|wget)\b|"
            r"\$\([^)]*\)|"
            r"`[^`]+`",
            re.IGNORECASE,
        ),
        "CRITICAL",
        "Potential command injection pattern detected",
    ),
    (
        "WEB_XSS",
        re.compile(
            r"<script\b|"
            r"javascript:|"
            r"%3cscript",
            re.IGNORECASE,
        ),
        "HIGH",
        "Potential cross-site scripting payload detected",
    ),
)


# ------------------------------------------------------------------
# Timestamp parsing
# ------------------------------------------------------------------

def parse_web_timestamp(
    timestamp_text: str,
) -> Optional[datetime]:
    """
    Parse the timestamp used by Apache/Nginx combined logs.

    Example:

        06/Oct/2026:22:14:03 +0530
    """

    formats = (
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
    )

    for fmt in formats:
        try:
            return datetime.strptime(
                timestamp_text,
                fmt,
            )
        except ValueError:
            continue

    return None


# ------------------------------------------------------------------
# Classification
# ------------------------------------------------------------------

def classify_web_request(
    path: str,
    user_agent: str = "",
) -> tuple[str, str, str]:
    """
    Classify a web request based on its path and user agent.

    Returns:

        event_type, severity, description
    """

    combined = (
        f"{path} {user_agent}"
    )

    for (
        event_type,
        pattern,
        severity,
        description,
    ) in WEB_RULES:

        if pattern.search(combined):
            return (
                event_type,
                severity,
                description,
            )

    return (
        "HTTP_REQUEST",
        "INFO",
        "HTTP request observed",
    )


# ------------------------------------------------------------------
# Event builder
# ------------------------------------------------------------------

def build_web_event(
    line: str,
    event_number: int,
) -> Optional[Event]:
    """
    Convert one Apache/Nginx access-log line
    into a normalized Event.
    """

    raw = line.rstrip("\n")

    match = ACCESS_LOG_PATTERN.match(
        raw
    )

    if not match:
        return None

    timestamp = parse_web_timestamp(
        match.group("timestamp")
    )

    if timestamp is None:
        return None

    source_ip = match.group(
        "source_ip"
    )

    method = match.group(
        "method"
    )

    path = match.group(
        "path"
    )

    protocol = (
        match.group("protocol")
        or "HTTP/1.1"
    )

    status = int(
        match.group("status")
    )

    size_text = match.group(
        "size"
    )

    if size_text == "-":
        response_size = 0
    else:
        try:
            response_size = int(
                size_text
            )
        except ValueError:
            response_size = 0

    referer = (
        match.group("referer")
        or ""
    )

    user_agent = (
        match.group("user_agent")
        or ""
    )

    (
        event_type,
        severity,
        description,
    ) = classify_web_request(
        path,
        user_agent,
    )

    return Event(
        event_id=f"WEB-{event_number:05d}",
        timestamp=timestamp,
        source="web_access",
        event_type=event_type,
        message=description,
        source_ip=source_ip,
        severity=severity,
        raw=raw,
        metadata={
            "http_method": method,
            "http_path": path,
            "http_protocol": protocol,
            "http_status": status,
            "response_size": response_size,
            "referer": referer,
            "user_agent": user_agent,
            "classification": event_type,
        },
    )


# ------------------------------------------------------------------
# Main parser
# ------------------------------------------------------------------

def parse_web_log(
    file_path: str,
) -> list[Event]:
    """
    Parse an Apache/Nginx combined access log.

    Supported information includes:

    - source IP
    - HTTP method
    - requested path
    - HTTP protocol
    - status code
    - response size
    - referer
    - user agent
    - suspicious request classification
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Web log file not found: {file_path}"
        )

    events: list[Event] = []

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:

        for line in file:

            if not line.strip():
                continue

            event = build_web_event(
                line=line,
                event_number=len(events) + 1,
            )

            if event is not None:
                events.append(event)

    return events
