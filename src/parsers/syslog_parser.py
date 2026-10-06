import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.timeline.events import Event
from src.parsers.auth_parser import (
    extract_process,
    parse_syslog_timestamp,
)


# ------------------------------------------------------------------
# Syslog classification patterns
# ------------------------------------------------------------------

SERVICE_STARTED_PATTERN = re.compile(
    r"(?:Started|Starting)\s+"
    r"(?P<service>.+?)(?:\.|$)",
    re.IGNORECASE,
)

SERVICE_STOPPED_PATTERN = re.compile(
    r"(?:Stopped|Stopping)\s+"
    r"(?P<service>.+?)(?:\.|$)",
    re.IGNORECASE,
)

SERVICE_FAILED_PATTERN = re.compile(
    r"(?:Failed to start|"
    r"Failed|"
    r"failure).*?"
    r"(?P<service>[A-Za-z0-9_.@:-]+)",
    re.IGNORECASE,
)

KERNEL_PATTERN = re.compile(
    r"\bkernel\b",
    re.IGNORECASE,
)

NETWORK_PATTERN = re.compile(
    r"\b("
    r"network|"
    r"interface|"
    r"link|"
    r"route|"
    r"routing|"
    r"firewall|"
    r"iptables|"
    r"nftables|"
    r"connection"
    r")\b",
    re.IGNORECASE,
)

AUTH_PATTERN = re.compile(
    r"\b("
    r"authentication|"
    r"authenticated|"
    r"login|"
    r"logout|"
    r"pam|"
    r"ssh"
    r")\b",
    re.IGNORECASE,
)

ERROR_PATTERN = re.compile(
    r"\b("
    r"error|"
    r"failed|"
    r"failure|"
    r"fatal|"
    r"panic"
    r")\b",
    re.IGNORECASE,
)

WARNING_PATTERN = re.compile(
    r"\b("
    r"warning|"
    r"warn"
    r")\b",
    re.IGNORECASE,
)


# ------------------------------------------------------------------
# Classification
# ------------------------------------------------------------------

def classify_syslog_message(
    message: str,
) -> tuple[str, str, str]:
    """
    Classify a general syslog message.

    Returns:

        event_type, severity, description
    """

    service_match = SERVICE_STARTED_PATTERN.search(
        message
    )

    if service_match:
        return (
            "SERVICE_STARTED",
            "INFO",
            "System service started",
        )

    service_match = SERVICE_STOPPED_PATTERN.search(
        message
    )

    if service_match:
        return (
            "SERVICE_STOPPED",
            "INFO",
            "System service stopped",
        )

    if SERVICE_FAILED_PATTERN.search(
        message
    ):
        return (
            "SERVICE_FAILURE",
            "HIGH",
            "System service reported a failure",
        )

    if KERNEL_PATTERN.search(
        message
    ):
        return (
            "KERNEL_EVENT",
            "INFO",
            "Kernel-generated system event",
        )

    if NETWORK_PATTERN.search(
        message
    ):
        return (
            "NETWORK_EVENT",
            "INFO",
            "System network activity detected",
        )

    if AUTH_PATTERN.search(
        message
    ):
        return (
            "AUTHENTICATION_EVENT",
            "INFO",
            "Authentication-related system event",
        )

    if ERROR_PATTERN.search(
        message
    ):
        return (
            "SYSTEM_ERROR",
            "HIGH",
            "System error or failure detected",
        )

    if WARNING_PATTERN.search(
        message
    ):
        return (
            "SYSTEM_WARNING",
            "MEDIUM",
            "System warning detected",
        )

    return (
        "SYSLOG_EVENT",
        "INFO",
        "General Linux system event",
    )


# ------------------------------------------------------------------
# Event builder
# ------------------------------------------------------------------

def build_syslog_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:
    """
    Convert one syslog line into a normalized Event.
    """

    raw = line.rstrip("\n")

    if not raw.strip():
        return None

    process, pid = extract_process(
        raw
    )

    # Remove the traditional syslog prefix
    # when constructing the message.
    message_match = re.match(
        r"^[A-Z][a-z]{2}\s+"
        r"\d{1,2}\s+"
        r"\d{2}:\d{2}:\d{2}\s+"
        r"\S+\s+"
        r"(?P<message>.*)$",
        raw,
    )

    if message_match:
        message = (
            message_match.group(
                "message"
            ).strip()
        )
    else:
        message = raw.strip()

    (
        event_type,
        severity,
        description,
    ) = classify_syslog_message(
        message
    )

    metadata = {
        "parser": "syslog",
        "classification": event_type,
    }

    service_match = SERVICE_STARTED_PATTERN.search(
        message
    )

    if service_match:
        metadata["service"] = (
            service_match.group(
                "service"
            ).strip()
        )

    service_match = SERVICE_STOPPED_PATTERN.search(
        message
    )

    if service_match:
        metadata["service"] = (
            service_match.group(
                "service"
            ).strip()
        )

    return Event(
        event_id=f"SYSLOG-{event_number:05d}",
        timestamp=timestamp,
        source="syslog",
        event_type=event_type,
        message=description,
        process=process,
        pid=pid,
        severity=severity,
        raw=raw,
        metadata=metadata,
    )


# ------------------------------------------------------------------
# Main parser
# ------------------------------------------------------------------

def parse_syslog(
    file_path: str,
    year: Optional[int] = None,
) -> list[Event]:
    """
    Parse a traditional Linux syslog file.

    Each recognized line becomes a normalized Event.

    Lines without a valid syslog timestamp are ignored.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Syslog file not found: {file_path}"
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

            timestamp = parse_syslog_timestamp(
                line,
                year=year,
            )

            if timestamp is None:
                continue

            event = build_syslog_event(
                line=line,
                timestamp=timestamp,
                event_number=len(events) + 1,
            )

            if event is not None:
                events.append(event)

    return events
