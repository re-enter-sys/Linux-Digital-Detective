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
# Sudo log patterns
# ------------------------------------------------------------------

SUDO_PATTERN = re.compile(
    r"(?P<user>\S+)\s*:\s*"
    r"TTY=(?P<tty>\S+)\s*;\s*"
    r"PWD=(?P<pwd>.*?)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*"
    r"COMMAND=(?P<command>.+)",
    re.IGNORECASE,
)

SUDO_COMMAND_PATTERN = re.compile(
    r"(?P<user>\S+)\s*:\s*"
    r"TTY=(?P<tty>\S+)\s*;\s*"
    r"PWD=(?P<pwd>.*?)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*"
    r"COMMAND=(?P<command>.+)",
    re.IGNORECASE,
)

SUDO_SESSION_OPEN_PATTERN = re.compile(
    r"session opened for user "
    r"(?P<user>\S+)",
    re.IGNORECASE,
)

SUDO_SESSION_CLOSE_PATTERN = re.compile(
    r"session closed for user "
    r"(?P<user>\S+)",
    re.IGNORECASE,
)


# ------------------------------------------------------------------
# Severity helpers
# ------------------------------------------------------------------

def _privilege_severity(
    invoking_user: str,
    target_user: str,
) -> str:
    """
    Determine severity for a sudo privilege transition.

    Escalation to root is considered critical.
    Other user transitions are high severity.
    Same-user sudo activity is informational.
    """

    if invoking_user == target_user:
        return "INFO"

    if target_user.lower() == "root":
        return "CRITICAL"

    return "HIGH"


# ------------------------------------------------------------------
# Event builder
# ------------------------------------------------------------------

def build_sudo_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:
    """
    Convert a sudo log line into a normalized Event.
    """

    raw = line.rstrip("\n")

    match = SUDO_PATTERN.search(
        raw
    )

    if not match:
        return None

    process, pid = extract_process(
        raw
    )

    invoking_user = match.group(
        "user"
    )

    target_user = match.group(
        "target_user"
    )

    command = match.group(
        "command"
    ).strip()

    privilege_change = (
        invoking_user != target_user
    )

    severity = _privilege_severity(
        invoking_user,
        target_user,
    )

    return Event(
        event_id=f"SUDO-{event_number:05d}",
        timestamp=timestamp,
        source="sudo",
        event_type="SUDO_COMMAND",
        message=(
            "User executed command through sudo"
        ),
        user=invoking_user,
        process=process,
        pid=pid,
        command=command,
        severity=severity,
        raw=raw,
        metadata={
            "tty": match.group("tty"),
            "pwd": match.group("pwd"),
            "target_user": target_user,
            "privilege_change": privilege_change,
            "privilege_transition": (
                f"{invoking_user}->{target_user}"
            ),
        },
    )


# ------------------------------------------------------------------
# Session event helpers
# ------------------------------------------------------------------

def build_sudo_session_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:
    """
    Parse sudo/PAM session open and close events.

    This is useful when sudo-related activity is represented
    by PAM session messages rather than a COMMAND record.
    """

    raw = line.rstrip("\n")

    process, pid = extract_process(
        raw
    )

    match = SUDO_SESSION_OPEN_PATTERN.search(
        raw
    )

    if match:
        return Event(
            event_id=f"SUDO-{event_number:05d}",
            timestamp=timestamp,
            source="sudo",
            event_type="SUDO_SESSION_OPEN",
            message="Privilege session opened",
            user=match.group("user"),
            process=process,
            pid=pid,
            severity="INFO",
            raw=raw,
            metadata={
                "session_state": "opened",
            },
        )

    match = SUDO_SESSION_CLOSE_PATTERN.search(
        raw
    )

    if match:
        return Event(
            event_id=f"SUDO-{event_number:05d}",
            timestamp=timestamp,
            source="sudo",
            event_type="SUDO_SESSION_CLOSE",
            message="Privilege session closed",
            user=match.group("user"),
            process=process,
            pid=pid,
            severity="INFO",
            raw=raw,
            metadata={
                "session_state": "closed",
            },
        )

    return None


# ------------------------------------------------------------------
# Main parser
# ------------------------------------------------------------------

def parse_sudo_log(
    file_path: str,
    year: Optional[int] = None,
) -> list[Event]:
    """
    Parse a Linux sudo/authentication log into normalized events.

    Supported events:

    - sudo command execution
    - privilege transitions
    - sudo/PAM session opening
    - sudo/PAM session closing
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Sudo log file not found: {file_path}"
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

            event_number = (
                len(events) + 1
            )

            event = build_sudo_event(
                line=line,
                timestamp=timestamp,
                event_number=event_number,
            )

            if event is None:
                event = build_sudo_session_event(
                    line=line,
                    timestamp=timestamp,
                    event_number=event_number,
                )

            if event is not None:
                events.append(event)

    return events
