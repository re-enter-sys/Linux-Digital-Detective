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
# SSH event patterns
# ------------------------------------------------------------------

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for "
    r"(?:(?:invalid user)\s+)?"
    r"(?P<user>\S+) "
    r"from "
    r"(?P<source_ip>\S+) "
    r"port "
    r"(?P<port>\d+)",
    re.IGNORECASE,
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"Accepted password for "
    r"(?P<user>\S+) "
    r"from "
    r"(?P<source_ip>\S+) "
    r"port "
    r"(?P<port>\d+)",
    re.IGNORECASE,
)

ACCEPTED_PUBLICKEY_PATTERN = re.compile(
    r"Accepted publickey for "
    r"(?P<user>\S+) "
    r"from "
    r"(?P<source_ip>\S+) "
    r"port "
    r"(?P<port>\d+)",
    re.IGNORECASE,
)

INVALID_USER_PATTERN = re.compile(
    r"Invalid user "
    r"(?P<user>\S+) "
    r"from "
    r"(?P<source_ip>\S+)",
    re.IGNORECASE,
)

DISCONNECT_PATTERN = re.compile(
    r"(?:Disconnected from|"
    r"Received disconnect from) "
    r"(?:invalid user\s+)?"
    r"(?P<source_ip>\S+)",
    re.IGNORECASE,
)

SESSION_OPEN_PATTERN = re.compile(
    r"session opened for user "
    r"(?P<user>\S+)",
    re.IGNORECASE,
)

SESSION_CLOSE_PATTERN = re.compile(
    r"session closed for user "
    r"(?P<user>\S+)",
    re.IGNORECASE,
)

CONNECTION_PATTERN = re.compile(
    r"(?:Connection from|Accepted connection from) "
    r"(?P<source_ip>\S+)",
    re.IGNORECASE,
)


# ------------------------------------------------------------------
# Event builders
# ------------------------------------------------------------------

def _build_event(
    *,
    event_number: int,
    timestamp: datetime,
    event_type: str,
    message: str,
    raw: str,
    user: Optional[str] = None,
    source_ip: Optional[str] = None,
    process: Optional[str] = None,
    pid: Optional[int] = None,
    severity: str = "INFO",
    metadata: Optional[dict] = None,
) -> Event:
    """Create a normalized SSH Event."""

    return Event(
        event_id=f"SSH-{event_number:05d}",
        timestamp=timestamp,
        source="ssh",
        event_type=event_type,
        message=message,
        user=user,
        source_ip=source_ip,
        process=process,
        pid=pid,
        severity=severity,
        raw=raw,
        metadata=metadata or {},
    )


def _extract_session_user(
    line: str,
) -> Optional[str]:
    """
    Extract a username from PAM session messages.

    Handles examples such as:

        session opened for user admin(uid=1000)
        session closed for user admin
    """

    match = re.search(
        r"session\s+(?:opened|closed)\s+"
        r"for\s+user\s+"
        r"(?P<user>[A-Za-z0-9_.@-]+)",
        line,
        re.IGNORECASE,
    )

    if not match:
        return None

    return match.group(
        "user"
    )


def build_ssh_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:
    """
    Parse one SSH log line.

    Returns None when the line does not represent a
    recognized SSH event.
    """

    raw = line.rstrip("\n")

    process, pid = extract_process(
        raw
    )

    # --------------------------------------------------------------
    # Failed password
    # --------------------------------------------------------------

    match = FAILED_PASSWORD_PATTERN.search(
        raw
    )

    if match:
        return _build_event(
            event_number=event_number,
            timestamp=timestamp,
            event_type="SSH_AUTH_FAILURE",
            message="Failed SSH password authentication",
            raw=raw,
            user=match.group(
                "user"
            ),
            source_ip=match.group(
                "source_ip"
            ),
            process=process,
            pid=pid,
            severity="MEDIUM",
            metadata={
                "authentication": "password",
                "result": "failure",
                "port": int(
                    match.group(
                        "port"
                    )
                ),
            },
        )

    # --------------------------------------------------------------
    # Successful password
    # --------------------------------------------------------------

    match = ACCEPTED_PASSWORD_PATTERN.search(
        raw
    )

    if match:
        return _build_event(
            event_number=event_number,
            timestamp=timestamp,
            event_type="SSH_AUTH_SUCCESS",
            message="Successful SSH password authentication",
            raw=raw,
            user=match.group(
                "user"
            ),
            source_ip=match.group(
                "source_ip"
            ),
            process=process,
            pid=pid,
            severity="INFO",
            metadata={
                "authentication": "password",
                "result": "success",
                "port": int(
                    match.group(
                        "port"
                    )
                ),
            },
        )

    # --------------------------------------------------------------
    # Successful public-key authentication
    # --------------------------------------------------------------

    match = ACCEPTED_PUBLICKEY_PATTERN.search(
        raw
    )

    if match:
        return _build_event(
            event_number=event_number,
            timestamp=timestamp,
            event_type="SSH_AUTH_SUCCESS",
            message="Successful SSH public-key authentication",
            raw=raw,
            user=match.group(
                "user"
            ),
            source_ip=match.group(
                "source_ip"
            ),
            process=process,
            pid=pid,
            severity="INFO",
            metadata={
                "authentication": "publickey",
                "result": "success",
                "port": int(
                    match.group(
                        "port"
                    )
                ),
            },
        )

    # --------------------------------------------------------------
    # Invalid username
    # --------------------------------------------------------------

    match = INVALID_USER_PATTERN.search(
        raw
    )

    if match:
        return _build_event(
            event_number=event_number,
            timestamp=timestamp,
            event_type="SSH_INVALID_USER",
            message="SSH connection attempted with an invalid user",
            raw=raw,
            user=match.group(
                "user"
            ),
            source_ip=match.group(
                "source_ip"
            ),
            process=process,
            pid=pid,
            severity="MEDIUM",
            metadata={
                "authentication": "unknown_user",
                "result": "failure",
            },
        )

    # --------------------------------------------------------------
    # Session opened
    # --------------------------------------------------------------

    match = SESSION_OPEN_PATTERN.search(
        raw
    )

    if match:
        user = (
            match.group(
                "user"
            )
            or _extract_session_user(
                raw
            )
        )

        return _build_event(
            event_number=event_number,
            timestamp=timestamp,
            event_type="SSH_SESSION_OPEN",
            message="SSH session opened",
            raw=raw,
            user=user,
            process=process,
            pid=pid,
            severity="INFO",
            metadata={
                "session_state": "opened",
            },
        )

    # --------------------------------------------------------------
    # Session closed
    # --------------------------------------------------------------

    match = SESSION_CLOSE_PATTERN.search(
        raw
    )

    if match:
        user = (
            match.group(
                "user"
            )
            or _extract_session_user(
                raw
            )
        )

        return _build_event(
            event_number=event_number,
            timestamp=timestamp,
            event_type="SSH_SESSION_CLOSE",
            message="SSH session closed",
            raw=raw,
            user=user,
            process=process,
            pid=pid,
            severity="INFO",
            metadata={
                "session_state": "closed",
            },
        )

    # --------------------------------------------------------------
    # SSH connection
    # --------------------------------------------------------------

    match = CONNECTION_PATTERN.search(
        raw
    )

    if match:
        return _build_event(
            event_number=event_number,
            timestamp=timestamp,
            event_type="SSH_CONNECTION",
            message="SSH connection established",
            raw=raw,
            source_ip=match.group(
                "source_ip"
            ),
            process=process,
            pid=pid,
            severity="INFO",
            metadata={
                "connection_state": "accepted",
            },
        )

    # --------------------------------------------------------------
    # SSH disconnect
    # --------------------------------------------------------------

    match = DISCONNECT_PATTERN.search(
        raw
    )

    if match:
        return _build_event(
            event_number=event_number,
            timestamp=timestamp,
            event_type="SSH_DISCONNECT",
            message="SSH connection disconnected",
            raw=raw,
            source_ip=match.group(
                "source_ip"
            ),
            process=process,
            pid=pid,
            severity="INFO",
            metadata={
                "connection_state": "closed",
            },
        )

    return None


# ------------------------------------------------------------------
# Main parser
# ------------------------------------------------------------------

def parse_ssh_log(
    file_path: str,
    year: Optional[int] = None,
) -> list[Event]:
    """
    Parse a Linux SSH log into normalized Event objects.

    Supported events include:

    - failed password authentication
    - successful password authentication
    - successful public-key authentication
    - invalid users
    - SSH sessions opening
    - SSH sessions closing
    - SSH connections
    - SSH disconnections
    """

    path = Path(
        file_path
    )

    if not path.is_file():
        raise FileNotFoundError(
            f"SSH log file not found: {file_path}"
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

            event = build_ssh_event(
                line=line,
                timestamp=timestamp,
                event_number=len(events) + 1,
            )

            if event is not None:
                events.append(
                    event
                )

    return events
