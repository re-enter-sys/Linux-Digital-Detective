import re
from datetime import datetime
from typing import Optional

from src.timeline.events import Event


# ------------------------------------------------------------------
# Linux authentication log patterns
# ------------------------------------------------------------------

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?P<user>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<port>\d+)"
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<port>\d+)"
)

SESSION_OPENED_PATTERN = re.compile(
    r"session opened for user (?P<user>\S+)"
)

SESSION_CLOSED_PATTERN = re.compile(
    r"session closed for user (?P<user>\S+)"
)

SUDO_PATTERN = re.compile(
    r"(?P<user>\S+)\s*:\s*"
    r"TTY=(?P<tty>\S+)\s*;\s*"
    r"PWD=(?P<pwd>.*?)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*"
    r"COMMAND=(?P<command>.+)"
)

PROCESS_PATTERN = re.compile(
    r"(?P<process>[A-Za-z0-9_.-]+)"
    r"(?:\[(?P<pid>\d+)\])?:"
)


# ------------------------------------------------------------------
# Timestamp parsing
# ------------------------------------------------------------------

def parse_syslog_timestamp(
    line: str,
    year: Optional[int] = None,
) -> Optional[datetime]:
    """
    Parse the traditional Linux syslog timestamp.

    Examples:
        Oct 6 22:14:03
        Oct  6 22:14:03
        Oct 16 22:14:03

    Traditional syslog timestamps do not contain a year,
    so the caller may provide the year explicitly.
    """

    match = re.match(
        r"^(?P<month>[A-Z][a-z]{2})"
        r"[ \t]+"
        r"(?P<day>\d{1,2})"
        r"[ \t]+"
        r"(?P<time>\d{2}:\d{2}:\d{2})",
        line,
    )

    if not match:
        return None

    if year is None:
        year = datetime.now().year

    timestamp_text = (
        f"{year} "
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')}"
    )

    try:
        return datetime.strptime(
            timestamp_text,
            "%Y %b %d %H:%M:%S",
        )

    except ValueError:
        return None


# ------------------------------------------------------------------
# Process extraction
# ------------------------------------------------------------------

def extract_process(line: str):
    """Extract process name and PID from a syslog/auth line."""

    match = PROCESS_PATTERN.search(line)

    if not match:
        return None, None

    process = match.group("process")

    pid = match.group("pid")

    if pid is not None:
        pid = int(pid)

    return process, pid


# ------------------------------------------------------------------
# Event builders
# ------------------------------------------------------------------

def build_failed_login_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:

    match = FAILED_PASSWORD_PATTERN.search(line)

    if not match:
        return None

    process, pid = extract_process(line)

    return Event(
        event_id=f"AUTH-{event_number:05d}",
        timestamp=timestamp,
        source="auth.log",
        event_type="SSH_AUTH_FAILURE",
        message="Failed SSH password authentication",
        user=match.group("user"),
        source_ip=match.group("source_ip"),
        process=process,
        pid=pid,
        severity="MEDIUM",
        raw=line.rstrip("\n"),
        metadata={
            "port": int(match.group("port")),
            "authentication": "password",
            "result": "failure",
        },
    )


def build_successful_login_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:

    match = ACCEPTED_PASSWORD_PATTERN.search(line)

    if not match:
        return None

    process, pid = extract_process(line)

    return Event(
        event_id=f"AUTH-{event_number:05d}",
        timestamp=timestamp,
        source="auth.log",
        event_type="SSH_AUTH_SUCCESS",
        message="Successful SSH password authentication",
        user=match.group("user"),
        source_ip=match.group("source_ip"),
        process=process,
        pid=pid,
        severity="INFO",
        raw=line.rstrip("\n"),
        metadata={
            "port": int(match.group("port")),
            "authentication": "password",
            "result": "success",
        },
    )


def build_session_open_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:

    match = SESSION_OPENED_PATTERN.search(line)

    if not match:
        return None

    process, pid = extract_process(line)

    return Event(
        event_id=f"AUTH-{event_number:05d}",
        timestamp=timestamp,
        source="auth.log",
        event_type="SSH_SESSION_OPEN",
        message="SSH session opened",
        user=match.group("user"),
        process=process,
        pid=pid,
        severity="INFO",
        raw=line.rstrip("\n"),
        metadata={
            "session_state": "opened",
        },
    )


def build_session_close_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:

    match = SESSION_CLOSED_PATTERN.search(line)

    if not match:
        return None

    process, pid = extract_process(line)

    return Event(
        event_id=f"AUTH-{event_number:05d}",
        timestamp=timestamp,
        source="auth.log",
        event_type="SSH_SESSION_CLOSE",
        message="SSH session closed",
        user=match.group("user"),
        process=process,
        pid=pid,
        severity="INFO",
        raw=line.rstrip("\n"),
        metadata={
            "session_state": "closed",
        },
    )


def build_sudo_event(
    line: str,
    timestamp: datetime,
    event_number: int,
) -> Optional[Event]:

    match = SUDO_PATTERN.search(line)

    if not match:
        return None

    process, pid = extract_process(line)

    return Event(
        event_id=f"AUTH-{event_number:05d}",
        timestamp=timestamp,
        source="auth.log",
        event_type="SUDO_COMMAND",
        message="User executed command through sudo",
        user=match.group("user"),
        process=process,
        pid=pid,
        command=match.group("command"),
        severity="HIGH",
        raw=line.rstrip("\n"),
        metadata={
            "tty": match.group("tty"),
            "pwd": match.group("pwd"),
            "target_user": match.group("target_user"),
            "privilege_change": (
                match.group("user")
                != match.group("target_user")
            ),
        },
    )


# ------------------------------------------------------------------
# Main parser
# ------------------------------------------------------------------

def parse_auth_log(
    file_path: str,
    year: Optional[int] = None,
) -> list[Event]:
    """
    Parse a Linux auth.log file into normalized Event objects.

    Supported events:

    - SSH authentication failures
    - SSH authentication successes
    - SSH session opened
    - SSH session closed
    - sudo commands
    """

    events: list[Event] = []

    with open(
        file_path,
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

            event_number = len(events) + 1

            event = build_failed_login_event(
                line,
                timestamp,
                event_number,
            )

            if event:
                events.append(event)
                continue

            event = build_successful_login_event(
                line,
                timestamp,
                event_number,
            )

            if event:
                events.append(event)
                continue

            event = build_session_open_event(
                line,
                timestamp,
                event_number,
            )

            if event:
                events.append(event)
                continue

            event = build_session_close_event(
                line,
                timestamp,
                event_number,
            )

            if event:
                events.append(event)
                continue

            event = build_sudo_event(
                line,
                timestamp,
                event_number,
            )

            if event:
                events.append(event)
                continue

    return events
