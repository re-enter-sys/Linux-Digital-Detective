import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.timeline.events import Event


# ------------------------------------------------------------------
# Bash history timestamp support
# ------------------------------------------------------------------

BASH_TIMESTAMP_PATTERN = re.compile(
    r"^#(?P<epoch>\d+)$"
)


# ------------------------------------------------------------------
# Command classification
# ------------------------------------------------------------------

COMMAND_RULES = (
    (
        "REVERSE_SHELL",
        re.compile(
            r"/dev/tcp/|bash\s+-i|sh\s+-i|"
            r"\bnc\s+-e\b|\bncat\s+-e\b|"
            r"\bsocat\s+.*exec:",
            re.IGNORECASE,
        ),
        "CRITICAL",
        "Potential reverse shell command",
    ),
    (
        "CREDENTIAL_ACCESS",
        re.compile(
            r"/etc/shadow|/etc/passwd|"
            r"\.ssh/id_rsa|"
            r"\.ssh/authorized_keys|"
            r"\bpasswd\b|\bshadow\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "Potential credential or authentication data access",
    ),
    (
        "PERSISTENCE",
        re.compile(
            r"authorized_keys|"
            r"\bcrontab\b|"
            r"/etc/cron|"
            r"\bsystemctl\s+enable\b|"
            r"/etc/systemd/system|"
            r"\.bashrc\b|"
            r"\.profile\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "Potential persistence-related command",
    ),
    (
        "NETWORK_RECON",
        re.compile(
            r"\bnmap\b|"
            r"\bmasscan\b|"
            r"\bnetcat\b|"
            r"\bnc\b|"
            r"\bss\b|"
            r"\bnetstat\b",
            re.IGNORECASE,
        ),
        "MEDIUM",
        "Potential network reconnaissance command",
    ),
    (
        "DOWNLOAD",
        re.compile(
            r"\bcurl\b|\bwget\b",
            re.IGNORECASE,
        ),
        "MEDIUM",
        "Potential remote file download",
    ),
    (
        "ENCODED_EXECUTION",
        re.compile(
            r"base64\s+(-d|--decode)|"
            r"base64\s+.*\|\s*(bash|sh)",
            re.IGNORECASE,
        ),
        "HIGH",
        "Potential encoded command execution",
    ),
    (
        "SUDO_COMMAND",
        re.compile(
            r"^\s*sudo(?:\s+|$)",
            re.IGNORECASE,
        ),
        "HIGH",
        "Command executed through sudo",
    ),
    (
        "SHELL_EXECUTION",
        re.compile(
            r"\b(bash|sh|zsh)\s+-c\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "Shell interpreter executed with command arguments",
    ),
)


# ------------------------------------------------------------------
# Timestamp helpers
# ------------------------------------------------------------------

def parse_bash_timestamp(
    line: str,
) -> Optional[datetime]:
    """
    Parse a Bash HISTTIMEFORMAT timestamp marker.

    Bash may store timestamps as:

        #1760000000

    The value represents Unix epoch seconds.

    Epoch timestamps are interpreted as UTC so that they remain
    consistent with the normalized Event timestamp model.
    """

    match = BASH_TIMESTAMP_PATTERN.match(
        line.strip()
    )

    if not match:
        return None

    try:
        return datetime.fromtimestamp(
            int(match.group("epoch")),
            tz=timezone.utc,
        )

    except (
        ValueError,
        OverflowError,
        OSError,
    ):
        return None


def _fallback_timestamp(
    timestamp: Optional[datetime],
) -> datetime:
    """
    Provide a deterministic timestamp when Bash history
    does not contain timestamp metadata.
    """

    if timestamp is not None:
        return timestamp

    return datetime.now(
        timezone.utc
    )


# ------------------------------------------------------------------
# Command classification
# ------------------------------------------------------------------

def classify_command(
    command: str,
) -> tuple[str, str, str]:
    """
    Return:

        event_type, severity, description

    for a Bash command.
    """

    for (
        event_type,
        pattern,
        severity,
        description,
    ) in COMMAND_RULES:

        if pattern.search(command):
            return (
                event_type,
                severity,
                description,
            )

    return (
        "BASH_COMMAND",
        "INFO",
        "Bash command executed",
    )


# ------------------------------------------------------------------
# Event builder
# ------------------------------------------------------------------

def build_bash_event(
    command: str,
    timestamp: datetime,
    event_number: int,
) -> Event:
    """
    Convert one Bash history command into a normalized Event.
    """

    (
        event_type,
        severity,
        description,
    ) = classify_command(command)

    return Event(
        event_id=f"BASH-{event_number:05d}",
        timestamp=timestamp,
        source="bash_history",
        event_type=event_type,
        message=description,
        command=command,
        severity=severity,
        raw=command,
        metadata={
            "shell": "bash",
            "classification": event_type,
        },
    )


# ------------------------------------------------------------------
# Main parser
# ------------------------------------------------------------------

def parse_bash_history(
    file_path: str,
    default_timestamp: Optional[datetime] = None,
) -> list[Event]:
    """
    Parse a Bash history file into normalized Event objects.

    Supported formats:

    Standard history:

        whoami
        sudo -i
        nmap 192.0.2.10

    Timestamp-enabled Bash history:

        #1760000000
        whoami
        #1760000010
        sudo -i

    When timestamps are unavailable, the parser uses the supplied
    default timestamp or the current UTC time.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Bash history file not found: {file_path}"
        )

    events: list[Event] = []

    pending_timestamp = (
        default_timestamp
    )

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:

        for raw_line in file:

            line = raw_line.rstrip("\n")

            if not line.strip():
                continue

            timestamp = parse_bash_timestamp(
                line
            )

            if timestamp is not None:
                pending_timestamp = timestamp
                continue

            event_timestamp = (
                pending_timestamp
                if pending_timestamp is not None
                else _fallback_timestamp(
                    default_timestamp
                )
            )

            event_number = (
                len(events) + 1
            )

            events.append(
                build_bash_event(
                    command=line.strip(),
                    timestamp=event_timestamp,
                    event_number=event_number,
                )
            )

            # A timestamp applies to the command
            # immediately following it.
            pending_timestamp = (
                default_timestamp
            )

    return events
