from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def normalize_timestamp(timestamp: datetime) -> datetime:
    """
    Normalize a datetime into timezone-aware UTC.

    Linux Digital Detective combines evidence from multiple
    sources, and those sources may produce either naive or
    timezone-aware datetime objects.

    Policy:
        - timezone-aware timestamps are converted to UTC
        - naive timestamps are interpreted as UTC
        - the returned value is always timezone-aware UTC

    This guarantees that forensic events can be safely sorted
    and compared across evidence sources.
    """

    if timestamp.tzinfo is None:
        return timestamp.replace(
            tzinfo=timezone.utc
        )

    return timestamp.astimezone(
        timezone.utc
    )


@dataclass
class Event:
    """
    Universal normalized forensic event.

    Every parser in Linux Digital Detective should eventually
    convert raw evidence into this common event structure.

    All event timestamps are normalized to timezone-aware UTC.
    """

    event_id: str
    timestamp: datetime

    source: str
    event_type: str
    message: str

    user: Optional[str] = None
    source_ip: Optional[str] = None

    process: Optional[str] = None
    pid: Optional[int] = None

    command: Optional[str] = None

    severity: str = "INFO"

    raw: str = ""

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        """
        Normalize timestamps immediately after Event creation.
        """

        self.timestamp = normalize_timestamp(
            self.timestamp
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the event into a JSON-serializable dictionary."""

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "message": self.message,
            "user": self.user,
            "source_ip": self.source_ip,
            "process": self.process,
            "pid": self.pid,
            "command": self.command,
            "severity": self.severity,
            "raw": self.raw,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "Event":
        """Create an Event from a dictionary."""

        return cls(
            event_id=data["event_id"],
            timestamp=datetime.fromisoformat(
                data["timestamp"]
            ),
            source=data["source"],
            event_type=data["event_type"],
            message=data["message"],
            user=data.get("user"),
            source_ip=data.get("source_ip"),
            process=data.get("process"),
            pid=data.get("pid"),
            command=data.get("command"),
            severity=data.get(
                "severity",
                "INFO",
            ),
            raw=data.get(
                "raw",
                "",
            ),
            metadata=data.get(
                "metadata",
                {},
            ),
        )

    def __str__(self) -> str:
        """Human-readable event representation."""

        return (
            f"[{self.timestamp.isoformat()}] "
            f"{self.event_type} "
            f"user={self.user or '-'} "
            f"source_ip={self.source_ip or '-'} "
            f"severity={self.severity}"
        )
