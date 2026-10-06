from datetime import datetime
from pathlib import Path
import json

from src.timeline.events import Event


class Timeline:
    """
    Represents a chronological collection of forensic events.
    """

    def __init__(self, events: list[Event] | None = None):
        self.events: list[Event] = []

        if events:
            self.events = sorted(
                events,
                key=lambda event: event.timestamp,
            )

    @property
    def start_time(self) -> datetime | None:
        """Return the timestamp of the first event."""

        if not self.events:
            return None

        return self.events[0].timestamp

    @property
    def end_time(self) -> datetime | None:
        """Return the timestamp of the final event."""

        if not self.events:
            return None

        return self.events[-1].timestamp

    @property
    def duration_seconds(self) -> float:
        """Return the timeline duration in seconds."""

        if len(self.events) < 2:
            return 0.0

        return (
            self.end_time - self.start_time
        ).total_seconds()

    def add_event(self, event: Event):
        """Add an event and keep the timeline chronological."""

        self.events.append(event)

        self.events.sort(
            key=lambda item: item.timestamp
        )

    def event_count(self) -> int:
        """Return the number of events."""

        return len(self.events)

    def get_event(self, index: int) -> Event:
        """Return an event by chronological index."""

        return self.events[index]

    def to_dict(self) -> dict:
        """Convert the complete timeline to a dictionary."""

        timeline_events = []

        previous_timestamp = None

        for sequence, event in enumerate(
            self.events,
            start=1,
        ):
            current_timestamp = event.timestamp

            if previous_timestamp is None:
                gap_seconds = 0.0
            else:
                gap_seconds = (
                    current_timestamp - previous_timestamp
                ).total_seconds()

            event_data = event.to_dict()

            event_data["sequence"] = sequence
            event_data["gap_from_previous_seconds"] = gap_seconds

            timeline_events.append(event_data)

            previous_timestamp = current_timestamp

        return {
            "event_count": len(self.events),
            "start_time": (
                self.start_time.isoformat()
                if self.start_time
                else None
            ),
            "end_time": (
                self.end_time.isoformat()
                if self.end_time
                else None
            ),
            "duration_seconds": self.duration_seconds,
            "events": timeline_events,
        }

    def save_json(self, file_path: str):
        """
        Save the timeline as a JSON investigation artifact.
        """

        path = Path(file_path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with path.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.to_dict(),
                file,
                indent=4,
            )

    def __str__(self) -> str:
        """Return a human-readable timeline."""

        lines = []

        lines.append(
            "LINUX DIGITAL DETECTIVE TIMELINE"
        )

        lines.append(
            "=" * 70
        )

        lines.append(
            f"Events: {self.event_count()}"
        )

        if self.start_time:
            lines.append(
                f"Start:  {self.start_time.isoformat()}"
            )

        if self.end_time:
            lines.append(
                f"End:    {self.end_time.isoformat()}"
            )

        lines.append(
            f"Duration: {self.duration_seconds:.2f} seconds"
        )

        lines.append(
            "=" * 70
        )

        for sequence, event in enumerate(
            self.events,
            start=1,
        ):
            lines.append(
                f"{sequence:02d}. "
                f"{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{event.event_type:<20} | "
                f"{event.user or '-':<10} | "
                f"{event.source_ip or '-':<15}"
            )

        return "\n".join(lines)


def build_timeline(events: list[Event]) -> Timeline:
    """
    Build a chronological investigation timeline.
    """

    return Timeline(events)
