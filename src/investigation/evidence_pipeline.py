from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.parsers.router import (
    get_parser_name,
    parse_evidence,
    parse_evidence_files,
)
from src.timeline.events import Event


@dataclass
class EvidenceParseResult:
    """
    Result of parsing one or more forensic evidence artifacts.
    """

    events: list[Event] = field(default_factory=list)

    parsed_files: list[dict[str, Any]] = field(
        default_factory=list
    )

    failed_files: list[dict[str, Any]] = field(
        default_factory=list
    )

    unsupported_files: list[dict[str, Any]] = field(
        default_factory=list
    )

    @property
    def total_files(self) -> int:
        return (
            len(self.parsed_files)
            + len(self.failed_files)
            + len(self.unsupported_files)
        )

    @property
    def successful_files(self) -> int:
        return len(self.parsed_files)

    @property
    def event_count(self) -> int:
        return len(self.events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_files": self.total_files,
            "successful_files": self.successful_files,
            "failed_files": len(self.failed_files),
            "unsupported_files": len(
                self.unsupported_files
            ),
            "event_count": self.event_count,
            "parsed_files": self.parsed_files,
            "failed_file_details": self.failed_files,
            "unsupported_file_details": (
                self.unsupported_files
            ),
        }


def parse_case_evidence(
    evidence_paths: list[str],
    *,
    year: int | None = None,
) -> EvidenceParseResult:
    """
    Parse all supplied evidence artifacts.

    Each file is routed to the appropriate parser.
    A failure in one artifact does not prevent the
    remaining evidence from being processed.
    """

    result = EvidenceParseResult()

    for evidence_path in evidence_paths:
        path = Path(evidence_path)

        parser_name = get_parser_name(
            str(path)
        )

        if parser_name is None:
            result.unsupported_files.append(
                {
                    "file": str(path),
                    "filename": path.name,
                    "reason": (
                        "No parser registered for "
                        "this evidence type."
                    ),
                }
            )
            continue

        try:
            events = parse_evidence(
                str(path),
                year=year,
            )

            result.events.extend(events)

            result.parsed_files.append(
                {
                    "file": str(path),
                    "filename": path.name,
                    "parser": parser_name,
                    "event_count": len(events),
                    "status": "PARSED",
                }
            )

        except Exception as exc:
            result.failed_files.append(
                {
                    "file": str(path),
                    "filename": path.name,
                    "parser": parser_name,
                    "status": "FAILED",
                    "error": str(exc),
                }
            )

    result.events.sort(
        key=lambda event: event.timestamp
    )

    return result


def parse_single_evidence(
    evidence_path: str,
    *,
    year: int | None = None,
) -> EvidenceParseResult:
    """
    Convenience wrapper for parsing one evidence artifact.
    """

    return parse_case_evidence(
        [evidence_path],
        year=year,
    )


def merge_event_sets(
    *event_sets: list[Event],
) -> list[Event]:
    """
    Merge multiple event collections and return a
    chronologically sorted list.
    """

    events: list[Event] = []

    for event_set in event_sets:
        events.extend(event_set)

    events.sort(
        key=lambda event: event.timestamp
    )

    return events
