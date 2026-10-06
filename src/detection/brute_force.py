from dataclasses import dataclass, field
from typing import Optional

from src.timeline.events import Event


@dataclass
class BruteForceFinding:
    """
    Represents a detected SSH brute-force pattern.
    """

    finding_id: str
    event_type: str
    title: str
    description: str
    severity: str
    source_ip: Optional[str]
    username: Optional[str]
    failed_attempts: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    event_ids: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert the finding into a JSON-compatible dictionary."""

        return {
            "finding_id": self.finding_id,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "username": self.username,
            "failed_attempts": self.failed_attempts,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_ids": self.event_ids,
            "metadata": self.metadata,
        }


@dataclass
class SuccessfulLoginAfterBruteForceFinding:
    """
    Represents a successful SSH authentication that occurred
    after repeated failed authentication attempts.
    """

    finding_id: str
    event_type: str
    title: str
    description: str
    severity: str
    source_ip: Optional[str]
    username: Optional[str]
    failed_attempts: int
    first_failure: Optional[str]
    successful_login: Optional[str]
    session_opened: Optional[str]
    event_ids: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert the finding into a JSON-compatible dictionary."""

        return {
            "finding_id": self.finding_id,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "username": self.username,
            "failed_attempts": self.failed_attempts,
            "first_failure": self.first_failure,
            "successful_login": self.successful_login,
            "session_opened": self.session_opened,
            "event_ids": self.event_ids,
            "metadata": self.metadata,
        }


def detect_ssh_brute_force(
    events: list[Event],
    threshold: int = 4,
    window_seconds: int = 300,
) -> list[BruteForceFinding]:
    """
    Detect repeated failed SSH authentication attempts.

    A brute-force finding is generated when the same source IP
    attempts to authenticate against the same username at least
    `threshold` times within `window_seconds`.
    """

    failures = [
        event
        for event in events
        if event.event_type == "SSH_AUTH_FAILURE"
    ]

    failures.sort(
        key=lambda event: event.timestamp
    )

    groups: dict[tuple[str, str], list[Event]] = {}

    for event in failures:
        source_ip = event.source_ip or "unknown"
        username = event.user or "unknown"

        key = (
            source_ip,
            username,
        )

        groups.setdefault(
            key,
            [],
        ).append(event)

    findings: list[BruteForceFinding] = []

    finding_number = 1

    for (
        source_ip,
        username,
    ), group in groups.items():

        if len(group) < threshold:
            continue

        start_index = 0

        for end_index in range(len(group)):

            current_time = group[end_index].timestamp
            start_time = group[start_index].timestamp

            elapsed_seconds = (
                current_time - start_time
            ).total_seconds()

            while elapsed_seconds > window_seconds:
                start_index += 1

                start_time = group[
                    start_index
                ].timestamp

                elapsed_seconds = (
                    current_time - start_time
                ).total_seconds()

            window = group[
                start_index:end_index + 1
            ]

            if len(window) < threshold:
                continue

            event_ids = [
                event.event_id
                for event in window
            ]

            first_seen = (
                window[0]
                .timestamp
                .isoformat()
            )

            last_seen = (
                window[-1]
                .timestamp
                .isoformat()
            )

            finding = BruteForceFinding(
                finding_id=(
                    f"BRUTE-FORCE-"
                    f"{finding_number:04d}"
                ),
                event_type="SSH_BRUTE_FORCE",
                title="SSH Brute-Force Activity Detected",
                description=(
                    f"{len(window)} failed SSH "
                    f"authentication attempts were "
                    f"detected from {source_ip} "
                    f"against user {username} "
                    f"within {window_seconds} seconds."
                ),
                severity="HIGH",
                source_ip=source_ip,
                username=username,
                failed_attempts=len(window),
                first_seen=first_seen,
                last_seen=last_seen,
                event_ids=event_ids,
                metadata={
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                    "detection": (
                        "repeated_failed_ssh_authentication"
                    ),
                },
            )

            findings.append(finding)

            finding_number += 1

            break

    return findings


def detect_successful_login_after_brute_force(
    events: list[Event],
    threshold: int = 4,
    window_seconds: int = 300,
) -> list[SuccessfulLoginAfterBruteForceFinding]:
    """
    Detect successful SSH authentication following repeated
    failed authentication attempts from the same source IP
    against the same username.

    The successful login must occur after at least `threshold`
    failed attempts and within `window_seconds` of the first
    failed attempt.

    A following SSH session-open event is included when it
    belongs to the same user and occurs after the successful
    authentication.
    """

    sorted_events = sorted(
        events,
        key=lambda event: event.timestamp,
    )

    failures = [
        event
        for event in sorted_events
        if event.event_type == "SSH_AUTH_FAILURE"
    ]

    successes = [
        event
        for event in sorted_events
        if event.event_type == "SSH_AUTH_SUCCESS"
    ]

    sessions = [
        event
        for event in sorted_events
        if event.event_type == "SSH_SESSION_OPEN"
    ]

    findings: list[
        SuccessfulLoginAfterBruteForceFinding
    ] = []

    finding_number = 1

    for success in successes:

        source_ip = success.source_ip or "unknown"
        username = success.user or "unknown"

        matching_failures = [
            event
            for event in failures
            if (
                (event.source_ip or "unknown")
                == source_ip
                and
                (event.user or "unknown")
                == username
                and
                event.timestamp < success.timestamp
                and
                (
                    success.timestamp
                    - event.timestamp
                ).total_seconds()
                <= window_seconds
            )
        ]

        if len(matching_failures) < threshold:
            continue

        matching_failures.sort(
            key=lambda event: event.timestamp
        )

        first_failure = matching_failures[0]

        session_opened = None

        for session in sessions:
            if (
                (session.user or "unknown")
                == username
                and
                session.timestamp >= success.timestamp
            ):
                session_opened = session
                break

        event_ids = [
            event.event_id
            for event in matching_failures
        ]

        event_ids.append(
            success.event_id
        )

        if session_opened:
            event_ids.append(
                session_opened.event_id
            )

        finding = SuccessfulLoginAfterBruteForceFinding(
            finding_id=(
                f"BRUTE-FORCE-SUCCESS-"
                f"{finding_number:04d}"
            ),
            event_type=(
                "SSH_BRUTE_FORCE_SUCCESS"
            ),
            title=(
                "Successful SSH Login After "
                "Brute-Force Activity"
            ),
            description=(
                f"{len(matching_failures)} failed SSH "
                f"authentication attempts from "
                f"{source_ip} against user "
                f"{username} were followed by "
                f"a successful SSH authentication."
            ),
            severity="CRITICAL",
            source_ip=source_ip,
            username=username,
            failed_attempts=len(
                matching_failures
            ),
            first_failure=(
                first_failure.timestamp.isoformat()
            ),
            successful_login=(
                success.timestamp.isoformat()
            ),
            session_opened=(
                session_opened.timestamp.isoformat()
                if session_opened
                else None
            ),
            event_ids=event_ids,
            metadata={
                "threshold": threshold,
                "window_seconds": window_seconds,
                "detection": (
                    "successful_login_after_"
                    "repeated_failed_ssh_authentication"
                ),
                "session_detected": (
                    session_opened is not None
                ),
            },
        )

        findings.append(finding)

        finding_number += 1

    return findings
