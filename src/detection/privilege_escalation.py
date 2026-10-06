from dataclasses import dataclass, field
from typing import Optional

from src.timeline.events import Event


@dataclass
class PrivilegeEscalationFinding:
    """
    Represents a potential privilege-escalation event.

    The detector currently focuses on normalized sudo events
    where a non-root user executes a command as another user,
    especially root.
    """

    finding_id: str
    event_type: str
    title: str
    description: str
    severity: str
    username: Optional[str]
    target_user: Optional[str]
    command: Optional[str]
    source_ip: Optional[str]
    event_id: str
    timestamp: str
    indicators: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert the finding into a JSON-compatible dictionary."""

        return {
            "finding_id": self.finding_id,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "username": self.username,
            "target_user": self.target_user,
            "command": self.command,
            "source_ip": self.source_ip,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "indicators": self.indicators,
            "metadata": self.metadata,
        }


def detect_privilege_escalation(
    events: list[Event],
) -> list[PrivilegeEscalationFinding]:
    """
    Detect privilege escalation from normalized events.

    A finding is generated when a SUDO_COMMAND event indicates
    that the invoking user differs from the target user.

    Root execution is treated as CRITICAL because it represents
    a transition into the highest-privilege local account.
    """

    sudo_events = [
        event
        for event in events
        if event.event_type == "SUDO_COMMAND"
    ]

    sudo_events.sort(
        key=lambda event: event.timestamp
    )

    findings: list[PrivilegeEscalationFinding] = []

    finding_number = 1

    for event in sudo_events:
        username = event.user or "unknown"

        target_user = event.metadata.get(
            "target_user"
        )

        if not target_user:
            target_user = "unknown"

        privilege_change = event.metadata.get(
            "privilege_change",
            username != target_user,
        )

        if not privilege_change:
            continue

        if target_user.lower() == "root":
            severity = "CRITICAL"
        else:
            severity = "HIGH"

        finding = PrivilegeEscalationFinding(
            finding_id=(
                f"PRIV-ESC-"
                f"{finding_number:04d}"
            ),
            event_type="PRIVILEGE_ESCALATION",
            title="Potential Privilege Escalation Detected",
            description=(
                f"User {username} executed a command through "
                f"sudo as {target_user}. "
                f"This represents a privilege transition "
                f"that requires investigation."
            ),
            severity=severity,
            username=username,
            target_user=target_user,
            command=event.command,
            source_ip=event.source_ip,
            event_id=event.event_id,
            timestamp=event.timestamp.isoformat(),
            indicators=[
                "sudo",
                f"target_user={target_user}",
            ],
            metadata={
                "detection": "sudo_privilege_transition",
                "original_event_type": event.event_type,
                "source": event.source,
                "tty": event.metadata.get("tty"),
                "pwd": event.metadata.get("pwd"),
                "privilege_change": True,
                "root_target": (
                    target_user.lower() == "root"
                ),
            },
        )

        findings.append(finding)

        finding_number += 1

    return findings
