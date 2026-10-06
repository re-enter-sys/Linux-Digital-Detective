from dataclasses import dataclass, field
from typing import Optional

from src.timeline.events import Event


@dataclass
class PersistenceFinding:
    """
    Represents a potential persistence mechanism discovered
    during forensic investigation.
    """

    finding_id: str
    event_type: str
    title: str
    description: str
    severity: str
    category: str
    username: Optional[str]
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
            "category": self.category,
            "username": self.username,
            "command": self.command,
            "source_ip": self.source_ip,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "indicators": self.indicators,
            "metadata": self.metadata,
        }


PERSISTENCE_RULES = [
    {
        "category": "SSH_AUTHORIZED_KEYS",
        "severity": "HIGH",
        "patterns": [
            "authorized_keys",
            ".ssh/authorized_keys",
        ],
        "title": "SSH Authorized Keys Persistence",
        "description": (
            "The command references an SSH authorized_keys "
            "file, which may be used to establish persistent "
            "SSH access."
        ),
    },
    {
        "category": "CRON",
        "severity": "HIGH",
        "patterns": [
            "crontab",
            "/etc/cron",
            "/var/spool/cron",
        ],
        "title": "Potential Cron Persistence",
        "description": (
            "The command references cron configuration "
            "that can be used to execute commands "
            "automatically."
        ),
    },
    {
        "category": "SYSTEMD",
        "severity": "HIGH",
        "patterns": [
            "systemctl enable",
            "systemctl start",
            "systemctl daemon-reload",
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
        ],
        "title": "Potential Systemd Persistence",
        "description": (
            "The command references systemd service "
            "configuration or service activation."
        ),
    },
    {
        "category": "SHELL_PROFILE",
        "severity": "MEDIUM",
        "patterns": [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
        ],
        "title": "Potential Shell Profile Persistence",
        "description": (
            "The command references a shell startup "
            "configuration file that may execute commands "
            "when a user starts a shell."
        ),
    },
    {
        "category": "STARTUP_CONFIGURATION",
        "severity": "HIGH",
        "patterns": [
            "/etc/rc.local",
            "rc.local",
            "/etc/init.d/",
        ],
        "title": "Potential Startup Persistence",
        "description": (
            "The command references a system startup "
            "configuration location."
        ),
    },
]


def detect_persistence(
    events: list[Event],
) -> list[PersistenceFinding]:
    """
    Detect potential persistence mechanisms in normalized
    command events.

    Matching is case-insensitive.
    """

    command_events = [
        event
        for event in events
        if event.command
    ]

    command_events.sort(
        key=lambda event: event.timestamp
    )

    findings: list[PersistenceFinding] = []

    finding_number = 1

    for event in command_events:

        command = event.command or ""

        normalized_command = command.lower()

        for rule in PERSISTENCE_RULES:

            matched_indicators = [
                pattern
                for pattern in rule["patterns"]
                if pattern.lower() in normalized_command
            ]

            if not matched_indicators:
                continue

            finding = PersistenceFinding(
                finding_id=(
                    f"PERSISTENCE-"
                    f"{finding_number:04d}"
                ),
                event_type="PERSISTENCE_DETECTED",
                title=rule["title"],
                description=(
                    f"{rule['description']} "
                    f"Observed command: {command}"
                ),
                severity=rule["severity"],
                category=rule["category"],
                username=event.user,
                command=command,
                source_ip=event.source_ip,
                event_id=event.event_id,
                timestamp=event.timestamp.isoformat(),
                indicators=matched_indicators,
                metadata={
                    "rule_category": rule["category"],
                    "source": event.source,
                    "original_event_type": (
                        event.event_type
                    ),
                    "sudo_context": (
                        event.event_type
                        == "SUDO_COMMAND"
                    ),
                },
            )

            findings.append(finding)

            finding_number += 1

    return findings
