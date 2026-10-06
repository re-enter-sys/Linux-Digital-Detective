from dataclasses import dataclass, field
from typing import Optional

from src.timeline.events import Event


@dataclass
class SuspiciousCommandFinding:
    """
    Represents a suspicious command discovered during
    forensic investigation.
    """

    finding_id: str
    event_type: str
    title: str
    description: str
    severity: str
    username: Optional[str]
    command: Optional[str]
    source_ip: Optional[str]
    category: str
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
            "command": self.command,
            "source_ip": self.source_ip,
            "category": self.category,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "indicators": self.indicators,
            "metadata": self.metadata,
        }


COMMAND_RULES = [
    {
        "category": "DOWNLOAD",
        "severity": "MEDIUM",
        "patterns": [
            "curl ",
            "curl\t",
            "wget ",
            "wget\t",
        ],
        "title": "Suspicious File Download Command",
        "description": (
            "A command capable of downloading remote "
            "content was executed."
        ),
    },
    {
        "category": "REVERSE_SHELL",
        "severity": "CRITICAL",
        "patterns": [
            "/dev/tcp/",
            "bash -i",
            "sh -i",
            "nc -e",
            "nc.exe -e",
            "ncat -e",
            "socat exec:",
        ],
        "title": "Potential Reverse Shell Command",
        "description": (
            "The command contains indicators commonly "
            "associated with interactive or reverse shell "
            "execution."
        ),
    },
    {
        "category": "ENCODED_EXECUTION",
        "severity": "HIGH",
        "patterns": [
            "base64 -d",
            "base64 --decode",
            "| base64 -d",
            "|base64 -d",
        ],
        "title": "Potential Encoded Command Execution",
        "description": (
            "The command contains an encoded-content "
            "decoding pattern that may indicate obfuscated "
            "command execution."
        ),
    },
    {
        "category": "SHELL_EXECUTION",
        "severity": "HIGH",
        "patterns": [
            "bash -c",
            "sh -c",
            "zsh -c",
        ],
        "title": "Suspicious Shell Execution",
        "description": (
            "A nested shell was invoked through a command "
            "execution construct."
        ),
    },
    {
        "category": "CREDENTIAL_ACCESS",
        "severity": "HIGH",
        "patterns": [
            "/etc/shadow",
            "/etc/passwd",
            "passwd",
            "shadow",
            "ssh-keygen",
            ".ssh/id_rsa",
            ".ssh/authorized_keys",
        ],
        "title": "Potential Credential or SSH Key Access",
        "description": (
            "The command references credential stores or "
            "SSH authentication material."
        ),
    },
    {
        "category": "NETWORK_RECON",
        "severity": "MEDIUM",
        "patterns": [
            "nmap ",
            "masscan ",
            "netcat ",
            "nc ",
            "ss -",
            "netstat ",
        ],
        "title": "Potential Network Reconnaissance Command",
        "description": (
            "The command contains a network discovery or "
            "connection utility."
        ),
    },
]


def detect_suspicious_commands(
    events: list[Event],
) -> list[SuspiciousCommandFinding]:
    """
    Detect suspicious command patterns in normalized events.

    Only events containing a command are considered.
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

    findings: list[SuspiciousCommandFinding] = []

    finding_number = 1

    for event in command_events:

        command = event.command or ""

        normalized_command = command.lower()

        for rule in COMMAND_RULES:

            matched_indicators = [
                pattern
                for pattern in rule["patterns"]
                if pattern.lower() in normalized_command
            ]

            if not matched_indicators:
                continue

            finding = SuspiciousCommandFinding(
                finding_id=(
                    f"SUSPICIOUS-CMD-"
                    f"{finding_number:04d}"
                ),
                event_type="SUSPICIOUS_COMMAND",
                title=rule["title"],
                description=(
                    f"{rule['description']} "
                    f"Observed command: {command}"
                ),
                severity=rule["severity"],
                username=event.user,
                command=command,
                source_ip=event.source_ip,
                category=rule["category"],
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
