from dataclasses import dataclass, field
from typing import Optional

from src.timeline.events import Event


@dataclass
class NetworkActivityFinding:
    """
    Represents suspicious or investigation-relevant
    network activity discovered in forensic evidence.
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
    destination_ip: Optional[str]
    destination_port: Optional[int]
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
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "indicators": self.indicators,
            "metadata": self.metadata,
        }


NETWORK_COMMAND_RULES = [
    {
        "category": "PORT_SCAN",
        "severity": "HIGH",
        "patterns": [
            "nmap ",
            "masscan ",
            "rustscan ",
        ],
        "title": "Potential Port Scanning Activity",
        "description": (
            "A network scanning utility was executed and "
            "may indicate reconnaissance against network "
            "hosts or services."
        ),
    },
    {
        "category": "NETWORK_DISCOVERY",
        "severity": "MEDIUM",
        "patterns": [
            "ip addr",
            "ip a",
            "ifconfig",
            "ip route",
            "route -n",
            "arp -a",
            "ip neigh",
        ],
        "title": "Network Discovery Activity",
        "description": (
            "The command performs local network "
            "configuration or neighbor discovery."
        ),
    },
    {
        "category": "CONNECTION_ENUMERATION",
        "severity": "MEDIUM",
        "patterns": [
            "ss -",
            "netstat ",
            "lsof -i",
        ],
        "title": "Network Connection Enumeration",
        "description": (
            "The command enumerates active or listening "
            "network connections."
        ),
    },
    {
        "category": "NETWORK_TOOL",
        "severity": "MEDIUM",
        "patterns": [
            "nc ",
            "netcat ",
            "ncat ",
            "socat ",
        ],
        "title": "Network Utility Execution",
        "description": (
            "A command-line network utility was executed "
            "and may require investigation."
        ),
    },
    {
        "category": "REMOTE_DOWNLOAD",
        "severity": "MEDIUM",
        "patterns": [
            "curl http://",
            "curl https://",
            "wget http://",
            "wget https://",
        ],
        "title": "Remote Network Download",
        "description": (
            "The command downloads content from a remote "
            "network location."
        ),
    },
]


def detect_network_activity(
    events: list[Event],
) -> list[NetworkActivityFinding]:
    """
    Detect suspicious or investigation-relevant network
    activity from normalized command events.

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

    findings: list[NetworkActivityFinding] = []

    finding_number = 1

    for event in command_events:

        command = event.command or ""

        normalized_command = command.lower()

        for rule in NETWORK_COMMAND_RULES:

            matched_indicators = [
                pattern
                for pattern in rule["patterns"]
                if pattern.lower() in normalized_command
            ]

            if not matched_indicators:
                continue

            finding = NetworkActivityFinding(
                finding_id=(
                    f"NETWORK-ACTIVITY-"
                    f"{finding_number:04d}"
                ),
                event_type="NETWORK_ACTIVITY",
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
                destination_ip=(
                    event.metadata.get(
                        "destination_ip"
                    )
                ),
                destination_port=(
                    event.metadata.get(
                        "destination_port"
                    )
                ),
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
