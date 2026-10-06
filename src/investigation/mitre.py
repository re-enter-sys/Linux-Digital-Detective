from dataclasses import dataclass, field
from typing import Any


@dataclass
class MitreTechnique:
    """
    Represents a MITRE ATT&CK technique mapped from
    investigation evidence.
    """

    technique_id: str
    name: str
    tactic: str
    description: str

    finding_ids: list[str] = field(
        default_factory=list
    )

    event_ids: list[str] = field(
        default_factory=list
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "finding_ids": self.finding_ids,
            "event_ids": self.event_ids,
        }


TECHNIQUE_RULES = {
    # --------------------------------------------------------------
    # Credential Access
    # --------------------------------------------------------------

    "SSH_BRUTE_FORCE": (
        "T1110.001",
        "Password Guessing",
        "Credential Access",
        (
            "Repeated authentication attempts against an "
            "SSH account are consistent with password guessing."
        ),
    ),

    "SSH_BRUTE_FORCE_SUCCESS": (
        "T1110.001",
        "Password Guessing",
        "Credential Access",
        (
            "Successful authentication following repeated "
            "failed attempts provides evidence consistent "
            "with password-guessing activity."
        ),
    ),

    # --------------------------------------------------------------
    # Discovery
    # --------------------------------------------------------------

    "PORT_SCAN": (
        "T1046",
        "Network Service Scanning",
        "Discovery",
        (
            "Network services were enumerated."
        ),
    ),

    "NETWORK_DISCOVERY": (
        "T1016",
        "System Network Configuration Discovery",
        "Discovery",
        (
            "Network configuration was inspected."
        ),
    ),

    "CONNECTION_ENUMERATION": (
        "T1049",
        "System Network Connections Discovery",
        "Discovery",
        (
            "Active network connections were enumerated."
        ),
    ),

    # --------------------------------------------------------------
    # Credential Access
    # --------------------------------------------------------------

    "CREDENTIAL_ACCESS": (
        "T1003",
        "OS Credential Dumping",
        "Credential Access",
        (
            "Credential-related system files or artifacts "
            "were accessed."
        ),
    ),

    # --------------------------------------------------------------
    # Privilege Escalation
    # --------------------------------------------------------------

    "PRIVILEGE_ESCALATION": (
        "T1548.003",
        "Sudo and Sudo Caching",
        "Privilege Escalation",
        (
            "Sudo was used to execute a command with "
            "higher local privileges."
        ),
    ),

    # --------------------------------------------------------------
    # Execution
    # --------------------------------------------------------------

    "REVERSE_SHELL": (
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        (
            "A shell execution pattern associated with "
            "remote access was detected."
        ),
    ),

    "SHELL_EXECUTION": (
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        (
            "Shell commands were executed."
        ),
    ),

    "ENCODED_EXECUTION": (
        "T1027",
        "Obfuscated Files or Information",
        "Defense Evasion",
        (
            "Encoded content was decoded during command "
            "execution."
        ),
    ),

    # --------------------------------------------------------------
    # Command and Control
    # --------------------------------------------------------------

    "DOWNLOAD": (
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
        (
            "Content was retrieved from a remote location."
        ),
    ),

    "REMOTE_DOWNLOAD": (
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
        (
            "Content was retrieved from a remote "
            "network location."
        ),
    ),

    # --------------------------------------------------------------
    # Persistence
    # --------------------------------------------------------------

    "SSH_AUTHORIZED_KEYS": (
        "T1098.004",
        "SSH Authorized Keys",
        "Persistence",
        (
            "SSH authorized keys were modified."
        ),
    ),

    "CRON": (
        "T1053.003",
        "Cron",
        "Persistence",
        (
            "Cron-based persistence activity was detected."
        ),
    ),

    "SYSTEMD": (
        "T1543.002",
        "Systemd Service",
        "Persistence",
        (
            "A systemd service was configured or enabled."
        ),
    ),

    "SHELL_PROFILE": (
        "T1546.004",
        "Unix Shell Configuration Modification",
        "Persistence",
        (
            "Shell startup configuration was modified."
        ),
    ),

    "STARTUP_CONFIGURATION": (
        "T1037",
        "Boot or Logon Initialization Scripts",
        "Persistence",
        (
            "Startup configuration was modified."
        ),
    ),
}


def _finding_to_dict(
    finding: Any,
) -> dict[str, Any]:
    """Normalize a finding into a dictionary."""

    if isinstance(
        finding,
        dict,
    ):
        return finding

    if hasattr(
        finding,
        "to_dict",
    ):
        return finding.to_dict()

    return {
        key: value
        for key, value in vars(finding).items()
        if not key.startswith("_")
    }


def _unique(
    values: list[Any],
) -> list[Any]:
    """Return unique values while preserving order."""

    return list(
        dict.fromkeys(
            value
            for value in values
            if value
        )
    )


def _resolve_rule(
    event_type: str,
    category: str,
):
    """
    Resolve a MITRE rule from event type first,
    then category.
    """

    event_type = str(
        event_type
    ).upper()

    category = str(
        category
    ).upper()

    return (
        TECHNIQUE_RULES.get(
            event_type
        )
        or TECHNIQUE_RULES.get(
            category
        )
    )


def map_findings_to_mitre(
    findings: list[Any],
) -> list[MitreTechnique]:
    """
    Map normalized detection findings to MITRE ATT&CK.

    Multiple findings mapping to the same ATT&CK technique
    are consolidated into a single technique record while
    retaining all associated finding and event IDs.
    """

    techniques: dict[
        str,
        MitreTechnique,
    ] = {}

    for finding in findings:
        data = _finding_to_dict(
            finding
        )

        event_type = str(
            data.get(
                "event_type",
                "",
            )
        )

        category = str(
            data.get(
                "category",
                "",
            )
        )

        rule = _resolve_rule(
            event_type,
            category,
        )

        if not rule:
            continue

        (
            technique_id,
            name,
            tactic,
            description,
        ) = rule

        if technique_id not in techniques:
            techniques[
                technique_id
            ] = MitreTechnique(
                technique_id=technique_id,
                name=name,
                tactic=tactic,
                description=description,
            )

        technique = techniques[
            technique_id
        ]

        finding_id = data.get(
            "finding_id"
        )

        if finding_id:
            technique.finding_ids.append(
                finding_id
            )

        event_ids = data.get(
            "event_ids",
            [],
        )

        if not event_ids:
            event_id = data.get(
                "event_id"
            )

            if event_id:
                event_ids = [
                    event_id
                ]

        technique.event_ids.extend(
            event_ids
        )

    # --------------------------------------------------------------
    # Deduplicate references
    # --------------------------------------------------------------

    for technique in techniques.values():
        technique.finding_ids = _unique(
            technique.finding_ids
        )

        technique.event_ids = _unique(
            technique.event_ids
        )

    return list(
        techniques.values()
    )
