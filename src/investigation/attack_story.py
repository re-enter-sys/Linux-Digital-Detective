from typing import Any


def _dict(value: Any) -> dict:
    """
    Convert an object into a dictionary.

    Supports dictionaries, dataclasses, and other
    objects exposing to_dict().
    """

    if isinstance(value, dict):
        return value

    if hasattr(value, "to_dict"):
        return value.to_dict()

    return vars(value)


def _normalize_items(
    items: list[Any],
) -> list[dict]:
    """Normalize a collection of objects into dictionaries."""

    return [
        _dict(item)
        for item in items
    ]


def _unique(values: list[Any]) -> list[Any]:
    """Return unique values while preserving order."""

    return list(
        dict.fromkeys(
            value
            for value in values
            if value
        )
    )


def _extract_source_ips(
    findings: list[dict],
    chains: list[dict],
) -> list[str]:
    """Extract unique source IP addresses."""

    values = []

    for finding in findings:
        source_ip = finding.get(
            "source_ip"
        )

        if source_ip:
            values.append(
                source_ip
            )

    for chain in chains:
        values.extend(
            chain.get(
                "source_ips",
                [],
            )
        )

    return _unique(values)


def _extract_usernames(
    findings: list[dict],
    chains: list[dict],
) -> list[str]:
    """Extract unique usernames."""

    values = []

    for finding in findings:
        username = (
            finding.get("username")
            or finding.get("user")
        )

        if username:
            values.append(
                username
            )

    for chain in chains:
        values.extend(
            chain.get(
                "usernames",
                [],
            )
        )

    return _unique(values)


def _finding_exists(
    findings: list[dict],
    event_type: str | None = None,
    category: str | None = None,
) -> bool:
    """Check whether a finding matches an event type or category."""

    for finding in findings:
        if (
            event_type
            and str(
                finding.get(
                    "event_type",
                    "",
                )
            ).upper()
            == event_type.upper()
        ):
            return True

        if (
            category
            and str(
                finding.get(
                    "category",
                    "",
                )
            ).upper()
            == category.upper()
        ):
            return True

    return False


def _severity_rank(
    severity: str,
) -> int:
    """Return a numerical severity ranking."""

    return {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(
        str(severity).upper(),
        0,
    )


def _highest_finding_severity(
    findings: list[dict],
) -> str:
    """Return the highest severity represented by findings."""

    if not findings:
        return "INFO"

    return max(
        (
            str(
                finding.get(
                    "severity",
                    "INFO",
                )
            ).upper()
            for finding in findings
        ),
        key=_severity_rank,
    )


def _build_primary_attack_path(
    findings: list[dict],
) -> list[str]:
    """
    Build an explainable high-level attack path.

    This is intentionally based on detected behavior rather
    than pretending that every event represents a confirmed
    attacker action.
    """

    path = []

    if _finding_exists(
        findings,
        event_type="SSH_BRUTE_FORCE",
    ):
        path.append(
            "Brute Force"
        )

    if _finding_exists(
        findings,
        event_type="SSH_BRUTE_FORCE_SUCCESS",
    ):
        path.append(
            "Successful SSH Access"
        )

    if _finding_exists(
        findings,
        event_type="PRIVILEGE_ESCALATION",
    ):
        path.append(
            "Privilege Escalation"
        )

    if _finding_exists(
        findings,
        category="CREDENTIAL_ACCESS",
    ):
        path.append(
            "Credential Access"
        )

    if (
        _finding_exists(
            findings,
            category="REVERSE_SHELL",
        )
        or _finding_exists(
            findings,
            category="SHELL_EXECUTION",
        )
        or _finding_exists(
            findings,
            category="ENCODED_EXECUTION",
        )
    ):
        path.append(
            "Command Execution"
        )

    if (
        _finding_exists(
            findings,
            category="SSH_AUTHORIZED_KEYS",
        )
        or _finding_exists(
            findings,
            category="CRON",
        )
        or _finding_exists(
            findings,
            category="SYSTEMD",
        )
        or _finding_exists(
            findings,
            category="SHELL_PROFILE",
        )
        or _finding_exists(
            findings,
            category="STARTUP_CONFIGURATION",
        )
    ):
        path.append(
            "Persistence"
        )

    return path


def _build_investigator_conclusion(
    findings: list[dict],
    risk: dict,
    usernames: list[str],
    source_ips: list[str],
) -> str:
    """
    Build a concise investigator-style assessment.
    """

    score = risk.get(
        "score",
        0,
    )

    severity = str(
        risk.get(
            "severity",
            "INFO",
        )
    ).upper()

    has_brute_force = _finding_exists(
        findings,
        event_type="SSH_BRUTE_FORCE",
    )

    has_success = _finding_exists(
        findings,
        event_type="SSH_BRUTE_FORCE_SUCCESS",
    )

    has_privilege_escalation = _finding_exists(
        findings,
        event_type="PRIVILEGE_ESCALATION",
    )

    if (
        has_brute_force
        and has_success
        and has_privilege_escalation
    ):
        conclusion = (
            "The available evidence is consistent with an "
            "SSH-based compromise involving repeated "
            "authentication failures, subsequent successful "
            "authentication, and a later privilege transition "
            "to a higher-privileged account."
        )

    elif has_brute_force and has_success:
        conclusion = (
            "The available evidence is consistent with "
            "successful SSH access following repeated "
            "authentication failures."
        )

    elif has_privilege_escalation:
        conclusion = (
            "The available evidence contains a privilege "
            "transition that requires investigation."
        )

    elif findings:
        conclusion = (
            "The investigation identified security-relevant "
            "activity requiring further investigation."
        )

    else:
        conclusion = (
            "No sufficiently strong malicious activity "
            "was identified from the available evidence."
        )

    identity_parts = []

    if usernames:
        identity_parts.append(
            "user="
            + ", ".join(usernames)
        )

    if source_ips:
        identity_parts.append(
            "source="
            + ", ".join(source_ips)
        )

    if identity_parts:
        conclusion += (
            " Observed "
            + " and ".join(identity_parts)
            + "."
        )

    conclusion += (
        f" Overall assessed risk is {severity} "
        f"({score}/100)."
    )

    return conclusion


def build_attack_story(
    findings: list[Any],
    chains: list[Any],
    risk_score: Any,
    mitre: list[Any],
) -> dict:
    """
    Build an explainable investigator-style attack narrative.

    The story combines detections, correlated attack chains,
    risk scoring, and MITRE ATT&CK mappings into a structured
    investigation summary suitable for the CLI, API, dashboard,
    and final report.
    """

    normalized_findings = _normalize_items(
        findings
    )

    normalized_chains = _normalize_items(
        chains
    )

    normalized_mitre = _normalize_items(
        mitre
    )

    risk = _dict(
        risk_score
    )

    story_parts: list[str] = []

    source_ips = _extract_source_ips(
        normalized_findings,
        normalized_chains,
    )

    usernames = _extract_usernames(
        normalized_findings,
        normalized_chains,
    )

    attack_path = _build_primary_attack_path(
        normalized_findings
    )

    # --------------------------------------------------------------
    # Initial access
    # --------------------------------------------------------------

    if _finding_exists(
        normalized_findings,
        event_type="SSH_BRUTE_FORCE",
    ):
        source_text = (
            f" from {', '.join(source_ips)}"
            if source_ips
            else ""
        )

        user_text = (
            f" against account(s) "
            f"{', '.join(usernames)}"
            if usernames
            else ""
        )

        story_parts.append(
            "Repeated SSH authentication failures "
            f"were detected{source_text}"
            f"{user_text}. "
            "This behavior is consistent with "
            "credential-guessing activity."
        )

    # --------------------------------------------------------------
    # Successful access
    # --------------------------------------------------------------

    if _finding_exists(
        normalized_findings,
        event_type="SSH_BRUTE_FORCE_SUCCESS",
    ):
        story_parts.append(
            "A successful SSH authentication occurred "
            "after the failed authentication sequence. "
            "This materially increases the likelihood that "
            "the targeted account was successfully accessed."
        )

    # --------------------------------------------------------------
    # Session
    # --------------------------------------------------------------

    if _finding_exists(
        normalized_findings,
        event_type="SSH_BRUTE_FORCE_SUCCESS",
    ):
        story_parts.append(
            "The authentication sequence was followed by "
            "an SSH session, providing additional evidence "
            "of successful account access."
        )

    # --------------------------------------------------------------
    # Privilege escalation
    # --------------------------------------------------------------

    if _finding_exists(
        normalized_findings,
        event_type="PRIVILEGE_ESCALATION",
    ):
        privilege_findings = [
            finding
            for finding in normalized_findings
            if "PRIVILEGE"
            in str(
                finding.get(
                    "event_type",
                    "",
                )
            ).upper()
        ]

        commands = _unique(
            [
                finding.get(
                    "command"
                )
                for finding in privilege_findings
            ]
        )

        command_text = ""

        if commands:
            command_text = (
                " Observed command(s): "
                + "; ".join(
                    commands
                )
                + "."
            )

        story_parts.append(
            "A privilege transition was detected through "
            "sudo execution. This indicates that the "
            "authenticated account obtained higher local "
            "privileges and requires investigation."
            + command_text
        )

    # --------------------------------------------------------------
    # Credential access
    # --------------------------------------------------------------

    if _finding_exists(
        normalized_findings,
        category="CREDENTIAL_ACCESS",
    ):
        story_parts.append(
            "Credential-access behavior was observed, "
            "indicating possible attempts to obtain or "
            "inspect authentication material."
        )

    # --------------------------------------------------------------
    # Network reconnaissance
    # --------------------------------------------------------------

    if (
        _finding_exists(
            normalized_findings,
            category="PORT_SCAN",
        )
        or _finding_exists(
            normalized_findings,
            category="NETWORK_RECON",
        )
        or _finding_exists(
            normalized_findings,
            category="NETWORK_DISCOVERY",
        )
        or _finding_exists(
            normalized_findings,
            category="CONNECTION_ENUMERATION",
        )
    ):
        story_parts.append(
            "Network reconnaissance activity was detected, "
            "indicating possible enumeration of services, "
            "network configuration, or active connections."
        )

    # --------------------------------------------------------------
    # Command execution
    # --------------------------------------------------------------

    if (
        _finding_exists(
            normalized_findings,
            category="REVERSE_SHELL",
        )
        or _finding_exists(
            normalized_findings,
            category="SHELL_EXECUTION",
        )
        or _finding_exists(
            normalized_findings,
            category="ENCODED_EXECUTION",
        )
    ):
        story_parts.append(
            "Suspicious command-execution behavior was "
            "detected and should be reviewed for evidence "
            "of attacker-controlled execution."
        )

    # --------------------------------------------------------------
    # Persistence
    # --------------------------------------------------------------

    if (
        _finding_exists(
            normalized_findings,
            category="SSH_AUTHORIZED_KEYS",
        )
        or _finding_exists(
            normalized_findings,
            category="CRON",
        )
        or _finding_exists(
            normalized_findings,
            category="SYSTEMD",
        )
        or _finding_exists(
            normalized_findings,
            category="SHELL_PROFILE",
        )
        or _finding_exists(
            normalized_findings,
            category="STARTUP_CONFIGURATION",
        )
    ):
        story_parts.append(
            "Persistence-related activity was detected, "
            "suggesting a possible attempt to maintain "
            "access beyond the initial session."
        )

    # --------------------------------------------------------------
    # Download / C2
    # --------------------------------------------------------------

    if (
        _finding_exists(
            normalized_findings,
            category="DOWNLOAD",
        )
        or _finding_exists(
            normalized_findings,
            category="REMOTE_DOWNLOAD",
        )
        or _finding_exists(
            normalized_findings,
            category="REVERSE_SHELL",
        )
    ):
        story_parts.append(
            "Remote content transfer or command-and-control "
            "behavior was observed."
        )

    # --------------------------------------------------------------
    # Fallback
    # --------------------------------------------------------------

    if not story_parts:
        story_parts.append(
            "No sufficiently strong multi-stage attack "
            "narrative was reconstructed from the available "
            "evidence."
        )

    highest_finding_severity = (
        _highest_finding_severity(
            normalized_findings
        )
    )

    confidence = risk.get(
        "confidence",
        0,
    )

    conclusion = _build_investigator_conclusion(
        normalized_findings,
        risk,
        usernames,
        source_ips,
    )

    return {
        "title": (
            "Linux Digital Detective Investigation"
        ),
        "narrative": story_parts,
        "conclusion": conclusion,
        "risk_score": risk,
        "attack_chains": normalized_chains,
        "mitre_techniques": normalized_mitre,
        "attack_path": attack_path,
        "source_ips": source_ips,
        "usernames": usernames,
        "finding_count": len(
            normalized_findings
        ),
        "chain_count": len(
            normalized_chains
        ),
        "highest_finding_severity": (
            highest_finding_severity
        ),
        "confidence": confidence,
    }
