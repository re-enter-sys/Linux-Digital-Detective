from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


DEFAULT_CORRELATION_WINDOW_SECONDS = 900


# ============================================================
# ATTACK STAGE MODEL
# ============================================================

STAGE_ORDER = {
    "RECONNAISSANCE": 10,
    "INITIAL_ACCESS": 20,
    "PRIVILEGE_ESCALATION": 30,
    "CREDENTIAL_ACCESS": 40,
    "EXECUTION": 50,
    "PERSISTENCE": 60,
    "COMMAND_AND_CONTROL": 70,
    "DISCOVERY": 80,
    "IMPACT": 90,
}


STAGE_LABELS = {
    "RECONNAISSANCE": "Reconnaissance",
    "INITIAL_ACCESS": "Initial Access",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "CREDENTIAL_ACCESS": "Credential Access",
    "EXECUTION": "Execution",
    "PERSISTENCE": "Persistence",
    "COMMAND_AND_CONTROL": "Command & Control",
    "DISCOVERY": "Discovery",
    "IMPACT": "Impact",
}


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class AttackChainStep:
    step_id: str
    stage: str
    title: str
    description: str
    timestamp: Optional[str]
    severity: str
    event_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "stage": self.stage,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "event_ids": self.event_ids,
            "finding_ids": self.finding_ids,
            "indicators": self.indicators,
            "metadata": self.metadata,
        }


@dataclass
class AttackChain:
    chain_id: str
    title: str
    summary: str
    severity: str
    confidence: int
    start_time: Optional[str]
    end_time: Optional[str]
    source_ips: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    steps: list[AttackChainStep] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "confidence": self.confidence,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "source_ips": self.source_ips,
            "usernames": self.usernames,
            "steps": [
                step.to_dict()
                for step in self.steps
            ],
            "finding_ids": self.finding_ids,
            "event_ids": self.event_ids,
            "metadata": self.metadata,
        }


# ============================================================
# NORMALIZATION HELPERS
# ============================================================

def _finding_dict(finding: Any) -> dict[str, Any]:
    if isinstance(finding, dict):
        return finding

    if hasattr(finding, "to_dict"):
        return finding.to_dict()

    return {
        key: value
        for key, value in vars(finding).items()
        if not key.startswith("_")
    }


def _event_dict(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return event

    if hasattr(event, "to_dict"):
        return event.to_dict()

    return {
        key: value
        for key, value in vars(event).items()
        if not key.startswith("_")
    }


def _timestamp(finding: dict[str, Any]) -> Optional[str]:
    return (
        finding.get("timestamp")
        or finding.get("first_seen")
        or finding.get("first_failure")
        or finding.get("successful_login")
    )


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        return value

    try:
        return datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00",
            )
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


def _timestamp_sort_key(
    finding: dict[str, Any],
) -> datetime:
    timestamp = _parse_timestamp(
        _timestamp(finding)
    )

    if timestamp is not None:
        return timestamp

    return datetime.min


# ============================================================
# SEVERITY
# ============================================================

def _severity_rank(severity: str) -> int:
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


def _highest_severity(
    findings: list[dict[str, Any]],
) -> str:
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


# ============================================================
# STAGE CLASSIFICATION
# ============================================================

def _stage_for_finding(
    finding: dict[str, Any],
) -> str:
    """
    Map a detection finding into an investigation stage.

    The classifier intentionally examines multiple fields
    because detection engines may expose the same concept
    through event_type, category, title, or description.
    """

    event_type = str(
        finding.get(
            "event_type",
            "",
        )
    ).upper()

    category = str(
        finding.get(
            "category",
            "",
        )
    ).upper()

    title = str(
        finding.get(
            "title",
            "",
        )
    ).upper()

    name = str(
        finding.get(
            "name",
            "",
        )
    ).upper()

    description = str(
        finding.get(
            "description",
            "",
        )
    ).upper()

    text = " ".join(
        [
            event_type,
            category,
            title,
            name,
            description,
        ]
    )

    # --------------------------------------------------------
    # Reconnaissance
    # --------------------------------------------------------

    if any(
        token in text
        for token in (
            "NETWORK_RECON",
            "PORT_SCAN",
            "NETWORK_DISCOVERY",
            "CONNECTION_ENUMERATION",
            "PORT ENUMERATION",
            "NETWORK RECON",
            "SCAN",
            "NMAP",
        )
    ):
        return "RECONNAISSANCE"

    # --------------------------------------------------------
    # SSH brute force / initial access
    # --------------------------------------------------------

    if any(
        token in text
        for token in (
            "BRUTE_FORCE",
            "BRUTE FORCE",
            "SSH_ATTACK",
            "AUTHENTICATION_FAILURE",
            "AUTH FAILURE",
            "FAILED LOGIN",
            "FAILED PASSWORD",
            "SSH FAILURE",
        )
    ):
        return "INITIAL_ACCESS"

    if (
        (
            "SUCCESS" in event_type
            and "LOGIN" in event_type
        )
        or any(
            token in text
            for token in (
                "SUCCESSFUL SSH LOGIN",
                "SUCCESSFUL LOGIN",
                "ACCEPTED PASSWORD",
                "SSH LOGIN",
                "LOGIN SUCCESS",
            )
        )
    ):
        return "INITIAL_ACCESS"

    # --------------------------------------------------------
    # Privilege escalation
    # --------------------------------------------------------

    if any(
        token in text
        for token in (
            "PRIVILEGE",
            "PRIV ESC",
            "PRIVESC",
            "SUDO",
            "ROOT ACCESS",
            "ELEVATED PRIVILEGE",
            "ELEVATION",
        )
    ):
        return "PRIVILEGE_ESCALATION"

    # --------------------------------------------------------
    # Credential access
    # --------------------------------------------------------

    if any(
        token in text
        for token in (
            "CREDENTIAL_ACCESS",
            "CREDENTIAL ACCESS",
            "PASSWORD",
            "SHADOW",
            "CREDENTIAL",
            "SECRET",
            "TOKEN",
            "KEY MATERIAL",
            "SSH KEY",
        )
    ):
        return "CREDENTIAL_ACCESS"

    # --------------------------------------------------------
    # Persistence
    # --------------------------------------------------------

    if any(
        token in text
        for token in (
            "PERSIST",
            "PERSISTENCE",
            "AUTHORIZED_KEYS",
            "CRON",
            "SYSTEMD",
            "SHELL_PROFILE",
            "STARTUP_CONFIGURATION",
            "AUTOSTART",
            "BOOT",
            "SSH_AUTHORIZED_KEYS",
        )
    ):
        return "PERSISTENCE"

    # --------------------------------------------------------
    # Execution
    # --------------------------------------------------------

    if any(
        token in text
        for token in (
            "REVERSE_SHELL",
            "REVERSE SHELL",
            "SHELL_EXECUTION",
            "ENCODED_EXECUTION",
            "COMMAND_EXECUTION",
            "COMMAND EXECUTION",
            "SHELL COMMAND",
            "MALICIOUS COMMAND",
            "EXECUTION",
        )
    ):
        return "EXECUTION"

    # --------------------------------------------------------
    # Command & Control
    # --------------------------------------------------------

    if any(
        token in text
        for token in (
            "REMOTE_DOWNLOAD",
            "DOWNLOAD",
            "NETWORK_TOOL",
            "CURL",
            "WGET",
            "C2",
            "COMMAND_AND_CONTROL",
            "COMMAND & CONTROL",
        )
    ):
        return "COMMAND_AND_CONTROL"

    # --------------------------------------------------------
    # Impact
    # --------------------------------------------------------

    if any(
        token in text
        for token in (
            "DENIAL_OF_SERVICE",
            "DOS",
            "IMPACT",
            "DESTRUCTIVE",
            "FILE_DELETION",
            "DATA_DESTRUCTION",
        )
    ):
        return "IMPACT"

    # --------------------------------------------------------
    # Default
    # --------------------------------------------------------

    return "DISCOVERY"


# ============================================================
# INDICATORS
# ============================================================

def _finding_identity(
    finding: dict[str, Any],
) -> set[str]:
    identities: set[str] = set()

    for key in (
        "username",
        "user",
        "target_user",
        "invoking_user",
        "account",
    ):
        value = finding.get(key)

        if value:
            identities.add(
                str(value)
            )

    indicators = finding.get(
        "indicators",
        [],
    )

    if isinstance(indicators, list):
        for indicator in indicators:
            if isinstance(indicator, dict):
                value = (
                    indicator.get("username")
                    or indicator.get("user")
                    or indicator.get("account")
                )

                if value:
                    identities.add(
                        str(value)
                    )

    return identities


def _finding_ips(
    finding: dict[str, Any],
) -> set[str]:
    addresses: set[str] = set()

    for key in (
        "source_ip",
        "src_ip",
        "remote_ip",
        "client_ip",
        "destination_ip",
        "dest_ip",
    ):
        value = finding.get(key)

        if value:
            addresses.add(
                str(value)
            )

    indicators = finding.get(
        "indicators",
        [],
    )

    if isinstance(indicators, list):
        for indicator in indicators:
            if isinstance(indicator, dict):
                value = (
                    indicator.get("source_ip")
                    or indicator.get("src_ip")
                    or indicator.get("remote_ip")
                    or indicator.get("client_ip")
                    or indicator.get("destination_ip")
                    or indicator.get("dest_ip")
                    or indicator.get("ip")
                )

                if value:
                    addresses.add(
                        str(value)
                    )

    return addresses


def _finding_event_ids(
    finding: dict[str, Any],
) -> list[str]:
    event_ids = finding.get(
        "event_ids",
        [],
    )

    if not event_ids and finding.get(
        "event_id"
    ):
        event_ids = [
            finding["event_id"]
        ]

    if not isinstance(event_ids, list):
        event_ids = [event_ids]

    return [
        str(event_id)
        for event_id in event_ids
        if event_id
    ]


# ============================================================
# EVIDENCE SOURCES
# ============================================================

def _finding_sources(
    finding: dict[str, Any],
    event_lookup: dict[str, dict[str, Any]],
) -> set[str]:
    sources: set[str] = set()

    source = finding.get(
        "source"
    )

    if source:
        sources.add(
            str(source)
        )

    event_ids = _finding_event_ids(
        finding
    )

    for event_id in event_ids:
        event = event_lookup.get(
            str(event_id)
        )

        if not event:
            continue

        event_source = event.get(
            "source"
        )

        if event_source:
            sources.add(
                str(event_source)
            )

    return sources


# ============================================================
# FINDING RELATIONSHIP LOGIC
# ============================================================

def _share_identity_or_ip(
    first: dict[str, Any],
    second: dict[str, Any],
) -> bool:
    return bool(
        _finding_identity(first)
        & _finding_identity(second)
    ) or bool(
        _finding_ips(first)
        & _finding_ips(second)
    )


def _stages_are_attack_related(
    first_stage: str,
    second_stage: str,
) -> bool:
    """
    Determine whether two stages can reasonably belong
    to the same intrusion storyline.

    This allows the chain to cross evidence boundaries
    even when the later finding does not repeat the
    attacker's IP or username.
    """

    if first_stage == second_stage:
        return True

    relationships = {
        (
            "RECONNAISSANCE",
            "INITIAL_ACCESS",
        ),
        (
            "INITIAL_ACCESS",
            "RECONNAISSANCE",
        ),
        (
            "INITIAL_ACCESS",
            "PRIVILEGE_ESCALATION",
        ),
        (
            "PRIVILEGE_ESCALATION",
            "INITIAL_ACCESS",
        ),
        (
            "PRIVILEGE_ESCALATION",
            "CREDENTIAL_ACCESS",
        ),
        (
            "CREDENTIAL_ACCESS",
            "PRIVILEGE_ESCALATION",
        ),
        (
            "PRIVILEGE_ESCALATION",
            "EXECUTION",
        ),
        (
            "EXECUTION",
            "PRIVILEGE_ESCALATION",
        ),
        (
            "CREDENTIAL_ACCESS",
            "EXECUTION",
        ),
        (
            "EXECUTION",
            "CREDENTIAL_ACCESS",
        ),
        (
            "EXECUTION",
            "PERSISTENCE",
        ),
        (
            "PERSISTENCE",
            "EXECUTION",
        ),
        (
            "PERSISTENCE",
            "COMMAND_AND_CONTROL",
        ),
        (
            "COMMAND_AND_CONTROL",
            "PERSISTENCE",
        ),
        (
            "EXECUTION",
            "COMMAND_AND_CONTROL",
        ),
        (
            "COMMAND_AND_CONTROL",
            "EXECUTION",
        ),
        (
            "INITIAL_ACCESS",
            "CREDENTIAL_ACCESS",
        ),
        (
            "CREDENTIAL_ACCESS",
            "PERSISTENCE",
        ),
        (
            "INITIAL_ACCESS",
            "EXECUTION",
        ),
    }

    return (
        first_stage,
        second_stage,
    ) in relationships


def _findings_are_temporally_close(
    first: dict[str, Any],
    second: dict[str, Any],
    correlation_window_seconds: int,
) -> bool:
    first_time = _parse_timestamp(
        _timestamp(first)
    )

    second_time = _parse_timestamp(
        _timestamp(second)
    )

    if first_time is None or second_time is None:
        return True

    delta = abs(
        (
            first_time
            - second_time
        ).total_seconds()
    )

    return (
        delta
        <= correlation_window_seconds
    )


def _findings_related(
    first: dict[str, Any],
    second: dict[str, Any],
    correlation_window_seconds: int,
) -> bool:
    """
    Explainable relationship test.

    Strong correlation:
        shared username
        shared IP

    Campaign correlation:
        temporally close + logically adjacent
        attack stages
    """

    if not _findings_are_temporally_close(
        first,
        second,
        correlation_window_seconds,
    ):
        return False

    if _share_identity_or_ip(
        first,
        second,
    ):
        return True

    first_stage = _stage_for_finding(
        first
    )

    second_stage = _stage_for_finding(
        second
    )

    return _stages_are_attack_related(
        first_stage,
        second_stage,
    )


# ============================================================
# GROUPING
# ============================================================

def _related_findings(
    findings: list[dict[str, Any]],
    *,
    correlation_window_seconds: int,
) -> list[list[dict[str, Any]]]:
    """
    Build connected investigation campaigns.

    Unlike the original implementation, this does not require
    every finding to carry the same IP/user.

    A campaign can therefore progress:

        Recon
          ↓
        SSH brute force
          ↓
        successful login
          ↓
        sudo
          ↓
        suspicious command
          ↓
        persistence

    while still requiring temporal and semantic relationships.
    """

    if not findings:
        return []

    sorted_findings = sorted(
        findings,
        key=_timestamp_sort_key,
    )

    groups: list[list[dict[str, Any]]] = []

    for finding in sorted_findings:
        placed = False

        for group in groups:
            if not group:
                continue

            # Compare against the most recent findings first.
            candidates = sorted(
                group,
                key=_timestamp_sort_key,
                reverse=True,
            )

            for existing in candidates[:5]:
                if _findings_related(
                    existing,
                    finding,
                    correlation_window_seconds,
                ):
                    group.append(
                        finding
                    )
                    placed = True
                    break

            if placed:
                break

        if not placed:
            groups.append(
                [finding]
            )

    return groups


def _merge_overlapping_groups(
    groups: list[list[dict[str, Any]]],
) -> list[list[dict[str, Any]]]:
    """
    Merge connected groups.

    A ↔ B
    B ↔ C

    becomes:

    A ↔ B ↔ C
    """

    changed = True

    while changed:
        changed = False

        for index in range(
            len(groups)
        ):
            if index >= len(groups):
                break

            current = groups[index]

            current_ids = {
                finding.get(
                    "finding_id"
                )
                for finding in current
            }

            for other_index in range(
                index + 1,
                len(groups),
            ):
                if other_index >= len(groups):
                    break

                other = groups[
                    other_index
                ]

                other_ids = {
                    finding.get(
                        "finding_id"
                    )
                    for finding in other
                }

                if current_ids & other_ids:
                    current.extend(
                        other
                    )

                    del groups[
                        other_index
                    ]

                    changed = True
                    break

            if changed:
                break

    # Remove accidental duplicates while preserving order.
    cleaned: list[list[dict[str, Any]]] = []

    for group in groups:
        seen: set[str] = set()
        clean_group: list[dict[str, Any]] = []

        for finding in group:
            finding_id = str(
                finding.get(
                    "finding_id",
                    id(finding),
                )
            )

            if finding_id in seen:
                continue

            seen.add(
                finding_id
            )

            clean_group.append(
                finding
            )

        if clean_group:
            cleaned.append(
                clean_group
            )

    return cleaned


# ============================================================
# CORRELATION SIGNALS
# ============================================================

def _cross_evidence_signals(
    group: list[dict[str, Any]],
    event_lookup: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    sources: set[str] = set()
    usernames: set[str] = set()
    source_ips: set[str] = set()

    for finding in group:
        sources.update(
            _finding_sources(
                finding,
                event_lookup,
            )
        )

        usernames.update(
            _finding_identity(
                finding
            )
        )

        source_ips.update(
            _finding_ips(
                finding
            )
        )

    if len(sources) >= 2:
        signals.append(
            {
                "type": "CROSS_EVIDENCE",
                "reason": (
                    "The attack sequence is represented "
                    "across multiple forensic evidence sources."
                ),
                "sources": sorted(
                    sources
                ),
                "confidence": 90,
            }
        )

    if usernames:
        signals.append(
            {
                "type": "IDENTITY_CORRELATION",
                "reason": (
                    "Multiple findings are associated "
                    "with the same user identity."
                ),
                "users": sorted(
                    usernames
                ),
                "confidence": 90,
            }
        )

    if source_ips:
        signals.append(
            {
                "type": "SOURCE_CORRELATION",
                "reason": (
                    "Multiple findings contain a shared "
                    "network source indicator."
                ),
                "source_ips": sorted(
                    source_ips
                ),
                "confidence": 95,
            }
        )

    stages = [
        _stage_for_finding(
            finding
        )
        for finding in group
    ]

    unique_stages = list(
        dict.fromkeys(
            stages
        )
    )

    if len(unique_stages) >= 3:
        signals.append(
            {
                "type": "ATTACK_SEQUENCE",
                "reason": (
                    "Findings form a multi-stage intrusion "
                    "sequence rather than isolated alerts."
                ),
                "stages": unique_stages,
                "confidence": 90,
            }
        )

    timestamps = [
        _parse_timestamp(
            _timestamp(finding)
        )
        for finding in group
    ]

    timestamps = [
        timestamp
        for timestamp in timestamps
        if timestamp is not None
    ]

    if len(timestamps) >= 2:
        start = min(
            timestamps
        )

        end = max(
            timestamps
        )

        duration = (
            end - start
        ).total_seconds()

        signals.append(
            {
                "type": "TEMPORAL_CORRELATION",
                "reason": (
                    "Related findings occurred within "
                    "the configured investigation window."
                ),
                "duration_seconds": duration,
                "confidence": 80,
            }
        )

    return signals


# ============================================================
# CHAIN DESCRIPTION
# ============================================================

def _chain_summary(
    group: list[dict[str, Any]],
    usernames: list[str],
    source_ips: list[str],
    signals: list[dict[str, Any]],
) -> str:
    stages = [
        _stage_for_finding(
            finding
        )
        for finding in group
    ]

    unique_stages = list(
        dict.fromkeys(
            stages
        )
    )

    stage_text = " → ".join(
        STAGE_LABELS.get(
            stage,
            stage.replace(
                "_",
                " ",
            ).title(),
        )
        for stage in unique_stages
    )

    identity = (
        ", ".join(usernames)
        if usernames
        else "unidentified account(s)"
    )

    source = (
        ", ".join(source_ips)
        if source_ips
        else "unidentified source(s)"
    )

    signal_text = ""

    if signals:
        signal_text = (
            f" {len(signals)} correlation signal(s) "
            "support the reconstructed sequence."
        )

    return (
        f"Reconstructed attack sequence: "
        f"{stage_text}. "
        f"The activity involved {identity} "
        f"and {source}. "
        f"{len(group)} finding(s) were correlated."
        f"{signal_text}"
    )


# ============================================================
# CONFIDENCE
# ============================================================

def _calculate_chain_confidence(
    group: list[dict[str, Any]],
    evidence_sources: set[str],
    signals: list[dict[str, Any]],
) -> int:
    stages = [
        _stage_for_finding(
            finding
        )
        for finding in group
    ]

    unique_stages = list(
        dict.fromkeys(
            stages
        )
    )

    score = 40

    # Multiple findings.
    score += min(
        20,
        len(group) * 3,
    )

    # Multi-stage attack.
    score += min(
        20,
        len(unique_stages) * 4,
    )

    # Cross-evidence.
    if len(evidence_sources) >= 2:
        score += 10

    # Strong identity/IP correlation.
    if any(
        signal.get("type")
        == "IDENTITY_CORRELATION"
        for signal in signals
    ):
        score += 5

    if any(
        signal.get("type")
        == "SOURCE_CORRELATION"
        for signal in signals
    ):
        score += 5

    # Explicit attack sequence.
    if any(
        signal.get("type")
        == "ATTACK_SEQUENCE"
        for signal in signals
    ):
        score += 5

    # High-value intrusion progression.
    if (
        "INITIAL_ACCESS" in stages
        and "PRIVILEGE_ESCALATION" in stages
    ):
        score += 5

    if (
        "PRIVILEGE_ESCALATION" in stages
        and "PERSISTENCE" in stages
    ):
        score += 5

    if (
        "INITIAL_ACCESS" in stages
        and "PERSISTENCE" in stages
    ):
        score += 5

    return min(
        100,
        score,
    )


# ============================================================
# PUBLIC CORRELATION ENGINE
# ============================================================

def correlate_findings(
    findings: list[Any],
    events: Optional[list[Any]] = None,
    *,
    correlation_window_seconds: int = (
        DEFAULT_CORRELATION_WINDOW_SECONDS
    ),
) -> list[AttackChain]:
    """
    Correlate independent findings into explainable attack chains.

    Correlation uses:

    1. Shared usernames.
    2. Shared source/network indicators.
    3. Temporal proximity.
    4. Evidence-source relationships.
    5. MITRE/detection stage semantics.
    6. Logical attack-stage progression.

    The result is designed for DFIR/SOC investigation rather
    than simple alert deduplication.
    """

    normalized = [
        _finding_dict(
            finding
        )
        for finding in findings
    ]

    if not normalized:
        return []

    event_lookup: dict[
        str,
        dict[str, Any],
    ] = {}

    if events:
        for event in events:
            data = _event_dict(
                event
            )

            event_id = data.get(
                "event_id"
            )

            if event_id:
                event_lookup[
                    str(event_id)
                ] = data

    normalized.sort(
        key=_timestamp_sort_key
    )

    groups = _related_findings(
        normalized,
        correlation_window_seconds=(
            correlation_window_seconds
        ),
    )

    groups = _merge_overlapping_groups(
        groups
    )

    # ========================================================
    # BUILD CHAINS
    # ========================================================

    chains: list[AttackChain] = []

    chain_number = 1

    for group in groups:
        if not group:
            continue

        group.sort(
            key=_timestamp_sort_key
        )

        steps: list[AttackChainStep] = []

        all_finding_ids: list[str] = []
        all_event_ids: list[str] = []

        source_ips: set[str] = set()
        usernames: set[str] = set()
        evidence_sources: set[str] = set()

        # ----------------------------------------------------
        # Build chronological attack steps
        # ----------------------------------------------------

        for index, finding in enumerate(
            group,
            start=1,
        ):
            finding_id = str(
                finding.get(
                    "finding_id",
                    f"FINDING-{index:04d}",
                )
            )

            event_ids = _finding_event_ids(
                finding
            )

            finding_ips = _finding_ips(
                finding
            )

            finding_users = _finding_identity(
                finding
            )

            finding_sources = _finding_sources(
                finding,
                event_lookup,
            )

            source_ips.update(
                finding_ips
            )

            usernames.update(
                finding_users
            )

            evidence_sources.update(
                finding_sources
            )

            stage = _stage_for_finding(
                finding
            )

            title = (
                finding.get(
                    "title"
                )
                or finding.get(
                    "name"
                )
                or STAGE_LABELS.get(
                    stage,
                    stage.replace(
                        "_",
                        " ",
                    ).title(),
                )
            )

            description = (
                finding.get(
                    "description"
                )
                or finding.get(
                    "message"
                )
                or (
                    f"{STAGE_LABELS.get(stage, stage)} "
                    "activity was detected during the investigation."
                )
            )

            indicators = finding.get(
                "indicators",
                [],
            )

            if not isinstance(
                indicators,
                list,
            ):
                indicators = [
                    str(indicators)
                ]

            # ------------------------------------------------
            # Step-level correlation metadata
            # ------------------------------------------------

            step_metadata = {
                "category": finding.get(
                    "category"
                ),
                "event_type": finding.get(
                    "event_type"
                ),
                "source": finding.get(
                    "source"
                ),
                "evidence_sources": sorted(
                    finding_sources
                ),
                "usernames": sorted(
                    finding_users
                ),
                "source_ips": sorted(
                    finding_ips
                ),
            }

            step = AttackChainStep(
                step_id=(
                    f"CHAIN-{chain_number:04d}-"
                    f"STEP-{index:02d}"
                ),
                stage=stage,
                title=str(
                    title
                ),
                description=str(
                    description
                ),
                timestamp=_timestamp(
                    finding
                ),
                severity=str(
                    finding.get(
                        "severity",
                        "INFO",
                    )
                ).upper(),
                event_ids=list(
                    event_ids
                ),
                finding_ids=[
                    finding_id
                ],
                indicators=indicators,
                metadata=step_metadata,
            )

            steps.append(
                step
            )

            all_finding_ids.append(
                finding_id
            )

            all_event_ids.extend(
                event_ids
            )

        unique_event_ids = list(
            dict.fromkeys(
                all_event_ids
            )
        )

        unique_finding_ids = list(
            dict.fromkeys(
                all_finding_ids
            )
        )

        stages = [
            step.stage
            for step in steps
        ]

        unique_stages = list(
            dict.fromkeys(
                stages
            )
        )

        signals = _cross_evidence_signals(
            group,
            event_lookup,
        )

        confidence = _calculate_chain_confidence(
            group,
            evidence_sources,
            signals,
        )

        severity = _highest_severity(
            group
        )

        timestamps = [
            step.timestamp
            for step in steps
            if step.timestamp
        ]

        start_time = (
            min(
                timestamps,
                key=lambda value: (
                    _parse_timestamp(value)
                    or datetime.min
                ),
            )
            if timestamps
            else None
        )

        end_time = (
            max(
                timestamps,
                key=lambda value: (
                    _parse_timestamp(value)
                    or datetime.min
                ),
            )
            if timestamps
            else None
        )

        # ----------------------------------------------------
        # Determine chain title
        # ----------------------------------------------------

        if (
            "INITIAL_ACCESS" in stages
            and "PERSISTENCE" in stages
        ):
            chain_title = (
                "Linux Intrusion — "
                "Initial Access to Persistence"
            )

        elif (
            "INITIAL_ACCESS" in stages
            and "PRIVILEGE_ESCALATION" in stages
        ):
            chain_title = (
                "Linux Intrusion — "
                "Access to Privilege Escalation"
            )

        elif len(unique_stages) >= 3:
            chain_title = (
                "Multi-Stage Linux Attack Chain"
            )

        elif len(evidence_sources) >= 2:
            chain_title = (
                "Cross-Evidence Linux Attack Chain"
            )

        else:
            chain_title = (
                "Correlated Linux Attack Chain"
            )

        # ----------------------------------------------------
        # Chain metadata
        # ----------------------------------------------------

        chain_metadata = {
            "stages": unique_stages,
            "stage_count": len(
                unique_stages
            ),
            "finding_count": len(
                unique_finding_ids
            ),
            "event_count": len(
                unique_event_ids
            ),
            "evidence_sources": sorted(
                evidence_sources
            ),
            "cross_evidence": (
                len(evidence_sources) >= 2
            ),
            "correlation_window_seconds": (
                correlation_window_seconds
            ),
            "correlation_signals": signals,
            "attack_sequence": [
                {
                    "order": index,
                    "stage": step.stage,
                    "title": step.title,
                    "finding_ids": step.finding_ids,
                    "event_ids": step.event_ids,
                }
                for index, step in enumerate(
                    steps,
                    start=1,
                )
            ],
        }

        chain = AttackChain(
            chain_id=(
                f"CHAIN-{chain_number:04d}"
            ),
            title=chain_title,
            summary=_chain_summary(
                group,
                sorted(
                    usernames
                ),
                sorted(
                    source_ips
                ),
                signals,
            ),
            severity=severity,
            confidence=confidence,
            start_time=start_time,
            end_time=end_time,
            source_ips=sorted(
                source_ips
            ),
            usernames=sorted(
                usernames
            ),
            steps=steps,
            finding_ids=unique_finding_ids,
            event_ids=unique_event_ids,
            metadata=chain_metadata,
        )

        chains.append(
            chain
        )

        chain_number += 1

    # ========================================================
    # FINAL ORDER
    # ========================================================

    chains.sort(
        key=lambda chain: (
            _parse_timestamp(
                chain.start_time
            )
            or datetime.min
        )
    )

    return chains
