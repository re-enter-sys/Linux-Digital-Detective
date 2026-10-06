from src.investigation.correlation import (
    AttackChain,
    AttackChainStep,
    STAGE_LABELS,
    _highest_severity,
    _stage_for_finding,
    correlate_findings,
)


def finding(
    finding_id,
    event_type,
    severity="HIGH",
    category=None,
    timestamp="2026-10-06T22:15:00+00:00",
    username="admin",
    source_ip="192.0.2.50",
    title=None,
    description="Test investigation finding.",
    event_id=None,
):
    data = {
        "finding_id": finding_id,
        "event_type": event_type,
        "severity": severity,
        "username": username,
        "source_ip": source_ip,
        "timestamp": timestamp,
        "title": title or event_type,
        "description": description,
    }

    if category is not None:
        data["category"] = category

    if event_id is not None:
        data["event_id"] = event_id

    return data


def test_attack_chain_step_to_dict():
    step = AttackChainStep(
        step_id="STEP-01",
        stage="INITIAL_ACCESS",
        title="SSH Brute Force",
        description="Repeated SSH authentication failures.",
        timestamp="2026-10-06T22:15:00+00:00",
        severity="HIGH",
        event_ids=["E-001"],
        finding_ids=["F-001"],
        indicators=["192.0.2.50"],
    )

    data = step.to_dict()

    assert data["step_id"] == "STEP-01"
    assert data["stage"] == "INITIAL_ACCESS"
    assert data["finding_ids"] == ["F-001"]
    assert data["event_ids"] == ["E-001"]
    assert data["indicators"] == ["192.0.2.50"]


def test_attack_chain_to_dict_preserves_steps():
    step = AttackChainStep(
        step_id="STEP-01",
        stage="PERSISTENCE",
        title="Cron Persistence",
        description="Persistence detected.",
        timestamp="2026-10-06T22:20:00+00:00",
        severity="HIGH",
        finding_ids=["F-003"],
    )

    chain = AttackChain(
        chain_id="CHAIN-0001",
        title="Linux Intrusion",
        summary="Initial access to persistence.",
        severity="CRITICAL",
        confidence=90,
        start_time="2026-10-06T22:15:00+00:00",
        end_time="2026-10-06T22:20:00+00:00",
        source_ips=["192.0.2.50"],
        usernames=["admin"],
        steps=[step],
        finding_ids=["F-003"],
    )

    data = chain.to_dict()

    assert data["chain_id"] == "CHAIN-0001"
    assert data["severity"] == "CRITICAL"
    assert data["confidence"] == 90
    assert len(data["steps"]) == 1
    assert data["steps"][0]["stage"] == "PERSISTENCE"


def test_stage_classifier_detects_reconnaissance():
    finding_data = finding(
        "F-001",
        "NETWORK_RECON",
        title="Network Reconnaissance",
    )

    assert (
        _stage_for_finding(finding_data)
        == "RECONNAISSANCE"
    )


def test_stage_classifier_detects_initial_access():
    finding_data = finding(
        "F-001",
        "SSH_BRUTE_FORCE",
        title="SSH Brute Force",
    )

    assert (
        _stage_for_finding(finding_data)
        == "INITIAL_ACCESS"
    )


def test_stage_classifier_detects_successful_login():
    finding_data = finding(
        "F-002",
        "SSH_AUTH_SUCCESS",
        title="Successful SSH Login",
    )

    assert (
        _stage_for_finding(finding_data)
        == "INITIAL_ACCESS"
    )


def test_stage_classifier_detects_privilege_escalation():
    finding_data = finding(
        "F-003",
        "PRIVILEGE_ESCALATION",
        title="Privilege Escalation",
    )

    assert (
        _stage_for_finding(finding_data)
        == "PRIVILEGE_ESCALATION"
    )


def test_stage_classifier_detects_credential_access():
    finding_data = finding(
        "F-004",
        "CREDENTIAL_ACCESS",
        title="Credential Access",
    )

    assert (
        _stage_for_finding(finding_data)
        == "CREDENTIAL_ACCESS"
    )


def test_stage_classifier_detects_execution():
    finding_data = finding(
        "F-005",
        "SHELL_EXECUTION",
        title="Suspicious Shell Command",
    )

    assert (
        _stage_for_finding(finding_data)
        == "EXECUTION"
    )


def test_stage_classifier_detects_persistence():
    finding_data = finding(
        "F-006",
        "PERSISTENCE_DETECTED",
        category="CRON",
        title="Cron Persistence",
    )

    assert (
        _stage_for_finding(finding_data)
        == "PERSISTENCE"
    )


def test_highest_severity():
    findings = [
        finding("F-001", "NETWORK_RECON", "LOW"),
        finding("F-002", "SSH_BRUTE_FORCE", "HIGH"),
        finding("F-003", "PERSISTENCE_DETECTED", "CRITICAL"),
        finding("F-004", "SHELL_EXECUTION", "MEDIUM"),
    ]

    assert _highest_severity(findings) == "CRITICAL"


def test_highest_severity_empty_findings():
    assert _highest_severity([]) == "INFO"


def test_correlation_creates_multi_stage_attack_chain():
    findings = [
        finding(
            "F-001",
            "NETWORK_RECON",
            "MEDIUM",
            timestamp="2026-10-06T22:10:00+00:00",
            title="Network Reconnaissance",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE",
            "HIGH",
            timestamp="2026-10-06T22:12:00+00:00",
            title="SSH Brute Force",
        ),
        finding(
            "F-003",
            "SSH_BRUTE_FORCE_SUCCESS",
            "CRITICAL",
            timestamp="2026-10-06T22:13:00+00:00",
            title="Successful SSH Login",
        ),
        finding(
            "F-004",
            "PRIVILEGE_ESCALATION",
            "HIGH",
            timestamp="2026-10-06T22:14:00+00:00",
            title="Privilege Escalation",
        ),
        finding(
            "F-005",
            "SHELL_EXECUTION",
            "HIGH",
            timestamp="2026-10-06T22:16:00+00:00",
            title="Suspicious Shell Command",
        ),
        finding(
            "F-006",
            "PERSISTENCE_DETECTED",
            "CRITICAL",
            category="CRON",
            timestamp="2026-10-06T22:18:00+00:00",
            title="Cron Persistence",
        ),
    ]

    chains = correlate_findings(findings)

    assert chains
    assert len(chains[0].steps) >= 4

    stages = [
        step.stage
        for step in chains[0].steps
    ]

    assert "RECONNAISSANCE" in stages
    assert "INITIAL_ACCESS" in stages
    assert "PRIVILEGE_ESCALATION" in stages
    assert "PERSISTENCE" in stages


def test_correlation_preserves_finding_ids():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            timestamp="2026-10-06T22:15:00+00:00",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            timestamp="2026-10-06T22:16:00+00:00",
        ),
        finding(
            "F-003",
            "PERSISTENCE_DETECTED",
            category="CRON",
            timestamp="2026-10-06T22:18:00+00:00",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    finding_ids = set(chains[0].finding_ids)

    assert finding_ids == {
        "F-001",
        "F-002",
        "F-003",
    }


def test_correlation_records_identity_and_source_information():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            timestamp="2026-10-06T22:15:00+00:00",
            username="admin",
            source_ip="192.0.2.50",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            timestamp="2026-10-06T22:16:00+00:00",
            username="admin",
            source_ip="192.0.2.50",
        ),
    ]

    chains = correlate_findings(findings)

    assert chains

    chain = chains[0]

    assert "admin" in chain.usernames
    assert "192.0.2.50" in chain.source_ips


def test_correlation_metadata_contains_signals():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            timestamp="2026-10-06T22:15:00+00:00",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            timestamp="2026-10-06T22:16:00+00:00",
        ),
        finding(
            "F-003",
            "PERSISTENCE_DETECTED",
            category="CRON",
            timestamp="2026-10-06T22:18:00+00:00",
        ),
    ]

    chains = correlate_findings(findings)

    assert chains

    metadata = chains[0].metadata

    assert "correlation_signals" in metadata
    assert "stages" in metadata
    assert "finding_count" in metadata
    assert "attack_sequence" in metadata


def test_correlation_confidence_is_valid_percentage():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            timestamp="2026-10-06T22:15:00+00:00",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            timestamp="2026-10-06T22:16:00+00:00",
        ),
    ]

    chains = correlate_findings(findings)

    assert chains

    assert 0 <= chains[0].confidence <= 100


def test_stage_labels_are_available():
    assert STAGE_LABELS["RECONNAISSANCE"] == "Reconnaissance"
    assert STAGE_LABELS["INITIAL_ACCESS"] == "Initial Access"
    assert STAGE_LABELS["PERSISTENCE"] == "Persistence"
