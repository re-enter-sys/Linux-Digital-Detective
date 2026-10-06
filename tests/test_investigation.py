from datetime import datetime

from src.investigation.attack_story import (
    build_attack_story,
)

from src.investigation.correlation import (
    correlate_findings,
)

from src.investigation.mitre import (
    map_findings_to_mitre,
)

from src.investigation.scoring import (
    calculate_risk_score,
)

from src.timeline.events import Event


def finding(
    finding_id,
    event_type,
    severity,
    category=None,
    event_id=None,
    username="admin",
    source_ip="192.0.2.50",
):
    data = {
        "finding_id": finding_id,
        "event_type": event_type,
        "severity": severity,
        "username": username,
        "source_ip": source_ip,
        "timestamp": "2026-10-06T22:15:00",
        "title": event_type,
        "description": (
            "Test investigation finding."
        ),
    }

    if category:
        data["category"] = category

    if event_id:
        data["event_id"] = event_id

    return data


def test_correlation_creates_attack_chain():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "HIGH",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            "CRITICAL",
        ),
        finding(
            "F-003",
            "PERSISTENCE_DETECTED",
            "HIGH",
            category="CRON",
        ),
    ]

    chains = correlate_findings(
        findings
    )

    assert len(chains) == 1
    assert len(chains[0].steps) == 3


def test_attack_chain_contains_finding_ids():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "HIGH",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            "CRITICAL",
        ),
    ]

    chains = correlate_findings(
        findings
    )

    assert chains[0].finding_ids == [
        "F-001",
        "F-002",
    ]


def test_attack_chain_severity():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "HIGH",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            "CRITICAL",
        ),
    ]

    chains = correlate_findings(
        findings
    )

    assert chains[0].severity == "CRITICAL"


def test_attack_chain_confidence():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "HIGH",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            "CRITICAL",
        ),
        finding(
            "F-003",
            "PERSISTENCE_DETECTED",
            "HIGH",
            category="CRON",
        ),
    ]

    chains = correlate_findings(
        findings
    )

    assert chains[0].confidence > 0


def test_empty_correlation():
    assert correlate_findings([]) == []


def test_risk_score():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "HIGH",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            "CRITICAL",
        ),
    ]

    risk = calculate_risk_score(
        findings
    )

    assert risk.score > 0
    assert risk.severity in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }


def test_risk_score_is_capped():
    findings = [
        finding(
            f"F-{index:03d}",
            "SSH_BRUTE_FORCE",
            "CRITICAL",
        )
        for index in range(100)
    ]

    risk = calculate_risk_score(
        findings
    )

    assert risk.score == 100


def test_risk_serialization():
    risk = calculate_risk_score(
        [
            finding(
                "F-001",
                "SSH_BRUTE_FORCE",
                "HIGH",
            )
        ]
    )

    data = risk.to_dict()

    assert "score" in data
    assert "severity" in data
    assert "confidence" in data
    assert "factors" in data


def test_mitre_mapping_brute_force():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "HIGH",
        )
    ]

    techniques = map_findings_to_mitre(
        findings
    )

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1110.001"


def test_mitre_mapping_port_scan():
    findings = [
        finding(
            "F-001",
            "NETWORK_ACTIVITY",
            "HIGH",
            category="PORT_SCAN",
        )
    ]

    techniques = map_findings_to_mitre(
        findings
    )

    assert techniques[0].technique_id == "T1046"


def test_mitre_mapping_persistence():
    findings = [
        finding(
            "F-001",
            "PERSISTENCE_DETECTED",
            "HIGH",
            category="CRON",
        )
    ]

    techniques = map_findings_to_mitre(
        findings
    )

    assert techniques[0].technique_id == "T1053.003"


def test_mitre_serialization():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "HIGH",
        )
    ]

    techniques = map_findings_to_mitre(
        findings
    )

    data = techniques[0].to_dict()

    assert data["technique_id"] == "T1110.001"
    assert "name" in data
    assert "tactic" in data


def test_attack_story():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "HIGH",
        ),
        finding(
            "F-002",
            "SSH_BRUTE_FORCE_SUCCESS",
            "CRITICAL",
        ),
    ]

    chains = correlate_findings(
        findings
    )

    risk = calculate_risk_score(
        findings,
        chains,
    )

    mitre = map_findings_to_mitre(
        findings
    )

    story = build_attack_story(
        findings,
        chains,
        risk,
        mitre,
    )

    assert story["finding_count"] == 2
    assert story["chain_count"] == 1
    assert story["narrative"]


def test_attack_story_conclusion():
    findings = [
        finding(
            "F-001",
            "SSH_BRUTE_FORCE",
            "CRITICAL",
        )
    ]

    chains = correlate_findings(
        findings
    )

    risk = calculate_risk_score(
        findings,
        chains,
    )

    mitre = map_findings_to_mitre(
        findings
    )

    story = build_attack_story(
        findings,
        chains,
        risk,
        mitre,
    )

    assert "risk" in story["conclusion"].lower()
