import json

from src.reporting.csv_report import (
    write_findings_csv,
)

from src.reporting.html_report import (
    generate_html_report,
)

from src.reporting.json_report import (
    write_json_report,
)

from src.reporting.summary import (
    generate_summary,
)


def sample_investigation():
    return {
        "events": [],
        "findings": [
            {
                "finding_id": "F-001",
                "event_type": "SSH_BRUTE_FORCE",
                "title": "SSH Brute Force",
                "severity": "HIGH",
                "category": "SSH",
                "description": "Test finding",
                "username": "admin",
                "source_ip": "192.0.2.50",
            }
        ],
        "attack_chains": [
            {
                "chain_id": "CHAIN-0001",
                "summary": "Test attack chain",
                "severity": "HIGH",
                "confidence": 80,
                "steps": [],
            }
        ],
        "risk_score": {
            "score": 70,
            "severity": "HIGH",
            "confidence": 80,
            "factors": [],
        },
        "mitre": [
            {
                "technique_id": "T1110.001",
                "name": "Password Guessing",
                "tactic": "Credential Access",
                "description": "Test",
            }
        ],
        "attack_story": {
            "title": "Test",
            "narrative": [
                "SSH attack detected."
            ],
            "conclusion": (
                "Risk is HIGH."
            ),
        },
    }


def test_json_report(tmp_path):
    investigation = sample_investigation()

    output = (
        tmp_path
        / "report.json"
    )

    write_json_report(
        investigation,
        str(output),
    )

    assert output.exists()

    data = json.loads(
        output.read_text(
            encoding="utf-8"
        )
    )

    assert data["risk_score"]["score"] == 70


def test_html_report():
    investigation = sample_investigation()

    html = generate_html_report(
        investigation
    )

    assert "<html" in html
    assert "Linux Digital Detective" in html
    assert "T1110.001" in html
    assert "SSH Brute Force" in html


def test_csv_report(tmp_path):
    investigation = sample_investigation()

    output = (
        tmp_path
        / "findings.csv"
    )

    write_findings_csv(
        investigation["findings"],
        str(output),
    )

    assert output.exists()

    content = output.read_text(
        encoding="utf-8"
    )

    assert "finding_id" in content
    assert "F-001" in content


def test_summary():
    investigation = sample_investigation()

    summary = generate_summary(
        investigation
    )

    assert summary["risk_score"] == 70
    assert summary["finding_count"] == 1
    assert summary["attack_chain_count"] == 1
    assert summary["mitre_technique_count"] == 1
