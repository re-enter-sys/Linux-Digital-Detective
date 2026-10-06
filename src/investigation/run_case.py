import json
from pathlib import Path
from typing import Any

from src.detection.brute_force import (
    detect_ssh_brute_force,
    detect_successful_login_after_brute_force,
)
from src.detection.network_activity import (
    detect_network_activity,
)
from src.detection.persistence import (
    detect_persistence,
)
from src.detection.privilege_escalation import (
    detect_privilege_escalation,
)
from src.detection.suspicious_commands import (
    detect_suspicious_commands,
)

from src.investigation.evidence_pipeline import (
    EvidenceParseResult,
    parse_case_evidence,
)
from src.investigation.pipeline import investigate

from src.reporting.csv_report import (
    write_findings_csv,
)
from src.reporting.html_report import (
    write_html_report,
)
from src.reporting.json_report import (
    write_json_report,
)


def run_detection_engines(
    events: list[Any],
) -> list[Any]:
    """
    Run all available LDD detection engines against
    the normalized event collection.
    """

    findings: list[Any] = []

    findings.extend(
        detect_ssh_brute_force(events)
    )

    findings.extend(
        detect_successful_login_after_brute_force(
            events
        )
    )

    findings.extend(
        detect_privilege_escalation(events)
    )

    findings.extend(
        detect_suspicious_commands(events)
    )

    findings.extend(
        detect_persistence(events)
    )

    findings.extend(
        detect_network_activity(events)
    )

    return findings


def run_investigation(
    case_id: str,
    events: list[Any],
    findings: list[Any],
) -> dict:
    """
    Run the investigation pipeline using an already
    normalized event and finding collection.

    This function is retained for compatibility with
    the existing LDD workflow.
    """

    case_dir = (
        Path("data")
        / "cases"
        / case_id
    )

    case_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    result = investigate(
        events=events,
        findings=findings,
    )

    write_json_report(
        result,
        str(
            case_dir
            / "investigation.json"
        ),
    )

    write_html_report(
        result,
        str(
            case_dir
            / "report.html"
        ),
    )

    write_findings_csv(
        result["findings"],
        str(
            case_dir
            / "findings.csv"
        ),
    )

    (
        case_dir / "findings.json"
    ).write_text(
        json.dumps(
            result,
            indent=4,
        ),
        encoding="utf-8",
    )

    (
        case_dir / "timeline.json"
    ).write_text(
        json.dumps(
            {
                "events": result[
                    "events"
                ]
            },
            indent=4,
        ),
        encoding="utf-8",
    )

    (
        case_dir / "mitre.json"
    ).write_text(
        json.dumps(
            result["mitre"],
            indent=4,
        ),
        encoding="utf-8",
    )

    return result


def run_case_investigation(
    case_id: str,
    evidence_paths: list[str],
    *,
    year: int | None = None,
) -> dict[str, Any]:
    """
    Full end-to-end investigation workflow.

    Pipeline:

        Evidence
            ↓
        Parser Router
            ↓
        Normalized Events
            ↓
        Detection Engines
            ↓
        Correlation
            ↓
        Risk Scoring
            ↓
        MITRE ATT&CK
            ↓
        Attack Story
            ↓
        Reports
    """

    parse_result: EvidenceParseResult = (
        parse_case_evidence(
            evidence_paths,
            year=year,
        )
    )

    events = parse_result.events

    findings = run_detection_engines(
        events
    )

    investigation = run_investigation(
        case_id=case_id,
        events=events,
        findings=findings,
    )

    investigation[
        "evidence_processing"
    ] = parse_result.to_dict()

    return investigation
