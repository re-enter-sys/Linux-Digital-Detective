from typing import Any

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


def _normalize_findings(
    findings: list[Any],
) -> list[Any]:
    return findings


def investigate(
    events: list[Any],
    findings: list[Any],
) -> dict:
    """
    Build the complete investigation result from
    normalized events and detection findings.
    """

    normalized_findings = _normalize_findings(
        findings
    )

    chains = correlate_findings(
        normalized_findings,
        events,
    )

    risk_score = calculate_risk_score(
        normalized_findings,
        chains,
    )

    mitre = map_findings_to_mitre(
        normalized_findings
    )

    attack_story = build_attack_story(
        normalized_findings,
        chains,
        risk_score,
        mitre,
    )

    return {
        "events": [
            event.to_dict()
            if hasattr(event, "to_dict")
            else event
            for event in events
        ],
        "findings": [
            finding.to_dict()
            if hasattr(finding, "to_dict")
            else finding
            for finding in normalized_findings
        ],
        "attack_chains": [
            chain.to_dict()
            if hasattr(chain, "to_dict")
            else chain
            for chain in chains
        ],
        "risk_score": risk_score.to_dict(),
        "mitre": [
            technique.to_dict()
            if hasattr(technique, "to_dict")
            else technique
            for technique in mitre
        ],
        "attack_story": attack_story,
    }
