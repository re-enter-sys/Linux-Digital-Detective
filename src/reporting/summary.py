from typing import Any


def generate_summary(
    investigation: dict[str, Any],
) -> dict[str, Any]:
    risk = investigation.get(
        "risk_score",
        {},
    )

    findings = investigation.get(
        "findings",
        [],
    )

    chains = investigation.get(
        "attack_chains",
        [],
    )

    mitre = investigation.get(
        "mitre",
        [],
    )

    severity_counts: dict[str, int] = {}

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "INFO",
            )
        ).upper()

        severity_counts[severity] = (
            severity_counts.get(
                severity,
                0,
            )
            + 1
        )

    return {
        "risk_score": risk.get(
            "score",
            0,
        ),
        "risk_severity": risk.get(
            "severity",
            "INFO",
        ),
        "confidence": risk.get(
            "confidence",
            0,
        ),
        "finding_count": len(findings),
        "attack_chain_count": len(chains),
        "mitre_technique_count": len(mitre),
        "severity_counts": severity_counts,
    }
