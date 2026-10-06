from dataclasses import dataclass
from typing import Any


SEVERITY_POINTS = {
    "INFO": 0,
    "LOW": 10,
    "MEDIUM": 20,
    "HIGH": 30,
    "CRITICAL": 40,
}


@dataclass
class RiskScore:
    score: int
    severity: str
    confidence: int
    factors: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "confidence": self.confidence,
            "factors": self.factors,
        }


def calculate_risk_score(
    findings: list[Any],
    attack_chains: list[Any] | None = None,
) -> RiskScore:
    factors: list[dict[str, Any]] = []

    score = 0

    for finding in findings:
        if isinstance(finding, dict):
            data = finding
        else:
            data = finding.to_dict()

        severity = str(
            data.get(
                "severity",
                "INFO",
            )
        ).upper()

        points = SEVERITY_POINTS.get(
            severity,
            0,
        )

        score += points

        factors.append(
            {
                "type": "finding",
                "finding_id": data.get(
                    "finding_id"
                ),
                "severity": severity,
                "points": points,
            }
        )

    chains = attack_chains or []

    for chain in chains:
        data = (
            chain
            if isinstance(chain, dict)
            else chain.to_dict()
        )

        steps = data.get(
            "steps",
            [],
        )

        if len(steps) >= 3:
            score += 15

            factors.append(
                {
                    "type": "attack_chain",
                    "chain_id": data.get(
                        "chain_id"
                    ),
                    "reason": (
                        "multi-stage attack chain"
                    ),
                    "points": 15,
                }
            )

        if (
            "PERSISTENCE"
            in data.get(
                "metadata",
                {},
            ).get(
                "stages",
                [],
            )
        ):
            score += 10

            factors.append(
                {
                    "type": "persistence",
                    "chain_id": data.get(
                        "chain_id"
                    ),
                    "points": 10,
                }
            )

    score = min(
        100,
        score,
    )

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    confidence = min(
        100,
        50
        + len(findings) * 5
        + len(chains) * 10,
    )

    return RiskScore(
        score=score,
        severity=severity,
        confidence=confidence,
        factors=factors,
    )
