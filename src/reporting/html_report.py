from html import escape
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _severity_class(severity: str) -> str:
    return str(severity or "INFO").lower()


def _safe(value: Any, default: str = "") -> str:
    if value is None:
        value = default

    return escape(str(value))


def _format_timestamp(timestamp: Any) -> str:
    if not timestamp:
        return "-"

    value = str(timestamp)

    if "T" in value:
        value = value.replace("T", " ", 1)

    if "+" in value:
        value = value.split("+", 1)[0]

    return value


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
        key=lambda severity: SEVERITY_ORDER.get(
            severity,
            0,
        ),
    )


def _build_attack_path(
    story: dict[str, Any],
) -> list[str]:
    path = story.get(
        "attack_path",
        [],
    )

    if isinstance(path, list):
        return [
            str(item)
            for item in path
            if item
        ]

    return []


def _render_attack_path(
    attack_path: list[str],
) -> str:
    if not attack_path:
        return """
        <div class="empty-state">
            No primary attack path was reconstructed.
        </div>
        """

    parts = []

    for index, stage in enumerate(attack_path):
        parts.append(
            f"""
            <div class="attack-stage">
                <span class="stage-number">
                    {index + 1}
                </span>
                <span class="stage-name">
                    {_safe(stage)}
                </span>
            </div>
            """
        )

        if index < len(attack_path) - 1:
            parts.append(
                '<div class="attack-arrow">→</div>'
            )

    return (
        '<div class="attack-path">'
        + "".join(parts)
        + "</div>"
    )


def _render_narrative(
    story: dict[str, Any],
) -> str:
    narrative = story.get(
        "narrative",
        [],
    )

    if not narrative:
        return """
        <div class="empty-state">
            No investigation narrative is available.
        </div>
        """

    return "".join(
        f"""
        <div class="story-item">
            <span class="story-number">
                {index}
            </span>
            <p>{_safe(item)}</p>
        </div>
        """
        for index, item in enumerate(
            narrative,
            start=1,
        )
    )


def _render_findings(
    findings: list[dict[str, Any]],
) -> str:
    if not findings:
        return """
        <tr>
            <td colspan="7" class="empty-cell">
                No findings detected.
            </td>
        </tr>
        """

    rows = []

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "INFO",
            )
        ).upper()

        rows.append(
            f"""
            <tr>
                <td class="mono">
                    {_safe(
                        finding.get(
                            "finding_id"
                        )
                    )}
                </td>

                <td>
                    <strong>
                        {_safe(
                            finding.get(
                                "title"
                            )
                        )}
                    </strong>

                    <div class="subtext">
                        {_safe(
                            finding.get(
                                "event_type"
                            )
                        )}
                    </div>
                </td>

                <td>
                    <span class="severity {_severity_class(severity)}">
                        {_safe(severity)}
                    </span>
                </td>

                <td>
                    {_safe(
                        finding.get(
                            "category",
                            "-"
                        )
                    )}
                </td>

                <td>
                    {_safe(
                        finding.get(
                            "username",
                            finding.get(
                                "user",
                                "-"
                            ),
                        )
                    )}
                </td>

                <td class="mono">
                    {_safe(
                        finding.get(
                            "source_ip",
                            "-"
                        )
                    )}
                </td>

                <td class="mono">
                    {_safe(
                        _format_timestamp(
                            finding.get(
                                "timestamp"
                            )
                        )
                    )}
                </td>
            </tr>

            <tr class="finding-detail">
                <td></td>

                <td colspan="6">
                    {_safe(
                        finding.get(
                            "description",
                            "No description available."
                        )
                    )}
                </td>
            </tr>
            """
        )

    return "".join(rows)


def _render_timeline(
    events: list[dict[str, Any]],
) -> str:
    if not events:
        return """
        <tr>
            <td colspan="7" class="empty-cell">
                No normalized events available.
            </td>
        </tr>
        """

    rows = []

    for event in events:
        severity = str(
            event.get(
                "severity",
                "INFO",
            )
        ).upper()

        rows.append(
            f"""
            <tr>
                <td class="sequence">
                    {_safe(
                        event.get(
                            "sequence",
                            "-"
                        )
                    )}
                </td>

                <td class="mono timestamp">
                    {_safe(
                        _format_timestamp(
                            event.get(
                                "timestamp"
                            )
                        )
                    )}
                </td>

                <td>
                    <strong>
                        {_safe(
                            event.get(
                                "event_type",
                                "-"
                            )
                        )}
                    </strong>

                    <div class="subtext">
                        {_safe(
                            event.get(
                                "source",
                                "-"
                            )
                        )}
                    </div>
                </td>

                <td>
                    {_safe(
                        event.get(
                            "user",
                            "-"
                        )
                    )}
                </td>

                <td class="mono">
                    {_safe(
                        event.get(
                            "source_ip",
                            "-"
                        )
                    )}
                </td>

                <td>
                    <span class="severity {_severity_class(severity)}">
                        {_safe(severity)}
                    </span>
                </td>

                <td class="gap">
                    {_safe(
                        event.get(
                            "gap_from_previous_seconds",
                            0
                        )
                    )}s
                </td>
            </tr>
            """
        )

    return "".join(rows)


def _render_chains(
    chains: list[dict[str, Any]],
) -> str:
    if not chains:
        return """
        <div class="empty-state">
            No correlated attack chains were generated.
        </div>
        """

    sections = []

    for chain in chains:
        severity = str(
            chain.get(
                "severity",
                "INFO",
            )
        ).upper()

        steps = chain.get(
            "steps",
            [],
        )

        step_html = ""

        if steps:
            step_html = "".join(
                f"""
                <div class="chain-step">
                    <div class="step-marker">
                        {index}
                    </div>

                    <div class="step-content">
                        <div class="step-header">

                            <strong>
                                {_safe(
                                    step.get(
                                        "title",
                                        step.get(
                                            "stage",
                                            "Investigation Step"
                                        )
                                    )
                                )}
                            </strong>

                            <span class="stage-badge">
                                {_safe(
                                    step.get(
                                        "stage",
                                        "UNKNOWN"
                                    )
                                )}
                            </span>

                        </div>

                        <div class="subtext">
                            {_safe(
                                _format_timestamp(
                                    step.get(
                                        "timestamp"
                                    )
                                )
                            )}
                        </div>

                        <p>
                            {_safe(
                                step.get(
                                    "description",
                                    ""
                                )
                            )}
                        </p>

                    </div>
                </div>
                """
                for index, step in enumerate(
                    steps,
                    start=1,
                )
            )

        sections.append(
            f"""
            <div class="chain-card">

                <div class="chain-header">

                    <div>

                        <div class="eyebrow">
                            {_safe(
                                chain.get(
                                    "chain_id",
                                    "CHAIN"
                                )
                            )}
                        </div>

                        <h3>
                            {_safe(
                                chain.get(
                                    "title",
                                    "Correlated Attack Chain"
                                )
                            )}
                        </h3>

                    </div>

                    <div class="chain-metrics">

                        <span class="severity {_severity_class(severity)}">
                            {_safe(severity)}
                        </span>

                        <span class="confidence">
                            {_safe(
                                chain.get(
                                    "confidence",
                                    0
                                )
                            )}% confidence
                        </span>

                    </div>

                </div>

                <p class="chain-summary">
                    {_safe(
                        chain.get(
                            "summary",
                            ""
                        )
                    )}
                </p>

                <div class="chain-steps">
                    {step_html}
                </div>

            </div>
            """
        )

    return "".join(sections)


def _render_mitre(
    mitre: list[dict[str, Any]],
) -> str:
    if not mitre:
        return """
        <tr>
            <td colspan="5" class="empty-cell">
                No MITRE ATT&CK techniques were mapped.
            </td>
        </tr>
        """

    rows = []

    for technique in mitre:
        finding_ids = technique.get(
            "finding_ids",
            [],
        )

        rows.append(
            f"""
            <tr>

                <td>
                    <span class="technique-id">
                        {_safe(
                            technique.get(
                                "technique_id",
                                "-"
                            )
                        )}
                    </span>
                </td>

                <td>
                    <strong>
                        {_safe(
                            technique.get(
                                "name",
                                "-"
                            )
                        )}
                    </strong>
                </td>

                <td>
                    {_safe(
                        technique.get(
                            "tactic",
                            "-"
                        )
                    )}
                </td>

                <td>
                    {_safe(
                        technique.get(
                            "description",
                            "-"
                        )
                    )}
                </td>

                <td class="mono">
                    {_safe(
                        ", ".join(
                            str(item)
                            for item in finding_ids
                        )
                        or "-"
                    )}
                </td>

            </tr>
            """
        )

    return "".join(rows)


def _render_context(
    story: dict[str, Any],
) -> str:
    users = story.get(
        "usernames",
        [],
    )

    source_ips = story.get(
        "source_ips",
        [],
    )

    return f"""
    <div class="context-grid">

        <div class="context-item">

            <span class="context-label">
                Observed User(s)
            </span>

            <strong>
                {_safe(
                    ", ".join(
                        str(user)
                        for user in users
                    )
                    or "Not identified"
                )}
            </strong>

        </div>

        <div class="context-item">

            <span class="context-label">
                Source Address(es)
            </span>

            <strong class="mono">
                {_safe(
                    ", ".join(
                        str(ip)
                        for ip in source_ips
                    )
                    or "Not identified"
                )}
            </strong>

        </div>

        <div class="context-item">

            <span class="context-label">
                Findings
            </span>

            <strong>
                {_safe(
                    story.get(
                        "finding_count",
                        0
                    )
                )}
            </strong>

        </div>

        <div class="context-item">

            <span class="context-label">
                Attack Chains
            </span>

            <strong>
                {_safe(
                    story.get(
                        "chain_count",
                        0
                    )
                )}
            </strong>

        </div>

    </div>
    """


def generate_html_report(
    investigation: dict[str, Any],
) -> str:
    """
    Generate a complete standalone forensic investigation report.

    The report contains no external CSS, JavaScript, fonts,
    or network dependencies and can therefore be archived
    and opened offline.
    """

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

    events = investigation.get(
        "events",
        [],
    )

    story = investigation.get(
        "attack_story",
        {},
    )

    attack_path = _build_attack_path(
        story
    )

    score = risk.get(
        "score",
        0,
    )

    severity = str(
        risk.get(
            "severity",
            _highest_severity(
                findings
            ),
        )
    ).upper()

    confidence = risk.get(
        "confidence",
        story.get(
            "confidence",
            0,
        ),
    )

    factors = risk.get(
        "factors",
        [],
    )

    factor_rows = ""

    for factor in factors:
        reference = factor.get(
            "finding_id",
            factor.get(
                "chain_id",
                "-"
            ),
        )

        reason = factor.get(
            "reason",
            factor.get(
                "severity",
                factor.get(
                    "type",
                    "-"
                ),
            ),
        )

        factor_rows += f"""
        <tr>

            <td>
                {_safe(
                    factor.get(
                        "type",
                        "-"
                    )
                )}
            </td>

            <td class="mono">
                {_safe(reference)}
            </td>

            <td>
                {_safe(reason)}
            </td>

            <td>
                +{_safe(
                    factor.get(
                        "points",
                        0
                    )
                )}
            </td>

        </tr>
        """

    if not factor_rows:
        factor_rows = """
        <tr>
            <td colspan="4" class="empty-cell">
                No risk factors recorded.
            </td>
        </tr>
        """

    conclusion = story.get(
        "conclusion",
        "No investigation conclusion available.",
    )

    return f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<meta
    name="generator"
    content="Linux Digital Detective"
>

<title>
    Linux Digital Detective — Investigation Report
</title>

<style>

:root {{
    --background: #0b0f14;
    --surface: #111820;
    --surface-alt: #17212b;
    --border: #293542;
    --text: #e7edf3;
    --muted: #91a0af;
    --critical: #ff5c5c;
    --high: #ff9f43;
    --medium: #f2c94c;
    --low: #5aa9ff;
    --info: #aab7c4;
    --accent: #62d8ff;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background:
        radial-gradient(
            circle at top right,
            #172531 0,
            var(--background) 42%
        );
    color: var(--text);
    font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    line-height: 1.55;
}}

.container {{
    width: min(
        1400px,
        calc(100% - 48px)
    );
    margin: 0 auto;
    padding: 42px 0 80px;
}}

header {{
    padding: 10px 0 30px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 28px;
}}

.brand {{
    display: flex;
    justify-content: space-between;
    gap: 30px;
    align-items: flex-start;
}}

.eyebrow {{
    color: var(--accent);
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 0.14em;
    text-transform: uppercase;
}}

h1 {{
    margin: 6px 0 4px;
    font-size: clamp(
        30px,
        5vw,
        52px
    );
    line-height: 1.05;
}}

h2 {{
    margin-top: 0;
    font-size: 23px;
}}

h3 {{
    margin: 4px 0;
}}

.subtitle {{
    color: var(--muted);
    margin: 0;
}}

.report-label {{
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 8px 13px;
    color: var(--muted);
    white-space: nowrap;
    font-size: 12px;
    font-weight: 700;
}}

.case-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 24px;
}}

.case-title {{
    font-size: 25px;
    font-weight: 800;
}}

.case-description {{
    color: var(--muted);
    max-width: 850px;
}}

.metrics {{
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(180px, 1fr)
        );
    gap: 14px;
    margin-bottom: 24px;
}}

.metric {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 19px;
}}

.metric-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 700;
}}

.metric-value {{
    margin-top: 7px;
    font-size: 30px;
    font-weight: 850;
}}

.metric-value.critical {{
    color: var(--critical);
}}

.metric-value.high {{
    color: var(--high);
}}

.metric-value.medium {{
    color: var(--medium);
}}

.metric-value.low {{
    color: var(--low);
}}

.metric-value.info {{
    color: var(--info);
}}

.section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 25px;
    margin-bottom: 24px;
}}

.section-header {{
    display: flex;
    justify-content: space-between;
    gap: 20px;
    align-items: center;
    margin-bottom: 20px;
}}

.section-header p {{
    color: var(--muted);
    margin: 4px 0 0;
}}

.attack-path {{
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    padding: 20px;
    border-radius: 13px;
    background: var(--surface-alt);
    border: 1px solid var(--border);
}}

.attack-stage {{
    display: flex;
    align-items: center;
    gap: 10px;
    border: 1px solid var(--border);
    background: #0e151d;
    border-radius: 10px;
    padding: 10px 13px;
    font-weight: 750;
}}

.stage-number {{
    width: 24px;
    height: 24px;
    display: grid;
    place-items: center;
    border-radius: 50%;
    background: var(--accent);
    color: #081016;
    font-size: 12px;
    font-weight: 900;
}}

.attack-arrow {{
    color: var(--accent);
    font-size: 22px;
    font-weight: 800;
}}

.story-item {{
    display: grid;
    grid-template-columns: 32px 1fr;
    gap: 13px;
    align-items: start;
    margin: 15px 0;
}}

.story-number {{
    width: 30px;
    height: 30px;
    display: grid;
    place-items: center;
    border: 1px solid var(--border);
    border-radius: 50%;
    color: var(--accent);
    font-weight: 800;
}}

.story-item p {{
    margin: 3px 0 0;
}}

.conclusion {{
    margin-top: 22px;
    padding: 18px;
    border-left: 4px solid var(--critical);
    background: var(--surface-alt);
    border-radius: 9px;
}}

.context-grid {{
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(200px, 1fr)
        );
    gap: 12px;
}}

.context-item {{
    padding: 16px;
    background: var(--surface-alt);
    border: 1px solid var(--border);
    border-radius: 11px;
}}

.context-label {{
    display: block;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 5px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th {{
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    background: var(--surface-alt);
}}

th,
td {{
    padding: 13px 12px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
}}

tr:last-child td {{
    border-bottom: 0;
}}

.mono {{
    font-family:
        "JetBrains Mono",
        "Cascadia Code",
        Consolas,
        monospace;
    font-size: 12px;
}}

.subtext {{
    color: var(--muted);
    font-size: 12px;
    margin-top: 2px;
}}

.severity {{
    font-weight: 850;
    font-size: 12px;
    letter-spacing: 0.04em;
}}

.critical {{
    color: var(--critical);
}}

.high {{
    color: var(--high);
}}

.medium {{
    color: var(--medium);
}}

.low {{
    color: var(--low);
}}

.info {{
    color: var(--info);
}}

.finding-detail td {{
    color: var(--muted);
    font-size: 13px;
    background: #0d141b;
}}

.sequence {{
    color: var(--accent);
    font-weight: 800;
}}

.timestamp {{
    white-space: nowrap;
}}

.gap {{
    color: var(--muted);
    white-space: nowrap;
}}

.chain-card {{
    background: var(--surface-alt);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 16px;
}}

.chain-card:last-child {{
    margin-bottom: 0;
}}

.chain-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 20px;
}}

.chain-metrics {{
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
}}

.confidence {{
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
}}

.chain-summary {{
    color: var(--muted);
}}

.chain-steps {{
    border-left: 2px solid var(--border);
    margin: 20px 0 0 12px;
}}

.chain-step {{
    position: relative;
    display: grid;
    grid-template-columns: 34px 1fr;
    gap: 13px;
    margin: 0 0 18px -18px;
}}

.step-marker {{
    width: 32px;
    height: 32px;
    display: grid;
    place-items: center;
    background: var(--surface);
    border: 1px solid var(--accent);
    color: var(--accent);
    border-radius: 50%;
    font-weight: 800;
}}

.step-content {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 13px 15px;
}}

.step-content p {{
    color: var(--muted);
    margin: 8px 0 0;
}}

.step-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
}}

.stage-badge {{
    color: var(--accent);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 4px 8px;
    font-size: 10px;
    font-weight: 800;
}}

.technique-id {{
    display: inline-block;
    padding: 5px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface-alt);
    font-family:
        "JetBrains Mono",
        Consolas,
        monospace;
    font-weight: 800;
}}

.empty-state,
.empty-cell {{
    color: var(--muted);
    text-align: center;
    padding: 25px;
}}

.footer {{
    color: var(--muted);
    text-align: center;
    padding: 25px 0 0;
    font-size: 12px;
}}

@media (max-width: 800px) {{

    .container {{
        width: min(
            100% - 24px,
            1400px
        );
        padding-top: 20px;
    }}

    .brand,
    .section-header,
    .chain-header {{
        flex-direction: column;
        align-items: flex-start;
    }}

    table {{
        display: block;
        overflow-x: auto;
    }}

    .attack-path {{
        align-items: flex-start;
    }}

}}

@media print {{

    body {{
        background: white;
        color: black;
    }}

    .container {{
        width: 100%;
        padding: 0;
    }}

    .section,
    .case-card,
    .metric {{
        break-inside: avoid;
        border-color: #ccc;
        background: white;
    }}

    .subtext,
    .subtitle,
    .chain-summary,
    .story-item p,
    .context-label {{
        color: #444;
    }}

}}

</style>

</head>

<body>

<div class="container">

<header>

    <div class="brand">

        <div>

            <div class="eyebrow">
                Linux Digital Detective
            </div>

            <h1>
                Investigation Report
            </h1>

            <p class="subtitle">
                Digital forensic investigation and attack reconstruction
            </p>

        </div>

        <div class="report-label">
            OFFLINE FORENSIC REPORT
        </div>

    </div>

</header>

<div class="case-card">

    <div class="eyebrow">
        Investigation Case
    </div>

    <div class="case-title">
        {_safe(
            investigation.get(
                "case_id",
                "CASE-0001"
            )
        )}
    </div>

    <p class="case-description">
        Evidence-derived investigation generated by
        Linux Digital Detective.
    </p>

    {_render_context(story)}

</div>

<div class="metrics">

    <div class="metric">

        <div class="metric-label">
            Risk Score
        </div>

        <div class="metric-value {_severity_class(severity)}">
            {_safe(score)}/100
        </div>

    </div>

    <div class="metric">

        <div class="metric-label">
            Risk Level
        </div>

        <div class="metric-value {_severity_class(severity)}">
            {_safe(severity)}
        </div>

    </div>

    <div class="metric">

        <div class="metric-label">
            Confidence
        </div>

        <div class="metric-value">
            {_safe(confidence)}%
        </div>

    </div>

    <div class="metric">

        <div class="metric-label">
            Normalized Events
        </div>

        <div class="metric-value">
            {len(events)}
        </div>

    </div>

    <div class="metric">

        <div class="metric-label">
            Findings
        </div>

        <div class="metric-value">
            {len(findings)}
        </div>

    </div>

    <div class="metric">

        <div class="metric-label">
            MITRE Techniques
        </div>

        <div class="metric-value">
            {len(mitre)}
        </div>

    </div>

</div>

<section class="section">

    <div class="section-header">

        <div>

            <h2>
                Attack Reconstruction
            </h2>

            <p>
                High-level sequence reconstructed from correlated detections.
            </p>

        </div>

    </div>

    {_render_attack_path(attack_path)}

</section>

<section class="section">

    <div class="section-header">

        <div>

            <h2>
                Investigator Assessment
            </h2>

            <p>
                Human-readable interpretation of the available evidence.
            </p>

        </div>

    </div>

    {_render_narrative(story)}

    <div class="conclusion">

        <strong>
            Assessment
        </strong>

        <p>
            {_safe(conclusion)}
        </p>

    </div>

</section>

<section class="section">

    <div class="section-header">

        <div>

            <h2>
                Evidence Timeline
            </h2>

            <p>
                Chronologically normalized forensic events.
            </p>

        </div>

    </div>

    <table>

        <thead>

            <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Event</th>
                <th>User</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Gap</th>
            </tr>

        </thead>

        <tbody>
            {_render_timeline(events)}
        </tbody>

    </table>

</section>

<section class="section">

    <div class="section-header">

        <div>

            <h2>
                Detection Findings
            </h2>

            <p>
                Security detections generated by the investigation engines.
            </p>

        </div>

    </div>

    <table>

        <thead>

            <tr>
                <th>ID</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>Category</th>
                <th>User</th>
                <th>Source</th>
                <th>Timestamp</th>
            </tr>

        </thead>

        <tbody>
            {_render_findings(findings)}
        </tbody>

    </table>

</section>

<section class="section">

    <div class="section-header">

        <div>

            <h2>
                Correlated Attack Chains
            </h2>

            <p>
                Related findings grouped into explainable investigation chains.
            </p>

        </div>

    </div>

    {_render_chains(chains)}

</section>

<section class="section">

    <div class="section-header">

        <div>

            <h2>
                MITRE ATT&CK Mapping
            </h2>

            <p>
                Investigation findings mapped to ATT&CK techniques.
            </p>

        </div>

    </div>

    <table>

        <thead>

            <tr>
                <th>Technique</th>
                <th>Name</th>
                <th>Tactic</th>
                <th>Description</th>
                <th>Finding IDs</th>
            </tr>

        </thead>

        <tbody>
            {_render_mitre(mitre)}
        </tbody>

    </table>

</section>

<section class="section">

    <div class="section-header">

        <div>

            <h2>
                Risk Calculation
            </h2>

            <p>
                Factors contributing to the final investigation score.
            </p>

        </div>

    </div>

    <table>

        <thead>

            <tr>
                <th>Type</th>
                <th>Reference</th>
                <th>Reason</th>
                <th>Points</th>
            </tr>

        </thead>

        <tbody>
            {factor_rows}
        </tbody>

    </table>

</section>

<footer class="footer">

    Linux Digital Detective —
    Turn scattered Linux evidence into an attack timeline.

</footer>

</div>

</body>

</html>
"""


def write_html_report(
    investigation: dict[str, Any],
    output_file: str,
) -> str:
    """
    Generate and write a standalone HTML investigation report.
    """

    path = Path(
        output_file
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    html = generate_html_report(
        investigation
    )

    path.write_text(
        html,
        encoding="utf-8",
    )

    return str(path)
