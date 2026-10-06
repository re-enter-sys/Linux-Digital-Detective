import json
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, jsonify


dashboard_api = Blueprint(
    "dashboard_api",
    __name__,
    url_prefix="/api",
)


def _cases_dir() -> Path:
    return Path(current_app.config["CASES_DIR"])


def _case_dir(case_id: str) -> Path:
    """
    Resolve a case directory safely.

    Case IDs are expected to be simple directory names such as
    CASE-0001.
    """

    if not case_id:
        raise ValueError("Case ID is required.")

    if (
        "/" in case_id
        or "\\" in case_id
        or ".." in case_id
    ):
        raise ValueError("Invalid case ID.")

    return _cases_dir() / case_id


def _read_json(path: Path, default: Any = None) -> Any:
    """
    Read JSON safely.

    Dashboard failures should not crash the Flask application.
    """

    if default is None:
        default = {}

    if not path.exists():
        return default

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return default


def _case_data(case_dir: Path) -> dict:
    return _read_json(
        case_dir / "case.json",
        {},
    )


def _findings_data(case_dir: Path) -> Any:
    return _read_json(
        case_dir / "findings.json",
        [],
    )


def _timeline_data(case_dir: Path) -> dict:
    return _read_json(
        case_dir / "timeline.json",
        {},
    )


def _mitre_data(case_dir: Path) -> Any:
    return _read_json(
        case_dir / "mitre.json",
        [],
    )


def _report_data(case_dir: Path) -> Any:
    """
    Prefer structured investigation/report data when available.
    """

    candidates = [
        "investigation.json",
        "report.json",
        "attack_story.json",
    ]

    for filename in candidates:
        data = _read_json(
            case_dir / filename,
            None,
        )

        if data is not None:
            return data

    return {}


def _manifest_data(case_dir: Path) -> list:
    data = _read_json(
        case_dir / "evidence_manifest.json",
        [],
    )

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in (
            "evidence",
            "items",
            "manifest",
        ):
            value = data.get(key)

            if isinstance(value, list):
                return value

    return []


def _normalise_list(data: Any) -> list:
    """
    Convert common JSON wrapper formats into a list.
    """

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in (
            "findings",
            "events",
            "techniques",
            "mitre",
            "attack_chains",
            "chains",
            "items",
            "results",
        ):
            value = data.get(key)

            if isinstance(value, list):
                return value

    return []


def _extract_events(data: Any) -> list:
    if isinstance(data, dict):
        events = data.get("events")

        if isinstance(events, list):
            return events

    return _normalise_list(data)


def _extract_findings(data: Any) -> list:
    return _normalise_list(data)


def _extract_mitre(data: Any) -> list:
    return _normalise_list(data)


def _extract_attack_chains(data: Any) -> list:
    if isinstance(data, dict):
        for key in (
            "attack_chains",
            "chains",
        ):
            value = data.get(key)

            if isinstance(value, list):
                return value

    return []


def _extract_risk(data: Any) -> dict:
    if not isinstance(data, dict):
        return {}

    risk = data.get("risk_score")

    if isinstance(risk, dict):
        return risk

    risk = data.get("risk")

    if isinstance(risk, dict):
        return risk

    return {}


def _extract_attack_story(data: Any) -> dict:
    if not isinstance(data, dict):
        return {}

    story = data.get("attack_story")

    if isinstance(story, dict):
        return story

    story = data.get("story")

    if isinstance(story, dict):
        return story

    return {}


def _build_investigation(case_dir: Path) -> dict:
    findings_raw = _findings_data(case_dir)
    timeline_raw = _timeline_data(case_dir)
    mitre_raw = _mitre_data(case_dir)
    report_raw = _report_data(case_dir)

    findings = _extract_findings(
        findings_raw
    )

    events = _extract_events(
        timeline_raw
    )

    mitre = _extract_mitre(
        mitre_raw
    )

    attack_chains = _extract_attack_chains(
        report_raw
    )

    risk = _extract_risk(
        report_raw
    )

    attack_story = _extract_attack_story(
        report_raw
    )

    if not attack_chains:
        attack_chains = _extract_attack_chains(
            findings_raw
        )

    if not risk:
        risk = _extract_risk(
            findings_raw
        )

    if not attack_story:
        attack_story = _extract_attack_story(
            findings_raw
        )

    return {
        "events": events,
        "findings": findings,
        "attack_chains": attack_chains,
        "risk_score": risk,
        "mitre": mitre,
        "attack_story": attack_story,
    }


def _case_exists(case_id: str) -> bool:
    try:
        return _case_dir(case_id).is_dir()
    except ValueError:
        return False


@dashboard_api.errorhandler(
    ValueError
)
def handle_value_error(error):
    return jsonify(
        {
            "error": str(error),
        }
    ), 400


@dashboard_api.route("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "Linux Digital Detective",
        }
    )


@dashboard_api.route("/cases")
def api_cases():
    results = []

    cases_dir = _cases_dir()

    if not cases_dir.exists():
        return jsonify(results)

    for directory in sorted(
        cases_dir.iterdir(),
        key=lambda item: item.name,
    ):
        if not directory.is_dir():
            continue

        data = _case_data(directory)

        if not data:
            continue

        results.append(
            {
                "case_id": data.get(
                    "case_id",
                    directory.name,
                ),
                "title": data.get(
                    "title",
                    directory.name,
                ),
                "description": data.get(
                    "description",
                    "",
                ),
                "severity": data.get(
                    "severity",
                    "UNKNOWN",
                ),
                "status": data.get(
                    "status",
                    "NEW",
                ),
                "investigator": data.get(
                    "investigator",
                    "Linux Digital Detective",
                ),
                "created_at": data.get(
                    "created_at"
                ),
                "updated_at": data.get(
                    "updated_at"
                ),
                "closed_at": data.get(
                    "closed_at"
                ),
            }
        )

    return jsonify(results)


@dashboard_api.route(
    "/cases/<case_id>"
)
def api_case(case_id):
    if not _case_exists(case_id):
        return jsonify(
            {
                "error": (
                    f"Case not found: {case_id}"
                )
            }
        ), 404

    case_dir = _case_dir(case_id)

    case = _case_data(
        case_dir
    )

    investigation = _build_investigation(
        case_dir
    )

    evidence = _manifest_data(
        case_dir
    )

    return jsonify(
        {
            "case": case,
            "investigation": investigation,
            "evidence": evidence,
        }
    )


@dashboard_api.route(
    "/cases/<case_id>/evidence"
)
def api_case_evidence(case_id):
    if not _case_exists(case_id):
        return jsonify(
            {
                "error": (
                    f"Case not found: {case_id}"
                )
            }
        ), 404

    return jsonify(
        _manifest_data(
            _case_dir(case_id)
        )
    )


@dashboard_api.route(
    "/cases/<case_id>/timeline"
)
def api_case_timeline(case_id):
    if not _case_exists(case_id):
        return jsonify(
            {
                "error": (
                    f"Case not found: {case_id}"
                )
            }
        ), 404

    return jsonify(
        _timeline_data(
            _case_dir(case_id)
        )
    )


@dashboard_api.route(
    "/cases/<case_id>/findings"
)
def api_case_findings(case_id):
    if not _case_exists(case_id):
        return jsonify(
            {
                "error": (
                    f"Case not found: {case_id}"
                )
            }
        ), 404

    return jsonify(
        _findings_data(
            _case_dir(case_id)
        )
    )


@dashboard_api.route(
    "/cases/<case_id>/mitre"
)
def api_case_mitre(case_id):
    if not _case_exists(case_id):
        return jsonify(
            {
                "error": (
                    f"Case not found: {case_id}"
                )
            }
        ), 404

    return jsonify(
        _mitre_data(
            _case_dir(case_id)
        )
    )


@dashboard_api.route(
    "/cases/<case_id>/attack-story"
)
def api_case_attack_story(case_id):
    if not _case_exists(case_id):
        return jsonify(
            {
                "error": (
                    f"Case not found: {case_id}"
                )
            }
        ), 404

    investigation = _build_investigation(
        _case_dir(case_id)
    )

    return jsonify(
        investigation.get(
            "attack_story",
            {},
        )
    )


@dashboard_api.route(
    "/cases/<case_id>/report"
)
def api_case_report(case_id):
    if not _case_exists(case_id):
        return jsonify(
            {
                "error": (
                    f"Case not found: {case_id}"
                )
            }
        ), 404

    case_dir = _case_dir(case_id)

    report = _report_data(
        case_dir
    )

    if report:
        return jsonify(report)

    investigation = _build_investigation(
        case_dir
    )

    return jsonify(
        {
            "case": _case_data(
                case_dir
            ),
            "investigation": investigation,
        }
    )


@dashboard_api.route(
    "/cases/<case_id>/summary"
)
def api_case_summary(case_id):
    if not _case_exists(case_id):
        return jsonify(
            {
                "error": (
                    f"Case not found: {case_id}"
                )
            }
        ), 404

    case_dir = _case_dir(case_id)

    case = _case_data(
        case_dir
    )

    investigation = _build_investigation(
        case_dir
    )

    return jsonify(
        {
            "case_id": case.get(
                "case_id",
                case_id,
            ),
            "title": case.get(
                "title",
                case_id,
            ),
            "status": case.get(
                "status",
                "NEW",
            ),
            "severity": case.get(
                "severity",
                "UNKNOWN",
            ),
            "evidence_count": len(
                _manifest_data(case_dir)
            ),
            "event_count": len(
                investigation.get(
                    "events",
                    [],
                )
            ),
            "finding_count": len(
                investigation.get(
                    "findings",
                    [],
                )
            ),
            "mitre_count": len(
                investigation.get(
                    "mitre",
                    [],
                )
            ),
            "attack_chain_count": len(
                investigation.get(
                    "attack_chains",
                    [],
                )
            ),
        }
    )
