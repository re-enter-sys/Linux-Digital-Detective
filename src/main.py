import argparse
import json
import sys
from pathlib import Path

from src.cases.manager import (
    create_case,
    list_cases,
    close_case,
)

from src.evidence.collector import (
    add_evidence,
    load_manifest,
)

from src.investigation.evidence_pipeline import (
    parse_case_evidence,
)

from src.investigation.run_case import (
    run_investigation,
)

from src.reporting.csv_report import (
    write_findings_csv,
)

from src.reporting.html_report import (
    write_html_report,
)

from src.reporting.json_report import (
    write_json_report,
)

from src.detection.brute_force import (
    detect_ssh_brute_force,
    detect_successful_login_after_brute_force,
)

from src.detection.privilege_escalation import (
    detect_privilege_escalation,
)

from src.detection.suspicious_commands import (
    detect_suspicious_commands,
)

from src.detection.persistence import (
    detect_persistence,
)

from src.detection.network_activity import (
    detect_network_activity,
)


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

CASES_DIR = (
    PROJECT_ROOT
    / "data"
    / "cases"
)


def _case_value(
    case,
    key: str,
    default=None,
):
    """
    Read a case field from either a dictionary
    or a Case-like object.
    """

    if isinstance(case, dict):
        return case.get(
            key,
            default,
        )

    return getattr(
        case,
        key,
        default,
    )


def find_case(case_id: str):
    """
    Find a case by ID.
    """

    cases = list_cases()

    for case in cases:
        if _case_value(
            case,
            "case_id",
        ) == case_id:
            return case

    raise FileNotFoundError(
        f"Case not found: {case_id}"
    )


def get_case_directory(
    case_id: str,
) -> Path:
    """
    Return the case directory.
    """

    return (
        CASES_DIR
        / case_id
    )


# ------------------------------------------------------------------
# CASE MANAGEMENT
# ------------------------------------------------------------------

def handle_case(args):
    if args.action == "create":
        try:
            case = create_case(
                case_id=args.case_id,
                title=args.title,
                description=args.description,
                severity=args.severity,
            )

            print()
            print("=" * 60)
            print("CASE CREATED")
            print("=" * 60)

            print(
                f"Case ID:       "
                f"{_case_value(case, 'case_id', args.case_id)}"
            )

            print(
                f"Title:         "
                f"{_case_value(case, 'title', args.title)}"
            )

            print(
                f"Description:   "
                f"{_case_value(case, 'description', args.description)}"
            )

            print(
                f"Severity:      "
                f"{_case_value(case, 'severity', args.severity)}"
            )

            print(
                f"Status:        "
                f"{_case_value(case, 'status', 'NEW')}"
            )

            print(
                f"Investigator:  "
                f"{_case_value(case, 'investigator', 'Linux Digital Detective')}"
            )

            print(
                f"Created:       "
                f"{_case_value(case, 'created_at', '-')}"
            )

            print("=" * 60)

        except (
            ValueError,
            FileExistsError,
        ) as e:
            print(
                f"\n✗ Error: {e}"
            )
            sys.exit(1)

    elif args.action == "list":
        try:
            cases = list_cases()

            if not cases:
                print(
                    "\nNo cases found."
                )
                return

            print()
            print("=" * 80)
            print(
                "LINUX DIGITAL DETECTIVE — CASES"
            )
            print("=" * 80)

            print(
                f"{'CASE ID':<15}"
                f"{'TITLE':<35}"
                f"{'SEVERITY':<12}"
                f"{'STATUS':<15}"
            )

            print("-" * 80)

            for case in cases:
                case_id = _case_value(
                    case,
                    "case_id",
                    "-",
                )

                title = _case_value(
                    case,
                    "title",
                    "-",
                )

                severity = _case_value(
                    case,
                    "severity",
                    "UNKNOWN",
                )

                status = _case_value(
                    case,
                    "status",
                    "UNKNOWN",
                )

                if len(str(title)) > 33:
                    title = (
                        str(title)[:33]
                        + ".."
                    )

                print(
                    f"{str(case_id):<15}"
                    f"{str(title):<35}"
                    f"{str(severity):<12}"
                    f"{str(status):<15}"
                )

            print("=" * 80)

        except Exception as e:
            print(
                f"\n✗ Error: {e}"
            )
            sys.exit(1)

    elif args.action == "show":
        try:
            case = find_case(
                args.case_id
            )

            print()
            print("=" * 60)
            print("CASE DETAILS")
            print("=" * 60)

            print(
                f"Case ID:       "
                f"{_case_value(case, 'case_id', args.case_id)}"
            )

            print(
                f"Title:         "
                f"{_case_value(case, 'title', '-')}"
            )

            print(
                f"Description:   "
                f"{_case_value(case, 'description', '-')}"
            )

            print(
                f"Severity:      "
                f"{_case_value(case, 'severity', '-')}"
            )

            print(
                f"Status:        "
                f"{_case_value(case, 'status', '-')}"
            )

            print(
                f"Investigator:  "
                f"{_case_value(case, 'investigator', '-')}"
            )

            print(
                f"Created:       "
                f"{_case_value(case, 'created_at', '-')}"
            )

            print(
                f"Updated:       "
                f"{_case_value(case, 'updated_at', '-')}"
            )

            closed_at = _case_value(
                case,
                "closed_at",
                None,
            )

            if closed_at:
                print(
                    f"Closed:        {closed_at}"
                )

            print("=" * 60)

        except (
            FileNotFoundError,
            ValueError,
        ) as e:
            print(
                f"\n✗ Error: {e}"
            )
            sys.exit(1)

    elif args.action == "close":
        try:
            case = close_case(
                args.case_id
            )

            print()
            print("=" * 60)
            print("CASE CLOSED")
            print("=" * 60)

            print(
                f"Case ID:       "
                f"{_case_value(case, 'case_id', args.case_id)}"
            )

            print(
                f"Title:         "
                f"{_case_value(case, 'title', '-')}"
            )

            print(
                f"Status:        "
                f"{_case_value(case, 'status', 'CLOSED')}"
            )

            closed_at = _case_value(
                case,
                "closed_at",
                None,
            )

            if closed_at:
                print(
                    f"Closed:        {closed_at}"
                )

            print("=" * 60)

        except (
            FileNotFoundError,
            ValueError,
        ) as e:
            print(
                f"\n✗ Error: {e}"
            )
            sys.exit(1)


# ------------------------------------------------------------------
# EVIDENCE MANAGEMENT
# ------------------------------------------------------------------

def handle_evidence(args):
    if args.action == "add":
        try:
            evidence = add_evidence(
                case_id=args.case_id,
                source_file=args.file,
            )

            print()
            print("=" * 60)
            print("EVIDENCE ADDED")
            print("=" * 60)

            print(
                f"Case ID:        "
                f"{args.case_id}"
            )

            print(
                f"Filename:       "
                f"{evidence['filename']}"
            )

            print(
                f"Stored as:      "
                f"{evidence['stored_filename']}"
            )

            print(
                f"Size:            "
                f"{evidence['size_bytes']} bytes"
            )

            print(
                f"SHA-256:        "
                f"{evidence['sha256']}"
            )

            print(
                f"Integrity:       "
                f"{evidence['integrity']}"
            )

            print(
                f"Original path:   "
                f"{evidence['original_path']}"
            )

            print(
                f"Acquired:        "
                f"{evidence['acquired_at']}"
            )

            print("=" * 60)

        except (
            FileNotFoundError,
            ValueError,
            FileExistsError,
            RuntimeError,
        ) as e:
            print(
                f"\n✗ Error: {e}"
            )
            sys.exit(1)

    elif args.action == "list":
        try:
            manifest = load_manifest(
                args.case_id
            )

            if not manifest:
                print()
                print("=" * 60)
                print(
                    f"NO EVIDENCE FOUND FOR "
                    f"{args.case_id}"
                )
                print("=" * 60)
                return

            print()
            print("=" * 100)
            print(
                f"EVIDENCE FOR CASE: "
                f"{args.case_id}"
            )
            print("=" * 100)

            print(
                f"{'FILENAME':<30}"
                f"{'SIZE':<12}"
                f"{'INTEGRITY':<12}"
                f"SHA-256"
            )

            print("-" * 100)

            for evidence in manifest:
                print(
                    f"{evidence['filename']:<30}"
                    f"{evidence['size_bytes']:<12}"
                    f"{evidence['integrity']:<12}"
                    f"{evidence['sha256']}"
                )

            print("=" * 100)

        except (
            FileNotFoundError,
            ValueError,
        ) as e:
            print(
                f"\n✗ Error: {e}"
            )
            sys.exit(1)


# ------------------------------------------------------------------
# CASE EVIDENCE
# ------------------------------------------------------------------

def _get_case_evidence_paths(
    case_id: str,
) -> list[str]:
    """
    Resolve every registered evidence artifact for a case.

    The evidence manifest remains the authoritative source
    for determining which files belong to the case.
    """

    manifest = load_manifest(
        case_id
    )

    if not manifest:
        raise FileNotFoundError(
            f"No evidence found for {case_id}"
        )

    evidence_dir = (
        get_case_directory(case_id)
        / "evidence"
    )

    evidence_paths = []

    for evidence in manifest:
        filename = evidence.get(
            "filename",
            "",
        )

        stored_filename = evidence.get(
            "stored_filename",
            filename,
        )

        evidence_path = (
            evidence_dir
            / stored_filename
        )

        if not evidence_path.is_file():
            raise FileNotFoundError(
                "Evidence file is missing: "
                f"{evidence_path}"
            )

        evidence_paths.append(
            str(evidence_path)
        )

    return evidence_paths


# ------------------------------------------------------------------
# DETECTION ENGINES
# ------------------------------------------------------------------

def _run_detections(
    events: list,
) -> list:
    """
    Run all currently implemented detection engines.
    """

    findings = []

    detectors = [
        (
            "SSH brute-force detection",
            detect_ssh_brute_force,
        ),
        (
            "Successful login after brute-force",
            detect_successful_login_after_brute_force,
        ),
        (
            "Privilege escalation detection",
            detect_privilege_escalation,
        ),
        (
            "Suspicious command detection",
            detect_suspicious_commands,
        ),
        (
            "Persistence detection",
            detect_persistence,
        ),
        (
            "Network activity detection",
            detect_network_activity,
        ),
    ]

    for name, detector in detectors:
        print(
            f"  → {name}...",
            end=" ",
            flush=True,
        )

        detector_findings = detector(
            events
        )

        findings.extend(
            detector_findings
        )

        print(
            f"✓ {len(detector_findings)} finding(s)"
        )

    return findings


# ------------------------------------------------------------------
# INVESTIGATION
# ------------------------------------------------------------------

def handle_investigate(args):
    case_id = args.case_id

    try:
        find_case(
            case_id
        )

        print()
        print("=" * 72)
        print(
            "LINUX DIGITAL DETECTIVE — INVESTIGATION"
        )
        print("=" * 72)

        print(
            f"Case: {case_id}"
        )

        print()
        print(
            "[1/4] Loading and parsing evidence"
        )

        evidence_paths = (
            _get_case_evidence_paths(
                case_id
            )
        )

        parse_result = parse_case_evidence(
            evidence_paths
        )

        for parsed_file in (
            parse_result.parsed_files
        ):
            print(
                "  → "
                f"{parsed_file['filename']} "
                f"→ {parsed_file['parser']} "
                f"✓ {parsed_file['event_count']} event(s)"
            )

        for unsupported_file in (
            parse_result.unsupported_files
        ):
            print(
                "  ! Unsupported evidence: "
                f"{unsupported_file['filename']}"
            )

        for failed_file in (
            parse_result.failed_files
        ):
            print(
                "  ✗ Parser failed: "
                f"{failed_file['filename']} "
                f"— {failed_file['error']}"
            )

        events = parse_result.events

        print()
        print(
            f"  ✓ Normalized events: "
            f"{len(events)}"
        )

        if not events:
            print(
                "\n✗ No normalized events were "
                "found in the case evidence."
            )
            sys.exit(1)

        print()
        print(
            "[2/4] Running detection engines"
        )

        findings = _run_detections(
            events
        )

        print()
        print(
            f"  ✓ Total findings: "
            f"{len(findings)}"
        )

        print()
        print(
            "[3/4] Correlating investigation"
        )

        result = run_investigation(
            case_id=case_id,
            events=events,
            findings=findings,
        )

        print(
            "  ✓ Attack chains built"
        )

        print(
            "  ✓ Risk score calculated"
        )

        print(
            "  ✓ MITRE ATT&CK mappings generated"
        )

        print(
            "  ✓ Attack story generated"
        )

        print()
        print(
            "[4/4] Writing investigation artifacts"
        )

        case_dir = get_case_directory(
            case_id
        )

        print(
            f"  ✓ {case_dir / 'investigation.json'}"
        )

        print(
            f"  ✓ {case_dir / 'report.html'}"
        )

        print(
            f"  ✓ {case_dir / 'findings.csv'}"
        )

        print(
            f"  ✓ {case_dir / 'findings.json'}"
        )

        print(
            f"  ✓ {case_dir / 'timeline.json'}"
        )

        print(
            f"  ✓ {case_dir / 'mitre.json'}"
        )

        risk_score = result.get(
            "risk_score",
            {},
        )

        if isinstance(
            risk_score,
            dict,
        ):
            score = risk_score.get(
                "score",
                risk_score.get(
                    "risk_score",
                    "N/A",
                ),
            )

            risk_level = risk_score.get(
                "severity",
                risk_score.get(
                    "level",
                    risk_score.get(
                        "risk_level",
                        "N/A",
                    ),
                ),
            )
        else:
            score = "N/A"
            risk_level = "N/A"

        print()
        print("=" * 72)
        print(
            "INVESTIGATION COMPLETE"
        )
        print("=" * 72)

        print(
            f"Case:          {case_id}"
        )

        print(
            f"Evidence:      {parse_result.total_files}"
        )

        print(
            f"Parsed files:  "
            f"{parse_result.successful_files}"
        )

        print(
            f"Events:        {len(events)}"
        )

        print(
            f"Findings:      {len(findings)}"
        )

        print(
            f"Attack chains: "
            f"{len(result.get('attack_chains', []))}"
        )

        print(
            f"MITRE mappings: "
            f"{len(result.get('mitre', []))}"
        )

        print(
            f"Risk score:    {score}"
        )

        print(
            f"Risk level:    {risk_level}"
        )

        print("=" * 72)

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        KeyError,
    ) as e:
        print(
            f"\n✗ Investigation failed: {e}"
        )
        sys.exit(1)

    except Exception as e:
        print(
            "\n✗ Unexpected investigation "
            f"error: {type(e).__name__}: {e}"
        )
        sys.exit(1)


# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

def handle_report(args):
    case_dir = get_case_directory(
        args.case_id
    )

    investigation_file = (
        case_dir
        / "investigation.json"
    )

    if not investigation_file.exists():
        print(
            "\n✗ Investigation has not been generated."
        )

        print(
            "Run:"
        )

        print(
            f"  python3 -m src.main "
            f"investigate {args.case_id}"
        )

        sys.exit(1)

    investigation = json.loads(
        investigation_file.read_text(
            encoding="utf-8"
        )
    )

    if args.format == "json":
        output = (
            case_dir
            / "investigation-export.json"
        )

        write_json_report(
            investigation,
            str(output),
        )

    elif args.format == "html":
        output = (
            case_dir
            / "report.html"
        )

        write_html_report(
            investigation,
            str(output),
        )

    elif args.format == "csv":
        output = (
            case_dir
            / "findings.csv"
        )

        write_findings_csv(
            investigation[
                "findings"
            ],
            str(output),
        )

    print(
        f"\n✓ Report generated: {output}"
    )


# ------------------------------------------------------------------
# ARGUMENT PARSER
# ------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="linux-digital-detective",
        description=(
            "Linux Digital Detective — "
            "Forensic evidence collection "
            "and investigation CLI"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # --------------------------------------------------------------
    # CASE
    # --------------------------------------------------------------

    case_parser = subparsers.add_parser(
        "case",
        help="Manage investigation cases",
    )

    case_subparsers = (
        case_parser.add_subparsers(
            dest="action",
            required=True,
        )
    )

    case_create = (
        case_subparsers.add_parser(
            "create",
            help="Create an investigation case",
        )
    )

    case_create.add_argument(
        "case_id"
    )

    case_create.add_argument(
        "--title",
        required=True,
    )

    case_create.add_argument(
        "--description",
        required=True,
    )

    case_create.add_argument(
        "--severity",
        default="MEDIUM",
        choices=[
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ],
    )

    case_subparsers.add_parser(
        "list",
        help="List investigation cases",
    )

    case_show = (
        case_subparsers.add_parser(
            "show",
            help="Show case details",
        )
    )

    case_show.add_argument(
        "case_id"
    )

    case_close = (
        case_subparsers.add_parser(
            "close",
            help="Close an investigation case",
        )
    )

    case_close.add_argument(
        "case_id"
    )

    # --------------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------------

    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Manage forensic evidence",
    )

    evidence_subparsers = (
        evidence_parser.add_subparsers(
            dest="action",
            required=True,
        )
    )

    evidence_add = (
        evidence_subparsers.add_parser(
            "add",
            help="Add forensic evidence",
        )
    )

    evidence_add.add_argument(
        "case_id"
    )

    evidence_add.add_argument(
        "file"
    )

    evidence_list = (
        evidence_subparsers.add_parser(
            "list",
            help="List case evidence",
        )
    )

    evidence_list.add_argument(
        "case_id"
    )

    # --------------------------------------------------------------
    # INVESTIGATE
    # --------------------------------------------------------------

    investigate_parser = (
        subparsers.add_parser(
            "investigate",
            help=(
                "Run the complete forensic "
                "investigation pipeline"
            ),
        )
    )

    investigate_parser.add_argument(
        "case_id",
        help="Case identifier",
    )

    # --------------------------------------------------------------
    # REPORT
    # --------------------------------------------------------------

    report_parser = subparsers.add_parser(
        "report",
        help="Generate investigation reports",
    )

    report_parser.add_argument(
        "case_id"
    )

    report_parser.add_argument(
        "--format",
        choices=[
            "json",
            "html",
            "csv",
        ],
        default="html",
    )

    return parser


# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------

def main():
    parser = build_parser()

    args = parser.parse_args()

    if args.command == "case":
        handle_case(args)

    elif args.command == "evidence":
        handle_evidence(args)

    elif args.command == "investigate":
        handle_investigate(args)

    elif args.command == "report":
        handle_report(args)


if __name__ == "__main__":
    main()
