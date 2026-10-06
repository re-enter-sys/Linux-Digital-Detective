from pathlib import Path


# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT
    / "data"
)

CASES_DIR = (
    DATA_DIR
    / "cases"
)

EVIDENCE_DIR = (
    DATA_DIR
    / "evidence"
)

SAMPLE_DIR = (
    DATA_DIR
    / "sample"
)

REPORTS_DIR = (
    PROJECT_ROOT
    / "reports"
)

REPORT_EXAMPLES_DIR = (
    REPORTS_DIR
    / "examples"
)


# ---------------------------------------------------------------------------
# Investigation configuration
# ---------------------------------------------------------------------------

DEFAULT_INVESTIGATOR = (
    "Linux Digital Detective"
)

DEFAULT_CASE_SEVERITY = "MEDIUM"

DEFAULT_CASE_STATUS = "NEW"


# ---------------------------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------------------------

BRUTE_FORCE_THRESHOLD = 4

BRUTE_FORCE_WINDOW_SECONDS = 300

SUCCESS_AFTER_BRUTE_FORCE_WINDOW_SECONDS = 300


# ---------------------------------------------------------------------------
# Supported evidence types
# ---------------------------------------------------------------------------

SUPPORTED_EVIDENCE_EXTENSIONS = {
    ".log",
    ".txt",
    ".history",
}

SUPPORTED_EVIDENCE_FILENAMES = {
    "auth.log",
    "secure",
    "secure.log",
    "syslog",
    "messages",
    "access.log",
    "error.log",
    "bash_history",
    ".bash_history",
}


# ---------------------------------------------------------------------------
# Parser identification
# ---------------------------------------------------------------------------

PARSER_AUTH = "auth"

PARSER_SSH = "ssh"

PARSER_SUDO = "sudo"

PARSER_SYSLOG = "syslog"

PARSER_BASH = "bash"

PARSER_WEB = "web"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def ensure_project_directories() -> None:
    """
    Create directories required by Linux Digital Detective.

    Existing directories are preserved.
    """

    directories = (
        DATA_DIR,
        CASES_DIR,
        EVIDENCE_DIR,
        SAMPLE_DIR,
        REPORTS_DIR,
        REPORT_EXAMPLES_DIR,
    )

    for directory in directories:
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )


def get_case_directory(
    case_id: str,
) -> Path:
    """
    Return the filesystem directory for a case.
    """

    if not case_id:
        raise ValueError(
            "case_id cannot be empty"
        )

    return (
        CASES_DIR
        / case_id
    )


def get_case_evidence_directory(
    case_id: str,
) -> Path:
    """
    Return the evidence directory for a case.
    """

    return (
        get_case_directory(case_id)
        / "evidence"
    )


def get_case_report_directory(
    case_id: str,
) -> Path:
    """
    Return the directory containing generated
    investigation reports for a case.
    """

    return get_case_directory(
        case_id
    )
