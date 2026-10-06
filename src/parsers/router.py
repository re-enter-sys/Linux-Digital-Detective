from pathlib import Path
from typing import Callable, Optional

from src.timeline.events import Event

from src.parsers.auth_parser import parse_auth_log
from src.parsers.bash_parser import parse_bash_history
from src.parsers.ssh_parser import parse_ssh_log
from src.parsers.sudo_parser import parse_sudo_log
from src.parsers.syslog_parser import parse_syslog
from src.parsers.web_parser import parse_web_log


ParserFunction = Callable[..., list[Event]]


# ------------------------------------------------------------------
# Evidence type detection
# ------------------------------------------------------------------

PARSER_BY_FILENAME: dict[str, ParserFunction] = {
    "auth.log": parse_auth_log,
    "secure": parse_auth_log,
    "secure.log": parse_auth_log,

    "ssh.log": parse_ssh_log,
    "sshd.log": parse_ssh_log,

    "sudo.log": parse_sudo_log,

    "syslog": parse_syslog,
    "syslog.log": parse_syslog,

    "bash_history": parse_bash_history,
    ".bash_history": parse_bash_history,

    "access.log": parse_web_log,
    "access_log": parse_web_log,
}


# ------------------------------------------------------------------
# Parser lookup
# ------------------------------------------------------------------

def get_parser(
    file_path: str,
) -> Optional[ParserFunction]:
    """
    Determine the appropriate parser from an evidence filename.

    The router first checks exact known filenames and then applies
    conservative token-based matching. This allows realistic
    forensic filenames such as:

        CASE-0002-ssh-followup.log
        CASE-0005-command-history.log
        host01-bash_history.txt
        incident-access.log

    without changing the behavior of existing evidence types.
    """

    filename = Path(
        file_path
    ).name.lower()

    # Exact filename match.
    if filename in PARSER_BY_FILENAME:
        return PARSER_BY_FILENAME[
            filename
        ]

    # Remove common separators so filenames can be inspected
    # consistently without requiring an exact naming convention.
    normalized = filename.replace(
        "-", "_"
    ).replace(
        ".", "_"
    )

    # --------------------------------------------------------------
    # Web / HTTP access logs
    # --------------------------------------------------------------
    if (
        filename.startswith("access")
        or "access_log" in normalized
        or "_access_" in f"_{normalized}_"
    ):
        return parse_web_log

    # --------------------------------------------------------------
    # Authentication logs
    # --------------------------------------------------------------
    if (
        filename.startswith("secure")
        or filename.startswith("auth")
        or "_auth_" in f"_{normalized}_"
        or normalized.endswith("_auth")
    ):
        return parse_auth_log

    # --------------------------------------------------------------
    # SSH authentication logs
    # --------------------------------------------------------------
    if (
        filename.startswith("sshd")
        or filename.startswith("ssh")
        or "_sshd_" in f"_{normalized}_"
        or "_ssh_" in f"_{normalized}_"
        or normalized.endswith("_ssh")
        or "ssh_followup" in normalized
    ):
        return parse_ssh_log

    # --------------------------------------------------------------
    # Sudo / privilege escalation logs
    # --------------------------------------------------------------
    if (
        filename.startswith("sudo")
        or "sudo" in normalized
    ):
        return parse_sudo_log

    # --------------------------------------------------------------
    # System logs
    # --------------------------------------------------------------
    if (
        filename.startswith("syslog")
        or "_syslog_" in f"_{normalized}_"
    ):
        return parse_syslog

    # --------------------------------------------------------------
    # Bash history / command history
    # --------------------------------------------------------------
    if (
        "bash_history" in normalized
        or "bashhistory" in normalized
        or "command_history" in normalized
        or "commandhistory" in normalized
        or "shell_history" in normalized
        or "shellhistory" in normalized
    ):
        return parse_bash_history

    return None


# ------------------------------------------------------------------
# Parser name
# ------------------------------------------------------------------

def get_parser_name(
    file_path: str,
) -> Optional[str]:
    """
    Return the name of the parser selected for an evidence file.
    """

    parser = get_parser(
        file_path
    )

    if parser is None:
        return None

    return parser.__name__


# ------------------------------------------------------------------
# Supported evidence types
# ------------------------------------------------------------------

def supported_evidence_types() -> list[str]:
    """
    Return supported canonical evidence filenames.

    The returned list is sorted for deterministic output.
    """

    return sorted(
        PARSER_BY_FILENAME.keys()
    )


# ------------------------------------------------------------------
# Parse evidence
# ------------------------------------------------------------------

def parse_evidence(
    file_path: str,
    *,
    year: Optional[int] = None,
) -> list[Event]:
    """
    Automatically select the appropriate parser and parse
    the supplied evidence file.

    Traditional syslog-style parsers receive the optional year.
    Bash and web parsers do not require it.
    """

    parser = get_parser(
        file_path
    )

    if parser is None:
        filename = Path(
            file_path
        ).name

        raise ValueError(
            "Unsupported evidence type: "
            f"{filename}"
        )

    parser_name = parser.__name__

    if parser_name in {
        "parse_auth_log",
        "parse_ssh_log",
        "parse_sudo_log",
        "parse_syslog",
    }:
        return parser(
            file_path,
            year=year,
        )

    return parser(
        file_path
    )


# ------------------------------------------------------------------
# Parse multiple evidence files
# ------------------------------------------------------------------

def parse_evidence_files(
    file_paths: list[str],
    *,
    year: Optional[int] = None,
) -> list[Event]:
    """
    Parse multiple evidence files through the appropriate
    parser and return one combined event collection.

    Events are sorted chronologically after parsing.
    """

    events: list[Event] = []

    for file_path in file_paths:
        events.extend(
            parse_evidence(
                file_path,
                year=year,
            )
        )

    events.sort(
        key=lambda event: event.timestamp
    )

    return events
