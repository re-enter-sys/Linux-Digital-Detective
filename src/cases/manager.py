from datetime import datetime, timezone

from .models import Case
from .storage import (
    case_exists,
    list_cases,
    load_case,
    save_case,
)


VALID_SEVERITIES = {
    "UNKNOWN",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


def create_case(
    case_id: str,
    title: str,
    description: str = "",
    severity: str = "UNKNOWN",
):
    if case_exists(case_id):
        raise ValueError(f"Case already exists: {case_id}")

    severity = severity.upper()

    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity: {severity}. "
            f"Choose from: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    case = Case.create(
        case_id=case_id,
        title=title,
        description=description,
        severity=severity,
    )

    save_case(case)

    return case


def get_cases():
    return list_cases()


def get_case(case_id: str):
    return load_case(case_id)


def close_case(case_id: str):
    case = load_case(case_id)

    if case is None:
        raise ValueError(f"Case not found: {case_id}")

    if case["status"] == "CLOSED":
        return case

    now = datetime.now(timezone.utc).isoformat()

    case["status"] = "CLOSED"
    case["closed_at"] = now
    case["updated_at"] = now

    class CaseWrapper:
        def __init__(self, data):
            self.case_id = data["case_id"]
            self.data = data

        def to_dict(self):
            return self.data

    save_case(CaseWrapper(case))

    return case
