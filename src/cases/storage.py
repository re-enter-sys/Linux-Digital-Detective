import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
CASES_DIR = BASE_DIR / "data" / "cases"


def get_case_path(case_id: str) -> Path:
    return CASES_DIR / case_id


def get_case_file(case_id: str) -> Path:
    return get_case_path(case_id) / "case.json"


def case_exists(case_id: str) -> bool:
    return get_case_file(case_id).exists()


def save_case(case):
    case_dir = get_case_path(case.case_id)
    case_dir.mkdir(parents=True, exist_ok=True)

    # Case subdirectories
    (case_dir / "evidence").mkdir(exist_ok=True)

    case_file = get_case_file(case.case_id)

    with case_file.open("w", encoding="utf-8") as f:
        json.dump(case.to_dict(), f, indent=4)

    # Initialize investigation files
    defaults = {
        "timeline.json": [],
        "findings.json": [],
        "mitre.json": [],
        "report.html": "",
    }

    for filename, content in defaults.items():
        file_path = case_dir / filename

        if not file_path.exists():
            if filename.endswith(".json"):
                file_path.write_text(
                    json.dumps(content, indent=4),
                    encoding="utf-8",
                )
            else:
                file_path.write_text("", encoding="utf-8")


def load_case(case_id: str):
    case_file = get_case_file(case_id)

    if not case_file.exists():
        return None

    with case_file.open("r", encoding="utf-8") as f:
        return json.load(f)


def list_cases():
    CASES_DIR.mkdir(parents=True, exist_ok=True)

    cases = []

    for case_dir in sorted(CASES_DIR.iterdir()):
        if not case_dir.is_dir():
            continue

        case_file = case_dir / "case.json"

        if not case_file.exists():
            continue

        try:
            with case_file.open("r", encoding="utf-8") as f:
                cases.append(json.load(f))
        except (json.JSONDecodeError, OSError):
            continue

    return cases
