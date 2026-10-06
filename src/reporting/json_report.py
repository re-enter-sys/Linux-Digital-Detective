import json
from pathlib import Path
from typing import Any


def write_json_report(
    investigation: dict[str, Any],
    output_file: str,
) -> str:
    """
    Write the complete investigation result as
    a machine-readable JSON report.
    """

    path = Path(
        output_file
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            investigation,
            file,
            indent=4,
            ensure_ascii=False,
        )

    return str(path)


def load_json_report(
    input_file: str,
) -> dict[str, Any]:
    """
    Load a previously generated investigation JSON report.
    """

    path = Path(
        input_file
    )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(
            file
        )
