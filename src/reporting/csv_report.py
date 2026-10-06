import csv
from pathlib import Path
from typing import Any


FIELDNAMES = [
    "finding_id",
    "event_type",
    "category",
    "title",
    "severity",
    "description",
    "username",
    "source_ip",
    "destination_ip",
    "destination_port",
    "command",
    "event_id",
    "timestamp",
]


def _normalize_finding(
    finding: Any,
) -> dict[str, Any]:
    """
    Convert finding objects into dictionaries.
    """

    if isinstance(
        finding,
        dict,
    ):
        return finding

    if hasattr(
        finding,
        "to_dict",
    ):
        return finding.to_dict()

    return {
        key: value
        for key, value in vars(
            finding
        ).items()
        if not key.startswith("_")
    }


def _csv_value(
    value: Any,
) -> Any:
    """
    Convert list-like values into a readable CSV value.
    """

    if isinstance(
        value,
        list,
    ):
        return "; ".join(
            str(item)
            for item in value
        )

    if isinstance(
        value,
        dict,
    ):
        return str(
            value
        )

    return value


def write_findings_csv(
    findings: list[Any],
    output_file: str,
) -> str:
    """
    Write investigation findings to CSV.

    The CSV is designed for analysts who want to open
    findings in Excel, LibreOffice, pandas, or another
    investigation workflow.
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
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDNAMES,
            extrasaction="ignore",
        )

        writer.writeheader()

        for finding in findings:
            data = _normalize_finding(
                finding
            )

            row = {
                field: _csv_value(
                    data.get(
                        field,
                        "",
                    )
                )
                for field in FIELDNAMES
            }

            writer.writerow(
                row
            )

    return str(path)
