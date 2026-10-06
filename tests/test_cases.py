import json

import pytest

from src.cases.models import Case
from src.cases import manager
from src.cases import storage


def test_case_create_defaults():
    case = Case.create(
        case_id="CASE-TEST-001",
        title="SSH Investigation",
    )

    assert case.case_id == "CASE-TEST-001"
    assert case.title == "SSH Investigation"
    assert case.description == ""
    assert case.status == "NEW"
    assert case.severity == "UNKNOWN"
    assert case.closed_at is None
    assert case.investigator == "Linux Digital Detective"
    assert case.created_at
    assert case.updated_at


def test_case_create_normalizes_severity():
    case = Case.create(
        case_id="CASE-TEST-002",
        title="Privilege Escalation",
        severity="high",
    )

    assert case.severity == "HIGH"


def test_case_to_dict_contains_all_fields():
    case = Case.create(
        case_id="CASE-TEST-003",
        title="Test Case",
        description="Case description",
        severity="medium",
    )

    data = case.to_dict()

    expected_fields = {
        "case_id",
        "title",
        "description",
        "status",
        "severity",
        "created_at",
        "updated_at",
        "investigator",
        "closed_at",
    }

    assert expected_fields.issubset(data.keys())


def test_save_and_load_case(tmp_path, monkeypatch):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )

    case = Case.create(
        case_id="CASE-TEST-004",
        title="Storage Test",
        description="Testing persistence",
        severity="HIGH",
    )

    storage.save_case(case)

    case_file = (
        tmp_path
        / "CASE-TEST-004"
        / "case.json"
    )

    assert case_file.exists()

    loaded = storage.load_case(
        "CASE-TEST-004"
    )

    assert loaded["case_id"] == "CASE-TEST-004"
    assert loaded["title"] == "Storage Test"
    assert loaded["severity"] == "HIGH"


def test_save_case_creates_required_directories(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )

    case = Case.create(
        case_id="CASE-TEST-005",
        title="Directory Test",
    )

    storage.save_case(case)

    case_dir = tmp_path / "CASE-TEST-005"

    assert case_dir.is_dir()
    assert (case_dir / "evidence").is_dir()
    assert (case_dir / "case.json").is_file()
    assert (case_dir / "timeline.json").is_file()
    assert (case_dir / "findings.json").is_file()
    assert (case_dir / "mitre.json").is_file()
    assert (case_dir / "report.html").is_file()


def test_save_case_initializes_json_defaults(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )

    case = Case.create(
        case_id="CASE-TEST-006",
        title="Defaults Test",
    )

    storage.save_case(case)

    case_dir = tmp_path / "CASE-TEST-006"

    for filename in (
        "timeline.json",
        "findings.json",
        "mitre.json",
    ):
        with (
            case_dir / filename
        ).open(
            "r",
            encoding="utf-8",
        ) as file:
            assert json.load(file) == []


def test_case_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )

    assert not storage.case_exists(
        "CASE-TEST-007"
    )

    case = Case.create(
        case_id="CASE-TEST-007",
        title="Existence Test",
    )

    storage.save_case(case)

    assert storage.case_exists(
        "CASE-TEST-007"
    )


def test_load_case_missing_returns_none(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )

    assert (
        storage.load_case(
            "CASE-DOES-NOT-EXIST"
        )
        is None
    )


def test_list_cases_returns_saved_cases(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )

    first = Case.create(
        case_id="CASE-TEST-008",
        title="First Case",
    )

    second = Case.create(
        case_id="CASE-TEST-009",
        title="Second Case",
    )

    storage.save_case(first)
    storage.save_case(second)

    cases = storage.list_cases()

    ids = {
        case["case_id"]
        for case in cases
    }

    assert ids == {
        "CASE-TEST-008",
        "CASE-TEST-009",
    }


def test_manager_create_case(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )
    monkeypatch.setattr(
        manager,
        "case_exists",
        storage.case_exists,
    )
    monkeypatch.setattr(
        manager,
        "save_case",
        storage.save_case,
    )

    case = manager.create_case(
        "CASE-TEST-010",
        "Manager Test",
        description="Created through manager",
        severity="critical",
    )

    assert case.case_id == "CASE-TEST-010"
    assert case.status == "NEW"
    assert case.severity == "CRITICAL"

    loaded = storage.load_case(
        "CASE-TEST-010"
    )

    assert loaded["title"] == "Manager Test"


def test_manager_rejects_duplicate_case(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )
    monkeypatch.setattr(
        manager,
        "case_exists",
        storage.case_exists,
    )
    monkeypatch.setattr(
        manager,
        "save_case",
        storage.save_case,
    )

    manager.create_case(
        "CASE-TEST-011",
        "Original",
    )

    with pytest.raises(ValueError):
        manager.create_case(
            "CASE-TEST-011",
            "Duplicate",
        )


def test_manager_rejects_invalid_severity(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )

    with pytest.raises(ValueError):
        manager.create_case(
            "CASE-TEST-012",
            "Invalid Severity",
            severity="SEVERE",
        )


def test_manager_close_case(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )
    monkeypatch.setattr(
        manager,
        "case_exists",
        storage.case_exists,
    )
    monkeypatch.setattr(
        manager,
        "save_case",
        storage.save_case,
    )
    monkeypatch.setattr(
        manager,
        "load_case",
        storage.load_case,
    )

    manager.create_case(
        "CASE-TEST-013",
        "Close Test",
        severity="HIGH",
    )

    closed = manager.close_case(
        "CASE-TEST-013"
    )

    assert closed["status"] == "CLOSED"
    assert closed["closed_at"] is not None
    assert closed["updated_at"] is not None

    loaded = storage.load_case(
        "CASE-TEST-013"
    )

    assert loaded["status"] == "CLOSED"


def test_manager_close_missing_case_raises(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        storage,
        "CASES_DIR",
        tmp_path,
    )
    monkeypatch.setattr(
        manager,
        "load_case",
        storage.load_case,
    )

    with pytest.raises(ValueError):
        manager.close_case(
            "CASE-DOES-NOT-EXIST"
        )
