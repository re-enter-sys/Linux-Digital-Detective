import json

import pytest

from src.evidence import collector
from src.evidence.collector import (
    add_evidence,
    get_evidence_directory,
    get_manifest_path,
    load_manifest,
    save_manifest,
)
from src.evidence.metadata import (
    collect_metadata,
)


def test_collect_metadata_returns_expected_fields(
    tmp_path,
):
    evidence = tmp_path / "auth.log"

    evidence.write_text(
        "authentication failure\n",
        encoding="utf-8",
    )

    metadata = collect_metadata(
        str(evidence)
    )

    assert metadata["filename"] == "auth.log"
    assert metadata["size_bytes"] == evidence.stat().st_size
    assert metadata["original_path"] == str(
        evidence.resolve()
    )
    assert metadata["acquired_at"]


def test_collect_metadata_missing_file_raises(
    tmp_path,
):
    missing = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        collect_metadata(str(missing))


def test_manifest_missing_returns_empty_list(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        tmp_path,
    )

    assert (
        load_manifest("CASE-TEST-001")
        == []
    )


def test_save_and_load_manifest(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        tmp_path,
    )

    case_dir = (
        tmp_path
        / "CASE-TEST-002"
    )
    case_dir.mkdir(
        parents=True
    )

    manifest = [
        {
            "filename": "auth.log",
            "sha256": "a" * 64,
            "integrity": "VERIFIED",
        }
    ]

    save_manifest(
        "CASE-TEST-002",
        manifest,
    )

    loaded = load_manifest(
        "CASE-TEST-002"
    )

    assert loaded == manifest


def test_corrupt_manifest_returns_empty_list(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        tmp_path,
    )

    case_dir = (
        tmp_path
        / "CASE-TEST-003"
    )
    case_dir.mkdir(
        parents=True
    )

    manifest_path = (
        case_dir
        / "evidence_manifest.json"
    )

    manifest_path.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    assert (
        load_manifest("CASE-TEST-003")
        == []
    )


def test_add_evidence_copies_and_verifies_file(
    tmp_path,
    monkeypatch,
):
    cases_dir = tmp_path / "cases"
    source_dir = tmp_path / "source"

    cases_dir.mkdir()
    source_dir.mkdir()

    case_id = "CASE-TEST-004"

    evidence_dir = (
        cases_dir
        / case_id
        / "evidence"
    )
    evidence_dir.mkdir(
        parents=True
    )

    source = (
        source_dir
        / "auth.log"
    )

    source.write_text(
        "Oct  6 22:15:01 server sshd[100]: "
        "Failed password for admin from 192.0.2.50\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        cases_dir,
    )

    result = add_evidence(
        case_id,
        str(source),
    )

    destination = (
        evidence_dir
        / "auth.log"
    )

    assert destination.exists()
    assert destination.read_bytes() == source.read_bytes()

    assert result["filename"] == "auth.log"
    assert result["stored_filename"] == "auth.log"
    assert len(result["sha256"]) == 64
    assert result["integrity"] == "VERIFIED"

    manifest = load_manifest(case_id)

    assert len(manifest) == 1
    assert manifest[0]["sha256"] == result["sha256"]
    assert manifest[0]["integrity"] == "VERIFIED"


def test_add_evidence_missing_source_raises(
    tmp_path,
    monkeypatch,
):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        cases_dir,
    )

    missing = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        add_evidence(
            "CASE-TEST-005",
            str(missing),
        )


def test_add_evidence_requires_existing_case(
    tmp_path,
    monkeypatch,
):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        cases_dir,
    )

    source = tmp_path / "auth.log"
    source.write_text(
        "test evidence\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        add_evidence(
            "CASE-DOES-NOT-EXIST",
            str(source),
        )


def test_add_evidence_rejects_duplicate_filename(
    tmp_path,
    monkeypatch,
):
    cases_dir = tmp_path / "cases"
    case_id = "CASE-TEST-006"

    evidence_dir = (
        cases_dir
        / case_id
        / "evidence"
    )
    evidence_dir.mkdir(
        parents=True
    )

    source = tmp_path / "auth.log"
    source.write_text(
        "original\n",
        encoding="utf-8",
    )

    existing = (
        evidence_dir
        / "auth.log"
    )
    existing.write_text(
        "already stored\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        cases_dir,
    )

    with pytest.raises(FileExistsError):
        add_evidence(
            case_id,
            str(source),
        )


def test_add_evidence_preserves_source_metadata(
    tmp_path,
    monkeypatch,
):
    cases_dir = tmp_path / "cases"
    case_id = "CASE-TEST-007"

    evidence_dir = (
        cases_dir
        / case_id
        / "evidence"
    )
    evidence_dir.mkdir(
        parents=True
    )

    source = tmp_path / "sudo.log"
    source.write_text(
        "sudo: admin : COMMAND=/bin/id\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        cases_dir,
    )

    result = add_evidence(
        case_id,
        str(source),
    )

    assert result["filename"] == "sudo.log"
    assert result["original_path"] == str(
        source.resolve()
    )
    assert result["size_bytes"] == source.stat().st_size
    assert result["acquired_at"]


def test_evidence_directory_and_manifest_paths(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        tmp_path,
    )

    evidence_path = get_evidence_directory(
        "CASE-TEST-008"
    )

    manifest_path = get_manifest_path(
        "CASE-TEST-008"
    )

    assert evidence_path == (
        tmp_path
        / "CASE-TEST-008"
        / "evidence"
    )

    assert manifest_path == (
        tmp_path
        / "CASE-TEST-008"
        / "evidence_manifest.json"
    )


def test_manifest_is_valid_json(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        collector,
        "CASES_DIR",
        tmp_path,
    )

    case_dir = (
        tmp_path
        / "CASE-TEST-009"
    )
    case_dir.mkdir(
        parents=True
    )

    manifest = [
        {
            "filename": "syslog",
            "sha256": "b" * 64,
            "integrity": "VERIFIED",
        }
    ]

    save_manifest(
        "CASE-TEST-009",
        manifest,
    )

    raw = (
        case_dir
        / "evidence_manifest.json"
    ).read_text(
        encoding="utf-8"
    )

    assert json.loads(raw) == manifest
