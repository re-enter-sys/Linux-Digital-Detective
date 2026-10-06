import hashlib

import pytest

from src.evidence.hashing import (
    calculate_sha256,
    verify_sha256,
)


def test_calculate_sha256_matches_known_hash(tmp_path):
    evidence = tmp_path / "evidence.log"
    content = b"Linux Digital Detective evidence\n"

    evidence.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()

    assert calculate_sha256(str(evidence)) == expected


def test_calculate_sha256_handles_binary_evidence(tmp_path):
    evidence = tmp_path / "binary.bin"
    content = bytes(range(256)) * 32

    evidence.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()

    assert calculate_sha256(str(evidence)) == expected


def test_calculate_sha256_uses_chunked_reads(tmp_path):
    evidence = tmp_path / "large.log"
    content = b"A" * 5000

    evidence.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()

    assert (
        calculate_sha256(
            str(evidence),
            chunk_size=17,
        )
        == expected
    )


def test_calculate_sha256_missing_file_raises(tmp_path):
    missing = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        calculate_sha256(str(missing))


def test_verify_sha256_accepts_matching_hash(tmp_path):
    evidence = tmp_path / "evidence.log"
    evidence.write_text(
        "authentication failure\n",
        encoding="utf-8",
    )

    expected = calculate_sha256(str(evidence))

    assert verify_sha256(
        str(evidence),
        expected,
    )


def test_verify_sha256_is_case_insensitive(tmp_path):
    evidence = tmp_path / "evidence.log"
    evidence.write_text(
        "SSH accepted password\n",
        encoding="utf-8",
    )

    expected = calculate_sha256(str(evidence))

    assert verify_sha256(
        str(evidence),
        expected.upper(),
    )


def test_verify_sha256_rejects_modified_hash(tmp_path):
    evidence = tmp_path / "evidence.log"
    evidence.write_text(
        "original evidence\n",
        encoding="utf-8",
    )

    assert not verify_sha256(
        str(evidence),
        "0" * 64,
    )


def test_hash_changes_when_evidence_changes(tmp_path):
    evidence = tmp_path / "evidence.log"

    evidence.write_text(
        "event one\n",
        encoding="utf-8",
    )
    first_hash = calculate_sha256(str(evidence))

    evidence.write_text(
        "event two\n",
        encoding="utf-8",
    )
    second_hash = calculate_sha256(str(evidence))

    assert first_hash != second_hash
