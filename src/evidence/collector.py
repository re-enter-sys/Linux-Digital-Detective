import json
import shutil
from pathlib import Path

from .hashing import calculate_sha256
from .metadata import collect_metadata


BASE_DIR = Path(__file__).resolve().parents[2]
CASES_DIR = BASE_DIR / "data" / "cases"


def get_evidence_directory(case_id: str) -> Path:
    return CASES_DIR / case_id / "evidence"


def get_manifest_path(case_id: str) -> Path:
    return CASES_DIR / case_id / "evidence_manifest.json"


def load_manifest(case_id: str) -> list:
    manifest_path = get_manifest_path(case_id)

    if not manifest_path.exists():
        return []

    try:
        with manifest_path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return []


def save_manifest(case_id: str, manifest: list):
    manifest_path = get_manifest_path(case_id)

    with manifest_path.open("w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=4)


def add_evidence(case_id: str, source_file: str) -> dict:
    source = Path(source_file)

    if not source.is_file():
        raise FileNotFoundError(
            f"Evidence source does not exist: {source_file}"
        )

    evidence_dir = get_evidence_directory(case_id)

    if not evidence_dir.exists():
        raise ValueError(
            f"Case does not exist or has no evidence directory: {case_id}"
        )

    metadata = collect_metadata(source)

    original_hash = calculate_sha256(source)

    destination = evidence_dir / source.name

    # Avoid accidentally overwriting existing evidence.
    if destination.exists():
        raise FileExistsError(
            f"Evidence already exists in case: {destination.name}"
        )

    shutil.copy2(source, destination)

    copied_hash = calculate_sha256(destination)

    if original_hash != copied_hash:
        destination.unlink(missing_ok=True)

        raise RuntimeError(
            "Evidence integrity verification failed. "
            "Copied file hash does not match original."
        )

    evidence = {
        **metadata,
        "stored_filename": destination.name,
        "sha256": original_hash,
        "integrity": "VERIFIED",
    }

    manifest = load_manifest(case_id)
    manifest.append(evidence)
    save_manifest(case_id, manifest)

    return evidence
