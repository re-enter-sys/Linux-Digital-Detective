import hashlib
from pathlib import Path


def calculate_sha256(file_path: str, chunk_size: int = 1024 * 1024) -> str:
    """
    Calculate the SHA-256 hash of a file.

    Files are processed in chunks so large forensic evidence
    does not need to be loaded entirely into memory.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(chunk_size):
            sha256.update(chunk)

    return sha256.hexdigest()


def verify_sha256(file_path: str, expected_hash: str) -> bool:
    actual_hash = calculate_sha256(file_path)

    return actual_hash.lower() == expected_hash.lower()
