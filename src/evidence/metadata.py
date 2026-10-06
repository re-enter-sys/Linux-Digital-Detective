from datetime import datetime, timezone
from pathlib import Path


def collect_metadata(file_path: str) -> dict:
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    stat = path.stat()

    return {
        "filename": path.name,
        "original_path": str(path.resolve()),
        "size_bytes": stat.st_size,
        "acquired_at": datetime.now(timezone.utc).isoformat(),
    }
