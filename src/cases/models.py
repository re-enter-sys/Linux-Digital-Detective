from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Case:
    case_id: str
    title: str
    description: str
    status: str
    severity: str
    created_at: str
    updated_at: str
    investigator: str = "Linux Digital Detective"
    closed_at: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    @classmethod
    def create(
        cls,
        case_id: str,
        title: str,
        description: str = "",
        severity: str = "UNKNOWN",
    ):
        now = datetime.now(timezone.utc).isoformat()

        return cls(
            case_id=case_id,
            title=title,
            description=description,
            status="NEW",
            severity=severity.upper(),
            created_at=now,
            updated_at=now,
        )
