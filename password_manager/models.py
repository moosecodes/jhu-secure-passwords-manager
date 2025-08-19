from dataclasses import dataclass, asdict, field
from typing import List, Optional
from uuid import uuid4
from datetime import datetime, timezone

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

@dataclass
class PasswordPolicy:
    length: int = 16
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = True

@dataclass
class EntryHistoryItem:
    password: str
    changed_at: str

@dataclass
class Entry:
    id: str
    site: str
    username: str
    password: str
    url: Optional[str] = None
    notes: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    updated_at: str = field(default_factory=now_iso)
    history: List[EntryHistoryItem] = field(default_factory=list)

    @staticmethod
    def new(site: str, username: str, password: str, **kw) -> "Entry":
        return Entry(id=str(uuid4()), site=site, username=username, password=password, **kw)

@dataclass
class Settings:
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy)

@dataclass
class Vault:
    version: int
    vault_id: str
    created_at: str
    entries: List[Entry]
    settings: Settings

    @staticmethod
    def new() -> "Vault":
        return Vault(
            version=1,
            vault_id=str(uuid4()),
            created_at=now_iso(),
            entries=[],
            settings=Settings()
        )

    def to_dict(self) -> dict:
        return asdict(self)
