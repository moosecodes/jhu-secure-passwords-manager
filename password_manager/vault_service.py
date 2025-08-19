# vault_service.py
from __future__ import annotations
from pathlib import Path
from typing import Optional, List, Dict, Any
from uuid import uuid4
from datetime import datetime, timezone
import logging
from logging.handlers import RotatingFileHandler

from .storage import save_vault, load_vault
from .crypto import encrypt_vault, decrypt_vault
from .passwords import generate_password
from .seed_vault import build_seed_vault

def now_iso(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def setup_security_logger(log_dir: Path = Path("logs")) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("security")
    if not logger.handlers:
        h = RotatingFileHandler(log_dir / "security.log", maxBytes=512_000, backupCount=3, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        h.setFormatter(fmt); logger.addHandler(h); logger.setLevel(logging.INFO)
    return logger

class VaultService:
    def __init__(self, vault_path: Path, master_password: str):
        self.path = vault_path
        self.master = master_password
        self.logger = setup_security_logger()
        self._vault: Dict[str, Any] = {}
        self._loaded = False

    # ---------- Load / Save ----------
    def load(self) -> None:
        enc = load_vault(self.path)
        self._vault = decrypt_vault(enc, self.master)
        self._loaded = True
        self.logger.info("vault_opened path=%s entries=%d", str(self.path), len(self._vault.get("entries", [])))

    def save(self) -> None:
        assert self._loaded, "vault not loaded"
        enc = encrypt_vault(self._vault, self.master)
        save_vault(self.path, enc)
        self.logger.info("vault_saved path=%s entries=%d", str(self.path), len(self._vault.get("entries", [])))

    # ---------- Queries ----------
    def list_entries(self, query: Optional[str] = None, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        es = list(self._vault.get("entries", []))
        if query:
            q = query.lower()
            es = [e for e in es if q in e.get("site","").lower() or q in e.get("username","").lower()]
        if tag:
            es = [e for e in es if tag in e.get("tags", [])]
        return es

    def get_entry(self, entry_id: Optional[str] = None, site: Optional[str] = None, username: Optional[str] = None) -> Optional[Dict[str, Any]]:
        for e in self._vault.get("entries", []):
            if entry_id and e["id"] == entry_id: return e
            if site and username and e.get("site")==site and e.get("username")==username: return e
        return None

    # ---------- CRUD ----------
    def add_entry(self, site: str, username: str, password: Optional[str] = None, **kw) -> Dict[str, Any]:
        pw = password or generate_password()
        entry = {
            "id": str(uuid4()),
            "site": site,
            "username": username,
            "password": pw,                 # DO NOT LOG THIS
            "url": kw.get("url"),
            "notes": kw.get("notes"),
            "tags": kw.get("tags", []),
            "updated_at": now_iso(),
            "history": [],
        }
        self._vault.setdefault("entries", []).append(entry)
        self.logger.info("entry_added site=%s user=%s id=%s", site, username, entry["id"])
        self.save()
        return entry

    def update_entry(self, entry_id: str, **changes) -> Optional[Dict[str, Any]]:
        e = self.get_entry(entry_id=entry_id)
        if not e: return None
        # handle password rotation
        if "password" in changes and changes["password"]:
            old = {"password": e["password"], "changed_at": now_iso()}
            e.setdefault("history", []).insert(0, old)
            e["password"] = changes["password"]
        for k in ["site","username","url","notes","tags"]:
            if k in changes and changes[k] is not None:
                e[k] = changes[k]
        e["updated_at"] = now_iso()
        self.logger.info("entry_updated id=%s fields=%s", entry_id, ",".join(changes.keys()))
        self.save()
        return e

    def rotate_password(self, entry_id: str, length: int = 16) -> Optional[str]:
        new_pw = generate_password(length=length)
        e = self.update_entry(entry_id, password=new_pw)
        if not e: return None
        self.logger.info("password_rotated id=%s", entry_id)
        return new_pw

    def delete_entry(self, entry_id: str) -> bool:
        es = self._vault.get("entries", [])
        for i, e in enumerate(es):
            if e["id"] == entry_id:
                es.pop(i)
                self.logger.info("entry_deleted id=%s site=%s user=%s", entry_id, e.get("site"), e.get("username"))
                self.save()
                return True
        return False

    def reset_to_defaults(self) -> None:
        """Reset vault to default test data."""
        self._vault = build_seed_vault().to_dict()
        self.save()
        self.logger.info("vault_reset_to_defaults")