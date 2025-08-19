'''Storage.py'''
import json
from pathlib import Path
from password_manager.crypto import encrypt_vault, decrypt_vault

def save_vault(path: Path, vault_obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(vault_obj, indent=2), encoding="utf-8")
    tmp.replace(path)

def load_vault(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
