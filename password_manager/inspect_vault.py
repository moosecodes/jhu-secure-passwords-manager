from pathlib import Path
import json, argparse, getpass
from cryptography.exceptions import InvalidTag
from .storage import load_vault
from .crypto import decrypt_vault

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="data/test.vault.json")
    ap.add_argument("--master")
    args = ap.parse_args()

    master = args.master or getpass.getpass("Master password: ")
    try:
        enc = load_vault(Path(args.file))
        dec = decrypt_vault(enc, master)
    except FileNotFoundError:
        print("Vault file not found.")
        return
    except InvalidTag:
        print("Decryption failed (wrong password or file corrupted).")
        return
    except Exception as e:
        print(f"Error: {e}")
        return

    # pretty summary
    print(f"vault_id: {dec.get('vault_id')}")
    print(f"created_at: {dec.get('created_at')}")
    entries = dec.get("entries", [])
    print(f"entries: {len(entries)}")
    for i, e in enumerate(entries, 1):
        print(f"{i}. {e.get('site')}  user={e.get('username')}  tags={','.join(e.get('tags', []))}")

if __name__ == "__main__":
    main()
