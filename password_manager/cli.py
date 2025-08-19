# cli.py
from pathlib import Path
import argparse, getpass, sys
from .vault_service import VaultService

VAULT_PATH = Path("data/test.vault.json")

def ask(prompt: str, default: str | None = None) -> str:
    s = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return s or (default or "")

def yesno(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    s = input(f"{prompt} ({d}): ").strip().lower()
    return (s == "" and default) or s in {"y", "yes"}

def choose_mode() -> str:
    print("Welcome to Secure Password Manager")
    print("1) Continue in CLI")
    print("2) Switch to Web interface")
    choice = input("Select: ").strip()
    if choice == "2":
        print("Web interface not implemented yet. Exiting. (Choose CLI to continue.)")
        sys.exit(0)
    return "cli"

def list_entries(svc: VaultService):
    es = svc.list_entries()
    if not es:
        print("No entries.")
        return
    for i, e in enumerate(es, 1):
        print(f"{i}. {e['site']} | {e['username']} | id={e['id']} | tags={','.join(e.get('tags', []))}")

def pick_entry(svc: VaultService):
    es = svc.list_entries()
    if not es:
        print("No entries.")
        return None
    list_entries(svc)
    try:
        idx = int(ask("Select #")) - 1
        return es[idx]
    except Exception:
        print("Invalid selection.")
        return None

def add_entry(svc: VaultService):
    site = ask("Site (e.g., github.com)")
    user = ask("Username/Email")
    if yesno("Auto-generate password?", True):
        length = int(ask("Length", "16"))
        entry = svc.add_entry(site, user, password=None, tags=[], url=None, notes=None)
        # rotate immediately to desired length
        svc.rotate_password(entry["id"], length=length)
        print("Added with generated password.")
    else:
        pw = getpass.getpass("Password: ")
        svc.add_entry(site, user, password=pw)
        print("Added.")

def retrieve_password(svc: VaultService):
    e = pick_entry(svc)
    if not e: return
    print(f"\n[{e['site']}] {e['username']}")
    print(f"PASSWORD: {e['password']}\n")

def update_entry(svc: VaultService):
    e = pick_entry(svc)
    if not e: return
    site = ask("New site", e["site"]) or e["site"]
    user = ask("New username", e["username"]) or e["username"]
    url  = ask("New URL", e.get("url") or "") or None
    notes= ask("New notes", e.get("notes") or "") or None
    tags = ask("Comma tags", ",".join(e.get("tags", [])))
    tags_list = [t.strip() for t in tags.split(",")] if tags else []
    if yesno("Change password?", False):
        if yesno("Auto-generate?", True):
            length = int(ask("Length", "16"))
            svc.rotate_password(e["id"], length=length)
        else:
            pw = getpass.getpass("New password: ")
            svc.update_entry(e["id"], password=pw, site=site, username=user, url=url, notes=notes, tags=tags_list)
    else:
        svc.update_entry(e["id"], site=site, username=user, url=url, notes=notes, tags=tags_list)
    print("Updated.")

def delete_entry(svc: VaultService):
    e = pick_entry(svc)
    if not e: return
    if yesno(f"Delete {e['site']} / {e['username']}?", False):
        svc.delete_entry(e["id"])
        print("Deleted.")

def search_entries(svc: VaultService):
    q = ask("Query (site/username, blank to skip)")
    t = ask("Tag filter (blank to skip)")
    es = svc.list_entries(query=q or None, tag=t or None)
    if not es:
        print("No matches.")
        return
    for i, e in enumerate(es, 1):
        print(f"{i}. {e['site']} | {e['username']} | id={e['id']} | tags={','.join(e.get('tags', []))}")

def menu_loop(svc: VaultService):
    actions = {
        "1": ("List entries", lambda: list_entries(svc)),
        "2": ("Add entry", lambda: add_entry(svc)),
        "3": ("Retrieve password", lambda: retrieve_password(svc)),
        "4": ("Update entry", lambda: update_entry(svc)),
        "5": ("Rotate password", lambda: (lambda e=pick_entry(svc): e and (svc.rotate_password(e['id']) or print('Rotated.')))()),
        "6": ("Delete entry", lambda: delete_entry(svc)),
        "7": ("Search", lambda: search_entries(svc)),
        "0": ("Exit", None),
    }
    while True:
        print("\n-- MENU --")
        for k,(name,_) in actions.items():
            print(f"{k}) {name}")
        choice = input("Select: ").strip()
        if choice == "0": break
        act = actions.get(choice)
        if not act:
            print("Invalid choice.")
            continue
        try:
            act[1]()
        except Exception as e:
            print("Error:", e)

def main():
    choose_mode()  # exits if Web selected
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(VAULT_PATH))
    ap.add_argument("--master")
    args = ap.parse_args()

    master = args.master or getpass.getpass("Master password: ")
    svc = VaultService(Path(args.file), master)
    svc.load()
    menu_loop(svc)
    print("Goodbye.")

if __name__ == "__main__":
    main()
