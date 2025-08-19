# cli.py
from pathlib import Path
import argparse, getpass, sys
import subprocess, webbrowser
import time
from .vault_service import VaultService
from .passwords import generate_password
from .models import PasswordPolicy # keep this import for future

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
        print("Starting web interface. Your browser will open shortly.")
        subprocess.Popen(['flask', '--app', 'password_manager.webapp', 'run'])
        time.sleep(2)
        webbrowser.open_new_tab('http://127.0.0.1:5000')
        sys.exit(0)
    return "cli"

def list_entries(svc: VaultService):
    es = svc.list_entries()
    if not es:
        print("No entries.")
        return
    for i, e in enumerate(es, 1):
        print(f"{i}. {e['site']} | {e['username']} | id={e['id']} | tags={','.join(e.get('tags', []))}")

def add_entry(svc: VaultService):
    site = ask("Site", "example.com")
    username = ask("Username")
    url = ask("URL", None)
    notes = ask("Notes", None)
    tags_in = ask("Tags (comma separated)", "")
    tags = [t.strip() for t in tags_in.split(",") if t.strip()]

    if yesno("Generate a password?"):
        length = int(ask("Length", "16"))
        password = generate_password(length)
        print(f"Generated password: {password}")
    else:
        password = getpass.getpass("Password: ")

    try:
        svc.add_entry(site, username, password, url=url, notes=notes, tags=tags)
        print("Entry added.")
    except Exception as e:
        print(f"Error adding entry: {e}")

def pick_entry(svc: VaultService):
    es = svc.list_entries()
    if not es:
        print("No entries.")
        return None
    for i, e in enumerate(es, 1):
        print(f"{i}. {e['site']} | {e['username']} | id={e['id']} | tags={','.join(e.get('tags', []))}")

    try:
        choice = int(input("Select entry number: ").strip())
        if 1 <= choice <= len(es):
            return es[choice - 1]
    except (ValueError, IndexError):
        pass
    print("Invalid choice.")
    return None

def retrieve_password(svc: VaultService):
    e = pick_entry(svc)
    if not e:
        return
    pw = svc.get_entry(entry_id=e['id'])['password']
    print(f"Password for {e['site']}: {pw}")

def update_entry(svc: VaultService):
    e = pick_entry(svc)
    if not e:
        return
    site = ask("Site", e['site'])
    username = ask("Username", e['username'])
    url = ask("URL", e.get('url', '')) or None
    notes = ask("Notes", e.get('notes', '')) or None
    tags_in = ask("Tags (comma separated)", ",".join(e.get('tags', [])))
    tags = [t.strip() for t in tags_in.split(",") if t.strip()]

    svc.update_entry(e['id'], site=site, username=username, url=url, notes=notes, tags=tags)
    print("Entry updated.")

def delete_entry(svc: VaultService):
    e = pick_entry(svc)
    if not e:
        return
    if yesno(f"Are you sure you want to delete '{e['site']}'?"):
        svc.delete_entry(e['id'])
        print("Entry deleted.")

def menu_loop(svc: VaultService):
    actions = {
        "1": ("List entries", lambda: list_entries(svc)),
        "2": ("Add entry", lambda: add_entry(svc)),
        "3": ("Retrieve password", lambda: retrieve_password(svc)),
        "4": ("Update entry", lambda: update_entry(svc)),
        "5": ("Rotate password", lambda: (lambda e=pick_entry(svc): e and (svc.rotate_password(e['id']) or print('Rotated.')))()),
        "6": ("Delete entry", lambda: delete_entry(svc)),
        "8": ("Reset to defaults", lambda: svc.reset_to_defaults()),
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
    choose_mode()
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(VAULT_PATH))
    ap.add_argument("--master")
    args = ap.parse_args()

    master = args.master
    if not master:
        print("Enter master password to unlock vault.")
        master = getpass.getpass("Master password: ")

    try:
        svc = VaultService(Path(args.file), master)
        svc.load()
        menu_loop(svc)
    except Exception as e:
        print("Could not unlock vault:", e)

if __name__ == "__main__":
    main()
