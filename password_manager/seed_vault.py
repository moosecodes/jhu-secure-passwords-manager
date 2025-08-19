'''Seed Vault'''
from pathlib import Path
import secrets
import string
from .models import Vault, Entry
from .crypto import encrypt_vault
from .storage import save_vault


AMBIG = set("O0Il1|`'\"{}[]()<>;:,./\\")


def generate_password(
        length=16,
        upper=True,
        lower=True,
        digits=True,
        symbols=True,
        exclude_ambiguous=True) -> str:
    pools = []
    if upper:
        pools.append(string.ascii_uppercase)
    if lower:
        pools.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*-_=+?")
    alphabet = "".join(pools)
    if exclude_ambiguous:
        alphabet = "".join(ch for ch in alphabet if ch not in AMBIG)
    # ensure at least one from each selected pool
    required = []
    if upper:
        required.append(secrets.choice(
            "".join(ch for ch in string.ascii_uppercase if ch not in AMBIG)))
    if lower:
        required.append(secrets.choice(
            "".join(ch for ch in string.ascii_lowercase if ch not in AMBIG)))
    if digits:
        required.append(secrets.choice(
            "".join(ch for ch in string.digits if ch not in AMBIG)))
    if symbols:
        required.append(secrets.choice(
            "".join(ch for ch in "!@#$%^&*-_=+?" if ch not in AMBIG)))
    pw = required + [secrets.choice(alphabet)
                     for _ in range(max(0, length - len(required)))]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def build_seed_vault():
    v = Vault.new()
    # three demo entries
    v.entries.append(Entry.new(
        site="github.com", username="moose",
        password=generate_password(), url="https://github.com/login",
        notes="2FA enabled", tags=["dev", "work"]
    ))
    v.entries.append(Entry.new(
        site="gmail.com", username="moose@example.com",
        password="TestOnly-Gmail!2025", url="https://accounts.google.com",
        notes="demo manual password", tags=["email"]
    ))
    v.entries.append(Entry.new(
        site="MyBank", username="moose123",
        password=generate_password(20), url=None,
        notes="Fake bank for testing", tags=["finance"]
    ))
    return v


def main():
    master = "TestOnly!2025"  # test-only master password
    out_path = Path("data/test.vault.json")
    v = build_seed_vault()
    enc = encrypt_vault(v.to_dict(), master)
    save_vault(out_path, enc)
    print(f"Seed vault written → {out_path}")


if __name__ == "__main__":
    main()
