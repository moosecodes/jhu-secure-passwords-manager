# 🔐 Secure Password Manager

A Python password manager with **Argon2id key derivation**, **AES-GCM encryption**, and both **CLI** and **Flask web interfaces**.
Built to demonstrate secure password handling and modern cryptography in a production-ready way.

---

## ✨ Features

- **Authentication**
  - Master password unlocks vault.
  - Argon2id key derivation (memory-hard, resistant to GPU/ASIC attacks).

- **Strong Password Generator**
  - Configurable: uppercase, lowercase, digits, symbols.
  - Excludes ambiguous characters for usability.
  - CLI option to enter custom or auto-generate passwords.

- **Vault Management (CRUD)**
  - Add, retrieve, update, rotate, and delete entries.
  - Password history retained.
  - CLI and optional Flask webapp.

- **Encryption & Storage**
  - AES-GCM 256-bit encryption with per-vault salt + nonce.
  - Atomic JSON file save with backup safety.
  - JSON schema (`vault_schema.json`) defines vault structure.

- **Security Logging**
  - Rotating security log (`logs/security.log`) records vault access, adds, updates, deletes.

---

## 📂 Project Structure

```
password_manager/
├── cli.py                 # Command-line interface
├── webapp.py              # Flask web interface
├── vault_service.py       # Vault CRUD service (final implementation)
├── storage.py             # File persistence
├── crypto.py              # AES-GCM + Argon2id crypto
├── kdf.py                 # Argon2id key derivation
├── models.py              # Dataclasses: Vault, Entry, Policy
├── passwords.py           # Secure password generator
├── seed_vault.py          # Create demo vault
├── inspect_vault.py       # Inspect vault contents
├── tests/                 # Pytest suite
└── static/                # Assets for Flask webapp
```

---

## 🚀 Usage

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Seed a demo vault
```bash
python -m password_manager.seed_vault
```
Creates `data/test.vault.json` with sample entries.

### 3. Run the CLI and select interface
```bash
python -m password_manager.cli
```

### 4. or just Run the Web Interface (optional)
```bash
python -m password_manager.webapp
```
Then open [http://127.0.0.1:5050](http://127.0.0.1:5050).

---

## 🧪 Tests

Run the full test suite:
```bash
pytest password_manager/tests -v
```

---

## 🔒 Security Highlights

- Argon2id key derivation (preferred modern KDF).
- AES-GCM authenticated encryption (confidentiality + integrity).
- Random salt & nonce for each vault.
- Secure random password generator.
- Rotating audit logs.

---

## 📄 License

MIT License — free to use, modify, and learn from.
