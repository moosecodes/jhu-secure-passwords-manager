# 🔐 Secure Password Manager

A Python-based password manager that demonstrates secure password **generation, storage, retrieval, and management** using modern cryptography.
This project was developed as an advanced case study to practice **security best practices, encryption, and authentication** in Python.

---

## ✨ Features

* **Authentication System**

  * Master password required to unlock vault.
  * Secure credential verification using **Argon2id KDF**.

* **Strong Password Generation**

  * Flexible generator supporting uppercase, lowercase, digits, and symbols.
  * Excludes ambiguous characters for usability.
  * Users can input their own passwords or auto-generate secure ones.

* **Vault Management (CRUD)**

  * Add, retrieve, update, rotate, and delete entries.
  * Password history tracked in entries.
  * CLI and optional **Flask-based web interface**.

* **Encryption & Storage**

  * Vault encrypted with **AES-GCM (256-bit)**.
  * Each vault includes random salt + nonce.
  * Atomic file save with backup protection.

* **Logging & Security**

  * Security actions logged via rotating log file (`logs/security.log`).
  * Tracks vault access, adds, updates, and deletes.

---

## 🏗 Project Structure

```
password_manager/
├── cli.py                 # Command-line interface
├── webapp.py              # Flask web interface (optional)
├── vault_service.py       # High-level vault CRUD service (production)
├── storage.py             # Vault persistence layer
├── crypto.py              # AES-GCM + Argon2id encryption
├── kdf.py                 # Argon2id key derivation
├── models.py              # Dataclasses: Vault, Entry, Policy
├── passwords.py           # Secure password generator
├── seed_vault.py          # Build sample vault for testing/demo
├── inspect_vault.py       # Utility: inspect vault contents
├── tests/                 # Unit test suite (pytest)
└── static/                # Assets for webapp
```

---

## 🚀 Getting Started

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Seed a demo vault

```bash
python -m password_manager.seed_vault
```

This creates `data/test.vault.json` with sample entries.

### 3. Run the CLI

```bash
python -m password_manager.cli
```

### 4. Run the Web Interface (optional)

```bash
flask --app password_manager.webapp run
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## 🧪 Running Tests

Run the full suite with:

```bash
pytest password_manager/tests -v
```

Covers encryption, storage, password generation, models, and manager logic.

---

## 📚 Implementation Notes

* The project contains **two parallel stacks** of crypto/storage logic:

  1. **Prototype:** `CryptoManager + FileStorageManager + PasswordManagerCore` (PBKDF2 + Fernet).
  2. **Production:** `VaultService + crypto.py + storage.py` (Argon2id + AES-GCM).

* The **VaultService stack** is the recommended final design, leveraging stronger KDF + cipher choices and full logging.

* The **PasswordManagerCore stack** is preserved as a **learning prototype** to demonstrate an alternative implementation.

---

## 🔒 Security Highlights

* Argon2id key derivation (memory-hard, resistant to GPU/ASIC attacks).
* AES-GCM authenticated encryption.
* Salt and nonce are regenerated per vault.
* Rotating logs for auditability.
* Secure random password generation with character diversity.

---

## 📄 License

MIT License — free to use, modify, and learn from.

