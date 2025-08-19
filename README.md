# 🔐 Secure Password Manager

A simple but modern **Secure Password Manager** built in Python for learning and experimentation.  
Developed as part of the **Johns Hopkins Generative AI Certificate program**.

The app supports both a **CLI interface** and a **Web interface (Flask + Bootstrap)**.

---

## ✨ Features
- AES-GCM encryption with keys derived using **Argon2id**
- Encrypted vault stored as JSON
- Auto-generation of strong, policy-compliant passwords
- Full CRUD:
  - Add / Retrieve / Update / Delete entries
  - Rotate password with history tracking
- Multiple interfaces:
  - **CLI menu**
  - **Web GUI** (Bootstrap-styled, responsive)
- Security logging (non-sensitive metadata only)
- Configurable password policy
- Pre-seeded test vault with example entries

---

## 📂 Project Structure
```
.
├── data/                # Encrypted vaults (ignored in git)
├── logs/                # Security logs
├── password_manager/    # Main package
│   ├── cli.py           # CLI interface
│   ├── crypto.py        # AES-GCM encryption / decryption
│   ├── kdf.py           # Argon2id key derivation
│   ├── models.py        # Vault + Entry dataclasses
│   ├── passwords.py     # Password generator
│   ├── seed_vault.py    # Seed a demo vault
│   ├── storage.py       # Read/write vault files
│   ├── vault_service.py # CRUD and business logic
│   ├── webapp.py        # Flask web interface
│   └── static/          # Static assets (favicon, CSS)
├── README.md
├── requirements.in
└── requirements.txt
```

---

## 🛠️ Setup

### 1. Clone & create environment
```bash
git clone https://github.com/<your-username>/jhu-secure-passwords-manager.git
cd jhu-secure-passwords-manager
python -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

Using pip with compiled requirements:
```bash
pip install -r requirements.txt
```

Or regenerate from the top-level list:
```bash
pip install pip-tools
pip-compile --generate-hashes -o requirements.txt requirements.in
pip install -r requirements.txt
```

---

## ▶️ Usage

### Seed a demo vault
```bash
python -m password_manager.seed_vault
```
This creates `data/test.vault.json` with a few sample entries.  
Master password for the demo vault: **`TestOnly!2025`**

### CLI
```bash
python -m password_manager.cli --file data/test.vault.json
# Master password: TestOnly!2025
```

### Web Interface
Set a Flask secret (required for sessions):
```bash
export SPM_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
export FLASK_APP=password_manager.webapp
export FLASK_ENV=development
flask run --reload
```
Then open: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🛡️ Security Notes
- This project is for **educational purposes** only — not production-ready.
- Master password is held in memory only during the session.
- Vault file and logs are excluded from git via `.gitignore`.

---

## 📚 Roadmap
- [ ] Idle timeout & re-auth
- [ ] Clipboard copy with auto-clear (Web)
- [ ] Stronger search & tag filters
- [ ] Desktop GUI with Tkinter / ttkbootstrap
- [ ] Packaging as pip installable tool

---

## 📄 License
MIT License
