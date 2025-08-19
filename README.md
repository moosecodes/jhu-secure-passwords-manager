# Secure Password Manager

A modern, secure password manager with both CLI and web interfaces, built with Python using state-of-the-art cryptography (Argon2id + AES-GCM).

## 🔒 Security Features

- **Modern Cryptography**: Argon2id key derivation + AES-256-GCM encryption
- **Secure Password Generation**: Cryptographically secure random passwords
- **Password History**: Track previous passwords when rotating
- **Security Audit Logging**: Complete audit trail of vault operations
- **Zero-Knowledge Architecture**: Master password never stored

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip or mamba package manager

### Installation

1. **Clone and setup:**
   ```bash
   git clone <your-repo-url>
   cd password_manager
   pip install -r requirements.txt  # or use mamba
   ```

2. **Environment Setup:**
   ```bash
   cp .env.example .env
   # Edit .env with your preferred settings
   ```

3. **Create Test Vault:**
   ```bash
   python -m password_manager.seed_vault
   ```

### Usage

**CLI Interface:**
```bash
python -m password_manager.cli
# Default master password: TestOnly!2025
```

**Web Interface:**
```bash
python -m flask --app password_manager.webapp run
# Navigate to http://localhost:5000
# Master password: TestOnly!2025
```

## 📁 Project Structure

```
password_manager/
├── cli.py                     # CLI interface with menu system
├── webapp.py                  # Flask web interface
├── vault_service.py           # Main service layer
├── crypto.py                  # Modern cryptography (Argon2id/AES-GCM)
├── models.py                  # Data models and structures
├── passwords.py               # Secure password generation
├── storage.py                 # Vault file I/O operations
├── seed_vault.py              # Test data creation
└── static/css/theme.css       # Web UI styling
```

## 🔧 Configuration

Environment variables (set in `.env`):

| Variable | Description | Default |
|----------|-------------|---------|
| `SPM_SECRET` | Flask secret key | `dev-secret-change-me` |
| `VAULT_PATH` | Path to vault file | `data/test.vault.json` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |
| `LOG_DIR` | Log file directory | `logs` |

## 🛡️ Security Notes

- **Test Environment Only**: Default passwords are for development/testing
- **Production Deployment**: Change all default secrets and passwords
- **Vault Files**: Encrypted with industry-standard cryptography
- **Master Password**: Required for all vault operations

## 📋 CLI Menu Options

1. **List entries** - View all password entries
2. **Add entry** - Create new password entry
3. **Retrieve password** - Display specific password
4. **Update entry** - Modify existing entry
5. **Rotate password** - Generate new password for entry
6. **Delete entry** - Remove password entry
7. **Search** - Find entries by site/username/tags

## 🌐 Web Interface Features

- **Responsive Design** - Works on desktop and mobile
- **Search & Filter** - Find entries quickly
- **Bulk Operations** - Manage multiple entries
- **Password Generation** - Built-in secure password generator
- **Dark Theme** - Easy on the eyes

## 🔍 Vault Inspection

Inspect vault contents without full CLI:
```bash
python -m password_manager.inspect_vault --file data/test.vault.json
```

## 🏗️ Development

**Project Goals:**
- Educational exercise for Johns Hopkins AI certification
- Demonstrate secure coding practices
- Modern Python development patterns
- Clean architecture and separation of concerns

**Security First:**
- No hardcoded production secrets
- Proper cryptographic implementations
- Secure defaults and clear test/prod separation

## 📄 License

Educational/Academic Use - Johns Hopkins University Generative AI Certification Project

---

⚠️ **Important**: This is a learning project. For production use, consider established password managers like Bitwarden or 1Password.
