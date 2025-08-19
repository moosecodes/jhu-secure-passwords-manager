'''File storage manager'''
import json
import os
import base64
from typing import Dict, Any, Optional
from crypto_manager import CryptoManager

class FileStorageManager:
    """Handles file operations for encrypted password database."""

    def __init__(self, file_path: str = "passwords.json"):
        self.file_path = file_path
        self.crypto_manager: Optional[CryptoManager] = None

    def set_crypto_manager(self, crypto_manager: CryptoManager) -> None:
        """Set the crypto manager for encryption/decryption operations."""
        self.crypto_manager = crypto_manager

    def _create_file_structure(self, encrypted_data: bytes, salt: bytes) -> Dict[str, str]:
        """Create the file structure with metadata and encrypted data."""
        return {
            "version": "1.0",
            "salt": base64.b64encode(salt).decode('utf-8'),
            "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
            "metadata": {
                "created": "password_manager_v1.0",
                "encryption": "PBKDF2-SHA256 + AES-256-GCM"
            }
        }

    def save_passwords(self, password_data: Dict[str, Any]) -> bool:
        """Save encrypted password data to file."""
        if self.crypto_manager is None:
            raise ValueError("CryptoManager not set")

        try:
            # Encrypt the password data
            encrypted_data = self.crypto_manager.encrypt_data(password_data)
            salt = self.crypto_manager.get_salt()

            # Create file structure
            file_content = self._create_file_structure(encrypted_data, salt)

            # Write to file
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(file_content, f, indent=2)

            return True

        except Exception as e:
            print(f"Error saving passwords: {e}")
            return False

    def load_passwords(self) -> Optional[Dict[str, Any]]:
        """Load and decrypt password data from file."""
        if self.crypto_manager is None:
            raise ValueError("CryptoManager not set")

        if not os.path.exists(self.file_path):
            return None

        try:
            # Read file
            with open(self.file_path, 'r', encoding='utf-8') as f:
                file_content = json.load(f)

            # Extract salt and encrypted data
            salt = base64.b64decode(file_content['salt'].encode('utf-8'))
            encrypted_data = base64.b64decode(file_content['encrypted_data'].encode('utf-8'))

            # Reinitialize crypto with stored salt
            self.crypto_manager.initialize_encryption(salt=salt)

            # Decrypt and return data
            return self.crypto_manager.decrypt_data(encrypted_data)

        except json.JSONDecodeError:
            raise ValueError("Corrupted password file - invalid JSON")
        except KeyError as e:
            raise ValueError(f"Invalid file format - missing key: {e}")
        except Exception as e:
            raise ValueError(f"Failed to load passwords: {e}")

    def file_exists(self) -> bool:
        """Check if password file exists."""
        return os.path.exists(self.file_path)

    def create_default_data(self) -> Dict[str, Any]:
        """Create default password data for testing."""
        return {
            "users": {
                "john_doe": {
                    "passwords": {
                        "gmail": {
                            "username": "john.doe@gmail.com",
                            "password": "SecurePass123!@#",
                            "url": "https://gmail.com",
                            "notes": "Personal email"
                        },
                        "github": {
                            "username": "johndoe_dev",
                            "password": "GitSecure456$%^",
                            "url": "https://github.com",
                            "notes": "Development account"
                        },
                        "banking": {
                            "username": "jdoe_bank",
                            "password": "BankSecure789&*()",
                            "url": "https://mybank.com",
                            "notes": "Main checking account"
                        }
                    }
                },
                "jane_smith": {
                    "passwords": {
                        "work_email": {
                            "username": "jane.smith@company.com",
                            "password": "WorkSecure321!",
                            "url": "https://outlook.office.com",
                            "notes": "Corporate email"
                        },
                        "linkedin": {
                            "username": "jane.smith.professional",
                            "password": "LinkedSecure654@",
                            "url": "https://linkedin.com",
                            "notes": "Professional networking"
                        }
                    }
                }
            }
        }

    def initialize_with_defaults(self) -> bool:
        """Initialize file with default data if it doesn't exist."""
        if not self.file_exists():
            default_data = self.create_default_data()
            return self.save_passwords(default_data)
        return True

    def backup_file(self, backup_suffix: str = ".backup") -> bool:
        """Create a backup of the current password file."""
        if not self.file_exists():
            return False

        try:
            backup_path = self.file_path + backup_suffix
            with open(self.file_path, 'r') as src, open(backup_path, 'w') as dst:
                dst.write(src.read())
            return True
        except Exception as e:
            print(f"Backup failed: {e}")
            return False
