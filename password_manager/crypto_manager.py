'''CrptoManager Class'''
import os
import base64
from typing import Dict, Any
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


class CryptoManager:
    """Handles all encryption/decryption operations for the password manager."""

    def __init__(self, master_password: str):
        self.master_password = master_password
        self.salt = None
        self.key = None
        self.fernet = None

    def _generate_salt(self) -> bytes:
        """Generate a random salt for key derivation."""
        return os.urandom(32)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # NIST recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def initialize_encryption(self, salt: bytes = None) -> None:
        """Initialize encryption with master password."""
        if salt is None:
            self.salt = self._generate_salt()
        else:
            self.salt = salt

        self.key = self._derive_key(self.master_password, self.salt)
        self.fernet = Fernet(self.key)

    def encrypt_data(self, data: Dict[str, Any]) -> bytes:
        """Encrypt password database."""
        if self.fernet is None:
            raise ValueError("Encryption not initialized")

        json_data = json.dumps(data, indent=2)
        encrypted_data = self.fernet.encrypt(json_data.encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Decrypt password database."""
        if self.fernet is None:
            raise ValueError("Encryption not initialized")

        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            raise ValueError("Failed to decrypt data - invalid master password?") from e

    def get_salt(self) -> bytes:
        """Get the current salt for storage."""
        if self.salt is None:
            raise ValueError("Salt not generated - call initialize_encryption first")
        return self.salt
