"""Test suite for crypto.py module - AES-GCM encryption with Argon2 KDF."""

import pytest
import os
import tempfile
from pathlib import Path

# Import the modules to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from password_manager.crypto import encrypt_vault, decrypt_vault
from password_manager.kdf import Argon2Params, DEFAULT_PARAMS


class TestCrypto:
    """Test suite for crypto.py encryption/decryption functions."""

    def setup_method(self):
        """Set up test data before each test."""
        self.test_password = "TestPassword123!"
        self.test_vault_data = {
            "version": 1,
            "vault_id": "test-vault-123",
            "created_at": "2025-01-01T00:00:00+00:00",
            "entries": [
                {
                    "id": "entry-1",
                    "site": "github.com",
                    "username": "testuser",
                    "password": "secret123",
                    "tags": ["dev", "work"]
                }
            ],
            "settings": {
                "password_policy": {
                    "length": 16,
                    "uppercase": True,
                    "lowercase": True,
                    "digits": True,
                    "symbols": True
                }
            }
        }

    def test_encrypt_decrypt_roundtrip(self):
        """Test basic encrypt/decrypt roundtrip."""
        # Encrypt the vault data
        encrypted_vault = encrypt_vault(self.test_vault_data, self.test_password)

        # Verify encrypted vault structure
        assert "version" in encrypted_vault
        assert "kdf" in encrypted_vault
        assert "kdf_params" in encrypted_vault
        assert "cipher" in encrypted_vault
        assert "nonce" in encrypted_vault
        assert "ciphertext" in encrypted_vault

        assert encrypted_vault["version"] == 1
        assert encrypted_vault["kdf"] == "argon2id"
        assert encrypted_vault["cipher"] == "aes-gcm"

        # Decrypt and verify
        decrypted_vault = decrypt_vault(encrypted_vault, self.test_password)
        assert decrypted_vault == self.test_vault_data
        print("✓ Basic encrypt/decrypt roundtrip works")

    def test_different_passwords_different_ciphertext(self):
        """Test that different passwords produce different ciphertext."""
        encrypted1 = encrypt_vault(self.test_vault_data, "password1")
        encrypted2 = encrypt_vault(self.test_vault_data, "password2")

        # Same data, different passwords should produce different ciphertext
        assert encrypted1["ciphertext"] != encrypted2["ciphertext"]
        assert encrypted1["kdf_params"]["salt"] != encrypted2["kdf_params"]["salt"]
        print("✓ Different passwords produce different ciphertext")

    def test_same_password_different_salt_nonce(self):
        """Test that same password produces different salt and nonce each time."""
        encrypted1 = encrypt_vault(self.test_vault_data, self.test_password)
        encrypted2 = encrypt_vault(self.test_vault_data, self.test_password)

        # Same password should still produce different salt and nonce
        assert encrypted1["kdf_params"]["salt"] != encrypted2["kdf_params"]["salt"]
        assert encrypted1["nonce"] != encrypted2["nonce"]
        assert encrypted1["ciphertext"] != encrypted2["ciphertext"]
        print("✓ Same password produces different salt and nonce")

    def test_wrong_password_decryption_fails(self):
        """Test that wrong password fails decryption."""
        encrypted_vault = encrypt_vault(self.test_vault_data, "correct_password")

        with pytest.raises(Exception):  # Should raise cryptography exception
            decrypt_vault(encrypted_vault, "wrong_password")
        print("✓ Wrong password fails decryption")

    def test_custom_kdf_params(self):
        """Test encryption with custom KDF parameters."""
        custom_params = Argon2Params(
            time_cost=2,
            memory_cost=32768,  # 32 MB
            parallelism=1,
            hash_len=32
        )

        encrypted_vault = encrypt_vault(self.test_vault_data, self.test_password, custom_params)

        # Verify custom parameters are stored
        assert encrypted_vault["kdf_params"]["t"] == 2
        assert encrypted_vault["kdf_params"]["m"] == 32768
        assert encrypted_vault["kdf_params"]["p"] == 1
        assert encrypted_vault["kdf_params"]["hash_len"] == 32

        # Verify decryption still works
        decrypted_vault = decrypt_vault(encrypted_vault, self.test_password)
        assert decrypted_vault == self.test_vault_data
        print("✓ Custom KDF parameters work")

    def test_empty_data_encryption(self):
        """Test encryption of empty/minimal data."""
        empty_data = {"entries": []}

        encrypted_vault = encrypt_vault(empty_data, self.test_password)
        decrypted_vault = decrypt_vault(encrypted_vault, self.test_password)

        assert decrypted_vault == empty_data
        print("✓ Empty data encryption works")

    def test_large_data_encryption(self):
        """Test encryption of larger datasets."""
        large_data = {
            "entries": [
                {
                    "id": f"entry-{i}",
                    "site": f"site{i}.com",
                    "username": f"user{i}",
                    "password": f"password{i}" * 10,  # Longer passwords
                    "notes": f"This is a long note for entry {i} " * 20,
                    "tags": [f"tag{j}" for j in range(5)]
                }
                for i in range(100)  # 100 entries
            ]
        }

        encrypted_vault = encrypt_vault(large_data, self.test_password)
        decrypted_vault = decrypt_vault(encrypted_vault, self.test_password)

        assert decrypted_vault == large_data
        assert len(decrypted_vault["entries"]) == 100
        print("✓ Large data encryption works")

    def test_unicode_data_encryption(self):
        """Test encryption with Unicode characters."""
        unicode_data = {
            "entries": [
                {
                    "id": "unicode-test",
                    "site": "测试网站.com",
                    "username": "пользователь",
                    "password": "パスワード123",
                    "notes": "Tëst nøtës with émojis 🔐🛡️",
                    "tags": ["🏷️", "тест", "テスト"]
                }
            ]
        }

        encrypted_vault = encrypt_vault(unicode_data, self.test_password)
        decrypted_vault = decrypt_vault(encrypted_vault, self.test_password)

        assert decrypted_vault == unicode_data
        print("✓ Unicode data encryption works")

    def test_corrupted_ciphertext_fails(self):
        """Test that corrupted ciphertext fails decryption."""
        encrypted_vault = encrypt_vault(self.test_vault_data, self.test_password)

        # Corrupt the ciphertext
        original_ct = encrypted_vault["ciphertext"]
        encrypted_vault["ciphertext"] = original_ct[:-4] + "XXXX"  # Corrupt last 4 chars

        with pytest.raises(Exception):
            decrypt_vault(encrypted_vault, self.test_password)
        print("✓ Corrupted ciphertext fails decryption")

    def test_corrupted_nonce_fails(self):
        """Test that corrupted nonce fails decryption."""
        encrypted_vault = encrypt_vault(self.test_vault_data, self.test_password)

        # Corrupt the nonce
        encrypted_vault["nonce"] = "INVALID_NONCE_DATA"

        with pytest.raises(Exception):
            decrypt_vault(encrypted_vault, self.test_password)
        print("✓ Corrupted nonce fails decryption")

    def test_unsupported_vault_format_fails(self):
        """Test that unsupported vault formats fail."""
        bad_vault = {
            "kdf": "pbkdf2",  # Unsupported
            "cipher": "aes-gcm",
            "kdf_params": {},
            "nonce": "dGVzdA==",
            "ciphertext": "dGVzdA=="
        }

        with pytest.raises(ValueError, match="Unsupported vault format"):
            decrypt_vault(bad_vault, self.test_password)

        bad_vault2 = {
            "kdf": "argon2id",
            "cipher": "aes-cbc",  # Unsupported
            "kdf_params": {},
            "nonce": "dGVzdA==",
            "ciphertext": "dGVzdA=="
        }

        with pytest.raises(ValueError, match="Unsupported vault format"):
            decrypt_vault(bad_vault2, self.test_password)
        print("✓ Unsupported vault formats fail correctly")

    def test_base64_encoding_integrity(self):
        """Test that base64 encoding/decoding maintains integrity."""
        encrypted_vault = encrypt_vault(self.test_vault_data, self.test_password)

        # All these fields should be valid base64
        import base64

        # Should not raise exceptions
        base64.b64decode(encrypted_vault["kdf_params"]["salt"])
        base64.b64decode(encrypted_vault["nonce"])
        base64.b64decode(encrypted_vault["ciphertext"])

        # Verify they decode to the expected lengths
        salt = base64.b64decode(encrypted_vault["kdf_params"]["salt"])
        nonce = base64.b64decode(encrypted_vault["nonce"])

        assert len(salt) >= 16  # Minimum salt length
        assert len(nonce) == 12  # AES-GCM nonce length
        print("✓ Base64 encoding integrity maintained")

    def test_deterministic_kdf_with_same_salt(self):
        """Test that KDF produces same key with same salt."""
        from password_manager.kdf import derive_key

        encrypted_vault = encrypt_vault(self.test_vault_data, self.test_password)

        # Extract parameters
        import base64
        salt = base64.b64decode(encrypted_vault["kdf_params"]["salt"])
        params = Argon2Params(
            time_cost=encrypted_vault["kdf_params"]["t"],
            memory_cost=encrypted_vault["kdf_params"]["m"],
            parallelism=encrypted_vault["kdf_params"]["p"],
            hash_len=encrypted_vault["kdf_params"]["hash_len"]
        )

        # Derive key twice with same parameters
        key1 = derive_key(self.test_password, salt, params)
        key2 = derive_key(self.test_password, salt, params)

        assert key1 == key2
        print("✓ KDF is deterministic with same salt")


def run_all_tests():
    """Run all crypto tests manually."""
    print("Running Crypto module tests...\n")

    test_instance = TestCrypto()

    test_methods = [
        test_instance.test_encrypt_decrypt_roundtrip,
        test_instance.test_different_passwords_different_ciphertext,
        test_instance.test_same_password_different_salt_nonce,
        test_instance.test_wrong_password_decryption_fails,
        test_instance.test_custom_kdf_params,
        test_instance.test_empty_data_encryption,
        test_instance.test_large_data_encryption,
        test_instance.test_unicode_data_encryption,
        test_instance.test_corrupted_ciphertext_fails,
        test_instance.test_corrupted_nonce_fails,
        test_instance.test_unsupported_vault_format_fails,
        test_instance.test_base64_encoding_integrity,
        test_instance.test_deterministic_kdf_with_same_salt,
    ]

    passed = 0
    for test_method in test_methods:
        try:
            test_instance.setup_method()
            test_method()
            passed += 1
        except Exception as e:
            print(f"❌ {test_method.__name__} failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    print(f"\n🎉 All {passed} Crypto tests passed!")
    print("Your AES-GCM + Argon2 encryption is bulletproof! 🔐")
    return True


if __name__ == "__main__":
    print("To run with pytest: pytest tests/test_crypto.py -v")
    print("Or run manually:\n")
    run_all_tests()