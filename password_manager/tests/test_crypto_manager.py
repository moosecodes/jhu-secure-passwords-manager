import sys
import os
import pytest

# Add the parent directory to the Python path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_manager import CryptoManager

def test_basic_encryption_decryption():
    """Test basic encrypt/decrypt functionality."""
    # Sample password data
    test_data = {
        "passwords": {
            "gmail": {
                "username": "user@gmail.com",
                "password": "superSecretPass123!",
                "url": "https://gmail.com"
            },
            "github": {
                "username": "developer",
                "password": "anotherSecretPass456@",
                "url": "https://github.com"
            }
        }
    }

    # Initialize crypto manager
    crypto = CryptoManager("my_master_password_123")
    crypto.initialize_encryption()

    # Encrypt data
    encrypted_data = crypto.encrypt_data(test_data)
    assert isinstance(encrypted_data, bytes)
    assert len(encrypted_data) > 0

    # Decrypt data
    decrypted_data = crypto.decrypt_data(encrypted_data)
    assert decrypted_data == test_data
    print("✓ Basic encryption/decryption works")

def test_different_master_passwords():
    """Test that different master passwords produce different encryption."""
    test_data = {"test": "data"}

    crypto1 = CryptoManager("password1")
    crypto1.initialize_encryption()
    encrypted1 = crypto1.encrypt_data(test_data)

    crypto2 = CryptoManager("password2")
    crypto2.initialize_encryption()
    encrypted2 = crypto2.encrypt_data(test_data)

    # Different passwords should produce different encrypted data
    assert encrypted1 != encrypted2
    print("✓ Different master passwords produce different encryption")

def test_wrong_master_password_fails():
    """Test that wrong master password fails decryption."""
    test_data = {"test": "secret"}

    # Encrypt with one password
    crypto1 = CryptoManager("correct_password")
    crypto1.initialize_encryption()
    salt = crypto1.get_salt()
    encrypted_data = crypto1.encrypt_data(test_data)

    # Try to decrypt with wrong password
    crypto2 = CryptoManager("wrong_password")
    crypto2.initialize_encryption(salt=salt)  # Same salt, wrong password

    with pytest.raises(ValueError, match="Failed to decrypt data"):
        crypto2.decrypt_data(encrypted_data)
    print("✓ Wrong master password properly fails")

def test_salt_persistence():
    """Test that salt can be retrieved and reused."""
    test_data = {"test": "data"}
    master_password = "test_password"

    # First encryption session
    crypto1 = CryptoManager(master_password)
    crypto1.initialize_encryption()
    salt = crypto1.get_salt()
    encrypted_data = crypto1.encrypt_data(test_data)

    # Second session with same salt (simulates loading from file)
    crypto2 = CryptoManager(master_password)
    crypto2.initialize_encryption(salt=salt)
    decrypted_data = crypto2.decrypt_data(encrypted_data)

    assert decrypted_data == test_data
    print("✓ Salt persistence and reuse works")

def test_error_handling():
    """Test proper error handling."""
    crypto = CryptoManager("test")

    # Should fail if not initialized
    with pytest.raises(ValueError, match="Encryption not initialized"):
        crypto.encrypt_data({"test": "data"})

    with pytest.raises(ValueError, match="Salt not generated"):
        crypto.get_salt()

    print("✓ Error handling works correctly")

if __name__ == "__main__":
    print("Running crypto manager tests...")

    test_basic_encryption_decryption()
    test_different_master_passwords()
    test_wrong_master_password_fails()
    test_salt_persistence()
    test_error_handling()

    print("\n🎉 All tests passed! Crypto module is solid.")
    print("\nTo run with pytest: pip install pytest && python test_crypto_manager.py")
