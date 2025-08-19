'''FileStorageManager Tests'''
import os
import json
import tempfile
import pytest
from file_storage_manager import FileStorageManager
from crypto_manager import CryptoManager

class TestFileStorageManager:
    """Test suite for FileStorageManager."""

    def setup_method(self):
        """Set up test environment before each test."""
        # Create temporary file for testing
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.test_file_path = self.temp_file.name

        # Initialize managers
        self.storage = FileStorageManager(self.test_file_path)
        self.crypto = CryptoManager("test_master_password")
        self.crypto.initialize_encryption()
        self.storage.set_crypto_manager(self.crypto)

        # Test data
        self.test_data = {
            "users": {
                "testuser": {
                    "passwords": {
                        "gmail": {
                            "username": "test@gmail.com",
                            "password": "TestPass123!",
                            "url": "https://gmail.com",
                            "notes": "Test account"
                        }
                    }
                }
            }
        }

    def teardown_method(self):
        """Clean up after each test."""
        if os.path.exists(self.test_file_path):
            os.unlink(self.test_file_path)

    def test_save_and_load_passwords(self):
        """Test basic save and load functionality."""
        # Save data
        result = self.storage.save_passwords(self.test_data)
        assert result is True
        assert self.storage.file_exists()

        # Load data
        loaded_data = self.storage.load_passwords()
        assert loaded_data == self.test_data
        print("✓ Save and load passwords works")

    def test_file_format_structure(self):
        """Test that saved file has correct structure."""
        self.storage.save_passwords(self.test_data)

        # Read raw file content
        with open(self.test_file_path, 'r') as f:
            file_content = json.load(f)

        # Check structure
        assert "version" in file_content
        assert "salt" in file_content
        assert "encrypted_data" in file_content
        assert "metadata" in file_content
        assert file_content["version"] == "1.0"
        assert "encryption" in file_content["metadata"]
        print("✓ File format structure is correct")

    def test_load_nonexistent_file(self):
        """Test loading when file doesn't exist."""
        os.unlink(self.test_file_path)  # Remove the file

        result = self.storage.load_passwords()
        assert result is None
        print("✓ Loading nonexistent file returns None")

    def test_wrong_master_password_on_load(self):
        """Test that wrong master password fails on load."""
        # Save with one password
        self.storage.save_passwords(self.test_data)

        # Try to load with different password
        wrong_crypto = CryptoManager("wrong_password")
        self.storage.set_crypto_manager(wrong_crypto)

        with pytest.raises(ValueError, match="Failed to load passwords"):
            self.storage.load_passwords()
        print("✓ Wrong master password properly fails on load")

    def test_corrupted_file_handling(self):
        """Test handling of corrupted files."""
        # Create corrupted file
        with open(self.test_file_path, 'w') as f:
            f.write("invalid json content")

        with pytest.raises(ValueError, match="Corrupted password file"):
            self.storage.load_passwords()
        print("✓ Corrupted file handling works")

    def test_invalid_file_format(self):
        """Test handling of files with missing required keys."""
        # Create file with invalid format
        invalid_content = {"version": "1.0", "missing_salt": True}
        with open(self.test_file_path, 'w') as f:
            json.dump(invalid_content, f)

        with pytest.raises(ValueError, match="Invalid file format"):
            self.storage.load_passwords()
        print("✓ Invalid file format handling works")

    def test_default_data_creation(self):
        """Test creation of default data."""
        default_data = self.storage.create_default_data()

        assert "users" in default_data
        assert "john_doe" in default_data["users"]
        assert "jane_smith" in default_data["users"]

        # Check john_doe has passwords
        john_passwords = default_data["users"]["john_doe"]["passwords"]
        assert "gmail" in john_passwords
        assert "github" in john_passwords
        assert "banking" in john_passwords

        # Check password structure
        gmail_entry = john_passwords["gmail"]
        required_fields = ["username", "password", "url", "notes"]
        for field in required_fields:
            assert field in gmail_entry

        print("✓ Default data creation works")

    def test_initialize_with_defaults(self):
        """Test initializing file with defaults when it doesn't exist."""
        os.unlink(self.test_file_path)  # Remove file

        result = self.storage.initialize_with_defaults()
        assert result is True
        assert self.storage.file_exists()

        # Load and verify default data
        loaded_data = self.storage.load_passwords()
        assert "users" in loaded_data
        assert len(loaded_data["users"]) == 2
        print("✓ Initialize with defaults works")

    def test_initialize_with_existing_file(self):
        """Test that initialize doesn't overwrite existing file."""
        # Save custom data first
        self.storage.save_passwords(self.test_data)

        # Try to initialize with defaults
        result = self.storage.initialize_with_defaults()
        assert result is True

        # Verify original data is preserved
        loaded_data = self.storage.load_passwords()
        assert loaded_data == self.test_data
        print("✓ Initialize preserves existing file")

    def test_backup_functionality(self):
        """Test file backup creation."""
        # Save some data
        self.storage.save_passwords(self.test_data)

        # Create backup
        backup_result = self.storage.backup_file()
        assert backup_result is True

        backup_path = self.test_file_path + ".backup"
        assert os.path.exists(backup_path)

        # Verify backup content matches original
        with open(self.test_file_path, 'r') as original, \
             open(backup_path, 'r') as backup:
            assert original.read() == backup.read()

        # Clean up backup
        os.unlink(backup_path)
        print("✓ Backup functionality works")

    def test_error_handling_without_crypto_manager(self):
        """Test error handling when crypto manager not set."""
        storage_no_crypto = FileStorageManager(self.test_file_path)

        with pytest.raises(ValueError, match="CryptoManager not set"):
            storage_no_crypto.save_passwords(self.test_data)

        with pytest.raises(ValueError, match="CryptoManager not set"):
            storage_no_crypto.load_passwords()

        print("✓ Error handling without crypto manager works")

def run_all_tests():
    """Run all tests manually."""
    print("Running File Storage Manager tests...")

    test_instance = TestFileStorageManager()

    test_methods = [
        test_instance.test_save_and_load_passwords,
        test_instance.test_file_format_structure,
        test_instance.test_load_nonexistent_file,
        test_instance.test_wrong_master_password_on_load,
        test_instance.test_corrupted_file_handling,
        test_instance.test_invalid_file_format,
        test_instance.test_default_data_creation,
        test_instance.test_initialize_with_defaults,
        test_instance.test_initialize_with_existing_file,
        test_instance.test_backup_functionality,
        test_instance.test_error_handling_without_crypto_manager
    ]

    for test_method in test_methods:
        try:
            test_instance.setup_method()
            test_method()
            test_instance.teardown_method()
        except Exception as e:
            test_instance.teardown_method()
            print(f"❌ {test_method.__name__} failed: {e}")
            return False

    print("\n🎉 All File Storage Manager tests passed!")
    return True

if __name__ == "__main__":
    print("To run with pytest: pip install pytest && pytest test_file_storage_manager.py")
    print("Or run manually:\n")
    run_all_tests()