import os
import tempfile
import pytest
import string
from password_manager_core import PasswordManagerCore

class TestPasswordManagerCore:
    """Test suite for PasswordManagerCore."""

    def setup_method(self):
        """Set up test environment before each test."""
        # Create temporary file path (but don't create the file)
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.test_file_path = self.temp_file.name

        # Remove the empty file so authentication creates defaults
        os.unlink(self.test_file_path)

        # Initialize password manager
        self.manager = PasswordManagerCore(self.test_file_path)
        self.master_password = "test_master_password_123"

        # Authenticate for most tests (this will create default data)
        success, msg = self.manager.authenticate(self.master_password)
        assert success, f"Authentication failed: {msg}"

    def teardown_method(self):
        """Clean up after each test."""
        if os.path.exists(self.test_file_path):
            os.unlink(self.test_file_path)
        backup_path = self.test_file_path + ".backup"
        if os.path.exists(backup_path):
            os.unlink(backup_path)

    def test_authentication_success(self):
        """Test successful authentication."""
        manager = PasswordManagerCore(self.test_file_path)
        success, msg = manager.authenticate(self.master_password)

        assert success is True
        assert "successful" in msg.lower()
        assert manager.is_authenticated is True
        print("✓ Authentication success works")

    def test_authentication_wrong_password(self):
        """Test authentication with wrong password."""
        # Create file with one password first
        os.unlink(self.test_file_path)  # Remove existing

        manager1 = PasswordManagerCore(self.test_file_path)
        manager1.authenticate("correct_password")

        # Try with wrong password
        manager2 = PasswordManagerCore(self.test_file_path)
        success, msg = manager2.authenticate("wrong_password")

        assert success is False
        assert "failed" in msg.lower()
        assert manager2.is_authenticated is False
        print("✓ Authentication with wrong password fails correctly")

    def test_get_available_users(self):
        """Test getting list of available users."""
        users = self.manager.get_available_users()

        assert isinstance(users, list)
        assert len(users) == 2  # Default users: john_doe, jane_smith
        assert "john_doe" in users
        assert "jane_smith" in users
        print("✓ Get available users works")

    def test_set_current_user_valid(self):
        """Test setting a valid current user."""
        success, msg = self.manager.set_current_user("john_doe")

        assert success is True
        assert self.manager.current_user == "john_doe"
        assert "john_doe" in msg
        print("✓ Set valid current user works")

    def test_set_current_user_invalid(self):
        """Test setting an invalid current user."""
        success, msg = self.manager.set_current_user("nonexistent_user")

        assert success is False
        assert "not found" in msg.lower()  # Message: "User 'nonexistent_user' not found"
        assert self.manager.current_user is None
        print("✓ Set invalid current user fails correctly")

    def test_generate_secure_password(self):
        """Test secure password generation."""
        password = self.manager.generate_secure_password()

        # Test default length
        assert len(password) == 16

        # Test custom length
        custom_password = self.manager.generate_secure_password(20)
        assert len(custom_password) == 20

        # Test character variety (should have uppercase, lowercase, digits, special)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        assert has_upper, "Password should contain uppercase letters"
        assert has_lower, "Password should contain lowercase letters"
        assert has_digit, "Password should contain digits"
        assert has_special, "Password should contain special characters"

        # Test uniqueness (generate multiple passwords)
        passwords = [self.manager.generate_secure_password() for _ in range(10)]
        assert len(set(passwords)) == 10, "Generated passwords should be unique"

        print("✓ Secure password generation works")

    def test_add_password_with_generated(self):
        """Test adding password with auto-generation."""
        self.manager.set_current_user("john_doe")

        success, msg = self.manager.add_password("netflix", "john@email.com")

        assert success is True
        assert "added successfully" in msg.lower()

        # Verify password was generated and stored
        success, data = self.manager.retrieve_password("netflix")
        assert success is True
        assert data["username"] == "john@email.com"
        assert len(data["password"]) == 16  # Default generated length

        print("✓ Add password with generation works")

    def test_add_password_with_custom(self):
        """Test adding password with custom password."""
        self.manager.set_current_user("john_doe")

        custom_password = "MyCustomPass123!"
        success, msg = self.manager.add_password(
            "custom_service", "johndoe", custom_password,
            "https://custom.com", "Dev account"
        )

        assert success is True

        # Verify all fields stored correctly
        success, data = self.manager.retrieve_password("custom_service")
        assert success is True
        assert data["username"] == "johndoe"
        assert data["password"] == custom_password
        assert data["url"] == "https://custom.com"
        assert data["notes"] == "Dev account"

        print("✓ Add password with custom values works")

    def test_add_duplicate_service(self):
        """Test adding password for existing service fails."""
        self.manager.set_current_user("john_doe")

        # Add first password
        success, msg = self.manager.add_password("duplicate", "user1")
        assert success is True

        # Try to add duplicate
        success, msg = self.manager.add_password("duplicate", "user2")
        assert success is False
        assert "already exists" in msg.lower()

        print("✓ Add duplicate service fails correctly")

    def test_retrieve_password_existing(self):
        """Test retrieving existing password."""
        self.manager.set_current_user("john_doe")

        # Should have default passwords from test data
        success, data = self.manager.retrieve_password("gmail")

        assert success is True
        assert "username" in data
        assert "password" in data
        assert "url" in data
        assert "notes" in data

        print("✓ Retrieve existing password works")

    def test_retrieve_password_nonexistent(self):
        """Test retrieving nonexistent password."""
        self.manager.set_current_user("john_doe")

        success, data = self.manager.retrieve_password("nonexistent")

        assert success is False
        assert "error" in data
        assert "no password found" in data["error"].lower()

        print("✓ Retrieve nonexistent password fails correctly")

    def test_update_password_partial(self):
        """Test updating individual fields of password entry."""
        self.manager.set_current_user("john_doe")

        # Get original data
        success, original = self.manager.retrieve_password("gmail")
        assert success is True

        # Update only username
        success, msg = self.manager.update_password("gmail", username="new_user@gmail.com")
        assert success is True

        # Verify only username changed
        success, updated = self.manager.retrieve_password("gmail")
        assert success is True
        assert updated["username"] == "new_user@gmail.com"
        assert updated["password"] == original["password"]  # Should be unchanged
        assert updated["url"] == original["url"]  # Should be unchanged

        print("✓ Partial password update works")

    def test_update_password_generate_new(self):
        """Test updating password with new generation."""
        self.manager.set_current_user("john_doe")

        # Get original password
        success, original = self.manager.retrieve_password("gmail")
        original_password = original["password"]

        # Update with new generated password
        success, msg = self.manager.update_password("gmail", generate_new=True)
        assert success is True

        # Verify password changed
        success, updated = self.manager.retrieve_password("gmail")
        assert success is True
        assert updated["password"] != original_password
        assert len(updated["password"]) == 16  # Default generated length

        print("✓ Update with generated password works")

    def test_update_nonexistent_password(self):
        """Test updating nonexistent password fails."""
        self.manager.set_current_user("john_doe")

        success, msg = self.manager.update_password("nonexistent", username="test")

        assert success is False
        assert "no password found" in msg.lower()

        print("✓ Update nonexistent password fails correctly")

    def test_delete_password(self):
        """Test deleting password entry."""
        self.manager.set_current_user("john_doe")

        # Verify password exists
        success, _ = self.manager.retrieve_password("gmail")
        assert success is True

        # Delete password
        success, msg = self.manager.delete_password("gmail")
        assert success is True
        assert "deleted successfully" in msg.lower()

        # Verify password no longer exists
        success, _ = self.manager.retrieve_password("gmail")
        assert success is False

        print("✓ Delete password works")

    def test_delete_nonexistent_password(self):
        """Test deleting nonexistent password fails."""
        self.manager.set_current_user("john_doe")

        success, msg = self.manager.delete_password("nonexistent")

        assert success is False
        assert "no password found" in msg.lower()  # Message: "No password found for 'nonexistent'"

        print("✓ Delete nonexistent password fails correctly")

    def test_list_services(self):
        """Test listing all services for user."""
        self.manager.set_current_user("john_doe")

        success, services = self.manager.list_services()

        assert success is True
        assert isinstance(services, list)
        assert len(services) >= 3  # Should have default services
        assert "gmail" in services
        assert "github" in services
        assert "banking" in services

        print("✓ List services works")

    def test_search_services(self):
        """Test searching services."""
        self.manager.set_current_user("john_doe")

        # Search for services containing "git"
        success, results = self.manager.search_services("git")

        assert success is True
        assert isinstance(results, list)
        assert "github" in results

        # Test case insensitive search
        success, results = self.manager.search_services("GIT")
        assert "github" in results

        print("✓ Search services works")

    def test_get_user_stats(self):
        """Test getting user statistics."""
        self.manager.set_current_user("john_doe")

        success, stats = self.manager.get_user_stats()

        assert success is True
        assert "total_passwords" in stats
        assert "services" in stats
        assert "user" in stats
        assert stats["user"] == "john_doe"
        assert stats["total_passwords"] >= 3
        assert isinstance(stats["services"], list)

        print("✓ Get user stats works")

    def test_create_backup(self):
        """Test creating backup file."""
        success, msg = self.manager.create_backup()

        assert success is True
        assert "backup created" in msg.lower()

        backup_path = self.test_file_path + ".backup"
        assert os.path.exists(backup_path)

        print("✓ Create backup works")

    def test_operations_without_authentication(self):
        """Test that operations fail without authentication."""
        manager = PasswordManagerCore(self.test_file_path)

        success, _ = manager.list_services()
        assert success is False

        success, _ = manager.add_password("test", "user")
        assert success is False

        print("✓ Operations fail without authentication")

    def test_operations_without_user_selection(self):
        """Test that operations fail without user selection."""
        manager = PasswordManagerCore(self.test_file_path)
        manager.authenticate(self.master_password)
        # Don't set current user

        success, _ = manager.add_password("test", "user")
        assert success is False

        success, _ = manager.list_services()
        assert success is False

        print("✓ Operations fail without user selection")

def run_all_tests():
    """Run all tests manually."""
    print("Running Password Manager Core tests...")

    test_instance = TestPasswordManagerCore()

    test_methods = [
        test_instance.test_authentication_success,
        test_instance.test_authentication_wrong_password,
        test_instance.test_get_available_users,
        test_instance.test_set_current_user_valid,
        test_instance.test_set_current_user_invalid,
        test_instance.test_generate_secure_password,
        test_instance.test_add_password_with_generated,
        test_instance.test_add_password_with_custom,
        test_instance.test_add_duplicate_service,
        test_instance.test_retrieve_password_existing,
        test_instance.test_retrieve_password_nonexistent,
        test_instance.test_update_password_partial,
        test_instance.test_update_password_generate_new,
        test_instance.test_update_nonexistent_password,
        test_instance.test_delete_password,
        test_instance.test_delete_nonexistent_password,
        test_instance.test_list_services,
        test_instance.test_search_services,
        test_instance.test_get_user_stats,
        test_instance.test_create_backup,
        test_instance.test_operations_without_authentication,
        test_instance.test_operations_without_user_selection,
    ]

    passed = 0
    for test_method in test_methods:
        try:
            test_instance.setup_method()
            test_method()
            test_instance.teardown_method()
            passed += 1
        except Exception as e:
            test_instance.teardown_method()
            print(f"❌ {test_method.__name__} failed: {e}")
            return False

    print(f"\n🎉 All {passed} Password Manager Core tests passed!")
    print("Your business logic layer is rock solid!")
    return True

if __name__ == "__main__":
    print("To run with pytest: pip install pytest && pytest test_password_manager_core.py")
    print("Or run manually:\n")
    run_all_tests()
