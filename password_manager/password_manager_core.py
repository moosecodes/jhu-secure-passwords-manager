'''PasswordManagerCore'''
import secrets
import string
from typing import Dict, List, Optional, Tuple
from crypto_manager import CryptoManager
from file_storage_manager import FileStorageManager

class PasswordManagerCore:
    """Core password manager functionality coordinating crypto and storage."""

    def __init__(self, file_path: str = "passwords.json"):
        self.file_path = file_path
        self.storage_manager = FileStorageManager(file_path)
        self.crypto_manager: Optional[CryptoManager] = None
        self.current_user: Optional[str] = None
        self.password_data: Optional[Dict] = None
        self.is_authenticated = False

    def authenticate(self, master_password: str) -> Tuple[bool, str]:
        """Authenticate with master password and load data."""
        try:
            # Initialize crypto manager
            self.crypto_manager = CryptoManager(master_password)
            self.storage_manager.set_crypto_manager(self.crypto_manager)

            # Initialize with defaults if file doesn't exist
            if not self.storage_manager.file_exists():
                self.crypto_manager.initialize_encryption()
                success = self.storage_manager.initialize_with_defaults()
                if not success:
                    return False, "Failed to create default password database"

            # Load password data
            self.password_data = self.storage_manager.load_passwords()
            if self.password_data is None:
                return False, "Failed to load password database"

            self.is_authenticated = True
            return True, "Authentication successful"

        except ValueError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"

    def set_current_user(self, username: str) -> Tuple[bool, str]:
        """Set the current user for operations."""
        if not self.is_authenticated:
            return False, "Not authenticated"

        if username not in self.password_data.get("users", {}):
            return False, f"User '{username}' not found"

        self.current_user = username
        return True, f"Current user set to '{username}'"

    def get_available_users(self) -> List[str]:
        """Get list of available users."""
        if not self.is_authenticated or not self.password_data:
            return []
        return list(self.password_data.get("users", {}).keys())

    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a cryptographically secure password."""
        # Character sets for secure passwords
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special_chars)
        ]

        # Fill the rest randomly from all sets
        all_chars = lowercase + uppercase + digits + special_chars
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))

        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    def add_password(self, service: str, username: str, password: str = None,
                    url: str = "", notes: str = "") -> Tuple[bool, str]:
        """Add a new password entry."""
        if not self._check_user_auth():
            return False, "Not authenticated or no user selected"

        # Generate password if not provided
        if password is None:
            password = self.generate_secure_password()

        # Initialize user's password dict if it doesn't exist
        user_data = self.password_data["users"][self.current_user]
        if "passwords" not in user_data:
            user_data["passwords"] = {}

        # Check if service already exists
        if service in user_data["passwords"]:
            return False, f"Password entry for '{service}' already exists"

        # Add new password entry
        user_data["passwords"][service] = {
            "username": username,
            "password": password,
            "url": url,
            "notes": notes
        }

        # Save to file
        if self._save_data():
            return True, f"Password for '{service}' added successfully"
        else:
            return False, "Failed to save password data"

    def retrieve_password(self, service: str) -> Tuple[bool, Dict]:
        """Retrieve password entry for a service."""
        if not self._check_user_auth():
            return False, {"error": "Not authenticated or no user selected"}

        user_passwords = self.password_data["users"][self.current_user].get("passwords", {})

        if service not in user_passwords:
            return False, {"error": f"No password found for '{service}'"}

        return True, user_passwords[service]

    def update_password(self, service: str, username: str = None, password: str = None,
                       url: str = None, notes: str = None, generate_new: bool = False) -> Tuple[bool, str]:
        """Update existing password entry."""
        if not self._check_user_auth():
            return False, "Not authenticated or no user selected"

        user_passwords = self.password_data["users"][self.current_user].get("passwords", {})

        if service not in user_passwords:
            return False, f"No password found for '{service}'"

        # Generate new password if requested
        if generate_new:
            password = self.generate_secure_password()

        # Update only provided fields
        entry = user_passwords[service]
        if username is not None:
            entry["username"] = username
        if password is not None:
            entry["password"] = password
        if url is not None:
            entry["url"] = url
        if notes is not None:
            entry["notes"] = notes

        # Save to file
        if self._save_data():
            return True, f"Password for '{service}' updated successfully"
        else:
            return False, "Failed to save updated password data"

    def delete_password(self, service: str) -> Tuple[bool, str]:
        """Delete password entry for a service."""
        if not self._check_user_auth():
            return False, "Not authenticated or no user selected"

        user_passwords = self.password_data["users"][self.current_user].get("passwords", {})

        if service not in user_passwords:
            return False, f"No password found for '{service}'"

        # Delete the entry
        del user_passwords[service]

        # Save to file
        if self._save_data():
            return True, f"Password for '{service}' deleted successfully"
        else:
            return False, "Failed to save password data after deletion"

    def list_services(self) -> Tuple[bool, List[str]]:
        """List all services for current user."""
        if not self._check_user_auth():
            return False, []

        user_passwords = self.password_data["users"][self.current_user].get("passwords", {})
        return True, list(user_passwords.keys())

    def search_services(self, query: str) -> Tuple[bool, List[str]]:
        """Search for services matching query."""
        success, services = self.list_services()
        if not success:
            return False, []

        matching_services = [
            service for service in services
            if query.lower() in service.lower()
        ]

        return True, matching_services

    def create_backup(self) -> Tuple[bool, str]:
        """Create a backup of the password database."""
        if not self.is_authenticated:
            return False, "Not authenticated"

        if self.storage_manager.backup_file():
            return True, f"Backup created: {self.file_path}.backup"
        else:
            return False, "Failed to create backup"

    def get_user_stats(self) -> Tuple[bool, Dict]:
        """Get statistics for current user."""
        if not self._check_user_auth():
            return False, {}

        user_passwords = self.password_data["users"][self.current_user].get("passwords", {})

        stats = {
            "total_passwords": len(user_passwords),
            "services": list(user_passwords.keys()),
            "user": self.current_user
        }

        return True, stats

    def _check_user_auth(self) -> bool:
        """Check if user is authenticated and selected."""
        return self.is_authenticated and self.current_user is not None

    def _save_data(self) -> bool:
        """Save current password data to file."""
        try:
            return self.storage_manager.save_passwords(self.password_data)
        except Exception as e:
            print(f"Error saving data: {e}")
            return False
