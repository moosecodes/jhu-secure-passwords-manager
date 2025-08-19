"""Tests for password_manager.models module."""

import pytest
from datetime import datetime, timezone
from uuid import UUID

from password_manager.models import (
    PasswordPolicy,
    EntryHistoryItem,
    Entry,
    Settings,
    Vault,
    now_iso
)


class TestPasswordPolicy:
    """Test PasswordPolicy dataclass."""

    def test_default_values(self):
        """Test PasswordPolicy default values."""
        policy = PasswordPolicy()
        assert policy.length == 16
        assert policy.uppercase is True
        assert policy.lowercase is True
        assert policy.digits is True
        assert policy.symbols is True
        assert policy.exclude_ambiguous is True

    def test_custom_values(self):
        """Test PasswordPolicy with custom values."""
        policy = PasswordPolicy(
            length=24,
            uppercase=False,
            symbols=False,
            exclude_ambiguous=False
        )
        assert policy.length == 24
        assert policy.uppercase is False
        assert policy.lowercase is True  # default
        assert policy.digits is True     # default
        assert policy.symbols is False
        assert policy.exclude_ambiguous is False


class TestEntryHistoryItem:
    """Test EntryHistoryItem dataclass."""

    def test_creation(self):
        """Test EntryHistoryItem creation."""
        item = EntryHistoryItem(
            password="old_password_123",
            changed_at="2025-01-01T12:00:00Z"
        )
        assert item.password == "old_password_123"
        assert item.changed_at == "2025-01-01T12:00:00Z"


class TestEntry:
    """Test Entry dataclass."""

    def test_new_entry_creation(self):
        """Test Entry.new() class method."""
        entry = Entry.new(
            site="example.com",
            username="user@example.com",
            password="secret123"
        )

        assert entry.site == "example.com"
        assert entry.username == "user@example.com"
        assert entry.password == "secret123"
        assert entry.url is None
        assert entry.notes is None
        assert entry.tags == []
        assert entry.history == []

        # Check generated fields
        assert isinstance(entry.id, str)
        UUID(entry.id)  # Should be valid UUID
        assert isinstance(entry.updated_at, str)
        datetime.fromisoformat(entry.updated_at.replace('Z', '+00:00'))

    def test_new_entry_with_optional_fields(self):
        """Test Entry.new() with all optional fields."""
        entry = Entry.new(
            site="github.com",
            username="developer",
            password="complex_password_123!",
            url="https://github.com/login",
            notes="Work account with 2FA enabled",
            tags=["work", "development", "github"]
        )

        assert entry.site == "github.com"
        assert entry.username == "developer"
        assert entry.password == "complex_password_123!"
        assert entry.url == "https://github.com/login"
        assert entry.notes == "Work account with 2FA enabled"
        assert entry.tags == ["work", "development", "github"]
        assert entry.history == []

        # Check generated fields
        assert isinstance(entry.id, str)
        UUID(entry.id)
        assert isinstance(entry.updated_at, str)

    def test_direct_entry_creation(self):
        """Test direct Entry creation (not using .new())."""
        entry = Entry(
            id="test-id-123",
            site="direct.com",
            username="directuser",
            password="directpass",
            updated_at="2025-01-01T10:00:00Z"
        )

        assert entry.id == "test-id-123"
        assert entry.site == "direct.com"
        assert entry.username == "directuser"
        assert entry.password == "directpass"
        assert entry.updated_at == "2025-01-01T10:00:00Z"
        assert entry.url is None
        assert entry.notes is None
        assert entry.tags == []
        assert entry.history == []


class TestSettings:
    """Test Settings dataclass."""

    def test_default_settings(self):
        """Test Settings default values."""
        settings = Settings()
        assert isinstance(settings.password_policy, PasswordPolicy)
        assert settings.password_policy.length == 16

    def test_custom_settings(self):
        """Test Settings with custom password policy."""
        custom_policy = PasswordPolicy(length=32, symbols=False)
        settings = Settings(password_policy=custom_policy)

        assert settings.password_policy.length == 32
        assert settings.password_policy.symbols is False


class TestVault:
    """Test Vault dataclass."""

    def test_new_vault_creation(self):
        """Test Vault.new() class method."""
        vault = Vault.new()

        assert vault.version == 1
        assert isinstance(vault.vault_id, str)
        UUID(vault.vault_id)  # Should be valid UUID
        assert isinstance(vault.created_at, str)
        datetime.fromisoformat(vault.created_at.replace('Z', '+00:00'))
        assert vault.entries == []
        assert isinstance(vault.settings, Settings)

    def test_vault_to_dict(self):
        """Test Vault.to_dict() method."""
        vault = Vault.new()
        vault.entries = [
            Entry.new("test.com", "testuser", "testpass", tags=["test"])
        ]

        vault_dict = vault.to_dict()

        assert isinstance(vault_dict, dict)
        assert vault_dict["version"] == 1
        assert "vault_id" in vault_dict
        assert "created_at" in vault_dict
        assert "entries" in vault_dict
        assert "settings" in vault_dict

        # Check entries are properly serialized
        assert len(vault_dict["entries"]) == 1
        entry_dict = vault_dict["entries"][0]
        assert entry_dict["site"] == "test.com"
        assert entry_dict["username"] == "testuser"
        assert entry_dict["password"] == "testpass"
        assert entry_dict["tags"] == ["test"]

        # Check settings are properly serialized
        assert "password_policy" in vault_dict["settings"]
        policy_dict = vault_dict["settings"]["password_policy"]
        assert policy_dict["length"] == 16

    def test_direct_vault_creation(self):
        """Test direct Vault creation (not using .new())."""
        vault = Vault(
            version=2,
            vault_id="custom-vault-id",
            created_at="2025-01-01T00:00:00Z",
            entries=[],
            settings=Settings()
        )

        assert vault.version == 2
        assert vault.vault_id == "custom-vault-id"
        assert vault.created_at == "2025-01-01T00:00:00Z"
        assert vault.entries == []
        assert isinstance(vault.settings, Settings)


class TestUtilityFunctions:
    """Test utility functions."""

    def test_now_iso(self):
        """Test now_iso() function."""
        timestamp = now_iso()

        # Should be a string
        assert isinstance(timestamp, str)

        # Should be valid ISO format
        parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        assert isinstance(parsed, datetime)

        # Should be UTC timezone
        assert parsed.tzinfo == timezone.utc

        # Should be recent (within last minute)
        now = datetime.now(timezone.utc)
        diff = abs((now - parsed).total_seconds())
        assert diff < 60

        # Should have no microseconds
        assert parsed.microsecond == 0

        # Should end with Z (UTC indicator)
        assert timestamp.endswith("Z") or timestamp.endswith("+00:00")


# Integration test for the models working together
class TestModelsIntegration:
    """Test how the models work together."""

    def test_complete_vault_structure(self):
        """Test creating a complete vault with all components."""
        # Create custom password policy
        policy = PasswordPolicy(length=20, symbols=False)
        settings = Settings(password_policy=policy)

        # Create vault with custom settings
        vault = Vault(
            version=1,
            vault_id="integration-test-vault",
            created_at=now_iso(),
            entries=[],
            settings=settings
        )

        # Add some entries
        entry1 = Entry.new(
            site="github.com",
            username="dev@example.com",
            password="github_password_123",
            url="https://github.com/login",
            notes="Development account",
            tags=["work", "dev"]
        )

        entry2 = Entry.new(
            site="gmail.com",
            username="personal@gmail.com",
            password="gmail_password_456",
            tags=["personal", "email"]
        )

        vault.entries = [entry1, entry2]

        # Test serialization
        vault_dict = vault.to_dict()

        # Verify structure
        assert vault_dict["version"] == 1
        assert vault_dict["vault_id"] == "integration-test-vault"
        assert len(vault_dict["entries"]) == 2
        assert vault_dict["settings"]["password_policy"]["length"] == 20
        assert vault_dict["settings"]["password_policy"]["symbols"] is False

        # Verify entries
        github_entry = next(e for e in vault_dict["entries"] if e["site"] == "github.com")
        assert github_entry["username"] == "dev@example.com"
        assert github_entry["url"] == "https://github.com/login"
        assert github_entry["notes"] == "Development account"
        assert "work" in github_entry["tags"]
        assert "dev" in github_entry["tags"]

        gmail_entry = next(e for e in vault_dict["entries"] if e["site"] == "gmail.com")
        assert gmail_entry["username"] == "personal@gmail.com"
        assert gmail_entry["url"] is None
        assert "personal" in gmail_entry["tags"]
        assert "email" in gmail_entry["tags"]
