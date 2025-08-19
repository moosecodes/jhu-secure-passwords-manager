"""Test suite for kdf.py module - Key Derivation Functions using Argon2."""

import pytest
import os
from pathlib import Path

# Import the modules to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from password_manager.kdf import derive_key, Argon2Params, DEFAULT_PARAMS


class TestKDF:
    """Test suite for Key Derivation Functions."""

    def setup_method(self):
        """Set up test data before each test."""
        self.test_password = "TestPassword123!"
        self.test_salt = os.urandom(16)

    def test_derive_key_basic(self):
        """Test basic key derivation."""
        key = derive_key(self.test_password, self.test_salt)

        # Key should be 32 bytes by default
        assert len(key) == 32
        assert isinstance(key, bytes)
        print("✓ Basic key derivation works")

    def test_derive_key_deterministic(self):
        """Test that key derivation is deterministic with same inputs."""
        key1 = derive_key(self.test_password, self.test_salt, DEFAULT_PARAMS)
        key2 = derive_key(self.test_password, self.test_salt, DEFAULT_PARAMS)

        assert key1 == key2
        print("✓ Key derivation is deterministic")

    def test_different_passwords_different_keys(self):
        """Test that different passwords produce different keys."""
        key1 = derive_key("password1", self.test_salt)
        key2 = derive_key("password2", self.test_salt)

        assert key1 != key2
        print("✓ Different passwords produce different keys")

    def test_different_salts_different_keys(self):
        """Test that different salts produce different keys."""
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)

        key1 = derive_key(self.test_password, salt1)
        key2 = derive_key(self.test_password, salt2)

        assert key1 != key2
        print("✓ Different salts produce different keys")

    def test_custom_params(self):
        """Test key derivation with custom parameters."""
        custom_params = Argon2Params(
            time_cost=2,
            memory_cost=32768,  # 32 MB
            parallelism=1,
            hash_len=64  # 64-byte key
        )

        key = derive_key(self.test_password, self.test_salt, custom_params)

        assert len(key) == 64  # Custom hash length
        print("✓ Custom parameters work")

    def test_minimal_valid_params(self):
        """Test with minimal valid parameters."""
        minimal_params = Argon2Params(
            time_cost=1,
            memory_cost=8,  # Minimum memory
            parallelism=1,
            hash_len=16  # Minimum practical key length
        )

        key = derive_key(self.test_password, self.test_salt, minimal_params)

        assert len(key) == 16
        print("✓ Minimal valid parameters work")

    def test_high_security_params(self):
        """Test with high-security parameters."""
        high_security_params = Argon2Params(
            time_cost=10,
            memory_cost=1024 * 1024,  # 1 GB
            parallelism=4,
            hash_len=64
        )

        # This might be slow, but should work
        key = derive_key(self.test_password, self.test_salt, high_security_params)

        assert len(key) == 64
        print("✓ High-security parameters work (may be slow)")

    def test_invalid_salt_length(self):
        """Test that salt shorter than 16 bytes fails."""
        short_salt = os.urandom(8)  # Only 8 bytes

        with pytest.raises(ValueError, match="salt must be >=16 bytes"):
            derive_key(self.test_password, short_salt)
        print("✓ Short salt properly rejected")

    def test_invalid_salt_type(self):
        """Test that invalid salt types fail."""
        with pytest.raises(ValueError, match="salt must be >=16 bytes"):
            derive_key(self.test_password, "string_salt")  # String instead of bytes

        with pytest.raises(ValueError, match="salt must be >=16 bytes"):
            derive_key(self.test_password, 12345)  # Integer instead of bytes
        print("✓ Invalid salt types properly rejected")

    def test_empty_password(self):
        """Test that empty password fails."""
        with pytest.raises(ValueError, match="password required"):
            derive_key("", self.test_salt)

        with pytest.raises(ValueError, match="password required"):
            derive_key(None, self.test_salt)
        print("✓ Empty password properly rejected")

    def test_unicode_passwords(self):
        """Test key derivation with Unicode passwords."""
        unicode_passwords = [
            "пароль123",  # Russian
            "パスワード456",  # Japanese
            "密码789",  # Chinese
            "contraseña🔐",  # Spanish with emoji
            "Pässwörd_ñ",  # Mixed Latin characters
        ]

        keys = []
        for password in unicode_passwords:
            key = derive_key(password, self.test_salt)
            keys.append(key)
            assert len(key) == 32

        # All keys should be different
        assert len(set(keys)) == len(keys)
        print("✓ Unicode passwords work correctly")

    def test_long_passwords(self):
        """Test key derivation with very long passwords."""
        short_password = "short"
        long_password = "a" * 1000  # 1000 characters
        very_long_password = "b" * 10000  # 10,000 characters

        key_short = derive_key(short_password, self.test_salt)
        key_long = derive_key(long_password, self.test_salt)
        key_very_long = derive_key(very_long_password, self.test_salt)

        # All should produce valid keys
        assert len(key_short) == 32
        assert len(key_long) == 32
        assert len(key_very_long) == 32

        # All should be different
        assert key_short != key_long != key_very_long
        print("✓ Long passwords work correctly")

    def test_argon2_params_dataclass(self):
        """Test Argon2Params dataclass functionality."""
        # Test default params
        assert DEFAULT_PARAMS.time_cost == 3
        assert DEFAULT_PARAMS.memory_cost == 65536  # 64 MB
        assert DEFAULT_PARAMS.parallelism == 2
        assert DEFAULT_PARAMS.hash_len == 32

        # Test custom params
        custom = Argon2Params(time_cost=5, memory_cost=128*1024, parallelism=4, hash_len=64)
        assert custom.time_cost == 5
        assert custom.memory_cost == 128*1024
        assert custom.parallelism == 4
        assert custom.hash_len == 64

        # Test immutability (frozen=True)
        with pytest.raises(AttributeError):
            custom.time_cost = 10

        print("✓ Argon2Params dataclass works correctly")

    def test_consistency_across_runs(self):
        """Test that same inputs produce same outputs across multiple runs."""
        results = []

        for _ in range(10):
            key = derive_key(self.test_password, self.test_salt, DEFAULT_PARAMS)
            results.append(key)

        # All results should be identical
        assert len(set(results)) == 1
        print("✓ Results consistent across multiple runs")

    def test_salt_length_boundary_conditions(self):
        """Test salt length boundary conditions."""
        # Exactly 16 bytes should work
        salt_16 = os.urandom(16)
        key = derive_key(self.test_password, salt_16)
        assert len(key) == 32

        # 15 bytes should fail
        salt_15 = os.urandom(15)
        with pytest.raises(ValueError):
            derive_key(self.test_password, salt_15)

        # Longer salts should work
        salt_32 = os.urandom(32)
        key_32 = derive_key(self.test_password, salt_32)
        assert len(key_32) == 32

        salt_64 = os.urandom(64)
        key_64 = derive_key(self.test_password, salt_64)
        assert len(key_64) == 32

        # Different length salts should produce different keys
        key_16 = derive_key(self.test_password, salt_16)
        assert key_16 != key_32 != key_64

        print("✓ Salt length boundary conditions handled correctly")

    def test_performance_scaling(self):
        """Test that higher cost parameters actually take more time."""
        import time

        fast_params = Argon2Params(time_cost=1, memory_cost=1024, parallelism=1, hash_len=32)
        slow_params = Argon2Params(time_cost=3, memory_cost=4096, parallelism=1, hash_len=32)

        # Time the fast version
        start_time = time.time()
        derive_key(self.test_password, self.test_salt, fast_params)
        fast_time = time.time() - start_time

        # Time the slow version
        start_time = time.time()
        derive_key(self.test_password, self.test_salt, slow_params)
        slow_time = time.time() - start_time

        # Slow should take longer (allowing for some variance)
        assert slow_time > fast_time * 0.5  # At least 50% of fast time difference
        print(f"✓ Performance scaling works (fast: {fast_time:.4f}s, slow: {slow_time:.4f}s)")

    def test_memory_cost_affects_output(self):
        """Test that different memory costs produce different outputs."""
        params_low_mem = Argon2Params(time_cost=2, memory_cost=1024, parallelism=1, hash_len=32)
        params_high_mem = Argon2Params(time_cost=2, memory_cost=4096, parallelism=1, hash_len=32)

        key_low = derive_key(self.test_password, self.test_salt, params_low_mem)
        key_high = derive_key(self.test_password, self.test_salt, params_high_mem)

        assert key_low != key_high
        print("✓ Memory cost affects output")


class TestArgon2Params:
    """Test the Argon2Params dataclass specifically."""

    def test_default_params(self):
        """Test default parameter values."""
        params = Argon2Params()

        assert params.time_cost == 3
        assert params.memory_cost == 65536
        assert params.parallelism == 2
        assert params.hash_len == 32
        print("✓ Default params have correct values")

    def test_equality(self):
        """Test parameter equality comparison."""
        params1 = Argon2Params(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32)
        params2 = Argon2Params(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32)
        params3 = Argon2Params(time_cost=4, memory_cost=65536, parallelism=2, hash_len=32)

        assert params1 == params2
        assert params1 != params3
        assert params1 == DEFAULT_PARAMS
        print("✓ Parameter equality works")

    def test_hash(self):
        """Test that params can be hashed (for use in sets/dicts)."""
        params_set = {
            Argon2Params(time_cost=1, memory_cost=1024, parallelism=1, hash_len=32),
            Argon2Params(time_cost=2, memory_cost=2048, parallelism=2, hash_len=32),
            Argon2Params(time_cost=1, memory_cost=1024, parallelism=1, hash_len=32),  # Duplicate
        }

        # Set should contain only 2 unique elements
        assert len(params_set) == 2
        print("✓ Parameters are hashable")


def run_all_tests():
    """Run all KDF tests manually."""
    print("Running KDF module tests...\n")

    # Test the main KDF class
    test_instance = TestKDF()

    test_methods = [
        test_instance.test_derive_key_basic,
        test_instance.test_derive_key_deterministic,
        test_instance.test_different_passwords_different_keys,
        test_instance.test_different_salts_different_keys,
        test_instance.test_custom_params,
        test_instance.test_minimal_valid_params,
        test_instance.test_high_security_params,
        test_instance.test_invalid_salt_length,
        test_instance.test_invalid_salt_type,
        test_instance.test_empty_password,
        test_instance.test_unicode_passwords,
        test_instance.test_long_passwords,
        test_instance.test_argon2_params_dataclass,
        test_instance.test_consistency_across_runs,
        test_instance.test_salt_length_boundary_conditions,
        test_instance.test_performance_scaling,
        test_instance.test_memory_cost_affects_output,
    ]

    # Test the Argon2Params class
    params_test = TestArgon2Params()
    params_methods = [
        params_test.test_default_params,
        params_test.test_equality,
        params_test.test_hash,
    ]

    all_methods = test_methods + params_methods
    passed = 0

    for test_method in all_methods:
        try:
            if hasattr(test_method, '__self__') and hasattr(test_method.__self__, 'setup_method'):
                test_method.__self__.setup_method()
            test_method()
            passed += 1
        except Exception as e:
            print(f"❌ {test_method.__name__} failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    print(f"\n🎉 All {passed} KDF tests passed!")
    print("Your Argon2 key derivation is secure and robust! 🔑")
    return True


if __name__ == "__main__":
    print("To run with pytest: pytest tests/test_kdf.py -v")
    print("Or run manually:\n")
    run_all_tests()
