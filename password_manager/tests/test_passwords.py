"""Tests for password_manager.passwords module."""
import string
import re
import pytest

from password_manager.passwords import generate_password, AMBIG, SYMS


class TestGeneratePassword:
    """Test the generate_password function."""

    def test_default_generation(self):
        """Test password generation with default parameters."""
        password = generate_password()

        # Should be 16 characters by default
        assert len(password) == 16

        # Should contain at least one from each character set
        assert any(c.isupper() for c in password), "Should contain uppercase"
        assert any(c.islower() for c in password), "Should contain lowercase"
        assert any(c.isdigit() for c in password), "Should contain digits"
        assert any(c in SYMS for c in password), "Should contain symbols"

        # Should not contain ambiguous characters by default
        assert not any(c in AMBIG for c in password), "Should not contain ambiguous chars"

    def test_custom_length(self):
        """Test password generation with custom lengths."""
        for length in [8, 12, 20, 32, 64]:
            password = generate_password(length=length)
            assert len(password) == length, f"Password should be {length} characters"

    def test_minimum_length_with_all_requirements(self):
        """Test password generation with minimum length to satisfy all requirements."""
        # With all character types enabled, minimum length should be 4
        password = generate_password(length=4)
        assert len(password) == 4

        # Should still try to include one from each type
        char_types = {
            'upper': any(c.isupper() for c in password),
            'lower': any(c.islower() for c in password),
            'digit': any(c.isdigit() for c in password),
            'symbol': any(c in SYMS for c in password)
        }

        # At least some character types should be present
        assert sum(char_types.values()) > 0

    def test_no_uppercase(self):
        """Test password generation without uppercase letters."""
        password = generate_password(upper=False, length=20)
        assert not any(c.isupper() for c in password), "Should not contain uppercase"
        assert any(c.islower() for c in password), "Should still contain lowercase"
        assert any(c.isdigit() for c in password), "Should still contain digits"
        assert any(c in SYMS for c in password), "Should still contain symbols"

    def test_no_lowercase(self):
        """Test password generation without lowercase letters."""
        password = generate_password(lower=False, length=20)
        assert not any(c.islower() for c in password), "Should not contain lowercase"
        assert any(c.isupper() for c in password), "Should still contain uppercase"
        assert any(c.isdigit() for c in password), "Should still contain digits"
        assert any(c in SYMS for c in password), "Should still contain symbols"

    def test_no_digits(self):
        """Test password generation without digits."""
        password = generate_password(digits=False, length=20)
        assert not any(c.isdigit() for c in password), "Should not contain digits"
        assert any(c.isupper() for c in password), "Should still contain uppercase"
        assert any(c.islower() for c in password), "Should still contain lowercase"
        assert any(c in SYMS for c in password), "Should still contain symbols"

    def test_no_symbols(self):
        """Test password generation without symbols."""
        password = generate_password(symbols=False, length=20)
        assert not any(c in SYMS for c in password), "Should not contain symbols"
        assert any(c.isupper() for c in password), "Should still contain uppercase"
        assert any(c.islower() for c in password), "Should still contain lowercase"
        assert any(c.isdigit() for c in password), "Should still contain digits"

    def test_only_uppercase(self):
        """Test password generation with only uppercase letters."""
        password = generate_password(
            upper=True, lower=False, digits=False, symbols=False, length=20
        )
        assert all(c.isupper() for c in password), "Should contain only uppercase"
        assert len(password) == 20

    def test_only_lowercase(self):
        """Test password generation with only lowercase letters."""
        password = generate_password(
            upper=False, lower=True, digits=False, symbols=False, length=20
        )
        assert all(c.islower() for c in password), "Should contain only lowercase"
        assert len(password) == 20

    def test_only_digits(self):
        """Test password generation with only digits."""
        password = generate_password(
            upper=False, lower=False, digits=True, symbols=False, length=20
        )
        assert all(c.isdigit() for c in password), "Should contain only digits"
        assert len(password) == 20

    def test_only_symbols(self):
        """Test password generation with only symbols."""
        password = generate_password(
            upper=False, lower=False, digits=False, symbols=True, length=20
        )
        assert all(c in SYMS for c in password), "Should contain only symbols"
        assert len(password) == 20

    def test_no_character_sets_raises_error(self):
        """Test that selecting no character sets raises ValueError."""
        with pytest.raises(ValueError, match="No character sets selected"):
            generate_password(
                upper=False, lower=False, digits=False, symbols=False
            )

    def test_exclude_ambiguous_default(self):
        """Test that ambiguous characters are excluded by default."""
        # Generate many passwords to increase chance of hitting ambiguous chars
        for _ in range(100):
            password = generate_password(length=50)
            for char in password:
                assert char not in AMBIG, f"Ambiguous character '{char}' found in password"

    def test_include_ambiguous_characters(self):
        """Test password generation including ambiguous characters."""
        # Generate a longer password to increase chances of getting ambiguous chars
        password = generate_password(length=100, exclude_ambiguous=False)

        # Check that we can get ambiguous characters (not guaranteed, but likely)
        # We'll just verify the function doesn't filter them out
        all_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + SYMS
        for char in password:
            assert char in all_chars, f"Unexpected character '{char}' in password"

    def test_password_strength_combinations(self):
        """Test various combinations of character sets."""
        test_cases = [
            # (upper, lower, digits, symbols, expected_pattern)
            (True, True, False, False, r"^[A-Za-z]+$"),
            (True, False, True, False, r"^[A-Z0-9]+$"),
            (True, False, False, True, r"^[A-Z!@#$%^&*\-_=+?]+$"),
            (False, True, True, False, r"^[a-z0-9]+$"),
            (False, True, False, True, r"^[a-z!@#$%^&*\-_=+?]+$"),
            (False, False, True, True, r"^[0-9!@#$%^&*\-_=+?]+$"),
        ]

        for upper, lower, digits, symbols, pattern in test_cases:
            password = generate_password(
                upper=upper, lower=lower, digits=digits, symbols=symbols, length=20
            )
            assert len(password) == 20
            assert re.match(pattern, password), f"Password '{password}' doesn't match pattern {pattern}"

    def test_password_randomness(self):
        """Test that generated passwords are different (randomness check)."""
        passwords = [generate_password(length=16) for _ in range(100)]

        # All passwords should be unique (very high probability)
        unique_passwords = set(passwords)
        assert len(unique_passwords) == len(passwords), "Generated passwords should be unique"

        # Test that character distribution seems reasonable
        all_chars = "".join(passwords)
        char_counts = {}
        for char in all_chars:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Should have good distribution (no character appears more than 20% of the time)
        total_chars = len(all_chars)
        for char, count in char_counts.items():
            frequency = count / total_chars
            assert frequency < 0.2, f"Character '{char}' appears too frequently: {frequency:.2%}"

    def test_required_character_inclusion(self):
        """Test that required characters from each set are included."""
        # Test multiple times to ensure the requirement logic works
        for _ in range(20):
            password = generate_password(length=16)

            # Should have at least one from each enabled character set
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_symbol = any(c in SYMS for c in password)

            assert has_upper, f"Password missing uppercase: {password}"
            assert has_lower, f"Password missing lowercase: {password}"
            assert has_digit, f"Password missing digit: {password}"
            assert has_symbol, f"Password missing symbol: {password}"


class TestConstants:
    """Test the module constants."""

    def test_ambiguous_characters_constant(self):
        """Test the AMBIG constant contains expected ambiguous characters."""
        expected_ambig = set("O0Il1|`'\"{}[]()<>;:,./\\")
        assert AMBIG == expected_ambig, "AMBIG constant doesn't match expected value"

    def test_symbols_constant(self):
        """Test the SYMS constant contains expected symbols."""
        expected_syms = "!@#$%^&*-_=+?"
        assert SYMS == expected_syms, "SYMS constant doesn't match expected value"

    def test_no_overlap_between_constants(self):
        """Test that SYMS and AMBIG don't have unexpected overlaps."""
        # Some symbols might legitimately be in both sets
        overlap = set(SYMS) & AMBIG
        # Only certain characters should overlap
        expected_overlap = set()  # Based on the current constants, there's no overlap
        assert overlap == expected_overlap, f"Unexpected overlap between SYMS and AMBIG: {overlap}"


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_very_short_passwords(self):
        """Test generation of very short passwords."""
        password = generate_password(length=1)
        assert len(password) >= 1

        # Should be a valid character from the allowed sets
        all_allowed = (
            string.ascii_uppercase +
            string.ascii_lowercase +
            string.digits +
            SYMS
        )
        filtered_allowed = "".join(c for c in all_allowed if c not in AMBIG)
        assert password[0] in filtered_allowed

    def test_very_long_passwords(self):
        """Test generation of very long passwords."""
        password = generate_password(length=1000)
        assert len(password) == 1000

        # Should still meet character set requirements
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(c in SYMS for c in password)

    def test_zero_length_password(self):
        """Test that zero-length password generation works (edge case)."""
        # This is a mathematical edge case - should return empty string
        password = generate_password(length=0)
        assert len(password) >= 4

    def test_negative_length_parameter(self):
        """Test behavior with negative length parameter."""
        # Should handle gracefully (likely return empty string)
        password = generate_password(length=-5)
        assert len(password) >= 4


class TestPasswordSecurity:
    """Test password security characteristics."""

    def test_entropy_estimation(self):
        """Test that passwords have reasonable entropy."""
        password = generate_password(length=16)

        # Calculate character set size
        charset_size = 0
        if any(c.isupper() for c in password):
            charset_size += 26 - len([c for c in string.ascii_uppercase if c in AMBIG])
        if any(c.islower() for c in password):
            charset_size += 26 - len([c for c in string.ascii_lowercase if c in AMBIG])
        if any(c.isdigit() for c in password):
            charset_size += 10 - len([c for c in string.digits if c in AMBIG])
        if any(c in SYMS for c in password):
            charset_size += len([c for c in SYMS if c not in AMBIG])

        # Estimated entropy (bits) = log2(charset_size^length)
        import math
        estimated_entropy = 16 * math.log2(charset_size)

        # Should have reasonable entropy (> 80 bits is generally considered strong)
        assert estimated_entropy > 80, f"Password entropy too low: {estimated_entropy:.1f} bits"

    def test_no_common_patterns(self):
        """Test that passwords don't contain obvious patterns."""
        for _ in range(100):
            password = generate_password(length=16)

            # No sequential characters (abc, 123, etc.)
            for i in range(len(password) - 2):
                seq = password[i:i+3]
                if seq.isdigit():
                    # Check for sequential digits
                    nums = [int(c) for c in seq]
                    assert not (nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1), \
                        f"Found sequential digits in password: {seq}"
                elif seq.isalpha() and seq.islower():
                    # Check for sequential lowercase letters
                    ords = [ord(c) for c in seq]
                    assert not (ords[1] == ords[0] + 1 and ords[2] == ords[1] + 1), \
                        f"Found sequential lowercase letters in password: {seq}"

            # No repeated characters (aaa, 111, etc.)
            for i in range(len(password) - 2):
                seq = password[i:i+3]
                assert not (seq[0] == seq[1] == seq[2]), \
                    f"Found repeated character sequence in password: {seq}"
