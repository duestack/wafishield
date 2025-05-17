"""
Unit tests for the sanitizer_engine module.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from wafishield.sanitizer_engine import SanitizerEngine

# Sample patterns for testing
SAMPLE_PATTERNS = [
    {
        "id": "TEST_PII_EMAIL",
        "description": "Test email pattern",
        "type": "regex",
        "pattern": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "replacement": "[REDACTED_EMAIL]",
        "action": "redact",
        "enabled": True,
    },
    {
        "id": "TEST_PII_PHONE",
        "description": "Test phone pattern",
        "type": "regex",
        "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
        "replacement": "[REDACTED_PHONE]",
        "action": "redact",
        "enabled": True,
    },
    {
        "id": "TEST_PATTERN_DISABLED",
        "description": "Test disabled pattern",
        "type": "regex",
        "pattern": r"should be ignored",
        "replacement": "[IGNORED]",
        "action": "redact",
        "enabled": False,
    },
    {
        "id": "TEST_MULTILINGUAL",
        "description": "Test multilingual pattern",
        "type": "regex",
        "english_pattern": r"confidential \w+",
        "french_pattern": r"confidentiel \w+",
        "replacement": "[REDACTED_CONFIDENTIAL]",
        "action": "redact",
        "enabled": True,
    },
]


@pytest.fixture
def sanitizer_engine():
    # Mock the load_yaml_file function
    with patch("wafishield.sanitizer_engine.load_yaml_file") as mock_load_yaml:
        mock_load_yaml.return_value = SAMPLE_PATTERNS

        # Mock the validate_yaml_against_schema function
        with patch(
            "wafishield.sanitizer_engine.validate_yaml_against_schema"
        ) as mock_validate:
            mock_validate.return_value = True

            # Mock os.path.exists and os.listdir
            with patch("os.path.exists") as mock_exists, patch(
                "os.listdir"
            ) as mock_listdir:
                mock_exists.return_value = True
                mock_listdir.return_value = ["test_patterns.yml"]

                # Create the SanitizerEngine
                engine = SanitizerEngine()

                # Replace the patterns with our test patterns
                engine.patterns = SAMPLE_PATTERNS

                yield engine


def test_sanitizer_engine_initialization(sanitizer_engine):
    """Test that the SanitizerEngine initializes correctly."""
    assert len(sanitizer_engine.patterns) == 4
    assert sanitizer_engine.patterns[0]["id"] == "TEST_PII_EMAIL"


def test_sanitize_clean_text(sanitizer_engine):
    """Test that clean text is not modified."""
    text = "This text has no sensitive information."
    result = sanitizer_engine.sanitize(text)
    assert result["sanitized_text"] == text
    assert len(result["patterns_matched"]) == 0
    assert result["match_count"] == 0


def test_sanitize_email(sanitizer_engine):
    """Test that emails are redacted."""
    text = "My email is john.doe@example.com"
    result = sanitizer_engine.sanitize(text)
    assert "john.doe@example.com" not in result["sanitized_text"]
    assert "[REDACTED_EMAIL]" in result["sanitized_text"]
    assert "TEST_PII_EMAIL" in result["patterns_matched"]
    assert result["match_count"] == 1


def test_sanitize_phone(sanitizer_engine):
    """Test that phone numbers are redacted."""
    text = "My phone number is 555-123-4567"
    result = sanitizer_engine.sanitize(text)
    assert "555-123-4567" not in result["sanitized_text"]
    assert "[REDACTED_PHONE]" in result["sanitized_text"]
    assert "TEST_PII_PHONE" in result["patterns_matched"]
    assert result["match_count"] == 1


def test_sanitize_multiple_patterns(sanitizer_engine):
    """Test that multiple patterns are redacted."""
    text = "My email is john.doe@example.com and my phone is 555-123-4567"
    result = sanitizer_engine.sanitize(text)
    assert "john.doe@example.com" not in result["sanitized_text"]
    assert "555-123-4567" not in result["sanitized_text"]
    assert "[REDACTED_EMAIL]" in result["sanitized_text"]
    assert "[REDACTED_PHONE]" in result["sanitized_text"]
    assert "TEST_PII_EMAIL" in result["patterns_matched"]
    assert "TEST_PII_PHONE" in result["patterns_matched"]
    assert result["match_count"] == 2


def test_disabled_pattern(sanitizer_engine):
    """Test that disabled patterns are ignored."""
    text = "This should be ignored"
    result = sanitizer_engine.sanitize(text)
    assert result["sanitized_text"] == text
    assert len(result["patterns_matched"]) == 0
    assert result["match_count"] == 0


def test_multilingual_pattern(sanitizer_engine):
    """Test that multilingual patterns work."""
    # English pattern
    text = "This contains confidential information"
    result = sanitizer_engine.sanitize(text)
    assert "confidential information" not in result["sanitized_text"]
    assert "[REDACTED_CONFIDENTIAL]" in result["sanitized_text"]

    # French pattern
    text = "Ceci contient confidentiel information"
    result = sanitizer_engine.sanitize(text)
    assert "confidentiel information" not in result["sanitized_text"]
    assert "[REDACTED_CONFIDENTIAL]" in result["sanitized_text"]


def test_register_pattern(sanitizer_engine):
    """Test registering a new pattern."""
    new_pattern = {
        "id": "NEW_PATTERN",
        "description": "New test pattern",
        "type": "regex",
        "pattern": r"secret\s+\w+",
        "replacement": "[REDACTED_SECRET]",
        "action": "redact",
        "enabled": True,
    }

    sanitizer_engine.register_pattern(new_pattern)

    # Check that the pattern was added
    assert len(sanitizer_engine.patterns) == 5
    assert sanitizer_engine.patterns[4]["id"] == "NEW_PATTERN"

    # Test that the new pattern works
    text = "This contains secret information"
    result = sanitizer_engine.sanitize(text)
    assert "secret information" not in result["sanitized_text"]
    assert "[REDACTED_SECRET]" in result["sanitized_text"]
    assert "NEW_PATTERN" in result["patterns_matched"]


def test_register_pattern_callback(sanitizer_engine):
    """Test registering a callback for an existing pattern."""
    callback_called = False

    def test_callback(pattern, original_text, sanitized_text, matches, context):
        nonlocal callback_called
        callback_called = True
        assert pattern["id"] == "TEST_PII_EMAIL"
        assert "john.doe@example.com" in original_text
        assert "[REDACTED_EMAIL]" in sanitized_text
        return "CUSTOM " + sanitized_text

    sanitizer_engine.register_pattern("TEST_PII_EMAIL", test_callback)

    # Test that the callback is called
    text = "My email is john.doe@example.com"
    result = sanitizer_engine.sanitize(text)
    assert callback_called == True
    assert result["sanitized_text"].startswith("CUSTOM ")


def test_register_custom_pattern_type(sanitizer_engine):
    """Test registering a custom pattern type."""
    custom_pattern = {
        "id": "CUSTOM_TYPE",
        "description": "Custom pattern type",
        "type": "custom",
        "enabled": True,
    }

    def custom_callback(pattern, original_text, sanitized_text, matches, context):
        if "custom keyword" in original_text:
            return original_text.replace("custom keyword", "[CUSTOM_REPLACED]")
        return sanitized_text

    sanitizer_engine.register_pattern(custom_pattern, custom_callback)

    # Test that the custom pattern works
    text = "This text has a custom keyword that should be replaced"
    result = sanitizer_engine.sanitize(text)
    assert "custom keyword" not in result["sanitized_text"]
    assert "[CUSTOM_REPLACED]" in result["sanitized_text"]
    assert "CUSTOM_TYPE" in result["patterns_matched"]


def test_register_invalid_pattern(sanitizer_engine):
    """Test that registering an invalid pattern raises an error."""
    invalid_pattern = {
        "description": "Missing ID field",
        "type": "regex",
        "pattern": r"pattern",
    }

    with pytest.raises(ValueError):
        sanitizer_engine.register_pattern(invalid_pattern)


def test_register_nonexistent_pattern_id(sanitizer_engine):
    """Test that registering a callback for a nonexistent pattern ID raises an error."""

    def test_callback(pattern, original_text, sanitized_text, matches, context):
        pass

    with pytest.raises(ValueError):
        sanitizer_engine.register_pattern("NONEXISTENT_PATTERN", test_callback)
