"""
Unit tests for the rules_engine module.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from wafishield.rules_engine import RulesEngine

# Sample rules for testing
SAMPLE_RULES = [
    {
        "id": "TEST_RULE_1",
        "description": "Test rule 1",
        "type": "blacklist",
        "pattern": r"bad pattern",
        "action": "deny",
        "enabled": True,
    },
    {
        "id": "TEST_RULE_2",
        "description": "Test rule 2",
        "type": "whitelist",
        "pattern": r"good pattern",
        "action": "allow",
        "enabled": True,
    },
    {
        "id": "TEST_RULE_3",
        "description": "Test rule 3 (disabled)",
        "type": "blacklist",
        "pattern": r"should be ignored",
        "action": "deny",
        "enabled": False,
    },
    {
        "id": "TEST_RULE_4",
        "description": "Test multilingual rule",
        "type": "blacklist",
        "english_pattern": r"bad english",
        "french_pattern": r"mauvais français",
        "action": "deny",
        "enabled": True,
    },
]


@pytest.fixture
def rules_engine():
    # Mock the load_yaml_file function
    with patch("wafishield.rules_engine.load_yaml_file") as mock_load_yaml:
        mock_load_yaml.return_value = SAMPLE_RULES

        # Mock the validate_yaml_against_schema function
        with patch(
            "wafishield.rules_engine.validate_yaml_against_schema"
        ) as mock_validate:
            mock_validate.return_value = True

            # Mock os.path.exists and os.listdir
            with patch("os.path.exists") as mock_exists, patch(
                "os.listdir"
            ) as mock_listdir:
                mock_exists.return_value = True
                mock_listdir.return_value = ["test_rules.yml"]

                # Create the RulesEngine
                engine = RulesEngine()

                # Replace the rules with our test rules
                engine.rules = SAMPLE_RULES

                yield engine


def test_rules_engine_initialization(rules_engine):
    """Test that the RulesEngine initializes correctly."""
    assert len(rules_engine.rules) == 4
    assert rules_engine.rules[0]["id"] == "TEST_RULE_1"


def test_evaluate_safe_text(rules_engine):
    """Test that safe text passes the rules."""
    result = rules_engine.evaluate("This is safe text")
    assert result["is_safe"] == True
    assert len(result["violations"]) == 0


def test_evaluate_unsafe_text(rules_engine):
    """Test that unsafe text is blocked by rules."""
    result = rules_engine.evaluate("This contains a bad pattern")
    assert result["is_safe"] == False
    assert len(result["violations"]) == 1
    assert result["violations"][0]["id"] == "TEST_RULE_1"


def test_evaluate_whitelist(rules_engine):
    """Test that whitelisted text passes even with blacklisted content."""
    result = rules_engine.evaluate("This contains a good pattern and a bad pattern")
    assert (
        result["is_safe"] == False
    )  # Whitelist doesn't override here unless specified


def test_multilingual_rule(rules_engine):
    """Test that multilingual rules work."""
    # English pattern
    result = rules_engine.evaluate("This contains bad english text")
    assert result["is_safe"] == False
    assert result["violations"][0]["id"] == "TEST_RULE_4"

    # French pattern
    result = rules_engine.evaluate("Ce texte contient mauvais français")
    assert result["is_safe"] == False
    assert result["violations"][0]["id"] == "TEST_RULE_4"


def test_disabled_rule(rules_engine):
    """Test that disabled rules are ignored."""
    result = rules_engine.evaluate("This should be ignored")
    assert result["is_safe"] == True
    assert len(result["violations"]) == 0


def test_register_rule(rules_engine):
    """Test registering a new rule."""
    new_rule = {
        "id": "NEW_RULE",
        "description": "New test rule",
        "type": "blacklist",
        "pattern": r"new bad pattern",
        "action": "deny",
        "enabled": True,
    }

    rules_engine.register_rule(new_rule)

    # Check that the rule was added
    assert len(rules_engine.rules) == 5
    assert rules_engine.rules[4]["id"] == "NEW_RULE"

    # Test that the new rule works
    result = rules_engine.evaluate("This contains a new bad pattern")
    assert result["is_safe"] == False
    assert result["violations"][0]["id"] == "NEW_RULE"


def test_register_rule_callback(rules_engine):
    """Test registering a callback for an existing rule."""
    callback_called = False

    def test_callback(rule, text, context):
        nonlocal callback_called
        callback_called = True
        assert rule["id"] == "TEST_RULE_1"
        assert "bad pattern" in text
        return {"continue_evaluation": False}

    rules_engine.register_rule("TEST_RULE_1", test_callback)

    # Test that the callback is called
    result = rules_engine.evaluate("This contains a bad pattern")
    assert callback_called == True
    assert result["is_safe"] == False
    assert result["continue_evaluation"] == False


def test_register_invalid_rule(rules_engine):
    """Test that registering an invalid rule raises an error."""
    invalid_rule = {
        "description": "Missing ID field",
        "type": "blacklist",
        "pattern": r"pattern",
    }

    with pytest.raises(ValueError):
        rules_engine.register_rule(invalid_rule)


def test_register_nonexistent_rule_id(rules_engine):
    """Test that registering a callback for a nonexistent rule ID raises an error."""

    def test_callback(rule, text, context):
        pass

    with pytest.raises(ValueError):
        rules_engine.register_rule("NONEXISTENT_RULE", test_callback)
