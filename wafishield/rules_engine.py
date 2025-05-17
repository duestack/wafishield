"""
Rules Engine module for detecting and blocking rule violations.
"""

import os
import re
import yaml
import logging
from typing import Dict, Any, List, Optional, Callable, Union

from .utils import validate_yaml_against_schema, get_package_dir, load_yaml_file


class RulesEngine:
    """
    Rules Engine for loading and evaluating rules.

    The Rules Engine handles:
    1. Loading rule definitions from YAML files
    2. Evaluating prompts against these rules
    3. Supporting custom rule registrations
    4. Supporting multilingual rule patterns

    Args:
        rules_dir: Optional path to directory containing YAML rule definitions
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.logger = logging.getLogger("wafishield.rules")
        self.rules = []
        self.rule_callbacks = {}

        # Default rules directory is within the package
        if not rules_dir:
            rules_dir = os.path.join(get_package_dir(), "rules")

        # Load default rules if directory exists and contains YAML files
        if os.path.exists(rules_dir):
            yaml_files = [
                f
                for f in os.listdir(rules_dir)
                if f.endswith(".yml") or f.endswith(".yaml")
            ]
            for yaml_file in yaml_files:
                try:
                    file_path = os.path.join(rules_dir, yaml_file)
                    rules_data = load_yaml_file(file_path)

                    # Validate rules against schema
                    validate_yaml_against_schema(rules_data, "rules")

                    # Add rules to the registry
                    if isinstance(rules_data, list):
                        self.rules.extend(rules_data)
                    else:
                        self.rules.append(rules_data)

                    self.logger.info(f"Loaded rules from {yaml_file}")
                except Exception as e:
                    self.logger.error(f"Error loading rules from {yaml_file}: {str(e)}")

    def register_rule(
        self, rule: Union[Dict[str, Any], str], callback: Optional[Callable] = None
    ):
        """
        Register a custom rule or a custom callback for an existing rule.

        Args:
            rule: Either a complete rule definition dictionary or a rule ID string
            callback: Optional callback function to be called when the rule is triggered

        Raises:
            ValueError: If the rule is invalid or if the rule ID is not found
        """
        if isinstance(rule, dict):
            # Validate the rule structure
            required_fields = ["id", "description", "type"]
            for field in required_fields:
                if field not in rule:
                    raise ValueError(f"Rule must contain a '{field}' field")

            # Add the rule to the registry
            # Check if rule with the same ID already exists
            existing_rule_index = None
            for i, r in enumerate(self.rules):
                if r["id"] == rule["id"]:
                    existing_rule_index = i
                    break

            if existing_rule_index is not None:
                self.rules[existing_rule_index] = rule
                self.logger.info(f"Updated rule {rule['id']}")
            else:
                self.rules.append(rule)
                self.logger.info(f"Added new rule {rule['id']}")

            # Register callback if provided
            if callback:
                self.rule_callbacks[rule["id"]] = callback

        elif isinstance(rule, str):
            # Register callback for existing rule ID
            rule_id = rule
            rule_exists = any(r["id"] == rule_id for r in self.rules)
            if not rule_exists:
                raise ValueError(f"Rule with ID '{rule_id}' not found")

            if callback:
                self.rule_callbacks[rule_id] = callback
                self.logger.info(f"Registered callback for rule {rule_id}")
            else:
                raise ValueError(
                    "Callback function must be provided when registering by rule ID"
                )
        else:
            raise ValueError("Rule must be either a dictionary or a string ID")

    def evaluate(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate a text against the rules.

        Args:
            text: The text to evaluate
            context: Optional context for the evaluation

        Returns:
            A dictionary containing the evaluation result:
            - is_safe: Whether the text passes all rules
            - violations: List of rules that were violated
            - continue_evaluation: Whether to continue evaluation after rule violations
        """
        result = {"is_safe": True, "violations": [], "continue_evaluation": True}

        if not context:
            context = {}

        # Check for whitelist matches first
        whitelist_match = False
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            if rule["type"] == "whitelist":
                if self._match_rule_pattern(rule, text):
                    whitelist_match = True
                    self.logger.debug(f"Whitelist rule {rule['id']} matched")

                    # Call the callback if registered
                    if rule["id"] in self.rule_callbacks:
                        try:
                            self.rule_callbacks[rule["id"]](rule, text, context)
                        except Exception as e:
                            self.logger.error(
                                f"Error in rule callback for {rule['id']}: {str(e)}"
                            )

                    # Early return if whitelist is matched and rule specifies to allow
                    if rule.get("action", "allow") == "allow":
                        return result

        # If no whitelist matches, check blacklist rules
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            if rule["type"] == "blacklist" and self._match_rule_pattern(rule, text):
                result["is_safe"] = False
                violation = {
                    "id": rule["id"],
                    "description": rule["description"],
                    "action": rule.get("action", "deny"),
                }
                result["violations"].append(violation)
                self.logger.info(
                    f"Rule violation: {rule['id']} - {rule['description']}"
                )

                # Call the callback if registered
                if rule["id"] in self.rule_callbacks:
                    try:
                        callback_result = self.rule_callbacks[rule["id"]](
                            rule, text, context
                        )
                        # Allow callback to override continue_evaluation
                        if (
                            isinstance(callback_result, dict)
                            and "continue_evaluation" in callback_result
                        ):
                            result["continue_evaluation"] = callback_result[
                                "continue_evaluation"
                            ]
                    except Exception as e:
                        self.logger.error(
                            f"Error in rule callback for {rule['id']}: {str(e)}"
                        )

                # If action is deny and continue_evaluation is not explicitly set to True,
                # stop evaluation
                if rule.get("action", "deny") == "deny" and not rule.get(
                    "continue_evaluation", False
                ):
                    result["continue_evaluation"] = False
                    break

        # If no violation found but whitelist is required and no whitelist matched,
        # mark as unsafe
        if (
            result["is_safe"]
            and any(
                r["type"] == "whitelist" and r.get("required", False)
                for r in self.rules
            )
            and not whitelist_match
        ):
            result["is_safe"] = False
            result["violations"].append(
                {
                    "id": "NO_WHITELIST_MATCH",
                    "description": "Required whitelist match not found",
                    "action": "deny",
                }
            )
            result["continue_evaluation"] = False

        return result

    def _match_rule_pattern(self, rule: Dict[str, Any], text: str) -> bool:
        """
        Check if the text matches the rule pattern.
        Supports multilingual patterns.

        Args:
            rule: The rule to check
            text: The text to match against

        Returns:
            True if the text matches the rule pattern
        """
        # Check for direct pattern field (backward compatibility)
        if "pattern" in rule:
            try:
                if re.search(rule["pattern"], text, re.IGNORECASE | re.DOTALL):
                    return True
            except Exception as e:
                self.logger.error(
                    f"Error matching pattern in rule {rule['id']}: {str(e)}"
                )

        # Check multilingual patterns
        languages = [
            "english",
            "arabic",
            "french",
            "spanish",
            "chinese",
            "russian",
            "hindi",
            "portuguese",
            "japanese",
            "german",
        ]

        for lang in languages:
            pattern_key = f"{lang}_pattern"
            if pattern_key in rule:
                try:
                    if re.search(rule[pattern_key], text, re.IGNORECASE | re.DOTALL):
                        return True
                except Exception as e:
                    self.logger.error(
                        f"Error matching {lang} pattern in rule {rule['id']}: {str(e)}"
                    )

        return False
