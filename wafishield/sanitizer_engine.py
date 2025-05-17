"""
Sanitizer Engine module for detecting and sanitizing sensitive information.
"""

import os
import re
import yaml
import logging
from typing import Dict, Any, List, Optional, Callable, Union

from .utils import validate_yaml_against_schema, get_package_dir, load_yaml_file


class SanitizerEngine:
    """
    Sanitizer Engine for loading and applying sanitization patterns.

    The Sanitizer Engine handles:
    1. Loading sanitizer patterns from YAML files
    2. Sanitizing text by replacing sensitive information with redacted placeholders
    3. Supporting custom pattern registrations
    4. Supporting multilingual pattern detection

    Args:
        patterns_dir: Optional path to directory containing YAML pattern definitions
    """

    def __init__(self, patterns_dir: Optional[str] = None):
        self.logger = logging.getLogger("wafishield.sanitizer")
        self.patterns = []
        self.pattern_callbacks = {}

        # Default patterns directory is within the package
        if not patterns_dir:
            patterns_dir = os.path.join(get_package_dir(), "patterns")

        # Load default patterns if directory exists and contains YAML files
        if os.path.exists(patterns_dir):
            yaml_files = [
                f
                for f in os.listdir(patterns_dir)
                if f.endswith(".yml") or f.endswith(".yaml")
            ]
            for yaml_file in yaml_files:
                try:
                    file_path = os.path.join(patterns_dir, yaml_file)
                    patterns_data = load_yaml_file(file_path)

                    # Validate patterns against schema
                    validate_yaml_against_schema(patterns_data, "patterns")

                    # Add patterns to the registry
                    if isinstance(patterns_data, list):
                        self.patterns.extend(patterns_data)
                    else:
                        self.patterns.append(patterns_data)

                    self.logger.info(f"Loaded patterns from {yaml_file}")
                except Exception as e:
                    self.logger.error(
                        f"Error loading patterns from {yaml_file}: {str(e)}"
                    )

    def register_pattern(
        self, pattern: Union[Dict[str, Any], str], callback: Optional[Callable] = None
    ):
        """
        Register a custom sanitizer pattern or a callback for an existing pattern.

        Args:
            pattern: Either a complete pattern definition dictionary or a pattern ID string
            callback: Optional callback function to be called when the pattern is matched

        Raises:
            ValueError: If the pattern is invalid or if the pattern ID is not found
        """
        if isinstance(pattern, dict):
            # Validate the pattern structure
            required_fields = ["id", "description", "type"]
            for field in required_fields:
                if field not in pattern:
                    raise ValueError(f"Pattern must contain a '{field}' field")

            # Add the pattern to the registry
            # Check if pattern with the same ID already exists
            existing_pattern_index = None
            for i, p in enumerate(self.patterns):
                if p["id"] == pattern["id"]:
                    existing_pattern_index = i
                    break

            if existing_pattern_index is not None:
                self.patterns[existing_pattern_index] = pattern
                self.logger.info(f"Updated pattern {pattern['id']}")
            else:
                self.patterns.append(pattern)
                self.logger.info(f"Added new pattern {pattern['id']}")

            # Register callback if provided
            if callback:
                self.pattern_callbacks[pattern["id"]] = callback

        elif isinstance(pattern, str):
            # Register callback for existing pattern ID
            pattern_id = pattern
            pattern_exists = any(p["id"] == pattern_id for p in self.patterns)
            if not pattern_exists:
                raise ValueError(f"Pattern with ID '{pattern_id}' not found")

            if callback:
                self.pattern_callbacks[pattern_id] = callback
                self.logger.info(f"Registered callback for pattern {pattern_id}")
            else:
                raise ValueError(
                    "Callback function must be provided when registering by pattern ID"
                )
        else:
            raise ValueError("Pattern must be either a dictionary or a string ID")

    def sanitize(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Sanitize sensitive information in the text.

        Args:
            text: The text to sanitize
            context: Optional context for sanitization

        Returns:
            A dictionary containing the sanitization result:
            - sanitized_text: The sanitized text with sensitive information replaced
            - patterns_matched: List of pattern IDs that were matched and applied
            - match_count: Number of pattern matches
        """
        if not context:
            context = {}

        sanitized_text = text
        patterns_matched = []
        match_count = 0

        for pattern in self.patterns:
            if not pattern.get("enabled", True):
                continue

            pattern_type = pattern.get("type", "regex")
            action = pattern.get("action", "redact")
            replacement = pattern.get("replacement", f"[REDACTED_{pattern['id']}]")

            if pattern_type == "regex":
                # Apply the regex pattern and count matches
                try:
                    if "pattern" in pattern:
                        regex_pattern = pattern["pattern"]
                        matches = list(
                            re.finditer(
                                regex_pattern, sanitized_text, re.IGNORECASE | re.DOTALL
                            )
                        )
                        if matches:
                            patterns_matched.append(pattern["id"])
                            match_count += len(matches)

                            # Apply replacement
                            if action == "redact":
                                sanitized_text = re.sub(
                                    regex_pattern,
                                    replacement,
                                    sanitized_text,
                                    flags=re.IGNORECASE | re.DOTALL,
                                )

                            # Call the callback if registered
                            if pattern["id"] in self.pattern_callbacks:
                                try:
                                    callback_result = self.pattern_callbacks[
                                        pattern["id"]
                                    ](pattern, text, sanitized_text, matches, context)
                                    # Allow callback to override the sanitized text
                                    if callback_result and isinstance(
                                        callback_result, str
                                    ):
                                        sanitized_text = callback_result
                                except Exception as e:
                                    self.logger.error(
                                        f"Error in pattern callback for {pattern['id']}: {str(e)}"
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
                        if pattern_key in pattern:
                            try:
                                regex_pattern = pattern[pattern_key]
                                matches = list(
                                    re.finditer(
                                        regex_pattern,
                                        sanitized_text,
                                        re.IGNORECASE | re.DOTALL,
                                    )
                                )
                                if matches:
                                    patterns_matched.append(f"{pattern['id']}_{lang}")
                                    match_count += len(matches)

                                    # Apply replacement
                                    if action == "redact":
                                        sanitized_text = re.sub(
                                            regex_pattern,
                                            replacement,
                                            sanitized_text,
                                            flags=re.IGNORECASE | re.DOTALL,
                                        )

                                    # Call the callback if registered
                                    if pattern["id"] in self.pattern_callbacks:
                                        try:
                                            callback_result = self.pattern_callbacks[
                                                pattern["id"]
                                            ](
                                                pattern,
                                                text,
                                                sanitized_text,
                                                matches,
                                                context,
                                            )
                                            # Allow callback to override the sanitized text
                                            if callback_result and isinstance(
                                                callback_result, str
                                            ):
                                                sanitized_text = callback_result
                                        except Exception as e:
                                            self.logger.error(
                                                f"Error in pattern callback for {pattern['id']} ({lang}): {str(e)}"
                                            )
                            except Exception as e:
                                self.logger.error(
                                    f"Error applying {lang} pattern in {pattern['id']}: {str(e)}"
                                )

                except Exception as e:
                    self.logger.error(
                        f"Error applying pattern {pattern['id']}: {str(e)}"
                    )

            elif pattern_type == "custom":
                # Custom patterns require a callback
                if pattern["id"] in self.pattern_callbacks:
                    try:
                        callback_result = self.pattern_callbacks[pattern["id"]](
                            pattern, text, sanitized_text, None, context
                        )
                        if callback_result:
                            if isinstance(callback_result, str):
                                # Callback returns sanitized text
                                if callback_result != sanitized_text:
                                    sanitized_text = callback_result
                                    patterns_matched.append(pattern["id"])
                                    match_count += 1
                            elif isinstance(callback_result, dict):
                                # Callback returns a result dictionary
                                if "sanitized_text" in callback_result:
                                    sanitized_text = callback_result["sanitized_text"]
                                if callback_result.get("matched", False):
                                    patterns_matched.append(pattern["id"])
                                    match_count += callback_result.get("match_count", 1)
                    except Exception as e:
                        self.logger.error(
                            f"Error in custom pattern callback for {pattern['id']}: {str(e)}"
                        )

            else:
                self.logger.warning(
                    f"Unknown pattern type '{pattern_type}' in pattern {pattern['id']}"
                )

        return {
            "sanitized_text": sanitized_text,
            "patterns_matched": patterns_matched,
            "match_count": match_count,
        }
