"""
Common utility functions for wafishield.
"""

import os
import json
import yaml
import logging
from typing import Dict, Any, Optional, Union

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wafishield.utils")


def get_package_dir() -> str:
    """
    Get the directory where the package is installed.

    Returns:
        The absolute path to the package directory
    """
    return os.path.dirname(os.path.abspath(__file__))


def load_yaml_file(file_path: str) -> Union[Dict[str, Any], list]:
    """
    Load and parse a YAML file.

    Args:
        file_path: Path to the YAML file

    Returns:
        Parsed YAML content as a dictionary or list

    Raises:
        FileNotFoundError: If the file does not exist
        yaml.YAMLError: If the file is not valid YAML
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = yaml.safe_load(file)
            return content
    except FileNotFoundError:
        logger.error(f"YAML file not found: {file_path}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {file_path}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error loading YAML file {file_path}: {str(e)}")
        raise


def validate_yaml_against_schema(
    data: Union[Dict[str, Any], list], schema_type: str
) -> bool:
    """
    Validate YAML data against a schema.

    Args:
        data: YAML data to validate
        schema_type: Type of schema to validate against ('rules' or 'patterns')

    Returns:
        True if validation is successful, raises exception otherwise

    Raises:
        ValueError: If the data does not match the schema
    """
    try:
        # Import jsonschema only when needed
        import jsonschema
    except ImportError:
        logger.warning(
            "jsonschema not installed, skipping validation. Install with 'pip install jsonschema'"
        )
        return True

    schema_file = os.path.join(get_package_dir(), f"schemas/{schema_type}_schema.json")

    # If schema file doesn't exist, create directory and default schema
    if not os.path.exists(schema_file):
        os.makedirs(os.path.dirname(schema_file), exist_ok=True)

        if schema_type == "rules":
            schema = {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "description", "type"],
                    "properties": {
                        "id": {"type": "string"},
                        "description": {"type": "string"},
                        "type": {
                            "type": "string",
                            "enum": ["blacklist", "whitelist", "flag"],
                        },
                        "pattern": {"type": "string"},
                        "english_pattern": {"type": "string"},
                        "arabic_pattern": {"type": "string"},
                        "french_pattern": {"type": "string"},
                        "spanish_pattern": {"type": "string"},
                        "chinese_pattern": {"type": "string"},
                        "action": {"type": "string", "enum": ["deny", "allow", "warn"]},
                        "enabled": {"type": "boolean"},
                    },
                },
            }
        elif schema_type == "patterns":
            schema = {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "description", "type"],
                    "properties": {
                        "id": {"type": "string"},
                        "description": {"type": "string"},
                        "type": {"type": "string", "enum": ["regex", "custom"]},
                        "pattern": {"type": "string"},
                        "english_pattern": {"type": "string"},
                        "arabic_pattern": {"type": "string"},
                        "french_pattern": {"type": "string"},
                        "spanish_pattern": {"type": "string"},
                        "chinese_pattern": {"type": "string"},
                        "replacement": {"type": "string"},
                        "action": {
                            "type": "string",
                            "enum": ["redact", "tag", "custom"],
                        },
                        "enabled": {"type": "boolean"},
                    },
                },
            }
        else:
            logger.error(f"Unknown schema type: {schema_type}")
            return True  # Skip validation for unknown schema types

        # Save the schema
        with open(schema_file, "w", encoding="utf-8") as file:
            json.dump(schema, file, indent=2)

    # Load the schema and validate
    try:
        with open(schema_file, "r", encoding="utf-8") as file:
            schema = json.load(file)

        if isinstance(data, dict):
            # Convert single object to list for validation against array schema
            data_list = [data]
            jsonschema.validate(instance=data_list, schema=schema)
        else:
            jsonschema.validate(instance=data, schema=schema)

        return True
    except FileNotFoundError:
        logger.warning(f"Schema file not found: {schema_file}, skipping validation")
        return True
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing schema file {schema_file}: {str(e)}")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logger.error(f"YAML validation failed: {str(e)}")
        raise ValueError(f"YAML validation failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during validation: {str(e)}")
        return True


def safe_regex_compile(pattern: str) -> Optional[str]:
    """
    Safely compile a regex pattern and return it, or None if invalid.

    Args:
        pattern: Regex pattern string

    Returns:
        The compiled pattern or None if invalid
    """
    import re

    try:
        re.compile(pattern)
        return pattern
    except re.error:
        logger.error(f"Invalid regex pattern: {pattern}")
        return None
