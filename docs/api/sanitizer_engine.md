---
layout: default
title: Sanitizer Engine API
---

# Sanitizer Engine API Reference

The `SanitizerEngine` class handles the detection and redaction of sensitive information from text.

## Pattern Definition

Sanitizer patterns are defined in YAML files with the following structure:

```yaml
- id: PII_EMAIL
  description: "Redact email addresses"
  type: regex
  pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
  action: redact
  replacement: "[REDACTED_EMAIL]"
  enabled: true
```

## Methods

### sanitize()

Sanitizes text by replacing sensitive information based on configured patterns.

```python
result = sanitizer_engine.sanitize(text, context=None)
```

**Parameters:**
- `text` (str): The text to sanitize
- `context` (dict, optional): Contextual information

**Returns:**
- Dictionary with:
  - `sanitized_text` (str): The sanitized version of the text
  - `patterns_matched` (list): List of pattern IDs that were matched
  - `match_count` (int): Total number of matches
  - `replacement_count` (int): Total number of replacements made

### register_pattern()

Registers a custom pattern or a callback for an existing pattern.

```python
sanitizer_engine.register_pattern(pattern, callback=None)
```

**Parameters:**
- `pattern` (dict or str): Pattern definition or pattern ID
- `callback` (callable, optional): Function to call when pattern matches

## Pattern Types

WAFIShield supports the following pattern types:

### Regex

Uses regular expressions to match and redact sensitive information.

```yaml
- id: CREDIT_CARD
  description: "Redact credit card numbers"
  type: regex
  pattern: "\\b(?:\\d{4}[- ]?){3}\\d{4}\\b"
  action: redact
  replacement: "[REDACTED_CREDIT_CARD]"
  enabled: true
```

### Dictionary

Matches against a predefined list of sensitive terms.

```yaml
- id: RESTRICTED_TERMS
  description: "Redact internal project names"
  type: dictionary
  terms:
    - "Project Alpha"
    - "Project Beta"
    - "Project Gamma"
  action: redact
  replacement: "[REDACTED_PROJECT]"
  enabled: true
```

## Actions

WAFIShield supports the following actions for matched patterns:

- `redact`: Replace the matched text with a placeholder
- `hash`: Replace the matched text with a hash of the original
- `mask`: Show partial information (e.g., last 4 digits of credit card)
- `flag`: Don't alter the text, but flag it as containing sensitive info

## Custom Pattern Callbacks

You can register custom callbacks to handle pattern matches:

```python
def custom_pattern_handler(pattern, original_text, sanitized_text, matches, context):
    # Log the detection
    print(f"Pattern {pattern['id']} matched {len(matches)} times")
    
    # You can implement custom sanitization logic
    # For example, replacing with a consistent identifier per match
    import hashlib
    
    for match in matches:
        match_text = match.group(0)
        hash_id = hashlib.md5(match_text.encode()).hexdigest()[:8]
        sanitized_text = sanitized_text.replace(
            f"[{pattern['replacement']}]", 
            f"[{pattern['replacement']}_{hash_id}]",
            1
        )
    
    return sanitized_text

sanitizer_engine.register_pattern("PII_EMAIL", custom_pattern_handler)
```
