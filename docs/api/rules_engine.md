---
layout: default
title: Rules Engine API
---

# Rules Engine API Reference

The `RulesEngine` class is responsible for evaluating text against configured rules to detect potential security threats.

## Rule Definition

Rules are defined in YAML files with the following structure:

```yaml
- id: LLM01
  description: "Prompt Injection: Block instruction override patterns and bypass attempts."
  type: blacklist
  pattern: "(ignore instructions|disregard previous|override system|bypass safety)"
  action: deny
  enabled: true
  severity: high
```

## Methods

### evaluate()

Evaluates text against all configured rules.

```python
result = rules_engine.evaluate(text, context=None)
```

**Parameters:**
- `text` (str): The text to evaluate
- `context` (dict, optional): Contextual information

**Returns:**
- Dictionary with:
  - `is_safe` (bool): Whether the text passes all rules
  - `violations` (list): List of violated rules
  - `continue_evaluation` (bool): Whether to continue evaluation

### register_rule()

Registers a custom rule or a callback for an existing rule.

```python
rules_engine.register_rule(rule, callback=None)
```

**Parameters:**
- `rule` (dict or str): Rule definition or rule ID
- `callback` (callable, optional): Function to call when rule matches

## Rule Types

WAFIShield supports the following rule types:

### Blacklist

Matches text against regex patterns and blocks if matched.

```yaml
- id: CUSTOM_RULE
  description: "Block prompts containing specific words"
  type: blacklist
  pattern: "(secret|password|backdoor)"
  action: deny
  enabled: true
```

### Whitelist

Only allows text that matches specific patterns.

```yaml
- id: WHITELIST_RULE
  description: "Only allow specific formats"
  type: whitelist
  pattern: "^[a-zA-Z0-9 .,!?]+$"
  action: allow
  enabled: true
```

### Score-based

Assigns a score based on multiple criteria; blocks if above threshold.

```yaml
- id: SCORE_RULE
  description: "Score-based filtering"
  type: score
  patterns:
    - pattern: "(hack|crack)"
      score: 0.5
    - pattern: "(password|credentials)"
      score: 0.3
  threshold: 0.7
  action: deny
  enabled: true
```

## Custom Rule Callbacks

You can register custom callbacks to handle rule violations:

```python
def custom_rule_handler(rule, text, context):
    # Log the violation
    print(f"Rule {rule['id']} was triggered by: {text}")
    
    # You can modify the behavior:
    return {
        "continue_evaluation": True,  # Continue evaluation despite the rule match
        "custom_data": {
            "reason": "Custom logic determined this is a false positive"
        }
    }

rules_engine.register_rule("LLM01", custom_rule_handler)
```
