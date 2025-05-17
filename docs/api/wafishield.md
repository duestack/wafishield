---
layout: default
title: WAFIShield Class API
---

# WAFIShield Class API Reference

The `WAFIShield` class is the main entry point for using the WAFIShield package. It orchestrates three protection layers:

1. Rules Engine - for detecting common attack patterns
2. Sanitizer Engine - for removing sensitive information
3. LLM Evaluator - for deep semantic analysis using a secondary LLM

## Initialization

```python
from wafishield import WAFIShield

wafishield = WAFIShield(
    rules_yaml_dir=None,         # Optional path to custom rules directory
    patterns_yaml_dir=None,      # Optional path to custom patterns directory
    llm_provider="openai",       # LLM provider for evaluation
    llm_api_key="your-api-key",  # API key for the LLM provider
    llm_model="gpt-3.5-turbo",   # Model to use
    llm_provider_api_url=None,   # Optional custom API URL
    enable_llm_evaluation=True,  # Enable/disable LLM evaluation
    enable_metrics=True          # Enable/disable metrics collection
)
```

## Main Methods

### evaluate_prompt()

Evaluates a user prompt against all protection layers.

```python
result = wafishield.evaluate_prompt(prompt, context=None)
```

**Parameters:**
- `prompt` (str): The user prompt to evaluate
- `context` (dict, optional): Contextual information for the evaluation

**Returns:**
- Dictionary with:
  - `is_safe` (bool): Whether the prompt is safe
  - `sanitized_prompt` (str): Sanitized version of prompt
  - `rule_violations` (list): List of rule violations
  - `llm_evaluation` (dict): Results from LLM evaluation
  - `metrics` (dict): Collected metrics

### evaluate_response()

Evaluates an LLM response against protection layers.

```python
result = wafishield.evaluate_response(response, context=None)
```

**Parameters:**
- `response` (str): The LLM response to evaluate
- `context` (dict, optional): Contextual information for the evaluation

**Returns:**
- Dictionary with:
  - `is_safe` (bool): Whether the response is safe
  - `sanitized_response` (str): Sanitized version of response
  - `rule_violations` (list): List of rule violations
  - `llm_evaluation` (dict): Results from LLM evaluation
  - `metrics` (dict): Collected metrics

## Registration Methods

### register_rule()

Registers a custom rule or a callback for an existing rule.

```python
wafishield.register_rule(rule, callback=None)
```

**Parameters:**
- `rule` (dict or str): Rule definition or rule ID
- `callback` (callable, optional): Function to call when rule matches

### register_sanitizer_pattern()

Registers a custom sanitizer pattern or a callback for an existing pattern.

```python
wafishield.register_sanitizer_pattern(pattern, callback=None)
```

**Parameters:**
- `pattern` (dict or str): Pattern definition or pattern ID
- `callback` (callable, optional): Function to call when pattern matches

### register_system_instruction()

Registers a custom system instruction for the LLM evaluator.

```python
wafishield.register_system_instruction(instruction_id, instruction_text)
```

**Parameters:**
- `instruction_id` (str): Unique ID for the instruction
- `instruction_text` (str): Text of the instruction

## LLM Evaluation Control

### set_llm_evaluation()

Enable or disable LLM evaluation at runtime.

```python
wafishield.set_llm_evaluation(enabled)
```

**Parameters:**
- `enabled` (bool): Whether to enable LLM evaluation

### get_llm_evaluation_status()

Get the current LLM evaluation status.

```python
status = wafishield.get_llm_evaluation_status()
```

**Returns:**
- `bool`: Whether LLM evaluation is currently enabled
