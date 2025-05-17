# Project: wafishield by duestack
# Description: A two-layer, fully-extensible Python package for protecting LLM/agent apps against OWASP Top 10 and other evolving LLM vulnerabilities.

"""
Python package scaffold for the following project.:

1. Package Layout:

    ├── wafishield/
    │   ├── __init__.py         # Package initialization, dont add logic here
    │   ├── rules_engine.py     # Loads and runs YAML-defined rules and client-registered rules
    │   ├── sanitizer_engine.py # Loads and runs YAML-defined sanitizer patterns and client-registered patterns
    │   ├── llm_evaluator.py    # Evaluates prompts using a secondary LLM and client-registered system instructions
    │   ├── metrics.py          # Metrics collection and observability support
    │   ├── utils.py            # Common helpers
    │   ├── rules/              # YAML rule definitions
    │   │   └── owasp_llm_top10.yml
    │   ├── patterns/           # YAML sanitizer patterns
    │   │   └── pii_sensitive_informations_patterns.yml
    ├── tests/                  # Unit tests for all modules
    ├── examples/               # Example integrations and configs
    ├── setup.py                # Project setup

2. Rule Engine:
    - rules example 
     {
          "id": "LLM01",
          "description": "Prompt Injection: Block instruction override patterns and bypass attempts.",
          "type": "blacklist",
          "english_pattern": r"ignore instructions|disregard previous|override system|bypass safety",
          "arabic_pattern": r"تجاهل التعليمات|تجاوز التعليمات|تجاوز الأمان",
          "french_pattern": r"ignorer les instructions|dépasser la sécurité|contourner les instructions",
          "spanish_pattern": r"ignorar instrucciones|eludir seguridad|contornar instrucciones",
          "chinese_pattern": r"忽略指令|绕过安全|超越指令",
          "action": "deny",
          "enabled": True,
     }
    - Load YAML (`rules/*.yml`), validate against OWASP LLM Top 10 schema.
    - Multilingual regex + NLP heuristics for all human languages.
    - Client can provide custom rules, provide `register_rule(rule, callback)`.
    - Provide `register_rule(rule_id, callback)`.

3. Sanitizer Engine:
    - patterns example 
    {
        "id": "PII01",
        "description": "Redact PII: Names, emails, phone numbers.",
        "type": "regex",
        "pattern": r"\b[A-Z][a-z]+ [A-Z][a-z]+\b|\b\d{3}-\d{2}-\d{4}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "action": "redact",
        "enabled": True,
    }
    - Load YAML (`patterns/*.yml`).
    - Smart redaction patterns, sensitive-data tagging.
    - Client can provide custom patterns, provide `register_sanitizer_pattern(pattern,call_back)` and `register_sanitizer_pattern(pattern_id, callback)`.
    - Multilingual regex + NLP heuristics for all human languages.
    - Validate all YAML pattern inputs before use.
    - Ensure extensibility and security for sanitizer patterns.
    - Each pattern must have a unique `id` for tracking and metrics.

4. Secondary LLM Evaluator:
    - After sanitization, the prompt is sent to a secondary LLM.
    - Client can enable or disable the secondary LLM evaluator via configuration.
    - Clients can extend the secondary LLM evaluation with custom system instructions for both input and output.
    - Provide `register_system_instruction(instruction_id, instruction_text)` for extensibility.
    - Example: `register_system_instruction("NO_PII", "Do not allow any personally identifiable information in the response.")`
    - Support configurable prompts, system instructions, and pass/fail thresholds.


5. Observability:
   - Metrics: prompts_total, rules_failed, sanitizations_patterns_failed, llm_checks.
   - Hooks for OpenTelemetry and any opensource llm Observability tools .

6. Data-Flow Diagram:
   - llm input: Client input → Rules → Sanitizer before sending to llm " to not expose senstive information to online llm" → LLM Evaluator → Client.
   - llm output: Client output → Rules → Sanitizer " if matches then will flaged as sentaized no need to evaluate" → LLM Evaluator → Client.


7. Dependencies in `setup.py`:
   - PyYAML, regex, nltk/spacy (for NLP), openai.
   - pytest (for testing), requests (for HTTP calls), opentelemetry (for observability).
8. README:
   - Usage examples: OpenAI SDK integration, custom rules/instructions, metrics export.
   - Diagram preview.
   - Installation instructions.
   - Contribution guidelines.
   - License information.

9. Testing:
   - Unit tests for all modules.
   - Mocking LLM calls and YAML loading.
   - Coverage >90%.

Project Rules for Copilot:
- Use clear, consistent naming (snake_case) for all functions and classes 
- Follow “start general, then get specific”: top‐level comment → detailed bullet list → code
- Include docstrings for every public function following Google/PyDoc style
- Write unit tests (pytest) for each module with >90% coverage
- Ensure security best practices: validate all YAML inputs, sanitize user content before LLM calls 
- Provide extensibility hooks: `register_rule`, `register_sanitizer`, `register_system_instruction`
"""
