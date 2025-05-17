"""
wafishield - A two-layer, fully-extensible Python package for protecting LLM/agent apps
against OWASP Top 10 and other evolving LLM vulnerabilities.
"""

__version__ = "0.1.0"

from .rules_engine import RulesEngine
from .sanitizer_engine import SanitizerEngine
from .llm_evaluator import LLMEvaluator
from .wafishield import WAFIShield
