"""
WAFIShield main module that combines the Rules Engine, Sanitizer Engine, and LLM Evaluator.
"""

from typing import Optional, Dict, Any, Callable, List, Union
import logging

from .rules_engine import RulesEngine
from .sanitizer_engine import SanitizerEngine
from .llm_evaluator import LLMEvaluator
from .metrics import MetricsCollector

class WAFIShield:
    """
    Main WAFIShield class that provides a unified interface for prompt and response evaluation.
    
    This class orchestrates the three protection layers:
    1. Rules Engine - for detecting common attack patterns
    2. Sanitizer Engine - for removing sensitive information
    3. LLM Evaluator - for deep semantic analysis using a secondary LLM
    
    Data Flow:
    - For LLM input (prompt evaluation):
      Client input → Rules Engine → Sanitizer Engine → LLM Evaluator → Client
      Note: Sanitization is applied before LLM evaluation to protect sensitive information.
    
    - For LLM output (response evaluation):
      Client output → Rules Engine → Sanitizer Engine → (conditional) LLM Evaluator → Client
      Note: LLM evaluation is skipped if sanitization patterns were matched (already flagged content).
    
    Args:
        rules_yaml_dir: Optional path to directory containing YAML rule definitions
        patterns_yaml_dir: Optional path to directory containing YAML pattern definitions
        llm_provider: Optional LLM provider for secondary evaluation (default is None)
        llm_api_key: Optional API key for the LLM provider
        llm_model: Optional model name for the LLM provider
        llm_provider_api_url: Optional custom API URL for the LLM provider
        enable_llm_evaluation: Enable or disable LLM evaluation (default is True)
        enable_metrics: Enable metrics collection (default is True)
    """
    def __init__(
        self,
        rules_yaml_dir: Optional[str] = None,
        patterns_yaml_dir: Optional[str] = None,
        llm_provider: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
        llm_provider_api_url: Optional[str] = None,
        enable_llm_evaluation: bool = True,
        enable_metrics: bool = True,
    ):
        # Initialize components
        self.rules_engine = RulesEngine(rules_yaml_dir) if rules_yaml_dir else RulesEngine()
        self.sanitizer_engine = SanitizerEngine(patterns_yaml_dir) if patterns_yaml_dir else SanitizerEngine()
        
        # Initialize LLM evaluator if provider is specified and evaluation is enabled
        self.llm_evaluator = None
        self.enable_llm_evaluation = enable_llm_evaluation
        
        if llm_provider and enable_llm_evaluation:
            self.llm_evaluator = LLMEvaluator(
                provider=llm_provider,
                api_key=llm_api_key,
                model=llm_model,
                api_url=llm_provider_api_url
            )
            
        # Initialize metrics collector
        self.metrics = MetricsCollector() if enable_metrics else None
        self.logger = logging.getLogger("wafishield")
    
    def evaluate_prompt(
        self, 
        prompt: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate a prompt against all protection layers and return the result.
        
        Args:
            prompt: The user prompt to evaluate
            context: Optional context information for the evaluation
            
        Returns:
            A dictionary containing the evaluation result with the following keys:
            - is_safe: Whether the prompt is safe to send to the LLM
            - sanitized_prompt: The sanitized version of the prompt
            - rule_violations: List of rules that were violated
            - llm_evaluation: Result from secondary LLM evaluation (if enabled)
            - metrics: Collected metrics for this evaluation
        """
        result = {
            "is_safe": True,
            "sanitized_prompt": prompt,
            "rule_violations": [],
            "llm_evaluation": None,
            "metrics": {}
        }
        
        if self.metrics:
            self.metrics.increment("prompts_total")
        
        # Step 1: Check against rules engine
        rules_result = self.rules_engine.evaluate(prompt, context)
        if not rules_result["is_safe"]:
            result["is_safe"] = False
            result["rule_violations"] = rules_result["violations"]
            if self.metrics:
                self.metrics.increment("rules_failed")
                for violation in rules_result["violations"]:
                    self.metrics.increment(f"rule_{violation['id']}_failed")
                    
            # Early return if rules are violated and we want to block
            if not rules_result.get("continue_evaluation", False):
                return result
        
        # Step 2: Sanitize the prompt before sending to LLM evaluator
        # This is to not expose sensitive information to the online LLM evaluator
        sanitized_result = self.sanitizer_engine.sanitize(prompt, context)
        result["sanitized_prompt"] = sanitized_result["sanitized_text"]
        
        if sanitized_result["patterns_matched"]:
            if self.metrics:
                self.metrics.increment("sanitizations_applied")
                for pattern in sanitized_result["patterns_matched"]:
                    self.metrics.increment(f"sanitizer_{pattern}_applied")
            self.logger.info("Sensitive information sanitized from prompt")
        
        # Step 3: Evaluate with secondary LLM if enabled
        if self.llm_evaluator and self.enable_llm_evaluation:
            # Use the sanitized prompt for LLM evaluation to protect sensitive info
            llm_result = self.llm_evaluator.evaluate(result["sanitized_prompt"], context)
            result["llm_evaluation"] = llm_result
            
            if not llm_result["is_safe"]:
                result["is_safe"] = False
                if self.metrics:
                    self.metrics.increment("llm_checks_failed")
        
        # Add metrics to result
        if self.metrics:
            result["metrics"] = self.metrics.get_current_metrics()
            
        return result
        
    def evaluate_response(
        self, 
        response: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate an LLM response against protection layers and return the result.
        
        Args:
            response: The LLM response to evaluate
            context: Optional context information for the evaluation
            
        Returns:
            A dictionary containing the evaluation result with the following keys:
            - is_safe: Whether the response is safe to show to the user
            - sanitized_response: The sanitized version of the response
            - rule_violations: List of rules that were violated
            - llm_evaluation: Result from secondary LLM evaluation (if enabled)
            - metrics: Collected metrics for this evaluation
        """
        result = {
            "is_safe": True,
            "sanitized_response": response,
            "rule_violations": [],
            "llm_evaluation": None,
            "metrics": {}
        }
        
        if self.metrics:
            self.metrics.increment("responses_total")
        
        # Step 1: Check against rules engine
        rules_result = self.rules_engine.evaluate(response, context)
        if not rules_result["is_safe"]:
            result["is_safe"] = False
            result["rule_violations"] = rules_result["violations"]
            if self.metrics:
                self.metrics.increment("rules_failed")
                for violation in rules_result["violations"]:
                    self.metrics.increment(f"rule_{violation['id']}_failed")
                    
            # Early return if rules are violated and we want to block
            if not rules_result.get("continue_evaluation", False):
                return result
                
        # Step 2: Sanitize the response
        sanitized_result = self.sanitizer_engine.sanitize(response, context)
        result["sanitized_response"] = sanitized_result["sanitized_text"]
        
        # Track if patterns were matched during sanitization
        patterns_matched = False
        if sanitized_result["patterns_matched"]:
            patterns_matched = True
            if self.metrics:
                self.metrics.increment("sanitizations_applied")
                for pattern in sanitized_result["patterns_matched"]:
                    self.metrics.increment(f"sanitizer_{pattern}_applied")
            self.logger.info("Response was sanitized - sensitive content detected")
        
        # Step 3: Evaluate with secondary LLM only if no patterns were matched and evaluation is enabled
        if not patterns_matched and self.llm_evaluator and self.enable_llm_evaluation:
            # If no sanitizer patterns matched, proceed with LLM evaluation
            self.logger.info("No sanitization patterns matched, proceeding with LLM evaluation")
            llm_result = self.llm_evaluator.evaluate(result["sanitized_response"], context)
            result["llm_evaluation"] = llm_result
            
            if not llm_result["is_safe"]:
                result["is_safe"] = False
                if self.metrics:
                    self.metrics.increment("llm_checks_failed")
        elif patterns_matched:
            self.logger.info("Skipping LLM evaluation since sanitization was already applied")
            if self.metrics:
                self.metrics.increment("llm_checks_skipped_after_sanitization")
        
        # Add metrics to result
        if self.metrics:
            result["metrics"] = self.metrics.get_current_metrics()
            
        return result
    
    def register_rule(self, rule: Union[Dict[str, Any], str], callback: Optional[Callable] = None):
        """
        Register a custom rule or a custom callback for an existing rule.
        
        Args:
            rule: Either a complete rule definition dictionary or a rule ID string
            callback: Optional callback function to be called when the rule is triggered
        """
        self.rules_engine.register_rule(rule, callback)
    
    def register_sanitizer_pattern(self, pattern: Union[Dict[str, Any], str], callback: Optional[Callable] = None):
        """
        Register a custom sanitizer pattern or a callback for an existing pattern.
        
        Args:
            pattern: Either a complete pattern definition dictionary or a pattern ID string
            callback: Optional callback function to be called when the pattern is matched
        """
        self.sanitizer_engine.register_pattern(pattern, callback)
    
    def register_system_instruction(self, instruction_id: str, instruction_text: str):
        """
        Register a custom system instruction for the LLM evaluator.
        
        Args:
            instruction_id: A unique ID for the instruction
            instruction_text: The text of the instruction
        """
        if self.llm_evaluator:
            self.llm_evaluator.register_system_instruction(instruction_id, instruction_text)
        else:
            self.logger.warning("LLM Evaluator is not enabled. Cannot register system instruction.")
    
    def set_llm_evaluation(self, enabled: bool):
        """
        Enable or disable LLM evaluation at runtime.
        
        Args:
            enabled: Whether to enable LLM evaluation
        """
        self.enable_llm_evaluation = enabled
        self.logger.info(f"LLM evaluation {'enabled' if enabled else 'disabled'}")
        
    def get_llm_evaluation_status(self) -> bool:
        """
        Get the current LLM evaluation status.
        
        Returns:
            Whether LLM evaluation is currently enabled
        """
        return self.enable_llm_evaluation