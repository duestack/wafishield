"""
Test script for the new WAFIShield data flow functionality.

This script specifically tests the skip LLM evaluation feature after sanitization.
"""

from wafishield import WAFIShield


def test_response_flow():
    print("Testing Response Evaluation Flow")
    print("=" * 50)

    # Initialize WAFIShield with mock LLM provider for testing
    wafishield = WAFIShield(
        enable_llm_evaluation=True,
        enable_metrics=True,
        # Using 'mock' provider - doesn't need real API keys
        llm_provider="mock",
        patterns_yaml_dir=None,  # Start with empty patterns
    )

    # Register our test sanitizer patterns
    wafishield.register_sanitizer_pattern(
        {
            "id": "TEST_PII_PATTERN",
            "description": "Test pattern for PII detection",
            "type": "regex",
            "pattern": r"SSN: \d{3}-\d{2}-\d{4}",
            "action": "redact",
            "replacement": "[REDACTED_SSN]",
            "enabled": True,
        }
    )

    # Test 1: Response with no PII - Should proceed to LLM evaluation
    print("\nTest 1: Response with no PII - Should proceed to LLM evaluation")
    response_no_pii = "This is a safe response with no PII."
    result = wafishield.evaluate_response(response_no_pii)
    print(f"Response sanitized: {response_no_pii != result['sanitized_response']}")
    print(f"LLM evaluation performed: {result['llm_evaluation'] is not None}")

    # Test 2: Response with PII - Should skip LLM evaluation
    print("\nTest 2: Response with PII - Should skip LLM evaluation")
    response_with_pii = "Your SSN: 123-45-6789 should be kept private."
    result = wafishield.evaluate_response(response_with_pii)
    print(f"Original: '{response_with_pii}'")
    print(f"Sanitized: '{result['sanitized_response']}'")
    print(f"Response sanitized: {response_with_pii != result['sanitized_response']}")
    print(f"LLM evaluation performed: {result['llm_evaluation'] is not None}")

    # Get metrics
    print("\nMetrics:")
    print(wafishield.metrics.get_current_metrics())


if __name__ == "__main__":
    test_response_flow()
