"""
Example integration with Anthropic Claude API.
"""

import os
from anthropic import Anthropic
from wafishield import WAFIShield

# Initialize WAFIShield
wafishield = WAFIShield(
    llm_provider="openai",  # Using OpenAI for evaluation
    llm_api_key=os.environ.get("OPENAI_API_KEY"),
    llm_model="gpt-3.5-turbo",
    enable_metrics=True,
)

# Initialize Anthropic client
anthropic = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))


def safe_anthropic_completion(prompt):
    """
    Send a prompt to Anthropic Claude, but only if it passes WAFIShield's security checks.
    This function also sanitizes both the prompt and the response.
    """

    # Evaluate the prompt
    prompt_eval = wafishield.evaluate_prompt(prompt)

    # Check if the prompt is safe
    if not prompt_eval["is_safe"]:
        return {
            "error": "Prompt was blocked by WAFIShield",
            "violations": prompt_eval["rule_violations"],
        }

    # Use the sanitized prompt
    sanitized_prompt = prompt_eval["sanitized_prompt"]

    try:
        # Send the sanitized prompt to Anthropic's Claude
        response = anthropic.messages.create(
            model="claude-2",
            messages=[{"role": "user", "content": sanitized_prompt}],
            max_tokens=1000,
        )

        # Extract the response text
        response_text = response.content[0].text

        # Evaluate the response
        response_eval = wafishield.evaluate_response(response_text)

        # Check if the response is safe
        if not response_eval["is_safe"]:
            return {
                "error": "Response was blocked by WAFIShield",
                "violations": response_eval["rule_violations"],
            }

        # Return the sanitized response
        return {
            "response": response_eval["sanitized_response"],
            "metrics": response_eval["metrics"],
        }

    except Exception as e:
        return {"error": f"Error calling Anthropic: {str(e)}"}


# Example usage
if __name__ == "__main__":
    # Safe prompt
    safe_prompt = "Tell me about quantum computing."
    print(f"Safe prompt: {safe_prompt}")
    result = safe_anthropic_completion(safe_prompt)
    if "response" in result:
        print(f"Response: {result['response']}")
    else:
        print(f"Error: {result['error']}")

    # Show metrics
    print("\nMetrics:")
    import json

    print(json.dumps(wafishield.metrics.get_current_metrics(), indent=2))
