"""
FastAPI integration example for WAFIShield.

This example shows how to build an API that protects LLM interactions
using WAFIShield.
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import os
import openai
from wafishield import WAFIShield
from typing import Optional, Dict, Any, List

# Initialize OpenAI client
openai.api_key = os.environ.get("OPENAI_API_KEY")

# Initialize WAFIShield
wafishield = WAFIShield(
    llm_provider="openai",
    llm_api_key=os.environ.get("OPENAI_API_KEY"),
    llm_model="gpt-3.5-turbo",
    enable_metrics=True,
)

# FastAPI app
app = FastAPI(
    title="WAFIShield API",
    description="An API for protecting LLM interactions using WAFIShield",
    version="0.1.0",
)


# Request and response models
class PromptRequest(BaseModel):
    prompt: str
    model: str = "gpt-4"
    context: Optional[Dict[str, Any]] = None


class CheckRequest(BaseModel):
    text: str
    context: Optional[Dict[str, Any]] = None


class PromptResponse(BaseModel):
    response: str
    metrics: Dict[str, Any]


class CheckResponse(BaseModel):
    is_safe: bool
    sanitized_text: str
    violations: List[Dict[str, Any]]
    metrics: Dict[str, Any]


# Authentication middleware (simple API key check)
async def verify_api_key(x_api_key: str = Header(None)):
    expected_api_key = os.environ.get("API_KEY")
    if not expected_api_key:
        # No API key set, so no authentication required
        return True

    if x_api_key != expected_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return True


@app.get("/")
async def root():
    return {"message": "WAFIShield API is running"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/metrics")
async def metrics(authenticated: bool = Depends(verify_api_key)):
    return wafishield.metrics.get_current_metrics()


@app.post("/check", response_model=CheckResponse)
async def check_text(
    request: CheckRequest, authenticated: bool = Depends(verify_api_key)
):
    """
    Check if a prompt or response text is safe according to WAFIShield rules.
    """
    evaluation = wafishield.evaluate_prompt(request.text, request.context)

    return {
        "is_safe": evaluation["is_safe"],
        "sanitized_text": evaluation["sanitized_prompt"],
        "violations": evaluation["rule_violations"],
        "metrics": evaluation.get("metrics", {}),
    }


@app.post("/prompt", response_model=PromptResponse)
async def process_prompt(
    request: PromptRequest, authenticated: bool = Depends(verify_api_key)
):
    """
    Process a prompt through WAFIShield and return the LLM response.
    """
    # Evaluate the prompt
    prompt_eval = wafishield.evaluate_prompt(request.prompt, request.context)

    # Check if the prompt is safe
    if not prompt_eval["is_safe"]:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Prompt was blocked by WAFIShield",
                "violations": prompt_eval["rule_violations"],
            },
        )

    # Use the sanitized prompt
    sanitized_prompt = prompt_eval["sanitized_prompt"]

    try:
        # Send the sanitized prompt to OpenAI
        response = openai.ChatCompletion.create(
            model=request.model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": sanitized_prompt},
            ],
        )

        # Extract the response text
        response_text = response.choices[0].message.content

        # Evaluate the response
        response_eval = wafishield.evaluate_response(response_text, request.context)

        # Check if the response is safe
        if not response_eval["is_safe"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Response was blocked by WAFIShield",
                    "violations": response_eval["rule_violations"],
                },
            )

        # Return the sanitized response
        return {
            "response": response_eval["sanitized_response"],
            "metrics": response_eval.get("metrics", {}),
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing prompt: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
