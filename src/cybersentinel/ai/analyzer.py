"""AI analysis module for CyberSentinel.

Integrates with multiple AI providers (OpenRouter, Anthropic Claude, Google Gemini)
to analyze security findings, distinguish verified facts from inferred risks,
assign defensive severity ratings, and recommend prioritized remediations.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional, Union

import requests

try:
    from cybersentinel.config import AI_MODELS, get_ai_api_key
except ImportError:
    from config import AI_MODELS, get_ai_api_key

DEFAULT_AI_PROVIDER = "openrouter"
DEFAULT_MAX_TOKENS = 800
DEFAULT_TEMPERATURE = 0.2
DEFAULT_STOP_SEQUENCES = ["\n\n"]

logger = logging.getLogger(__name__)


def _serialize_scan_data(scan_results: Dict[str, Any]) -> str:
    try:
        return json.dumps(scan_results, indent=2, sort_keys=True)
    except TypeError:
        return json.dumps(scan_results, indent=2, sort_keys=True, default=str)


def build_analysis_prompt(scan_results: Dict[str, Any], target: Optional[str] = None) -> str:
    """Build a defensively focused analysis prompt."""
    target_name = target or scan_results.get("target", "unknown target")
    scan_summary = _serialize_scan_data(scan_results)

    return (
        "You are a defensive cybersecurity analyst. Analyze the following authorized security assessment results "
        "and provide a concise, structured response with the following sections:\n"
        "1. Plain English explanation of each finding (distinguishing confirmed observations from inferred risks)\n"
        "2. Risk severity rating for each issue (Critical/High/Medium/Low)\n"
        "3. Recommended defensive remediation and hardening steps for the target environment\n"
        "4. Overall defensive risk posture summary\n\n"
        "IMPORTANT SECURITY BOUNDARY: Do NOT provide exploit payloads, attack scripts, or penetration steps. "
        "Focus exclusively on mitigation, patch verification, and defense-in-depth.\n\n"
        f"Target: {target_name}\n\n"
        "Scan Results:\n"
        f"{scan_summary}\n\n"
        "If no vulnerabilities are detected, state that the target appears to have no obvious security misconfigurations "
        "based on the non-invasive data provided. Use a concise bullet list for findings and mitigation steps."
    )


def _parse_response_text(response: Dict[str, Any]) -> str:
    if not isinstance(response, dict):
        return ""
    # OpenAI-style response
    choices = response.get("choices")
    if choices and isinstance(choices, list):
        first = choices[0]
        message = first.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                return content.strip()
            if isinstance(content, dict):
                return content.get("text", "").strip()
        if isinstance(first.get("text"), str):
            return first["text"].strip()

    # Gemini-style response
    candidates = response.get("candidates")
    if candidates and isinstance(candidates, list):
        first = candidates[0]
        if isinstance(first, dict):
            if "output" in first:
                output = first["output"]
                if isinstance(output, list) and output and isinstance(output[0], dict):
                    text = output[0].get("content", "")
                    if isinstance(text, str):
                        return text.strip()
            content = first.get("content")
            if isinstance(content, list) and content:
                text_piece = content[0].get("text")
                if isinstance(text_piece, str):
                    return text_piece.strip()

    # Anthropic-style response
    return response.get("completion", "").strip()


def _extract_error_message(response: Any) -> Optional[str]:
    if not isinstance(response, dict):
        return None
    # Standard OpenAI/GPT and OpenRouter error shape
    error = response.get("error")
    if isinstance(error, dict):
        message = error.get("message") or error.get("detail")
        if isinstance(message, str) and message:
            return message.strip()
    if isinstance(error, str) and error:
        return error.strip()

    # OpenRouter / provider-specific fields
    for key in ("detail", "message", "error_message", "status_message"):
        value = response.get(key)
        if isinstance(value, str) and value:
            return value.strip()

    # Fallback direct text fields
    if isinstance(response.get("response_text"), str) and response["response_text"]:
        return response["response_text"].strip()
    if isinstance(response.get("text"), str) and response["text"]:
        return response["text"].strip()

    return None


def _http_post_json(
    url: str,
    api_key: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    retry_on_statuses: Optional[list[int]] = None,
    max_attempts: int = 3,
) -> Dict[str, Any]:
    final_headers = {"Content-Type": "application/json"}
    if headers:
        final_headers.update(headers)

    if params is None:
        params = {}

    if retry_on_statuses is None:
        retry_on_statuses = [429]

    attempt = 0
    while True:
        attempt += 1
        response = requests.post(url, json=payload, headers=final_headers, params=params, timeout=60)
        try:
            response.raise_for_status()
            try:
                return response.json()
            except json.JSONDecodeError:
                response_body = response.text.strip()
                content_type = response.headers.get("Content-Type")
                error_string = (
                    f"Invalid JSON response from {url}: status={response.status_code}, "
                    f"content_type={content_type}, body={response_body[:300]!r}"
                )
                logger.warning(error_string)
                return {
                    "provider": None,
                    "error": error_string,
                    "response_text": response_body,
                    "status_code": response.status_code,
                    "content_type": content_type,
                }
        except requests.exceptions.HTTPError:
            status_code = getattr(response, "status_code", None)
            if status_code in retry_on_statuses and attempt < max_attempts:
                wait_time = 2 ** (attempt - 1)
                logger.warning(
                    "Request to %s returned %s. Retrying in %s seconds (attempt %s/%s).",
                    url,
                    status_code,
                    wait_time,
                    attempt,
                    max_attempts,
                )
                time.sleep(wait_time)
                continue
            try:
                return response.json()
            except json.JSONDecodeError:
                return {
                    "provider": None,
                    "error": f"HTTP {status_code} with non-JSON response",
                    "response_text": response.text,
                    "status_code": response.status_code,
                }


def _analyze_with_claude_http(
    prompt: str,
    model: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    api_key = api_key or get_ai_api_key("claude")
    if not api_key:
        return {
            "provider": "claude",
            "model": model,
            "error": "Claude API key not configured. Set ANTHROPIC_API_KEY environment variable.",
            "analysis": "",
        }
    try:
        data = {
            "model": model,
            "prompt": prompt,
            "max_tokens_to_sample": max_tokens,
            "temperature": temperature,
            "stop_sequences": DEFAULT_STOP_SEQUENCES,
        }
        response = _http_post_json(
            "https://api.anthropic.com/v1/complete",
            api_key,
            data,
            headers={"x-api-key": api_key},
        )
        analysis_text = _parse_response_text(response)
        if not analysis_text:
            error_message = _extract_error_message(response) or "Claude returned an empty response."
            return {
                "provider": "claude",
                "model": model,
                "error": error_message,
                "analysis": "",
                "response": response,
            }
        return {
            "provider": "claude",
            "model": model,
            "analysis": analysis_text,
            "response": response,
        }
    except Exception as exc:
        logger.error("Claude HTTP API error: %s", exc)
        return {
            "provider": "claude",
            "model": model,
            "error": str(exc),
            "analysis": "",
        }


def analyze_with_claude(
    prompt: str,
    model: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyze using Anthropic Claude API."""
    api_key = api_key or get_ai_api_key("claude")
    if not api_key:
        return {
            "provider": "claude",
            "model": model,
            "error": "Claude API key not configured. Set ANTHROPIC_API_KEY environment variable.",
            "analysis": "",
        }
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[
                {"role": "user", "content": prompt},
            ],
        )
        content = getattr(response, "content", None)
        analysis_text = ""
        if isinstance(content, list) and content:
            first_content = content[0]
            analysis_text = getattr(first_content, "text", "").strip() if first_content is not None else ""
        elif isinstance(response, dict):
            candidates = response.get("content")
            if isinstance(candidates, list) and candidates:
                analysis_text = candidates[0].get("text", "").strip()
        if not analysis_text:
            analysis_text = getattr(response, "completion", "").strip()
        return {
            "provider": "claude",
            "model": model,
            "response_id": getattr(response, "id", None),
            "analysis": analysis_text,
            "api_response": response,
        }
    except ImportError:
        return _analyze_with_claude_http(prompt, model, max_tokens, temperature, api_key)
    except Exception as exc:
        logger.error("Claude API error: %s", exc)
        return _analyze_with_claude_http(prompt, model, max_tokens, temperature, api_key)


def _analyze_with_openrouter_http(
    prompt: str,
    model: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    api_key = api_key or get_ai_api_key("openrouter")
    if not api_key:
        return {
            "provider": "openrouter",
            "model": model,
            "error": "OpenRouter API key not configured. Set OPENROUTER_API_KEY environment variable.",
            "analysis": "",
        }

    def _expand_openrouter_variants(model_name: str) -> list[str]:
        variants = [model_name]
        if model_name.endswith(":free"):
            base = model_name[: -len(":free")]
            variants.append(base)
        elif ":" not in model_name:
            variants.append(f"{model_name}:free")
        return list(dict.fromkeys(variants))

    candidate_models: list[str] = []
    candidate_models.extend(_expand_openrouter_variants(model))
    fallback_models = AI_MODELS.get("openrouter", {}).get("fallback_models", [])
    for fallback_model in fallback_models:
        for variant in _expand_openrouter_variants(fallback_model):
            if variant not in candidate_models:
                candidate_models.append(variant)

    last_error = "OpenRouter analysis failed."
    for current_model in candidate_models:
        if not current_model:
            continue

        try:
            data = {
                "model": current_model,
                "messages": [
                    {"role": "system", "content": "You are a defensive cybersecurity analyst expert in security audits and hardening."},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            response = _http_post_json(
                "https://openrouter.ai/api/v1/chat/completions",
                api_key,
                data,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "HTTP-Referer": "https://github.com/cybersentinel",
                    "X-Title": "CyberSentinel Security Toolkit",
                },
            )
            if response is None:
                last_error = "No response received from OpenRouter."
                continue
            if not isinstance(response, dict):
                continue

            if response.get("content_type", "").lower().startswith("text/html"):
                last_error = (
                    "OpenRouter endpoint returned HTML instead of JSON. "
                    "Verify host reachability or DNS settings."
                )
                continue

            analysis_text = _parse_response_text(response)
            if not analysis_text:
                last_error = _extract_error_message(response) or "OpenRouter returned an empty analysis result."
                continue

            return {
                "provider": "openrouter",
                "model": current_model,
                "response_id": response.get("id"),
                "analysis": analysis_text,
                "api_response": response,
            }
        except Exception as exc:
            last_error = str(exc)
            logger.warning("OpenRouter model %s failed: %s", current_model, last_error)
            continue

    return {
        "provider": "openrouter",
        "model": model,
        "error": last_error,
        "analysis": "",
    }


def analyze_with_openrouter(
    prompt: str,
    model: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyze using OpenRouter unified API gateway."""
    return _analyze_with_openrouter_http(prompt, model, max_tokens, temperature, api_key)


def _extract_gemini_text(response: Dict[str, Any]) -> str:
    if not isinstance(response, dict):
        return ""
    candidates = response.get("candidates")
    if isinstance(candidates, list) and candidates:
        first = candidates[0]
        if isinstance(first, dict):
            if "output" in first:
                output = first["output"]
                if isinstance(output, list) and output:
                    text = output[0].get("content")
                    if isinstance(text, str):
                        return text.strip()
            if "content" in first:
                content = first["content"]
                if isinstance(content, list) and content:
                    text = content[0].get("text")
                    if isinstance(text, str):
                        return text.strip()
    if isinstance(response.get("text"), str):
        return response["text"].strip()
    return ""


def _analyze_with_gemini_http(
    prompt: str,
    model: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    api_key = api_key or get_ai_api_key("gemini")
    if not api_key:
        return {
            "provider": "gemini",
            "model": model,
            "error": "Gemini API key not configured. Set GEMINI_API_KEY environment variable.",
            "analysis": "",
        }
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        data = {
            "contents": [
                {"parts": [{"text": prompt}]},
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        response = _http_post_json(url, api_key, data, params={"key": api_key})
        analysis_text = _extract_gemini_text(response)
        if not analysis_text:
            error_message = _extract_error_message(response) or "Gemini returned an empty response."
            return {
                "provider": "gemini",
                "model": model,
                "error": error_message,
                "analysis": "",
                "response": response,
            }
        return {
            "provider": "gemini",
            "model": model,
            "analysis": analysis_text,
            "response": response,
        }
    except Exception as exc:
        logger.error("Gemini HTTP API error: %s", exc)
        return {
            "provider": "gemini",
            "model": model,
            "error": str(exc),
            "analysis": "",
        }


def analyze_with_gemini(
    prompt: str,
    model: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyze using Google Gemini API."""
    api_key = api_key or get_ai_api_key("gemini")
    if not api_key:
        return {
            "provider": "gemini",
            "model": model,
            "error": "Gemini API key not configured. Set GEMINI_API_KEY environment variable.",
            "analysis": "",
        }
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model_obj = genai.GenerativeModel(model)
        response = model_obj.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            ),
        )
        analysis_text = response.text.strip()
        return {
            "provider": "gemini",
            "model": model,
            "analysis": analysis_text,
            "api_response": response,
        }
    except ImportError:
        return _analyze_with_gemini_http(prompt, model, max_tokens, temperature, api_key)
    except Exception as exc:
        logger.error("Gemini API error: %s", exc)
        return _analyze_with_gemini_http(prompt, model, max_tokens, temperature, api_key)


def _resolve_provider_api_key(
    provider: str,
    api_key: Optional[str] = None,
    settings_manager: Optional[object] = None,
) -> Optional[str]:
    if api_key:
        return api_key
    return get_ai_api_key(provider, settings_manager)


def analyze_scan_results(
    scan_results: Dict[str, Any],
    target: Optional[str] = None,
    provider: str = DEFAULT_AI_PROVIDER,
    model: Optional[str] = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    api_key: Optional[str] = None,
    settings_manager: Optional[object] = None,
) -> Dict[str, Any]:
    """Analyze scan results using the specified AI provider with automatic fallback."""
    if provider not in AI_MODELS:
        return {
            "error": f"Unknown AI provider: {provider}. Choose from: {', '.join(AI_MODELS.keys())}",
            "analysis": "",
        }

    if not model:
        model = AI_MODELS[provider]["default_model"]

    prompt = build_analysis_prompt(scan_results, target=target)
    resolved_api_key = _resolve_provider_api_key(provider, api_key=api_key, settings_manager=settings_manager)

    if provider == "openrouter":
        ai_result = analyze_with_openrouter(prompt, model, max_tokens, temperature, resolved_api_key)
    elif provider == "claude":
        ai_result = analyze_with_claude(prompt, model, max_tokens, temperature, resolved_api_key)
    elif provider == "gemini":
        ai_result = analyze_with_gemini(prompt, model, max_tokens, temperature, resolved_api_key)
    else:
        ai_result = {
            "error": f"Unknown AI provider: {provider}",
            "analysis": "",
        }

    if not ai_result.get("error"):
        return ai_result

    logger.warning(
        "AI provider '%s' failed with error: %s. Attempting fallback providers.",
        provider,
        ai_result.get("error"),
    )

    fallback_providers = [p for p in AI_MODELS.keys() if p != provider]
    for fallback_provider in fallback_providers:
        fallback_api_key = get_ai_api_key(fallback_provider, settings_manager)
        if not fallback_api_key:
            continue

        fallback_model = AI_MODELS[fallback_provider]["default_model"]

        if fallback_provider == "claude":
            fallback_result = analyze_with_claude(prompt, fallback_model, max_tokens, temperature, fallback_api_key)
        elif fallback_provider == "gemini":
            fallback_result = analyze_with_gemini(prompt, fallback_model, max_tokens, temperature, fallback_api_key)
        elif fallback_provider == "openrouter":
            fallback_result = analyze_with_openrouter(prompt, fallback_model, max_tokens, temperature, fallback_api_key)
        else:
            continue

        if not fallback_result.get("error"):
            fallback_result["provider"] = fallback_provider
            fallback_result["fallback_from"] = provider
            return fallback_result

    return ai_result


def generate_ai_report(
    scan_results: Dict[str, Any],
    target: Optional[str] = None,
    provider: str = DEFAULT_AI_PROVIDER,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Generate a full AI report for the provided scan results."""
    return analyze_scan_results(scan_results, target=target, provider=provider, **kwargs)


__all__ = [
    "build_analysis_prompt",
    "analyze_scan_results",
    "generate_ai_report",
    "analyze_with_claude",
    "analyze_with_gemini",
    "analyze_with_openrouter",
]
