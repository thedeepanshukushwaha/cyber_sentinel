"""Tests for AI analysis module and fallback mechanisms."""

from unittest.mock import MagicMock, patch

import pytest

from cybersentinel.ai.analyzer import (
    _extract_error_message,
    _parse_response_text,
    analyze_scan_results,
    build_analysis_prompt,
)


def test_build_analysis_prompt():
    scan_data = {
        "target": "scanme.nmap.org",
        "open_ports": [80],
        "findings": ["HTTP service active"],
    }
    prompt = build_analysis_prompt(scan_data, target="scanme.nmap.org")
    assert "scanme.nmap.org" in prompt
    assert "defensive cybersecurity analyst" in prompt
    assert "IMPORTANT SECURITY BOUNDARY" in prompt
    assert "Do NOT provide exploit payloads" in prompt


def test_parse_response_text_openai():
    openai_resp = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Analysis: System shows open port 80 with missing security headers.",
                }
            }
        ]
    }
    assert "Analysis:" in _parse_response_text(openai_resp)


def test_parse_response_text_gemini():
    gemini_resp = {
        "candidates": [
            {
                "content": [
                    {
                        "text": "Gemini Assessment: Low risk posture.",
                    }
                ]
            }
        ]
    }
    assert "Gemini Assessment:" in _parse_response_text(gemini_resp)


def test_extract_error_message():
    error_resp = {
        "error": {
            "message": "Invalid API key provided.",
            "code": 401,
        }
    }
    assert _extract_error_message(error_resp) == "Invalid API key provided."


@patch("cybersentinel.ai.analyzer.get_ai_api_key", return_value=None)
def test_analyze_scan_results_no_key(mock_get_key):
    scan_results = {"target": "127.0.0.1"}
    result = analyze_scan_results(scan_results, provider="openrouter")
    assert "error" in result
    assert "API key not configured" in result["error"]


@patch("cybersentinel.ai.analyzer._http_post_json")
@patch("cybersentinel.ai.analyzer.get_ai_api_key", return_value="test-api-key")
def test_analyze_scan_results_success(mock_get_key, mock_http_post):
    mock_http_post.return_value = {
        "id": "gen-123",
        "choices": [
            {
                "message": {
                    "content": "Defensive Summary: No high severity issues found.",
                }
            }
        ],
    }

    scan_results = {"target": "127.0.0.1"}
    result = analyze_scan_results(scan_results, provider="openrouter")
    assert result["provider"] == "openrouter"
    assert "Defensive Summary" in result["analysis"]
    assert not result.get("error")
