"""Tests for web assessment module."""

from unittest.mock import MagicMock, patch

import pytest

from cybersentinel.scanners.web_scanner import (
    _build_url,
    assess_web_target,
    check_security_headers,
    discover_directories,
    normalize_web_target,
)


def test_normalize_web_target():
    assert normalize_web_target("https://example.com/app/") == "example.com/app"
    assert normalize_web_target("http://127.0.0.1:8080/") == "127.0.0.1:8080"
    assert normalize_web_target("localhost/") == "localhost"


def test_build_url():
    assert _build_url("example.com", secure=True) == "https://example.com"
    assert _build_url("example.com", secure=False) == "http://example.com"


def test_check_security_headers():
    # Headers missing all defenses
    headers = {
        "server": "Apache/2.4.41",
        "x-powered-by": "PHP/7.4",
    }
    result = check_security_headers(headers)
    assert len(result["missing_security_headers"]) > 0
    assert "content-security-policy" in result["missing_security_headers"]
    assert "strict-transport-security" in result["missing_security_headers"]
    # Check infrastructure disclosures flagged
    findings_text = " ".join(result["findings"])
    assert "Server header is present" in findings_text
    assert "X-Powered-By header is present" in findings_text


def test_check_security_headers_well_configured():
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
        "x-xss-protection": "1; mode=block",
        "cache-control": "no-store",
        "expect-ct": "max-age=86400, enforce",
    }
    result = check_security_headers(headers)
    assert len(result["missing_security_headers"]) == 0
    assert result["security_headers"]["x-frame-options"] == "DENY"


@patch("cybersentinel.scanners.web_scanner._request_url")
def test_discover_directories(mock_request):
    mock_request.side_effect = lambda url, **kwargs: {
        "url": url,
        "status_code": 200 if "robots.txt" in url else 404,
        "reason": "OK" if "robots.txt" in url else "Not Found",
        "headers": {},
        "content_length": 50,
    }

    discovered = discover_directories("example.com", wordlist=["robots.txt", "nonexistent_dir"])
    assert len(discovered) == 1
    assert discovered[0]["path"] == "robots.txt"
    assert discovered[0]["status_code"] == 200


@patch("cybersentinel.scanners.web_scanner._request_url")
def test_assess_web_target(mock_request):
    mock_request.return_value = {
        "url": "https://example.com",
        "status_code": 200,
        "reason": "OK",
        "headers": {"server": "nginx"},
        "content_length": 1024,
    }

    assessment = assess_web_target("example.com", discovery_limit=2)
    assert assessment["target"] == "example.com"
    assert assessment["http_response"]["status_code"] == 200
    assert "content-security-policy" in assessment["missing_security_headers"]
