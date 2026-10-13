"""Web assessment module for CyberSentinel.

This module performs lightweight, non-invasive HTTP/web security checks:
- Security headers audit (CSP, HSTS, X-Frame-Options, etc.)
- Common directory and resource discovery
- Infrastructure disclosure detection (Server, X-Powered-By)
"""

from __future__ import annotations

import re
import urllib3
from typing import Any, Callable, Dict, List, Optional

import requests

try:
    from cybersentinel.config import DEFAULT_HTTP_TIMEOUT, WORDLISTS_DIR
except ImportError:
    from config import DEFAULT_HTTP_TIMEOUT, WORDLISTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_WEB_PATHS = [
    "admin",
    "login",
    "dashboard",
    "server-status",
    "robots.txt",
    "sitemap.xml",
    ".git",
    ".env",
    "config.php",
    "backup.zip",
    "uploads",
    "phpmyadmin",
    "wp-admin",
    "wp-login.php",
    "admin.php",
    "login.php",
    "api",
    "test",
    "portal",
    "dev",
    "staging",
]

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cache-control",
    "expect-ct",
]

DEFAULT_USER_AGENT = "CyberSentinel-SecurityAudit/1.0 (Authorized Security Assessment)"


def normalize_web_target(target: str) -> str:
    """Normalize a web target and strip protocol and trailing slashes."""
    target = target.strip()
    if target.startswith("https://") or target.startswith("http://"):
        target = re.sub(r"https?://", "", target, flags=re.IGNORECASE)
    target = target.rstrip("/")
    return target


def _build_url(target: str, secure: bool = True) -> str:
    scheme = "https" if secure else "http"
    return f"{scheme}://{normalize_web_target(target)}"


def _load_wordlist(limit: int = 100) -> List[str]:
    wordlist_path = WORDLISTS_DIR / "common.txt"
    if wordlist_path.exists():
        try:
            with wordlist_path.open("r", encoding="utf-8", errors="ignore") as handle:
                entries = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
                return list(dict.fromkeys(entries))[:limit]
        except Exception:
            return COMMON_WEB_PATHS[:limit]
    return COMMON_WEB_PATHS[:limit]


def _request_url(url: str, timeout: int = DEFAULT_HTTP_TIMEOUT) -> Dict[str, Any]:
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    request_timeout = (max(1, timeout // 2), max(2, timeout))
    try:
        response = requests.get(url, headers=headers, timeout=request_timeout, allow_redirects=True, verify=False)
        return {
            "url": url,
            "status_code": response.status_code,
            "headers": {k.lower(): v for k, v in response.headers.items()},
            "final_url": response.url,
            "reason": response.reason,
            "content_length": len(response.content),
        }
    except requests.RequestException as exc:
        return {
            "url": url,
            "status_code": None,
            "headers": {},
            "final_url": url,
            "reason": str(exc),
            "content_length": 0,
        }


def check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Inspect HTTP response headers for missing defensive protections."""
    missing = [name for name in SECURITY_HEADERS if name not in headers]
    findings: List[str] = []

    if headers.get("server"):
        findings.append("Server header is present and may disclose infrastructure information.")

    if headers.get("x-powered-by"):
        findings.append("X-Powered-By header is present and may disclose backend technology stack.")

    if missing:
        findings.append(f"Missing recommended security headers: {', '.join(missing)}.")

    return {
        "security_headers": {name: headers.get(name) for name in SECURITY_HEADERS if headers.get(name) is not None},
        "missing_security_headers": missing,
        "findings": findings,
    }


def discover_directories(
    target: str,
    wordlist: Optional[List[str]] = None,
    timeout: int = DEFAULT_HTTP_TIMEOUT,
    max_results: int = 25,
    prefer_https: bool = True,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, Any]]:
    """Probe common web paths non-invasively using GET requests."""
    if wordlist is None:
        wordlist = _load_wordlist(limit=max_results)

    base_urls = [
        _build_url(target, secure=True),
        _build_url(target, secure=False),
    ]
    discovered: List[Dict[str, Any]] = []
    visited = set()

    for path in wordlist:
        if stop_callback is not None and stop_callback():
            break

        if prefer_https:
            request_urls = [f"{base_urls[0]}/{path.lstrip('/')}", f"{base_urls[1]}/{path.lstrip('/')}"]
        else:
            request_urls = [f"{base_urls[1]}/{path.lstrip('/')}", f"{base_urls[0]}/{path.lstrip('/')}"]

        for url in request_urls:
            if stop_callback is not None and stop_callback():
                break
            if url in visited:
                continue
            visited.add(url)
            entry = _request_url(url, timeout=timeout)
            if entry["status_code"] in {200, 301, 302, 401, 403}:
                discovered.append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": entry["status_code"],
                        "reason": entry["reason"],
                    }
                )
                break
            if len(discovered) >= max_results:
                return discovered
        if stop_callback is not None and stop_callback():
            break
    return discovered


def assess_web_target(
    target: str,
    timeout: int = DEFAULT_HTTP_TIMEOUT,
    discovery_limit: int = 10,
    prefer_https: bool = True,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Perform a complete lightweight non-invasive web security assessment."""
    normalized_target = normalize_web_target(target)
    primary_url = _build_url(normalized_target, secure=prefer_https)
    fallback_url = _build_url(normalized_target, secure=not prefer_https)

    primary_response = _request_url(primary_url, timeout=timeout)
    fallback_response = None
    if primary_response["status_code"] is None and fallback_url != primary_url:
        fallback_response = _request_url(fallback_url, timeout=timeout)

    active_response = primary_response if primary_response["status_code"] not in (None, 0) else fallback_response or primary_response
    active_url = active_response["url"]
    headers = active_response.get("headers", {})
    security_data = check_security_headers(headers)

    exposed_paths: List[Dict[str, Any]] = []
    if active_response["status_code"] in {200, 301, 302, 401, 403}:
        exposed_paths = discover_directories(
            normalized_target,
            timeout=timeout,
            max_results=discovery_limit,
            prefer_https=prefer_https,
            stop_callback=stop_callback,
        )

    findings: List[str] = []
    if active_response["status_code"] is None:
        findings.append(f"Target {normalized_target} did not respond to HTTP requests.")
    else:
        findings.append(f"HTTP status code {active_response['status_code']} returned from {active_url}.")

    findings.extend(security_data["findings"])
    if exposed_paths:
        findings.append(f"Discovered {len(exposed_paths)} accessible endpoints or resources.")

    return {
        "target": normalized_target,
        "active_url": active_url,
        "primary_url": primary_url,
        "fallback_url": fallback_url,
        "http_response": active_response,
        "security_headers": security_data["security_headers"],
        "missing_security_headers": security_data["missing_security_headers"],
        "exposed_paths": exposed_paths,
        "findings": findings,
    }


__all__ = [
    "normalize_web_target",
    "check_security_headers",
    "discover_directories",
    "assess_web_target",
]
