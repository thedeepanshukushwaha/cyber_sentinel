"""Reconnaissance module for CyberSentinel.

This module provides passive reconnaissance helpers:
- Target normalization and IP resolution
- DNS record collection (A, AAAA, CNAME, MX, NS)
- Passive subdomain resolution using local wordlists
- WHOIS lookups with Python library and system command fallbacks
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional

try:
    import dns.exception
    import dns.resolver
except ImportError:
    dns = None

try:
    from cybersentinel.config import DEFAULT_SCAN_TIMEOUT, WORDLISTS_DIR
except ImportError:
    from config import DEFAULT_SCAN_TIMEOUT, WORDLISTS_DIR

logger = logging.getLogger(__name__)

DEFAULT_DNS_RECORDS = ["A", "AAAA", "CNAME", "MX", "NS"]
COMMON_SUBDOMAIN_CANDIDATES = [
    "www",
    "mail",
    "ftp",
    "api",
    "admin",
    "dev",
    "stage",
    "test",
    "portal",
    "secure",
    "vpn",
    "webmail",
    "blog",
    "shop",
    "m",
]


def normalize_target(target: str) -> str:
    """Normalize a target value by stripping protocol and path."""
    target = target.strip().lower()
    target = re.sub(r"^https?://", "", target)
    target = re.sub(r"/.*$", "", target)
    return target


def is_ip_address(target: str) -> bool:
    """Return True if the normalized target is a numeric IP address."""
    try:
        ipaddress.ip_address(normalize_target(target))
        return True
    except ValueError:
        return False


def get_host_ip(target: str) -> Optional[str]:
    """Resolve the target to an IP address if possible."""
    target = normalize_target(target)

    if is_ip_address(target):
        return target

    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def resolve_dns_records(target: str, record_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Collect DNS records for a target domain."""
    target = normalize_target(target)
    if is_ip_address(target):
        return {}

    if dns is None:
        logger.warning("dnspython is not installed; DNS record resolution skipped.")
        return {}

    record_types = record_types or DEFAULT_DNS_RECORDS
    resolver = dns.resolver.Resolver()
    resolver.timeout = min(5, DEFAULT_SCAN_TIMEOUT)
    resolver.lifetime = min(10, DEFAULT_SCAN_TIMEOUT)

    results: Dict[str, List[str]] = {}
    for record_type in record_types:
        try:
            answers = resolver.resolve(target, record_type)
            results[record_type] = [str(answer).strip() for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            results[record_type] = []
        except Exception:
            results[record_type] = []
    return results


def _load_wordlist() -> List[str]:
    """Load subdomain candidates from local wordlist file, fallback to defaults."""
    wordlist_path = WORDLISTS_DIR / "common.txt"
    if wordlist_path.exists():
        try:
            with wordlist_path.open("r", encoding="utf-8", errors="ignore") as handle:
                words = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
                return words[:500]
        except Exception:
            return COMMON_SUBDOMAIN_CANDIDATES[:]
    return COMMON_SUBDOMAIN_CANDIDATES[:]


def is_resolvable(subdomain: str) -> bool:
    """Return True if the subdomain resolves to a DNS record."""
    try:
        socket.gethostbyname(subdomain)
        return True
    except (socket.gaierror, socket.herror, OSError):
        return False
    except Exception:
        return False


def enumerate_subdomains(domain: str, limit: Optional[int] = 100) -> List[str]:
    """Enumerate common subdomains for a target domain non-invasively."""
    domain = normalize_target(domain)
    if is_ip_address(domain):
        return []

    candidates = _load_wordlist()
    subdomains: List[str] = []

    for word in candidates:
        if limit is not None and len(subdomains) >= limit:
            break
        subdomain = f"{word}.{domain}"
        if is_resolvable(subdomain):
            subdomains.append(subdomain)

    return subdomains


def perform_whois_lookup(target: str) -> str:
    """Gather WHOIS data for the target domain using the best available method."""
    target = normalize_target(target)

    try:
        import whois

        record = whois.whois(target)
        return str(record)
    except ImportError:
        pass
    except Exception as exc:
        return f"WHOIS lookup failed: {exc}"

    try:
        completed = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=DEFAULT_SCAN_TIMEOUT,
        )
        if completed.returncode == 0:
            return completed.stdout.strip() or "WHOIS lookup returned no data."
        return f"WHOIS command failed: {completed.stderr.strip() or completed.stdout.strip()}"
    except FileNotFoundError:
        return "WHOIS tool is not installed or not available on PATH."
    except subprocess.TimeoutExpired:
        return "WHOIS lookup timed out."
    except Exception as exc:
        return f"WHOIS lookup error: {exc}"


def collect_recon_data(target: str) -> Dict[str, Any]:
    """Collect a standard recon dataset for a target."""
    target = normalize_target(target)
    ip_address = get_host_ip(target)
    if is_ip_address(target):
        return {
            "target": target,
            "ip_address": ip_address,
            "dns_records": {},
            "subdomains": [],
            "whois": "WHOIS lookup skipped for numeric IP addresses.",
        }

    return {
        "target": target,
        "ip_address": ip_address,
        "dns_records": resolve_dns_records(target),
        "subdomains": enumerate_subdomains(target, limit=50),
        "whois": perform_whois_lookup(target),
    }


__all__ = [
    "normalize_target",
    "is_ip_address",
    "get_host_ip",
    "resolve_dns_records",
    "enumerate_subdomains",
    "perform_whois_lookup",
    "collect_recon_data",
]
