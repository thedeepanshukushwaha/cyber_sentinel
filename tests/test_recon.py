"""Tests for reconnaissance module."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from cybersentinel.reconnaissance.recon import (
    collect_recon_data,
    enumerate_subdomains,
    get_host_ip,
    is_ip_address,
    is_resolvable,
    normalize_target,
    resolve_dns_records,
)


def test_normalize_target_urls():
    assert normalize_target("https://example.com/admin/login") == "example.com"
    assert normalize_target("http://192.168.1.1:8080/") == "192.168.1.1:8080"
    assert normalize_target("SUB.DOMAIN.ORG/") == "sub.domain.org"
    assert normalize_target("  localhost  ") == "localhost"


def test_is_ip_address():
    assert is_ip_address("127.0.0.1") is True
    assert is_ip_address("192.168.1.100") is True
    assert is_ip_address("::1") is True
    assert is_ip_address("example.com") is False
    assert is_ip_address("127.0.0.999") is False


def test_get_host_ip_with_direct_ip():
    assert get_host_ip("127.0.0.1") == "127.0.0.1"


@patch("socket.gethostbyname")
def test_get_host_ip_with_domain(mock_gethostbyname):
    mock_gethostbyname.return_value = "93.184.216.34"
    assert get_host_ip("example.com") == "93.184.216.34"
    mock_gethostbyname.assert_called_once_with("example.com")


@patch("socket.gethostbyname", side_effect=socket.gaierror("Resolution failed"))
def test_get_host_ip_failure(mock_gethostbyname):
    assert get_host_ip("nonexistent.local") is None


def test_resolve_dns_records_for_ip():
    # IP targets should return empty dict without performing DNS lookup
    assert resolve_dns_records("192.168.1.1") == {}


@patch("cybersentinel.reconnaissance.recon.dns")
def test_resolve_dns_records_mocked(mock_dns):
    mock_resolver_instance = MagicMock()
    mock_dns.resolver.Resolver.return_value = mock_resolver_instance
    mock_answer = [MagicMock(__str__=lambda self: "93.184.216.34")]
    mock_resolver_instance.resolve.return_value = mock_answer

    records = resolve_dns_records("example.com", record_types=["A"])
    assert "A" in records
    assert records["A"] == ["93.184.216.34"]


@patch("socket.gethostbyname")
def test_enumerate_subdomains(mock_gethostbyname):
    def fake_resolve(hostname):
        if hostname.startswith("www."):
            return "1.2.3.4"
        raise socket.gaierror

    mock_gethostbyname.side_effect = fake_resolve
    results = enumerate_subdomains("example.com", limit=10)
    assert "www.example.com" in results


def test_collect_recon_data_for_ip():
    data = collect_recon_data("127.0.0.1")
    assert data["target"] == "127.0.0.1"
    assert data["ip_address"] == "127.0.0.1"
    assert data["dns_records"] == {}
    assert data["subdomains"] == []
    assert "numeric IP" in data["whois"]
