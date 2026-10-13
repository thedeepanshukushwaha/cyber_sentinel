"""Tests for port scanner module."""

from unittest.mock import MagicMock, patch

import pytest

from cybersentinel.scanners.port_scanner import (
    _build_port_spec,
    _parse_nmap_xml,
    _parse_port_list,
    _socket_port_check,
    get_nmap_backend_status,
    normalize_target,
    scan_port_range,
    scan_ports,
    summarize_scan_result,
    validate_nmap_backends,
)


def test_normalize_target():
    assert normalize_target("https://target.local:8080/path") == "target.local:8080"
    assert normalize_target("127.0.0.1") == "127.0.0.1"


def test_parse_port_list():
    assert _parse_port_list("80,443") == [80, 443]
    assert _parse_port_list("80,82-84,80") == [80, 82, 83, 84]
    assert _parse_port_list([8080, 80]) == [80, 8080]


def test_build_port_spec():
    assert _build_port_spec([80, 443]) == "80,443"
    assert _build_port_spec("22,80") == "22,80"


def test_backend_status():
    status = get_nmap_backend_status()
    assert "preferred_backend" in status
    assert status["preferred_backend"] in ("python-nmap", "system-nmap", "none")

    report = validate_nmap_backends()
    assert report["ready"] is True
    assert "message" in report


def test_socket_port_check():
    # Test closed/unreachable high port on localhost
    result = _socket_port_check("127.0.0.1", 65530, timeout=1)
    assert result["port"] == 65530
    assert result["state"] in ("closed", "open")
    assert result["protocol"] == "tcp"


def test_parse_nmap_xml_sample():
    sample_xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.50" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="closed" reason="reset"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    parsed = _parse_nmap_xml(sample_xml)
    assert parsed["ip_address"] == "192.168.1.50"
    assert len(parsed["ports"]) == 2
    assert parsed["ports"][0]["port"] == 80
    assert parsed["ports"][0]["state"] == "open"
    assert parsed["ports"][1]["port"] == 443
    assert parsed["ports"][1]["state"] == "closed"


def test_scan_ports_socket_fallback():
    # Force socket scan against localhost for a port
    result = scan_ports("127.0.0.1", ports=[65531], timeout=1)
    assert result["target"] == "127.0.0.1"
    assert "ports" in result
    assert "summary" in result
    assert result["summary"]["total_ports"] == 1


def test_scan_port_range_validation():
    with pytest.raises(ValueError):
        scan_port_range("127.0.0.1", start_port=100, end_port=50)


def test_summarize_scan_result():
    mock_scan_data = {
        "target": "10.0.0.1",
        "ip_address": "10.0.0.1",
        "open_ports": [80, 443],
        "summary": {"total_ports": 5, "open_ports": 2},
    }
    summary = summarize_scan_result(mock_scan_data)
    assert summary["target"] == "10.0.0.1"
    assert summary["open_port_count"] == 2
    assert summary["total_ports_scanned"] == 5
