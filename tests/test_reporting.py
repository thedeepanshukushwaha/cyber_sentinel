"""Tests for HTML report generation."""

import tempfile
from pathlib import Path

import pytest

from cybersentinel.reporting.report_gen import (
    _build_context,
    generate_report,
    render_report_html,
)


def test_build_context():
    raw_results = {
        "results": {
            "recon": {"target": "127.0.0.1", "ip_address": "127.0.0.1"},
            "port_scan": {"open_ports": [80], "ports": [{"port": 80, "state": "open", "service": "http", "protocol": "tcp"}]},
            "web_assessment": {"missing_security_headers": ["csp"], "findings": ["Missing CSP"]},
            "ai_analysis": {"analysis": "AI assessment text"},
        }
    }
    context = _build_context("127.0.0.1", raw_results)
    assert context["target"] == "127.0.0.1"
    assert "authorized_use_notice" in context
    assert len(context["port_scans"]) >= 1


def test_render_report_html():
    raw_results = {
        "results": {
            "recon": {"target": "127.0.0.1"},
            "summary": {"severity": "Low", "highest_score": 10},
        }
    }
    html = render_report_html("127.0.0.1", raw_results)
    assert "<!DOCTYPE html>" in html
    assert "CyberSentinel Security Assessment" in html
    assert "127.0.0.1" in html


def test_generate_report_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        output_file = Path(temp_dir) / "test_report.html"
        raw_results = {
            "results": {
                "recon": {"target": "localhost"},
            }
        }
        saved_path = generate_report("localhost", raw_results, output_path=output_file)
        assert saved_path.exists()
        content = saved_path.read_text(encoding="utf-8")
        assert "CyberSentinel Security Assessment" in content
