"""HTML report generator for CyberSentinel."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    from cybersentinel.config import AUTHORIZED_USE_NOTICE, HTML_REPORT_TEMPLATE, REPORTS_DIR
except ImportError:
    from config import AUTHORIZED_USE_NOTICE, HTML_REPORT_TEMPLATE, REPORTS_DIR

REPORT_TEMPLATE_DIR = HTML_REPORT_TEMPLATE.parent
REPORT_TEMPLATE_NAME = HTML_REPORT_TEMPLATE.name

env = Environment(
    loader=FileSystemLoader(str(REPORT_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def _extract_results(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    if raw_results is None:
        return {}
    if isinstance(raw_results, dict) and "results" in raw_results:
        return raw_results["results"]
    return raw_results


def _find_port_scans(results: Dict[str, Any]) -> list[Dict[str, Any]]:
    scans = []
    for key, value in results.items():
        if key.startswith("port_") or key == "port_scan":
            scans.append({"name": key, "data": value})
    if not scans and "scan_data" in results:
        scans.append({"name": "port_scan", "data": results["scan_data"]})
    return scans


def _aggregate_findings(extracted: Dict[str, Any], port_scans: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    findings: list[str] = []
    if extracted.get("findings"):
        findings.extend(extracted["findings"])

    for scan in port_scans:
        scan_data = scan.get("data") or {}
        if isinstance(scan_data, dict):
            findings.extend(scan_data.get("findings", []))

    web_findings = extracted.get("web_assessment", {}).get("findings", [])
    if isinstance(web_findings, list):
        findings.extend(web_findings)

    return findings


def _build_context(
    target: str,
    results: Dict[str, Any],
    risk_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    extracted = _extract_results(results)
    port_scans = _find_port_scans(extracted)
    combined_findings = _aggregate_findings(extracted, port_scans)

    context = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "authorized_use_notice": AUTHORIZED_USE_NOTICE,
        "risk_summary": risk_summary or extracted.get("summary", {}),
        "recon": extracted.get("recon", {}),
        "port_scans": port_scans,
        "web_assessment": extracted.get("web_assessment", {}),
        "ai_analysis": extracted.get("ai_analysis", {}),
        "missing_security_headers": extracted.get("missing_security_headers", []),
        "exposed_paths": extracted.get("exposed_paths", []),
        "findings": combined_findings,
    }

    if "web_assessment" in extracted and isinstance(extracted["web_assessment"], dict):
        context["missing_security_headers"] = extracted["web_assessment"].get("missing_security_headers", [])
        context["exposed_paths"] = extracted["web_assessment"].get("exposed_paths", [])

    return context


def render_report_html(
    target: str,
    results: Dict[str, Any],
    risk_summary: Optional[Dict[str, Any]] = None,
) -> str:
    template = env.get_template(REPORT_TEMPLATE_NAME)
    context = _build_context(target, results, risk_summary)
    return template.render(context)


def save_report_html(
    target: str,
    results: Dict[str, Any],
    risk_summary: Optional[Dict[str, Any]] = None,
    output_path: Optional[Path] = None,
) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    html = render_report_html(target, results, risk_summary)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    filename = output_path or REPORTS_DIR / f"report_{safe_target}_{timestamp}.html"
    filename.parent.mkdir(parents=True, exist_ok=True)
    with filename.open("w", encoding="utf-8") as handle:
        handle.write(html)
    return filename


def generate_report(
    target: str,
    results: Dict[str, Any],
    risk_summary: Optional[Dict[str, Any]] = None,
    output_path: Optional[Path] = None,
) -> Path:
    return save_report_html(target, results, risk_summary, output_path)


__all__ = [
    "render_report_html",
    "save_report_html",
    "generate_report",
]
