"""Port scanner module for CyberSentinel.

This module provides non-invasive port scanning using python-nmap when available,
system nmap binary execution, or native Python socket connect scanning.
"""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Union

try:
    from cybersentinel.config import DEFAULT_SCAN_TIMEOUT, get_tool_path
except ImportError:
    from config import DEFAULT_SCAN_TIMEOUT, get_tool_path

logger = logging.getLogger(__name__)

COMMON_PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "rdp",
    8080: "http-proxy",
    8443: "https-alt",
}

try:
    import nmap
except ImportError:
    nmap = None

DEFAULT_TCP_PORTS = "21,22,23,25,53,80,110,139,143,161,443,445,3306,3389,8080,8443"
DEFAULT_NMAP_ARGS = "-sS -Pn -T4"


def normalize_target(target: str) -> str:
    """Normalize a scan target by stripping protocol and path."""
    target = target.strip().lower()
    target = re.sub(r"^https?://", "", target)
    target = re.sub(r"/.*$", "", target)
    return target


def _get_nmap_executable() -> Optional[str]:
    """Return the resolved nmap executable path if available."""
    return get_tool_path("nmap")


def is_python_nmap_available() -> bool:
    """Return True when the python-nmap package is installed."""
    return nmap is not None


def is_system_nmap_available() -> bool:
    """Return True when the system nmap binary is available."""
    return _get_nmap_executable() is not None


def get_nmap_backend_status() -> Dict[str, Union[bool, str]]:
    """Return the current nmap backend availability status."""
    python_available = is_python_nmap_available()
    system_available = is_system_nmap_available()
    if python_available:
        preferred = "python-nmap"
    elif system_available:
        preferred = "system-nmap"
    else:
        preferred = "none"

    return {
        "python_nmap_installed": python_available,
        "system_nmap_available": system_available,
        "preferred_backend": preferred,
        "system_nmap_path": _get_nmap_executable(),
    }


def validate_nmap_backends() -> Dict[str, Union[bool, str]]:
    """Validate available nmap backends and return a startup readiness report."""
    status = get_nmap_backend_status()
    if status["preferred_backend"] == "none":
        return {
            **status,
            "ready": True,
            "message": "No nmap backend found. Falling back to built-in TCP connect scanning.",
        }

    return {
        **status,
        "ready": True,
        "message": f"Ready to scan using {status['preferred_backend']}.",
    }


def _parse_port_list(ports: Optional[Union[str, List[int]]]) -> List[int]:
    if ports is None:
        return [int(port) for port in DEFAULT_TCP_PORTS.split(",") if port.strip()]
    if isinstance(ports, list):
        return sorted(set(ports))

    parsed_ports: List[int] = []
    for part in str(ports).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text.strip())
            end = int(end_text.strip())
            if start <= end:
                parsed_ports.extend(range(start, end + 1))
        else:
            parsed_ports.append(int(part))
    return sorted(set(parsed_ports))


def _build_port_spec(ports: Optional[Union[str, List[int]]]) -> str:
    if ports is None:
        return DEFAULT_TCP_PORTS
    if isinstance(ports, list):
        return ",".join(str(port) for port in ports)
    return str(ports)


def _parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)
    host_element = root.find("host")
    target_address = None
    if host_element is not None:
        address_element = host_element.find("address[@addrtype='ipv4']")
        if address_element is None:
            address_element = host_element.find("address")
        if address_element is not None:
            target_address = address_element.attrib.get("addr")

    ports: List[Dict[str, Any]] = []
    for port_element in root.findall(".//port"):
        protocol = port_element.attrib.get("protocol", "tcp")
        port_id = int(port_element.attrib.get("portid", "0"))
        state = "unknown"
        service_name = "unknown"
        reason = ""

        state_element = port_element.find("state")
        if state_element is not None:
            state = state_element.attrib.get("state", state)
            reason = state_element.attrib.get("reason", "")

        service_element = port_element.find("service")
        if service_element is not None:
            service_name = service_element.attrib.get("name", service_name)

        ports.append(
            {
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "reason": reason,
            }
        )

    return {
        "ip_address": target_address,
        "ports": ports,
    }


def _run_nmap_subprocess(target: str, port_spec: str, arguments: str, timeout: int) -> Dict[str, Any]:
    executable = _get_nmap_executable()
    if executable is None:
        raise RuntimeError("nmap executable not found in PATH or configured tool paths.")

    command = [executable, *arguments.split(), "-p", port_spec, target, "-oX", "-"]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if not completed.stdout.strip() and completed.stderr.strip():
        raise RuntimeError(f"nmap error: {completed.stderr.strip()}")

    parsed = _parse_nmap_xml(completed.stdout)
    return {
        "target": target,
        "command_line": " ".join(command),
        "raw_output": completed.stdout.strip(),
        "ip_address": parsed.get("ip_address"),
        "ports": parsed.get("ports", []),
    }


def _run_nmap_python_module(
    target: str,
    port_spec: str,
    arguments: str,
    timeout: int,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    if not is_python_nmap_available():
        raise RuntimeError("python-nmap is not installed.")
    if not is_system_nmap_available():
        raise RuntimeError("python-nmap requires the system nmap binary, which is not available.")

    scan_args = f"-p {port_spec} {arguments}"
    try:
        scanner = nmap.PortScanner()
        scan_result = scanner.scan(target, arguments=scan_args)
    except Exception as exc:
        logger.warning(
            "python-nmap scan failed for %s: %s. Falling back to available backend.",
            target,
            exc,
        )
        if is_system_nmap_available():
            return _run_nmap_subprocess(target, port_spec, arguments, timeout)
        return _run_socket_port_scan(target, port_spec, timeout, stop_callback=stop_callback)

    scan_data: Dict[str, Any] = {
        "target": target,
        "command_line": scan_result.get("nmap", {}).get("command_line", scan_args),
        "raw_output": scan_result.get("nmap", {}).get("raw_output", ""),
        "ip_address": None,
        "ports": [],
    }

    hosts = scan_result.get("scan", {})
    if hosts:
        host_data = next(iter(hosts.values()))
        scan_data["ip_address"] = host_data.get("addresses", {}).get("ipv4") or host_data.get("addresses", {}).get("ipv6")
        port_data = host_data.get("tcp", {})
        for port_id, port_details in port_data.items():
            scan_data["ports"].append(
                {
                    "port": int(port_id),
                    "protocol": "tcp",
                    "state": port_details.get("state", "unknown"),
                    "service": port_details.get("name", "unknown"),
                    "reason": port_details.get("reason", ""),
                }
            )

    return scan_data


def _socket_port_check(target: str, port: int, timeout: int) -> Dict[str, Any]:
    service = COMMON_PORT_SERVICES.get(port, "unknown")
    state = "closed"
    reason = "connection refused or timed out"

    try:
        with socket.create_connection((target, port), timeout=timeout):
            state = "open"
            reason = "tcp connect succeeded"
    except socket.timeout:
        reason = "connection timed out"
    except ConnectionRefusedError:
        reason = "connection refused"
    except socket.gaierror as exc:
        raise RuntimeError(f"Unable to resolve target '{target}': {exc}") from exc
    except OSError as exc:
        reason = str(exc)

    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "service": service,
        "reason": reason,
    }


def _run_socket_port_scan(
    target: str,
    port_spec: str,
    timeout: int,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    ports = _parse_port_list(port_spec)
    port_entries = []
    for port in ports:
        if stop_callback is not None and stop_callback():
            logger.info("Socket scan canceled before checking port %s", port)
            break
        port_entries.append(_socket_port_check(target, port, timeout))
        if stop_callback is not None and stop_callback():
            logger.info("Socket scan canceled after checking port %s", port)
            break

    return {
        "target": target,
        "command_line": f"socket-scan {target} ports={','.join(str(port) for port in ports)}",
        "raw_output": "",
        "ip_address": target,
        "ports": port_entries,
    }


def scan_ports(
    target: str,
    ports: Optional[Union[str, List[int]]] = None,
    arguments: str = DEFAULT_NMAP_ARGS,
    timeout: int = DEFAULT_SCAN_TIMEOUT,
    use_binary: bool = False,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Perform a safe TCP port scan and return structured results.

    Prefers python-nmap, falls back to subprocess nmap, and ultimately to safe native
    TCP socket connect scanning if nmap is unavailable.
    """
    normalized_target = normalize_target(target)
    port_spec = _build_port_spec(ports)

    if use_binary:
        if not is_system_nmap_available():
            raise RuntimeError("Binary nmap is not available on the system.")
        result = _run_nmap_subprocess(normalized_target, port_spec, arguments, timeout)
    else:
        if is_python_nmap_available() and is_system_nmap_available():
            result = _run_nmap_python_module(
                normalized_target,
                port_spec,
                arguments,
                timeout,
                stop_callback=stop_callback,
            )
        elif is_system_nmap_available():
            result = _run_nmap_subprocess(normalized_target, port_spec, arguments, timeout)
        else:
            result = _run_socket_port_scan(normalized_target, port_spec, timeout, stop_callback=stop_callback)

    open_ports = [entry["port"] for entry in result["ports"] if entry["state"] == "open"]
    result["open_ports"] = open_ports
    result["summary"] = {
        "total_ports": len(result["ports"]),
        "open_ports": len(open_ports),
        "closed_ports": len([entry for entry in result["ports"] if entry["state"] != "open"]),
    }
    return result


def scan_common_ports(
    target: str,
    timeout: int = DEFAULT_SCAN_TIMEOUT,
    use_binary: bool = False,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Scan a predefined set of common TCP ports."""
    return scan_ports(target, ports=DEFAULT_TCP_PORTS, timeout=timeout, use_binary=use_binary, stop_callback=stop_callback)


def scan_port_range(
    target: str,
    start_port: int,
    end_port: int,
    timeout: int = DEFAULT_SCAN_TIMEOUT,
    use_binary: bool = False,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Scan a custom TCP port range."""
    if start_port < 1 or end_port < start_port:
        raise ValueError("Invalid port range specified.")
    return scan_ports(
        target,
        ports=f"{start_port}-{end_port}",
        timeout=timeout,
        use_binary=use_binary,
        stop_callback=stop_callback,
    )


def scan_single_port(
    target: str,
    port: int,
    timeout: int = DEFAULT_SCAN_TIMEOUT,
    use_binary: bool = False,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Scan a single TCP port."""
    return scan_ports(
        target,
        ports=[port],
        timeout=timeout,
        use_binary=use_binary,
        stop_callback=stop_callback,
    )


def summarize_scan_result(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a lightweight summary from raw scan data."""
    return {
        "target": scan_data.get("target"),
        "ip_address": scan_data.get("ip_address"),
        "open_ports": scan_data.get("open_ports", []),
        "total_ports_scanned": scan_data.get("summary", {}).get("total_ports", 0),
        "open_port_count": scan_data.get("summary", {}).get("open_ports", 0),
    }


__all__ = [
    "normalize_target",
    "is_python_nmap_available",
    "is_system_nmap_available",
    "get_nmap_backend_status",
    "validate_nmap_backends",
    "scan_ports",
    "scan_common_ports",
    "scan_port_range",
    "scan_single_port",
    "summarize_scan_result",
]
