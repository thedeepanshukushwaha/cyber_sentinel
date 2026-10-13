"""Project configuration and path utilities for CyberSentinel."""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent if PACKAGE_DIR.name == "cybersentinel" else PACKAGE_DIR

OS_NAME = platform.system()
IS_WINDOWS = OS_NAME == "Windows"
IS_LINUX = OS_NAME == "Linux"
IS_MAC = OS_NAME == "Darwin"

# Directories
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMPLATES_DIR = PACKAGE_DIR / "reporting" / "templates"
if not TEMPLATES_DIR.exists():
    TEMPLATES_DIR = PROJECT_ROOT / "reports" / "templates"

WORDLISTS_DIR = PACKAGE_DIR / "wordlists"
if not WORDLISTS_DIR.exists():
    WORDLISTS_DIR = PROJECT_ROOT / "wordlists"

LOG_DIR = PROJECT_ROOT / "logs"

DEFAULT_SCAN_TIMEOUT = 60
DEFAULT_HTTP_TIMEOUT = 10

AUTHORIZED_USE_NOTICE = (
    "WARNING: Only scan targets you own or have explicit authorization to test. "
    "Unauthorized scanning may be illegal and unethical."
)

# AI Provider API Keys
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip() or None
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip() or None
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip() or None

# Default AI provider and model
DEFAULT_AI_PROVIDER = "openrouter"  # "openrouter", "claude", "gemini"
AI_MODELS = {
    "openrouter": {
        "name": "OpenRouter (Free Gateway)",
        "default_model": "google/gemini-2.0-flash-exp",
        "fallback_models": [
            "openrouter/owl-alpha",
            "tencent/hy3-preview",
            "nvidia/nemotron-3-super",
            "inclusionai/ling-2.6-1t",
            "openai/gpt-oss-120b",
            "poolside/laguna-m.1",
            "z.ai/glm-4.5-air",
        ],
        "api_key_env": "OPENROUTER_API_KEY",
    },
    "claude": {
        "name": "Claude (Anthropic)",
        "default_model": "claude-sonnet-4-20250514",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "gemini": {
        "name": "Gemini (Google)",
        "default_model": "gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
    },
}

TOOL_NAMES: Dict[str, str] = {
    "nmap": "nmap",
    "subfinder": "subfinder",
    "dirsearch": "dirsearch",
    "nikto": "nikto",
    "python": "python" if IS_WINDOWS else "python3",
}

TOOL_PATHS: Dict[str, Optional[str]] = {
    name: None for name in TOOL_NAMES.keys()
}

PORT_PRIORITIES: Dict[int, int] = {
    # Critical ports
    21: 1,      # FTP
    23: 1,      # Telnet
    445: 1,     # SMB
    3306: 1,    # MySQL
    3389: 1,    # RDP
    # High priority
    22: 2,      # SSH
    25: 2,      # SMTP
    80: 2,      # HTTP
    # Medium priority
    443: 3,     # HTTPS
    8080: 3,    # Alt HTTP
    8443: 3,    # Alt HTTPS
    # Other common ports
    53: 4,      # DNS
    110: 4,     # POP3
    143: 4,     # IMAP
    389: 4,     # LDAP
    427: 4,     # SLP
    465: 4,     # SMTPS
    587: 4,     # SMTP
    636: 4,     # LDAPS
    993: 4,     # IMAPS
    995: 4,     # POP3S
    1433: 4,    # MSSQL
    5432: 4,    # PostgreSQL
    5984: 4,    # CouchDB
    6379: 4,    # Redis
    7000: 4,    # Cassandra
    7001: 4,    # Cassandra
    8000: 4,    # Alt HTTP
    8001: 4,    # Alt HTTP
    8888: 4,    # Alt HTTP
    9000: 4,    # SonarQube
    9200: 4,    # Elasticsearch
    9300: 4,    # Elasticsearch
    11211: 4,   # Memcached
    27017: 4,   # MongoDB
    50070: 4,   # Hadoop
}

COMMON_PORT_GROUPS = {
    "web_only": [80, 443, 8080, 8443, 8000, 8888],
    "web_and_ssh": [22, 80, 443, 8080, 8443],
    "database": [3306, 5432, 1433, 27017, 6379],
    "all_common": list(PORT_PRIORITIES.keys()),
}

RISK_SCORE_WEIGHTS: Dict[str, int] = {
    "open_ftp": 15,
    "open_telnet": 20,
    "open_rdp": 15,
    "missing_security_header": 10,
    "exposed_admin_directory": 25,
    "outdated_service_version": 10,
}

HTML_REPORT_TEMPLATE = TEMPLATES_DIR / "report.html"


def locate_executable(name: str, extra_paths: Optional[List[Path]] = None) -> Optional[str]:
    """Locate an executable in the system PATH or in common install locations."""
    candidate = shutil.which(name)
    if candidate:
        return candidate

    if extra_paths is None:
        extra_paths = []

    for directory in extra_paths:
        candidate_path = directory / name
        if IS_WINDOWS:
            candidate_path = candidate_path.with_suffix(".exe")
        if candidate_path.exists():
            return str(candidate_path)

    return None


def build_tool_paths() -> Dict[str, Optional[str]]:
    """Resolve tool paths for the current operating system."""
    search_locations: List[Path] = []

    if IS_WINDOWS:
        search_locations.extend([
            Path("C:/Program Files/Nmap"),
            Path("C:/Program Files (x86)/Nmap"),
            Path("C:/tools"),
            Path(os.getenv("LOCALAPPDATA", "")) / "Programs",
        ])
    else:
        search_locations.extend([
            Path("/usr/bin"),
            Path("/usr/local/bin"),
            Path("/snap/bin"),
            Path.home() / ".local" / "bin",
        ])

    for tool_name, binary in TOOL_NAMES.items():
        if tool_name == "python":
            TOOL_PATHS[tool_name] = shutil.which(binary) or shutil.which("python")
        else:
            TOOL_PATHS[tool_name] = locate_executable(binary, search_locations)

    return TOOL_PATHS


def ensure_directories() -> None:
    """Create required workspace directories if they do not already exist."""
    for directory in (REPORTS_DIR, TEMPLATES_DIR, WORDLISTS_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def get_tool_path(tool_name: str) -> Optional[str]:
    """Return the resolved executable path for a named tool."""
    return TOOL_PATHS.get(tool_name)


def get_anthropic_api_key() -> Optional[str]:
    """Return the Anthropic API key from the environment."""
    return ANTHROPIC_API_KEY


def get_gemini_api_key() -> Optional[str]:
    """Return the Gemini API key from the environment."""
    return GEMINI_API_KEY


def get_openrouter_api_key() -> Optional[str]:
    """Return the OpenRouter API key from the environment."""
    return OPENROUTER_API_KEY


def get_ai_api_key(provider: str, settings_manager=None) -> Optional[str]:
    """Return the API key for the specified AI provider.
    
    First checks environment variables, then falls back to settings_manager if provided.
    """
    key = None
    if provider == "openrouter":
        key = get_openrouter_api_key()
    elif provider == "claude":
        key = get_anthropic_api_key()
    elif provider == "gemini":
        key = get_gemini_api_key()
    
    # Fallback to settings if environment variable not found
    if not key and settings_manager:
        try:
            key = settings_manager.get_api_key(provider)
        except Exception:
            pass
    
    return key


def set_ai_api_key(provider: str, api_key: str) -> None:
    """Set the API key for the specified AI provider in environment."""
    if provider == "openrouter":
        os.environ["OPENROUTER_API_KEY"] = api_key
        global OPENROUTER_API_KEY
        OPENROUTER_API_KEY = api_key
    elif provider == "claude":
        os.environ["ANTHROPIC_API_KEY"] = api_key
        global ANTHROPIC_API_KEY
        ANTHROPIC_API_KEY = api_key
    elif provider == "gemini":
        os.environ["GEMINI_API_KEY"] = api_key
        global GEMINI_API_KEY
        GEMINI_API_KEY = api_key


def is_tool_available(tool_name: str) -> bool:
    """Check whether a named external tool is available."""
    return bool(get_tool_path(tool_name))


# Initialize tool paths and workspace directories when imported.
TOOL_PATHS = build_tool_paths()
ensure_directories()
