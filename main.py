#!/usr/bin/env python3
"""CyberSentinel — Top-Level Entry Point Wrapper.

This entry point allows running CyberSentinel directly from the repository root:
    python main.py 127.0.0.1
    python main.py --gui
"""

import sys
from pathlib import Path

# Ensure src/ and repository root are on sys.path
_REPO_ROOT = Path(__file__).resolve().parent
_SRC_DIR = _REPO_ROOT / "src"

if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(1, str(_REPO_ROOT))

from cybersentinel.main import main

if __name__ == "__main__":
    raise SystemExit(main())
