"""Compatibility wrapper for modules.web_assess."""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cybersentinel.scanners.web_scanner import *
