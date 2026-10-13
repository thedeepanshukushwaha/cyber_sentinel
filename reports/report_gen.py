"""Compatibility wrapper for reports.report_gen."""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cybersentinel.reporting.report_gen import *
