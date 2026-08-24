"""Make the ``vscp`` package importable when pytest runs from the vscp project dir.

The VSCP-own test suite runs from ``vscp/`` (its own CI job). This puts the project dir on
``sys.path`` so ``import vscp`` resolves to ``vscp/vscp``. ``vigil_core`` is provided by the
environment (installed, or on PYTHONPATH) — VSCP's one runtime dependency.
"""
from __future__ import annotations

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
