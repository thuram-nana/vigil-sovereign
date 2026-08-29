"""Test helpers for the range. Makes `vigil_range` importable uninstalled and offers a free-port picker."""

from __future__ import annotations

import os
import socket
import sys

# Allow `import vigil_range` when running the suite from a checkout without an editable install.
_RANGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _RANGE_ROOT not in sys.path:
    sys.path.insert(0, _RANGE_ROOT)

REPO_ROOT = os.path.dirname(_RANGE_ROOT)


def free_port() -> int:
    """An ephemeral loopback port, released immediately (races are acceptable in a single-host test)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
