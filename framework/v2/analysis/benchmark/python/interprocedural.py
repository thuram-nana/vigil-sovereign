"""
DAA inter-procedural benchmark.

Taint crosses a function boundary: the request value flows through
`_passthrough` before reaching the command sink. This is the case CPG
dataflow (Joern) is built for. Benchmark fixture, not a runnable app.
"""

from __future__ import annotations

import os

from flask import request


def _passthrough(value: str) -> str:
    return value


def handler() -> None:
    name = request.args.get("cmd")          # source
    forwarded = _passthrough(name)          # taint crosses a call boundary
    os.system("ping -c1 " + forwarded)      # sink: CWE-78 (inter-procedural)
