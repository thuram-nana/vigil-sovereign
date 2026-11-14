"""FATAL-2 import-cleanliness, checked in a FRESH interpreter (a helper module, not a test file).

An import-clean check written as a ``sys.modules`` scan inside the test process depends on test ORDER: any
earlier test in the same process that loaded ``framework`` (or put ``engine/crucible`` on ``sys.path`` at
module level) makes it fail, and in a process where ``framework`` cannot be imported at all it can never
fail, so a lazy or guarded cross-plane import inside the module under test would go unnoticed.

:func:`assert_import_clean` runs the snippet in a NEW ``sys.executable`` whose path makes BOTH planes
importable (``integration``, ``engine/crucible``, ``apps/sigil``, ``gateway``, plus ``vigil_core``), then
asserts that no forbidden top-level package was loaded. Because the child CAN import every plane, any import
of one — eager, lazy-at-import-time or guarded — is loaded and caught. The child is a separate interpreter,
so this test process never co-loads the planes (FATAL-2 is a per-process rule).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional

REPO = Path(__file__).resolve().parents[2]

# Every first-party plane is importable in the child, so an import of a forbidden one is LOADED, not skipped.
CHILD_PATH: tuple[str, ...] = (
    "integration",
    "engine/crucible",
    "apps/sigil",
    "gateway",
    "packages/core/vigil_core",
)
DEFAULT_FORBIDDEN: tuple[str, ...] = ("framework", "strix", "sigil")

_REPORT = """
import importlib.util as _ilu, json as _json, sys as _sys
_forbidden = set({forbidden!r})
_bad = sorted(_m for _m in list(_sys.modules) if _m.split(".")[0] in _forbidden)
print("@@FATAL2@@" + _json.dumps({{
    "bad": _bad,
    "framework_importable": _ilu.find_spec("framework") is not None,
}}))
"""


def child_env(extra_path: Iterable[str] = ()) -> dict[str, str]:
    """A minimal environment for the child: both planes on PYTHONPATH (``extra_path`` first), no inherited
    PYTHONPATH and no plane-selecting variables from the invoking shell."""
    paths = [str(p) for p in extra_path] + [str(REPO / p) for p in CHILD_PATH]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": os.pathsep.join(paths),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    return env


def import_report(snippet: str, forbidden: Iterable[str] = DEFAULT_FORBIDDEN,
                  extra_path: Iterable[str] = (), timeout: float = 120.0) -> dict:
    """Run ``snippet`` in a fresh interpreter and return ``{"bad": [...], "framework_importable": bool}``.
    Raises AssertionError (with the child's output) if the snippet itself fails."""
    code = snippet + "\n" + _REPORT.format(forbidden=tuple(forbidden))
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=timeout,
                          cwd=str(REPO), env=child_env(extra_path))
    report: Optional[dict] = None
    for line in proc.stdout.splitlines():
        if line.startswith("@@FATAL2@@"):
            report = json.loads(line[len("@@FATAL2@@"):])
    assert proc.returncode == 0 and report is not None, (
        f"the import-clean child failed (rc={proc.returncode}) running:\n{snippet}\n"
        f"--- stdout ---\n{proc.stdout[-4000:]}\n--- stderr ---\n{proc.stderr[-4000:]}"
    )
    return report


def assert_import_clean(snippet: str, forbidden: Iterable[str] = DEFAULT_FORBIDDEN,
                        extra_path: Iterable[str] = ()) -> None:
    """Assert that running ``snippet`` in a fresh both-planes interpreter loads no ``forbidden`` top-level
    package. Also asserts the child really could import ``framework`` — otherwise the check would prove
    nothing about a framework import."""
    report = import_report(snippet, forbidden=forbidden, extra_path=extra_path)
    assert report["framework_importable"], (
        "framework is not importable in the import-clean child, so a framework import could not be caught; "
        f"child PYTHONPATH={child_env(extra_path)['PYTHONPATH']}"
    )
    assert report["bad"] == [], f"cross-plane modules loaded by:\n{snippet}\n-> {report['bad']}"
