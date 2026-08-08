"""BRAIN-SLOT guard (red-pen HIGH-1): the vendored hexstrike-ai offense framework must be QUARANTINED —
never importable, never executable, never on any import path — and no VIGIL source may import it. The
only reuse is the clean-room drift-free brain (test_hexstrike_brain.py). This tripwire fails the build if
a future change makes the ungated upstream reachable.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_VENDOR = _REPO / "vendor" / "hexstrike-ai"
# the VIGIL source trees a runnable import could live in
_SRC_TREES = [
    _REPO / "integration" / "vigil_integration",
    _REPO / "engine" / "crucible" / "framework",
    _REPO / "gateway",
    _REPO / "packages" / "core",
    _REPO / "apps" / "sigil",
]
_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+hexstrike", re.MULTILINE)


def test_no_vigil_source_imports_hexstrike():
    offenders = []
    for tree in _SRC_TREES:
        if not tree.is_dir():
            continue
        for py in tree.rglob("*.py"):
            if _IMPORT_RE.search(py.read_text(encoding="utf-8", errors="ignore")):
                offenders.append(str(py.relative_to(_REPO)))
    assert not offenders, f"VIGIL source imports the quarantined hexstrike upstream: {offenders}"


def test_vendored_server_is_nonrunnable_reference_only():
    # the runnable modules must exist ONLY as .reference blobs (not importable/executable as .py modules)
    assert (_VENDOR / "hexstrike_server.py.reference").is_file()
    assert (_VENDOR / "hexstrike_mcp.py.reference").is_file()
    assert not (_VENDOR / "hexstrike_server.py").exists(), "runnable hexstrike_server.py must NOT be vendored"
    assert not (_VENDOR / "hexstrike_mcp.py").exists(), "runnable hexstrike_mcp.py must NOT be vendored"


def test_no_runnable_hexstrike_module_anywhere_in_repo():
    # a `python vendor/.../hexstrike_server.py` must be impossible: no importable/runnable copy anywhere
    bad = [str(p.relative_to(_REPO)) for p in _REPO.rglob("hexstrike_server.py")]
    bad += [str(p.relative_to(_REPO)) for p in _REPO.rglob("hexstrike_mcp.py")]
    # allow the scratch clone outside the repo; inside the repo there must be none
    assert not bad, f"a runnable hexstrike module exists in the repo tree: {bad}"


def test_attribution_present():
    lic = (_VENDOR / "LICENSE").read_text(encoding="utf-8")
    assert "MIT" in lic and "Muhammad Osama" in lic
    notice = (_REPO / "NOTICE").read_text(encoding="utf-8")
    assert "hexstrike-ai" in notice and "0x4m4" in notice
    assert (_VENDOR / "UPSTREAM.md").is_file()
