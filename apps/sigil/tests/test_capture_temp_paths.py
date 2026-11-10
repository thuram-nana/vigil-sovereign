"""CQ-1 — capture output paths are created race-free (CodeQL py/insecure-temporary-file).

``tempfile.mktemp`` only returns a NAME in the shared temp dir: another local user can pre-create that name, or
a symlink at it, between the name being chosen and the screenshot / camera tool writing it. Every capture site
now uses ``private_capture_path``: its own fresh ``0700`` directory with an unpredictable name, and an output
file that does not exist yet (each tool creates / overwrites its output path exactly as before).
"""
from __future__ import annotations

import ast
import os
import stat
from pathlib import Path

from sigil.perception.capture import private_capture_path

_SIGIL = Path(__file__).resolve().parents[1] / "sigil"


def test_each_capture_gets_its_own_private_directory_and_a_fresh_path():
    a = Path(private_capture_path("sigil-screen-", ".png"))
    b = Path(private_capture_path("sigil-screen-", ".png"))
    for p in (a, b):
        assert not p.exists()                                       # the tool creates it, as before
        assert p.suffix == ".png" and p.parent.name.startswith("sigil-screen-")
        mode = stat.S_IMODE(os.stat(p.parent).st_mode)
        assert mode == 0o700, oct(mode)                            # no other user can plant a file/symlink here
        assert p.parent.owner() == Path.home().owner() or os.getuid() == os.stat(p.parent).st_uid
    assert a.parent != b.parent                                     # never a shared, guessable location
    for p in (a, b):
        p.parent.rmdir()


def test_a_capture_tool_can_write_the_path():
    p = Path(private_capture_path("sigil-cam-", ".jpg"))
    p.write_bytes(b"\xff\xd8frame")                                 # what screencap / ffmpeg / mss do
    assert p.read_bytes().startswith(b"\xff\xd8")
    p.unlink()
    p.parent.rmdir()


def test_no_shipped_sigil_code_calls_mktemp():
    """A real CALL (AST), not a docstring mention."""
    offenders = []
    for f in _SIGIL.rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) == "mktemp":
                offenders.append(f"{f.relative_to(_SIGIL)}:{node.lineno}")
    assert offenders == [], offenders
