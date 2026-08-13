"""`launch_scan` must actually honour `use_library` — it used to accept it and drop it.

The parameter appeared exactly ONCE in `console/actions.py`: in the signature. Nothing read it,
so every console-launched scan ran the built-in checks only and never the declarative check
library, while the caller believed it had asked for both (the default is True). The scan looked
healthy and its report looked complete; it was simply narrower than anyone thought.

That failure mode — a flag that is accepted, defaulted ON, and silently ignored — leaves no trace
in the output to notice, which is why it needs a test rather than a comment. These assert the
built command, since the command IS the contract between the console and the scanner.
"""

from __future__ import annotations

import json

from framework.v2.console import actions


def _cmd_for(monkeypatch, tmp_path, **kwargs) -> list[str]:
    """Launch a scan with the subprocess stubbed out, and return the argv it would have run.
    Reads the command back from the run's meta.json, which is where launch_scan records it."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    # never actually spawn: replace the thread target so the launch is pure bookkeeping
    monkeypatch.setattr(actions.threading, "Thread", lambda *a, **k: type(
        "_T", (), {"start": lambda self: None, "daemon": True})())
    res = actions.launch_scan("http://127.0.0.1:18080/", **kwargs)
    assert "error" not in res, res
    meta = json.loads((tmp_path / "runs" / res["run_id"] / "meta.json").read_text(encoding="utf-8"))
    return list(meta["cmd"])


def test_use_library_true_passes_the_library_flag(monkeypatch, tmp_path):
    # the default is True, so the DEFAULT console scan must include the library
    assert "--library" in _cmd_for(monkeypatch, tmp_path)


def test_use_library_false_omits_the_flag(monkeypatch, tmp_path):
    """MUTATION CONTROL for the test above: the flag is driven by the parameter, not
    unconditionally appended. Without this, hard-coding `--library` would pass the first test
    while quietly removing the caller's ability to turn it off."""
    assert "--library" not in _cmd_for(monkeypatch, tmp_path, use_library=False)


def test_the_scanner_actually_accepts_the_flag_we_pass(monkeypatch, tmp_path):
    """The console and the scanner are separate programs, so a flag name agreed only by
    convention can drift. Assert the scanner's parser really declares `--library`, otherwise the
    console would pass an argument that makes every scan exit non-zero."""
    from framework.v2.scanner import cli as scanner_cli

    parser = scanner_cli.build_parser() if hasattr(scanner_cli, "build_parser") else None
    if parser is None:                      # parser built inline; fall back to the source
        import inspect
        assert '"--library"' in inspect.getsource(scanner_cli)
    else:
        assert any("--library" in (a.option_strings or []) for a in parser._actions)
