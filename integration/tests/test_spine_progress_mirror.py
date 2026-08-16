"""Engine→console live-steps bridge: the integration `vigil engage` OODA timeline is mirrored to the
console's progress feed. The engine's ``spine_post`` seam already writes every OODA event to the
blackboard DB; this adds a best-effort mirror to ``$VIGIL_PROOF_RUN_DIR/progress.jsonl`` (the file the
console's ``/api/events?run=`` already tails) in KIND_META-native ``{kind, payload}`` shape, so the
process box / Live view show the full timeline of an integration-engine run — not just the handful of
event names the older scan/strix bridge emitted.

Invariants:
  * every OODA kind the engine posts is mirrored verbatim as ``{kind, payload}``;
  * the mirror NO-OPS with no ``$VIGIL_PROOF_RUN_DIR`` (a hand-run engage is unaffected);
  * the mirror runs even when the framework blackboard is absent (sink is None) — a run with no
    blackboard still narrates its steps to the operator;
  * the mirror is best-effort and boundary-clean (progress.py is stdlib-only).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vigil_integration.live.wiring import _build_spine_poster


def _lines(d) -> list:
    p = os.path.join(str(d), "progress.jsonl")
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


@pytest.fixture(autouse=True)
def _run_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(tmp_path))
    (tmp_path / "progress.jsonl").write_text("", encoding="utf-8")   # console pre-creates it
    yield tmp_path


def test_every_ooda_kind_is_mirrored_to_progress(tmp_path):
    post = _build_spine_poster("mirror-slug")
    assert callable(post), "the poster must always be built (progress mirror is unconditional)"
    post("decision", {"question": "probe login?", "choice": "USE_TOOL", "rationale": "auth smells off"})
    post("tool_call", {"tool": "nmap", "target": "127.0.0.1", "tier": "A1", "args_summary": "-sV"})
    post("finding", {"ref": "run-1", "title": "sqli", "bug_class": "sqli", "surface": "/x",
                     "status": "fact", "verified_by_oracle": True})
    post("refusal", {"gate": "authorize_edge", "action_refused": "exec", "reason": "A3 needs approval"})

    got = _lines(tmp_path)
    kinds = [e.get("kind") for e in got]
    assert kinds == ["decision", "tool_call", "finding", "refusal"], got
    # payloads are carried verbatim (KIND_META reads these plain keys directly)
    dec = next(e for e in got if e["kind"] == "decision")
    assert dec["payload"]["question"] == "probe login?" and dec["payload"]["choice"] == "USE_TOOL"
    fnd = next(e for e in got if e["kind"] == "finding")
    assert fnd["payload"]["verified_by_oracle"] is True and fnd["payload"]["bug_class"] == "sqli"


def test_no_run_dir_no_progress(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    post = _build_spine_poster("mirror-slug")
    post("decision", {"question": "q", "choice": "c"})
    # nothing written anywhere under the tmp run dir — the hand-run engage path is unaffected
    assert _lines(tmp_path) == []


def test_mirror_runs_even_without_the_blackboard(tmp_path, monkeypatch):
    """The sink is None (no blackboard DB) → the poster is STILL built and STILL mirrors to progress (the
    operator sees steps even with no blackboard). Works in BOTH environments: where `framework` is present
    (force open_blackboard to raise → sink None), and where it is ABSENT — the two-env P5 process runs with
    no `framework` on the path, which is *itself* the no-blackboard case (`_build_spine_poster` catches the
    ImportError → sink None). So we never hard-import `framework` here."""
    try:
        import framework.v2.agents.blackboard as bb
        monkeypatch.setattr(bb, "open_blackboard",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no bb")))
    except ModuleNotFoundError:
        pass  # framework absent (the P5 sovereign-path process) — sink is already None: the case under test
    post = _build_spine_poster("mirror-slug")
    assert callable(post), "poster must be built even when the blackboard cannot open"
    post("observation", {"source": "lead:web", "surface": "/login", "summary": "LEAD (unconfirmed): x"})
    got = _lines(tmp_path)
    assert [e["kind"] for e in got] == ["observation"]
    assert got[0]["payload"]["summary"].startswith("LEAD")
