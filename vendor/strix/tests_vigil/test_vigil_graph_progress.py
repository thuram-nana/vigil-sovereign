"""VIGIL W6c — the vendored-Strix half of the progress bridge.

``AgentCoordinator._maybe_snapshot`` mirrors a compact graph histogram to the console's live process box.
Three properties matter and none was covered by the integration-side tests:

  * a BARE vendored checkout (no ``vigil_integration`` importable) is a silent no-op — the vendor stays
    byte-identical at runtime — and the failed import is attempted ONCE per process, not on every one of
    the seven coordinator mutation sites;
  * the emit fires only when the histogram CHANGES, so the box's bounded scrollback holds real
    transitions rather than hundreds of identical lines;
  * a snapshot failure (``None``) never reaches the bridge.
"""

from __future__ import annotations

import contextlib
import sys
import types

import pytest


def _load_agents():
    """Import ``strix.core.agents`` without the heavy SDK. It needs exactly one symbol from
    ``strix.core.sessions`` (``session_write_lock``), and that module imports the openai-agents SDK at
    top level — so stub it. This keeps the test running EVERYWHERE rather than skipping wherever the SDK
    is absent (a skipped test would leave the bridge's only coverage decorative)."""
    installed = False
    if "strix.core.sessions" not in sys.modules:
        stub = types.ModuleType("strix.core.sessions")
        stub.session_write_lock = contextlib.nullcontext
        sys.modules["strix.core.sessions"] = stub
        installed = True
    try:
        import strix.core.agents as mod
    finally:
        # Remove the stub again: it defines ONLY session_write_lock, while strix.core.{inputs,runner,
        # execution} import other names from that module — leaving it in sys.modules would silently
        # break any future test in this process that imports one of them.
        if installed:
            sys.modules.pop("strix.core.sessions", None)
    return mod


agents = _load_agents()


@pytest.fixture(autouse=True)
def _reset_bridge_state():
    agents._vigil_last_graph = None
    agents._vigil_bridge_absent = False
    yield
    agents._vigil_last_graph = None
    agents._vigil_bridge_absent = False


class _BlockVigilIntegration:
    """Simulate a bare vendored checkout: `vigil_integration` is simply not importable."""

    def find_module(self, name, path=None):   # legacy API, harmless
        return None

    def find_spec(self, name, path=None, target=None):
        if name == "vigil_integration" or name.startswith("vigil_integration."):
            raise ModuleNotFoundError(f"No module named {name!r}")
        return None


def test_bare_checkout_is_a_silent_noop_and_the_import_is_attempted_once(monkeypatch):
    for mod in [m for m in list(sys.modules) if m.startswith("vigil_integration")]:
        monkeypatch.delitem(sys.modules, mod, raising=False)
    blocker = _BlockVigilIntegration()
    monkeypatch.setattr(sys, "meta_path", [blocker, *sys.meta_path])

    snap = {"statuses": {"a1": "running"}}
    for _ in range(50):
        agents._vigil_emit_graph_progress(snap)     # must never raise
    assert agents._vigil_bridge_absent is True, "a failed import must be remembered, not retried per mutation"
    assert agents._vigil_last_graph is None


@pytest.fixture()
def emitted(monkeypatch):
    """A FAKE ``vigil_integration.progress`` so these tests run WHEREVER the suite runs.

    They exercise STRIX-side logic — emit-on-change and the None guard — while the real writer is
    covered by ``integration/tests/test_progress_bridge.py``. Requiring the real package here made both
    tests skip permanently in CI (the strix job never puts `integration` on the path), which is how two
    mutants survived: dropping the dedup, and emitting on a failed snapshot."""
    calls = []
    pkg = types.ModuleType("vigil_integration")
    pkg.__path__ = []
    mod = types.ModuleType("vigil_integration.progress")

    def _append(event, **_kw):
        calls.append(dict(event))
        return True

    def _graph(snap):
        if not snap or not isinstance(snap, dict):
            return None
        statuses = snap.get("statuses") or {}
        if not isinstance(statuses, dict):
            return None
        counts: dict[str, int] = {}
        for st in statuses.values():
            counts[str(st)] = counts.get(str(st), 0) + 1
        return {"event": "strix.graph", "agents": len(statuses), "statuses": counts}

    mod.append_progress = _append
    mod.strix_graph_event = _graph
    monkeypatch.setitem(sys.modules, "vigil_integration", pkg)
    monkeypatch.setitem(sys.modules, "vigil_integration.progress", mod)
    return calls


def test_emits_only_on_change(emitted):
    same = {"statuses": {"a1": "running", "a2": "running"}}
    for _ in range(25):
        agents._vigil_emit_graph_progress(same)
    agents._vigil_emit_graph_progress({"statuses": {"a1": "completed", "a2": "running"}})
    assert len(emitted) == 2, f"expected one emit per DISTINCT histogram, got {len(emitted)}"
    assert emitted[0]["statuses"] == {"running": 2}
    assert emitted[1]["statuses"] == {"completed": 1, "running": 1}


def test_a_failed_snapshot_never_reaches_the_bridge(emitted):
    agents._vigil_emit_graph_progress(None)      # _maybe_snapshot passes None when snapshot() failed
    agents._vigil_emit_graph_progress({})
    assert emitted == []
