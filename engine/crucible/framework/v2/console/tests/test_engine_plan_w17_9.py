"""
W17-9 — surface the agentic engine's TRIPLE-CONJUNCTION gate BEFORE the operator clicks Send.

The agentic (integration ``vigil engage``) engine runs ONLY when
``(agentic|graph_backed) AND session_id AND is_loopback`` AND a ``vigil`` entrypoint resolves; otherwise
the launch SILENTLY fell through to the plain offense engine (and, when ``vigil`` was off PATH, said
nothing at all). ``actions.engine_plan`` is the PRE-Send preflight that states WHICH engine will run and,
when the agentic one will not, NAMES the unmet conjunct.

These tests pin:
  * each of the three conjuncts (no session / remote target / ``vigil`` not on PATH) yields a DISTINCT,
    visible reason key + sentence — the fall-through reason mapping;
  * the POSITIVE control: with every conjunct met, the plan says the agentic engine WILL run ("");
  * a NEGATIVE control: a deliberately bad state (``vigil`` off PATH) is NOT routed to the agentic engine;
  * a source/logic guard: the plan cannot disagree with the real routing — when the plan says the agentic
    engine runs, ``launch_assessment`` spawns ``engine:"integration"``; when it names an unmet reason, it
    does NOT — so the surfaced reason can never drift from what the launch actually does.

Every assertion here references ``actions.engine_plan`` / ``actions._agentic_unmet_reason``, which do not
exist on a tree WITHOUT the fix (the import/attribute access fails), so the suite fails without it.
"""

from __future__ import annotations

import json

import pytest

from framework.v2.console import actions


_LOOPBACK = "http://127.0.0.1:8000/"
_REMOTE = "https://app.example.com/"


@pytest.fixture()
def vigil_present(monkeypatch):
    """The ``vigil`` entrypoint resolves — so the PATH conjunct is met and only the OTHER conjuncts vary."""
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/local/bin/vigil")


# ---------------------------------------------------------------------------
# the reason mapping — each conjunct yields a DISTINCT, visible reason
# ---------------------------------------------------------------------------

def test_agentic_runs_when_every_conjunct_is_met(vigil_present):
    """POSITIVE control — opted in, a session, loopback, and `vigil` on PATH → the agentic engine WILL run."""
    p = actions.engine_plan({"mode": "url", "target": _LOOPBACK, "session_id": "sess1", "agentic": True})
    assert p["agentic_unmet"] == ""              # every conjunct met
    assert p["agentic_requested"] is True
    assert p["engine"] == "integration"
    assert "vigil engage" in p["engine_label"]


def test_no_session_names_its_own_reason(vigil_present):
    p = actions.engine_plan({"mode": "url", "target": _LOOPBACK, "session_id": "", "agentic": True})
    assert p["agentic_unmet"] == "no_session"
    assert p["engine"] != "integration"          # fell through — the offense engine
    assert "session" in p["agentic_unmet_reason"].lower()


def test_remote_target_names_its_own_reason(vigil_present, monkeypatch):
    monkeypatch.setattr(actions, "_has_charter", lambda slug: True)  # so it is a routing, not a refusal
    p = actions.engine_plan({"mode": "url", "target": _REMOTE, "session_id": "sess1", "agentic": True})
    assert p["agentic_unmet"] == "remote_target"
    assert p["engine"] != "integration"
    assert "loopback" in p["agentic_unmet_reason"].lower()


def test_vigil_not_on_path_names_its_own_reason(monkeypatch):
    """NEGATIVE control — every OTHER conjunct is met, but `vigil` is deliberately OFF PATH: the plan must
    say so (this is the silent fall-through the issue calls out), and must NOT route to the agentic engine."""
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)         # off PATH
    p = actions.engine_plan({"mode": "url", "target": _LOOPBACK, "session_id": "sess1", "agentic": True})
    assert p["agentic_unmet"] == "vigil_not_on_path"
    assert p["engine"] != "integration"          # the gate is not a no-op — the bad state is rejected
    assert "path" in p["agentic_unmet_reason"].lower()


def test_the_three_fall_through_reasons_are_distinct_and_visible(vigil_present, monkeypatch):
    """The three conjuncts must map to THREE distinct reason keys AND three distinct sentences — a single
    'it fell through' would hide which condition to fix."""
    monkeypatch.setattr(actions, "_has_charter", lambda slug: True)
    no_session = actions.engine_plan({"mode": "url", "target": _LOOPBACK, "session_id": "", "agentic": True})
    remote = actions.engine_plan({"mode": "url", "target": _REMOTE, "session_id": "sess1", "agentic": True})
    with monkeypatch.context() as m:
        m.setattr(actions, "_vigil_bin", lambda: None)
        no_vigil = actions.engine_plan({"mode": "url", "target": _LOOPBACK, "session_id": "sess1",
                                        "agentic": True})
    keys = {no_session["agentic_unmet"], remote["agentic_unmet"], no_vigil["agentic_unmet"]}
    assert keys == {"no_session", "remote_target", "vigil_not_on_path"}   # three DISTINCT keys
    sentences = {no_session["agentic_unmet_reason"], remote["agentic_unmet_reason"],
                 no_vigil["agentic_unmet_reason"]}
    assert len(sentences) == 3                                           # three DISTINCT sentences
    assert all(s.strip() for s in sentences)                            # each is non-empty (visible)


def test_graph_backed_is_honoured_as_the_legacy_alias(vigil_present):
    """The gate opts in on EITHER `agentic` or the legacy `graph_backed` — both must open the same engine."""
    p = actions.engine_plan({"mode": "url", "target": _LOOPBACK, "session_id": "sess1", "graph_backed": True})
    assert p["agentic_unmet"] == "" and p["engine"] == "integration"


def test_not_requested_is_not_a_fall_through(vigil_present):
    """A body that never opted in is NOT a fall-through — the offense engine was the choice, not a silent
    downgrade — so no unmet-conjunct reason is surfaced as a problem."""
    p = actions.engine_plan({"mode": "url", "target": _LOOPBACK, "session_id": "sess1"})
    assert p["agentic_requested"] is False
    assert p["agentic_unmet"] == "not_requested"
    assert p["engine"] != "integration"


# ---------------------------------------------------------------------------
# source/logic guard — the plan cannot disagree with the real routing
# ---------------------------------------------------------------------------

@pytest.fixture()
def stub_spawn(tmp_path, monkeypatch):
    """Redirect the run registry to tmp and NO-OP the spawn, so ``launch_assessment`` records its argv +
    meta (which name the engine) without running any real tool."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_spawn_background", lambda *a, **k: None)
    def _meta(run_id):
        return json.loads((tmp_path / "runs" / run_id / "meta.json").read_text(encoding="utf-8"))
    return _meta


def _launch_engine(body: dict, meta_reader) -> str:
    r = actions.launch_assessment(dict(body))
    if "run_id" not in r:
        return "error"
    return str(meta_reader(r["run_id"]).get("engine") or "offense")


def test_plan_matches_the_real_routing_when_agentic_runs(vigil_present, stub_spawn):
    """If the plan says the agentic engine will run, the SAME body must actually spawn engine:'integration'."""
    body = {"mode": "url", "target": _LOOPBACK, "session_id": "sess1", "agentic": True}
    p = actions.engine_plan(body)
    assert p["agentic_unmet"] == "" and p["engine"] == "integration"
    assert _launch_engine(body, stub_spawn) == "integration"            # no drift plan↔run


def test_plan_matches_the_real_routing_when_vigil_off_path(monkeypatch, stub_spawn):
    """If the plan names `vigil_not_on_path`, the SAME body must NOT spawn the agentic engine (it silently
    fell through before this fix; now the plan states it BEFORE Send)."""
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    body = {"mode": "url", "target": _LOOPBACK, "session_id": "sess1", "agentic": True}
    p = actions.engine_plan(body)
    assert p["agentic_unmet"] == "vigil_not_on_path"
    engine = _launch_engine(body, stub_spawn)
    assert engine != "integration"                                      # fell through to the offense engine


def test_launch_response_names_the_fall_through_engine(monkeypatch, stub_spawn):
    """No silent fall-through at RUNTIME either: when `vigil` is off PATH the launch RESPONSE carries an
    `engine_note` naming that the agentic engine was requested but the offense engine ran."""
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    r = actions.launch_assessment({"mode": "url", "target": _LOOPBACK, "session_id": "sess1",
                                   "agentic": True, "scan_mode": "quick"})
    assert "engine_note" in r and "agentic" in r["engine_note"].lower()
