"""W17-8 — the Brain-decision panel's data path is GENUINELY PRODUCED (no longer a file nothing writes).

The defect (issue #542): the console's Brain-decision panel reads ``<run_dir>/brain-proposal.json`` via
``api.brain_decision``, but NOTHING in the repo ever wrote that file — the panel was pure documentation.

The fix wires the REAL producer: a ``vigil engage --brain hexstrike`` run drives
``vigil_integration.brains.engine_think.BrainThink``, which now persists the ordered chain it proposes to
``<run_dir>/brain-proposal.json`` (opt-in, from the ``VIGIL_PROOF_RUN_DIR`` run dir the console already
hands a spawned run, or an explicit ``proposal_out``). The console reader then surfaces it.

What is pinned here — the acceptance criteria of #542:
  * PRODUCED, not documentation: the REAL producer (``BrainThink``, as the CLI constructs and the engine
    drives it) writes the exact file ``api.brain_decision`` reads, and the panel renders its chain.
    (fail-before/pass-after: without the ``_persist`` wiring the file is never written → ``present`` is
    False → these asserts fail.)
  * NEGATIVE CONTROL 1 — no cross-run stale bleed: a run with no proposal renders the explicit empty state
    even when ANOTHER run has one (``?run=`` scoping, no fallback).
  * NEGATIVE CONTROL 2 — a deliberately bad persisted state (malformed / wrong-typed brain-proposal.json)
    is rejected to the honest empty state, never a fabricated chain and never a 500.
  * STRUCTURAL: the basename the API reads is the same basename the producer writes — the panel no longer
    reads a file nothing writes; and the route is `?run=`-scoped (not a zero-arg exact route that would
    drop the scope back to "any run").

Runs in the OFFENSE leg (it needs both ``vigil_integration`` and ``framework`` importable); the module-top
``importorskip("framework")`` makes it skip cleanly in the sovereign leg.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("framework")  # offense leg only — the sovereign leg lacks engine/crucible on the path

from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain


TARGET = "http://127.0.0.1/"

_REPO = Path(__file__).resolve().parents[2]   # integration/tests/<file> → repo root (cwd-independent)
_API = _REPO / "engine/crucible/framework/v2/console/api.py"
_PRODUCER = _REPO / "integration/vigil_integration/brains/engine_think.py"
_DOC = _REPO / "docs/plain-english/_inventory/B-screens-and-ui.md"


@pytest.fixture()
def console_root(tmp_path, monkeypatch):
    """Point the console's run store at tmp_path so api.brain_decision reads our fixture run dirs."""
    from framework.v2.console import actions
    root = tmp_path / "console"
    (root / "runs").mkdir(parents=True)
    monkeypatch.setattr(actions, "console_dir", lambda: root)
    return root


def _run_dir(console_root: Path, run_id: str) -> Path:
    d = console_root / "runs" / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _drive_brain(*, target: str = TARGET, objective: str = "comprehensive",
                 proposal_out: "Path | None" = None) -> list:
    """Drive BrainThink EXACTLY as `vigil engage --brain hexstrike` does: construct it as the CLI does
    (``BrainThink(HexstrikeBrain(), target=..., objective=...)``) and call it repeatedly with the engine's
    AgentState until the chain is exhausted. Returns the ordered tool names it proposed."""
    bt = BrainThink(HexstrikeBrain(), target=target, objective=objective, proposal_out=proposal_out)
    state = SimpleNamespace(objective=target)
    tools: list[str] = []
    for _ in range(64):  # bounded; the chain is short and terminates with COMPLETE
        dec = bt(state)
        tc = getattr(dec, "tool", None)
        if tc is None:  # COMPLETE — chain exhausted
            break
        tools.append(tc.tool_name)
    assert tools, "the brain proposed no steps — fixture/brain broken"
    return tools


# ---------------------------------------------------------------------------------------------------
# PRODUCED: the real producer writes the file the panel reads (fail-before/pass-after)
# ---------------------------------------------------------------------------------------------------
def test_real_producer_writes_the_file_the_panel_reads(console_root):
    from framework.v2.console import api

    rd = _run_dir(console_root, "A")
    proposed = _drive_brain(proposal_out=rd)

    # the producer wrote EXACTLY the file the reader reads
    artifact = rd / "brain-proposal.json"
    assert artifact.is_file(), "BrainThink did not persist brain-proposal.json (the wiring is missing)"

    d = api.brain_decision(run_id="A")
    prop = d["proposal"]
    assert prop["present"] is True, "the panel did not surface the persisted proposal"
    assert prop["run_id"] == "A"
    assert prop["target"] == TARGET
    assert prop["objective"] == "comprehensive"
    assert prop["posture"] == "live"

    # the panel's chain is EXACTLY what the engine drove (single serialiser — no drift)
    panel_tools = [s["tool"] for s in prop["steps"]]
    assert panel_tools == proposed, (panel_tools, proposed)

    # every step carries the fields the UI renders (tool/priority/danger/effectiveness/params)
    for s in prop["steps"]:
        assert {"tool", "priority", "danger", "effectiveness", "params"} <= set(s), s
        assert s["danger"] in ("recon", "active")

    # the OBSERVED profile carries the fields the panel's `brainProfile` reads
    assert {"target", "target_type", "attack_surface_score", "risk_level", "confidence_score"} \
        <= set(prop["profile"]), prop["profile"]


def test_env_run_dir_triggers_persistence_like_a_spawned_run(console_root, monkeypatch):
    """The real trigger the console uses is the ``VIGIL_PROOF_RUN_DIR`` env it hands a spawned run — not an
    explicit arg. Prove the producer honours it (constructed exactly as the CLI does, with no proposal_out)."""
    from framework.v2.console import api

    rd = _run_dir(console_root, "ENV")
    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(rd))
    _drive_brain()  # no proposal_out → falls back to the env
    assert (rd / "brain-proposal.json").is_file()
    assert api.brain_decision(run_id="ENV")["proposal"]["present"] is True


def test_opt_in_no_run_dir_writes_nothing(tmp_path, monkeypatch):
    """Additive / no-regression: a plain `vigil engage --brain hexstrike` with NO run dir configured writes
    nothing (byte-identical to before this change)."""
    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    _drive_brain()  # no proposal_out, no env
    # nothing was created anywhere we handed it — the producer had no sink
    assert not list(tmp_path.glob("**/brain-proposal.json"))


# ---------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL 1 — a run with no proposal never bleeds a stale proposal from another run
# ---------------------------------------------------------------------------------------------------
def test_run_with_no_proposal_shows_empty_not_a_stale_file(console_root):
    from framework.v2.console import api

    _drive_brain(proposal_out=_run_dir(console_root, "A"))   # A HAS a proposal
    _run_dir(console_root, "B")                               # B has none

    # scoped to B: empty state, NOT A's proposal (the gate is not a no-op)
    dB = api.brain_decision(run_id="B")
    assert dB["proposal"]["present"] is False
    assert "note" in dB["proposal"]

    # sanity: scoped to A it IS present (proves B's False is real scoping, not a broken reader)
    assert api.brain_decision(run_id="A")["proposal"]["present"] is True


# ---------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL 2 — a deliberately bad persisted state is rejected, never fabricated
# ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    "{ not valid json ",                                   # torn/invalid JSON
    json.dumps({"target": "x", "steps": "not-a-list"}),    # wrong-typed steps
    json.dumps({"target": "x"}),                            # steps absent
    json.dumps([1, 2, 3]),                                  # not even an object
])
def test_bad_persisted_proposal_is_rejected_not_fabricated(console_root, bad):
    from framework.v2.console import api

    rd = _run_dir(console_root, "BAD")
    (rd / "brain-proposal.json").write_text(bad, encoding="utf-8")
    prop = api.brain_decision(run_id="BAD")["proposal"]
    assert prop["present"] is False, "a malformed proposal must render empty, never a fabricated chain"


def test_bad_run_id_fails_closed_to_empty(console_root):
    from framework.v2.console import api
    # a traversal-shaped id: run_dir raises → _safe → honest empty state, never a 500 or a read outside runs/
    assert api.brain_decision(run_id="../etc")["proposal"]["present"] is False


# ---------------------------------------------------------------------------------------------------
# STRUCTURAL — the panel no longer reads a file nothing writes; the route is ?run=-scoped
# ---------------------------------------------------------------------------------------------------
def test_reader_basename_equals_producer_basename():
    """The one basename the API reads must be the one a real producer writes. This is the structural tie
    that keeps the panel from ever reading a file nothing writes again."""
    api_src = _API.read_text(encoding="utf-8")
    producer_src = _PRODUCER.read_text(encoding="utf-8")
    assert "brain-proposal.json" in api_src, "reader no longer references the artifact"
    # the producer must actually WRITE it (a docstring mention is not a producer): the write lands via the
    # atomic tmp→final replace onto the exact final name.
    assert 'tmp.replace(d / "brain-proposal.json")' in producer_src, \
        "no producer writes the artifact the panel reads"


def test_route_is_run_scoped_not_a_zero_arg_exact_route():
    """A zero-arg exact route would ignore ?run= and drop back to 'any run' — reintroducing the stale-bleed
    the negative control forbids. Mirror test_run_scope's guard for /api/runs."""
    from framework.v2.console import server
    assert "/api/brain/decision" not in server._EXACT_ROUTES


def test_doc_claim_names_the_real_producer_and_artifact():
    """Doc-truth: the plain-english screen inventory claims the panel's proposal is written by a real
    producer. Derive that claim from the code so the doc can't drift into overclaim — the producer module
    and the artifact name it asserts must both be real (the module exists and writes that exact file)."""
    doc = _DOC.read_text(encoding="utf-8")
    # the doc names the producer module and the artifact; both must be true of the code.
    assert "brains/engine_think.py" in doc and "BrainThink" in doc, "doc no longer names the real producer"
    assert "brain-proposal.json" in doc, "doc no longer names the artifact"
    assert _PRODUCER.is_file(), "the producer module the doc names does not exist"
    assert 'tmp.replace(d / "brain-proposal.json")' in _PRODUCER.read_text(encoding="utf-8"), \
        "the doc claims BrainThink writes brain-proposal.json, but the code no longer does"
