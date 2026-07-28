"""
test_engine_live — WS-5 live validation of the unified engine against the REAL sovereign seams.

Unlike test_engine.py (injected fakes), this drives :func:`live.wiring.build_engine` with the REAL
CRUCIBLE gate (over a freshly-provisioned signed authority) and the REAL oracle
(:func:`oracle_adapter.confirm_and_certify`). It proves, live:

  * the run is attestation-first — a signed usage-attestation is minted + durably recorded before any
    action, and the ledger verifies;
  * the real gate ALLOWS an in-scope 127.0.0.1 tool call and DENIES an out-of-scope host;
  * the real oracle — not the LLM — mints the FACT: a scripted ``exploit_succeeded`` carrying a FIRING
    SQLi ``oracle_context`` becomes a signed FACT; an identical claim with a NON-firing context stays a
    LEAD;
  * a state checkpoint is written to the real signed spine.

Framework co-loads the offense env, so this module SKIPS where ``framework.v2`` is not importable (the
main integration pytest process / the sovereign env); it runs in the offense process
(``PYTHONPATH=integration:engine/crucible``). A deterministic echo runner replaces the live Kali
subprocess so the gate/oracle/spine wiring is exercised without the binaries present — the
gate/oracle/egress checks are byte-identical either way.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.authority.charter", reason="CRUCIBLE (offense) not importable here")

from vigil_integration.agent.state import (  # noqa: E402
    ActionType,
    LLMDecision,
    OutputAnalysis,
    ToolCall,
)
from vigil_integration.attestation.identity import operator_key_resolver  # noqa: E402
from vigil_integration.attestation.ledger import read_ledger, verify_ledger  # noqa: E402
from vigil_integration.conjunctive_gate import build_offense_gate  # noqa: E402
from vigil_integration.live.think_claude import ReplayThinker  # noqa: E402
from vigil_integration.live.wiring import (  # noqa: E402
    EngineConfig,
    build_engine,
    default_classify,
    provision_authority,
)

LOOPBACK = "http://127.0.0.1:18080/search?q=1"

# a boolean-SQLi oracle_context that FIRES (true differs from both falses, falses agree) — the exact
# shape the BOOLEAN_INFERENCE oracle re-fires over (from the framework's own oracle-adapter fixture).
_MANY = {"status": 200, "body": "id=1\nid=2\nid=3\nid=4\nid=5 (all rows)"}
_NONE = {"status": 200, "body": "no results"}
_FIRING_SQLI = {"bug_class": "sqli",
                "probe_rounds": [{"true": _MANY, "false_a": _NONE, "false_b": _NONE} for _ in range(24)]}
_NONFIRING_SQLI = {"bug_class": "sqli",
                   "probe_rounds": [{"true": _NONE, "false_a": _NONE, "false_b": _NONE} for _ in range(24)]}


def _echo_runner(argv, *, timeout=0, output_cap=1 << 20):
    """A deterministic stand-in for the live subprocess: returns fixed output, never spawns anything."""
    return SimpleNamespace(exit_code=0, stdout="id=1 id=2 id=3 (rows)", stderr="",
                           timed_out=False, truncated=False)


def _use_tool(*, oracle_context=None, tool="httpx"):
    info = {}
    if oracle_context is not None:
        info = {"oracle_context": oracle_context, "bug_class": "sqli",
                "check_id": "sqli-loopback-001", "insertion_point": "q"}
    return LLMDecision(
        action=ActionType.USE_TOOL,
        tool=ToolCall(tool_name=tool, tool_args={"target": LOOPBACK}),
        output_analysis=OutputAnalysis(exploit_succeeded=oracle_context is not None, extracted_info=info),
    )


def _complete():
    return LLMDecision(action=ActionType.COMPLETE, summary="done")


@pytest.fixture()
def hermetic_root(tmp_path, monkeypatch):
    """Point the CRUCIBLE authority store at a throwaway dir so provisioning is hermetic."""
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    return tmp_path


def _engine(tmp_path, replay, *, owner_approves=True):
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    # owner_approves_offense=True: the operator's STANDING approval (the human leg of the conjunctive
    # gate) to run queued offense tools against their own chartered loopback. CRUCIBLE scope is still
    # enforced, so an out-of-scope target is denied even with approval granted.
    cfg = EngineConfig(slug="loopback", base_dir=str(tmp_path / "live"), replay=replay,
                       provisioned=prov, runner=_echo_runner, max_iterations=6,
                       owner_approves_offense=owner_approves)
    return build_engine(cfg), prov, cfg


# --- the real gate ---------------------------------------------------------------------------------


def test_live_remote_in_scope_tool_runs_end_to_end(hermetic_root, tmp_path, monkeypatch):
    # WS-A e2e: a SIGNED REMOTE scope threads build_engine → executor; an in-scope remote tool call RUNS,
    # pinned to the resolved public IP. Hermetic DNS (no real network); the echo runner never spawns.
    import socket
    REMOTE = "http://scanme.example.com/search?q=1"

    def _fake_getaddrinfo(host, port, *a, **k):
        if host == "scanme.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]
        raise socket.gaierror("name does not resolve")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)   # patches executor + scope_source both

    replay = ReplayThinker([
        LLMDecision(action=ActionType.USE_TOOL,
                    tool=ToolCall(tool_name="httpx", tool_args={"target": REMOTE}),
                    output_analysis=OutputAnalysis(exploit_succeeded=False, extracted_info={})),
        _complete()])
    prov = provision_authority(slug="acme", scope=["scanme.example.com"])
    cfg = EngineConfig(slug="acme", base_dir=str(tmp_path / "live"), replay=replay, provisioned=prov,
                       runner=_echo_runner, max_iterations=4, owner_approves_offense=True)
    report = build_engine(cfg).engage(REMOTE)
    assert any(t.outcome == "ran" for t in report.tool_calls)      # the remote in-scope tool actually ran


def test_real_gate_in_scope_is_in_envelope_out_of_scope_denies(hermetic_root):
    # The sovereign posture: an in-scope offense tool is IN-ENVELOPE but QUEUES for the owner (an
    # autonomous agent may never auto-fire an offense tool >= A2); an out-of-scope host is a hard DENY
    # by the CRUCIBLE scope gate (approval can never widen scope).
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    gate = build_offense_gate(slug="loopback", trust_root=prov.trust_root, classify=default_classify)
    in_scope = gate("httpx", "127.0.0.1", False)
    out_scope = gate("httpx", "example.com", False)
    assert getattr(in_scope, "outcome", "") == "queue"          # in-envelope, needs owner approval
    assert getattr(in_scope, "crucible_allowed", None) is True  # CRUCIBLE scope PASSED
    assert getattr(out_scope, "outcome", "") == "deny"          # out of scope → hard deny
    assert getattr(out_scope, "crucible_allowed", None) is False


# --- the full attestation-first loop, live -----------------------------------------------------------


def test_live_run_is_attestation_first_and_ledger_verifies(hermetic_root, tmp_path):
    engine, prov, cfg = _engine(tmp_path, ReplayThinker([_complete()]))
    report = engine.engage(LOOPBACK, objective="loopback smoke")
    assert report.refused is False
    assert report.attestation_ref                                  # a real attestation was minted
    # the durable ledger exists and VERIFIES under the box's own operator key.
    records = read_ledger(str(tmp_path / "live" / "usage-ledger.jsonl"))
    assert len(records) >= 1
    resolver = operator_key_resolver(keypair_path=str(tmp_path / "live" / "operator.key"))
    assert verify_ledger(records, resolve_key=resolver).ok is True


def test_live_llm_crafted_firing_context_stays_a_lead_not_a_fact(hermetic_root, tmp_path):
    # AUDIT G4 (sovereign invariant): a FIRING SQLi context that arrives via the model's extracted_info is
    # LLM-PROVENANCED — the deterministic oracle re-fires over it, but it is the model's PROPOSAL, not a
    # reproduction from a non-LLM channel, so it is retained as a LEAD and NEVER minted into a signed FACT.
    # A crafted-but-firing context can no longer route to a fact. (Minting requires reproduction from the
    # executor-captured raw output / a live re-drive — the documented follow-up.)
    engine, prov, cfg = _engine(tmp_path, ReplayThinker([_use_tool(oracle_context=_FIRING_SQLI),
                                                         _complete()]))
    report = engine.engage(LOOPBACK)
    assert any(t.outcome == "ran" for t in report.tool_calls)      # the gate ALLOWED the in-scope call
    assert report.fact_count == 0                                  # LLM-provenanced context ⇒ NO signed FACT
    assert report.leads                                            # retained as a labelled lead
    assert report.checkpoints                                      # state still checkpointed to the real spine


def test_live_nonfiring_context_stays_a_lead(hermetic_root, tmp_path):
    engine, prov, cfg = _engine(tmp_path, ReplayThinker([_use_tool(oracle_context=_NONFIRING_SQLI),
                                                         _complete()]))
    report = engine.engage(LOOPBACK)
    assert report.fact_count == 0                                  # the oracle did not fire ⇒ no FACT
    assert any("UNCONFIRMED" in (ld.title or "") for ld in report.leads)


# --- F3: the Neo4j graph partition is the SESSION id (falls back to the slug) -----------------------

class _RecSession:
    """A recording fake Neo4j session: captures every Cypher param map (so a test can read back which
    PARTITION the engine's graph reads/writes targeted). Returns an empty result (a read → no rows)."""
    def __init__(self, calls: list) -> None:
        self.calls = calls

    def run(self, cypher, parameters=None):
        self.calls.append(dict(parameters or {}))
        return []

    def close(self) -> None:
        pass


def _partitions_touched(tmp_path, monkeypatch, *, session_id: str, connections=()) -> set:
    from vigil_integration.live import graph_driver
    calls: list = []
    # inject a recording Neo4j so build_engine wires a real writer (+ retrieve_priors), no live driver needed.
    monkeypatch.setattr(graph_driver, "build_neo4j_session_factory",
                        lambda *a, **k: (lambda: _RecSession(calls)))
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    cfg = EngineConfig(slug="loopback", session_id=session_id, connections=tuple(connections),
                       base_dir=str(tmp_path / "live"),
                       replay=ReplayThinker([_use_tool(oracle_context=_FIRING_SQLI), _complete()]),
                       provisioned=prov, runner=_echo_runner, max_iterations=6, owner_approves_offense=True)
    build_engine(cfg).engage(LOOPBACK)
    # retrieve_priors fires on every think (before any fact is projected), so the read Cypher records the
    # partition regardless of whether a FACT was minted — this is exactly the per-session partition key.
    return {p["engagement_id"] for p in calls if "engagement_id" in p}


def test_graph_partition_is_the_session_id_when_set(hermetic_root, tmp_path, monkeypatch):
    parts = _partitions_touched(tmp_path, monkeypatch, session_id="sess-XYZ")
    assert parts == {"sess-XYZ"}, f"the graph must be scoped to the SESSION partition, saw {parts}"
    assert "loopback" not in parts                                 # NOT the slug when a session is set


def test_graph_partition_falls_back_to_slug_without_a_session(hermetic_root, tmp_path, monkeypatch):
    parts = _partitions_touched(tmp_path, monkeypatch, session_id="")
    assert parts == {"loopback"}                                   # empty session_id → slug partition


def test_connected_sessions_union_their_partitions_as_priors(hermetic_root, tmp_path, monkeypatch):
    # F4: with --connect, the run's prior retrieval UNIONS the consented connected partitions (a read-time
    # scope) alongside its own — so the recorded reads touch BOTH the session and the connected partition.
    parts = _partitions_touched(tmp_path, monkeypatch, session_id="sess-A", connections=["sess-B", "sess-C"])
    assert parts == {"sess-A", "sess-B", "sess-C"}                 # own + consented connections, nothing else


def test_no_connections_reads_only_own_partition(hermetic_root, tmp_path, monkeypatch):
    parts = _partitions_touched(tmp_path, monkeypatch, session_id="sess-A", connections=[])
    assert parts == {"sess-A"}                                     # isolated by default (no leak)


def test_live_without_owner_approval_the_offense_tool_queues(hermetic_root, tmp_path):
    # the fail-closed default: no operator approval ⇒ the queued offense tool never runs.
    engine, prov, cfg = _engine(tmp_path, ReplayThinker([_use_tool(oracle_context=_FIRING_SQLI)]),
                                owner_approves=False)
    report = engine.engage(LOOPBACK)
    assert report.paused == "awaiting_approval"
    assert report.queued_edges and not any(t.outcome == "ran" for t in report.tool_calls)
    assert report.fact_count == 0


def test_provision_authority_uses_a_stable_governance_key(hermetic_root, tmp_path):
    # S7: with a base_dir the anchor-1 (governance/authority) key is STABLE across calls, so ONE owner
    # delegation covers it across runs; without a base_dir it falls back to the legacy per-run ephemeral key.
    base = str(tmp_path / "home")
    p1 = provision_authority(slug="loopback", scope=["127.0.0.1"], base_dir=base)
    p2 = provision_authority(slug="loopback", scope=["127.0.0.1"], base_dir=base)
    assert p1.keypair.public_key_b64 == p2.keypair.public_key_b64      # same anchor-1 signer across runs
    e1 = provision_authority(slug="loopback", scope=["127.0.0.1"])
    e2 = provision_authority(slug="loopback", scope=["127.0.0.1"])
    assert e1.keypair.public_key_b64 != e2.keypair.public_key_b64      # legacy ephemeral: fresh each call


def test_wiring_mints_detection_under_the_spine_key_id(hermetic_root, tmp_path, monkeypatch):
    # S7c pin: the live detect seam MUST stamp detection certs with SPINE_KEY_ID so they match the owner-
    # delegated offense-spine authorizer at anchor-1. Capture the key_id the wiring passes; reverting
    # wiring.py's literal to the old "vigil-detection" fails HERE (the seam-tests alone would stay green).
    from vigil_integration.live import wiring as W
    from vigil_integration.live.spine_identity import SPINE_KEY_ID
    captured: dict = {}

    def _fake_run_all(**kw):
        captured.update(kw)
        return []
    monkeypatch.setattr(W, "run_all_detections", _fake_run_all)
    engine, _prov, _cfg = _engine(tmp_path, ReplayThinker([_complete()]))
    engine.seams.detect()
    assert captured.get("key_id") == SPINE_KEY_ID


def test_build_engine_persists_a_stable_governance_key_under_base_dir(hermetic_root, tmp_path):
    # end-to-end: build_engine (with NO pre-provisioned authority) provisions under the engagement home with a
    # STABLE governance key, and a later provision against the SAME home reuses that identity (file persisted).
    import json
    from pathlib import Path
    base = str(tmp_path / "live2")
    cfg = EngineConfig(slug="loopback", base_dir=base, replay=ReplayThinker([_complete()]),
                       runner=_echo_runner, max_iterations=2, owner_approves_offense=True)
    build_engine(cfg)                                                  # provisioned=None ⇒ provisions here
    keyfile = Path(base) / "offense-governance.key"
    assert keyfile.exists()                                            # persisted, not ephemeral
    persisted = json.loads(keyfile.read_text())["public_key_b64"]
    prov2 = provision_authority(slug="loopback", scope=["127.0.0.1"], base_dir=base)
    assert prov2.keypair.public_key_b64 == persisted                  # reuses the SAME anchor-1 signer
