"""BRAIN-SLOT slice 2 — HexstrikeAgentBody, FULLY wired.

Contract (injected fakes): gate-before-execute (a DENY/QUEUE never executes), no self-authorization, the
body never supplies provenance/oracle_context (red-pen HIGH-3), an oracle-unmapped tool stays a LEAD,
learn() only records. WARDEN A2 floor: on a LIVE target nothing auto-fires; a RECON tool autos only in
staging/twin (red-pen MEDIUM). LIVE: the body's real execute path mints a signed service_reachability FACT
through the R4 runner against a loopback listener — no mocks.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from framework.v2.agent_body.interface import ActionOutcome, GateDecision, Observation, ProposedAction
from vigil_core import generate_keypair
from vigil_core.models import AuthorizerKey, TrustRoot
from vigil_gateway.scope_source import StaticScopeSource
from vigil_integration.brains.hexstrike_body import HexstrikeAgentBody, RunnerDeps
from vigil_integration.live.external_tool import LocalSubprocessBackend, ScopeGate

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=SIGNER.public_key_b64)])


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2 import entitlement
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-08-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n",
        encoding="utf-8")


def _obs():
    return Observation(state={"target": "http://127.0.0.1/", "target_type": "web_application",
                              "open_ports": [80, 443], "cms_type": "wordpress"})


# ---- contract (injected fakes) --------------------------------------------------------------------
def test_deny_gate_never_executes():
    calls = []
    body = HexstrikeAgentBody(gate_fn=lambda a: GateDecision(authorized=False, reason="denied"),
                              executor=lambda a, d: (calls.append(a) or ActionOutcome(executed=True, ok=True)))
    outcome = body.run_cycle(_obs())
    assert outcome.executed is False and "gate denied" in outcome.blocked_reason and calls == []
    assert body.history and body.history[-1]["executed"] is False


def test_allow_gate_reaches_executor_without_provenance():
    seen = {}
    def _exec(a, d):
        seen["params"] = dict(a.params)
        return ActionOutcome(executed=True, ok=True, detail={"lead": True})
    body = HexstrikeAgentBody(gate_fn=lambda a: GateDecision(authorized=True), executor=_exec)
    assert body.run_cycle(_obs()).executed is True
    assert not ({"provenance", "oracle_context", "authorized", "_authorized"} & set(seen["params"]))


def test_body_refuses_a_forbidden_key():
    body = HexstrikeAgentBody(gate_fn=lambda a: GateDecision(authorized=True),
                              executor=lambda a, d: ActionOutcome(executed=True, ok=True))
    out = body.execute(ProposedAction(kind="nmap", target="127.0.0.1", params={"provenance": "live_redrive"}),
                       GateDecision(authorized=True))
    assert out.executed is False and "forbidden key" in out.blocked_reason


def test_unmapped_tool_stays_a_lead():
    body = HexstrikeAgentBody(runner=None)  # default real executor, no runner
    out = body.execute(ProposedAction(kind="sqlmap", target="127.0.0.1", params={}), GateDecision(authorized=True))
    assert out.executed is False and "LEAD" in out.blocked_reason


def test_propose_returns_host_targeted_action_without_authority():
    body = HexstrikeAgentBody()
    action = body.propose(body.think(_obs()))
    assert isinstance(action, ProposedAction) and not hasattr(action, "authorized")
    assert action.target == "127.0.0.1"  # the scannable host, resolved from the URL/charter (no network)


def test_learn_only_records():
    body = HexstrikeAgentBody()
    body.learn(ActionOutcome(executed=False, ok=False, blocked_reason="x"))
    assert body.history[-1]["executed"] is False and body.history[-1]["blocked_reason"] == "x"


# ---- WARDEN A2 floor (red-pen MEDIUM) -------------------------------------------------------------
def test_a2_floor_live_queues_every_tool():
    body = HexstrikeAgentBody(posture="live")
    # nmap is RECON, but on a LIVE target even recon queues (nothing auto-fires)
    d = body.gate(ProposedAction(kind="nmap", target="127.0.0.1", params={"danger": "recon"}))
    assert d.authorized is False and "queued" in d.reason


def test_recon_autos_in_staging_active_still_queues():
    body = HexstrikeAgentBody(posture="staging")
    recon = body.gate(ProposedAction(kind="nmap", target="127.0.0.1", params={"danger": "recon"}))
    active = body.gate(ProposedAction(kind="sqlmap", target="127.0.0.1", params={"danger": "active"}))
    assert recon.authorized is True
    assert active.authorized is False and "queued" in active.reason  # active NEVER autos, even in staging


# ---- LIVE end-to-end: a real signed FACT through the body ------------------------------------------
@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed (present-tool path)")
def test_live_nmap_fact_through_the_body(tmp_path: Path):
    from framework.v2.evidence.certify import verify_certificate

    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=LocalSubprocessBackend(), engagement_slug="alpha", signers=SIGNERS)
    body = HexstrikeAgentBody(posture="staging", runner=deps)  # staging so the recon nmap step autos
    try:
        # execute the body's REAL R4 path for an nmap step scoped to the one open port
        action = ProposedAction(kind="nmap", target="127.0.0.1", params={"ports": str(port), "danger": "recon"})
        decision = body.gate(action)
        assert decision.authorized is True  # recon + staging => auto
        outcome = body.execute(action, decision)
    finally:
        srv.close()
    assert outcome.executed is True and outcome.ok is True, outcome
    assert outcome.detail.get("n_facts") == 1, f"expected 1 oracle-confirmed FACT, got {outcome.detail}"


def test_fatal2_body_imports_no_offense_engine():
    code = (
        "import sys; import vigil_integration.brains.hexstrike_body as m; "
        "bad=[k for k in sys.modules if any(h in k for h in "
        "('framework.v2.scanner','framework.v2.agents','framework.v2.intel','framework.v2.sensors',"
        "'framework.v2.veracity')) or k.split('.')[0] in {'flask','selenium','mitmproxy','angr'}]; "
        "assert not bad, bad; print('clean')"
    )
    repo = Path(__file__).resolve().parents[1].parent
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(repo),
                       env={"PYTHONPATH": "integration:engine/crucible", "PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stdout + r.stderr and "clean" in r.stdout
