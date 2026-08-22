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


def test_sslscan_is_oracle_mapped_and_dispatches_to_the_tls_runner():
    """Slice 4: sslscan is oracle-mapped (a second FACT-capable tool). With no runner provisioned it
    reaches the runner dispatch (a DIFFERENT LEAD reason than an unmapped tool), proving the body routes
    sslscan to the TLS ToolSpec rather than rejecting it as unmapped."""
    from vigil_integration.brains.hexstrike_body import _ORACLE_MAPPED_TOOLS

    assert "sslscan" in _ORACLE_MAPPED_TOOLS
    body = HexstrikeAgentBody(runner=None)
    unmapped = body.execute(ProposedAction(kind="whatweb", target="127.0.0.1", params={}),
                            GateDecision(authorized=True))
    mapped = body.execute(ProposedAction(kind="sslscan", target="127.0.0.1", params={"port": 443}),
                          GateDecision(authorized=True))
    assert "no oracle-mapped ToolSpec" in unmapped.blocked_reason      # unmapped -> rejected before dispatch
    assert "runner not provisioned" in mapped.blocked_reason           # mapped -> reached the runner dispatch


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


# ===================================================================================================
# H5 — masscan / rustscan / naabu are oracle-mapped SERVICE_REACHABILITY tools reachable on the REAL body
# path (the same runner path nmap uses). Each dispatches to its ToolSpec; the runner re-proves each port.
# ===================================================================================================
class _CannedBackend:
    """Returns a fixed stdout for ANY argv — supplies a tool's real-format proposal with no binary present."""
    name = "canned"

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def available(self):
        return True, "canned"

    def run(self, argv, *, timeout=0):
        from vigil_integration.live.external_tool import ToolOutcome
        return ToolOutcome(list(argv), 0, self._stdout, "", self.name)


def test_h5_reachability_tools_are_oracle_mapped_and_dispatch_to_the_runner():
    """masscan/rustscan/naabu are oracle-mapped: with NO runner provisioned they reach the runner dispatch
    (a DIFFERENT LEAD reason than an unmapped tool), proving the body routes each to its reachability
    ToolSpec rather than rejecting it as unmapped."""
    from vigil_integration.brains.hexstrike_body import _ORACLE_MAPPED_TOOLS

    for tool in ("masscan", "rustscan", "naabu"):
        assert tool in _ORACLE_MAPPED_TOOLS
        body = HexstrikeAgentBody(runner=None)
        out = body.execute(ProposedAction(kind=tool, target="127.0.0.1", params={"ports": "80"}),
                           GateDecision(authorized=True))
        assert "runner not provisioned" in out.blocked_reason, f"{tool} did not reach the runner dispatch: {out}"
    # an unmapped tool is still rejected BEFORE dispatch (control)
    unmapped = HexstrikeAgentBody(runner=None).execute(
        ProposedAction(kind="whatweb", target="127.0.0.1", params={}), GateDecision(authorized=True))
    assert "no oracle-mapped ToolSpec" in unmapped.blocked_reason


def test_oracle_mapped_tools_all_have_a_spec_builder_no_drift():
    """_ORACLE_MAPPED_TOOLS and _spec_for_kind stay in lock-step: every mapped tool builds a spec, and an
    unmapped name builds None (so a mapped-but-unbuildable tool cannot silently reach the runner)."""
    from vigil_integration.brains.hexstrike_body import _ORACLE_MAPPED_TOOLS, _spec_for_kind

    for tool in _ORACLE_MAPPED_TOOLS:
        params = {"port": 443} if tool == "sslscan" else {"ports": "80"}
        spec = _spec_for_kind(tool, params)
        assert spec is not None and spec.name in (tool, "tls_scan"), f"{tool}: no spec builder"
    assert _spec_for_kind("whatweb", {}) is None


def test_h5_invalid_ports_are_rejected_by_the_toolspec_schema_and_stay_a_lead(tmp_path: Path):
    """A server-side ports value that fails the ToolSpec's STRICT schema keeps the action a LEAD (fail-closed)
    — the body never runs an un-validated argv, and never crashes."""
    _charter(tmp_path, "127.0.0.1")
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=_CannedBackend(""), engagement_slug="alpha", signers=SIGNERS)
    body = HexstrikeAgentBody(posture="staging", runner=deps)
    out = body.execute(ProposedAction(kind="masscan", target="127.0.0.1",
                                      params={"ports": "$(id)", "danger": "recon"}),
                       GateDecision(authorized=True))
    assert out.executed is False and "rejected by the ToolSpec schema" in out.blocked_reason


def test_h5_live_masscan_fact_through_the_body(tmp_path: Path):
    """The reuse path end-to-end through the BODY: a canned masscan proposal of a REAL open loopback port,
    dispatched by the body to masscan_service_scan, re-proven by the runner's own gated handshake → 1 FACT.
    Hermetic (no masscan binary needed — the FACT is VIGIL's handshake, the tool is only the proposer)."""
    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=_CannedBackend(f"Discovered open port {port}/tcp on 127.0.0.1\n"),
                      engagement_slug="alpha", signers=SIGNERS)
    body = HexstrikeAgentBody(posture="staging", runner=deps)
    try:
        action = ProposedAction(kind="masscan", target="127.0.0.1",
                                params={"ports": str(port), "danger": "recon"})
        decision = body.gate(action)
        assert decision.authorized is True  # recon + staging => auto
        outcome = body.execute(action, decision)
    finally:
        srv.close()
    assert outcome.executed is True and outcome.ok is True, outcome
    assert outcome.detail.get("n_facts") == 1, f"expected 1 reachability FACT via masscan, got {outcome.detail}"
