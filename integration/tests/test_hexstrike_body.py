"""BRAIN-SLOT slice 2 — HexstrikeAgentBody, FULLY wired.

Contract (injected fakes): gate-before-execute (a DENY/QUEUE never executes), no self-authorization, the
body never supplies provenance/oracle_context (red-pen HIGH-3), an oracle-unmapped tool stays a LEAD,
learn() only records. WARDEN A2 floor: on a LIVE target nothing auto-fires; a RECON tool autos only in
staging/twin (red-pen MEDIUM). LIVE: the body's real execute path mints a signed service_reachability FACT
through the R4 runner against a loopback listener — no mocks.
"""
from __future__ import annotations

import http.server
import json
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from framework.v2.agent_body.interface import ActionOutcome, GateDecision, Observation, ProposedAction
from vigil_core import generate_keypair
from vigil_core.models import AuthorizerKey, TrustRoot
from vigil_gateway.scope_source import StaticScopeSource
from vigil_integration.brains.hexstrike_body import HexstrikeAgentBody, RunnerDeps
from vigil_integration.live.capability_token import (
    CapabilityAuthority,
    CapabilityGrant,
    mint_capability_token,
    operation_hash,
    policy_digest,
)
from vigil_integration.live.external_tool import (
    CapabilityCheck,
    LocalSubprocessBackend,
    ScopeGate,
    masscan_service_scan,
    nmap_service_scan,
    unicornscan_service_scan,
    zmap_service_scan,
)
from vigil_integration.live.nonce_ledger import NonceLedger

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=SIGNER.public_key_b64)])

# H8f GATE PARITY — the single-use capability token a PROVISIONED runner must now carry (a runner-less
# planning body needs none). The token is bound to the EXACT argv the body builds (operation_hash), so a
# test mints it over the SAME spec the body will run.
_CAP_KP = generate_keypair()
_CAP_KEY_ID = "owner-root"
_CAP_AUTHORITY = CapabilityAuthority(owner_key_id=_CAP_KEY_ID, owner_public_key_b64=_CAP_KP.public_key_b64)
_CAP_DEPLOYMENT = "deploy-test-1"
_CAP_DANGER = "recon"
_CAP_POLICY_DIGEST = policy_digest({"warden": "A2", "charter": "alpha"})


def _capability_for(spec, target, ledger, *, nonce="cap-1", now=1100.0, op_argv=None):
    """Mint a single-use CapabilityCheck bound to the exact argv the body runs. ``op_argv`` overrides the
    argv used for the operation_hash — used to forge a DIFFERENT-operation token (the tamper control)."""
    argv = op_argv if op_argv is not None else list(spec.build_argv(target))
    grant = CapabilityGrant(
        deployment=_CAP_DEPLOYMENT, engagement="alpha",
        operation_hash=operation_hash(spec.name, target, argv),
        target=target, tool=spec.name, danger_class=_CAP_DANGER, policy_digest=_CAP_POLICY_DIGEST,
    )
    token = mint_capability_token(grant, owner_private_key_b64=_CAP_KP.private_key_b64, key_id=_CAP_KEY_ID,
                                  nonce=nonce, not_before=1000.0, expiry=1300.0)
    return CapabilityCheck(token=token, authority=_CAP_AUTHORITY, ledger=ledger, deployment=_CAP_DEPLOYMENT,
                           danger_class=_CAP_DANGER, policy_digest=_CAP_POLICY_DIGEST, now=lambda: now)


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
    ledger = NonceLedger(tmp_path / "nonces")
    cap = _capability_for(nmap_service_scan(ports=str(port)), "127.0.0.1", ledger)
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=LocalSubprocessBackend(), engagement_slug="alpha", signers=SIGNERS, capability=cap)
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
    assert ledger.is_consumed("cap-1"), "the body must burn the single-use capability nonce (H8f gate parity)"


class _SpyBackend:
    """Records every tool launch so 'refused BEFORE traffic' is proven by the tool never being invoked."""
    name = "spy"
    loopback_only = False

    def __init__(self) -> None:
        self.launches: list = []

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        from vigil_integration.live.external_tool import ToolOutcome
        self.launches.append(list(argv))
        return ToolOutcome(list(argv), 0, "", "", self.name)


# ===================================================================================================
# H8f GATE PARITY (closes the H1x-1 red-pen prerequisite): a PROVISIONED runner is a live egress path, so
# the body must re-enforce the executor's single-use, action-bound capability token BEFORE any traffic. A
# runner without a token is refused pre-traffic; a replayed or different-operation token is refused at the
# executor boundary and the tool never launches. (Scope/loopback/pre-flight/isolation parity is already
# proven by test_executor_capability_boundary + test_external_tool_runner — run_external_tool applies those
# unconditionally; this file pins the token leg the body now threads.)
# ===================================================================================================
def test_h8f_provisioned_runner_without_a_capability_refuses_before_traffic(tmp_path: Path):
    """A runner with NO capability token would emit a packet on an unspent authorization — the body refuses
    it before the runner is even entered, so the backend is never launched."""
    _charter(tmp_path, "127.0.0.1")
    spy = _SpyBackend()
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=spy, engagement_slug="alpha", signers=SIGNERS, capability=None)
    body = HexstrikeAgentBody(posture="staging", runner=deps)
    out = body.execute(ProposedAction(kind="nmap", target="127.0.0.1", params={"ports": "80", "danger": "recon"}),
                       GateDecision(authorized=True))
    assert out.executed is False and "without a single-use capability token" in out.blocked_reason, out
    assert spy.launches == [], "no tool may launch when the runner carries no capability token"


def test_h8f_a_replayed_capability_token_is_refused_and_no_second_run(tmp_path: Path):
    """The FIRST run burns the single-use nonce; replaying the SAME token for the SAME action is refused at
    the executor boundary (the masscan tool is launched exactly once)."""
    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    ledger = NonceLedger(tmp_path / "nonces")
    cap = _capability_for(masscan_service_scan(ports=str(port), rate=1000), "127.0.0.1", ledger)
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=_CannedBackend(f"Discovered open port {port}/tcp on 127.0.0.1\n"),
                      engagement_slug="alpha", signers=SIGNERS, capability=cap)
    body = HexstrikeAgentBody(posture="staging", runner=deps)
    action = ProposedAction(kind="masscan", target="127.0.0.1", params={"ports": str(port), "danger": "recon"})
    try:
        first = body.execute(action, GateDecision(authorized=True))
        second = body.execute(action, GateDecision(authorized=True))
    finally:
        srv.close()
    assert first.executed is True and first.detail.get("n_facts") == 1, first
    # pin the CAPABILITY-specific refusal (the spent nonce), not just the generic runner-refused wrapper, so a
    # future regression that refused the replay for an unrelated reason cannot slip through.
    assert second.executed is False, second
    assert "already consumed" in second.blocked_reason, second


def test_h8f_a_capability_for_a_different_operation_is_refused(tmp_path: Path):
    """A token minted for a DIFFERENT argv (different ports) does not authorize THIS operation — the boundary
    recomputes the operation_hash over the real argv and refuses, so the tool never launches."""
    _charter(tmp_path, "127.0.0.1")
    spy = _SpyBackend()
    ledger = NonceLedger(tmp_path / "nonces")
    # token bound to ports=443, but the body will run ports=80 → operation_hash mismatch at the boundary.
    other = masscan_service_scan(ports="443", rate=1000)
    cap = _capability_for(masscan_service_scan(ports="80", rate=1000), "127.0.0.1", ledger,
                          op_argv=list(other.build_argv("127.0.0.1")))
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=spy, engagement_slug="alpha", signers=SIGNERS, capability=cap)
    body = HexstrikeAgentBody(posture="staging", runner=deps)
    out = body.execute(ProposedAction(kind="masscan", target="127.0.0.1", params={"ports": "80", "danger": "recon"}),
                       GateDecision(authorized=True))
    # pin the operation-hash mismatch specifically — the boundary recomputes the hash over the REAL argv.
    assert out.executed is False, out
    assert "does not match this operation" in out.blocked_reason, out
    assert spy.launches == [], "a token for a different operation must not launch the tool"


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
    """masscan/rustscan/naabu and the W1 batch-2 zmap/unicornscan are oracle-mapped: with NO runner
    provisioned they reach the runner dispatch (a DIFFERENT LEAD reason than an unmapped tool), proving the
    body routes each to its reachability ToolSpec rather than rejecting it as unmapped."""
    from vigil_integration.brains.hexstrike_body import _ORACLE_MAPPED_TOOLS

    for tool in ("masscan", "rustscan", "naabu", "zmap", "unicornscan"):
        assert tool in _ORACLE_MAPPED_TOOLS
        params = {"port": 80} if tool == "zmap" else {"ports": "80"}
        body = HexstrikeAgentBody(runner=None)
        out = body.execute(ProposedAction(kind=tool, target="127.0.0.1", params=params),
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
    ledger = NonceLedger(tmp_path / "nonces")
    cap = _capability_for(masscan_service_scan(ports=str(port), rate=1000), "127.0.0.1", ledger)
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=_CannedBackend(f"Discovered open port {port}/tcp on 127.0.0.1\n"),
                      engagement_slug="alpha", signers=SIGNERS, capability=cap)
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
    assert ledger.is_consumed("cap-1"), "the body must burn the single-use capability nonce (H8f gate parity)"


@pytest.mark.parametrize("tool", ["zmap", "unicornscan"])
def test_h5_batch2_live_fact_through_the_body(tool: str, tmp_path: Path):
    """W1 batch-2 end-to-end through the BODY: a canned zmap/unicornscan proposal of a REAL open loopback
    port, dispatched by the body via _spec_for_kind to <tool>_service_scan(fact_capable=True), is re-proven
    by the runner's OWN gated handshake and minted as 1 SERVICE_REACHABILITY FACT — the SAME
    service_reachability.tcp_handshake branch nmap/masscan use (no new oracle, no new branch). Hermetic (no
    tool binary needed — the FACT is VIGIL's connect()-based handshake; the tool is only the proposer)."""
    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    if tool == "zmap":
        spec = zmap_service_scan(port=port, fact_capable=True)
        stdout = "127.0.0.1\n"                                    # a responding IP line for the scanned port
    else:
        spec = unicornscan_service_scan(ports=str(port), fact_capable=True)
        stdout = f"TCP open  svc[ {port}]  from 127.0.0.1  ttl 64\n"
    ledger = NonceLedger(tmp_path / "nonces")
    cap = _capability_for(spec, "127.0.0.1", ledger)
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=_CannedBackend(stdout),
                      engagement_slug="alpha", signers=SIGNERS, capability=cap)
    body = HexstrikeAgentBody(posture="staging", runner=deps)
    params = {"port": port, "danger": "recon"} if tool == "zmap" else {"ports": str(port), "danger": "recon"}
    try:
        action = ProposedAction(kind=tool, target="127.0.0.1", params=params)
        decision = body.gate(action)
        assert decision.authorized is True                       # recon + staging => auto-eligible
        outcome = body.execute(action, decision)
    finally:
        srv.close()
    assert outcome.executed is True and outcome.ok is True, outcome
    assert outcome.detail.get("n_facts") == 1, f"expected 1 reachability FACT via {tool}, got {outcome.detail}"
    assert ledger.is_consumed("cap-1"), "the body must burn the single-use capability nonce (H8f gate parity)"


# ===================================================================================================
# W2 — ``ok`` is TRUTHFUL PER TOOL CLASS (red-pen advisory D)
# ===================================================================================================
class _LiveItemApp(http.server.BaseHTTPRequestHandler):
    """/item/ZQabcdefgh has real content; every same-shape sibling gets the route's own stable 200
    not-found body. The differential is REAL, so the deterministic oracle fires — and admission still
    demotes it, because the branch is LEAD-only. Exactly the shape of a successful enrichment."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        body = (b'{"item":"ZQabcdefgh","owner":"acme","qty":7}'
                if self.path.split("?")[0] == "/item/ZQabcdefgh" else b'{"item":null}')
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_a_successful_lead_enricher_run_reports_ok_true_without_implying_a_fact(tmp_path: Path):
    """``ok=bool(facts)`` is the right success predicate for an ORACLE-MAPPED tool and a CATEGORY ERROR
    for a LEAD ENRICHER. httpx/ffuf re-drive on ``achieved_state.endpoint_liveness``, which is
    fact_capable=false PERMANENTLY, so a FULLY SUCCESSFUL run (tool ran, gated GETs completed, both
    sibling cohorts probed, capture retained, LEAD emitted) minted zero facts and used to come back
    ``executed=True, ok=False`` — a consumer keying on ``ok`` (the run report, ``learn``, a retry loop)
    read a healthy enrichment as a failure.

    Pin the fixed semantics AND the honesty bound: ok is True, ``ok_semantics`` says WHY (so nobody has to
    infer it), ``n_facts`` is 0 and ``facts`` is empty — the truthful ok never implies a FACT."""
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.external_tool import httpx_url_scan

    srv = http.server.HTTPServer(("127.0.0.1", 0), _LiveItemApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/item/ZQabcdefgh"
    ledger = NonceLedger(tmp_path / "nonces")
    cap = _capability_for(httpx_url_scan(scheme="http"), "127.0.0.1", ledger)
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=_CannedBackend(
                          json.dumps({"url": url, "input": url, "status_code": 200, "failed": False}) + "\n"),
                      engagement_slug="alpha", signers=SIGNERS, capability=cap, timeout=30.0)
    body = HexstrikeAgentBody(posture="staging", runner=deps)
    try:
        action = ProposedAction(kind="httpx", target="127.0.0.1", params={"danger": "recon"})
        decision = body.gate(action)
        assert decision.authorized is True                       # recon + staging => auto-eligible
        outcome = body.execute(action, decision)
    finally:
        srv.shutdown()
    assert outcome.executed is True, outcome
    assert outcome.ok is True, (
        f"a successful LEAD-ENRICHER run reported ok=False — a consumer keying on ok reads this healthy "
        f"enrichment as a failure: {outcome.detail}")
    assert outcome.detail.get("ok_semantics") == "lead_enricher", outcome.detail
    assert outcome.detail.get("tool_errored") is False, outcome.detail
    # ...and ok=True still implies NOTHING about a FACT. This branch mints none, and must not look like it.
    assert outcome.detail.get("n_facts") == 0 and not outcome.detail.get("facts"), outcome.detail
    assert outcome.detail.get("n_leads", 0) >= 1, f"the enrichment produced no LEAD at all: {outcome.detail}"
    assert "demoted to a lead" in (outcome.detail["leads"][0].note or "").lower(), outcome.detail["leads"]
    assert ledger.is_consumed("cap-1"), "the body must burn the single-use capability nonce (H8f gate parity)"


def test_the_fact_based_ok_semantics_are_unchanged_for_oracle_mapped_tools(tmp_path: Path):
    """The other half of advisory D: the lead-enricher fix must NOT loosen ``ok`` for a tool that CAN
    mint. For an oracle-mapped tool ``ok`` still means "the runner minted a FACT" — a canned proposal of a
    CLOSED port re-driven by VIGIL's own handshake finds nothing, so ok stays False even though the tool
    itself ran perfectly. That asymmetry is the point: only the branch that can never mint gets the
    execution-based predicate."""
    _charter(tmp_path, "127.0.0.1")
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()                                                   # nothing is listening on this port now
    ledger = NonceLedger(tmp_path / "nonces")
    spec = masscan_service_scan(ports=str(closed_port), rate=1000)
    cap = _capability_for(spec, "127.0.0.1", ledger)
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=_CannedBackend(f"Discovered open port {closed_port}/tcp on 127.0.0.1\n"),
                      engagement_slug="alpha", signers=SIGNERS, capability=cap)
    body = HexstrikeAgentBody(posture="staging", runner=deps)
    action = ProposedAction(kind="masscan", target="127.0.0.1",
                            params={"ports": str(closed_port), "danger": "recon"})
    outcome = body.execute(action, body.gate(action))
    assert outcome.executed is True, outcome
    assert outcome.detail.get("ok_semantics") == "fact", outcome.detail
    assert outcome.detail.get("n_facts") == 0, outcome.detail
    assert outcome.ok is False, f"an oracle-mapped tool that minted nothing must stay ok=False: {outcome.detail}"


# ===================================================================================================
# H7 — the body integrates BY SHARED ORACLE FAMILY: the FACT-capable set is DERIVED from the family
# registry (not a flat hand-kept list), and the chain's tools fuse by family into raised-priority LEADs
# that can NEVER become a FACT.
# ===================================================================================================
def test_h7_oracle_mapped_set_is_derived_from_the_family_registry():
    """_ORACLE_MAPPED_TOOLS is no longer a literal: it is oracle_mapped_tools(_SPEC_BUILDER_TOOLS), so
    FACT-capability is a property of a tool's family (FACT-capable) AND its having a runner spec builder.
    The derived set is exactly the seven shipped re-drive tools, and each is in a FACT-capable family."""
    from vigil_integration.brains.hexstrike_body import _ORACLE_MAPPED_TOOLS, _SPEC_BUILDER_TOOLS
    from vigil_integration.live.oracle_families import is_fact_capable_family, oracle_mapped_tools

    # httpx/ffuf are NOT here: they have R4 ToolSpec builders and still run the gated web re-drive, but
    # as LEAD ENRICHERS (hexstrike_body._LEAD_ENRICHER_TOOLS) — their branch is LEAD-only, so they are
    # absent from SPEC_BUILDER_TOOLS and therefore cannot be oracle-mapped. A builder is not a mint.
    assert _ORACLE_MAPPED_TOOLS == oracle_mapped_tools(_SPEC_BUILDER_TOOLS)
    assert _ORACLE_MAPPED_TOOLS == {"nmap", "sslscan", "masscan", "rustscan", "naabu", "zmap", "unicornscan"}
    for tool in _ORACLE_MAPPED_TOOLS:
        assert is_fact_capable_family(tool), f"{tool}: mapped but its family is not FACT-capable"


def test_h7_family_votes_raise_priority_but_never_mint():
    """The body's family_votes() fuses the proposed chain BY FAMILY. Where several tools of one family are
    proposed (three web-discovery tools here), agreement raises the family LEAD's priority — but every vote
    is a LEAD, is_fact False, no matter the agreement count. Routing/voting never mints."""
    body = HexstrikeAgentBody()
    body.plan(_obs())
    votes = body.family_votes()
    assert votes, "the web chain has several families to vote"
    assert all(v.verdict == "LEAD" and v.is_fact is False for v in votes), \
        "a family vote must ALWAYS be a LEAD — agreement is not evidence"
    web = [v for v in votes if v.family == "web_discovery"]
    assert web and web[0].agreement >= 2, "httpx/katana/gobuster should agree in the web-discovery family"
    assert web[0].verifier == "ACHIEVED_STATE"
    # a lone-member family (tls: sslscan) gets no raise beyond its base
    tls = [v for v in votes if v.family == "tls"]
    assert tls and tls[0].agreement == 1


def test_h7_the_only_fact_path_is_the_runner_redrive_not_the_family_route():
    """An oracle-mapped tool with NO runner provisioned reaches the runner dispatch and stays a LEAD; the
    family route/vote never substitutes a FACT for it. Minting is the runner-owned re-drive's job alone."""
    from vigil_integration.live.oracle_families import route

    r = route("nmap", env={})            # DEFAULT-OFF flag → routing emits a LEAD, no mint
    assert r.verdict == "LEAD" and r.mint_via_redrive is False and r.fact_capable_family is True
    out = HexstrikeAgentBody(runner=None).execute(
        ProposedAction(kind="nmap", target="127.0.0.1", params={"ports": "80"}),
        GateDecision(authorized=True))
    assert out.executed is False and "runner not provisioned" in out.blocked_reason
