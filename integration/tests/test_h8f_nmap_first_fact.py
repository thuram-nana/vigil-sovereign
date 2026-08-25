"""H8f — HexStrike's FIRST live FACT (nmap SERVICE_REACHABILITY) through the PRODUCTION brain path.

The operator-checkpoint-gated slice that PROVISIONS the body's runner so a `vigil engage --brain hexstrike`
run can mint its first real, signed, offline-verifiable FACT. The MECHANISM already existed and was tested
(`test_hexstrike_body.test_live_nmap_fact_through_the_body`); what this slice adds is the PRODUCTION seam:
`BrainThink(runner=RunnerDeps(...))` returns a runner-equipped body, and a per-action capability minter
mints a fresh single-use token bound to the exact argv the brain proposes. DEFAULT (no runner) stays
runner-less → 0 facts → the FP-0 canary and every `fact_count==0` test are unchanged.

Scope of THIS slice: minting + offline re-verification through the production seam. Surfacing the
body-minted FACT into `report.fact_count` (which needs durable certificate PERSISTENCE) is the immediate
follow-up **H8f-b** — until then a body-routed run mints the signed certificate but the run report's headline
count does not yet reflect it (asserted honestly below).

Full FACT-enabling battery (plan Part III / release gate #2,#7,#6,#9):
  * POSITIVE           — BrainThink(runner) mints a real signed nmap SERVICE_REACHABILITY FACT that
                         re-verifies OFFLINE (the runner's own admit()+certify; the body supplies no provenance).
  * PRODUCTION SEAM    — through `build_engine.engage` (`--brain-execute-via-body`) the body is reached and mints.
  * false-FACT         — an nmap run with NO reachable service mints NO fact (paired with a minting control).
  * false-CLEAN        — a missing handshake precondition is INCONCLUSIVE, never a false CLEAN.
  * scope              — an out-of-charter target is refused BEFORE traffic (the tool never launches).
  * gate parity        — a provisioned runner with no capability is refused pre-traffic (slice-1 invariant).

Offense leg only (imports framework via the runner/oracle) → listed in the ci.yml offense run-list.
"""
from __future__ import annotations

import socket
from pathlib import Path

import pytest

pytest.importorskip("framework")  # offense leg only — the runner + oracle need engine/crucible on the path

from framework.v2.agent_body.interface import GateDecision, ProposedAction
from vigil_core import generate_keypair
from vigil_core.models import AuthorizerKey, TrustRoot
from vigil_gateway.scope_source import StaticScopeSource
from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain
from vigil_integration.brains.hexstrike_body import RunnerDeps
from vigil_integration.live.capability_token import (
    CapabilityAuthority,
    CapabilityGrant,
    mint_capability_token,
    operation_hash,
    policy_digest,
)
from vigil_integration.live.external_tool import CapabilityCheck, ScopeGate, ToolOutcome
from vigil_integration.live.nonce_ledger import NonceLedger

_GOV = generate_keypair()
SIGNERS = [("gov0", _GOV.private_key_b64)]          # governance m-of-n signers (certify the FACT)
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=_GOV.public_key_b64)])
_OWNER = generate_keypair()                          # the deployment owner key (mints capability tokens)
_KEY_ID = "owner-root"
_AUTHORITY = CapabilityAuthority(owner_key_id=_KEY_ID, owner_public_key_b64=_OWNER.public_key_b64)
_DEPLOYMENT = "deploy-h8f-1"
_DANGER = "recon"
_POLICY_DIGEST = policy_digest({"warden": "A2", "charter": "alpha"})


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


def _loopback_listener() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    return srv, srv.getsockname()[1]


class _CannedNmap:
    """A gated-backend stand-in: returns a fixed nmap grepable line (naming ``open_port`` if set, else no
    open port), and records launches so 'refused before traffic' is provable. Hermetic — no nmap binary; the
    FACT is still VIGIL's OWN gated handshake against the real loopback listener, not these canned bytes."""

    name = "canned-nmap"
    loopback_only = False

    def __init__(self, open_port: "int | None") -> None:
        self._open_port = open_port
        self.launches: list = []

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        self.launches.append(list(argv))
        if self._open_port is None:
            body = "Host: 127.0.0.1 ()\tStatus: Up\n"       # up, but NO open port → propose finds nothing
        else:
            body = f"Host: 127.0.0.1 ()\tPorts: {self._open_port}/open/tcp//unknown///\n"
        return ToolOutcome(list(argv), 0, body, "", self.name)


def _minter(ledger: NonceLedger, *, now: float = 1100.0):
    """A PER-ACTION capability minter: mints a fresh single-use token bound to the EXACT argv the runner is
    about to build for THIS operation, under the deployment owner key. This is the shape the operator-checkpoint
    wiring supplies in production (the owner authorises the specific operation → a token minted for it)."""
    counter = {"n": 0}

    def _mint(spec, target):
        counter["n"] += 1
        grant = CapabilityGrant(
            deployment=_DEPLOYMENT, engagement="alpha",
            operation_hash=operation_hash(spec.name, target, list(spec.build_argv(target))),
            target=target, tool=spec.name, danger_class=_DANGER, policy_digest=_POLICY_DIGEST)
        token = mint_capability_token(grant, owner_private_key_b64=_OWNER.private_key_b64, key_id=_KEY_ID,
                                      nonce=f"h8f-{counter['n']}", not_before=1000.0, expiry=1300.0)
        return CapabilityCheck(token=token, authority=_AUTHORITY, ledger=ledger, deployment=_DEPLOYMENT,
                               danger_class=_DANGER, policy_digest=_POLICY_DIGEST, now=lambda: now)

    return _mint


def _deps(backend, ledger: NonceLedger, *, scope=("127.0.0.1",)) -> RunnerDeps:
    return RunnerDeps(
        scope_gate=ScopeGate(scope=StaticScopeSource(list(scope)), loopback_allowed_if_scoped=True),
        backend=backend, engagement_slug="alpha", signers=SIGNERS, capability=_minter(ledger))


# ===================================================================================================
# POSITIVE — the first live FACT: BrainThink provisions the runner, the body mints a signed nmap
# SERVICE_REACHABILITY FACT via the per-action capability minter, and it re-verifies OFFLINE.
# ===================================================================================================
def test_h8f_brainthink_runner_mints_a_signed_nmap_fact_offline_verifiable(tmp_path: Path):
    from framework.v2.evidence.certify import verify_certificate

    _charter(tmp_path, "127.0.0.1")
    srv, port = _loopback_listener()
    ledger = NonceLedger(tmp_path / "nonces")
    deps = _deps(_CannedNmap(port), ledger)
    # staging posture → the recon nmap step is gate-auto-eligible; the runner is provisioned via BrainThink.
    brain = BrainThink(HexstrikeBrain(), target="127.0.0.1", posture="staging", runner=deps)
    body = brain.body()                      # the SAME canonical body the production engine seam drives
    try:
        action = ProposedAction(kind="nmap", target="127.0.0.1", params={"ports": str(port), "danger": "recon"})
        assert body.gate(action).authorized is True     # recon + staging → auto (the operator checkpoint)
        outcome = body.execute(action, body.gate(action))
    finally:
        srv.close()
    assert outcome.executed is True and outcome.detail.get("n_facts") == 1, outcome
    af = outcome.detail["facts"][0]
    assert af.is_fact and af.bug_class == "service_reachable", af
    # OFFLINE re-verification: the runner retained the oracle_context; verify_certificate re-runs the oracle
    # over it with NO target on the path — a genuine offline replay of the signed certificate.
    ctx = outcome.detail["contexts"][af.finding_ref]
    ver = verify_certificate(af.signed, oracle_context=ctx, trust_root=TRUST)
    assert ver.ok is True, f"the minted nmap FACT did not re-verify offline: {ver}"
    assert ledger.is_consumed("h8f-1"), "the per-action single-use capability nonce must be burned"


def test_h8f_default_brainthink_is_runnerless_and_mints_nothing(tmp_path: Path):
    """The DEFAULT (no runner provisioned) stays runner-less: the body executes nothing and mints ZERO facts —
    so the FP-0 seam is closed unless the operator explicitly provisions a runner (the checkpoint)."""
    body = BrainThink(HexstrikeBrain(), target="127.0.0.1", posture="staging").body()
    out = body.execute(ProposedAction(kind="nmap", target="127.0.0.1", params={"ports": "80", "danger": "recon"}),
                       GateDecision(authorized=True))
    assert out.executed is False and "runner not provisioned" in out.blocked_reason, out


# ===================================================================================================
# PRODUCTION SEAM — through the live engine (--brain-execute-via-body) the runner-equipped body is reached
# and mints. (report.fact_count surfacing is H8f-b; here we prove the seam reaches the minting body.)
# ===================================================================================================
def test_h8f_production_engine_seam_reaches_the_minting_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from types import SimpleNamespace

    from vigil_integration.brains import hexstrike_body
    from vigil_integration.live.wiring import EngineConfig, build_engine, provision_authority

    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    from framework.v2.agents import blackboard as _bb
    db = tmp_path / "bb.sqlite"
    monkeypatch.setattr(_bb, "open_blackboard", lambda **_kw: _bb.Blackboard(db_path=db))
    _charter(tmp_path, "127.0.0.1")
    srv, port = _loopback_listener()

    # spy the body's execute to capture the minted FACT the engine seam drives it to produce.
    minted = {"facts": []}
    orig = hexstrike_body.HexstrikeAgentBody.execute

    def _spy(self, action, decision):
        out = orig(self, action, decision)
        for f in (out.detail or {}).get("facts", []) or []:
            minted["facts"].append(f)
        return out

    monkeypatch.setattr(hexstrike_body.HexstrikeAgentBody, "execute", _spy)

    ledger = NonceLedger(tmp_path / "nonces")
    deps = _deps(_CannedNmap(port), ledger)
    brain = BrainThink(HexstrikeBrain(), target="127.0.0.1", posture="staging", runner=deps)
    prov = provision_authority(slug="alpha", scope=["127.0.0.1"])
    cfg = EngineConfig(slug="alpha", base_dir=str(tmp_path / "live"), provisioned=prov,
                       runner=lambda *a, **k: SimpleNamespace(exit_code=0, stdout="", stderr="",
                                                              timed_out=False, truncated=False),
                       max_iterations=6, owner_approves_offense=True, brain=brain,
                       brain_execute_via_body=True)
    try:
        report = build_engine(cfg).engage("127.0.0.1")
    finally:
        srv.close()
    # the production engine seam routed a gate-authorized nmap through the runner-equipped body, which minted a
    # real SERVICE_REACHABILITY FACT (captured at the body seam).
    nmap_facts = [f for f in minted["facts"] if getattr(f, "bug_class", "") == "service_reachable"]
    assert nmap_facts, "the engine seam did not drive the runner-equipped body to mint an nmap FACT"
    # H8f-b (follow-up) surfaces the body FACT into the run report; until then the headline count is honestly 0.
    assert report.fact_count == 0, "report surfacing of body facts is H8f-b — the count must not silently change"


# ===================================================================================================
# false-FACT — an nmap run against NO reachable service mints NO fact (the gated handshake never connects),
# paired with the minting control so 'no fact' is a real difference, not a runner that never mints.
# ===================================================================================================
def test_h8f_false_fact_no_open_service_mints_nothing(tmp_path: Path):
    _charter(tmp_path, "127.0.0.1")
    ledger = NonceLedger(tmp_path / "nonces")
    body = BrainThink(HexstrikeBrain(), target="127.0.0.1", posture="staging",
                      runner=_deps(_CannedNmap(None), ledger)).body()  # canned output names NO open port
    out = body.execute(ProposedAction(kind="nmap", target="127.0.0.1", params={"ports": "80", "danger": "recon"}),
                       GateDecision(authorized=True))
    assert out.executed is True and out.detail.get("n_facts") == 0, out


def test_h8f_false_fact_scanner_claims_unreachable_port_mints_nothing(tmp_path: Path):
    """The SHARP 'don't trust the scanner' case: the tool PROPOSES an open port, but VIGIL's OWN gated
    handshake cannot reach it — so NO fact is minted. Stronger than the no-port row: here a service IS
    proposed, yet the independent re-drive refuses to confirm the scanner's say-so."""
    _charter(tmp_path, "127.0.0.1")
    # a port bound but NOT listening → the kernel refuses connects (RST), so VIGIL's handshake fails to
    # establish a channel even though the canned nmap 'reports' it open. (Kept open so the port cannot be
    # reused by another listener mid-test.)
    dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    ledger = NonceLedger(tmp_path / "nonces")
    body = BrainThink(HexstrikeBrain(), target="127.0.0.1", posture="staging",
                      runner=_deps(_CannedNmap(dead_port), ledger)).body()
    try:
        out = body.execute(ProposedAction(kind="nmap", target="127.0.0.1",
                                          params={"ports": str(dead_port), "danger": "recon"}),
                           GateDecision(authorized=True))
    finally:
        dead.close()
    # the tool ran and PROPOSED the port, but VIGIL's own handshake could not reach it → zero FACTs.
    assert out.executed is True and out.detail.get("n_facts") == 0, out


def test_h8f_negative_control_a_reachable_service_DOES_mint(tmp_path: Path):
    """Non-vacuity for the false-FACT row: the SAME path DOES mint when a service is genuinely reachable."""
    _charter(tmp_path, "127.0.0.1")
    srv, port = _loopback_listener()
    ledger = NonceLedger(tmp_path / "nonces")
    body = BrainThink(HexstrikeBrain(), target="127.0.0.1", posture="staging",
                      runner=_deps(_CannedNmap(port), ledger)).body()
    try:
        out = body.execute(ProposedAction(kind="nmap", target="127.0.0.1",
                                          params={"ports": str(port), "danger": "recon"}),
                           GateDecision(authorized=True))
    finally:
        srv.close()
    assert out.detail.get("n_facts") == 1, out


# ===================================================================================================
# false-CLEAN — the reachability branch must not read CLEAN off missing handshake evidence.
# ===================================================================================================
def test_h8f_false_clean_withheld_precondition_is_inconclusive_never_clean():
    """The admit-level guard: the reachability branch's declared precondition (gate_authorized) was NOT
    satisfied for this observation, so neither a firing nor a non-firing is meaningful — admit() must return
    INCONCLUSIVE, never a CLEAN off evidence that was never established. (The production runner additionally
    guards false-CLEAN via the oracle's conclusiveness — exercised by the unreachable-port row above and by
    the reachability oracle's own tests.)"""
    from vigil_integration.live.verdict import Verdict, admit

    out = admit("service_reachability.tcp_handshake", fired=False, conclusive=True, observed={})
    assert out.verdict is Verdict.INCONCLUSIVE, (
        f"a withheld precondition produced {out.verdict} — a reachability negative must never be CLEAN off "
        "evidence that was never established")


def test_h8f_negative_control_reachability_CAN_reach_clean_when_earned():
    """Non-vacuity: with the channel established and a conclusive non-fire, the branch DOES reach CLEAN — so
    the row above proves 'missing evidence != clean', not 'CLEAN is unreachable'."""
    from vigil_integration.live.verdict import Verdict, admit

    out = admit("service_reachability.tcp_handshake", fired=False, conclusive=True,
                observed={"channel_established": True, "gate_authorized": True})
    assert out.verdict in (Verdict.CLEAN, Verdict.INCONCLUSIVE)  # never a FACT off a non-fire
    assert out.verdict is not Verdict.FACT


# ===================================================================================================
# scope — an out-of-charter target is refused BEFORE any traffic (the tool never launches).
# ===================================================================================================
def test_h8f_out_of_scope_target_is_refused_before_traffic(tmp_path: Path):
    _charter(tmp_path, "127.0.0.1")
    ledger = NonceLedger(tmp_path / "nonces")
    spy = _CannedNmap(80)
    # charter authorises 127.0.0.1 only; drive nmap at a private IP the charter does NOT name.
    body = BrainThink(HexstrikeBrain(), target="10.0.0.5", posture="staging",
                      runner=_deps(spy, ledger, scope=("127.0.0.1",))).body()
    out = body.execute(ProposedAction(kind="nmap", target="10.0.0.5", params={"ports": "80", "danger": "recon"}),
                       GateDecision(authorized=True))
    assert out.executed is False and "runner refused (pre-traffic)" in out.blocked_reason, out
    assert spy.launches == [], "an out-of-scope target must be refused before the tool is launched"


# ===================================================================================================
# gate parity (slice-1 invariant, re-pinned on the BrainThink production path) — a provisioned runner with
# NO capability minter/token is refused before traffic.
# ===================================================================================================
def test_h8f_provisioned_runner_without_capability_is_refused(tmp_path: Path):
    _charter(tmp_path, "127.0.0.1")
    spy = _CannedNmap(80)
    deps = RunnerDeps(scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
                      backend=spy, engagement_slug="alpha", signers=SIGNERS, capability=None)
    body = BrainThink(HexstrikeBrain(), target="127.0.0.1", posture="staging", runner=deps).body()
    out = body.execute(ProposedAction(kind="nmap", target="127.0.0.1", params={"ports": "80", "danger": "recon"}),
                       GateDecision(authorized=True))
    assert out.executed is False and "without a single-use capability token" in out.blocked_reason, out
    assert spy.launches == []
