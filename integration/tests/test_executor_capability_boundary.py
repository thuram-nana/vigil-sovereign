"""W13-5 (#498) — FUNCTIONAL proof that the OFFENSE executor (``run_external_tool``) validates a
nine-field-bound, single-use CAPABILITY TOKEN immediately before it launches a tool, and refuses a
stale/replayed/different-operation token BEFORE any subprocess runs.

This complements ``test_capability_token.py`` (which proves the token machinery + the STRUCTURAL invariant,
import-clean). This file drives the REAL runner end-to-end, so it imports ``framework`` (via the runner's
pre-flight gate + oracle adapter) and therefore runs ONLY in the OFFENSE leg of the required
`integration two-env boundary (P5)` CI job — it is listed there explicitly. A SPY backend records whether
the tool was actually launched, so "refused before running" is proven by the tool never being invoked.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here (offense leg only)")

from vigil_core import generate_keypair  # noqa: E402
from vigil_gateway.scope_source import StaticScopeSource  # noqa: E402
from vigil_integration.live.capability_token import (  # noqa: E402
    CapabilityAuthority,
    CapabilityGrant,
    mint_capability_token,
    operation_hash,
    policy_digest,
)
from vigil_integration.live.external_tool import (  # noqa: E402
    CapabilityCheck,
    ScopeGate,
    ToolOutcome,
    nmap_service_scan,
    run_external_tool,
)
from vigil_integration.live.nonce_ledger import NonceLedger  # noqa: E402

_KP = generate_keypair()
_KEY_ID = "owner-root"
_AUTHORITY = CapabilityAuthority(owner_key_id=_KEY_ID, owner_public_key_b64=_KP.public_key_b64)
_SIGNER = generate_keypair()
_SIGNERS = [("root0", _SIGNER.private_key_b64)]
_POLICY_DIGEST = policy_digest({"warden": "A2", "charter": "alpha"})
_DEPLOYMENT = "deploy-prod-1"
_DANGER = "recon"


@dataclass
class SpyBackend:
    """A gated-backend stand-in that records EVERY launch. ``loopback_only=False`` so the loopback-floor
    check is not what stops a run — only the capability boundary is under test here."""

    name: str = "spy"
    loopback_only: bool = False
    launches: list = field(default_factory=list)

    def available(self) -> tuple[bool, str]:
        return True, ""

    def run(self, tool_argv, *, timeout: float) -> ToolOutcome:
        self.launches.append(list(tool_argv))
        return ToolOutcome(list(tool_argv), 0, "", "", self.name)


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate the kill-switch/charter paths and grant the active-recon entitlement so the runner's
    pre-flight gate passes — mirrors test_external_tool_runner._isolate — leaving the capability token as
    the control variable."""
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _spec_and_grant(target="127.0.0.1"):
    spec = nmap_service_scan(ports="80")
    grant = CapabilityGrant(
        deployment=_DEPLOYMENT, engagement="alpha",
        operation_hash=operation_hash(spec.name, target, list(spec.build_argv(target))),
        target=target, tool=spec.name, danger_class=_DANGER, policy_digest=_POLICY_DIGEST,
    )
    return spec, grant


def _token(grant: CapabilityGrant, *, nonce="n-1", not_before=1000.0, expiry=1300.0):
    return mint_capability_token(grant, owner_private_key_b64=_KP.private_key_b64, key_id=_KEY_ID,
                                 nonce=nonce, not_before=not_before, expiry=expiry)


def _check(token, ledger, *, now=1100.0):
    return CapabilityCheck(token=token, authority=_AUTHORITY, ledger=ledger, deployment=_DEPLOYMENT,
                           danger_class=_DANGER, policy_digest=_POLICY_DIGEST, now=lambda: now)


def _gate():
    return ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)


def test_a_valid_token_lets_the_executor_run_the_tool_and_burns_the_nonce(tmp_path: Path):
    spec, grant = _spec_and_grant()
    token = _token(grant, nonce="ok-1")
    ledger = NonceLedger(tmp_path / "nonces")
    spy = SpyBackend()
    res = run_external_tool(spec, "127.0.0.1", scope_gate=_gate(), backend=spy,
                            engagement_slug="alpha", signers=_SIGNERS, capability=_check(token, ledger))
    assert res.status == "ran", res.reason
    assert spy.launches, "the tool must have been launched with a valid token"
    assert ledger.is_consumed("ok-1"), "the nonce must be burned at the executor boundary"


def test_the_same_token_replayed_is_refused_and_the_tool_never_runs(tmp_path: Path):
    spec, grant = _spec_and_grant()
    token = _token(grant, nonce="replay-1")
    ledger = NonceLedger(tmp_path / "nonces")
    # first run consumes the nonce
    assert run_external_tool(spec, "127.0.0.1", scope_gate=_gate(), backend=SpyBackend(),
                             engagement_slug="alpha", signers=_SIGNERS,
                             capability=_check(token, ledger)).status == "ran"
    # replay: same token, same ledger → refused BEFORE the tool launches
    spy = SpyBackend()
    res = run_external_tool(spec, "127.0.0.1", scope_gate=_gate(), backend=spy,
                            engagement_slug="alpha", signers=_SIGNERS, capability=_check(token, ledger))
    assert res.refused and "capability token refused" in res.reason
    assert spy.launches == [], "a replayed token must not launch the tool"


def test_a_token_for_a_different_operation_is_refused_before_running(tmp_path: Path):
    spec, _grant_80 = _spec_and_grant()
    # a token minted for a DIFFERENT operation (port 443 → different argv → different operation_hash)
    other_target_spec = nmap_service_scan(ports="443")
    wrong_grant = CapabilityGrant(
        deployment=_DEPLOYMENT, engagement="alpha",
        operation_hash=operation_hash(other_target_spec.name, "127.0.0.1",
                                      list(other_target_spec.build_argv("127.0.0.1"))),
        target="127.0.0.1", tool=spec.name, danger_class=_DANGER, policy_digest=_POLICY_DIGEST,
    )
    token = _token(wrong_grant, nonce="wrong-op")
    ledger = NonceLedger(tmp_path / "nonces")
    spy = SpyBackend()
    # present it while the executor is about to run the PORT-80 operation
    res = run_external_tool(spec, "127.0.0.1", scope_gate=_gate(), backend=spy,
                            engagement_slug="alpha", signers=_SIGNERS, capability=_check(token, ledger))
    assert res.refused and "capability token refused" in res.reason
    assert spy.launches == []
    assert not ledger.is_consumed("wrong-op"), "a mismatched token must not burn its nonce"


def test_an_expired_token_is_refused_before_running(tmp_path: Path):
    spec, grant = _spec_and_grant()
    token = _token(grant, nonce="exp-1", not_before=1000.0, expiry=1300.0)
    ledger = NonceLedger(tmp_path / "nonces")
    spy = SpyBackend()
    res = run_external_tool(spec, "127.0.0.1", scope_gate=_gate(), backend=spy,
                            engagement_slug="alpha", signers=_SIGNERS,
                            capability=_check(token, ledger, now=1400.0))  # past expiry
    assert res.refused and "capability token refused" in res.reason
    assert spy.launches == []


def test_a_token_for_a_different_engagement_is_refused(tmp_path: Path):
    spec, grant = _spec_and_grant()
    token = _token(grant, nonce="eng-1")  # bound to engagement "alpha"
    ledger = NonceLedger(tmp_path / "nonces")
    spy = SpyBackend()
    # run under a DIFFERENT engagement slug → the executor-built grant.engagement won't match the token
    res = run_external_tool(spec, "127.0.0.1", scope_gate=_gate(), backend=spy,
                            engagement_slug="bravo", signers=_SIGNERS, capability=_check(token, ledger))
    assert res.refused and "capability token refused" in res.reason
    assert spy.launches == []


def test_no_capability_threaded_preserves_existing_behaviour(tmp_path: Path):
    """NEGATIVE CONTROL that the boundary is not a blanket blocker: with no capability threaded the runner
    behaves exactly as before (the upstream gate chain governs), so existing callers are unbroken."""
    spec, _ = _spec_and_grant()
    spy = SpyBackend()
    res = run_external_tool(spec, "127.0.0.1", scope_gate=_gate(), backend=spy,
                            engagement_slug="alpha", signers=_SIGNERS)  # capability=None
    assert res.status == "ran"
    assert spy.launches, "with no capability the tool still runs under the existing gates"
