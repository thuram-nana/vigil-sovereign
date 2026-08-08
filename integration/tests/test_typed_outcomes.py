"""PHASE 0.1 — the typed outcome taxonomy (criterion 7).

An integration standard requires positive / clean / inconclusive / error / skipped / unsupported to stay
DISTINCT — never collapsed into one "lead" bucket. These tests prove all six are produced and distinguished:

  * adapter layer (confirm_and_certify) — POSITIVE (a signed FACT), CLEAN (an oracle conclusively did not
    fire), INCONCLUSIVE (an oracle ran with no decisive channel), UNSUPPORTED (fired but not
    oracle-mapped / not runner-owned so no FACT can be minted);
  * runner layer (run_external_tool) — ERROR (the tool timed out / could not spawn) and SKIPPED (the
    runner's own capture yielded no evidence a re-drive can judge).

Soundness is unchanged: POSITIVE is still the ONLY signed-FACT state; the classification is behaviour-
preserving over the FACT decision (adjudicate_finding + confirmed_from_result == confirm_finding).
"""
from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_gateway.scope_source import StaticScopeSource  # noqa: E402
from vigil_integration.oracle_adapter import Outcome, confirm_and_certify  # noqa: E402
from vigil_integration.live.external_tool import (  # noqa: E402
    ProposedService,
    Redrive,
    ScopeGate,
    ToolOutcome,
    ToolSpec,
    run_external_tool,
)

_SIGNER = generate_keypair()
SIGNERS = [("root0", _SIGNER.private_key_b64)]

# the real open_redirect predicate shape
_OR_PRED = {"any": [{"all": [{"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                             {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]}]}


def _predicate_finding(observed: dict, *, bug_class: str = "open_redirect") -> dict:
    from framework.v2.verify.adapter import FindingContext
    ctx = FindingContext.from_predicate(observed_evidence=observed, predicate=_OR_PRED,
                                        bug_class=bug_class).to_verifier_context()
    return {"bug_class": bug_class, "check_id": "t", "surface": "http://t/", "oracle_context": ctx}


# ---- adapter layer: the four adjudication outcomes ----------------------------------------------

def test_positive_outcome_is_the_only_fact():
    """A firing, oracle-mapped, runner-owned (live_redrive) predicate → POSITIVE + a signed FACT."""
    finding = _predicate_finding({"status": 302, "location_host": "c.test", "canary_host": "c.test", "body": ""})
    res = confirm_and_certify(finding, engagement_slug="e", signers=SIGNERS, provenance="live_redrive")
    assert res.is_fact and res.outcome == Outcome.POSITIVE.value
    assert res.signed is not None


def test_clean_outcome_conclusive_non_fire():
    """A predicate that conclusively does NOT fire (predicate_oracle is conclusive either way) → CLEAN,
    not a FACT, and distinct from inconclusive."""
    finding = _predicate_finding({"status": 200, "location_host": "", "canary_host": "c.test", "body": ""})
    res = confirm_and_certify(finding, engagement_slug="e", signers=SIGNERS, provenance="live_redrive")
    assert not res.is_fact and res.outcome == Outcome.CLEAN.value


def test_inconclusive_outcome_no_channel():
    """A single-shot differential over indistinguishable responses (one-sided, non-conclusive) →
    INCONCLUSIVE — never CLEAN."""
    from framework.v2.verify.adapter import FindingContext
    resp = {"status": 200, "body": "identical body", "latency_ms": 10}
    ctx = FindingContext.from_http_responses(
        resp, resp, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]}).to_verifier_context()
    res = confirm_and_certify({"bug_class": "boolean_sqli", "check_id": "t", "oracle_context": ctx},
                              engagement_slug="e", signers=SIGNERS, provenance="live_redrive")
    assert not res.is_fact and res.outcome == Outcome.INCONCLUSIVE.value


def test_unsupported_outcome_llm_provenance_fires_but_cannot_mint():
    """A firing, oracle-mapped predicate whose context is LLM-provenanced (the default) → UNSUPPORTED:
    VIGIL structurally will not mint a FACT (not runner-owned), even though the oracle fired."""
    finding = _predicate_finding({"status": 302, "location_host": "c.test", "canary_host": "c.test", "body": ""})
    res = confirm_and_certify(finding, engagement_slug="e", signers=SIGNERS, provenance="llm")
    assert not res.is_fact and res.outcome == Outcome.UNSUPPORTED.value


def test_the_four_adapter_outcomes_are_distinct():
    """Positive/clean/inconclusive/unsupported are four DIFFERENT values (no collapse)."""
    vals = {Outcome.POSITIVE.value, Outcome.CLEAN.value, Outcome.INCONCLUSIVE.value,
            Outcome.UNSUPPORTED.value, Outcome.ERROR.value, Outcome.SKIPPED.value}
    assert len(vals) == 6


# ---- runner layer: ERROR + SKIPPED --------------------------------------------------------------

def _charter(tmp_path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `t`   Date: `2026-08-08`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n",
        encoding="utf-8")


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


class _TimeoutBackend:
    name = "timeout"

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), None, "", "", self.name, timed_out=True)


def test_runner_records_error_on_tool_timeout(tmp_path):
    """A tool that times out → RunnerResult.tool_errored + an ERROR outcome, distinct from a clean run."""
    _charter(tmp_path, "127.0.0.1")
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    spec = ToolSpec("faketool", lambda t: ["faketool", t], lambda o, t: [])
    res = run_external_tool(spec, "127.0.0.1", scope_gate=gate, backend=_TimeoutBackend(),
                            engagement_slug="alpha", signers=SIGNERS)
    assert res.tool_errored is True
    assert any(o["outcome"] == Outcome.ERROR.value for o in res.outcomes)
    assert res.facts == []


class _OkBackend:
    name = "ok"

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), 0, "reached", "", self.name)

    def available(self):
        return True, ""


def test_runner_records_skipped_when_capture_yields_no_evidence(tmp_path):
    """A re-drive whose context builder returns None (the runner's capture yielded nothing to judge) →
    a SKIPPED outcome — never a fabricated FACT and never a false CLEAN."""
    _charter(tmp_path, "127.0.0.1")
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    # a spec that proposes one service, with a re-drive whose capture is trivial and whose context is None
    spec = ToolSpec(
        "skiptool",
        lambda t: ["skiptool", t],
        lambda o, t: [ProposedService(host=t, port=443, protocol="tcp")],
        redrives=(Redrive("weak_crypto_artifact", lambda h, p, *, slug, protocol: {"connected": True},
                          lambda cap: None),),
    )
    res = run_external_tool(spec, "127.0.0.1", scope_gate=gate, backend=_OkBackend(),
                            engagement_slug="alpha", signers=SIGNERS)
    assert res.facts == [] and res.tool_errored is False
    assert any(o["outcome"] == Outcome.SKIPPED.value for o in res.outcomes)


class _TimeoutButProposingBackend:
    """A tool that TIMED OUT yet emitted a partial row a naive parser would trust."""
    name = "toerr"

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), None, "80/open/tcp (partial, truncated)", "", self.name, timed_out=True)


_FIRE_OR = {"any": [{"all": [{"in": [{"var": "status"}, [302]]},
                            {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]}]}


def _firing_redrive_ctx(_cap):
    from framework.v2.verify.adapter import FindingContext
    return FindingContext.from_predicate(
        observed_evidence={"status": 302, "location_host": "c.test", "canary_host": "c.test", "body": ""},
        predicate=_FIRE_OR, bug_class="open_redirect").to_verifier_context()


def test_tool_errored_fact_still_comes_from_the_runner_owned_redrive(tmp_path):
    """Criterion-3 soundness lock-in (red-pen advisory): even when the TOOL errored, any FACT is minted
    from the runner's OWN re-drive capture — never the (untrusted, truncated) tool output. The ERROR and
    the POSITIVE are recorded as DISTINCT outcomes; the FACT's oracle_context carries the re-drive keys and
    contains none of the tool's stdout."""
    import json as _json

    _charter(tmp_path, "127.0.0.1")
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    spec = ToolSpec(
        "toerr", lambda t: ["toerr", t],
        lambda o, t: [ProposedService(host=t, port=443, protocol="tcp")],
        redrives=(Redrive("open_redirect", lambda h, p, *, slug, protocol: {}, _firing_redrive_ctx),),
    )
    res = run_external_tool(spec, "127.0.0.1", scope_gate=gate, backend=_TimeoutButProposingBackend(),
                            engagement_slug="alpha", signers=SIGNERS)
    assert res.tool_errored is True
    outs = {o["outcome"] for o in res.outcomes}
    assert Outcome.ERROR.value in outs and Outcome.POSITIVE.value in outs   # distinct, not conflated
    assert res.facts, "expected a FACT from the runner-owned re-drive"
    fact_ctx = res.contexts[res.facts[0].finding_ref]
    assert "predicate" in fact_ctx and "observed_evidence" in fact_ctx      # re-drive evidence, not tool output
    assert "80/open/tcp" not in _json.dumps(fact_ctx)                       # tool stdout never enters the FACT
