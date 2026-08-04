"""TRUTHENOVATION R1 (PR1) — the DIFFERENTIAL (boolean-inference) remediation channel, offline against a fake.

Exercises the differential branch of :func:`prove_remediation` (``_prove_differential``) over the §8 adversarial
corpus of ``docs/proof-carrying-finding/DIFFERENTIAL-REMEDIATION.md``, WITHOUT a live target: the fake emits
matched-decoy round bundles (``{true, false_a, false_b, baseline}``) and each corpus case drives one branch.

THE ONE INVARIANT under test — a false REMEDIATED is the exact overclaim this program exists to KILL:
REMEDIATED is minted ONLY on a decisive SPRT ``refute`` AND a passing WAF-closure test. A blocking
payload-discriminating WAF (case 3) and an SPRT-inconclusive run (case 7) both yield INCONCLUSIVE, NEVER
REMEDIATED. The oracle re-fire (boolean_inference SPRT + differential_response WAF-closure) is REAL (framework),
so a REMEDIATED verdict is earned over the fake's round bytes exactly as it would be over live bytes.

Needs framework (the oracles + the retained-control reverify) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import pytest

from vigil_core import (
    generate_keypair, identity_digest, prove_wielder, sign_capability, sign_identity_attestation,
)
from vigil_integration.remediation.prove_driver import (
    ControlObservation, Freshness, ProvePolicy, Reason, State, TrialObservation,
    prove_remediation, verify_prove_certificate,
)

OWNER = generate_keypair()
WIELDER = generate_keypair()

ENG = "acme"
NOW = 1_000
BUG = "boolean_sqli"
POLICY = {"host": ["shop.acme.test"]}
SAMPLE = {"host": "shop.acme.test"}
PUBKEYS = {"gov0": OWNER.public_key_b64}
SIGNERS = [("gov0", OWNER.private_key_b64)]

BOOL_DISC = {"dimensions": ["status", "length", "lexical"]}


# ---- response / round builders (the observed bytes the oracles judge) ----
def R(status: int, body: str) -> dict:
    return {"status": status, "body": body}


NORMAL = R(200, '{"results": []}')                 # a benign "no results" page (JSON so structural applies)
ROWS = R(200, '{"results": [{"id": 1}]}')          # a TRUE-predicate page: a record materialised
BLOCK = R(403, "<html><body>Request blocked by WAF</body></html>")   # a metachar block page


def _round(true, false_a, false_b, baseline) -> dict:
    return {"true": true, "false_a": false_a, "false_b": false_b, "baseline": baseline}


# genuine fix / sanitizing WAF: all four probes indistinguishable and baseline-shaped (SPRT refute, closure holds)
SILENT_ROUND = _round(NORMAL, NORMAL, NORMAL, NORMAL)
# still-vulnerable clean path: true differs from a STABLE false pair (SPRT confirm)
SIGNAL_ROUND = _round(ROWS, NORMAL, NORMAL, NORMAL)
# a non-signal round whose baseline == false_a (drives the SPRT toward refute without tripping closure)
NONSIGNAL_ROUND = _round(NORMAL, NORMAL, NORMAL, NORMAL)
# blocking WAF: the metachar probes get an identical block page; the benign baseline is a normal 200
BLOCKED_ROUND = _round(BLOCK, BLOCK, BLOCK, NORMAL)
# structurally-dynamic page: every probe differs in record COUNT (baseline != false_a → closure fails)
DYNAMIC_ROUND = _round(R(200, '{"i": [1, 2, 3]}'), R(200, '{"i": [1, 2]}'),
                       R(200, '{"i": [1, 2, 3, 4]}'), R(200, '{"i": [1]}'))
CONFIRM_ROUNDS = [SIGNAL_ROUND, SIGNAL_ROUND, SIGNAL_ROUND]   # retained firing rounds for the positive control


class FakeDifferentialAdapter:
    """A configurable differential ``LiveTargetAdapter``. ``rounds`` are emitted per trial (cyclically); the
    positive control returns RETAINED confirming rounds so the SAME boolean oracle still CONFIRMS. Knobs drive
    the malformed-round (fail-closed) and freshness-echo cases."""

    def __init__(self, *, rounds, confirm_rounds=None, nonce_echoed=True, malformed_at=None,
                 identity=None, bug_class=BUG):
        self.bug_class = bug_class
        self.oracle_family = "boolean_inference"
        self.differential_channel = True
        self.oracle_id = "oracle:boolean_inference"
        self.oracle_version = "1.0"
        self.original_probe_recipe_digest = "sha256:probe"
        self.execution_profile_digest = "sha256:profile"
        self.destructive = False
        self._rounds = rounds
        self._confirm_rounds = confirm_rounds if confirm_rounds is not None else CONFIRM_ROUNDS
        self._nonce_echoed = nonce_echoed
        self._malformed_at = malformed_at
        self._identity = identity or dict(SAMPLE)
        self.id_calls = 0

    def identity_sample(self):
        self.id_calls += 1
        return dict(self._identity)

    def run_positive_control(self, *, challenge, auth):
        ctx = {"bug_class": self.bug_class, "probe_rounds": [dict(r) for r in self._confirm_rounds],
               "discriminator": dict(BOOL_DISC)}
        return ControlObservation(reachable=True, channel_alive=True, oracle_context=ctx,
                                  definition_digest="sha256:control")

    def run_exploit_trial(self, *, challenge, trial_index, auth):
        if self._malformed_at is not None and trial_index == self._malformed_at:
            # §8 case 10 — one probe fetch failed → the WHOLE round is invalid (fail-closed; the driver must
            # NOT let boolean_inference silently continue past it).
            return TrialObservation(reachable=True, valid=False, oracle_context=None,
                                    invalid_reason="one matched-decoy probe fetch failed (simulated)")
        spec = self._rounds[trial_index % len(self._rounds)]
        return TrialObservation(reachable=True, valid=True, oracle_context=dict(spec),
                                freshness_level=Freshness.F1_TARGET_ECHOES, nonce_echoed=self._nonce_echoed)


def _identity_att(policy=None, not_after=9_000):
    return sign_identity_attestation(OWNER, engagement=ENG, policy=(policy or POLICY), not_after=not_after)


def _run(adapter, *, policy=ProvePolicy(), rate_limit=10, pop_challenge="pop-1"):
    ident = _identity_att()
    cap = sign_capability(OWNER, engagement=ENG, identity_digest=identity_digest(ident),
                          class_allowlist=[adapter.bug_class], not_before=0, not_after=9_000,
                          rate_limit=rate_limit, revocation_id="rev-1", audience=WIELDER.public_key_b64)
    wp = prove_wielder(WIELDER, challenge=pop_challenge, capability=cap)
    return prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wp,
        trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, finding_id="boolsqli-1",
        original_certificate_digest="sha256:orig", signers=SIGNERS, now=NOW, run_id="run-1",
        pop_challenge=pop_challenge, freshness_nonce="fresh-nonce-xyz", policy=policy)


# ============================ §8 corpus ============================
def test_case1_genuine_fix_is_remediated_origin_reached():
    # §8.1 — data-dependent true ≈ false, all baseline-shaped → SPRT refute + WAF-closure holds → REMEDIATED,
    # origin_reached=true. The signed cert independently RE-EXECUTES (SPRT re-refutes + closure re-holds).
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND]))
    assert out.state == State.REMEDIATED and out.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS, out
    assert out.achieved_freshness == Freshness.F1_TARGET_ECHOES   # PR1: differential channel is F1
    ev = out.certificate["evidence"]["differential"]
    assert ev["origin_reached"] is True and ev["sprt_decision"] == "refute" and ev["waf_closure"] == "pass"
    assert out.certificate["channel"] == "boolean_inference"
    ok, reason = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert ok, reason
    assert "origin_reached" in reason.lower()


def test_case2_still_vulnerable_clean_path_is_still_vulnerable():
    # §8.2 — injectable origin: true ≠ false, false_a ≈ false_b → SPRT confirm → STILL_VULNERABLE.
    out = _run(FakeDifferentialAdapter(rounds=[SIGNAL_ROUND, SIGNAL_ROUND, SIGNAL_ROUND]))
    assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED, out
    assert out.certificate["verdict"]["oracle_fired"] is True
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert ok


def test_case3_blocking_waf_is_inconclusive_interposer_suspected():
    # §8.3 — THE HEADLINE. Metachar probes get an identical block page; the benign baseline is a normal 200.
    # SPRT refutes (all block pages agree) BUT false_a differs from baseline → WAF-closure FAILS → INCONCLUSIVE
    # (INTERPOSER_SUSPECTED), NEVER REMEDIATED.
    out = _run(FakeDifferentialAdapter(rounds=[BLOCKED_ROUND, BLOCKED_ROUND, BLOCKED_ROUND]))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INTERPOSER_SUSPECTED, out
    assert out.state != State.REMEDIATED


def test_case4_sanitizing_waf_remediated_carries_origin_reached_only_not_clean_fix():
    # §8.4 — the BLOCK-1 disclosure pinned as a test. An in-flight sanitizer makes every probe inert (identical
    # to the genuine-fix observation) → REMEDIATED. Assert the cert carries ONLY origin_reached (NOT a clean-fix
    # claim) and SURFACES the (a-sanitize) residual, so the honesty cannot silently regress.
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND]))
    assert out.state == State.REMEDIATED, out
    ev = out.certificate["evidence"]["differential"]
    assert ev["origin_reached"] is True
    assert "sanitiz" in ev["residual_disclosure"].lower()          # the (a-sanitize) residual is surfaced
    assert "as observed through this edge" in out.detail.lower()   # not presented as a clean code fix
    # the cert asserts NOTHING stronger than origin_reached — no "clean_fix"/"code_fixed" claim field exists
    assert "clean_fix" not in ev and "code_fixed" not in ev


def test_case6_dynamic_page_is_not_a_false_still_vulnerable():
    # §8.6 — every probe differs in record COUNT. false_a ≠ false_b trips the per-round dynamic-page control →
    # non-signal → SPRT refutes; but baseline ≠ false_a → WAF-closure fails → INCONCLUSIVE. NOT STILL_VULNERABLE
    # (the control absorbed the noise) and NOT a false REMEDIATED (closure caught the structural drift).
    out = _run(FakeDifferentialAdapter(rounds=[DYNAMIC_ROUND, DYNAMIC_ROUND, DYNAMIC_ROUND]))
    assert out.state != State.STILL_VULNERABLE
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INTERPOSER_SUSPECTED, out


def test_case7_sprt_inconclusive_is_inconclusive_never_remediated():
    # §8.7 — oscillating rounds (signal, non-signal, signal) never reach an SPRT boundary → INCONCLUSIVE
    # (INSUFFICIENT_ROUNDS). Absence of evidence is not a fix: REMEDIATED requires a DECISIVE refute (HIGH-3).
    out = _run(FakeDifferentialAdapter(rounds=[SIGNAL_ROUND, NONSIGNAL_ROUND, SIGNAL_ROUND]))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_ROUNDS, out
    assert out.state != State.REMEDIATED


def test_case10_malformed_round_is_inconclusive_fail_closed():
    # §8.10 — one probe fetch fails → the whole run fails CLOSED (INCONCLUSIVE), never a silently-dropped round
    # that lets boolean_inference continue past it.
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND], malformed_at=1))
    assert out.state == State.INCONCLUSIVE, out
    assert out.reason_code == Reason.ORACLE_CONTEXT_UNREBUILDABLE
    assert out.state != State.REMEDIATED


# ============================ freshness / headline guards ============================
def test_freshness_echo_missing_is_inconclusive():
    # the inert challenge marker must be reflected (a query-stripping cache / non-echoing edge fails this).
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND], nonce_echoed=False))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.FRESHNESS_ECHO_MISSING


def test_headline_neither_blocking_waf_nor_sprt_inconclusive_ever_reaches_remediated():
    for adapter in (FakeDifferentialAdapter(rounds=[BLOCKED_ROUND, BLOCKED_ROUND, BLOCKED_ROUND]),
                    FakeDifferentialAdapter(rounds=[SIGNAL_ROUND, NONSIGNAL_ROUND, SIGNAL_ROUND])):
        out = _run(adapter)
        assert out.state == State.INCONCLUSIVE and out.state != State.REMEDIATED, out


def test_tampered_differential_rounds_fail_remediated_verification():
    # a REMEDIATED cert whose retained rounds are swapped for a FIRING round must NOT re-execute to a refute.
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND]))
    assert out.state == State.REMEDIATED
    out.certificate["evidence"]["differential"]["judged_rounds"] = [SIGNAL_ROUND, SIGNAL_ROUND, SIGNAL_ROUND]
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert not ok   # the signature is now broken AND the rounds would not re-refute
