"""TRUTHENOVATION R1 (PR1) — the DIFFERENTIAL (boolean-inference) remediation channel.

Two harnesses, both re-firing the REAL framework oracles (SPRT + WAF-closure), so a REMEDIATED verdict is
earned over the round bytes exactly as it would be over live bytes:

  * a FAKE-driven corpus that hands ``_prove_differential`` matched-decoy TRUTH-VALUE ATTRIBUTION round
    bundles (``{trues, falses, true_repeats, false_repeats, baseline}``) — covering the verdict-determining
    §8 cases 1,2,3,4,6,7,10
    (`DIFFERENTIAL-REMEDIATION.md`), the freshness-echo/floor guards, and the dual-red-pen regressions below;
  * a REAL ``DifferentialHttpAdapter`` driven end-to-end against a stdlib loopback origin through a genuine
    gated ``HttpExecutor`` (:func:`test_real_adapter_*`) — exercising the actual probe path (URL build,
    gated_fetch, fail-closed round assembly, nonce reflection) that the fake bypasses.

THE ONE INVARIANT — a false REMEDIATED is the overclaim this program KILLS. REMEDIATED is minted ONLY on a
decisive SPRT ``refute`` **attributable to genuine channel CLOSURE** (across=False on every judged round) AND a
passing WAF-closure test. Each of these yields INCONCLUSIVE, NEVER REMEDIATED: a blocking WAF (case 3), an
SPRT-inconclusive run (case 7), a malformed round (case 10), a caller demanding F2 (the freshness floor), and —
the red-pen BLOCK — a still-vulnerable NOISY origin (ASP.NET ``__VIEWSTATE`` / rotating token) whose refute is
driven by the dynamic-page control tripping, not closure (:func:`test_dynamic_page_noise_over_live_vuln_is_not_remediated`).

NOT tested here (disclosed, not claimed closed — spec §7): the a-sanitize / param-strip / structurally-matched
200 block-page / producer-forgery residuals, and §8 cases 8/9/11 (heuristic-boundary / cache / text-only
lexical) which the PR1 discriminators disclose as residual rather than guarantee.

Needs framework (the oracles + the retained-control reverify) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from vigil_core import (
    generate_keypair, identity_digest, prove_wielder, sign_capability, sign_identity_attestation,
)
from vigil_core import sign
from vigil_integration.remediation.differential_adapter import DifferentialHttpAdapter
from vigil_integration.remediation.prove_driver import (
    ControlObservation, Freshness, ProvePolicy, Reason, State, TrialObservation,
    _cert_signing_bytes, prove_remediation, verify_prove_certificate,
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


def _round(trues, falses, baseline, *, true_repeats=None, false_repeats=None) -> dict:
    """A TRUTH-VALUE ATTRIBUTION round: the responses to K_T distinct always-TRUE clauses, K_F distinct
    always-FALSE clauses, a byte-identical repeat of each, and the benign baseline. The repeats default to
    copies (a DETERMINISTIC origin); a dynamic / noisy origin passes DIFFERING repeats so the determinism
    hard-refute trips."""
    trues, falses = list(trues), list(falses)
    return {"trues": trues, "falses": falses,
            "true_repeats": [dict(r) for r in (trues if true_repeats is None else true_repeats)],
            "false_repeats": [dict(r) for r in (falses if false_repeats is None else false_repeats)],
            "baseline": baseline}


def _uniform(true, false, baseline, k: int = 4) -> dict:
    """A DETERMINISTIC origin whose response IS a function of the truth value: every always-true clause lands
    on ``true``, every always-false clause on ``false``."""
    return _round([dict(true) for _ in range(k)], [dict(false) for _ in range(k)], baseline)


# genuine fix / sanitizing WAF: every probe indistinguishable and baseline-shaped (SPRT refute, closure holds)
SILENT_ROUND = _uniform(NORMAL, NORMAL, NORMAL)
# still-vulnerable clean path: the TRUE cluster separates from a stable FALSE cluster (SPRT confirm)
SIGNAL_ROUND = _uniform(ROWS, NORMAL, NORMAL)
# a non-signal round whose baseline == the false cluster (drives the SPRT toward refute without tripping closure)
NONSIGNAL_ROUND = _uniform(NORMAL, NORMAL, NORMAL)
# blocking WAF: the metachar probes get an identical block page; the benign baseline is a normal 200
BLOCKED_ROUND = _uniform(BLOCK, BLOCK, NORMAL)
# structurally-dynamic page: EVERY probe differs in record COUNT (baseline != the falses → closure fails),
# INCLUDING every byte-identical repeat (varies with any input → the determinism hard-refute trips)
def _ilist(counts) -> list:
    return [R(200, '{"i": %s}' % list(range(1, c + 1))) for c in counts]


DYNAMIC_ROUND = _round(_ilist([3, 5, 7, 15]), _ilist([2, 4, 6, 14]), R(200, '{"i": [1]}'),
                       true_repeats=_ilist([9, 11, 13, 19]), false_repeats=_ilist([8, 10, 12, 18]))
CONFIRM_ROUNDS = [SIGNAL_ROUND, SIGNAL_ROUND, SIGNAL_ROUND]   # retained firing rounds for the positive control


def _vs(seed: str) -> str:
    """A long OPAQUE per-request token (ASP.NET ``__VIEWSTATE`` / rotating banner / big reflected nonce):
    structurally invisible (the JSON shape is unchanged) but LEXICALLY loud (distinct seeds → dissimilar
    bodies). Deterministic — no RNG."""
    return (seed * 200)[:600]


def _noisy(seed: str, rows: str) -> dict:
    return R(200, '{"vs": "%s", "results": %s}' % (_vs(seed), rows))


LEAK = '[{"id": 1, "leak": "admin@corp:HASHLEAK"}]'   # the TRUE-predicate leak an attacker reads bit-by-bit


def _noisy_vuln_round(n: int) -> dict:
    """A STILL-VULNERABLE origin (every true clause leaks the extra row) on a page with structurally-invisible
    per-request VIEWSTATE noise: the within-truth clusters do NOT agree and the byte-identical repeats carry
    fresh noise (→ the SPRT refutes / hard-refutes) while a true clause still SEPARATES from a false clause
    (the injection STILL fires) and baseline ≈ the falses structurally (WAF-closure passes). The red-pen's
    reproduced false-REMEDIATED shape — the attribution gate MUST catch it."""
    return _round([_noisy(f"t{n}{j}", LEAK) for j in range(4)],
                  [_noisy(f"a{n}{j}", "[]") for j in range(4)],
                  _noisy(f"c{n}", "[]"),
                  true_repeats=[_noisy(f"tr{n}{j}", LEAK) for j in range(4)],
                  false_repeats=[_noisy(f"ar{n}{j}", "[]") for j in range(4)])


NOISY_VULN_ROUNDS = [_noisy_vuln_round(0), _noisy_vuln_round(1), _noisy_vuln_round(2)]


_STABLE = "<html><body>" + ("<p>catalog item 0</p>" * 30)   # a large stable page the 1-bit leak hides in


def _leakpage(bit: int) -> str:
    return _STABLE + f"<span id=x>SECRET_BIT={bit}</span></body></html>"


def _subthreshold_round() -> dict:
    """A STILL-EXPLOITABLE 1-bit boolean channel: true/false differ by a single deterministic byte
    (``SECRET_BIT=1`` vs ``=0``) in a large page → ~99.85% lexically similar, BELOW the fuzzy SPRT thresholds
    (lexical 0.10 / length 0.05) → SPRT refutes, false pair stable, closure passes. An attacker reads the DB
    bit-by-bit with exact comparison. Only a ZERO-tolerance attribution check catches it (red-pen BLOCK-B)."""
    return _uniform(R(200, _leakpage(1)), R(200, _leakpage(0)), R(200, _leakpage(0)))


SUBTHRESHOLD_ROUNDS = [_subthreshold_round(), _subthreshold_round(), _subthreshold_round()]

# a 200-STATUS block page: same status as the baseline (so a status-ONLY closure "holds") but structurally
# different (so the protocol-fixed {status,structural} closure catches it) — the re-check #2 weak-disc probe.
BLOCK200 = R(200, "<html><body>Request blocked by WAF</body></html>")
BLOCK200_ROUND = _uniform(BLOCK200, BLOCK200, NORMAL)


def _RT(body: str) -> dict:                     # a probe body captured at the truncation cap (a prefix only)
    return {"status": 200, "body": body, "truncated": True}


# a round whose observed prefixes are IDENTICAL (would be REMEDIATED in-window) but every body was TRUNCATED —
# a boolean leak in the untruncated tail would be invisible, so closure cannot be attributed (red-pen R2 BLOCK).
TRUNCATED_ROUND = _uniform(_RT("<baseline/>"), _RT("<baseline/>"), _RT("<baseline/>"))


class FakeDifferentialAdapter:
    """A configurable differential ``LiveTargetAdapter``. ``rounds`` are emitted per trial (cyclically); the
    positive control returns RETAINED confirming rounds so the SAME boolean oracle still CONFIRMS. Knobs drive
    the malformed-round (fail-closed) and freshness-echo cases."""

    def __init__(self, *, rounds, confirm_rounds=None, nonce_echoed=True, malformed_at=None,
                 identity=None, bug_class=BUG, reflect_challenge=False):
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
        self._reflect_challenge = reflect_challenge   # R1-PR2: echo the run challenge into the true response
        self.id_calls = 0

    def identity_sample(self):
        self.id_calls += 1
        return dict(self._identity)

    def run_positive_control(self, *, challenge, auth):
        rounds = [dict(r) for r in self._confirm_rounds]
        # determinism pre-filter derived from the ONE identical request the retained rounds repeat
        # (falses[0] + its byte-identical repeat) — the positive control clears the same screen a fresh mint
        # does, and is held to the SAME truth-value attribution bar by the oracle itself.
        baseline = [r[k][0] for r in rounds for k in ("falses", "false_repeats")
                    if isinstance(r.get(k), list) and r[k]]
        ctx = {"bug_class": self.bug_class, "probe_rounds": rounds,
               "discriminator": dict(BOOL_DISC), "false_baseline_samples": baseline}
        return ControlObservation(reachable=True, channel_alive=True, oracle_context=ctx,
                                  definition_digest="sha256:control")

    def run_exploit_trial(self, *, challenge, trial_index, auth):
        if self._malformed_at is not None and trial_index == self._malformed_at:
            # §8 case 10 — one probe fetch failed → the WHOLE round is invalid (fail-closed; the driver must
            # NOT let boolean_inference silently continue past it).
            return TrialObservation(reachable=True, valid=False, oracle_context=None,
                                    invalid_reason="one matched-decoy probe fetch failed (simulated)")
        spec = self._rounds[trial_index % len(self._rounds)]
        ctx = {k: (dict(v) if isinstance(v, dict) else [dict(x) for x in v] if isinstance(v, list) else v)
               for k, v in spec.items()}
        if self._reflect_challenge:
            # R1-PR2: reflect the fresh challenge in EVERY SIGNAL-BEARING (true-cluster) response — clause AND
            # its byte-identical repeat, or the repeat would diverge and hard-refute — as a live app would when
            # the injected input is echoed. Earns F2 (the sink was exercised this run, not a replay).
            for arm in ("trues", "true_repeats"):
                ctx[arm] = [{**t, "body": f'{t.get("body", "")} <!--{challenge}-->'} for t in ctx[arm]]
        return TrialObservation(reachable=True, valid=True, oracle_context=ctx,
                                freshness_level=Freshness.F1_TARGET_ECHOES, nonce_echoed=self._nonce_echoed)


def _identity_att(policy=None, not_after=9_000):
    return sign_identity_attestation(OWNER, engagement=ENG, policy=(policy or POLICY), not_after=not_after)


def _run(adapter, *, policy=ProvePolicy(), rate_limit=10, pop_challenge="pop-1",
         requested_min_freshness=None):
    ident = _identity_att()
    cap = sign_capability(OWNER, engagement=ENG, identity_digest=identity_digest(ident),
                          class_allowlist=[adapter.bug_class], not_before=0, not_after=9_000,
                          rate_limit=rate_limit, revocation_id="rev-1", audience=WIELDER.public_key_b64)
    wp = prove_wielder(WIELDER, challenge=pop_challenge, capability=cap)
    return prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wp,
        trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, finding_id="boolsqli-1",
        original_certificate_digest="sha256:orig", signers=SIGNERS, now=NOW, run_id="run-1",
        pop_challenge=pop_challenge, freshness_nonce="fresh-nonce-xyz", policy=policy,
        requested_min_freshness=requested_min_freshness)


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


# ============================ R1-PR2 — differential F2 freshness (STILL_VULNERABLE only) ====================
def test_r1pr2_firing_with_reflected_challenge_earns_f2():
    # §5 — a differential FIRING whose signal-bearing (true) responses reflect the fresh challenge was exercised
    # THIS run → STILL_VULNERABLE at F2 (not the F1 the error-signature-only gate used to cap a boolean firing to).
    out = _run(FakeDifferentialAdapter(rounds=[SIGNAL_ROUND, SIGNAL_ROUND, SIGNAL_ROUND], reflect_challenge=True))
    assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED, out
    assert out.achieved_freshness == Freshness.F2_PATH_TRAVERSED, out


def test_r1pr2_firing_without_reflected_challenge_stays_f1():
    # a blind firing that does NOT reflect the fresh marker stays honestly F1 (the conservative floor).
    out = _run(FakeDifferentialAdapter(rounds=[SIGNAL_ROUND, SIGNAL_ROUND, SIGNAL_ROUND], reflect_challenge=False))
    assert out.state == State.STILL_VULNERABLE, out
    assert out.achieved_freshness == Freshness.F1_TARGET_ECHOES, out


def test_r1pr2_f2_demanded_reflected_firing_passes_the_floor():
    # a caller REQUESTING F2 is satisfied by a reflected firing → STILL_VULNERABLE@F2, not INCONCLUSIVE.
    out = _run(FakeDifferentialAdapter(rounds=[SIGNAL_ROUND, SIGNAL_ROUND, SIGNAL_ROUND], reflect_challenge=True),
               requested_min_freshness=Freshness.F2_PATH_TRAVERSED)
    assert out.state == State.STILL_VULNERABLE and out.achieved_freshness == Freshness.F2_PATH_TRAVERSED, out


def test_r1pr2_static_echo_marker_does_not_earn_f2():
    # red-pen parity note — the marker must be in the DISCRIMINATING bytes (present in EVERY `trues[i]`,
    # ABSENT from every `falses[j]`), the boolean analog of the error-signature "in the matched signature
    # line". A static header echoed into EVERY probe is NOT attributable to the firing → stays F1.
    from vigil_integration.remediation.prove_driver import _challenge_in_firing_differential as _f

    def _r(true_bodies, false_bodies):
        return {"trues": [{"body": b} for b in true_bodies], "falses": [{"body": b} for b in false_bodies]}

    assert _f("CH", [_r(["rows <!--CH-->"] * 3, ["base"] * 3)]) is True                    # true-cluster only
    assert _f("CH", [_r(["rows <!--CH-->"] * 3, ["base <!--CH-->"] * 3)]) is False         # static echo
    assert _f("CH", [_r(["rows"] * 3, ["base <!--CH-->"] * 3)]) is False                   # false-only
    # one un-marked TRUE clause is enough to drop back to F1 (conservative: EVERY true must carry it)
    assert _f("CH", [_r(["rows <!--CH-->", "rows <!--CH-->", "rows"], ["base"] * 3)]) is False


def test_r1pr2_f2_demanded_unreflected_firing_is_inconclusive():
    # a caller REQUESTING F2 over a firing that only reaches F1 (no reflection) is enforced → INCONCLUSIVE, never
    # a silently-downgraded STILL_VULNERABLE@F1 (downgrade resistance, parity with the error-signature floor).
    out = _run(FakeDifferentialAdapter(rounds=[SIGNAL_ROUND, SIGNAL_ROUND, SIGNAL_ROUND], reflect_challenge=False),
               requested_min_freshness=Freshness.F2_PATH_TRAVERSED)
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS, out
    assert out.state != State.STILL_VULNERABLE


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
    assert "as observed through this edge" in ev["residual_disclosure"].lower()   # not a clean code fix
    # with NO origin re-drive configured (R2), the verdict is honestly EDGE-ONLY — a-sanitize residual OPEN.
    assert ev["origin_confirmed"] is False and ev["origin_redrive"] == "not_attempted"
    assert "edge-only" in out.detail.lower()
    # the cert asserts NOTHING stronger than origin_reached — no "clean_fix"/"code_fixed" claim field exists
    assert "clean_fix" not in ev and "code_fixed" not in ev


def test_case6_dynamic_page_is_not_a_false_still_vulnerable():
    # §8.6 — every probe differs in record COUNT. false_a ≠ false_b trips the per-round dynamic-page control →
    # non-signal → SPRT refutes; but true still SEPARATES from false_a (across=True) → the attribution gate fires
    # first → INCONCLUSIVE. NOT STILL_VULNERABLE (the control absorbed the noise) and — critically — NOT a false
    # REMEDIATED (the refute is unattributable to a fix).
    out = _run(FakeDifferentialAdapter(rounds=[DYNAMIC_ROUND, DYNAMIC_ROUND, DYNAMIC_ROUND]))
    assert out.state != State.STILL_VULNERABLE
    assert out.state == State.INCONCLUSIVE and out.state != State.REMEDIATED, out
    assert out.reason_code == Reason.CHANNEL_NOISE_UNATTRIBUTABLE, out


def test_dynamic_page_noise_over_live_vuln_is_not_remediated():
    # RED-PEN BLOCK regression — the reproduced false REMEDIATED. A STILL-VULNERABLE origin (true leaks a row
    # every round) on a page with structurally-invisible per-request __VIEWSTATE noise makes false_a != false_b
    # (within_same tripped) → SPRT REFUTES, and baseline ≈ false_a structurally → WAF-closure PASSES. Pre-fix this
    # minted REMEDIATED over a live-leaking origin. The attribution gate (across must be False = genuine closure)
    # catches that across=True (the injection still fires) → INCONCLUSIVE / CHANNEL_NOISE_UNATTRIBUTABLE, NEVER
    # REMEDIATED. This is NOT the disclosed a-sanitize residual — there is no interposer; it is the raw vuln app.
    out = _run(FakeDifferentialAdapter(rounds=NOISY_VULN_ROUNDS))
    assert out.state != State.REMEDIATED, out
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.CHANNEL_NOISE_UNATTRIBUTABLE, out


def test_subthreshold_boolean_channel_is_not_remediated():
    # RED-PEN BLOCK-B — a still-EXPLOITABLE 1-bit boolean channel (true/false differ by a single deterministic
    # byte in a large page, ~99.85% similar) is BELOW the fuzzy SPRT thresholds → SPRT refutes + closure passes.
    # Pre-fix the fuzzy attribution recompute read across=False → REMEDIATED. The ZERO-tolerance attribution disc
    # catches the 1-byte separation → across=True → INCONCLUSIVE, never REMEDIATED.
    out = _run(FakeDifferentialAdapter(rounds=SUBTHRESHOLD_ROUNDS))
    assert out.state != State.REMEDIATED, out
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.CHANNEL_NOISE_UNATTRIBUTABLE, out


def test_truncated_observation_is_not_remediated():
    # RED-PEN R2 BLOCK-1 — a >8 KB response captured at the truncation cap: even if the observed prefixes are
    # identical (across=False IN-WINDOW), a boolean leak in the untruncated TAIL is invisible, so channel-closure
    # cannot be attributed over a bounded window → INCONCLUSIVE / OBSERVATION_TRUNCATED, NEVER REMEDIATED.
    out = _run(FakeDifferentialAdapter(rounds=[TRUNCATED_ROUND, TRUNCATED_ROUND, TRUNCATED_ROUND]))
    assert out.state != State.REMEDIATED, out
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.OBSERVATION_TRUNCATED, out


def test_verifier_demotes_a_signed_across_true_remediated_cert():
    # RED-PEN BLOCK-A — the attribution gate must live at RE-EXECUTION too, or the veracity firewall cannot
    # DEMOTE a false-REMEDIATED cert (invariant 3: re-execution can only demote). Model a cert the PRE-FIX minter
    # (no attribution gate) would have signed: a genuine REMEDIATED cert whose judged_rounds are swapped for a
    # still-vulnerable across=True set, then RE-SIGNED with the trusted governance key. verify_prove_certificate
    # MUST now reject it via the attribution re-check — not attest a live-leaking origin as remediated.
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND]))
    assert out.state == State.REMEDIATED
    cert = out.certificate
    ok_before, _ = verify_prove_certificate(cert, signer_pubkeys=PUBKEYS)
    assert ok_before                                        # the genuine cert verifies
    for across_true_rounds in (NOISY_VULN_ROUNDS, SUBTHRESHOLD_ROUNDS):
        tampered = {k: v for k, v in cert.items() if k != "signer"}
        tampered = {**tampered, "evidence": {**tampered["evidence"],
                    "differential": {**tampered["evidence"]["differential"],
                                     "judged_rounds": across_true_rounds}}}
        tampered["signer"] = {"key_id": "gov0", "signature": sign(OWNER.private_key_b64,
                                                                  _cert_signing_bytes(tampered))}
        ok, reason = verify_prove_certificate(tampered, signer_pubkeys=PUBKEYS)
        assert not ok, f"verifier attested an across=True (still-open) cert: {reason}"
        # the still-open rounds are demoted EITHER by the determinism gate (NOISY_VULN — an identical repeat
        # diverges, so the rounds do not re-execute to a decisive refute) OR by the zero-tolerance attribution
        # re-check (SUBTHRESHOLD — a deterministic 1-bit leak: true still separates from false_a). Both demote.
        r = reason.lower()
        assert ("attribution re-check" in r) or ("decisive sprt refute" in r) or ("deterministic" in r), reason


def test_verifier_ignores_a_weakened_cert_supplied_closure_discriminator():
    # RED-PEN re-check #2 hardening — the verifier re-executes with PROTOCOL-FIXED discriminators, IGNORING any
    # cert-supplied ones. A signed cert carrying real 200-block-page rounds (structurally != baseline) plus a
    # WEAKENED closure_discriminator=["status"] (dropping structural, so a status-only closure would "hold") must
    # NOT re-verify as REMEDIATED — the fixed {status,structural} closure catches the structural divergence.
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND]))
    assert out.state == State.REMEDIATED
    cert = out.certificate
    tampered = {k: v for k, v in cert.items() if k != "signer"}
    diff = {**tampered["evidence"]["differential"], "judged_rounds": [BLOCK200_ROUND, BLOCK200_ROUND, BLOCK200_ROUND],
            "closure_discriminator": {"dimensions": ["status"], "expect": "same"}}   # weakened by the producer
    tampered = {**tampered, "evidence": {**tampered["evidence"], "differential": diff}}
    tampered["signer"] = {"key_id": "gov0",
                          "signature": sign(OWNER.private_key_b64, _cert_signing_bytes(tampered))}
    ok, reason = verify_prove_certificate(tampered, signer_pubkeys=PUBKEYS)
    assert not ok, f"verifier trusted a weakened cert-supplied closure_discriminator: {reason}"
    assert "waf-closure" in reason.lower()


def test_freshness_floor_above_the_policy_is_enforced_not_ignored():
    # ISOLATION-PARITY red-pen: the error-signature path enforces a requested freshness ABOVE the floor
    # (prove_driver.py:601-608, spec §5). The differential channel is honestly F1 for BOTH verdicts in PR1, so a
    # caller REQUESTING F2 must get INCONCLUSIVE / INSUFFICIENT_FRESHNESS — never a silently-downgraded
    # REMEDIATED@F1. (Genuine-fix rounds that WOULD be REMEDIATED at the F1 floor.)
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND]),
               requested_min_freshness=Freshness.F2_PATH_TRAVERSED)
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS, out
    assert out.state != State.REMEDIATED
    # control: at the F1 floor the SAME rounds ARE remediated (so the guard, not the rounds, produced INCONCLUSIVE).
    ctrl = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND]))
    assert ctrl.state == State.REMEDIATED


def test_degenerate_adapter_clauses_are_rejected_at_construction():
    # §8.5 / red-pen: identical or challenge-only-differing clauses can never separate true from false (a
    # trivial refute → a false REMEDIATED over a vulnerable origin). The adapter must REFUSE them at construction.
    common = dict(executor=None, base_url="http://127.0.0.1/", endpoint_path="/", param="q", nonce_param="rc",
                  base_value="1")
    four_t = ("1' AND 1=1 -- {challenge}", "1' AND 'b'>'a' -- {challenge}",
              "1' AND 'ab' LIKE 'a%' -- {challenge}", "1' AND 9>4 -- {challenge}")
    four_f = ("1' AND 1=2 -- {challenge}", "1' AND 'a'>'b' -- {challenge}",
              "1' AND 'ab' LIKE 'z%' -- {challenge}", "1' AND 4>9 -- {challenge}")
    with pytest.raises(ValueError, match="IDENTICAL"):
        DifferentialHttpAdapter(**common, true_payload_templates=four_t,
                                false_payload_templates=(four_t[0],) + four_f[1:])
    with pytest.raises(ValueError, match="ONLY in the .challenge. marker"):
        # raw templates DIFFER (challenge inside the predicate vs in the comment) but are equal once the
        # {challenge} marker is stripped → the ONLY difference is the inert nonce, which must not flip the boolean.
        DifferentialHttpAdapter(
            **common,
            true_payload_templates=("1' AND SUBSTR(x,1,1)='{challenge}' -- z",) + four_t[1:],
            false_payload_templates=("1' AND SUBSTR(x,1,1)='' -- z{challenge}",) + four_f[1:])
    # TRUTH-VALUE ATTRIBUTION floor: below the oracle's CONFIRM floor of 4 distinct clauses per truth value
    # an adapter could never reach STILL_VULNERABLE (every round is a non-signal), so it would answer
    # "refute" for a live-vulnerable origin — refused loudly at construction instead.
    with pytest.raises(ValueError, match="4 DISTINCT"):
        DifferentialHttpAdapter(**common, true_payload_templates=four_t[:3],
                                false_payload_templates=four_f)
    # duplicates are not independent draws either
    with pytest.raises(ValueError, match="duplicate clauses"):
        DifferentialHttpAdapter(**common, true_payload_templates=four_t[:3] + (four_t[0],),
                                false_payload_templates=four_f)
    # genuinely data-dependent, shape-varied clause SETS are ACCEPTED.
    ok = DifferentialHttpAdapter(**common, true_payload_templates=_TRUE_TEMPLATES,
                                 false_payload_templates=_FALSE_TEMPLATES)
    assert ok.bug_class == "boolean_sqli"


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


# ============================ REAL DifferentialHttpAdapter over a stdlib loopback origin ============================
# Exercises the ACTUAL probe path the fake bypasses: _probe_url build, gated_fetch through a real HttpExecutor
# (charter/scope gate), fail-closed round assembly, nonce reflection. The origin reflects ONLY the rc nonce (never
# the q payload), so a FIXED origin returns identical bodies for all four probes (across=False → REMEDIATED); a
# VULNERABLE origin materialises a row for the TRUE predicate (1=1) only (across=True, false stable → CONFIRM).
_REAL_ENG = "boolreal"
# K_T = K_F = 4 DISTINCT clauses per truth value, metacharacter-identical in class and — the point —
# varying in COMPARISON SHAPE (`=`, `>`, `LIKE`, a compound), not merely in their literals. A set whose
# truth value tracks one SURFACE feature (e.g. "both operands are the same token") is partitionable by a
# regex WAF with no SQL engine at all; see the scanner-side lexical-filter regression.
# ...and at least one SQL-EVALUATED pair whose truth needs EVALUATION, not constant folding: shape
# diversity alone is partitionable by a complete constant folder with no SQL engine (measured 500/500).
_TRUE_TEMPLATES = ("1' AND 1=1 -- {challenge}", "1' AND 'b'>'a' -- {challenge}",
                   "1' AND 'ab' LIKE 'a%' -- {challenge}", "1' AND 9>4 AND 2<5 -- {challenge}",
                   "1' AND 1 IN (SELECT 1) -- {challenge}")
_FALSE_TEMPLATES = ("1' AND 1=2 -- {challenge}", "1' AND 'a'>'b' -- {challenge}",
                    "1' AND 'ab' LIKE 'z%' -- {challenge}", "1' AND 4>9 AND 2<5 -- {challenge}",
                    "1' AND 1 IN (SELECT 2) -- {challenge}")
_REAL_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Loopback test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
"""


_ORIGIN_DB = sqlite3.connect(":memory:", check_same_thread=False)
_ORIGIN_DB.execute("CREATE TABLE items(id INTEGER, sku TEXT)")
_ORIGIN_DB.execute("INSERT INTO items VALUES(1, '1')")
_ORIGIN_DB_LOCK = threading.Lock()


def _predicate_is_true(qv: str) -> bool:
    """A REAL string-concatenated sqlite3 sink, so the origin EVALUATES the injected clause and answers
    its TRUTH VALUE rather than a payload substring. That is what lets the K_T clauses — which vary in
    COMPARISON SHAPE, not only in their literals — all land on the same response."""
    with _ORIGIN_DB_LOCK:
        try:
            return bool(_ORIGIN_DB.execute(
                "SELECT count(*) FROM items WHERE sku = '" + qv + "'").fetchone()[0])
        except sqlite3.Error:
            return False


class _Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep the test output quiet
        pass

    def do_GET(self):  # noqa: N802
        self.server.hits += 1                        # count connections that actually landed (scope-gate proof)
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        qv = (q.get("q") or [""])[0]
        rc = (q.get("rc") or [""])[0]
        # A still-vulnerable origin EVALUATES the injected comparison → a TRUE predicate leaks an extra row;
        # every FALSE predicate and the benign baseline do not. A FIXED origin ignores the injection entirely.
        # The response reflects ONLY the rc nonce (freshness) — NEVER the q payload — mirroring a real app's
        # output channel, so all K_T true clauses land on ONE body and all K_F false clauses on another.
        leaks = self.server.vulnerable and _predicate_is_true(qv)
        if self.server.big_tail:
            # a >8 KB response whose boolean leak lands in the TAIL (past the 8 KiB capture cap). The rc nonce is
            # in the head (so freshness echoes); the leak marker `z` is past ~9 KB of padding → truncated away.
            body = '{"echo":"%s","pad":"%s","z":"%s"}' % (rc, "A" * 9000, ("LEAK" if leaks else "____"))
        else:
            rows = '[{"id": 1, "leak": "HASHLEAK"}]' if leaks else "[]"
            body = '{"results": %s, "echo": "%s"}' % (rows, rc)
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _OriginServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start_origin(*, vulnerable: bool, big_tail: bool = False, host: str = "127.0.0.1") -> _OriginServer:
    srv = _OriginServer((host, 0), _Origin)
    srv.vulnerable = vulnerable  # type: ignore[attr-defined]
    srv.big_tail = big_tail      # type: ignore[attr-defined]
    srv.hits = 0                 # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture()
def real_gated(tmp_path, monkeypatch):
    """A throwaway CRUCIBLE tree so the executor's scope gate admits 127.0.0.1 (mirrors test_reprove)."""
    from framework.v2.common import paths as _paths
    targets = tmp_path / "targets"
    (targets / _REAL_ENG).mkdir(parents=True)
    (targets / _REAL_ENG / "charter.md").write_text(_REAL_CHARTER.format(slug=_REAL_ENG), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")
    return tmp_path


def _real_adapter(base_url: str) -> DifferentialHttpAdapter:
    from framework.v2.agents import HttpExecutor
    # request_budget sized for the TRUTH-VALUE ATTRIBUTION round: min_valid_trials * (1 + 2*K_T + 2*K_F)
    # probes for the EDGE leg and the same again for the R2 origin re-drive, plus the positive control. The
    # HttpExecutor default (100) is below that at K_T = K_F = 4 — the caller owns this sizing.
    executor = HttpExecutor(engagement_slug=_REAL_ENG, base_url=base_url, prompt_callback=lambda *_a: False,
                            request_budget=400)
    return DifferentialHttpAdapter(
        executor=executor, base_url=base_url, endpoint_path="/search", param="q", nonce_param="rc",
        base_value="1", true_payload_templates=_TRUE_TEMPLATES, false_payload_templates=_FALSE_TEMPLATES,
        original_firing_rounds=CONFIRM_ROUNDS, engagement=_REAL_ENG)


def _run_real(adapter):
    ident = sign_identity_attestation(OWNER, engagement=_REAL_ENG, policy={"host": ["127.0.0.1"]}, not_after=9_000)
    cap = sign_capability(OWNER, engagement=_REAL_ENG, identity_digest=identity_digest(ident),
                          class_allowlist=["boolean_sqli"], not_before=0, not_after=9_000, rate_limit=20,
                          revocation_id="rev-r", audience=WIELDER.public_key_b64)
    wp = prove_wielder(WIELDER, challenge="pop-r", capability=cap)
    return prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wp,
        trusted_owner_pubkey=OWNER.public_key_b64, engagement=_REAL_ENG, finding_id="boolsqli-real",
        original_certificate_digest="sha256:orig", signers=SIGNERS, now=NOW, run_id="run-r",
        pop_challenge="pop-r", freshness_nonce="fresh-r", policy=ProvePolicy())


def test_real_adapter_fixed_origin_is_remediated(real_gated):
    srv = _start_origin(vulnerable=False)
    try:
        out = _run_real(_real_adapter(f"http://127.0.0.1:{srv.server_address[1]}/"))
        assert out.state == State.REMEDIATED and out.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS, out
        ev = out.certificate["evidence"]["differential"]
        assert ev["origin_reached"] is True and ev["channel_closed"] is True
        ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
        assert ok
    finally:
        srv.shutdown(); srv.server_close()


def test_real_adapter_vulnerable_origin_is_still_vulnerable(real_gated):
    srv = _start_origin(vulnerable=True)
    try:
        out = _run_real(_real_adapter(f"http://127.0.0.1:{srv.server_address[1]}/"))
        assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED, out
        assert out.state != State.REMEDIATED
    finally:
        srv.shutdown(); srv.server_close()


# ============================ R2 — direct-to-origin re-drive (closes the a-sanitize residual) ================
def _real_origin_adapter(edge_url: str, *, origin_ip: str, origin_port: int) -> DifferentialHttpAdapter:
    """A real adapter whose EDGE is ``edge_url`` and whose direct-to-origin re-drive targets ``origin_ip:port``
    with the Host pinned to the loopback (the origin server ignores Host; the scope gate matches the URL host)."""
    from framework.v2.agents import HttpExecutor
    executor = HttpExecutor(engagement_slug=_REAL_ENG, base_url=edge_url, prompt_callback=lambda *_a: False,
                            request_budget=400)
    return DifferentialHttpAdapter(
        executor=executor, base_url=edge_url, endpoint_path="/search", param="q", nonce_param="rc",
        base_value="1", true_payload_templates=_TRUE_TEMPLATES, false_payload_templates=_FALSE_TEMPLATES,
        original_firing_rounds=CONFIRM_ROUNDS, engagement=_REAL_ENG,
        origin_ip=origin_ip, origin_port=origin_port, origin_host="127.0.0.1")


def test_r2_sanitizing_edge_over_vulnerable_origin_is_demoted(real_gated):
    # THE R2 HEADLINE: the EDGE sanitizes (all probes inert → the edge path refutes → REMEDIATED-at-edge), but
    # the ORIGIN behind it is still vulnerable → the direct-to-origin re-drive (Host pinned, edge bypassed) FIRES
    # → DEMOTE to STILL_VULNERABLE. R2 catches the sanitizer the edge-only path (a-sanitize residual) could not.
    edge = _start_origin(vulnerable=False)          # a sanitizing edge: baseline for everything
    origin = _start_origin(vulnerable=True)         # the still-vulnerable origin behind it
    try:
        edge_url = f"http://127.0.0.1:{edge.server_address[1]}/"
        out = _run_real(_real_origin_adapter(edge_url, origin_ip="127.0.0.1",
                                             origin_port=origin.server_address[1]))
        assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED, out
        assert out.state != State.REMEDIATED
        assert out.certificate["evidence"]["differential"]["origin_redrive"] == "fired"
    finally:
        edge.shutdown(); edge.server_close(); origin.shutdown(); origin.server_close()


def test_r2_clean_origin_is_origin_confirmed_remediated(real_gated):
    # both the edge and the origin are clean → the direct-to-origin re-drive stays silent + closed →
    # origin_confirmed REMEDIATED (the a-sanitize residual is RULED OUT for this finding). The signed cert
    # re-executes INCLUDING the origin rounds (the origin upgrade is mirrored at re-execution).
    edge = _start_origin(vulnerable=False)
    origin = _start_origin(vulnerable=False)
    try:
        edge_url = f"http://127.0.0.1:{edge.server_address[1]}/"
        out = _run_real(_real_origin_adapter(edge_url, origin_ip="127.0.0.1",
                                             origin_port=origin.server_address[1]))
        assert out.state == State.REMEDIATED, out
        ev = out.certificate["evidence"]["differential"]
        assert ev["origin_confirmed"] is True and ev["origin_redrive"] == "confirmed", ev
        assert isinstance(ev.get("origin_rounds"), list) and ev["origin_rounds"]
        # BLOCK-2: origin_confirmed rules out a sanitizing EDGE but NOT the forgeable/bounded response channel —
        # the byte-forgery + observation-window frontier must STILL be disclosed (not a clean bill of health).
        rd = ev["residual_disclosure"].lower()
        assert "byte-forgery" in rd and "observation" in rd, rd
        ok, reason = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
        assert ok and "origin_confirmed" in reason.lower(), reason
    finally:
        edge.shutdown(); edge.server_close(); origin.shutdown(); origin.server_close()


def test_r2_origin_leak_past_capture_cap_is_not_origin_confirmed(real_gated):
    # RED-PEN R2 BLOCK-1 end-to-end — the ORIGIN returns a >8 KB body whose boolean leak is in the TAIL (past the
    # 8 KiB capture cap). The executor flags the body truncated → the driver REFUSES origin_confirmed (edge-only),
    # never a false "a-sanitize ruled out" over a still-leaking origin. Exercises the executor→adapter→driver flag.
    edge = _start_origin(vulnerable=False)
    origin = _start_origin(vulnerable=True, big_tail=True)      # leaks past the capture window
    try:
        edge_url = f"http://127.0.0.1:{edge.server_address[1]}/"
        out = _run_real(_real_origin_adapter(edge_url, origin_ip="127.0.0.1",
                                             origin_port=origin.server_address[1]))
        # never origin_confirmed: either edge-only REMEDIATED (origin truncated → inconclusive) or, if the leak
        # were visible in-window, STILL_VULNERABLE. In NO case a false a-sanitize-ruled-out.
        if out.state == State.REMEDIATED:
            assert out.certificate["evidence"]["differential"]["origin_confirmed"] is False, out
        else:
            assert out.state == State.STILL_VULNERABLE, out
    finally:
        edge.shutdown(); edge.server_close(); origin.shutdown(); origin.server_close()


def test_r2_reachable_out_of_scope_origin_is_refused_by_the_gate(real_gated):
    # FINDING-3 — the true scope control: a REACHABLE origin on 127.0.0.2 that the charter does NOT scope (it
    # lists only 127.0.0.1). The gate must REFUSE the origin re-drive (0 connections landed), not merely time out
    # → edge-only REMEDIATED. Distinguishes a scope refusal from an unreachable-IP timeout.
    edge = _start_origin(vulnerable=False)
    origin = _start_origin(vulnerable=True, host="127.0.0.2")   # reachable, but OUT of charter scope
    try:
        edge_url = f"http://127.0.0.1:{edge.server_address[1]}/"
        out = _run_real(_real_origin_adapter(edge_url, origin_ip="127.0.0.2",
                                             origin_port=origin.server_address[1]))
        assert out.state == State.REMEDIATED, out
        ev = out.certificate["evidence"]["differential"]
        assert ev["origin_confirmed"] is False and ev["origin_redrive"] == "unavailable", ev
        assert origin.hits == 0, f"scope gate leaked {origin.hits} connections to an out-of-scope origin"
    finally:
        edge.shutdown(); edge.server_close(); origin.shutdown(); origin.server_close()


def test_r2_origin_out_of_scope_stays_edge_only(real_gated):
    # the origin IP is NOT in the charter scope → the scope gate REFUSES the origin re-drive → edge-only
    # REMEDIATED with the a-sanitize residual STILL OPEN. R2 fail-closes; it NEVER bypasses the gate to reach a
    # raw IP. (203.0.113.7 is TEST-NET-3 documentation space, not in scope — the gate refuses before any send.)
    edge = _start_origin(vulnerable=False)
    try:
        edge_url = f"http://127.0.0.1:{edge.server_address[1]}/"
        out = _run_real(_real_origin_adapter(edge_url, origin_ip="203.0.113.7", origin_port=80))
        assert out.state == State.REMEDIATED, out
        ev = out.certificate["evidence"]["differential"]
        assert ev["origin_confirmed"] is False and ev["origin_redrive"] == "unavailable", ev
        assert "sanitiz" in ev["residual_disclosure"].lower()      # residual still open
    finally:
        edge.shutdown(); edge.server_close()


def test_verifier_demotes_a_false_origin_confirmed_cert():
    # R2 + R1b lesson — a signed cert claiming origin_confirmed whose ORIGIN rounds actually FIRE (across=True)
    # MUST be demoted by the offline verifier (the origin upgrade is re-executed, invariant 3: only demote).
    out = _run(FakeDifferentialAdapter(rounds=[SILENT_ROUND, SILENT_ROUND, SILENT_ROUND]))
    assert out.state == State.REMEDIATED
    cert = out.certificate
    tampered = {k: v for k, v in cert.items() if k != "signer"}
    diff = {**tampered["evidence"]["differential"], "origin_confirmed": True, "origin_redrive": "confirmed",
            "origin_rounds": NOISY_VULN_ROUNDS}                    # a still-firing origin (across=True)
    tampered = {**tampered, "evidence": {**tampered["evidence"], "differential": diff}}
    tampered["signer"] = {"key_id": "gov0",
                          "signature": sign(OWNER.private_key_b64, _cert_signing_bytes(tampered))}
    ok, reason = verify_prove_certificate(tampered, signer_pubkeys=PUBKEYS)
    assert not ok, f"verifier trusted a false origin_confirmed over a firing origin: {reason}"
    assert "origin" in reason.lower()
