"""TRUTHENOVATION R1 (PR1) — the DIFFERENTIAL (boolean-inference) remediation channel.

Two harnesses, both re-firing the REAL framework oracles (SPRT + WAF-closure), so a REMEDIATED verdict is
earned over the round bytes exactly as it would be over live bytes:

  * a FAKE-driven corpus that hands ``_prove_differential`` matched-decoy round bundles
    (``{true, false_a, false_b, baseline}``) — covering the verdict-determining §8 cases 1,2,3,4,6,7,10
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


def _vs(seed: str) -> str:
    """A long OPAQUE per-request token (ASP.NET ``__VIEWSTATE`` / rotating banner / big reflected nonce):
    structurally invisible (the JSON shape is unchanged) but LEXICALLY loud (distinct seeds → dissimilar
    bodies). Deterministic — no RNG."""
    return (seed * 200)[:600]


def _noisy(seed: str, rows: str) -> dict:
    return R(200, '{"vs": "%s", "results": %s}' % (_vs(seed), rows))


LEAK = '[{"id": 1, "leak": "admin@corp:HASHLEAK"}]'   # the TRUE-predicate leak an attacker reads bit-by-bit


def _noisy_vuln_round(n: int) -> dict:
    """A STILL-VULNERABLE origin (true leaks the extra row every round) on a page with structurally-invisible
    per-request VIEWSTATE noise: false_a != false_b (within_same tripped → SPRT refutes) while true != false_a
    (across=True → the injection STILL fires) and baseline ≈ false_a structurally (WAF-closure passes). The
    red-pen's reproduced false-REMEDIATED shape — the attribution gate MUST catch it."""
    return _round(true=_noisy(f"t{n}", LEAK), false_a=_noisy(f"a{n}", "[]"),
                  false_b=_noisy(f"b{n}", "[]"), baseline=_noisy(f"c{n}", "[]"))


NOISY_VULN_ROUNDS = [_noisy_vuln_round(0), _noisy_vuln_round(1), _noisy_vuln_round(2)]


_STABLE = "<html><body>" + ("<p>catalog item 0</p>" * 30)   # a large stable page the 1-bit leak hides in


def _leakpage(bit: int) -> str:
    return _STABLE + f"<span id=x>SECRET_BIT={bit}</span></body></html>"


def _subthreshold_round() -> dict:
    """A STILL-EXPLOITABLE 1-bit boolean channel: true/false differ by a single deterministic byte
    (``SECRET_BIT=1`` vs ``=0``) in a large page → ~99.85% lexically similar, BELOW the fuzzy SPRT thresholds
    (lexical 0.10 / length 0.05) → SPRT refutes, false pair stable, closure passes. An attacker reads the DB
    bit-by-bit with exact comparison. Only a ZERO-tolerance attribution check catches it (red-pen BLOCK-B)."""
    return _round(true=R(200, _leakpage(1)), false_a=R(200, _leakpage(0)),
                  false_b=R(200, _leakpage(0)), baseline=R(200, _leakpage(0)))


SUBTHRESHOLD_ROUNDS = [_subthreshold_round(), _subthreshold_round(), _subthreshold_round()]


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
        assert "attribution re-check" in reason.lower()


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
    with pytest.raises(ValueError, match="IDENTICAL"):
        DifferentialHttpAdapter(**common, true_payload_template="1' AND 1=1 -- {challenge}",
                                false_payload_template="1' AND 1=1 -- {challenge}")
    with pytest.raises(ValueError, match="ONLY in the .challenge. marker"):
        # raw templates DIFFER (challenge inside the predicate vs in the comment) but are equal once the
        # {challenge} marker is stripped → the ONLY difference is the inert nonce, which must not flip the boolean.
        DifferentialHttpAdapter(**common, true_payload_template="1' AND SUBSTR(x,1,1)='{challenge}' -- z",
                                false_payload_template="1' AND SUBSTR(x,1,1)='' -- z{challenge}")
    # a genuinely data-dependent pair is ACCEPTED (the predicate difference is independent of the challenge).
    ok = DifferentialHttpAdapter(**common,
                                 true_payload_template="1' AND SUBSTR(@@version,1,1)>'' -- {challenge}",
                                 false_payload_template="1' AND SUBSTR(@@version,1,1)>'~~~' -- {challenge}")
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


class _Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep the test output quiet
        pass

    def do_GET(self):  # noqa: N802
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        qv = (q.get("q") or [""])[0]
        rc = (q.get("rc") or [""])[0]
        # A still-vulnerable origin executes the TRUE predicate (1=1) → an extra row leaks; the FALSE predicate
        # (1=2) and the benign baseline do not. A FIXED origin ignores the injection entirely. The response
        # reflects ONLY the rc nonce (freshness) — NEVER the q payload — mirroring a real app's output channel.
        leaks = self.server.vulnerable and ("1=1" in qv) and ("1=2" not in qv)
        rows = '[{"id": 1, "leak": "HASHLEAK"}]' if leaks else "[]"
        raw = ('{"results": %s, "echo": "%s"}' % (rows, rc)).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _OriginServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start_origin(*, vulnerable: bool) -> _OriginServer:
    srv = _OriginServer(("127.0.0.1", 0), _Origin)
    srv.vulnerable = vulnerable  # type: ignore[attr-defined]
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
    executor = HttpExecutor(engagement_slug=_REAL_ENG, base_url=base_url, prompt_callback=lambda *_a: False)
    return DifferentialHttpAdapter(
        executor=executor, base_url=base_url, endpoint_path="/search", param="q", nonce_param="rc",
        base_value="1", true_payload_template="1' AND 1=1 -- {challenge}",
        false_payload_template="1' AND 1=2 -- {challenge}", original_firing_rounds=CONFIRM_ROUNDS,
        engagement=_REAL_ENG)


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
