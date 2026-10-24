"""
Gate-invariant TRIPWIRE (roadmap #2) — fail loudly the moment the two byte-identity guarantees drift.

The whole AEGIS discipline is that every append is additive and default-OFF, so `make gate` stays
byte-identical. Two things must never move without a deliberate, reviewed change:

  1. The unknown-class fallback ``verify.verifier._ALL_ORACLES`` is FROZEN to exactly the 15 pre-AEGIS
     OracleKind members. If a NEW oracle kind (AEGIS telemetry, the request-side parse-proof kinds, the
     k8s-posture kind, or a future one) ever leaks into it, every unknown-class benchmark finding would
     begin running that oracle and the serialized gate output would drift. This file hardcodes the
     exact 15 names so a drift fails with an explicit diff — not a silently-recomputed set.
     (``test_gate_byte_identical.py`` asserts the same count via set arithmetic; this is the
     name-pinned twin that survives even if the enum or the arithmetic is refactored.)

  2. The in-process benchmark tally is byte-identical: crucible tp=11, fp=0, fn=0, precision=recall=
     f1=1.0, 1836 requests, 11 findings reported — the exact row `make gate` prints and gates on.
     (Lane S moved ONLY the unsigned cost 1831 -> 1836: +5 PathProbe control fetches; see STAGE 3 below.)
     (TRUTHENOVATION-M1 #213 deliberately broadened the corpus 9->11 bugs — adding SSTI + host-header —
     and re-baselined the gate; the frozen row moved 9/853/9 -> 11/1069/11 with it.)

     The COST half of that row was re-baselined again, 1069 -> 1544 -> 1831, deliberately. The
     ACCURACY half did NOT move: 11/0/0 held through the change, and the signed
     ``eval/baselines/recall-accuracy-core.json`` still reproduces BYTE-IDENTICALLY (sha256
     01c1728c…) and still verifies against its pinned trust root — nothing signed was re-signed,
     because the request count is deliberately NOT in the signed accuracy bytes.

     WHY the cost moved. The corpus used to model boolean-blind SQLi at ``/users?name`` with two
     REGEXES over a `` OR ``-split string, which only understand LITERAL EQUALITY. Measured against
     the seven syntactically-varied always-TRUE/always-FALSE clause shapes a SOUND detector sends
     (``scanner.checks.boolean_clause_families``), exactly 1 of 7 partitioned the fixture and the
     other six collapsed onto the same 118-byte body. The only detector that fixture rewarded was
     the bare benign-vs-payload DIFFERENTIAL — the one separately measured minting High
     ``boolean_sqli`` at rate 1.0 against a static page behind a WAF tautology rule, on targets with
     NO DATABASE. So this row had been certifying that an UNSOUND oracle still fires. ``/users?name``
     is now a real sqlite3 engine with a concatenated WHERE clause (7 of 7 shapes partition), the
     gate scores it with the sound SPRT ``BooleanInferenceCheck``, and ``/users/safe`` is the
     parameterised twin that must never fire (0 of 7).

     STAGE 1 (this slice alone, 1069 -> 1544, +475 reported / +476 counted):
       +114  the NEW ``/users/safe`` twin becomes an 11th param surface, audited like the other
             safe controls (82 base + 32 library-boolean sends).
       -320  the 21 declarative library ``boolean_sqli`` DIFFERENTIAL entries are dropped from the
             gate roster: -32 on each of the 10 non-vulnerable param surfaces (on ``/users`` they
             already short-circuited at the first confirm, so 0 there).
       +682  the bare 2-send ``DifferentialCheck`` is replaced by the SPRT on all 11 param
             surfaces: +62 each = 8 determinism pre-gate sends + 2 SPRT rounds x 28 byte-identical
             probes (64), less the 2 sends the differential used.
       -----
       +476  counted; reported is +475 (see the offset rule below).
     The new sqlite3 fixture itself costs ZERO extra requests (``/users`` sat at 82 sends both
     before and after, with the detector held fixed).

     STAGE 2 (1544 -> 1831, +287 reported / +289 counted), two independent causes:
         +1  ``fix/audit-c-checks`` gives the file-signature check a BENIGN CONTROL request, spent
             only on a probe that would otherwise FIRE. The corpus fires it at exactly one place,
             so ``/file`` goes 139 -> 140 and nothing else moves.
       +288  the two DISCRIMINATING negative controls become the 12th and 13th param surfaces:
             ``/locations?city`` (a CRS-942130 tautology WAF rule over a static page) and
             ``/lookup?term`` (strict input validation over a static page), 144 sends each — the
             same per-surface cost as every other param surface in the corpus.
       -----
       +289  counted; reported is +287.
     THE OFFSET RULE, which holds at every stage: ``requests_sent`` runs 1 below the counted total
     per param SURFACE (it excludes one discovery fetch each). 12 counted-vs-reported at 10
     surfaces, 13 at 11, 15 at 13 — so a counted delta and a reported delta differ by exactly the
     number of surfaces added, and nothing else.

     WHERE THE SOUND DETECTOR LIVES, and why this file no longer names a gate-only roster. The
     benchmark used to build its own ``_GATE_CHECKS`` that swapped a local ``BooleanInferenceCheck``
     in for the bare ``BOOLEAN_SQLI`` differential. That override is gone: ``DEFAULT_CHECKS`` now
     carries ``scanner.checks.BOOLEAN_SQLI_SPRT``, parameter-identical to the local copy (same id,
     same family-0 clause sets, same ``n_max=6``), so the comprehension had become an element-wise
     IDENTITY map and the local check a duplicate. The gate now runs the SAME roster an operator's
     default scan runs, which is the stronger property — the corpus can no longer certify a
     detector that ships to nobody. The row did not move across that collapse: 11/0/0 at 1831,
     measured twice on each side.

     HONEST BOUND on what the default boolean detector covers: clause FAMILY 0 only (the
     single-quote string-literal breakout). The numeric and double-quote families cost +62
     requests per insertion point each and are not on the default path; the gated
     ``live/runtime_redrive.py::boolean_redrive`` drives all three. Recorded in
     docs/capability-matrix/evidence-branches.json as a limitation, not left implicit.

     WHY THE TWO NEW CONTROLS EXIST. A review BLOCKed the stage-1 slice: reverting its ENTIRE
     detector content still passed the gate, so the gate was not actually pinning the soundness the
     slice was for. ``/users/safe`` could not close that, because it refutes only a detector that
     fires ON IT and a payload-SHAPE reader does not (measured: the bare ``DifferentialCheck``
     confirms on ``/users`` and returns None on ``/users/safe``). ``/locations`` and ``/lookup`` are
     surfaces where the SHAPE is present and the INJECTION is not, so a bare differential SEES a
     channel (measured, both) and a sound detector must REFUSE (measured, both). Their assertions
     live in ``eval/tests/test_gate_corpus_controls.py`` and are POSITIVE about the refusal — the
     SPRT must be shown to have run full 7-TRUE/7-FALSE rounds and THEN declined, because "no
     finding" is also what a 404 or a disconnected route produces.

Colocated with ``test_gate_byte_identical.py`` under ``aegis/tests/`` so ``make test`` collects it.
"""

from __future__ import annotations

import pytest

from framework.v2.verify import verifier as V
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES

# The 15 pre-AEGIS oracle kinds — the ONLY members allowed in the frozen unknown-class fallback.
# Hardcoded by NAME so any rename/add/remove fails loudly with an explicit diff.
_FROZEN_15 = frozenset({
    "DIFFERENTIAL_RESPONSE", "ACHIEVED_STATE", "SIDE_EFFECT", "OOB_CALLBACK", "SANITIZER_SIGNAL",
    "TIMING", "BOOLEAN_INFERENCE", "REFLECTION_CONTEXT", "EVALUATION", "ERROR_SIGNATURE",
    "DOM_EXECUTION", "SERVICE_REACHABILITY", "TLS_WEAKNESS", "VERSION_RANGE", "POLICY_PATH",
})

# The additive kinds (4 AEGIS telemetry + 3 request-side parse-proof [sqli/cmdi/nosql] + 1 WS-3
# k8s-posture + 1 TRUTHENOVATION-T4 k8s-WORKLOAD-posture + 1 WS-B sso-assertion-forgery + 1 NW-1 saml-structural-forgery + 1 Wave-F1 cloud/CSPM
# achieved-state posture + 1 Wave-G3 service-mesh posture + 1 Phase-2 CI/CD posture + 1 Phase-2 mobile
# static-posture + 1 FORGE Domain 10 email-auth posture + 1 FORGE Domain 7 identity posture + 1 Slice-C3
# active-exposure + 1 BUILD-PLAN §E1 IMDS/metadata credential-capture + 1 §E5 exposed-secret validity + 1 §E3
# GCP SA impersonation) that MUST stay OUT of the frozen fallback — reachable only via their explicit
# BUG_CLASS_ORACLES rows.
_ADDITIVE = frozenset({
    "PROMPT_INJECTION", "SYSTEM_PROMPT_DISCLOSURE", "AUTOMATED_ACCESS", "CREDENTIAL_STUFFING",
    "SQL_INJECTION_BREAKOUT", "COMMAND_INJECTION_BREAKOUT", "NOSQL_INJECTION_BREAKOUT",
    # Request-side directory-traversal / LFI parse-proof — the request-side sibling of the three parse-proof
    # kinds above (keyed on the SAME `request_payload` ctx field no benchmark/scan finding carries), DISTINCT
    # from the response-side SIDE_EFFECT path_traversal/lfi leak-proof; never in the frozen fallback.
    "PATH_TRAVERSAL_BREAKOUT",
    # Request-side SSRF / XXE parse-proofs — the request-side siblings of the parse-proof kinds above (SAME
    # `request_payload` ctx field), the BLOCK-worthy UNAMBIGUOUS subset of the SSRF/XXE LEADs (cloud-metadata
    # host / dangerous scheme; a COMPLETE external-entity DOCTYPE). The softer cases stay LEADs. Never in the
    # frozen fallback — reachable only via their explicit `ssrf_attempt` / `xxe_attempt` rows.
    "SSRF_BREAKOUT", "XXE_BREAKOUT",
    "K8S_POSTURE",
    "K8S_WORKLOAD_POSTURE",
    "SSO_ASSERTION_FORGERY", "SAML_STRUCTURAL_FORGERY", "CLOUD_POSTURE", "MESH_POSTURE",
    "CICD_POSTURE", "MOBILE_POSTURE", "EMAIL_AUTH_POSTURE", "IDENTITY_POSTURE", "ACTIVE_EXPOSURE",
    "IMDS_CREDENTIAL_CAPTURE", "SECRET_CREDENTIAL_VALIDITY",
    # BUILD-PLAN §E3 GCP service-account impersonation + §E2 IAM privilege-escalation PRIMITIVE (the
    # strict-gain dual of POLICY_PATH reachability) — two additive kinds landed in parallel.
    "GCP_SA_IMPERSONATION", "IAM_ESCALATION_PRIMITIVE",
    # BUILD-PLAN §E4 TIER-2 K8s dangerous-VERB / default-SA RBAC verb-grant (the rule-PARSING sibling of the
    # TIER-1 K8S_WORKLOAD_POSTURE name-match oracle).
    "K8S_RBAC_VERB_GRANT",
    # W16-STD-5 client-side POSTURE-WEAKNESS kinds (constitution §V client-side classes: clickjacking /
    # CSRF / postMessage) — each proves a MISSING/WEAK defense, reachable ONLY via its explicit row keyed
    # on a `*_control` ctx field no benchmark/scan finding carries; never in the frozen fallback.
    "CLICKJACKING_POSTURE", "CSRF_POSTURE", "POSTMESSAGE_POSTURE",
    # Wave 2.2 client-side PROTOTYPE POLLUTION achieved-state kind (CWE-1321) — additive, reachable ONLY
    # via its `prototype_pollution` row keyed on a `proto_pollution` ctx field; never in the frozen fallback.
    "PROTOTYPE_POLLUTION",
    # Wave 2.4 CSP permissive-policy POSTURE kind (CWE-693/CWE-1021) — additive, reachable ONLY via its
    # `csp_posture` row keyed on a `csp_control` ctx field; never in the frozen fallback. (The achieved
    # csp_bypass class reuses DOM_EXECUTION and adds no kind.)
    "CSP_POSTURE",
    # Wave 3.2 SESSION FIXATION achieved-state kind (CWE-384) — its OWN dedicated kind (so editing its
    # differential body changes ONLY oracle_version(SESSION_FIXATION), never ACHIEVED_STATE), additive,
    # reachable ONLY via its `session_fixation` row keyed on a `session_fixation` ctx field; never in the
    # frozen fallback.
    "SESSION_FIXATION",
    # Wave 4.5 MFA BYPASS achieved-state kind (CWE-287/CWE-308) — its OWN dedicated kind (so editing its
    # differential body changes ONLY oracle_version(MFA_BYPASS), never ACHIEVED_STATE), additive, reachable
    # ONLY via its `mfa_bypass` row keyed on a `mfa_bypass` ctx field; never in the frozen fallback.
    "MFA_BYPASS",
    # Wave 4.3 PASSWORD-RESET / ACCOUNT-RECOVERY TOKEN INVARIANT kind (CWE-640/613/330) — its OWN dedicated
    # kind (so editing its reuse/collision body changes ONLY oracle_version(PASSWORD_RESET_INVARIANT), never
    # ACHIEVED_STATE), additive, reachable ONLY via its `password_reset_reuse` / `password_reset_collision`
    # rows keyed on a `password_reset_invariant` ctx field; never in the frozen fallback. (The cross-user reset
    # class reuses ACHIEVED_STATE and adds no kind; host-poisoning folds onto host_header_injection.)
    "PASSWORD_RESET_INVARIANT",
    # Wave 5.1 STATIC source-code RULE kind (the SAST bridge) — a re-runnable deterministic rule over RETAINED
    # SOURCE-CODE BYTES (the source-code sibling of the retained-artifact posture kinds). Additive, reachable
    # ONLY via its four `static_*` rows keyed on a `static_rule` ctx field no benchmark/scan finding carries;
    # never in the frozen fallback. Each mints a code-property FACT (never runtime exploitability).
    "STATIC_RULE",
    # M1.3 TLS CERTIFICATE VALIDITY kind — the presented leaf's validity window / identity / self-issuance,
    # re-derived from RETAINED DER at a RETAINED instant. Its OWN dedicated kind (so editing the validity
    # derivation changes ONLY oracle_version(CERTIFICATE_VALIDITY), never TLS_WEAKNESS), additive, reachable
    # ONLY via its `certificate_validity` row keyed on a `cert_validity` ctx field no benchmark/scan finding
    # carries; never in the frozen fallback. FACT-capable (an existential defect) but NOT clean-capable
    # (leaf-only, no chain).
    "CERTIFICATE_VALIDITY",
    # M-11.3 CREDENTIAL ACCEPTANCE kind — a target auth ACCEPTED a credential the operator-planted TEST policy
    # marks should-be-REJECTED, re-derived offline from a VIGIL-captured auth-attempt record. Its OWN dedicated
    # kind, additive, reachable ONLY via its `credential_acceptance` row keyed on a `credential_acceptance` ctx
    # field no benchmark/scan finding carries; never in the frozen fallback. hydra/john are LEAD proposers only;
    # the oracle REFUSES without the operator-planted test corpus (TEST-IDENTITIES-ONLY, no real secret read).
    "CREDENTIAL_ACCEPTANCE",
})


def test_all_oracles_fallback_is_exactly_the_frozen_15_by_name():
    got = {k.name for k in V._ALL_ORACLES}
    assert len(V._ALL_ORACLES) == 15, f"_ALL_ORACLES size drifted: {sorted(got)}"
    assert got == _FROZEN_15, (
        "the frozen unknown-class fallback membership drifted; "
        f"added={sorted(got - _FROZEN_15)} removed={sorted(_FROZEN_15 - got)}")
    # no accidental duplicate row bloated the tuple.
    assert len(V._ALL_ORACLES) == len(set(V._ALL_ORACLES))


def test_every_additive_oraclekind_is_excluded_from_the_fallback():
    frozen_names = {k.name for k in V._ALL_ORACLES}
    for name in _ADDITIVE:
        member = OracleKind[name]
        assert member not in V._ALL_ORACLES, f"{name} leaked into the frozen fallback"
        assert name not in frozen_names
    # the enum is exactly the 15 frozen + 32 additive = 47; a new frozen member (or a new additive one
    # not accounted for here) fails this, forcing an explicit review of the byte-identity impact.
    # (E3 GCP_SA_IMPERSONATION, E2 IAM_ESCALATION_PRIMITIVE and E4-TIER-2 K8S_RBAC_VERB_GRANT landed
    # additively: 35 -> 36 -> 37 -> 38; W16-STD-5 added the 3 client-side posture kinds: 38 -> 41;
    # Wave 2.2 added PROTOTYPE_POLLUTION (achieved-state, CWE-1321): 41 -> 42; Wave 2.4 added CSP_POSTURE
    # (permissive-policy posture, CWE-693/CWE-1021): 42 -> 43; Wave 3.2 added SESSION_FIXATION (achieved-state,
    # CWE-384, its own dedicated kind so ACHIEVED_STATE's oracle_version is untouched): 43 -> 44; Wave 4.5 added
    # MFA_BYPASS (achieved-state, CWE-287/CWE-308, its own dedicated kind so ACHIEVED_STATE's oracle_version is
    # untouched): 44 -> 45; Wave 4.3 added PASSWORD_RESET_INVARIANT (token reuse/non-expiry + deterministic
    # predictable-counter collision, CWE-640/613/330, its own dedicated kind so ACHIEVED_STATE's oracle_version
    # is untouched): 45 -> 46; Wave 5.1 added STATIC_RULE (the SAST bridge — a deterministic rule over retained
    # source-code bytes; four static_* classes, its own dedicated kind): 46 -> 47. M1.3 added
    # CERTIFICATE_VALIDITY (TLS leaf validity window/identity/self-issuance, its own dedicated kind so
    # TLS_WEAKNESS's oracle_version is untouched): 47 -> 48. M-11.3 added CREDENTIAL_ACCEPTANCE (a target auth
    # accepted a planted should-be-rejected credential, re-derived offline; its own dedicated kind, LEAD-proposer
    # tools only, refuses without the planted test corpus): 48 -> 49. The request-side PATH_TRAVERSAL_BREAKOUT
    # parse-proof (the request-side sibling of SQL/CMD/NOSQL break-out; keyed on `request_payload`, never in the
    # frozen fallback — the response-side path_traversal/lfi leak-proof stays a distinct SIDE_EFFECT class):
    # 49 -> 50. The request-side SSRF_BREAKOUT + XXE_BREAKOUT parse-proofs (the BLOCK-worthy unambiguous
    # subset of the SSRF/XXE LEADs — cloud-metadata host / dangerous scheme; a complete external-entity
    # DOCTYPE — keyed on `request_payload`, never in the frozen fallback; the softer cases stay LEADs and the
    # response-side/OOB proofs stay distinct classes): 50 -> 52.)
    assert len(OracleKind) == 52
    assert {k.name for k in OracleKind} == _FROZEN_15 | _ADDITIVE
    assert set(V._ALL_ORACLES) == set(OracleKind) - {OracleKind[n] for n in _ADDITIVE}


def test_unknown_class_falls_back_to_the_frozen_15_after_importing_aegis():
    import framework.v2.aegis  # noqa: F401  — importing AEGIS must not grow the fallback
    fallback = V.OracleVerifier().oracles_for("a_class_no_oracle_maps_to")
    assert fallback == V._ALL_ORACLES
    assert {k.name for k in fallback} == _FROZEN_15


def test_xxe_mapping_is_unchanged_and_adds_no_new_kind():
    """AEGIS emits in-band XXE as a request-side LEAD (never an inline block — the review proved a
    single inline exchange cannot soundly confirm it). The offensive ``xxe`` -> (OOB_CALLBACK,
    SIDE_EFFECT) mapping is UNCHANGED and both kinds are pre-existing frozen members, so nothing about
    XXE introduced a new OracleKind or touched the frozen fallback."""
    assert BUG_CLASS_ORACLES["xxe"] == (OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT)
    assert OracleKind.SIDE_EFFECT in V._ALL_ORACLES
    assert "SIDE_EFFECT" in _FROZEN_15


# ---------------------------------------------------------------------------
# Byte-identical benchmark tally — the exact row `make gate` prints and gates on.
# In-process + loopback-only (no Docker / no external tool), so it is a real unit test.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def crucible_measured():
    from framework.v2.eval.benchmark_run import run_benchmark_measured
    boards = run_benchmark_measured(incumbents=False)
    return next(mb for mb in boards if mb.scoreboard.tool == "crucible")


def test_benchmark_tally_is_byte_identical(crucible_measured):
    sb = crucible_measured.scoreboard
    assert (sb.true_positives, sb.false_positives, sb.false_negatives) == (11, 0, 0), (
        f"accuracy tally drifted: tp={sb.true_positives} fp={sb.false_positives} "
        f"fn={sb.false_negatives} (gate requires 11/0/0)")
    assert sb.precision == 1.0 and sb.recall == 1.0 and sb.f1 == 1.0


def test_benchmark_cost_row_is_byte_identical(crucible_measured):
    m = crucible_measured.metrics
    # STAGE 3 (Lane S, 1831 -> 1836, +5): PathProbeCheck's Option-B soundness upgrade fetches ONE benign
    # random-path control per PRESENT sensitive path, to require a present/absent signature DIFFERENTIAL
    # instead of a bare literal match. The corpus has 5 such present paths, so +5 control fetches. The
    # ACCURACY half did NOT move — 11/0/0 still holds (the 3 exposure TPs still fire: the sensitive path
    # reveals the secret while the random control 404s without it) — so the signed
    # ``eval/baselines/recall-accuracy-core.json`` is NOT re-signed (the request count is not in its signed
    # bytes). Only this UNSIGNED cost row moves.
    assert m.requests_sent == 1836, f"request budget drifted: {m.requests_sent} (gate requires 1836)"
    assert m.findings_reported == 11, f"findings reported drifted: {m.findings_reported} (gate requires 11)"
