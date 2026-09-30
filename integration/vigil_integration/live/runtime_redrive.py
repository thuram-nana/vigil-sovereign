"""runtime_redrive — runner-owned gated HTTP re-drive → signed FACT for the RESPONSE-DERIVED vuln classes
whose deterministic oracle is NOT the predicate oracle that :mod:`live.web_redrive` hardcodes.

It extends the exact, already-reviewed ``web_redrive`` discipline — a gated, DNS-pinned, proxy-free send
(reused verbatim: :func:`web_redrive._gated_web_send`) → the RUNNER (never a tool) crafts the probe → the
existing deterministic oracle judges the FRESH captured bytes → one atomic evidence branch is admitted
against its declared capability → ``certify_admitted(provenance="live_redrive")`` mints a signed,
offline-re-verifiable FACT — to three more MERIDIAN-planted classes:

  * ``path_traversal``   — **LEAD-ONLY** (see ``RUNTIME_LEAD_CLASSES``). The ``side_effect`` oracle over a
                           KNOWN file-content signature (``root:x:0:0:``) still runs behind TWO unreadable
                           controls (a PATH-SHAPED traversal to a nonce filename, and a benign NON-path
                           "constant emission" value) and an alternate-ENCODING corroboration, but those
                           guards test only the SHAPE OF THE INPUT, never the relationship between the
                           response and the file — so eight benign origins that read nothing satisfied them.
                           The branch is registered ``fact_capable: false`` and the arm produces LEADs,
                           never FACTs.
  * ``xss`` (reflected)  — the ``reflection_context`` oracle: a unique canary that reaches an EXECUTABLE
                           HTML position (a tag name / ``<script>`` / an ``on*`` handler), never inert text.
  * ``exposure``         — the ``predicate`` oracle over a JSON AST that the RUNNER composes and the
                           VERIFIER re-executes offline: the secret signature present at a fixed framework
                           path (``/.env`` / ``/actuator/env`` / ``/.git/config``), ABSENT from the BODY of
                           a random control path, corroborated by strings a genuine artifact of that kind
                           also carries, and — for a ``KEY=`` signature — carrying a right-hand side that
                           is a real value rather than a template/placeholder/self-referential expression.
  * ``ssi``              — the ``ssi_evaluation`` oracle (Wave-4.1, CWE-97): a PER-PROBE RANDOM product
                           ``N1*N2`` injected as a Server-Side Include directive pair
                           (``<!--#set var=X value="N1*N2" --><!--#echo var=X -->``) that the server
                           EVALUATED — the product present, the raw directive absent — with a benign
                           no-directive control that lacked it. The RUNNER crafts the directive; a page
                           that merely reflects the directive as an inert comment is the honest boundary
                           (reflected, not evaluated) and does NOT fire. The sound minting path is this
                           computed-product proof, never a bare marker; the shell ``<!--#exec cmd=…-->``
                           command variant is a separate SIDE_EFFECT/OOB path, out of this runner's scope.

SCOPE OF THE path_traversal DEMOTION — stated here because it is NARROWER than "VIGIL will not certify a
traversal". The demotion is enforced at exactly ONE place: ``live.verdict.admit``, which reads the
``fact_capable`` column of ``docs/capability-matrix/evidence-branches.json``. It therefore binds this
runner, ``live.wiring`` and the Strix proof rail — every route that admits through ``verdict.admit``.
It does NOT bind the CORE ENGINE. Measured per route on this same commit:

  * ``python3 -m framework.v2 scan``  — 11/11 benign origins that read NO file still produce
    ``grounding:"fact"``, High, 0.90 via ``scanner/checks.py:ContentSignatureCheck``;
  * ``python3 -m framework.v2 verify`` — re-verifies those ``ok=True`` (a hand-written report passes too);
  * ``aegis/inspect.py:547`` and ``scanner/library.py:404`` — the same uncontrolled path, and in the
    DEFENSIVE product that is ``decision='confirmed'`` / ``action='block'`` on legitimate traffic.

That core route is PRE-EXISTING and owned by another slice; nothing here changed it. What IS this slice's
responsibility is not to let the registry contradict the behaviour, so the ``path_traversal.file_signature``
row no longer names ``scanner/checks.py:ContentSignatureCheck`` in its ``implementation_refs`` (it describes
THIS runner), and it carries an explicit ``MISSING:`` control requirement for the open route. THE SECOND,
INDEPENDENT REFUSAL IS STILL MISSING. The precedent the row follows is ``verify/verifier.py:52-58``: "its
evidence branch is declared fact_capable=false … this absence is the SECOND, independent refusal, so a
direct confirm_and_certify() that skipped admission still cannot mint the class." For that to hold here,
``verify/verifier.py:139-140`` must drop SIDE_EFFECT for the two rows

    BUG_CLASS_ORACLES["path_traversal"] = (OracleKind.SIDE_EFFECT,)    # verify/verifier.py:139
    BUG_CLASS_ORACLES["lfi"]            = (OracleKind.SIDE_EFFECT,)    # verify/verifier.py:140

exactly as ``:384``/``:401`` already did for ``postmessage_exploited`` and ``csp_bypass``. That file is
owned by another agent and is deliberately untouched here; until it lands, the scan/verify/AEGIS routes
remain open and this module may not be read as closing them.

Unlike ``web_redrive`` (which probes EVERY web class on one URL), this runs ONLY the CLAIMED class, so a
minted FACT is inherently that class — no sibling cross-attribution. Soundness is inherited unchanged: the
gated send refuses out-of-scope / kill-switched traffic before any byte is sent; a probe that established no
channel is INCONCLUSIVE, never CLEAN ("found nothing ≠ CLEAN"); a body VIGIL could not decode is likewise
INCONCLUSIVE; and the oracle over the target's FRESH bytes — never the LLM's claimed context — decides. All
three branches are response-body/service-response derived and therefore NOT clean-capable. The
undecodable-body rule holds on EVERY leg, including the traversal arm's controls and its alternate-encoding
re-sends (:func:`_read_a_document`) — those legs previously read only ``status``/``body`` and so scored a
Brotli body, two concatenated gzip members and a WAF 403 as "observed, signature absent".

FATAL-2: every framework-touching import is FUNCTION-LOCAL — importing this module co-loads no offense engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# The classes this runner mints as FACTs, each mapped to its ONE registered evidence branch + the oracle
# whose deterministic decision procedure adjudicates it. Named by value (the framework enums are resolved
# function-locally, FATAL-2). Kept in lockstep with docs/capability-matrix/evidence-branches.json.
#
# INLINE FACT CLASSES — adjudicated by the single-capture body of :func:`runtime_redrive` via ``_BRANCH_FOR``.
RUNTIME_FACT_CLASSES = ("xss", "exposure", "ssi")

# STATISTICAL / EVAL FACT CLASSES (W2) — the injection classes the deterministic scanner already PROVES but
# whose evidence is MULTI-CAPTURE (a per-round SPRT truth-value attribution, an interleaved dose-response
# timing series, a per-probe evaluated product), so they are NOT adjudicated by the single-shot ``_BRANCH_FOR``
# body above. Each is minted by its OWN self-contained sibling arm (:func:`ssti_redrive` /
# :func:`boolean_redrive` / :func:`timing_redrive`), to which :func:`runtime_redrive` DELEGATES. Their branches
# (``ssti.evaluation`` / ``boolean_sqli.sprt_inference`` / ``time_based_sqli.timing_inference``) are all already
# ``fact_capable`` in docs/capability-matrix/evidence-branches.json — no new OracleKind. Kept out of
# ``RUNTIME_FACT_CLASSES`` precisely because that tuple's contract is "resolvable through ``_BRANCH_FOR`` +
# the inline body"; these resolve through the arms instead. They ARE dispatch classes (see
# ``RUNTIME_REDRIVE_CLASSES``), so the engage seam (engine ``_redrive_spec`` → wiring
# ``_live_runtime_redrive_fact``) now produces a spec and admits them — closing the under-report where the
# deterministic scanner proved the class but the governed engage/chat seam refused to mint it.
RUNTIME_STAT_FACT_CLASSES = ("ssti", "boolean_sqli", "time_based_sqli")

# LEAD-ONLY classes: the runner still probes them end to end and records an admitted verdict, but their
# registered branch declares ``fact_capable: false``, so ``verdict.admit`` demotes even a fired oracle to a
# LEAD. Kept here (rather than deleted) because the probe is genuinely useful evidence for a human — it is
# the CLAIM "VIGIL proved a file was read" that the evidence does not support.
#
# "STILL PROBES THEM END TO END" IS LOAD-BEARING, AND IT IS TRUE ON THE OPERATOR'S PRIMARY ROUTE. An earlier
# revision of this slice made it false: ``wiring._live_runtime_redrive_fact`` gated on RUNTIME_FACT_CLASSES
# and returned ``None`` BEFORE driving, so on the governed engage route the arm sent ZERO requests and
# recorded NO admitted verdict — the operator's lead was then sourced entirely from the LLM's assertion
# with no VIGIL-owned capture behind it, while this comment and the registry ``limitation`` both said the
# arm was driven. The seam now gates on RUNTIME_REDRIVE_CLASSES and drives the lead-only classes too; the
# FACT check downstream (``family_verdict == "FACT"``) is what still makes minting impossible.
#
# WHY path_traversal is here. A red-pen drove EIGHT benign origins that read no file through the shipped
# arm and every one of them minted a signed FACT that re-verified offline (rate 1.0): five that canonicalise
# the requested name before deciding (a hardening-advisory KB, canonicalise-then-basename, a canonicalising
# deny-list 403, a case-insensitive variant, a canonical-prefix deny KB) and THREE with no normaliser at all
# (``v.endswith("passwd")``; an anchored WAF regex ``(?:\.\./)+.*passwd\Z`` whose 403 quotes a sample line;
# ``v.rsplit("/", 1)[-1] == "passwd"``). Neither guard can be patched into soundness:
#   * the PATH-SHAPED control works by APPENDING a nonce suffix, which mutates exactly the token real
#     matchers key on (basename / suffix), so a suffix-keyed matcher answers the control with a miss and
#     the treatment with the signature — indistinguishable from a read;
#   * both alternate ENCODINGS canonicalise to the same path, so any endpoint that canonicalises before
#     deciding corroborates by construction.
# Decisively: the soundness suite's own true-positive fixture ``_LfiApp`` and the worst false positive are
# THE SAME PROGRAM with a different dict value. Neither guard tests the relationship between the RESPONSE
# and the FILE; both test only the SHAPE OF THE INPUT, and a read cannot be proven by varying input shape.
#
# Precedent: verify/verifier.py:384 and :401 already dropped SIDE_EFFECT for ``postmessage_exploited`` and
# ``csp_bypass`` — "a bare marker-in-sink is not a sound proof of execution and let a crafted finding mint a
# FACT with no execution." This is the same predicate over a different sink.
#
# DIRECTION FOR THE FUTURE SLICE (deliberately NOT built here): the sound shape is a CONTENT-relationship
# test, modelled on the ``ssi`` arm — which survived every attack precisely because its evidence is a
# per-probe UNGUESSABLE PRODUCT the server must COMPUTE. Candidates: multi-file corroboration (a second,
# different system file whose format VIGIL can validate independently — a canonical-path KB will have an
# article for ``passwd`` but cannot produce a well-formed second file), a size/entropy relation between the
# response and the file VIGIL asked for, or a per-probe unpredictable target whose content VIGIL already
# knows. Each also needs a multi-capture oracle row; see the branch's ``blocking_work``.
RUNTIME_LEAD_CLASSES = ("path_traversal",)

# Every class this runner will DISPATCH. A FACT-capable class can reach a signed FACT; a lead-only class
# runs the identical pipeline and stops at a LEAD. The union spans the INLINE fact classes, the W2
# STATISTICAL/EVAL fact classes (delegated to their sibling arms), and the LEAD-only classes; the engage
# seam (engine ``_redrive_spec`` + wiring ``_live_runtime_redrive_fact``) gates on this DISPATCH set.
RUNTIME_REDRIVE_CLASSES = RUNTIME_FACT_CLASSES + RUNTIME_STAT_FACT_CLASSES + RUNTIME_LEAD_CLASSES

_BRANCH_FOR = {
    "path_traversal": "path_traversal.file_signature",
    "xss": "xss.reflected_execution",
    "exposure": "exposure.secret_signature",
    "ssi": "ssi.evaluation",
}

# Candidate query-parameter names synthesised for the point-check classes when the proposed URL does not
# already carry a usable parameter, so the insertion surface EXISTS to be rendered into (mirrors
# web_redrive._candidate_redirect_names). A CLEAN would be bounded to these names — but these branches are
# not clean-capable, so the set only bounds where a FACT is SOUGHT, never a claim of absence.
_PATH_TRAVERSAL_PARAMS = ("file", "path", "filename", "name", "doc", "document", "page", "template",
                          "download", "read", "include", "view")
_XSS_PARAMS = ("q", "query", "search", "s", "ref", "name", "keyword", "term", "message", "comment",
               "title", "redirect")
# Candidate parameter names for the SSI class — where a server-side include tends to be assembled from
# a request value (a document/template/page name). A CLEAN would be bounded to these names, but this
# branch is not clean-capable, so the set only bounds where a FACT is SOUGHT, never a claim of absence.
_SSI_PARAMS = ("doc", "document", "file", "page", "template", "include", "name", "view", "path", "content",
               "tpl", "fragment")
_MAX_CANDIDATE_NAMES = 12

# --- W2: three more HTTP-response-derived FACT arms (SSTI / boolean-blind / time-based) ---------------
# Each is a sibling of :func:`runtime_redrive` (runner-owned gated re-drive → the matching frozen oracle →
# admit()+certify_admitted(provenance="live_redrive")). Their classes are ``RUNTIME_STAT_FACT_CLASSES``, part of
# the dispatch union ``RUNTIME_REDRIVE_CLASSES``, so BOTH the Strix proof-sink dispatch rail (proof/run.py) AND
# the governed engage seam reach them: :func:`runtime_redrive` DELEGATES a claimed stat class to its arm here
# (B1 — governed-engage FACT-parity), and the engage ``_redrive_spec`` producer emits a ``{"kind":"runtime"}``
# spec for them because they are in ``RUNTIME_REDRIVE_CLASSES``. No new OracleKind: SSTI reuses EVALUATION,
# boolean reuses BOOLEAN_INFERENCE (the multi-round SPRT ``BooleanInferenceCheck``, never the single-shot
# DifferentialCheck), timing reuses TIMING (all already frozen in _ALL_ORACLES). The registered evidence
# branch each admits through:
_SSTI_BRANCH = "ssti.evaluation"
_BOOLEAN_BRANCH = "boolean_sqli.sprt_inference"
_TIMING_BRANCH = "time_based_sqli.timing_inference"

# Where each blind/response-derived arm SEEKS a FACT if the proposed URL carries no usable parameter (mirrors
# _XSS_PARAMS). A CLEAN would be bounded to these — but these branches are not clean-capable, so the set only
# bounds where a FACT is sought, never a claim of absence.
_SSTI_PARAMS = ("q", "query", "search", "name", "input", "data", "msg", "message", "comment", "title",
                "tpl", "template", "expr", "eval", "page")
_BOOLEAN_PARAMS = ("id", "q", "query", "search", "name", "user", "uid", "item", "category", "cat", "page",
                   "sort", "order", "filter")
_TIMING_PARAMS = ("id", "q", "query", "search", "name", "user", "uid", "item", "category", "sort", "filter")

# The RUNNER-crafted probe payloads. The RUNNER owns these (never a Strix/LLM value), so a FACT rests on
# VIGIL's OWN injected expression/clause. SSTI: distinctive per-probe products go in ``{n1}``/``{n2}`` (filled
# per probe with a fresh random pair). Boolean: clause FAMILIES (see below) — a true clause that breaks
# out and evaluates TRUE vs a false one that evaluates FALSE, over the same insertion point. Timing:
# (benign, low_sleep, high_sleep, low_ms, high_ms) — a benign value vs two SLEEP doses for the dose-response.
_SSTI_EXPR_TEMPLATES = ("{{{{{n1}*{n2}}}}}", "${{{n1}*{n2}}}", "#{{{n1}*{n2}}}", "{{{n1}*{n2}}}")
# The TRUTH-VALUE ATTRIBUTION clause families live in ONE place — ``framework.v2.scanner.checks.
# boolean_clause_families`` — next to the check that sends them and the invariants they must satisfy
# (comparison-shape diversity, breakout validity, truth-correctness, index-aligned length matching).
# The set is a STABLE PUBLIC CONSTANT: two calls return the identical clauses, so a run is replayable
# and the operator can grep their WAF/access logs for exactly these strings (constitution VI.4). A
# previous revision randomised the literals per run to keep the set out of an exact-string blocklist;
# that is retracted — measured worthless, and it pointed at a defender's control. What the clause set
# does NOT do is close the truth-correlated-request-filter residual; that residual is OPEN, and the
# measured ladder is on ``boolean_inference_oracle`` residual (a). Imported lazily at use (FATAL-2: no
# framework import at module scope).
# doses in SECONDS for the SLEEP payloads + the injected milliseconds the timing oracle expects.
_TIMING_LOW_S, _TIMING_HIGH_S = 0.3, 0.6
_TIMING_SLEEP_TEMPLATES = (
    "x' OR SLEEP({s})-- -",                  # MySQL string-literal breakout
    "1 OR SLEEP({s})",                       # MySQL numeric context
    "x'||pg_sleep({s})--",                   # PostgreSQL
)
_STAT_MAX_PARAMS = 4     # blind/statistical arms are expensive — probe at most this many insertion points
# The BOOLEAN arm is capped tighter than the other statistical arms. Each (param, clause-family) pair is an
# INDEPENDENT attempt, and independent attempts MULTIPLY the per-attempt residual into a per-URL figure that
# boolean_redrive's docstring has to state; 2 params x 3 families = 6 attempts puts that at ~0.073% at the
# shipped K=7 (it was ~9.2% at K=4 over 4 params), and it is also what keeps the (now 28-send) rounds inside
# a sane live traffic budget.
_BOOLEAN_MAX_PARAMS = 2
# Identical-request sends for the per-PARAM determinism screen, shared across the clause families.
_BOOLEAN_BASELINE_SAMPLES = 8

# --- B2: governed-engage re-drive for the non-SQL injection classes (nosqli / ldap / xpath) -----------
# Through governed engage these three were structurally LEAD-only (no dedicated branch → the LLM-provenanced
# LEAD fallback). This arm DRIVES them end-to-end — a runner-owned, DNS-pinned gated re-drive of a
# class-specific error-provoking probe + a benign CONTROL twin, judged by the deterministic
# ``error_signature_oracle`` over VIGIL's FRESH bytes — so the operator's lead has a VIGIL-owned capture
# behind it rather than the model's assertion (the same reason path_traversal is DRIVEN though LEAD-only).
#
# BOTH registered branches for these classes are LEAD-ONLY; this arm mints NO FACT (``admit`` demotes the
# fired oracle because the branch is ``fact_capable: false``):
#   * ``<class>.datastore_error`` — LEAD-only. RED-PEN BLOCK (fixed here): ``error_signature_oracle`` is a
#     STRING MATCH and re-verifies only CONDITIONAL EMISSION, which is necessary but NOT sufficient for a
#     query break. The benign control twin rules out only UNCONDITIONAL emission; a datastore-error-shaped
#     string emitted CONDITIONALLY on the metacharacter by a NON-datastore source — a WAF/security-filter
#     block page that names the engine, a validator rejection, or an unrelated 500 whose stack trace merely
#     names the driver package (com.mongodb / javax.naming / MS.Internal.Xml) — passes the guard (four such
#     false FACTs were reproduced at rate 1.0). The sound FACT path is a break-vs-repair PARSER-STATE-TOGGLE
#     causation oracle re-executed OFFLINE (a new OracleKind, out of this reuse-only slice's scope) — see the
#     branch ``blocking_work``.
#   * ``<class>.sprt_inference``  — the boolean_inference SPRT truth-value channel, LEAD-only: the shipped SQL
#     clause families cannot soundly ATTRIBUTE a non-SQL class (a SQL clause that partitions proves SQL
#     boolean injection), so a class-specific truth-correct clause set is that branch's blocking_work.
#
# It is a governed-engage sibling of ``proof.run._strix_errsig_redrive`` built on the runtime_redrive
# discipline so the engage seam reads ``family_verdict``/``facts`` like the other seams. NOT in
# ``RUNTIME_REDRIVE_CLASSES`` (its own dispatch set + ``"injection"`` spec kind), so B1's ssti/boolean/timing
# runtime wiring is untouched.
_INJECTION_ERRSIG_BRANCH = {
    "nosqli": "nosqli.datastore_error",
    "ldap_injection": "ldap_injection.datastore_error",
    "xpath_injection": "xpath_injection.datastore_error",
}
# The engage seam's dispatch set (an import-clean tuple, FATAL-2). Deliberately SEPARATE from
# RUNTIME_REDRIVE_CLASSES so this slice adds arms without restructuring the runtime/web/sqli wiring.
INJECTION_REDRIVE_CLASSES = tuple(_INJECTION_ERRSIG_BRANCH)
# RUNNER-crafted, class-specific error-provoking probe payloads (kept in lockstep with
# ``proof.run._ERRSIG_PROBE_PAYLOADS``). The RUNNER owns these — never a Strix/LLM value — so the observed
# evidence rests on VIGIL's OWN injected metacharacters. The oracle (not the payload) decides whether an
# engine error string appeared; the class stays a LEAD (see the branch note above).
_INJECTION_ERRSIG_PAYLOAD = {
    "nosqli": "'\"{[",              # break a JSON/BSON query document / operator parse
    "ldap_injection": "*)(|&",     # unbalanced LDAP filter parens/operators
    "xpath_injection": "']|//*[",  # break an XPath string/predicate
}
# The datastore/parser ENGINE the ``error_signature_oracle`` must match for the observed error to be
# attributed to the claimed class (the engine label side of ``proof.run._ERRSIG_ENGINE_TO_CLASS``, class-
# scoped). A nosqli probe that provokes a SQL error is SQLi, not nosqli — a mismatched (or unmapped) engine
# is not admitted for this class, so even the LEAD stays class-appropriate.
_INJECTION_ENGINE_FOR = {"nosqli": {"mongodb"}, "ldap_injection": {"ldap"}, "xpath_injection": {"xpath"}}
# Candidate parameter names for the injection arm (mirrors the other point-check sets); the set only bounds
# where the arm PROBES, never a claim of absence (the branches are not clean-capable).
_INJECTION_PARAMS = ("id", "q", "query", "search", "name", "user", "uid", "item", "filter", "category",
                     "username", "password", "email", "login")

# --- D1: what the traversal arm's LEAD-quality guards do, and what they provably do NOT do -----------
# The canonical traversal payload, plus SEMANTICALLY-IDENTICAL re-encodings of the SAME path. POSIX
# dot-segment resolution makes every one of them name /etc/passwd, so a genuine file read reproduces the
# signature under all of them; an endpoint keyed on the LITERAL payload string does not.
#
# These are LEAD-QUALITY filters, not a proof of a read (the branch is ``fact_capable: false`` — see
# ``RUNTIME_LEAD_CLASSES``). They test the SHAPE OF THE INPUT only, so an endpoint that CANONICALISES the
# requested name before deciding (a hardening-advisory KB, a canonicalising deny-list/WAF) reproduces the
# signature under every encoding, and an endpoint keyed on the BASENAME or a SUFFIX defeats the PATH-SHAPED
# control below because that control is built by APPENDING to the target name.
_TRAVERSAL_PAYLOAD = "../../../../etc/passwd"
_TRAVERSAL_ALT_PAYLOADS = (
    "../../../../etc/./passwd",          # dot-segment identity  (etc/./passwd  -> etc/passwd)
    "../../../../etc/../etc/passwd",     # up-then-down identity (etc/../etc/passwd -> etc/passwd)
)
# TWO controls, both sent BEFORE the treatment on the same parameter, because they ask DIFFERENT questions.
#
#   1. The PATH-SHAPED control — a traversal to a nonce filename that CANNOT exist, deliberately built as a
#      sibling of the real target so it is maximally correlated with it lexically while retrieving nothing.
#      It catches a page that answers ANY path-ish input with the signature (a 403 "path rejected" notice
#      quoting a sample passwd line; a search hit keyed on "passwd").
#   2. The BENIGN NON-PATH control ("constant emission") — a value that is not path-shaped at all and names
#      nothing that exists anywhere. It catches a page that prints the signature regardless of input.
#
# A RETRACTION IS ITSELF RETRACTED. A previous revision DELETED control 2, claiming a mutation matrix had
# measured it DOMINATED ("removing it failed ZERO tests") and that the earlier claim "the two together are
# strictly stronger than either alone" was false. That was the overclaim: the mutation matrix measured the
# TEST SUITE, not the shape space. A red-pen built the counterexample — an EXTENSION-ALLOWLIST static server
# (known or absent extension => a boilerplate help page that quotes a sample passwd line; unknown extension
# => a clean 403 with no sample), which is neither basename- nor suffix-keyed:
#     control 2  ``vigilctl<nonce>.txt``                    signature PRESENT -> REFUSES (correctly)
#     control 1  ``../../../../etc/passwd.vigilctl<nonce>`` signature ABSENT  -> MISSES
#     treatment  ``../../../../etc/passwd``                 signature PRESENT -> fires
# With control 2 deleted the arm emitted a false LEAD against a correctly-defended server. The two ARE
# strictly stronger than either alone. Control 2 is RESTORED and the counterexample is pinned as a permanent
# control (test_runtime_redrive_soundness.py::test_b3_extension_allowlist_...). Cost: one extra live request
# per candidate parameter, and the bounded-work break means a constant-emitting origin costs exactly one.
_TRAVERSAL_PATH_CONTROL = "../../../../etc/passwd.vigilctl{nonce}"
_TRAVERSAL_CONST_CONTROL = "vigilctl{nonce}.txt"

# FAIL-CLOSED OBSERVATION RULE. A response is an ANSWER ABOUT THE PATH only when VIGIL actually READ A
# DOCUMENT: the channel was established, the status is 2xx, the body was SEMANTICALLY AVAILABLE
# (completely decompressed, strictly decoded, not truncated — ``body_decode``'s own guarantee, the same one
# the MAIN arm already consults through ``state["body_unavailable"]``), AND the decoded body is NOT EMPTY.
# Everything else is COULD-NOT-OBSERVE. The empty-body clause is not pedantry: an empty 2xx is what a WAF
# or an edge worker typically returns when it drops a dot-segment payload, and "nothing came back" is not
# evidence that the read failed to reproduce. This rule governs the CORROBORATION leg only; the CONTROL leg
# (:func:`_observed_signature`) deliberately ACCEPTS an empty body, because it asks a different question —
# see the two docstrings before changing either.
#
# The previous rule was an enumerated ALLOW-LIST of "throttle" statuses ({0, 408, 425, 429} plus >=500) and
# it never consulted the decode provenance at all. Measured against a GENUINE normpath+read LFI, the
# alternate-encoding leg concluded a REFUTATION at: 403 (the canonical WAF block), 401, 302, 451, 404, an
# empty 200, a ``Content-Encoding: br`` body, and two CONCATENATED gzip members (a real proxy artifact).
# Each of those persisted the sentence "every semantically-equivalent re-encoding ... was sent, answered,
# and OBSERVED not to carry it ... so it tracks the literal payload rather than the path" into the audit
# trail, and silently discarded a real arbitrary-file read. VIGIL had observed nothing. An enumerated
# deny-list cannot be right here: the question is not "which statuses are a throttle" but "did VIGIL read
# the document this path names", and only a 2xx with a decoded body answers it.
_ANSWER_STATUS_MIN, _ANSWER_STATUS_MAX = 200, 299


def _read_a_document(resp: Any, state: dict, body_unavailable_before: int) -> bool:
    """Whether ``resp`` is a response VIGIL may reason about the BODY of — for the CORROBORATION leg: a
    2xx whose body was semantically available AND NOT EMPTY. Consults BOTH the per-response
    ``body_semantically_available`` flag and the send-state counter the main arm uses, so a capture that
    reports neither is refused (fail-closed). Pure.

    THE TWO LEGS ASK DIFFERENT QUESTIONS, WHICH IS WHY THEY TREAT AN EMPTY BODY DIFFERENTLY. Do not
    "fix" the inconsistency by collapsing this into :func:`_observed_signature`; the tests
    ``test_b2_a_genuine_read_whose_reencodings_are_not_answers_is_inconclusive[empty-200]`` and
    ``test_b2_the_control_leg_still_accepts_an_empty_body`` pin both directions and one of them will go
    red.

      * THIS leg asks "did the same READ reproduce under a semantically-equivalent re-encoding of the
        same path?". An empty 2xx is NOT evidence that the read failed to reproduce; it is evidence that
        NOTHING CAME BACK — which is the same category error as scoring a WAF 403 or an undecodable body
        as "signature absent". An empty body therefore routes to COULD-NOT-OBSERVE here. (It is also the
        shape a WAF or an edge worker most often returns when it drops a dot-segment payload.)
      * :func:`_observed_signature`, the CONTROL leg, asks "does this origin emit the signature
        REGARDLESS OF INPUT?". An empty body genuinely answers that: no, it does not — there are no bytes
        for the signature to be in. Its ``raw_len == 0`` acceptance is correct and deliberate, and
        without it every ordinary bare 404 control (no ``Content-Type``, no body) would make the arm
        INCONCLUSIVE before the treatment was ever sent."""
    if not isinstance(resp, dict):
        return False
    try:
        status = int(resp.get("status", 0) or 0)
    except Exception:  # noqa: BLE001 — a malformed status is not an observation
        return False
    if not (_ANSWER_STATUS_MIN <= status <= _ANSWER_STATUS_MAX):
        return False
    if not bool(resp.get("body_semantically_available", False)):
        return False
    if not str(resp.get("body", "") or ""):
        return False           # nothing came back → nothing was observed about the path
    return state["body_unavailable"] <= body_unavailable_before


def _observed_signature(resp: Any, state: dict, body_unavailable_before: int,
                        signature: str) -> "Optional[bool]":
    """Whether ``signature`` was OBSERVED PRESENT (``True``) or OBSERVED ABSENT (``False``) in this
    response's BODY, or ``None`` when VIGIL read no document and therefore observed NEITHER.

    Used for the CONTROL leg, where — unlike the alternate-encoding leg — the STATUS is irrelevant: a 403
    "path rejected" notice whose decoded body quotes a sample passwd line is a perfectly good control
    refusal, and demanding a 2xx there would silently stop refusing the correctly-defended origins the
    control exists for. What is NOT acceptable is concluding ABSENCE from bytes VIGIL never decoded.

    An EMPTY body (``raw_len == 0``) is a sound observation of ABSENCE whatever the charset situation:
    there are no bytes for the signature to be in. That matters because the ordinary 404 a control gets
    back carries no ``Content-Type`` at all, and treating it as unobservable would make every such origin
    INCONCLUSIVE before the treatment was ever sent.

    DELIBERATE ASYMMETRY WITH :func:`_read_a_document`, which REFUSES an empty body. That is not an
    oversight to be tidied away: the corroboration leg asks "did the READ reproduce?", where an empty
    response is a NON-OBSERVATION, while this leg asks "does the origin emit the signature regardless of
    input?", where an empty response is a real and sufficient NO. Collapsing the two rules breaks one of
    them, and each direction is pinned by its own control. Pure."""
    if not isinstance(resp, dict):
        return None
    available = (bool(resp.get("body_semantically_available", False))
                 and state["body_unavailable"] <= body_unavailable_before)
    if available:
        return signature in str(resp.get("body", ""))
    try:
        raw_len = int(resp.get("raw_len", -1))
    except Exception:  # noqa: BLE001 — an unparseable length is not an observation
        raw_len = -1
    return False if raw_len == 0 else None

# --- D3: what makes a secret signature VALUE-SHAPED --------------------------------------------------
# A bare ``DB_PASSWORD=`` proves nothing: documentation prose (``<code>DB_PASSWORD=</code>``), a CI template
# (``DB_PASSWORD=${{ secrets.DB_PASSWORD }}``), a JS bundle that concatenates the key with an env lookup
# (``"DB_PASSWORD="+process.env.DB_PASSWORD``) and a shipped ``.env.example`` (``changeme_in_production``)
# all contain it. A leak needs a right-hand side that is an actual value: non-empty, long enough, and not a
# template / placeholder / self-referential expression. Every rule below is ALSO expressed in the JSON
# predicate the certificate carries, so the shape is RE-EXECUTED by the offline verifier rather than merely
# trusted at mint time.
_SECRET_VALUE_MIN_LEN = 6
_SECRET_VALUE_FORBIDDEN = (
    "${", "{{", "}}", "process.env", "changeme", "change_me", "your_", "your-", "placeholder",
    "example", "redacted", "todo", "xxxx", "<", ">", '"', "'", "`", "$", "{", "}", "+", "(", ")",
    ",", " ", "\t", "\n", "\r", "\\",
)

# Fixed framework/CMS paths, the distinctive signature each leaks, the CORROBORATING strings a genuine
# artifact of that kind also carries, and whether the signature is a ``KEY=`` assignment whose right-hand
# side must be a real value (see :func:`_secret_assignment`). Presence of the signature is NOT on its own
# the proof: every entry additionally requires the signature to be ABSENT from the BODY of a random control
# path — a differential the RUNNER evaluates over the control body, never over its status code.
_EXPOSURE_PROBES = (
    # (probe_path, signature, corroborators, value_shaped)
    ("/.env", "DB_PASSWORD=", (), True),
    ("/actuator/env", "spring.datasource", ("propertySources", '"value"'), False),
    ("/.git/config", "[core]", ("repositoryformatversion",), False),
)


# Every runner-side REFUSAL note used to end "→ LEAD". Measured against a refusing origin: leads=0 and
# family_verdict='INCONCLUSIVE' — no AdapterResult is created on any refusal path, because a refusal happens
# BEFORE admit(). The note promised a record that does not exist, so it says what actually happened.
_NOT_ADMITTED = "→ refused before admission (no verdict record is created for this surface)"


def _note(res: "RuntimeRedriveResult", msg: str) -> None:
    """Append ``msg`` to the audit trail ONCE. A re-drive walks up to 12 candidate parameter names against
    the same origin, so an origin-level refusal used to be written 12 times verbatim; the duplicates carry
    no information and bury the distinct notes."""
    if msg not in res.notes:
        res.notes.append(msg)


@dataclass
class RuntimeRedriveResult:
    url: str
    bug_class: str
    facts: list = field(default_factory=list)          # AdapterResult (is_fact), signed
    leads: list = field(default_factory=list)          # AdapterResult (channel-confirmed non-fact)
    inconclusive: list = field(default_factory=list)   # (bug_class, item) — no channel / unreadable body
    admissions: list = field(default_factory=list)     # (branch, verdict, reason) — the audit trail
    branch_verdicts: dict = field(default_factory=dict)  # bug_class -> {branch: verdict}
    contexts: dict = field(default_factory=dict)       # finding_ref -> oracle_context (offline re-verify)
    surfaces: dict = field(default_factory=dict)       # bug_class -> set(surface actually EXAMINED)
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def family_verdict(self, bug_class: str) -> str:
        """The conservative composition over every branch of ``bug_class`` (see verdict.compose)."""
        from .verdict import compose  # noqa: PLC0415
        verdicts = list(self.branch_verdicts.get(bug_class, {}).values())
        if not verdicts:
            return "INCONCLUSIVE"
        return compose(verdicts).value


def _candidate_query_names(url: str, base_names: "tuple[str, ...]") -> "list[str]":
    """Query-parameter names to probe: the names the URL already carries FIRST (so the endpoint's real
    parameter is exercised), then the well-known set for breadth, de-duped case-insensitively and capped.
    Purely lexical — no network."""
    from urllib.parse import parse_qsl, urlsplit  # noqa: PLC0415
    names: "list[str]" = []
    seen: "set[str]" = set()
    try:
        for k, _v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            low = k.lower()
            if k and low not in seen:
                names.append(k)
                seen.add(low)
    except Exception:  # noqa: BLE001 — a malformed URL simply contributes no grounded names
        pass
    for n in base_names:
        if n.lower() not in seen:
            names.append(n)
            seen.add(n.lower())
    return names[:_MAX_CANDIDATE_NAMES]


def _url_with_param(url: str, name: str, value: str = "x") -> str:
    """``url`` guaranteed to carry a ``name`` query parameter (append if absent). Lexical only."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit  # noqa: PLC0415
    sp = urlsplit(url)
    pairs = parse_qsl(sp.query, keep_blank_values=True)
    if any(k.lower() == name.lower() for k, _ in pairs):
        return url
    pairs.append((name, value))
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(pairs), sp.fragment))


def _fetch_path(tmpl: Any, send: Callable, probe_path: str, method: str = "GET") -> dict:
    """GET ``probe_path`` on the template's origin through the SAME gated send (mirrors the URL construction
    ``scanner.checks.PathProbeCheck.probe`` uses, so the request on the wire is identical). The runner owns
    this fetch so the exposure arm can evaluate the signature predicate over BOTH bodies itself instead of
    inferring a differential from whether a check returned ``None``."""
    from urllib.parse import urljoin, urlsplit  # noqa: PLC0415
    req = tmpl.request
    parts = urlsplit(req.url)
    base = f"{parts.scheme}://{parts.netloc}/"
    target = urljoin(base, str(probe_path).lstrip("/"))
    return send(req.model_copy(update={"method": method, "url": target, "body": ""}))


def _lower_aligned(s: str) -> str:
    """A LENGTH-PRESERVING lowercase: ``_lower_aligned(s)[i]`` is the fold of ``s[i]``, so an index found in
    the folded text is a VALID INDEX INTO ``s``.

    ``str.lower()`` is NOT length-preserving, and indexing one string while slicing the other is a real,
    exploitable defect rather than a theoretical one. ``lower()`` is a per-codepoint map whose image is one
    or more codepoints, and U+0130 (``İ``, the LATIN CAPITAL LETTER I WITH DOT ABOVE — the Turkish dotted
    capital I) maps to TWO: ``i`` + U+0307 COMBINING DOT ABOVE. A red-pen enumerated all 0x110000 codepoints
    and found it is the only one, but this helper does not depend on that: it is length-preserving BY
    CONSTRUCTION.

    What the desynchronisation did. :func:`_secret_assignment` searched the LOWERCASED body and then sliced
    the ORIGINAL body with the index that search returned, so every ``İ`` before the signature shifted the
    slice by one character. A ``/.env`` containing NO credential at all —

        ``#İİİİİİİİ dagitim notlari`` / ``DB_PASSWORD=`` (EMPTY) / ``notes:DB_PASSWORD=documented_here``

    — minted a signed, offline-re-verifying ``exposure`` FACT (rc=0, 1/1 reproduced) whose ``secret_value``
    was ``'B_PASSWORD=documented_here'``: an arbitrary window, not a secret. The EMPTY assignment is the
    exact template shape the value-shape test exists to refuse. On the non-minting side the same offset bug
    put a TRUNCATED credential on the ACCEPT branch (``why=""``) — ``# İ region`` + a real
    ``DB_PASSWORD=Pr0dKey-Real-Value-9x`` returned ``'r0dKey-Real-Value-9x'`` — violating D7 and both of the
    tests written to pin it.

    The fast path is sound because ``lower()`` never contracts (no codepoint maps to the empty string), so
    equal total lengths can only mean every codepoint mapped to exactly one."""
    low = s.lower()
    if len(low) == len(s):
        return low
    return "".join((c.lower() or c)[0] for c in s)


def _secret_assignment(body: str, signature: str) -> "tuple[str, str, str]":
    """The first ``<signature><value>`` occurrence in ``body`` whose right-hand side is a REAL value.

    Returns ``(assignment, value, why_not)``. ``assignment`` is the literal substring of ``body`` that runs
    from the signature through the end of the value — so an offline verifier can re-find it verbatim in the
    retained body — and is ``""`` when no occurrence qualifies, with ``why_not`` naming the reason WITHOUT
    quoting the candidate (an audit note must never print a secret, nor a value it just judged not to be
    one). Pure and deterministic: no network, no clock, no rng.

    The rejected shapes are the measured ones: an empty right-hand side (``<code>DB_PASSWORD=</code>``, a
    JS concatenation ``"DB_PASSWORD="+process.env.X`` where the next character closes the string literal),
    a template interpolation (``${{ secrets.X }}``, ``{{ x }}``), and a shipped placeholder
    (``changeme_in_production``)."""
    hay, needle = str(body or ""), str(signature or "")
    if not needle:
        return "", "", "no signature is configured for this probe"
    # INDEX AND SLICE THE SAME STRING. ``low_hay`` is a LENGTH-PRESERVING fold of ``hay`` (see
    # :func:`_lower_aligned`), so every index this function derives from ``low_hay`` — ``i``, ``j``, and
    # the ``rest``/``start``/``stop`` offsets computed from them — is a valid index into ``hay`` itself.
    # Using ``hay.lower()`` here desynchronised the two by one character per U+0130 and minted a signed
    # FACT out of a ``.env`` that carried no credential.
    low_hay, low_needle = _lower_aligned(hay), _lower_aligned(needle)
    if len(low_hay) != len(hay) or len(low_needle) != len(needle):   # pragma: no cover - fold is total
        # The alignment invariant, enforced rather than asserted (an ``assert`` vanishes under -O, and this
        # is the one property every offset below depends on). Fail closed: no extraction, no certificate.
        return "", "", "the captured body could not be case-folded without changing its length"
    i = low_hay.find(low_needle)
    if i < 0:
        return "", "", f"{signature!r} is not present in the body"
    why = "its right-hand side carries no value"
    while i >= 0:
        j = i + len(needle)                      # first character of the right-hand side
        # THE OCCURRENCE MUST BE AN ASSIGNMENT, not a mention. In .env / shell-export grammar an assignment
        # BEGINS A LINE (optionally after whitespace, optionally after ``export``). Anything else —
        # ``notes:DB_PASSWORD=documented_here``, ``OLD_DB_PASSWORD=...``, a path or a JSON string that
        # happens to contain the key, a commented ``# DB_PASSWORD=<yours>`` — is the key being NAMED, which
        # is precisely what the value shape exists to refuse; without this, a ``/.env`` whose only
        # ``DB_PASSWORD=`` at a line start is EMPTY (the template shape) still minted off a prose line
        # further down. RECALL COST, disclosed in the branch ``limitation``: a commented-out but genuine
        # credential, and an assignment embedded in a longer key, are refused to a LEAD.
        line_start = hay.rfind("\n", 0, i) + 1
        if hay[line_start:i].strip() not in ("", "export"):
            why = ("the signature does not begin an assignment — it occurs inside other text on its line "
                   "(prose, a comment, a longer key, a path or a JSON string), which is the key being "
                   "NAMED rather than assigned")
            i = low_hay.find(low_needle, j)
            continue
        rest = hay[j:]
        start = stop = -1
        if rest[:1] in ('"', "'"):
            quote = rest[0]
            end, eol = rest.find(quote, 1), rest.find("\n")
            if end > 0 and (eol < 0 or end < eol):
                start, stop = j + 1, j + end     # a quoted value that CLOSES on the same line
            else:
                why = ("its right-hand side opens a quote that never closes on that line — a string "
                       "concatenation naming the key, not an assignment")
        else:
            # An UNQUOTED right-hand side runs to the END OF THE LINE. Nothing else terminates it: in .env
            # semantics ``;`` is not a delimiter at all, ``&`` is a query-string separator, and ``#`` only
            # starts a comment when it is whitespace-preceded (and a value containing a space is refused
            # below anyway). Cutting on those three TRUNCATED real credentials: it turned
            # ``DB_PASSWORD=abc;defghij`` into a 3-character value and then refused it with "its
            # right-hand side is only 3 character(s) long" — an unobserved claim, since the runner's own
            # cut made it 3 — and, worse, it put a TRUNCATED secret ("django-insecure-8k", "Tr0ub4dor")
            # into a signed certificate as the evidence. A certificate must never carry a truncated value.
            cut = len(rest)
            for ch in ("\r", "\n"):
                k = rest.find(ch)
                if 0 <= k < cut:
                    cut = k
            start, stop = j, j + cut
        if start >= 0:
            value = hay[start:stop].strip()
            forbidden = next((t for t in _SECRET_VALUE_FORBIDDEN if t in value.lower()), None)
            if not value:
                why = "its right-hand side is empty"
            elif len(value) < _SECRET_VALUE_MIN_LEN:
                why = (f"its right-hand side is only {len(value)} character(s) long — below the "
                       f"{_SECRET_VALUE_MIN_LEN}-character floor for a credential")
            elif forbidden is not None:
                # HONEST wording: this token set is how a template interpolation, a JS concatenation and a
                # shipped placeholder are told apart from a value, and it is deliberately over-broad — a
                # GENUINE credential containing it is refused too. See the branch's measured recall figure
                # in evidence-branches.json (exposure.secret_signature.limitation).
                why = (f"its right-hand side contains {forbidden!r}, which this arm's value shape does not "
                       f"accept — the marker set that separates a template interpolation, a JS "
                       f"concatenation and a shipped placeholder from a real value also refuses a genuine "
                       f"credential that happens to contain one of those characters")
            else:
                vstart = hay.find(value, start, stop + 1)
                if vstart >= 0:
                    return hay[i:vstart + len(value)], value, ""
                why = "its right-hand side could not be located verbatim in the retained body"
        i = low_hay.find(low_needle, j)
    return "", "", why


def _secret_value_predicates(signature: str) -> "list[dict]":
    """The value-shape conjunction, as a pure JSON AST over the RETAINED body — so the offline verifier
    RE-EXECUTES the shape test instead of trusting that the runner ran it. Every clause binds back to
    ``body``: the assignment must be a literal substring of the captured body, it must carry the signature,
    the value must be part of the assignment, be long enough, and contain none of the template/placeholder
    markers.

    NAMED RESIDUAL — the AST does NOT re-derive the extraction, and a previous revision of this docstring
    claimed it did ("which is what makes a substituted value fail the conjunction rather than ride through
    it"). That claim is RETRACTED; it was measured false. The conjunction tests only the SELF-CONSISTENCY
    of the triple ``(secret_assignment, secret_value, body)``: any window of the retained body that happens
    to contain the signature and satisfy the shape rules satisfies it. It therefore catches a value
    SUBSTITUTED for one that is not in the body (``test_secret_value_predicate_is_a_pure_json_ast``
    pins that), but it CANNOT catch a runner-side extraction bug that returns the wrong window of the REAL
    body — the U+0130 off-by-N did exactly that and the resulting certificate re-verified offline, rc=0.
    Closing it needs a predicate operation that re-derives "the FIRST occurrence of ``signature`` whose
    right-hand side qualifies" from ``body`` alone, i.e. a new op in ``framework/v2/verify/oracles.py``
    (owned by another slice). Until that exists, the extraction OFFSET is the runner's, and the defence
    against an offset bug is :func:`_lower_aligned` plus its controls, not the certificate."""
    return [
        {"contains": [{"var": "body"}, {"var": "secret_assignment"}]},
        {"icontains": [{"var": "secret_assignment"}, signature]},
        {"contains": [{"var": "secret_assignment"}, {"var": "secret_value"}]},
        {"min_len": [{"var": "secret_value"}, _SECRET_VALUE_MIN_LEN]},
        {"not": {"any": [{"icontains": [{"var": "secret_value"}, t]}
                         for t in _SECRET_VALUE_FORBIDDEN]}},
    ]


def _encoding_corroboration(send: Callable, tmpl: Any, point: Any, signature: str, state: dict,
                            res: "RuntimeRedriveResult", bug_class: str,
                            probe_url: str) -> "tuple[Optional[str], str, bool]":
    """Re-send the SAME path under a semantically-equivalent alternate ENCODING and report the first one
    that reproduces ``signature``.

    A filesystem resolves ``etc/passwd``, ``etc/./passwd`` and ``etc/../etc/passwd`` to the same file, so a
    genuine read answers all three identically; an endpoint keyed on the LITERAL payload does not survive
    the rewrite. (An endpoint that CANONICALISES before deciding DOES survive it — which is why this is a
    lead-quality filter and not a proof; see ``RUNTIME_LEAD_CLASSES``.)

    Returns ``(payload, "", True)`` on corroboration, and otherwise ``(None, why, observed)`` where
    ``observed`` says whether VIGIL actually MADE the observation it would be reasoning from:

      * ``observed=True``  — every alternate encoding was sent, VIGIL READ THE DOCUMENT it answered with
        (a 2xx with a semantically-available body, see :func:`_read_a_document`), and that body genuinely
        LACKED the signature. That is a REFUTATION: the caller may conclude the signature tracks the
        literal payload rather than the path.
      * ``observed=False`` — at least one alternate encoding produced no channel, a transport error, a
        status that is not a 2xx, or a body VIGIL could not decode, so "no re-encoding reproduced it" was
        never established. That is COULD-NOT-OBSERVE, and the caller must treat it as INCONCLUSIVE.

    The rule is FAIL-CLOSED (``_ANSWER_STATUS_MIN``/``_ANSWER_STATUS_MAX`` + the decode provenance) rather
    than an enumerated list of "throttle" statuses. The enumerated version concluded a REFUTATION at 403 —
    the canonical WAF block — and at 401/302/451/404/empty-200/undecodable, each time persisting a sentence
    claiming VIGIL had OBSERVED the re-encoding not to carry the signature, and each time silently
    discarding a real arbitrary-file read behind a WAF that flags dot-segment obfuscation but not the plain
    payload. The same fail-closed rule governs the CORROBORATION direction: a signature seen in a body
    VIGIL could not decode is not an observation either, so it does not corroborate.
    """
    tried: "list[str]" = []
    unobservable = False
    for alt in _TRAVERSAL_ALT_PAYLOADS:
        before, before_bodies = state["channels"], state["body_unavailable"]
        try:
            resp = send(tmpl.render(point, alt))
        except Exception as e:  # noqa: BLE001 — a transport error is not corroboration, and not a refutation
            tried.append(f"{alt}: {type(e).__name__} (no observation)")
            unobservable = True
            continue
        if state["channels"] <= before:
            res.inconclusive.append((bug_class, f"{probe_url}#alt-encoding"))
            tried.append(f"{alt}: no channel (no observation)")
            unobservable = True
            continue
        status = int(resp.get("status", 0) or 0) if isinstance(resp, dict) else 0
        if not _read_a_document(resp, state, before_bodies):
            # The origin put bytes on the wire, but VIGIL did not READ THE DOCUMENT this path names: a
            # non-2xx (a WAF 403, a 401, a redirect whose body was never fetched, a 404, a rate-limit 429,
            # a 5xx) or a body it could not completely decompress and strictly decode (br/zstd, two
            # concatenated gzip members, an undeclared charset, a truncated read). Counting that as "the
            # signature was absent" is what manufactured a correlation claim out of a measurement nobody
            # took and threw away real arbitrary-file reads behind ordinary CDN/WAF infrastructure.
            why = ""
            if isinstance(resp, dict):
                why = str(resp.get("body_unavailable_reason", "") or "")
            detail = f"status {status}" + (f"; body not readable: {why}" if why else
                                           ("; body not readable" if _ANSWER_STATUS_MIN <= status
                                            <= _ANSWER_STATUS_MAX else ""))
            tried.append(f"{alt}: {detail} (not an answer about the path — no observation)")
            unobservable = True
            continue
        body = str(resp.get("body", ""))
        if signature in body:
            return alt, "", True
        tried.append(f"{alt}: observed (status {status}, body decoded), signature absent")
    if not tried:
        return None, "no alternate encoding was attempted", False
    return None, "; ".join(tried), not unobservable


def runtime_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                    claimed_class: str, timeout: float = 8.0) -> RuntimeRedriveResult:
    """Re-drive ``url`` for the single CLAIMED response-derived class through a gated send + the matching
    deterministic oracle, and mint a signed FACT ONLY when the oracle confirms CAUSATION (not mere presence)
    over VIGIL's OWN live capture:

      * path_traversal — **LEAD-ONLY; this arm mints NOTHING** (``RUNTIME_LEAD_CLASSES``; the branch is
        registered ``fact_capable: false``, so ``admit`` demotes even a fired oracle). It is still driven —
        including from the governed engage seam — and it still applies its LEAD-QUALITY filters: TWO
        controls on the same parameter must each come back WITHOUT the signature (a PATH-SHAPED traversal
        to a nonce filename that cannot exist, and a benign NON-path "constant emission" value), and a
        SECOND, semantically-different encoding of the same path (``etc/./passwd`` /
        ``etc/../etc/passwd``) must REPRODUCE it. Every one of those legs is adjudicated FAIL-CLOSED: only
        a 2xx whose body VIGIL completely decoded counts as an observation (:func:`_read_a_document`).
        None of it proves a READ: all three vary only the SHAPE OF THE INPUT, so an endpoint that
        CANONICALISES the requested name, or keys on its BASENAME or a SUFFIX, satisfies them all while
        reading nothing — eight such benign origins did, at rate 1.0. And the demotion binds only the
        ``verdict.admit`` layer: see SCOPE OF THE path_traversal DEMOTION in the module docstring — the
        ``framework.v2 scan`` / ``verify`` / AEGIS routes over the same check remain open.
      * xss (reflected) — the reflection oracle must report the ``html_tag`` context (the canary became a live
        element); mere presence inside a ``<script>`` string literal or a ``<noscript>`` block is NOT accepted.
      * exposure — the runner fetches BOTH a random control path and the fixed probe path, and hands the
        predicate oracle a JSON AST over BOTH bodies: signature present at the probe path, ABSENT from the
        control BODY (a status-only soft-404 test is not a differential, and it is what silently skipped the
        probe fetch entirely against any origin that does not 404 unknown paths), plus per-path corroborators
        and — for a ``KEY=`` signature — a right-hand side that is a real value. The whole conjunction is in
        the certificate, so the offline verifier RE-EXECUTES it rather than trusting the runner.
      * ssti / boolean_sqli / time_based_sqli (``RUNTIME_STAT_FACT_CLASSES``) — DELEGATED verbatim to their
        self-contained sibling arms (:func:`ssti_redrive` / :func:`boolean_redrive` / :func:`timing_redrive`),
        because each carries a MULTI-CAPTURE recipe + control the single-capture body here cannot express (a
        per-round SPRT truth-value attribution with a dynamic-page control for boolean, an interleaved
        base/treatment dose-response for timing, a per-probe evaluated random product with a benign control
        for ssti). This delegation is what gives the governed engage seam FACT-parity with the deterministic
        scanner for these classes; the arm runs its OWN charter gate before any traffic.

    A probe that established no channel is INCONCLUSIVE (never CLEAN). Returns a :class:`RuntimeRedriveResult`.
    Never raises (a probe error is recorded and what held is returned).

    RESIDUAL, named rather than papered over: for path_traversal the two controls and the encoding
    corroboration are RUNNER-side preconditions checked before admission — ``BUG_CLASS_ORACLES`` pins the
    class to a single-capture ``side_effect`` row that takes one (marker, sink) pair and can express neither
    a negation nor a conjunction, so neither filter re-executes offline. That is the SECOND of the two
    prerequisites in the branch's ``blocking_work``; the first is a guard that discriminates a READ from a
    canonical-path LOOKUP. (``exposure`` does not share this residual: its predicate AST carries the control
    body and the value shape, so the whole decision re-executes.)"""
    import hashlib  # noqa: PLC0415 — stdlib; deterministic control tokens (no rng, determinism invariant)

    import secrets  # noqa: PLC0415 — per-probe UNPREDICTABLE product so the value cannot pre-exist (not rng
    #                                  in learning/reward math; the oracle re-fires deterministically offline)

    # PathProbeCheck is deliberately NOT used: its ``probe`` returns a context for any status outside
    # (0, 404) and never evaluates the signature predicate, so it cannot express the exposure arm's
    # control differential. The runner fetches both paths itself (see _fetch_path) and composes the
    # predicate the oracle judges.
    from framework.v2.scanner.checks import MarkerReflectionCheck  # noqa: PLC0415
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.adapter import FindingContext  # noqa: PLC0415
    from framework.v2.verify.oracles import (  # noqa: PLC0415
        predicate_oracle, reflection_context_oracle, side_effect_oracle, ssi_evaluation_oracle)
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from framework.v2.verify.verifier import normalize_bug_class  # noqa: PLC0415

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, branch_ids, compose  # noqa: PLC0415
    from .web_redrive import _gated_web_send  # noqa: PLC0415 — the reviewed gated, DNS-pinned, no-proxy send

    bug_class = normalize_bug_class(claimed_class)
    res = RuntimeRedriveResult(url=url, bug_class=bug_class)
    if bug_class not in RUNTIME_REDRIVE_CLASSES:
        res.notes.append(f"{bug_class!r} is not a runtime-redrive class")
        return res
    # W2 STATISTICAL/EVAL ARMS (B1 — governed-engage FACT-parity). ssti / boolean_sqli / time_based_sqli are
    # minted by their OWN self-contained sibling arms, NOT by the single-capture ``_BRANCH_FOR`` body below:
    # each carries a distinct multi-capture recipe + control (a per-round SPRT truth-value attribution for
    # boolean, an interleaved dose-response series for timing, a per-probe evaluated product for ssti) that
    # the inline body cannot express, and each runs its own charter gate (:func:`_stat_setup` → ``_authorize``)
    # before any byte. Delegate and return the arm's result VERBATIM — it is the same ``RuntimeRedriveResult``
    # the seam reads (``.facts`` / ``.family_verdict()``). ``param=None`` ⇒ the arm walks its candidate
    # parameter set, because the governed engage seam carries no declared param. boolean_sqli routes to
    # :func:`boolean_redrive`, which adjudicates through the multi-round ``BooleanInferenceCheck`` /
    # ``boolean_inference_oracle`` SPRT (dynamic-page control), never the single-shot ``DifferentialCheck``.
    if bug_class in RUNTIME_STAT_FACT_CLASSES:
        _arm = {"ssti": ssti_redrive, "boolean_sqli": boolean_redrive,
                "time_based_sqli": timing_redrive}[bug_class]
        return _arm(url, slug=slug, engagement_slug=engagement_slug, signers=signers, timeout=timeout)
    branch = _BRANCH_FOR[bug_class]
    if branch not in branch_ids():
        res.notes.append(f"branch {branch!r} is not registered — cannot admit (fail-closed)")
        return res

    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    send, state = _gated_web_send(slug, timeout=timeout)
    nonce = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]

    def _body(resp: Any) -> str:
        return str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)

    def _admit(context: dict, item: str, surface: str, *, fired: bool, conclusive: bool,
               body_unreadable: bool) -> Any:
        res.surfaces.setdefault(bug_class, set()).add(surface)
        observed = {"channel_established": True, "body_semantically_available": not body_unreadable,
                    "gate_authorized": True}
        finding = {"check_id": f"rt:{bug_class}:{item}#{branch}", "bug_class": bug_class,
                   "insertion_point": item, "oracle_context": context}
        admitted = admit(branch, fired=fired, conclusive=conclusive, observed=observed)
        res.admissions.append((branch, admitted.verdict.value, admitted.reason))
        bm = res.branch_verdicts.setdefault(bug_class, {})
        prior = bm.get(branch)
        bm[branch] = compose([prior, admitted.verdict.value]).value if prior else admitted.verdict.value
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="live_redrive")
        res.contexts[r.finding_ref] = context
        if r.is_fact:
            res.facts.append(r)
        elif admitted.verdict is Verdict.INCONCLUSIVE:
            res.inconclusive.append((bug_class, f"{item}#{branch}"))
        else:
            res.leads.append(r)
        return r

    try:
        if bug_class == "path_traversal":
            sig = "root:x:0:0:"
            # TWO controls on the same parameter, both sent BEFORE the treatment, because they refuse
            # DIFFERENT shapes (see _TRAVERSAL_PATH_CONTROL / _TRAVERSAL_CONST_CONTROL for the measured
            # counterexample that put the second one back):
            #   path-shaped        — a traversal to a nonce filename that cannot exist: refuses a page that
            #                        answers ANY path-ish input with the signature (a 403 "path rejected"
            #                        notice quoting a sample line; a KB search whose corpus documents it);
            #   constant-emission  — a benign NON-path value naming nothing: refuses a page that prints the
            #                        signature regardless of input, including an extension-allowlist server
            #                        whose help page quotes it and which the path-shaped control MISSES.
            controls = (("path-shaped", _TRAVERSAL_PATH_CONTROL.format(nonce=nonce)),
                        ("constant-emission", _TRAVERSAL_CONST_CONTROL.format(nonce=nonce)))
            for name in _candidate_query_names(url, _PATH_TRAVERSAL_PARAMS):
                probe_url = _url_with_param(url, name)
                tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
                point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                              if p.name.lower() == name.lower()), None)
                if point is None:
                    continue
                surface = f"query:{name}"
                # Record the surface as EXAMINED even when a control refuses below, so a runner-side
                # refusal is attributable in the audit trail (and is distinguishable from not probing).
                res.surfaces.setdefault(bug_class, set()).add(surface)
                # ``None`` = every control passed; "stop" = refused or unobservable (bounded work);
                # "skip" = this parameter could not be controlled, try the next one.
                outcome = None
                for label, control_value in controls:
                    before, before_bodies_ctl = state["channels"], state["body_unavailable"]
                    try:
                        control = send(tmpl.render(point, control_value))
                    except Exception as e:  # noqa: BLE001
                        _note(res, f"path_traversal control error [{name}/{label}]: "
                                   f"{type(e).__name__}: {e}")
                        outcome = "skip"
                        break
                    if state["channels"] <= before:
                        res.inconclusive.append((bug_class, f"{probe_url}#control:{label}"))
                        outcome = "skip"
                        break
                    seen = _observed_signature(control, state, before_bodies_ctl, sig)
                    if seen is None:
                        # The SAME fail-closed rule the alternate-encoding leg uses: "the control did not
                        # carry the signature" is a claim about a document, so it may only be made about
                        # bytes VIGIL actually decoded (or about an empty body, which provably carries
                        # nothing). An undecodable control body is not a clean control; treating it as one
                        # would let the treatment through on a differential that was never measured.
                        res.inconclusive.append((bug_class, f"{probe_url}#control:{label}"))
                        reason = str(control.get("body_unavailable_reason", "")
                                     if isinstance(control, dict) else "")
                        status_ctl = int(control.get("status", 0) or 0) if isinstance(control, dict) else 0
                        _note(res,
                              f"path_traversal: control COULD NOT BE OBSERVED [{surface}/{label}] — the "
                              f"control request was answered (status {status_ctl}) but VIGIL could not "
                              f"decode its body" + (f" ({reason})" if reason else "") + ", so the "
                              f"differential was never measured and nothing is concluded → INCONCLUSIVE")
                        outcome = "stop"
                        break
                    if seen:
                        _note(res,
                              f"path_traversal: control-differential refused [{surface}/{label}] — the "
                              f"{label} control value reproduced the file signature, so its presence is "
                              f"not attributable to a file read {_NOT_ADMITTED}")
                        # BOUNDED WORK: this origin answers this control shape with the signature, so the
                        # same refusal would repeat verbatim on every remaining candidate parameter
                        # (measured: 12 identical notes, 60 live requests). Stop here.
                        outcome = "stop"
                        break
                if outcome == "stop":
                    break
                if outcome == "skip":
                    continue
                # TREATMENT: the canonical traversal payload, sent DIRECTLY (not via
                # ContentSignatureCheck.probe) so that ``treatment_unreadable`` measures the TREATMENT's
                # OWN decode provenance and nothing else. ContentSignatureCheck.probe now spends its own
                # benign control whenever the signature is present (36fd3cf8, "a file signature needs a
                # control"); on an ordinary origin that control legitimately reads a bare-404/empty body,
                # which increments ``state["body_unavailable"]``. Folding that (empty, sound) control miss
                # into this treatment window made ``treatment_unreadable`` true and demoted a GENUINE
                # arbitrary-file read from LEAD to INCONCLUSIVE. This arm supplies its OWN two controls
                # above and runs the 2-arg side_effect_oracle itself, so it never used chk's control_sink —
                # this reproduces exactly the single-request probe the arm was written against
                # (``from_side_effect`` over the treatment body, no control_sink), and leaves
                # ContentSignatureCheck's control intact for every other consumer (the scanner engine and
                # the library LFI entries).
                before2, before_bodies = state["channels"], state["body_unavailable"]
                treatment = send(tmpl.render(point, _TRAVERSAL_PAYLOAD))
                if state["channels"] <= before2:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                # The TREATMENT's OWN decode provenance, read HERE — before the corroboration re-sends.
                # Reading it after them (``state["body_unavailable"] > before_bodies`` at the admit call)
                # attributed an undecodable ALTERNATE ENCODING to the treatment and turned an otherwise
                # admissible verdict INCONCLUSIVE for the wrong reason.
                treatment_unreadable = state["body_unavailable"] > before_bodies
                ctx_obj = FindingContext.from_side_effect(sig, _body(treatment), bug_class=bug_class)
                context = ctx_obj.to_verifier_context()
                signal = side_effect_oracle(context.get("marker", ""), context.get("observed_sink", ""))
                if signal.fired:
                    # ENCODING CORROBORATION: the same path, written differently. A filesystem resolves
                    # ``etc/./passwd`` and ``etc/../etc/passwd`` to the same inode; a page keyed on the
                    # LITERAL payload string does not. (A page that CANONICALISES does, which is why this
                    # is a lead-quality filter, not a proof of a read.)
                    alt, why, observed = _encoding_corroboration(send, tmpl, point, sig, state, res,
                                                                 bug_class, probe_url)
                    if alt is None and not observed:
                        # COULD NOT OBSERVE — a transport error or a lost channel on a re-encoding (a WAF,
                        # a rate limiter, a dropped keep-alive). VIGIL made no observation either way, so
                        # it concludes nothing: reporting this as "it correlates with the payload" asserted
                        # a measurement that was never taken AND silently discarded real arbitrary-file
                        # reads on every throttled target.
                        res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                        _note(res,
                              f"path_traversal: encoding corroboration COULD NOT BE OBSERVED [{surface}] — "
                              f"the signature appeared under {_TRAVERSAL_PAYLOAD!r}, but at least one "
                              f"re-encoding of the same path was NOT OBSERVABLE — no channel, a transport "
                              f"error, a status that is not a 2xx (a WAF 403, a 401, a redirect, a 404, a "
                              f"rate-limit or a 5xx), or a body VIGIL could not completely decode "
                              f"({why}); no observation was made either way, so nothing is concluded "
                              f"→ INCONCLUSIVE")
                        break     # bounded work: the channel is degraded, stop probing this endpoint
                    if alt is None:
                        _note(res,
                              f"path_traversal: encoding-corroboration refused [{surface}] — the signature "
                              f"appeared under {_TRAVERSAL_PAYLOAD!r} but every semantically-equivalent "
                              f"re-encoding of the same path was sent, answered, and OBSERVED not to carry "
                              f"it ({why}), so it tracks the literal payload rather than the path "
                              f"{_NOT_ADMITTED}")
                        break     # bounded work: the origin is keyed on the literal payload, not the path
                    _note(res, f"path_traversal: signature reproduced under the alternate encoding {alt!r} "
                               f"[{surface}] — consistent with a read, but NOT a proof of one: an endpoint "
                               f"that CANONICALISES the requested name answers every encoding identically, "
                               f"and one keyed on the BASENAME or a SUFFIX also answers the path-shaped "
                               f"control with a miss (branch path_traversal.file_signature is "
                               f"fact_capable:false) → LEAD")
                _admit(context, f"{probe_url}#{point.id}", surface,
                       fired=signal.fired, conclusive=signal.conclusive,
                       body_unreadable=treatment_unreadable)
                if signal.fired and res.admissions and res.admissions[-1][1] != "INCONCLUSIVE":
                    # One ADMITTED fire is decisive for a re-drive — stop (bounded work, ONE verdict record
                    # per bug). Previously this broke only on ``is_fact``; now that the branch is LEAD-only
                    # that condition is never true, and without this the arm would emit one signed LEAD per
                    # candidate parameter (the D4 duplicate-certificate defect, re-introduced by demotion).
                    #
                    # It must break on the ADMITTED verdict, not on ``signal.fired`` alone. A fired oracle
                    # over a body that was not semantically available (a truncated read: the signature sits
                    # in the prefix VIGIL holds, but the document is incomplete) admits INCONCLUSIVE — no
                    # record is produced at all — and breaking there ended the whole candidate-parameter
                    # walk on the FIRST unreadable response, losing every remaining insertion point.
                    break

        elif bug_class == "xss":
            chk = MarkerReflectionCheck(id="reflected-xss", bug_class="xss",
                                        payload_template="\"'><x{marker}>")
            for name in _candidate_query_names(url, _XSS_PARAMS):
                probe_url = _url_with_param(url, name)
                tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
                point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                              if p.name.lower() == name.lower()), None)
                if point is None:
                    continue
                before, before_bodies = state["channels"], state["body_unavailable"]
                try:
                    ctx_obj = chk.probe(tmpl, point, send)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"xss probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                if ctx_obj is None:
                    continue
                context = ctx_obj.to_verifier_context()
                signal = reflection_context_oracle(context.get("marker", ""), context.get("observed_sink", ""))
                # SOUND breakout ONLY: the canary must have become a live ELEMENT (html_tag). Mere presence
                # inside a <script> string literal or a <noscript> block is NOT a proven breakout (BLOCK-3 fix).
                ctxkind = (getattr(signal, "observed", {}) or {}).get("context")
                accepted = bool(signal.fired) and ctxkind == "html_tag"
                r = _admit(context, f"{probe_url}#{point.id}", f"query:{name}",
                           fired=accepted, conclusive=(signal.conclusive if accepted else False),
                           body_unreadable=state["body_unavailable"] > before_bodies)
                if getattr(r, "is_fact", False):
                    break     # one FACT is decisive for a re-drive — stop (bounded work, ONE cert per bug)

        elif bug_class == "ssi":
            # SSI (CWE-97): the RUNNER crafts a Server-Side Include directive pair carrying a PER-PROBE
            # RANDOM product; a fire needs the product PRESENT, the raw directive ABSENT (not merely
            # reflected), AND a benign no-directive control that LACKS the product — the computed-product
            # evaluation proof (ssi_evaluation_oracle). A page that echoes the directive verbatim as an
            # inert comment is the honest boundary and does not fire.
            for name in _candidate_query_names(url, _SSI_PARAMS):
                probe_url = _url_with_param(url, name)
                tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
                point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                              if p.name.lower() == name.lower()), None)
                if point is None:
                    continue
                # CONTROL first: a benign, non-directive value. Its body must NOT carry the (random) product.
                before, before_bodies = state["channels"], state["body_unavailable"]
                try:
                    control = send(tmpl.render(point, f"vigilbenign{nonce}"))
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"ssi control error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before:
                    res.inconclusive.append((bug_class, f"{probe_url}#control"))
                    continue
                control_body = _body_text(control)
                # TREATMENT: a fresh, UNPREDICTABLE product injected as an SSI set+echo directive pair. The
                # var name is nonce-scoped so the directive is well-formed and self-contained.
                n1 = secrets.randbelow(90000) + 10000
                n2 = secrets.randbelow(90000) + 10000
                product = str(n1 * n2)
                var = f"vc{nonce}"
                directive = f'<!--#set var="{var}" value="{n1}*{n2}" --><!--#echo var="{var}" -->'
                before2, before_bodies2 = state["channels"], state["body_unavailable"]
                try:
                    probe = send(tmpl.render(point, directive))
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"ssi probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before2:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                fc = FindingContext.from_ssi(directive, product, _body(probe),
                                             control_body=control_body, bug_class="ssi")
                context = fc.to_verifier_context()
                signal = ssi_evaluation_oracle(context.get("ssi_raw", ""), context.get("ssi_expected", ""),
                                               context.get("ssi_observed", ""), context.get("ssi_control"))
                r = _admit(context, f"{probe_url}#{point.id}", f"query:{name}",
                           fired=signal.fired, conclusive=signal.conclusive,
                           body_unreadable=state["body_unavailable"] > before_bodies2)
                if getattr(r, "is_fact", False):
                    break     # one FACT is decisive for a re-drive — stop (bounded work, ONE cert per bug)

        else:  # exposure — a request-level fixed-path probe with a random-path CONTENT-differential control
            # The runner fetches BOTH bodies and composes the predicate itself. It does NOT delegate the
            # control to ``PathProbeCheck``: that check returns a context for ANY status outside (0, 404)
            # and leaves the signature predicate UNEVALUATED inside it, so "control is not None" was a
            # STATUS test, not a signature differential. Against an origin that does not 404 unknown paths
            # (an SPA, a custom 404, a 403, a 500 — most of the modern web) that read as "the signature is
            # served everywhere", refused a genuine leak, and — worst of all — wrote a sentence into the
            # persisted audit trail asserting an observation that had never been made. Below, the soft-404
            # note is emitted ONLY from a signature actually seen in the control BODY, and the probe path is
            # fetched whatever the control's status was.
            tmpl = RequestTemplate(HttpRequest(method="GET", url=url))
            rand_path = f"/vigil-{nonce}-notfound"
            control_resp = None
            try:
                before_ctl = state["channels"]
                control_resp = _fetch_path(tmpl, send, rand_path)
                if state["channels"] <= before_ctl:
                    control_resp = None
            except Exception as e:  # noqa: BLE001
                res.notes.append(f"exposure control error [{rand_path}]: {type(e).__name__}: {e}")
                control_resp = None
            if control_resp is None:
                # No control ⇒ no differential ⇒ nothing here may be adjudicated (never a bare presence FACT).
                res.inconclusive.append((bug_class, f"{url}#control:{rand_path}"))
                res.notes.append("exposure: the random control path established no channel — without the "
                                 "differential a signature's presence is not adjudicable → INCONCLUSIVE")
            control_body = _body(control_resp) if control_resp is not None else ""
            control_status = int(control_resp.get("status", 0) or 0) if control_resp is not None else 0
            for probe_path, signature, corroborators, value_shaped in (
                    _EXPOSURE_PROBES if control_resp is not None else ()):
                surface = f"path:{probe_path}"
                res.surfaces.setdefault(bug_class, set()).add(surface)
                # CONTROL DIFFERENTIAL, evaluated by the RUNNER over the control BODY.
                if signature.lower() in control_body.lower():
                    _note(res,
                          f"exposure: control-differential refused [{probe_path}] — the signature "
                          f"{signature!r} was OBSERVED in the body of the random control path "
                          f"{rand_path!r} (status {control_status}), so it is served regardless of path "
                          f"(soft-404 / catch-all) and is not path-specific {_NOT_ADMITTED}")
                    continue
                before, before_bodies = state["channels"], state["body_unavailable"]
                try:
                    resp = _fetch_path(tmpl, send, probe_path)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"exposure probe error [{probe_path}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before:
                    res.inconclusive.append((bug_class, f"{url}#{probe_path}"))
                    continue
                status, body = int(resp.get("status", 0) or 0), _body(resp)
                if status in (0, 404):
                    continue      # not present — nothing to adjudicate (never a CLEAN either)
                if signature.lower() not in body.lower():
                    # THE SIGNATURE IS SIMPLY NOT THERE. Nothing to adjudicate and — decisively — nothing
                    # to SAY. Without this check the arm fell through to the value-shape branch below and
                    # composed a sentence out of a branch that had not executed: against a benign 200
                    # catch-all SPA with no secret anywhere it wrote "the signature 'DB_PASSWORD=' is
                    # present but 'DB_PASSWORD=' is not present in the body", asserting two unmade
                    # observations, contradicting itself inside one sentence, and persisting that into the
                    # audit trail. Presence is CHECKED before it is CLAIMED.
                    continue
                observed = {"status": status, "body": body, "probe_path": probe_path,
                            "control_status": control_status, "control_body": control_body,
                            "control_path": rand_path}
                preds: "list[dict]" = [
                    {"icontains": [{"var": "body"}, signature]},
                    {"not": {"icontains": [{"var": "control_body"}, signature]}},
                ]
                preds += [{"icontains": [{"var": "body"}, c]} for c in corroborators]
                if value_shaped:
                    # The signature's presence in ``body`` was OBSERVED above, so "is present but ..." is
                    # a claim the runner has already measured.
                    assignment, value, why = _secret_assignment(body, signature)
                    if not assignment:
                        # THE WRAPPER MAY NOT OUT-CLAIM ``why``. It used to append "so what was
                        # observed is a key being NAMED (documentation, a CI template, a bundled string,
                        # a shipped placeholder)" to EVERY refusal reason — an INFERENCE, and a false one
                        # whenever the reason is narrower than that: on a CR-terminated .env carrying a
                        # genuine credential the anchor refuses because the prefix on its line is
                        # non-blank, which is not evidence of documentation or a template. ``why`` is
                        # already hedged precisely; the tail now states only what follows from it for
                        # EVERY value of ``why`` (an empty right-hand side IS still an assignment, so
                        # "this is not an assignment" would be the same error in the other direction).
                        # Same class as D2 — do not let an unobserved claim back in through a wrapper.
                        _note(res,
                              f"exposure: value-shape refused [{probe_path}] — the signature "
                              f"{signature!r} is present in the body but {why}, so this occurrence does "
                              f"not evidence a leaked value {_NOT_ADMITTED}")
                        continue
                    observed["secret_assignment"] = assignment
                    observed["secret_value"] = value
                    preds += _secret_value_predicates(signature)
                fc = FindingContext.from_predicate(observed, {"all": preds}, bug_class="exposure")
                context = fc.to_verifier_context()
                signal = predicate_oracle(context.get("observed_evidence", {}), context.get("predicate", {}))
                _admit(context, f"{url}#{probe_path}", surface,
                       fired=signal.fired, conclusive=signal.conclusive,
                       body_unreadable=state["body_unavailable"] > before_bodies)
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"runtime_redrive error: {type(e).__name__}: {e}")
    return res


# =====================================================================================================
# W2 — shared machinery + the three new response-derived FACT arms (SSTI / boolean-blind / time-based).
# =====================================================================================================


def _candidate_names_hint(url: str, base_names: "tuple[str, ...]", hint: "str | None",
                          max_names: int) -> "list[str]":
    """The candidate query-parameter names to probe: the finding's OWN declared ``hint`` param FIRST (so the
    endpoint's real parameter is exercised), then the URL's existing params, then the well-known set —
    de-duped case-insensitively and capped to ``max_names``. Purely lexical (no network)."""
    names = _candidate_query_names(url, base_names)
    if hint and hint.strip():
        h = hint.strip()
        names = [h] + [n for n in names if n.lower() != h.lower()]
    return names[:max_names]


def _admit_one(res: "RuntimeRedriveResult", *, branch: str, bug_class: str, engagement_slug: str,
               signers: "list[tuple[str, str]]", context: dict, item: str, surface: str,
               fired: bool, conclusive: bool, body_unreadable: bool) -> Any:
    """Admit ONE branch outcome against its declared capability and, on a FACT-capable fire, mint a signed,
    offline-re-verifiable certificate over VIGIL's OWN reproduced context (provenance=live_redrive). A
    standalone twin of the ``_admit`` closure in :func:`runtime_redrive`, shared by the three W2 arms so the
    admission + certification discipline is identical. Returns the ``AdapterResult`` (``.is_fact``)."""
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, compose  # noqa: PLC0415

    res.surfaces.setdefault(bug_class, set()).add(surface)
    observed = {"channel_established": True, "body_semantically_available": not body_unreadable,
                "gate_authorized": True}
    finding = {"check_id": f"rt:{bug_class}:{item}#{branch}", "bug_class": bug_class,
               "insertion_point": item, "oracle_context": context}
    admitted = admit(branch, fired=fired, conclusive=conclusive, observed=observed)
    res.admissions.append((branch, admitted.verdict.value, admitted.reason))
    bm = res.branch_verdicts.setdefault(bug_class, {})
    prior = bm.get(branch)
    bm[branch] = compose([prior, admitted.verdict.value]).value if prior else admitted.verdict.value
    r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                         provenance="live_redrive")
    res.contexts[r.finding_ref] = context
    if r.is_fact:
        res.facts.append(r)
    elif admitted.verdict is Verdict.INCONCLUSIVE:
        res.inconclusive.append((bug_class, f"{item}#{branch}"))
    else:
        res.leads.append(r)
    return r


def _stat_setup(url: str, slug: str, bug_class: str, branch: str, timeout: float):
    """Shared preamble for the three W2 arms: build the result, verify the branch is REGISTERED (fail-closed),
    run the URL-shaped charter gate BEFORE any traffic, and open the reviewed gated send. Returns
    ``(res, send, state)`` on success, or ``(res, None, None)`` when the arm must return early (unregistered
    branch / gate refusal)."""
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from .verdict import branch_ids  # noqa: PLC0415
    from .web_redrive import _gated_web_send  # noqa: PLC0415 — the reviewed gated, DNS-pinned, no-proxy send

    res = RuntimeRedriveResult(url=url, bug_class=bug_class)
    if branch not in branch_ids():
        res.notes.append(f"branch {branch!r} is not registered — cannot admit (fail-closed)")
        return res, None, None
    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res, None, None
    send, state = _gated_web_send(slug, timeout=timeout)
    return res, send, state


def ssti_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                 param: "str | None" = None, timeout: float = 8.0) -> "RuntimeRedriveResult":
    """Re-drive ``url`` for SERVER-SIDE TEMPLATE / EXPRESSION-LANGUAGE injection and mint a signed FACT ONLY
    when the deterministic ``evaluation_oracle`` confirms the server EVALUATED a runner-injected expression:
    a PER-PROBE random product ``N1*N2`` present in the FRESH response body, the raw expression ABSENT
    (reflected-verbatim ⇒ a conclusive clean, not a fire), and a benign no-expression CONTROL lacking it.

    FP boundary (all → LEAD): a raw expression that survives unevaluated (reflected==sent), a product present
    in the benign control, and an arithmetic coincidence (guarded by the unique per-probe product + raw-absent
    check). Never raises."""
    import secrets  # noqa: PLC0415 — per-probe UNPREDICTABLE product (not learning/reward rng)

    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.adapter import FindingContext  # noqa: PLC0415
    from framework.v2.verify.oracles import evaluation_oracle  # noqa: PLC0415

    bug_class = "ssti"
    res, send, state = _stat_setup(url, slug, bug_class, _SSTI_BRANCH, timeout)
    if send is None:
        return res
    nonce = _sha(url)
    try:
        for name in _candidate_names_hint(url, _SSTI_PARAMS, param, _MAX_CANDIDATE_NAMES):
            probe_url = _url_with_param(url, name)
            tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
            point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                          if p.name.lower() == name.lower()), None)
            if point is None:
                continue
            # CONTROL first: a benign, non-expression value. Its body must NOT already carry the product.
            before = state["channels"]
            try:
                control = send(tmpl.render(point, f"vigilbenign{nonce}"))
            except Exception as e:  # noqa: BLE001
                res.notes.append(f"ssti control error [{name}]: {type(e).__name__}: {e}")
                continue
            if state["channels"] <= before:
                res.inconclusive.append((bug_class, f"{probe_url}#control"))
                continue
            control_body = _body_text(control)
            fired_here = False
            for tpl in _SSTI_EXPR_TEMPLATES:
                n1 = secrets.randbelow(90000) + 10000
                n2 = secrets.randbelow(90000) + 10000
                product = str(n1 * n2)
                payload = tpl.format(n1=n1, n2=n2)
                before2, before_bodies2 = state["channels"], state["body_unavailable"]
                try:
                    probe = send(tmpl.render(point, payload))
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"ssti probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before2:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                fc = FindingContext.from_evaluation(payload, product, _body_text(probe),
                                                    control_body=control_body, bug_class="ssti")
                context = fc.to_verifier_context()
                signal = evaluation_oracle(context.get("eval_raw", ""), context.get("eval_expected", ""),
                                           context.get("eval_observed", ""), context.get("eval_control"))
                r = _admit_one(res, branch=_SSTI_BRANCH, bug_class=bug_class,
                               engagement_slug=engagement_slug, signers=signers, context=context,
                               item=f"{probe_url}#{point.id}", surface=f"query:{name}",
                               fired=signal.fired, conclusive=signal.conclusive,
                               body_unreadable=state["body_unavailable"] > before_bodies2)
                if r.is_fact:
                    fired_here = True
                    break
            if fired_here:
                break     # one FACT is decisive for a re-drive — stop (bounded work)
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"ssti_redrive error: {type(e).__name__}: {e}")
    return res


def _determinism_baseline(tmpl, point, send, value: str, n: int = _BOOLEAN_BASELINE_SAMPLES) -> tuple:
    """``n`` responses to ONE BYTE-IDENTICAL request — the boolean oracle's determinism PRE-FILTER, collected
    ONCE PER PARAM and shared by every clause family (determinism is a property of the endpoint, not of the
    clause). Short-circuits on the first divergence: a non-deterministic endpoint is proven with two samples
    and the oracle refuses over them, so there is no reason to spend the other six. Returns ``()`` if a send
    fails, which makes the check collect its own (fail-safe, never a fabricated baseline)."""
    from framework.v2.verify.oracles import differential_response_oracle  # noqa: PLC0415
    from framework.v2.scanner.checks import BOOLEAN_DISCRIMINATOR  # noqa: PLC0415
    out: list = []
    try:
        for _ in range(max(2, n)):
            r = send(tmpl.render(point, value))
            out.append(r if isinstance(r, dict) else {"body": str(r)})
            if differential_response_oracle(out[0], out[-1], BOOLEAN_DISCRIMINATOR).fired:
                break
    except Exception:  # noqa: BLE001 — a send failure means "collect it the ordinary way", never a fake
        return ()
    return tuple(out)


def boolean_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                    param: "str | None" = None, timeout: float = 8.0, n_max: int = 14) -> "RuntimeRedriveResult":
    """Re-drive ``url`` for BOOLEAN-BLIND injection and mint a signed FACT ONLY when the deterministic
    ``boolean_inference_oracle`` reaches its SPRT confirm boundary over N runner-crafted TRUTH-VALUE
    ATTRIBUTION rounds. Reuses the reviewed ``BooleanInferenceCheck`` discipline over VIGIL's OWN gated send:
    each round sends 7 DISTINCT always-TRUE clauses and 7 DISTINCT always-FALSE clauses (one
    ``scanner.checks.boolean_clause_families`` entry — shape-varied, a stable public constant), each twice
    byte-identically, and signals only when the response is a FUNCTION of the injected boolean's TRUTH
    VALUE — one TRUE cluster, one FALSE cluster, disjoint.

    FP boundary (all → LEAD): an endpoint whose response varies INDEPENDENTLY of the input — coarse
    (low-cardinality), SKEWED, or high-entropy — cannot make 14 true-side and 14 false-side draws split
    cleanly by truth value (``<= 7.5e-9`` per round, vs the SPRT's ``p0 = 0.1``), so it refutes; a single flip
    without SPRT significance ⇒ inconclusive. A legitimately noisy-but-vulnerable page is a LEAD (a recall
    cost, the safe direction). Never raises.

    PER-URL EXPOSURE, STATED (independent attempts MULTIPLY a per-attempt residual, so the count is bounded
    and the product is named rather than left implicit). The dominant residual is the oracle's case (b): an
    endpoint that is a DETERMINISTIC but arbitrary function of the URL (a per-URL CDN cache over an origin
    that picked a variant at fill time), where repetition is not new evidence. Measured over the real mint
    path on a uniform 2-variant cached page: ``1.20e-4`` per attempt at the shipped ``K = 7`` (200k trials;
    analytic ``2 * 2**-(K_T+K_F)`` = ``1.22e-4``). This arm makes at most ``_BOOLEAN_MAX_PARAMS`` (2) params
    x 3 families = 6 independent attempts per URL, so the per-URL figure is ``1 - (1 - 1.20e-4)**6`` =
    ``~7.3e-4`` (0.073%); a TARGETED re-drive of a KNOWN param is 3 attempts => ``~3.7e-4``.

    That figure is the honest cost of this class, not a claim of safety: it applies ONLY to an endpoint that
    is input-independent AND frozen per URL. It replaces what an earlier revision shipped — K=4 over 4
    params = 12 attempts x a measured 7.98e-3 = ``~9.2%`` per URL, undisclosed. K was raised 4 -> 7 and the
    attempts halved 12 -> 6; going further trades against recall (every extra clause is another chance a real
    vulnerable target answers one of them differently and the round refutes). The OTHER residual — an
    interposer that partitions the probes by a request property with no boolean channel behind it — is
    residual (a) on the oracle and it is OPEN: the clause families make every INCOMPLETE filter refute, but a
    filter COMPLETE over the shape set partitions them (measured 600/600 on a static page), and no clause set
    can fix that, because a clause whose truth we know a priori is a constant expression a filter can fold
    too. This arm is not sound against a filter purpose-built for this clause set.

    TRAFFIC BUDGET (constitution VI — this runs against live authorized production). Per param: ONE shared
    determinism baseline of 8 identical sends (determinism is a property of the ENDPOINT, not of the clause,
    so it is collected once and reused by all three families) + 28 sends per SPRT round. A deterministic
    endpoint decides in 2 rounds, so the MEASURED ordinary cost is ``8 + 3 x 56 = 176`` gated requests per
    param and ``352`` per URL at 2 params; the bound is ``8 + 3 x (n_max x 28)`` = 1184/param (2368/URL) in
    the pathological oscillating case that two same-direction rounds normally prevent. A NON-deterministic
    endpoint costs 2 sends total — the shared baseline proves it in two and all three families short-circuit."""
    from framework.v2.scanner.checks import (  # noqa: PLC0415
        BooleanInferenceCheck, boolean_clause_families)
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.oracles import boolean_inference_oracle  # noqa: PLC0415

    bug_class = "boolean_sqli"
    # A STABLE PUBLIC CONSTANT — the same clauses every run, so the operator can correlate them in
    # their logs and the run is replayable (see the header, and constitution VI.4).
    families = boolean_clause_families()
    res, send, state = _stat_setup(url, slug, bug_class, _BOOLEAN_BRANCH, timeout)
    if send is None:
        return res
    # A targeted re-drive of a KNOWN param probes ONLY that param (mirrors the errsig arm — bounded work on
    # the expensive SPRT arm); a captureless finding with no declared param falls back to the candidate set,
    # capped at _BOOLEAN_MAX_PARAMS so the number of INDEPENDENT attempts per URL (and hence the multiplied
    # per-URL residual stated in the docstring) stays bounded.
    max_params = 1 if param else _BOOLEAN_MAX_PARAMS
    try:
        for name in _candidate_names_hint(url, _BOOLEAN_PARAMS, param, max_params):
            probe_url = _url_with_param(url, name)
            tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
            point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                          if p.name.lower() == name.lower()), None)
            if point is None:
                continue
            # ONE determinism baseline per PARAM, shared by all three clause families: determinism is a
            # property of the endpoint, not of the clause, so re-sending it per family was 2/3 waste.
            shared_baseline = _determinism_baseline(tmpl, point, send, families[0][1][0])
            fired_here = False
            for true_clauses, false_clauses in families:
                chk = BooleanInferenceCheck(id="boolean-redrive", bug_class="boolean_sqli",
                                            true_clauses=true_clauses, false_clauses=false_clauses,
                                            n_max=n_max, shared_baseline=shared_baseline)
                before, before_bodies = state["channels"], state["body_unavailable"]
                try:
                    fc = chk.probe(tmpl, point, send)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"boolean probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before or fc is None:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                context = fc.to_verifier_context()
                # The oracle recomputes the TRUTH-VALUE ATTRIBUTION decision over the retained rounds; the
                # determinism baseline the check collected (identical false-clause sends) rides along as the
                # cheap pre-filter a confirm additionally requires (fail-closed).
                signal = boolean_inference_oracle(context.get("probe_rounds"),
                                                  discriminator=context.get("discriminator"),
                                                  false_baseline_samples=context.get("false_baseline_samples"))
                r = _admit_one(res, branch=_BOOLEAN_BRANCH, bug_class=bug_class,
                               engagement_slug=engagement_slug, signers=signers, context=context,
                               item=f"{probe_url}#{point.id}", surface=f"query:{name}",
                               fired=signal.fired, conclusive=signal.conclusive,
                               body_unreadable=state["body_unavailable"] > before_bodies)
                if r.is_fact:
                    fired_here = True
                    break
            if fired_here:
                break
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"boolean_redrive error: {type(e).__name__}: {e}")
    return res


def timing_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                   param: "str | None" = None, timeout: float = 8.0, samples: int = 6) -> "RuntimeRedriveResult":
    """Re-drive ``url`` for TIME-BASED blind injection and mint a signed FACT ONLY when the deterministic
    ``timing_oracle`` confirms a delay: a Mann-Whitney U rejection, a Hodges-Lehmann median shift clearing the
    effect-size floor, AND a dose-response that SCALES with the injected delay (a low + a high SLEEP dose).
    Benign and delay-injecting requests are interleaved (the reviewed ``TimingCheck`` discipline) so drift
    biases both equally, over VIGIL's OWN gated send.

    FP boundary (all → LEAD): a uniformly slow/loaded endpoint (the test fails to reject / the floor is not
    cleared), a one-off latency spike (no distribution shift), and a constant offset with no dose-response
    (the ratio fails to scale). Never raises."""
    from framework.v2.scanner.checks import TimingCheck  # noqa: PLC0415
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.oracles import timing_oracle  # noqa: PLC0415

    bug_class = "time_based_sqli"
    res, send, state = _stat_setup(url, slug, bug_class, _TIMING_BRANCH, timeout)
    if send is None:
        return res
    low_ms, high_ms = _TIMING_LOW_S * 1000.0, _TIMING_HIGH_S * 1000.0
    # A targeted re-drive of a KNOWN param probes ONLY that param (mirrors the errsig arm — bounded work on
    # the expensive timing arm); a captureless finding with no declared param falls back to the candidate set.
    max_params = 1 if param else _STAT_MAX_PARAMS
    try:
        for name in _candidate_names_hint(url, _TIMING_PARAMS, param, max_params):
            probe_url = _url_with_param(url, name)
            tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
            point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                          if p.name.lower() == name.lower()), None)
            if point is None:
                continue
            fired_here = False
            for tpl in _TIMING_SLEEP_TEMPLATES:
                low = tpl.format(s=_TIMING_LOW_S)
                high = tpl.format(s=_TIMING_HIGH_S)
                chk = TimingCheck(id="timing-redrive", bug_class="time_based_sqli",
                                  benign=f"vigilbenign{_sha(name)}", sleep_payload=low, injected_ms=low_ms,
                                  samples=samples, dose_payload=high, dose_ms=high_ms)
                before = state["channels"]
                try:
                    fc = chk.probe(tmpl, point, send)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"timing probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before or fc is None:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                context = fc.to_verifier_context()
                signal = timing_oracle(context.get("baseline_latencies") or [],
                                       context.get("treatment_latencies") or [],
                                       injected_ms=context.get("timing_injected_ms"),
                                       alpha=float(context.get("timing_alpha", 0.01)),
                                       dose=context.get("timing_dose"))
                # Timing is service-response (latency) derived, not body-derived — body readability is
                # irrelevant to this branch, so it never gates the admission.
                r = _admit_one(res, branch=_TIMING_BRANCH, bug_class=bug_class,
                               engagement_slug=engagement_slug, signers=signers, context=context,
                               item=f"{probe_url}#{point.id}", surface=f"query:{name}",
                               fired=signal.fired, conclusive=signal.conclusive, body_unreadable=False)
                if r.is_fact:
                    fired_here = True
                    break
            if fired_here:
                break
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"timing_redrive error: {type(e).__name__}: {e}")
    return res


def injection_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                      claimed_class: str, param: "str | None" = None, timeout: float = 8.0
                      ) -> "RuntimeRedriveResult":
    """Governed-engage re-drive for ``nosqli`` / ``ldap_injection`` / ``xpath_injection``. It DRIVES VIGIL's
    OWN gated probe end-to-end and records an admitted LEAD; it mints **NO FACT** — both registered branches
    for these classes are ``fact_capable: false``, so ``admit`` demotes even a fired oracle to a LEAD.

    WHY LEAD-ONLY (red-pen BLOCK, fixed here). ``error_signature_oracle`` is a STRING MATCH; a fire over
    VIGIL's fresh bytes proves only that a datastore-error-shaped string was emitted CONDITIONALLY on the
    payload (present on the probe, absent from the benign control). That is NECESSARY but NOT SUFFICIENT for a
    query break: the benign control twin rules out only UNCONDITIONAL emission, so a signature emitted
    conditionally by a NON-datastore source — a WAF/security-filter block page that names the engine, an
    input-validator rejection, or an unrelated 500 whose stack trace merely names the driver package — passes
    the guard (four such false FACTs were reproduced at rate 1.0, one of them a high-frequency real-world case).
    The SOUND FACT path is a break-vs-repair PARSER-STATE-TOGGLE causation oracle re-executed OFFLINE (a new
    OracleKind, out of this reuse-only slice's scope) — see the branches' ``blocking_work``.

    WHAT IT STILL DOES (real evidence for a human, same rationale as the DRIVEN-but-LEAD path_traversal arm):
      * the RUNNER sends its OWN class-specific error-provoking probe (``_INJECTION_ERRSIG_PAYLOAD``) — the
        Strix/LLM payload is never trusted — plus a benign CONTROL twin fetched FIRST;
      * the oracle observes whether the matched engine string appeared conditionally, and the LEAD is admitted
        only under the ENGINE that NAMES the claimed class (``_INJECTION_ENGINE_FOR``); a mismatched/unmapped
        engine is not admitted for this class, so even the LEAD stays class-appropriate.

    A gate refusal / no channel / an unreadable-or-empty body / an oracle non-fire / the same error in the
    control / a mismatched engine all leave the finding a LEAD. Not CLEAN-capable either (a non-firing is
    uninformative). Runs ONLY the claimed class. Never raises.

    FATAL-2: every framework-touching import is function-local (offense-side re-drive path)."""
    from framework.v2.evidence.poc import CapturedExchange  # noqa: PLC0415 (FATAL-2: offense plane)
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.oracles import error_signature_oracle  # noqa: PLC0415
    from framework.v2.verify.poc_translate import context_from_exchanges  # noqa: PLC0415
    from framework.v2.verify.verifier import normalize_bug_class  # noqa: PLC0415

    bug_class = normalize_bug_class(claimed_class)
    if bug_class not in INJECTION_REDRIVE_CLASSES:
        res = RuntimeRedriveResult(url=url, bug_class=bug_class)
        res.notes.append(f"{bug_class!r} is not an injection-redrive class")
        return res
    branch = _INJECTION_ERRSIG_BRANCH[bug_class]
    payload = _INJECTION_ERRSIG_PAYLOAD[bug_class]
    expected_engines = _INJECTION_ENGINE_FOR[bug_class]
    res, send, state = _stat_setup(url, slug, bug_class, branch, timeout)
    if send is None:
        return res
    nonce = _sha(f"{url}:{bug_class}")
    try:
        for name in _candidate_names_hint(url, _INJECTION_PARAMS, param, _MAX_CANDIDATE_NAMES):
            probe_url = _url_with_param(url, name)
            tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
            point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                          if p.name.lower() == name.lower()), None)
            if point is None:
                continue
            # CONTROL FIRST — a benign, metacharacter-free value on the SAME endpoint+param, so any datastore
            # error is attributable to the PAYLOAD, not to the parameter's mere presence.
            before_c = state["channels"]
            try:
                control = send(tmpl.render(point, f"vfctl{nonce}"))
            except Exception as e:  # noqa: BLE001
                res.notes.append(f"injection control error [{name}]: {type(e).__name__}: {e}")
                continue
            if state["channels"] <= before_c:
                res.inconclusive.append((bug_class, f"{probe_url}#control"))
                continue
            control_bytes = _body_text(control).encode("utf-8", errors="replace")
            # TREATMENT — VIGIL's OWN runner-crafted metacharacter payload.
            before_t = state["channels"]
            try:
                probe = send(tmpl.render(point, payload))
            except Exception as e:  # noqa: BLE001
                res.notes.append(f"injection probe error [{name}]: {type(e).__name__}: {e}")
                continue
            if state["channels"] <= before_t:
                res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                continue
            observed_text = _body_text(probe)
            if not observed_text:
                res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                continue     # a real channel but no readable body → the oracle cannot fire → INCONCLUSIVE
            observed_bytes = observed_text.encode("utf-8", errors="replace")
            # the oracle over VIGIL's FRESH bytes, WITH the control twin. The control rules out only
            # UNCONDITIONAL emission; a fire here is CONDITIONAL emission of an error-shaped string — necessary
            # but NOT sufficient for a query break (a WAF/validator/unrelated-500 passes it), so it is a LEAD.
            sig = error_signature_oracle(observed_bytes, control_bytes)
            if not getattr(sig, "fired", False):
                # no engine error string, or the SAME string rides the benign control → nothing to admit.
                _note(res, f"error_signature did not fire for {bug_class} → LEAD")
                continue
            engine = str((getattr(sig, "observed", None) or {}).get("engine", ""))
            if engine not in expected_engines:
                # a real datastore error, but NOT the engine that names this class — the evidence proves a
                # DIFFERENT class; refuse rather than mislabel (fail-closed, mirrors the Strix rail).
                _note(res, f"error_signature matched engine {engine!r}, not {sorted(expected_engines)} for "
                           f"{bug_class} → LEAD (the evidence proves a different class, not this one)")
                continue
            # Build the error_signature context (observed + control) and admit it. admit() DEMOTES this to a
            # LEAD because the branch is fact_capable:false — no FACT is minted (the re-driven capture is
            # retained on the result as real, class-appropriate evidence for the operator). Same context shape
            # as the Strix rail (``context_from_exchanges`` + ``model_dump``).
            blobs = {"inj_obs": observed_bytes, "inj_ctrl": control_bytes}
            exchanges = [
                CapturedExchange(channel="error_signature", role="mutated",
                                 response_bytes_ref="inj_obs", status=probe.get("status")),
                CapturedExchange(channel="error_signature", role="control",
                                 response_bytes_ref="inj_ctrl", status=control.get("status")),
            ]
            ctx = context_from_exchanges(exchanges, bug_class=bug_class, resolve=blobs.get)
            if ctx is None:
                res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                continue
            context = ctx.model_dump(mode="json")
            _admit_one(res, branch=branch, bug_class=bug_class, engagement_slug=engagement_slug,
                       signers=signers, context=context, item=f"{probe_url}#{point.id}",
                       surface=f"query:{name}", fired=True, conclusive=True, body_unreadable=False)
            break     # one admitted (class-appropriate) capture is enough for a re-drive — stop (bounded work)
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"injection_redrive error: {type(e).__name__}: {e}")
    return res


def _sha(s: str) -> str:
    """A short, deterministic content-address token (no wallclock/rng) — used for benign control markers and
    per-probe nonces so a re-drive is replayable and the oracle re-fires identically offline."""
    import hashlib  # noqa: PLC0415 — stdlib
    return hashlib.sha256(str(s).encode("utf-8")).hexdigest()[:12]


def _body_text(resp: Any) -> str:
    """The response body as text (module-level twin of the ``_body`` closure in :func:`runtime_redrive`)."""
    return str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)
