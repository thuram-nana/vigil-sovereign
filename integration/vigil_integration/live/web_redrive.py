"""web_redrive — a runner-owned, gated HTTP re-drive → ACHIEVED_STATE FACT (Wave #3, the web column).

A web tool (httpx / katana / nuclei) PROPOSES a URL; this re-drives it — the RUNNER (never the tool) crafts
the probe, sends it through a GATED HTTP client, and the existing deterministic ``predicate_oracle`` judges
the captured response. It mints a signed, offline-re-verifiable FACT for the web classes whose predicate is
a DEFINITE, EXPLOITABLE proposition over observed values (scoped to the co-located condition, not a loose
substring match — a benign reflecting page does not false-FACT):

  * open_redirect   — a 30x whose Location host == the injected canary host (or a meta/JS redirect to it);
  * cors            — Access-Control-Allow-Origin reflects the evil origin (or ``*``) AND ...-Credentials=true;
  * host_header_injection — a hostile Host header became a redirect Location authority (or a ``//evil`` in body);
  * graphql_introspection — VIGIL's OWN introspection query returns a well-formed schema (data.__schema.types).

It REUSES the shipped ``scanner.checks`` probes verbatim (same crafting + the exact predicate the oracle
already trusts) driven by a gated ``send`` — so nothing about the oracle or the predicate is reinvented; only
the transport is made charter-gated. A grype/nuclei match never mints a FACT; only this re-drive + the oracle
do (criterion-6). ``provenance="live_redrive"`` — the evidence is the runner's own live, gated capture.

FATAL-2: framework + urllib imports are FUNCTION-LOCAL; importing this module co-loads no offense engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

# the web classes this wave mints as FACTs (each has a definite, exploitable-condition ACHIEVED_STATE predicate).
WEB_FACT_CLASSES = ("open_redirect", "cors", "host_header_injection", "graphql_introspection",
                    "oidc_redirect_uri")

# The subset of WEB_FACT_CLASSES a re-drive may mint from an LLM-SUPPLIED class claim (the autonomous engage
# seam, wiring._live_web_redrive_fact). oidc_redirect_uri is EXCLUDED: its distinguishing A07 impact (a broken
# redirect_uri at an OAuth/OIDC authorization endpoint that leaks the auth code/token) is NOT verified by any
# predicate — the live evidence is byte-identical to a plain open_redirect (a 3xx Location to the canary
# host), so the OIDC classification rests ENTIRELY on the claimant's label. That is defensible when the claim
# is a tool report (proof.run, where web_redrive still accepts oidc), but NOT when the claim is the model's
# free text: an honest / hallucinating / prompt-injected LLM could label a plain open redirect "oidc" and
# obtain a signed A07 certificate the deterministic layer only proved as A01. Until an OIDC-specific oracle
# (independent code/token evidence) exists, the LLM-claim seam never upgrades to oidc. (red-pen BLOCK-1)
LLM_CLAIM_WEB_FACT_CLASSES = tuple(c for c in WEB_FACT_CLASSES if c != "oidc_redirect_uri")

# ---------------------------------------------------------------------------
# HexStrike W2 — SIBLING RESPONSE DIFFERENTIAL.  *** LEAD-ONLY, PERMANENTLY. ***
# Shipped bug-class token: ``sibling_response_differential``. Evidence-branch id (an internal admission key,
# not a shipped claim): ``achieved_state.endpoint_liveness``, declared fact_capable=false AND
# clean_capable=false in ``docs/capability-matrix/evidence-branches.json`` — so ``verdict.admit()`` maps a
# FIRED oracle on this branch to a LEAD and a conclusive non-firing to INCONCLUSIVE. The branch REGISTRY,
# not this module, is the choke: everything below still RUNS, and its capture is attached as LEAD evidence.
#
# WHY IT IS A LEAD. Five adversarial rounds, and every single one found a NEW class of URL where NOTHING
# EXISTS and this predicate minted a signed, offline-RE-VERIFYING FACT. Rounds 1-4 are the history further
# down (each of their fixes is still in the code and still does its job). Round 5 found two more classes:
#
#   (A) PER-POSITION FORMAT ROUTES (``^report\d$``, ``^user\d{3}$``, ``^dashboard\d$``). The sibling cohorts
#       do NOT mirror the target's per-position class. :func:`_alnum_class_alphabet` unions the alnum
#       characters of the WHOLE segment into ONE class, and BOTH :func:`_same_shape_sibling` and
#       :func:`_hamming1_probe_urls` draw EVERY alnum position from that single union alphabet; only the
#       NON-alnum separators are preserved per position. So on a word+digits identifier a Hamming-1 edit at
#       a DIGIT slot becomes a LETTER about 74% of the time, the route rejects it, no twin is found, and the
#       FACT mints for a url where nothing exists. MEASURED: 11/100, 32/100 and 55/100 on the direct
#       re-drive and 29-40/80 through BOTH runner legs, every one re-verifying offline.
#   (B) SKEWED PER-PATH BOUNDED NOT-FOUND BODY SPACE: 13/100 direct at P(B)=1/20, 9/80 through the httpx
#       leg, 13/80 through the ffuf leg.
#
# DECISIVE. On one route where ``/o/dashboard9`` EXISTS and ``/o/dashboard1`` does NOT, the predicate minted
# 40/40 for the existing id and 21/40 for the nonexistent one — it barely discriminates. And the honest
# narrowing (below) already disclaims not-found-ness, phantom-ness, existence AND liveness, so the
# proposition that survives does not justify a signed FACT at confidence 0.9. Each round's fix narrowed the
# CLAIM rather than strengthening the EVIDENCE; that is a ratchet, and it stops here.
#
# WHAT IS KEPT, AND WHY. The gated GETs, the same-branch baseline, the k=4 multi-sampling, the
# validator-aware controls and the NO-TWIN minimal-edit-distance cohort ALL still run, and the retained
# capture — every raw per-sample status and body hash, plus ``control_urls`` and ``probe_urls`` — is
# attached to the LEAD and re-verifies offline. That is genuinely high-quality lead evidence: it tells a
# human which siblings and which neighbours were probed and exactly what each returned, which is worth real
# triage priority. It is simply not a fact about the world, so it never mints.
#
# THE CAPTURE'S PROPOSITION — see :func:`_liveness_claim`, the one place it is written:
#
#     VIGIL's own gated GET of this URL returned content that DIFFERS from the server's stable same-status
#     response to N randomized same-shape siblings, and NO minimal-edit-distance sibling returned that same
#     response.
#
# It asserts NOTHING about not-found-ness, phantom-ness, existence or liveness.
#
# WITHDRAWN CLAIMS — each was measurably FALSE. Do not reintroduce any of them:
#   * "distinguishable from a NOT-FOUND baseline" / "not a soft-404 phantom of that shape": in the validator
#     classes the siblings' stable answer is the route's REJECT body and the TARGET is the phantom.
#   * "the sibling mirrors the target's EXACT per-position class/structure": FALSE — it is a per-SEGMENT
#     UNION class (only the non-alnum separators are per-position). See (A) above.
#   * "the LOCAL-constraint family (prefix / suffix / positional / format rule) is CLOSED ... 0/80 on all
#     three paths": FALSE — falsified at 11-55% by the FORMAT sub-family. The prefix/suffix/positional
#     variants measure 0/80 only because their reject rule happens to be satisfied by a union-alphabet
#     neighbour; a per-position format rule is not.
#   * "the RESIDUAL is an unknown validator constraining the identifier JOINTLY ACROSS POSITIONS / a
#     whole-string checksum": this materially UNDERSTATED it. The true condition is "NO Hamming-1 neighbour
#     OVER THE MIRROR (UNION) ALPHABET is accepted", which also covers ordinary word+digits FORMAT routes.
#   * "bounded not-found body space (per REQUEST or per PATH) ... measured at 0": FALSE for the SKEWED
#     per-path variant (13/100 direct, 9/80 httpx, 13/80 ffuf). The per-REQUEST variant does measure 0 at k=4.
#   * "the AST proves the whole partition ... and cannot be cherry-picked after the fact" and "the
#     certificate cannot claim a neighbourhood search that did not happen": FALSE. The AST proves relations
#     only among the samples the runner RETAINED. A runner that retained a subset would emit a predicate
#     that re-verifies perfectly over what is left. RETENTION COMPLETENESS IS A TRUST BOUNDARY, NOT A PROOF
#     — the RUNNER is the prover here, exactly as it already was for the baseline cohort, and an offline
#     verifier re-checks the retained capture, never that the capture is complete.
#   * "bounded ... raising _LIVENESS_CONTROLS trades traffic for it": measured 40/40 at N=10, 40/40 at
#     N=160, 15/15 at N=640. More baseline siblings do not mitigate an in-branch reject.
#
# A web-discovery tool (httpx / ffuf / …) PROPOSES a URL; the RUNNER (never the tool) sends PLAIN gated GETs
# (no canary) and the EXISTING ACHIEVED_STATE predicate_oracle adjudicates. Reuses ACHIEVED_STATE (no new
# OracleKind, so `make gate` stays byte-identical). OPSEC: one re-drive costs up to
# :data:`MAX_GATED_GETS_PER_URL` SERIAL gated GETs, which is why the runner leg caps how many proposed urls
# it re-drives (``external_tool._LIVENESS_REQUEST_BUDGET``).
#
# THE FIREWALL THAT STILL RUNS (each round's fix closed a class that MINTED a false FACT on the preceding
# HEAD; all of them still demote, which is what makes the LEAD worth reading):
#   BLOCK-1 (coarse char-class): a control of a WIDER class than the route (a random alnum control on a
#     hex/uuid route) 404s as a route-MISS while a well-formed nonexistent target soft-404s 200 → false
#     FACT. Fixed by a NARROW-CLASS, structure-preserving mirror: every alnum position is drawn from the
#     narrowest well-known class containing EVERY alnum character of the segment (digits, hex, alpha,
#     alnum …), with the non-alnum separators, the length and the extension preserved. NOTE the correction
#     above: that is a per-SEGMENT union class, NOT a per-POSITION class, which is exactly the hole round 5
#     walked through. An AMBIGUOUS class (all a–f letters: both alpha and hex) fails CLOSED, as does a
#     root/directory URL with no last segment.
#   BLOCK-2 (bounded not-found body space): a soft-404 whose not-found body is one of a SMALL set (random
#     per request, or per path) let two controls COLLIDE on one body ~1/b of the time → a spurious "stable
#     baseline" → an INTERMITTENT false FACT. Fixed by MULTI-SAMPLE stability: many DISTINCT same-shape
#     controls, EACH resampled k=4 times, and the target itself resampled; a control that is unstable INSIDE
#     the target's own branch is AMBIGUOUS and fails the whole run CLOSED. Closed for the per-REQUEST
#     variant (k=2 → 2/120, k=3 → 0/120, k=4 → 0/120); NOT closed for the SKEWED per-PATH variant (see (B)).
#   BLOCK-3 (checksum / validation-constrained routes): a route whose acceptance is a SEMANTIC predicate
#     (a Luhn-valid card id, a base58 id excluding 0/O/I/l, a UUIDv4 nibble) accepts a STRICTLY NARROWER set
#     than ANY character class, so a random same-class control lands in the route's VALIDATION-REJECT branch
#     while the checksum-valid-but-NONEXISTENT target soft-404s 200 (measured: Luhn 38/120 ≈ 32%, base58
#     ≈ 7%). Fixed in two halves: (a) VALIDATOR-AWARE CONTROLS — every control must satisfy each WELL-KNOWN
#     validator the TARGET satisfies, so the controls land in the ACCEPTED set; and (b) the SAME-BRANCH
#     BASELINE — the baseline is built ONLY from controls that took the TARGET'S OWN response branch.
#     Every control is classified over ALL its resamples: IN-BRANCH iff every sample carries the TARGET'S
#     EXACT STATUS and one body-hash; OFF-BRANCH iff NO sample carries the target's status (a
#     validation-reject / route-miss — DISCARDED, never the contrast); anything else is AMBIGUOUS and FAILS
#     THE WHOLE RUN CLOSED. We NEVER contrast the target across a response branch.
#   BLOCK-4 (unknown validator, reject INSIDE the target's own status branch): a route that answers 200 with
#     body V for an id IT considers invalid and 200 with a different body N for a valid-but-nonexistent one.
#     Every uniformly random sibling is invalid, so the "baseline" is V — a REJECT baseline — and the
#     target's own not-found body N looks like a differential (measured 39/40 minting for a NONEXISTENT
#     url). Mitigated by the MINIMAL-EDIT-DISTANCE (NO-TWIN) cohort (:func:`_hamming1_probe_urls`): a
#     sibling differing at exactly ONE position stays inside the validity neighbourhood of a LOCAL rule
#     whose accepted set is closed under the UNION alphabet, comes back with the target's own body, and the
#     no-twin clause kills the FACT (39/40 → 0/40; 0/80 for the prefix, suffix and positional variants on
#     all three paths). It does NOT cover a per-position FORMAT rule — see (A). The probes are a SEARCH
#     ONLY: their own cohort, referenced by the AST in NEGATIVE clauses plus a channel check, NEVER counted
#     toward :data:`_MIN_LIVENESS_CONTROLS`, so the cohort can only turn a FACT into a LEAD.
#
# The predicate is a pure JSON AST over RAW status codes + RAW body hashes of every RETAINED sample, so a
# consumer re-verifies it OFFLINE like every predicate_oracle context — bounded by the retention trust
# boundary stated above. The CLEAN direction is WITHDRAWN too: a hard 404/410 at the exact URL is
# control-independent, but on that path the sibling and twin cohorts are NEVER PROBED AT ALL, so a
# "conclusive non-firing" of a DIFFERENTIAL predicate would assert an absence nothing measured — and a 404
# is routinely what a server returns for a resource that EXISTS but is not authorised. Both directions are
# INCONCLUSIVE.
# The SHIPPED bug-class token. Deliberately NOT "endpoint_liveness" (red-pen BLOCK-3): the token is the
# ONLY thing many consumers read, and `endpoint_liveness` at confidence 0.9 asserts exactly what this branch
# must never assert. The EVIDENCE-BRANCH id (below) keeps its historical spelling — it is an internal
# admission key, not a shipped claim.
ENDPOINT_LIVENESS_BUG_CLASS = "sibling_response_differential"
ENDPOINT_LIVENESS_BRANCH = "achieved_state.endpoint_liveness"
# served-resource statuses the TARGET must return (2xx/3xx). 401/403/405/5xx are deliberately NOT minted here:
# they are exists-but-gated / error responses that a plain GET cannot soundly separate from a blanket policy,
# so they stay INCONCLUSIVE. A definite hard not-found at the TARGET (404/410) is the channel-confirmed CLEAN
# case — bounded to the EXACT probed URL, never an enumeration-completeness claim.
_TARGET_ABSENT_STATUSES = frozenset({404, 410})
# Multi-sample budget (BLOCK-2/BLOCK-3). DISTINCT same-shape controls dominate robustness against a per-PATH
# bounded body space AND against a validator whose acceptance rate is p (a control that lands in the target's
# own branch with the target's own body breaks the baseline's unanimity ⇒ LEAD, so the residual shrinks as
# (1-p)^_LIVENESS_CONTROLS); resampling each control + the target catches a per-REQUEST varying body — which
# is now AMBIGUOUS (fail the run closed) rather than a droppable control, so a b-element bounded space cannot
# manufacture a "stable" baseline out of the samples that happened to agree.
_LIVENESS_CONTROLS = 10         # DISTINCT same-shape not-found control URLs (dominates per-PATH robustness)
# times EACH control is fetched. THE BOUND (red-pen BLOCK-2): against a server whose not-found body is drawn
# per REQUEST from a b-element space, one control is MISCLASSIFIED as in-branch-stable (all k samples happen
# to coincide) with probability exactly b * (1/b)^k = b^(1-k). At k=2 that is 1/2 for b=2 — which is why the
# partially-varying class still minted 7/300 — at k=4 it is 1/8, and a run additionally needs EVERY varying
# control to be misclassified AND to land on the same value as the deterministic ones AND no twin probe to
# return the target's body. Measured over the shipped cohort: k=2 -> 2/120, k=3 -> 0/120, k=4 -> 0/120.
_LIVENESS_RESAMPLES = 4
_LIVENESS_TARGET_SAMPLES = 3    # times the TARGET is fetched (its response must be stable across these)
# TWIN SEARCH (red-pen BLOCK-1) — the MINIMAL-EDIT-DISTANCE cohort. The main cohort maximises INDEPENDENCE
# from the target (uniform random over the narrow class), which is exactly wrong when an unknown validator
# exists: every uniform draw lands in the route's REJECT set, so the "baseline" is a reject baseline. These
# probes do the opposite — each differs from the TARGET at exactly ONE alnum position (same narrow class,
# same origin, same parent directory, same lexical construction, same gated send), so they stay inside the
# validity neighbourhood of whatever the route accepts. ONE sample each: distinct paths buy more twin-finding
# power than repeat samples of the same path.
_LIVENESS_TWIN_PROBES = 20
# A FACT must have actually SEARCHED the neighbourhood: below this many channel-reaching probes the twin
# search is too thin to license the "no minimal-edit-distance sibling returned the same response" half of the
# claim ⇒ FAIL CLOSED. Always satisfiable when a control cohort exists (the narrowest class has >= 10
# characters, so a single alnum position already yields >= 9 distinct neighbours).
_MIN_TWIN_PROBES = 4
# The FLOOR of distinct IN-BRANCH controls a FACT needs. Two things make the count vary: a short segment /
# small alphabet (e.g. a single digit) cannot yield the full _LIVENESS_CONTROLS distinct siblings, and a
# validating route sends most siblings OFF-BRANCH (discarded). Fewer than this floor in the TARGET'S OWN
# branch ⇒ the baseline is too thin ⇒ FAIL CLOSED to a LEAD. The predicate is generated for the ACTUAL
# retained samples and stored per-finding, so a variable count still re-verifies offline against exactly the
# predicate that was minted.
_MIN_LIVENESS_CONTROLS = 4
# OPSEC / constitution §VI ("throttle, don't break their production"). The WORST-CASE number of gated GETs
# ONE call to :func:`endpoint_liveness_redrive` puts on the target: the target resamples + every control
# resample + the whole twin cohort. They are SERIAL with no inter-request delay, so this is also the burst
# a single URL costs. DERIVED from the constants above rather than written down, so raising a knob cannot
# silently multiply the traffic a caller budgeted for. Against the shipped constants: 63 worst case, 43 on
# a path that does not reach the twin search (the twin cohort is probed only when a run would otherwise
# have minted). ``external_tool._max_redriven_proposals()`` divides the runner's per-run request BUDGET
# (``external_tool._LIVENESS_REQUEST_BUDGET``) by this to cap how many tool-proposed URLs one run re-drives.
MAX_GATED_GETS_PER_URL = (_LIVENESS_TARGET_SAMPLES
                          + _LIVENESS_CONTROLS * _LIVENESS_RESAMPLES
                          + _LIVENESS_TWIN_PROBES)


def _liveness_claim(url: str, status: int, target_samples: int, same_branch: int, probes: int) -> str:
    """THE claim sentence — the single source of what this capture asserts (red-pen BLOCK-4).

    Every earlier wording asserted something the capture does not prove. "distinguishable from a NOT-FOUND
    baseline" and "not a soft-404 PHANTOM of that shape" are both FALSE in the classes where the siblings'
    stable answer is the route's REJECT body and the target's answer is its not-found body: there the
    baseline is a reject baseline and the target IS the phantom. So the sentence asserts only the two things
    the raw capture establishes, and says outright that it asserts nothing else.

    The branch is LEAD-ONLY (see the module header), so this sentence now travels on the LEAD as its
    ``note``. It is still computed in exactly ONE place: a narrowing that lives in two places drifts."""
    return (f"VIGIL's own gated GET of {url} returned content that DIFFERS from the server's stable "
            f"same-status response to {same_branch} randomized same-shape siblings (target status {status} "
            f"over {target_samples} samples; every sibling answered in the same status branch with one "
            f"shared body-hash), and NO minimal-edit-distance sibling — {probes} probed, each differing from "
            f"the target at exactly one position — returned that same response. This asserts NOTHING about "
            f"not-found-ness, phantom-ness, existence or liveness of the URL: it is a statement about how "
            f"this server's responses differ across a neighbourhood of identifiers, nothing more.")


def _build_liveness_predicate(in_branch: "list[list[int]]", off_branch: "list[list[int]]",
                              probes: "list[int]", n_target_samples: int, floor: int,
                              twin_floor: int) -> dict:
    """Generate the differential predicate as a pure JSON AST over the RAW per-sample values (no
    rubber-stamp — every decision is an AST op over retained raw statuses + body hashes, so the retained
    context re-verifies OFFLINE).

    TRUST BOUNDARY, stated plainly because an earlier version of this docstring denied it: the AST proves
    relations among the samples the RUNNER RETAINED, and nothing more. It does NOT prove that the retained
    set is the complete set — a runner that dropped inconvenient samples would emit a predicate that
    re-verifies perfectly over what is left. The claims "the classification cannot be cherry-picked after
    the fact" and "the certificate cannot claim a neighbourhood search that did not happen" are therefore
    WITHDRAWN as false. The RUNNER is the prover; the offline verifier re-checks the capture, never the
    capture's completeness. This is the SAME boundary the baseline cohort always had — it is disclosed, not
    newly introduced, and it is one of the reasons this branch is LEAD-only.

    ``in_branch`` / ``off_branch`` are the observed_evidence index blocks of the control samples, one block
    per DISTINCT control URL (``[[0,1],[2,3],…]``), as the runner classified them against the TARGET's own
    response branch. The AST re-checks that whole partition over the retained samples:

      * the target is SERVED (2xx/3xx) and STABLE across its resamples (status AND body-hash);
      * EVERY sample of EVERY in-branch control carries the TARGET'S EXACT STATUS (branch membership, tied to
        the target — never a 4xx/5xx validation-reject the target would be falsely "distinguished" from) AND
        the anchor's body-hash (per-control stability + unanimity of the baseline in one sweep);
      * EVERY sample of EVERY discarded control is proven OFF-BRANCH — its status differs from the target's
        on every resample (so a control that merely FLAPPED across the branch boundary cannot be discarded:
        the runner classifies it AMBIGUOUS and fails the run closed);
      * the retained same-branch count meets the floor;
      * NO-TWIN (red-pen BLOCK-1): NO probe other than the target — not one control sample, not one
        minimal-edit-distance neighbour — returned the target's body-hash. A response the target shares with
        any sibling is not a response the target is distinguished by, whatever the baseline says;
      * every RETAINED minimal-edit-distance probe REACHED a channel and the retained probe count meets the
        twin floor (a floor over the RETAINED probes — see the trust boundary above; it does not establish
        that no further neighbour was probed and discarded);
      * the target is DISTINGUISHABLE from that baseline BY BODY-HASH (the status is necessarily identical —
        same branch — so body-hash is the only sound differential).

    A missing var resolves to ``None``: the ``ge``/``eq``-to-target clauses then fail, so a predicate that
    references an absent sample (an empty control set, a truncated capture) CANNOT fire. Generated for the
    EXACT samples retained with the finding, so a variable control count still re-verifies offline."""
    clauses: list = [
        # (1) the target SERVED content (2xx/3xx) ...
        {"ge": [{"var": "target_0_status"}, 200]},
        {"not": {"ge": [{"var": "target_0_status"}, 400]}},
    ]
    # ... and was STABLE across its resamples (an unstable target — random content — cannot be soundly judged).
    for j in range(1, n_target_samples):
        clauses.append({"eq": [{"var": "target_0_status"}, {"var": f"target_{j}_status"}]})
        clauses.append({"eq": [{"var": "target_0_sha"}, {"var": f"target_{j}_sha"}]})
    # (2) the SAME-BRANCH baseline: every sample of every in-branch control carries the TARGET'S status and
    # the anchor's body-hash. The anchor's own status clause ties the whole baseline into the target's branch.
    anchor = in_branch[0][0] if in_branch else -1
    # the anchor sample must EXIST and be a served status — an absent var resolves to None and ``ge`` is
    # None-guarded, so a predicate generated with NO in-branch control can never fire (belt-and-braces: this
    # does not depend on the runner-supplied count in clause (4)).
    clauses.append({"ge": [{"var": f"control_{anchor}_status"}, 200]})
    clauses.append({"not": {"ge": [{"var": f"control_{anchor}_status"}, 400]}})
    for block in in_branch:
        for k in block:
            clauses.append({"eq": [{"var": f"control_{k}_status"}, {"var": "target_0_status"}]})
            clauses.append({"eq": [{"var": f"control_{k}_sha"}, {"var": f"control_{anchor}_sha"}]})
    # (3) the DISCARD PROOF: every sample of every discarded control took a DIFFERENT branch (its status is
    # not the target's). A validation-reject / route-miss is never the contrast, and a flapping control
    # cannot be silently dropped.
    for block in off_branch:
        for k in block:
            clauses.append({"not": {"eq": [{"var": f"control_{k}_status"}, {"var": "target_0_status"}]}})
    # (4) the retained same-branch DISTINCT-control count meets the floor. (A count the runner retains with
    # the evidence and the AST re-checks — the per-sample clauses above are the actual proof; this makes the
    # policy floor itself visible and re-checkable in the offline certificate.)
    clauses.append({"ge": [{"var": "same_branch_controls"}, floor]})
    # (5) NO-TWIN over the MINIMAL-EDIT-DISTANCE cohort: each neighbour reached a channel and did NOT return
    # the target's body. This is the clause that closes the unknown-validator class — on a prefix / suffix /
    # positional / format rule the neighbours stay ACCEPTED, so if the target's body is merely the route's
    # not-found answer a neighbour returns it too and the FACT dies here.
    for k in probes:
        clauses.append({"ge": [{"var": f"probe_{k}_status"}, 100]})
        clauses.append({"not": {"eq": [{"var": f"probe_{k}_sha"}, {"var": "target_0_sha"}]}})
    clauses.append({"ge": [{"var": "twin_probes"}, twin_floor]})
    # (6) NO-TWIN over the CONTROL cohort as well — redundant with (2)+(7) for an in-branch control, but the
    # rule "no probe other than the target returned the target's response" is then literally in the AST,
    # and it binds the off-branch controls too (a reject body that equals the target's body is not a
    # differential, whatever its status).
    for block in list(in_branch) + list(off_branch):
        for k in block:
            clauses.append({"not": {"eq": [{"var": f"control_{k}_sha"}, {"var": "target_0_sha"}]}})
    # (7) DISTINGUISHABLE BY BODY within that same branch (the status is identical by construction).
    clauses.append({"not": {"eq": [{"var": "target_0_sha"}, {"var": f"control_{anchor}_sha"}]}})
    return {"all": clauses}


@dataclass
class WebLivenessResult:
    """The outcome of ONE sibling-differential re-drive of a single URL.

    ``lead`` holds the labelled LEAD — which, on this LEAD-only branch, is EVERY outcome — and ``context``
    is the retained oracle_context (predicate AST + raw statuses + raw body hashes + control_urls +
    probe_urls) for OFFLINE re-verify, carried on the LEAD as well as on a (currently unreachable) FACT.
    ``note`` carries the narrowing sentence or the demotion reason in words. ``fact`` stays None while
    ``achieved_state.endpoint_liveness`` is declared fact_capable=false; the field and the plumbing remain
    because ``verdict.admit()`` — not this dataclass — is the choke that decides.
    ``outcome`` is one of positive|clean|inconclusive|deceptive_no_fact|refused."""

    url: str
    control_urls: list = field(default_factory=list)
    fact: Any = None
    lead: Any = None
    context: "dict | None" = None
    outcome: str = ""
    target_status: int = 0
    control_statuses: list = field(default_factory=list)
    same_branch_controls: int = 0   # DISTINCT controls that took the target's OWN served branch (the baseline)
    twin_probes: int = 0            # MINIMAL-EDIT-DISTANCE neighbours actually probed (the twin search)
    twin_found: bool = False        # a neighbour returned the TARGET's own body-hash ⇒ never a FACT
    note: str = ""
    refused: bool = False

    @property
    def is_fact(self) -> bool:
        return self.fact is not None


def _alnum_class_alphabet(alnum_chars: "set[str]") -> "str | None":
    """The alphabet of the NARROWEST well-known character class that contains EXACTLY the observed alnum
    characters, or ``None`` when the class is AMBIGUOUS (BLOCK-1 fail-closed). The candidate classes form a
    subset lattice (digits ⊂ hex ⊂ alnum; alpha ⊂ alnum; …). A control drawn from the target's narrowest
    class is ⊆ the route's accepted class (the target is accepted, so its class ⊆ the route's), so the control
    is route-valid and a 404 on it is a real not-found, not a route-miss. When two INCOMPARABLE minimal classes
    both fit (e.g. all a–f letters, which is both lower-alpha and lower-hex) the route class is genuinely
    ambiguous → return None → the caller fails closed to a LEAD rather than guess a wider bucket."""
    import string  # noqa: PLC0415 — stdlib, function-local
    classes = {
        "digits": set(string.digits),
        "lower_hex": set("0123456789abcdef"),
        "upper_hex": set("0123456789ABCDEF"),
        "lower_alpha": set(string.ascii_lowercase),
        "upper_alpha": set(string.ascii_uppercase),
        "alpha": set(string.ascii_letters),
        "lower_alnum": set(string.ascii_lowercase + string.digits),
        "upper_alnum": set(string.ascii_uppercase + string.digits),
        "alnum": set(string.ascii_letters + string.digits),
    }
    containing = {name: s for name, s in classes.items() if alnum_chars and alnum_chars <= s}
    if not containing:
        return None
    # minimal = no OTHER containing class is a strict subset of it. A unique minimum ⇒ that class; otherwise
    # (0 or ≥2 incomparable minima) the shape is ambiguous ⇒ fail closed.
    minimal = [name for name, s in containing.items()
               if not any(other != name and containing[other] < s for other in containing)]
    if len(minimal) != 1:
        return None
    return "".join(sorted(classes[minimal[0]]))


def _same_shape_sibling(seg: str, rand: Any) -> "str | None":
    """A randomized NARROW-CLASS, STRUCTURE-PRESERVING sibling of the last path segment ``seg``, or ``None``
    when its shape cannot be confidently mirrored (BLOCK-1 fail-closed → the caller degrades to a LEAD).

    WHAT IS AND IS NOT PER-POSITION — stated exactly, because an earlier version of this docstring claimed
    more than the code does and that overclaim is what ended the FACT. Every NON-alphanumeric character
    (a ``-`` in a UUID, an ``_``/``+``/``=`` in base64, an internal ``.``) is KEPT IN PLACE, so the
    STRUCTURE is per-position. The CHARACTER CLASS is NOT: every alphanumeric position is replaced by a
    random character from ONE alphabet — the narrowest well-known class containing EVERY alnum character
    of the WHOLE segment (:func:`_alnum_class_alphabet`), i.e. a per-SEGMENT UNION. So hex→hex, uuid→uuid
    (dashes kept, hex in the hex slots), numeric→numeric and alpha→alpha all hold, but a MIXED segment
    like ``dashboard1`` mirrors as lower-ALNUM at every position: a letter slot can become a digit and a
    digit slot can become a letter. A route with a per-POSITION format rule (``^dashboard\\d$``) therefore
    rejects most siblings, which is exactly the class the branch was downgraded over (module header, RP5).
    Preserves LENGTH and a trailing EXTENSION (``foo.php`` → ``<same-len>.php``). Returns ``None`` (fail
    closed) when there is no alnum position to randomise or the class is ambiguous. Pure/lexical — no
    network, no fixed literal a signature rule can fingerprint."""
    if not seg:
        return None
    stem, dot, ext = seg.rpartition(".")
    if dot and stem and 1 <= len(ext) <= 8 and ext.isalnum():
        base, suffix = stem, "." + ext
    else:
        base, suffix = seg, ""
    if not base:
        return None
    alnum_positions = [i for i, c in enumerate(base) if c.isalnum()]
    if not alnum_positions:
        return None   # nothing to randomise (all separators) — cannot mirror
    alphabet = _alnum_class_alphabet({base[i] for i in alnum_positions})
    if alphabet is None:
        return None   # ambiguous class — fail closed (do not guess a coarse bucket)
    chars = list(base)
    for i in alnum_positions:
        chars[i] = rand.choice(alphabet)
    return "".join(chars) + suffix


def _luhn_valid(s: str) -> bool:
    """The Luhn (mod-10) check over an all-digit string — the checksum on card / IMEI style identifiers."""
    if not s.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(s)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_BASE58_ALPHABET = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")   # no 0 O I l


def _base58_valid(s: str) -> bool:
    return bool(s) and all(c in _BASE58_ALPHABET for c in s)


def _uuid_v4_valid(s: str) -> bool:
    """A version-4 / RFC-4122-variant UUID: the version nibble is ``4`` and the variant nibble is 8|9|a|b."""
    import re  # noqa: PLC0415 — stdlib, function-local
    return bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                             s, re.IGNORECASE))


def _known_validators(seg: str) -> list:
    """The WELL-KNOWN SEMANTIC validators the TARGET segment itself satisfies (BLOCK-3, the capability half
    of the fix).

    A route whose acceptance is a semantic predicate (a Luhn checksum, the base58 alphabet, a UUID version /
    variant nibble) accepts a STRICTLY NARROWER set than any character class, so a purely character-class
    control mostly lands in the route's VALIDATION-REJECT branch. The same-branch baseline keeps that from
    becoming a false FACT (the rejects are discarded and the run fails closed below the floor) — but it also
    means such a route can never be adjudicated. So the control generator additionally REQUIRES every control
    to satisfy each well-known validator the TARGET satisfies: the controls then land in the route's ACCEPTED
    set by construction, the baseline is the route's TRUE not-found response, and the checksum-valid-but-
    nonexistent target is correctly seen to MATCH it (⇒ LEAD) while a genuinely distinguishable id still
    mints. Applying a validator can only NARROW the control set (a narrower set is still inside the target's
    character class), so the worst case is fewer distinct controls ⇒ the floor ⇒ FAIL CLOSED — never a wrong
    contrast. Validators are applied only where they are MEANINGFUL, never inferred from a coincidence:
    Luhn only on card/IMEI-length all-digit segments, base58 only on mixed-case alphanumeric segments long
    enough for the 0/O/I/l exclusion to be a real signal, UUIDv4 only on a literal v4 UUID. An APP-SPECIFIC
    validator VIGIL does not know stays covered by the same-branch fail-closed path (and is the branch's
    documented residual)."""
    vs: list = []
    if seg.isdigit() and 12 <= len(seg) <= 19 and _luhn_valid(seg):
        vs.append(_luhn_valid)
    if (len(seg) >= 8 and seg.isalnum() and any(c.islower() for c in seg) and any(c.isupper() for c in seg)
            and _base58_valid(seg)):
        vs.append(_base58_valid)
    if _uuid_v4_valid(seg):
        vs.append(_uuid_v4_valid)
    return vs


# Bounded attempt budget for drawing DISTINCT, validator-satisfying controls (rejection sampling: a Luhn-16
# draw is accepted ~10% of the time, a base58-filtered 20-char alnum draw ~26%). Exhausting it simply yields
# FEWER controls, which the _MIN_LIVENESS_CONTROLS floor then fails closed on.
_CONTROL_ATTEMPT_BUDGET = 4096


def _liveness_control_urls(url: str, n: int = _LIVENESS_CONTROLS) -> "list[str]":
    """Return UP TO ``n`` NARROW-CLASS, structure-preserving, randomized, DISTINCT sibling control URLs of
    ``url`` under the SAME origin (scheme/host/port) and the SAME parent directory — the last path segment
    mirrored by :func:`_same_shape_sibling` and additionally required to satisfy every well-known SEMANTIC
    validator the target segment satisfies (:func:`_known_validators`: Luhn / base58 / UUIDv4), so that a
    checksum-constrained route accepts the controls instead of validation-rejecting them. Best-effort: a
    short segment / small alphabet (e.g. a single digit, whose mirror space is only 10), or a validator that
    exhausts the attempt budget, yields fewer than ``n``; the caller enforces the
    :data:`_MIN_LIVENESS_CONTROLS` floor and fails closed below it. Returns ``[]`` when there is no mirrorable
    last segment (a root/directory URL like ``/`` or ``/api/``) or the shape is ambiguous/un-mirrorable.
    Same host as the target, so each is authorised by the identical charter scope the target GET is (the
    host-pin invariant). Purely lexical over the URL — no network."""
    import secrets  # noqa: PLC0415 — stdlib, function-local
    from urllib.parse import urlsplit, urlunsplit  # noqa: PLC0415 — stdlib, function-local
    rand = secrets.SystemRandom()
    parts = urlsplit(url)
    path = parts.path or "/"
    slash = path.rfind("/")
    parent = path[: slash + 1] if slash >= 0 else "/"
    seg = path[slash + 1:] if slash >= 0 else path
    if not seg:
        return []   # a root/directory URL has no last segment to mirror — fail closed to a LEAD
    if _same_shape_sibling(seg, rand) is None:
        return []   # shape cannot be mirrored / ambiguous class → fail closed
    urls: "list[str]" = []
    tokens: "set[str]" = {seg}
    # collect as many DISTINCT same-shape siblings as the mirror space allows, up to n, each satisfying every
    # WELL-KNOWN SEMANTIC validator the target satisfies (rejection sampling under a bounded attempt budget).
    # When the space/budget is exhausted we stop with what we have — the caller enforces the floor. All
    # siblings are != the target segment (seeded into ``tokens``).
    validators = _known_validators(seg)
    attempts = 0
    while len(urls) < n and attempts < _CONTROL_ATTEMPT_BUDGET:
        attempts += 1
        tok = _same_shape_sibling(seg, rand)
        if tok is None:                       # (shape checked above; defensive)
            break
        if tok in tokens or any(not v(tok) for v in validators):
            continue
        tokens.add(tok)
        urls.append(urlunsplit((parts.scheme, parts.netloc, parent + tok, "", "")))
    return urls


def _hamming1_probe_urls(url: str, n: int = _LIVENESS_TWIN_PROBES) -> "list[str]":
    """Up to ``n`` DISTINCT sibling URLs whose last path segment differs from the TARGET's at EXACTLY ONE
    alphanumeric position — the MINIMAL-EDIT-DISTANCE (validity-neighbourhood) cohort of the twin search
    (red-pen BLOCK-1).

    Same origin (scheme/host/port), same parent directory, same length, same extension, and the SAME
    per-SEGMENT UNION alphabet as :func:`_same_shape_sibling` — only the mutation rule differs: one position
    changes, everything else is the TARGET's own bytes. That is deliberate. A uniform random draw is
    maximally INDEPENDENT of the target, so on a route with a semantic validator it lands in the REJECT set
    essentially always; a Hamming-1 neighbour stays inside the validity neighbourhood of a LOCAL rule whose
    accepted set is closed under that alphabet, so if the target's response is merely the route's not-found
    answer for ACCEPTED ids, a neighbour returns that same response and exposes it as a TWIN.

    THE LIMIT, stated exactly (RP5 — this is why the branch is LEAD-only). The edit is drawn from the UNION
    alphabet, not from the class of THAT position. On a word+digits identifier (``dashboard1`` → lower
    alnum) an edit at the single digit slot produces a LETTER 26/35 of the time, so a route with a
    per-POSITION format rule (``^dashboard\\d$``) rejects the neighbour and NO twin is found — for a url
    where nothing exists. Measured 11/100, 32/100 and 55/100 false FACTs before the downgrade. The true
    residual condition is therefore "no Hamming-1 neighbour OVER THIS ALPHABET is accepted", which covers
    ordinary format routes and not merely whole-string checksums.

    Positions are visited round-robin in a random order, one new alternative character each pass, so a SHORT
    segment still yields many probes (a 1-digit segment yields 9) and a LONG one covers many positions first.
    No validator filter is applied: an invalid neighbour simply cannot be a twin, and filtering would empty
    the cohort exactly where it is cheapest to run. Returns ``[]`` when the shape is not mirrorable (the
    caller then fails closed). Purely lexical — no network."""
    import secrets  # noqa: PLC0415 — stdlib, function-local
    from urllib.parse import urlsplit, urlunsplit  # noqa: PLC0415 — stdlib, function-local
    rand = secrets.SystemRandom()
    parts = urlsplit(url)
    path = parts.path or "/"
    slash = path.rfind("/")
    parent = path[: slash + 1] if slash >= 0 else "/"
    seg = path[slash + 1:] if slash >= 0 else path
    if not seg:
        return []
    stem, dot, ext = seg.rpartition(".")
    if dot and stem and 1 <= len(ext) <= 8 and ext.isalnum():
        base, suffix = stem, "." + ext
    else:
        base, suffix = seg, ""
    if not base:
        return []
    positions = [i for i, c in enumerate(base) if c.isalnum()]
    if not positions:
        return []
    alphabet = _alnum_class_alphabet({base[i] for i in positions})
    if alphabet is None:
        return []   # ambiguous class — the same fail-closed rule the control cohort uses
    order = list(positions)
    rand.shuffle(order)
    used: "dict[int, set]" = {i: set() for i in positions}
    tokens: "list[str]" = []
    while len(tokens) < n:
        progressed = False
        for i in order:
            if len(tokens) >= n:
                break
            choices = [c for c in alphabet if c != base[i] and c not in used[i]]
            if not choices:
                continue
            c = rand.choice(choices)
            used[i].add(c)
            chars = list(base)
            chars[i] = c
            tokens.append("".join(chars) + suffix)
            progressed = True
        if not progressed:
            break   # the whole neighbourhood is exhausted
    return [urlunsplit((parts.scheme, parts.netloc, parent + t, "", "")) for t in tokens]


def endpoint_liveness_redrive(url: str, *, slug: str, engagement_slug: str,
                             signers: "list[tuple[str, str]]", timeout: float = 8.0) -> WebLivenessResult:
    """Re-drive ``url`` with VIGIL's OWN plain gated GETs (no canary) and measure whether the server's
    response to it DIFFERS from its own stable, SAME-BRANCH response to randomized same-shape siblings, with
    no minimal-edit-distance neighbour returning that same response. Returns a :class:`WebLivenessResult`.
    NEVER raises.

    LEAD-ONLY. ``achieved_state.endpoint_liveness`` is declared fact_capable=false AND clean_capable=false
    (see the module header for the five rounds and the measured false-FACT classes), so ``admit()`` returns
    a LEAD for a fired oracle and INCONCLUSIVE for a conclusive non-firing. This function still performs the
    WHOLE measurement and retains the whole capture, because the capture is good evidence for a human and
    re-verifies offline — what it is not is a fact about the world.

    Order (fail-closed): pre-flight the charter gate ONCE (a refused engagement means VIGIL never observed
    the target — no channel, so nothing is examined and nothing is asserted); GET the target
    ``_LIVENESS_TARGET_SAMPLES`` times through the gated send; GET up to ``_LIVENESS_CONTROLS`` DISTINCT
    narrow-class same-shape sibling controls, ``_LIVENESS_RESAMPLES`` times each; classify every control
    against the TARGET'S OWN response branch (in-branch / off-branch-discarded / ambiguous-fail-closed); on
    the only path that would otherwise conclude, probe the minimal-edit-distance TWIN cohort; run the
    predicate_oracle over the RAW statuses + RAW body hashes; admit through the branch. OPSEC: worst case
    :data:`MAX_GATED_GETS_PER_URL` SERIAL gated GETs for ONE url."""
    from framework.v2.scanner.insertion import HttpRequest  # noqa: PLC0415 (FATAL-2: function-local)
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

    from ..oracle_adapter import AdapterResult, certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit  # noqa: PLC0415

    res = WebLivenessResult(url=url)
    finding_ref = f"web:{ENDPOINT_LIVENESS_BUG_CLASS}:{url}"

    # PRE-FLIGHT the gate ONCE: a refused engagement (kill-switch / out-of-scope / no-slug / bad URL) means
    # VIGIL never observed the target — there is NO channel, so we must NOT mint and must NOT report a
    # channel-confirmed CLEAN. Return refused with zero adjudication (no traffic).
    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.outcome = "refused"
        res.note = f"refused before any traffic: {refusal}"
        return res

    def _status(resp: "dict | None") -> int:
        return int((resp or {}).get("status", 0) or 0)

    def _sha(resp: "dict | None") -> str:
        return str((resp or {}).get("raw_sha256", "") or "")

    send, _state = _gated_web_send(slug, timeout=timeout)
    control_urls = _liveness_control_urls(url)
    # enforce the multi-sample FLOOR: below _MIN_LIVENESS_CONTROLS distinct same-shape siblings the not-found
    # baseline is too thin to be trusted, so fail closed (no controls ⇒ the FACT cannot fire; a hard-404 target
    # can still be a control-independent CLEAN).
    if len(control_urls) < _MIN_LIVENESS_CONTROLS:
        control_urls = []
    res.control_urls = list(control_urls)
    try:
        # TARGET first, resampled T times — its response must be STABLE across resamples (a random-content
        # target cannot be soundly judged). All sends are total (a refusal/error is a status-0 _EMPTY).
        target_samples = [send(HttpRequest(method="GET", url=url)) for _ in range(_LIVENESS_TARGET_SAMPLES)]
        target_statuses = [_status(t) for t in target_samples]
        target_channel = any(s >= 100 for s in target_statuses)
        target_all_absent = target_channel and all(s in _TARGET_ABSENT_STATUSES for s in target_statuses)
        # CONTROLS: each DISTINCT same-shape URL resampled K times (BLOCK-2 multi-sample stability). Skipped
        # when the target had no channel (deceptive), when no sound same-shape control exists (fail closed),
        # or when the target is a hard not-found (the CLEAN path is control-independent).
        control_samples: list = []
        if target_channel and control_urls and not target_all_absent:
            for c in control_urls:
                for _ in range(_LIVENESS_RESAMPLES):
                    control_samples.append(send(HttpRequest(method="GET", url=c)))
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return a lead
        res.outcome = "inconclusive"
        res.note = f"probe error: {type(e).__name__}: {e}"
        res.lead = AdapterResult("lead", res.note, ENDPOINT_LIVENESS_BUG_CLASS, finding_ref,
                                 outcome="inconclusive")
        return res

    if not target_channel:
        # DECEPTIVE: the tool claimed the URL, but VIGIL's OWN gated GET reached no channel (transport error /
        # mid-run gate deny). NOT reproducible ⇒ NO fact (never a CLEAN — no channel means nothing examined).
        res.outcome = "deceptive_no_fact"
        res.note = ("VIGIL's own gated GET reached no channel — the tool's URL claim is not reproducible "
                    "(deceptive_no_fact)")
        res.lead = AdapterResult("lead", res.note, ENDPOINT_LIVENESS_BUG_CLASS, finding_ref,
                                 outcome="inconclusive")
        return res

    res.target_status = target_statuses[0]
    res.control_statuses = sorted({_status(s) for s in control_samples})
    # observed_evidence: EVERY raw sample (status + raw body hash), keyed for the generated predicate AST — no
    # rubber-stamp, the AST does all the comparing. The predicate references only the SAME-BRANCH subset (below)
    # and is retained WITH the finding, so the certificate re-verifies offline against exactly what was minted.
    observed_evidence: dict = {"target_url": url, "control_urls": list(control_urls)}
    for j, t in enumerate(target_samples):
        observed_evidence[f"target_{j}_status"] = _status(t)
        observed_evidence[f"target_{j}_sha"] = _sha(t)
    for i, s in enumerate(control_samples):
        observed_evidence[f"control_{i}_status"] = _status(s)
        observed_evidence[f"control_{i}_sha"] = _sha(s)

    # SAME-BRANCH BASELINE (the RP3 fix). The sibling baseline must be built ONLY from controls that
    # took the TARGET's OWN response branch. Classify each DISTINCT control by ALL of its resamples:
    #   IN-BRANCH  — every sample carries the TARGET'S EXACT STATUS and they share ONE body-hash;
    #   OFF-BRANCH — NO sample carries the target's status (a validation-reject / route-miss) ⇒ DISCARDED;
    #   AMBIGUOUS  — anything else: a control that FLAPPED across the branch boundary, or whose body VARIES
    #                inside the target's own branch (the bounded/per-request body space of BLOCK-2). One
    #                ambiguous control FAILS THE WHOLE RUN CLOSED: a nondeterministic route yields no sound
    #                baseline, and silently dropping such a control is exactly how a bounded body space
    #                manufactures a spurious "stable" baseline.
    # An off-branch control is NEVER the contrast the target is "distinguished" from — we do not contrast
    # across response branches. The AST proves this partition (membership AND the discard), so it re-verifies
    # offline; the runner only selects, it never adjudicates.
    target_stable = len({(_status(t), _sha(t)) for t in target_samples}) == 1
    target_status = target_statuses[0]
    target_served = target_stable and 200 <= target_status < 400
    in_branch: "list[list[int]]" = []
    off_branch: "list[list[int]]" = []
    ambiguous = 0
    for c_idx in range(len(control_urls)):
        block = [i for i in range(c_idx * _LIVENESS_RESAMPLES, (c_idx + 1) * _LIVENESS_RESAMPLES)
                 if i < len(control_samples)]
        if not block:
            continue
        samples = [control_samples[i] for i in block]
        statuses = {_status(x) for x in samples}
        shas = {_sha(x) for x in samples}
        if statuses == {target_status} and len(shas) == 1:
            in_branch.append(block)
        elif target_status not in statuses:
            off_branch.append(block)
        else:
            ambiguous += 1
    distinct_same_branch = len(in_branch)
    res.same_branch_controls = distinct_same_branch
    # the baseline must also be UNANIMOUS across the in-branch controls (a per-PATH not-found space gives each
    # sibling its own body ⇒ no baseline). The predicate enforces it; computed here only to label the LEAD.
    baseline_unanimous = len({_sha(control_samples[b[0]]) for b in in_branch}) <= 1

    # A FACT requires: the target SERVED + stable, NO ambiguous control, and at least the floor of DISTINCT
    # IN-BRANCH controls. A checksum route (random controls validation-reject off-branch), a hard-404 server
    # (no served baseline), or a varying body space (ambiguous) all FAIL CLOSED here.
    have_baseline = target_served and ambiguous == 0 and distinct_same_branch >= _MIN_LIVENESS_CONTROLS
    baseline_sha = _sha(control_samples[in_branch[0][0]]) if in_branch else None
    target_sha = _sha(target_samples[0])
    # TWIN SEARCH (red-pen BLOCK-1). Run it ONLY when the run is otherwise about to mint — it can only turn a
    # FACT into a LEAD, so on every other path it is pure traffic. Each MINIMAL-EDIT-DISTANCE neighbour is
    # fetched ONCE through the SAME gated send, and if ANY of them returns the TARGET's body-hash the
    # target's response is not its own ⇒ LEAD. The probes are a TWIN SEARCH ONLY: they are kept in their own
    # list and NEVER counted toward _MIN_LIVENESS_CONTROLS, so they cannot push a sub-floor run over the
    # floor — the cohort is strictly restrictive by construction.
    provisional = (have_baseline and baseline_unanimous and baseline_sha is not None
                   and target_sha != baseline_sha)
    probe_urls: "list[str]" = []
    probe_samples: list = []
    twin_found = False
    if provisional:
        try:
            probe_urls = _hamming1_probe_urls(url)
            probe_samples = [send(HttpRequest(method="GET", url=u)) for u in probe_urls]
        except Exception as e:  # noqa: BLE001 — a probe error never mints; it fails the twin search closed
            res.outcome = "inconclusive"
            res.note = f"twin-search probe error: {type(e).__name__}: {e}"
            res.lead = AdapterResult("lead", res.note, ENDPOINT_LIVENESS_BUG_CLASS, finding_ref,
                                     outcome="inconclusive")
            return res
        twin_found = any(_sha(x) == target_sha for x in probe_samples)
    res.twin_probes = len(probe_samples)
    res.twin_found = twin_found
    for k, x in enumerate(probe_samples):
        observed_evidence[f"probe_{k}_status"] = _status(x)
        observed_evidence[f"probe_{k}_sha"] = _sha(x)
    # Retain WHICH neighbours were probed, alongside their per-sample status/body-hash vars — the control
    # cohort already retains ``control_urls`` and the twin cohort must be just as auditable. The predicate
    # AST never reads these (it reads the indexed ``probe_k_*`` vars), so this is purely so a human or an
    # OFFLINE auditor can see the actual neighbourhood that was searched instead of taking the count on
    # trust. Aligned index-for-index with the ``probe_k_*`` samples.
    observed_evidence["probe_urls"] = list(probe_urls[:len(probe_samples)])
    observed_evidence["twin_probes"] = len(probe_samples)
    observed_evidence["same_branch_controls"] = distinct_same_branch
    observed_evidence["same_branch_sample_keys"] = [i for b in in_branch for i in b]
    observed_evidence["off_branch_sample_keys"] = [i for b in off_branch for i in b]
    observed_evidence["ambiguous_controls"] = ambiguous
    have_baseline = (provisional and not twin_found and len(probe_samples) >= _MIN_TWIN_PROBES)
    context = {"predicate": _build_liveness_predicate(in_branch, off_branch, list(range(len(probe_samples))),
                                                      _LIVENESS_TARGET_SAMPLES, _MIN_LIVENESS_CONTROLS,
                                                      _MIN_TWIN_PROBES),
               "observed_evidence": observed_evidence}
    # CONCLUSIVENESS: what the deterministic layer saw. ``admit()`` then applies the branch's DECLARED
    # capabilities, and ``achieved_state.endpoint_liveness`` is declared fact_capable=false AND
    # clean_capable=false — so a FIRED oracle here becomes a LEAD and a conclusive non-firing becomes
    # INCONCLUSIVE. ``conclusive`` is still computed honestly (a hard 404/410 on every resample IS a
    # channel-confirmed non-firing) because the registry, not this function, is where the policy lives:
    # hard-coding the demotion here would hide it from the one place a reviewer reads capabilities.
    fired = _oracle_signal(context).fired if have_baseline else False
    conclusive = fired or target_all_absent
    admitted = admit(ENDPOINT_LIVENESS_BRANCH, fired=fired, conclusive=conclusive,
                     observed={"channel_established": True, "gate_authorized": True})

    finding = {"check_id": finding_ref, "bug_class": ENDPOINT_LIVENESS_BUG_CLASS,
               "insertion_point": url, "oracle_context": context}
    # The narrowing sentence is computed in ONE place and travels with the result (red-pen BLOCK-3): a
    # bug-class token alone does not state what was observed, and a note the runner drops is not a
    # disclosure. ``report_claims`` would bind it into the SIGNED certificate if this branch ever minted;
    # it does not mint, so the sentence travels on the LEAD's ``note`` instead and the claims list stays
    # None (``certify_admitted`` refuses to certify a non-FACT admission anyway — the choke is admission).
    claim_sentence = _liveness_claim(url, res.target_status, _LIVENESS_TARGET_SAMPLES,
                                     distinct_same_branch, len(probe_samples))
    claims = None
    if fired and admitted.is_fact:
        from framework.v2.evidence.certify import ReportClaim  # noqa: PLC0415 (FATAL-2: function-local)
        claims = [ReportClaim(sentence=claim_sentence, bug_class=ENDPOINT_LIVENESS_BUG_CLASS,
                              render_as="analyst-commentary")]
    r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                         provenance="live_redrive", report_claims=claims)
    if r.is_fact:
        res.fact = r
        res.context = context
        res.outcome = "positive"
        res.note = claim_sentence
        # AdapterResult is FROZEN (a minted result is not editable in place); carry the claim by rebuilding.
        res.fact = replace(r, note=claim_sentence)
        return res
    # Not a FACT — a labelled LEAD, which on this branch is EVERY path. The retained capture rides along on
    # ``res.context`` so the LEAD carries the same offline-re-verifiable evidence a FACT would have: the
    # predicate AST, every raw per-sample status and body hash, the control urls and the probe urls. That
    # is the whole point of keeping the pipeline — the evidence is good, the conclusion was not.
    res.lead = r
    res.context = context
    res.outcome = "clean" if admitted.verdict is Verdict.CLEAN else "inconclusive"
    if admitted.verdict is Verdict.CLEAN:
        res.note = (f"channel-confirmed hard not-found ({res.target_status}) at THIS exact URL — CLEAN bounded "
                    f"to the probed URL only, never a claim that no other endpoint exists")
    elif fired:
        # The differential WAS observed and the oracle DID fire; admission demoted it because the branch is
        # LEAD-only. Saying "no differential" here would be a fresh false statement, so say what happened.
        res.note = (f"{claim_sentence} DEMOTED TO A LEAD: {admitted.reason} — this observation is priority "
                    f"and context for a human, not a fact about the world. The retained capture re-verifies "
                    f"offline; see docs/capability-matrix/evidence-branches.json for the measured classes "
                    f"that took FACT-capability off this branch.")
    elif target_all_absent:
        res.note = (f"hard not-found ({res.target_status}) at THIS exact URL on every resample — "
                    f"INCONCLUSIVE, not CLEAN: the sibling and twin cohorts are not probed on this path, so "
                    f"nothing measured the differential this branch is about, and a 404 is also what a "
                    f"server returns for a resource that EXISTS but is not authorised")
    elif not control_urls:
        res.note = ("no sound NARROW-CLASS same-shape control for this URL (a root/directory URL or an "
                    "ambiguous/un-mirrorable last segment) — fails closed to a LEAD")
    elif not target_served:
        res.note = (f"the target is not a STABLE served (2xx/3xx) response (status {res.target_status}, "
                    f"stable={target_stable}) — nothing sound to distinguish; a LEAD")
    elif ambiguous:
        res.note = (f"{ambiguous} of {len(control_urls)} same-shape controls took an AMBIGUOUS response "
                    f"branch (their samples disagree on status, or the body VARIES inside the target's own "
                    f"branch across {_LIVENESS_RESAMPLES} resamples) — a nondeterministic route yields no "
                    f"sound baseline, and dropping such a control is how a bounded body space manufactures "
                    f"a false one; fail closed")
    elif distinct_same_branch < _MIN_LIVENESS_CONTROLS:
        res.note = (f"no SAME-BRANCH baseline: only {distinct_same_branch} of {len(control_urls)} same-shape "
                    f"controls answered in the target's OWN response branch (the rest validation-rejected / "
                    f"route-missed into a DIFFERENT branch) — below the floor of {_MIN_LIVENESS_CONTROLS}, "
                    f"and we never contrast the target across response branches; a LEAD")
    elif not baseline_unanimous:
        res.note = (f"the {distinct_same_branch} same-branch controls do NOT agree on one body-hash (a "
                    f"per-path / bounded body space) — no stable baseline; a LEAD")
    elif twin_found:
        res.note = (f"TWIN FOUND: of {len(probe_samples)} minimal-edit-distance siblings (each differing "
                    f"from the target at exactly ONE position), at least one returned the TARGET'S OWN "
                    f"body — so that response is the route's answer for a whole neighbourhood of "
                    f"identifiers, not something this URL is distinguished by; a LEAD")
    elif provisional and len(probe_samples) < _MIN_TWIN_PROBES:
        res.note = (f"only {len(probe_samples)} minimal-edit-distance probes reached a channel (floor "
                    f"{_MIN_TWIN_PROBES}) — the validity neighbourhood was not searched, so the no-twin "
                    f"half of the claim is unproven; fail closed to a LEAD")
    else:
        res.note = (f"no differential: target {res.target_status}, {distinct_same_branch} same-branch "
                    f"controls — the target's body is IDENTICAL to the same-branch sibling baseline; a LEAD")
    if res.lead is not None:
        res.lead = replace(res.lead, note=res.note)   # the demotion reason reaches every consumer
    return res


@dataclass
class WebRedriveResult:
    url: str
    facts: list = field(default_factory=list)     # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)     # AdapterResult (status=="lead") — CHANNEL-CONFIRMED
    inconclusive: list = field(default_factory=list)  # (bug_class, item) — a probe with NO channel; never CLEAN
    admissions: list = field(default_factory=list)    # (branch, verdict, reason) — the audit trail
    branch_verdicts: dict = field(default_factory=dict)  # bug_class -> {branch: verdict}
    contexts: dict = field(default_factory=dict)  # finding_ref -> oracle_context (offline re-verify)
    insertion_surfaces: dict = field(default_factory=dict)  # bug_class -> set(surface) actually EXAMINED
    probed_redirect_param_names: list = field(default_factory=list)  # candidate names on the synth carriers
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def surfaces_probed(self, bug_class: str) -> list:
        """The insertion surfaces on which ``bug_class`` was ACTUALLY examined (a channel was established),
        in a stable order. A surface only appears here if a real HTTP response came back on it — a
        gate-refused or transport-errored probe examined nothing and is deliberately excluded."""
        return sorted(self.insertion_surfaces.get(bug_class, set()))

    def coverage_statement(self, bug_class: str) -> str:
        """Name the insertion surfaces a CLEAN for ``bug_class`` is BOUNDED to.

        The product thesis is a SOUND negative: a CLEAN must mean "examined here and found nothing", never
        "did not look". So a family CLEAN is only honest when it also names WHERE it looked. An empty
        coverage set is not a clean bill of health — it is INCONCLUSIVE (nothing was examined)."""
        surfaces = self.surfaces_probed(bug_class)
        if not surfaces:
            return (f"{bug_class}: no insertion surface established a channel — INCONCLUSIVE, not CLEAN "
                    f"(nothing was examined)")
        return (f"{bug_class}: examined across insertion surfaces [{', '.join(surfaces)}]; any CLEAN is "
                f"bounded to these surfaces and the probed redirect-parameter names, never a claim of "
                f"absence on a surface or parameter name not examined")

    def family_coverage(self) -> dict:
        """Every examined family -> the insertion surfaces it was examined on (for persisted reporting)."""
        return {bug: self.surfaces_probed(bug) for bug in self.insertion_surfaces}

    def family_verdict(self, bug_class: str) -> str:
        """The conservative composition over every branch of ``bug_class`` (see verdict.compose).

        Reporting must use this rather than any single branch: a CLEAN header branch sitting beside a FACT
        body branch would otherwise be summarised as a clean family, asserting safety no branch established."""
        from .verdict import compose  # noqa: PLC0415
        return compose(list(self.branch_verdicts.get(bug_class, {}).values())).value

    def family_verdicts(self) -> dict:
        """Every examined family, conservatively composed."""
        return {bug: self.family_verdict(bug) for bug in self.branch_verdicts}


def _gated_web_send(slug: str, *, timeout: float = 8.0):
    """Return ``(send, state)``. ``send`` is a ``scanner.checks.Send`` —
    ``send(HttpRequest) -> {status, body, headers, latency_ms}`` — that AUTHORIZES each request's URL
    through the URL-shaped active-recon gate (kill-switch → single-host → ACTIVE_RECON → charter scope →
    http(s), no embedded creds) BEFORE issuing it, follows NO redirects (so the raw Location is captured),
    and is bounded.

    ``state`` is a mutable ``{"channels": int, "no_channel": int}`` counter the runner uses to tell a
    GENUINE observation from a NON-observation. A refusal (per-request gate deny / kill-switch tripped
    mid-run) or any transport error (connection refused, timeout, DNS failure) increments ``no_channel``
    and returns a status-0 empty response — the check sees nothing and mints no FACT (never an un-gated
    send). The runner MUST NOT treat a no-channel probe as a "channel-confirmed CLEAN": no channel means
    INCONCLUSIVE, not clean (the "found nothing != CLEAN" invariant). Only a real HTTP response — any
    status, including 4xx/5xx — increments ``channels``."""
    import time
    import urllib.error
    import urllib.request

    from framework.v2.verify.reachability_cloud import _authorize  # the URL-shaped gate (offense-side)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D401
            return None

    from urllib.parse import urlsplit

    from .body_decode import MAX_RAW_BYTES, decode_body
    from .dns_pin import pinned_handlers, resolve_and_validate

    def _address_authorized(address: str) -> bool:
        """Re-ask the SAME gate about the resolved address. Reusing the charter decision (rather than a
        second, looser rule) is what keeps the pin honest: an address the gate would refuse as a target is
        refused as a destination."""
        scheme = "https" if str(address).count(":") > 1 else "http"   # bracket IPv6 for the URL form
        literal = f"[{address}]" if str(address).count(":") > 1 else address
        return _authorize(f"http://{literal}/", slug) is None

    _EMPTY = {"status": 0, "body": "", "headers": [], "latency_ms": 0.0,
              "body_semantically_available": False, "body_unavailable_reason": "no channel"}
    state = {"channels": 0, "no_channel": 0, "body_unavailable": 0}

    def send(req: Any) -> dict:
        if _authorize(req.url, slug) is not None:
            state["no_channel"] += 1
            return dict(_EMPTY)   # refused (gate deny / kill-switch mid-run) — NO channel, not a CLEAN
        data = req.body.encode("utf-8") if getattr(req, "body", None) else None
        r = urllib.request.Request(req.url, data=data, method=getattr(req, "method", "GET"))
        for k, v in getattr(req, "headers", []) or []:
            r.add_header(k, v)
        if not r.has_header("Accept-encoding"):
            # Ask only for encodings we can reverse. A target may still answer with something else (some
            # CDNs compress unconditionally) — that path is handled by decode_body, which refuses rather
            # than guessing, so the body is INCONCLUSIVE rather than silently mangled.
            r.add_header("Accept-Encoding", "gzip, deflate, identity")
        # An EMPTY ProxyHandler is MANDATORY (mirrors the shipped gated connector): without it urllib honours
        # http_proxy/https_proxy/ALL_PROXY, so the real TCP peer would be a proxy the gate never authorized —
        # the charter/single-host scope check would pass while traffic went elsewhere, and the proxy's bytes
        # would be labelled provenance="live_redrive". No auth handler either: the probe stays anonymous.
        # DNS time-of-check/time-of-use: the gate authorized a NAME, but urllib would resolve that name
        # again at connect time, so nothing binds the authorization to the endpoint actually reached
        # (rebinding, a short TTL, a poisoned resolver, or a multi-A record with one address out of scope).
        # Resolve once, require EVERY address to satisfy the same charter scope the gate used, then PIN the
        # connection to the validated address while still presenting the original hostname for TLS/Host.
        parts = urlsplit(req.url)
        target_host = parts.hostname or ""
        target_port = parts.port or (443 if parts.scheme == "https" else 80)
        resolution = resolve_and_validate(target_host, target_port, _address_authorized)
        if not resolution.allowed:
            state["no_channel"] += 1
            refused = dict(_EMPTY)
            refused["body_unavailable_reason"] = resolution.refused_reason
            return refused
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect,
                                             *pinned_handlers(resolution.pinned))
        t0 = time.monotonic()
        try:
            # Read ONE BYTE PAST the bound: reading exactly the cap cannot distinguish "the response was
            # this long" from "the response was longer and we hold a prefix", and a body-dependent NEGATIVE
            # over a prefix cannot prove the absence of markup.
            with opener.open(r, timeout=timeout) as resp:
                status, raw, headers = resp.status, resp.read(MAX_RAW_BYTES + 1), list(resp.headers.items())
        except urllib.error.HTTPError as e:      # a 4xx/5xx is a real, useful response — a genuine channel
            status, raw, headers = e.code, e.read(MAX_RAW_BYTES + 1), list(e.headers.items())
        except Exception:                        # noqa: BLE001 — transport error (no channel) → INCONCLUSIVE
            state["no_channel"] += 1
            return dict(_EMPTY)
        state["channels"] += 1
        headers = [(str(k), str(v)) for k, v in headers]
        truncated = len(raw) > MAX_RAW_BYTES
        body = decode_body(raw[:MAX_RAW_BYTES], headers, truncated=truncated)
        # The capture carries its own decoding provenance so an adjudicator can tell "the document said
        # nothing" from "we never read the document".
        if not body.body_semantically_available:
            # A real channel, but NOT a readable document. Header-derived evidence in this same response
            # stays adjudicable; body-derived evidence must not be scored as CLEAN over bytes we never
            # decoded, so the runner is told.
            state["body_unavailable"] += 1
        return {"status": status, "body": body.text, "headers": headers,
                "latency_ms": (time.monotonic() - t0) * 1000.0,
                "pinned_ip": resolution.pinned, "resolved_addresses": list(resolution.addresses),
                "raw_sha256": body.raw_sha256, "raw_len": body.raw_len,
                "content_encoding": body.content_encoding, "charset": body.charset,
                "decoded": body.decoded, "truncated": body.truncated,
                "body_semantically_available": body.body_semantically_available,
                "body_unavailable_reason": body.reason}

    return send, state


def benign_control_fetch(url: str, *, slug: str, timeout: float = 8.0) -> "bytes | None":
    """One VIGIL-owned, GATED, benign GET of ``url`` (no payload, no canary) — the CONTROL an error-signature
    proof is compared against (S6). Its response BODY bytes are what ``verify.oracles.error_signature_oracle``
    checks the exploit response against: the same datastore/parser error present in BOTH the exploit and this
    benign control means the page always errors ⇒ NOT attributable ⇒ the mint stays a LEAD.

    It reuses the SAME charter-gated, DNS-pinned, proxy-free send as the web re-drive (kill-switch →
    single-host → ACTIVE_RECON → charter scope), so a control is only ever fetched from an in-scope target.
    Returns the decoded body bytes when a real channel was established AND the whole document was read and
    soundly decoded, else ``None`` — a refusal (out of scope / kill-switch), a transport error, an
    un-decodable body, OR a body the send could only capture as a PREFIX (``truncated``: the document was
    longer than ``MAX_RAW_BYTES``) all yield ``None``. The truncated-but-decodable case is the load-bearing
    one: the send caps the control at ``MAX_RAW_BYTES`` while the observed side is the (uncapped) retained
    blob, so returning a decoded PREFIX would let the oracle compare an error present in the full observed
    response against a control from which that error was merely truncated away — an always-erroring page
    whose datastore error sits past the cap would then mint a FALSE FACT. A control we cannot soundly
    adjudicate over (``not body_semantically_available``) is therefore refused: the caller degrades the FACT
    to a LEAD (fail-closed), never adjudicates over bytes it never read. NEVER raises."""
    if not str(url or "").strip():
        return None
    try:
        from framework.v2.scanner.insertion import HttpRequest  # noqa: PLC0415 — FATAL-2 (offense plane)
        from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

        # PRE-FLIGHT the gate ONCE (mirrors ``web_redrive``): a refused engagement means VIGIL never observed
        # the target, so there is no control to compare against — refuse rather than send.
        if _authorize(url, slug) is not None:
            return None
        send, state = _gated_web_send(slug, timeout=timeout)
        resp = send(HttpRequest(method="GET", url=url))
        if state["channels"] <= 0:
            return None   # no channel established (gate deny mid-run / transport error) ⇒ no control
        # Refuse a control the module cannot soundly adjudicate OVER THE WHOLE DOCUMENT. ``send`` reads only
        # ``MAX_RAW_BYTES`` and sets ``body_semantically_available = decoded and not truncated``; the observed
        # side (proof/run.py::_resolve) is the UNCAPPED retained blob. A truncated (or un-decodable) control
        # would be captured ASYMMETRICALLY against the observed bytes — an error past the cap absent from the
        # prefix would fail to suppress a fire — so mirror the web_redrive runner's INCONCLUSIVE handling
        # (``state["body_unavailable"]``) and refuse. A None control ⇒ the caller keeps the mint fail-closed.
        if not resp.get("body_semantically_available"):
            return None
        body = resp.get("body")
        if isinstance(body, (bytes, bytearray)):
            return bytes(body) or None
        if isinstance(body, str):
            return body.encode("utf-8", errors="replace") or None
        return None
    except Exception:  # noqa: BLE001 — a control fetch must never raise into the mint; no channel ⇒ None
        return None


# The insertion surfaces this re-drive probes for open-redirect. A redirect parameter is NOT only a query
# value: apps read next/returnTo from a URL PATH segment, a COOKIE, a urlencoded BODY, or a JSON BODY just as
# often. A bare GET template exposes only the URL, so restricting the re-drive to QUERY_VALUE / URL_PATH_SEG
# meant those other surfaces were ABSENT from adjudication — not reported unexamined, simply missing, which
# reads to a consumer as "nothing there" and let a redirect reachable ONLY via a cookie/body param be
# reported CLEAN (a latent false-CLEAN). The runner therefore SYNTHESISES the cookie / urlencoded / JSON
# carriers (each with the correct method + Content-Type) so those insertion points EXIST to be rendered into
# and adjudicated by the SAME admission path. No benign-twin baseline is needed for soundness: the
# OpenRedirectCheck predicate fires ONLY on a real navigation to the UNIQUE canary HOST — which the app can
# only reach by using the injected value as a redirect target — so a benign reflection never false-FACTs.
# QUERY_NAME / BODY_FORM_NAME / JSON_KEY stay OUT as an ORACLE BOUNDARY: a canary injected as a parameter
# NAME does not model the redirect-VALUE property under test.
#
# Named by VALUE, not by enum member: the framework import is function-local (FATAL-2), so this module must
# not reference InsertionKind at import time. _redirect_templates() resolves them where the enum is available.

# Well-known redirect-parameter names tried on the synthesised cookie/body/JSON carriers, in addition to any
# name the proposed URL itself carries. A CLEAN over the synthesised surfaces is BOUNDED to this candidate
# set — stated honestly in the coverage statement — never a claim that no body/cookie redirect exists under
# some other name. Kept small so the re-drive's request footprint stays bounded.
_REDIRECT_PARAM_NAMES = (
    "next", "url", "redirect", "redirect_uri", "redirect_url", "returnto", "return_url",
    "returnurl", "return", "dest", "destination", "continue",
)
_MAX_CANDIDATE_REDIRECT_NAMES = 12


def _candidate_redirect_names(url: str) -> "list[str]":
    """Redirect-parameter names to try on the synthesised cookie/body/JSON carriers.

    GROUNDED first in the names the proposed URL actually carries (so an endpoint's real redirect parameter
    is exercised on EVERY surface, not only the query), then a small fixed set of well-known names for
    breadth, de-duplicated case-insensitively and capped. Purely lexical over the URL — no network."""
    from urllib.parse import parse_qsl, urlsplit  # noqa: PLC0415 — stdlib, function-local (style parity)
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
    for n in _REDIRECT_PARAM_NAMES:
        if n not in seen:
            names.append(n)
            seen.add(n)
    return names[:_MAX_CANDIDATE_REDIRECT_NAMES]


def _redirect_templates(url, names, http_request, insertion_kind, request_template):
    """The ``(RequestTemplate, insertion-kinds)`` carriers the open-redirect re-drive probes.

    Four carriers, each restricted to the surface it introduces so the URL query/path is not re-probed by the
    body carriers: the bare GET (URL query + path), a GET with a synthesised Cookie header, a POST with a
    urlencoded body, and a POST with a JSON body. ``names`` (from :func:`_candidate_redirect_names`) are the
    redirect-parameter names placed on the synthesised carriers — the caller passes them so it can also record
    the CLEAN's parameter-name bound. Every carrier feeds the identical admission path, so each surface's
    outcome is attributed and capability-checked like any other. Returns a list; never raises."""
    import json  # noqa: PLC0415 — stdlib, function-local
    templates = [
        (request_template(http_request(method="GET", url=url)),
         (insertion_kind.QUERY_VALUE, insertion_kind.URL_PATH_SEG)),
    ]
    if names:
        cookie = "; ".join(f"{n}=redir" for n in names)
        templates.append((
            request_template(http_request(method="GET", url=url, headers=[("Cookie", cookie)])),
            (insertion_kind.COOKIE_VALUE,)))
        form = "&".join(f"{n}=redir" for n in names)
        templates.append((
            request_template(http_request(
                method="POST", url=url,
                headers=[("Content-Type", "application/x-www-form-urlencoded")], body=form)),
            (insertion_kind.BODY_FORM_VALUE,)))
        js = json.dumps({n: "redir" for n in names}, separators=(",", ":"))
        templates.append((
            request_template(http_request(
                method="POST", url=url, headers=[("Content-Type", "application/json")], body=js)),
            (insertion_kind.JSON_VALUE,)))
    return templates


def _oracle_signal(context: "dict"):
    """Run the deterministic oracle over the retained context and return its (fired, conclusive) signal.

    Kept separate from minting so admission can see the oracle's answer BEFORE any certificate exists."""
    from framework.v2.verify.oracles import predicate_oracle  # noqa: PLC0415 (FATAL-2: function-local)

    evidence = context.get("observed_evidence") or {}
    predicate = context.get("predicate") or {}
    return predicate_oracle(evidence, predicate)


def _branch_outcomes(bug_class: str, context: "dict", overall_fired: bool) -> "list[tuple[str, bool]]":
    """Every ATOMIC branch outcome present in this response, as ``(branch_id, fired)``.

    Deliberately NOT "one branch per response". A single response can carry a 302 ``Location``, a body
    meta-refresh AND a JavaScript sink at once; collapsing that to a single branch by precedence would
    discard real evidence and, worse, hide the LIMITATIONS of the branches it dropped — the body branches
    are not CLEAN-capable, so silently reporting only the header branch would let a response look more
    conclusively examined than it was.

    Each outcome is admitted separately, so each is judged against ITS OWN declared capability and appears
    in the audit trail with its own verdict."""
    evidence = context.get("observed_evidence") or {}
    followed = bool(evidence.get("followed_redirect"))
    body = evidence.get("body") or ""
    # A Location host equals the target only when the response ACTUALLY REDIRECTED. Without this, a status
    # 200 that merely reflects the canary into a Location header (or a render-dependent body/JS redirect on
    # a page that also sets Location) was attributed to the `location_header` branch — laundering
    # body/JS-derived, render-dependent evidence into a 3xx-header FACT whose DECLARED evidence surface was
    # never observed. The status gate MUST match the oracle's own Location disjunct (checks.py: a 3xx status
    # AND a matching Location host), so the branch fires exactly when its declared evidence is present.
    is_redirect = int(evidence.get("status", 0) or 0) in (301, 302, 303, 307, 308)
    location_host = evidence.get("location_host")

    if bug_class == "cors":
        return [("cors.reflected_origin_with_credentials", overall_fired)]

    if bug_class == "graphql_introspection":
        # A single, oracle-driven branch: the check's predicate already IS the exploitable proposition (a
        # well-formed schema returned to VIGIL's own introspection query), so the branch simply mirrors the
        # oracle's verdict over that live capture — no per-response decomposition to do (like cors).
        return [("graphql_introspection.schema_returned", overall_fired)]

    if bug_class == "host_header_injection":
        # The host-header Location disjunct is itself status-free (checks.py:HostHeaderCheck), so branch and
        # oracle already agree here — do not add a gate the oracle does not have.
        evil = evidence.get("evil_host")
        emitted = evidence.get("emitted_url_hosts") or []
        return [
            ("host_header.location_header", bool(evil) and location_host == evil),
            ("host_header.body_emission", bool(evil) and evil in emitted and not followed),
        ]

    prefix = "oidc_redirect_uri" if bug_class == "oidc_redirect_uri" else "open_redirect"
    canary = evidence.get("canary_host")
    outcomes = [(f"{prefix}.location_header",
                 bool(canary) and is_redirect and location_host == canary)]
    meta_fired = js_fired = False
    if canary and body:
        from framework.v2.scanner.checks import js_sink_hosts, meta_refresh_hosts  # noqa: PLC0415
        meta_fired = canary in meta_refresh_hosts(body) and not followed
        js_fired = canary in js_sink_hosts(body) and not followed
    outcomes.append((f"{prefix}.body_markup", meta_fired))
    if prefix == "open_redirect":       # the SSO check has no registered JS-sink branch
        outcomes.append(("open_redirect.js_sink", js_fired))
    return outcomes


def web_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                timeout: float = 8.0, claimed_class: str = "") -> WebRedriveResult:
    """Re-drive ``url`` through the shipped web checks via a gated send and mint a signed FACT for every
    ACHIEVED_STATE predicate the oracle confirms over VIGIL's OWN live capture. The predicates are scoped to
    the exploitable, co-located condition (a real navigation target / reflected-origin+creds), and a probe
    that established no channel is INCONCLUSIVE (never CLEAN). Returns a :class:`WebRedriveResult`."""
    from framework.v2.scanner.checks import (  # noqa: PLC0415
        CorsActiveCheck,
        GraphqlIntrospectionCheck,
        HostHeaderCheck,
        OpenRedirectCheck,
    )
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, compose as _compose  # noqa: PLC0415

    res = WebRedriveResult(url=url)
    # PRE-FLIGHT the gate ONCE: a refused engagement (kill-switch / out-of-scope / no-slug / bad URL) means
    # VIGIL never observed the target, so there is NO channel — we must NOT run the checks and let their
    # empty captures be mislabelled a "channel-confirmed CLEAN" (the "found nothing ≠ CLEAN" invariant). We
    # return refused with zero adjudications. The per-request gate in `send` remains as defence-in-depth.
    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    send, state = _gated_web_send(slug, timeout=timeout)
    template = RequestTemplate(HttpRequest(method="GET", url=url))

    def _run(probe_fn, bug_class: str, item: str, *, surface: str = "") -> None:
        """Run one check, but adjudicate ONLY if the probe established a real channel. A probe whose every
        send was gate-refused (kill-switch tripped mid-run) or errored (connection refused / timeout)
        observed NOTHING — it is INCONCLUSIVE, never a 'channel-confirmed CLEAN' (the 'found nothing !=
        CLEAN' invariant). We snapshot the channel counter around the probe to decide.

        ``surface`` names the insertion surface this probe examined (e.g. ``json_value``); it is recorded as
        EXAMINED only when a channel was established, so the coverage statement can bound a CLEAN to the
        surfaces actually reached and never count a no-channel probe as coverage."""
        before, before_bodies = state["channels"], state["body_unavailable"]
        ctx = probe_fn()
        had_channel = state["channels"] > before
        if not had_channel:
            res.inconclusive.append((bug_class, item))   # no observation → do NOT let it become CLEAN
            return
        if surface:
            res.insertion_surfaces.setdefault(bug_class, set()).add(surface)
        body_unreadable = state["body_unavailable"] > before_bodies
        if ctx is None:
            return
        context = ctx.to_verifier_context()
        finding = {"check_id": f"web:{bug_class}:{item}", "bug_class": bug_class,
                   "insertion_point": item, "oracle_context": context}

        # ADMISSION DECIDES, MINTING EXECUTES. Run the deterministic oracle, attribute the outcome to ONE
        # registered evidence branch, and let admit() apply that branch's declared capabilities against what
        # this observation actually supports. Calling confirm_and_certify directly would let a verdict reach
        # a certificate without any capability check ever running.
        signal = _oracle_signal(context)
        observed = {
            "channel_established": True,
            "body_semantically_available": not body_unreadable,
            "not_followed_redirect": not bool(context.get("observed_evidence", {}).get("followed_redirect")),
            "gate_authorized": True,
        }
        # One admission PER ATOMIC BRANCH OUTCOME. A response carrying several kinds of evidence yields
        # several admissions, each judged against its own declared capability, so nothing is hidden by the
        # precedence of a stronger sibling.
        for branch, fired in _branch_outcomes(bug_class, context, signal.fired):
            admitted = admit(branch, fired=fired, conclusive=signal.conclusive, observed=observed)
            res.admissions.append((branch, admitted.verdict.value, admitted.reason))
            # STRONGEST-wins across insertion points, not last-wins. `_run` fires once PER insertion point,
            # all with the same branch names, so a benign point processed AFTER the firing one used to
            # overwrite its verdict — reporting a family as INCONCLUSIVE while it held a live signed FACT
            # (?next=<redirect>&utm_source=x is an everyday URL). A branch is FACT for the family if ANY
            # point produced a FACT; compose() over {prior, new} takes the stronger under the same lattice.
            branch_map = res.branch_verdicts.setdefault(bug_class, {})
            prior = branch_map.get(branch)
            branch_map[branch] = _compose([prior, admitted.verdict.value]).value if prior else admitted.verdict.value
            per_branch = dict(finding, check_id=f"{finding['check_id']}#{branch}")
            r = certify_admitted(per_branch, admitted, engagement_slug=engagement_slug, signers=signers,
                                 provenance="live_redrive")
            res.contexts[r.finding_ref] = context
            if r.is_fact:
                res.facts.append(r)
            elif admitted.verdict is Verdict.INCONCLUSIVE:
                res.inconclusive.append((bug_class, f"{item}#{branch}"))
                res.notes.append(f"{bug_class} [{branch}]: {admitted.reason}")
            else:
                res.leads.append(r)

    try:
        # request-level checks (add an evil Origin / Host to the whole request)
        _run(lambda: CorsActiveCheck().probe(template, send), "cors", url, surface="origin_header")
        _run(lambda: HostHeaderCheck().probe(template, send), "host_header_injection", url,
             surface="host_header")
        # graphql introspection: VIGIL POSTs its OWN minimal introspection query and the oracle fires only on
        # a well-formed returned schema — a definite proposition, so a single oracle-driven branch (like cors).
        _run(lambda: GraphqlIntrospectionCheck().probe(template, send), "graphql_introspection", url,
             surface="graphql_introspection_query")
        # oidc redirect_uri: CLASS-GATED (run ONLY when the CLAIMED class is exactly "oidc_redirect_uri").
        # OidcRedirectUriCheck's predicate is observationally IDENTICAL to open_redirect (a 3xx Location to
        # the canary host, or a meta-refresh to it), so running it unconditionally would UPGRADE a plain
        # open_redirect endpoint that merely carries a redirect_uri param to the higher-severity oidc class
        # (A07 vs A01) — a severity-overclaim, the inverse of the S6 relabel. The OIDC-authorization semantic
        # is carried by the CLAIM, never the 302; the check itself no-ops unless redirect_uri is present.
        if claimed_class == "oidc_redirect_uri":
            from framework.v2.scanner.sso import OidcRedirectUriCheck  # noqa: PLC0415 (FATAL-2: function-local)
            _run(lambda: OidcRedirectUriCheck().probe(template, send), "oidc_redirect_uri", url,
                 surface="redirect_uri_query")
        # per-insertion-point: open-redirect injects the canary into each redirect insertion point, across
        # EVERY surface a redirect parameter is really taken from — the URL query/path, a Cookie, a
        # urlencoded body, and a JSON body. The runner synthesises the cookie/body/JSON carriers (see
        # _redirect_templates) so those insertion points EXIST to be rendered into; each carrier is restricted
        # to the surface it introduces so the URL is not re-probed. Every outcome flows through the SAME
        # admission path, so each surface is attributed and capability-checked like any other.
        orc = OpenRedirectCheck()
        # the candidate redirect-parameter names placed on the synthesised cookie/body/JSON carriers — recorded
        # so the location_header CLEAN's parameter-name bound is machine-readable, not prose-only.
        names = _candidate_redirect_names(url)
        res.probed_redirect_param_names = list(names)
        for tmpl, kinds in _redirect_templates(url, names, HttpRequest, InsertionKind, RequestTemplate):
            for point in tmpl.insertion_points(kinds=kinds):
                _run(lambda t=tmpl, p=point: orc.probe(t, p, send), "open_redirect",
                     f"{url}#{point.id}", surface=point.kind.value)
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"probe error: {type(e).__name__}: {e}")
    return res
