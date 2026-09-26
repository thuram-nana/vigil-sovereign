"""
scanner.checks — the active-check library.

A check is the unit Burp's scanner is built from: for a bug class, it knows how
to *probe* one insertion point (what payloads to place, how many requests to
send) and how to shape the observed responses into a :class:`verify.FindingContext`
that the deterministic oracle layer adjudicates. The oracle — never the LLM,
never a heuristic — decides confirmation, so every finding this library produces
is signal-anchored (the precision property Burp's Tentative/Firm heuristics
lack).

Checks are pure w.r.t. the graph and deterministic given a `send`: the marker a
reflection check plants is derived from the insertion point's id, so a run is
replayable. A check emits a FindingContext or None (insufficient evidence); it
makes NO confirmation decision itself.

Boundary: checks place payloads only into the insertion point the engine hands
them, and only issue requests through the engine's injected `send` — which in
production is the scope/charter/kill-switch/egress-gated executor. Payloads here
are verification probes (differential terms, unique canary markers, traversal
tokens), not weaponized exploits.
"""

from __future__ import annotations

import math
import re
import time
from html.parser import HTMLParser
from dataclasses import dataclass
from typing import Callable, ClassVar, Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

from ..verify.adapter import FindingContext
from ..verify.oob import OOBReceiver
from . import js_lex as _js_lex
from .insertion import HttpRequest, InsertionPoint, RequestTemplate

# A `send` turns a rendered request into an observed response dict
# {status, body, latency_ms?}. Injected by the engine so checks never touch the
# network directly (and tests drive a localhost target).
Send = Callable[[HttpRequest], dict]


@runtime_checkable
class Check(Protocol):
    """Probes one insertion point and returns oracle-ready evidence, or None."""

    id: str
    bug_class: str

    def probe(
        self, template: RequestTemplate, point: InsertionPoint, send: Send
    ) -> FindingContext | None: ...


# ---------------------------------------------------------------------------
# Wave 3.1 — SHARED SUBSTANTIVENESS GUARDS (against VACUOUS PREDICATE SATISFACTION)
# ---------------------------------------------------------------------------
#
# A contains / not-contains predicate is EVIDENCE only over a SUBSTANTIVE body. An
# empty / errored / denied / 404 response makes a ``not-contains`` pass TRIVIALLY —
# the marker is "absent" only because the body carries nothing, not because the app
# withheld it. Absence in such a body proves NOTHING, so it can neither satisfy a
# fire predicate NOR serve as a negative control; the class must fail CLOSED to a
# rigorous LEAD, never mint a FACT off a vacuous read. These two helpers make every
# fire-predicate and every negative-control SUBSTANTIVE. (A later commit DRYs them
# into one shared module; the names and semantics here are the contract — keep them
# identical across the Wave-3 access-control slices.)

# Multi-word denial / error phrases that mark a 2xx body as a SOFT-deny or soft-error
# rather than a real record read. A substantive read of a private record never
# consists of one of these. High precision on purpose: over-rejecting only downgrades
# a would-be FACT to an honest LEAD — it can NEVER mint a false FACT — so the safe
# direction is to treat an ambiguous body as non-substantive. Single ambiguous words
# ("error", "forbidden", "unauthorized") are deliberately EXCLUDED so legitimate
# record content that merely mentions them stays substantive; only unmistakable
# denial/error PHRASES count.
_BARE_ERROR_SIGNATURES: tuple[str, ...] = (
    "access denied", "access is denied", "permission denied", "not authorized",
    "you are not authorized", "you do not have permission", "insufficient privileges",
    "insufficient permission", "authentication required", "authentication failed",
    "must be logged in", "please log in", "please login", "login required",
    "not logged in", "internal server error", "service unavailable",
)

# A body shorter (stripped) than this carries no record content to speak of — an
# empty / whitespace / one-word body cannot be a substantive success nor prove absence.
_SUBSTANTIVE_MIN_LEN: int = 16

# A logged-out baseline is a GENUINE authorization denial (which DOES prove the content
# is gated) at these statuses — as opposed to a bare error (5xx / empty / network / 404)
# whose absent marker is vacuous. 401/403 are the honest "you must authenticate / you
# are forbidden" signals; a 404 is treated as non-proof (it can be a transient miss).
_AUTHORIZATION_DENIAL_STATUSES: tuple[int, ...] = (401, 403)


def is_substantive_success(status: object, body: object) -> bool:
    """True iff a response can serve as EITHER a fire body OR a negative control: a real
    2xx read with actual content, not an error / deny / empty page.

    Semantics (shared across the Wave-3 access-control slices): ``status`` in ``[200, 300)``
    AND the stripped body is at least :data:`_SUBSTANTIVE_MIN_LEN` chars AND the body is not a
    bare error / deny signature. A body that FAILS this cannot satisfy a fire predicate NOR
    prove ``absent`` for a negative control — absence in an errored / empty / denied body is
    VACUOUS, so the class fails closed to a LEAD."""
    try:
        s = int(status)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if not (200 <= s < 300):
        return False
    stripped = str(body or "").strip()
    if len(stripped) < _SUBSTANTIVE_MIN_LEN:
        return False
    low = stripped.lower()
    return not any(sig in low for sig in _BARE_ERROR_SIGNATURES)


def valid_discriminator(marker: object) -> bool:
    """True iff ``marker`` is usable as a per-identity discriminator: present, non-whitespace,
    and long enough that its presence in a body is not incidental.

    Semantics (shared): ``marker`` is not None AND ``len(marker.strip()) >= 3`` AND not pure
    whitespace. (IDOR additionally enforces REF-INDEPENDENCE — the marker must not be a
    substring of the requested ref — as a separate guard, plus a stricter ``>= 6`` length floor
    in the predicate. Where a per-probe nonce exists a caller must also refuse a marker that
    overlaps that nonce; IDOR's ``victim_ref`` plays that role.)"""
    if marker is None:
        return False
    return len(str(marker).strip()) >= 3


def _substantive_success_clauses(status_var: str, body_var: str) -> list[dict]:
    """DSL clauses (AND-composed) that RE-DERIVE :func:`is_substantive_success` over the RETAINED
    raw evidence, so offline predicate re-verification enforces the SAME floor the live probe did —
    a durable ``oracle_context`` built from a non-substantive body can never re-fire. The predicate
    DSL's ``min_len`` measures the stored body (which the probe stores STRIPPED), so the length floor
    matches the Python helper; each denial phrase is an ``icontains`` refusal."""
    clauses: list[dict] = [
        {"ge": [{"var": status_var}, 200]},
        {"not": {"ge": [{"var": status_var}, 300]}},
        {"min_len": [{"var": body_var}, _SUBSTANTIVE_MIN_LEN]},
    ]
    clauses += [{"not": {"icontains": [{"var": body_var}, sig]}} for sig in _BARE_ERROR_SIGNATURES]
    return clauses


# A genuine authorization denial still has to SAY something (a real deny message) to count — a 401/403
# with an EMPTY / whitespace body is a bare, vacuous baseline whose absent marker proves nothing. This
# floor is deliberately BELOW a real deny message ("please log in" = 13 chars) so genuine denials pass.
_DENIAL_BODY_MIN_LEN: int = 3


def _nocred_baseline_valid(status: object, body: object) -> bool:
    """True iff a no-credential / logged-out baseline read is a VALID proof that the content is
    authorization-gated (not public) — its ``not-contains(marker)`` is meaningful.

    A baseline proves gating when it is EITHER a substantive success (a 2xx body that simply lacks
    the marker — the record is gated at the record level) OR a GENUINE authorization DENIAL (401 / 403
    that CARRIES a real deny body — access requires credentials). A bare / empty error (5xx / empty /
    whitespace / network failure / 404, or a body-less 401/403) proves NOTHING: its absent marker is
    vacuous, so the baseline is INVALID and the class fails closed to a LEAD. (This is why the
    benchmark's 401/403 logged-out baseline still permits a FACT while a 5xx / empty baseline does not.)"""
    try:
        s = int(status)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if is_substantive_success(status, body):
        return True
    return s in _AUTHORIZATION_DENIAL_STATUSES and len(str(body or "").strip()) >= _DENIAL_BODY_MIN_LEN


def _baseline_valid_clause(status_var: str, body_var: str) -> dict:
    """The DSL twin of :func:`_nocred_baseline_valid` over an arbitrary retained same-ref baseline
    (``status_var`` / ``body_var``), re-derived offline: a substantive 2xx that lacks the marker OR a
    genuine 401/403 authorization denial carrying a real (non-empty) deny body. Used for BOTH the
    no-credential (logged-out) baseline and the round-4 authenticated-but-UNAUTHORIZED baseline — a
    bare 5xx / empty / 404 read is not a valid discriminating baseline (its absent marker is vacuous)."""
    return {"any": [
        {"all": _substantive_success_clauses(status_var, body_var)},
        {"all": [
            {"in": [{"var": status_var}, list(_AUTHORIZATION_DENIAL_STATUSES)]},
            {"min_len": [{"var": body_var}, _DENIAL_BODY_MIN_LEN]},
        ]},
    ]}


def _nocred_baseline_valid_clause() -> dict:
    """The DSL twin of :func:`_nocred_baseline_valid` (re-derived offline over the retained baseline):
    a substantive success OR a 401/403 authorization denial carrying a real (non-empty) deny body."""
    return _baseline_valid_clause("nocred_status", "nocred_body")


@dataclass(frozen=True)
class DifferentialCheck:
    """Boolean/logic differential: send a benign value and a probe value into the
    same point and let the differential oracle judge whether the responses
    diverge (boolean-blind SQLi/NoSQLi, auth-logic, filter bypass).

    The point's own base value is NOT used as the baseline — a fresh benign value
    is, so the comparison is payload-vs-payload and the base is left untouched as
    a control the engine can re-check."""

    id: str
    bug_class: str
    benign: str
    probe_payload: str

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        baseline = send(template.render(point, self.benign))
        mutated = send(template.render(point, self.probe_payload))
        return FindingContext.from_http_responses(
            baseline, mutated, bug_class=self.bug_class,
            discriminator={"dimensions": ["status", "length", "lexical"]},
        )


# --------------------------------------------------------------------------------------------------
# TRUTH-VALUE ATTRIBUTION clause families (shared by the scanner arm and its regressions).
# --------------------------------------------------------------------------------------------------
# A family is ``(K_T always-TRUE clauses, K_F always-FALSE clauses)`` for ONE injection context. Read
# this header before editing a shape: what the set does and does NOT buy has been measured, and the
# measurements are not what the shapes look like they buy.
#
# THE STRUCTURAL FACT, FIRST — because it bounds everything below. Every clause here is one whose
# truth value VIGIL must know A PRIORI: before the request is sent, without touching the target's
# database. A predicate knowable that way IS A CONSTANT EXPRESSION, and any constant expression the
# scanner can evaluate offline, a REQUEST-SIDE FILTER in front of a STATIC page can also evaluate
# offline. There is therefore NO clause set that removes the truth-correlated-request-filter residual;
# there is only a set that makes such a filter's job harder. That residual — residual (a) on
# ``verify.oracles.boolean_inference_oracle`` — IS OPEN. Everything below raises the bar; nothing
# below closes it, and the measured ladder in that docstring shows each rung being cleared.
#
# 1. COMPARISON-SHAPE DIVERSITY — the property with a real, measured mechanism behind it.
#    An early revision varied only the LITERALS, so every TRUE clause was `X = X` and every FALSE
#    clause `X = Y`. Truth value was then perfectly correlated with the surface feature "the two
#    operands are the same token" — exactly what a ModSecurity-CRS-942130-shape BACKREFERENCE rule
#    keys on with no SQL engine anywhere. A STATIC, NON-VULNERABLE page behind that rule answered 403
#    to the whole TRUE side and 200 to the whole FALSE side and minted a false FACT on EVERY attempt
#    (measured 2000/2000). Raising K does not help: every extra `X = X` matches the same rule. Varying
#    the comparison does, and the mechanism is INCOMPLETENESS: a filter that catches SOME shapes leaves
#    the others alone, so the TRUE cluster stops agreeing and the round REFUTES. Measured: 0/2000
#    against CRS-942130, and 0 in a LEAVE-ONE-SHAPE-OUT sweep for every one of the seven shapes
#    blinded. What that buys is precise and limited: a filter must be COMPLETE over the whole shape
#    set. It does not have to be a SQL engine to be complete.
#
# 2. THE SEVENTH SHAPE (`{d1} IN (SELECT {d1})` vs `{d1} IN (SELECT {d2})`) — KEPT, but NOT for the
#    reason it was added. It shipped under the claim that its truth "needs EVALUATION rather than
#    folding", so a constant folder could not decide it. THAT CLAIM IS RETRACTED: over a one-row
#    constant SELECT, `LIT IN (SELECT LIT)` IS literal equality (sqlite3: `3 IN (SELECT 3)` -> 1,
#    `3 IN (SELECT 5)` -> 0). It is `X = X` vs `X = Y` in a costume — the separating surface feature is
#    still "the two operand tokens are identical" — and THREE LINES of regex added to the constant
#    folder below decide it, after which the folder partitions the SHIPPED set perfectly (measured
#    600/600 false FACTs through the real mint path on a static page).
#    WHY IT IS STILL HERE, on its merits and nothing more:
#      * it is the SEVENTH distinct clause per truth value, and K is the documented lever for the
#        OTHER residual — the per-URL-cache case (b). At K=7 that residual measures 1.20e-4 per
#        attempt; at K=6 the analytic figure is 4x worse (`2 * 2**-12` = 4.9e-4). Dropping this pair
#        would regress the dominant disclosed residual by 4x to save ~16% of the boolean arm's traffic.
#      * it is one more rule an incomplete filter must implement: a folder complete over the other six
#        shapes but blind to `IN` refutes (measured 0/200), exactly like every other leave-one-out cell.
#    HONEST COST, stated because it is real: this is the only shape here that is not portable SQL.
#    `SELECT <literal>` with no FROM is valid on sqlite/MySQL/PostgreSQL/SQL Server but NOT on Oracle
#    (which needs `FROM DUAL`), so on an Oracle origin this clause errors, the TRUE cluster stops
#    agreeing and the whole boolean arm refutes — a RECALL loss (a LEAD, never a false FACT).
#
# 3. THE LITERALS ARE FIXED PUBLIC CONSTANTS — deliberately, and this is a REVERSAL. A previous
#    revision randomised them per run so "the clause set is not a public constant an operator can
#    paste into an exact-string blocklist". That is dropped, for two reasons.
#      * NO MEASURED BENEFIT. The shape TEMPLATES are public in this open-source file whatever the
#        literals are, so a filter derives a per-shape rule from them directly. Measured: a constant
#        folder plus a NINE-STRING blocklist over the `IN` atom alone (the `d1` slot ranged over only
#        1..9) partitioned 1500/1500 randomised family draws and minted 300/300 through the real
#        mint path — randomisation bought nothing against the attack it was sold against.
#      * IT POINTED THE WRONG WAY. Constitution VI.4 says MAKE YOURSELF CORRELATABLE: the operator
#        must be able to grep their WAF and access logs and find our traffic. Defeating an operator's
#        exact-string control is defeating a DEFENDER's control on the operator's own estate, and it
#        also contradicted this module's own contract that "a run is replayable".
#    The honest consequence is stated rather than engineered around: a fixed public set IS
#    blocklistable, and a static page behind an exact-string blocklist of a family's seven TRUE
#    clauses (21 across the three families) mints at rate 1.0 — measured 200/200 through the real
#    mint path, and pinned as a live cell. That is residual (a), OPEN either way, and randomising
#    did not change it: see the ladder on the oracle.
#
# Invariants every shape must preserve (checked by test_boolean_clause_families):
#   * valid in its own breakout context — a quote-breakout clause must END on an UNCLOSED quote, so the
#     origin's own trailing quote closes it;
#   * truth-correct against a real SQL engine (the tests evaluate every clause on sqlite3);
#   * TRUE[i] LENGTH-MATCHED to FALSE[i]. A length-correlated set would re-open the hole through the
#     ``length`` dimension: an endpoint that merely ECHOES the parameter would separate by truth value;
#   * STABLE across calls — two calls return the identical set, so a run is replayable and the operator
#     can correlate it in their logs;
#   * PARTITIONED by the complete constant folder + the three-line `IN` rule, and NOT partitioned when
#     that filter is blinded to any one shape. The first half pins the OPEN class honestly; the second
#     is the incompleteness mechanism of (1).
_BOOLEAN_FAMILY_SHAPES = (
    # --- single-quote string-literal breakout: the origin wraps the value in '...' -------------------
    (("x' OR '{w}'='{w}",                        "x' OR '{w}'='{w2}"),
     ("x' OR '{hi}'>'{lo}",                      "x' OR '{lo}'>'{hi}"),
     ("x' OR {n2}>{n1} AND '{k}'<'{m}",          "x' OR {n1}>{n2} AND '{k}'<'{m}"),
     ("x' OR '{w}' LIKE '{w0}%",                 "x' OR '{w}' LIKE '{zc}%"),
     ("x' OR '{u}'<>'{v}",                       "x' OR '{u}'<>'{u}"),
     ("x' OR '{bm}' BETWEEN '{bl}' AND '{bh}",   "x' OR '{bg}' BETWEEN '{bl}' AND '{bh}"),
     ("x' OR {d1} IN (SELECT {d1}) AND '{k}'='{k}",
      "x' OR {d1} IN (SELECT {d2}) AND '{k}'='{k}")),
    # --- numeric context: the origin interpolates the value bare -------------------------------------
    (("1 OR {n1}={n1}",                          "1 OR {n1}={n2}"),
     ("1 OR {n2}>{n1}",                          "1 OR {n1}>{n2}"),
     ("1 OR {p2}>{p1} AND {q1}<{q2}",            "1 OR {p1}>{p2} AND {q1}<{q2}"),
     ("1 OR '{w}' LIKE '{w0}%'",                 "1 OR '{w}' LIKE '{zc}%'"),
     ("1 OR {n1}<>{n2}",                         "1 OR {n1}<>{n1}"),
     ("1 OR {nm} BETWEEN {nl} AND {nh}",         "1 OR {ng} BETWEEN {nl} AND {nh}"),
     ("1 OR {d1} IN (SELECT {d1})",              "1 OR {d1} IN (SELECT {d2})")),
    # --- double-quote string-literal breakout --------------------------------------------------------
    (('x" OR "{w}"="{w}',                        'x" OR "{w}"="{w2}'),
     ('x" OR "{hi}">"{lo}',                      'x" OR "{lo}">"{hi}'),
     ('x" OR {n2}>{n1} AND "{k}"<"{m}',          'x" OR {n1}>{n2} AND "{k}"<"{m}'),
     ('x" OR "{w}" LIKE "{w0}%',                 'x" OR "{w}" LIKE "{zc}%'),
     ('x" OR "{u}"<>"{v}',                       'x" OR "{u}"<>"{u}'),
     ('x" OR "{bm}" BETWEEN "{bl}" AND "{bh}',   'x" OR "{bg}" BETWEEN "{bl}" AND "{bh}'),
     ('x" OR {d1} IN (SELECT {d1}) AND "{k}"="{k}',
      'x" OR {d1} IN (SELECT {d2}) AND "{k}"="{k}')),
)


# The FIXED, PUBLIC literals. Every one is drawn at a FIXED WIDTH (letters 1 char, words 2 chars,
# numbers 2 digits, subquery operands 1 digit) and a shape's TRUE/FALSE templates are structurally
# identical, so TRUE[i] and FALSE[i] are length-matched by construction. The orderings each shape
# needs:  lo < k < bm < m < hi < bg  =>  hi > lo, k < m, lo <= bm <= hi (BETWEEN true), bg > hi (false).
# These are CONSTANTS on purpose (header point 3): the operator greps their logs for exactly these
# strings, and a run is replayable. Randomising them was measured worthless and pointed the wrong way.
_BOOLEAN_LITERALS = {
    "w": "mk", "w2": "mn", "w0": "m", "zc": "v", "u": "zr", "v": "zw",
    "k": "d", "m": "h", "lo": "b", "hi": "p", "bm": "f", "bl": "b", "bh": "p", "bg": "t",
    "n1": 31, "n2": 64, "p1": 27, "p2": 58, "q1": 42, "q2": 83,
    "nl": 19, "nm": 35, "nh": 71, "ng": 88, "d1": 3, "d2": 8,
}


def boolean_clause_families() -> tuple:
    """The shipped ``((trues, falses), ...)`` clause families — a STABLE, PUBLIC constant.

    Two calls return the identical set. That is deliberate (constitution VI.4 "make yourself
    correlatable", and this module's own contract that a run is replayable): the operator can grep
    their WAF and access logs for exactly these strings. The literals were randomised per run for one
    revision, to keep the set out of an operator's exact-string blocklist; that is retracted — it was
    measured worthless against a filter that derives its rules from the public TEMPLATES (a folder plus
    a nine-string blocklist over the ``IN`` atom partitioned 1500/1500 randomised draws), and defeating
    a defender's control on the operator's own estate is not something this scanner should do."""
    return tuple(
        (tuple(t.format(**_BOOLEAN_LITERALS) for t, _ in shapes),
         tuple(f.format(**_BOOLEAN_LITERALS) for _, f in shapes))
        for shapes in _BOOLEAN_FAMILY_SHAPES)


# The PINNED boolean discriminator. ``differential_response_oracle``'s DEFAULT dimension set includes
# ``latency``, so a boolean check that passed no discriminator let a FACT rest on TIMING alone over
# byte-identical bodies — and since the probe order is all-TRUE then all-FALSE, a step-slowdown crossing
# that boundary lands exactly on the truth partition. (The oracle pins this too, so a retained context
# cannot widen it back; this constant keeps the check's own early-stop reading the same channel.)
BOOLEAN_DISCRIMINATOR = {"dimensions": ["status", "length", "lexical"]}
# The oracle will not CONFIRM below this many distinct clauses per truth value (it may still refute).
_MIN_CLAUSES_PER_TRUTH_VALUE = 4


@dataclass(frozen=True)
class BooleanInferenceCheck:
    """Boolean-blind via a sequential probability ratio test (SPRT) whose per-round signal is a
    TRUTH-VALUE ATTRIBUTION test.

    A boolean FACT here means one thing: the response is a deterministic FUNCTION OF THE
    INJECTED BOOLEAN'S TRUTH VALUE. "The true request and the false request came back
    different" is NOT that claim — on a page whose body is drawn independently of the input
    (rotating banner, A/B bucket, two replicas behind a balancer) two draws differ by
    coincidence, and a determinism SCREEN does not remove it: a window that looks deterministic
    still contains the coincidence. So each round sends ``K_T`` DISTINCT, syntactically VARIED
    always-TRUE clauses and ``K_F`` distinct always-FALSE clauses (``true_clauses`` /
    ``false_clauses``), each twice byte-identically, and the round signals only when every TRUE
    response agrees with every other TRUE response, every FALSE with every FALSE, and the two
    clusters are disjoint. A page whose body is an INDEPENDENT DRAW per request must land ALL
    ``2*K_T`` true-side draws on one variant and ALL ``2*K_F`` false-side draws on another —
    ``<= 2 * 2**-(2*K_T+2*K_F)`` per round (``7.5e-9`` at the ``K_T = K_F = 7`` the drivers ship;
    ``3.1e-5``, still ~3300x below the SPRT's ``p0``, at the oracle's CONFIRM floor of 4).

    TWO THINGS THAT BOUND DOES NOT COVER, both real and both documented on the oracle as OPEN: a
    TRUTH-CORRELATED REQUEST FILTER (clause-SHAPE diversity makes every INCOMPLETE one refute, and
    that is ALL it does — a COMPLETE filter still partitions, and K is no lever at all here; see
    ``true_clauses`` below) and a page that is a deterministic but ARBITRARY function of the URL
    (a per-URL CDN cache), where repetition is not new evidence and the bound degrades to
    ``2 * 2**-(K_T+K_F)``; for THAT one more distinct clauses is the lever, and the drivers also
    bound the number of independent attempts per URL.

    A cheap BASELINE PRE-GATE runs first (``baseline_samples`` identical sends of
    ``false_clauses[0]``; not-all-identical ⇒ the oracle refuses without any inference) and each
    round's byte-identical repeats are a HARD REFUTE — but those are pre-filters, not the
    soundness core.

    A legitimately noisy-but-vulnerable page, and a vulnerable page whose varied true clauses do
    not all land on the same response, are refused to a LEAD — a documented recall cost, the safe
    direction (a false LEAD, never a false FACT)."""

    id: str
    bug_class: str
    # K_T clauses that are all logically TRUE and K_F that are all logically FALSE. Build them with
    # ``boolean_clause_families`` unless you have read that block's header: the clauses must be DISTINCT
    # and must vary in COMPARISON SHAPE rather than only in their literals, because a set whose truth
    # value tracks ONE surface feature is partitioned by an interposer with NO SQL engine at all, which
    # then mints on a STATIC page (measured 2000/2000 for a literal-only set behind a CRS-942130 regex).
    # Shape diversity buys INCOMPLETENESS, nothing more: it makes a PARTIAL filter refute. A filter that
    # is COMPLETE over the shape set still partitions the shipped clauses perfectly — measured 600/600
    # false FACTs behind a constant folder carrying one rule per shape — and no clause set fixes that,
    # because a clause whose truth VIGIL knows a priori is a constant expression the filter can fold
    # too. That is residual (a) on ``boolean_inference_oracle``, and it is OPEN.
    # >= 4 each is the oracle's CONFIRM floor; the drivers ship 7.
    true_clauses: tuple[str, ...]
    false_clauses: tuple[str, ...]
    n_max: int = 24
    alpha: float = 0.05
    beta: float = 0.05
    p1: float = 0.9
    p0: float = 0.1
    # identical-request sends for the determinism pre-gate. Only a cheap PRE-FILTER now (each round
    # already carries 2*(K_T+K_F) identical-request pairs as the hard refute), so 8 is plenty — it was
    # 16 when the gate was load-bearing, and that cost 3x over the three clause families.
    baseline_samples: int = 8
    # An ALREADY-COLLECTED determinism baseline (responses to ONE identical request on this endpoint).
    # Determinism is a property of the ENDPOINT, not of the clause, so a driver probing several clause
    # families against the same insertion point collects it ONCE and shares it (see boolean_redrive).
    shared_baseline: tuple = ()

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        from ..verify.oracles import differential_response_oracle  # local: avoid import cycle at module load

        trues = tuple(self.true_clauses)
        falses = tuple(self.false_clauses)
        if (len(set(trues)) < _MIN_CLAUSES_PER_TRUTH_VALUE
                or len(set(falses)) < _MIN_CLAUSES_PER_TRUTH_VALUE or set(trues) & set(falses)):
            # FAIL-CLOSED: too few DISTINCT clauses per truth value cannot attribute a response to a truth
            # VALUE (one clause is one draw, and a duplicate is not an independent draw — on a page that
            # caches per URL a duplicate returns the identical cached body and would fake agreement).
            # A clause appearing on BOTH sides is degenerate too. Emit no rounds — the oracle can only refuse.
            return FindingContext.from_boolean_probes(
                true_rounds=[], false_rounds=[], true_repeat_rounds=[], false_repeat_rounds=[],
                bug_class=self.bug_class, discriminator=BOOLEAN_DISCRIMINATOR)

        def _differs(a: dict, b: dict) -> bool:
            # the PINNED boolean discriminator — never the oracle's default set, which includes LATENCY
            # (a boolean FACT must rest on response CONTENT; timing is timing_oracle's job).
            return differential_response_oracle(a, b, BOOLEAN_DISCRIMINATOR).fired

        # --- DETERMINISM PRE-GATE: responses to ONE IDENTICAL request, all of which must be identical.
        #     A non-deterministic page (coarse OR high-entropy) fails this and is refused BEFORE any
        #     inference — short-circuit on the first divergence to bound the traffic. A driver that
        #     already collected this for the endpoint hands it in via ``shared_baseline`` (no re-sends).
        baseline: list[dict] = [dict(b) for b in self.shared_baseline]
        for _ in range(0 if baseline else max(2, self.baseline_samples)):
            s = _as_dict(send(template.render(point, falses[0])))
            baseline.append(s)
            if _differs(baseline[0], s):
                break  # proven non-deterministic — the oracle will refuse over these samples
        if len(baseline) >= 2 and _differs(baseline[0], baseline[-1]):
            # non-deterministic: hand the oracle the baseline (no rounds) so it authoritatively refuses.
            return FindingContext.from_boolean_probes(
                true_rounds=[], false_rounds=[], true_repeat_rounds=[], false_repeat_rounds=[],
                bug_class=self.bug_class, false_baseline_samples=baseline,
                discriminator=BOOLEAN_DISCRIMINATOR)

        upper = math.log((1.0 - self.beta) / self.alpha)
        lower = math.log(self.beta / (1.0 - self.alpha))
        llr = 0.0
        true_rounds: list[list[dict]] = []
        false_rounds: list[list[dict]] = []
        true_repeat_rounds: list[list[dict]] = []
        false_repeat_rounds: list[list[dict]] = []
        for _ in range(self.n_max):
            t = [_as_dict(send(template.render(point, c))) for c in trues]
            t_rep = [_as_dict(send(template.render(point, c))) for c in trues]
            f = [_as_dict(send(template.render(point, c))) for c in falses]
            f_rep = [_as_dict(send(template.render(point, c))) for c in falses]
            true_rounds.append(t)
            true_repeat_rounds.append(t_rep)
            false_rounds.append(f)
            false_repeat_rounds.append(f_rep)
            # PER-ROUND HARD REFUTE: a byte-identical clause repeat that differs proves the page is
            # non-deterministic → stop and let the oracle refuse the whole finding.
            if any(_differs(a, b) for a, b in zip(t, t_rep)) or any(_differs(a, b) for a, b in zip(f, f_rep)):
                break
            # TRUTH-VALUE ATTRIBUTION: one TRUE cluster, one FALSE cluster, disjoint. (The oracle
            # recomputes this authoritatively; this local copy only drives the early SPRT stop.)
            t_all, f_all = t + t_rep, f + f_rep
            within = all(not _differs(x, y) for c in (t_all, f_all)
                         for i, x in enumerate(c) for y in c[i + 1:])
            across = all(_differs(x, y) for x in t_all for y in f_all)
            signal = within and across
            llr += math.log(self.p1 / self.p0) if signal else math.log((1.0 - self.p1) / (1.0 - self.p0))
            if llr >= upper or llr <= lower:
                break  # SPRT reached a decision — stop early

        return FindingContext.from_boolean_probes(
            true_rounds=true_rounds, false_rounds=false_rounds,
            true_repeat_rounds=true_repeat_rounds, false_repeat_rounds=false_repeat_rounds,
            bug_class=self.bug_class, false_baseline_samples=baseline,
            discriminator=BOOLEAN_DISCRIMINATOR,
        )


def _as_dict(resp: object) -> dict:
    if isinstance(resp, dict):
        return resp
    return {"body": str(resp)}


@dataclass(frozen=True)
class TimingCheck:
    """Statistical time-based blind (SQLi / command injection).

    Measures ``samples`` paired latencies — a benign value vs a delay-injecting
    payload — and hands them to the timing oracle, which decides via a rank-sum
    test + effect-size floor + optional dose-response (never a fixed threshold).
    Benign and probe requests are interleaved so latency drift biases both
    equally. Expensive (``2*samples`` requests per point), so it is opt-in and
    best spent on bandit-prioritised candidates."""

    id: str
    bug_class: str
    benign: str
    sleep_payload: str
    injected_ms: float
    samples: int = 15
    # optional second, larger delay for a dose-response corroboration
    dose_payload: str | None = None
    dose_ms: float | None = None

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        base: list[float] = []
        treat: list[float] = []
        dose_samples: list[float] = []
        for _ in range(self.samples):
            base.append(self._time(send, template, point, self.benign))
            treat.append(self._time(send, template, point, self.sleep_payload))
            if self.dose_payload is not None:
                dose_samples.append(self._time(send, template, point, self.dose_payload))

        dose = None
        if self.dose_payload is not None and self.dose_ms:
            dose = {
                "low_ms": self.injected_ms, "low_samples": treat,
                "high_ms": self.dose_ms, "high_samples": dose_samples,
            }
        return FindingContext.from_timing_samples(
            base, treat, bug_class=self.bug_class,
            injected_ms=self.injected_ms, dose=dose,
        )

    @staticmethod
    def _time(send: Send, template: RequestTemplate, point: InsertionPoint, value: str) -> float:
        """Wall-time one request in milliseconds. Times the ``send`` itself (the
        I/O), so it works whether or not the send reports its own latency; a
        blind payload that makes the target error is still timed."""
        t0 = time.monotonic()
        try:
            send(template.render(point, value))
        except Exception:
            pass
        return (time.monotonic() - t0) * 1000.0


@dataclass(frozen=True)
class MarkerReflectionCheck:
    """Side-effect reflection: place a unique canary (wrapped by `payload_template`)
    and confirm via the side-effect oracle iff the *raw* canary reaches the
    response sink (reflected/stored XSS, error-based/echoed injection,
    template/EL reflection, path-traversal content markers).

    The canary is derived from the point id so it is unique per position and the
    run is deterministic. `payload_template` must contain `{marker}`."""

    id: str
    bug_class: str
    payload_template: str = "{marker}"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        marker = f"crucible{_slugify(point.id)}mark"
        payload = self.payload_template.format(marker=marker)
        resp = send(template.render(point, payload))
        body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
        return FindingContext.from_side_effect(marker, body, bug_class=self.bug_class)

    def adapt(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        """WAF-adaptive fallback (opt-in, engine-driven): when the canonical payload
        is filtered/blocked, synthesize a form that both gets past the filter AND
        reflects the canary into an EXECUTABLE context, then hand that response to the
        same side-effect oracle. The sink proxy is the executable-reflection oracle
        itself, so a bypass that only reflects inertly is not treated as success — the
        precision anchor is unchanged."""
        from .fitness import reflection_proximity
        from .waf_evasion import adaptive_bypass
        from ..verify.oracles import reflection_context_oracle

        marker = f"crucible{_slugify(point.id)}mark"
        payload = self.payload_template.format(marker=marker)

        def send_form(form: str) -> dict:
            return send(template.render(point, form))

        def sink_present(resp: dict) -> bool:
            body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
            return reflection_context_oracle(marker, body).fired

        def proximity(resp: dict) -> float:
            body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
            return reflection_proximity(marker, body)

        res = adaptive_bypass(payload, send_form, sink_present, proximity=proximity)
        if res is None:
            return None
        body = res.response.get("body", "") if isinstance(res.response, dict) else str(res.response)
        return FindingContext.from_side_effect(marker, body, bug_class=self.bug_class)


@dataclass(frozen=True)
class OOBCheck:
    """Out-of-band (blind) check: mint a unique correlation token, embed its
    loopback callback URL into a payload, inject it, and poll the receiver for
    an inbound interaction. The proof is the *callback the target makes*, not
    anything in the response — so this reaches the blind classes (SSRF, blind
    XXE, OOB SQLi, deserialization/JNDI gadgets) that leave no visible signal.

    ``payload_template`` must contain ``{callback}``. Polling is deadline-bounded
    with a small interval so a DEFERRED interaction (a callback that lands after
    the injecting request returns) is still caught — the case a single one-shot
    poll misses. Distinguished from response-based checks by ``wants_oob``; the
    engine hands it the receiver."""

    id: str
    bug_class: str
    payload_template: str = "{callback}"
    poll_deadline: float = 2.0
    poll_interval: float = 0.05

    wants_oob: ClassVar[bool] = True

    ttl: float = 300.0

    def probe(
        self, template: RequestTemplate, point: InsertionPoint, send: Send, oob: OOBReceiver
    ) -> FindingContext | None:
        token, callback_url = oob.register_token()
        # VF-2b: when the receiver signs receipts (a collector keypair is configured), a receipt-bearing hit
        # REQUIRES an authority-bound TTL window, so record the mint anchor. When there is NO collector key
        # (VF-2a token-only), omit it so the windowless path stays byte-identical.
        issued_at = time.time() if getattr(oob, "collector_pubkey", None) else None
        payload = self.payload_template.format(callback=callback_url)
        try:
            send(template.render(point, payload))
        except Exception:
            # A blind payload may make the target error its own response; the
            # callback — not the response — is the signal, so keep waiting for it.
            pass
        deadline = time.monotonic() + self.poll_deadline
        hits = oob.poll(token)
        while not hits and time.monotonic() < deadline:
            time.sleep(self.poll_interval)
            hits = oob.poll(token)
        # VF-2a: retain the REGISTERED per-finding token so the oracle fires only for a callback that carried
        # it (live AND on offline re-verify) — a fabricated/unrelated hit no longer confirms. On the VF-2b
        # path, also retain the mint anchor (the TTL DURATION is taken out-of-band from the signed authority).
        return FindingContext.from_oob(
            hits, bug_class=self.bug_class, expected_token=token,
            issued_at=issued_at,
            expires_at=(issued_at + float(self.ttl)) if issued_at is not None else None,
        )


@dataclass(frozen=True)
class DNSOOBCheck:
    """DNS out-of-band (blind) check: the sibling of :class:`OOBCheck` for a target whose outbound HTTP is
    blocked but whose resolver still forwards DNS. Mint a unique token whose callback HOST is
    ``<token>.<base-domain>``, embed it in a payload that triggers a DNS LOOKUP even when HTTP egress is
    filtered, inject it, and poll the AUTHORITATIVE DNS collector (``verify.dns_collector.DNSCollector``)
    for the query the target's resolver forwarded. The proof is the DNS lookup — a strictly weaker but still
    sound claim than a completed HTTP fetch (resolution reached us; a connection need not have completed).

    ``payload_template`` must contain ``{callback}`` (the bare DNS host — NOT a URL with a scheme, though a
    payload may wrap it, e.g. ``http://{callback}/``). ``ttl`` (seconds) mints a TTL window retained on the
    finding context; a lookup observed outside it is refused as EXPIRED/REPLAY on live AND offline re-verify.
    ``oob`` is a ``DNSCollector`` (its ``register_dns_token`` / ``poll`` surface); an ``OOBReceiver`` also
    fits (``register_token`` alias), so the same check runs against either collector."""

    id: str
    bug_class: str
    payload_template: str = "{callback}"
    poll_deadline: float = 2.0
    poll_interval: float = 0.05
    ttl: float = 300.0

    wants_oob: ClassVar[bool] = True

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send, oob) -> "FindingContext | None":
        register = getattr(oob, "register_dns_token", None) or oob.register_token
        token, host = register()
        issued_at = time.time()
        payload = self.payload_template.format(callback=host)
        try:
            send(template.render(point, payload))
        except Exception:
            # A blind payload may make the target error its own response; the DNS lookup — not the
            # response — is the signal, so keep waiting for it.
            pass
        deadline = time.monotonic() + self.poll_deadline
        hits = oob.poll(token)
        while not hits and time.monotonic() < deadline:
            time.sleep(self.poll_interval)
            hits = oob.poll(token)
        # Retain the registered token AND the mint TTL window so the oracle fires only for a token-matched
        # lookup observed inside the window (live AND on deterministic offline re-verify).
        return FindingContext.from_oob(
            hits, bug_class=self.bug_class, expected_token=token,
            issued_at=issued_at, expires_at=issued_at + float(self.ttl),
        )


@runtime_checkable
class RequestCheck(Protocol):
    """A check that operates on the WHOLE request/response — adding a header,
    reading a response header — rather than fuzzing one insertion point. The
    engine runs it once per request. Returns oracle-ready evidence, or None."""

    id: str
    bug_class: str

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None: ...


@dataclass(frozen=True)
class CorsActiveCheck:
    """Active CORS misconfiguration: send a hostile ``Origin`` and check whether
    the server REFLECTS it back with credentials — the exact combination that lets
    an attacker page read authenticated responses. Confirmed via achieved-state
    only on the dangerous reflection, so a properly-scoped CORS policy does not
    fire. Note: ``Access-Control-Allow-Origin: *`` WITH credentials is deliberately
    NOT confirmed here — browsers refuse ``*``+credentials, so it is not
    credential-readable and would be an over-claim as an exploitable FACT (a passive
    check may still surface it as a lower-severity misconfiguration lead)."""

    id: str = "cors-active"
    bug_class: str = "cors"
    evil_origin: str = "https://crucible-evil-origin.test"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        headers = [(k, v) for k, v in req.headers if k.lower() != "origin"]
        headers.append(("Origin", self.evil_origin))
        resp = send(req.model_copy(update={"headers": headers}))
        if not isinstance(resp, dict):
            return None
        rh = resp.get("headers", []) or []
        acao = next((str(v) for k, v in rh if str(k).lower() == "access-control-allow-origin"), "")
        acac = next((str(v) for k, v in rh if str(k).lower() == "access-control-allow-credentials"), "")
        # The ORACLE decides the exploitable condition over the raw header values:
        # ACAO REFLECTS the hostile origin AND credentials are allowed. A wildcard
        # (`*`) is excluded — browsers do not honour `*`+credentials, so it cannot
        # read authenticated responses. A properly-scoped policy fails the predicate.
        return FindingContext.from_predicate(
            {"acao": acao, "acac": acac, "evil_origin": self.evil_origin},
            {"all": [
                {"eq": [{"var": "acao"}, {"var": "evil_origin"}]},
                {"ieq": [{"var": "acac"}, "true"]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class HostHeaderCheck:
    """Host-header injection: send a hostile ``Host`` and check whether the app
    reflects it into an absolute URL — a redirect ``Location`` or an absolute link
    in the body — which is what poisons password-reset links and web-cache. A
    plain-text echo of the host does not fire; only its use as a URL authority."""

    id: str = "host-header"
    bug_class: str = "host_header_injection"
    evil_host: str = "crucible-evil-host.test"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        headers = [(k, v) for k, v in req.headers if k.lower() != "host"]
        headers.append(("Host", self.evil_host))
        resp = send(req.model_copy(update={"headers": headers}))
        if not isinstance(resp, dict):
            return None
        body = str(resp.get("body", ""))
        rh = resp.get("headers", []) or []
        location = next((str(v) for k, v in rh if str(k).lower() == "location"), "")
        # The oracle checks whether the hostile Host became the AUTHORITY of a URL the
        # app EMITS (a redirect Location, an href/src/action link/resource/form, or a
        # meta/JS redirect) — the only forms a victim's browser would actually use. A
        # plain-text ECHO of the reconstructed URL back to the requester does NOT fire
        # (not exploitable), and matching is on the WHOLE authority, so a subdomain
        # reflection like `//evil-host.cdn.example.com` does not collide with the evil
        # host either.
        # As above: on a followed 3xx the body is never rendered, so a Host-derived link inside it is not
        # something a victim can use. The Location disjunct still stands on its own.
        followed = bool(location) and int(resp.get("status", 0) or 0) in (301, 302, 303, 307, 308)
        body_available = bool(resp.get("body_semantically_available", True))
        return FindingContext.from_predicate(
            {"location_host": _host(location), "evil_host": self.evil_host,
             "body": body, "followed_redirect": followed, "body_available": body_available,
             "emitted_url_hosts": _emitted_url_hosts(body)},
            {"any": [
                {"eq": [{"var": "location_host"}, {"var": "evil_host"}]},
                {"all": [
                    {"eq": [{"var": "body_available"}, True]},
                    {"not": {"eq": [{"var": "followed_redirect"}, True]}},
                    {"in": [{"var": "evil_host"}, {"var": "emitted_url_hosts"}]},
                ]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class OpenRedirectCheck:
    """Open redirection: inject a canary absolute URL into a redirect parameter
    and confirm via achieved-state ONLY when the response actually redirects to
    the canary's host — a 30x Location to the canary host, or a meta-refresh /
    JS-location redirect that resolves to it. A redirect that stays on the app's
    own host (the app merely echoing the param inside its own URL) does NOT fire,
    so this does not false-positive on reflected-but-safe redirect params.

    Runs on any point (the caller scopes it via targeting to redirect-ish params).
    Needs response headers from ``send``; a follow-redirects=False client (the
    production executor) exposes the Location header."""

    id: str = "open-redirect"
    bug_class: str = "open_redirect"
    canary: str = "https://crucible-redirect-canary.test/pwned"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        resp = send(template.render(point, self.canary))
        if not isinstance(resp, dict):
            return None
        status = int(resp.get("status", 0))
        headers = resp.get("headers", []) or []
        location = next((str(v) for k, v in headers if str(k).lower() == "location"), "")
        body = str(resp.get("body", ""))

        # The oracle decides redirection to the canary host over the raw status,
        # Location, and the body's ACTUAL navigation targets: a 30x Location to the
        # canary host, OR a meta-refresh / JS-location sink whose target host IS the
        # canary host. Reflection on the app's own host — or the canary merely echoed
        # somewhere in the body next to an unrelated <meta http-equiv=...> — fails the
        # predicate (no false positive on echoed-but-safe params).
        # A 3xx that carries a Location is FOLLOWED by the browser, so its body is never rendered: any
        # navigation the body describes cannot happen, and counting it would be a false FACT.
        followed = bool(location) and status in (301, 302, 303, 307, 308)
        # A body VIGIL could not decode (unsupported Content-Encoding, undeclared non-UTF-8 charset, a
        # truncated response) is NOT evidence: the body disjunct must not fire over it, and a non-firing
        # over it is INCONCLUSIVE for the runner, never CLEAN. Captures without the flag are treated as
        # available so the engine's own plain-text sends behave exactly as before.
        body_available = bool(resp.get("body_semantically_available", True))
        return FindingContext.from_predicate(
            {"status": status, "location_host": _host(location),
             "canary_host": _host(self.canary), "body": body,
             "followed_redirect": followed, "body_available": body_available,
             "markup_redirect_hosts": _markup_redirect_hosts(body)},
            {"any": [
                {"all": [
                    {"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                    {"eq": [{"var": "location_host"}, {"var": "canary_host"}]},
                ]},
                {"all": [
                    {"eq": [{"var": "body_available"}, True]},
                    {"not": {"eq": [{"var": "followed_redirect"}, True]}},
                    {"min_len": [{"var": "canary_host"}, 1]},
                    {"in": [{"var": "canary_host"}, {"var": "markup_redirect_hosts"}]},
                ]},
            ]},
            bug_class=self.bug_class)


def _graphql_schema_type_count(body: str) -> int:
    """Number of types in a GraphQL introspection RESPONSE (``data.__schema.types``), or 0 when the body is
    not a well-formed introspection response. VIGIL sends its OWN introspection query; this counts what came
    back. Total on untrusted input — a non-JSON body, a GraphQL ``errors`` response ("introspection is
    disabled"), or a non-GraphQL page all count 0, so the predicate fires ONLY on a real returned schema."""
    import json
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return 0
    if not isinstance(obj, dict):
        return 0
    data = obj.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    types = schema.get("types") if isinstance(schema, dict) else None
    return len(types) if isinstance(types, list) else 0


@dataclass(frozen=True)
class GraphqlIntrospectionCheck:
    """GraphQL introspection exposure: send VIGIL's OWN minimal introspection query and confirm via
    achieved-state ONLY when the endpoint returns a WELL-FORMED introspection schema
    (``data.__schema.types`` is a non-empty array). A 400/403, a GraphQL ``errors`` response
    ("introspection is disabled"), or any non-GraphQL page fails the predicate — so this does NOT fire on the
    mere presence of a ``/graphql`` path, and never on a tool's say-so: the schema is read from VIGIL's own
    live capture. A body VIGIL could not decode is NOT evidence (the predicate is suppressed), so a
    non-firing over an unreadable body is INCONCLUSIVE for the runner, never CLEAN.

    Request-level (no insertion point): it POSTs the query to the endpoint URL as ``application/json``."""

    id: str = "graphql-introspection"
    bug_class: str = "graphql_introspection"
    query: str = '{"query":"query IntrospectionQuery { __schema { types { name } } }"}'

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        headers = [(k, v) for k, v in req.headers if k.lower() != "content-type"]
        headers.append(("Content-Type", "application/json"))
        resp = send(req.model_copy(update={"method": "POST", "headers": headers, "body": self.query}))
        if not isinstance(resp, dict):
            return None
        body = str(resp.get("body", ""))
        # A body VIGIL could not decode (unsupported encoding / undeclared charset / truncated) is not
        # evidence: the count disjunct must not fire over it, and a non-firing is INCONCLUSIVE not CLEAN.
        body_available = bool(resp.get("body_semantically_available", True))
        return FindingContext.from_predicate(
            {"introspection_type_count": _graphql_schema_type_count(body), "body_available": body_available},
            {"all": [
                {"eq": [{"var": "body_available"}, True]},
                {"gt": [{"var": "introspection_type_count"}, 0]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class IdorCheck:
    """Broken-object-level authorization (IDOR / BOLA / BFLA) via a two-identity read.

    Confirmation is achieved-state, not reflection: acting as the attacker, it
    requests an object owned by a DIFFERENT identity (``victim_ref``) and checks
    whether the response actually reveals that identity's PRIVATE content — the
    ground truth being what the victim's own session (``victim_send``) sees for
    the same reference.

    SOUNDNESS (this is why bola/idor were once reverted as UNSOUND): a naive
    ``contains(attacker_body, victim_body)`` over the WHOLE body FALSE-POSITIVES on
    shared boilerplate — two identities render the same shell/nav/footer, so the
    victim's page is trivially a substring of the attacker's. Even a victim-UNIQUE
    discriminator (``victim_discriminator``) is not enough ON ITS OWN: the operator
    can HONESTLY BUT WRONGLY believe a footer/banner/tenant string is victim-unique
    when it is really global boilerplate present in EVERY record — including the
    attacker's own. That mistake reconstructs the exact reverted false positive.
    So a FACT here requires the discriminator PLUS the mandatory guards. The oracle
    fires ONLY when:

      * (round-3, substantiveness) the attacker's cross-read is a SUBSTANTIVE SUCCESS
        — a 2xx body with real content, not an empty / errored / soft-deny page —
        because a ``contains`` / ``not-contains`` over a non-substantive body is
        VACUOUS (an absent marker proves nothing when the body carries nothing). The
        old ``attacker_status == 200`` floor is replaced by ``is_substantive_success``,
        AND
      * the discriminator genuinely IS in the victim's AUTHORITATIVE body — and that
        victim read is ITSELF a substantive success (proving the operator handed a real
        per-identity marker present in a real record, not a typo echoed in an error), AND
      * the attacker's cross-read REACHED that same discriminator (the achieved
        unauthorized read), AND
      * the discriminator is ABSENT from the attacker's OWN object (``control_ref``)
        AND that control read is a SUBSTANTIVE SUCCESS — the differential proves the
        marker is victim-SPECIFIC only when the attacker's own object was actually READ.
        If the control 404s / 403s / is empty, its absent marker is VACUOUS (a global
        boilerplate string would pass the not-contains for free), so a non-substantive
        control fails CLOSED to a LEAD — never a FACT (round-3), AND
      * (round-2, ref-independence) the discriminator is NOT a substring of the
        requested ``victim_ref`` — otherwise a "discriminator" that is really the
        object id itself reduces to pure REFLECTION: a secured app that echoes the
        requested id in a 200 soft-deny body ("access denied for object 42") would
        mint a false FACT with ZERO unauthorized read. A ref-derived discriminator
        is refused, AND
      * (round-2, authorization-gated) the discriminator is ABSENT from a
        no-credential / logged-out baseline GET of the SAME ``victim_ref``
        (``nocred_send``) AND that baseline is a VALID gating proof — EITHER a
        substantive 2xx that simply lacks the marker OR a genuine authorization
        DENIAL (401 / 403). A bare error (5xx / empty / network / 404) baseline is
        NOT proof: its absent marker is VACUOUS, so it fails CLOSED to a LEAD
        (round-3). If a logged-out request reaches the marker, the read was never
        "unauthorized"; it is public content, and must not mint, AND
      * (round-4, access-gated by a same-ref UNAUTHORIZED-AUTHENTICATED baseline;
        round-5 HARDENED to SAME-SHAPE) the discriminator is ABSENT from a read of
        the SAME ``victim_ref`` by a THIRD identity — an authenticated-but-
        UNAUTHORIZED principal (``unauth_send``: a second attacker-controlled
        account that also lacks access to ``victim_ref``) — AND that baseline is a
        SUBSTANTIVE SAME-SHAPE read: a 2xx that actually RENDERED the same object,
        the same class as the attacker's (required-substantive) cross-read. This is
        the DECISIVE anti-reflection proof that content heuristics could not give: a
        per-object REFLECTED token (a public slug / uuid / display-id echoed into an
        authenticated 200 soft-deny — no bare-error phrase, not a literal substring
        of ``victim_ref``) is echoed by ANY same-shape read of that object, so it
        appears in this baseline TOO, the absent-clause FAILS, and the check does
        NOT fire. ONLY a datum genuinely access-gated at the object level — PRESENT
        in the attacker's read yet ABSENT from a peer's SAME-SHAPE read of the same
        object — passes. A 401/403 DENIAL is NOT a valid clause-(c) control: it
        never renders the object, so a reflected token is absent from it VACUOUSLY
        (absent because unrendered, not because private) — accepting it is exactly
        the round-4 hole a reflected slug rode into a durable false FACT. Absent a
        supplied ``unauth_send`` — OR when the supplied baseline is a denial / not a
        substantive same-shape read — the class DOWNGRADES to a LEAD (never a FACT).

    Without a discriminator, without ``control_ref``, when the discriminator is
    ref-derived, without a ``nocred_send`` baseline, without an ``unauth_send``
    same-ref unauthorized-authenticated baseline, OR when ANY of the reads
    (victim ground-truth, attacker cross-read, attacker-own control) is not a
    substantive success / either baseline is not a valid discriminating proof, the
    check CANNOT fire soundly, so it returns None (the class stays a rigorous LEAD,
    never a false CLEAN and never a false FACT). 'Victim-unique' is ENFORCED by the
    substantive control-object differential; the datum being genuinely ACCESS-GATED
    (private, not reflected / public / boilerplate / a common per-object token) is
    ENFORCED by the 3-VIEW DIFFERENTIAL — present in the owner's authoritative read
    AND the attacker's cross-read, PROVABLY ABSENT from the same-ref
    unauthorized-authenticated baseline (and from the logged-out baseline) — never
    by ref-independence alone (a literal-substring test a reflected non-substring
    token defeats) and never accepted as a bare operator assertion or satisfied
    VACUOUSLY over an empty / errored / denied body. GET-only
    (a cross-read is a non-mutating read; a non-GET/HEAD template returns None). Runs
    only on the object-reference point (``ref_param``); other points return None.
    ``victim_send`` is a send authenticated as the victim/owner (a second AuthSession / the
    ceremony's second identity riding the same gated executor); the ``send`` passed to
    ``probe`` is the ATTACKER identity (authenticated as a DIFFERENT user); ``unauth_send`` is a
    THIRD, authenticated-but-UNAUTHORIZED identity (a second attacker-controlled account that also
    lacks access to ``victim_ref``) — the same-ref negative reference clause (c) is derived from;
    all are distinct from the credential-free ``nocred_send``."""

    id: str
    ref_param: str
    victim_ref: str
    victim_send: Send
    bug_class: str = "idor"
    # The per-identity marker that ONLY the victim's authoritative record contains. Empty ⇒ the sound
    # check cannot fire (fail-closed to a non-firing LEAD, never the boilerplate false positive). Contract:
    # a REF-INDEPENDENT victim-PRIVATE token (an account id / private email / invoice number that is NOT the
    # requested object id), never the object reference itself — a ref-derived value is pure reflection.
    victim_discriminator: str = ""
    # MANDATORY attacker-owned reference for the near-zero-FP negative control: the discriminator MUST be
    # absent when the attacker reads their OWN object, proving the marker is victim-specific not global. That
    # control read MUST be a SUBSTANTIVE SUCCESS (round-3): a 404/403/empty control makes the not-contains
    # VACUOUS (a global marker would pass it for free), so a non-substantive control fails closed to a LEAD.
    # Empty ⇒ the FACT cannot be minted (probe returns None ⇒ a rigorous LEAD), because 'victim-unique'
    # is only PROVEN by the SUBSTANTIVE control differential, never by the operator's assertion.
    control_ref: str = ""
    # MANDATORY no-credential (logged-out) baseline send for the round-2 authorization-gated proof: a
    # same-ref GET issued with NO identity. The discriminator MUST be ABSENT from it AND the baseline read
    # MUST be a VALID gating proof (round-3) — EITHER a substantive 2xx that lacks the marker OR a genuine
    # 401/403 authorization denial; a bare 5xx/empty/404 baseline is vacuous and fails closed. Absence in a
    # valid baseline proves the content is authorization-gated, not public/reflected. None ⇒ baseline-less ⇒
    # the probe returns None (a rigorous LEAD, never a FACT), because 'unauthorized read' is only PROVEN by
    # the logged-out denial, never asserted.
    nocred_send: Send | None = None
    # MANDATORY (round-4) same-ref UNAUTHORIZED-AUTHENTICATED baseline, HARDENED to SAME-SHAPE (round-5): a GET
    # of ``victim_ref`` as a THIRD identity — an authenticated-but-UNAUTHORIZED principal (a second
    # attacker-controlled account that also lacks access to victim_ref). The discriminator MUST be ABSENT from it
    # AND the read MUST be a SUBSTANTIVE SAME-SHAPE read: a 2xx that RENDERED the same object (the same class as
    # the attacker's substantive cross-read). This is the DECISIVE anti-reflection proof: a per-object REFLECTED
    # token (a public slug/uuid/display-id echoed into an authenticated 200 soft-deny — the round-3 fourth-variant
    # FP) is echoed by ANY same-shape read of the object, so it appears in THIS baseline too, its absent-clause
    # fails, and the check does NOT fire; only a datum genuinely access-gated at the object level (present for the
    # attacker, absent from a peer's same-shape read of the same object) passes. A 401/403 DENIAL is NOT a valid
    # clause-(c) control — a denial never renders the object, so a reflected token is absent from it VACUOUSLY;
    # accepting it (as round-4 did) let a reflected slug mint a DURABLE false FACT. None, a denial, or a
    # non-substantive read ⇒ the probe returns None (a rigorous LEAD, never a FACT) — the enforced boundary.
    unauth_send: Send | None = None

    # Safe (non-mutating) methods a cross-read / baseline may use — a read must never mutate.
    _READ_METHODS: ClassVar[frozenset[str]] = frozenset({"GET", "HEAD"})

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        if point.name != self.ref_param:
            return None
        disc = (self.victim_discriminator or "").strip()
        if not valid_discriminator(disc):
            # No usable victim-unique discriminator ⇒ the only sound predicate is unavailable. Do NOT fall
            # back to the whole-body containment (the reverted false positive). Emit nothing: a rigorous LEAD.
            return None
        control_ref = (self.control_ref or "").strip()
        if not control_ref:
            # The negative control is MANDATORY: without an attacker-owned reference we cannot PROVE the
            # discriminator is victim-unique rather than global boilerplate (the exact shared-boilerplate FP
            # that caused the prior IDOR/BOLA revert). Fail closed to a non-firing LEAD — never mint here.
            return None
        # ROUND-2 (v) ref-independence, config-level guard: a discriminator that is a substring of the
        # requested victim_ref is REF-DERIVED — its "presence" in the attacker's body can be a pure echo of
        # the requested id (a soft-deny that reflects the ref), NOT an achieved read. Fail closed to a LEAD.
        if disc in self.victim_ref:
            return None
        # ROUND-2 (iv) authorization-gated, config-level guard: without a no-credential baseline we cannot
        # PROVE the content is gated (a public/reflected body is not an unauthorized read). Fail closed.
        nocred_send = self.nocred_send
        if nocred_send is None:
            return None
        # ROUND-4 access-gated, config-level guard: without a same-ref UNAUTHORIZED-AUTHENTICATED baseline we
        # cannot distinguish an achieved read of PRIVATE content from a per-object REFLECTED token echoed into
        # an authenticated soft-deny (the round-3 fourth-variant FP). This is the ENFORCED BOUNDARY: no such
        # baseline ⇒ DOWNGRADE to a LEAD (never a FACT), never a content-heuristic guess.
        unauth_send = self.unauth_send
        if unauth_send is None:
            return None
        victim_req = template.render(point, self.victim_ref)
        # GET-only: a cross-read (and its baseline) is a non-mutating read; a mutating template cannot serve
        # as a read-confirmation, so fail closed to a LEAD rather than issue a write under this check.
        if victim_req.method.strip().upper() not in self._READ_METHODS:
            return None
        victim = self.victim_send(victim_req)
        attacker = send(template.render(point, self.victim_ref))
        control = send(template.render(point, control_ref))
        nocred = nocred_send(template.render(point, self.victim_ref))
        # ROUND-4: the SAME victim_ref read as the THIRD, authenticated-but-UNAUTHORIZED principal.
        unauth = unauth_send(template.render(point, self.victim_ref))

        def _status(resp: object) -> int:
            return int(resp.get("status", 0)) if isinstance(resp, dict) else 0

        def _body(resp: object) -> str:
            # Stored STRIPPED so the predicate's ``min_len`` measures real content (a whitespace-padded body
            # cannot masquerade as substantive) and the ``contains`` clauses search the same normalized text.
            return (str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)).strip()

        victim_status, attacker_status = _status(victim), _status(attacker)
        control_status, nocred_status = _status(control), _status(nocred)
        unauth_status = _status(unauth)
        victim_body, attacker_body = _body(victim), _body(attacker)
        control_body, nocred_body = _body(control), _body(nocred)
        unauth_body = _body(unauth)

        # ROUND-3 substantiveness, fail-CLOSED to a LEAD (return None, so the class is NOT falsely marked
        # CLEAN — a broken read is INCONCLUSIVE, not proof of authorization). A contains / not-contains over a
        # non-substantive body is VACUOUS: an absent marker proves nothing when the body is empty / errored /
        # denied. So the fire bodies (victim ground-truth + attacker cross-read) AND the attacker-own negative
        # control MUST each be a substantive success, and the logged-out baseline MUST be a valid gating proof
        # (a substantive 2xx OR a genuine 401/403 denial). Any that is not ⇒ no context, a rigorous LEAD.
        if not is_substantive_success(victim_status, victim_body):
            return None
        if not is_substantive_success(attacker_status, attacker_body):
            return None
        if not is_substantive_success(control_status, control_body):
            return None
        if not _nocred_baseline_valid(nocred_status, nocred_body):
            return None
        # ROUND-4 (HARDENED, round-5): the unauthorized-authenticated baseline is the anti-REFLECTION control,
        # so it must be a SUBSTANTIVE SAME-SHAPE read — a 2xx that actually RENDERED the same object (the same
        # class as the attacker's substantive cross-read). A 401/403 denial is NOT a valid clause-(c) control:
        # a denial that never renders the object cannot exhibit a per-object REFLECTED token, so the token's
        # absence from it is VACUOUS (absent because the object was not rendered, not because the datum is
        # private) and a reflected slug/uuid echoed into the attacker's soft-deny would mint a DURABLE false
        # FACT. Requiring a substantive same-shape 2xx means a reflected per-object token — which any same-shape
        # read of the object echoes — appears in THIS baseline too, so its absent-clause fails and NOTHING mints;
        # only a datum PRESENT in the attacker's read yet ABSENT from a peer's same-shape read of the same object
        # (genuinely access-gated) survives. A denial baseline fails closed to a LEAD (the honest boundary).
        if not is_substantive_success(unauth_status, unauth_body):
            return None

        evidence: dict[str, object] = {
            "attacker_status": attacker_status, "victim_status": victim_status,
            "attacker_own_status": control_status, "nocred_status": nocred_status,
            "unauth_status": unauth_status,
            "victim_body": victim_body, "attacker_body": attacker_body,
            "attacker_own_body": control_body, "nocred_body": nocred_body,
            "unauth_body": unauth_body,
            "victim_ref": self.victim_ref, "discriminator": disc,
        }
        # Every guard is retained in the oracle_context as an EXPLICIT clause (not a bare bool), so offline
        # ``verify`` re-derives substantiveness AND presence-in-victim AND presence-in-attacker-cross-read AND
        # absence-in-substantive-control AND ref-independence AND absence-in-(substantive-or-denied)-logged-out
        # baseline AND absence-in-(substantive-or-denied)-UNAUTHORIZED-AUTHENTICATED baseline (clause (c)) over
        # the retained evidence — the pure achieved-state predicate re-fires exactly, and no false FACT
        # (INCLUDING a durable one built from a non-substantive read OR a reflected per-object token) survives
        # re-verification.
        clauses: list[dict] = [
            {"min_len": [{"var": "discriminator"}, 6]},
            # ROUND-3: the attacker cross-read is a SUBSTANTIVE SUCCESS (real 2xx content, not empty/error/deny)
            *_substantive_success_clauses("attacker_status", "attacker_body"),
            # ROUND-3: the victim ground-truth read is a SUBSTANTIVE SUCCESS (the marker sits in a real record)
            *_substantive_success_clauses("victim_status", "victim_body"),
            # ROUND-3: the attacker-own negative control is a SUBSTANTIVE SUCCESS — only then does its
            # not-contains PROVE the marker victim-specific (a 404/403/empty control proves nothing).
            *_substantive_success_clauses("attacker_own_status", "attacker_own_body"),
            # the discriminator genuinely identifies the victim's AUTHORITATIVE record (operator input is real)
            {"contains": [{"var": "victim_body"}, {"var": "discriminator"}]},
            # the attacker's cross-read REACHED the victim-unique marker (the achieved unauthorized read)
            {"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]},
            # MANDATORY negative control: the marker must NOT appear when the attacker reads their OWN object —
            # this refutes a globally-present string the operator wrongly believed was victim-unique. It is
            # meaningful ONLY because the control read above is proven substantive.
            {"not": {"contains": [{"var": "attacker_own_body"}, {"var": "discriminator"}]}},
            # ROUND-2 (v) ref-independence: the marker is NOT a substring of the requested ref — so a body
            # that merely echoes the requested id (a reflected soft-deny) can never satisfy the read clause.
            {"not": {"contains": [{"var": "victim_ref"}, {"var": "discriminator"}]}},
            # ROUND-2 (iv) + ROUND-3 authorization-gated: the logged-out baseline is a VALID gating proof
            # (a substantive 2xx that lacks the marker OR a genuine 401/403 denial — never a vacuous
            # 5xx/empty/404) AND the marker is ABSENT from it — proving the content is gated, not public.
            _nocred_baseline_valid_clause(),
            {"not": {"contains": [{"var": "nocred_body"}, {"var": "discriminator"}]}},
            # ROUND-4 access-gated by a same-ref UNAUTHORIZED-AUTHENTICATED baseline (clause (c), the DECISIVE
            # anti-reflection differential — HARDENED round-5): the unauth baseline is a SUBSTANTIVE SAME-SHAPE
            # read (a 2xx that RENDERED the same object, the same class as the attacker's substantive cross-read)
            # AND the marker is ABSENT from it. A per-object REFLECTED token echoed into an authenticated soft-deny
            # appears in this SAME-SHAPE baseline too (any same-shape read of the object echoes it), so its
            # absent-clause fails and no false FACT is minted; only a datum genuinely access-gated at the object
            # level — PRESENT in the attacker's read yet ABSENT from a peer's same-shape read of the same object —
            # survives. A 401/403 DENIAL baseline is NOT accepted here (its absent marker is vacuous — the object
            # was never rendered), so it is not a valid clause-(c) control and the class fails closed to a LEAD.
            # Re-derived offline over the RETAINED unauth_status/unauth_body: a durable reflected-token FACT
            # cannot survive re-verification.
            *_substantive_success_clauses("unauth_status", "unauth_body"),
            {"not": {"contains": [{"var": "unauth_body"}, {"var": "discriminator"}]}},
        ]
        return FindingContext.from_predicate(evidence, {"all": clauses}, bug_class=self.bug_class)


@dataclass(frozen=True)
class EvaluationCheck:
    """Server-side template / expression-language injection via EVALUATION.

    Sends a benign control and an arithmetic probe expression (e.g. Jinja2
    ``{{31337*31337}}``), captures both responses, and hands them to the
    evaluation oracle — which confirms SSTI/EL only when the server COMPUTED the
    expression (the result present, the raw template text absent), never on mere
    reflection. ``probe_expr`` and ``expected_result`` are paired per template
    engine; use a distinctive product so the result cannot coincidentally appear."""

    id: str
    bug_class: str
    probe_expr: str
    expected_result: str
    benign: str = "crucible-benign-eval"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        control = send(template.render(point, self.benign))
        probe = send(template.render(point, self.probe_expr))
        control_body = control.get("body", "") if isinstance(control, dict) else str(control)
        probe_body = probe.get("body", "") if isinstance(probe, dict) else str(probe)
        return FindingContext.from_evaluation(
            self.probe_expr, self.expected_result, probe_body,
            control_body=control_body, bug_class=self.bug_class,
        )


@dataclass(frozen=True)
class ErrorSignatureCheck:
    """Error-based injection (SQL/NoSQL/LDAP/XPath) via a provoked backend error.

    Sends a benign control and a syntax-breaking payload (e.g. a lone quote), and
    hands both responses to the error-signature oracle — which confirms only when
    a distinctive datastore/parser error appears in the probe response but NOT in
    the benign control, so a page that always shows a stack trace cannot be
    mistaken for injection."""

    id: str
    bug_class: str
    probe_payload: str = "'\"`)"
    benign: str = "crucible-benign-term"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        control = send(template.render(point, self.benign))
        probe = send(template.render(point, self.probe_payload))
        control_body = control.get("body", "") if isinstance(control, dict) else str(control)
        probe_body = probe.get("body", "") if isinstance(probe, dict) else str(probe)
        return FindingContext.from_error_signature(
            probe_body, control_body=control_body, bug_class=self.bug_class,
        )


@dataclass(frozen=True)
class ContentSignatureCheck:
    """File read / local file inclusion by KNOWN-CONTENT signature.

    Injects a payload (e.g. a traversal ``../../../../etc/passwd``) into the
    insertion point and confirms via the side-effect oracle ONLY when a
    distinctive signature of the *target file's content* (``root:x:0:0:``, a
    ``[extensions]`` INI section, ``<web-app``) appears in the response — proof the
    file was actually READ, not merely that the path was reflected. The signature
    is specific enough that its presence is the proof; a reflected-but-not-read
    payload does not fire (the current marker-reflection path-traversal check only
    proved reflection, which is not a file read)."""

    id: str
    bug_class: str
    payload: str
    signature: str

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        resp = send(template.render(point, self.payload))
        body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
        return FindingContext.from_side_effect(self.signature, body, bug_class=self.bug_class)

    def adapt(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        """WAF-adaptive fallback (opt-in): when a traversal payload is filtered,
        synthesize a form that gets past the filter AND still returns the target
        file's content signature. The sink proxy is the signature's presence — proof
        the file was read, not merely that the path reflected — so the confirmation
        bar is identical to the normal path."""
        from .waf_evasion import adaptive_bypass

        def send_form(form: str) -> dict:
            return send(template.render(point, form))

        def sink_present(resp: dict) -> bool:
            body = resp.get("body", "") if isinstance(resp, dict) else str(resp)
            return self.signature in body

        res = adaptive_bypass(self.payload, send_form, sink_present)
        if res is None:
            return None
        body = res.response.get("body", "") if isinstance(res.response, dict) else str(res.response)
        return FindingContext.from_side_effect(self.signature, body, bug_class=self.bug_class)


@dataclass(frozen=True)
class PathProbeCheck:
    """Framework/CMS exposure via a known-path signature (a request-level check).

    Fetches a fixed path relative to the target (e.g. ``/actuator/env``,
    ``/wp-json``, ``/.git/config``) and confirms exposure ONLY when a distinctive
    signature the framework leaks (``propertySources``, ``DB_PASSWORD``, a WP REST
    JSON) appears in the response — adjudicated by the predicate oracle, not a mere
    2xx. The signature must be specific enough that its presence is proof; a 404 or
    a signature-less response does not fire. Runs once per host."""

    id: str
    bug_class: str
    probe_path: str
    signature: str
    http_method: str = "GET"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        parts = urlsplit(req.url)
        base = f"{parts.scheme}://{parts.netloc}/"
        url = urljoin(base, self.probe_path.lstrip("/"))
        resp = send(req.model_copy(update={"method": self.http_method, "url": url, "body": ""}))
        if not isinstance(resp, dict):
            return None
        status = int(resp.get("status", 0))
        body = str(resp.get("body", ""))
        if status in (0, 404):
            return None  # not present -> nothing to adjudicate
        return FindingContext.from_predicate(
            {"status": status, "body": body},
            {"all": [{"icontains": [{"var": "body"}, self.signature]}]},
            bug_class=self.bug_class,
        )


def _slugify(s: str) -> str:
    return "".join(c for c in s if c.isalnum())


def _host(url: str) -> str:
    """The netloc of a URL, lowercased, or '' if it has none (relative URL)."""
    return urlsplit(url).netloc.lower()


# Scan windows are BOUNDED so a hostile, unterminated body cannot cause quadratic backtracking: a real
# <meta> tag or redirect URL never approaches these limits, but an attacker-controlled response could
# otherwise pack many "<meta " starts with no ">" (each greedy [^>]* rescanning to end → O(n^2)).
_MARKUP_SCAN_CAP = 512_000        # only the head of a response carries navigation markup; cap the parse
# Only two regexes remain: the URL inside a meta-refresh `content` value, and the JS navigation sinks inside
# script text. Everything structural — which bytes are markup at all, where a tag ends, which quote closes an
# attribute, what a raw-text element swallows — is delegated to the stdlib tokenizer below.
_META_REFRESH_VALUE_CAP = 4096    # a real refresh target never approaches this


_HTML_WHITESPACE = " \t\n\x0c\r"     # the HTML Standard's ASCII-whitespace set, not str.isspace()


def _meta_refresh_url(content: str) -> str:
    """The URL a browser would navigate to from a ``<meta http-equiv=refresh>`` ``content`` value, or "".

    This follows the HTML Standard's *shared declarative refresh steps* rather than approximating them —
    twice now an approximation was wrong in BOTH directions at once. Searching the value for any ``url=``
    minted a false FACT on ``content="url=http://evil/"`` (no time component, so a browser refreshes
    NOTHING) and on ``content="0; please wait;url=http://evil/"`` (the URL is the whole remainder after the
    separator, so it is the relative string ``please wait;url=…`` and stays same-origin). Requiring a
    literal ``url=`` simultaneously MISSED ``content="0;http://evil/"`` — the keyword is optional and every
    major browser navigates it — reporting a real open redirect as CLEAN.

    The steps, in order: skip whitespace; require a time (digits, or a leading ``.``); skip the fractional
    part; skip whitespace; consume ONE ``;`` or ``,``; skip whitespace; if the rest starts with ``url``,
    consume it plus an optional ``=`` (each with surrounding whitespace); the URL is then the remainder,
    optionally delimited by a quote. Bounded input, single forward pass, no backtracking."""
    value = (content or "")[:_META_REFRESH_VALUE_CAP]
    i, n = 0, len(value)

    def skip_ws(k: int) -> int:
        while k < n and value[k] in _HTML_WHITESPACE:
            k += 1
        return k

    i = skip_ws(i)
    start = i
    while i < n and value[i].isascii() and value[i].isdigit():
        i += 1
    if i == start and not (i < n and value[i] == "."):
        return ""                       # no time component: the browser refreshes nothing at all
    while i < n and ((value[i].isascii() and value[i].isdigit()) or value[i] == "."):
        i += 1                          # fractional part is parsed and ignored
    if i >= n:
        return ""                       # a bare time reloads the SAME page — not a navigation elsewhere
    if value[i] not in ";," and value[i] not in _HTML_WHITESPACE:
        return ""                       # the code point right after the time MUST be `;`, `,` or ASCII
                                        # whitespace; anything else ends parsing, so `0url=http://evil/`
                                        # and `0http://evil/` navigate NOWHERE (they reload same-origin)
    i = skip_ws(i)
    if i < n and value[i] in ";,":
        i = skip_ws(i + 1)
    if i >= n:
        return ""
    if value[i:i + 3].lower() == "url":
        i = skip_ws(i + 3)              # the keyword is consumed whether or not an `=` follows it
        if i < n and value[i] == "=":
            i = skip_ws(i + 1)
    if i < n and value[i] in "\"'":     # a quote delimits the URL; anything after the match is dropped
        quote, i = value[i], i + 1
        end = value.find(quote, i)
        return value[i:end if end >= 0 else n].strip(_HTML_WHITESPACE)
    # strip only ASCII whitespace: urlsplit (and a browser) KEEP other Unicode spaces such as U+00A0
    return value[i:].strip(_HTML_WHITESPACE)
# JS navigation sinks: location.href/.assign/.replace, window/document.location[.href], with = or (
#
# Sinks are filtered by lexical region (see js_lex): a match only counts when it BEGINS in executable code,
# so a commented-out or quoted sink is excluded structurally rather than by hoping the regex misses it. The
# one ambiguity JavaScript's grammar cannot settle without parsing — `/` as regex-start vs division — is
# resolved AWAY from minting, so an ambiguous span can never produce a FACT.
_JS_REDIRECT = re.compile(
    r"(?<![-\w])(?:(?:window|document|top|parent|self)\.)?location(?:\.href|\.assign|\.replace)?\s*(?:=|\()\s*"
    r"[\"']([^\"']{1,4096})[\"']",
    re.IGNORECASE)
# The property name must match the WHOLE value against an allow-list of genuinely URL-valued properties
# (`fullmatch`). A substring test would fire on `not-og:url`, on a value that merely CONTAINS `og:url`, and
# — worst — on `twitter:image:alt` / `og:image:alt`, which are ALT TEXT, not URLs.
_URL_VALUED_META = re.compile(
    r"og:(?:url|(?:image|audio|video)(?::(?:url|secure_url))?)|twitter:(?:url|image(?::src)?)",
    re.IGNORECASE)


class _MarkupScan(HTMLParser):
    """Tokenize a response body with the STDLIB HTML tokenizer and record only what the app actually EMITS.

    This deliberately replaces a hand-written masker. Deciding "is this URL live markup or inert text?" is a
    tokenizer problem — comments, raw-text and escapable-raw-text elements, attribute quoting (including
    unquoted values), malformed and unterminated tags — and every hand-rolled approximation of it leaked in
    BOTH directions: inert text counted as an emission (a benign page minting a signed FALSE FACT) and live
    markup masked away (a real vulnerability silently DROPPED), plus repeated super-linear blowups on
    attacker-controlled bodies. ``html.parser`` gets those cases right, is linear, and ships with Python.

    Two things are layered on top, because the tokenizer does not model them and both change a verdict:

    * ``<template>`` content is an inert document fragment — it is not rendered and its resources are not
      fetched — but the tokenizer reports its children as ordinary tags, so emissions are suppressed while
      inside one. Depth is tracked on real tokenizer events, so a ``</template>`` appearing inside a script
      string or an attribute value cannot close it.
    * The WHATWG script-data DOUBLE-ESCAPE state: after ``<!--<script`` the next ``</script>`` returns to the
      escaped state instead of closing the element, so the markup after it is still script text. The
      tokenizer closes at the first ``</script>``, so emissions are suppressed until the following one —
      unless a ``-->`` ends the escape first.

    Everything the tokenizer already gets right (comments, ``script``/``style``/``textarea``/``title``/
    ``xmp``/``plaintext``/``noembed``/``noframes``/``iframe`` content, and live ``noscript``/``pre``/``code``
    content) is simply trusted.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.url_attrs: list[str] = []          # href/src/action values of LIVE tags
        self.metas: list[dict[str, str]] = []   # attributes of LIVE <meta> tags
        self.script_text: list[str] = []        # raw text of LIVE <script> elements (JS sink source)
        self._template_depth = 0
        self._in_script = False                 # the tokenizer is inside a <script> element
        self._script_open = False               # a script element is LOGICALLY still open (WHATWG state)
        self._escaped = False                   # script-data-escaped   (entered by `<!--`)
        self._double = False                    # script-data-double-escaped (entered by `<script` there)

    @property
    def _live(self) -> bool:
        # `_script_open` while the tokenizer is NOT in a script element means WHATWG considers us still
        # inside script data — what the tokenizer is now reporting as markup is really script text.
        return self._template_depth == 0 and not (self._script_open and not self._in_script)

    def _record(self, tag: str, attrs: "list[tuple[str, str | None]]") -> None:
        if not self._live:
            return
        # FIRST duplicate wins, as WHATWG specifies ("if there is already an attribute with that name, drop
        # the new one"). A plain dict comprehension keeps the LAST, which both mints a false FACT (a benign
        # first href with a hostile second) and drops a real one (hostile first, benign second).
        d: dict[str, str] = {}
        for key, value in attrs:
            d.setdefault(key.lower(), value or "")
        if tag == "meta":
            self.metas.append(d)
        for key in ("href", "src", "action"):
            if d.get(key):
                self.url_attrs.append(d[key])

    @property
    def _in_script_data(self) -> bool:
        """WHATWG still considers us inside script TEXT even though the tokenizer thinks it left the
        element. Tags it reports here are not tags at all, so they must not move any state."""
        return self._script_open and not self._in_script

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001
        if tag == "template":
            self._template_depth += 1
            return
        if tag == "script":
            # A `<script>` seen while a script element is still logically OPEN (the tokenizer closed it at a
            # `</script>` that WHATWG treats as double-escape-exit) re-enters the double-escaped state.
            if self._script_open:
                self._double = True
            else:
                self._script_open, self._double, self._escaped = True, False, False
            self._in_script = True
        self._record(tag, attrs)

    def handle_startendtag(self, tag: str, attrs) -> None:  # noqa: ANN001
        if self._in_script_data:
            return
        # The solidus is IGNORED on a non-void element, so `<template/>` OPENS a template: its content is an
        # inert fragment until the matching end tag. Treating it as open-and-closed left that content live.
        if tag == "template":
            self._template_depth += 1
            return
        self._record(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if self._in_script_data and tag != "script":
            return                          # a `</template>` inside script text closes nothing
        if tag == "template":
            self._template_depth = max(0, self._template_depth - 1)
            return
        if tag == "script":
            self._in_script = False
            if self._double:
                self._double = False        # double-escaped: this end tag returns to escaped, not a close
            else:
                # A real close ends the element AND its escape state: `_escaped` leaking into the next
                # script element made a later `<script ` look like a double-escape entry and suppressed a
                # live sink after it (a real vulnerability reported CLEAN).
                self._script_open, self._escaped = False, False

    def handle_data(self, data: str) -> None:
        # The escape state must also advance while the tokenizer is OUTSIDE the element but WHATWG still
        # considers us in script data: that text is script text, so a `-->` in it really does end the
        # escape. Ignoring it left `_escaped` stale, and a later `<script ` then looked like a fresh
        # double-escape entry and suppressed a live page (a real vulnerability reported CLEAN).
        if not (self._in_script or self._in_script_data):
            return
        if self._live and self._in_script:
            self.script_text.append(data)
        self._escaped, self._double = _script_data_state(data, self._escaped, self._double)


def _script_data_state(text: str, escaped: bool, double: bool) -> tuple[bool, bool]:
    """Advance the WHATWG script-data escape state across one chunk of script text.

    Models the actual state machine rather than guessing from substrings, because both guesses were wrong:
    a bare ``rfind("<!--<script")`` missed a NON-ADJACENT entry (``<!-- x <script>``, which really does
    double-escape) and fired on ``<!--<script<`` / ``<!--<scripting`` (which really do NOT, because
    ``<script`` must be followed by whitespace, ``/`` or ``>``) — minting a false FACT in the first case and
    certifying a genuinely vulnerable page CLEAN in the second. ``find``-based, so it stays linear."""
    i, n = 0, len(text)
    while i < n:
        if not escaped:
            start = text.find("<!--", i)
            if start < 0:
                break
            escaped, i = True, start + 4
            continue
        close = text.find("-->", i)
        entry = -1
        if not double:
            k = i
            while True:
                k = text.find("<script", k)
                if k < 0:
                    break
                after = k + 7
                if after >= n or text[after].isspace() or text[after] in "/>":
                    entry = k
                    break
                k += 7
        if close >= 0 and (entry < 0 or close < entry):
            escaped, double, i = False, False, close + 3      # `-->` leaves both escaped states
        elif entry >= 0:
            double, i = True, entry + 7                       # `<script` + terminator enters double-escape
        else:
            break
    return escaped, double


def _scan_markup(body: str) -> _MarkupScan:
    """Tokenize (a capped prefix of) ``body``. Malformed input never raises: whatever was tokenized before
    the error is what a browser would have parsed up to that point, and is what we judge."""
    text = (body or "")[:_MARKUP_SCAN_CAP]
    scan = _MarkupScan()
    if ">" not in text:
        return scan          # no complete tag can exist, so nothing is emitted — skip the tokenizer
    try:
        scan.feed(text)
        scan.close()
    except Exception:                             # noqa: BLE001 — keep what parsed; never fail the probe
        pass
    return scan


def _meta_refresh_hosts(scan: _MarkupScan) -> list[str]:
    """Hosts a declarative ``<meta http-equiv=refresh>`` would navigate to."""
    hosts: list[str] = []
    for meta in scan.metas:
        if (meta.get("http-equiv") or "").strip().lower() == "refresh":
            target = _meta_refresh_url(meta.get("content") or "")
            if target:
                hosts.append(_host(target))
    return [h for h in hosts if h]


def _js_sink_hosts(scan: _MarkupScan) -> list[str]:
    """Hosts a JS location sink would navigate to — counting ONLY sinks that begin in executable code."""
    hosts: list[str] = []
    for text in scan.script_text:
        for match in _JS_REDIRECT.finditer(text):
            # A sink inside a comment, a string, a template literal, or an ambiguous `/`-span never runs (or
            # cannot be shown to run without parsing); counting it was the false-FACT surface that kept this
            # branch quarantined LEAD-only.
            if _js_lex.sink_is_executable(text, match.start()):
                hosts.append(_host(match.group(1).strip()))
    return [h for h in hosts if h]


def _redirect_hosts(scan: _MarkupScan) -> list[str]:
    """Every host parsed markup would navigate to. Kept as the union for the predicate, while the two
    sources stay separately available: they are DIFFERENT evidence branches with different capabilities
    (a declarative refresh is statically decidable; a JS sink is only lexically decidable), so a verdict
    must be attributable to one of them rather than to their merger."""
    return _meta_refresh_hosts(scan) + _js_sink_hosts(scan)


def meta_refresh_hosts(body: str) -> list[str]:
    """Public: declarative-refresh navigation targets in ``body`` (branch ``*.body_markup``)."""
    return _meta_refresh_hosts(_scan_markup(body))


def js_sink_hosts(body: str) -> list[str]:
    """Public: executable JS-sink navigation targets in ``body`` (branch ``open_redirect.js_sink``)."""
    return _js_sink_hosts(_scan_markup(body))


def _markup_redirect_hosts(body: str) -> list[str]:
    """The hosts a browser would actually NAVIGATE to from the response markup — the target of a
    meta-refresh or a JS location sink. Returns lowercased netlocs; a relative / same-origin target
    contributes nothing. This is the co-location test that makes open-redirect confirmation sound: the
    canary host must be an ACTUAL navigation target, not merely a substring reflected somewhere in the body
    next to an unrelated ``<meta http-equiv=Content-Type>``.

    HONEST RESIDUAL: the extracted host list is a DERIVED observation stored in ``observed_evidence``
    alongside the raw ``body``, so re-verification re-fires the predicate over the derived list rather than
    re-parsing the body. The certificate signature makes the stored evidence tamper-evident, but the
    veracity firewall cannot demote a MINT-TIME derivation bug here — which is why this path is pinned by
    explicit true-positive AND negative-control tests plus a differential test against the stdlib tokenizer.
    This is the same property every shipped predicate has (e.g. ``location_host = _host(location)``)."""
    return _redirect_hosts(_scan_markup(body))


def _emitted_url_hosts(body: str) -> list[str]:
    """The hosts that appear as the AUTHORITY of a URL the app EMITS — an href/src/action attribute value, a
    URL-valued canonical/social meta (og:url, …), or a meta-refresh / JS-location redirect target. These are
    URLs a VICTIM's browser or a cache/crawler actually uses, which is what makes a reflected ``Host``
    exploitable (cache poisoning, poisoned reset link, canonical hijack).

    Crucially this is EMISSION, not mere presence: a URL that only appears as inert text — a 404 message
    echoing the reconstructed ``http://<Host>/path`` back to the requester, a ``<pre>`` sample, an HTML
    comment, a JSON error string — is NOT counted. Such an echo is shown only to the requester (who set
    their own Host) and is not exploitable. Authorities come from stdlib ``urlsplit`` (via ``_host``), so a
    relative URL whose QUERY contains ``//evil`` is correctly NOT an emission of ``evil``."""
    scan = _scan_markup(body)
    hosts = _redirect_hosts(scan)
    for value in scan.url_attrs:
        host = _host(value.strip())
        if host:
            hosts.append(host)
    for meta in scan.metas:
        prop = (meta.get("property") or meta.get("name") or "").strip()
        if _URL_VALUED_META.fullmatch(prop):
            host = _host((meta.get("content") or "").strip())
            if host:
                hosts.append(host)
    return [h for h in hosts if h]


# ---------------------------------------------------------------------------
# A seed library covering oracle-observable classes the verify layer confirms.
# Each check reuses an EXISTING oracle (differential / side_effect), so adding a
# class is a payload+shape declaration, not new confirmation machinery.
# ---------------------------------------------------------------------------

BOOLEAN_SQLI = DifferentialCheck(
    id="boolean-sqli", bug_class="boolean_sqli",
    benign="crucible-benign-term",
    probe_payload="x' OR '1'='1",
)

REFLECTED_XSS = MarkerReflectionCheck(
    id="reflected-xss", bug_class="xss",
    payload_template="\"'><x{marker}>",
)

# SSTI / path-traversal / error-based used to be MarkerReflectionCheck probes that
# confirmed on bare canary REFLECTION — but reflecting a canary only proves input
# is echoed (an XSS signal, already covered by REFLECTED_XSS), NOT that a template
# was evaluated, a file was read, or a datastore errored. On any endpoint that
# reflects input verbatim (a search box, an echo, an error page) all three fired as
# FALSE POSITIVES — the benchmark app only dodged this by reflecting solely
# markup-shaped input. These now use the evidence-carrying oracles: SSTI confirms
# only when the server COMPUTED the arithmetic (result present, raw absent),
# path-traversal only when the target file's CONTENT appears, error-based only when
# a datastore error appears in the probe but not the benign control. Prove, don't
# guess — a reflecting endpoint no longer trips any of the three.
SSTI_EVAL_BRACES = EvaluationCheck(
    id="ssti-eval-braces", bug_class="ssti",
    probe_expr="{{7331*7331}}", expected_result="53743561",
)

SSTI_EVAL_DOLLAR = EvaluationCheck(
    id="ssti-eval-dollar", bug_class="ssti",
    probe_expr="${7331*7331}", expected_result="53743561",
)

PATH_TRAVERSAL = ContentSignatureCheck(
    id="path-traversal", bug_class="path_traversal",
    payload="../../../../etc/passwd", signature="root:x:0:0:",
)

ERROR_BASED = ErrorSignatureCheck(
    id="error-based-injection", bug_class="error_based_sqli",
)


# --- out-of-band (blind) checks: confirmed by a callback, not a response ----

SSRF_OOB = OOBCheck(
    id="ssrf-oob", bug_class="ssrf",
    # a bare callback URL: a server-side fetch of it is the interaction
    payload_template="{callback}",
)

XXE_OOB = OOBCheck(
    id="xxe-oob", bug_class="blind_xxe",
    # external general entity that dereferences the callback on parse
    payload_template=(
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE r [<!ENTITY x SYSTEM \"{callback}\">]><r>&x;</r>"
    ),
)

RCE_OOB = OOBCheck(
    id="rce-oob", bug_class="command_injection",
    # a command-injection break-out that curls the callback (blind OS cmdi)
    payload_template=";curl {callback};",
)

DESERIALIZATION_OOB = OOBCheck(
    id="deserialization-oob", bug_class="deserialization",
    # JNDI/log4shell-style lookup: dereferenced during unsafe deserialization
    payload_template="${{jndi:ldap://{callback}}}",
)


# --- DNS out-of-band (blind) checks: confirmed by the DNS lookup the target's resolver forwards, even
#     when outbound HTTP is blocked. Each payload triggers a resolution of <token>.<base-domain>.
DNS_SSRF_OOB = DNSOOBCheck(
    id="ssrf-dns-oob", bug_class="ssrf",
    # a server-side fetch resolves the callback host before any (blocked) HTTP connect
    payload_template="http://{callback}/",
)

DNS_XXE_OOB = DNSOOBCheck(
    id="xxe-dns-oob", bug_class="blind_xxe",
    # external general entity: the parser resolves the SYSTEM host on parse
    payload_template=(
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE r [<!ENTITY x SYSTEM \"http://{callback}/x\">]><r>&x;</r>"
    ),
)

DNS_RCE_OOB = DNSOOBCheck(
    id="rce-dns-oob", bug_class="command_injection",
    # a command-injection break-out that forces a DNS lookup (no HTTP needed)
    payload_template=";nslookup {callback};",
)


# Open redirect: an evidence-carrying point check (fires only on a real redirect
# to the canary host), safe to run everywhere — the targeting selector still
# prioritises redirect-ish params.
OPEN_REDIRECT = OpenRedirectCheck()

DEFAULT_CHECKS: tuple[Check, ...] = (
    BOOLEAN_SQLI,
    REFLECTED_XSS,
    SSTI_EVAL_BRACES,
    SSTI_EVAL_DOLLAR,
    PATH_TRAVERSAL,
    ERROR_BASED,
    OPEN_REDIRECT,
    SSRF_OOB,
    XXE_OOB,
    RCE_OOB,
    DESERIALIZATION_OOB,
)
"""A ready-to-run seed set. Every check maps to a bug_class the verifier already
routes to an oracle, so it confirms end-to-end. The OOB checks (`wants_oob`) run
only when the engine has an OOBReceiver — without one they are skipped, never
guessed. Extend by declaring more DifferentialCheck / MarkerReflectionCheck /
OOBCheck entries — no new oracle needed."""
