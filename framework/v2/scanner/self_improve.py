"""
scanner.self_improve — gap mining + gated capability PROPOSALS.

The scanner is honest about what it confirms (every finding is oracle-anchored).
This module makes it honest about what it *cannot* confirm yet: it mines the
places the scanner is structurally or empirically weak and DRAFTS reviewable
proposals to close them. It proposes; it never self-applies.

Three signals feed :func:`analyze_gaps`, each a real, computable shortfall:

  * **missing check** — a ``bug_class`` the verify layer already routes to an
    oracle (:data:`~framework.v2.verify.BUG_CLASS_ORACLES`) but which *no*
    check in the active library produces. The confirmation machinery exists;
    the producer does not. This is a structural coverage hole.
  * **low recall** — a class that *has* a producing check but which the
    ground-truth :class:`~framework.v2.scanner.benchmark.BenchmarkReport`
    shows the scanner missing (recall below a floor). Empirical weakness.
  * **low confirm-rate** — a class whose findings, once resolved in an
    :class:`~framework.v2.calibration.OutcomeLedger`, turned out mostly *not*
    exploitable (a precision/calibration problem). Empirical noise.

:func:`draft_proposals` turns each gap into a :class:`CapabilityProposal` — a
structured spec a human or a downstream agent implements. The suggested
``oracle_kind`` is taken from the verifier's own routing table, so a proposal
never suggests an oracle the system cannot actually run for that class.

:class:`MergeGate` mirrors ``improve/merge_gate.py``'s never-self-applied
governance control (in miniature, stdlib-only): a proposal is APPROVED only
when the candidate eval is green AND enough independent approvals are present.
Everything else is REJECTED with the reason. The gate authorises; it does not
apply. There is deliberately **no** function in this module that writes check
code or mutates the framework — see :data:`SELF_APPLY`.

Deterministic and pure: no wallclock, no randomness, no I/O. Given the same
ledger/benchmark/check-set, the gaps and proposals are byte-stable.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Callable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..verify import BUG_CLASS_ORACLES, OracleKind, normalize_bug_class
from .checks import DEFAULT_CHECKS, Check

if TYPE_CHECKING:  # import-cost-free type refs; runtime uses duck-typed access
    from ..calibration.ledger import OutcomeLedger
    from .benchmark import BenchmarkReport


# This module PROPOSES. It never applies. The absence of any writer is a
# governance property, asserted by the test suite. Do not add an apply().
SELF_APPLY: bool = False

# Empirical-signal floors. A class only becomes a gap when it falls under one.
DEFAULT_MIN_RECALL = 0.5
DEFAULT_MIN_CONFIRM_RATE = 0.5
DEFAULT_MIN_LEDGER_SAMPLES = 3


# ---------------------------------------------------------------------------
# Gaps
# ---------------------------------------------------------------------------


class GapSource(str, enum.Enum):
    """Which signal surfaced the gap — each is a genuinely computed shortfall,
    not a guess."""

    MISSING_CHECK = "missing_check"        # routed class, no producing check
    LOW_RECALL = "low_recall"              # producing check, benchmark misses it
    LOW_CONFIRM_RATE = "low_confirm_rate"  # findings mostly resolve non-exploitable


class CapabilityGap(BaseModel):
    """One place the scanner is weak, with the evidence that says so.

    A gap names a ``bug_class`` and the ``oracle_kinds`` the verify layer would
    use to confirm it (copied from the routing table, so a downstream proposal
    cannot invent an oracle the system does not run). ``metric`` carries the
    number that triggered the gap (a recall or a confirm-rate) for the empirical
    sources; it is ``None`` for a structural missing-check gap."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    source: GapSource
    bug_class: str = Field(min_length=1)
    oracle_kinds: list[OracleKind] = Field(
        min_length=1,
        description="Oracle kinds the verify layer routes this class to.",
    )
    priority: int = Field(ge=0, le=100, description="Higher = more valuable to close.")
    title: str = Field(min_length=1)
    description: str = Field(default="")
    metric: float | None = Field(
        default=None,
        description="The recall / confirm-rate that triggered the gap; None for "
        "a structural (missing-check) gap.",
    )
    evidence: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------


class CapabilityProposal(BaseModel):
    """A STRUCTURED, REVIEWABLE SPEC for a new capability — NOT executable code.

    This is the honest boundary of the self-improvement loop: it drafts *what a
    new check should do* (which bug class, which oracle confirms it, where to
    place the payload, a payload-family skeleton, and why) so a human or a
    downstream agent can implement and review it. It does **not** contain a
    working check, it is never imported as one, and applying it is a separate,
    human-gated step (see :class:`MergeGate`). ``executable`` is always False
    and the skeleton is a template with placeholders, never a live payload."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    gap_id: str = Field(min_length=1)
    bug_class: str = Field(min_length=1)
    oracle_kind: OracleKind = Field(
        description="The primary oracle the verify layer already routes this "
        "class to — the confirmation authority the implemented check must feed."
    )
    insertion_point_strategy: str = Field(
        min_length=1,
        description="Where/how the check should place its probe (query value, "
        "header, cross-identity object ref, OOB URL, crash input, ...).",
    )
    payload_family: str = Field(
        min_length=1, description="The family of probe values the check should carry."
    )
    payload_template_skeleton: str = Field(
        min_length=1,
        description="A NON-EXECUTABLE template sketch with {marker}/{callback} "
        "placeholders — a starting point for the implementer, not a live payload.",
    )
    rationale: str = Field(min_length=1)
    status: str = Field(default="draft", pattern=r"^draft$", description="Always 'draft'.")
    executable: bool = Field(
        default=False,
        description="Always False: a proposal is a spec, never runnable check code.",
    )


# ---------------------------------------------------------------------------
# Merge gate — the governance control (authorises, never applies)
# ---------------------------------------------------------------------------


class Verdict(str, enum.Enum):
    APPROVED = "approved"
    REJECTED = "rejected"


class Decision(BaseModel):
    """The gate's verdict on one proposal. ``approved`` is True only when the
    eval was green AND approvals met the threshold. Authorisation only — the
    gate never touches the working tree."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(min_length=1)
    approved: bool
    eval_green: bool
    approvals: int = Field(ge=0)
    threshold: int = Field(ge=1)
    reason: str = Field(min_length=1)

    @property
    def verdict(self) -> Verdict:
        return Verdict.APPROVED if self.approved else Verdict.REJECTED


class MergeGate:
    """Authorise (never apply) a capability proposal.

    Mirrors ``improve/merge_gate.py``'s discipline: a self-improving offensive
    tool that could silently rewrite its own checks is exactly what must not
    ship, so deployment is held behind an eval-green + threshold-approval gate.
    This is the stdlib-only miniature of that control; the production SIL gate
    additionally requires the Pillar-2 capability and threshold *signatures*."""

    def evaluate(
        self,
        proposal: CapabilityProposal,
        *,
        eval_green: bool,
        approvals: int,
        threshold: int,
    ) -> Decision:
        """APPROVE iff ``eval_green and approvals >= threshold``; else REJECT
        with the reason(s). ``threshold`` must be >= 1 — a zero threshold would
        be a governance hole (auto-approve on green)."""
        if threshold < 1:
            raise ValueError(f"threshold must be >= 1 (governance floor), got {threshold}")
        if approvals < 0:
            raise ValueError(f"approvals must be >= 0, got {approvals}")

        reasons: list[str] = []
        if not eval_green:
            reasons.append("eval red: candidate regression gate did not pass")
        if approvals < threshold:
            reasons.append(f"insufficient approvals: {approvals}/{threshold}")

        approved = eval_green and approvals >= threshold
        if approved:
            reason = (
                f"authorised: {approvals}/{threshold} approvals, eval green — "
                f"apply by hand or via a gated deploy step (the gate does not apply)"
            )
        else:
            reason = "; ".join(reasons)
        return Decision(
            proposal_id=proposal.id,
            approved=approved,
            eval_green=eval_green,
            approvals=approvals,
            threshold=threshold,
            reason=reason,
        )


# ---------------------------------------------------------------------------
# Gap mining
# ---------------------------------------------------------------------------


def _oracles_for(bug_class: str) -> tuple[OracleKind, ...]:
    """The oracle kinds the verify layer routes ``bug_class`` to (canonicalised),
    or ``()`` if the class is not routed (and thus not confirmable end-to-end)."""
    return BUG_CLASS_ORACLES.get(normalize_bug_class(bug_class), ())


def _priority_missing(bug_class: str) -> int:
    return 60


def _priority_low_recall(recall: float) -> int:
    return min(100, 70 + int((1.0 - recall) * 25))


def _priority_low_confirm(rate: float) -> int:
    return min(100, 55 + int((1.0 - rate) * 25))


def analyze_gaps(
    *,
    ledger: "OutcomeLedger | None" = None,
    benchmark_report: "BenchmarkReport | None" = None,
    checks: tuple[Check, ...] = DEFAULT_CHECKS,
    ledger_bug_classes: Mapping[str, str] | None = None,
    min_recall: float = DEFAULT_MIN_RECALL,
    min_confirm_rate: float = DEFAULT_MIN_CONFIRM_RATE,
    min_ledger_samples: int = DEFAULT_MIN_LEDGER_SAMPLES,
) -> list[CapabilityGap]:
    """Mine underperforming areas of the scanner into a deterministic list of
    :class:`CapabilityGap`.

    Sources (each real and non-overlapping):

      * every routed ``bug_class`` in :data:`~framework.v2.verify.BUG_CLASS_ORACLES`
        that no check in ``checks`` produces -> a ``MISSING_CHECK`` gap;
      * every class with a producing check whose ``benchmark_report`` recall is
        below ``min_recall`` -> a ``LOW_RECALL`` gap (skipped when the class is
        already a missing-check gap — the structural hole is the root cause);
      * every class in the ``ledger`` whose resolved findings were exploitable
        less than ``min_confirm_rate`` of the time (>= ``min_ledger_samples``
        resolved) -> a ``LOW_CONFIRM_RATE`` gap.

    ``ledger_bug_classes`` maps a ledger ``finding_id`` to its ``bug_class`` —
    required for the ledger path because a :class:`Prediction` does not itself
    carry a bug class. Without it the ledger is not mined (we do not invent the
    class). Gaps are returned sorted by descending priority then bug_class."""
    produced = {normalize_bug_class(c.bug_class) for c in checks}
    gaps: list[CapabilityGap] = []

    # 1. Structural coverage holes: the oracle exists, the producer does not.
    for bug_class in sorted(BUG_CLASS_ORACLES):
        if bug_class in produced:
            continue
        oks = _oracles_for(bug_class)
        gaps.append(
            CapabilityGap(
                id=f"gap-{GapSource.MISSING_CHECK.value}-{bug_class}",
                source=GapSource.MISSING_CHECK,
                bug_class=bug_class,
                oracle_kinds=list(oks),
                priority=_priority_missing(bug_class),
                title=f"No check produces confirmable class {bug_class!r}",
                description=(
                    f"The verify layer routes {bug_class!r} to "
                    f"{[o.value for o in oks]}, but no check in the active library "
                    f"emits it — the confirmation path is unreachable."
                ),
                metric=None,
                evidence=[f"routed_oracles={[o.value for o in oks]}", "producing_checks=0"],
            )
        )

    # 2. Empirical recall holes: a produced class the benchmark still misses.
    if benchmark_report is not None:
        for raw_bc, score in sorted(benchmark_report.per_class.items()):
            bug_class = normalize_bug_class(raw_bc)
            if bug_class not in produced:
                continue  # already a MISSING_CHECK gap; do not double-count
            expected = score.true_positives + score.false_negatives
            if expected <= 0:
                continue  # nothing planted for this class -> recall is undefined
            recall = score.recall
            if recall >= min_recall:
                continue
            oks = _oracles_for(bug_class)
            if not oks:
                continue
            gaps.append(
                CapabilityGap(
                    id=f"gap-{GapSource.LOW_RECALL.value}-{bug_class}",
                    source=GapSource.LOW_RECALL,
                    bug_class=bug_class,
                    oracle_kinds=list(oks),
                    priority=_priority_low_recall(recall),
                    title=f"Low benchmark recall on {bug_class!r}: {recall:.0%}",
                    description=(
                        f"A check for {bug_class!r} exists but confirmed "
                        f"{score.true_positives}/{expected} planted case(s) — the "
                        f"probe or its payload family is not triggering the signal."
                    ),
                    metric=recall,
                    evidence=[
                        f"true_positives={score.true_positives}",
                        f"false_negatives={score.false_negatives}",
                        f"recall={recall:.4f}",
                        f"min_recall={min_recall}",
                    ],
                )
            )

    # 3. Empirical precision/calibration holes: findings that resolve non-exploitable.
    if ledger is not None and ledger_bug_classes:
        stats = _ledger_confirm_stats(ledger, ledger_bug_classes)
        for bug_class in sorted(stats):
            confirmed, total = stats[bug_class]
            if total < min_ledger_samples:
                continue
            oks = _oracles_for(bug_class)
            if not oks:
                continue  # not routed -> no confirmation path to reason about
            rate = confirmed / total
            if rate >= min_confirm_rate:
                continue
            gaps.append(
                CapabilityGap(
                    id=f"gap-{GapSource.LOW_CONFIRM_RATE.value}-{bug_class}",
                    source=GapSource.LOW_CONFIRM_RATE,
                    bug_class=bug_class,
                    oracle_kinds=list(oks),
                    priority=_priority_low_confirm(rate),
                    title=f"Low confirm-rate on {bug_class!r}: {rate:.0%}",
                    description=(
                        f"Of {total} resolved {bug_class!r} finding(s), only "
                        f"{confirmed} were exploitable — the class is producing "
                        f"noise; its check/discriminator needs to be tightened."
                    ),
                    metric=rate,
                    evidence=[
                        f"exploitable={confirmed}",
                        f"resolved={total}",
                        f"confirm_rate={rate:.4f}",
                        f"min_confirm_rate={min_confirm_rate}",
                    ],
                )
            )

    gaps.sort(key=lambda g: (-g.priority, g.bug_class, g.source.value))
    return gaps


def _ledger_confirm_stats(
    ledger: "OutcomeLedger", bug_class_of: Mapping[str, str]
) -> dict[str, tuple[int, int]]:
    """Per-class (exploitable_count, resolved_count) over the ledger's resolved
    pairs. DISPUTED outcomes (target None) are excluded — never guessed. Classes
    are canonicalised so aliases fold together."""
    stats: dict[str, list[int]] = {}
    for prediction, outcome in ledger.pairs():
        raw = bug_class_of.get(prediction.finding_id)
        if raw is None:
            continue
        target = outcome.target  # 1.0 exploitable/remediated, 0.0 FP, None disputed
        if target is None:
            continue
        bug_class = normalize_bug_class(raw)
        bucket = stats.setdefault(bug_class, [0, 0])
        bucket[1] += 1
        if target >= 1.0:
            bucket[0] += 1
    return {k: (v[0], v[1]) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# Proposal drafting
# ---------------------------------------------------------------------------

# Insertion-point strategy per oracle kind: how a check that feeds THIS oracle
# must place its probe. Mirrors how the existing check library is built.
_STRATEGY_BY_ORACLE: dict[OracleKind, str] = {
    OracleKind.DIFFERENTIAL_RESPONSE: (
        "place a paired benign value and a probe value into the same insertion "
        "point; feed both responses to the differential oracle and let it judge "
        "divergence (status/length/lexical/latency)"
    ),
    OracleKind.ACHIEVED_STATE: (
        "issue the request as an attacker identity against another tenant's "
        "object/function reference; assert the achieved-state oracle sees the "
        "victim-owned fields the request should have been denied"
    ),
    OracleKind.SIDE_EFFECT: (
        "plant a unique canary marker (derived from the insertion-point id) into "
        "the point; confirm via the side-effect oracle iff the raw marker reaches "
        "the rendered sink"
    ),
    OracleKind.OOB_CALLBACK: (
        "embed a per-finding unique out-of-band callback URL/token; poll the OOB "
        "receiver and confirm on an inbound interaction (blind execution)"
    ),
    OracleKind.SANITIZER_SIGNAL: (
        "supply a crash/UB-inducing input and capture the target process's "
        "stdout/stderr; confirm on an ASAN/UBSAN/panic/abort marker"
    ),
}

# Payload-family skeletons per canonical bug_class. These are NON-EXECUTABLE
# sketches (placeholders {marker}/{callback}) — a starting point for the human
# who implements the check, deliberately not a live weaponised payload.
_SKELETON_BY_CLASS: dict[str, tuple[str, str]] = {
    "boolean_sqli": ("boolean-blind tautology differential", "benign vs \"x' OR '1'='1\""),
    "time_based_sqli": ("time-blind delay differential", "\"'; WAITFOR DELAY '0:0:{n}'--\" vs benign; paired latency samples -> timing oracle"),
    "time_based": ("statistical time-blind", "benign vs delay-injecting payload; k paired latency samples -> Mann-Whitney timing oracle"),
    "time_based_command_injection": ("time-blind OS command", ";sleep {n}; vs benign; paired latency samples -> timing oracle (+ OOB)"),
    "error_based_sqli": ("syntax-breaking error probe", "{marker}'\\\"\\\\ (look for the marker/DB error in the sink)"),
    "sqli": ("generic SQLi (differential + OOB)", "benign vs \"x' OR '1'='1\"; OOB variant \"';SELECT ...{callback}...\""),
    "nosqli": ("operator-injection differential", "benign vs {\"$ne\": null} / \"[$gt]=\" style operator payload"),
    "idor": ("cross-tenant object reference", "swap ref param to the victim's id; expected_state={'owner': '<victim>'}"),
    "bola": ("cross-tenant object reference", "swap ref param to the victim's id; expected_state={'owner': '<victim>'}"),
    "bfla": ("cross-role function access", "invoke a privileged function as a low-role identity; expect the privileged result"),
    "broken_access_control": ("forced-browse / missing authz", "request the protected resource without/with a lower role; expect it served"),
    "authorization": ("horizontal/vertical authz bypass", "replay a privileged action across identities; expect the achieved state"),
    "auth_bypass": ("authentication bypass", "omit/forge the auth token; expect an authenticated-only response (achieved_state or differential)"),
    "mass_assignment": ("over-posting a protected field", "add {'role': 'admin'} (or similar) to the body; expect it reflected in state"),
    "privilege_escalation": ("role elevation", "mutate a role/permission field; expect the elevated state to persist"),
    "open_redirect": ("off-site redirect target", "set the redirect param to //evil.example/{marker}; expect Location to honour it"),
    "cors": ("reflected cross-origin trust", "send Origin: https://evil.example; expect ACAO to reflect it with credentials"),
    "host_header_injection": ("host override", "set Host: evil.example; expect it reflected into an absolute URL/link"),
    "jwt": ("token forgery", "alg:none / signature-strip / kid-injection; expect an authenticated-only state"),
    "graphql_introspection": ("introspection exposure", "POST the __schema introspection query; expect the type system returned"),
    "graphql_suggestions": ("field-suggestion leak", "send a near-miss field name; expect a 'Did you mean' suggestion"),
    "request_smuggling": ("CL.TE / TE.CL desync", "conflicting Content-Length/Transfer-Encoding; differential on the smuggled response"),
    "dom_xss": ("client-side sink canary", "source-controlled value {marker} into a DOM sink; confirm the raw marker in rendered DOM"),
    "cross_site_websocket_hijacking": ("cross-origin WS handshake", "open the WS from a foreign Origin; expect the authenticated stream"),
    "websocket_injection": ("WS frame injection canary", "inject {marker} in a WS frame; confirm reflection or a differential"),
    "request_race": ("concurrency race window", "fire N concurrent identical requests; expect a limit-once invariant to break"),
    "ssrf": ("server-side fetch callback", "{callback} as a URL/host param; confirm on the inbound OOB interaction"),
    "xxe": ("external-entity callback", "<!DOCTYPE r [<!ENTITY x SYSTEM \"{callback}\">]><r>&x;</r>"),
    "blind_xxe": ("blind external-entity callback", "parameter-entity OOB DTD dereferencing {callback}"),
    "deserialization": ("gadget-triggered lookup", "${{jndi:ldap://{callback}}} / language-native gadget that dereferences {callback}"),
    "rce": ("command execution callback", "break-out that curls {callback}; also scan process output for a canary"),
    "command_injection": ("OS command break-out", ";curl {callback}; (blind) or ;echo {marker}; (reflected)"),
    "ssti": ("template-evaluation canary", "{{7*7}} / {marker}; confirm the evaluated/reflected marker in output"),
    "xss": ("reflected markup canary", "\"'><x{marker}> ; confirm the raw canary reaches the HTML sink"),
    "path_traversal": ("traversal read canary", "../../{marker} (or ../../etc/passwd); confirm the read content in the sink"),
    "lfi": ("local-file inclusion canary", "path=../../{marker}; confirm the included file's content in the response"),
    "memory_corruption": ("oversized/malformed input", "boundary/oversized input; confirm on a sanitizer marker in process output"),
    "buffer_overflow": ("boundary-overrun input", "input past the buffer bound; confirm on an ASAN buffer-overflow marker"),
    "use_after_free": ("free-then-use trigger", "input that frees then references; confirm on an ASAN use-after-free marker"),
    "crash": ("crash-inducing input", "malformed input; confirm on a signal/abort/panic marker in process output"),
}


def _skeleton_for(bug_class: str, oracle_kind: OracleKind) -> tuple[str, str]:
    """(payload_family, skeleton) for a class. Falls back to an oracle-generic
    sketch so an unroutinely-named-but-routed class still yields a usable spec."""
    entry = _SKELETON_BY_CLASS.get(bug_class)
    if entry is not None:
        return entry
    generic = {
        OracleKind.DIFFERENTIAL_RESPONSE: ("paired benign/probe differential", "benign vs {probe}; compare responses"),
        OracleKind.ACHIEVED_STATE: ("cross-identity state probe", "act across identities; expected_state={...}"),
        OracleKind.SIDE_EFFECT: ("unique canary marker", "{marker}; confirm it reaches the sink"),
        OracleKind.OOB_CALLBACK: ("out-of-band callback", "{callback}; confirm on inbound interaction"),
        OracleKind.SANITIZER_SIGNAL: ("crash-inducing input", "malformed input; scan process output"),
        OracleKind.TIMING: ("statistical time-blind", "benign vs delay-injecting payload; k paired latency samples -> timing oracle"),
        OracleKind.BOOLEAN_INFERENCE: ("SPRT true/false differential", "repeat true vs false clause + a false control; SPRT to a bounded-error decision"),
        OracleKind.REFLECTION_CONTEXT: ("context-aware markup canary", "\"'><x{marker}>; confirm the marker reaches an EXECUTABLE (tag/script/handler) context"),
        OracleKind.EVALUATION: ("template-arithmetic probe", "inject {{31337*31337}}; confirm the server EVALUATED it (result present, raw template text absent)"),
        OracleKind.ERROR_SIGNATURE: ("syntax-breaking probe", "inject a lone quote/paren vs a benign control; confirm a datastore/parser error appears in the probe but not the control"),
    }
    return generic.get(oracle_kind, ("payload probe", "inject a class-appropriate payload; confirm via the routed oracle"))


def draft_proposals(gaps: list[CapabilityGap]) -> list[CapabilityProposal]:
    """Turn each gap into a reviewable :class:`CapabilityProposal` spec.

    The suggested ``oracle_kind`` is the first (primary) oracle the verify layer
    routes the class to — so the implemented check is guaranteed to have a
    confirmation authority. The output preserves the input gap order (already
    priority-sorted by :func:`analyze_gaps`).

    Reminder: a proposal is a SPEC, not runnable check code — nothing here
    produces or installs a check (see the module docstring and :data:`SELF_APPLY`)."""
    proposals: list[CapabilityProposal] = []
    for gap in gaps:
        oracle_kind = gap.oracle_kinds[0]
        strategy = _STRATEGY_BY_ORACLE.get(
            oracle_kind, "place the probe into the insertion point and feed the oracle"
        )
        family, skeleton = _skeleton_for(gap.bug_class, oracle_kind)
        rationale = (
            f"Gap {gap.id} ({gap.source.value}): {gap.title}. "
            f"Implement a check that produces {gap.bug_class!r} and feeds the "
            f"{oracle_kind.value} oracle. This is a draft spec for human review; "
            f"it is not executable and will not be auto-applied."
        )
        proposals.append(
            CapabilityProposal(
                id=f"proposal-{gap.id}",
                gap_id=gap.id,
                bug_class=gap.bug_class,
                oracle_kind=oracle_kind,
                insertion_point_strategy=strategy,
                payload_family=family,
                payload_template_skeleton=skeleton,
                rationale=rationale,
            )
        )
    return proposals


__all__ = [
    "SELF_APPLY",
    "GapSource",
    "CapabilityGap",
    "CapabilityProposal",
    "Verdict",
    "Decision",
    "MergeGate",
    "analyze_gaps",
    "draft_proposals",
]
