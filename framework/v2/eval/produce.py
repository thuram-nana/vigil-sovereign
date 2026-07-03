"""
eval.produce — bridge live engagement output into the eval harness.

The eval core (models/scoring/regression/harness) is deliberately
decoupled from the rest of the framework: it scores `ProducedFinding`s
against ground truth without knowing how they were produced. This module
is the adapter that closes the loop — it reads the findings a real
engagement recorded on the blackboard and maps them to `ProducedFinding`,
so the harness measures the actual framework rather than a fixture.

Kept out of `eval/__init__` on purpose: importing it pulls the agents
layer, and the eval core must stay importable without it.

Mapping decisions:
  - Only critique-CONFIRMED findings count by default. The framework's
    own gate is that the critique-agent must confirm a finding before it
    reaches a report; eval should measure what the framework would
    actually report, not pending or objected-to claims. Override with
    `confirmed_only=False` to score raw recall before the critique gate.
  - Confidence is derived from the critique status, and the originating
    hypothesis handle is carried as a detection key so surface-light
    findings can still match ground truth that supplies the same key.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Union

from ..agents.blackboard import Blackboard, BlackboardError
from ..agents.models import FindingPayload
from .models import BenchmarkTarget, ProducedFinding

if TYPE_CHECKING:  # avoid importing the calibration layer at module import time.
    from ..calibration import Calibrator, OutcomeLedger

# A fitted mapping (Calibrator), the ledger to fit one from (OutcomeLedger), or
# nothing. Kept as a public alias so callers can annotate the optional arg.
CalibratorLike = Union["Calibrator", "OutcomeLedger"]

# critique_status -> confidence the produced finding carries when NO calibrator
# is supplied. This is the honest, uncalibrated prior. "confirmed" is 0.9, NOT
# 1.0: critique- or oracle-confirmation is strong evidence, not certainty, and
# this module never emits a hardcoded 1.0 on any path (that false certainty was
# AUDIT finding #8 / DAA-adjacent). Whenever a calibrator IS supplied, the
# confirmed confidence is instead a probability *learned from recorded outcomes*
# (see `_HONEST_PRIOR` and framework.v2.calibration), clamped below 1.0.
_CONFIDENCE: dict[str, float] = {
    "confirmed": 0.9,
    "pending": 0.6,
    "objections": 0.2,
}

# critique_status -> honest, uncalibrated prior fed to a calibrator as the raw
# score. "confirmed" is 0.9, not 1.0: critique-confirmation is strong evidence,
# not certainty. Under an *identity* (data-sparse) calibrator these pass through
# unchanged, so even an unfitted calibrator never re-emits a false 1.0; under a
# *fitted* calibrator they are replaced by the isotonically-learned probability.
_HONEST_PRIOR: dict[str, float] = {
    "confirmed": 0.9,
    "pending": 0.6,
    "objections": 0.2,
}


def _resolve_calibrator(calibrator: CalibratorLike) -> "Calibrator":
    """Coerce a supplied calibrator-or-ledger into a fitted `Calibrator`.

    Imported lazily so `eval.produce` stays importable without the calibration
    layer when no calibrator is used. An `OutcomeLedger` is fit on the spot
    (deterministic: `fit` is a pure function of the ledger's resolved pairs);
    a `Calibrator` is used as-is."""
    from ..calibration import Calibrator, OutcomeLedger, fit

    if isinstance(calibrator, Calibrator):
        return calibrator
    if isinstance(calibrator, OutcomeLedger):
        return fit(calibrator.pairs())
    raise TypeError(
        "calibrator must be a calibration.Calibrator or calibration.OutcomeLedger, "
        f"got {type(calibrator).__name__}"
    )


def _confidence(payload: FindingPayload, calibrator: "Calibrator | None") -> float:
    """The confidence a produced finding carries.

    No calibrator -> the honest uncalibrated table ("confirmed" is 0.9, never a
    false 1.0). With a calibrator -> the honest prior for
    the finding's status is fed through the calibrator, so "confirmed" becomes
    a probability *learned from outcomes* rather than a hardcoded 1.0. A
    finding whose confirmation was carried by a deterministic oracle
    (`verified_by_oracle`) contributes a strong learned prior via the
    calibrator's noisy-OR, raising — never pinning — the number."""
    status = payload.critique_status
    if calibrator is None:
        return _CONFIDENCE.get(status, 0.5)
    raw = _HONEST_PRIOR.get(status, 0.5)
    return calibrator.calibrate(raw, oracle_confirmed=payload.verified_by_oracle)


def map_finding(
    payload: FindingPayload, *, calibrator: CalibratorLike | None = None
) -> ProducedFinding:
    """Map one blackboard finding to a ProducedFinding.

    `calibrator` is optional and additive: when omitted, confidence comes from
    the legacy status table (backward compatible). When supplied (a fitted
    `Calibrator` or an `OutcomeLedger` to fit one from), the confidence is the
    calibrated exploitability probability learned from recorded outcomes."""
    keys = [payload.derived_from_hypothesis] if payload.derived_from_hypothesis else []
    cal = _resolve_calibrator(calibrator) if calibrator is not None else None
    return ProducedFinding(
        bug_class=payload.bug_class,
        surface=payload.surface,
        summary=payload.title or payload.summary,
        confidence=_confidence(payload, cal),
        detection_keys=keys,
    )


def map_findings(
    findings: list[FindingPayload],
    *,
    confirmed_only: bool = True,
    calibrator: CalibratorLike | None = None,
) -> list[ProducedFinding]:
    """Map blackboard findings, optionally restricting to critique-confirmed.

    An optional `calibrator` (a fitted `Calibrator` or an `OutcomeLedger`) is
    resolved once and applied to every mapped finding, so a confirmed
    finding's confidence reflects learned outcomes rather than a hardcoded
    1.0. Omitting it preserves the legacy behavior exactly."""
    selected = [
        f for f in findings if (not confirmed_only or f.critique_status == "confirmed")
    ]
    cal = _resolve_calibrator(calibrator) if calibrator is not None else None
    return [
        ProducedFinding(
            bug_class=f.bug_class,
            surface=f.surface,
            summary=f.title or f.summary,
            confidence=_confidence(f, cal),
            detection_keys=(
                [f.derived_from_hypothesis] if f.derived_from_hypothesis else []
            ),
        )
        for f in selected
    ]


def read_blackboard_findings(bb: Blackboard, engagement_slug: str) -> list[FindingPayload]:
    """Read and validate the finding events for an engagement. Returns an
    empty list if the engagement does not exist on the blackboard."""
    try:
        rows = bb.read(engagement=engagement_slug, kinds=["finding"])
    except BlackboardError:
        return []
    out: list[FindingPayload] = []
    for row in rows:
        try:
            out.append(FindingPayload.model_validate(row.payload))
        except Exception:
            # A malformed finding row is skipped, not fatal to the run.
            continue
    return out


class BlackboardFindingProducer:
    """A `FindingProducer` that sources its findings from a live
    blackboard. Maps each benchmark target to an engagement slug (default:
    the target's own slug) and returns that engagement's confirmed
    findings as ProducedFindings.

    Usage:
        producer = BlackboardFindingProducer(bb)
        run = run_harness(corpus, producer, run_id="...")
    """

    def __init__(
        self,
        bb: Blackboard,
        *,
        slug_resolver: Callable[[BenchmarkTarget], str] | None = None,
        confirmed_only: bool = True,
        calibrator: CalibratorLike | None = None,
    ) -> None:
        self._bb = bb
        self._resolver = slug_resolver or (lambda t: t.slug)
        self._confirmed_only = confirmed_only
        # Optional and additive: None preserves the legacy naive confidences.
        self._calibrator = calibrator

    def __call__(self, target: BenchmarkTarget) -> list[ProducedFinding]:
        slug = self._resolver(target)
        findings = read_blackboard_findings(self._bb, slug)
        return map_findings(
            findings,
            confirmed_only=self._confirmed_only,
            calibrator=self._calibrator,
        )
