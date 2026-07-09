"""
calibration.reward_bus — one reward fan-out for one confirmed-finding outcome.

Three learners want to hear about the same outcome — the check-ordering bandit
(``scanner.learning``), the calibration ledger (``calibration.ledger``), and the
cross-engagement memory priors (``memory.priors``) — plus the event spine. Historically each
was fed ad-hoc from a different code path (and the flagship ``engage`` loop fed none of them).
``credit_outcome`` is the single fan-out: it updates exactly the sinks a caller owns and emits
a ``reward`` event onto the spine, so the reward signal is finally visible on the one stream.

Two DISTINCT signals, kept honest:

  * The CALIBRATION LABEL is NON-CIRCULAR — ``outcome_label`` resolves EXPLOITABLE only on
    genuine cross-oracle corroboration (>=2 distinct oracle kinds firing); everything else is
    DISPUTED (excluded from every calibrator fit). A silent oracle is NEVER auto-labelled
    FALSE_POSITIVE — that would be the oracle judging itself. This is the SAME rule
    ``agents.critique_agent`` applies, now single-sourced here.
  * The BANDIT reward is check PRODUCTIVITY (did the oracle fire), which is legitimate because
    the bandit ORDERS effort — it never gates a surface or promotes a finding. LLM/critic
    signals never enter this path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Outcome, OutcomeLabel

_CORROBORATION_MIN = 2   # distinct oracle kinds needed for an autonomous EXPLOITABLE label


def outcome_label(oracle_fired: bool, distinct_confirming_kinds: int) -> OutcomeLabel:
    """The non-circular ground-truth label: EXPLOITABLE only on genuine cross-oracle
    corroboration (>= ``_CORROBORATION_MIN`` distinct kinds), else DISPUTED. A silent oracle
    is never auto-FALSE_POSITIVE. Real EXPLOITABLE/FALSE_POSITIVE labels come only from an
    INDEPENDENT adjudicator (eval corpus / operator) via ``ledger.record_outcome``."""
    return (OutcomeLabel.EXPLOITABLE
            if (oracle_fired and distinct_confirming_kinds >= _CORROBORATION_MIN)
            else OutcomeLabel.DISPUTED)


@dataclass
class RewardSignal:
    """The result of fanning out one outcome: the non-circular label + which sinks updated."""

    label: OutcomeLabel
    oracle_fired: bool
    updated: list[str] = field(default_factory=list)


def credit_outcome(
    *,
    oracle_fired: bool,
    distinct_confirming_kinds: int,
    seq: int,
    # bandit (check productivity — orders effort)
    bandit: Any = None,
    context: Any = None,
    arm: Any = None,
    # calibration ledger (non-circular label; only when a Prediction is supplied)
    ledger: Any = None,
    prediction: Any = None,
    # memory priors (cross-engagement)
    priors_store: Any = None,
    archetype: str = "",
    bug_class: str = "",
    surface_pattern: str = "",
    # event spine (a duck-typed sink exposing .reward(...) — e.g. agents.SpineSink)
    spine_sink: Any = None,
    target_event_id: int | None = None,
) -> RewardSignal:
    """Fan one confirmed-finding outcome out to exactly the sinks provided. Updates are
    independent and best-effort (an append-only/already-recorded ledger write is swallowed),
    so a caller wires only what it owns and no sink is double-fed. ``seq`` is the caller's
    monotonic clock (e.g. the finding's spine event id): the ledger pair uses ``2*seq`` /
    ``2*seq+1`` to match ``critique_agent``. Returns the non-circular label + what updated."""
    label = outcome_label(oracle_fired, distinct_confirming_kinds)
    updated: list[str] = []

    if bandit is not None and context is not None and arm is not None:
        try:
            bandit.update(context, arm, bool(oracle_fired))
            updated.append("bandit")
        except Exception:
            pass

    if ledger is not None and prediction is not None:
        try:
            ledger.add_prediction(prediction, seq=2 * seq)
            ledger.record_outcome(Outcome(finding_id=prediction.finding_id, label=label),
                                  seq=2 * seq + 1)
            updated.append("ledger")
        except Exception:
            pass   # append-only / already-recorded is expected and fine

    if priors_store is not None and archetype and bug_class:
        try:
            from ..memory.priors import bump_attempt, bump_success
            bump_attempt(priors_store, archetype, bug_class, surface_pattern)
            if oracle_fired:
                bump_success(priors_store, archetype, bug_class, surface_pattern)
            updated.append("priors")
        except Exception:
            pass

    if spine_sink is not None:
        try:
            sig = ("corroborated" if label is OutcomeLabel.EXPLOITABLE
                   else ("oracle_fired_disputed" if oracle_fired else "no_fire"))
            spine_sink.reward(
                "reward-bus", 1.0 if oracle_fired else 0.0, arm=str(arm or ""),
                signal=sig, target_event_id=target_event_id,
                rationale=f"label={label.value}; distinct_kinds={distinct_confirming_kinds}")
            updated.append("spine")
        except Exception:
            pass

    return RewardSignal(label=label, oracle_fired=bool(oracle_fired), updated=updated)
