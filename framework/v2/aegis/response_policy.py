"""
aegis.response_policy — graduated challenge / throttle from the per-actor Beta belief (the G5 slice).

Doctrine: a LEAD never blocks and belief NEVER blocks — a hard block rides ONLY on a fired oracle's
re-runnable certificate (prove-don't-guess). But an actor that SUSTAINS suspicious behavior — repeated
SSRF/XXE leads, repeated confirmed attacks — earns a GRADUATED, availability-first response short of a
block: first ``challenge``, then (higher belief) ``throttle``. Both are soft (HTTP 429, retryable), so
a legitimate user degraded by a burst simply retries; a hard block is never reached on belief alone.

The escalation rides on the per-actor Beta belief's LOWER credible bound (``BeliefRef.lcb``), which
structurally requires SUSTAINED evidence: a thinly-evidenced actor has high variance → a low LCB → no
escalation, so a single hit cannot escalate (a dedicated ``MIN_SUSTAINED_OBS`` floor reinforces this).
Everything here is pure + deterministic (no wallclock, no rng): the Beta accumulation is commutative,
so a fixed multiset of AFFIRMING (lead/confirmed) inputs yields the same escalation regardless of
arrival order (the one order-sensitive step is the deliberate bounded-memory guard that declines to
create a node for a purely-benign actor — a leading benign is dropped rather than tracked). The
gateway applies this ONLY under ``enforce`` + the ``AEGIS_RESPOND`` entitlement.
"""

from __future__ import annotations

from ..intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from ..intel.refs import EntityRef
from ..worldmodel.models import NodeKind
from .actor_graph import ActorGraph
from .models import BeliefRef, Verdict

# Gateway telemetry is a LEAD-tier source (reliability C, credibility 3) — real, never a fact on its
# own, exactly like the aegis sensors and the third-party web-scanner source.
_GATEWAY_RELIABILITY = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)

# LCB escalation thresholds. challenge < throttle; a hard block is NEVER belief-driven. Calibrated
# against the Beta accumulation: sustained leads (affirms ~0.7) cross CHALLENGE around 3-4 hits and
# reach THROTTLE only under high sustained volume; repeated confirmed attacks (affirms ~0.9) reach
# THROTTLE faster. Because THROTTLE_LCB > CHALLENGE_LCB, challenge always precedes throttle.
CHALLENGE_LCB = 0.40
THROTTLE_LCB = 0.50
# Escalation ALSO requires the belief MEAN to show that suspicion DOMINATES the actor's history — not
# just a collapsed-variance LCB. Without this, a single lead pinned the mean just above 0.5 while
# sustained BENIGN traffic shrank the variance and lifted the LCB past the threshold, challenging a
# benign actor (the review's false positive). The gates are calibrated against the MEASURED belief
# curve so they sit strictly BETWEEN the benign and suspicious populations:
#   * CHALLENGE_MEAN = 0.55 — a benign-dominant actor tops out at mean 0.500 (the exactly-50/50
#     lead/benign case; any benign-MAJORITY actor is strictly below it, and the 0.7-refute benign
#     decay drives the review's "1 lead amid benign" FP down to ~0.38). A genuinely suspicious actor
#     starts at 0.578 (3 sustained leads). 0.55 separates them with margin on the benign side.
#   * THROTTLE_MEAN = 0.66 — a pure-lead actor's mean ASYMPTOTES at ~0.63 (never reaches it however
#     many leads), so plain leads only ever reach `challenge`. `throttle` is reached only by a sustained
#     STRONGER-than-lead affirming signal: repeated CONFIRMED attacks (~0.9) or repeated OOB-CORRELATED
#     SSRF/XXE elevations (~0.85, `feed_oob_correlation`) — i.e. sustained high-belief evidence, not lead
#     volume. Both remain belief-only: `throttle` is still a soft, retryable 429, NEVER a hard block.
CHALLENGE_MEAN = 0.55
THROTTLE_MEAN = 0.66
# "sustained, not one hit": a floor on APPLIED observations before ANY escalation, on top of the LCB
# (whose variance term already penalises thin evidence).
MIN_SUSTAINED_OBS = 3

# Per-verdict belief signal (polarity, confidence). A confirmed attack is the strongest affirming
# signal; a lead is moderate; a benign / None request is a genuine REFUTE (confidence > 0.5 so it is
# beta-dominant) that DECAYS an already-tracked actor's belief toward benign (recovery) — a neutral
# 0.5 never decayed it, so a NAT/shared-IP actor stayed locked (the review's no-recovery finding).
# Untracked benign actors are never given a node.
_CONFIRMED_SIGNAL = (Polarity.AFFIRMS, 0.9)
_LEAD_SIGNAL = (Polarity.AFFIRMS, 0.7)
_BENIGN_SIGNAL = (Polarity.REFUTES, 0.7)
# An OOB-CORRELATED SSRF/XXE lead — an unsolicited inbound hit on the operator's planted canary that
# ties back to an actor's SSRF/XXE payload (the app dereferenced the attacker-chosen canary host). It
# is STRONGER than a plain lead (0.85 > 0.70) — the out-of-band interaction is real corroboration a
# single inline response cannot supply — yet DELIBERATELY below a confirmed attack (0.90): it is still
# NOT a fired oracle, so it stays belief-only. It mints NO certificate and can NEVER produce a block
# (``graduated_action`` only ever returns challenge/throttle/None). Prove-don't-guess holds.
_OOB_CORRELATED_SIGNAL = (Polarity.AFFIRMS, 0.85)


def _verdict_signal(verdict: Verdict | None) -> tuple[tuple[Polarity, float], str]:
    """(``(polarity, confidence)``, ``claim``) for a verdict — the belief update this request warrants."""
    if verdict is not None and verdict.decision == "confirmed":
        return _CONFIRMED_SIGNAL, "confirmed_attack"
    if verdict is not None and verdict.decision == "lead":
        return _LEAD_SIGNAL, "attack_lead"
    return _BENIGN_SIGNAL, "benign_request"


def feed_and_score(graph: ActorGraph, actor_key: str, verdict: Verdict | None, *, seq: int) -> BeliefRef | None:
    """Fold this request's ``verdict`` into ``actor_key``'s Beta belief and return the updated belief.

    A purely-benign actor (a refute) with NO existing node is NOT tracked — only actors that have
    shown a lead/confirmed accumulate a node (bounded memory + no spurious escalation), and their
    LATER benign requests then decay the belief (recovery). ``obs_id`` is keyed on
    ``(seq, actor, claim)`` — no positional counter, no wallclock, no rng — so the accumulation is
    deterministic and order-independent."""
    subject = EntityRef(kind=NodeKind.SESSION, key=actor_key)
    node_id = subject.node_id
    (polarity, confidence), claim = _verdict_signal(verdict)
    if polarity is Polarity.REFUTES and graph.belief(node_id) is None:
        return None   # do not create a node for a benign-only actor
    obs = Observation(
        obs_id=f"aegis:gateway:{seq}:{node_id}|{claim}",
        source="aegis:gateway", source_kind=IntelSourceKind.REQUEST_TELEMETRY, collector="aegis",
        subject=subject, attrs={}, source_reliability=_GATEWAY_RELIABILITY,
        confidence=confidence, polarity=polarity, seq=seq, evidence=f"gateway verdict: {claim}")
    graph.observe(obs)
    return graph.belief(node_id)


def feed_oob_correlation(graph: ActorGraph, actor_key: str, attack_class: str, *, seq: int) -> BeliefRef | None:
    """Fold an OOB-CORRELATED elevation (an unsolicited canary hit tied to this actor's SSRF/XXE lead)
    into ``actor_key``'s Beta belief and return the updated belief. A STRONG affirming signal —
    stronger than a plain lead — but STILL belief-only: it mints NO certificate and can NEVER produce a
    block (``graduated_action`` never returns "block"). It only raises the actor toward the SAME
    graduated challenge/throttle a sustained lead earns.

    Reuses the SAME projection keystone as ``feed_and_score`` (same node, same source tier), so the
    accumulation stays deterministic + order-independent (``obs_id`` keyed on ``(seq, actor, claim)`` —
    no wallclock, no rng). AFFIRMS always accumulates a node (the actor already has one from the prior
    lead), so — unlike a benign refute — this is never dropped."""
    subject = EntityRef(kind=NodeKind.SESSION, key=actor_key)
    node_id = subject.node_id
    polarity, confidence = _OOB_CORRELATED_SIGNAL
    claim = f"oob_correlated:{attack_class}"
    obs = Observation(
        obs_id=f"aegis:gateway:oob:{seq}:{node_id}|{claim}",
        source="aegis:gateway", source_kind=IntelSourceKind.REQUEST_TELEMETRY, collector="aegis",
        subject=subject, attrs={}, source_reliability=_GATEWAY_RELIABILITY,
        confidence=confidence, polarity=polarity, seq=seq, evidence=f"gateway oob-correlation: {claim}")
    graph.observe(obs)
    return graph.belief(node_id)


def graduated_action(belief: BeliefRef | None) -> str | None:
    """The graduated action a SUSTAINED belief warrants: ``"throttle"`` | ``"challenge"`` | ``None``.

    NEVER ``"block"`` — a hard block rides only on a fired oracle's certificate (prove-don't-guess).
    Requires both ``MIN_SUSTAINED_OBS`` applied observations AND the LCB threshold, so a single hit
    (high variance → low LCB) can never escalate."""
    if belief is None or belief.n_observations < MIN_SUSTAINED_OBS:
        return None
    if belief.mean >= THROTTLE_MEAN and belief.lcb >= THROTTLE_LCB:
        return "throttle"
    if belief.mean >= CHALLENGE_MEAN and belief.lcb >= CHALLENGE_LCB:
        return "challenge"
    return None
