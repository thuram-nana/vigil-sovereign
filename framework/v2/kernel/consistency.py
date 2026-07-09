"""
kernel.consistency — self-consistency + semantic entropy for NO-ORACLE bindings.

Some claims no oracle will ever dispose: recon hypothesis generation, severity/impact
narratives, chain synthesis, threat-model drafting. For those there is no deterministic
re-fire to lean on — so the anti-hallucination move is DISAGREEMENT-AS-UNCERTAINTY: sample
the LLM binding N times, cluster the outputs by their DECISION-BEARING signature (not their
prose), and either return the answer the samples AGREE on or ABSTAIN when they don't. A
lone confident hallucination and a stable fact look identical in one sample; across N they
do not — a fabrication scatters, a real inference clusters.

Hard rule (matches the plan's scope decision): this is ONLY for no-oracle bindings. Where an
oracle settles the claim, stay single-shot — an LLM self-consistency vote must NEVER promote
a claim the oracle refused, and must never enter the oracle/SCE path. This module produces an
abstention signal and an entropy PENALTY; it never manufactures confidence.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable


class RateLimiter:
    """A minimum-interval throttle shared across parallel self-consistency samples — the LLM
    path's missing rate limit (Speed X4). Thread-safe; only ever DELAYS a call, never changes an
    output, so it is determinism-neutral and off the replay path. ``min_interval_s <= 0`` is a
    no-op (the default), so wiring it is opt-in and changes no default timing."""

    def __init__(self, min_interval_s: float) -> None:
        self._min = max(0.0, float(min_interval_s))
        self._lock = threading.Lock()
        self._next = 0.0

    def __call__(self) -> None:
        if self._min <= 0.0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            self._next = max(now, self._next) + self._min
        if wait > 0.0:
            time.sleep(wait)


def _guarded(run_fn: Callable[[], Any], rate_limiter: Callable[[], None] | None) -> Any:
    if rate_limiter is not None:
        rate_limiter()
    return run_fn()


def categorical_entropy(counts: Any, *, n_samples: int | None = None) -> float:
    """Normalised Shannon entropy in [0, 1] over a cluster-size distribution — the
    categorical generalisation of ``planner.goal_tree._bernoulli_entropy``. 0 = unanimous
    (all samples in one cluster); →1 = maximally split. Normalised by log2(n_samples) so
    the value is a stable penalty scalar independent of how many clusters formed."""
    sizes = [c for c in (counts.values() if isinstance(counts, dict) else counts) if c > 0]
    total = sum(sizes)
    if total <= 0 or len(sizes) <= 1:
        return 0.0
    h = -sum((c / total) * math.log2(c / total) for c in sizes)
    denom = math.log2(n_samples) if (n_samples and n_samples > 1) else math.log2(len(sizes))
    return round(h / denom, 6) if denom > 0 else 0.0


@dataclass
class ConsistencyResult:
    """The verdict of sampling a no-oracle binding N times.

    ``modal`` is the most-agreed output (a representative from the largest cluster);
    ``abstained`` is the load-bearing signal — True means the samples disagreed enough that
    the answer should be routed to ``needs_evidence`` rather than asserted. ``entropy`` is a
    confidence PENALTY (0 = unanimous, 1 = scattered), never a confidence boost."""

    modal: Any
    trace: Any = None
    n_samples: int = 0
    agreement: float = 0.0          # modal cluster share in [0, 1]
    entropy: float = 0.0            # normalised categorical entropy in [0, 1]
    abstained: bool = False
    clusters: dict[str, int] = field(default_factory=dict)
    reason: str = ""


def _canon(value: Any) -> str:
    """A stable, hashable signature for a decision key (order-independent, no wallclock)."""
    return json.dumps(value, sort_keys=True, default=str)


def _default_key(parsed: Any) -> Any:
    """Cluster on the FULL structured output when no decision-field extractor is given."""
    if hasattr(parsed, "model_dump"):
        return parsed.model_dump(mode="json")
    return parsed


def run_consistent(
    run_fn: Callable[[], tuple[Any, Any]],
    *,
    samples: int = 5,
    agreement_gate: float = 0.6,
    entropy_gate: float = 1.0,
    key_fn: Callable[[Any], Any] | None = None,
    max_workers: int = 1,
    rate_limiter: Callable[[], None] | None = None,
) -> ConsistencyResult:
    """Sample ``run_fn`` (a no-oracle binding call returning ``(parsed, trace)``) ``samples``
    times, cluster by ``key_fn`` (the decision-bearing signature; defaults to the whole
    structured output), and ABSTAIN when agreement < ``agreement_gate`` or entropy >
    ``entropy_gate``. Returns the modal answer either way — but ``abstained`` tells the caller
    whether to act on it or route it to ``needs_evidence``. Pure over ``run_fn``: it sources
    no randomness itself (variation comes from the backend's own sampling temperature).

    ``max_workers`` (X4) runs the samples through a bounded thread pool for external speed on a
    network-bound backend. Results are gathered in SUBMISSION ORDER (``ThreadPoolExecutor.map``
    preserves input order), so the modal representative — the first sample in the largest cluster
    — is byte-identical to the serial run. ``max_workers <= 1`` (the default) is exactly the old
    serial loop. ``rate_limiter`` (opt-in) spaces the concurrent calls."""
    # Agreement (modal share) is the PRIMARY gate; entropy is a secondary tripwire + the
    # confidence penalty. entropy_gate defaults to 1.0 (inclusive-off): since normalised
    # entropy is bounded by 1.0 and the check is strict `>`, the entropy condition never
    # fires at the default — a maximal split is already caught by agreement (1/n < gate).
    # Lower entropy_gate below 1.0 to add an independent entropy tripwire.
    key_fn = key_fn or _default_key
    n = max(1, int(samples))
    workers = max(1, int(max_workers))
    if workers <= 1 or n <= 1:
        outs: list[tuple[Any, Any]] = [_guarded(run_fn, rate_limiter) for _ in range(n)]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, n)) as ex:
            # map preserves input (submission) order → byte-stable modal representative.
            outs = list(ex.map(lambda _i: _guarded(run_fn, rate_limiter), range(n)))
    keys = [_canon(key_fn(p)) for p, _ in outs]
    counts = Counter(keys)
    modal_key, modal_n = counts.most_common(1)[0]
    agreement = modal_n / len(outs)
    entropy = categorical_entropy(dict(counts), n_samples=len(outs))
    rep = next(o for o, k in zip(outs, keys) if k == modal_key)   # first sample in the modal cluster

    abstained = agreement < agreement_gate or entropy > entropy_gate
    if abstained:
        reason = (f"self-consistency ABSTAIN: {len(counts)} distinct answers across {len(outs)} "
                  f"samples (agreement {agreement:.2f} < {agreement_gate}, entropy {entropy:.2f}) "
                  f"— routed to needs_evidence, not asserted")
    else:
        reason = (f"self-consistency OK: {modal_n}/{len(outs)} samples agree "
                  f"(agreement {agreement:.2f}, entropy {entropy:.2f})")
    return ConsistencyResult(
        modal=rep[0], trace=rep[1], n_samples=len(outs), agreement=round(agreement, 4),
        entropy=entropy, abstained=abstained, clusters=dict(counts), reason=reason)


def consistency_evidence(result: ConsistencyResult) -> dict[str, Any]:
    """An SCE-style Evidence PENALTY derived from a ConsistencyResult, for a no-oracle site
    to discount its confidence by disagreement. Never a boost: ``penalty`` = entropy, and an
    abstention floors the effective confidence. This carries an LLM-derived uncertainty
    signal OUT to the caller; it must not be fed back into the deterministic oracle/SCE inputs
    (self-consistency measures the LLM's stability, not the world's truth)."""
    return {
        "kind": "self_consistency",
        "n_samples": result.n_samples,
        "agreement": result.agreement,
        "entropy": result.entropy,
        "penalty": result.entropy,          # multiply a no-oracle confidence by (1 - penalty)
        "abstained": result.abstained,
    }
