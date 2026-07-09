"""
memory.priors — Bayesian-flavoured prior tracker.

For each (archetype, bug_class, surface_pattern) triple, MLS keeps a
running successes/attempts count. The posterior mean under a Beta(1,1)
prior is the Laplace-smoothed success rate:

    p_hat = (successes + 1) / (attempts + 2)

The (deferred) planner reads these priors to bias initial branch
selection. They are recorded after-the-fact based on engagement
outcomes — never invented.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .store import Store


@dataclass
class Prior:
    archetype: str
    bug_class: str
    surface_pattern: str
    successes: int
    attempts: int
    last_updated: str

    @property
    def mean(self) -> float:
        """Laplace-smoothed success rate."""
        return (self.successes + 1) / (self.attempts + 2)

    @property
    def lower_bound(self) -> float:
        """Wilson 95% lower bound — conservative for the planner."""
        if self.attempts == 0:
            return 0.0
        n = self.attempts
        p = self.successes / n if n > 0 else 0.0
        z = 1.96
        denom = 1 + z * z / n
        centre = p + z * z / (2 * n)
        margin = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5
        return max(0.0, (centre - margin) / denom)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def bump_attempt(
    store: Store, archetype: str, bug_class: str, surface_pattern: str = "",
) -> None:
    store.execute(
        """
        INSERT INTO archetype_priors
          (archetype, bug_class, surface_pattern, successes, attempts, last_updated)
        VALUES (?, ?, ?, 0, 1, ?)
        ON CONFLICT(archetype, bug_class, surface_pattern) DO UPDATE SET
            attempts     = archetype_priors.attempts + 1,
            last_updated = excluded.last_updated
        """,
        (archetype, bug_class, surface_pattern or "", _now()),
    )
    store.commit()


def bump_success(
    store: Store, archetype: str, bug_class: str, surface_pattern: str = "",
) -> None:
    store.execute(
        """
        INSERT INTO archetype_priors
          (archetype, bug_class, surface_pattern, successes, attempts, last_updated)
        VALUES (?, ?, ?, 1, 1, ?)
        ON CONFLICT(archetype, bug_class, surface_pattern) DO UPDATE SET
            successes    = archetype_priors.successes + 1,
            attempts     = archetype_priors.attempts + 1,
            last_updated = excluded.last_updated
        """,
        (archetype, bug_class, surface_pattern or "", _now()),
    )
    store.commit()


def get_prior(
    store: Store, archetype: str, bug_class: str, surface_pattern: str = "",
) -> Prior | None:
    row = store.fetchone(
        "SELECT archetype, bug_class, surface_pattern, successes, attempts, last_updated "
        "FROM archetype_priors "
        "WHERE archetype = ? AND bug_class = ? AND surface_pattern = ?",
        (archetype, bug_class, surface_pattern or ""),
    )
    if row is None:
        return None
    return Prior(
        archetype=row["archetype"], bug_class=row["bug_class"],
        surface_pattern=row["surface_pattern"] or "",
        successes=row["successes"], attempts=row["attempts"],
        last_updated=row["last_updated"],
    )


def top_priors_for(store: Store, archetype: str, limit: int = 20) -> list[Prior]:
    rows = store.fetchall(
        "SELECT archetype, bug_class, surface_pattern, successes, attempts, last_updated "
        "FROM archetype_priors WHERE archetype = ? "
        "ORDER BY successes DESC, attempts DESC LIMIT ?",
        (archetype, limit),
    )
    return [
        Prior(
            archetype=r["archetype"], bug_class=r["bug_class"],
            surface_pattern=r["surface_pattern"] or "",
            successes=r["successes"], attempts=r["attempts"],
            last_updated=r["last_updated"],
        )
        for r in rows
    ]


def all_priors(store: Store, limit: int = 200) -> list[Prior]:
    rows = store.fetchall(
        "SELECT archetype, bug_class, surface_pattern, successes, attempts, last_updated "
        "FROM archetype_priors "
        "ORDER BY successes DESC, attempts DESC LIMIT ?",
        (limit,),
    )
    return [
        Prior(
            archetype=r["archetype"], bug_class=r["bug_class"],
            surface_pattern=r["surface_pattern"] or "",
            successes=r["successes"], attempts=r["attempts"],
            last_updated=r["last_updated"],
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# W1.3 — cross-engagement TRANSFER: embedding-smoothed, similarity-weighted priors.
#
# The exact prior is keyed on a single archetype, so a NEW or rarely-seen archetype
# starts cold even when very similar archetypes have paid-off history. Transfer fixes
# that: when the local prior is sparse, blend in priors from SIMILAR archetypes,
# weighted by lexical-embedding similarity and DISCOUNTED so borrowed evidence counts
# for less than direct. It never fabricates — a borrowed value is labelled, and a blend
# with too little effective evidence is withheld (meta_monitor's 'gather_evidence'
# doctrine applied to transfer). Deterministic; no bandit / gate coupling (priors are
# not on the make-gate path).
# ---------------------------------------------------------------------------

# A local exact prior with at least this many attempts is trusted as-is (no transfer).
_TRANSFER_EXACT_MIN_ATTEMPTS = 5
# Neighbour archetypes below this cosine similarity contribute nothing.
_TRANSFER_SIM_THRESHOLD = 0.15
# At most this many similar archetypes are blended (deterministic top-k).
_TRANSFER_MAX_NEIGHBORS = 8
# Transferred evidence is discounted: a neighbour's counts are scaled by
# similarity * this weight, so cross-archetype evidence is worth less than direct.
_TRANSFER_WEIGHT = 0.5
# A smoothed prior needs at least this many EFFECTIVE attempts to be trusted enough to
# warm-start an arm — the honesty gate on transfer.
_TRANSFER_MIN_EFFECTIVE_ATTEMPTS = 2.0


@dataclass
class SmoothedPrior:
    """A cross-engagement prior that may blend a LOCAL exact prior with
    similarity-weighted priors transferred from SIMILAR archetypes.

    Prior-shaped (``bug_class`` / ``successes`` / ``attempts``) so it drops straight
    into ``scanner.learning.ContextualBandit.seed_from_priors`` — but its counts are
    FRACTIONAL effective evidence and it is honestly labelled: ``is_transferred`` and
    the contributing ``sources`` make clear when a value was borrowed, never invented."""

    archetype: str
    bug_class: str
    surface_pattern: str
    successes: float          # effective (possibly fractional) pseudo-counts
    attempts: float
    is_transferred: bool
    sources: list[str]        # neighbour archetypes that contributed (sorted)
    sim_weight: float         # total transferred weight folded in

    @property
    def mean(self) -> float:
        """Laplace-smoothed success rate over the effective counts."""
        return (self.successes + 1) / (self.attempts + 2)

    def evidence_sufficient(
        self, min_effective_attempts: float = _TRANSFER_MIN_EFFECTIVE_ATTEMPTS,
    ) -> bool:
        """The honesty gate: a smoothed prior is trustworthy enough to warm-start an
        arm only when its EFFECTIVE attempt count clears a floor. A transfer from too
        little / too dissimilar data does not clear it and is left at the uniform prior
        (gather more evidence rather than assert a borrowed guess)."""
        return self.attempts >= min_effective_attempts


def distinct_archetypes(store: Store) -> list[str]:
    """Every archetype with at least one recorded prior, in a stable (sorted) order."""
    rows = store.fetchall(
        "SELECT DISTINCT archetype FROM archetype_priors ORDER BY archetype"
    )
    return [r["archetype"] for r in rows]


def _lexical_embedder():
    """The DETERMINISTIC embedder for transfer similarity — pinned to the stdlib
    ``LexicalEmbedder`` (SHA-1 feature hashing, PYTHONHASHSEED-independent), NOT the
    env-selected ``get_embedder()`` which may pick a nondeterministic model backend."""
    from .embed import LexicalEmbedder
    return LexicalEmbedder()


def get_prior_smoothed(
    store: Store,
    archetype: str,
    bug_class: str,
    surface_pattern: str = "",
    *,
    embedder=None,
    archetype_text=None,
    exact_min_attempts: int = _TRANSFER_EXACT_MIN_ATTEMPTS,
    sim_threshold: float = _TRANSFER_SIM_THRESHOLD,
    max_neighbors: int = _TRANSFER_MAX_NEIGHBORS,
    transfer_weight: float = _TRANSFER_WEIGHT,
) -> SmoothedPrior | None:
    """Cross-engagement prior for ``(archetype, bug_class, surface_pattern)``, smoothed
    by TRANSFER from similar archetypes.

    A well-evidenced LOCAL prior (``attempts >= exact_min_attempts``) is returned as-is
    (``is_transferred=False``) — no borrowing needed. Otherwise the (possibly empty)
    local counts are blended with counts from OTHER archetypes that carry a prior for
    the same ``(bug_class, surface_pattern)``, each weighted by
    ``cosine(embed(archetype), embed(neighbour)) * transfer_weight`` (``archetype_text``
    optionally maps an archetype name to a richer descriptor to embed). Returns ``None``
    only when there is neither a local prior nor a similar neighbour — never a fabricated
    value. Deterministic: the pinned LexicalEmbedder, neighbours sorted by name, and a
    canonical (sorted) summation make the blended float reproducible."""
    emb = embedder or _lexical_embedder()

    def _text(a: str) -> str:
        return archetype_text(a) if archetype_text is not None else a

    q_vec = emb.embed(_text(archetype))
    exact = get_prior(store, archetype, bug_class, surface_pattern)
    if exact is not None and exact.attempts >= exact_min_attempts:
        return SmoothedPrior(
            archetype=archetype, bug_class=bug_class, surface_pattern=surface_pattern or "",
            successes=float(exact.successes), attempts=float(exact.attempts),
            is_transferred=False, sources=[], sim_weight=0.0,
        )

    from .embed import cosine

    neighbours: list[tuple[str, float, Prior]] = []
    for other in distinct_archetypes(store):
        if other == archetype:
            continue
        nb = get_prior(store, other, bug_class, surface_pattern)
        if nb is None or nb.attempts <= 0:
            continue
        sim = cosine(q_vec, emb.embed(_text(other)))
        if sim >= sim_threshold:
            neighbours.append((other, sim, nb))
    # Deterministic top-k: most similar first, ties by archetype name.
    neighbours.sort(key=lambda t: (-t[1], t[0]))
    neighbours = neighbours[: max(0, int(max_neighbors))]

    if exact is None and not neighbours:
        return None

    succ = float(exact.successes) if exact is not None else 0.0
    att = float(exact.attempts) if exact is not None else 0.0
    total_w = 0.0
    # Canonical summation order (by neighbour name) → reproducible float sum.
    for other, sim, nb in sorted(neighbours, key=lambda t: t[0]):
        w = sim * transfer_weight
        succ += w * float(nb.successes)
        att += w * float(nb.attempts)
        total_w += w
    return SmoothedPrior(
        archetype=archetype, bug_class=bug_class, surface_pattern=surface_pattern or "",
        successes=succ, attempts=att, is_transferred=bool(neighbours),
        sources=sorted(other for other, _, _ in neighbours), sim_weight=total_w,
    )


def smoothed_priors_for(
    store: Store,
    archetype: str,
    *,
    embedder=None,
    archetype_text=None,
    min_effective_attempts: float = _TRANSFER_MIN_EFFECTIVE_ATTEMPTS,
    **kw,
) -> list[SmoothedPrior]:
    """The evidence-sufficient smoothed priors for ``archetype`` across every
    ``(bug_class, surface_pattern)`` recorded anywhere in the store — the transfer set
    that warm-starts a run's check-ordering bandit (feed it to ``WebScanCampaign(priors=
    …)``). A smoothed prior that does not clear the effective-attempts floor is DROPPED
    (its arm stays uniform), so transfer only ever adds evidence the data supports.
    Deterministic order (by bug_class, surface_pattern)."""
    emb = embedder or _lexical_embedder()
    rows = store.fetchall(
        "SELECT DISTINCT bug_class, surface_pattern FROM archetype_priors "
        "ORDER BY bug_class, surface_pattern"
    )
    out: list[SmoothedPrior] = []
    for r in rows:
        sm = get_prior_smoothed(
            store, archetype, r["bug_class"], r["surface_pattern"] or "",
            embedder=emb, archetype_text=archetype_text, **kw,
        )
        if sm is not None and sm.evidence_sufficient(min_effective_attempts):
            out.append(sm)
    return out
