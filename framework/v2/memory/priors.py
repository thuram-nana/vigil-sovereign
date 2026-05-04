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
