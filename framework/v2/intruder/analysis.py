"""
intruder.analysis — anomaly detection over an attack's result population.

Burp shows the tester a table and lets them find the interesting row by sorting on
status/length/time. That human step is the manual heart of Intruder. This module
replaces it: it baselines the whole response population and flags the rows that
stand out — a minority status code (the 200 among 401s), a length far from the
robust centre (the dumped record among the empties), or a grep-match hit.

Pure and deterministic: same rows in, same outlier indices out. Robust statistics
(median + MAD) are used so a few extreme rows don't hide the rest.
"""

from __future__ import annotations

from collections import Counter
from typing import Protocol


class _Row(Protocol):
    status: int
    length: int

    @property
    def grep(self) -> dict[str, bool]: ...


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def detect_outliers(
    rows: list["_Row"],
    *,
    minority_fraction: float = 0.2,
    mad_multiplier: float = 6.0,
) -> list[int]:
    """Indices of anomalous rows.

    A row is flagged if ANY of: its status code is a minority (held by
    ``<= minority_fraction`` of rows and not by all), its response length is more
    than ``mad_multiplier`` MADs from the median length, or one of its grep
    expressions matched. Empty/uniform populations yield no outliers."""
    n = len(rows)
    if n <= 1:
        return []

    status_counts = Counter(r.status for r in rows)
    threshold = max(1, int(n * minority_fraction))
    rare_statuses = {
        s for s, c in status_counts.items() if c <= threshold and c < n
    }

    lengths = [float(r.length) for r in rows]
    med = _median(lengths)
    mad = _median([abs(x - med) for x in lengths]) or 1.0

    outliers: list[int] = []
    for i, r in enumerate(rows):
        rare_status = r.status in rare_statuses
        length_outlier = abs(float(r.length) - med) > mad_multiplier * mad
        grep_hit = any(getattr(r, "grep", {}).values())
        if rare_status or length_outlier or grep_hit:
            outliers.append(i)
    return outliers
