"""intel.frontier — the unified, deterministic DISCOVERY FRONTIER (Phase-1 Slice 1).

Slice 0 promotes in-scope recon/sensor assets into url-bearing ENDPOINT nodes; the autonomous loop
then seeds a probe-leaf per such node. But several producers write ENDPOINT candidates (promotion,
web-scanner web-leads, and — Slice 2 — in-loop crawling), each with its own url shape, and a large
recon graph could flood the goal tree with near-duplicate leaves (``?id=1`` vs ``?id=2`` are the SAME
testable location). The frontier is the normalizer between the producers and the goal tree: it collapses
candidates to ONE canonical location key, orders them by expected information gain, and caps the count.

It does NOT replace the goal tree (which is already a deterministic, VOI-ordered work-queue with a
drain) — it feeds it a clean, bounded, deduped candidate set. Everything here is pure + deterministic
(no wallclock / rng), so the same world yields the same frontier, and the caller invokes it ONLY on the
opt-in discover path — structurally unreachable from ``benchmark --gate``.

THE CANONICAL KEY ``(scheme_host, path, sorted-param-names, bug_class)`` is the crawler's own
trap-avoidance identity (:func:`scanner.crawler._location` collapses value-variants of one URL)
intersected with the fold's finding identity (``(bug_class, endpoint, insertion_point)``). Deduping on
it here means a surface is queued — and later probed and folded — at most once, however many producers
or value-variants surfaced it.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from ..planner.goal_tree import expected_information_gain

# A bound on how many probe-leaves one cycle seeds from the frontier, so a large recon/crawl graph
# cannot flood the goal tree. Truncation is REPORTED (never silent) by the caller.
DEFAULT_MAX_ITEMS = 64


def canonical_key(url: str, bug_class: str) -> tuple[str, str, tuple[str, ...], str]:
    """The location identity a testable surface dedups on: ``(scheme://host, path, sorted param-names,
    bug_class)``. Value-variants of one URL (``?id=1`` / ``?id=2``) and any duplicate producer collapse
    to one key; a different PATH, a different PARAM SET, or a different bug_class stays distinct. Host +
    scheme are lowercased; an empty path normalises to ``/``. Total (a URL it cannot split → a best-effort
    key over the raw string), never raises."""
    try:
        sp = urlsplit(url)
        scheme_host = f"{sp.scheme.lower()}://{sp.netloc.lower()}"
        path = sp.path or "/"
        params = tuple(sorted(parse_qs(sp.query, keep_blank_values=True).keys()))
        return (scheme_host, path, params, bug_class)
    except Exception:
        return ("", url or "", (), bug_class)


class FrontierItem(BaseModel):
    """One deduped, testable candidate surface the loop may probe. Frozen + hashable so it is usable in
    a set / as a dict key. ``prior`` is kept LOW (confirmed findings dominate goal-tree ordering);
    ``origin`` is provenance for telemetry only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    origin: str = "promotion"          # "promotion" | "sensor" | "crawl"
    bug_class: str = "xss"
    prior: float = Field(default=0.05, ge=0.0, le=1.0)

    @property
    def key(self) -> tuple[str, str, tuple[str, ...], str]:
        return canonical_key(self.url, self.bug_class)

    @property
    def eig(self) -> float:
        """Expected information gain of probing this surface — the SAME VOI kernel the recon planner and
        the goal tree use. Orders the frontier so the cap keeps the most-informative candidates."""
        return expected_information_gain(self.prior)


def _origin_for(node_id: str, provenance: str) -> str:
    """Classify a candidate's producer from its provenance, for telemetry (not for gating)."""
    p = (provenance or "").lower()
    if p.startswith("intel:promote:"):
        return "promotion"
    if "crawl" in p or "expand" in p:
        return "crawl"
    return "sensor"


class DiscoveryFrontier:
    """A deterministic, canonically-deduped, VOI-ordered, size-capped queue of testable surfaces.

    ``ingest`` adds a candidate (dedup by :func:`canonical_key` — first candidate for a key wins, so the
    order candidates are ingested in is the tie-break, and callers ingest in a deterministic id-sorted
    order). ``items`` returns the ordered, capped list. Pure + deterministic."""

    def __init__(self, *, max_items: int = DEFAULT_MAX_ITEMS, bug_class: str = "xss",
                 prior: float = 0.05) -> None:
        self.max_items = max(0, int(max_items))
        self.bug_class = str(bug_class or "xss")
        self.prior = min(max(float(prior), 0.0), 1.0)
        self._by_key: dict[tuple, FrontierItem] = {}
        self.truncated = 0   # how many candidates the cap dropped (reported, never silent)

    def ingest(self, url: str, node_id: str, *, origin: str = "sensor",
               bug_class: str | None = None, prior: float | None = None) -> bool:
        """Add a candidate surface; return True if it was NEW (not a canonical duplicate). Best-effort —
        an unusable url/node_id is ignored."""
        u = (url or "").strip()
        if not u or not (u.startswith("http://") or u.startswith("https://")) or not node_id:
            return False
        bc = str(bug_class or self.bug_class)
        item = FrontierItem(url=u, node_id=node_id, origin=origin, bug_class=bc,
                            prior=self.prior if prior is None else min(max(float(prior), 0.0), 1.0))
        k = item.key
        if k in self._by_key:
            return False
        self._by_key[k] = item
        return True

    def items(self) -> list[FrontierItem]:
        """The ordered, capped candidate list: by DESCENDING expected information gain, tie-broken by the
        canonical key (so the order is total + deterministic regardless of ingest order). The cap keeps
        the most-informative ``max_items``; the remainder is counted in :attr:`truncated`."""
        ordered = sorted(self._by_key.values(), key=lambda it: (-it.eig, it.key))
        if self.max_items and len(ordered) > self.max_items:
            self.truncated = len(ordered) - self.max_items
            ordered = ordered[: self.max_items]
        else:
            self.truncated = 0
        return ordered


def frontier_from_targets(
    targets: list[tuple[str, str]],
    *,
    world: object | None = None,
    bug_class: str = "xss",
    prior: float = 0.05,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> DiscoveryFrontier:
    """Build a frontier from ``(node_id, url)`` probe targets (e.g. the output of
    ``engage_autonomous._endpoint_probe_targets``), tagging each candidate's origin from its world-model
    node provenance when a ``world`` is given. Ingests in the given (deterministic, id-sorted) order so
    the canonical-dedup tie-break is stable."""
    fr = DiscoveryFrontier(max_items=max_items, bug_class=bug_class, prior=prior)
    for node_id, url in targets:
        origin = "sensor"
        if world is not None:
            try:
                node = world.get_node(node_id)   # type: ignore[attr-defined]
                if node is not None:
                    origin = _origin_for(node_id, getattr(node, "provenance", ""))
            except Exception:
                origin = "sensor"
        fr.ingest(url, node_id, origin=origin, bug_class=bug_class, prior=prior)
    return fr
