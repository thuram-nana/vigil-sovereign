"""
memory.fleet — cross-engagement / fleet learning transfer (opt-in, purely additive).

A single MLS store already pools ``archetype_priors`` across every engagement that
wrote to *that* database. This module goes one level further: it aggregates outcomes
across a **fleet** of CRUCIBLE deployments — many stores, and portable prior/label
*shards* exported from them — into one pooled view, so a fresh engagement can warm-start
from the whole fleet's history, not just the local box's.

Two pooled surfaces are provided, each strictly additive and evidence-gated:

  * :class:`FleetPriors` — pooled ``(archetype, bug_class, surface_pattern)`` success/
    attempt counts. Consumed as an OPT-IN extra source by
    ``memory.priors.smoothed_priors_for`` / ``get_prior_smoothed`` (pass ``fleet=`` or
    enable ``CRUCIBLE_FLEET``). It only ever *adds* recorded evidence to the same
    similarity-weighted, discounted, effective-attempts-gated transfer math the local
    store already runs — it never invents a count, and an under-evidenced pooled blend is
    still withheld by the existing honesty gate. It warm-starts the bandit ONLY through
    the existing ``ContextualBandit.seed_from_priors`` cold-start bridge (the pooled prior
    is ``Prior``-shaped); nothing here touches the bandit's rank/mean/serialization.

  * :class:`FleetLabels` — pooled, de-duplicated ``(Prediction, Outcome)`` calibration
    labels drawn from many engagements' outcome ledgers. This mitigates calibration
    data-starvation: conformal prediction reaches its ``MIN_LABELS`` (≥8) coverage
    guarantee sooner because more *real* labels are available. It fabricates nothing —
    below the threshold ``coverage_guaranteed`` stays ``False`` exactly as
    ``calibration.conformal`` enforces — and it can filter to a single ``model_version``
    to preserve the exchangeability the conformal guarantee rests on.

Doctrine (CLAUDE.md / metacognition, and the invariants in the crucible skill):

  * **Never fabricate.** Every pooled number is a sum of recorded counts / a union of
    recorded labels. A source with no evidence contributes nothing.
  * **Opt-in, default-off, deterministic.** ``load_fleet_*_from_env`` return ``None``
    unless ``CRUCIBLE_FLEET`` is truthy, so the default and replayed paths (and the
    regression gate, which never enables it) are byte-identical. Shard/store ordering is
    sorted and pooling is canonical, so the aggregate is reproducible.
  * **Additive.** No existing behaviour is on this module's import path; a fleet is only
    ever an extra source folded into the *same* gated transfer / calibration math.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..common import logging as v2log
from ..common import paths
from ..common.errors import CrucibleError
from .priors import Prior
from .store import Store, open_store

_log = v2log.get_logger(__name__)


# ---------------------------------------------------------------------------
# Opt-in flag + resolution (mirrors common.capabilities._flag semantics).
# ---------------------------------------------------------------------------

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def fleet_enabled() -> bool:
    """Fleet transfer is OPT-IN: it fires only when ``CRUCIBLE_FLEET`` is truthy.
    Default OFF, so the default / replayed path — and ``make gate``, which never sets
    it — is byte-identical whether or not fleet shards exist on disk."""
    return _flag("CRUCIBLE_FLEET")


class FleetError(CrucibleError):
    """A malformed fleet shard. Recoverable: the loader logs and skips a bad shard
    rather than sinking the engagement, so a single corrupt file never blocks transfer."""


# ---------------------------------------------------------------------------
# FleetPriors — pooled cross-engagement prior counts
# ---------------------------------------------------------------------------

FLEET_PRIORS_SCHEMA = 1
FLEET_PRIORS_KIND = "crucible-fleet-priors"

# A pooled prior must carry at least this many recorded attempts to be offered at all.
# This is the *fabrication* floor (never surface a key with zero evidence); the far
# stronger *trust* gate is the effective-attempts floor applied downstream in
# memory.priors after the similarity discount.
_MIN_POOLED_ATTEMPTS = 1


class FleetPriors:
    """Pooled ``(archetype, bug_class, surface_pattern) -> (successes, attempts)`` counts
    aggregated across many engagements / fleet nodes.

    Fold in evidence from any mix of live stores (:meth:`add_store`) and portable JSON
    shards (:meth:`add_shard`). Read it back through the same shape the transfer math
    uses on a single store — :meth:`get_prior`, :meth:`distinct_archetypes`,
    :meth:`class_surface_keys` — so ``memory.priors`` can consult it as a drop-in extra
    source. Counts are integer sums, so pooling is exact and order-independent."""

    def __init__(self, *, min_pooled_attempts: int = _MIN_POOLED_ATTEMPTS) -> None:
        # keyed by (archetype, bug_class, surface_pattern) -> [successes, attempts]
        self._counts: dict[tuple[str, str, str], list[int]] = {}
        self._last_updated: dict[tuple[str, str, str], str] = {}
        self._sources: set[str] = set()
        self._min_pooled_attempts = max(0, int(min_pooled_attempts))

    # -- folding evidence in ----------------------------------------------

    def _fold(
        self,
        archetype: str,
        bug_class: str,
        surface_pattern: str,
        successes: int,
        attempts: int,
        *,
        last_updated: str = "",
    ) -> None:
        if successes < 0 or attempts < 0:
            raise FleetError(
                f"negative fleet counts for {(archetype, bug_class, surface_pattern)!r}: "
                f"successes={successes} attempts={attempts}"
            )
        if successes > attempts:
            # Honesty: successes can never exceed attempts. A shard that claims otherwise
            # is malformed — refuse it rather than silently clamp and assert unrecorded wins.
            raise FleetError(
                f"fleet successes ({successes}) exceed attempts ({attempts}) for "
                f"{(archetype, bug_class, surface_pattern)!r}"
            )
        key = (archetype, bug_class, surface_pattern or "")
        slot = self._counts.setdefault(key, [0, 0])
        slot[0] += int(successes)
        slot[1] += int(attempts)
        if last_updated and last_updated > self._last_updated.get(key, ""):
            self._last_updated[key] = last_updated

    def add_store(self, store: Store, *, source_id: str | None = None) -> int:
        """Fold every ``archetype_priors`` row of a live MLS ``store`` into the pool.
        Returns the number of rows folded. Reads the FULL table (not the top-N view) so
        the fleet aggregate is complete."""
        rows = store.fetchall(
            "SELECT archetype, bug_class, surface_pattern, successes, attempts, last_updated "
            "FROM archetype_priors"
        )
        n = 0
        for r in rows:
            self._fold(
                r["archetype"], r["bug_class"], r["surface_pattern"] or "",
                int(r["successes"]), int(r["attempts"]),
                last_updated=r["last_updated"] or "",
            )
            n += 1
        self._sources.add(source_id or "store")
        return n

    def add_store_path(self, db_path: Path | str, *, source_id: str | None = None) -> int:
        """Open an EXISTING store read-only, fold its priors, close it. A missing path
        contributes nothing (returns 0) — never creates a store just to read a fleet."""
        p = Path(db_path)
        if not p.exists():
            return 0
        s = open_store(p)
        try:
            return self.add_store(s, source_id=source_id or str(p))
        finally:
            s.close()

    def add_shard(self, data: dict | Path | str, *, source_id: str | None = None) -> int:
        """Fold a portable prior shard — a dict, a JSON string, or a path to a ``.json``
        shard file (see :meth:`to_shard_dict` for the format). Returns rows folded.
        Raises :class:`FleetError` on a malformed shard (the env loader catches & skips)."""
        doc = self._read_shard(data)
        kind = doc.get("kind")
        if kind != FLEET_PRIORS_KIND:
            raise FleetError(f"not a {FLEET_PRIORS_KIND} shard (kind={kind!r})")
        version = doc.get("schema_version")
        if version != FLEET_PRIORS_SCHEMA:
            raise FleetError(
                f"unsupported fleet-priors schema_version {version!r} "
                f"(expected {FLEET_PRIORS_SCHEMA})"
            )
        recs = doc.get("priors", [])
        if not isinstance(recs, list):
            raise FleetError("fleet-priors 'priors' must be an array")
        sid = source_id or str(doc.get("source_id") or "shard")
        n = 0
        for rec in recs:
            if not isinstance(rec, dict):
                raise FleetError("each fleet prior record must be an object")
            try:
                archetype = str(rec["archetype"])
                bug_class = str(rec["bug_class"])
                successes = int(rec["successes"])
                attempts = int(rec["attempts"])
            except (KeyError, TypeError, ValueError) as e:
                raise FleetError(f"malformed fleet prior record {rec!r}: {e}") from e
            surface = str(rec.get("surface_pattern") or "")
            self._fold(archetype, bug_class, surface, successes, attempts,
                       last_updated=str(rec.get("last_updated") or ""))
            n += 1
        self._sources.add(sid)
        return n

    @staticmethod
    def _read_shard(data: dict | Path | str) -> dict:
        if isinstance(data, dict):
            return data
        if isinstance(data, Path):
            text = data.read_text(encoding="utf-8")
        elif isinstance(data, str) and data.lstrip().startswith("{"):
            text = data
        else:  # a path-like string
            text = Path(data).read_text(encoding="utf-8")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise FleetError(f"fleet shard is not valid JSON: {e}") from e
        if not isinstance(doc, dict):
            raise FleetError("fleet shard must be a JSON object")
        return doc

    # -- reading the pool back --------------------------------------------

    def get_prior(
        self, archetype: str, bug_class: str, surface_pattern: str = "",
    ) -> Prior | None:
        """The pooled prior for one key as a ``Prior`` (so it drops straight into the
        transfer math and the ``seed_from_priors`` bridge), or ``None`` when the pool has
        no — or too little — recorded evidence for it. Never fabricates: the returned
        counts are exactly the fleet's recorded sums."""
        key = (archetype, bug_class, surface_pattern or "")
        slot = self._counts.get(key)
        if slot is None or slot[1] < self._min_pooled_attempts or slot[1] <= 0:
            return None
        return Prior(
            archetype=archetype, bug_class=bug_class, surface_pattern=surface_pattern or "",
            successes=slot[0], attempts=slot[1],
            last_updated=self._last_updated.get(key, ""),
        )

    def distinct_archetypes(self) -> list[str]:
        """Every archetype with pooled evidence, sorted (stable neighbour scan order)."""
        return sorted({k[0] for k in self._counts})

    def class_surface_keys(self) -> list[tuple[str, str]]:
        """Every ``(bug_class, surface_pattern)`` with pooled evidence, sorted."""
        return sorted({(k[1], k[2]) for k in self._counts})

    def sources(self) -> list[str]:
        """The (sorted) source ids folded into this pool — provenance, not a score."""
        return sorted(self._sources)

    def is_empty(self) -> bool:
        return not self._counts

    def __bool__(self) -> bool:
        return bool(self._counts)

    def __len__(self) -> int:
        return len(self._counts)

    # -- export -----------------------------------------------------------

    def to_shard_dict(self, *, source_id: str | None = None) -> dict:
        """A portable, diffable prior shard: this pool serialised for another fleet node.
        Records are sorted by key so the document is byte-stable / reproducible."""
        recs = []
        for key in sorted(self._counts):
            succ, att = self._counts[key]
            rec = {
                "archetype": key[0], "bug_class": key[1], "surface_pattern": key[2],
                "successes": succ, "attempts": att,
            }
            lu = self._last_updated.get(key, "")
            if lu:
                rec["last_updated"] = lu
            recs.append(rec)
        return {
            "schema_version": FLEET_PRIORS_SCHEMA,
            "kind": FLEET_PRIORS_KIND,
            "source_id": source_id or "",
            "priors": recs,
        }

    def write_shard(self, path: Path | str, *, source_id: str | None = None,
                    indent: int | None = 2) -> Path:
        """Write this pool as a shard file (owner-only). Deterministic bytes."""
        p = Path(path)
        text = json.dumps(self.to_shard_dict(source_id=source_id),
                          indent=indent, sort_keys=True, ensure_ascii=False)
        paths.secure_write(p, text)
        return p


def _shard_dir_from_env() -> Path:
    override = os.environ.get("CRUCIBLE_FLEET_DIR")
    if override:
        return Path(override).expanduser()
    return paths.memory_dir() / "fleet"


def _extra_db_paths_from_env() -> list[Path]:
    raw = os.environ.get("CRUCIBLE_FLEET_DB", "").strip()
    if not raw:
        return []
    return [Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip()]


def load_fleet_from_env() -> FleetPriors | None:
    """Assemble a :class:`FleetPriors` from the environment, or ``None`` when fleet
    transfer is not enabled or no evidence is found.

    Enabled only by ``CRUCIBLE_FLEET`` (truthy). Sources, folded in a deterministic
    (sorted) order:
      * every ``*.json`` prior shard under ``CRUCIBLE_FLEET_DIR`` (default
        ``<memory_dir>/fleet``) whose ``kind`` is ``crucible-fleet-priors``;
      * every ``os.pathsep``-separated store path in ``CRUCIBLE_FLEET_DB``.
    Best-effort: a malformed / unreadable shard is logged and skipped, never raised into
    the engagement. Returns ``None`` on an empty pool so callers stay byte-identical."""
    if not fleet_enabled():
        return None
    fleet = FleetPriors()
    # Prior shards (deterministic order).
    shard_dir = _shard_dir_from_env()
    if shard_dir.is_dir():
        for shard in sorted(shard_dir.glob("*.json")):
            try:
                # Peek: only fold shards that declare our prior kind, so a fleet dir may
                # also hold label shards (a different kind) without erroring here.
                doc = FleetPriors._read_shard(shard)
                if doc.get("kind") != FLEET_PRIORS_KIND:
                    continue
                fleet.add_shard(doc, source_id=str(shard))
            except FleetError as e:
                _log.warning("memory.fleet.shard_skipped", path=str(shard), error=str(e))
            except OSError as e:
                _log.warning("memory.fleet.shard_unreadable", path=str(shard), error=str(e))
    # Extra live stores (deterministic order).
    for db in sorted(_extra_db_paths_from_env()):
        try:
            fleet.add_store_path(db, source_id=str(db))
        except Exception as e:  # a broken sidecar store must never sink transfer
            _log.warning("memory.fleet.store_skipped", path=str(db), error=str(e))
    if fleet.is_empty():
        return None
    return fleet


# ---------------------------------------------------------------------------
# FleetLabels — pooled cross-engagement calibration labels
# ---------------------------------------------------------------------------
#
# Conformal prediction only emits a coverage GUARANTEE once it has >= MIN_LABELS (8)
# labelled outcomes; below that it honestly falls back to the Bayesian credible interval
# and marks coverage_guaranteed=False. A single fresh engagement rarely has 8 resolved
# labels, so the guarantee is perpetually out of reach. Pooling REAL labels from other
# engagements reaches the threshold sooner without inventing anything — the honesty gate
# in calibration.conformal is untouched and still fires below the (now-poolable) count.
# ---------------------------------------------------------------------------


class FleetLabels:
    """Pooled, de-duplicated ``(Prediction, Outcome)`` calibration labels from many
    engagements' outcome ledgers.

    De-dup is by ``finding_id`` (the ledger's append-only key): a finding that appears in
    several shards is counted ONCE (first-seen in deterministic add order), so pooling
    never double-counts the same resolved finding. Only RESOLVED entries (those with an
    outcome) are retained — an unresolved prediction is not a label."""

    def __init__(self) -> None:
        # finding_id -> (Prediction, Outcome); insertion order is the add order.
        self._by_id: dict[str, tuple[object, object]] = {}
        self._sources: set[str] = set()

    def add_ledger(self, ledger: object, *, source_id: str | None = None) -> int:
        """Fold the resolved pairs of an ``OutcomeLedger`` (anything exposing
        ``pairs()`` of ``(prediction, outcome)`` with ``.finding_id``). Returns the number
        of NEW labels added (already-seen finding_ids are skipped, not overwritten —
        append-only)."""
        pairs = getattr(ledger, "pairs", None)
        if not callable(pairs):
            raise FleetError("ledger must expose a pairs() method")
        n = 0
        for prediction, outcome in pairs():
            fid = getattr(prediction, "finding_id", None)
            if fid is None:
                continue
            if fid in self._by_id:
                continue
            self._by_id[fid] = (prediction, outcome)
            n += 1
        self._sources.add(source_id or "ledger")
        return n

    def add_ledger_shard(self, data: dict | Path | str, *, source_id: str | None = None) -> int:
        """Fold a ledger shard — the JSON document ``OutcomeLedger.to_dict`` produces
        (a dict, JSON string, or path). Reuses the ledger's own validation."""
        from ..calibration.ledger import OutcomeLedger

        if isinstance(data, dict):
            ledger = OutcomeLedger.from_dict(data)
        elif isinstance(data, Path):
            ledger = OutcomeLedger.load(data)
        elif isinstance(data, str) and data.lstrip().startswith("{"):
            ledger = OutcomeLedger.from_json(data)
        else:
            ledger = OutcomeLedger.load(Path(data))
        return self.add_ledger(ledger, source_id=source_id or "ledger-shard")

    def pooled_pairs(self, *, model_version: str | None = None) -> list[tuple[object, object]]:
        """The pooled resolved pairs in a deterministic order (by ``finding_id``).

        ``model_version`` (recommended) restricts the pool to labels produced by ONE
        scoring model, preserving the exchangeability the conformal guarantee rests on —
        residuals from a different scorer are not exchangeable with the query's. ``None``
        pools every model (the caller accepts the mixed-scorer caveat)."""
        out = []
        for fid in sorted(self._by_id):
            pred, outcome = self._by_id[fid]
            if model_version is not None and getattr(pred, "model_version", None) != model_version:
                continue
            out.append((pred, outcome))
        return out

    def augment(
        self,
        local_pairs: list[tuple[object, object]],
        *,
        model_version: str | None = None,
    ) -> list[tuple[object, object]]:
        """``local_pairs`` followed by every pooled label whose ``finding_id`` is not
        already present locally — the calibration set to hand to
        ``calibration.conformal``. Local labels always come first and are never displaced;
        fleet labels only ADD real, non-duplicate evidence. Deterministic."""
        seen = {
            getattr(p, "finding_id", None)
            for p, _o in local_pairs
        }
        merged = list(local_pairs)
        for pred, outcome in self.pooled_pairs(model_version=model_version):
            fid = getattr(pred, "finding_id", None)
            if fid in seen:
                continue
            seen.add(fid)
            merged.append((pred, outcome))
        return merged

    def sources(self) -> list[str]:
        return sorted(self._sources)

    def is_empty(self) -> bool:
        return not self._by_id

    def __bool__(self) -> bool:
        return bool(self._by_id)

    def __len__(self) -> int:
        return len(self._by_id)


FLEET_LABELS_KIND = "crucible-fleet-labels"  # reserved: ledger shards keep their own schema


def _label_dir_from_env() -> Path:
    override = os.environ.get("CRUCIBLE_FLEET_LABELS_DIR")
    if override:
        return Path(override).expanduser()
    return _shard_dir_from_env()  # labels live alongside prior shards by default


def load_fleet_labels_from_env() -> FleetLabels | None:
    """Assemble pooled calibration labels from the environment, or ``None`` when disabled
    / empty. Enabled by ``CRUCIBLE_FLEET``; reads every ``*.ledger.json`` shard under
    ``CRUCIBLE_FLEET_LABELS_DIR`` (default: the fleet dir). Best-effort: a malformed shard
    is logged and skipped. Returns ``None`` on an empty pool (callers stay byte-identical).

    A ledger shard is simply an ``OutcomeLedger.to_dict`` document; naming them
    ``*.ledger.json`` keeps them distinct from prior shards in a shared fleet dir."""
    if not fleet_enabled():
        return None
    labels = FleetLabels()
    label_dir = _label_dir_from_env()
    if label_dir.is_dir():
        for shard in sorted(label_dir.glob("*.ledger.json")):
            try:
                labels.add_ledger_shard(shard, source_id=str(shard))
            except Exception as e:  # noqa: BLE001 - never sink on a bad shard
                _log.warning("memory.fleet.label_shard_skipped", path=str(shard), error=str(e))
    if labels.is_empty():
        return None
    return labels


__all__ = [
    "FleetPriors",
    "FleetLabels",
    "FleetError",
    "fleet_enabled",
    "load_fleet_from_env",
    "load_fleet_labels_from_env",
    "FLEET_PRIORS_SCHEMA",
    "FLEET_PRIORS_KIND",
    "FLEET_LABELS_KIND",
]
