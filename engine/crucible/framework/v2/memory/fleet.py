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


# ---------------------------------------------------------------------------
# FleetRollup — cross-engagement RESULT aggregation (verdict-preserving)
# ---------------------------------------------------------------------------
#
# FleetPriors/FleetLabels pool LEARNING evidence (counts, labels). FleetRollup pools
# RESULTS: it composes many engagements' ``report.json`` / ``reverifiable.json`` and their
# signed coverage certificate (``verify.coverage_oracle``) into one fleet view — a portfolio
# roll-up over a whole deployment, not a single engagement.
#
# THE HARD INVARIANT — aggregation is VERDICT-PRESERVING; the roll-up never launders a verdict:
#
#   * INCONCLUSIVE stays INCONCLUSIVE. A class the run's plan committed but no oracle could
#     adjudicate is NOT rounded up to clean. In the fleet join, INCONCLUSIVE DOMINATES CLEAN
#     (``clean < inconclusive``), so a class clean in one engagement and inconclusive in
#     another aggregates to INCONCLUSIVE — never clean.
#   * CLEAN aggregates ONLY from real per-engagement CLEANs — a fleet ``clean`` for a class
#     means EVERY engagement that stated a verdict for it adjudicated it clean (none inconclusive,
#     none finding). "Not assessed" contributes no clean; it can only leave the verdict at, or
#     push it to, inconclusive. ``clean_is_corpus_wide`` at the fleet level is True only when
#     every contributing engagement was itself corpus-wide clean AND nothing is inconclusive.
#   * LEAD stays LEAD and FACT stays FACT. On the finding axis a FACT is counted ONLY from a
#     real per-engagement FACT WITH its certificate — a finding the engagement graded
#     ``grounding == "fact"`` (which the honest export guarantees carries a re-verifiable
#     ``oracle_context``: ``check_id != "" ==> grounding == "fact"``). A LEAD — passive
#     hygiene, a DOM candidate, an ungrounded / contradicted / hypothesis active — is counted
#     as a lead and can NEVER be rounded up to a fact.
#   * The coverage certificate's BOUNDS are preserved: ``n_inconclusive`` is summed and
#     surfaced (never dropped), and any truncation / budget-exhaustion in ANY certificate
#     marks the fleet reach as bounded — so a reader can never mistake the pooled reach for
#     whole-fleet completeness.
#
# The verdict lattice (the JOIN is the aggregate): clean < inconclusive < finding.
# ---------------------------------------------------------------------------

FLEET_ROLLUP_SCHEMA = "vigil-fleet-rollup/1"
_COVERAGE_CERT_SCHEMA = "vigil-coverage-certificate/1"

# The per-class coverage-verdict lattice. The aggregate over engagements is the JOIN (max):
# inconclusive dominates clean (no laundering of not-assessed / inconclusive into clean), and
# a real finding for the class dominates both (a confirmed positive is never hidden).
_VERDICT_RANK = {"clean": 0, "inconclusive": 1, "finding": 2}
_RANK_VERDICT = {v: k for k, v in _VERDICT_RANK.items()}


def _join_verdict(a: str, b: str) -> str:
    """The lattice join of two per-class coverage verdicts. Unknown verdicts are treated as
    ``inconclusive`` (fail-safe: an unrecognised label can never be read as clean)."""
    ra = _VERDICT_RANK.get(a, _VERDICT_RANK["inconclusive"])
    rb = _VERDICT_RANK.get(b, _VERDICT_RANK["inconclusive"])
    return _RANK_VERDICT[max(ra, rb)]


class FleetRollup:
    """Verdict-preserving cross-engagement roll-up of results.

    Fold in each engagement's ``report.json`` (:meth:`add_report`), its coverage certificate
    (:meth:`add_coverage_certificate`), and — for the strongest, RE-EXECUTED fact count — its
    ``reverifiable.json`` (:meth:`add_reverifiable`). Read the pooled view back with
    :meth:`to_rollup_dict`. Every aggregate is a verdict-preserving fold: see the module
    invariant above. Deterministic — output keys/lists are sorted, so two roll-ups over the
    same inputs are byte-identical."""

    def __init__(self) -> None:
        # coverage axis — per-class fleet verdict (the lattice join over contributing engagements)
        self._class_verdict: dict[str, str] = {}
        self._class_sources: dict[str, set[str]] = {}
        # the union corpus (every class any engagement adjudicated OR left inconclusive)
        self._corpus: set[str] = set()
        # each contributing report's own clean_is_corpus_wide (fleet clean-wide needs all True)
        self._engagement_corpus_wide: list[bool] = []
        self._classes_outside_corpus: set[str] = set()
        # finding axis — facts (grounding == "fact") vs leads (everything else)
        self._facts_by_class: dict[str, int] = {}
        self._leads_by_bucket: dict[str, int] = {}
        # reverifiable-sourced, RE-EXECUTED facts (independent corroboration)
        self._reverified_facts_by_class: dict[str, int] = {}
        self._reverify_failures: int = 0
        # coverage certificate bounds (summed / disjoined — never dropped)
        self._cert_n_finding = 0
        self._cert_n_clean = 0
        self._cert_n_inconclusive = 0
        self._cert_surfaces_reached = 0
        self._cert_frontier_truncated = 0
        self._cert_budget_exhausted = False
        self._cert_count = 0
        # provenance
        self._report_sources: set[str] = set()
        self._cert_sources: set[str] = set()
        self._reverifiable_sources: set[str] = set()

    # -- folding evidence in ----------------------------------------------

    @staticmethod
    def _read_doc(data: dict | Path | str) -> dict:
        if isinstance(data, dict):
            return data
        if isinstance(data, Path):
            text = data.read_text(encoding="utf-8")
        elif isinstance(data, str) and data.lstrip().startswith("{"):
            text = data
        else:
            text = Path(data).read_text(encoding="utf-8")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise FleetError(f"roll-up input is not valid JSON: {e}") from e
        if not isinstance(doc, dict):
            raise FleetError("roll-up input must be a JSON object")
        return doc

    def _fold_class_verdict(self, bug_class: str, verdict: str, source: str) -> None:
        """Fold one ``(class, verdict)`` via the lattice join. NEVER lowers a verdict — a
        clean can only raise to inconclusive/finding, never the reverse — so no source can
        launder an inconclusive/finding back down to clean."""
        if not bug_class:
            return
        cur = self._class_verdict.get(bug_class)
        self._class_verdict[bug_class] = verdict if cur is None else _join_verdict(cur, verdict)
        self._class_sources.setdefault(bug_class, set()).add(source)

    def add_report(self, data: dict | Path | str, *, source_id: str | None = None) -> str:
        """Fold one engagement's rendered ``report.json`` (``scanner.report.build_report``).

        Consumes THREE honest surfaces: ``verdict_by_class`` (the per-class coverage verdict,
        folded via the join), ``coverage_verdict`` (the bounded-CLEAN summary — its exercised
        ∪ inconclusive sets define the engagement's corpus and its ``clean_is_corpus_wide``
        gates the fleet's), and ``findings`` (each graded FACT vs LEAD by its ``grounding``).
        Returns the source id folded. Raises :class:`FleetError` on a doc that is clearly not a
        report (none of the three surfaces present)."""
        doc = self._read_doc(data)
        sid = source_id or str(doc.get("target") or "report")

        vbc = doc.get("verdict_by_class")
        cov = doc.get("coverage_verdict")
        findings = doc.get("findings")
        if not isinstance(vbc, dict) and not isinstance(cov, dict) and not isinstance(findings, list):
            raise FleetError(
                "not a CRUCIBLE report.json (no verdict_by_class / coverage_verdict / findings)")

        if isinstance(vbc, dict):
            for cls, verdict in vbc.items():
                self._fold_class_verdict(str(cls), str(verdict), sid)

        if isinstance(cov, dict):
            exercised = [str(c) for c in (cov.get("classes_exercised") or [])]
            inconclusive = [str(c) for c in (cov.get("classes_inconclusive") or [])]
            outside = [str(c) for c in (cov.get("classes_probed_outside_corpus") or [])]
            self._corpus.update(exercised)
            self._corpus.update(inconclusive)
            self._classes_outside_corpus.update(outside)
            # An inconclusive corpus class MUST fold as inconclusive even if verdict_by_class
            # was absent — never let a not-adjudicated class default to clean.
            for c in inconclusive:
                self._fold_class_verdict(c, "inconclusive", sid)
            self._engagement_corpus_wide.append(bool(cov.get("clean_is_corpus_wide")))

        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                self._fold_finding(f, sid)

        self._report_sources.add(sid)
        return sid

    def _fold_finding(self, f: dict, source: str) -> None:
        """Classify one rendered finding as a FACT or a LEAD and tally it. A FACT requires
        ``kind == "active"`` AND ``grounding == "fact"`` — the honest per-engagement fact label,
        which by the export's total invariant (``check_id != "" ==> grounding == "fact"``) also
        carries a re-verifiable certificate. Everything else is a LEAD, bucketed by why it is
        one (its grounding for a demoted active, its kind for a passive / DOM lead)."""
        kind = str(f.get("kind") or "")
        bug_class = str(f.get("bug_class") or "")
        grounding = str(f.get("grounding") or "unclassified")
        if kind == "active" and grounding == "fact":
            self._facts_by_class[bug_class] = self._facts_by_class.get(bug_class, 0) + 1
            return
        # LEAD — never a fact. Bucket by the honest reason it is not one.
        if kind == "active":
            bucket = f"active:{grounding}"     # ungrounded / contradicted / hypothesis / unclassified
        else:
            bucket = kind or "lead"            # passive / dom_xss_candidate
        self._leads_by_bucket[bucket] = self._leads_by_bucket.get(bucket, 0) + 1

    def add_coverage_certificate(self, data: dict | Path | str, *,
                                 source_id: str | None = None) -> str:
        """Fold one signed coverage certificate (``verify.coverage_oracle``). Sums its bounded
        summary (``n_finding`` / ``n_clean`` / ``n_inconclusive`` — the inconclusive count is
        surfaced, never dropped) and its denominator (surfaces reached, truncation, budget), and
        folds each per-probe ``(class, verdict)`` into the coverage-verdict join so a roll-up
        built purely from certificates still yields a verdict_by_class. Raises on a doc that is
        not a coverage certificate."""
        doc = self._read_doc(data)
        if doc.get("schema") != _COVERAGE_CERT_SCHEMA:
            raise FleetError(
                f"not a {_COVERAGE_CERT_SCHEMA} (schema={doc.get('schema')!r})")
        sid = source_id or str(doc.get("target_host") or "coverage-cert")

        summary = doc.get("summary") or {}
        self._cert_n_finding += int(summary.get("n_finding", 0) or 0)
        self._cert_n_clean += int(summary.get("n_clean", 0) or 0)
        self._cert_n_inconclusive += int(summary.get("n_inconclusive", 0) or 0)

        denom = doc.get("denominator") or {}
        self._cert_surfaces_reached += int(denom.get("surfaces_reached", 0) or 0)
        self._cert_frontier_truncated += int(denom.get("frontier_truncated", 0) or 0)
        if bool(denom.get("budget_exhausted")):
            self._cert_budget_exhausted = True

        for row in (doc.get("probes") or []):
            if not isinstance(row, dict):
                continue
            self._fold_class_verdict(str(row.get("class") or ""), str(row.get("verdict") or ""), sid)

        self._cert_count += 1
        self._cert_sources.add(sid)
        return sid

    def add_reverifiable(self, data: dict | Path | str, *, source_id: str | None = None,
                         reverify: bool = True) -> str:
        """Fold one engagement's ``reverifiable.json`` (a raw ScanReport dump, or the spine cert
        bundle from :mod:`agents.spine_certs`) — the FACTs WITH their retained ``oracle_context``.

        With ``reverify=True`` (default) each ``active_findings`` entry is RE-EXECUTED offline
        (``verify.reverify``): only a finding whose pure oracle re-fires over its retained
        evidence is counted a re-verified fact; one that does not reproduce (tampered, or never
        truly confirmed) is counted a failure, NOT a fact. This is the strongest, independently
        re-executed fact tally — it can never launder a lead or a tampered cert into a fact.
        Returns the source id folded."""
        doc = self._read_doc(data)
        sid = source_id or str(doc.get("target") or doc.get("engagement") or "reverifiable")
        findings = doc.get("active_findings")
        if not isinstance(findings, list):
            raise FleetError("not a reverifiable bundle (no active_findings array)")

        reverifier = None
        if reverify:
            # lazy import — the verify package pulls the oracle layer; keep it off memory's import path
            from ..verify.reverify import reverify_finding as reverifier  # type: ignore

        for f in findings:
            if not isinstance(f, dict):
                continue
            oc = f.get("oracle_context")
            bug_class = str(f.get("bug_class") or "")
            if not (isinstance(oc, dict) and oc):
                # no certificate ⇒ not a re-verifiable fact, never counted as one
                self._reverify_failures += 1
                continue
            if reverifier is not None:
                res = reverifier(f)
                if not getattr(res, "ok", False):
                    self._reverify_failures += 1
                    continue
            self._reverified_facts_by_class[bug_class] = (
                self._reverified_facts_by_class.get(bug_class, 0) + 1)

        self._reverifiable_sources.add(sid)
        return sid

    def add_engagement(self, run_dir: Path | str, *,
                       source_id: str | None = None, reverify: bool = True) -> str:
        """Convenience: fold one engagement's run directory — ``report.json`` (required),
        ``coverage.json`` / ``coverage-cert.json`` (if present), and ``reverifiable.json`` (if
        present). Missing optional artifacts are skipped, never fabricated. Returns the source id."""
        d = Path(run_dir).expanduser()
        sid = source_id or d.name
        report = d / "report.json"
        if report.is_file():
            self.add_report(report, source_id=sid)
        for name in ("coverage-cert.json", "coverage.json", "coverage_certificate.json"):
            cert = d / name
            if cert.is_file():
                try:
                    self.add_coverage_certificate(cert, source_id=sid)
                except FleetError:
                    pass  # a non-cert file under that name is skipped, not fatal
                break
        for name in ("reverifiable.json", "proofs/reverifiable.json"):
            rev = d / name
            if rev.is_file():
                try:
                    self.add_reverifiable(rev, source_id=sid, reverify=reverify)
                except FleetError:
                    pass
                break
        return sid

    # -- reading the pool back --------------------------------------------

    def _partition(self) -> tuple[list[str], list[str], list[str]]:
        """(clean, inconclusive, finding) class lists from the fleet join — a partition of the
        classes with a stated verdict."""
        clean, inconclusive, finding = [], [], []
        for cls, verdict in self._class_verdict.items():
            if verdict == "finding":
                finding.append(cls)
            elif verdict == "clean":
                clean.append(cls)
            else:
                inconclusive.append(cls)
        return sorted(clean), sorted(inconclusive), sorted(finding)

    def to_rollup_dict(self) -> dict[str, Any]:
        """The deterministic fleet roll-up. Verdict-preserving by construction (see the module
        invariant); every list/dict is sorted so two roll-ups over the same inputs match byte
        for byte."""
        clean, inconclusive, finding = self._partition()
        # fleet clean-corpus-wide: every contributing report was itself corpus-wide clean AND
        # the fleet join has nothing inconclusive and nothing found. "Not assessed" anywhere
        # blocks it — a not-assessed corpus class is inconclusive, which fails this gate.
        clean_is_corpus_wide = bool(
            self._engagement_corpus_wide
            and all(self._engagement_corpus_wide)
            and not inconclusive
            and not finding
        )
        return {
            "schema": FLEET_ROLLUP_SCHEMA,
            "engagements": {
                "reports": sorted(self._report_sources),
                "coverage_certificates": sorted(self._cert_sources),
                "reverifiable_bundles": sorted(self._reverifiable_sources),
                "count": len(self._report_sources | self._cert_sources | self._reverifiable_sources),
            },
            # coverage axis — the verdict-preserving per-class join
            "verdict_by_class": dict(sorted(self._class_verdict.items())),
            "coverage_bounds": {
                "corpus_classes": len(self._corpus | set(self._class_verdict)),
                "classes_clean": clean,
                "classes_inconclusive": inconclusive,
                "classes_finding": finding,
                "classes_probed_outside_corpus": sorted(self._classes_outside_corpus),
                # True ONLY when nothing is inconclusive AND every engagement was corpus-wide clean
                "clean_is_corpus_wide": clean_is_corpus_wide,
            },
            # the folded coverage-certificate bounds — inconclusive surfaced, reach disclosed
            "coverage_certificate_bounds": {
                "certificates": self._cert_count,
                "n_finding": self._cert_n_finding,
                "n_clean": self._cert_n_clean,
                "n_inconclusive": self._cert_n_inconclusive,
                "surfaces_reached": self._cert_surfaces_reached,
                "frontier_truncated": self._cert_frontier_truncated,
                "budget_exhausted": self._cert_budget_exhausted,
                # any truncation or budget exhaustion in ANY cert ⇒ the pooled reach is bounded
                "reach_bounded": bool(self._cert_frontier_truncated or self._cert_budget_exhausted),
            },
            # finding axis — FACTs (grounding=="fact", cert-backed) vs LEADs
            "facts": {
                "count": sum(self._facts_by_class.values()),
                "by_class": dict(sorted(self._facts_by_class.items())),
            },
            "leads": {
                "count": sum(self._leads_by_bucket.values()),
                "by_bucket": dict(sorted(self._leads_by_bucket.items())),
            },
            # independently RE-EXECUTED facts from reverifiable bundles (strongest tally)
            "reverified_facts": {
                "count": sum(self._reverified_facts_by_class.values()),
                "by_class": dict(sorted(self._reverified_facts_by_class.items())),
                "failures": self._reverify_failures,
            },
        }

    def write_rollup(self, path: Path | str, *, indent: int | None = 2) -> Path:
        """Write the roll-up as deterministic JSON. Returns the path written."""
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_rollup_dict(), indent=indent, sort_keys=True,
                                ensure_ascii=False), encoding="utf-8")
        return p


__all__ = [
    "FleetPriors",
    "FleetLabels",
    "FleetRollup",
    "FleetError",
    "fleet_enabled",
    "load_fleet_from_env",
    "load_fleet_labels_from_env",
    "FLEET_PRIORS_SCHEMA",
    "FLEET_PRIORS_KIND",
    "FLEET_LABELS_KIND",
    "FLEET_ROLLUP_SCHEMA",
]
