"""Spine health — the read-time integrity guards that keep the derived projections HONEST against the
owner-signed record (W16-STD-4 / issue #530).

Three defects observed on the reference host motivated this module:

  (1) MISSING SIGNED HEAD. A host held spine records but had NO valid owner-signed head, so it served
      un-anchored memory with no tamper-evidence at all — silently.
  (2) PROJECTION DRIFT. The vector (Qdrant) / graph (Kùzu) PROJECTIONS drifted from the signed chain —
      13,667 vector points over a 16-record chain — and were served as if they were current.
  (3) UNRESOLVABLE CITATIONS. Individual retrieval hits carried a `seq`/`entry_hash` the signed chain does
      not hold (a stale/rebuilt projection point), and were rendered as if they cited a real record.

Doctrine (fail-closed DIRECTIONS):
  * an UNRESOLVABLE citation is REFUSED at read time — never rendered  (`resolve_citation`);
  * a DRIFTED projection is REPORTED — never silently served          (`projection_drift`);
  * a records-bearing host with no valid signed head is UNHEALTHY     (`signed_head_health`).

Everything here is PURE and store-only: it imports neither qdrant nor kuzu, so it runs in the required
pure-Python CI job. The vector/graph layers call it with plain counts + `(seq, entry_hash)` tuples they
already hold, so drift detection never depends on the heavy ML stack being importable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .checkpoint import verify_checkpoint
from .store import SpineStore


# --------------------------------------------------------------------------------------------------
# (1) signed-head health — a records-bearing host with no valid owner-signed head is UNHEALTHY.
# --------------------------------------------------------------------------------------------------
def signed_head_health(store: SpineStore) -> tuple[bool, str]:
    """``(ok, detail)``. A spine that HOLDS RECORDS must be anchored by a valid owner-signed head:

      * records > 0 and (no head / head does not verify)  → UNHEALTHY (the reference-host defect:
        records served with no tamper-evidence anchor). This is the check a health probe must FAIL.
      * records == 0 and no head                          → advisory OK (a pristine box — nothing to
        anchor yet; `sigil sign` writes the first head). Keeps a fresh checkout's doctor green.
      * head verifies (even benign-stale)                 → OK.

    The crypto itself (Ed25519 threshold + monotonic ``last_seq`` + the durable anti-rollback floor) is
    delegated to :func:`verify_checkpoint`; this only adds the records-present classification so a genuinely
    empty box is not failed for never having been signed."""
    ok, detail = verify_checkpoint(store)
    if ok:
        return True, detail
    if store.next_seq == 0:                       # zero records: pristine box — advisory, not a failure
        return True, "empty spine, not yet signed (pristine — run `sigil sign` to anchor once it has records)"
    return False, f"spine holds records but has no valid signed head: {detail}"


# --------------------------------------------------------------------------------------------------
# (3) unresolvable-citation refusal — the READ-TIME negative control.
# --------------------------------------------------------------------------------------------------
def resolve_citation(store: SpineStore, seq: Any, entry_hash: Any) -> bool:
    """True IFF ``(seq, entry_hash)`` resolves to a LIVE spine record whose ``entry_hash`` matches exactly.

    A citation that does NOT resolve — the seq is not in the live chain (a projection point that outlived a
    spine reset/prune), or its ``entry_hash`` differs from the record actually at that seq (a rebuilt/tampered
    projection) — returns False and MUST be refused at read time, never rendered. Fail-closed on any error
    (a malformed seq, an unreadable segment): an unverifiable citation is treated as unresolved."""
    if seq is None or entry_hash is None:
        return False
    try:
        rec = store.get(int(seq))
    except Exception:  # noqa: BLE001 — any read/parse failure ⇒ the citation is UNVERIFIABLE ⇒ refuse it
        return False
    return rec is not None and rec.entry_hash == entry_hash


def filter_resolved_hits(store: SpineStore, hits: list[dict], *, seq_key: str = "seq",
                         hash_key: str = "entry_hash") -> tuple[list[dict], list[dict]]:
    """Partition projection ``hits`` (the payload dicts a vector search returns) into
    ``(resolved, refused)`` by :func:`resolve_citation`. The caller renders ``resolved`` and DROPS
    ``refused`` — the read-time refusal of a citation that does not resolve to a signed record."""
    resolved: list[dict] = []
    refused: list[dict] = []
    for h in hits:
        (resolved if resolve_citation(store, h.get(seq_key), h.get(hash_key)) else refused).append(h)
    return resolved, refused


# --------------------------------------------------------------------------------------------------
# (2) projection-drift detection — REPORT, never silently serve.
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ProjectionDrift:
    """A verdict on whether a derived projection (the vector index or the graph) still matches the
    signed chain. PURE data — no live backend handle."""
    projection: str            # "vector" | "graph" | ...
    signed_records: int        # records the signed chain holds that this projection is derived from
    projected: int             # points/nodes the projection currently holds
    projected_max_seq: int     # highest spine seq the projection references (-1 if empty/unknown)
    spine_tip_seq: int         # highest seq the signed chain holds (-1 if empty)
    drift: bool
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "projection": self.projection, "signed_records": self.signed_records,
            "projected": self.projected, "projected_max_seq": self.projected_max_seq,
            "spine_tip_seq": self.spine_tip_seq, "drift": self.drift, "reasons": self.reasons,
        }


def projection_drift(projection: str, *, signed_records: int, projected: int,
                     projected_max_seq: int, spine_tip_seq: int) -> ProjectionDrift:
    """Compare a projection's shape against the SIGNED chain and return a drift verdict. Two independent,
    cheap, monotone signals — either one trips drift:

      * OUT-OF-RANGE REFERENCE: the projection references a seq BEYOND the signed chain's tip
        (``projected_max_seq > spine_tip_seq``) — the 13,667-vs-16 case, where the vector index still cites
        seqs a reset/rebuilt chain no longer holds. Every such citation is unresolvable by construction.
      * COUNT OVER-RUN: the projection holds MORE points than the signed chain holds projectable records
        (``projected > signed_records``) — stale points that survived a spine shrink.

    Both are drift in the UNSAFE direction (the projection claims MORE than the signed record supports). A
    projection that merely TRAILS the chain (fewer/older points — ``projected <= signed_records`` and
    ``projected_max_seq <= spine_tip_seq``) is stale-but-honest, NOT drift: re-projecting catches it up and
    it never serves a citation the chain cannot back."""
    reasons: list[str] = []
    if projected_max_seq > spine_tip_seq:
        reasons.append(
            f"projection references seq {projected_max_seq} beyond the signed chain tip {spine_tip_seq} "
            f"(those citations cannot resolve to a signed record)")
    if projected > signed_records:
        reasons.append(
            f"projection holds {projected} point(s) but the signed chain holds only {signed_records} "
            f"projectable record(s) (stale points survived a spine shrink/reset)")
    return ProjectionDrift(projection=projection, signed_records=signed_records, projected=projected,
                           projected_max_seq=projected_max_seq, spine_tip_seq=spine_tip_seq,
                           drift=bool(reasons), reasons=reasons)


def embeddable_record_count(store: SpineStore) -> tuple[int, int]:
    """``(embeddable_records, spine_tip_seq)`` over the LIVE (signed) spine — the denominator the vector
    projection is measured against. `embeddable` mirrors the vector index's own EMBEDDABLE_KINDS policy so
    the count is apples-to-apples with `VectorIndex.count()`. One pass, read-only."""
    from ..vectors.index import EMBEDDABLE_KINDS      # a frozenset of strings — no qdrant import triggered
    n = 0
    tip = -1
    for r in store.iter_records():
        tip = r.seq
        if r.kind in EMBEDDABLE_KINDS and r.text().strip():
            n += 1
    return n, tip
