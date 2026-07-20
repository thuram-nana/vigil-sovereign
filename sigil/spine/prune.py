"""Cold-archive hard-prune — the NON-DESTRUCTIVE machinery (Slice D): the referential-floor guards, the
owner-committed snapshot payload (Merkle accumulator + folded state), the archive COPY, and the
`--with-archive` re-attach verifier. NOTHING here deletes a live record or commits a head — Slice E wires
these into the crash-safe cutover. Everything is testable on a throwaway spine.

The archive is `SIGIL_HOME/spine/archive/` (relocatable via `SIGIL_SPINE_ARCHIVE_DIR`):
    archive/segments/seg-*.jsonl[.gz]     # whole sealed segments, byte-identical (copy, never a rename)
    archive/archive.manifest.json         # APPEND-ONLY across prunes: one row per archived segment + snapshot

Doctrine: MOVE = copy → verify → (Slice E) drop; here we stop after copy+verify (additive-only). The
verifier (`verify_with_archive`) anchors the archive to the OWNER SIGNATURE — never to the (attacker-
controllable) archive manifest: it requires a valid owner-signed live head, checks the per-record content
binding + the genesis chain, and ties the archived leaves to the owner key (before a prune commits: the
archive must equal the still-present live prefix; after: the archive tail == the signed head.base_prev_hash
and the re-derived cumulative == the signed head.cumulative_merkle_root). Only then is the manifest's own
Merkle re-derivation a meaningful self-consistency cross-check. Losing the archive makes the pruned prefix
unrecoverable (only the owner-signed Merkle commitment survives) — an explicit MAX-RECLAIM tradeoff.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional

from ..config import SIGIL_HOME, SCOPE
from ..reuse.chain import _GENESIS_PREV, _entry_hash, verify_chain
from ..reuse.models import ChainEntry
from .atomicio import atomic_write_text, fsync_dir
from .manifest import Segment, read_manifest
from .merkle import chain_cumulative, merkle_root
from .models import SpineRecord
from .snapshot import SnapshotState, build


class PruneUnsafe(Exception):
    """A prune point K fails a referential-integrity guard (§7) — refuse; touch nothing."""


def archive_dir() -> Path:
    env = os.environ.get("SIGIL_SPINE_ARCHIVE_DIR")
    return Path(env) if env else (SIGIL_HOME / "spine" / "archive")


# ---- segment IO (gz-aware, standalone so the archive path never depends on a live store handle) ---------
def _open_seg(path: Path):
    return gzip.open(path, "rt", encoding="utf-8") if str(path).endswith(".gz") else open(path, encoding="utf-8")


def read_segment_records(path: Path) -> list[SpineRecord]:
    out: list[SpineRecord] = []
    with _open_seg(path) as f:
        for raw in f:
            if raw.strip():
                out.append(SpineRecord.from_dict(json.loads(raw)))
    return out


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:                             # hash the ON-DISK bytes (gz stays gz — byte-identical)
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- §7 referential-integrity guards -------------------------------------------------------------------
def open_workflow_floor(store) -> int:
    """§7(b): the lowest seq that ANY still-open workflow — or anything it references — sits at. A prune
    boundary K must be <= this floor so no open loop (or its cited history) is ever pruned. Returns the
    live tip's next_seq when nothing is open (any segment-aligned K is then referentially safe). CONSERVATIVE
    by construction: a source we cannot enumerate can only make the true floor LOWER, so callers must treat
    this as an UPPER bound and the review must confirm completeness before Slice E enables deletion."""
    from ..agents.approvals import pending
    from ..consolidate.queries import due_commitments, open_threads, pending_contradictions

    floor = store.next_seq                                  # nothing open -> the tip
    seqs: list[int] = []
    for item in pending(store):                             # unresolved approval proposals + their targets
        p = item.payload
        seqs.append(item.seq)
        for k in ("target_seq", "proposal_seq", "plan_seq", "step_seq"):
            v = p.get(k)
            if isinstance(v, int):
                seqs.append(v)
    for row in open_threads(store, limit=10_000):           # open threads + cited source_seqs
        seqs.append(row["seq"])
        seqs.extend(s for s in (row.get("source_seqs") or []) if isinstance(s, int))
    for row in due_commitments(store, limit=10_000):
        seqs.append(row["seq"])
        seqs.extend(s for s in (row.get("source_seqs") or []) if isinstance(s, int))
    for row in pending_contradictions(store, limit=10_000):
        seqs.append(row["seq"])
        seqs.extend(s for s in (row.get("source_seqs") or []) if isinstance(s, int))
    # un-executed OPERATOR plans: a `operator.plan` not yet resolved by a terminal `operator.execute`
    # (APPLIED or FAILED+ROLLED_BACK) or a `refused` — its plan + preview must stay live until executed.
    plans: set[int] = set()                                 # non-refused operator.plan seqs
    executed: set[int] = set()
    for r in store.iter_records():
        p = r.payload
        sig = p.get("signal")
        if sig == "operator.plan" and p.get("decision") != "refused":
            plans.add(r.seq)                                # a real plan (a refused plan-attempt never opens)
        elif sig == "operator.execute" and isinstance(p.get("target_seq"), int):
            executed.add(p["target_seq"])                   # an execute (APPLIED or FAILED+ROLLED_BACK) closes it
    # CONSERVATIVE (over-restrict is the safe failure direction for the referential floor): a plan with no
    # terminal execute stays OPEN and floors the prune. We deliberately do NOT close a plan on a bare
    # `decision=="refused"` (a TOCTOU execute-abort is not terminal, and a global refused-match would couple
    # to unrelated actor-step refusals) — an unexecuted plan simply keeps its segment live.
    seqs.extend(plan_seq for plan_seq in plans if plan_seq not in executed)
    if seqs:
        floor = min(floor, min(seqs))
    return floor


def check_prune_safe(store, K: int) -> list[Segment]:
    """Validate a prune boundary K and return the sealed segments to archive (whole segments, last_seq < K),
    oldest-first. Raises PruneUnsafe on any violation. Reads only; touches nothing."""
    m = read_manifest(store._layout)
    if m is None:
        raise PruneUnsafe("legacy (un-migrated) spine — run `sigil spine migrate` before pruning")
    sealed = m.sealed_in_order()
    # (d) K MUST be a sealed-segment first_seq (whole segments only; base_prev_hash is then a stored value).
    boundaries = {s.first_seq for s in sealed}
    if K not in boundaries:
        raise PruneUnsafe(f"K={K} is not a sealed-segment boundary (aligns to whole segments only); "
                          f"valid boundaries: {sorted(boundaries)}")
    if K <= 0:
        raise PruneUnsafe("K must be > 0 (nothing to prune at genesis)")
    # (b) referential floor: every open workflow + everything it cites stays live.
    floor = open_workflow_floor(store)
    if K > floor:
        raise PruneUnsafe(f"K={K} exceeds the open-workflow referential floor {floor} — an open loop or a "
                          f"record it cites would be pruned; lower K or resolve the open work first")
    archived = [s for s in sealed if s.last_seq is not None and s.last_seq < K]
    if not archived:
        raise PruneUnsafe(f"no whole sealed segment lies entirely below K={K} — nothing to archive")
    # (a) dangling OPEN reference: a retained record whose parent/supersedes points below K into a seq that
    # is NOT itself covered by the archive (i.e. would become unresolvable). A closed ref is benign
    # (resolve()->PrunedRef in Slice E); an OPEN one already blocked by the floor above. Here assert the
    # archived set is a contiguous genesis-rooted prefix so no retained record links to a HOLE.
    if archived[0].first_seq != 0:
        raise PruneUnsafe("archive set does not start at genesis seq 0 — a non-prefix prune would strand refs")
    exp = 0
    for s in archived:
        if s.first_seq != exp:
            raise PruneUnsafe(f"archive set is non-contiguous at seg {s.id} (expected first_seq {exp})")
        exp = (s.last_seq or 0) + 1
    if exp != K:
        raise PruneUnsafe(f"archive set covers [0..{exp}) but K={K} — must be exactly contiguous to K")
    return archived


# ---- the owner-committed snapshot payload (Merkle accumulator + folded state) ---------------------------
def snapshot_payload(store, K: int, *, prior: Optional[dict] = None,
                     trusted_pubkey: Optional[str] = None) -> dict:
    """Compute the `kind="snapshot"` record payload committing the pruned prefix [0..K). `prior` is the
    previous snapshot's payload dict (None for the first prune). Pure computation — appends nothing."""
    from ..governor.identity import owner_pubkey
    tp = trusted_pubkey if trusted_pubkey is not None else (owner_pubkey() or "")
    archived = check_prune_safe(store, K)
    k_prev = int(prior["base_seq"]) if prior else 0
    prior_cumulative = str(prior["cumulative_merkle_root"]) if prior else ""
    # the prior snapshot's OWN seq is only known once it has been appended (Slice E stamps it back into the
    # payload); a not-yet-committed prior (e.g. the fold-of-fold computation) carries none -> -1.
    prior_snapshot_seq = int(prior.get("snapshot_seq", -1)) if prior else -1
    prior_folded = SnapshotState.model_validate(prior["folded_state"]) if prior else None

    # delta = the records pruned THIS round: [k_prev .. K-1], read from the segments being archived now.
    delta: list[SpineRecord] = []
    for seg in archived:
        if seg.first_seq >= k_prev:                         # a segment newly archived this round
            delta.extend(read_segment_records(store._layout.seg_path(seg)))
    delta.sort(key=lambda r: r.seq)
    if delta:
        if delta[0].seq != k_prev or delta[-1].seq != K - 1 or len(delta) != K - k_prev:
            raise PruneUnsafe(f"delta records do not cover [{k_prev}..{K}) exactly (got "
                              f"{delta[0].seq}..{delta[-1].seq}, n={len(delta)})")

    delta_root = merkle_root([r.entry_hash for r in delta])
    cumulative = chain_cumulative(prior_cumulative, delta_root)
    base_prev_hash = archived[-1].boundary_hash or _GENESIS_PREV   # == entry_hash(K-1), a stored boundary
    folded = build(delta, trusted_pubkey=tp, base_seq=K, snapshot_seq=-1, seed=prior_folded)
    return {
        "signal": "spine.snapshot",
        "base_seq": K,
        "base_prev_hash": base_prev_hash,
        "base_count": K,                                    # contiguous from genesis -> == K
        "delta_merkle_root": delta_root,
        "cumulative_merkle_root": cumulative,
        "prev_snapshot_seq": prior_snapshot_seq,
        "trusted_pubkey": tp,
        "folded_state": folded.model_dump(),
    }


# ---- archive COPY (copy -> verify; NEVER a live drop here) ----------------------------------------------
def archive_copy(store, K: int, snap_payload: dict, *, adir: Optional[Path] = None) -> dict:
    """Copy the whole sealed segments below K into the archive (byte-identical), append their rows + this
    snapshot's row to `archive.manifest.json`, and VERIFY (per-segment sha256 + genesis-rooted re-attach:
    seg-0.first_prev_hash==GENESIS, each boundary_hash==next.first_prev_hash, last boundary_hash==
    base_prev_hash). Additive + idempotent (re-copying an already-archived segment is a no-op on identical
    bytes). Returns a report. Raises PruneUnsafe on any verification failure — leaving the live spine
    untouched (nothing is dropped here in any case)."""
    from .floor import floor_lock                            # a generic sibling-lockfile flock (reused)
    ad = adir if adir is not None else archive_dir()
    segdir = ad / "segments"
    segdir.mkdir(parents=True, exist_ok=True)
    archived = check_prune_safe(store, K)
    manifest_path = ad / "archive.manifest.json"

    # Serialize the whole read-modify-write of archive.manifest.json + the segment copies, so two concurrent
    # archive_copy() calls cannot lose a manifest update or race on a segment file.
    with floor_lock(manifest_path):
        existing: dict[str, Any] = (json.loads(manifest_path.read_text(encoding="utf-8"))
                                    if manifest_path.exists()
                                    else {"scope": SCOPE, "schema_version": 1, "segments": [], "snapshots": []})
        have = {row["id"] for row in existing["segments"]}
        copied = _copy_segments(store, archived, existing, have, segdir, ad)
        existing["segments"].sort(key=lambda r: r["first_seq"])
        # append this snapshot's row (idempotent by cumulative root)
        srow = {k: snap_payload[k] for k in ("base_seq", "base_count", "delta_merkle_root",
                                             "cumulative_merkle_root", "prev_snapshot_seq")}
        if not any(s.get("cumulative_merkle_root") == srow["cumulative_merkle_root"]
                   for s in existing["snapshots"]):
            existing["snapshots"].append(srow)
        atomic_write_text(manifest_path, json.dumps(existing, indent=2), prefix=".amanifest-")
        fsync_dir(ad)
        _verify_archive_shape(existing, base_prev_hash=snap_payload["base_prev_hash"])
    return {"copied": copied, "archived_segments": len(existing["segments"]),
            "archive_dir": str(ad), "verified": True}


def _copy_segments(store, archived: list[Segment], existing: dict, have: set,
                   segdir: Path, ad: Path) -> int:
    copied = 0
    for seg in archived:
        src = store._layout.seg_path(seg)
        dst = segdir / src.name
        sha = _sha256_file(src)
        row = {"id": seg.id, "file": f"segments/{src.name}", "first_seq": seg.first_seq,
               "last_seq": seg.last_seq, "first_prev_hash": seg.first_prev_hash,
               "boundary_hash": seg.boundary_hash, "sha256": sha,
               "count": (seg.last_seq or 0) - seg.first_seq + 1}
        if seg.id in have:
            prior_row = next(r for r in existing["segments"] if r["id"] == seg.id)
            # IDEMPOTENCY on CODEC-INVARIANT chain identity (first/last_seq + first_prev_hash + boundary_hash)
            # — stable across a live gzip-compaction that changes the segment's on-disk bytes (and thus its
            # sha256). Same identity -> keep the existing archived copy + its recorded sha256 untouched.
            same = all(prior_row.get(k) == row[k]
                       for k in ("first_seq", "last_seq", "first_prev_hash", "boundary_hash"))
            if not same:
                raise PruneUnsafe(f"archive already holds seg {seg.id} with a DIFFERENT chain identity — "
                                  f"refusing to overwrite (possible corruption/rewrite)")
            continue                                        # same segment already archived — idempotent no-op
        if not dst.exists():                                # copy -> fsync -> only then record (crash-safe)
            data = src.read_bytes()
            fd, tmp = _mkstemp(segdir, src.name)
            try:
                with os.fdopen(fd, "wb") as fo:
                    fo.write(data)
                    fo.flush()
                    os.fsync(fo.fileno())
                os.replace(tmp, dst)
            finally:
                Path(tmp).unlink(missing_ok=True)           # no-op if os.replace already consumed it
            fsync_dir(segdir)
        if _sha256_file(dst) != sha:
            raise PruneUnsafe(f"archived copy of seg {seg.id} hashes differently than the source — aborting")
        existing["segments"].append(row)
        copied += 1
    return copied


def _mkstemp(directory: Path, name: str):
    import tempfile
    return tempfile.mkstemp(dir=str(directory), prefix=f".{name}.", suffix=".tmp")


def _verify_archive_shape(manifest: dict, *, base_prev_hash: str) -> None:
    """The archived segment set must be a genesis-rooted, gap-free chain up to base_prev_hash."""
    segs = sorted(manifest["segments"], key=lambda r: r["first_seq"])
    if not segs:
        raise PruneUnsafe("archive manifest has no segments")
    if segs[0]["first_prev_hash"] != _GENESIS_PREV:
        raise PruneUnsafe("archive seg-0 does not link from genesis")
    for a, b in zip(segs, segs[1:]):
        if a["boundary_hash"] != b["first_prev_hash"]:
            raise PruneUnsafe(f"archive boundary break between seg {a['id']} and {b['id']}")
        if a["last_seq"] + 1 != b["first_seq"]:
            raise PruneUnsafe(f"archive seq gap between seg {a['id']} and {b['id']}")
    if segs[-1]["boundary_hash"] != base_prev_hash:
        raise PruneUnsafe("archive tail boundary != the snapshot's base_prev_hash")


# ---- re-attach verifier (`sigil spine verify --with-archive`) ------------------------------------------
def verify_with_archive(store, *, adir: Optional[Path] = None) -> tuple[bool, str]:
    """Prove the archived pruned prefix is AUTHENTIC — anchored to the OWNER SIGNATURE, never to the
    (attacker-controllable) archive manifest. Read-only; returns (ok, message). Checks, in order:
      (1) at-rest sha256 of every archived file;
      (2) the per-record CONTENT BINDING (verify_record: payload -> cert_digest AND entry_hash derivation)
          on every archived record — so a payload swap that preserves the chain fields is caught;
      (3) the LIVE spine head is a valid owner Ed25519 head (verify_checkpoint) — the anchor;
      (4) the archived prefix is a genesis-rooted contiguous chain (verify_chain);
      (5) the OWNER anchor, by whether a prune is committed in the signed head:
          • base_seq == 0 (no prune committed — the Slice-D capability state): the live spine STILL holds the
            archived prefix, so every archived record must EQUAL the owner-signed live record at that seq
            (entry_hash identity). The live head signs [0..T] incl. the prefix, so this ties the archive to
            the owner key.
          • base_seq  > 0 (a prune IS committed — Slice E): the live prefix is GONE. The archive must cover
            exactly [0..base_seq), its tail entry_hash must equal the owner-signed head.base_prev_hash, and
            the re-derived cumulative_merkle_root must equal the owner-signed head.cumulative_merkle_root;
            then [archive ‖ live] re-attaches into one genesis chain.
    Only after (5) is the manifest-vs-manifest Merkle re-derivation (6) a meaningful cross-check."""
    from ..config import HEAD_PATH
    from ..reuse.models import SignedChainHead
    from .checkpoint import verify_checkpoint
    from .verify import verify_record

    ad = adir if adir is not None else archive_dir()
    manifest_path = ad / "archive.manifest.json"
    if not manifest_path.exists():
        return False, f"no archive manifest at {manifest_path}"
    am = json.loads(manifest_path.read_text(encoding="utf-8"))
    segrows = sorted(am["segments"], key=lambda r: r["first_seq"])

    # (1) at-rest integrity + (2) per-record content BINDING (not just chain linkage).
    arch: list[SpineRecord] = []
    for row in segrows:
        p = ad / row["file"]
        if not p.exists():
            return False, f"archived segment {row['file']} is missing (pruned prefix unrecoverable)"
        if _sha256_file(p) != row["sha256"]:
            return False, f"archived segment {row['file']} sha256 mismatch (at-rest tamper/corruption)"
        for r in read_segment_records(p):
            bok, bwhy = verify_record(r)
            if not bok:
                return False, f"archived record seq {r.seq} content binding failed: {bwhy}"
            arch.append(r)
    arch.sort(key=lambda r: r.seq)

    # (3) the live spine head must be owner-authentic — the anchor for everything below.
    hok, hmsg = verify_checkpoint(store)
    if not hok:
        return False, f"live spine head does not verify ({hmsg}) — cannot anchor the archive to the owner key"
    head = SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8")) if HEAD_PATH.exists() else None
    base_seq = head.base_seq if head else 0
    base_prev_hash = head.base_prev_hash if head else _GENESIS_PREV
    committed_cumulative = head.cumulative_merkle_root if head else ""

    # (4) the archived prefix is a genesis-rooted contiguous chain on its own.
    aentries = [ChainEntry(seq=r.seq, prev_hash=r.prev_hash, cert_digest=r.cert_digest, entry_hash=r.entry_hash)
                for r in arch]
    aok, amsg = verify_chain(aentries)
    if not aok:
        return False, f"archived prefix chain does not verify: {amsg}"

    # (5) OWNER anchor.
    if base_seq == 0:
        # no prune committed: the live spine STILL holds the archived prefix. ONE iter_records() pass builds
        # {seq: entry_hash} (never per-record store.get — that would emit .idx sidecars; this stays read-only
        # w.r.t. spine data), then cross-check every archived record against the owner-signed live record.
        live_hash = {r.seq: r.entry_hash for r in store.iter_records()}
        for r in arch:
            if live_hash.get(r.seq) != r.entry_hash:
                return False, (f"archived record seq {r.seq} does not match the owner-signed live spine "
                               f"(the archive is not a verified prefix of the current spine)")
        anchor = "against the owner-signed live prefix (no prune committed)"
    else:                                                   # a prune IS committed (Slice E): live prefix gone
        if not arch or arch[-1].seq != base_seq - 1 or arch[0].seq != 0 or len(arch) != base_seq:
            return False, f"archive does not cover exactly [0..{base_seq}) as the signed head declares"
        if arch[-1].entry_hash != base_prev_hash:
            return False, "archive tail entry_hash != the owner-signed head.base_prev_hash"
        # the committed snapshot rows must partition exactly [0..base_seq): all boundaries <= base_seq and the
        # LAST == base_seq. This both binds the cumulative to the owner-signed prefix AND keeps _cumulative_over
        # from indexing a leaf the archive doesn't hold (an attacker-added out-of-range snapshot row).
        snap_bases = sorted(int(s["base_seq"]) for s in am["snapshots"])
        if not snap_bases or snap_bases[-1] != base_seq or snap_bases[0] <= 0 or any(b > base_seq for b in snap_bases):
            return False, "archive snapshot boundaries do not partition [0..head.base_seq)"
        live_tail = [r for r in store.iter_records() if r.seq >= base_seq]
        chain = [ChainEntry(seq=r.seq, prev_hash=r.prev_hash, cert_digest=r.cert_digest, entry_hash=r.entry_hash)
                 for r in (arch + live_tail)]
        cok, cmsg = verify_chain(chain)
        if not cok:
            return False, f"re-attached [archive‖live] chain does not verify: {cmsg}"
        rederived = _cumulative_over(arch, am)
        if rederived != committed_cumulative:
            return False, ("re-derived cumulative_merkle_root != the owner-signed head.cumulative_merkle_root "
                           "(archived leaves are not what the owner committed)")
        anchor = "against owner-signed head.cumulative_merkle_root + base_prev_hash"

    # (6) manifest self-consistency: each committed delta/cumulative re-derives from the real archived leaves.
    by_seq = {r.seq: r for r in arch}
    prior_cumulative, k_prev = "", 0
    for srow in sorted(am["snapshots"], key=lambda s: s["base_seq"]):
        K = srow["base_seq"]
        if any(s not in by_seq for s in range(k_prev, K)):
            return False, f"archive is missing leaves for snapshot base_seq {K}"
        delta = merkle_root([by_seq[s].entry_hash for s in range(k_prev, K)])
        cumulative = chain_cumulative(prior_cumulative, delta)
        if delta != srow["delta_merkle_root"] or cumulative != srow["cumulative_merkle_root"]:
            return False, f"Merkle root mismatch at snapshot base_seq {K} (archive manifest inconsistent)"
        prior_cumulative, k_prev = cumulative, K
    return True, (f"archive verified {anchor}: {len(segrows)} segment(s), {len(arch)} records bound + "
                  f"chained from genesis; {len(am['snapshots'])} Merkle root(s) re-derived")


def _cumulative_over(arch: list[SpineRecord], am: dict) -> str:
    """The running cumulative over the full archived prefix, re-derived per committed snapshot boundary.
    Defensive: a snapshot boundary that indexes a leaf the archive does not hold returns a non-matching
    sentinel (never a KeyError) — the caller's `!= committed_cumulative` then fails closed."""
    by_seq = {r.seq: r for r in arch}
    cumulative, k_prev = "", 0
    for srow in sorted(am["snapshots"], key=lambda s: s["base_seq"]):
        K = int(srow["base_seq"])
        if any(s not in by_seq for s in range(k_prev, K)):
            return "MISSING-LEAF"                           # -> != any real cumulative -> caller fails closed
        cumulative = chain_cumulative(cumulative, merkle_root([by_seq[s].entry_hash for s in range(k_prev, K)]))
        k_prev = K
    return cumulative


# entry_hash recomputation guard used by tests (a leaf whose entry_hash != H(seq,prev,cert) is tampered).
def recompute_entry_hash(r: SpineRecord) -> str:
    return _entry_hash(r.seq, r.prev_hash, r.cert_digest)
