"""spool_watcher — the SOVEREIGN-side consumer of the inert-finding filesystem seam (VIGIL COMMAND P5b).

It drains ``<spool>/incoming/*.json`` written by the offense producer (``vigil_integration.finding_spool``),
verifies each envelope's anchor-1 signature under an OWNER-SIGNED delegation, and ingests it onto the spine
— from where the cockpit governance feed (``SpineTailer`` → ``/api/stream``) surfaces it automatically.

The boundary invariants (this is the ONE inert seam — treat every byte as hostile):
  * SOVEREIGN OFFENSE-FREE: this module imports NO ``framework`` / ``strix``. Verification is ``vigil_core``
    only (via ``FindingReceiver`` / ``inert_finding``). It never executes or imports offense code.
  * OWNER-TIED, never blind: findings verify under an ``OFFENSE_GOVERNANCE_ROLE`` delegation, detection FACTs
    under an ``OFFENSE_SPINE_ROLE`` delegation — both owner-signed. The needed delegation MUST be configured
    for a kind, else every envelope of that kind is REJECTED (fail-closed).
  * FAIL-CLOSED: any validation / signature / scope / role / IO failure moves the file to ``rejected/`` with
    a ``.reason`` sidecar and appends NOTHING. Only a structurally-valid, owner-anchored, in-scope envelope
    is spined; on success the file moves to ``processed/``.
  * TRUSTED CLOCK: delegation expiry is checked against a LOCAL clock (``int(time.time())``), never anything
    derived from the envelope.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from vigil_integration.inert_finding import InertFindingError

from ..spine.store import SpineStore
from .finding_receiver import FindingReceiver

_MAX_BYTES = 256 * 1024  # mirror the validator's envelope cap; a larger file is rejected unread
# Dedup look-back for the RECLAIM path only: effectively unbounded (store clamps to the whole spine), so a
# re-ingested finding whose append had already landed before a crash is found regardless of how many records
# the shared spine accumulated during the restart gap. The O(spine) scan is paid only during crash recovery
# (reclaim is rare); the normal incoming/ path keeps the cheap bounded default.
_RECLAIM_DEDUP_WINDOW = 1 << 62


class SpoolWatcher:
    """Drains an offense→sovereign inert-finding spool onto the owner-signed spine, fail-closed."""

    def __init__(self, store: SpineStore, *, spool_dir: str | os.PathLike, owner_pubkey: str,
                 scope: str = "*", governance_delegation=None, spine_delegation=None,
                 now_fn: Callable[[], int] = lambda: int(time.time())) -> None:
        if not owner_pubkey:
            raise ValueError("owner_pubkey is required — a spool cannot be drained without the owner root")
        self.store = store
        self.owner_pubkey = owner_pubkey
        self.scope = scope
        self.governance_delegation = governance_delegation
        self.spine_delegation = spine_delegation
        self._now = now_fn
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"       # a file is CLAIMED here (out of incoming) before append
        self.processed = self.spool / "processed"   # doubles as the dedup ledger: <name> present ⇒ ingested
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    # -- ingest one file (fail-closed) -------------------------------------------------------------
    def _ingest_text(self, text: str, *, reclaim: bool = False) -> int:
        """Route by kind to an owner-delegated receiver and ingest. Raises InertFindingError on any
        refusal (nothing is written). A missing delegation for the file's kind is itself a refusal.

        ``reclaim=True`` (a file recovered from ``working/`` after a crash, the only path where the append may
        have ALREADY landed) widens the receiver's idempotency dedup to the whole spine, so the earlier append
        is found and the re-ingest de-duplicates to it no matter how many records intervened during the gap."""
        dedup_window = _RECLAIM_DEDUP_WINDOW if reclaim else None
        try:
            obj = json.loads(text)
        except ValueError as exc:
            raise InertFindingError(f"not valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise InertFindingError("envelope is not a JSON object")
        kind = obj.get("kind")
        now = int(self._now())
        if kind == "detection":
            if self.spine_delegation is None:
                raise InertFindingError("no offense-spine delegation configured — refusing detection FACTs")
            recv = FindingReceiver.from_spine_delegation(
                self.store, owner_pubkey=self.owner_pubkey, delegation=self.spine_delegation,
                now=now, scope=self.scope)
            return recv.ingest_detection(text, dedup_window=dedup_window)
        # a finding (or anything without kind=="detection") goes through the governance path
        if self.governance_delegation is None:
            raise InertFindingError("no offense-governance delegation configured — refusing findings")
        recv = FindingReceiver.from_delegation(
            self.store, owner_pubkey=self.owner_pubkey, delegation=self.governance_delegation,
            now=now, scope=self.scope)
        return recv.ingest(text, dedup_window=dedup_window)

    def _quarantine(self, path: Path, reason: str) -> None:
        dest = self.rejected / path.name
        try:
            os.replace(path, dest)
        except OSError:
            dest = self.rejected / (path.name + ".orphan")
        try:
            (self.rejected / (dest.name + ".reason")).write_text(reason[:2000], encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _read_regular(path: Path) -> str:
        """Read a REGULAR file without following a symlink or blocking on a FIFO, and decode it as UTF-8.
        A compromised producer that plants a symlink / named pipe / device / non-UTF-8 blob in the spool
        must never hang or CRASH the ingest, nor make us read/follow an arbitrary path. O_NOFOLLOW rejects
        a symlink at open; O_NONBLOCK returns instead of blocking on a writer-less FIFO; then S_ISREG + the
        size cap reject anything that is not a bounded regular file; and a non-UTF-8 decode is normalised to
        OSError. Raises OSError (ONLY) on any of these — so the caller's single ``except OSError`` catches
        every hostile-file case and quarantines it, and ``drain()`` never raises on one bad file."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file (symlink/FIFO/device refused)")
            if st.st_size > _MAX_BYTES:
                raise OSError(f"file exceeds {_MAX_BYTES} bytes")
            chunks, remaining = [], _MAX_BYTES + 1
            while remaining > 0:
                b = os.read(fd, remaining)
                if not b:
                    break
                chunks.append(b)
                remaining -= len(b)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if len(data) > _MAX_BYTES:
            raise OSError(f"file exceeds {_MAX_BYTES} bytes")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:          # a non-UTF-8 blob is hostile input, not a crash
            raise OSError(f"not valid UTF-8: {exc}") from exc

    def _reclaim_working(self) -> set[str]:
        """Crash recovery (no-loss): move any file stranded in ``working/`` — a claim (``os.replace`` into
        working/) that was interrupted before the file was archived to ``processed/`` or quarantined to
        ``rejected/``, i.e. a mid-drain crash — back to ``incoming/`` so it is reprocessed, and RETURN the set
        of reclaimed names. Without this, ``drain()`` (which scans ONLY ``incoming/``) would never look at a
        stranded file again and the confirmed FACT it carries would be SILENTLY LOST. This is the load-bearing
        durability guarantee: the FACT is recovered.

        A reclaimed file is the one case where re-ingest can hit an append that ALREADY LANDED before the crash
        (record on the spine, ``processed/`` archive not yet done). ``drain()`` therefore ingests a reclaimed
        file with an UNBOUNDED dedup scan (see ``_ingest_text(reclaim=True)``) so the earlier append is found
        and the re-ingest de-duplicates to it regardless of how many records the shared spine accumulated
        during the restart gap — not merely within the cheap bounded window the normal path uses. Reclaim is
        rare (a crash interrupts at most the in-flight claims), so the O(spine) scan is paid only in recovery.

        On a move failure the file is LEFT in ``working/`` (never deleted), so the next drain's reclaim retries
        it — a reclaim can never itself lose the FACT it exists to save."""
        reclaimed: set[str] = set()
        try:
            stale = list(self.working.glob("*.json"))
        except OSError:
            return reclaimed
        for f in stale:
            try:
                os.replace(f, self.incoming / f.name)
                reclaimed.add(f.name)
            except OSError:
                # Leave it in working/ for the next reclaim — NEVER unlink (that would lose the FACT this
                # sweep exists to save). A persistently-unmovable file is a filesystem fault for the operator,
                # not a reason to drop a confirmed finding.
                continue
        return reclaimed

    def drain(self) -> dict:
        """Process every file currently in ``incoming/`` once. Returns {ingested, rejected, deduped, seqs}.

        Begins with a crash-recovery sweep of ``working/`` (``_reclaim_working``): a file a mid-drain crash
        left stranded there — claimed out of ``incoming/`` but not yet archived/quarantined — is moved back
        to ``incoming/`` so its FACT is never lost. For each file: CLAIM it out of ``incoming/`` (atomic
        rename into ``working/``) BEFORE anything else, so a failed archive or a re-run can never re-read it
        from ``incoming/`` and double-append. Read it as a bounded regular UTF-8 file, then compute the dedup
        identity from the READ BYTES (not the producer-chosen filename — so a mismatched name cannot suppress
        a different finding). If that identical envelope was already ingested (``processed/<sha256>`` exists),
        the claimed copy is a re-spool and is archived WITHOUT re-appending (idempotent). Otherwise ingest and
        archive to ``processed/<sha256>`` (the dedup marker). The append is ALSO idempotent on the finding's
        content identity (``FindingReceiver`` uses ``dedup=True``): on the normal path a cheap bounded window;
        on the RECLAIM path an UNBOUNDED spine scan, so a reclaimed file whose ingest had already appended
        before a crash (no ``processed/`` marker yet) deduplicates to that earlier record rather than
        double-ingesting, no matter how many records the shared spine accumulated during the restart gap.
        ANY failure → ``rejected/``, nothing appended. Never raises on one bad file; never blocks on a hostile
        one."""
        reclaimed = self._reclaim_working()
        ingested, rejected, deduped, seqs = 0, 0, 0, []
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue  # a producer's in-flight temp; skip until it is atomically renamed in
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)   # atomic CLAIM: the file leaves incoming/ before we act on it
            except OSError:
                continue                    # gone / raced away — nothing to do
            try:
                text = self._read_regular(claimed)   # regular-file-only, bounded, UTF-8 → OSError on any breach
            except OSError as exc:
                self._quarantine(claimed, f"unreadable / not a bounded regular UTF-8 file: {exc}")
                rejected += 1
                continue
            # dedup identity is the sha256 of the ACTUAL bytes, not the producer's filename — a producer
            # cannot suppress a real finding by naming it after an already-processed marker.
            marker = self.processed / (hashlib.sha256(text.encode("utf-8")).hexdigest() + ".json")
            if marker.exists():
                # a byte-identical envelope already crossed onto the spine — do NOT re-append (idempotent)
                try:
                    os.replace(claimed, marker)   # archive the duplicate over its identical marker
                except OSError:
                    self._safe_unlink(claimed)
                deduped += 1
                continue
            try:
                seq = self._ingest_text(text, reclaim=src.name in reclaimed)
            except InertFindingError as exc:
                self._quarantine(claimed, f"rejected (fail-closed): {exc}")
                rejected += 1
                continue
            except Exception as exc:  # noqa: BLE001 — any unexpected error is still a refusal, never an append
                self._quarantine(claimed, f"rejected (unexpected {type(exc).__name__}): {exc}")
                rejected += 1
                continue
            # appended. Archive to the dedup marker. If this fails the record is already spined AND the file
            # is in working/ (NOT incoming/), so it is never re-drained → no double-ingest either way.
            try:
                os.replace(claimed, marker)
            except OSError:
                self._safe_unlink(claimed)
            ingested += 1
            seqs.append(seq)
        return {"ingested": ingested, "rejected": rejected, "deduped": deduped, "seqs": seqs}

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def watch(self, *, interval: float = 2.0, stop: Optional["object"] = None) -> None:
        """Drain in a loop until ``stop`` (a threading.Event) is set. Each round is a fresh ``drain()``
        (delegations are re-verified against the current clock, so an expired delegation stops admitting).

        A single bad drain NEVER kills the daemon: ``drain()`` already quarantines per-file failures, but an
        unexpected error OUTSIDE the per-file loop (e.g. a transient spine/IO fault) is caught here, reported
        to stderr, and the loop continues — so the results-delivery drain survives a blip rather than silently
        dying and stranding every subsequent finding in ``incoming/`` (mirrors the money drains' watch loop)."""
        while True:
            try:
                self.drain()
            except Exception as exc:  # noqa: BLE001 — the watch loop must survive any single-drain failure
                sys.stderr.write("vigil finding-drain: WARNING drain error (continuing): "
                                 f"{type(exc).__name__}: {exc}\n")
            if stop is not None and getattr(stop, "wait", None) is not None:
                if stop.wait(interval):
                    return
            else:
                time.sleep(interval)
