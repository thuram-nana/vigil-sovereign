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

import json
import os
import time
from pathlib import Path
from typing import Callable, Optional

from vigil_integration.inert_finding import InertFindingError

from ..spine.store import SpineStore
from .finding_receiver import FindingReceiver

_MAX_BYTES = 256 * 1024  # mirror the validator's envelope cap; a larger file is rejected unread


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
        self.processed = self.spool / "processed"
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    # -- ingest one file (fail-closed) -------------------------------------------------------------
    def _ingest_text(self, text: str) -> int:
        """Route by kind to an owner-delegated receiver and ingest. Raises InertFindingError on any
        refusal (nothing is written). A missing delegation for the file's kind is itself a refusal."""
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
            return recv.ingest_detection(text)
        # a finding (or anything without kind=="detection") goes through the governance path
        if self.governance_delegation is None:
            raise InertFindingError("no offense-governance delegation configured — refusing findings")
        recv = FindingReceiver.from_delegation(
            self.store, owner_pubkey=self.owner_pubkey, delegation=self.governance_delegation,
            now=now, scope=self.scope)
        return recv.ingest(text)

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

    def drain(self) -> dict:
        """Process every file currently in ``incoming/`` once. Returns {ingested, rejected, seqs}.
        A file too large to be a valid envelope is rejected unread; a valid one is ingested + moved to
        ``processed/``; any failure quarantines it in ``rejected/``. Never raises on one bad file."""
        ingested, rejected, seqs = 0, 0, []
        for path in sorted(self.incoming.glob("*.json")):
            if path.name.startswith(".tmp-"):
                continue  # a producer's in-flight temp; skip until it is atomically renamed in
            try:
                if path.stat().st_size > _MAX_BYTES:
                    self._quarantine(path, f"file exceeds {_MAX_BYTES} bytes (rejected unread)")
                    rejected += 1
                    continue
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                self._quarantine(path, f"unreadable: {exc}")
                rejected += 1
                continue
            try:
                seq = self._ingest_text(text)
            except InertFindingError as exc:
                self._quarantine(path, f"rejected (fail-closed): {exc}")
                rejected += 1
                continue
            except Exception as exc:  # noqa: BLE001 — any unexpected error is still a refusal, never an append
                self._quarantine(path, f"rejected (unexpected {type(exc).__name__}): {exc}")
                rejected += 1
                continue
            try:
                os.replace(path, self.processed / path.name)
            except OSError:
                pass  # the record is already spined; a move failure must not double-ingest — leave it, next
            ingested += 1
            seqs.append(seq)
        return {"ingested": ingested, "rejected": rejected, "seqs": seqs}

    def watch(self, *, interval: float = 2.0, stop: Optional["object"] = None) -> None:
        """Drain in a loop until ``stop`` (a threading.Event) is set. Each round is a fresh ``drain()``
        (delegations are re-verified against the current clock, so an expired delegation stops admitting)."""
        while True:
            self.drain()
            if stop is not None and getattr(stop, "wait", None) is not None:
                if stop.wait(interval):
                    return
            else:
                time.sleep(interval)
