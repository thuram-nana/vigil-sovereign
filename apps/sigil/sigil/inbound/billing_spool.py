"""billing_spool — the SOVEREIGN-side drain of the inbound BILLING-WEBHOOK inert seam (SaaS Slice C).

The stdlib ``vigil up`` proxy (``vigil_integration.uiproxy``) receives ``POST /webhooks/billing``, authenticates
the Flutterwave ``verif-hash`` header (constant-time, an anti-flood pre-filter), and writes ONE inert
``vigil.webhook.billing.v1`` envelope — ``{schema, body_b64}`` — to ``<spool>/incoming/``. It NEVER mints,
forwards, or spawns, and it stores only the RAW webhook body: NEVER the ``verif-hash`` value, which equals the
secret. This module drains that spool: for each envelope it base64-decodes the body and runs it through
``BillingSigner.ingest``, which does the ``verif-hash`` compare + the MANDATORY server-side transaction
re-verify + the owner-signed mint. The RE-VERIFY is the authoritative gate — a forged / replayed / unverifiable
body mints nothing — so this seam is fail-closed by construction even though the body arrived unauthenticated at
rest.

The ``sig_header`` passed to ``ingest`` is the webhook secret (resolved OFF-SPINE from the env, the SAME value the
proxy validated the inbound header against). The proxy already authenticated the inbound ``verif-hash``; supplying
the secret here simply lets ``ingest`` run its single verify->mint path, whose real authority is the re-verify.
The secret stays in the env on the sovereign host and is NEVER written to the spool.

BOUNDARY INVARIANTS (mirror ``inbound/spool_watcher.py`` — treat every byte as hostile):
  * SOVEREIGN-only: imports NO ``framework`` / ``strix`` (``assert_no_offense`` at import); the mint is the
    injected ``BillingSigner``'s, under the owner key it holds.
  * FAIL-CLOSED: any validation / decode / ingest failure moves the file to ``rejected/`` with a ``.reason``
    sidecar and appends NOTHING. A well-formed body that ``ingest`` maps to a NO-OP (unverified, or an unknown
    catalog price) is NOT an error — it is archived without spining (nothing was minted).
  * IDEMPOTENT twice over: content-addressed spool dedup (``processed/<sha256>``) AND ``BillingSigner.ingest``'s
    own ``event_id`` idempotency — a duplicate Flutterwave delivery credits exactly once.
  * HOSTILE-FILE-HARDENED: ``O_NOFOLLOW`` + ``O_NONBLOCK`` + ``S_ISREG`` + size cap + UTF-8 decode, so a planted
    symlink / FIFO / device / oversized / non-UTF-8 blob is quarantined, never followed, and never hangs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor.billing import BillingSigner  # noqa: E402  (the EVIDENCE->owner-signed-FACT boundary this feeds)

_MAX_BYTES = 256 * 1024                     # mirror the proxy's envelope cap; a larger file is rejected unread
_ENVELOPE_SCHEMA = "vigil.webhook.billing.v1"
_MAX_DECODED_BODY = 192 * 1024              # decoded-body cap: the proxy caps the raw body at 128K, whose base64
#                                             envelope stays under the 256K read cap above; 192K is the ceiling a
#                                             256K envelope can decode to (defense-in-depth, fail-closed).


class BillingSpoolError(RuntimeError):
    """A fail-closed refusal while draining one billing-webhook envelope (nothing was spined)."""


class BillingSpoolWatcher:
    """Drains an inbound billing-webhook spool through ``BillingSigner.ingest`` onto the owner-signed spine,
    fail-closed. Construction mirrors ``inbound.spool_watcher.SpoolWatcher`` (same on-disk claim/dedup/quarantine
    contract and the same hostile-file hardening)."""

    def __init__(self, signer: BillingSigner, *, spool_dir: str | os.PathLike, verif_hash: str,
                 now_fn: Callable[[], float] = time.time) -> None:
        if not isinstance(signer, BillingSigner):
            raise ValueError("a BillingSigner is required — the drain never mints on its own")
        if not isinstance(verif_hash, str) or not verif_hash:
            raise ValueError("verif_hash (the off-spine webhook secret) is required — fail-closed without it")
        self.signer = signer
        self.verif_hash = verif_hash
        self._now = now_fn
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"       # a file is CLAIMED here (out of incoming) before ingest
        self.processed = self.spool / "processed"   # doubles as the dedup ledger: <sha256> present ⇒ handled
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    # -- ingest one envelope (fail-closed) ---------------------------------------------------------
    def _ingest_text(self, text: str) -> Optional[int]:
        """Parse one inert billing envelope, decode the raw body, and run it through the signer. Returns the
        appended spine seq, or None when the signer mints nothing (unverified / unknown price / no-op — NOT an
        error). Raises BillingSpoolError on a malformed envelope (a refusal; nothing is spined)."""
        try:
            obj = json.loads(text)
        except ValueError as exc:
            raise BillingSpoolError(f"not valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise BillingSpoolError("envelope is not a JSON object")
        if obj.get("schema") != _ENVELOPE_SCHEMA:
            raise BillingSpoolError(f"unexpected envelope schema {obj.get('schema')!r}")
        body_b64 = obj.get("body_b64")
        if not isinstance(body_b64, str):
            raise BillingSpoolError("envelope missing body_b64")
        try:
            raw = base64.b64decode(body_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BillingSpoolError(f"body_b64 is not valid base64: {exc}") from exc
        if len(raw) > _MAX_DECODED_BODY:
            raise BillingSpoolError("decoded webhook body exceeds the size cap")
        # The authoritative verify->mint path. ingest does the verif-hash compare (vs the injected secret) +
        # the MANDATORY server-side re-verify + the owner-signed mint, and is itself idempotent by event_id.
        # None ⇒ the webhook did not re-verify / carried no catalog entitlement ⇒ nothing minted (safe no-op).
        return self.signer.ingest(raw, self.verif_hash, now=float(self._now()))

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
        """Read a REGULAR file without following a symlink or blocking on a FIFO, decoded UTF-8. Mirrors
        ``SpoolWatcher._read_regular``: O_NOFOLLOW rejects a symlink at open, O_NONBLOCK returns instead of
        blocking on a writer-less FIFO, S_ISREG + the size cap reject anything but a bounded regular file, and a
        non-UTF-8 decode is normalised to OSError — so the caller's single ``except OSError`` quarantines every
        hostile-file case and ``drain()`` never hangs or crashes on one bad file."""
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
        except UnicodeDecodeError as exc:
            raise OSError(f"not valid UTF-8: {exc}") from exc

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def drain(self) -> dict:
        """Process every file currently in ``incoming/`` once. Returns {minted, noop, rejected, deduped, seqs}.

        For each file: CLAIM it (atomic rename into ``working/``) BEFORE acting, so a failed archive or a re-run
        can never re-read it from ``incoming/`` and double-process. Read it as a bounded regular UTF-8 file, then
        dedup on the sha256 of the READ BYTES (not the producer filename). A byte-identical envelope already
        handled (``processed/<sha256>`` exists) is archived WITHOUT re-ingesting. Otherwise run the signer; a
        mint (seq) or a safe no-op (None) both archive to ``processed/`` (handled). ANY failure ⇒ ``rejected/``,
        nothing appended. Never raises on one bad file; never blocks on a hostile one."""
        minted, noop, rejected, deduped, seqs = 0, 0, 0, 0, []
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue                                 # a producer's in-flight temp; skip until renamed in
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)                 # atomic CLAIM: leaves incoming/ before we act
            except OSError:
                continue                                 # gone / raced away
            try:
                text = self._read_regular(claimed)
            except OSError as exc:
                self._quarantine(claimed, f"unreadable / not a bounded regular UTF-8 file: {exc}")
                rejected += 1
                continue
            marker = self.processed / (hashlib.sha256(text.encode("utf-8")).hexdigest() + ".json")
            if marker.exists():
                try:
                    os.replace(claimed, marker)          # archive the duplicate over its identical marker
                except OSError:
                    self._safe_unlink(claimed)
                deduped += 1
                continue
            try:
                seq = self._ingest_text(text)
            except BillingSpoolError as exc:
                self._quarantine(claimed, f"rejected (fail-closed): {exc}")
                rejected += 1
                continue
            except Exception as exc:  # noqa: BLE001 — any unexpected error is still a refusal, never an append
                self._quarantine(claimed, f"rejected (unexpected {type(exc).__name__}): {exc}")
                rejected += 1
                continue
            # handled (minted or a safe no-op). Archive to the dedup marker. If the archive fails the record is
            # already spined (if it minted) AND the file is in working/ (NOT incoming/), so it is never
            # re-drained -> no double-ingest either way.
            try:
                os.replace(claimed, marker)
            except OSError:
                self._safe_unlink(claimed)
            if seq is None:
                noop += 1
            else:
                minted += 1
                seqs.append(seq)
        return {"minted": minted, "noop": noop, "rejected": rejected, "deduped": deduped, "seqs": seqs}

    def watch(self, *, interval: float = 2.0, stop: Optional["object"] = None) -> None:
        """Drain in a loop until ``stop`` (a threading.Event) is set."""
        while True:
            self.drain()
            waiter = getattr(stop, "wait", None)
            if stop is not None and waiter is not None:
                if waiter(interval):
                    return
            else:
                time.sleep(interval)
