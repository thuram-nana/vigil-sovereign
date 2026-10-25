"""webhook_drain — the INBOUND webhook spool consumer: an inert envelope → an enqueued SecurityJob.

The forward of the offense→sovereign finding spool. It drains ``<spool>/incoming/*.json`` written by the
uiproxy GitHub webhook route (an INERT, HMAC-authenticated envelope — see ``uiproxy._webhooks_github``),
normalizes each to a :class:`SecurityJob`, and ENQUEUES it onto the durable idempotent
:class:`SecurityJobQueue`. It is ENQUEUE-ONLY: it never runs a job — execution is SOLELY
``jobs.runner.JobRunner.run_one``, behind the hard authorization gate. The queue is the one path; this is
one trigger adapter feeding it (mirrors ``sigil.inbound.spool_watcher`` / ``learn_drain`` on the way in).

Boundary + idempotency invariants (treat every spooled byte as hostile):
  * FATAL-2: installed in both venvs; ``framework.v2`` is imported LAZILY (``SecurityJobQueue`` defers it),
    so the module AND the class stay sovereign-importable. No ``sigil`` import. ``SecurityJob`` is pure
    stdlib, so importing the model at module scope pulls no engine.
  * FAIL-CLOSED: a non-bounded-regular-UTF-8 file, non-JSON, a wrong/absent schema, or a
    ``SecurityJob.normalize`` ValueError (e.g. a webhook envelope with no ``delivery_id``) → ``rejected/``
    with a ``.reason`` sidecar; NOTHING is enqueued.
  * TWO idempotency layers: the spool dedups on ``sha256`` of the file BYTES (reprocessing the same file);
    the queue dedups on ``delivery_id`` (a replayed webhook) and on the work ``fingerprint`` (same work in
    flight). A ``duplicate_delivery`` / ``duplicate_fingerprint`` enqueue result is TERMINAL — the queue has
    already coalesced it — so the file is archived, never looped.
  * A transient enqueue FAILURE (the durable insert raised) DEFERS the file back to ``incoming/`` to retry:
    ``enqueue`` rolls back its own markers, so the retry is clean; archiving a failed enqueue would silently
    DROP the job.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Optional

from .jobs.model import SecurityJob, work_delivery_id   # pure stdlib — importing the model pulls no framework

_MAX_BYTES = 256 * 1024                       # mirror the producer's envelope cap; a larger file is rejected unread
_WEBHOOK_SCHEMA = "vigil.webhook.github.v1"   # must match uiproxy._GH_WEBHOOK_ENVELOPE_SCHEMA


class WebhookSpoolDrain:
    """Drains an inbound webhook spool, normalizing each inert envelope into an enqueued SecurityJob."""

    def __init__(self, *, spool_dir: "str | os.PathLike", queue_root: "str | os.PathLike | None" = None,
                 queue: Any = None) -> None:
        if queue is None and queue_root is None:
            raise ValueError("WebhookSpoolDrain needs a queue (injected) or a queue_root to build one")
        self._q = queue                        # an injected SecurityJobQueue (tests), else built lazily
        self._queue_root = queue_root
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"
        self.processed = self.spool / "processed"    # dedup ledger: <sha256> present ⇒ already enqueued/coalesced
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    def _queue(self) -> Any:
        """The SecurityJobQueue, built LAZILY so the module/class stay sovereign-importable (the queue's
        framework import is deferred to construction, which only happens in the offense/integration run)."""
        if self._q is None:
            from .jobs.queue import SecurityJobQueue   # lazy (two-env: framework deferred inside the queue)
            self._q = SecurityJobQueue(self._queue_root)
        return self._q

    @staticmethod
    def _read_regular(path: Path) -> str:
        """Read a REGULAR file without following a symlink or blocking on a FIFO, decode UTF-8. A hostile
        producer that plants a symlink / named pipe / device / non-UTF-8 / oversized blob must never hang or
        crash the drain — every such case is normalised to OSError so the caller quarantines it."""
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
    def _safe_unlink(path: Path) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _archive(self, claimed: Path, marker: Path) -> None:
        """Move a TERMINAL file to its dedup marker (so it is never reprocessed); unlink if the move fails."""
        try:
            os.replace(claimed, marker)
        except OSError:
            self._safe_unlink(claimed)

    def _reclaim_working(self) -> None:
        """Crash recovery: move any file stranded in ``working/`` (a claim interrupted before it was
        archived / deferred / quarantined) back to ``incoming/`` so it is reprocessed. The downstream dedup
        (spool sha256 + the queue's permanent delivery_id) makes a re-process idempotent, so this can never
        double-enqueue a completed delivery."""
        try:
            stale = list(self.working.glob("*.json"))
        except OSError:
            return
        for f in stale:
            try:
                os.replace(f, self.incoming / f.name)
            except OSError:
                self._safe_unlink(f)

    def drain(self) -> dict:
        """Process every file in ``incoming/`` once. Returns
        ``{enqueued, duplicate, rejected, deduped, deferred}``. ENQUEUE-ONLY — never runs a job. Begins with
        a crash-recovery sweep of ``working/`` (a claim interrupted mid-process is re-queued, never lost)."""
        enqueued = duplicate = rejected = deduped = deferred = 0
        self._reclaim_working()
        queue = self._queue()   # built once; surfaces a misconfig (e.g. framework unavailable) BEFORE claiming a file
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)                 # atomic CLAIM out of incoming/
            except OSError:
                continue
            try:
                text = self._read_regular(claimed)
            except OSError as exc:
                self._quarantine(claimed, f"unreadable / not a bounded regular UTF-8 file: {exc}")
                rejected += 1
                continue
            marker = self.processed / (hashlib.sha256(text.encode("utf-8")).hexdigest() + ".json")
            if marker.exists():                          # spool-level idempotency: identical bytes seen before
                self._archive(claimed, marker)
                deduped += 1
                continue
            try:
                env = json.loads(text)
            except Exception as exc:  # noqa: BLE001 — hostile body (non-JSON, deeply-nested → RecursionError, …) quarantined, never a loop crash
                self._quarantine(claimed, f"not parseable JSON: {type(exc).__name__}: {exc}")
                rejected += 1
                continue
            if not isinstance(env, dict) or env.get("schema") != _WEBHOOK_SCHEMA:
                self._quarantine(claimed, f"not a {_WEBHOOK_SCHEMA} envelope")
                rejected += 1
                continue
            # Strict envelope contract: a real webhook delivery always carries the provider GUID (the ingress
            # requires X-GitHub-Delivery). The QUEUE key is content-addressed below, but a missing GUID means
            # a malformed envelope → quarantine (fail-closed), not a silently-keyed job.
            if not str(env.get("delivery_id") or "").strip():
                self._quarantine(claimed, "webhook envelope missing github delivery id")
                rejected += 1
                continue
            try:
                repo = str(env.get("repo") or "")
                commit = str(env.get("commit") or "")
                pr_number = env.get("pr_number")
                job = SecurityJob.normalize(
                    source="webhook", repo=repo, commit=commit, pr_number=pr_number,
                    # content-addressed on (repo,pr,commit) so a webhook and the reconciliation poller SHARE
                    # the exactly-once key (cross-path dedup); the provider GUID is kept in extra for audit.
                    delivery_id=work_delivery_id(repo, pr_number, commit),
                    tenant_id=str(env.get("tenant_id") or ""),
                    extra={"event": str(env.get("event") or "")[:512],
                           "github_delivery": str(env.get("delivery_id") or "")[:512]})
            except (ValueError, TypeError, OverflowError) as exc:   # empty delivery_id, or a non-finite pr_number, …
                self._quarantine(claimed, f"not a valid SecurityJob (fail-closed): {exc}")
                rejected += 1
                continue
            try:
                res = queue.enqueue(job)
            except OSError:   # the transient durable-insert class (the queue rolls back its own markers) — DEFER + retry
                try:
                    os.replace(claimed, self.incoming / src.name)   # un-claim → retry next drain
                except OSError:
                    pass
                deferred += 1
                continue
            # enqueued OR duplicate_delivery/duplicate_fingerprint are all TERMINAL — the queue coalesced it.
            self._archive(claimed, marker)
            if getattr(res, "enqueued", False):
                enqueued += 1
            else:
                duplicate += 1
        return {"enqueued": enqueued, "duplicate": duplicate, "rejected": rejected,
                "deduped": deduped, "deferred": deferred}

    def watch(self, *, interval: float = 2.0, sleep: Optional[Callable[[float], None]] = None) -> None:
        """Drain in a loop forever (Ctrl-C / SIGTERM to stop). A single bad drain NEVER kills the daemon: an
        unexpected error is reported to stderr and the loop continues. ``sleep`` is injectable for tests."""
        import sys as _sys
        import time
        _sleep = sleep or time.sleep
        while True:
            try:
                self.drain()
            except Exception as exc:  # noqa: BLE001 — the watch loop must survive any single-drain failure
                _sys.stderr.write("vigil webhook-drain: WARNING drain error (continuing): "
                                  f"{type(exc).__name__}: {exc}\n")
            _sleep(interval)
