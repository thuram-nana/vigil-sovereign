"""redpen_webhook_drain — the Red-Pen inbound-webhook spool consumer: an inert envelope → an enqueued SecurityJob.

The Red-Pen sibling of :mod:`webhook_drain`. It drains ``<redpen-spool>/incoming/*.json`` — the inert, HMAC-
authenticated envelopes the uiproxy writes for the customer-facing GitHub App's webhook (``/webhooks/github-app``,
mounted only when ``VIGIL_REDPEN_ENABLED`` is on; schema ``vigil.webhook.github.redpen.v1``; see
``uiproxy._webhooks_github_redpen``) — normalizes each REVIEWABLE pull-request event into a :class:`SecurityJob`
(``profile="redpen"``) and ENQUEUES it onto the durable idempotent :class:`SecurityJobQueue`. It is ENQUEUE-ONLY: it
never runs a job — execution is SOLELY ``jobs.runner.JobRunner.run_one`` (the ``vigil redpen-review`` drain), behind
the hard authorization gate.

Why a SEPARATE spool + queue from the repo-connect ``webhook_drain``: the two consumers run DIFFERENT workers, so
they must never claim one another's events. The App route writes its own schema into its own ``<spool>/redpen``
subtree (the repo-connect ``/webhooks/github`` route and its ``<spool>/incoming`` are untouched in every flag state);
this drain reads only that subtree and enqueues onto the Red-Pen queue the Red-Pen review runner drains. With the
master flag OFF the App route is not mounted (404) and writes nothing here, so this drain has nothing to do — the
Red-Pen path is byte-identically absent.

Event handling (decision O-2/O-3, HANDOFF §12):
  * ``kind="pr"`` with a REVIEWABLE action (``opened`` / ``synchronize`` / ``reopened``) → a ``SecurityJob`` whose
    ``commit`` is the PR HEAD sha (the "VIGIL Red-Pen" check run is written at that sha) — ENQUEUED.
  * ``kind="pr"`` with any other action (``closed`` / ``labeled`` / …) → acknowledged, NOT enqueued (nothing to
    review).
  * ``kind="installation"`` (connect/disconnect sync) → acknowledged as a SYNC signal, NOT enqueued: a CONNECT is
    owner-signed SOVEREIGN-side (the connected-repo registry holds the authorization of record, decision O-3), which
    the keyless offense plane cannot mint — the sovereign reconciliation of these signals is a documented follow-on.

Idempotency + fail-closed (treat every spooled byte as hostile), identical to ``webhook_drain``:
  * FATAL-2: ``framework`` is imported LAZILY (``SecurityJobQueue`` defers it); no ``sigil`` import; ``SecurityJob``
    is pure stdlib, so importing the model pulls no engine.
  * TWO idempotency layers: the spool dedups on ``sha256`` of the file BYTES; the queue dedups on ``delivery_id``
    (content-addressed over ``(repo, pr, commit)``) and the work ``fingerprint``. A ``duplicate_*`` enqueue is
    TERMINAL — the file is archived, never looped.
  * A non-bounded-regular-UTF-8 file, non-JSON, a wrong schema, or a ``SecurityJob.normalize`` ValueError →
    ``rejected/`` with a ``.reason`` sidecar; NOTHING is enqueued. A transient enqueue OSError DEFERS the file to
    retry (never a silent drop).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Optional

from .jobs.model import SecurityJob, work_delivery_id   # pure stdlib — importing the model pulls no framework

_MAX_BYTES = 256 * 1024                            # mirror the producer's envelope cap; a larger file is rejected unread
_REDPEN_SCHEMA = "vigil.webhook.github.redpen.v1"   # must match uiproxy._GH_WEBHOOK_REDPEN_ENVELOPE_SCHEMA
#: The pull-request actions that trigger a Red-Pen review (a new PR or a push to its head). Any other PR action
#: (closed / labeled / assigned / …) is acknowledged but not reviewed.
REVIEWABLE_PR_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


class RedpenWebhookDrain:
    """Drains the Red-Pen inbound-webhook spool, normalizing each REVIEWABLE PR envelope into an enqueued job."""

    def __init__(self, *, spool_dir: "str | os.PathLike", queue_root: "str | os.PathLike | None" = None,
                 queue: Any = None) -> None:
        if queue is None and queue_root is None:
            raise ValueError("RedpenWebhookDrain needs a queue (injected) or a queue_root to build one")
        self._q = queue                        # an injected SecurityJobQueue (tests), else built lazily
        self._queue_root = queue_root
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"
        self.processed = self.spool / "processed"    # dedup ledger: <sha256> present ⇒ already handled
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    def _queue(self) -> Any:
        if self._q is None:
            from .jobs.queue import SecurityJobQueue   # lazy (two-env: framework deferred inside the queue)
            self._q = SecurityJobQueue(self._queue_root)
        return self._q

    @staticmethod
    def _read_regular(path: Path) -> str:
        """Read a REGULAR file without following a symlink or blocking on a FIFO, decode UTF-8 — a hostile
        producer that plants a symlink / named pipe / device / non-UTF-8 / oversized blob is normalised to
        OSError so the caller quarantines it (never a hang / crash)."""
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
        """Crash recovery: move any file stranded in ``working/`` back to ``incoming/``. The downstream dedup
        (spool sha256 + the queue's permanent delivery_id) makes a re-process idempotent."""
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
        ``{enqueued, duplicate, rejected, deduped, deferred, acknowledged}``. ENQUEUE-ONLY — never runs a job.
        ``acknowledged`` counts the non-review envelopes (a non-reviewable PR action, or an installation sync
        signal) that are handled + archived WITHOUT enqueueing a review."""
        enqueued = duplicate = rejected = deduped = deferred = acknowledged = 0
        self._reclaim_working()
        queue = self._queue()   # built once; surfaces a misconfig BEFORE claiming a file
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
            except Exception as exc:  # noqa: BLE001 — hostile body quarantined, never a loop crash
                self._quarantine(claimed, f"not parseable JSON: {type(exc).__name__}: {exc}")
                rejected += 1
                continue
            if not isinstance(env, dict) or env.get("schema") != _REDPEN_SCHEMA:
                self._quarantine(claimed, f"not a {_REDPEN_SCHEMA} envelope")
                rejected += 1
                continue
            if not str(env.get("delivery_id") or "").strip():
                self._quarantine(claimed, "webhook envelope missing github delivery id")
                rejected += 1
                continue
            # kind="installation" (connect/disconnect sync) and any non-reviewable PR action are acknowledged —
            # handled + archived, NEVER enqueued as a review. A CONNECT is owner-signed sovereign-side (the
            # connected-repo registry is the authorization of record, O-3), which this keyless plane cannot mint.
            kind = str(env.get("kind") or "")
            action = str(env.get("action") or "").strip().lower()
            if kind != "pr" or action not in REVIEWABLE_PR_ACTIONS:
                self._archive(claimed, marker)
                acknowledged += 1
                continue
            try:
                repo = str(env.get("repo") or "")
                commit = str(env.get("commit") or "")
                pr_number = env.get("pr_number")
                job = SecurityJob.normalize(
                    source="webhook", repo=repo, commit=commit, pr_number=pr_number, profile="redpen",
                    # content-addressed on (repo,pr,commit) — a webhook + the reconciliation poller SHARE the
                    # exactly-once key; the provider GUID is kept in extra for audit.
                    delivery_id=work_delivery_id(repo, pr_number, commit),
                    tenant_id=str(env.get("tenant_id") or ""),
                    extra={"event": str(env.get("event") or "")[:512], "action": action,
                           "github_delivery": str(env.get("delivery_id") or "")[:512]})
            except (ValueError, TypeError, OverflowError) as exc:
                self._quarantine(claimed, f"not a valid SecurityJob (fail-closed): {exc}")
                rejected += 1
                continue
            try:
                res = queue.enqueue(job)
            except OSError:   # transient durable-insert class (queue rolls back its markers) — DEFER + retry
                try:
                    os.replace(claimed, self.incoming / src.name)
                except OSError:
                    pass
                deferred += 1
                continue
            self._archive(claimed, marker)
            if getattr(res, "enqueued", False):
                enqueued += 1
            else:
                duplicate += 1
        return {"enqueued": enqueued, "duplicate": duplicate, "rejected": rejected, "deduped": deduped,
                "deferred": deferred, "acknowledged": acknowledged}

    def watch(self, *, interval: float = 2.0, sleep: Optional[Callable[[float], None]] = None) -> None:
        """Drain in a loop forever. A single bad drain NEVER kills the daemon: an unexpected error is reported to
        stderr and the loop continues. ``sleep`` is injectable for tests."""
        import sys as _sys
        import time
        _sleep = sleep or time.sleep
        while True:
            try:
                self.drain()
            except Exception as exc:  # noqa: BLE001 — the watch loop must survive any single-drain failure
                _sys.stderr.write("vigil redpen-webhook-drain: WARNING drain error (continuing): "
                                  f"{type(exc).__name__}: {exc}\n")
            _sleep(interval)
