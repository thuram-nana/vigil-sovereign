"""reconciliation — the SAFETY-NET trigger adapter for the SecurityJob spine (repo-connect Slice 2b).

A deliberately SLOW periodic poller (NOT fast polling). Per connected repo it loads a resume checkpoint,
lists the PRs changed since that checkpoint (via an injected git-host lister — the real ``api.github.com``
client is Slice 3; v1 defaults to an inert empty lister), normalizes each changed PR to a
:class:`SecurityJob` (``source='reconciliation'``) and ENQUEUES it, then advances the checkpoint AFTER the
batch is durably enqueued (durable-BEFORE-cursor). It recovers deliveries a webhook missed — its whole
purpose — without ever being the primary path. ENQUEUE-ONLY: execution stays with the authorized runner.

Invariants:
  * FATAL-2 / pure stdlib at module scope: ``SecurityJob`` (the model) is pure stdlib and the queue's
    framework import is deferred (lazy/injected), so this module + its classes stay sovereign-importable.
    No ``sigil`` import.
  * Idempotent + re-scan-safe: the per-repo checkpoint is the PRIMARY dedup (a completed PR-head is
    suppressed by the advanced cursor), with a STABLE ``delivery_id`` as the queue-level backstop (a replay
    coalesces permanently in the delivery seen-set). Enqueue is durable-BEFORE-cursor, so a crash only
    re-enqueues (coalesced), never drops; a row that was NOT durably enqueued never advances the cursor
    past itself.
  * Fail-open per repo (and per row): a repo whose lister raises is skipped THIS cycle; a single malformed
    PR row is counted + dropped (never crashes the cycle or starves the repo's other PRs).

KNOWN, ACCEPTED PROPERTIES (documented so they are not silent surprises):
  * COMMIT-SCOPED scan dedup. The work fingerprint is ``(tenant, repo, commit, profile, policy)`` — it
    excludes ``pr_number`` by design, so two distinct PRs at the SAME head commit COALESCE to one scan
    (the code is identical — scanning it twice is waste). The PR-bot worker (Slice 3) is responsible for
    FANNING a single commit-scan's result out to every PR that points at that head; the scan layer stays
    commit-scoped on purpose.
  * CROSS-PATH dedup is a Slice-3 prerequisite. Today a webhook job's ``delivery_id`` is its provider GUID
    while a reconciliation job's is content-addressed, so once Slice 3 wires a REAL lister, a webhook-
    completed commit could be re-listed + re-scanned by reconciliation. v1 uses the inert
    :func:`empty_lister` (produces nothing), so this is LATENT; Slice 3 MUST unify the two paths on a
    shared content-addressed work key (or fan-out) when it adds the git-host lister. See the program memo.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .model import SecurityJob          # pure stdlib — importing the model pulls no framework

_CURSOR_VERSION = 1
_MAX_CURSOR_BYTES = 64 * 1024           # a checkpoint file is tiny; a larger (planted) file is ignored


def _safe_slug(slug: str) -> str:
    """A single safe filename component for a checkpoint file (mirrors vulnfeed's cursor-name sanitization)."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(slug or "ephemeral"))[:80]


@dataclass(frozen=True)
class ChangedPR:
    """One changed PR a lister reports: the PR number, its head commit SHA, and an opaque per-PR cursor
    token (e.g. the PR's ``updated_at``) the poller advances the repo checkpoint past once the PR is
    durably enqueued (or coalesced, or dropped as unprocessable)."""

    pr_number: int
    head_sha: str
    cursor: str = ""


#: A git-host lister: given ``(repo, since_cursor)`` return ``(changed PRs, the new high-water cursor)``.
#: The real ``api.github.com`` client is Slice 3; v1 uses :func:`empty_lister`, so reconciliation is WIRED
#: and testable but produces nothing until a real lister is injected.
RepoLister = Callable[[str, str], "tuple[list[ChangedPR], str]"]


def empty_lister(repo: str, since_cursor: str) -> "tuple[list[ChangedPR], str]":
    """The default inert lister — no git-host client yet (Slice 3). Reports no change, holds the cursor."""
    return [], since_cursor


def _recon_delivery_id(repo: str, pr_number: Any, head_sha: str) -> str:
    """A STABLE, INJECTIVE exactly-once key per ``(repo, pr, head)``: a re-list of the same PR-head
    coalesces permanently at the queue's delivery seen-set (the checkpoint is the primary dedup; this is the
    backstop that also closes the window after a completion clears the work fingerprint). The components are
    JSON-encoded (not ``|``-joined), so no field value can be mistaken for the delimiter and collide."""
    canon = json.dumps([str(repo), pr_number, str(head_sha)], separators=(",", ":"), default=str)
    return "recon-" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:24]


def _job_for(repo: str, pr: ChangedPR) -> SecurityJob:
    """Normalize one changed PR into a reconciliation SecurityJob (the authoritative validator — a bad row
    raises, which the caller DROPS + counts)."""
    return SecurityJob.normalize(
        source="reconciliation", repo=repo, pr_number=pr.pr_number,
        commit=str(pr.head_sha or ""),
        delivery_id=_recon_delivery_id(repo, pr.pr_number, str(pr.head_sha or "")))


class ReconciliationCheckpoints:
    """Per-repo resume cursors under ``<root>/reconciliation_cursors/<slug>.json`` — the vulnfeed cursor
    pattern: atomic temp + ``os.replace``, 0700 dir / 0600 file, FAIL-OPEN (a read/write failure degrades
    to a full re-list, never raises). Keyed by the canonical SecurityJob slug (one per repo)."""

    def __init__(self, root: "str | os.PathLike") -> None:
        self.dir = Path(root) / "reconciliation_cursors"

    def load(self, slug: str) -> str:
        p = self.dir / f"{_safe_slug(slug)}.json"
        try:
            text = self._read_regular(p)
            data = json.loads(text)
            if not isinstance(data, dict):
                return ""
            c = data.get("cursor", "")
            return c if isinstance(c, str) else ""       # a non-str cursor degrades to "" (full re-list)
        except (OSError, ValueError):                    # missing / torn / symlink / oversized / non-JSON ⇒ fail-open
            return ""

    @staticmethod
    def _read_regular(path: Path) -> str:
        """Read a REGULAR checkpoint file without following a symlink or blocking on a FIFO (a planted
        symlink to /dev/zero or a pipe must never hang/OOM the poller), bounded + UTF-8."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file")
            if st.st_size > _MAX_CURSOR_BYTES:
                raise OSError("cursor file too large")
            data = os.read(fd, _MAX_CURSOR_BYTES)
        finally:
            os.close(fd)
        return data.decode("utf-8")

    def advance(self, slug: str, repo: str, cursor: Any) -> None:
        tmp = None
        try:
            cursor_s = cursor if isinstance(cursor, str) else ""   # never persist the literal "None"/non-str
            payload = json.dumps({"version": _CURSOR_VERSION, "slug": slug, "repo": repo,
                                  "cursor": cursor_s}, sort_keys=True, separators=(",", ":"))
            self.dir.mkdir(parents=True, exist_ok=True)
            try:
                self.dir.chmod(0o700)
            except OSError:
                pass
            p = self.dir / f"{_safe_slug(slug)}.json"
            tmp = p.with_name(p.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, p)                           # atomic swap → no torn cursor on crash
        except Exception:  # noqa: BLE001 — fail-open: a persist failure just re-lists next cycle
            try:
                if tmp is not None and Path(tmp).exists():
                    Path(tmp).unlink()
            except OSError:
                pass


@dataclass
class ReconciliationTrigger:
    """A :class:`TriggerSource` that PRODUCES reconciliation SecurityJobs (never runs them). ``poll()`` lists
    every connected repo's changed PRs via the injected lister and normalizes them — the generic
    produce-jobs interface (for the ``drain(sources)`` fan-in). It does NOT advance checkpoints; the
    stateful safety-net driver :func:`reconcile_once` owns enqueue + durable-before-cursor advancement."""

    repos: "list[str]"
    lister: RepoLister = empty_lister

    def poll(self) -> "list[SecurityJob]":
        out: list[SecurityJob] = []
        for repo in self.repos:
            try:
                prs, _new = self.lister(repo, "")
                for pr in prs:
                    try:
                        out.append(_job_for(repo, pr))
                    except Exception:  # noqa: BLE001 — a malformed row is dropped, never crashes poll()
                        continue
            except Exception:  # noqa: BLE001 — a flaky lister for one repo must not blank out the others via drain()
                continue
        return out


def reconcile_once(*, repos: "list[str]", lister: RepoLister,
                   checkpoints: ReconciliationCheckpoints, queue: Any) -> dict:
    """One safety-net cycle. Per repo: load the checkpoint, list PRs changed since it, enqueue each, and
    advance the checkpoint. Durable-BEFORE-cursor + per-row safe:
      * a row that fails validation is DROPPED + counted (``dropped``) and the cursor advances PAST it (a
        deterministic normalize failure will never succeed, so re-listing it forever would wedge the repo);
      * a durable ENQUEUE failure STOPS the cursor at the last cleanly-processed PR (``failed``, ``stalled``)
        so the failed row + the rest re-list next cycle (coalescing the ones already enqueued);
      * a clean batch advances to the lister's batch high-water cursor.
    Fail-open per repo. Returns ``{enqueued, duplicate, dropped, skipped, failed}``. ENQUEUE-ONLY."""
    enqueued = duplicate = dropped = skipped = failed = 0
    for repo in repos:
        try:
            slug = SecurityJob(repo=repo).slug
            cursor = checkpoints.load(slug)
            prs, new_cursor = lister(repo, cursor)
            advance_to = cursor            # how far we can SAFELY advance (last cleanly-processed point)
            stalled = False                # a durable enqueue failure stops cursor advancement
            for pr in prs:
                try:
                    job = _job_for(repo, pr)
                except Exception:  # noqa: BLE001 — a malformed/odd row (ValueError/TypeError/OverflowError/…) is dropped
                    dropped += 1
                    advance_to = getattr(pr, "cursor", "") or advance_to    # skip PAST an unprocessable row
                    continue
                try:
                    res = queue.enqueue(job)
                except Exception:  # noqa: BLE001 — a durable-insert failure: hold the cursor, re-list next cycle
                    failed += 1
                    stalled = True
                    break
                if getattr(res, "enqueued", False):
                    enqueued += 1
                else:
                    duplicate += 1
                advance_to = getattr(pr, "cursor", "") or advance_to
            # advance to the batch high-water only if nothing stalled; else to the last cleanly-processed PR
            checkpoints.advance(slug, repo, new_cursor if not stalled else advance_to)
        except Exception:  # noqa: BLE001 — fail-open per repo: a flaky lister / odd repo is skipped this cycle
            skipped += 1
            continue
    return {"enqueued": enqueued, "duplicate": duplicate, "dropped": dropped,
            "skipped": skipped, "failed": failed}


@dataclass
class Reconciler:
    """The ``vigil reconcile`` entrypoint: holds the connected repos, the lister, the per-repo checkpoints,
    and the (lazily-built) SecurityJob queue. ``once()`` runs one cycle; ``watch()`` loops on a deliberately
    slow interval, survives a bad cycle, and SURFACES each cycle's tally so a stuck repo is observable."""

    repos: "list[str]"
    queue_root: "str | os.PathLike | None" = None
    queue: Any = None
    lister: RepoLister = empty_lister
    checkpoints: "Optional[ReconciliationCheckpoints]" = None
    checkpoint_root: "str | os.PathLike | None" = None
    _q: Any = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.queue is None and self.queue_root is None:
            raise ValueError("Reconciler needs a queue (injected) or a queue_root to build one")
        self._q = self.queue
        if self.checkpoints is None:
            root = self.checkpoint_root or self.queue_root
            if root is None:
                raise ValueError(
                    "Reconciler needs checkpoints or a checkpoint_root/queue_root for the per-repo cursors")
            self.checkpoints = ReconciliationCheckpoints(root)

    def _queue(self) -> Any:
        if self._q is None:
            from .queue import SecurityJobQueue   # lazy (two-env: framework deferred inside the queue)
            self._q = SecurityJobQueue(self.queue_root)
        return self._q

    def once(self) -> dict:
        return reconcile_once(repos=list(self.repos), lister=self.lister,
                              checkpoints=self.checkpoints, queue=self._queue())

    def watch(self, *, interval: float = 900.0, sleep: Optional[Callable[[float], None]] = None,
              max_cycles: int = 0) -> int:
        """Reconcile on a slow interval forever (or ``max_cycles`` cycles, for tests). A single bad cycle
        NEVER stops the loop — it is reported to stderr and the loop continues. A cycle with any
        ``failed``/``skipped``/``dropped`` is surfaced to stderr so a repo that is not reconciling is
        OBSERVABLE (a safety net that fails silently is not a safety net). Returns the cycle count."""
        import sys as _sys
        import time
        _sleep = sleep or time.sleep
        n = 0
        while max_cycles <= 0 or n < max_cycles:
            try:
                tally = self.once()
                if tally.get("failed") or tally.get("skipped") or tally.get("dropped"):
                    _sys.stderr.write("vigil reconcile: WARNING cycle had unprocessed work "
                                      f"(failed={tally.get('failed', 0)}, skipped={tally.get('skipped', 0)}, "
                                      f"dropped={tally.get('dropped', 0)}, enqueued={tally.get('enqueued', 0)})\n")
            except Exception as exc:  # noqa: BLE001 — the watch loop must survive any single-cycle failure
                _sys.stderr.write("vigil reconcile: WARNING cycle error (continuing): "
                                  f"{type(exc).__name__}: {exc}\n")
            n += 1
            if max_cycles and n >= max_cycles:
                break
            _sleep(interval)
        return n
