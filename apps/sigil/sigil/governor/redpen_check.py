"""The "VIGIL Red-Pen" merge-blocking CHECK RUN — written SOVEREIGN-side from an inert review outcome (R3, O-5).

Decision O-5: the GitHub App key and the check-run write are SOVEREIGN-only. The keyless offense review worker emits
an INERT review-outcome envelope (schema ``vigil.redpen.review-outcome.v1``) carrying ONLY reproduced-FACT severities
— never a LEAD, never a model's text — and THIS module, holding nothing but that envelope plus the owner-signed
connected-repo record, decides the check conclusion and writes it via :func:`governor.github_app.post_check_run`
(which mints a short-lived per-repo installation token from the App key — the App key never leaves the sovereign
plane).

The conclusion (owner decision §12):
  * ``failure`` (BLOCKS the merge) when a reproduced FACT sits at or above the repository's merge-blocking
    ``block_threshold`` (``NONE`` never blocks · ``CRITICAL_HIGH`` blocks Critical/High · ``MEDIUM_UP`` blocks
    Medium and up);
  * ``neutral`` when reproduced FACTs exist but all sit BELOW the threshold (they are review comments only), or when
    the review was REFUSED (e.g. the monthly spending limit — O-2 — so the merge is not blocked, only not reviewed);
  * ``success`` when the review ran and reproduced no FACT.

Only ``fact_severities`` decide — and the envelope carries NO LEAD, so a LEAD can never make the check block (the
two independent guarantees: the offense worker never puts a LEAD in the envelope, and this writer only ever reads
``fact_severities``). The threshold lives INSIDE the owner-signed connected-repo record, so a tenant cannot relax it
without a fresh owner signature.

FATAL-2: SOVEREIGN-only (``assert_no_offense``); imports ``vigil_core`` + sovereign siblings (``github_app``,
``connected_repos``). No ``framework`` / ``strix`` / offense import.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import BlockThreshold  # noqa: E402

from . import github_app as _app  # noqa: E402

REVIEW_OUTCOME_SCHEMA = "vigil.redpen.review-outcome.v1"   # must match jobs.redpen_review.REVIEW_OUTCOME_SCHEMA

# Which reproduced-FACT severities BLOCK the merge, per the repository's owner-signed threshold. Only reproduced
# FACTs ever appear in an outcome envelope (decision O-1); this maps the threshold to the blocking severity set.
_BLOCKING_FOR = {
    BlockThreshold.NONE: frozenset(),
    BlockThreshold.CRITICAL_HIGH: frozenset({"critical", "high"}),
    BlockThreshold.MEDIUM_UP: frozenset({"critical", "high", "medium"}),
}
_KNOWN_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


class RedpenCheckError(RuntimeError):
    """A fail-closed Red-Pen check-run refusal (the flag off, a malformed outcome, no connected record, or an egress
    failure surfaced up). The message never contains a token or the App key."""


class RedpenCheckEgressError(RedpenCheckError):
    """The check could not be WRITTEN (the token mint or the check-run POST failed at GitHub). Unlike a definitive
    refusal (malformed / unconnected / flag off) this may be transient, so the outcome drain RETRIES it a bounded
    number of times before quarantining — a GitHub outage must not silently drop a merge-blocking check."""


def _as_threshold(threshold: Any) -> BlockThreshold:
    if isinstance(threshold, BlockThreshold):
        return threshold
    try:
        return BlockThreshold(str(threshold))
    except ValueError:
        # An unknown / malformed threshold is the STRICTEST default — never fail OPEN to "never block".
        return BlockThreshold.CRITICAL_HIGH


def _fact_severities(outcome: Mapping[str, Any]) -> "list[str]":
    """The reproduced-FACT severities carried by the envelope — the ONLY thing that can make the check block. A
    LEAD is never in the envelope, so a LEAD can never appear here. Bounded + normalised; an unknown value is
    ignored (never silently treated as blocking or as clean)."""
    raw = outcome.get("fact_severities")
    if not isinstance(raw, (list, tuple)):
        return []
    return [str(s).strip().lower() for s in raw if str(s).strip().lower() in _KNOWN_SEVERITIES]


def redpen_check_decision(outcome: Mapping[str, Any], *, threshold: Any) -> dict:
    """Decide the "VIGIL Red-Pen" check conclusion for one inert review outcome, under the repository's
    ``threshold``. Returns ``{status, conclusion, blocking, title, summary, blocking_count, fact_count}`` — a PURE
    function (no egress, no key). ``failure`` iff a reproduced FACT is at/above the threshold; ``neutral`` for
    below-threshold FACTs or a refused review; ``success`` for a clean review. Only ``fact_severities`` are read,
    so a LEAD (never in the envelope) can never block."""
    th = _as_threshold(threshold)
    blocking_set = _BLOCKING_FOR[th]
    sevs = _fact_severities(outcome)
    blocking = [s for s in sevs if s in blocking_set]
    refused = bool(outcome.get("refused"))

    if blocking:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        counts = {s: blocking.count(s) for s in sorted(set(blocking), key=lambda s: order.get(s, 9))}
        detail = ", ".join(f"{n} {s.capitalize()}" for s, n in counts.items())
        return {
            "status": "completed", "conclusion": "failure", "blocking": True,
            "blocking_count": len(blocking), "fact_count": len(sevs),
            "title": "Reproduced findings block this merge",
            "summary": (f"VIGIL Red-Pen reproduced {detail} finding(s) that this repository's policy blocks. Each "
                        "was reproduced twice in an isolated sandbox and confirmed by a deterministic oracle, and "
                        "is posted as a review comment with its reproduce command and evidence reference. Open the "
                        "**Fix this** action in the VIGIL dashboard for a re-checked fix PR (VIGIL never merges "
                        "it)."),
        }
    if refused:
        reason = str(outcome.get("reason") or "the review did not run")
        return {
            "status": "completed", "conclusion": "neutral", "blocking": False,
            "blocking_count": 0, "fact_count": len(sevs),
            "title": "Red-Pen review did not run",
            "summary": f"VIGIL Red-Pen did not review this change: {reason[:400]}",
        }
    if sevs:
        return {
            "status": "completed", "conclusion": "neutral", "blocking": False,
            "blocking_count": 0, "fact_count": len(sevs),
            "title": "Reproduced findings (non-blocking)",
            "summary": (f"VIGIL Red-Pen reproduced {len(sevs)} finding(s) below this repository's merge-blocking "
                        "threshold; they are posted as review comments. The merge is not blocked."),
        }
    return {
        "status": "completed", "conclusion": "success", "blocking": False,
        "blocking_count": 0, "fact_count": 0,
        "title": "No reproduced findings",
        "summary": "VIGIL Red-Pen reviewed the changed files and reproduced no blocking finding.",
    }


def _validate_outcome(outcome: Any) -> "tuple[str, str, str]":
    """Validate the inert envelope's schema + the bits the write needs: ``(repo, org_id, head_sha)``. Fail-closed
    ``RedpenCheckError`` on a wrong schema / missing repo / missing org / non-hex head sha."""
    if not isinstance(outcome, Mapping) or outcome.get("schema") != REVIEW_OUTCOME_SCHEMA:
        raise RedpenCheckError(f"not a {REVIEW_OUTCOME_SCHEMA} review-outcome envelope")
    repo = str(outcome.get("repo") or "").strip()
    org_id = str(outcome.get("org_id") or "").strip()
    head = str(outcome.get("head_sha") or "").strip()
    if not repo:
        raise RedpenCheckError("review outcome carries no repo")
    if not org_id:
        raise RedpenCheckError("review outcome carries no org_id (cannot resolve the connected-repo record)")
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", head):
        raise RedpenCheckError("review outcome carries no hex head_sha to attach the check to")
    return repo, org_id, head


def write_redpen_check(
    outcome: Mapping[str, Any],
    *,
    registry: Any,
    now: Optional[float] = None,
    env: "Optional[Mapping[str, str]]" = None,
    _mint_token: Optional[Callable[..., dict]] = None,
    _post_check: Optional[Callable[..., dict]] = None,
    transport: Any = None,
) -> dict:
    """Write the "VIGIL Red-Pen" check run for one inert review outcome, SOVEREIGN-side (decision O-5).

    Behind the master flag ``config.redpen_enabled()`` (off ⇒ refuse before anything, even with injected seams).
    ALWAYS resolves the owner-signed connected-repo record for ``(org_id, repo)`` from ``registry`` — the
    authorization of record (O-3): no record (never connected, disconnected, or another org's) ⇒ refuse, so a check
    is never written for a repository nobody authorized. That record is the SOLE source of BOTH the merge-blocking
    ``block_threshold`` (inside the owner-signed bytes — a tenant cannot relax it) AND the ``installation_id`` the
    token is minted from; there is deliberately no caller override. It then decides the conclusion
    (:func:`redpen_check_decision`), mints a SHORT-LIVED per-repo installation token
    (:func:`github_app.mint_installation_token` — the App key stays sovereign), and POSTs the check
    (:func:`github_app.post_check_run`). Only ``fact_severities`` cross into the decision, so a LEAD can never
    block. Fail-closed ``RedpenCheckError`` on the flag off, a malformed outcome, no connected record, or an egress
    refusal. ``_mint_token`` / ``_post_check`` are offline-test injection seams."""
    from .. import config
    if not config.redpen_enabled():
        raise RedpenCheckError("Red-Pen is off (VIGIL_REDPEN_ENABLED): refusing to write a check (fail-closed)")
    repo, org_id, head = _validate_outcome(outcome)

    record = registry.active(org_id, repo) if registry is not None else None
    if record is None:
        raise RedpenCheckError(f"{repo} is not connected for org {org_id} — refusing to write a check "
                               "(fail-closed: no owner-signed connection authorizes it)")
    th, iid = record.block_threshold, record.installation_id

    decision = redpen_check_decision(outcome, threshold=th)

    mint = _mint_token or _app.mint_installation_token
    post = _post_check or _app.post_check_run
    try:
        minted = mint(iid, now=now, env=env, transport=transport)
        token = str(minted.get("token") or "") if isinstance(minted, Mapping) else ""
    except _app.GitHubAppError as exc:
        raise RedpenCheckEgressError(f"could not mint an installation token for the check run on {repo}: "
                                     f"{exc}") from None
    if not token:
        raise RedpenCheckEgressError("installation-token exchange returned no token (fail-closed)")
    try:
        resp = post(token, repo, head_sha=head, status=decision["status"], conclusion=decision["conclusion"],
                    title=decision["title"], summary=decision["summary"], transport=transport)
    except _app.GitHubAppError as exc:
        raise RedpenCheckEgressError(f"could not write the {_app.CHECK_RUN_NAME} check on {repo}: {exc}") from None
    return {"ok": True, "repo": repo, "head_sha": head, "conclusion": decision["conclusion"],
            "blocking": decision["blocking"], "decision": decision, "check_run": dict(resp) if isinstance(
                resp, Mapping) else {}}


_OUTCOME_MAX_BYTES = 256 * 1024     # mirror the offense spooler's inert-envelope cap
_MAX_WRITE_ATTEMPTS = 5             # a check write failing at GitHub this many times is quarantined (re-drivable)


class RedpenOutcomeDrain:
    """Drain the Red-Pen review-outcome spool (the offense worker's ``emit_outcome`` sink) and write the
    "VIGIL Red-Pen" check run for each one, SOVEREIGN-side. It only reads inert envelopes and writes checks.

    Fail-closed per file, never a loop crash: a malformed / oversized / unconnected outcome is QUARANTINED with a
    reason (a definitive refusal); a check that could not be WRITTEN at GitHub (:class:`RedpenCheckEgressError` —
    possibly a transient outage) is DEFERRED back to ``incoming/`` and retried on the next drain, up to
    ``_MAX_WRITE_ATTEMPTS`` before it too is quarantined, so an outage never silently drops a merge-blocking check;
    a written check is archived (content-addressed, idempotent). A claim interrupted by a crash is reclaimed from
    ``working/`` on the next drain."""

    def __init__(self, *, spool_dir: "str | os.PathLike", registry: Any, now: Optional[float] = None,
                 _mint_token: Any = None, _post_check: Any = None, transport: Any = None) -> None:
        self.registry = registry
        self.now = now
        self._mint = _mint_token
        self._post = _post_check
        self._transport = transport
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"
        self.processed = self.spool / "processed"
        self.rejected = self.spool / "rejected"
        self.attempts = self.spool / "attempts"
        for d in (self.incoming, self.working, self.processed, self.rejected, self.attempts):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

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

    def _reclaim_working(self) -> None:
        """Crash recovery: a file stranded in ``working/`` (a claim interrupted before it was archived / deferred /
        quarantined) goes back to ``incoming/``. A re-write of the same check is harmless (GitHub shows the latest
        run for the name at that sha), so this never loses an outcome."""
        try:
            stale = list(self.working.glob("*.json"))
        except OSError:
            return
        for f in stale:
            try:
                os.replace(f, self.incoming / f.name)
            except OSError:
                pass

    def _bump_attempts(self, name: str) -> int:
        """Record one more failed write for spool file ``name``; returns the new count (an unreadable counter
        restarts at 1 — it can only ever delay the quarantine, never skip a retry)."""
        counter = self.attempts / (name + ".n")
        try:
            n = int(counter.read_text(encoding="ascii").strip() or "0") + 1
        except (OSError, ValueError):
            n = 1
        try:
            counter.write_text(str(n), encoding="ascii")
        except OSError:
            pass
        return n

    def _clear_attempts(self, name: str) -> None:
        try:
            os.unlink(self.attempts / (name + ".n"))
        except OSError:
            pass

    @staticmethod
    def _read_outcome(path: Path) -> "tuple[bytes, Any]":
        """Read a REGULAR, bounded file without following a symlink or blocking on a FIFO and parse it. ANY failure
        (symlink / FIFO / oversized / non-UTF-8 / non-JSON / pathologically nested) raises — the caller quarantines."""
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file (symlink/FIFO/device refused)")
            if st.st_size > _OUTCOME_MAX_BYTES:
                raise OSError(f"outcome exceeds {_OUTCOME_MAX_BYTES} bytes")
            data = os.read(fd, _OUTCOME_MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > _OUTCOME_MAX_BYTES:
            raise OSError(f"outcome exceeds {_OUTCOME_MAX_BYTES} bytes")
        return data, json.loads(data.decode("utf-8"))

    def drain(self) -> dict:
        """Process every inert outcome in ``incoming/`` once. Returns ``{written, blocked, rejected, deferred}``.
        With Red-Pen OFF it is a no-op that touches nothing (the files wait; nothing quarantined, nothing written)."""
        from .. import config
        written = blocked = rejected = deferred = 0
        if not config.redpen_enabled():
            return {"written": 0, "blocked": 0, "rejected": 0, "deferred": 0}
        self._reclaim_working()
        try:
            files = sorted(self.incoming.glob("*.json"))
        except OSError:
            files = []
        for src in files:
            if src.name.startswith(".tmp-"):
                continue
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)
            except OSError:
                continue
            try:
                data, outcome = self._read_outcome(claimed)
            except Exception as exc:  # noqa: BLE001 — a hostile file is quarantined, never a loop crash
                self._quarantine(claimed, f"unreadable outcome: {type(exc).__name__}: {exc}")
                rejected += 1
                continue
            try:
                res = write_redpen_check(outcome, registry=self.registry, now=self.now, _mint_token=self._mint,
                                         _post_check=self._post, transport=self._transport)
            except RedpenCheckEgressError as exc:
                n = self._bump_attempts(src.name)
                if n >= _MAX_WRITE_ATTEMPTS:
                    self._quarantine(claimed, f"check-run write failed {n} times (re-drive by moving it back to "
                                     f"incoming/): {exc}")
                    self._clear_attempts(src.name)
                    rejected += 1
                else:
                    try:
                        os.replace(claimed, self.incoming / src.name)   # DEFER — retried on the next drain
                    except OSError:
                        pass
                    deferred += 1
                continue
            except RedpenCheckError as exc:       # definitive: malformed / unconnected (retrying cannot help)
                self._quarantine(claimed, f"check-run write refused: {exc}")
                rejected += 1
                continue
            except Exception as exc:  # noqa: BLE001 — an unexpected failure is quarantined, never a loop crash
                self._quarantine(claimed, f"check-run write error: {type(exc).__name__}: {exc}")
                rejected += 1
                continue
            self._clear_attempts(src.name)
            marker = self.processed / (hashlib.sha256(data).hexdigest() + ".json")
            try:
                os.replace(claimed, marker)
            except OSError:
                try:
                    os.unlink(claimed)
                except OSError:
                    pass
            written += 1
            if res.get("blocking"):
                blocked += 1
        return {"written": written, "blocked": blocked, "rejected": rejected, "deferred": deferred}


__all__ = ["REVIEW_OUTCOME_SCHEMA", "RedpenCheckError", "RedpenCheckEgressError", "redpen_check_decision",
           "write_redpen_check", "RedpenOutcomeDrain"]
