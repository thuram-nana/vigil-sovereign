"""
jobs.model — the normalized ``SecurityJob`` event + the ``TriggerSource`` adapter interface.

A ``SecurityJob`` is the ONE internal event every trigger adapter emits; VIGIL's core understands only
this shape, never "a GitHub webhook" / "a manual click" / "a cron tick". The adapter PRODUCES a job; it
never runs one (the queue + the authorized worker do). Pure stdlib — no framework/sigil import, no I/O.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, runtime_checkable

#: The six trigger provenances the architecture normalizes into one event. Carried for audit/telemetry;
#: it NEVER changes authorization (a job is authorized by the signed authority + scope, not by its source).
SECURITY_JOB_SOURCES: frozenset[str] = frozenset(
    {"webhook", "manual", "api", "scheduled", "ci", "reconciliation"})

_MAX_STR = 512                       # bound every untrusted string field (an adapter may carry remote data)
# NB: the DOT is deliberately EXCLUDED so a slug can never contain ``..`` (path-safety on the stores that
# key off it); every non-[a-z0-9_-] run collapses to ``-``.
_SLUG_RE = re.compile(r"[^a-z0-9_-]+")
#: Sources that CARRY a delivery id (the provider stamps one): they MUST supply it — it is the exactly-once
#: idempotency key, and silently dropping it degrades replay-protection to at-least-once.
_DELIVERY_REQUIRED_SOURCES: frozenset[str] = frozenset({"webhook", "ci"})


def _clip(value: Any, limit: int = _MAX_STR) -> str:
    """A length-bounded, control-char-free string (an adapter's fields may come from an untrusted remote)."""
    s = str(value or "")
    if any(c in s for c in ("\x00", "\n", "\r")):
        s = s.replace("\x00", "").replace("\n", " ").replace("\r", " ")
    return s[:limit]


def _canon_repo(repo: Any) -> str:
    """Canonical repo identity — trimmed, trailing-slash-stripped, lowercased — so the slug and the shared
    work-key never diverge on case / trailing-slash spelling drift between the webhook + reconciliation paths."""
    return str(repo or "").strip().rstrip("/").lower()


def work_delivery_id(repo: Any, pr_number: Any, commit: Any) -> str:
    """The SHARED, content-addressed exactly-once key for one unit of repo work ``(repo, pr, commit)``.

    Both inbound paths derive their ``delivery_id`` from this — the webhook drain (instead of the provider
    GUID) and the reconciliation poller — so the queue's PERMANENT delivery seen-set coalesces them ACROSS
    paths: once a webhook-handled commit is enqueued, a later reconciliation re-list of the same
    ``(repo, pr, commit)`` returns ``duplicate_delivery`` and is never re-scanned (closes the cross-path
    double-scan). It is INJECTIVE — the components are JSON-encoded, never ``|``-joined, so no value can be
    mistaken for a delimiter — and stable (a changed ``commit`` yields a NEW key, so new code re-scans)."""
    canon = json.dumps([_canon_repo(repo), pr_number, str(commit or "")],
                       separators=(",", ":"), default=str)
    return "work-" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class SecurityJob:
    """One normalized security-job request. Immutable + canonically hashable so the queue can dedup it.

    Fields:
      * ``tenant_id``      — the owning tenant (process-level isolation frame; "" = the single-tenant default).
      * ``source``         — one of :data:`SECURITY_JOB_SOURCES` (provenance only, never an authz input).
      * ``delivery_id``    — the trigger's unique delivery id (e.g. a webhook's X-GitHub-Delivery). The
                             EXACTLY-ONCE key: the same delivery enqueues at most once (idempotency).
      * ``repo``           — the connected repo identity, e.g. ``github.com/org/repo``.
      * ``commit``         — the commit SHA under review ("" when not commit-pinned).
      * ``pr_number``      — the pull-request number (``None`` for a non-PR scan).
      * ``profile``        — the scan profile (e.g. ``default`` / ``diff`` / ``full``).
      * ``policy_version`` — the policy/ruleset version the fingerprint is bound to.
    """

    tenant_id: str = ""
    source: str = "manual"
    delivery_id: str = ""
    repo: str = ""
    commit: str = ""
    pr_number: "int | None" = None
    profile: str = "default"
    policy_version: str = "v1"
    extra: dict = field(default_factory=dict)

    # -- derived identities ----------------------------------------------------------------------------

    @property
    def fingerprint(self) -> str:
        """The canonical DEDUP key — ``sha256`` of the sorted-key compact JSON of the work-defining tuple
        ``(tenant, repo, commit, profile, policy_version)``. Mirrors ``intel.vulnfeed._plan_fingerprint``:
        two jobs that would do the SAME work collapse to one, independent of field order / source /
        delivery_id. NOT a security boundary — a convenience dedup key; authorization is separate."""
        blob = json.dumps(
            {"tenant": self.tenant_id, "repo": self.repo, "commit": self.commit,
             "profile": self.profile, "policy": self.policy_version},
            sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @property
    def slug(self) -> str:
        """The engagement slug this job runs under — ONE slug per connected repo (v1 authorizes it
        host-broad; the exact-repo conjunct is a later slice). Deterministic, INJECTIVE, and a single safe
        path component: the repo is canonicalized (trimmed, trailing ``/`` dropped, lowercased), the
        readable stem is non-``[a-z0-9_-]``-collapsed-to-``-`` (the DOT is excluded, so no ``..``) and
        bounded, then a ``sha256`` suffix of the FULL canonical repo makes it COLLISION-RESISTANT — two
        distinct repos (or two tenants' repos) never share a slug, so they never share a verified authority
        or a per-slug run-lease. ``repo/`` and ``repo`` canonicalize identically (the same repo, one slug)."""
        canon = _canon_repo(self.repo)
        stem = _SLUG_RE.sub("-", canon).strip("-")[:40]
        suffix = hashlib.sha256(canon.encode("utf-8")).hexdigest()[:12]
        return f"repo-{stem}-{suffix}" if stem else f"repo-{suffix}"

    # -- (de)serialization for the EngagementJob.params carrier ----------------------------------------

    def to_params(self) -> dict:
        """The job as a plain dict for ``EngagementScheduler`` ``params`` (JSON-round-trippable)."""
        return {
            "tenant_id": self.tenant_id, "source": self.source, "delivery_id": self.delivery_id,
            "repo": self.repo, "commit": self.commit, "pr_number": self.pr_number,
            "profile": self.profile, "policy_version": self.policy_version,
            "extra": dict(self.extra or {}),
        }

    @classmethod
    def from_params(cls, params: "dict | None") -> "SecurityJob":
        """Reconstruct a job from an ``EngagementJob.params`` dict — TOTAL + bounded (an on-disk queue row
        is untrusted-at-rest): unknown/malformed fields degrade to defaults, never raise."""
        p = params or {}
        pr = p.get("pr_number")
        try:
            pr = int(pr) if pr is not None else None
        except (TypeError, ValueError):
            pr = None
        src = _clip(p.get("source") or "manual", 32)
        extra = p.get("extra")
        return cls(
            tenant_id=_clip(p.get("tenant_id"), 64),
            source=src if src in SECURITY_JOB_SOURCES else "manual",
            delivery_id=_clip(p.get("delivery_id")),
            repo=_clip(p.get("repo")),
            commit=_clip(p.get("commit"), 128),
            pr_number=pr,
            profile=_clip(p.get("profile") or "default", 64),
            policy_version=_clip(p.get("policy_version") or "v1", 64),
            extra=dict(extra) if isinstance(extra, dict) else {},
        )

    @classmethod
    def normalize(cls, *, source: str, repo: str, delivery_id: str = "", commit: str = "",
                  pr_number: "int | None" = None, tenant_id: str = "", profile: str = "default",
                  policy_version: str = "v1", extra: "dict | None" = None) -> "SecurityJob":
        """Build a validated job from an adapter's raw inputs — the single construction path every
        ``TriggerSource`` uses, so provenance is bounded + the source is one of the known six."""
        src = _clip(source, 32)
        if src not in SECURITY_JOB_SOURCES:
            raise ValueError(f"unknown SecurityJob source {source!r}; must be one of {sorted(SECURITY_JOB_SOURCES)}")
        if not str(repo or "").strip():
            raise ValueError("SecurityJob requires a non-empty repo")
        if src in _DELIVERY_REQUIRED_SOURCES and not _clip(delivery_id).strip():
            raise ValueError(
                f"source {src!r} carries a provider delivery id and MUST supply a non-empty delivery_id "
                "(the exactly-once idempotency key); without it replay-protection degrades to at-least-once")
        pr = int(pr_number) if pr_number is not None else None
        return cls(
            tenant_id=_clip(tenant_id, 64), source=src, delivery_id=_clip(delivery_id),
            repo=_clip(repo), commit=_clip(commit, 128), pr_number=pr,
            profile=_clip(profile or "default", 64), policy_version=_clip(policy_version or "v1", 64),
            extra=dict(extra) if isinstance(extra, dict) else {})


@runtime_checkable
class TriggerSource(Protocol):
    """A trigger adapter: it PRODUCES ``SecurityJob`` events and NEVER runs them. Webhook / manual / api /
    scheduled / ci / reconciliation each implement this; the queue + the authorized worker are the only
    things that execute. ``poll`` returns the jobs available right now (an empty list when none)."""

    def poll(self) -> "list[SecurityJob]": ...


@dataclass
class ManualTrigger:
    """The simplest adapter — an operator/CLI hands it explicit jobs; it emits them once. Carries no I/O,
    no network, no execution. Used by the console/CLI 'review this repo/PR' action and by the tests."""

    _pending: "list[SecurityJob]" = field(default_factory=list)

    def submit(self, job: SecurityJob) -> None:
        self._pending.append(job)

    def poll(self) -> "list[SecurityJob]":
        out = list(self._pending)
        self._pending.clear()
        return out


def drain(sources: "Iterable[TriggerSource]") -> "list[SecurityJob]":
    """Collect every pending job across adapters, deterministically (adapter order, then emission order).
    Pure: a source that raises is skipped (fail-open on a flaky adapter — a missed event is recovered by
    the reconciliation adapter, never by crashing the drain)."""
    out: list[SecurityJob] = []
    for src in sources:
        try:
            out.extend(src.poll())
        except Exception:  # noqa: BLE001 — one flaky adapter never sinks the others
            continue
    return out
