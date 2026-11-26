"""AEGIS AS-2c — the keyless gateway's V2 authority resolver (verify-only; holds NO key).

The data-plane COMPOSITION of the AS-2a authority-V2 contracts (``vigil_core.authority_v2``) for the
inline gateway. It answers one question per request: *given everything the sovereign has published for
this (tenant, host) subject, is AEGIS authorized to PASS-THROUGH, OBSERVE, or ENFORCE this traffic right
now — and under what epoch floor?* It wires the seven AS-2c behaviours:

  * **Dual-accept.** The grant / revocation / epoch statement are verified against ANY root in an owner-root
    OVERLAP SET, and the release against any root in a release-root overlap set. During an authority-root
    rotation the reconciler publishes both the retiring and the incoming root; a document that verifies under
    either is accepted, so no in-flight request is refused across the rotation seam (§4.4 rotation overlap).
  * **Monotone floor.** A per-subject enforcement epoch FLOOR (``MonotoneEpochFloor``) seeded from the verified
    ``EpochStatement`` and raised to ``max(local, statement)`` on every resolve; it NEVER regresses. A grant whose
    epoch sits below the floor is detectably STALE and degrades to PASS_THROUGH (anti-rollback / anti-replay).
  * **Signed revocations** honoured: a verified ``MonitoringRevocationV2`` at or above the grant's epoch supersedes
    it (PASS_THROUGH). (The UNSIGNED withdrawal / override are the fail-safe, downgrade-only signals — honoured
    without a signature because they only ever REDUCE authority.)
  * **Lease ⇒ pass-through (R16).** When the grant's short-lived lease has LAPSED (or its outer window has), the
    data plane degrades to uninspected PASS_THROUGH, shown visibly — it never hard-fails the tenant's traffic.
  * **release_valid.** An ENFORCING capability renders ONLY when a release-root ``EnforceRelease`` covers it and is
    live at ``now`` and at/above the floor. With no release root provisioned (AS-29 pending) ``release_valid`` is
    always False, so enforcement never renders and the gate degrades to OBSERVE — the safe default.
  * **≤1 s decision cache.** ``AuthorityV2Cache`` memoises the resolved decision per (org, host) for a short TTL on
    an INJECTED monotonic clock (never wallclock), so a hot path re-reads the published docs at most ~1× / TTL.
    End to end the lease still bounds staleness (§4.7); this cache is the unit-local verify cache only.
  * **Re-plant idempotency.** The resolver emits at most ONE ``AuthorityEvent`` per distinct (subject, epoch): a
    re-plant of an already-known grant (same epoch, or a stale lower epoch after the floor moved) produces no new
    event. This is the data-plane half of the AS-2c acceptance ("re-plant produces no event").

Everything fails CLOSED toward PASS_THROUGH / OBSERVE; nothing here ever raises on the request path, holds a key,
or reads a wallclock on a decision that feeds a signature check.

FATAL-2: engine-side; imports only ``vigil_core`` (the shared contracts) + stdlib. No ``sigil``; no sovereign code.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from vigil_core.authority_v2 import (
    AuthorityDecision,
    AuthorityOutcome,
    AuthoritySubject,
    EnforceRelease,
    EpochStatement,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringRevocationV2,
    SignedEnforceRelease,
    SignedEpochStatement,
    SignedMonitoringAuthorityV2,
    SignedMonitoringRevocationV2,
    SubjectKind,
    authority_publish_path,
    evaluate_authority,
    verify_enforce_release,
    verify_epoch_statement,
    verify_monitoring_authority_v2,
    verify_monitoring_revocation_v2,
)
from vigil_core.models import TrustRoot

# Reuse the v1 reader's hardened, fail-closed primitives rather than re-code them (no double-coding): the same
# symlink-refusing, size-capped regular-file read and the same host normalization the v1 gate uses.
from .monitoring_authority_check import _read_regular_file, normalize_host

__all__ = [
    "AuthorityEvent",
    "AuthorityV2Cache",
    "AuthorityV2Decision",
    "AuthorityV2Paths",
    "MonotoneEpochFloor",
    "resolve_authority_v2",
    "VERIFY_CACHE_TTL_S",
]

# Fixed, well-known filenames for the per-instance V2 control dir the sovereign reconciler publishes into (§4.7
# per-instance publish). The GRANT file name is the canonical AS-2a per-instance hash (so the reconciler and this
# read path share ONE source of truth); the per-SUBJECT documents sit beside it under fixed names. All are UNTRUSTED
# bytes verified against OUR pinned roots, never a root the artifact carries.
RELEASE_FILENAME = "enforce_release.json"
EPOCH_FILENAME = "epoch_statement.json"
REVOCATION_FILENAME = "revocation.json"
WITHDRAWAL_FILENAME = "withdrawal.json"      # UNSIGNED fail-safe signal (downgrade-only)
OVERRIDE_FILENAME = "override.json"          # UNSIGNED fail-safe signal (downgrade-only)


def _subject_dir_name(subject: AuthoritySubject) -> str:
    """A fixed-charset, hashed directory name for one subject, so the per-subject documents (release / epoch /
    revocation) of distinct subjects never collide under a shared V2 root, and no org/host string — however
    hostile — can traverse it. Deterministic; distinct subjects map to distinct dirs with overwhelming
    probability."""
    import hashlib
    key = f"{subject.kind.value}\x00{subject.org_id}\x00{subject.host}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

# The enforcing capability the inline gateway renders (a 403 block). virtual_patch / respond are other slices.
_GATEWAY_ENFORCING_CAPABILITY = MonitoringCapability.BLOCK

#: Decision-cache TTL (seconds). "≤1 s" per §4.7 — the unit-local verify cache ONLY; the lease bounds staleness
#: end to end. Measured on an INJECTED monotonic clock so the cache is deterministic and never reads a wallclock.
VERIFY_CACHE_TTL_S = 1.0


@dataclass(frozen=True)
class AuthorityEvent:
    """A de-duplicated authority-lifecycle observation the data plane surfaces at most ONCE per distinct
    (subject, epoch). ``kind`` is ``"planted"`` (a newly-accepted grant generation became live) — a re-plant of
    an already-known grant, or a stale re-plant the floor rejects, yields NO event. Pure data; no verdict, no
    certificate, no block (an authority becoming live is never itself a detection)."""

    kind: str
    org_id: str
    host: str
    epoch: int
    outcome: str


@dataclass
class AuthorityV2Decision:
    """The resolved, fail-closed data-plane decision for one request. ``outcome`` is the contract outcome
    (pass_through / observe / enforce); ``release_valid`` is True only when a release-root EnforceRelease covers
    the enforcing capability and is live and at/above the floor (AS-29); ``epoch`` is the live grant's epoch (0
    when none); ``floor`` is the monotone epoch floor applied; ``reasons`` are the machine-readable trace."""

    outcome: AuthorityOutcome
    release_valid: bool = False
    capability: Optional[MonitoringCapability] = None
    epoch: int = 0
    floor: int = 0
    grant_present: bool = False
    reasons: tuple[str, ...] = ()

    @property
    def pass_through(self) -> bool:
        return self.outcome is AuthorityOutcome.PASS_THROUGH

    @property
    def observe(self) -> bool:
        return self.outcome is AuthorityOutcome.OBSERVE

    @property
    def enforce(self) -> bool:
        return self.outcome is AuthorityOutcome.ENFORCE


def _pass_through(reason: str, *, floor: int = 0, grant_present: bool = False,
                  epoch: int = 0) -> AuthorityV2Decision:
    return AuthorityV2Decision(outcome=AuthorityOutcome.PASS_THROUGH, reasons=(reason,), floor=floor,
                              grant_present=grant_present, epoch=epoch)


@dataclass(frozen=True)
class AuthorityV2Paths:
    """Where this gateway reads its per-instance V2 control documents. Deterministic: the GRANT file is the
    canonical AS-2a per-instance hash for (subject, instance_id, replica_index); the per-subject documents sit
    beside it under the fixed names above. The directory and names are a pure function of the configured
    identity — no client input ever names a file here."""

    base: Path
    subject: AuthoritySubject
    instance_id: str
    replica_index: int = 0

    @property
    def grant(self) -> Path:
        return self.base / authority_publish_path(self.subject, instance_id=self.instance_id,
                                                   replica_index=self.replica_index)

    @property
    def release(self) -> Path:
        return self.base / RELEASE_FILENAME

    @property
    def epoch(self) -> Path:
        return self.base / EPOCH_FILENAME

    @property
    def revocation(self) -> Path:
        return self.base / REVOCATION_FILENAME

    @property
    def withdrawal(self) -> Path:
        return self.base / WITHDRAWAL_FILENAME

    @property
    def override(self) -> Path:
        return self.base / OVERRIDE_FILENAME


class MonotoneEpochFloor:
    """A per-subject enforcement epoch FLOOR that only ever RISES. Seeded from the verified ``EpochStatement``
    and raised to ``max(local, statement)`` on every resolve; a grant below the floor is STALE. Thread-safe (the
    gateway is threaded). In-memory for the process lifetime — the durable boot/replacement/move seed is the
    signed ``EpochStatement`` the reconciler publishes, so the floor is re-established keylessly on restart and
    can never be rolled BACK below a signed statement (anti-rollback, modelled in formal/antirollback/MonotoneFloor.tla)."""

    def __init__(self) -> None:
        self._floors: dict[str, int] = {}
        self._seen_events: set[tuple[str, int]] = set()   # (subject-key, epoch) already surfaced (re-plant dedup)
        self._lock = threading.Lock()

    @staticmethod
    def _key(subject: AuthoritySubject) -> str:
        return f"{subject.kind.value}\x00{subject.org_id}\x00{subject.host}"

    def current(self, subject: AuthoritySubject) -> int:
        with self._lock:
            return self._floors.get(self._key(subject), 0)

    def raise_to(self, subject: AuthoritySubject, epoch: int) -> int:
        """Advance the floor to ``max(current, epoch)`` (UPWARD-ONLY) and return the new floor. A lower epoch is
        a no-op — the floor never regresses."""
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            return self.current(subject)
        key = self._key(subject)
        with self._lock:
            new = max(self._floors.get(key, 0), epoch)
            self._floors[key] = new
            return new

    def mark_event_once(self, subject: AuthoritySubject, epoch: int) -> bool:
        """Record (subject, epoch) as surfaced and return True iff it was NOT already seen — the re-plant dedup.
        Scoped to this floor (one per gateway lifetime), so a fresh gateway starts clean."""
        key = (self._key(subject), int(epoch))
        with self._lock:
            if key in self._seen_events:
                return False
            self._seen_events.add(key)
            return True


def _load_signed(path: Path, model) -> Optional[object]:
    """Read + parse one UNTRUSTED signed document, fail-closed (None on any miss/malformation). Uses the v1
    gate's symlink-refusing, size-capped reader."""
    raw = _read_regular_file(path)
    if raw is None:
        return None
    try:
        return model.model_validate_json(raw)
    except Exception:
        return None


def _verify_any(signed, roots: list[TrustRoot], verify: Callable[[object, TrustRoot], "tuple[bool, str]"]) -> bool:
    """DUAL-ACCEPT: True iff ``signed`` verifies under ANY root in ``roots`` (the rotation overlap set). Each
    ``verify`` is itself verify-only + fail-closed; this just OR-folds across the overlap set."""
    for root in roots:
        if root is None:
            continue
        try:
            ok, _why = verify(signed, root)
        except Exception:
            ok = False
        if ok:
            return True
    return False


def resolve_authority_v2(
    org_id: str,
    host: str,
    *,
    paths: AuthorityV2Paths,
    owner_roots: list[TrustRoot],
    release_roots: list[TrustRoot],
    floor: MonotoneEpochFloor,
    now: datetime,
    requested_capability: MonitoringCapability = _GATEWAY_ENFORCING_CAPABILITY,
    on_event: Optional[Callable[[AuthorityEvent], None]] = None,
) -> AuthorityV2Decision:
    """Resolve the full AS-2c data-plane decision for (``org_id``, ``host``) at ``now``. Verify-only, fail-CLOSED,
    NEVER raises. The caller supplies the owner-root and release-root OVERLAP SETS (dual-accept), the monotone
    floor, and the wall ``now`` to compare windows against (injected for determinism). ``on_event`` receives at
    most one de-duplicated :class:`AuthorityEvent` per distinct (subject, epoch) — the re-plant idempotency hook."""
    try:
        return _resolve(org_id, host, paths=paths, owner_roots=owner_roots, release_roots=release_roots,
                        floor=floor, now=now, requested_capability=requested_capability, on_event=on_event)
    except Exception:
        # Total fail-safe: any unexpected error degrades to uninspected pass-through (never toward enforce).
        return _pass_through("resolver-raised-fail-closed")


def _emit_once(floor: MonotoneEpochFloor, subject: AuthoritySubject, epoch: int, outcome: AuthorityOutcome,
               on_event: Optional[Callable[[AuthorityEvent], None]]) -> None:
    """Fire ``on_event`` at most once per (subject, epoch) for this floor/gateway — the re-plant dedup."""
    if on_event is None:
        return
    if not floor.mark_event_once(subject, epoch):
        return
    try:
        on_event(AuthorityEvent(kind="planted", org_id=subject.org_id, host=subject.host, epoch=int(epoch),
                                outcome=outcome.value))
    except Exception:
        pass


def _resolve(org_id, host, *, paths, owner_roots, release_roots, floor, now, requested_capability,
             on_event) -> AuthorityV2Decision:
    h = normalize_host(host)
    if h is None:
        return _pass_through("invalid-host")
    if not owner_roots or all(r is None for r in owner_roots):
        return _pass_through("no-owner-root")   # unprovisioned / unreadable owner root ⇒ no authority (fail-closed)

    # (1) GRANT — verify against ANY owner root (dual-accept). No grant ⇒ pass-through (R16, "no valid authority").
    signed_grant = _load_signed(paths.grant, SignedMonitoringAuthorityV2)
    if signed_grant is None:
        return _pass_through("no-grant")
    assert isinstance(signed_grant, SignedMonitoringAuthorityV2)
    if not _verify_any(signed_grant, owner_roots, verify_monitoring_authority_v2):
        return _pass_through("grant-unverified")
    grant: MonitoringAuthorityV2 = signed_grant.document
    subject = grant.subject

    # The grant must BIND the exact (tenant, host) this gateway serves — a grant for another subject never
    # authorizes this one (the v1 gate's cross-tenant/host guard, V2).
    if subject.org_id != org_id or subject.host != h or subject.kind is not SubjectKind.HOST:
        return _pass_through("grant-subject-mismatch", grant_present=True)

    # (2) REVOCATION — a verified owner-signed revocation at/above the grant's epoch supersedes it.
    revocation: Optional[MonitoringRevocationV2] = None
    signed_rev = _load_signed(paths.revocation, SignedMonitoringRevocationV2)
    if signed_rev is not None and isinstance(signed_rev, SignedMonitoringRevocationV2):
        if _verify_any(signed_rev, owner_roots, verify_monitoring_revocation_v2) \
                and signed_rev.document.subject == subject:
            revocation = signed_rev.document

    # (3) EPOCH STATEMENT — a verified owner-signed statement RAISES the monotone floor (max(local, statement)).
    signed_epoch = _load_signed(paths.epoch, SignedEpochStatement)
    if signed_epoch is not None and isinstance(signed_epoch, SignedEpochStatement):
        if _verify_any(signed_epoch, owner_roots, verify_epoch_statement) \
                and signed_epoch.document.subject == subject:
            floor.raise_to(subject, signed_epoch.document.epoch)
    epoch_floor = floor.current(subject)

    # (4) RELEASE — verified against the SEPARATE release root(s) ALONE (AS-29). Absent/unprovisioned ⇒ None ⇒
    #     no enforce (release_valid False). Never verified against an owner root (the separate-root wall).
    release: Optional[EnforceRelease] = None
    if release_roots and not all(r is None for r in release_roots):
        signed_rel = _load_signed(paths.release, SignedEnforceRelease)
        if signed_rel is not None and isinstance(signed_rel, SignedEnforceRelease):
            if _verify_any(signed_rel, release_roots, verify_enforce_release) \
                    and signed_rel.document.subject == subject:
                release = signed_rel.document

    # (5) UNSIGNED fail-safe signals — honoured without a signature because they only REDUCE authority.
    withdrawal = _load_unsigned_withdrawal(paths.withdrawal, subject)
    override = _load_unsigned_override(paths.override, subject)

    # (6) Compose the already-verified documents into the contract-level decision (AS-2a evaluate_authority).
    decision: AuthorityDecision = evaluate_authority(
        grant=grant, now=now, epoch_floor=epoch_floor, requested_capability=requested_capability,
        release=release, revocation=revocation, withdrawal=withdrawal, override=override,
    )
    release_valid = "release-valid" in decision.reasons
    out = AuthorityV2Decision(
        outcome=decision.outcome, release_valid=release_valid, capability=decision.capability,
        epoch=int(grant.epoch), floor=int(epoch_floor), grant_present=True, reasons=decision.reasons,
    )

    # (7) Re-plant idempotency: emit the authority event only when the grant is LIVE (observe/enforce) and only
    #     once per (subject, epoch). A stale/superseded/lapsed re-plant is pass-through ⇒ no event.
    if out.outcome is not AuthorityOutcome.PASS_THROUGH:
        _emit_once(floor, subject, grant.epoch, out.outcome, on_event)
    return out


def _load_unsigned_withdrawal(path: Path, subject: AuthoritySubject):
    from vigil_core.authority_v2 import AuthorityWithdrawal
    doc = _load_signed(path, AuthorityWithdrawal)
    if isinstance(doc, AuthorityWithdrawal) and doc.subject == subject:
        return doc
    return None


def _load_unsigned_override(path: Path, subject: AuthoritySubject):
    from vigil_core.authority_v2 import EnforcementOverride
    doc = _load_signed(path, EnforcementOverride)
    if isinstance(doc, EnforcementOverride) and doc.subject == subject:
        return doc
    return None


class AuthorityV2Cache:
    """A ≤1 s, thread-safe decision cache keyed on (org, host), on an INJECTED monotonic clock. Memoises the
    resolved :class:`AuthorityV2Decision` so a hot request path re-reads the published docs at most ~1× / TTL.
    Deterministic: the clock is injected (``time.monotonic`` in production, a fake in tests) — NEVER a wallclock,
    so the cache boundary is reproducible. The lease still bounds end-to-end staleness independently (§4.7)."""

    def __init__(self, resolver: Callable[..., AuthorityV2Decision], *,
                 monotonic: Callable[[], float], ttl_s: float = VERIFY_CACHE_TTL_S) -> None:
        self._resolver = resolver
        self._monotonic = monotonic
        self._ttl = float(ttl_s)
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], tuple[float, AuthorityV2Decision]] = {}

    def get(self, org_id: str, host: str, **resolve_kwargs) -> AuthorityV2Decision:
        now_m = self._monotonic()
        key = (org_id, host)
        with self._lock:
            hit = self._entries.get(key)
            if hit is not None and hit[0] > now_m:
                return hit[1]
        decision = self._resolver(org_id, host, **resolve_kwargs)
        with self._lock:
            self._entries[key] = (now_m + self._ttl, decision)
        return decision
