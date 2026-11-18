"""Red-Pen System schedule — the SOVEREIGN record of owner-signed per-repo REVIEW SCHEDULES (Red-Pen R4).

A schedule record authorizes VIGIL to run a WHOLE-REPOSITORY (System) Red-Pen review of ONE connected repository
(``github.com/org/repo``) for ONE tenant (``org_id``) on a recurring CADENCE — ``weekly`` or ``monthly``. It is a
CONVENIENCE over the connected-repo authorization (decision O-3): the connected-repo record is still the authorization
of record for any review; this schedule only decides WHEN a System review is enqueued on the owner's behalf. A review
the schedule enqueues is still reserved + metered through ``reserve_redpen_review`` (refused at the per-repo monthly
limit) and still authorized at the job gate — a schedule can NEVER widen scope or bypass a limit.

This module is the SPINE-OF-RECORD (SOVEREIGN; the keyless offense plane never reads it — the integration scheduler
is handed only an owner-signed System-review ticket per DUE repo, never this record). It mirrors
``monitoring_authority`` / ``connected_repos``:

ASYMMETRIC AUTHENTICATION:
  * set-schedule = the DANGEROUS direction → honored only if the record is OWNER-SIGNED (``authn`` bare-canonical,
    verified under the owner pubkey valid AT ITS SEQ) AND FRESH (``issued_at`` strictly above the per-(org, repo)
    high-water). A captured record cannot resurrect a cleared schedule, and the cadence is inside the signed bytes —
    a tenant cannot set or change a schedule without a fresh owner signature.
  * clear-schedule = the SAFE direction → a minimal top-level ``state="disabled"`` record honored even UNSIGNED (a
    replay merely re-disables; gating the fail-safe direction would make it fail OPEN — a review that keeps firing).

PER-PERIOD ENQUEUE HIGH-WATER (``governor.redpen_schedule_run``): each time the scheduler enqueues a System review
for (org, repo) it owner-signs ONE run marker naming the calendar PERIOD it enqueued for. ``due`` treats a schedule
as due iff the current period differs from the last VERIFIED enqueued period — so a review enqueues at most once per
period, and a FORGED run marker (bad signature) is inert ⇒ treated as "not enqueued" ⇒ the review still enqueues
(fail-SAFE: a forgery can never SUPPRESS a due review, only — at worst — allow a duplicate, which the queue coalesces).

CROSS-TENANT ISOLATION: every record is keyed per (org_id, repo); ``schedules_of_org`` / ``due`` for one org return
only that org's repositories, so one tenant's schedule can never read, overwrite or trigger another tenant's.

HARD-PRUNE DURABILITY: a fail-closed TRIPWIRE (``spine.prune.stranded_active_redpen_schedules``) refuses a hard prune
that would strand the authoritative latest record of any (org, repo) — covering both an active schedule and a disabled
tombstone, exactly like ``connected_repos`` (a genesis-scan fold with no snapshot seed in this slice; carrying rows
into the seed is a clean follow-on when prune performance for schedules matters).

FATAL-2: SOVEREIGN-only (``assert_no_offense``); imports only the shared ``vigil_core`` + sovereign siblings.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import check_connected_repo  # noqa: E402

from . import key_history as _kh  # noqa: E402  (owner-key succession resolver, mirrors connected_repos)
from .asset_ownership import _check_org_id  # noqa: E402  (ONE tenant-id validator, shared)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .connected_repos import ConnectedRepoRegistry  # noqa: E402  (the authorization of record, O-3)
from .identity import owner_keypair, owner_pubkey  # noqa: E402

SIGNAL = "governor.redpen_schedule"
RUN_SIGNAL = "governor.redpen_schedule_run"
CADENCE_WEEKLY = "weekly"
CADENCE_MONTHLY = "monthly"
_CADENCES = frozenset({CADENCE_WEEKLY, CADENCE_MONTHLY})
# The authenticated CORE of an ACTIVE schedule record and of a per-period enqueue run marker.
_CORE = ("signal", "org_id", "repo", "cadence", "state", "issued_at")
_RUN_CORE = ("signal", "org_id", "repo", "period", "issued_at")
_LOAD_FROM_VAULT = object()
_SKIP = object()


def _check_cadence(cadence) -> str:
    c = str(cadence or "").strip().lower()
    if c not in _CADENCES:
        raise ValueError(f"cadence must be one of {sorted(_CADENCES)}")
    return c


def period_key(cadence: str, now: float) -> str:
    """The calendar PERIOD bucket (UTC) for ``now`` under ``cadence``: ``weekly`` → ISO ``YYYY-Www`` (ISO
    year + week, so the week that straddles New Year is one bucket), ``monthly`` → ``YYYY-MM``. A System review
    is enqueued at most once per bucket; a later bucket re-arms it (``due``). Fail-closed ``ValueError`` on a bad
    cadence — a review is never enqueued under an unknown cadence."""
    c = _check_cadence(cadence)
    dt = datetime.fromtimestamp(float(now), tz=timezone.utc)
    return dt.strftime("%G-W%V") if c == CADENCE_WEEKLY else dt.strftime("%Y-%m")


class RedPenScheduleRegistry:
    def __init__(self, store, *, owner_key=_LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None):
        self.store = store
        # Signing paths load the owner key from the vault; a pure-read caller passes owner_key=None explicitly so
        # the sovereign private key is never touched on a read path (least-privilege, mirrors connected_repos).
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ------------------------------------------------------------------------------
    def set_schedule(self, org_id: str, repo: str, *, cadence: str, issued_at: float, note: str = "") -> dict:
        """Owner-sign a ``cadence`` (``weekly``/``monthly``) System-review schedule for (org, repo) — the
        DANGEROUS direction, honored only if it verifies AND is FRESH (``issued_at`` strictly above the
        per-(org, repo) high-water). The cadence is inside the signed bytes. Fail-closed ``ValueError`` on a bad
        org / repo / cadence, a repository not CURRENTLY connected for this org, or a missing signing key. Returns
        the stored core dict."""
        if self.owner_key is None:
            raise ValueError("setting a Red-Pen schedule requires the owner signing key")
        oid = _check_org_id(org_id)
        repo_ref = check_connected_repo(repo)
        cad = _check_cadence(cadence)
        # NECESSARY-NOT-SUFFICIENT (defence in depth, mirrors monitoring_authority's ownership check): a schedule is
        # only ever set for a repository CURRENTLY connected for THIS org — the connected-repo record is the
        # authorization of record (O-3). The reserve at enqueue re-checks it, so a later disconnect still refuses.
        if ConnectedRepoRegistry(self.store, owner_key=None,
                                 trusted_pubkey=self.trusted_pubkey).active(oid, repo_ref) is None:
            raise ValueError(f"{repo_ref} is not connected for org {oid}: connect it before scheduling reviews")
        core = {"signal": SIGNAL, "org_id": oid, "repo": repo_ref, "cadence": cad, "state": "active",
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"Red-Pen {cad} System-review schedule set for {repo_ref} (org {oid}){_note(note)}"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return core

    def clear_schedule(self, org_id: str, repo: str) -> int:
        """Clear the schedule for (org, repo) — the SAFE direction (honored even unsigned, so it can never fail
        open and leave a review firing). Idempotent; a cleared repo is simply not ``due``."""
        oid = _check_org_id(org_id)
        repo_ref = check_connected_repo(repo)
        payload = {"signal": SIGNAL, "org_id": oid, "repo": repo_ref, "state": "disabled", "by": "owner",
                   "requested_by": "owner", "tier": "A0", "decision": "auto",
                   "reason": f"Red-Pen System-review schedule cleared for {repo_ref} (org {oid})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def record_enqueue(self, org_id: str, repo: str, *, period: str, now: float) -> int:
        """Owner-sign ONE per-period enqueue marker for (org, repo): after this, ``due`` no longer returns the
        schedule for ``period`` (it re-arms next period). Fail-closed ``ValueError`` on a bad org / repo / period
        or a missing signing key. Returns the appended seq."""
        if self.owner_key is None:
            raise ValueError("recording a Red-Pen schedule enqueue requires the owner signing key")
        oid = _check_org_id(org_id)
        repo_ref = check_connected_repo(repo)
        per = str(period or "").strip()
        if not per or ":" in per:
            raise ValueError("period must be a non-empty string without ':'")
        core = {"signal": RUN_SIGNAL, "org_id": oid, "repo": repo_ref, "period": per, "issued_at": float(now)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"Red-Pen System review enqueued for {repo_ref} (org {oid}) period {per}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads ----------------------------------------------------------------------------------------
    def _fold(self) -> "dict[tuple, str]":
        """{(org_id, repo): cadence} for repositories whose latest schedule state is ACTIVE. A signature-
        verifying genesis scan of the live window: an owner-signed active record counts only under the owner
        pubkey valid at its seq and only when FRESH (LWW high-water); a disable (even unsigned) supersedes."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: "dict[tuple, str]" = {}
        issued: "dict[tuple, float]" = {}
        cadence: "dict[tuple, str]" = {}
        for r in self.store.iter_records():
            self._apply(r, resolver, state, issued, cadence)
        return {k: cadence[k] for k, st in state.items() if st == "active"}

    def _apply(self, r, resolver, state: dict, issued: dict, cadence: dict):
        """Fold ONE spine record into (state, issued, cadence). Returns the (org, repo) touched, or ``_SKIP``."""
        p = getattr(r, "payload", None)
        if not isinstance(p, dict) or p.get("signal") != SIGNAL:
            return _SKIP
        oid, repo = p.get("org_id"), p.get("repo")
        if not isinstance(oid, str) or not oid or not isinstance(repo, str) or not repo:
            return _SKIP
        key = (oid, repo)
        st = p.get("state")
        if st == "disabled":                              # the SAFE direction (honored even unsigned)
            state[key] = "disabled"
            return key
        if st == "active":                                # the DANGEROUS direction (owner-signed + fresh)
            if p.get("cadence") not in _CADENCES:
                return _SKIP
            if not verify_signed(p, _CORE, resolver.at(r.seq)):
                return _SKIP                              # fail-closed: unsigned/forged/wrong-epoch-key record
            at = as_issued_at(p.get("issued_at"))
            if at <= issued.get(key, NO_HIGHWATER):
                return _SKIP                              # REPLAY / stale re-append of an already-honored record
            issued[key] = at
            state[key] = "active"
            cadence[key] = p.get("cadence")
            return key
        return _SKIP

    def active(self, org_id: str, repo: str) -> Optional[str]:
        """The active cadence for (org, repo), or None (fail-closed / DEFAULT-DENY: no record, a disabled repo,
        or a record for a DIFFERENT org all return None)."""
        if not isinstance(org_id, str) or not org_id or not isinstance(repo, str) or not repo:
            return None
        try:
            key = (_check_org_id(org_id), check_connected_repo(repo))
        except ValueError:
            return None
        return self._fold().get(key)

    def schedules_of_org(self, org_id: str) -> "list[tuple[str, str]]":
        """``[(repo, cadence), ...]`` every repository (org_id) currently schedules, in repo order. Cross-tenant
        isolated (only this org's rows)."""
        if not isinstance(org_id, str) or not org_id:
            return []
        try:
            oid = _check_org_id(org_id)
        except ValueError:
            return []
        return [(repo, cad) for (o, repo), cad in sorted(self._fold().items()) if o == oid]

    def active_records(self) -> "list[tuple[str, str, str]]":
        """The CROSS-TENANT view ``[(org_id, repo, cadence), ...]`` across all orgs, in (org, repo) order.
        OWNER-side only (the sovereign scheduler / an owner report); a per-tenant caller uses
        ``schedules_of_org`` for isolation."""
        return [(o, repo, cad) for (o, repo), cad in sorted(self._fold().items())]

    def last_enqueued_period(self, org_id: str, repo: str) -> Optional[str]:
        """The period of the LATEST VERIFIED owner-signed enqueue marker for (org, repo), by issued_at, or None.
        A forged/unsigned marker is ignored (fail-SAFE: it can never suppress a due review)."""
        try:
            oid, repo_ref = _check_org_id(org_id), check_connected_repo(repo)
        except ValueError:
            return None
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        best_at, best_period = NO_HIGHWATER, None
        for r in self.store.iter_records():
            p = getattr(r, "payload", None)
            if not isinstance(p, dict) or p.get("signal") != RUN_SIGNAL:
                continue
            if p.get("org_id") != oid or p.get("repo") != repo_ref:
                continue
            if not isinstance(p.get("period"), str) or not p.get("period"):
                continue
            if not verify_signed(p, _RUN_CORE, resolver.at(r.seq)):
                continue                                  # a forged enqueue marker is inert (fail-safe)
            at = as_issued_at(p.get("issued_at"))
            if at >= best_at:
                best_at, best_period = at, p.get("period")
        return best_period

    def due(self, now: float) -> "list[tuple[str, str, str]]":
        """The CROSS-TENANT list ``[(org_id, repo, cadence), ...]`` of active schedules whose CURRENT period has
        NOT yet been enqueued (the current ``period_key`` differs from the last verified enqueued period). Used by
        the sovereign scheduler tick; per-tenant callers filter by org. Deterministic order; read-only."""
        out: "list[tuple[str, str, str]]" = []
        for oid, repo, cad in self.active_records():
            try:
                cur = period_key(cad, now)
            except ValueError:
                continue
            if cur != self.last_enqueued_period(oid, repo):
                out.append((oid, repo, cad))
        return out


def _note(note: str) -> str:
    n = str(note or "").strip()
    return f" ({n})" if n else ""
