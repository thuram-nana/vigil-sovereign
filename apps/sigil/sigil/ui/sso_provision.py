"""Consumer PR-H (Area 7) — the PROVISIONER side of the SSO / SCIM HTTP edge.

The keyless customer edge (`ui.sso_edge`, mixed into `ui.custui`) holds no key and never reads the spine. Every
SSO / SCIM request it accepts is relayed over the hop key to the sovereign provisioner, whose `Provisioner`
methods (`sso_login_start`, `sso_saml_acs`, `sso_oidc_finish`, `scim_request`) delegate here. This module runs
in the ONE process that holds the owner key, so it is where the owner-signed config is read, the identity is
verified and the capped membership is minted (through `ui.scim` → `governor.scim.provision_membership`).

Where the ORG comes from (IDOR-safety for these session-less bootstrap actions): there is no customer session
yet, so the org is never trusted on its own — it only selects WHICH owner-signed config the proof is checked
against. Sign-in start takes the org a person asks to sign in to (public: it reveals only the IdP sign-in URL the
browser is about to visit anyway); the SAML ACS and the OIDC finish take the org from the edge's SERVER-SIDE,
single-use login state (minted at start, bound to the browser), and the assertion / id_token must then verify
under THAT org's owner-signed IdP (audience, issuer, signature, InResponseTo / nonce); SCIM takes the org from
the path and must present THAT org's bearer. A proof for org A can therefore never provision into org B.

Each action is fail-closed and rate-limited:
  * sign-in: the per-IP leg counter bounds start / ACS / finish (the coarse, cross-org volume bound); a refused
    verification counts as a failure against the (org, FULL client address) lockout, so an org's IdP can only ever
    lock out its OWN sign-ins, from exactly the address the failures came from;
  * SCIM: failed bearer authentications are counted per (org, client IP) and lock out that pair's further
    INVALID attempts (a valid bearer is never refused by it — see `scim_request`); both limiters are on disk (the
    provisioner is rebuilt per request).

ONE ORG CANNOT STALL ANOTHER. Every membership change commits inside the SAME critical section — the process-wide
spine lock (`p._lock`), then the cross-process membership flock the Team-screen verbs and the owner's `sigil org`
verbs hold (`_membership_section`) — so a sign-in or a SCIM change never interleaves with an owner act in another
process. That section is shared by every org, so what one org's token may make it do is bounded:
  * PER-ORG SERIALIZATION: an org's SCIM writes take that org's own lock first (`_org_lock`, a cross-process flock
    per org; a bounded wait, then 429 + Retry-After), and its SCIM reads a separate per-org read lock, so an org
    has at most one write and one read in flight — and the write budget below is checked AND charged inside that
    lock, so concurrent writes can never all be admitted before any is charged. Another org never waits on it.
  * READS NEVER ENTER THE SHARED SECTION: a SCIM GET folds the spine lock-free (it appends nothing), under the
    per-org read lock and a per-org read budget (`VIGIL_SCIM_READS_PER_MIN`, guard-and-count; 429 when spent).
  * WRITES FOLD OUTSIDE IT: a write's folds (config, memberships, directory) run before the section is taken; on
    entry the records appended since the fold began are checked, and if any changed this org's state (a membership,
    org, SSO-config or directory record of this org, or an owner-key rotation) the fold is redone.
  * BOUNDED HOLDS: a group change's PLAN (its staged copy of the directory and every affected member's new role) is
    computed with the section released (`_SharedSection.outside`, re-checked like a fold), so the section is held
    only to append; inside, a request appends at most `ui.scim.MAX_RECORDS_PER_HOLD` (= 128) spine records per hold
    of the section; past that it releases the section between two members' changes (or two directory records),
    lets other requests run, and re-takes it — re-checking that nothing of this org changed meanwhile (else it
    stops with a retryable 503, every record so far landed in the safe order). A group change too large for one hold
    (a rename re-roling thousands of members, the delete of a large mapped group) first opens a durable pending job
    on the spine (`governor.scim_directory`): it lowers every role first, then commits the directory, then raises,
    so at no point — between holds or after a crash — is a member above the role the directory then implies, and
    an open job is finished by the org's next SCIM write or sign-in.
  * PER-REQUEST BOUNDS: a body over a per-request bound (more than `ui.scim.MAX_PATCH_OPS` = 1000 PATCH operations,
    or more than `ui.scim.MAX_MEMBER_VALUES` = 1000 member references SUMMED over every operation of a group write)
    is refused 400 `tooMany` before the org lock, the write budget and the critical section; a group write that
    would author more than `ui.scim.MAX_DIRECTORY_WRITES` (= 1016) directory records is refused whole, before any
    record is written. Removing state already on the spine is exempt (a group DELETE, or a removal of every member,
    of a group of any size still deprovisions — that state was written, and charged, by earlier requests).
  * WRITE BUDGET: the per-org budget (`VIGIL_SCIM_OPS_PER_MIN`) admits a write only while the org is not over budget
    (guard-and-count, one unit), then charges — in a `finally`, so also when the request fails part-way — every
    further spine record the request appended. An overdraft holds the org's next write off until the budget has
    repaid it (a minute per `VIGIL_SCIM_OPS_PER_MIN` records). A request that can only take privilege away
    (`ui.scim.lowers_only`: a user / group DELETE, a deactivation, a removal of group members) is admitted even
    while the org is over budget — an offboarding never waits out an earlier sync's debt — and is still serialized,
    paced and charged. It has its own per-org cap instead (`VIGIL_SCIM_DEPROVISIONS_PER_MIN`, default 6000 units a
    minute, a request costing the records it appended and at least one): never a refusal while the org is under
    it, and even over it one deprovisioning a minute is admitted, so an offboarding always makes progress.
  * SIGN-INS: an org's IdP can mint valid assertions for its own users without limit and from any address, so the
    assertion / id_token is verified FIRST (no lock, no budget, no membership or directory fold — only the org's
    config is read), then a per-org sign-in budget (`VIGIL_SSO_SIGNINS_PER_MIN`, default 600 verified sign-ins a
    minute, beside the per-IP limiter; over it ⇒ a customer-safe refusal, nothing minted) is spent, the org's
    sign-ins are resolved one at a time (its own sign-in lock), and the member is resolved with the folds OUTSIDE
    the shared section, which is taken and re-checked only for the at most 3 records a sign-in appends.

Every membership grant / revoke writes a CRITICAL `provision.audit` row FIRST (a failed audit write aborts the
change — committed implies audited). The enterprise-OIDC token exchange + JWKS fetch go out ONLY to the hosts in
the owner-signed config's `oidc_egress_hosts` allowlist (https only), never to an arbitrary URL — and both happen
BEFORE the critical section is entered (no network wait while it is held).

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix` (`assert_no_offense()` at import).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import threading
import time
from collections import OrderedDict
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Iterator, Optional

from ..reuse import assert_no_offense

assert_no_offense()

_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")      # org_id == tenant_id (mirrors orgs._TENANT_RE)
# The scopes an SP-initiated enterprise-OIDC sign-in asks for (identity only; groups ride the id_token claim).
OIDC_SCOPES = "openid email profile"
# A SAML Response is a few KiB; the base64 form relayed by the edge is capped (the XML parser caps again).
MAX_SAML_RESPONSE_B64 = 512 * 1024
_SCIM_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_SCIM_WRITES = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: How long a SCIM request waits for its org's own lock (another request of the SAME org in flight) before a 429.
_ORG_LOCK_WAIT_S = 10.0
#: The pause between two holds of the shared section, so a request waiting for it is handed the lock.
_HANDOFF_S = 0.005
#: How long a sign-in waits for its org's sign-in lock (another sign-in of the SAME org being resolved) before a
#: customer-safe refusal.
_SIGNIN_LOCK_WAIT_S = 10.0
#: How many times a request re-folds outside the shared section when its org's state changed meanwhile, before it
#: gives up with a retryable refusal (a fold never runs under the section).
_FOLD_ATTEMPTS = 3


#: How long an unauthenticated SSO leg waits for a slot of the provisioner's SSO work bound before a 503.
_SSO_GATE_WAIT_S = 5.0
_SSO_GATES: "dict[int, threading.BoundedSemaphore]" = {}
_SSO_GATES_GUARD = threading.Lock()


def _sso_gate_semaphore() -> "threading.BoundedSemaphore":
    """The process-wide bound on concurrent unauthenticated SSO work (`VIGIL_SSO_CONCURRENCY` slots)."""
    from .. import config
    n = max(1, int(config.SSO_CONCURRENCY))
    with _SSO_GATES_GUARD:
        return _SSO_GATES.setdefault(n, threading.BoundedSemaphore(n))


_SSO_ORG_GATES: "OrderedDict[tuple, list]" = OrderedDict()       # (org, n) -> [semaphore, holders + waiters]
_SSO_ORG_GATES_MAX = 4096


@contextmanager
def _sso_org_semaphore_ref(org_id: str) -> "Iterator[threading.BoundedSemaphore]":
    """One org's share of the SSO work bound (`VIGIL_SSO_ORG_CONCURRENCY` slots), referenced for the duration of the
    `with`. At most `_SSO_ORG_GATES_MAX` are kept: the least recently used one nobody references is forgotten first, so
    naming arbitrary org ids never grows this, and a share in use is never replaced."""
    from .. import config
    n = max(1, int(config.SSO_ORG_CONCURRENCY))
    key = (str(org_id or ""), n)
    with _SSO_GATES_GUARD:
        entry = _SSO_ORG_GATES.get(key)
        if entry is None:
            entry = _SSO_ORG_GATES[key] = [threading.BoundedSemaphore(n), 0]
        _SSO_ORG_GATES.move_to_end(key)
        entry[1] += 1
        if len(_SSO_ORG_GATES) > _SSO_ORG_GATES_MAX:
            for k in [k for k, e in _SSO_ORG_GATES.items() if e[1] == 0][:len(_SSO_ORG_GATES) - _SSO_ORG_GATES_MAX]:
                del _SSO_ORG_GATES[k]
    try:
        yield entry[0]
    finally:
        with _SSO_GATES_GUARD:
            entry[1] -= 1


def _sso_org_semaphore(org_id: str) -> "threading.BoundedSemaphore":
    """The org's share (tests take it directly)."""
    with _sso_org_semaphore_ref(org_id) as sem:
        return sem


@contextmanager
def _sso_gate(org_id: str = "") -> Iterator[None]:
    """One slot of the provisioner's bound on concurrent UNAUTHENTICATED SSO work (the CPU of a sign-in start, an
    assertion / id_token verification): first one of the ORG's own slots (`VIGIL_SSO_ORG_CONCURRENCY`, default 1 —
    an org's further requests wait in that org's own queue and never take another slot of the global bound), then one
    of the global slots (`VIGIL_SSO_CONCURRENCY`, default 4). A short wait for both together (`_SSO_GATE_WAIT_S`,
    blocked — not polling), then `ProvisionBusy` (503 + Retry-After). A network wait (the OIDC code exchange) and the
    replay ledger's reaping never hold a slot."""
    from .provision import ProvisionBusy
    deadline = time.monotonic() + _SSO_GATE_WAIT_S
    with _sso_org_semaphore_ref(org_id) as mine:
        if not mine.acquire(timeout=_SSO_GATE_WAIT_S):
            raise ProvisionBusy(_SSO_GATE_WAIT_S)
        try:
            gate = _sso_gate_semaphore()
            if not gate.acquire(timeout=max(0.0, deadline - time.monotonic())):
                raise ProvisionBusy(_SSO_GATE_WAIT_S)
            try:
                yield
            finally:
                gate.release()
        finally:
            mine.release()


class _LegCounter:
    """Guard-and-count per key in MEMORY: at most `limit` per fixed `window_s` window, O(1) per call and per key, and
    at most `max_keys` keys (the least recently seen is forgotten first). The unauthenticated SSO legs are counted
    here rather than on disk: an on-disk limiter sweeps its whole directory on every count, and a flood from many
    addresses would make that sweep — serialized for every caller — the cost of every other organization's
    sign-in."""

    def __init__(self, *, window_s: float = 60.0, max_keys: int = 65536) -> None:
        from collections import OrderedDict
        self.window_s = float(window_s)
        self.max_keys = int(max_keys)
        self._lock = threading.Lock()
        self._keys: "OrderedDict[tuple, list]" = OrderedDict()

    def admit(self, key: tuple, *, limit: int, now: float) -> "Optional[float]":
        with self._lock:
            slot = self._keys.get(key)
            if slot is None or now - slot[0] >= self.window_s or now < slot[0]:
                slot = [now, 0]
            self._keys[key] = slot
            self._keys.move_to_end(key)
            while len(self._keys) > self.max_keys:
                self._keys.popitem(last=False)
            if slot[1] >= max(0, int(limit)):
                return max(1.0, slot[0] + self.window_s - now)
            slot[1] += 1
            return None


_LEGS = _LegCounter()


class _FailLock:
    """A per-key failure lockout in MEMORY (the SSO legs' per-(org, address) lockout): `max_fails` failures within
    `window_s` lock the key for `base_lock_s`, doubling on each further lockout up to `max_lock_s`; a success clears
    the key. O(1) per call, at most `max_keys` keys (the least recently seen forgotten first)."""

    def __init__(self, *, max_fails: int = 5, window_s: float = 900.0, base_lock_s: float = 60.0,
                 max_lock_s: float = 3600.0, max_keys: int = 65536) -> None:
        from collections import OrderedDict
        self.max_fails, self.window_s = int(max_fails), float(window_s)
        self.base_lock_s, self.max_lock_s, self.max_keys = float(base_lock_s), float(max_lock_s), int(max_keys)
        self._lock = threading.Lock()
        self._keys: "OrderedDict[tuple, list]" = OrderedDict()      # key -> [window start, fails, lock until, locks]

    def locked(self, key: tuple, *, now: float) -> "Optional[float]":
        with self._lock:
            slot = self._keys.get(key)
            if slot is not None and slot[2] > now:
                return slot[2] - now
            return None

    def record_failure(self, key: tuple, *, now: float) -> None:
        with self._lock:
            slot = self._keys.get(key)
            if slot is None or now - slot[0] >= self.window_s or now < slot[0]:
                slot = [now, 0, slot[2] if slot else 0.0, slot[3] if slot else 0]
            slot[1] += 1
            if slot[1] >= self.max_fails:
                slot[3] += 1
                slot[2] = now + min(self.base_lock_s * (2 ** (slot[3] - 1)), self.max_lock_s)
                slot[0], slot[1] = now, 0
            self._keys[key] = slot
            self._keys.move_to_end(key)
            while len(self._keys) > self.max_keys:
                self._keys.popitem(last=False)

    def record_success(self, key: tuple) -> None:
        with self._lock:
            self._keys.pop(key, None)


_SSO_FAILS = _FailLock()


#: RFC 6052 NAT64 well-known prefix: an IPv4 host reached through a NAT64 / SIIT front arrives as
#: ``64:ff9b::<a.b.c.d>``, so its last 32 bits ARE the client's own IPv4 — a whole /64 of it is NOT one client.
_NAT64_WELLKNOWN = "64:ff9b::/96"


def _embedded_ipv4(addr) -> "Optional[str]":
    """The IPv4 a single client owns inside an IPv4-mapped (``::ffff:a.b.c.d``) or NAT64 well-known
    (``64:ff9b::a.b.c.d``) IPv6 address, else None — so independent IPv4 clients reaching the edge through one
    translation front keep their own key instead of collapsing into one /64."""
    import ipaddress
    if getattr(addr, "version", None) != 6:
        return None
    if addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    if addr in ipaddress.ip_network(_NAT64_WELLKNOWN):
        return str(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    return None


def _client_key(ip: str) -> str:
    """The address a per-client SSO / SCIM VOLUME count is kept under (the coarse, anti-abuse key): the IPv6 /64 a
    single client controls (one host is routinely given a whole /64), or the IPv4 address — but the IPv4 EMBEDDED in
    an IPv4-mapped or NAT64 well-known address (`_embedded_ipv4`), so a shared translation front does not collapse many
    independent clients into one /64; anything else as given."""
    import ipaddress
    raw = str(ip or "").strip()
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if addr.version == 6:
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            return embedded
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def _lockout_key(ip: str) -> str:
    """The address the SSO failure LOCKOUT is counted under — a single client's FULL address, NEVER a shared /64 or
    translation front: the IPv4 embedded in an IPv4-mapped / NAT64 well-known address (`_embedded_ipv4`), else the full
    IPv6 address, else the IPv4 address. A lockout is long-lived and an org's IdP decides what a lured browser posts,
    so collapsing independent clients into one lockout key would let one org's failures deny unrelated clients; paired
    with the per-(spine, org) lockout scope, an org's IdP can lock out only its OWN sign-ins, and only from exactly the
    address the failures came from."""
    import ipaddress
    raw = str(ip or "").strip()
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if addr.version == 6:
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            return embedded
    return str(addr)


def _ident(p) -> str:
    try:
        return str(Path(p.store.path).resolve())
    except Exception:  # noqa: BLE001 — a store without a path still gets one bucket per address
        return ""


def _fail_key(p, org_id: str, ip: str) -> tuple:
    """The SSO failure-lockout key: per (spine, ORG, full client address). Scoped to the org so one org's IdP
    failures lock only that org's sign-ins, and to the FULL address (`_lockout_key`) so a shared /64 or NAT64 front is
    never locked as one — the two properties that keep a hostile org's IdP from denying an unrelated network's SSO."""
    return (_ident(p), str(org_id or ""), _lockout_key(ip))


def _sso_client_guard(p, ip: str, *, org_id: str, now: float) -> None:
    """Refuse an address this ORG's SSO failure lockout has locked (`_SSO_FAILS`, per (spine, org, address)), before
    anything else. Another org's lockout of the same address never refuses here."""
    from .provision import ProvisionRateLimited
    wait = _SSO_FAILS.locked(_fail_key(p, org_id, ip), now=now)
    if wait is not None:
        raise ProvisionRateLimited(wait)


def _sso_client_failed(p, ip: str, *, org_id: str, now: float) -> None:
    _SSO_FAILS.record_failure(_fail_key(p, org_id, ip), now=now)


def _sso_client_ok(p, ip: str, *, org_id: str) -> None:
    _SSO_FAILS.record_success(_fail_key(p, org_id, ip))


class _AuditWindows:
    """At most ONE spine row per (spine, org, action, reason) per `window_s`, for refusals an unauthenticated client
    can provoke: the first refusal of a window is written (carrying how many the previous window suppressed), the
    rest are counted only. So such refusals grow the spine by a constant per org per window, whatever the number of
    requests or addresses."""

    def __init__(self, *, window_s: float = 60.0, max_keys: int = 65536) -> None:
        from collections import OrderedDict
        self.window_s, self.max_keys = float(window_s), int(max_keys)
        self._lock = threading.Lock()
        self._keys: "OrderedDict[tuple, list]" = OrderedDict()      # key -> [window start, suppressed]

    def admit(self, key: tuple, *, now: float) -> "Optional[int]":
        """None ⇒ suppress (counted); else write now, reporting the previous window's suppressed count."""
        with self._lock:
            slot = self._keys.get(key)
            if slot is not None and 0 <= now - slot[0] < self.window_s:
                slot[1] += 1
                return None
            prev = slot[1] if slot is not None else 0
            self._keys[key] = [now, 0]
            self._keys.move_to_end(key)
            while len(self._keys) > self.max_keys:
                self._keys.popitem(last=False)
            return prev


_AUDIT_WINDOWS = _AuditWindows()


def _bounded_audit(p, action: str, *, org_id: str, reason: str, now: float, **fields) -> None:
    """A refusal audit row an unauthenticated client can provoke, bounded to one per org per minute (`_AuditWindows`);
    the row names how many the previous minute suppressed."""
    prev = _AUDIT_WINDOWS.admit((_ident(p), str(org_id or ""), action, reason), now=now)
    if prev is None:
        return
    p._audit(action, org_id=org_id, reason=reason if not prev else f"{reason} (+{prev} in the previous minute)",
             **fields)


def _count_unauthenticated_leg(p, ip: str, *, now: float) -> None:
    """GUARD-AND-COUNT one unauthenticated SSO leg (start, ACS, OIDC callback) for the client IP, successes included
    (`VIGIL_SSO_REQUESTS_PER_IP_PER_MIN` per minute, per spine): over it ⇒ `ProvisionRateLimited`, before any spine
    read. Counted in this process's memory (`_LegCounter`; the provisioner process is the only one serving these
    legs, and a restart only forgets the current minute)."""
    from .. import config
    from .provision import ProvisionRateLimited
    wait = _LEGS.admit((_ident(p), _client_key(ip)), limit=config.SSO_REQUESTS_PER_IP_PER_MIN, now=now)
    if wait is not None:
        raise ProvisionRateLimited(wait)


def _registries(p):
    """The owner-signed SSO config registry + the SCIM directory, over the provisioner's spine and owner key. The
    config registry reads through the verified incremental fold cache (`cached=True`): an unauthenticated sign-in
    start, ACS, OIDC callback or SCIM request then costs the records appended since the last read, never a fold of
    the whole spine (with its owner-key-history scan)."""
    from ..governor.scim_directory import ScimDirectoryRegistry
    from ..governor.sso_config import SsoConfigRegistry
    cfg = SsoConfigRegistry(p.store, owner_key=p.orgs.owner_key, trusted_pubkey=p.orgs.trusted_pubkey, cached=True)
    directory = ScimDirectoryRegistry(p.store, owner_key=p.orgs.owner_key, trusted_pubkey=p.orgs.trusted_pubkey,
                                      cached=True)
    return cfg, directory


def _orgs(p):
    """The org + membership registry the SSO / SCIM paths read: the provisioner's, through the verified incremental
    fold cache (`force_cache`), so the org and membership folds cost the records appended since the last read."""
    from ..governor.orgs import OrgRegistry
    orgs = OrgRegistry(p.orgs.store, owner_key=p.orgs.owner_key, trusted_pubkey=p.orgs.trusted_pubkey)
    orgs.force_cache = True
    return orgs


def _org(org_id) -> str:
    """The org id EXACTLY as relayed when it is a well-formed tenant id, else "" (selects no config, so every leg
    refuses): never trimmed into a well-formed one."""
    oid = str(org_id or "")
    return oid if _TENANT_RE.fullmatch(oid) else ""


@contextmanager
def _membership_section(p) -> Iterator[None]:
    """The critical section of every membership change (`ui.provision._members_section`): the process-wide spine
    lock, then the cross-process membership flock — never waiting on the flock while holding the spine lock (a
    bounded wait without it, then `LockBusy` with nothing written; a nested entry is refused at once)."""
    from .provision import _members_section
    with _members_section(p._lock, p.store):
        yield


_ORG_THREAD_LOCKS: "dict[str, threading.Lock]" = {}
_ORG_THREAD_LOCKS_GUARD = threading.Lock()


@contextmanager
def _org_lock(p, org_id: str, kind: str, *, wait_s: float = _ORG_LOCK_WAIT_S) -> Iterator[None]:
    """ONE org's own cross-process lock (`kind` "write", "read" or "signin"): an flock on
    ``<spine dir>/<stem>.scim-orgs/<kind>-<sha256(org)>.lock`` (`*.lock` transients the backups skip), taken BEFORE
    the shared section and never while holding it (lock order: this -> `spine_lock` -> the membership flock). A
    bounded wait, then `LockBusy`. Another org's lock is a different file, so it never waits on this one.

    In front of the flock sits an in-process lock per file: requests of this process WAIT on it (blocked, not
    polling), so a queue of one org's requests costs other orgs nothing while it waits; the flock (polled by
    `locked_file`) then only ever waits for another process."""
    from vigil_integration.live.seam_lock import LockBusy, locked_file
    raw = getattr(p.store, "path", None)
    if not raw:
        raise ValueError("the per-org SCIM lock needs a spine store with a path")
    sp = Path(raw)
    d = sp.parent / f"{sp.stem or sp.name}.scim-orgs"
    d.mkdir(mode=0o700, exist_ok=True)
    digest = hashlib.sha256(f"{kind}\x00{org_id}".encode("utf-8")).hexdigest()[:32]
    path = d / f"{kind}-{digest}.lock"
    with _ORG_THREAD_LOCKS_GUARD:
        tl = _ORG_THREAD_LOCKS.setdefault(str(path.resolve()), threading.Lock())
    deadline = time.monotonic() + max(0.0, float(wait_s))
    if not (tl.acquire(timeout=float(wait_s)) if wait_s > 0 else tl.acquire(blocking=False)):
        raise LockBusy(f"lock busy after {float(wait_s):g}s: {path.name}")
    try:
        with locked_file(path, wait_s=max(0.0, deadline - time.monotonic()), create=False, chown_like=d):
            yield
    finally:
        tl.release()


def _handoff() -> None:
    """The pause between two holds of the shared section: a request waiting for it is handed the lock."""
    time.sleep(_HANDOFF_S)


def _anchor(store):
    """The spine's last record as (seq, entry_hash) — read from the tail of the active segment, O(1) — or None when
    that is undecidable."""
    try:
        last = store._read_last_entry()
    except Exception:  # noqa: BLE001 — undecidable: the caller treats the state as changed
        return None
    return (last.seq, last.entry_hash) if last is not None else (-1, "")


def _records_since(store, anchor):
    """The records appended after `anchor` — read from the END of the active segment (`tail_after`, O(new records),
    no seq index built on a per-request store), else through the index; None when the anchor no longer holds (a
    rollback / rewrite)."""
    if anchor is None:
        return None
    seq, entry_hash = anchor
    tail = getattr(store, "tail_after", None)
    if tail is not None and seq >= 0:
        recs = tail(seq, entry_hash)
        if recs is False:
            return None
        if recs is not None:
            return recs
    return store.iter_records(since_seq=seq)


def _org_state_changed(store, org_id: str, anchor, member_ok=None) -> bool:
    """True iff a record after `anchor` (`_anchor`) can change what a request of `org_id` folded: an org, SSO-config or
    SCIM-directory record of that org, a membership record of that org (only one `member_ok(username, payload)`
    calls relevant, when given), or an owner-key-history record (it moves every signature window). An anchor that is
    undecidable or no longer holds counts as a change."""
    from ..governor.key_history import KEY_HISTORY_KIND
    from ..governor.orgs import MEMBERSHIP_SIGNAL, ORG_SIGNAL
    from ..governor.scim_directory import SCIM_DIRECTORY_SIGNAL
    from ..governor.sso_config import SSO_CONFIG_SIGNAL
    signals = (MEMBERSHIP_SIGNAL, ORG_SIGNAL, SSO_CONFIG_SIGNAL, SCIM_DIRECTORY_SIGNAL)
    records = _records_since(store, anchor)
    if records is None:
        return True
    for r in records:
        if r.kind == KEY_HISTORY_KIND:
            return True
        pl = r.payload
        if not (isinstance(pl, dict) and pl.get("signal") in signals and pl.get("org_id") == org_id):
            continue
        if pl.get("signal") == MEMBERSHIP_SIGNAL and member_ok is not None \
                and not member_ok(str(pl.get("username") or ""), pl):
            continue
        return True
    return False


def _scim_member(username: str, _payload: dict) -> bool:
    """A SCIM request only ever acts on directory users (their ids are `sso_...`), so a membership record of another
    member of the org (a Team-screen act on a password or Google member) cannot change what it folded."""
    return username.startswith("sso_")


class _SharedSection:
    """The shared membership critical section (`_membership_section`: `p._lock`, then the membership flock) as a
    SCIM request of one org uses it — entered in BOUNDED HOLDS (`ui.scim` paces the request: at most
    `ui.scim.MAX_RECORDS_PER_HOLD` records per hold), with the request's folds run outside it:

      * `fold(fn)`: note the spine tip, run `fn` (the folds) WITHOUT the section, take it, and keep the result only
        if no record of this org's state was appended since the tip (`_org_state_changed`) — else re-fold (bounded),
        finally under the section;
      * `slice()`: between two holds — release, hand the lock over (`_HANDOFF_S`), re-take, and raise
        `ui.scim.SectionLost` when it cannot be re-taken (the flock's bounded wait) or this org's state changed while
        it was released (the request then stops in the safe order; see `ui.scim._group_change`).

    The caller holds its org's own lock (`_org_lock`) throughout, so no other SCIM write of the org runs between two
    holds; `holds` counts the holds taken (tests read it)."""

    def __init__(self, p, org_id: str, *, member_filter=None) -> None:
        self.p = p
        self.org_id = org_id
        self.records = 0                       # what the request appended (ui.scim sets it)
        self.holds = 0
        self._flock: "Optional[AbstractContextManager]" = None
        # `member_filter(folded value) -> member_ok(username, payload)`: which membership records of the org can change
        # what this request folded (None: all of them)
        self._member_filter = member_filter
        self._member_ok = None

    @property
    def held(self) -> bool:
        return self._flock is not None

    def _enter(self) -> None:
        from vigil_integration.live.seam_lock import LockBusy

        from .provision import _members_section
        from .scim import SectionLost
        cm = _members_section(self.p._lock, self.p.store)
        try:
            cm.__enter__()
        except LockBusy as e:
            raise SectionLost("the membership critical section is busy") from e
        self._flock = cm
        self.holds += 1

    def _exit(self) -> None:
        cm, self._flock = self._flock, None
        if cm is not None:
            cm.__exit__(None, None, None)

    def fold(self, fn):
        """Run `fn` (the folds) OUTSIDE the section, take it, and return the result while HOLDING it — only when
        nothing of this org's state was appended since the fold began; else fold again, up to `_FOLD_ATTEMPTS`
        times, then `SectionLost` (a retryable refusal). A fold never runs under the section."""
        from .scim import SectionLost
        store = self.p.store
        for _attempt in range(_FOLD_ATTEMPTS):
            t0 = _anchor(store)
            if t0 is None:
                break
            value = fn()
            self._member_ok = self._member_filter(value) if self._member_filter is not None else None
            self._enter()
            if not _org_state_changed(store, self.org_id, t0, self._member_ok):
                return value
            self._exit()
        raise SectionLost("this organization's state kept changing while the request read it; retry")

    def slice(self) -> None:
        from .scim import SectionLost
        tip = _anchor(self.p.store)
        self._exit()
        _handoff()
        self._enter()
        if tip is None or _org_state_changed(self.p.store, self.org_id, tip, self._member_ok):
            raise SectionLost("this organization's membership state changed while the request was paused")

    def outside(self, fn):
        """Run `fn` — pure computation over what the request folded (a group change's plan, `ui.scim._Req.outside`)
        — with the section RELEASED, then re-take it; `SectionLost` (as `slice`) when it cannot be re-taken or this
        org's state changed meanwhile, so a plan that is returned still holds. Work proportional to an org is never
        done while holding the lock every org's membership change (and every spine append of the process) takes."""
        from .scim import SectionLost
        if self._flock is None:
            return fn()
        tip = _anchor(self.p.store)
        self._exit()
        try:
            value = fn()
        finally:
            self._enter()
        if tip is None or _org_state_changed(self.p.store, self.org_id, tip, self._member_ok):
            raise SectionLost("this organization's state changed while the request was planning")
        return value

    def close(self) -> None:
        self._exit()


def _critical_audit(p, org_id: str):
    """The audit hook `ui.scim` calls BEFORE each membership grant / revoke: a critical row (fail-closed)."""
    def audit(action: str, target: str, outcome: str) -> None:
        p._audit(action, requester="idp", org_id=org_id, target=target, outcome=outcome, critical=True)
    return audit


def _resume_pending_jobs(p, org_id: str, cfgreg, directory, *, now: float) -> None:
    """At a sign-in of a directory-managed org: finish the org's pending group jobs (`ui.scim.resume_directory_jobs`)
    — in bounded holds, under the org's own lock, charged to its write budget — so a group change a crash cut short
    does not wait for the IdP's next write. Only when that lock is FREE (a SCIM write of the org in flight finishes
    the job itself), and best effort: whatever it cannot do, the sign-in's own clamp still keeps the person at or
    below the role the directory implies."""
    from . import scim as uiscim
    from .provision import members_section_held
    if members_section_held():          # never nested inside a held section (its flock would wait on itself)
        return
    try:
        with _org_lock(p, org_id, "write", wait_s=0.0):
            section = _SharedSection(p, org_id, member_filter=lambda _v: _scim_member)
            try:
                uiscim.resume_directory_jobs(org_id=org_id, config_registry=cfgreg, org_registry=_orgs(p), now=now,
                                             directory_registry=directory, issued_at_fn=p._next_issued,
                                             audit=_critical_audit(p, org_id), section=section)
            finally:
                section.close()
                if section.records > 0 and p.scim_write_limiter is not None:
                    p.scim_write_limiter.charge(f"scim:writes:{org_id}", section.records, now=now)
    except Exception:  # noqa: BLE001 — best effort (busy lock, audit store down, ...): the sign-in decides alone
        return


def sso_login_start(p, org_id: str, *, ip: str = "", now: Optional[float] = None) -> dict:
    """What the edge needs to send the browser to the org's IdP: the protocol and the IdP sign-in endpoint from the
    org's OWNER-SIGNED config (never a secret). Refused unless the org is active and has an active config."""
    from .provision import ProvisionDenied
    t = p._now() if now is None else float(now)
    oid = _org(org_id)
    _sso_client_guard(p, ip, org_id=oid, now=t)
    _count_unauthenticated_leg(p, ip, now=t)
    cfgreg, _ = _registries(p)
    with _sso_gate(oid):                                   # all of the leg's spine reads, inside the org's share
        cfg = cfgreg.config(oid) if oid else None
        active = cfg is not None and _orgs(p).org(oid) is not None
    if not active or cfg is None:
        raise ProvisionDenied("single sign-on is not set up for this organization")
    if cfg.protocol == "saml":
        if not cfg.idp_sso_url:
            raise ProvisionDenied("this organization's SAML sign-in has no IdP sign-in URL (owner setup)")
        return {"protocol": "saml", "org_id": oid, "idp_sso_url": cfg.idp_sso_url,
                "sp_entity_id": cfg.sp_entity_id, "acs_url": cfg.acs_url}
    return {"protocol": "oidc", "org_id": oid, "client_id": cfg.oidc_client_id,
            "authorize_endpoint": cfg.oidc_authorize_endpoint, "redirect_uri": cfg.oidc_redirect_uri,
            "scopes": OIDC_SCOPES}


def _decode_saml_response(saml_response: object) -> bytes:
    s = re.sub(r"\s+", "", str(saml_response or ""))       # IdPs may fold the base64 across lines
    if not s or len(s) > MAX_SAML_RESPONSE_B64:
        raise ValueError("missing or oversize SAMLResponse")
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("SAMLResponse is not base64") from e


def sso_saml_acs(p, org_id: str, saml_response: str, *, request_id: str, ip: str = "",
                 now: Optional[float] = None) -> dict:
    """The SAML ACS tail: verify the IdP's Response for the org the edge's single-use login state names, BOUND to
    that login's AuthnRequest (`request_id` ⇒ the signed InResponseTo), then resolve the member (JIT, or linked
    to the SCIM directory) through `_admit_sign_in` (the org's sign-in budget, its sign-in lock, the folds outside
    the shared section). The signature backend is `ui.saml`'s default — it FAILS CLOSED without a vetted XML-DSig
    library, so with none installed every SAML sign-in is refused here (never bypassed)."""
    from . import scim as uiscim
    from .provision import ProvisionDenied, ProvisionError
    t = p._now() if now is None else float(now)
    oid = _org(org_id)
    _sso_client_guard(p, ip, org_id=oid, now=t)
    _count_unauthenticated_leg(p, ip, now=t)
    if p.saml_replay is None:
        raise ProvisionError("SAML sign-in is not available on this deployment (no replay ledger)")
    cfgreg, directory = _registries(p)
    try:
        if not oid or not str(request_id or ""):
            raise ValueError("no org / AuthnRequest to bind the response to")
        try:
            with _sso_gate(oid):                           # the whole unauthenticated work, inside the org's share
                _sign_in_budget_open(p, oid, ip=ip, now=t, reason="saml")
                if cfgreg.config(oid) is None:
                    raise ValueError("no SSO config for this organization")
                xml = _decode_saml_response(saml_response)
                signin = uiscim.verify_saml_sign_in(xml, org_id=oid, config_registry=cfgreg,
                                                    replay_ledger=p.saml_replay, now=t,
                                                    expected_request_id=str(request_id))
        finally:
            # the replay ledger's reaping: AFTER the gate is released, bounded per call (single-flight per org), on
            # every outcome — a partition at capacity frees its expired markers even while its spends are refused
            try:
                p.saml_replay.maintain(oid, now=t)
            except OSError:
                pass                                       # housekeeping only: never masks the sign-in's outcome
    except (uiscim.SsoLoginError, ValueError):
        _sso_client_failed(p, ip, org_id=oid, now=t)
        _bounded_audit(p, "sso_login", org_id=oid, reason="saml", outcome="denied", now=t)
        raise ProvisionDenied("single sign-on could not be verified")
    try:
        res = _admit_sign_in(p, oid, signin, cfgreg, directory, now=t, reason="saml")
    except uiscim.SsoLoginError:
        _sso_client_failed(p, ip, org_id=oid, now=t)
        p._audit("sso_login", org_id=oid, outcome="denied", reason="saml")
        raise ProvisionDenied("single sign-on could not be verified")
    _sso_client_ok(p, ip, org_id=oid)
    p._audit("sso_login", requester=res.username, org_id=oid, target=res.username, outcome="ok", reason="saml")
    return {"username": res.username, "org_id": res.org_id}


def _sign_in_budget_open(p, org_id: str, *, ip: str, now: float, reason: str) -> None:
    """Refuse — before any verification, so nothing is spent (the assertion stays unused) — a sign-in of an org whose
    sign-in budget (`VIGIL_SSO_SIGNINS_PER_MIN`) is spent. Only VERIFIED sign-ins spend it (`_admit_sign_in`), so
    nobody but the org's own IdP can exhaust it. The refusal is counted against (this org, the client address)
    (`_SSO_FAILS`) and audited at most once per org per minute (`_bounded_audit`): such a request is not yet
    authenticated, so it must not grow the spine per request. No budget wired ⇒ refused (fail-closed)."""
    from .provision import ProvisionDenied
    lim = getattr(p, "sso_signin_limiter", None)
    wait = lim.locked(f"sso:org:{org_id}", now=now) if lim is not None else 60.0
    if wait is not None:
        _sso_client_failed(p, ip, org_id=org_id, now=now)
        _bounded_audit(p, "sso_login", org_id=org_id, reason=f"{reason}:org_rate", outcome="denied", now=now)
        raise ProvisionDenied("too many sign-ins to this organization right now; try again in a minute")


def _sign_in_member_filter(org_id: str):
    """Which membership records of the org can change what a sign-in folded: the SSO members (the person signing in
    is one) and any record that can change who administers the org (the clamp's last-administrator rule) — a record
    granting a role that manages members, or re-roling / revoking someone the fold saw holding one."""
    from vigil_core.rbac import role_can

    def make(value):
        orgs = value[1]

        def ok(username: str, payload: dict) -> bool:
            if username.startswith("sso_"):
                return True
            if payload.get("state") != "active" or role_can(str(payload.get("role") or ""), "manage_members"):
                return True
            held = orgs.membership_role(username, org_id)
            return bool(held) and role_can(held, "manage_members")
        return ok
    return make


def _admit_sign_in(p, org_id: str, signin, cfgreg, directory, *, now: float, reason: str):
    """Mint (or link) the member a VERIFIED sign-in names, bounded so one org's sign-ins cannot stall another org:
      * the org's sign-in budget is SPENT here, after verification (guard-and-count, `VIGIL_SSO_SIGNINS_PER_MIN` per
        minute; over it ⇒ a customer-safe refusal, nothing minted, not counted against the client IP);
      * the org's sign-ins are resolved ONE AT A TIME (its own sign-in lock, `_org_lock(..., "signin")`; a bounded
        wait, then the same refusal) — verification above runs concurrently, it folds no membership or directory;
      * an open pending group job of the org is finished first (`_resume_pending_jobs`);
      * the config / membership / directory folds run OUTSIDE the shared membership critical section
        (`_SharedSection.fold`), which is then taken, re-checked for any change of this org's state, and held for
        the at most 3 records a sign-in appends (`ui.scim.admit_verified_sign_in`)."""
    from . import scim as uiscim
    from .provision import ProvisionDenied
    lim = getattr(p, "sso_signin_limiter", None)
    busy = "too many sign-ins to this organization right now; try again in a minute"
    lock = _held(_org_lock(p, org_id, "signin", wait_s=_SIGNIN_LOCK_WAIT_S))
    if lock is None:
        _bounded_audit(p, "sso_login", org_id=org_id, reason=f"{reason}:org_busy", outcome="denied", now=now)
        raise ProvisionDenied(busy)
    with lock:
        # the budget is spent INSIDE the org's sign-in lock: one of its sign-ins at a time touches the shared limiter
        if lim is None or lim.admit(f"sso:org:{org_id}", now=now) is not None:
            _bounded_audit(p, "sso_login", org_id=org_id, reason=f"{reason}:org_rate", outcome="denied", now=now)
            raise ProvisionDenied(busy)
        section = _SharedSection(p, org_id, member_filter=_sign_in_member_filter(org_id))
        try:
            return uiscim.admit_verified_sign_in(
                signin, config_registry=cfgreg, org_registry=_orgs(p), issued_at=p._next_issued(),
                directory_registry=directory, audit=_critical_audit(p, org_id), section=section,
                resume=lambda: _resume_pending_jobs(p, org_id, cfgreg, directory, now=now))
        except uiscim.SectionLost:
            raise ProvisionDenied(busy) from None
        finally:
            section.close()


def _oidc_transport(p, cfg):
    """The token-exchange + JWKS transport, leg by leg: a test-injected hook where one is set, else that leg of the
    HOST-ALLOWLISTED https transport over the owner-signed `oidc_egress_hosts` (an empty allowlist refuses every
    egress — fail-closed). A leg without a hook is never left to the unpinned stdlib default."""
    from .oidc import host_allowlisted_transport
    post, fetch = host_allowlisted_transport(cfg.oidc_egress_hosts)
    return (p.sso_oidc_http_post or post), (p.sso_oidc_jwks_fetcher or fetch)


def sso_oidc_finish(p, org_id: str, *, code: str, code_verifier: str, nonce: str, ip: str = "",
                    now: Optional[float] = None) -> dict:
    """The enterprise-OIDC callback tail (the edge already proved the single-use state + the browser binding): the
    PKCE code exchange at the org's owner-signed token endpoint, the id_token verified against its JWKS (both only
    through the owner-signed egress allowlist), then the member resolved (JIT, or linked to the SCIM directory)."""
    from . import oidc as _oidc
    from . import scim as uiscim
    from .provision import ProvisionDenied
    from .provision import ProvisionRateLimited
    t = p._now() if now is None else float(now)
    oid = _org(org_id)
    _sso_client_guard(p, ip, org_id=oid, now=t)
    _count_unauthenticated_leg(p, ip, now=t)
    cfgreg, directory = _registries(p)
    with _sso_gate(oid):
        _sign_in_budget_open(p, oid, ip=ip, now=t, reason="oidc")
        cfg = cfgreg.config(oid) if oid else None
    try:
        if cfg is None or cfg.protocol != "oidc":
            raise uiscim.SsoLoginError("no active enterprise-OIDC config for this organization")
        poster, fetcher = _oidc_transport(p, cfg)
        oc = _oidc.OidcConfig(issuer=cfg.oidc_issuer, client_id=cfg.oidc_client_id, client_secret="",
                              redirect_uri=cfg.oidc_redirect_uri, authorize_endpoint=cfg.oidc_authorize_endpoint,
                              token_endpoint=cfg.oidc_token_endpoint, jwks_uri=cfg.oidc_jwks_uri,
                              scopes=OIDC_SCOPES, username_claim="sub", signing_algs=cfg.oidc_signing_algs,
                              clock_skew_seconds=cfg.clock_skew_seconds)
        tokens = _oidc.exchange_code(oc, code, code_verifier=code_verifier, http_post=poster)
        keys = _oidc.JwksProvider(oc.jwks_uri, fetcher=fetcher).keys(now=t)
        with _sso_gate(oid):
            signin = uiscim.verify_oidc_sign_in(tokens["id_token"], org_id=oid, config_registry=cfgreg,
                                                jwks_keys=keys, expected_nonce=str(nonce or ""), now=t)
    except ProvisionRateLimited:        # the SSO work bound (busy): retryable, not a failed sign-in
        raise
    except Exception:  # noqa: BLE001 — a refused token or an IdP/network fault: one fail-closed denial
        _sso_client_failed(p, ip, org_id=oid, now=t)
        _bounded_audit(p, "sso_login", org_id=oid, reason="oidc", outcome="denied", now=t)
        raise ProvisionDenied("single sign-on could not be verified")
    try:
        res = _admit_sign_in(p, oid, signin, cfgreg, directory, now=t, reason="oidc")
    except ProvisionDenied:
        raise
    except Exception:  # noqa: BLE001 — a non-member or a refused grant: the same fail-closed denial
        _sso_client_failed(p, ip, org_id=oid, now=t)
        p._audit("sso_login", org_id=oid, outcome="denied", reason="oidc")
        raise ProvisionDenied("single sign-on could not be verified")
    _sso_client_ok(p, ip, org_id=oid)
    p._audit("sso_login", requester=res.username, org_id=oid, target=res.username, outcome="ok", reason="oidc")
    return {"username": res.username, "org_id": res.org_id}


def _scim_refusal(status: int, detail: str, *, retry_after: float = 0.0) -> dict:
    from .scim import _error
    out: dict = {"status": status, "body": _error(status, detail), "deactivated": []}
    if retry_after:
        out["retry_after"] = int(max(1, math.ceil(retry_after)))
    return out


def scim_request(p, org_id: str, *, method: str, path: str, query: str = "", body=None, authorization: str = "",
                 ip: str = "", now: Optional[float] = None) -> dict:
    """One SCIM 2.0 request for the org in the edge's path, answered as {status, body, deactivated[,
    retry_after]} — the edge returns `status`/`body` to the IdP verbatim and severs the sessions of every username
    in `deactivated`. Authentication is the org's owner-signed bearer fingerprint (constant-time). Then (see the
    module docstring for every bound):
      * a body over a per-request bound is refused 400 before anything is taken;
      * a READ takes the org's read lock (bounded wait, else 429), spends one unit of the org's read budget
        (`VIGIL_SCIM_READS_PER_MIN`; 429 + Retry-After when spent) and folds lock-free — it never enters the shared
        membership critical section;
      * a WRITE takes the org's write lock (bounded wait, else 429), and INSIDE it is admitted by the org's write
        budget (one unit; skipped for a request that can only take privilege away, `ui.scim.lowers_only`), runs in
        bounded holds of the shared section (`_SharedSection`, `ui.scim.MAX_RECORDS_PER_HOLD` records per hold),
        and is charged in a `finally` for every further record it appended, also when it fails part-way.

    FAILED authentications count against (org, client IP) AND against the client IP across every org id; past either
    limit, further INVALID attempts are refused 429 without another audit row. A failure is audited on the spine
    only for an org that has a SCIM bearer — so the spine grows by at most the per-IP limit's failures per window and
    per address, and never for an org id with no SCIM config (answered the same 401). A VALID bearer is never refused by that lock: an IdP's
    SCIM egress addresses are shared by every tenant of that IdP, so a lock that also stopped the valid token
    would let anyone with an account at the same IdP stall this org's DEPROVISIONING (an offboarded employee
    keeping access) by spraying wrong tokens from the shared address. A success therefore does not clear the
    count either (legitimate traffic never re-opens an attacker's quota). Guessing is bounded by the token
    (>= 256 random bits from `sigil sso`)."""
    from . import scim as uiscim
    from ..governor.scim import authenticate_scim, bearer_from_authorization_header
    t = p._now() if now is None else float(now)
    m = str(method or "").upper()
    if m not in _SCIM_METHODS:
        return _scim_refusal(405, f"{m or 'the method'} is not a SCIM method")
    reads = getattr(p, "scim_read_limiter", None)
    deprov_cap = getattr(p, "scim_deprov_limiter", None)
    deprov_floor = getattr(p, "scim_deprov_floor_limiter", None)
    if getattr(p, "scim_auth_limiter", None) is None or getattr(p, "scim_write_limiter", None) is None \
            or reads is None or deprov_cap is None or deprov_floor is None:
        return _scim_refusal(503, "SCIM is not available on this deployment")
    oid = _org(org_id)
    cfgreg, directory = _registries(p)
    cfg = cfgreg.config(oid) if oid else None
    if not authenticate_scim(cfg, bearer_from_authorization_header(authorization)):
        # per (org, client IP) AND per client IP across EVERY org id: rotating the org id in the path never escapes
        client = _client_key(ip)
        keys = (f"scim:auth:{oid}:{client}", f"scim:auth-ip:{client}")
        locked = p.scim_auth_limiter.check(*keys, now=t)
        if locked is not None:
            return _scim_refusal(429, "too many failed SCIM authentications; wait and retry", retry_after=locked)
        for k in keys:
            p.scim_auth_limiter.record_failure(k, now=t)
        if cfg is not None and cfg.scim_enabled:
            # audited only for an org that HAS a SCIM bearer, and at most the per-IP limit's failures per window
            # before that address is locked out — an org id with no SCIM config gets no spine record at all (and the
            # same 401: the answer never tells whether the org exists)
            _bounded_audit(p, "scim_auth", org_id=oid, reason="", outcome="denied", now=t)
        return _scim_refusal(401, "SCIM authentication failed")
    over = uiscim.request_bound_refusal(m, path, body)
    if over is not None:                   # refused on its body alone: no lock taken, no budget spent
        return {"status": over.status, "body": over.body, "deactivated": []}

    def dispatch(section, lower_only: bool = False) -> "uiscim.ScimResult":
        return uiscim.scim_dispatch(m, path, body, authorization, org_id=oid, config_registry=cfgreg,
                                    org_registry=_orgs(p), now=t, query=str(query or ""),
                                    directory_registry=directory, issued_at_fn=p._next_issued,
                                    audit=_critical_audit(p, oid), section=section, lower_only=lower_only)
    busy = _scim_refusal(429, "another SCIM request of this organization is in progress; retry shortly",
                         retry_after=_ORG_LOCK_WAIT_S)
    if m not in _SCIM_WRITES:
        lock = _held(_org_lock(p, oid, "read"))
        if lock is None:
            return busy
        with lock:
            wait = reads.admit(f"scim:reads:{oid}", now=t)
            if wait is not None:
                return _scim_refusal(429, "this organization's SCIM read rate is exceeded; retry shortly",
                                     retry_after=wait)
            r = dispatch(None)               # lock-free: a read appends nothing and never enters the shared section
        return {"status": r.status, "body": r.body, "deactivated": list(r.deactivated)}
    budget = f"scim:writes:{oid}"
    lock = _held(_org_lock(p, oid, "write"))
    if lock is None:
        return busy
    deprov = f"scim:deprov:{oid}"
    with lock:
        lowers = uiscim.lowers_only(m, path, body)
        if lowers:                           # its own, much higher cap — never the write budget's debt
            wait = deprov_cap.locked(deprov, now=t)
            if wait is not None:             # over the cap: still ONE a minute (an offboarding always progresses)
                floor = deprov_floor.admit(f"scim:deprov-floor:{oid}", now=t)
                if floor is not None:
                    return _scim_refusal(429, "this organization's deprovisioning rate is exceeded; retry shortly",
                                         retry_after=min(wait, floor))
            try:                             # held to LOWERING ONLY (`ui.scim.lowers_only`)
                r = _charged_write(p, oid, dispatch, lower_only=True, now=t)
                return {"status": r.status, "body": r.body, "deactivated": list(r.deactivated)}
            except uiscim.NeedsWriteBudget:
                pass                         # it authors more than a deactivation: the write budget decides
        wait = p.scim_write_limiter.admit(budget, now=t)       # checked AND (below) charged inside the org's lock
        if wait is not None:
            return _scim_refusal(429, "this organization's SCIM write rate is exceeded; retry shortly",
                                 retry_after=wait)
        r = _charged_write(p, oid, dispatch, lower_only=False, now=t)
    return {"status": r.status, "body": r.body, "deactivated": list(r.deactivated)}


def _charged_write(p, oid: str, dispatch, *, lower_only: bool, now: float):
    """Run one SCIM write in bounded holds of the shared section and charge — in a `finally`, so also when it fails
    part-way — every record it appended to the write budget (beyond the one unit `admit` counted for a budgeted
    write), and, for a deprovisioning request (`lower_only`, admitted without the write budget), also to the
    deprovisioning cap (at least one unit, also when it appended nothing)."""
    section = _SharedSection(p, oid, member_filter=lambda _v: _scim_member)
    try:
        return dispatch(section, lower_only)
    finally:
        section.close()
        owed = section.records - (0 if lower_only else 1)       # a budgeted write's `admit` counted one unit
        if owed > 0:
            p.scim_write_limiter.charge(f"scim:writes:{oid}", owed, now=now)
        if lower_only:
            p.scim_deprov_limiter.charge(f"scim:deprov:{oid}", max(1, section.records), now=now)


@contextmanager
def _entered(cm) -> Iterator[None]:
    try:
        yield
    finally:
        cm.__exit__(None, None, None)


def _held(cm):
    """`cm` (an `_org_lock`) entered, as a context manager that releases it — or None when it stayed busy."""
    from vigil_integration.live.seam_lock import LockBusy
    try:
        cm.__enter__()
    except LockBusy:
        return None
    return _entered(cm)
