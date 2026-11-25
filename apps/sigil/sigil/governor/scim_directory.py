"""Consumer PR-H (Area 7) — the OWNER-SIGNED per-org SCIM DIRECTORY (users, groups, group-membership edges).

A real IdP (Okta, Entra ID, ...) drives SCIM 2.0 as a RECONCILIATION protocol: it asks "does `userName eq x`
exist?", reads a user back by the `id` we returned, patches a group's `members`, and expects what it wrote to be
what it later reads. That needs per-org state the membership fold does not carry — the IdP's `userName` /
`externalId` / profile for each provisioned user, the IdP's groups, and which users sit in which group. This
module is that state, kept on the spine as OWNER-SIGNED records (the provisioner is the only writer; it holds
the owner key — the same single key custody as `governor.orgs`).

THE DIRECTORY IS BOOKKEEPING, NEVER AUTHORITY. Nothing here grants anything: the authority is the owner-signed,
ceiling-capped MEMBERSHIP minted by `governor.scim.provision_membership` (viewer / analyst / org_admin only). The
directory only feeds role SELECTION (`governor.scim.resolve_role` over the user's group names, every candidate
clamped to the owner-signed config's cap and the ceiling) — so even a forged directory record could at most
select among roles the owner already signed into that org's config. Records are still owner-signed and
LWW-high-water guarded (the codebase discipline for any record a fold trusts), so a forged or replayed record is
inert:

  * every record (user / group / member edge, active or deleted) must verify under the owner key valid AT ITS
    SEQ (`key_history.key_resolver(...).at(seq)`), else it is skipped;
  * the per-(org, rtype, rid) `issued_at` must STRICTLY exceed that key's high-water, so re-appending a captured
    older record (e.g. "user U is in group admins" after U was removed) is refused.

ORG-SCOPED BY CONSTRUCTION: every record carries its `org_id` inside the signed core and a directory view is
built for ONE org; an id from another org's directory never resolves here. User ids are the stable per-org
`governor.scim.sso_username` (`sso_<24 hex>`, namespaced by org + IdP + the IdP's id for the user), group ids are
server-minted `grp_<24 hex>`, and an edge id is `<group id>|<user id>` — all charset-fixed, so no IdP-supplied
string ever becomes a record key.

DELETE CASCADES: deleting a user also deletes every edge to that user (its id is deterministic, so a later
re-create must start in no group); deleting a group deletes its edges.

PENDING GROUP JOBS (`job` records, keyed by the group id): a group change too large to land within one hold of the
shared membership critical section (`ui.scim`) is announced by an owner-signed job record naming the change's
END STATE (the group's name and externalId plus its final member list, or its member delta, or "deleted") BEFORE
its first membership record, and closed by a deleted job record once every record of it has landed. A job still
open after a crash, or after the request was cut short, is what the org's NEXT SCIM write or sign-in finishes
(`ui.scim.resume_directory_jobs`). A job names only state the provisioner itself staged from an authenticated
request; it is folded like every other record here (owner-signed, LWW), and a malformed one is inert.

HARD-PRUNE RESIDUAL (the same honest boundary `governor.sso_config` documents): this fold scans from genesis with
no snapshot seed, so a hard prune below these records would forget them. That residual can only make the
directory FORGET users/groups (the IdP then re-creates them — SCIM is idempotent by design); it can never mint or
widen a membership, which stays the owner-signed, snapshot-seeded `governor.orgs` fold.

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix` (`assert_no_offense()` at import).
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Optional, cast

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (owner-key-succession-aware resolver, mirrors orgs._fold_*)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402  (the verified incremental fold cache)
from ..spine.fold_cache import FoldCache  # noqa: E402

# Dedicated payload signal under the enforced generic `kind="event"` governor record (mirrors sso_config).
SCIM_DIRECTORY_SIGNAL = "governor.scim_directory"

# The authenticated core of every record — `data` (the bounded attribute object) is INSIDE it, so a signed
# record can never be re-aimed (org_id / rtype / rid), flipped (state), re-stamped (issued_at) or have its
# attributes rewritten without breaking the signature.
_DIR_CORE = ("signal", "org_id", "rtype", "rid", "state", "issued_at", "data")

RTYPES = ("user", "group", "member", "job")
_STATES = ("active", "deleted")

# Charset-fixed ids (never an IdP-supplied string): the per-org user id is `governor.scim.sso_username`'s form.
_USER_ID_RE = re.compile(r"sso_[0-9a-f]{24}")
_GROUP_ID_RE = re.compile(r"grp_[0-9a-f]{24}")
_EDGE_ID_RE = re.compile(r"(grp_[0-9a-f]{24})\|(sso_[0-9a-f]{24})")
# Mirrors orgs._TENANT_RE (org_id == tenant_id); a lockstep test keeps them equal.
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# Bounds on the IdP-supplied attributes a record may carry (the record is signed and lives on the spine forever).
MAX_ATTR = 256                 # userName / externalId / displayName / one selector
MAX_SELECTORS = 64             # role selectors (group / role names) carried on a User resource
MAX_PROFILE_BYTES = 4096       # the echoed-back profile (name + emails), canonical JSON
MAX_JOB_MEMBERS = 4096         # user ids one pending group job may list (the writer lists at most ~1000)


class DirectoryError(ValueError):
    """A fail-closed directory write refusal (bad id, oversize attribute, no owner key)."""


def _id_ok(rtype: str, rid: str) -> bool:
    if rtype == "user":
        return bool(_USER_ID_RE.fullmatch(rid))
    if rtype == "group":
        return bool(_GROUP_ID_RE.fullmatch(rid))
    if rtype == "member":
        return bool(_EDGE_ID_RE.fullmatch(rid))
    if rtype == "job":                     # a pending group change, keyed by the group it changes
        return bool(_GROUP_ID_RE.fullmatch(rid))
    return False


def username_key(user_name: str) -> "tuple[str, str]":
    """What two SCIM `userName`s are compared by (userName is caseExact=false): the name under BOTH the full lower-
    and the full upper-case mapping, so two names match iff they differ ONLY by letter case. Unlike `casefold()` (or
    either mapping alone) it never equates a look-alike with the letter it resembles — KELVIN SIGN vs `K` (its
    uppercase is itself), LONG S vs `s` (their lowercases differ), `ß` vs `ss`, a ligature vs its letters, dotted or
    dotless `i` vs `i` — so a DIFFERENT IdP account whose name merely looks like a member's can neither be linked
    to that member at sign-in nor collide with it in the directory. Whitespace is never trimmed either: an identifier
    that begins or ends with whitespace (any Unicode space) is refused at every entry — the SCIM write, the SAML
    NameID, the OIDC sub — and matches nobody here (`_exact_key`), so a padded look-alike is never trimmed INTO a
    member's identifier."""
    s = str(user_name or "")
    return s.lower(), s.upper()


def _exact_key(value: object) -> str:
    """A lookup key used EXACTLY as given: "" (matches nobody) when it is blank or begins or ends with whitespace."""
    s = str(value or "")
    return s if s.strip() and s == s.strip() else ""


def edge_id(group_id: str, user_id: str) -> str:
    """The record id of the edge "user `user_id` is a member of group `group_id`"."""
    return f"{group_id}|{user_id}"


def _clean_str(value: object, what: str, *, required: bool = False) -> str:
    """A bounded, control-free attribute string (fail-closed). Never used as a path or a key."""
    s = str(value or "").strip() if not isinstance(value, (dict, list)) else ""
    if not s:
        if required:
            raise DirectoryError(f"{what} is required")
        return ""
    if len(s) > MAX_ATTR:
        raise DirectoryError(f"{what} is longer than {MAX_ATTR} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        raise DirectoryError(f"{what} must not contain control characters")
    return s


def _clean_selectors(values) -> list:
    out: list = []
    for v in values or ():
        s = _clean_str(v, "role selector")
        if s and s not in out:
            out.append(s)
    if len(out) > MAX_SELECTORS:
        raise DirectoryError(f"at most {MAX_SELECTORS} role selectors per user")
    return out


def _clean_profile(profile: object) -> dict:
    """The echoed-back profile: only `name` (string sub-attributes) and `emails` (value/type/primary), bounded. An
    IdP compares what it reads back with what it wrote; storing these keeps a re-sync from re-writing forever."""
    if not isinstance(profile, dict):
        return {}
    out: dict = {}
    name = profile.get("name")
    if isinstance(name, dict):
        nm = {}
        for k in ("formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"):
            v = name.get(k)
            if isinstance(v, str) and v.strip():
                nm[k] = _clean_str(v, f"name.{k}")
        if nm:
            out["name"] = nm
    emails = profile.get("emails")
    if isinstance(emails, list):
        em = []
        for e in emails[:10]:
            if isinstance(e, dict) and isinstance(e.get("value"), str) and e["value"].strip():
                item = {"value": _clean_str(e["value"], "emails.value")}
                if isinstance(e.get("type"), str) and e["type"].strip():
                    item["type"] = _clean_str(e["type"], "emails.type")
                if isinstance(e.get("primary"), bool):
                    item["primary"] = e["primary"]
                em.append(item)
        if em:
            out["emails"] = em
    if len(json.dumps(out, sort_keys=True, separators=(",", ":"))) > MAX_PROFILE_BYTES:
        raise DirectoryError(f"the user profile exceeds {MAX_PROFILE_BYTES} bytes")
    return out


@dataclass(frozen=True)
class DirectoryUser:
    org_id: str
    id: str                        # the stable per-org id == the membership username (sso_<24 hex>)
    user_name: str                 # the IdP's userName (mutable; unique per org, case-insensitive)
    external_id: str               # the IdP's own id for the user (may be "")
    display_name: str
    active: bool                   # SCIM `active` — False ⇒ the membership is revoked
    selectors: tuple               # role selectors carried on the User resource (groups/roles values)
    profile: dict = field(default_factory=dict)
    issued_at: float = 0.0
    # The sign-in CLAMP's bookkeeping (`ui.scim`): (the role the clamp took away, the issued_at of the membership
    # grant the clamp minted), or () — never an IdP-supplied value, and never authority: it only lets a later
    # sign-in give back what the clamp took while that grant is still the live one.
    clamp: tuple = ()


@dataclass(frozen=True)
class DirectoryGroup:
    org_id: str
    id: str                        # server-minted grp_<24 hex>
    display_name: str              # matched against the owner-signed group_role_map (role SELECTION only)
    external_id: str
    issued_at: float = 0.0


def _clamp_from(value: object) -> tuple:
    """The clamp bookkeeping of a user record — (took, at) — or () for none. A malformed value is no record (the
    give-back it would allow then never applies: the fail-safe direction)."""
    if not isinstance(value, dict):
        return ()
    took, at = value.get("from"), value.get("at")
    if not isinstance(took, str) or not took or len(took) > MAX_ATTR:
        return ()
    if isinstance(at, bool) or not isinstance(at, (int, float)) or not math.isfinite(at):
        return ()
    return (took, float(at))


def _user_from(org_id: str, rid: str, data: dict, at: float) -> Optional[DirectoryUser]:
    try:
        return DirectoryUser(
            org_id=org_id, id=rid, user_name=_clean_str(data.get("userName"), "userName", required=True),
            external_id=_clean_str(data.get("externalId"), "externalId"),
            display_name=_clean_str(data.get("displayName"), "displayName"),
            active=data.get("active") is True, selectors=tuple(_clean_selectors(data.get("selectors"))),
            profile=_clean_profile(data.get("profile")), issued_at=at, clamp=_clamp_from(data.get("clamp")))
    except (DirectoryError, TypeError, AttributeError):
        return None


def _group_from(org_id: str, rid: str, data: dict, at: float) -> Optional[DirectoryGroup]:
    try:
        return DirectoryGroup(org_id=org_id, id=rid,
                              display_name=_clean_str(data.get("displayName"), "displayName", required=True),
                              external_id=_clean_str(data.get("externalId"), "externalId"), issued_at=at)
    except (DirectoryError, TypeError, AttributeError):
        return None


def _job_since(data: dict) -> "Optional[float]":
    """A job's re-role window start (`since`, a finite issued_at >= 0), 0.0 when absent, None when malformed."""
    since = data.get("since", 0.0)
    if isinstance(since, bool) or not isinstance(since, (int, float)) or not math.isfinite(since) or since < 0:
        return None
    return float(since)


def _job_from(data: object) -> Optional[dict]:
    """A pending group job's END STATE, normalized, or None for a malformed record (inert): {"delete": True}, or
    {"delete": False, "name", "ext"} plus either "members" (the final member list) or "add" / "remove" (the member
    delta against the group as it stands) — and, optionally, "touch": users whose role a deprovisioning request left
    to a budgeted write (re-resolved when the job is finished), and/or "rerole": True when they were more than a job
    may list (`MAX_JOB_MEMBERS`) — then every user whose membership EDGE of the job's group was written at or after
    the job's window start "since" (an issued_at; 0.0 when absent) is re-resolved when the job is finished: exactly
    the members the deferring requests removed from (or deleted with) the group, never the rest of the org."""
    if not isinstance(data, dict):
        return None
    rerole = data.get("rerole")
    if rerole is not None and rerole is not True:
        return None
    since = _job_since(data) if rerole else None
    if rerole and since is None:
        return None
    if data.get("delete") is True:
        touch = data.get("touch")
        out: dict = {"delete": True}
        if touch is not None:
            if not isinstance(touch, list) or len(touch) > MAX_JOB_MEMBERS \
                    or any(not isinstance(x, str) or not _USER_ID_RE.fullmatch(x) for x in touch):
                return None
            out["touch"] = sorted(set(touch))
        if rerole:
            out["rerole"] = True
            out["since"] = since
        return out
    try:
        out = {"delete": False, "name": _clean_str(data.get("name"), "name", required=True),
                     "ext": _clean_str(data.get("ext"), "ext")}
    except (DirectoryError, TypeError):
        return None
    for k in ("members", "add", "remove", "touch"):
        v = data.get(k)
        if v is None:
            continue
        if not isinstance(v, list) or len(v) > MAX_JOB_MEMBERS \
                or any(not isinstance(x, str) or not _USER_ID_RE.fullmatch(x) for x in v):
            return None
        out[k] = sorted(set(v))
    if "members" in out and ("add" in out or "remove" in out):
        return None
    if rerole:
        out["rerole"] = True
        out["since"] = since
    return out


class OrgDirectory:
    """ONE org's directory, folded once and then kept in step with this view's own (owner-signed) writes, so a
    multi-step SCIM request reads what it wrote without re-scanning the spine. Every write appends an
    owner-signed record whose `issued_at` strictly exceeds its key's high-water (so it is honored by any later
    fold) and SKIPS the append when nothing changed (a re-sync does not grow the spine)."""

    def __init__(self, registry: "ScimDirectoryRegistry | _Journal", org_id: str, *, users: dict, groups: dict,
                 edges: set, highwater: dict, jobs: Optional[dict] = None) -> None:
        self._reg = registry
        self.org_id = org_id
        self._users: "dict[str, DirectoryUser]" = users
        self._groups: "dict[str, DirectoryGroup]" = groups
        self._edges: "set[tuple[str, str]]" = edges
        self._hw: "dict[tuple[str, str], float]" = highwater
        self._jobs: "dict[str, dict]" = dict(jobs or {})
        self._dir_writes = 0               # directory records (all but job records) written through this view
        self._shared = False               # True while this view reads a shared read-only snapshot (`over`)
        self._by_group: "dict[str, set[str]]" = {}
        self._by_user: "dict[str, set[str]]" = {}
        self._index()

    @classmethod
    def over(cls, registry: "ScimDirectoryRegistry", org_id: str, snap: _DirSnapshot) -> "OrgDirectory":
        """A view READING the cached fold's shared read-only snapshot `snap` (`_OrgFold.snapshot`) — built in O(1)
        (its edge index is the snapshot's, derived once per snapshot) — that takes its own copy of the containers on
        its first write (`_own`), so nothing it writes ever reaches the snapshot another reader holds."""
        self = cls.__new__(cls)
        self._reg = registry
        self.org_id = org_id
        by_group, by_user = snap.index()
        # read-only mappings / frozensets: any write path that skipped `_own` raises instead of corrupting the snapshot
        self._users = cast("dict[str, DirectoryUser]", snap.users)
        self._groups = cast("dict[str, DirectoryGroup]", snap.groups)
        self._edges = cast("set[tuple[str, str]]", snap.edges)
        self._hw = cast("dict[tuple[str, str], float]", snap.hw)
        self._jobs = cast("dict[str, dict]", snap.jobs)
        self._by_group = cast("dict[str, set[str]]", by_group)
        self._by_user = cast("dict[str, set[str]]", by_user)
        self._dir_writes = 0
        self._shared = True
        return self

    def _own(self) -> None:
        """Before this view's first write: replace the shared read-only snapshot it reads (`over`) with its own
        mutable copy (O(the org), once per writing view — a write is budgeted; a read never pays it)."""
        if not self._shared:
            return
        self._users = dict(self._users)
        self._groups = dict(self._groups)
        self._edges = set(self._edges)
        self._hw = dict(self._hw)
        self._jobs = {g: _copy_job(dict(j)) for g, j in self._jobs.items()}
        self._by_group = {g: set(m) for g, m in self._by_group.items()}
        self._by_user = {u: set(m) for u, m in self._by_user.items()}
        self._shared = False

    def _index(self) -> None:
        """The edges indexed both ways, so a group's members / a user's groups are read in time proportional to
        THEIR edges, never to every edge of the org (a request touching many members stays linear)."""
        self._by_group = {}
        self._by_user = {}
        for g, u in self._edges:
            self._by_group.setdefault(g, set()).add(u)
            self._by_user.setdefault(u, set()).add(g)

    # -- reads --------------------------------------------------------------------------------------------
    def users(self) -> "list[DirectoryUser]":
        return [self._users[k] for k in sorted(self._users)]

    def user(self, user_id: str) -> Optional[DirectoryUser]:
        return self._users.get(str(user_id or ""))

    def user_by_name(self, user_name: str) -> Optional[DirectoryUser]:
        """The user whose userName equals `user_name` up to letter case ONLY (`username_key`: SCIM userName is
        caseExact=false, but a case-folding look-alike is a different name). `user_name` is compared as given, never
        trimmed: a blank one, or one that begins or ends with whitespace, matches nobody (`_exact_key`)."""
        want = _exact_key(user_name)
        if not want:
            return None
        key = username_key(want)
        return next((u for u in self.users() if username_key(u.user_name) == key), None)

    def user_by_external_id(self, external_id: str) -> Optional[DirectoryUser]:
        """The user whose externalId equals `external_id` EXACTLY (externalId is caseExact; never trimmed — a blank or
        padded one matches nobody)."""
        want = _exact_key(external_id)
        if not want:
            return None
        return next((u for u in self.users() if u.external_id == want), None)

    def users_by_external_id(self, external_id: str) -> "list[DirectoryUser]":
        """EVERY user whose externalId equals `external_id` exactly (same matching as `user_by_external_id`). A caller
        that admits a person by externalId must see more than one match as AMBIGUOUS, never pick one of them."""
        want = _exact_key(external_id)
        if not want:
            return []
        return [u for u in self.users() if u.external_id == want]

    def users_linked_by(self, identifier: str) -> "list[DirectoryUser]":
        """EVERY user a sign-in presenting `identifier` links to: the one whose userName it equals up to letter case
        only, and each whose externalId it equals exactly (the matching of `user_by_name` / `user_by_external_id`; a
        blank or padded identifier links nobody). A caller that admits a person must treat more than one as
        AMBIGUOUS, never pick one of them."""
        want = _exact_key(identifier)
        if not want:
            return []
        key = username_key(want)
        return [u for u in self.users() if username_key(u.user_name) == key or u.external_id == want]

    def users_sharing_a_sign_in_identifier(self, user_id: str, *, user_name: str,
                                           external_id: str = "") -> "frozenset[str]":
        """The ids of the OTHER users (never `user_id`) that one sign-in identifier would link to together with a
        user carrying `user_name` / `external_id` (`users_linked_by`): another user whose userName equals this
        userName or this externalId up to letter case, whose externalId equals this userName up to letter case, or
        whose externalId equals this externalId exactly. Any of them makes such a sign-in ambiguous."""
        out = {u.id for u in self.users_linked_by(external_id)}
        name = _exact_key(user_name)
        if name:
            key = username_key(name)
            out.update(u.id for u in self.users()
                       if username_key(u.user_name) == key or (u.external_id and username_key(u.external_id) == key))
        out.discard(str(user_id or ""))
        return frozenset(out)

    def groups(self) -> "list[DirectoryGroup]":
        return [self._groups[k] for k in sorted(self._groups)]

    def group(self, group_id: str) -> Optional[DirectoryGroup]:
        return self._groups.get(str(group_id or ""))

    def group_by_name(self, display_name: str) -> Optional[DirectoryGroup]:
        want = str(display_name or "").strip().casefold()
        if not want:
            return None
        return next((g for g in self.groups() if g.display_name.casefold() == want), None)

    def members(self, group_id: str) -> "list[str]":
        """The ids of the users in `group_id` (edges to a deleted user/group are never counted)."""
        if group_id not in self._groups:
            return []
        return sorted(u for u in self._by_group.get(group_id, ()) if u in self._users)

    def groups_of(self, user_id: str) -> "list[DirectoryGroup]":
        if user_id not in self._users:
            return []
        return [self._groups[g] for g in sorted(self._by_user.get(user_id, ())) if g in self._groups]

    def jobs(self) -> "dict[str, dict]":
        """The pending group jobs, {group id: end state} (see the module docstring) — copies, lists included."""
        return {g: _copy_job(dict(j)) for g, j in sorted(self._jobs.items())}

    def job_issued_at(self, group_id: str) -> float:
        """The issued_at of group `group_id`'s pending job record (0.0 when none) — the moment the job was last
        (re)opened. A resume leaves a deferred member whose LIVE membership grant is newer than this untouched, so an
        owner hand-change made after the job is not reverted by it."""
        return float(self._hw.get(("job", str(group_id or "")), 0.0))

    def edge_users_since(self, group_id: str, since: float) -> "set[str]":
        """The ids of the users whose membership EDGE of group `group_id` (added or removed) was last written at or
        after `since` — what a re-role job's window names (`_job_from`): the members a deferring request removed from,
        or deleted with, the group. A scan of this view's high-water map (no fold, no lock)."""
        prefix = f"{group_id}|"
        return {rid[len(prefix):] for (rtype, rid), at in self._hw.items()
                if rtype == "member" and at >= since and rid.startswith(prefix)}

    # -- writes (owner-signed; in-memory view kept in step) --------------------------------------------------
    def _fresh(self, rtype: str, rid: str, now: float) -> float:
        hw = self._hw.get((rtype, rid), NO_HIGHWATER)
        at = float(now)
        return at if at > hw else math.nextafter(hw, math.inf)

    def _write(self, rtype: str, rid: str, state: str, data: dict, *, now: float) -> int:
        self._own()                        # every write path appends through here BEFORE it touches a container
        at = self._fresh(rtype, rid, now)
        seq = self._reg._append(self.org_id, rtype, rid, state, data, issued_at=at)
        self._hw[(rtype, rid)] = at
        if rtype != "job":
            self._dir_writes += 1
        return seq

    def put_user(self, user_id: str, *, user_name: str, external_id: str = "", display_name: str = "",
                 active: bool, selectors=(), profile: Optional[dict] = None, clamp: tuple = (), now: float) -> bool:
        """Create or replace user `user_id` (with the sign-in clamp's bookkeeping `clamp` = (took, at), or () for
        none). Returns True iff a record was appended (False ⇒ already identical)."""
        if not _USER_ID_RE.fullmatch(str(user_id or "")):
            raise DirectoryError("a directory user id must be the per-org sso_ id")
        data = {"userName": _clean_str(user_name, "userName", required=True),
                "externalId": _clean_str(external_id, "externalId"),
                "displayName": _clean_str(display_name, "displayName"), "active": bool(active),
                "selectors": _clean_selectors(selectors), "profile": _clean_profile(profile or {})}
        if clamp:
            data["clamp"] = {"from": str(clamp[0]), "at": float(clamp[1])}
            if _clamp_from(data["clamp"]) != (str(clamp[0]), float(clamp[1])):
                raise DirectoryError("malformed clamp bookkeeping")
        cur = self._users.get(user_id)
        if cur is not None and _user_data(cur) == data:
            return False
        self._write("user", user_id, "active", data, now=now)
        self._users[user_id] = _user_from(self.org_id, user_id, data, self._hw[("user", user_id)])  # type: ignore[assignment]
        return True

    def delete_user(self, user_id: str, *, now: float, before_each=None) -> bool:
        """Delete user `user_id` and CASCADE-delete every edge to it. Returns True iff the user existed.
        `before_each()` (optional) is called before each record is appended."""
        if user_id not in self._users:
            return False
        for g in sorted(self._by_user.get(user_id, ())):
            if before_each is not None:
                before_each()
            self.remove_member(g, user_id, now=now)
        if before_each is not None:
            before_each()
        self._write("user", user_id, "deleted", {}, now=now)
        del self._users[user_id]
        return True

    def put_group(self, group_id: str, *, display_name: str, external_id: str = "", now: float) -> bool:
        if not _GROUP_ID_RE.fullmatch(str(group_id or "")):
            raise DirectoryError("a directory group id must be a server-minted grp_ id")
        data = {"displayName": _clean_str(display_name, "displayName", required=True),
                "externalId": _clean_str(external_id, "externalId")}
        cur = self._groups.get(group_id)
        if cur is not None and {"displayName": cur.display_name, "externalId": cur.external_id} == data:
            return False
        self._write("group", group_id, "active", data, now=now)
        self._groups[group_id] = _group_from(self.org_id, group_id, data, self._hw[("group", group_id)])  # type: ignore[assignment]
        return True

    def delete_group(self, group_id: str, *, now: float) -> "list[str]":
        """Delete group `group_id` (+ its edges). Returns the ids of the users who were in it."""
        if group_id not in self._groups:
            return []
        was = self.members(group_id)
        for u in sorted(self._by_group.get(group_id, ())):
            self.remove_member(group_id, u, now=now)
        self._write("group", group_id, "deleted", {}, now=now)
        del self._groups[group_id]
        return was

    def add_member(self, group_id: str, user_id: str, *, now: float) -> bool:
        if group_id not in self._groups or user_id not in self._users:
            return False
        if (group_id, user_id) in self._edges:
            return False
        self._write("member", edge_id(group_id, user_id), "active", {}, now=now)
        self._edges.add((group_id, user_id))
        self._by_group.setdefault(group_id, set()).add(user_id)
        self._by_user.setdefault(user_id, set()).add(group_id)
        return True

    def remove_member(self, group_id: str, user_id: str, *, now: float) -> bool:
        if (group_id, user_id) not in self._edges:
            return False
        self._write("member", edge_id(group_id, user_id), "deleted", {}, now=now)
        self._edges.discard((group_id, user_id))
        self._by_group.get(group_id, set()).discard(user_id)
        self._by_user.get(user_id, set()).discard(group_id)
        return True

    def put_job(self, group_id: str, spec: dict, *, now: float) -> bool:
        """Open (or restate) the pending job of group `group_id` with end state `spec`. True iff a record was
        appended (False ⇒ the same job is already open)."""
        job = _job_from(spec)
        if job is None or not _GROUP_ID_RE.fullmatch(str(group_id or "")):
            raise DirectoryError("malformed pending group job")
        if self._jobs.get(group_id) == job:
            return False
        self._write("job", group_id, "active", job, now=now)
        self._jobs[group_id] = job
        return True

    def finish_job(self, group_id: str, *, now: float) -> bool:
        """Close the pending job of group `group_id`. True iff one was open."""
        if group_id not in self._jobs:
            return False
        self._write("job", group_id, "deleted", {}, now=now)
        del self._jobs[group_id]
        return True

    # -- staging (a multi-record change is applied to a scratch copy, then committed in one step) ---------------
    def staged(self) -> "OrgDirectory":
        """A scratch copy of this view: it reads and writes exactly like this view, but its writes only JOURNAL the
        owner-signed records they would append (nothing reaches the spine) until `commit` replays them here. A
        caller computes what a change WILL make of the directory, acts on that first (e.g. lowers a role, with its
        audit), and only then commits — so a failure before the commit leaves the directory exactly as it was."""
        # a staged view is only ever made from a registry-backed one (a staged view is never staged again)
        return OrgDirectory(_Journal(cast("ScimDirectoryRegistry", self._reg), self), self.org_id, users=dict(self._users),
                            groups=dict(self._groups), edges=set(self._edges), highwater=dict(self._hw),
                            jobs=self.jobs())

    def commit(self, staged: "OrgDirectory", *, before_each=None) -> None:
        """Append, in order, every record `staged` (a `staged()` copy of THIS view, with no directory write here
        since — a pending-job record is not one) journaled — each with the issued_at it was stamped with — and fold
        each one into this view as it lands (`_fold_entity`), so this view ends exactly where `staged` was. The cost is
        the journaled records, never a copy of the org (a commit runs inside the shared membership section).
        `before_each()` (optional) is called before each record is appended."""
        journal = staged._reg
        if not isinstance(journal, _Journal) or journal.origin is not self or journal.base_writes != self._dir_writes:
            raise DirectoryError("a staged directory change commits only onto the unchanged view it was staged from")
        if journal.records:
            self._own()
        for org_id, rtype, rid, state, data, at in journal.records:
            if before_each is not None:
                before_each()
            self._reg._append(org_id, rtype, rid, state, data, issued_at=at)
            self._hw[(rtype, rid)] = at
            if rtype != "job":
                self._dir_writes += 1
            _fold_entity(self.org_id, rtype, rid, state, data, at, users=self._users, groups=self._groups,
                         edges=self._edges, jobs=self._jobs, by_group=self._by_group, by_user=self._by_user)
        journal.records = []
        journal.base_writes = self._dir_writes

    def journaled(self) -> int:
        """For a `staged()` copy: how many records `commit` would append (0 for a view that is not staged)."""
        journal = self._reg
        return len(journal.records) if isinstance(journal, _Journal) else 0

    def journaled_edges_from(self, group_id: str) -> Optional[float]:
        """For a `staged()` copy: the earliest issued_at among the membership-edge records of group `group_id` it has
        journaled (a re-role job's window start, `ui.scim`), or None when it journaled none (or is not staged)."""
        journal = self._reg
        if not isinstance(journal, _Journal):
            return None
        prefix = f"{group_id}|"
        ats = [at for _org, rtype, rid, _st, _d, at in journal.records if rtype == "member" and rid.startswith(prefix)]
        return min(ats) if ats else None

    def authored_writes(self) -> int:
        """For a `staged()` copy: how many of the records it has journaled AUTHOR state — every record except the
        first write, in this change, of a record that DELETES it. Such a delete undoes state that was already on the
        spine before the change (a delete is only ever journaled for a live record, so a key's first write being a
        delete means it was live in the view staged from); it is bounded by what earlier, separately budgeted writes
        put there. Everything else — a new edge, a rename, or a delete of something this same change wrote — is
        authored by the request itself. 0 for a view that is not staged."""
        journal = self._reg
        if not isinstance(journal, _Journal):
            return 0
        seen: "set[tuple[str, str]]" = set()
        authored = 0
        for _org, rtype, rid, state, _data, _at in journal.records:
            key = (rtype, rid)
            if key in seen or state != "deleted":
                authored += 1
            seen.add(key)
        return authored


class _Journal:
    """The registry stand-in of a `staged()` directory: records the owner-signed appends it is asked for (after the
    same record-key checks the real append makes) instead of writing them."""

    def __init__(self, base: "ScimDirectoryRegistry", origin: OrgDirectory) -> None:
        self.base, self.origin = base, origin
        self.base_writes = origin._dir_writes          # the origin's directory writes when this was staged
        self.records: "list[tuple]" = []

    def _append(self, org_id: str, rtype: str, rid: str, state: str, data: dict, *, issued_at: float) -> int:
        self.base._check_record(org_id, rtype, rid, state)
        self.records.append((org_id, rtype, rid, state, dict(data), float(issued_at)))
        return 0


def _user_data(u: DirectoryUser) -> dict:
    data = {"userName": u.user_name, "externalId": u.external_id, "displayName": u.display_name,
            "active": bool(u.active), "selectors": list(u.selectors), "profile": dict(u.profile)}
    if u.clamp:
        data["clamp"] = {"from": u.clamp[0], "at": u.clamp[1]}
    return data


def _directory_accept(r, resolver, hw: dict) -> "Optional[tuple[str, str, str, dict, float]]":
    """The (rtype, rid, state, data, issued_at) of record `r` when it is a well-formed, owner-signed directory record
    that beats its key's high-water in `hw` (which it then raises), else None (inert: unsigned / forged / wrong-epoch
    key / malformed / a replay or stale re-append). The caller has matched the org."""
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != SCIM_DIRECTORY_SIGNAL:
        return None
    rtype, rid, st = p.get("rtype"), p.get("rid"), p.get("state")
    if rtype not in RTYPES or st not in _STATES or not isinstance(rid, str) or not _id_ok(rtype, rid):
        return None
    if not verify_signed(p, _DIR_CORE, resolver.at(r.seq)):
        return None                                    # unsigned / forged / wrong-epoch key → inert
    at = as_issued_at(p.get("issued_at"))
    key = (rtype, rid)
    if at <= hw.get(key, NO_HIGHWATER):
        return None                                    # replay / stale re-append → refused
    hw[key] = at
    d = p.get("data")
    return rtype, rid, st, (d if isinstance(d, dict) else {}), at


def _directory_step(r, resolver, state: dict, data: dict, hw: dict) -> None:
    """Fold ONE record into one org's (state, data, hw) — the loop body of `ScimDirectoryRegistry.directory`'s full
    fold (the caller has matched the org)."""
    got = _directory_accept(r, resolver, hw)
    if got is not None:
        rtype, rid, st, d, at = got
        state[(rtype, rid)] = st
        data[(rtype, rid)] = (d, at)


def _fold_entity(oid: str, rtype: str, rid: str, st: str, d: dict, at: float, *, users: dict, groups: dict,
                 edges: set, jobs: dict, by_group: Optional[dict] = None, by_user: Optional[dict] = None) -> None:
    """Fold the effect of ONE accepted record of key (rtype, rid) into one org's parsed entities, in place: the key's
    entity is replaced by what this record makes of it (removed when it is deleted or does not parse). The entity of a
    key depends only on the LAST accepted record of that key, so folding every accepted record in order through this
    ends exactly where `_parse_active` over the final (state, data) does — the incremental form of that parse, used by
    the cached fold (O(1) per record) and by `OrgDirectory.commit` (O(the records committed)). `by_group` / `by_user`
    (an `OrgDirectory`'s edge index), when given, are kept in step."""
    if rtype == "user":
        users.pop(rid, None)
        u = _user_from(oid, rid, d, at) if st == "active" else None
        if u is not None:
            users[rid] = u
    elif rtype == "group":
        groups.pop(rid, None)
        g = _group_from(oid, rid, d, at) if st == "active" else None
        if g is not None:
            groups[rid] = g
    elif rtype == "job":
        jobs.pop(rid, None)
        j = _job_from(d) if st == "active" else None
        if j is not None:
            jobs[rid] = j
    else:
        m = _EDGE_ID_RE.fullmatch(rid)
        if not m:
            return
        g_id, u_id = m.group(1), m.group(2)
        if st == "active":
            edges.add((g_id, u_id))
            if by_group is not None and by_user is not None:
                by_group.setdefault(g_id, set()).add(u_id)
                by_user.setdefault(u_id, set()).add(g_id)
        else:
            edges.discard((g_id, u_id))
            if by_group is not None and by_user is not None:
                by_group.get(g_id, set()).discard(u_id)
                by_user.get(u_id, set()).discard(g_id)


def _parse_active(oid: str, state: dict, data: dict) -> tuple:
    """One org's folded (state, data) as FRESH (users, groups, edges, jobs): the per-record parse of the ACTIVE
    records. Never a reference into the fold's state."""
    users: dict = {}
    groups: dict = {}
    edges: set = set()
    jobs: dict = {}
    for (rtype, rid), st in state.items():
        if st == "active":
            d, at = data[(rtype, rid)]
            _fold_entity(oid, rtype, rid, st, d, at, users=users, groups=groups, edges=edges, jobs=jobs)
    return users, groups, edges, jobs


def _materialize(oid: str, state: dict, data: dict, hw: dict) -> tuple:
    """One org's folded (state, data, hw) as FRESH (users, groups, edges, highwater, jobs) — never a reference into
    the fold's state (an `OrgDirectory` is mutated by its own writes)."""
    users, groups, edges, jobs = _parse_active(oid, state, data)
    return users, groups, edges, dict(hw), jobs


def _copy_job(j: dict) -> dict:
    return {k: (list(v) if isinstance(v, list) else v) for k, v in j.items()}


class _DirSnapshot:
    """ONE org's directory as of one state of its cached fold, READ-ONLY and SHARED by every reader until that org's
    fold changes (`_OrgFold.snapshot`): read-only mappings and frozensets over copies the fold no longer touches, so a
    write through a view built on it must take its own copy first (`OrgDirectory._own`) — a missed one raises instead
    of reaching another reader. The edge index (both ways) is derived from it at most once, by the first reader that
    needs it, OUTSIDE the fold cache's entry lock (`index`)."""

    __slots__ = ("users", "groups", "edges", "hw", "jobs", "_by")

    def __init__(self, users: dict, groups: dict, edges: set, hw: dict, jobs: dict) -> None:
        self.users = MappingProxyType(dict(users))
        self.groups = MappingProxyType(dict(groups))
        self.edges = frozenset(edges)
        self.hw = MappingProxyType(dict(hw))
        self.jobs = MappingProxyType({g: MappingProxyType(_copy_job(j)) for g, j in jobs.items()})
        self._by: "Optional[tuple]" = None

    def index(self) -> tuple:
        """(by_group, by_user): the edges indexed both ways, behind read-only mappings — computed once per snapshot
        (two readers racing compute the same value; either one is kept), at the cost one view's own index has
        (`OrgDirectory._index`). The member sets inside are not re-frozen (that would double the cost): a view never
        writes them before `_own` has replaced them with its own copies."""
        by = self._by
        if by is None:
            by_group: "dict[str, set[str]]" = {}
            by_user: "dict[str, set[str]]" = {}
            for g, u in self.edges:
                by_group.setdefault(g, set()).add(u)
                by_user.setdefault(u, set()).add(g)
            by = self._by = (MappingProxyType(by_group), MappingProxyType(by_user))
        return by


class _OrgFold:
    """ONE org's cached directory fold, kept PARSED: the high-water map plus the entities (`_fold_entity`), updated
    record by record — and MEMOISED for reading: `snapshot()` hands every reader the same read-only `_DirSnapshot`
    until a record of this org is folded (`invalidate`), so an unchanged directory is read in O(1) and a changed one
    costs ONE copy of its containers, never a re-parse. The memo lives outside the slots (`__dict__`): it is derived
    from them, so the S0d rebuild-and-compare audit (which compares the slots by value) ignores it."""

    __slots__ = ("hw", "users", "groups", "edges", "jobs", "__dict__")

    def __init__(self) -> None:
        self.hw: "dict[tuple[str, str], float]" = {}
        self.users: "dict[str, DirectoryUser]" = {}
        self.groups: "dict[str, DirectoryGroup]" = {}
        self.edges: "set[tuple[str, str]]" = set()
        self.jobs: "dict[str, dict]" = {}
        self.memo: "Optional[_DirSnapshot]" = None

    def snapshot(self) -> _DirSnapshot:
        """The org's directory as folded so far, read-only (runs under the fold cache's entry lock): the memo when
        nothing of this org was folded since it was taken, else ONE copy of the containers (C-level) — never a
        reference into the containers later records extend in place."""
        snap = self.memo
        if snap is None:
            snap = self.memo = _DirSnapshot(self.users, self.groups, self.edges, self.hw, self.jobs)
        return snap

    def invalidate(self) -> None:
        self.memo = None


class _DirectoryView:
    """The cached directory fold of EVERY org: org id -> its parsed fold (`_OrgFold`) — exactly what `directory` folds
    for it. Every field folds deterministically from the records, so the S0d rebuild-and-compare audit
    (`FoldCache.audit`) compares it whole."""

    __slots__ = ("orgs",)

    def __init__(self) -> None:
        self.orgs: "dict[str, _OrgFold]" = {}


_EMPTY_SNAPSHOT = _DirSnapshot({}, {}, set(), {}, {})


def _read_cached(view: _DirectoryView, oid: str) -> _DirSnapshot:
    """ONE org's directory from the cached fold `view` (runs under the fold cache's entry lock, which every org's
    directory read takes): its memoised read-only snapshot — O(1) while the org is unchanged, ONE copy of its
    already-parsed containers after a change; never a re-parse, and nothing of any other org."""
    folded = view.orgs.get(oid)
    return folded.snapshot() if folded is not None else _EMPTY_SNAPSHOT


def _directory_cache_step(view: _DirectoryView, r, resolver) -> None:
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != SCIM_DIRECTORY_SIGNAL:
        return
    oid = p.get("org_id")
    if not isinstance(oid, str) or not oid:
        return
    folded = view.orgs.get(oid)
    if folded is None:
        folded = view.orgs[oid] = _OrgFold()
    got = _directory_accept(r, resolver, folded.hw)
    if got is not None:
        folded.invalidate()
        _fold_entity(oid, *got, users=folded.users, groups=folded.groups, edges=folded.edges, jobs=folded.jobs)


_DIRECTORY_FOLD = FoldCache("governor.scim_directory", step=_directory_cache_step)


class ScimDirectoryRegistry:
    """The owner-signed SCIM directory on the spine. Construction mirrors `OrgRegistry` / `SsoConfigRegistry`:
    the owner signing key + trusted pubkey default to the persisted owner identity; tests inject keypairs.
    `cached=True` reads through the verified incremental fold cache (the SSO / SCIM provisioner paths)."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None, cached: bool = False):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
        self.appended = 0                  # owner-signed records this registry has appended (a request's cost)
        self.cached = bool(cached)

    def _check_record(self, org_id: str, rtype: str, rid: str, state: str) -> None:
        if self.owner_key is None:
            raise DirectoryError("a SCIM directory write requires the owner signing key")
        if not _TENANT_RE.fullmatch(str(org_id or "")) or rtype not in RTYPES or state not in _STATES \
                or not _id_ok(rtype, rid):
            raise DirectoryError("malformed SCIM directory record key")

    def _append(self, org_id: str, rtype: str, rid: str, state: str, data: dict, *, issued_at: float) -> int:
        self._check_record(org_id, rtype, rid, state)
        core = {"signal": SCIM_DIRECTORY_SIGNAL, "org_id": org_id, "rtype": rtype, "rid": rid, "state": state,
                "issued_at": float(issued_at), "data": dict(data)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"SCIM directory {rtype} {state} (owner-signed)"}
        seq = self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        self.appended += 1
        return seq

    def directory(self, org_id: str) -> OrgDirectory:
        """Fold the spine into ONE org's directory view (owner-key-succession-aware, LWW high-water per
        (org, rtype, rid); unsigned / forged / stale / malformed records are inert). With `cached` the fold is the
        verified incremental fold cache's (`fold_read.cached_read(force=True)`): a read then costs the records
        appended since the last one, and hands back this org's memoised read-only snapshot (O(1) while the org is
        unchanged; one copy of its state after a change) — never a re-parse, nor a re-verification of the spine."""
        oid = str(org_id or "")
        if self.cached:
            hit = cached_read(_DIRECTORY_FOLD, self.store, trusted_pubkey=self.trusted_pubkey,
                              seed=lambda snap: (_DirectoryView(), -1), live_window=True, force=True,
                              reader=lambda v: _read_cached(v, oid))
            if hit is not _UNCACHED:
                return OrgDirectory.over(self, oid, hit)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: "dict[tuple[str, str], str]" = {}
        data: "dict[tuple[str, str], tuple[dict, float]]" = {}
        hw: "dict[tuple[str, str], float]" = {}
        for r in self.store.iter_records():
            p = r.payload
            if isinstance(p, dict) and p.get("org_id") == oid:
                _directory_step(r, resolver, state, data, hw)
        users, groups, edges, hw, jobs = _materialize(oid, state, data, hw)
        return OrgDirectory(self, oid, users=users, groups=groups, edges=edges, highwater=hw, jobs=jobs)
