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
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (owner-key-succession-aware resolver, mirrors orgs._fold_*)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

# Dedicated payload signal under the enforced generic `kind="event"` governor record (mirrors sso_config).
SCIM_DIRECTORY_SIGNAL = "governor.scim_directory"

# The authenticated core of every record — `data` (the bounded attribute object) is INSIDE it, so a signed
# record can never be re-aimed (org_id / rtype / rid), flipped (state), re-stamped (issued_at) or have its
# attributes rewritten without breaking the signature.
_DIR_CORE = ("signal", "org_id", "rtype", "rid", "state", "issued_at", "data")

RTYPES = ("user", "group", "member")
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


class DirectoryError(ValueError):
    """A fail-closed directory write refusal (bad id, oversize attribute, no owner key)."""


def _id_ok(rtype: str, rid: str) -> bool:
    if rtype == "user":
        return bool(_USER_ID_RE.fullmatch(rid))
    if rtype == "group":
        return bool(_GROUP_ID_RE.fullmatch(rid))
    if rtype == "member":
        return bool(_EDGE_ID_RE.fullmatch(rid))
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


class OrgDirectory:
    """ONE org's directory, folded once and then kept in step with this view's own (owner-signed) writes, so a
    multi-step SCIM request reads what it wrote without re-scanning the spine. Every write appends an
    owner-signed record whose `issued_at` strictly exceeds its key's high-water (so it is honored by any later
    fold) and SKIPS the append when nothing changed (a re-sync does not grow the spine)."""

    def __init__(self, registry: "ScimDirectoryRegistry", org_id: str, *, users: dict, groups: dict,
                 edges: set, highwater: dict) -> None:
        self._reg = registry
        self.org_id = org_id
        self._users: "dict[str, DirectoryUser]" = users
        self._groups: "dict[str, DirectoryGroup]" = groups
        self._edges: "set[tuple[str, str]]" = edges
        self._hw: "dict[tuple[str, str], float]" = highwater
        self._index()

    def _index(self) -> None:
        """The edges indexed both ways, so a group's members / a user's groups are read in time proportional to
        THEIR edges, never to every edge of the org (a request touching many members stays linear)."""
        self._by_group: "dict[str, set[str]]" = {}
        self._by_user: "dict[str, set[str]]" = {}
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

    # -- writes (owner-signed; in-memory view kept in step) --------------------------------------------------
    def _fresh(self, rtype: str, rid: str, now: float) -> float:
        hw = self._hw.get((rtype, rid), NO_HIGHWATER)
        at = float(now)
        return at if at > hw else math.nextafter(hw, math.inf)

    def _write(self, rtype: str, rid: str, state: str, data: dict, *, now: float) -> int:
        at = self._fresh(rtype, rid, now)
        seq = self._reg._append(self.org_id, rtype, rid, state, data, issued_at=at)
        self._hw[(rtype, rid)] = at
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

    def delete_user(self, user_id: str, *, now: float) -> bool:
        """Delete user `user_id` and CASCADE-delete every edge to it. Returns True iff the user existed."""
        if user_id not in self._users:
            return False
        for g in sorted(self._by_user.get(user_id, ())):
            self.remove_member(g, user_id, now=now)
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

    # -- staging (a multi-record change is applied to a scratch copy, then committed in one step) ---------------
    def staged(self) -> "OrgDirectory":
        """A scratch copy of this view: it reads and writes exactly like this view, but its writes only JOURNAL the
        owner-signed records they would append (nothing reaches the spine) until `commit` replays them here. A
        caller computes what a change WILL make of the directory, acts on that first (e.g. lowers a role, with its
        audit), and only then commits — so a failure before the commit leaves the directory exactly as it was."""
        return OrgDirectory(_Journal(self._reg, self), self.org_id, users=dict(self._users),
                            groups=dict(self._groups), edges=set(self._edges), highwater=dict(self._hw))

    def commit(self, staged: "OrgDirectory") -> None:
        """Append, in order, every record `staged` (a `staged()` copy of THIS view, with no write here since)
        journaled — each with the issued_at it was stamped with — then adopt its state."""
        journal = staged._reg
        if not isinstance(journal, _Journal) or journal.origin is not self or journal.base_hw != self._hw:
            raise DirectoryError("a staged directory change commits only onto the unchanged view it was staged from")
        for org_id, rtype, rid, state, data, at in journal.records:
            self._reg._append(org_id, rtype, rid, state, data, issued_at=at)
            self._hw[(rtype, rid)] = at
        self._users, self._groups, self._edges = dict(staged._users), dict(staged._groups), set(staged._edges)
        self._index()
        journal.records = []
        journal.base_hw = dict(self._hw)

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
        self.base_hw = dict(origin._hw)
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


class ScimDirectoryRegistry:
    """The owner-signed SCIM directory on the spine. Construction mirrors `OrgRegistry` / `SsoConfigRegistry`:
    the owner signing key + trusted pubkey default to the persisted owner identity; tests inject keypairs."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
        self.appended = 0                  # owner-signed records this registry has appended (a request's cost)

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
        (org, rtype, rid); unsigned / forged / stale / malformed records are inert)."""
        oid = str(org_id or "")
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: "dict[tuple[str, str], str]" = {}
        data: "dict[tuple[str, str], tuple[dict, float]]" = {}
        hw: "dict[tuple[str, str], float]" = {}
        for r in self.store.iter_records():
            p = r.payload
            if not isinstance(p, dict) or p.get("signal") != SCIM_DIRECTORY_SIGNAL or p.get("org_id") != oid:
                continue
            rtype, rid, st = p.get("rtype"), p.get("rid"), p.get("state")
            if rtype not in RTYPES or st not in _STATES or not isinstance(rid, str) or not _id_ok(rtype, rid):
                continue
            if not verify_signed(p, _DIR_CORE, resolver.at(r.seq)):
                continue                                   # unsigned / forged / wrong-epoch key → inert
            at = as_issued_at(p.get("issued_at"))
            key = (rtype, rid)
            if at <= hw.get(key, NO_HIGHWATER):
                continue                                   # replay / stale re-append → refused
            hw[key] = at
            state[key] = st
            d = p.get("data")
            data[key] = (d if isinstance(d, dict) else {}, at)
        users: dict = {}
        groups: dict = {}
        edges: set = set()
        for (rtype, rid), st in state.items():
            if st != "active":
                continue
            d, at = data[(rtype, rid)]
            if rtype == "user":
                u = _user_from(oid, rid, d, at)
                if u is not None:
                    users[rid] = u
            elif rtype == "group":
                g = _group_from(oid, rid, d, at)
                if g is not None:
                    groups[rid] = g
            else:
                m = _EDGE_ID_RE.fullmatch(rid)
                if m:
                    edges.add((m.group(1), m.group(2)))
        return OrgDirectory(self, oid, users=users, groups=groups, edges=edges, highwater=hw)
