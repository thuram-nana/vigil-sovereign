"""Engagement WORKSPACES — a per-engagement, OWNER-SIGNED, tamper-evident workspace on the spine (consumer
C-WS). When a customer starts an engagement/chat, VIGIL auto-creates a named workspace that AGGREGATES — by
REFERENCE, never by copy — everything that engagement produced: its transcript (the chat-continuity store, when
present), its oracle-confirmed findings + replayable evidence-certificate ids, its launch/engagement record, the
org's uploaded knowledge docs, and the engagement's notes. The workspace is portable (an owner-signed export
bundle), tamper-evident, and always accessible, so the customer can return to one place and reach all of a run's
work — the Strix "run workspace", done sovereign-side and tenant-isolated.

WHY THIS LAYER (discover-and-reuse, not re-implement): VIGIL already keeps every artifact a workspace points at.
This module invents NO new storage for them; it is an owner-signed INDEX that organises what already exists:

  * the launches/engagement records          -> ``ui/customer_launches`` (per-(org, host) leases, the seam);
  * the oracle-confirmed findings + evidence -> the assessments projection / ``ui/proof_export`` (seam-published,
    never the offense engine — importing it would breach FATAL-2);
  * the org's uploaded knowledge docs         -> ``tenant_knowledge`` (the per-org corpus);
  * the engagement transcript                 -> the chat-continuity store, when a parallel slice ships it (referenced
    by ``engagement_id`` only; absent today, so the reference is navigational, never a hard dependency).

A workspace record therefore stores ONLY an opaque id, a human TITLE, ``created_at``/``updated_at``, a ``status``,
the ``engagement_id`` it belongs to, and the owner signature — a small, bounded reference, never the artifacts.

TRUST CONSTRUCTION (mirrors ``governor/orgs.py`` EXACTLY — owner-signed + per-record LWW anti-replay):
  * create / rename = the DANGEROUS direction -> honored only if OWNER-SIGNED (``verify_signed``) AND its
    ``issued_at`` STRICTLY exceeds the per-(org_id, workspace_id) high-water. A forged or replayed ``active``
    record is INERT in the fold (never folds in / never resurrects), so a tampered workspace changes nothing.
  * archive = the SAFE direction -> ``status="archived"`` is honored even UNSIGNED, with a FIXED ``issued_at`` of
    0.0 (a replayed archive merely re-archives). Gating the fail-safe direction would make it fail OPEN.
  * ANTI-REPLAY (per-record LWW high-water, keyed PER-(org_id, workspace_id), the SAME resurrection guard
    ``accounts``/``orgs`` carry): the LWW state of org A's workspace is fully independent of org B's.
  * OWNER-KEY SUCCESSION: each ``active`` grant is authenticated under the owner pubkey valid AT ITS SEQ
    (``key_history.key_resolver(...).at(seq)``), identical to ``orgs._fold_orgs``.

TENANT ISOLATION is structural: ``org_id`` is INSIDE the owner-signed core (a record cannot be re-aimed at
another tenant without breaking the signature), the opaque ``workspace_id`` is DERIVED from a domain-separated
hash of ``(org_id, engagement_id)`` (so two orgs' ids never collide), and every read is filtered by the hop-bound
session ``org_id`` (the provisioner passes the session org, NEVER a body field). A requester in org A can never
list or get org B's workspace — proven by test.

BOUNDED + TRIM: at most ``customer_workspaces_max_per_org()`` ACTIVE workspaces per org; creating a new one when
at the cap auto-archives the OLDEST-created active workspace (an owner-signed safe-direction archive) so the newest
engagement always gets a workspace and the active set stays bounded. The title + engagement id are length-capped,
and the whole signed record is byte-capped, before any append.

IDEMPOTENT create-on-start: ``ensure_workspace`` derives the workspace id from ``(org_id, engagement_id)``, so the
same engagement always maps to the SAME workspace. If it already exists (active or archived) ``ensure`` returns it
WITHOUT a new append — the "creating workspace '<title>'" announcement is safe to fire on every engagement start.

EXPORT: ``export_workspace`` returns a PORTABLE owner-signed bundle (the workspace manifest + its reference
descriptors, canonicalised and Ed25519-signed under the owner key), re-verifiable offline with ``verify_one`` and
the owner pubkey — tamper-evident like the evidence certificates, so a workspace can leave VIGIL and still prove it
was the one VIGIL issued.

HARD-PRUNE DURABILITY (mirrors ``orgs``/``customer_credentials`` EXACTLY): the fold is SEEDED from the committed
``spine.snapshot`` leaf (schema v14 grew ``workspace_state``/``workspace_issued``/``workspace_row``) and then folds
only the LIVE window (``iter_records(since_seq=base_seq-1)``). So an active workspace whose only owner-signed grant
sits below a prune boundary SURVIVES (no stranding — list/get/export still see it), and the per-(org, workspace)
anti-replay high-water is carried across the prune, so a captured owner-signed create grant can NEVER re-open an
ARCHIVED workspace after a prune drops its records (no replay-resurrection). ``spine.prune.check_prune_safe`` refuses
any prune that would strand an active workspace the seed does not carry. A rotated/empty trust anchor bypasses the
seed and full-scans from genesis (byte-identical under an empty snapshot).

FATAL-2: SOVEREIGN-side, ``assert_no_offense()`` at import. It imports NO ``framework``/``strix``/``engine`` module
— the owner-signed-spine primitives (``authn``/``identity``/``key_history``) and ``vigil_core`` crypto are shared
sovereign substrate, exactly as ``orgs``/``tenant_knowledge`` reuse them.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors orgs._fold_orgs)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import _check_org_id  # noqa: E402  (ONE tenant-id validator — org == tenant_id)
from ..reuse import canonical_json, sign, verify_one  # noqa: E402
from ..spine.snapshot import SnapshotState, seed_applies  # noqa: E402  (hard-prune seed — mirrors orgs._fold_orgs)

__all__ = [
    "Workspace", "WorkspaceRegistry", "WorkspaceError", "WorkspaceCapError",
    "WORKSPACE_SIGNAL", "derive_workspace_id", "EXPORT_CONTEXT",
]

# A dedicated payload signal under the generic enforced ``kind="event"`` governor record (mirrors orgs' signals),
# so a NEW spine kind need not be registered with the W5-1 write-path guard — the signal disambiguates the fold.
WORKSPACE_SIGNAL = "governor.engagement_workspace"

# Domain separation for the opaque workspace-id hash — distinct from every other per-org hashed-name namespace
# (``tenant_knowledge._CORPUS_CONTEXT``, the authz-requests name, ...), so a workspace id can never collide with
# another derived name. ``org_id`` is hashed IN, so org A and org B never share a workspace id for the same
# engagement id. The NUL is an escape, never a raw control char (ruff PLE2515-clean).
_WORKSPACE_ID_CONTEXT = b"vigil-engagement-workspace\x00"
#: Domain-separated context for the portable export bundle's owner signature (distinct from the id hash).
EXPORT_CONTEXT = b"vigil-workspace-export-v1\x00"

#: The owner-signed authenticated CORE of each grant. ``issued_at`` MUST be inside it (else a captured grant could
#: be re-stamped fresh without breaking the signature — the replay this guard refuses). ``org_id``/``workspace_id``/
#: ``engagement_id`` are inside it so a grant can never be re-aimed at another tenant, workspace or engagement, and
#: ``title`` is inside it so an owner-signed workspace cannot be silently re-labelled.
_WS_CORE = ("signal", "org_id", "workspace_id", "title", "engagement_id", "status", "issued_at")

# Field bounds (fail-closed at BINDING time — a clean ``WorkspaceError`` now, never a silent bad grant later).
_MAX_TITLE_CHARS = 200
_MAX_ENGAGEMENT_CHARS = 200
#: The opaque workspace id is ``ws_`` + a 40-hex-char digest prefix; validated on every read so a hostile id can
#: never reach the fold as anything but "no such workspace".
_WORKSPACE_ID_RE = re.compile(r"ws_[0-9a-f]{40}")


class WorkspaceError(RuntimeError):
    """A workspace operation failed (bad input, or a not-found / archived state the caller may not mutate). Raised,
    never swallowed, so the provisioner fails closed with a clean, customer-facing message."""


class WorkspaceCapError(WorkspaceError):
    """A create was refused by a hard cap (the title/engagement id over length, or — only when trim is disabled —
    the org is at its workspace ceiling). A clean refusal, distinct from an internal fault."""


# ---------------------------------------------------------------------------------------------------
# Validation + id derivation (fail-closed).
# ---------------------------------------------------------------------------------------------------

def _check_engagement_id(engagement_id: object) -> str:
    """Validate the engagement id a workspace belongs to — a non-empty, control-free, bounded string. It is
    reference data (the id of the chat/launch the workspace indexes), not a path, so the charset is permissive;
    the SECURITY-bearing identifiers are ``org_id`` (a validated tenant id) and the DERIVED ``workspace_id``."""
    e = str(engagement_id or "").strip()
    if not e or len(e) > _MAX_ENGAGEMENT_CHARS:
        raise WorkspaceError(f"engagement id must be a non-empty string of <= {_MAX_ENGAGEMENT_CHARS} chars")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in e):
        raise WorkspaceError("engagement id must not contain control characters")
    return e


def _clean_title(title: object, *, engagement_id: str) -> str:
    """Normalise a human workspace title, fail-closed. Control chars stripped, surrounding whitespace trimmed,
    length-capped. A blank title AUTO-DERIVES from the engagement id (the Strix "creating workspace '<target>'"
    behaviour: the engagement's target/first-message is the engagement id the edge passes)."""
    t = "".join(ch for ch in str(title or "") if ord(ch) >= 0x20 and ord(ch) != 0x7f).strip()
    if not t:
        t = f"Engagement {engagement_id}".strip()
    if len(t) > _MAX_TITLE_CHARS:
        t = t[:_MAX_TITLE_CHARS].rstrip()
    if not t:                                             # engagement id was itself only control chars -> fail-closed
        raise WorkspaceError("a workspace title could not be derived")
    return t


def derive_workspace_id(org_id: str, engagement_id: str) -> str:
    """The opaque, DETERMINISTIC workspace id for ``(org_id, engagement_id)`` — the idempotency key for
    create-on-start. ``org_id`` is validated first (a safe tenant id) and hashed IN with domain separation, so the
    id is opaque (neither org nor engagement appears in it) AND per-org (two orgs never share an id)."""
    oid = _check_org_id(org_id)
    eid = _check_engagement_id(engagement_id)
    digest = hashlib.sha256(_WORKSPACE_ID_CONTEXT + oid.encode("utf-8") + b"\x00" + eid.encode("utf-8")).hexdigest()
    return "ws_" + digest[:40]


def _check_workspace_id(workspace_id: object) -> str:
    """Validate a workspace id presented by a caller (get/rename/archive/export). Fail-closed: a non-matching id
    is refused outright (it can never be a real derived id), so a hostile id reaches the fold only as "not found"."""
    w = str(workspace_id or "").strip()
    if not _WORKSPACE_ID_RE.fullmatch(w):
        raise WorkspaceError("workspace id must be an opaque 'ws_'-prefixed identifier")
    return w


# ---------------------------------------------------------------------------------------------------
# Entity
# ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Workspace:
    org_id: str          # the owning tenant (inside the owner-signed core — a workspace can't be re-aimed)
    workspace_id: str    # opaque, derived from (org_id, engagement_id)
    title: str           # human label (auto-derived, user-renameable)
    engagement_id: str   # the engagement/chat this workspace indexes
    created_at: float    # issued_at of the FIRST owner-signed create grant (stable across renames)
    updated_at: float    # issued_at of the latest honored active grant (the per-record high-water)
    status: str          # "active" | "archived"

    def as_dict(self) -> dict:
        return {"workspace_id": self.workspace_id, "org_id": self.org_id, "title": self.title,
                "engagement_id": self.engagement_id, "created_at": self.created_at,
                "updated_at": self.updated_at, "status": self.status}


# ---------------------------------------------------------------------------------------------------
# The fold — ONE step per record (mirrors orgs._apply_org_record), full genesis scan.
# ---------------------------------------------------------------------------------------------------

_SKIP = object()


def _apply_record(r, resolver, state: dict, issued: dict, created: dict, entities: dict):
    """Fold ONE spine record into (state, issued, created, entities). Returns the (org_id, workspace_id) it
    touched, or ``_SKIP``."""
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != WORKSPACE_SIGNAL:
        return _SKIP
    org_id = p.get("org_id")
    workspace_id = p.get("workspace_id")
    if (not isinstance(org_id, str) or not org_id
            or not isinstance(workspace_id, str) or not workspace_id):
        return _SKIP
    key = (org_id, workspace_id)
    rec_state = p.get("status")
    if rec_state == "archived":
        state[key] = "archived"                           # honor ANY archive (even unsigned) — safe direction
        return key
    if rec_state == "active":
        if not verify_signed(p, _WS_CORE, resolver.at(r.seq)):
            return _SKIP                                  # fail-closed: unsigned/forged/wrong-epoch-key grant
        at = as_issued_at(p.get("issued_at"))
        if at <= issued.get(key, NO_HIGHWATER):
            return _SKIP                                  # REPLAY / stale re-append of an already-honored grant
        issued[key] = at                                  # consume it so its own replay is refused hereafter
        if key not in created:
            created[key] = at                             # the FIRST create's issued_at (stable across renames)
        state[key] = "active"
        entities[key] = Workspace(
            org_id=org_id, workspace_id=workspace_id, title=str(p.get("title") or ""),
            engagement_id=str(p.get("engagement_id") or ""), created_at=created[key],
            updated_at=at, status="active")
        return key
    return _SKIP


# ---------------------------------------------------------------------------------------------------
# The registry — owner-signed workspace grants on the spine (construction mirrors OrgRegistry).
# ---------------------------------------------------------------------------------------------------

class WorkspaceRegistry:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None,
                 max_per_org: Optional[int] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
        self._max_per_org_override = max_per_org

    # -- caps -------------------------------------------------------------------------------------
    def _max_per_org(self) -> int:
        if self._max_per_org_override is not None:
            return max(1, int(self._max_per_org_override))
        from .. import config
        return config.customer_workspaces_max_per_org()

    # -- owner mutations --------------------------------------------------------------------------
    def _append_active(self, org_id: str, workspace_id: str, title: str, engagement_id: str,
                       *, issued_at: float) -> int:
        core = {"signal": WORKSPACE_SIGNAL, "org_id": org_id, "workspace_id": workspace_id, "title": title,
                "engagement_id": engagement_id, "status": "active", "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"workspace {workspace_id} ({title!r}) created/renamed (owner-signed grant)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _append_archived(self, org_id: str, workspace_id: str) -> int:
        """Append a safe-direction archive. Owner-signed for provenance/audit, but honored regardless of the
        signature, with a FIXED ``issued_at`` of 0.0 (a replayed archive merely re-archives)."""
        core = {"signal": WORKSPACE_SIGNAL, "org_id": org_id, "workspace_id": workspace_id, "title": "",
                "engagement_id": "", "status": "archived", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"workspace {workspace_id} ARCHIVED (governed)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def ensure_workspace(self, org_id: str, engagement_id: str, title: object, *,
                         issued_at: float) -> "tuple[Workspace, bool]":
        """IDEMPOTENT create-on-start. Derive the workspace id from ``(org_id, engagement_id)``; if a workspace
        with that id already exists (active OR archived) return it unchanged with ``created=False`` (no append —
        safe to call on every engagement start). Otherwise, enforce the per-org cap (auto-archiving the oldest
        active workspace to make room — the TRIM policy), owner-sign a fresh ``active`` grant and return it with
        ``created=True``. Requires the owner signing key (an unsigned grant never folds in, so it would be inert)."""
        if self.owner_key is None:
            raise WorkspaceError("creating a workspace requires the owner signing key")
        oid = _check_org_id(org_id)
        eid = _check_engagement_id(engagement_id)
        wid = derive_workspace_id(oid, eid)
        existing = self.get_workspace(oid, wid)
        if existing is not None:
            return existing, False
        ttl = _clean_title(title, engagement_id=eid)
        self._trim_to_cap(oid, making_room_for=1)
        self._append_active(oid, wid, ttl, eid, issued_at=float(issued_at))
        made = self.get_workspace(oid, wid)
        if made is None:                                  # defensive: the grant must fold back in under our key
            raise WorkspaceError("the workspace grant did not fold in (owner-key mismatch?)")
        return made, True

    def rename_workspace(self, org_id: str, workspace_id: str, title: object, *, issued_at: float) -> Workspace:
        """Rename a workspace — the DANGEROUS direction, a fresh owner-signed ``active`` grant with a strictly
        greater ``issued_at``. Refused (``WorkspaceError``) if the workspace is absent or ARCHIVED (an archived
        workspace is read-only; a fresh active grant would silently un-archive it)."""
        if self.owner_key is None:
            raise WorkspaceError("renaming a workspace requires the owner signing key")
        oid = _check_org_id(org_id)
        wid = _check_workspace_id(workspace_id)
        cur = self.get_workspace(oid, wid)
        if cur is None:
            raise WorkspaceError("no such workspace")
        if cur.status != "active":
            raise WorkspaceError("an archived workspace cannot be renamed")
        ttl = _clean_title(title, engagement_id=cur.engagement_id)
        # The fresh active grant MUST strictly exceed the per-record high-water (``cur.updated_at``) or the fold
        # refuses it as a replay. A caller passing a strictly-greater ``issued_at`` is honored as-is; a same-tick
        # wall clock is nudged just past the high-water so a legitimate rename never silently no-ops.
        at = max(float(issued_at), cur.updated_at + 1e-6)
        self._append_active(oid, wid, ttl, cur.engagement_id, issued_at=at)
        out = self.get_workspace(oid, wid)
        return out if out is not None else replace(cur, title=ttl)

    def archive_workspace(self, org_id: str, workspace_id: str) -> Optional[Workspace]:
        """Archive a workspace — the SAFE direction (honored even unsigned, fixed ``issued_at`` 0.0). Idempotent:
        archiving an already-archived or unknown workspace is a no-op that still records the safe-direction marker.
        The workspace stays LISTED and GETtable (archive is a status, not a deletion — a run's work is always
        accessible); only its ``status`` becomes ``archived`` and it no longer counts against the active cap."""
        oid = _check_org_id(org_id)
        wid = _check_workspace_id(workspace_id)
        self._append_archived(oid, wid)
        return self.get_workspace(oid, wid)

    def _trim_to_cap(self, org_id: str, *, making_room_for: int) -> None:
        """Keep the ACTIVE workspace count for ``org_id`` within the cap by archiving the OLDEST-created active
        workspaces (the trim policy), so a new engagement always gets a workspace. Only active workspaces count."""
        cap = self._max_per_org()
        active = [w for w in self._fold(org_id) if w.status == "active"]
        over = len(active) + making_room_for - cap
        if over <= 0:
            return
        active.sort(key=lambda w: (w.created_at, w.workspace_id))     # oldest first, stable tiebreak
        for w in active[:over]:
            self._append_archived(org_id, w.workspace_id)

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune; tenant-isolated) --
    def _seed(self, snap) -> "tuple[tuple[dict, dict, dict, dict], int]":
        """((state, issued, created, entities), since): the HARD-PRUNE SEED from ``snap`` (mirrors
        ``orgs._org_seed`` / ``customer_credentials._seed``), or the empty genesis start when our trust anchor
        differs from the snapshot's. ``entities`` holds rebuilt :class:`Workspace` objects for EVERY carried
        workspace — active AND archived-with-prior-active — reconstructed with the SAME coercions ``_apply_record``
        uses, so a post-prune ``_fold`` re-reads them (both the per-(org, workspace) anti-replay high-water AND the
        workspace row survive): a pruned active workspace is not stranded, and a pruned archived workspace stays
        listed/gettable. ``status`` joins from ``state``; ``updated_at`` joins from the per-pair high-water."""
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return ({}, {}, {}, {}), -1
        state = dict(snap.workspace_state_map())             # (org, workspace) -> "active"|"archived" (keep archived)
        issued = dict(snap.workspace_issued_map())           # (org, workspace) -> per-pair active high-water
        created: dict = {}
        entities: dict = {}
        # flat row [org_id, workspace_id, title, engagement_id, created_at] -> Workspace.
        for row in snap.workspace_row:
            key = (row[0], row[1])
            cat = as_issued_at(row[4])
            created[key] = cat
            entities[key] = Workspace(
                org_id=str(row[0]), workspace_id=str(row[1]), title=str(row[2] or ""),
                engagement_id=str(row[3] or ""), created_at=cat,
                updated_at=as_issued_at(issued.get(key, cat)), status=state.get(key, "active"))
        return (state, issued, created, entities), snap.base_seq - 1

    def _fold(self, org_id: Optional[str] = None) -> "list[Workspace]":
        """Fold the spine into the workspaces whose latest state is known, optionally scoped to ONE org. Each
        ``active`` grant is authenticated under the owner pubkey valid AT ITS SEQ and the per-(org, workspace)
        high-water refuses any stale/replayed re-append. Archived workspaces are KEPT (listed, with
        ``status="archived"``) — archive is a status, not a deletion. Scoping to ``org_id`` is tenant isolation at
        the read boundary: only that org's own records are ever returned.

        HARD-PRUNE SEED (mirrors ``orgs._fold_orgs`` EXACTLY): seed the per-(org, workspace) state / anti-replay
        high-water / created / rebuilt Workspace set from the committed :class:`SnapshotState`, then fold the LIVE
        window only — so an active workspace whose only owner-signed grant was pruned SURVIVES and its high-water
        is NOT reset (else the first hard prune below a workspace's grants strands it AND re-opens the archive-then-
        replay resurrection). A rotated/empty anchor bypasses the seed and full-scans from genesis (byte-identical
        under an empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (state, issued, created, entities), since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            _apply_record(r, resolver, state, issued, created, entities)
        out: "list[Workspace]" = []
        for key, w in entities.items():
            if org_id is not None and key[0] != org_id:
                continue
            out.append(replace(w, status=state.get(key, "active")))
        # newest-first by created_at (stable tiebreak), so the most recent engagement leads the list.
        out.sort(key=lambda w: (w.created_at, w.workspace_id), reverse=True)
        return out

    def list_workspaces(self, org_id: str) -> "list[Workspace]":
        """Every workspace of ``org_id`` (active AND archived), newest-first. A pure read — mints nothing, takes no
        lock, and returns ONLY this org's own workspaces (tenant isolation at the fold boundary)."""
        return self._fold(_check_org_id(org_id))

    def get_workspace(self, org_id: str, workspace_id: str) -> Optional[Workspace]:
        """The one workspace ``(org_id, workspace_id)``, or None (fail-closed — unknown id, or an id belonging to a
        DIFFERENT org, reads as absent). Tenant isolation: the fold is org-scoped, so org A asking for org B's id
        gets None even though the record exists."""
        oid = _check_org_id(org_id)
        wid = _check_workspace_id(workspace_id)
        for w in self._fold(oid):
            if w.workspace_id == wid:
                return w
        return None

    # -- export (portable, owner-signed, tamper-evident) -----------------------------------------
    def export_bundle(self, org_id: str, workspace_id: str, *, references: Optional[list] = None) -> dict:
        """A PORTABLE owner-signed export of ``(org_id, workspace_id)``: the workspace manifest + its reference
        descriptors, canonicalised and Ed25519-signed under the owner key. Re-verifiable offline with
        :func:`verify_export` (or any holder of the owner pubkey + ``vigil_core.verify_one``), so a workspace that
        leaves VIGIL still proves it is the one VIGIL issued — a forged/edited bundle fails verification (inert,
        like the evidence certificates). Fail-closed on an unknown workspace. References are inert descriptors the
        provisioner supplies (navigational links into the existing screens), carried verbatim and signed."""
        w = self.get_workspace(org_id, workspace_id)
        if w is None:
            raise WorkspaceError("no such workspace")
        manifest = {"kind": "vigil.engagement_workspace.export", "version": 1, "workspace": w.as_dict(),
                    "references": list(references or [])}
        body = canonical_json(manifest)
        core = EXPORT_CONTEXT + (body if isinstance(body, bytes) else body.encode("utf-8"))
        sig = sign(self.owner_key.private_key_b64, core) if self.owner_key else None
        return {"manifest": manifest, "sig": sig,
                "pubkey": self.owner_key.public_key_b64 if self.owner_key else None}


def verify_export(bundle: object, trusted_pubkey: Optional[str]) -> bool:
    """True iff ``bundle`` is a workspace export carrying a valid owner signature over its manifest. Fail-closed:
    no trusted key, a non-str/mismatched pubkey, a tampered manifest, or malformed signature material -> not
    authentic. The verifier re-canonicalises the manifest exactly as the signer did (``EXPORT_CONTEXT`` domain
    separation), so a bundle whose manifest was edited after signing never verifies."""
    if not trusted_pubkey or not isinstance(bundle, dict):
        return False
    sig = bundle.get("sig")
    if not sig or not isinstance(sig, str) or bundle.get("pubkey") != trusted_pubkey:
        return False
    manifest = bundle.get("manifest")
    if not isinstance(manifest, dict):
        return False
    try:
        body = canonical_json(manifest)
        core = EXPORT_CONTEXT + (body if isinstance(body, bytes) else body.encode("utf-8"))
        from ..reuse import IntegrityError
        try:
            return verify_one(trusted_pubkey, core, sig)
        except (IntegrityError, TypeError, ValueError):
            return False
    except (TypeError, ValueError):                       # a manifest that cannot be canonicalised is not authentic
        return False
