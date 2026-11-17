"""Connected-repo registry — the SOVEREIGN record of owner-signed CONNECTED GITHUB REPOSITORIES (Red-Pen R2).

A connected-repo record authorizes VIGIL to REVIEW one tenant's (``org_id``) pull requests on ONE repository
(``github.com/org/repo``) under ONE GitHub App installation, with a per-repo merge-blocking ``block_threshold`` and
an optional ``monthly_limit_credits`` ceiling. **This record is the AUTHORIZATION OF RECORD (decision O-3):** it is
the white-box, owner-authorized basis a review is reserved + metered against — ``reserve_redpen_review`` substitutes
verifying this record for the host-ownership-proof + engagement-authority conjuncts a host launch uses.
Doctrine: ``own-a-repo != own-a-host != observe != offense-test`` — this is a DISTINCT capability from the asset
``OwnershipProof``, the monitoring grant and the offense ``EngagementAuthority``.

This module is the spine-of-record (SOVEREIGN; the keyless offense plane never reads it — R3 hands the worker only a
short-lived per-repo installation token, never this record). Each ACTIVE record is the owner-signed, domain-tagged
``vigil_core.connected_repo_record.SignedConnectedRepoRecord`` stored directly as the spine event payload, so there
is ONE signed object (byte-identical sovereign mint ⟷ any future verifier) rather than a mint-then-publish split.

ASYMMETRIC AUTHENTICATION (mirrors ``asset_ownership`` / ``monitoring_authority``):
  * connect / change-settings = the DANGEROUS direction → honored only if the record is OWNER-SIGNED (verified
    against the owner ``TrustRoot`` under the owner pubkey valid AT ITS SEQ) AND FRESH (``issued_at`` strictly above
    the per-(org_id, repo) high-water). A captured record cannot resurrect a disconnected repository, and its
    settings (threshold + limit) are inside the signed bytes — a tenant cannot lift a limit without a fresh owner
    signature.
  * disconnect = the SAFE direction → a minimal ``state="revoked"`` record honored even UNSIGNED (a replay merely
    re-disconnects; gating the fail-safe direction would make it fail OPEN).

CROSS-TENANT ISOLATION: every record is keyed per (org_id, repo) and ``repos_of_org`` returns only that org's
repositories, so one tenant's connection can never read, overwrite or authorize another tenant's.

HARD-PRUNE DURABILITY: a fail-closed TRIPWIRE (``spine.prune.stranded_active_connected_repos``) refuses a hard prune
that would strand the authoritative latest record of any (org_id, repo) — covering BOTH an active connection and a
revoked tombstone, so no connection is ever silently dropped and no replay-resurrection is re-opened. The fold here
is a signature-verifying genesis scan of the live window (no snapshot seed in this slice — the tripwire is the
invariant; carrying rows into the snapshot seed, exactly as AE-0 did, is a clean follow-on when prune performance
for connected repos matters).

FATAL-2: SOVEREIGN-only (``assert_no_offense``); imports only the shared ``vigil_core`` + sovereign siblings.
"""
from __future__ import annotations

from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import (  # noqa: E402
    AuthorizerKey, BlockThreshold, ConnectedRepoRecord, SignedConnectedRepoRecord, TrustRoot,
    check_connected_repo, sign_connected_repo_record, verify_connected_repo_record,
)

from . import key_history as _kh  # noqa: E402  (owner-key succession resolver, mirrors accounts/orgs)
from .asset_ownership import _check_org_id  # noqa: E402  (ONE tenant-id validator, shared)
from .authn import NO_HIGHWATER, as_issued_at  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

SIGNAL = "governor.connected_repo"
_LOAD_FROM_VAULT = object()
_SKIP = object()


def _check_threshold(threshold) -> BlockThreshold:
    if isinstance(threshold, BlockThreshold):
        return threshold
    try:
        return BlockThreshold(str(threshold))
    except ValueError:
        raise ValueError(f"block_threshold must be one of {[t.value for t in BlockThreshold]}") from None


def _check_limit(monthly_limit_credits) -> int:
    try:
        n = int(monthly_limit_credits)
    except (TypeError, ValueError):
        raise ValueError("monthly_limit_credits must be an integer (0 = no limit)") from None
    if n < 0:
        raise ValueError("monthly_limit_credits must be >= 0 (0 = no limit)")
    return n


class ConnectedRepoRegistry:
    def __init__(self, store, *, owner_key=_LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None):
        self.store = store
        # Signing paths load the owner key from the vault; a pure-read caller passes owner_key=None explicitly so
        # the sovereign private key is never touched on a read path (least-privilege, mirrors asset_ownership).
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ------------------------------------------------------------------------------
    def connect(self, org_id: str, installation_id: int, repo: str, *, block_threshold=BlockThreshold.CRITICAL_HIGH,
                monthly_limit_credits: int = 0, issued_at: float, note: str = "") -> ConnectedRepoRecord:
        """Owner-sign a connection of ``repo`` for ``org_id`` under ``installation_id`` — the DANGEROUS direction,
        honored only if it verifies AND is FRESH (``issued_at`` strictly above the per-(org, repo) high-water).
        Fail-closed ``ValueError`` on a bad org / repo / installation / threshold / limit or a missing signing key.
        The settings are inside the signed bytes. Returns the minted record."""
        if self.owner_key is None:
            raise ValueError("connecting a repository requires the owner signing key")
        oid = _check_org_id(org_id)
        repo_ref = check_connected_repo(repo)
        try:
            iid = int(installation_id)
        except (TypeError, ValueError):
            raise ValueError("installation_id must be an integer") from None
        if iid < 1:
            raise ValueError("installation_id must be a positive GitHub installation id")
        doc = ConnectedRepoRecord(org_id=oid, installation_id=iid, repo=repo_ref,
                                  block_threshold=_check_threshold(block_threshold),
                                  monthly_limit_credits=_check_limit(monthly_limit_credits),
                                  issued_at=float(issued_at), note=str(note or ""))
        signed = sign_connected_repo_record(doc, {"owner": self.owner_key.private_key_b64})
        payload = {"signal": SIGNAL, "record": signed.model_dump(mode="json"), "by": "owner",
                   "requested_by": "owner", "tier": "A0", "decision": "auto",
                   "reason": f"repository {repo_ref} connected for org {oid} (owner-signed)"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return doc

    def set_settings(self, org_id: str, repo: str, *, issued_at: float, block_threshold=None,
                     monthly_limit_credits=None, installation_id=None, note=None) -> ConnectedRepoRecord:
        """Owner-sign a settings change for an already-connected ``repo``: a FRESH active record carrying the new
        ``block_threshold`` and/or ``monthly_limit_credits`` (the rest kept from the current record). Refused with
        ``ValueError`` if the repo is not currently connected (a settings change is not a connect). The anti-replay
        high-water advances, so the change is bound to ``issued_at``."""
        oid = _check_org_id(org_id)
        repo_ref = check_connected_repo(repo)
        cur = self.active(oid, repo_ref)
        if cur is None:
            raise ValueError(f"{repo_ref} is not connected for org {oid}: connect it before changing settings")
        return self.connect(
            oid, cur.installation_id if installation_id is None else installation_id, repo_ref,
            block_threshold=cur.block_threshold if block_threshold is None else block_threshold,
            monthly_limit_credits=(cur.monthly_limit_credits if monthly_limit_credits is None
                                   else monthly_limit_credits),
            issued_at=issued_at, note=cur.note if note is None else note)

    def disconnect(self, org_id: str, repo: str) -> int:
        """Disconnect ``repo`` — the SAFE direction (honored even unsigned, so it can never fail open). A review
        of a disconnected repo is refused at ``reserve_redpen_review`` (no active record). Idempotent."""
        oid = _check_org_id(org_id)
        repo_ref = check_connected_repo(repo)
        payload = {"signal": SIGNAL, "org_id": oid, "repo": repo_ref, "state": "revoked", "by": "owner",
                   "requested_by": "owner", "tier": "A0", "decision": "auto",
                   "reason": f"repository {repo_ref} disconnected for org {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads ----------------------------------------------------------------------------------------
    def _fold(self) -> "dict[tuple, ConnectedRepoRecord]":
        """{(org_id, repo): ConnectedRepoRecord} for repositories whose latest state is ACTIVE. A signature-
        verifying genesis scan of the live window: an owner-signed active record is honored only under the owner
        pubkey valid at its seq and only when FRESH (LWW high-water); a revoke (even unsigned) supersedes."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: "dict[tuple, str]" = {}
        issued: "dict[tuple, float]" = {}
        rows: "dict[tuple, ConnectedRepoRecord]" = {}
        for r in self.store.iter_records():
            self._apply(r, resolver, state, issued, rows)
        return {k: doc for k, doc in rows.items() if state.get(k) == "active"}

    def _apply(self, r, resolver, state: dict, issued: dict, rows: dict):
        """Fold ONE spine record into (state, issued, rows). Returns the (org, repo) it touched, or ``_SKIP``."""
        p = getattr(r, "payload", None)
        if not isinstance(p, dict) or p.get("signal") != SIGNAL:
            return _SKIP
        rec = p.get("record")
        if isinstance(rec, dict):                         # the DANGEROUS direction: a signed active record
            signed = _parse_signed(rec)
            if signed is None:
                return _SKIP
            doc = signed.document
            key = (doc.org_id, doc.repo)
            tp = resolver.at(r.seq)
            root = _owner_root(tp)
            if root is None:
                return _SKIP
            ok, _ = verify_connected_repo_record(signed, root)
            if not ok:
                return _SKIP                              # fail-closed: unsigned/forged/wrong-epoch-key record
            at = as_issued_at(doc.issued_at)
            if at <= issued.get(key, NO_HIGHWATER):
                return _SKIP                              # REPLAY / stale re-append of an already-honored record
            issued[key] = at
            state[key] = "active"
            rows[key] = doc
            return key
        # the SAFE direction: a minimal revoke (honored even unsigned)
        if p.get("state") == "revoked":
            oid, repo = p.get("org_id"), p.get("repo")
            if isinstance(oid, str) and oid and isinstance(repo, str) and repo:
                state[(oid, repo)] = "revoked"
                return (oid, repo)
        return _SKIP

    def active(self, org_id: str, repo: str) -> Optional[ConnectedRepoRecord]:
        """The current active connection record for (org_id, repo), or None (fail-closed / DEFAULT-DENY: no
        record, a disconnected repo, or a record for a DIFFERENT org all refuse). THIS is the authorization
        ``reserve_redpen_review`` checks (and the source of the per-repo threshold + monthly limit)."""
        if not isinstance(org_id, str) or not org_id or not isinstance(repo, str) or not repo:
            return None
        try:
            key = (_check_org_id(org_id), check_connected_repo(repo))
        except ValueError:
            return None
        return self._fold().get(key)

    def repos_of_org(self, org_id: str) -> "list[ConnectedRepoRecord]":
        """Every repository (org_id) currently has connected, in repo order. Cross-tenant isolated (only this
        org's rows)."""
        if not isinstance(org_id, str) or not org_id:
            return []
        try:
            oid = _check_org_id(org_id)
        except ValueError:
            return []
        return [doc for (o, _r), doc in sorted(self._fold().items()) if o == oid]

    def active_records(self) -> "list[ConnectedRepoRecord]":
        """The CROSS-TENANT view: every active connection across all orgs, in (org, repo) order. OWNER-side only
        (the sovereign doctor / an owner report) — a per-tenant caller uses ``repos_of_org`` for isolation."""
        return [doc for _k, doc in sorted(self._fold().items())]


def _owner_root(trusted_pubkey: Optional[str]) -> Optional[TrustRoot]:
    """A threshold-1 owner ``TrustRoot`` from the pubkey valid at a record's seq, or None (⇒ fail-closed skip)."""
    if not trusted_pubkey:
        return None
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=trusted_pubkey)])


def _parse_signed(rec: dict) -> Optional[SignedConnectedRepoRecord]:
    """Reconstruct a ``SignedConnectedRepoRecord`` from a spine payload's ``record`` dict, fail-closed (a hostile
    or corrupt payload yields None, never raises out of the fold)."""
    try:
        return SignedConnectedRepoRecord.model_validate(rec)
    except Exception:  # noqa: BLE001 — a malformed payload is inert, never a crash in the fold
        return None
