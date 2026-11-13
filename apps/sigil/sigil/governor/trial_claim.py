"""Free-trial CLAIMS — one owner-signed, permanent claim per canonical mailbox / registrable domain.

A free trial is limited to one per org, one per canonical mailbox and one per registrable domain. The per-org
limit is the trial grant's own deterministic entry id (wallet). This ledger carries the other two: a
`governor.trial_claim` record says "key K of kind {email, domain} is claimed by org O". The FIRST verified
claim of a (kind, digest) wins, forever — a later claim by another org is inert, a replay is inert, and a claim
outlives the account that made it (a revoked customer's mailbox cannot take a second trial).

KEY DIGEST. `digest = sha256(kind + "\\0" + canonical key)`. This is a DEDUPLICATION KEY, not anonymisation:
mailboxes and domains are guessable, so a digest can be reversed by dictionary. The digests are personal data
and are covered by the retention and erasure policy like the mailbox itself.

MODEL: owner-signed only (no honoured-unsigned direction). The tenant (`org_id`) and the key are inside the
signed core, so a captured claim cannot be re-aimed at another org or key. Each record is verified under the
owner pubkey valid AT ITS SEQ; a rotated/empty anchor bypasses the snapshot and full-scans from genesis.

ANTI-REPLAY ACROSS A HARD PRUNE: the claims are a lifetime, first-wins map, so they are seeded from
`SnapshotState.trial_claim_row`; `spine.prune` refuses a prune that would strand a below-K claim the seed does
not carry (`stranded_trial_claims`). The per-payload fold step `apply_trial_claim` is the ONE fold body, shared
by the registry, the snapshot build and the prune tripwire, so the three cannot diverge.

No caller mints a claim yet (S2); the sign-up and launch paths wire it later behind their default-OFF flags.
FATAL-2: sovereign-side, `assert_no_offense` at import.
"""
from __future__ import annotations

import hashlib
import re
from typing import Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402
from .authn import as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402
from ..spine.snapshot import SnapshotState, seed_applies  # noqa: E402
from ..spine.fold_cache import FoldCache  # noqa: E402
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402

TRIAL_CLAIM_SIGNAL = "governor.trial_claim"
KEY_KINDS = frozenset({"email", "domain"})
# The owner-signed core: the tenant, the key kind and its digest are all inside it.
_CLAIM_CORE = ("signal", "key_kind", "key_digest", "org_id", "issued_at")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


def key_digest(kind: str, canonical_key: str) -> str:
    """The dedup digest for a canonical key (a dedup key, not anonymisation — see the module doc)."""
    k = _check_kind(kind)
    key = str(canonical_key or "")
    if not key:
        raise ValueError("canonical key must be non-empty")
    return hashlib.sha256((k + "\0" + key).encode("utf-8")).hexdigest()


def claim_entry_id(kind: str, digest: str) -> str:
    return f"trial-claim:{kind}:{digest}"


def _check_kind(kind: str) -> str:
    k = str(kind or "").strip()
    if k not in KEY_KINDS:
        raise ValueError(f"trial claim kind must be one of {sorted(KEY_KINDS)}")
    return k


def _check_digest(digest: str) -> str:
    d = str(digest or "")
    if not _DIGEST_RE.fullmatch(d):
        raise ValueError("trial claim digest must be 64 lowercase hex characters")
    return d


def apply_trial_claim(p, pubkey: Optional[str], rows: dict) -> Optional[tuple]:
    """Fold ONE record payload into `rows` {(kind, digest): [org_id, issued_at]}: the first VERIFIED claim of a
    key wins. Returns the key it added, or None. Shared by the registry fold, `SnapshotState.build` and the prune
    tripwire."""
    if not isinstance(p, dict) or p.get("signal") != TRIAL_CLAIM_SIGNAL:
        return None
    kind, digest, oid = p.get("key_kind"), p.get("key_digest"), p.get("org_id")
    if not (isinstance(kind, str) and kind in KEY_KINDS and isinstance(digest, str)
            and _DIGEST_RE.fullmatch(digest) and isinstance(oid, str) and oid):
        return None
    key = (kind, digest)
    if key in rows:
        return None                                   # first claim wins; a replay or a later claim is inert
    if not verify_signed(p, _CLAIM_CORE, pubkey):
        return None                                   # unsigned / forged / wrong-epoch: inert
    rows[key] = [oid, float(as_issued_at(p.get("issued_at")))]
    return key


def seed_rows(snap) -> dict:
    """The claim rows a snapshot carries, in the fold's shape."""
    out: dict = {}
    for row in snap.trial_claim_row:
        if (isinstance(row, (list, tuple)) and len(row) >= 4 and isinstance(row[0], str) and row[0] in KEY_KINDS
                and isinstance(row[1], str) and isinstance(row[2], str) and (row[0], row[1]) not in out):
            out[(row[0], row[1])] = [row[2], float(as_issued_at(row[3]))]
    return out


class _ClaimsView:
    __slots__ = ("rows", "by_org")

    def __init__(self, rows: dict) -> None:
        self.rows = rows
        self.by_org: "dict[str, list]" = {}
        for key in rows:
            self.index(key)

    def index(self, key) -> None:
        self.by_org.setdefault(self.rows[key][0], []).append(key)


def _claims_step(view: _ClaimsView, r, resolver) -> None:
    key = apply_trial_claim(r.payload, resolver.at(r.seq), view.rows)
    if key is not None:
        view.index(key)


_CLAIMS_FOLD = FoldCache("governor.trial_claim", step=_claims_step)


class TrialClaimRegistry:
    """Owner-signed, first-wins trial claims on the spine. Construction mirrors `InvoiceRegistry`."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def claim(self, kind: str, digest: str, org_id: str, *, issued_at: float) -> int:
        """Owner-sign a claim of (kind, digest) for `org_id`. Appends unconditionally; the fold keeps the first
        verified claim, so a retry by the same org is harmless and a claim by a second org is inert. Callers check
        `claimant()` first under their own lock. Returns the record seq."""
        if self.owner_key is None:
            raise ValueError("trial claim requires the owner signing key")
        k = _check_kind(kind)
        d = _check_digest(digest)
        oid = org_tenant_id(org_id)
        core = {"signal": TRIAL_CLAIM_SIGNAL, "key_kind": k, "key_digest": d, "org_id": oid,
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "entry_id": claim_entry_id(k, d), "by": "owner",
                   "requested_by": "owner", "tier": "A0", "decision": "auto",
                   "reason": f"trial claim ({k}) -> {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads -------------------------------------------------------------------------------------
    def _seed(self, snap) -> "tuple[dict, int]":
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return {}, -1                                 # nothing pruned: the genesis scan is the whole fold
        return seed_rows(snap), snap.base_seq - 1

    def _cached(self, reader: Callable):
        def seed(snap):
            rows, since = self._seed(snap)
            return _ClaimsView(rows), since

        return cached_read(_CLAIMS_FOLD, self.store, trusted_pubkey=self.trusted_pubkey, seed=seed,
                           reader=reader)

    def _fold(self) -> dict:
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        rows, since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            apply_trial_claim(r.payload, resolver.at(r.seq), rows)
        return rows

    def claimant(self, kind: str, digest: str) -> Optional[str]:
        """The org that holds the claim on (kind, digest), or None. Fail-closed on a malformed key (None)."""
        if kind not in KEY_KINDS or not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            return None
        hit = self._cached(lambda v: (v.rows.get((kind, digest)) or [None])[0])
        if hit is not _UNCACHED:
            return hit
        return (self._fold().get((kind, digest)) or [None])[0]

    def claims_of(self, org_id: str) -> "list[tuple[str, str]]":
        """Every (kind, digest) `org_id` holds, sorted."""
        if not isinstance(org_id, str) or not org_id:
            return []
        hit = self._cached(lambda v: list(v.by_org.get(org_id, ())))
        if hit is not _UNCACHED:
            return sorted(hit)
        return sorted(k for k, v in self._fold().items() if v[0] == org_id)


# A customer with no active org membership is still claimed (so their mailbox cannot take a trial later) under this
# sentinel holder. It is never a real org: sign-up org ids are server-derived `org_<digest>` values.
BACKFILL_HOLDER = "trial-backfill"


def backfill_email_claims(customers, orgs, claims, *, canonical, issued_at) -> "dict[str, int]":
    """Owner backfill: write an email claim for every existing customer account (active OR revoked) whose
    canonical mailbox is not yet claimed, held by the customer's earliest active org (or BACKFILL_HOLDER).
    Idempotent: an already-claimed mailbox is skipped. Returns counts {claimed, skipped, unusable}."""
    out = {"claimed": 0, "skipped": 0, "unusable": 0}
    by_user: dict = {}
    for m in orgs.memberships():
        cur = by_user.get(m.username)
        if cur is None or (m.issued_at, m.org_id) < (cur.issued_at, cur.org_id):
            by_user[m.username] = m
    accounts = customers.accounts_ever()               # every account the fold holds, including revoked ones
    t = float(issued_at)
    for username in sorted(accounts):
        ekey = canonical(accounts[username].email)
        if not ekey:
            out["unusable"] += 1
            continue
        digest = key_digest("email", ekey)
        if claims.claimant("email", digest) is not None:
            out["skipped"] += 1
            continue
        holder = by_user[username].org_id if username in by_user else BACKFILL_HOLDER
        claims.claim("email", digest, holder, issued_at=t)
        t += 0.001
        out["claimed"] += 1
    return out
