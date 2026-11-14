"""Slice E2a — the CUSTOMER CREDENTIAL namespace (owner-signed, LWW): the substrate every non-password
customer login method binds to.

A sibling signal to `governor.customer` (`governor.customer_credential`), holding the per-customer
authentication credentials that `governor.customer` itself does not: a WebAuthn PASSKEY (public key + COSE
alg), an enrolled TOTP SECRET (owner-vault-sealed — the plaintext never reaches the spine), and a Google
OIDC FEDERATED binding `(iss, sub)`. Kept as its OWN signal (not inline fields on `governor.customer`)
because passkeys are MULTI-VALUED per customer and churn independently of the identity grant, and because a
passkey LOGIN must be a pure signature check with NO owner re-sign (the monotonic sign-count clone-floor
lives in a separate non-signed edge ledger, E3b — never here).

Keyed PER-`(username, cred_key)` where `cred_key` is the WebAuthn `credential_id` for a passkey (so N
passkeys coexist) and the fixed `"totp"` / `"oidc"` otherwise (one each per customer). Trust construction
MIRRORS `governor/asset_ownership.py` (the per-key multi-valued owner-signed fold) EXACTLY:
  * enroll = the DANGEROUS direction -> honored only if OWNER-SIGNED (`verify_signed`) AND `issued_at`
    STRICTLY exceeds the per-(username, cred_key) high-water; the credential MATERIAL is inside the signed
    core, so an owner-signed passkey record can never be re-aimed to another public key / COSE alg, nor a
    TOTP seal / `(iss, sub)` binding swapped, without breaking the signature;
  * revoke = the SAFE direction -> `state="revoked"` honored even UNSIGNED, fixed `issued_at` 0.0;
  * per-key LWW high-water closes replay-resurrection (a captured owner-signed active credential cannot
    resurrect a revoked one); owner-key succession-aware verify; HARD-PRUNE SEED from `SnapshotState`
    (customer_credential_state/_issued/_row), with `spine.prune.stranded_active_customer_credentials` the
    fail-closed tripwire.

GLOBAL UNIQUENESS (anti-takeover): a `credential_id` may be active for AT MOST ONE customer and an
`(iss, sub)` for AT MOST ONE customer — enrolment refuses a binding already held by a DIFFERENT username,
and the resolvers (`by_credential_id` / `by_federated`) return a match ONLY when exactly one active binding
exists (fail-closed on zero or an ambiguous >1). Identity != authority: a resolved username is handed to the
Provisioner's `finish_login`; nothing here grants a role.

FATAL-2: sovereign-side (`assert_no_offense` at import); reuses only the sovereign `authn`/`identity`/
`key_history` primitives (same plane as `customers.py`/`asset_ownership.py`). No framework/strix.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from ..spine.snapshot import SnapshotState, seed_applies  # noqa: E402  (hard-prune seed — mirrors asset_ownership._fold_proofs)
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402

SIGNAL = "governor.customer_credential"

KIND_PASSKEY = "passkey"
KIND_TOTP = "totp"
KIND_OIDC = "oidc"
_KINDS = frozenset({KIND_PASSKEY, KIND_TOTP, KIND_OIDC})

# cred_key = credential_id (passkey; multi-valued) or the fixed kind (totp/oidc; one per customer).
_CRED_KEY_TOTP = "totp"
_CRED_KEY_OIDC = "oidc"
# credential_id is authenticator-supplied (b64url, no padding); bound to a safe, length-capped shape — it is
# NEVER a trusted path component and a malformed one is refused at enrolment, fail-closed.
_CREDENTIAL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")

# The owner-signed authenticated CORE. The base is always present; each credential MATERIAL field is folded
# into the core IFF present in the record (mirrors accounts/customers conditional core: a record missing one
# canonicalizes like the pre-field encoding, so an old signature still verifies and the malleability inverse
# — strip/add a signed field — stays closed). `issued_at` is inside it (anti-replay high-water).
_BASE_CORE = ("signal", "username", "cred_key", "kind", "state", "issued_at")
_MATERIAL_ORDER = ("cose_alg", "public_key_spki_b64", "uv", "sealed_secret", "federated_iss", "federated_sub")


def _cred_core(payload: dict) -> "tuple[str, ...]":
    fields: tuple[str, ...] = _BASE_CORE
    for f in _MATERIAL_ORDER:
        if f in payload:
            fields += (f,)
    return fields


def _check_username(username: str) -> str:
    u = str(username or "").strip()
    if not u or len(u) > 64:
        raise ValueError("customer username required")
    return u


def _check_credential_id(credential_id: str) -> str:
    cid = str(credential_id or "").strip()
    if not _CREDENTIAL_ID_RE.match(cid):
        raise ValueError("credential_id must be 1-512 chars of b64url [A-Za-z0-9_-]")
    return cid


@dataclass(frozen=True)
class CustomerCredential:
    """One active customer credential. Exactly the fields of the credential's kind are populated."""
    username: str
    cred_key: str
    kind: str
    issued_at: float
    # passkey
    cose_alg: Optional[int] = None
    public_key_spki_b64: Optional[str] = None
    uv: bool = False
    # totp
    sealed_secret: Optional[str] = None
    # oidc
    federated_iss: Optional[str] = None
    federated_sub: Optional[str] = None


_SKIP = object()          # `_apply_credential_record`: the record did not touch any (username, cred_key)


def _apply_credential_record(r, resolver, state: dict, issued: dict, rows: dict):
    """Fold ONE spine record into (state, issued, rows) — THE credential fold body, shared by the full `_fold`
    and the verified fold cache (Front C S0d). Returns the (username, cred_key) it touched, or `_SKIP`."""
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != SIGNAL:
        return _SKIP
    u = p.get("username")
    ck = p.get("cred_key")
    if not isinstance(u, str) or not u or not isinstance(ck, str) or not ck:
        return _SKIP
    key = (u, ck)
    st = p.get("state")
    if st == "revoked":
        state[key] = "revoked"                 # safe direction: honor ANY revoke (even unsigned)
        return key
    if st == "active":
        if not verify_signed(p, _cred_core(p), resolver.at(r.seq)):
            return _SKIP                       # fail-closed: unsigned/forged/wrong-epoch grant
        at = as_issued_at(p.get("issued_at"))
        if at <= issued.get(key, NO_HIGHWATER):
            return _SKIP                       # REPLAY / stale re-append of an already-honored grant
        issued[key] = at
        state[key] = "active"
        rows[key] = {"kind": p.get("kind"), "issued_at": at, "cose_alg": p.get("cose_alg"),
                     "public_key_spki_b64": p.get("public_key_spki_b64"), "uv": p.get("uv"),
                     "sealed_secret": p.get("sealed_secret"), "federated_iss": p.get("federated_iss"),
                     "federated_sub": p.get("federated_sub")}
        return key
    return _SKIP


class _CredentialsView:
    """The cached credential fold: the full fold's (state, issued, rows) plus `active` (exactly `_fold()`'s
    result) and three read indexes kept in step — `by_user` (username -> its cred_keys), `by_ck` (cred_key ->
    the usernames holding it, any kind) and `by_fed` ((iss, sub) -> the (username, cred_key) oidc credentials
    binding it: pairs, so two credentials of one user still count as two, exactly as the full scan does) — so
    a login's passkey / Google / TOTP resolution is O(1) instead of a scan. An (owner-signed, never minted)
    oidc credential whose iss/sub is not hashable is left out of `by_fed`: it can never equal the str
    (iss, sub) a lookup asks for, exactly as the full scan's `==` never matches it."""

    __slots__ = ("state", "issued", "rows", "active", "by_user", "by_ck", "by_fed")

    def __init__(self, state: dict, issued: dict, rows: dict) -> None:
        self.state, self.issued, self.rows = state, issued, rows
        self.active: dict = {}
        self.by_user: "dict[str, set]" = {}
        self.by_ck: "dict[str, set]" = {}
        self.by_fed: "dict[tuple, set]" = {}
        for k in list(rows):
            self.sync(k)

    @staticmethod
    def _fed_key(row: dict):
        if row.get("kind") != KIND_OIDC:
            return None
        return (row.get("federated_iss"), row.get("federated_sub"))

    def _unindex(self, k, row: dict) -> None:
        u, ck = k
        for idx, ik, member in ((self.by_user, u, ck), (self.by_ck, ck, u)):
            names = idx.get(ik)
            if names is not None:
                names.discard(member)
                if not names:
                    del idx[ik]
        fk = self._fed_key(row)
        if fk is not None:
            try:
                names = self.by_fed.get(fk)
            except TypeError:                   # unhashable: never indexed (see the class docstring)
                return
            if names is not None:
                names.discard(k)
                if not names:
                    del self.by_fed[fk]

    def sync(self, k) -> None:
        row = self.rows.get(k) if self.state.get(k) == "active" else None
        old = self.active.get(k)
        if old is row:
            return
        if old is not None:
            self._unindex(k, old)
        if row is None:
            self.active.pop(k, None)
            return
        self.active[k] = row
        u, ck = k
        self.by_user.setdefault(u, set()).add(ck)
        self.by_ck.setdefault(ck, set()).add(u)
        fk = self._fed_key(row)
        if fk is not None:
            try:
                self.by_fed.setdefault(fk, set()).add(k)
            except TypeError:                   # unhashable: never indexed (see the class docstring)
                pass


def _credentials_step(view: _CredentialsView, r, resolver) -> None:
    k = _apply_credential_record(r, resolver, view.state, view.issued, view.rows)
    if k is not _SKIP:
        view.sync(k)


_CREDENTIALS_FOLD = FoldCache("governor.customer_credential", step=_credentials_step)


class CustomerCredentialRegistry:
    """Owner-signed per-customer credential grants on the spine, under `governor.customer_credential`.
    Construction mirrors `CustomerRegistry`/`AssetOwnershipRegistry`."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations (the DANGEROUS direction: owner-signed + FRESH) ----------------------------
    def enroll_passkey(self, username: str, credential_id: str, *, cose_alg: int,
                       public_key_spki_b64: str, uv: bool, issued_at: float) -> int:
        """Bind a WebAuthn passkey public key to a customer. Refuses a `credential_id` already active for a
        DIFFERENT customer (global uniqueness — an attacker must not re-bind a victim's credential id)."""
        u = _check_username(username)
        cid = _check_credential_id(credential_id)
        self._refuse_cross_user(cid, u)
        if not isinstance(cose_alg, int) or isinstance(cose_alg, bool):
            raise ValueError("cose_alg must be an int")
        if not isinstance(public_key_spki_b64, str) or not public_key_spki_b64:
            raise ValueError("public_key_spki_b64 required")
        return self._append_active(u, cid, KIND_PASSKEY, issued_at=issued_at,
                                   cose_alg=int(cose_alg), public_key_spki_b64=public_key_spki_b64,
                                   uv=bool(uv))

    def enroll_totp(self, username: str, *, sealed_secret: str, issued_at: float) -> int:
        """Enroll (or re-enroll) a customer's TOTP, storing the OWNER-VAULT-SEALED secret (never plaintext).
        One TOTP per customer (`cred_key="totp"`); a fresh enroll supersedes the prior via the high-water."""
        u = _check_username(username)
        if not isinstance(sealed_secret, str) or not sealed_secret:
            raise ValueError("sealed_secret required (owner-vault seal, not plaintext)")
        return self._append_active(u, _CRED_KEY_TOTP, KIND_TOTP, issued_at=issued_at,
                                   sealed_secret=sealed_secret)

    def link_federated(self, username: str, *, iss: str, sub: str, issued_at: float) -> int:
        """Bind a Google OIDC `(iss, sub)` to a customer. Refuses an `(iss, sub)` already active for a
        DIFFERENT customer (global uniqueness — the anti-takeover gate's crypto backing). One federated link
        per customer (`cred_key="oidc"`); re-linking a different account supersedes via the high-water."""
        u = _check_username(username)
        issv, subv = str(iss or "").strip(), str(sub or "").strip()
        if not issv or not subv or len(issv) > 512 or len(subv) > 512:
            raise ValueError("federated (iss, sub) required (<=512 chars each)")
        owner = self._federated_username(issv, subv)
        if owner is not None and owner != u:
            raise ValueError("this federated identity is already linked to another customer")
        return self._append_active(u, _CRED_KEY_OIDC, KIND_OIDC, issued_at=issued_at,
                                   federated_iss=issv, federated_sub=subv)

    def revoke(self, username: str, cred_key: str) -> int:
        """Revoke one credential — the SAFE direction (honored even unsigned, fixed `issued_at` 0.0).
        Idempotent; a replayed revoke merely re-revokes. `cred_key` is a credential_id (passkey) or
        "totp"/"oidc"."""
        u = _check_username(username)
        ck = str(cred_key or "").strip()
        if not ck:
            raise ValueError("cred_key required")
        core = {"signal": SIGNAL, "username": u, "cred_key": ck, "kind": "", "state": "revoked",
                "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"customer credential {u}/{ck} REVOKED"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _append_active(self, username: str, cred_key: str, kind: str, *, issued_at: float, **material) -> int:
        if kind not in _KINDS:
            raise ValueError(f"unknown credential kind {kind!r}")
        if self.owner_key is None:
            raise ValueError("credential enrolment requires the owner signing key")
        core = {"signal": SIGNAL, "username": username, "cred_key": cred_key, "kind": kind,
                "state": "active", "issued_at": float(issued_at), **material}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"customer credential {username}/{cred_key} ({kind})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _refuse_cross_user(self, credential_id: str, username: str) -> None:
        holders = self._cached(lambda v: sorted(v.by_ck.get(credential_id, ())))
        if holders is not _UNCACHED:
            if any(u != username for u in holders):
                raise ValueError("this credential_id is already bound to another customer")
            return
        for (u, ck), row in self._fold().items():
            if ck == credential_id and u != username:
                raise ValueError("this credential_id is already bound to another customer")

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _seed(self, snap) -> "tuple[tuple[dict, dict, dict], int]":
        """((state, issued, rows), since): the HARD-PRUNE SEED from `snap`, or the empty genesis start when the
        trusted pubkey differs from the snapshot's."""
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return ({}, {}, {}), -1
        state = dict(snap.customer_credential_state_map())
        issued = dict(snap.customer_credential_issued_map())
        # flat row [username, cred_key, kind, cose_alg, public_key_spki_b64, uv, sealed_secret,
        # federated_iss, federated_sub, issued_at] -> the material dict the live fold also builds.
        rows = {(r[0], r[1]): {"kind": r[2], "cose_alg": r[3], "public_key_spki_b64": r[4], "uv": r[5],
                               "sealed_secret": r[6], "federated_iss": r[7], "federated_sub": r[8],
                               "issued_at": r[9]}
                for r in snap.customer_credential_row}
        return (state, issued, rows), snap.base_seq - 1

    def _cached(self, reader):
        """`reader(view)` over the verified incremental credential fold (`fold_read.cached_read`, flag-gated),
        else `_UNCACHED` (the caller then runs the full `_fold`)."""
        def seed(snap):
            st, since = self._seed(snap)
            return _CredentialsView(*st), since

        return cached_read(_CREDENTIALS_FOLD, self.store, trusted_pubkey=self.trusted_pubkey, seed=seed,
                           reader=reader)

    def _fold(self) -> "dict[tuple, dict]":
        """Fold the spine into {(username, cred_key): record dict} for credentials whose latest state is
        active — the hard-prune-durable fold every resolver reads. Mirrors `asset_ownership._fold_proofs`
        EXACTLY: seed per-(username, cred_key) state / high-water / row from `SnapshotState`, then fold the
        LIVE window only; a rotated/empty anchor bypasses the seed and full-scans from genesis."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (state, issued, rows), since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            _apply_credential_record(r, resolver, state, issued, rows)
        return {k: row for k, row in rows.items() if state.get(k) == "active"}

    @staticmethod
    def _to_cred(username: str, cred_key: str, row: dict) -> CustomerCredential:
        uv = row.get("uv")
        return CustomerCredential(
            username=username, cred_key=cred_key, kind=str(row.get("kind") or ""),
            issued_at=as_issued_at(row.get("issued_at")),
            cose_alg=(int(row["cose_alg"]) if isinstance(row.get("cose_alg"), int) and not isinstance(row.get("cose_alg"), bool) else None),
            public_key_spki_b64=(str(row["public_key_spki_b64"]) if row.get("public_key_spki_b64") else None),
            uv=bool(uv) if uv is not None else False,
            sealed_secret=(str(row["sealed_secret"]) if row.get("sealed_secret") else None),
            federated_iss=(str(row["federated_iss"]) if row.get("federated_iss") else None),
            federated_sub=(str(row["federated_sub"]) if row.get("federated_sub") else None))

    def for_user(self, username: str) -> "list[CustomerCredential]":
        """Every active credential for `username`, in cred_key order (the customer's enrolled factors)."""
        if not isinstance(username, str) or not username:
            return []
        hit = self._cached(lambda v: [(username, ck, v.active[(username, ck)])
                                      for ck in sorted(v.by_user.get(username, ()))])
        if hit is not _UNCACHED:
            return [self._to_cred(u, ck, row) for u, ck, row in hit]
        fold = self._fold()
        out = [self._to_cred(u, ck, row) for (u, ck), row in fold.items() if u == username]
        return sorted(out, key=lambda c: c.cred_key)

    def totp_for(self, username: str) -> Optional[CustomerCredential]:
        """The active TOTP credential for `username` (carrying the sealed secret), or None."""
        if not isinstance(username, str) or not username:
            return None
        row = self._cached(lambda v: v.active.get((username, _CRED_KEY_TOTP)))
        if row is _UNCACHED:
            row = self._fold().get((username, _CRED_KEY_TOTP))
        return self._to_cred(username, _CRED_KEY_TOTP, row) if row is not None else None

    def by_credential_id(self, credential_id: str) -> Optional[CustomerCredential]:
        """The active PASSKEY credential whose credential_id matches — resolving the owning customer. Returns
        a match ONLY when EXACTLY ONE active passkey binds that id (fail-closed on 0 or an ambiguous >1, so a
        duplicate-id hijack can never resolve a login to the wrong customer)."""
        cid = str(credential_id or "").strip()
        if not cid:
            return None
        hits = self._cached(lambda v: [(u, cid, v.active[(u, cid)]) for u in sorted(v.by_ck.get(cid, ()))
                                       if v.active[(u, cid)].get("kind") == KIND_PASSKEY])
        if hits is _UNCACHED:
            hits = [(u, ck, row) for (u, ck), row in self._fold().items()
                    if ck == cid and row.get("kind") == KIND_PASSKEY]
        if len(hits) != 1:
            return None
        u, ck, row = hits[0]
        return self._to_cred(u, ck, row)

    def by_federated(self, iss: str, sub: str) -> Optional[str]:
        """The customer username bound to a Google `(iss, sub)` — a match ONLY when EXACTLY ONE active oidc
        credential binds it (fail-closed on 0 or an ambiguous >1). The anti-takeover resolver E2b trusts."""
        return self._federated_username(str(iss or "").strip(), str(sub or "").strip())

    def _federated_username(self, iss: str, sub: str) -> Optional[str]:
        if not iss or not sub:
            return None
        cached = self._cached(lambda v: sorted(v.by_fed.get((iss, sub), ())))
        if cached is not _UNCACHED:
            return cached[0][0] if len(cached) == 1 else None
        hits = [u for (u, ck), row in self._fold().items()
                if row.get("kind") == KIND_OIDC and row.get("federated_iss") == iss
                and row.get("federated_sub") == sub]
        return hits[0] if len(hits) == 1 else None
