"""Enterprise SaaS BILLING — the per-tenant prepaid CREDIT WALLET (owner-signed grants + deterministic debits).

This is the SOVEREIGN system-of-record for a paying tenant's credit balance: an append-only, owner-signed
ledger folded from the spine, keyed per `org_id` (== `tenant_id`, the identity wave), with the SAME anti-replay
+ hard-prune durability as `accounts.py` / `orgs.py`. The keyless OFFENSE plane never reads this module
directly (FATAL-2); a later slice has the offense runner DELEGATE the balance check to the sovereign plane (as
`uiproxy._whoami` already delegates auth) or consume a signed decision. This module is the ledger primitive
only — the pre-scan and mid-scan credit GATES, the Stripe adapter, and the metering wire are later slices.

MODEL (both directions owner/gate-signed + verified — a wallet has NO "honored-unsigned" direction: an
unsigned grant must not credit you AND an unsigned debit must not drain you, so a forged record of either kind
is inert in the fold):
  * `governor.credit_grant` — adds `credits` to a tenant's balance. `kind` in {trial, subscription_refill,
    topup}. Each grant carries a globally-unique `entry_id`; a grant whose (org_id, entry_id) is ALREADY folded
    is IGNORED (idempotent), so a captured/replayed grant — including one replayed AFTER a hard prune — can
    never re-credit. `source_ref` (e.g. a Stripe event id) dedups at the webhook→grant layer above; `entry_id`
    is the spine-level idempotency key.
  * `governor.credit_debit` — subtracts `credits`, appended by the deterministic sovereign metering gate as a
    tenant spends (one debit per completed, metered unit of scan work). Same idempotency per (org_id,
    entry_id); `credits` CLAMPED >= 0 so a forged NEGATIVE debit cannot refund.

BALANCE(org) = Σ(honored grant credits) − Σ(honored debit credits), each credit clamped >= 0 and FROZEN per
record (the spine IS the ledger — no mutable counter to drift or forge; a later price-table edit never
rewrites history). Fail-CLOSED: balance <= 0 means no spend (enforced by the later gates; this module exposes
the deterministic balance + the append primitives). A tenant can never spend another's credits — the balance
is keyed on the owner-signed `org_id`, never an LLM/agent-asserted label.

ANTI-REPLAY ACROSS A HARD PRUNE (the load-bearing difference from `governor/budget.py`): a per-UTC-day budget
needs no snapshot seed because the prune retention invariant keeps today's records live. A wallet balance is a
LIFETIME running total, so it MUST be seeded from `SnapshotState` or the first hard prune would (1) ZERO every
tenant's balance (every historical grant is gone) and (2) drop the consumed-`entry_id` set, re-opening grant
replay (a pruned grant re-appended above the prune boundary would be counted afresh). The fold therefore seeds
per-org `granted_total` / `debited_total` + the consumed `(org_id, entry_id)` set from `SnapshotState` (the
same cross-a-prune carry the `consumed_arm_nonces` / `device_approval_dedup` bearers already have), then folds
the LIVE window only. `spine.prune` refuses any prune that would strand a tenant wallet the seed does not carry
(same fail-closed tripwire as `stranded_active_accounts`). Owner-key-succession-aware exactly like the account
fold: each signed record is verified under the owner pubkey valid AT ITS SEQ; a rotated/empty anchor bypasses
the snapshot and full-scans from genesis (byte-identical under the empty snapshot).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors accounts._fold)
from .authn import signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402  (org_id validation == tenant-id validation; same-plane reuse)
from ..spine.snapshot import SnapshotState  # noqa: E402  (hard-prune seed — mirrors accounts._fold)

CREDIT_GRANT_SIGNAL = "governor.credit_grant"
CREDIT_DEBIT_SIGNAL = "governor.credit_debit"

# The kinds of grant that may credit a wallet. `trial` = the free-trial grant at signup; `subscription_refill`
# = the per-period plan allotment; `topup` = a paid credit purchase (anytime, incl. the pay-to-complete moment);
# `refund` = returning the UNUSED portion of a launch reservation on settlement/cancel (Slice G; reserve debits
# the spend cap, settle grants back cap - consumed, so net spend == metered consumption).
GRANT_KINDS = frozenset({"trial", "subscription_refill", "topup", "refund"})

# The owner-signed authenticated CORE of each record. `entry_id` is inside it so a captured record cannot be
# re-stamped with a fresh idempotency key to bypass the seen-set. `credits`/`org_id` are inside it so a grant
# for (orgA, 100) can never be re-aimed at another org or have its amount rewritten without breaking the
# signature. `issued_at` is inside it (audit/ordering only — the wallet is additive, NOT LWW, so there is no
# per-key issued_at high-water; idempotency is by entry_id, which is why entry_id MUST be signed).
_GRANT_CORE = ("signal", "org_id", "entry_id", "credits", "kind", "source_ref", "issued_at")
_DEBIT_CORE = ("signal", "org_id", "entry_id", "credits", "engagement_id", "issued_at")


def _as_credits(v: object) -> int:
    """A credits value read off the spine → a non-negative int. CLAMPED to >= 0 (mirrors budget.py::_as_int):
    the fold SUMS signed per-record values, so a NEGATIVE grant/debit must not CANCEL real balance (that would
    be a fail-OPEN refund/credit bypass). Junk / NaN / an over-large int (OverflowError) → 0. Credits are whole
    units by construction."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float, str)):
        try:
            n = int(v)
        except (TypeError, ValueError, OverflowError):
            return 0
        return n if n > 0 else 0
    return 0


def _check_credits(credits: int) -> int:
    """Validate a credits amount at BINDING time (a clean ValueError now, never a silent bad record later).
    Must be a positive whole number (a grant/debit of 0 or negative is meaningless and refused)."""
    if isinstance(credits, bool) or not isinstance(credits, int):
        raise ValueError("credits must be a positive integer")
    if credits <= 0:
        raise ValueError("credits must be a positive integer (> 0)")
    return credits


def _check_entry_id(entry_id: Optional[str]) -> str:
    """A globally-unique idempotency key for one ledger entry. Generated server-side when not supplied. Bounded
    and non-control so it round-trips the signed core and the snapshot rows verbatim."""
    if entry_id is None:
        import uuid
        return uuid.uuid4().hex
    e = str(entry_id).strip()
    if not e or len(e) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in e):
        raise ValueError("entry_id must be a non-empty, non-control string of <= 128 chars")
    return e


@dataclass(frozen=True)
class Balance:
    """A tenant's current credit position, every field derived from the spine (never a stored counter)."""
    org_id: str
    granted: int        # Σ honored grant credits (lifetime)
    debited: int        # Σ honored debit credits (lifetime)

    @property
    def available(self) -> int:
        """Spendable credits now. Clamped >= 0 for display; the gates deny at <= 0 (fail-closed). A sound
        ledger never debits past the balance, so `granted - debited` is already >= 0 in practice; the clamp is
        defence-in-depth against a forged over-debit (which can only harm the attacker's own tenant)."""
        return max(0, self.granted - self.debited)


class WalletRegistry:
    """Owner-signed per-tenant credit wallet on the spine. Construction mirrors `OrgRegistry` / `AccountsRegistry`:
    the owner signing key + trusted pubkey default to the persisted owner identity; tests inject explicit keys."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def grant(self, org_id: str, credits: int, kind: str, *, source_ref: str = "",
              entry_id: Optional[str] = None, issued_at: float) -> int:
        """Owner-sign a credit grant for a tenant — adds `credits` to the wallet. Requires the owner signing
        key (an unsigned grant never verifies in the fold, so it would be inert). `kind` ∈ GRANT_KINDS;
        `source_ref` is the upstream idempotency anchor (e.g. a Stripe event id), carried for audit. Returns
        the record seq. Re-appending the same `entry_id` is a harmless no-op in the fold (idempotent)."""
        if self.owner_key is None:
            raise ValueError("credit grant requires the owner signing key")
        oid = org_tenant_id(org_id)                       # validates org_id == a valid tenant id, fail-closed
        c = _check_credits(credits)
        k = str(kind or "").strip()
        if k not in GRANT_KINDS:
            raise ValueError(f"grant kind must be one of {sorted(GRANT_KINDS)}")
        eid = _check_entry_id(entry_id)
        core = {"signal": CREDIT_GRANT_SIGNAL, "org_id": oid, "entry_id": eid, "credits": c,
                "kind": k, "source_ref": str(source_ref or ""), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"credit grant {c} ({k}) -> {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def debit(self, org_id: str, credits: int, *, engagement_id: str = "",
              entry_id: Optional[str] = None, issued_at: float) -> int:
        """Record a credit debit as a tenant spends (the deterministic metering gate calls this with the
        metered cost of one COMPLETED unit of scan work). Owner/gate-signed + verified so a forged debit cannot
        drain a victim tenant's balance; idempotent per `entry_id` so a retried settlement cannot double-charge;
        `credits` clamped > 0 at binding. A debit for work LOST to a VIGIL-side failure is simply never appended
        (mirrors a DENIED action carrying no usage), so a crash never costs the customer credits."""
        if self.owner_key is None:
            raise ValueError("credit debit requires the owner signing key")
        oid = org_tenant_id(org_id)
        c = _check_credits(credits)
        eid = _check_entry_id(entry_id)
        core = {"signal": CREDIT_DEBIT_SIGNAL, "org_id": oid, "entry_id": eid, "credits": c,
                "engagement_id": str(engagement_id or ""), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"credit debit {c} <- {oid} (engagement {engagement_id or '-'})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _fold(self) -> tuple[dict[Any, int], dict[Any, int], set]:
        """Fold the spine into (granted_total, debited_total, seen) where `seen` is the set of consumed
        (org_id, entry_id) idempotency keys. Each signed record is authenticated under the owner pubkey valid
        AT ITS SEQ; a record whose (org_id, entry_id) is already in `seen` is ignored (idempotent — the
        replay/double-count guard). HARD-PRUNE SEED (mirrors `accounts._fold`): seed the per-org totals + the
        `seen` set from `SnapshotState`, then fold the LIVE window only — so a pruned grant/debit stays counted
        and its entry_id stays consumed (a pruned grant cannot be replayed to re-credit). The seed is valid only
        under the pubkey it was folded with: a rotated/empty anchor BYPASSES the snapshot and full-scans from
        genesis (byte-identical under the empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        if self.trusted_pubkey != snap.trusted_pubkey:
            # Anchor mismatch (rotated key / empty identity) ⇒ bypass the snapshot and full-scan from genesis,
            # mirroring accounts._fold. DEFERRED (prune-integration slice): unlike the pubkey-DEPENDENT folds,
            # the wallet seed is ADDITIVE and was already verified under the key valid at each seq, so a future
            # prune+rotation path should CARRY this seed (accept a snapshot whose trusted_pubkey is any key in
            # the succession history) rather than bypass to a rescan — else a pruned tenant's balance would
            # transiently under-read until the next prune re-commits under the new key. Unreachable today:
            # SnapshotState.load fails closed on any real prune (the Slice-D/E cutover is unwired), so this
            # bypass is only taken under the empty (no-prune) snapshot, where genesis-scan == the correct fold.
            granted: dict[Any, int] = {}
            debited: dict[Any, int] = {}
            seen: set = set()
            since = -1
        else:
            granted = dict(snap.wallet_granted_map())
            debited = dict(snap.wallet_debited_map())
            seen = set(snap.wallet_seen_set())
            since = snap.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict):
                continue
            sig = p.get("signal")
            if sig != CREDIT_GRANT_SIGNAL and sig != CREDIT_DEBIT_SIGNAL:
                continue
            oid = p.get("org_id")
            eid = p.get("entry_id")
            if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid):
                continue
            core = _GRANT_CORE if sig == CREDIT_GRANT_SIGNAL else _DEBIT_CORE
            if not verify_signed(p, core, resolver.at(r.seq)):
                continue                                  # fail-closed: unsigned/forged/wrong-epoch record
            # Idempotency key is namespaced by SIGNAL (direction), not just (org, entry_id): a grant and a
            # debit are distinct events even if a caller reuses an entry_id across directions, so they must
            # occupy DISJOINT dedup spaces — else the second to fold would be silently dropped (free credits,
            # or lost paid credits). Per-direction replay protection is unchanged (a replayed grant is still an
            # identical (grant, org, entry_id)).
            key = (sig, oid, eid)
            if key in seen:
                continue                                  # idempotent: this entry already counted (replay)
            seen.add(key)
            amount = _as_credits(p.get("credits"))
            if sig == CREDIT_GRANT_SIGNAL:
                granted[oid] = granted.get(oid, 0) + amount
            else:
                debited[oid] = debited.get(oid, 0) + amount
        return granted, debited, seen

    def balance(self, org_id: str) -> Balance:
        """The current credit position for `org_id` (fail-closed: an unknown/empty org reads as all-zero)."""
        if not isinstance(org_id, str) or not org_id:
            return Balance(org_id="", granted=0, debited=0)
        granted, debited, _ = self._fold()
        return Balance(org_id=org_id, granted=granted.get(org_id, 0), debited=debited.get(org_id, 0))

    def available(self, org_id: str) -> int:
        """Spendable credits for `org_id` right now (0 for unknown). The scalar the later pre-scan / mid-scan
        gates test ( > 0 to proceed, fail-closed)."""
        return self.balance(org_id).available

    def balances(self) -> list[Balance]:
        """Every tenant with ledger activity, in org_id order (the per-tenant billing view)."""
        granted, debited, _ = self._fold()
        orgs = sorted(set(granted) | set(debited))
        return [Balance(org_id=str(o), granted=granted.get(o, 0), debited=debited.get(o, 0)) for o in orgs]
