"""SnapshotState — the folded summary of a pruned spine prefix `[0..base_seq)` (cold-archive hard-prune).

A hard prune deletes records `[0..K)` from the live spine but keeps a signed `kind="snapshot"` record that
commits a FOLDED summary of everything the pruned prefix carried that a consumer still needs. Every consumer
that today scans ALL records from genesis to compute a MONOTONIC security state (a replay high-water, a latch,
an authorization set, a cap count, ...) must instead: `st = SnapshotState.load(store)` (the folded state of
`[0..K)`), then fold `st` forward over the LIVE records `[K..T]` only.

For this to be EXACT and crash-safe, every bearer's fold is ASSOCIATIVE (max / set-union / last-write-wins /
count-add / boolean-latch), so `fold(fold(empty,[0..K)),[K..T]) == fold(empty,[0..T]) == the current full
scan`, for any prune point K. **Slice C ships NO prune**: `load()` returns the EMPTY identity (`base_seq=0`,
every sub-state empty) universally, so every rewired consumer, seeded with the identity and windowed at
`base_seq=0` (a full scan), is BYTE-IDENTICAL to its current genesis scan. `build()` (the prefix folder) and
the identity/split equivalence tests prove the fold machinery for when Slice D/E turns pruning on.

Sub-state ↔ bearer (all identity-empty in Slice C):
  nonce_highwater        {device: max int-nonce}                 join-semilattice (max)         envelope replay floor
  killswitch_engaged     bool                                    last-write latch (ID/T/F)      governor halt
  killswitch_issued_hw   float|None                              join-semilattice (max)         release anti-replay
  capability_issued      {capability: max issued_at}             join-semilattice (max)         enable anti-replay
  creation_created       {(service,origin): count}               count-add (PAIR key!)          DELEGATE account cap
  capability_map         {host_id: cap}                          right-biased LWW               mesh host capability
  capability_map_issued  {host_id: max issued_at}                join-semilattice (max)         advert anti-replay
  mesh_dev_state         {device_pubkey: authorized|revoked}     LWW (keep revoked!)            mesh device authz
  mesh_dev_issued        {device_pubkey: max issued_at}          join-semilattice (max)         authorize anti-replay
  promotion              {(agent,scope): granted|revoked}        LWW (keep revoked!)            auto-approval grants
  promotion_issued       {(agent,scope): max issued_at}          join-semilattice (max)         grant anti-replay
  account_state          {username: active|revoked}              LWW (keep revoked!)            RBAC account authz
  account_issued         {username: max issued_at}               join-semilattice (max)         grant anti-replay
  account_cred           {username: role/cred_hash/cred_salt/pubkey} right-biased LWW           active-account rebuild
  consumed_arm_nonces    {(device_pubkey, nonce)}                set-union                      HID-arm replay ledger
  device_approval_dedup  {(pubkey,sig): min_seq}                 min-seq semilattice            device-approval idempotency
  warden_best            {pubkey: (max_count, head_hash, seq)}   max-count LWW-tie              warden anchor high-water
  archivist_view + grounded_keys + refused_keys                  dict-union + set-union         archivist current-view
  approvals (open_queued_below_base assert)                      referential-floor ASSERT       approval queue
  budget                 (no sub-state)                          retention invariant            per-UTC-day cap

The pubkey-dependent folds (killswitch/capability/mesh_dev/promotion) are valid ONLY under the trust anchor
they were folded with; `trusted_pubkey` is recorded so a rotated-key or custom-anchor query bypasses the
snapshot and re-scans from genesis (see each consumer).
"""
from __future__ import annotations

import dataclasses
from typing import Any, Iterable, Optional

from pydantic import BaseModel, ConfigDict

from ..config import HEAD_PATH
from ..reuse import SignedChainHead
from .models import SpineRecord
from .schema_guard import refuse_newer

_MAX_SNAPSHOT_SCHEMA = 2   # refuse-newer gate (W5-3): a snapshot schema above this is "upgrade sigil".
#                            v2 (Slice E1) ADDED the governor.customer sub-state (customer_state/issued/cred).
#                            A pre-E1 build (max v1) refuses a v2 snapshot cleanly; this build still reads a v1
#                            snapshot (the customer_* fields default to empty — additive-with-defaults, C1/C3).


class SnapshotState(BaseModel):
    """The persisted folded state. Fields are JSON-native (tuple-keyed / set sub-states use list forms that
    round-trip verbatim); runtime accessors reconstruct the sets / tuple-keyed dicts. Non-secret."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 2   # W5-3: bumped 1->2 by Slice E1 (added the governor.customer sub-state). Every
    #                           snapshot this build emits carries the customer_* keys, so it is a v2 artifact;
    #                           a pre-E1 build (max v1) refuses it cleanly via the refuse-newer gate.
    base_seq: int = 0                 # first LIVE seq K; pruned prefix is [0..base_seq); 0 = no prune
    snapshot_seq: int = -1            # the committed snapshot record's seq; -1 = no prune (identity)
    trusted_pubkey: str = ""          # owner pubkey the pubkey-dependent folds were computed under

    nonce_highwater: dict[str, int] = {}
    killswitch_engaged: bool = False
    # ANTI-REPLAY high-waters of the governance latches: the largest `issued_at` whose DANGEROUS-direction
    # record was actually HONORED in the pruned prefix. `None` (or an absent row) means "none honored yet" —
    # the -inf bottom. A sentinel and not a number because -inf is not portable JSON and 0.0 is itself a
    # legitimate high-water (an unparseable `issued_at` folds to 0.0). These MUST be carried across a prune:
    # without them the first hard prune would reset every high-water to the bottom and make every release /
    # enable / grant / device authorization in the pruned prefix replayable again — i.e. the pruning work
    # would silently undo the anti-replay guard. The fold is `max` over honored records, a join-semilattice,
    # so it is associative exactly like `nonce_highwater`.
    killswitch_issued_hw: Optional[float] = None
    capability_latch: list = []       # [[capability, enabled_bool], ...] — governor.capability latch (LWW:
    #                                   disable=any, enable=owner-verified). Missing capability ⇒ enabled.
    capability_issued: list = []      # [[capability, issued_at], ...] — PER-CAPABILITY enable high-water.
    #                                   Missing row ⇒ the -inf bottom. Per capability and never global: a
    #                                   global one would let a fresh enable(voice) refuse a legitimate
    #                                   later enable(gesture) carrying a smaller issued_at.
    # tuple-keyed / None-tolerant sub-states as list-of-rows (JSON-safe + type-verbatim): a non-str key an
    # owner-signed-but-malformed record could carry (host_id/device_pubkey/agent/scope = None/int) is
    # preserved EXACTLY — the live scans key on p.get(...) with no type guard, so dropping such a key would
    # make build() != scan. `dict(rows)` / the accessors reconstruct the map (incl. any non-str key).
    creation_created: list = []       # [[service|None, origin|None, count], ...]
    capability_map: list = []         # [[host_id, cap_dict], ...]  -> dict() reconstructs (keys verbatim)
    capability_map_issued: list = []  # [[host_id, issued_at], ...] — PER-HOST advertisement high-water.
    #                                   Missing row ⇒ the -inf bottom. Per host and never global.
    mesh_dev_state: list = []         # [[device_pubkey, "authorized"|"revoked"], ...] -> dict() reconstructs
    mesh_dev_issued: list = []        # [[device_pubkey, issued_at], ...] — PER-DEVICE authorize high-water.
    #                                   Missing row ⇒ the -inf bottom. Per device and never global: one
    #                                   phone's fresh authorization must not refuse another phone's
    #                                   legitimate later one carrying a smaller issued_at.
    promotion: list = []              # [[agent, scope, "granted"|"revoked"], ...]
    promotion_issued: list = []       # [[agent, scope, issued_at], ...] — PER-(agent,scope) grant high-water.
    #                                   Missing row ⇒ the -inf bottom. Per key and never global: a global one
    #                                   would let a grant for agent A refuse a legitimate later grant for
    #                                   agent B carrying a smaller issued_at.
    account_state: list = []          # [[username, "active"|"revoked"], ...] — governor.account LWW
    #                                   (revoke=any, active=owner-verified + FRESH). Keep revoked.
    account_issued: list = []         # [[username, issued_at], ...] — PER-USERNAME active-grant high-water.
    #                                   Missing row ⇒ the -inf bottom. Per username and never global. MUST cross
    #                                   a prune, or the first hard prune resets it and a captured owner-signed
    #                                   `active` grant becomes replay-resurrectable again (the LWW replay HIGH).
    account_cred: list = []           # [[username, role, cred_hash, cred_salt, user_pubkey, totp_secret,
    #                                   password_hash, expires_at], ...] — the fields to REBUILD an active
    #                                   `Account` from the seed (issued_at joins from account_issued;
    #                                   state="active"). Each optional trailing field is None for a shorter/legacy
    #                                   row: user_pubkey (S3 PoP key), totp_secret (S4 SEALED second factor),
    #                                   password_hash (S4 optional login), expires_at (the ABSOLUTE token
    #                                   deadline). Carrying totp_secret/password_hash/expires_at keeps a hard
    #                                   prune from silently DOWNGRADING an account's auth (dropping its enrolled
    #                                   second factor) or its DEADLINE (a pruned account silently never-expiring).
    #                                   Carried for every honored-active username (incl. ones later revoked —
    #                                   dropped at read time by account_state, exactly as the scan).
    customer_state: list = []         # [[username, "active"|"revoked"], ...] — governor.customer LWW
    #                                   (revoke=any, active=owner-verified + FRESH). Keep revoked. A DISJOINT
    #                                   namespace from account_state (a customer is never an operator account).
    customer_issued: list = []        # [[username, issued_at], ...] — PER-USERNAME active-grant high-water.
    #                                   Missing row ⇒ -inf bottom. MUST cross a prune, or the first hard prune
    #                                   resets it and a captured owner-signed `active` customer grant becomes
    #                                   replay-resurrectable (identical invariant to account_issued).
    customer_cred: list = []          # [[username, email, password_hash], ...] — the fields to REBUILD an
    #                                   active `CustomerAccount` from the seed (issued_at joins from
    #                                   customer_issued; state="active"). password_hash is None for an
    #                                   OIDC/passkey-only customer; carried so a pruned customer keeps its login.
    org_state: list = []              # [[org_id, "active"|"revoked"], ...] — governor.org LWW (keep revoked).
    org_issued: list = []             # [[org_id, issued_at], ...] — PER-ORG active-grant high-water. Missing
    #                                   row ⇒ the -inf bottom. MUST cross a prune, or the first hard prune
    #                                   resets it and a captured owner-signed `active` org grant becomes
    #                                   replay-resurrectable (identical invariant to account_issued).
    org_row: list = []                # [[org_id, name, owner], ...] — the fields to REBUILD an active `Org`
    #                                   from the seed (created_at joins from org_issued; state="active").
    membership_state: list = []       # [[org_id, username, "active"|"revoked"], ...] — governor.org_membership
    #                                   LWW, keyed PER-(org_id, username). Keep revoked.
    membership_issued: list = []      # [[org_id, username, issued_at], ...] — PER-(org_id, username) high-water.
    #                                   Same cross-a-prune invariant as account_issued, per membership key.
    membership_row: list = []         # [[org_id, username, role], ...] — the fields to REBUILD an active
    #                                   `Membership` from the seed (issued_at joins from membership_issued).
    wallet_granted: list = []         # [[org_id, granted_total], ...] — Σ honored SaaS credit GRANTS per
    #                                   tenant (governor.credit_grant). balance = granted - debited is a
    #                                   LIFETIME running total, so (unlike the per-UTC-day budget, which keeps
    #                                   NO sub-state) it MUST cross a prune or the first prune zeroes it.
    wallet_debited: list = []         # [[org_id, debited_total], ...] — Σ honored SaaS credit DEBITS per tenant.
    wallet_seen: list = []            # [[signal, org_id, entry_id], ...] — consumed wallet idempotency keys,
    #                                   NAMESPACED BY SIGNAL (grant vs debit are disjoint dedup spaces), carried
    #                                   across a prune so a pruned grant/debit cannot be replayed to re-credit
    #                                   or re-charge (set-union bearer, like consumed_arm_nonces).
    subscription_state: list = []     # [[org_id, "active"|"past_due"|"canceled"], ...] — governor.subscription
    #                                   LWW per org (active = owner-verified + FRESH; down-states honored on
    #                                   sight). Keep the down-state.
    subscription_issued: list = []    # [[org_id, issued_at], ...] — PER-ORG active high-water; MUST cross a
    #                                   prune or a replayed `active` could resurrect a lapsed plan.
    subscription_row: list = []       # [[org_id, plan_id, period_start, period_end, allotment], ...] — the plan
    #                                   fields to REBUILD the Subscription from the seed (status joins from
    #                                   subscription_state).
    plan_granted: list = []           # [[org_id, period_end, granted_total], ...] — Σ honored PLAN-credit GRANTS
    #                                   per (tenant, billing period) (governor.plan_grant). A per-period tranche
    #                                   remainder (granted - debited) is spendable only until period_end, so (like
    #                                   the wallet, unlike the per-UTC-day budget) it MUST cross a prune or the
    #                                   first prune would zero an unexpired tranche.
    plan_debited: list = []           # [[org_id, period_end, debited_total], ...] — Σ honored PLAN-credit DEBITS
    #                                   per (tenant, billing period) (governor.plan_debit).
    plan_seen: list = []              # [[signal, org_id, entry_id], ...] — consumed plan-credit idempotency keys,
    #                                   NAMESPACED BY SIGNAL (grant vs debit are disjoint), carried across a prune
    #                                   so a pruned plan grant/debit cannot be replayed (set-union bearer).
    consumed_arm_nonces: list = []    # [[device_pubkey, nonce], ...]  (nonce int OR str, verbatim)
    device_approval_dedup: list = []  # [[pubkey|None, sig|None, min_seq], ...]
    warden_best: dict[str, list] = {} # {pubkey: [max_count, head_hash, tiebreak_seq]}
    archivist_view: list = []         # [full record dict, ...] (ALL source==archivist records)
    grounded_keys: list[str] = []
    refused_keys: list[str] = []
    open_queued_below_base: list = [] # approvals referential-floor ASSERT — expected EMPTY

    # ---- runtime accessors (reconstruct the non-JSON-native runtime forms) -----------------------------
    def creation_counter(self) -> dict[tuple[Optional[str], Optional[str]], int]:
        return {(row[0], row[1]): row[2] for row in self.creation_created}

    def promotion_map(self) -> dict[tuple[Optional[str], Optional[str]], str]:
        return {(row[0], row[1]): row[2] for row in self.promotion}

    def promotion_issued_map(self) -> dict[tuple[Optional[str], Optional[str]], float]:
        return {(row[0], row[1]): row[2] for row in self.promotion_issued}

    def account_state_map(self) -> dict[Any, str]:
        return {row[0]: row[1] for row in self.account_state}

    def account_issued_map(self) -> dict[Any, float]:
        return {row[0]: row[1] for row in self.account_issued}
    #   account_cred stays a raw list-of-rows: `AccountsRegistry._fold` rebuilds the Account objects from it
    #   (joining issued_at from account_issued_map), keeping the `Account` import out of this leaf module.

    def customer_state_map(self) -> dict[Any, str]:
        return {row[0]: row[1] for row in self.customer_state}

    def customer_issued_map(self) -> dict[Any, float]:
        return {row[0]: row[1] for row in self.customer_issued}
    #   customer_cred stays a raw list-of-rows: `CustomerRegistry._fold` rebuilds the CustomerAccount objects
    #   from it (joining issued_at from customer_issued_map), keeping the import out of this leaf module.

    def org_state_map(self) -> dict[Any, str]:
        return {row[0]: row[1] for row in self.org_state}

    def org_issued_map(self) -> dict[Any, float]:
        return {row[0]: row[1] for row in self.org_issued}
    #   org_row stays a raw list-of-rows: `OrgRegistry._fold_orgs` rebuilds the Org objects from it (joining
    #   created_at from org_issued_map), keeping the `Org` import out of this leaf module.

    def membership_state_map(self) -> dict[tuple, str]:
        return {(row[0], row[1]): row[2] for row in self.membership_state}

    def membership_issued_map(self) -> dict[tuple, float]:
        return {(row[0], row[1]): row[2] for row in self.membership_issued}
    #   membership_row is a raw list-of-rows: `OrgRegistry._fold_memberships` rebuilds the Membership objects
    #   from it (joining issued_at from membership_issued_map), keyed PER-(org_id, username).

    def wallet_granted_map(self) -> dict[Any, int]:
        return {row[0]: row[1] for row in self.wallet_granted}

    def wallet_debited_map(self) -> dict[Any, int]:
        return {row[0]: row[1] for row in self.wallet_debited}

    def wallet_seen_set(self) -> set:
        return {(row[0], row[1], row[2]) for row in self.wallet_seen}   # (signal, org_id, entry_id)

    def subscription_state_map(self) -> dict[Any, str]:
        return {row[0]: row[1] for row in self.subscription_state}

    def subscription_issued_map(self) -> dict[Any, float]:
        return {row[0]: row[1] for row in self.subscription_issued}
    #   subscription_row stays raw: `SubscriptionRegistry._fold` rebuilds the Subscription (status from
    #   subscription_state_map), keeping the Subscription import out of this leaf module.
    #   `WalletRegistry._fold` seeds (granted, debited, seen) from these; balance = granted - debited, and the
    #   seen-set is the idempotency/anti-replay guard that MUST survive a prune (mirrors accounts._fold).

    def plan_granted_map(self) -> dict[Any, int]:
        return {(row[0], row[1]): row[2] for row in self.plan_granted}   # (org_id, period_end) -> Σ grants

    def plan_debited_map(self) -> dict[Any, int]:
        return {(row[0], row[1]): row[2] for row in self.plan_debited}   # (org_id, period_end) -> Σ debits

    def plan_seen_set(self) -> set:
        return {(row[0], row[1], row[2]) for row in self.plan_seen}      # (signal, org_id, entry_id)
    #   `PlanCreditLedger._fold` seeds (granted, debited, seen) from these, keyed per (org_id, period_end); a
    #   tranche is spendable only while period_end > now (non-rollover), applied at read time in `available`.

    def capability_latch_map(self) -> dict[Optional[str], bool]:
        return {row[0]: row[1] for row in self.capability_latch}

    def capability_issued_map(self) -> dict[Optional[str], float]:
        return {row[0]: row[1] for row in self.capability_issued}

    def mesh_dev_issued_map(self) -> dict[Any, float]:
        return {row[0]: row[1] for row in self.mesh_dev_issued}

    def capability_map_issued_map(self) -> dict[Any, float]:
        return {row[0]: row[1] for row in self.capability_map_issued}

    def arm_set(self) -> set:
        return {(row[0], row[1]) for row in self.consumed_arm_nonces}

    def approval_dedup_map(self) -> dict[tuple[Optional[str], Optional[str]], int]:
        return {(row[0], row[1]): row[2] for row in self.device_approval_dedup}

    def warden_best_of(self, pubkey: str) -> tuple[int, str, int]:
        row = self.warden_best.get(pubkey)
        return (row[0], row[1], row[2]) if row else (0, "", -1)

    def archivist_records_of(self, kinds: Optional[Iterable[str]]) -> list[SpineRecord]:
        ks = set(kinds) if kinds is not None else None
        recs = [SpineRecord.from_dict(d) for d in self.archivist_view]
        recs = [r for r in recs if ks is None or r.kind in ks]
        recs.sort(key=lambda r: r.seq)     # ascending seq (all snapshot seqs < base_seq)
        return recs

    @classmethod
    def empty(cls) -> "SnapshotState":
        return cls()

    @classmethod
    def from_folded(cls, folded: dict) -> "SnapshotState":
        """Validate a persisted ``folded_state`` dict, REFUSING a schema version newer than this build
        understands (W5-3, #447). ``extra="forbid"`` already rejects an UNKNOWN field a newer writer added,
        but a newer writer that DROPS a fold row this build carries would parse clean — every missing field
        defaulting to its empty identity, which is precisely the "hard prune silently resets an anti-replay
        high-water" failure this state's own docstring warns about. So gate on ``schema_version`` and fail
        CLOSED. Both the production load path and the prune-time seed re-load route through here so neither
        can silently down-read a future snapshot."""
        st = cls.model_validate(folded)
        refuse_newer(st.schema_version, _MAX_SNAPSHOT_SCHEMA, artifact="snapshot state")
        return st

    # ---- load (production) -----------------------------------------------------------------------------
    @classmethod
    def load(cls, store) -> "SnapshotState":
        """The folded state committed by the CURRENT signed head. In Slice C there is no prune, so this is
        the EMPTY identity (`base_seq=0`, `snapshot_seq=-1`) universally. When a prune is declared
        (`head.snapshot_seq >= 0`), the boundary is trusted ONLY after the owner signature over it verifies
        (`_verified_prune_boundary`); it then deserializes the `kind="snapshot"` record the head names and
        cross-checks it — RAISING on an unverifiable head OR a missing/mismatched snapshot (fail closed: a
        pruned spine whose snapshot is forged/unreadable must NEVER be scanned as a truncated window)."""
        base_seq, snapshot_seq = _verified_prune_boundary(store)
        if snapshot_seq < 0:
            return cls.empty()                             # no prune — identity (the universal Slice-C path)
        rec = store.get(snapshot_seq)
        if rec is None or rec.kind != "snapshot":
            raise SnapshotError(f"pruned head names snapshot seq {snapshot_seq} but it is absent/not a "
                                f"snapshot record — refusing to scan a truncated window")
        folded = rec.payload.get("folded_state")
        if not isinstance(folded, dict):
            raise SnapshotError(f"snapshot record {snapshot_seq} carries no folded_state")
        st = cls.from_folded(folded)                        # W5-3: refuse a snapshot newer than we understand
        if st.base_seq != base_seq or st.snapshot_seq != snapshot_seq:
            raise SnapshotError(f"snapshot record {snapshot_seq} base/seq disagree with the signed head")
        return st


class SnapshotError(Exception):
    """A committed snapshot is missing or inconsistent — fail closed, never scan a truncated window."""


def _verified_prune_boundary(store) -> tuple[int, int]:
    """(base_seq, snapshot_seq) from the signed head — but the folded governance state a prune commits
    (kill-switch latch, device authz, promotion grants) is trustworthy ONLY under the OWNER SIGNATURE that
    covers base_seq/snapshot_seq. The genesis scan this slice replaces verified EVERY governance record
    per-signature, so without this check an FS-write attacker (no owner key) could forge a `kind="snapshot"`
    record + edit head.json to release a kill-switched mesh or authorize a rogue device — the folded rows
    carry no signature of their own, and `trusted_pubkey` is a PUBLIC string an attacker can set. So: when a
    prune is declared, VERIFY the on-disk head (owner Ed25519 + floor) before returning the boundary. Fails
    CLOSED (SnapshotError) on an unverifiable pruned head. Returns (0, -1) ONLY for a genuinely absent head
    or a parsed no-prune head; a PRESENT-but-unparseable head also fails closed (never masquerades as
    no-prune, which would scan a truncated post-prune window with empty seeds)."""
    if not HEAD_PATH.exists():
        return 0, -1                                        # genuinely no head -> genesis, nothing pruned
    try:
        head = SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — present but corrupt/unparseable/future-schema: fail CLOSED
        raise SnapshotError(f"head present but unparseable — refusing to treat as no-prune (would scan a "
                            f"truncated window with empty seeds): {e}") from e
    if head.snapshot_seq < 0:
        return 0, -1                                        # parsed, no prune declared -> empty identity
    # A prune IS declared: the boundary is only trustworthy under the owner signature. Reuse the full
    # verifier (owner Ed25519 over head_hash+base_seq+snapshot_seq, monotonic floor). Fail closed on any
    # non-clean result. (Not on the Slice-C hot path — legit Slice-C heads carry snapshot_seq == -1.)
    from .checkpoint import verify_checkpoint
    ok, msg = verify_checkpoint(store)
    if not ok:
        raise SnapshotError(f"pruned head does not verify ({msg}) — refusing to trust its snapshot boundary")
    return head.base_seq, head.snapshot_seq


# ======================================================================================================
# build() — fold a record iterable into a full SnapshotState. Used by Slice D/E (compute the snapshot at
# prune time) and by the Slice-C equivalence tests (synthesize a prefix snapshot to prove fold == scan).
# Each per-record step mirrors its consumer's live-fold EXACTLY; the equivalence tests pin build+consumer
# == the old genesis scan. Helpers/constants are imported LAZILY so snapshot.py stays a leaf (the consumer
# modules import THIS module).
# ======================================================================================================
def build(records: Iterable[SpineRecord], *, trusted_pubkey: Optional[str],
          base_seq: int, snapshot_seq: int, seed: Optional["SnapshotState"] = None,
          resolver=None) -> SnapshotState:
    """Fold `records` into a SnapshotState. With `seed` (a prior snapshot), the fold STARTS from the prior
    state — i.e. fold(prior, delta) — which is the multi-prune fold-of-fold: build(prior_folded, delta[K_prev
    ..K)) == build(empty, [0..K)) because every fold is associative. Without a seed, starts from the empty
    identity (the first prune / the Slice-C equivalence tests)."""
    from ..agents.actor_scope import _origin
    from ..bridge.envelope import RECEIPT_SIGNAL
    from ..consolidate.grounding import CONSOLIDATE_SOURCE
    from ..governor.authn import NO_HIGHWATER, as_issued_at, verify_signed
    # Import each consumer's REAL signed-core tuple rather than restating it here. A restated tuple is a
    # silent drift hazard: adding a field to a consumer's core (as the anti-replay `issued_at` did) while
    # this copy lagged would make build() honor records the live scan rejects, and vice versa.
    from ..governor.accounts import SIGNAL as _ACCT_SIGNAL
    # accounts signs `user_pubkey` CONDITIONALLY (only when a key is bound), so the verified field set is
    # derived per-grant from the payload — mirror the SAME helper the live scan uses, else a KEYED grant
    # (signed over 8 fields) would fail a static 7-field verify here and be dropped from the seed.
    from ..governor.accounts import _core_fields as _acct_core_fields
    # governor.customer — a DISJOINT owner-signed identity namespace (Slice E1). Its signed core is also
    # CONDITIONAL on password_hash, so mirror the SAME helper the live scan uses (same drift guard as acct).
    from ..governor.customers import SIGNAL as _CUST_SIGNAL
    from ..governor.customers import _core_fields as _cust_core_fields
    from ..governor.capability import SIGNAL as _CAPLATCH_SIGNAL
    from ..governor.capability import _CORE as _CAPLATCH_CORE
    from ..governor.killswitch import SIGNAL as _KS_SIGNAL
    from ..governor.killswitch import _CORE as _KS_CORE
    from ..governor.promotion import SIGNAL as _PROMO_SIGNAL
    from ..governor.promotion import _CORE as _PROMO_CORE
    from ..mesh.registry import CAP_SIGNAL, DEV_SIGNAL, _CAP_CORE, _DEV_CORE, cap_descriptor
    # org/membership signed-core tuples imported from the live module (never restated — same drift guard as
    # the account core above); the fold below carries them across a prune exactly as it does accounts.
    from ..governor.orgs import (ORG_SIGNAL as _ORG_SIGNAL, MEMBERSHIP_SIGNAL as _MEM_SIGNAL,
                                 _ORG_CORE, _MEMBERSHIP_CORE)
    # SaaS wallet signed-core tuples + the credits clamp imported from the live module (never restated — same
    # drift guard as the org cores above); the fold below carries the balance + anti-replay seen-set across a
    # prune exactly as it does accounts/orgs.
    from ..governor.wallet import (CREDIT_GRANT_SIGNAL as _WGRANT_SIGNAL, CREDIT_DEBIT_SIGNAL as _WDEBIT_SIGNAL,
                                   _GRANT_CORE as _WGRANT_CORE, _DEBIT_CORE as _WDEBIT_CORE,
                                   _as_credits as _w_as_credits)
    # plan-credit signed-cores + helpers imported from the live module (never restated — same drift guard); the
    # fold below carries per-(org, period_end) tranche totals + the consumed seen-set across a prune like wallet.
    from ..governor.metering import (PLAN_GRANT_SIGNAL as _PGRANT_SIGNAL, PLAN_DEBIT_SIGNAL as _PDEBIT_SIGNAL,
                                     _PLAN_GRANT_CORE as _PGRANT_CORE, _PLAN_DEBIT_CORE as _PDEBIT_CORE,
                                     _as_period as _p_as_period)
    # subscription signed-core + helpers imported from the live module (never restated — same drift guard);
    # the fold below carries the per-org status/high-water/plan-row across a prune exactly as it does orgs.
    from ..governor.subscription import (SUBSCRIPTION_SIGNAL as _SUB_SIGNAL, _SUB_CORE as _SUBS_CORE,
                                         STATUS_ACTIVE as _SUB_ACTIVE, _DOWN_STATES as _SUB_DOWN,
                                         _as_allotment as _sub_as_allotment)

    # The order-DEPENDENT folds (the kill-switch latch, every last-write-wins map) require ascending seq.
    # iter_records already yields ascending seq, but sort defensively so build() is correct for ANY caller /
    # iterable — an out-of-order input must never flip a latch or pick the wrong last-write.
    records = sorted(records, key=lambda r: r.seq)
    tp = trusted_pubkey or ""
    s = seed
    nonce: dict[str, int] = dict(s.nonce_highwater) if s else {}
    ks_engaged = s.killswitch_engaged if s else False
    ks_issued = (s.killswitch_issued_hw if s.killswitch_issued_hw is not None else NO_HIGHWATER) \
        if s else NO_HIGHWATER
    cap_latch: dict[Any, bool] = dict(s.capability_latch) if s else {}   # list-of-rows -> {capability: bool}
    cap_issued: dict[Any, float] = dict(s.capability_issued_map()) if s else {}
    creation: dict[tuple[Optional[str], Optional[str]], int] = dict(s.creation_counter()) if s else {}
    capability: dict[Any, dict] = dict(s.capability_map) if s else {}   # list-of-rows -> dict (keys verbatim)
    cap_map_issued: dict[Any, float] = dict(s.capability_map_issued_map()) if s else {}
    mesh_dev: dict[Any, str] = dict(s.mesh_dev_state) if s else {}
    mesh_dev_issued: dict[Any, float] = dict(s.mesh_dev_issued_map()) if s else {}
    promo: dict[tuple[Optional[str], Optional[str]], str] = dict(s.promotion_map()) if s else {}
    promo_issued: dict[tuple[Optional[str], Optional[str]], float] = (dict(s.promotion_issued_map())
                                                                      if s else {})
    acct_state: dict[Any, str] = dict(s.account_state_map()) if s else {}
    acct_issued: dict[Any, float] = dict(s.account_issued_map()) if s else {}
    acct_cred: dict[Any, list] = {row[0]: [row[1], row[2], row[3], (row[4] if len(row) > 4 else None),
                                           (row[5] if len(row) > 5 else None),
                                           (row[6] if len(row) > 6 else None),
                                           (row[7] if len(row) > 7 else None)]
                                  for row in s.account_cred} if s else {}   # 5/6/7/8 = user_pubkey / totp_secret /
    #                                                                         password_hash / expires_at (None legacy)
    cust_state: dict[Any, str] = dict(s.customer_state_map()) if s else {}
    cust_issued: dict[Any, float] = dict(s.customer_issued_map()) if s else {}
    cust_cred: dict[Any, list] = {row[0]: [row[1], (row[2] if len(row) > 2 else None)]
                                  for row in s.customer_cred} if s else {}   # [email, password_hash] (None legacy)
    org_state: dict[Any, str] = dict(s.org_state_map()) if s else {}
    org_issued: dict[Any, float] = dict(s.org_issued_map()) if s else {}
    org_row: dict[Any, list] = {row[0]: [row[1], row[2]] for row in s.org_row} if s else {}  # org_id->[name,owner]
    mem_state: dict[tuple, str] = dict(s.membership_state_map()) if s else {}
    mem_issued: dict[tuple, float] = dict(s.membership_issued_map()) if s else {}
    mem_row: dict[tuple, Any] = {(row[0], row[1]): row[2] for row in s.membership_row} if s else {}  # ->role
    w_granted: dict[Any, int] = dict(s.wallet_granted_map()) if s else {}   # org_id -> Σ grant credits
    w_debited: dict[Any, int] = dict(s.wallet_debited_map()) if s else {}   # org_id -> Σ debit credits
    w_seen: set = set(s.wallet_seen_set()) if s else set()                  # consumed (org_id, entry_id) keys
    p_granted: dict[Any, int] = dict(s.plan_granted_map()) if s else {}     # (org_id, period_end) -> Σ grants
    p_debited: dict[Any, int] = dict(s.plan_debited_map()) if s else {}     # (org_id, period_end) -> Σ debits
    p_seen: set = set(s.plan_seen_set()) if s else set()                    # consumed plan (sig, org, entry) keys
    sub_state: dict[Any, str] = dict(s.subscription_state_map()) if s else {}   # org_id -> status (LWW)
    sub_issued: dict[Any, float] = dict(s.subscription_issued_map()) if s else {}   # org_id -> active high-water
    sub_row: dict[Any, list] = {r[0]: [r[1], r[2], r[3], r[4]] for r in s.subscription_row} if s else {}
    arm: set = set(s.arm_set()) if s else set()
    dedup: dict[tuple[Optional[str], Optional[str]], int] = dict(s.approval_dedup_map()) if s else {}
    warden: dict[str, tuple[int, str, int]] = ({k: (v[0], v[1], v[2]) for k, v in s.warden_best.items()}
                                               if s else {})
    view: dict[int, dict] = ({dataclasses.asdict(r)["seq"]: dataclasses.asdict(r)
                              for r in s.archivist_records_of(None)} if s else {})
    grounded: set[str] = set(s.grounded_keys) if s else set()
    refused: set[str] = set(s.refused_keys) if s else set()

    for r in records:
        p = r.payload
        sig = p.get("signal")
        # W9-1: verify every owner-signed record under the owner key valid AT ITS SEQ when a succession
        # `resolver` is supplied (the rotation-aware prune path); `tp` (the single current/anchor key)
        # otherwise — byte-identical to the pre-W9-1 fold for an un-rotated spine.
        vpk = resolver.at(r.seq) if resolver is not None else tp
        # --- nonce highwater (max; ALL devices) ---
        if sig == RECEIPT_SIGNAL:
            dev = p.get("device")
            if isinstance(dev, str):
                nr = p.get("nonce")
                if nr is not None:
                    try:
                        n = int(nr)
                    except (TypeError, ValueError):        # keep EXACTLY this tuple (see envelope)
                        n = None
                    if n is not None and n > nonce.get(dev, -1):
                        nonce[dev] = n
        # --- killswitch latch (engage=any, release=owner-verified + ANTI-REPLAY FRESH, IN ORDER) ---
        if sig == _KS_SIGNAL:
            state = p.get("state")
            if state == "engaged":
                ks_engaged = True
            elif state == "released" and verify_signed(p, _KS_CORE, vpk):
                issued = as_issued_at(p.get("issued_at"))
                if issued > ks_issued:              # mirror _scan_engaged EXACTLY: stale/replayed ⇒ no effect
                    ks_issued = issued
                    ks_engaged = False
        # --- capability latch (disable=any, enable=owner-verified, IN ORDER, per capability). No isinstance
        #     guard on the key — mirror the scan, which keys on p.get("capability") unconditionally. ---
        if sig == _CAPLATCH_SIGNAL:
            state = p.get("state")
            if state == "disabled":
                cap_latch[p.get("capability")] = False
            elif state == "enabled" and verify_signed(p, _CAPLATCH_CORE, vpk):
                cap_key = p.get("capability")
                issued = as_issued_at(p.get("issued_at"))
                if issued > cap_issued.get(cap_key, NO_HIGHWATER):   # mirror _scan_enabled EXACTLY
                    cap_issued[cap_key] = issued
                    cap_latch[cap_key] = True
        # --- creation cap (PAIR-keyed count; account.create applied). Record shape (actor.py): kind="event",
        #     payload{signal:"web.actor.step", step_kind:"account.create", status:"applied", service, url}. ---
        if p.get("signal") == "web.actor.step" and p.get("step_kind") == "account.create" \
                and p.get("status") == "applied":
            key = (p.get("service"), _origin(p.get("url", "")))
            creation[key] = creation.get(key, 0) + 1
        # --- mesh host capability (LWW verified + ANTI-REPLAY FRESH). NO isinstance guard — mirror the
        #     scan, which keys on p.get("host_id") unconditionally (a non-str key is preserved via the
        #     list-of-rows form). This ledger has NO safe direction, so freshness gates EVERY record. ---
        if sig == CAP_SIGNAL and verify_signed(p, _CAP_CORE, vpk):
            hkey = p.get("host_id")
            at = as_issued_at(p.get("issued_at"))
            if at > cap_map_issued.get(hkey, NO_HIGHWATER):   # mirror capability_map EXACTLY
                cap_map_issued[hkey] = at
                capability[hkey] = cap_descriptor(p)
        # --- mesh device authz (LWW verified + authorize ANTI-REPLAY FRESH; keep revoked) — no
        #     isinstance guard (mirror the scan) ---
        if sig == DEV_SIGNAL and p.get("state") in ("authorized", "revoked") and verify_signed(p, _DEV_CORE, vpk):
            dkey = p.get("device_pubkey")
            fresh = True
            if p["state"] == "authorized":        # mirror authorized_devices EXACTLY
                at = as_issued_at(p.get("issued_at"))
                fresh = at > mesh_dev_issued.get(dkey, NO_HIGHWATER)
                if fresh:
                    mesh_dev_issued[dkey] = at
            if fresh:
                mesh_dev[dkey] = p["state"]
        # --- promotion grants (LWW verified + grant ANTI-REPLAY FRESH; keep revoked) — no isinstance
        #     guard (mirror the scan) ---
        if sig == _PROMO_SIGNAL and p.get("state") in ("granted", "revoked") \
                and verify_signed(p, _PROMO_CORE, vpk):
            akey = (p.get("agent"), p.get("scope"))
            fresh = True
            if p["state"] == "granted":           # mirror PromotionPolicy._fold EXACTLY
                at = as_issued_at(p.get("issued_at"))
                fresh = at > promo_issued.get(akey, NO_HIGHWATER)
                if fresh:
                    promo_issued[akey] = at
            if fresh:
                promo[akey] = p["state"]
        # --- RBAC account grants (revoke=any, active=owner-verified + ANTI-REPLAY FRESH; keep revoked) — no
        #     isinstance guard (mirror AccountsRegistry._fold, which keys on p.get("username") unconditionally).
        #     acct_cred is set alongside the honored high-water and NOT cleared on revoke, exactly as the scan
        #     leaves `accts[u]` in place (it is dropped at read time by the account_state filter). ---
        if sig == _ACCT_SIGNAL:
            ustate = p.get("state")
            if ustate == "revoked":
                acct_state[p.get("username")] = "revoked"
            elif ustate == "active" and verify_signed(p, _acct_core_fields(p), vpk):
                ukey = p.get("username")
                at = as_issued_at(p.get("issued_at"))
                if at > acct_issued.get(ukey, NO_HIGHWATER):   # mirror _fold: stale/replayed active ⇒ no effect
                    acct_issued[ukey] = at
                    acct_state[ukey] = "active"
                    # carry user_pubkey / totp_secret / password_hash / expires_at (None when absent) so a
                    # KEYED / TOTP-enrolled / password / EXPIRING account survives a prune with its full auth —
                    # else a pruned+seeded account would silently lose its PoP key, its SECOND FACTOR, its
                    # password, or its DEADLINE (silently becoming never-expiring).
                    acct_cred[ukey] = [p.get("role"), p.get("cred_hash"), p.get("cred_salt"),
                                       p.get("user_pubkey"), p.get("totp_secret"), p.get("password_hash"),
                                       p.get("expires_at")]
        # --- governor.customer LWW + PER-USERNAME anti-replay high-water (mirrors the ACCT fold above
        #     EXACTLY — a DISJOINT signal/namespace, so a customer survives a prune with its high-water
        #     intact and never collides with an operator account). revoke=any; active=owner-verified+FRESH.
        if sig == _CUST_SIGNAL:
            cstate = p.get("state")
            if cstate == "revoked":
                cust_state[p.get("username")] = "revoked"
            elif cstate == "active" and verify_signed(p, _cust_core_fields(p), vpk):
                ckey = p.get("username")
                at = as_issued_at(p.get("issued_at"))
                if at > cust_issued.get(ckey, NO_HIGHWATER):   # mirror _fold: stale/replayed active ⇒ no effect
                    cust_issued[ckey] = at
                    cust_state[ckey] = "active"
                    cust_cred[ckey] = [p.get("email"), p.get("password_hash")]   # None pw ⇒ OIDC/passkey-only
        # --- governor.org LWW + PER-ORG anti-replay high-water (mirrors the ACCT fold above EXACTLY, so an
        #     active org whose only grant is pruned survives and its high-water is NOT reset — the fix for the
        #     org replay-resurrection HIGH). revoke=any (safe direction); active=owner-verified + FRESH. ---
        if sig == _ORG_SIGNAL:
            oid = p.get("org_id")
            if isinstance(oid, str) and oid:
                ost = p.get("state")
                if ost == "revoked":
                    org_state[oid] = "revoked"
                elif ost == "active" and verify_signed(p, _ORG_CORE, vpk):
                    at = as_issued_at(p.get("issued_at"))
                    if at > org_issued.get(oid, NO_HIGHWATER):   # stale/replayed active ⇒ no effect
                        org_issued[oid] = at
                        org_state[oid] = "active"
                        org_row[oid] = [p.get("name"), p.get("owner")]
        # --- governor.org_membership LWW + PER-(org_id, username) high-water (same carry-across-prune). ---
        if sig == _MEM_SIGNAL:
            oid = p.get("org_id")
            uname = p.get("username")
            if isinstance(oid, str) and oid and isinstance(uname, str) and uname:
                mkey = (oid, uname)
                mst = p.get("state")
                if mst == "revoked":
                    mem_state[mkey] = "revoked"
                elif mst == "active" and verify_signed(p, _MEMBERSHIP_CORE, vpk):
                    at = as_issued_at(p.get("issued_at"))
                    if at > mem_issued.get(mkey, NO_HIGHWATER):
                        mem_issued[mkey] = at
                        mem_state[mkey] = "active"
                        mem_row[mkey] = p.get("role")
        # --- SaaS credit wallet: ADDITIVE grant/debit ledger, idempotent per (org_id, entry_id) — mirrors
        #     WalletRegistry._fold EXACTLY (verify under the key valid at the seq; a record whose key is already
        #     in w_seen is ignored, the replay/double-count guard; credits clamped >= 0). Both signals share the
        #     seen-set (entry_ids are globally unique). Carried across a prune so a pruned grant cannot re-credit. ---
        if sig == _WGRANT_SIGNAL or sig == _WDEBIT_SIGNAL:
            woid = p.get("org_id")
            weid = p.get("entry_id")
            if isinstance(woid, str) and woid and isinstance(weid, str) and weid:
                wcore = _WGRANT_CORE if sig == _WGRANT_SIGNAL else _WDEBIT_CORE
                if verify_signed(p, wcore, vpk):
                    wkey = (sig, woid, weid)              # namespaced by signal — mirror WalletRegistry._fold
                    if wkey not in w_seen:
                        w_seen.add(wkey)
                        wc = _w_as_credits(p.get("credits"))
                        if sig == _WGRANT_SIGNAL:
                            w_granted[woid] = w_granted.get(woid, 0) + wc
                        else:
                            w_debited[woid] = w_debited.get(woid, 0) + wc
        # --- SaaS PLAN credits: ADDITIVE grant/debit ledger keyed per (org_id, period_end) tranche, idempotent
        #     per (signal, org_id, entry_id) — mirrors PlanCreditLedger._fold EXACTLY (verify under the key valid
        #     at the seq; already-seen key ignored; credits clamped >= 0; period_end coerced the same way).
        #     Carried across a prune so a pruned, still-UNEXPIRED tranche is not zeroed and cannot be re-credited. ---
        if sig == _PGRANT_SIGNAL or sig == _PDEBIT_SIGNAL:
            poid = p.get("org_id")
            peid = p.get("entry_id")
            if isinstance(poid, str) and poid and isinstance(peid, str) and peid:
                pcore = _PGRANT_CORE if sig == _PGRANT_SIGNAL else _PDEBIT_CORE
                if verify_signed(p, pcore, vpk):
                    pskey = (sig, poid, peid)                # namespaced by signal — mirror PlanCreditLedger._fold
                    if pskey not in p_seen:
                        p_seen.add(pskey)
                        ptkey = (poid, _p_as_period(p.get("period_end")))
                        pc = _w_as_credits(p.get("credits"))
                        if sig == _PGRANT_SIGNAL:
                            p_granted[ptkey] = p_granted.get(ptkey, 0) + pc
                        else:
                            p_debited[ptkey] = p_debited.get(ptkey, 0) + pc
        # --- governor.subscription LWW (active = owner-verified + FRESH per-org high-water; past_due/canceled
        #     honored on sight) — mirrors SubscriptionRegistry._fold EXACTLY so build() == scan. ---
        if sig == _SUB_SIGNAL:
            soid = p.get("org_id")
            if isinstance(soid, str) and soid:
                sst = p.get("status")
                if sst in _SUB_DOWN:
                    sub_state[soid] = sst
                elif sst == _SUB_ACTIVE and verify_signed(p, _SUBS_CORE, vpk):
                    at = as_issued_at(p.get("issued_at"))
                    if at > sub_issued.get(soid, NO_HIGHWATER):
                        sub_issued[soid] = at
                        sub_state[soid] = _SUB_ACTIVE
                        sub_row[soid] = [str(p.get("plan_id") or ""),
                                         float(as_issued_at(p.get("period_start"))),
                                         float(as_issued_at(p.get("period_end"))),
                                         _sub_as_allotment(p.get("allotment"))]
        # --- gesture device-arm replay ledger (set-union) ---
        if sig == "gesture.session_armed" and p.get("armed_by") == "device":
            arm.add((p.get("device_pubkey"), p.get("nonce")))
        # --- device-approval dedup (min-seq) ---
        if sig == "governor.approval":
            k = (p.get("pubkey"), p.get("sig"))
            cur = dedup.get(k)
            if cur is None or r.seq < cur:
                dedup[k] = r.seq
        # --- warden anchor best-count (max count, LWW head_hash on tie) ---
        if r.kind == "warden_checkpoint":
            wk = p.get("pubkey")
            if isinstance(wk, str):
                c = int(p.get("count", 0))
                bc, _, _ = warden.get(wk, (0, "", -1))
                if c >= bc:
                    warden[wk] = (c, p.get("head_hash", ""), r.seq)
        # --- archivist current-view + ledgers. Retain EVERY source==archivist record (not just fact-kinds):
        #     consolidation_records(kinds=None) serves refusals/briefs too — dropping them would under-return.
        #     The query-time kind filter lives in archivist_records_of(). ---
        if r.source == CONSOLIDATE_SOURCE:
            view[r.seq] = dataclasses.asdict(r)
            pkey = p.get("promotion_key")
            if pkey is not None:
                (refused if r.kind == "refusal" else grounded).add(pkey)

    return SnapshotState(
        base_seq=base_seq, snapshot_seq=snapshot_seq, trusted_pubkey=tp,
        nonce_highwater=nonce,
        killswitch_engaged=ks_engaged,
        killswitch_issued_hw=(None if ks_issued == NO_HIGHWATER else ks_issued),   # -inf ⇒ the None sentinel
        capability_latch=[[c, e] for c, e in cap_latch.items()],
        capability_issued=[[c, i] for c, i in cap_issued.items()],
        creation_created=[[s, o, c] for (s, o), c in creation.items()],
        capability_map=[[h, c] for h, c in capability.items()],
        capability_map_issued=[[h, i] for h, i in cap_map_issued.items()],
        mesh_dev_state=[[d, s] for d, s in mesh_dev.items()],
        mesh_dev_issued=[[d, i] for d, i in mesh_dev_issued.items()],
        promotion=[[a, s, v] for (a, s), v in promo.items()],
        promotion_issued=[[a, s, i] for (a, s), i in promo_issued.items()],
        account_state=[[u, v] for u, v in acct_state.items()],
        account_issued=[[u, i] for u, i in acct_issued.items()],
        account_cred=[[u, c[0], c[1], c[2], (c[3] if len(c) > 3 else None), (c[4] if len(c) > 4 else None),
                       (c[5] if len(c) > 5 else None), (c[6] if len(c) > 6 else None)]
                      for u, c in acct_cred.items()],
        customer_state=[[u, v] for u, v in cust_state.items()],
        customer_issued=[[u, i] for u, i in cust_issued.items()],
        customer_cred=[[u, c[0], (c[1] if len(c) > 1 else None)] for u, c in cust_cred.items()],
        org_state=[[o, v] for o, v in org_state.items()],
        org_issued=[[o, i] for o, i in org_issued.items()],
        org_row=[[o, r[0], r[1]] for o, r in org_row.items()],
        membership_state=[[k[0], k[1], v] for k, v in mem_state.items()],
        membership_issued=[[k[0], k[1], i] for k, i in mem_issued.items()],
        membership_row=[[k[0], k[1], r] for k, r in mem_row.items()],
        wallet_granted=[[o, c] for o, c in w_granted.items()],
        wallet_debited=[[o, c] for o, c in w_debited.items()],
        wallet_seen=[[sg, o, e] for (sg, o, e) in w_seen],
        plan_granted=[[o, pe, c] for (o, pe), c in p_granted.items()],
        plan_debited=[[o, pe, c] for (o, pe), c in p_debited.items()],
        plan_seen=[[sg, o, e] for (sg, o, e) in p_seen],
        subscription_state=[[o, v] for o, v in sub_state.items()],
        subscription_issued=[[o, i] for o, i in sub_issued.items()],
        subscription_row=[[o, r[0], r[1], r[2], r[3]] for o, r in sub_row.items()],
        consumed_arm_nonces=[[d, n] for (d, n) in arm],
        device_approval_dedup=[[pk, sg, seq] for (pk, sg), seq in dedup.items()],
        warden_best={k: [c, h, s] for k, (c, h, s) in warden.items()},
        archivist_view=[view[s] for s in sorted(view)],
        grounded_keys=sorted(grounded),
        refused_keys=sorted(refused),
        open_queued_below_base=[],  # computed by the prune's referential-floor guard (Slice D/E), not here
    )
