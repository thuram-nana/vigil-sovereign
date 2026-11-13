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
import os
from typing import Any, Iterable, Optional

from pydantic import BaseModel, ConfigDict

from ..config import HEAD_PATH
from ..reuse import SignedChainHead
from .models import SpineRecord
from .schema_guard import refuse_newer

_MAX_SNAPSHOT_SCHEMA = 10  # refuse-newer gate (W5-3): a snapshot schema above this is "upgrade sigil".
#                            v2 (Slice E1) ADDED governor.customer (customer_state/issued/cred); v3 (Slice G0)
#                            ADDED asset_ownership_proof (ownership_proof_state/issued/row); v4 (Slice H) ADDED
#                            the governor.invoice billing-history sub-state (invoice_row); v5 (Slice E2a) ADDED
#                            governor.customer_credential (customer_credential_state/issued/row); v6 (AEGIS-SaaS AE-0) ADDED
#                            governor.monitoring_authority (monitoring_authority_state/issued/row); v7 (AEGIS fold)
#                            ADDED governor.monitoring_subscription (monitoring_subscription_state/issued/row); v8 (PP-1)
#                            ADDED governor.postpaid (postpaid_state/issued/row) + the postpaid arrears ledger
#                            (postpaid_arrears_debited/credited/seen); v9 (EC-4) ADDED the per-tenant cost
#                            envelope ledger (cost_reserved/cost_settled/cost_seen); v10 (pricing S2) ADDED the
#                            governor.trial_claim claims (trial_claim_row) and the governor.report_unlock ledger
#                            (report_unlock_billing/report_unlock_owner). Every bump is
#                            ADDITIVE-WITH-DEFAULTS: a pre-bump build refuses a newer snapshot cleanly via the
#                            refuse-newer gate, and this build still reads any older snapshot (the newer fields
#                            default to empty — e.g. a v1 snapshot loads with customer_*/ownership_*/invoice_*
#                            all empty).


class SnapshotState(BaseModel):
    """The persisted folded state. Fields are JSON-native (tuple-keyed / set sub-states use list forms that
    round-trip verbatim); runtime accessors reconstruct the sets / tuple-keyed dicts. Non-secret."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 10  # W5-3: 1->2 Slice E1 (governor.customer); 2->3 Slice G0 (asset_ownership_proof);
    #                           3->4 Slice H (governor.invoice billing history); 4->5 Slice E2a (customer_credential);
    #                           5->6 AEGIS-SaaS AE-0 (governor.monitoring_authority); 6->7 AEGIS fold
    #                           (governor.monitoring_subscription); 7->8 PP-1 (governor.postpaid account mode +
    #                           the postpaid arrears ledger); 8->9 EC-4 (the per-tenant cost envelope ledger);
    #                           9->10 pricing S2 (trial claims + report unlocks).
    #                           Every snapshot this build emits carries the v10 keys; a pre-bump build refuses it
    #                           cleanly via the refuse-newer gate.
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
    ownership_proof_state: list = []  # [[org_id, host, "active"|"revoked"], ...] — governor.asset_ownership_proof
    #                                   LWW, keyed PER-(org_id, host). Keep revoked (Slice G0 schema v3).
    ownership_proof_issued: list = [] # [[org_id, host, issued_at], ...] — PER-(org_id, host) active high-water.
    #                                   Same cross-a-prune invariant as account_issued: MUST cross a prune or a
    #                                   captured owner-signed `active` proof becomes replay-resurrectable, which
    #                                   would resurrect a REVOKED/expired engagement authorization basis.
    ownership_proof_row: list = []    # [[org_id, host, method, token_sha256, verified_at, expires_at], ...] — the
    #                                   fields to REBUILD an active `OwnershipProof` (issued_at joins from
    #                                   ownership_proof_issued; state="active"). expires_at is owner-signed.
    monitoring_authority_state: list = []  # [[org_id, host, "active"|"revoked"], ...] — AE-0
    #                                   governor.monitoring_authority LWW per (org_id, host). Keep revoked (v6).
    monitoring_authority_issued: list = []  # [[org_id, host, issued_at], ...] — per-(org,host) active high-water;
    #                                   MUST cross a prune or a captured owner-signed grant becomes replay-resurrectable.
    monitoring_authority_row: list = []  # [[org_id, host, mode, not_before, not_after, proof_sha256], ...] — rebuild a grant.
    customer_credential_state: list = []  # [[username, cred_key, "active"|"revoked"], ...] —
    #                                   governor.customer_credential LWW, keyed PER-(username, cred_key). Keep
    #                                   revoked (Slice E2a schema v5; mirrors ownership_proof).
    customer_credential_issued: list = []  # [[username, cred_key, issued_at], ...] — PER-(username, cred_key)
    #                                   active high-water. MUST cross a prune, or a captured owner-signed active
    #                                   credential becomes replay-resurrectable (a revoked passkey/TOTP/OIDC link
    #                                   could be resurrected) — the same invariant as ownership_proof_issued.
    customer_credential_row: list = []  # [[username, cred_key, kind, cose_alg, public_key_spki_b64, uv,
    #                                   sealed_secret, federated_iss, federated_sub, issued_at], ...] — the fields
    #                                   to REBUILD an active CustomerCredential from the seed (state="active").
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
    monitoring_subscription_state: list = []   # [[org_id, status], ...] — governor.monitoring_subscription: the
    #                                   AEGIS monitoring plan line, SEPARATE from governor.subscription (schema v7);
    #                                   same LWW / high-water / row shape as subscription_* below.
    monitoring_subscription_issued: list = []  # [[org_id, issued_at], ...]
    monitoring_subscription_row: list = []     # [[org_id, plan_id, period_start, period_end, allotment], ...]
    postpaid_state: list = []         # [[org_id, enabled_bool], ...] — governor.postpaid (PP-1): the account-mode
    #                                   LWW line (enabled = drawing against a credit line). SEPARATE sub-state from
    #                                   subscription; same high-water / row shape idiom.
    postpaid_issued: list = []        # [[org_id, issued_at], ...] — per-org enabled anti-replay high-water
    postpaid_row: list = []           # [[org_id, credit_limit, net_terms_days], ...] — the last-enabled line
    postpaid_arrears_debited: list = []   # [[org_id, Σ credits], ...] — governor.postpaid_debit (ADDITIVE accrual)
    postpaid_arrears_credited: list = []  # [[org_id, Σ credits], ...] — governor.postpaid_credit (reversals/payments)
    postpaid_arrears_seen: list = []      # [[signal, org_id, entry_id], ...] — consumed arrears idempotency keys
    # EC-4: the per-tenant token-cost envelope ledger (governor.cost_reserve/cost_settle), ADDITIVE per-org,
    # idempotent per (signal, org_id, entry_id) — mirrors the postpaid arrears sub-state above exactly.
    cost_reserved: list = []              # [[org_id, Σ tokens], ...] — governor.cost_reserve (reserved envelopes)
    cost_settled: list = []               # [[org_id, Σ tokens], ...] — governor.cost_settle (actual settled cost)
    cost_seen: list = []                  # [[signal, org_id, entry_id], ...] — consumed cost idempotency keys
    # pricing S2 (schema v10): first-wins trial claims and the report-unlock ledger. Lifetime state, so both MUST
    # cross a prune (a dropped claim would re-open a second trial; a dropped unlock would re-lock a paying org).
    trial_claim_row: list = []        # [[key_kind, key_digest, org_id, issued_at], ...] — first verified claim wins
    report_unlock_billing: list = []  # [[org_id, entry_id, source_kind, source_ref, issued_at], ...] — first wins
    report_unlock_owner: list = []    # [[org_id, entry_id, action, source_ref, issued_at], ...] — latest wins
    invoice_row: list = []            # [[org_id, invoice_id, kind, price_id, amount_minor, currency, credits,
    #                                   period_start, period_end, issued_at], ...] — governor.invoice billing
    #                                   HISTORY (Slice H schema v4). ADDITIVE append-only (NOT LWW), idempotent
    #                                   per (org_id, invoice_id). MUST cross a prune or the first hard prune would
    #                                   LOSE historical invoices AND drop the consumed invoice_id set (re-opening
    #                                   invoice replay); `InvoiceRegistry._fold` rebuilds the Invoice from it.
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

    def monitoring_authority_state_map(self) -> dict[tuple, str]:
        return {(row[0], row[1]): row[2] for row in self.monitoring_authority_state}

    def monitoring_authority_issued_map(self) -> dict[tuple, float]:
        return {(row[0], row[1]): row[2] for row in self.monitoring_authority_issued}

    def ownership_proof_state_map(self) -> dict[tuple, str]:
        return {(row[0], row[1]): row[2] for row in self.ownership_proof_state}

    def ownership_proof_issued_map(self) -> dict[tuple, float]:
        return {(row[0], row[1]): row[2] for row in self.ownership_proof_issued}
    #   ownership_proof_row is a raw list-of-rows: `AssetOwnershipRegistry._fold_proofs` rebuilds the
    #   OwnershipProof objects from it (joining issued_at from ownership_proof_issued_map), keyed
    #   PER-(org_id, host), so a pruned proof survives and its anti-replay high-water is not reset.

    def customer_credential_state_map(self) -> dict[tuple, str]:
        return {(row[0], row[1]): row[2] for row in self.customer_credential_state}

    def customer_credential_issued_map(self) -> dict[tuple, float]:
        return {(row[0], row[1]): row[2] for row in self.customer_credential_issued}
    #   customer_credential_row is a raw list-of-rows: `CustomerCredentialRegistry._fold` rebuilds the
    #   CustomerCredential objects from it, keyed PER-(username, cred_key), so a pruned passkey/TOTP/OIDC link
    #   survives and its anti-replay high-water is not reset.

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

    #   postpaid_state/issued stay raw ([[org_id, enabled_bool]] / [[org_id, issued_at]]): `PostpaidRegistry._fold`
    #   reads them via getattr (like subscription), rebuilding the PostpaidAccount with postpaid_row.
    def postpaid_arrears_debited_map(self) -> dict[Any, int]:
        return {row[0]: row[1] for row in self.postpaid_arrears_debited}   # org_id -> Σ accrued credits

    def postpaid_arrears_credited_map(self) -> dict[Any, int]:
        return {row[0]: row[1] for row in self.postpaid_arrears_credited}  # org_id -> Σ reversed credits

    def postpaid_arrears_seen_set(self) -> set:
        return {(row[0], row[1], row[2]) for row in self.postpaid_arrears_seen}   # (signal, org_id, entry_id)
    #   `PostpaidArrearsLedger._fold` seeds (debited, credited, seen) from these, keyed per org_id; accrued =
    #   debited - credited (clamped >= 0). The seen-set is the idempotency/anti-replay guard that MUST survive a
    #   prune (a pruned debit stays counted, so a tenant can never draw past their line by waiting out a prune).

    #   EC-4: `CostEnvelopeLedger._fold` seeds (reserved, settled, seen) from these, keyed per org_id; committed =
    #   Σ settled, in-flight = Σ reserved-but-unsettled. Same prune-durability contract as the arrears seen-set.
    def cost_reserved_map(self) -> dict[Any, int]:
        return {row[0]: row[1] for row in self.cost_reserved}      # org_id -> Σ reserved envelope tokens

    def cost_settled_map(self) -> dict[Any, int]:
        return {row[0]: row[1] for row in self.cost_settled}       # org_id -> Σ settled actual tokens

    def cost_seen_set(self) -> set:
        return {(row[0], row[1], row[2]) for row in self.cost_seen}   # (signal, org_id, entry_id)

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
        # The folded state cannot name its OWN record's seq: `prune.snapshot_payload` builds it before the
        # snapshot record is appended (and the append is idempotent across a crash re-run), so it is persisted
        # with the placeholder -1 and the seq travels beside it — in the owner-signed head (verified above) and
        # as the record's own position. Demanding equality here refused EVERY real prune (each seeded fold and
        # `KillSwitch.is_engaged` then raised, with the pruned prefix already deleted). So: the boundary must
        # agree with the signed head; the state's seq must be the placeholder (or, were a writer ever to stamp
        # it, the head's — any OTHER value is a state minted for a different snapshot record: refuse); and the
        # state handed to the folds carries the head-verified seq.
        if st.base_seq != base_seq or st.snapshot_seq not in (-1, snapshot_seq):
            raise SnapshotError(f"snapshot record {snapshot_seq} base/seq disagree with the signed head")
        return st.model_copy(update={"snapshot_seq": snapshot_seq})


def seed_applies(snap: "SnapshotState", reader_pubkey: "Optional[str]", store) -> bool:
    """Whether a registry whose trust anchor is `reader_pubkey` may start its fold from `snap` — THE one rule every
    seeded fold uses (each registry's `_seed`). True: seed from the folded prefix. False: start from the spine's
    first record with an empty seed — returned ONLY when nothing is pruned, where that IS the whole fold (the
    historic "different trust anchor" bypass, byte-identical for every un-pruned spine).

    A seed is folded under the owner key of its time (`snap.trusted_pubkey`). It applies when that is the reader's
    own key, or when the reader's owner-key succession (`key_history.key_resolver`, the same resolver the fold
    verifies records with: walked from the pinned genesis, DENY-all when forked or when it does not end at the
    reader's key) says that key was the owner's AT the snapshot's seq — a routine rotation after a prune.

    On a PRUNED spine anything else RAISES `SnapshotError`: the folded prefix is gone, so an empty start would read a
    short history — the kill switch released, wallets zero — for a reader holding a different key (a swapped
    `owner.pub`, a forked succession, a re-genesis). Fail closed; never re-bind the seed to another key."""
    if reader_pubkey == snap.trusted_pubkey:
        return True
    if snap.base_seq <= 0 and snap.snapshot_seq < 0:
        return False                                      # nothing pruned: the genesis scan is the whole fold
    if reader_pubkey:
        from ..governor import key_history as _kh
        if _kh.key_resolver(store, current=reader_pubkey).at(snap.snapshot_seq) == snap.trusted_pubkey:
            return True
    raise SnapshotError(
        f"the spine is hard-pruned (live window from seq {snap.base_seq}) and its snapshot was folded under an owner "
        f"key ({(snap.trusted_pubkey or '-')[:12]}…) that this reader's trust anchor "
        f"({(reader_pubkey or '-')[:12]}…) does not succeed — a different or swapped owner key, a forked key "
        f"succession, or a re-genesis. Refusing to fold the live window from an empty seed (the pruned prefix's "
        f"state would be lost). Run `sigil verify` and `sigil key status`")


_LIVE_START: "dict[str, tuple[tuple, int]]" = {}


def live_window_start(store) -> int:
    """The seq the spine's live window starts at: 0 un-pruned, K after a committed hard prune (the manifest's
    first segment). O(1): memoized on the manifest file's (inode, mtime, size) — every manifest write is an
    atomic replace — so the hot read path pays one `stat`, not a manifest parse (O(segments)). 0 for a legacy
    single-file spine (never prunable) or a store without a segment layout."""
    layout = getattr(store, "_layout", None)
    path = getattr(layout, "manifest_path", None)
    if layout is None or path is None:
        return 0
    try:
        st = os.stat(path)
    except OSError:
        return 0
    sig = (st.st_ino, st.st_mtime_ns, st.st_size)
    hit = _LIVE_START.get(str(path))
    if hit is not None and hit[0] == sig:
        return hit[1]
    from .manifest import read_manifest
    m = read_manifest(layout)
    segs = m.ordered() if m is not None else []
    first = segs[0].first_seq if segs else 0
    _LIVE_START[str(path)] = (sig, first)
    return first


class SnapshotError(Exception):
    """A committed snapshot is missing or inconsistent — fail closed, never scan a truncated window."""


def _refuse_unanchored_prune(store, why: str) -> None:
    """A spine whose live window starts above seq 0 HAS been hard-pruned: reading it as un-pruned would start every
    seeded fold from an EMPTY seed over a truncated window (the kill switch released, wallets zero) — silently.
    A head deleted by accident, a restore that brought back the spine without its head, or a re-sign by a build
    that did not carry the boundary forward all land here: fail CLOSED."""
    k = live_window_start(store)
    if k > 0:
        raise SnapshotError(
            f"the live window starts at seq {k} (a hard-pruned spine) but {why} — refusing to read it as "
            f"un-pruned (every seeded fold would start from an empty seed). Do not re-sign: put back the "
            f"`spine/head.json` this spine was pruned under (from a file-level copy of SIGIL_HOME), then `sigil "
            f"verify`; `sigil restore` does not yet restore a hard-pruned spine")


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
        _refuse_unanchored_prune(store, "no signed head stands")
        return 0, -1                                        # genuinely no head -> genesis, nothing pruned
    try:
        head = SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — present but corrupt/unparseable/future-schema: fail CLOSED
        raise SnapshotError(f"head present but unparseable — refusing to treat as no-prune (would scan a "
                            f"truncated window with empty seeds): {e}") from e
    if head.snapshot_seq < 0:
        _refuse_unanchored_prune(store, "the signed head declares no prune")
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
    # governor.customer_credential — the per-customer passkey/TOTP/OIDC-link substrate (Slice E2a). Its signed
    # core is CONDITIONAL on the credential material; mirror the SAME helper the live fold uses (drift guard).
    from ..governor.monitoring_authority import SIGNAL as _MA_SIGNAL
    from ..governor.monitoring_authority import _CORE as _MA_CORE
    from ..governor.monitoring_authority import _MODES as _MA_MODES
    from ..governor.customer_credentials import SIGNAL as _CRED_SIGNAL
    from ..governor.customer_credentials import _cred_core as _cred_core_fields
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
    # asset-ownership proof signed-core imported from the live module (never restated — same drift guard as the
    # org cores); the fold carries the per-(org_id, host) proof state + high-water across a prune like memberships
    # so a captured owner-signed active proof cannot resurrect a revoked one after the first hard prune (Slice G0).
    from ..governor.asset_ownership import PROOF_SIGNAL as _PROOF_SIGNAL, _PROOF_CORE
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
    from ..governor.monitoring_subscription import MONITORING_SUBSCRIPTION_SIGNAL as _MSUB_SIGNAL
    # postpaid (PP-1): the account-mode LWW signal/core + the ADDITIVE arrears ledger signals/cores, imported
    # from the live module (never restated — the same drift guard the other folds use).
    from ..governor.postpaid import (POSTPAID_SIGNAL as _PP_SIGNAL, POSTPAID_DEBIT_SIGNAL as _PPDEBIT_SIGNAL,
                                     POSTPAID_CREDIT_SIGNAL as _PPCREDIT_SIGNAL, _PP_CORE as _PPACCT_CORE,
                                     _PP_DEBIT_CORE as _PPDEBIT_CORE, _PP_CREDIT_CORE as _PPCREDIT_CORE,
                                     _as_nonneg_int as _pp_as_nonneg)
    # cost ledger (EC-4): the ADDITIVE per-tenant token-cost reserve/settle signals/cores + the tokens clamp,
    # imported from the live module (never restated — same drift guard). Carried across a prune so a pruned
    # reserve/settle stays counted and its entry_id stays consumed, exactly like the postpaid arrears fold.
    from ..governor.cost_ledger import (COST_RESERVE_SIGNAL as _CRES_SIGNAL, COST_SETTLE_SIGNAL as _CSET_SIGNAL,
                                        _RESERVE_CORE as _CRES_CORE, _SETTLE_CORE as _CSET_CORE,
                                        _as_tokens as _c_as_tokens)
    from ..governor.subscription import (SUBSCRIPTION_SIGNAL as _SUB_SIGNAL, _SUB_CORE as _SUBS_CORE,
                                         STATUS_ACTIVE as _SUB_ACTIVE, _DOWN_STATES as _SUB_DOWN,
                                         _as_allotment as _sub_as_allotment)
    # invoice billing-history signed-core imported from the live module (never restated — same drift guard); the
    # fold below carries the ADDITIVE per-(org, invoice_id) history rows across a prune like the wallet seen-set.
    from ..governor.invoices import (INVOICE_SIGNAL as _INV_SIGNAL, _INVOICE_CORE as _INV_CORE,
                                     _as_nonneg_int as _inv_as_nonneg)
    # pricing S2: the ONE fold step of each ledger, imported from the live module (never restated).
    from ..governor.trial_claim import (TRIAL_CLAIM_SIGNAL as _TC_SIGNAL, apply_trial_claim as _tc_apply,
                                        seed_rows as _tc_seed)
    from ..governor.report_unlock import (REPORT_UNLOCK_SIGNAL as _RU_SIGNAL, apply_report_unlock as _ru_apply,
                                          seed_state as _ru_seed)

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
    op_state: dict[tuple, str] = dict(s.ownership_proof_state_map()) if s else {}   # (org,host) -> state (LWW)
    op_issued: dict[tuple, float] = dict(s.ownership_proof_issued_map()) if s else {}   # (org,host) -> high-water
    op_row: dict[tuple, list] = {(r[0], r[1]): [r[2], r[3], r[4], r[5]]
                                 for r in s.ownership_proof_row} if s else {}   # ->[method,sha,verified,expires]
    ma_state: dict[tuple, str] = dict(s.monitoring_authority_state_map()) if s else {}   # (org,host) -> state
    ma_issued: dict[tuple, float] = dict(s.monitoring_authority_issued_map()) if s else {}   # (org,host) -> hw
    ma_row: dict[tuple, list] = {(r[0], r[1]): [r[2], r[3], r[4], (r[5] if len(r) > 5 else "")]
                                 for r in s.monitoring_authority_row} if s else {}   # ->[mode,nb,na,proof_sha]
    cc_state: dict[tuple, str] = dict(s.customer_credential_state_map()) if s else {}   # (user,cred_key) -> state
    cc_issued: dict[tuple, float] = dict(s.customer_credential_issued_map()) if s else {}   # (user,cred_key) -> hw
    cc_row: dict[tuple, list] = {(r[0], r[1]): [r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]]
                                 for r in s.customer_credential_row} if s else {}   # ->[kind,alg,pk,uv,seal,iss,sub,at]
    w_granted: dict[Any, int] = dict(s.wallet_granted_map()) if s else {}   # org_id -> Σ grant credits
    w_debited: dict[Any, int] = dict(s.wallet_debited_map()) if s else {}   # org_id -> Σ debit credits
    w_seen: set = set(s.wallet_seen_set()) if s else set()                  # consumed (org_id, entry_id) keys
    p_granted: dict[Any, int] = dict(s.plan_granted_map()) if s else {}     # (org_id, period_end) -> Σ grants
    p_debited: dict[Any, int] = dict(s.plan_debited_map()) if s else {}     # (org_id, period_end) -> Σ debits
    p_seen: set = set(s.plan_seen_set()) if s else set()                    # consumed plan (sig, org, entry) keys
    sub_state: dict[Any, str] = dict(s.subscription_state_map()) if s else {}   # org_id -> status (LWW)
    sub_issued: dict[Any, float] = dict(s.subscription_issued_map()) if s else {}   # org_id -> active high-water
    sub_row: dict[Any, list] = {r[0]: [r[1], r[2], r[3], r[4]] for r in s.subscription_row} if s else {}
    msub_state: dict[Any, str] = {r[0]: r[1] for r in s.monitoring_subscription_state} if s else {}
    msub_issued: dict[Any, float] = {r[0]: r[1] for r in s.monitoring_subscription_issued} if s else {}
    msub_row: dict[Any, list] = ({r[0]: [r[1], r[2], r[3], r[4]] for r in s.monitoring_subscription_row}
                                 if s else {})
    sub_lines = {_SUB_SIGNAL: (sub_state, sub_issued, sub_row), _MSUB_SIGNAL: (msub_state, msub_issued, msub_row)}
    pp_state: dict[Any, bool] = {r[0]: r[1] for r in s.postpaid_state} if s else {}      # org_id -> enabled (LWW)
    pp_issued: dict[Any, float] = {r[0]: r[1] for r in s.postpaid_issued} if s else {}   # org_id -> enabled hw
    pp_row: dict[Any, list] = {r[0]: [r[1], r[2]] for r in s.postpaid_row} if s else {}  # org_id -> [limit, net]
    pp_debited: dict[Any, int] = dict(s.postpaid_arrears_debited_map()) if s else {}     # org_id -> Σ draws
    pp_credited: dict[Any, int] = dict(s.postpaid_arrears_credited_map()) if s else {}   # org_id -> Σ reversals
    pp_seen: set = set(s.postpaid_arrears_seen_set()) if s else set()                    # consumed arrears keys
    cl_reserved: dict[Any, int] = dict(s.cost_reserved_map()) if s else {}               # org_id -> Σ reserved tok
    cl_settled: dict[Any, int] = dict(s.cost_settled_map()) if s else {}                 # org_id -> Σ settled tok
    cl_seen: set = set(s.cost_seen_set()) if s else set()                                # consumed cost keys
    # invoice history: (org_id, invoice_id) -> [kind, price_id, amount_minor, currency, credits, p_start, p_end,
    # issued_at]. ADDITIVE append-only (NOT LWW); the key presence IS the idempotency seen-set (mirror wallet).
    inv_rows: dict[tuple, list] = ({(r[0], r[1]): list(r[2:10]) for r in s.invoice_row
                                    if isinstance(r, (list, tuple)) and len(r) >= 10} if s else {})
    tc_rows: dict = _tc_seed(s) if s else {}
    ru_billing, ru_owner = _ru_seed(s) if s else ({}, {})
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
        # --- governor.asset_ownership_proof LWW + PER-(org_id, host) high-water (mirrors the MEM fold EXACTLY,
        #     so an active ownership proof whose only grant is pruned survives and its high-water is NOT reset —
        #     the fix for the proof replay-resurrection flagged by the G0 red-pen). Keep revoked (safe dir). ---
        if sig == _PROOF_SIGNAL:
            oid = p.get("org_id")
            host = p.get("host")
            if isinstance(oid, str) and oid and isinstance(host, str) and host:
                opkey = (oid, host)
                pst = p.get("state")
                if pst == "revoked":
                    op_state[opkey] = "revoked"
                elif pst == "active" and verify_signed(p, _PROOF_CORE, vpk):
                    at = as_issued_at(p.get("issued_at"))
                    if at > op_issued.get(opkey, NO_HIGHWATER):
                        op_issued[opkey] = at
                        op_state[opkey] = "active"
                        op_row[opkey] = [p.get("method"), p.get("token_sha256"),
                                         p.get("verified_at"), p.get("expires_at")]
        # --- governor.monitoring_authority LWW + PER-(org_id, host) high-water (AE-0; mirrors the proof fold so
        #     an active grant whose only record is pruned survives with its high-water intact). ---
        if sig == _MA_SIGNAL:
            oid = p.get("org_id")
            host = p.get("host")
            if isinstance(oid, str) and oid and isinstance(host, str) and host:
                makey = (oid, host)
                mst = p.get("state")
                if mst == "revoked":
                    ma_state[makey] = "revoked"
                elif (mst == "active" and p.get("mode") in _MA_MODES
                      and verify_signed(p, _MA_CORE, vpk)):
                    at = as_issued_at(p.get("issued_at"))
                    if at > ma_issued.get(makey, NO_HIGHWATER):
                        ma_issued[makey] = at
                        ma_state[makey] = "active"
                        ma_row[makey] = [p.get("mode"), p.get("not_before"), p.get("not_after"),
                                         p.get("proof_sha256")]
        # --- governor.customer_credential LWW + PER-(username, cred_key) high-water (mirrors the ownership_proof
        #     fold EXACTLY, so an active passkey/TOTP/OIDC-link whose only grant is pruned survives and its
        #     high-water is NOT reset — else a captured owner-signed active credential becomes replay-
        #     resurrectable). verify under the CONDITIONAL core (same drift guard as acct/customer). ---
        if sig == _CRED_SIGNAL:
            ccu = p.get("username")
            cck = p.get("cred_key")
            if isinstance(ccu, str) and ccu and isinstance(cck, str) and cck:
                cckey = (ccu, cck)
                ccst = p.get("state")
                if ccst == "revoked":
                    cc_state[cckey] = "revoked"
                elif ccst == "active" and verify_signed(p, _cred_core_fields(p), vpk):
                    at = as_issued_at(p.get("issued_at"))
                    if at > cc_issued.get(cckey, NO_HIGHWATER):
                        cc_issued[cckey] = at
                        cc_state[cckey] = "active"
                        cc_row[cckey] = [p.get("kind"), p.get("cose_alg"), p.get("public_key_spki_b64"),
                                         p.get("uv"), p.get("sealed_secret"), p.get("federated_iss"),
                                         p.get("federated_sub"), at]
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
        # --- governor.subscription LWW (active = owner-verified + FRESH per-org high-water; down-states:
        #     owner-manual 0.0 honored on sight, webhook-driven freshness-gated vs the active high-water)
        #     — mirrors SubscriptionRegistry._fold EXACTLY so build() == scan. ---
        if sig in sub_lines:       # the credit-plan line AND the separate AEGIS monitoring line (same shape)
            l_state, l_issued, l_row = sub_lines[sig]
            soid = p.get("org_id")
            if isinstance(soid, str) and soid:
                sst = p.get("status")
                if sst in _SUB_DOWN:
                    sdat = as_issued_at(p.get("issued_at"))     # mirror _fold: 0.0 on sight; else fresher-only
                    if sdat <= 0.0 or sdat > l_issued.get(soid, NO_HIGHWATER):
                        l_state[soid] = sst
                elif sst == _SUB_ACTIVE and verify_signed(p, _SUBS_CORE, vpk):
                    at = as_issued_at(p.get("issued_at"))
                    if at > l_issued.get(soid, NO_HIGHWATER):
                        l_issued[soid] = at
                        l_state[soid] = _SUB_ACTIVE
                        l_row[soid] = [str(p.get("plan_id") or ""),
                                       float(as_issued_at(p.get("period_start"))),
                                       float(as_issued_at(p.get("period_end"))),
                                       _sub_as_allotment(p.get("allotment"))]
        # --- governor.postpaid LWW account mode (PP-1): enabled = owner-verified + FRESH per-org high-water;
        #     disabled = safe direction (owner-manual 0.0 on sight, webhook-driven freshness-gated). Mirrors
        #     PostpaidRegistry._fold EXACTLY so build() == scan. Distinct enabled-bool shape (not a status str). ---
        if sig == _PP_SIGNAL:
            ppoid = p.get("org_id")
            if isinstance(ppoid, str) and ppoid:
                if p.get("enabled") is True:
                    if verify_signed(p, _PPACCT_CORE, vpk):
                        at = as_issued_at(p.get("issued_at"))
                        if at > pp_issued.get(ppoid, NO_HIGHWATER):   # stale/replayed open ⇒ no effect
                            pp_issued[ppoid] = at
                            pp_state[ppoid] = True
                            pp_row[ppoid] = [_pp_as_nonneg(p.get("credit_limit")),
                                             _pp_as_nonneg(p.get("net_terms_days"))]
                else:
                    dat = as_issued_at(p.get("issued_at"))   # 0.0 on sight; else fresher-than-open only
                    if dat <= 0.0 or dat > pp_issued.get(ppoid, NO_HIGHWATER):
                        pp_state[ppoid] = False
        # --- governor.postpaid_debit/credit: ADDITIVE per-org arrears ledger, idempotent per (signal, org, entry)
        #     — mirrors PostpaidArrearsLedger._fold / WalletRegistry._fold EXACTLY (verify under the key valid at
        #     the seq; already-seen key ignored; credits clamped >= 0). Carried across a prune so a pruned draw
        #     stays counted (a tenant cannot draw past the line by waiting out a prune). ---
        if sig == _PPDEBIT_SIGNAL or sig == _PPCREDIT_SIGNAL:
            paoid = p.get("org_id")
            paeid = p.get("entry_id")
            if isinstance(paoid, str) and paoid and isinstance(paeid, str) and paeid:
                pacore = _PPDEBIT_CORE if sig == _PPDEBIT_SIGNAL else _PPCREDIT_CORE
                if verify_signed(p, pacore, vpk):
                    pakey = (sig, paoid, paeid)              # namespaced by signal — mirror the ledger fold
                    if pakey not in pp_seen:
                        pp_seen.add(pakey)
                        pac = _w_as_credits(p.get("credits"))
                        if sig == _PPDEBIT_SIGNAL:
                            pp_debited[paoid] = pp_debited.get(paoid, 0) + pac
                        else:
                            pp_credited[paoid] = pp_credited.get(paoid, 0) + pac
        # --- governor.cost_reserve/cost_settle: ADDITIVE per-tenant token-cost envelope ledger, idempotent per
        #     (signal, org, entry) — mirrors CostEnvelopeLedger._fold EXACTLY (verify under the key valid at the
        #     seq; already-seen key ignored; tokens clamped >= 0). Carried across a prune so a pruned reserve/
        #     settle stays counted + its entry_id stays consumed (reserve/settle replay is closed across a prune). ---
        if sig == _CRES_SIGNAL or sig == _CSET_SIGNAL:
            cloid = p.get("org_id")
            cleid = p.get("entry_id")
            if isinstance(cloid, str) and cloid and isinstance(cleid, str) and cleid:
                clcore = _CRES_CORE if sig == _CRES_SIGNAL else _CSET_CORE
                if verify_signed(p, clcore, vpk):
                    clkey = (sig, cloid, cleid)              # namespaced by signal — mirror the ledger fold
                    if clkey not in cl_seen:
                        cl_seen.add(clkey)
                        clt = _c_as_tokens(p.get("tokens"))
                        if sig == _CRES_SIGNAL:
                            cl_reserved[cloid] = cl_reserved.get(cloid, 0) + clt
                        else:
                            cl_settled[cloid] = cl_settled.get(cloid, 0) + clt
        # --- governor.invoice: ADDITIVE append-only billing history, idempotent per (org_id, invoice_id) —
        #     mirrors InvoiceRegistry._fold EXACTLY (first mint of an invoice_id wins; verify under the key valid
        #     at the seq). Carried across a prune so a pruned invoice line is not lost and cannot be replayed. ---
        if sig == _INV_SIGNAL:
            ioid = p.get("org_id")
            iid = p.get("invoice_id")
            if isinstance(ioid, str) and ioid and isinstance(iid, str) and iid:
                ikey = (ioid, iid)
                if ikey not in inv_rows and verify_signed(p, _INV_CORE, vpk):
                    inv_rows[ikey] = [str(p.get("kind") or ""), str(p.get("price_id") or ""),
                                      _inv_as_nonneg(p.get("amount_minor")), str(p.get("currency") or ""),
                                      _inv_as_nonneg(p.get("credits")),
                                      float(as_issued_at(p.get("period_start"))),
                                      float(as_issued_at(p.get("period_end"))),
                                      float(as_issued_at(p.get("issued_at")))]
        # --- pricing S2: trial claims (first-wins) and report unlocks (billing first-wins, owner latest-wins),
        #     through each module's own fold step under the key valid at the seq. ---
        if sig == _TC_SIGNAL:
            _tc_apply(p, vpk, tc_rows)
        if sig == _RU_SIGNAL:
            _ru_apply(p, vpk, ru_billing, ru_owner)
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
        ownership_proof_state=[[k[0], k[1], v] for k, v in op_state.items()],
        ownership_proof_issued=[[k[0], k[1], i] for k, i in op_issued.items()],
        ownership_proof_row=[[k[0], k[1], r[0], r[1], r[2], r[3]] for k, r in op_row.items()],
        monitoring_authority_state=[[k[0], k[1], v] for k, v in ma_state.items()],
        monitoring_authority_issued=[[k[0], k[1], i] for k, i in ma_issued.items()],
        monitoring_authority_row=[[k[0], k[1], r[0], r[1], r[2], r[3]] for k, r in ma_row.items()],
        customer_credential_state=[[k[0], k[1], v] for k, v in cc_state.items()],
        customer_credential_issued=[[k[0], k[1], i] for k, i in cc_issued.items()],
        customer_credential_row=[[k[0], k[1], r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]]
                                 for k, r in cc_row.items()],
        wallet_granted=[[o, c] for o, c in w_granted.items()],
        wallet_debited=[[o, c] for o, c in w_debited.items()],
        wallet_seen=[[sg, o, e] for (sg, o, e) in w_seen],
        plan_granted=[[o, pe, c] for (o, pe), c in p_granted.items()],
        plan_debited=[[o, pe, c] for (o, pe), c in p_debited.items()],
        plan_seen=[[sg, o, e] for (sg, o, e) in p_seen],
        subscription_state=[[o, v] for o, v in sub_state.items()],
        subscription_issued=[[o, i] for o, i in sub_issued.items()],
        subscription_row=[[o, r[0], r[1], r[2], r[3]] for o, r in sub_row.items()],
        monitoring_subscription_state=[[o, v] for o, v in msub_state.items()],
        monitoring_subscription_issued=[[o, i] for o, i in msub_issued.items()],
        monitoring_subscription_row=[[o, r[0], r[1], r[2], r[3]] for o, r in msub_row.items()],
        postpaid_state=[[o, v] for o, v in pp_state.items()],
        postpaid_issued=[[o, i] for o, i in pp_issued.items()],
        postpaid_row=[[o, r[0], r[1]] for o, r in pp_row.items()],
        postpaid_arrears_debited=[[o, c] for o, c in pp_debited.items()],
        postpaid_arrears_credited=[[o, c] for o, c in pp_credited.items()],
        postpaid_arrears_seen=[[sg, o, e] for (sg, o, e) in pp_seen],
        cost_reserved=[[o, t] for o, t in cl_reserved.items()],
        cost_settled=[[o, t] for o, t in cl_settled.items()],
        cost_seen=[[sg, o, e] for (sg, o, e) in cl_seen],
        invoice_row=[[k[0], k[1], *r] for k, r in inv_rows.items()],
        trial_claim_row=[[k[0], k[1], *r] for k, r in tc_rows.items()],
        report_unlock_billing=[[o, *r] for o, r in ru_billing.items()],
        report_unlock_owner=[[o, *r] for o, r in ru_owner.items()],
        consumed_arm_nonces=[[d, n] for (d, n) in arm],
        device_approval_dedup=[[pk, sg, seq] for (pk, sg), seq in dedup.items()],
        warden_best={k: [c, h, s] for k, (c, h, s) in warden.items()},
        archivist_view=[view[s] for s in sorted(view)],
        grounded_keys=sorted(grounded),
        refused_keys=sorted(refused),
        open_queued_below_base=[],  # computed by the prune's referential-floor guard (Slice D/E), not here
    )
