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

_MAX_SNAPSHOT_SCHEMA = 1   # refuse-newer gate (W5-3): a snapshot schema above this is "upgrade sigil"


class SnapshotState(BaseModel):
    """The persisted folded state. Fields are JSON-native (tuple-keyed / set sub-states use list forms that
    round-trip verbatim); runtime accessors reconstruct the sets / tuple-keyed dicts. Non-secret."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
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
    #                                   password_hash], ...] — the fields to REBUILD an active `Account` from the
    #                                   seed (issued_at joins from account_issued; state="active"). Each optional
    #                                   trailing field is None for a shorter/legacy row: user_pubkey (S3 PoP key),
    #                                   totp_secret (S4 SEALED second factor), password_hash (S4 optional login).
    #                                   Carrying totp_secret/password_hash keeps a hard prune from silently
    #                                   DOWNGRADING an account's auth (e.g. dropping its enrolled second factor).
    #                                   Carried for every honored-active username (incl. ones later revoked —
    #                                   dropped at read time by account_state, exactly as the scan).
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
          base_seq: int, snapshot_seq: int, seed: Optional["SnapshotState"] = None) -> SnapshotState:
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
    from ..governor.capability import SIGNAL as _CAPLATCH_SIGNAL
    from ..governor.capability import _CORE as _CAPLATCH_CORE
    from ..governor.killswitch import SIGNAL as _KS_SIGNAL
    from ..governor.killswitch import _CORE as _KS_CORE
    from ..governor.promotion import SIGNAL as _PROMO_SIGNAL
    from ..governor.promotion import _CORE as _PROMO_CORE
    from ..mesh.registry import CAP_SIGNAL, DEV_SIGNAL, _CAP_CORE, _DEV_CORE, cap_descriptor

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
                                           (row[6] if len(row) > 6 else None)]
                                  for row in s.account_cred} if s else {}   # 5/6/7 = user_pubkey / totp_secret /
    #                                                                         password_hash (None for a legacy row)
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
            elif state == "released" and verify_signed(p, _KS_CORE, tp):
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
            elif state == "enabled" and verify_signed(p, _CAPLATCH_CORE, tp):
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
        if sig == CAP_SIGNAL and verify_signed(p, _CAP_CORE, tp):
            hkey = p.get("host_id")
            at = as_issued_at(p.get("issued_at"))
            if at > cap_map_issued.get(hkey, NO_HIGHWATER):   # mirror capability_map EXACTLY
                cap_map_issued[hkey] = at
                capability[hkey] = cap_descriptor(p)
        # --- mesh device authz (LWW verified + authorize ANTI-REPLAY FRESH; keep revoked) — no
        #     isinstance guard (mirror the scan) ---
        if sig == DEV_SIGNAL and p.get("state") in ("authorized", "revoked") and verify_signed(p, _DEV_CORE, tp):
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
                and verify_signed(p, _PROMO_CORE, tp):
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
            elif ustate == "active" and verify_signed(p, _acct_core_fields(p), tp):
                ukey = p.get("username")
                at = as_issued_at(p.get("issued_at"))
                if at > acct_issued.get(ukey, NO_HIGHWATER):   # mirror _fold: stale/replayed active ⇒ no effect
                    acct_issued[ukey] = at
                    acct_state[ukey] = "active"
                    # carry user_pubkey / totp_secret / password_hash (None when absent) so a KEYED /
                    # TOTP-enrolled / password account survives a prune with its full auth — else a
                    # pruned+seeded account would silently lose its PoP key, its SECOND FACTOR, or its password.
                    acct_cred[ukey] = [p.get("role"), p.get("cred_hash"), p.get("cred_salt"),
                                       p.get("user_pubkey"), p.get("totp_secret"), p.get("password_hash")]
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
                       (c[5] if len(c) > 5 else None)] for u, c in acct_cred.items()],
        consumed_arm_nonces=[[d, n] for (d, n) in arm],
        device_approval_dedup=[[pk, sg, seq] for (pk, sg), seq in dedup.items()],
        warden_best={k: [c, h, s] for k, (c, h, s) in warden.items()},
        archivist_view=[view[s] for s in sorted(view)],
        grounded_keys=sorted(grounded),
        refused_keys=sorted(refused),
        open_queued_below_base=[],  # computed by the prune's referential-floor guard (Slice D/E), not here
    )
