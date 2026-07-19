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
  creation_created       {(service,origin): count}               count-add (PAIR key!)          DELEGATE account cap
  capability_map         {host_id: cap}                          right-biased LWW               mesh host capability
  mesh_dev_state         {device_pubkey: authorized|revoked}     LWW (keep revoked!)            mesh device authz
  promotion              {(agent,scope): granted|revoked}        LWW (keep revoked!)            auto-approval grants
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
    # tuple-keyed / None-tolerant sub-states as list-of-rows (JSON-safe + type-verbatim): a non-str key an
    # owner-signed-but-malformed record could carry (host_id/device_pubkey/agent/scope = None/int) is
    # preserved EXACTLY — the live scans key on p.get(...) with no type guard, so dropping such a key would
    # make build() != scan. `dict(rows)` / the accessors reconstruct the map (incl. any non-str key).
    creation_created: list = []       # [[service|None, origin|None, count], ...]
    capability_map: list = []         # [[host_id, cap_dict], ...]  -> dict() reconstructs (keys verbatim)
    mesh_dev_state: list = []         # [[device_pubkey, "authorized"|"revoked"], ...] -> dict() reconstructs
    promotion: list = []              # [[agent, scope, "granted"|"revoked"], ...]
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
        st = cls.model_validate(folded)
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
          base_seq: int, snapshot_seq: int) -> SnapshotState:
    from ..agents.actor_scope import _origin
    from ..bridge.envelope import RECEIPT_SIGNAL
    from ..consolidate.grounding import CONSOLIDATE_SOURCE
    from ..governor.authn import verify_signed
    from ..mesh.registry import CAP_SIGNAL, DEV_SIGNAL, _CAP_CORE, _DEV_CORE

    # The order-DEPENDENT folds (the kill-switch latch, every last-write-wins map) require ascending seq.
    # iter_records already yields ascending seq, but sort defensively so build() is correct for ANY caller /
    # iterable — an out-of-order input must never flip a latch or pick the wrong last-write.
    records = sorted(records, key=lambda r: r.seq)
    tp = trusted_pubkey or ""
    nonce: dict[str, int] = {}
    ks_engaged = False
    creation: dict[tuple[Optional[str], Optional[str]], int] = {}
    capability: dict[Any, dict] = {}    # host_id key kept verbatim (may be non-str; mirrors the scan)
    mesh_dev: dict[Any, str] = {}       # device_pubkey key kept verbatim (may be non-str)
    promo: dict[tuple[Optional[str], Optional[str]], str] = {}
    arm: set = set()
    dedup: dict[tuple[Optional[str], Optional[str]], int] = {}
    warden: dict[str, tuple[int, str, int]] = {}
    view: dict[int, dict] = {}
    grounded: set[str] = set()
    refused: set[str] = set()

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
        # --- killswitch latch (engage=any, release=owner-verified, IN ORDER) ---
        if sig == "governor.killswitch":
            state = p.get("state")
            if state == "engaged":
                ks_engaged = True
            elif state == "released" and verify_signed(p, ("signal", "state"), tp):
                ks_engaged = False
        # --- creation cap (PAIR-keyed count; account.create applied). Record shape (actor.py): kind="event",
        #     payload{signal:"web.actor.step", step_kind:"account.create", status:"applied", service, url}. ---
        if p.get("signal") == "web.actor.step" and p.get("step_kind") == "account.create" \
                and p.get("status") == "applied":
            key = (p.get("service"), _origin(p.get("url", "")))
            creation[key] = creation.get(key, 0) + 1
        # --- mesh host capability (LWW verified). NO isinstance guard — mirror the scan, which keys on
        #     p.get("host_id") unconditionally (a non-str key is preserved via the list-of-rows form). ---
        if sig == CAP_SIGNAL and verify_signed(p, _CAP_CORE, tp):
            capability[p.get("host_id")] = {k: p.get(k) for k in _CAP_CORE if k != "signal"}
        # --- mesh device authz (LWW verified; keep revoked) — no isinstance guard (mirror the scan) ---
        if sig == DEV_SIGNAL and p.get("state") in ("authorized", "revoked") and verify_signed(p, _DEV_CORE, tp):
            mesh_dev[p.get("device_pubkey")] = p["state"]
        # --- promotion grants (LWW verified; keep revoked) — no isinstance guard (mirror the scan) ---
        if sig == "governor.promotion" and p.get("state") in ("granted", "revoked") \
                and verify_signed(p, ("signal", "state", "agent", "scope"), tp):
            promo[(p.get("agent"), p.get("scope"))] = p["state"]
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
        creation_created=[[s, o, c] for (s, o), c in creation.items()],
        capability_map=[[h, c] for h, c in capability.items()],
        mesh_dev_state=[[d, s] for d, s in mesh_dev.items()],
        promotion=[[a, s, v] for (a, s), v in promo.items()],
        consumed_arm_nonces=[[d, n] for (d, n) in arm],
        device_approval_dedup=[[pk, sg, seq] for (pk, sg), seq in dedup.items()],
        warden_best={k: [c, h, s] for k, (c, h, s) in warden.items()},
        archivist_view=[view[s] for s in sorted(view)],
        grounded_keys=sorted(grounded),
        refused_keys=sorted(refused),
        open_queued_below_base=[],  # computed by the prune's referential-floor guard (Slice D/E), not here
    )
