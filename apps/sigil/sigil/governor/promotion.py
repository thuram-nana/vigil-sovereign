"""Per-scope promotion policy (SIGIL §5). An owner may promote a specific (agent, scope) so its A2
proposals auto-approve instead of queuing — EXCEPT ENVOY, which has NO promotion path (§4.6). A3
never promotes.

AUTHENTICATED (Phase 6 red-pen RP-2/RP-4): a grant/revoke is meaningless unless SIGNED by the owner
key and verified against the persisted trusted pubkey. `is_promoted` ignores any grant that does not
verify — so a forged grant written by a prompt-injected agent via `self.store` grants nothing. The
gate scope is the proposal's RECORD KIND (the real action written), not a self-asserted label
(RP-3), so a promotion is "agent X may auto-approve A2 records of kind K." """
from __future__ import annotations

from typing import Optional

from ..spine.snapshot import SnapshotState
from .authn import signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.promotion"
NO_PROMOTION_AGENTS = frozenset({"ENVOY", "DELEGATE"})   # outbound + account actions stay human-gated forever
_CORE = ("signal", "state", "agent", "scope")


class PromotionPolicy:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def grant(self, agent: str, scope: str = "*"):
        if agent in NO_PROMOTION_AGENTS:
            self.store.append(kind="refusal", source="governor", actor="WARDEN",
                              payload={"signal": SIGNAL, "decision": "refused", "agent": agent,
                                       "scope": scope, "tier": "A0",
                                       "reason": f"{agent} has no promotion path (SIGIL §4.6) — outbound stays human-gated"})
            return None
        core = {"signal": SIGNAL, "state": "granted", "agent": agent, "scope": scope}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def revoke(self, agent: str, scope: str = "*") -> int:
        core = {"signal": SIGNAL, "state": "revoked", "agent": agent, "scope": scope}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def state_all(self) -> list[dict]:
        """Every currently-GRANTED (agent, scope), read-only — the SAME verified fold ``is_promoted`` uses,
        so a listed grant is exactly one ``is_promoted`` would confirm. A later ``revoke`` supersedes; an
        unsigned / forged grant (e.g. one a prompt-injected agent wrote via the shared ``store``) is NOT
        listed (fail-closed verification), so this can never over-report the owner's real grants."""
        st = SnapshotState.load(self.store)
        # Mirror is_promoted's pubkey-dependent fold exactly (a pre-folded prefix is valid only under the
        # pubkey it was folded with; otherwise full-scan from genesis).
        if self.trusted_pubkey != st.trusted_pubkey:
            state, since = {}, -1
        else:
            state, since = dict(st.promotion_map()), st.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if p.get("signal") != SIGNAL or p.get("state") not in ("granted", "revoked"):
                continue
            if not verify_signed(p, _CORE, self.trusted_pubkey):
                continue                          # fail-closed: an unsigned/forged grant is not counted
            state[(p.get("agent"), p.get("scope"))] = p["state"]
        # Mirror is_promoted's structural denylist early-return (NO_PROMOTION_AGENTS): if such an agent ever
        # carried an owner-signed grant (e.g. a currently-promotable agent later ADDED to the denylist), it is
        # NOT enforced — so it must not be LISTED either, or the card would show a phantom promotion. This is
        # the "a mint-side gate must be mirrored at the read surface" invariant applied to the read.
        return [{"agent": a, "scope": s}
                for (a, s), v in sorted(state.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1])))
                if v == "granted" and a not in NO_PROMOTION_AGENTS]

    def is_promoted(self, agent: str, scope: str = "*") -> bool:
        if agent in NO_PROMOTION_AGENTS:
            return False                          # never — structural, not policy
        st = SnapshotState.load(self.store)
        # promotion is a pubkey-DEPENDENT fold: the pre-folded prefix state is valid ONLY under the
        # pubkey it was folded with. If our anchor differs (rotated key / custom anchor / the empty
        # Slice-C identity whose tp=="") BYPASS the snapshot and full-scan from genesis (seed empty,
        # since=-1). BYTE-IDENTICAL under the empty snapshot: base_seq==0 => since_seq=-1 => the current
        # full scan and dict(promotion_map())=={}/{} seed => both branches collapse to the genesis scan.
        if self.trusted_pubkey != st.trusted_pubkey:
            state, since = {}, -1
        else:
            state, since = dict(st.promotion_map()), st.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if p.get("signal") != SIGNAL or p.get("state") not in ("granted", "revoked"):
                continue
            if not verify_signed(p, _CORE, self.trusted_pubkey):
                continue                          # fail-closed: an unsigned/forged grant grants nothing
            state[(p.get("agent"), p.get("scope"))] = p["state"]   # latest verified wins
        return state.get((agent, scope)) == "granted" or state.get((agent, "*")) == "granted"
