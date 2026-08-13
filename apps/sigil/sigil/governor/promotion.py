"""Per-scope promotion policy (SIGIL §5). An owner may promote a specific (agent, scope) so its A2
proposals auto-approve instead of queuing — EXCEPT ENVOY, which has NO promotion path (§4.6). A3
never promotes.

AUTHENTICATED (Phase 6 red-pen RP-2/RP-4): a grant/revoke is meaningless unless SIGNED by the owner
key and verified against the persisted trusted pubkey. `is_promoted` ignores any grant that does not
verify — so a forged grant written by a prompt-injected agent via `self.store` grants nothing. The
gate scope is the proposal's RECORD KIND (the real action written), not a self-asserted label
(RP-3), so a promotion is "agent X may auto-approve A2 records of kind K."

ANTI-REPLAY (this slice): verifying the signature proved WHO granted, never WHEN the grant counts.
Anyone able to append to the spine could capture an owner-signed `granted`, wait for the owner to
revoke it, and re-append the captured bytes VERBATIM — genuine signature, cleanly-extending hash chain,
and the revoked agent silently regains A2 auto-approval. So `issued_at` joins the signed core and BOTH
folds (`is_promoted` and `state_all`) keep a PER-(agent, scope) high-water: a grant counts only while
its `issued_at` strictly exceeds every grant already honored for that same key. Per-key and not global,
or a grant for one agent would refuse a legitimate later grant for another that happened to carry a
smaller `issued_at`. `revoked` — the SAFE direction — keeps its existing owner-signature requirement but
takes NO freshness requirement: a replayed revoke merely re-revokes, and gating the fail-safe direction
would turn it into a fail-open."""
from __future__ import annotations

from typing import Optional

from ..spine.snapshot import SnapshotState
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

SIGNAL = "governor.promotion"
NO_PROMOTION_AGENTS = frozenset({"ENVOY", "DELEGATE"})   # outbound + account actions stay human-gated forever
# `issued_at` MUST be in the core: outside it, an attacker could re-stamp a captured grant's freshness
# past the high-water without breaking the signature — exactly the replay this guard refuses.
_CORE = ("signal", "state", "agent", "scope", "issued_at")


class PromotionPolicy:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def grant(self, agent: str, scope: str = "*", *, issued_at: float):
        """Promote (agent, scope) — the DANGEROUS direction. `issued_at` is a REQUIRED, owner-set,
        strictly-increasing value: the fold honors this grant only while it exceeds every grant already
        honored for this exact (agent, scope), so a replayed one never lands. Required rather than
        defaulted because this module reads NO clock — the authority over "when" belongs to the caller
        holding the owner key (the same contract as `offense_gate.open_gate`)."""
        if agent in NO_PROMOTION_AGENTS:
            self.store.append(kind="refusal", source="governor", actor="WARDEN",
                              payload={"signal": SIGNAL, "decision": "refused", "agent": agent,
                                       "scope": scope, "tier": "A0",
                                       "reason": f"{agent} has no promotion path (SIGIL §4.6) — outbound stays human-gated"})
            return None
        core = {"signal": SIGNAL, "state": "granted", "agent": agent, "scope": scope,
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def revoke(self, agent: str, scope: str = "*") -> int:
        """Revoke (agent, scope) — the SAFE direction. Still owner-signed (an unsigned revoke has never
        counted here, unlike the kill-switch's unsigned engage), but carries a FIXED `issued_at` of 0.0
        and is subject to NO freshness check: a replayed revoke merely re-revokes. The constant keeps the
        record signature-valid under the new core so the revoke itself still verifies."""
        core = {"signal": SIGNAL, "state": "revoked", "agent": agent, "scope": scope, "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _fold(self) -> dict:
        """THE fold — one implementation, shared by `state_all` and `is_promoted`.

        These were two hand-copied folds. That duplication has already produced a real defect once: the
        NO_PROMOTION_AGENTS denylist landed in `is_promoted` and had to be mirrored into `state_all`
        afterwards (see the comment in `state_all`), because "a mint-side gate must be mirrored at the
        read surface". Rather than hand-copy the anti-replay guard into both and re-run that risk, both
        reads now call this. A future gate added here is structurally present at BOTH read surfaces.

        Returns {(agent, scope): "granted"|"revoked"} — latest VERIFIED, FRESH record wins.

        Pubkey-DEPENDENT: the pre-folded prefix state (and its high-water) is valid ONLY under the pubkey
        it was folded with. If our anchor differs (rotated key / custom anchor / the empty Slice-C
        identity whose tp=="") BYPASS the snapshot and full-scan from genesis. BYTE-IDENTICAL under the
        empty snapshot: base_seq==0 => since_seq=-1 => the full scan, and an empty seed either way."""
        st = SnapshotState.load(self.store)
        if self.trusted_pubkey != st.trusted_pubkey:
            state, since, issued = {}, -1, {}
        else:
            # PER-(agent, scope) high-water, seeded from the SAME snapshot under the SAME pubkey condition
            # — otherwise the first hard prune would reset it and make every pruned grant replayable.
            state, since, issued = dict(st.promotion_map()), st.base_seq - 1, dict(st.promotion_issued_map())
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if p.get("signal") != SIGNAL or p.get("state") not in ("granted", "revoked"):
                continue
            if not verify_signed(p, _CORE, self.trusted_pubkey):
                continue                          # fail-closed: an unsigned/forged record is not counted
            key = (p.get("agent"), p.get("scope"))
            if p["state"] == "granted":
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(key, NO_HIGHWATER):
                    continue                      # REPLAY / stale re-append of an already-honored grant
                issued[key] = at                  # consume it so its own replay is refused hereafter
            state[key] = p["state"]               # latest verified (and, for a grant, FRESH) wins
        return state

    def state_all(self) -> list[dict]:
        """Every currently-GRANTED (agent, scope), read-only — the SAME verified fold ``is_promoted`` uses
        (literally: both call ``_fold``), so a listed grant is exactly one ``is_promoted`` would confirm. A
        later ``revoke`` supersedes; an unsigned / forged / REPLAYED grant (e.g. one a prompt-injected agent
        wrote via the shared ``store``) is NOT listed, so this can never over-report the owner's grants."""
        state = self._fold()
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
        state = self._fold()
        return state.get((agent, scope)) == "granted" or state.get((agent, "*")) == "granted"
