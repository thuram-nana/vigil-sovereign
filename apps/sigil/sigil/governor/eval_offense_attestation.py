"""
governor.eval_offense_attestation — the owner-signed, charter-bound, AUTO-EXPIRING, EVALUATOR-countersigned
HARD PRECONDITION that must verify before weaponized offense may ARM against a LIVE eval target
(VIGIL M-11.1).

It is modeled line-for-line on :mod:`governor.offense_gate` (the fail-closed, owner-signed, charter-bound,
auto-expiring offense gate), with ONE capability added: a distinct EVALUATOR proves possession of their own
owner-enrolled key by COUNTER-SIGNING the exact attestation the owner signs. The evaluator PoP is purely
ADDITIVE admission — it binds a DISTINCT evaluator identity to the arming decision; it is NEVER a governance
key. The OWNER key remains the sole governance signer; a forged, unsigned, wrong-charter, wrong-environment,
expired, replayed, or evaluator-unsigned "attestation" arms NOTHING.

Defaults UNATTESTED (arming denied). Like the offense gate:
  * the signed CORE carries the charter binding (id+hash), the environment, the expiry (``not_after``) AND
    the anti-replay ``issued_at``, so none can be rewritten without breaking the owner signature;
  * state lives ONLY on the append-only, fsync'd spine and is re-derived on every check (survives restart);
  * it is time-dependent (it expires), so the verdict is NEVER cached;
  * a ``revoke`` is the fail-safe direction — honoured whoever signs it (any event can un-arm), exactly as
    the offense gate's ``close`` and the kill-switch ``engage`` are;
  * control events are logged at tier A0/auto so they are never themselves offense-gated (deadlock
    avoidance).

DOMAIN SEPARATION: the evaluator PoP signs under the FRESH ``eval-offense-attestation`` spine domain tag, so
an owner or evaluator signature produced for ANY other purpose (authority, login-pop, offense_gate, account,
the WS2 live-target-attestation) can never verify here, and vice-versa.

FATAL-2: this is a SIGIL (sovereign) governance concept. It imports NO offense-engine module
(``assert_no_offense`` holds). The OFFENSE plane never imports this module and never holds the owner key: it
reads the PUBLIC signed attestation back from the shared seam (published by :meth:`attest` / :meth:`revoke`
via the import-clean ``vigil_integration.live.eval_attestation`` broker) and VERIFIES it against the pinned
owner key — see ``vigil_integration.live.eval_attestation.verify_live_offense_attested``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from ..reuse import IntegrityError, assert_no_offense, canonical_json, verify_one
from . import key_history as _kh
from .authn import as_issued_at, signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey

assert_no_offense()

SIGNAL = "governor.eval_offense_attestation"

# The one domain tag this attestation's evaluator PoP signs under (imported from the single registry so the
# sovereign signer and the offense verifier can never drift to two spellings).
_DOMAIN_KEY = "eval-offense-attestation"

# Only these fields are authenticated by the OWNER signature. ``not_after``/``charter_id``/``charter_hash``/
# ``environment``/``evaluator_pubkey``/``allow_destructive`` MUST be here or an attacker could rewrite the
# expiry / charter binding / environment / evaluator identity / destructive-floor echo without breaking the
# sig; and ``issued_at`` MUST be here so a captured attestation cannot be REPLAYED to reverse a later revoke
# (the fold rejects any attestation whose ``issued_at`` does not strictly exceed the highest already seen).
_CORE = (
    "signal", "state", "engagement_slug", "charter_id", "charter_hash", "evaluator_pubkey",
    "environment", "not_after", "issued_at", "allow_destructive",
)


class EvalOffenseAttestationMissing(RuntimeError):
    """No verified EvalOffenseAttestation covers this engagement/charter at this time — weaponized offense
    must not ARM. Raised fail-closed; must not be silently caught (it is the sovereign HARD PRECONDITION
    refusing to let offense arm)."""


@dataclass(frozen=True)
class EvalOffenseAttestationState:
    attested: bool
    reason: str
    engagement_slug: str = ""
    charter_hash: str = ""
    evaluator_pubkey: str = ""
    not_after: float = 0.0


def _domain_tag() -> bytes:
    from vigil_core.spine_domains import DOMAIN_TAGS
    return DOMAIN_TAGS[_DOMAIN_KEY]


def _canon(core: dict) -> bytes:
    m = canonical_json(core)
    return bytes(m) if isinstance(m, (bytes, bytearray)) else str(m).encode("utf-8")


def build_core(
    *, engagement_slug: str, charter_id: str, charter_hash: str, evaluator_pubkey: str,
    not_after: float, issued_at: float, environment: str = "live", state: str = "attested",
) -> dict:
    """The exact authenticated CORE the OWNER signs and the EVALUATOR counter-signs. ``allow_destructive`` is
    HARD-WIRED ``False`` — this attestation is an ARMING precondition only; it never grants destructive
    action (destructive stays behind the separate m-of-n quorum). Floats are coerced so sign and verify
    canonicalize byte-identically."""
    return {
        "signal": SIGNAL,
        "state": state,
        "engagement_slug": str(engagement_slug),
        "charter_id": str(charter_id),
        "charter_hash": str(charter_hash),
        "evaluator_pubkey": str(evaluator_pubkey),
        "environment": str(environment),
        "not_after": float(not_after),
        "issued_at": float(issued_at),
        "allow_destructive": False,
    }


def pop_signing_bytes(core: dict) -> bytes:
    """The exact bytes the EVALUATOR signs for the proof-of-possession: the fresh ``eval-offense-attestation``
    domain tag followed by the canonical JSON of the SAME core the owner signs. Domain separation means this
    signature can never verify under any other purpose; binding the whole core means the evaluator attests to
    exactly this charter / environment / expiry, not a re-aimed copy."""
    return _domain_tag() + _canon({k: core.get(k) for k in _CORE})


def sign_evaluator_pop(core: dict, evaluator_private_key_b64: str) -> str:
    """The evaluator's PoP signature over :func:`pop_signing_bytes` — produced with the evaluator's OWN
    private key (never the owner's). This is what the evaluator hands the owner to co-sign into an
    attestation."""
    from ..reuse import sign
    return sign(evaluator_private_key_b64, pop_signing_bytes(core))


def _verify_pop(core: dict, evaluator_sig) -> bool:
    """True iff ``evaluator_sig`` is a valid PoP by ``core['evaluator_pubkey']`` over the domain-tagged core.
    Fail-closed (never raises out of a fold): a hostile spine payload can carry any JSON type for the sig."""
    pk = core.get("evaluator_pubkey")
    if not pk or not isinstance(pk, str):
        return False
    if not evaluator_sig or not isinstance(evaluator_sig, str):
        return False
    try:
        return verify_one(pk, pop_signing_bytes(core), evaluator_sig)
    except (IntegrityError, TypeError):
        # malformed base64 / wrong-length / non-decodable sig → NOT authentic (fail-closed contract)
        return False


def _as_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0  # unparseable expiry → treated as already-expired (fail-closed)


class EvalOffenseAttestation:
    """Owner-signed, charter-bound, auto-expiring, evaluator-countersigned arming precondition, on the spine.
    Construction mirrors :class:`OffenseGate`: the owner signing key and trusted pubkey default to the
    persisted owner identity."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        # Signing key is the OWNER's (may be None → cannot attest anything, the desired default).
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        # Verification is PINNED to the persisted owner identity, never a caller-supplied key.
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner transitions (both A0/auto so they are never themselves offense-gated) -------------------

    def attest(
        self, *, engagement_slug: str, charter_id: str, charter_hash: str, evaluator: str,
        evaluator_pubkey: str, evaluator_pop: str, not_after: float, issued_at: float,
        environment: str = "live", by: str = "owner", reason: str = "",
    ) -> int:
        """Owner-sign an EvalOffenseAttestation binding exactly ``(engagement_slug, charter_id, charter_hash,
        environment)``, expiring at ``not_after`` (unix seconds), anti-replay-bound by a strictly-increasing
        ``issued_at``. The ADDITIVE evaluator PoP (``evaluator_pop``) is verified here against the evaluator's
        OWNER-ENROLLED ``Account.user_pubkey`` (a DISTINCT identity, never the owner's) — so a mint requires
        BOTH the owner signature AND a genuine counter-signature by the enrolled evaluator. Only the owner key
        produces a signature the fold will honour; the evaluator PoP alone arms nothing."""
        if self.owner_key is None:
            raise ValueError("attest requires the owner signing key")
        if not engagement_slug or not charter_id or not charter_hash:
            raise ValueError("attest requires engagement_slug, charter_id and charter_hash to bind to")
        if not evaluator or not evaluator_pubkey:
            raise ValueError("attest requires the evaluator username and its enrolled pubkey")
        # The evaluator PoP must be by a DISTINCT, owner-ENROLLED identity — look the account up and require
        # the supplied pubkey to be exactly the one the owner enrolled (accounts.enroll_pubkey). This is the
        # SAME primitive server._login_pop / ui.login_challenges use (Account.user_pubkey).
        from .accounts import AccountsRegistry
        try:
            acct = AccountsRegistry(self.store).account(evaluator)
        except Exception:  # noqa: BLE001 — a hostile/corrupt spine must never crash the ceremony → fail-closed
            acct = None
        if acct is None or not acct.user_pubkey:
            raise ValueError(
                f"no owner-bound cryptographic identity for evaluator {evaluator!r} — the owner must enroll "
                f"the evaluator's key (enroll_pubkey) before it can co-sign an eval-offense attestation")
        if acct.user_pubkey != str(evaluator_pubkey):
            raise ValueError(
                f"evaluator_pubkey does not match the enrolled key for {evaluator!r} (the evaluator PoP must "
                f"bind the DISTINCT enrolled identity, not an arbitrary key)")
        core = build_core(
            engagement_slug=engagement_slug, charter_id=charter_id, charter_hash=charter_hash,
            evaluator_pubkey=str(evaluator_pubkey), not_after=not_after, issued_at=issued_at,
            environment=environment, state="attested",
        )
        if not _verify_pop(core, evaluator_pop):
            raise ValueError(
                "the evaluator proof-of-possession is invalid for this exact attestation (it must be the "
                "enrolled evaluator's signature over the domain-tagged core)")
        payload = {
            **signed_payload(core, self.owner_key),
            "evaluator_sig": str(evaluator_pop), "evaluator": str(evaluator),
            "by": by, "reason": reason, "tier": "A0", "decision": "auto",
        }
        seq = self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        self._publish(str(engagement_slug))
        return seq

    def revoke(self, *, engagement_slug: str, by: str = "owner", reason: str = "") -> int:
        """Revoke every attestation for ``engagement_slug`` — the SAFE direction (honoured whoever signs it,
        like the offense gate's close). Carries a FIXED ``issued_at`` of 0.0 (a replayed revoke merely
        re-revokes). After a revoke, arming is DENIED until a fresh owner+evaluator attestation lands."""
        if not engagement_slug:
            raise ValueError("revoke requires the engagement_slug to un-arm")
        core = build_core(
            engagement_slug=engagement_slug, charter_id="", charter_hash="", evaluator_pubkey="",
            not_after=0.0, issued_at=0.0, environment="", state="revoked",
        )
        payload = {
            **signed_payload(core, self.owner_key),
            "by": by, "reason": reason, "tier": "A0", "decision": "auto",
        }
        seq = self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        self._publish(str(engagement_slug))
        return seq

    # -- the fail-closed fold (NEVER cached — the verdict is time-dependent) ---------------------------

    def state(
        self, *, engagement_slug: str, charter_hash: Optional[str] = None, now: float,
        environment: str = "live",
    ) -> EvalOffenseAttestationState:
        """Fold the spine to the arming state for ``engagement_slug`` (optionally constrained to a specific
        ``charter_hash``) at time ``now``. UNATTESTED unless the latest-winning event is an owner-signed,
        evaluator-countersigned attestation bound to this engagement + ``environment`` with ``now <
        not_after``. Any revoke (even unsigned) un-arms it. Succession-aware (W9-1): each record is
        authenticated under the owner key valid AT ITS SEQ, so a since-rotated key still verifies while a
        forged record minted with a retired key at a later seq is refused. NEVER cached."""
        attested = False
        reason = "default-unattested: no owner-signed eval-offense attestation on the spine"
        na = 0.0
        ev = ""
        max_issued = float("-inf")  # anti-replay high-water: each honoured attestation must exceed it
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)  # succession-aware
        for record in self.store.iter_records():
            payload = record.payload if isinstance(record.payload, dict) else {}
            if payload.get("signal") != SIGNAL:
                continue
            if payload.get("engagement_slug") != engagement_slug:
                continue  # an attestation / revoke for a DIFFERENT engagement — no effect on this one
            st = payload.get("state")
            if st == "revoked":
                attested, reason, na, ev = False, "revoked by a governance event", 0.0, ""  # honour ANY revoke
            elif st == "attested":
                # A forged/unsigned/wrong-charter/wrong-env/destructive/evaluator-unsigned record is treated
                # exactly like the offense gate treats a forged open: `continue` with NO effect and NO
                # high-water consume (it is not a valid attestation).
                if charter_hash is not None and payload.get("charter_hash") != charter_hash:
                    continue  # attestation for a DIFFERENT charter — no effect on this query
                if payload.get("environment") != environment:
                    continue  # bound to a DIFFERENT environment — no effect
                if payload.get("allow_destructive") is not False:
                    continue  # the destructive-floor echo must be False — never honour one claiming otherwise
                if not verify_signed(payload, _CORE, resolver.at(record.seq)):
                    continue  # forged/unsigned owner sig (or wrong key at this seq) — no effect
                core = {k: payload.get(k) for k in _CORE}
                if not _verify_pop(core, payload.get("evaluator_sig")):
                    continue  # missing/forged evaluator PoP — the ADDITIVE identity proof failed, no effect
                issued = as_issued_at(payload.get("issued_at"))  # NaN/inf-safe → bottom (cannot poison HW)
                if issued <= max_issued:
                    continue  # REPLAY / stale re-append of an already-honoured attestation
                max_issued = issued  # consume this issued_at so its own replay is refused hereafter
                signed_na = _as_float(payload.get("not_after"))
                if now < signed_na:
                    attested, reason, na = True, "owner-signed + evaluator-PoP attested, unexpired", signed_na
                    ev = str(payload.get("evaluator_pubkey") or "")
                else:
                    attested, reason, na, ev = False, "owner-signed attestation but EXPIRED", 0.0, ""
        return EvalOffenseAttestationState(
            attested=attested, reason=reason,
            engagement_slug=engagement_slug if attested else "",
            charter_hash=(charter_hash or "") if attested else "",
            evaluator_pubkey=ev if attested else "",
            not_after=na if attested else 0.0,
        )

    def is_attested(
        self, *, engagement_slug: str, charter_hash: Optional[str] = None, now: float,
        environment: str = "live",
    ) -> bool:
        return self.state(engagement_slug=engagement_slug, charter_hash=charter_hash, now=now,
                          environment=environment).attested

    # -- seam publication (so the OFFENSE plane can verify the public signed material) -----------------

    def _base_dir(self) -> str:
        return os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"

    def _publish(self, engagement_slug: str) -> None:
        """Mirror every eval-offense-attestation record for ``engagement_slug`` (attestations AND revokes) to
        the shared seam, so the offense plane can READ+VERIFY the public signed material without importing
        this module or holding the owner key (FATAL-2). The spine stays the source of truth; a publish
        failure merely leaves the offense plane UNARMED (fail-closed), never falsely armed. Best-effort over
        an OSError (unwritable seam); a programming error propagates.

        The loose seam's record-LIST order/membership is unauthenticated on its own (each record is signed, but
        the list is not), so an off-seam DROP/REORDER/ROLLBACK of the revoke record could re-arm a revoked
        attestation on the offense plane (the sovereign fold is immune because it reads the append-only
        hash-chained spine; the offense plane cannot fold that spine at arm time). So the OWNER additionally
        signs a SEAL over the WHOLE ordered record list + a monotonic publish ``seq`` (the current spine head);
        the offense verifier re-derives it over the records it read (drop/reorder no longer verify) and enforces
        the monotonic ``seq`` against a durable high-water (a rollback is refused). The owner key signs ONLY
        here in SIGIL; the import-clean broker merely transports the public seal (FATAL-2)."""
        records = []
        for record in self.store.iter_records():
            p = record.payload if isinstance(record.payload, dict) else {}
            if p.get("signal") == SIGNAL and p.get("engagement_slug") == engagement_slug:
                records.append(dict(p))
        try:
            from vigil_integration.live.eval_attestation import build_seal, write_eval_attestations
            seal = None
            if self.owner_key is not None:
                from ..reuse import sign
                # The monotonic publish seq is the current spine head — strictly larger than any prior
                # publish's (every attest/revoke appended to the spine before calling _publish), so a
                # replayed older seam has a lower seq and is refused by the offense high-water. ``next_seq``
                # is a property; fall back to the per-slug record count (also strictly growing per publish,
                # since each attest/revoke appends exactly one record for this slug) for a store without it.
                seq = getattr(self.store, "next_seq", None)
                if not isinstance(seq, int):
                    seq = len(records)
                seal = build_seal(
                    engagement_slug, seq, records,
                    sign_fn=lambda b: sign(self.owner_key.private_key_b64, b),
                    pubkey=self.owner_key.public_key_b64,
                )
            write_eval_attestations(self._base_dir(), engagement_slug, records, seal=seal)
        except (OSError, ValueError):
            # Unwritable / unsafe seam → the offense plane simply never arms (fail-closed). The spine record
            # stands; a later attest/revoke re-publishes the full list.
            pass


def assert_eval_offense_attested(
    store, *, engagement_slug: str, charter_hash: Optional[str] = None, now: float,
    environment: str = "live", owner_key=None, trusted_pubkey: Optional[str] = None,
) -> EvalOffenseAttestationState:
    """Fail-closed assertion the SOVEREIGN gate makes before permitting a LIVE authorization: raise
    :class:`EvalOffenseAttestationMissing` unless a verified EvalOffenseAttestation covers this engagement
    (and, when given, this exact ``charter_hash``) at ``now``. Returns the attested state on success."""
    att = EvalOffenseAttestation(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    st = att.state(engagement_slug=engagement_slug, charter_hash=charter_hash, now=now,
                   environment=environment)
    if not st.attested:
        raise EvalOffenseAttestationMissing(
            f"no verified eval-offense attestation for engagement {engagement_slug!r} "
            f"(environment={environment!r}): {st.reason}")
    return st
