"""
governor.eval_capability_grant — the owner-signed, charter-/engagement-bound, EVALUATOR-countersigned
EvalCapabilityGrant: a SECURITY-CONTROL OVERRIDE authorization (the "eval button") that, when published,
PRE-AUTHORIZES the owner+evaluator to LIFT a CLOSED-ENUM set of OPT-IN, DEMOTE-ONLY authority-gate vetoes
for ONE engagement/target during a sanctioned full-capability evaluation (VIGIL M-11 "eval grant").

It is modeled line-for-line on :mod:`governor.eval_offense_attestation` (the owner-signed, evaluator-
countersigned, auto-expiring arming precondition), and inherits its whole security posture:

  * TWO-PARTY control — a mint requires BOTH the owner signature AND a FRESH proof-of-possession by a
    DISTINCT owner-enrolled EVALUATOR over the GRANT core (FIX B). The evaluator PoP is NEVER reused from
    the covering EvalOffenseAttestation — it is a fresh signature over THIS grant's core (which binds the
    ``allowed_gate_overrides`` AND ``max_covered_actions``), verified at mint AND re-verified in the keyless
    offense fold. :meth:`attest` refuses, before any spine write, a mint whose ``evaluator_pubkey`` is the
    owner's own key (a self-grant would collapse the two-party control to the owner key alone).
  * COVERING ATTESTATION — a grant may be minted ONLY when a verified EvalOffenseAttestation already covers
    the same engagement (the grant widens nothing the arming precondition has not already admitted; it rides
    strictly inside that envelope). Its temporal ceiling is therefore the covering attestation's ``not_after``
    (enforced independently at arm time by ``verify_live_offense_attested``), PLUS revoke, PLUS the per-
    engagement kill-switch, PLUS the signed engagement scope.
  * CLOSED ENUM — :func:`build_core` validates ``allowed_gate_overrides`` ⊆ :data:`ALLOWED_OVERRIDES`
    (``witness_quorum`` / ``blast_veto`` / ``containment_preview``) and RAISES before any spine write on any
    other token. The NEVER-LIFTABLE floors (the egress floor, the m-of-n destruction quorum, the GET-only
    write baseline) are NOT members of this enum and are structurally separate conjuncts the grant cannot
    feed — a grant can only lift the three OPT-IN, DEMOTE-ONLY vetoes, never a base refusal.
  * DEFAULTS UNGRANTED — no grant published ⇒ the offense verifier injects no acks ⇒ every gate enforces
    exactly as today (fail-closed; byte-identical).

FATAL-2: this is a SIGIL (sovereign) governance concept. It imports NO offense-engine module
(``assert_no_offense`` holds). The OFFENSE plane never imports this module and never holds the owner key: it
reads the PUBLIC signed grant back from the shared seam (published by :meth:`attest` / :meth:`revoke` via the
import-clean ``vigil_integration.live.eval_capability_grant`` broker) and VERIFIES it against the pinned owner
key — see ``vigil_integration.live.eval_capability_grant.verify_eval_capability_grant``.

DOMAIN SEPARATION: the evaluator PoP signs under the FRESH ``eval-capability-grant`` spine domain tag, so an
owner or evaluator signature produced for ANY other purpose (authority, login-pop, offense_gate, account, the
eval-offense attestation, the WS2 live-target-attestation) can never verify here, and vice-versa; the publish
SEAL signs under ``eval-capability-grant-seal``.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from ..reuse import IntegrityError, assert_no_offense, canonical_json, verify_one
from . import key_history as _kh
from .authn import as_issued_at, signed_payload, verify_signed
from .identity import owner_keypair, owner_pubkey
from .seam_publish import (
    encodable_or_revoke,
    granted_after_last_revoke,
    publish_lock,
    published_slugs,
    raise_close_alarm,
    retract_for_revoke,
    withdraw_publication,
)

assert_no_offense()

SIGNAL = "governor.eval_capability_grant"

# The one domain tag this grant's evaluator PoP signs under (imported from the single registry so the
# sovereign signer and the offense verifier can never drift to two spellings).
_DOMAIN_KEY = "eval-capability-grant"

# The CLOSED ENUM of gate vetoes a grant may lift. STRUCTURALLY this excludes the never-liftable floors
# (egress floor, m-of-n destruction quorum, GET-only write baseline) — those are separate conjuncts the
# grant never feeds. Only these three OPT-IN, DEMOTE-ONLY authority-gate vetoes are grantable:
#   * "witness_quorum"       — lift the 6c witness-quorum DEMOTE-ONLY veto for THIS action (gate.py 6c ack)
#   * "blast_veto"           — lift the 6b blast-radius ADVISORY veto for THIS action (gate.py 6b ack)
#   * "containment_preview"  — pre-authorize the DEFENSIVE containment capability allowlist for the M4.3
#                              preview / V2-prepare path ONLY (the real actuator stays DECLINED/frontier).
ALLOWED_OVERRIDES = frozenset({"witness_quorum", "blast_veto", "containment_preview"})

# Only these fields are authenticated by the OWNER signature AND the evaluator PoP. ``allowed_gate_overrides``
# and ``max_covered_actions`` MUST be here (FIX B) or an attacker could widen the override set / the budget
# ceiling without breaking either signature; ``issued_anchor`` MUST be here so a captured grant cannot be
# REPLAYED to reverse a later revoke (the fold rejects any grant whose ``issued_anchor`` does not strictly
# exceed the highest already seen — the monotonic, spine-anchored anti-replay high-water).
_CORE = (
    "signal", "state", "engagement_slug", "target", "allowed_gate_overrides", "issued_anchor",
    "max_covered_actions", "evaluator_pubkey",
)


class EvalGrantSeamUnreconciled(RuntimeError):
    """A reconcile (offense close, or `sigil eval-grant reconcile`) could not confirm the seam for one or more
    publications: they could be neither re-published from the spine nor withdrawn, or their revoke never reached
    the spine, so they may still authorize. ``failed`` names them; ``alarm_recorded`` says whether the durable alarm
    `vigil doctor` reports was written."""

    def __init__(self, message: str, *, failed=(), alarm_recorded: bool = False):
        super().__init__(message)
        self.failed = list(failed)
        self.alarm_recorded = bool(alarm_recorded)


class EvalCapabilityGrantMissing(RuntimeError):
    """No verified EvalCapabilityGrant covers this engagement/target at this time — no gate veto may be
    lifted. Raised fail-closed; must not be silently caught."""


@dataclass(frozen=True)
class EvalCapabilityGrantState:
    granted: bool
    reason: str
    engagement_slug: str = ""
    target: str = ""
    evaluator_pubkey: str = ""
    max_covered_actions: int = 0
    allowed_gate_overrides: tuple = ()
    issued_anchor: float = 0.0


def _domain_tag() -> bytes:
    from vigil_core.spine_domains import DOMAIN_TAGS
    return DOMAIN_TAGS[_DOMAIN_KEY]


def _canon(core: dict) -> bytes:
    m = canonical_json(core)
    return bytes(m) if isinstance(m, (bytes, bytearray)) else str(m).encode("utf-8")


def _normalize_overrides(overrides) -> list:
    """The canonical, de-duplicated, SORTED override token list. A sorted list canonicalizes byte-identically
    on both planes and makes the signed set order-independent (adding/reordering tokens changes the bytes)."""
    if isinstance(overrides, str):
        items = [overrides]
    else:
        try:
            items = list(overrides or [])
        except TypeError:
            items = []
    return sorted({str(x) for x in items})


def build_core(
    *, engagement_slug: str, target: str, allowed_gate_overrides, issued_anchor: float,
    max_covered_actions: int, evaluator_pubkey: str, state: str = "granted",
) -> dict:
    """The exact authenticated CORE the OWNER signs and the EVALUATOR counter-signs (FIX B — the evaluator
    PoP is a FRESH signature over THIS dict, binding ``allowed_gate_overrides`` AND ``max_covered_actions``).

    CLOSED ENUM: validates every ``allowed_gate_overrides`` token is a member of :data:`ALLOWED_OVERRIDES`
    and RAISES ``ValueError`` on ANY other token — BEFORE :meth:`attest` performs any spine write (mirrors the
    eval-offense ``allow_destructive``-False discipline). This is the structural guarantee a grant can NEVER
    name the never-liftable floors (egress / destruction quorum / GET-only write) — they are not enum members.
    Floats / ints are coerced so sign and verify canonicalize byte-identically."""
    tokens = _normalize_overrides(allowed_gate_overrides)
    bad = [t for t in tokens if t not in ALLOWED_OVERRIDES]
    if bad:
        raise ValueError(
            f"eval-capability-grant refuses override token(s) {bad!r}: a grant may lift ONLY "
            f"{sorted(ALLOWED_OVERRIDES)} — the never-liftable floors (egress, m-of-n destruction quorum, "
            f"GET-only write baseline) are structurally separate conjuncts the grant cannot feed")
    return {
        "signal": SIGNAL,
        "state": state,
        "engagement_slug": str(engagement_slug),
        "target": str(target),
        "allowed_gate_overrides": tokens,
        "issued_anchor": float(issued_anchor),
        "max_covered_actions": int(max_covered_actions),
        "evaluator_pubkey": str(evaluator_pubkey),
    }


def pop_signing_bytes(core: dict) -> bytes:
    """The exact bytes the EVALUATOR signs for the proof-of-possession: the fresh ``eval-capability-grant``
    domain tag followed by the canonical JSON of the SAME core the owner signs. Domain separation means this
    signature can never verify under any other purpose; binding the whole core means the evaluator attests to
    exactly this engagement / target / override-set / budget, not a re-aimed copy (FIX B)."""
    return _domain_tag() + _canon({k: core.get(k) for k in _CORE})


def sign_evaluator_pop(core: dict, evaluator_private_key_b64: str) -> str:
    """The evaluator's FRESH PoP signature over :func:`pop_signing_bytes` — produced with the evaluator's OWN
    private key (never the owner's, and NEVER reused from the covering attestation's stored evaluator_sig)."""
    from ..reuse import sign
    return sign(evaluator_private_key_b64, pop_signing_bytes(core))


def _verify_pop(core: dict, evaluator_sig) -> bool:
    """True iff ``evaluator_sig`` is a valid FRESH PoP by ``core['evaluator_pubkey']`` over the domain-tagged
    grant core. Fail-closed (never raises out of a fold)."""
    pk = core.get("evaluator_pubkey")
    if not pk or not isinstance(pk, str):
        return False
    if not evaluator_sig or not isinstance(evaluator_sig, str):
        return False
    try:
        return verify_one(pk, pop_signing_bytes(core), evaluator_sig)
    except (IntegrityError, TypeError, ValueError):   # ValueError: a core that cannot be UTF-8 canonicalised
        return False


class EvalCapabilityGrant:
    """Owner-signed, engagement-/target-bound, evaluator-countersigned gate-override grant, on the spine.
    Construction mirrors :class:`EvalOffenseAttestation`: the owner signing key and trusted pubkey default to
    the persisted owner identity."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner transitions (both A0/auto so they are never themselves offense-gated) -------------------

    def attest(
        self, *, engagement_slug: str, target: str, allowed_gate_overrides, evaluator: str,
        evaluator_pubkey: str, evaluator_pop: str, max_covered_actions: int, issued_anchor: float,
        charter_hash: Optional[str] = None, now: float, environment: str = "live",
        by: str = "owner", reason: str = "",
    ) -> int:
        """Owner-sign an EvalCapabilityGrant binding exactly ``(engagement_slug, target,
        allowed_gate_overrides, max_covered_actions)``, anti-replay-bound by a strictly-increasing
        ``issued_anchor``.

        HARD PRECONDITION: a COVERING, verified EvalOffenseAttestation must already cover this engagement at
        ``now`` — a grant never widens past the arming precondition. Refused before any spine write otherwise.

        TWO-PARTY (FIX B): the ADDITIVE evaluator PoP is a FRESH signature over THIS grant's core (NOT reused
        from the attestation), verified here against the evaluator's OWNER-ENROLLED ``Account.user_pubkey``,
        which is ENFORCED DISTINCT from the owner key (a self-grant is refused before any spine write). Only
        the owner key produces a signature the fold will honour; the evaluator PoP alone grants nothing."""
        if self.owner_key is None:
            raise ValueError("attest requires the owner signing key")
        if not engagement_slug or not target:
            raise ValueError("attest requires engagement_slug and target to bind to")
        if not evaluator or not evaluator_pubkey:
            raise ValueError("attest requires the evaluator username and its enrolled pubkey")
        tokens = _normalize_overrides(allowed_gate_overrides)
        if not tokens:
            raise ValueError("attest requires at least one allowed_gate_override to grant")
        # CLOSED ENUM is re-validated in build_core below (raises before any spine write on a bad token).

        # HARD PRECONDITION: a verified EvalOffenseAttestation must already cover this engagement. The grant
        # rides strictly inside that envelope — it cannot admit what the arming precondition has not.
        from .eval_offense_attestation import EvalOffenseAttestation
        att = EvalOffenseAttestation(self.store, owner_key=self.owner_key,
                                     trusted_pubkey=self.trusted_pubkey)
        att_st = att.state(engagement_slug=engagement_slug, charter_hash=charter_hash, now=now,
                           environment=environment)
        if not att_st.attested:
            raise ValueError(
                f"refusing to mint an eval-capability-grant for engagement {engagement_slug!r}: no verified "
                f"covering EvalOffenseAttestation at this time ({att_st.reason}). The grant may only ride "
                f"inside a sanctioned arming envelope.")

        # TWO-PARTY DISTINCTNESS: the evaluator MUST be a DISTINCT identity from the owner. Refuse — BEFORE any
        # spine write — a self-grant whose evaluator_pubkey is the owner's own signing/pinned key (the offense
        # verifier refuses the identical shape independently, so the control holds at BOTH mint and arm).
        _owner_pub = getattr(self.owner_key, "public_key_b64", None)
        if str(evaluator_pubkey) in {k for k in (_owner_pub, self.trusted_pubkey) if k}:
            raise ValueError(
                "evaluator must be DISTINCT from the owner — refusing to mint a self-grant "
                "(evaluator_pubkey equals the owner key; the two-party control requires an independent, "
                "owner-enrolled evaluator identity, never the owner's own key)")
        from .accounts import AccountsRegistry
        try:
            acct = AccountsRegistry(self.store).account(evaluator)
        except Exception:  # noqa: BLE001 — a hostile/corrupt spine must never crash the ceremony → fail-closed
            acct = None
        if acct is None or not acct.user_pubkey:
            raise ValueError(
                f"no owner-bound cryptographic identity for evaluator {evaluator!r} — the owner must enroll "
                f"the evaluator's key (enroll_pubkey) before it can co-sign an eval-capability-grant")
        if acct.user_pubkey != str(evaluator_pubkey):
            raise ValueError(
                f"evaluator_pubkey does not match the enrolled key for {evaluator!r} (the evaluator PoP must "
                f"bind the DISTINCT enrolled identity, not an arbitrary key)")

        core = build_core(
            engagement_slug=engagement_slug, target=target, allowed_gate_overrides=tokens,
            issued_anchor=issued_anchor, max_covered_actions=max_covered_actions,
            evaluator_pubkey=str(evaluator_pubkey), state="granted",
        )
        if not _verify_pop(core, evaluator_pop):
            raise ValueError(
                "the evaluator proof-of-possession is invalid for this exact grant (it must be the enrolled "
                "evaluator's FRESH signature over the domain-tagged grant core — never the attestation's)")
        payload = {
            **signed_payload(core, self.owner_key),
            "evaluator_sig": str(evaluator_pop), "evaluator": str(evaluator),
            "by": by, "reason": reason, "tier": "A0", "decision": "auto",
        }
        seq = self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        self._publish(str(engagement_slug))
        return seq

    def revoke(self, *, engagement_slug: str, by: str = "owner", reason: str = "") -> int:
        """Revoke every grant for ``engagement_slug`` — the SAFE direction (honoured whoever signs it, like
        the eval-offense revoke). Carries a FIXED ``issued_anchor`` of 0.0 (a replayed revoke merely
        re-revokes). After a revoke, every gate enforces again until a fresh owner+evaluator grant lands."""
        if not engagement_slug:
            raise ValueError("revoke requires the engagement_slug to un-grant")
        core = build_core(
            engagement_slug=engagement_slug, target="", allowed_gate_overrides=[], issued_anchor=0.0,
            max_covered_actions=0, evaluator_pubkey="", state="revoked",
        )
        payload = {
            **signed_payload(core, self.owner_key),
            "by": by, "reason": reason, "tier": "A0", "decision": "auto",
        }
        slug = str(engagement_slug)
        # Un-grant the offense plane BEFORE the spine append and again before waiting for the publish lock (always
        # safe): a revoke killed after its append, or while it waits for the lock, has already raised the floor and
        # removed the stale publication.
        self._retract(slug, ahead=True)
        seq = self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        self._retract(slug)
        try:
            self._publish(slug)
        except Exception:
            if self._seam_path(slug) is not None:
                raise_close_alarm(f"a revoke of eval-capability grant {slug!r} could not be confirmed on the seam",
                                  cause="seam_unreconciled", failed=[f"grant:{slug}"])
            raise
        return seq

    def _append_revoke(self, slug: str, *, by: str, reason: str) -> int:
        core = build_core(
            engagement_slug=slug, target="", allowed_gate_overrides=[], issued_anchor=0.0,
            max_covered_actions=0, evaluator_pubkey="", state="revoked",
        )
        payload = {**signed_payload(core, self.owner_key), "by": by, "reason": reason, "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _retract(self, slug: str, *, ahead: bool = False) -> bool:
        """Raise the floor and remove a publication sealed below it, without the publish lock. ``ahead`` is the
        pre-append step: the floor goes one above the next seq, since the last seal can equal it."""
        bump = 1 if ahead else 0
        return retract_for_revoke(lambda: self._seam_path(slug), what=f"eval-capability-grant {slug!r}",
                                  floor_fn=lambda: self._raise_floor(slug, self.store.next_seq + bump))

    def structurally_live(self, *, engagement_slug: str) -> bool:
        """A granted record after the last revoke, signature unchecked (see ``seam_publish``)."""
        return granted_after_last_revoke(self.store, signal=SIGNAL, engagement_slug=engagement_slug)

    # -- the fail-closed fold (NEVER cached) -----------------------------------------------------------

    def state(self, *, engagement_slug: str, target: Optional[str] = None, now: float) -> EvalCapabilityGrantState:
        """Fold the spine to the grant state for ``engagement_slug`` (optionally constrained to a specific
        ``target``). UNGRANTED unless the latest-winning event is an owner-signed, evaluator-countersigned
        grant bound to this engagement (+ target). Any revoke (even unsigned) un-grants it. Succession-aware;
        anti-replay via the monotonic ``issued_anchor`` high-water. NEVER cached."""
        granted = False
        reason = "default-ungranted: no owner-signed eval-capability-grant on the spine"
        ev = ""
        tgt = ""
        mca = 0
        overrides: tuple = ()
        anch = 0.0
        max_issued = float("-inf")
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        for record in self.store.iter_records():
            payload = record.payload if isinstance(record.payload, dict) else {}
            if payload.get("signal") != SIGNAL:
                continue
            if payload.get("engagement_slug") != engagement_slug:
                continue
            st = payload.get("state")
            if st == "revoked":
                granted, reason, ev, tgt, mca, overrides, anch = (
                    False, "revoked by a governance event", "", "", 0, (), 0.0)
            elif st == "granted":
                if target is not None and payload.get("target") != target:
                    continue
                if not verify_signed(payload, _CORE, resolver.at(record.seq)):
                    continue
                if payload.get("evaluator_pubkey") in {payload.get("pubkey"), self.trusted_pubkey}:
                    continue  # self-grant: the evaluator is the owner key — not an independent co-signer
                core = {k: payload.get(k) for k in _CORE}
                if not _verify_pop(core, payload.get("evaluator_sig")):
                    continue
                toks = _normalize_overrides(payload.get("allowed_gate_overrides"))
                if any(t not in ALLOWED_OVERRIDES for t in toks):
                    continue  # a record carrying a non-enum token was written outside the ceremony — no effect
                issued = as_issued_at(payload.get("issued_anchor"))
                if issued <= max_issued:
                    continue  # REPLAY / stale re-append
                max_issued = issued
                granted = True
                reason = "owner-signed + evaluator-PoP granted"
                ev = str(payload.get("evaluator_pubkey") or "")
                tgt = str(payload.get("target") or "")
                try:
                    mca = int(payload.get("max_covered_actions") or 0)
                except (TypeError, ValueError):
                    mca = 0
                overrides = tuple(toks)
                anch = issued
        return EvalCapabilityGrantState(
            granted=granted, reason=reason,
            engagement_slug=engagement_slug if granted else "",
            target=tgt if granted else "",
            evaluator_pubkey=ev if granted else "",
            max_covered_actions=mca if granted else 0,
            allowed_gate_overrides=overrides if granted else (),
            issued_anchor=anch if granted else 0.0,
        )

    def is_granted(self, *, engagement_slug: str, target: Optional[str] = None, now: float) -> bool:
        return self.state(engagement_slug=engagement_slug, target=target, now=now).granted

    def granted_targets(self, *, engagement_slug: str, now: float = 0.0) -> list:
        """Every target a grant for ``engagement_slug`` currently covers. Each target is folded on its own, with
        its own anti-replay high-water, exactly as the offense verifier folds the action's target; the
        ``target=None`` fold shares ONE high-water across targets, so it can call a slug ungranted while a
        per-target grant still authorizes on the offense plane. Revoke decisions and ``status`` use this."""
        targets: list = []
        for record in self.store.iter_records():
            p = record.payload if isinstance(record.payload, dict) else {}
            if (p.get("signal") == SIGNAL and p.get("engagement_slug") == engagement_slug
                    and p.get("state") == "granted" and p.get("target") not in targets):
                targets.append(p.get("target"))
        return [t for t in targets if self.state(engagement_slug=engagement_slug, target=t, now=now).granted]

    def is_granted_any_target(self, *, engagement_slug: str, now: float = 0.0) -> bool:
        return bool(self.granted_targets(engagement_slug=engagement_slug, now=now))

    # -- seam publication (so the OFFENSE plane can verify the public signed material) -----------------

    def _base_dir(self) -> str:
        return os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"

    def _seam_path(self, engagement_slug: str) -> Optional[Path]:
        from vigil_integration.live.eval_capability_grant import eval_capability_grant_path
        return eval_capability_grant_path(self._base_dir(), engagement_slug)

    def _raise_floor(self, engagement_slug: str, seq: Optional[int] = None) -> int:
        """Raise the seam-directory rollback floor for ``engagement_slug`` to ``seq`` (default: the spine's next
        seq, above every publication already sealed) and return it. Raises on failure."""
        from vigil_integration.live.eval_capability_grant import advance_publication_floor
        floor = self.store.next_seq if seq is None else int(seq)
        advance_publication_floor(self._base_dir(), engagement_slug, floor)
        return floor

    def _published_slugs(self) -> list:
        """The engagement slugs that have a readable publication on the seam (raises OSError when the directory
        exists but cannot be listed)."""
        from vigil_integration.live.eval_capability_grant import eval_capability_grants_root
        return published_slugs(eval_capability_grants_root(self._base_dir()), self._seam_path)

    def _publish(self, engagement_slug: str) -> None:
        """Mirror every eval-capability-grant record for ``engagement_slug`` (grants AND revokes) to the
        shared seam, plus an OWNER SEAL over the WHOLE ordered record list + a monotonic publish seq (so an
        off-seam DROP/REORDER/ROLLBACK of the revoke cannot re-arm a revoked grant on the keyless offense
        plane). FAIL-CLOSED on every failure (``seam_publish``): a record that cannot be canonicalised is published
        as an unsigned revoke placeholder, and if the publish fails the previous publication is WITHDRAWN, so the
        offense plane falls back to default-ungranted, never a stale list a revoke never reached. Once withdrawn,
        an OSError / ValueError is absorbed (the spine record stands; the next publish re-sends the full list);
        anything else, or a publication that could not be withdrawn, re-raises. The owner key signs ONLY here in
        SIGIL (FATAL-2)."""
        with contextlib.ExitStack() as held:   # the lock is held through any withdrawal
            try:
                held.enter_context(publish_lock(self.store))   # one publish at a time
                records = []
                tip = -1                          # the snapshot's last seq (another process may have appended)
                for record in self.store.iter_records():
                    rseq = getattr(record, "seq", None)
                    if isinstance(rseq, int):
                        tip = max(tip, rseq)
                    p = record.payload if isinstance(record.payload, dict) else {}
                    if p.get("signal") == SIGNAL and p.get("engagement_slug") == engagement_slug:
                        records.append(dict(p))
                records = encodable_or_revoke(records, signal=SIGNAL, engagement_slug=engagement_slug)
                from vigil_integration.live.eval_capability_grant import (
                    build_seal,
                    write_eval_capability_grants,
                )
                seal = None
                if self.owner_key is not None:
                    from ..reuse import sign
                    seq = getattr(self.store, "next_seq", None)
                    if not isinstance(seq, int):
                        seq = len(records)
                    seq = max(seq, tip + 1)       # never below the newest record this publish has seen
                    seal = build_seal(
                        engagement_slug, seq, records,
                        sign_fn=lambda b: sign(self.owner_key.private_key_b64, b),
                        pubkey=self.owner_key.public_key_b64,
                    )
                write_eval_capability_grants(self._base_dir(), engagement_slug, records, seal=seal)
                if seal is not None:
                    # Every superseded publication (an older seal seq) is refused from now on, not only once the
                    # offense plane happens to read this one.
                    self._raise_floor(engagement_slug, seal["seq"])
            except Exception as e:
                withdrawn = withdraw_publication(lambda: self._seam_path(engagement_slug),
                                                 what=f"eval-capability-grant {engagement_slug!r}", cause=e,
                                                 floor_fn=lambda: self._raise_floor(engagement_slug))
                if not withdrawn or not isinstance(e, (OSError, ValueError)):
                    raise   # never report success while a stale publication may still be honoured


def revoke_grants_on_close(store, *, owner_key=None, trusted_pubkey: Optional[str] = None,
                           by: str = "owner", reason: str = "offense-gate/engagement close") -> list:
    """FIX C1: on an offense close, revoke EVERY eval-capability grant that is live on the spine and confirm the
    whole eval seam against the spine (:func:`reconcile_eval_seam` with ``revoke_live_grants=True``). Returns the
    revoked engagement slugs; raises :class:`EvalGrantSeamUnreconciled` when a publication could not be confirmed
    (the durable alarm names it). With NO grant ever published this is a NO-OP (byte-identical to today)."""
    return reconcile_eval_seam(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey, revoke_live_grants=True,
                               by=by, reason=reason)["revoked"]


def reconcile_eval_seam(store, *, owner_key=None, trusted_pubkey: Optional[str] = None,
                        revoke_live_grants: bool, by: str = "owner",
                        reason: str = "offense-gate/engagement close") -> dict:
    """Make the eval seam say what the spine says, and confirm it. With ``revoke_live_grants`` (an offense close)
    every grant that is live on the spine is revoked first; without it (`sigil eval-grant reconcile`) nothing is
    revoked. In order:

    1. every live grant's revoke is appended and its publication retracted (floor raised, stale file removed)
       BEFORE any publish waits for the lock, so a close killed mid-way has already un-granted every one;
    2. every grant that was revoked here, has a publication, or is named by the alarm is re-published from the
       spine (a failed publish withdraws, floor first). A grant whose revoke could not be appended is withdrawn
       directly and stays named: the spine still grants it, so its next publish would re-arm it;
    3. every other grant on the spine that is not live gets its floor raised (a slug whose earlier floor raise
       failed, with no file left to re-publish);
    4. every published or alarm-named eval-offense attestation is re-published from the spine.

    The alarm is cleared only when every name was confirmed; otherwise it names exactly what is still unconfirmed
    and this raises :class:`EvalGrantSeamUnreconciled`. Liveness is structural (any grant record after the last
    revoke, signature unchecked), so a key resolver that rejects every signature cannot make a grant look revoked.
    Returns ``{"revoked": [...], "republished": [...]}``."""
    from .seam_publish import IN_PROGRESS, read_close_alarm, settle_close_alarm
    prior = read_close_alarm() or {}
    prior_names = {str(n) for n in prior.get("failed") or [] if isinstance(n, str)}
    try:
        from .eval_offense_attestation import SIGNAL as ATT_SIGNAL
        from .eval_offense_attestation import EvalOffenseAttestation
        grant = EvalCapabilityGrant(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
        att = EvalOffenseAttestation(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    except Exception as e:
        rec = raise_close_alarm(f"the eval seam reconcile could not start ({type(e).__name__})",
                                cause="seam_unreconciled", failed=["(reconcile did not run)"])
        raise EvalGrantSeamUnreconciled("the eval seam reconcile could not start", failed=["(reconcile did not run)"],
                                        alarm_recorded=rec) from e
    try:
        g_slugs: list = []
        a_slugs: list = []
        for record in store.iter_records():
            p = record.payload if isinstance(record.payload, dict) else {}
            slug = p.get("engagement_slug")
            if not slug or not isinstance(slug, str):
                continue
            if p.get("signal") == SIGNAL and slug not in g_slugs:
                g_slugs.append(slug)
            elif p.get("signal") == ATT_SIGNAL and slug not in a_slugs:
                a_slugs.append(slug)
        live = {s for s in g_slugs if grant.structurally_live(engagement_slug=s)}
    except Exception as e:
        not_withdrawn = _withdraw_every_published_grant(grant, by=by, reason=reason, cause=e)
        rec = raise_close_alarm(f"the eval seam reconcile could not read the spine ({type(e).__name__})",
                                cause="seam_unreconciled" if not_withdrawn else "spine_unreadable",
                                failed=not_withdrawn)
        raise EvalGrantSeamUnreconciled("the eval seam reconcile could not read the spine", failed=not_withdrawn,
                                        alarm_recorded=rec) from e
    failed: dict = {}
    try:
        pub_g = set(grant._published_slugs())
    except OSError as e:
        pub_g = set()
        failed["(grant seam directory unreadable)"] = type(e).__name__
    try:
        pub_a = set(att._published_slugs())
    except OSError as e:
        pub_a = set()
        failed["(attestation seam directory unreadable)"] = type(e).__name__
    alarm_g = {n[len("grant:"):] for n in prior_names if n.startswith("grant:")}
    alarm_a = {n[len("attestation:"):] for n in prior_names if n.startswith("attestation:")}
    to_revoke = sorted(live) if revoke_live_grants else []
    work = bool(to_revoke or pub_g or pub_a or prior_names)
    if work:
        raise_close_alarm("an eval seam reconcile is in progress (a reconcile that stops here leaves this alarm)",
                          cause="in_progress", failed=[IN_PROGRESS])
    # 1) every revoke appended and retracted before any lock wait
    revoked: list = []
    not_recorded: set = set()
    for s in to_revoke:
        if grant._seam_path(s) is None:
            continue                       # the offense plane cannot read this slug either
        grant._retract(s, ahead=True)
        try:
            grant._append_revoke(s, by=by, reason=reason)
        except Exception as e:  # noqa: BLE001 - handled in step 2
            not_recorded.add(s)
            failed[f"grant:{s}"] = f"revoke not recorded on the spine ({type(e).__name__})"
            continue
        grant._retract(s)
        revoked.append(s)
    # 2) re-publish (or, for an unrecorded revoke, withdraw) every grant revoked here, published, or alarm-named
    republished: list = []
    for s in sorted(set(to_revoke) | pub_g | alarm_g):
        if grant._seam_path(s) is None:
            continue
        if s in not_recorded or (not revoke_live_grants and s in alarm_g and s in live):
            # The spine still grants it although a revoke was attempted (its record never landed): re-publishing
            # would re-arm what the owner revoked. Keep it withdrawn and named until a revoke reaches the spine.
            failed.setdefault(f"grant:{s}", "a revoke of it never reached the spine; revoke it again "
                                            "(`sigil eval-grant revoke`)")
            if not _withdraw_above(grant, s, what=f"eval-capability-grant {s!r}"):
                failed[f"grant:{s}"] += "; its publication could NOT be withdrawn"
            continue
        try:
            grant._publish(s)
            republished.append(s)
        except Exception as e:  # noqa: BLE001
            failed[f"grant:{s}"] = f"neither re-published nor withdrawn ({type(e).__name__})"
    # 3) a floor for every other grant on the spine that is not live
    handled = set(to_revoke) | pub_g | alarm_g
    for s in g_slugs:
        if s in handled or s in live or grant._seam_path(s) is None:
            continue
        try:
            grant._raise_floor(s)
        except Exception as e:  # noqa: BLE001
            failed[f"grant:{s}"] = f"rollback floor not raised ({type(e).__name__})"
    # 4) attestations: re-publish what is published or named
    for s in sorted(pub_a | alarm_a):
        if att._seam_path(s) is None:
            continue
        try:
            att._publish(s)
        except Exception as e:  # noqa: BLE001
            failed[f"attestation:{s}"] = f"neither re-published nor withdrawn ({type(e).__name__})"
    if not work and not failed:
        return {"revoked": revoked, "republished": republished}
    checked = prior_names | {f"grant:{s}" for s in handled} | {f"attestation:{s}" for s in pub_a | alarm_a}
    checked |= {"(reconcile did not run)", "(grant seam directory unreadable)", "(attestation seam directory unreadable)"}
    detail = (f"{len(failed)} eval seam publication(s) could not be confirmed: "
              + "; ".join(f"{k}: {v}" for k, v in sorted(failed.items()))[:400])
    rec = settle_close_alarm(failed, checked=checked, detail=detail)
    if failed:
        raise EvalGrantSeamUnreconciled(f"the eval seam could not be confirmed for {sorted(failed)}",
                                        failed=sorted(failed), alarm_recorded=rec)
    return {"revoked": revoked, "republished": republished}


def _withdraw_above(grant: "EvalCapabilityGrant", slug: str, *, what: str,
                    cause: Optional[BaseException] = None) -> bool:
    """Withdraw ``slug``'s publication with its floor raised one above the next seq (above every seal so far)."""
    def _path() -> Optional[Path]:
        return grant._seam_path(slug)

    def _floor() -> int:
        return grant._raise_floor(slug, grant.store.next_seq + 1)
    return withdraw_publication(_path, what=what, cause=cause, floor_fn=_floor)


def _withdraw_every_published_grant(grant: "EvalCapabilityGrant", *, by: str, reason: str,
                                    cause: BaseException) -> list:
    """Fail-closed fallback when the spine cannot be read: for every grant that has a published seam file, append a
    revoke (best-effort) and withdraw the publication (floor first, one above the next seq). Never raises (the
    caller re-raises ``cause``); returns the alarm names of what could NOT be withdrawn."""
    import logging

    log = logging.getLogger(__name__)
    try:
        published = grant._published_slugs()
    except OSError:
        log.critical("eval seam: the eval-capability-grant seam cannot be listed, so the published grants could not "
                     "be withdrawn", exc_info=True)
        return ["(grant seam directory unreadable)"]
    failed: list = []
    for slug in published:
        try:
            grant._append_revoke(slug, by=by, reason=f"{reason} (spine unreadable: fail-closed)")
        except Exception:  # noqa: BLE001 - the withdrawal below is the guarantee
            pass
        if not _withdraw_above(grant, slug, what=f"eval-capability-grant {slug!r} (spine unreadable)", cause=cause):
            failed.append(f"grant:{slug}")
    return failed


def assert_eval_capability_granted(
    store, *, engagement_slug: str, target: Optional[str] = None, now: float,
    owner_key=None, trusted_pubkey: Optional[str] = None,
) -> EvalCapabilityGrantState:
    """Fail-closed assertion: raise :class:`EvalCapabilityGrantMissing` unless a verified grant covers this
    engagement (and, when given, this target) at ``now``. Returns the granted state on success."""
    g = EvalCapabilityGrant(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    st = g.state(engagement_slug=engagement_slug, target=target, now=now)
    if not st.granted:
        raise EvalCapabilityGrantMissing(
            f"no verified eval-capability-grant for engagement {engagement_slug!r}: {st.reason}")
    return st
