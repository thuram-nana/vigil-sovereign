#!/usr/bin/env python3
"""Sovereign-side FAILOVER INTERLOCK — the anti-rollback gate a PASSIVE runs before it is promoted.

Claim 6, Piece B (B-S4). See docs/architecture/HA-PROFILE.md §3.

The sovereign spine is SINGLE-WRITER. HA of the writer is active-PASSIVE failover, and the hazard on
promotion is a passive coming up on an UNTRUSTED MIRROR — a mirror whose head has been rolled back
(STALE), forged (a head not signed by the owner), or forked (a different owner-signed history at the
same height). Promoting any of those would roll the durable anti-rollback floor BACKWARDS or activate a
divergent history — the "cold verifier off an untrusted mirror" gap documented in
``apps/sigil/sigil/spine/floor.py`` (HONEST LIMIT). This guard CLOSES that gap (up to the all-keys
limit below): it AUTHENTICATES the local head's OWNER signature and BINDS it to an OFF-BOX-retained,
witness-signed checkpoint before it will activate — head authenticated + fork-bound + extension-proven —
and REFUSES (fail-closed, exit 2) otherwise.

What it checks (fail-closed at every step):
  1. the off-box witnessed-checkpoint envelope parses and is for THIS scope;
  2. the envelope is signed by a TRUSTED WITNESS QUORUM — a forged/unsigned "checkpoint" is not a floor;
  3. the LOCAL HEAD is AUTHENTICATED, running the SAME owner-signature authentication the live spine runs
     before ``check_floor`` — ``checkpoint.classify_head`` -> ``reuse.verify_head``: the owner Ed25519
     signature at the owner threshold AND binding of ``head_hash``/``last_seq``/``entry_count`` to the
     passive's actual live chain. An unsigned, attacker-key-signed, or count-inflated head is REFUSED
     (a self-declared scalar is never trusted before this). This is the step the earlier build was
     MISSING — it applied (4)/(5) to an UNAUTHENTICATED head;
  4. ``check_floor(local_head, floor_of_the_witnessed_checkpoint)`` passes — no monotonic quantity rolls
     back below the witnessed anchor — and the head's ``entry_count``/``last_seq`` are >= the witnessed
     checkpoint's (belt-and-braces on the exact witnessed height); AND
  5. the authenticated head is TIED to the witnessed HISTORY, not merely at/above its count: at EQUAL
     height ``local_head.head_hash`` MUST equal the witnessed ``head_hash`` (a different one is an
     owner-key EQUIVOCATION / same-height fork -> refuse); when GROWN, ``witness.verify_against_external``
     proves an append-only EXTENSION (the current record at the retained ``last_seq`` carries the retained
     ``head_hash``, so records ``0..retained`` are byte-identical — a real superset, not a divergent
     longer history) -> unprovable -> refuse.

HONEST LIMITS (do NOT overclaim):
  * TWO SEPARATE properties, do not conflate them. (a) The LOCAL HEAD's authenticity is CRYPTOGRAPHIC and
    holds regardless of witness independence — its owner signature is verified and it is bound to the
    witnessed head_hash / proven to extend it (steps 3 + 5). (b) The ANCHOR's strength is EXTERNAL
    RETENTION + witness independence, NOT this code: at the default owner-only, threshold-1 witness set
    the anchor is rollback DETECTION via retention, NOT independent split-view PREVENTION — the sole
    witness is the head signer itself. This guard LABELS that honestly ("retention-based DETECTION, NOT
    independence") and never prints "split-view-resistant" for a solo self-witness. Independent prevention
    needs >=2 independent witness keys at a strict majority, a DEPLOYMENT property code cannot verify (see
    ``witness.guarantee_label``).
  * IRREDUCIBLE LIMIT: an attacker who holds BOTH the owner key AND a witness quorum can mint a mutually
    consistent forged anchor+head; that all-keys-compromised case is NOT closed here (no code can). What
    IS now closed — for any adversary short of that — is the untrusted-mirror ROLLBACK (stale head), the
    FORGED head (attacker key or a self-declared count past the live chain), and the same-height / grown
    FORK: each is refused because the head is authenticated and bound to the retained witnessed history.

FATAL-2: this module is SOVEREIGN-SIDE. It may import ``sigil`` and ``vigil_core``/``vigil_integration``
(``vigil_integration.transparency`` is vigil_core-only). It MUST NOT be imported by any OFFENSE-plane
module — the offense plane never links the sovereign owner-key code path.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


def _bootstrap_sys_path() -> None:
    """Make the sovereign packages importable when this file is run STANDALONE
    (``python3 tools/ha/spine_failover_guard.py``). Idempotent + additive: if the packages already
    resolve (e.g. imported from within sigil, or PYTHONPATH is set), this changes nothing."""
    repo = Path(__file__).resolve().parents[2]          # tools/ha/<this> -> repo root
    for sub in ("apps/sigil", "integration", "packages/core/vigil_core", "gateway"):
        p = str(repo / sub)
        if p not in sys.path and (repo / sub).is_dir():
            sys.path.append(p)


_bootstrap_sys_path()

from sigil.spine.checkpoint import classify_head                 # noqa: E402
from sigil.spine.floor import Floor, check_floor, head_sig_hash  # noqa: E402
from sigil.spine import witness as W                             # noqa: E402
from vigil_integration.transparency import (                     # noqa: E402
    is_split_view_resistant,
    verify_witnessed,
)
from vigil_integration.witnessed_anchor import (                 # noqa: E402
    envelope_emitted_at,
    freshness_verdict,
)

_EXIT_ACTIVATE = 0
_EXIT_REFUSE = 2


@dataclass(frozen=True)
class PromotionVerdict:
    """The guard's decision. ``activate`` gates promotion; ``exit_code`` is the process exit
    (0 = safe to promote, 2 = REFUSE / fail-closed). ``independent`` is the HONEST independence flag —
    False for a solo/owner-only (threshold==1) self-witness."""
    activate: bool
    exit_code: int
    reason: str
    independent: bool = False
    guarantee: str = ""
    local_count: Optional[int] = None
    local_last_seq: Optional[int] = None
    witnessed_count: Optional[int] = None
    witnessed_last_seq: Optional[int] = None
    freshness: str = ""                       # W7-5: the anchor's freshness status (fresh/stale-warn/…)
    anchor_age_s: Optional[float] = None      # W7-5: age of the retained anchor at evaluation time (s)

    def lines(self) -> list[str]:
        head = ("PROMOTE: SAFE — " if self.activate else "REFUSE (fail-closed): ") + self.reason
        out = [head]
        if self.freshness:
            out.append(f"anchor freshness: {self.freshness}"
                       + ("" if self.anchor_age_s is None else f" (age {self.anchor_age_s:.0f}s)"))
        if self.guarantee:
            out.append(f"witness guarantee: {self.guarantee}")
        if not self.independent:
            # risk #13 honesty: a solo/owner-only witness is retention-based DETECTION, never independence.
            out.append("witness anchor: SOLO/owner-only (threshold==1) or sub-majority — this is "
                       "retention-based DETECTION, NOT independent split-view resistance. Add >=2 "
                       "independent witness keys at a strict majority for prevention (a deployment property).")
        return out

    def to_json(self) -> str:
        return json.dumps({
            "activate": self.activate, "exit_code": self.exit_code, "reason": self.reason,
            "independent": self.independent, "guarantee": self.guarantee,
            "freshness": self.freshness, "anchor_age_s": self.anchor_age_s,
            "local": {"entry_count": self.local_count, "last_seq": self.local_last_seq},
            "witnessed": {"entry_count": self.witnessed_count, "last_seq": self.witnessed_last_seq},
        }, sort_keys=True)


def evaluate_promotion(local_head: Any, witnessed_env: str, *, scope: str, trust_root,
                       owner_trust_root, entries, now: Optional[float] = None,
                       warn_after_s: Optional[int] = None,
                       refuse_after_s: Optional[int] = None) -> PromotionVerdict:
    """Pure decision function (no IO) — the testable core.

    ``local_head`` is the passive's restored/synced ``SignedChainHead`` (or None); ``entries`` is that
    passive's local live chain (``SpineStore.entries()``); ``witnessed_env`` is the off-box
    witnessed-checkpoint envelope JSON; ``trust_root`` is the WITNESS ``TrustRoot`` the envelope's
    signatures are verified against; ``owner_trust_root`` is the OWNER ``TrustRoot`` (owner-only,
    threshold 1 — the SAME anchor ``verify_checkpoint`` uses) the LOCAL head's signature is authenticated
    against.

    The local head is NEVER trusted on its self-declared scalar fields until it has been AUTHENTICATED:
    the guard runs the same owner-signature authentication the live spine runs before ``check_floor``
    (``classify_head`` -> ``verify_head``), then BINDS the head to the witnessed history (head_hash at
    equal height, a proven append-only extension when grown). This is what closes the untrusted-mirror
    forged/forked-head attacks — a stale/forged/forked mirror head is refused, not silently promoted."""
    if local_head is None:
        return PromotionVerdict(False, _EXIT_REFUSE,
                                "no local spine head on this passive — run `sigil sign` on the synced mirror first")

    # (1) parse + scope
    try:
        wc, wc_scope = W.load_witnessed(witnessed_env)
    except W.WitnessError as e:
        return PromotionVerdict(False, _EXIT_REFUSE, f"witnessed checkpoint unreadable (refuse): {e}")
    if wc_scope != scope:
        return PromotionVerdict(False, _EXIT_REFUSE,
                                f"witnessed checkpoint is for scope {wc_scope!r}, not this store's {scope!r}")

    # honest independence label (computed regardless of outcome, printed on every path)
    independent = bool(is_split_view_resistant(trust_root) and len(trust_root.authorizers) >= 2)
    guarantee = W.guarantee_label(trust_root)

    # (2) the anchor must ITSELF be witness-signed by a trusted quorum, else it is not a floor at all.
    try:
        signed_ok = verify_witnessed(wc, witness_trust_root=trust_root)
    except Exception as e:  # noqa: BLE001 — malformed sig/key material -> fail-closed, never a silent pass
        return PromotionVerdict(False, _EXIT_REFUSE,
                                f"witnessed checkpoint signature is malformed (refuse): {e}",
                                independent=independent, guarantee=guarantee)
    if not signed_ok:
        return PromotionVerdict(False, _EXIT_REFUSE,
                                "witnessed checkpoint is NOT signed by a trusted witness quorum "
                                "(forged/tampered anchor, or its witnesses are not in this store's roster)",
                                independent=independent, guarantee=guarantee)

    # (2b) W7-5 (#463) FRESHNESS: the anchor the whole HA interlock depends on must be RECENT. An anchor
    # older than the refusal bound (or un-dated, or future-dated past the skew tolerance) means the scheduled
    # off-box emitter has stopped and the rollback window is silently widening — REFUSE (fail-closed). Enforced
    # only when ``now`` is supplied (the CLI / standalone run() path always supplies it; a test that omits it
    # keeps the pre-W7-5 behaviour). ``emitted_at`` is UNSIGNED envelope metadata (see witness.dump_witnessed);
    # it is a freshness/operational-drift signal, distinct from the anchor's SIGNATURE (verified in step 2).
    fv = None
    if now is not None:
        fv = freshness_verdict(envelope_emitted_at(witnessed_env), now=now,
                               warn_after_s=warn_after_s, refuse_after_s=refuse_after_s)
        if fv.refuse:
            return PromotionVerdict(False, _EXIT_REFUSE,
                                    f"STALE ANCHOR — {fv.detail}",
                                    independent=independent, guarantee=guarantee,
                                    freshness=fv.status, anchor_age_s=fv.age_s)

    # (3) AUTHENTICATE THE LOCAL HEAD before trusting ANY of its self-declared scalar fields. This runs the
    # SAME owner-signature authentication the live spine runs before check_floor (checkpoint.classify_head ->
    # reuse.verify_head): it re-derives the head's signing bytes and checks the OWNER Ed25519 signature at
    # the owner threshold, AND binds head.head_hash / last_seq / entry_count to the passive's ACTUAL live
    # chain (`floor=None` — the WITNESSED-anchor comparison is done separately in (4)/(5), not here). An
    # unsigned head, an attacker-key-signed head, or one whose entry_count is inflated past the live chain
    # fails here -> REFUSE. Without this the guard applied the floor/scalar checks to an UNAUTHENTICATED
    # head, so a forged head (any self-declared count) sailed through — the forged-head attack.
    if entries is None:
        return PromotionVerdict(False, _EXIT_REFUSE,
                                "cannot authenticate the local head without its live spine chain (refuse)",
                                independent=independent, guarantee=guarantee)
    local_entries = list(entries)
    try:
        ok_auth, auth_msg = classify_head(local_head, local_entries, owner_trust_root, floor=None)
    except Exception as e:  # noqa: BLE001 — malformed sig/key material in the local head -> fail-closed refuse
        # Mirror the sibling anchor-signature handler above: a head whose signature/key bytes are malformed
        # (e.g. non-base64) makes verify_one raise; catch it and REFUSE with the documented exit code rather
        # than let it crash out as an uncaught traceback (exit 1) — so the "fail-closed, exit 2" claim holds
        # literally for this input subclass too.
        return PromotionVerdict(False, _EXIT_REFUSE,
                                f"local head signature/key material is malformed (refuse): {e}",
                                independent=independent, guarantee=guarantee)
    if not ok_auth:
        return PromotionVerdict(False, _EXIT_REFUSE,
                                f"local head is NOT authentically owner-signed (refuse): {auth_msg}",
                                independent=independent, guarantee=guarantee)

    cp = wc.checkpoint
    lc, ls = int(local_head.entry_count), int(local_head.last_seq)

    # (4) reuse the AUDITED monotonic anti-rollback logic to catch a head BELOW the witnessed height.
    # Synthesize a Floor from the witnessed checkpoint's committed height. A compact checkpoint does NOT
    # carry base_seq/base_count or the meta-chain head_sig_hash (pre-Piece-C), so we neutralize those guards
    # by construction:
    #   - base_seq/base_count = 0  -> head.base_* (>=0) always satisfies them (no false UN-PRUNE);
    #   - head_sig_hash = the LOCAL head's own -> the v2 meta-chain identity check is a no-op pass
    #     (we cannot derive meta-chain linkage from a checkpoint; the checkpoint commits HEIGHT, not linkage).
    # check_floor then reduces to exactly the sound quantities a checkpoint DOES commit: the ABSOLUTE,
    # prune-invariant entry_count and last_seq. NOTE: these fields are now AUTHENTICATED (owner-signed, (3)).
    witnessed_floor = Floor(scope=scope, entry_count=int(cp.entry_count), last_seq=int(cp.last_seq),
                            base_seq=0, base_count=0, head_sig_hash=head_sig_hash(local_head), updated_ts="")
    ok, msg = check_floor(local_head, witnessed_floor)
    if not ok:
        return PromotionVerdict(False, _EXIT_REFUSE,
                                f"ROLLBACK — local head is BELOW the witnessed checkpoint: {msg}",
                                independent=independent, guarantee=guarantee,
                                local_count=lc, local_last_seq=ls,
                                witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq))
    if lc < int(cp.entry_count) or ls < int(cp.last_seq):
        return PromotionVerdict(False, _EXIT_REFUSE,
                                f"ROLLBACK — local head (count {lc}, last_seq {ls}) is below the witnessed "
                                f"checkpoint (count {cp.entry_count}, last_seq {cp.last_seq})",
                                independent=independent, guarantee=guarantee,
                                local_count=lc, local_last_seq=ls,
                                witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq))

    # (5) At or above the witnessed height, a higher/equal COUNT alone is NOT enough — the authenticated head
    # must be TIED to the witnessed HISTORY, or a same-height fork / a divergent longer history would pass.
    if lc == int(cp.entry_count):
        # (5a) EQUAL HEIGHT: bind to the witnessed head_hash. (3) already tied the head's head_hash to the
        # passive's REAL chain tip; requiring it EQUAL the witnessed checkpoint's head_hash proves the local
        # history at this height IS the witnessed one (head_hash hash-chains the whole prefix). A different
        # head_hash at the same count is an owner-key EQUIVOCATION / same-height fork -> REFUSE.
        if str(local_head.head_hash) != str(cp.head_hash):
            return PromotionVerdict(False, _EXIT_REFUSE,
                                    f"SAME-HEIGHT FORK — local head at the witnessed height (count {lc}) carries "
                                    f"head_hash {str(local_head.head_hash)[:16]}… but the off-box witnessed "
                                    f"checkpoint commits {str(cp.head_hash)[:16]}… (owner-key equivocation / "
                                    f"divergent history) — refuse to promote a fork",
                                    independent=independent, guarantee=guarantee,
                                    local_count=lc, local_last_seq=ls,
                                    witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq))
        bind_note = "equals and is head_hash-bound to"
    else:
        # (5b) GROWN: the passive claims to be ABOVE the witnessed height. Prove it is a genuine append-only
        # EXTENSION of the witnessed checkpoint via the AUDITED verify_against_external: the current record at
        # the retained last_seq must carry the retained head_hash (records 0..retained are byte-identical), so
        # the passive is a real SUPERSET of the witnessed history, not a divergent longer one. Unprovable (or a
        # retained point below the live prune base, which needs the archive) -> REFUSE, never a silent pass.
        try:
            ok_ext, ext_msg = W.verify_against_external(witnessed_env, head=local_head, entries=local_entries,
                                                        scope=scope, trust_root=trust_root)
        except W.WitnessError as e:
            return PromotionVerdict(False, _EXIT_REFUSE,
                                    f"EXTENSION UNPROVEN — local head above the witnessed height could not be "
                                    f"verified as its append-only extension (refuse): {e}",
                                    independent=independent, guarantee=guarantee,
                                    local_count=lc, local_last_seq=ls,
                                    witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq))
        if not ok_ext:
            return PromotionVerdict(False, _EXIT_REFUSE,
                                    f"EXTENSION UNPROVEN — local head (count {lc}) does not provably extend the "
                                    f"off-box witnessed checkpoint (count {cp.entry_count}): {ext_msg}",
                                    independent=independent, guarantee=guarantee,
                                    local_count=lc, local_last_seq=ls,
                                    witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq))
        bind_note = "provably extends (append-only)"

    return PromotionVerdict(True, _EXIT_ACTIVATE,
                            f"local head (count {lc}, last_seq {ls}) is OWNER-AUTHENTICATED and {bind_note} the "
                            f"off-box witnessed checkpoint (count {cp.entry_count}, last_seq {cp.last_seq}); no "
                            f"rollback, no same-height fork — safe to promote this passive to ACTIVE",
                            independent=independent, guarantee=guarantee,
                            local_count=lc, local_last_seq=ls,
                            witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq),
                            freshness=(fv.status if fv is not None else ""),
                            anchor_age_s=(fv.age_s if fv is not None else None))


# --------------------------------------------------------------------------------------------- IO / CLI

def load_local_head(head_path: Optional[Path] = None):
    """Read the passive's local ``SignedChainHead`` from ``head_path`` (default: config.HEAD_PATH).
    Returns None if absent/unparseable (the guard then REFUSES — a passive with no head is not promotable)."""
    from sigil.config import HEAD_PATH
    from sigil.reuse import SignedChainHead
    p = Path(head_path) if head_path is not None else HEAD_PATH
    try:
        if not p.exists():
            return None
        return SignedChainHead.model_validate_json(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a corrupt/future-schema head is not a promotable head
        return None


def load_local_entries():
    """The passive's local live chain (``SpineStore.entries()``) — needed to AUTHENTICATE the local head
    (``classify_head`` binds the head to it) and to prove an append-only EXTENSION over the witnessed
    checkpoint. Returns [] on any read error: an unreadable store cannot authenticate a head, so the guard
    then fails head authentication and REFUSES (fail-closed)."""
    from sigil.spine.store import SpineStore
    try:
        return SpineStore().entries()
    except Exception:  # noqa: BLE001 — a corrupt/unreadable store is not a promotable passive -> refuse downstream
        return []


def _trust_root_from_config():
    """Build the WITNESS ``TrustRoot`` (from the owner-signed roster, or the default owner-only set) AND the
    OWNER ``TrustRoot`` the local head is authenticated against (owner-only, threshold 1 — the SAME anchor
    ``verify_checkpoint`` uses). Returns (scope, witness_trust_root, owner_trust_root). Raises SystemExit(2)
    if no owner key exists (no trust anchor -> refuse)."""
    from sigil import config
    from sigil.governor.identity import owner_pubkey
    pub = owner_pubkey()
    if not pub:
        print("REFUSE (fail-closed): no owner key / trust root on this host — cannot authenticate a "
              "witnessed checkpoint. Establish the owner key (`sigil sign`) on the synced mirror first.",
              file=sys.stderr)
        raise SystemExit(_EXIT_REFUSE)
    roster_path = config.SIGIL_HOME / "witness.trust.json"
    roster = W.load_roster(roster_path, owner_pub=pub, scope=config.SCOPE)
    tr = W.witness_trust_root(roster, owner_pub=pub, owner_key_id=config.OWNER_KEY_ID)
    # The OWNER trust root — owner-only at threshold 1 — the LOCAL head's Ed25519 signature is authenticated
    # against. Distinct from the witness quorum ``tr`` (which may include independent witnesses like a phone).
    owner_tr = W.witness_trust_root(None, owner_pub=pub, owner_key_id=config.OWNER_KEY_ID)
    return config.SCOPE, tr, owner_tr


def run(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="spine_failover_guard",
        description="Anti-rollback failover interlock: refuse to promote a PASSIVE whose local spine head "
                    "is below an off-box witnessed checkpoint (fail-closed, exit 2).")
    ap.add_argument("--witnessed", "--external", dest="witnessed", required=True,
                    help="the OFF-BOX retained witnessed-checkpoint envelope the passive must not roll back "
                         "below (- for stdin)")
    ap.add_argument("--head", default=None, help="path to the local head.json (default: config.HEAD_PATH)")
    ap.add_argument("--json", action="store_true", help="emit the verdict as JSON")
    args = ap.parse_args(argv)

    try:
        scope, tr, owner_tr = _trust_root_from_config()
    except W.WitnessError as e:
        print(f"REFUSE (fail-closed): witness roster error: {e}", file=sys.stderr)
        return _EXIT_REFUSE
    except SystemExit as e:
        return int(e.code or _EXIT_REFUSE)

    data = sys.stdin.read() if args.witnessed == "-" else Path(args.witnessed).read_text(encoding="utf-8")
    local_head = load_local_head(Path(args.head) if args.head else None)
    local_entries = load_local_entries()
    # W7-5: production enforces anchor FRESHNESS — pass the wall clock so a stale off-box anchor is refused.
    verdict = evaluate_promotion(local_head, data, scope=scope, trust_root=tr,
                                 owner_trust_root=owner_tr, entries=local_entries, now=time.time())

    if args.json:
        print(verdict.to_json())
    else:
        for line in verdict.lines():
            print(line, file=(sys.stdout if verdict.activate else sys.stderr))
    return verdict.exit_code


if __name__ == "__main__":
    raise SystemExit(run())
