#!/usr/bin/env python3
"""Sovereign-side FAILOVER INTERLOCK — the anti-rollback gate a PASSIVE runs before it is promoted.

Claim 6, Piece B (B-S4). See docs/architecture/HA-PROFILE.md §3.

The sovereign spine is SINGLE-WRITER. HA of the writer is active-PASSIVE failover, and the one real
hazard on promotion is a ROLLBACK: a passive that came up on a STALE mirror carries an older head, and
promoting it blindly would roll the durable anti-rollback floor BACKWARDS — the exact "cold verifier off
an untrusted mirror" gap documented in ``apps/sigil/sigil/spine/floor.py`` (HONEST LIMIT). This guard
closes that: it REFUSES to activate (fail-closed, exit 2) unless the local synced head is at or above an
OFF-BOX-retained, witness-signed checkpoint.

What it checks (fail-closed at every step):
  1. the off-box witnessed-checkpoint envelope parses and is for THIS scope;
  2. the envelope is signed by a TRUSTED WITNESS QUORUM — a forged/unsigned "checkpoint" is not a floor;
  3. ``check_floor(local_head, floor_of_the_witnessed_checkpoint)`` passes — no monotonic quantity rolls
     back below the witnessed anchor; AND
  4. the local head's ``entry_count`` AND ``last_seq`` are >= the witnessed checkpoint's (belt-and-braces
     on the exact witnessed height).

HONEST LIMITS (do NOT overclaim):
  * The anchor's strength is EXTERNAL RETENTION + witness independence, not this code. At the default
    owner-only, threshold-1 witness set this is rollback DETECTION via retention, NOT independent
    split-view prevention — the sole witness is the head signer itself. This guard LABELS that honestly
    ("retention-based DETECTION, NOT independence") and never prints "split-view-resistant" for a solo
    self-witness. Independent prevention needs >=2 independent witness keys at a strict majority, a
    DEPLOYMENT property code cannot verify (see ``witness.guarantee_label``).
  * A fully-dishonest producer who ALSO holds the witness key(s) can forge any checkpoint; that case is
    NOT closed here (it is the irreducible all-keys-compromised limit). This guard closes the STALE-MIRROR
    rollback (a passive that legitimately synced an old mirror), which is the failover hazard.

FATAL-2: this module is SOVEREIGN-SIDE. It may import ``sigil`` and ``vigil_core``/``vigil_integration``
(``vigil_integration.transparency`` is vigil_core-only). It MUST NOT be imported by any OFFENSE-plane
module — the offense plane never links the sovereign owner-key code path.
"""
from __future__ import annotations

import argparse
import json
import sys
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

from sigil.spine.floor import Floor, check_floor, head_sig_hash  # noqa: E402
from sigil.spine import witness as W                             # noqa: E402
from vigil_integration.transparency import (                     # noqa: E402
    is_split_view_resistant,
    verify_witnessed,
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

    def lines(self) -> list[str]:
        head = ("PROMOTE: SAFE — " if self.activate else "REFUSE (fail-closed): ") + self.reason
        out = [head]
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
            "local": {"entry_count": self.local_count, "last_seq": self.local_last_seq},
            "witnessed": {"entry_count": self.witnessed_count, "last_seq": self.witnessed_last_seq},
        }, sort_keys=True)


def evaluate_promotion(local_head: Any, witnessed_env: str, *, scope: str, trust_root) -> PromotionVerdict:
    """Pure decision function (no IO) — the testable core. ``local_head`` is the passive's restored/synced
    ``SignedChainHead`` (or None); ``witnessed_env`` is the off-box witnessed-checkpoint envelope JSON;
    ``trust_root`` is the witness ``TrustRoot`` the envelope's signatures are verified against."""
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

    cp = wc.checkpoint
    lc, ls = int(local_head.entry_count), int(local_head.last_seq)

    # (3) reuse the AUDITED monotonic anti-rollback logic. Synthesize a Floor from the witnessed
    # checkpoint's committed height. A compact checkpoint does NOT carry base_seq/base_count or the
    # meta-chain head_sig_hash (pre-Piece-C), so we neutralize those guards by construction:
    #   - base_seq/base_count = 0  -> head.base_* (>=0) always satisfies them (no false UN-PRUNE);
    #   - head_sig_hash = the LOCAL head's own -> the v2 meta-chain identity check is a no-op pass
    #     (we cannot derive meta-chain linkage from a checkpoint; the checkpoint commits HEIGHT, not linkage).
    # check_floor then reduces to exactly the sound quantities a checkpoint DOES commit: the ABSOLUTE,
    # prune-invariant entry_count and last_seq.
    witnessed_floor = Floor(scope=scope, entry_count=int(cp.entry_count), last_seq=int(cp.last_seq),
                            base_seq=0, base_count=0, head_sig_hash=head_sig_hash(local_head), updated_ts="")
    ok, msg = check_floor(local_head, witnessed_floor)
    if not ok:
        return PromotionVerdict(False, _EXIT_REFUSE,
                                f"ROLLBACK — local head is BELOW the witnessed checkpoint: {msg}",
                                independent=independent, guarantee=guarantee,
                                local_count=lc, local_last_seq=ls,
                                witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq))

    # (4) belt-and-braces explicit gate on the exact witnessed height.
    if lc < int(cp.entry_count) or ls < int(cp.last_seq):
        return PromotionVerdict(False, _EXIT_REFUSE,
                                f"ROLLBACK — local head (count {lc}, last_seq {ls}) is below the witnessed "
                                f"checkpoint (count {cp.entry_count}, last_seq {cp.last_seq})",
                                independent=independent, guarantee=guarantee,
                                local_count=lc, local_last_seq=ls,
                                witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq))

    return PromotionVerdict(True, _EXIT_ACTIVATE,
                            f"local head (count {lc}, last_seq {ls}) is at/above the off-box witnessed "
                            f"checkpoint (count {cp.entry_count}, last_seq {cp.last_seq}); no rollback — "
                            f"safe to promote this passive to ACTIVE",
                            independent=independent, guarantee=guarantee,
                            local_count=lc, local_last_seq=ls,
                            witnessed_count=int(cp.entry_count), witnessed_last_seq=int(cp.last_seq))


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


def _trust_root_from_config():
    """Build the witness ``TrustRoot`` from the owner-signed roster (or the default owner-only set).
    Returns (scope, trust_root). Raises SystemExit(2) if no owner key exists (no trust anchor -> refuse)."""
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
    return config.SCOPE, tr


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
        scope, tr = _trust_root_from_config()
    except W.WitnessError as e:
        print(f"REFUSE (fail-closed): witness roster error: {e}", file=sys.stderr)
        return _EXIT_REFUSE
    except SystemExit as e:
        return int(e.code or _EXIT_REFUSE)

    data = sys.stdin.read() if args.witnessed == "-" else Path(args.witnessed).read_text(encoding="utf-8")
    local_head = load_local_head(Path(args.head) if args.head else None)
    verdict = evaluate_promotion(local_head, data, scope=scope, trust_root=tr)

    if args.json:
        print(verdict.to_json())
    else:
        for line in verdict.lines():
            print(line, file=(sys.stdout if verdict.activate else sys.stderr))
    return verdict.exit_code


if __name__ == "__main__":
    raise SystemExit(run())
