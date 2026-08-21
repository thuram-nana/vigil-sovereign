"""
agents.evidence_erasure — the WIRED right-to-erasure path for append-only evidence (W16-8).

Given an engagement, this crypto-shreds its at-rest credential-bearing evidence WITHOUT
deleting or rewriting a single append-only spine row, so the append-only / tamper-evidence
guarantee survives the erasure. Decision + consequences: ADR knowledge/decisions/0008.

What one ``erase_engagement_evidence`` call does:

  1. On-disk archive (``targets/<slug>/evidence/``): every plaintext evidence file (the raw
     ``request.http`` credential lines + ``response.body``) is SEALED in place under the
     engagement DEK. Files already sealed are skipped (idempotent). This is a filesystem
     rewrite — the FILESYSTEM is not append-only, only the spine is — so it is permitted.
  2. The DEK is SHREDDED (``EvidenceKeyring.shred``): the just-sealed on-disk ciphertext, plus
     any off-host backup copy of it and any sealed excerpt embedded in a spine payload, become
     cryptographically unrecoverable.
  3. A TOMBSTONE is APPENDED to the spine (a new ``decision`` event — an append, never a
     delete/update) recording the erasure: engagement, key fingerprint of the destroyed DEK,
     algorithm, file count, timestamp, operator reason. The audit log therefore shows THAT and
     WHEN erasure happened while proving nothing was excised.
  4. If governance ``signers`` are supplied, the spine head is RE-ANCHORED over the new log
     (including the tombstone) and returned, so the operator can persist a fresh signed anchor.

Because steps 1–2 never touch a spine row, ``spine_chain.verify_spine_chain`` still passes and
the append-only triggers still refuse DELETE/UPDATE afterwards (proven by the tests).

Offense-plane, sigil-free. Destructive: the CLI default-denies without an explicit ``--yes``.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from ..common import crypto_shred, paths
from ..common.crypto_shred import EvidenceKeyring, ShredReceipt
from .blackboard import Blackboard, open_blackboard
from .spine_chain import sign_spine_head


@dataclass
class ErasureResult:
    """Outcome of a right-to-erasure run over one engagement."""

    engagement: str
    sealed_files: int              # plaintext evidence files newly sealed in place
    already_sealed: int            # files skipped because they were already crypto-shredded
    receipt: ShredReceipt          # proof of the DEK destruction
    tombstone_event_id: int        # the append-only spine event recording the erasure
    signed_head: object | None     # a re-anchored SignedChainHead if signers were given, else None
    evidence_root: str

    def to_dict(self) -> dict[str, object]:
        return {
            "engagement": self.engagement,
            "sealed_files": self.sealed_files,
            "already_sealed": self.already_sealed,
            "receipt": self.receipt.to_dict(),
            "tombstone_event_id": self.tombstone_event_id,
            "reanchored": self.signed_head is not None,
            "evidence_root": self.evidence_root,
        }


def _seal_evidence_tree(keyring: EvidenceKeyring, engagement: str, root: Path) -> tuple[int, int]:
    """Seal every plaintext regular file under ``root`` in place under the engagement DEK.
    Returns (newly_sealed, already_sealed). Skips files already sealed so a re-run is
    idempotent and does not double-encrypt."""
    sealed = 0
    already = 0
    if not root.exists():
        return (0, 0)
    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        data = f.read_bytes()
        if crypto_shred.is_sealed(data):
            already += 1
            continue
        blob = keyring.seal(engagement, data)
        paths.secure_write(f, blob)          # overwrite plaintext with ciphertext, owner-only
        sealed += 1
    return (sealed, already)


def erase_engagement_evidence(
    engagement: str,
    *,
    bb: Blackboard,
    keyring: EvidenceKeyring | None = None,
    evidence_root: Path | None = None,
    signers: list[tuple[str, str]] | None = None,
    agent_name: str = "privacy-officer",
    reason: str = "",
) -> ErasureResult:
    """Crypto-shred an engagement's at-rest evidence and record the erasure on the append-only
    spine. See the module docstring. ``evidence_root`` defaults to the engagement's real
    on-disk archive; pass an explicit path in tests. ``signers`` (governance keypairs) re-anchor
    the spine head over the post-erasure log."""
    keyring = keyring or EvidenceKeyring()
    root = evidence_root if evidence_root is not None else paths.evidence_archive_dir(engagement)

    # 1. Seal the on-disk archive in place, then 2. destroy the DEK.
    sealed, already = _seal_evidence_tree(keyring, engagement, root)
    receipt = keyring.shred(engagement)

    # 3. Append the tombstone (a NEW row — the append-only trigger is never bypassed).
    rationale = json.dumps({
        "policy": "crypto-shred (ADR-0008)",
        "reason": reason,
        "sealed_files": sealed,
        "already_sealed": already,
        "evidence_root": str(root),
        "receipt": receipt.to_dict(),
    }, sort_keys=True)
    tombstone_id = bb.post(
        engagement=engagement,
        kind="decision",
        agent_name=agent_name,
        payload={
            "question": f"right-to-erasure:{engagement}",
            "choice": "crypto-shredded" if receipt.shredded else "no-key-present",
            "rationale": rationale,
        },
    )

    # 4. Optional re-anchor over the post-erasure log (including the tombstone).
    head = sign_spine_head(bb, engagement, signers=signers) if signers else None

    return ErasureResult(
        engagement=str(engagement),
        sealed_files=sealed,
        already_sealed=already,
        receipt=receipt,
        tombstone_event_id=tombstone_id,
        signed_head=head,
        evidence_root=str(root),
    )


# ---------------------------------------------------------------------------
# CLI: `python3 -m framework.v2 erase-evidence --engagement <slug> --yes`
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="python3 -m framework.v2 erase-evidence",
        description="Crypto-shred an engagement's at-rest credential-bearing evidence "
                    "(right to erasure) without breaking the append-only spine. See ADR-0008.",
    )
    p.add_argument("--engagement", required=True, help="engagement slug to erase")
    p.add_argument("--reason", default="", help="operator reason recorded in the spine tombstone")
    p.add_argument("--yes", action="store_true",
                   help="confirm this DESTRUCTIVE, irreversible erasure (default-deny without it)")
    args = p.parse_args(argv)

    if not args.yes:
        # Destructive + irreversible → fail closed (constitution §VIII: ask before destruction).
        print("erase-evidence is DESTRUCTIVE and IRREVERSIBLE: it permanently shreds the "
              "per-engagement key so the sealed evidence can never be recovered.\n"
              "Re-run with --yes to confirm. [default-deny]", file=sys.stderr)
        return 2

    bb = open_blackboard()
    try:
        result = erase_engagement_evidence(args.engagement, bb=bb, reason=args.reason)
    finally:
        bb.close()

    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    if not result.receipt.shredded and result.sealed_files == 0:
        print("note: no DEK and no plaintext evidence found for this engagement — nothing to "
              "erase (a tombstone was still recorded).", file=sys.stderr)
    return 0
