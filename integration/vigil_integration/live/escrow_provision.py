"""escrow_provision — OPT-IN m-of-n passphrase escrow: distribute Shamir shares to holders, recover at
threshold. W7-7 (#465).

The cryptographic core is :mod:`vigil_core.escrow` (Shamir over GF(2^8) + a sealed random master, so
recovery is fail-closed via the AEAD — a below-threshold or tampered share set never yields a wrong
passphrase). This module is the thin, offense-local DISTRIBUTION ceremony around it, and it deliberately
REUSES the #438 (W9-5) secure per-host share-distribution primitive rather than re-inventing one:

  * each share is written with :func:`destruction_provision.write_cosigner_private_key` — the SAME
    ``O_CREAT | O_EXCL``, 0600, refuse-to-clobber secret-file writer that keeps a co-signer's destruction
    key on its own host. A share is exactly the same kind of object (secret material that belongs with
    exactly ONE holder, kept off any central box), so it gets exactly the same handling.
  * the public ``sealed_passphrase`` metadata is written world-readable (0644) — it is a ciphertext under
    the split master and leaks nothing below threshold.

SOVEREIGNTY TRADE-OFF (opt-in, off by default — declining changes nothing): enabling escrow is a NAMED
trust concession — any ``m`` of the ``n`` share-holders can COLLECTIVELY recover the backup passphrase and
thus the backup. See docs/decisions/W7-7-passphrase-escrow.md. Import-clean: ``vigil_core`` + the offense-
local ``destruction_provision`` only — NO framework/strix/sigil.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from vigil_core.escrow import (
    EscrowError, Share, escrow_passphrase, parse_public_metadata, recover_passphrase,
)

from .destruction_provision import write_cosigner_private_key

_METADATA_NAME = "escrow-metadata.json"
_SHARE_SUFFIX = ".escrow-share"


@dataclass(frozen=True)
class DistributedEscrow:
    """Where an opt-in escrow landed on disk: the PUBLIC metadata file (safe to store with the backup) and
    the per-holder SECRET share files (each must go to its holder and stay on the holder's own host)."""

    metadata_path: str
    share_paths: tuple[tuple[str, str], ...]   # (holder, path) — SECRET, one per holder
    threshold: int
    share_count: int
    group_id: str


def _holder_names(holders: "list[str] | None", share_count: int) -> list[str]:
    names = [str(h or "").strip() for h in (holders or []) if str(h or "").strip()]
    if not names:
        names = [f"holder{i + 1}" for i in range(share_count)]
    if len(names) != share_count:
        raise EscrowError(f"got {len(names)} holder name(s) but share_count is {share_count} "
                          "(give exactly one --holder per share, or none to auto-name)")
    if len(set(names)) != len(names):
        raise EscrowError("holder names must be unique (each share goes to a distinct holder)")
    return names


def distribute_escrow(*, passphrase: str, threshold: int, share_count: int, out_dir: str,
                      holders: "list[str] | None" = None) -> DistributedEscrow:
    """OPT-IN. Escrow ``passphrase`` m-of-n and write the shares out for distribution: one SECRET share file
    per holder (0600, ``O_EXCL`` — refuses to clobber, reusing the #438 writer) plus the PUBLIC metadata
    file. Fail-closed on bad params (delegated to :func:`vigil_core.escrow.escrow_passphrase`) or a holder
    list that does not match ``share_count``. Returns the paths written."""
    names = _holder_names(holders, share_count)
    bundle = escrow_passphrase(passphrase, threshold=threshold, share_count=share_count)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    meta_path = out / _METADATA_NAME
    meta_path.write_text(json.dumps(bundle.public_metadata(), indent=2, sort_keys=True), encoding="utf-8")

    share_paths: list[tuple[str, str]] = []
    for name, share in zip(names, bundle.shares):
        p = out / f"{name}{_SHARE_SUFFIX}"
        # REUSE #438: 0600, O_EXCL secret-file write (refuse to overwrite an existing share).
        write_cosigner_private_key(str(p), share.to_line())
        share_paths.append((name, str(p)))

    return DistributedEscrow(
        metadata_path=str(meta_path),
        share_paths=tuple(share_paths),
        threshold=bundle.threshold,
        share_count=bundle.share_count,
        group_id=bundle.shares[0].group_id,
    )


def load_share_file(path: str) -> Share:
    """Read + checksum-verify ONE share file written by :func:`distribute_escrow`. Fail-closed on a missing
    file or a mistyped/tampered share line (:func:`Share.from_line`)."""
    try:
        line = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise EscrowError(f"could not read share file {path!r}: {exc}") from exc
    if not line:
        raise EscrowError(f"share file {path!r} is empty")
    return Share.from_line(line)


def recover_from_files(*, metadata_path: str, share_paths: "list[str]") -> str:
    """Recover the passphrase from the PUBLIC metadata file and a set of SECRET share files. Reconstructs at
    threshold and FAILS CLOSED below it (a below-threshold / mismatched / tampered set raises
    :class:`EscrowError` — a wrong passphrase is NEVER returned)."""
    try:
        doc = Path(metadata_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise EscrowError(f"could not read escrow metadata {metadata_path!r}: {exc}") from exc
    sealed, _threshold, _gid = parse_public_metadata(doc)
    shares = [load_share_file(p) for p in (share_paths or [])]
    if not shares:
        raise EscrowError("no share files supplied")
    return recover_passphrase(sealed, shares)
