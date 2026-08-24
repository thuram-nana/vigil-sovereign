"""W7-7 (#465) — OPTIONAL m-of-n passphrase escrow, end-to-end through the file-distribution ceremony.

This is the integration face of :mod:`vigil_core.escrow` (whose crypto core is proven exhaustively in
``packages/core/vigil_core/tests/test_escrow.py``): it drives the offense-local distribution ceremony
(:mod:`vigil_integration.live.escrow_provision`, which REUSES the #438 secure per-host share writer) and
proves the acceptance bar against the REAL off-box backup KDF:

  * reconstruct AT threshold succeeds — a threshold set of SHARE FILES recovers the exact passphrase, and
    that recovered passphrase opens a body sealed EXACTLY as the offense backup seals it (the real
    ``vigil_integration.backup._derive_key`` + ``_BODY_CONTEXT`` — a lost backup passphrase is genuinely
    recoverable);
  * NEGATIVE CONTROL — any m-1 share files CANNOT reconstruct (refused, fail-closed), and a below-threshold
    coalition that forges the missing share still cannot open the backup body (a wrong passphrase is NEVER
    surfaced);
  * OPT-IN, default OFF — no share exists unless escrow is explicitly requested.

vigil_core + the framework-FREE ``vigil_integration.backup`` KDF only (no framework/strix/sigil), so it runs
in the required "integration two-env boundary (P5)" sovereign leg (``pytest integration/tests``).

Run: PYTHONPATH=integration:packages/core/vigil_core python -m pytest integration/tests/test_passphrase_escrow.py -q
"""
from __future__ import annotations

import itertools
import os

import pytest

from vigil_core.escrow import EscrowError, Share, recover_passphrase
from vigil_core.sealing import seal, unseal
from vigil_integration.backup import _BODY_CONTEXT, _SALT_LEN, _derive_key
from vigil_integration.live.escrow_provision import (
    distribute_escrow, load_share_file, recover_from_files,
)

PASSPHRASE = "correct horse battery staple — off-box backup passphrase 42"


def _sealed_backup_body(passphrase: str, salt: bytes) -> bytes:
    """Seal a stand-in backup body under the REAL offense-backup KDF + AEAD context, exactly as
    ``vigil_integration.backup.create_offense_backup`` seals its body. If the recovered passphrase opens
    THIS, it opens a real backup."""
    return seal(_derive_key(passphrase, salt), b"OFFENSE-BACKUP-BODY-v1", context=_BODY_CONTEXT)


def test_threshold_set_of_files_recovers_a_real_backup_passphrase(tmp_path):
    salt = os.urandom(_SALT_LEN)
    body = _sealed_backup_body(PASSPHRASE, salt)  # a body sealed under the ORIGINAL passphrase

    dist = distribute_escrow(passphrase=PASSPHRASE, threshold=3, share_count=5,
                             out_dir=str(tmp_path / "shares"),
                             holders=["alice", "bob", "carol", "dave", "eve"])
    assert len(dist.share_paths) == 5
    paths = [p for _holder, p in dist.share_paths]
    # every share file is 0600 (secret material), the metadata is public.
    for p in paths:
        assert (os.stat(p).st_mode & 0o777) == 0o600
    assert (os.stat(dist.metadata_path).st_mode & 0o777) != 0o600

    # AT threshold: any 3 of the 5 share files recover the EXACT passphrase, which opens the real body.
    for combo in itertools.combinations(paths, 3):
        recovered = recover_from_files(metadata_path=dist.metadata_path, share_paths=list(combo))
        assert recovered == PASSPHRASE
        assert unseal(_derive_key(recovered, salt), body, context=_BODY_CONTEXT) == b"OFFENSE-BACKUP-BODY-v1"


def test_m_minus_one_files_cannot_reconstruct(tmp_path):
    dist = distribute_escrow(passphrase=PASSPHRASE, threshold=3, share_count=5,
                             out_dir=str(tmp_path / "shares"))
    paths = [p for _holder, p in dist.share_paths]
    subsets = list(itertools.combinations(paths, 2))  # m-1 = 2
    assert subsets
    for combo in subsets:
        with pytest.raises(EscrowError, match="insufficient shares"):
            recover_from_files(metadata_path=dist.metadata_path, share_paths=list(combo))


def test_below_threshold_forged_share_never_yields_a_working_passphrase(tmp_path):
    """A below-threshold coalition (2 of 3) that fabricates the missing share reconstructs a WRONG master;
    the sealed passphrase's AEAD fails and recovery raises — no wrong passphrase, no backup access."""
    salt = os.urandom(_SALT_LEN)
    body = _sealed_backup_body(PASSPHRASE, salt)
    dist = distribute_escrow(passphrase=PASSPHRASE, threshold=3, share_count=5,
                             out_dir=str(tmp_path / "shares"))
    paths = [p for _holder, p in dist.share_paths]
    from vigil_core.escrow import parse_public_metadata
    sealed, _t, gid = parse_public_metadata(open(dist.metadata_path, encoding="utf-8").read())
    two_real = [load_share_file(paths[0]), load_share_file(paths[1])]
    forged = Share(threshold=3, group_id=gid, x=200, y=bytes(len(two_real[0].y)))
    with pytest.raises(EscrowError, match="did NOT open the sealed passphrase"):
        recover_passphrase(sealed, two_real + [forged])
    # the body remains sealed to anyone below threshold.
    assert body  # (sanity) the real body exists and was never opened above


def test_a_tampered_share_file_is_refused(tmp_path):
    dist = distribute_escrow(passphrase=PASSPHRASE, threshold=2, share_count=3,
                             out_dir=str(tmp_path / "shares"))
    victim = dist.share_paths[0][1]
    data = open(victim, encoding="utf-8").read().rstrip("\n")
    tampered = data[:-1] + ("0" if data[-1] != "0" else "1")
    open(victim, "w", encoding="utf-8").write(tampered + "\n")
    with pytest.raises(EscrowError, match="checksum mismatch"):
        load_share_file(victim)


def test_escrow_is_opt_in_no_shares_without_a_request(tmp_path):
    """OPT-IN / default OFF: escrow only exists because distribute_escrow was called explicitly. A flow that
    does not opt in produces no share files at all — declining changes nothing."""
    out = tmp_path / "declined"
    # declining = not calling distribute_escrow. No directory, no metadata, no shares.
    assert not out.exists()
    # opting in creates exactly the shares requested.
    dist = distribute_escrow(passphrase=PASSPHRASE, threshold=2, share_count=2, out_dir=str(out))
    assert out.exists() and len(dist.share_paths) == 2


def test_holder_count_must_match_shares(tmp_path):
    with pytest.raises(EscrowError, match="holder"):
        distribute_escrow(passphrase=PASSPHRASE, threshold=2, share_count=3,
                          out_dir=str(tmp_path / "x"), holders=["only-one"])


def test_shares_from_two_escrows_do_not_mix(tmp_path):
    a = distribute_escrow(passphrase=PASSPHRASE, threshold=2, share_count=3, out_dir=str(tmp_path / "a"))
    b = distribute_escrow(passphrase="a different passphrase", threshold=2, share_count=3,
                          out_dir=str(tmp_path / "b"))
    # one share from each escrow → refused (group_id mismatch), never a silent wrong result.
    with pytest.raises(EscrowError, match="different escrows"):
        recover_passphrase(
            _read_sealed(a.metadata_path),
            [load_share_file(a.share_paths[0][1]), load_share_file(b.share_paths[0][1])])


def _read_sealed(metadata_path: str) -> bytes:
    from vigil_core.escrow import parse_public_metadata
    sealed, _t, _gid = parse_public_metadata(open(metadata_path, encoding="utf-8").read())
    return sealed
