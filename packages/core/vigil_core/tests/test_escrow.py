"""W7-7 (#465) — OPTIONAL m-of-n passphrase escrow (Shamir split-knowledge recovery).

Proves the whole acceptance bar for :mod:`vigil_core.escrow`, deterministically and offline:

  * reconstruct AT threshold succeeds — every m-of-n subset recovers the exact passphrase;
  * NEGATIVE CONTROL — every m-1 subset CANNOT reconstruct (the API refuses it, fail-closed), and a
    below-threshold coalition that forges the missing share recovers a WRONG master whose AEAD open
    fails, so a wrong passphrase is NEVER surfaced;
  * shares are INDISTINGUISHABLE below threshold — an exhaustive proof that m-1 shares are consistent
    with all 256 values of a secret byte (they leak zero bits);
  * OPT-IN, default OFF — ``maybe_escrow`` does nothing unless an explicit request is supplied;
  * a COMMITTED known-answer vector pins the GF(2^8) arithmetic and the split, and the constant-time
    field multiply is checked EXHAUSTIVELY against a textbook reference.

Run: pytest packages/core/vigil_core/tests/test_escrow.py -q
"""
from __future__ import annotations

import itertools

import pytest

from vigil_core import escrow
from vigil_core.escrow import (
    EscrowError, EscrowRequest, Share, escrow_passphrase, maybe_escrow, parse_public_metadata,
    recover_passphrase, recover_secret, split_secret,
)


# --------------------------------------------------------------------------------------------------
# a deterministic, injectable RNG so the split is a reproducible known-answer test
# --------------------------------------------------------------------------------------------------
class FixedRNG:
    """Returns bytes from a fixed buffer, in order — the split draws randomness ONLY through this seam."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._i = 0

    def __call__(self, n: int) -> bytes:
        out = self._data[self._i:self._i + n]
        assert len(out) == n, "FixedRNG exhausted — the test buffer is too short"
        self._i += n
        return out


# --------------------------------------------------------------------------------------------------
# a textbook GF(2^8) reference (log/exp-free, plain conditional Russian peasant) — INDEPENDENT of the
# constant-time implementation under test, so an equivalence check is a real cross-check, not a tautology.
# --------------------------------------------------------------------------------------------------
def _ref_gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def _lagrange_at(points, X):
    """General Lagrange interpolation over GF(2^8): value at ``X`` of the poly through ``points``. Used only
    to build the indistinguishability proof; leans on the module's field ops for the arithmetic."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _yj) in enumerate(points):
            if i == j:
                continue
            num = escrow._gf_mul(num, X ^ xj)
            den = escrow._gf_mul(den, xi ^ xj)
        total ^= escrow._gf_mul(yi, escrow._gf_mul(num, escrow._gf_inv(den)))
    return total & 0xFF


# ==================================================================================================
# GF(2^8) core — exhaustive correctness + the constant-time property's premise
# ==================================================================================================
def test_gf_mul_matches_textbook_reference_exhaustively():
    for a in range(256):
        for b in range(256):
            assert escrow._gf_mul(a, b) == _ref_gf_mul(a, b), (a, b)


def test_gf_inverse_is_correct_for_every_nonzero_element():
    for a in range(1, 256):
        assert escrow._gf_mul(a, escrow._gf_inv(a)) == 1, a
    # 0 has no inverse; the impl returns 0 (0**254) and the recover path never divides by it.
    assert escrow._gf_inv(0) == 0


# ==================================================================================================
# COMMITTED known-answer vector — pins the split so a regression in the field math or the polynomial
# evaluation reddens CI. Regenerate deliberately if the scheme ever changes (it must not, silently).
# ==================================================================================================
_KAT_SECRET = bytes([0xDE, 0xAD, 0xBE, 0xEF])
_KAT_GROUP = "cafebabecafebabecafebabecafebabe"
_KAT_COEFFS = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])  # 2 per byte (threshold-1=2)
_KAT_EXPECTED_Y = {
    1: "edda8d10",
    2: "74c09717",
    3: "47b7a4e8",
    4: "8c4dcb70",
    5: "bf3af88f",
}


def test_committed_known_answer_vector():
    shares = split_secret(_KAT_SECRET, threshold=3, share_count=5,
                          rng=FixedRNG(_KAT_COEFFS), group_id=_KAT_GROUP)
    got = {sh.x: sh.y.hex() for sh in shares}
    assert got == _KAT_EXPECTED_Y, got
    # and the committed vector reconstructs the exact secret from any 3 of the 5 shares.
    for combo in itertools.combinations(shares, 3):
        assert recover_secret(list(combo)) == _KAT_SECRET


# ==================================================================================================
# reconstruct AT threshold succeeds  (positive control)
# ==================================================================================================
@pytest.mark.parametrize("threshold,share_count", [(2, 3), (3, 5), (5, 5), (4, 7)])
def test_reconstruct_at_threshold_succeeds(threshold, share_count):
    secret = bytes(range(16))
    shares = split_secret(secret, threshold=threshold, share_count=share_count)
    for combo in itertools.combinations(shares, threshold):
        assert recover_secret(list(combo)) == secret
    # more than the threshold also works (over-determined but consistent)
    assert recover_secret(shares) == secret


# ==================================================================================================
# NEGATIVE CONTROL — m-1 shares CANNOT reconstruct
# ==================================================================================================
def test_m_minus_one_shares_are_refused_for_every_subset():
    threshold, share_count = 3, 5
    shares = split_secret(bytes(range(16)), threshold=threshold, share_count=share_count)
    subsets = list(itertools.combinations(shares, threshold - 1))
    assert subsets, "there must be at least one m-1 subset to test"
    for combo in subsets:
        with pytest.raises(EscrowError, match="insufficient shares"):
            recover_secret(list(combo))


def test_below_threshold_interpolation_yields_the_WRONG_secret():
    """The extra share is load-bearing, not decorative: interpolating a below-threshold point set (bypassing
    the count gate) reconstructs a value that is NOT the secret — so the threshold genuinely gates recovery."""
    secret = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    shares = split_secret(secret, threshold=3, share_count=5, rng=FixedRNG(_KAT_COEFFS), group_id=_KAT_GROUP)
    # only 2 points for a degree-2 polynomial → interpolation at 0 gives some byte, and it is NOT the secret.
    wrong = bytes(
        escrow._interpolate_at_zero([(shares[0].x, shares[0].y[i]), (shares[1].x, shares[1].y[i])])
        for i in range(len(secret)))
    assert wrong != secret


# ==================================================================================================
# shares are INDISTINGUISHABLE below threshold — exhaustive information-theoretic proof
# ==================================================================================================
def test_shares_indistinguishable_below_threshold_exhaustive():
    """For a 1-byte secret at threshold 3, hold only 2 shares. For EVERY candidate secret c in 0..255 there
    is exactly one consistent completion, and the predicted 3rd share is a bijection of c — so 2 shares are
    consistent with all 256 secrets equally and reveal zero bits. This is the perfect-secrecy property."""
    secret = bytes([0x5A])
    shares = split_secret(secret, threshold=3, share_count=5,
                          rng=FixedRNG(bytes([0x9C, 0x1D])), group_id=_KAT_GROUP)
    x1, y1 = shares[0].x, shares[0].y[0]
    x2, y2 = shares[1].x, shares[1].y[0]
    x3, actual_y3 = shares[2].x, shares[2].y[0]
    predicted = {}
    for c in range(256):
        # assume secret == c: the unique degree-2 poly through (0,c),(x1,y1),(x2,y2); predict share at x3.
        predicted[c] = _lagrange_at([(0, c), (x1, y1), (x2, y2)], x3)
    # (a) bijection: 256 distinct predictions → every candidate secret is equally consistent with the 2 shares
    assert len(set(predicted.values())) == 256
    # (b) exactly the true secret predicts the ACTUAL 3rd share (recovery would need that 3rd share)
    matching = [c for c, y in predicted.items() if y == actual_y3]
    assert matching == [secret[0]]


# ==================================================================================================
# passphrase escrow — round trip + fail-closed integrity (AEAD is the correctness oracle)
# ==================================================================================================
_PASSPHRASE = "correct horse battery staple — off-box backup passphrase 42"


def test_passphrase_escrow_round_trip_every_threshold_subset():
    bundle = escrow_passphrase(_PASSPHRASE, threshold=3, share_count=5)
    assert len(bundle.shares) == 5
    for combo in itertools.combinations(bundle.shares, 3):
        assert recover_passphrase(bundle.sealed_passphrase, list(combo)) == _PASSPHRASE


def test_recover_passphrase_below_threshold_fails_closed():
    bundle = escrow_passphrase(_PASSPHRASE, threshold=3, share_count=5)
    for combo in itertools.combinations(bundle.shares, 2):
        with pytest.raises(EscrowError, match="insufficient shares"):
            recover_passphrase(bundle.sealed_passphrase, list(combo))


def test_forged_share_below_threshold_fails_closed_never_returns_wrong_passphrase():
    """A below-threshold coalition (2 of 3) that fabricates the missing share reconstructs a WRONG master;
    the AEAD open fails and recovery raises — a plausible-but-wrong passphrase is NEVER surfaced."""
    bundle = escrow_passphrase(_PASSPHRASE, threshold=3, share_count=5)
    real_two = list(bundle.shares[:2])
    forged = Share(threshold=3, group_id=bundle.shares[0].group_id, x=250,
                   y=bytes(len(bundle.shares[0].y)))  # attacker-chosen y
    with pytest.raises(EscrowError, match="did NOT open the sealed passphrase"):
        recover_passphrase(bundle.sealed_passphrase, real_two + [forged])


def test_tampered_sealed_blob_fails_closed():
    bundle = escrow_passphrase(_PASSPHRASE, threshold=2, share_count=3)
    blob = bytearray(bundle.sealed_passphrase)
    blob[-1] ^= 0x01  # flip one ciphertext/tag bit
    with pytest.raises(EscrowError, match="did NOT open the sealed passphrase"):
        recover_passphrase(bytes(blob), list(bundle.shares[:2]))


def test_shares_from_different_escrows_are_refused():
    a = escrow_passphrase(_PASSPHRASE, threshold=2, share_count=3)
    b = escrow_passphrase(_PASSPHRASE, threshold=2, share_count=3)
    with pytest.raises(EscrowError, match="different escrows"):
        recover_secret([a.shares[0], b.shares[0]])


def test_duplicate_share_coordinate_is_refused():
    bundle = escrow_passphrase(_PASSPHRASE, threshold=2, share_count=3)
    with pytest.raises(EscrowError, match="duplicate share coordinate"):
        recover_secret([bundle.shares[0], bundle.shares[0]])


def test_recover_secret_refuses_empty_and_length_mismatch_and_bad_x():
    with pytest.raises(EscrowError, match="no shares"):
        recover_secret([])
    s = split_secret(b"abcd", threshold=2, share_count=3)
    bad_len = Share(threshold=2, group_id=s[0].group_id, x=9, y=b"short")
    with pytest.raises(EscrowError, match="disagree on secret length"):
        recover_secret([s[0], bad_len])
    bad_x = Share(threshold=2, group_id=s[0].group_id, x=999, y=bytes(len(s[0].y)))
    with pytest.raises(EscrowError, match="out of range"):
        recover_secret([s[0], bad_x])


# ==================================================================================================
# OPT-IN, default OFF — declining escrow changes nothing
# ==================================================================================================
def test_maybe_escrow_is_opt_in_and_off_by_default():
    # declined (the default): returns None, produces no bundle and no share — nothing happens.
    assert maybe_escrow(_PASSPHRASE) is None
    assert maybe_escrow(_PASSPHRASE, escrow=None) is None
    # opted-in: an explicit request produces a recoverable bundle.
    bundle = maybe_escrow(_PASSPHRASE, escrow=EscrowRequest(threshold=2, share_count=3))
    assert bundle is not None
    assert recover_passphrase(bundle.sealed_passphrase, list(bundle.shares[:2])) == _PASSPHRASE


def test_escrow_shares_do_not_contain_the_passphrase():
    """The share y-bytes are evaluations of a random-master polynomial, not the passphrase — a single share
    reveals neither the passphrase nor (below threshold) the master."""
    bundle = escrow_passphrase(_PASSPHRASE, threshold=3, share_count=5)
    pw = _PASSPHRASE.encode("utf-8")
    for sh in bundle.shares:
        assert pw not in sh.y
        assert sh.y != pw[: len(sh.y)]


# ==================================================================================================
# share serialisation — transcription/tamper detection
# ==================================================================================================
def test_share_line_round_trip():
    shares = split_secret(b"payload-bytes", threshold=3, share_count=5)
    for sh in shares:
        assert Share.from_line(sh.to_line()) == sh


def test_share_line_checksum_detects_a_mistyped_share():
    line = split_secret(b"payload", threshold=2, share_count=3)[0].to_line()
    flipped = line[:-1] + ("0" if line[-1] != "0" else "1")
    with pytest.raises(EscrowError, match="checksum mismatch"):
        Share.from_line(flipped)


@pytest.mark.parametrize("bad", [
    "",
    "not-a-share",
    "vigil-escrow-share-v1:3:gid:1:AAAA",           # too few fields
    "wrong-prefix:3:gid:1:AAAA:0000000000000000",   # wrong prefix
])
def test_share_line_malformed_is_refused(bad):
    with pytest.raises(EscrowError):
        Share.from_line(bad)


def test_share_line_out_of_range_fields_refused():
    # a well-checksummed line whose threshold is below 2 must still be refused.
    core = f"{escrow._SHARE_PREFIX}:1:gid:1:AAAA"
    line = f"{core}:{escrow._share_checksum(core)}"
    with pytest.raises(EscrowError, match="out of range"):
        Share.from_line(line)


def test_share_line_non_integer_fields_refused():
    # a well-checksummed line whose numeric fields are non-integers is refused as malformed (not crashed).
    core = f"{escrow._SHARE_PREFIX}:xx:gid:1:AAAA"
    line = f"{core}:{escrow._share_checksum(core)}"
    with pytest.raises(EscrowError, match="malformed share fields"):
        Share.from_line(line)


# ==================================================================================================
# public metadata — the non-secret record stored with the backup
# ==================================================================================================
def test_public_metadata_round_trips_and_carries_no_secret():
    import json
    bundle = escrow_passphrase(_PASSPHRASE, threshold=3, share_count=5)
    doc = json.dumps(bundle.public_metadata())
    # the metadata must not contain any share's secret y-bytes
    for sh in bundle.shares:
        assert sh.y.hex() not in doc
    sealed, threshold, gid = parse_public_metadata(doc)
    assert threshold == 3 and gid == bundle.shares[0].group_id
    assert recover_passphrase(sealed, list(bundle.shares[:3])) == _PASSPHRASE


def test_public_metadata_detects_corruption():
    import json
    bundle = escrow_passphrase(_PASSPHRASE, threshold=2, share_count=3)
    meta = bundle.public_metadata()
    meta["sealed_passphrase_sha256"] = "0" * 64  # wrong hash
    with pytest.raises(EscrowError, match="does not match its bytes"):
        parse_public_metadata(json.dumps(meta))
    with pytest.raises(EscrowError, match="malformed escrow metadata"):
        parse_public_metadata("{not json")


# ==================================================================================================
# parameter guards — the off-by-one / degenerate-threshold fail-closed gate
# ==================================================================================================
@pytest.mark.parametrize("threshold,share_count,msg", [
    (1, 5, "threshold must be at least 2"),      # a threshold of 1 is no split knowledge
    (6, 5, "exceeds share_count"),               # off-by-one: a quorum that can never be met
    (3, 1, "share_count must be in"),            # n below 2
    (2, 999, "share_count must be in"),          # n beyond the 255 GF(2^8) coordinates
])
def test_parameter_guards(threshold, share_count, msg):
    with pytest.raises(EscrowError, match=msg):
        escrow_passphrase("pw", threshold=threshold, share_count=share_count)
    with pytest.raises(EscrowError, match=msg):
        split_secret(b"secret", threshold=threshold, share_count=share_count)


def test_empty_secret_and_passphrase_refused():
    with pytest.raises(EscrowError, match="non-empty bytes"):
        split_secret(b"", threshold=2, share_count=3)
    with pytest.raises(EscrowError, match="non-empty string"):
        escrow_passphrase("", threshold=2, share_count=3)


def test_non_integer_params_refused():
    with pytest.raises(EscrowError, match="must be integers"):
        split_secret(b"x", threshold=2.0, share_count=3)  # type: ignore[arg-type]


def test_rng_underdelivery_is_refused():
    # an rng that returns too few bytes must fail closed rather than silently produce a weak split.
    with pytest.raises(EscrowError, match="group id"):
        split_secret(b"secretbytes", threshold=2, share_count=3, rng=lambda n: b"")
    # enough for the group id (16), then too few coefficient bytes
    with pytest.raises(EscrowError, match="coefficient"):
        split_secret(b"secretbytes", threshold=2, share_count=3, rng=lambda n: bytes(16))
    with pytest.raises(EscrowError, match="escrow master"):
        escrow_passphrase("pw", threshold=2, share_count=3, rng=lambda n: b"")


def test_recover_passphrase_rejects_wrong_size_master():
    # shares that reconstruct a non-32-byte secret are not a passphrase escrow.
    shares = split_secret(b"1234", threshold=2, share_count=3)  # 4-byte secret
    with pytest.raises(EscrowError, match="wrong size"):
        recover_passphrase(b"\x00" * 83, list(shares[:2]))
