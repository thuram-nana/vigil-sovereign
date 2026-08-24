"""vigil_core.escrow — OPTIONAL m-of-n passphrase escrow (Shamir split-knowledge recovery). W7-7 (#465).

The off-box backup passphrase (``integration.vigil_integration.backup`` / ``apps.sigil.sigil.backup``) is
the ONLY key to the encrypted backup and is NEVER stored — lose it and the backup is unrecoverable BY
DESIGN. That is the right default for a sovereignty tool, but it makes passphrase loss TOTAL and PERMANENT.
This module offers an OPT-IN alternative: split the passphrase into ``n`` shares under a threshold ``m`` so
that ANY ``m`` share-holders can jointly recover it and ANY ``m-1`` CANNOT. Declining it changes nothing —
nothing here runs unless the operator explicitly asks for it (:func:`maybe_escrow` returns ``None`` by
default), and it never touches the backup file format or the create/restore path.

WHY A SPLIT MASTER, NOT THE PASSPHRASE DIRECTLY
-----------------------------------------------
Shamir over the passphrase bytes would recover a WRONG passphrase silently if shares are insufficient,
mismatched, or tampered (interpolation always returns *some* value), and storing any commitment to the
passphrase (a hash) next to the shares would expose a weak passphrase to offline guessing. Instead:

  1. mint a fresh, uniformly-random 32-byte MASTER ``R`` (high entropy — not the passphrase);
  2. Shamir-split ``R`` (m-of-n over GF(2^8)) into the shares that go to the holders;
  3. seal the passphrase UNDER ``R`` with the already-reviewed AEAD (:func:`vigil_core.sealing.seal`,
     ChaCha20-Poly1305) into a public ``sealed_passphrase`` blob — safe to store anywhere.

Recovery reconstructs ``R`` from ``m`` shares and OPENS the sealed blob. Because the AEAD authenticates,
recovery is FAIL-CLOSED: an insufficient / mismatched / tampered share set reconstructs the WRONG ``R``,
the open fails its tag, and :func:`recover_passphrase` raises :class:`EscrowError` — it NEVER returns a
wrong passphrase. And because ``R`` is 32 uniformly-random bytes, the stored ``sealed_passphrase`` blob is
NOT subject to offline passphrase guessing: below threshold ``R`` is information-theoretically hidden, so
the blob is a ciphertext under an unknown uniform key and leaks nothing about the passphrase.

THE SHAMIR CORE (GF(2^8), AES field 0x11B)
------------------------------------------
Byte-wise Shamir Secret Sharing: each secret byte is the constant term of an independent degree-(m-1)
polynomial over GF(2^8); a share is the evaluation of every byte-polynomial at a distinct nonzero
x-coordinate; recovery is Lagrange interpolation at x=0. The field multiply is a CONSTANT-TIME, branchless,
table-free Russian-peasant loop (fixed 8 iterations, no secret-indexed memory, no data-dependent branch) so
neither the split nor the recover leaks the coefficient/secret bytes through a cache-timing side channel;
the inverse is ``a^254`` (Fermat) via square-and-multiply over a PUBLIC fixed exponent. Escrow recovery is a
rare, offline, interactive ceremony, so timing exposure is low — the constant-time core is defence in depth,
and its correctness is pinned by an EXHAUSTIVE known-answer test against a reference log/exp field.

SOVEREIGNTY TRADE-OFF (be honest about it — see docs/decisions/W7-7-passphrase-escrow.md)
-----------------------------------------------------------------------------------------
Escrow is a NAMED, DELIBERATE trust concession. With it enabled, any ``m`` of the ``n`` share-holders can
COLLECTIVELY recover the passphrase and thus decrypt the backup — the sole-custody "only the operator can
ever recover" property is knowingly traded for survivability of passphrase loss. WHO holds the shares and
what ``m``/``n`` to choose is the operator's decision; the tooling only makes the shares easy to keep apart
(one per holder). It is OPT-IN and OFF by default: a deployment that declines escrow keeps the original
lose-it-and-it-is-gone guarantee, unchanged and byte-for-byte.

Import-clean and dependency-pure: stdlib + the in-package :mod:`vigil_core.sealing` only. No framework, no
strix, no sigil — the two-env boundary and SIGIL's offense-free guarantee are untouched.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from .sealing import SealError, seal, unseal

# ======================================================================================================
# GF(2^8) — the AES field (reduction polynomial x^8 + x^4 + x^3 + x + 1 == 0x11B). Constant-time core.
# ======================================================================================================

_REDUCE = 0x1B  # low 8 bits of 0x11B — the term xor'd in on an overflowing left shift.


def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8), CONSTANT-TIME: a fixed 8-iteration Russian-peasant loop with NO data-dependent
    branch and NO table lookup, so it leaks neither operand through control flow or a cache-timing channel."""
    a &= 0xFF
    b &= 0xFF
    p = 0
    for _ in range(8):
        # if the low bit of b is set, xor a into the accumulator — masked, not branched.
        p ^= a & (-(b & 1) & 0xFF)
        # a <<= 1, and if it overflowed bit 7, xor in the reduction polynomial — masked, not branched.
        hi = -((a >> 7) & 1) & 0xFF
        a = ((a << 1) & 0xFF) ^ (_REDUCE & hi)
        b >>= 1
    return p & 0xFF


def _gf_pow(a: int, e: int) -> int:
    """``a**e`` in GF(2^8) by square-and-multiply. ``e`` is PUBLIC (a fixed exponent), so branching on its
    bits leaks nothing; each step is the constant-time :func:`_gf_mul`."""
    result = 1
    base = a & 0xFF
    for i in range(8):
        if (e >> i) & 1:            # branch on the PUBLIC exponent only
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
    return result & 0xFF


def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^8): ``a**254`` (Fermat, since ``a**255 == 1`` for ``a != 0``). Returns
    0 for input 0 (``0**254 == 0``); the denominators here are ``x_i xor x_j`` for DISTINCT nonzero public
    x-coordinates, so the 0 case never arises in a valid recover."""
    return _gf_pow(a, 254)


def _poly_eval(coeffs: Sequence[int], x: int) -> int:
    """Evaluate a polynomial (``coeffs[0]`` = constant term, ascending) at ``x`` over GF(2^8), by Horner."""
    y = 0
    for c in reversed(coeffs):
        y = _gf_mul(y, x) ^ (c & 0xFF)
    return y & 0xFF


def _interpolate_at_zero(points: Sequence[tuple[int, int]]) -> int:
    """Lagrange-interpolate the value at x=0 of the degree-(len(points)-1) polynomial through ``points`` =
    ``[(x, y), ...]`` over GF(2^8). In characteristic 2, ``0 - x == x`` and ``x_j - x_k == x_j xor x_k``, so
    the basis at 0 is ``L_j(0) = prod_{k!=j} x_k * inv(x_j xor x_k)``. Requires DISTINCT x (caller-checked)."""
    secret = 0
    n = len(points)
    for j in range(n):
        xj, yj = points[j]
        num = 1
        den = 1
        for k in range(n):
            if k == j:
                continue
            xk = points[k][0]
            num = _gf_mul(num, xk)
            den = _gf_mul(den, xj ^ xk)
        secret ^= _gf_mul(yj, _gf_mul(num, _gf_inv(den)))
    return secret & 0xFF


# ======================================================================================================
# Shamir share model + split / recover over a byte string.
# ======================================================================================================

_SHARE_PREFIX = "vigil-escrow-share-v1"
_MAX_SHARES = 255            # x-coordinates 1..255 are the nonzero elements of GF(2^8).
_GROUP_ID_LEN = 16           # bytes; a random per-split id so shares of different splits never mix.
_MASTER_LEN = 32             # the escrow master R is a 32-byte AEAD KEK for vigil_core.sealing.
# AEAD context binding the sealed passphrase to THIS purpose (domain-separated from every other seal).
_ESCROW_CONTEXT = b"vigil-core/passphrase-escrow/v1"


class EscrowError(Exception):
    """An escrow operation was refused or could not complete: bad parameters, a below-threshold /
    mismatched / tampered share set, or a recovered master that did not open the sealed passphrase.
    Fail-closed — an escrow that cannot faithfully recover the ORIGINAL secret raises, never returns a
    wrong value."""


@dataclass(frozen=True)
class Share:
    """One Shamir share. ``threshold`` (m) and ``group_id`` are common to every share of a split; ``x`` is
    the share's distinct nonzero GF(2^8) coordinate (1..255); ``y`` is the per-byte evaluation. All fields
    but ``y`` are non-secret metadata; ``y`` is secret material and lives with exactly one holder."""

    threshold: int
    group_id: str
    x: int
    y: bytes

    def to_line(self) -> str:
        """Serialise to ONE self-describing, transcription-checked text line for distribution to a holder:
        ``vigil-escrow-share-v1:<m>:<group_id>:<x>:<y_b64>:<checksum>``. The checksum is a truncated SHA-256
        over the canonical fields — a typo/tamper DETECTOR only (it commits to the share, which is already
        indistinguishable-below-threshold; it commits to NOTHING about the secret)."""
        y_b64 = base64.b64encode(self.y).decode("ascii")
        core = f"{_SHARE_PREFIX}:{self.threshold}:{self.group_id}:{self.x}:{y_b64}"
        return f"{core}:{_share_checksum(core)}"

    @staticmethod
    def from_line(line: str) -> "Share":
        """Parse + checksum-verify a share line. Fail-closed on any malformation or a checksum mismatch
        (a mistyped share is refused HERE, before it can silently corrupt a recovery)."""
        s = str(line or "").strip()
        parts = s.split(":")
        if len(parts) != 6 or parts[0] != _SHARE_PREFIX:
            raise EscrowError("not a vigil-escrow-share-v1 line (wrong shape or prefix)")
        _, m_s, gid, x_s, y_b64, chk = parts
        core = f"{_SHARE_PREFIX}:{m_s}:{gid}:{x_s}:{y_b64}"
        if not hmac.compare_digest(chk, _share_checksum(core)):
            raise EscrowError("share checksum mismatch — the line was mistyped or tampered")
        try:
            m = int(m_s)
            x = int(x_s)
            y = base64.b64decode(y_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise EscrowError(f"malformed share fields: {exc}") from exc
        if not gid or m < 2 or not (1 <= x <= _MAX_SHARES) or not y:
            raise EscrowError("share fields out of range")
        return Share(threshold=m, group_id=gid, x=x, y=y)


def _share_checksum(core: str) -> str:
    return hashlib.sha256(core.encode("utf-8")).hexdigest()[:16]


def _validate_params(threshold: int, share_count: int) -> None:
    """Fail-closed parameter gate shared by split and escrow. Refuses the degenerate thresholds that would
    make "split knowledge" a costume: ``m < 2`` (any single holder recovers = no split), ``m > n`` (the
    off-by-one that can NEVER be met), and ``n`` beyond the 255 nonzero GF(2^8) coordinates."""
    if not isinstance(threshold, int) or not isinstance(share_count, int):
        raise EscrowError("threshold and share_count must be integers")
    if share_count < 2 or share_count > _MAX_SHARES:
        raise EscrowError(f"share_count must be in 2..{_MAX_SHARES} (got {share_count})")
    if threshold < 2:
        raise EscrowError("threshold must be at least 2 — a threshold of 1 is no split knowledge "
                          "(any single holder could recover)")
    if threshold > share_count:
        raise EscrowError(f"threshold {threshold} exceeds share_count {share_count} — a quorum that can "
                          "never be met (off-by-one guard)")


def split_secret(secret: bytes, *, threshold: int, share_count: int,
                 rng: Callable[[int], bytes] = os.urandom, group_id: Optional[str] = None) -> list[Share]:
    """Shamir-split ``secret`` (bytes) into ``share_count`` shares recoverable at ``threshold``. Draws
    randomness ONLY from ``rng`` (injectable for a deterministic known-answer test; ``os.urandom`` in
    production), in a fixed, documented order: ``group_id`` first (16 bytes, if not supplied), then the
    ``(threshold-1) * len(secret)`` coefficient bytes. Coordinates are ``1..share_count`` (distinct,
    nonzero). Fail-closed on bad params, an empty secret, or an ``rng`` that under-delivers."""
    _validate_params(threshold, share_count)
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise EscrowError("secret must be non-empty bytes")
    secret = bytes(secret)

    if group_id is None:
        gid_bytes = rng(_GROUP_ID_LEN)
        if len(gid_bytes) != _GROUP_ID_LEN:
            raise EscrowError("rng did not deliver enough bytes for the group id")
        gid = gid_bytes.hex()
    else:
        gid = str(group_id)

    n_coeff = (threshold - 1) * len(secret)
    rand = rng(n_coeff)
    if len(rand) != n_coeff:
        raise EscrowError("rng did not deliver enough coefficient bytes")

    shares: list[Share] = []
    for x in range(1, share_count + 1):
        y = bytearray(len(secret))
        for i in range(len(secret)):
            coeffs = [secret[i]] + [rand[i * (threshold - 1) + j] for j in range(threshold - 1)]
            y[i] = _poly_eval(coeffs, x)
        shares.append(Share(threshold=threshold, group_id=gid, x=x, y=bytes(y)))
    return shares


def recover_secret(shares: Sequence[Share]) -> bytes:
    """Reconstruct the secret from ``shares`` by Lagrange interpolation at x=0. ENFORCES the threshold: it
    refuses fewer than ``m`` shares, refuses shares from different splits (mismatched ``group_id``/``m``),
    refuses duplicate coordinates, and refuses inconsistent share lengths — all fail-closed. Given at least
    ``m`` CONSISTENT shares it returns the exact secret; given a tampered/foreign share it returns some
    value (Shamir cannot detect that alone — the passphrase layer's AEAD is the integrity oracle)."""
    if not shares:
        raise EscrowError("no shares supplied")
    first = shares[0]
    m = first.threshold
    gid = first.group_id
    ylen = len(first.y)
    seen_x: set[int] = set()
    for sh in shares:
        if sh.threshold != m or sh.group_id != gid:
            raise EscrowError("shares are from different escrows (threshold/group_id mismatch) — refusing "
                              "to mix them")
        if len(sh.y) != ylen:
            raise EscrowError("shares disagree on secret length — refusing to mix them")
        if not (1 <= sh.x <= _MAX_SHARES):
            raise EscrowError(f"share coordinate {sh.x} out of range")
        if sh.x in seen_x:
            raise EscrowError(f"duplicate share coordinate {sh.x} — a share was supplied twice")
        seen_x.add(sh.x)
    if len(shares) < m:
        raise EscrowError(f"insufficient shares: have {len(shares)}, need the threshold of {m} "
                          "(m-1 shares CANNOT reconstruct)")
    out = bytearray(ylen)
    for i in range(ylen):
        points = [(sh.x, sh.y[i]) for sh in shares]
        out[i] = _interpolate_at_zero(points)
    return bytes(out)


# ======================================================================================================
# Passphrase escrow — split a random master R, seal the passphrase under R (fail-closed AEAD integrity).
# ======================================================================================================

@dataclass(frozen=True)
class EscrowRequest:
    """The OPT-IN escrow parameters. Constructing one is the operator's explicit choice to escrow; the
    default (no request) is :func:`maybe_escrow` returning ``None`` and doing nothing."""

    threshold: int
    share_count: int


@dataclass(frozen=True)
class EscrowBundle:
    """The output of escrowing a passphrase. ``sealed_passphrase`` is PUBLIC (a ciphertext under the split
    master — safe to store with the backup); ``shares`` are SECRET, one per holder, kept apart. ``threshold``
    and ``share_count`` echo the request for display/records."""

    sealed_passphrase: bytes
    shares: tuple[Share, ...]
    threshold: int
    share_count: int

    def public_metadata(self) -> dict:
        """The non-secret record to register/store alongside the backup (NEVER a share, NEVER the master)."""
        return {
            "scheme": "shamir-gf256-over-sealed-master",
            "threshold": self.threshold,
            "share_count": self.share_count,
            "group_id": self.shares[0].group_id if self.shares else "",
            "sealed_passphrase_b64": base64.b64encode(self.sealed_passphrase).decode("ascii"),
            "sealed_passphrase_sha256": hashlib.sha256(self.sealed_passphrase).hexdigest(),
        }


def escrow_passphrase(passphrase: str, *, threshold: int, share_count: int,
                      rng: Callable[[int], bytes] = os.urandom) -> EscrowBundle:
    """OPT-IN: escrow ``passphrase`` under an m-of-n split. Mints a fresh 32-byte master ``R``, Shamir-splits
    ``R`` into ``share_count`` shares at ``threshold``, and seals the passphrase UNDER ``R`` with the reviewed
    AEAD. Any ``m`` shares recover it; any ``m-1`` cannot. Fail-closed on bad params / empty passphrase."""
    _validate_params(threshold, share_count)
    if not isinstance(passphrase, str) or passphrase == "":
        raise EscrowError("passphrase must be a non-empty string")
    master = rng(_MASTER_LEN)
    if len(master) != _MASTER_LEN:
        raise EscrowError("rng did not deliver enough bytes for the escrow master")
    shares = split_secret(master, threshold=threshold, share_count=share_count, rng=rng)
    sealed = seal(master, passphrase.encode("utf-8"), context=_ESCROW_CONTEXT)
    return EscrowBundle(sealed_passphrase=sealed, shares=tuple(shares),
                        threshold=threshold, share_count=share_count)


def recover_passphrase(sealed_passphrase: bytes, shares: Sequence[Share]) -> str:
    """Recover the passphrase from a threshold set of ``shares`` and the public ``sealed_passphrase`` blob.
    Reconstructs the master ``R`` (:func:`recover_secret` enforces the threshold) and OPENS the sealed blob
    under it. FAIL-CLOSED: an insufficient / mismatched / tampered share set reconstructs the WRONG ``R``,
    the AEAD tag fails, and this raises :class:`EscrowError` — it NEVER returns a wrong passphrase."""
    master = recover_secret(shares)
    if len(master) != _MASTER_LEN:
        raise EscrowError("recovered master is the wrong size — these shares are not a passphrase escrow")
    try:
        plaintext = unseal(master, bytes(sealed_passphrase), context=_ESCROW_CONTEXT)
    except SealError as exc:
        raise EscrowError(
            "the recovered master did NOT open the sealed passphrase — the shares are below threshold, from "
            "a different escrow, or tampered. Fail-closed: no passphrase is returned (a wrong passphrase is "
            "NEVER surfaced).") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - a sealed passphrase is always valid utf-8
        raise EscrowError("recovered passphrase is not valid UTF-8 (corrupt escrow blob)") from exc


def maybe_escrow(passphrase: str, *, escrow: Optional[EscrowRequest] = None,
                 rng: Callable[[int], bytes] = os.urandom) -> Optional[EscrowBundle]:
    """The OPT-IN gate: escrow is OFF by default. With ``escrow=None`` (the default — declined) this returns
    ``None`` and does NOTHING — the caller's flow is byte-for-byte unchanged, the passphrase is not split and
    no share exists. ONLY when the operator supplies an :class:`EscrowRequest` is a bundle produced. This is
    the single choke point that makes "declining escrow changes nothing" true by construction."""
    if escrow is None:
        return None
    return escrow_passphrase(passphrase, threshold=escrow.threshold,
                             share_count=escrow.share_count, rng=rng)


def parse_public_metadata(doc: str) -> tuple[bytes, int, str]:
    """Read a bundle's :meth:`EscrowBundle.public_metadata` JSON back into
    ``(sealed_passphrase_bytes, threshold, group_id)`` for a recovery. Fail-closed on malformation or a
    sealed-blob hash that does not match its bytes (a corrupted record is refused, not silently used)."""
    try:
        d = json.loads(doc)
        sealed = base64.b64decode(str(d["sealed_passphrase_b64"]), validate=True)
        threshold = int(d["threshold"])
        gid = str(d["group_id"])
        want_hash = str(d.get("sealed_passphrase_sha256", ""))
    except (ValueError, KeyError, TypeError, binascii.Error) as exc:
        raise EscrowError(f"malformed escrow metadata: {exc}") from exc
    if want_hash and hashlib.sha256(sealed).hexdigest() != want_hash:
        raise EscrowError("escrow metadata sealed-blob hash does not match its bytes (corrupt record)")
    return sealed, threshold, gid
