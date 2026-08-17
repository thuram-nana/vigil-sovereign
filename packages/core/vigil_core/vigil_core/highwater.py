"""Durable, file-backed anti-rollback high-water floor (namespace-pure core, VF-1b).

A tiny, dependency-minimal twin of the sovereign spine floor (``apps/sigil/sigil/spine/floor.py``) and the
offense evidence twin (``framework/v2/evidence/cli.py:_load_highwater``), promoted into ``vigil_core`` so an
offense-side, framework-free consumer (the Continuous Attestation Log, VF-1b) can persist a monotonic floor
WITHOUT importing either app. It stores exactly the two monotonic quantities a :class:`SignedChainHead`
anchors::

    {"schema_version": 1, "entry_count": N, "last_seq": M}

``entry_count`` is the **PRIMARY** monotonic guard. ``last_seq`` is 0-indexed, so it reads 0 for BOTH an
empty chain AND a one-record chain — a 1→0 truncation would slip past a ``last_seq``-only check but is
caught by ``entry_count`` (this is the exact lesson the sovereign floor's docstring records). Both are
checked; ``entry_count`` is the one that cannot be fooled by the 0-index degeneracy.

Deterministic (no wallclock / rng), stdlib + ``vigil_core`` only, so it stays importable in BOTH the
sovereign and offense process without co-loading ``framework`` or ``sigil`` (the P5 two-env boundary).

HONEST LIMIT (do NOT overclaim, mirrors the sovereign floor §1.3): this is a **LOCAL** floor — an UNSIGNED
file at 0600. A SAME-HOST attacker with the owner's UID (or root) defeats the local verify path by rewriting
the log AND this floor together (a local verifier re-reads the floor from that same attacker-controlled
disk). The floor's real anti-rollback guarantee therefore holds only against (i) an attacker who can
overwrite the log/head but NOT this floor, and (ii) an OUT-OF-BAND verifier that retained a newer floor. A
fully-dishonest producer that rewrites everything is closed only by the out-of-band witness (VF-1c), not by
this file. What this module DOES give, unconditionally, is last-writer-MONOTONIC, downgrade-refusing,
crash-safe advance under a cross-process lock — so no honest process ever lowers the floor, even racing.
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, Union

from .canonical import canonical_json
from .crypto import sign, verify_one

try:
    import fcntl
except ImportError:  # pragma: no cover — non-POSIX; the advance degrades to best-effort (single host)
    fcntl = None  # type: ignore[assignment]

_log = logging.getLogger(__name__)

_PathLike = Union[str, os.PathLike]
_SCHEMA_VERSION = 1

# DOMAIN-SEPARATION tags for the OFFENSE high-water GOVERNANCE signature (C.2 — bring the offense floor to
# parity with the signed sovereign floor). The signing bytes begin with the tag so a governance signature over
# a high-water floor can NEVER be confused with a signature over any other artifact.
#
# There are TWO high-water VARIANTS that share these signing helpers, and they MUST NOT cross-verify: this
# module's attestation-log floor commits ``{schema_version, entry_count, last_seq}`` while the evidence twin
# (``framework/v2/evidence/cli.py``) commits only ``{last_seq}``. Because ``_hw_core_bytes`` signs a DENY-list
# core (every field except the sig envelope), a signature minted for one variant would otherwise verify for the
# other whenever their field sets are compatible (the evidence verifier reads ``last_seq`` from the richer
# attestation-log core). So each variant carries its OWN domain tag; a signature under one tag can never verify
# under the other. Bump a version suffix if that variant's signed-core shape ever changes (invalidates its prior
# signatures, exactly like a floor re-sign).
_HW_DOMAIN = b"vigil-highwater-v1\x00"                    # this module's attestation-log floor variant
_HW_EVIDENCE_DOMAIN = b"vigil-highwater-evidence-v1\x00"  # the evidence-cli {last_seq} floor variant
# Persisted fields that are NOT part of the signed core (the signature envelope itself); stripped before the
# signing bytes are computed so sign() and verify() operate over the SAME monotonic core.
_SIG_ENVELOPE = ("sig", "pubkey")
# Warn at most once per process (on the verify path) that a floor is UNSIGNED — mirrors the sovereign
# ``_warned_unsigned_floor``.
_warned_unsigned_highwater = False


class HighWaterError(ValueError):
    """A PRESENT-but-unreadable / malformed floor. Raised (never silently treated as absent) so a corrupt
    floor fails CLOSED — reading it as "no floor" would fail-OPEN the whole anti-rollback guarantee."""


class HighWaterDowngrade(HighWaterError):
    """The INTENDED refusal: an advance whose head would lower a monotonic field of the floor (a stale
    concurrent writer, or a rolled-back head). Typed distinctly from a load/write FAILURE so a caller can
    treat this one as a benign 'someone already advanced higher' while surfacing a real IO error loudly."""


def _is_nonneg_int(x: object) -> bool:
    # bool is an int subclass — reject it explicitly so a JSON `true` cannot masquerade as a count.
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _lock_path(p: Path) -> Path:
    return p.parent / (p.name + ".lock")


def _read_raw_highwater(p: Path) -> Optional[dict]:
    """Shared parse for the durable floor: ``None`` iff ABSENT; RAISES :class:`HighWaterError` on a
    symlink / unreadable-corrupt / non-object floor. The SINGLE site of the symlink-precedes-exists
    class-fix (both :func:`load_highwater` and :func:`read_highwater_dict` route through here, so the guard
    can never drift between them). A SYMLINK is suspicious (tamper) and ``is_symlink()`` MUST precede
    ``exists()``: ``exists()`` FOLLOWS the link and returns False for a DANGLING one, which would wrongly read
    as "absent / pre-floor" and silently skip the rollback check (twin of ``evidence/cli.py::_load_highwater``)."""
    if p.is_symlink():
        raise HighWaterError(f"durable high-water at {p} is a symlink (possible tamper) — refusing")
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise HighWaterError(f"durable high-water at {p} is present but unreadable/corrupt: {e}") from e
    if not isinstance(raw, dict):
        raise HighWaterError(f"durable high-water at {p} is not a JSON object (possible tamper)")
    return raw


def load_highwater(path: _PathLike) -> Optional[dict]:
    """Read the durable floor at ``path``. ``None`` iff ABSENT (pre-floor / never-advanced — floor checks are
    then skipped, byte-identical to no floor). RAISES :class:`HighWaterError` on a PRESENT-but-corrupt or
    shape-invalid floor: that is suspicious (tamper / a partial write that survived) and must fail CLOSED,
    never read as absent. Returns the normalised ``{"entry_count": N, "last_seq": M}`` (both non-negative
    ints); extra persisted fields (schema_version, and any ``sig``/``pubkey`` envelope) are dropped from the
    returned view. This stays a PURE PARSE of the monotonic quantities — the governance-signature check lives
    in :func:`verify_highwater_signature` at the caller that holds the trust anchor, exactly like
    ``floor.load_floor`` vs ``floor.verify_floor_signature`` (one key source, no divergence)."""
    p = Path(path)
    raw = _read_raw_highwater(p)
    if raw is None:
        return None
    ec, ls = raw.get("entry_count"), raw.get("last_seq")
    if not (_is_nonneg_int(ec) and _is_nonneg_int(ls)):
        raise HighWaterError(f"durable high-water at {p} has a missing/invalid entry_count/last_seq "
                             f"(possible tamper): entry_count={ec!r} last_seq={ls!r}")
    return {"entry_count": int(ec), "last_seq": int(ls)}


def read_highwater_dict(path: _PathLike) -> Optional[dict]:
    """Read the FULL persisted floor dict (including any ``sig``/``pubkey`` envelope), symlink/corrupt guards
    applied — the analogue of ``floor.load_floor`` returning the whole ``Floor``. ``None`` iff ABSENT; RAISES
    :class:`HighWaterError` on symlink/corrupt/non-object. This is the input an out-of-band verifier feeds to
    :func:`verify_highwater_signature`; :func:`load_highwater` remains the normalised monotonic-only view the
    check/write paths use."""
    return _read_raw_highwater(Path(path))


def check_highwater(head, hw: Optional[dict]) -> tuple[bool, str]:
    """Reject rule (pure, side-effect-free, so it is shared by the write path's downgrade guard AND every
    read path). A validly-signed ``head`` that nonetheless sits below the floor is a ROLLBACK (stale-head
    replay / truncated log). ``hw is None`` ⇒ pass (byte-identical to no floor). ``entry_count`` is checked
    FIRST because it is the sound guard (``last_seq`` is 0 for both an empty and a 1-record chain)."""
    if hw is None:
        return True, "no durable high-water floor"
    if int(head.entry_count) < int(hw["entry_count"]):
        return False, (f"ROLLBACK: head entry_count {head.entry_count} < durable floor entry_count "
                       f"{hw['entry_count']} (truncated log / stale head replay)")
    if int(head.last_seq) < int(hw["last_seq"]):
        return False, (f"ROLLBACK: head last_seq {head.last_seq} < durable floor last_seq "
                       f"{hw['last_seq']} (stale head / truncated log replay)")
    return True, "within durable high-water floor"


# --- OFFENSE GOVERNANCE SIGNATURE (C.2): sign the offense floor to parity with the sovereign one ----------
# Structure mirrors ``apps/sigil/sigil/spine/floor.py`` (``_sign_floor`` / ``verify_floor_signature``), but
# the offense floor signs with the GOVERNANCE key (owner-tied only via the ``OFFENSE_GOVERNANCE_ROLE``
# delegation), NEVER an owner key — the offense side holds no owner key by construction (the two-env boundary).
# The helpers are generic over the persisted *core* dict AND its domain tag, so BOTH this module's
# ``{schema_version, entry_count, last_seq}`` attestation-log floor (default ``_HW_DOMAIN``) and the evidence
# twin's ``{last_seq}`` floor (``_HW_EVIDENCE_DOMAIN``, passed by the twin in ``framework/v2/evidence/cli.py``)
# sign/verify with ONE implementation while staying cryptographically NON-interchangeable. What the signature
# closes: the tamper-of-a-SIGNED-floor case (any edit to a signed floor's content breaks the signature) for a
# verifier holding the governance anchor. What it does NOT close: (1) strip-to-unsigned — an unsigned floor is
# still WARN-ACCEPTED, not rejected (the honest residual, closed only by the retained out-of-band witnessed
# checkpoint anchor, a separate slice); (2) the fully-dishonest-producer-owns-all-keys case (only an INDEPENDENT
# out-of-band witness closes that).


def _hw_core_bytes(hw: dict, domain: bytes = _HW_DOMAIN) -> bytes:
    """Domain-tagged canonical signing bytes over the monotonic core: every field EXCEPT the ``sig``/``pubkey``
    envelope, prefixed with the VARIANT's ``domain`` tag. ``sign`` (build path) and ``verify`` (check path)
    both route through here with the SAME ``domain`` so they operate over identical bytes; a signed floor's
    CONTENT cannot be edited without breaking the signature, and a signature minted under one variant's domain
    can never verify under another's (the two-variant separation — see the module notes above)."""
    core = {k: v for k, v in hw.items() if k not in _SIG_ENVELOPE}
    return domain + canonical_json(core)


def _sign_highwater(core: dict, signer, domain: bytes = _HW_DOMAIN) -> dict:
    """Attach a GOVERNANCE Ed25519 signature over the ``domain``-tagged core. ``signer`` is a
    :class:`vigil_core.crypto.KeyPair` (``.private_key_b64`` / ``.public_key_b64``) — the offense governance
    key. ``domain`` selects the variant (default this module's attestation-log floor; the evidence twin passes
    ``_HW_EVIDENCE_DOMAIN``). Returns ``{**core, "sig": …, "pubkey": …}``. Pure: no IO, no wallclock, so it
    stays deterministic and testable in isolation."""
    signature = sign(signer.private_key_b64, _hw_core_bytes(core, domain))
    return {**core, "sig": signature, "pubkey": signer.public_key_b64}


def verify_highwater_signature(hw: dict, trusted_pubkeys, domain: bytes = _HW_DOMAIN) -> tuple[bool, str]:
    """The offense floor's OWN governance-signature check (mirrors ``floor.verify_floor_signature``). ``domain``
    MUST match the variant the floor was signed under (default this module's attestation-log floor; the evidence
    twin passes ``_HW_EVIDENCE_DOMAIN``) — a floor signed under a different variant's domain fails the verify,
    which is the cross-variant separation. Fail-closed + non-bricking:

      * sig ABSENT (legacy unsigned floor) → ``(True, …)``; warn ONCE if a trusted key exists (the next
        advance re-signs it). No trusted key at all → silent accept (byte-identical to the pre-signing floor,
        so an out-of-band verifier that never provisioned a key is not bricked).
      * sig PRESENT + ``pubkey`` is a trusted governance key + verifies UNDER ``domain`` → ``(True, …)``.
      * sig PRESENT + untrusted key / malformed / does not verify (incl. a wrong-variant domain) → ``(False,
        …)`` — a tampered or cross-variant SIGNED floor is TAMPERING, the caller certifies NOTHING.

    ``trusted_pubkeys`` is any iterable of base64 governance public keys the caller trusts (out-of-band the
    owner authenticates them via the ``OFFENSE_GOVERNANCE_ROLE`` delegation). Note: this alone does NOT close
    the strip-to-unsigned case (an unsigned floor is still WARN-ACCEPTED) — that is closed only by the retained
    out-of-band witnessed checkpoint (a separate slice)."""
    global _warned_unsigned_highwater
    trusted = set(trusted_pubkeys or ())
    sig, pub = hw.get("sig"), hw.get("pubkey")
    if sig is None and pub is None:
        if trusted and not _warned_unsigned_highwater:
            _warned_unsigned_highwater = True
            _log.warning("durable offense high-water is UNSIGNED — it will be governance-signed on the next "
                         "advance. Until then a same-host attacker could strip-and-downgrade it (full "
                         "prevention needs the out-of-band witnessed checkpoint anchor).")
        return True, "high-water unsigned (legacy — accepted, will re-sign on next advance)"
    if not isinstance(sig, str) or pub not in trusted:
        return False, "durable high-water signature is not from a trusted governance key (possible tamper)"
    try:
        ok = verify_one(pub, _hw_core_bytes(hw, domain), sig)
    except Exception as e:  # noqa: BLE001 — malformed sig/key material → fail-closed, never a silent accept
        return False, f"durable high-water signature is malformed (possible tamper): {e}"
    return (True, "high-water signature verified") if ok else \
        (False, "durable high-water signature does not verify (possible tamper)")


@contextmanager
def highwater_lock(path: _PathLike) -> Iterator[None]:
    """Exclusive CROSS-PROCESS lock serializing a floor advance (and any log/head write a caller wants inside
    the same critical section) so the load→check→write triple is ATOMIC and last-writer-MONOTONIC, not
    last-writer-wins. Without it two racing advances each read a STALE prior floor, both pass the downgrade
    guard, and the later ``os.replace`` rolls the floor BACKWARDS — a false-clean window for a stale replay.
    The flock binds to a sibling ``<name>.lock`` inode so it survives the atomic replace of the floor file.
    Best-effort where ``fcntl`` is absent / the lockfile is unwritable (single-host assumption)."""
    p = Path(path)
    lockp = _lock_path(p)
    fd = None
    try:
        try:
            lockp.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(lockp), os.O_RDWR | os.O_CREAT, 0o600)
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError:  # pragma: no cover — lock unsupported on this fs; degrade best-effort
                    pass
        except OSError:
            # Cannot create/open the lockfile (read-only dir, root-owned stray lock, ENOSPC). DEGRADE to
            # best-effort UNLOCKED rather than brick the append; a genuinely unwritable dir then fails loudly
            # at the atomic write below, never silently.
            fd = None
        yield
    finally:
        if fd is not None:
            os.close(fd)


def _atomic_write_0600(p: Path, text: str) -> None:
    """Crash-safe, owner-only write: temp → fsync → os.replace → dir-fsync, 0600 throughout. A partial write
    can only ever leave the ``.tmp-*`` file (never a half-written floor), and the rename is atomic."""
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.parent / (f".{p.name}.tmp-{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(p))
    try:
        os.chmod(p, 0o600)
    except OSError:  # pragma: no cover — non-POSIX / unusual fs; content is non-secret, mode is best-effort
        pass
    try:
        dfd = os.open(str(p.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:  # pragma: no cover — dir fsync unsupported; the os.replace already committed the name
        pass


def _floor_dict(head) -> dict:
    return {"schema_version": _SCHEMA_VERSION,
            "entry_count": int(head.entry_count), "last_seq": int(head.last_seq)}


def advance_highwater(path: _PathLike, head, *, signer=None, _locked: bool = False) -> dict:
    """Advance the durable floor to a just-committed ``head`` — UPWARD-ONLY. The load→check→write runs under
    :func:`highwater_lock` and the prior floor is RE-LOADED inside the lock, so a concurrent advance that
    already wrote a HIGHER floor is observed and this stale write is REFUSED (raises :class:`HighWaterDowngrade`)
    — making the floor last-writer-MONOTONIC, never last-writer-wins. Refuses to lower any monotonic field —
    the exact thing the floor exists to prevent. Written atomically at 0600 only after the check passes.
    ``_locked=True`` when the caller already holds :func:`highwater_lock` for the same critical section
    (append_tick does) — the re-load + downgrade guard still run (defense in depth), the lock is not re-taken.

    ``signer`` (C.2 — offense parity with the signed sovereign floor): when a :class:`vigil_core.crypto.KeyPair`
    (the offense GOVERNANCE key, NEVER an owner key) is threaded in, the new floor is GOVERNANCE-SIGNED before
    the atomic write. When ``signer is None`` (every pre-C.2 caller) the write is BYTE-IDENTICAL to before — the
    unsigned floor is unchanged. Returns the persisted floor dict."""
    p = Path(path)
    if _locked:
        return _advance_locked(p, head, signer)
    with highwater_lock(p):
        return _advance_locked(p, head, signer)


def _advance_locked(p: Path, head, signer=None) -> dict:
    prior = load_highwater(p)                       # RE-LOAD under the lock — sees a racing advance / tamper
    if prior is not None:
        ok, msg = check_highwater(head, prior)
        if not ok:
            raise HighWaterDowngrade(f"refusing to advance the durable high-water DOWNWARD: {msg}")
    new = _floor_dict(head)
    if signer is not None:
        new = _sign_highwater(new, signer)          # governance signature over the domain-tagged core
    _atomic_write_0600(p, json.dumps(new, sort_keys=True))
    return new
