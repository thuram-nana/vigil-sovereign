"""RFC-6238 TOTP (time-based one-time password) — a STDLIB-ONLY second factor for SIGIL logins (Slice S4).

A from-scratch RFC-4226 (HOTP) + RFC-6238 (TOTP) implementation using ONLY the Python standard library:
``hmac`` + ``hashlib`` + ``struct`` + ``base64`` (+ ``secrets`` for the shared-secret CSPRNG, and stdlib
``time`` / ``urllib.parse`` for the clock and the provisioning URI). NO third-party dependency — we do NOT
add ``pyotp`` to the sovereign env: the algorithm is a few lines, and every new dependency is a
supply-chain surface the sovereign core deliberately avoids. It interoperates with any standard
authenticator app (Google Authenticator, Aegis, 1Password, FreeOTP, ...) via a base32 shared secret and an
``otpauth://totp/...`` provisioning URI.

Design notes:
  * SHA1 is the DEFAULT digest — not for its strength but because it is what authenticator apps assume when
    an ``otpauth://`` URI omits ``algorithm``. TOTP's security rests on the secret's confidentiality + the
    short validity window, not on the hash's collision resistance; ``algorithm=`` is parameterised for a
    caller that pins SHA256/SHA512 on both ends.
  * The submitted-code compare is CONSTANT-TIME (``hmac.compare_digest``), and ``verify`` scans the WHOLE
    skew window without early-return, so neither whether a code matched nor WHICH step it matched leaks
    through timing.
  * ``verify`` tolerates a ±``window``-step clock skew (default ±1 = one 30 s step either side of "now")
    and RETURNS THE MATCHED STEP so the caller can record it in a per-account replay ledger. A TOTP code is
    valid for its whole step, so without that replay guard a sniffed code is replayable inside the window —
    the step this returns is exactly what the ledger keys on.

PURE stdlib and offense-free: this module imports NOTHING from ``sigil`` / ``vigil_core`` / ``framework`` /
``strix``. It holds no secret custody and does no I/O — the caller owns the secret's lifecycle (sealing it
at rest, running the replay ledger).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time as _time
from typing import Optional
from urllib.parse import quote, urlencode

_DEFAULT_DIGITS = 6
_DEFAULT_PERIOD = 30
_DEFAULT_ALGORITHM = "SHA1"
# The digests an otpauth URI may name. SHA1 is the interop default (see the module docstring).
_DIGEST = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def generate_secret(nbytes: int = 20) -> str:
    """A fresh base32 TOTP shared secret. 20 random bytes (160 bits) is the RFC-4226 recommendation and the
    authenticator-app default. Returned as UNPADDED uppercase base32 — the exact form apps and ``otpauth``
    URIs consume."""
    if int(nbytes) < 16:
        raise ValueError("a TOTP secret must be at least 16 bytes (128 bits) of entropy")
    return base64.b32encode(secrets.token_bytes(int(nbytes))).decode("ascii").rstrip("=")


def _decode_secret(secret_b32: str) -> bytes:
    """Decode a (padded or unpadded) base32 secret to raw key bytes. Fail-closed with ValueError on garbage
    — never a bare ``binascii.Error`` bubbling out of a verify."""
    s = str(secret_b32 or "").strip().replace(" ", "").upper()
    if not s:
        raise ValueError("empty TOTP secret")
    pad = (-len(s)) % 8
    try:
        return base64.b32decode(s + ("=" * pad), casefold=True)
    except Exception as e:  # noqa: BLE001 — binascii.Error (a ValueError subclass) or any decode fault
        raise ValueError(f"malformed base32 TOTP secret: {type(e).__name__}") from e


def current_step(at: Optional[float] = None, *, period: int = _DEFAULT_PERIOD) -> int:
    """The TOTP step counter for time ``at`` (default: now). C = floor((now - T0) / period), with T0 = 0
    per RFC-6238."""
    t = _time.time() if at is None else float(at)
    return int(t // int(period))


def code_for_step(secret_b32: str, step: int, *, digits: int = _DEFAULT_DIGITS,
                  algorithm: str = _DEFAULT_ALGORITHM) -> str:
    """HOTP(K, step) — RFC-4226 HMAC over the 8-byte big-endian counter, dynamic truncation to a 31-bit
    integer, mod 10**digits, zero-padded to ``digits``."""
    digestmod = _DIGEST.get(str(algorithm).upper())
    if digestmod is None:
        raise ValueError(f"unsupported TOTP algorithm {algorithm!r}")
    key = _decode_secret(secret_b32)
    counter = struct.pack(">Q", int(step) & 0xFFFFFFFFFFFFFFFF)          # 8-byte big-endian moving factor
    mac = hmac.new(key, counter, digestmod).digest()
    offset = mac[-1] & 0x0F                                             # low nibble selects the slice offset
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF   # 31-bit dynamic truncation
    return str(truncated % (10 ** int(digits))).zfill(int(digits))


def code_now(secret_b32: str, *, at: Optional[float] = None, digits: int = _DEFAULT_DIGITS,
             period: int = _DEFAULT_PERIOD, algorithm: str = _DEFAULT_ALGORITHM) -> str:
    """The current TOTP code — convenience for enrollment self-checks / tests."""
    return code_for_step(secret_b32, current_step(at, period=period), digits=digits, algorithm=algorithm)


def verify(secret_b32: str, code: str, *, at: Optional[float] = None, window: int = 1,
           digits: int = _DEFAULT_DIGITS, period: int = _DEFAULT_PERIOD,
           algorithm: str = _DEFAULT_ALGORITHM) -> Optional[int]:
    """Verify a submitted ``code`` against the secret, tolerating ±``window`` steps of clock skew.

    Returns the MATCHED step (an int) on success, or ``None`` on any failure. The caller MUST record the
    matched step in a per-account replay ledger and refuse a repeat: a TOTP code is valid for its whole
    step, so without that guard a code sniffed once is replayable across the window. The compare is
    constant-time and the whole window is scanned without early-return, so timing reveals neither success
    nor which step matched."""
    c = str(code or "").strip()
    if not c or not c.isdigit() or len(c) != int(digits):
        return None
    now_step = current_step(at, period=period)
    w = max(0, int(window))
    matched: Optional[int] = None
    for step in range(now_step - w, now_step + w + 1):
        candidate = code_for_step(secret_b32, step, digits=digits, algorithm=algorithm)
        if hmac.compare_digest(candidate, c):
            matched = step                                             # no break: constant work over the window
    return matched


def provisioning_uri(secret_b32: str, *, account_name: str, issuer: str,
                     digits: int = _DEFAULT_DIGITS, period: int = _DEFAULT_PERIOD,
                     algorithm: str = _DEFAULT_ALGORITHM) -> str:
    """Build the standard ``otpauth://totp/{issuer}:{account}?secret=...&issuer=...`` URI an authenticator
    app scans. This carries the PLAINTEXT secret, so it is shown to the operator exactly ONCE at enrollment
    and never persisted (the spine keeps only the sealed blob). ``issuer``/``account`` are percent-encoded
    into the label so a name with reserved characters cannot corrupt the URI."""
    label = quote(f"{issuer}:{account_name}", safe="")
    params = {"secret": str(secret_b32), "issuer": str(issuer),
              "algorithm": str(algorithm).upper(), "digits": int(digits), "period": int(period)}
    return f"otpauth://totp/{label}?{urlencode(params)}"
