"""Slice S5 — an OIDC Relying Party for the SIGIL cockpit, SHIPPED OFF BY DEFAULT.

This module is the SOVEREIGN, offense-free protocol/crypto core for the OIDC login. It NEVER touches the
network unless the cockpit is explicitly opted in (`config.oidc_enabled()`); the two routes that use it are
registered in `ui.server` ONLY when the toggle is on, so with the toggle off the cockpit is byte-identical
(no `/api/oidc/*` route, no egress, no new surface).

Two doctrines shape every line here:

  • IDENTITY, NOT AUTHORITY. OIDC proves *who you are* (a verified `id_token`). It NEVER carries a role.
    The caller (`ui.server`) maps the verified identity to an owner-signed `governor.account` grant and takes
    the role FROM THAT GRANT — an OIDC identity with no matching owner-signed account is REFUSED. The
    single-owner-key / nothing-self-authorizes doctrine is preserved: the IdP authenticates, the owner still
    authorizes.

  • PROVE, DON'T TRUST. The `id_token` is verified by RE-EXECUTING its signature against the IdP's published
    JWKS (asymmetric only), plus every registered claim check (iss / aud / exp / iat / nbf / nonce). We reject
    `alg: none`, any symmetric alg, and any alg the RP did not configure (algorithm-confusion defence: we do
    not even implement HMAC verification, and we bind the alg family to the JWK key type). A single-use,
    server-minted `nonce` (bound to the `state` at login) defeats id_token replay; a single-use `state`
    defeats callback CSRF and nonce/state mix-and-match.

Crypto uses the vendored `cryptography` library (NOT a hand-rolled ASN.1/JWT parser). Imports are stdlib +
`cryptography` + `sigil.config` only — no `framework` / `strix` (FATAL-2 clean).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# --- alg registry: ASYMMETRIC ONLY --------------------------------------------------------------------
# We deliberately map ONLY asymmetric algorithms. A symmetric alg (HS*) or `none` is not present here at all,
# so it can never be selected — the algorithm-confusion class (an attacker submitting `alg:HS256` and signing
# with the RSA *public* key as the HMAC secret) is closed by construction: no HMAC code path exists, and the
# per-alg key-type binding below (RS*/PS* ⇒ RSA JWK, ES* ⇒ EC JWK) rejects a family/key mismatch too.
_RSA_PKCS1_ALGS = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}
_RSA_PSS_ALGS = {"PS256": hashes.SHA256, "PS384": hashes.SHA384, "PS512": hashes.SHA512}
# ES* → (hash, curve, coordinate byte-length). P-521 ⇒ 66 bytes per r/s (521 bits rounded up).
_EC_ALGS = {"ES256": (hashes.SHA256, SECP256R1, 32),
            "ES384": (hashes.SHA384, SECP384R1, 48),
            "ES512": (hashes.SHA512, SECP521R1, 66)}
KNOWN_ASYMMETRIC_ALGS = frozenset(_RSA_PKCS1_ALGS) | frozenset(_RSA_PSS_ALGS) | frozenset(_EC_ALGS)
_JWK_CRV = {"P-256": SECP256R1, "P-384": SECP384R1, "P-521": SECP521R1}


class OidcError(Exception):
    """A fail-closed OIDC refusal (misconfiguration, a token that fails verification, an unreachable IdP).
    The route turns this into a 401/500 with a terse message; it never leaks token internals."""


# --- config ------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    authorize_endpoint: str
    token_endpoint: str
    jwks_uri: str
    scopes: str
    username_claim: str
    signing_algs: tuple = ("RS256",)
    clock_skew_seconds: int = 60

    @staticmethod
    def from_settings(settings: dict) -> "OidcConfig":
        """Build (and VALIDATE, fail-closed) the config from `config.oidc_settings()`. Every endpoint is
        required (a blank one is a misconfiguration, not a silent default), and the signing-alg allowlist
        must be non-empty AND contain only KNOWN asymmetric algs — a configured `none`/`HS256` is refused
        here so it can never even reach token verification."""
        algs = tuple(a.strip().upper() for a in (settings.get("signing_algs") or []) if a.strip())
        if not algs:
            raise OidcError("SIGIL_OIDC_SIGNING_ALGS is empty (need at least one asymmetric alg, e.g. RS256)")
        bad = [a for a in algs if a not in KNOWN_ASYMMETRIC_ALGS]
        if bad:
            raise OidcError(f"refusing non-asymmetric / unknown id_token signing alg(s): {bad} "
                            f"(allowed: {sorted(KNOWN_ASYMMETRIC_ALGS)}; `none`/HS* are never permitted)")
        required = {
            "issuer": settings.get("issuer", ""),
            "client_id": settings.get("client_id", ""),
            "redirect_uri": settings.get("redirect_uri", ""),
            "authorize_endpoint": settings.get("authorize_endpoint", ""),
            "token_endpoint": settings.get("token_endpoint", ""),
            "jwks_uri": settings.get("jwks_uri", ""),
        }
        missing = sorted(k for k, v in required.items() if not str(v or "").strip())
        if missing:
            raise OidcError(f"OIDC is enabled but these SIGIL_OIDC_* settings are unset: {missing}")
        try:
            skew = int(settings.get("clock_skew_seconds", 60))
        except (TypeError, ValueError):
            skew = 60
        return OidcConfig(
            issuer=str(required["issuer"]).strip(),
            client_id=str(required["client_id"]).strip(),
            client_secret=str(settings.get("client_secret", "") or ""),
            redirect_uri=str(required["redirect_uri"]).strip(),
            authorize_endpoint=str(required["authorize_endpoint"]).strip(),
            token_endpoint=str(required["token_endpoint"]).strip(),
            jwks_uri=str(required["jwks_uri"]).strip(),
            scopes=str(settings.get("scopes", "openid") or "openid").strip(),
            username_claim=str(settings.get("username_claim", "preferred_username") or
                               "preferred_username").strip(),
            signing_algs=algs,
            clock_skew_seconds=max(0, skew),
        )


def load_config() -> OidcConfig:
    """The active OIDC config, resolved from the environment (via `config.oidc_settings()`)."""
    from ..config import oidc_settings
    return OidcConfig.from_settings(oidc_settings())


# --- base64url + JWK → public key --------------------------------------------------------------------
def _b64url_decode(seg: str) -> bytes:
    """Strict URL-safe base64 decode with padding restored. Any malformed segment is a fail-closed refusal
    (never a partial/heuristic parse)."""
    if not isinstance(seg, str) or seg == "":
        raise OidcError("empty/invalid base64url segment")
    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (ValueError, TypeError) as e:
        raise OidcError("malformed base64url segment") from e


def _b64url_uint(seg: str) -> int:
    return int.from_bytes(_b64url_decode(seg), "big")


def _public_key_from_jwk(jwk: dict, alg: str):
    """Construct a public key object from a JWKS entry, ENFORCING that the JWK key type matches the alg
    family (RS*/PS* ⇒ RSA, ES* ⇒ EC). A `use:"enc"` key is refused (a signature verification must use a
    signing key). This is a second, independent guard against algorithm confusion."""
    if not isinstance(jwk, dict):
        raise OidcError("JWKS entry is not an object")
    if str(jwk.get("use", "sig")) == "enc":
        raise OidcError("refusing to verify a signature with an encryption (use:enc) key")
    kty = str(jwk.get("kty", ""))
    if alg in _RSA_PKCS1_ALGS or alg in _RSA_PSS_ALGS:
        if kty != "RSA":
            raise OidcError(f"alg {alg} requires an RSA key, JWKS key is kty={kty!r}")
        n, e = jwk.get("n"), jwk.get("e")
        if not isinstance(n, str) or not isinstance(e, str):
            raise OidcError("RSA JWK missing n/e")
        return RSAPublicNumbers(e=_b64url_uint(e), n=_b64url_uint(n)).public_key()
    if alg in _EC_ALGS:
        if kty != "EC":
            raise OidcError(f"alg {alg} requires an EC key, JWKS key is kty={kty!r}")
        crv = str(jwk.get("crv", ""))
        curve = _JWK_CRV.get(crv)
        _, expected_curve, _ = _EC_ALGS[alg]
        if curve is None or curve is not expected_curve:
            raise OidcError(f"alg {alg} requires curve {expected_curve.__name__}, JWK crv={crv!r}")
        x, y = jwk.get("x"), jwk.get("y")
        if not isinstance(x, str) or not isinstance(y, str):
            raise OidcError("EC JWK missing x/y")
        return EllipticCurvePublicNumbers(_b64url_uint(x), _b64url_uint(y), curve()).public_key()
    raise OidcError(f"unsupported id_token alg: {alg!r}")


def _verify_signature(alg: str, public_key, signing_input: bytes, signature: bytes) -> None:
    """Re-execute the JWS signature verification for `alg`. Raises OidcError on ANY failure (bad signature,
    wrong key type, malformed EC point length). Never returns a boolean — a caller cannot forget to check."""
    try:
        if alg in _RSA_PKCS1_ALGS:
            public_key.verify(signature, signing_input, padding.PKCS1v15(), _RSA_PKCS1_ALGS[alg]())
            return
        if alg in _RSA_PSS_ALGS:
            h = _RSA_PSS_ALGS[alg]
            public_key.verify(signature, signing_input,
                              padding.PSS(mgf=padding.MGF1(h()), salt_length=padding.PSS.DIGEST_LENGTH), h())
            return
        if alg in _EC_ALGS:
            h, _curve, coord = _EC_ALGS[alg]
            # JWS ECDSA is the raw fixed-length r||s concatenation; `cryptography` wants a DER-encoded sig.
            if len(signature) != 2 * coord:
                raise OidcError(f"ES signature length {len(signature)} != {2 * coord} for {alg}")
            r = int.from_bytes(signature[:coord], "big")
            s = int.from_bytes(signature[coord:], "big")
            public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(h()))
            return
    except InvalidSignature as e:
        raise OidcError("id_token signature is invalid") from e
    except OidcError:
        raise
    except Exception as e:  # noqa: BLE001 — malformed key/point material → fail-closed refusal, not a crash
        raise OidcError("id_token signature verification failed") from e
    raise OidcError(f"unsupported id_token alg: {alg!r}")


def _select_jwk(jwks_keys: list, kid: str) -> dict:
    """Select the JWKS entry to verify against. If the header carries a `kid`, an EXACT match is required
    (an attacker controls the header, but can only point at a real published key — they still cannot forge a
    signature). If the header has no `kid`, use the sole key when JWKS has exactly one, else refuse the
    ambiguity."""
    if not isinstance(jwks_keys, list) or not jwks_keys:
        raise OidcError("empty JWKS")
    if kid:
        for k in jwks_keys:
            if isinstance(k, dict) and str(k.get("kid", "")) == kid:
                return k
        raise OidcError(f"no JWKS key matches kid={kid!r}")
    if len(jwks_keys) == 1 and isinstance(jwks_keys[0], dict):
        return jwks_keys[0]
    raise OidcError("id_token header has no kid and JWKS has multiple keys (ambiguous)")


# --- the id_token verification (the red-pen keystone) ------------------------------------------------
def _reject_non_finite(literal: str):
    """`json.loads` calls this for the JSON tokens NaN / Infinity / -Infinity (RFC 8259 forbids them).
    We fail CLOSED so an id_token carrying a non-finite numeric literal is rejected at PARSE — a token with
    exp:NaN / Infinity (or nbf:NaN) would otherwise SLIP the freshness checks, since every comparison with
    NaN is False. Belt-and-suspenders with the `math.isfinite` guard in `_num`."""
    raise OidcError(f"id_token contains a non-finite JSON literal ({literal})")


def _num(claim, name: str) -> float:
    try:
        v = float(claim)
    except (TypeError, ValueError) as e:
        raise OidcError(f"id_token {name} claim is not numeric") from e
    if not math.isfinite(v):                              # NaN / +/-Infinity => INVALID (fail closed)
        raise OidcError(f"id_token {name} claim is not a finite number")
    return v


def verify_id_token(id_token: str, *, jwks_keys: list, issuer: str, client_id: str,
                    expected_nonce: str, allowed_algs, now: float, skew: int = 60) -> dict:
    """Verify an id_token and return its validated claims, or raise OidcError. Order matters — SIGNATURE
    FIRST (never trust an unverified payload), THEN registered-claim checks:

      1. exactly three JWS segments; header parses; `alg` is a str, is in `allowed_algs`, and is NOT `none`
         / symmetric (belt-and-suspenders — `allowed_algs` is asymmetric-only, but we hard-reject anyway).
      2. select the JWK by `kid`; bind alg-family↔key-type; RE-EXECUTE the signature over `header.payload`.
      3. iss == issuer; client_id ∈ aud (and azp==client_id when present); exp/iat/nbf within skew;
         nonce present and equal (constant-time) to the single-use nonce minted at login.

    `expected_nonce` MUST be the non-empty nonce bound to the login's `state`; a blank one is refused so a
    token that simply omits `nonce` can never satisfy the check."""
    if not isinstance(id_token, str) or id_token.count(".") != 2:
        raise OidcError("id_token is not a well-formed compact JWS")
    header_b64, payload_b64, sig_b64 = id_token.split(".")

    try:
        header = json.loads(_b64url_decode(header_b64), parse_constant=_reject_non_finite)
    except (ValueError, json.JSONDecodeError) as e:
        raise OidcError("id_token header is not valid JSON") from e
    if not isinstance(header, dict):
        raise OidcError("id_token header is not an object")
    alg = header.get("alg")
    if not isinstance(alg, str):
        raise OidcError("id_token header has no string alg")
    alg = alg.upper()
    # HARD reject `none` and any symmetric alg regardless of the allowlist (defence in depth).
    if alg == "NONE" or alg.startswith("HS") or alg not in KNOWN_ASYMMETRIC_ALGS:
        raise OidcError(f"refusing id_token alg {header.get('alg')!r} (none / symmetric / unknown)")
    allowed = {a.upper() for a in (allowed_algs or ())}
    if alg not in allowed:
        raise OidcError(f"id_token alg {alg} is not in the configured allowlist {sorted(allowed)}")

    jwk = _select_jwk(jwks_keys, str(header.get("kid", "")))
    # An `alg` declared on the JWK, if present, must agree with the header alg (some IdPs omit it).
    jwk_alg = jwk.get("alg")
    if isinstance(jwk_alg, str) and jwk_alg.upper() != alg:
        raise OidcError(f"JWKS key alg {jwk_alg} disagrees with id_token alg {alg}")
    public_key = _public_key_from_jwk(jwk, alg)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    _verify_signature(alg, public_key, signing_input, _b64url_decode(sig_b64))

    # Signature verified — NOW the payload can be trusted enough to parse and check.
    try:
        claims = json.loads(_b64url_decode(payload_b64), parse_constant=_reject_non_finite)
    except (ValueError, json.JSONDecodeError) as e:
        raise OidcError("id_token payload is not valid JSON") from e
    if not isinstance(claims, dict):
        raise OidcError("id_token payload is not an object")

    if str(claims.get("iss", "")) != str(issuer):
        raise OidcError("id_token iss does not match the configured issuer")

    aud = claims.get("aud")
    aud_set = {aud} if isinstance(aud, str) else (set(aud) if isinstance(aud, list) else set())
    if client_id not in aud_set:
        raise OidcError("id_token aud does not contain the configured client_id")
    if "azp" in claims and str(claims.get("azp")) != str(client_id):
        raise OidcError("id_token azp is not the configured client_id")

    if "exp" not in claims:
        raise OidcError("id_token has no exp")
    if now > _num(claims["exp"], "exp") + skew:
        raise OidcError("id_token is expired")
    if "nbf" in claims and now < _num(claims["nbf"], "nbf") - skew:
        raise OidcError("id_token is not yet valid (nbf)")
    if "iat" in claims and _num(claims["iat"], "iat") > now + skew:
        raise OidcError("id_token iat is in the future")

    nonce = claims.get("nonce")
    if not expected_nonce or not isinstance(nonce, str) or \
            not hmac.compare_digest(nonce, str(expected_nonce)):
        raise OidcError("id_token nonce is missing or does not match the login nonce")

    return claims


def identity_from_claims(claims: dict, username_claim: str) -> str:
    """Extract the username the id_token asserts (the configured claim, e.g. preferred_username / email /
    sub). Returns a stripped non-empty string, or raises. This is the identity ONLY — the ROLE is looked up
    later from an owner-signed account, never taken from any claim here."""
    val = claims.get(username_claim)
    if not isinstance(val, str) or not val.strip():
        raise OidcError(f"id_token is missing a usable {username_claim!r} claim")
    return val.strip()


# --- authorize redirect + token exchange -------------------------------------------------------------
def build_authorize_url(config: OidcConfig, state: str, nonce: str) -> str:
    """The IdP authorize URL for a fresh login (response_type=code). `state` and `nonce` are the single-use
    server-minted values recorded in the state store; the IdP echoes `state` at the callback and binds
    `nonce` into the id_token."""
    params = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scope": config.scopes,
        "state": state,
        "nonce": nonce,
    }
    sep = "&" if urllib.parse.urlparse(config.authorize_endpoint).query else "?"
    return config.authorize_endpoint + sep + urllib.parse.urlencode(params)


# A JWKS / token response is a few KiB; cap the read so a compromised/misconfigured IdP cannot stream an
# unbounded body into the cockpit (defence-in-depth — the token path already fails closed on any parse error).
_MAX_IDP_RESPONSE_BYTES = 4 * 1024 * 1024


def _read_capped(resp) -> bytes:
    raw = resp.read(_MAX_IDP_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_IDP_RESPONSE_BYTES:
        raise OidcError("IdP response exceeded the response-size cap")
    return raw


def _http_post_form(url: str, form: dict, *, timeout: float = 10.0) -> dict:
    """POST an application/x-www-form-urlencoded body and parse a JSON response. The ONLY outbound network
    call on the token path (used only when OIDC is enabled and a callback is processed). Refuses a non-http(s)
    scheme. Injectable in `exchange_code` so tests never touch the network."""
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise OidcError(f"refusing token-endpoint request to non-http(s) URL scheme {scheme!r}")
    data = urllib.parse.urlencode(form).encode("ascii")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — scheme guarded above
        return json.loads(_read_capped(r).decode("utf-8"))


def _http_get_json(url: str, *, timeout: float = 10.0) -> dict:
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise OidcError(f"refusing JWKS request to non-http(s) URL scheme {scheme!r}")
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — scheme guarded above
        return json.loads(_read_capped(r).decode("utf-8"))


def exchange_code(config: OidcConfig, code: str, *, http_post=None) -> dict:
    """Exchange an authorization `code` for tokens at the token endpoint (client_secret_post auth). Returns
    the token response dict; raises OidcError unless it carries a non-empty string `id_token`. `http_post`
    is injectable `(url, form) -> dict` so tests use a local mock IdP with no network."""
    if not isinstance(code, str) or not code:
        raise OidcError("missing authorization code")
    poster = http_post or _http_post_form
    form = {"grant_type": "authorization_code", "code": code,
            "redirect_uri": config.redirect_uri, "client_id": config.client_id}
    if config.client_secret:
        form["client_secret"] = config.client_secret
    resp = poster(config.token_endpoint, form)
    if not isinstance(resp, dict):
        raise OidcError("token endpoint returned a non-object")
    idt = resp.get("id_token")
    if not isinstance(idt, str) or not idt:
        raise OidcError("token endpoint response carried no id_token")
    return resp


class JwksProvider:
    """Fetch + TTL-cache the IdP JWKS. `fetcher` is injectable `(url) -> dict` for tests. `keys()` returns
    the cached `keys` array, refreshing when the TTL lapses or when forced (key rotation)."""

    def __init__(self, jwks_uri: str, *, fetcher=None, ttl_seconds: float = 300.0) -> None:
        self.jwks_uri = jwks_uri
        self._fetch = fetcher or (lambda u: _http_get_json(u))
        self.ttl = float(ttl_seconds)
        self._cache: "list | None" = None
        self._fetched_at = 0.0

    def keys(self, *, now: "float | None" = None, force: bool = False) -> list:
        t = time.time() if now is None else float(now)
        if force or self._cache is None or (t - self._fetched_at) > self.ttl:
            data = self._fetch(self.jwks_uri)
            keys = data.get("keys") if isinstance(data, dict) else None
            if not isinstance(keys, list):
                raise OidcError("JWKS response has no 'keys' array")
            self._cache = keys
            self._fetched_at = t
        return self._cache


# --- single-use state→nonce store (mirrors ui.login_challenges.ChallengeLedger) ----------------------
class OidcStateStore:
    """A durable, atomic single-use ledger binding each login `state` to the `nonce` minted with it — one
    marker file per state, where the atomic exclusive-create (mint) and atomic unlink (consume) are the
    serialization points that make single-use hold even under concurrent callbacks. This mirrors the S3
    challenge ledger exactly (sha256(state)-named marker: no traversal, no newline injection; a per-mint
    sweep + a hard cap bound the directory), with ONE addition: the marker STORES the bound nonce, so the
    callback recovers the exact nonce that was tied to this state — a nonce/state mix-and-match (a valid
    state paired with a different login's nonce) cannot pass, and a replayed callback finds its state spent.
    Stdlib only; offense-free by construction."""

    _DEFAULT_TTL_SECONDS = 600.0          # the round-trip through the IdP (interactive login) — a few minutes
    _DEFAULT_MAX_OUTSTANDING = 8192

    def __init__(self, path, *, ttl_seconds: float = _DEFAULT_TTL_SECONDS,
                 max_outstanding: int = _DEFAULT_MAX_OUTSTANDING) -> None:
        self.dir = Path(path)
        self.ttl = float(ttl_seconds)
        self.max_outstanding = int(max_outstanding)

    def _marker(self, state: str) -> Path:
        digest = hashlib.sha256(state.encode("utf-8")).hexdigest()   # fixed [0-9a-f]{64}: no traversal
        return self.dir / digest

    @staticmethod
    def _unlink(path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _sweep(self, now: float) -> int:
        live = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for entry in entries:
            try:
                rec = json.loads(Path(entry.path).read_text(encoding="utf-8"))
                issued_at = float(rec["iat"])
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                self._unlink(entry.path)                  # unreadable / corrupt marker → reap it
                continue
            if now - issued_at > self.ttl:
                self._unlink(entry.path)                  # expired → dead, reap it
            else:
                live += 1
        return live

    def issue(self, state: str, nonce: str, *, now: "float | None" = None) -> None:
        """Record a freshly-minted (state, nonce) pair as OUTSTANDING (single-use). Sweeps expired markers
        first (the bound), refuses at capacity, then `O_CREAT | O_EXCL`-creates the marker storing the bound
        nonce + issue time. Raises on a blank state/nonce, a full ledger, or a real I/O error."""
        st = str(state or "").strip()
        nc = str(nonce or "").strip()
        if not st or not nc:
            raise ValueError("refusing to issue an OIDC state/nonce with a blank component")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        t = time.time() if now is None else float(now)
        if self._sweep(t) >= self.max_outstanding:
            raise RuntimeError(f"OIDC state ledger at capacity ({self.max_outstanding}); retry shortly")
        marker = self._marker(st)
        payload = json.dumps({"iat": t, "nonce": nc}, ensure_ascii=False)
        fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # FileExistsError on a dup
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        self._fsync_dir()

    def consume(self, state: str, *, now: "float | None" = None) -> "str | None":
        """ATOMICALLY spend an OUTSTANDING, UNEXPIRED state and return its bound nonce (or None on unknown /
        expired / already-consumed). The `os.unlink` is the serialization point — of N concurrent consumers
        exactly one wins; the losers get FileNotFoundError and are refused (replay guard). Never raises."""
        st = str(state or "").strip()
        if not st:
            return None
        marker = self._marker(st)
        try:
            rec = json.loads(marker.read_text(encoding="utf-8"))
            issued_at = float(rec["iat"])
            nonce = str(rec["nonce"])
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None                                   # unknown / unreadable / corrupt → refuse
        try:
            os.unlink(str(marker))                        # atomic single-use: one winner
        except OSError:
            return None                                   # lost the race / already consumed → replay refused
        t = time.time() if now is None else float(now)
        if t - issued_at > self.ttl:                      # expired (marker now cleaned) → refuse
            return None
        return nonce

    def _fsync_dir(self) -> None:
        try:
            dfd = os.open(str(self.dir), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)
