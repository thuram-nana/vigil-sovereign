"""Slice S5 — the OIDC Relying Party (SHIPPED OFF BY DEFAULT). Lanes:

  * OFF-by-default: with SIGIL_OIDC_ENABLED unset the /api/oidc/* routes are UNREGISTERED — every method/path
    404s and the cockpit is byte-identical (no egress). A single affirmative env turns them on.
  * happy path: a valid id_token whose identity maps to an owner-signed account yields a WORKING bearer for
    THAT account's role (RS256 and ES256 both verify). The role comes from the owner-signed grant, NEVER from
    a claim (a token carrying `role:owner` for a `viewer` account still resolves to `viewer`).
  * negative control: a VERIFIED OIDC identity with NO owner-signed account is REFUSED (401, no bearer).
  * id_token verification: alg:none, HS256 (algorithm-confusion), a wrong kid, a bad signature, a bad iss,
    a bad aud, an expired token, and a missing / mismatched nonce each → 401 with NO bearer.
  * single-use: the `state` (which carries the bound `nonce`) is single-use — a replayed callback is refused;
    the OidcStateStore binds state↔nonce so a mix-and-match fails.
  * second factor: a TOTP-enrolled mapped account still needs its second factor (the redirect flow can't
    carry a code) → refused.
  * MUTATION: neutering `_verify_signature` (accept any) flips the bad-signature case pass→leak, proving the
    signature check is load-bearing.
  * FATAL-2: oidc.py imports no framework/strix.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:packages/core/vigil_core \
     /home/kali/vigil/.venv-sovereign/bin/python -m pytest apps/sigil/tests/test_oidc.py -q
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import http.cookies
import itertools
import json
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from sigil.governor.accounts import AccountsRegistry
from sigil.governor.identity import ensure_owner_keypair, owner_pubkey
from sigil.spine.store import SpineStore
from sigil.ui import oidc as _oidc
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-oidc-xyz"
ISSUER = "https://idp.internal.tailnet/realms/vigil"      # an OPERATOR-RUN IdP identifier (tunnel-reachable)
CLIENT_ID = "vigil-cockpit"
REDIRECT_URI = "http://127.0.0.1:8733/api/oidc/callback"
_SID_COOKIE = "sigil_oidc_sid"       # the HttpOnly session-binding cookie the RP sets at /api/oidc/login
_iss = itertools.count(1)
# a minimal, VALID from_settings() input with NO username_claim (so the immutable `sub` default applies)
_BASE_SETTINGS = {"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s", "redirect_uri": REDIRECT_URI,
                  "authorize_endpoint": "http://127.0.0.1:1/a", "token_endpoint": "http://127.0.0.1:1/t",
                  "jwks_uri": "http://127.0.0.1:1/j", "scopes": "openid", "signing_algs": ["RS256"],
                  "clock_skew_seconds": 60}


def _issue() -> float:
    return float(next(_iss))


# ------------------------------------------------------------------ base64url / int helpers
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _itb(n: int, length: "int | None" = None) -> bytes:
    length = length or max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big")


# ------------------------------------------------------------------ the in-process mock IdP
class MockIdP:
    """A tiny local IdP: an RSA (RS256) and an EC/P-256 (ES256) signing key, a JWKS derived from them, and a
    flexible id_token minter that can emit both valid tokens and every attack variant. NO network."""

    def __init__(self) -> None:
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_kid = "rsa-key-1"
        self.ec_priv = ec.generate_private_key(ec.SECP256R1())
        self.ec_kid = "ec-key-1"
        self.next_id_token: "str | None" = None            # the token the mock token-endpoint will return
        self.last_token_form: "dict | None" = None         # the form the RP posted to /token (PKCE assertions)

    # --- JWKS ---
    def _rsa_jwk(self) -> dict:
        n = self.rsa_priv.public_key().public_numbers()
        return {"kty": "RSA", "kid": self.rsa_kid, "use": "sig", "alg": "RS256",
                "n": _b64u(_itb(n.n)), "e": _b64u(_itb(n.e))}

    def _ec_jwk(self) -> dict:
        p = self.ec_priv.public_key().public_numbers()
        return {"kty": "EC", "kid": self.ec_kid, "use": "sig", "alg": "ES256", "crv": "P-256",
                "x": _b64u(_itb(p.x, 32)), "y": _b64u(_itb(p.y, 32))}

    def jwks(self) -> dict:
        return {"keys": [self._rsa_jwk(), self._ec_jwk()]}

    # --- injectable hooks for build_server ---
    def http_post(self, url: str, form: dict) -> dict:      # the mock token endpoint
        self.last_token_form = dict(form)                  # capture (PKCE code_verifier assertions)
        return {"id_token": self.next_id_token, "token_type": "Bearer", "access_token": "opaque"}

    def jwks_fetcher(self, url: str) -> dict:               # the mock JWKS endpoint
        return self.jwks()

    # --- id_token minting (valid + every attack) ---
    def mint(self, *, nonce: str, alg: str = "RS256", kid: "str | None" = None, iss: str = ISSUER,
             aud=CLIENT_ID, sub: str = "sub-abc", username: str = "alice", exp_delta: int = 300,
             iat_delta: int = 0, nbf_delta: "int | None" = None, include_nonce: bool = True,
             sign_key: str = "correct", extra: "dict | None" = None) -> str:
        now = int(time.time())
        claims = {"iss": iss, "aud": aud, "sub": sub, "preferred_username": username,
                  "exp": now + exp_delta, "iat": now + iat_delta}
        if nbf_delta is not None:
            claims["nbf"] = now + nbf_delta
        if include_nonce:
            claims["nonce"] = nonce
        if extra:
            claims.update(extra)
        default_kid = self.ec_kid if alg == "ES256" else self.rsa_kid
        header = {"alg": alg, "typ": "JWT", "kid": kid if kid is not None else default_kid}
        h = _b64u(json.dumps(header, separators=(",", ":")).encode())
        p = _b64u(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode("ascii")
        sig = self._sign(alg, signing_input, sign_key)
        return f"{h}.{p}.{_b64u(sig)}"

    def _sign(self, alg: str, signing_input: bytes, sign_key: str) -> bytes:
        if alg == "none":
            return b""
        if alg == "HS256":
            # the classic algorithm-confusion PoC: HMAC the signing input with the RSA PUBLIC key bytes.
            pub_pem = self.rsa_priv.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            return hmac.new(pub_pem, signing_input, hashlib.sha256).digest()
        if alg == "RS256":
            key = self.rsa_priv if sign_key == "correct" else \
                rsa.generate_private_key(public_exponent=65537, key_size=2048)   # "wrong" → bad signature
            return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        if alg == "ES256":
            key = self.ec_priv if sign_key == "correct" else ec.generate_private_key(ec.SECP256R1())
            der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der)
            return _itb(r, 32) + _itb(s, 32)               # JWS raw r||s (not DER)
        raise AssertionError(f"unhandled alg {alg}")


# ------------------------------------------------------------------ live-server harness
def _enable_oidc(monkeypatch, idp: MockIdP, *, enabled: bool = True) -> None:
    if enabled:
        monkeypatch.setenv("SIGIL_OIDC_ENABLED", "1")
    else:
        monkeypatch.delenv("SIGIL_OIDC_ENABLED", raising=False)
    monkeypatch.setenv("SIGIL_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("SIGIL_OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("SIGIL_OIDC_CLIENT_SECRET", "cockpit-secret")
    monkeypatch.setenv("SIGIL_OIDC_REDIRECT_URI", REDIRECT_URI)
    monkeypatch.setenv("SIGIL_OIDC_AUTHORIZE_ENDPOINT", "http://127.0.0.1:1/authorize")
    monkeypatch.setenv("SIGIL_OIDC_TOKEN_ENDPOINT", "http://127.0.0.1:1/token")
    monkeypatch.setenv("SIGIL_OIDC_JWKS_URI", "http://127.0.0.1:1/jwks")
    monkeypatch.setenv("SIGIL_OIDC_SIGNING_ALGS", "RS256,ES256")
    monkeypatch.setenv("SIGIL_OIDC_USERNAME_CLAIM", "preferred_username")


def _serve(idp: MockIdP):
    """A live cockpit over an isolated temp spine, with the mock IdP wired in as the token/JWKS hooks."""
    ensure_owner_keypair()                                 # persisted owner key in the test SIGIL_HOME
    spine = tempfile.mktemp(suffix=".jsonl")
    SpineStore(spine).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    s = build_server(token=TOKEN, port=0, spine_path=spine,
                     oidc_http_post=idp.http_post, oidc_jwks_fetcher=idp.jwks_fetcher)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port, spine


def _mkaccount(spine: str, username: str, role: str, *, totp_secret: "str | None" = None):
    """Owner-sign an active account on the SAME spine + owner key the server trusts."""
    reg = AccountsRegistry(SpineStore(spine), owner_key=ensure_owner_keypair(), trusted_pubkey=owner_pubkey())
    reg.create(username, role, bearer_token=(username + "-bearer-" + "z" * 16), issued_at=_issue())
    if totp_secret is not None:
        reg.enroll_totp(username, totp_secret, issued_at=_issue())   # a dummy sealed blob — _check_totp only
        #                                                              needs it non-empty to demand a code


def _raw(port: int, method: str, path: str, headers: "dict | None" = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": f"127.0.0.1:{port}"}
    if headers:
        h.update(headers)
    conn.request(method, path, headers=h)
    r = conn.getresponse()
    body = r.read()
    status, loc = r.status, r.getheader("Location")
    conn.close()
    doc = json.loads(body) if body and r.getheader("Content-Type", "").startswith("application/json") else None
    return status, doc, loc


def _login(port: int):
    """Hit /api/oidc/login (no redirect-follow); return (state, nonce, sid, params). Captures BOTH the
    single-use `state`/`nonce` AND the PKCE `code_challenge` from the authorize URL, and the value of the
    HttpOnly session-binding cookie set in the Set-Cookie header — the callback needs that cookie back."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/api/oidc/login", headers={"Host": f"127.0.0.1:{port}"})
    r = conn.getresponse()
    r.read()
    status, loc, setck = r.status, r.getheader("Location"), r.getheader("Set-Cookie")
    conn.close()
    assert status == 302 and loc, (status, loc)
    params = parse_qs(urlparse(loc).query)
    sid = http.cookies.SimpleCookie(setck)[_SID_COOKIE].value if setck else ""
    return params["state"][0], params["nonce"][0], sid, params


def _callback(port: int, idp: MockIdP, id_token: str, state: str, *, sid: "str | None" = None,
              code: str = "auth-code-1"):
    """Drive the callback. `sid` (when given) is replayed as the session-binding cookie — the SAME browser
    that started the flow. Omit it (or pass a different value) to model a login-CSRF / injected response."""
    idp.next_id_token = id_token
    headers = {"Cookie": f"{_SID_COOKIE}={sid}"} if sid else None
    return _raw(port, "GET", f"/api/oidc/callback?code={code}&state={state}", headers)


# ================================================================== OFF-by-default
def test_off_by_default_routes_404_and_are_byte_identical(monkeypatch):
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp, enabled=False)          # env present but SIGIL_OIDC_ENABLED unset ⇒ OFF
    from sigil import config
    assert config.oidc_enabled() is False
    s, port, _spine = _serve(idp)
    tok = {"X-SIGIL-Token": TOKEN}                          # pass the generic /api/ auth gate to see the
    try:                                                    # TRUE disposition of the path (unregistered → 404)
        # the OIDC GET paths are indistinguishable from any never-defined /api path — byte-identical, not a
        # real endpoint. (Without a token an unknown /api/* 401s at the shared gate first, as it always has.)
        unknown = _raw(port, "GET", "/api/zzz-never-defined", tok)[0]
        assert _raw(port, "GET", "/api/oidc/login", tok)[0] == unknown == 404
        assert _raw(port, "GET", "/api/oidc/callback?code=x&state=y", tok)[0] == 404
        assert _raw(port, "POST", "/api/oidc/login")[0] == 404          # POST unknown → 404 pre-auth
        # the rest of the cockpit is unchanged (whoami still answers token-optional)
        assert _raw(port, "GET", "/api/whoami")[0] == 200
    finally:
        s.shutdown()


def test_config_toggle_affirmative_and_negative(monkeypatch):
    from sigil import config
    for v in ("1", "true", "TRUE", "yes", "on", "enabled"):
        monkeypatch.setenv("SIGIL_OIDC_ENABLED", v)
        assert config.oidc_enabled() is True, v
    for v in ("", "0", "false", "no", "off", "disabled", "banana"):
        monkeypatch.setenv("SIGIL_OIDC_ENABLED", v)
        assert config.oidc_enabled() is False, v
    monkeypatch.delenv("SIGIL_OIDC_ENABLED", raising=False)
    assert config.oidc_enabled() is False


# ================================================================== happy path
def test_valid_rs256_id_token_maps_to_account_and_yields_working_bearer(monkeypatch):
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "alice", "operator")
        state, nonce, sid, _ = _login(port)
        token = idp.mint(nonce=nonce, alg="RS256", username="alice")
        status, doc, _ = _callback(port, idp, token, state, sid=sid)
        assert status == 200 and doc["authenticated"] is True
        assert doc["username"] == "alice" and doc["role"] == "operator"
        bearer = doc["bearer"]
        assert bearer and _raw(port, "GET", "/api/snapshot", {"X-SIGIL-Token": bearer})[0] == 200
    finally:
        s.shutdown()


def test_valid_es256_id_token_also_verifies(monkeypatch):
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "erin", "analyst")
        state, nonce, sid, _ = _login(port)
        token = idp.mint(nonce=nonce, alg="ES256", username="erin")
        status, doc, _ = _callback(port, idp, token, state, sid=sid)
        assert status == 200 and doc["role"] == "analyst"
        assert _raw(port, "GET", "/api/snapshot", {"X-SIGIL-Token": doc["bearer"]})[0] == 200
    finally:
        s.shutdown()


def test_role_comes_from_owner_signed_grant_not_from_a_claim(monkeypatch):
    """Negative control for the CORE invariant: an attacker-flavoured id_token that asserts `role:owner` (and
    even a `roles`/`groups` array) still resolves to the account's OWNER-SIGNED role — the claim is ignored."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "mallory", "viewer")             # owner granted VIEWER only
        state, nonce, sid, _ = _login(port)
        token = idp.mint(nonce=nonce, username="mallory",
                         extra={"role": "owner", "roles": ["owner", "operator"], "groups": ["admins"]})
        status, doc, _ = _callback(port, idp, token, state, sid=sid)
        assert status == 200 and doc["username"] == "mallory"
        assert doc["role"] == "viewer", "the ROLE must come from the owner-signed grant, never from a claim"
    finally:
        s.shutdown()


def test_verified_identity_with_no_owner_signed_account_is_refused(monkeypatch):
    """A fully VALID id_token for an identity that has NO owner-signed account → 401, no bearer. The token
    alone never mints access or a role (nothing-self-authorizes)."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        state, nonce, sid, _ = _login(port)
        token = idp.mint(nonce=nonce, username="ghost")    # no _mkaccount("ghost")
        status, doc, _ = _callback(port, idp, token, state, sid=sid)
        assert status == 401 and doc.get("authenticated") is False
        assert "no owner-signed account" in doc["error"]
        assert "bearer" not in doc
    finally:
        s.shutdown()


# ================================================================== id_token verification attacks
@pytest.mark.parametrize("variant", ["alg_none", "hs256_confusion", "wrong_kid", "bad_signature",
                                     "bad_iss", "bad_aud", "expired", "missing_nonce", "mismatched_nonce",
                                     "exp_nan", "exp_inf", "nbf_inf"])
def test_id_token_verification_rejects_every_attack(monkeypatch, variant):
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "alice", "operator")             # a REAL mapped account, so ONLY the token is bad
        state, nonce, sid, _ = _login(port)
        if variant == "alg_none":
            token = idp.mint(nonce=nonce, alg="none", sign_key="none")
        elif variant == "hs256_confusion":
            token = idp.mint(nonce=nonce, alg="HS256")
        elif variant == "wrong_kid":
            token = idp.mint(nonce=nonce, kid="no-such-kid")
        elif variant == "bad_signature":
            token = idp.mint(nonce=nonce, sign_key="wrong")
        elif variant == "bad_iss":
            token = idp.mint(nonce=nonce, iss="https://evil.example.com/")
        elif variant == "bad_aud":
            token = idp.mint(nonce=nonce, aud="some-other-client")
        elif variant == "expired":
            token = idp.mint(nonce=nonce, exp_delta=-3600, iat_delta=-7200)
        elif variant == "missing_nonce":
            token = idp.mint(nonce=nonce, include_nonce=False)
        elif variant == "mismatched_nonce":
            token = idp.mint(nonce="a-different-nonce-entirely")
        elif variant == "exp_nan":
            token = idp.mint(nonce=nonce, extra={"exp": float("nan")})     # NaN slips `now > exp+skew`
        elif variant == "exp_inf":
            token = idp.mint(nonce=nonce, extra={"exp": float("inf")})     # a never-expiring token
        elif variant == "nbf_inf":
            token = idp.mint(nonce=nonce, extra={"nbf": float("inf")})     # non-finite nbf
        status, doc, _ = _callback(port, idp, token, state, sid=sid)
        assert status == 401, f"{variant} should be refused"
        assert doc.get("authenticated") is False and "bearer" not in doc, variant
    finally:
        s.shutdown()


def test_state_is_single_use_replay_is_refused(monkeypatch):
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "alice", "operator")
        state, nonce, sid, _ = _login(port)
        token = idp.mint(nonce=nonce, username="alice")
        assert _callback(port, idp, token, state, sid=sid)[0] == 200            # first use wins
        status, doc, _ = _callback(port, idp, token, state, sid=sid)            # same state again → spent
        assert status == 401 and "state" in doc["error"] and "bearer" not in doc
    finally:
        s.shutdown()


def test_totp_enrolled_mapped_account_still_needs_second_factor(monkeypatch):
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        # a dummy non-empty "sealed" blob is enough: _check_totp demands a code the redirect can't carry
        _mkaccount(spine, "carol", "operator", totp_secret=base64.b64encode(b"sealed-placeholder").decode())
        state, nonce, sid, _ = _login(port)
        token = idp.mint(nonce=nonce, username="carol")
        status, doc, _ = _callback(port, idp, token, state, sid=sid)
        assert status == 401 and doc.get("second_factor_required") is True
        assert "bearer" not in doc, "OIDC identity-1 alone must not mint a bearer for a 2FA account"
    finally:
        s.shutdown()


# ================================================================== W16-6: PKCE + session-bound state
def test_authorize_carries_pkce_and_token_exchange_sends_matching_verifier(monkeypatch):
    """The authorize redirect MUST carry a PKCE `code_challenge` (+ method=S256), and the token exchange MUST
    send the matching `code_verifier` (never the challenge). Closes authorization-code injection/interception:
    a stolen `code` is useless without the session-held verifier."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "alice", "operator")
        state, nonce, sid, params = _login(port)
        assert params.get("code_challenge_method") == ["S256"], "authorize must request PKCE S256"
        challenge = params["code_challenge"][0]
        assert challenge and "code_verifier" not in params, "the verifier must NOT ride in the authorize URL"
        token = idp.mint(nonce=nonce, username="alice")
        status, doc, _ = _callback(port, idp, token, state, sid=sid)
        assert status == 200 and doc["authenticated"] is True
        form = idp.last_token_form or {}
        assert "code_verifier" in form and "code_challenge" not in form, "verifier goes to /token, not authorize"
        # the verifier the RP sent, S256-hashed, must equal the challenge it advertised at authorize
        assert _oidc.pkce_challenge_s256(form["code_verifier"]) == challenge
    finally:
        s.shutdown()


def test_callback_requires_session_bound_cookie_defeats_login_csrf(monkeypatch):
    """NEGATIVE CONTROL for login-CSRF / authorization-response injection: the callback binds `state` to the
    initiating browser via an HttpOnly cookie set at /api/oidc/login. A response presented by a DIFFERENT
    browser (no cookie, or a mismatched one — an attacker feeding a victim the attacker's own auth response)
    is REFUSED with no bearer; the SAME browser (correct cookie) still completes."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "alice", "operator")
        # (a) MISSING cookie — the classic login-CSRF: victim's browser lacks the initiating session cookie.
        state, nonce, sid, _ = _login(port)
        token = idp.mint(nonce=nonce, username="alice")
        status, doc, _ = _callback(port, idp, token, state, sid=None)
        assert status == 401 and "session" in doc["error"] and "bearer" not in doc
        # (b) MISMATCHED cookie — an attacker's own session id cannot vouch for a victim's browser.
        state2, nonce2, sid2, _ = _login(port)
        token2 = idp.mint(nonce=nonce2, username="alice")
        status, doc, _ = _callback(port, idp, token2, state2, sid="not-the-initiating-session")
        assert status == 401 and "session" in doc["error"] and "bearer" not in doc
        # (c) POSITIVE: the SAME browser (correct cookie) completes — the gate is not a blanket deny.
        state3, nonce3, sid3, _ = _login(port)
        token3 = idp.mint(nonce=nonce3, username="alice")
        status, doc, _ = _callback(port, idp, token3, state3, sid=sid3)
        assert status == 200 and doc["authenticated"] is True and doc["bearer"]
    finally:
        s.shutdown()


def test_login_sets_httponly_samesite_lax_session_cookie(monkeypatch):
    """DOC-TRUTH + hardening: /api/oidc/login sets the session-binding cookie HttpOnly, SameSite=Lax,
    Path=/api/oidc (so script can't read it, a cross-site subresource can't send it, but the IdP's top-level
    GET redirect back to the callback still carries it)."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/oidc/login", headers={"Host": f"127.0.0.1:{port}"})
        r = conn.getresponse()
        r.read()
        setck = r.getheader("Set-Cookie") or ""
        conn.close()
        assert setck.startswith(_SID_COOKIE + "="), setck
        low = setck.lower()
        assert "httponly" in low and "samesite=lax" in low and "path=/api/oidc" in low, setck
    finally:
        s.shutdown()


def test_default_username_claim_is_immutable_sub(monkeypatch):
    """With SIGIL_OIDC_USERNAME_CLAIM unset the mapping claim DEFAULTS to the IMMUTABLE `sub`, NOT the mutable
    `preferred_username`. An id_token whose `preferred_username` names a real account but whose `sub` does not
    must map on `sub` (and vice-versa) — so a user who can change their preferred_username cannot steer onto
    another owner-signed account."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    monkeypatch.delenv("SIGIL_OIDC_USERNAME_CLAIM", raising=False)      # exercise the DEFAULT
    from sigil import config
    assert config.oidc_settings()["username_claim"] == "sub"
    assert _oidc.OidcConfig.from_settings({**_BASE_SETTINGS}).username_claim == "sub"
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "sub-immutable-9", "operator")               # account keyed on the immutable sub
        state, nonce, sid, _ = _login(port)
        # preferred_username points at a DIFFERENT (non-existent) account; the mapping must ignore it.
        token = idp.mint(nonce=nonce, sub="sub-immutable-9", username="attacker-chosen-handle")
        status, doc, _ = _callback(port, idp, token, state, sid=sid)
        assert status == 200 and doc["username"] == "sub-immutable-9" and doc["role"] == "operator"
    finally:
        s.shutdown()


def test_exchange_code_refuses_blank_pkce_verifier():
    """Unit: the token exchange REFUSES a blank code_verifier (PKCE is required, not best-effort)."""
    cfg = _oidc.OidcConfig.from_settings({**_BASE_SETTINGS})
    with pytest.raises(_oidc.OidcError):
        _oidc.exchange_code(cfg, "auth-code-1", code_verifier="",
                            http_post=lambda url, form: {"id_token": "x.y.z"})
    with pytest.raises(_oidc.OidcError):
        _oidc.build_authorize_url(cfg, "state", "nonce", code_challenge="")   # authorize needs the challenge


def test_pkce_s256_matches_rfc7636_appendix_b_vector():
    """The RFC 7636 Appendix B worked example pins the S256 transform (BASE64URL-NOPAD(SHA256(verifier)))."""
    assert _oidc.pkce_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == \
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


# ================================================================== MUTATION: verify is load-bearing
def test_neutering_signature_verify_flips_bad_signature_pass_to_leak(monkeypatch):
    """With the real verifier a wrong-key signature is refused (401). Monkeypatching `_verify_signature` to a
    no-op (accept any) makes the SAME token mint a bearer — proving the signature re-execution is what stops
    the leak. Everything else about the token is valid, so only the signature check is under test."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp)
    s, port, spine = _serve(idp)
    try:
        _mkaccount(spine, "alice", "operator")
        state, nonce, sid, _ = _login(port)
        bad = idp.mint(nonce=nonce, username="alice", sign_key="wrong")
        assert _callback(port, idp, bad, state, sid=sid)[0] == 401             # real verify refuses the bad signature

        monkeypatch.setattr(_oidc, "_verify_signature", lambda *a, **k: None)   # NEUTER the check
        state2, nonce2, sid2, _ = _login(port)
        bad2 = idp.mint(nonce=nonce2, username="alice", sign_key="wrong")
        status, doc, _ = _callback(port, idp, bad2, state2, sid=sid2)
        assert status == 200 and doc.get("bearer"), "neutering signature verify must LEAK — check is load-bearing"
    finally:
        s.shutdown()


# ================================================================== unit lane: state store + verifier
def test_state_store_single_use_binds_nonce_verifier_sid_and_refuses_mix(tmp_path):
    store = _oidc.OidcStateStore(tmp_path / "oidc-state")
    store.issue("state-A", "nonce-A", verifier="ver-A", sid_hash="sid-A")
    store.issue("state-B", "nonce-B", verifier="ver-B", sid_hash="sid-B")
    rec = store.consume("state-A")                         # returns the BOUND (nonce, verifier, sid_hash)
    assert (rec.nonce, rec.verifier, rec.sid_hash) == ("nonce-A", "ver-A", "sid-A")
    assert store.consume("state-A") is None                # single-use: replay refused
    assert store.consume("unknown-state") is None          # unknown → refused (mix-and-match can't pass)
    assert store.consume("state-B").verifier == "ver-B"    # a different state carries a different binding


def test_state_store_ttl_expiry(tmp_path):
    store = _oidc.OidcStateStore(tmp_path / "oidc-state", ttl_seconds=10.0)
    store.issue("s", "n", now=1000.0)
    assert store.consume("s", now=1005.0).nonce == "n"     # within TTL
    store.issue("s2", "n2", now=1000.0)
    assert store.consume("s2", now=1100.0) is None         # past TTL → refused


def test_verify_id_token_unit_rejects_none_and_hs256_directly():
    idp = MockIdP()
    keys = idp.jwks()["keys"]
    common = dict(jwks_keys=keys, issuer=ISSUER, client_id=CLIENT_ID, expected_nonce="n",
                  allowed_algs=("RS256", "ES256"), now=time.time(), skew=60)
    for alg in ("none", "HS256"):
        tok = idp.mint(nonce="n", alg=alg, sign_key="none" if alg == "none" else "correct")
        with pytest.raises(_oidc.OidcError):
            _oidc.verify_id_token(tok, **common)
    # non-finite time claims (NaN / Infinity) are rejected at parse — they must never slip the freshness
    # checks (every comparison with NaN is False; Infinity never expires)
    for bad in ({"exp": float("nan")}, {"exp": float("inf")}, {"nbf": float("inf")}):
        with pytest.raises(_oidc.OidcError):
            _oidc.verify_id_token(idp.mint(nonce="n", extra=bad), **common)
    # a blank expected_nonce can never be satisfied (a token omitting nonce must not slip through)
    good = idp.mint(nonce="n")
    with pytest.raises(_oidc.OidcError):
        _oidc.verify_id_token(good, **{**common, "expected_nonce": ""})
    # the genuine token verifies
    claims = _oidc.verify_id_token(good, **common)
    assert claims["preferred_username"] == "alice"


def test_config_from_settings_rejects_symmetric_and_missing(monkeypatch):
    base = {"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s", "redirect_uri": REDIRECT_URI,
            "authorize_endpoint": "http://127.0.0.1:1/a", "token_endpoint": "http://127.0.0.1:1/t",
            "jwks_uri": "http://127.0.0.1:1/j", "scopes": "openid", "username_claim": "preferred_username",
            "signing_algs": ["RS256"], "clock_skew_seconds": 60}
    assert _oidc.OidcConfig.from_settings(base).client_id == CLIENT_ID
    with pytest.raises(_oidc.OidcError):
        _oidc.OidcConfig.from_settings({**base, "signing_algs": ["HS256"]})      # symmetric refused
    with pytest.raises(_oidc.OidcError):
        _oidc.OidcConfig.from_settings({**base, "signing_algs": ["none"]})       # none refused
    with pytest.raises(_oidc.OidcError):
        _oidc.OidcConfig.from_settings({**base, "jwks_uri": ""})                 # missing endpoint refused


# =============================== W17-2 (#536): reachable through `vigil up` =====================
def _send(port: int, method: str, path: str, body: "bytes | None" = None):
    """Like _raw but can carry a POST body (needed to probe the POST-only bootstrap routes)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": f"127.0.0.1:{port}"}
    if body is not None:
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    raw = r.read()
    status, loc = r.status, r.getheader("Location")
    conn.close()
    doc = json.loads(raw) if raw and r.getheader("Content-Type", "").startswith("application/json") else None
    return status, doc, loc


def test_whoami_advertises_oidc_enabled_to_the_login_gate(monkeypatch):
    """W17-2: the (token-optional, bootstrap) /api/whoami tells the anonymous login gate whether to offer the
    SSO button. With the RP ON it reports oidc:true; the flag carries no secret and is reachable before any
    session exists (so the gate can decide what to render)."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp, enabled=True)
    s, port, _ = _serve(idp)
    try:
        st, doc, _ = _raw(port, "GET", "/api/whoami")           # NO token — the anonymous probe
        assert st == 200 and doc["authenticated"] is False
        assert doc.get("oidc") is True
    finally:
        s.shutdown()


def test_whoami_oidc_flag_is_false_when_the_rp_is_off(monkeypatch):
    """NEGATIVE CONTROL for the flag: with the RP OFF the OIDC routes are unregistered, so the gate must NOT
    show the SSO button — whoami reports oidc:false (a button that always showed would dead-end on a 404)."""
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp, enabled=False)
    s, port, _ = _serve(idp)
    try:
        st, doc, _ = _raw(port, "GET", "/api/whoami")
        assert st == 200 and doc.get("oidc") is False
        # and the RP really is inactive: /api/oidc/login is unregistered, so it never drives a 302 redirect
        # (it falls through to the auth gate). The point is that no SSO flow can start when the RP is off.
        assert _send(port, "GET", "/api/oidc/login")[0] != 302
    finally:
        s.shutdown()


def test_bootstrap_paths_are_all_pre_auth_and_the_gate_is_enforced(monkeypatch):
    """The proxy forwards exactly server.BOOTSTRAP_PATHS without proxy auth (test_uiproxy_peruser_auth pins
    that). Here we prove each listed path is GENUINELY pre-auth: with NO bearer it reaches its own handler
    (never the missing-token 401), and it is registered (not 404). The NEGATIVE CONTROL: a normal authed
    route (/api/settings) with no token IS refused with that exact missing-token 401 — so the gate is real,
    not a no-op, and BOOTSTRAP_PATHS cannot list a route that is actually token-gated."""
    from sigil.ui.server import BOOTSTRAP_PATHS
    idp = MockIdP()
    _enable_oidc(monkeypatch, idp, enabled=True)             # so the OIDC pair is registered
    s, port, _ = _serve(idp)
    try:
        # negative control — the auth gate IS enforced on a non-bootstrap route
        st, doc, _ = _raw(port, "GET", "/api/settings")
        assert st == 401 and doc and "missing/invalid token" in (doc.get("error") or "")
        # the method + (query/body) each bootstrap route actually answers, with NO bearer presented
        plan = {
            "/api/whoami": ("GET", "/api/whoami", None),
            "/api/login": ("POST", "/api/login", b"{}"),
            "/api/login/challenge": ("POST", "/api/login/challenge", b"{}"),
            "/api/oidc/login": ("GET", "/api/oidc/login", None),
            "/api/oidc/callback": ("GET", "/api/oidc/callback?code=x&state=y", None),
        }
        assert set(plan) == set(BOOTSTRAP_PATHS), \
            "the pre-auth probe plan must cover exactly BOOTSTRAP_PATHS (a new one must be probed too)"
        for path in sorted(BOOTSTRAP_PATHS):
            method, url, body = plan[path]
            st, doc, _ = _send(port, method, url, body)
            assert st != 404, f"{path} is not registered — it would ship unreachable: {st}"
            err = (doc or {}).get("error", "") if isinstance(doc, dict) else ""
            assert "missing/invalid token" not in err, f"{path} is token-gated, not pre-auth: {st} {err!r}"
    finally:
        s.shutdown()


# ================================================================== FATAL-2
def test_fatal2_oidc_module_is_offense_free():
    from sigil.reuse import assert_no_offense
    assert_no_offense()
    src = Path(_oidc.__file__).read_text(encoding="utf-8")
    assert "import framework" not in src and "from framework" not in src
    assert "import strix" not in src and "from strix" not in src
