"""PR-H edge — enterprise SSO + SCIM over the REAL HTTP edge, end to end: the keyless customer edge (`ui.custui` +
`ui.sso_edge`) → the hop key → the sovereign cockpit's provisioner (`ui.server` `_sso_dispatch` →
`ui.sso_provision`) → the owner-signed, ceiling-capped membership.

Two in-process servers (the cockpit serving `/api/provision/*`, the customer edge pointed at it), a persisted owner
key, isolated ledgers. Load-bearing invariants (each attack below must FAIL):
  * flag OFF ⇒ every new route is exactly the edge's unknown route (GET/POST 404) or exactly what the stdlib answers
    for a method the handler lacks (PUT/PATCH/DELETE 501), byte for byte; the cockpit actions are unknown (404);
  * SAML: SP-initiated (AuthnRequest → IdP) and the ACS accepts only a Response whose SIGNED InResponseTo names THIS
    login's AuthnRequest; with no XML-DSig backend it FAILS CLOSED (the edge refuses, never bypasses); a forged /
    unsigned / wrong-key / tampered / replayed / cross-org / unsolicited assertion mints nothing; the session is
    minted only in the browser that started the login (login-CSRF);
  * enterprise OIDC: PKCE + nonce + state bound to the browser; another org's id_token is refused;
  * SCIM: org A's token on org B is 401; wrong tokens lock out only INVALID attempts (a valid IdP bearer is never
    stalled); a group named founder/owner never escalates; the per-org write budget answers 429 + Retry-After;
    DEACTIVATION kills the member's live session at once, and is refused on the very next request even where the
    edge did not see it (live `admit_customer`).

THE XML-DSig STAND-IN (honest boundary, LIMIT-sso-saml-xmldsig-backend-unprovisioned): the vetted backend (`signxml`)
is not installed in this venv, so the shipped default verifier refuses every SAML response — pinned by
`test_saml_fails_closed_without_the_xmldsig_backend`, which runs WITHOUT any stand-in. The happy-path tests swap in
`_toy_xmldsig_verifier`: a REAL RSA-PKCS1v15-SHA256 check of the assertion's ElementTree serialization under the
owner-registered IdP certificate (same contract: the ids whose signature verifies under the configured certs). It is
not exclusive-c14n — it exists so "unsigned", "signed by another key" and "tampered after signing" genuinely fail
cryptographically here, rather than being simulated by a list of accepted ids.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import http.cookies
import json
import secrets
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import HOP, TOKEN

from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.sso_config import SsoConfigRegistry
from sigil.spine.store import SpineStore
from sigil.ui import saml as uisaml
from sigil.ui.custui import CUSTOMER_COOKIE, CustomerHandler, build_customer_server
from sigil.ui.server import build_server
from sigil.ui.sso_edge import SSO_SID_COOKIE, public_urls

NS_P = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_A = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
IDP_ENTITY = "https://idp.acme.example/saml/metadata"
IDP_SSO_URL = "https://idp.acme.example/sso/saml"
OIDC_ISS = "https://login.acme-idp.example"
ORG_A, ORG_B = "org_" + "a" * 24, "org_" + "b" * 24
TOKEN_A, TOKEN_B = "scim-A-" + "x" * 40, "scim-B-" + "y" * 40


# ---- an IdP signing key + cert (the owner registers the CERT), and an attacker's key ---------------------------------
def _key_and_cert(cn: str):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(7)
         .not_valid_before(datetime(2020, 1, 1)).not_valid_after(datetime(2040, 1, 1)).sign(k, hashes.SHA256()))
    return k, c.public_bytes(serialization.Encoding.PEM).decode()


IDP_KEY, IDP_CERT = _key_and_cert("idp.acme.example")
ATTACKER_KEY, _ = _key_and_cert("evil")


def _toy_xmldsig_verifier(xml_bytes: bytes, cert_pems: tuple) -> frozenset:
    """TEST STAND-IN for the owner-provisioned XML-DSig backend (see the module note): the ids of the assertions whose
    `<ds:SignatureValue>` is a valid RSA-PKCS1v15-SHA256 signature, under one of the configured certs, of the
    assertion's ElementTree serialization with its `<ds:Signature>` removed."""
    out: set = set()
    root = ET.fromstring(xml_bytes)
    for a in root.iter(f"{{{NS_A}}}Assertion"):
        sig = a.find(f"{{{NS_DS}}}Signature")
        if sig is None:
            continue
        value = sig.findtext(f"{{{NS_DS}}}SignatureValue") or ""
        a.remove(sig)
        signed = ET.tostring(a)
        for pem in cert_pems:
            pub = x509.load_pem_x509_certificate(pem.encode()).public_key()
            try:
                pub.verify(base64.b64decode(value), signed, padding.PKCS1v15(), hashes.SHA256())
                out.add(a.get("ID"))
            except Exception:  # noqa: BLE001 — not this cert / not a valid signature
                continue
    return frozenset(out)


def _sign(xml: str, key) -> bytes:
    """Sign the ONE assertion of `xml` the way `_toy_xmldsig_verifier` checks (an enveloped <ds:Signature>)."""
    root = ET.fromstring(xml)
    a = root.find(f".//{{{NS_A}}}Assertion")
    sig_value = key.sign(ET.tostring(a), padding.PKCS1v15(), hashes.SHA256())
    s = ET.SubElement(a, f"{{{NS_DS}}}Signature")
    ET.SubElement(s, f"{{{NS_DS}}}SignatureValue").text = base64.b64encode(sig_value).decode()
    return ET.tostring(root)


def _instant(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _saml_response(*, request_id: str, audience: str, recipient: str, name_id: str, groups=(), aid: str = "",
                   issuer: str = IDP_ENTITY, response_irt: "str | None" = None) -> str:
    now = time.time()
    aid = aid or "_a" + secrets.token_hex(16)
    vals = "".join(f"<saml:AttributeValue>{g}</saml:AttributeValue>" for g in groups)
    return (f'<samlp:Response xmlns:samlp="{NS_P}" xmlns:saml="{NS_A}" ID="_r{secrets.token_hex(8)}" Version="2.0" '
            f'IssueInstant="{_instant(now)}" Destination="{recipient}" '
            f'InResponseTo="{request_id if response_irt is None else response_irt}">'
            f'<saml:Issuer>{issuer}</saml:Issuer>'
            f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f'<saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{_instant(now)}">'
            f'<saml:Issuer>{issuer}</saml:Issuer>'
            f'<saml:Subject><saml:NameID>{name_id}</saml:NameID>'
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData Recipient="{recipient}" NotOnOrAfter="{_instant(now + 300)}" '
            f'InResponseTo="{request_id}"/></saml:SubjectConfirmation></saml:Subject>'
            f'<saml:Conditions NotBefore="{_instant(now - 60)}" NotOnOrAfter="{_instant(now + 300)}">'
            f'<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>'
            f'</saml:Conditions>'
            f'<saml:AuthnStatement AuthnInstant="{_instant(now)}" SessionIndex="_s1"/>'
            f'<saml:AttributeStatement><saml:Attribute Name="groups">{vals}</saml:Attribute></saml:AttributeStatement>'
            f'</saml:Assertion></samlp:Response>')


# ---- a fake enterprise OIDC IdP (no network): real RS256 id_tokens, PKCE re-derived at the token endpoint -------------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class OidcIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes: dict = {}
        self.posts: list = []

    def jwks(self, _url):
        pub = self.key.public_key().public_numbers()
        n = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
        e = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
        return {"keys": [{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": _b64u(n), "e": _b64u(e)}]}

    def _token(self, claims: dict) -> str:
        h = _b64u(json.dumps({"alg": "RS256", "kid": "k1", "typ": "JWT"}).encode())
        p = _b64u(json.dumps(claims).encode())
        return f"{h}.{p}.{_b64u(self.key.sign(f'{h}.{p}'.encode(), padding.PKCS1v15(), hashes.SHA256()))}"

    def http_post(self, url, form):
        self.posts.append((url, dict(form)))
        claims, challenge = self.codes.pop(form.get("code"), (None, None))
        if claims is None:
            raise OSError("invalid_grant")
        if _b64u(hashlib.sha256(str(form.get("code_verifier") or "").encode()).digest()) != challenge:
            raise OSError("invalid_grant (PKCE)")                  # the verifier must re-derive the challenge
        return {"id_token": self._token(claims)}

    def authorize(self, location: str, *, sub: str, groups=(), **override) -> "tuple[str, str]":
        """What the IdP does at its authorize endpoint after the person signs in: mint a code for the client in the
        URL, bound to its PKCE challenge, carrying the nonce it was given. → (code, state)."""
        q = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        now = int(time.time())
        claims = {"iss": OIDC_ISS, "sub": sub, "aud": q["client_id"][0], "iat": now, "exp": now + 300,
                  "nonce": q["nonce"][0], "groups": list(groups)}
        claims.update(override)
        code = secrets.token_urlsafe(16)
        self.codes[code] = (claims, q["code_challenge"][0])
        return code, q["state"][0]


# ---- the two servers -------------------------------------------------------------------------------------------------
class Resp:
    def __init__(self, status: int, headers, body: bytes):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        return json.loads(self.body.decode())

    def cookie(self, name: str) -> "str | None":
        for raw in self.headers.get_all("Set-Cookie") or ():
            jar = http.cookies.SimpleCookie(raw)
            if name in jar:
                return jar[name].value
        return None

    @property
    def location(self) -> str:
        return self.headers.get("Location") or ""


def _call(port: int, method: str, path: str, *, body=None, headers=None, host: "str | None" = None) -> Resp:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    h = {"Host": host or f"127.0.0.1:{port}"}
    h.update(headers or {})
    data = body if (body is None or isinstance(body, bytes)) else json.dumps(body).encode()
    if data is not None:
        h.setdefault("Content-Length", str(len(data)))
    conn.request(method, path, body=data, headers=h)
    r = conn.getresponse()
    out = Resp(r.status, r.headers, r.read())
    conn.close()
    return out


class Stack:
    """The cockpit (provisioner) + the keyless customer edge over the hop key, with isolated ledgers."""

    def __init__(self, tmp_path, monkeypatch, *, sso: bool = True):
        from sigil import config
        monkeypatch.setenv("VIGIL_PROVISION_HOP_KEY", HOP)
        if sso:
            monkeypatch.setenv("VIGIL_CUSTOMER_SSO", "1")
        else:
            monkeypatch.delenv("VIGIL_CUSTOMER_SSO", raising=False)
        for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR",
                     "CUSTOMER_SAML_REPLAY_DIR", "SCIM_AUTH_RATELIMIT_DIR", "SCIM_WRITE_RATELIMIT_DIR",
                     "SCIM_READ_RATELIMIT_DIR", "SCIM_DEPROV_RATELIMIT_DIR", "SSO_SIGNIN_RATELIMIT_DIR"):
            monkeypatch.setattr(config, attr, tmp_path / attr.lower())
        self.tmp = tmp_path
        self.spine = str(tmp_path / "spine.jsonl")
        SpineStore(self.spine).append(kind="message", source="x", actor="user", payload={"text": "hi"})
        ensure_owner_keypair()
        self.idp = OidcIdP()
        self.sov = build_server(token=TOKEN, port=0, spine_path=self.spine, sso_oidc_http_post=self.idp.http_post,
                                sso_oidc_jwks_fetcher=self.idp.jwks)
        threading.Thread(target=self.sov.serve_forever, daemon=True).start()
        self.sport = self.sov.server_address[1]
        self.edges: list = []
        self.edge, self.port = self.new_edge("custsessions")
        self.base = f"http://127.0.0.1:{self.port}"

    def new_edge(self, name: str):
        e = build_customer_server(host="127.0.0.1", port=0, hop_key=HOP, provision_base=f"http://127.0.0.1:{self.sport}",
                                  sessions_dir=str(self.tmp / name / "sessions"))
        threading.Thread(target=e.serve_forever, daemon=True).start()
        self.edges.append(e)
        return e, e.server_address[1]

    def close(self):
        for s in (*self.edges, self.sov):
            s.shutdown()
            s.server_close()

    # -- owner setup (the persisted owner key, exactly as `sigil sso` signs) --
    def store(self) -> SpineStore:
        return SpineStore(self.spine)

    def orgs(self) -> OrgRegistry:
        return OrgRegistry(self.store())

    def cfg(self) -> SsoConfigRegistry:
        return SsoConfigRegistry(self.store())

    def urls(self, org: str) -> dict:
        return public_urls(self.base, org)

    def create_org(self, org: str) -> None:
        self.orgs().create_org(org, org[-4:], owner="cust_founder_" + org[-4:], issued_at=time.time())

    def saml_org(self, org: str, *, scim_token: str = "", group_role_map=None) -> dict:
        self.create_org(org)
        u = self.urls(org)
        self.cfg().set_saml_config(org, idp_entity_id=IDP_ENTITY, idp_certs_pem=[IDP_CERT], idp_sso_url=IDP_SSO_URL,
                                   sp_entity_id=u["saml_sp_entity_id"], acs_url=u["saml_acs_url"],
                                   default_role="viewer",
                                   group_role_map=group_role_map or {"Admins": "org_admin", "Security": "analyst"},
                                   role_cap="org_admin", scim_enabled=bool(scim_token), scim_token=scim_token,
                                   issued_at=time.time())
        return u

    def oidc_org(self, org: str, *, client_id: str, scim_token: str = "") -> dict:
        self.create_org(org)
        u = self.urls(org)
        self.cfg().set_oidc_config(org, issuer=OIDC_ISS, client_id=client_id, jwks_uri=f"{OIDC_ISS}/keys",
                                   authorize_endpoint=f"{OIDC_ISS}/authorize", token_endpoint=f"{OIDC_ISS}/token",
                                   redirect_uri=u["oidc_redirect_uri"], signing_algs=("RS256",),
                                   egress_hosts=("login.acme-idp.example",), default_role="viewer",
                                   group_role_map={"Admins": "org_admin"}, role_cap="org_admin",
                                   scim_enabled=bool(scim_token), scim_token=scim_token, issued_at=time.time())
        return u

    def role(self, username: str, org: str):
        return self.orgs().membership_role(username, org)

    def audits(self, action: str) -> list:
        return [r.payload for r in self.store().iter_records() if isinstance(r.payload, dict)
                and r.payload.get("signal") == "provision.audit" and r.payload.get("action") == action]

    # -- the browser + IdP legs --
    def get(self, path: str, *, cookie: str = "", port: "int | None" = None, **kw) -> Resp:
        return _call(port or self.port, "GET", path, headers={"Cookie": cookie} if cookie else {}, **kw)

    def start(self, org: str) -> "tuple[Resp, str]":
        r = self.get(f"/api/customer/sso/login?org={org}")
        return r, (r.cookie(SSO_SID_COOKIE) or "")

    def post_acs(self, saml_xml: bytes, relay: str, *, path: str = "/api/customer/sso/saml/acs") -> Resp:
        form = urllib.parse.urlencode({"SAMLResponse": base64.b64encode(saml_xml).decode(),
                                       "RelayState": relay}).encode()
        return _call(self.port, "POST", path, body=form,
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Origin": "https://idp.acme.example"})      # the IdP's page: a FOREIGN origin

    def scim(self, method: str, path: str, body=None, *, token: str = TOKEN_A, port: "int | None" = None,
             ip: str = "203.0.113.10") -> Resp:
        # X-Real-IP: the client address the edge trusts from its loopback reverse-proxy hop (custui `_ip`)
        h = {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json", "X-Real-IP": ip}
        return _call(port or self.port, method, path, body=body, headers=h)


@pytest.fixture
def stack(tmp_path, monkeypatch):
    s = Stack(tmp_path, monkeypatch)
    yield s
    s.close()


@pytest.fixture
def signed(monkeypatch):
    """Swap the absent XML-DSig backend for the test stand-in (a real RSA check — see the module note)."""
    monkeypatch.setattr(uisaml, "signxml_sig_verifier", _toy_xmldsig_verifier)


def _authn_request(location: str) -> "tuple[ET.Element, str]":
    q = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    xml = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15)       # raw DEFLATE, HTTP-Redirect binding
    return ET.fromstring(xml), q["RelayState"][0]


def _session_cookie(r: Resp) -> str:
    v = r.cookie(CUSTOMER_COOKIE)
    return f"{CUSTOMER_COOKIE}={v}" if v else ""


def _saml_sign_in(stack: Stack, org: str, *, name_id: str, groups=(), key=None) -> "tuple[str, str]":
    """The whole SAML round trip for `org` → (the session cookie header, the username). Asserts every hop."""
    r, sid = stack.start(org)
    assert r.status == 302 and r.location.startswith(IDP_SSO_URL + "?") and sid, (r.status, r.location)
    req, relay = _authn_request(r.location)
    u = stack.urls(org)
    xml = _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"],
                               recipient=u["saml_acs_url"], name_id=name_id, groups=groups), key or IDP_KEY)
    acs = stack.post_acs(xml, relay)
    assert acs.status == 303 and acs.location.startswith("/api/customer/sso/finish?ticket="), (acs.status, acs.location)
    assert acs.cookie(CUSTOMER_COOKIE) is None                     # never a session on the cross-site POST
    fin = stack.get(acs.location, cookie=f"{SSO_SID_COOKIE}={sid}")
    assert fin.status == 302 and fin.location == "/", (fin.status, fin.location)
    cookie = _session_cookie(fin)
    who = stack.get("/api/customer/whoami", cookie=cookie).json()
    assert who["authenticated"] is True and who["org_id"] == org
    return cookie, who["username"]


def _oidc_sign_in(stack: Stack, org: str, *, sub: str, groups=(), **override) -> Resp:
    r, sid = stack.start(org)
    assert r.status == 302 and r.location.startswith(f"{OIDC_ISS}/authorize?") and sid, (r.status, r.location)
    code, state = stack.idp.authorize(r.location, sub=sub, groups=groups, **override)
    return stack.get(f"/api/customer/sso/oidc/callback?code={code}&state={state}", cookie=f"{SSO_SID_COOKIE}={sid}")


# =====================================================================================================================
# FLAG OFF — absent, byte-identical
# =====================================================================================================================
_NEW_GETS = ("/api/customer/sso/login?org=" + ORG_A, "/api/customer/sso/finish?ticket=t",
             "/api/customer/sso/oidc/callback?code=c&state=s", f"/scim/v2/{ORG_A}/Users",
             f"/scim/v2/{ORG_A}/ServiceProviderConfig")
_NEW_POSTS = ("/api/customer/sso/saml/acs", f"/api/customer/sso/saml/acs/{ORG_A}", f"/scim/v2/{ORG_A}/Users")


def _comparable(r: Resp) -> tuple:
    return r.status, [(k, v) for k, v in r.headers.items() if k.lower() != "date"], r.body


class _Stdlib(BaseHTTPRequestHandler):
    """A handler with NO do_PUT / do_PATCH / do_DELETE: what the stdlib answers for a method a handler lacks."""
    server_version = CustomerHandler.server_version

    def log_message(self, *_a):
        pass


def test_flag_off_every_new_route_is_the_unknown_route_byte_identical(tmp_path, monkeypatch):
    s = Stack(tmp_path, monkeypatch, sso=False)
    plain = ThreadingHTTPServer(("127.0.0.1", 0), _Stdlib)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    try:
        s.saml_org(ORG_A, scim_token=TOKEN_A)        # a config signed while the flag is off stays inert
        for path in _NEW_GETS:
            unknown = "/api/customer/zz-unknown" if path.startswith("/api/") else "/zz/unknown"
            got, want = s.get(path), s.get(unknown)
            assert got.status == 404 and _comparable(got) == _comparable(want), path
        form = b"SAMLResponse=PHg%2B&RelayState=r"
        for path in _NEW_POSTS:
            unknown = "/api/customer/zz-unknown" if path.startswith("/api/") else "/zz/unknown"
            hdr = {"Content-Type": "application/x-www-form-urlencoded", "Origin": s.base,
                   "Authorization": f"Bearer {TOKEN_A}"}
            got = _call(s.port, "POST", path, body=form, headers=hdr)
            want = _call(s.port, "POST", unknown, body=form, headers=hdr)
            assert got.status in (400, 404) and _comparable(got) == _comparable(want), path
        for method in ("PUT", "PATCH", "DELETE"):
            hdr = {"Authorization": f"Bearer {TOKEN_A}", "Content-Type": "application/scim+json"}
            got = _call(s.port, method, f"/scim/v2/{ORG_A}/Users/x", body=b"{}", headers=hdr)
            want = _call(plain.server_address[1], method, f"/scim/v2/{ORG_A}/Users/x", body=b"{}", headers=hdr)
            assert got.status == 501 and _comparable(got) == _comparable(want), method
        assert not s.edge.sso_state_dir.exists()                              # no login state was ever minted
        assert not s.audits("scim_auth") and not s.audits("sso_login")       # the provisioner was never reached
    finally:
        plain.shutdown()
        plain.server_close()
        s.close()


def _hop(sport: int, action: str, body: dict) -> Resp:
    """A correctly hop-stamped provision call straight to the cockpit (what the edge sends)."""
    from vigil_core.hopauth import body_binding, stamp_hop_assertion
    data = json.dumps(body).encode()
    path = f"/api/provision/{action}"
    ts = str(int(time.time()))
    sig = stamp_hop_assertion(HOP, "", f"{action}:{body_binding(HOP, data)}", "POST", path, ts)
    return _call(sport, "POST", path, body=data, headers={"Content-Type": "application/json",
                                                         "X-VIGIL-Provision-Principal": "",
                                                         "X-VIGIL-Provision-Ts": ts, "X-VIGIL-Provision-Sig": sig})


def test_flag_off_the_cockpit_actions_are_unknown_and_on_they_exist(tmp_path, monkeypatch):
    s = Stack(tmp_path, monkeypatch, sso=False)
    try:
        s.saml_org(ORG_A, scim_token=TOKEN_A)
        unknown = _hop(s.sport, "zz_not_an_action", {"org_id": ORG_A})
        assert unknown.status == 404
        calls = {"sso_login_start": {"org_id": ORG_A, "ip": "1.2.3.4"},
                 "sso_saml_acs": {"org_id": ORG_A, "saml_response": "PHg+", "request_id": "_r", "ip": "1.2.3.4"},
                 "sso_oidc_finish": {"org_id": ORG_A, "code": "c", "code_verifier": "v", "nonce": "n"},
                 "scim_request": {"org_id": ORG_A, "method": "GET", "path": "/Users",
                                  "authorization": f"Bearer {TOKEN_A}"}}
        for action, body in calls.items():
            got = _hop(s.sport, action, body)
            assert (got.status, got.body) == (unknown.status, unknown.body), action
        monkeypatch.setenv("VIGIL_CUSTOMER_SSO", "1")                       # read at CALL time
        assert _hop(s.sport, "sso_login_start", calls["sso_login_start"]).json()["protocol"] == "saml"
        on = _hop(s.sport, "scim_request", calls["scim_request"]).json()
        assert on["status"] == 200 and on["body"]["totalResults"] == 0
    finally:
        s.close()


# =====================================================================================================================
# SAML
# =====================================================================================================================
def test_saml_sp_initiated_login_end_to_end(stack, signed):
    u = stack.saml_org(ORG_A)
    r, sid = stack.start(ORG_A)
    assert r.status == 302 and r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    raw_cookie = next(c for c in r.headers.get_all("Set-Cookie") if c.startswith(SSO_SID_COOKIE))
    assert "HttpOnly" in raw_cookie and "SameSite=Lax" in raw_cookie and "Path=/api/customer/sso" in raw_cookie
    req, relay = _authn_request(r.location)
    assert req.tag == f"{{{NS_P}}}AuthnRequest" and req.get("ID", "").startswith("_")
    assert req.get("AssertionConsumerServiceURL") == u["saml_acs_url"] and req.get("Destination") == IDP_SSO_URL
    assert req.findtext(f"{{{NS_A}}}Issuer") == u["saml_sp_entity_id"]
    assert sid not in r.location and relay != sid                      # the browser binding never rides the URL
    # the IdP signs a Response to THIS AuthnRequest; the browser auto-POSTs it (foreign origin, no cookie)
    xml = _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"], recipient=u["saml_acs_url"],
                               name_id="alice@acme.com", groups=("Security",)), IDP_KEY)
    acs = stack.post_acs(xml, relay)
    assert acs.status == 303 and acs.location.startswith("/api/customer/sso/finish?ticket=")
    assert acs.cookie(CUSTOMER_COOKIE) is None
    fin = stack.get(acs.location, cookie=f"{SSO_SID_COOKIE}={sid}")
    assert fin.status == 302 and fin.location == "/" and fin.cookie(SSO_SID_COOKIE) == ""   # the binding is cleared
    cookie = _session_cookie(fin)
    who = stack.get("/api/customer/whoami", cookie=cookie).json()
    assert who["authenticated"] and who["org_id"] == ORG_A and who["username"].startswith("sso_")
    assert stack.role(who["username"], ORG_A) == "analyst"             # the OWNER-SIGNED map, capped (JIT)
    assert stack.role(who["username"], ORG_B) is None
    # committed implies audited: the critical JIT-grant row, then the sign-in outcome
    assert [a["target"] for a in stack.audits("sso_jit_grant")] == [who["username"]]
    assert [a["outcome"] for a in stack.audits("sso_login")] == ["ok"]
    # the finish ticket is single use
    assert stack.get(acs.location, cookie=f"{SSO_SID_COOKIE}={sid}").location == "/#sso=err"


def test_saml_fails_closed_without_the_xmldsig_backend(stack):
    """NO stand-in: the shipped verifier, with no vetted XML-DSig library installed, refuses — and the edge only
    relays that refusal (it never verifies, never bypasses, never mints)."""
    u = stack.saml_org(ORG_A)
    r, sid = stack.start(ORG_A)
    req, relay = _authn_request(r.location)
    xml = _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"], recipient=u["saml_acs_url"],
                               name_id="alice@acme.com"), IDP_KEY)
    acs = stack.post_acs(xml, relay)
    assert acs.status == 303 and acs.location == "/#sso=err" and acs.cookie(CUSTOMER_COOKIE) is None
    assert stack.orgs().memberships(ORG_A) == [] and not stack.audits("sso_jit_grant")
    assert [a["outcome"] for a in stack.audits("sso_login")] == ["denied"]


@pytest.mark.parametrize("variant", ["unsigned", "wrong-key", "tampered-subject", "tampered-groups"])
def test_saml_forged_assertions_are_refused(stack, signed, variant):
    u = stack.saml_org(ORG_A)
    r, sid = stack.start(ORG_A)
    req, relay = _authn_request(r.location)
    good = _saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"], recipient=u["saml_acs_url"],
                          name_id="mallory@acme.com", groups=("Security",))
    if variant == "unsigned":
        xml = good.encode()
    elif variant == "wrong-key":
        xml = _sign(good, ATTACKER_KEY)
    elif variant == "tampered-subject":                                 # signed for mallory, re-pointed at the CEO
        xml = _sign(good, IDP_KEY).replace(b"mallory@acme.com", b"ceo@acme.com")
    else:                                                               # signed as Security, rewritten to Admins
        xml = _sign(good, IDP_KEY).replace(b">Security<", b">Admins<")
    acs = stack.post_acs(xml, relay)
    assert acs.location == "/#sso=err" and acs.cookie(CUSTOMER_COOKIE) is None, variant
    assert stack.orgs().memberships(ORG_A) == [], variant


def test_saml_replayed_assertion_is_refused(stack, signed):
    u = stack.saml_org(ORG_A)
    r, sid = stack.start(ORG_A)
    req, relay = _authn_request(r.location)
    xml = _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"], recipient=u["saml_acs_url"],
                               name_id="alice@acme.com"), IDP_KEY)
    first = stack.post_acs(xml, relay)
    assert first.location.startswith("/api/customer/sso/finish?ticket=")
    n = len(stack.orgs().memberships(ORG_A))
    # (1) the same POST again: the RelayState was spent → refused at the edge, nothing relayed
    assert stack.post_acs(xml, relay).location == "/#sso=err"
    # (2) the captured assertion under a FRESH login (an attacker's own RelayState + browser): the signed
    #     InResponseTo names the victim's AuthnRequest, not this one → refused (and its ID is spent anyway)
    r2, sid2 = stack.start(ORG_A)
    _req2, relay2 = _authn_request(r2.location)
    assert stack.post_acs(xml, relay2).location == "/#sso=err"
    assert len(stack.orgs().memberships(ORG_A)) == n


def test_saml_cross_org_assertion_and_acs_path_are_refused(stack, signed):
    ua = stack.saml_org(ORG_A)
    ub = stack.saml_org(ORG_B)
    assert ua["saml_sp_entity_id"] != ub["saml_sp_entity_id"]           # per-org audience (exclusive)
    # a person of org B (same IdP) answers a login STARTED for org A: the assertion's audience is B's → refused
    r, _sid = stack.start(ORG_A)
    req, relay = _authn_request(r.location)
    xml_b = _sign(_saml_response(request_id=req.get("ID"), audience=ub["saml_sp_entity_id"],
                                 recipient=ub["saml_acs_url"], name_id="bob@beta.com", groups=("Admins",)), IDP_KEY)
    assert stack.post_acs(xml_b, relay).location == "/#sso=err"
    # an org-suffixed ACS path that disagrees with the login's org is refused before any relay
    r2, _ = stack.start(ORG_A)
    req2, relay2 = _authn_request(r2.location)
    xml_a = _sign(_saml_response(request_id=req2.get("ID"), audience=ua["saml_sp_entity_id"],
                                 recipient=ua["saml_acs_url"], name_id="alice@acme.com"), IDP_KEY)
    assert stack.post_acs(xml_a, relay2, path=f"/api/customer/sso/saml/acs/{ORG_B}").location == "/#sso=err"
    assert stack.orgs().memberships(ORG_A) == [] and stack.orgs().memberships(ORG_B) == []


def test_saml_unsolicited_idp_initiated_responses_are_refused(stack, signed):
    u = stack.saml_org(ORG_A)
    xml = _sign(_saml_response(request_id="_idp_initiated", audience=u["saml_sp_entity_id"],
                               recipient=u["saml_acs_url"], name_id="alice@acme.com"), IDP_KEY)
    for relay in ("", "an-unknown-relay-state"):
        assert stack.post_acs(xml, relay).location == "/#sso=err"
    # a login WAS started, but the response answers another request id (InResponseTo mismatch) → refused
    r, _sid = stack.start(ORG_A)
    _req, relay = _authn_request(r.location)
    assert stack.post_acs(xml, relay).location == "/#sso=err"
    assert stack.orgs().memberships(ORG_A) == []
    assert [a["outcome"] for a in stack.audits("sso_login")] == ["denied"]   # only the bound one was relayed


def test_saml_login_csrf_the_finish_needs_the_browser_that_started(stack, signed):
    """An attacker completes a login in THEIR browser and lures the victim to the finish URL: no session."""
    u = stack.saml_org(ORG_A)
    _r, victim_sid = stack.start(ORG_A)                                 # the victim's own browser binding

    def attacker_ticket() -> "tuple[str, str]":
        r, attacker_sid = stack.start(ORG_A)
        req, relay = _authn_request(r.location)
        xml = _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"],
                                   recipient=u["saml_acs_url"], name_id="attacker@acme.com"), IDP_KEY)
        acs = stack.post_acs(xml, relay)
        assert acs.location.startswith("/api/customer/sso/finish?ticket=")
        return acs.location, attacker_sid

    for cookie in ("", f"{SSO_SID_COOKIE}={victim_sid}", f"{SSO_SID_COOKIE}=forged"):
        finish, attacker_sid = attacker_ticket()                        # a FRESH ticket per variant
        fin = stack.get(finish, cookie=cookie)
        assert fin.location == "/#sso=err" and fin.cookie(CUSTOMER_COOKIE) is None, cookie
        # the refused attempt spent the ticket (single use): the attacker cannot finish with it either
        assert stack.get(finish, cookie=f"{SSO_SID_COOKIE}={attacker_sid}").location == "/#sso=err"


def test_sso_login_start_gates(stack):
    stack.saml_org(ORG_A)
    for org in ("org_" + "c" * 24, "", "../etc", "a" * 80):            # unknown / malformed org: no oracle
        r = stack.get(f"/api/customer/sso/login?org={urllib.parse.quote(org)}")
        assert r.status == 302 and r.location == "/#sso=err" and r.cookie(SSO_SID_COOKIE) is None, org
    stack.saml_org(ORG_B)
    stack.orgs().revoke_org(ORG_B)                                    # a revoked org keeps its config, signs in nobody
    r = stack.get(f"/api/customer/sso/login?org={ORG_B}")
    assert r.status == 302 and r.location == "/#sso=err" and r.cookie(SSO_SID_COOKIE) is None
    assert stack.get(f"/api/customer/sso/login?org={ORG_A}", host="evil.example").status == 403   # anti-rebinding
    # an IdP app tile / bookmark is a cross-site top-level navigation: a foreign Referer must NOT block it
    tile = _call(stack.port, "GET", f"/api/customer/sso/login?org={ORG_A}",
                 headers={"Referer": "https://acme.okta.example/app/UserHome"})
    assert tile.status == 302 and tile.location.startswith(IDP_SSO_URL)


def test_every_sso_browser_leg_refuses_a_foreign_host_before_touching_state(stack):
    """Anti-rebinding on the legs the gates test above does not reach: the ACS, the finish and the OIDC callback
    answer a foreign Host 403 BEFORE any state is read or spent (the RelayState stays live), while the very same
    requests with the edge's own Host get the ordinary refusal redirect."""
    stack.saml_org(ORG_A)
    r, _sid = stack.start(ORG_A)
    _req, relay = _authn_request(r.location)
    form = urllib.parse.urlencode({"SAMLResponse": "PHg+", "RelayState": relay}).encode()
    legs = (("acs", "POST", "/api/customer/sso/saml/acs", form, {"Content-Type": "application/x-www-form-urlencoded"}),
            ("finish", "GET", "/api/customer/sso/finish?ticket=t", None, {}),
            ("oidc-callback", "GET", "/api/customer/sso/oidc/callback?code=c&state=s", None, {}))
    for name, method, path, body, hdr in legs:
        foreign = _call(stack.port, method, path, body=body, headers=hdr, host="evil.example")
        assert foreign.status == 403 and not foreign.location, name
    assert stack.audits("sso_login") == []                             # nothing reached the cockpit
    for name, method, path, body, hdr in legs:                         # control: the edge's own Host
        own = _call(stack.port, method, path, body=body, headers=hdr)
        assert own.status in (302, 303) and own.location == "/#sso=err", name
    assert [a["outcome"] for a in stack.audits("sso_login")] == ["denied"]   # the RelayState was still unspent


def test_saml_acs_refuses_an_oversize_body_before_reading_it(stack):
    """The ACS (like SCIM, whose 413 is pinned below) reads its body itself, outside the cookie plane's reader: its
    own cap must refuse a declared body over the limit at once — nothing is read, consumed or relayed."""
    from sigil.ui.sso_edge import _MAX_ACS_BODY
    stack.saml_org(ORG_A)
    big = _call(stack.port, "POST", "/api/customer/sso/saml/acs", body=b"x" * 8,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(_MAX_ACS_BODY + 1)})
    assert big.status == 303 and big.location == "/#sso=err"
    assert stack.audits("sso_login") == []


def test_refused_saml_sign_ins_lock_the_address_out_of_start_and_acs(stack, signed):
    """The per-IP sign-in limiter: every refused verification is COUNTED, and once the address is locked both a new
    sign-in start and the ACS refuse it — even a validly signed answer to a login begun before the lockout."""
    u = stack.saml_org(ORG_A)
    r, _sid = stack.start(ORG_A)
    req, relay = _authn_request(r.location)
    good = _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"],
                                recipient=u["saml_acs_url"], name_id="alice@acme.com"), IDP_KEY)
    for _ in range(5):                                                 # the limiter's threshold within its window
        rx, _ = stack.start(ORG_A)
        reqx, relayx = _authn_request(rx.location)
        unsigned = _saml_response(request_id=reqx.get("ID"), audience=u["saml_sp_entity_id"],
                                  recipient=u["saml_acs_url"], name_id="mallory@acme.com").encode()
        assert stack.post_acs(unsigned, relayx).location == "/#sso=err"
    assert stack.start(ORG_A)[0].location == "/#sso=err"              # a locked address cannot start a sign-in …
    assert stack.post_acs(good, relay).location == "/#sso=err"        # … nor finish one it began before the lock
    assert stack.orgs().memberships(ORG_A) == []


def test_a_saml_answer_the_parser_cannot_decode_is_a_counted_audited_refusal(stack, signed):
    """A validly signed answer whose XML declaration names an encoding the parser cannot decode is refused like any
    other unverifiable answer: COUNTED by the per-IP sign-in limiter and audited as a denied sign-in — never an
    exception that escapes the ACS tail's accounting (the cockpit's generic 500 path)."""
    u = stack.saml_org(ORG_A)

    def answer() -> "tuple[bytes, str]":
        r, _sid = stack.start(ORG_A)
        req, relay = _authn_request(r.location)
        return _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"],
                                    recipient=u["saml_acs_url"], name_id="alice@acme.com"), IDP_KEY), relay

    # isolation control: the very same kind of signed answer, without the declaration, signs in
    xml, relay = answer()
    assert stack.post_acs(xml, relay).location.startswith("/api/customer/sso/finish?ticket=")
    for _ in range(5):                                                 # the limiter's threshold within its window
        xml, relay = answer()
        undecodable = b'<?xml version="1.0" encoding="x-no-such-codec"?>' + xml
        assert stack.post_acs(undecodable, relay).location == "/#sso=err"
    assert [a["outcome"] for a in stack.audits("sso_login")] == ["ok"] + ["denied"] * 5
    assert stack.start(ORG_A)[0].location == "/#sso=err"              # counted: the address is now locked out


# =====================================================================================================================
# Enterprise OIDC
# =====================================================================================================================
def test_enterprise_oidc_login_end_to_end(stack):
    stack.oidc_org(ORG_A, client_id="cid-acme")
    cb = _oidc_sign_in(stack, ORG_A, sub="00u-alice", groups=("Admins",))
    assert cb.status == 302 and cb.location == "/", (cb.status, cb.location)
    who = stack.get("/api/customer/whoami", cookie=_session_cookie(cb)).json()
    assert who["authenticated"] and who["org_id"] == ORG_A and stack.role(who["username"], ORG_A) == "org_admin"
    (url, form), = stack.idp.posts
    assert url == f"{OIDC_ISS}/token" and form["client_id"] == "cid-acme" and form["code_verifier"]
    assert "client_secret" not in form                                  # a PKCE public client: no secret anywhere


def test_enterprise_oidc_refusals(stack):
    stack.oidc_org(ORG_A, client_id="cid-acme")
    stack.oidc_org(ORG_B, client_id="cid-beta")
    # cross-org: an id_token issued to org B's client answers a login started for org A → refused
    assert _oidc_sign_in(stack, ORG_A, sub="00u-bob", aud="cid-beta").location == "/#sso=err"
    # a token for another login's nonce (mix-up / replay) → refused
    assert _oidc_sign_in(stack, ORG_A, sub="00u-eve", nonce="someone-elses-nonce").location == "/#sso=err"
    # the browser binding: a callback without / with another browser's sid cookie → refused (a fresh login each)
    exchanged = len(stack.idp.posts)
    for cookie in ("", f"{SSO_SID_COOKIE}=not-the-starting-browser"):
        r, sid = stack.start(ORG_A)
        code, state = stack.idp.authorize(r.location, sub="00u-carol")
        got = stack.get(f"/api/customer/sso/oidc/callback?code={code}&state={state}", cookie=cookie)
        assert got.location == "/#sso=err" and got.cookie(CUSTOMER_COOKIE) is None, cookie
        # the state died on that first use: even the right browser cannot replay it
        replay = stack.get(f"/api/customer/sso/oidc/callback?code={code}&state={state}",
                           cookie=f"{SSO_SID_COOKIE}={sid}")
        assert replay.location == "/#sso=err"
    assert len(stack.idp.posts) == exchanged                            # an unbound callback exchanges no code
    # an IdP error answer, and a code minted for ANOTHER login's PKCE challenge, are refused
    r2, sid2 = stack.start(ORG_A)
    _c2, st2 = stack.idp.authorize(r2.location, sub="00u-dan")
    assert stack.get(f"/api/customer/sso/oidc/callback?error=access_denied&state={st2}",
                     cookie=f"{SSO_SID_COOKIE}={sid2}").location == "/#sso=err"
    assert stack.orgs().memberships(ORG_A) == [] and stack.orgs().memberships(ORG_B) == []


def test_an_oidc_callback_carrying_an_idp_error_is_refused_even_with_a_valid_code(stack):
    """The IdP-error answer above carries no code, so the missing-code check alone would refuse it; this callback
    carries BOTH an `error` and a live code for a correctly bound login: the error guard refuses it, and the code is
    never exchanged."""
    stack.oidc_org(ORG_A, client_id="cid-acme")
    r, sid = stack.start(ORG_A)
    code, state = stack.idp.authorize(r.location, sub="00u-erin")
    got = stack.get(f"/api/customer/sso/oidc/callback?error=access_denied&code={code}&state={state}",
                    cookie=f"{SSO_SID_COOKIE}={sid}")
    assert got.location == "/#sso=err" and got.cookie(CUSTOMER_COOKIE) is None
    assert stack.idp.posts == [] and stack.orgs().memberships(ORG_A) == []


def test_refused_oidc_sign_ins_lock_the_address_out_of_the_callback(stack):
    """As SAML: refused id_tokens are COUNTED per address, and once it is locked the callback refuses even a valid
    code for a login begun before the lockout (and a new start is refused too)."""
    stack.oidc_org(ORG_A, client_id="cid-acme")
    r, sid = stack.start(ORG_A)
    code, state = stack.idp.authorize(r.location, sub="00u-alice")
    for _ in range(5):                                                 # five refused tokens (another login's nonce)
        assert _oidc_sign_in(stack, ORG_A, sub="00u-eve", nonce="someone-elses-nonce").location == "/#sso=err"
    got = stack.get(f"/api/customer/sso/oidc/callback?code={code}&state={state}", cookie=f"{SSO_SID_COOKIE}={sid}")
    assert got.location == "/#sso=err" and got.cookie(CUSTOMER_COOKIE) is None
    assert stack.start(ORG_A)[0].location == "/#sso=err"
    assert stack.orgs().memberships(ORG_A) == []


# =====================================================================================================================
# SCIM over HTTP
# =====================================================================================================================
def _okta_user(user_name: str, ext: str, active: bool = True) -> dict:
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": user_name, "externalId": ext,
            "name": {"givenName": user_name.split("@")[0], "familyName": "Test"}, "active": active,
            "emails": [{"primary": True, "value": user_name, "type": "work"}]}


def test_scim_deactivation_kills_the_live_session(stack):
    """The IdP pushes Alice, adds her to Admins; she signs in with SSO (linked to her directory user) and reads her
    org's billing; the IdP deactivates her → her session is gone on the very next request."""
    stack.oidc_org(ORG_A, client_id="cid-acme", scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    c = stack.scim("POST", f"{base}/Users", _okta_user("alice@acme.com", "00u-alice"))
    assert c.status == 201 and c.headers.get("Content-Type") == "application/scim+json", (c.status, c.body)
    uid = c.json()["id"]
    g = stack.scim("POST", f"{base}/Groups", {"displayName": "Admins", "members": [{"value": uid}]})
    assert g.status == 201 and stack.role(uid, ORG_A) == "org_admin"
    cb = _oidc_sign_in(stack, ORG_A, sub="00u-alice")                   # sub == the directory user's externalId
    cookie = _session_cookie(cb)
    who = stack.get("/api/customer/whoami", cookie=cookie).json()
    assert who["authenticated"] and who["username"] == uid
    assert stack.get("/api/customer/billing", cookie=cookie).status == 200
    d = stack.scim("PATCH", f"{base}/Users/{uid}", {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                                   "Operations": [{"op": "replace", "value": {"active": False}}]})
    assert d.status == 200 and d.json()["active"] is False
    assert stack.role(uid, ORG_A) is None
    assert stack.get("/api/customer/whoami", cookie=cookie).json() == {"authenticated": False}
    assert stack.get("/api/customer/billing", cookie=cookie).status == 401
    # and a still-valid IdP sign-in can never bring a deactivated person back
    assert _oidc_sign_in(stack, ORG_A, sub="00u-alice").location == "/#sso=err"


def test_a_deactivation_the_edge_did_not_see_still_refuses_the_next_request(stack):
    """Multi-edge: the IdP's SCIM call lands on ANOTHER edge. This edge still holds Bob's session file, but the
    per-org role is resolved LIVE by `admit_customer`, so his next relayed request is refused."""
    stack.oidc_org(ORG_A, client_id="cid-acme", scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    uid = stack.scim("POST", f"{base}/Users", _okta_user("bob@acme.com", "00u-bob")).json()["id"]
    stack.scim("POST", f"{base}/Groups", {"displayName": "Admins", "members": [{"value": uid}]})
    cookie = _session_cookie(_oidc_sign_in(stack, ORG_A, sub="00u-bob"))
    assert stack.get("/api/customer/billing", cookie=cookie).status == 200
    _edge2, port2 = stack.new_edge("edge2")
    assert stack.scim("DELETE", f"{base}/Users/{uid}", port=port2).status == 204
    assert stack.get("/api/customer/whoami", cookie=cookie).json()["authenticated"] is True   # stale label only
    assert stack.get("/api/customer/billing", cookie=cookie).status == 403                    # refused LIVE


def test_scim_tokens_are_per_org_and_lockout_never_stalls_the_valid_bearer(stack):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    probe = "198.51.100.7"
    assert stack.scim("GET", f"/scim/v2/{ORG_B}/Users", token=TOKEN_A, ip=probe).status == 401   # A's token on B
    assert stack.scim("GET", f"/scim/v2/{ORG_A}/Users", token=TOKEN_B, ip=probe).status == 401   # B's token on A
    uid = stack.scim("POST", f"/scim/v2/{ORG_A}/Users", _okta_user("al@acme.com", "00u-al")).json()["id"]
    assert stack.scim("DELETE", f"/scim/v2/{ORG_B}/Users/{uid}", token=TOKEN_B).status == 404   # ids never cross
    assert stack.role(uid, ORG_A) == "viewer"
    # spray wrong tokens at A from the IdP's SHARED egress address until that (org, address) locks …
    shared = "203.0.113.10"
    codes = [stack.scim("GET", f"/scim/v2/{ORG_A}/Users", token="wrong-" + "z" * 40, ip=shared).status
             for _ in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429
    locked = stack.scim("GET", f"/scim/v2/{ORG_A}/Users", token="wrong-" + "z" * 40, ip=shared)
    assert locked.status == 429 and int(locked.headers.get("Retry-After")) > 0
    # … the real IdP, behind the SAME address, is never stalled (offboarding must keep working)
    assert stack.scim("DELETE", f"/scim/v2/{ORG_A}/Users/{uid}", ip=shared).status == 204
    assert stack.role(uid, ORG_A) is None
    assert stack.scim("GET", f"/scim/v2/{ORG_A}/Users", token="wrong-" + "z" * 40, ip=shared).status == 429
    # a refusal an unauthenticated client provokes is audited at most once per org per minute (both orgs here)
    assert sorted(a["org_id"] for a in stack.audits("scim_auth")) == sorted([ORG_A, ORG_B])


def test_scim_role_escalation_never_reaches_founder_or_owner(stack):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    uid = stack.scim("POST", f"{base}/Users", {**_okta_user("eve@acme.com", "00u-eve"),
                                               "roles": [{"value": "owner"}, {"value": "founder"}],
                                               "groups": [{"value": "founder"}]}).json()["id"]
    assert stack.role(uid, ORG_A) == "viewer"
    for name in ("founder", "owner", "operator", "org_admin"):
        gid = stack.scim("POST", f"{base}/Groups", {"displayName": name, "members": [{"value": uid}]}).json()["id"]
        assert stack.role(uid, ORG_A) == "viewer", name
        assert stack.scim("DELETE", f"{base}/Groups/{gid}").status == 204
    stack.scim("PATCH", f"{base}/Users/{uid}", {"Operations": [{"op": "add", "path": "roles",
                                                                "value": [{"value": "owner"}, {"value": "Admins"}]}]})
    assert stack.role(uid, ORG_A) == "org_admin"                       # the owner-mapped selector, at the cap
    founder = "cust_founder_" + ORG_A[-4:]
    stack.orgs().grant_membership(ORG_A, founder, "founder", issued_at=time.time())
    assert stack.scim("DELETE", f"{base}/Users/{founder}").status == 404   # SCIM cannot touch a non-SCIM member
    assert stack.role(founder, ORG_A) == "founder"


def test_scim_write_budget_answers_429_with_retry_after(stack, monkeypatch):
    from sigil import config
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 6)     # spine records: each create writes 3 (user, audit, grant)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    made = [stack.scim("POST", f"{base}/Users", _okta_user(f"u{i}@acme.com", f"00u{i}")) for i in range(3)]
    assert [r.status for r in made] == [201, 201, 429]
    over = stack.scim("POST", f"{base}/Users", _okta_user("u9@acme.com", "00u9"))
    assert over.status == 429 and int(over.headers.get("Retry-After")) > 0
    assert over.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert stack.scim("GET", f"{base}/Users").json()["totalResults"] == 2   # reads have their own budget
    # every write verb that can grant is budgeted: a PUT / PATCH that keeps the user active, a group write that adds
    uid, other = made[0].json()["id"], made[1].json()["id"]
    for method, path, body in (("PUT", f"/Users/{uid}", _okta_user("u0@acme.com", "00u0")),
                               ("PATCH", f"/Users/{uid}", {"Operations": [{"op": "replace", "path": "displayName",
                                                                          "value": "x"}]}),
                               ("PATCH", f"/Users/{uid}", {"Operations": [
                                   {"op": "replace", "path": "active", "value": False},
                                   {"op": "replace", "path": "active", "value": True}]}),
                               ("POST", "/Groups", {"displayName": "Admins", "members": [{"value": uid}]})):
        assert stack.scim(method, f"{base}{path}", body).status == 429, (method, path)
    assert stack.role(uid, ORG_A) == "viewer"
    # ... but a request that can only take privilege away is never held off by the org's write debt (offboarding)
    off = stack.scim("PATCH", f"{base}/Users/{uid}", {"Operations": [{"op": "replace", "path": "active",
                                                                      "value": False}]})
    assert off.status == 200 and stack.role(uid, ORG_A) is None and off.json()["active"] is False
    assert stack.scim("DELETE", f"{base}/Users/{other}").status == 204 and stack.role(other, ORG_A) is None


def _flood_body(ids: list) -> dict:
    """One PATCH repeating add-every-member / remove-every-member up to the operation bound."""
    refs = [{"value": u} for u in ids]
    ops: list = []
    while len(ops) < 1000:
        ops += [{"op": "add", "path": "members", "value": refs}, {"op": "remove", "path": "members"}]
    return {"Operations": ops}


def _spine_len(stack) -> int:
    return sum(1 for _ in stack.store().iter_records())


def test_an_over_bound_scim_body_is_refused_before_the_membership_critical_section(stack):
    """A group write naming more member references than one request may is refused on its BODY, before the write
    budget and before the critical section every org's membership change shares: it answers 400 tooMany even while
    another process holds that section, and writes nothing."""
    from sigil.ui.provision import _members_lock
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    ids = [stack.scim("POST", f"{base}/Users", _okta_user(f"f{i}@acme.com", f"00u-f{i}")).json()["id"]
           for i in range(5)]
    gid = stack.scim("POST", f"{base}/Groups", {"displayName": "Plain"}).json()["id"]
    before = _spine_len(stack)
    out: dict = {}
    with _members_lock(stack.store()):
        t = threading.Thread(target=lambda: out.update(r=stack.scim("PATCH", f"{base}/Groups/{gid}",
                                                                     _flood_body(ids))))
        t.start()
        t.join(10)
        assert "r" in out, "an over-bound request waited on the shared critical section"
    r = out["r"]
    assert r.status == 400 and r.json()["scimType"] == "tooMany"
    assert _spine_len(stack) == before
    assert stack.scim("GET", f"{base}/Groups/{gid}").json()["members"] == []


def test_a_flood_patch_from_one_org_never_stalls_another_orgs_scim(stack):
    """The amplification shape (one budgeted PATCH repeating add-N / remove-all) is refused with nothing written, and
    a second organization's SCIM request made while it is in flight is answered at once."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    base = f"/scim/v2/{ORG_A}"
    ids = [stack.scim("POST", f"{base}/Users", _okta_user(f"g{i}@acme.com", f"00u-g{i}")).json()["id"]
           for i in range(20)]
    gid = stack.scim("POST", f"{base}/Groups", {"displayName": "Plain"}).json()["id"]
    before = _spine_len(stack)
    out: dict = {}
    t0 = time.time()
    th = threading.Thread(target=lambda: out.update(r=stack.scim("PATCH", f"{base}/Groups/{gid}",
                                                                  _flood_body(ids))))
    th.start()
    time.sleep(0.2)
    t1 = time.time()
    other = stack.scim("GET", f"/scim/v2/{ORG_B}/Users", token=TOKEN_B)
    other_s = time.time() - t1
    th.join(300)
    assert other.status == 200 and other_s < 5.0, other_s
    assert out["r"].status == 400 and out["r"].json()["scimType"] == "tooMany" and time.time() - t0 < 10.0
    assert _spine_len(stack) == before


def test_the_scim_write_budget_is_charged_per_record_not_per_request(stack, monkeypatch):
    """One admitted request that appends many records spends that many units: the org's next write waits until the
    budget has repaid them (longer than the one-minute lock a single unit could arm). Reads are never budgeted."""
    from sigil import config
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    a = stack.scim("POST", f"{base}/Users", _okta_user("a@acme.com", "00u-a")).json()["id"]
    b = stack.scim("POST", f"{base}/Users", _okta_user("b@acme.com", "00u-b")).json()["id"]
    before = _spine_len(stack)
    g = stack.scim("POST", f"{base}/Groups", {"displayName": "Admins", "members": [{"value": a}, {"value": b}]})
    assert g.status == 201 and _spine_len(stack) - before == 7     # group + 2 edges + 2 x (audit + grant)
    # 3 + 3 + 7 = 13 units against a budget of 10: locked for 13/10 of the budget period
    nxt = stack.scim("POST", f"{base}/Users", _okta_user("c@acme.com", "00u-c"))
    assert nxt.status == 429 and int(nxt.headers.get("Retry-After")) > 60
    assert stack.scim("GET", f"{base}/Users").json()["totalResults"] == 2


def test_scim_protocol_hygiene_over_http(stack):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    spc = stack.scim("GET", f"{base}/ServiceProviderConfig")
    assert spc.status == 200 and spc.json()["patch"]["supported"] is True
    for r in (spc, stack.scim("GET", f"{base}/Users")):
        assert r.headers.get("Content-Type") == "application/scim+json" and r.headers.get("Cache-Control") == "no-store"
        assert r.headers.get("X-Content-Type-Options") == "nosniff" and r.headers.get_all("Set-Cookie") is None
    bad = _call(stack.port, "POST", f"{base}/Users", body=b"{not json",
                headers={"Authorization": f"Bearer {TOKEN_A}", "Content-Type": "application/scim+json"})
    assert bad.status == 400 and bad.json()["scimType"] == "invalidSyntax"
    big = _call(stack.port, "POST", f"{base}/Users", body=b" " * 8,
                headers={"Authorization": f"Bearer {TOKEN_A}", "Content-Length": str(2 * 1024 * 1024)})
    assert big.status == 413
    assert stack.scim("GET", f"{base}/Bogus").status == 404
    assert stack.scim("GET", "/scim/v2/../etc/Users").status == 404       # a malformed org segment
    assert stack.scim("GET", f"{base}/Users", token="").status == 401
    assert stack.scim("GET", f"{base}/Users", token=TOKEN_A).status == 200
    assert _call(stack.port, "GET", f"{base}/Users", host="evil.example",
                 headers={"Authorization": f"Bearer {TOKEN_A}"}).status == 403
    d = stack.scim("DELETE", f"{base}/Users/sso_" + "0" * 24)
    assert d.status == 404 and d.json()["status"] == "404"


def test_scim_changes_wait_for_the_cross_process_membership_lock(stack):
    """An owner `sigil org ...` verb (another process) holds the membership flock mid-change: an IdP's SCIM write
    WAITS for it (the same critical section as every membership change), then lands — never interleaves."""
    from sigil.ui.provision import _members_lock
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    out: dict = {}
    with _members_lock(stack.store()):
        t = threading.Thread(target=lambda: out.update(
            r=stack.scim("POST", f"/scim/v2/{ORG_A}/Users", _okta_user("ann@acme.com", "00u-ann"))))
        t.start()
        t.join(1.5)
        assert t.is_alive() and "r" not in out               # still waiting on the owner's critical section
    t.join(20)
    assert out["r"].status == 201 and stack.role(out["r"].json()["id"], ORG_A) == "viewer"


@pytest.mark.parametrize("protocol", ["saml", "oidc"])
def test_sso_sign_in_grants_wait_for_the_cross_process_membership_lock(stack, signed, protocol):
    """As SCIM above: a just-in-time sign-in grant runs inside the same critical section as every membership change,
    so it WAITS for an owner verb holding the membership flock — then lands, never interleaved."""
    from sigil.ui.provision import _members_lock
    if protocol == "saml":
        u = stack.saml_org(ORG_A)
        r, _sid = stack.start(ORG_A)
        req, relay = _authn_request(r.location)
        xml = _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"],
                                   recipient=u["saml_acs_url"], name_id="ann@acme.com"), IDP_KEY)

        def sign_in() -> Resp:
            return stack.post_acs(xml, relay)
    else:
        stack.oidc_org(ORG_A, client_id="cid-acme")
        r, sid = stack.start(ORG_A)
        code, state = stack.idp.authorize(r.location, sub="00u-ann")

        def sign_in() -> Resp:
            return stack.get(f"/api/customer/sso/oidc/callback?code={code}&state={state}",
                             cookie=f"{SSO_SID_COOKIE}={sid}")
    out: dict = {}
    with _members_lock(stack.store()):
        t = threading.Thread(target=lambda: out.update(r=sign_in()))
        t.start()
        t.join(1.5)
        assert t.is_alive() and "r" not in out               # still waiting on the owner's critical section
    t.join(20)
    landed = out["r"].location
    assert landed.startswith("/api/customer/sso/finish?ticket=") if protocol == "saml" else landed == "/"
    assert len(stack.orgs().memberships(ORG_A)) == 1


def test_scim_bearer_rotation_retires_the_old_token_at_once(stack):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    assert stack.scim("GET", f"/scim/v2/{ORG_A}/Users").status == 200
    _seq, fresh = stack.cfg().rotate_scim_token(ORG_A, issued_at=time.time())
    assert stack.scim("GET", f"/scim/v2/{ORG_A}/Users").status == 401
    assert stack.scim("GET", f"/scim/v2/{ORG_A}/Users", token=fresh).status == 200
    stack.cfg().disable_scim(ORG_A, issued_at=time.time())
    assert stack.scim("GET", f"/scim/v2/{ORG_A}/Users", token=fresh).status == 401


# =====================================================================================================================
# COMMITTED IMPLIES AUDITED — through the real provisioner wiring (`sso_provision._critical_audit`)
# =====================================================================================================================
class _FailingAudit:
    """Makes the spine refuse every `provision.audit` row whose action is in `actions` while `on` (an unwritable audit
    store), recording each refused attempt — every other spine write (the owner-signed grants included) is untouched.
    Patched on the class, so it reaches the cockpit's provisioner in its server thread."""

    def __init__(self, monkeypatch, actions):
        self.on, self.actions, self.attempts = True, frozenset(actions), []
        orig = SpineStore.append
        failing = self

        def append(store, *a, **kw):
            payload = kw.get("payload")
            if (failing.on and isinstance(payload, dict) and payload.get("signal") == "provision.audit"
                    and payload.get("action") in failing.actions):
                failing.attempts.append(payload["action"])
                raise OSError("the audit store is unavailable (test)")
            return orig(store, *a, **kw)
        monkeypatch.setattr(SpineStore, "append", append)


@pytest.mark.parametrize("protocol", ["saml", "oidc"])
def test_a_sign_in_grant_whose_critical_audit_fails_never_lands(stack, signed, monkeypatch, protocol):
    """Every just-in-time sign-in grant is committed only once its CRITICAL `provision.audit` row is written: with the
    audit store failing, the verified sign-in is refused, no membership is minted and no session is issued."""
    fail = _FailingAudit(monkeypatch, {"sso_jit_grant"})
    if protocol == "saml":
        u = stack.saml_org(ORG_A)
        r, sid = stack.start(ORG_A)
        req, relay = _authn_request(r.location)
        xml = _sign(_saml_response(request_id=req.get("ID"), audience=u["saml_sp_entity_id"],
                                   recipient=u["saml_acs_url"], name_id="ann@acme.com"), IDP_KEY)
        refused = stack.post_acs(xml, relay)
        assert refused.location == "/#sso=err" and refused.cookie(CUSTOMER_COOKIE) is None, (refused.status,
                                                                                            refused.location)
    else:
        stack.oidc_org(ORG_A, client_id="cid-acme")
        refused = _oidc_sign_in(stack, ORG_A, sub="00u-ann")
        assert refused.location == "/#sso=err" and not _session_cookie(refused), (refused.status, refused.location)
    assert fail.attempts == ["sso_jit_grant"]                  # the grant WAS reached, and its audit write failed
    assert stack.orgs().memberships(ORG_A) == []               # … so the grant never landed
    assert stack.audits("sso_jit_grant") == []
    # same-shape control: the identical sign-in with a working audit store lands, audited
    fail.on = False
    if protocol == "saml":
        _cookie, who = _saml_sign_in(stack, ORG_A, name_id="ann@acme.com")
    else:
        ok = _oidc_sign_in(stack, ORG_A, sub="00u-ann")
        assert ok.location == "/", (ok.status, ok.location)
        who = stack.get("/api/customer/whoami", cookie=_session_cookie(ok)).json()["username"]
    assert stack.role(who, ORG_A) == "viewer"
    assert [a["target"] for a in stack.audits("sso_jit_grant")] == [who]


def test_a_scim_grant_or_revoke_whose_critical_audit_fails_never_lands(stack, monkeypatch):
    """Every SCIM membership grant and revoke is committed only once its CRITICAL `provision.audit` row is written:
    with the audit store failing, the IdP's write is answered with an error and the membership is left unchanged
    (the IdP retries, and the retry lands)."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    fail = _FailingAudit(monkeypatch, {"scim_grant", "scim_deactivate"})
    grant = stack.scim("POST", f"{base}/Users", _okta_user("ann@acme.com", "00u-ann"))
    assert grant.status >= 500, (grant.status, grant.body)
    assert fail.attempts == ["scim_grant"] and stack.orgs().memberships(ORG_A) == []
    fail.on = False                                            # the IdP retries once the store is back
    # the refused create kept its directory record (holding NO membership — the fail-safe side): the IdP's re-POST of
    # the same user completes the create with the audited grant (never a 409 that strands the user grant-less)
    again = stack.scim("POST", f"{base}/Users", _okta_user("ann@acme.com", "00u-ann"))
    assert again.status == 201, (again.status, again.body)
    (listed,) = stack.scim("GET", f"{base}/Users").json()["Resources"]
    uid = listed["id"]
    assert again.json()["id"] == uid and again.json()["roles"] == [{"value": "viewer"}]
    assert stack.role(uid, ORG_A) == "viewer" and [a["target"] for a in stack.audits("scim_grant")] == [uid]
    # a create of a user that now holds its membership is a 409 again; an update is a no-op (nothing re-granted)
    assert stack.scim("POST", f"{base}/Users", _okta_user("ann@acme.com", "00u-ann")).status == 409
    assert stack.scim("PUT", f"{base}/Users/{uid}", _okta_user("ann@acme.com", "00u-ann")).status == 200
    assert stack.role(uid, ORG_A) == "viewer" and len(stack.audits("scim_grant")) == 1
    # revoke: a deactivation and a delete whose audit write fails leave the member's grant in place
    fail.on = True
    deact = stack.scim("PATCH", f"{base}/Users/{uid}",
                       {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{"op": "replace", "value": {"active": False}}]})
    assert deact.status >= 500, (deact.status, deact.body)
    delete = stack.scim("DELETE", f"{base}/Users/{uid}")
    assert delete.status >= 500, (delete.status, delete.body)
    assert fail.attempts == ["scim_grant", "scim_deactivate", "scim_deactivate"]
    assert stack.role(uid, ORG_A) == "viewer" and stack.audits("scim_deactivate") == []
    fail.on = False                                            # control: the same delete, audited, revokes
    assert stack.scim("DELETE", f"{base}/Users/{uid}").status == 204
    assert stack.role(uid, ORG_A) is None and [a["target"] for a in stack.audits("scim_deactivate")] == [uid]


def test_a_scim_re_post_completes_only_an_unfinished_create(stack):
    """Only a directory user the failed create left behind — same identity, active, no membership — is completed by a
    re-POST: a deactivated user (also holding no membership) and a different person reusing the userName stay 409s."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    uid = stack.scim("POST", f"{base}/Users", _okta_user("ann@acme.com", "00u-ann")).json()["id"]
    off = stack.scim("PATCH", f"{base}/Users/{uid}", {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                                     "Operations": [{"op": "replace", "value": {"active": False}}]})
    assert off.status == 200 and stack.role(uid, ORG_A) is None
    assert stack.scim("POST", f"{base}/Users", _okta_user("ann@acme.com", "00u-ann")).status == 409
    assert stack.scim("POST", f"{base}/Users", _okta_user("ANN@acme.com", "00u-other")).status == 409
    assert stack.role(uid, ORG_A) is None and stack.scim("GET", f"{base}/Users/{uid}").json()["active"] is False


def _scim_group_with_admins(stack) -> "tuple[str, str, list]":
    """ORG_A (SCIM on) with two directory users in its `Admins` group — each org_admin through it."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    uids = [stack.scim("POST", f"{base}/Users", _okta_user(n, x)).json()["id"]
            for n, x in (("ann@acme.com", "00u-ann"), ("bob@acme.com", "00u-bob"))]
    g = stack.scim("POST", f"{base}/Groups", {"displayName": "Admins", "members": [{"value": u} for u in uids]})
    assert g.status == 201 and [stack.role(u, ORG_A) for u in uids] == ["org_admin", "org_admin"], g.body
    return base, g.json()["id"], uids


def _downgrades(stack, since: int) -> list:
    """The members a `role=viewer` grant audit row was written for after the first `since` grant rows."""
    return sorted(a["target"] for a in stack.audits("scim_grant")[since:] if a.get("outcome") == "role=viewer")


def test_a_group_delete_whose_downgrade_audit_fails_leaves_the_group_and_the_retry_lands(stack, monkeypatch):
    """A group DELETE lowers its members' roles BEFORE the group record goes: with the audit store failing, the IdP's
    DELETE is an error, the group (and every member's place in it) is still there and nobody's role moved, so the
    IdP's retry finds the group and lands every downgrade, each with its audit row."""
    base, gid, uids = _scim_group_with_admins(stack)
    n0 = len(stack.audits("scim_grant"))
    fail = _FailingAudit(monkeypatch, {"scim_grant"})
    refused = stack.scim("DELETE", f"{base}/Groups/{gid}")
    assert refused.status >= 500, (refused.status, refused.body)
    assert fail.attempts == ["scim_grant"]                     # the downgrade WAS reached, and its audit write failed
    still = stack.scim("GET", f"{base}/Groups/{gid}")
    assert still.status == 200 and sorted(m["value"] for m in still.json()["members"]) == sorted(uids)
    assert [stack.role(u, ORG_A) for u in uids] == ["org_admin", "org_admin"] and _downgrades(stack, n0) == []
    fail.on = False                                            # the IdP retries once the store is back
    assert stack.scim("DELETE", f"{base}/Groups/{gid}").status == 204
    assert stack.scim("GET", f"{base}/Groups/{gid}").status == 404
    assert [stack.role(u, ORG_A) for u in uids] == ["viewer", "viewer"] and _downgrades(stack, n0) == sorted(uids)


_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


@pytest.mark.parametrize("how", ["patch-filtered-remove", "patch-remove", "patch-replace", "put", "put-rename"])
def test_a_group_member_removal_whose_downgrade_audit_fails_changes_nothing_and_the_retry_lands(stack, monkeypatch,
                                                                                                  how):
    """A group PATCH / PUT that takes a member out of (or renames away from) a mapped group lowers that member's role
    BEFORE the directory changes: with the audit store failing the IdP's write is an error, the directory still has
    the member in the group (under its name) and the role is untouched; the IdP's retry of the same write lands the
    downgrade with its audit row, and the directory change with it."""
    base, gid, (ann, bob) = _scim_group_with_admins(stack)
    method, body = {
        "patch-filtered-remove": ("PATCH", {"schemas": [_PATCH], "Operations": [
            {"op": "remove", "path": f'members[value eq "{ann}"]'}]}),
        "patch-remove": ("PATCH", {"schemas": [_PATCH], "Operations": [
            {"op": "remove", "path": "members", "value": [{"value": ann}]}]}),
        "patch-replace": ("PATCH", {"schemas": [_PATCH], "Operations": [
            {"op": "replace", "path": "members", "value": [{"value": bob}]}]}),
        "put": ("PUT", {"displayName": "Admins", "members": [{"value": bob}]}),
        "put-rename": ("PUT", {"displayName": "Staff", "members": [{"value": ann}, {"value": bob}]}),
    }[how]
    lowered = sorted([ann, bob]) if how == "put-rename" else [ann]
    n0 = len(stack.audits("scim_grant"))
    fail = _FailingAudit(monkeypatch, {"scim_grant"})
    refused = stack.scim(method, f"{base}/Groups/{gid}", body)
    assert refused.status >= 500, (refused.status, refused.body)
    assert fail.attempts == ["scim_grant"]
    g = stack.scim("GET", f"{base}/Groups/{gid}").json()
    assert g["displayName"] == "Admins" and sorted(m["value"] for m in g["members"]) == sorted([ann, bob])
    assert [x["display"] for x in stack.scim("GET", f"{base}/Users/{ann}").json()["groups"]] == ["Admins"]
    assert [stack.role(u, ORG_A) for u in (ann, bob)] == ["org_admin", "org_admin"] and _downgrades(stack, n0) == []
    fail.on = False                                            # the IdP retries the same write
    again = stack.scim(method, f"{base}/Groups/{gid}", body)
    assert again.status == 200, (again.status, again.body)
    assert {u: stack.role(u, ORG_A) for u in (ann, bob)} == {u: ("viewer" if u in lowered else "org_admin")
                                                              for u in (ann, bob)}
    assert _downgrades(stack, n0) == lowered
    g = stack.scim("GET", f"{base}/Groups/{gid}").json()
    if how == "put-rename":
        assert g["displayName"] == "Staff" and sorted(m["value"] for m in g["members"]) == sorted([ann, bob])
    else:
        assert [m["value"] for m in g["members"]] == [bob]


def test_a_group_add_whose_raise_audit_fails_grants_nothing_extra_and_the_retry_lands(stack, monkeypatch):
    """A raise caused by a group add is committed directory-first: a failed grant audit leaves the member in the group
    at the LOWER role it held (never extra privilege), and the IdP's retry of the same add — the member already in the
    group — still re-resolves it and lands the audited raise."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    base = f"/scim/v2/{ORG_A}"
    uid = stack.scim("POST", f"{base}/Users", _okta_user("ann@acme.com", "00u-ann")).json()["id"]
    gid = stack.scim("POST", f"{base}/Groups", {"displayName": "Admins"}).json()["id"]
    add = {"schemas": [_PATCH], "Operations": [{"op": "add", "path": "members", "value": [{"value": uid}]}]}
    fail = _FailingAudit(monkeypatch, {"scim_grant"})
    refused = stack.scim("PATCH", f"{base}/Groups/{gid}", add)
    assert refused.status >= 500 and fail.attempts == ["scim_grant"], (refused.status, refused.body)
    assert stack.role(uid, ORG_A) == "viewer"                  # the fail-safe side: no raise without its audit
    fail.on = False
    assert stack.scim("PATCH", f"{base}/Groups/{gid}", add).status == 200
    assert stack.role(uid, ORG_A) == "org_admin"
    assert [a["target"] for a in stack.audits("scim_grant") if a.get("outcome") == "role=org_admin"] == [uid]
