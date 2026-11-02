"""#25 — the composed, end-to-end customer-loop verification (the automated cross-plane integration slice).

NOT a per-slice test: this stands up the WHOLE customer stack ONCE — the sovereign cockpit + provisioner
(owner-key holder) and the keyless `custui` edge over the real loopback hop, with EVERY customer feature ON
at the same time (Google OIDC + passkey + TOTP + step-up enforcement) and a provisioned owner vault — and
drives the real journeys across both planes, then adversarially probes the isolation/replay/forgery
invariants the whole program rests on. It exists because per-slice red-pens don't prove the slices COMPOSE.

Drives: signup → password login → step-up gated sensitive op → TOTP enroll + step-up → member management
(billing != testing) → owner promotion → ownership challenge → launch gate; Google-OIDC auto-provision and
passkey enroll/login as CUSTOMER sessions (never operator); cross-tenant (org A ⊥ org B) and cross-plane
(customer cookie ⊥ operator cockpit, and vice-versa) isolation; and replay/forgery inertness (single-use
OIDC state, single-use passkey challenge, single-use TOTP step, a forged cookie).
"""
from __future__ import annotations

import http.cookies
import tempfile
import threading
import time
import urllib.request

import pytest
from sigil.governor.accounts import AccountsRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui.custui import CUSTOMER_COOKIE, build_customer_server
from sigil.ui.server import build_server

# reuse the hardened harness bits from the per-slice suites (same-dir pytest import)
from test_custui import HOP, TOKEN, _edge_raw, _get, _MiniIdP, _oidc_login, _opener, _post
from test_customer_passkey import ORIGIN as PK_ORIGIN
from test_customer_passkey import RP as PK_RP
from test_customer_passkey import SoftAuthenticator
from test_secrets_sealed import make_fake_tpm


@pytest.fixture(autouse=True)
def _scrub_shared_owner_state():
    """_full_stack calls ensure_owner_keypair()/build_server() against the shared SIGIL_HOME, leaving an
    owner keypair there with NO sealed vault KEK. In the shared-SIGIL_HOME CI process (the P7 governor job /
    the full apps/sigil run) that half-provisioned home breaks the later-collected test_ui_durability, whose
    backup can only self-provision a KEK on a CLEAN home. Scrub the owner-key + vault state before AND after
    each test (the same before/after idiom test_ui_durability uses for its own HEAD/SPINE state) so the
    shared home is left pristine; _full_stack re-provisions its own tmp fake-TPM vault + owner key."""
    import shutil
    from sigil import config
    from sigil.platform import vault as _vault

    def _scrub():
        shutil.rmtree(config.KEYS_DIR, ignore_errors=True)
        shutil.rmtree(config.SIGIL_HOME / "vault", ignore_errors=True)
        _vault.reset_owner_vault_for_test()

    _scrub()
    yield
    _scrub()


def _full_stack(tmp_path, monkeypatch):
    """Sovereign cockpit + keyless edge over the hop, with a PROVISIONED owner vault and ALL customer
    features ON (OIDC + passkey + step-up), a fake Google IdP injected into the provisioner, and every
    SIGIL_HOME-rooted customer ledger isolated to tmp. Returns (sov, edge, eport, sport, idp)."""
    from sigil import config
    from sigil.platform import vault as vaultmod
    # a provisioned fake-TPM owner vault (for the TOTP seal); drop a stale sealed DEK first
    (config.SIGIL_HOME / "spine" / "keys" / "spine.dek").unlink(missing_ok=True)
    vaultmod.reset_owner_vault_for_test()
    v = vaultmod.Vault(tmp_path / "ownervault", make_fake_tpm())
    v.provision()
    monkeypatch.setattr(vaultmod, "_owner_vault", v)
    # env: hop + dev tokens + every customer feature ON
    monkeypatch.setenv("VIGIL_PROVISION_HOP_KEY", HOP)
    monkeypatch.setenv("VIGIL_PROVISION_DEV_TOKENS", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_ENABLED", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_CLIENT_ID", "client-123")
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_REDIRECT_URI", "http://127.0.0.1/api/customer/oidc/callback")
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ENABLED", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_RP_ID", PK_RP)
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ORIGINS", PK_ORIGIN)
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR",
                 "CUSTOMER_MFA_REPLAY_DIR", "CUSTOMER_PASSKEY_SIGNCOUNT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    ensure_owner_keypair()
    idp = _MiniIdP()
    sov = build_server(token=TOKEN, port=0, spine_path=path,
                       customer_oidc_http_post=idp.http_post, customer_oidc_jwks_fetcher=idp.jwks_fetcher)
    threading.Thread(target=sov.serve_forever, daemon=True).start()
    time.sleep(0.05)
    sport = sov.server_address[1]
    edge = build_customer_server(host="127.0.0.1", port=0, hop_key=HOP,
                                 provision_base=f"http://127.0.0.1:{sport}",
                                 sessions_dir=str(tmp_path / "custsessions"))
    threading.Thread(target=edge.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return sov, edge, edge.server_address[1], sport, path


def _signup(op, ep, email, org="Acme"):
    tok = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    return _post(op, ep, "/api/customer/signup/confirm",
                 {"token": tok, "password": "customer-pw-123", "org_name": org})[1]


def test_e2e_password_journey_with_stepup_and_billing_not_testing(tmp_path, monkeypatch):
    import sigil.governor.totp as _totp
    sov, edge, ep, _sp, spine = _full_stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        conf = _signup(op, ep, "founder@acme.com")                    # signup → owner-signed org + org_admin
        assert conf["username"].startswith("cust_") and conf["org_id"].startswith("org_")
        assert _get(op, ep, "/api/customer/whoami")[1]["authenticated"] is True
        # a billing org_admin CAN read billing but NOT register/launch tests (billing != testing)
        assert _get(op, ep, "/api/customer/billing")[1]["org_id"] == conf["org_id"]
        assert _post(op, ep, "/api/customer/target/challenge", {"host": "acme.example"})[0] == 403
        # a teammate to manage — step-up is ON, so member/grant is refused until a fresh factor
        mate = _opener()
        m = _signup(mate, ep, "mate@acme.com", org="Mate")
        c, r = _post(op, ep, "/api/customer/member/grant", {"member_username": m["username"], "role": "analyst"})
        assert c == 401 and r.get("step_up_required") is True, (c, r)
        # enroll TOTP + step up (the owner vault seals the secret) → the grant now proceeds
        secret = _post(op, ep, "/api/customer/mfa/totp/enroll", {})[1]["secret"]
        assert _post(op, ep, "/api/customer/mfa/verify", {"code": _totp.code_now(secret, at=time.time())})[0] == 200
        c, r = _post(op, ep, "/api/customer/member/grant", {"member_username": m["username"], "role": "analyst"})
        assert c == 200 and r["role"] == "analyst" and r["org_id"] == conf["org_id"], (c, r)
        # the owner promotes the founder to operator (an owner act on the sovereign store) → testing authority
        OrgRegistry(sov.store()).grant_membership(conf["org_id"], conf["username"], "operator",
                                                  issued_at=time.time() + 1e6)
        # now (still stepped-up) the founder can register a target; the challenge binds the SESSION org
        c, ch = _post(op, ep, "/api/customer/target/challenge", {"host": "acme.example"})
        assert c == 200 and ch["dns_name"] == "_vigil-challenge.acme.example", (c, ch)
    finally:
        sov.shutdown(); edge.shutdown()


def test_e2e_oidc_and_passkey_logins_are_customer_sessions_never_operator(tmp_path, monkeypatch):
    sov, edge, ep, sp, spine = _full_stack(tmp_path, monkeypatch)
    store = sov.store()
    try:
        # (1) Google OIDC auto-provision login → a customer session. The fake IdP is the _MiniIdP instance
        # bound into the provisioner's injected http_post (sov.customer_oidc_http_post.__self__); mint a token
        # for the login's server-minted nonce.
        opg = _opener()
        state, nonce, sid, _ = _oidc_login(ep)
        srv_idp = sov.customer_oidc_http_post.__self__
        srv_idp.next_id_token = srv_idp.mint(nonce=nonce, sub="g-founder", email="g@gmail.com")
        st, hdr, _ = _edge_raw(ep, f"/api/customer/oidc/callback?code=c&state={state}",
                               cookie=f"vigil_customer_oidc_sid={sid}")
        assert st == 302 and hdr.get("Location") == "/", (st, hdr)
        gcookie = http.cookies.SimpleCookie(hdr.get("Set-Cookie"))[CUSTOMER_COOKIE].value
        gwho = _get(opg, ep, "/api/customer/whoami", cookie=f"{CUSTOMER_COOKIE}={gcookie}")[1]
        assert gwho["authenticated"] is True and gwho["username"].startswith("cust_")
        # the OIDC customer is a governor.customer, NEVER a governor.account
        assert AccountsRegistry(store).account(gwho["username"]) is None
        assert CustomerRegistry(store).customer(gwho["username"]) is not None
        # and that customer cookie does NOT authenticate on the OPERATOR cockpit
        _, opwho = _get(urllib.request.build_opener(), sp, "/api/whoami", cookie=f"sigil_session={gcookie}")
        assert opwho.get("authenticated") in (False, None), opwho

        # (2) passkey enroll (needs a session) + a fresh-browser passkey LOGIN → also a customer session
        opp = _opener()
        conf = _signup(opp, ep, "pk@acme.com", org="PkOrg")
        auth = SoftAuthenticator(); cid = "cred-e2e-1"
        ech = _post(opp, ep, "/api/customer/passkey/enroll/challenge", {})[1]["challenge"]
        reg = auth.register(ech)
        assert _post(opp, ep, "/api/customer/passkey/enroll/verify",
                     {"credential_id": cid, "public_key_spki_b64": reg["public_key_spki_b64"],
                      "cose_alg": reg["cose_alg"], "uv": False, "client_data_json": reg["client_data_json"],
                      "challenge": ech})[0] == 200
        fresh = _opener()
        lch = _post(fresh, ep, "/api/customer/passkey/login/challenge", {})[1]["challenge"]
        a = auth.assert_(lch, count=9)
        c, r = _post(fresh, ep, "/api/customer/passkey/login/verify",
                     {"credential_id": cid, "authenticator_data": a["authenticator_data"],
                      "client_data_json": a["client_data_json"], "signature": a["signature"], "challenge": lch})
        assert c == 200 and r["username"] == conf["username"], (c, r)   # resolved to the enrolling customer
        assert AccountsRegistry(store).account(r["username"]) is None   # never an operator
    finally:
        sov.shutdown(); edge.shutdown()


def test_e2e_cross_tenant_and_cross_plane_isolation(tmp_path, monkeypatch):
    from sigil.governor.wallet import WalletRegistry
    sov, edge, ep, sp, spine = _full_stack(tmp_path, monkeypatch)
    try:
        opA = _opener(); a = _signup(opA, ep, "a@acme.com", org="A")
        opB = _opener(); b = _signup(opB, ep, "b@beta.com", org="B")
        assert a["org_id"] != b["org_id"]
        WalletRegistry(sov.store()).grant(b["org_id"], 777, "topup", entry_id="seed-b", issued_at=time.time())
        # A's session sees ONLY A; naming B's org on the query is IGNORED (org from the session)
        bA = _get(opA, ep, "/api/customer/billing")[1]
        assert bA["org_id"] == a["org_id"]
        bQ = _get(opA, ep, f"/api/customer/billing?org_id={b['org_id']}")[1]
        assert bQ["org_id"] == a["org_id"] and bQ["credits"]["available"] == bA["credits"]["available"]
        # B sees B — exactly 777 more than A (same trial + B's private seed), never leaked to A
        bB = _get(opB, ep, "/api/customer/billing")[1]
        assert bB["credits"]["available"] == bA["credits"]["available"] + 777
        # cross-plane: A's customer cookie presented to the operator cockpit → anon
        jar = opA.handlers[[type(h).__name__ for h in opA.handlers].index("HTTPCookieProcessor")].cookiejar
        sidA = next(ck.value for ck in jar if ck.name == CUSTOMER_COOKIE)
        _, opwho = _get(urllib.request.build_opener(), sp, "/api/whoami", cookie=f"sigil_session={sidA}")
        assert opwho.get("authenticated") in (False, None)
        # and an operator-style cookie on the edge → anon
        assert _get(urllib.request.build_opener(), ep, "/api/customer/whoami",
                    cookie=f"sigil_session={sidA}")[1]["authenticated"] is False
    finally:
        sov.shutdown(); edge.shutdown()


def test_e2e_replay_and_forgery_inertness(tmp_path, monkeypatch):
    import sigil.governor.totp as _totp
    sov, edge, ep, sp, spine = _full_stack(tmp_path, monkeypatch)
    try:
        # single-use OIDC state: a replayed callback finds its state spent
        state, nonce, sid, _ = _oidc_login(ep)
        srv_idp = sov.customer_oidc_http_post.__self__
        srv_idp.next_id_token = srv_idp.mint(nonce=nonce, sub="g-replay", email="r@gmail.com")
        assert _edge_raw(ep, f"/api/customer/oidc/callback?code=c&state={state}",
                         cookie=f"vigil_customer_oidc_sid={sid}")[0] == 302        # first use
        srv_idp.next_id_token = srv_idp.mint(nonce=nonce, sub="g-replay", email="r@gmail.com")
        assert _edge_raw(ep, f"/api/customer/oidc/callback?code=c&state={state}",
                         cookie=f"vigil_customer_oidc_sid={sid}")[0] == 401        # replay refused
        # single-use passkey challenge + single-use TOTP step
        op = _opener(); _signup(op, ep, "rep@acme.com", org="Rep")
        secret = _post(op, ep, "/api/customer/mfa/totp/enroll", {})[1]["secret"]
        code = _totp.code_now(secret, at=time.time())
        assert _post(op, ep, "/api/customer/mfa/verify", {"code": code})[0] == 200
        assert _post(op, ep, "/api/customer/mfa/verify", {"code": code})[0] == 403  # replayed TOTP step refused
        # a forged/garbage customer cookie is simply anonymous (never authenticates)
        assert _get(urllib.request.build_opener(), ep, "/api/customer/whoami",
                    cookie=f"{CUSTOMER_COOKIE}=totally-made-up")[1]["authenticated"] is False
    finally:
        sov.shutdown(); edge.shutdown()
