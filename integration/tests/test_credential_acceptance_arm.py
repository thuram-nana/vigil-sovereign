"""M-11.2 — the CREDENTIAL-UNIT re-drive arm (``credential_acceptance_redrive``) that FEEDS
``credential_acceptance_oracle``.

Every control here drives a REAL loopback origin through the REAL gated send and asserts POSITIVELY what the
arm did — the examined surface, the minted/withheld FACT, the specific refusal note — never merely that a
result is falsy, so stubbing the arm to ``return None`` fails these. The arm is a single-shot GATED re-drive
(NOT a brute-forcer): it takes an operator-planted TEST corpus + attestation, performs ONE gated login per
planted credential + ONE gated read of the attested protected resource, and lets the deterministic oracle
adjudicate the ACHIEVED-ACCESS differential over VIGIL's OWN capture.

EMBEDDED CONTROLS:
  * POSITIVE — a VULNERABLE login that ACCEPTS the planted weak credential + an auth-gated resource ⇒ ONE
    signed FACT that RE-VERIFIES OFFLINE;
  * SAFE TWIN 1 — a REJECTING login (the weak read is itself a denial) ⇒ no FACT;
  * SAFE TWIN 2 — a NON-auth-gated resource served to the baseline too (no differential) ⇒ no FACT;
  * REFUSALS — no planted corpus / no attestation ⇒ a recorded refusal and NO traffic (no corpus, no FACT);
  * the LLM-claim seam is fail-closed WITHOUT a planted corpus on the trusted spec (TEST-IDENTITIES-ONLY).
"""
from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pytest

pytest.importorskip("framework.v2")  # offense-leg only; skips cleanly in the keyless two-env leg


# ---------------------------------------------------------------------------------------------------
# gate isolation + charter (mirrors test_runtime_redrive_soundness)
# ---------------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


# ---------------------------------------------------------------------------------------------------
# a loopback app with a POST login + an auth-gated protected resource + the two safe twins
# ---------------------------------------------------------------------------------------------------

# A STRONG authenticated-content signal (>= 12 chars, >= 2.5 bits/char): present ONLY in an authenticated view.
_SIGNAL = 'data-cred-acct="acct_8Qv3Lp7xZ2"'
# A distinctive planted TEST secret, so the no-retention control is meaningful (it must never land in the record).
_PLANTED_SECRET = "s3cr3t-PLANTED-xZ9-do-not-retain"
_CRED_ID = "admin:weak"


def _make_handler(*, strict_login: bool = False, public_resource: bool = False, redirect_denial: bool = False):
    """Build a handler class. ``strict_login`` rejects every credential (SAFE TWIN 1); ``public_resource``
    serves the resource to everyone (SAFE TWIN 2); ``redirect_denial`` denies the no-session read with a 302 to
    the attested login url instead of a 401."""

    class _CredApp(http.server.BaseHTTPRequestHandler):
        def _sessions(self) -> dict:
            if not hasattr(self.server, "_cred_sessions"):
                self.server._cred_sessions = {}            # type: ignore[attr-defined]
            return self.server._cred_sessions              # type: ignore[attr-defined]

        def _cookie_sid(self) -> str:
            import http.cookies
            jar = http.cookies.SimpleCookie(self.headers.get("Cookie", "") or "")
            m = jar.get("SESSION")
            return m.value if m is not None else ""

        def _reply(self, status: int, body: str, extra=None) -> None:
            raw = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (extra or []):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _fields(self) -> dict:
            from urllib.parse import parse_qs
            n = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            return parse_qs(raw, keep_blank_values=True)

        def do_POST(self):  # noqa: N802
            path = urlsplit(self.path).path
            f = self._fields()
            user, pw = f.get("username", [""])[0], f.get("password", [""])[0]
            if path != "/login":
                self._reply(404, "nope")
                return
            if (not strict_login) and user == "admin" and pw == _PLANTED_SECRET:
                sid = "sess-admin"
                self._sessions()[sid] = user
                self._reply(200, "<p>authenticated</p>", extra=[("Set-Cookie", f"SESSION={sid}; Path=/; HttpOnly")])
            else:
                # SAFE TWIN 1 / a correct rejection: 401 and NO session cookie issued.
                self._reply(401, "<p>Authentication required</p>")

        def do_GET(self):  # noqa: N802
            path = urlsplit(self.path).path
            if path != "/account":
                self._reply(404, "nope")
                return
            if public_resource:
                # SAFE TWIN 2: served to EVERYONE (no auth gate) — the baseline is not a denial.
                self._reply(200, f"<main {_SIGNAL}><h1>Account</h1></main>")
                return
            if self._cookie_sid() in self._sessions():
                self._reply(200, f"<main {_SIGNAL}><h1>Account</h1><p>settings</p></main>")
            elif redirect_denial:
                host = self.headers.get("Host", "")
                self._reply(302, "", extra=[("Location", f"http://{host}/login?next=/account")])
            else:
                self._reply(401, "<p>Authentication required</p>")

        def log_message(self, *a):  # silence
            return

    return _CredApp


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _corpus():
    return {_CRED_ID: {"username": "admin", "secret": _PLANTED_SECRET}}


def _policy():
    return {"corpus_id": "OBSIDIAN-TEST-cred-corpus-1", "should_reject": [_CRED_ID]}


def _run(monkeypatch, tmp_path, handler, *, corpus=None, policy=None, descriptor_extra=None,
         login_path="/login", resource_path="/account", url_host=None):
    """Drive the REAL arm against a REAL loopback origin; returns (result, base_url, port)."""
    from vigil_integration.live.runtime_redrive import credential_acceptance_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve(handler)
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    descriptor = {"url": f"{base}{resource_path}", "method": "GET", "authenticated_signal": _SIGNAL}
    if descriptor_extra:
        descriptor.update(descriptor_extra)
    try:
        res = credential_acceptance_redrive(
            (url_host or base) + resource_path, slug="alpha", engagement_slug="alpha", signers=_signers(),
            corpus=_corpus() if corpus is None else corpus,
            policy=_policy() if policy is None else policy,
            protected_resource=descriptor,
            login_spec={"url": f"{base}{login_path}"})
        return res, base, port
    finally:
        srv.shutdown()


# ===================================================================================================
# POSITIVE: a weak credential that ACHIEVES protected access mints exactly one FACT
# ===================================================================================================

def test_weak_credential_that_achieves_protected_access_mints_one_fact(monkeypatch, tmp_path):
    res, _base, _port = _run(monkeypatch, tmp_path, _make_handler())
    assert res.surfaces.get("credential_acceptance"), "the arm examined NO surface — it was stubbed, not run"
    assert res.n_facts == 1, f"expected exactly one achieved-access FACT, got {res.n_facts}; notes={res.notes}"
    fact = res.facts[0]
    assert fact.is_fact
    from vigil_integration.live.runtime_redrive import _CREDENTIAL_BRANCH
    # the admission audit trail records a FACT on the achieved-access branch
    assert any(v == "FACT" and b == _CREDENTIAL_BRANCH for (b, v, _r) in res.admissions), res.admissions
    assert res.family_verdict("credential_acceptance") == "FACT"


def test_the_minted_fact_re_verifies_offline(monkeypatch, tmp_path):
    res, _base, _port = _run(monkeypatch, tmp_path, _make_handler())
    assert res.n_facts == 1
    fact = res.facts[0]
    context = res.contexts[fact.finding_ref]
    # re-run the SAME deterministic oracle over the RETAINED record — the offline re-verify contract.
    from framework.v2.verify.oracles import credential_acceptance_oracle
    again = credential_acceptance_oracle(context["credential_acceptance"])
    assert again.fired, "the retained record did not re-fire the oracle offline — the FACT is not re-executable"


def test_no_planted_secret_is_retained_in_the_fact_context(monkeypatch, tmp_path):
    res, _base, _port = _run(monkeypatch, tmp_path, _make_handler())
    assert res.n_facts == 1
    blob = json.dumps(res.contexts[res.facts[0].finding_ref])
    assert _PLANTED_SECRET not in blob, "the planted secret LEAKED into the retained record — not secret-safe"
    # the credential IDENTIFIER (not the secret) is allowed and present
    assert _CRED_ID in blob


# the redirect test needs the resolved port inside the attested login prefix, so drive it explicitly:
def test_login_redirect_denial_fires_with_resolved_prefix(monkeypatch, tmp_path):
    from vigil_integration.live.runtime_redrive import credential_acceptance_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve(_make_handler(redirect_denial=True))
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        res = credential_acceptance_redrive(
            f"{base}/account", slug="alpha", engagement_slug="alpha", signers=_signers(),
            corpus=_corpus(), policy=_policy(),
            protected_resource={"url": f"{base}/account", "method": "GET", "authenticated_signal": _SIGNAL,
                                "login_redirect_locations": [f"{base}/login"]},
            login_spec={"url": f"{base}/login"})
    finally:
        srv.shutdown()
    assert res.n_facts == 1, f"a redirect-to-login denied baseline must still fire; notes={res.notes}"


# ===================================================================================================
# SAFE TWINS: the arm must NEVER flag these
# ===================================================================================================

def test_a_rejecting_login_mints_nothing(monkeypatch, tmp_path):
    # SAFE TWIN 1 — the login REJECTS the planted credential, so the weak read is itself a denial.
    res, _base, _port = _run(monkeypatch, tmp_path, _make_handler(strict_login=True))
    assert res.surfaces.get("credential_acceptance"), "the arm must still RUN (examine the surface) and refuse"
    assert res.n_facts == 0, f"a rejecting login must mint NOTHING, got {res.n_facts}"
    # it ran the oracle and recorded a non-FACT admission (not a crash / not a stub)
    assert res.admissions, "the arm recorded no admission — it did not actually adjudicate"
    assert all(v != "FACT" for (_b, v, _r) in res.admissions)


def test_a_non_auth_gated_resource_mints_nothing(monkeypatch, tmp_path):
    # SAFE TWIN 2 — the resource is served to EVERYONE, so the no-session baseline is NOT a denial.
    res, _base, _port = _run(monkeypatch, tmp_path, _make_handler(public_resource=True))
    assert res.surfaces.get("credential_acceptance"), "the arm must still RUN and refuse"
    assert res.n_facts == 0, f"a non-auth-gated resource must mint NOTHING, got {res.n_facts}"


# ===================================================================================================
# REFUSALS: fail-closed before any traffic without the operator-planted corpus / attestation
# ===================================================================================================

def test_refuses_without_a_planted_corpus(monkeypatch, tmp_path):
    res, _base, _port = _run(monkeypatch, tmp_path, _make_handler(), corpus={})
    assert res.n_facts == 0
    assert not res.surfaces.get("credential_acceptance"), "a no-corpus refusal must happen BEFORE any traffic"
    assert any("no operator-planted TEST credential corpus" in n for n in res.notes), res.notes


def test_refuses_without_a_should_reject_policy(monkeypatch, tmp_path):
    res, _base, _port = _run(monkeypatch, tmp_path, _make_handler(),
                             policy={"corpus_id": "OBSIDIAN-TEST-cred-corpus-1", "should_reject": []})
    assert res.n_facts == 0
    assert any("should_reject" in n for n in res.notes), res.notes


def test_refuses_without_a_protected_resource_attestation(monkeypatch, tmp_path):
    # drive the arm directly with a descriptor missing the authenticated_signal
    from vigil_integration.live.runtime_redrive import credential_acceptance_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve(_make_handler())
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        res = credential_acceptance_redrive(
            f"{base}/account", slug="alpha", engagement_slug="alpha", signers=_signers(),
            corpus=_corpus(), policy=_policy(),
            protected_resource={"url": f"{base}/account", "method": "GET"},   # NO authenticated_signal
            login_spec={"url": f"{base}/login"})
    finally:
        srv.shutdown()
    assert res.n_facts == 0
    assert any("protected-resource attestation" in n for n in res.notes), res.notes


# ===================================================================================================
# REGISTRATION + ADMISSION: the branch is registered FACT-capable and demotion/minting is correct
# ===================================================================================================

def test_the_branch_is_registered_fact_capable_and_dispatched(monkeypatch, tmp_path):
    from vigil_integration.live.runtime_redrive import CREDENTIAL_REDRIVE_CLASSES, _CREDENTIAL_BRANCH
    from vigil_integration.live.tool_manifest import load_branch_registry
    from vigil_integration.live.verdict import admit

    assert "credential_acceptance" in CREDENTIAL_REDRIVE_CLASSES
    reg = {b["id"]: b for b in load_branch_registry(
        Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "evidence-branches.json")}
    row = reg[_CREDENTIAL_BRANCH]
    assert row["fact_capable"] is True
    assert row["clean_capable"] is False, "a credential-acceptance non-fire is not a sound CLEAN (positive-only)"
    assert row["oracle_version"] == "credential_acceptance"

    # a FIRED oracle over this branch is admitted to a FACT; a non-fire is INCONCLUSIVE (never CLEAN)
    v_fact = admit(_CREDENTIAL_BRANCH, fired=True, conclusive=True,
                   observed={"channel_established": True, "body_semantically_available": True,
                             "gate_authorized": True})
    assert v_fact.verdict.value == "FACT"
    v_non = admit(_CREDENTIAL_BRANCH, fired=False, conclusive=False,
                  observed={"channel_established": True, "body_semantically_available": True,
                            "gate_authorized": True})
    assert v_non.verdict.value == "INCONCLUSIVE"


def test_the_generic_runtime_redrive_delegation_is_inert_without_a_corpus(monkeypatch, tmp_path):
    # a generic runtime_redrive for the class delegates to the arm WITHOUT a corpus ⇒ a recorded refusal, no FACT
    from vigil_integration.live.runtime_redrive import runtime_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve(_make_handler())
    port = srv.server_address[1]
    try:
        res = runtime_redrive(f"http://127.0.0.1:{port}/account", slug="alpha", engagement_slug="alpha",
                              signers=_signers(), claimed_class="credential_acceptance")
    finally:
        srv.shutdown()
    assert res.bug_class == "credential_acceptance"
    assert res.n_facts == 0
    assert any("no operator-planted TEST credential corpus" in n for n in res.notes), res.notes


# ===================================================================================================
# SEAM / ROUTER: the planted corpus never comes from the model (TEST-IDENTITIES-ONLY)
# ===================================================================================================

def test_the_live_seam_is_fail_closed_without_a_planted_corpus():
    from vigil_integration.live.wiring import _live_credential_redrive_fact

    class _Prov:
        slug = "alpha"
        signers = _signers()

    # a spec with NO planted corpus (the LLM-claim path) ⇒ None (LEAD, fail-closed)
    spec = {"kind": "credential", "url": "http://127.0.0.1:1/account", "bug_class": "credential_acceptance"}
    assert _live_credential_redrive_fact(_Prov(), {"bug_class": "credential_acceptance"}, spec) is None
    # a wrong-class spec ⇒ None
    assert _live_credential_redrive_fact(_Prov(), {}, {"url": "http://x/", "corpus": {"a": {}},
                                                      "policy": {}, "protected_resource": {},
                                                      "login_spec": {}, "bug_class": "xss"}) is None
    # no redrive spec at all ⇒ None
    assert _live_credential_redrive_fact(_Prov(), {}, None) is None


def test_the_redrive_spec_router_never_sources_a_corpus_from_the_model():
    # the engine router emits only {kind, url, bug_class} for credential_acceptance — never a model-sourced corpus
    import inspect

    from vigil_integration.live import engine
    src = inspect.getsource(engine.LiveEngine._redrive_spec) if hasattr(engine, "LiveEngine") else ""
    if not src:
        # locate whichever class defines the staticmethod
        for _n, obj in vars(engine).items():
            if isinstance(obj, type) and "_redrive_spec" in vars(obj):
                src = inspect.getsource(obj._redrive_spec)
                break
    assert '"kind": "credential"' in src, "the router must emit a credential spec kind"
    # the credential branch of the router returns only class+url (no corpus/policy/login_spec keys sourced here)
    assert "corpus" not in src.split('"kind": "credential"')[1][:200], (
        "the router must NOT source a corpus from its LLM-derived inputs")


# ===================================================================================================
# END-TO-END against the shipped benchmark app's planted /credtest scenario + its safe twins
# ===================================================================================================

def _serve_benchmark():
    from framework.v2.eval.benchmark_app import BenchmarkHandler
    return _serve(BenchmarkHandler)


def test_benchmark_credtest_scenario_mints_and_its_safe_twins_are_clean(monkeypatch, tmp_path):
    from framework.v2.eval.benchmark_app import _CREDTEST_SIGNAL
    from vigil_integration.live.runtime_redrive import credential_acceptance_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve_benchmark()
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    corpus = {"admin:admin": {"username": "admin", "secret": "admin"}}
    policy = {"corpus_id": "OBSIDIAN-TEST-bench-cred", "should_reject": ["admin:admin"]}
    try:
        # POSITIVE: the VULNERABLE login accepts admin:admin; /credtest/account is auth-gated ⇒ a FACT
        pos = credential_acceptance_redrive(
            f"{base}/credtest/account", slug="alpha", engagement_slug="alpha", signers=_signers(),
            corpus=corpus, policy=policy,
            protected_resource={"url": f"{base}/credtest/account", "method": "GET",
                                "authenticated_signal": _CREDTEST_SIGNAL},
            login_spec={"url": f"{base}/credtest/login"})
        # SAFE TWIN 1: the REJECTING login (/credtest/login-strict) ⇒ no FACT
        twin1 = credential_acceptance_redrive(
            f"{base}/credtest/account", slug="alpha", engagement_slug="alpha", signers=_signers(),
            corpus=corpus, policy=policy,
            protected_resource={"url": f"{base}/credtest/account", "method": "GET",
                                "authenticated_signal": _CREDTEST_SIGNAL},
            login_spec={"url": f"{base}/credtest/login-strict"})
        # SAFE TWIN 2: the NON-auth-gated resource (/credtest/public) ⇒ no FACT (baseline not denied)
        twin2 = credential_acceptance_redrive(
            f"{base}/credtest/public", slug="alpha", engagement_slug="alpha", signers=_signers(),
            corpus=corpus, policy=policy,
            protected_resource={"url": f"{base}/credtest/public", "method": "GET",
                                "authenticated_signal": _CREDTEST_SIGNAL},
            login_spec={"url": f"{base}/credtest/login"})
    finally:
        srv.shutdown()
    assert pos.n_facts == 1, f"the planted benchmark credential scenario must mint one FACT; notes={pos.notes}"
    assert twin1.n_facts == 0, "the rejecting-login safe twin must mint nothing"
    assert twin2.n_facts == 0, "the non-auth-gated safe twin must mint nothing"
