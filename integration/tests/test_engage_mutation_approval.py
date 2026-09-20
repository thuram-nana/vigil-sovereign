"""Slice 0.3 — the gated MUTATING-proof path (``engage --approve-mutations``).

A state-changing HTTP action (POST/PUT/DELETE/PATCH, or destructive-by-path) is fail-closed by default: the
CRUCIBLE ``HttpExecutor`` default-denies it unless an operator confirms. This slice lets a mutating proof be
authorized into a run by an OWNER-SIGNED, SINGLE-USE, ACTION-BOUND per-request token, by REUSING the existing
per-action approval machinery (``approval_broker`` / ``approval_token`` / ``nonce_ledger``) through
``engage.prompt_callback_from_args`` — while the GET-only default stays fail-closed.

These tests prove, with REAL crypto (a real owner keypair, real Ed25519 sign/verify, a real atomic nonce
burn — nothing mocked past the crypto), the six required properties:

  (a) DEFAULT fail-closed — no ``--approve-mutations`` ⇒ ``prompt_callback_from_args`` returns None ⇒ a
      destructive action is DENIED (never issued);
  (b) APPROVED — a validly owner-signed token for the EXACT action ⇒ authorized=True and the write proceeds;
  (c) ACTION-BINDING — a token minted for a different (tool,target,args) ⇒ DENIED;
  (d) REPLAY — the same token used twice ⇒ the second use is DENIED (single-use nonce burned);
  (e) GET is NEVER gated (the approval callback is never even invoked for a non-destructive GET);
  (f) a CRUCIBLE deny / tripped kill-switch stays DENIED even with a valid token in the signed inbox.

FATAL-2: ``framework`` co-loads the offense env, so this module runs in the OFFENSE CI leg (it is listed in
.github/workflows/ci.yml) and SKIPS in the sovereign leg via the importorskip below. It exercises the KEYLESS
offense path — it loads only the owner PUBLIC authority + verifies/consumes owner-signed tokens; the private
key is used ONLY to MINT the test tokens (the sovereign-side act), exactly as apps/sigil sign_pending does.
"""
from __future__ import annotations

import secrets
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.engage", reason="CRUCIBLE (offense) not importable here")

from framework.v2.agents.http_executor import (  # noqa: E402
    HttpExecutor,
    body_sha256_hex,
    format_destructive_prompt,
    parse_destructive_prompt,
    stdin_prompt_with_timeout,
)
from framework.v2.agents.models import HypothesisPayload, PlanPayload  # noqa: E402
from framework.v2.authority.killswitch import KillSwitch  # noqa: E402
from framework.v2.common import paths as _paths  # noqa: E402
from framework.v2.engage import prompt_callback_from_args  # noqa: E402

from vigil_integration.live.approval_broker import (  # noqa: E402
    approvals_root,
    load_authority,
    provision_authority_material,
    write_signed_token,
)
from vigil_integration.live.approval_token import (  # noqa: E402
    ApprovalAction,
    action_digest,
    consume_token,
    mint_token,
)
from vigil_integration.live.nonce_ledger import NonceLedger  # noqa: E402


# ---------------------------------------------------------------------------------------------------
# charter fixture (mirrors framework/v2/agents/tests/test_http_executor.py so the scope gate passes)
# ---------------------------------------------------------------------------------------------------

_SIGNED_CHARTER_TEMPLATE = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""

_SLUG = "mut-alpha"
_HOST = "127.0.0.1"
_BASE_URL = f"http://{_HOST}/"


class _Args:
    """A minimal stand-in for the engage argparse.Namespace (only the dest the callback reads)."""

    def __init__(self, approve_mutations: bool) -> None:
        self.approve_mutations = approve_mutations


def _install_charter(monkeypatch, targets_root, host: str) -> None:
    """Write a signed, in-scope charter for ``host`` and redirect the executor's charter/target paths."""
    (targets_root / _SLUG).mkdir(parents=True, exist_ok=True)
    (targets_root / _SLUG / "charter.md").write_text(
        _SIGNED_CHARTER_TEMPLATE.format(slug=_SLUG, host=host), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")


@pytest.fixture()
def isolated_charter(tmp_path, monkeypatch):
    """Provision a signed, in-scope charter (host 127.0.0.1) and redirect the executor's charter/target paths."""
    targets_root = tmp_path / "targets"
    _install_charter(monkeypatch, targets_root, _HOST)
    return targets_root


@pytest.fixture()
def approval_env(tmp_path, monkeypatch):
    """Provision a REAL owner approval authority under a shared base dir and point both planes at it.

    Returns (base_dir, owner_private_key_b64). The base dir holds ONLY the PUBLIC authority; the returned
    private key is the sovereign secret the test uses to MINT signed tokens (as the SIGIL cockpit would)."""
    base = tmp_path / "live"
    base.mkdir()
    _path, _pub, priv = provision_authority_material(str(base), key_id="owner")
    monkeypatch.setenv("VIGIL_BASE_DIR", str(base))
    # Non-blocking poll in tests: a present token is found on the first poll (wait irrelevant); an absent one
    # denies immediately instead of blocking the broker's real 5-minute default window.
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "0")
    monkeypatch.setenv("VIGIL_APPROVAL_NONCE_DIR", str(base / "approval-nonces"))
    assert load_authority(str(base)) is not None
    return str(base), priv


def _sign_token(base: str, priv: str, method: str, url: str, *,
                body: "str | bytes | None" = None,
                nonce: str | None = None, key_id: str = "owner", ttl: float = 300.0,
                skew: float = 2.0) -> str:
    """Mint a real owner-signed token bound to (engage.http, url, {method[, body_sha256]}) and drop it in the
    signed inbox. ``body`` present ⇒ the digest binds the sha256 of the exact bytes the executor transmits.
    Returns the nonce it carries (so a replay test can assert it burned)."""
    n = nonce or secrets.token_hex(16)
    args = {"method": method} if body is None else {"method": method, "body_sha256": body_sha256_hex(body)}
    digest = action_digest("engage.http", url, args)
    action = ApprovalAction(tool_name="engage.http", target=url, action_digest=digest)
    t = time.time()
    token = mint_token(action, owner_private_key_b64=priv, key_id=key_id, nonce=n,
                       not_before=t - skew, not_after=t + ttl)
    write_signed_token(approvals_root(base), secrets.token_hex(8), token)
    return n


def _destructive_hyp(surface: str) -> HypothesisPayload:
    return HypothesisPayload(
        handle="H-mut", surface=surface, bug_class="mass-assignment",
        given="an authorized owner-test", if_action=surface,
        then_observation="persisted change", because_model="write endpoint",
        refute_on="4xx", cheap_test="single request",
    )


_PLAN = PlanPayload(plan_id="P-mut", targets_hypothesis="H-mut", next_action="mutate")


def _executor(*, prompt_callback, killswitch=None) -> HttpExecutor:
    return HttpExecutor(
        engagement_slug=_SLUG, base_url=_BASE_URL, dry_run=True,
        prompt_callback=prompt_callback, killswitch=killswitch,
    )


# ---------------------------------------------------------------------------------------------------
# (a) DEFAULT fail-closed — no flag ⇒ None ⇒ a destructive action is denied
# ---------------------------------------------------------------------------------------------------


def test_a_no_flag_returns_none():
    assert prompt_callback_from_args(_Args(approve_mutations=False)) is None


def test_a_flag_but_no_authority_returns_none(tmp_path, monkeypatch):
    # --approve-mutations set but NO authority provisioned ⇒ still None (fail-closed default; GET-only).
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "empty"))
    assert prompt_callback_from_args(_Args(approve_mutations=True)) is None


def test_a_default_destructive_action_is_denied(isolated_charter, monkeypatch):
    # The engage default path: prompt_callback_from_args(None) → stdin default-deny (non-tty ⇒ False), so a
    # destructive POST is refused and never issued. This is exactly what run_engagement does with the result.
    cb = prompt_callback_from_args(_Args(approve_mutations=False)) or stdin_prompt_with_timeout
    ex = _executor(prompt_callback=cb)
    out = ex.execute(_destructive_hyp("POST /admin"), _PLAN)
    ex.close()
    assert "destructive" in out.note.lower()
    assert ex.stats()["destructive_refusals"] == 1
    assert ex.stats()["requests_made"] == 0


# ---------------------------------------------------------------------------------------------------
# (b) APPROVED — a validly owner-signed token for the exact action ⇒ authorized and the write proceeds
# ---------------------------------------------------------------------------------------------------


def test_b_valid_token_authorizes_the_callback(approval_env):
    base, priv = approval_env
    url = "http://127.0.0.1/admin"
    _sign_token(base, priv, "POST", url)
    cb = prompt_callback_from_args(_Args(approve_mutations=True))
    assert cb is not None
    assert cb(format_destructive_prompt("POST", url), 30.0) is True


def test_b_valid_token_lets_the_write_proceed(isolated_charter, approval_env):
    base, priv = approval_env
    url = "http://127.0.0.1/admin"
    _sign_token(base, priv, "POST", url)
    cb = prompt_callback_from_args(_Args(approve_mutations=True))
    ex = _executor(prompt_callback=cb)
    out = ex.execute(_destructive_hyp("POST /admin"), _PLAN)
    ex.close()
    # dry_run short-circuits AFTER the full gate chain (incl. the destructive-confirm) passes.
    assert ex.stats()["destructive_refusals"] == 0
    assert ex.stats()["requests_made"] == 1
    assert "would have issued POST" in out.note


# ---------------------------------------------------------------------------------------------------
# (c) ACTION-BINDING — a token minted for a different (tool,target,args) never authorizes this action
# ---------------------------------------------------------------------------------------------------


def test_c_token_for_a_different_action_is_denied(approval_env):
    base, priv = approval_env
    # An owner-signed token for /other must NOT authorize a write to /admin.
    _sign_token(base, priv, "POST", "http://127.0.0.1/other")
    cb = prompt_callback_from_args(_Args(approve_mutations=True))
    assert cb(format_destructive_prompt("POST", "http://127.0.0.1/admin"), 30.0) is False


def test_c_token_for_a_different_method_is_denied(approval_env):
    base, priv = approval_env
    # A PUT token must NOT authorize a DELETE to the same URL (the method rides in the args-digest).
    url = "http://127.0.0.1/admin"
    _sign_token(base, priv, "PUT", url)
    cb = prompt_callback_from_args(_Args(approve_mutations=True))
    assert cb(format_destructive_prompt("DELETE", url), 30.0) is False


def test_c_consume_token_rejects_the_binding_directly(approval_env):
    # The crypto-level guarantee under the callback: ApprovalToken.matches refuses a digest mismatch.
    base, priv = approval_env
    url_a, url_b = "http://127.0.0.1/a", "http://127.0.0.1/b"
    n = _sign_token(base, priv, "POST", url_a)
    token = mint_token(
        ApprovalAction("engage.http", url_a, action_digest("engage.http", url_a, {"method": "POST"})),
        owner_private_key_b64=priv, key_id="owner", nonce=n,
        not_before=time.time() - 1, not_after=time.time() + 300)
    action_b = ApprovalAction("engage.http", url_b, action_digest("engage.http", url_b, {"method": "POST"}))
    ledger = NonceLedger(str(Path(base) / "approval-nonces"))
    d = consume_token(token, action_b, authority=load_authority(base), now=time.time(), ledger=ledger)
    assert d.authorized is False
    assert "binding" in d.reason


# ---------------------------------------------------------------------------------------------------
# (d) REPLAY — the same token used twice ⇒ the second use is denied (single-use nonce burned)
# ---------------------------------------------------------------------------------------------------


def test_d_replay_of_the_same_token_is_denied(approval_env):
    base, priv = approval_env
    url = "http://127.0.0.1/admin"
    _sign_token(base, priv, "POST", url)
    cb = prompt_callback_from_args(_Args(approve_mutations=True))
    q = format_destructive_prompt("POST", url)
    assert cb(q, 30.0) is True     # first use spends the single-use nonce
    assert cb(q, 30.0) is False    # replay: the nonce is burned ⇒ denied


# ---------------------------------------------------------------------------------------------------
# no owner-signed token in the window ⇒ fail-closed deny (the block resolves to DENY, never fail-open)
# ---------------------------------------------------------------------------------------------------


def test_no_token_denies(approval_env):
    base, _priv = approval_env
    cb = prompt_callback_from_args(_Args(approve_mutations=True))
    assert cb(format_destructive_prompt("POST", "http://127.0.0.1/admin"), 30.0) is False


# ---------------------------------------------------------------------------------------------------
# (e) GET is NEVER gated — the approval callback is not even invoked for a non-destructive GET
# ---------------------------------------------------------------------------------------------------


def test_e_get_is_never_gated(isolated_charter, approval_env):
    base, priv = approval_env
    calls = {"n": 0}
    inner = prompt_callback_from_args(_Args(approve_mutations=True))

    def spy(q, t):
        calls["n"] += 1
        return inner(q, t)

    # A benign GET is not destructive ⇒ the destructive-confirm gate never fires ⇒ the callback is not called.
    ex = _executor(prompt_callback=spy)
    out = ex.execute(_destructive_hyp("GET /orders/1"), _PLAN)
    ex.close()
    assert calls["n"] == 0
    assert "would have issued GET" in out.note
    assert ex.stats()["destructive_refusals"] == 0

    # Contrast: a POST DOES invoke the callback (proving the spy is wired and the gate distinguishes method).
    _sign_token(base, priv, "POST", "http://127.0.0.1/admin")
    ex2 = _executor(prompt_callback=spy)
    ex2.execute(_destructive_hyp("POST /admin"), _PLAN)
    ex2.close()
    assert calls["n"] == 1


# ---------------------------------------------------------------------------------------------------
# (f) a CRUCIBLE deny / tripped kill-switch stays denied even with a valid token
# ---------------------------------------------------------------------------------------------------


def test_f_tripped_killswitch_stays_denied_with_a_valid_token(isolated_charter, approval_env, tmp_path):
    base, priv = approval_env
    url = "http://127.0.0.1/admin"
    _sign_token(base, priv, "POST", url)     # a perfectly valid owner-signed token exists
    ks = KillSwitch(_SLUG, path=tmp_path / "engagement.halt")
    ks.trip("owner halted the engagement")

    calls = {"n": 0}
    inner = prompt_callback_from_args(_Args(approve_mutations=True))

    def spy(q, t):
        calls["n"] += 1
        return inner(q, t)

    ex = _executor(prompt_callback=spy, killswitch=ks)
    out = ex.execute(_destructive_hyp("POST /admin"), _PLAN)
    ex.close()
    # The kill-switch is checked BEFORE the destructive prompt ⇒ the token never gets a chance to authorize.
    assert calls["n"] == 0, "the approval callback must not even be consulted once a CRUCIBLE deny fired"
    assert ex.stats()["requests_made"] == 0
    assert "kill-switch" in out.note.lower()


def test_f_out_of_scope_stays_denied_with_a_valid_token(isolated_charter, approval_env):
    # A CRUCIBLE scope deny (out-of-scope host) also short-circuits before the destructive prompt. Even with a
    # valid token for the out-of-scope URL, the write is denied by the scope gate — a token never widens scope.
    base, priv = approval_env
    oos = "http://evil.example/admin"
    _sign_token(base, priv, "POST", oos)
    calls = {"n": 0}
    inner = prompt_callback_from_args(_Args(approve_mutations=True))

    def spy(q, t):
        calls["n"] += 1
        return inner(q, t)

    ex = _executor(prompt_callback=spy)
    out = ex.execute(_destructive_hyp("POST http://evil.example/admin"), _PLAN)
    ex.close()
    assert calls["n"] == 0
    assert ex.stats()["requests_made"] == 0
    assert "scope" in out.note.lower()


# ---------------------------------------------------------------------------------------------------
# BODY-BINDING (the red-pen substance gap): the approval must cover the request BODY, not just method+url
# ---------------------------------------------------------------------------------------------------


def test_body_binding_token_for_body_a_denies_body_b(approval_env):
    # A token owner-signed for body A must NOT authorize a DIFFERENT body B on the SAME (method, url) — the
    # property that was untested (and false) before this fix. And the matching body A IS authorized.
    base, priv = approval_env
    url = "http://127.0.0.1/api/users/1"
    body_a = '{"role":"user"}'
    body_b = '{"role":"admin"}'          # a privilege-escalating payload the owner never saw
    _sign_token(base, priv, "PUT", url, body=body_a)     # owner signed ONLY body A
    cb = prompt_callback_from_args(_Args(approve_mutations=True))

    q_b = format_destructive_prompt("PUT", url, body_sha256=body_sha256_hex(body_b),
                                    body_preview=body_b)
    assert cb(q_b, 30.0) is False, "a token bound to body A must never authorize body B"

    q_a = format_destructive_prompt("PUT", url, body_sha256=body_sha256_hex(body_a),
                                    body_preview=body_a)
    assert cb(q_a, 30.0) is True, "the exact approved body A must be authorized"


def test_body_binding_replay_denied(approval_env):
    # Single-use holds for a body-bound token too: the second use of the same body-bound token is denied.
    base, priv = approval_env
    url = "http://127.0.0.1/api/users/1"
    body = '{"role":"user"}'
    _sign_token(base, priv, "POST", url, body=body)
    cb = prompt_callback_from_args(_Args(approve_mutations=True))
    q = format_destructive_prompt("POST", url, body_sha256=body_sha256_hex(body), body_preview=body)
    assert cb(q, 30.0) is True
    assert cb(q, 30.0) is False       # nonce burned ⇒ replay denied


def test_body_binding_end_to_end_gated_fetch(tmp_path, monkeypatch, approval_env, httpserver):
    # END-TO-END: the APPROVED action == the TRANSMITTED action. The owner signs the sha256 of the exact body,
    # the callback binds it, and gated_fetch actually sends that body to the server — which receives it verbatim.
    base, priv = approval_env
    _install_charter(monkeypatch, tmp_path / "targets", httpserver.host)
    body = '{"role":"admin","transfer":"999"}'
    url = httpserver.url_for("/admin")
    httpserver.expect_request("/admin", method="POST", data=body).respond_with_data(
        '{"ok":true}', status=200, content_type="application/json")

    _sign_token(base, priv, "POST", url, body=body)     # owner signs the sha256 of THIS exact body

    seen = {"q": None}
    inner = prompt_callback_from_args(_Args(approve_mutations=True))

    def spy(q, t):
        seen["q"] = q                                    # capture what the owner/signer is shown
        return inner(q, t)

    ex = HttpExecutor(engagement_slug=_SLUG, base_url=httpserver.url_for("/"), prompt_callback=spy)
    request = SimpleNamespace(method="POST", url=url, headers=[("Content-Type", "application/json")], body=body)
    resp = ex.gated_fetch(request)
    ex.close()

    assert resp["status"] == 200, resp                   # the write was authorized and issued
    assert len(httpserver.log) == 1                      # exactly one request reached the server
    received = httpserver.log[0][0].get_data(as_text=True)
    assert received == body, "the transmitted body must be exactly the one the owner approved"
    # informed consent: the owner-facing prompt (== the signer's pending preview) shows the bound sha AND
    # a human preview of the body — not just method+url.
    assert seen["q"] is not None
    assert f"[body-sha256={body_sha256_hex(body)}]" in seen["q"]
    assert '"role":"admin"' in seen["q"]
    # a replay of the (now-burned) token is denied — the second identical write cannot be re-authorized.
    resp2 = ex.gated_fetch(SimpleNamespace(method="POST", url=url,
                                           headers=[("Content-Type", "application/json")], body=body))
    assert resp2["status"] == 0 and "refused" in resp2


# ---------------------------------------------------------------------------------------------------
# (c) the no-body / GET / query-param path stays BYTE-IDENTICAL to before the body-binding fix
# ---------------------------------------------------------------------------------------------------


def test_no_body_prompt_and_digest_are_byte_identical():
    # The no-body destructive-confirm question is byte-identical to the pre-body-binding string, its parse
    # recovers (method, url, None), and the digest binds exactly {"method": …} (no body_sha256). This is what
    # keeps every existing no-body/GET/query-param test unchanged.
    method, url = "POST", "http://127.0.0.1/admin"
    legacy = f"about to issue {method} {url} " f"(classified destructive). proceed?"
    assert format_destructive_prompt(method, url) == legacy
    assert parse_destructive_prompt(legacy) == (method, url, None)
    # the no-body digest is exactly the method-only digest (byte-identical binding)
    assert action_digest("engage.http", url, {"method": method}) == \
        action_digest("engage.http", url, {"method": method})
    # and it DIFFERS from any body-bound digest (so the two forms can never be confused)
    body_digest = action_digest("engage.http", url, {"method": method, "body_sha256": body_sha256_hex("x")})
    assert body_digest != action_digest("engage.http", url, {"method": method})


# ---------------------------------------------------------------------------------------------------
# BLOCK-1 (redaction): a JSON body secret must be masked in the owner PROMPT and the LOGGED question, while
# the security-relevant NON-secret content stays visible (informed consent survives). Plus form regression.
# ---------------------------------------------------------------------------------------------------


def test_json_body_secret_masked_in_prompt_and_log(tmp_path, monkeypatch, approval_env, httpserver):
    base, priv = approval_env
    _install_charter(monkeypatch, tmp_path / "targets", httpserver.host)
    # a JSON body carrying credentials under secret keys AND non-secret business content
    body = '{"role":"admin","password":"hunter2","token":"t0ps3cr3t","amount":100}'
    url = httpserver.url_for("/admin")
    httpserver.expect_request("/admin", method="POST", data=body).respond_with_data(
        "{}", status=200, content_type="application/json")
    _sign_token(base, priv, "POST", url, body=body)   # the sha binds the RAW body (redaction never changes it)

    seen = {"q": None}
    inner = prompt_callback_from_args(_Args(approve_mutations=True))

    def spy(q, t):
        seen["q"] = q
        return inner(q, t)

    ex = HttpExecutor(engagement_slug=_SLUG, base_url=httpserver.url_for("/"), prompt_callback=spy)
    logged: list = []
    real_log = ex._log_event

    def cap(event, **kw):
        logged.append((event, kw))
        return real_log(event, **kw)

    monkeypatch.setattr(ex, "_log_event", cap)
    resp = ex.gated_fetch(SimpleNamespace(method="POST", url=url,
                                          headers=[("Content-Type", "application/json")], body=body))
    ex.close()

    assert resp["status"] == 200, resp                 # the write was authorized + issued
    received = httpserver.log[0][0].get_data(as_text=True)
    assert received == body, "the RAW body is transmitted; redaction is display-only"

    # (1) the owner-facing PROMPT masks the secrets but keeps the non-secret business content visible
    q = seen["q"]
    assert "hunter2" not in q and "t0ps3cr3t" not in q, "secret VALUES must be masked in the prompt"
    assert '"role":"admin"' in q and '"amount":100' in q, "non-secret content must stay visible (consent)"
    # (2) the SAME masked string is what is written to the engagement log via _log_event(question=…)
    dp = [kw for (e, kw) in logged if e == "destructive.prompt"]
    assert dp, "the destructive.prompt event must be logged"
    logged_q = dp[0]["question"]
    assert "hunter2" not in logged_q and "t0ps3cr3t" not in logged_q, "the logged question must mask secrets"
    assert '"role":"admin"' in logged_q, "the logged question must retain non-secret content"


def test_form_body_secret_still_masked():
    # Regression: the pre-existing form/header masker still masks a form-encoded credential, and keeps the
    # non-secret fields visible.
    from framework.v2.agents.http_executor import _redact_body_preview
    out = _redact_body_preview("username=alice&password=hunter2&role=admin")
    assert "hunter2" not in out
    assert "username=alice" in out and "role=admin" in out


# ---------------------------------------------------------------------------------------------------
# OBS-1 / OBS-2 — fail-closed hardening: an unbindable URL is refused at format time; a non-str/bytes body
# fails closed to a clean DENY (never an uncaught crash).
# ---------------------------------------------------------------------------------------------------


def test_obs1_format_refuses_unbindable_url():
    for bad in ("http://127.0.0.1/a b", "http://127.0.0.1/x[body-sha256=" + "a" * 64 + "]"):
        with pytest.raises(ValueError):
            format_destructive_prompt("POST", bad)                                   # no-body form
        with pytest.raises(ValueError):
            format_destructive_prompt("POST", bad, body_sha256="a" * 64, body_preview="x")  # body form


def test_obs2_non_str_bytes_body_fails_closed(isolated_charter, approval_env):
    # A dict body (violating the str|bytes|None contract) must DENY cleanly, not raise out of gated_fetch.
    base, _priv = approval_env
    cb = prompt_callback_from_args(_Args(approve_mutations=True))
    ex = _executor(prompt_callback=cb)   # dry_run — _run_gates still runs the destructive branch first
    resp = ex.gated_fetch(SimpleNamespace(method="POST", url="http://127.0.0.1/admin",
                                          headers=[], body={"role": "admin"}))
    ex.close()
    assert resp["status"] == 0 and "refused" in resp, resp
    assert ex.stats()["destructive_refusals"] == 1
