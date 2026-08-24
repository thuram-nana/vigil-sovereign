"""W16-12 — per-user RBAC + authenticated-principal attribution on the offense gated API.

Before this slice the loopback external API (`framework.v2.api`) had ONE auth path: an optional shared
bearer (`CRUCIBLE_API_KEY`), off by default — no users, no roles, no sessions, and no attribution of an
action to a human. This suite drives the API's HTTP surface directly and proves it now consumes the SAME
multi-user model as the offense console: the `vigil up` proxy resolves the caller against the owner-signed
sovereign accounts spine and STAMPS a hop-signed `X-VIGIL-Role` (bound under the per-run
`VIGIL_CONSOLE_HOP_KEY`, shared ONLY with the offense children), and the API enforces
`role_can(stamped_role, offense_perm_for(path))` and ATTRIBUTES the action to the authenticated principal.

  * NEGATIVE CONTROL: a viewer/analyst-stamped (validly HMAC'd) POST to an operator route → 403, the
    refusal NAMES the principal, and the tool NEVER runs (the gate is not a no-op);
  * POSITIVE CONTROL: an operator-stamped POST to an operator route reaches the handler AND the response
    attributes the action to the authenticated principal;
  * a FORGED `X-VIGIL-Role: owner` WITHOUT a valid HMAC (or wrong key / stale ts / wrong path) → 403;
  * NO hop headers but a valid loopback+same-origin request → full access (direct credential-holder =
    owner-equivalent, the no-regression path), attributed as the on-host operator;
  * an UNMAPPED POST route WITH a valid hop assertion → default-deny 403 (even owner);
  * an API with NO hop key refuses any stamped role but still allows the direct credential-holder;
  * the hop key can arrive via `$VIGIL_CONSOLE_HOP_KEY` (how `vigil up` hands it to the child);
  * FATAL-2: importing `api.server` co-loads no `sigil.*`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from framework.v2.agents.tools.base import ToolRegistry, ToolResult
from framework.v2.api import actions, server

HOP_KEY = "hop-key-test-518-a1b2c3d4e5f6"

INVOKE = "/api/v1/tool/invoke"       # run_engagement (operator+) — an ordinary offense action
IMPORT = "/api/v1/import"            # run_engagement (operator+)
UNMAPPED = "/api/v1/does-not-exist"  # not in the map → default-deny


class _SpyHostTool:
    """A gated tool that records whether its body ever executed — the proof that a REFUSED action
    (403 at the RBAC gate) never reaches the tool at all."""

    name = "spy_scan"
    tier = "T2"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def __init__(self) -> None:
        self.ran = False

    def run(self, args, ctx) -> ToolResult:
        self.ran = True
        return ToolResult(ok=True, summary="ran")


def _registry_with_spy() -> tuple[ToolRegistry, _SpyHostTool]:
    reg = actions.default_registry(import_store_factory=lambda: None)
    spy = _SpyHostTool()
    reg.register(spy)
    return reg, spy


@contextmanager
def _running(registry=None, hop_key=HOP_KEY):
    httpd = server.serve(host="127.0.0.1", port=0, registry=registry, hop_key=hop_key,
                         import_store_factory=lambda: None)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _hop_headers(role: str, path: str, *, principal: str = "alice", hop_key: str = HOP_KEY,
                 ts: str | None = None, method: str = "POST") -> dict:
    """The exact identity headers the proxy stamps: principal/role + the HMAC over
    `principal\\nrole\\nmethod\\npath\\nts` under the hop key + the ts."""
    ts = ts if ts is not None else str(int(time.time()))
    msg = f"{principal}\n{role}\n{method}\n{path}\n{ts}".encode("utf-8")
    sig = base64.b64encode(hmac.new(hop_key.encode("utf-8"), msg, hashlib.sha256).digest()).decode("ascii")
    return {"X-VIGIL-Principal": principal, "X-VIGIL-Role": role,
            "X-VIGIL-Role-Sig": sig, "X-VIGIL-Role-Ts": ts}


def _post(base: str, path: str, *, body=None, extra_headers: dict | None = None, csrf: bool = True):
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(base + path, method="POST", data=data)
    if csrf:
        req.add_header("X-Requested-With", "fetch")     # the same-origin custom header a cross-site form cannot set
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


_REVERIFY_BODY = {"slug": "demo", "tool": "reverify_finding",
                  "args": {"finding": {"bug_class": "xss", "oracle_context": None}}}


# --- NEGATIVE CONTROL: a role lacking the permission is refused AND attributed, tool never runs -------
def test_viewer_stamped_invoke_is_refused_attributed_and_tool_never_runs():
    reg, spy = _registry_with_spy()
    with _running(registry=reg) as base:
        st, body = _post(base, INVOKE, body={"slug": "x", "tool": "spy_scan", "args": {}},
                         extra_headers=_hop_headers("viewer", INVOKE))
        assert st == 403, f"a viewer lacking run_engagement must be refused, got {st}"
        # the refusal is ATTRIBUTED — it names the principal and the role it refused.
        assert body["principal"] == "alice" and body["role"] == "viewer"
        assert "run_engagement" in body["error"] and "forbidden" in body["error"]
    # the load-bearing negative control: a refused action NEVER executed the tool (the gate is not a no-op).
    assert spy.ran is False


def test_analyst_stamped_invoke_is_refused_and_attributed():
    with _running() as base:
        st, body = _post(base, INVOKE, body=_REVERIFY_BODY,
                         extra_headers=_hop_headers("analyst", INVOKE, principal="bob"))
        assert st == 403 and body["principal"] == "bob" and body["role"] == "analyst"


# --- POSITIVE CONTROL: an operator/owner reaches the handler AND the action is attributed -------------
def test_operator_stamped_invoke_reaches_handler_and_is_attributed():
    with _running() as base:
        st, body = _post(base, INVOKE, body=_REVERIFY_BODY,
                         extra_headers=_hop_headers("operator", INVOKE, principal="carol"))
        assert st == 200, f"an operator carrying run_engagement must pass RBAC, got {st}: {body}"
        # it reached the GATED-invoke handler (a "gate" field is the action-layer result, not an auth 403);
        # whether the downstream gate chain then admits the tool is orthogonal to RBAC.
        assert "gate" in body, f"an operator must reach the action handler, got {body}"
        # the action names the AUTHENTICATED principal — not an OS login + git config.
        assert body["actor"]["principal"] == "carol" and body["actor"]["role"] == "operator"
        assert body["actor"]["authenticated"] is True and body["actor"]["via"] == "hop"


def test_owner_stamped_invoke_reaches_handler():
    with _running() as base:
        st, body = _post(base, INVOKE, body=_REVERIFY_BODY,
                         extra_headers=_hop_headers("owner", INVOKE))
        assert st == 200 and body["actor"]["role"] == "owner"


# --- forgery / replay: a stamped role that does not verify never lifts -------------------------------
def test_forged_or_replayed_role_assertion_is_refused():
    with _running() as base:
        # a bare, unsigned X-VIGIL-Role: owner (guessed header name, no key)
        assert _post(base, INVOKE, body=_REVERIFY_BODY,
                     extra_headers={"X-VIGIL-Role": "owner"})[0] == 403
        # a signature under the WRONG key
        bad = _hop_headers("owner", INVOKE, hop_key="not-the-real-hop-key")
        assert _post(base, INVOKE, body=_REVERIFY_BODY, extra_headers=bad)[0] == 403
        # a STALE timestamp (outside the freshness window)
        stale = _hop_headers("owner", INVOKE, ts=str(int(time.time()) - 120))
        assert _post(base, INVOKE, body=_REVERIFY_BODY, extra_headers=stale)[0] == 403
        # a valid signature bound to a DIFFERENT path cannot be re-aimed at the invoke route
        wrong_path = _hop_headers("owner", IMPORT)
        assert _post(base, INVOKE, body=_REVERIFY_BODY, extra_headers=wrong_path)[0] == 403


# --- no-regression: the direct credential-holder path (no hop headers) keeps full access -------------
def test_no_hop_headers_keeps_full_access_and_is_attributed_as_on_host():
    with _running() as base:
        st, body = _post(base, INVOKE, body=_REVERIFY_BODY)   # no X-VIGIL-* headers at all
        assert st == 200, f"a direct loopback credential-holder must keep full access, got {st}"
        # honest attribution: the on-host operator, NOT a named authenticated human.
        assert body["actor"]["via"] == "direct-credential"
        assert body["actor"]["authenticated"] is False


# --- default-deny: an unmapped route under a valid hop assertion refuses even owner ------------------
def test_unmapped_route_with_valid_hop_assertion_is_default_deny():
    with _running() as base:
        st, _ = _post(base, UNMAPPED, extra_headers=_hop_headers("owner", UNMAPPED))
        assert st == 403
    # by contrast a DIRECT credential-holder reaches the 404 'unknown action' (the no-regression path).
    with _running() as base:
        st, body = _post(base, UNMAPPED)
        assert st == 404 and "unknown action" in body["error"]


# --- fail-closed: no hop key ⇒ no stamped role trusted, but the direct path still works --------------
def test_api_with_no_hop_key_refuses_stamped_role_but_allows_direct(monkeypatch):
    monkeypatch.delenv("VIGIL_CONSOLE_HOP_KEY", raising=False)
    with _running(hop_key="") as base:
        assert _post(base, INVOKE, body=_REVERIFY_BODY,
                     extra_headers=_hop_headers("operator", INVOKE))[0] == 403
        assert _post(base, INVOKE, body=_REVERIFY_BODY)[0] == 200   # direct credential-holder still works


def test_hop_key_loaded_from_env(monkeypatch):
    # how `vigil up` hands the key to the api child: via $VIGIL_CONSOLE_HOP_KEY, not an explicit arg.
    monkeypatch.setenv("VIGIL_CONSOLE_HOP_KEY", HOP_KEY)
    with _running(hop_key=None) as base:
        st, body = _post(base, INVOKE, body=_REVERIFY_BODY,
                         extra_headers=_hop_headers("operator", INVOKE))
        assert st == 200 and body["actor"]["principal"] == "alice"
        # and a viewer under the same env key is still refused (the env key really gates, both ways)
        assert _post(base, INVOKE, body=_REVERIFY_BODY,
                     extra_headers=_hop_headers("viewer", INVOKE))[0] == 403


# --- FATAL-2 -----------------------------------------------------------------------------------------
def test_importing_api_server_loads_no_sigil():
    __import__("framework.v2.api.server")
    leaked = [m for m in sys.modules if m == "sigil" or m.startswith("sigil.")]
    assert not leaked, f"FATAL-2: offense api co-loaded sovereign modules {leaked}"
