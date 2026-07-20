"""
api — the loopback, gated external API (Wave 6).

Pins the load-bearing security guarantees. A downstream review probes these HARD:

  * LOOPBACK-ONLY, DEFAULT-SAFE: ``serve`` refuses any non-loopback bind; the default
    host is loopback; nothing runs unless started.
  * READ-FIRST: the GET surface returns resilient JSON and issues no traffic.
  * GATED ACTIONS: every POST is a tool invocation through the fail-closed gate chain —
    an out-of-scope / unentitled action is REFUSED, the tool NEVER runs, nothing is sent.
  * NO GATE BYPASS: a cross-site POST (missing custom header, cross-site fetch, foreign
    Origin, DNS-rebinding/malformed Host) is refused BEFORE any action.
  * UNTRUSTED INPUT: a malformed / oversize / non-object body fails as a clean 4xx,
    never a traceback; there is no static-file / path-traversal surface.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from framework.v2.agents.tools.base import ToolRegistry, ToolResult
from framework.v2.api import actions, reads, server


# ---------------------------------------------------------------------------
# loopback-only + default-safe
# ---------------------------------------------------------------------------


def test_serve_refuses_non_loopback() -> None:
    for host in ("0.0.0.0", "192.168.1.10", "::", "10.0.0.5"):
        with pytest.raises(ValueError, match="loopback only"):
            server.serve(host=host, port=0)


def test_serve_defaults_to_loopback() -> None:
    import inspect
    sig = inspect.signature(server.serve)
    assert sig.parameters["host"].default == "127.0.0.1"


# ---------------------------------------------------------------------------
# a stub gated tool that records whether it ran + whether it "sent" anything
# ---------------------------------------------------------------------------


class _SpyHostTool:
    """A gated tool that acts on a host (so the charter-scope gate applies) and records
    if its body ever executed — the proof that a refused action never runs."""

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
def _running(registry=None, import_store_factory=None, api_key=None):
    httpd = server.serve(host="127.0.0.1", port=0, registry=registry,
                         import_store_factory=import_store_factory, api_key=api_key)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}/api/v1"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, json.loads(r.read())


def _post(url: str, body=None, *, csrf=True, headers=None, raw: bytes | None = None):
    data = raw if raw is not None else json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(url, method="POST", data=data)
    if csrf:
        req.add_header("X-Requested-With", "fetch")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# ---------------------------------------------------------------------------
# read-first surface
# ---------------------------------------------------------------------------


def test_read_surface_is_resilient_json() -> None:
    with _running() as base:
        assert _get(base + "/status")[1].keys() >= {"paths", "backends"}
        assert "engagements" in _get(base + "/engagements")[1]
        assert "runs" in _get(base + "/runs")[1]
        tools = _get(base + "/tools")[1]["tools"]
        names = {t["name"] for t in tools}
        assert {"reverify_finding", "import_findings"} <= names
        # the importer is enumerated as passive: no egress, not destructive.
        imp = next(t for t in tools if t["name"] == "import_findings")
        assert imp["destructive"] is False and imp["reaches_hosts"] is False


def test_unknown_endpoint_is_404() -> None:
    with _running() as base:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(base + "/does-not-exist")
        assert ei.value.code == 404
        # there is NO static-file surface — a traversal-looking path is just an unknown API.
        with pytest.raises(urllib.error.HTTPError) as ei2:
            _get(base + "/../__main__.py")
        assert ei2.value.code in (400, 404)


# ---------------------------------------------------------------------------
# GATED actions — the core safety story
# ---------------------------------------------------------------------------


def test_gated_action_refused_out_of_scope_and_tool_never_runs() -> None:
    reg, spy = _registry_with_spy()
    with _running(registry=reg) as base:
        st, body = _post(base + "/tool/invoke", {
            "slug": "no-such-engagement", "tool": "spy_scan",
            "args": {"target": "http://out-of-scope.example/"}})
        assert st == 200
        assert body["refused"] is True and body["gate"] == "scope"
        assert body["ok"] is False
    # the load-bearing assertion: a refused action NEVER executed the tool.
    assert spy.ran is False


def test_unknown_tool_is_refused_not_run() -> None:
    with _running() as base:
        st, body = _post(base + "/tool/invoke", {"slug": "x", "tool": "exploit_everything", "args": {}})
        assert st == 200 and body["ok"] is False and "no such tool" in body["note"]


def test_tool_invoke_requires_tool_name() -> None:
    with _running() as base:
        st, body = _post(base + "/tool/invoke", {"slug": "x", "args": {}})
        assert st == 400 and "tool" in body["error"]


def test_reverify_tool_invocable_and_safe() -> None:
    # reverify_finding is passive (no egress, no capability) -> it runs; a cert-less
    # finding is simply NOT grounded (never a crash, never a fabricated fact).
    with _running() as base:
        st, body = _post(base + "/tool/invoke", {
            "slug": "demo", "tool": "reverify_finding",
            "args": {"finding": {"bug_class": "xss", "oracle_context": None}}})
        assert st == 200 and body["ok"] is True
        assert body["output"]["is_fact"] is False


# ---------------------------------------------------------------------------
# CSRF / same-origin — no gate bypass from a browser
# ---------------------------------------------------------------------------


def test_cross_site_post_refused_before_action() -> None:
    reg, spy = _registry_with_spy()
    with _running(registry=reg) as base:
        # missing custom header (a cross-site <form> cannot set it)
        st, body = _post(base + "/tool/invoke", {"tool": "spy_scan"}, csrf=False)
        assert st == 403 and "X-Requested-With" in body["error"]
        # cross-site fetch metadata
        st, _ = _post(base + "/tool/invoke", {"tool": "spy_scan"}, headers={"Sec-Fetch-Site": "cross-site"})
        assert st == 403
        # foreign Origin
        st, _ = _post(base + "/tool/invoke", {"tool": "spy_scan"}, headers={"Origin": "http://evil.example"})
        assert st == 403
        # DNS-rebinding Host
        st, _ = _post(base + "/tool/invoke", {"tool": "spy_scan"}, headers={"Host": "evil.example"})
        assert st == 403
    assert spy.ran is False  # not one of those reached the tool


def test_malformed_host_fails_closed_cleanly() -> None:
    with _running() as base:
        for bad in ("127.0.0.1:notaport", "127.0.0.1]", "[::1", "127.0.0.1:99999"):
            st, _ = _post(base + "/tool/invoke", {"tool": "reverify_finding"},
                          headers={"Host": bad})
            assert st == 403, f"malformed Host {bad!r} must be a clean 403, got {st}"


# ---------------------------------------------------------------------------
# untrusted input safety
# ---------------------------------------------------------------------------


def test_malformed_and_oversize_body_rejected_cleanly() -> None:
    with _running() as base:
        st, body = _post(base + "/tool/invoke", raw=b"{not valid json")
        assert st == 400 and "JSON" in body["error"]
        st, body = _post(base + "/tool/invoke", raw=b'"a string, not an object"')
        assert st == 400 and "object" in body["error"]
        # an oversize body is refused without buffering it into an action.
        big = b'{"x":"' + b"A" * (9 * 1024 * 1024) + b'"}'
        st, body = _post(base + "/tool/invoke", raw=big)
        assert st == 400 and "exceeds" in body["error"]


# ---------------------------------------------------------------------------
# importer over the API: mint leads, then read them back
# ---------------------------------------------------------------------------


def test_import_action_mints_leads_and_reads_back(tmp_path) -> None:
    from framework.v2.intel.store import IntelStore
    from framework.v2.memory.store import Store

    db = tmp_path / "api.db"
    factory = lambda: IntelStore(Store(db))  # noqa: E731
    export = json.dumps({"findings": [
        {"bug_class": "xss", "url": "http://t.example/s?q=1", "severity": "high"}]})

    with _running(import_store_factory=factory) as base:
        st, body = _post(base + "/import", {"slug": "demo", "format": "generic", "report": export})
        assert st == 200 and body["ok"] is True and body["refused"] is False
        assert len(body["output"]["leads"]) == 1
        assert body["output"]["applied"] > 0

        # the leads are enumerable via the read surface, labelled unverified.
        st, view = _get(base + "/imports/demo")
        assert st == 200 and view["count"] >= 1
        assert all(row["unverified"] for row in view["leads"])
        assert view["leads"][0]["bug_class"] == "xss"


def test_import_action_still_passes_through_gate_chain() -> None:
    # the /import convenience route is routed through invoke_tool: a bad format is a
    # clean failed result (not a crash), proving it went through the tool, not a raw call.
    with _running(import_store_factory=lambda: None) as base:
        st, body = _post(base + "/import", {"slug": "demo", "format": "nessus", "report": "<x/>"})
        assert st == 200 and body["ok"] is False


# ---------------------------------------------------------------------------
# the action layer refuses a destructive tool (no interactive operator on an API)
# ---------------------------------------------------------------------------


def test_destructive_tool_refused_on_api() -> None:
    class _Destructive:
        name = "wipe"
        tier = "T3"
        capability = None
        destructive = True
        egress_hosts: tuple = ()

        def __init__(self) -> None:
            self.ran = False

        def run(self, args, ctx) -> ToolResult:
            self.ran = True
            return ToolResult(ok=True)

    reg = actions.default_registry(import_store_factory=lambda: None)
    dtool = _Destructive()
    reg.register(dtool)
    with _running(registry=reg) as base:
        st, body = _post(base + "/tool/invoke", {"slug": "demo", "tool": "wipe", "args": {}})
        assert st == 200 and body["refused"] is True
        assert body["gate"] == "destructive-confirm"
    assert dtool.ran is False


# ---------------------------------------------------------------------------
# OPTIONAL API-key hardening (api.authn) — stacked ON TOP of loopback + same-origin
# ---------------------------------------------------------------------------


def _get_status(url: str, *, headers=None) -> int:
    req = urllib.request.Request(url, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_api_key_refuses_absent_or_wrong_key_when_configured() -> None:
    # With a key configured, EVERY request (read AND action) must present it — fail-closed.
    with _running(api_key="s3cret") as base:
        # GET: no key -> 401; wrong key -> 403; right key -> 200.
        assert _get_status(base + "/status") == 401
        assert _get_status(base + "/status", headers={"X-Relay-Key": "nope"}) == 403
        assert _get_status(base + "/status", headers={"X-Relay-Key": "s3cret"}) == 200
        # the key is also accepted as a standard bearer token.
        assert _get_status(base + "/status", headers={"Authorization": "Bearer s3cret"}) == 200
        # POST: no key -> 401 (before the same-origin/body handling); right key -> 200.
        st, body = _post(base + "/tool/invoke", {"tool": "reverify_finding"},
                         headers={"X-Relay-Key": "wrong"})
        assert st == 403
        st, _ = _post(base + "/tool/invoke", {"tool": "reverify_finding"}, csrf=False)
        assert st == 401  # absent key is refused BEFORE the same-origin guard even fires
        # a correct key still has to pass the existing same-origin (csrf) guard on top.
        st, body = _post(base + "/tool/invoke",
                         {"slug": "demo", "tool": "reverify_finding",
                          "args": {"finding": {"bug_class": "xss", "oracle_context": None}}},
                         headers={"Authorization": "Bearer s3cret"})
        assert st == 200 and body["ok"] is True


def test_api_key_is_noop_when_unset(monkeypatch) -> None:
    # The default (no key configured, env unset) is UNCHANGED behaviour: reads and gated
    # actions work with NO key header at all — the loopback + same-origin guards still apply.
    monkeypatch.delenv("CRUCIBLE_API_KEY", raising=False)
    with _running() as base:
        assert _get_status(base + "/status") == 200
        st, body = _post(base + "/tool/invoke",
                         {"slug": "demo", "tool": "reverify_finding",
                          "args": {"finding": {"bug_class": "xss", "oracle_context": None}}})
        assert st == 200 and body["ok"] is True


def test_api_key_loaded_from_env_when_not_passed(monkeypatch) -> None:
    # serve(api_key=None) falls back to CRUCIBLE_API_KEY, so an operator can front the API
    # behind a proxy purely via the environment.
    monkeypatch.setenv("CRUCIBLE_API_KEY", "envkey")
    with _running() as base:
        assert _get_status(base + "/status") == 401
        assert _get_status(base + "/status", headers={"X-Relay-Key": "envkey"}) == 200
