"""WS-B — hosting the cockpit behind a domain (tunnel + reverse proxy), never a public listener.

The cockpit still binds a `bind_ok` address (loopback default; a PRIVATE/WireGuard IP allowed), NEVER
0.0.0.0 / a public address. To serve a real domain the operator puts a reverse proxy in front that
terminates TLS and forwards the original `Host`/`Origin`; those domain forms are unioned into the
anti-DNS-rebinding allowlist via `--allow-host`/`--allow-origin` (or the SIGIL_UI_ALLOWED_* env). This
suite proves: (1) a public/unspecified bind is refused (ValueError + CLI exit 2, no token minted);
(2) the default loopback posture is unchanged; (3) a configured domain Host+Origin is accepted while
every foreign Host/Origin is still refused.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_ui_remote.py -q
"""
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest

from sigil.spine.store import SpineStore
from sigil.ui.server import build_server

TOKEN = "remote-test-token-abc"
DOMAIN = "cockpit.example.com"
DOMAIN_ORIGIN = "https://cockpit.example.com"


def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve(spine_path, *, allowed_hosts=(), allowed_origins=()):
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path,
                       allowed_hosts=allowed_hosts, allowed_origins=allowed_origins)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _post_action(port, *, host, origin, action="disable_gesture"):
    """POST an owner-signed action carrying an explicit Host/Origin (as a reverse proxy would forward)."""
    h = {"X-SIGIL-Token": TOKEN, "Content-Type": "application/json", "Host": host, "Origin": origin}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/action",
                                 data=json.dumps({"action": action}).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


# --- (1) never a public bind ------------------------------------------------------------------------

# NB: genuinely GLOBALLY-ROUTABLE / unspecified / unparseable addresses only. bind_ok classifies the
# TEST-NET documentation ranges (203.0.113.0/24 etc.) as private-not-global, so they are NOT refused —
# they simply are not publicly routable; using one here would reach a real socket bind (OSError), not the
# ValueError we assert. The security property is "never a PUBLIC (globally routable) or 0.0.0.0 listener".
@pytest.mark.parametrize("bad", ["0.0.0.0", "::", "8.8.8.8", "2606:4700:4700::1111", "not-an-ip"])
def test_public_or_unspecified_bind_is_refused(bad):
    with pytest.raises(ValueError):
        build_server(token=TOKEN, host=bad, port=0, spine_path=_spine())


def test_cli_serve_exits_2_on_a_public_bind_and_mints_no_token(monkeypatch, capsys):
    from sigil.cli import cmd_serve

    class _Args:
        port = 0
        host = "0.0.0.0"
        allow_host: list = []
        allow_origin: list = []

    # if bind_ok were bypassed this would try to bind + mint a token; assert it fails closed instead.
    called = {"served": False}
    import sigil.ui.server as uiserver
    monkeypatch.setattr(uiserver, "serve", lambda **k: called.__setitem__("served", True))
    with pytest.raises(SystemExit) as ei:
        cmd_serve(_Args())
    assert ei.value.code == 2
    assert called["served"] is False, "no serve()/token when the bind is refused (fail-closed)"


# --- (2) default loopback posture unchanged ---------------------------------------------------------

def test_default_bind_is_loopback_with_the_loopback_allowlist():
    srv = build_server(token=TOKEN, port=0, spine_path=_spine())
    try:
        port = srv.server_address[1]
        assert srv.server_address[0] == "127.0.0.1"
        assert f"127.0.0.1:{port}" in srv.allowed_hosts and f"localhost:{port}" in srv.allowed_hosts
        assert f"http://127.0.0.1:{port}" in srv.allowed_origins
        # no domain leaked into the allowlist when none was configured
        assert DOMAIN not in srv.allowed_hosts and DOMAIN_ORIGIN not in srv.allowed_origins
    finally:
        srv.server_close()


# --- (3) the reverse-proxy domain path --------------------------------------------------------------

def test_configured_domain_host_and_origin_are_accepted():
    srv, port = _serve(_spine(), allowed_hosts=[DOMAIN], allowed_origins=[DOMAIN_ORIGIN])
    try:
        # the domain forms are in the allowlist AND the loopback default still is (proxy is co-located)
        assert DOMAIN in srv.allowed_hosts and DOMAIN_ORIGIN in srv.allowed_origins
        assert f"127.0.0.1:{port}" in srv.allowed_hosts
        # a request forwarded by the proxy (Host+Origin = the domain) passes the action gate
        assert _post_action(port, host=DOMAIN, origin=DOMAIN_ORIGIN) == 200
        # the co-located loopback path still works too
        assert _post_action(port, host=f"127.0.0.1:{port}",
                            origin=f"http://127.0.0.1:{port}", action="enable_gesture") == 200
    finally:
        srv.shutdown()


def test_foreign_host_or_origin_still_refused_even_with_a_domain_configured():
    srv, port = _serve(_spine(), allowed_hosts=[DOMAIN], allowed_origins=[DOMAIN_ORIGIN])
    try:
        # a DIFFERENT domain (not the configured one) → 403 on both Host and Origin
        assert _post_action(port, host="evil.example", origin="https://evil.example") == 403
        # right Host, wrong Origin → 403 (exact-match Origin, no rebinding)
        assert _post_action(port, host=DOMAIN, origin="https://evil.example") == 403
        # a prefix attack on the configured origin → 403 (exact match)
        assert _post_action(port, host=DOMAIN, origin=DOMAIN_ORIGIN + ".evil.com") == 403
    finally:
        srv.shutdown()


def test_trailing_slash_on_a_configured_origin_is_normalised():
    # operators paste origins with/without a trailing slash; both must land as the exact header form
    srv, port = _serve(_spine(), allowed_hosts=[DOMAIN], allowed_origins=[DOMAIN_ORIGIN + "/"])
    try:
        assert DOMAIN_ORIGIN in srv.allowed_origins           # stored without the trailing slash
        assert _post_action(port, host=DOMAIN, origin=DOMAIN_ORIGIN) == 200
    finally:
        srv.shutdown()
