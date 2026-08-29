"""Wave 10 (parity) — read-only sovereign KEY-MATERIAL CEREMONY status (`sigil vault|kernel|key status`,
`owner-pubkey`). Fixed argv (no request input), shell=False; viewer+ reads (public keys + at-rest sealing
metadata only — no private key, and none of these reads unseal one). The owner-key MUTATIONS
(provision/pin/rotate/authorize/reset) stay owner-only, deferred to a later slice."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.ui import ceremonies
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-ceremonies"


class _P:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def test_reads_shell_fixed_argv(monkeypatch):
    # Every read is a LITERAL argv (verb never request-controlled), action always the fixed status form.
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda a, **k: (seen.append(a) or _P(0, "owner pubkey: AAAA…")))
    assert ceremonies.owner_pubkey_show()["ok"] is True
    assert seen[-1] == [sys.executable, "-m", "sigil", "owner-pubkey"]
    ceremonies.vault_status()
    assert seen[-1] == [sys.executable, "-m", "sigil", "vault", "status"]
    ceremonies.kernel_status()
    assert seen[-1] == [sys.executable, "-m", "sigil", "kernel", "status"]
    ceremonies.key_status()
    assert seen[-1] == [sys.executable, "-m", "sigil", "key", "status"]


def test_bad_exit_is_not_a_false_green(monkeypatch):
    # a forked / tampered succession chain exits non-zero — `ok` is derived from the EXIT CODE, never from
    # the presence of text, so a bad state can never surface as a false green.
    monkeypatch.setattr(subprocess, "run", lambda a, **k: _P(2, "owner-key succession: FORKED / AMBIGUOUS"))
    r = ceremonies.key_status()
    assert r["ok"] is False and r["exit_code"] == 2 and "FORKED" in r["text"]


def test_failcloses_on_spawn_error(monkeypatch):
    def _boom(*a, **k):
        raise OSError("no exec")
    monkeypatch.setattr(subprocess, "run", _boom)
    assert ceremonies.vault_status()["ok"] is False


def _serve():
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=None)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _get(port, path, token=TOKEN):
    h = {}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


def _make_account(port, username, role):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}",
         "X-SIGIL-Token": TOKEN}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/action",
                                 data=json.dumps({"action": "create_account", "username": username, "role": role}).encode(),
                                 headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())["bearer_token"]


def _post(port, path, token=TOKEN, body=None):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=json.dumps(body or {}).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


def test_routes_are_operator_plus(monkeypatch):
    # OPERATOR+ (config_nonsecret) — the same tier as /api/doctor, because `key status` surfaces absolute
    # sealed-key file PATHS + the SEALED/PLAINTEXT posture + TOTP labels (an operational/FS-layout class a
    # viewer, who cannot read config, must not see). stub the real spawns so the route test never shells.
    for fn in ("vault_status", "kernel_status", "key_status", "owner_pubkey_show"):
        monkeypatch.setattr(ceremonies, fn, lambda: {"ok": True, "verb": "x", "text": "ok"})
    _s, port = _serve()
    viewer = _make_account(port, "cera", "viewer")
    operator = _make_account(port, "cero", "operator")
    for leaf in ("vault", "kernel", "key", "owner-pubkey"):
        assert _get(port, f"/api/ceremonies/{leaf}")[0] == 200                      # owner
        assert _get(port, f"/api/ceremonies/{leaf}", token=operator)[0] == 200      # operator+
        assert _get(port, f"/api/ceremonies/{leaf}", token=viewer)[0] == 403        # viewer REFUSED
    assert _get(port, "/api/ceremonies/vault", token=None)[0] == 401                # unauth


# --- Wave 10b: OWNER-ONLY mutations (vault provision / kernel pin) ------------------------------------

def test_mutations_shell_fixed_argv(monkeypatch):
    # zero-arg owner ceremonies — the argv is a LITERAL (never request-controlled), reusing the audited verb.
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda a, **k: (seen.append(a) or _P(0, "vault provisioned")))
    assert ceremonies.vault_provision()["ok"] is True
    assert seen[-1] == [sys.executable, "-m", "sigil", "vault", "provision"]
    ceremonies.kernel_pin()
    assert seen[-1] == [sys.executable, "-m", "sigil", "kernel", "pin"]


def test_mutations_failclose(monkeypatch):
    # a non-zero exit (e.g. no TPM, locked vault, unresolved kernel binary) → ok:false, never a false green.
    monkeypatch.setattr(subprocess, "run", lambda a, **k: _P(1, "", "!! could not provision"))
    r = ceremonies.vault_provision()
    assert r["ok"] is False and r["exit_code"] == 1

    def _boom(*a, **k):
        raise OSError("no exec")
    monkeypatch.setattr(subprocess, "run", _boom)
    assert ceremonies.kernel_pin()["ok"] is False


def test_mutation_routes_are_owner_only(monkeypatch):
    # OWNER-only (`secrets`): both ceremonies act on/with the owner trust root. operator+ and viewer are
    # REFUSED; a POST with no credential is 403 (the action plane refuses with 403, not 401). Stub the spawns.
    for fn in ("vault_provision", "kernel_pin"):
        monkeypatch.setattr(ceremonies, fn, lambda: {"ok": True, "verb": "x", "text": "done"})
    _s, port = _serve()
    viewer = _make_account(port, "cmv", "viewer")
    operator = _make_account(port, "cmo", "operator")
    for leaf in ("vault-provision", "kernel-pin"):
        assert _post(port, f"/api/ceremonies/{leaf}")[0] == 200                      # owner
        assert _post(port, f"/api/ceremonies/{leaf}", token=operator)[0] == 403      # operator REFUSED
        assert _post(port, f"/api/ceremonies/{leaf}", token=viewer)[0] == 403        # viewer REFUSED
        assert _post(port, f"/api/ceremonies/{leaf}", token=None)[0] == 403          # unauth


def test_mutation_routes_reject_cross_origin(monkeypatch):
    # CSRF/rebind NEGATIVE CONTROL: a POST with a MISMATCHED Origin is refused BEFORE the action even with a
    # valid OWNER token — `_origin_host_ok` fires first in _ceremonies_post. (Neutering that gate must flip
    # this red; the owner-only tests above can't catch it because they always send a same-origin header.)
    for fn in ("vault_provision", "kernel_pin"):
        monkeypatch.setattr(ceremonies, fn, lambda: {"ok": True, "verb": "x", "text": "done"})
    _s, port = _serve()
    h = {"Content-Type": "application/json", "Origin": "http://evil.example", "Host": f"127.0.0.1:{port}",
         "X-SIGIL-Token": TOKEN}   # valid owner token, but a cross-origin Origin
    for leaf in ("vault-provision", "kernel-pin"):
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/ceremonies/{leaf}",
                                     data=b"{}", headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 403, f"{leaf} accepted a cross-origin POST (CSRF gate not firing first)"
