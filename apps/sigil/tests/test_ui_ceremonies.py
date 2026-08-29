"""Wave 10 (parity) — read-only sovereign KEY-MATERIAL CEREMONY status (`sigil vault|kernel|key status`,
`owner-pubkey`). Fixed argv (no request input), shell=False; viewer+ reads (public keys + at-rest sealing
metadata only — no private key, and none of these reads unseal one). The owner-key MUTATIONS
(provision/pin/rotate/authorize/reset) stay owner-only, deferred to a later slice."""
from __future__ import annotations

import base64
import json
import os
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


# --- Wave 10c: OWNER-ONLY mesh device enrollment (authorize / revoke / fingerprint preview) ------------

GOOD_PUB = base64.b64encode(bytes(range(32))).decode()   # valid base64 of EXACTLY 32 bytes (Ed25519-shaped)


def test_mesh_fingerprint_is_pure_and_matches_cli(monkeypatch):
    # the preview is PURE (no subprocess), deterministic, and byte-identical to the CLI's _device_fingerprint
    # (so the operator eyeball-matches the SAME code the phone/CLI show — the anti-key-swap guard).
    called = []
    monkeypatch.setattr(subprocess, "run", lambda a, **k: called.append(a))
    r = ceremonies.mesh_fingerprint(GOOD_PUB)
    assert r["ok"] is True and r["fingerprint"] and called == []       # computed in-process, no spawn
    from sigil.cli import _device_fingerprint
    assert r["fingerprint"] == _device_fingerprint(GOOD_PUB)
    assert ceremonies.mesh_fingerprint("not base64!!")["ok"] is False
    assert ceremonies.mesh_fingerprint(base64.b64encode(b"short").decode())["ok"] is False   # not 32 bytes


def test_mesh_argv_shape_and_injection_rejected(monkeypatch):
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda a, **k: (seen.append(a) or _P(0, "ok")))
    ceremonies.mesh_authorize("junior-pixel", GOOD_PUB)
    assert seen[-1] == [sys.executable, "-m", "sigil", "mesh", "authorize", "junior-pixel", GOOD_PUB, "--yes"]
    ceremonies.mesh_revoke("junior-pixel", GOOD_PUB)
    assert seen[-1] == [sys.executable, "-m", "sigil", "mesh", "revoke", "junior-pixel", GOOD_PUB]
    # ARGV-INJECTION negative controls: a flag-ish/spaced/newline device_id or a non-base64/wrong-length
    # pubkey is REJECTED before any spawn, so a hostile value can never become an argv flag.
    n = len(seen)
    for bad_dev in ("-rf", "a b", "ok\ninject", "--yes"):
        assert ceremonies.mesh_authorize(bad_dev, GOOD_PUB)["ok"] is False
    for bad_pub in ("--evil", GOOD_PUB + " --x", "not-base64", base64.b64encode(b"x" * 31).decode()):
        assert ceremonies.mesh_authorize("dev", bad_pub)["ok"] is False
    assert len(seen) == n            # NONE of the rejected inputs reached a spawn


def test_mesh_routes_are_owner_only(monkeypatch):
    monkeypatch.setattr(ceremonies, "mesh_list", lambda: {"ok": True, "text": "no authorized devices"})
    monkeypatch.setattr(ceremonies, "mesh_authorize", lambda d, p: {"ok": True, "text": "authorized"})
    monkeypatch.setattr(ceremonies, "mesh_revoke", lambda d, p: {"ok": True, "text": "revoked"})
    monkeypatch.setattr(ceremonies, "mesh_fingerprint", lambda p: {"ok": True, "fingerprint": "aaaa-bbbb-cccc-dddd"})
    _s, port = _serve()
    viewer = _make_account(port, "mmv", "viewer")
    operator = _make_account(port, "mmo", "operator")
    assert _get(port, "/api/ceremonies/mesh/devices")[0] == 200                        # owner roster read
    assert _get(port, "/api/ceremonies/mesh/devices", token=operator)[0] == 403        # operator refused
    assert _get(port, "/api/ceremonies/mesh/devices", token=viewer)[0] == 403
    for leaf in ("mesh/fingerprint", "mesh/authorize", "mesh/revoke"):
        assert _post(port, f"/api/ceremonies/{leaf}")[0] == 200                         # owner
        assert _post(port, f"/api/ceremonies/{leaf}", token=operator)[0] == 403         # operator refused
        assert _post(port, f"/api/ceremonies/{leaf}", token=viewer)[0] == 403           # viewer refused
        assert _post(port, f"/api/ceremonies/{leaf}", token=None)[0] == 403             # unauth


# --- Wave 10d: OWNER-ONLY offense delegation (preview + sign) -----------------------------------------

GOOD_ID = {"schema": 1, "spine": {"key_id": "off-spine", "public_key_b64": GOOD_PUB},
           "governance": {"key_id": "off-gov", "public_key_b64": GOOD_PUB}}


def test_delegate_preview_is_pure_and_validates(monkeypatch):
    called = []
    monkeypatch.setattr(subprocess, "run", lambda a, **k: called.append(a))
    r = ceremonies.delegate_offense_preview(GOOD_ID)
    assert r["ok"] is True and r["spine"]["pubkey"] == GOOD_PUB and called == []       # pure, no spawn
    assert ceremonies.delegate_offense_preview({"schema": 2})["ok"] is False           # wrong schema
    assert ceremonies.delegate_offense_preview({"schema": 1, "spine": GOOD_ID["spine"]})["ok"] is False  # no gov
    bad = {"schema": 1, "spine": {"key_id": "s", "public_key_b64": "nope"}, "governance": GOOD_ID["governance"]}
    assert ceremonies.delegate_offense_preview(bad)["ok"] is False                     # bad base64 pubkey


def test_delegate_uses_server_paths_and_validates(monkeypatch, tmp_path):
    seen = {}

    def _rec(a, **k):
        seen["argv"] = a
        idx = a.index("--offense-identity") + 1
        seen["id_path"] = a[idx]
        with open(a[idx], encoding="utf-8") as fh:               # temp file EXISTS during the run
            seen["id_content"] = json.load(fh)
        return _P(0, "owner-signed offense delegations written")
    monkeypatch.setattr(subprocess, "run", _rec)
    ceremonies.delegate_offense(GOOD_ID, "engagement-x", "24", str(tmp_path))
    argv = seen["argv"]
    assert argv[3] == "delegate-offense"
    # the identity reaches argv ONLY via a server-controlled temp file (never a user path), holding the
    # identity JSON, and it is cleaned up after the run
    assert seen["id_content"] == GOOD_ID and not os.path.exists(seen["id_path"])
    assert argv[argv.index("--scope") + 1] == "engagement-x"
    assert argv[argv.index("--out-dir") + 1].startswith(str(tmp_path))                 # server out-dir
    # validation negative controls — a flag-ish scope, out-of-range hours, or a bad identity NEVER spawn
    seen.clear()
    assert ceremonies.delegate_offense(GOOD_ID, "-flag", "24", str(tmp_path))["ok"] is False
    assert ceremonies.delegate_offense(GOOD_ID, "ok", "0", str(tmp_path))["ok"] is False        # hours <= 0
    assert ceremonies.delegate_offense(GOOD_ID, "ok", "999999", str(tmp_path))["ok"] is False   # hours too big
    assert ceremonies.delegate_offense(GOOD_ID, "ok", "notnum", str(tmp_path))["ok"] is False
    assert ceremonies.delegate_offense({"schema": 9}, "ok", "24", str(tmp_path))["ok"] is False
    assert "argv" not in seen        # none of the rejected inputs reached a spawn


def test_delegate_routes_are_owner_only(monkeypatch):
    monkeypatch.setattr(ceremonies, "delegate_offense_preview", lambda i: {"ok": True, "spine": {}, "governance": {}})
    monkeypatch.setattr(ceremonies, "delegate_offense", lambda i, s, h, home: {"ok": True, "text": "signed"})
    _s, port = _serve()
    viewer = _make_account(port, "dgv", "viewer")
    operator = _make_account(port, "dgo", "operator")
    for leaf in ("delegate/preview", "delegate"):
        assert _post(port, f"/api/ceremonies/{leaf}")[0] == 200                         # owner
        assert _post(port, f"/api/ceremonies/{leaf}", token=operator)[0] == 403         # operator refused
        assert _post(port, f"/api/ceremonies/{leaf}", token=viewer)[0] == 403           # viewer refused
        assert _post(port, f"/api/ceremonies/{leaf}", token=None)[0] == 403             # unauth


def test_delegate_route_rejects_cross_origin(monkeypatch):
    # the shared _ceremonies_post CSRF gate also protects the delegate routes (pinned here, not only on the
    # vault/kernel routes): a cross-origin POST with a valid OWNER token is refused before the action.
    monkeypatch.setattr(ceremonies, "delegate_offense", lambda i, s, h, home: {"ok": True, "text": "signed"})
    _s, port = _serve()
    h = {"Content-Type": "application/json", "Origin": "http://evil.example", "Host": f"127.0.0.1:{port}",
         "X-SIGIL-Token": TOKEN}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/ceremonies/delegate",
                                 data=b"{}", headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    assert code == 403


def test_ceremony_body_route_400s_on_malformed_json(monkeypatch):
    # a malformed JSON body on a body-taking ceremony route returns a clean 400 (the shared parse is wrapped),
    # never a connection drop / 500. Owner-authenticated so the failure is the PARSE, not the gate.
    monkeypatch.setattr(ceremonies, "mesh_fingerprint", lambda p: {"ok": True, "fingerprint": "x"})
    _s, port = _serve()
    hh = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}",
          "X-SIGIL-Token": TOKEN}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/ceremonies/mesh/fingerprint",
                                 data=b"{ this is not json", headers=hh, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    assert code == 400
