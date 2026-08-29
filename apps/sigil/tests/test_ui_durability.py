"""Wave 3 (durability) — owner-only trust-root backup/restore orchestrated from the browser.

Backup (`secrets`) + restore (`offense_authority`) are OWNER-ONLY; the operator's passphrase is transient and
never stored/logged/audited/echoed; download is path-traversal-safe; restore always stages into a FRESH home
(never the live one). Run under `SIGIL_HOME=$(mktemp -d)` so the owner key/vault/spine resolve to one home.
"""
from __future__ import annotations

import json
import shutil
import threading
import time
import urllib.error
import urllib.request

import pytest

from sigil import config
from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.checkpoint import checkpoint
from sigil.spine.store import SpineStore
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-durability"
PASSPHRASE = "correcthorsebatterystaple"


@pytest.fixture(autouse=True)
def _isolate_shared_home():
    """These tests exercise the HTTP route, which uses the module-level `config.SIGIL_HOME`; so they SIGN a
    head + write backups/restored under the shared home. Remove that state before AND after each test so a
    later test that assumes NO signed head (e.g. test_ui_verify) is never polluted (the full-dir CI run
    collects test_ui_durability BEFORE test_ui_verify alphabetically)."""
    def _clean():
        for pth in (config.HEAD_PATH, config.SPINE_PATH):
            try:
                pth.unlink()
            except OSError:
                pass
        for sub in ("backups", "restored"):
            shutil.rmtree(config.SIGIL_HOME / sub, ignore_errors=True)
    _clean()
    yield
    _clean()


def _serve():
    ensure_owner_keypair()
    s = SpineStore()                                  # default spine under config.SIGIL_HOME
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    checkpoint(s)                                     # sign the head — create_backup requires it
    srv = build_server(token=TOKEN, port=0, spine_path=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _req(port, path, *, method="GET", token=TOKEN, body=None, raw=False):
    h = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            payload = r.read()
            return r.status, (payload if raw else json.loads(payload or b"{}"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, (e.read() if raw else json.loads(e.read() or b"{}"))
        except Exception:  # noqa: BLE001
            return e.code, {}


def _make_account(port, username, role):
    code, d = _req(port, "/api/action", method="POST",
                   body={"action": "create_account", "username": username, "role": role})
    assert code == 200, d
    return d["bearer_token"]


def test_backup_then_list_then_download_roundtrip():
    _s, port = _serve()
    code, d = _req(port, "/api/backup", method="POST", body={"passphrase": PASSPHRASE})
    assert code == 200, d
    bid = d["id"]
    assert bid.startswith("backup-") and bid.endswith(".enc")
    assert d.get("size", 0) > 0 and d.get("files")
    # the passphrase is NEVER echoed back
    assert "passphrase" not in json.dumps(d).lower()
    # it appears in the list
    code, lst = _req(port, "/api/backup/list")
    assert code == 200 and any(b["id"] == bid for b in lst["backups"])
    # download returns the ciphertext bytes
    code, raw = _req(port, f"/api/backup/download/{bid}", raw=True)
    assert code == 200 and isinstance(raw, (bytes, bytearray)) and len(raw) == d["size"]


def test_download_is_path_traversal_safe():
    _s, port = _serve()
    for bad in ("../../../etc/passwd", "..%2f..%2fetc%2fpasswd", "foo.enc", "backup-x.enc"):
        code, _ = _req(port, f"/api/backup/download/{bad}", raw=True)
        assert code == 404, f"{bad!r} should 404, got {code}"


def test_restore_stages_into_a_fresh_home_and_verifies():
    _s, port = _serve()
    code, d = _req(port, "/api/backup", method="POST", body={"passphrase": PASSPHRASE})
    assert code == 200
    code, r = _req(port, "/api/restore", method="POST",
                   body={"passphrase": PASSPHRASE, "backup_id": d["id"]})
    assert code == 200, r
    assert r.get("verified") is True
    # restore NEVER targets the live home in-place — it stages under <home>/restored/
    assert "/restored/restore-" in r.get("home", "")
    assert str(config.SIGIL_HOME) != r.get("home", "")


def test_wrong_passphrase_and_short_passphrase_fail_closed():
    _s, port = _serve()
    code, d = _req(port, "/api/backup", method="POST", body={"passphrase": PASSPHRASE})
    # a wrong restore passphrase → 400 (nothing trusted), not a 200
    code, r = _req(port, "/api/restore", method="POST",
                   body={"passphrase": "WRONGWRONGWRONG", "backup_id": d["id"]})
    assert code == 400
    # a too-short backup passphrase → 400
    code, _ = _req(port, "/api/backup", method="POST", body={"passphrase": "short"})
    assert code == 400


def test_backup_and_restore_are_owner_only():
    _s, port = _serve()
    viewer = _make_account(port, "vera", "viewer")
    operator = _make_account(port, "otto", "operator")
    for tok in (viewer, operator):
        assert _req(port, "/api/backup", method="POST", body={"passphrase": PASSPHRASE}, token=tok)[0] == 403
        assert _req(port, "/api/restore", method="POST",
                    body={"passphrase": PASSPHRASE, "backup_id": "x"}, token=tok)[0] == 403
        assert _req(port, "/api/backup/list", token=tok)[0] == 403
    # unauthenticated → 401 (read) / 403 (action-plane)
    assert _req(port, "/api/backup/list", token=None)[0] == 401
    assert _req(port, "/api/backup", method="POST", body={"passphrase": PASSPHRASE}, token=None)[0] == 403


def test_passphrase_never_reaches_the_audit_spine():
    import dataclasses
    _s, port = _serve()
    code, d = _req(port, "/api/backup", method="POST", body={"passphrase": PASSPHRASE})
    assert code == 200
    recs = list(SpineStore().iter_records())          # read the REAL spine the HTTP route wrote to
    # the audit path actually RAN (a secret-free durability event was appended) — not a vacuous check
    dur = [r for r in recs if getattr(r, "kind", "") == "event" and getattr(r, "source", "") == "durability"]
    assert dur, "no durability audit event was written"
    assert any(r.payload.get("action") == "backup" and r.payload.get("id") == d["id"] for r in dur)
    # and the passphrase is nowhere in ANY record (mutation-sensitive: it would appear if the audit leaked it)
    blob = "\n".join(json.dumps(dataclasses.asdict(r), default=str) for r in recs)
    assert PASSPHRASE not in blob
