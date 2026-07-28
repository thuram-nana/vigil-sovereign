"""SIGIL Phase 7 WS-C — the loopback glass-cockpit server: token-gated read plane, CSRF/Host/Origin-
gated owner-signed action plane, provenance re-verify, SSE auth. Run: ~/.sigil/venv/bin/python tests/test_ui.py"""
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from sigil.agents.base import Agent, Proposal, Tier
from sigil.governor import Governor
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.server import build_server

OWNER = generate_keypair()
OP = OWNER.public_key_b64
TOKEN = "test-secret-token-xyz"


class _Emitter(Agent):
    name = "TESTER"
    ceiling = Tier.A2

    def __init__(self, store):
        super().__init__(store, governor=Governor(store, owner_key=OWNER, trusted_pubkey=OP))

    def run(self, tier, kind="draft"):
        return self._dispatch([Proposal(kind, {"subject": "please approve me"}, tier)])


def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hello world"})
    return p


def _serve(spine_path):
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path)   # port 0 = ephemeral
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _get(port, path, *, token=TOKEN, headers=None):
    h = dict(headers or {})
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _post(port, path, body, *, token=TOKEN, headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_binds_loopback_only():
    srv, _ = _serve(_spine())
    assert srv.server_address[0] == "127.0.0.1", "the cockpit binds 127.0.0.1 only, never 0.0.0.0"
    srv.shutdown()


def test_read_plane_requires_the_token():
    srv, port = _serve(_spine())
    try:
        code, _ = _get(port, "/api/snapshot", token=None)
        assert code == 401, "no token → 401"
        code, body = _get(port, "/api/snapshot")
        assert code == 200 and "head_seq" in body, "with the token → the snapshot"
        code, _ = _get(port, "/api/snapshot", token="WRONG")
        assert code == 401, "a wrong token → 401"
    finally:
        srv.shutdown()


def test_record_endpoint_reverifies_provenance():
    p = _spine()
    srv, port = _serve(p)
    try:
        code, body = _get(port, "/api/record/0")
        d = json.loads(body)
        assert code == 200 and d["integrity_ok"] is True and d["entry_hash"], "an atom re-verifies live"
        # tamper the record on disk → the endpoint reports integrity broken, not truth
        lines = Path(p).read_text().splitlines()
        rec = json.loads(lines[0]); rec["payload"] = {"text": "TAMPERED"}; lines[0] = json.dumps(rec)
        Path(p).write_text("\n".join(lines) + "\n")
        code, body = _get(port, "/api/record/0")
        assert json.loads(body)["integrity_ok"] is False, "a tampered atom is flagged, never served as verified"
        code, body = _get(port, "/api/record/999")
        assert code == 404 and "not fabricated" in body, "an absent record is honest, not fabricated"
    finally:
        srv.shutdown()


def test_action_plane_is_csrf_host_origin_gated():
    p = _spine()
    _Emitter(SpineStore(p)).run(Tier.A2)                 # queue an A2 for approval (seq 1)
    srv, port = _serve(p)
    try:
        good_origin = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
        # (a) no token → 403
        assert _post(port, "/api/action", {"action": "approve", "seq": 1}, token=None,
                     headers=good_origin)[0] == 403
        # (b) cross-origin (even WITH the token) → 403
        assert _post(port, "/api/action", {"action": "approve", "seq": 1},
                     headers={"Origin": "http://evil.example", "Host": f"127.0.0.1:{port}"})[0] == 403
        # (c) DNS-rebinding Host → 403
        assert _post(port, "/api/action", {"action": "approve", "seq": 1},
                     headers={"Origin": f"http://127.0.0.1:{port}", "Host": "evil.example"})[0] == 403
        # (d) token + loopback origin + allowed host → the owner-signed approval is recorded
        code, body = _post(port, "/api/action", {"action": "approve", "seq": 1}, headers=good_origin)
        assert code == 200 and json.loads(body)["ok"] is True, "a legitimate in-browser approve succeeds"
    finally:
        srv.shutdown()


def test_in_browser_approval_produces_a_verifying_record_and_clears_the_queue():
    p = _spine()
    _Emitter(SpineStore(p)).run(Tier.A2)                 # queued at seq 1
    srv, port = _serve(p)
    try:
        good = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
        _post(port, "/api/action", {"action": "approve", "seq": 1}, headers=good)
        # the queue is now empty and the approval verifies against the owner pubkey
        from sigil.agents.approvals import pending, verify_approval
        from sigil.governor.identity import owner_pubkey
        s = SpineStore(p)
        assert not pending(s, owner_pubkey()), "the approved item left the queue"
        appr = [r for r in s.iter_records() if r.payload.get("signal") == "governor.approval"]
        assert appr and verify_approval(appr[-1], owner_pubkey()), "the browser-triggered approval is owner-signed + verifies"
    finally:
        srv.shutdown()


def test_action_plane_refuses_unknown_action():
    srv, port = _serve(_spine())
    try:
        good = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
        code, _ = _post(port, "/api/action", {"action": "rm -rf", "seq": 1}, headers=good)
        assert code == 400, "an unknown action is refused (closed action set)"
    finally:
        srv.shutdown()


def test_sse_requires_token_and_streams():
    srv, port = _serve(_spine())
    try:
        assert _get_stream_status(port, token=None) == 401, "SSE without a token → 401"
        # with the token via query param, the stream opens as text/event-stream
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/stream?token={TOKEN}&since=-1")
        with urllib.request.urlopen(req, timeout=5) as r:
            assert r.status == 200 and "event-stream" in r.headers.get("Content-Type", "")
            r.read(64)                                    # read a little, then close
    finally:
        srv.shutdown()


def _get_stream_status(port, token):
    url = f"http://127.0.0.1:{port}/api/stream" + (f"?token={token}" if token else "")
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_sigil_hud_requires_the_token_and_streams():
    # S2: the SIGIL HUD nav channel is a READ-ONLY SSE behind the SAME token gate as /api/stream.
    srv, port = _serve(_spine())
    try:
        url_no = f"http://127.0.0.1:{port}/api/sigil/hud"
        try:
            with urllib.request.urlopen(url_no, timeout=3) as r:
                assert False, f"HUD without a token should 401, got {r.status}"
        except urllib.error.HTTPError as e:
            assert e.code == 401                              # no token → 401
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/sigil/hud?token={TOKEN}&since=-1")
        with urllib.request.urlopen(req, timeout=5) as r:
            assert r.status == 200 and "event-stream" in r.headers.get("Content-Type", "")
            r.read(16)                                        # heartbeat, then close (no history replayed)
    finally:
        srv.shutdown()


def test_sigil_hud_emits_direction_and_screen_id_and_drops_garbled():
    # S3: the HUD fans out a gesture-swipe as {"t":"nav","direction":"next"} and a voice/pinch as
    # {"t":"nav","screen_id":"settings"}, and DROPS a garbled nav value. Use since=<seq> (not -1) to
    # stream the pre-appended nav records (since>=0 bypasses the tip-default).
    p = _spine()                                              # seq 0 = the hello message
    s = SpineStore(p)
    s.append(kind="event", source="gesture", actor="OWNER",
             payload={"signal": "sigil.nav", "nav": "next", "tier": "A1"})            # seq 1
    s.append(kind="event", source="gesture", actor="OWNER",
             payload={"signal": "sigil.nav", "nav": "../evil", "tier": "A1"})          # seq 2 → dropped
    s.append(kind="event", source="voice", actor="OWNER",
             payload={"signal": "sigil.nav", "screen_id": "settings", "tier": "A1"})   # seq 3
    srv, port = _serve(p)
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/sigil/hud?token={TOKEN}&since=0")
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(400).decode("utf-8")                # the first poll emits all matching events
        events = [json.loads(ln[len("data: "):]) for ln in body.splitlines() if ln.startswith("data: ")]
        assert {"t": "nav", "direction": "next", "seq": 1} in events                   # the swipe
        assert any(e.get("screen_id") == "settings" for e in events)                   # the voice nav
        assert all(e.get("direction") != "../evil" for e in events)                    # garbled → dropped
        assert not any("evil" in json.dumps(e) for e in events)
    finally:
        srv.shutdown()


def test_sigil_hud_emits_voice_fsm_state():
    # S4: the HUD fans out the voice FSM state from the EPHEMERAL 0600 status file (never the spine).
    import os

    from sigil.voice.hud_status import StatusSink, status_path
    StatusSink()({"state": "listening", "transcript": "open settings", "feedback": ""})
    srv, port = _serve(_spine())
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/sigil/hud?token={TOKEN}&since=-1")
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(400).decode("utf-8")
        events = [json.loads(ln[len("data: "):]) for ln in body.splitlines() if ln.startswith("data: ")]
        st = next(e for e in events if e.get("t") == "state")
        assert st["state"] == "listening" and st["transcript"] == "open settings"
    finally:
        srv.shutdown()
        try:
            os.unlink(status_path())                              # don't leak the HUD state to sibling tests
        except OSError:
            pass


def test_index_embeds_token_and_needs_no_token_itself():
    srv, port = _serve(_spine())
    try:
        code, body = _get(port, "/", token=None)          # the page itself is served (token embedded)
        assert code == 200 and "__SIGIL_TOKEN__" not in body and TOKEN in body, "the page embeds the real token"
    finally:
        srv.shutdown()


# ---- red-pen negative controls (BLOCK-1..4) ------------------------------------------------------
def test_origin_prefix_is_not_accepted():                         # BLOCK-2
    p = _spine(); _Emitter(SpineStore(p)).run(Tier.A2)
    srv, port = _serve(p)
    try:
        # a prefix-Origin (`http://127.0.0.1:PORT.evil.com`) must NOT pass exact-match
        code, _ = _post(port, "/api/action", {"action": "approve", "seq": 1},
                        headers={"Origin": f"http://127.0.0.1:{port}.evil.com", "Host": f"127.0.0.1:{port}"})
        assert code == 403, "an Origin that merely shares the prefix is refused (exact match)"
    finally:
        srv.shutdown()


def test_static_assets_served_and_page_has_no_inline_script():     # BLOCK-3
    srv, port = _serve(_spine())
    try:
        for asset, ctype in (("app.js", "javascript"), ("style.css", "css")):
            code, _ = _get(port, f"/static/{asset}", token=None)
            assert code == 200, f"/static/{asset} is served token-free (bootstrap)"
        _, html = _get(port, "/", token=None)
        assert "<script src=" in html and "onclick=" not in html and "<script>" not in html.replace("<script src=", ""), \
            "the page uses only external CSP-safe scripts — no inline script/handlers"
        assert "/static/app.js" in html and "/static/style.css" in html
        code, _ = _get(port, "/static/../server.py", token=None)   # traversal on the static allowlist
        assert code == 404, "static serving is allowlisted (no traversal)"
    finally:
        srv.shutdown()


def test_ask_carries_the_full_action_gate():                      # BLOCK-1
    srv, port = _serve(_spine())
    try:
        assert _get(port, "/api/ask?q=hi", token=None)[0] == 401, "ask without a token → 401"
        # cross-origin ask (with token) → 403: /api/ask dispatches the KERNEL, so it gets the action gate
        code, _ = _get(port, "/api/ask?q=hi", headers={"Origin": "http://evil.example", "Host": f"127.0.0.1:{port}"})
        assert code == 403, "a cross-origin ask is refused (full gate, not just token)"
    finally:
        srv.shutdown()


def test_oversized_action_body_rejected():                        # BLOCK-4
    srv, port = _serve(_spine())
    try:
        good = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
        big = {"action": "approve", "seq": 1, "pad": "x" * 70000}
        code, _ = _post(port, "/api/action", big, headers=good)
        assert code == 413, "an oversized body is rejected (no Content-Length hang / alloc)"
    finally:
        srv.shutdown()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-7 WS-C (glass cockpit) guarantees hold")
