"""SIGIL Phase 9 W1-C — the installable, self-contained Companion PWA the owner's phone loads over
WireGuard to approve actions, panic-halt, relay commands, and view state. It holds the phone's OWN
Ed25519 device key and signs LOCALLY; the desktop bridge only verifies.

These tests assert three things the slice must hold:
  1. all webapp files exist and are non-empty;
  2. CSP-safety — no external origins, no inline event handlers, no inline <script> bodies (the app
     is served under a strict `default-src 'self'` CSP that would break any of those);
  3. the #1 correctness item — CANONICALIZATION PARITY: the JS `canonicalJson` (canonical.js) must
     reproduce, BYTE-FOR-BYTE, the exact signed bytes the Python bridge verifies
     (sigil.bridge.envelope.envelope_message / sigil.reuse.canonical_json). This is run under Node so
     it is falsifiable, not asserted by inspection.

Run: ~/.sigil/venv/bin/python tests/test_bridge_webapp.py
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from sigil.bridge import build_core, envelope_message
from sigil.gesture.session import arm_request_message
from sigil.reuse import canonical_json

from sigil.bridge import envelope as _E
WEBAPP = Path(_E.__file__).parent / "webapp"

FILES = ["index.html", "app.js", "style.css", "manifest.webmanifest", "service-worker.js", "canonical.js"]


def _read(name):
    return (WEBAPP / name).read_text(encoding="utf-8")


# ---- 1. every webapp file exists and is non-empty -------------------------------------------------
def test_all_webapp_files_exist_and_nonempty():
    for name in FILES:
        p = WEBAPP / name
        assert p.is_file(), f"missing webapp file: {name}"
        assert p.stat().st_size > 0, f"empty webapp file: {name}"


# ---- 2a. no external origins in the JS/HTML (CSP default-src 'self') ------------------------------
def test_no_external_origins():
    for name in ("app.js", "index.html"):
        text = _read(name)
        assert "http://" not in text, f"{name} must not reference an http:// external origin"
        assert "https://" not in text, f"{name} must not reference an https:// external origin"


# ---- 2b. no inline event handlers (event-delegation discipline only) -----------------------------
def test_no_inline_event_handlers():
    for name in ("app.js", "index.html"):
        text = _read(name)
        assert "onclick=" not in text, f"{name} must not use an inline onclick= handler"
        assert "onload=" not in text, f"{name} must not use an inline onload= handler"
    # index.html: no HTML tag may carry ANY inline on*= handler attribute
    html = _read("index.html")
    inline_attr = re.compile(r"<[a-zA-Z][^>]*\son[a-z]+\s*=", re.DOTALL)
    assert not inline_attr.search(html), "index.html has an inline on*= handler attribute (CSP-unsafe)"


# ---- 2c. index.html has only <script src=...> — no inline script body -----------------------------
def test_index_scripts_are_external_only():
    html = _read("index.html")
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
    assert scripts, "index.html should load the app via <script src=...>"
    for attrs, body in scripts:
        assert "src=" in attrs, f"<script{attrs}> has no src= (inline script is CSP-unsafe)"
        assert body.strip() == "", f"<script{attrs}> has an inline body (CSP-unsafe): {body!r}"


# ---- 2d. the JS wires behaviour via a delegated listener + holds no vendored crypto ---------------
def test_app_uses_event_delegation_and_webcrypto_only():
    app = _read("app.js")
    assert 'addEventListener("click"' in app, "app.js must wire clicks via event delegation"
    assert "crypto.subtle" in app and "Ed25519" in app, "app.js must use WebCrypto Ed25519"
    # honest failure path if the browser cannot hold a device key (no silent weak-crypto fallback)
    assert "can't hold a device key" in app or "cannot hold a device key" in app, \
        "app.js must fail honestly when crypto.subtle lacks Ed25519"


# ---- 3. CANONICALIZATION PARITY (the signed-bytes contract), verified under Node ------------------
_NODE_SCRIPT = (
    "const {canonicalJson}=require(process.env.CANON);"
    "const core=JSON.parse(process.argv[1]);"
    "process.stdout.write(Buffer.from(canonicalJson(core),'utf8'));"
)


def _need_node() -> str:
    """The node binary (callers use it as argv[0]), or a SKIP where node is absent — except in CI
    (GITHUB_ACTIONS) or where VIGIL_REQUIRE_NODE is set (every CI job that runs this file sets it): there a
    missing node FAILS, so these executed-JS proofs can never go green unrun."""
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH: this job must "
                        "EXECUTE these JS tests")
        pytest.skip("node not installed")
    return node


def _node_canonical(core: dict) -> bytes:
    """Run the SHIPPED JS canonicalJson (canonical.js) under Node over `core`; return its UTF-8 bytes."""
    out = subprocess.run(
        [_need_node(), "-e", _NODE_SCRIPT, json.dumps(core)],
        env={"CANON": str((WEBAPP / "canonical.js").resolve()), "PATH": __import__("os").environ.get("PATH", "")},
        capture_output=True, timeout=30,
    )
    assert out.returncode == 0, f"node canonicalJson failed: {out.stderr.decode(errors='replace')}"
    return out.stdout


def test_canonicaljson_parity_via_node():
    # (a) the DOCUMENTED fixed envelope vector — byte-identical to sigil.bridge.envelope.envelope_message
    core = build_core("DEVKEYB64", "read:snapshot", {}, 1, 1700000000)
    expected = b'{"action":"read:snapshot","args":{},"device":"DEVKEYB64","nonce":1,"ts":1700000000,"v":1}'
    assert envelope_message(core) == expected, "the Python parity contract byte string drifted"
    js = _node_canonical(core)
    assert js == expected, f"JS canonicalJson drifted from the pinned vector:\n  py={expected!r}\n  js={js!r}"
    assert js == envelope_message(core), "JS canonicalJson != Python envelope_message (signatures would be rejected)"

    # (b) the approval message the phone signs for /api/action — canonical_json({approver,decision,target})
    approval = {"approver": "device", "decision": "approved", "target": 5}
    assert _node_canonical(approval) == canonical_json(approval), "approval-message canonicalization drifted"

    # (b2) the gesture ARM-REQUEST core the phone signs for /api/gesture/arm. sigil.gesture.session
    #      :: arm_request_message selects EXACTLY the _ARM_CORE keys {signal,device_id,nonce,ts,
    #      ttl_seconds} — all present here — so the phone MUST reproduce these bytes or arm_by_device /
    #      submit_arm_request reject every signature. Verified under Node against the shipped canonical.js.
    arm_core = {"signal": "gesture.arm_request", "device_id": "phone1", "nonce": 1,
                "ts": 1700000000, "ttl_seconds": 120}
    arm_expected = b'{"device_id":"phone1","nonce":1,"signal":"gesture.arm_request","ts":1700000000,"ttl_seconds":120}'
    assert arm_request_message(arm_core) == arm_expected, "the Python arm_request_message byte string drifted"
    assert _node_canonical(arm_core) == arm_request_message(arm_core), \
        "JS canonicalJson(arm core) != Python arm_request_message (arm signatures would be rejected)"

    # (c) nested / unicode / integer edges — key sort recurses, non-ASCII stays raw, ints have no .0
    for obj in (
        {"b": 2, "a": {"z": [3, 2, 1], "y": "x"}, "n": None, "t": True, "f": False},
        {"device": "abc/def+ghi==", "note": "café — naïve ✓", "nonce": 42},
        {"args": {"text": "halt now"}, "action": "relay", "v": 1, "nonce": 7, "ts": 1700000123, "device": "K"},
    ):
        assert _node_canonical(obj) == canonical_json(obj), f"canonicalization parity failed for {obj!r}"


# ---- 4. FIX 2 (HIGH-3): the phone can actually ARM a gesture session, CSP-safely -----------------
def test_gesture_arm_control_wired():
    html = _read("index.html")
    app = _read("app.js")
    assert 'data-act="arm-gesture"' in html, "index.html must expose an Arm-gesture button (data-act, no inline handler)"
    assert '"arm-gesture"' in app, "app.js click delegation must handle the arm-gesture action"
    assert "/api/gesture/arm" in app, "app.js must POST the arm request to /api/gesture/arm"
    assert "gesture.arm_request" in app, "app.js must build the gesture.arm_request core"
    # honest copy: the button confirms a request was SENT/recorded, never that it definitely armed
    assert "not armed yet" in app or "actually arms" in app, \
        "app.js arm copy must stay honest — the desktop re-verifies and is what actually arms"


# ---- 5. FIX 1 (LOW-8): a refused queued POST on flush is surfaced, never silently dropped ---------
def test_flush_surfaces_refused_delivery():
    app = _read("app.js")
    assert "FAILED delivery" in app, "flushOutbox must surface a refused (>=400) queued POST as FAILED, not swallow it"
    assert "PANIC NOT DELIVERED" in app, "a refused queued PANIC (emergency stop) must be surfaced explicitly (LOW-8)"
    # the delete is now CONDITIONAL on a 2xx (r.ok) — a NON-OK response marks failed, it does not idbDel
    assert "if (r.ok)" in app, "flushOutbox must inspect the response status before deleting a queued POST"


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
    print(f"{passed}/{len(fns)} Phase-9 W1-C (Companion PWA) guarantees hold")


def test_esc_is_safe_in_a_quoted_attribute_executed():
    """CQ-1: esc() output is placed inside `data-seq="…"` — it must escape BOTH quote styles, or a value
    carrying `"` ends the attribute and the rest becomes markup (CodeQL js/incomplete-html-attribute-
    sanitization). Executes the webapp's OWN esc() under node."""
    src = (WEBAPP / "app.js").read_text(encoding="utf-8")
    start = src.index("var ESC_MAP = ")
    end = src.index("};", src.index("var esc = function")) + 2
    prog = src[start:end] + "\nprocess.stdout.write(JSON.stringify(process.argv.slice(1).map(esc)));\n"
    hostile = ['1" onmouseover="alert(1)', "1' autofocus onfocus='alert(1)", "<img src=x>", "a&b", "42"]
    out = subprocess.run([_need_node(), "-e", prog, *hostile], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assert got == ["1&quot; onmouseover=&quot;alert(1)", "1&#39; autofocus onfocus=&#39;alert(1)",
                   "&lt;img src=x&gt;", "a&amp;b", "42"]
    for g in got:
        assert '"' not in g and "'" not in g and "<" not in g
    attr = '<button data-seq="' + got[0] + '">'                  # what refreshPending() builds
    assert attr.count('"') == 2                                  # the attribute cannot be broken out of


# ---- 6. installable with the owner's icons, served with the right types (Phase 3.4) ---------------------------
def _png_size(path):
    import struct
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR", path
    w, h, _d, colour = struct.unpack(">IIBB", data[16:26])
    return w, h, colour


def test_manifest_icons_are_the_owners_pngs():
    m = json.loads(_read("manifest.webmanifest"))
    assert m["start_url"] == "/static/index.html" and m["scope"] == "/static/" and m["display"] == "standalone"
    icons = m["icons"]
    assert {(i["sizes"], i["purpose"]) for i in icons} >= {("192x192", "any"), ("512x512", "any"),
                                                          ("512x512", "maskable")}
    for i in icons:
        assert i["type"] == "image/png" and i["src"].startswith("/static/brand/") and "data:" not in i["src"]
        w, h, colour = _png_size(WEBAPP / i["src"][len("/static/"):])
        assert f"{w}x{h}" == i["sizes"] and colour == 2, i          # the opaque dark avatar
    html = _read("index.html")
    assert '<link rel="manifest" href="/static/manifest.webmanifest">' in html
    assert '<link rel="icon" href="/static/brand/favicon.svg" type="image/svg+xml">' in html
    assert '<link rel="apple-touch-icon" href="/static/brand/apple-touch-icon.png">' in html
    assert 'href="data:' not in html


def _bridge():
    import tempfile
    import threading

    from sigil.bridge.server import build_server
    from sigil.reuse import generate_keypair
    spine = tempfile.mktemp(suffix=".jsonl")
    srv = build_server(addr="127.0.0.1", port=0, spine_path=spine,
                       trusted_pubkey=generate_keypair().public_key_b64)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _get(port, path):
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    return r.status, r.getheader("Content-Type"), r.read()


def test_the_bridge_serves_the_manifest_and_icons_with_their_types():
    srv, port = _bridge()
    try:
        for path, ctype in (("/static/manifest.webmanifest", "application/manifest+json"),
                            ("/static/brand/icon-192.png", "image/png"), ("/static/brand/icon-512.png", "image/png"),
                            ("/static/brand/favicon.svg", "image/svg+xml"),
                            ("/static/app.js", "application/javascript; charset=utf-8"),
                            ("/static/style.css", "text/css; charset=utf-8")):
            status, got, body = _get(port, path)
            assert status == 200 and got == ctype and body, (path, status, got)
        assert _get(port, "/static/manifest.json")[0] == 404            # the old name is gone
    finally:
        srv.shutdown()


def test_the_worker_cache_is_named_after_the_apps_build():
    from sigil.bridge import server as bridge_server
    srv, port = _bridge()
    try:
        status, ctype, body = _get(port, "/static/service-worker.js")
        assert status == 200 and ctype.startswith("application/javascript")
        build = bridge_server._webapp_build()
        assert re.fullmatch(r"[0-9a-f]{12}", build)
        text = body.decode()
        assert f'var BUILD = "{build}";' in text and "__COMPANION_BUILD__" not in text
        assert 'var CACHE = "sigil-companion-" + BUILD;' in text
    finally:
        srv.shutdown()


def test_a_changed_app_is_a_new_build(tmp_path, monkeypatch):
    from sigil.bridge import server as bridge_server
    for name in FILES:
        (tmp_path / name).write_bytes((WEBAPP / name).read_bytes())
    monkeypatch.setattr(bridge_server, "_WEBAPP", tmp_path)
    one = bridge_server._webapp_build()
    (tmp_path / "app.js").write_text(_read("app.js") + "\n// changed\n", encoding="utf-8")
    assert bridge_server._webapp_build() != one


_SW_HARNESS = r"""
const vm = require("vm");
const [SRC, CFG] = process.argv.slice(-2);
const cfg = JSON.parse(CFG);
const log = { puts: 0, added: [], deleted: [], skip: 0, claimed: 0, answers: {} };
const store = { "sigil-companion-v1": {}, "sigil-companion-oldbuild0000": {} };
const L = {};
const caches = {
  open: async (n) => { store[n] = store[n] || {}; const c = store[n];
    return { addAll: async (urls) => { log.added.push([n, urls]); urls.forEach(u => { c[u] = "cached:" + u; }); },
             put: async () => { log.puts++; },
             match: async (u) => (c[u] ? { body: c[u] } : undefined) }; },
  keys: async () => Object.keys(store),
  delete: async (k) => { log.deleted.push(k); delete store[k]; return true; } };
const self = { location: { origin: "https://phone.wg" }, addEventListener: (t, f) => { L[t] = f; },
  skipWaiting: () => { log.skip++; }, clients: { claim: async () => { log.claimed++; } } };
const ctx = { self, caches, URL, Promise, console, fetch: async (r) => ({ body: "net:" + (r.url || r) }) };
vm.createContext(ctx);
vm.runInContext(SRC, ctx);
(async () => {
  let p; L.install({ waitUntil: (x) => { p = x; } }); await p;
  L.activate({ waitUntil: (x) => { p = x; } }); await p;
  for (const [m, u] of cfg.requests) {
    let res = null;
    L.fetch({ request: { method: m, url: "https://phone.wg" + u }, respondWith: (x) => { res = x; } });
    log.answers[m + " " + u] = res === null ? null : (await res).body;
  }
  L.message({ data: { type: "nope" } });
  log.skipBeforeAsk = log.skip;
  L.message({ data: { type: "SKIP_WAITING" } });
  log.caches = Object.keys(store);
  console.log(JSON.stringify(log));
})();
"""


def test_the_worker_stores_only_the_shell_waits_for_the_owner_and_never_touches_api():
    src = _read("service-worker.js").replace("__COMPANION_BUILD__", "abcdef012345")
    code = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    assert ".put(" not in code, "the worker must store nothing at run time"
    reqs = [["GET", "/static/app.js"], ["GET", "/static/index.html"], ["GET", "/api/snapshot"],
            ["GET", "/api/stream"], ["POST", "/api/action"], ["POST", "/static/app.js"],
            ["GET", "/static/app.js?x=1"], ["GET", "/static/unknown.js"], ["GET", "/"]]
    out = subprocess.run([_need_node(), "-e", _SW_HARNESS, src, json.dumps({"requests": reqs})], capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    log = json.loads(out.stdout)
    assert log["answers"]["GET /static/app.js"] == "cached:/static/app.js"
    assert log["answers"]["GET /static/index.html"] == "cached:/static/index.html"
    for k in ("GET /api/snapshot", "GET /api/stream", "POST /api/action", "POST /static/app.js",
              "GET /static/app.js?x=1", "GET /static/unknown.js", "GET /"):
        assert log["answers"][k] is None, k
    assert log["puts"] == 0
    assert log["added"][0][0] == "sigil-companion-abcdef012345"
    assert "/static/manifest.webmanifest" in log["added"][0][1] and "/static/brand/icon-192.png" in log["added"][0][1]
    assert sorted(log["deleted"]) == ["sigil-companion-oldbuild0000", "sigil-companion-v1"]
    assert log["caches"] == ["sigil-companion-abcdef012345"]
    assert log["skipBeforeAsk"] == 0 and log["skip"] == 1        # it waits until the page asks


def test_the_app_offers_the_update_and_switches_only_when_asked():
    app = _read("app.js")
    assert 'btn.dataset.act = "apply-update";' in app and 'if (act === "apply-update") { return applyUpdate(); }' in app
    assert 'UPDATE.worker.postMessage({ type: "SKIP_WAITING" });' in app
    assert '"controllerchange", function () { if (UPDATE.asked) { location.reload(); } }' in app
    assert "if (!navigator.serviceWorker.controller) { return; }" in app       # not on the first install
    assert ".then(watchUpdates)" in app
