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
import re
import shutil
import subprocess
from pathlib import Path

from sigil.bridge import build_core, envelope_message
from sigil.reuse import canonical_json

from sigil.bridge import envelope as _E
WEBAPP = Path(_E.__file__).parent / "webapp"

FILES = ["index.html", "app.js", "style.css", "manifest.json", "service-worker.js", "canonical.js"]


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


def _node_canonical(core: dict) -> bytes:
    """Run the SHIPPED JS canonicalJson (canonical.js) under Node over `core`; return its UTF-8 bytes."""
    out = subprocess.run(
        ["node", "-e", _NODE_SCRIPT, json.dumps(core)],
        env={"CANON": str((WEBAPP / "canonical.js").resolve()), "PATH": __import__("os").environ.get("PATH", "")},
        capture_output=True, timeout=30,
    )
    assert out.returncode == 0, f"node canonicalJson failed: {out.stderr.decode(errors='replace')}"
    return out.stdout


def test_canonicaljson_parity_via_node():
    if not shutil.which("node"):
        print("  SKIP  node not present — canonicalization parity NOT verified (install Node 22 to falsify)")
        return

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

    # (c) nested / unicode / integer edges — key sort recurses, non-ASCII stays raw, ints have no .0
    for obj in (
        {"b": 2, "a": {"z": [3, 2, 1], "y": "x"}, "n": None, "t": True, "f": False},
        {"device": "abc/def+ghi==", "note": "café — naïve ✓", "nonce": 42},
        {"args": {"text": "halt now"}, "action": "relay", "v": 1, "nonce": 7, "ts": 1700000123, "device": "K"},
    ):
        assert _node_canonical(obj) == canonical_json(obj), f"canonicalization parity failed for {obj!r}"


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
