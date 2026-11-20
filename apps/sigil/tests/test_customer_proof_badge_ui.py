"""Consumer PR-I (Area 8) — the proof badge in the customer app (executed under node), its page flag, and the public
"Verify a VIGIL finding" explainer on the public site.

What this pins:
  * THE BADGE renders ONLY for ``proof.verifiable === true`` with a well-formed certificate digest + fingerprint and a
    finding it can name — anything else (false, a string "true", a malformed digest, no slug, the flag off) leaves the
    card EXACTLY as it was; the panel opens on click with the server's values, the download link carries only the
    finding's identity, and the exact verify command;
  * THE PAGE FLAG: the edge writes data-proof-badge from VIGIL_CUSTOMER_PROOF_BADGE; the flag is the page's only
    difference (its value and the build id);
  * THE PUBLIC EXPLAINER: /verify and /verify/verify_pcf.py exist only while the flag is on (else the same 404 as any
    unknown path, and the site's build id never changes); the page names the shipped verifier's sha256 and the
    fingerprints VIGIL publishes; the verifier served is the shipped bytes.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
UI_JS = APP / "ui.js"
VERIFIER = REPO / "docs" / "proof-carrying-finding" / "verify_pcf.py"
FLAG = "VIGIL_CUSTOMER_PROOF_BADGE"

_PROOF_START = '  var PROOF_ON = pageFlag("proofBadge");'
_PROOF_END = "  // ---- end of proof badge (PR-I)"
_RETEST_START = '  var RETEST_ON = pageFlag("retest");'
_RETEST_END = "  // ---- end of retest (C1b)"
# PR-L (Area 11) merged in: the shared findingsBlock now also calls blindVulnBadge, so the harness slices in the
# blind-vuln region (its own var BLIND_VULN_ON = pageFlag("blindVuln") + helpers) exactly as it does retest/proof.
# With the flag off (the harness carries no data-blind-vuln) blindVulnBadge returns null, so the proof card is unchanged.
_BLIND_START = '  var BLIND_VULN_ON = pageFlag("blindVuln");'
_BLIND_END = "  // ---- Attack-path storytelling (PR-L, Area 11)"


# ------------------------------------------------------------------------------------- the SPA under node ----
def _need_node() -> str:
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH")
        pytest.skip("node not installed")
    return node


def _slice(src: str, start: str, end: str) -> str:
    return src[src.index(start):src.index(end)]


def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


_SER = r"""
function ser(e) {
  if (e == null) return "";
  if (!(e instanceof Node)) return String(e);
  if (e.children === undefined) return JSON.stringify(e.textContent);
  return e.tagName + (e.id ? "#" + e.id : "") + (e.className ? "." + e.className.split(" ").join(".") : "")
    + JSON.stringify(e.attrs) + "[" + e.children.map(ser).join(",") + "]";
}
"""

_PRELUDE = r"""
document.body.dataset.proofBadge = %(flag)s;
var API = "api/customer";                 // app.js's own constant, above the extracted code
var GUIDE_ON = false, RETEST_ON = false, PROOF_ON = false;
var BLIND_VULN_ON = false, ATTACK_PATH_ON = false;   // PR-L flags, stubbed off; the sliced blind block resets its own
function pageFlag(name) { var ds = (document.body && document.body.dataset) || {}; return ds[name] === "1"; }
function nav() {} async function refreshWho() {}
const VUI = window.VUI;
const h = VUI.h;
"""


def _run(script: str, *, flag="1") -> dict:
    """app.js's own kv + findingsBlock + the retest block + the PR-I proof block (all verbatim), the world stubbed."""
    from test_customer_onboarding import _DOM
    src = APP_JS.read_text(encoding="utf-8")
    prog = (_DOM + f"\nrequire({json.dumps(str(UI_JS))});\nconst out = {{}};\n" + _PRELUDE % {"flag": json.dumps(flag)}
            + _fn(src, "kv") + "\n" + _fn(src, "findingsBlock") + "\n" + _slice(src, _RETEST_START, _RETEST_END)
            + _slice(src, _PROOF_START, _PROOF_END)
            + _slice(src, _BLIND_START, _BLIND_END)        # PR-L: findingsBlock also calls blindVulnBadge
            + _SER
            + "\n(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
              " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


_GOOD = r"""
var DIG = "c".repeat(64), FP = "sha256:" + "f".repeat(64), OCD = "d".repeat(64);
function finding(proof, extra) {
  return Object.assign({ engagement_slug: "cust_a&b=c", finding_ref: "F1", oracle_context_digest: OCD,
                         severity: "high", bug_class: "sqli", proof: proof }, extra || {});
}
var GOODP = { verifiable: true, cert_digest: DIG, trust_root_fingerprint: FP, threshold: 2, signers: 2 };
"""


def test_the_badge_opens_a_verify_it_yourself_panel_with_the_servers_values():
    out = _run(_GOOD + r"""
var block = findingsBlock("a.example", [finding(GOODP)]);
var badge = block.querySelectorAll("button").filter(function (b) { return b.textContent === "✓ Independently verifiable"; })[0];
out.hasBadge = !!badge; out.cls = badge.className;
var panel = block.querySelector("div.cust-proof-panel");
out.hiddenBefore = panel.hidden; out.emptyBefore = panel.children.length;
badge.click();
out.hiddenAfter = panel.hidden; out.expanded = badge.attrs["aria-expanded"];
var a = panel.querySelector("a.cust-proof-download");
out.href = a.attrs.href; out.download = ("download" in a.attrs); out.linkText = text(a);
out.cmd = text(panel.querySelector("code"));
out.text = text(panel);
badge.click();
out.hiddenAgain = panel.hidden; out.expandedAgain = badge.attrs["aria-expanded"];
""")
    assert out["hasBadge"] is True and "cust-badge-verified" in out["cls"]
    assert out["hiddenBefore"] is True and out["emptyBefore"] == 0          # nothing is built until it is opened
    assert out["hiddenAfter"] is False and out["expanded"] == "true"
    assert out["hiddenAgain"] is True and out["expandedAgain"] == "false"
    # the download names ONLY the finding's identity, URL-encoded (never an org or a user)
    assert out["href"] == "api/customer/assessments/proof?engagement_slug=cust_a%26b%3Dc&cert_digest=" + "c" * 64
    assert out["download"] is True and out["linkText"] == "Download proof bundle"
    assert out["cmd"] == ("python3 verify_pcf.py finding --bundle proof-bundle.json --trust-root-fingerprint sha256:"
                          + "f" * 64)
    t = out["text"]
    assert "at least 2 keys had to agree" in t and "d" * 64 in t and "c" * 64 in t and "sha256:" + "f" * 64 in t
    assert "not part of the download" in t and "public verify page" in t and "does not re-run the test" in t
    assert "not part of this bundle" not in t                                # no retest verdict -> no fix sentence


def test_a_fixed_retest_is_never_presented_as_part_of_the_proof():
    """The bundle proves the FINDING; a retest's "fixed" is the retest's own verdict. With one, the panel says so
    plainly (the negative clearance certificate is not surfaced on this plane), and only for status "fixed"."""
    out = _run(_GOOD + r"""
function opened(extra) {
  var block = findingsBlock("a.example", [finding(GOODP, extra)]);
  var badge = block.querySelectorAll("button").filter(function (b) { return b.textContent === "✓ Independently verifiable"; })[0];
  badge.click();
  return text(block.querySelector("div.cust-proof-panel"));
}
out.fixed = opened({ retest: { status: "fixed", ts: 1 } });
out.still = opened({ retest: { status: "still_vulnerable", ts: 1 } });
out.odd = opened({ retest: { status: "FIXED", ts: 1 } });
""")
    assert "Your retest shows this finding fixed" in out["fixed"] and "not part of this bundle" in out["fixed"]
    assert "not part of this bundle" not in out["still"] and "not part of this bundle" not in out["odd"]


def test_anything_but_a_verified_proof_leaves_the_card_exactly_as_it_was():
    out = _run(_GOOD + r"""
var plain = ser(findingsBlock("a.example", [finding(undefined)]));
out.same = {};
var cases = {
  no_proof: finding(undefined), falsy: finding({ verifiable: false }), string_true: finding(Object.assign({}, GOODP, { verifiable: "true" })),
  bad_digest: finding(Object.assign({}, GOODP, { cert_digest: "C".repeat(64) })), short_digest: finding(Object.assign({}, GOODP, { cert_digest: "c" })),
  bad_fp: finding(Object.assign({}, GOODP, { trust_root_fingerprint: "f".repeat(64) })),
};
for (var k in cases) { out.same[k] = ser(findingsBlock("a.example", [cases[k]])) === plain; }
var noslug = finding(GOODP); delete noslug.engagement_slug;
var noslugPlain = finding(undefined); delete noslugPlain.engagement_slug;
out.same.no_slug = ser(findingsBlock("a.example", [noslug])) === ser(findingsBlock("a.example", [noslugPlain]));
out.badgeOn = ser(findingsBlock("a.example", [finding(GOODP)])) !== plain;
""")
    assert out["badgeOn"] is True
    assert out["same"] == {k: True for k in out["same"]}, out["same"]


def test_with_the_flag_off_a_verified_proof_changes_nothing():
    out = _run(_GOOD + r"""
out.same = ser(findingsBlock("a.example", [finding(GOODP)])) === ser(findingsBlock("a.example", [finding(undefined)]));
out.on = PROOF_ON;
out.html = ser(findingsBlock("a.example", [finding(GOODP)]));
""", flag="0")
    assert out["same"] is True and out["on"] is False
    assert "Independently verifiable" not in out["html"] and "cust-proof" not in out["html"]


def test_the_findings_card_calls_the_proof_block_and_the_retest_harness_still_sees_it():
    src = APP_JS.read_text(encoding="utf-8")
    fb = _fn(src, "findingsBlock")
    assert "proofBadge(f)," in fb                                            # one self-contained hook in the card
    assert src.count(_PROOF_START) == 1 and src.count(_PROOF_END) == 1
    block = _slice(src, _PROOF_START, _PROOF_END)
    assert "postJSON" not in block and "getJSON" not in block              # the badge never fetches on its own


# ------------------------------------------------------------------------------------------- the page flag ----
def _page_and_build(tmp_path):
    from sigil.ui.custui import build_customer_server
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
        r = c.getresponse()
        return r.read().decode(), r.getheader("X-Vigil-Build")
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_edge_writes_the_proof_badge_flag_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-proof-badge="0"' in off and "__VIGIL_PROOF_BADGE__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-proof-badge="1"' in on and build_on != build_off
    assert on.replace('data-proof-badge="1"', 'data-proof-badge="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert 'data-proof-badge="0"' in _page_and_build(tmp_path / f"c{v or 'e'}")[0], v


def test_the_edge_flag_helper_tracks_the_config(monkeypatch):
    from sigil.ui.custui import _proof_badge_on
    monkeypatch.delenv(FLAG, raising=False)
    assert _proof_badge_on() is False
    monkeypatch.setenv(FLAG, "on")
    assert _proof_badge_on() is True


# ------------------------------------------------------------------------------------ the public explainer ----
def _serve():
    from sigil.ui.pubui import build_public_server
    srv = build_public_server(host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _get(port, path, *, method="GET", etag=None):
    h = {"If-None-Match": etag} if etag else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_off_the_explainer_is_an_unknown_path_and_the_site_is_unchanged(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    srv, port = _serve()
    try:
        unknown = _get(port, "/no-such-page")
        for path in ("/verify", "/verify/", "/verify/verify_pcf.py"):
            code, hdr, body = _get(port, path)
            assert (code, body) == (unknown[0], unknown[2]) and code == 404, path
        build_off = _get(port, "/version.json")[2]
    finally:
        srv.shutdown()
    monkeypatch.setenv(FLAG, "1")
    srv, port = _serve()
    try:
        assert _get(port, "/version.json")[2] == build_off              # the site's build id never depends on it
    finally:
        srv.shutdown()


def test_on_the_explainer_names_the_shipped_verifier_and_the_published_fingerprints(monkeypatch):
    fp1, fp2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv("VIGIL_PROOF_PUBLISHED_FINGERPRINTS", f"{fp1}, not-a-fingerprint <script>, {fp2}")
    srv, port = _serve()
    try:
        for path in ("/verify", "/verify/"):
            code, hdr, body = _get(port, path)
            assert code == 200 and hdr["Content-Type"].startswith("text/html"), path
            assert "default-src 'self'" in hdr["Content-Security-Policy"] and "Set-Cookie" not in hdr
            page = body.decode()
            assert hashlib.sha256(VERIFIER.read_bytes()).hexdigest() in page
            assert f"<code>{fp1}</code>" in page and f"<code>{fp2}</code>" in page
            assert "<script" not in page and "not-a-fingerprint" not in page   # only validated values reach the page
            assert "__VIGIL_" not in page                                       # every placeholder was filled
            assert "verify_pcf.py finding --bundle proof-bundle.json" in page
        code, hdr, body = _get(port, "/verify/verify_pcf.py")
        assert code == 200 and hdr["Content-Type"] == "text/plain; charset=utf-8" and body == VERIFIER.read_bytes()
        assert hdr["X-Content-Type-Options"] == "nosniff"
        # revalidation + HEAD + anything else under /verify is a plain 404
        assert _get(port, "/verify/verify_pcf.py", etag=hdr["ETag"])[0] == 304
        code, hdr2, body2 = _get(port, "/verify", method="HEAD")
        assert code == 200 and body2 == b""
        assert _get(port, "/verify/other.html")[0] == 404
        assert _get(port, "/verify/../index.html")[0] == 200                  # normalised to the site's own landing
    finally:
        srv.shutdown()


def test_on_without_published_fingerprints_the_page_says_so_honestly(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.delenv("VIGIL_PROOF_PUBLISHED_FINGERPRINTS", raising=False)
    srv, port = _serve()
    try:
        page = _get(port, "/verify")[2].decode()
        assert "has not published a governance fingerprint" in page and "<code>sha256:" not in page
    finally:
        srv.shutdown()


def test_the_public_site_and_the_export_ship_the_same_verifier():
    from sigil.ui import proof_export, pubui
    assert pubui._VERIFIER_PATH == proof_export.VERIFIER_PATH == VERIFIER
