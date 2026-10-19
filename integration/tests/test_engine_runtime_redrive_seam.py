"""Wave 2 — the ENGAGE oracle seam confirms the RESPONSE-DERIVED classes via ``live.runtime_redrive``.

path_traversal (side_effect over a KNOWN file-content signature — LEAD-ONLY, it may not mint: see
test_runtime_redrive_soundness.py D5), reflected xss (reflection_context — the
canary reaches an EXECUTABLE HTML position), and exposure (predicate over a secret signature at a fixed
framework path) now mint signed FACTs from the autonomous chat/engage re-drive. This pins:

  * ``VigilEngine._redrive_spec`` emits a ``{"kind": "runtime", ...}`` spec for these classes (+ aliases).
  * ``wiring._live_runtime_redrive_fact`` mints a signed FACT ONLY when the matching deterministic oracle
    confirms the CLAIMED class over VIGIL's own gated live capture — and mints NOTHING for a benign endpoint
    (the mandatory negative controls), a non-runtime class, or an out-of-scope URL.

B1 (governed-engage FACT-parity) extends this to the W2 statistical/eval injection classes the deterministic
scanner already proves but the governed engage/chat seam previously refused to mint: ``ssti`` (evaluation
oracle over a per-probe product), ``boolean_sqli`` (the multi-round SPRT BooleanInferenceCheck /
boolean_inference_oracle — never the single-shot DifferentialCheck), and ``time_based_sqli`` (timing oracle:
Mann-Whitney U + effect-size floor + dose-response). ``runtime_redrive`` DELEGATES these to their
ssti/boolean/timing sibling arms; this file pins the routing spec, a live positive per class over a planted
sink, and the mandatory safe-twin controls (a FACT never mints on a benign endpoint).

Reuses the reviewed gated send (web_redrive._gated_web_send) and the existing checks
(ContentSignatureCheck / MarkerReflectionCheck / PathProbeCheck / BooleanInferenceCheck / TimingCheck) +
oracles; this file proves the routing + live positive + the negative controls end-to-end.
"""
from __future__ import annotations

import http.server
import re
import sqlite3
import subprocess
import threading
import time
import types
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---------------------------------------------------------------------------------------------------
# hermetic: _redrive_spec routing
# ---------------------------------------------------------------------------------------------------

def _decision(bug_class: str, *, url: str) -> types.SimpleNamespace:
    analysis = types.SimpleNamespace(exploit_succeeded=True, extracted_info={"bug_class": bug_class})
    tool = types.SimpleNamespace(tool_args={"url": url})
    return types.SimpleNamespace(tool=tool, output_analysis=analysis)


@pytest.mark.parametrize("claimed,norm", [
    ("path_traversal", "path_traversal"), ("directory_traversal", "path_traversal"),
    ("xss", "xss"), ("reflected_xss", "xss"), ("cross_site_scripting", "xss"),
    ("exposure", "exposure"), ("information_disclosure", "exposure"), ("framework_exposure", "exposure"),
])
def test_redrive_spec_emits_a_runtime_spec_for_response_derived_classes(claimed, norm):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(
        _decision(claimed, url="http://127.0.0.1:19010/documents/download?file=x"), None)
    assert spec is not None, f"{claimed} should be re-drivable"
    assert spec["kind"] == "runtime"
    assert spec["bug_class"] == norm
    assert spec["url"].endswith("/documents/download?file=x")


@pytest.mark.parametrize("claimed,norm", [
    # B1 (governed-engage FACT-parity): the W2 statistical/eval injection classes the deterministic scanner
    # already proves must now ALSO get a runtime re-drive spec from the governed engage producer. The blind
    # SQLi spellings must normalize to THEMSELVES (never to `sqli`) so the producer claims them HERE and they
    # never fall through to the error_signature SQLi branch.
    ("ssti", "ssti"), ("server_side_template_injection", "ssti"),
    ("boolean_sqli", "boolean_sqli"), ("blind_sqli", "boolean_sqli"), ("boolean_based_sqli", "boolean_sqli"),
    ("time_based_sqli", "time_based_sqli"), ("time_based_blind_sqli", "time_based_sqli"),
    ("time_sqli", "time_based_sqli"),
    # the SOUND in-band command-injection FACT is the dose-scaled timing channel — it normalizes to ITSELF
    # (never to `command_injection`, which would fall through to the OOB/side_effect branches) so the producer
    # claims it HERE and the seam routes it to the _cmdi_timing_redrive arm.
    ("time_based_command_injection", "time_based_command_injection"),
    ("time_based_rce", "time_based_command_injection"), ("time_based_cmdi", "time_based_command_injection"),
    # EL / SpEL / OGNL expression-language injection (CWE-917) — the EL-family subset of the SOUND evaluation
    # channel. Normalizes to itself (distinct CWE from ssti); the framework spellings fold onto it.
    ("el_injection", "el_injection"), ("spel_injection", "el_injection"),
    ("ognl_injection", "el_injection"), ("expression_language_injection", "el_injection"),
])
def test_redrive_spec_emits_a_runtime_spec_for_injection_classes(claimed, norm):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(
        _decision(claimed, url="http://127.0.0.1:19010/items?id=1"), None)
    assert spec is not None, f"{claimed} should be re-drivable through the governed engage seam"
    assert spec["kind"] == "runtime", (
        f"{claimed} must route to the runner-owned runtime engine, not the error_signature SQLi path")
    assert spec["bug_class"] == norm
    assert spec["url"].endswith("/items?id=1")


# ---------------------------------------------------------------------------------------------------
# live: _live_runtime_redrive_fact over a loopback app (positive + mandatory negative controls)
# ---------------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _prov(slug: str = "alpha"):
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    from vigil_integration.live.wiring import Provisioned
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return Provisioned(keypair=kp, trust_root=tr, signers=[("gov0", kp.private_key_b64)],
                       authority_path="", slug=slug)


_DECOY_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_DOTENV = "APP_ENV=production\nDB_PASSWORD=Sup3rSecret-LAB-DECOY-not-real\nJWT_SECRET=lab-decoy\n"


_DECOY_DOCROOT = "/srv/app/public/docs"
_DECOY_FS = {
    "/etc/passwd": _DECOY_PASSWD,
    "/srv/app/public/docs/report.pdf": "report contents",
}


def _decoy_read(value: str) -> "str | None":
    """A GENUINE local-file-inclusion sink: join the value to the docroot, RESOLVE it with POSIX
    dot-segment semantics, and serve whatever that names. Every encoding of the same path therefore
    resolves to the same file, and a name that does not exist simply misses.

    This replaces the substring matcher the fixture used to be (``any(t in f for t in ("..", "%2e",
    "/etc/", "passwd"))``). That shape is not a traversal at all — it answers what the payload MEANS
    rather than reading anything — so it is exactly the payload-CORRELATED false positive the soundness
    controls now refuse, and it could no longer stand in for a real read (see
    integration/tests/test_runtime_redrive_soundness.py)."""
    import posixpath
    if not value:
        return None
    return _DECOY_FS.get(posixpath.normpath(posixpath.join(_DECOY_DOCROOT, value)))


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


class _VulnApp(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        path = parts.path
        if path == "/download":                                   # VULNERABLE path traversal (a REAL read)
            content = _decoy_read((q.get("file") or [""])[0])
            if content is not None:
                return self._text(content, "text/plain")
            self.send_response(404)
            self.end_headers()
            return None
        if path == "/static":                                     # BENIGN: fixed body, no file signature
            return self._text("<html><body>static page</body></html>", "text/html")
        if path == "/search":                                     # VULNERABLE reflected xss (unescaped)
            v = (q.get("q") or [""])[0]
            return self._text(f"<html><body><h1>Results for: {v}</h1></body></html>", "text/html")
        if path == "/search-safe":                               # BENIGN: HTML-escaped reflection (inert)
            v = (q.get("q") or [""])[0]
            return self._text(f"<html><body><h1>Results for: {_esc(v)}</h1></body></html>", "text/html")
        if path == "/.env":                                       # VULNERABLE exposure
            return self._text(_DOTENV, "text/plain")
        self.send_response(404); self.end_headers()

    def _text(self, body: str, ctype: str):
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # silence
        return


class _SafeApp(http.server.BaseHTTPRequestHandler):
    """404s everything — the exposure negative control (no /.env, no /actuator/env, no /.git/config)."""
    def do_GET(self):  # noqa: N802
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Not Found")

    def log_message(self, *a):  # silence
        return


def _serve(handler=_VulnApp):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _redrive(url: str, bug_class: str) -> dict:
    return {"kind": "runtime", "url": url, "bug_class": bug_class}


def _fact(monkeypatch, tmp_path, url: str, bug_class: str, handler=_VulnApp):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_runtime_redrive_fact
    srv = _serve(handler); port = srv.server_address[1]
    try:
        return _live_runtime_redrive_fact(_prov(), {}, _redrive(url.format(port=port), bug_class))
    finally:
        srv.shutdown()


# -- positives --------------------------------------------------------------------------------------

class _CountingVulnApp(_VulnApp):
    """``_VulnApp`` that records how many requests actually reached the origin, so the seam test can tell
    "the arm ran and refused to certify" from "the arm was never dispatched"."""

    hits = 0

    def do_GET(self):  # noqa: N802
        type(self).hits += 1
        return super().do_GET()


def test_live_path_traversal_is_DRIVEN_and_never_mints_a_fact(monkeypatch, tmp_path):
    """path_traversal is LEAD-ONLY, and the seam must DRIVE it anyway.

    Two claims, both asserted against BEHAVIOUR rather than against a constant:

      1. Even a GENUINE read of /etc/passwd may not mint through this seam —
         ``path_traversal.file_signature`` is registered ``fact_capable: false`` because every guard the
         arm has varies only the SHAPE OF THE INPUT, and eight benign origins that read nothing satisfied
         all of them (see integration/tests/test_runtime_redrive_soundness.py, D5).
      2. The arm is nevertheless DISPATCHED, so the operator's LEAD has a VIGIL-owned gated capture behind
         it. A previous revision gated the seam on ``RUNTIME_FACT_CLASSES`` and returned before driving:
         zero requests reached the origin, no admitted verdict was recorded, and the lead was sourced
         entirely from the LLM's assertion — while the module comment and the registry ``limitation`` both
         said "the arm is still driven (it is real evidence for a human)". This test previously started a
         server that was never contacted, so it would have passed against a dead port; it now counts the
         requests.
    """
    from vigil_integration.live.runtime_redrive import RUNTIME_FACT_CLASSES, RUNTIME_REDRIVE_CLASSES
    assert "path_traversal" not in RUNTIME_FACT_CLASSES
    assert "path_traversal" in RUNTIME_REDRIVE_CLASSES, "the class is demoted, not removed"
    _CountingVulnApp.hits = 0
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/download?file=report.pdf",
                "path_traversal", handler=_CountingVulnApp)
    assert ref is None, "a traversal claim may only be confirmed to a LEAD, never to a signed FACT"
    # 2 controls + the treatment + the first alternate encoding (which corroborates and short-circuits)
    # on the first candidate parameter.
    assert _CountingVulnApp.hits >= 4, (
        f"the seam did not DRIVE the lead-only arm — only {_CountingVulnApp.hits} request(s) reached the "
        f"origin, so there is no VIGIL-owned capture behind the operator's lead and the registry's "
        f"'the arm is still driven' is false")


def test_live_reflected_xss_mints_a_fact(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/search?q=hello", "xss")
    assert ref, "a live unescaped reflection into an executable position must mint a signed FACT"


def test_live_exposure_mints_a_fact(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/", "exposure")
    assert ref, "a live /.env leaking DB_PASSWORD must mint a signed FACT"


# -- mandatory negative controls --------------------------------------------------------------------

def test_negctl_path_traversal_benign_endpoint_mints_nothing(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/static", "path_traversal")
    assert ref is None, "an endpoint that never returns file content must not mint a traversal FACT"


def test_negctl_reflected_xss_escaped_endpoint_mints_nothing(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/search-safe?q=hello", "xss")
    assert ref is None, "an HTML-escaping endpoint (inert reflection) must not mint an xss FACT"


def test_negctl_exposure_no_secret_mints_nothing(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/", "exposure", handler=_SafeApp)
    assert ref is None, "a host that 404s /.env etc. must not mint an exposure FACT"


def test_negctl_wrong_class_mints_nothing(monkeypatch, tmp_path):
    """An exposure claim over a traversal-only endpoint must not mint (the /.env probe 404s here)."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/download?file=x", "exposure",
                handler=_SafeApp)
    assert ref is None


def test_non_runtime_class_is_not_handled_here(monkeypatch, tmp_path):
    """A web-fact class (open_redirect) is routed to the web seam, not this one → None here."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/search?q=x", "open_redirect")
    assert ref is None


def test_out_of_scope_url_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")   # only 127.0.0.1 is in scope
    from vigil_integration.live.wiring import _live_runtime_redrive_fact
    ref = _live_runtime_redrive_fact(
        _prov(), {}, _redrive("http://10.99.99.99/download?file=x", "path_traversal"))
    assert ref is None, "an out-of-scope target must never mint a FACT"


# ---------------------------------------------------------------------------------------------------
# red-pen near-miss negative controls (BLOCK-1/2/3): presence != causation
# ---------------------------------------------------------------------------------------------------

class _DocsApp(http.server.BaseHTTPRequestHandler):
    """BLOCK-1 near-miss: a benign docs page that IGNORES ?file and always prints the passwd signature as
    documentation. A presence-only check would false-FACT; the control differential must refuse it."""
    def do_GET(self):  # noqa: N802
        body = ("<html><body><h1>Docs</h1><p>An /etc/passwd line looks like: "
                "<code>root:x:0:0:root:/root:/bin/bash</code></p></body></html>")
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


class _SpaApp(http.server.BaseHTTPRequestHandler):
    """BLOCK-2 near-miss: a 200 soft-404 SPA that serves the SAME bundle (naming DB_PASSWORD=... in a JS
    config) at EVERY path. The random-path control must catch the catch-all and refuse."""
    def do_GET(self):  # noqa: N802
        body = ("<html><head><script>window.__CFG='APP_ENV=prod;DB_PASSWORD=placeholder;'</script></head>"
                "<body>app</body></html>")
        raw = body.encode("utf-8")
        self.send_response(200)   # 200 for EVERYTHING (soft-404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


class _JsStringApp(http.server.BaseHTTPRequestHandler):
    """BLOCK-3 near-miss: /search reflects q into a QUOTE-ESCAPED JS string literal inside <script> (the SAFE
    server-side pattern). The canary is present in <script> text but did NOT break out — must NOT mint."""
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        v = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        safe = v.replace("\\", "\\\\").replace('"', '\\"')   # escape the JS string literal
        body = f'<html><head><script>var searchTerm = "{safe}";</script></head><body>ok</body></html>'
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


def test_negctl_path_traversal_docs_page_with_signature_mints_nothing(monkeypatch, tmp_path):
    """BLOCK-1: a page that always shows root:x:0:0: (docs) but does not READ the file must not mint."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/docs", "path_traversal", handler=_DocsApp)
    assert ref is None, "a docs page that merely prints the signature must not mint a traversal FACT"


def test_negctl_exposure_soft_404_spa_mints_nothing(monkeypatch, tmp_path):
    """BLOCK-2: a 200 soft-404 SPA that names DB_PASSWORD everywhere must not mint (control catches it)."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/", "exposure", handler=_SpaApp)
    assert ref is None, "a soft-404 catch-all naming the signature everywhere must not mint an exposure FACT"


def test_negctl_xss_quote_escaped_js_string_mints_nothing(monkeypatch, tmp_path):
    """BLOCK-3: a canary reflected into a quote-escaped <script> string literal (no breakout) must not mint."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/search?q=hello", "xss", handler=_JsStringApp)
    assert ref is None, "a quote-escaped JS-string reflection (presence, not breakout) must not mint an xss FACT"


# ---------------------------------------------------------------------------------------------------
# B1 — governed-engage FACT-parity for the W2 statistical/eval injection classes
# ---------------------------------------------------------------------------------------------------
#
# The deterministic scanner (and the Strix proof-sink rail, test_strix_http_redrive.py) already PROVE ssti /
# boolean_sqli / time_based_sqli; before B1 the governed engage/chat seam refused to mint them (under-report of
# already-proven findings). These tests pin that the SAME seam the response-derived classes use now mints a
# signed FACT for the three injection classes over a planted instance — through ``runtime_redrive``'s delegation
# to the ssti/boolean/timing sibling arms — and stays SILENT (no FACT → LEAD) on a safe twin. The planted
# surfaces mirror test_strix_http_redrive.py::_App: a REAL sink per class (never a payload-substring matcher),
# so a FACT rests on the target's own behaviour, not on the shape of VIGIL's probe.

_SLEEP_RE = re.compile(r"(?:pg_)?sleep\(\s*(\d*\.?\d+)\s*\)", re.IGNORECASE)
_ARITH_RE = re.compile(r"(\d{4,})\s*\*\s*(\d{4,})")
# EL / SpEL / OGNL arithmetic ONLY inside an expression wrapper (${...} / #{...} / %{...}) — so the /el sink
# evaluates an EL expression (the vuln) but a bare reflected number never fires it.
_EL_ARITH_RE = re.compile(r"[$#%]\{(\d{4,})\s*\*\s*(\d{4,})\}")

_INJ_DB = sqlite3.connect(":memory:", check_same_thread=False)
_INJ_DB.execute("CREATE TABLE users(id INTEGER, name TEXT)")
_INJ_DB.executemany("INSERT INTO users VALUES(?, ?)",
                    list(enumerate("alice bob carol dave erin frank grace heidi".split())))
_INJ_DB_LOCK = threading.Lock()


def _inj_bool_rows(value: str) -> int:
    """A REAL string-concatenated sqlite3 injection sink, so the origin EVALUATES the injected clause and
    answers its TRUTH VALUE (mirrors test_strix_http_redrive._bool_rows). This is what lets the SPRT arm's
    shape-varied always-true clauses land on one response and the always-false clauses on another — the
    2-cluster split ``boolean_inference_oracle`` demands. A substring fixture would answer the payload STRING,
    the exact confusion a lexical WAF masquerading as a boolean channel would exploit."""
    with _INJ_DB_LOCK:
        try:
            return len(_INJ_DB.execute(
                "SELECT id, name FROM users WHERE name = '" + value + "'").fetchall())
        except sqlite3.Error:
            return -1


class _InjApp(http.server.BaseHTTPRequestHandler):
    """Planted SSTI / boolean-blind / time-based sinks + their safe twins, for the governed engage seam."""

    def _html(self, body: str, code: int = 200) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")   # declared → body is adjudicable
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        q = parse_qs(parts.query, keep_blank_values=True)
        value = (q.get("q") or q.get("id") or [""])[0]
        path = parts.path

        if path == "/ssti":                       # VULNERABLE: EVALUATES the arithmetic, emits ONLY the product
            m = _ARITH_RE.search(value)
            if m:
                return self._html(f"<html><body><p>{int(m.group(1)) * int(m.group(2))}</p></body></html>")
            return self._html(f"<html><body><p>{_esc(value)}</p></body></html>")   # benign echo, no product
        if path == "/ssti-safe":                  # BENIGN: reflects the RAW expression verbatim (not evaluated)
            return self._html(f"<html><body><p>{value}</p></body></html>")

        if path == "/bool":                       # VULNERABLE: a REAL sqlite3 string-concatenation sink
            n = _inj_bool_rows(value)
            if n < 0:
                return self._html("<html><body>query error, please retry</body></html>")
            return self._html("<html><body>alice bob carol dave erin frank grace heidi</body></html>"
                              if n else "<html><body>no results found for your query</body></html>")
        if path == "/bool-safe":                  # BENIGN: identical body for ANY input → no boolean channel
            return self._html("<html><body>welcome to the catalogue, browse our products</body></html>")
        if path == "/bool-dynamic":               # DECOY (DETERMINISTIC always-varies, no RNG): the body LENGTH
            # steps by a large fixed amount per request, so a byte-identical clause repeat comes back different →
            # the SPRT determinism/stability control trips EVERY round and it refutes — this is the exact
            # dynamic-page trap a single-shot DifferentialCheck would false-FACT on.
            type(self).dyn = getattr(type(self), "dyn", 0) + 1
            pad = "=" * (40 + (type(self).dyn % 5) * 90)
            return self._html(f"<html><body>catalogue {pad} listing</body></html>")

        if path == "/time":                       # VULNERABLE: sleeps the injected duration (dose-responsive)
            m = _SLEEP_RE.search(value)
            if m:
                time.sleep(min(float(m.group(1)), 2.0))
            return self._html("<html><body>ok</body></html>")
        if path == "/time-safe":                  # BENIGN: UNIFORMLY slow — a fixed sleep for EVERY request
            time.sleep(0.05)
            return self._html("<html><body>ok</body></html>")

        if path == "/cmd-time":                    # VULNERABLE: GENUINE shell execution of the host param
            # (subprocess shell=True) — a REAL command-injection sink, NOT a simulated timer. The cmdi-timing
            # arm injects `127.0.0.1;sleep {s}` into `host`, so the shell runs a REAL `sleep` and the latency
            # SCALES with the injected dose (dose-responsive) → time_based_command_injection.
            host = (q.get("host") or [""])[0]
            try:
                subprocess.run("echo reached " + host, shell=True, capture_output=True, text=True, timeout=5)
            except Exception:  # noqa: BLE001
                pass
            return self._html("<html><body>ok</body></html>")

        if path == "/el":                          # VULNERABLE: EVALUATES an EL/SpEL/OGNL expression and emits
            # ONLY the product (a server-side expression evaluator — the CWE-917 vuln). Fires on ${N*M}/#{N*M}/
            # %{N*M}; a bare reflected number does not (the wrapper is required), mirroring /ssti for EL syntax.
            m = _EL_ARITH_RE.search(value)
            if m:
                return self._html(f"<html><body><p>{int(m.group(1)) * int(m.group(2))}</p></body></html>")
            return self._html(f"<html><body><p>{_esc(value)}</p></body></html>")   # benign echo, no product
        if path == "/el-safe":                     # BENIGN ${VAR} SUBSTITUTION engine — the decisive EL control:
            # substitutes KNOWN variables but NEVER computes arithmetic, so ${N*M} (an unknown "var") yields the
            # empty string, the product never appears, and the evaluation oracle refuses → LEAD, not a FACT.
            out = re.sub(r"[$#%]\{([^}]*)\}", lambda mo: {"user": "guest", "env": "prod"}.get(mo.group(1), ""), value)
            return self._html(f"<html><body><p>config: {_esc(out)}</p></body></html>")

        self.send_response(404)
        self.end_headers()

    def log_message(self, *a):  # silence
        return


# -- positives: the governed engage seam mints a FACT for each injection class ----------------------

def test_live_ssti_mints_a_fact(monkeypatch, tmp_path):
    """A live server that EVALUATES a runner-injected per-probe product must mint a signed SSTI FACT."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/ssti?q=seed", "ssti", handler=_InjApp)
    assert ref, "a live server evaluating the injected expression must mint a signed SSTI FACT via the seam"


def test_live_el_injection_mints_a_fact(monkeypatch, tmp_path):
    """A live server that EVALUATES a runner-injected EL/SpEL/OGNL expression (${N*M} / #{N*M} / %{N*M}) must
    mint a signed el_injection FACT via the governed seam — the EL-family sibling of SSTI, the SAME sound
    evaluation_oracle. Proves el_injection reaches the (already EL-capable) evaluation arm and mints under its
    own CWE-917 class rather than staying a LEAD."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/el?q=seed", "el_injection", handler=_InjApp)
    assert ref, "a live EL-evaluating sink must mint a signed el_injection FACT via the seam"


def test_live_boolean_sqli_mints_a_fact_via_sprt(monkeypatch, tmp_path):
    """A REAL boolean-blind sink must mint a signed FACT — and ONLY via the multi-round SPRT
    ``BooleanInferenceCheck`` / ``boolean_inference_oracle`` (never the single-shot DifferentialCheck, which
    false-FACTs on a dynamic page). The boolean channel here is a genuine sqlite3 concatenation, so the SPRT
    reaches its confirm boundary over the shape-varied true/false clusters."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/bool?q=seed", "boolean_sqli", handler=_InjApp)
    assert ref, "a live boolean-blind sink must mint a signed boolean_sqli FACT via the SPRT arm"


def test_boolean_seam_routes_through_the_sprt_control_not_differential():
    """Correctness-trap pin (non-negotiable): the boolean arm the seam dispatches to adjudicates through the
    multi-round SPRT ``BooleanInferenceCheck`` + ``boolean_inference_oracle``, NOT the single-shot
    ``DifferentialCheck`` (which false-FACTs on a dynamic page). Asserted structurally against the arm source so
    a future refactor that swaps the control is caught even without a live dynamic-page origin."""
    import inspect

    from vigil_integration.live import runtime_redrive as rr
    src = inspect.getsource(rr.boolean_redrive)
    assert "BooleanInferenceCheck" in src and "boolean_inference_oracle" in src, (
        "boolean_redrive must route through the SPRT BooleanInferenceCheck / boolean_inference_oracle")
    assert "DifferentialCheck" not in src, (
        "boolean_redrive must NOT use the single-shot DifferentialCheck (false-FACTs on a dynamic page)")
    # and the dispatcher must delegate boolean_sqli to that arm (not to the single-capture inline body).
    disp = inspect.getsource(rr.runtime_redrive)
    assert "boolean_redrive" in disp and "RUNTIME_STAT_FACT_CLASSES" in disp, (
        "the dispatcher must delegate the statistical classes to their sibling arms")


def test_live_time_based_sqli_mints_a_fact(monkeypatch, tmp_path):
    """A live server that SLEEPs proportionally to the injected delay must mint a signed time-based FACT."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/time?q=seed", "time_based_sqli",
                handler=_InjApp)
    assert ref, "a live dose-responsive SLEEP sink must mint a signed time_based_sqli FACT via the seam"


def test_live_time_based_command_injection_mints_a_fact(monkeypatch, tmp_path):
    """The SOUND in-band command-injection FACT: a GENUINE shell sink (subprocess shell=True) that runs the
    injected `;sleep {s}` makes the latency SCALE with the dose, so the governed engage seam dispatches
    time_based_command_injection to the _cmdi_timing_redrive arm and the timing oracle mints a signed FACT —
    the channel the calculator-fakeable in-band computed-product side_effect (now LEAD-only) could not sound."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/cmd-time?host=seed",
                "time_based_command_injection", handler=_InjApp)
    assert ref, "a live dose-responsive shell `sleep` sink must mint a signed time_based_command_injection FACT"


def test_cmdi_timing_seam_routes_through_the_timing_oracle_not_the_side_effect():
    """Correctness-trap pin: the seam dispatches time_based_command_injection to the _cmdi_timing_redrive arm,
    which adjudicates through the dose-response TimingCheck / timing_oracle over SHELL sleep break-outs — NOT
    the calculator-fakeable side_effect computed-product channel (command_injection.reflected_output, now
    LEAD-only). Asserted structurally so a refactor that re-points it at the unsound channel is caught."""
    import inspect

    from vigil_integration.live import runtime_redrive as rr
    wrapper = inspect.getsource(rr._cmdi_timing_redrive)
    assert "timing_redrive" in wrapper and "_CMDI_SLEEP_TEMPLATES" in wrapper, (
        "_cmdi_timing_redrive must drive the timing arm with the shell sleep break-out templates")
    assert "cmdi_reflected_redrive(" not in wrapper and "side_effect_oracle" not in wrapper, (
        "_cmdi_timing_redrive must NOT call the calculator-fakeable side_effect arm/oracle (the docstring may "
        "name it to contrast; the routing must go through timing_redrive only)")
    disp = inspect.getsource(rr.runtime_redrive)
    assert '"time_based_command_injection": _cmdi_timing_redrive' in disp, (
        "the dispatcher must delegate time_based_command_injection to the _cmdi_timing_redrive arm")
    # and the shell sleep templates must actually be shell break-outs that run `sleep`
    assert all("sleep {s}" in t for t in rr._CMDI_SLEEP_TEMPLATES) and len(rr._CMDI_SLEEP_TEMPLATES) >= 3, (
        "_CMDI_SLEEP_TEMPLATES must be shell break-outs invoking `sleep`")


# -- mandatory negative controls: a safe twin mints nothing (stays a LEAD) --------------------------

def test_negctl_ssti_reflected_but_unevaluated_mints_nothing(monkeypatch, tmp_path):
    """FP: the raw expression survives verbatim (reflected, not evaluated) → no product → LEAD, not a FACT."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/ssti-safe?q=seed", "ssti", handler=_InjApp)
    assert ref is None, "a verbatim-reflected (unevaluated) expression must not mint an SSTI FACT"


def test_negctl_el_injection_variable_substitution_mints_nothing(monkeypatch, tmp_path):
    """FP (the decisive EL control): a benign ${VAR} substitution engine substitutes known variables but NEVER
    computes arithmetic, so the unguessable ${N*M} product never appears → the evaluation oracle refuses →
    LEAD, not a FACT. This is why the EL evaluation channel is SOUND where the cmdi computed product is not:
    only a real server-side EXPRESSION EVALUATOR (the vuln) produces the product, not a variable substitution."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/el-safe?q=seed", "el_injection", handler=_InjApp)
    assert ref is None, "a benign ${VAR} substitution engine must not mint an el_injection FACT"


def test_negctl_boolean_sqli_static_page_mints_nothing(monkeypatch, tmp_path):
    """FP: an endpoint with no true/false differential (same body for any input) → no SPRT flip → LEAD."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/bool-safe?q=seed", "boolean_sqli",
                handler=_InjApp)
    assert ref is None, "a static page (no boolean channel) must not mint a boolean_sqli FACT"


def test_negctl_boolean_sqli_dynamic_page_mints_nothing(monkeypatch, tmp_path):
    """CORRECTNESS-TRAP control: a DETERMINISTIC always-varies page (body length steps every request) is the
    exact dynamic page a single-shot differential would false-FACT on. The seam delegates to the SPRT arm, whose
    per-round stability control sees a byte-identical clause repeat come back different → refutes EVERY round →
    LEAD, not a FACT."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/bool-dynamic?q=seed", "boolean_sqli",
                handler=_InjApp)
    assert ref is None, "a dynamic (always-varies) page must not mint a boolean_sqli FACT through the seam"


def test_negctl_time_based_sqli_uniformly_slow_mints_nothing(monkeypatch, tmp_path):
    """FP: a uniformly slow endpoint (fixed sleep for every request) — no distribution shift, no dose-response
    → the timing oracle refuses → LEAD, not a FACT."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/time-safe?q=seed", "time_based_sqli",
                handler=_InjApp)
    assert ref is None, "a uniformly slow endpoint must not mint a time_based_sqli FACT"


def test_negctl_time_based_command_injection_uniformly_slow_mints_nothing(monkeypatch, tmp_path):
    """FP: the same uniformly slow endpoint, claimed as time_based_command_injection — a fixed per-request
    delay has no dose-response, so the cmdi-timing arm refuses → LEAD, not a FACT (the dose-response gate is
    what makes the shell-sleep channel sound where a slow/loaded endpoint is not)."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/time-safe?host=seed",
                "time_based_command_injection", handler=_InjApp)
    assert ref is None, "a uniformly slow endpoint must not mint a time_based_command_injection FACT"
