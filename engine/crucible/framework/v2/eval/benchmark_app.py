"""
eval.benchmark_app — a labelled, deliberately-vulnerable benchmark target.

The comparative spine (`eval.validation`) can score any tool against a labelled
`CorpusTarget`, but a *public* benchmark needs a target whose ground truth is
known exactly — otherwise a "false positive" count is guesswork. This module is
that target: a self-contained :class:`ThreadingHTTPServer` handler that plants a
SPREAD of real, distinct, deterministic web bugs, each at a known location, plus
:func:`benchmark_corpus` — the ground-truth manifest every tool is scored against.

Design rules that make the numbers trustworthy:

  * **Every planted bug is real.** The XSS reflects an attacker payload verbatim
    into executable HTML; the boolean SQLi dumps every row for a tautology and
    none for a benign term; the error-based SQLi echoes a real MySQL parser error
    on a quote; the open redirect reflects a parameter into a 302 ``Location``;
    the CORS endpoint reflects a hostile ``Origin`` with credentials; ``.git/config``,
    ``.env`` and the Spring ``/actuator/env`` leak their signature secrets.
  * **Every planted bug is single-class.** Each vulnerable endpoint is engineered
    to trip exactly ONE of CRUCIBLE's oracle-anchored checks, so the manifest is
    honest (no endpoint is silently also SSTI/traversal). Concretely: a reflecting
    sink is only exercised for markup-shaped input (so the marker-reflection
    side-effect checks for SSTI / path-traversal / error-based do not co-fire on a
    pure XSS sink), and the error page embeds its DB error inside a large static
    body so the boolean differential stays below threshold.
  * **The SAFE endpoints take input and handle it correctly** — a parameterised
    profile lookup, a constant health endpoint, an allow-listed download, an
    auto-escaping template, and an ordinary benign page — so a tool that flags them
    is measurably wrong. They are the false-positive ruler for the param-level
    checks. The two HOST-level classes (CORS, host-header) are anchored on the seed
    ``/`` alone: those checks probe only the first request per host, so the
    misconfiguration is planted there and every other route emits a clean
    CORS/host response — **no safe endpoint carries either bug**, which is what
    makes "anything reported on a safe endpoint is a false positive" honest for
    every class, not just the param-level ones.

The handler binds to loopback only and is served via :func:`serve`. It sends the
``Server: Jetty`` banner so the technology fingerprinter marks the stack ``java``
and the Spring-actuator check applies (that check is stack-gated by design).

Boundary: this is a target we own and run in-process for measurement. It is not a
probe, an exploit, or anything aimed at a third party.
"""

from __future__ import annotations

import contextlib
import html
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from .validation import CorpusTarget, ExpectedFinding

# ---------------------------------------------------------------------------
# Stored / second-order XSS model (Wave 2.1). A guestbook: a POST to surface A
# (/guestbook) PERSISTS a comment keyed by author; a GET to render-surface B
# (/guestbook/view) reflects the persisted comment VERBATIM into an executable
# HTML position (the planted stored-XSS), while the benign twin B' (/guestbook/
# safe) renders it HTML-escaped (inert — a textContent-equivalent store that must
# NEVER fire).
#
# These routes are DELIBERATELY NOT linked from the index and the store starts
# EMPTY, so the DEFAULT GET-only benchmark crawl (which drives `make gate`) never
# POSTs and never reaches a populated render — the default corpus + signed
# baseline stay byte-identical. The stored-XSS FACT is exercised only by the
# dedicated deep-profile assertion (scanner/tests/test_stored_xss.py), which POSTs
# through the gated write path and renders B in a real browser.
_GUESTBOOK: dict[str, str] = {}

# Session-fixation store (Wave 3.2). The set of session ids the login flow has BLESSED as authenticated.
# The VULNERABLE flow blesses the client-fixed id UNCHANGED (fixation); the SAFE twin rotates to a fresh id.
# Class-level in-process state, exercised only by the deep-profile session-fixation assertion — the default
# GET-only crawl never POSTs to the login routes, so `make gate` is unaffected.
# Maps an authenticated session id -> the username it belongs to (so the protected page renders that user's
# PER-IDENTITY PRIVATE datum, not a shared banner). The PRIVATE-READ REDUCTION needs per-user private content:
# the fixed session confirms fixation ONLY by reaching the VICTIM's private datum, absent from an OTHER
# identity's same-shape read. The chrome ``success_marker`` is shown to EVERY authenticated identity (it is
# NOT private) — modelling exactly the sixth-variant benign case a marker differential would false-fire on.
_SESSFIX_SESSIONS: dict[str, str] = {}
_SESSFIX_COOKIE = "SESSION"
_SESSFIX_SUCCESS_MARKER = "SESSFIX-AUTHENTICATED"


def _sessfix_private(user: str) -> str:
    """The per-user PRIVATE datum only that user's authenticated read renders — the victim-private
    discriminator the oracle's private-read differential requires (present in the owner's read, absent from
    an other-identity's same-shape read)."""
    return f"PRIVATE-SSN-{user}-4021-7788"

# ---------------------------------------------------------------------------
# CSRF-achieved model (Wave 3.3). A cookie-authenticated state-changing endpoint that
# authorizes a write on the ambient session cookie ALONE, driven by a REAL headless browser:
#   * GET  /csrf/login?mode=none|strict — VIGIL's OWN authenticated session: the SERVER sets the
#                                      ambient session cookie WITH a SameSite attribute a real
#                                      browser honours. mode=none (default) => SameSite=None;Secure
#                                      (the VULNERABLE config: the browser SENDS it cross-site);
#                                      mode=strict => SameSite=Strict (the DEFENDED config: the
#                                      browser does NOT send it cross-site => must NEVER fire);
#   * POST /csrf/transfer            — the VULNERABLE endpoint: accepts the write on the ambient
#                                      session cookie with NO anti-CSRF token and NO Origin check
#                                      → the planted achieved CSRF (when the cookie is SameSite=None);
#   * POST /csrf/transfer-protected  — the BENIGN TWIN: the SAME write, but requires a valid
#                                      anti-CSRF token in addition to the cookie, so a token-less
#                                      cross-site write is rejected → must NEVER fire;
#   * GET  /csrf/state[-protected]   — the AUTHORITATIVE post-state readback (an independent GET
#                                      of the applied markers, NOT an echo of the write request).
# The state-changing routes are DELIBERATELY NOT linked from the index and are POST-only, and the
# login/state routes are unlinked, so the default GET-only benchmark crawl (which drives `make gate`)
# never issues the write and never reaches an applied state — the default corpus + signed baseline
# stay byte-identical. The FACT / non-fire is exercised only by the dedicated deep-profile browser
# assertion (scanner/tests/test_csrf_achieved_browser.py), which drives the genuinely cross-site
# form POST from VIGIL's own different-site attacker page. The unique per-probe markers accumulate
# across probes (the oracle searches for THIS probe's marker), so no reset is needed.
_CSRF_APPLIED: list[str] = []
_CSRF_APPLIED_PROTECTED: list[str] = []
# The ambient session cookie VIGIL's OWN authenticated session holds (name=value), and the anti-CSRF
# token the protected twin additionally demands.
_CSRF_SESSION_COOKIE_NAME = "csrf_session"
_CSRF_SESSION_COOKIE_VALUE = "owner-authenticated-session"
_CSRF_TOKEN_VALUE = "bench-csrf-ok"

# ---------------------------------------------------------------------------
# Two-identity access-control model (Wave 3.1). Object endpoints keyed by ``id``,
# each account carrying a per-identity UNIQUE discriminator (its private IBAN) that
# appears ONLY in that account's authoritative record. The sound IdorCheck fires
# only when an attacker's cross-read REACHES the victim's discriminator — never a
# whole-body containment over shared boilerplate.
#   * /account       — the PLANTED IDOR/BOLA: authentication REQUIRED (logged-out is
#                      denied, so the content is authorization-gated) and object-level
#                      authz is BROKEN — an authenticated session reads any account IN
#                      ITS OWN TENANT (should be own-account-only), so a same-tenant peer
#                      (alice) cross-reads bob's IBAN (the achieved BOLA); a CROSS-tenant
#                      read still RENDERS the same account shell (SAME SHAPE) with the IBAN
#                      WITHHELD. A no-credential baseline gets 403 (no IBAN), and a THIRD,
#                      authenticated-but-UNAUTHORIZED principal (carol, a different tenant)
#                      gets that same-shape 200 render WITHOUT the IBAN — the round-5 same-ref
#                      unauthorized-authenticated baseline that proves the IBAN is genuinely
#                      access-gated PRIVATE data, not a reflected per-object token (which would
#                      appear in carol's same-shape render too);
#   * /account/safe  — the BENIGN TWIN: object-level authz ENFORCED, a caller reads
#                      only the account its OWN session cookie owns, so an attacker
#                      requesting the victim's id gets 403 with NO discriminator and
#                      the sound check MUST NOT fire.
# Both are DELIBERATELY NOT linked from the index and never issued by the default
# GET-only benchmark crawl (a fire needs the operator-supplied SECOND identity +
# per-identity discriminator), so the default corpus + signed baseline — and
# `make gate` — stay byte-identical. Exercised only by the two-identity assertion
# (scanner/tests/test_access_control_benchmark.py).
_ACCOUNTS: dict[str, tuple[str, str]] = {
    # id -> (holder, victim-UNIQUE private discriminator)
    "1": ("alice", "IBAN-ALICE-GB29-NWBK-6016-1331-9268-19"),
    "2": ("bob", "IBAN-BOB-DE89-VICTIM-UNIQUE-3704-0044-0532-0130-00"),
}
# session cookie value -> the account id that session legitimately owns. carol owns account 3 (a
# different tenant); she is a valid authenticated principal but has NO access to alice's/bob's tenant.
_ACCOUNT_SESSIONS: dict[str, str] = {"alice-sess": "1", "bob-sess": "2", "carol-sess": "3"}
# account id -> tenant. alice(1)+bob(2) share a tenant (the intra-tenant BOLA); carol(3) is in another.
_ACCOUNT_TENANTS: dict[str, str] = {"1": "acme", "2": "acme", "3": "globex"}


def _account_caller(cookie_header: str) -> str | None:
    """The account id the caller's ``sess=`` cookie legitimately owns, or None (unauthenticated / unknown)."""
    for part in (cookie_header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "sess":
            return _ACCOUNT_SESSIONS.get(v.strip())
    return None


# ---------------------------------------------------------------------------
# Client-side prototype pollution model (Wave 2.2). Two GET pages that both PARSE
# the URL query, the fragment (location.hash) and a JSON `json=` value into an
# object and reflect it, but differ in one way:
#   * /proto      — a VULNERABLE nested-key parser that FOLLOWS `__proto__` /
#                   `constructor.prototype` segments, so a `__proto__[KEY]=VAL`
#                   gadget writes onto Object.prototype (the planted bug);
#   * /proto/safe — the BENIGN TWIN: the SAME shape, but the parser GUARDS the
#                   dangerous keys, so it reflects the payload (presence) WITHOUT
#                   polluting Object.prototype (must never fire).
# Both are DELIBERATELY NOT linked from the index; the default GET-only benchmark
# crawl never runs their client JS (no browser), so `make gate` stays byte-
# identical. The FACT / non-fire is exercised only by the deep-profile browser
# assertion (scanner/tests/test_proto_pollution_browser.py).
_PROTO_PARSER_JS = r"""
function toPath(k){ return k.replace(/\]/g,'').replace(/\[/g,'.').split('.').filter(Boolean); }
function ingest(qs, walkSet, mergeFn){
  (qs||'').split('&').forEach(function(pair){
    if(!pair) return;
    var eq = pair.indexOf('=');
    var rk = eq<0?pair:pair.slice(0,eq);
    var rv = eq<0?'':pair.slice(eq+1);
    var name, value;
    try { name = decodeURIComponent(rk.replace(/\+/g,' ')); } catch(e){ name = rk; }
    try { value = decodeURIComponent(rv.replace(/\+/g,' ')); } catch(e){ value = rv; }
    if (name === 'json'){ try { mergeFn(JSON.parse(value)); } catch(e){} }
    else { walkSet(toPath(name), value); }
  });
}
function reflect(){
  var out = document.getElementById('out');
  if (out) out.textContent = 'source: ' + location.search + ' ' + location.hash;
}
"""

# The VULNERABLE parser: walkSet/merge follow every key, INCLUDING __proto__.
_PROTO_VULN_BODY = (
    "<h2>Proto</h2><div id=out></div><script>"
    + _PROTO_PARSER_JS
    + r"""
var data = {};
function walkSet(path, val){
  var cur = data;
  for (var i=0;i<path.length-1;i++){
    var k = path[i];
    if (!(k in cur)) cur[k] = {};
    cur = cur[k];              /* VULN: for k==='__proto__' this is Object.prototype */
  }
  cur[path[path.length-1]] = val;
}
function merge(src){ (function rec(target, s){
  for (var k in s){
    var v = s[k];
    if (v && typeof v === 'object'){ if (!(k in target)) target[k] = {}; rec(target[k], v); }
    else { target[k] = v; }    /* VULN: rec into target['__proto__'] === Object.prototype */
  }
})(data, src); }
ingest(location.search.replace(/^\?/,''), walkSet, merge);
ingest(location.hash.replace(/^#/,''), walkSet, merge);
reflect();
</script>"""
)

# The BENIGN TWIN: identical shape, but every write GUARDS the dangerous keys, so the
# payload is reflected (present) yet Object.prototype is never touched.
_PROTO_SAFE_BODY = (
    "<h2>Proto</h2><div id=out></div><script>"
    + _PROTO_PARSER_JS
    + r"""
function bad(k){ return k === '__proto__' || k === 'constructor' || k === 'prototype'; }
var data = Object.create(null);
function walkSet(path, val){
  if (path.some(bad)) return;   /* SAFE: refuse dangerous segments */
  var cur = data;
  for (var i=0;i<path.length-1;i++){
    var k = path[i];
    if (!(k in cur)) cur[k] = Object.create(null);
    cur = cur[k];
  }
  cur[path[path.length-1]] = val;
}
function merge(src){ (function rec(target, s){
  for (var k in s){
    if (bad(k)) continue;       /* SAFE: refuse dangerous keys */
    var v = s[k];
    if (v && typeof v === 'object'){ if (!(k in target)) target[k] = Object.create(null); rec(target[k], v); }
    else { target[k] = v; }
  }
})(data, src); }
ingest(location.search.replace(/^\?/,''), walkSet, merge);
ingest(location.hash.replace(/^#/,''), walkSet, merge);
reflect();
</script>"""
)

# ---------------------------------------------------------------------------
# Cross-origin postMessage achieved-exploit model (Wave 2.3). Three GET pages, each
# registering a window "message" handler, differing only in how they treat an
# untrusted-origin message:
#   * /postmessage         — the VULNERABLE handler: it does NOT check event.origin and
#                            routes the message to an EXECUTING sink (new Function for a
#                            code-bearing object, innerHTML for an HTML string). A gadget
#                            postMessage'd from a DIFFERENT (untrusted) origin executes —
#                            the planted achieved-exploit.
#   * /postmessage/origin-checked — the BENIGN TWIN: the SAME executing sinks, but the
#                            handler first REJECTS any message whose event.origin is not
#                            its own origin, so a cross-origin sender is dropped (this also
#                            IS the same-origin-only fixture). Must never fire.
#   * /postmessage/noexec  — the BENIGN TWIN: accepts ANY origin but routes the message to
#                            a NON-executing sink (textContent), so it RECEIVES but never
#                            executes. Must never fire.
# All three are DELIBERATELY NOT linked from the index; the default GET-only benchmark crawl
# never runs their client JS (no browser, and delivery needs VIGIL's cross-origin sender),
# so `make gate` stays byte-identical. The FACT / non-fire is exercised only by the
# deep-profile browser assertion (scanner/tests/test_postmessage_exploited_browser.py).
_PM_VULN_BODY = r"""<h2>postMessage</h2><div id=sink></div><script>
window.addEventListener('message', function(ev){
  /* VULN: no ev.origin check — an untrusted origin's message is trusted */
  var d = ev.data;
  if (d && typeof d === 'object') {
    if (typeof d.code === 'string') { try { (new Function(d.code))(); } catch(e){} return; }
    if (typeof d.html === 'string') { document.getElementById('sink').innerHTML = d.html; return; }
    if (typeof d.url === 'string')  { var a=document.createElement('a'); a.href=d.url; return; }
  }
  if (typeof d === 'string') {
    /* an HTML sink for a string message: an <img onerror> / <svg onload> executes here */
    document.getElementById('sink').innerHTML = d;
  }
}, false);
</script>"""

_PM_ORIGIN_CHECKED_BODY = r"""<h2>postMessage</h2><div id=sink></div><script>
window.addEventListener('message', function(ev){
  /* SAFE: reject any message not from THIS page's own origin (same-origin only) */
  if (ev.origin !== window.location.origin) { return; }
  var d = ev.data;
  if (d && typeof d === 'object' && typeof d.code === 'string') { try { (new Function(d.code))(); } catch(e){} return; }
  if (typeof d === 'string') { document.getElementById('sink').innerHTML = d; }
}, false);
</script>"""

_PM_NOEXEC_BODY = r"""<h2>postMessage</h2><div id=sink></div><script>
window.addEventListener('message', function(ev){
  /* SAFE: accepts any origin but routes to a NON-executing sink (textContent) — it
     RECEIVES the message but never executes it (the data-leak/posture residual). */
  var d = ev.data;
  document.getElementById('sink').textContent = (typeof d === 'string') ? d : JSON.stringify(d);
}, false);
</script>"""

# The STATIC (reusable-across-responses) script-src nonce the /csp-bypass route reflects — the
# planted bug. A properly-hardened app mints a FRESH nonce per response; a static one is readable
# from any response and reflected back in a <script nonce=…>, so it is the achieved-bypass primitive.
# /csp-wellformed and /csp-neutralized reuse it only as a well-formed nonce-based script-src.
CSP_STATIC_NONCE = "crucibleStaticNonce2024"

# ---------------------------------------------------------------------------
# The boolean-blind SQLi model (a faithful reuse of the vulnerable matcher from
# verify.confirmation): user input is string-built into ``name = '<q>'`` and split
# on `` OR ``, so an `` ' OR '1'='1`` tautology breaks out and selects every row,
# while any benign term selects none. This is a REAL, observable differential.
# ---------------------------------------------------------------------------

_ROWS: tuple[dict[str, object], ...] = (
    {"id": 1, "name": "alice", "role": "user", "email": "alice@corp.example"},
    {"id": 2, "name": "bob", "role": "admin", "email": "bob@corp.example"},
    {"id": 3, "name": "carol", "role": "user", "email": "carol@corp.example"},
)

_CLAUSE_NAME = re.compile(r"name = '(.*)'")
_CLAUSE_TAUTOLOGY = re.compile(r"'(.*)'\s*=\s*'(.*)'")


def _clause_true(clause: str, name: str) -> bool:
    m = _CLAUSE_NAME.fullmatch(clause)
    if m:
        return name == m.group(1)
    m = _CLAUSE_TAUTOLOGY.fullmatch(clause)
    if m:
        return m.group(1) == m.group(2)
    return False


def _vulnerable_match(q: str) -> list[dict[str, object]]:
    """Deliberately flawed: builds ``name = '<q>'`` by concatenation, so a
    `` ' OR '1'='1`` clause is an always-true tautology that returns every row."""
    stmt = "name = '" + q + "'"
    clauses = [c.strip() for c in stmt.split(" OR ")]
    return [row for row in _ROWS if any(_clause_true(c, row["name"]) for c in clauses)]


def _safe_match(q: str) -> list[dict[str, object]]:
    """The parameterised twin: ``q`` is bound as a literal value, never structure,
    so no tautology can widen the result set (the SAFE control)."""
    return [row for row in _ROWS if row["name"] == q]


# ---------------------------------------------------------------------------
# Static bodies. The product page is deliberately large so the error variant
# (page + a short MySQL error line) stays under the boolean-differential's 5%
# length / 10% lexical thresholds — the error-based endpoint must NOT also read
# as a boolean-blind differential.
# ---------------------------------------------------------------------------

# ~4.5 KB of neutral product copy (no SQL/error/exposure signature strings).
_PRODUCT_FILLER = (
    "The Aurora field kit is a compact, weather-sealed carrier built for long "
    "shifts outdoors. Its modular internal dividers reshape to fit a laptop, a "
    "tablet, and a full change of layers without crushing anything soft. The "
    "outer shell is a recycled ripstop weave that sheds a passing shower and "
    "wipes clean, and the base panel is reinforced so the bag stands on its own "
    "when you set it down. Padded, breathable straps spread the load across the "
    "shoulders, a sternum clip keeps everything stable on the move, and a hidden "
    "back panel pocket keeps documents flat and close. Reviewers consistently "
    "call out the balance of capacity and comfort: enough room for a two-day "
    "trip, light enough to carry all day, and organised enough that nothing "
    "rattles loose. Thoughtful touches abound, from the quiet magnetic closures "
    "to the loop that parks a water bottle, to the soft-lined sleeve that keeps a "
    "screen from scuffing. It ships flat-packed in fully recyclable materials and "
    "is covered by a straightforward multi-year guarantee against manufacturing "
    "defects. Customers who bought this also considered the matching pouch set, "
    "the rain cover, and the compact travel organiser, each designed to slot into "
    "the same interior without adding bulk. In short, a dependable everyday "
    "companion that keeps its shape, protects what matters, and looks the part. "
) * 3

# A genuine MySQL parser error string (matches the error-signature oracle). It is
# fixed and never echoes the raw payload, so it cannot become an XSS/SSTI sink.
_MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax to use near ''' at line 1"
)

# ---------------------------------------------------------------------------
# The server-side template-evaluation model (the SSTI planted bug). A naive
# renderer EVALUATES an injected ``{{N*M}}`` / ``${N*M}`` expression and emits
# only the computed RESULT — the raw template text is consumed, never reflected.
# That is exactly what the evaluation oracle demands (result present, raw absent),
# and it keeps the sink single-class: only a template-shaped arithmetic expression
# is ever acted on, so an XSS marker, a SQL tautology, a traversal, or a quote all
# fall through to a constant render and cannot co-fire.
# ---------------------------------------------------------------------------

_SSTI_BRACES = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")
_SSTI_DOLLAR = re.compile(r"\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}")


def _eval_template(raw: str) -> str | None:
    """The deliberately-flawed template evaluator: if ``raw`` is a bare ``{{N*M}}``
    or ``${N*M}`` expression, COMPUTE it and return the product as a string (server-
    side evaluation). Anything else returns None — the caller renders a constant, so
    non-expression input is never reflected and the sink stays single-class SSTI."""
    m = _SSTI_BRACES.fullmatch(raw) or _SSTI_DOLLAR.fullmatch(raw)
    if m:
        return str(int(m.group(1)) * int(m.group(2)))
    return None


# The Server-Side Include model (the SSI planted bug, Wave-4.1, CWE-97). A naive include
# processor EVALUATES an injected ``<!--#set var="X" value="A*B" --><!--#echo var="X" -->``
# directive pair server-side, computing the arithmetic and emitting only the RESULT — the raw
# directive is consumed, never reflected. That is exactly what the SSI evaluation oracle demands
# (product present, raw directive absent), and the fullmatch keeps the sink single-class: only a
# well-formed set+echo directive pair is ever acted on, so an XSS marker, a SQL tautology, a
# template expression, a traversal, or a quote all fall through to a constant render and cannot
# co-fire. (Modelling a custom/legacy include layer that evaluates the arithmetic in a directive
# value — the EVALUATION path — NOT the shell ``<!--#exec cmd=…-->`` command form.)
_SSI_SET_ECHO = re.compile(
    r'<!--#\s*set\s+var="(?P<name>[A-Za-z_][A-Za-z0-9_]*)"\s+'
    r'value="(?P<a>\d+)\s*\*\s*(?P<b>\d+)"\s*-->'
    r'\s*<!--#\s*echo\s+var="(?P=name)"\s*-->'
)


def _eval_ssi(raw: str) -> str | None:
    """The deliberately-flawed SSI processor: if ``raw`` is a bare ``<!--#set var="X"
    value="A*B" --><!--#echo var="X" -->`` directive pair, COMPUTE ``A*B`` and return the
    product (server-side include evaluation). Anything else returns None — the caller renders a
    constant, so a non-directive payload is never reflected and the sink stays single-class SSI."""
    m = _SSI_SET_ECHO.fullmatch((raw or "").strip())
    if m:
        return str(int(m.group("a")) * int(m.group("b")))
    return None


def _page(title: str, body: str) -> bytes:
    return (
        f"<!doctype html><html><head><title>{title}</title></head>"
        f"<body>{body}</body></html>"
    ).encode("utf-8")


class BenchmarkHandler(BaseHTTPRequestHandler):
    """The deliberately-vulnerable benchmark app. One route per planted bug plus
    the SAFE controls; unknown paths 404 so the many path-signature exposure
    checks that were NOT planted cannot fire."""

    # Advertise a Java app-server so the fingerprinter marks the stack ``java`` and
    # the (stack-gated) Spring-actuator exposure check runs. sys_version="" keeps
    # the banner from also leaking "Python".
    server_version = "Jetty(9.4.z-SNAPSHOT)"
    sys_version = ""

    # -- plumbing ----------------------------------------------------------

    def log_message(self, *args: object) -> None:  # keep the target quiet
        return

    def _query(self, key: str) -> str:
        qs = urlsplit(self.path).query
        return parse_qs(qs, keep_blank_values=True).get(key, [""])[0]

    def _respond(
        self,
        status: int,
        body: bytes,
        *,
        ctype: str = "text/html; charset=utf-8",
        location: str | None = None,
        cors_reflect: bool = False,
        csp: str | None = None,
        csp_report_only: bool = False,
        extra_headers: "list[tuple[str, str]] | None" = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if location is not None:
            self.send_header("Location", location)
        # PLANTED CSP posture / bypass model (Wave 2.4) — emit the exact Content-Security-Policy the
        # route models. ``csp_report_only`` sends it as Content-Security-Policy-Report-Only (enforces
        # nothing), so the posture oracle / bypass guard can prove they never mint from a report-only
        # header. Only the /csp-* routes pass this; every other route emits no CSP header at all.
        if csp is not None:
            header = "Content-Security-Policy-Report-Only" if csp_report_only else "Content-Security-Policy"
            self.send_header(header, csp)
        for _hk, _hv in (extra_headers or []):
            self.send_header(_hk, _hv)
        # PLANTED BUG (CORS) — scoped to the ONE anchor the check probes. CORS is a
        # host-ANCHOR-level check: it sends a hostile Origin against the seed request
        # (`/`) ONLY, so the misconfiguration is planted there and nowhere else. Only
        # the index route passes ``cors_reflect=True``; every other route — in
        # particular the SAFE controls — emits NO Access-Control-Allow-Origin at all,
        # so a per-endpoint CORS report on a safe route would be flagging a bug that
        # genuinely is not there, and "anything reported on a safe endpoint is a false
        # positive by construction" holds for the CORS class too. When reflected, a
        # hostile Origin is echoed AND credentials allowed — the exact combination
        # that lets an attacker page read authenticated responses.
        if cors_reflect:
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        if body:
            self.wfile.write(body)

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = urlsplit(self.path).path.rstrip("/") or "/"
        route = _ROUTES.get(path)
        if route is None:
            self._respond(404, _page("404", "<h1>Not Found</h1>"))
            return
        route(self)

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        # State-changing surface A (the stored-XSS WRITE). Only exercised by the
        # deep-profile stored-XSS assertion through the gated write path; the
        # default GET-only benchmark crawl never reaches it, so `make gate` is
        # unaffected.
        path = urlsplit(self.path).path.rstrip("/") or "/"
        route = _POST_ROUTES.get(path)
        if route is None:
            self._respond(404, _page("404", "<h1>Not Found</h1>"))
            return
        route(self)

    # -- stored / second-order XSS (Wave 2.1) ------------------------------

    def _guestbook_write(self) -> None:
        # PLANTED BUG (stored XSS), surface A — the WRITE. Persists the posted
        # comment VERBATIM keyed by author; the payload executes later when the
        # vulnerable render surface B (/guestbook/view) renders it. This is a
        # state-changing POST — in a governed run it routes through the Wave-0.3
        # per-action approval; the benchmark handler performs the write directly
        # (the test supplies the gated-write seam).
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        fields = parse_qs(raw, keep_blank_values=True)
        author = fields.get("name", ["guest"])[0]
        comment = fields.get("comment", [""])[0]
        _GUESTBOOK[author] = comment
        self._respond(201, _page("Posted", "<p>Comment stored.</p>"))

    def _guestbook_view(self) -> None:
        # PLANTED BUG (stored XSS), render-surface B — reflects the PERSISTED
        # comment VERBATIM into an executable HTML position. Nothing is echoed from
        # THIS request (the value comes from the store written at surface A), which
        # is exactly what makes it second-order.
        author = self._query("name")
        stored = _GUESTBOOK.get(author, "")
        body = f"<h2>Guestbook</h2><div class=comment>{stored}</div>"
        self._respond(200, _page("Guestbook", body))

    def _guestbook_safe(self) -> None:
        # SAFE (stored-XSS BENIGN TWIN), render-surface B' — renders the SAME
        # persisted comment HTML-ESCAPED (a textContent-equivalent store). The
        # payload appears verbatim as inert TEXT, never as markup, so it can never
        # execute. This must NEVER fire the DOM-execution oracle.
        author = self._query("name")
        stored = html.escape(_GUESTBOOK.get(author, ""))
        body = f"<h2>Guestbook</h2><div class=comment>{stored}</div>"
        self._respond(200, _page("Guestbook", body))

    # -- CSRF achieved (Wave 3.3) ------------------------------------------

    def _csrf_post_fields(self) -> "dict[str, list[str]]":
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return parse_qs(raw, keep_blank_values=True)

    def _csrf_login(self) -> None:
        # VIGIL's OWN authenticated session. The SERVER sets the ambient session cookie WITH a SameSite
        # attribute a real browser honours: mode=none (default) is the VULNERABLE config (SameSite=None;
        # Secure — the browser SENDS it on a cross-site top-level POST); mode=strict is the DEFENDED
        # config (SameSite=Strict — the browser does NOT send it cross-site, so no CSRF is achievable).
        # 127.0.0.1/localhost are secure contexts, so Secure cookies are accepted over http loopback.
        mode = self._query("mode") or "none"
        attr = "SameSite=Strict" if mode == "strict" else "SameSite=None; Secure"
        cookie = f"{_CSRF_SESSION_COOKIE_NAME}={_CSRF_SESSION_COOKIE_VALUE}; Path=/; {attr}"
        body = _page("Login", "<p>authenticated</p>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _csrf_has_session(self) -> bool:
        # The ambient session cookie is present. A real browser attaches it to a cross-site top-level POST
        # ONLY when it was set SameSite=None (the vulnerable /csrf/login); a SameSite=Strict cookie is not
        # sent cross-site, so this returns False on the defended config and the write is rejected.
        return f"{_CSRF_SESSION_COOKIE_NAME}={_CSRF_SESSION_COOKIE_VALUE}" in (self.headers.get("Cookie", "") or "")

    def _csrf_transfer(self) -> None:
        # PLANTED BUG (CSRF achieved). The write is authorized on the ambient session cookie ALONE:
        # no anti-CSRF token, no Origin check. With the cookie the marker is applied to the
        # authoritative state; without it the write is rejected 403 (so the no-cookie control
        # reaches no state change). State-changing POST — in a governed run it routes through the
        # Wave-0.3 per-action approval; the test supplies the gated-write seam.
        if not self._csrf_has_session():
            self._respond(403, _page("Forbidden", "<p>no session</p>"))
            return
        marker = self._csrf_post_fields().get("marker", [""])[0]
        if marker:
            _CSRF_APPLIED.append(marker)
        self._respond(201, _page("Transferred", "<p>transfer applied</p>"))

    def _csrf_transfer_protected(self) -> None:
        # SAFE (CSRF BENIGN TWIN). The SAME write, but it ADDITIONALLY requires a valid anti-CSRF
        # token, so a token-less cross-site write (all VIGIL can send with only the ambient cookie)
        # is rejected — the marker never reaches the authoritative state and the oracle must NEVER
        # fire. (A SameSite=Lax cookie would ALSO not be sent cross-site; that twin is covered by the
        # oracle unit test, since SameSite is a browser behaviour a server cannot enforce.)
        if not self._csrf_has_session():
            self._respond(403, _page("Forbidden", "<p>no session</p>"))
            return
        fields = self._csrf_post_fields()
        if fields.get("csrf_token", [""])[0] != _CSRF_TOKEN_VALUE:
            self._respond(403, _page("Forbidden", "<p>bad or missing anti-CSRF token</p>"))
            return
        marker = fields.get("marker", [""])[0]
        if marker:
            _CSRF_APPLIED_PROTECTED.append(marker)
        self._respond(201, _page("Transferred", "<p>transfer applied</p>"))

    def _csrf_state(self) -> None:
        # AUTHORITATIVE post-state readback — an independent GET of the applied markers, never an echo
        # of a write request. This is the observable post-state the oracle differential reads.
        body = "<h2>state</h2><ul>" + "".join(f"<li>{html.escape(m)}</li>" for m in _CSRF_APPLIED) + "</ul>"
        self._respond(200, _page("State", body))

    def _csrf_state_protected(self) -> None:
        body = ("<h2>state</h2><ul>"
                + "".join(f"<li>{html.escape(m)}</li>" for m in _CSRF_APPLIED_PROTECTED) + "</ul>")
        self._respond(200, _page("State", body))

    # -- two-identity access control (Wave 3.1) ----------------------------

    def _account(self) -> None:
        # PLANTED BUG (IDOR / BOLA / BFLA) — a three-identity object endpoint that REQUIRES
        # authentication (a logged-out caller is denied) with BROKEN object-level authorization:
        # an authenticated session may read ANY account IN ITS OWN TENANT (it should be
        # own-account-only), so a same-tenant peer (alice) cross-reads bob's account and sees the
        # victim's UNIQUE private discriminator (its IBAN) — the achieved intra-tenant BOLA. A
        # CROSS-tenant read is correctly DENIED (403). Authentication IS required so the content is
        # authorization-GATED (not public): a no-credential baseline gets 403 with NO discriminator,
        # and a THIRD, authenticated-but-UNAUTHORIZED principal (carol, a different tenant) ALSO gets
        # 403 with NO discriminator — the round-4 same-ref unauthorized-authenticated baseline that
        # proves the IBAN is genuinely access-gated PRIVATE data, not a reflected per-object token.
        # GET-only. Unlinked from the index and never crawled by the default GET benchmark, so
        # `make gate` is byte-identical.
        acct = self._query("id") or "1"
        rec = _ACCOUNTS.get(acct)
        if rec is None:
            self._respond(404, _page("404", "<h1>No such account</h1>"))
            return
        caller = _account_caller(self.headers.get("Cookie", ""))
        if caller is None:
            # Logged-out / unknown session: authentication is required (the content is gated). No IBAN.
            self._respond(403, _page("403", "<h1>Forbidden</h1>"
                                     "<p>Standard Acme Bank statement footer.</p>"))
            return
        # BROKEN object-level authz within a tenant. A CROSS-tenant read still RENDERS the same account
        # shell (SAME SHAPE) but WITHHOLDS the private IBAN: carol (a different tenant) gets a substantive
        # 200 render of bob's account without the IBAN — the round-5 SAME-SHAPE unauthorized-authenticated
        # baseline. A reflected per-object token would appear in this same-shape render too; the IBAN does
        # not, proving it is genuinely access-gated PRIVATE data. (A 403 denial here would be a VACUOUS
        # clause-(c) control — it never renders the object — and is no longer accepted by round-5.)
        if _ACCOUNT_TENANTS.get(caller) != _ACCOUNT_TENANTS.get(acct):
            body = (f"<h2>Account {acct}</h2><p>holder={rec[0]}</p>"
                    f"<p>iban=(restricted to owner tenant)</p><p>Standard Acme Bank statement footer.</p>")
            self._respond(200, _page("Account", body))
            return
        body = (f"<h2>Account {acct}</h2><p>holder={rec[0]}</p>"
                f"<p>iban={rec[1]}</p><p>Standard Acme Bank statement footer.</p>")
        self._respond(200, _page("Account", body))

    def _account_safe(self) -> None:
        # SAFE (IDOR BENIGN TWIN) — the SAME records + the SAME shared boilerplate, but
        # object-level authz is ENFORCED: a caller reads ONLY the account its own
        # session cookie owns. An attacker (no / other cookie) requesting the victim's
        # id gets 403 with NO discriminator, so the sound check never reaches the
        # victim-unique marker and MUST NOT fire; the victim's OWN session still sees
        # its authoritative record (the ground truth the cross-read is compared to).
        acct = self._query("id") or "1"
        rec = _ACCOUNTS.get(acct)
        if rec is None:
            self._respond(404, _page("404", "<h1>No such account</h1>"))
            return
        caller = _account_caller(self.headers.get("Cookie", ""))
        if caller != acct:
            self._respond(403, _page("403", "<h1>Forbidden</h1>"
                                     "<p>Standard Acme Bank statement footer.</p>"))
            return
        body = (f"<h2>Account {acct}</h2><p>holder={rec[0]}</p>"
                f"<p>iban={rec[1]}</p><p>Standard Acme Bank statement footer.</p>")
        self._respond(200, _page("Account", body))

    # -- client-side prototype pollution (Wave 2.2) ------------------------

    def _proto(self) -> None:
        # PLANTED BUG (client-side prototype pollution). A vulnerable nested-key parser
        # merges the URL query, the fragment (location.hash) and a JSON `json=` value
        # into an object, FOLLOWING `__proto__` / `constructor.prototype` segments — so a
        # `__proto__[KEY]=VAL` gadget writes onto Object.prototype itself. The value is
        # ALSO reflected as inert text (presence) — but that is NOT what the oracle judges;
        # the oracle reads the ACHIEVED Object.prototype state via a planted binding.
        # Unlinked from the index and reached only by the deep-profile browser assertion,
        # so the default GET-only benchmark crawl (and `make gate`) never runs its JS.
        self._respond(200, _page("Proto", _PROTO_VULN_BODY))

    def _proto_safe(self) -> None:
        # SAFE (prototype-pollution BENIGN TWIN). The SAME shape, but the parser GUARDS the
        # dangerous keys (`__proto__` / `constructor` / `prototype`), and it still REFLECTS
        # the raw source text into the DOM (so the payload is PRESENT) — proving the oracle
        # fires on the ACHIEVED polluted state, never on mere presence. Object.prototype
        # stays clean, so this must NEVER fire.
        self._respond(200, _page("Proto", _PROTO_SAFE_BODY))

    # -- cross-origin postMessage achieved-exploit (Wave 2.3) --------------

    def _postmessage(self) -> None:
        # PLANTED BUG (cross-origin postMessage XSS). The handler does NOT check
        # event.origin and routes the message to an EXECUTING sink, so a gadget
        # postMessage'd from VIGIL's own attacker-origin sender (a DIFFERENT origin)
        # executes. Unlinked from the index and reached only by the deep-profile browser
        # assertion, so the default GET-only crawl (and `make gate`) never runs its JS.
        self._respond(200, _page("postMessage", _PM_VULN_BODY))

    def _postmessage_origin_checked(self) -> None:
        # SAFE (postMessage BENIGN TWIN / same-origin-only). The SAME executing sinks, but
        # the handler REJECTS any message whose origin is not its own — a cross-origin
        # sender is dropped, so this must NEVER fire the DOM-execution oracle.
        self._respond(200, _page("postMessage", _PM_ORIGIN_CHECKED_BODY))

    def _postmessage_noexec(self) -> None:
        # SAFE (postMessage BENIGN TWIN / receives-but-does-not-execute). Accepts any
        # origin but routes the message to a NON-executing sink (textContent) — it RECEIVES
        # the message (the data-leak/posture residual) but never executes it, so it must
        # NEVER fire the DOM-execution oracle.
        self._respond(200, _page("postMessage", _PM_NOEXEC_BODY))

    # -- Content-Security-Policy: achieved bypass + permissive posture (Wave 2.4) --------
    #
    # Every /csp-* route REFLECTS the `q` query param VERBATIM into an executable HTML
    # position; they differ only in the enforced CSP header. All are DELIBERATELY NOT linked
    # from the index and need a browser (bypass) or a header parse (posture), so the default
    # GET-only benchmark crawl never runs their JS and `make gate` stays byte-identical. The
    # FACT / non-fire is exercised only by the deep-profile assertion
    # (scanner/tests/test_csp_bypass_browser.py).

    def _csp_reflect_body(self) -> str:
        # reflects q verbatim into the DOM (the injection sink) — the payload the scanner
        # crafts (a nonce-carrying <script>, or an img/onerror) renders here.
        return f"<h2>CSP</h2><div id=out>{self._query('q')}</div>"

    def _csp_bypass(self) -> None:
        # PLANTED BUG (CSP bypass via a STATIC/reusable nonce). The enforced policy is
        # RESTRICTIVE (no 'unsafe-inline', no wildcard) — it purports to block arbitrary
        # inline script — BUT the script-src nonce is STATIC across responses, so an attacker
        # reads it from any response and reflects `<script nonce=CSP_STATIC_NONCE>` back in.
        # The browser sees a matching nonce and EXECUTES the injected script: a genuine bypass
        # of a restrictive policy. csp_purports_to_block is True (restrictive), so a fire is a
        # csp_bypass FACT, not plain DOM-XSS.
        self._respond(200, _page("CSP", self._csp_reflect_body()),
                      csp=f"script-src 'self' 'nonce-{CSP_STATIC_NONCE}'")

    def _csp_strict(self) -> None:
        # SAFE (CSP-bypass BENIGN TWIN / strict policy that BLOCKS). The SAME reflection sink,
        # but the enforced policy is `script-src 'self'` with NO nonce and NO 'unsafe-inline' —
        # an injected inline <script> / img-onerror carries no valid nonce, so the browser
        # BLOCKS it and nothing executes. csp_purports_to_block is True, but executed is False,
        # so this must NEVER fire the csp_bypass FACT.
        self._respond(200, _page("CSP", self._csp_reflect_body()),
                      csp="script-src 'self'")

    def _csp_none(self) -> None:
        # SAFE (for the csp_bypass class): the SAME reflection sink but NO CSP header at all.
        # An injected img-onerror EXECUTES — but with no enforced policy purporting to block it,
        # the guard adjudicates plain DOM-XSS (the dom_xss class), NOT a CSP bypass. This must
        # NEVER fire the csp_bypass FACT (execution-on-a-page-with-no-CSP is not a bypass).
        self._respond(200, _page("CSP", self._csp_reflect_body()))

    def _csp_permissive(self) -> None:
        # PLANTED permissive-CSP header (the csp_posture FACT). The enforced script-src carries
        # 'unsafe-inline' with NO neutralizing nonce/hash — a real permissive weakness a browser
        # honors. capture_csp_posture parses the retained header (no browser) and fires the
        # csp_posture FACT.
        self._respond(200, _page("CSP", self._csp_reflect_body()),
                      csp="script-src 'unsafe-inline'; object-src 'none'")

    def _csp_wellformed(self) -> None:
        # SAFE (csp_posture BENIGN TWIN / well-formed policy). A nonce-based script-src with NO
        # permissive token — the browser-hardened shape. capture_csp_posture must NOT fire.
        self._respond(200, _page("CSP", self._csp_reflect_body()),
                      csp=f"script-src 'nonce-{CSP_STATIC_NONCE}'; object-src 'none'")

    def _csp_neutralized(self) -> None:
        # SAFE (csp_posture BENIGN TWIN / nonce-neutralized 'unsafe-inline'). 'unsafe-inline'
        # BESIDE a nonce — the browser IGNORES 'unsafe-inline' per CSP3, so this is NOT a
        # weakness. capture_csp_posture honors that rule and must NOT fire.
        self._respond(200, _page("CSP", self._csp_reflect_body()),
                      csp=f"script-src 'nonce-{CSP_STATIC_NONCE}' 'unsafe-inline'")

    # -- session fixation (Wave 3.2, gated-workflow) -----------------------

    def _sessfix_cookie(self) -> str:
        """The value of the SESSION cookie the client presented (last-wins), or ''."""
        raw = self.headers.get("Cookie", "") or ""
        val = ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == _SESSFIX_COOKIE:
                val = v
        return val

    def _sessfix_user(self, body: str) -> str:
        """The username the login body authenticates (``user=<name>``), defaulting to ``admin`` — so the
        protected page can render that identity's PRIVATE datum. Any password 'succeeds' for the benchmark."""
        for part in body.replace("&", ";").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "user" and v:
                return v
        return "admin"

    def _sessfix_login(self) -> None:
        # PLANTED BUG (session fixation). On login the app BLESSES the session id the client already
        # presented — UNCHANGED — and issues NO new Set-Cookie, binding it to the authenticating USER. An
        # attacker who fixes a victim's session id before login therefore holds the VICTIM's authenticated
        # session afterward and reads the victim's PRIVATE datum (CWE-384). Reached only by the deep-profile
        # session-fixation assertion (a POST); the default GET-only crawl never touches it, so `make gate` is
        # unaffected.
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        sid = self._sessfix_cookie()
        if sid:
            _SESSFIX_SESSIONS[sid] = self._sessfix_user(body)   # client-fixed id bound to the user — NOT rotated
        self._respond(200, _page("Login", "<p>Logged in.</p>"))

    def _sessfix_rotate_login(self) -> None:
        # SAFE (session-fixation BENIGN TWIN). On login the app ROTATES the session id: it mints a FRESH id,
        # binds only the NEW id to the user, and Set-Cookies it — the client-fixed pre-auth id is NEVER
        # authenticated. This is the correct defense, so the session_fixation_oracle must NEVER fire here
        # (post-auth id != the VIGIL-fixed id, and the fixed id never reaches the user's private datum).
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        new_sid = "rot_" + secrets.token_hex(16)
        _SESSFIX_SESSIONS[new_sid] = self._sessfix_user(body)
        self._respond(200, _page("Login", "<p>Logged in.</p>"),
                      extra_headers=[("Set-Cookie", f"{_SESSFIX_COOKIE}={new_sid}; Path=/; HttpOnly")])

    def _sessfix_account(self) -> None:
        # Protected page shared by all identities. The chrome ``success_marker`` is rendered to EVERY
        # authenticated identity (it is NOT private — the exact benign credential-presence signal a marker
        # differential would false-fire on); the PER-USER PRIVATE datum is rendered ONLY for the identity the
        # presented SESSION id belongs to. A non-authenticated id gets a logged-out body. So an OTHER
        # identity's same-shape read carries the chrome marker but NOT the victim's private datum — the
        # differential the private-read reduction requires.
        sid = self._sessfix_cookie()
        user = _SESSFIX_SESSIONS.get(sid) if sid else None
        if user:
            self._respond(200, _page("Account", f"<h1>{_SESSFIX_SUCCESS_MARKER}</h1><p>Welcome back.</p>"
                                                 f"<p>{_sessfix_private(user)}</p>"))
        else:
            self._respond(200, _page("Account", "<h1>Please log in</h1><p>You are logged out.</p>"))

    # -- planted-bug routes ------------------------------------------------

    def _index(self) -> None:
        # Links carry a query so the crawler discovers each endpoint's parameter.
        links = "".join(
            f'<li><a href="{href}">{label}</a></li>'
            for href, label in (
                ("/search?q=widgets", "Search"),
                ("/users?name=guest", "User lookup"),
                ("/product?id=1", "Product"),
                ("/redirect?url=/", "Continue"),
                ("/file?name=manual.txt", "Docs"),
                ("/render?name=guest", "Dashboard"),
                ("/profile?name=guest", "Profile (safe)"),
                ("/api/health?check=all", "Health (safe)"),
                ("/download?file=manual.pdf", "Download (safe)"),
                ("/greeting?name=guest", "Greeting (safe)"),
                ("/support", "Support (safe)"),
            )
        )
        # PLANTED BUG (host-header injection): the landing page derives its canonical
        # Open-Graph URL from the incoming Host header with no allow-list, so a
        # poisoned ``Host`` becomes an absolute ``//attacker`` URL — the primitive
        # behind web-cache poisoning and password-reset-link hijacking. It is
        # confirmed by HostHeaderCheck, which is a HOST-ANCHOR-level check (it runs
        # once, against the first request seen for the host — the seed ``/``), which
        # is exactly why the sink lives on the index. It reflects only the Host header
        # (never a query value), so it cannot co-fire as XSS or open redirect, and the
        # og:url meta is not a navigable link, so the crawler does not chase it.
        host = self.headers.get("Host", "localhost")
        page = (
            "<!doctype html><html><head><title>Acme Store</title>"
            f'<meta property="og:url" content="https://{host}/">'
            "</head>"
            f"<body><h1>Acme Store</h1><ul>{links}</ul></body></html>"
        ).encode("utf-8")
        # The seed `/` is the sole anchor for the two HOST-level checks: it carries
        # both the host-header sink (og:url above) and the CORS misconfiguration
        # (cors_reflect=True) — the only route that reflects a hostile Origin. Every
        # other route leaves cors_reflect at its default False and is CORS-clean.
        self._respond(200, page, cors_reflect=True)

    def _search(self) -> None:
        # PLANTED BUG (reflected XSS): a markup-shaped search term is reflected
        # VERBATIM into an executable HTML position. The sink is only exercised for
        # values that look like markup, which keeps this a single-class XSS bug:
        # the bare-marker reflection probes (SSTI / path-traversal / error-based)
        # carry no '<', so they never reach the sink and cannot co-fire here.
        q = self._query("q")
        if "<" in q:
            body = f"<h2>Results for: {q}</h2><p>No products matched.</p>"
        else:
            body = f"<h2>Search</h2><p>Showing results for the term <b>widgets</b>.</p>"
        self._respond(200, _page("Search", body))

    def _users(self) -> None:
        # PLANTED BUG (boolean-blind SQLi): a tautology dumps every row, a benign
        # term dumps none — an observable status/length/lexical differential.
        rows = _vulnerable_match(self._query("name"))
        if not rows:
            body = "<h2>User lookup</h2><p>No results found.</p>"
        else:
            items = "".join(
                f"<li>id={r['id']} name={r['name']} role={r['role']} email={r['email']}</li>"
                for r in rows
            )
            body = f"<h2>User lookup</h2><ul>{items}</ul>"
        self._respond(200, _page("Users", body))

    def _product(self) -> None:
        # PLANTED BUG (error-based SQLi): a quote/backtick provokes a real MySQL
        # parser error. The error is embedded in the large static product page and
        # never echoes the raw input, so (a) the boolean differential stays sub-
        # threshold and (b) the page can never become an XSS/SSTI sink.
        raw = self._query("id")
        page = f"<h1>Aurora Field Kit</h1><p>{_PRODUCT_FILLER}</p>"
        if any(c in raw for c in "'\"`"):
            page += f"<!-- {_MYSQL_ERROR} -->"
        self._respond(200, _page("Product", page))

    def _redirect(self) -> None:
        # PLANTED BUG (open redirect): the `url` parameter is reflected verbatim
        # into a 302 Location with no allow-list, so an attacker can bounce a
        # victim to any external site.
        target = self._query("url") or "/"
        self._respond(302, b"", location=target)

    def _render(self) -> None:
        # PLANTED BUG (SSTI): a naive template renderer EVALUATES an injected
        # expression server-side. ``{{N*M}}`` / ``${N*M}`` is computed and only the
        # RESULT is rendered (the raw template text is consumed, not echoed), so the
        # evaluation oracle confirms a real evaluation — result present, raw absent.
        # Non-expression input renders a constant "guest", so nothing is reflected:
        # the XSS marker / SQL tautology / traversal / quote probes all fall through
        # to the same constant and cannot co-fire. Single-class SSTI by construction.
        rendered = _eval_template(self._query("name")) or "guest"
        body = f"<h1>Dashboard</h1><p>Welcome back, {rendered}.</p>"
        self._respond(200, _page("Dashboard", body))

    # -- SAFE controls (must NEVER be flagged) -----------------------------

    def _profile(self) -> None:
        # SAFE: parameterised lookup — input is bound as a literal, never reflected.
        # A tautology returns the same "Unknown user." as any other miss, and no
        # input is ever echoed, so no differential / reflection / injection fires.
        rows = _safe_match(self._query("name"))
        if not rows:
            body = "<h2>Profile</h2><p>Unknown user.</p>"
        else:
            r = rows[0]
            body = f"<h2>Profile</h2><p>Role: {r['role']}. Member in good standing.</p>"
        self._respond(200, _page("Profile", body))

    def _health(self) -> None:
        # SAFE: constant response, input ignored.
        self._respond(
            200,
            b'{"status":"ok","checks":{"db":"ok","cache":"ok"},"uptime_s":86400}',
            ctype="application/json",
        )

    def _download(self) -> None:
        # SAFE: allow-listed file names only; a traversal payload resolves to a
        # miss, and the requested name is never reflected into the response.
        allowed = {"manual.pdf", "spec-sheet.pdf", "warranty.pdf"}
        if self._query("file") in allowed:
            body = b"%PDF-1.4 (binary content elided for the benchmark)"
            self._respond(200, body, ctype="application/pdf")
        else:
            self._respond(404, _page("Download", "<h2>Download</h2><p>File not found.</p>"))

    def _greeting(self) -> None:
        # SAFE (SSTI twin): an auto-escaping template — the user value is rendered
        # as DATA, never evaluated. It echoes the input HTML-escaped inside a large
        # static page, so ``{{7331*7331}}`` appears VERBATIM (the evaluation oracle's
        # rule #2: raw present -> not evaluation) and its computed value 53743561
        # never appears. The escaped echo cannot become an XSS sink (inert, encoded)
        # and the constant filler keeps benign-vs-probe length/lexical deltas below
        # the boolean-differential thresholds. The false-positive ruler for SSTI.
        name = html.escape(self._query("name"))
        body = f"<h1>Greeting</h1><p>Hello, {name}.</p><p>{_PRODUCT_FILLER}</p>"
        self._respond(200, _page("Greeting", body))

    def _ssi(self) -> None:
        # PLANTED BUG (SSI, CWE-97): a naive server-side include processor EVALUATES an injected
        # ``<!--#set var="X" value="A*B" --><!--#echo var="X" -->`` directive pair server-side,
        # computing the arithmetic and emitting only the RESULT (the raw directive is consumed, not
        # echoed), so the SSI evaluation oracle confirms a real evaluation — product present, raw
        # directive absent. Non-directive input renders a constant "index", so nothing is reflected:
        # the XSS marker / SQL tautology / SSTI expression / traversal / quote probes all fall through
        # to the same constant and cannot co-fire. Single-class SSI by construction (DELIBERATELY NOT
        # linked from the index, so the default GET crawl never reaches it and `make gate` is
        # byte-identical; exercised only by the gated SSI re-drive, integration/tests/test_ssi_redrive.py).
        rendered = _eval_ssi(self._query("doc")) or "index"
        body = f"<h1>Included document</h1><p>{rendered}</p>"
        self._respond(200, _page("Include", body))

    def _ssi_safe(self) -> None:
        # SAFE (SSI twin): SSI is DISABLED — a well-formed include directive is echoed VERBATIM into
        # the body as an INERT HTML comment (never processed). The raw ``<!--#…-->`` survives (the SSI
        # oracle's rule #3: raw present -> reflected, not evaluated -> conclusive clean) and its
        # computed product never appears. To avoid being any OTHER sink, only a well-formed set+echo
        # directive is reflected; every other input renders the constant "index" (so it is never a
        # reflected-XSS sink), and the filler keeps benign-vs-probe deltas below the differential
        # thresholds. The false-positive ruler for SSI — a page that reflects but does NOT evaluate.
        doc = self._query("doc")
        shown = doc if _SSI_SET_ECHO.fullmatch(doc.strip()) else "index"
        body = f"<h1>Included document</h1><p>{shown}</p><p>{_PRODUCT_FILLER}</p>"
        self._respond(200, _page("Include", body))

    def _support(self) -> None:
        # SAFE (ordinary benign page): a static page whose single absolute link points
        # at a FIXED, configured host. Its false-positive value is for the PARAM-LEVEL
        # checks — a clean crawled route with an absolute URL that a tool must not flag
        # as open-redirect, XSS, or injection. It is deliberately NOT called a
        # host-header "twin": host-header (like CORS) is a host-ANCHOR check that
        # probes ONLY the seed `/`, so it never re-probes this route and a per-endpoint
        # safe twin for it would carry no measured signal. The correct fixed-host
        # handling shown here is documentation of the safe pattern, not a discriminator.
        body = (
            "<h2>Support</h2>"
            '<p>Contact us at <a href="https://acme.example/support">support</a>.</p>'
        )
        self._respond(200, _page("Support", body))

    def _file(self) -> None:
        # PLANTED BUG (path traversal): a traversal escapes the document directory
        # and reads an arbitrary file. It returns the FILE CONTENT and never
        # reflects the raw path, so ONLY a real file-content signature
        # (``root:x:0:0:``) confirms it — a marker-reflection probe learns nothing
        # here (which is why the content-signature check is the one that catches
        # it). A benign name yields an ordinary document with no reflection.
        name = self._query("name")
        # A pure path-traversal sink joins the name onto a base dir and opens it, so
        # a filesystem traversal reads the file but a scheme wrapper (file://, php://)
        # does NOT — the benchmark plants exactly one traversal bug, not a scheme LFI.
        if "://" not in name and ("etc/passwd" in name or name.rstrip("/").endswith("passwd")):
            body = (
                b"root:x:0:0:root:/root:/bin/bash\n"
                b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            )
            self._respond(200, body, ctype="text/plain; charset=utf-8")
        else:
            self._respond(200, _page("Document", "<h2>Document</h2><p>The requested manual page.</p>"))

    # -- exposure routes (leak their signature) ----------------------------

    def _git_config(self) -> None:
        # PLANTED BUG (exposure): a deployed .git/config exposes repo metadata.
        body = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "[remote \"origin\"]\n"
            "\turl = https://git.internal.example/acme/store.git\n"
        ).encode("utf-8")
        self._respond(200, body, ctype="text/plain; charset=utf-8")

    def _env(self) -> None:
        # PLANTED BUG (exposure): a served .env leaks database credentials. It
        # carries DB_PASSWORD but NOT APP_KEY, so exactly one .env signature check
        # (m5-fw-env-dbpass) fires — the manifest counts one .env exposure.
        body = (
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            "DB_CONNECTION=mysql\n"
            "DB_HOST=10.0.3.12\n"
            "DB_DATABASE=acme_store\n"
            "DB_USERNAME=acme\n"
            "DB_PASSWORD=s3cr3t-prod-db-pw\n"
        ).encode("utf-8")
        self._respond(200, body, ctype="text/plain; charset=utf-8")

    def _actuator_env(self) -> None:
        # PLANTED BUG (exposure): an unauthenticated Spring Actuator /env dumps the
        # property sources (secrets). Signature: "propertySources". Stack-gated on
        # java, satisfied by the Jetty Server banner above.
        body = json.dumps({
            "activeProfiles": ["production"],
            "propertySources": [
                {"name": "systemEnvironment",
                 "properties": {"DB_PASSWORD": {"value": "s3cr3t-prod-db-pw"}}},
                {"name": "applicationConfig",
                 "properties": {"spring.datasource.url": {"value": "jdbc:mysql://10.0.3.12/acme"}}},
            ],
        }).encode("utf-8")
        self._respond(200, body, ctype="application/json")


# Path -> handler method. Everything else 404s (so the un-planted path-signature
# exposure checks — /.git/HEAD, /actuator/health, /swagger.json, ... — do not fire).
_ROUTES = {
    "/": BenchmarkHandler._index,
    "/search": BenchmarkHandler._search,
    "/users": BenchmarkHandler._users,
    "/product": BenchmarkHandler._product,
    "/redirect": BenchmarkHandler._redirect,
    "/render": BenchmarkHandler._render,
    "/profile": BenchmarkHandler._profile,
    "/api/health": BenchmarkHandler._health,
    "/download": BenchmarkHandler._download,
    "/greeting": BenchmarkHandler._greeting,
    "/support": BenchmarkHandler._support,
    "/file": BenchmarkHandler._file,
    "/.git/config": BenchmarkHandler._git_config,
    "/.env": BenchmarkHandler._env,
    "/actuator/env": BenchmarkHandler._actuator_env,
    # Stored-XSS render surfaces (Wave 2.1). DELIBERATELY NOT linked from the index
    # and served over an EMPTY store during the default crawl, so the default GET
    # benchmark (and `make gate`) never produces a finding here.
    "/guestbook/view": BenchmarkHandler._guestbook_view,
    "/guestbook/safe": BenchmarkHandler._guestbook_safe,
    # Client-side prototype-pollution pages (Wave 2.2). DELIBERATELY NOT linked from the
    # index; the default GET-only crawl never runs their client JS (no browser), so the
    # default corpus + signed baseline stay byte-identical.
    "/proto": BenchmarkHandler._proto,
    "/proto/safe": BenchmarkHandler._proto_safe,
    # Cross-origin postMessage achieved-exploit pages (Wave 2.3). DELIBERATELY NOT linked
    # from the index; the default GET-only crawl never runs their client JS (no browser, and
    # a fire needs VIGIL's cross-origin sender), so the default corpus + signed baseline stay
    # byte-identical.
    "/postmessage": BenchmarkHandler._postmessage,
    "/postmessage/origin-checked": BenchmarkHandler._postmessage_origin_checked,
    "/postmessage/noexec": BenchmarkHandler._postmessage_noexec,
    # Content-Security-Policy pages (Wave 2.4). DELIBERATELY NOT linked from the index; the
    # default GET-only crawl never runs their JS (bypass needs a browser) and never parses their
    # CSP posture, so the default corpus + signed baseline stay byte-identical. /csp-bypass is the
    # achieved bypass (static-nonce reuse under a restrictive policy); /csp-strict and /csp-none
    # are its benign twins (strict-blocks / no-CSP-so-plain-DOM-XSS); /csp-permissive is the
    # posture FACT; /csp-wellformed and /csp-neutralized are the posture benign twins.
    "/csp-bypass": BenchmarkHandler._csp_bypass,
    "/csp-strict": BenchmarkHandler._csp_strict,
    "/csp-none": BenchmarkHandler._csp_none,
    "/csp-permissive": BenchmarkHandler._csp_permissive,
    "/csp-wellformed": BenchmarkHandler._csp_wellformed,
    "/csp-neutralized": BenchmarkHandler._csp_neutralized,
    # CSRF-achieved authoritative post-state readbacks + VIGIL's session-login (Wave 3.3).
    # DELIBERATELY NOT linked from the index; the default GET-only crawl reaches these but the
    # state routes render an EMPTY applied state (no write is ever POSTed by the default crawl)
    # and the login route only Set-Cookies, so no finding is produced and the default corpus +
    # signed baseline stay byte-identical.
    "/csrf/login": BenchmarkHandler._csrf_login,
    "/csrf/state": BenchmarkHandler._csrf_state,
    "/csrf/state-protected": BenchmarkHandler._csrf_state_protected,
    # Two-identity access-control object endpoints (Wave 3.1). DELIBERATELY NOT linked
    # from the index; a fire needs the operator-supplied SECOND identity + per-identity
    # discriminator, which the default GET-only crawl never supplies, so the default
    # corpus + signed baseline stay byte-identical.
    "/account": BenchmarkHandler._account,
    "/account/safe": BenchmarkHandler._account_safe,
    # Session-fixation protected page (Wave 3.2). DELIBERATELY NOT linked from the index and reached only by
    # the deep-profile gated session-fixation assertion (which first POSTs a login); the default GET-only
    # crawl only ever sees a logged-out page here, so the default corpus + signed baseline stay byte-identical.
    "/sessfix/account": BenchmarkHandler._sessfix_account,
    # Server-Side Includes (SSI, CWE-97) pages (Wave 4.1). DELIBERATELY NOT linked from the index; the SSI
    # sink acts ONLY on a well-formed <!--#set…--><!--#echo…--> directive pair (which the default GET crawl
    # never sends) and renders a constant otherwise, so the default corpus + signed baseline stay
    # byte-identical. /ssi is the planted evaluation FACT; /ssi/safe is the benign twin (SSI disabled — the
    # directive is echoed verbatim as an inert comment). Exercised by integration/tests/test_ssi_redrive.py.
    "/ssi": BenchmarkHandler._ssi,
    "/ssi/safe": BenchmarkHandler._ssi_safe,
}


# POST surfaces (state-changing writes). Only the stored-XSS write surface A; the
# default GET-only benchmark crawl never issues a POST, so this leaves `make gate`
# byte-identical.
_POST_ROUTES = {
    "/guestbook": BenchmarkHandler._guestbook_write,
    # CSRF-achieved state-changing writes (Wave 3.3). The default GET-only benchmark crawl never
    # issues a POST, so these leave `make gate` byte-identical; exercised only by the deep-profile
    # scanner/tests/test_csrf_achieved.py through the cross-site cookie / no-cookie differential.
    "/csrf/transfer": BenchmarkHandler._csrf_transfer,
    "/csrf/transfer-protected": BenchmarkHandler._csrf_transfer_protected,
    # Session-fixation login flows (Wave 3.2). Only exercised by the deep-profile gated assertion; the
    # default GET-only benchmark crawl never issues a POST, so this leaves `make gate` byte-identical.
    "/sessfix/login": BenchmarkHandler._sessfix_login,           # VULNERABLE: keeps the client-fixed id
    "/sessfix/rotate/login": BenchmarkHandler._sessfix_rotate_login,   # SAFE TWIN: rotates the id at login
}


# ---------------------------------------------------------------------------
# Ground-truth manifest
# ---------------------------------------------------------------------------


def benchmark_corpus(base_url: str) -> CorpusTarget:
    """The complete, honest ground truth for the benchmark app.

    Locations are written in CRUCIBLE's vocabulary so the comparative scorer lines
    a produced finding up with its label: param-level bugs as ``path?param`` (the
    scorer's path+param fallback matches CRUCIBLE's param-level location), and the
    two host/endpoint-level classes (CORS, exposures) as the ``request:<check-id>``
    token CRUCIBLE emits for a request-level finding.

    Eleven planted bugs; the five SAFE endpoints (``/profile``, ``/api/health``,
    ``/download``, ``/greeting``, ``/support``) are intentionally absent — anything a
    tool reports on them is a false positive by construction."""
    expected = [
        ExpectedFinding(bug_class="xss", location="/search?q"),
        ExpectedFinding(bug_class="boolean_sqli", location="/users?name"),
        ExpectedFinding(bug_class="error_based_sqli", location="/product?id"),
        ExpectedFinding(bug_class="open_redirect", location="/redirect?url"),
        ExpectedFinding(bug_class="path_traversal", location="/file?name"),
        ExpectedFinding(bug_class="ssti", location="/render?name"),
        ExpectedFinding(bug_class="host_header_injection", location="request:host-header"),
        ExpectedFinding(bug_class="cors", location="request:cors-active"),
        ExpectedFinding(bug_class="exposure", location="request:m5-fw-git-config"),
        ExpectedFinding(bug_class="exposure", location="request:m5-fw-env-dbpass"),
        ExpectedFinding(bug_class="exposure", location="request:m5-fw-spring-actuator-env"),
    ]
    return CorpusTarget(
        name="crucible-benchmark-app",
        base_url=base_url,
        expected=expected,
        notes=(
            "Self-contained labelled benchmark: reflected XSS, boolean-blind SQLi, "
            "error-based SQLi, open redirect, path traversal, SSTI (server-side "
            "template evaluation), host-header injection, CORS-with-credentials, and "
            "three exposures (.git/config, .env, Spring /actuator/env), plus five SAFE "
            "controls (/profile, /api/health, /download, /greeting, /support) that "
            "must not be flagged."
        ),
    )


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def serve() -> Iterator[str]:
    """Run the benchmark app on ``127.0.0.1:<ephemeral>`` for the duration of the
    block, yielding its base URL and shutting it down cleanly on exit."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="benchmark-app", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
