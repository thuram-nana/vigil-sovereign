"""
M2c — XSS-context breadth as data, confirmed by the context-aware oracle.

The ``m2-xss-*`` library entries (``library_entries/m2_xss_*.json``) each carry a
real XSS breakout payload with a ``{marker}`` placeholder and compile to a
``MarkerReflectionCheck`` whose ``bug_class: "xss"`` routes confirmation to the
CONTEXT-AWARE ``reflection_context_oracle`` — which fires ONLY when the planted
marker reaches an executable position (a new tag name, an event-handler / JS-URL
attribute, or inside ``<script>``), never when it is HTML-encoded or lands inert.

This suite proves the whole path, and — crucially — the PRECISION property:

  * every entry loads/validates, is uniquely id'd, and compiles to the reflection
    check with the reflection-context oracle in its routed set;
  * against a loopback fixture that reflects the query value RAW into the context
    the payload was designed to break out of, a representative subset CONFIRMS via
    ``confirm_finding`` + ``OracleVerifier`` (``confirmed_by == reflection_context``),
    spanning html_tag / event-handler-attribute / script contexts;
  * against a twin fixture that HTML-ENCODES the same reflection, those entries do
    NOT confirm — reflect-but-encode is not XSS (the false-positive Burp's
    substring XSS heuristics produce and this oracle refuses);
  * NO entry fires when the marker lands inside an HTML comment or as plain
    encoded text.

Design note (oracle scope, verified empirically): HTML-entity encoding is the
correct defense — and therefore a clean encoded-negative — only for contexts a
payload BREAKS INTO via markup metacharacters (``<``/``>``/quote). For a URL
attribute (``javascript:``), an unquoted attribute (space delimiter), or a JS
string already inside ``<script>``, entity-encoding the usual metacharacters does
NOT neutralize the payload, so those entries assert the RAW confirm plus the
comment / plain-encoded-text negatives, but not a same-context encoded negative.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

from framework.v2.scanner.checks import Check, MarkerReflectionCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import LibraryEntry, compile_entry, load_library
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES, OracleVerifier, normalize_bug_class

M2_PREFIX = "m2-xss-"


# ---------------------------------------------------------------------------
# entry selection helpers
# ---------------------------------------------------------------------------


def _all_entries() -> list[LibraryEntry]:
    return load_library()


def _m2_entries() -> list[LibraryEntry]:
    return [e for e in _all_entries() if e.id.startswith(M2_PREFIX)]


def _by_id(entry_id: str) -> LibraryEntry:
    return next(e for e in _m2_entries() if e.id == entry_id)


# ---------------------------------------------------------------------------
# reflecting loopback fixtures — each reflects ?q=<payload> RAW or HTML-ENCODED
# into a specific HTML context, so a payload is exercised where it breaks out.
# ---------------------------------------------------------------------------


def _enc(s: str) -> str:
    """The context-neutral HTML entity encoding a safe app applies: the negative
    control. Encodes & < > " ' — leaves the marker itself intact so the oracle
    still SEES a reflection, but an inert one."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


# raw context renderers (value spliced verbatim)
def _text_raw(v: str) -> str:
    return f"<html><body><h1>Search</h1><div>{v}</div></body></html>"


def _dq_raw(v: str) -> str:
    return f'<html><body><input type="text" name="q" value="{v}"></body></html>'


def _sq_raw(v: str) -> str:
    return f"<html><body><input type='text' name='q' value='{v}'></body></html>"


def _uq_raw(v: str) -> str:
    return f"<html><body><input type=text name=q value={v}></body></html>"


def _href_raw(v: str) -> str:
    return f'<html><body><a href="{v}">continue</a></body></html>'


def _script_raw(v: str) -> str:
    return f"<html><body><script>var q = '{v}';</script></body></html>"


def _script_bslash_raw(v: str) -> str:
    """The server that escapes the QUOTE but not the BACKSLASH — the context the
    ``\\';…//`` statement-break payload is actually designed for.

    The plain ``_script_raw`` splice is NOT vulnerable to that payload, and that is
    a fact, not an opinion: node evaluates ``var q = '\\';vigMARKER//';`` to the
    STRING ``';vigMARKER//`` — no injection. The entry used to "confirm" against
    ``_script_raw`` only because the reflection oracle fired on mere PRESENCE of the
    marker inside a ``<script>`` (audit F4), so that fixture was modelling an UNSOUND
    detection. Here the input's ``'`` is escaped to ``\\'``, so the payload's leading
    backslash pairs with it, the literal closes, and the marker lands at CODE
    position — which node confirms executes."""
    return _script_raw(v.replace("'", "\\'"))


# encoded twins (same context, value HTML-entity-encoded)
def _text_enc(v: str) -> str:
    return _text_raw(_enc(v))


def _dq_enc(v: str) -> str:
    return _dq_raw(_enc(v))


def _sq_enc(v: str) -> str:
    return _sq_raw(_enc(v))


# universal negatives
def _comment(v: str) -> str:
    return f"<html><body><!-- last query: {v} --></body></html>"


def _plain_encoded_text(v: str) -> str:
    return _text_enc(v)


Render = Callable[[str], str]


def _handler(render: Render) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:  # keep the fixture quiet
            return

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            body = render(q).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return H


@contextlib.contextmanager
def _server(render: Render) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler(render))
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _send(req: HttpRequest) -> dict:
    with urllib.request.urlopen(req.url, timeout=10) as r:  # noqa: S310 (loopback)
        return {"status": r.status, "body": r.read().decode("utf-8", "replace")}


def _q_point(base: str) -> tuple[RequestTemplate, object]:
    tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/search?q=x"))
    point = next(
        p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q"
    )
    return tpl, point


def _confirm(check: Check, render: Render):
    """Drive `check` against a live fixture rendering `render`; return the
    ConfirmedFinding or None through the real oracle authority."""
    with _server(render) as base:
        tpl, point = _q_point(base)
        ctx = check.probe(tpl, point, _send)
    if ctx is None:
        return None
    return confirm_finding(
        finding={"bug_class": check.bug_class, "title": "t", "severity": "High",
                 "surface": "GET /search?q=", "summary": "x"},
        context=ctx,
        verifier=OracleVerifier(),
    )


def _reflection_context(confirmed) -> str | None:
    for s in confirmed.signals:
        if s.kind is OracleKind.REFLECTION_CONTEXT and s.fired:
            return str(s.observed.get("context"))
    return None


# ---------------------------------------------------------------------------
# the case table: entry -> (raw renderer, clean same-context encoded twin | None)
# clean encoded twin present only where HTML-entity-encoding IS the correct
# defense (markup-metacharacter breakouts). url / unquoted / script-string
# entries have None: entity-encoding does not neutralize them (security truth),
# so they get only the comment / plain-encoded-text negatives.
# ---------------------------------------------------------------------------

CASES: list[tuple[str, Render, Render | None]] = [
    # text-context breakouts (need <,> — entity-encoding neutralizes)
    ("m2-xss-tag-svg-onload", _text_raw, _text_enc),
    ("m2-xss-tag-img-onerror", _text_raw, _text_enc),
    ("m2-xss-tag-body-onload", _text_raw, _text_enc),
    ("m2-xss-tag-details-ontoggle", _text_raw, _text_enc),
    ("m2-xss-tag-textarea-newtag", _text_raw, _text_enc),
    ("m2-xss-script-title-close", _text_raw, _text_enc),
    ("m2-xss-script-svg-nested", _text_raw, _text_enc),
    ("m2-xss-script-close-reopen", _text_raw, _text_enc),
    # double-quoted attribute breakouts (need " — entity-encoding neutralizes)
    ("m2-xss-attr-dq-onmouseover", _dq_raw, _dq_enc),
    ("m2-xss-attr-dq-autofocus-onfocus", _dq_raw, _dq_enc),
    ("m2-xss-attr-dq-src-onerror", _dq_raw, _dq_enc),
    # single-quoted attribute breakout (need ' — entity-encoding neutralizes)
    ("m2-xss-attr-sq-onmouseover", _sq_raw, _sq_enc),
    # unquoted attribute breakouts (space delimiter — NOT entity-encodable)
    ("m2-xss-attr-unquoted-onmouseover", _uq_raw, None),
    ("m2-xss-attr-unquoted-autofocus-onfocus", _uq_raw, None),
    # javascript: URI in a URL attribute (scheme — NOT entity-encodable)
    ("m2-xss-jsurl-href", _href_raw, None),
    # JS string inside an existing <script> (needs JS-encoding, NOT entity)
    ("m2-xss-script-string-break", _script_raw, None),
    # statement-break: needs the quote-escaping (backslash-unescaping) server — see
    # _script_bslash_raw. Against the verbatim splice this payload does NOT break out.
    ("m2-xss-script-string-stmt", _script_bslash_raw, None),
]

_CASE_IDS = [c[0] for c in CASES]
_CLEAN_NEG = [(cid, raw, enc) for cid, raw, enc in CASES if enc is not None]


# ---------------------------------------------------------------------------
# load + validate
# ---------------------------------------------------------------------------


def test_whole_library_loads_and_includes_m2_xss() -> None:
    entries = _all_entries()
    assert entries, "library failed to load"
    m2 = [e for e in entries if e.id.startswith(M2_PREFIX)]
    assert 12 <= len(m2) <= 18, f"expected 12-18 m2-xss entries, got {len(m2)}"


def test_case_table_covers_every_shipped_entry() -> None:
    # the test's case table and the shipped entries must be in lockstep, so no
    # entry ships untested and no test references a removed entry.
    shipped = {e.id for e in _m2_entries()}
    tabled = set(_CASE_IDS)
    assert shipped == tabled, f"drift: shipped-only={shipped - tabled}, table-only={tabled - shipped}"


def test_m2_xss_ids_unique_prefixed_and_globally_unique() -> None:
    m2 = _m2_entries()
    ids = [e.id for e in m2]
    assert len(ids) == len(set(ids)), "duplicate m2-xss ids"
    assert all(i.startswith(M2_PREFIX) for i in ids)
    all_ids = [e.id for e in _all_entries()]
    assert len(all_ids) == len(set(all_ids)), "m2-xss ids collide with existing library entries"


def test_m2_xss_entries_are_rich_and_well_formed() -> None:
    for e in _m2_entries():
        assert e.bug_class == "xss", e.id
        assert e.title, e.id
        assert e.severity == "High", f"{e.id} must be High"
        assert e.applies_when == {"always": True}, f"{e.id} XSS is stack-agnostic — default always"
        assert "CWE-79" in e.references, f"{e.id} must cite CWE-79"
        assert e.remediation, f"{e.id} carries no remediation"
        assert "CSP" in e.remediation or "Content-Security-Policy" in e.remediation, e.id
        assert e.payload_family, f"{e.id} carries no payload_family"


def test_m2_xss_context_breadth() -> None:
    families = {e.payload_family for e in _m2_entries()}
    # distinct breakout contexts, not just distinct payloads
    expected = {
        "html-tag-breakout",
        "html-element-event-handler",
        "script-element-injection",
        "attribute-breakout-double-quote",
        "attribute-breakout-single-quote",
        "attribute-breakout-unquoted",
        "javascript-uri",
        "script-string-breakout",
    }
    assert expected <= families, f"missing breakout families: {expected - families}"


# ---------------------------------------------------------------------------
# compile + route: every entry is a reflection check whose class routes to the
# context-aware oracle (never a dud that cannot confirm)
# ---------------------------------------------------------------------------


def test_every_m2_xss_compiles_to_marker_reflection() -> None:
    for e in _m2_entries():
        check = compile_entry(e)
        assert isinstance(check, MarkerReflectionCheck), e.id
        assert check.id == e.id
        assert check.bug_class == "xss", e.id
        assert e.oracle.kind == "reflection", e.id
        assert "{marker}" in check.payload_template, e.id


def test_m2_xss_routes_to_reflection_context_oracle() -> None:
    v = OracleVerifier()
    for e in _m2_entries():
        key = normalize_bug_class(e.bug_class)
        assert key in BUG_CLASS_ORACLES, f"{e.id}: bug_class not routed"
        kinds = v.oracles_for(e.bug_class)
        assert OracleKind.REFLECTION_CONTEXT in kinds, e.id
        # xss routes to the CONTEXT-AWARE oracle only (not substring side-effect)
        assert kinds == (OracleKind.REFLECTION_CONTEXT,), f"{e.id}: unexpected routing {kinds}"


# ---------------------------------------------------------------------------
# end-to-end: raw reflection into the intended context CONFIRMS via the oracle
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry_id, raw_render, _enc_render", CASES, ids=_CASE_IDS)
def test_raw_reflection_confirms_via_reflection_context(
    entry_id: str, raw_render: Render, _enc_render: Render | None
) -> None:
    check = compile_entry(_by_id(entry_id))
    confirmed = _confirm(check, raw_render)
    assert confirmed is not None, f"{entry_id} did not confirm on its raw-reflection fixture"
    assert confirmed.confirmed_by is OracleKind.REFLECTION_CONTEXT
    assert confirmed.confirmed_by.value == "reflection_context"
    ctx = _reflection_context(confirmed)
    assert ctx in ("html_tag", "script") or (ctx or "").startswith("js_attribute"), (
        f"{entry_id} confirmed in unexpected context {ctx!r}"
    )


def test_representative_subset_spans_distinct_executable_contexts() -> None:
    # >= 6 entries spanning html_tag / event-handler-attribute / script, proving
    # breadth of breakout, not one lucky payload.
    subset = [
        "m2-xss-tag-textarea-newtag",   # html_tag
        "m2-xss-tag-svg-onload",        # js_attribute:onload
        "m2-xss-tag-img-onerror",       # js_attribute:onerror
        "m2-xss-script-close-reopen",   # script
        "m2-xss-attr-dq-onmouseover",   # js_attribute:onmouseover (dq attr)
        "m2-xss-attr-sq-onmouseover",   # js_attribute:onmouseover (sq attr)
    ]
    contexts: set[str] = set()
    for entry_id in subset:
        raw_render = next(raw for cid, raw, _ in CASES if cid == entry_id)
        confirmed = _confirm(compile_entry(_by_id(entry_id)), raw_render)
        assert confirmed is not None, entry_id
        ctx = _reflection_context(confirmed) or ""
        contexts.add("js_attribute" if ctx.startswith("js_attribute") else ctx)
    assert {"html_tag", "js_attribute", "script"} <= contexts, contexts


# ---------------------------------------------------------------------------
# PRECISION: HTML-encoding the SAME reflection does NOT confirm (reflect-but-
# encode is not XSS) — for the contexts where entity-encoding is the right fix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry_id, _raw_render, enc_render",
    _CLEAN_NEG,
    ids=[c[0] for c in _CLEAN_NEG],
)
def test_encoded_reflection_does_not_confirm(
    entry_id: str, _raw_render: Render, enc_render: Render
) -> None:
    check = compile_entry(_by_id(entry_id))
    assert _confirm(check, enc_render) is None, (
        f"{entry_id} false-positived on an HTML-ENCODED reflection (reflect-but-encode is not XSS)"
    )


# ---------------------------------------------------------------------------
# universal negatives: NO entry fires inside an HTML comment or as plain
# encoded text — true for EVERY shipped entry, including url/unquoted/script
# ones whose same-context encoded twin is (correctly) not a clean negative.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry_id", _CASE_IDS)
def test_no_entry_confirms_inside_html_comment(entry_id: str) -> None:
    check = compile_entry(_by_id(entry_id))
    assert _confirm(check, _comment) is None, f"{entry_id} fired inside an HTML comment"


@pytest.mark.parametrize("entry_id", _CASE_IDS)
def test_no_entry_confirms_on_plain_encoded_text(entry_id: str) -> None:
    check = compile_entry(_by_id(entry_id))
    assert _confirm(check, _plain_encoded_text) is None, (
        f"{entry_id} fired on a plain HTML-encoded text reflection"
    )


# ---------------------------------------------------------------------------
# PRECISION (audit F4/R5): the oracle must NOT confirm where the page escaped
# correctly — the two shapes that used to mint a High xss FACT.
# ---------------------------------------------------------------------------


def _json_script_safe(v: str) -> str:
    """Django ``json_script`` / Rails ``json_escape``: JSON-encode, then escape the
    markup metacharacters as ``\\uXXXX`` so nothing in the value can terminate the
    element or the literal. The canonical CORRECT way to hand a value to JS."""
    import json as _json

    lit = (_json.dumps(v).replace("<", "\\u003c").replace(">", "\\u003e")
           .replace("&", "\\u0026").replace("/", "\\/"))
    return ("<html><body><div id=app></div>"
            f"<script>window.__BOOTSTRAP__ = {{\"query\": {lit}}};</script></body></html>")


def _quot_escaped_handler(v: str) -> str:
    """A handler the PAGE composed, with the value correctly ``&quot;``-escaped into
    it. HTML attribute values are entity-decoded unconditionally, so the marker
    reaches the ``on*`` value as DATA — it did not break out."""
    return f'<html><body><button onclick="search(&quot;{_enc(v)}&quot;)">go</button></body></html>'


def _json_data_block(v: str) -> str:
    """A ``type="application/json"`` block: the browser never executes it."""
    return f'<html><body><script type="application/json">{{"q": "{v}"}}</script></body></html>'


def _noscript_container(v: str) -> str:
    """Raw-text container: ``<xMARKER>`` here is inert text, not a live element."""
    return f"<html><body><noscript>{v}</noscript></body></html>"


_ALL_BUT_CONTAINER_BREAKERS = (
    "m2-xss-tag-svg-onload", "m2-xss-tag-img-onerror", "m2-xss-script-string-break",
    "m2-xss-attr-dq-onmouseover", "m2-xss-jsurl-href",
)

@pytest.mark.parametrize(
    "render, entries, why",
    [
        (_json_script_safe, _ALL_BUT_CONTAINER_BREAKERS + ("m2-xss-tag-textarea-newtag",),
         "json_script JS-string escaping"),
        (_quot_escaped_handler, _ALL_BUT_CONTAINER_BREAKERS + ("m2-xss-tag-textarea-newtag",),
         "&quot;-escaped page-composed handler"),
        (_json_data_block, _ALL_BUT_CONTAINER_BREAKERS + ("m2-xss-tag-textarea-newtag",),
         "non-executable application/json script"),
        # NOTE the entry set here EXCLUDES m2-xss-tag-textarea-newtag on purpose: its
        # payload OPENS with `</textarea></noscript>`, so it genuinely escapes the
        # container and SHOULD still confirm — see the companion assertion below.
        (_noscript_container, _ALL_BUT_CONTAINER_BREAKERS, "raw-text <noscript> container"),
    ],
    ids=["json_script", "quot_escaped_handler", "json_data_block", "noscript"],
)
def test_correctly_escaped_pages_never_confirm_xss(
    render: Render, entries: tuple[str, ...], why: str
) -> None:
    for entry_id in entries:
        confirmed = _confirm(compile_entry(_by_id(entry_id)), render)
        assert confirmed is None, f"{entry_id} minted a FACT against {why}"


def test_container_escaping_payload_still_confirms_out_of_noscript() -> None:
    # the precision fix must not cost a real detection: a payload that CLOSES the
    # raw-text container genuinely reaches live markup and must still confirm.
    confirmed = _confirm(compile_entry(_by_id("m2-xss-tag-textarea-newtag")), _noscript_container)
    assert confirmed is not None
    assert confirmed.confirmed_by is OracleKind.REFLECTION_CONTEXT


# ---------------------------------------------------------------------------
# RED-PEN B1 (END-TO-END) — the lexer desync, through confirm_finding +
# OracleVerifier, against a live loopback page.
#
# `_json_script_safe` above is the canonical CORRECT defence and the suite already
# asserts it never confirms. Add ONE benign regex literal containing an apostrophe
# — `/(\w+)'s\b/g`, the sort of thing a real page carries to render possessives —
# and the whole assertion collapsed: MEASURED on 1ccd18a5, 4 of the 17 m2 entries
# minted a High xss FACT at conf 0.90 through the full authority, certificate
# evidence reading "injection into an executable position PROVEN". It was not
# proven. The apostrophe opened a phantom string state and the opening quote of the
# JSON literal closed it, putting the escaped value at apparent code position.
# ---------------------------------------------------------------------------


def _json_script_safe_with_regex(v: str) -> str:
    """`_json_script_safe` plus ONE benign possessive-matching regex ahead of it.
    The page is exactly as SAFE as its twin: nothing in the value can terminate the
    element or the literal."""
    import json as _json

    lit = (_json.dumps(v).replace("<", "\\u003c").replace(">", "\\u003e")
           .replace("&", "\\u0026").replace("/", "\\/"))
    return ("<html><body><div id=app></div>"
            "<script>var POSSESSIVE = /(\\w+)'s\\b/g;\n"
            f"window.__BOOTSTRAP__ = {{\"query\": {lit}}};</script></body></html>")


@pytest.mark.parametrize("entry_id", _CASE_IDS)
def test_json_script_plus_a_benign_regex_never_confirms_xss(entry_id: str) -> None:
    confirmed = _confirm(compile_entry(_by_id(entry_id)), _json_script_safe_with_regex)
    assert confirmed is None, (
        f"{entry_id} minted a {getattr(confirmed, 'severity', '?')} FACT at "
        f"{getattr(confirmed, 'confidence', 0):.2f} against a correctly json_script-escaped "
        f"page that merely contains a regex literal"
    )


def _src_bearing_script(v: str) -> str:
    return f'<html><body><script src="/app.js">var q = {v};</script></body></html>'


# This payload OPENS with `</script>`, so it genuinely TERMINATES the element and
# the `<script>` it then opens is a real, live, src-less element — it must still
# confirm (see the companion assertion below).
#
# `m2-xss-script-title-close` and `m2-xss-script-svg-nested` deliberately do NOT
# belong here: their `<script>` tag sits INSIDE the outer element's raw text, which
# a browser does not parse as markup, and the outer element ignores that text
# because it bears `src`. Both of them DID confirm before the B2 fix.
_SCRIPT_ELEMENT_ESCAPERS = ("m2-xss-script-close-reopen",)


@pytest.mark.parametrize(
    "entry_id", [e for e in _CASE_IDS if e not in _SCRIPT_ELEMENT_ESCAPERS])
def test_a_src_bearing_script_never_confirms_xss_end_to_end(entry_id: str) -> None:
    """RED-PEN B2 end-to-end: a `<script src=...>` never evaluates its child text, so
    a reflection CONFINED to that child text cannot be an xss FACT however it lands."""
    confirmed = _confirm(compile_entry(_by_id(entry_id)), _src_bearing_script)
    assert confirmed is None, f"{entry_id} minted a FACT inside a src-bearing <script>"


@pytest.mark.parametrize("entry_id", _SCRIPT_ELEMENT_ESCAPERS)
def test_a_payload_that_leaves_the_src_bearing_script_still_confirms(entry_id: str) -> None:
    """The mutation control for the `src` rule: it must not cost a real detection. A
    payload that CLOSES the element reaches live markup outside it and still mints."""
    confirmed = _confirm(compile_entry(_by_id(entry_id)), _src_bearing_script)
    assert confirmed is not None, f"{entry_id} stopped confirming after the src fix"
    assert confirmed.confirmed_by is OracleKind.REFLECTION_CONTEXT


def test_the_raw_script_splice_still_confirms_end_to_end() -> None:
    """The mutation control for both B1 and B2 at the end-to-end layer: the SAME
    entry that the two negatives above must refuse still mints against a genuinely
    vulnerable raw splice, so neither negative is vacuous."""
    confirmed = _confirm(compile_entry(_by_id("m2-xss-script-string-break")), _script_raw)
    assert confirmed is not None
    assert confirmed.confirmed_by is OracleKind.REFLECTION_CONTEXT
