"""
Wave 6 — structural (AST) differential + HTML-context reflection.

The structural diff is invariant to token noise (nonces, CSRF tokens, timestamps)
but sensitive to real change (an added record / DOM node). The reflection-context
oracle fires only on a PROVEN BREAKOUT — the marker became a tag name, owns a
whole event-handler / javascript: value, or sits at CODE position inside an
executable <script>. Mere presence inside a <script> or inside an on* value is
NOT a breakout (audit F4/R5: a correctly json_script-escaped page and a correctly
&quot;-escaped handler both reproduced a High xss FACT under the old rule); those
are non-firing, NON-CONCLUSIVE advisories now. And in every case the claim is
"reached a live/executable POSITION", never "executed".
"""

from __future__ import annotations

import json

import pytest

import html as _html

from framework.v2.verify.oracles import (
    differential_response_oracle,
    reflection_context_oracle,
    structural_diff,
)


# --- structural diff -------------------------------------------------------


def test_json_nonce_change_is_not_a_structural_diff() -> None:
    a = '{"token": "abc123", "user": "alice", "items": [1, 2, 3]}'
    b = '{"token": "zzz999", "user": "alice", "items": [1, 2, 3]}'  # only the nonce changed
    assert structural_diff(a, b) == 0.0


def test_json_added_record_is_a_structural_diff() -> None:
    a = '{"items": [1, 2, 3]}'
    b = '{"items": [1, 2, 3, 4, 5]}'  # two more records -> new paths
    assert structural_diff(a, b) > 0.0


def test_json_reordered_keys_is_not_a_diff() -> None:
    assert structural_diff('{"a": 1, "b": 2}', '{"b": 2, "a": 1}') == 0.0


def test_html_csrf_token_change_is_not_a_structural_diff() -> None:
    a = '<form><input name="csrf" value="AAAA"><input name="q"></form>'
    b = '<form><input name="csrf" value="ZZZZ"><input name="q"></form>'
    assert structural_diff(a, b) == 0.0


def test_html_added_row_is_a_structural_diff() -> None:
    a = "<table><tr><td>1</td></tr></table>"
    b = "<table><tr><td>1</td></tr><tr><td>2</td></tr></table>"
    assert structural_diff(a, b) > 0.0


def test_structural_dimension_does_not_fire_on_reflected_nonce() -> None:
    # a response that reflects a per-request nonce should NOT read as a boolean
    # differential under the structural dimension
    base = {"status": 200, "body": '{"nonce": "n1", "rows": [1, 2, 3]}'}
    mut = {"status": 200, "body": '{"nonce": "n2", "rows": [1, 2, 3]}'}
    sig = differential_response_oracle(base, mut, {"dimensions": ["structural"]})
    assert not sig.fired


def test_structural_dimension_fires_on_extra_rows() -> None:
    base = {"status": 200, "body": '{"rows": [1, 2, 3]}'}
    mut = {"status": 200, "body": '{"rows": [1, 2, 3, 4, 5, 6, 7, 8]}'}
    sig = differential_response_oracle(base, mut, {"dimensions": ["structural"]})
    assert sig.fired


# --- reflection context ----------------------------------------------------

_MARKER = "cruciblexyzmark"


def test_marker_creating_a_tag_fires() -> None:
    body = f"<html>results: \"'><x{_MARKER}></html>"  # payload broke out into markup
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and sig.observed["context"] == "html_tag"


def test_marker_at_code_position_in_script_fires() -> None:
    # the payload broke OUT of the string literal: `''-MARKER-''` leaves the marker
    # at CODE position, so this is a proven breakout.
    body = f"<html><script>var x = ''-{_MARKER}-'';</script></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and sig.observed["context"] == "script"


def test_marker_inside_a_js_string_literal_does_not_fire() -> None:
    # AUDIT F4. The old rule fired on mere PRESENCE inside <script> and called it an
    # "executable JS context" — so a CORRECTLY escaped page minted a High xss FACT.
    # A marker confined to a string literal is DATA; no breakout is proven.
    body = f"<html><script>var x = '{_MARKER}';</script></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired
    assert sig.observed["context"] == "script_string_literal"
    # ... and it is NOT a clean bill of health either: an escaping bug this parse
    # cannot see could still make it executable, so the advisory is NON-conclusive.
    assert not sig.conclusive


def test_json_script_escaped_page_does_not_fire() -> None:
    # AUDIT F4, the measured repro: Django json_script / Rails json_escape —
    # JSON-encode then \uXXXX-escape < > & / so the value cannot terminate the
    # element or the literal. This page is SAFE and must never mint an xss FACT.
    raw = f"\"'><x{_MARKER}>"
    lit = (json.dumps(raw).replace("<", "\\u003c").replace(">", "\\u003e")
           .replace("&", "\\u0026").replace("/", "\\/"))
    body = ("<html><body><script>window.__BOOTSTRAP__ = "
            f"{{\"query\": {lit}, \"results\": []}};</script></body></html>")
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired, sig.evidence


def test_marker_in_a_non_executable_script_type_does_not_fire() -> None:
    # <script type="application/json"> is a DATA block the browser never runs.
    body = f'<script type="application/json">{{"q": {_MARKER}}}</script>'
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired and sig.observed["context"] == "script_data_block"


def test_marker_owning_a_whole_event_handler_fires() -> None:
    # the attacker supplied the ENTIRE handler body — a proven breakout.
    body = f"<div><svg onload={_MARKER}></div>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and "js_attribute" in sig.observed["context"]


def test_marker_embedded_in_a_page_composed_handler_does_not_fire() -> None:
    # AUDIT R5. HTML attribute values are entity-decoded unconditionally, so a
    # CORRECTLY &quot;-escaped handler argument arrives as a marker inside an on*
    # value. The page composed that handler; the attacker does not own the value.
    body = f'<div onclick="doThing(&quot;{_MARKER}&quot;)">x</div>'
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired
    assert sig.observed["context"] == "js_attribute_data"
    assert not sig.conclusive


def test_marker_in_a_raw_text_container_does_not_fire() -> None:
    # <noscript>/<textarea>/... content is not parsed as live markup by a browser,
    # though HTMLParser happily reports the inner start tag.
    body = f"<html><body><noscript>\"'><x{_MARKER}></noscript></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired and sig.observed["context"] == "inert_text_container"


def test_no_reflection_context_evidence_claims_execution() -> None:
    # The claim this oracle is allowed to make is "reached a live/executable
    # POSITION", never "executed". Guard the certificate wording.
    bodies = [
        f"<html>x\"'><x{_MARKER}></html>",                     # html_tag
        f"<div><svg onload={_MARKER}></div>",                  # js_attribute
        f"<script>var x = ''-{_MARKER}-'';</script>",          # script code position
        f"<script>var x = '{_MARKER}';</script>",              # advisory
        f"<p>{_MARKER}</p>",                                   # inert
    ]
    for body in bodies:
        sig = reflection_context_oracle(_MARKER, body)
        low = sig.evidence.lower()
        assert "executed" not in low and "execution proven" not in low, sig.evidence
        assert "proven execution" not in low, sig.evidence


def test_html_encoded_marker_does_not_fire() -> None:
    raw = f"\"'><x{_MARKER}>"
    body = f"<html>results: {_html.escape(raw)}</html>"  # the payload was encoded
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired


def test_marker_in_plain_text_does_not_fire() -> None:
    body = f"<html><p>you searched for {_MARKER}</p></html>"  # inert text reflection
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired


def test_marker_in_inert_attribute_does_not_fire() -> None:
    body = f'<input type="text" value="{_MARKER}">'  # encoded/quoted, no break-out
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired


def test_marker_absent_does_not_fire() -> None:
    assert not reflection_context_oracle(_MARKER, "<html>nothing here</html>").fired


# ---------------------------------------------------------------------------
# RED-PEN B1 — the JS lexer manufactured FACTs.
#
# The old `_js_code_position` docstring claimed: "Regex literals are NOT modelled:
# every misparse biases toward NOT-code -> NOT-firing. The failure direction is a
# missed detection, never a manufactured FACT." REFUTED. With no regex-literal
# state, an apostrophe inside a regex literal opens a PHANTOM string state, and the
# OPENING quote of the next REAL string CLOSES it — leaving that real string's
# contents at apparent code position. One quote of desync.
#
# Each page below was MEASURED on 1ccd18a5 as fired=True, conf=0.90,
# conclusive=True, context="script"; node v22 `vm.runInNewContext` executes nothing
# in any of them. They must now be non-firing, NON-CONCLUSIVE advisories.
# ---------------------------------------------------------------------------

_LEXER_AMBIGUITY_PAGES: dict[str, str] = {
    # a regex literal whose BODY is the marker: `/MARKER/i` is data, not code
    "regex_flag_suffix":
        f"<html><body><script>var re = /{_MARKER}/i; if (re.test(q)) hl(q);"
        "</script></body></html>",
    # the one-quote desync: the apostrophe in /it's/ opens a phantom string that the
    # opening quote of 'MARKER' then closes
    "regex_apostrophe":
        f"<html><body><script>var re = /it's/; var q = '{_MARKER}';</script></body></html>",
    # the same desync with a double quote inside a character class
    "regex_double_quote":
        f'<html><body><script>var re = /["]/; var q = "{_MARKER}";</script></body></html>',
    # Annex B SingleLineHTMLOpenComment: `<!--` starts a line comment in a classic script
    "annexb_open_comment":
        f"<html><body><script><!-- var q = {_MARKER}\n//--></script></body></html>",
    # Annex B HTMLCloseComment
    "annexb_close_comment":
        f"<html><body><script>\n--> {_MARKER}\n</script></body></html>",
    # a template substitution whose body contains a nested backtick: the same
    # one-quote desync through a construct the lexer does not model
    "template_substitution":
        "<html><body><script>var t = `${'`'}`; var q = '" + _MARKER
        + "';</script></body></html>",
}


@pytest.mark.parametrize("name", sorted(_LEXER_AMBIGUITY_PAGES))
def test_lexer_ambiguity_never_mints_a_script_fact(name: str) -> None:
    sig = reflection_context_oracle(_MARKER, _LEXER_AMBIGUITY_PAGES[name])
    assert not sig.fired, f"{name}: manufactured a FACT — {sig.evidence}"
    assert sig.confidence == 0.0
    # a downgrade, not a clean bill of health: INCONCLUSIVE is recoverable,
    # a manufactured FACT is not.
    assert not sig.conclusive, f"{name}: claimed a decisive verdict it cannot support"
    assert sig.observed["context"] == "script_lexer_ambiguous", sig.observed
    assert "FAILS CLOSED" in sig.evidence


def test_unambiguous_script_code_position_still_fires() -> None:
    """The mutation control for the fail-closed downgrade: a script whose text holds
    NO regex candidate, NO Annex B comment and NO template substitution before the
    marker is still adjudicated, and a real breakout still mints."""
    body = f"<html><body><script>var x = ''-{_MARKER}-'';</script></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and sig.observed["context"] == "script"
    # ... and a string literal in the same unambiguous script is still a clean advisory
    safe = f"<html><body><script>var x = '{_MARKER}';</script></body></html>"
    assert reflection_context_oracle(_MARKER, safe).observed["context"] == "script_string_literal"


def test_a_division_before_the_marker_costs_the_detection_by_design() -> None:
    """The stated COST of failing closed. A `/` at apparent code position is a regex
    literal or a division and this lexer cannot tell which, so a genuine breakout
    downstream of ANY such slash is downgraded to an advisory. That is a missed
    detection — recoverable, and the trade this fix deliberately makes."""
    body = f"<html><body><script>var r = a / b; var x = ''-{_MARKER}-'';</script></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired
    assert sig.observed["context"] == "script_lexer_ambiguous"
    assert sig.observed["detail"] == "regex_literal"
    assert not sig.conclusive       # the finding stays OPEN, it is not closed as clean


def test_split_script_text_is_ambiguity_not_a_breakout() -> None:
    """A continuation data chunk starts mid-token, so "code position" is unknowable
    from it. Fail closed rather than restart the lexer in a known-wrong state."""
    from framework.v2.verify.oracles import _ReflectionScanner

    # HTMLParser buffers CDATA until it sees `</script`, so a plain two-`feed()`
    # split is re-joined into one chunk; the callbacks are driven directly to
    # exercise the guard for the case where it does not.
    scanner = _ReflectionScanner(_MARKER.lower())
    scanner.handle_starttag("script", [])
    scanner.handle_data("var q = '")
    scanner.handle_data(f"{_MARKER}';")
    scanner.handle_endtag("script")
    assert scanner.context is None
    assert scanner.advisory == "script_lexer_ambiguous"
    assert scanner.advisory_detail == "split_script_text"


# ---------------------------------------------------------------------------
# RED-PEN B2 — two more false-FACT generators.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attr", ["on-click", "once", "online", "only", "onyx", "on"])
def test_an_on_prefixed_non_handler_never_fires(attr: str) -> None:
    """`is_handler = a.startswith("on")` is not a test for anything a browser runs.
    MEASURED firing at conf 0.90 on `on-click`, `once` and `online` — none is an HTML
    event-handler content attribute and no browser executes any of them."""
    body = f'<html><body><div {attr}="{_MARKER}">x</div></body></html>'
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired, f"{attr}: fired on a non-handler attribute — {sig.evidence}"
    assert sig.confidence == 0.0


@pytest.mark.parametrize("attr", ["on-click", "on", "data-onclick", "title", "class"])
def test_a_non_on_shaped_attribute_is_still_a_CONCLUSIVE_clean(attr: str) -> None:
    """AUDIT-B4 guard-rail. The B4 fix must not swallow the decisive negative: an
    attribute that is NOT ``on``-shaped (hyphenated, the bare ``on``, a ``data-*``
    or an ordinary attribute) cannot possibly be an unmodelled event handler, so a
    marker landing in it stays a CHANNEL-CONFIRMED CLEAN (``conclusive=True``, ctx
    ``inert``). Without this assertion B4's fix could quietly turn every reflection
    into ``inconclusive`` and nothing would notice."""
    body = f'<html><body><div {attr}="{_MARKER}">x</div></body></html>'
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired
    assert sig.conclusive is True, f"{attr}: lost the decisive negative"
    assert sig.observed["context"] == "inert"


@pytest.mark.parametrize("attr", ["onclick", "onerror", "onload", "onmouseover",
                                  "ontoggle", "onfocus", "onpointerdown", "ononline"])
def test_real_event_handler_attributes_still_fire(attr: str) -> None:
    """The mutation control for the closed set: the handlers that ARE handlers, and
    whose whole value the attacker owns, must still mint."""
    body = f"<html><body><div {attr}={_MARKER}>x</div></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired, f"{attr}: a real event handler stopped firing"
    assert sig.observed["context"] == f"js_attribute:{attr}"


def test_a_src_bearing_script_never_fires_on_its_child_text() -> None:
    """Per the HTML spec a `<script src=...>` IGNORES its child text — the element's
    inline content is never evaluated. MEASURED firing at conf 0.90 before the fix."""
    body = f'<html><body><script src="/app.js">{_MARKER}();</script></body></html>'
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired, sig.evidence
    assert sig.observed["context"] == "script_src_ignored_body"
    assert not sig.conclusive
    # the identical script WITHOUT src is a real breakout and must still fire
    live = f"<html><body><script>{_MARKER}();</script></body></html>"
    assert reflection_context_oracle(_MARKER, live).observed["context"] == "script"


def test_a_javascript_url_src_is_unaffected_by_the_script_src_rule() -> None:
    """The `src` rule is about a <script> element's CHILD TEXT. A `javascript:` URL in
    an `src` attribute of any element is still an executable value the attacker can
    own, and must still fire."""
    body = f'<html><body><a href="javascript:{_MARKER}">go</a></body></html>'
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and sig.observed["context"] == "js_attribute:href"


# ---------------------------------------------------------------------------
# AUDIT B1-B4 — the four defects a RED-PEN reproduced against a REAL headless
# Chromium (`/usr/bin/chromium --headless --dump-dom`, Chromium 150) used as
# ground truth for "does this actually execute".
#
# The measurement method, so it is reproducible: every probe page's injected code
# runs `document.documentElement.setAttribute('data-gt', ['OBSIDIAN','EXEC'].join('-'))`,
# so the sentinel string is COMPUTED at runtime and never appears in the page
# source — a `--dump-dom` grep therefore cannot be fooled by the source bytes.
# Each assertion below names what Chromium did.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("container", ["noscript", "template"])
def test_B1_a_script_nested_in_an_inert_container_never_fires(container: str) -> None:
    """AUDIT-B1 (CRITICAL). `_inert_depth` was maintained but READ ONLY in
    `handle_starttag`; `handle_data` never consulted it. Python's `HTMLParser` has
    RCDATA handling for textarea/title/iframe/xmp — so those were ACCIDENTALLY safe
    — but NOT for `<noscript>` (with scripting enabled the HTML LS gives its start
    tag the generic RAW TEXT algorithm) or `<template>` (contents live in an inert
    `DocumentFragment`), so a nested `<script>` was reported LIVE.

    CHROMIUM (measured): `<noscript><script>…</script></noscript>` and the
    `<template>` twin execute NOTHING. ORACLE BEFORE: fired=True conf=0.90
    ctx=script (a High/0.9 xss FACT). ORACLE NOW: non-firing, NON-CONCLUSIVE."""
    body = (f"<html><body><{container}><script>{_MARKER}();</script>"
            f"</{container}></body></html>")
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired, f"<{container}> minted a FACT Chromium does not execute"
    assert sig.confidence == 0.0
    assert sig.observed["context"] == "inert_text_container"
    assert sig.observed["detail"] == container, "the advisory must NAME the container"
    assert sig.conclusive is False, "an inert container is an advisory, not a clean"


def test_B1_the_guard_does_not_cost_the_live_script_detection() -> None:
    """Positive control for B1: the SAME script OUTSIDE any inert container is a
    real breakout and must still mint (Chromium: EXECUTES). If the `_inert_depth`
    guard were widened to swallow this, this dies."""
    body = f"<html><body><script>{_MARKER}();</script></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and sig.confidence == 0.9
    assert sig.observed["context"] == "script"


@pytest.mark.parametrize("container", ["noscript", "template"])
def test_B1_a_payload_that_CLOSES_the_container_still_fires(container: str) -> None:
    """The B1 guard must not cost the escape case: a payload that closes the inert
    container genuinely reaches live markup (Chromium 150, measured: EXECUTES) and
    must still fire. Without this the fix could be "made to pass" by treating every
    container as permanently inert."""
    body = (f"<html><body><{container}></{container}><script>{_MARKER}();</script>"
            "</body></html>")
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired, f"closing <{container}> must restore the live verdict"
    assert sig.observed["context"] == "script"


@pytest.mark.parametrize("container", ["noscript", "template"])
def test_B1_an_UNMATCHED_end_tag_does_not_cancel_the_container(container: str) -> None:
    """AUDIT-B1, second order. The first cut of the depth bookkeeping did a plain
    `self._inert_depth -= 1` on any inert-container end tag, so the SHIPPED payload
    `</title><script>{marker}</script>` cancelled an enclosing `<noscript>` that was
    never opened as a title — and the marker was reported live again. A browser
    IGNORES an unmatched end tag. Chromium 150, measured: executes nothing."""
    body = (f"<html><body><{container}></title><script>{_MARKER}();</script>"
            f"</{container}></body></html>")
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired, f"an unmatched </title> cancelled <{container}>"
    assert sig.observed["context"] == "inert_text_container"


# (type attribute source, chromium EXECUTES?) — every row MEASURED in Chromium 150.
_B2_TYPES = [
    ("",                                   True,  "attribute absent"),
    ('type=""',                            True,  "raw empty string -> classic"),
    ('type="text/javascript"',             True,  "essence match"),
    ('type="TEXT/JAVASCRIPT"',             True,  "essence match is case-insensitive"),
    ('type=" text/javascript "',           True,  "essence match strips whitespace"),
    ('type="application/javascript"',      True,  "essence match"),
    ('type="text/livescript"',             True,  "essence match (legacy, still runs)"),
    ('type="module"',                      True,  "module"),
    ('type="MODULE"',                      True,  "module is case-insensitive"),
    ('type="module" nomodule',             True,  "nomodule is IGNORED for modules"),
    ('type="text/javascript; charset=utf-8"', False, "a parameter breaks the essence"),
    ('type="text/javascript;charset=utf-8"',  False, "a parameter breaks the essence"),
    ('type="text/javascript;"',            False, "a trailing ; breaks the essence"),
    ('type=" module "',                    False, "module is matched UNSTRIPPED"),
    ('type=" "',                           False, "whitespace-only is NOT the empty string"),
    ('type="\t"',                          False, "whitespace-only is NOT the empty string"),
    ('type="application/json"',            False, "data block"),
    ('type="importmap"',                   False, "importmap is not executed as script"),
    ('type="speculationrules"',            False, "not executed as script"),
    ('type="text/javascript1.6"',          False, "not a JS MIME essence"),
    ("nomodule",                           False, "nomodule on a CLASSIC script"),
    ('nomodule="false"',                   False, "nomodule is a BOOLEAN attribute"),
    ("NOMODULE",                           False, "attribute names are case-insensitive"),
]


@pytest.mark.parametrize("attrs, executes, why", _B2_TYPES,
                         ids=[r[0] or "no-type" for r in _B2_TYPES])
def test_B2_script_type_executability_matches_chromium(
    attrs: str, executes: bool, why: str
) -> None:
    """AUDIT-B2 (CRITICAL). `_EXECUTABLE_SCRIPT_TYPES` was broader than any browser
    in three ways, each reproduced against Chromium 150:

      * `.split(";")[0]` made the test a PATTERN. The HTML LS requires a JavaScript
        MIME type ESSENCE match (whatwg/html#3699, Chrome 69+), and a parameter
        makes the element NON-executing. `type="text/javascript; charset=utf-8"`
        and `type="text/javascript;charset=utf-8"` both fired at 0.90; CHROMIUM
        RUNS NEITHER. That contradicted the file's own principle twelve lines below
        the set: "So membership, never a pattern."
      * `nomodule` was never checked. "Prepare the script element" returns early for
        a classic script bearing it. `<script nomodule>` fired; CHROMIUM DOES NOT
        RUN IT. This is the real-world legacy-fallback pattern.
      * `type=" "` stripped to `""` and was admitted by the `""` member, but the LS
        empty-string rule is about the RAW attribute value. CHROMIUM: `type=""`
        executes, `type=" "` does not.

    Each row here is an INDEPENDENT measurement; the `executes=True` rows are the
    positive controls that die if the fix is over-tightened."""
    body = f"<html><body><script {attrs}>{_MARKER}();</script></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired is executes, (
        f"<script {attrs}>: oracle fired={sig.fired} but Chromium executes={executes} ({why})")
    if executes:
        assert sig.confidence == 0.9 and sig.observed["context"] == "script"
    else:
        assert sig.confidence == 0.0
        assert sig.conclusive is False, "a non-executing script is an advisory, not a clean"
        assert sig.observed["context"] in ("script_data_block", "script_nomodule_ignored")


def test_B2_nomodule_has_its_own_named_advisory() -> None:
    """The `nomodule` rule must be DISTINGUISHABLE in the evidence, not folded into
    the generic data-block message — an operator reading it has to know why."""
    body = f"<html><body><script nomodule>{_MARKER}();</script></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.observed["context"] == "script_nomodule_ignored"
    assert "nomodule" in sig.evidence


def test_B3_a_marker_inside_a_hashbang_comment_never_fires() -> None:
    """AUDIT-B3. `#!` at offset 0 is a HashbangComment covering the whole first line
    (ECMA-262 § Hashbang Comments; `node -e` agrees). The lexer had no `#!` state,
    found no ambiguity, and reported CODE POSITION.

    CHROMIUM (measured): a page whose entire payload sits on the hashbang line
    executes NOTHING. ORACLE BEFORE: fired=True conf=0.90 ctx=script."""
    body = f"<html><body><script>#! {_MARKER}()\n</script></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired, "a hashbang-commented marker minted a FACT"
    assert sig.confidence == 0.0
    assert sig.conclusive is False


def test_B3_a_marker_AFTER_the_hashbang_line_still_fires() -> None:
    """B3 is MODELLED, not merely refused — so the hashbang costs no capability.
    CHROMIUM: the second line EXECUTES, and the oracle must still say so."""
    body = f"<html><body><script>#!/usr/bin/env node\n{_MARKER}();\n</script></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired, "modelling the hashbang must not swallow the next line"
    assert sig.observed["context"] == "script"


def test_B3_a_hashbang_inside_a_string_literal_costs_nothing() -> None:
    """The legacy hashbang-routing shape `var r = "#!/users"` is in STRING state, so
    neither B3 rule is reached. CHROMIUM: the following statement EXECUTES."""
    body = (f'<html><body><script>var r = "#!/users"; {_MARKER}();</script>'
            "</body></html>")
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and sig.observed["context"] == "script"


def test_B3_a_misplaced_hashbang_fails_closed() -> None:
    """`#!` away from offset 0 is a SyntaxError — the script never parses, so NOTHING
    runs and "code position" is not a claim this lexer may make.
    CHROMIUM (measured): executes nothing."""
    body = f"<html><body><script>var a=1;\n#! x\n{_MARKER}();</script></body></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired
    assert sig.observed["context"] == "script_lexer_ambiguous"
    assert sig.observed["detail"] == "hashbang"
    assert sig.conclusive is False


# Real, Chromium-executed handler content attributes that the closed set was
# missing. Found by enumerating every `on[a-z]+` IDL attribute on
# Element/HTMLElement/HTMLBodyElement/HTMLMediaElement/SVGElement/Document/window
# in Chromium 150, then confirming for EACH that a CONTENT attribute compiles into
# a handler AND that dispatching the event runs the attacker-supplied body.
_B4_RECOVERED = ["oncommand", "oncontentvisibilityautostatechange", "onmousewheel",
                 "onscrollsnapchange", "onscrollsnapchanging"]


@pytest.mark.parametrize("attr", _B4_RECOVERED)
def test_B4_a_measured_real_handler_the_closed_set_was_missing_now_fires(attr: str) -> None:
    """AUDIT-B4 (REGRESSION). CHROMIUM (measured, end-to-end): setting each of these
    as a content attribute and dispatching its event RUNS the attacker's body. They
    were absent from the 131-member set, so the oracle returned
    `fired=False conclusive=True ctx=inert` and `probe_verdict` certified the probe
    CLEAN — a true positive turned into a channel-confirmed clean."""
    body = f'<html><body><div {attr}="{_MARKER}">x</div></body></html>'
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired, f"{attr} is a Chromium-executed handler and must mint"
    assert sig.observed["context"] == f"js_attribute:{attr}"


def test_B4_a_closed_set_MISS_is_an_advisory_and_never_a_clean() -> None:
    """AUDIT-B4, the SYSTEMIC half — and the point of the whole item.

    The comment on `_EVENT_HANDLER_ATTRIBUTES` promises "a handler that is missing
    from it is a MISSED detection (a non-firing advisory) — recoverable". It was
    NOT: a non-member never called `_note(...)`, so the scan fell through to the
    terminal `conclusive=True` branch with the evidence "marker reflected but NOT in
    an executable context (encoded/inert)". A missed detection is acceptable; a
    FALSE CLEAN is not.

    Adding the five measured handlers above does not fix this — the NEXT handler the
    web platform ships would reproduce it. So any `on`-SHAPED non-member is routed
    to a non-conclusive advisory. `onfuturethinghere` stands in for that next
    handler (Chromium, measured: it does NOT execute today — which is exactly why
    the oracle must not FIRE on it either)."""
    body = f'<html><body><div onfuturethinghere="{_MARKER}">x</div></body></html>'
    sig = reflection_context_oracle(_MARKER, body)
    assert not sig.fired, "an unmodelled shape must never mint a FACT"
    assert sig.conclusive is False, "a closed-set MISS must NOT be a conclusive clean"
    assert sig.observed["context"] == "unmodelled_handler_shape"
    assert sig.observed["detail"] == "onfuturethinghere"


def test_B4_the_miss_advisory_makes_the_probe_INCONCLUSIVE_not_clean() -> None:
    """The B4 defect only bites through `probe_verdict`, so assert it THERE: a
    closed-set miss must produce `inconclusive`, and a genuine inert reflection must
    still produce `clean` (the control that dies if B4's fix is over-applied)."""
    from framework.v2.scanner.engine import probe_verdict
    from framework.v2.verify.models import VerificationResult

    def verdict(attr: str) -> str:
        sig = reflection_context_oracle(
            _MARKER, f'<html><body><div {attr}="{_MARKER}">x</div></body></html>')
        return probe_verdict(VerificationResult(confirmed=sig.fired, signals=[sig]))[0]

    assert verdict("onfuturethinghere") == "inconclusive", "a closed-set miss was certified CLEAN"
    assert verdict("title") == "clean", "the decisive negative was lost"
    assert verdict("onclick") == "finding"
