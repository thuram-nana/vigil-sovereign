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
