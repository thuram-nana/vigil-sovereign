"""
Wave 6 — structural (AST) differential + HTML-context reflection.

The structural diff is invariant to token noise (nonces, CSRF tokens, timestamps)
but sensitive to real change (an added record / DOM node). The reflection-context
oracle fires only when a marker reaches an EXECUTABLE position (a live tag, a
<script>, an event/JS attribute), not when it is HTML-encoded or sits in text —
materially fewer false positives than substring XSS detection.
"""

from __future__ import annotations

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


def test_marker_inside_script_fires() -> None:
    body = f"<html><script>var x = '{_MARKER}';</script></html>"
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and sig.observed["context"] == "script"


def test_marker_in_event_handler_fires() -> None:
    body = f'<div onclick="doThing(\'{_MARKER}\')">x</div>'
    sig = reflection_context_oracle(_MARKER, body)
    assert sig.fired and "js_attribute" in sig.observed["context"]


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
