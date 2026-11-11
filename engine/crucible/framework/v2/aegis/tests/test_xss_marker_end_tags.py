"""CQ-1 — the AEGIS reflected-XSS oracle extracts the executable token whatever end-tag spelling the payload
uses (CodeQL py/bad-tag-filter). A browser ends a script element at `</script >` and `</script\\n foo>` too; a
bare `</script>` filter let an attacker hide the payload's script body from the oracle by spelling the end tag
that way, so a verbatim reflection of it never fired."""
from __future__ import annotations

import pytest

from framework.v2.aegis.inspect import _xss_markers


@pytest.mark.parametrize("end", ["</script>", "</script >", "</script\n>", "</SCRIPT\tfoo=1>", "</script/>"])
def test_script_body_is_extracted_for_every_browser_end_tag_spelling(end):
    assert "alert(document.domain)" in _xss_markers("<script>alert(document.domain)" + end)


def test_a_non_end_tag_is_not_treated_as_one():
    # `</scriptx>` does not end a script element; the body is not a complete script token.
    assert "alert(document.domain)" not in _xss_markers("<script>alert(document.domain)</scriptx>")
    assert "alert(document.domain)" not in _xss_markers("<scriptx>alert(document.domain)</script>")
