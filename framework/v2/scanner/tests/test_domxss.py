"""
Static DOM-XSS source→sink analysis — real flows found, safe patterns ignored,
and candidates honestly labeled (never claimed as oracle-confirmed).
"""

from __future__ import annotations

from framework.v2.scanner.domxss import DomXssCandidate, analyze_html, analyze_js


def _flows(cands: list[DomXssCandidate]) -> set[tuple[str, str]]:
    return {(c.source, c.sink) for c in cands}


def test_direct_source_to_sink_is_firm() -> None:
    js = "document.getElementById('o').innerHTML = location.hash;"
    cands = analyze_js(js)
    assert ("location.hash", "innerHTML") in _flows(cands)
    assert cands[0].confidence == "Firm" and cands[0].bug_class == "dom_xss"


def test_source_via_variable_is_tentative() -> None:
    js = "var q = location.search; document.write(q);"
    cands = analyze_js(js)
    assert ("location.search", "document.write") in _flows(cands)
    assert any(c.confidence == "Tentative" for c in cands)


def test_eval_and_settimeout_string_sinks() -> None:
    assert ("location.hash", "eval") in _flows(analyze_js("eval(location.hash)"))
    assert ("document.referrer", "setTimeout") in _flows(
        analyze_js("setTimeout('x=' + document.referrer, 100)"))


def test_safe_patterns_do_not_flag() -> None:
    # textContent is not a sink; a static innerHTML has no source; an untainted var is clean
    assert analyze_js("el.textContent = location.hash;") == []
    assert analyze_js('el.innerHTML = "static content";') == []
    assert analyze_js('var safe = "x"; el.innerHTML = safe;') == []
    assert analyze_js("var q = location.search; console.log(q);") == []  # source but no sink


def test_html_extraction_of_inline_scripts() -> None:
    html = """
      <html><body>
        <script>document.write(location.hash);</script>
        <a href="javascript:eval(location.search)">x</a>
      </body></html>
    """
    flows = _flows(analyze_html(html))
    assert ("location.hash", "document.write") in flows
    assert ("location.search", "eval") in flows
