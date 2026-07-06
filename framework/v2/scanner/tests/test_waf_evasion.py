"""
Adaptive WAF-bypass wired into the live audit loop (B2).

`adaptive.waf_adapt` / `evolve` / `fitness` were real code the scan loop never
called. These tests pin the bridge: `looks_blocked` classifies filter rejections,
`adaptive_bypass` climbs the evasion ladder (then a small GA) to a form that gets
past the filter AND fires the sink, and the engine — only when `waf_adaptive` is on
— re-adjudicates a blocked probe through that synthesized form, confirming via the
SAME oracle so precision is unchanged (a bypass that does not fire the oracle is not
a finding).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.checks import ContentSignatureCheck
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.waf_evasion import adaptive_bypass, looks_blocked
from framework.v2.verify.adapter import FindingContext


# --------------------------------------------------------------------------- #
# looks_blocked
# --------------------------------------------------------------------------- #


def test_looks_blocked_on_status_and_markers() -> None:
    assert looks_blocked({"status": 403, "body": "nope"})
    assert looks_blocked({"status": 406, "body": ""})
    assert looks_blocked({"status": 200, "body": "Request Blocked by WAF"})
    # an ordinary 404/500/200 is NOT a block — the request reached the app
    assert not looks_blocked({"status": 404, "body": "not found"})
    assert not looks_blocked({"status": 500, "body": "stack trace"})
    assert not looks_blocked({"status": 200, "body": "<div>hello</div>"})


# --------------------------------------------------------------------------- #
# adaptive_bypass (the ladder + evolve mechanism), fully controlled send
# --------------------------------------------------------------------------- #


def test_adaptive_bypass_finds_a_ladder_form() -> None:
    # A naive filter that blocks a literal '<'; a url-encode ladder rung turns it
    # into %3C, slipping past, and the app then reaches the sink (a response-side
    # signal, so it survives the payload transforms).
    def send_form(form: str) -> dict:
        if "<" in form:
            return {"status": 403, "body": "request blocked"}
        return {"status": 200, "body": "SINK_HIT: the sink was reached"}

    def sink_present(resp: dict) -> bool:
        return "SINK_HIT" in resp.get("body", "")

    res = adaptive_bypass("<x>", send_form, sink_present)
    assert res is not None
    assert res.method in ("ladder", "evolve")
    assert not looks_blocked(res.response)
    assert sink_present(res.response)


def test_adaptive_bypass_returns_none_when_everything_blocked() -> None:
    # A filter that rejects every form -> honest failure, not a fabricated bypass.
    res = adaptive_bypass("<x>", lambda f: {"status": 403, "body": "blocked"},
                          lambda r: True, evolve_generations=3, evolve_population=6)
    assert res is None


def test_adaptive_bypass_returns_none_when_bypass_never_fires_sink() -> None:
    # The filter is bypassable, but the sink never appears -> not a finding.
    def send_form(form: str) -> dict:
        return {"status": 200, "body": "ordinary page, nothing of interest"}

    res = adaptive_bypass("<x>", send_form, lambda r: "SINK_HIT" in r.get("body", ""))
    assert res is None


# --------------------------------------------------------------------------- #
# engine wiring: adapt is called ONLY when waf_adaptive is on, and only for checks
# that implement it.
# --------------------------------------------------------------------------- #


class _StubBlockedCheck:
    """A check whose canonical probe is blocked (returns None) but whose adapt
    synthesizes a confirming context."""

    id = "stub-blocked"
    bug_class = "path_traversal"

    def probe(self, template, point, send):
        return None  # canonical payload filtered

    def adapt(self, template, point, send):
        return FindingContext.from_side_effect(
            "root:x:0:0:", "root:x:0:0:root:/root:/bin/bash", bug_class="path_traversal")


class _StubNoAdapt:
    id = "stub-no-adapt"
    bug_class = "path_traversal"

    def probe(self, template, point, send):
        return None


def _q_template() -> tuple[RequestTemplate, object]:
    tmpl = RequestTemplate(HttpRequest(method="GET", url="http://t/s?q=hi"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q"]
    return tmpl, pt


def _noop_send(request) -> dict:
    return {"status": 200, "body": "ok"}


def test_engine_calls_adapt_only_when_enabled() -> None:
    tmpl, _ = _q_template()
    req = tmpl.request
    # off -> the blocked probe yields nothing
    off = AuditEngine(_noop_send, waf_adaptive=False).audit(
        req, checks=(_StubBlockedCheck(),), insertion_kinds=(InsertionKind.QUERY_VALUE,))
    assert off == []
    # on -> adapt fires and its context is confirmed
    on = AuditEngine(_noop_send, waf_adaptive=True).audit(
        req, checks=(_StubBlockedCheck(),), insertion_kinds=(InsertionKind.QUERY_VALUE,))
    assert len(on) == 1 and on[0].bug_class == "path_traversal"


def test_engine_adapt_is_noop_for_checks_without_adapt() -> None:
    tmpl, _ = _q_template()
    on = AuditEngine(_noop_send, waf_adaptive=True).audit(
        tmpl.request, checks=(_StubNoAdapt(),), insertion_kinds=(InsertionKind.QUERY_VALUE,))
    assert on == []  # no adapt method -> nothing synthesized, no crash


# --------------------------------------------------------------------------- #
# end-to-end: a real ContentSignatureCheck bypasses a modelled WAF via adapt.
# --------------------------------------------------------------------------- #


def _waf_lfi_send(request) -> dict:
    """Models a WAF + a file-reading app. The WAF blocks the EXACT canonical
    traversal payload; any transformed form slips past, and the app then reads the
    file (returns the /etc/passwd signature)."""
    q = parse_qs(urlsplit(request.url).query).get("q", [""])[0]
    if q == "../../../../etc/passwd":       # the canonical payload -> blocked
        return {"status": 403, "body": "request blocked by waf"}
    if "etc/passwd" in q.lower():           # any evaded form still hits the sink
        return {"status": 200, "body": "root:x:0:0:root:/root:/bin/bash\n"}
    return {"status": 200, "body": "<p>ordinary</p>"}


def test_content_signature_bypasses_modelled_waf_via_adapt() -> None:
    check = ContentSignatureCheck(
        id="lfi", bug_class="path_traversal",
        payload="../../../../etc/passwd", signature="root:x:0:0:")
    tmpl, _ = _q_template()
    req = tmpl.request

    # off: the canonical payload is blocked, nothing confirmed
    off = AuditEngine(_waf_lfi_send, waf_adaptive=False).audit(
        req, checks=(check,), insertion_kinds=(InsertionKind.QUERY_VALUE,))
    assert off == []

    # on: adapt synthesizes an evaded form that still returns the file content,
    # confirmed by the SAME content-signature oracle
    on = AuditEngine(_waf_lfi_send, waf_adaptive=True).audit(
        req, checks=(check,), insertion_kinds=(InsertionKind.QUERY_VALUE,))
    assert len(on) == 1
    assert on[0].bug_class == "path_traversal"
    assert on[0].confirmed_by == "side_effect"
