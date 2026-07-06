"""
Wave 2 — the authorized `engage` runner drives the Wave-1 arsenal through the
full gated executor, end to end, and every confirmed finding carries a re-
verifiable certificate.

  * Against an in-scope loopback fixture it confirms findings, each with an
    `oracle_context` that independently re-verifies via the pure oracle.
  * A tripped kill-switch and an out-of-scope seed are refused BEFORE any
    traffic (fail-closed preflight).
  * The opt-in OOB relay advertises an allowlisted callback host but still
    records hits delivered to loopback (the tunnel model); a relay host not in
    scope is refused.

All traffic is loopback pytest-httpserver; nothing leaves the test host.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2.authority.killswitch import KillSwitch
from framework.v2.common import paths as _paths
from framework.v2 import engage as engage_mod
from framework.v2.engage import EngagementRefused, EngagementResult, run_engagement
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.oob import OOBReceiver
from framework.v2.verify.verifier import OracleVerifier

_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def isolated_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    targets_root = tmp_path / "targets"
    targets_root.mkdir()

    def build(slug: str, host: str) -> Path:
        td = targets_root / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug, host=host), encoding="utf-8")
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets_root / s / ".halt")
    return build


def _root(request) -> Response:
    return Response('<a href="/search?q=hi">search</a>', status=200, mimetype="text/html")


def _search(request) -> Response:
    q = request.args.get("q", "")
    if "'1'='1" in q or "1=1" in q:
        body = "echo:" + q + "\n" + "".join(f"user{i}:secret{i}\n" for i in range(40))
    else:
        body = "echo:" + q
    return Response(body, status=200, mimetype="text/html")


def _deny(_q: str, _t: float) -> bool:
    return False


def _dom_root(request) -> Response:
    return Response('<a href="/s?q=hi">go</a>', status=200, mimetype="text/html")


def _dom_sink(request) -> Response:
    # q flows into innerHTML unsanitised — DOM-XSS confirmable by execution
    body = ("<div id=o></div><script>document.getElementById('o').innerHTML="
            "new URLSearchParams(location.search).get('q')||''</script>")
    return Response(body, status=200, mimetype="text/html")


def test_engage_confirms_findings_with_reverifiable_certificates(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    report = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, prompt_callback=_deny,
    ).report

    assert report.active_findings, "engage confirmed nothing against a vulnerable target"
    # every confirmed finding carries a certificate that independently re-verifies
    for f in report.active_findings:
        assert f.oracle_context is not None, f"finding {f.bug_class} has no certificate"
        ctx = FindingContext.model_validate(f.oracle_context)
        confirmed = confirm_finding(
            finding={"bug_class": f.bug_class, "title": "t", "severity": "High",
                     "surface": "s", "summary": "x"},
            context=ctx, verifier=OracleVerifier(),
        )
        assert confirmed is not None, f"certificate for {f.bug_class} did not re-verify"


def test_engage_refuses_tripped_killswitch_before_any_traffic(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    KillSwitch("alpha").trip("operator stop")

    with pytest.raises(EngagementRefused, match="kill-switch"):
        run_engagement("alpha", f"http://127.0.0.1:{port}/", enable_oob=False, prompt_callback=_deny)
    # no request was ever issued
    assert "/" not in [r[0].path for r in httpserver.log]


def test_engage_refuses_out_of_scope_seed(isolated_engagement):
    isolated_engagement("alpha", "127.0.0.1")  # only 127.0.0.1 is in scope
    with pytest.raises(EngagementRefused, match="out of scope"):
        run_engagement("alpha", "http://10.11.12.13/", enable_oob=False, prompt_callback=_deny)


def test_engage_refuses_relay_host_not_in_scope(isolated_engagement, httpserver: HTTPServer):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    with pytest.raises(EngagementRefused, match="not on charter allowlist"):
        run_engagement(
            "alpha", f"http://127.0.0.1:{port}/",
            enable_oob=False, prompt_callback=_deny,
            oob_advertise_base_url="https://evil-relay.example/oob",  # not in charter scope
        )


def test_oob_relay_advertises_remote_but_records_loopback_delivery():
    """The relay model: probes embed the operator's allowlisted host, but the hit
    (delivered to loopback via the operator's tunnel) is still recorded here."""
    import urllib.request

    with OOBReceiver(advertise_base_url="https://relay.op.example/oob") as oob:
        token, callback = oob.register_token()
        assert callback == f"https://relay.op.example/oob/{token}"
        # simulate the operator's tunnel delivering the interaction to loopback,
        # preserving the token path segment
        loopback_hit = f"http://127.0.0.1:{oob.port}/{token}/probe"
        urllib.request.urlopen(loopback_hit, timeout=5).read()  # noqa: S310 (loopback)
        hits = oob.poll(token)
        assert hits and hits[0].token == token


def test_engage_browser_xss_confirms_by_execution_confined_to_scope(
    isolated_engagement, httpserver: HTTPServer,
):
    """The remote browser path: engage drives a headless browser (confined to the
    in-scope host at the resolver layer) that confirms DOM-XSS by real execution."""
    from framework.v2.scanner.cdp import cdp_available
    if not cdp_available():
        import pytest as _pytest
        _pytest.skip("no Chromium/Chrome for the CDP driver")

    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_dom_root)
    httpserver.expect_request("/s").respond_with_handler(_dom_sink)

    report = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=3, enable_oob=False, enable_browser_xss=True, prompt_callback=_deny,
    ).report
    dom = [f for f in report.active_findings if f.confirmed_by == "dom_execution"]
    assert dom, "engage browser pass did not confirm the DOM-XSS by execution"
    assert dom[0].oracle_context is not None  # re-verifiable certificate


# ---------------------------------------------------------------------------
# B1 — the reasoning brain is wired into the live loop: engage returns not just a
# scan report but the forward reasoning (attack paths) over the confirmed facts.
# ---------------------------------------------------------------------------


def test_engage_returns_engagement_result_with_chaining_wired(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    result = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, prompt_callback=_deny,
    )
    # the new contract: an EngagementResult carrying the report AND the reasoning
    assert isinstance(result, EngagementResult)
    assert result.report.active_findings, "engage confirmed nothing against a vulnerable target"
    # chaining ran without error; its outputs are lists (possibly empty — these
    # findings are not crown-jewel-chainable, and that is honest, not a failure)
    assert isinstance(result.attack_paths, list)
    assert isinstance(result.chained_conclusions, list)


def test_engage_chaining_produces_attack_paths_from_chainable_findings():
    # The keystone, exercised directly through engage's own chaining code path
    # (AutonomousCampaign over a report, no traffic): a confirmed IDOR fronting a
    # datastore and a deserialization on a host yield attacker->crown-jewel paths.
    from framework.v2.scanner.campaign import ScanReport
    from framework.v2.scanner.engine import AuditFinding
    from framework.v2.scanner.orchestrator import AutonomousCampaign

    report = ScanReport(
        target="http://t/", pages_crawled=1,
        active_findings=[
            AuditFinding(check_id="idor", bug_class="idor", insertion_point="query:id",
                         param="id", endpoint="http://t/account?id=1", confidence=0.9,
                         confirmed_by="achieved_state", rationale="object swap"),
            AuditFinding(check_id="deser", bug_class="deserialization", insertion_point="body:data",
                         param="data", endpoint="http://t/import", confidence=0.9,
                         confirmed_by="oob_callback", rationale="gadget"),
        ],
    )
    auto = AutonomousCampaign(engage_mod._no_send).chain_findings(report)
    assert auto.attack_paths, "chainable findings produced no attack path"
    # every hop is technique-annotated (the reasoning, not a guess)
    assert all(step.technique for ap in auto.attack_paths for step in ap.steps)


def test_engage_chaining_is_best_effort(
    isolated_engagement, httpserver: HTTPServer, monkeypatch: pytest.MonkeyPatch,
):
    # A chaining failure must NEVER sink the engagement: the oracle-confirmed report
    # is authoritative and is returned with empty paths rather than raising.
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    class _Boom:
        def __init__(self, *a, **k):
            pass

        def chain_findings(self, report):
            raise RuntimeError("reasoning exploded")

    monkeypatch.setattr(engage_mod, "AutonomousCampaign", _Boom)
    result = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, prompt_callback=_deny,
    )
    assert result.report.active_findings, "report must survive a chaining failure"
    assert result.attack_paths == []
    assert result.chained_conclusions == []
