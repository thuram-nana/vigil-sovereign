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
from framework.v2.engage import EngagementRefused, run_engagement
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
    )

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
