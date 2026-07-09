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


_INTEL_PREFIXES = ("host:", "domain:", "application:", "service:", "certificate:",
                   "asn:", "netblock:", "organization:")
_ATTACK_PREFIXES = ("endpoint:", "finding:", "datastore:", "cloud_resource:", "attacker")


def test_engage_recon_joins_intel_and_attack_on_one_clock_safe_world(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    result = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, enable_recon=True, prompt_callback=_deny,
    )
    # the scan still works — recon must not disturb it
    assert result.report.active_findings, "recon must not break the scan"
    # the target was resolved into the intel inventory
    assert result.entities, "recon produced no asset inventory"
    assert any(m.node_id == "host:127.0.0.1" for e in result.entities for m in e.members)
    # predictions (if any — an IP target yields no sibling domains) are ALWAYS gated
    assert all(p.gated for p in result.predictions)

    # intel assets and attack facts coexist on ONE shared world with disjoint ids...
    world = result.world
    assert world is not None
    intel = [n for n in world.all_nodes() if n.id.startswith(_INTEL_PREFIXES)]
    attack = [n for n in world.all_nodes() if n.id.startswith(_ATTACK_PREFIXES)]
    assert intel and attack, "expected both intel and attack nodes on the shared world"
    # ...and the monotonic clock never inverts: every attack fact is stamped strictly
    # ABOVE the recon band (the fix for the partial-failure seq_base collapse).
    assert min(a.first_seen for a in attack) > max(i.last_seen for i in intel)


def test_engage_default_path_produces_no_intel_and_is_unchanged(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    result = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, prompt_callback=_deny,  # enable_recon defaults False
    )
    assert result.report.active_findings                 # scan unchanged
    assert result.entities == [] and result.predictions == []  # no intel on the default path
    # world carries only attack facts, and finding projection starts at seq 1 (seq_base
    # default) exactly as before the integration.
    assert result.world is not None
    assert not [n for n in result.world.all_nodes() if n.id.startswith(_INTEL_PREFIXES)]
    attack = [n for n in result.world.all_nodes() if n.id.startswith(_ATTACK_PREFIXES)]
    assert attack and min(n.first_seen for n in attack) == 1


def test_finding_confidence_is_per_finding_not_collapsed_by_bug_class() -> None:
    # two findings of the SAME bug_class must each get their OWN confidence report,
    # index-aligned — a weak passive finding must not inherit a strong sibling's posterior.
    from framework.v2.engage import _assess_findings
    from framework.v2.scanner.campaign import ScanReport
    from framework.v2.scanner.engine import AuditFinding

    rep = ScanReport(target="https://x/", active_findings=[
        AuditFinding(check_id="a", bug_class="xss", insertion_point="q.b", param="b",
                     confidence=0.4, confirmed_by="passive"),
        AuditFinding(check_id="c", bug_class="xss", insertion_point="q.a", param="a",
                     confidence=0.9, confirmed_by="oracle", oracle_context={"x": 1}),
    ])
    reports = _assess_findings(rep)
    assert len(reports) == 2                                   # index-aligned with findings
    assert reports[0].focal.posterior < reports[1].focal.posterior
    assert not reports[0].reaches_target and reports[1].reaches_target


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


# ---------------------------------------------------------------------------
# Nervous-System N0 — the engagement mirrors onto the immutable event spine.
# ---------------------------------------------------------------------------


def test_engage_spine_mirrors_findings_onto_the_immutable_stream(
    isolated_engagement, httpserver: HTTPServer, tmp_path: Path,
):
    from framework.v2.agents.blackboard import open_blackboard

    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    bb = open_blackboard(db_path=tmp_path / "spine.sqlite")
    result = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, prompt_callback=_deny, spine=bb,
    )
    assert result.report.active_findings, "engage confirmed nothing"

    # every confirmed finding is mirrored as a finding event, index-for-index
    finding_events = bb.read(engagement="alpha", kinds=["finding"])
    assert len(finding_events) == len(result.report.active_findings)
    # oracle authority preserved in the mirror: a re-grounded finding is 'confirmed'
    assert all(fe.payload["critique_status"] in ("confirmed", "llm_advisory") for fe in finding_events)
    assert any(fe.payload["verified_by_oracle"] for fe in finding_events)
    # scan progress observations + a summary decision also landed on the spine
    assert bb.read(engagement="alpha", kinds=["observation"])
    assert bb.read(engagement="alpha", kinds=["decision"])
    bb.close()


def test_spine_finding_mirror_never_claims_confirmed_without_a_live_verdict():
    # oracle-authority fidelity (N0 review fix): with NO live grounding verdict, the mirror
    # must NOT launder certificate-presence into 'confirmed'/verified_by_oracle — it mirrors
    # honestly as llm_advisory (matching scanner.report._grounding_label's admitted-is-None).
    class _F:
        bug_class = "boolean_sqli"
        insertion_point = "query:q"
        param = "q"
        confidence = 0.9
        confirmed_by = "differential_response"
        rationale = "rows diverged"
        oracle_context = {"bug_class": "boolean_sqli"}   # a certificate is PRESENT...
    p = engage_mod._spine_finding_payload(_F(), None)     # ...but NO live grounding verdict
    assert p["verified_by_oracle"] is False and p["critique_status"] == "llm_advisory"
    assert p["oracle_context"] is not None                # retained so downstream can re-verify


def test_engage_spine_records_a_refusal_as_evidence(isolated_engagement, tmp_path: Path):
    from framework.v2.agents.blackboard import open_blackboard

    isolated_engagement("alpha", "127.0.0.1")   # only 127.0.0.1 is in scope
    bb = open_blackboard(db_path=tmp_path / "spine.sqlite")
    # the refusal STILL propagates (fail-closed) AND is recorded as evidence on the spine
    with pytest.raises(EngagementRefused, match="out of scope"):
        run_engagement("alpha", "http://10.11.12.13/", enable_oob=False,
                       prompt_callback=_deny, spine=bb)
    refusals = bb.read(engagement="alpha", kinds=["refusal"])
    assert refusals and refusals[0].payload["fatal"] is True
    assert refusals[0].payload["gate"] == "preflight"
    bb.close()


# ---------------------------------------------------------------------------
# Wave 1 / W1.1 — the nervous system runs ADVISORY-ONLY over the mirrored findings.
# ---------------------------------------------------------------------------


def test_engage_spine_runs_advisory_reasoning_pass(
    isolated_engagement, httpserver: HTTPServer, tmp_path: Path,
):
    # W1.1: with a spine attached, engage runs the multi-critic panel + cognitive refusal +
    # reward-bus credit over each authoritative finding — all ADVISORY. The findings themselves
    # are unchanged (oracle authority preserved); the reasoning only lands as evidence events.
    from framework.v2.agents.blackboard import open_blackboard

    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    bb = open_blackboard(db_path=tmp_path / "spine.sqlite")
    result = run_engagement(
        "alpha", f"http://127.0.0.1:{port}/",
        max_pages=5, enable_oob=False, prompt_callback=_deny, spine=bb,
    )
    assert result.report.active_findings, "engage confirmed nothing"

    # (1) the multi-critic panel posted verdicts, each hung off its finding via parent_id, and
    # NO verdict is 'confirm' — a critic can only endorse/object/abstain (oracle authority).
    verdicts = bb.read(engagement="alpha", kinds=["critic_verdict"])
    assert verdicts, "the critic panel produced no verdicts on the spine"
    assert all(v.payload["verdict"] in ("endorse", "object", "abstain") for v in verdicts)
    finding_ids = {fe.id for fe in bb.read(engagement="alpha", kinds=["finding"])}
    assert all(v.parent_id in finding_ids for v in verdicts)

    # (2) the reward-bus credited each finding onto the unified stream (non-circular label).
    rewards = bb.read(engagement="alpha", kinds=["reward"])
    assert rewards and all(r.payload["source"] == "reward-bus" for r in rewards)

    # (3) an aggregate critic-panel decision landed alongside the engagement summary.
    questions = [d.payload["question"] for d in bb.read(engagement="alpha", kinds=["decision"])]
    assert any(q.startswith("critic panel:") for q in questions)
    assert "engagement summary" in questions

    # (4) NO spurious cognitive refusal: genuinely re-grounding findings must NOT be refused
    # (the refusal fires only when a certificate no longer re-executes — guarded here so the
    # W1.1 fix cannot regress into false refusals on every good finding).
    refusals = bb.read(engagement="alpha", kinds=["refusal"])
    assert all(r.payload.get("gate") != "epistemic" for r in refusals), \
        "a genuinely-confirmed finding was wrongly refused"
    bb.close()


def test_engage_cognitive_refusal_is_not_inert():
    # W1.1 review-fix: the cognitive-refusal primitive must ACTUALLY fire. It is fed the finding
    # AS THE SCAN CONCLUDED IT (its retained certificate) — not the post-grounding mirror, whose
    # verified_by_oracle is already demoted, which would make the check a no-op on exactly the
    # findings it must catch. When the retained certificate no longer re-executes, it refuses.
    from framework.v2.agents.cognitive_refusal import epistemic_refusal
    from framework.v2.engage import _scanner_verification_claim

    class _F:
        check_id = "c"
        bug_class = "reflected_xss"
        insertion_point = "query:q"
        param = "q"
        endpoint = "http://x/"
        confidence = 0.9
        confirmed_by = "reflected_marker"
        rationale = "r"
        oracle_context = {"bug_class": "reflected_xss"}   # a certificate PRESENT but too thin to re-fire

    claim = _scanner_verification_claim(_F())
    assert claim["verified_by_oracle"] is True            # asserts the scan's OWN oracle claim
    assert "param" not in claim                           # refusal turns on re-execution, not world-membership
    decision = epistemic_refusal(claim, world=None)
    assert decision is not None and decision.gate == "epistemic"   # NOT inert — it refuses to conclude

    # a finding with NO retained certificate makes no oracle claim → nothing to refuse (None)
    class _G(_F):
        oracle_context = None
    assert epistemic_refusal(_scanner_verification_claim(_G()), world=None) is None
