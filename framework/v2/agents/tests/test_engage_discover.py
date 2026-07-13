"""
Workstream C — the first honest step toward a DISCOVERING autonomous loop.

Until now the autonomous OODA cycle only RE-VERIFIES confirmed findings. This proves the new
DISCOVERY slice end-to-end against a LIVE loopback app: an unexplored ENDPOINT lead → the gated
``probe_surface`` tool runs ONE existing scanner check (REFLECTED_XSS) → the check's deterministic
oracle FIRES → a NEW oracle-confirmed finding is minted that was NOT in the seed set.

The doctrine this slice must not violate, asserted here:
  * the ORACLE stays the sole authority — a finding is minted ONLY when confirm_finding fires over
    evidence a real (loopback) target produced; the tool/planner never promote on their own;
  * fully GATED + fail-closed — the probe rides the full invoke_tool chain, so an out-of-scope
    endpoint or a tripped kill-switch REFUSES it and mints nothing;
  * default OFF is byte-identical — no probe-leaf is seeded and nothing is discovered;
  * W-F3: on the opt-in discover path the discovered facts are then FOLDED into the authoritative
    ScanReport.active_findings — deterministically (stable sort) and deduped — so the same engagement
    replays to the same report; every folded finding keeps its oracle_context (prove-don't-guess). The
    fold is unreachable from the byte-identical benchmark/gate and the default engage path.

Loopback-only (pytest_httpserver / urllib to 127.0.0.1); nothing leaves the test host.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2.common import paths as _paths
from framework.v2.authority.killswitch import KillSwitch
from framework.v2.engage import EngagementResult
from framework.v2.engage_autonomous import _fold_discovered_into_report, run_autonomous_cycle
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.worldmodel import Node, NodeKind, WorldModel

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


def _deny(_q: str, _t: float) -> bool:
    return False


def _reflect(request) -> Response:
    """A REAL reflected-XSS sink: werkzeug percent-DECODES ``q`` and this reflects it verbatim into
    executable HTML, so a marker payload lands as an actual ``<x...>`` tag — the reflection-context
    oracle fires. A constant page would not reflect and would not fire."""
    q = request.args.get("q", "")
    return Response(f"<html><body>results for {q}</body></html>", status=200, mimetype="text/html")


def _loopback_send():
    """A loopback HTTP send for the discovery tool: it takes a ``scanner.insertion.HttpRequest`` and
    actually fetches it from the in-process app (127.0.0.1 only), returning the ``{status, body,
    headers}`` shape the AuditEngine expects. This is the test's I/O seam — in production the injected
    send is the charter/scope/egress/rate-gated ``HttpExecutor.gated_fetch``."""

    def send(req) -> dict:
        r = urllib.request.Request(req.url, method=(getattr(req, "method", "GET") or "GET"))
        for k, v in (getattr(req, "headers", None) or []):
            try:
                r.add_header(k, v)
            except Exception:
                pass
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 - loopback only
                return {"status": resp.status,
                        "body": resp.read().decode("utf-8", "replace"),
                        "headers": list(resp.headers.items())}
        except urllib.error.HTTPError as e:
            return {"status": e.code,
                    "body": e.read().decode("utf-8", "replace"),
                    "headers": list(e.headers.items())}

    return send


def _endpoint_world(url: str) -> WorldModel:
    """A world with ONE unexplored ENDPOINT node (the discovery lead) and an attacker foothold. No
    crown jewel is reachable, so selection is plain greedy and the sole probe-leaf is picked."""
    w = WorldModel()
    w.add_node(Node(id="attacker:self", kind=NodeKind.PRINCIPAL, attrs={"role": "attacker"},
                    provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))
    w.add_node(Node(id="ep_reflect", kind=NodeKind.ENDPOINT, attrs={"url": url},
                    provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))
    return w


def _result(world: WorldModel, findings: list) -> EngagementResult:
    return EngagementResult(
        report=ScanReport(target="http://127.0.0.1/", active_findings=findings), world=world)


def _mk_finding(bug_class: str, insertion_point: str, endpoint: str, *, oracle: bool = True) -> AuditFinding:
    """A minimal oracle-confirmed AuditFinding for the fold unit tests. ``oracle=False`` drops the
    oracle_context so the prove-don't-guess guard rejects it."""
    return AuditFinding(
        check_id="c", bug_class=bug_class, insertion_point=insertion_point, param="p",
        endpoint=endpoint, confidence=0.9, confirmed_by="reflection_context",
        oracle_context=({"marker": "m", "bug_class": bug_class} if oracle else None))


# ---------------------------------------------------------------------------
# THE PROOF — an unexplored ENDPOINT lead → probe_surface → oracle FIRES → a
# NEW oracle-confirmed finding minted that was NOT in the seed set.
# ---------------------------------------------------------------------------


def test_discovery_mints_a_new_finding_from_an_unexplored_endpoint(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/reflect").respond_with_handler(_reflect)

    url = f"http://127.0.0.1:{port}/reflect?q=seed"
    world = _endpoint_world(url)
    result = _result(world, [])   # ZERO seed findings — pure discovery from the endpoint lead

    out = run_autonomous_cycle(
        result, slug="disco", enable_discover=True, discover_send=_loopback_send(),
        prompt_callback=_deny)

    # a probe-leaf was seeded from the ENDPOINT node and driven as a gated tool call
    assert out.discover_enabled is True
    assert out.probe_leaves_seeded == 1, "the unexplored ENDPOINT lead did not seed a probe-leaf"
    assert out.probes_driven == 1 and out.probes_refused == 0
    assert out.cycles and out.cycles[0].is_probe is True
    assert out.cycles[0].tool == "probe_surface"
    assert out.cycles[0].refused is False and out.cycles[0].gate == ""

    # THE POINT: a NEW oracle-confirmed finding was minted (the oracle FIRED over live evidence)
    assert out.discovered_count == 1, "discovery did not mint a NEW finding when the oracle fired"
    assert out.cycles[0].discovered_findings == 1
    minted = AuditFinding.model_validate(out.discovered_findings[0])
    assert minted.bug_class == "xss"
    assert minted.endpoint == url, "the minted finding is not located on the probed endpoint"
    assert minted.oracle_context is not None, "a minted finding must carry its retained oracle proof"
    assert minted.confirmed_by, "the minted finding names no oracle kind"

    # W-F3: the discovered finding is now FOLDED into the authoritative report (the honest next slice
    # WS-C deferred). The seed set was EMPTY, so this is genuinely NEW — not a re-report of a seed.
    assert out.findings_folded == 1
    folded = list(result.report.active_findings)
    assert len(folded) == 1, "the discovered finding was not folded into the authoritative report"
    ff = folded[0]
    assert (ff.bug_class, ff.insertion_point, ff.endpoint) == \
           (minted.bug_class, minted.insertion_point, minted.endpoint)
    assert ff.oracle_context is not None, "the folded finding lost its oracle proof (prove-don't-guess)"
    # the fold splices the SAME oracle-confirmed finding discovery minted (no fabrication)
    assert ff.model_dump() == minted.model_dump()


def test_discovery_off_mints_nothing_byte_identical(
    isolated_engagement, httpserver: HTTPServer,
):
    """The SAME live app + world with discovery OFF (the default): no probe-leaf is seeded, the
    probe tool is never constructed, and nothing is discovered — the byte-identical control."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/reflect").respond_with_handler(_reflect)

    url = f"http://127.0.0.1:{port}/reflect?q=seed"
    result = _result(_endpoint_world(url), [])

    # default OFF: enable_discover defaults False
    out = run_autonomous_cycle(result, slug="disco", prompt_callback=_deny)
    assert out.discover_enabled is False
    assert out.probe_leaves_seeded == 0
    assert out.probes_driven == 0 and out.discovered_count == 0
    assert out.discovered_findings == []
    # with no findings AND no probe-leaves, the cycle takes the no-op early return (nothing minted)
    assert not any(getattr(s, "is_probe", False) for s in out.cycles)

    # even with enable_discover=True but NO send injected, discovery cannot run (no probe I/O)
    out2 = run_autonomous_cycle(result, slug="disco", enable_discover=True, discover_send=None,
                                prompt_callback=_deny)
    assert out2.discover_enabled is False and out2.discovered_count == 0


# ---------------------------------------------------------------------------
# SLICE-0 KEYSTONE — a recon/sensor asset that is NOT an ENDPOINT (a SERVICE)
# is PROMOTED to a testable ENDPOINT and reaches the gated probe loop. This is
# the recon→test bridge: without promotion the loop sees nothing to probe.
# ---------------------------------------------------------------------------


def _service_world(hostkey: str, port: int) -> WorldModel:
    """A world with ONLY a web SERVICE node (as a sensor/nmap mints it — ``{hostkey}:{port}/{proto}``
    with a web service name) and an attacker foothold. Crucially NO ENDPOINT node exists, so the loop
    has nothing to probe UNTIL promotion mints one."""
    w = WorldModel()
    w.add_node(Node(id="attacker:self", kind=NodeKind.PRINCIPAL, attrs={"role": "attacker"},
                    provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))
    w.add_node(Node(id=f"service:{hostkey}:{port}/tcp", kind=NodeKind.SERVICE,
                    attrs={"port": port, "protocol": "tcp", "service": "http"},
                    provenance="intel:obs:svc", confidence=0.8, first_seen=1, last_seen=1))
    return w


def test_promotion_bridges_a_recon_service_into_the_probe_loop(
    isolated_engagement, httpserver: HTTPServer,
):
    """THE KEYSTONE: a world holding ONLY a recon/sensor SERVICE (no ENDPOINT) — the loop has nothing
    to probe. Promotion mints an in-scope ``endpoint:promoted:http://127.0.0.1:<port>/`` ENDPOINT,
    which then seeds a probe-leaf that the gated probe drives. Proves a *discovered* asset (not one a
    human pointed at) reaches the test loop. (A finding needs a query param to inject into — that
    arrives with in-loop crawl/mine expansion, Slice 2; here the bridge itself is the proof.)"""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_reflect)  # promoted root url is probed

    world = _service_world("127.0.0.1", port)
    # sanity: NO endpoint yet — the loop cannot see the service as a probe target
    assert not any(n.kind is NodeKind.ENDPOINT for n in world.all_nodes())

    out = run_autonomous_cycle(
        world_result := _result(world, []), slug="disco", enable_discover=True,
        discover_send=_loopback_send(), prompt_callback=_deny)

    # the SERVICE was promoted to a url-bearing ENDPOINT, which seeded a probe-leaf the gate let run
    assert out.endpoints_promoted == 1, "the in-scope recon SERVICE was not promoted to an endpoint"
    assert world.has_node(f"endpoint:promoted:http://127.0.0.1:{port}/")
    assert out.probe_leaves_seeded == 1, "the promoted endpoint did not seed a probe-leaf"
    assert out.probes_driven == 1 and out.probes_refused == 0, "the promoted endpoint was not probed"
    assert out.cycles and out.cycles[0].is_probe is True
    _ = world_result


def test_promotion_of_out_of_scope_service_is_refused(isolated_engagement):
    """An out-of-scope recon SERVICE (charter lists only 127.0.0.1) is NEVER promoted, so it seeds no
    probe-leaf and no traffic is attempted — in-scope-by-construction at the promotion layer, atop the
    fail-closed per-request gate."""
    isolated_engagement("disco", "127.0.0.1")

    def _no_send(_req):
        raise AssertionError("no send may occur for an out-of-scope asset")

    world = _service_world("10.9.9.9", 8080)   # out of scope
    out = run_autonomous_cycle(
        _result(world, []), slug="disco", enable_discover=True, discover_send=_no_send,
        prompt_callback=_deny)
    assert out.endpoints_promoted == 0
    assert out.probe_leaves_seeded == 0
    assert out.probes_driven == 0


def _root_links_to_search(request) -> Response:
    """The promoted root: an HTML page linking to a param-bearing /search page. Crawl-expansion follows
    the link and discovers /search?q=... as a new testable (injectable) surface."""
    return Response('<html><body><a href="/search?q=hello">search</a></body></html>',
                    status=200, mimetype="text/html")


def test_full_chain_service_to_crawl_to_param_to_minted_finding(
    isolated_engagement, httpserver: HTTPServer,
):
    """THE COMPOUNDING DISCOVERER, end to end: a world with ONLY a recon SERVICE (no ENDPOINT, no param
    anywhere) -> promotion mints the root endpoint -> crawl-expansion (Slice 2) discovers the real
    param-bearing /search?q= surface on it -> the gated probe injects q -> the reflection oracle FIRES
    -> a NEW oracle-confirmed finding is minted. Nothing here was pointed at by a human: the whole chain
    began from a single discovered service."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root_links_to_search)
    httpserver.expect_request("/search").respond_with_handler(_reflect)

    world = _service_world("127.0.0.1", port)
    assert not any(n.kind is NodeKind.ENDPOINT for n in world.all_nodes())

    out = run_autonomous_cycle(
        _result(world, []), slug="disco", max_cycles=3, enable_discover=True,
        enable_crawl_expand=True, discover_send=_loopback_send(), prompt_callback=_deny)

    assert out.endpoints_promoted == 1, "the recon SERVICE was not promoted"
    assert out.endpoints_expanded == 1, "crawl-expansion did not discover the param-bearing surface"
    assert world.has_node(f"endpoint:expand:http://127.0.0.1:{port}/search?q=hello")
    # the discovered param surface was probed and the oracle minted a NEW finding
    assert out.discovered_count >= 1, "the discovered param surface did not mint a finding"
    minted = [AuditFinding.model_validate(d) for d in out.discovered_findings]
    assert any(m.bug_class == "xss" and "/search" in m.endpoint for m in minted)


def test_crawl_expand_off_by_default_on_discover_path(isolated_engagement, httpserver: HTTPServer):
    """Crawl-expansion is opt-in ON TOP of discovery: with enable_crawl_expand unset, a promoted root is
    reached but NOT crawled — the existing discover behaviour is unchanged (byte-identical control)."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root_links_to_search)
    world = _service_world("127.0.0.1", port)
    out = run_autonomous_cycle(
        _result(world, []), slug="disco", enable_discover=True,   # enable_crawl_expand default False
        discover_send=_loopback_send(), prompt_callback=_deny)
    assert out.endpoints_promoted == 1
    assert out.endpoints_expanded == 0
    assert not world.has_node(f"endpoint:expand:http://127.0.0.1:{port}/search?q=hello")


def test_promotion_off_when_discovery_off(isolated_engagement, httpserver: HTTPServer):
    """Promotion runs ONLY on the opt-in discover path — with discovery off, a world full of recon
    SERVICE nodes promotes nothing and the authoritative report is untouched (byte-identical control)."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    world = _service_world("127.0.0.1", port)
    out = run_autonomous_cycle(_result(world, []), slug="disco", prompt_callback=_deny)  # discover OFF
    assert out.endpoints_promoted == 0
    assert not world.has_node(f"endpoint:promoted:http://127.0.0.1:{port}/")


# ---------------------------------------------------------------------------
# FAIL-CLOSED — the probe rides the full gate chain: an out-of-scope endpoint
# and a tripped kill-switch REFUSE it, and it mints nothing (no traffic).
# ---------------------------------------------------------------------------


def test_discovery_probe_refused_out_of_scope(isolated_engagement):
    """The ENDPOINT lead is on an out-of-scope host (charter only lists 127.0.0.1). The gated
    probe_surface call is REFUSED at the scope gate — the tool never runs, nothing is minted, and no
    traffic leaves the box (the send is never reached)."""
    isolated_engagement("disco", "127.0.0.1")

    def _no_send(_req):
        raise AssertionError("the send must never be reached for an out-of-scope probe")

    world = _endpoint_world("http://t.invalid/reflect?q=seed")
    out = run_autonomous_cycle(
        _result(world, []), slug="disco", enable_discover=True, discover_send=_no_send,
        prompt_callback=_deny)

    assert out.probe_leaves_seeded == 1
    assert out.probes_driven == 0 and out.probes_refused == 1
    assert out.discovered_count == 0
    assert out.cycles and out.cycles[0].is_probe is True
    assert out.cycles[0].refused is True and out.cycles[0].gate == "scope"


def test_discovery_probe_refused_by_tripped_killswitch(isolated_engagement, httpserver: HTTPServer):
    """A tripped kill-switch REFUSES the probe before it runs (the same fail-closed chain as
    reverify_finding) — nothing is discovered."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/reflect").respond_with_handler(_reflect)
    KillSwitch("disco").trip("operator stop")

    def _no_send(_req):
        raise AssertionError("the send must never be reached when the kill-switch is tripped")

    url = f"http://127.0.0.1:{port}/reflect?q=seed"
    out = run_autonomous_cycle(
        _result(_endpoint_world(url), []), slug="disco", enable_discover=True, discover_send=_no_send,
        prompt_callback=_deny)

    assert out.probes_driven == 0 and out.probes_refused == 1
    assert out.discovered_count == 0
    assert out.cycles and out.cycles[0].refused is True and out.cycles[0].gate == "kill-switch"


# ---------------------------------------------------------------------------
# a SAFE endpoint (no reflection) mints nothing — the oracle stays the authority
# ---------------------------------------------------------------------------


def test_discovery_on_a_safe_endpoint_mints_nothing(isolated_engagement, httpserver: HTTPServer):
    """The probe RUNS through the gate chain, but the endpoint does not reflect, so the check's
    oracle stays SILENT — no finding is minted. Proves the oracle (not the probe running) is what
    mints a finding."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/safe").respond_with_data(
        "<html><body>constant page</body></html>", content_type="text/html")

    url = f"http://127.0.0.1:{port}/safe?q=seed"
    out = run_autonomous_cycle(
        _result(_endpoint_world(url), []), slug="disco", enable_discover=True,
        discover_send=_loopback_send(), prompt_callback=_deny)

    assert out.probes_driven == 1 and out.probes_refused == 0   # the probe ran (not refused)
    assert out.discovered_count == 0                            # but the oracle did not fire
    assert out.cycles and out.cycles[0].is_probe is True and out.cycles[0].discovered_findings == 0


def _reflect_json(request) -> Response:
    """Reflects ``q`` verbatim but serves it as application/json — the marker lands in the body yet is
    NOT executable (a browser will not run HTML markup in a JSON response). This is the review's false
    XSS FACT: a reflecting JSON API that must NOT mint an XSS finding."""
    q = request.args.get("q", "")
    return Response(f'{{"results": "{q}"}}', status=200, mimetype="application/json")


def test_discovery_on_a_json_endpoint_mints_nothing(isolated_engagement, httpserver: HTTPServer):
    """Regression for the review's false XSS FACT [10]: a JSON API that echoes a query value reflects
    the marker inertly. The probe RUNS and the reflection is present, but the content-type gate (the
    reflection is not under text/html) drops it — nothing is minted (near-zero-FP)."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/api").respond_with_handler(_reflect_json)

    url = f"http://127.0.0.1:{port}/api?q=seed"
    out = run_autonomous_cycle(
        _result(_endpoint_world(url), []), slug="disco", enable_discover=True,
        discover_send=_loopback_send(), prompt_callback=_deny)

    assert out.probes_driven == 1 and out.probes_refused == 0   # the probe ran (not refused)
    assert out.discovered_count == 0                            # but the non-HTML reflection is inert


def _reflect_no_ctype(request) -> Response:
    """Reflects ``q`` verbatim but OMITS the Content-Type header entirely — a MIME-sniff-only
    reflection. Minting a confirmed XSS FACT on that ambiguity is exactly the near-zero-FP overclaim
    the gate must not make, so this must mint nothing."""
    q = request.args.get("q", "")
    r = Response('{"echo": "' + q + '"}', status=200)
    r.headers.remove("Content-Type")
    return r


def test_discovery_missing_content_type_mints_nothing(isolated_engagement, httpserver: HTTPServer):
    """A reflecting endpoint that omits Content-Type must NOT mint an XSS FACT — a missing type is not
    affirmatively HTML, and a confirmed FACT via auto-discovery needs the higher bar."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/nctype").respond_with_handler(_reflect_no_ctype)

    url = f"http://127.0.0.1:{port}/nctype?q=seed"
    out = run_autonomous_cycle(
        _result(_endpoint_world(url), []), slug="disco", enable_discover=True,
        discover_send=_loopback_send(), prompt_callback=_deny)
    assert out.probes_driven == 1 and out.discovered_count == 0


def _reflect_json_data_static_html_page(request) -> Response:
    """A multi-param endpoint: the ``data`` param reflects the marker under application/json (inert),
    while any other request returns a STATIC text/html page that does NOT reflect. Proves the gate keys
    on the REFLECTING response's content-type — an unrelated param's HTML page must not license the
    inert JSON reflection (the review's cross-contamination case)."""
    data = request.args.get("data", "")
    if "crucible" in data and "mark" in data:      # the data param carried the reflection marker
        return Response('{"results": "' + data + '"}', status=200, mimetype="application/json")
    return Response("<html><body>static page, no reflection</body></html>",
                    status=200, mimetype="text/html")


def test_discovery_multiparam_html_sibling_does_not_license_json_reflection(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/api").respond_with_handler(_reflect_json_data_static_html_page)

    url = f"http://127.0.0.1:{port}/api?data=seed&page=1"
    out = run_autonomous_cycle(
        _result(_endpoint_world(url), []), slug="disco", enable_discover=True,
        discover_send=_loopback_send(), prompt_callback=_deny)
    # the JSON reflection is inert; the sibling static HTML page carries no marker → nothing minted.
    assert out.probes_driven == 1 and out.discovered_count == 0


# ---------------------------------------------------------------------------
# SLICE-3 — the generalized probe: one probe tests a discovered surface for
# several near-zero-FP bug classes (not just XSS), each oracle-adjudicated.
# ---------------------------------------------------------------------------


def _passwd_on_traversal(request) -> Response:
    """A path-traversal sink: any ``file`` value containing a traversal / ``etc/passwd`` leaks the
    passwd signature. The PATH_TRAVERSAL content-signature oracle fires on ``root:x:0:0:``."""
    f = request.args.get("file", "")
    if "../" in f or "etc/passwd" in f:
        return Response("root:x:0:0:root:/root:/bin/bash\n", status=200, mimetype="text/plain")
    return Response("no such file", status=404, mimetype="text/plain")


def test_curated_probe_set_covers_multiple_classes():
    from framework.v2.agents.tools.builtin import curated_probe_checks
    bug_classes = {str(getattr(c, "bug_class", "")) for c in curated_probe_checks()}
    assert len(curated_probe_checks()) == 6
    assert "xss" in bug_classes
    assert any("redirect" in b for b in bug_classes)
    assert any("traversal" in b or "lfi" in b for b in bug_classes)


def test_multi_probe_mints_a_non_xss_class(isolated_engagement, httpserver: HTTPServer):
    """The generalized probe finds a PATH-TRAVERSAL on a discovered endpoint — a class the single XSS
    probe could never mint. Proves one probe now tests a surface for more than reflection-XSS."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/read").respond_with_handler(_passwd_on_traversal)

    url = f"http://127.0.0.1:{port}/read?file=seed"
    out = run_autonomous_cycle(
        _result(_endpoint_world(url), []), slug="disco", enable_discover=True,
        enable_multi_probe=True, discover_send=_loopback_send(), prompt_callback=_deny)

    assert out.probes_driven == 1 and out.probes_refused == 0
    assert out.discovered_count >= 1, "the curated probe did not mint the path-traversal finding"
    minted = [AuditFinding.model_validate(d) for d in out.discovered_findings]
    assert any("traversal" in m.bug_class or "lfi" in m.bug_class for m in minted)


def test_multi_probe_still_gates_xss_on_a_json_endpoint(isolated_engagement, httpserver: HTTPServer):
    """The per-check content-type gate survives generalization: a JSON API that echoes a value under the
    curated multi-check probe still mints NO XSS fact (the inert reflection is dropped)."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/api").respond_with_handler(_reflect_json)

    url = f"http://127.0.0.1:{port}/api?q=seed"
    out = run_autonomous_cycle(
        _result(_endpoint_world(url), []), slug="disco", enable_discover=True,
        enable_multi_probe=True, discover_send=_loopback_send(), prompt_callback=_deny)
    assert out.probes_driven == 1
    assert out.discovered_count == 0, "the multi-check probe minted a false XSS fact on a JSON reflection"


def test_multi_probe_still_mints_xss_on_html(isolated_engagement, httpserver: HTTPServer):
    """Regression: the curated set INCLUDES REFLECTED_XSS, so a genuine HTML reflection still mints an
    XSS fact under multi-probe (generalization did not drop the base case)."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/reflect").respond_with_handler(_reflect)
    url = f"http://127.0.0.1:{port}/reflect?q=seed"
    out = run_autonomous_cycle(
        _result(_endpoint_world(url), []), slug="disco", enable_discover=True,
        enable_multi_probe=True, discover_send=_loopback_send(), prompt_callback=_deny)
    minted = [AuditFinding.model_validate(d) for d in out.discovered_findings]
    assert any(m.bug_class == "xss" for m in minted)


# ---------------------------------------------------------------------------
# determinism — same inputs → same discovery outcome
# ---------------------------------------------------------------------------


def test_discovery_is_deterministic(isolated_engagement, httpserver: HTTPServer):
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/reflect").respond_with_handler(_reflect)
    url = f"http://127.0.0.1:{port}/reflect?q=seed"

    def run():
        out = run_autonomous_cycle(
            _result(_endpoint_world(url), []), slug="disco", enable_discover=True,
            discover_send=_loopback_send(), prompt_callback=_deny)
        return (out.probe_leaves_seeded, out.probes_driven, out.discovered_count,
                [(s.is_probe, s.tool, s.discovered_findings) for s in out.cycles])

    assert run() == run(), "the discovery cycle is not deterministic"


# ---------------------------------------------------------------------------
# W-F3 — the FOLD: discovered findings are spliced into the authoritative report,
# deterministically + deduped, and ONLY on the opt-in discover path.
# ---------------------------------------------------------------------------


def test_fold_is_replay_deterministic(isolated_engagement, httpserver: HTTPServer):
    """The whole discover cycle over the SAME live app + world replays to the SAME authoritative
    report — the folded active_findings are byte-for-byte identical across two runs (stable sort,
    deterministic minted evidence). This is the replay-determinism guarantee the fold must not break."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/reflect").respond_with_handler(_reflect)
    url = f"http://127.0.0.1:{port}/reflect?q=seed"

    def run_report() -> list:
        result = _result(_endpoint_world(url), [])
        run_autonomous_cycle(result, slug="disco", enable_discover=True,
                             discover_send=_loopback_send(), prompt_callback=_deny)
        return [f.model_dump() for f in result.report.active_findings]

    r1 = run_report()
    r2 = run_report()
    assert len(r1) == 1 and r1[0]["oracle_context"] is not None
    assert r1 == r2, "the folded report is not replay-deterministic"


def test_fold_dedup_does_not_double_count():
    """_fold_discovered_into_report DEDUPS a discovered finding that duplicates an EXISTING seed
    finding — total_findings / by_severity() never double-count. A genuinely-new discovered finding
    is appended; intra-set duplicates collapse; and the splice is in the stable
    (bug_class, endpoint, insertion_point) order regardless of the dumps' input order."""
    seed = _mk_finding("xss", "query:q", "http://127.0.0.1/a")
    report = ScanReport(target="http://127.0.0.1/", active_findings=[seed])

    dup = _mk_finding("xss", "query:q", "http://127.0.0.1/a")   # SAME key as the seed
    new = _mk_finding("sqli", "query:id", "http://127.0.0.1/b")
    new_again = _mk_finding("sqli", "query:id", "http://127.0.0.1/b")  # intra-set dup of `new`

    folded = _fold_discovered_into_report(
        SimpleNamespace(report=report),
        [dup.model_dump(), new.model_dump(), new_again.model_dump()],
    )
    assert folded == 1, "only the genuinely-new finding should fold in (dup + intra-dup dropped)"
    assert report.total_findings == 2, "the seed was double-counted"
    assert report.by_severity()["Confirmed"] == 2
    keys = [(f.bug_class, f.insertion_point, f.endpoint) for f in report.active_findings]
    assert keys == [
        ("xss", "query:q", "http://127.0.0.1/a"),     # the seed, untouched, still first
        ("sqli", "query:id", "http://127.0.0.1/b"),   # the one new finding, appended
    ]


def test_fold_splices_in_stable_sorted_order():
    """The discovered set is spliced in a STABLE (bug_class, endpoint, insertion_point) order,
    independent of the order the dumps arrive in — so the replayed report is order-stable."""
    report = ScanReport(target="t", active_findings=[])
    a = _mk_finding("xss", "query:z", "http://127.0.0.1/z")
    b = _mk_finding("sqli", "query:a", "http://127.0.0.1/a")
    c = _mk_finding("xss", "query:a", "http://127.0.0.1/a")
    # scrambled input order
    _fold_discovered_into_report(SimpleNamespace(report=report),
                                 [a.model_dump(), b.model_dump(), c.model_dump()])
    got = [(f.bug_class, f.endpoint, f.insertion_point) for f in report.active_findings]
    assert got == [
        ("sqli", "http://127.0.0.1/a", "query:a"),
        ("xss", "http://127.0.0.1/a", "query:a"),
        ("xss", "http://127.0.0.1/z", "query:z"),
    ], "the fold did not splice in the stable sorted order"


def test_fold_rejects_unconfirmed_finding():
    """PROVE-DON'T-GUESS: a discovered dump WITHOUT an oracle_context is never spliced — the fold
    keeps active_findings a prove-don't-guess set."""
    report = ScanReport(target="t", active_findings=[])
    unconfirmed = _mk_finding("xss", "query:q", "http://127.0.0.1/u", oracle=False)
    folded = _fold_discovered_into_report(SimpleNamespace(report=report), [unconfirmed.model_dump()])
    assert folded == 0
    assert list(report.active_findings) == []


def test_fold_off_report_byte_identical_and_unreachable_from_gate(
    isolated_engagement, httpserver: HTTPServer,
):
    """BYTE-IDENTICAL: with discovery OFF (the default) the fold never runs, so a report that already
    carries a seed finding is left byte-for-byte unchanged (no splice, no re-order, no dedup pass).
    And the fold lives inside run_autonomous_cycle, which the byte-identical benchmark/gate path NEVER
    calls — pinned here so the fold stays structurally unreachable from the gate."""
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/reflect").respond_with_handler(_reflect)
    url = f"http://127.0.0.1:{port}/reflect?q=seed"

    seed = _mk_finding("xss", "query:q", url)
    result = _result(_endpoint_world(url), [seed])
    before = [f.model_dump() for f in result.report.active_findings]
    out = run_autonomous_cycle(result, slug="disco", prompt_callback=_deny)  # enable_discover default OFF
    after = [f.model_dump() for f in result.report.active_findings]
    assert out.findings_folded == 0
    assert out.discover_enabled is False
    assert before == after, "discovery-off mutated the authoritative report"

    # PIN — the fold host (run_autonomous_cycle) and the fold itself are absent from the benchmark
    # gate module the `benchmark --gate` path runs (it drives WebScanCampaign directly, never the
    # autonomous cycle), so the fold can never touch the byte-identical benchmark path.
    import framework.v2.eval.benchmark_run as _bench
    bench_src = Path(_bench.__file__).read_text(encoding="utf-8")
    assert "run_autonomous_cycle" not in bench_src
    assert "_fold_discovered_into_report" not in bench_src
    assert "engage_autonomous" not in bench_src
