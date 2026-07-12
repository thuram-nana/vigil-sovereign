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
  * the authoritative ScanReport is left UNTOUCHED (discovered facts land on the AutonomyResult).

Loopback-only (pytest_httpserver / urllib to 127.0.0.1); nothing leaves the test host.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2.common import paths as _paths
from framework.v2.authority.killswitch import KillSwitch
from framework.v2.engage import EngagementResult
from framework.v2.engage_autonomous import run_autonomous_cycle
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

    # NOT in the seed set — this is genuinely NEW, not a re-report of a confirmed finding
    seed_ids = {(f.bug_class, f.insertion_point, f.endpoint) for f in result.report.active_findings}
    assert (minted.bug_class, minted.insertion_point, minted.endpoint) not in seed_ids

    # the authoritative ScanReport is left UNTOUCHED (conservative boundary)
    assert list(result.report.active_findings) == [], "discovery mutated the authoritative report"


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
