"""AEGIS AS-18a (the deterministic read-only 1b OBSERVE view) — deterministic, offline acceptance tests.

AS-18a is the OBSERVE leg of deployment path 1b (AEGIS consumes the tenant's OWN existing CDN/WAF telemetry;
the enforcement point stays at the tenant's edge). It is a read-only VIEW that UNIFIES its three merged deps:
the AS-9b receiver (the RECEIVED EVENTS — a path-1b edge finding's ``source`` + ``rule_refs``), the AS-31
detection mirror (the REFLECTION — ``DetectionMirrorMeter.reflect`` / ``.summary``), and the AS-4b contract
evaluator (the GRADE — ``headline_floor`` over the Headline ladder). It DETECTS (which received findings
become admissible leads) and REPORTS (the graded observe posture), and it NEVER blocks (the 1b ENFORCE leg is
the separate AS-18b slice). The DoD points, mapped to the sections below:

  (1) e2e behavioral — a configured gateway with the flag ON (and the AS-31 dep + a CRS corpus) surfaces the
      1b observe view on the AS-5c probe snapshot, graded end-to-end through the gateway.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at 15 (AS-18a adds NO OracleKind);
      observe_1b.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__; the env is in lockstep.
  (3) FATAL-2 — observe_1b.py imports ONLY the stdlib at MODULE scope (reaching AS-4b by a LAZY import and the
      AS-31 mirror by COMPOSITION); never sigil/governor/strix/apps.
  (4) determinism — identical mirror posture + events yield a byte-identical view and digest; no wall-clock, RNG.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_OBSERVE_1B off (or the AS-31 dep off, or NO corpus) => NO meter
      is active, nothing is computed, and the probe snapshot is byte-identical (no observe_1b keys); strict flag.
  (6) correctness + negative controls — leads track the admissible CRS content reflected per event; the headline
      is AS-4b's floor; a drifted/unlicensed corpus is DETECTED (content inadmissible) and caps the headline at
      ``degraded`` while dropping every lead; the digest MOVES on any posture change.
  (7) observe-only / read-only — the view NEVER mutates the injected mirror/inventory/ledger/corpus, NEVER drives
      an admit/shed/allow/block decision, carries no block/enforce semantics, and the headline never reaches
      ``enforcing``; a reflected finding is a LEAD.
  (8) fail-closed + no-leak — an EMPTY intake, an UNCATALOGED source, and INADMISSIBLE content all raise NO lead;
      the view is ADDRESS-FREE (a dotted-quad ref is dropped by the AS-31 hygiene gate) and bounded/sorted/deduped.

Everything is a pure function of its inputs; no real secret and no network beyond the loopback gateway/upstream.
"""
from __future__ import annotations

import ast
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from framework.v2.aegis import observe_1b as OB
from framework.v2.aegis.coraza_source import CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT, CorazaAttestationMeter, CorazaCorpus
from framework.v2.aegis.detection_mirror import DetectionMirrorMeter
from framework.v2.aegis.license_gate import LicenseRecord, load_ledger
from framework.v2.aegis.license_policy import UseMode
from framework.v2.aegis.observe_1b import (
    OBSERVE_1B_ENV,
    Observe1bMeter,
    Observe1bView,
    ReceivedEvent,
    observe_1b_digest,
    observe_1b_enabled,
)
from framework.v2.aegis.provider_runtime import build_provider_runtime_registry


def _corpus(rule_ids=("942100", "941110", "932160"), *, version="4.3.0", paranoia=1, expected_pin=None):
    return CorazaCorpus.build(version=version, paranoia=paranoia, rule_ids=rule_ids, expected_pin=expected_pin)


def _shipped_ledger():
    return load_ledger()


def _mirror(corpus=None, *, ledger=None, inventory=None, redact_literals=()):
    corp = corpus if corpus is not None else _corpus()
    cm = CorazaAttestationMeter(corp, ledger=ledger if ledger is not None else _shipped_ledger())
    return DetectionMirrorMeter(cm, corp.rule_ids, inventory=inventory, redact_literals=redact_literals)


def _meter(corpus=None, **kw):
    return Observe1bMeter(_mirror(corpus, **kw))


# ==================================================================================================
# (6) correctness — leads track the admissible CRS content reflected per received event; AS-4b headline.
# ==================================================================================================
def test_observe_reflects_received_events_into_admissible_leads():
    ob = _meter()
    events = [
        ReceivedEvent(source="cloudtrail", rule_refs=("942100", "941110")),
        ReceivedEvent(source="edr", rule_refs=("932160",)),
    ]
    view = ob.observe(events)
    assert view.events_observed == 2 and view.lead_events == 2
    assert view.leads == ("932160", "941110", "942100")                      # admitted, sorted, de-duplicated
    assert view.lead_count == 3 and view.content_admissible is True and view.clean is True
    assert view.headline == "observing"                                      # AS-4b floor: every axis observing


def test_headline_is_the_as4b_floor_over_the_observe_axes():
    from vigil_core.contract_eval import headline_floor
    from vigil_core.protection_contract import Headline

    ob = _meter()
    # events present, at least one lead => intake axis observing => floor(observing, observing, observing)
    view = ob.observe([ReceivedEvent(source="edr", rule_refs=("942100",))])
    assert view.headline == headline_floor([Headline.OBSERVING, Headline.OBSERVING, Headline.OBSERVING]).value


def test_events_received_but_none_admissible_grades_unverified():
    """Telemetry arrived, but every hit is from an uncataloged source => no admissible lead => the intake axis
    is ``unverified`` (active + observing, but nothing corroborated through admissible content)."""
    ob = _meter()
    view = ob.observe([ReceivedEvent(source="not-a-provider", rule_refs=("942100",))])
    assert view.events_observed == 1 and view.lead_events == 0 and view.leads == ()
    assert view.headline == "unverified"


def test_source_count_tracks_the_as30_catalog_through_the_mirror():
    inv_ids = sorted(set(build_provider_runtime_registry().provider_ids))
    view = _meter().observe([ReceivedEvent(source="edr", rule_refs=("942100",))])
    assert view.source_count == len(inv_ids)


def test_accepts_plain_mapping_events_too():
    ob = _meter()
    view = ob.observe([{"source": "cloudtrail", "rule_refs": ["941110"]}, {"source": "edr", "rule_refs": ["932160"]}])
    assert view.leads == ("932160", "941110") and view.lead_events == 2


# ==================================================================================================
# (8) fail-closed — empty intake, uncataloged source, inadmissible content all raise NO lead.
# ==================================================================================================
def test_empty_intake_raises_no_lead_and_grades_the_standing_posture():
    """Fail-closed on an empty intake: no events => no leads; the headline grades the STANDING plane only
    (sources x content), which is ``observing`` over an admissible corpus (no intake axis to cap it)."""
    view = _meter().observe(())
    assert view.events_observed == 0 and view.lead_events == 0 and view.leads == () and view.lead_count == 0
    assert view.headline == "observing" and view.content_admissible is True


def test_uncataloged_source_raises_no_belief():
    ob = _meter()
    view = ob.observe([ReceivedEvent(source="", rule_refs=("942100",)),
                       ReceivedEvent(source="rogue", rule_refs=("941110",))])
    assert view.lead_events == 0 and view.leads == ()


def test_a_drifted_corpus_caps_the_headline_at_degraded_and_drops_every_lead():
    """A corpus whose live content no longer matches its pin is NOT admissible => content_admissible False =>
    NO leads are reflected even from a cataloged source, and the content axis caps the headline at ``degraded``
    (the AS-7b/AS-4b fail-closed stance)."""
    drifted = _corpus(rule_ids=("942100", "941110"), expected_pin="deadbeef" * 8)
    view = _meter(drifted).observe([ReceivedEvent(source="edr", rule_refs=("942100",))])
    assert view.content_admissible is False and view.leads == () and view.lead_count == 0
    assert view.headline == "degraded"


def test_a_missing_crs_licence_caps_the_headline_at_degraded():
    ledger = [r for r in _shipped_ledger() if r.artefact != CRS_CORPUS_ARTEFACT]
    view = _meter(ledger=ledger).observe([ReceivedEvent(source="edr", rule_refs=("942100",))])
    assert view.content_admissible is False and view.leads == () and view.headline == "degraded"


def test_a_policy_denied_crs_licence_caps_the_headline_at_degraded():
    ledger = [r for r in _shipped_ledger() if r.artefact not in (CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT)]
    ledger.append(LicenseRecord(artefact=WAF_ENGINE_ARTEFACT, license="Apache-2.0", use_mode=UseMode.SERVICE))
    ledger.append(LicenseRecord(artefact=CRS_CORPUS_ARTEFACT, component_kind="rule", license="SSPL-1.0",
                                use_mode=UseMode.SERVICE))
    view = _meter(ledger=ledger).observe([ReceivedEvent(source="edr", rule_refs=("942100",))])
    assert view.content_admissible is False and view.headline == "degraded"


def test_no_cataloged_sources_grades_unsupported():
    """An empty provider inventory (no detection SOURCES) caps the source axis at ``unsupported`` — the surface
    is not covered, the fail-closed floor."""
    class _EmptyReg:
        provider_ids = ()
    view = _meter(inventory=_EmptyReg()).observe([ReceivedEvent(source="edr", rule_refs=("942100",))])
    assert view.source_count == 0 and view.leads == () and view.headline == "unsupported"


# ==================================================================================================
# (8) no-leak — ADDRESS-FREE: an IP-shaped ref is dropped by the AS-31 hygiene gate; bounded/sorted/deduped.
# ==================================================================================================
def test_an_ip_shaped_rule_ref_is_dropped_from_the_view():
    ob = _meter()
    view = ob.observe([ReceivedEvent(source="edr", rule_refs=("203.0.113.9", "942100"))])
    assert view.leads == ("942100",)
    assert "203.0.113.9" not in json.dumps(view.to_dict())


def test_a_secret_literal_in_a_ref_is_dropped_from_the_view():
    ob = _meter(redact_literals=("S3CRET",))
    view = ob.observe([ReceivedEvent(source="edr", rule_refs=("S3CRET", "942100"))])
    assert view.leads == ("942100",) and "S3CRET" not in json.dumps(view.to_dict())


def test_the_lead_set_is_bounded_sorted_and_deduplicated():
    # Each reflect() admits at most 32 refs (the AS-7b per-hit cap), so three events carrying DISJOINT 32-ref
    # sets (96 distinct) exercise the view's own _MAX_LEADS=64 union bound.
    ob = _meter()
    events = [ReceivedEvent(source="edr", rule_refs=tuple(str(900000 + base + i) for i in range(32)))
              for base in (0, 100, 200)]
    view = ob.observe(events)
    assert view.lead_count == OB._MAX_LEADS and list(view.leads) == sorted(view.leads)
    assert len(set(view.leads)) == view.lead_count                           # de-duplicated


def test_the_event_fan_in_is_bounded():
    ob = _meter()
    flood = [ReceivedEvent(source="edr", rule_refs=("942100",)) for _ in range(OB._MAX_EVENTS + 100)]
    view = ob.observe(flood)
    assert view.events_observed == OB._MAX_EVENTS


def test_the_view_is_metadata_only_and_carries_no_address():
    view = _meter(_corpus(rule_ids=("942100", "10.0.0.1", "941110"))).observe(
        [ReceivedEvent(source="edr", rule_refs=("942100", "10.0.0.1"))])
    blob = json.dumps(view.to_dict())
    assert "10.0.0.1" not in blob and view.clean is True


# ==================================================================================================
# (7) observe-only / read-only — a VIEW is a measurement, never a block/verdict; never claims enforcing.
# ==================================================================================================
def test_the_view_carries_no_block_or_enforce_semantics():
    ob = _meter()
    blob = json.dumps(ob.observe([ReceivedEvent(source="edr", rule_refs=("942100",))]).to_dict())
    for forbidden in ("certificate", "verdict", "decision", "action", "block", "enforce", "shed", "allow"):
        assert forbidden not in blob


def test_the_headline_is_structurally_capped_at_observing():
    """Across every posture the view can reach (healthy, degraded, unverified, unsupported), the graded
    headline is NEVER ``enforcing`` — the observe leg claims at most ``observing`` (the 1b ENFORCE leg is
    AS-18b)."""
    postures = [
        _meter().observe([ReceivedEvent(source="edr", rule_refs=("942100",))]),          # observing
        _meter().observe(()),                                                             # observing (standing)
        _meter().observe([ReceivedEvent(source="rogue", rule_refs=("942100",))]),         # unverified
        _meter(_corpus(rule_ids=("942100",), expected_pin="00" * 32)).observe(            # degraded
            [ReceivedEvent(source="edr", rule_refs=("942100",))]),
    ]
    for view in postures:
        assert view.headline != "enforcing"


def test_meter_never_mutates_the_injected_mirror_inventory_ledger_or_corpus():
    ledger = _shipped_ledger()
    before_ledger = [r.model_dump() for r in ledger]
    corp = _corpus()
    before_corpus = (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin)
    inv = build_provider_runtime_registry()
    before_inv = inv.provider_ids
    cm = CorazaAttestationMeter(corp, ledger=ledger)
    ob = Observe1bMeter(DetectionMirrorMeter(cm, corp.rule_ids, inventory=inv))
    for _ in range(50):
        ob.snapshot()
        ob.observe([ReceivedEvent(source="edr", rule_refs=("942100", "203.0.113.9"))])
    assert [r.model_dump() for r in ledger] == before_ledger
    assert (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin) == before_corpus
    assert inv.provider_ids == before_inv


# ==================================================================================================
# (4) determinism — identical inputs yield a byte-identical view and digest; the digest moves on change.
# ==================================================================================================
def test_identical_inputs_yield_a_byte_identical_view():
    events = [ReceivedEvent(source="cloudtrail", rule_refs=("942100",)), ReceivedEvent(source="edr", rule_refs=("932160",))]

    def _run() -> str:
        return json.dumps(_meter().observe(events).to_dict(), sort_keys=True)

    assert _run() == _run()


def test_view_is_a_pure_typed_dataclass():
    view = _meter().observe([ReceivedEvent(source="edr", rule_refs=("942100",))])
    assert isinstance(view, Observe1bView)
    assert len(view.digest) == 64 and view.lead_count == len(view.leads)


def test_digest_moves_on_any_posture_change():
    base = observe_1b_digest("observing", 3, True, ["942100"], 1, 1)
    assert base != observe_1b_digest("degraded", 3, True, ["942100"], 1, 1)        # headline changed
    assert base != observe_1b_digest("observing", 4, True, ["942100"], 1, 1)       # a source added
    assert base != observe_1b_digest("observing", 3, False, ["942100"], 1, 1)      # content flips inadmissible
    assert base != observe_1b_digest("observing", 3, True, ["942100", "941110"], 1, 1)  # a lead added
    assert base != observe_1b_digest("observing", 3, True, ["942100"], 2, 1)       # another event observed
    assert base != observe_1b_digest("observing", 3, True, ["942100"], 1, 0)       # the lead-event tally moved


def test_digest_is_order_and_duplicate_invariant_over_leads():
    a = observe_1b_digest("observing", 2, True, ["942100", "941110"], 1, 1)
    b = observe_1b_digest("observing", 2, True, ["941110", "942100", "942100"], 1, 1)
    assert a == b


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_observe_1b_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(OBSERVE_1B_ENV, raising=False)
    assert observe_1b_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(OBSERVE_1B_ENV, on)
        assert observe_1b_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(OBSERVE_1B_ENV, off)
        assert observe_1b_enabled() is False, off


# ==================================================================================================
# (2) gate-invariance — AS-18a adds NO OracleKind; observe_1b.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                        # a view is a measurement, not an oracle


def test_observe_1b_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                              # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.observe_1b' not in sys.modules, "
        "'observe_1b.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env, capture_output=True, text=True)
    assert out.returncode == 0, f"observe_1b reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_observe_1b_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.OBSERVE_1B_ENV == OBSERVE_1B_ENV == "VIGIL_AEGIS_OBSERVE_1B"


# ==================================================================================================
# (3) FATAL-2 — observe_1b.py imports ONLY the stdlib at MODULE scope (AS-4b lazy, AS-31 by composition).
# ==================================================================================================
def test_observe_1b_imports_only_stdlib_at_module_scope_and_reaches_as4b_lazily():
    src = Path(OB.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    # All absolute import roots anywhere in the file: never an offense/engine root.
    all_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            all_roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            all_roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps"):
        assert forbidden not in all_roots, f"observe_1b must never import {forbidden!r} (FATAL-2)"
    # MODULE-SCOPE imports (the eager import plane) are STDLIB ONLY — AS-4b (vigil_core) is reached by a LAZY
    # import, so it must NOT appear at module scope.
    module_scope: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            module_scope |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            module_scope.add((node.module or "").split(".")[0])
    allowed = {"__future__", "hashlib", "json", "os", "dataclasses", "typing"}
    assert module_scope <= allowed, f"non-stdlib import at module scope: {sorted(module_scope - allowed)}"
    assert "vigil_core" not in module_scope, "AS-4b (vigil_core) must be reached by a LAZY import, off the eager plane"
    # AS-4b IS reached — by a function-local (lazy) absolute import of vigil_core.
    assert "vigil_core" in all_roots, "observe_1b must grade through AS-4b (vigil_core.contract_eval)"
    # AS-31 is reached by COMPOSITION (an injected meter), NOT a runtime import: the only relative import is
    # the TYPE_CHECKING type-only one, which never runs.
    runtime_rel = {(n.module or "") for n in ast.walk(tree)
                   if isinstance(n, ast.ImportFrom) and n.level == 1 and not _under_type_checking(tree, n)}
    assert runtime_rel == set(), f"observe_1b reaches AS-31 by composition, not a runtime import: {sorted(runtime_rel)}"


def _under_type_checking(tree: ast.Module, target: ast.ImportFrom) -> bool:
    """True iff ``target`` lives inside an ``if TYPE_CHECKING:`` block (never executed at runtime)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            is_tc = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
            if is_tc and any(target is sub for sub in ast.walk(node)):
                return True
    return False


# ==================================================================================================
# (1)/(5) gateway integration — end-to-end through the live gateway over real loopback sockets.
# ==================================================================================================
class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def _reply(self):
        body = b"UPSTREAM-OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _run_gateway(upstream_port: int, *, coraza_corpus=None):
    from framework.v2.aegis.gateway import serve_gateway
    from framework.v2.aegis.models import AegisConfig
    cfg = AegisConfig(deployment_secret="k", mode="observe")
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       coraza_corpus=coraza_corpus)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)   # noqa: S310
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_gateway_observe_1b_off_builds_no_meter_and_probe_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_OBSERVE_1B unset (the AS-31 dep + corpus on) => NO active meter,
    the data path still forwards, and the probe snapshot carries NO observe_1b keys."""
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "1")
    monkeypatch.delenv(OBSERVE_1B_ENV, raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.observe_1b_meter is None
        assert gw.settings.observe_1b_active is False
        assert [_get(port, "/x")[0] for _ in range(3)] == [200] * 3
        snap = gw.settings._probe_snapshot()
        assert "observe_1b" not in snap and "observe_1b_active" not in snap
        assert "detection_mirror" in snap                                   # the AS-31 dep is unaffected
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_observe_1b_inert_without_the_detection_mirror_dep(upstream, monkeypatch):
    """The view is inert whenever its AS-31 dep is off: flag on, but VIGIL_AEGIS_DETECTION_MIRROR off => no
    mirror meter => no observe-1b meter, no probe keys."""
    monkeypatch.setenv(OBSERVE_1B_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.delenv("VIGIL_AEGIS_DETECTION_MIRROR", raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.observe_1b_meter is None and gw.settings.observe_1b_active is False
        assert "observe_1b" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_observe_1b_on_but_no_corpus_is_inert(upstream, monkeypatch):
    """No CRS corpus configured => the AS-31 dep is inert => no mirror meter => no observe-1b meter."""
    monkeypatch.setenv(OBSERVE_1B_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        assert gw.settings.observe_1b_meter is None and gw.settings.observe_1b_active is False
        assert "observe_1b" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_observe_1b_on_surfaces_the_view_on_the_probe_snapshot(upstream, monkeypatch):
    """Flag ON + the AS-31 dep ON + a CRS corpus => the probe snapshot surfaces the 1b observe view graded over
    the AS-31 mirror, metadata-only (a headline + counts + a digest, never request bytes)."""
    monkeypatch.setenv(OBSERVE_1B_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.observe_1b_meter is not None and gw.settings.observe_1b_active is True
        for _ in range(3):
            assert _get(port, "/x")[0] == 200                               # data path forwards unchanged
        snap = gw.settings._probe_snapshot()
        assert snap["observe_1b_active"] is True
        v = snap["observe_1b"]
        assert v["content_admissible"] is True and v["clean"] is True
        assert v["headline"] == "observing" and v["headline"] != "enforcing"
        assert v["events_observed"] == 0 and v["lead_count"] == 0            # standing posture (no intake)
        assert len(v["digest"]) == 64
        assert "127.0.0.1" not in json.dumps(snap)                          # NO raw caller/upstream address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_observe_1b_flip_off_at_runtime_stops_surfacing(upstream, monkeypatch):
    """Flipping VIGIL_AEGIS_OBSERVE_1B (or the AS-31 dep) OFF at runtime makes the view go inert live, so the
    probe answer drops the observe_1b keys again."""
    monkeypatch.setenv(OBSERVE_1B_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        _get(port, "/x")
        assert "observe_1b" in gw.settings._probe_snapshot()
        monkeypatch.setenv(OBSERVE_1B_ENV, "0")
        assert gw.settings.observe_1b_active is False
        assert "observe_1b" not in gw.settings._probe_snapshot()
        monkeypatch.setenv(OBSERVE_1B_ENV, "1")
        assert "observe_1b" in gw.settings._probe_snapshot()                # restored -> surfaced again
        monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "0")             # the dep going off also makes it inert
        assert "observe_1b" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_probe_without_corpus_is_byte_identical_whether_flag_on_or_off(upstream, monkeypatch):
    """The strongest OFF-invariance: with NO corpus configured, the probe snapshot is byte-identical whether the
    observe-1b flag is on or off (AS-18a never touches the data path or the probe without its dependency)."""
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        monkeypatch.delenv(OBSERVE_1B_ENV, raising=False)
        off = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        monkeypatch.setenv(OBSERVE_1B_ENV, "1")
        on = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        assert off == on
    finally:
        gw.shutdown(); gw.server_close()
