"""AEGIS AS-11a (the deterministic read-only DETECTION-LEAD CORRELATION into INCIDENT records) — deterministic,
offline acceptance tests.

AS-11a is a read-only correlation that groups the AS-31 mirror's admissible reflected LEADS (reached by
COMPOSITION) into a bounded, address-free, de-duplicated set of INCIDENT records keyed by their AS-8 detection
TECHNIQUE (reached by a LAZY RELATIVE import of the AS-8 band classifier), over a recency window, with a
deterministic posture digest; when an AS-5b denial-source rollup is armed, its aggregate denial pressure is carried
beside the incidents as read-only CONTEXT. It is not a detector, so DoD-1's "detector near-zero-FP" is N/A; it is
substituted by correlation-correctness vs a hand-computed expectation + a byte-identity negative control. The DoD
points, mapped to the sections below:

  (1) e2e behavioral — a configured gateway with the flag ON (AS-31 + AS-7b armed, a CRS corpus) surfaces the
      incident correlation on the AS-5c probe snapshot, computed from the mirror's admissible reflected leads,
      end-to-end through the gateway.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-11a adds NO
      OracleKind); incidents.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__; gateway.
      INCIDENTS_ENV is in lockstep.
  (3) FATAL-2 — incidents.py imports ONLY the stdlib (reaching detection_coverage / monitoring_event_v2 by RELATIVE
      import, the AS-31 mirror and AS-5b rollup by injection / type-only relative import); never sigil/governor/
      strix/apps/vigil_core.
  (4) determinism — identical mirror reflection yields a byte-identical incident set and posture digest; no
      wall-clock, no RNG; the optional AS-5b pressure is live context and is kept OUT of the digest.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_INCIDENTS off (or the AS-31 dep off, or NO corpus) => NO meter is
      active, nothing is computed, and the probe snapshot is byte-identical (no incidents keys); strict/fail-closed
      flag.
  (6) correctness + negative controls — the incidents group the admissible CRS content by AS-8 technique; the
      digest matches a hand-computed canonical digest; a drifted/unlicensed corpus is DETECTED (admissible=False)
      and yields NO incidents; the digest MOVES on any posture change; a correlation is NOT a block/verdict.
  (7) read-only — AS-11a NEVER mutates the injected inventory, the licence ledger, or the corpus, and NEVER drives
      an admit/shed/allow/block decision; only a fired oracle blocks; a correlated incident is a LEAD.
  (8) no-leak — summary/correlate are ADDRESS-FREE and bounded/sorted/de-duplicated; a dotted-quad that survives
      the AS-7b charset scrub is DROPPED by the AS-2e hygiene gate; an uncataloged source and inadmissible content
      both fail closed; an empty intake yields an empty incident set.

Everything is a pure function of its inputs; no real secret and no network beyond the loopback gateway/upstream.
"""
from __future__ import annotations

import ast
import hashlib
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import types
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from framework.v2.aegis import incidents as INC
from framework.v2.aegis.coraza_source import CorazaAttestationMeter, CorazaCorpus
from framework.v2.aegis.detection_mirror import DetectionMirrorMeter
from framework.v2.aegis.incidents import (
    INCIDENTS_ENV,
    Incident,
    IncidentMeter,
    IncidentPosture,
    incidents_enabled,
    posture_digest,
)
from framework.v2.aegis.license_gate import LicenseRecord, load_ledger
from framework.v2.aegis.license_policy import UseMode
from framework.v2.aegis.provider_runtime import build_provider_runtime_registry


def _corpus(rule_ids=("942100", "942200", "941110", "932160"), *, version="4.3.0", paranoia=1, expected_pin=None):
    return CorazaCorpus.build(version=version, paranoia=paranoia, rule_ids=rule_ids, expected_pin=expected_pin)


def _shipped_ledger():
    return load_ledger()


def _mirror(corpus=None, *, ledger=None, inventory=None, redact_literals=()):
    corp = corpus if corpus is not None else _corpus()
    cm = CorazaAttestationMeter(corp, ledger=ledger if ledger is not None else _shipped_ledger())
    return DetectionMirrorMeter(cm, corp.rule_ids, inventory=inventory, redact_literals=redact_literals)


def _meter(corpus=None, *, ledger=None, inventory=None, redact_literals=(), attribution=None, window=INC._MAX_WINDOW):
    mir = _mirror(corpus, ledger=ledger, inventory=inventory, redact_literals=redact_literals)
    return IncidentMeter(mir, attribution_meter=attribution, redact_literals=redact_literals, window=window)


# ==================================================================================================
# (6) correctness — incidents group the admissible CRS content by the AS-8 technique.
# ==================================================================================================
def test_incidents_group_the_admissible_content_by_as8_technique():
    post = _meter(_corpus(rule_ids=["942100", "942200", "941110", "932160"])).summary()
    assert post.admissible is True and post.clean is True
    by_key = {inc.key: inc for inc in post.incidents}
    assert set(by_key) == {"sqli", "xss", "rce"}                              # the AS-8 band taxonomy keys
    assert by_key["sqli"].leads == ("942100", "942200") and by_key["sqli"].lead_count == 2
    assert by_key["xss"].leads == ("941110",)
    assert by_key["rce"].leads == ("932160",)
    assert post.lead_count == 4 and post.incident_count == 3
    # incidents are sorted by key, de-duplicated, and each digest is a 64-hex incident id.
    assert list(post.incidents) == sorted(post.incidents, key=lambda i: i.key)
    assert all(len(inc.digest) == 64 for inc in post.incidents)


def test_posture_sources_reflect_the_as30_catalog_content_derived():
    inv_ids = sorted(set(build_provider_runtime_registry().provider_ids))
    post = _meter().summary()
    assert list(post.sources) == inv_ids                                      # the cataloged detection sources
    # content-derived: a content lead is tied to no observed source, so each incident's sources is ().
    assert all(inc.sources == () for inc in post.incidents)


def test_digest_matches_a_hand_computed_canonical_digest():
    post = _meter(_corpus(rule_ids=["942100", "941110"])).summary()
    incidents = [
        Incident(key="sqli", leads=("942100",), lead_count=1, sources=(), weight=1, digest=""),
        Incident(key="xss", leads=("941110",), lead_count=1, sources=(), weight=1, digest=""),
    ]
    payload = {
        "admissible": True,
        "incidents": [
            {"key": "sqli", "leads": ["942100"], "sources": [], "weight": 1},
            {"key": "xss", "leads": ["941110"], "sources": [], "weight": 1},
        ],
    }
    expect = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    assert posture_digest(True, incidents) == expect
    assert post.digest == expect


def test_posture_digest_is_order_and_duplicate_invariant():
    a = posture_digest(True, [
        Incident("sqli", ("942100", "942200"), 2, ("edr",), 2, ""),
        Incident("xss", ("941110",), 1, ("idp",), 1, ""),
    ])
    b = posture_digest(True, [
        Incident("xss", ("941110",), 1, ("idp",), 1, ""),                      # reordered
        Incident("sqli", ("942200", "942100", "942100"), 2, ("edr", "edr"), 2, ""),  # duplicate leads/sources
    ])
    assert a == b


def test_digest_moves_on_any_posture_change():
    base = posture_digest(True, [Incident("sqli", ("942100",), 1, (), 1, "")])
    assert base != posture_digest(False, [Incident("sqli", ("942100",), 1, (), 1, "")])   # content inadmissible
    assert base != posture_digest(True, [Incident("sqli", ("942100", "942200"), 2, (), 2, "")])  # a lead added
    assert base != posture_digest(True, [Incident("xss", ("942100",), 1, (), 1, "")])     # key changed
    assert base != posture_digest(True, [Incident("sqli", ("942100",), 1, ("edr",), 1, "")])  # a source added
    assert base != posture_digest(True, [Incident("sqli", ("942100",), 1, (), 3, "")])     # weight changed
    assert base != posture_digest(True, ())                                                # incident dropped


# ==================================================================================================
# (6) negative controls — a drifted / unlicensed corpus is DETECTED and yields NO incidents (fail closed).
# ==================================================================================================
def test_a_drifted_corpus_is_detected_and_yields_no_incidents():
    drifted = _corpus(rule_ids=["942100", "941110"], expected_pin="deadbeef" * 8)
    post = _meter(drifted).summary()
    assert post.admissible is False and post.incidents == () and post.incident_count == 0
    assert post.lead_count == 0 and post.observations == 0


def test_a_missing_crs_licence_record_yields_no_incidents():
    from framework.v2.aegis.coraza_source import CRS_CORPUS_ARTEFACT
    ledger = [r for r in _shipped_ledger() if r.artefact != CRS_CORPUS_ARTEFACT]
    post = _meter(ledger=ledger).summary()
    assert post.admissible is False and post.incidents == ()


def test_a_policy_denied_crs_licence_yields_no_incidents():
    from framework.v2.aegis.coraza_source import CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT
    ledger = [r for r in _shipped_ledger() if r.artefact not in (CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT)]
    ledger.append(LicenseRecord(artefact=WAF_ENGINE_ARTEFACT, license="Apache-2.0", use_mode=UseMode.SERVICE))
    ledger.append(LicenseRecord(artefact=CRS_CORPUS_ARTEFACT, component_kind="rule", license="SSPL-1.0",
                                use_mode=UseMode.SERVICE))
    post = _meter(ledger=ledger).summary()
    assert post.admissible is False and post.incidents == ()


def test_an_empty_corpus_yields_an_empty_incident_set():
    post = _meter(_corpus(rule_ids=[])).summary()
    assert post.admissible is True and post.incidents == () and post.incident_count == 0
    assert post.lead_count == 0


# ==================================================================================================
# (6)/(7)/(8) correlate() — a window of OBSERVED hits groups into incidents, fail-closed per hit.
# ==================================================================================================
def test_correlate_groups_observed_hits_by_technique_with_observed_sources():
    post = _meter().correlate([
        ("cloudtrail", ["942100", "941110"]),
        ("edr", ["942200"]),
        ("idp", ["942100"]),                                                   # 942100 recurs (weight up)
    ])
    by_key = {inc.key: inc for inc in post.incidents}
    assert set(by_key) == {"sqli", "xss"}
    assert by_key["sqli"].leads == ("942100", "942200")                        # distinct leads, sorted
    assert by_key["sqli"].sources == ("cloudtrail", "edr", "idp")              # the observed sources, per incident
    assert by_key["sqli"].weight == 3                                          # 942100(cloudtrail) + 942200(edr) + 942100(idp)
    assert by_key["xss"].sources == ("cloudtrail",)


def test_correlate_drops_a_hit_from_an_uncataloged_source_fail_closed():
    post = _meter().correlate([("not-a-provider", ["942100"]), ("", ["942100"])])
    assert post.incidents == ()                                               # an uncataloged source raises no belief


def test_correlate_drops_every_hit_over_inadmissible_content_fail_closed():
    post = _meter(_corpus(rule_ids=["942100"], expected_pin="00" * 32)).correlate([("cloudtrail", ["942100"])])
    assert post.admissible is False and post.incidents == ()                  # unverified content raises no incident


def test_correlate_on_empty_intake_yields_an_empty_incident_set():
    post = _meter().correlate([])
    assert post.admissible is True and post.incidents == () and post.observations == 0


def test_correlate_honours_the_recency_window_bound():
    m = _meter(window=2)
    # 3 observations, window=2 => only the last two are retained.
    post = m.correlate([("edr", ["942100"]), ("edr", ["941110"]), ("edr", ["932160"])])
    keys = {inc.key for inc in post.incidents}
    assert keys == {"xss", "rce"}                                             # the first (sqli) fell out of the window
    assert post.window == 2 and post.observations == 2


# ==================================================================================================
# (8) no-leak — ADDRESS-FREE: a dotted-quad that survives the AS-7b charset scrub is DROPPED by the AS-2e gate.
# ==================================================================================================
def test_an_ip_shaped_lead_is_dropped_by_the_hygiene_gate():
    post = _meter().correlate([("edr", ["203.0.113.9", "942100"])])
    blob = json.dumps(post.to_dict())
    assert "203.0.113.9" not in blob                                         # the IP-shaped token is dropped
    by_key = {inc.key: inc for inc in post.incidents}
    assert by_key["sqli"].leads == ("942100",)


def test_a_secret_literal_in_a_lead_is_dropped():
    post = _meter(redact_literals=("S3CRET",)).correlate([("edr", ["S3CRET", "942100"])])
    blob = json.dumps(post.to_dict())
    assert "S3CRET" not in blob
    assert {inc.key for inc in post.incidents} == {"sqli"}


def test_summary_is_address_free_and_metadata_only():
    """Feed a corpus whose rule-id field smuggles an address-shaped token; the correlation must surface no raw
    address and ``clean`` must hold."""
    post = _meter(_corpus(rule_ids=["942100", "10.0.0.1", "941110"])).summary()
    blob = json.dumps(post.to_dict())
    assert "10.0.0.1" not in blob and post.clean is True


# ==================================================================================================
# (4) determinism — identical inputs yield a byte-identical incident set and posture digest.
# ==================================================================================================
def test_identical_inputs_yield_a_byte_identical_summary():
    def _run() -> str:
        return json.dumps(_meter().summary().to_dict(), sort_keys=True)
    assert _run() == _run()


def test_summary_is_a_pure_typed_dataclass():
    post = _meter().summary()
    assert isinstance(post, IncidentPosture)
    assert all(isinstance(inc, Incident) for inc in post.incidents)
    assert len(post.digest) == 64 and post.incident_count == len(post.incidents)


def test_a_correlation_is_a_measurement_never_a_block_or_verdict():
    blob = json.dumps(_meter().summary().to_dict())
    for forbidden in ("certificate", "verdict", "decision", "action", "block", "allow", "shed"):
        assert forbidden not in blob


# ==================================================================================================
# (6) AS-5b pressure — an OPTIONAL aggregate denial-source CONTEXT, kept OUT of the deterministic digest.
# ==================================================================================================
def _fake_attribution(*, concentration=0.75, constrained=2, tracked=3, verified=True):
    """A minimal AS-5b rollup stub: a ``.summary()`` returning the REAL AttributionSummary dataclass (so the
    exact fields the gateway's live meter produces are exercised). Deterministic, no capacity/impact wiring."""
    from framework.v2.aegis.attribution import AttributionSummary
    s = AttributionSummary(tracked=tracked, constrained=constrained, inflight=1,
                           concentration=concentration, verified=verified)
    return types.SimpleNamespace(summary=lambda: s)


def test_pressure_is_surfaced_when_an_as5b_rollup_is_armed():
    post = _meter(attribution=_fake_attribution()).summary()
    assert post.pressure == {"concentration": 0.75, "constrained": 2, "tracked": 3, "verified": True}
    assert "pressure" in post.to_dict()


def test_pressure_is_absent_when_no_as5b_rollup_is_armed():
    post = _meter().summary()
    assert post.pressure is None and "pressure" not in post.to_dict()


def test_pressure_is_live_context_and_does_not_move_the_digest():
    """The content-addressed digest correlates the LEADS only; the live AS-5b pressure is context, so the SAME
    content yields the SAME digest whether or not an AS-5b rollup is armed, and whatever its values."""
    bare = _meter().summary().digest
    assert _meter(attribution=_fake_attribution()).summary().digest == bare
    assert _meter(attribution=_fake_attribution(concentration=0.1, constrained=9)).summary().digest == bare


def test_a_pressure_read_fault_degrades_only_the_annotation():
    """A rollup whose summary raises degrades the pressure annotation to None, never the correlation."""
    boom = types.SimpleNamespace(summary=lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    post = _meter(attribution=boom).summary()
    assert post.pressure is None and post.incident_count == 3                 # the incidents still correlate


# ==================================================================================================
# (7) READ-ONLY — the meter never mutates the injected inventory, the ledger, or the corpus.
# ==================================================================================================
def test_meter_never_mutates_the_injected_inventory_ledger_or_corpus():
    ledger = _shipped_ledger()
    before_ledger = [r.model_dump() for r in ledger]
    corp = _corpus()
    before_corpus = (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin)
    inv = build_provider_runtime_registry()
    before_inv = inv.provider_ids
    cm = CorazaAttestationMeter(corp, ledger=ledger)
    mir = DetectionMirrorMeter(cm, corp.rule_ids, inventory=inv)
    im = IncidentMeter(mir)
    for _ in range(50):
        im.snapshot()
        im.correlate([("edr", ["942100", "203.0.113.9"]), ("cloudtrail", ["941110"])])
    assert [r.model_dump() for r in ledger] == before_ledger                 # ledger untouched
    assert (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin) == before_corpus
    assert inv.provider_ids == before_inv                                    # inventory untouched (append-only)


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_incidents_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(INCIDENTS_ENV, raising=False)
    assert incidents_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(INCIDENTS_ENV, on)
        assert incidents_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(INCIDENTS_ENV, off)
        assert incidents_enabled() is False, off


# ==================================================================================================
# (2) gate-invariance — AS-11a adds NO OracleKind; incidents.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                        # a correlation is a measurement, not an oracle


def test_incidents_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                              # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.incidents' not in sys.modules, "
        "'incidents.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "assert 'framework.v2.aegis.detection_mirror' not in sys.modules, "
        "'detection_mirror must stay OFF the import path';"
        "assert 'framework.v2.aegis.detection_coverage' not in sys.modules, "
        "'detection_coverage must stay OFF the import path (incidents must not drag it on eagerly)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"incidents reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_incidents_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.INCIDENTS_ENV == INCIDENTS_ENV == "VIGIL_AEGIS_INCIDENTS"


# ==================================================================================================
# (3) FATAL-2 — incidents.py imports ONLY the stdlib (reaching its deps by RELATIVE import / injection).
# ==================================================================================================
def test_incidents_imports_only_stdlib_and_reaches_deps_by_relative_import():
    src = Path(INC.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:          # absolute imports only
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core", "pydantic"):
        assert forbidden not in roots, f"incidents must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "hashlib", "json", "os", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in incidents.py: {sorted(roots - allowed)}"
    # AS-8 / AS-2e are reached by RELATIVE import; AS-31 / AS-5b by injection (type-only relative import).
    rel = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level == 1}
    assert "detection_coverage" in rel, "incidents must reach the AS-8 band classifier by relative import"
    assert "monitoring_event_v2" in rel, "incidents must reach the AS-2e hygiene gate by relative import"
    assert "detection_mirror" in rel, "incidents must reach the AS-31 mirror type by relative import"


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


def test_gateway_incidents_off_builds_no_meter_and_probe_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_INCIDENTS unset (mirror + coraza on + corpus) => NO active meter, the
    data path still forwards, and the probe snapshot carries NO incidents keys."""
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "1")
    monkeypatch.delenv(INCIDENTS_ENV, raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.incident_meter is None
        assert gw.settings.incidents_active is False
        assert [_get(port, "/x")[0] for _ in range(3)] == [200] * 3          # data path byte-identical
        snap = gw.settings._probe_snapshot()
        assert "incidents" not in snap and "incidents_active" not in snap
        assert "detection_mirror" in snap                                   # the AS-31 dep is unaffected
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_incidents_inert_without_the_mirror_dep(upstream, monkeypatch):
    """The correlation is inert whenever its AS-31 dep is off: flag on, but VIGIL_AEGIS_DETECTION_MIRROR off => no
    mirror meter => no incident meter, no probe keys."""
    monkeypatch.setenv(INCIDENTS_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.delenv("VIGIL_AEGIS_DETECTION_MIRROR", raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.incident_meter is None and gw.settings.incidents_active is False
        assert "incidents" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_incidents_on_but_no_corpus_is_inert(upstream, monkeypatch):
    """No CRS corpus configured => the mirror dep is inert => no incident meter."""
    monkeypatch.setenv(INCIDENTS_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        assert gw.settings.incident_meter is None and gw.settings.incidents_active is False
        assert "incidents" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_incidents_on_surfaces_the_correlation_on_the_probe_snapshot(upstream, monkeypatch):
    """Flag ON + the AS-31 dep ON + a CRS corpus => the probe snapshot surfaces the incident correlation computed
    from the mirror's admissible reflected leads, metadata-only (labels + ids + counts + a digest, no request
    bytes)."""
    monkeypatch.setenv(INCIDENTS_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus(rule_ids=["942100", "942200", "941110", "932160"]))
    try:
        assert gw.settings.incident_meter is not None and gw.settings.incidents_active is True
        for _ in range(3):
            assert _get(port, "/x")[0] == 200                               # data path forwards unchanged
        snap = gw.settings._probe_snapshot()
        assert snap["incidents_active"] is True
        m = snap["incidents"]
        assert m["admissible"] is True and m["clean"] is True
        keys = {inc["key"] for inc in m["incidents"]}
        assert keys == {"sqli", "xss", "rce"}
        assert len(m["digest"]) == 64
        assert "127.0.0.1" not in json.dumps(snap)                          # NO raw caller/upstream address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_incidents_flip_off_at_runtime_stops_surfacing(upstream, monkeypatch):
    """Flipping VIGIL_AEGIS_INCIDENTS (or the mirror/coraza dep) OFF at runtime makes the correlation go inert live,
    so the probe answer drops the incidents keys again."""
    monkeypatch.setenv(INCIDENTS_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        _get(port, "/x")
        assert "incidents" in gw.settings._probe_snapshot()
        monkeypatch.setenv(INCIDENTS_ENV, "0")
        assert gw.settings.incidents_active is False
        assert "incidents" not in gw.settings._probe_snapshot()
        monkeypatch.setenv(INCIDENTS_ENV, "1")
        assert "incidents" in gw.settings._probe_snapshot()                 # restored -> surfaced again
        monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "0")             # the dep going off also makes it inert
        assert "incidents" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_probe_without_corpus_is_byte_identical_whether_flag_on_or_off(upstream, monkeypatch):
    """The strongest OFF-invariance: with NO corpus configured, the probe snapshot is byte-identical whether the
    incidents flag is on or off (AS-11a never touches the data path or the probe without its dependency)."""
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        monkeypatch.delenv(INCIDENTS_ENV, raising=False)
        off = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        monkeypatch.setenv(INCIDENTS_ENV, "1")
        on = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        assert off == on
    finally:
        gw.shutdown(); gw.server_close()
