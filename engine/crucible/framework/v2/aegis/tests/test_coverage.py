"""AEGIS AS-8 (the deterministic read-only DETECTION-CONTENT COVERAGE measure), deterministic, offline tests.

AS-8 is a read-only, metadata-only MEASURE of what the AS-7b admissible CRS detection content COVERS: it classifies
the admissible CRS rule-ids into their canonical detection TECHNIQUE (by the CRS rule-id thousands-band taxonomy,
``942xxx`` is SQLi, ``941xxx`` is XSS, ...) and reports which techniques the admissible, hygiene-clean content
covers, how much of the known technique taxonomy that is, and a deterministic posture digest. It is not a detector,
so DoD-1's "detector near-zero-FP" is N/A; it is substituted by coverage-correctness vs a hand-computed expectation
+ a byte-identity negative control. The DoD points, mapped to the sections below:

  (1) e2e behavioral, a configured gateway with the flag ON (and a CRS corpus) surfaces the coverage measure on the
      AS-5c probe snapshot, computed from the AS-7b attestation, end-to-end through the gateway.
  (2) gate-invariance, importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-8 adds NO OracleKind);
      detection_coverage.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__ (nor are its deps,
      through it); gateway.COVERAGE_ENV is in lockstep.
  (3) FATAL-2, detection_coverage.py imports ONLY the stdlib (reaching coraza_source / monitoring_event_v2 by
      RELATIVE import, consuming their results by composition); never sigil/governor/strix/apps/vigil_core.
  (4) determinism, identical attestation + content yield a byte-identical digest and summary; no wall-clock, no RNG.
  (5) default-OFF + byte-identity, VIGIL_AEGIS_COVERAGE off (or the AS-7b dep off, or NO corpus) => NO meter is
      active, nothing is computed, and the probe snapshot is byte-identical (no coverage keys); strict/fail-closed.
  (6) correctness + negative controls, the techniques track the admissible CRS content; the digest matches a
      hand-computed canonical digest; a drifted/unlicensed corpus is DETECTED (admissible=False) and covers NOTHING;
      the digest MOVES on any posture change; a measure is NOT a block/verdict.
  (7) read-only, AS-8 NEVER mutates the licence ledger or the corpus, and NEVER drives an admit/shed/allow/block
      decision; only a fired oracle blocks; a classified technique is a LEAD.
  (8) no-leak, summary/classify are ADDRESS-FREE and bounded/sorted/de-duplicated; a dotted-quad that survives the
      AS-7b charset scrub is DROPPED by the AS-2e hygiene gate before it is ever classified; inadmissible content
      covers nothing (fail closed).

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
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from framework.v2.aegis import detection_coverage as DC
from framework.v2.aegis.coraza_source import CorazaAttestationMeter, CorazaCorpus
from framework.v2.aegis.detection_coverage import (
    COVERAGE_ENV,
    CRS_TECHNIQUES,
    KNOWN_TECHNIQUES,
    UNCLASSIFIED,
    DetectionCoverage,
    DetectionCoverageMeter,
    coverage_digest,
    coverage_enabled,
    crs_technique,
)
from framework.v2.aegis.license_gate import LicenseRecord, load_ledger
from framework.v2.aegis.license_policy import UseMode


def _corpus(rule_ids=("942100", "941110", "932160"), *, version="4.3.0", paranoia=1, expected_pin=None):
    return CorazaCorpus.build(version=version, paranoia=paranoia, rule_ids=rule_ids, expected_pin=expected_pin)


def _shipped_ledger():
    return load_ledger()


def _meter(corpus=None, *, ledger=None, redact_literals=()):
    corp = corpus if corpus is not None else _corpus()
    cm = CorazaAttestationMeter(corp, ledger=ledger if ledger is not None else _shipped_ledger())
    return DetectionCoverageMeter(cm, corp.rule_ids, redact_literals=redact_literals)


# ==================================================================================================
# (6) taxonomy, the CRS rule-id banding classifies deterministically and address-free.
# ==================================================================================================
def test_crs_technique_classifies_the_known_bands():
    assert crs_technique("942100") == "sqli"
    assert crs_technique("941110") == "xss"
    assert crs_technique("932160") == "rce"
    assert crs_technique("930120") == "lfi"
    assert crs_technique("913100") == "scanner-detection"
    assert crs_technique("951100") == "data-leakage-sql"


def test_crs_technique_falls_through_operational_and_malformed_bands_to_unclassified():
    assert crs_technique("949110") == UNCLASSIFIED   # anomaly / blocking-evaluation, not an attack technique
    assert crs_technique("980170") == UNCLASSIFIED   # correlation, not an attack technique
    assert crs_technique("") == UNCLASSIFIED
    assert crs_technique("xx") == UNCLASSIFIED
    assert crs_technique("1.2.3.4") == UNCLASSIFIED  # a dotted token is not a CRS band


def test_known_techniques_is_the_sorted_distinct_named_taxonomy():
    assert KNOWN_TECHNIQUES == tuple(sorted(set(CRS_TECHNIQUES.values())))
    assert UNCLASSIFIED not in KNOWN_TECHNIQUES       # the catch-all is never counted as a known technique
    assert "sqli" in KNOWN_TECHNIQUES and "xss" in KNOWN_TECHNIQUES


# ==================================================================================================
# (6) correctness, the coverage tracks the admissible CRS content over the shipped ledger.
# ==================================================================================================
def test_coverage_tracks_the_admissible_crs_content():
    cov = _meter(_corpus(rule_ids=["942100", "942190", "941110", "932160"])).summary()
    assert cov.admissible is True
    assert cov.techniques == ("rce", "sqli", "xss")          # sorted, de-duplicated
    assert cov.per_technique == {"rce": 1, "sqli": 2, "xss": 1}
    assert cov.covered == 3 and cov.known == len(KNOWN_TECHNIQUES)
    assert cov.rules == 4 and cov.technique_count == 3 and cov.clean is True


def test_coverage_bps_is_integer_floor_covered_over_known():
    cov = _meter(_corpus(rule_ids=["942100", "941110", "932160"])).summary()
    assert cov.covered == 3
    assert cov.coverage_bps == (3 * 10000 // len(KNOWN_TECHNIQUES))   # integer floor, no float
    assert isinstance(cov.coverage_bps, int)


def test_unclassified_rules_are_counted_but_not_credited_as_coverage():
    """An operational-scoring rule (949xxx) is counted honestly in per_technique + rules, but it is NOT a named
    technique, so it does not inflate ``covered`` or the coverage ratio."""
    cov = _meter(_corpus(rule_ids=["942100", "949110"])).summary()
    assert cov.per_technique == {"sqli": 1, UNCLASSIFIED: 1}
    assert cov.rules == 2
    assert cov.covered == 1                                   # only sqli is a NAMED technique
    assert UNCLASSIFIED in cov.techniques


def test_digest_matches_a_hand_computed_canonical_digest():
    per = {"rce": 1, "sqli": 1, "xss": 1}
    payload = {"admissible": True, "per_technique": {k: per[k] for k in sorted(per)}, "rules": 3}
    expect = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    assert coverage_digest(True, per, 3) == expect
    assert _meter(_corpus(rule_ids=["942100", "941110", "932160"])).summary().digest == expect


def test_coverage_digest_is_order_and_representation_invariant():
    a = coverage_digest(True, {"sqli": 2, "xss": 1}, 3)
    b = coverage_digest(True, {"xss": 1, "sqli": 2}, 3)
    assert a == b


def test_digest_moves_on_any_posture_change():
    base = coverage_digest(True, {"sqli": 1}, 1)
    assert base != coverage_digest(False, {"sqli": 1}, 1)            # content flips inadmissible
    assert base != coverage_digest(True, {"sqli": 2}, 2)            # a per-technique count changes
    assert base != coverage_digest(True, {"sqli": 1, "xss": 1}, 2)  # a technique gained
    assert base != coverage_digest(True, {}, 0)                     # coverage emptied


# ==================================================================================================
# (6) negative controls, a drifted / unlicensed corpus is DETECTED and covers NOTHING (fail closed).
# ==================================================================================================
def test_a_drifted_corpus_is_detected_and_covers_nothing():
    """A corpus whose live content no longer matches the pin it is pinned to is NOT admissible => admissible False
    => NOTHING is covered, even though the licence ledger is clean (the AS-7b fail-closed stance)."""
    drifted = _corpus(rule_ids=["942100", "941110"], expected_pin="deadbeef" * 8)
    cov = _meter(drifted).summary()
    assert cov.admissible is False
    assert cov.techniques == () and cov.covered == 0 and cov.rules == 0 and cov.coverage_bps == 0
    assert cov.per_technique == {}


def test_a_missing_crs_licence_record_is_detected_and_covers_nothing():
    from framework.v2.aegis.coraza_source import CRS_CORPUS_ARTEFACT
    ledger = [r for r in _shipped_ledger() if r.artefact != CRS_CORPUS_ARTEFACT]
    cov = _meter(ledger=ledger).summary()
    assert cov.admissible is False and cov.techniques == () and cov.covered == 0


def test_a_policy_denied_crs_licence_covers_nothing():
    from framework.v2.aegis.coraza_source import CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT
    ledger = [r for r in _shipped_ledger() if r.artefact not in (CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT)]
    ledger.append(LicenseRecord(artefact=WAF_ENGINE_ARTEFACT, license="Apache-2.0", use_mode=UseMode.SERVICE))
    ledger.append(LicenseRecord(artefact=CRS_CORPUS_ARTEFACT, component_kind="rule", license="SSPL-1.0",
                                use_mode=UseMode.SERVICE))
    cov = _meter(ledger=ledger).summary()
    assert cov.admissible is False and cov.techniques == ()


# ==================================================================================================
# (6)/(7)/(8) classify(), a detection hit is measured into TECHNIQUES only over admissible content.
# ==================================================================================================
def test_classify_measures_a_hit_over_admissible_content():
    mt = _meter()
    assert mt.classify(["942100", "942190", "941110"]) == ("sqli", "xss")   # sorted, de-duplicated techniques
    assert mt.classify(["932160"]) == ("rce",)


def test_classify_drops_every_hit_over_inadmissible_content_fail_closed():
    mt = _meter(_corpus(rule_ids=["942100"], expected_pin="00" * 32))        # drifted => inadmissible
    assert mt.classify(["942100", "941110"]) == ()                          # unverified content covers nothing


def test_classify_bounds_the_technique_set():
    mt = _meter()
    many = [str(900000 + i) for i in range(DC._MAX_TECHNIQUES + 40)]
    out = mt.classify(many)
    assert len(out) <= DC._MAX_TECHNIQUES and list(out) == sorted(out)


# ==================================================================================================
# (8) no-leak, ADDRESS-FREE: a dotted-quad that survives the AS-7b charset scrub is DROPPED by AS-2e.
# ==================================================================================================
def test_an_ip_shaped_rule_ref_is_dropped_before_classification():
    """The AS-7b address-free charset keeps digits and ``.``, so a raw dotted-quad SURVIVES its scrub. The AS-2e
    hygiene gate is the belt that catches it: an IP-shaped token is DROPPED before it is ever classified."""
    mt = _meter()
    out = mt.classify(["203.0.113.9", "942100"])
    assert out == ("sqli",)                                                  # the IP-shaped token is dropped
    assert "203.0.113.9" not in json.dumps(out)


def test_a_secret_literal_in_a_ref_is_dropped():
    mt = _meter(redact_literals=("S3CRET",))
    out = mt.classify(["S3CRET", "942100"])
    assert out == ("sqli",) and "S3CRET" not in json.dumps(out)


def test_summary_is_address_free_and_metadata_only():
    """Feed a corpus whose rule-id field smuggles an address-shaped token; the summary must surface no raw address
    and ``clean`` must hold. (The scrub + hygiene gate run end-to-end over the classified content.)"""
    cov = _meter(_corpus(rule_ids=["942100", "10.0.0.1", "941110"])).summary()
    blob = json.dumps(cov.to_dict())
    assert "10.0.0.1" not in blob
    assert cov.clean is True
    assert cov.per_technique == {"sqli": 1, "xss": 1}                        # the IP-shaped token never classified


# ==================================================================================================
# (4) determinism, identical inputs yield a byte-identical digest and summary.
# ==================================================================================================
def test_identical_inputs_yield_a_byte_identical_summary():
    def _run() -> str:
        return json.dumps(_meter().summary().to_dict(), sort_keys=True)
    assert _run() == _run()


def test_summary_is_a_pure_typed_dataclass():
    cov = _meter().summary()
    assert isinstance(cov, DetectionCoverage)
    assert len(cov.digest) == 64 and cov.technique_count == len(cov.techniques)
    assert cov.rules == sum(cov.per_technique.values())


def test_a_coverage_measure_is_never_a_block_or_verdict():
    blob = json.dumps(_meter().summary().to_dict())
    for forbidden in ("certificate", "verdict", "decision", "action", "block"):
        assert forbidden not in blob


# ==================================================================================================
# (7) READ-ONLY, the meter never mutates the injected ledger or the corpus.
# ==================================================================================================
def test_meter_never_mutates_the_injected_ledger_or_corpus():
    ledger = _shipped_ledger()
    before_ledger = [r.model_dump() for r in ledger]
    corp = _corpus()
    before_corpus = (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin)
    cm = CorazaAttestationMeter(corp, ledger=ledger)
    mt = DetectionCoverageMeter(cm, corp.rule_ids)
    for _ in range(50):
        mt.snapshot()
        mt.classify(["942100", "203.0.113.9"])
    assert [r.model_dump() for r in ledger] == before_ledger                 # ledger untouched
    assert (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin) == before_corpus


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_coverage_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(COVERAGE_ENV, raising=False)
    assert coverage_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(COVERAGE_ENV, on)
        assert coverage_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(COVERAGE_ENV, off)
        assert coverage_enabled() is False, off


# ==================================================================================================
# (2) gate-invariance, AS-8 adds NO OracleKind; detection_coverage.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                        # a coverage measure is not an oracle


def test_detection_coverage_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                              # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.detection_coverage' not in sys.modules, "
        "'detection_coverage.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "assert 'framework.v2.aegis.coraza_source' not in sys.modules, "
        "'coraza_source must stay OFF the import path (detection_coverage must not drag it on eagerly)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"detection_coverage reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_coverage_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.COVERAGE_ENV == COVERAGE_ENV == "VIGIL_AEGIS_COVERAGE"


# ==================================================================================================
# (3) FATAL-2, detection_coverage.py imports ONLY the stdlib (reaching its deps by RELATIVE import).
# ==================================================================================================
def test_detection_coverage_imports_only_stdlib_and_reaches_deps_by_relative_import():
    src = Path(DC.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:          # absolute imports only
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core", "pydantic"):
        assert forbidden not in roots, f"detection_coverage must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "hashlib", "json", "os", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in detection_coverage.py: {sorted(roots - allowed)}"
    # AS-7b / AS-2e are reached by RELATIVE import only (never an absolute framework.* root).
    rel = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level == 1}
    assert "coraza_source" in rel, "detection_coverage must reach the AS-7b admit gate by relative import"
    assert "monitoring_event_v2" in rel, "detection_coverage must reach the AS-2e hygiene gate by relative import"


# ==================================================================================================
# (1)/(5) gateway integration, end-to-end through the live gateway over real loopback sockets.
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


def test_gateway_coverage_off_builds_no_meter_and_probe_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_COVERAGE unset (coraza on + corpus) => NO active meter, the data path
    still forwards, and the probe snapshot carries NO coverage keys."""
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.delenv(COVERAGE_ENV, raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.coverage_meter is None
        assert gw.settings.coverage_active is False
        assert [_get(port, "/x")[0] for _ in range(3)] == [200] * 3          # data path byte-identical
        snap = gw.settings._probe_snapshot()
        assert "coverage" not in snap and "coverage_active" not in snap
        assert "coraza" in snap                                             # the AS-7b dep is unaffected
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_coverage_inert_without_the_coraza_dep(upstream, monkeypatch):
    """The measure is inert whenever its AS-7b dep is off: flag on, but VIGIL_AEGIS_CORAZA off => no coraza meter =>
    no coverage meter, no probe keys."""
    monkeypatch.setenv(COVERAGE_ENV, "1")
    monkeypatch.delenv("VIGIL_AEGIS_CORAZA", raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.coverage_meter is None
        assert gw.settings.coverage_active is False
        assert "coverage" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_coverage_on_but_no_corpus_is_inert(upstream, monkeypatch):
    """No CRS corpus configured => inert (mirrors AS-7b's no-corpus case): no coraza meter => no coverage meter."""
    monkeypatch.setenv(COVERAGE_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        assert gw.settings.coverage_meter is None and gw.settings.coverage_active is False
        assert "coverage" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_coverage_on_surfaces_the_measure_on_the_probe_snapshot(upstream, monkeypatch):
    """Flag ON + the AS-7b dep ON + a CRS corpus => the probe snapshot surfaces the coverage measure computed from
    the AS-7b attestation, metadata-only (counts + labels + a digest, never request bytes)."""
    monkeypatch.setenv(COVERAGE_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus(rule_ids=["942100", "941110", "932160"]))
    try:
        assert gw.settings.coverage_meter is not None and gw.settings.coverage_active is True
        for _ in range(3):
            assert _get(port, "/x")[0] == 200                               # data path forwards unchanged
        snap = gw.settings._probe_snapshot()
        assert snap["coverage_active"] is True
        m = snap["coverage"]
        assert m["admissible"] is True and m["clean"] is True
        assert m["techniques"] == ["rce", "sqli", "xss"]
        assert m["per_technique"] == {"rce": 1, "sqli": 1, "xss": 1}
        assert m["covered"] == 3 and m["known"] == len(KNOWN_TECHNIQUES)
        assert len(m["digest"]) == 64
        assert "127.0.0.1" not in json.dumps(snap)                          # NO raw caller/upstream address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_coverage_flip_off_at_runtime_stops_surfacing(upstream, monkeypatch):
    """Flipping VIGIL_AEGIS_COVERAGE (or the coraza dep) OFF at runtime makes the measure go inert live, so the
    probe answer drops the coverage keys again."""
    monkeypatch.setenv(COVERAGE_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        _get(port, "/x")
        assert "coverage" in gw.settings._probe_snapshot()
        monkeypatch.setenv(COVERAGE_ENV, "0")
        assert gw.settings.coverage_active is False
        assert "coverage" not in gw.settings._probe_snapshot()
        monkeypatch.setenv(COVERAGE_ENV, "1")
        assert "coverage" in gw.settings._probe_snapshot()                  # restored -> surfaced again
        monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "0")                       # the dep going off also makes it inert
        assert "coverage" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_probe_without_corpus_is_byte_identical_whether_flag_on_or_off(upstream, monkeypatch):
    """The strongest OFF-invariance: with NO corpus configured, the probe snapshot is byte-identical whether the
    coverage flag is on or off (AS-8 never touches the data path or the probe without its dependency)."""
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        monkeypatch.delenv(COVERAGE_ENV, raising=False)
        off = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        monkeypatch.setenv(COVERAGE_ENV, "1")
        on = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        assert off == on
    finally:
        gw.shutdown(); gw.server_close()
