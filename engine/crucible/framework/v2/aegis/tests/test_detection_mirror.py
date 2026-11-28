"""AEGIS AS-31 (the deterministic read-only DETECTION MIRROR) — deterministic, offline acceptance tests.

AS-31 is a read-only, metadata-only REFLECTION of the detection posture that UNIFIES its three merged deps: the
AS-30 provider runtime (the detection SOURCE catalog — ``build_provider_runtime_registry``), the AS-7b Coraza/CRS
attestation (the detection CONTENT admissibility — ``CorazaAttestation.admissible`` + ``admit_rule_refs``), and the
AS-3b v2 emission (the AS-2e OUTPUT HYGIENE leak gate — ``is_hygiene_clean`` / ``contains_raw_ip``). It is not a
detector, so DoD-1's "detector near-zero-FP" is N/A; it is substituted by reflection-correctness vs a hand-computed
expectation + a byte-identity negative control. The DoD points, mapped to the sections below:

  (1) e2e behavioral — a configured gateway with the flag ON (and a CRS corpus) surfaces the detection mirror on the
      AS-5c probe snapshot, computed from the AS-30 inventory + the AS-7b attestation, end-to-end through the gateway.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-31 adds NO OracleKind);
      detection_mirror.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__ (nor are its deps,
      through it); gateway.DETECTION_MIRROR_ENV is in lockstep.
  (3) FATAL-2 — detection_mirror.py imports ONLY the stdlib (reaching provider_runtime / coraza_source /
      monitoring_event_v2 by RELATIVE import, consuming their results by composition); never sigil/governor/strix/
      apps/vigil_core.
  (4) determinism — identical inventory + attestation + content yield a byte-identical digest and summary; no
      wall-clock, no RNG.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_DETECTION_MIRROR off (or the AS-7b dep off, or NO corpus) => NO meter
      is active, nothing is computed, and the probe snapshot is byte-identical (no detection_mirror keys); strict/fail-
      closed flag.
  (6) correctness + negative controls — the digest matches a hand-computed canonical digest; sources track the AS-30
      catalog; leads track the admissible CRS content; a drifted/unlicensed corpus is DETECTED (content_admissible=
      False) and DROPS every lead; the digest MOVES on any posture change; a reflection is NOT a block/verdict.
  (7) read-only — AS-31 NEVER mutates the injected inventory, the licence ledger, or the corpus, and NEVER drives an
      admit/shed/allow/block decision; only a fired oracle blocks; a mirrored detection hit is a LEAD.
  (8) no-leak — reflect/summary are ADDRESS-FREE and bounded/sorted/de-duplicated; a dotted-quad that survives the
      AS-7b charset scrub is DROPPED by the AS-3b hygiene gate; an uncataloged source and inadmissible content both
      fail closed.

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

from framework.v2.aegis import detection_mirror as DM
from framework.v2.aegis.coraza_source import CorazaAttestationMeter, CorazaCorpus
from framework.v2.aegis.detection_mirror import (
    DETECTION_MIRROR_ENV,
    DetectionMirror,
    DetectionMirrorMeter,
    detection_mirror_enabled,
    mirror_digest,
)
from framework.v2.aegis.license_gate import LicenseRecord, load_ledger
from framework.v2.aegis.license_policy import UseMode
from framework.v2.aegis.provider_runtime import build_provider_runtime_registry


def _corpus(rule_ids=("942100", "941110", "932160"), *, version="4.3.0", paranoia=1, expected_pin=None):
    return CorazaCorpus.build(version=version, paranoia=paranoia, rule_ids=rule_ids, expected_pin=expected_pin)


def _shipped_ledger():
    return load_ledger()


def _meter(corpus=None, *, ledger=None, inventory=None, redact_literals=()):
    corp = corpus if corpus is not None else _corpus()
    cm = CorazaAttestationMeter(corp, ledger=ledger if ledger is not None else _shipped_ledger())
    return DetectionMirrorMeter(cm, corp.rule_ids, inventory=inventory, redact_literals=redact_literals)


# ==================================================================================================
# (6) correctness — sources track the AS-30 catalog; leads track the admissible CRS content.
# ==================================================================================================
def test_sources_reflect_the_as30_provider_inventory_sorted_deduped():
    inv_ids = sorted(set(build_provider_runtime_registry().provider_ids))
    mir = _meter().summary()
    assert list(mir.sources) == inv_ids and mir.source_count == len(inv_ids)
    assert list(mir.sources) == sorted(set(mir.sources))                     # sorted + de-duplicated
    # the AS-30 telemetry providers are cataloged as detection sources.
    for pid in ("edr", "cloudtrail", "idp"):
        assert pid in mir.sources


def test_leads_reflect_the_admissible_crs_content_over_the_shipped_ledger():
    mir = _meter(_corpus(rule_ids=["942100", "941110", "932160"])).summary()
    assert mir.content_admissible is True
    assert mir.leads == ("932160", "941110", "942100")                       # admitted, sorted, de-duplicated
    assert mir.lead_count == 3 and mir.clean is True


def test_digest_matches_a_hand_computed_canonical_digest():
    inv_ids = sorted(set(build_provider_runtime_registry().provider_ids))
    leads = ["932160", "941110", "942100"]
    payload = {"sources": inv_ids, "content_admissible": True, "leads": sorted(leads)}
    expect = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    assert mirror_digest(inv_ids, True, leads) == expect
    assert _meter().summary().digest == expect


def test_mirror_digest_is_order_and_duplicate_invariant():
    a = mirror_digest(["edr", "idp"], True, ["942100", "941110"])
    b = mirror_digest(["idp", "edr", "edr"], True, ["941110", "942100", "942100"])
    assert a == b


def test_digest_moves_on_any_posture_change():
    base = mirror_digest(["edr", "idp"], True, ["942100"])
    assert base != mirror_digest(["edr", "idp", "cloudtrail"], True, ["942100"])   # a source added
    assert base != mirror_digest(["edr", "idp"], False, ["942100"])               # content flips inadmissible
    assert base != mirror_digest(["edr", "idp"], True, ["942100", "941110"])       # a lead added
    assert base != mirror_digest(["edr", "idp"], True, [])                         # leads dropped


# ==================================================================================================
# (6) negative controls — a drifted / unlicensed corpus is DETECTED and DROPS every lead (fail closed).
# ==================================================================================================
def test_a_drifted_corpus_is_detected_and_drops_every_lead():
    """A corpus whose live content no longer matches the pin it is pinned to is NOT admissible => content_admissible
    False => NO leads are reflected, even though the licence ledger is clean (the AS-7b fail-closed stance)."""
    drifted = _corpus(rule_ids=["942100", "941110"], expected_pin="deadbeef" * 8)
    mir = _meter(drifted).summary()
    assert mir.content_admissible is False and mir.leads == () and mir.lead_count == 0


def test_a_missing_crs_licence_record_is_detected_and_drops_every_lead():
    """Drop the coreruleset-crs-4x §7 record -> the AS-7a gate fails closed -> content_admissible False -> no leads,
    even though the corpus content is self-consistently pinned."""
    from framework.v2.aegis.coraza_source import CRS_CORPUS_ARTEFACT
    ledger = [r for r in _shipped_ledger() if r.artefact != CRS_CORPUS_ARTEFACT]
    mir = _meter(ledger=ledger).summary()
    assert mir.content_admissible is False and mir.leads == ()


def test_a_policy_denied_crs_licence_drops_every_lead():
    from framework.v2.aegis.coraza_source import CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT
    ledger = [r for r in _shipped_ledger() if r.artefact not in (CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT)]
    ledger.append(LicenseRecord(artefact=WAF_ENGINE_ARTEFACT, license="Apache-2.0", use_mode=UseMode.SERVICE))
    ledger.append(LicenseRecord(artefact=CRS_CORPUS_ARTEFACT, component_kind="rule", license="SSPL-1.0",
                                use_mode=UseMode.SERVICE))
    mir = _meter(ledger=ledger).summary()
    assert mir.content_admissible is False and mir.leads == ()


# ==================================================================================================
# (6)/(7)/(8) reflect() — a detection hit is a LEAD, admitted ONLY over a cataloged source + admissible content.
# ==================================================================================================
def test_reflect_admits_a_hit_from_a_cataloged_source_over_admissible_content():
    dm = _meter()
    assert dm.reflect("cloudtrail", ["942100", "941110"]) == ("941110", "942100")   # normalized (sorted, deduped)
    assert dm.reflect("edr", ["932160"]) == ("932160",)


def test_reflect_drops_a_hit_from_an_uncataloged_source_fail_closed():
    dm = _meter()
    assert dm.reflect("not-a-provider", ["942100"]) == ()                    # uncataloged source raises NO belief
    assert dm.reflect("", ["942100"]) == ()


def test_reflect_drops_every_hit_over_inadmissible_content_fail_closed():
    dm = _meter(_corpus(rule_ids=["942100"], expected_pin="00" * 32))        # drifted => inadmissible
    assert dm.reflect("cloudtrail", ["942100", "941110"]) == ()             # unverified content raises NO belief


def test_reflect_bounds_the_lead_set():
    dm = _meter()
    many = [str(900000 + i) for i in range(DM._MAX_LEADS + 40)]
    out = dm.reflect("edr", many)
    assert len(out) <= DM._MAX_LEADS and list(out) == sorted(out)


# ==================================================================================================
# (8) no-leak — ADDRESS-FREE: a dotted-quad that survives the AS-7b charset scrub is DROPPED by the AS-3b gate.
# ==================================================================================================
def test_an_ip_shaped_rule_ref_is_dropped_by_the_hygiene_gate():
    """The AS-7b address-free charset keeps digits and ``.``, so a raw dotted-quad SURVIVES its scrub. The AS-3b
    hygiene gate is the belt that catches it: a reflected lead that still parses as a raw IP is DROPPED."""
    dm = _meter()
    out = dm.reflect("edr", ["203.0.113.9", "942100"])
    assert out == ("942100",)                                                # the IP-shaped token is dropped
    assert "203.0.113.9" not in json.dumps(out)


def test_a_secret_literal_in_a_ref_is_dropped():
    dm = _meter(redact_literals=("S3CRET",))
    out = dm.reflect("edr", ["S3CRET", "942100"])
    assert out == ("942100",) and "S3CRET" not in json.dumps(out)


def test_summary_is_address_free_and_metadata_only():
    """Feed a corpus whose rule-id field smuggles an address-shaped token; the summary must surface no raw address
    and ``clean`` must hold. (The scrub + hygiene gate run end-to-end over the reflected content.)"""
    mir = _meter(_corpus(rule_ids=["942100", "10.0.0.1", "941110"])).summary()
    blob = json.dumps(mir.to_dict())
    for leak in ("10.0.0.1",):
        assert leak not in blob
    assert mir.clean is True


# ==================================================================================================
# (4) determinism — identical inputs yield a byte-identical digest and summary.
# ==================================================================================================
def test_identical_inputs_yield_a_byte_identical_summary():
    def _run() -> str:
        return json.dumps(_meter().summary().to_dict(), sort_keys=True)
    assert _run() == _run()


def test_summary_is_a_pure_typed_dataclass():
    mir = _meter().summary()
    assert isinstance(mir, DetectionMirror)
    assert len(mir.digest) == 64 and mir.source_count == len(mir.sources) and mir.lead_count == len(mir.leads)


def test_a_mirror_is_a_measurement_never_a_block_or_verdict():
    blob = json.dumps(_meter().summary().to_dict())
    for forbidden in ("certificate", "verdict", "decision", "action", "block"):
        assert forbidden not in blob


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
    dm = DetectionMirrorMeter(cm, corp.rule_ids, inventory=inv)
    for _ in range(50):
        dm.snapshot()
        dm.reflect("edr", ["942100", "203.0.113.9"])
    assert [r.model_dump() for r in ledger] == before_ledger                 # ledger untouched
    assert (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin) == before_corpus
    assert inv.provider_ids == before_inv                                    # inventory untouched (append-only)


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_detection_mirror_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(DETECTION_MIRROR_ENV, raising=False)
    assert detection_mirror_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(DETECTION_MIRROR_ENV, on)
        assert detection_mirror_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(DETECTION_MIRROR_ENV, off)
        assert detection_mirror_enabled() is False, off


# ==================================================================================================
# (2) gate-invariance — AS-31 adds NO OracleKind; detection_mirror.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                        # a mirror is a measurement, not an oracle


def test_detection_mirror_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                              # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.detection_mirror' not in sys.modules, "
        "'detection_mirror.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "assert 'framework.v2.aegis.provider_runtime' not in sys.modules, "
        "'provider_runtime must stay OFF the import path (detection_mirror must not drag it on eagerly)';"
        "assert 'framework.v2.aegis.coraza_source' not in sys.modules, "
        "'coraza_source must stay OFF the import path';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"detection_mirror reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_detection_mirror_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.DETECTION_MIRROR_ENV == DETECTION_MIRROR_ENV == "VIGIL_AEGIS_DETECTION_MIRROR"


# ==================================================================================================
# (3) FATAL-2 — detection_mirror.py imports ONLY the stdlib (reaching its deps by RELATIVE import).
# ==================================================================================================
def test_detection_mirror_imports_only_stdlib_and_reaches_deps_by_relative_import():
    src = Path(DM.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:          # absolute imports only
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core", "pydantic"):
        assert forbidden not in roots, f"detection_mirror must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "hashlib", "json", "os", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in detection_mirror.py: {sorted(roots - allowed)}"
    # AS-30 / AS-7b / AS-3b are reached by RELATIVE import only (never an absolute framework.* root).
    rel = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level == 1}
    assert "provider_runtime" in rel, "detection_mirror must reach the AS-30 inventory by relative import"
    assert "coraza_source" in rel, "detection_mirror must reach the AS-7b admit gate by relative import"
    assert "monitoring_event_v2" in rel, "detection_mirror must reach the AS-3b hygiene gate by relative import"


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


def test_gateway_detection_mirror_off_builds_no_meter_and_probe_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_DETECTION_MIRROR unset (coraza on + corpus) => NO active meter, the
    data path still forwards, and the probe snapshot carries NO detection_mirror keys."""
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    monkeypatch.delenv(DETECTION_MIRROR_ENV, raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.detection_mirror_meter is None
        assert gw.settings.detection_mirror_active is False
        assert [_get(port, "/x")[0] for _ in range(3)] == [200] * 3          # data path byte-identical
        snap = gw.settings._probe_snapshot()
        assert "detection_mirror" not in snap and "detection_mirror_active" not in snap
        assert "coraza" in snap                                             # the AS-7b dep is unaffected
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_detection_mirror_inert_without_the_coraza_dep(upstream, monkeypatch):
    """The mirror is inert whenever its AS-7b dep is off: flag on, but VIGIL_AEGIS_CORAZA off => no coraza meter =>
    no detection-mirror meter, no probe keys."""
    monkeypatch.setenv(DETECTION_MIRROR_ENV, "1")
    monkeypatch.delenv("VIGIL_AEGIS_CORAZA", raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.detection_mirror_meter is None
        assert gw.settings.detection_mirror_active is False
        assert "detection_mirror" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_detection_mirror_on_but_no_corpus_is_inert(upstream, monkeypatch):
    """No CRS corpus configured => inert (mirrors AS-7b's no-corpus case): no coraza meter => no mirror meter."""
    monkeypatch.setenv(DETECTION_MIRROR_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        assert gw.settings.detection_mirror_meter is None and gw.settings.detection_mirror_active is False
        assert "detection_mirror" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_detection_mirror_on_surfaces_the_mirror_on_the_probe_snapshot(upstream, monkeypatch):
    """Flag ON + the AS-7b dep ON + a CRS corpus => the probe snapshot surfaces the detection mirror computed from
    the AS-30 inventory + the AS-7b attestation, metadata-only (counts + tokens + a digest, never request bytes)."""
    monkeypatch.setenv(DETECTION_MIRROR_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.detection_mirror_meter is not None and gw.settings.detection_mirror_active is True
        for _ in range(3):
            assert _get(port, "/x")[0] == 200                               # data path forwards unchanged
        snap = gw.settings._probe_snapshot()
        assert snap["detection_mirror_active"] is True
        m = snap["detection_mirror"]
        assert m["content_admissible"] is True and m["clean"] is True
        assert "edr" in m["sources"] and "cloudtrail" in m["sources"] and "idp" in m["sources"]
        assert m["leads"] == ["932160", "941110", "942100"]
        assert len(m["digest"]) == 64
        assert "127.0.0.1" not in json.dumps(snap)                          # NO raw caller/upstream address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_detection_mirror_flip_off_at_runtime_stops_surfacing(upstream, monkeypatch):
    """Flipping VIGIL_AEGIS_DETECTION_MIRROR (or the coraza dep) OFF at runtime makes the mirror go inert live, so
    the probe answer drops the detection_mirror keys again."""
    monkeypatch.setenv(DETECTION_MIRROR_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        _get(port, "/x")
        assert "detection_mirror" in gw.settings._probe_snapshot()
        monkeypatch.setenv(DETECTION_MIRROR_ENV, "0")
        assert gw.settings.detection_mirror_active is False
        assert "detection_mirror" not in gw.settings._probe_snapshot()
        monkeypatch.setenv(DETECTION_MIRROR_ENV, "1")
        assert "detection_mirror" in gw.settings._probe_snapshot()          # restored -> surfaced again
        monkeypatch.setenv("VIGIL_AEGIS_CORAZA", "0")                       # the dep going off also makes it inert
        assert "detection_mirror" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_probe_without_corpus_is_byte_identical_whether_flag_on_or_off(upstream, monkeypatch):
    """The strongest OFF-invariance: with NO corpus configured, the probe snapshot is byte-identical whether the
    detection-mirror flag is on or off (AS-31 never touches the data path or the probe without its dependency)."""
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        monkeypatch.delenv(DETECTION_MIRROR_ENV, raising=False)
        off = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        monkeypatch.setenv(DETECTION_MIRROR_ENV, "1")
        on = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        assert off == on
    finally:
        gw.shutdown(); gw.server_close()
