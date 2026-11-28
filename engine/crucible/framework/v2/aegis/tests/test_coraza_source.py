"""AEGIS AS-7b (Coraza/CRS front-WAF SUPPLY-CHAIN ATTESTATION + typed ``rule_refs`` lead admission) — deterministic,
offline acceptance tests.

AS-7b is the SUPPLY-CHAIN gate for the Coraza v3 DetectionOnly front WAF + its CRS rule corpus. Per doctrine
(ADR 0003) a CRS hit is a LEAD in typed ``rule_refs``, never a standalone block. AS-7b composes the two SC gates
already in the tree — the AS-7a §7 licence gate (is the ``coraza-v3`` engine + ``coreruleset-crs-4x`` corpus
licence-admitted for service use?) and an AS-28-style corpus PIN (is the rule corpus pinned to a known digest?) —
into a read-only attestation: ``admissible = licensed AND pinned``. A Coraza hit's refs are admitted as LEADS only
over an admissible corpus; otherwise they are DROPPED (fail closed). It is not a detector, so DoD-1's
"detector near-zero-FP" is N/A; it is substituted by attestation-correctness vs a hand-computed expectation + a
byte-identity negative control. The DoD points, mapped to the sections below:

  (1) e2e behavioral — a configured gateway with the flag ON (and a CRS corpus) surfaces the attestation on the
      AS-5c probe snapshot, computed from the shipped §7 ledger + the corpus pin, end-to-end through the gateway.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-7b adds NO
      OracleKind); coraza_source.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__ (nor is
      license_gate, through it); gateway.CORAZA_ENV is in lockstep.
  (3) FATAL-2 — coraza_source.py imports ONLY the stdlib (reaching the AS-7a license_gate + §7 UseMode by RELATIVE
      import, consuming the ledger records by injection); never sigil/governor/strix/apps/vigil_core.
  (4) determinism — identical corpus + ledger yield a byte-identical pin and summary; no wall-clock, no RNG.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_CORAZA off (or NO corpus configured) => NO meter is active, nothing
      is computed, and the probe snapshot is byte-identical (no coraza keys); the flag is strict/fail-closed.
  (6) correctness + negative controls — the pin matches a hand-computed digest; licensed/pinned/admissible track the
      §7 ledger + the corpus content; a drifted corpus is DETECTED (pinned=False) and a removed §7 record is
      DETECTED (licensed=False), both dropping admission; normalize is ADDRESS-FREE (no client address / URI / data
      leak) and bounded/sorted/de-duplicated; an attestation is NOT a block/verdict (it never acts).
  (7) read-only — AS-7b NEVER mutates the injected ledger or the corpus, and NEVER drives an admit/shed/allow/block
      decision; only a fired oracle blocks; a CRS rule_ref is a LEAD.

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

from framework.v2.aegis import coraza_source as C
from framework.v2.aegis.coraza_source import (
    CORAZA_ENV,
    CRS_CORPUS_ARTEFACT,
    WAF_ENGINE_ARTEFACT,
    CorazaAttestation,
    CorazaAttestationMeter,
    CorazaCorpus,
    admit_rule_refs,
    coraza_enabled,
    corpus_pin,
    normalize_rule_refs,
)
from framework.v2.aegis.license_gate import LicenseRecord, load_ledger
from framework.v2.aegis.license_policy import UseMode


def _corpus(rule_ids=("942100", "941110", "932160"), *, version="4.3.0", paranoia=1, expected_pin=None):
    return CorazaCorpus.build(version=version, paranoia=paranoia, rule_ids=rule_ids, expected_pin=expected_pin)


def _shipped_ledger():
    return load_ledger()


# ==================================================================================================
# (6) corpus pin correctness — matches a hand-computed digest; order/dup-invariant; moves on content change.
# ==================================================================================================
def test_corpus_pin_matches_a_hand_computed_canonical_digest():
    ids = ["942100", "941110", "941110"]  # a duplicate + unsorted
    payload = {"artefact": CRS_CORPUS_ARTEFACT, "version": "4.3.0", "paranoia": 1,
               "rule_ids": ["941110", "942100"]}  # normalized: sorted + de-duplicated
    expect = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    assert corpus_pin("4.3.0", 1, ids) == expect


def test_corpus_pin_is_order_and_duplicate_invariant():
    a = corpus_pin("4.3.0", 1, ["942100", "941110", "932160"])
    b = corpus_pin("4.3.0", 1, ["932160", "942100", "941110", "942100"])  # reordered + duplicated
    assert a == b


def test_corpus_pin_moves_when_a_rule_version_or_paranoia_changes():
    base = corpus_pin("4.3.0", 1, ["942100", "941110"])
    assert base != corpus_pin("4.3.0", 1, ["942100", "941110", "933100"])  # rule added
    assert base != corpus_pin("4.3.0", 1, ["942100"])                      # rule removed
    assert base != corpus_pin("4.4.0", 1, ["942100", "941110"])            # version bump
    assert base != corpus_pin("4.3.0", 2, ["942100", "941110"])            # paranoia bump


def test_corpus_build_normalizes_rule_ids_and_self_pins():
    corp = _corpus(rule_ids=["942100", "941110", "942100", "x!bad id"])
    assert corp.rule_ids == ("941110", "942100", "xbadid")                 # scrubbed, de-duplicated, sorted
    assert corp.pinned is True and corp.pin == corp.expected_pin           # self-consistent by default


# ==================================================================================================
# (6) licensed / pinned / admissible — track the §7 ledger + the corpus content.
# ==================================================================================================
def test_attestation_over_the_shipped_ledger_is_admissible():
    att = CorazaAttestationMeter(_corpus(), ledger=_shipped_ledger()).summary()
    assert att.licensed is True and att.pinned is True and att.admissible is True
    assert att.engine == WAF_ENGINE_ARTEFACT and att.artefact == CRS_CORPUS_ARTEFACT
    assert att.blocking == 0 and att.rules == 3


def test_a_drifted_corpus_is_detected_and_blocks_admission():
    """A corpus whose live content no longer matches the digest it is pinned to is NOT pinned => NOT admissible,
    even though the licence ledger is clean. The AS-28-style tamper-evidence for the rule content."""
    drifted = _corpus(rule_ids=["942100"], expected_pin="deadbeef" * 8)
    att = CorazaAttestationMeter(drifted, ledger=_shipped_ledger()).summary()
    assert att.licensed is True and att.pinned is False and att.admissible is False


def test_a_missing_crs_licence_record_is_detected_and_blocks_admission():
    """Drop the coreruleset-crs-4x §7 record from the ledger -> the AS-7a gate fails closed (missing_ledger_record)
    -> licensed=False -> NOT admissible, even though the corpus content is self-consistently pinned."""
    ledger = [r for r in _shipped_ledger() if r.artefact != CRS_CORPUS_ARTEFACT]
    att = CorazaAttestationMeter(_corpus(), ledger=ledger).summary()
    assert att.licensed is False and att.pinned is True and att.admissible is False
    assert att.blocking >= 1


def test_a_policy_denied_crs_licence_is_detected():
    """A CRS corpus ledgered under a DENIED licence (e.g. SSPL for service use) fails the §7 policy -> licensed
    False -> not admissible. Models an unacceptable third-party rule-content licence."""
    ledger = [r for r in _shipped_ledger() if r.artefact not in (CRS_CORPUS_ARTEFACT, WAF_ENGINE_ARTEFACT)]
    ledger.append(LicenseRecord(artefact=WAF_ENGINE_ARTEFACT, license="Apache-2.0", use_mode=UseMode.SERVICE))
    ledger.append(LicenseRecord(artefact=CRS_CORPUS_ARTEFACT, component_kind="rule", license="SSPL-1.0",
                                use_mode=UseMode.SERVICE))
    att = CorazaAttestationMeter(_corpus(), ledger=ledger).summary()
    assert att.licensed is False and att.admissible is False and att.blocking >= 1


# ==================================================================================================
# (6)/(7) admit gate — refs admitted as leads ONLY over an admissible corpus; never a block.
# ==================================================================================================
def test_admit_passes_refs_over_an_admissible_corpus():
    att = CorazaAttestationMeter(_corpus(), ledger=_shipped_ledger()).summary()
    assert admit_rule_refs(["942100", "941110"], att) == ("941110", "942100")  # normalized (sorted, de-duplicated)


def test_admit_drops_refs_over_an_inadmissible_corpus_fail_closed():
    drifted = _corpus(rule_ids=["942100"], expected_pin="00" * 32)
    att = CorazaAttestationMeter(drifted, ledger=_shipped_ledger()).summary()
    assert att.admissible is False
    assert admit_rule_refs(["942100", "941110"], att) == ()                    # unverified content raises NO belief


def test_admit_bounds_and_normalizes():
    att = CorazaAttestationMeter(_corpus(), ledger=_shipped_ledger()).summary()
    many = [str(900000 + i) for i in range(C._MAX_RULE_REFS + 20)]
    out = admit_rule_refs(many, att)
    assert len(out) == C._MAX_RULE_REFS and list(out) == sorted(out)           # bounded + sorted


def test_an_attestation_is_a_measurement_never_a_block_or_verdict():
    att = CorazaAttestationMeter(_corpus(), ledger=_shipped_ledger()).summary()
    blob = json.dumps(att.to_dict())
    assert "certificate" not in blob and "verdict" not in blob and "decision" not in blob and "action" not in blob


# ==================================================================================================
# (6) ADDRESS-FREE normalize — only scrubbed rule ids surface, never a client address / URI / matched data.
# ==================================================================================================
def test_normalize_is_address_free_and_drops_request_bytes():
    event = {
        "clientIp": "203.0.113.9",
        "uri": "/admin?q=' OR 1=1",
        "messages": [
            {"id": "942100", "data": "Matched Data: SECRET-TOKEN found in ARGS:q", "message": "SQLi"},
            {"ruleId": "941110", "data": "203.0.113.9 <script>"},
        ],
    }
    refs = normalize_rule_refs(event)
    assert refs == ("941110", "942100")
    blob = json.dumps(refs)
    for leak in ("203.0.113.9", "SECRET-TOKEN", "OR 1=1", "/admin", "script"):
        assert leak not in blob


def test_normalize_handles_shapes_bounds_sorts_and_dedupes():
    assert normalize_rule_refs({"rule_ids": ["942100", "942100", "941110"]}) == ("941110", "942100")
    assert normalize_rule_refs(b'{"messages":[{"id":"932160"}]}') == ("932160",)
    assert normalize_rule_refs('{"messages":[{"id":"949110"}]}') == ("949110",)
    flood = {"messages": [{"id": str(900000 + i)} for i in range(C._MAX_RULE_REFS + 50)]}
    assert len(normalize_rule_refs(flood)) == C._MAX_RULE_REFS


def test_normalize_is_total_on_malformed_input():
    for bad in (None, 123, "not json", b"\xff\xfe", {"messages": "nope"}, {"no_messages": 1}, []):
        out = normalize_rule_refs(bad)
        assert isinstance(out, tuple) and all(isinstance(t, str) for t in out)
    assert normalize_rule_refs(None) == () and normalize_rule_refs("not json") == ()
    assert normalize_rule_refs({"messages": [{"id": "!!!"}]}) == ()           # scrubs to empty -> dropped


# ==================================================================================================
# (4) determinism — identical corpus + ledger yield a byte-identical pin and summary.
# ==================================================================================================
def test_identical_inputs_yield_a_byte_identical_summary():
    ledger = _shipped_ledger()
    corp = _corpus()

    def _run() -> str:
        return json.dumps(CorazaAttestationMeter(corp, ledger=ledger).summary().to_dict(), sort_keys=True)

    assert _run() == _run()


def test_summary_is_a_pure_typed_dataclass():
    att = CorazaAttestationMeter(_corpus(), ledger=_shipped_ledger()).summary()
    assert isinstance(att, CorazaAttestation)
    assert att.corpus_digest == _corpus().pin


# ==================================================================================================
# (7) READ-ONLY — the meter never mutates the injected ledger or the corpus.
# ==================================================================================================
def test_meter_never_mutates_the_injected_ledger_or_corpus():
    ledger = _shipped_ledger()
    before = [r.model_dump() for r in ledger]
    corp = _corpus()
    before_corpus = (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin)
    meter = CorazaAttestationMeter(corp, ledger=ledger)
    for _ in range(50):
        meter.snapshot()
    assert [r.model_dump() for r in ledger] == before                        # ledger untouched
    assert (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin) == before_corpus


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_coraza_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(CORAZA_ENV, raising=False)
    assert coraza_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(CORAZA_ENV, on)
        assert coraza_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(CORAZA_ENV, off)
        assert coraza_enabled() is False, off


# ==================================================================================================
# (2) gate-invariance — AS-7b adds NO OracleKind; coraza_source.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                        # an attestation is a measurement, not an oracle


def test_coraza_source_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                              # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.coraza_source' not in sys.modules, "
        "'coraza_source.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "assert 'framework.v2.aegis.license_gate' not in sys.modules, "
        "'license_gate.py must stay OFF the import path (coraza_source must not drag it on eagerly)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"coraza_source reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_coraza_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.CORAZA_ENV == CORAZA_ENV == "VIGIL_AEGIS_CORAZA"


# ==================================================================================================
# (3) FATAL-2 — coraza_source.py imports ONLY the stdlib (reaching license_gate by RELATIVE import).
# ==================================================================================================
def test_coraza_source_imports_only_stdlib_and_reaches_deps_by_relative_import():
    src = Path(C.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:          # absolute imports only
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core", "pydantic"):
        assert forbidden not in roots, f"coraza_source must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "hashlib", "json", "os", "re", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in coraza_source.py: {sorted(roots - allowed)}"
    # the AS-7a licence gate / §7 policy are reached by RELATIVE import only (never an absolute framework.* root).
    rel = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level == 1}
    assert "license_gate" in rel, "coraza_source must reach the AS-7a licence gate by relative import"


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


def test_gateway_coraza_off_builds_no_meter_and_probe_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_CORAZA unset (corpus configured) => NO active meter, the data path
    still forwards, and the probe snapshot carries NO coraza keys."""
    monkeypatch.delenv(CORAZA_ENV, raising=False)
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.coraza_meter is None
        assert gw.settings.coraza_active is False
        assert [_get(port, "/x")[0] for _ in range(3)] == [200] * 3          # data path byte-identical
        snap = gw.settings._probe_snapshot()
        assert "coraza" not in snap and "coraza_active" not in snap
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_coraza_on_but_no_corpus_is_inert(upstream, monkeypatch):
    """No CRS corpus configured => inert (mirrors AS-5a's no-budget case): no meter, no probe keys."""
    monkeypatch.setenv(CORAZA_ENV, "1")
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        assert gw.settings.coraza_meter is None and gw.settings.coraza_active is False
        assert "coraza" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_coraza_on_surfaces_the_attestation_on_the_probe_snapshot(upstream, monkeypatch):
    """Flag ON + a CRS corpus => the probe snapshot surfaces the supply-chain attestation computed from the shipped
    §7 ledger + the corpus pin, metadata-only (counts + a digest, never request bytes)."""
    monkeypatch.setenv(CORAZA_ENV, "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        assert gw.settings.coraza_meter is not None and gw.settings.coraza_active is True
        for _ in range(3):
            assert _get(port, "/x")[0] == 200                               # data path forwards unchanged
        snap = gw.settings._probe_snapshot()
        assert snap["coraza_active"] is True
        a = snap["coraza"]
        assert a["licensed"] is True and a["pinned"] is True and a["admissible"] is True
        assert a["engine"] == WAF_ENGINE_ARTEFACT and a["artefact"] == CRS_CORPUS_ARTEFACT and a["rules"] == 3
        assert len(a["corpus_digest"]) == 64
        assert "127.0.0.1" not in json.dumps(snap)                          # NO raw caller/upstream address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_coraza_flip_off_at_runtime_stops_surfacing_the_attestation(upstream, monkeypatch):
    """Flipping VIGIL_AEGIS_CORAZA OFF at runtime makes the attestation go inert live, so the probe answer drops the
    coraza keys again."""
    monkeypatch.setenv(CORAZA_ENV, "1")
    gw, port = _run_gateway(upstream, coraza_corpus=_corpus())
    try:
        _get(port, "/x")
        assert "coraza" in gw.settings._probe_snapshot()
        monkeypatch.setenv(CORAZA_ENV, "0")
        assert gw.settings.coraza_active is False
        assert "coraza" not in gw.settings._probe_snapshot()
        monkeypatch.setenv(CORAZA_ENV, "1")
        assert "coraza" in gw.settings._probe_snapshot()                    # restored -> surfaced again
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_probe_without_corpus_is_byte_identical_whether_flag_on_or_off(upstream, monkeypatch):
    """The strongest OFF-invariance: with NO corpus configured, the probe snapshot is byte-identical whether the
    flag is on or off (AS-7b never touches the data path or the probe without its configured dependency)."""
    gw, port = _run_gateway(upstream, coraza_corpus=None)
    try:
        monkeypatch.delenv(CORAZA_ENV, raising=False)
        off = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        monkeypatch.setenv(CORAZA_ENV, "1")
        on = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        assert off == on
    finally:
        gw.shutdown(); gw.server_close()
