"""AEGIS AS-23a (the deterministic read-only EARLY DETECTION-POSTURE BENCHMARK), deterministic, offline tests.

AS-23a is the EARLY benchmark: a read-only, metadata-only efficacy MEASURE that COMPOSES its three merged deps,
the AS-8 detection-content coverage (``DetectionCoverageMeter.summary``), the AS-7b Coraza/CRS admissibility
(carried by both composed meters), and the AS-31 detection mirror (``DetectionMirrorMeter.summary``), scoring
the admissible content against a small, FIXED, in-repo reference technique set (``REFERENCE_TECHNIQUES``). It is
not a detector, so DoD-1's "detector near-zero-FP" is N/A; it is substituted by efficacy-correctness vs a
hand-computed expectation + a byte-identity negative control. The DoD points, mapped to the sections below:

  (2) gate-invariance, importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-23a adds NO
      OracleKind); benchmark_early.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__ (nor
      are its deps, through it).
  (3) FATAL-2, benchmark_early.py imports ONLY the stdlib (reaching detection_coverage / detection_mirror /
      coraza_source / monitoring_event_v2 by RELATIVE import, consuming their results by composition); never
      sigil/governor/strix/apps/vigil_core.
  (4) determinism, identical coverage + mirror summaries yield a byte-identical digest and summary; no
      wall-clock, no RNG.
  (5) default-OFF + byte-identity, VIGIL_AEGIS_BENCHMARK off (or any dep flag off) => the armed-gated snapshot
      is a byte-identical inert no-op ({}) and the composed meters are never consulted; strict/fail-closed flag.
  (6) correctness + negative controls, the covered/missing reference tracks the admissible CRS content; the
      efficacy is integer-floor basis points; the digest matches a hand-computed canonical digest; a
      drifted/unlicensed corpus is DETECTED (admissible=False) and covers NOTHING of the reference; the digest
      MOVES on any posture change; a benchmark is NOT a block/verdict.
  (7) read-only, AS-23a NEVER mutates the licence ledger or the corpus, and NEVER drives an admit/shed/allow/
      block decision; only a fired oracle blocks; a covered reference technique is a LEAD.
  (8) no-leak, the summary is ADDRESS-FREE and bounded/sorted; a dotted-quad that survives the AS-7b charset
      scrub is DROPPED by the AS-8 hygiene gate before it is ever classified, so it never reaches the reference
      scoring; inadmissible content covers nothing of the reference (fail closed).

Everything is a pure function of its inputs; no real secret and no network. The benchmark runs lazily, off the
gate path (FORGE-DOMAIN-MAP Domain 6), so there is no live-gateway leg: it asserts nothing about live traffic.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from framework.v2.aegis import benchmark_early as BE
from framework.v2.aegis.benchmark_early import (
    BENCHMARK_ENV,
    REFERENCE_TECHNIQUES,
    BenchmarkEarly,
    BenchmarkEarlyMeter,
    benchmark_armed,
    benchmark_deps_armed,
    benchmark_digest,
    benchmark_early_enabled,
    benchmark_early_snapshot,
)
from framework.v2.aegis.coraza_source import CRS_CORPUS_ARTEFACT, CorazaAttestationMeter, CorazaCorpus
from framework.v2.aegis.detection_coverage import KNOWN_TECHNIQUES, DetectionCoverageMeter
from framework.v2.aegis.detection_mirror import DetectionMirrorMeter
from framework.v2.aegis.license_gate import load_ledger

# Every dependency flag the early benchmark requires to be armed (its own flag plus the three dep flags).
_ALL_FLAGS = (BENCHMARK_ENV, "VIGIL_AEGIS_CORAZA", "VIGIL_AEGIS_COVERAGE", "VIGIL_AEGIS_DETECTION_MIRROR")


def _corpus(rule_ids=("942100", "941110", "932160"), *, version="4.3.0", paranoia=1, expected_pin=None):
    return CorazaCorpus.build(version=version, paranoia=paranoia, rule_ids=rule_ids, expected_pin=expected_pin)


def _shipped_ledger():
    return load_ledger()


def _meter(corpus=None, *, ledger=None, inventory=None, reference=REFERENCE_TECHNIQUES, redact_literals=()):
    corp = corpus if corpus is not None else _corpus()
    cm = CorazaAttestationMeter(corp, ledger=ledger if ledger is not None else _shipped_ledger())
    cov = DetectionCoverageMeter(cm, corp.rule_ids, redact_literals=redact_literals)
    mir = DetectionMirrorMeter(cm, corp.rule_ids, inventory=inventory, redact_literals=redact_literals)
    return BenchmarkEarlyMeter(cov, mir, reference=reference, redact_literals=redact_literals)


# ==================================================================================================
# fixture sanity, the reference set is a fixed, sorted, address-free subset of the AS-8 taxonomy.
# ==================================================================================================
def test_reference_set_is_fixed_sorted_and_classifiable():
    assert REFERENCE_TECHNIQUES == tuple(sorted(REFERENCE_TECHNIQUES))        # sorted, representation-stable
    assert len(REFERENCE_TECHNIQUES) == len(set(REFERENCE_TECHNIQUES))        # de-duplicated
    # every reference technique is a NAMED AS-8 technique (so it is classifiable and can be covered)
    for tech in REFERENCE_TECHNIQUES:
        assert tech in KNOWN_TECHNIQUES, tech
    # a fixed in-repo constant, address-free (plain technique labels, no address shapes)
    assert all(ch.isalnum() or ch == "-" for tok in REFERENCE_TECHNIQUES for ch in tok)


# ==================================================================================================
# (6) correctness, the covered/missing reference tracks the admissible CRS content.
# ==================================================================================================
def test_efficacy_tracks_the_admissible_crs_content():
    # 942100 sqli, 941110 xss, 932160 rce, 930120 lfi => covers 4 of the 8 reference techniques.
    bm = _meter(_corpus(rule_ids=["942100", "941110", "932160", "930120"])).summary()
    assert bm.admissible is True and bm.consistent is True
    assert bm.covered == ("lfi", "rce", "sqli", "xss")                       # sorted intersection with reference
    assert bm.covered_count == 4
    assert bm.missing == ("php-injection", "protocol-attack", "rfi", "scanner-detection")
    assert bm.missing_count == 4
    assert bm.reference == REFERENCE_TECHNIQUES and bm.reference_count == len(REFERENCE_TECHNIQUES)
    assert bm.clean is True


def test_covered_counts_only_reference_techniques():
    """A covered technique OUTSIDE the reference set (943xxx session-fixation) raises efficacy NOT at all, only
    reference techniques count toward the benchmark numerator."""
    bm = _meter(_corpus(rule_ids=["942100", "943100"])).summary()            # sqli (in ref) + session-fixation
    assert bm.covered == ("sqli",)                                           # session-fixation is not referenced
    assert bm.covered_count == 1


def test_efficacy_bps_is_integer_floor_covered_over_reference():
    bm = _meter(_corpus(rule_ids=["942100", "941110", "932160"])).summary()  # 3 of 8 reference techniques
    assert bm.covered_count == 3
    assert bm.efficacy_bps == (3 * 10000 // len(REFERENCE_TECHNIQUES))       # integer floor, no float
    assert isinstance(bm.efficacy_bps, int)


def test_full_reference_coverage_is_ten_thousand_bps():
    # one rule per reference technique band: 930 lfi, 933 php-injection, 921 protocol-attack, 932 rce,
    # 931 rfi, 913 scanner-detection, 942 sqli, 941 xss.
    bands = ["930100", "933100", "921100", "932100", "931100", "913100", "942100", "941100"]
    bm = _meter(_corpus(rule_ids=bands)).summary()
    assert set(bm.covered) == set(REFERENCE_TECHNIQUES) and bm.covered_count == len(REFERENCE_TECHNIQUES)
    assert bm.missing == () and bm.efficacy_bps == 10000


def test_digest_matches_a_hand_computed_canonical_digest():
    # sqli + xss + rce => covered {rce, sqli, xss}; mirror leads = the 3 admissible rule-ids; 4 sources (shipped).
    bm = _meter(_corpus(rule_ids=["942100", "941110", "932160"])).summary()
    payload = {
        "admissible": True,
        "reference": sorted(REFERENCE_TECHNIQUES),
        "covered": sorted(["rce", "sqli", "xss"]),
        "efficacy_bps": bm.efficacy_bps,
        "reflected_leads": bm.reflected_leads,
        "sources": bm.sources,
    }
    expect = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    assert bm.digest == expect
    assert benchmark_digest(True, REFERENCE_TECHNIQUES, ["rce", "sqli", "xss"],
                            bm.efficacy_bps, bm.reflected_leads, bm.sources) == expect


def test_benchmark_digest_is_order_and_duplicate_invariant():
    a = benchmark_digest(True, ["sqli", "xss"], ["xss", "sqli"], 2500, 3, 4)
    b = benchmark_digest(True, ["xss", "sqli", "sqli"], ["sqli", "xss", "xss"], 2500, 3, 4)
    assert a == b


def test_digest_moves_on_any_posture_change():
    base = benchmark_digest(True, ["sqli", "xss"], ["sqli"], 5000, 1, 4)
    assert base != benchmark_digest(False, ["sqli", "xss"], ["sqli"], 5000, 1, 4)     # content flips inadmissible
    assert base != benchmark_digest(True, ["sqli", "xss"], ["sqli", "xss"], 10000, 2, 4)  # a reference covered
    assert base != benchmark_digest(True, ["sqli", "xss"], ["sqli"], 5000, 2, 4)      # reflected posture moved
    assert base != benchmark_digest(True, ["sqli", "xss"], ["sqli"], 5000, 1, 5)      # a source added
    assert base != benchmark_digest(True, ["sqli", "xss", "rce"], ["sqli"], 3333, 1, 4)  # reference changed


# ==================================================================================================
# (6) negative controls, a drifted / unlicensed corpus covers NOTHING of the reference (fail closed).
# ==================================================================================================
def test_a_drifted_corpus_covers_nothing_of_the_reference():
    """A corpus whose live content no longer matches the pin it is pinned to is NOT admissible => admissible
    False => NOTHING of the reference is covered, efficacy 0, the whole reference is missing, even though the
    licence ledger is clean (the AS-7b fail-closed stance propagated through AS-8)."""
    drifted = _corpus(rule_ids=["942100", "941110"], expected_pin="deadbeef" * 8)
    bm = _meter(drifted).summary()
    assert bm.admissible is False
    assert bm.covered == () and bm.covered_count == 0 and bm.efficacy_bps == 0
    assert bm.missing == bm.reference and bm.missing_count == bm.reference_count


def test_a_missing_crs_licence_covers_nothing_of_the_reference():
    ledger = [r for r in _shipped_ledger() if r.artefact != CRS_CORPUS_ARTEFACT]
    bm = _meter(ledger=ledger).summary()
    assert bm.admissible is False and bm.covered == () and bm.efficacy_bps == 0


def test_an_empty_reference_set_is_fail_closed_zero_efficacy():
    bm = _meter(reference=()).summary()
    assert bm.reference == () and bm.reference_count == 0
    assert bm.covered == () and bm.missing == () and bm.efficacy_bps == 0     # no division, deterministic 0


# ==================================================================================================
# (6) composition, the benchmark genuinely composes AS-8 coverage + AS-31 reflection.
# ==================================================================================================
def test_reflected_posture_tracks_the_as31_mirror():
    from framework.v2.aegis.provider_runtime import build_provider_runtime_registry
    inv_ids = sorted(set(build_provider_runtime_registry().provider_ids))
    bm = _meter(_corpus(rule_ids=["942100", "941110", "932160"])).summary()
    assert bm.sources == len(inv_ids)                                        # AS-31 cataloged source count
    assert bm.reflected_leads == 3                                           # AS-31 admissible lead count


def test_consistent_flag_holds_when_both_meters_share_the_corpus():
    bm = _meter().summary()
    assert bm.consistent is True                                            # AS-8 and AS-31 agree on admissibility


def test_consistency_divergence_is_surfaced_when_meters_differ():
    """Build the coverage meter over an ADMISSIBLE corpus and the mirror over a DRIFTED one: AS-8 says admissible,
    AS-31 says inadmissible, so the composition flags the divergence (a measurement, never an action)."""
    good = _corpus(rule_ids=["942100", "941110"])
    drifted = _corpus(rule_ids=["942100", "941110"], expected_pin="00" * 32)
    cov = DetectionCoverageMeter(CorazaAttestationMeter(good, ledger=_shipped_ledger()), good.rule_ids)
    mir = DetectionMirrorMeter(CorazaAttestationMeter(drifted, ledger=_shipped_ledger()), drifted.rule_ids)
    bm = BenchmarkEarlyMeter(cov, mir).summary()
    assert bm.admissible is True and bm.consistent is False


# ==================================================================================================
# (8) no-leak, ADDRESS-FREE: an IP-shaped rule-ref never reaches the reference scoring.
# ==================================================================================================
def test_an_ip_shaped_rule_ref_never_reaches_the_reference_scoring():
    """The AS-7b address-free charset keeps digits and '.', so a raw dotted-quad SURVIVES its scrub. The AS-8
    hygiene gate drops it before classification, so it never becomes a covered technique and never leaks into
    the benchmark body."""
    bm = _meter(_corpus(rule_ids=["203.0.113.9", "942100"])).summary()
    blob = json.dumps(bm.to_dict())
    assert "203.0.113.9" not in blob
    assert bm.covered == ("sqli",) and bm.clean is True                     # the IP-shaped token is dropped


def test_a_secret_literal_is_redacted_from_the_surfaced_body():
    bm = _meter(_corpus(rule_ids=["S3CRET", "942100"]), redact_literals=("S3CRET",)).summary()
    assert "S3CRET" not in json.dumps(bm.to_dict())
    assert bm.covered == ("sqli",)


def test_summary_is_address_free_and_metadata_only():
    bm = _meter(_corpus(rule_ids=["942100", "10.0.0.1", "941110"])).summary()
    blob = json.dumps(bm.to_dict())
    assert "10.0.0.1" not in blob
    assert bm.clean is True
    assert set(bm.covered) == {"sqli", "xss"}                               # the IP-shaped token never classified


def test_a_benchmark_is_never_a_block_or_verdict():
    blob = json.dumps(_meter().summary().to_dict())
    for forbidden in ("certificate", "verdict", "decision", "action", "block", "shed", "allow"):
        assert forbidden not in blob


# ==================================================================================================
# (4) determinism, identical inputs yield a byte-identical digest and summary.
# ==================================================================================================
def test_identical_inputs_yield_a_byte_identical_summary():
    def _run() -> str:
        return json.dumps(_meter().summary().to_dict(), sort_keys=True)
    assert _run() == _run()


def test_summary_is_a_pure_typed_dataclass():
    bm = _meter().summary()
    assert isinstance(bm, BenchmarkEarly)
    assert len(bm.digest) == 64
    assert bm.covered_count == len(bm.covered) and bm.missing_count == len(bm.missing)
    assert bm.covered_count + bm.missing_count == bm.reference_count        # covered and missing partition the ref
    assert set(bm.covered).isdisjoint(set(bm.missing))


# ==================================================================================================
# (7) READ-ONLY, the meter never mutates the injected ledger or the corpus.
# ==================================================================================================
def test_meter_never_mutates_the_injected_ledger_or_corpus():
    ledger = _shipped_ledger()
    before_ledger = [r.model_dump() for r in ledger]
    corp = _corpus()
    before_corpus = (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin)
    cm = CorazaAttestationMeter(corp, ledger=ledger)
    bm = BenchmarkEarlyMeter(DetectionCoverageMeter(cm, corp.rule_ids), DetectionMirrorMeter(cm, corp.rule_ids))
    for _ in range(50):
        bm.snapshot()
    assert [r.model_dump() for r in ledger] == before_ledger                # ledger untouched
    assert (corp.version, corp.paranoia, corp.rule_ids, corp.expected_pin) == before_corpus


# ==================================================================================================
# (5) default-OFF arming + fail-closed flag parse + byte-identical inert no-op.
# ==================================================================================================
def test_benchmark_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(BENCHMARK_ENV, raising=False)
    assert benchmark_early_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(BENCHMARK_ENV, on)
        assert benchmark_early_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(BENCHMARK_ENV, off)
        assert benchmark_early_enabled() is False, off


def test_armed_requires_the_own_flag_and_every_dep_flag(monkeypatch):
    for f in _ALL_FLAGS:
        monkeypatch.setenv(f, "1")
    assert benchmark_deps_armed() is True and benchmark_armed() is True
    # dropping ANY single flag disarms the benchmark (strict AND).
    for f in _ALL_FLAGS:
        monkeypatch.setenv(f, "1")
        monkeypatch.setenv(f, "0")
        assert benchmark_armed() is False, f
        monkeypatch.setenv(f, "1")


def test_snapshot_is_a_byte_identical_inert_no_op_when_not_armed(monkeypatch):
    """OFF (own flag or ANY dep flag) => the armed-gated snapshot is {} regardless of what the meter would
    compute, byte-identical across every unarmed configuration."""
    mt = _meter()
    for f in _ALL_FLAGS:
        monkeypatch.delenv(f, raising=False)
    assert benchmark_early_snapshot(mt) == {}
    # own flag off, deps on
    for f in ("VIGIL_AEGIS_CORAZA", "VIGIL_AEGIS_COVERAGE", "VIGIL_AEGIS_DETECTION_MIRROR"):
        monkeypatch.setenv(f, "1")
    monkeypatch.delenv(BENCHMARK_ENV, raising=False)
    assert benchmark_early_snapshot(mt) == {}
    # own flag on, one dep off
    monkeypatch.setenv(BENCHMARK_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_DETECTION_MIRROR", "0")
    assert benchmark_early_snapshot(mt) == {}


def test_snapshot_surfaces_the_measure_only_when_fully_armed(monkeypatch):
    mt = _meter(_corpus(rule_ids=["942100", "941110", "932160"]))
    for f in _ALL_FLAGS:
        monkeypatch.setenv(f, "1")
    snap = benchmark_early_snapshot(mt)
    assert snap and snap["admissible"] is True and snap["covered"] == ["rce", "sqli", "xss"]
    assert snap["efficacy_bps"] == (3 * 10000 // len(REFERENCE_TECHNIQUES))
    assert len(snap["digest"]) == 64
    # the armed snapshot equals the raw meter snapshot (arming only gates WHETHER it is read, not WHAT).
    assert snap == mt.snapshot()


# ==================================================================================================
# (2) gate-invariance, AS-23a adds NO OracleKind; benchmark_early.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                        # a benchmark is a measurement, not an oracle


def test_benchmark_early_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                              # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.benchmark_early' not in sys.modules, "
        "'benchmark_early.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "assert 'framework.v2.aegis.detection_coverage' not in sys.modules, "
        "'detection_coverage must stay OFF the import path (benchmark_early must not drag it on eagerly)';"
        "assert 'framework.v2.aegis.detection_mirror' not in sys.modules, "
        "'detection_mirror must stay OFF the import path';"
        "assert 'framework.v2.aegis.coraza_source' not in sys.modules, "
        "'coraza_source must stay OFF the import path';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"benchmark_early reachable from init/main:\n{out.stdout}\n{out.stderr}"


# ==================================================================================================
# (3) FATAL-2, benchmark_early.py imports ONLY the stdlib (reaching its deps by RELATIVE import).
# ==================================================================================================
def test_benchmark_early_imports_only_stdlib_and_reaches_deps_by_relative_import():
    src = Path(BE.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:          # absolute imports only
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core", "pydantic"):
        assert forbidden not in roots, f"benchmark_early must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "hashlib", "json", "os", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in benchmark_early.py: {sorted(roots - allowed)}"
    # the AS-8 / AS-31 / AS-7b / AS-2e deps are reached by RELATIVE import only (never an absolute framework.* root).
    rel = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level == 1}
    assert "detection_coverage" in rel, "benchmark_early must reach the AS-8 coverage meter by relative import"
    assert "detection_mirror" in rel, "benchmark_early must reach the AS-31 mirror meter by relative import"
    assert "coraza_source" in rel, "benchmark_early must reach the AS-7b flag predicate by relative import"
    assert "monitoring_event_v2" in rel, "benchmark_early must reach the AS-2e hygiene gate by relative import"


def test_benchmark_early_has_no_module_scope_framework_import():
    """FATAL-2 boundary: at MODULE SCOPE benchmark_early.py imports only the stdlib; every framework.* dep is a
    lazy relative import inside a function/method body (so it stays off the eager __init__/__main__ plane)."""
    src = Path(BE.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in tree.body:                                                  # module-scope statements only
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"module-scope relative import not allowed: {ast.dump(node)}"
            assert (node.module or "").split(".")[0] in {
                "__future__", "hashlib", "json", "os", "dataclasses", "typing"}
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in {"hashlib", "json", "os", "dataclasses", "typing"}
