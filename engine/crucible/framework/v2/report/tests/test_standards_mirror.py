"""APEX PR-A — the vigil_core standards MIRROR never drifts from the engine tables.

The sovereign consumer renders standards chips + impact×effort priority from ``vigil_core.standards_mirror``
(inert JSON) instead of importing the engine (FATAL-2). That is sound ONLY if the mirror is byte-faithful to
the engine's ``report.standards`` / ``report.priority``. This test — which runs where BOTH are importable (the
offense/engine env) — RE-GENERATES the mirror in memory with the committed generator and asserts:

  1. the committed ``standards_mirror.json`` is EXACTLY what the generator produces now (no hand-edit, no drift);
  2. ``vigil_core.standards_mirror.controls_for(x)`` == ``report.standards.controls_for(x)`` for EVERY known
     class spelling AND a spread of raw inputs (the consumer's lookup is faithful); and
  3. the mirrored priority primitives (effort_size / priority_score / tier) equal the engine's.

If the engine table changes and the committed mirror is not regenerated, (1) REDS — the single source of truth
is the engine, and the mirror is a generated artifact.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

# engine/crucible/framework/v2/report/tests/test_standards_mirror.py -> parents[6] is the repo root.
_REPO = pathlib.Path(__file__).resolve().parents[6]
_GEN = _REPO / "tools" / "gen_standards_mirror.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_standards_mirror", _GEN)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mirror():
    try:
        from vigil_core import standards_mirror as sm
    except Exception:  # pragma: no cover - vigil_core must be importable in this env
        pytest.skip("vigil_core not importable in this environment")
    return sm


def test_committed_mirror_matches_freshly_generated():
    gen = _load_generator()
    fresh = gen.mirror_json(gen.build_mirror())
    committed = gen.target_path().read_text(encoding="utf-8")
    assert committed == fresh, (
        "standards_mirror.json is stale — regenerate it:\n"
        "  PYTHONPATH=engine/crucible:packages/core/vigil_core "
        ".venv-offense/bin/python tools/gen_standards_mirror.py")


def test_mirror_controls_match_engine_for_every_known_class():
    from framework.v2.report import standards as S
    from framework.v2.verify.verifier import known_bug_classes
    sm = _mirror()
    mismatches = [c for c in sorted(known_bug_classes()) if sm.controls_for(c) != S.controls_for(c)]
    assert not mismatches, f"mirror disagrees with the engine for: {mismatches[:10]}"


def test_mirror_controls_match_engine_for_raw_inputs():
    from framework.v2.report import standards as S
    sm = _mirror()
    for raw in ["SQL Injection", "sql-injection", "  RCE  ", "OPEN_REDIRECT", "Cross-Site Scripting",
                "not_a_class", "", "path traversal"]:
        assert sm.controls_for(raw) == S.controls_for(raw), raw


def test_mirror_priority_matches_engine():
    from framework.v2.report import priority as P
    sm = _mirror()
    for bc in ["sqli", "xss", "open_redirect", "rce", "supply_chain", "unknown_class"]:
        assert sm.effort_size(bc) == P.effort_size(bc), bc
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            assert sm.priority_score(sev, bc) == P.priority_score(sev, bc), (sev, bc)
            assert sm.tier(sev, sm.effort_size(bc)) == P._tier(sev, P.effort_size(bc)), (sev, bc)
    # (the mirror's namespace-purity — that it imports no `framework` — is proven authoritatively by the
    # sovereign two-env boundary test, which imports it in a REAL engine-free venv.)
