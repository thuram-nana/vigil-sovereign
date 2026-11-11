"""EC-2b — the A/B no-regression eval harness (eval.ab).

The proof that turning model-tier routing ON (arm B "cheaper") costs NO detection vs routing OFF (arm A
"capable"). These assertions are DETERMINISTIC + OFFLINE: a stub engagement runner stands in for the live
engine, so both arms' findings are controlled and the verdict is exact (no key, no network, no LLM).

Mutation-verify targets (each neuter reds a NAMED test here):
  * flip the gate DIRECTION (snapshot B / gate A instead of snapshot A / gate B)  -> test_fails_when_cheaper_arm_adds_a_false_positive
                                                                                    / test_fails_when_cheaper_arm_drops_a_true_positive
  * aggregate arm A at its WORST instead of its BEST (best=False in _run_arm A)     -> test_conservative_takes_A_at_its_best
  * aggregate arm B at its BEST instead of its WORST (best=True in _run_arm B)       -> test_conservative_takes_B_at_its_worst
  * stop scoping/restoring the arm routing env (leak it)                             -> test_routing_env_is_scoped_and_restored
  * fabricate a $ when the owner rate is unset                                       -> test_money_is_tokens_only_without_a_rate
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.v2.eval import ab
from framework.v2.eval.ab import ARM_A_CAPABLE, ARM_B_CHEAPER, _ROUTING_ENABLE_ENV, run_ab
from framework.v2.eval.benchmark_app import benchmark_corpus
from framework.v2.eval.validation import ExpectedFinding, NormalizedFinding
from framework.v2.kernel import cost_tap

_CRUCIBLE = Path(__file__).resolve().parents[4]


# --------------------------------------------------------------------------- fixtures / helpers
@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Routing + cost-tap read env at call time; clear them so a leak cannot make a test order-dependent."""
    monkeypatch.delenv(_ROUTING_ENABLE_ENV, raising=False)
    monkeypatch.delenv(cost_tap._ENABLE_ENV, raising=False)
    monkeypatch.delenv(ab._COST_RATES_ENV, raising=False)
    cost_tap.reset()
    yield
    cost_tap.reset()


def _target():
    """The labelled loopback target (11 planted bugs) — built offline, no server."""
    return benchmark_corpus("http://127.0.0.1")


def _nf(e: ExpectedFinding) -> NormalizedFinding:
    return NormalizedFinding(tool="crucible", bug_class=e.bug_class, location=e.location, confirmed=True)


def _all_tp(target) -> list[NormalizedFinding]:
    """A finding set that scores 11 TP / 0 FP against the manifest (one finding per planted bug)."""
    return [_nf(e) for e in target.expected]


def _fp(bug_class: str = "xss", location: str = "/users/safe?name") -> NormalizedFinding:
    """An off-manifest finding (a SAFE control) — a false positive by construction."""
    return NormalizedFinding(tool="crucible", bug_class=bug_class, location=location)


def _stub(per_repeat, tokens=None):
    """A deterministic engagement runner. ``per_repeat`` maps an arm name to a list of finding-lists (one per
    repeat). ``tokens`` optionally maps an arm name to a per-model token dict recorded into the cost tap on
    every repeat (used by the money tests)."""
    counters: dict[str, int] = {}

    def run(target, arm):
        i = counters.get(arm.name, 0)
        counters[arm.name] = i + 1
        if tokens and arm.name in tokens:
            for model, toks in tokens[arm.name].items():
                cost_tap.record(SimpleNamespace(model=model, tokens_in=int(toks), tokens_out=0, is_dryrun=False))
        return list(per_repeat[arm.name][i])

    return run


def _same(findings, repeats):
    return [list(findings) for _ in range(repeats)]


# --------------------------------------------------------------------------- the no-regression verdict
def test_passes_when_arms_are_identical():
    t = _target()
    tp = _all_tp(t)
    res = run_ab(t, repeats=3, runner=_stub({ARM_A_CAPABLE.name: _same(tp, 3),
                                             ARM_B_CHEAPER.name: _same(tp, 3)}))
    assert res.passed
    assert not res.verdict.regressions
    assert res.arm_a.aggregate.true_positives == 11 and res.arm_a.aggregate.false_positives == 0
    assert res.arm_b.aggregate.true_positives == 11 and res.arm_b.aggregate.false_positives == 0


def test_fails_when_cheaper_arm_adds_a_false_positive():
    # Arm B (cheaper) raises a false alarm on a SAFE control the capable arm did not — a detection REGRESSION.
    # This also pins the gate DIRECTION: B is the candidate gated against A's snapshot. Flip it and B's extra
    # FP reads as A's "improvement" and the gate wrongly passes.
    t = _target()
    tp = _all_tp(t)
    res = run_ab(t, repeats=2, runner=_stub({ARM_A_CAPABLE.name: _same(tp, 2),
                                             ARM_B_CHEAPER.name: _same(tp + [_fp()], 2)}))
    assert not res.passed
    assert any("NEW FP" in r for r in res.verdict.regressions)


def test_fails_when_cheaper_arm_drops_a_true_positive():
    # Arm B misses a planted bug the capable arm found — a coverage/recall REGRESSION. Also direction-sensitive.
    t = _target()
    tp = _all_tp(t)
    res = run_ab(t, repeats=2, runner=_stub({ARM_A_CAPABLE.name: _same(tp, 2),
                                             ARM_B_CHEAPER.name: _same(tp[:-1], 2)}))
    assert not res.passed
    assert any(("NEWLY MISSED" in r) or ("recall" in r.lower()) for r in res.verdict.regressions)


# --------------------------------------------------------------------------- conservative aggregation
def test_conservative_takes_A_at_its_best():
    # Arm A has an FP on ONE repeat but not the other. Taken at its BEST (fp=0), arm B's steady 1 FP is a
    # regression. If A were taken at its worst (fp=1) the gate would wrongly pass — so this pins "A best-case".
    t = _target()
    tp = _all_tp(t)
    a = [tp, tp + [_fp()]]              # repeat 0: clean; repeat 1: one FP  -> best-case fp = 0
    b = _same(tp + [_fp()], 2)          # steady 1 FP
    res = run_ab(t, repeats=2, runner=_stub({ARM_A_CAPABLE.name: a, ARM_B_CHEAPER.name: b}))
    assert res.arm_a.aggregate.false_positives == 0
    assert not res.passed
    assert any("NEW FP" in r for r in res.verdict.regressions)


def test_conservative_takes_B_at_its_worst():
    # Arm A is steadily clean; arm B has an FP on ONE repeat. Taken at its WORST (fp=1), B regresses. If B were
    # taken at its best (fp=0) the gate would wrongly pass — so this pins "B worst-case".
    t = _target()
    tp = _all_tp(t)
    a = _same(tp, 2)
    b = [tp, tp + [_fp()]]              # worst-case fp = 1
    res = run_ab(t, repeats=2, runner=_stub({ARM_A_CAPABLE.name: a, ARM_B_CHEAPER.name: b}))
    assert res.arm_b.aggregate.false_positives == 1
    assert not res.passed


# --------------------------------------------------------------------------- env scoping (never leaked)
def test_routing_env_is_scoped_and_restored(monkeypatch):
    t = _target()
    tp = _all_tp(t)
    seen: dict[str, str | None] = {}

    def run(target, arm):
        seen[arm.name] = os.environ.get(_ROUTING_ENABLE_ENV)
        return list(tp)

    assert _ROUTING_ENABLE_ENV not in os.environ
    run_ab(t, repeats=1, runner=run)
    # Each arm saw its own routing flag DURING its run ...
    assert seen[ARM_A_CAPABLE.name] == "0"   # capable: routing off
    assert seen[ARM_B_CHEAPER.name] == "1"   # cheaper: routing on
    # ... and the env is restored to its prior (unset) state afterwards — no leak.
    assert _ROUTING_ENABLE_ENV not in os.environ


# --------------------------------------------------------------------------- token / $ delta (money honesty)
def test_token_delta_is_real_and_per_model(monkeypatch):
    monkeypatch.setenv(cost_tap._ENABLE_ENV, "1")
    t = _target()
    tp = _all_tp(t)
    res = run_ab(
        t, repeats=1,
        runner=_stub({ARM_A_CAPABLE.name: _same(tp, 1), ARM_B_CHEAPER.name: _same(tp, 1)},
                     tokens={ARM_A_CAPABLE.name: {"claude-opus-4-8": 1000},
                             ARM_B_CHEAPER.name: {"claude-haiku-4-5": 400, "claude-opus-4-8": 100}}),
    )
    td = res.token_delta
    assert td.a_tokens == 1000 and td.b_tokens == 500
    assert td.delta_tokens == -500                       # cheaper arm saves 500 tokens
    assert td.a_tokens_by_model == {"claude-opus-4-8": 1000}
    assert td.b_tokens_by_model == {"claude-haiku-4-5": 400, "claude-opus-4-8": 100}
    assert td.usd_basis == "unset" and td.a_usd is None and td.delta_usd is None  # no rate -> no $


def test_money_is_tokens_only_without_a_rate(monkeypatch):
    monkeypatch.setenv(cost_tap._ENABLE_ENV, "1")
    t = _target()
    tp = _all_tp(t)
    res = run_ab(t, repeats=1,
                 runner=_stub({ARM_A_CAPABLE.name: _same(tp, 1), ARM_B_CHEAPER.name: _same(tp, 1)},
                              tokens={ARM_A_CAPABLE.name: {"m": 100}, ARM_B_CHEAPER.name: {"m": 40}}))
    # Tokens are real; $ is intentionally withheld (never fabricated) when no owner rate is configured.
    assert res.token_delta.delta_tokens == -60
    assert res.token_delta.usd_basis == "unset"
    assert res.token_delta.a_usd is None and res.token_delta.b_usd is None


def test_money_projects_from_owner_rate(monkeypatch):
    monkeypatch.setenv(cost_tap._ENABLE_ENV, "1")
    monkeypatch.setenv(ab._COST_RATES_ENV, '{"claude-opus-4-8": 15.0, "claude-haiku-4-5": 1.0}')
    t = _target()
    tp = _all_tp(t)
    res = run_ab(
        t, repeats=1,
        runner=_stub({ARM_A_CAPABLE.name: _same(tp, 1), ARM_B_CHEAPER.name: _same(tp, 1)},
                     tokens={ARM_A_CAPABLE.name: {"claude-opus-4-8": 1_000_000},
                             ARM_B_CHEAPER.name: {"claude-haiku-4-5": 1_000_000}}),
    )
    td = res.token_delta
    assert td.usd_basis == "usd_per_mtok"
    assert td.a_usd == pytest.approx(15.0) and td.b_usd == pytest.approx(1.0)
    assert td.delta_usd == pytest.approx(-14.0)          # going cheaper saves $14 / Mtok here


def test_money_withheld_when_a_spending_model_has_no_rate(monkeypatch):
    monkeypatch.setenv(cost_tap._ENABLE_ENV, "1")
    monkeypatch.setenv(ab._COST_RATES_ENV, '{"claude-opus-4-8": 15.0}')   # no rate for the cheaper model
    t = _target()
    tp = _all_tp(t)
    res = run_ab(
        t, repeats=1,
        runner=_stub({ARM_A_CAPABLE.name: _same(tp, 1), ARM_B_CHEAPER.name: _same(tp, 1)},
                     tokens={ARM_A_CAPABLE.name: {"claude-opus-4-8": 1000},
                             ARM_B_CHEAPER.name: {"claude-haiku-4-5": 400}}),
    )
    assert res.token_delta.usd_basis.startswith("incomplete")
    assert res.token_delta.b_usd is None and res.token_delta.delta_usd is None   # no fabrication


def test_cost_tap_off_reports_tokens_only():
    # Flag unset (the default): no tokens are attributed, and the delta is honestly zero with basis "off".
    t = _target()
    tp = _all_tp(t)
    res = run_ab(t, repeats=1,
                 runner=_stub({ARM_A_CAPABLE.name: _same(tp, 1), ARM_B_CHEAPER.name: _same(tp, 1)},
                              tokens={ARM_A_CAPABLE.name: {"m": 100}, ARM_B_CHEAPER.name: {"m": 40}}))
    assert res.token_delta.a_tokens == 0 and res.token_delta.b_tokens == 0
    assert res.token_delta.usd_basis == "off"


# --------------------------------------------------------------------------- manifest / ground truth
def test_manifest_matches_benchmark_corpus():
    # The dedicated vulnapp manifest DERIVES from the authoritative benchmark corpus — single source of truth,
    # no drift. ab.py scores against exactly the public baseline's ground truth.
    mod = ab._vulnapp_manifest()
    got = [(e.bug_class, e.location) for e in mod.vulnapp_target("http://127.0.0.1").expected]
    want = [(e.bug_class, e.location) for e in benchmark_corpus("http://127.0.0.1").expected]
    assert got == want and len(got) == 11


def test_render_is_honest_about_the_verdict():
    t = _target()
    tp = _all_tp(t)
    res = run_ab(t, repeats=1, runner=_stub({ARM_A_CAPABLE.name: _same(tp, 1),
                                             ARM_B_CHEAPER.name: _same(tp + [_fp()], 1)}))
    out = ab.render_ab(res)
    assert "FAIL" in out and "REGRESSION" in out and "A-capable" in out and "B-cheaper" in out


# --------------------------------------------------------------------------- FATAL-2 import hygiene
def test_make_gate_path_does_not_import_engage():
    # The make-gate/benchmark import path (benchmark_run + the eval CLI parser) must NOT pull `engage`
    # (heavy + offense-plane). `eval.ab` is the module that imports it, which is exactly why `eval.cli`
    # lazy-imports ab inside the `ab` handler. Checked in a FRESH interpreter so other tests' imports can't
    # mask a leak.
    code = (
        "import sys\n"
        "import framework.v2.eval.benchmark_run as _br\n"
        "import framework.v2.eval.cli as _cli\n"
        "_cli.build_parser()\n"
        "assert 'framework.v2.engage' not in sys.modules, 'make-gate/benchmark path imported engage'\n"
        "import framework.v2.eval.ab as _ab\n"
        "assert 'framework.v2.engage' in sys.modules, 'eval.ab is expected to import engage'\n"
        "print('ok')\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_CRUCIBLE), str(_CRUCIBLE.parents[1] / "packages" / "core" / "vigil_core")])
    r = subprocess.run([sys.executable, "-c", code], cwd=str(_CRUCIBLE),
                       env=env, capture_output=True, text=True)
    assert r.returncode == 0, f"stdout={r.stdout!r} stderr={r.stderr!r}"
