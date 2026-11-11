"""eval.ab — the A/B no-regression eval harness (EC-2b).

Model-tier routing (EC-2a) is the engine's biggest model-cost lever, but turning it ON is only defensible if
going CHEAPER costs no DETECTION. This harness is that proof. It runs the engine's engagement loop against the
in-process loopback benchmark app under TWO routing arms —

  * **arm A "capable"** — routing OFF (every reasoning tier resolves to the backend's configured, capable
    model), the strongest-detection baseline; and
  * **arm B "cheaper"** — routing ON (the operator's ``CRUCIBLE_MODEL_TIER_*`` mappings send the mechanical /
    no-oracle bindings to a cheaper model), the money-saving candidate —

scores each arm's findings against the planted-bug ground truth (``eval.corpus.vulnapp_manifest``) with the
EXISTING comparative scorer (``eval.validation.score`` — never a reimplemented one), and then gates arm B
against a SNAPSHOT of arm A with the EXISTING regression gate (``eval.gate``). The gate is deliberately
ASYMMETRIC: a new false positive, a dropped true positive, a precision drop, or a recall drop in B vs A FAILS;
B doing BETTER is an improvement, never a failure. So the harness answers exactly one question — *does the
cheaper arm detect everything the capable arm did?* — and, alongside it, reports the token/$ saved.

Doctrine / safety:

  * **OPERATOR tool, NOT a CI gate.** This runs the REAL engagement loop with LIVE keys and is STOCHASTIC, so
    it is never part of ``make gate`` / the benchmark baseline. ``eval.cli`` lazy-imports this module inside
    the ``ab`` handler so the make-gate/benchmark import path never pulls ``engage`` (this module imports it
    at top — heavy + offense-plane). That is a FATAL-2 / import-hygiene requirement.
  * **Conservative aggregation.** Each arm runs N repeats to blunt stochasticity. We aggregate AGAINST
    ourselves: arm A is taken at its BEST (max TP, min FP — the hardest baseline to beat) and arm B at its
    WORST (min TP, max FP — the weakest candidate). So a PASS means *even B's worst run did not regress
    against A's best* — the strict direction for "cheaper must not cost detection".
  * **Routing is armed by ENV, scoped and restored.** Each arm sets its routing env (``CRUCIBLE_MODEL_ROUTING``
    on/off) only for the duration of that arm and ALWAYS restores the prior environment in a ``finally`` — the
    harness never leaks a routing flag into the surrounding process.
  * **Money honesty.** The token delta is always real (summed from the per-run, per-model cost tap,
    ``kernel.cost_tap``). The $ figure is a DISPLAY projection from an OPTIONAL owner cost-rate env
    (``VIGIL_AB_COST_RATES_USD_PER_MTOK`` — a JSON ``{model: USD-per-million-tokens}`` map); it is NEVER
    hardcoded. Unset (or missing a rate for any model that actually spent) ⇒ tokens are reported and the $ is
    left UNSET — never fabricated.
  * **Determinism of the scored/gated path.** Scoring, conservative aggregation, and the gate read only
    confusion counts — no wall-clock, no RNG. The cost tap (display only) is off the gated path and skips
    dry-run traces, so a keyless/offline run accumulates nothing and the verdict is unaffected.
"""
from __future__ import annotations

import importlib.util
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..common.errors import EvalError
from ..engage import run_engagement  # HEAVY + offense-plane: eval.cli lazy-imports this module to keep it off
from ..kernel import cost_tap        # the make-gate/benchmark import path (FATAL-2 import hygiene).
from ..kernel.routing import _ENABLE_ENV as _ROUTING_ENABLE_ENV
from .benchmark_app import serve
from .gate import Baseline, GateVerdict, gate, snapshot
from .validation import (
    CorpusTarget,
    CrucibleAdapter,
    ExpectedFinding,
    MeasuredBoard,
    NormalizedFinding,
    RunMetrics,
    Scoreboard,
    score,
)

# The gated tool name. Must be "crucible" so the eval gate (default ``tools=("crucible",)``) actually
# evaluates these boards — the tool whose zero-FP / recall properties this project owns.
_TOOL = "crucible"

# A small default repeat count: enough to blunt per-run stochasticity, cheap enough for an operator run.
_DEFAULT_REPEATS = 3

# A stable slug for the loopback self-test engagement (writes under targets/<slug>/ like any engage run).
_ENGAGEMENT_SLUG = "ab-benchmark"

# Owner cost-rate env for the $ DISPLAY projection: a JSON object mapping a concrete model to its price in
# USD per MILLION tokens, e.g. {"claude-opus-4-8": 15.0, "claude-haiku-4-5": 1.0}. Optional — unset ⇒ the
# harness reports tokens only and never invents a dollar figure (money honesty).
_COST_RATES_ENV = "VIGIL_AB_COST_RATES_USD_PER_MTOK"

# Engine kwargs for the loopback benchmark engagement each arm runs. Mirrors the benchmark adapter's intent
# (declarative library on so the exposure/framework checks run; OOB off — bounded + fast). Loopback is
# authorized by default (engage stays loopback-only unless a charter widens scope), so a 127.0.0.1 seed needs
# no extra setup. An operator can override via ``run_ab_benchmark(engine_kwargs=...)``.
_DEFAULT_ENGINE_KWARGS: dict[str, object] = {
    "use_library": True,
    "enable_oob": False,
}


@dataclass(frozen=True)
class ArmSpec:
    """One routing arm: a human ``name`` plus the environment overrides that ARM it. The overrides are scoped
    around the arm's repeats and restored afterwards (never leaked). The default arms toggle only
    ``CRUCIBLE_MODEL_ROUTING``; the per-tier model MAPPINGS (which cheaper model each tier uses) stay the
    operator's ambient ``CRUCIBLE_MODEL_TIER_*`` policy, which arm B's routing-on simply activates."""

    name: str
    env: Mapping[str, str]


# Arm A — "capable": routing OFF ⇒ every reasoning tier resolves to the backend's configured (capable) model
# (``routing.resolve_model`` fail-toward-capable). The strongest-detection baseline.
ARM_A_CAPABLE = ArmSpec(name="A-capable", env={_ROUTING_ENABLE_ENV: "0"})
# Arm B — "cheaper": routing ON ⇒ the operator's ``CRUCIBLE_MODEL_TIER_*`` mappings take effect, sending the
# mechanical / no-oracle bindings to the cheaper model. The money-saving candidate under test.
ARM_B_CHEAPER = ArmSpec(name="B-cheaper", env={_ROUTING_ENABLE_ENV: "1"})


# The per-arm engagement runner seam: given the labelled target and the arm, return the arm's normalized
# findings. The default (:func:`_engine_arm_runner`) runs the real engine; tests inject a deterministic stub.
ArmRunner = Callable[[CorpusTarget, ArmSpec], list[NormalizedFinding]]


@contextmanager
def _scoped_env(overrides: Mapping[str, str]) -> Iterator[None]:
    """Apply ``overrides`` to ``os.environ`` for the block and ALWAYS restore the prior state on exit — a var
    that was unset before is DELETED again, never left behind. This is what keeps an arm's routing flag from
    leaking into the surrounding process (or the other arm)."""
    missing = object()
    saved: dict[str, object] = {}
    try:
        for k, v in overrides.items():
            saved[k] = os.environ.get(k, missing)
            os.environ[k] = v
        yield
    finally:
        for k, old in saved.items():
            if old is missing:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old  # type: ignore[assignment]


def make_engine_runner(engine_kwargs: Mapping[str, object] | None = None) -> ArmRunner:
    """Build the DEFAULT (live) arm runner: a closure that runs ONE real engagement against the loopback
    target under the arm's already-scoped routing env (applied by :func:`_run_arm` around all repeats), and
    maps its oracle-confirmed ``report.active_findings`` to NormalizedFindings by REUSING the benchmark
    adapter's exact AuditFinding→NormalizedFinding mapping (:meth:`eval.validation.CrucibleAdapter._normalize`)
    — the same engage→NormalizedFinding path the public benchmark scores. Operator-only (live keys,
    stochastic) — never exercised by the gate (tests inject a stub). ``engine_kwargs`` overrides the per-arm
    engagement kwargs (defaults to :data:`_DEFAULT_ENGINE_KWARGS`)."""
    kwargs = dict(_DEFAULT_ENGINE_KWARGS if engine_kwargs is None else engine_kwargs)

    def _run(target: CorpusTarget, arm: ArmSpec) -> list[NormalizedFinding]:
        result = run_engagement(_ENGAGEMENT_SLUG, target.base_url, **kwargs)
        return [CrucibleAdapter._normalize(f) for f in result.report.active_findings]

    return _run


# ---------------------------------------------------------------------------
# result shapes (structured, serializable)
# ---------------------------------------------------------------------------


class TokenDelta(BaseModel):
    """The cost side of the comparison: tokens (always real) and, when an owner cost rate is configured, the $
    projection. ``delta_*`` is B − A, so a NEGATIVE delta is the SAVING from going cheaper. ``usd_*`` are
    ``None`` whenever ``usd_basis`` is not ``"usd_per_mtok"`` — the harness never fabricates a dollar figure."""

    model_config = ConfigDict(extra="forbid")

    a_tokens: int
    b_tokens: int
    delta_tokens: int
    a_tokens_by_model: dict[str, int] = Field(default_factory=dict)
    b_tokens_by_model: dict[str, int] = Field(default_factory=dict)
    a_usd: float | None = None
    b_usd: float | None = None
    delta_usd: float | None = None
    # "off"            — the cost tap was not enabled (CRUCIBLE_COST_TAP unset): no tokens were attributed.
    # "unset"          — tap on, but no owner cost-rate env: tokens only, $ intentionally unset.
    # "incomplete: ..."— a rate was configured but is missing for a model that spent: $ withheld (no fabrication).
    # "usd_per_mtok"   — $ projected from the owner's per-model rates.
    usd_basis: str = "off"


class ArmReport(BaseModel):
    """One arm's outcome: its per-repeat scoreboards, the CONSERVATIVE aggregate the gate reads (A best-case /
    B worst-case), and its per-model token breakdown."""

    model_config = ConfigDict(extra="forbid")

    name: str
    env: dict[str, str] = Field(default_factory=dict)
    repeats: int
    per_repeat: list[Scoreboard] = Field(default_factory=list)
    aggregate: Scoreboard
    tokens_by_model: dict[str, int] = Field(default_factory=dict)


class ABResult(BaseModel):
    """The full A/B outcome: both arm reports, the asymmetric no-regression verdict (B gated against
    snapshot(A)), and the token/$ delta. ``passed`` is the operator's go/no-go for turning routing on."""

    model_config = ConfigDict(extra="forbid")

    target: str
    repeats: int
    arm_a: ArmReport
    arm_b: ArmReport
    verdict: GateVerdict
    token_delta: TokenDelta

    @property
    def passed(self) -> bool:
        """True iff the cheaper arm showed NO detection regression against the capable arm."""
        return self.verdict.passed


# ---------------------------------------------------------------------------
# money projection (owner-rate-derived, never hardcoded)
# ---------------------------------------------------------------------------


def _load_cost_rates(explicit: Mapping[str, float] | None) -> Optional[dict[str, float]]:
    """The owner per-model cost rates (USD per MILLION tokens), from the explicit arg or the
    ``VIGIL_AB_COST_RATES_USD_PER_MTOK`` env (a JSON object). ``None`` when neither is supplied or the env is
    malformed — the signal to report tokens only. Never raises."""
    if explicit is not None:
        return {str(k): float(v) for k, v in explicit.items()}
    raw = os.environ.get(_COST_RATES_ENV, "").strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    out: dict[str, float] = {}
    for k, v in data.items():
        try:
            out[str(k)] = float(v)
        except (TypeError, ValueError):
            continue
    return out or None


def _project_usd(
    tokens_by_model: Mapping[str, int], rates: Optional[Mapping[str, float]]
) -> tuple[Optional[float], list[str]]:
    """Project a USD figure from a per-model token breakdown and owner rates, or ``(None, missing)`` when the
    projection would require FABRICATING a number: no rates at all, or a rate missing for a model that spent.
    USD per million tokens: ``sum(tokens/1e6 * rate)``."""
    if rates is None:
        return None, []
    missing = sorted(m for m in tokens_by_model if m not in rates)
    if missing:
        return None, missing
    usd = sum((tokens / 1_000_000.0) * rates[model] for model, tokens in tokens_by_model.items())
    return round(usd, 6), []


# ---------------------------------------------------------------------------
# conservative aggregation + one arm
# ---------------------------------------------------------------------------


def _aggregate(boards: list[Scoreboard], *, expected_count: int, best: bool, target: str) -> Scoreboard:
    """Collapse an arm's per-repeat scoreboards into one CONSERVATIVE scoreboard.

    ``best=True`` (arm A, the baseline) takes the arm at its STRONGEST — max TP, min FP — the hardest line for
    the candidate to hold. ``best=False`` (arm B, the candidate) takes it at its WEAKEST — min TP, max FP. In
    both, ``fn = expected_count − tp`` keeps ``tp + fn`` equal to the fixed ground-truth count, so recall is
    consistent. A PASS of (B worst) vs (A best) is the strict "cheaper cost no detection" direction."""
    tps = [b.true_positives for b in boards]
    fps = [b.false_positives for b in boards]
    tp = max(tps) if best else min(tps)
    fp = min(fps) if best else max(fps)
    return Scoreboard(
        tool=_TOOL,
        target=target,
        true_positives=tp,
        false_positives=fp,
        false_negatives=max(0, expected_count - tp),
    )


def _run_arm(
    arm: ArmSpec,
    target: CorpusTarget,
    *,
    repeats: int,
    runner: ArmRunner,
    best: bool,
) -> ArmReport:
    """Run one arm: scope its routing env, scope a per-arm cost tap, run ``repeats`` engagements, score each
    against ground truth with the EXISTING scorer, and return the per-repeat boards + the conservative
    aggregate + the per-model token totals. The env + cost scopes wrap ALL repeats and are always torn down."""
    expected: list[ExpectedFinding] = list(target.expected)
    expected_count = len(expected)
    per_repeat: list[Scoreboard] = []
    with _scoped_env(arm.env):
        with cost_tap.scope():
            for _ in range(repeats):
                findings = runner(target, arm)
                per_repeat.append(
                    score(findings, expected, tool=_TOOL, target=target.name)
                )
            tokens_by_model = cost_tap.totals_by_model()
    aggregate = _aggregate(per_repeat, expected_count=expected_count, best=best, target=target.name)
    return ArmReport(
        name=arm.name,
        env=dict(arm.env),
        repeats=repeats,
        per_repeat=per_repeat,
        aggregate=aggregate,
        tokens_by_model=tokens_by_model,
    )


# ---------------------------------------------------------------------------
# the harness
# ---------------------------------------------------------------------------


def run_ab(
    target: CorpusTarget,
    *,
    arm_a: ArmSpec = ARM_A_CAPABLE,
    arm_b: ArmSpec = ARM_B_CHEAPER,
    repeats: int = _DEFAULT_REPEATS,
    runner: ArmRunner | None = None,
    cost_rates: Mapping[str, float] | None = None,
) -> ABResult:
    """Run the A/B no-regression comparison against ``target`` and return the structured result.

    Pure core: given a labelled ``target`` and an engagement ``runner`` (the default runs the real engine;
    tests inject a deterministic stub), it runs both arms, aggregates conservatively, gates arm B against a
    snapshot of arm A with the EXISTING ``eval.gate`` (asymmetric, ``tools=("crucible",)``), and computes the
    token/$ delta from the cost tap. Reuses the existing scorer and gate — it reimplements neither."""
    if repeats < 1:
        raise EvalError(f"run_ab needs repeats >= 1, got {repeats}")
    run = runner or make_engine_runner()

    # Arm A at its BEST (the hardest baseline); arm B at its WORST (the weakest candidate).
    report_a = _run_arm(arm_a, target, repeats=repeats, runner=run, best=True)
    report_b = _run_arm(arm_b, target, repeats=repeats, runner=run, best=False)

    # The asymmetric no-regression gate: B must not regress vs a SNAPSHOT of A. Direction matters — A is the
    # baseline (snapshot), B is the candidate — so "going cheaper" is what is held to "no detection loss".
    a_board = MeasuredBoard(scoreboard=report_a.aggregate,
                            metrics=RunMetrics(tool=_TOOL, target=target.name))
    b_board = MeasuredBoard(scoreboard=report_b.aggregate,
                            metrics=RunMetrics(tool=_TOOL, target=target.name))
    baseline: Baseline = snapshot({target.name: [a_board]}, label=f"A:{arm_a.name}")
    verdict: GateVerdict = gate({target.name: [b_board]}, baseline, tools=(_TOOL,))

    token_delta = _compute_delta(report_a.tokens_by_model, report_b.tokens_by_model, cost_rates=cost_rates)

    return ABResult(
        target=target.name,
        repeats=repeats,
        arm_a=report_a,
        arm_b=report_b,
        verdict=verdict,
        token_delta=token_delta,
    )


def _compute_delta(
    a_tokens_by_model: Mapping[str, int],
    b_tokens_by_model: Mapping[str, int],
    *,
    cost_rates: Mapping[str, float] | None,
) -> TokenDelta:
    """Build the token/$ delta from the two arms' per-model token breakdowns. Tokens are always real; the $
    projection is owner-rate-derived and withheld (``None``) whenever it would require fabricating a figure."""
    a_tokens = sum(a_tokens_by_model.values())
    b_tokens = sum(b_tokens_by_model.values())
    rates = _load_cost_rates(cost_rates)
    a_usd, a_missing = _project_usd(a_tokens_by_model, rates)
    b_usd, b_missing = _project_usd(b_tokens_by_model, rates)
    delta_usd = round(b_usd - a_usd, 6) if (a_usd is not None and b_usd is not None) else None

    if not a_tokens_by_model and not b_tokens_by_model:
        usd_basis = "off"  # no tokens attributed — the cost tap was not enabled (CRUCIBLE_COST_TAP unset)
    elif rates is None:
        usd_basis = "unset"  # tokens attributed, but no owner cost-rate env: tokens only, no fabricated $
    elif a_missing or b_missing:
        usd_basis = "incomplete: no rate for " + ",".join(sorted(set(a_missing) | set(b_missing)))
    else:
        usd_basis = "usd_per_mtok"

    return TokenDelta(
        a_tokens=a_tokens,
        b_tokens=b_tokens,
        delta_tokens=b_tokens - a_tokens,
        a_tokens_by_model=dict(a_tokens_by_model),
        b_tokens_by_model=dict(b_tokens_by_model),
        a_usd=a_usd,
        b_usd=b_usd,
        delta_usd=delta_usd,
        usd_basis=usd_basis,
    )


# ---------------------------------------------------------------------------
# operator entry: stand up the loopback app and run the comparison
# ---------------------------------------------------------------------------


_MANIFEST_CACHE: object | None = None


def _vulnapp_manifest() -> object:
    """Load the ground-truth manifest module (``eval/corpus/vulnapp_manifest.py``). It lives in the ``corpus/``
    DATA dir, which the ``corpus.py`` loader module SHADOWS for imports, so — like everything under
    ``corpus/`` — it is loaded by FILE PATH. Cached after first load."""
    global _MANIFEST_CACHE
    if _MANIFEST_CACHE is None:
        path = Path(__file__).resolve().parent / "corpus" / "vulnapp_manifest.py"
        spec = importlib.util.spec_from_file_location(
            "framework.v2.eval._corpus_vulnapp_manifest", path)
        if spec is None or spec.loader is None:  # pragma: no cover - defensive
            raise EvalError(f"cannot load the vulnapp manifest from {path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MANIFEST_CACHE = mod
    return _MANIFEST_CACHE


def run_ab_benchmark(
    *,
    repeats: int = _DEFAULT_REPEATS,
    arm_a: ArmSpec = ARM_A_CAPABLE,
    arm_b: ArmSpec = ARM_B_CHEAPER,
    cost_rates: Mapping[str, float] | None = None,
    engine_kwargs: Mapping[str, object] | None = None,
) -> ABResult:
    """OPERATOR entry: stand up the in-process loopback benchmark app, build the labelled target from the
    ground-truth manifest, and run the A/B comparison with the real engine runner. Live keys, stochastic —
    NOT a CI gate. ``engine_kwargs`` overrides the per-arm engagement kwargs."""
    vulnapp_target = _vulnapp_manifest().vulnapp_target  # type: ignore[attr-defined]
    runner = make_engine_runner(engine_kwargs)
    with serve() as base_url:
        target = vulnapp_target(base_url)
        return run_ab(target, arm_a=arm_a, arm_b=arm_b, repeats=repeats,
                      runner=runner, cost_rates=cost_rates)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _fmt_arm(tag: str, arm: ArmReport, *, conservative: str) -> str:
    sb = arm.aggregate
    return (
        f"arm {tag} ({arm.name}, {_routing_word(arm.env)}): "
        f"tp={sb.true_positives} fp={sb.false_positives} fn={sb.false_negatives} "
        f"precision={sb.precision:.3f} recall={sb.recall:.3f}   [{conservative}]"
    )


def _routing_word(env: Mapping[str, str]) -> str:
    val = str(env.get(_ROUTING_ENABLE_ENV, "")).strip().lower()
    return "routing on" if val in ("1", "true", "yes", "on") else "routing off"


def render_ab(result: ABResult) -> str:
    """A compact, honest text summary of an :class:`ABResult`: both arms' conservative scoreboards, the
    asymmetric verdict with its named regressions, and the token/$ delta (tokens always; $ only when
    owner-rate-configured)."""
    td = result.token_delta
    lines: list[str] = []
    lines.append("== CRUCIBLE A/B no-regression (EC-2b) ==")
    lines.append(f"target: {result.target}   repeats: {result.repeats}")
    lines.append(_fmt_arm("A", result.arm_a, conservative="A best-case"))
    lines.append(_fmt_arm("B", result.arm_b, conservative="B worst-case"))
    lines.append("")
    verdict = "PASS" if result.verdict.passed else "FAIL"
    lines.append(f"no-regression gate (B vs snapshot(A), {_TOOL}): {verdict}")
    for r in result.verdict.regressions:
        lines.append(f"  REGRESSION: {r}")
    for w in result.verdict.warnings:
        lines.append(f"  warn: {w}")
    for imp in result.verdict.improvements:
        lines.append(f"  improved: {imp}")
    lines.append("")
    sign = "" if td.delta_tokens < 0 else "+"
    lines.append(
        f"cost: A={td.a_tokens} tokens, B={td.b_tokens} tokens, "
        f"delta={sign}{td.delta_tokens} tokens (B-A; negative = cheaper arm saves)"
    )
    if td.a_tokens_by_model or td.b_tokens_by_model:
        lines.append(f"  per-model A: {td.a_tokens_by_model}")
        lines.append(f"  per-model B: {td.b_tokens_by_model}")
    if td.usd_basis == "usd_per_mtok" and td.delta_usd is not None:
        dsign = "" if td.delta_usd < 0 else "+"
        lines.append(
            f"  $ (owner rate): A=${td.a_usd:.6f}, B=${td.b_usd:.6f}, "
            f"delta={dsign}${td.delta_usd:.6f}"
        )
    elif td.usd_basis == "off":
        lines.append("  $ : not shown — cost tap OFF (set CRUCIBLE_COST_TAP=1 to attribute tokens)")
    elif td.usd_basis == "unset":
        lines.append(f"  $ : tokens only — owner cost rate unset ({_COST_RATES_ENV})")
    else:
        lines.append(f"  $ : tokens only — {td.usd_basis}")
    return "\n".join(lines)
