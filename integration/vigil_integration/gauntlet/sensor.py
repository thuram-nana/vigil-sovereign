"""
gauntlet.sensor — the offensive-LLM sensor: uniform ``run`` + the FACT/LEAD routing (VIGIL-FUSION F8).

This is the sovereign core of the AI-Gauntlet sensor family. It takes a ``GauntletSpec`` (which tool to
drive, the argv, the injected ``run_tool`` subprocess boundary, the injected deterministic seed), fires
the tool, parses its output (``gauntlet.adapters``), and ROUTES each candidate by its ``oracle_kind``
(``gauntlet.owasp_map``):

    contains / classifier / regex   → DETERMINISTIC → the INJECTED oracle re-executes over the retained
                                       raw output with a fresh per-run challenge token; only a signed
                                       evidence ref mints a FACT.
    judge_llm / unmapped            → NON-DETERMINISTIC → ALWAYS a LEAD; the oracle is never consulted.

THE SOVEREIGN INVARIANT (the red-pen attacks exactly this):

  * A ``judge_llm`` finding can NEVER auto-promote to a FACT. The routing returns a LEAD *before any
    oracle call*, so no code path — not even a compromised/adversarial oracle that returns a strong ref,
    not a maxed-out ASR/severity — can mint a FACT from an LLM-judge result.
  * ONLY a deterministic ``oracle_kind`` that the INJECTED oracle CONFIRMS (returns a non-empty signed
    evidence ref for) mints a signed FACT.
  * No oracle wired, an oracle error, an empty/whitespace ref → LEAD (fail-closed).
  * ASR is a METRIC, never a promotion signal.
  * TOTAL on malformed adapter output / spec / run_tool failure → no signal, never a raise.
  * DETERMINISTIC — the per-run challenge token derives from the INJECTED seed (no wallclock/RNG).

Pure/injected: the oracle and the subprocess ``run_tool`` are callables passed in, so the whole sensor
is testable without a live kernel, a live model target, or any external red-team framework. The emitted
records reuse ``agent.state.Finding`` (a FACT is type-level-required to carry a signed evidence ref).

Import-clean: pydantic/stdlib + F1 safety + F3 tools + agent.state; no framework/strix, no network.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Optional, Sequence

from ..agent.state import Finding
from .adapters import KNOWN_TOOLS, CandidateFinding, parse_adapter_output
from .metrics import attack_success_rate, sanitize_counts, severity_band
from .owasp_map import DETERMINISTIC_KINDS, OwaspEntry, map_category

# ---------------------------------------------------------------------------------------------------
# injected boundaries
# ---------------------------------------------------------------------------------------------------

# The subprocess boundary: given the tool argv, return the tool's raw report text. Modelled as an
# injected callable so garak/PyRIT/… run out-of-process (deps + egress isolated) and the sensor is
# testable without them. Any exception it raises is caught and degraded to "no signal".
RunTool = Callable[[Sequence[str]], str]


@dataclass(frozen=True)
class OracleRequest:
    """What the deterministic oracle is asked to re-execute. ``raw_output`` is the retained adapter
    evidence (handed only to the oracle, never logged by gauntlet). ``challenge_token`` is a fresh
    per-run nonce derived DETERMINISTICALLY from the injected seed — a recorded/hallucinated response
    cannot satisfy a challenge the oracle issues around it."""

    oracle_kind: str
    owasp_llm_id: str
    chip: str
    probe: str
    raw_output: str
    challenge_token: str


# The injected deterministic oracle. It re-executes the (contains/classifier/regex) check — in
# production wrapping a randomized-challenge oracle (I1) + the CRUCIBLE confirm/certify pipeline — and
# returns a NON-EMPTY signed evidence ref (spine hash / SCITT cert id) iff it genuinely CONFIRMS, else
# ``None``. It is NEVER called for a judge_llm category. Contract: a return value is a proof reference,
# not a boolean an LLM could assert.
GauntletOracle = Callable[[OracleRequest], Optional[str]]


@dataclass(frozen=True)
class GauntletSpec:
    """One gauntlet run. ``run_tool`` is the injected subprocess boundary; ``seed`` is the injected
    deterministic seed (no RNG/wallclock anywhere). ``target`` is provenance only (scope-gated upstream
    by the WARDEN tier + egress gate before this sensor ever fires)."""

    tool: str
    argv: tuple = ()
    run_tool: Optional[RunTool] = None
    seed: str = ""
    target: str = ""


@dataclass(frozen=True)
class CategoryMetric:
    """Per-candidate ASR metric. Descriptive/triage only — NEVER a promotion signal."""

    chip: str
    owasp_llm_id: str
    oracle_kind: str
    hits: int
    trials: int
    asr: float
    severity: str


@dataclass(frozen=True)
class GauntletResult:
    """The full sensor result: the routed findings + the ASR metrics. ``findings`` is what the uniform
    ``run`` contract returns; ``metrics``/``overall_asr`` are the metric layer alongside it."""

    tool: str
    findings: tuple = ()
    metrics: tuple = ()
    overall_asr: float = 0.0
    fact_count: int = 0
    lead_count: int = 0


def _challenge_token(seed: object, probe: object, index: int) -> str:
    """A fresh per-run challenge token, derived DETERMINISTICALLY from the injected seed (no RNG, no
    wallclock). Same seed → same token (reproducible); different seed → different token."""
    msg = f"vigil.gauntlet.challenge|{seed}|{probe}|{index}"
    return sha256(msg.encode("utf-8", "replace")).hexdigest()


def _lead(ref: str, entry: OwaspEntry, title: str, severity: str, source: str) -> Finding:
    return Finding(ref=ref, bug_class=entry.chip, title=title, severity=severity,
                   status="lead", evidence_ref="", source=source)


def route_candidate(
    cand: CandidateFinding,
    *,
    tool: str,
    seed: str,
    index: int,
    oracle: Optional[GauntletOracle],
) -> tuple[Finding, CategoryMetric]:
    """Route one candidate to a FACT or a LEAD, enforcing the sovereign invariant. Never raises.

    The emitted ``bug_class``/``owasp_llm_id`` come ONLY from the TRUSTED taxonomy row (``map_category``),
    never from the raw category string — so nothing attacker-influenced reaches the record and, crucially,
    a ``judge_llm`` category is decided by that trusted row, not by anything the tool output can forge."""
    entry = map_category(cand.category)
    hits, trials = sanitize_counts(cand.hits, cand.trials)
    asr = attack_success_rate(hits, trials)
    sev = severity_band(asr)
    ref = f"gauntlet:{tool}:{entry.chip}:{index}"
    title = f"{entry.owasp_llm_id} {entry.chip} (ASR {hits}/{trials})"
    source = f"gauntlet/{tool}"
    metric = CategoryMetric(chip=entry.chip, owasp_llm_id=entry.owasp_llm_id,
                            oracle_kind=entry.oracle_kind, hits=hits, trials=trials, asr=asr, severity=sev)
    lead = _lead(ref, entry, title, sev, source)

    # ---- THE SOVEREIGN INVARIANT -------------------------------------------------------------------
    # A NON-DETERMINISTIC (judge_llm) or unmapped category is ALWAYS a LEAD. We return here BEFORE any
    # oracle call: the promotion path below is structurally unreachable for these, so an adversarial
    # oracle, a maxed-out ASR, or a high severity band can NEVER launder an LLM-judge guess into a FACT.
    if entry.oracle_kind not in DETERMINISTIC_KINDS:
        return lead, metric

    # ---- deterministic path: a FACT requires the INJECTED oracle to re-fire and return a signed ref --
    if oracle is None:
        return lead, metric  # no oracle wired → LEAD (fail-closed)
    request = OracleRequest(
        oracle_kind=entry.oracle_kind, owasp_llm_id=entry.owasp_llm_id, chip=entry.chip,
        probe=str(cand.category), raw_output=cand.evidence or "",
        challenge_token=_challenge_token(seed, cand.category, index),
    )
    try:
        evidence_ref = oracle(request)
    except Exception:  # noqa: BLE001 — any oracle error confirms nothing (fail-closed)
        evidence_ref = None
    if isinstance(evidence_ref, str) and evidence_ref.strip():
        # Construct the FACT via the model so the TYPE-level invariant (a FACT needs a non-empty signed
        # evidence ref) is actively exercised — defense in depth over the strip() guard.
        return Finding(ref=ref, bug_class=entry.chip, title=title, severity=sev,
                       status="fact", evidence_ref=evidence_ref.strip(), source=source), metric
    return lead, metric  # oracle abstained / returned an empty-or-garbage ref → LEAD


def _empty_result(tool: object) -> GauntletResult:
    return GauntletResult(tool=tool if isinstance(tool, str) else "")


def run_gauntlet(spec: GauntletSpec, *, oracle: Optional[GauntletOracle] = None) -> GauntletResult:
    """Drive one gauntlet run end-to-end and return findings + ASR metrics. TOTAL: an unknown tool, a
    missing/failing ``run_tool``, or malformed output degrades to an empty result — never a raise."""
    try:
        tool = getattr(spec, "tool", "")
        run_tool = getattr(spec, "run_tool", None)
        seed = getattr(spec, "seed", "")
        argv = getattr(spec, "argv", ())
        if not isinstance(tool, str) or tool not in KNOWN_TOOLS:
            return _empty_result(tool)
        if not callable(run_tool):
            return _empty_result(tool)  # no subprocess boundary wired → no signal (fail-closed)
        try:
            raw = run_tool(argv)
        except Exception:  # noqa: BLE001 — a subprocess/adapter failure is no signal, never a crash
            return _empty_result(tool)
        candidates = parse_adapter_output(tool, raw)
        findings: list[Finding] = []
        metrics: list[CategoryMetric] = []
        total_hits = 0
        total_trials = 0
        for i, cand in enumerate(candidates):
            f, m = route_candidate(cand, tool=tool, seed=str(seed), index=i, oracle=oracle)
            findings.append(f)
            metrics.append(m)
            total_hits += m.hits
            total_trials += m.trials
        overall = attack_success_rate(total_hits, total_trials)
        facts = sum(1 for f in findings if f.status == "fact")
        return GauntletResult(tool=tool, findings=tuple(findings), metrics=tuple(metrics),
                              overall_asr=overall, fact_count=facts, lead_count=len(findings) - facts)
    except Exception:  # noqa: BLE001 — the whole sensor is total on any unexpected input
        return _empty_result(getattr(spec, "tool", "") if spec is not None else "")


def run(spec: GauntletSpec, *, oracle: Optional[GauntletOracle] = None) -> list[Finding]:
    """The uniform sensor entrypoint: ``run(spec, *, oracle) -> list[Finding]``. A thin view over
    :func:`run_gauntlet` returning just the routed findings (FACTs carry signed evidence refs; everything
    else, and every ``judge_llm`` result, is a LEAD). Never raises."""
    return list(run_gauntlet(spec, oracle=oracle).findings)
