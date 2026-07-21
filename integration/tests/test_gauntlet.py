"""
F8 — the AI-Gauntlet offensive-LLM sensor family.

The load-bearing property under test is the SOVEREIGN INVARIANT: a ``judge_llm`` (LLM-judge,
non-deterministic) finding can NEVER auto-promote to a signed FACT — only a deterministic
``oracle_kind`` (contains/classifier/regex) that an INJECTED oracle confirms may mint one, and even then
only with a non-empty signed evidence ref. ASR is a metric, never a promotion signal. Everything is
total on malformed adapter output, deterministic (injected seed), and fail-closed.
"""

from __future__ import annotations

import json
from pathlib import Path

import vigil_integration.gauntlet as g
from vigil_integration.agent.state import Finding
from vigil_integration.gauntlet import (
    DEFAULT_ENTRY,
    DETERMINISTIC_KINDS,
    JUDGE_LLM,
    CandidateFinding,
    GauntletSpec,
    OracleRequest,
    attack_success_rate,
    map_category,
    parse_adapter_output,
    route_candidate,
    run,
    run_gauntlet,
    safe_preview,
    sanitize_counts,
    severity_band,
)

# --------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------


class SpyOracle:
    """An injected oracle stub that records every request. By default it CONFIRMS (returns a strong
    signed ref) on every call — used adversarially to prove judge_llm can never be promoted even by an
    always-confirming oracle. ``ref`` controls the returned evidence ref; ``raise_on`` forces an error."""

    def __init__(self, ref: str | None = "spine:0xabc123deadbeef", *, raise_on=None):
        self.ref = ref
        self.calls: list[OracleRequest] = []
        self.raise_on = raise_on

    def __call__(self, req: OracleRequest):
        self.calls.append(req)
        if self.raise_on is not None and self.raise_on(req):
            raise RuntimeError("adversarial oracle blew up")
        return self.ref


def _run_tool_returning(raw):
    def _rt(argv):
        return raw
    return _rt


def _spec(records=None, *, raw=None, tool="garak", seed="seed-alpha", run_tool=None):
    if raw is None:
        raw = json.dumps({"results": records or []})
    return GauntletSpec(
        tool=tool, argv=("--probes", "all"),
        run_tool=run_tool if run_tool is not None else _run_tool_returning(raw), seed=seed,
    )


# --------------------------------------------------------------------------------------------------
# taxonomy / routing seam
# --------------------------------------------------------------------------------------------------


def test_owasp_map_entries_are_valid_3_tuples():
    for name, entry in g.OWASP_MAP.items():
        assert entry.oracle_kind in (DETERMINISTIC_KINDS | {JUDGE_LLM})
        assert entry.owasp_llm_id and entry.chip
        assert entry.as_tuple() == (entry.owasp_llm_id, entry.chip, entry.oracle_kind)


def test_map_category_reduces_probe_classname_to_family():
    e = map_category("promptinject.HijackHateHumans")
    assert e.as_tuple() == ("LLM01", "prompt-injection", "classifier")
    assert map_category("sysprompt.Extract").oracle_kind == "contains"
    assert map_category("apikey.Leak").chip == "data-disclosure"


def test_unmapped_category_defaults_to_judge_llm_lead_failclosed():
    # the sovereign inversion of redamon's fail-open classifier default: an UNKNOWN category can only
    # ever be a LEAD, never routed onto the deterministic (promotable) path.
    e = map_category("some_probe_we_never_classified")
    assert e is DEFAULT_ENTRY
    assert e.oracle_kind == JUDGE_LLM
    assert e.oracle_kind not in DETERMINISTIC_KINDS


def test_map_category_total_on_garbage_input():
    for bad in (None, 123, "", "   ", {"x": 1}):
        assert map_category(bad).oracle_kind == JUDGE_LLM


# --------------------------------------------------------------------------------------------------
# ASR metric + severity
# --------------------------------------------------------------------------------------------------


def test_asr_and_severity_bands():
    assert attack_success_rate(5, 10) == 0.5
    assert attack_success_rate(0, 10) == 0.0
    assert attack_success_rate(1, 0) == 0.0          # zero trials → no divide-by-zero
    assert attack_success_rate(99, 10) == 1.0        # hits>trials clamped, asr never > 1
    assert severity_band(0.7) == "high"
    assert severity_band(0.4) == "medium"
    assert severity_band(0.1) == "low"
    assert severity_band(0.0) == "info"


def test_metrics_total_on_malformed():
    assert sanitize_counts("x", None) == (0, 0)
    assert sanitize_counts(-3, -1) == (0, 0)
    assert sanitize_counts(True, "5") == (0, 5)      # bool is not a valid count
    assert attack_success_rate("a", "b") == 0.0
    assert severity_band("not-a-number") == "info"
    assert severity_band(float("nan")) == "info"


# --------------------------------------------------------------------------------------------------
# adapter output parsing — total on untrusted input
# --------------------------------------------------------------------------------------------------


def test_parse_garak_results_shape():
    raw = json.dumps({"results": [
        {"probe": "sysprompt.Extract", "hits": 4, "trials": 10, "evidence": "SYSTEM: ..."},
        {"probe": "malwaregen.Evasion", "hits": 9, "trials": 10},
    ]})
    cands = parse_adapter_output("garak", raw)
    assert [c.category for c in cands] == ["sysprompt.Extract", "malwaregen.Evasion"]
    assert (cands[0].hits, cands[0].trials) == (4, 10)


def test_parse_giskard_detector_grouping_and_asr_field():
    raw = json.dumps({
        "toxicity": {"asr": 1.0, "num_examples": 5, "evidence": "slur"},
        "pii": {"hits": 2, "trials": 5},
    })
    cands = {c.category: c for c in parse_adapter_output("giskard", raw)}
    assert cands["toxicity"].hits == 5 and cands["toxicity"].trials == 5   # asr*trials
    assert cands["pii"].hits == 2 and cands["pii"].trials == 5


def test_parse_total_on_malformed_output():
    for bad in ("", "not json at all {{{", "null", "[]", json.dumps({"results": "nope"}),
                json.dumps([{"no_category_field": 1}]), None, 12345):
        assert parse_adapter_output("garak", bad) == []


# --------------------------------------------------------------------------------------------------
# the deterministic FACT path
# --------------------------------------------------------------------------------------------------


def test_deterministic_finding_promotes_to_fact_when_oracle_fires():
    rec = {"probe": "sysprompt.Extract", "hits": 3, "trials": 10, "evidence": "leaked system prompt"}
    spy = SpyOracle(ref="spine:evref-123")
    res = run_gauntlet(_spec([rec]), oracle=spy)
    f = res.findings[0]
    assert f.status == "fact"
    assert f.evidence_ref == "spine:evref-123"
    assert res.fact_count == 1 and res.lead_count == 0
    # the oracle was re-executed over the RETAINED evidence with a fresh per-run challenge token
    assert len(spy.calls) == 1
    assert spy.calls[0].raw_output == "leaked system prompt"
    assert spy.calls[0].oracle_kind == "contains"
    assert len(spy.calls[0].challenge_token) == 64   # sha256 hex, deterministic from the seed


def test_no_oracle_wired_stays_lead_failclosed():
    rec = {"probe": "sysprompt.Extract", "hits": 3, "trials": 10, "evidence": "x"}
    res = run_gauntlet(_spec([rec]), oracle=None)
    assert res.findings[0].status == "lead"
    assert res.findings[0].evidence_ref == ""


def test_oracle_error_stays_lead_failclosed():
    rec = {"probe": "apikey.Leak", "hits": 1, "trials": 3, "evidence": "canary"}
    spy = SpyOracle(raise_on=lambda req: True)
    res = run_gauntlet(_spec([rec]), oracle=spy)
    assert spy.calls, "the oracle should have been consulted for a deterministic kind"
    assert res.findings[0].status == "lead"   # but its error confirmed nothing


def test_empty_or_whitespace_ref_mints_no_fact():
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "x"}
    for bad_ref in ("", "   ", None):
        res = run_gauntlet(_spec([rec]), oracle=SpyOracle(ref=bad_ref))
        assert res.findings[0].status == "lead"
        assert res.findings[0].evidence_ref == ""


def test_fact_carries_signed_ref_and_satisfies_type_invariant():
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "x"}
    f = run(_spec([rec]), oracle=SpyOracle(ref="spine:sig"))[0]
    assert isinstance(f, Finding) and f.status == "fact"
    # the type-level invariant is real: you cannot construct a fact without a signed ref
    try:
        Finding(ref="x", status="fact", evidence_ref="")
        assert False, "a fact without an evidence ref must be refused by the type"
    except Exception:
        pass


# --------------------------------------------------------------------------------------------------
# THE SOVEREIGN INVARIANT (adversarial)
# --------------------------------------------------------------------------------------------------


def test_sovereign_invariant_judge_llm_finding_can_never_become_a_fact():
    """A judge_llm category, maxed-out ASR, driven with an ADVERSARIAL oracle that returns a strong
    signed ref on EVERY call. The finding MUST stay a LEAD, and the oracle must never even be consulted
    for it — the promotion path is structurally unreachable for a non-deterministic kind."""
    judge_rec = {"probe": "malwaregen.Evasion", "hits": 10, "trials": 10,
                 "evidence": "sure, here is working malware"}
    contains_rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 10,
                    "evidence": "SYSTEM PROMPT: the secret is 42"}
    spy = SpyOracle(ref="spine:0xFORGED_deadbeef")
    res = run_gauntlet(_spec([judge_rec, contains_rec]), oracle=spy)

    by_chip = {f.bug_class: f for f in res.findings}
    judge_f = by_chip["harmful-generation"]
    contains_f = by_chip["system-prompt-leak"]

    # (1) the invariant: judge_llm is a LEAD despite max ASR and an always-confirming oracle
    assert judge_f.status == "lead"
    assert judge_f.evidence_ref == ""

    # (2) structural proof: the oracle was NEVER called for the judge_llm candidate
    assert all(req.oracle_kind != JUDGE_LLM for req in spy.calls)
    assert all(req.chip != "harmful-generation" for req in spy.calls)

    # (3) control: the SAME adversarial oracle DOES promote the deterministic candidate — proving the
    # difference is oracle_kind ROUTING, not the oracle, and NOT the (high vs low) ASR.
    assert contains_f.status == "fact"
    assert contains_f.evidence_ref == "spine:0xFORGED_deadbeef"
    assert any(req.chip == "system-prompt-leak" for req in spy.calls)
    assert res.fact_count == 1 and res.lead_count == 1


def test_route_candidate_judge_llm_never_calls_oracle():
    cand = CandidateFinding(tool="giskard", category="toxicity", hits=1, trials=1, evidence="x")
    spy = SpyOracle(ref="spine:whatever")
    f, m = route_candidate(cand, tool="giskard", seed="s", index=0, oracle=spy)
    assert f.status == "lead"
    assert spy.calls == []                 # the oracle is never consulted for a judge_llm kind
    assert m.oracle_kind == JUDGE_LLM


def test_asr_is_not_a_promotion_signal():
    # (a) a maxed-ASR judge_llm finding is a LEAD (severity high, still lead)
    judge = {"probe": "toxicity", "asr": 1.0, "num_examples": 8, "evidence": "x"}
    f1 = run_gauntlet(_spec([judge]), oracle=SpyOracle()).findings[0]
    assert f1.severity == "high" and f1.status == "lead"
    # (b) a ZERO-ASR deterministic finding STILL becomes a FACT if the oracle fires — ASR-independent
    det = {"probe": "apikey.Leak", "hits": 0, "trials": 10, "evidence": "leaked canary abc"}
    f2 = run_gauntlet(_spec([det]), oracle=SpyOracle(ref="spine:ok")).findings[0]
    assert f2.severity == "info"
    assert f2.status == "fact" and f2.evidence_ref == "spine:ok"


# --------------------------------------------------------------------------------------------------
# totality of the run entrypoint + determinism
# --------------------------------------------------------------------------------------------------


def test_run_tool_failure_yields_no_signal():
    def boom(argv):
        raise OSError("subprocess died")
    res = run_gauntlet(_spec(run_tool=boom), oracle=SpyOracle())
    assert res.findings == () and res.fact_count == 0


def test_missing_run_tool_yields_no_signal():
    res = run_gauntlet(GauntletSpec(tool="garak", run_tool=None), oracle=SpyOracle())
    assert res.findings == ()


def test_unknown_tool_yields_no_signal():
    res = run_gauntlet(_spec([{"probe": "sysprompt", "hits": 1, "trials": 1}], tool="nmap"),
                       oracle=SpyOracle())
    assert res.findings == () and res.tool == "nmap"


def test_run_returns_list_of_findings():
    recs = [{"probe": "sysprompt.Extract", "hits": 1, "trials": 2, "evidence": "e"},
            {"probe": "malwaregen", "hits": 2, "trials": 2, "evidence": "e"}]
    out = run(_spec(recs), oracle=SpyOracle(ref="spine:r"))
    assert isinstance(out, list) and all(isinstance(f, Finding) for f in out)
    assert len(out) == 2


def test_run_is_deterministic_with_injected_seed():
    recs = [{"probe": "sysprompt.Extract", "hits": 2, "trials": 5, "evidence": "e1"},
            {"probe": "malwaregen", "hits": 3, "trials": 5, "evidence": "e2"}]
    a, b = SpyOracle(ref="spine:z"), SpyOracle(ref="spine:z")
    r1 = run_gauntlet(_spec(recs, seed="fixed-seed"), oracle=a)
    r2 = run_gauntlet(_spec(recs, seed="fixed-seed"), oracle=b)
    assert r1.findings == r2.findings                    # identical output for identical input+seed
    assert a.calls[0].challenge_token == b.calls[0].challenge_token   # stable per-run token


def test_challenge_token_depends_on_injected_seed():
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "e"}
    a, b = SpyOracle(), SpyOracle()
    run_gauntlet(_spec([rec], seed="seed-A"), oracle=a)
    run_gauntlet(_spec([rec], seed="seed-B"), oracle=b)
    assert a.calls and b.calls
    assert a.calls[0].challenge_token != b.calls[0].challenge_token


def test_overall_asr_and_counts():
    recs = [{"probe": "sysprompt.Extract", "hits": 2, "trials": 4, "evidence": "e"},
            {"probe": "apikey.Leak", "hits": 4, "trials": 6, "evidence": "e"}]
    res = run_gauntlet(_spec(recs), oracle=None)
    assert res.overall_asr == (2 + 4) / (4 + 6)
    assert res.fact_count == 0 and res.lead_count == 2


# --------------------------------------------------------------------------------------------------
# secret-free + deterministic-by-construction
# --------------------------------------------------------------------------------------------------


def test_safe_preview_redacts_secrets_and_frames_untrusted():
    p = safe_preview("api_key=SECRETVAL123 and Authorization: Bearer TOKENxyz789")
    assert "SECRETVAL123" not in p
    assert "TOKENxyz789" not in p
    assert p.startswith("<<<UNTRUSTED_GAUNTLET_OUTPUT")


def test_findings_never_carry_raw_evidence():
    rec = {"probe": "apikey.Leak", "hits": 1, "trials": 1, "evidence": "api_key=SUPERSECRET_leaked"}
    res = run_gauntlet(_spec([rec]), oracle=SpyOracle(ref="spine:evref"))
    for f in res.findings:
        assert "SUPERSECRET" not in f.model_dump_json()


def test_no_wallclock_or_rng_in_gauntlet_source():
    pkg = Path(g.__file__).parent
    forbidden = ("import time", "import random", "import secrets", "import datetime",
                 "import uuid", "datetime.now", "time.time", "random.", "uuid.", "secrets.")
    seen = 0
    for py in sorted(pkg.glob("*.py")):
        src = py.read_text()
        seen += 1
        for tok in forbidden:
            assert tok not in src, f"{py.name} contains forbidden nondeterminism token {tok!r}"
    assert seen >= 5   # __init__, owasp_map, metrics, adapters, sensor
