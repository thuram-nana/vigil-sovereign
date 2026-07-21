"""F5 — the non-authoritative cognition governors: productivity scoring, the honesty audit, the
uniform-response anomaly (INCONCLUSIVE, not NEGATIVE), the tested-axes ledger, and the deep-think
novelty guard. The through-line every test asserts: these governors re-rank / defer / hint / block an
expensive next call — they NEVER promote, suppress, or gate a finding's truth (the oracle's sole job)."""

from __future__ import annotations

from vigil_integration.agent import (
    AgentState,
    audit_productivity_claim,
    axis_key,
    axis_unproductive_count,
    compute_productivity_score,
    deep_think_is_novel,
    detect_state_growth,
    detect_uniform_response_anomaly,
    downgrade_verdict_to_no_progress,
    extract_axis,
    governance_decision,
    record_axis_attempt,
    tier_for_score,
    update_stall_counters,
)
from vigil_integration.agent.cognition import (
    _normalize_args_pattern,
    _output_fingerprint,
    is_unproductive,
    jaccard,
)


# --- fingerprint / pattern helpers -----------------------------------------------------------

def test_normalize_args_collapses_ids_to_one_pattern():
    a = _normalize_args_pattern("http_get", {"url": "http://t/order/300500"})
    b = _normalize_args_pattern("http_get", {"url": "http://t/order/300600"})
    assert a == b  # different order IDs → one logical pattern
    c = _normalize_args_pattern("http_get", {"url": "http://t/login"})
    assert c != a


def test_output_fingerprint_ignores_timestamps_and_uuids():
    s1 = {"tool_output": "result at 2026-07-21T10:00:00Z id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee ok"}
    s2 = {"tool_output": "result at 2026-07-21T11:22:33Z id=11111111-2222-3333-4444-555555555555 ok"}
    assert _output_fingerprint(s1) == _output_fingerprint(s2)
    s3 = {"tool_output": "totally different body"}
    assert _output_fingerprint(s3) != _output_fingerprint(s1)


# --- the honesty audit (kin to the veracity firewall) ----------------------------------------

def test_honesty_audit_flags_claimed_progress_without_state_delta():
    prod = {"verdict": "new_info", "new_information_gained": True}
    msg = audit_productivity_claim(prod, extracted_info={}, actionable_findings=[], findings_grew=False)
    assert msg is not None and "no finding" in msg


def test_honesty_audit_silent_when_state_actually_grew():
    prod = {"verdict": "new_info", "new_information_gained": True}
    assert audit_productivity_claim(prod, {"ports": [80]}, [], findings_grew=True) is None
    # extracted_info alone is enough evidence of growth
    assert audit_productivity_claim(prod, {"services": ["http"]}, [], findings_grew=False) is None


def test_honesty_audit_rejects_truthy_scalar_as_growth():
    # RED-PEN BLOCK-5 regression: a truthy scalar in extracted_info is NOT state growth — only a
    # non-empty collection is. Otherwise the model fakes progress with `{"ports": "anything"}`.
    prod = {"verdict": "new_info", "new_information_gained": True}
    assert audit_productivity_claim(prod, {"ports": "totally not a real port"}, [], False) is not None
    assert audit_productivity_claim(prod, {"credentials": 0.0001}, [], False) is not None
    assert audit_productivity_claim(prod, {"ports": True}, [], False) is not None
    # a genuinely non-empty collection IS growth → silent
    assert audit_productivity_claim(prod, {"ports": [80, 443]}, [], False) is None


def test_honesty_audit_survives_nonstring_llm_fields():
    # RED-PEN BLOCK-3 + RE-1 regression: `productivity` is the LLM's unvalidated self-report. A
    # non-string OR empty what_was_new is NOT a valid citation → it must be FLAGGED (never crash, and
    # never silently accepted via str()-coercion: `str([]) == "[]"` must not read as "cited").
    for wwn in (["x"], 5, [], {}, 0, False, None, "", "   "):
        msg = audit_productivity_claim({"verdict": "diagnostic_progress", "what_was_new": wwn}, {}, [], False)
        assert msg is not None, f"non-string/empty what_was_new={wwn!r} must be flagged, not accepted"
    # only a real non-empty string citation passes
    assert audit_productivity_claim({"verdict": "diagnostic_progress", "what_was_new": "ruled out SQLi"},
                                    {}, [], False) is None
    # totally malformed top-level inputs still don't crash
    assert audit_productivity_claim("not-a-dict", {}, [], False) is None
    assert audit_productivity_claim({"verdict": "new_info", "new_information_gained": True},
                                    "not-a-dict", [], False) is not None  # non-dict extracted_info


def test_honesty_audit_scalar_actionable_findings_not_growth():
    # RE-2 regression: a truthy non-collection actionable_findings must not fake growth (same bypass
    # class as BLOCK-5, on the adjacent argument). Only a non-empty collection counts.
    prod = {"verdict": "new_info", "new_information_gained": True}
    for junk in ("garbage", 1, 0.5, True):
        assert audit_productivity_claim(prod, {}, junk, False) is not None, junk
    # a real non-empty list of leads IS growth
    assert audit_productivity_claim(prod, {}, [{"title": "idor"}], False) is None


def test_honesty_audit_requires_what_was_new_for_diagnostic_progress():
    prod = {"verdict": "diagnostic_progress", "what_was_new": "   "}
    msg = audit_productivity_claim(prod, {}, [], findings_grew=False)
    assert msg is not None and "what_was_new" in msg
    ok = {"verdict": "diagnostic_progress", "what_was_new": "ruled out SQLi on the id param"}
    assert audit_productivity_claim(ok, {}, [], findings_grew=False) is None


def test_downgrade_preserves_original_and_forces_no_progress():
    prod = {"verdict": "new_info", "new_information_gained": True, "what_was_new": "x"}
    out = downgrade_verdict_to_no_progress(prod, "lied about progress")
    assert out["verdict"] == "no_progress"
    assert out["new_information_gained"] is False
    assert out["_original_verdict"] == "new_info"
    assert out["_downgrade_reason"] == "lied about progress"
    # original object is not mutated (immutable update)
    assert prod["verdict"] == "new_info"


def test_honesty_audit_is_not_authoritative_over_findings():
    """The audit downgrades a *verdict* (scheduling); it must never remove a fact. A state carrying an
    oracle-confirmed FACT keeps it regardless of how the productivity claim is judged."""
    state = AgentState(engagement_slug="t")
    from vigil_integration.agent import Finding
    state.record_fact(Finding(ref="f1", bug_class="idor", status="lead"), evidence_ref="spine:abc")
    prod = {"verdict": "new_info", "new_information_gained": True}
    _ = audit_productivity_claim(prod, {}, [], findings_grew=False)          # flags dishonesty
    _ = downgrade_verdict_to_no_progress(prod, "flagged")                     # downgrades the verdict
    assert len(state.facts) == 1 and state.facts[0].status == "fact"          # the FACT is untouched


# --- uniform-response anomaly: INCONCLUSIVE, not NEGATIVE -------------------------------------

def _diag_step(size=100, dur=10, ec="shell_parser_error"):
    return {"error_class": ec, "tool_output": "x" * size, "duration_ms": dur, "success": False}


def test_uniform_anomaly_fires_on_fast_identical_diagnostic_failures():
    trace = [_diag_step() for _ in range(6)]
    msg = detect_uniform_response_anomaly(trace)
    assert msg is not None
    assert "INCONCLUSIVE, not NEGATIVE" in msg
    assert "Do NOT mark this vector 'tested'" in msg


def test_uniform_anomaly_silent_when_responses_are_slow():
    # a genuine reachable target answers in real time (>50ms) — not a short-circuit
    trace = [_diag_step(dur=250) for _ in range(6)]
    assert detect_uniform_response_anomaly(trace) is None


def test_uniform_anomaly_only_on_diagnostic_failure_classes():
    # a real 404 streak is a legitimate NEGATIVE, not a diagnostic short-circuit → no anomaly
    trace = [{"error_class": "application_404", "tool_output": "not found", "duration_ms": 5,
              "success": False} for _ in range(6)]
    assert detect_uniform_response_anomaly(trace) is None


def test_uniform_anomaly_needs_enough_samples():
    assert detect_uniform_response_anomaly([_diag_step() for _ in range(3)]) is None


def test_uniform_anomaly_silent_on_zero_duration_legacy_steps():
    # duration_ms=0 (unmeasured/legacy) must not be read as "instant short-circuit"
    trace = [_diag_step(dur=0) for _ in range(6)]
    assert detect_uniform_response_anomaly(trace) is None


def test_uniform_anomaly_fires_despite_size_jitter():
    # RED-PEN BLOCK-1 regression: a parser that echoes the offending payload jitters body length.
    # A hard len//32 grid split these across buckets and silently MISSED the short-circuit; the
    # size-SPREAD check must still fire.
    small_jitter = [_diag_step(size=s, dur=8) for s in (62, 62, 62, 62, 65, 66)]
    assert detect_uniform_response_anomaly(small_jitter) is not None
    echo_jitter = [_diag_step(size=s, dur=8) for s in (58, 68, 78, 88, 98, 108)]
    assert detect_uniform_response_anomaly(echo_jitter) is not None
    # but wildly different sizes are NOT a uniform short-circuit → no anomaly
    wild = [_diag_step(size=s, dur=8) for s in (40, 400, 4000, 40, 400, 4000)]
    assert detect_uniform_response_anomaly(wild) is None


def test_uniform_anomaly_survives_malformed_steps():
    # RED-PEN BLOCK-2 regression: tool_output is untrusted; non-str / non-dict steps must not crash.
    trace = [
        {"error_class": "shell_parser_error", "tool_output": 999, "duration_ms": 8, "success": False},
        {"error_class": "shell_parser_error", "tool_output": {"k": "v"}, "duration_ms": "abc", "success": False},
        {"error_class": "shell_parser_error", "tool_output": None, "duration_ms": float("inf"), "success": False},
        {"error_class": "shell_parser_error", "tool_output": [1, 2], "duration_ms": 8, "success": False},
        None,
        "not-a-dict",
    ]
    assert detect_uniform_response_anomaly(trace) is None  # no crash, no false fire


# --- tested-axes semantic ledger -------------------------------------------------------------

def test_extract_axis_credential_brute_force_dedups_by_fixed_user():
    code = ('for pw in wordlist:\n'
            '    requests.post("http://t/login", json={"username": "admin", "password": pw})')
    ax1 = extract_axis("execute_code", {"code": code})
    assert ax1 and ax1["family"] == "credential_brute_force" and ax1["fixed_user"] == "admin"
    # a textually different attempt on the SAME logical vector → same axis key
    code2 = ('for password in open("rockyou.txt"):\n'
             '    requests.post("http://t/login", json={"username": "admin", "password": password})')
    ax2 = extract_axis("execute_code", {"code": code2})
    assert axis_key(ax1) == axis_key(ax2)


def test_extract_axis_none_for_non_repeating_tool():
    assert extract_axis("http_get", {"url": "http://t/"}) is None
    assert extract_axis("execute_code", {"code": "print(1+1)"}) is None  # no brute-force hint


def test_extract_axis_survives_malformed_args():
    # RED-PEN BLOCK-4 regression: tool_name / tool_args are LLM/tool-authored → any shape must not crash.
    assert extract_axis("execute_code", {"code": ["for pw in x"]}) is None      # non-str code
    assert extract_axis("execute_code", {"code": 5}) is None
    assert extract_axis("job_spawn", {"tool_name": ["execute_ffuf"]}) is None    # non-str inner tool
    assert extract_axis("execute_hydra", {"foo": {1, 2, 3}}) is None             # non-JSON-serializable
    assert extract_axis("execute_ffuf", {"foo": {1, 2, 3}}) is None
    assert extract_axis("execute_sqlmap", {"command": {1, 2, 3}}) is None
    assert extract_axis(None, {"code": "x"}) is None                             # non-str tool_name
    assert extract_axis("execute_code", "not-a-dict") is None                    # non-dict args


def test_extract_axis_ffuf_and_job_spawn_wrapper():
    ax = extract_axis("execute_ffuf", {"args": "-u http://t/FUZZ -mc 200,301 -w big.txt"})
    assert ax and ax["family"] == "directory_brute_force" and ax["target"] == "http://t/FUZZ"
    wrapped = extract_axis("job_spawn", {"tool_name": "execute_ffuf",
                                         "args": {"args": "-u http://t/FUZZ -mc 200,301 -w big.txt"}})
    assert axis_key(ax) == axis_key(wrapped)


def test_axis_ledger_counts_only_unproductive_attempts():
    led = {}
    k = axis_key({"family": "credential_brute_force", "target": "t", "fixed_user": "admin", "varied": "password"})
    led = record_axis_attempt(led, k, 1, "no_progress", "execute_code")
    led = record_axis_attempt(led, k, 2, "duplicate", "execute_code")
    led = record_axis_attempt(led, k, 3, "new_info", "execute_code")   # productive: not counted
    assert axis_unproductive_count(led, k) == 2
    # record is immutable — the empty ledger it started from is unchanged
    assert axis_unproductive_count({}, k) == 0


# --- productivity score + tiering + governance -----------------------------------------------

def test_productivity_score_rises_with_stall_and_repeats():
    fresh = compute_productivity_score(execution_trace=[], tested_axes={},
                                       iterations_since_state_grew=0, iteration=1, max_iterations=100)
    assert fresh["score"] == 0.0
    axes = {"k": [{"iteration": i, "verdict": "no_progress", "tool": "t"} for i in range(5)]}
    trace = [{"tool_name": "execute_code", "tool_args": {"code": "x"},
              "tool_output": "same error", "success": False,
              "productivity": {"verdict": "no_progress", "new_information_gained": False}} for _ in range(6)]
    stalled = compute_productivity_score(execution_trace=trace, tested_axes=axes,
                                         iterations_since_state_grew=8, iteration=90, max_iterations=100,
                                         phase="exploitation")
    assert stalled["score"] > fresh["score"]
    assert stalled["components"]["max_axis_repeats"] == 5


def test_productivity_new_info_lowers_score():
    trace = [{"tool_name": "http_get", "tool_args": {"url": f"http://t/{i}"},
              "tool_output": f"unique body {i}", "success": True,
              "productivity": {"verdict": "new_info"}, "actionable_findings": [{"x": i}]} for i in range(5)]
    r = compute_productivity_score(execution_trace=trace, tested_axes={},
                                   iterations_since_state_grew=0, iteration=5, max_iterations=100)
    assert r["score"] == 0.0  # rewards clamp the floor at 0, never negative
    assert r["components"]["new_info_events"] == 5


def test_tier_thresholds():
    assert tier_for_score(0.0) == "green"
    assert tier_for_score(3.0) == "yellow"
    assert tier_for_score(5.0) == "orange"
    assert tier_for_score(7.0) == "red"
    assert tier_for_score(9.9) == "critical"


def test_governance_decision_is_total_on_malformed_trace():
    # RED-PEN BLOCK-2 regression at the documented entry point: a hostile tool response (non-str
    # output, non-int duration, non-dict steps, garbage tested_axes) must degrade to "no signal",
    # never a denial-of-cognition crash.
    trace = [
        {"tool_name": "t", "tool_args": {1, 2}, "tool_output": 12345, "success": True},
        {"tool_name": 7, "tool_args": "x", "tool_output": {"a": 1}, "productivity": "nope"},
        None,
        "garbage",
        {"tool_output": b"bytes", "duration_ms": None},
    ]
    v = governance_decision(execution_trace=trace, tested_axes={"k": "not-a-list"},
                            iterations_since_state_grew="oops", iteration=3, max_iterations=0)
    assert v.action in {"none", "inject_hint", "require_deep_think", "require_pivot",
                        "block_next_expensive_call"}
    # PANEL regression: totality on a truthy NON-LIST container, not just a str (a str is subscriptable
    # so it accidentally passed; int/dict/set/bool/float subscript-crashed before _trace_list).
    for bad_trace in ("not-a-list", 1, 3.14, True, {"k": "v"}, {1, 2}, None):
        v = governance_decision(execution_trace=bad_trace, tested_axes=["nope"],
                                iterations_since_state_grew=float("inf"), iteration=None,
                                max_iterations=100)
        assert v.tier == "green", bad_trace          # degrades to no-signal, never crashes
    from vigil_integration.agent import detect_uniform_response_anomaly as _d
    for bad_trace in (1, 3.14, True, {"k": "v"}, "str"):
        assert _d(bad_trace) is None


def test_governance_decision_maps_tier_to_budget_action():
    v = governance_decision(execution_trace=[], tested_axes={}, iterations_since_state_grew=0,
                            iteration=1, max_iterations=100)
    assert v.tier == "green" and v.action == "none"
    axes = {"k": [{"iteration": i, "verdict": "no_progress", "tool": "t"} for i in range(6)]}
    trace = [{"tool_name": "t", "tool_args": {}, "tool_output": "e", "success": False,
              "productivity": {"verdict": "no_progress"}} for _ in range(6)]
    hot = governance_decision(execution_trace=trace, tested_axes=axes, iterations_since_state_grew=10,
                              iteration=95, max_iterations=100, phase="exploitation")
    assert hot.action in ("require_pivot", "block_next_expensive_call")
    # the action vocabulary is budget/scheduling only — never a finding verb
    assert hot.action in {"none", "inject_hint", "require_deep_think", "require_pivot",
                          "block_next_expensive_call"}


# --- deep-think novelty guard ----------------------------------------------------------------

def test_deep_think_requires_two_hypotheses_and_novelty():
    ok, why = deep_think_is_novel("attack the JWT alg-none and the session-fixation cookie path",
                                  "brute force the login form with rockyou",
                                  competing_hypotheses=2)
    assert ok, why
    bad, why2 = deep_think_is_novel("x", "y", competing_hypotheses=1)
    assert not bad and "competing hypotheses" in why2


def test_deep_think_rejects_paraphrase_of_prior_plan():
    plan = "brute force the login form using the rockyou wordlist against admin"
    near = "brute force the login form using the rockyou wordlist against admin user"  # +1 token
    ok, why = deep_think_is_novel(near, plan, competing_hypotheses=3)
    assert not ok and "paraphrase" in why
    assert jaccard(plan, plan) == 1.0


# --- stall bookkeeping -----------------------------------------------------------------------

def test_state_growth_detection():
    before = {"target_info": {"ports": [80]}}
    after = {"target_info": {"ports": [80, 443]}}
    assert detect_state_growth(before, after) is True
    assert detect_state_growth(after, after) is False


def test_state_growth_scalar_in_list_slot_is_not_growth():
    # PANEL regression: a STR scalar in a list-slot faked growth via bare len() ("open" len 4 > []);
    # a non-str scalar CRASHED len(). Both must read as no-growth (growth = a non-empty COLLECTION).
    assert detect_state_growth({"target_info": {"ports": []}},
                               {"target_info": {"ports": "open"}}) is False   # str scalar ≠ growth
    assert detect_state_growth({}, {"target_info": {"ports": 5}}) is False     # int scalar: no crash
    assert detect_state_growth({}, {"target_info": {"credentials": 3.14}}) is False
    assert detect_state_growth({"chain_findings_memory": ""},
                               {"chain_findings_memory": "boom"}) is False     # chain str scalar ≠ growth
    assert detect_state_growth({}, {"chain_findings_memory": 7}) is False      # chain int: no crash
    # a real collection still grows
    assert detect_state_growth({"chain_findings_memory": []},
                               {"chain_findings_memory": [{"f": 1}]}) is True


def test_stall_counters_reset_on_growth_and_cap_diagnostic_masking():
    # real growth resets both counters
    assert update_stall_counters(5, 3, grew=True, diag=True) == (0, 0)
    # diagnostic progress resets the stall — but only up to the cap
    assert update_stall_counters(4, 2, grew=False, diag=True, cap=6) == (0, 3)
    # past the cap, diagnostic progress can no longer mask the stall
    assert update_stall_counters(4, 6, grew=False, diag=True, cap=6) == (5, 6)
    # neither grew nor diagnostic → stall advances
    assert update_stall_counters(4, 1, grew=False, diag=False) == (5, 1)


# --- is_unproductive read path ---------------------------------------------------------------

def test_is_unproductive_reads_nested_and_respects_diagnostic_progress():
    assert is_unproductive({"output_analysis": {"productivity": {"verdict": "no_progress"}}}) is True
    assert is_unproductive({"productivity": {"verdict": "diagnostic_progress"}}) is False
    assert is_unproductive({"productivity": {"new_information_gained": False}}) is True
    assert is_unproductive({}) is False  # no verdict → not counted as unproductive here


# --- PANEL-ROUND regressions (perspective-diverse verification, round 3) ----------------------

def test_honesty_audit_flags_zero_width_citation():
    # PANEL RE-1 + ROUND-4 residual: an invisible "citation" must be flagged. Covers the WHOLE invisible
    # class, not just Cf: Cf (ZWSP/BOM/WJ/SHY/ZWNJ/ZWJ), Lo Hangul fillers (U+3164/U+115F/U+1160/U+FFA0),
    # So Braille blank (U+2800), Mn variation-selector + lone combining mark, Z* separators.
    invisible = ("​", "﻿", "⁠", "­", "‌‍",       # Cf
                 "ㅤ", "ᅟ", "ᅠ", "ﾠ",                        # Lo Hangul fillers
                 "⠀",                                                       # So Braille blank
                 "️", "́", "́́",                            # Mn marks / variation selector
                 " ", "　", "   ", "​ ⁠", "ㅤ" * 3)      # Z* / mixed
    for ch in invisible:
        msg = audit_productivity_claim({"verdict": "diagnostic_progress", "what_was_new": ch}, {}, [], False)
        assert msg is not None, f"invisible citation {ch!r} (U+{ord(ch[0]):04X}) must be flagged"
    # a real citation with visible text (even amid zero-width chars, or emoji-only) passes
    assert audit_productivity_claim({"verdict": "diagnostic_progress", "what_was_new": "ruled​ out"},
                                    {}, [], False) is None
    assert audit_productivity_claim({"verdict": "diagnostic_progress", "what_was_new": "\U0001f525"},
                                    {}, [], False) is None


def test_uniform_anomaly_survives_nonstring_error_class():
    # PANEL HIGH: a non-string error_class (list/dict) is unhashable → crashed `ec not in frozenset`.
    for ec in (["shell_parser_error"], {"k": "v"}, {1, 2}, 5):
        trace = [{"error_class": ec, "tool_output": "x", "duration_ms": 8, "success": False} for _ in range(6)]
        assert detect_uniform_response_anomaly(trace) is None   # no crash, and no fire (not a diag class)


def test_uniform_anomaly_robust_to_single_outlier():
    # PANEL MEDIUM: max-min spread let ONE outlier suppress an otherwise-uniform short-circuit streak.
    def diag(s):
        return {"error_class": "shell_parser_error", "tool_output": "x" * s, "duration_ms": 8, "success": False}
    assert detect_uniform_response_anomaly([diag(s) for s in (40,) * 7 + (500,)]) is not None  # long echo outlier
    assert detect_uniform_response_anomaly([diag(s) for s in (40,) * 7 + (5,)]) is not None    # truncated outlier
    # still silent on genuinely wild variance (no modal cluster of >= min_count)
    assert detect_uniform_response_anomaly([diag(s) for s in (40, 400, 4000, 40, 400, 4000)]) is None


def test_score_reward_ignores_truthy_scalar_actionable_findings():
    # PANEL MEDIUM (completeness critic): a truthy SCALAR actionable_findings must not earn the reward
    # that suppresses the stall/deep-think governor — same growth invariant as the honesty audit.
    honest = [{"tool_name": "http_get", "tool_args": {"url": f"http://t/{i}"}, "tool_output": f"error {i}",
               "success": False, "productivity": {"verdict": "no_progress", "new_information_gained": False}}
              for i in range(5)]
    gamed = [dict(s, actionable_findings=True) for s in honest]   # a single truthy-scalar lever
    kw = dict(tested_axes={}, iterations_since_state_grew=0, iteration=5, max_iterations=100)
    r_honest = compute_productivity_score(execution_trace=honest, **kw)
    r_gamed = compute_productivity_score(execution_trace=gamed, **kw)
    assert r_gamed["components"]["actionable_events"] == 0        # scalar earns nothing
    assert r_gamed["score"] == r_honest["score"]                 # cannot suppress the governor
    # a real non-empty list of findings DOES earn the reward
    real = [dict(s, actionable_findings=[{"f": 1}]) for s in honest]
    assert compute_productivity_score(execution_trace=real, **kw)["components"]["actionable_events"] == 5


def test_tier_for_score_total_on_nonnumeric():
    # PANEL LOW: tier_for_score is public (__all__) — a non-numeric score must degrade, not crash.
    for bad in ("abc", None, [], {"x": 1}):
        assert tier_for_score(bad) == "green"
    assert tier_for_score(float("nan")) == "green"


def test_axis_key_total_on_mixed_keys():
    # PANEL LOW: sorted() over mixed-type keys raised TypeError; values are stringified via _as_text.
    assert axis_key({1: "a", "b": 2})           # no crash on unorderable keys
    assert axis_key({"b": 2, 1: "a"}) == axis_key({1: "a", "b": 2})   # order-independent
    assert axis_key({1: [1, 2], None: 3})       # non-str keys and values coerced, no crash


def test_extract_axis_ffuf_match_code_reorder_dedups():
    # PANEL LOW: -mc "200,301" vs "301,200" are the same filter SET → must dedup to one axis key.
    a = extract_axis("execute_ffuf", {"args": "-u http://t/FUZZ -mc 200,301 -w big.txt"})
    b = extract_axis("execute_ffuf", {"args": "-u http://t/FUZZ -mc 301,200 -w other.txt"})
    assert axis_key(a) == axis_key(b)
    # a genuinely different filter set stays distinct
    c = extract_axis("execute_ffuf", {"args": "-u http://t/FUZZ -mc 200,404 -w big.txt"})
    assert axis_key(a) != axis_key(c)


def test_deep_think_rejects_padded_superset_of_prior_plan():
    # PANEL LOW: a re-plan that keeps the ENTIRE dead plan verbatim + padding diluted Jaccard below
    # threshold yet is a full restatement — the coverage guard must reject it.
    prior = "brute force login rockyou admin"
    padded = prior + " " + " ".join(f"tok{i}" for i in range(20))
    ok, why = deep_think_is_novel(padded, prior, competing_hypotheses=3)
    assert not ok and "restates" in why
    # a genuine pivot that drops the prior approach is still accepted
    ok2, _ = deep_think_is_novel("pivot to jwt alg-none and ssrf on the metadata endpoint", prior,
                                 competing_hypotheses=2)
    assert ok2
