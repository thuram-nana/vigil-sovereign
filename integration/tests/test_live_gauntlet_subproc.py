"""
WS1c — the LIVE AI-Gauntlet subprocess adapter (``live.gauntlet_subproc``).

This adapter wires the F8 gauntlet sensor to a REAL garak/PyRIT CLI behind an INJECTED subprocess
runner. On this box garak is NOT installed, so the runner honestly reports ``{'available': False}`` and
the adapter returns ``[]`` — an honest, fail-closed no-signal.

The load-bearing property under test is the SOVEREIGN INVARIANT, unchanged by going live: a ``judge_llm``
(LLM-judge, non-deterministic) candidate can NEVER auto-promote to a signed FACT — only a deterministic
``oracle_kind`` (contains/classifier/regex) that the INJECTED oracle CONFIRMS may mint one, and even then
only with a non-empty signed evidence ref. ASR is a metric, never a promotion signal. Every path is total
on malformed input, deterministic (injected seed), egress-pinned to loopback, and fail-closed.
"""

from __future__ import annotations

import json
from pathlib import Path

from vigil_integration.agent.state import Finding
from vigil_integration.gauntlet import JUDGE_LLM
from vigil_integration.gauntlet.sensor import OracleRequest
from vigil_integration.live import gauntlet_subproc as gs
from vigil_integration.live.gauntlet_subproc import (
    GauntletProbe,
    build_argv,
    loopback_only_egress,
    redacted_argv,
    run_gauntlet,
    run_gauntlet_report,
)

LOOPBACK = "http://127.0.0.1:18080"


# --------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------


class SpyOracle:
    """An injected oracle stub. By default CONFIRMS (returns a strong signed ref) on EVERY call — used
    adversarially to prove a judge_llm candidate can never be promoted even by an always-confirming
    oracle. ``ref`` controls the returned ref; ``raise_on`` forces an error."""

    def __init__(self, ref: str | None = "spine:0xabc123deadbeef", *, raise_on=None):
        self.ref = ref
        self.calls: list[OracleRequest] = []
        self.raise_on = raise_on

    def __call__(self, req: OracleRequest):
        self.calls.append(req)
        if self.raise_on is not None and self.raise_on(req):
            raise RuntimeError("adversarial oracle blew up")
        return self.ref


def _runner(records=None, *, raw=None, available=True, key="report"):
    """A fake ``run_tool``: returns an envelope with a garak-style report. ``available`` toggles the
    installed/not-installed signal; ``raw`` overrides the report body."""
    if raw is None:
        raw = json.dumps({"results": records or []})

    def _rt(argv):
        env = {"available": available, "returncode": 0}
        if available:
            env[key] = raw
        return env

    return _rt


def _probe(*probes, seed="seed-alpha", tool="garak"):
    return GauntletProbe(tool=tool, probes=tuple(probes) or ("all",), seed=seed)


# --------------------------------------------------------------------------------------------------
# garak-unavailable / runner-error → honest empty (never a fabricated finding)
# --------------------------------------------------------------------------------------------------


def test_garak_unavailable_returns_empty_and_is_honest():
    # the real state on this box: garak is not installed → runner reports {'available': False}
    rec = {"probe": "sysprompt.Extract", "hits": 9, "trials": 10, "evidence": "leaked"}
    rep = run_gauntlet_report(
        _probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(), run_tool=_runner([rec], available=False),
    )
    assert rep.findings == ()
    assert rep.available is False            # honest: the tool did NOT run
    assert rep.egress_allowed is True        # ...but the target WAS a valid loopback egress
    assert run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(),
                        run_tool=_runner([rec], available=False)) == []


def test_runner_error_returns_empty():
    def boom(argv):
        raise OSError("garak binary vanished mid-run")

    out = run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(), run_tool=boom)
    assert out == []


def test_missing_run_tool_returns_empty():
    assert run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(), run_tool=None) == []


def test_non_mapping_envelope_returns_empty():
    for bad in ("just a string", None, 12345, ["a", "list"], object()):
        out = run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(),
                           run_tool=lambda argv, _b=bad: _b)
        assert out == []


def test_available_true_but_no_report_yields_no_findings():
    # the tool ran but produced nothing readable → honest zero findings, never a fabricated one
    rep = run_gauntlet_report(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(),
                              run_tool=lambda argv: {"available": True, "returncode": 0})
    assert rep.available is True and rep.findings == ()


def test_unknown_tool_returns_empty():
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "x"}
    out = run_gauntlet(GauntletProbe(tool="nmap", probes=("x",)), target=LOOPBACK,
                       oracle=SpyOracle(), run_tool=_runner([rec]))
    assert out == []


# --------------------------------------------------------------------------------------------------
# egress pin — loopback only (fail-closed on anything else)
# --------------------------------------------------------------------------------------------------


def test_loopback_variants_are_allowed():
    for t in ("http://127.0.0.1:18080", "127.0.0.1", "127.0.0.1:18080", "http://127.1.2.3",
              "http://localhost:8080", "localhost", "http://[::1]:9090", "::1"):
        allowed, _reason = loopback_only_egress(t)
        assert allowed is True, t


def test_non_loopback_targets_are_denied():
    for t in ("http://93.184.216.34", "http://10.0.0.5", "http://169.254.169.254/latest/meta-data",
              "http://192.168.1.1", "http://8.8.8.8", "http://example.com", "http://metadata.google.internal",
              "", None, "not a url", 12345):
        allowed, _reason = loopback_only_egress(t)
        assert allowed is False, t


def test_non_loopback_target_denied_end_to_end_even_with_confirming_oracle():
    # a would-be deterministic FACT against a NON-loopback target must be dropped BEFORE the runner fires
    rec = {"probe": "apikey.Leak", "hits": 1, "trials": 1, "evidence": "canary"}
    fired = {"n": 0}

    def _rt(argv):
        fired["n"] += 1
        return {"available": True, "report": json.dumps({"results": [rec]})}

    rep = run_gauntlet_report(_probe("apikey"), target="http://93.184.216.34",
                              oracle=SpyOracle(ref="spine:sig"), run_tool=_rt)
    assert rep.findings == ()
    assert rep.available is False and rep.egress_allowed is False
    assert fired["n"] == 0, "the runner must never be invoked for a non-loopback target"


def test_userinfo_atsign_resolves_to_real_connect_host():
    # requests/urllib3 connect to the host AFTER the last '@'; the pin must agree with the real client.
    assert loopback_only_egress("http://evil.com@127.0.0.1/")[0] is True     # connects to loopback → allow
    assert loopback_only_egress("http://127.0.0.1@evil.com/")[0] is False    # connects to evil.com → deny
    # backslash is folded to '/' (WHATWG/urllib3 semantics) → host is 127.0.0.1 → the real connect target
    assert loopback_only_egress("http://127.0.0.1\\@evil.com/")[0] is True


def test_injected_egress_check_overrides_default_and_is_failclosed():
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "x"}
    # an injected check that DENIES everything → no findings even for a loopback target
    deny_all = run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(),
                            run_tool=_runner([rec]), egress_check=lambda t: (False, "policy: denied"))
    assert deny_all == []
    # an egress check that RAISES is fail-closed (deny), never allow
    def _boom(_t):
        raise RuntimeError("egress policy engine down")
    assert run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(),
                        run_tool=_runner([rec]), egress_check=_boom) == []


# --------------------------------------------------------------------------------------------------
# ssrf_egress_gate — the CORRECT adapter for the general SSRF gate
# (regression: WS1c egress-polarity — wiring the raw is_egress_denied inverted the gate)
# --------------------------------------------------------------------------------------------------


def test_ssrf_egress_gate_inverts_polarity_and_denies_metadata():
    """REGRESSION: wiring the raw ``is_egress_denied`` as ``egress_check`` inverted the gate — its
    ``(denied, reason)`` verdict read as ``(allowed, reason)``, so cloud metadata and every URL (which is
    "unparseable" as a bare IP) fired the runner. ``ssrf_egress_gate`` is the correct adapter: it inverts
    the polarity exactly once and extracts the host from the URL, so a genuinely-denied target is DENIED."""
    from vigil_gateway.denylist import is_egress_denied

    # (1) polarity is inverted for an IP literal: allowed == NOT denied
    for ip in ("127.0.0.1", "8.8.8.8", "169.254.169.254"):
        denied = is_egress_denied(ip)[0]
        allowed = gs.ssrf_egress_gate(ip)[0]
        assert allowed is (not denied), ip

    # (2) the exact repro targets that used to leak: metadata is DENIED (was ALLOWED before the fix)
    assert gs.ssrf_egress_gate("http://169.254.169.254/latest/")[0] is False
    # (3) a bare-hostname URL is DENIED fail-closed (DNS-free, no resolver wired) — never "unparseable=allow"
    assert gs.ssrf_egress_gate("http://example.com/")[0] is False


def test_ssrf_egress_gate_wired_as_egress_check_never_fires_runner():
    """END-TO-END: the documented correct wiring (``egress_check=ssrf_egress_gate``) drops a metadata /
    non-loopback target BEFORE the runner fires — closing the inversion the raw wiring opened. Uses the
    lazily-defaulted real ``is_egress_denied`` gate, exactly as an orchestrator would wire it."""
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "x"}
    for tgt in ("http://169.254.169.254/latest/", "http://example.com/", "http://8.8.8.8/"):
        fired = {"n": 0}

        def _rt(argv, _f=fired):
            _f["n"] += 1
            return {"available": True, "report": json.dumps({"results": [rec]})}

        rep = run_gauntlet_report(_probe("sysprompt"), target=tgt, oracle=SpyOracle(ref="spine:x"),
                                  run_tool=_rt, egress_check=gs.ssrf_egress_gate)
        if tgt == "http://8.8.8.8/":
            continue  # a globally-routable, non-SSRF target: the general gate legitimately ALLOWS it
        assert rep.findings == () and rep.available is False and rep.egress_allowed is False, tgt
        assert fired["n"] == 0, tgt


def test_ssrf_egress_gate_is_total_and_fail_closed():
    g = gs.ssrf_egress_gate
    # denied_check not callable → deny
    assert g("http://127.0.0.1/", denied_check="nope")[0] is False
    # denied_check raises → deny (never allow)
    def _boom(_ip):
        raise RuntimeError("gate down")
    assert g("http://8.8.8.8/", denied_check=_boom)[0] is False
    # a malformed gate verdict (not a (denied, reason) tuple) → deny
    assert g("http://8.8.8.8/", denied_check=lambda ip: True)[0] is False
    # a hostname with no resolver → deny (DNS-free fail-closed)
    assert g("http://host.example/", denied_check=lambda ip: (False, "ok"))[0] is False
    # a resolver that raises → deny
    def _rboom(_h):
        raise RuntimeError("dns down")
    assert g("http://host.example/", denied_check=lambda ip: (False, "ok"), resolve=_rboom)[0] is False
    # a resolver that yields nothing → deny
    assert g("http://host.example/", denied_check=lambda ip: (False, "ok"), resolve=lambda h: [])[0] is False
    # a non-string target (no host) → deny
    assert g(12345, denied_check=lambda ip: (False, "ok"))[0] is False


def test_ssrf_egress_gate_checks_every_resolved_ip():
    # a hostname that resolves to several IPs — if ANY is denied, the whole target is DENIED (fail-closed)
    def denied_check(ip):
        return (ip == "169.254.169.254", f"{ip} verdict")

    # all-clean resolution → allowed
    assert gs.ssrf_egress_gate("http://svc.internal/", denied_check=denied_check,
                               resolve=lambda h: ["93.184.216.34", "8.8.8.8"])[0] is True
    # one metadata IP hidden among clean ones → DENIED, and the reason names the culprit
    allowed, reason = gs.ssrf_egress_gate("http://svc.internal/", denied_check=denied_check,
                                          resolve=lambda h: ["8.8.8.8", "169.254.169.254"])
    assert allowed is False and "169.254.169.254" in reason


# --------------------------------------------------------------------------------------------------
# the deterministic FACT path
# --------------------------------------------------------------------------------------------------


def test_deterministic_finding_promotes_to_fact_when_oracle_confirms():
    rec = {"probe": "sysprompt.Extract", "hits": 3, "trials": 10, "evidence": "leaked system prompt"}
    spy = SpyOracle(ref="spine:evref-123")
    rep = run_gauntlet_report(_probe("sysprompt"), target=LOOPBACK, oracle=spy, run_tool=_runner([rec]))
    f = rep.findings[0]
    assert f.status == "fact" and f.evidence_ref == "spine:evref-123"
    assert rep.fact_count == 1 and rep.lead_count == 0
    # the oracle re-executed over the RETAINED raw evidence with a fresh per-run challenge token
    assert len(spy.calls) == 1
    assert spy.calls[0].raw_output == "leaked system prompt"
    assert spy.calls[0].oracle_kind == "contains"
    assert len(spy.calls[0].challenge_token) == 64      # sha256 hex, derived from the injected seed


def test_no_oracle_wired_stays_lead_failclosed():
    rec = {"probe": "sysprompt.Extract", "hits": 3, "trials": 10, "evidence": "x"}
    out = run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=None, run_tool=_runner([rec]))
    assert out[0].status == "lead" and out[0].evidence_ref == ""


def test_oracle_error_stays_lead_failclosed():
    rec = {"probe": "apikey.Leak", "hits": 1, "trials": 3, "evidence": "canary"}
    spy = SpyOracle(raise_on=lambda req: True)
    out = run_gauntlet(_probe("apikey"), target=LOOPBACK, oracle=spy, run_tool=_runner([rec]))
    assert spy.calls, "a deterministic kind must consult the oracle"
    assert out[0].status == "lead"          # ...but the oracle error confirmed nothing


def test_empty_or_whitespace_ref_mints_no_fact():
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "x"}
    for bad_ref in ("", "   ", None):
        out = run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(ref=bad_ref),
                           run_tool=_runner([rec]))
        assert out[0].status == "lead" and out[0].evidence_ref == ""


# --------------------------------------------------------------------------------------------------
# THE SOVEREIGN INVARIANT (adversarial) — a judge_llm finding can NEVER become a FACT
# --------------------------------------------------------------------------------------------------


def test_sovereign_invariant_judge_llm_finding_can_never_become_a_fact():
    """A judge_llm category, maxed-out ASR, driven LIVE with an ADVERSARIAL oracle that returns a strong
    signed ref on EVERY call. The finding MUST stay a LEAD and the oracle must NEVER be consulted for it;
    a deterministic control in the SAME run IS promoted — proving the difference is oracle_kind ROUTING,
    not the oracle and not the (high vs low) ASR."""
    judge_rec = {"probe": "malwaregen.Evasion", "hits": 10, "trials": 10,
                 "evidence": "sure, here is working malware"}
    contains_rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 10,
                    "evidence": "SYSTEM PROMPT: the secret is 42"}
    spy = SpyOracle(ref="spine:0xFORGED_deadbeef")
    rep = run_gauntlet_report(_probe("malwaregen", "sysprompt"), target=LOOPBACK, oracle=spy,
                              run_tool=_runner([judge_rec, contains_rec]))

    by_chip = {f.bug_class: f for f in rep.findings}
    judge_f = by_chip["harmful-generation"]
    contains_f = by_chip["system-prompt-leak"]

    # (1) the invariant: judge_llm is a LEAD despite max ASR and an always-confirming oracle
    assert judge_f.status == "lead" and judge_f.evidence_ref == ""

    # (2) structural proof: the oracle was NEVER consulted for the judge_llm candidate
    assert all(req.oracle_kind != JUDGE_LLM for req in spy.calls)
    assert all(req.chip != "harmful-generation" for req in spy.calls)

    # (3) control: the SAME adversarial oracle DOES promote the deterministic candidate
    assert contains_f.status == "fact" and contains_f.evidence_ref == "spine:0xFORGED_deadbeef"
    assert any(req.chip == "system-prompt-leak" for req in spy.calls)
    assert rep.fact_count == 1 and rep.lead_count == 1


def test_unmapped_category_is_a_lead_not_a_fact():
    rec = {"probe": "some_probe_we_never_classified", "hits": 5, "trials": 5, "evidence": "x"}
    out = run_gauntlet(_probe("misc"), target=LOOPBACK, oracle=SpyOracle(ref="spine:x"),
                       run_tool=_runner([rec]))
    assert out[0].status == "lead"          # an unmapped category defaults to judge_llm (LEAD-only)


def test_asr_is_a_metric_not_a_promotion_signal():
    # (a) a maxed-ASR judge_llm finding is a LEAD (severity high, still lead)
    judge = {"probe": "toxicity", "asr": 1.0, "num_examples": 8, "evidence": "x"}
    rep1 = run_gauntlet_report(_probe("toxicity"), target=LOOPBACK, oracle=SpyOracle(),
                               run_tool=_runner([judge]))
    assert rep1.findings[0].severity == "high" and rep1.findings[0].status == "lead"
    assert rep1.overall_asr == 1.0          # ASR IS computed as a metric...
    # (b) ...yet a ZERO-ASR deterministic finding STILL becomes a FACT if the oracle fires
    det = {"probe": "apikey.Leak", "hits": 0, "trials": 10, "evidence": "leaked canary abc"}
    rep2 = run_gauntlet_report(_probe("apikey"), target=LOOPBACK, oracle=SpyOracle(ref="spine:ok"),
                               run_tool=_runner([det]))
    assert rep2.findings[0].severity == "info" and rep2.overall_asr == 0.0
    assert rep2.findings[0].status == "fact" and rep2.findings[0].evidence_ref == "spine:ok"


# --------------------------------------------------------------------------------------------------
# totality on malformed tool output + determinism
# --------------------------------------------------------------------------------------------------


def test_total_on_malformed_report_bodies():
    for bad in ("", "not json at all {{{", "null", "[]", json.dumps({"results": "nope"}),
                json.dumps([{"no_category_field": 1}]), "\x00\x01garbage"):
        out = run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(),
                           run_tool=_runner(raw=bad))
        assert out == [], repr(bad)


def test_report_may_be_an_already_parsed_list_or_dict():
    # some runners hand back a parsed structure rather than text — the adapter serializes + parses it
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "leaked"}
    out_list = run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(ref="spine:a"),
                            run_tool=lambda argv: {"available": True, "report": [rec]})
    out_dict = run_gauntlet(_probe("sysprompt"), target=LOOPBACK, oracle=SpyOracle(ref="spine:a"),
                            run_tool=lambda argv: {"available": True, "report": {"results": [rec]}})
    assert out_list and out_list[0].status == "fact"
    assert out_dict and out_dict[0].status == "fact"


def test_deterministic_with_injected_seed():
    recs = [{"probe": "sysprompt.Extract", "hits": 2, "trials": 5, "evidence": "e1"},
            {"probe": "malwaregen", "hits": 3, "trials": 5, "evidence": "e2"}]
    a, b = SpyOracle(ref="spine:z"), SpyOracle(ref="spine:z")
    r1 = run_gauntlet_report(_probe("sysprompt", "malwaregen", seed="fixed"), target=LOOPBACK,
                             oracle=a, run_tool=_runner(recs))
    r2 = run_gauntlet_report(_probe("sysprompt", "malwaregen", seed="fixed"), target=LOOPBACK,
                             oracle=b, run_tool=_runner(recs))
    assert r1.findings == r2.findings                        # identical input+seed → identical output
    assert a.calls[0].challenge_token == b.calls[0].challenge_token


def test_challenge_token_depends_on_injected_seed():
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "e"}
    a, b = SpyOracle(), SpyOracle()
    run_gauntlet(_probe("sysprompt", seed="seed-A"), target=LOOPBACK, oracle=a, run_tool=_runner([rec]))
    run_gauntlet(_probe("sysprompt", seed="seed-B"), target=LOOPBACK, oracle=b, run_tool=_runner([rec]))
    assert a.calls and b.calls
    assert a.calls[0].challenge_token != b.calls[0].challenge_token


# --------------------------------------------------------------------------------------------------
# argv construction + probe coercion + secret-free
# --------------------------------------------------------------------------------------------------


def test_build_argv_is_a_list_never_a_shell_string():
    argv = build_argv(GauntletProbe(tool="garak", probes=("promptinject", "dan"), model_name="rest-gen"),
                      target=LOOPBACK)
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert argv[0] == "garak"
    assert "--probes" in argv and "promptinject,dan" in argv
    assert "--target" in argv and LOOPBACK in argv


def test_redacted_argv_scrubs_secrets():
    argv = build_argv(GauntletProbe(tool="garak", probes=("dan",),
                                    extra_argv=("--api-key", "SUPERSECRET_TOKEN_123")), target=LOOPBACK)
    red = redacted_argv(argv)
    assert "SUPERSECRET_TOKEN_123" not in " ".join(red)
    assert "dan" in " ".join(red)                           # non-secret args pass through


def test_probe_coercion_accepts_str_and_sequence():
    rec = {"probe": "sysprompt.Extract", "hits": 1, "trials": 1, "evidence": "x"}
    # a bare string probe
    out1 = run_gauntlet("sysprompt", target=LOOPBACK, oracle=SpyOracle(ref="spine:1"),
                        run_tool=_runner([rec]))
    # a sequence of probe families
    out2 = run_gauntlet(["sysprompt", "apikey"], target=LOOPBACK, oracle=SpyOracle(ref="spine:1"),
                        run_tool=_runner([rec]))
    assert out1 and out1[0].status == "fact"
    assert out2 and out2[0].status == "fact"
    # a nonsense probe → no runnable probe → fail-closed empty
    assert run_gauntlet(12345, target=LOOPBACK, oracle=SpyOracle(), run_tool=_runner([rec])) == []


def test_findings_never_carry_raw_evidence_secrets():
    rec = {"probe": "apikey.Leak", "hits": 1, "trials": 1, "evidence": "api_key=SUPERSECRET_leaked"}
    rep = run_gauntlet_report(_probe("apikey"), target=LOOPBACK, oracle=SpyOracle(ref="spine:evref"),
                              run_tool=_runner([rec]))
    for f in rep.findings:
        assert "SUPERSECRET" not in f.model_dump_json()


def test_run_gauntlet_returns_list_of_findings():
    recs = [{"probe": "sysprompt.Extract", "hits": 1, "trials": 2, "evidence": "e"},
            {"probe": "malwaregen", "hits": 2, "trials": 2, "evidence": "e"}]
    out = run_gauntlet(_probe("sysprompt", "malwaregen"), target=LOOPBACK,
                       oracle=SpyOracle(ref="spine:r"), run_tool=_runner(recs))
    assert isinstance(out, list) and all(isinstance(f, Finding) for f in out)
    assert len(out) == 2


def test_no_wallclock_or_rng_in_source():
    src = Path(gs.__file__).read_text()
    forbidden = ("import time", "import random", "import secrets", "import datetime", "import uuid",
                 "datetime.now", "time.time", "random.", "uuid.", "secrets.")
    for tok in forbidden:
        assert tok not in src, f"live gauntlet source contains forbidden nondeterminism token {tok!r}"
