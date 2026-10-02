"""WS4 — the ANTI-GREEN-WASH test for the per-VM production acceptance harness
(``vigil_integration.sovereign_deploy.acceptance``).

The harness is the self-test a freshly provisioned investor-eval box runs before handover: every required
check PASS -> exit 0 (handover-ready); ANY check FAIL, or a REQUIRED check NOT-RUN -> non-zero (handover
BLOCKED). The harness reuses the REAL product paths (``agent.intake_result``, ``proof.run.build_report_mint``,
``live.transport_redrive``, ``live.oracle_families``, ``verify.reverify.main``, ``aegis.gateway``,
``codescan.run_codescan``); it reimplements/stubs nothing.

A harness that passes a HEALTHY box but CANNOT fail a BROKEN one is worthless — the broken-box controls are the
deliverable, so this module proves BOTH directions:

  * HEALTHY — against a bundled loopback target with a hermetic (no-egress) Anthropic client injected, the
    harness reports PASS and exits 0.
  * HONEST NOT-RUN — with neither a key nor a hermetic client, the Anthropic check is reported NOT-RUN (never
    silently rounded to green). The harness's OWN policy (confirmed here, not assumed) is that a NOT-RUN on a
    REQUIRED check BLOCKS handover: it is reported honestly and it exits non-zero. This is also broken-control
    #5 (a required check NOT-RUN).
  * BROKEN controls — each simulates one broken box by monkeypatching the REAL seam the harness calls, and
    asserts the harness EXITS NON-ZERO (handover BLOCKED) with the failure attributed to the right check:
      - the oracle is disabled (a fired oracle mints nothing)      -> check 1 FAIL (mutation control broken)
      - the offline verifier no longer rejects a tampered report   -> check 2 FAIL (tamper not rejected)
      - AEGIS is un-entitled while enforce is expected             -> check 5 FAIL (downgraded to observe)
      - the governed engage mints no FACT                          -> check 2 FAIL (no signed FACT)
      - a required check is NOT-RUN                                -> check 1 NOT-RUN blocks

Invariant guard: importing/running the harness adds NO oracle — ``verify.verifier._ALL_ORACLES`` stays 15.

FATAL-2: ``acceptance.py`` is import-clean (every ``framework`` / ``vigil_integration.live`` import is
function-local), so importing it at module scope here pulls no engine; the two-env boundary is proven
separately by ``test_two_env_boundary.py`` (run alongside this module).
"""

from __future__ import annotations

import json
import socket
import threading

import pytest

from vigil_integration.sovereign_deploy.acceptance import (
    FAIL,
    NOT_RUN,
    PASS,
    AcceptanceConfig,
    AcceptanceHarness,
    exit_code,
    render_report,
    run_acceptance,
)

# The acceptance harness drives the full CRUCIBLE engine pipeline (framework.v2.* — real engage,
# proof mint, offline re-verify, entitlement, AEGIS). That engine is absent from the keyless
# two-env boundary leg BY CONSTRUCTION (FATAL-2), so these end-to-end checks can only run in the
# offense leg. Skip the whole module where framework is unavailable; it runs fully under offense.
# (The harness module itself lazy-imports framework, so importing it above stays safe here.)
pytest.importorskip("framework.v2")


# ---------------------------------------------------------------------------------------------------
# a hermetic (no-egress) Anthropic client — the documented test/air-gap seam ``think`` accepts. It
# records nothing off-host and returns a scripted, VALID decision so ``think`` yields an LLMDecision
# proposal (which the oracle then gates). Declared LOCAL (``anthropic_backend="ollama"``) so the
# sovereignty gate permits it with no bytes leaving the box.
# ---------------------------------------------------------------------------------------------------
_VALID_DECISION = json.dumps({
    "action": "use_tool",
    "tool": {"tool_name": "nmap", "tool_args": {"target": "127.0.0.1"}},
    "reasoning": "probe the bundled loopback target for a misconfiguration",
})


class _Block:
    def __init__(self, type_: str, text: str) -> None:
        self.type = type_
        self.text = text


class _Response:
    def __init__(self, text: str) -> None:
        self.content = [_Block("text", text)]


class _Messages:
    def __init__(self, outer: "_HermeticAnthropic") -> None:
        self._outer = outer

    def create(self, **kwargs):
        self._outer.captured = kwargs
        return _Response(self._outer.text)


class _HermeticAnthropic:
    """A stand-in for ``anthropic.Anthropic`` that egresses nowhere: returns a scripted response."""

    def __init__(self, text: str = _VALID_DECISION) -> None:
        self.text = text
        self.captured: dict = {}
        self.messages = _Messages(self)


# ---------------------------------------------------------------------------------------------------
# the bundled controlled loopback target: a trivial 127.0.0.1 TCP listener so VIGIL's OWN gated
# ``capture_handshake`` (the service_reachability.tcp_handshake branch) connects and mints a FACT. A
# fresh ephemeral port per test; NEVER an external host.
# ---------------------------------------------------------------------------------------------------
@pytest.fixture()
def loopback_port():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.recv(2048)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except OSError:
                pass
            finally:
                conn.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        try:
            srv.close()
        except OSError:
            pass


def _hermetic_cfg(port: int) -> AcceptanceConfig:
    return AcceptanceConfig(target_host="127.0.0.1", target_port=port,
                            anthropic_client=_HermeticAnthropic(), anthropic_backend="ollama")


def _by_key(results, key: str):
    for r in results:
        if r.key == key:
            return r
    raise AssertionError(f"no check with key {key!r} in {[r.key for r in results]}")


# ===================================================================================================
# (a) HEALTHY — the harness reports PASS / exit 0 against the bundled loopback target.
# ===================================================================================================


def test_healthy_box_reports_pass_and_exit_zero(loopback_port):
    results, rc = run_acceptance(_hermetic_cfg(loopback_port))
    report = render_report(results)
    # every one of the six required checks must PASS — no FAIL, no NOT-RUN rounded to green.
    assert [r.status for r in results] == [PASS] * 6, report
    assert not any(r.blocks for r in results), report
    assert rc == 0, report
    assert "HANDOVER-READY" in report
    # the Anthropic check genuinely RAN (hermetic), it was not skipped-as-green.
    assert _by_key(results, "1").status == PASS
    assert "hermetic" in _by_key(results, "1").detail


# ===================================================================================================
# (a) HONEST NOT-RUN + (b) broken control #5 — a required check NOT-RUN. Confirms the harness's OWN
# NOT-RUN policy rather than assuming it: a NOT-RUN on a REQUIRED check is reported honestly (never
# green) AND it blocks handover (exit non-zero).
# ===================================================================================================


def test_not_run_anthropic_is_honest_and_blocks(loopback_port, monkeypatch):
    # neither a hermetic client NOR a key -> the keyed think path cannot run.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = AcceptanceConfig(target_host="127.0.0.1", target_port=loopback_port,
                           anthropic_client=None, anthropic_backend=None)
    results, rc = run_acceptance(cfg)
    report = render_report(results)

    anthropic = _by_key(results, "1")
    # honest: reported NOT-RUN, never rounded up to PASS/green.
    assert anthropic.status == NOT_RUN, report
    assert anthropic.status != PASS
    # the harness's OWN policy, confirmed from the live result: a NOT-RUN on a REQUIRED check blocks.
    assert anthropic.required is True
    assert anthropic.blocks is True
    # the other five checks against the healthy loopback target still pass — the box is "otherwise healthy",
    # and it is reported honestly: NOT-RUN shown, verdict BLOCKED, non-zero exit (never a silent green).
    assert [r.status for r in results if r.key != "1"] == [PASS] * 5, report
    assert rc != 0, report
    assert "NOT-RUN" in report and "HANDOVER BLOCKED" in report
    # the rendered check-1 line is the honest NOT-RUN line, not a PASS line.
    assert not _by_key(results, "1").line().startswith("[PASS")


# ===================================================================================================
# (b) BROKEN control — the ORACLE is disabled (a fired oracle mints nothing). The REAL keystone the
# harness calls is ``agent.intake_result``; neuter its oracle so even a fired oracle yields 0 facts.
# The harness's mutation control (0 facts w/o oracle, 1 w/ a fired oracle) must then FAIL -> blocked.
# ===================================================================================================


def test_broken_oracle_disabled_blocks(loopback_port, monkeypatch):
    from vigil_integration import agent as _agent

    real_intake = _agent.intake_result

    def _oracle_disabled(raw, analysis, *args, oracle=None, **kwargs):
        # drop any oracle: the deterministic authority is dead, so NOTHING can be minted into a FACT.
        return real_intake(raw, analysis, *args, oracle=None, **kwargs)

    monkeypatch.setattr(_agent, "intake_result", _oracle_disabled)

    results, rc = run_acceptance(_hermetic_cfg(loopback_port))
    report = render_report(results)
    check1 = _by_key(results, "1")
    assert check1.status == FAIL, report
    assert check1.blocks is True
    assert "oracle" in check1.detail.lower()  # "a fired oracle failed to mint the FACT (mutation control broken)"
    assert rc != 0, report
    assert "HANDOVER BLOCKED" in report


# ===================================================================================================
# (b) BROKEN control — the offline VERIFIER no longer rejects a TAMPERED report. The REAL seam is
# ``verify.reverify.main`` (the SAME entry ``python3 -m framework.v2 verify`` dispatches to). Force it
# to accept everything (rc=0); the harness's tamper-rejection control must then FAIL -> blocked.
# ===================================================================================================


def test_broken_verify_accepts_tamper_blocks(loopback_port, monkeypatch):
    from framework.v2.verify import reverify as _reverify

    monkeypatch.setattr(_reverify, "main", lambda argv: 0)  # a verifier that passes a tampered report

    results, rc = run_acceptance(_hermetic_cfg(loopback_port))
    report = render_report(results)
    check2 = _by_key(results, "2")
    assert check2.status == FAIL, report
    assert check2.blocks is True
    assert "tamper" in check2.detail.lower()  # "a TAMPERED report re-verified (rc=0) — the verifier is not sound"
    assert rc != 0, report
    assert "HANDOVER BLOCKED" in report


# ===================================================================================================
# (b) BROKEN control — AEGIS is UN-ENTITLED while enforce is expected. The REAL seam is the entitlement
# policy the gateway consults at construction (``entitlement.policy.is_capability_available``); deny the
# AEGIS_RESPOND capability only. The gateway must then downgrade enforce->observe and the check FAIL ->
# blocked. (Only AEGIS_RESPOND is denied, so checks 2/4/6 — which need ACTIVE_RECON / DEEP_STATIC —
# still pass, isolating the failure to the entitlement under test.)
# ===================================================================================================


def test_broken_aegis_unentitled_blocks(loopback_port, monkeypatch):
    from framework.v2.entitlement import Capability
    from framework.v2.entitlement import policy as _policy

    real_avail = _policy.is_capability_available

    def _deny_aegis(capability):
        if capability == Capability.AEGIS_RESPOND:
            return False
        return real_avail(capability)

    monkeypatch.setattr(_policy, "is_capability_available", _deny_aegis)

    results, rc = run_acceptance(_hermetic_cfg(loopback_port))
    report = render_report(results)
    check5 = _by_key(results, "5")
    assert check5.status == FAIL, report
    assert check5.blocks is True
    assert "observe" in check5.detail.lower()  # "enforce is not active (downgraded to observe)"
    assert rc != 0, report
    assert "HANDOVER BLOCKED" in report


# ===================================================================================================
# (b) BROKEN control — the governed ENGAGE mints no FACT. The REAL seam is VIGIL's own gated transport
# re-drive (``live.transport_redrive.transport_redrive``), which performs the TCP handshake the
# SERVICE_REACHABILITY FACT rests on. Make it confirm nothing; the harness's engage->FACT check (and the
# HexStrike reachability check) must then FAIL -> blocked.
# ===================================================================================================


def test_broken_engage_mints_no_fact_blocks(loopback_port, monkeypatch):
    from vigil_integration.live import transport_redrive as _tr

    monkeypatch.setattr(_tr, "transport_redrive", lambda *a, **k: None)  # no handshake -> no FACT

    results, rc = run_acceptance(_hermetic_cfg(loopback_port))
    report = render_report(results)
    check2 = _by_key(results, "2")
    assert check2.status == FAIL, report
    assert check2.blocks is True
    assert "no signed fact" in check2.detail.lower()  # "the engage minted NO signed FACT against the bundled target"
    assert rc != 0, report
    assert "HANDOVER BLOCKED" in report


# ===================================================================================================
# A degenerate result set is itself a block (nothing was proven) — never a silent green.
# ===================================================================================================


def test_empty_results_block_by_construction():
    assert exit_code([]) == 1


# ===================================================================================================
# INVARIANT — importing/running the harness adds NO oracle: the unknown-class fallback stays frozen at 15.
# ===================================================================================================


def test_all_oracles_frozen_at_fifteen():
    from framework.v2.verify import verifier as V

    assert len(V._ALL_ORACLES) == 15, sorted(k.name for k in V._ALL_ORACLES)
    # and no duplicates crept in.
    assert len(V._ALL_ORACLES) == len(set(V._ALL_ORACLES))
