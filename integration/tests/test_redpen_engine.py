"""R1 — the Red-Pen reproduction engine orchestrator (redpen.engine).

Doctrine under test (design §7.2, decision O-1):
  * with VIGIL_REDPEN_ENABLED off the engine is INERT and byte-identically absent — the reviewer is never
    consulted, the sandbox is never touched, nothing is minted;
  * a candidate reproduced TWICE in the sandbox becomes a signed FACT from the O-1 oracle set;
  * a candidate that fires once, or never, is a LEAD — never a FACT;
  * a lens whose reviewer RAISES is logged and SKIPPED; it never aborts the run and never promotes;
  * the engine only ever asks the firewall with provenance="reproduced" (no LLM route to a FACT);
  * the whole pipeline makes NO network connection.

Needs framework for the FACT path (confirm_and_certify) → tw.sh off / offense venv.
"""

from __future__ import annotations

import socket

import pytest

pytest.importorskip("framework.v2.verify.poc_translate")

from vigil_core import generate_keypair  # noqa: E402
from vigil_integration.live.sandbox_exec import SandboxOutcome  # noqa: E402
from vigil_integration.redpen import (  # noqa: E402
    LensCandidate,
    LensResponse,
    run_redpen,
)

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]

_SQLI = LensCandidate(
    lens="injection", bug_class="sqli_attempt", channel="request_payload", poc_command="python poc.py",
    fire_markers=("SINK_REACHED",), request_value="' OR '1'='1", param="q", severity="high",
    finding_ref="rp-sqli-1")


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    """Default the flag ON for the pipeline tests; the inert test overrides it OFF."""
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")


def _fire(_cmd):
    return SandboxOutcome(exit_code=0, stdout="SINK_REACHED at db.execute", stderr="")


def _reviewer_for(candidate, lens="injection"):
    def review(req):
        return LensResponse(candidates=(candidate,)) if req.lens == lens else LensResponse(candidates=())
    return review


def test_flag_off_is_inert_and_the_reviewer_is_never_called(monkeypatch, tmp_path):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    calls = {"n": 0}

    def review(_req):
        calls["n"] += 1
        return LensResponse(candidates=(_SQLI,))

    def sandbox(_cmd):
        raise AssertionError("sandbox must not run when the flag is off")

    report = run_redpen(checkout_path=str(tmp_path), changed_paths=["x.py"], reviewer=review,
                        engagement_slug="acme", signers=SIGNERS, sandbox=sandbox)
    assert report.enabled is False
    assert report.facts == () and report.leads == () and report.skipped_lenses == ()
    assert report.candidates_seen == 0
    assert calls["n"] == 0                              # the model seam was never consulted


def test_a_candidate_reproduced_twice_becomes_a_signed_fact(tmp_path):
    report = run_redpen(checkout_path=str(tmp_path), changed_paths=["x.py"],
                        reviewer=_reviewer_for(_SQLI), engagement_slug="acme", signers=SIGNERS,
                        sandbox=_fire, lenses=("injection",))
    assert report.enabled is True and len(report.facts) == 1 and len(report.leads) == 0
    fact = report.facts[0]
    assert fact.confirmed_by == "sql_injection_breakout" and fact.signed is not None
    assert fact.severity == "high" and fact.lens == "injection"


def test_a_candidate_that_fires_once_is_a_lead_not_a_fact(tmp_path):
    seq = {"n": 0}

    def once(_cmd):
        seq["n"] += 1
        return SandboxOutcome(exit_code=0, stdout=("SINK_REACHED" if seq["n"] == 1 else "quiet"), stderr="")

    report = run_redpen(checkout_path=str(tmp_path), changed_paths=["x.py"],
                        reviewer=_reviewer_for(_SQLI), engagement_slug="acme", signers=SIGNERS,
                        sandbox=once, lenses=("injection",))
    assert len(report.facts) == 0 and len(report.leads) == 1
    assert report.leads[0].outcome == "not_reproduced"


def test_a_candidate_that_never_fires_is_a_lead(tmp_path):
    def quiet(_cmd):
        return SandboxOutcome(exit_code=0, stdout="nothing happened", stderr="")

    report = run_redpen(checkout_path=str(tmp_path), changed_paths=["x.py"],
                        reviewer=_reviewer_for(_SQLI), engagement_slug="acme", signers=SIGNERS,
                        sandbox=quiet, lenses=("injection",))
    assert len(report.facts) == 0 and len(report.leads) == 1


def test_a_lens_that_raises_is_skipped_and_never_aborts_or_promotes(tmp_path):
    def review(req):
        if req.lens == "injection":
            raise RuntimeError("lens boom")
        return LensResponse(candidates=())

    # Two lenses: the first raises (skipped), the engine still runs the second and returns normally.
    report = run_redpen(checkout_path=str(tmp_path), changed_paths=["x.py"], reviewer=review,
                        engagement_slug="acme", signers=SIGNERS, sandbox=_fire,
                        lenses=("injection", "crypto_secrets"))
    assert report.enabled is True
    assert len(report.facts) == 0                       # a raised lens promotes NOTHING
    assert len(report.skipped_lenses) == 1 and report.skipped_lenses[0].lens == "injection"
    assert "RuntimeError" in report.skipped_lenses[0].reason


def test_the_engine_only_asks_the_firewall_with_reproduced_provenance(tmp_path):
    seen = {}

    class _Res:
        is_fact = True
        confirmed_by = "sql_injection_breakout"
        bug_class = "sqli_attempt"
        finding_ref = "rp-sqli-1"
        reason = "ok"
        confidence = 1.0
        outcome = "positive"
        signed = object()

    def spy_confirm(_finding, *, provenance, **_kw):
        seen["provenance"] = provenance                 # capture what the engine forwards
        return _Res()

    report = run_redpen(checkout_path=str(tmp_path), changed_paths=["x.py"],
                        reviewer=_reviewer_for(_SQLI), engagement_slug="acme", signers=SIGNERS,
                        sandbox=_fire, confirm=spy_confirm, lenses=("injection",))
    assert seen.get("provenance") == "reproduced"       # never "llm" — no LLM route to a FACT
    assert len(report.facts) == 1


def test_the_pipeline_makes_no_network_connection(tmp_path, monkeypatch):
    # A hard guard: any socket connect during the run fails the test. The reviewer + sandbox are injected,
    # and confirm_and_certify re-fires offline, so a reproduced FACT is produced with zero network I/O.
    def _blocked(*_a, **_k):
        raise AssertionError("the red-pen pipeline must make no network connection")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)

    report = run_redpen(checkout_path=str(tmp_path), changed_paths=["x.py"],
                        reviewer=_reviewer_for(_SQLI), engagement_slug="acme", signers=SIGNERS,
                        sandbox=_fire, lenses=("injection",))
    assert len(report.facts) == 1                       # completed, and the guard never fired
