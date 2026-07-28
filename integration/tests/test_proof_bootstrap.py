"""Proof Studio wiring (B5) — the bootstrap that ASSIGNS the proof_sink into a Strix process (proof.bootstrap).

``install`` must set ``strix.report.state.proof_sink`` to a sink that, on an allowed report carrying an
executor capture, mints + persists a proof record. ``install_from_env`` must be a NO-OP without the run
context env (so vendored Strix launched standalone is byte-identical).

Strix is faked in ``sys.modules`` (a bare ``strix.report.state`` with a ``proof_sink`` slot), so the test
needs no Strix runtime. The mint path is real → run with PYTHONPATH=integration:engine/crucible:gateway.
"""

from __future__ import annotations

import sys
import types

import pytest

from vigil_core import generate_keypair
from vigil_integration.proof.run import read_proofs
from vigil_integration.proof.sink import CAPTURE_KEY

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]


@pytest.fixture()
def fake_strix_state(monkeypatch):
    """Inject a minimal ``strix.report.state`` module (just the ``proof_sink`` slot bootstrap assigns)."""
    strix = types.ModuleType("strix")
    report = types.ModuleType("strix.report")
    state = types.ModuleType("strix.report.state")
    state.proof_sink = None
    strix.report = report
    report.state = state
    monkeypatch.setitem(sys.modules, "strix", strix)
    monkeypatch.setitem(sys.modules, "strix.report", report)
    monkeypatch.setitem(sys.modules, "strix.report.state", state)
    return state


def _captured_report(check_id="sqli-001", value=b"' OR '1'='1"):
    return {"id": check_id, "bug_class": "sqli_attempt", "poc_script_code": "print('benign')",
            CAPTURE_KEY: {"exchanges": [{"channel": "request_payload", "role": "q",
                                         "request_bytes_ref": "req", "bug_class": "sqli_attempt"}],
                          "blobs": {"req": value}}}


def test_install_assigns_a_sink_that_mints_and_persists(fake_strix_state, tmp_path):
    from vigil_integration.proof import bootstrap

    sink = bootstrap.install(run_dir=tmp_path, engagement_slug="acme", signers=SIGNERS)
    assert fake_strix_state.proof_sink is sink              # the hook is now assigned

    out = fake_strix_state.proof_sink(_captured_report())
    assert out.gate == "allow" and out.minted
    recs = read_proofs(tmp_path)
    assert len(recs) == 1 and recs[0]["status"] == "fact"


def test_install_from_env_is_a_noop_without_the_run_context(fake_strix_state, monkeypatch):
    from vigil_integration.proof import bootstrap

    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    assert bootstrap.install_from_env() is None
    assert fake_strix_state.proof_sink is None              # vendored Strix stays byte-identical


def test_install_from_env_installs_when_run_dir_is_set(fake_strix_state, tmp_path, monkeypatch):
    from vigil_integration.proof import bootstrap

    # explicit signers via a monkeypatched _run_signers keeps the test off the authority-provisioning path
    monkeypatch.setattr(bootstrap, "_run_signers", lambda *a, **k: SIGNERS)
    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("VIGIL_ENGAGEMENT", "acme")
    assert bootstrap.install_from_env() is not None
    out = fake_strix_state.proof_sink(_captured_report())
    assert out.minted and len(read_proofs(tmp_path)) == 1
