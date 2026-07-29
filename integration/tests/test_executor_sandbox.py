"""sandbox.exec — the GATED entry over the network-isolated bwrap sandbox (``executor.execute_sandbox``).

Mirrors the terminal governance tests with INJECTED seams (a fake ``run_sandbox``, a fake signer, a gate stub)
so the gate + signed-record path is exercised WITHOUT real bwrap or the framework: no signer ⇒ refuse; empty
command / no workspace ⇒ refuse; a gate deny (killswitch/scope) or a queue (no approval) ⇒ refuse; a missing
bwrap (SandboxUnavailable) / unsafe workspace (ValueError) ⇒ refuse (fail-closed, NO un-sandboxed fallback);
and only an ALLOWED command runs, producing a SIGNED record at the NEVER-auto A3 tier. Framework-free.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from vigil_integration.agent.state import Phase
from vigil_integration.live.executor import execute_sandbox
from vigil_integration.live.sandbox_exec import SandboxOutcome, SandboxUnavailable


def det_signer(data: bytes) -> str:
    return "sig-" + hashlib.sha256(data).hexdigest()[:24]


class FakeSandbox:
    """Records the command + workspace it was handed and echoes canned output — NEVER spawns bwrap."""

    def __init__(self, stdout="OK", stderr="", exit_code=0, raises=None):
        self.calls: list = []
        self.stdout, self.stderr, self.exit_code, self.raises = stdout, stderr, exit_code, raises

    def __call__(self, command, *, workspace, timeout, output_cap):
        self.calls.append((command, str(workspace)))
        if self.raises is not None:
            raise self.raises
        return SandboxOutcome(exit_code=self.exit_code, stdout=self.stdout, stderr=self.stderr)


def gate(outcome="allow", allowed=None, reason="ok"):
    def _g(tool_name, target, destructive):
        a = (outcome == "allow") if allowed is None else allowed
        return SimpleNamespace(outcome=outcome, allowed=a, reason=reason)
    return _g


_VIEW = {"sandbox.exec": [p.value for p in list(Phase)]}


def _run(command, *, g=None, run_sandbox=None, signer=det_signer, workspace="/tmp/ws", view=None):
    return execute_sandbox(
        command, Phase.INFORMATIONAL, workspace=workspace,
        gate=g if g is not None else gate(), view=view if view is not None else _VIEW,
        destructive_view={}, run_sandbox=run_sandbox if run_sandbox is not None else FakeSandbox(),
        signer=signer, seq=1, now=0)


def test_allowed_command_runs_signed_at_A3():
    fk = FakeSandbox(stdout="hello-from-box")
    res = _run("echo hi > out.txt", run_sandbox=fk)
    assert res.ran and res.outcome == "ran" and res.tier == "A3"     # A3 — the most-gated tier, never auto
    assert res.stdout == "hello-from-box"
    assert res.record is not None and res.signed                     # a signed ExecRecord was produced
    assert fk.calls == [("echo hi > out.txt", "/tmp/ws")]            # the command + workspace reached the box


def test_no_signer_refuses():
    res = _run("echo hi", signer=None)
    assert not res.ran and res.outcome == "deny" and "signer" in res.reason.lower()


def test_empty_command_and_no_workspace_refuse():
    assert not _run("   ").ran
    r = execute_sandbox("echo hi", Phase.INFORMATIONAL, workspace="", gate=gate(), view=_VIEW,
                        destructive_view={}, run_sandbox=FakeSandbox(), signer=det_signer, seq=1, now=0)
    assert not r.ran and "workspace" in r.reason.lower()


def test_gate_deny_and_queue_do_not_run():
    # a CRUCIBLE deny (out-of-scope / killswitch) is preserved; a queue without approval is not "allowed" —
    # either way the sandbox is NEVER reached.
    for verdict_gate in (gate(outcome="deny", allowed=False), gate(outcome="queue", allowed=False)):
        fk = FakeSandbox()
        res = _run("echo hi", g=verdict_gate, run_sandbox=fk)
        assert not res.ran and res.outcome == "deny"
        assert fk.calls == []


def test_missing_bwrap_fails_closed_no_fallback():
    res = _run("echo hi", run_sandbox=FakeSandbox(raises=SandboxUnavailable("no bwrap")))
    assert not res.ran and res.outcome == "deny" and "unavailable" in res.reason.lower()


def test_unsafe_workspace_fails_closed():
    res = _run("echo hi", run_sandbox=FakeSandbox(raises=ValueError("unsafe workspace")))
    assert not res.ran and res.outcome == "deny" and "workspace" in res.reason.lower()


def test_off_phase_command_is_refused():
    # sandbox.exec must be registered for the phase; an empty view (unregistered) denies at the phase gate.
    res = _run("echo hi", view={})
    assert not res.ran and res.outcome == "deny"


def test_runner_outage_is_captured_not_a_crash():
    # a GENERIC runner error (not SandboxUnavailable/ValueError) → a captured failure record, never a crash.
    res = _run("echo hi", run_sandbox=FakeSandbox(raises=RuntimeError("boom")))
    assert res.ran and res.exit_code is None and "runner error" in res.stderr.lower()
