"""
Tests for vigil_integration.live.executor (VIGIL-LIVE WS1a): the GOVERNED live Kali-tool executor.

The executor spawns a real tool ONLY behind two conjunctive gates — (a) the target resolves to IPv4
loopback (127.0.0.0/8), and (b) the injected conjunctive gate allows — plus a signed, redacted spine
record of every run. These tests inject a FAKE ``run`` (echo, never a real tool), a FAKE gate, and a
deterministic signer, so nothing here spawns nmap/hydra/etc.

The explicit adversarial test of the sovereign invariant is ``test_SOVEREIGN_INVARIANT_*`` — it is the
exact surface the red-pen attacks: no subprocess reaches a non-loopback host even when the gate allows
and the target smuggles a second host; and the gate alone can never run a non-loopback target either.
"""

from __future__ import annotations

import itertools
import socket

import pytest
from types import SimpleNamespace

from vigil_integration.agent.state import Phase
from vigil_integration.live.executor import (
    ExecRecord,
    ExecResult,
    RunOutcome,
    execute,
)


# --- injected primitives (deterministic: no wallclock, no RNG) ----------------------------------


def make_seq():
    counter = itertools.count(1)
    return lambda: next(counter)


def det_signer(data: bytes) -> str:
    """Deterministic stand-in for the injected Ed25519 signer (pure function of the record bytes)."""
    import hashlib
    return "sig-" + hashlib.sha256(data).hexdigest()[:24]


class FakeRun:
    """A fake runner: records the argv it was handed and echoes a canned stdout. NEVER spawns anything."""

    def __init__(self, stdout: str = "OK", stderr: str = "", exit_code: int = 0, raises: bool = False):
        self.calls: list[list[str]] = []
        self.stdout, self.stderr, self.exit_code, self.raises = stdout, stderr, exit_code, raises

    def __call__(self, argv, *, timeout, output_cap):
        self.calls.append(list(argv))
        if self.raises:
            raise RuntimeError("boom")
        return RunOutcome(exit_code=self.exit_code, stdout=self.stdout, stderr=self.stderr)


def gate(outcome="allow", allowed=None, reason="ok", raises=False):
    def _g(tool_name, target, destructive):
        if raises:
            raise RuntimeError("gate boom")
        a = (outcome == "allow") if allowed is None else allowed
        return SimpleNamespace(outcome=outcome, allowed=a, reason=reason)
    return _g


def full_view():
    """A permissive phase-view: every tested tool registered in every phase (the phase gate is not what
    these tests exercise — the loopback pin and the conjunctive gate are)."""
    phases = [p.value for p in Phase]
    return {t: list(phases) for t in ("nmap", "nuclei", "httpx", "ffuf", "sqlmap", "hydra")}


def dview():
    return {"nmap": False, "httpx": False, "nuclei": True, "ffuf": False, "sqlmap": True, "hydra": True}


def run_exec(tool, args, phase=Phase.INFORMATIONAL, *, g=None, run=None, signer=det_signer,
             view=None, seq=None):
    return execute(tool, args, phase, gate=g if g is not None else gate(), view=view or full_view(),
                   destructive_view=dview(), run=run if run is not None else FakeRun(),
                   signer=signer, seq=(seq or make_seq())(), now=7)


# ================================================================================================
# happy path: a loopback target under an allowing gate runs, is pinned, and is recorded (signed)
# ================================================================================================


def test_loopback_ip_runs_and_pins_host():
    fr = FakeRun(stdout="Nmap scan report for 127.0.0.1")
    res = run_exec("nmap", {"target": "127.0.0.1:18080"}, run=fr)
    assert res.ran is True and res.outcome == "ran"
    assert fr.calls, "the runner must have been invoked"
    argv = fr.calls[0]
    assert argv[0] == "nmap" and "127.0.0.1" in argv and "18080" in argv
    assert res.signed is True and isinstance(res.record, ExecRecord)
    assert res.record.signature.startswith("sig-")
    assert res.record.tool == "nmap" and res.record.target == "127.0.0.1:18080"


def test_localhost_url_httpx_pins_loopback_url():
    fr = FakeRun()
    res = run_exec("httpx", {"url": "http://127.0.0.1:18080/app?x=1"}, run=fr)
    assert res.ran is True
    argv = fr.calls[0]
    assert argv[0] == "httpx"
    url = argv[argv.index("-u") + 1]
    assert url.startswith("http://127.0.0.1:18080/") and url.endswith("?x=1")


def test_record_commits_to_raw_output_hash():
    fr = FakeRun(stdout="banner\nline2")
    res = run_exec("httpx", {"url": "http://127.0.0.1:18080/"}, run=fr)
    import hashlib
    assert res.record.stdout_sha256 == hashlib.sha256(b"banner\nline2").hexdigest()
    # the RAW output is returned for the oracle
    assert res.stdout == "banner\nline2"


# ================================================================================================
# the loopback pin — non-loopback / metadata / smuggle all DENY before any subprocess
# ================================================================================================


@pytest.mark.parametrize("target", [
    "8.8.8.8",                       # public
    "http://93.184.216.34/",         # public (literal, no DNS)
    "10.0.0.5:8080",                 # RFC1918 private
    "169.254.169.254",               # cloud metadata (IMDS)
    "http://169.254.169.254/latest/meta-data/",
    "[::1]:18080",                   # IPv6 loopback — outside the IPv4 127.0.0.0/8 pin
])
def test_non_loopback_targets_denied_before_spawn(target):
    fr = FakeRun()
    res = run_exec("nmap", {"target": target}, run=fr)
    assert res.ran is False and res.outcome == "deny"
    assert not fr.calls, "no subprocess may spawn for a non-loopback target"
    assert res.record is None


def test_metadata_deny_reason_from_denylist():
    res = run_exec("httpx", {"url": "http://169.254.169.254/"})
    assert res.ran is False
    assert "always-denied" in res.reason or "metadata" in res.reason.lower()


@pytest.mark.parametrize("target", [
    "",                              # empty
    "127.0.0.1:notaport",            # malformed port
    "127.0.0.1 evil.com",            # space-smuggled second host → unresolvable
])
def test_malformed_or_unresolvable_targets_denied(target):
    fr = FakeRun()
    res = run_exec("nmap", {"target": target}, run=fr)
    assert res.ran is False and not fr.calls


def test_unresolvable_host_denied_no_network(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("no resolution")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    fr = FakeRun()
    res = run_exec("nmap", {"target": "some-host.example"}, run=fr)
    assert res.ran is False and not fr.calls


# ================================================================================================
# the gate leg — deny / None / exception all block the spawn (fail-closed)
# ================================================================================================


def test_gate_deny_blocks_spawn():
    fr = FakeRun()
    res = execute("nmap", {"target": "127.0.0.1:18080"}, Phase.INFORMATIONAL,
                  gate=gate(outcome="deny", allowed=False, reason="warden nope"),
                  view=full_view(), destructive_view=dview(), run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and res.outcome == "deny" and not fr.calls
    assert "authorization denied" in res.reason


def test_no_gate_wired_blocks_spawn():
    fr = FakeRun()
    res = execute("nmap", {"target": "127.0.0.1:18080"}, Phase.INFORMATIONAL,
                  gate=None, view=full_view(), destructive_view=dview(), run=fr, signer=det_signer,
                  seq=1, now=0)
    assert res.ran is False and not fr.calls


def test_gate_exception_blocks_spawn():
    fr = FakeRun()
    res = execute("nmap", {"target": "127.0.0.1:18080"}, Phase.INFORMATIONAL,
                  gate=gate(raises=True), view=full_view(), destructive_view=dview(), run=fr,
                  signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls


def test_out_of_phase_tool_denied():
    fr = FakeRun()
    # sqlmap registered only in exploitation; call it in informational → phase gate denies pre-gate
    view = {"sqlmap": [Phase.EXPLOITATION.value]}
    res = execute("sqlmap", {"url": "http://127.0.0.1:18080/"}, Phase.INFORMATIONAL,
                  gate=gate(), view=view, destructive_view=dview(), run=fr, signer=det_signer,
                  seq=1, now=0)
    assert res.ran is False and not fr.calls


# ================================================================================================
# no signer wired → refuse to run an unrecordable call, BEFORE any spawn
# ================================================================================================


def test_no_signer_refuses_before_spawn():
    fr = FakeRun()
    res = execute("nmap", {"target": "127.0.0.1:18080"}, Phase.INFORMATIONAL, gate=gate(),
                  view=full_view(), destructive_view=dview(), run=fr, signer=None, seq=1, now=0)
    assert res.ran is False and not fr.calls
    assert "no signer" in res.reason


# ================================================================================================
# destructive tools stay behind the m-of-n leg (flagged; gate is the authority)
# ================================================================================================


def test_destructive_tool_flagged_and_gated():
    fr = FakeRun()
    # gate DENIES (simulating an unmet m-of-n) → no spawn, but requires_quorum is surfaced
    res = execute("sqlmap", {"url": "http://127.0.0.1:18080/x?id=1"}, Phase.EXPLOITATION,
                  gate=gate(outcome="deny", allowed=False), view=full_view(), destructive_view=dview(),
                  run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls
    assert res.destructive is True and res.requires_quorum is True and res.tier == "A3"


def test_destructive_tool_runs_when_gate_allows():
    fr = FakeRun()
    res = execute("sqlmap", {"url": "http://127.0.0.1:18080/x?id=1", "level": 2, "risk": 2},
                  Phase.EXPLOITATION, gate=gate(), view=full_view(), destructive_view=dview(),
                  run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is True and res.destructive is True
    argv = fr.calls[0]
    assert argv[0] == "sqlmap" and "--batch" in argv and "--level" in argv and "--risk" in argv


# ================================================================================================
# redaction — the signed record leaks NO secret; the RAW output still reaches the oracle
# ================================================================================================


def test_hydra_inline_password_masked_in_record(tmp_path):
    fr = FakeRun(stdout="[80][http-get] host: 127.0.0.1   login: admin   password: hunter2")
    res = execute("hydra", {"target": "127.0.0.1:18080", "service": "http-get",
                            "username": "admin", "password": "s3cr3t-pw"},
                  Phase.EXPLOITATION, gate=gate(), view=full_view(), destructive_view=dview(),
                  run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is True
    # the raw argv handed to the runner contains the real password (it must, to actually run)
    assert "s3cr3t-pw" in fr.calls[0]
    # but the RECORD's argv masks it
    assert "s3cr3t-pw" not in " ".join(res.record.argv)
    assert "••••" in res.record.argv
    # a found-password line in stdout is redacted in the record but RAW for the oracle
    assert "hunter2" not in res.record.stdout
    assert "hunter2" in res.stdout


def test_output_bearer_token_redacted_in_record():
    fr = FakeRun(stdout="Authorization: Bearer sk-abc123SECRETtoken")
    res = run_exec("httpx", {"url": "http://127.0.0.1:18080/"}, run=fr)
    assert "sk-abc123SECRETtoken" not in res.record.stdout   # redacted on the spine
    assert "sk-abc123SECRETtoken" in res.stdout               # raw for the oracle


def test_url_query_secret_redacted_in_record_argv():
    fr = FakeRun()
    res = run_exec("httpx", {"url": "http://127.0.0.1:18080/cb?token=abc123def456"}, run=fr)
    joined = " ".join(res.record.argv)
    assert "abc123def456" not in joined


# ================================================================================================
# totality — malformed input never raises; unknown tools + bad builder args deny
# ================================================================================================


@pytest.mark.parametrize("tool,args", [
    (None, {"target": "127.0.0.1"}),
    ("", {"target": "127.0.0.1"}),
    ("nmap", "not-a-dict"),
    ("nmap", {"target": 12345}),
    ("nmap", {"nope": "no target here"}),
    ("kali_shell", {"target": "127.0.0.1"}),   # unknown tool → no builder → deny
    ("nmap", {"target": "127.0.0.1", "ports": "99999999"}),  # invalid port spec ignored, still runs host
])
def test_total_on_malformed_input(tool, args):
    fr = FakeRun()
    res = execute(tool, args, Phase.INFORMATIONAL, gate=gate(), view=full_view(),
                  destructive_view=dview(), run=fr, signer=det_signer, seq=1, now=0)
    assert isinstance(res, ExecResult)   # never raised


def test_ffuf_requires_wordlist_file(tmp_path):
    fr = FakeRun()
    # no wordlist → builder refuses → deny, no spawn
    res = execute("ffuf", {"url": "http://127.0.0.1:18080/"}, Phase.EXPLOITATION, gate=gate(),
                  view=full_view(), destructive_view=dview(), run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls
    # a real local wordlist → runs with FUZZ appended
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nlogin\n")
    fr2 = FakeRun()
    res2 = execute("ffuf", {"url": "http://127.0.0.1:18080/", "wordlist": str(wl)},
                   Phase.EXPLOITATION, gate=gate(), view=full_view(), destructive_view=dview(),
                   run=fr2, signer=det_signer, seq=1, now=0)
    assert res2.ran is True
    argv = fr2.calls[0]
    assert "FUZZ" in argv[argv.index("-u") + 1] and str(wl) in argv


def test_ffuf_rejects_url_as_wordlist():
    fr = FakeRun()
    res = execute("ffuf", {"url": "http://127.0.0.1:18080/", "wordlist": "http://evil.com/wl.txt"},
                  Phase.EXPLOITATION, gate=gate(), view=full_view(), destructive_view=dview(),
                  run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls


def test_runner_exception_does_not_crash():
    fr = FakeRun(raises=True)
    res = run_exec("httpx", {"url": "http://127.0.0.1:18080/"}, run=fr)
    # the gates passed and we invoked the runner; its failure degrades to a recorded no-output result
    assert res.ran is True and res.exit_code is None
    assert "runner error" in res.stderr and isinstance(res.record, ExecRecord)


# ================================================================================================
# THE SOVEREIGN INVARIANT — the red-pen's target
# ================================================================================================


# All smuggle hosts are NUMERIC (or malformed) so no DNS/network is needed: the userinfo trick makes the
# REAL host the numeric non-loopback one after '@'; the space/tab cases fail resolution outright.
@pytest.mark.parametrize("smuggle", [
    "http://127.0.0.1@169.254.169.254/",    # userinfo trick → real host is metadata (IMDS)
    "http://127.0.0.1@1.1.1.1/",            # userinfo → real host is public (numeric)
    "http://127.0.0.1@10.0.0.9/",           # userinfo → real host is RFC1918 private
    "127.0.0.1 evil.com",                   # space-separated second host → unresolvable
    "127.0.0.1\tevil.com",                  # tab-separated second host → unresolvable
])
def test_SOVEREIGN_INVARIANT_smuggled_second_host_never_spawns(smuggle):
    """Even with the gate WIDE OPEN, a target that smuggles a second (non-loopback) host must never reach
    a subprocess — the argv builder is never even called because the loopback pin refuses first, and no
    argv can name evil.com because the host is pinned from the VALIDATED resolution."""
    fr = FakeRun()
    res = execute("httpx", {"url": smuggle}, Phase.INFORMATIONAL, gate=gate(outcome="allow", allowed=True),
                  view=full_view(), destructive_view=dview(), run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and res.outcome == "deny"
    assert not fr.calls, "a smuggled second host must never spawn a subprocess"
    assert res.record is None


def test_SOVEREIGN_INVARIANT_gate_allow_cannot_run_non_loopback():
    """An allowing gate is necessary but NOT sufficient: a non-loopback target is refused BEFORE the gate
    is even consulted, so gate=allow can never by itself run a public target."""
    fr = FakeRun()
    res = execute("nmap", {"target": "8.8.8.8"}, Phase.INFORMATIONAL, gate=gate(outcome="allow", allowed=True),
                  view=full_view(), destructive_view=dview(), run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls


def test_SOVEREIGN_INVARIANT_loopback_pass_needs_both_gates():
    """The dual-gate truth table on a genuine loopback target: only (loopback AND gate-allow) spawns."""
    tgt = {"target": "127.0.0.1:18080"}
    # loopback + allow → runs
    fr1 = FakeRun()
    r1 = execute("nmap", tgt, Phase.INFORMATIONAL, gate=gate(allowed=True), view=full_view(),
                 destructive_view=dview(), run=fr1, signer=det_signer, seq=1, now=0)
    assert r1.ran is True and fr1.calls
    # loopback + deny → no spawn
    fr2 = FakeRun()
    r2 = execute("nmap", tgt, Phase.INFORMATIONAL, gate=gate(outcome="deny", allowed=False),
                 view=full_view(), destructive_view=dview(), run=fr2, signer=det_signer, seq=1, now=0)
    assert r2.ran is False and not fr2.calls


def test_no_shell_argv_is_a_list():
    """The runner is only ever handed an argv LIST — never a shell string; there is no interpolation."""
    fr = FakeRun()
    run_exec("nmap", {"target": "127.0.0.1:18080"}, run=fr)
    assert isinstance(fr.calls[0], list) and all(isinstance(a, str) for a in fr.calls[0])
