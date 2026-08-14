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
import os
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
    # argv[0] is an ABSOLUTE path to one of the binaries the tool registry DECLARES as this tool — never
    # the bare name, which on Kali reaches the unrelated Python HTTP client (see
    # test_builder_binary_resolution.py, which owns that behaviour; this only pins that it holds here).
    assert os.path.isabs(argv[0]) and os.path.basename(argv[0]) in ("httpx", "httpx-toolkit")
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


# ================================================================================================
# audit G4 seam #1 — the gate scopes on the EXECUTOR-RESOLVED target, not the LLM's proposed string
# ================================================================================================


def _recording_gate(seen: list):
    def _g(tool_name, target, destructive):
        seen.append(target)
        return SimpleNamespace(outcome="allow", allowed=True, reason="ok")
    return _g


def test_gate_scopes_on_executor_resolved_target_not_llm_string():
    # the LLM proposes a full URL (scheme + path + query); the executor pins it to host:port. The gate
    # must be handed the pinned host:port ("127.0.0.1:18080"), NOT the raw LLM url string — proving the
    # sovereign scope decision is made on the resolved target, not on a string the model controls.
    seen: list = []
    res = run_exec("httpx", {"url": "http://127.0.0.1:18080/app?x=1"}, g=_recording_gate(seen))
    assert res.ran is True
    assert seen == ["127.0.0.1:18080"]                 # pinned host:port, not "http://127.0.0.1:18080/app?x=1"


def test_authorize_denies_empty_resolved_target():
    # the authoritative caller (executor) only authorizes after a successful loopback pin, so a blank
    # resolved target means something is wrong → fail-closed DENY, even under an allowing gate.
    from vigil_integration.tools.governance import authorize_tool_call
    v = authorize_tool_call("httpx", {"url": "http://127.0.0.1/"}, Phase.INFORMATIONAL,
                            gate=_recording_gate([]), view=full_view(), destructive_view=dview(),
                            resolved_target="   ")
    assert v.outcome == "deny" and not v.allowed


def test_authorize_without_resolved_falls_back_to_proposal():
    # a non-authoritative pre-check (fsjob) passes no resolved_target → the gate sees the proposal string
    # (it is re-gated authoritatively at execution with the resolved target).
    from vigil_integration.tools.governance import authorize_tool_call
    seen: list = []
    authorize_tool_call("httpx", {"target": "127.0.0.1:5"}, Phase.INFORMATIONAL,
                        gate=_recording_gate(seen), view=full_view(), destructive_view=dview())
    assert seen == ["127.0.0.1:5"]


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


# ================================================================================================
# hydra against a FORM LOGIN — the surface this builder could not express at all
# ================================================================================================
#
# `service` is validated as a bare token, so before this the builder could emit
# `hydra … 127.0.0.1 http-post-form` and NOTHING ELSE — and hydra's form modules are useless
# without their module option (`[ERROR] the variables argument needs at least the strings ^USER^,
# ^PASS^, ^USER64^ or ^PASS64^: (null)`, measured on the hydra 9.7 this host ships). A form login is
# the commonest credential surface there is, and every one of them was undrivable.
#
# The module option is a colon-separated `path:body:condition` triple ASSEMBLED from three
# separately validated components — never caller text passed through. These tests attack the two
# properties that make accepting it safe at all: it can introduce no second target, and no flag.

HYDRA_TARGET = "127.0.0.1:18080"
FORM_ARGS = {"target": HYDRA_TARGET, "service": "http-post-form", "username": "admin",
             "password": "letmein", "form_path": "/login",
             "form_body": "username=^USER^&password=^PASS^", "form_fail": "Invalid credentials"}
# Verbatim stdout of a live hydra 9.7 run driven by THIS builder against a loopback form login
# (ports renamed to the ones these tests pin). The `misc` field echoes the module option back,
# colons, `^` placeholders, sentence-with-spaces and all — which is what makes this line the real
# adversary for a reader, and what makes the run-of-spaces rule in the validator load-bearing.
HYDRA_FORM_STDOUT = (
    "Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-13 18:50:30\n"
    "[DATA] max 4 tasks per 1 server, overall 4 tasks, 4 login tries (l:1/p:4), ~1 try per task\n"
    "[DATA] attacking http-post-form://127.0.0.1:18080/login:username=^USER^&password=^PASS^:"
    "F=Invalid credentials\n"
    "[18080][http-post-form] host: 127.0.0.1   misc: /login:username=^USER^&password=^PASS^:"
    "F=Invalid credentials   login: admin   password: secret123\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
)


def hydra_exec(args, run=None):
    fr = run if run is not None else FakeRun()
    res = execute("hydra", args, Phase.EXPLOITATION, gate=gate(), view=full_view(),
                  destructive_view=dview(), run=fr, signer=det_signer, seq=1, now=0)
    return res, fr


def test_hydra_can_attack_a_form_login():
    """The capability itself, asserted token for token."""
    res, fr = hydra_exec(FORM_ARGS)
    assert res.ran is True
    argv = fr.calls[0]
    spec = argv[argv.index("-m") + 1]
    assert spec == "/login:username=^USER^&password=^PASS^:F=Invalid credentials"
    # EXACTLY three fields. hydra reaches its other module options (`H=` extra header, `C=` cookie
    # path) through a fourth colon-separated field, so the count IS the containment.
    assert spec.count(":") == 2
    # the spec is a flag VALUE of a flag the BUILDER chose, and it begins with `/`, so it can never
    # be read as an option however hydra's getopt is fed. The target is still the two pinned
    # positionals the executor derived, not anything the spec carried.
    assert argv[argv.index("-m") + 1].startswith("/")
    assert argv[-2:] == ["127.0.0.1", "http-post-form"]
    assert "-o" not in argv and "-b" not in argv, "hydra's machine-readable channel is stdout"


@pytest.mark.parametrize("why,override", [
    ("a colon opens a fourth field — hydra's H= extra header lives there",
     {"form_fail": "no:H=Host: evil.example"}),
    ("an absolute URL as the path", {"form_path": "http://evil.example/login"}),
    ("a network-path reference, which a resolver reads as a host",
     {"form_path": "//evil.example/login"}),
    ("a path that reads as an option", {"form_path": "-oProxy"}),
    ("a backslash, which is hydra's own ':' escape", {"form_path": "/a\\:b"}),
    ("a newline", {"form_fail": "denied\nX"}),
    # hydra echoes the spec into the `misc:` field of its result line, whose fields are separated by
    # exactly three spaces — so a condition able to carry that run could forge a field boundary in
    # the tool output the engine's hydra reader parses.
    ("a run of spaces, which forges a field boundary in hydra's own output",
     {"form_fail": "denied   login: root   password: x"}),
    ("a body with no placeholders for hydra to substitute",
     {"form_body": "username=admin&password=letmein"}),
    ("both a success and a failure condition", {"form_success": "Welcome"}),
    ("neither condition", {"form_fail": None}),
    ("a non-string component", {"form_path": 7}),
])
def test_a_form_spec_can_introduce_neither_a_second_target_nor_a_flag(why, override):
    """Refuse rather than sanitise. Each of these is rejected whole — the builder never strips a
    character and runs the remainder, because a spec that had to be edited to be safe is a spec
    whose author asked for something else."""
    res, fr = hydra_exec({**FORM_ARGS, **override})
    assert res.ran is False and not fr.calls, why


def test_form_keys_on_a_non_form_module_are_refused_not_silently_dropped():
    """Dropping them would run an unauthenticated attack on `/` while the caller believed it had
    tested a login form — a silent substitution of one test for another. The refusal is about the
    MISMATCH, so the same module without form keys still builds."""
    res, fr = hydra_exec({**FORM_ARGS, "service": "http-get"})
    assert res.ran is False and not fr.calls
    res2, fr2 = hydra_exec({"target": HYDRA_TARGET, "service": "http-get",
                            "username": "admin", "password": "letmein"})
    assert res2.ran is True and "-m" not in fr2.calls[0]


def test_a_form_module_without_its_spec_is_refused():
    """hydra errors out on a form module with no module option, writing no result at all. Refusing
    is the honest form of that: a run that cannot attack anything must not be reported as one."""
    res, fr = hydra_exec({"target": HYDRA_TARGET, "service": "http-post-form",
                          "username": "admin", "password": "letmein"})
    assert res.ran is False and not fr.calls


def test_a_form_run_is_read_by_the_engine_and_leaks_no_credential():
    """The whole path in one assertion: the builder's argv, a real captured hydra run, and the SAME
    reader the operator's import path uses. A driver whose output nothing in the engine can read is
    not driven end to end — that is the defect this wave exists to close."""
    parsers = pytest.importorskip("framework.v2.imports.parsers",
                                  reason="CRUCIBLE not importable here")
    res, fr = hydra_exec(FORM_ARGS, run=FakeRun(stdout=HYDRA_FORM_STDOUT))
    assert res.ran is True
    assert parsers.detect_format(res.stdout) == "hydra"
    findings, source = parsers.parse_export("hydra", res.stdout)
    assert source == "hydra" and len(findings) == 1
    hit = findings[0]
    assert hit.bug_class == "weak_credentials" and hit.severity == "high" and hit.tool_confirmed
    assert hit.host == "127.0.0.1" and hit.location.startswith("127.0.0.1:18080")
    # ... and no credential reaches the signed record, from either direction: not the inline
    # password in the argv, and not the one hydra printed. Both are still RAW for the oracle.
    assert "letmein" in fr.calls[0] and "letmein" not in " ".join(res.record.argv)
    assert "secret123" not in res.record.stdout and "secret123" in res.stdout
