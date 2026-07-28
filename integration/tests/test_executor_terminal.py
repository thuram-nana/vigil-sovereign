"""
T1 — the GOVERNED LOCAL terminal (``vigil_integration.live.executor.execute_terminal``).

``execute`` is a target-PINNED network-tool runner: its IP-pin is the never-liftable egress floor.
``execute_terminal`` has NO network target, so the floor is preserved BY CONSTRUCTION instead — the
allowlist admits ONLY local, non-network, non-interpreter, non-writer read/inspect utilities, so a terminal
command cannot make network egress or mutate the host. These tests prove that argument and the fail-closed
pipeline: no signer ⇒ refuse; any shell metacharacter ⇒ refuse; an off-allowlist binary ⇒ refuse; an unsafe
``find`` predicate ⇒ refuse; a kill-switch / gate deny ⇒ refuse; and only an allowlisted command under a
signer + an allowing gate runs, producing a SIGNED record at a NEVER-auto (A2/A3) tier.

They inject a FAKE ``run`` (an echo, never a real spawn), a FAKE signer, and a permissive gate stub —
exactly as ``test_live_executor.py`` / ``test_executor_scoped.py`` do, so nothing here spawns a process.

Run: PYTHONPATH=integration:engine/crucible:gateway pytest integration/tests/test_executor_terminal.py -q
"""

from __future__ import annotations

import hashlib
import itertools
from types import SimpleNamespace

import pytest

from vigil_integration.agent.state import Phase
from vigil_integration.live.executor import (
    _TERMINAL_ALLOWLIST,
    _TERMINAL_DENY_FLAGS,
    ExecRecord,
    ExecResult,
    RunOutcome,
    execute_terminal,
)


# --- injected primitives (deterministic: no wallclock, no RNG) ----------------------------------


def make_seq():
    counter = itertools.count(1)
    return lambda: next(counter)


def det_signer(data: bytes) -> str:
    """Deterministic stand-in for the injected Ed25519 signer (pure function of the record bytes)."""
    return "sig-" + hashlib.sha256(data).hexdigest()[:24]


class FakeRun:
    """A fake runner: records the argv + cwd it was handed and echoes a canned stdout. NEVER spawns."""

    def __init__(self, stdout: str = "OK", stderr: str = "", exit_code: int = 0, raises: bool = False):
        self.calls: list[list[str]] = []
        self.cwds: list = []
        self.stdout, self.stderr, self.exit_code, self.raises = stdout, stderr, exit_code, raises

    def __call__(self, argv, *, timeout, output_cap, cwd=None):
        self.calls.append(list(argv))
        self.cwds.append(cwd)
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


def _view(phases=None):
    """Register terminal.run for the given phases (default: every phase)."""
    return {"terminal.run": [p.value for p in (phases or list(Phase))]}


def run_term(command, phase=Phase.INFORMATIONAL, *, g=None, run=None, signer=det_signer, view=None,
             cwd=None, seq=None):
    return execute_terminal(command, phase, gate=g if g is not None else gate(),
                            view=view if view is not None else _view(),
                            destructive_view={}, run=run if run is not None else FakeRun(),
                            signer=signer, seq=(seq or make_seq())(), now=7, cwd=cwd)


# ================================================================================================
# THE EGRESS-FLOOR ARGUMENT — no allowlist binary can make network egress or mutate the host
# ================================================================================================


def test_allowlist_is_exactly_the_curated_local_read_inspect_set():
    # The whole safety argument for skipping the IP-pin: the allowlist is a CLOSED, curated set of local
    # read/inspect utilities. Pin it exactly so a future edit that adds an egressing/interpreter/writer
    # binary must change this test (and be caught in review).
    assert _TERMINAL_ALLOWLIST == frozenset({
        "ls", "cat", "head", "tail", "wc", "stat", "file", "pwd", "whoami", "id", "uname",
        "env", "hostname", "date", "df", "du", "ps", "uptime", "echo", "grep", "sort",
        "uniq", "cut", "tr", "find",
    })


def test_no_network_interpreter_or_writer_binary_is_allowlisted():
    # By CONSTRUCTION: every network / interpreter / writer binary is ABSENT from the allowlist, so a
    # terminal command can never open a socket (egress), spawn an interpreter, or mutate the host.
    network = {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "telnet", "socat",
               "rsync", "ftp", "nmap", "dig", "host", "nslookup", "ping"}
    interpreters = {"bash", "sh", "zsh", "dash", "python", "python3", "perl", "ruby", "node", "php",
                    "awk", "gawk", "lua", "xargs"}
    writers = {"sed", "tee", "cp", "mv", "rm", "dd", "ln", "chmod", "chown", "mkdir", "touch",
               "truncate", "install", "tar"}
    for forbidden in (network | interpreters | writers):
        assert forbidden not in _TERMINAL_ALLOWLIST, f"{forbidden!r} must never be terminal-allowlisted"


# ================================================================================================
# (0) no signer wired → refuse an UNRECORDABLE command, BEFORE anything runs
# ================================================================================================


def test_no_signer_refuses_before_running():
    fr = FakeRun()
    res = execute_terminal("ls -la", Phase.INFORMATIONAL, gate=gate(), view=_view(),
                           destructive_view={}, run=fr, signer=None, seq=1, now=0)
    assert res.ran is False and res.outcome == "deny" and not fr.calls
    assert "no signer" in res.reason
    assert res.record is None


# ================================================================================================
# (1) shell metacharacters → refuse the WHOLE command (no shell is ever invoked)
# ================================================================================================


@pytest.mark.parametrize("command", [
    "ls; rm -rf /",       # command separator
    "cat x | y",          # pipe
    "`id`",               # backtick command substitution
    "$(id)",              # $() command substitution
    "a > b",              # output redirect
    "cat < /etc/passwd",  # input redirect
    "ls & whoami",        # background / control op
    "echo ${HOME}",       # brace / var expansion
    "cat foo\nrm bar",    # embedded newline
    "cat foo\\nbar",      # backslash
])
def test_metacharacter_command_refuses(command):
    fr = FakeRun()
    res = run_term(command, run=fr)
    assert res.ran is False and res.outcome == "deny" and not fr.calls
    assert res.record is None


def test_nul_byte_in_command_refuses():
    fr = FakeRun()
    res = run_term("ls \x00 foo", run=fr)
    assert res.ran is False and not fr.calls


# ================================================================================================
# (1) off-allowlist binary → refuse (network / interpreter / writer families all denied)
# ================================================================================================


@pytest.mark.parametrize("command", [
    "curl http://x",          # network egress
    "wget http://x/y",        # network egress
    "nc 127.0.0.1 4444",      # network / shell
    "ssh user@host",          # network
    "bash -c whoami",         # interpreter
    "sh script",              # interpreter
    "python -c print",        # interpreter
    "perl -e code",           # interpreter
    "rm -rf /",               # writer / destroyer
    "cp a b",                 # writer
    "tee out",                # writer
    "sed -i s/a/b/ f",        # in-place writer
    "dd if=a of=b",           # writer
    "unknownbin arg",         # simply not on the allowlist
])
def test_off_allowlist_binary_refuses(command):
    fr = FakeRun()
    res = run_term(command, run=fr)
    assert res.ran is False and res.outcome == "deny" and not fr.calls
    assert "allowlist" in res.reason


# ================================================================================================
# (1) find is allowlisted, but its executing/writing predicates are rejected
# ================================================================================================


@pytest.mark.parametrize("command", [
    "find . -exec rm {} \\;",   # classic exec (also metachar-refused; either way DENY)
    "find /etc -exec cat",      # exec predicate (metachar-free → hits the find-flag branch)
    "find . -delete",           # delete predicate
    "find / -fprint out",       # fprint writer
    "find . -fls out",          # fls writer
    "find . -ok cat",           # interactive exec
    "find . -okdir cat",        # interactive exec
    "find . -execdir cat",      # exec in dir
])
def test_find_execute_or_write_predicate_refuses(command):
    fr = FakeRun()
    res = run_term(command, run=fr)
    assert res.ran is False and res.outcome == "deny" and not fr.calls


def test_find_deny_flags_are_the_pinned_set():
    assert _TERMINAL_DENY_FLAGS == frozenset({
        "-exec", "-execdir", "-delete", "-fprint", "-fprintf", "-fls", "-ok", "-okdir",
    })


def test_benign_find_runs():
    # a read-only find (no exec/write predicate, no metachar) is allowed
    fr = FakeRun(stdout="./a\n./b")
    res = run_term("find . -maxdepth 1 -name passwd -type f", run=fr)
    assert res.ran is True and fr.calls
    assert fr.calls[0][0] == "find"


def test_bare_dotdot_token_refuses():
    fr = FakeRun()
    res = run_term("cat ..", run=fr)
    assert res.ran is False and not fr.calls


# ================================================================================================
# (1) exec/write forms of the FEW capable allowlisted binaries (env/sort/uniq/date) are refused —
# this is what makes the by-construction "no egress / no host-write" guarantee actually hold.
# ================================================================================================


@pytest.mark.parametrize("command,why", [
    ("env curl http://evil", "env exec-wrapper → egress"),
    ("env FOO=bar id", "env NAME=VAL PROG → exec"),
    ("env bash", "env interpreter → exec"),
    ("sort -o /etc/passwd file", "sort -o → file write"),
    ("sort --output=/etc/passwd file", "sort --output → file write"),
    ("sort --compress-program=curl file", "sort --compress-program → exec → egress"),
    ("sort -uo out file", "sort bundled -uo → output write"),
    ("uniq in out", "uniq 2nd operand → output write"),
    ("date -s 2020-01-01", "date -s → system-clock write"),
    ("date --set=2020-01-01", "date --set → system-clock write"),
    ("file -C -m /tmp/magic", "file -C → compiled magic write"),
    ("file --compile", "file --compile → magic write"),
    ("hostname newname", "hostname NAME → sets system hostname"),
    ("hostname -F /tmp/hn", "hostname -F file → sets hostname"),
])
def test_capable_binary_exec_or_write_forms_refuse(command, why):
    fr = FakeRun()
    res = run_term(command, run=fr)
    assert res.ran is False and res.outcome == "deny" and not fr.calls, why


@pytest.mark.parametrize("command", [
    "env",                    # bare env just prints the environment
    "sort -r file",           # reverse sort to stdout
    "sort file1 file2 file3",  # multi-input merge to stdout (NOT an output-file write)
    "sort -n -k2 data",       # numeric sort, key
    "uniq -c file",           # count-dedup a single input
    "uniq -f 2 file",         # separate numeric flag value is not the output operand
    "date -u",                # print UTC date
    "date +%s",               # NB: '%' and '+' are not metachars; format string is one token
    "hostname",               # bare hostname prints the name
    "file /etc/hostname",     # identify a file (read-only)
    "uname -n",               # node name via uname (the safe hostname-with-flags alternative)
])
def test_capable_binary_benign_forms_run(command):
    fr = FakeRun(stdout="ok")
    res = run_term(command, g=gate(allowed=True), run=fr)
    assert res.ran is True and fr.calls
    assert fr.calls[0] == command.split()


# ================================================================================================
# (2) cwd confinement — a '..' cwd denies; a valid cwd is passed through to the runner
# ================================================================================================


def test_cwd_with_dotdot_refuses():
    fr = FakeRun()
    res = run_term("ls", run=fr, cwd="/tmp/../etc")
    assert res.ran is False and res.outcome == "deny" and not fr.calls
    assert "cwd" in res.reason


def test_valid_cwd_is_confined_and_forwarded(tmp_path):
    fr = FakeRun()
    res = run_term("ls -la", run=fr, cwd=str(tmp_path))
    assert res.ran is True
    assert fr.cwds and fr.cwds[0] == str(tmp_path)


# ================================================================================================
# (3/4/5) an allowlisted command runs under a signer + allowing gate → SIGNED, NEVER-auto record
# ================================================================================================


@pytest.mark.parametrize("command,phase", [
    ("ls -la", Phase.INFORMATIONAL),
    ("grep -n foo file", Phase.EXPLOITATION),
    ("cat /etc/hostname", Phase.POST_EXPLOITATION),
    ("whoami", Phase.INFORMATIONAL),
])
def test_allowlisted_command_runs_signed_and_never_auto(command, phase):
    fr = FakeRun(stdout="canned-output")
    res = execute_terminal(command, phase, gate=gate(outcome="allow", allowed=True), view=_view(),
                           destructive_view={}, run=fr, signer=det_signer, seq=3, now=9)
    assert isinstance(res, ExecResult)
    assert res.ran is True and res.outcome == "ran"
    assert fr.calls and fr.calls[0] == command.split()          # argv is a literal whitespace split
    # a SIGNED spine record for tool="terminal.run"
    assert isinstance(res.record, ExecRecord)
    assert res.record.tool == "terminal.run" and res.tool == "terminal.run"
    assert res.record.target == "local"
    assert res.signed is True and res.record.signature.startswith("sig-")
    # NEVER auto: the record + result tier is A2/A3, never A0/A1 (terminal.run carries no danger token → A2)
    assert res.tier in ("A2", "A3") and res.record.tier in ("A2", "A3")
    assert res.tier not in ("A0", "A1") and res.record.tier not in ("A0", "A1")
    assert res.destructive is False and res.requires_quorum is False
    # the RAW output is returned for the oracle; the record commits to its hash
    assert res.stdout == "canned-output"
    assert res.record.stdout_sha256 == hashlib.sha256(b"canned-output").hexdigest()


def test_record_is_signed_over_the_a2_tier_not_the_phase_tier():
    # regression: informational phase-tier is A1 (auto), but a terminal.run must record at its A2 WARDEN
    # classification, and the signature must be over THAT record (so the never-auto tier is provable).
    fr = FakeRun()
    res = run_term("ls", Phase.INFORMATIONAL, g=gate(allowed=True), run=fr)
    assert res.ran is True and res.record.tier == "A2"
    # the signature verifies against the record's own signing bytes (tier A2 is part of them)
    assert res.record.signature == det_signer(res.record.signing_bytes())


def test_argv_handed_to_runner_is_a_list_no_shell():
    fr = FakeRun()
    run_term("grep -n foo file", run=fr)
    assert isinstance(fr.calls[0], list) and all(isinstance(a, str) for a in fr.calls[0])


# ================================================================================================
# (3) the gate leg — kill-switch / deny / None / exception all block the run (fail-closed)
# ================================================================================================


def test_killswitch_or_gate_deny_blocks_run():
    fr = FakeRun()
    res = execute_terminal("ls -la", Phase.INFORMATIONAL,
                           gate=gate(outcome="deny", allowed=False, reason="killswitch tripped"),
                           view=_view(), destructive_view={}, run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and res.outcome == "deny" and not fr.calls
    assert "authorization denied" in res.reason


def test_no_gate_wired_blocks_run():
    fr = FakeRun()
    res = execute_terminal("ls -la", Phase.INFORMATIONAL, gate=None, view=_view(),
                           destructive_view={}, run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls


def test_gate_exception_blocks_run():
    fr = FakeRun()
    res = run_term("ls -la", g=gate(raises=True), run=fr)
    assert res.ran is False and not fr.calls


def test_out_of_phase_tool_denied():
    # terminal.run registered only for exploitation; called in informational → phase gate denies pre-gate
    fr = FakeRun()
    res = execute_terminal("ls -la", Phase.INFORMATIONAL, gate=gate(), view=_view([Phase.EXPLOITATION]),
                           destructive_view={}, run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls


def test_unregistered_terminal_tool_denied():
    # an EMPTY view (terminal.run not registered anywhere) → the phase gate denies every phase
    fr = FakeRun()
    res = execute_terminal("ls -la", Phase.INFORMATIONAL, gate=gate(), view={},
                           destructive_view={}, run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls


# ================================================================================================
# totality — malformed input never raises; a runner outage degrades to a recorded no-output result
# ================================================================================================


@pytest.mark.parametrize("command", [None, "", "   ", 12345, b"ls", ["ls", "-la"], {"cmd": "ls"}])
def test_total_on_malformed_command(command):
    fr = FakeRun()
    res = execute_terminal(command, Phase.INFORMATIONAL, gate=gate(), view=_view(),
                           destructive_view={}, run=fr, signer=det_signer, seq=1, now=0)
    assert isinstance(res, ExecResult)      # never raised
    assert res.ran is False and not fr.calls


def test_runner_outage_does_not_crash():
    fr = FakeRun(raises=True)
    res = run_term("ls -la", g=gate(allowed=True), run=fr)
    # the gates passed and the runner was invoked; its failure degrades to a recorded no-output result
    assert res.ran is True and res.exit_code is None
    assert "runner error" in res.stderr and isinstance(res.record, ExecRecord)


def test_bad_phase_denies():
    fr = FakeRun()
    res = execute_terminal("ls -la", "not-a-phase", gate=gate(), view=_view(),
                           destructive_view={}, run=fr, signer=det_signer, seq=1, now=0)
    assert res.ran is False and not fr.calls
