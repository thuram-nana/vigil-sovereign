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
    _FIND_SAFE_PREDICATES,
    _TERMINAL_ALLOWLIST,
    _TERMINAL_BARE_ONLY,
    ExecRecord,
    ExecResult,
    RunOutcome,
    _parse_terminal_pipeline,
    _run_pipeline,
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
        "ls", "cat", "head", "tail", "wc", "stat", "pwd", "whoami", "id", "uname", "echo",
        "df", "du", "ps", "uptime", "grep", "cut", "tr",
        "nl", "tac", "rev", "fold", "expand", "column", "paste", "comm", "cmp", "diff",
        "readlink", "realpath", "basename", "dirname",
        "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
        "base64", "base32", "od", "xxd", "hexdump", "strings",
        "arch", "nproc", "lscpu", "lsblk", "free", "cal", "groups", "locale",
        "find", "sort", "uniq", "file", "date", "hostname",
    })
    # EGRESS/secret binaries stay OFF: getent (`getent hosts` → DNS lookup = egress), env/printenv (secret
    # dump / `env PROG` execs) — plus every network / interpreter / writer family.
    for excluded in ("getent", "env", "printenv", "curl", "wget", "nc", "ssh",
                     "bash", "sh", "python", "python3", "perl", "awk", "rm", "tee", "cp", "sed", "dd"):
        assert excluded not in _TERMINAL_ALLOWLIST, f"{excluded!r} must never be allowlisted"


# ================================================================================================
# pipelines — allowlisted composition, no shell; every stage validated; write/exec/egress impossible
# ================================================================================================


@pytest.mark.parametrize("command", [
    "grep root /etc/passwd | sort | uniq -c | head",   # the classic inspection idiom
    "cat /etc/hostname | tr a-z A-Z",
    "ls -la | grep conf | wc -l",
    "cat f | sort -r | head -n 3",
])
def test_safe_pipelines_parse_ok(command):
    stages, why = _parse_terminal_pipeline(command)
    assert stages is not None, why
    assert len(stages) >= 2


@pytest.mark.parametrize("command", [
    "cat x | curl http://evil",     # a network binary in a stage
    "grep a f | sh",                # an interpreter in a stage
    "cat x | rm -rf /",             # a writer/destroyer in a stage
    "cat x | sort --out=/etc/passwd",  # a write flag in a stage
    "cat x | | head",               # an empty stage (double pipe)
    "| head",                       # leading pipe
    "cat x |",                      # trailing pipe
    "cat a > b | c",                # a redirect metachar anywhere refuses the WHOLE command
    "a | b | c | d | e | f | g | h | i",  # too many stages
])
def test_dangerous_pipelines_refuse(command):
    stages, why = _parse_terminal_pipeline(command)
    assert stages is None, f"{command!r} must be refused"


def test_pipeline_runs_sequentially_no_shell():
    out = _run_pipeline([["echo", "hello world"], ["tr", "a-z", "A-Z"], ["wc", "-w"]], timeout=10)
    assert out.stdout.strip() == "2" and out.exit_code == 0


def test_reAdded_capable_binaries_write_or_exec_forms_still_refuse():
    # sort/uniq/file are back for pipelines, but their write/exec forms are refused by the flag allowlist —
    # incl. the getopt_long ABBREVIATION + bundled-short bypasses a red-pen used against the old denylist.
    for bad in ("sort -o /etc/passwd f", "sort --output=/etc/passwd f", "sort --out=/etc/passwd f",
                "sort --compress-program=curl f", "sort --compress=curl f", "sort -ro out f",
                "uniq in out", "file -C x", "file --compile x", "file --comp x"):
        stages, why = _parse_terminal_pipeline(bad)
        assert stages is None, f"{bad!r} must be refused"


@pytest.mark.parametrize("command", [
    "sha256sum /etc/hostname", "diff a b", "readlink -f /etc/hostname", "od -c f", "xxd f",
    "strings /bin/ls", "lsblk", "nproc", "rev f", "nl f", "base64 f", "comm a b", "sort -r f", "uniq -c f",
])
def test_expanded_read_tools_are_allowlisted(command):
    stages, why = _parse_terminal_pipeline(command)
    assert stages is not None, why


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
    "find /etc -exec cat",      # exec predicate (metachar-free → hits the find-flag branch)
    "find . -delete",           # delete predicate
    "find / -fprint out",       # fprint writer
    "find / -fprint0 out",      # RED-PEN BYPASS: -fprint0 was missed by the old denylist; omission catches it
    "find . -fprintf out fmt",  # fprintf writer
    "find . -fls out",          # fls writer
    "find . -ok cat",           # interactive exec
    "find . -okdir cat",        # interactive exec
    "find . -execdir cat",      # exec in dir
    "find . -newerXY ref",      # any unknown -predicate is refused by OMISSION (allowlist, not denylist)
])
def test_find_execute_or_write_predicate_refuses(command):
    fr = FakeRun()
    res = run_term(command, run=fr)
    assert res.ran is False and res.outcome == "deny" and not fr.calls


def test_find_predicate_allowlist_omits_every_exec_or_write_predicate():
    # the allowlist approach: exec/write predicates are refused by OMISSION — none may be present, and the
    # abbreviation-immune property holds because find predicates are matched EXACTLY, not by getopt prefix.
    for dangerous in ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"):
        assert dangerous not in _FIND_SAFE_PREDICATES
    for safe in ("-name", "-type", "-maxdepth", "-print", "-print0", "-size"):
        assert safe in _FIND_SAFE_PREDICATES


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
# (1) every exec/write form is refused — the exec/write-capable coreutils (sort/uniq/file/env) are OFF the
# allowlist entirely, and date/hostname are admitted BARE-ONLY. Includes the RED-PEN bypasses (getopt_long
# prefix abbreviations + positional aliases) a spelling-denylist guard would have missed.
# ================================================================================================


@pytest.mark.parametrize("command,why", [
    # exec/write-capable coreutils are OFF the allowlist — refused regardless of the (ab)form:
    ("env curl http://evil", "env exec-wrapper → egress (off-allowlist)"),
    ("env FOO=bar id", "env NAME=VAL PROG → exec (off-allowlist)"),
    ("env bash", "env interpreter → exec (off-allowlist)"),
    ("sort -o /etc/passwd file", "sort -o → file write (off-allowlist)"),
    ("sort --output=/etc/passwd file", "sort --output → file write (off-allowlist)"),
    ("sort --compress-program=curl file", "sort --compress-program → exec → egress (off-allowlist)"),
    ("sort --compress=curl file", "RED-PEN: --compress abbrev of --compress-program → refused (off-allowlist)"),
    ("sort --out=/etc/passwd file", "RED-PEN: --out abbrev of --output → refused (off-allowlist)"),
    ("sort --o=/etc/passwd file", "RED-PEN: --o abbrev of --output → refused (off-allowlist)"),
    ("uniq in out", "uniq 2nd operand → output write (off-allowlist)"),
    ("file -C -m /tmp/magic", "file -C → compiled magic write (off-allowlist)"),
    # date/hostname host-state PRINTERS: any operand/flag is refused (bare-only) — incl. abbrev + positional:
    ("date -s 2020-01-01", "date -s → clock write (bare-only)"),
    ("date --set=2020-01-01", "date --set → clock write (bare-only)"),
    ("date --s 2020", "RED-PEN: --s abbrev of --set → refused (bare-only)"),
    ("date 010100002025", "RED-PEN: positional MMDDhhmmYY set-clock synopsis → refused (bare-only)"),
    ("date -u", "any flag on date is refused (bare-only)"),
    ("hostname newname", "hostname NAME → sets system hostname (bare-only)"),
    ("hostname -F /tmp/hn", "hostname -F file → sets hostname (bare-only)"),
])
def test_every_exec_or_write_form_refuses(command, why):
    fr = FakeRun()
    res = run_term(command, run=fr)
    assert res.ran is False and res.outcome == "deny" and not fr.calls, why


@pytest.mark.parametrize("command", [
    "ls -la /etc",            # list a dir (read)
    "cat /etc/hostname",      # read a file
    "grep -rn root /etc",     # recursive read-only search
    "grep -f patterns.txt f", # -f reads a pattern file (a read, not exec/write)
    "head -c 64 f", "tail -n 5 f", "wc -l f", "stat /etc/hostname",
    "cut -d: -f1 /etc/passwd", "tr a b", "du -sh .", "df -h", "ps aux", "uptime",
    "id", "whoami", "uname -a", "echo hello", "pwd",
    "find . -maxdepth 1 -name passwd -type f",   # read-only walk with SAFE predicates only
    "date", "hostname",       # the host-state printers, BARE
])
def test_benign_read_commands_run(command):
    fr = FakeRun(stdout="ok")
    res = run_term(command, g=gate(allowed=True), run=fr)
    assert res.ran is True and fr.calls
    assert fr.calls[0] == command.split()


def test_bare_only_binaries_are_the_pinned_set():
    assert _TERMINAL_BARE_ONLY == frozenset({"date", "hostname"})


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
