"""Guard: the nightly live-fire cannot be pinned to an httpx that cannot record a refused probe.

WHY THIS EXISTS. ``_build_httpx`` passes ``-json -probe`` so that a probe which did NOT connect is
RECORDED (``"failed":true``) rather than dropped, and the live-fire table's closed-port control reads
that record as its evidence that the tool ran and reached its conclusion. ProjectDiscovery httpx only
keeps that promise from v1.6.10: up to v1.6.9 every errored result was skipped before the JSON writer,
so the control leg returned exit 0 and zero bytes. The nightly was pinned at v1.6.9 and was red on
exactly that row on every scheduled run from 2026-10-29 to 2026-11-11 — a non-required job nobody was
reading.

So, from the committed workflow alone (pure file reads — this guard is framework-free and runs in the
SOVEREIGN leg; keep it out of any ``--ignore``, which the last test enforces):

  1. every way the workflow obtains httpx is an exact ``go install …@vX.Y.Z`` at or above the floor,
     inside the full-table job and BEFORE the proof step;
  2. the full-table job carries the step that proves the BEHAVIOUR on the installed binary — a version
     is only a proxy for it — between the install and the table, and that step cannot be switched off
     (``if:``, ``shell:``, ``continue-on-error``, ``|| true``) or hollowed out (the probe must carry
     the builder's flags, the record must be grepped for, and the miss must ``exit 1``);
  3. the flags the step probes with are the flags ``_build_httpx`` really emits.

NEGATIVE CONTROLS. The checkers take the workflow text as an ARGUMENT, so each perturbation is exercised
in-process, and every control first asserts that its perturbation actually changed the text — a control
that silently stopped perturbing would otherwise pass for the wrong reason.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LIVEFIRE = _REPO / ".github" / "workflows" / "livefire.yml"
_CI = _REPO / ".github" / "workflows" / "ci.yml"
_EXECUTOR = _REPO / "integration" / "vigil_integration" / "live" / "executor.py"

# The first release whose `-json -probe` writes a record for a probe that did not connect.
HTTPX_FLOOR = (1, 6, 10)

_JOB = "livefire-full"
_PROOF_STEP = "the installed httpx records a refused probe"
_DRIVE_STEP = "drive the table against the loopback range"

# Any way of obtaining the tool: the Go module path, or the name Kali packages it under.
_MENTIONS_HTTPX_TOOL = re.compile(r"projectdiscovery/httpx|httpx-toolkit")
_INSTALL = re.compile(r"^go install github\.com/projectdiscovery/httpx/cmd/httpx@(\S+)")
_VERSION = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
_STEP_START = re.compile(r"^      - ", re.M)
_STEP_NAME = re.compile(r"\A(?:name: *)(['\"]?)(.+?)\1 *$", re.M)
_SWITCH_KEYS = re.compile(r"^        (if|shell|continue-on-error) *:", re.M)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code(text: str) -> str:
    """``text`` without comments: whole-line ``#`` lines dropped, a trailing `` # …`` cut off. Prose
    that merely QUOTES a pin, a flag or an ``exit 1`` must never be read as the real thing."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(re.sub(r"\s+#\s.*$", "", line))
    return "\n".join(out)


def _job_block(workflow: str, job: str) -> str:
    """The text of one job (its 2-space-indented key up to the next one), or ''."""
    m = re.search(rf"^  {re.escape(job)}:\s*$", workflow, re.M)
    if not m:
        return ""
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\s*$", workflow[m.end():], re.M)
    return workflow[m.end(): m.end() + nxt.start()] if nxt else workflow[m.end():]


def _steps(job_block: str) -> list[str]:
    """Each step of a job as its own text, the leading ``      - `` removed."""
    starts = [m.start() for m in _STEP_START.finditer(job_block)]
    return [job_block[a:b][len("      - "):] for a, b in zip(starts, starts[1:] + [len(job_block)])]


def _step_index(steps: list[str], name: str) -> int:
    for i, step in enumerate(steps):
        m = _STEP_NAME.match(step)
        if m and m.group(2) == name:
            return i
    return -1


def httpx_pin_problems(workflow: str) -> list[str]:
    """Why the workflow could run the table on an httpx below the floor ([] when it cannot)."""
    steps = _steps(_job_block(workflow, _JOB))
    proof = _step_index(steps, _PROOF_STEP)
    before_proof = _code("\n".join(steps[:proof])) if proof > 0 else ""
    problems, pins = [], 0
    for line in _code(workflow).splitlines():
        if not _MENTIONS_HTTPX_TOOL.search(line):
            continue
        m = _INSTALL.match(line.strip())
        if not m:
            problems.append(f"httpx is obtained by something other than a plain pinned `go install`: "
                            f"{line.strip()[:90]!r}")
            continue
        ref = m.group(1)
        v = _VERSION.fullmatch(ref)
        if not v:
            problems.append(f"httpx@{ref} is not an exact vX.Y.Z pin")
            continue
        if tuple(int(g) for g in v.groups()) < HTTPX_FLOOR:
            problems.append(f"httpx@{ref} is below v{'.'.join(map(str, HTTPX_FLOOR))}: it writes no "
                            f"record for a refused probe under -json -probe")
        pins += 1
    covered = sum(1 for line in before_proof.splitlines() if _MENTIONS_HTTPX_TOOL.search(line))
    if pins > covered:
        problems.append(f"httpx is installed outside the {_JOB} job or after the proof step, so the "
                        f"proof step does not cover that install")
    if not pins and not problems:
        problems.append("no `go install …/httpx/cmd/httpx@<version>` line found — the pin cannot be checked")
    return problems


def proof_step_problems(workflow: str) -> list[str]:
    """Why the workflow does not prove the failed-probe record on the installed binary ([] when it does)."""
    job = _job_block(workflow, _JOB)
    if not job:
        return [f"the {_JOB} job is missing"]
    problems = []
    if re.search(r"^    continue-on-error *:", job, re.M):
        problems.append(f"the {_JOB} job is continue-on-error, so a failed proof would not be seen")
    steps = _steps(job)
    proof, drive = _step_index(steps, _PROOF_STEP), _step_index(steps, _DRIVE_STEP)
    if proof < 0:
        return problems + [f"the step {_PROOF_STEP!r} is missing from the {_JOB} job"]
    install = next((i for i, s in enumerate(steps) if any(_INSTALL.match(ln.strip())
                                                         for ln in _code(s).splitlines())), -1)
    if not (0 <= install < proof):
        problems.append("the proof step does not run AFTER httpx is installed")
    if not (proof < drive):
        problems.append("the proof step does not run BEFORE the table is driven")
    step = steps[proof]
    for m in _SWITCH_KEYS.finditer(step):
        problems.append(f"the proof step carries `{m.group(1)}:`, which can switch it off or soften it")
    lines = [ln.strip() for ln in _code(step).splitlines()]
    if any("|| true" in ln or "set +e" in ln for ln in lines):
        problems.append("the proof step swallows a failure (`|| true` / `set +e`)")
    probe = next((i for i, ln in enumerate(lines)
                  if '"$bin"' in ln and " -u " in ln and not ln.startswith("echo")), -1)
    if probe < 0:
        return problems + ["the proof step no longer probes with the installed binary"]
    for flag in ("-json", "-probe"):
        if flag not in lines[probe].split():
            problems.append(f"the probe no longer passes {flag}, the flag the engine's builder emits")
    # The one legitimate `exit 0` is the missing-binary branch (the table reports that itself).
    absent = next((i for i, ln in enumerate(lines) if ln == 'if [ ! -x "$bin" ]; then'), -1)
    absent_end = next((i for i, ln in enumerate(lines) if i > absent >= 0 and ln == "fi"), -1)
    if any(ln == "exit 0" and not (0 <= absent < i < absent_end) for i, ln in enumerate(lines)):
        problems.append("the proof step can `exit 0` without having judged the probe's output")
    check = next((i for i, ln in enumerate(lines) if i > probe and ln.startswith("if ! ")
                  and "grep -q '\"failed\":true'" in ln and ln.endswith("; then")), -1)
    if check < 0:
        problems.append("the proof step no longer greps the probe's output for '\"failed\":true'")
    else:
        end = next((i for i, ln in enumerate(lines) if i > check and ln == "fi"), len(lines))
        if "exit 1" not in lines[check:end]:
            problems.append("a missing failed-probe record no longer ends the step with `exit 1`")
    return problems


def builder_flag_problems(executor_source: str) -> list[str]:
    """Why the proof step's flags are not the flags ``_build_httpx`` emits ([] when they are)."""
    m = re.search(r"^def _build_httpx\(.*?(?=^def )", executor_source, re.M | re.S)
    if not m:
        return ["_build_httpx not found in executor.py — the flag check is blind"]
    argv = re.search(r"^\s*argv = \[.*?\]", _code(m.group(0)), re.M | re.S)
    if not argv:
        return ["_build_httpx no longer builds a literal argv — the flag check is blind"]
    return [f"_build_httpx no longer passes {flag!r}; the workflow's proof step probes with it"
            for flag in ('"-json"', '"-probe"') if flag not in argv.group(0)]


# ---------------------------------------------------------------------------------------------------
# the committed artifacts hold
# ---------------------------------------------------------------------------------------------------
def test_the_nightly_httpx_pin_can_record_a_refused_probe():
    assert httpx_pin_problems(_read(_LIVEFIRE)) == []


def test_the_workflow_proves_the_failed_probe_record_before_driving_the_table():
    assert proof_step_problems(_read(_LIVEFIRE)) == []


def test_the_proof_step_probes_with_the_flags_the_builder_emits():
    assert builder_flag_problems(_read(_EXECUTOR)) == []


def test_this_guard_is_not_ignored_in_ci():
    name = Path(__file__).name
    ignored = [ln.strip() for ln in _code(_read(_CI)).splitlines() if "--ignore" in ln and name in ln]
    assert ignored == []


# ---------------------------------------------------------------------------------------------------
# negative controls
# ---------------------------------------------------------------------------------------------------
def _perturb(old: str, new: str, *, count: int = 1) -> str:
    text = _read(_LIVEFIRE)
    assert old in text, f"the negative control's anchor is gone from livefire.yml: {old!r}"
    out = text.replace(old, new, count)
    assert out != text
    return out


def _pin_line() -> str:
    line = next(ln for ln in _read(_LIVEFIRE).splitlines() if _INSTALL.match(ln.strip()))
    return line.strip().split(" ||")[0].rstrip()


def test_negative_control_the_old_pin_is_reported():
    pin = _pin_line()
    old = _perturb(pin, pin.rsplit("@", 1)[0] + "@v1.6.9")
    assert any("below v1.6.10" in p for p in httpx_pin_problems(old))


def test_negative_control_an_inexact_ref_is_reported():
    pin = _pin_line()
    for ref in ("latest", "v1.6", "v1.6.010", "${HTTPX_VERSION}"):
        text = _perturb(pin, pin.rsplit("@", 1)[0] + "@" + ref)
        assert any("not an exact" in p for p in httpx_pin_problems(text)), ref


def test_negative_control_a_second_way_of_obtaining_httpx_is_reported():
    pin = _pin_line()
    for extra in ("go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9",
                  "sudo apt-get install -y httpx-toolkit",
                  "curl -sSLO https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx.zip"):
        text = _perturb(pin, pin + "\n          " + extra)
        assert any("other than a plain pinned" in p for p in httpx_pin_problems(text)), extra


def test_negative_control_a_reinstall_after_the_proof_step_is_reported():
    anchor = f"      - name: {_DRIVE_STEP}"
    step = "      - name: reinstall\n        run: |\n          " + _pin_line() + " \n"
    text = _perturb(anchor, step + anchor)
    assert any("after the proof step" in p for p in httpx_pin_problems(text))


def test_negative_control_a_pin_only_quoted_in_a_comment_is_not_a_pin():
    text = "jobs:\n  livefire-full:\n    steps:\n      # go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10\n"
    assert any("no `go install" in p for p in httpx_pin_problems(text))


def test_negative_control_a_missing_or_misplaced_proof_step_is_reported():
    assert any("missing" in p for p in proof_step_problems(
        _perturb(f"- name: {_PROOF_STEP}", "- name: something else")))
    # moved out of the full-table job (here: the job is renamed away from under it)
    assert proof_step_problems(_perturb(f"\n  {_JOB}:\n", "\n  some-other-job:\n"))
    # moved ahead of the install: the binary is absent, the step warns and proves nothing
    job = _job_block(_read(_LIVEFIRE), _JOB)
    steps = _steps(job)
    proof = _step_index(steps, _PROOF_STEP)
    install = proof - 1
    assert any(_INSTALL.match(ln.strip()) for ln in steps[install].splitlines())
    swapped = steps[:install] + [steps[proof], steps[install]] + steps[proof + 1:]
    text = _read(_LIVEFIRE).replace(job, job[: _STEP_START.search(job).start()]
                                    + "".join("      - " + s for s in swapped))
    assert text != _read(_LIVEFIRE)
    assert any("AFTER httpx is installed" in p for p in proof_step_problems(text))
    # moved after the table
    drive = _step_index(steps, _DRIVE_STEP)
    late = steps[:proof] + steps[proof + 1: drive + 1] + [steps[proof]] + steps[drive + 1:]
    text = _read(_LIVEFIRE).replace(job, job[: _STEP_START.search(job).start()]
                                    + "".join("      - " + s for s in late))
    assert any("BEFORE the table" in p for p in proof_step_problems(text))


def test_negative_control_a_switched_off_proof_step_is_reported():
    name = f"      - name: {_PROOF_STEP}\n"
    for key in ("if: false", "if: github.event_name == 'workflow_dispatch'", "shell: bash +e {0}",
                "continue-on-error: true"):
        text = _perturb(name, name + f"        {key}\n")
        assert any("switch it off" in p for p in proof_step_problems(text)), key
    text = _perturb(f"\n  {_JOB}:\n", f"\n  {_JOB}:\n    continue-on-error: true\n")
    assert any("job is continue-on-error" in p for p in proof_step_problems(text))


def test_negative_control_a_hollowed_out_proof_step_is_reported():
    probe = "-disable-update-check -json -probe </dev/null"
    cases = {
        "no longer passes -probe": _perturb(probe, "-disable-update-check -json </dev/null"),
        "no longer passes -json": _perturb(probe, "-disable-update-check -probe </dev/null"),
        "no longer greps": _perturb("grep -q '\"failed\":true'; then", "grep -q 'failed'; then"),
        "swallows a failure": _perturb("grep -q '\"failed\":true'; then",
                                       "grep -q '\"failed\":true' || true; then"),
        "can `exit 0` without having judged": _perturb("          rc=0\n", "          rc=0\n          exit 0\n"),
    }
    miss = 'the closed-port control cannot be read as evidence"\n            exit 1\n          fi\n\n'
    cases["no longer ends the step with `exit 1`"] = _perturb(miss, miss.replace("exit 1", "# exit 1"))
    for expected, perturbed in cases.items():
        assert any(expected in p for p in proof_step_problems(perturbed)), expected


def test_negative_control_builder_flags_that_drift_are_reported():
    src = _read(_EXECUTOR)
    for flag in ('"-json"', '"-probe"'):
        m = re.search(r"^def _build_httpx\(.*?(?=^def )", src, re.M | re.S)
        assert m is not None
        body = m.group(0)
        head, sep, tail = body.rpartition(flag)
        assert sep
        drifted = src.replace(body, head + '"-x"' + tail)
        assert drifted != src
        assert any(flag in p for p in builder_flag_problems(drifted)), flag
