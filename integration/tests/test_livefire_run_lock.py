"""The tool-driver live-fire harness must ISOLATE ITSELF — one run per machine, unique artifacts.

WHAT THIS IS ABOUT. Three copies of ``tools/livefire/tool_drivers_livefire.{sh,py}`` were observed
running at once, with two nikto processes writing the same report file. The harness had no concurrency
guard of its own: its report path is derived from the tool and the TARGET URL (identical across runs),
ZAP's proxy port is pinned to one number, and one run's teardown destroys the range target another run
is still scanning. Evidence a second run corrupted is worse than no evidence, because it still looks
like a result — and a tool that was interrupted goes quiet in exactly the way a tool that found nothing
goes quiet.

So the harness locks itself, and these tests are the proof that it does. They START TWO INVOCATIONS —
of the Python harness and of the shell driver — and assert that the second REFUSES cleanly, naming the
run that holds the lock, while the first is unharmed: still alive, still holding it, its holder record
on disk untouched by the run that was turned away.

WHAT THEY DO NOT NEED. No range target, no offense virtualenv, no security tool, and no network. The
lock is taken before any of that, which is the point of taking it there: a refused run must not be able
to bring a target up or tear one down. Every test redirects ``TMPDIR``, so it locks on its own temporary
file rather than the machine's — a test that fought a real live-fire run for the real lock would be the
very defect it is here to prevent.
"""

import importlib.util
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
HARNESS_PY = REPO / "tools" / "livefire" / "tool_drivers_livefire.py"
HARNESS_SH = REPO / "tools" / "livefire" / "tool_drivers_livefire.sh"

# The same two source trees CI puts on PYTHONPATH, put there here as well so the artifact test RUNS on a
# plain `pytest integration/tests` instead of skipping. A skip that depends on how pytest was invoked is
# a test nobody is looking at, and this suite exists because silence was mistaken for a result once.
for _tree in (REPO / "integration", REPO / "gateway"):
    if str(_tree) not in sys.path:
        sys.path.insert(0, str(_tree))

# The harness's own exit code for "somebody else is already running", kept distinct from the 1 a failed
# expectation returns so a caller cannot record a driver failure that never happened.
LOCK_BUSY_EXIT = 3

# Takes the lock, says so, and then holds it until its stdin is written to. Loaded from the harness by
# path: the module's top level is stdlib-only, so this needs nothing installed.
_HOLDER = """
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("livefire_harness", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod          # dataclasses resolve annotations through sys.modules
spec.loader.exec_module(mod)
lock = mod.acquire_run_lock(sys.argv[2])
print(json.dumps({"pid": os.getpid(), "path": lock.path, "nonce": lock.nonce,
                  "inherited": lock.inherited}), flush=True)
sys.stdin.readline()
print("STILL-HELD", flush=True)
"""

# Isolates a run's artifacts (or deliberately does not, with --no-isolate) and reports where the
# ENGINE'S OWN allocator would then put a report file.
_ARTIFACTS = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("livefire_harness", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod          # dataclasses resolve annotations through sys.modules
spec.loader.exec_module(mod)
workdir, isolate = sys.argv[2], sys.argv[3] == "isolate"
root = mod.isolate_run_artifacts(workdir) if isolate else None
from vigil_integration.live.executor import _report_path, _report_root, _report_subdir
print(json.dumps({"run_root": root, "report_root": _report_root(),
                  "nikto": _report_path("nikto", "http://127.0.0.1:8080/"),
                  "zap_home": _report_subdir("zaproxy-home")}), flush=True)
"""


def _env(tmp_path, **extra):
    """A child's environment: its own TMPDIR (so it locks on its own file, never the machine's) and the
    two source trees on PYTHONPATH so the engine's executor is importable."""
    env = dict(os.environ)
    env["TMPDIR"] = str(tmp_path)
    env.pop("TEMP", None)
    env.pop("TMP", None)
    # Never inherit a real run's launcher claim into a test: a stale nonce in this process's
    # environment would let a child think it was running under a launcher that holds the lock.
    for name in ("VIGIL_LIVEFIRE_LOCK", "VIGIL_LIVEFIRE_LOCK_NONCE", "VIGIL_LIVEFIRE_LOCK_PID"):
        env.pop(name, None)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO / "integration"), str(REPO / "gateway")] +
        ([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else []))
    env.update(extra)
    return env


class Holder:
    """A live-fire run that holds the lock, so a second invocation has something real to be refused by."""

    def __init__(self, proc, record):
        self.proc, self.record = proc, record

    @property
    def pid(self):
        return self.record["pid"]

    @property
    def path(self):
        return self.record["path"]

    def alive(self):
        return self.proc.poll() is None

    def release(self):
        """Let it finish, and report whether it was still holding the lock when we did."""
        self.proc.stdin.write("go\n")
        self.proc.stdin.flush()
        out = self.proc.stdout.readline().strip()
        return out, self.proc.wait(timeout=30)


@pytest.fixture
def holder(tmp_path):
    proc = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(HARNESS_PY), "the-first-run"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=_env(tmp_path), cwd=str(REPO))
    line = proc.stdout.readline()
    if not line:
        proc.kill()
        pytest.fail(f"the first run never took the lock: {proc.stderr.read()}")
    held = Holder(proc, json.loads(line))
    assert held.record["inherited"] is False
    yield held
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=30)


def _second_python_run(tmp_path, **extra):
    return subprocess.run(
        [sys.executable, "-c", _HOLDER, str(HARNESS_PY), "the-second-run"],
        input="", capture_output=True, text=True, timeout=60,
        env=_env(tmp_path, **extra), cwd=str(REPO))


def _load_harness():
    """The harness as a module. Its top level is stdlib-only and takes no lock, sends nothing and
    starts nothing — importing it is safe even while a real live-fire run is in progress."""
    spec = importlib.util.spec_from_file_location("livefire_harness_under_test", HARNESS_PY)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _dead_pid():
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=30)
    return proc.pid


# ---------------------------------------------------------------------------------------------------
# two invocations: the second refuses cleanly, the first is unharmed
# ---------------------------------------------------------------------------------------------------


def test_a_second_run_is_refused_fast_and_names_the_run_that_holds_the_lock(tmp_path, holder):
    started = time.monotonic()
    second = _second_python_run(tmp_path)
    elapsed = time.monotonic() - started

    assert second.returncode == LOCK_BUSY_EXIT, (
        f"a second run must refuse with {LOCK_BUSY_EXIT}, not interleave "
        f"(rc={second.returncode})\n{second.stdout}\n{second.stderr}")
    assert "already holds the run lock" in second.stderr
    # NAMING THE HOLDER is the difference between a refusal an operator can act on and a mystery.
    assert str(holder.pid) in second.stderr, f"the refusal must name the holder:\n{second.stderr}"
    assert holder.path in second.stderr
    assert "the-first-run" in second.stderr, "it must say what the holder is doing"
    # Fail fast: a second run that blocked would start later, when nobody remembers queuing it.
    assert elapsed < 30, f"the refusal took {elapsed:.1f}s — it must not queue behind the first run"


def test_the_first_run_is_unharmed_by_the_refusal(tmp_path, holder):
    before = pathlib.Path(holder.path).read_text()

    second = _second_python_run(tmp_path)
    assert second.returncode == LOCK_BUSY_EXIT

    assert holder.alive(), "the refused run must not have disturbed the run that holds the lock"
    # The holder RECORD is what a refusal quotes; a second run that opened the lock file for writing
    # would truncate it before discovering it cannot have it, and the next refusal would name nobody.
    assert pathlib.Path(holder.path).read_text() == before, (
        "the refused run rewrote the holder record — the next refusal would name the wrong run")
    assert json.loads(before)["nonce"] == holder.record["nonce"]

    out, code = holder.release()
    assert out == "STILL-HELD" and code == 0, "the first run must finish normally after the refusal"


def test_the_shell_driver_refuses_before_it_touches_the_range(tmp_path, holder):
    """The lock is taken by the shell driver BEFORE the range is brought up, the virtualenv is checked
    or the teardown trap is installed — so a refused run can neither start a target nor destroy one.
    That is why this test needs no range, no venv and no tool: it never gets that far."""
    if shutil.which("flock") is None:
        pytest.skip("flock(1) is not installed; the shell driver refuses to run unlocked without it")

    started = time.monotonic()
    second = subprocess.run(["bash", str(HARNESS_SH)], capture_output=True, text=True,
                            timeout=120, env=_env(tmp_path), cwd=str(REPO))
    elapsed = time.monotonic() - started
    both = second.stdout + second.stderr

    assert second.returncode == LOCK_BUSY_EXIT, f"rc={second.returncode}\n{both}"
    assert "already holds the run lock" in both
    assert str(holder.pid) in both, f"the refusal must name the holder:\n{both}"
    assert "Bringing up the vulnerable target" not in second.stdout, (
        "a refused run reached the range — the lock is being taken too late to protect it")
    assert "Tearing down" not in both, "a refused run must never run the teardown"
    assert elapsed < 60, f"the shell driver took {elapsed:.1f}s to refuse"

    assert holder.alive()
    out, code = holder.release()
    assert out == "STILL-HELD" and code == 0


# ---------------------------------------------------------------------------------------------------
# the shell driver launches the Python harness UNDER its own lock — which must not deadlock, and must
# not become a way around the lock either
# ---------------------------------------------------------------------------------------------------


def test_the_launcher_is_recognised_rather_than_deadlocked_against(tmp_path, holder):
    """The Python harness runs as a child of the shell driver, which already holds the lock. It cannot
    take the lock, and must not treat that as a reason to refuse — the nonce its launcher exported
    proves the holder is the process whose environment it inherited."""
    inherited = _second_python_run(
        tmp_path,
        VIGIL_LIVEFIRE_LOCK=holder.path,
        VIGIL_LIVEFIRE_LOCK_NONCE=holder.record["nonce"],
        VIGIL_LIVEFIRE_LOCK_PID=str(holder.pid))

    assert inherited.returncode == 0, f"the harness deadlocked against its own launcher\n{inherited.stderr}"
    assert json.loads(inherited.stdout.splitlines()[0])["inherited"] is True


@pytest.mark.parametrize("claim", [
    pytest.param({"VIGIL_LIVEFIRE_LOCK_NONCE": "00" * 16}, id="wrong nonce"),
    pytest.param({"VIGIL_LIVEFIRE_LOCK_PID": "999999"}, id="wrong pid"),
])
def test_a_forged_launcher_claim_is_still_refused(tmp_path, holder, claim):
    """The negative control for the test above, and the one that matters: if merely SETTING those
    variables let a run through, the inheritance path would be a documented way around the lock."""
    env = {"VIGIL_LIVEFIRE_LOCK": holder.path,
           "VIGIL_LIVEFIRE_LOCK_NONCE": holder.record["nonce"],
           "VIGIL_LIVEFIRE_LOCK_PID": str(holder.pid)}
    env.update(claim)

    second = _second_python_run(tmp_path, **env)
    assert second.returncode == LOCK_BUSY_EXIT, (
        f"a forged launcher claim got through the lock\n{second.stdout}\n{second.stderr}")
    assert "already holds the run lock" in second.stderr


def test_the_lock_is_released_when_a_run_is_killed(tmp_path, holder):
    """An advisory flock, not a pid file: whatever a run dies of, the kernel drops it. A live-fire that
    crashed must not wedge the machine, or the next operator's only move is to delete a file they have
    to be told about."""
    os.kill(holder.pid, signal.SIGKILL)
    holder.proc.wait(timeout=30)

    after = _second_python_run(tmp_path)
    assert after.returncode == 0, (
        f"the lock survived its holder — a crashed run wedges the machine\n{after.stderr}")


# ---------------------------------------------------------------------------------------------------
# what the shell driver depends on, and the honesty of the refusal itself
# ---------------------------------------------------------------------------------------------------


def test_the_shell_and_the_python_agree_on_one_lock_path(tmp_path):
    """The shell driver asks the Python harness where the lock lives rather than spelling it itself. If
    that mode broke, the two would drift onto different locks — both "locked", neither exclusive."""
    res = subprocess.run([sys.executable, str(HARNESS_PY), "--lock-path"],
                         capture_output=True, text=True, timeout=60,
                         env=_env(tmp_path), cwd=str(REPO))
    assert res.returncode == 0, res.stderr
    path = pathlib.Path(res.stdout.strip())
    assert str(tmp_path) in str(path), f"the lock escaped this test's TMPDIR: {path}"
    assert path.exists(), "the mode must leave the lock file in place for the shell to open"
    # 0700 on the directory is what keeps another local user from planting a symlink at the lock path.
    assert oct(path.parent.stat().st_mode)[-3:] == "700"
    # Asking where the lock is must not TAKE it — the shell asks first and locks second.
    second = subprocess.run([sys.executable, str(HARNESS_PY), "--lock-path"],
                            capture_output=True, text=True, timeout=60,
                            env=_env(tmp_path), cwd=str(REPO))
    assert second.returncode == 0 and second.stdout.strip() == str(path)


def test_an_unknown_argument_is_refused_rather_than_ignored(tmp_path):
    res = subprocess.run([sys.executable, str(HARNESS_PY), "--no-such-mode"],
                         capture_output=True, text=True, timeout=60,
                         env=_env(tmp_path), cwd=str(REPO))
    assert res.returncode != 0
    assert "--no-such-mode" in res.stderr


def test_a_stale_holder_record_is_flagged_rather_than_quoted_as_fact():
    """The record is written a moment AFTER the lock is taken, so a run arriving in that window reads
    the PREVIOUS holder's record. Naming that run with total confidence would send an operator after a
    process that no longer exists, so the refusal says when the pid it names is gone."""
    harness = _load_harness()
    live = {"pid": os.getpid(), "user": "u", "host": "h", "started": "t",
            "purpose": "the-first-run", "target": "vulnapp"}

    described = harness.describe_holder(live)
    assert "the-first-run" in described and "stale" not in described

    stale = harness.describe_holder(dict(live, pid=_dead_pid()))
    assert "stale" in stale, f"a record naming a dead process was quoted as fact:\n{stale}"

    assert "unidentified" in harness.describe_holder({}), (
        "a holder that has not written a record must be reported as unidentified, never as absent — "
        "the lock is held by the kernel, not by the record")


# ---------------------------------------------------------------------------------------------------
# the safety net under the lock: two runs cannot NAME the same artifact
# ---------------------------------------------------------------------------------------------------


def _artifacts(tmp_path, workdir, mode):
    workdir.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        [sys.executable, "-c", _ARTIFACTS, str(HARNESS_PY), str(workdir), mode],
        capture_output=True, text=True, timeout=120,
        env=_env(tmp_path / "shared-tmp"), cwd=str(REPO))
    assert res.returncode == 0, f"{res.stdout}\n{res.stderr}"
    return json.loads(res.stdout.splitlines()[-1])


def test_two_runs_cannot_name_the_same_report_artifact(tmp_path):
    """Belt and braces. The lock is the guard; this is what makes a LOCK FAILURE survivable.

    The executor derives a report's path from the tool and the pinned target, both identical across
    runs of this harness — so the first half of this test measures the collision (two runs, one file),
    and the second half shows the harness's per-run temporary root removing it. It asserts nothing about
    the executor's own behaviour, and changes nothing about it: the same allocator runs, at a path only
    one run can name."""
    pytest.importorskip("vigil_integration.live.executor",
                        reason="the engine's executor is what allocates the report artifact")
    (tmp_path / "shared-tmp").mkdir()

    # THE DEFECT, measured: without per-run isolation the same file is handed to both runs.
    collided = [_artifacts(tmp_path, tmp_path / f"unisolated-{n}", "no-isolate") for n in (1, 2)]
    assert collided[0]["nikto"] and collided[0]["nikto"] == collided[1]["nikto"], (
        "expected the unisolated path to collide — if it no longer does, this test is measuring "
        "nothing and the claim below is unsupported")

    # THE FIX: each run's artifacts live under its own workdir, so neither can overwrite the other's.
    runs = [_artifacts(tmp_path, tmp_path / f"run-{n}", "isolate") for n in (1, 2)]
    for run, name in zip(runs, ("run-1", "run-2")):
        assert run["nikto"], "a run with no report path would make the scanner refuse"
        for key in ("report_root", "nikto", "zap_home"):
            assert str(tmp_path / name) in run[key], (
                f"{key} escaped this run's workdir: {run[key]}")
    assert runs[0]["nikto"] != runs[1]["nikto"], "two runs still name the same report file"
    assert runs[0]["zap_home"] != runs[1]["zap_home"], "two runs still share ZAP's home directory"
