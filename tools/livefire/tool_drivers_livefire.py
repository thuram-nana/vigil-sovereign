"""Prove the engine's TYPED TOOL DRIVERS end to end against the live loopback range.

Driven by ``tool_drivers_livefire.sh``, which brings up the range target this needs, provisions the
virtualenv, and tears everything down afterwards.

WHY THIS EXISTS. A typed argv builder that produces a plausible-looking command line proves nothing.
Unit-testing the argv STRING is how you ship a driver that has never worked. For each tool this harness
proves the whole path, and refuses to call it proven when a leg is missing:

  1. THE ARGV IS BUILT BY THE ENGINE'S OWN BUILDER. Every run goes through
     ``live.executor.execute`` under the production phase manifest (``live.wiring.DEFAULT_TOOL_VIEW``),
     the production destructive manifest, and a REAL signed CRUCIBLE authority + conjunctive gate — the
     executor picks the builder out of its own ``_BUILDERS`` table and pins the loopback host itself.
     This harness never writes a command line. If it did, it would be testing itself.
  2. THE TOOL ACTUALLY RUNS against a real local target and returns real bytes — and that target is
     STILL ANSWERING when the leg ends. A target that dies mid-row produces exactly what a driver
     that found nothing produces, so without this the harness blames the engine's reader for a
     target that was not there. Measured: it did.
  3. THOSE BYTES PARSE THROUGH AN ENGINE READER — an import adapter under ``framework.v2.imports`` or
     a sensor parser — never through a regex this file invented. A tool that runs but whose output
     nothing in the engine can read is NOT driven end to end, and is reported as a failure naming the
     reader that is missing or incompatible.
  4. THE NEGATIVE CONTROL. The same driver, the same argument shape, against a target where the
     planted weakness is ABSENT — and it must report nothing. A detector that only ever says "found
     something" is worthless. The controls are the product.
  5. AND THE CONTROL IS ITSELF CONTROLLED. A control that is silent because the tool never reached it
     proves nothing at all, so every row also asserts a LIVENESS fact about the control run: ffuf must
     still discover the benign path, nuclei must still match the benign template, sqlmap must be seen
     testing the parameter, hydra's own tally must show the attack ran to completion against a target
     it connected to. Silence is only evidence when we can show the tool was working while it stayed
     silent.
     WHERE THE TOOL'S OWN CONSOLE CANNOT SETTLE THAT, THE TARGET IS ASKED. A row may carry a WITNESS
     that reads the control server's own counters across the leg. hydra's form row does, for a
     measured reason: a run against a twin whose login page had gone missing prints the identical
     console to a correct negative control — module engaged, tally completed, nothing found, no
     error. Only the target knows it was never asked to check a password.
  6. AND WHAT THE ENGINE KEEPS IS SEARCHED FOR THE CREDENTIALS THE ROW HANDED THE TOOL. hydra cracks a
     real password and prints it; that raw stream is the oracle's evidence and stays raw. What must
     never carry it is anything the engine PERSISTS — the observations a reader minted and the signed
     spine record — and the rows that supply a credential assert exactly that, by search, per leg.

Every expectation is ASSERTED and the process exits non-zero the moment reality stops matching the
claim. A live-fire script that only prints and never fails is a demo, not a proof.

WHAT A ROW MEANS, HONESTLY. Everything counted here is a LEAD produced by a third-party tool. It is
NOT an oracle-confirmed fact, and nothing in this harness confirms that a vulnerability exists. The
engine's own import path says so in code: ``imports.to_observations`` mints these as
``lead: True, unverified: True`` at deliberately low confidence, and a FINDING is only what a CRUCIBLE
oracle re-verified from first-party evidence. This harness proves the PLUMBING — build, run, read, and
stay quiet on a clean control — and claims nothing more.

ADDING A TOOL IS ADDING A ROW. Waves of new builders are coming; each is provable by appending one
``ToolProof`` to ``TABLE``. The harness cross-checks ``TABLE`` against the executor's own ``_BUILDERS``
and reports every builder that has no row, so a new builder cannot quietly arrive unproven.

AND IT ISOLATES ITSELF RATHER THAN ASKING TO BE RUN CAREFULLY. Three copies of this harness were
once observed running at once, with two nikto processes writing the same report file. Evidence a
second run corrupted is worse than no evidence, because it still looks like a result. So the
harness takes a machine-wide RUN LOCK before anything shared is touched (:func:`acquire_run_lock`),
gives every run its own artifact paths underneath it (:func:`isolate_run_artifacts`), and refuses
up front when the one port the executor PINS is already somebody else's
(:func:`assert_pinned_listener_ports_are_free`). None of that changes what a row asserts — only
what a row's evidence can be confused with.

AUTHORIZATION. targets/loopback/charter.md: a self-hosted, deliberately-vulnerable loopback target
VIGIL stands up and owns, with every tool bound to 127.0.0.0/8. The vulnerable target comes from the
range manifest (integers only; its loopback binding is re-asserted here before anything is sent at
it), and the control servers are started by this process on 127.0.0.1 and die with it. Nothing
external is contacted, and no public test site exists in this file.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import getpass
import html
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
LOOPBACK = "127.0.0.1"

# The engagement slug this harness's authority is minted under. Deliberately its own, so provisioning
# it can never overwrite the authority of a real engagement.
#
# AND DELIBERATELY PER-RUN. The authority store is ONE global directory keyed by slug
# (``framework.v2.common.paths.authority_path`` → ``<v2_root>/.authority/<slug>.authority.json``), while
# each run mints a FRESH keypair and verifies against its OWN trust root. Two runs sharing a slug
# therefore destroy each other: the second's ``save_signed_authority`` overwrites the first's file, and
# the first's next gate call fails with "only 0 valid distinct signature(s) < threshold 1" — every
# remaining row reported as an authorization DENY that has nothing to do with the driver under test.
# That is a false negative dressed as a security result, which is the one outcome this harness must
# never produce. The pid makes the slug unique per run; :func:`_forget_authority` removes it afterwards
# so the store does not accumulate. Nothing about the authority itself is relaxed — it is still real,
# signed, loopback-scoped, and verified against the trust root that signed it.
SLUG = f"livefire-tool-drivers-{os.getpid()}"


def _forget_authority() -> None:
    """Remove this run's signed authority from the shared store. Total — a store that cannot be
    reached is not a reason to fail a proof run that has already finished."""
    try:
        from framework.v2.common import paths
        os.unlink(paths.authority_path(SLUG))
    except Exception:  # noqa: BLE001 — best-effort cleanup of a short-lived, loopback-scoped artifact
        pass

# The range target the vulnerable side of the web rows points at. It is the repository's own app: no
# image to pull, a known planted weakness, and the range asserts its loopback binding four ways at
# start. Point this at another range target (juice, dvwa, …) to drive the same rows against it.
RANGE_TARGET = os.environ.get("VIGIL_LIVEFIRE_RANGE_TARGET", "vulnapp")

# A tool that is absent cannot be proven. That is not a passing result, so it fails by default; name a
# tool here to acknowledge it as known-missing and downgrade it to a reported SKIP.
ALLOW_MISSING = {t.strip().lower() for t in
                 (os.environ.get("VIGIL_LIVEFIRE_ALLOW_MISSING") or "").split(",") if t.strip()}

# Builders that exist in the executor but have no row here are always reported; this makes them fail
# the run (turn it on once a wave's rows have landed).
STRICT_ALL_BUILDERS = os.environ.get("VIGIL_LIVEFIRE_STRICT_BUILDERS") == "1"

# A SUBSET of the rows, so a per-PR CI job can prove the drivers whose tools install in seconds while
# the full table (which needs a JVM and three Go binaries, ~69 min) runs nightly.
#
# THE HONESTY REQUIREMENT THAT COMES WITH IT. A run that silently drove 3 of 10 rows and printed the
# same green verdict as a full run would be the exact overclaim this harness exists to prevent — the
# reader cannot see what was not attempted. So a filtered run: names every row it EXCLUDED in the
# table and the honesty block, and refuses the unqualified "every driver" verdict. Filtering changes
# what is ATTEMPTED; it never changes what a passing row MEANS.
ONLY_TOOLS = {t.strip().lower() for t in
              (os.environ.get("VIGIL_LIVEFIRE_ONLY") or "").split(",") if t.strip()}

BOLD, DIM, RED, GREEN, YELLOW, OFF = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"
if not sys.stdout.isatty():
    BOLD = DIM = RED = GREEN = YELLOW = OFF = ""


def say(msg: str) -> None:
    print(f"\n{BOLD}{msg}{OFF}")


def info(msg: str) -> None:
    print(f"   {msg}")


def die(msg: str) -> None:
    print(f"\n   {RED}STOP{OFF} {msg}", file=sys.stderr)
    raise SystemExit(2)


# =====================================================================================================
# The run lock, and per-run artifact paths beneath it — ONE live-fire on this machine at a time
# =====================================================================================================
#
# WHY THIS IS IN THE HARNESS AND NOT IN A WRAPPER AROUND IT. Three copies of this harness were observed
# running at once, with two nikto processes writing the same report file. A harness that has to be RUN
# carefully will eventually be run carelessly, so it isolates itself. What concurrent runs actually
# share, none of it owned exclusively by any of them:
#
#   * THE RANGE TARGET. One run's teardown (``range.sh down``) destroys the target a sibling is still
#     scanning. The sibling's tools then report nothing — which is precisely what a driver that found
#     nothing reports. A false negative wearing the clothes of a clean control is the one result this
#     harness must never produce.
#   * THE REPORT ARTIFACTS. ``live.executor._report_path`` names a report
#     ``<tempfile.gettempdir()>/vigil-live-reports/<tool>-<sha256(tool|target)[:16]>.json`` — derived
#     from the tool and the PINNED TARGET and nothing else, and both are identical across runs of this
#     harness. Two runs of the same row therefore collide on the byte: each unlinks the other's report
#     on the way in, and whoever reads last reads whatever happens to be there.
#   * THE PINNED ZAP PROXY PORT. ``live.executor._ZAP_PROXY_PORT`` is one fixed port, pinned precisely
#     so that a scan does not depend on what else the operator is running. The SECOND ZAP to start
#     exits 1 after about ten seconds with "Failed to start the main proxy: Address already in use" and
#     writes no report at all, while the executor sees a process that ran to completion.
#
# THE LOCK IS THE GUARD; THE UNIQUE PATHS ARE THE SAFETY NET. :func:`acquire_run_lock` refuses a second
# run outright, naming the one that holds it. :func:`isolate_run_artifacts` then re-points this PROCESS
# at a temporary root only this run can name, so even a lock that somehow failed could not make two runs
# write the same file. Both, deliberately — the same reason the range asserts its loopback binding four
# separate ways.
#
# AND NOTHING HERE RELAXES AN ASSERTION. No row's signal, liveness fact or control is touched. The
# isolation only stops one run's evidence from being confused with another run's.

# Deliberately a name nothing else uses. ``/tmp/vigil-livefire`` was already in use on this box as an
# ad-hoc scratch directory, and a lock whose directory somebody else may delete and recreate is a lock
# that quietly stops holding the ownership claims stored beside it.
_LOCK_DIR_NAME = "vigil-livefire-runlock"
_LOCK_FILE_NAME = "tool-drivers.lock"

# Exported by ``tool_drivers_livefire.sh``, which takes the lock before it touches the range. They let
# this process recognise the holder as its OWN launcher instead of refusing to run underneath it — see
# :func:`_holder_is_our_launcher`, which does not take their word for it.
LOCK_PATH_ENV = "VIGIL_LIVEFIRE_LOCK"
LOCK_NONCE_ENV = "VIGIL_LIVEFIRE_LOCK_NONCE"
LOCK_PID_ENV = "VIGIL_LIVEFIRE_LOCK_PID"

# The exit code a refused run returns, kept distinct from the 1 a failed expectation returns and the 2
# :func:`die` returns: "somebody else is already running" is not a live-fire result, and a caller that
# treats it as one would record a driver failure that never happened.
LOCK_BUSY_EXIT = 3

# Captured at import, BEFORE :func:`isolate_run_artifacts` re-points this process at its own per-run
# temporary root. The lock has to live where every run agrees to look, which is exactly what a per-run
# root is not.
_HOST_TMPDIR = tempfile.gettempdir()


def _private_dir(path: str) -> Optional[str]:
    """Create and validate ``path`` as a private 0700 directory this euid owns, or return None.

    The same test ``live.executor._report_root`` applies to the report root, for the same reason: a
    directory another local user can pre-create is a directory in which they can plant a symlink and
    redirect what we write. Every caller REFUSES on None — there is no fallback to somewhere
    world-writable, because a lock nobody else respects is worse than no lock at all."""
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        st = os.lstat(path)                       # lstat, not stat: a symlink here must NOT resolve
    except (OSError, ValueError):
        return None
    if not stat.S_ISDIR(st.st_mode):
        return None
    euid_of = getattr(os, "geteuid", None)
    if callable(euid_of) and st.st_uid != euid_of():
        return None
    if st.st_mode & 0o077:                        # group/other access ⇒ someone else could plant one
        try:
            os.chmod(path, 0o700)
            st = os.lstat(path)
        except OSError:
            return None
        if st.st_mode & 0o077:
            return None
    return path


def lock_path() -> str:
    """The one path every run of this harness locks on, created if absent. Dies rather than returning a
    path that could not be made private — see :func:`_private_dir`.

    ``tool_drivers_livefire.sh`` asks for this path (``--lock-path``) instead of spelling it itself, so
    the shell and the Python cannot drift onto two different locks and leave both of them "locked" and
    neither of them exclusive."""
    directory = _private_dir(os.path.join(_HOST_TMPDIR, _LOCK_DIR_NAME))
    if directory is None:
        die(f"cannot establish a private run-lock directory at "
            f"{os.path.join(_HOST_TMPDIR, _LOCK_DIR_NAME)}.\n"
            "        It must be a real directory, owned by this user, with no group or other access.\n"
            "        Refusing to run unlocked: a second live-fire run corrupts this one's evidence.")
    path = os.path.join(directory, _LOCK_FILE_NAME)
    try:
        # O_NOFOLLOW and no O_TRUNC: create it if absent, never follow a symlink into it, and never
        # erase a holder record that a run currently being refused still needs to quote.
        os.close(os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600))
    except OSError as exc:
        die(f"cannot open the run lock at {path}: {exc}")
    return path


def _holder_record(path: str) -> dict:
    """What the lock's current holder wrote about itself. ``{}`` when there is nothing readable there —
    which a caller must report as an UNIDENTIFIED holder, never as an absent one: the lock is held by
    the kernel's flock, not by this file, and a holder that has not yet written its record still holds
    it. Total — never raises."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            record = json.loads(fh.read(8192) or "{}")
    except (OSError, ValueError):
        return {}
    return record if isinstance(record, dict) else {}


def describe_holder(record: dict) -> str:
    """The holder, in the words it wrote about itself, for a refusal message that names somebody.

    The record is quoted, not trusted. It is written a moment AFTER the lock is taken, so a run that
    arrives inside that window reads the PREVIOUS holder's record and would otherwise name the wrong
    process with total confidence. Whether the pid it names is still alive is therefore checked and
    said out loud — the lock is held by the kernel either way, so this changes no decision, only how
    honestly the refusal describes what it knows."""
    if not record:
        return ("an unidentified run — it holds the lock but has not written a holder record.\n"
                "        Find it with:   ps -ef | grep -i livefire")
    who = f"pid {record.get('pid', '?')} ({record.get('user', '?')}@{record.get('host', '?')})"
    lines = [who,
             f"        started   : {record.get('started', 'unknown')}",
             f"        running   : {record.get('purpose', 'a VIGIL live-fire run')} "
             f"against range target '{record.get('target', '?')}'"]
    if not _process_alive(record.get("pid")):
        lines.append("        NOTE      : that process is gone, so this record is stale — the lock is "
                     "held by a\n                    run that has not written its own record yet. "
                     "Retry in a moment.")
    return "\n".join(lines)


def refusal_text(path: str, record: dict) -> str:
    """Why a second run is refused rather than queued, in full, once — quoted by both the Python
    harness and the ``--lock-holder`` mode the shell driver prints from."""
    return ("another VIGIL live-fire tool-driver run already holds the run lock.\n"
            f"        lock      : {path}\n"
            f"        held by   : {describe_holder(record)}\n"
            "\n"
            "        Two runs share the range target, the executor's report artifacts and the port the\n"
            "        executor pins for ZAP's proxy listener, so a second run would CORRUPT the first's\n"
            "        evidence rather than merely slow it down — and corrupted evidence still looks like\n"
            "        a result. Wait for that run to finish, or stop it.")


def _process_alive(pid: Any) -> bool:
    """Is ``pid`` a live process? A PermissionError means it exists and belongs to somebody else.

    Anything that is not a POSITIVE pid is answered no without asking the kernel:
    ``os.kill(0, 0)`` addresses this process's whole group, so a record naming 0 would otherwise
    answer yes to itself."""
    try:
        number = int(pid)
    except (TypeError, ValueError):
        return False
    if number <= 0:
        return False
    try:
        os.kill(number, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _holder_is_our_launcher(path: str, record: dict) -> bool:
    """Is the process holding the lock the launcher that started US?

    ``tool_drivers_livefire.sh`` takes the lock before it touches the range and then runs this file as a
    child, so this process CANNOT take the lock and must not treat that as a reason to refuse. The proof
    is the nonce: the shell generates 128 random bits, writes them into the holder record, and exports
    them, so a record whose nonce matches the one in our environment was written by the very process
    whose environment we inherited. Nothing else could know it.

    Everything else here closes a gap that a nonce alone would leave. The pid must match too, the lock
    file must be the one the launcher named, and the launcher must still be ALIVE — otherwise a dead
    launcher's leftover record, with a genuinely different run holding the lock behind it, would read as
    inheritance and let two runs proceed on the strength of a stale environment variable."""
    nonce = os.environ.get(LOCK_NONCE_ENV, "")
    pid = os.environ.get(LOCK_PID_ENV, "")
    named = os.environ.get(LOCK_PATH_ENV, "")
    if not nonce or not pid:
        return False
    if named and os.path.realpath(named) != os.path.realpath(path):
        return False
    return (str(record.get("nonce") or "") == nonce
            and str(record.get("pid") or "") == pid
            and _process_alive(pid))


@dataclass
class RunLock:
    """A held run lock. ``inherited`` means our launcher holds it and we are running underneath it."""

    path: str
    nonce: str
    inherited: bool
    holder: dict
    fd: Optional[int] = None

    @property
    def holder_pid(self) -> Any:
        return self.holder.get("pid")


# Module-global on purpose: the lock lives as long as the descriptor that holds it, and a descriptor
# that only a local variable referenced would be closed — silently releasing the lock mid-run — the
# moment the frame that took it returned.
_HELD_LOCK: Optional[RunLock] = None


def acquire_run_lock(purpose: str, *, target: str = RANGE_TARGET) -> RunLock:
    """Take the machine-wide live-fire run lock, or refuse fast naming whoever holds it.

    An advisory flock on a descriptor held for the life of the process, so the kernel releases it
    however this process ends — including SIGKILL. There is no stale lock to clear and no "is that pid
    still alive" guess to get wrong; the record beside it names the holder, but the record is not the
    lock. NON-BLOCKING deliberately: a second run that waited would eventually start, and by then the
    operator would have forgotten it was queued behind an eight-minute scan."""
    global _HELD_LOCK
    path = lock_path()
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        die(f"cannot open the run lock at {path}: {exc}")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        # CONTENDED is EAGAIN/EWOULDBLOCK and nothing else. Any other errno means locking did not
        # WORK here — no lockd on an NFS mount, a filesystem that does not support it — and
        # reporting that as "another run holds it" would be a comfortable lie that sends the
        # operator looking for a process that does not exist. Fail closed, with the real reason:
        # an unlocked run is exactly what this is here to prevent.
        if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
            os.close(fd)
            die(f"the run lock at {path} could not be taken, and NOT because another run holds "
                f"it: {exc}.\n"
                "        Locking has to work for two runs to be kept apart, so this refuses "
                "rather than\n        running unlocked. A local filesystem for TMPDIR fixes it.")
        record = _holder_record(path)
        os.close(fd)
        if _holder_is_our_launcher(path, record):
            _HELD_LOCK = RunLock(path=path, nonce=str(record.get("nonce") or ""),
                                 inherited=True, holder=record)
            return _HELD_LOCK
        print(f"\n   {RED}STOP{OFF} {refusal_text(path, record)}", file=sys.stderr)
        raise SystemExit(LOCK_BUSY_EXIT)
    record = {"pid": os.getpid(), "nonce": base64.b16encode(os.urandom(16)).decode().lower(),
              "user": _current_user(), "host": socket.gethostname(),
              "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "purpose": purpose, "target": target}
    # Written only NOW, after the lock is held, so two runs can never interleave their records — and
    # through the SAME descriptor that holds the lock, so there is no second open to race with.
    try:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, (json.dumps(record) + "\n").encode("utf-8"))
    except OSError as exc:
        die(f"holding the run lock at {path} but cannot write the holder record: {exc}")
    _HELD_LOCK = RunLock(path=path, nonce=str(record["nonce"]), inherited=False, holder=record, fd=fd)
    return _HELD_LOCK


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 — no passwd entry and no environment is not a reason to fail
        return "unknown"


def isolate_run_artifacts(workdir: str) -> str:
    """Give THIS run its own temporary root, so no two runs can name the same artifact file.

    The safety net under the lock, for the failure the lock is supposed to prevent.
    ``live.executor._report_path`` derives a report's name from the tool and the target — both constant
    across runs of this harness — under ``tempfile.gettempdir()``. Re-pointing the PROCESS's temporary
    root moves that whole tree (the reports, wapiti's session store, ZAP's home) inside this run's own
    workdir WITHOUT TOUCHING THE EXECUTOR: the same allocation code runs, at a path only this run can
    name. TMPDIR/TEMP/TMP are exported too, so the tools' own scratch files follow the same way.

    It also gets the artifacts deleted with the workdir at the end of a passing run and kept beside the
    fixtures after a failing one, instead of accumulating in the operator's ``/tmp`` forever.

    AND IT IS CHECKED, NOT HOPED FOR. The executor's own allocator is asked where it would put a report
    and the answer must be inside this run's root. If the executor ever stops deriving that path from
    the process temporary root, this function silently stops isolating anything — so it stops the run
    and says so. That is a defect to report, not one to discover later inside a corrupted artifact."""
    root = os.path.join(workdir, "tmp")
    if _private_dir(root) is None:
        die(f"cannot create this run's private temporary root at {root}")
    for var in ("TMPDIR", "TEMP", "TMP"):
        os.environ[var] = root
    tempfile.tempdir = root          # in-process: what the executor's own gettempdir() now returns
    try:
        from vigil_integration.live import executor
    except ImportError as exc:
        die(f"cannot import the engine's executor to confirm this run's artifacts are isolated: {exc}")
    allocator = getattr(executor, "_report_root", None)
    if not callable(allocator):
        die("live.executor no longer exposes _report_root, so this harness cannot confirm that two "
            "concurrent runs would not share a report artifact.\n"
            "        The isolation this run depends on may no longer be doing anything. Re-point it at\n"
            "        whatever allocates report paths now, rather than running without it.")
    seen = allocator()
    inside = os.path.realpath(root) + os.sep
    if not seen or not os.path.realpath(seen).startswith(inside):
        die("the engine's report artifacts are NOT isolated to this run.\n"
            f"        this run's temporary root : {root}\n"
            f"        executor._report_root()   : {seen}\n"
            "        It no longer derives that from the process temporary root, so two concurrent runs\n"
            "        would write the same report file and each would read back the other's bytes.")
    return root


def assert_pinned_listener_ports_are_free() -> None:
    """The one shared resource per-run isolation CANNOT move out of the way.

    ZAP starts its main proxy listener even for a one-shot headless scan, and the executor pins it
    to a single port so a scan does not depend on what else is running on the box. A pinned port is by
    definition not a per-run resource: if anything already holds it, ZAP exits 1 after about ten seconds
    having written no report, and the executor sees a process that ran to completion. The row would then
    fail for the wrong reason — "the engine's reader read nothing" — naming a defect that is not there.

    So the question is asked before any tool runs, and whoever has the port is named. The run lock keeps
    a SIBLING RUN of this harness off it; this catches whatever else on the machine already has it.

    WHAT NEITHER OF THEM CATCHES, stated rather than implied: a process that takes the port AFTER this
    check and is not a run of this harness. Measured on this box while proving the lock — another
    process was driving ``executor._BUILDERS["zaproxy"]`` directly, so it never took the lock, and it
    held 18099 and wrote into the shared report root at the same time. A lock cannot bind code that does
    not take it, and the harness cannot move a port the EXECUTOR pins. The failure mode that leaves is
    an empty ZAP report reported as a reader failure — a row that fails for the wrong reason, which is
    visible, rather than a row that passes for the wrong reason, which is not. Un-pinning that port
    per-run is the executor's to do; nothing here can."""
    if not any(getattr(proof, "tool", "") == "zaproxy" for proof in TABLE):
        return
    try:
        from vigil_integration.live import executor
    except ImportError as exc:
        die(f"cannot import the engine's executor: {exc}")
    port = getattr(executor, "_ZAP_PROXY_PORT", None)
    if not isinstance(port, int):
        info(f"{YELLOW}note{OFF} live.executor no longer pins a ZAP proxy port, so this harness cannot "
             "check it is free; a port held by something else would show up as an empty ZAP report")
        return
    listening = _listen_addrs(port)
    if not listening:
        info(f"{GREEN}ok  {OFF}the port the executor pins for ZAP's proxy listener ({port}) is free")
        return
    die(f"the port the executor pins for ZAP's main proxy listener ({port}) is already in use.\n"
        f"        listening on : {', '.join(listening)}\n"
        f"        holder       : {_port_holder(port) or 'not reported by ss'}\n"
        "        ZAP would exit after ~10s having written no report, and the executor would see a\n"
        "        process that ran to completion — a silent no-op scan reported as a reader failure.\n"
        f"        Free it, or stop whatever holds it:   ss -ltnp | grep {port}")


def _port_holder(port: int) -> str:
    """Whoever the kernel says is listening on ``port``, for a message that names a culprit rather than
    describing a symptom. Empty when ``ss`` cannot say (it needs privileges to name another user's
    process) — which is reported as unknown, never as nobody."""
    try:
        res = subprocess.run(["ss", "-ltnpH", f"sport = :{int(port)}"],
                             capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return " ".join(res.stdout.split())


# =====================================================================================================
# The range — read from the manifest, never hardcoded here
# =====================================================================================================
#
# THE CONVENTION (the contract with range.sh): ONE file, tools/livefire/range_targets.json, is where
# target facts are written down. range.sh drives docker from it and range_targets.py exposes it to
# Python, so there is no second copy of a port to drift. This harness reads it through
# range_targets.py for the same reason — a port changed there changes here, and re-implementing the
# manifest reader would only add a third copy. The manifest cannot express a host address at all
# (ports are plain integers); the loopback binding is re-asserted below regardless, and the executor
# refuses a non-loopback target independently. All three, on purpose.


def load_range_target(name: str):
    """The range's own record for ``name``, its first HTTP port, and the range module itself."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    try:
        import range_targets  # noqa: PLC0415 — the sibling range module IS the manifest reader
    except ImportError as exc:
        die(f"cannot import the range manifest reader ({HERE}/range_targets.py): {exc}")
    try:
        target = range_targets.Manifest().get(name)
    except Exception as exc:  # noqa: BLE001 — a bad/missing manifest is a hard stop, never a default
        die(f"the range manifest has no usable target {name!r}: {exc}")
    ports = [p for p in getattr(target, "ports", []) if getattr(p, "name", "") == "http"]
    ports = ports or list(getattr(target, "ports", []))
    if not ports:
        die(f"range target {name!r} declares no ports")
    return target, int(ports[0].host), range_targets


def assert_target_live(port: int, what: str) -> None:
    """The target must be up AND loopback-only before a single packet is sent at it."""
    if not _listening(port):
        die(f"nothing is listening on 127.0.0.1:{port} ({what}).\n"
            f"        Bring the range up first:   tools/livefire/range.sh up {RANGE_TARGET}")
    off_loopback = [a for a in _listen_addrs(port) if not _is_loopback_addr(a)]
    if off_loopback:
        die(f"{what} on port {port} is listening on {off_loopback} — NOT loopback-only. "
            "Refusing to run (charter hard limit).")


def _listen_addrs(port: int) -> list:
    """Every address currently listening on ``port``, read from the host's own socket table."""
    out: list = []
    try:
        res = subprocess.run(["ss", "-ltnH"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return out
    for line in res.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        addr, _, p = fields[3].rpartition(":")
        if p == str(port):
            out.append(addr.strip("[]") or "0.0.0.0")
    return out


def _is_loopback_addr(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _listening(port: int, host: str = LOOPBACK) -> bool:
    with socket.socket() as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) == 0


def free_port() -> int:
    """A port the OS has just confirmed is free. Used for the control servers, and — left deliberately
    unbound — for the closed-port control the network drivers need."""
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        return int(s.getsockname()[1])


# =====================================================================================================
# The clean control — the same surface with each weakness removed
# =====================================================================================================
#
# The range ships deliberately-vulnerable applications; it ships no hardened twin, and a negative
# control has to be a target where the weakness is genuinely ABSENT rather than one that is merely
# different. So this process serves one: the same routes as the range's vulnapp, each written safely.
#
#   /             a marker page, so a benign liveness template can match here too
#   /about        200 — a benign discoverable path, so ffuf's silence on /api/users cannot be confused
#                 with ffuf failing to discover anything at all
#   /api/users    404 — the sensitive endpoint is NOT exposed, and does not announce itself with a 401
#                 either (a 401 is still a hit for a content scanner)
#   /search?q=    200, reflects q HTML-ESCAPED and queries with a PARAMETERIZED statement. It still
#                 reflects, and is still dynamic, so a scanner has a real live parameter to work on —
#                 it simply cannot break it. That is what makes it a control instead of a dead end.
#
# and, for the credential rows, the same server with a LOGIN in front of it, in two shapes and two
# flavours each. The weakness a credential attack looks for is "guessable", so its absence is the same
# login with a password that is not guessable — the twin therefore comes as a guessable/unguessable
# pair for each shape:
#
#   HTTP Basic   every path behind a 401 challenge          (drives hydra's `http-get` module)
#   a FORM POST  /login accepts a posted username+password  (drives hydra's `http-post-form` module)
#
# THE FORM EXISTS BECAUSE THE BASIC-AUTH TWIN CANNOT PROVE IT. `_build_hydra` can express a form spec
# (path / body / condition), it is unit-tested against verbatim hydra 9.7 output, and until this twin
# it had never met a real form: the only credential twin served no login form, so the passing row
# proved `http-get` and said nothing whatever about `http-post-form`. A capability that is claimed and
# unexercised is the thing this whole harness exists to refuse.

# The control's rows are the SAME rows the range's vulnapp holds. That symmetry is load-bearing: a
# scanner decides whether a parameter is worth attacking by watching the response CHANGE, so a probe
# value that returns a row on one target and nothing on the other would be testing two different
# things. (Learned the hard way — a value absent from the vulnerable target's data made sqlmap call
# the parameter static and skip it, which reads in the table exactly like a broken driver.)
_TWIN_ROWS = [(1, "apple"), (2, "banana"), (3, "test")]
_PROBE_VALUE = "apple"   # a value that returns exactly one row on BOTH targets
_TWIN_USER = "admin"
_TWIN_WEAK_PASSWORD = "letmein"                                  # present in the harness passlist
_TWIN_STRONG_PASSWORD = "n0t-in-any-wordlist-9f3c2a17b845de60"   # absent from it

# The form twin's contract with the hydra row. These four values are the ONLY place the form is
# described: the twin serves them and the row's `form_path`/`form_body`/`form_fail` are read from the
# same constants, so the spec hydra is given and the form it meets cannot drift apart silently. (They
# still CAN drift in the way that matters — a path the twin no longer serves — and hydra's console is
# blind to exactly that; see `_form_witness` for the measurement and the guard.)
_TWIN_FORM_PATH = "/login"
_TWIN_FORM_BODY = "username=^USER^&password=^PASS^"
_TWIN_FORM_FAIL = "Invalid credentials"       # the recognisable failure string hydra's `F=` keys on
_TWIN_FORM_OK = "Signed in as admin"          # and what a correct pair gets instead


@dataclass
class FormLedger:
    """What the FORM TWIN ITSELF saw — the target-side reading of what the tool actually did.

    WHY A TARGET-SIDE LEDGER AT ALL, when the row already asserts a liveness fact about hydra's own
    console. Because that console cannot distinguish the case that matters. Measured on this host
    (hydra 9.7), a run against a twin whose ``/login`` had gone missing — hydra attacking a 404 —
    prints::

        [DATA] attacking http-post-form://127.0.0.1:49395/login:username=^USER^&password=^PASS^:F=…
        1 of 1 target completed, 0 valid password found

    which is byte-for-byte the shape of a CORRECT negative control: the module engaged, the tally
    completed, no error, nothing found. A console-only liveness fact certifies it as evidence. The
    twin's own counters do not: it served zero login attempts, and that is unambiguous.

    Nothing here stores a credential. ``weak_attempts`` counts the submissions whose password EQUALS
    the value the guessable twin accepts — a comparison against a constant this module already holds
    — so the row can prove the wordlist's live entry was actually offered to the control without the
    ledger ever holding a value of its own."""

    posts: int = 0            # login submissions the twin PROCESSED (POSTs that reached the form)
    successes: int = 0        # ... that authenticated
    weak_attempts: int = 0    # ... that offered the password the GUESSABLE twin accepts
    lock: Any = field(default_factory=threading.Lock)

    def record(self, *, ok: bool, was_weak: bool) -> None:
        with self.lock:
            self.posts += 1
            self.successes += int(ok)
            self.weak_attempts += int(was_weak)

    def snapshot(self) -> tuple:
        with self.lock:
            return (self.posts, self.successes, self.weak_attempts)


class _TwinHandler(http.server.BaseHTTPRequestHandler):
    """One handler, three mutually exclusive shapes, set per subclass by :func:`start_twin`:
    ``auth_password`` (HTTP Basic on every path), ``form_password`` (a POST login form), or neither
    (the hardened web twin)."""

    protocol_version = "HTTP/1.1"
    server_version = "vigil-control/1.0"
    auth_password: Optional[str] = None
    form_password: Optional[str] = None
    ledger: Optional[FormLedger] = None
    db: Any = None
    lock: Any = None

    # A login body is three short fields. The cap is here so a malformed Content-Length cannot make
    # the twin allocate on demand — it is a control server, not a target.
    _MAX_BODY = 64 * 1024

    def log_message(self, *args: Any) -> None:  # noqa: A003 — silence the per-request stderr log
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html", headers: tuple = ()) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode("utf-8", "replace").partition(":")
        except (ValueError, TypeError):
            return False
        return user == _TWIN_USER and password == self.auth_password

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's interface
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if self.auth_password is not None:
            # The credential control in its HTTP BASIC shape: every path sits behind the challenge.
            # The row driving it supplies no form spec, so `_build_hydra` emits no `-m` and hydra's
            # http-get module attacks "/" — which is why a 401 has to be what it finds there.
            if not self._authorized():
                self._send(401, "<p>authentication required</p>",
                           headers=(("WWW-Authenticate", 'Basic realm="vigil-control"'),))
                return
            self._send(200, "<h1>VIGIL control — authenticated</h1>")
            return

        if self.form_password is not None:
            # The credential control in its FORM shape. GET only renders; the credential decision is
            # made in do_POST, which is the request hydra's http-post-form module actually sends.
            if parsed.path == _TWIN_FORM_PATH:
                self._send(200, self._login_page())
            elif parsed.path == "/":
                self._send(200, "<h1>VIGIL form control</h1>"
                                f"<a href='{_TWIN_FORM_PATH}'>sign in</a>")
            else:
                self._send(404, "<h1>404 Not Found</h1>")
            return

        if parsed.path == "/":
            self._send(200, "<h1>VIGIL hardened control</h1><a href='/search?q=test'>search</a>")
        elif parsed.path == "/about":
            self._send(200, "<p>The hardened twin of the loopback target: same routes, no weaknesses.</p>")
        elif parsed.path == "/search":
            self._search(qs.get("q", [""])[0])
        else:
            self._send(404, "<h1>404 Not Found</h1>")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's interface
        """The form login. The body is drained FIRST, unconditionally: this is a keep-alive HTTP/1.1
        server and an unread body desynchronises every later request on the same connection — which
        hydra, running several tasks over persistent connections, would see as a target that fails
        intermittently and this harness would see as a flaky control."""
        body = self._read_body()
        if self.auth_password is not None and not self._authorized():
            # A basic-auth twin answers a POST the way it answers everything else. Letting it 404 an
            # unauthenticated POST would make one verb on the control behave unlike the rest of it.
            self._send(401, "<p>authentication required</p>",
                       headers=(("WWW-Authenticate", 'Basic realm="vigil-control"'),))
            return
        if self.form_password is None or urllib.parse.urlsplit(self.path).path != _TWIN_FORM_PATH:
            self._send(404, "<h1>404 Not Found</h1>")
            return
        fields = urllib.parse.parse_qs(body)
        user = (fields.get("username") or [""])[0]
        password = (fields.get("password") or [""])[0]
        ok = user == _TWIN_USER and password == self.form_password
        if self.ledger is not None:
            self.ledger.record(ok=ok, was_weak=password == _TWIN_WEAK_PASSWORD)
        # BOTH outcomes are a 200 that differs only in its body. That is what makes the row a test of
        # the FORM: hydra's `F=` condition has to read the page, and a status-code or redirect
        # differential would let it succeed without ever looking at one.
        if ok:
            self._send(200, f"<h1>{_TWIN_FORM_OK}</h1>")
        else:
            self._send(200, f"{self._login_page()}<p class='error'>{_TWIN_FORM_FAIL}</p>")

    def _read_body(self) -> str:
        """The request body, bounded. Total — a malformed/absent length is an empty body, never an
        exception that would kill this connection mid-attack and be read as the target dying."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            return ""
        if length <= 0:
            return ""
        try:
            return self.rfile.read(min(length, self._MAX_BODY)).decode("utf-8", "replace")
        except OSError:
            return ""

    def _login_page(self) -> str:
        return ("<h1>Sign in</h1>"
                f"<form method='post' action='{_TWIN_FORM_PATH}'>"
                "<input name='username' type='text'>"
                "<input name='password' type='password'>"
                "<button type='submit'>Sign in</button></form>")

    def _search(self, q: str) -> None:
        """The whole point of the control: a live, dynamic, reflecting parameter that is nevertheless
        neither injectable nor XSS-able. Parameterized SQL, escaped output."""
        with self.lock:
            cur = self.db.cursor()
            cur.execute("SELECT id, name FROM items WHERE name = ?", (q,))
            rows = cur.fetchall()
        self._send(200, f"<h1>Results for: {html.escape(q)}</h1>"
                        f"<ul>{''.join(f'<li>{r[0]}:{r[1]}</li>' for r in rows)}</ul>")


@dataclass
class Twin:
    name: str
    port: int
    server: Any
    thread: Any
    ledger: Optional[FormLedger] = None   # form twins only — see :class:`FormLedger`

    @property
    def url(self) -> str:
        return f"http://{LOOPBACK}:{self.port}/"

    @property
    def form_url(self) -> str:
        return f"http://{LOOPBACK}:{self.port}{_TWIN_FORM_PATH}"


def start_twin(name: str, *, auth_password: Optional[str] = None,
               form_password: Optional[str] = None) -> Twin:
    """Start one control server on a free loopback port, inside this process, dying with it."""
    if auth_password is not None and form_password is not None:
        die(f"twin {name!r} asks for BOTH HTTP Basic and a form login. A form twin behind a 401 "
            "would answer hydra's form module with a challenge page, and every password would look "
            "like a hit — refusing to build a control that manufactures false positives")
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    db.executemany("INSERT INTO items VALUES (?, ?)", _TWIN_ROWS)
    db.commit()

    ledger = FormLedger() if form_password is not None else None
    handler = type(f"_Twin_{name}", (_TwinHandler,),
                   {"auth_password": auth_password, "form_password": form_password,
                    "ledger": ledger, "db": db, "lock": threading.Lock()})
    port = free_port()
    server = http.server.ThreadingHTTPServer((LOOPBACK, port), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name=f"twin-{name}", daemon=True)
    thread.start()
    return Twin(name=name, port=port, server=server, thread=thread, ledger=ledger)


def http_get(url: str, *, auth: Optional[tuple] = None, timeout: float = 5.0) -> tuple:
    req = urllib.request.Request(url, headers={"User-Agent": "VIGIL-LIVEFIRE/1.0 (loopback harness)"})
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — loopback literal only
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, f"<no response: {exc}>"


def http_post_form(url: str, fields: dict, *, timeout: float = 5.0) -> tuple:
    """POST a urlencoded form, exactly as hydra's http-post-form module does."""
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": "VIGIL-LIVEFIRE/1.0 (loopback harness)",
                 "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — loopback literal only
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, f"<no response: {exc}>"


def assert_form_control_is_a_control(form_weak: Twin, form_hard: Twin, passwords: list,
                                     failures: list) -> None:
    """Prove the form pair before hydra ever sees it — the pre-flight the `http-post-form` row rests on.

    Three separate things have to hold, and each of them fails SILENTLY if it does not:

      * the form is a real form — a page that accepts a posted username and password;
      * it says something recognisable on a wrong pair, and something else on the right one. A form
        that answered identically either way gives hydra's `F=` condition nothing to read;
      * and the CONTROL's password is genuinely not in the wordlist, which is asserted by submitting
        EVERY password in that list to it and watching all of them be refused — while its own
        password is accepted. A form that refused everything, including the correct pair, would be a
        broken login rather than a hard one, and would produce exactly the silence a good control
        produces. That is the failure this check exists to separate.
    """
    checks: list = []

    status, body = http_get(form_weak.form_url)
    checks.append(("the form control serves a login page", status == 200, f"status {status}"))
    checks.append(("and it is a real form: a POST with a username and a password field",
                   "method='post'" in body.lower() and "name='username'" in body.lower()
                   and "name='password'" in body.lower(),
                   f"the page is not a login form: {body[:120]!r}"))

    status, body = http_post_form(form_weak.form_url,
                                  {"username": _TWIN_USER, "password": "definitely-wrong"})
    checks.append((f"a wrong password returns the failure string {_TWIN_FORM_FAIL!r}",
                   status == 200 and _TWIN_FORM_FAIL in body and _TWIN_FORM_OK not in body,
                   f"status {status}, body {body[:120]!r}"))

    status, body = http_post_form(form_weak.form_url,
                                  {"username": _TWIN_USER, "password": _TWIN_WEAK_PASSWORD})
    checks.append(("and the ONE known-good pair signs in",
                   status == 200 and _TWIN_FORM_OK in body and _TWIN_FORM_FAIL not in body,
                   f"status {status}, body {body[:120]!r}"))

    # The negative control's soundness: not one entry of the wordlist opens it.
    refused = []
    for password in passwords:
        status, body = http_post_form(form_hard.form_url,
                                      {"username": _TWIN_USER, "password": password})
        refused.append(status == 200 and _TWIN_FORM_FAIL in body and _TWIN_FORM_OK not in body)
    checks.append((f"the form NEGATIVE CONTROL refuses all {len(passwords)} passwords in the wordlist",
                   bool(refused) and all(refused),
                   f"{refused.count(False)} of {len(refused)} were not refused — the control's "
                   "password is IN the list, so its silence would mean nothing"))

    # ... and it is a hard login, not a dead one.
    status, body = http_post_form(form_hard.form_url,
                                  {"username": _TWIN_USER, "password": _TWIN_STRONG_PASSWORD})
    checks.append(("but it DOES sign in with its own, unguessable, password — so it is a working "
                   "login that resisted, not a broken one that refuses everybody",
                   status == 200 and _TWIN_FORM_OK in body,
                   f"status {status}, body {body[:120]!r}"))

    for label, ok, detail in checks:
        print(f"   {GREEN + 'ok  ' + OFF if ok else RED + 'FAIL' + OFF} {label}")
        if not ok:
            failures.append(f"form control pre-flight: {label} — {detail}")


def assert_control_is_a_control(twin: Twin, auth_hard: Twin, failures: list) -> None:
    """Before any tool runs: prove the control will be silent for the RIGHT reason.

    This is the k8s-RBAC harness's rule applied to a web target — refuse to read a conclusion into
    evidence we did not actually get. A control whose /search were dead rather than hardened would
    make every clean-run result below worthless, and would look exactly the same in the table.
    """
    checks: list = []

    status, body = http_get(f"{twin.url}search?q=%3Cvigilmark%3E")
    checks.append(("the control's /search answers", status == 200, f"status {status}"))
    checks.append(("it really does reflect the parameter", "vigilmark" in body,
                   "the marker is absent from the body"))
    checks.append(("but reflects it ESCAPED, so an XSS template must not match",
                   "&lt;vigilmark&gt;" in body and "<vigilmark>" not in body,
                   "the marker came back unescaped — this is NOT a hardened control"))

    status, body = http_get(f"{twin.url}search?q={_PROBE_VALUE}")
    checks.append((f"its query really runs, and {_PROBE_VALUE!r} returns a row here too",
                   status == 200 and f":{_PROBE_VALUE}" in body, f"status {status}, body {body[:80]!r}"))

    status, body = http_get(f"{twin.url}search?q=%27")
    checks.append(("a lone quote does not break it (parameterized, no SQL error)",
                   status == 200 and "error" not in body.lower(), f"status {status}, body {body[:80]!r}"))

    status, _ = http_get(f"{twin.url}about")
    checks.append(("the benign discoverable path /about is present", status == 200, f"status {status}"))

    status, _ = http_get(f"{twin.url}api/users")
    checks.append(("the sensitive path /api/users is NOT exposed", status == 404, f"status {status}"))

    status, _ = http_get(auth_hard.url)
    checks.append(("the credential control challenges for HTTP Basic", status == 401, f"status {status}"))

    status, _ = http_get(auth_hard.url, auth=(_TWIN_USER, _TWIN_STRONG_PASSWORD))
    checks.append(("and accepts its own, unguessable, password", status == 200, f"status {status}"))

    for label, ok, detail in checks:
        print(f"   {GREEN + 'ok  ' + OFF if ok else RED + 'FAIL' + OFF} {label}")
        if not ok:
            failures.append(f"control pre-flight: {label} — {detail}")


def assert_weakness_is_present(range_target: Any, range_targets: Any, failures: list) -> None:
    """And prove the vulnerable side is genuinely vulnerable — with the RANGE's OWN differential
    probe, not our assumption. If the planted weakness is not actually there, a tool that reports
    nothing is RIGHT, and the harness must not read a driver failure into it."""
    probe_name = getattr(range_target, "weakness_probe", None)
    if not probe_name:
        info(f"{DIM}the range declares no weakness probe for this target — nothing to confirm{OFF}")
        return
    try:
        result = range_targets.WEAKNESS_PROBES[probe_name](range_target)
    except Exception as exc:  # noqa: BLE001 — a probe that cannot run is an unknown, never a pass
        print(f"   {RED}FAIL{OFF} the range's own weakness probe could not run: {exc}")
        failures.append(f"the range's weakness probe {probe_name!r} could not run: {exc}")
        return
    present = bool(getattr(result, "present", False))
    print(f"   {GREEN + 'ok  ' + OFF if present else RED + 'FAIL' + OFF} "
          f"the range's own probe ({probe_name}): {getattr(result, 'detail', '')}")
    print(f"        control: {getattr(result, 'control', '')}")
    print(f"        attack:  {getattr(result, 'attack', '')}")
    if not present:
        failures.append(f"the planted weakness is NOT present on {RANGE_TARGET} — a tool reporting "
                        "nothing would be correct, so no driver can be proven against it")


# =====================================================================================================
# Fixtures the builders require as VALUES (never as options)
# =====================================================================================================
#
# Two builders refuse to run without a local file: ffuf needs a wordlist, hydra needs a password list.
# Those are DATA the caller supplies and the builder validates with ``_local_file`` (a URL or a
# non-existent path is refused). Writing them here is not writing a command line.
#
# The nuclei templates are the same kind of thing with one wrinkle worth saying out loud: the
# executor's nuclei builder has NO template selector, so nuclei falls back to its configured template
# directory. This machine has none, and downloading the public template set would be external egress,
# which the charter forbids. So the harness points nuclei at its OWN offline template directory
# through NUCLEI_CONFIG_DIR — environment, inherited by the executor's subprocess; the ARGV remains
# entirely the engine's. An operator deploying the nuclei driver must provision templates the same
# way: a nuclei with no templates matches nothing and reports success while doing so.

_NUCLEI_TEMPLATES = {
    # The signal: the planted weakness. A marker of our choosing, reflected without escaping.
    "vigil-reflected-xss.yaml": """\
id: vigil-reflected-xss
info:
  name: parameter reflected without escaping
  author: vigil-livefire
  severity: medium
  description: The q parameter is echoed into the HTML body unescaped (reflected XSS).
  tags: vigil
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=%3Cvigilmark%3E"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "<vigilmark>"
""",
    # The liveness template: it matches BOTH targets. Its job is to prove, on the clean run, that
    # nuclei loaded templates and reached the target — so the XSS template's silence there means
    # something. Without it, a nuclei that loaded no templates at all would look like a clean control.
    "vigil-service-alive.yaml": """\
id: vigil-service-alive
info:
  name: VIGIL loopback service answered
  author: vigil-livefire
  severity: info
  description: A benign control template matching any VIGIL loopback range service.
  tags: vigil
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "VIGIL"
""",
}


@dataclass
class Fixtures:
    wordlist: str
    passlist: str
    passwords: tuple            # the same list, in memory, for the pre-flight that proves it
    nuclei_config_dir: str


# The credential rows' wordlist. It is DATA the caller hands the builder, and it is the whole meaning
# of both credential controls: the guessable twin's password is in it, the unguessable twin's is not.
# Kept as a tuple so the file on disk and the list the pre-flight submits are one thing.
_PASSWORDS = ("123456", _TWIN_WEAK_PASSWORD, "qwerty")


def write_fixtures(workdir: str) -> Fixtures:
    wordlist = os.path.join(workdir, "paths.txt")
    with open(wordlist, "w", encoding="utf-8") as fh:
        # `about` is the benign liveness word — it exists on both targets. `api/users` is the signal:
        # the sensitive endpoint, present on the vulnerable target and absent on the control.
        fh.write("about\napi/users\nsearch\nnope-xyzzy-absent\n")

    passlist = os.path.join(workdir, "passwords.txt")
    with open(passlist, "w", encoding="utf-8") as fh:
        fh.write("".join(f"{p}\n" for p in _PASSWORDS))

    cfg = os.path.join(workdir, "nuclei-config")
    templates = os.path.join(workdir, "nuclei-templates")
    os.makedirs(cfg, exist_ok=True)
    os.makedirs(templates, exist_ok=True)
    for name, body in _NUCLEI_TEMPLATES.items():
        with open(os.path.join(templates, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    with open(os.path.join(cfg, "config.yaml"), "w", encoding="utf-8") as fh:
        fh.write(f"templates:\n  - {templates}\n")
    open(os.path.join(cfg, ".nuclei-ignore"), "a", encoding="utf-8").close()
    return Fixtures(wordlist=wordlist, passlist=passlist, passwords=_PASSWORDS,
                    nuclei_config_dir=cfg)


# =====================================================================================================
# Governance — the REAL gate, including the m-of-n leg the charter demands of destructive tools
# =====================================================================================================
#
# The charter: "Destructive tools (metasploit/sqlmap/hydra) require the m-of-n threshold gate even
# against loopback." So this harness does not hand the executor a permissive stub. It mints a signed
# CRUCIBLE authority scoped to 127.0.0.1, builds the production conjunctive gate over it, and — for a
# destructive call — mints and owner-signs a single-use DestructionAuthorization bound to exactly that
# (tool, target), burned through the atomic on-disk nonce ledger. Every DENY here is a real DENY.
#
# TWO THINGS THE PRODUCTION WIRING DOES NOT DO, which this harness therefore has to do itself, and
# which it reports rather than papering over:
#   * ``live.wiring.provision_authority`` does not expose ``allow_destructive``, so an authority it
#     mints refuses sqlmap/hydra at the CRUCIBLE leg;
#   * ``live.wiring._build_gate`` passes no ``destruction_authority``, and ``authorize_tool_call``
#     calls the gate with no per-call destruction arguments, so the m-of-n conjunct is never wired and
#     ``conjunctive_decide`` denies a destructive tool outright.
# Both are gaps in REACHING the destructive drivers. Neither is a hole in the gate — the gate is
# fail-closed and behaving exactly as designed.


@dataclass
class Governance:
    signer: Callable[[bytes], Any]
    # The conjunctive gate (CRUCIBLE scope ∧ WARDEN tier ∧ the m-of-n destructive leg) — WITHOUT any
    # approval wrapper. sqlmap/hydra classify A2, so under the A1 ceiling the gate QUEUES them (the WARDEN
    # human leg). The harness supplies that human leg PER ACTION via :func:`approve_action_gate` (W0-11):
    # a single blanket promote-all no longer exists, so a driver of MULTIPLE trusted offense actions must
    # approve each one, exactly as the engine's ``run_tool`` binds each action before executing it.
    base_gate: Callable[..., Any]
    notes: list = field(default_factory=list)


def approve_action_gate(base_gate: Callable[..., Any], tool_name: Any, tool_args: Any) -> Callable[..., Any]:
    """The harness is the TRUSTED human leg, approving EACH offense action individually (W0-11 / #406).

    The standing ``--approve-offense`` grant is no longer a BLANKET boolean that auto-promotes every queued
    WARDEN action — it is a PER-ACTION, single-use :class:`StandingApproval` bound to the ONE action it
    authorizes. So a harness that drives many trusted offense rows can no longer rely on one blanket wrapper;
    it must approve each row on its own, precisely as the engine's ``run_tool`` does before every execution.

    This mints a FRESH single-use grant, binds it to exactly THIS action, and wraps the base gate so the
    grant is SPENT on this one action. The ``(tool, target)`` pair is computed by the executor's OWN
    ``derive_gate_binding`` — with the same default scope/allowed_ips :func:`run_leg`'s ``execute`` uses — so
    it equals the pair the gate is called with BYTE-FOR-BYTE; the ``action_digest`` binds the args. The next
    row mints its own grant (re-granted per action — the operator approving each). An action that is NOT
    bound (an underivable / out-of-scope target, or — at the gate — a DIFFERENT action than the one bound)
    stays QUEUED and is DENIED: no blanket promote-all is reintroduced.
    """
    from vigil_integration.live.approval_token import action_digest
    from vigil_integration.live.executor import derive_gate_binding
    from vigil_integration.live.wiring import StandingApproval, _approval_gate

    standing = StandingApproval(True)
    # scope/allowed_ips default to None here AND in run_leg's execute(), so the loopback-pinned (tool,
    # target) derived here is the exact pair the gate sees inside the executor.
    binding = derive_gate_binding(tool_name, tool_args)
    if binding is not None:
        gtool, gtarget = binding
        try:
            digest = action_digest(gtool, gtarget, tool_args)
        except Exception:  # noqa: BLE001 — a non-serialisable args ⇒ no binding ⇒ the action stays QUEUED
            standing.unbind()
        else:
            standing.bind(gtool, gtarget, digest)
    # binding is None (underivable / out-of-scope target) ⇒ standing stays unbound ⇒ the gate DENIES.
    return _approval_gate(base_gate, standing)


def build_governance(workdir: str) -> Governance:
    from framework.v2.authority.charter import authority_from_scope
    from framework.v2.authority.models import TargetEnvironment
    from framework.v2.authority.signing import sign_authority
    from framework.v2.authority.store import save_signed_authority
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair, sign
    from vigil_integration.conjunctive_gate import build_offense_gate
    from vigil_integration.destruction_gate import (DestructionAuthority, DestructionAuthorization,
                                                    DestructiveAction, sign_authorization)
    from vigil_integration.live.nonce_ledger import NonceLedger
    from vigil_integration.live.wiring import default_classify

    notes: list = []

    # (1) The CRUCIBLE authority: signed, scoped to the loopback literal, short-lived, and explicitly
    #     permitting destructive actions against a TWIN environment — which is what this range is.
    gov = generate_keypair()
    doc = authority_from_scope(SLUG, [LOOPBACK], environment=TargetEnvironment("twin"),
                               duration_hours=1.0, allow_destructive=True, max_actions=500)
    save_signed_authority(sign_authority(doc, {"root0": gov.private_key_b64}))
    trust_root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="root0", name="root0", public_key_b64=gov.public_key_b64)])
    notes.append("live.wiring.provision_authority has no allow_destructive parameter, so an authority "
                 "it mints denies sqlmap/hydra; this harness mints its own")

    # (2) The owner-inclusive quorum for the threshold-destruction leg, and the durable single-use
    #     ledger its nonces are burned in.
    owner = generate_keypair()
    destruction_authority = DestructionAuthority(
        trust_root=TrustRoot(threshold=1, authorizers=[
            AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)]),
        mandatory_signer_ids=frozenset({"owner"}))
    ledger = NonceLedger(os.path.join(workdir, "destruction-nonces"))

    real_gate = build_offense_gate(slug=SLUG, trust_root=trust_root, classify=default_classify,
                                  ceiling="A1", destruction_authority=destruction_authority,
                                  destruction_ledger=ledger)
    notes.append("live.wiring._build_gate wires no destruction authority and authorize_tool_call "
                 "passes no per-call quorum, so as wired today the executor path cannot reach a "
                 "destructive builder at all; this harness supplies both")

    counter = {"n": 0}

    def with_destruction(gate: Callable[..., Any]) -> Callable[..., Any]:
        """Supply the per-call m-of-n authorization the executor's gate call cannot carry. Each call
        gets its OWN action id and nonce, so the ledger burns exactly one per execution and a replay
        of any of them is denied."""
        def wrapped(tool_name: str, target: str, destructive: bool = False, **kw: Any) -> Any:
            if not destructive:
                return gate(tool_name, target, destructive, **kw)
            counter["n"] += 1
            action_id = f"livefire-{counter['n']:03d}-{tool_name}"
            now = time.time()
            action = DestructiveAction(action_id=action_id, engagement_slug=SLUG, target=target,
                                       blast_class="destructive")
            authorization = DestructionAuthorization(
                action_id=action_id, engagement_slug=SLUG, target=target, blast_class="destructive",
                not_before=now - 30.0, not_after=now + 600.0, nonce=action_id)
            signed = sign_authorization(authorization, [("owner", owner.private_key_b64)])
            return gate(tool_name, target, destructive,
                        destruction_action=action, destruction_signed=signed)
        return wrapped

    # The per-action approval is the production seam for an owner-approved tool call: WARDEN queues
    # anything above the A1 ceiling (sqlmap and hydra classify A2) and the operator's approval is the human
    # leg. W0-11 made that standing grant PER-ACTION + single-use — one flag no longer auto-fires every
    # queued action — so the base gate is stored WITHOUT the approval wrapper and :func:`run_leg` mints a
    # fresh per-action grant (:func:`approve_action_gate`) bound to each row before it runs, exactly as the
    # engine's ``run_tool`` binds each action. ``_approval_gate`` / ``StandingApproval`` are imported (never
    # re-written); a copy of them here would only test the copy.
    return Governance(signer=lambda b: sign(gov.private_key_b64, b),
                      base_gate=with_destruction(real_gate), notes=notes)


# =====================================================================================================
# Engine readers — the only things allowed to turn tool bytes into observations
# =====================================================================================================


@dataclass(frozen=True)
class Reader:
    """An ENGINE symbol that reads a tool's output. ``parse`` returns whatever the engine mints
    (observations / findings). An empty list from non-empty output is a parse FAILURE, not a pass:
    the engine's readers degrade silently by design, and a silent degradation is precisely the bug
    this harness exists to catch."""

    symbol: str
    parse: Callable[[str], list]


def _imports_reader(fmt: str) -> Reader:
    """The engine's third-party import path: format adapter -> ImportedFinding -> intel Observations.
    The same code an operator's findings-import runs through."""
    def parse(raw: str) -> list:
        from framework.v2.imports.parsers import parse_export
        from framework.v2.imports.to_observations import observations_from_imported
        findings, source_tool = parse_export(fmt, raw)
        return list(observations_from_imported(findings, source_tool=source_tool))
    return Reader(symbol=f"imports.parse_export({fmt!r}) -> to_observations", parse=parse)


def _nmap_sensor_reader() -> Reader:
    """The engine's only nmap reader. It consumes ``nmap -oX`` XML."""
    def parse(raw: str) -> list:
        from framework.v2.sensors.nmap import parse_nmap_xml
        out: list = []
        for host, services in parse_nmap_xml(raw):
            out.extend({"host": host, **svc} for svc in services
                       if str(svc.get("state", "")).lower() == "open")
        return out
    return Reader(symbol="sensors.nmap.parse_nmap_xml -> open services", parse=parse)


# =====================================================================================================
# The table — one row per tool. A new builder is proven by appending a row, not by writing code.
# =====================================================================================================


@dataclass
class Env:
    """Everything a row's argument builders may reference. No row hardcodes a port."""

    vuln_url: str
    vuln_host: str
    vuln_port: int
    twin_url: str
    twin_port: int
    auth_weak_port: int
    auth_hard_port: int
    closed_port: int
    fixtures: Fixtures
    # The form twins are handed over WHOLE, not as ports, because their rows read the target-side
    # ledger as well as addressing them.
    form_weak: Twin
    form_hard: Twin


@dataclass(frozen=True)
class ToolProof:
    """ONE ROW = one proven driver.

    ``vuln``/``clean`` return the ``tool_args`` dict handed to ``executor.execute``; the executor
    picks the builder, validates and pins the target, and constructs the argv. ``signal`` decides
    whether the planted weakness was reported — it must be TRUE on the vulnerable target and FALSE on
    the control. ``control_liveness`` reads the control run's raw output and must show the tool was
    actually working there, so that its silence is evidence rather than an absence of evidence.
    """

    tool: str
    phase: str
    weakness: str                          # what this row is about, in one line
    identify: tuple                        # (argv tail, expected substring) — is this the right binary?
    vuln: Callable[[Env], dict]
    clean: Callable[[Env], dict]
    vuln_label: Callable[[Env], str]
    clean_label: Callable[[Env], str]
    reader: Optional[Reader]               # None = the engine cannot read this tool's output at all
    signal: Callable[[list, str], bool]    # (engine-parsed items, raw output) -> weakness reported?
    control_liveness: Callable[[str], bool]
    liveness_desc: str
    timeout: float = 180.0
    note: str = ""
    control_may_be_silent: bool = False    # a control that legitimately produces NO output at all
    # Did the tool REPLAY stored state instead of testing this target? Some tools keep a session cache
    # keyed by hostname, and on loopback every target in the range shares one hostname — so a result
    # confirmed against one port can be re-reported, verbatim, as another port's. A run like that is
    # not evidence in EITHER direction, so a row that can detect it says how here.
    stateful_evidence: Optional[Callable[[str], bool]] = None
    stateful_note: str = ""

    # A tool with MORE THAN ONE row needs each of them named, or two verdicts arrive under one word
    # and neither says which capability it is about. hydra has two: `http-get` and `http-post-form`.
    variant: str = ""

    # THE TARGET-SIDE READING. `arm` is called immediately BEFORE a leg and returns an opaque
    # snapshot; `witness` is called immediately after with that snapshot and answers "and what did
    # the target see?" — the one question the tool's own console cannot be trusted with, because a
    # tool that never reached the target still writes a completed-and-found-nothing console. Both
    # take the leg ("vuln" | "clean"). A witness that returns False FAILS the row.
    arm: Optional[Callable[[Env, str], Any]] = None
    witness: Optional[Callable[[Env, str, Any], tuple]] = None
    witness_desc: str = ""

    # Values that must reach NEITHER the observations an engine reader minted NOR the signed spine
    # record — a credential the row deliberately puts in front of the tool being the case. The RAW
    # tool output is deliberately NOT in scope: it is the operator's evidence and the oracle's input,
    # and `ExecResult` says so ("RAW — for the oracle, NOT for the spine"). What is in scope is
    # everything the engine KEEPS.
    must_not_leak: Optional[Callable[[Env], tuple]] = None

    @property
    def name(self) -> str:
        return f"{self.tool}/{self.variant}" if self.variant else self.tool


def _obs_mentions(items: list, needle: str) -> bool:
    """Read the signal out of the ENGINE'S OWN objects, whatever their concrete class."""
    return any(needle in json.dumps(_jsonable(i), default=str).lower() for i in items)


def _jsonable(obj: Any) -> Any:
    for attr in ("model_dump", "dict", "_asdict"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:  # noqa: BLE001 — fall through to the string form
                break
    return obj if isinstance(obj, (dict, list, str, int, float, bool, type(None))) else str(obj)


# THIS ROW'S module list — narrower than the builder's own declared default, and not to be confused
# with it (``live.executor._WAPITI_SAFE_MODULES`` is the engine's; this one belongs to the row).
#
# It is wapiti's own default set (``wapiti --list-modules``, the "(used by default)" entries) MINUS
# ``ssrf``. Detecting server-side request forgery requires an out-of-band collector, and wapiti's is a
# host on the public internet — so the module cannot run under a charter that forbids egress. Dropping
# it costs this range nothing (the planted weakness is a reflected parameter, which ``xss`` finds), and
# an unloaded module cannot send anything, which ``--endpoint`` would not achieve. Measured: with this
# list the third-party contact disappears from the console entirely and the reflected-XSS finding is
# unchanged.
#
# Keeping the list here NARROW is what keeps the control's silence readable: the row's in-tool budget is
# 90 seconds, and a control that went quiet because the budget expired would look exactly like a control
# that went quiet because the weakness is absent. The BUILDER's default is a wider set and is proven
# safe by integration/tests/test_live_executor_report_builders.py, which asserts the whole argv.
_WAPITI_SAFE_MODULES = "exec,file,permanentxss,redirect,sql,ssl,upload,xss"


def _wapiti_crawled_and_attacked(raw: str) -> bool:
    """Did wapiti actually REACH the target and attack it?

    This row's liveness fact used to be ``"urls and forms during the scan" in raw`` — which wapiti
    prints whether it found a hundred URLs or none, because the sentence it emits when it reached
    NOTHING is "Wapiti found 0 URLs and forms during the scan". Measured against a real run whose
    target was down: the console said ``ConnectError``, the report said ``crawled_pages_nbr: 0``,
    and that assertion still returned True. A control that was never connected to would therefore
    have been certified as evidence, which is the one thing the liveness facts exist to prevent.

    So the count is READ, not merely matched, and it has to be non-zero. Total: an unparseable
    console is not liveness."""
    text = raw.lower()
    if "launching module xss" not in text:
        return False                      # the module that would have found the weakness never ran
    match = re.search(r"found\s+(\d+)\s+urls? and forms? during the scan", text)
    return bool(match) and int(match.group(1)) > 0


# hydra's closing tally — `%d of %d target%s%scompleted, %lu valid password` in the 9.7 binary, so
# both "1 of 1 target completed, 0 valid password found" and its "successfully" variant match.
_HYDRA_TALLY = re.compile(r"(\d+) of (\d+) target[^\n]*?completed,\s*(\d+) valid password")
# BOTH spellings. `strings /usr/bin/hydra` on this host carries "can not connect" (3 sites) AND
# "cannot connect" (1) — and the one the child process actually prints, measured live against a
# closed port, is the UNSPACED one. The row's old guard tested only the spaced form, so it never
# matched anything this hydra emits; it survived on `all children were disabled` alone, which covers
# a TOTAL connection failure but not a partial one. Both are listed now, and the tally below is what
# the check really rests on.
_HYDRA_CONNECT_ERRORS = ("all children were disabled", "cannot connect", "can not connect")


def _hydra_finished_empty(raw: str) -> bool:
    """hydra attacked its target THROUGH TO THE END and cracked nothing.

    The tally is READ, not matched — the lesson `_wapiti_crawled_and_attacked` records, and it
    applies here for a measured reason. Against a closed port hydra still prints
    `0 valid password found`, so the substring alone is satisfied by a run that never connected; the
    counts are what separate them (`0 of 1 target completed` vs `1 of 1`). Total: no tally, no
    liveness."""
    match = _HYDRA_TALLY.search(raw)
    if not match:
        return False                      # killed, crashed, or never got to the end — not evidence
    completed, total, found = (int(g) for g in match.groups())
    if total < 1 or completed != total or found != 0:
        return False
    return not any(err in raw for err in _HYDRA_CONNECT_ERRORS)


def _hydra_control_ok(module: str) -> Callable[[str], bool]:
    """The control run engaged THIS module against the target and finished empty. The module name is
    asserted because hydra's `[DATA] attacking <module>://…` line is the only place its output says
    which capability was exercised — and a row that proved a different module from the one it claims
    is precisely the defect the second hydra row exists to close."""
    def check(raw: str) -> bool:
        return f"attacking {module}://" in raw and _hydra_finished_empty(raw)
    return check


# --- the form row's target-side witness ---------------------------------------------------------
# The form twins run in this process, so the row can ask the TARGET what it saw instead of taking
# hydra's word for it. See `FormLedger` for the measurement that makes this necessary rather than
# decorative: a hydra run against a twin whose /login had gone missing writes a console that is
# indistinguishable from a correct negative control's.


def _form_twin(env: Env, which: str) -> Twin:
    """The ONE place a leg is mapped to a form twin. The row's `tool_args` and its witness both come
    through here, so the twin hydra is pointed at and the twin whose counters are read can never be
    two different servers — a row that attacked one and witnessed the other would be reporting the
    witness's silence as the target's."""
    return env.form_weak if which == "vuln" else env.form_hard


def _form_args(env: Env, which: str) -> dict:
    """The form row's ``tool_args``. The spec's three components are VALUES the builder validates and
    assembles itself (``_hydra_form_option``); this harness writes no part of the command line."""
    return {"target": f"{LOOPBACK}:{_form_twin(env, which).port}", "service": "http-post-form",
            "username": _TWIN_USER, "passlist": env.fixtures.passlist,
            "form_path": _TWIN_FORM_PATH, "form_body": _TWIN_FORM_BODY,
            "form_fail": _TWIN_FORM_FAIL}


def _form_arm(env: Env, which: str) -> tuple:
    ledger = _form_twin(env, which).ledger
    return ledger.snapshot() if ledger else ()


def _form_witness(env: Env, which: str, armed: Any) -> tuple:
    twin = _form_twin(env, which)
    if not twin.ledger or not isinstance(armed, tuple) or len(armed) != 3:
        return False, "the form twin kept no ledger, so the target side cannot be read at all"
    posts, authenticated, weak = (now - before for now, before in zip(twin.ledger.snapshot(), armed))
    detail = (f"{posts} login submission(s) reached the form, {weak} of them offering the password "
              f"the guessable twin accepts; {authenticated} authenticated")
    if which == "vuln":
        return (posts >= 1 and authenticated >= 1), detail
    # The control's three facts, and not one of them is readable from hydra's console: the attack
    # ARRIVED (posts), it got far enough through the wordlist to offer the entry that cracks the
    # other twin (weak), and the form still refused every one of them (authenticated == 0). Only
    # then does "0 valid password found" mean "did not crack it" rather than "did not run".
    return (posts >= len(_PASSWORDS) and weak >= 1 and authenticated == 0), detail


TABLE: list = [
    ToolProof(
        tool="nmap",
        phase="informational",
        weakness="a service is listening on the port",
        identify=(("-V",), "nmap version"),
        vuln=lambda e: {"target": f"{e.vuln_host}:{e.vuln_port}", "service_detection": True},
        clean=lambda e: {"target": f"{e.vuln_host}:{e.closed_port}", "service_detection": True},
        vuln_label=lambda e: f"{RANGE_TARGET} :{e.vuln_port} (open)",
        clean_label=lambda e: f":{e.closed_port} (nothing listening)",
        reader=_nmap_sensor_reader(),
        signal=lambda items, raw: bool(items),
        control_liveness=lambda raw: "Nmap done" in raw,
        liveness_desc="nmap completed its scan of the closed port",
        timeout=120.0,
        note="the reader is sensors.nmap.parse_nmap_xml, so the builder must emit `-oX -`; this row "
             "is what caught it emitting nmap's human-readable text instead",
    ),
    ToolProof(
        tool="httpx",
        phase="informational",
        weakness="an HTTP service is exposed on the port",
        identify=(("-version",), "projectdiscovery"),
        vuln=lambda e: {"target": e.vuln_url},
        clean=lambda e: {"target": f"http://{LOOPBACK}:{e.closed_port}/"},
        vuln_label=lambda e: f"{RANGE_TARGET} :{e.vuln_port}",
        clean_label=lambda e: f":{e.closed_port} (nothing listening)",
        # The engine DOES read httpx now (imports.parsers.parse_httpx_export over its `-json` JSONL),
        # so the row reads the ENGINE'S observations rather than the raw text. Reading raw text here
        # would prove the tool ran and nothing about the engine seeing it — which is the whole
        # distinction this harness exists to make.
        reader=_imports_reader("httpx"),
        signal=lambda items, raw: _obs_mentions(items, "http_fingerprint"),
        # This row used to assert NOTHING about its control (`lambda raw: True`, "probing a closed port
        # produces no output by design") — and that was true of the argv it drove: measured here, the
        # control leg returned exit=0 and 0 BYTES. Zero bytes is byte-identical to httpx never having
        # run, so the one thing the control was there to establish — that the tool worked and still said
        # nothing — was the one thing it could not show. `_build_httpx` now passes `-probe`, so a refused
        # connection is RECORDED (`"failed":true`) instead of dropped, and the silence becomes evidence.
        # The engine's reader still mints nothing from it (`parse_httpx_export` drops failed probes), so
        # the control is silent for the right reason rather than for no reason.
        control_liveness=lambda raw: '"failed":true' in raw.replace(" ", ""),
        liveness_desc="httpx recorded a failed probe for the closed port, so it ran and reached it",
        timeout=90.0,
    ),
    ToolProof(
        tool="nuclei",
        phase="informational",
        weakness="the q parameter is reflected into the page unescaped",
        identify=(("-version",), "nuclei engine version"),
        vuln=lambda e: {"target": e.vuln_url, "tags": "vigil"},
        clean=lambda e: {"target": e.twin_url, "tags": "vigil"},
        vuln_label=lambda e: f"{RANGE_TARGET} :{e.vuln_port}",
        clean_label=lambda e: f"hardened control :{e.twin_port} (escapes it)",
        reader=_imports_reader("nuclei"),
        signal=lambda items, raw: _obs_mentions(items, "vigil-reflected-xss"),
        control_liveness=lambda raw: "vigil-service-alive" in raw,
        liveness_desc="the benign template still matched the control, so nuclei had templates and reached it",
        timeout=180.0,
    ),
    ToolProof(
        tool="ffuf",
        phase="informational",
        weakness="the sensitive endpoint /api/users is discoverable by brute force",
        identify=(("-V",), "ffuf version"),
        vuln=lambda e: {"target": e.vuln_url, "wordlist": e.fixtures.wordlist},
        clean=lambda e: {"target": e.twin_url, "wordlist": e.fixtures.wordlist},
        vuln_label=lambda e: f"{RANGE_TARGET} :{e.vuln_port}",
        clean_label=lambda e: f"hardened control :{e.twin_port} (404s it)",
        # Both halves of what was missing. `_build_ffuf` now asks for `-of json -o <report>` — the
        # machine-readable form — and `imports.parse_export("ffuf", …)` reads it. The signal is taken
        # from the ENGINE'S observations, not from the raw text: reading `"api/users" in raw` would
        # have passed against ffuf's console table, which is exactly the blindness this row exists to
        # rule out.
        reader=_imports_reader("ffuf"),
        signal=lambda items, raw: _obs_mentions(items, "api/users"),
        control_liveness=lambda raw: "about" in raw,
        liveness_desc="ffuf still discovered the benign /about on the control",
        timeout=120.0,
    ),
    ToolProof(
        tool="sqlmap",
        phase="exploitation",
        weakness="the q parameter is concatenated into a SQL statement",
        identify=(("--version",), "."),
        vuln=lambda e: {"target": f"{e.vuln_url}search?q={_PROBE_VALUE}", "level": 1, "risk": 1},
        clean=lambda e: {"target": f"{e.twin_url}search?q={_PROBE_VALUE}", "level": 1, "risk": 1},
        vuln_label=lambda e: f"{RANGE_TARGET} /search?q=",
        clean_label=lambda e: "hardened control /search?q= (parameterized)",
        reader=_imports_reader("sqlmap"),
        signal=lambda items, raw: bool(items),
        control_liveness=lambda raw: "testing for SQL injection on GET parameter 'q'" in raw,
        liveness_desc="sqlmap was seen testing parameter q on the control",
        timeout=420.0,
        stateful_evidence=lambda raw: ("resumed the following injection point" in raw
                                       or "resuming back-end DBMS" in raw),
        stateful_note=(
            "sqlmap keeps a session store keyed by HOSTNAME (~/.local/share/sqlmap/output/<host>/), so on "
            "loopback — where every target on this range and every twin is 127.0.0.1 — a confirmed "
            "injection point on one PORT is resumed and re-reported as another port's, and the engine's "
            "own sqlmap reader turns that into a real observation for a target that has none. This tripwire "
            "is what CAUGHT that: one run wrote both the vulnerable app and the parameterized control into "
            "sqlmap's results CSV with an identical technique set. `_build_sqlmap` now emits "
            "`--flush-session` (a fresh scan, never a resumed one — the guard `_build_wapiti` already "
            "carried), so this firing again means the fix has regressed or the tool found another way to "
            "carry state across two runs"),
    ),
    # --- hydra, TWICE ------------------------------------------------------------------------------
    # One row per MODULE, because a hydra row proves the module it drove and nothing else. The
    # builder can express two credential surfaces — an HTTP Basic challenge (`http-get`) and a POST
    # login form (`http-post-form`) — and they share almost no code inside hydra: the form module is
    # the one that needs `-m path:body:condition`, that has to read the response body to decide
    # success, and that every real web login actually uses. For a while only the first had a control
    # to run against, so the table showed a green `hydra` that said nothing whatever about forms.
    # Both are exercised here, and each verdict is printed under its own module name.

    ToolProof(
        tool="hydra",
        variant="http-get",
        phase="exploitation",
        weakness="the account's password is in a common wordlist (HTTP Basic)",
        identify=(("-h",), "hydra v"),
        vuln=lambda e: {"target": f"{LOOPBACK}:{e.auth_weak_port}", "service": "http-get",
                        "username": _TWIN_USER, "passlist": e.fixtures.passlist},
        clean=lambda e: {"target": f"{LOOPBACK}:{e.auth_hard_port}", "service": "http-get",
                         "username": _TWIN_USER, "passlist": e.fixtures.passlist},
        vuln_label=lambda e: f"basic-auth control :{e.auth_weak_port} (guessable)",
        clean_label=lambda e: f"basic-auth control :{e.auth_hard_port} (not guessable)",
        # `imports.parse_export("hydra", …)` reads hydra's stdout — the format contract for this tool,
        # because routing its machine-readable channel through `-o … -b json` would put the plaintext
        # `-p` password into the signed record via hydra's own `commandline` echo (see `_build_hydra`).
        # The signal is the ENGINE'S graded observation, not a regex this file invented over the text.
        reader=_imports_reader("hydra"),
        signal=lambda items, raw: _obs_mentions(items, "weak_credentials"),
        control_liveness=_hydra_control_ok("http-get"),
        liveness_desc=("hydra engaged the http-get module against the control and its tally shows "
                       "the attack completed with nothing cracked and no connection error"),
        must_not_leak=lambda e: (_TWIN_WEAK_PASSWORD,),
        timeout=180.0,
    ),

    ToolProof(
        tool="hydra",
        variant="http-post-form",
        phase="exploitation",
        weakness="the account's password is in a common wordlist (a POST login form)",
        identify=(("-h",), "hydra v"),
        # The form spec is three separately-validated VALUES — `_hydra_form_option` assembles the
        # `-m path:body:F=condition` triple itself, and refuses the call outright rather than editing
        # anything it does not like. They are read from the same constants the twin serves, so the
        # spec hydra is given and the form it meets cannot drift apart unnoticed in this file. Both
        # legs go through `_form_args`, which is also where the witness gets its twin.
        vuln=lambda e: _form_args(e, "vuln"),
        clean=lambda e: _form_args(e, "clean"),
        vuln_label=lambda e: f"form-login control :{e.form_weak.port} (guessable)",
        clean_label=lambda e: f"form-login control :{e.form_hard.port} (not guessable)",
        reader=_imports_reader("hydra"),
        signal=lambda items, raw: _obs_mentions(items, "weak_credentials"),
        control_liveness=_hydra_control_ok("http-post-form"),
        liveness_desc=("hydra engaged the http-post-form module against the control and its tally "
                       "shows the attack completed with nothing cracked and no connection error"),
        # AND THE CONSOLE IS NOT ENOUGH HERE, which is the whole reason this row carries a witness.
        arm=_form_arm,
        witness=_form_witness,
        witness_desc=("measured on this host: hydra attacking a twin whose /login had gone missing "
                      "prints `attacking http-post-form://…` and `1 of 1 target completed, 0 valid "
                      "password found` — the exact console of a correct negative control, with no "
                      "error of any kind. The twin's own counters are what tell the two apart"),
        must_not_leak=lambda e: (_TWIN_WEAK_PASSWORD,),
        timeout=180.0,
        note="the capability this row exists for was BUILT and unit-tested against verbatim hydra "
             "9.7 output long before it met a real form. Unit-testing the argv string is how you "
             "ship a driver that has never worked, and a form login is the commonest credential "
             "surface there is",
    ),

    # --- the three report-file scanners ------------------------------------------------------------
    # These write a machine-readable report to a file the executor allocates, and `_absorb_report` makes
    # that report the outcome's stdout — so the engine reader sees the REPORT, and the tool's console
    # chatter lands in stderr (still part of `raw`, which is where the liveness assertions read).

    ToolProof(
        tool="nikto",
        phase="informational",
        weakness="robots.txt advertises a path (/admin) that an attacker should go and read",
        identify=(("-Version",), "nikto"),
        vuln=lambda e: {"target": e.vuln_url},
        clean=lambda e: {"target": e.twin_url},
        vuln_label=lambda e: f"{RANGE_TARGET} :{e.vuln_port}",
        clean_label=lambda e: f"hardened control :{e.twin_port} (serves no robots.txt)",
        reader=_imports_reader("nikto"),
        signal=lambda items, raw: _obs_mentions(items, "robots.txt"),
        # The control is not silent — it still reports the same missing-header hygiene items as the
        # vulnerable target. That is exactly what makes its silence about robots.txt meaningful: the
        # scan demonstrably ran, reached the target, and had things to say.
        control_liveness=lambda raw: "security header missing" in raw.lower(),
        liveness_desc="nikto still reported its missing-header findings on the control, so it ran and reached it",
        timeout=240.0,
        note="the differential is the disclosure itself: vulnapp serves /robots.txt naming /admin, and "
             "the hardened twin serves no robots.txt at all — which is the actual remediation for this "
             "finding, not merely a different surface",
    ),

    ToolProof(
        tool="wapiti",
        phase="informational",
        weakness="the q parameter is reflected into the page unescaped",
        identify=(("--help",), "wapiti"),
        # `modules` IS the caller-supplied value the builder already validates (`_safe_csv`); naming it
        # here is not writing a command line. It narrows the scan to the modules this differential is
        # about, so the row stays inside its 90s in-tool budget and its silence on the control means
        # "the xss module ran and found nothing" rather than "the budget ran out". The BUILDER'S OWN
        # default no longer needs to be avoided — see the note.
        vuln=lambda e: {"target": e.vuln_url, "modules": _WAPITI_SAFE_MODULES},
        clean=lambda e: {"target": e.twin_url, "modules": _WAPITI_SAFE_MODULES},
        vuln_label=lambda e: f"{RANGE_TARGET} :{e.vuln_port}",
        clean_label=lambda e: f"hardened control :{e.twin_port} (escapes it)",
        reader=_imports_reader("wapiti"),
        # The engine's CANONICAL bug class, quoted so it matches the attribute value and not some
        # incidental substring. This asserted `cross_site_scripting` until this row was dumped and
        # read: the observation said `reflected_cross_site_scripting`, the slug fallback, because
        # wapiti's real label ("Reflected Cross Site Scripting") was missing from the reader's class
        # map. The needle matched it as a SUBSTRING, so the row was green while wapiti's XSS was
        # filed where it could never correlate with nuclei's or ZAP's. The map now carries the label
        # and this asserts the class the engine is supposed to mint.
        signal=lambda items, raw: _obs_mentions(items, '"xss"'),
        # With the module list narrowed, a clean control legitimately produces ZERO findings — so the
        # liveness fact cannot be "it still found something". It is read off wapiti's own console
        # instead: it crawled a NON-ZERO number of URLs AND launched the module that would have found
        # the weakness. See `_wapiti_crawled_and_attacked` for why the count has to be read.
        control_liveness=_wapiti_crawled_and_attacked,
        liveness_desc="wapiti crawled at least one URL on the control and launched the xss module at it",
        timeout=300.0,
        control_may_be_silent=True,
        note="THIS ROW FOUND THE BUILDER'S EGRESS. With no `modules` given, _build_wapiti used to "
             "inherit wapiti's OWN default set, which includes `ssrf` — a module that resolves and "
             "contacts https://wapiti3.ovh (188.165.53.185:443) for out-of-band results on every run, "
             "against both targets. That breaks the charter's hard limit ('No external egress. No tool, "
             "no DNS, no callback may leave the host'), and neither the egress pin (which constrains the "
             "TARGET, not a host the tool addresses itself) nor --no-bugreport (a different path) covers "
             "it. _build_wapiti now DECLARES its module set instead of inheriting one, and refuses the "
             "off-host modules even when a caller names them (`_WAPITI_EGRESSING_MODULES` = ssrf, "
             "log4shell, wapp — `wapp` is the one that shows a declared set is not automatically a safe "
             "one: it needs no collaborator, yet `mod_wapp.attack` downloads its Wappalyzer database "
             "from raw.githubusercontent.com whenever the local copy is missing, which under this "
             "builder's pinned config dir it always is). That default is pinned by "
             "integration/tests/test_live_executor_report_builders.py, not by this row: this row keeps "
             "a narrower explicit list so the differential stays about the planted weakness",
    ),

    ToolProof(
        tool="zaproxy",
        phase="informational",
        weakness="the q parameter is injectable and reflected (ZAP's active scan)",
        identify=(("-h",), "zap"),
        # THE BARE HOST, deliberately — and this row exists to keep it that way. The weakness is on
        # /search?q=, which nothing here names: the builder has to CRAWL to it and then attack what it
        # crawled. Seeding the parameterised URL instead (which this row used to do, to work around the
        # defect below) would let a scan that only ever attacks its seed node pass this row forever.
        vuln=lambda e: {"target": e.vuln_url, "max_minutes": 3},
        clean=lambda e: {"target": e.twin_url, "max_minutes": 3},
        vuln_label=lambda e: f"{RANGE_TARGET} :{e.vuln_port} (bare host — the crawl has to find /search)",
        clean_label=lambda e: f"hardened control :{e.twin_port} (same crawl, escapes it)",
        reader=_imports_reader("zap"),
        signal=lambda items, raw: _obs_mentions(items, "cross site scripting"),
        # THE CONTROL'S SILENCE IS ONLY EVIDENCE IF THE ACTIVE SCAN REACHED THE PARAMETER. Passive
        # header alerts fire on a target ZAP merely fetched, so "it raised CSP" — what this row used to
        # check — would have passed for the very defect described below, where the active scanner
        # scanned one parameterless node and every injection rule sent zero requests. So the claim is
        # made of the two facts that are actually in the streams: ZAP's active-scan JOB ran to
        # completion (its own progress line, on the console the executor keeps as stderr), and the
        # crawl reached the parameterised URL (it is in the report's own alert instances).
        control_liveness=lambda raw: ("job activescan finished" in raw.lower()
                                      and "/search?q=" in raw.lower()),
        liveness_desc=("ZAP's active-scan job ran to completion on the control and its crawl reached "
                       "/search?q= there, so the control was attacked and still reported no injection"),
        timeout=420.0,
        note="THIS ROW WAS SEEDED WITH THE PARAMETERISED URL TO WORK AROUND A DEFECT, AND SO COULD NOT "
             "SEE IT. `_build_zaproxy` drove ZAP's quick scan (`-quickurl`), which actively attacks "
             "ONLY the sites-tree node it is seeded with — `AttackThread.run` hands the active scanner "
             "the seed node and its `setRecurse(true)` is inert on a leaf. Seeded with the bare host "
             "the parameter rules therefore sent zero requests (`CrossSiteScriptingScanRule ... 0 "
             "message(s) sent`, `Scanning 1 node(s)`) while the spider had already fetched the "
             "injectable /search?q= — measured: 99 requests, 2 to /search, both the benign q=test, and "
             "a report byte-identical to this control's. Raising the budget fivefold changed nothing. "
             "The builder now drives ZAP's automation framework, whose activeScan job takes the "
             "CONTEXT: measured on the same target and the same budget, `Scanning 5 node(s)` instead of "
             "1, and reflected XSS + SQL injection on q — 15 findings through the import adapter where "
             "the quick scan produced 0 of either. The control, crawled and attacked identically, has "
             "ZAP's own log showing 6 XSS probes and 22 SQL-injection probes sent to it and no alert "
             "raised: it was attacked, and its silence is a measurement rather than an absence",
    ),
]


# =====================================================================================================
# Running a row
# =====================================================================================================


@dataclass
class Leg:
    """One execution of one driver against one target."""

    label: str
    ran: bool = False
    reason: str = ""
    argv: tuple = ()
    stdout: str = ""            # the machine-readable stream — the ONLY thing an engine reader sees
    raw: str = ""               # stdout + the tool's own log stream, for the raw differentials
    exit_code: Optional[int] = None
    timed_out: bool = False
    truncated: bool = False     # the executor capped the captured output — see the leak check
    record_json: str = ""       # the SIGNED spine record, as the engine would persist it
    parsed: Optional[list] = None
    parse_error: str = ""
    signal: bool = False
    contaminated: bool = False  # the tool replayed stored state; this run is not evidence either way
    target_gone: bool = False   # the target stopped answering DURING this leg; see `_judge`
    witness_ok: Optional[bool] = None   # what the TARGET saw of this leg; None = the row asks nothing
    witness_detail: str = ""
    leak_checked: bool = False  # was the no-credential check able to run conclusively?
    leaked: tuple = ()          # LABELS of values found where the engine keeps things — never values


@dataclass
class Row:
    proof: ToolProof
    vuln: Optional[Leg] = None
    clean: Optional[Leg] = None
    tool_present: bool = True
    tool_note: str = ""
    verdict: str = "?"
    failures: list = field(default_factory=list)

    @property
    def ran(self) -> bool:
        return bool(self.vuln and self.vuln.ran and self.clean and self.clean.ran)


# Tools whose NAME does not resolve to their binary by a plain PATH lookup, and the executor function
# that knows what it does resolve to. ``httpx`` is the case: on Kali the real ProjectDiscovery binary
# installs as ``httpx-toolkit`` because the plain name belongs to an unrelated Python HTTP client, and
# ``live.executor`` resolves that from the tool registry's declared ``alt_binaries``/``wrong_markers``.
# Asking the executor is the whole point — a harness that resolved the name ITSELF would be checking a
# different binary from the one it is about to prove, which is how a correct driver gets reported broken.
_EXECUTOR_RESOLVERS = {"httpx": "_resolve_httpx_binary"}


def resolved_binary(tool: str) -> tuple:
    """``(path, reason)`` for the binary the EXECUTOR will actually spawn for ``tool``. Deferred import,
    matching ``run_leg``: this module is importable without the sovereign package on the path."""
    resolver_name = _EXECUTOR_RESOLVERS.get(tool)
    if resolver_name:
        from vigil_integration.live import executor as _executor
        return getattr(_executor, resolver_name)()
    path = shutil.which(tool)
    return (path, "") if path else (None, "not on PATH")


def identify_binary(tool: str, spec: tuple) -> tuple:
    """Is the binary the executor will spawn actually the tool the builder was written for?

    This is not paranoia. On this machine ``httpx`` resolves to the Python HTTP library's CLI, which
    shares the name and shares nothing else — a driver aimed at the wrong binary fails in a way that
    looks exactly like the target being boring.

    The binary is resolved THE EXECUTOR'S WAY (see ``resolved_binary``) and probed BY ABSOLUTE PATH, so
    this answers a question about the process that will really run. Probing ``[tool, *args]`` by bare
    name instead was measurably wrong on this very box: with the real tool installed as
    ``httpx-toolkit`` and correctly resolved by the executor, this function reported
    ``/home/kali/.../httpx is not the expected tool`` and the whole httpx row was skipped as
    unprovable — the harness failing a driver for a defect that lived in the harness."""
    path, why = resolved_binary(tool)
    if not path:
        return False, why or "not on PATH"
    args, expected = spec
    try:
        res = subprocess.run([path, *args], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{path} — could not be executed: {exc}"
    blob = (res.stdout + res.stderr).lower()
    if expected == ".":                      # any non-empty version-ish output will do
        return (bool(blob.strip()), path if blob.strip() else f"{path} — printed nothing for {args}")
    if expected in blob:
        return True, path
    first = (blob.strip().splitlines() or ["<no output>"])[0][:90]
    return False, f"{path} is not the expected tool (it said: {first!r})"


def run_leg(proof: ToolProof, tool_args: dict, label: str, gov: Governance, seq: int) -> Leg:
    from vigil_integration.live.executor import execute
    from vigil_integration.live.wiring import DEFAULT_DESTRUCTIVE_VIEW, DEFAULT_TOOL_VIEW

    leg = Leg(label=label)
    # W0-11: approve THIS action, then run it. A fresh single-use standing grant is bound to exactly this
    # (tool, target, args) — the harness is the operator's human leg, approving each row individually — so a
    # queued A2 tool (sqlmap/hydra) is upgraded to allow for this one action only. The base gate is passed the
    # same default scope/allowed_ips ``derive_gate_binding`` used, so the bound pair equals the gate-seen pair.
    gate = approve_action_gate(gov.base_gate, proof.tool, tool_args)
    result = execute(
        proof.tool, tool_args, proof.phase,
        gate=gate, view=DEFAULT_TOOL_VIEW, destructive_view=DEFAULT_DESTRUCTIVE_VIEW,
        signer=gov.signer, seq=seq, timeout=proof.timeout,
    )
    leg.ran = bool(result.ran)
    leg.reason = result.reason
    leg.argv = tuple(result.argv)
    leg.exit_code = result.exit_code
    leg.timed_out = bool(result.timed_out)
    leg.truncated = bool(result.truncated)
    # THE SIGNED SPINE RECORD, kept — not for the differential, but because it is one of the two
    # places a credential must never reach, and a check that cannot see it cannot make that claim.
    # `ExecResult.record` is None only on a deny, which `leg.ran` already reports.
    record = getattr(result, "record", None)
    if record is not None:
        try:
            leg.record_json = record.model_dump_json()
        except Exception as exc:  # noqa: BLE001 — a record we cannot serialise is a check we cannot make
            leg.record_json = ""
            info(f"   {YELLOW}the signed record could not be serialised for inspection: {exc}{OFF}")
    # The oracle-facing RAW streams. stdout is the machine-readable side for every builder here;
    # stderr carries the tool's own log (nuclei's INF lines, hydra's progress, sqlmap's trace). The
    # engine reader is given stdout ONLY — handing it the log stream would be a different claim.
    leg.stdout = result.stdout or ""
    leg.raw = leg.stdout + (("\n" + result.stderr) if result.stderr else "")
    return leg


def _target_port(tool_args: dict) -> Optional[int]:
    """The port a row's target names, or None when it names none.

    Read from the row's OWN ``tool_args`` — the same string the executor parses — never from the
    built argv, because a builder is free to rewrite the target (ffuf appends /FUZZ, hydra splits
    host from port) and this has to be the port the ROW meant."""
    raw = str((tool_args or {}).get("target") or "").strip()
    if not raw:
        return None
    authority = raw.split("://", 1)[-1].split("/", 1)[0]
    _, _, port = authority.rpartition(":")
    return int(port) if port.isdigit() and 0 < int(port) < 65536 else None


def parse_leg(proof: ToolProof, leg: Leg) -> None:
    if proof.reader is None:
        return
    try:
        leg.parsed = list(proof.reader.parse(leg.stdout))
    except Exception as exc:  # noqa: BLE001 — a reader that raises is a parse failure, and is reported
        leg.parsed = []
        leg.parse_error = f"{type(exc).__name__}: {exc}"


def check_leg_for_leaks(proof: ToolProof, leg: Leg, env: Env) -> None:
    """Did a value the row put in front of the tool survive into anything the ENGINE KEEPS?

    Two places, and only these two: the observations an engine reader minted, and the signed spine
    record (its redacted argv, its redacted stdout/stderr — every field, via its own serialisation).
    The raw tool output is excluded on purpose and the harness says so out loud: hydra prints the
    cracked password to stdout, that stream is the oracle's evidence, and `ExecResult` marks it "RAW
    — for the oracle, NOT for the spine".

    The check REFUSES TO CONCLUDE rather than passing quietly when it cannot see what it is
    searching: no record, or a record whose streams the executor capped (a value past the cap is not
    absent, merely unread). `leak_checked` carries that, and `_judge` fails on it — a check that
    could not run is not a check that passed, which is the same rule the negative controls follow."""
    if proof.must_not_leak is None:
        return
    needles = [n for n in proof.must_not_leak(env) if isinstance(n, str) and n]
    if not needles:
        return
    if not leg.record_json or leg.truncated:
        leg.leak_checked = False
        return
    observations = json.dumps([_jsonable(i) for i in (leg.parsed or [])], default=str)
    leg.leak_checked = True
    # The FINDING is reported by its label, never by its value: a harness that printed the credential
    # to prove the engine had not would be the leak it is looking for.
    leg.leaked = tuple(f"a value of {len(n)} characters"
                       + (" (the observations the engine minted)" if n in observations else "")
                       + (" (the signed spine record)" if n in leg.record_json else "")
                       for n in needles if n in observations or n in leg.record_json)


def run_row(proof: ToolProof, env: Env, gov: Governance, seq: int) -> Row:
    row = Row(proof=proof)
    say(f"{proof.name} — {proof.weakness}")

    present, note = identify_binary(proof.tool, proof.identify)
    row.tool_present, row.tool_note = present, note
    if not present:
        info(f"{RED}the tool is not usable: {note}{OFF}")
        if proof.tool in ALLOW_MISSING:
            row.verdict = "SKIP"
            info(f"{YELLOW}acknowledged via VIGIL_LIVEFIRE_ALLOW_MISSING — reported, not proven{OFF}")
        else:
            row.verdict = "UNPROVEN"
            row.failures.append(f"{proof.name}: {note} — the driver cannot be proven end to end")
        return row
    info(f"{DIM}binary: {note}{OFF}")

    for which, args_fn, label_fn, tag in (("vuln", proof.vuln, proof.vuln_label, "vulnerable target"),
                                          ("clean", proof.clean, proof.clean_label, "clean control")):
        tool_args = args_fn(env)
        # Armed IMMEDIATELY before the leg, so the witness reads a DELTA. An absolute count would
        # silently absorb the pre-flight's own requests to the same twin — and absorbing traffic is
        # the direction that makes a liveness check easier to satisfy, which is the direction a
        # liveness check must never be wrong in.
        armed = proof.arm(env, which) if proof.arm else None
        leg = run_leg(proof, tool_args, label_fn(env), gov, seq)
        seq += 1
        if proof.witness:
            try:
                leg.witness_ok, leg.witness_detail = proof.witness(env, which, armed)
            except Exception as exc:  # noqa: BLE001 — a witness that cannot answer is not a pass
                leg.witness_ok, leg.witness_detail = False, f"the witness could not be read: {exc}"
        # IS THE VULNERABLE TARGET STILL THERE? Asked AFTER the leg, because a target that dies
        # mid-row is indistinguishable, in the output, from a driver that found nothing — and the
        # harness used to report it as the READER'S failure. Measured on this box: the range's
        # vulnapp stopped answering partway through a run, and the two rows that ran after it were
        # reported as `the reader read nothing`, naming a defect that was not there. The same two
        # rows passed against a target that was up. `tools/livefire` re-ran the zaproxy builder
        # against a port with nothing listening and got 1188 bytes and zero observations — the
        # byte count the failing run reported, exactly. So the question is asked, and a row whose
        # target vanished is refused as evidence rather than blamed on the engine. The CONTROL leg
        # is not asked: one row's control is a deliberately-closed port, and every other control is
        # an in-process twin whose liveness `control_liveness` already establishes from the output.
        if which == "vuln":
            port = _target_port(tool_args)
            if port is not None and not _listening(port):
                leg.target_gone = True
        setattr(row, which, leg)
        info(f"{tag:<18} {leg.label}")
        info(f"   argv, built by the engine: {' '.join(leg.argv) if leg.argv else '<none — refused>'}")
        if not leg.ran:
            info(f"   {RED}the executor did not run it: {leg.reason}{OFF}")
            row.failures.append(f"{proof.name} ({tag}): {leg.reason}")
            continue
        if leg.timed_out:
            info(f"   {RED}the tool timed out after {proof.timeout:.0f}s{OFF}")
            row.failures.append(f"{proof.name} ({tag}): timed out after {proof.timeout:.0f}s")
        parse_leg(proof, leg)
        check_leg_for_leaks(proof, leg, env)
        leg.signal = bool(proof.signal(leg.parsed or [], leg.raw))
        parsed = "-" if leg.parsed is None else str(len(leg.parsed))
        info(f"   exit={leg.exit_code}  output={len(leg.raw)}B  engine-parsed={parsed}  "
             f"weakness reported={'YES' if leg.signal else 'no'}")
        if leg.witness_detail:
            mark = GREEN + "ok  " + OFF if leg.witness_ok else RED + "FAIL" + OFF
            info(f"   {mark} the target itself saw: {leg.witness_detail}")
        if proof.must_not_leak is not None:
            if leg.leak_checked and not leg.leaked:
                info(f"   {GREEN}ok  {OFF}no credential in the engine's observations or the signed "
                     "record (the raw tool output is the oracle's evidence and is out of scope)")
            elif not leg.leak_checked:
                info(f"   {RED}FAIL{OFF} the no-credential check could not be made conclusively")

    _judge(row)
    return row


def _judge(row: Row) -> None:
    """Every expectation, asserted, in the order of the claim: it ran, it produced output, an ENGINE
    reader read that output, it saw the weakness where the weakness is, and it stayed quiet where the
    weakness is not — while demonstrably still working."""
    proof, vuln, clean = row.proof, row.vuln, row.clean
    if vuln is None or clean is None:
        row.verdict = "FAIL"
        return

    if vuln.ran and not vuln.raw.strip() and not vuln.target_gone:
        row.failures.append(f"{proof.name}: ran against the vulnerable target and produced NO output")
    if clean.ran and not clean.raw.strip() and not proof.control_may_be_silent:
        row.failures.append(f"{proof.name}: ran against the control and produced NO output")

    # WHAT THE TARGET SAW. Asserted before anything is read out of the tool's own output, because it
    # is the fact that decides whether that output describes this target at all.
    for leg, where in ((vuln, "vulnerable target"), (clean, "clean control")):
        if leg.ran and leg.witness_ok is False:
            row.failures.append(
                f"{proof.name}: the {where} itself did not see what a working run leaves behind — "
                f"{leg.witness_detail}. The tool's own console cannot settle this"
                + (f" ({proof.witness_desc})" if proof.witness_desc else ""))

    # AND WHAT THE ENGINE KEPT. A credential the row handed the tool must not survive into the
    # observations or the signed record; a check that could not be made conclusively fails too.
    for leg, where in ((vuln, "vulnerable target"), (clean, "clean control")):
        if not leg.ran or proof.must_not_leak is None:
            continue
        if not leg.leak_checked:
            row.failures.append(
                f"{proof.name} ({where}): the no-credential invariant could NOT be checked — "
                + ("the executor capped this run's captured output, so a value past the cap would "
                   "read as absent" if leg.truncated else "there is no signed record to search")
                + ". An unverifiable invariant is not a held one")
        for label in leg.leaked:
            row.failures.append(
                f"{proof.name} ({where}): a credential this row put in front of the tool SURVIVED "
                f"into what the engine keeps — {label}")

    # A run that replayed stored state never tested the target in front of it. Its "yes" is not a
    # detection and its "no" is not a control — so it is refused as evidence in both directions, and
    # the state reuse itself is the finding.
    for leg, where in ((vuln, "vulnerable target"), (clean, "clean control")):
        if leg.ran and proof.stateful_evidence and proof.stateful_evidence(leg.raw):
            leg.contaminated = True
            row.failures.append(
                f"{proof.name}: the run against the {where} REPLAYED A STORED SESSION instead of "
                f"testing it, so its result describes a different target. {proof.stateful_note}")

    # A target that stopped answering was never tested, so — exactly as for a replayed session — the
    # run is refused as evidence and the judgments below are skipped rather than reported against a
    # driver that did nothing wrong. The row still FAILS: this can never turn a red row green.
    if vuln.ran and vuln.target_gone:
        row.failures.append(
            f"{proof.name}: the VULNERABLE TARGET stopped answering during this row, so this run "
            "describes a target that was not there. Its silence is not a reader result and not a "
            "detection result — bring the range back up (tools/livefire/range.sh up) and re-run it")

    if proof.reader is None:
        row.failures.append(
            f"{proof.name}: the engine has no reader for this tool's output — it runs, but nothing in "
            "the engine can turn its bytes into observations, so it is NOT driven end to end"
            + (f" ({proof.note})" if proof.note else ""))
    elif vuln.ran and not vuln.target_gone:
        if vuln.parse_error:
            row.failures.append(
                f"{proof.name}: {proof.reader.symbol} could not read the output: {vuln.parse_error}")
        elif not vuln.parsed and vuln.raw.strip():
            row.failures.append(
                f"{proof.name}: {proof.reader.symbol} read the tool's real output and produced "
                "NOTHING — the reader exists, but does not match what this builder's argv emits"
                + (f" ({proof.note})" if proof.note else ""))

    if vuln.ran and not vuln.contaminated and not vuln.target_gone and not vuln.signal:
        # Say WHERE the weakness went unreported. For a row with a reader this is the engine's view,
        # which is the view that matters — but it must not be read as "the tool found nothing", since
        # a reader that cannot parse the output makes the engine blind to what the tool did find.
        through = f"through {proof.reader.symbol}" if proof.reader else "in its raw output"
        row.failures.append(f"{proof.name}: the planted weakness ({proof.weakness}) was NOT reported "
                            f"{through} on the vulnerable target")
    # The control's two judgments are skipped on a contaminated run, not because they passed, but
    # because that run is not evidence — reporting a "false positive" there would misname the defect.
    if clean.ran and not clean.contaminated:
        if clean.signal:
            row.failures.append(f"{proof.name}: reported the weakness on the CLEAN CONTROL — a false "
                                "positive, so this driver's output cannot be trusted")
        if not proof.control_liveness(clean.raw):
            row.failures.append(f"{proof.name}: the control run cannot be read as evidence — "
                                f"{proof.liveness_desc} did not hold, so its silence proves nothing")

    row.verdict = "FAIL" if row.failures else "PASS"


# =====================================================================================================
# Output
# =====================================================================================================


def _reported(leg: Optional[Leg]) -> str:
    if leg is None or not leg.ran:
        return "-"
    if leg.contaminated:
        return "REPLAY"   # the tool answered from stored state; this cell is not a measurement
    if leg.target_gone:
        return "GONE"     # the target stopped answering; this cell is not a measurement either
    return "yes" if leg.signal else "no"


def print_table(rows: list, unproven_builders: list) -> None:
    say("RESULTS — tool · ran · output parsed by the engine · weakness reported · verdict")
    print(f"   {'TOOL':<22} {'RAN':<5} {'ENGINE-PARSED':<32} {'VULN':<6} {'CONTROL':<8} VERDICT")
    print(f"   {'-' * 22} {'-' * 5} {'-' * 32} {'-' * 6} {'-' * 8} {'-' * 7}")
    for row in rows:
        proof = row.proof
        if row.verdict in ("UNPROVEN", "SKIP"):
            colour = RED if row.verdict == "UNPROVEN" else YELLOW
            print(f"   {proof.name:<22} {'-':<5} {'-':<32} {'-':<6} {'-':<8} "
                  f"{colour}{row.verdict}{OFF} — {row.tool_note}")
            continue
        if proof.reader is None:
            parsed = "NO — no engine reader exists"
        elif row.vuln and row.vuln.target_gone:
            parsed = "n/a — the target stopped answering"
        elif row.vuln and row.vuln.parse_error:
            parsed = "NO — the reader errored"
        elif row.vuln and not row.vuln.parsed:
            parsed = "NO — the reader read nothing"
        else:
            parsed = f"yes — {len(row.vuln.parsed)} observation(s)" if row.vuln else "-"
        mark = "" if proof.reader else "*"
        colour = GREEN if row.verdict == "PASS" else RED
        print(f"   {proof.name:<22} {('yes' if row.ran else 'NO'):<5} {parsed:<32} "
              f"{_reported(row.vuln) + mark:<6} {_reported(row.clean) + mark:<8} "
              f"{colour}{row.verdict}{OFF}")
    print()
    print(f"   {DIM}VULN / CONTROL: did the driver report the planted weakness on that target."
          f" It must be yes on{OFF}")
    print(f"   {DIM}the vulnerable target and no on the control.  * = the harness had to read the "
          f"tool's RAW text{OFF}")
    print(f"   {DIM}itself because the engine has no reader for it. That is a gap, not a capability."
          f"{OFF}")
    if any(leg and leg.contaminated for row in rows for leg in (row.vuln, row.clean)):
        print(f"   {DIM}REPLAY = the tool answered from a stored session instead of testing the "
              f"target in front of it,{OFF}")
        print(f"   {DIM}    so that cell is not a measurement at all. See the verdict for which, "
              f"and why.{OFF}")
    if any(leg and leg.target_gone for row in rows for leg in (row.vuln, row.clean)):
        print(f"   {DIM}GONE = the target stopped answering during that row, so the tool was scanning "
              f"nothing and that{OFF}")
        print(f"   {DIM}    cell is not a measurement either. The row fails on the TARGET, not on "
              f"the driver.{OFF}")

    if unproven_builders:
        say("BUILDERS IN THE EXECUTOR WITH NO ROW HERE")
        for name in unproven_builders:
            print(f"   {YELLOW}unproven{OFF}  {name} — a typed builder exists; nothing has ever run it "
                  "against a live target")
        print(f"\n   {DIM}Prove one by appending a ToolProof to TABLE. "
              f"VIGIL_LIVEFIRE_STRICT_BUILDERS=1 makes this a failure.{OFF}")


def print_honesty() -> None:
    say("WHAT THESE RESULTS ARE, AND WHAT THEY ARE NOT")
    print("   Every 'yes' above is a LEAD produced by a third-party tool. None of it is an oracle-")
    print("   confirmed fact, and this harness has not proven that any vulnerability exists. The")
    print("   engine agrees in code: imports.to_observations mints these as lead/unverified at")
    print("   deliberately low confidence, and a FINDING is only what a CRUCIBLE oracle re-verified")
    print("   from first-party evidence.")
    print()
    print("   What IS proven here is the plumbing: the engine's own builder produced the argv, the")
    print("   tool ran against a live local target, an engine reader read the bytes it returned, the")
    print("   weakness was reported where it was planted, and the driver stayed silent on a control")
    print("   that was demonstrably still being tested.")


# =====================================================================================================


def main() -> int:
    failures: list = []

    # Resolve the row selection FIRST — before the lock, before the range, before any packet. A typo in
    # VIGIL_LIVEFIRE_ONLY must not bring a target up and only then refuse; and a filter that selected
    # nothing must never be mistaken for a clean run.
    selected = [p for p in TABLE if not ONLY_TOOLS or p.tool.lower() in ONLY_TOOLS]
    excluded = [p for p in TABLE if p not in selected]
    if ONLY_TOOLS:
        unknown = ONLY_TOOLS - {p.tool.lower() for p in TABLE}
        if unknown:
            die(f"the row filter names {sorted(unknown)}, which no row in the table drives. "
                f"Rows available: {sorted({p.tool for p in TABLE})}")
        if not selected:
            die("the row filter excluded every row — a run that drives nothing proves nothing.")

    # ONE live-fire on this machine at a time, enforced HERE: before a control is started, before
    # an authority is minted, and before a single packet is sent at anything. A second run is
    # refused rather than queued — see the run-lock section for what concurrent runs corrupt.
    lock = acquire_run_lock("tool_drivers_livefire.py")
    say("0. The run lock — this machine runs ONE tool-driver live-fire at a time")
    if lock.inherited:
        info(f"held by this run's launcher (pid {lock.holder_pid}) at {lock.path}")
    else:
        info(f"held by this process (pid {os.getpid()}) at {lock.path}")
    info(f"{DIM}the range target, the executor's report artifacts and the port it pins for ZAP's "
         f"proxy listener are machine-global; a second run would corrupt this one's evidence{OFF}")
    assert_pinned_listener_ports_are_free()

    say("1. The vulnerable target — read from the range manifest, re-asserted as loopback")
    range_target, vuln_port, range_targets = load_range_target(RANGE_TARGET)
    info(f"{RANGE_TARGET}: {getattr(range_target, 'title', '')} on {LOOPBACK}:{vuln_port}")
    assert_target_live(vuln_port, RANGE_TARGET)
    info(f"{GREEN}ok  {OFF}it is up, and listening on loopback only")
    assert_weakness_is_present(range_target, range_targets, failures)
    if failures:
        for failure in failures:
            print(f"   {RED}FAIL{OFF} {failure}")
        return 1

    say("2. The clean control — the same surface with every weakness removed")
    twin = start_twin("hardened")
    auth_weak = start_twin("auth-weak", auth_password=_TWIN_WEAK_PASSWORD)
    auth_hard = start_twin("auth-hard", auth_password=_TWIN_STRONG_PASSWORD)
    form_weak = start_twin("form-weak", form_password=_TWIN_WEAK_PASSWORD)
    form_hard = start_twin("form-hard", form_password=_TWIN_STRONG_PASSWORD)
    info(f"hardened control on :{twin.port}; HTTP Basic credential controls on :{auth_weak.port} "
         f"(guessable) and :{auth_hard.port} (not); FORM-LOGIN credential controls on "
         f"     :{form_weak.port} (guessable) and :{form_hard.port} (not)")
    assert_control_is_a_control(twin, auth_hard, failures)
    assert_form_control_is_a_control(form_weak, form_hard, list(_PASSWORDS), failures)
    if failures:
        print()
        for failure in failures:
            print(f"   {RED}FAIL{OFF} {failure}")
        print(f"\n   {RED}The control is not a control. Nothing below would mean anything.{OFF}")
        return 1

    closed_port = free_port()
    if _listening(closed_port):
        die(f"the port chosen as the closed-port control ({closed_port}) is in use")
    info(f"closed-port control on :{closed_port} — nothing is listening there")

    workdir = tempfile.mkdtemp(prefix="vigil-livefire-drivers-")
    # Every artifact this run produces gets a path only this run can name — the belt to the run
    # lock's braces, and the reason two runs cannot write the same report file even if the lock
    # somehow failed. Checked against the executor's own allocator, not assumed.
    run_tmp = isolate_run_artifacts(workdir)
    fixtures = write_fixtures(workdir)
    # nuclei has no template selector in the engine's argv, so its template directory is supplied out
    # of band, through the environment the executor's subprocess inherits. The argv stays the
    # engine's; only the tool's own configuration is ours.
    os.environ["NUCLEI_CONFIG_DIR"] = fixtures.nuclei_config_dir
    # And every tool that keeps state under XDG_DATA_HOME (sqlmap's session store, most importantly)
    # gets a PRISTINE one per run. This is not a courtesy to the operator's home directory: without
    # it, results depend on what was scanned on this machine before, and neither a pass nor a fail
    # here would be reproducible. The isolation is also evidence in its own right — a driver that
    # needs the harness to reset its state is a driver carrying state the engine never resets.
    os.environ["XDG_DATA_HOME"] = os.path.join(workdir, "tool-state")
    os.makedirs(os.environ["XDG_DATA_HOME"], exist_ok=True)
    info(f"fixtures in {workdir} — wordlist, password list, offline nuclei templates, "
         "and a pristine per-run tool-state directory")
    info(f"the engine's report artifacts are confined to {run_tmp} — unique to this run, so a "
         "second run cannot overwrite this one's evidence")

    say("3. Governance — the real signed authority and the real conjunctive gate")
    gov = build_governance(workdir)
    info(f"{GREEN}ok  {OFF}CRUCIBLE authority signed and scoped to {LOOPBACK}; WARDEN tier gate and "
         "the m-of-n destruction leg wired")
    for note in gov.notes:
        info(f"{YELLOW}note{OFF} {note}")

    env = Env(vuln_url=f"http://{LOOPBACK}:{vuln_port}/", vuln_host=LOOPBACK, vuln_port=vuln_port,
              twin_url=twin.url, twin_port=twin.port,
              auth_weak_port=auth_weak.port, auth_hard_port=auth_hard.port,
              closed_port=closed_port, fixtures=fixtures,
              form_weak=form_weak, form_hard=form_hard)

    say("4. Driving each tool through the engine — vulnerable target, then clean control")
    if ONLY_TOOLS:
        info(f"{YELLOW}SUBSET RUN{OFF} driving {len(selected)} of {len(TABLE)} rows "
             f"(VIGIL_LIVEFIRE_ONLY={','.join(sorted(ONLY_TOOLS))})")
        info(f"{YELLOW}not attempted:{OFF} {', '.join(p.name for p in excluded)}")
    rows: list = []
    seq = 1
    for proof in selected:
        row = run_row(proof, env, gov, seq)
        seq += 10
        rows.append(row)
        failures.extend(row.failures)

    # A builder nobody has ever driven is not a proven driver, and silence about it would be the exact
    # failure mode this harness exists to prevent.
    from vigil_integration.live.executor import _BUILDERS
    unproven = sorted(set(_BUILDERS) - {p.tool for p in TABLE})
    if STRICT_ALL_BUILDERS:
        failures.extend(f"{name}: a typed builder exists in the executor, but no row proves it"
                        for name in unproven)

    print_table(rows, unproven)
    print_honesty()

    for control in (twin, auth_weak, auth_hard, form_weak, form_hard):
        control.server.shutdown()
    _forget_authority()

    say("VERDICT")
    if failures:
        print(f"   {RED}LIVE-FIRE FAILED — {len(failures)} expectation(s) did not hold:{OFF}")
        for failure in failures:
            print(f"     - {failure}")
        passed = [r.proof.name for r in rows if r.verdict == "PASS"]
        print(f"\n   Drivers proven end to end: {', '.join(passed) if passed else 'none'}")
        print(f"   Fixtures and tool output left in {workdir}")
        return 1
    scope = "Every driver in the table" if not ONLY_TOOLS else (
        f"Each of the {len(selected)} driver(s) this SUBSET run attempted")
    print(f"   {GREEN}{scope} built its own argv through the engine, ran against a "
          f"live target,{OFF}")
    print(f"   {GREEN}parsed through an engine reader, reported the planted weakness, and stayed "
          f"silent on a{OFF}")
    print(f"   {GREEN}control that was still being tested.{OFF}")
    if ONLY_TOOLS:
        # The reader must not be able to mistake this for the full proof. Say what was NOT attempted,
        # in the verdict itself, where a passing run is read.
        print(f"\n   {YELLOW}THIS RUN PROVES A SUBSET.{OFF} {len(excluded)} row(s) were not attempted "
              f"and are NOT covered by this verdict:")
        print(f"     {', '.join(p.name for p in excluded)}")
        print(f"   {DIM}Run with no VIGIL_LIVEFIRE_ONLY for the full table.{OFF}")
    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    # Two tiny modes tool_drivers_livefire.sh drives, so the shell and this file share ONE
    # definition of where the run lock lives and ONE wording for why a second run is refused.
    # Neither runs a tool, sends a packet, or takes the lock.
    _ARG = sys.argv[1] if len(sys.argv) > 1 else ""
    if _ARG == "--lock-path":
        print(lock_path())
        sys.exit(0)
    if _ARG == "--lock-holder":
        _PATH = lock_path()
        print(f"   {RED}FAIL{OFF} {refusal_text(_PATH, _holder_record(_PATH))}")
        sys.exit(0)
    if _ARG.startswith("--only"):
        # `--only nmap,hydra` / `--only=nmap,hydra` — the same subset the env var selects, so a CI job
        # or an operator can drive one row without exporting anything.
        _VAL = _ARG.split("=", 1)[1] if "=" in _ARG else (sys.argv[2] if len(sys.argv) > 2 else "")
        if not _VAL.strip():
            die("--only needs a comma-separated tool list, e.g. --only nmap,hydra")
        ONLY_TOOLS = {t.strip().lower() for t in _VAL.split(",") if t.strip()}
        sys.exit(main())
    if _ARG:
        die(f"unknown argument {_ARG!r}. This harness takes no arguments, or --lock-path / "
            "--lock-holder / --only <tools>.")
    sys.exit(main())
