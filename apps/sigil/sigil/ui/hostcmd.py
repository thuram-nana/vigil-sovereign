"""Wave 6 (parity) — the sovereign HOST-RUN BROKER: run a CLOSED SET of long `sigil` host-ops (rebuild
memory / vectors / consolidate) as a TRACKED background subprocess, from the browser. Owner-gated at the
route; status/list reads are viewer+.

This is the single highest-risk architectural addition in the FULL-UI-CONTROL program, so it is DELIBERATELY
NOT a generic "run host command" primitive:
  * CLOSED VERB SET — only a key of `_HOST_VERBS` can run; any other verb is refused.
  * NO free-text / NO path argv — the ONLY request input is a list of BOOLEAN flag NAMES; each is looked up
    in the verb's own allowlist and emitted as ``--<name>`` (an unknown flag is silently dropped). So the
    only strings that ever reach argv are a verb + flags drawn from fixed allowlists. `shell=False`.
  * RBAC BEFORE spawn — the route enforces owner BEFORE this module is reached.
  * ORPHAN-RECONCILE — the child's pid + the host boot_id are recorded at spawn, so a run orphaned by a
    host REBOOT (boot_id changed) or a dead pid is reconciled running→interrupted. (A pid recycled to an
    unrelated process WITHOUT a reboot is a narrow residual window — bounded by the 30-min timeout.)
  * BOUNDED — at most _MAX_CONCURRENT live runs at once (a launch beyond that is refused), owner-only.
FATAL-2: pure sovereign — imports nothing from framework/strix; it spawns ``python -m sigil`` in THIS venv.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

# verb -> the frozenset of ALLOWED boolean flag names (each becomes ``--<name>``). No value flags, no free
# text, no paths. Keep this the ONLY thing that decides what runs.
_HOST_VERBS: "dict[str, frozenset[str]]" = {
    "index": frozenset(),                            # rebuild the vector index — no flags
    "ingest": frozenset({"reset", "docs", "git"}),   # rebuild memory from transcripts/docs/git — boolean selectors
    "consolidate": frozenset({"dry-run"}),           # ARCHIVIST consolidation — only the safe dry-run from the UI
}

_MAX_CONCURRENT = 4   # a launch beyond this many live runs is refused (owner-only; each is a real subprocess)


def _dir() -> Path:
    from .. import config
    d = Path(config.SIGIL_HOME) / ".vigil-live" / "hostcmd"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _pid_alive(pid) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, ValueError):
        return False
    except PermissionError:
        return True   # exists, owned by another user (won't happen here, but treat as alive)


def _write(run_id: str, meta: dict) -> None:
    p = _dir() / f"{run_id}.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, default=str), encoding="utf-8")
    os.replace(tmp, p)


def _read(run_id: str) -> "dict | None":
    try:
        return json.loads((_dir() / f"{run_id}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _argv(verb: str, picked_flags: "list[str]") -> "list[str]":
    # verb + flags are already validated against the allowlists; run THIS interpreter's `sigil` module.
    return [sys.executable, "-m", "sigil", verb, *[f"--{f}" for f in picked_flags]]


def launch(verb: str, flags) -> dict:
    """Validate `verb` against the closed set + `flags` against the verb's allowlist, then spawn `sigil <verb>`
    as a tracked background subprocess. Returns {ok, run_id, verb, flags}. Owner-gated at the route."""
    verb = str(verb or "").strip()
    if verb not in _HOST_VERBS:
        return {"ok": False, "error": f"unknown host verb (allowed: {sorted(_HOST_VERBS)})"}
    live = sum(1 for r in list_runs(limit=100) if r.get("status") in ("running", "starting"))
    if live >= _MAX_CONCURRENT:
        return {"ok": False, "error": f"too many host ops running ({live}/{_MAX_CONCURRENT}) — wait for one to finish"}
    want = {str(x) for x in flags} if isinstance(flags, (list, tuple)) else set()
    picked = sorted(f for f in _HOST_VERBS[verb] if f in want)   # closed allowlist; deterministic order
    run_id = secrets.token_hex(8)
    base = {"run_id": run_id, "verb": verb, "flags": picked, "started": time.time()}
    _write(run_id, {**base, "status": "starting"})

    def _run() -> None:
        try:
            proc = subprocess.Popen(_argv(verb, picked), stdout=subprocess.PIPE,      # noqa: S603 — fixed argv
                                    stderr=subprocess.STDOUT, text=True)
        except (OSError, subprocess.SubprocessError) as e:
            _write(run_id, {**base, "status": "error", "error": f"{type(e).__name__}: {e}", "finished": time.time()})
            return
        _write(run_id, {**base, "status": "running", "pid": proc.pid, "boot_id": _boot_id()})
        try:
            out, _ = proc.communicate(timeout=1800)             # 30-min ceiling for a host op
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            out, rc = "(timed out after 30 min — killed)", 124
        _write(run_id, {**base, "status": ("done" if rc == 0 else "failed"), "exit_code": rc,
                        "finished": time.time(), "tail": (out or "")[-4000:], "pid": proc.pid,
                        "boot_id": _boot_id()})

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "run_id": run_id, "verb": verb, "flags": picked,
            "detail": f"{verb} started as a background host op — poll its status."}


def _reconcile(meta: dict) -> dict:
    """A run left 'running' by a console/host restart is dead — reconcile it so it never shows live forever."""
    if meta.get("status") == "running":
        boot = meta.get("boot_id") or ""
        if boot and boot != _boot_id():
            meta = {**meta, "status": "interrupted", "detail": "the host rebooted while this run was live"}
            _write(str(meta.get("run_id")), meta)
        elif not _pid_alive(meta.get("pid")):
            meta = {**meta, "status": "interrupted", "detail": "the process is gone (console restart?)"}
            _write(str(meta.get("run_id")), meta)
    return meta


def run_status(run_id) -> dict:
    if not isinstance(run_id, str) or not run_id.isalnum():      # token_hex is alnum → also blocks path chars
        return {"ok": False, "error": "bad run id"}
    meta = _read(run_id)
    if meta is None:
        return {"ok": False, "error": "no such run"}
    return {"ok": True, **_reconcile(meta)}


def list_runs(limit: int = 20) -> list:
    out: list = []
    try:
        paths = sorted(_dir().glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    except OSError:
        return out
    for p in paths[: max(1, min(int(limit or 20), 100))]:
        m = _read(p.stem)
        if m:
            out.append(_reconcile(m))
    return out
