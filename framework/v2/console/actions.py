"""
console.actions — the SAFE operator actions (the only mutations the console makes).

Three, all non-destructive and none of which relax scope or bypass a gate:

  * launch a loopback `scan` — spawns the SAME gated CLI as a subprocess with
    `--format json --progress-log`, streams progress to a run file the SSE tails, and
    saves the JSON report for the Findings screen. The scan itself is unchanged.
  * re-verify a saved report — a pure re-computation of the retained oracle
    certificates (`verify.reverify`), no traffic.
  * trip the kill-switch — the emergency hard stop (a write the operator explicitly
    asks for; the console never CLEARS a kill-switch — clearing is a deliberate act).

Runs live under `<.console>/runs/<run_id>/` (progress.jsonl + report.json + meta.json).
Nothing here is on the scan hot path; a launched run is an ordinary subprocess.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from ..common import paths

_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def console_dir() -> Path:
    d = Path(paths.v2_root()) / ".console"
    (d / "runs").mkdir(parents=True, exist_ok=True)
    return d


def run_dir(run_id: str) -> Path:
    return console_dir() / "runs" / run_id


def _write_meta(run_id: str, **fields) -> None:
    try:
        (run_dir(run_id) / "meta.json").write_text(
            json.dumps(fields, default=str, indent=2), encoding="utf-8")
    except OSError:
        pass


def launch_scan(target: str, *, max_pages: int = 60, use_library: bool = True) -> dict:
    """Spawn a loopback `scan` subprocess that streams progress + saves its report.
    Returns ``{run_id, status}``. Refuses a non-loopback target (scan is loopback-only;
    a remote target must go through the gated `engage`)."""
    host = (urlsplit(target).hostname or "").lower()
    if host not in _LOOPBACK:
        return {"error": "scan is loopback-only (127.0.0.1/localhost/::1); use engage for remote"}

    run_id = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}"
    rd = run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    progress = rd / "progress.jsonl"
    progress.write_text("", encoding="utf-8")
    cmd = [
        sys.executable, "-m", "framework.v2", "scan", target,
        "--format", "json", "--progress-log", str(progress),
        "--reverifiable-out", str(rd / "reverifiable.json"),
        "--max-pages", str(max_pages),
        # a quick, bounded console scan: skip the out-of-band blind checks (they need
        # a receiver + poll for callbacks, adding latency) and prioritise per point.
        "--no-oob", "--targeted",
    ]
    _write_meta(run_id, target=target, cmd=cmd, status="running", started=time.time())

    def _run() -> None:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # noqa: S603
            if proc.returncode == 0 and proc.stdout.strip():
                (rd / "report.json").write_text(proc.stdout, encoding="utf-8")
                _write_meta(run_id, target=target, cmd=cmd, status="done",
                            rc=proc.returncode, finished=time.time())
            else:
                _write_meta(run_id, target=target, cmd=cmd, status="error",
                            rc=proc.returncode, stderr=(proc.stderr or "")[-2000:],
                            finished=time.time())
        except Exception as e:  # never let a launch crash the console
            _write_meta(run_id, target=target, cmd=cmd, status="error", error=str(e))

    threading.Thread(target=_run, daemon=True).start()
    return {"run_id": run_id, "status": "running", "progress": f"runs/{run_id}"}


def reverify_run(run_id: str) -> dict:
    """Re-run the retained oracle certificates in a saved run's report — a pure,
    offline re-computation (no traffic). Returns a compact reproduce roll-up."""
    rep = run_dir(run_id) / "reverifiable.json"
    if not rep.is_file():
        return {"error": "no re-verifiable artifact for that run (still running?)"}
    try:
        from ..verify import reverify

        doc = json.loads(rep.read_text(encoding="utf-8"))
        results = reverify.reverify_document(doc)
        total = len(results)
        ok = sum(1 for r in results if getattr(r, "ok", False))
        return {
            "run_id": run_id, "total": total, "reproduced": ok,
            "results": [
                {"finding": getattr(r, "finding_ref", ""), "reproduced": getattr(r, "reproduced", None),
                 "confirmed_by": getattr(r, "confirmed_by", None), "note": getattr(r, "note", "")}
                for r in results
            ],
        }
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def trip_killswitch(slug: str, reason: str) -> dict:
    """Trip the kill-switch for an engagement — the emergency stop. Idempotent (the
    first reason is preserved). The console never CLEARS a kill-switch."""
    try:
        from ..authority.killswitch import KillSwitch

        ks = KillSwitch(slug)
        ks.trip(reason or "tripped from Ops Console")
        return {"slug": slug, "tripped": True, "reason": ks.reason()}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
