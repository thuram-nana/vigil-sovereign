"""
console.actions — the SAFE operator actions (the only mutations the console makes).

Non-destructive, and none of which relaxes scope or bypasses a gate:

  * launch a loopback `scan` — spawns the SAME gated CLI as a subprocess with
    `--format json --progress-log`, streams progress to a run file the SSE tails, and
    saves the JSON report for the Findings screen. The scan itself is unchanged.
  * launch an ASSESSMENT (P2) — the New-Assessment wizard's one action. It routes a
    {mode,target,…} body to the SAME gated CLI a hand-run engagement uses (`scan` /
    `engage` / `engage --autonomous` / `strix` / `aegis`), spawned as a subprocess with
    `--spine` (engage) or `--progress-log` (scan) so the live view can tail it. It
    CANNOT relax scope or bypass a gate: scope is charter-signed (never passed here), a
    remote `engage` without a signed charter is refused, a non-loopback `scan` is refused,
    and every target-touching / destructive step still QUEUES for owner approval inside
    the engine (approve-then-run). Offense-side only.
  * re-verify a saved report — a pure re-computation of the retained oracle
    certificates (`verify.reverify`), no traffic.
  * trip the kill-switch — the emergency hard stop (a write the operator explicitly
    asks for; the console never CLEARS a kill-switch — clearing is a deliberate act).

Runs live under `<.console>/runs/<run_id>/` (progress.jsonl + report.json + meta.json).
Nothing here is on the scan hot path; a launched run is an ordinary subprocess.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from ..common import paths

_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

# The valid assessment modes and the wizard target-types they back.
_MODES = frozenset({"url", "codebase", "tool", "suite", "aegis"})

# The offense engine's ENGAGE capability packs — the "tools" the wizard offers under
# "pick tools". Each id maps to a REAL, already-gated `engage` flag (single source of
# truth for both the catalog the UI shows and the flags a launch spawns), so a picked
# capability deterministically becomes a gated engage flag and can never widen authority
# beyond what the charter/scope/kill-switch/egress stack already enforces. `tier` mirrors
# the governance tiers (T1 passive · T2 active · T3 adversary-sim) purely for display.
ENGAGE_CAPABILITIES: tuple[dict[str, str], ...] = (
    {"id": "recon", "flag": "--recon", "tier": "T1", "label": "Recon",
     "purpose": "Passive/active reconnaissance of the in-scope surface (endpoints, params, stack)."},
    {"id": "domxss", "flag": "--domxss", "tier": "T2", "label": "DOM XSS leads",
     "purpose": "Emit static DOM-XSS leads from client-side sinks (leads, not facts)."},
    {"id": "browser-xss", "flag": "--browser-xss", "tier": "T2", "label": "Browser XSS",
     "purpose": "Drive a real browser to confirm reflected/stored XSS via execution."},
    {"id": "spa", "flag": "--spa", "tier": "T2", "label": "SPA crawl",
     "purpose": "Crawl a single-page app's client-rendered routes for surface."},
    {"id": "sso", "flag": "--sso", "tier": "T2", "label": "SSO / federated",
     "purpose": "Probe SAML/OIDC flows for the federated-identity weakness classes."},
    {"id": "access-control", "flag": "--access-control", "tier": "T2", "label": "Access control",
     "purpose": "Test BOLA/BFLA authorization with operator-supplied victim references."},
    {"id": "graphql-dos", "flag": "--graphql-dos", "tier": "T3", "label": "GraphQL DoS",
     "purpose": "Adversary-sim GraphQL complexity/depth probes (gated; bounded)."},
    {"id": "arsenal", "flag": "--arsenal", "tier": "T3", "label": "Host arsenal",
     "purpose": "Run host CLIs (nmap/nuclei/…) — each host-gated through the full authority stack."},
)
_CAP_BY_ID: dict[str, dict[str, str]] = {c["id"]: c for c in ENGAGE_CAPABILITIES}

# scan depth (loopback quick-scan) → bounded page budget + the targeted flag.
_SCAN_DEPTH = {"quick": (20, True), "standard": (60, False), "deep": (150, False)}
# engage depth → a bounded request budget (scope/gate still enforce the real ceiling).
_ENGAGE_DEPTH = {"quick": 60, "standard": 200, "deep": 500}


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


# ---------------------------------------------------------------------------
# launch_assessment (P2) — the New-Assessment wizard's one gated action
# ---------------------------------------------------------------------------


def _new_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}"


def _slugify(raw: str, *, fallback: str) -> str:
    s = "".join(c if (c.isalnum() or c in "-_") else "-" for c in (raw or "").lower()).strip("-")
    return s[:48] or fallback


def _has_charter(slug: str) -> bool:
    """True iff the offense side already holds a signed charter OR authority for ``slug`` — the
    fail-closed pre-flight for a REMOTE engage. The console never mints one; provisioning a charter
    is a deliberate off-console act."""
    try:
        if Path(paths.charter_path(slug)).is_file():
            return True
    except Exception:
        pass
    try:
        return Path(paths.authority_path(slug)).is_file()
    except Exception:
        return False


def _spawn_background(run_id: str, rd: Path, cmd: list[str], meta: dict, *,
                      capture_report: bool) -> None:
    """Run ``cmd`` as a daemon subprocess, recording status transitions into meta.json. When
    ``capture_report`` (the scan path) and it exits 0 with JSON on stdout, the report is saved for
    the Findings screen; otherwise stdout/stderr are retained for the run detail. Mirrors
    ``launch_scan``'s runner exactly — a launched run is an ordinary, non-hot-path subprocess."""

    def _run() -> None:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # noqa: S603
            ok = proc.returncode == 0
            if capture_report and ok and proc.stdout.strip():
                (rd / "report.json").write_text(proc.stdout, encoding="utf-8")
            else:
                (rd / "stdout.txt").write_text(proc.stdout or "", encoding="utf-8")
            _write_meta(run_id, **{**meta, "status": "done" if ok else "error", "rc": proc.returncode,
                                   "stderr": (proc.stderr or "")[-2000:] if not ok else "",
                                   "finished": time.time()})
        except Exception as e:  # never let a launch crash the console
            _write_meta(run_id, **{**meta, "status": "error", "error": str(e)})

    threading.Thread(target=_run, daemon=True).start()


def launch_assessment(body: dict) -> dict:
    """Route the New-Assessment wizard body to the SAME gated CLI a hand-run engagement uses and
    spawn it. Returns ``{run_id, status, mode, slug, stream}`` or ``{error}`` (a clean, fail-closed
    refusal — never a traceback). It cannot relax scope (scope is charter-signed, never an argument
    here) nor bypass a gate (it spawns only the already-gated ``scan``/``engage``/``strix``/``aegis``
    CLIs); destructive/target-touching steps still QUEUE for owner approval inside the engine."""
    mode = str(body.get("mode", "")).strip().lower()
    if mode not in _MODES:
        return {"error": f"unknown assessment mode {mode!r} (expected one of {sorted(_MODES)})"}
    target = str(body.get("target", "")).strip()
    if not target:
        return {"error": "a target is required (a URL, a codebase path, or a log file)"}

    # scope is validated here for HONESTY (no CIDR — the offense scope model is literal hosts /
    # *.wildcards) and echoed into meta, but it is NEVER passed to the spawn: an engage's scope is
    # the one signed into its charter/authority, so the console structurally cannot widen it.
    scope = [str(s).strip() for s in (body.get("scope") or []) if str(s).strip()]
    for entry in scope:
        if "/" in entry:
            return {"error": f"scope entry {entry!r} looks like CIDR — use literal hosts or *.wildcards (no CIDR)"}

    objective = str(body.get("objective", "")).strip()[:400]
    scan_mode = str(body.get("scan_mode", "standard")).strip().lower()
    if scan_mode not in _SCAN_DEPTH:
        scan_mode = "standard"
    tools = [str(t).strip() for t in (body.get("tools") or []) if str(t).strip()]
    apply_fixes = bool(body.get("apply_fixes", False))
    keyless = bool(body.get("keyless", False))
    model = str(body.get("model", "")).strip()[:64]

    run_id = _new_run_id()
    rd = run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "progress.jsonl").write_text("", encoding="utf-8")

    # meta shared by every branch; apply_fixes/model/keyless are RECORDED (shown in the UI) but do
    # not add an un-gated fire path — a fix is proposed and QUEUES for approval (the Fixes screen).
    base = {"mode": mode, "target": target, "scope": scope, "objective": objective,
            "scan_mode": scan_mode, "tools": tools, "apply_fixes": apply_fixes,
            "keyless": keyless, "model": model, "started": time.time()}

    # ---- codebase → strix (path-validated) --------------------------------
    if mode == "codebase":
        p = Path(target).expanduser()
        if not p.exists():
            return {"error": f"codebase path does not exist: {target}"}
        strix = shutil.which("strix") or "strix"
        mount = bool(body.get("mount", False))
        cmd = [strix, ("--mount" if mount else "--target"), str(p)]
        if objective:
            cmd += ["--instruction", objective]
        slug = _slugify(p.name, fallback="codebase")
        meta = {**base, "slug": slug, "cmd": cmd, "stream": "none", "status": "running"}
        _write_meta(run_id, **meta)
        _spawn_background(run_id, rd, cmd, meta, capture_report=False)
        return {"run_id": run_id, "status": "running", "mode": mode, "slug": slug, "stream": "none"}

    # ---- aegis → the defensive dual (detect over a telemetry/log file) -----
    if mode == "aegis":
        sub = str(body.get("aegis_action", "detect")).strip().lower()
        if sub not in ("detect", "gateway"):
            sub = "detect"
        cmd = [sys.executable, "-m", "framework.v2", "aegis", sub]
        if sub == "detect":
            src = Path(target).expanduser()
            if not src.is_file():
                return {"error": f"aegis detect needs a TelemetryEnvelope/log file; not found: {target}"}
            cmd += [str(src)]
        slug = _slugify(body.get("slug") or "aegis", fallback="aegis")
        meta = {**base, "slug": slug, "cmd": cmd, "stream": "none", "status": "running"}
        _write_meta(run_id, **meta)
        _spawn_background(run_id, rd, cmd, meta, capture_report=False)
        return {"run_id": run_id, "status": "running", "mode": mode, "slug": slug, "stream": "none"}

    # ---- everything else targets a URL: url / suite / tool ----------------
    host = (urlsplit(target).hostname or "").lower()
    if not host:
        return {"error": f"target must be an absolute URL (got {target!r})"}
    is_loopback = host in _LOOPBACK

    # url + loopback → the SAME gated loopback scan (progress-log stream, JSON report captured).
    if mode == "url" and is_loopback:
        pages, targeted = _SCAN_DEPTH[scan_mode]
        cmd = [sys.executable, "-m", "framework.v2", "scan", target,
               "--format", "json", "--progress-log", str(rd / "progress.jsonl"),
               "--reverifiable-out", str(rd / "reverifiable.json"),
               "--max-pages", str(pages), "--no-oob"]
        if targeted:
            cmd += ["--targeted"]
        slug = _slugify(body.get("slug") or "loopback", fallback="loopback")
        meta = {**base, "slug": slug, "cmd": cmd, "stream": "progress", "status": "running"}
        _write_meta(run_id, **meta)
        _spawn_background(run_id, rd, cmd, meta, capture_report=True)
        return {"run_id": run_id, "status": "running", "mode": mode, "slug": slug, "stream": "progress"}

    # url / suite / tool on a URL → the gated `engage` (mirrors onto the blackboard via --spine).
    slug = _slugify(body.get("slug") or host, fallback="engagement")
    if not is_loopback and not _has_charter(slug):
        return {"error": f"a remote engage needs a signed charter/authority for slug {slug!r} — "
                         f"provision one first (it carries the signed scope; the console cannot mint it)"}

    cmd = [sys.executable, "-m", "framework.v2", "engage", slug, target, "--spine",
           "--request-budget", str(_ENGAGE_DEPTH[scan_mode])]
    if mode == "suite":
        cmd += ["--autonomous"]
        if scan_mode == "deep":
            cmd += ["--autonomous-cycles", "2"]
    # capability packs → their real, already-gated engage flags (single source of truth). For a
    # one-tool assessment exactly one is used; for url/suite the operator's picks are added.
    chosen = tools[:1] if mode == "tool" else tools
    for cap_id in chosen:
        cap = _CAP_BY_ID.get(cap_id)
        if cap:
            cmd += [cap["flag"]]
    meta = {**base, "slug": slug, "cmd": cmd, "stream": "blackboard", "status": "running"}
    _write_meta(run_id, **meta)
    _spawn_background(run_id, rd, cmd, meta, capture_report=False)
    return {"run_id": run_id, "status": "running", "mode": mode, "slug": slug, "stream": "blackboard"}


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
