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

import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from ..common import paths

_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_AEGIS_MODES = frozenset({"observe", "enforce"})

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


# A run id is a single, self-generated path component (`_new_run_id` → a timestamp + counter). Anything
# else — a separator, "..", a leading dot, an absolute/drive form — is refused so a URL-derived run id can
# never traverse out of the runs dir. Every console read route funnels through run_dir, so this one guard
# covers report / worldmodel / coverage / evidence / remediate alike (fail-closed: a bad id raises, and the
# read routes are _safe-wrapped so it surfaces as an honest empty/not-found, never a traversal).
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _safe_run_id(run_id: str) -> str:
    rid = str(run_id or "")
    if ".." in rid or not _SAFE_RUN_ID.match(rid):
        raise ValueError(f"unsafe run id: {run_id!r}")
    return rid


def run_dir(run_id: str) -> Path:
    return console_dir() / "runs" / _safe_run_id(run_id)


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


# ---------------------------------------------------------------------------
# AEGIS Defense gateway (P5a) — launch / stop / current-pointer
#
# The AEGIS gateway is a PERSISTENT data-plane reverse proxy (`serve_forever`), so — unlike a scan —
# it is spawned with subprocess.Popen (subprocess.run's timeout would kill it) and tracked by pid. It
# writes browser-safe verdicts to a JSONL the console SSE tails and a status snapshot the status read
# consumes. Exactly ONE managed gateway at a time (a single-pointer file). This does NOT relax any gate:
# it spawns the SAME `aegis gateway` CLI a hand-run deployment uses; enforce still needs the entitlement.
# ---------------------------------------------------------------------------


def _aegis_current_path() -> Path:
    return console_dir() / "aegis-current.json"


def _read_aegis_current() -> dict:
    try:
        return json.loads(_aegis_current_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_aegis_current(meta: dict) -> None:
    try:
        _aegis_current_path().write_text(json.dumps(meta, default=str, indent=2), encoding="utf-8")
    except OSError:
        pass


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, TypeError, ValueError):
        return False


def aegis_verdicts_path() -> str | None:
    """The JSONL the live verdict feed tails — the current gateway's verdicts file, or None."""
    cur = _read_aegis_current()
    p = cur.get("verdicts")
    return p if p else None


def aegis_setup(body: dict) -> dict:
    """Launch a managed AEGIS gateway in front of the operator's app. Fail-closed validation BEFORE any
    spawn; refuses if a gateway is already running. Returns the run info + the production edge command
    (secret redacted) so the operator can also run it on their own routable edge. Loopback-default; a
    routable bind is flagged (`warn_public`) — the gateway is the ONLY VIGIL server allowed off-loopback."""
    upstream = str(body.get("upstream", "")).strip()
    us = urlsplit(upstream)
    if us.scheme not in ("http", "https") or not us.hostname:
        return {"error": "upstream must be a full http(s) URL to your app, e.g. http://127.0.0.1:3000"}
    host = str(body.get("host", "127.0.0.1")).strip() or "127.0.0.1"
    try:
        port = int(body.get("port", 8080))
    except (TypeError, ValueError):
        return {"error": "port must be a number"}
    if not (1 <= port <= 65535):
        return {"error": "port must be 1–65535"}
    mode = str(body.get("mode", "observe")).strip()
    if mode not in _AEGIS_MODES:
        return {"error": "mode must be 'observe' or 'enforce'"}
    slug = _slugify(str(body.get("slug", "")), fallback="aegis-gateway")
    secret = str(body.get("deployment_secret", "")).strip()
    if not secret:
        return {"error": "a deployment secret is required — it keys privacy pseudonymisation of actor "
                         "identifiers (NOT request authentication); use the generate button"}
    if any(ord(c) < 0x20 for c in secret) or len(secret) > 4096:
        return {"error": "deployment secret must be a single line, ≤4096 chars"}
    honeypots = [str(h).strip() for h in (body.get("honeypot_paths") or []) if str(h).strip()]
    # A honeypot is a URL PATH — require a leading "/" (and no control chars). This also means a value
    # can never begin with "-" and be mistaken for a flag when it reaches the child argv (defence in depth
    # on top of the argv-list, no-shell spawn) — a hostile path is rejected here, never spawned.
    for hp in honeypots:
        if not hp.startswith("/") or any(ord(c) < 0x20 for c in hp):
            return {"error": f"honeypot path must start with '/' and contain no control chars: {hp!r}"}
    # Parse-check the config fail-closed before spawning (extra='forbid' rejects a malformed field).
    try:
        from ..aegis.models import AegisConfig
        AegisConfig(deployment_secret=secret, mode=mode, honeypot_paths=honeypots)
    except Exception as e:  # noqa: BLE001
        return {"error": f"invalid gateway config: {type(e).__name__}: {str(e)[:160]}"}
    if importlib.util.find_spec("httpx") is None:
        return {"error": "the gateway needs httpx to forward requests — install it (pip install httpx)"}
    cur = _read_aegis_current()
    if cur and _pid_alive(cur.get("pid")):
        return {"error": f"a gateway is already running (pid {cur.get('pid')} → {cur.get('upstream')}); "
                         f"stop it first", "running": cur}

    run_id = _new_run_id()
    rd = run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    verdicts = rd / "verdicts.jsonl"
    verdicts.write_text("", encoding="utf-8")
    status_file = rd / "status.json"
    cmd = [sys.executable, "-m", "framework.v2", "aegis", "gateway",
           "--upstream", upstream, "--host", host, "--port", str(port), "--mode", mode,
           "--slug", slug, "--secret", secret,
           "--verdicts-out", str(verdicts), "--status-out", str(status_file)]
    for hp in honeypots:
        cmd += ["--honeypot", hp]
    try:
        logf = open(rd / "gateway.log", "ab")  # noqa: SIM115 — held by the persistent child
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)  # noqa: S603
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not launch the gateway: {type(e).__name__}: {e}"}
    meta = {"run_id": run_id, "kind": "aegis", "upstream": upstream, "host": host, "port": port,
            "mode": mode, "slug": slug, "pid": proc.pid, "status": "running", "started": time.time(),
            "verdicts": str(verdicts), "status_file": str(status_file)}
    _write_meta(run_id, **meta)
    _write_aegis_current(meta)
    # the production edge command (secret REDACTED) — the operator runs this on their own routable edge.
    prod = ["aegis", "gateway", "--upstream", upstream, "--host", "0.0.0.0", "--port", str(port),
            "--mode", mode, "--slug", slug, "--secret", "<your-deployment-secret>"]
    for hp in honeypots:
        prod += ["--honeypot", hp]
    return {"run_id": run_id, "status": "running", "pid": proc.pid, "bind": f"{host}:{port}",
            "warn_public": host not in _LOOPBACK, "requested_mode": mode,
            "production_command": " ".join(prod)}


def aegis_stop(_body: dict | None = None) -> dict:
    """Stop the managed AEGIS gateway (SIGTERM). Idempotent — a no-op if none is running."""
    cur = _read_aegis_current()
    pid = cur.get("pid")
    if not pid or not _pid_alive(pid):
        _write_aegis_current({})
        return {"stopped": False, "note": "no gateway was running"}
    try:
        os.kill(int(pid), signal.SIGTERM)
    except (OSError, TypeError, ValueError) as e:
        return {"error": f"could not stop pid {pid}: {e}"}
    if cur.get("run_id"):
        _write_meta(cur["run_id"], **{**cur, "status": "stopped", "finished": time.time()})
    _write_aegis_current({})
    return {"stopped": True, "pid": pid}
