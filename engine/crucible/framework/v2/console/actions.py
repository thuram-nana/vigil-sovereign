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


# ---- slice C2b: seedless cloud / Kubernetes / infra posture launch ----------
#
# A cloud/K8s/infra assessment has NO web seed URL — the just-added `engage <slug> --fuse-only` path
# runs ONLY the operator's declared OFFLINE sensor fusion (targets/<slug>/fusion.json) and its
# promotion oracles. This action just ENSURES the right sensor task is on that manifest and SPAWNS the
# already-gated `engage --fuse-only` CLI; it mints nothing itself, cannot relax scope (scope is
# charter-signed) and cannot bypass a gate (the spawned CLI has its own kill-switch + signed-charter
# preflight, and every fused sensor is gated at run time). Two-env boundary: this file imports nothing
# from sigil/apps — only the offense engine's own CLI, spawned as a subprocess.

# mode -> the SAFE, offline, Tier-1 fusion sensor it runs. AWS/GCP/Azure all use the cloud/CSPM export
# importer (cloud_import); Kubernetes uses the kube-bench report importer (kube_bench); a generic infra
# posture uses the declared-service inventory (declared_service). Each is already on
# engage_fusion._SAFE_SENSORS and registered in engage_fusion._fusion_registry.
_CLOUD_MODES = {
    "cloud": "cloud_import",
    "k8s": "kube_bench",
    "infra": "declared_service",
}

# A `cloud` assessment must name its provider (recorded on the task for operator context; the sensor
# reads inventory_file/format only).
_CLOUD_PROVIDERS = frozenset({"aws", "gcp", "azure"})

# An engagement slug directs targets/<slug>/... — it MUST be a single, path-safe component (no
# separators, no traversal). A single-segment allowlist rules out '/', '\\', '..' and every shell
# metacharacter, so it can never escape targets/ nor be mis-read as anything but a slug.
_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

# A cloud identifier: an account id / subscription / project / cluster label. Allow alphanumerics and a
# small safe punctuation set; DISALLOW '/' (which rules out URLs and CIDRs and path separators) and
# every shell metacharacter. The label is NEVER a shell arg (the spawn is an argv list, no shell) and
# NEVER a file path (data paths are derived from the validated slug) — this allowlist is defence in
# depth so it also cannot be a seed URL or a network range.
_CLOUD_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:@-]{0,127}\Z")


def _valid_slug(slug: str) -> bool:
    return bool(slug) and ".." not in slug and _SLUG_RE.match(slug) is not None


def _valid_cloud_label(target: str) -> tuple[bool, str]:
    """Validate the cloud identifier (account/subscription/project/cluster label). It must be a
    non-empty, injection-safe label — explicitly NOT a URL, a CIDR/network range, or a path."""
    if not target:
        return False, "target (a cloud account/subscription/project/cluster label) is required"
    if "://" in target:
        return False, "target is a cloud identifier, not a URL — a cloud/K8s run has no web seed"
    if "/" in target:
        return False, "target is a cloud identifier, not a URL / CIDR / path (no '/')"
    if not _CLOUD_LABEL_RE.match(target):
        return False, ("target has invalid characters — expected a plain account/subscription/project/"
                       "cluster label (letters, digits, '.', '_', '-', ':', '@', space)")
    return True, ""


def _has_signed_charter(slug: str) -> bool:
    """True iff a SIGNED charter exists for the slug — the console-side authorization gate. Uses the
    SAME ``ethics.is_charter_signed`` bar the spawned engage --fuse-only re-checks fail-closed (an
    unfilled ``<name>`` placeholder does NOT count as signed), so the console cannot start an assessment
    the engine's own charter gate would refuse. Total: any path/parse trouble is a fail-closed False."""
    try:
        from ..common.ethics import is_charter_signed
        return bool(is_charter_signed(slug)[0])
    except Exception:
        return False


def _fusion_task_for(slug: str, mode: str, provider: str, label: str) -> dict:
    """The single fusion task for a chosen mode — a default the operator fills in with their real
    export. Every FILE path is derived from the validated slug (via paths.target_dir), NEVER from
    operator input, so the write target cannot be traversed. The provider/label are recorded as
    context only (the offline sensor reads inventory_file/report/host)."""
    td = Path(paths.target_dir(slug))
    if mode == "cloud":
        return {"sensor": "cloud_import",
                "args": {"inventory_file": str(td / "cloud-inventory.json"), "format": "auto",
                         "provider": provider, "label": label}}
    if mode == "k8s":
        return {"sensor": "kube_bench",
                "args": {"report": str(td / "kube-bench.json"), "label": label}}
    # infra -> declared_service: a host/services inventory (the operator edits in real in-scope
    # services; the sensor is charter-scope-gated, so an out-of-scope label simply no-ops — fail-closed).
    return {"sensor": "declared_service",
            "args": {"host": label, "services": [], "label": label}}


def _ensure_fusion_manifest(slug: str, mode: str, provider: str, label: str) -> tuple[Path, bool]:
    """Ensure targets/<slug>/fusion.json carries the right sensor task. Writes a DEFAULT single-task
    manifest ONLY when absent (owner-only, path-safe); an operator-authored manifest is RESPECTED and
    left untouched. Returns ``(path, wrote_default)``."""
    path = Path(paths.target_dir(slug)) / "fusion.json"
    if path.is_file():
        return path, False
    task = _fusion_task_for(slug, mode, provider, label)
    paths.secure_write(path, json.dumps({"tasks": [task]}, indent=2))
    return path, True


def _append_progress(progress: Path, event: dict) -> None:
    """Append one JSON event line to a run's progress.jsonl (best-effort) so the run-based SSE view has
    something to tail immediately (mirrors the scan launcher's progress stream)."""
    try:
        with progress.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except OSError:
        pass

def launch_cloud(slug: str, mode: str, target: str, *, provider: str = "") -> dict:
    """Launch a SEEDLESS cloud / Kubernetes / infra POSTURE assessment (slice C2b).

    Requires a signed charter for ``slug`` (the gate), validates ``mode``/``provider`` and the cloud
    ``target`` label (non-empty, injection-safe, NOT a URL/CIDR/path — never a seed), ENSURES
    ``targets/<slug>/fusion.json`` carries the right offline sensor task (writing a path-safe default
    only when absent), then SPAWNS the already-gated ``engage <slug> --fuse-only --spine`` subprocess.

    Returns ``{run_id, status, mode, slug, provider, target, stream}`` on launch, or ``{error}`` on any
    refusal. Cannot relax scope (scope is charter-signed) nor bypass a gate (the spawned CLI has its own
    kill-switch + signed-charter preflight, and every fused sensor is gated at run time)."""
    mode = (mode or "").strip().lower()
    if mode not in _CLOUD_MODES:
        return {"error": f"unknown assessment mode {mode!r} "
                         f"(expected one of: {', '.join(sorted(_CLOUD_MODES))})"}
    slug = (slug or "").strip()
    if not _valid_slug(slug):
        return {"error": "invalid engagement slug (expected [A-Za-z0-9._-], a single path-safe "
                         "component — no separators, no '..')"}
    target = (target or "").strip()
    ok, why = _valid_cloud_label(target)
    if not ok:
        return {"error": why}
    provider = (provider or "").strip().lower()
    if mode == "cloud" and provider not in _CLOUD_PROVIDERS:
        return {"error": f"a cloud assessment needs a provider "
                         f"(one of: {', '.join(sorted(_CLOUD_PROVIDERS))})"}
    # THE GATE: a cloud/K8s posture engagement needs a SIGNED charter for the slug, like a remote
    # engage. (The spawned CLI re-checks this fail-closed — this is the early, honest console refusal.)
    if not _has_signed_charter(slug):
        return {"error": f"no signed charter for {slug!r} — a cloud/Kubernetes/infra assessment needs "
                         f"a SIGNED charter (targets/{slug}/charter.md; fill the 'Signed:' line). Run "
                         "`intake` to scaffold one."}

    try:
        fusion_path, wrote = _ensure_fusion_manifest(slug, mode, provider, target)
    except Exception as e:
        return {"error": f"could not prepare the fusion plan: {type(e).__name__}: {e}"}

    sensor = _CLOUD_MODES[mode]
    run_id = _new_run_id()
    rd = run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    progress = rd / "progress.jsonl"
    progress.write_text("", encoding="utf-8")
    # The spawn is an ARGV LIST (no shell) built from the VALIDATED slug — the operator's target label
    # is NEVER on the command line (it lives only inside the JSON fusion.json value), so there is no
    # argv-injection surface. --fuse-only forbids a seed; --spine mirrors the gated run onto the spine.
    cmd = [sys.executable, "-m", "framework.v2", "engage", slug, "--fuse-only", "--spine"]

    def _meta(**extra) -> None:
        _write_meta(run_id, target=target, slug=slug, mode=mode, provider=provider or None,
                    sensor=sensor, fusion_json=str(fusion_path), wrote_fusion=wrote, cmd=cmd, **extra)

    _meta(status="running", started=time.time())
    _append_progress(progress, {"event": "launch.fusion", "mode": mode, "slug": slug,
                                "sensor": sensor, "provider": provider or None, "target": target})

    def _run() -> None:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # noqa: S603
            status = "done" if proc.returncode == 0 else "error"
            _append_progress(progress, {"event": "scan.done", "status": status, "rc": proc.returncode})
            _meta(status=status, rc=proc.returncode,
                  summary=(proc.stdout or "")[-4000:], stderr=(proc.stderr or "")[-2000:],
                  finished=time.time())
        except Exception as e:  # never let a launch crash the console
            _append_progress(progress, {"event": "scan.done", "status": "error"})
            _meta(status="error", error=str(e), finished=time.time())

    threading.Thread(target=_run, daemon=True).start()
    return {"run_id": run_id, "status": "running", "mode": mode, "slug": slug,
            "provider": provider or None, "target": target, "stream": f"runs/{run_id}"}
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
# never traverse out of the runs dir. Every console read/write route funnels through run_dir, so this one
# guard covers report / worldmodel / coverage / evidence / remediate / reverify alike (fail-closed: a bad id
# raises ValueError; remediate_plan _safe-wraps it to an honest empty state, every other route lets it
# bubble to do_GET/do_POST which map it to a clean 404 — never a 500, never a traversal).
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _safe_run_id(run_id: str) -> str:
    rid = str(run_id or "")
    if ".." in rid or not _SAFE_RUN_ID.match(rid):
        raise ValueError(f"unsafe run id: {run_id!r}")
    return rid


def run_dir(run_id: str, *, ephemeral: bool = False) -> Path:
    # D2: an ephemeral run store lives on an in-memory tmpfs base (purged when the console
    # exits), never under the repo's .console/runs. Default path unchanged.
    if ephemeral:
        from ..common.ephemeral import console_run_base
        return console_run_base() / _safe_run_id(run_id)
    return console_dir() / "runs" / _safe_run_id(run_id)


def _write_meta(run_id: str, *, ephemeral: bool = False, **fields) -> None:
    try:
        (run_dir(run_id, ephemeral=ephemeral) / "meta.json").write_text(
            json.dumps({**fields, "ephemeral": ephemeral}, default=str, indent=2),
            encoding="utf-8")
    except OSError:
        pass


def launch_scan(target: str, *, max_pages: int = 60, use_library: bool = True,
                ephemeral: bool = False) -> dict:
    """Spawn a loopback `scan` subprocess that streams progress + saves its report.
    Returns ``{run_id, status}``. Refuses a non-loopback target (scan is loopback-only;
    a remote target must go through the gated `engage`). With ``ephemeral`` the whole run
    store (progress/report/reverifiable/meta) lands on an in-memory tmpfs base purged when
    the console exits — nothing under the repo's .console/runs."""
    host = (urlsplit(target).hostname or "").lower()
    if host not in _LOOPBACK:
        return {"error": "scan is loopback-only (127.0.0.1/localhost/::1); use engage for remote"}

    run_id = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}"
    rd = run_dir(run_id, ephemeral=ephemeral)
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
    _write_meta(run_id, ephemeral=ephemeral, target=target, cmd=cmd,
                status="running", started=time.time())

    def _run() -> None:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # noqa: S603
            if proc.returncode == 0 and proc.stdout.strip():
                (rd / "report.json").write_text(proc.stdout, encoding="utf-8")
                _write_meta(run_id, ephemeral=ephemeral, target=target, cmd=cmd, status="done",
                            rc=proc.returncode, finished=time.time())
            else:
                _write_meta(run_id, ephemeral=ephemeral, target=target, cmd=cmd, status="error",
                            rc=proc.returncode, stderr=(proc.stderr or "")[-2000:],
                            finished=time.time())
        except Exception as e:  # never let a launch crash the console
            _write_meta(run_id, ephemeral=ephemeral, target=target, cmd=cmd,
                        status="error", error=str(e))

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


def provision_tool(body: dict) -> dict:
    """On-demand install of ONE B1-admitted, missing host tool (Phase B2). CSRF/rebind-gated by the caller
    (do_POST). Delegates to the fail-closed tools.install.install_tool: only an admitted tool, only its
    DECLARED apt/pip hint (never a caller package/command), and only with explicit operator ``consent`` —
    without consent it returns the exact command it WOULD run (the ask-operator path), mutating nothing."""
    from ..tools.install import install_tool
    # STRICT consent: only a real JSON boolean `true` is consent — NOT a truthy non-bool like the string
    # "false" (bool("false") is True). Anything else takes the ask path (needs_consent), mutating nothing.
    return install_tool(str(body.get("name", "")), consent=(body.get("consent") is True))


def _docker_ready() -> tuple[bool, str]:
    """Whether the Strix sandbox can run: the ``docker`` CLI is on PATH AND its daemon answers. Strix runs
    every agent inside a container and HARD-EXITS if docker is missing, so a codebase run must pre-flight
    this and fail HONESTLY rather than hang or error opaquely. Bounded + never raises."""
    if not shutil.which("docker"):
        return False, "the 'docker' CLI was not found on PATH"
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=8)  # noqa: S603,S607
    except (subprocess.TimeoutExpired, OSError, ValueError) as e:
        # ValueError covers a UnicodeDecodeError from text=True on non-UTF-8 output — so "never raises" holds.
        return False, f"the docker daemon did not answer ({type(e).__name__})"
    if p.returncode == 0:
        return True, "docker daemon reachable"
    return False, "the docker daemon is not reachable (is Docker running?)"


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
                      capture_report: bool, env_extra: "dict | None" = None) -> None:
    """Run ``cmd`` as a daemon subprocess, recording status transitions into meta.json. When
    ``capture_report`` (the scan path) and it exits 0 with JSON on stdout, the report is saved for
    the Findings screen; otherwise stdout/stderr are retained for the run detail. Mirrors
    ``launch_scan``'s runner exactly — a launched run is an ordinary, non-hot-path subprocess.

    ``env_extra`` is merged over ``os.environ`` for the child (used to hand a Strix run its Proof Studio
    run context — ``VIGIL_PROOF_RUN_DIR`` — so the proof_sink writes proofs under this run's dir)."""
    child_env = {**os.environ, **env_extra} if env_extra else None

    def _run() -> None:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600,  # noqa: S603
                                  env=child_env)
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


# ---- console → live-engine bridge (per-session Neo4j graph) ------------------
# The raw offense `framework.v2 engage` the console spawns uses an in-memory world-model and has NO Neo4j
# projection (by the two-env boundary — the offense plane carries no Neo4j code). The per-session knowledge
# graph lives ONLY on the integration `vigil engage` path (partitions by `--session`, unions connected
# sessions by `--connect`; F3/F4). So a graph-backed run must be routed to that separate `vigil` process —
# subprocessed, never imported (the console is offense-plane; importing vigil_integration is FATAL-2).
_GRAPH_ITERS = {"quick": 6, "standard": 12, "deep": 20}


def _vigil_bin() -> "str | None":
    """The integration `vigil` entrypoint if resolvable — a `VIGIL_BIN` override or on PATH. Subprocessed
    (never imported), exactly as the console already subprocesses the foreign `strix` binary."""
    return os.environ.get("VIGIL_BIN") or shutil.which("vigil")


def _graph_backed_engage_cmd(target: str, slug: str, session_id: str, scan_mode: str) -> "list | None":
    """The argv for a GRAPH-BACKED loopback engage via `vigil engage`, or None (→ caller falls back to the
    offense engage) unless BOTH a `vigil` entrypoint is resolvable AND Neo4j is configured (NEO4J_URI). The
    caller gates on is_loopback, so `--scope 127.0.0.1` is the owner's own machine — no charter downgrade is
    possible. `--session` partitions the per-session graph; `--connect` unions the operator-connected
    sessions (each prior stays origin-tagged + non-authoritative)."""
    vigil = _vigil_bin()
    if not vigil or not os.environ.get("NEO4J_URI"):
        return None
    from . import sessions
    conns = ",".join(sessions.connections_of(session_id))
    cmd = [vigil, "engage", target, "--slug", slug, "--scope", "127.0.0.1",
           "--session", session_id, "--max-iterations", str(_GRAPH_ITERS.get(scan_mode, 12))]
    if conns:
        cmd += ["--connect", conns]
    return cmd


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
    # F2: the session this run belongs to (optional). Recorded in meta so list_runs/session_detail can
    # associate the run; an unsafe id is dropped (never a traversal, never a raise) — the run still launches.
    session_id = str(body.get("session_id", "")).strip()
    if session_id:
        try:
            from . import sessions
            session_id = sessions._safe_session_id(session_id)
        except ValueError:
            session_id = ""

    run_id = _new_run_id()
    rd = run_dir(run_id)
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "progress.jsonl").write_text("", encoding="utf-8")
    if session_id:                                    # F2: attach this run to its permanent session
        try:
            from . import sessions
            sessions.link_run(session_id, run_id)
        except Exception:  # noqa: BLE001 — a registry hiccup must never sink the launch
            pass

    # meta shared by every branch; apply_fixes/model/keyless are RECORDED (shown in the UI) but do
    # not add an un-gated fire path — a fix is proposed and QUEUES for approval (the Fixes screen).
    base = {"mode": mode, "target": target, "scope": scope, "objective": objective,
            "scan_mode": scan_mode, "tools": tools, "apply_fixes": apply_fixes,
            "keyless": keyless, "model": model, "started": time.time(), "session_id": session_id}

    # ---- codebase → strix (path-validated, headless, Docker pre-flighted) --
    if mode == "codebase":
        p = Path(target).expanduser()
        if not p.exists():
            return {"error": f"codebase path does not exist: {target}"}
        # Strix runs every agent inside a Docker sandbox and hard-exits without it — pre-flight so a codebase
        # run fails honestly instead of hanging (operator "a failure always indicates" rule). URL/infra
        # targets don't need Docker; only the Strix codebase body does.
        ready, why = _docker_ready()
        if not ready:
            return {"error": f"a codebase run uses the Strix sandbox, which needs Docker — {why}. Start "
                             f"Docker and retry, or give a URL/infra target instead."}
        strix = shutil.which("strix") or "strix"
        mount = bool(body.get("mount", False))
        # --non-interactive: run headless (no TUI, exit on completion). WITHOUT it Strix launches its
        # terminal UI and a background/console spawn hangs forever — the A4a codebase path was broken.
        cmd = [strix, "--non-interactive", ("--mount" if mount else "--target"), str(p)]
        if objective:
            cmd += ["--instruction", objective]
        slug = _slugify(p.name, fallback="codebase")
        meta = {**base, "slug": slug, "cmd": cmd, "stream": "none", "status": "running"}
        _write_meta(run_id, **meta)
        # Proof Studio (B5/C1) activation: hand the Strix child THIS run's dir so its proof_sink
        # (vigil_integration.proof.bootstrap.install_from_env) mints + persists oracle-confirmed proofs under
        # <rd>/proofs (+ evidence under <rd>/evidence), which the Export button then bundles. Absent for a
        # standalone Strix; a NO-OP if the integration package isn't importable.
        _spawn_background(run_id, rd, cmd, meta, capture_report=False,
                          env_extra={"VIGIL_PROOF_RUN_DIR": str(rd), "VIGIL_ENGAGEMENT": slug})
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

    # console→live-engine bridge (OPT-IN): a session-linked LOOPBACK run can go GRAPH-BACKED through the
    # integration `vigil engage` — which partitions the per-session Neo4j graph and unions the connected
    # sessions (F3/F4), the thing the offense engine the console otherwise spawns cannot do. Loopback-only
    # (owner's own machine — no charter downgrade). If opted-in but `vigil`/Neo4j is unavailable, fall
    # through to the normal path with an honest note; the run still launches (session linkage is kept).
    if bool(body.get("graph_backed")) and session_id and is_loopback:
        gslug = _slugify(body.get("slug") or "loopback", fallback="loopback")
        gcmd = _graph_backed_engage_cmd(target, gslug, session_id, scan_mode)
        if gcmd is not None:
            meta = {**base, "slug": gslug, "cmd": gcmd, "stream": "none", "status": "running",
                    "engine": "integration-graph", "graph_partition": session_id}
            _write_meta(run_id, **meta)
            _spawn_background(run_id, rd, gcmd, meta, capture_report=False)
            return {"run_id": run_id, "status": "running", "mode": mode, "slug": gslug,
                    "stream": "none", "engine": "integration-graph", "graph_partition": session_id}
        base["graph_note"] = ("graph-backed requested but unavailable (needs the `vigil` entrypoint + "
                              "NEO4J_URI + a loopback target); ran the offense engine — session linkage kept")

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


def run_evolve_tick(slug: str) -> dict:
    """K5 self-evolve TICK that PERSISTS — unlike the read-only ``api.evolve_data`` GET. Seeds one
    calibration PREDICTION per DRAFT proposal into the slug's OutcomeLedger, saves it, then RE-PLANS so
    ``studied_enough`` reflects the now-open predictions. Kill-switch gated. It only DRAFTS proposals +
    records predictions — it NEVER merges/applies a proposal, fires no oracle, and mints NO fact (the OUTCOME
    of each prediction is recorded later by a real engagement)."""
    slug = "".join(c for c in str(slug or "").strip() if c.isalnum() or c in "-_.")[:120]
    if not slug:
        return {"ok": False, "error": "select an engagement (slug required)"}
    try:
        from datetime import datetime, timezone

        from ..authority.killswitch import KillSwitch
        from ..calibration.ledger import OutcomeLedger
        from ..knowledge_engine.cli import _DEFAULT_SKILLS, _vuln_leads
        from ..knowledge_engine.evolve import ledger_path, plan_evolution, record_predictions

        if KillSwitch(slug).is_tripped():
            return {"ok": False, "refused": "kill-switch tripped", "slug": slug}
        leads = _vuln_leads(slug)
        now = datetime.now(timezone.utc)                 # wallclock read ONCE at the action boundary
        lp = ledger_path(slug)
        ledger = OutcomeLedger.load(lp) if lp.is_file() else OutcomeLedger()
        plan = plan_evolution(leads, skills_dir=_DEFAULT_SKILLS, now=now, ledger=ledger)
        recorded = record_predictions(plan, ledger, base_seq=len(ledger))
        ledger.save(lp)
        # re-plan AFTER seeding so studied_enough reflects the now-open predictions (else done=True could
        # flip False on the next read).
        plan = plan_evolution(leads, skills_dir=_DEFAULT_SKILLS, now=now, ledger=ledger)
        return {"ok": True, "slug": slug, "predictions_recorded": recorded,
                "proposals": [p.id for p in plan.proposals], "horizon_gaps": len(plan.horizon_gaps),
                "coverage_gaps": [{"bug_class": g.bug_class, "priority": g.priority}
                                  for g in plan.coverage_gaps],
                "unlearned_leads": plan.unlearned, "studied_enough": plan.studied_enough}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def knowledge_gitsync(action: str) -> dict:
    """A6c/K6: run ``vigil knowledge status|sync`` from the Knowledge screen and surface the result —
    ESPECIALLY the secret-scan REFUSAL. ``status`` shows what would commit; ``sync`` regenerates the
    system-map + secret-scans + commits the ``knowledge/`` folder LOCALLY (it does NOT push — the outward
    ``vigil knowledge push`` stays a deliberate CLI act). Shells the exec-only ``vigil`` (never imports it),
    fail-closed on a bad action / unresolvable bin / non-JSON output. On a secret-scan refusal (exit 3) the
    files are surfaced so the operator can redact."""
    action = str(action or "").strip()
    if action not in ("status", "sync"):
        return {"ok": False, "error": "action must be 'status' or 'sync' (push stays a deliberate CLI act)"}
    vigil = _vigil_bin()
    if not vigil:
        return {"ok": False, "error": "the `vigil` entrypoint is not resolvable (set VIGIL_BIN / activate the venv)"}
    try:
        proc = subprocess.run([vigil, "knowledge", action], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    parsed = {}
    if proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
        except ValueError:
            parsed = {"raw": proc.stdout[:2000]}
    if proc.returncode == 3:      # `vigil knowledge sync` exits 3 on a secret-scan refusal (stderr lists files)
        return {"ok": False, "action": action,
                "refused": "secret(s) found in knowledge/ — remove or redact before committing",
                "stderr": (proc.stderr or "")[:2000],
                **(parsed if isinstance(parsed, dict) else {})}
    return {"ok": proc.returncode == 0, "action": action,
            **(parsed if isinstance(parsed, dict) else {})}


# A vulnerability lead id (CVE-…, GHSA-…, an advisory id) as it reaches the `knowledge learn --vuln`
# CLI. It is NEVER a shell arg (the spawn is an argv LIST, no shell) — this allowlist is defence in depth
# so a hostile value can never begin with '-' (mistaken for a flag), carry a separator, or traverse.
_VULN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}\Z")

# Doctrine surfaced to the Knowledge screen for both new actions — kept honest: leads/advisories only.
_DEEPLEARN_DOCTRINE = ("Advisory only: deep-learn drafts FIND/PREVENT skills + a GATED DETECT proposal. "
                       "It mints NO fact, bumps NO prior, fires NO oracle, applies nothing "
                       "(a DETECT maps onto EXISTING oracle kinds or a gated proposal — authorise≠apply).")
_FEEDPULL_DOCTRINE = ("Every feed entry is an intel-tier LEAD, never a fact — only a fired oracle mints a "
                      "FACT. 'Pull now' is a one-shot, conscious opt-in egress; recurring auto-pull stays a "
                      "separate sidecar, never started here.")


def run_deep_learn(slug: str, vuln_id: str) -> dict:
    """K3 deep-learn for ONE unlearned vuln lead — DRAFT FIND/PREVENT advisory skills + a GATED DETECT
    proposal, by shelling the SAME gated ``knowledge learn --slug S --vuln V`` CLI a hand-run uses (an argv
    LIST, no shell — the offense engine's own ``python -m framework.v2``, never the integration ``vigil``).

    It mints NO fact, bumps NO prior, fires NO oracle, and applies nothing: a DETECT resolves onto EXISTING
    deterministic oracle kinds or drafts a GATED ``ImprovementProposal`` (authorise≠apply). Kill-switch gated
    — pre-checked HERE (an honest early refusal, no subprocess) AND re-checked by the CLI (exit 3). Fail-closed
    on a bad slug / vuln id / unresolvable interpreter; never a traceback."""
    slug = "".join(c for c in str(slug or "").strip() if c.isalnum() or c in "-_.")[:120]
    if not slug:
        return {"ok": False, "error": "select an engagement (slug required)"}
    vuln_id = str(vuln_id or "").strip()
    if not _VULN_ID_RE.match(vuln_id):
        return {"ok": False, "error": "a vulnerability id is required "
                                      "(e.g. CVE-2024-1234 — letters, digits, '.', '-', '_' only)"}
    try:
        from ..authority.killswitch import KillSwitch
        if KillSwitch(slug).is_tripped():                 # honest early refusal — nothing spawned under STOP
            return {"ok": False, "refused": "kill-switch tripped", "slug": slug}
    except Exception as e:  # noqa: BLE001 — a killswitch read hiccup fails closed, never a traceback
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    # argv LIST (no shell); the sanitized slug + allowlisted vuln id are the only operator-derived tokens.
    cmd = [sys.executable, "-m", "framework.v2", "knowledge", "learn", "--slug", slug, "--vuln", vuln_id]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)  # noqa: S603
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if proc.returncode == 3:                               # kill-switch tripped between pre-check and spawn
        return {"ok": False, "refused": "kill-switch tripped", "slug": slug}
    if proc.returncode == 2:                               # no such vuln lead for this slug (CLI usage/error)
        return {"ok": False, "slug": slug, "vuln_id": vuln_id,
                "error": (proc.stderr or "no such vulnerability lead for this engagement").strip()[:400]}
    parsed = {}
    if proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
        except ValueError:
            parsed = {"raw": proc.stdout[:2000]}
    d = parsed if isinstance(parsed, dict) else {}
    return {"ok": proc.returncode == 0, "slug": slug, "vuln_id": vuln_id,
            "learned": d.get("learned") or [], "drafted_oracle_proposals": d.get("drafted_oracle_proposals"),
            "doctrine": d.get("doctrine") or _DEEPLEARN_DOCTRINE}


def run_feed_pull(slug: str) -> dict:
    """K1 'Pull now' — a ONE-SHOT gated vuln-feed refresh from the trusted sources (NVD / OSV / CISA-KEV), by
    shelling the SAME gated ``intel refresh-vulnintel --live --slug S`` CLI (an argv LIST, no shell). ``--live``
    IS the conscious operator opt-in this click carries; recurring auto-pull stays a separate sidecar, never
    started here.

    Everything minted is an intel-tier LEAD — NO fact, NO prior, NO oracle fired. Kill-switch gated —
    pre-checked HERE (an honest early refusal, no traffic) AND re-checked by the CLI before and BETWEEN fetches
    (exit 3). Fail-closed on an unresolvable interpreter / non-JSON output; never a traceback. In an offline
    environment the per-source single-host allowlist simply refuses egress (applied 0, hosts_refused N) — honest,
    not a crash."""
    slug = "".join(c for c in str(slug or "").strip() if c.isalnum() or c in "-_.")[:120]
    if not slug:
        return {"ok": False, "error": "select an engagement (slug required)"}
    try:
        from ..authority.killswitch import KillSwitch
        if KillSwitch(slug).is_tripped():                 # honest early refusal — no traffic under STOP
            return {"ok": False, "refused": "kill-switch tripped", "slug": slug}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    cmd = [sys.executable, "-m", "framework.v2", "intel", "refresh-vulnintel", "--live", "--slug", slug]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # noqa: S603
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if proc.returncode == 3:                               # kill-switch tripped between pre-check and spawn
        return {"ok": False, "refused": "kill-switch tripped", "slug": slug}
    parsed = {}
    if proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
        except ValueError:
            parsed = {"raw": proc.stdout[:2000]}
    d = parsed if isinstance(parsed, dict) else {}
    if proc.returncode != 0 and not d:
        return {"ok": False, "slug": slug, "error": (proc.stderr or "feed pull failed").strip()[:400]}
    return {"ok": proc.returncode == 0, "slug": slug, "live": True,
            "minted_by_source": d.get("minted_by_source"), "applied": d.get("applied"),
            "queries_run": d.get("queries_run"), "cancelled": d.get("cancelled"),
            "hosts_refused": d.get("refused"),            # per-source egress refusals (NOT a gating refusal)
            "doctrine": d.get("doctrine") or _FEEDPULL_DOCTRINE}


def proof_export(run_id: str) -> dict:
    """Proof Studio (C1): assemble a CLIENT-VERIFIABLE proof bundle from a run's oracle-confirmed FACTs, so a
    third party can re-verify it OFFLINE with zero trust in VIGIL. Shells the exec-only ``vigil proof-export``
    (never imports the integration package), passing the RESOLVED run dir (the integration process can't
    locate the console's ``.console/runs/<id>`` across the two-env boundary) + the run's slug. Fail-closed on
    an unresolvable bin / bad run id (``run_dir`` raises ValueError on traversal → do_POST maps it to 404)."""
    rd = run_dir(run_id)                       # traversal-guarded; raises ValueError on a bad id
    try:
        slug = json.loads((rd / "meta.json").read_text(encoding="utf-8")).get("slug") or ""
    except (OSError, ValueError, AttributeError):
        slug = ""
    slug = "".join(c for c in str(slug).strip() if c.isalnum() or c in "-_.")[:120] or "engagement"
    vigil = _vigil_bin()
    if not vigil:
        return {"ok": False, "error": "the `vigil` entrypoint is not resolvable (set VIGIL_BIN / activate the venv)"}
    out = str(rd / "proof-bundle")
    try:
        proc = subprocess.run([vigil, "proof-export", "--run-dir", str(rd), "--out", out, "--slug", slug],
                              capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or "export failed").strip()[:800]}
    try:
        fingerprint = (Path(out) / "TRUST-ROOT-FINGERPRINT.txt").read_text(encoding="utf-8").strip()
    except OSError:
        fingerprint = ""
    return {"ok": True, "bundle": out, "output": (proc.stdout or "")[:2000],
            "trust_root_fingerprint": fingerprint,
            "verify_cmd": ("cd <bundle> && python -m framework.v2 evidence verify --report reverifiable.json "
                           "--bundle . --trust-root trust-root.json --evidence-root evidence "
                           "--trust-root-fingerprint " + (fingerprint or "<published-fingerprint>")),
            "note": "A third party re-verifies this bundle OFFLINE — no target, no network. They don't trust "
                    "VIGIL's word: they re-run the deterministic check themselves. Trust reduces to two "
                    "auditable things — the operator's governance PUBLIC key (identified by the fingerprint "
                    "above, which you PUBLISH OUT-OF-BAND so the client pins it) and the open-source verifier. "
                    "One flipped byte fails it closed; an unpinned in-bundle root proves consistency + "
                    "reproduction but NOT authenticity."}


def apply_fix(run_id: str, finding_ref: str) -> dict:
    """Fixes screen (U1): run the GATED, NON-DESTRUCTIVE auto-patch ladder for ONE oracle-confirmed finding by
    shelling ``vigil patch`` — the SAME provenance-grounded gated verb the CLI uses. The driving finding comes
    from the engagement's OWN signed spine (``--from-spine``, never raw JSON); ``--apply-edits`` applies the fix
    into a DISPOSABLE clone + sandbox-build, so the real source is never touched and NO PR is opened. Returns the
    verb's REAL output — a proof-of-fix on success, or its fail-closed refusal verbatim (e.g. a missing signed
    spine, or no model to propose a patch). The console NEVER opens a PR: that stays a deliberate m-of-n CLI act
    (`vigil patch --open-pr`), and `remediated=True` is EARNED only when the driving oracle re-fires SILENT on
    the rebuilt patch (the live re-drive capability), never asserted here.

    Fail-closed: a bad run id (``run_dir`` raises ValueError → do_POST maps to 404), an unsafe finding ref, a run
    with no repository to patch (a live-target/URL/cloud run), or an unresolvable ``vigil`` bin each refuse cleanly.
    """
    rd = run_dir(run_id)                        # traversal-guarded; raises ValueError on a bad id → 404
    finding_ref = str(finding_ref or "").strip()
    # the ref is an argv element AND is echoed into the spine finding lookup — keep it a bare token, never a
    # path / flag / whitespace-injection (no separators, no '..', no leading dash).
    if (not finding_ref or len(finding_ref) > 200 or finding_ref.startswith("-") or ".." in finding_ref
            or any(c in finding_ref for c in "/\\ \t\r\n")):
        return {"ok": False, "error": "invalid finding reference"}
    try:
        meta = json.loads((rd / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ok": False, "error": f"no such run {run_id!r}"}
    slug = str(meta.get("slug") or "").strip()
    if not _valid_slug(slug):
        return {"ok": False, "error": "this run has no valid engagement slug to ground the fix in."}
    repo = str(meta.get("target") or "").strip()
    # only a codebase (Strix) run has a source tree to patch; a live-target (URL/cloud/aegis) run has nothing.
    if str(meta.get("mode")) != "codebase" or not repo:
        return {"ok": False, "runnable": False,
                "error": "this run has no repository to patch — the gated auto-patch applies to a codebase "
                         "(Strix) run's source. Run a codebase assessment to enable a gated fix here."}
    vigil = _vigil_bin()
    if not vigil:
        return {"ok": False, "error": "the `vigil` entrypoint is not resolvable (set VIGIL_BIN / activate the venv)"}
    # PROVENANCE PRE-CHECK (honesty): `vigil patch --from-spine` grounds the finding in the engagement's OWN
    # signed offense spine at <base>/<slug>.spine — written ONLY by the integration `vigil engage` flow, NOT by
    # a console Strix codebase run. So rather than shell the verb only to surface its cryptic fail-closed error,
    # we check the spine exists first and, if not, return an HONEST, actionable refusal naming exactly what is
    # needed. `--base-dir` is passed EXPLICITLY so this check and the verb agree on the same base.
    base_dir = os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"
    spine = Path(base_dir) / f"{slug}.spine"
    if not spine.is_file():
        return {"ok": False, "runnable": False,
                "error": (f"no signed offense spine for {slug!r} at {spine} — the gated auto-patch grounds the "
                          "finding in the engagement's OWN signed spine (never raw JSON), and a console Strix "
                          "codebase run does not emit one yet. To enable a gated fix, run this engagement through "
                          f"`vigil engage --slug {slug} --base-dir {base_dir}` (which writes the signed spine), "
                          "then apply the fix here."),
                "command": (f"vigil patch --from-spine {slug} --finding-ref {finding_ref} "
                            f"--target-repo <repo> --base-dir {base_dir} --apply-edits")}
    # NON-DESTRUCTIVE + NEVER --open-pr from the console. The spawn is an argv LIST (no shell); slug + ref are
    # validated tokens; the repo path lives only in argv (no shell), never interpolated.
    cmd = [vigil, "patch", "--from-spine", slug, "--finding-ref", finding_ref,
           "--target-repo", repo, "--base-dir", base_dir, "--apply-edits"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # noqa: S603
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"the patch ladder failed to run: {type(e).__name__}: {e}"}
    out = ((proc.stdout or "") + (("\n--- stderr ---\n" + proc.stderr) if proc.stderr else "")).strip()[-8000:]
    return {"ok": proc.returncode == 0, "runnable": True, "rc": proc.returncode,
            "finding_ref": finding_ref, "slug": slug,
            "command": ("vigil patch --from-spine " + slug + " --finding-ref " + finding_ref
                        + " --target-repo <repo> --base-dir " + base_dir + " --apply-edits"),
            "output": out or "(no output)",
            "note": ("Non-destructive: `vigil patch` proposes a fix and, IF it can, applies it into a DISPOSABLE "
                     "clone + sandbox-build — your source is never touched and no PR is opened. The real per-run "
                     "status/applied_paths/remediated are in the output above. `remediated=True` is EARNED only "
                     "when the driving oracle re-fires SILENT on the rebuilt patch (the live re-drive capability); "
                     "opening a real PR is a separate m-of-n-gated CLI act (`vigil patch --open-pr`).")}


def provision_loopback_authority(slug: str) -> dict:
    """Charter/attestation UI: mint + sign a CRUCIBLE authority for a LOOPBACK engagement slug, scope
    HARD-FIXED to ``127.0.0.1``. The UI can provision a *loopback* charter, but — per the constitution — a
    REMOTE target needs a signed charter the UI CANNOT mint (that is a deliberate out-of-band ceremony).
    Shells the exec-only ``vigil provision``; fail-closed. Scope is never taken from the caller."""
    slug = "".join(c for c in str(slug or "").strip() if c.isalnum() or c in "-_.")[:120]
    if not slug:
        return {"ok": False, "error": "slug required (a path-safe token)"}
    vigil = _vigil_bin()
    if not vigil:
        return {"ok": False, "error": "the `vigil` entrypoint is not resolvable (set VIGIL_BIN / activate the venv)"}
    try:
        # scope is a HARD-CODED literal, never the caller's — the UI cannot widen it or provision a remote charter.
        proc = subprocess.run([vigil, "provision", "--slug", slug, "--scope", "127.0.0.1"],
                              capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": proc.returncode == 0, "slug": slug, "scope": "127.0.0.1",
            "output": (proc.stdout or "")[:2000], "stderr": (proc.stderr or "")[:1000] if proc.returncode else "",
            "note": "Provisioned a LOOPBACK authority (scope 127.0.0.1). A REMOTE target needs a signed charter "
                    "this UI cannot mint — that stays a deliberate `vigil provision` / charter ceremony."}


def attestation_ledger() -> dict:
    """Charter/attestation UI: replay the who/when/what usage-attestation ledger + verify its hash-chain.
    Shells the exec-only ``vigil ledger who`` + ``vigil verify-ledger`` (read-only) — the ledger is
    append-only + signed, so this only REPLAYS it, never mints. Fail-closed."""
    vigil = _vigil_bin()
    if not vigil:
        return {"ok": False, "error": "the `vigil` entrypoint is not resolvable"}

    def _run(args: list) -> tuple:
        try:
            p = subprocess.run([vigil, *args], capture_output=True, text=True, timeout=60)
            return p.returncode, (p.stdout or "").strip()
        except (OSError, subprocess.SubprocessError):
            return 1, ""

    who_rc, who = _run(["ledger", "who"])
    ver_rc, ver = _run(["verify-ledger"])
    return {"ok": who_rc == 0, "who": who[:4000], "verify": ver[:1000], "verified": ver_rc == 0,
            "note": "The usage attestation (who / when / what) is minted BEFORE any target-touching action — "
                    "no attestation, no run — and the chain is signed, so a record can't be back-dated."}


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
