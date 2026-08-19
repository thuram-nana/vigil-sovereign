"""doctor — a read-only preflight/health report for the WHOLE system.

Answers, in one place: is every prerequisite present, are the two venvs built, are the runtime dirs
writable, are the UI ports free (or already held by a running `vigil up`), and is every docker service the
system needs UP (create the missing ones with `vigil services up`)? Read-only + pure-stdlib (no
framework/strix/sigil), so it runs on the boundary-safe path and never mutates anything.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path

_UI_PORTS = (("proxy", 8770), ("cockpit", 8733), ("console", 8787), ("api", 8799))


def find_repo_root() -> Path:
    """Best-effort repo root — the dir holding `.venv-offense` / `.vigil-live` / `docker-compose.yml`.
    Anchors on the offense venv (a console/CLI runs IN `repo/.venv-offense`, so `sys.prefix`'s parent is
    the repo), then the cwd. Never raises; falls back to the venv parent. Shared by the readiness report
    and the services bring-up so both agree on which tree to inspect/act on."""
    import sys
    for start in (Path(sys.prefix).parent, Path.cwd()):
        try:
            start = start.resolve()
        except OSError:
            continue
        for cand in [start, *start.parents]:
            if (cand / ".venv-offense").exists():
                return cand
    return Path(sys.prefix).parent


def _port_free(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # mirror the real proxy bind
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _writable(p: Path) -> bool:
    """True if p exists and is writable, OR p is absent but its nearest existing parent is writable (so it
    can be created). Never raises."""
    try:
        probe = p
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        return os.access(str(probe), os.W_OK)
    except OSError:
        return False


# ── LLM backend probe ───────────────────────────────────────────────────────────────────────────────
# The LOCAL, network-served backends the engine routes through the loopback-enforced provider layer (never
# a cloud SDK). SELF-CONTAINED stdlib mirror of live.think_claude._LOCAL_BACKEND_NAMES (minus `dryrun`, the
# in-process stub handled separately) — kept here so doctor never imports framework on the boundary-safe
# path. KEEP IN SYNC with integration/vigil_integration/live/think_claude.py.
_LOCAL_NET_BACKENDS = ("ollama", "vllm", "llama-cpp", "tgi", "self-hosted")
# Ollama's endpoint when CRUCIBLE_OLLAMA_HOST is unset — mirror of think_claude._configured_local_endpoint.
_OLLAMA_DEFAULT_HOST = "http://localhost:11434"
_SOVEREIGN_TRUTHY = ("1", "true", "yes", "on")     # mirror of kernel.sovereignty._TRUTHY


def _resolve_tier() -> str:
    """The sovereignty TIER from env — stdlib mirror of kernel.sovereignty._resolve_tier_from_env: an
    explicit CRUCIBLE_SOVEREIGNTY_TIER wins (an UNKNOWN name → AIR_GAPPED, fail-closed); the legacy
    CRUCIBLE_SOVEREIGN_MODE flag → AIR_GAPPED; else PERMISSIVE (the development default)."""
    raw = os.environ.get("CRUCIBLE_SOVEREIGNTY_TIER", "").strip().upper()
    if raw:
        return raw if raw in ("AIR_GAPPED", "SOVEREIGN_CLOUD", "TRUSTED_CLOUD", "PERMISSIVE") else "AIR_GAPPED"
    if os.environ.get("CRUCIBLE_SOVEREIGN_MODE", "").strip().lower() in _SOVEREIGN_TRUTHY:
        return "AIR_GAPPED"
    return "PERMISSIVE"


def _local_endpoint(backend: str) -> str:
    """The endpoint a LOCAL backend WILL dial, resolved from env WITHOUT constructing it — stdlib mirror of
    think_claude._configured_local_endpoint. Ollama → CRUCIBLE_OLLAMA_HOST (default localhost:11434); the
    self-hosted family → CRUCIBLE_SELFHOSTED_ENDPOINT / LLM_API_BASE."""
    name = (backend or "").strip().lower()
    if name == "ollama":
        return os.environ.get("CRUCIBLE_OLLAMA_HOST", _OLLAMA_DEFAULT_HOST).strip()
    return (os.environ.get("CRUCIBLE_SELFHOSTED_ENDPOINT") or os.environ.get("LLM_API_BASE") or "").strip()


def _endpoint_host_port(url: str) -> "tuple[str, int]":
    """(host, port) from a URL — port defaults by scheme (https→443, else 80). ('', 0) when unparseable.
    Never raises."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return "", 0
    host = (parts.hostname or "").strip().strip("[]")
    if not host:
        return "", 0
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:                                  # an out-of-range port literal
        return host, 0
    return host, int(port)


def _host_is_loopback(host: str) -> bool:
    """True IFF host is loopback (`localhost` or a loopback IP LITERAL). A hostname (DNS can move) or a
    non-loopback IP is NOT — mirror of think_claude._url_host_is_local's host rule. Never raises."""
    import ipaddress
    h = (host or "").strip().strip("[]").lower()
    if not h:
        return False
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _tcp_reachable(host: str, port: int, timeout: float = 1.5) -> bool:
    """True IFF a bare TCP connect to (host, port) succeeds in `timeout`s. Read-only (no request body),
    used ONLY against a loopback endpoint, so nothing leaves the host. Never raises."""
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_llm_backend() -> dict:
    """Resolve the LLM backend `vigil engage`'s think step will use, plus its endpoint, and — for a LOCAL
    network backend — whether its loopback daemon actually answers.

    Read-only + pure-stdlib: it makes at most ONE bare TCP connect, and ONLY to a loopback endpoint (a
    non-loopback local endpoint, which the engine itself REFUSES, is reported but never probed), so nothing
    leaves the host. Reachability is a tri-state: True/False for a probed loopback backend, None when not
    applicable (a cloud pick, the in-process DryRun stub, or a non-loopback/absent endpoint). Never raises."""
    override = os.environ.get("CRUCIBLE_LLM_BACKEND", "").strip().lower()
    tier = _resolve_tier()
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    out: dict = {"tier": tier, "override": override or None, "anthropic_api_key": has_key}

    def _describe_local(backend: str) -> None:
        ep = _local_endpoint(backend)
        out.update(backend=backend, local=True, endpoint=(ep or None))
        if not ep:
            out["reachable"] = None
            out["detail"] = (f"local backend {backend!r}: no endpoint configured "
                             f"(set CRUCIBLE_SELFHOSTED_ENDPOINT / LLM_API_BASE) — reachability not probed.")
            return
        host, port = _endpoint_host_port(ep)
        if not _host_is_loopback(host):
            out["reachable"] = None                     # the engine refuses this; do NOT egress-probe it
            out["detail"] = (f"local backend {backend!r} points at a NON-loopback endpoint ({ep}); the engine "
                             f"REFUSES it (it would send the prompt off-host). Point it at localhost / 127.0.0.1.")
            return
        reachable = _tcp_reachable(host, port)
        out["reachable"] = reachable
        out["detail"] = (f"local backend {backend!r} at {ep} is "
                         f"{'reachable' if reachable else 'NOT answering'} on loopback.")

    if override:
        out["source"] = "CRUCIBLE_LLM_BACKEND"
        if override in _LOCAL_NET_BACKENDS:
            _describe_local(override)
        elif override == "dryrun":
            out.update(backend="dryrun", local=True, endpoint=None, reachable=None,
                       detail="the deterministic in-process DryRun stub — always available, egresses nothing.")
        else:                                           # a cloud backend (or unknown name): no local probe
            out.update(backend=override, local=False, endpoint=None, reachable=None,
                       detail=(f"cloud backend {override!r} (tier {tier}); reachability is not probed offline. "
                               f"ANTHROPIC_API_KEY is {'set' if has_key else 'NOT set'}."))
        return out

    # auto (CRUCIBLE_LLM_BACKEND unset): an HONEST best-effort of the engine's documented order — cloud
    # first WHEN the tier admits an Anthropic key and one is set, else the local Ollama daemon, else DryRun.
    out["source"] = "auto"
    cloud_ok = tier in ("PERMISSIVE", "TRUSTED_CLOUD")   # tiers that admit a direct / ZDR Anthropic key
    if cloud_ok and has_key:
        name = ("anthropic-zdr"
                if os.environ.get("CRUCIBLE_ANTHROPIC_ZDR", "").strip().lower() in _SOVEREIGN_TRUTHY
                else "anthropic")
        out.update(backend=name, local=False, endpoint=None, reachable=None,
                   detail=(f"auto ⇒ cloud {name!r} (tier {tier}, ANTHROPIC_API_KEY set); reachability not "
                           f"probed offline. Set CRUCIBLE_LLM_BACKEND to pin a backend."))
        return out
    _describe_local("ollama")                            # no usable cloud key (or a local-only tier)
    if not out.get("reachable"):                         # Ollama absent → the always-available DryRun stub
        prior = out.get("detail", "")
        out.update(backend="dryrun", local=True, endpoint=None, reachable=None,
                   detail=(f"{prior} Falling back to the in-process DryRun stub (always available; egresses "
                           f"nothing). Start Ollama (CRUCIBLE_OLLAMA_HOST) or set CRUCIBLE_LLM_BACKEND.").strip())
    return out


def collect(repo_root) -> dict:
    """Assemble the health report as a plain dict (JSON-safe). Never raises — every probe fails soft."""
    repo = Path(repo_root)
    report: dict = {"ok": True, "issues": [], "notes": []}

    def _issue(msg: str) -> None:      # a HARD prerequisite (flips ok False → `vigil doctor` exits 1)
        report["ok"] = False
        report["issues"].append(msg)

    def _note(msg: str) -> None:       # advisory (optional dependency) — does NOT flip ok
        report["notes"].append(msg)

    # 1) binaries
    bins = {b: bool(shutil.which(b)) for b in ("docker", "git", "python3", "nft", "bwrap")}
    report["binaries"] = bins
    has_docker = bins["docker"]
    compose_ok = False
    if has_docker:
        try:
            compose_ok = subprocess.run(["docker", "compose", "version"],
                                        capture_output=True, text=True, timeout=15).returncode == 0
        except (OSError, subprocess.SubprocessError):
            compose_ok = False
    report["docker_compose"] = compose_ok
    if not has_docker:
        _note("docker is not installed — the gateway + qdrant/neo4j/otel services can't be brought up "
              "(optional: the engine still runs; SIGIL falls back to embedded vectors).")

    # 2) the two venvs (hard prerequisites for `vigil up`)
    venvs = {
        "offense (vigil)": (repo / ".venv-offense" / "bin" / "vigil").exists(),
        "sovereign (sigil)": (repo / ".venv-sovereign" / "bin" / "sigil").exists(),
    }
    report["venvs"] = venvs
    for label, present in venvs.items():
        if not present:
            _issue(f"the {label} venv is not built — run ./bootstrap.sh (or envs/build_envs.sh).")

    # 3) runtime dirs
    home = Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))
    live = repo / ".vigil-live"
    report["dirs"] = {
        "SIGIL_HOME": {"path": str(home), "exists": home.exists(), "writable": _writable(home)},
        ".vigil-live": {"path": str(live), "exists": live.exists(), "writable": _writable(live)},
    }
    for key in ("SIGIL_HOME", ".vigil-live"):
        if not report["dirs"][key]["writable"]:
            _issue(f"{key} ({report['dirs'][key]['path']}) is not writable — `vigil up` needs to write there.")

    # 4) UI ports (free, or in-use — likely a `vigil up` already running)
    report["ui_ports"] = {name: ("free" if _port_free(p) else "in-use") for name, p in _UI_PORTS}

    # 5) docker services (create the absent ones with `vigil services up`)
    services: dict = {}
    if has_docker:
        try:
            from vigil_gateway.docker import SandboxNetworking
            gw = SandboxNetworking().status()
            services["vigil-gateway"] = {"state": gw.get("gateway", "absent"),
                                         "networks": gw.get("networks", {}), "image": gw.get("image")}
        except Exception as exc:  # noqa: BLE001 — a probe must never crash the report
            services["vigil-gateway"] = {"error": str(exc)}
        try:
            from .services import RootServices
            for name, meta in RootServices(repo).status().items():
                services[name] = {"state": meta["state"], "purpose": meta["purpose"]}
        except Exception as exc:  # noqa: BLE001
            services["_root_error"] = str(exc)
    report["docker_services"] = services

    # 6) the `vigil` entrypoint — the console SUBPROCESSES it (never imports it across the two-env boundary).
    #    Resolve it EXACTLY as the console does (console.actions._vigil_bin: a VIGIL_BIN override, else on
    #    $PATH) so doctor agrees with the console. ABSENT ⇒ two visible features degrade SILENTLY, so this is
    #    a HARD issue that names them.
    vigil_env = os.environ.get("VIGIL_BIN", "").strip()
    vigil_bin = vigil_env or shutil.which("vigil")
    report["vigil_entrypoint"] = {
        "resolved": bool(vigil_bin), "path": vigil_bin or None,
        "source": ("VIGIL_BIN" if vigil_env else ("PATH" if vigil_bin else None)),
    }
    if not vigil_bin:
        _issue("`vigil` is not on $PATH (and VIGIL_BIN is unset) — TWO features degrade silently: the console "
               "Terminal Run button errors ('the vigil entrypoint is not resolvable'), and the "
               "agentic/fireteam engage bridge falls back to the non-agentic offense engine. Fix: add "
               "~/.local/bin to $PATH (bootstrap.sh installs the launcher there) or export "
               "VIGIL_BIN=<repo>/.venv-offense/bin/vigil.")

    # 7) LLM backend — the backend + endpoint `vigil engage`'s think step will use, and (for a LOCAL network
    #    backend) whether its loopback daemon actually answers. A local backend that is not answering is a
    #    NOTE (advisory: a cloud pick needs no local daemon; a LOCAL pick never falls back to cloud — it
    #    REFUSES — so a dead local daemon is worth surfacing, but it does not block the rest of bring-up).
    llm = _probe_llm_backend()
    report["llm_backend"] = llm
    if llm.get("local") and llm.get("reachable") is False:
        _note(f"the LLM backend {str(llm.get('backend'))!r} at {llm.get('endpoint')} is not answering on "
              f"loopback — a LOCAL model pick will REFUSE (it never falls back to cloud). Start it, or pick a "
              f"cloud model / set CRUCIBLE_LLM_BACKEND.")
    return report


def render(report: dict) -> str:
    """A compact human-readable rendering of collect()'s dict."""
    def _mark(ok: bool) -> str:
        return "OK " if ok else "!! "
    lines = ["VIGIL doctor — system readiness", "=" * 34]
    lines.append("\nBinaries:")
    for b, present in report.get("binaries", {}).items():
        lines.append(f"  {_mark(present)}{b}")
    lines.append(f"  {_mark(report.get('docker_compose'))}docker compose (v2)")
    lines.append("\nEnvironments:")
    for label, present in report.get("venvs", {}).items():
        lines.append(f"  {_mark(present)}{label} venv")
    lines.append("\nRuntime dirs:")
    for key, d in report.get("dirs", {}).items():
        lines.append(f"  {_mark(d['writable'])}{key}  ({d['path']}, writable={d['writable']})")
    lines.append("\nUI ports (127.0.0.1):")
    for name, st in report.get("ui_ports", {}).items():
        lines.append(f"  {'OK ' if st == 'free' else '.. '}{name}: {st}")
    lines.append("\nDocker services (create absent ones: `vigil services up [--all]`):")
    for name, d in report.get("docker_services", {}).items():
        if isinstance(d, dict) and "error" in d:
            lines.append(f"  !! {name}: {d['error']}")
        elif isinstance(d, dict):
            st = d.get("state", "?")
            lines.append(f"  {'OK ' if st == 'running' else '.. '}{name}: {st}"
                         + (f"  ({d['purpose']})" if d.get("purpose") else ""))
        else:
            lines.append(f"  .. {name}: {d}")
    ve = report.get("vigil_entrypoint")
    if ve is not None:
        lines.append("\n`vigil` entrypoint (Terminal Run + agentic/fireteam bridge subprocess it):")
        if ve.get("resolved"):
            lines.append(f"  OK vigil: {ve.get('path')}  (via {ve.get('source')})")
        else:
            lines.append("  !! vigil: NOT on $PATH (VIGIL_BIN unset) — Terminal Run errors, and agentic/"
                         "fireteam engage falls back to the non-agentic engine")
    llm = report.get("llm_backend")
    if llm is not None:
        lines.append("\nLLM backend (`vigil engage` think step):")
        reach = llm.get("reachable")
        mark = "!! " if reach is False else "OK "
        seg = f"  {mark}{llm.get('backend', '?')}  (source: {llm.get('source', '?')}, tier: {llm.get('tier')}"
        if llm.get("endpoint"):
            seg += f", endpoint: {llm['endpoint']}"
        seg += (", reachable" if reach is True else (", NOT answering" if reach is False else "")) + ")"
        lines.append(seg)
        if llm.get("detail"):
            lines.append(f"     {llm['detail']}")
    issues = report.get("issues", [])
    if issues:
        lines.append("\nAction needed (blocks bring-up):")
        lines += [f"  - {m}" for m in issues]
    else:
        lines.append("\nAll hard prerequisites present. Bring up services with `vigil services up`, then "
                     "`vigil up`.")
    notes = report.get("notes", [])
    if notes:
        lines.append("\nNotes (optional):")
        lines += [f"  - {m}" for m in notes]
    return "\n".join(lines)
