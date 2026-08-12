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
