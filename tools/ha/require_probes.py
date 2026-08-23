"""W6-2 — every shipped VIGIL workload declares REAL health probes, wired to /readyz + /healthz.

WHY THIS EXISTS. Before W6-2 the k8s probes were decorative: the proxy Deployment and the sovereign
StatefulSet did a shallow ``GET /`` on the STATIC bundle — a page that returns 200 as long as the web
tier can read a file off disk, so **a proxy whose sovereign backend is dead stays Ready** and the load
balancer keeps routing to it. Worse, the single-writer sovereign StatefulSet — the one workload where a
wedged process is most dangerous — had **no liveness probe at all**, so a hung writer was never restarted.

W6-1 (#452) added the real surfaces: an unauthenticated, Host-ungated ``/healthz`` (liveness: the process
answers) and ``/readyz`` (readiness: a live probe of THAT server's real dependency, 503 when it is down).
This module is the deploy-time GATE that REFUSES to ship a manifest set unless:

  * every Deployment/StatefulSet workload declares BOTH a livenessProbe and a readinessProbe on every
    serving container (a container that declares a port), and
  * every VIGIL-OWNED workload (the sovereign cockpit, the reverse proxy) wires readiness to httpGet
    ``/readyz`` and liveness to httpGet ``/healthz`` on its serving port — never the shallow ``GET /``, and
  * every shipped VIGIL SERVER image's Dockerfile declares a HEALTHCHECK that exercises its real readiness
    surface (``/readyz`` for the AEGIS gateway; a TCP connect to the bind for the egress forward proxy,
    which is a CONNECT proxy with no HTTP routes and so no ``/readyz`` — W6-1 deliberately excluded it).

Pure stdlib + PyYAML (no sigil/offense imports, no live cluster), so it runs both as the ``tools/ha/deploy.sh``
preflight AND inside the required ``sigil-governor`` CI job (via ``apps/sigil/tests/test_ha_probes_required.py``).
Modelled on ``tools/ha/require_networkpolicy.py``.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# VIGIL's OWN HTTP servers in the k8s set — the ones that expose the W6-1 /healthz + /readyz routes. Their
# probes MUST be wired to those exact endpoints (readiness -> /readyz, liveness -> /healthz).
VIGIL_OWNED_APPS = ("vigil-sovereign", "vigil-proxy")
READYZ_PATH = "/readyz"
HEALTHZ_PATH = "/healthz"
# The pre-fix defect: a readiness probe on the static bundle root returns 200 even when the real backend is
# dead. A VIGIL-owned readiness probe must never point here.
SHALLOW_PATHS = ("/",)

WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet")

# The shipped VIGIL SERVER images (long-running services) and what a correct HEALTHCHECK must exercise.
# NOT listed, deliberately: the vendored Strix sandbox image (a throwaway per-target runner, third-party,
# no VIGIL health surface) and engine/crucible/.../eval/corpus_apps/* (deliberately-vulnerable SCAN
# FIXTURES, not services). Adding a HEALTHCHECK to those would be meaningless or wrong.
SERVER_DOCKERFILES = {
    # the AEGIS gateway exposes the W6-1 /healthz + /readyz (AegisGatewayHandler._handle_probe) on :8080;
    # its HEALTHCHECK must exercise /readyz.
    "engine/crucible/framework/v2/aegis/Dockerfile": "readyz",
    # the egress forward proxy is a CONNECT proxy, NOT an HTTP-routes server — it has no /readyz (W6-1's
    # server list deliberately excludes it). Its readiness surface is the LISTENING proxy socket, so its
    # HEALTHCHECK is a TCP connect to the bind (the same check infra/docker/docker-compose.yml uses).
    "gateway/Dockerfile": "tcp",
}


class ProbeRequirementError(RuntimeError):
    """Raised to REFUSE a deploy: a workload ships without both probes, a VIGIL-owned workload's probes are
    not wired to /readyz (readiness) + /healthz (liveness), or a shipped server image has no HEALTHCHECK."""


def _load_docs(path: Path) -> list[dict[str, Any]]:
    """Every mapping document in a (possibly multi-doc) YAML file; comment-only docs (``None``) dropped."""
    with Path(path).open(encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]


def _app_label(doc: dict[str, Any]) -> str | None:
    """The workload's ``app`` label — prefer its own metadata, fall back to the pod template's labels."""
    meta = ((doc.get("metadata") or {}).get("labels") or {}).get("app")
    if meta:
        return meta
    tmpl = (((doc.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels") or {}
    return tmpl.get("app")


def iter_workloads(manifests_dir: Path) -> list[tuple[Path, dict[str, Any], str | None]]:
    """(path, doc, app_label) for every Deployment/StatefulSet/... in the manifest dir."""
    out: list[tuple[Path, dict[str, Any], str | None]] = []
    for path in sorted(Path(manifests_dir).glob("*.yaml")):
        for doc in _load_docs(path):
            if doc.get("kind") in WORKLOAD_KINDS:
                out.append((path, doc, _app_label(doc)))
    return out


def serving_containers(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Containers (NOT initContainers) that declare at least one port — the ones that serve traffic and so
    must carry both probes. initContainers are one-shot and excluded."""
    spec = (((doc.get("spec") or {}).get("template") or {}).get("spec")) or {}
    return [c for c in (spec.get("containers") or []) if c.get("ports")]


def _container_ports(c: dict[str, Any]) -> set:
    """Every port name AND number the container declares (a probe may reference either)."""
    ports: set = set()
    for p in (c.get("ports") or []):
        if p.get("name") is not None:
            ports.add(p["name"])
        if p.get("containerPort") is not None:
            ports.add(p["containerPort"])
    return ports


def probe_target(probe: Any) -> tuple[str, str | None, Any]:
    """(kind, path, port) for a probe. kind is one of httpGet/tcpSocket/exec/grpc, or '' if none/other.
    ``path`` is set only for httpGet; ``port`` for httpGet/tcpSocket/grpc."""
    if not isinstance(probe, dict):
        return "", None, None
    if "httpGet" in probe:
        hg = probe["httpGet"] or {}
        return "httpGet", hg.get("path"), hg.get("port")
    if "tcpSocket" in probe:
        return "tcpSocket", None, (probe["tcpSocket"] or {}).get("port")
    if "grpc" in probe:
        return "grpc", None, (probe["grpc"] or {}).get("port")
    if "exec" in probe:
        return "exec", None, None
    return "", None, None


def check_workload_probes(doc: dict[str, Any]) -> tuple[bool, str]:
    """(ok, reason): every SERVING container in the workload declares BOTH a livenessProbe and a
    readinessProbe. A workload with no serving container is itself a failure — nothing to route to."""
    kind = doc.get("kind")
    name = (doc.get("metadata") or {}).get("name", "?")
    containers = serving_containers(doc)
    if not containers:
        return False, f"{kind}/{name}: no serving container (one declaring a port) to probe"
    for c in containers:
        cn = c.get("name", "?")
        if "livenessProbe" not in c:
            return False, (f"{kind}/{name} container {cn!r}: NO livenessProbe — a wedged process is never "
                           f"restarted (the exact gap on the single-writer sovereign StatefulSet)")
        if "readinessProbe" not in c:
            return False, (f"{kind}/{name} container {cn!r}: NO readinessProbe — traffic routes to a "
                           f"not-ready pod")
    return True, ""


def check_vigil_wiring(doc: dict[str, Any]) -> tuple[bool, str]:
    """For a VIGIL-owned workload: readinessProbe must be httpGet /readyz and livenessProbe httpGet /healthz
    (the W6-1 endpoints), each on one of the container's own serving ports. A readiness probe on '/' is the
    pre-fix defect (a dead backend stays Ready) and is rejected explicitly."""
    kind = doc.get("kind")
    name = (doc.get("metadata") or {}).get("name", "?")
    for c in serving_containers(doc):
        cn = c.get("name", "?")
        ports = _container_ports(c)
        rk, rp, rport = probe_target(c.get("readinessProbe"))
        lk, lp, lport = probe_target(c.get("livenessProbe"))
        if rp in SHALLOW_PATHS:
            return False, (f"{kind}/{name} container {cn!r}: readinessProbe is a SHALLOW GET {rp} on the "
                           f"static bundle — a proxy whose backend is dead stays Ready. It must probe "
                           f"{READYZ_PATH}.")
        if rk != "httpGet" or rp != READYZ_PATH:
            return False, (f"{kind}/{name} container {cn!r}: readinessProbe must be httpGet {READYZ_PATH} "
                           f"(got {rk or 'none'} path={rp!r})")
        if rport not in ports:
            return False, (f"{kind}/{name} container {cn!r}: readinessProbe port {rport!r} is not one of "
                           f"the container's ports {sorted(map(str, ports))}")
        if lk != "httpGet" or lp != HEALTHZ_PATH:
            return False, (f"{kind}/{name} container {cn!r}: livenessProbe must be httpGet {HEALTHZ_PATH} "
                           f"(got {lk or 'none'} path={lp!r})")
        if lport not in ports:
            return False, (f"{kind}/{name} container {cn!r}: livenessProbe port {lport!r} is not one of "
                           f"the container's ports {sorted(map(str, ports))}")
    return True, ""


_HEALTHCHECK_RE = re.compile(r"^\s*HEALTHCHECK\b", re.IGNORECASE)


def dockerfile_healthcheck(text: str) -> str | None:
    """The full HEALTHCHECK instruction (backslash-continued lines joined), or ``None`` if the Dockerfile
    declares none. ``HEALTHCHECK NONE`` (which DISABLES an inherited healthcheck) counts as none here."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if _HEALTHCHECK_RE.match(lines[i]):
            buf = [lines[i]]
            while buf[-1].rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                buf.append(lines[i])
            joined = " ".join(x.rstrip().rstrip("\\").strip() for x in buf)
            if re.search(r"\bHEALTHCHECK\s+NONE\b", joined, re.IGNORECASE):
                return None
            return joined
        i += 1
    return None


def check_dockerfile(text: str, expect: str) -> tuple[bool, str]:
    """(ok, reason): the Dockerfile declares a HEALTHCHECK that exercises the expected readiness surface —
    ``readyz`` => the instruction references /readyz; ``tcp`` => it is a real TCP connect to the bind (not a
    ``CMD true`` no-op)."""
    hc = dockerfile_healthcheck(text)
    if hc is None:
        return False, "no HEALTHCHECK instruction (an image with no healthcheck is never marked unhealthy)"
    if expect == "readyz":
        if READYZ_PATH not in hc:
            return False, f"HEALTHCHECK does not exercise {READYZ_PATH}: {hc}"
    elif expect == "tcp":
        if not any(tok in hc for tok in ("create_connection", "nc ", "/dev/tcp")):
            return False, f"HEALTHCHECK is not a TCP-connect readiness check: {hc}"
    else:  # pragma: no cover - guarded by the fixed SERVER_DOCKERFILES table
        return False, f"unknown expectation {expect!r}"
    return True, ""


def require(manifests_dir: Path, repo_root: Path) -> None:
    """REFUSE (raise :class:`ProbeRequirementError`) unless EVERY workload ships both probes, EVERY
    VIGIL-owned workload is wired to /readyz + /healthz, and EVERY shipped server Dockerfile declares a
    HEALTHCHECK. Returns ``None`` on success. Pure file/logic — no live cluster."""
    workloads = iter_workloads(manifests_dir)
    if not workloads:
        raise ProbeRequirementError(
            f"REFUSING TO DEPLOY: no Deployment/StatefulSet workloads found under {manifests_dir}")
    for path, doc, app in workloads:
        ok, why = check_workload_probes(doc)
        if not ok:
            raise ProbeRequirementError(f"REFUSING TO DEPLOY: {path.name}: {why}")
        if app in VIGIL_OWNED_APPS:
            ok, why = check_vigil_wiring(doc)
            if not ok:
                raise ProbeRequirementError(f"REFUSING TO DEPLOY: {path.name}: {why}")
    for rel, expect in SERVER_DOCKERFILES.items():
        p = Path(repo_root) / rel
        if not p.is_file():
            raise ProbeRequirementError(f"REFUSING TO DEPLOY: shipped server Dockerfile missing: {rel}")
        ok, why = check_dockerfile(p.read_text(encoding="utf-8"), expect)
        if not ok:
            raise ProbeRequirementError(f"REFUSING TO DEPLOY: {rel}: {why}")


def main(argv: list[str] | None = None) -> int:
    repo_default = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(
        description="Gate the HA deploy on REAL health probes + Dockerfile HEALTHCHECKs (W6-2).")
    ap.add_argument("--manifests", type=Path, default=repo_default / "infra" / "ha" / "k8s",
                    help="directory holding the HA k8s manifests")
    ap.add_argument("--repo-root", type=Path, default=repo_default,
                    help="repo root, for resolving shipped server Dockerfiles")
    args = ap.parse_args(argv)
    try:
        require(args.manifests, args.repo_root)
    except ProbeRequirementError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print("OK: every workload declares liveness+readiness probes; VIGIL-owned probes wired to /readyz + "
          "/healthz on their serving port; shipped server Dockerfiles declare a HEALTHCHECK. Proceeding.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
