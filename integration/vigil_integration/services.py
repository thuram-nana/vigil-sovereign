"""services — bring up the root docker-compose services (qdrant / neo4j / otel) create-if-absent.

`docker compose up -d <svc>` is idempotent — it creates ONLY the containers/networks that do not already
exist and starts stopped ones — so `vigil services up` is safe to re-run. Mirrors the gateway's
`SandboxNetworking` lifecycle. EXEC-ONLY / pure-stdlib (subprocess/shutil/json) — imports no
framework/strix/sigil, so it stays on the same boundary-safe path `vigil up` uses.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Optional

# The root-compose services the running system uses. `profile` is the compose profile that gates the
# service (None = always available); `port` is the loopback port it serves on (for the doctor health note).
ROOT_SERVICES = {
    "qdrant":         {"profile": None,            "port": 6333, "purpose": "vector memory (SIGIL)"},
    "neo4j":          {"profile": "graph",         "port": 7687, "purpose": "knowledge graph"},
    "otel-collector": {"profile": "observability", "port": 4318, "purpose": "telemetry / OTLP export"},
}
# Default set brought up by `vigil services up` (qdrant only; the graph/observability services are opt-in via
# their flags — they are heavier and off by default, matching bootstrap.sh).
DEFAULT_SERVICES = ("qdrant",)

# Every docker call is timeout-bounded so a wedged daemon / a synchronous image pull can never pin the
# caller (esp. the console request thread on `vigil services up` from the UI). Reads are quick; a `compose
# up` may pull an image, so it gets a generous bound.
READ_TIMEOUT = 30.0
UP_TIMEOUT = 600.0
BUILD_TIMEOUT = 1800.0   # a from-scratch Kali/AEGIS image build is minutes; bounded so it can't hang forever

# The BUILD-ONLY engine images (offence + defence sandboxes). Nothing PULLS them — each is built via its
# compose profile (the root docker-compose.yml `strix-sandbox` / `aegis-gateway` build services, whose build
# contexts are non-obvious). `image` is the tag the engine resolves at run time; absence degrades a later
# engagement with a clear error (it is NOT a security gate, unlike the egress gateway), so building them is
# best-effort — a build failure is recorded, never raised.
ENGINE_IMAGES = {
    "strix-sandbox": {"image": "vigil/strix-sandbox:local", "profile": "strix", "service": "strix-sandbox",
                      "purpose": "Strix offence sandbox"},
    "aegis-gateway": {"image": "vigil/aegis-gateway:local", "profile": "aegis", "service": "aegis-gateway",
                      "purpose": "AEGIS defensive gateway"},
}


class RootServices:
    def __init__(self, repo_root, compose: Optional[Path] = None):
        self.repo_root = Path(repo_root)
        self.compose = Path(compose) if compose else self.repo_root / "docker-compose.yml"
        self.env_file = self.repo_root / ".env"

    @staticmethod
    def _docker() -> str:
        d = shutil.which("docker")
        if not d:
            raise RuntimeError("docker binary not found — install Docker to bring up the services")
        return d

    def _compose(self, *args, profiles=()) -> list[str]:
        cmd = [self._docker(), "compose", "-f", str(self.compose)]
        if self.env_file.exists():
            cmd += ["--env-file", str(self.env_file)]
        for p in profiles:
            cmd += ["--profile", p]
        return cmd + list(args)

    def _run(self, cmd, timeout: float = READ_TIMEOUT) -> subprocess.CompletedProcess:
        # Every docker call is TIMEOUT-BOUNDED: a wedged daemon / a synchronous image pull must never pin
        # the caller (e.g. the console request thread) indefinitely. On timeout, subprocess kills the client
        # and raises TimeoutExpired, which the caller/`_safe` layer turns into a fail-soft error.
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    @staticmethod
    def _profiles_for(services) -> list[str]:
        return sorted({ROOT_SERVICES[s]["profile"] for s in services
                       if s in ROOT_SERVICES and ROOT_SERVICES[s]["profile"]})

    @staticmethod
    def _port_open(port: Optional[int], host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
        """True iff SOMETHING is already serving on host:port. This is what makes detection
        ENDPOINT-aware rather than compose-project-scoped: the sovereign app ships qdrant as a
        differently-named container (`sigil-qdrant`) in a different compose project, so `ps()` reports
        the root-compose `qdrant` service as absent even while 6333 is served. Probing the port tells
        the operator the truth ("something is already answering here") without a false "absent". Never
        raises; a closed port refuses fast, so the bound only bites a silently-dropping port."""
        if not port:
            return False
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except OSError:
            return False

    def ps(self) -> dict:
        """{service: docker-state} for every service that has a container. Robust to both compose-v2 output
        shapes (a JSON array, or newline-delimited JSON objects)."""
        proc = self._run(self._compose("ps", "--all", "--format", "json",
                                       profiles=self._profiles_for(ROOT_SERVICES)))
        states: dict = {}
        if proc.returncode != 0:
            return states
        out = proc.stdout.strip()
        rows: list = []
        if out.startswith("["):
            try:
                rows = json.loads(out)
            except ValueError:
                rows = []
        else:
            for line in out.splitlines():
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
        for row in rows:
            if isinstance(row, dict):
                svc = row.get("Service") or row.get("Name")
                st = row.get("State") or row.get("Status")
                if svc:
                    states[svc] = st or "unknown"
        return states

    def status(self) -> dict:
        """A create-if-absent readiness snapshot for every known root service.

        `reachable` (endpoint-aware) is True when SOMETHING already answers on the service's loopback
        port even if THIS compose project has no such container — so a differently-named external
        container (e.g. `sigil-qdrant` on 6333) reads as reachable instead of a misleading "absent"."""
        live = self.ps()
        return {name: {"state": live.get(name, "absent"), "profile": meta["profile"],
                       "port": meta["port"], "purpose": meta["purpose"],
                       "reachable": self._port_open(meta["port"])}
                for name, meta in ROOT_SERVICES.items()}

    def up(self, services) -> dict:
        """Create/start the given services if absent (idempotent). Returns {service: state} after."""
        services = [s for s in services if s in ROOT_SERVICES]
        if not services:
            return {}
        proc = self._run(self._compose("up", "-d", *services, profiles=self._profiles_for(services)),
                         timeout=UP_TIMEOUT)   # may pull an image → generous, but bounded
        if proc.returncode != 0:
            raise RuntimeError(f"docker compose up failed: {proc.stderr.strip()[-800:]}")
        snap = self.status()
        return {s: snap[s]["state"] for s in services}

    def down(self, services) -> None:
        """Stop + remove the given services (idempotent)."""
        services = [s for s in services if s in ROOT_SERVICES]
        if services:
            self._run(self._compose("stop", *services, profiles=self._profiles_for(services)), timeout=UP_TIMEOUT)
            self._run(self._compose("rm", "-f", *services, profiles=self._profiles_for(services)), timeout=UP_TIMEOUT)

    def _image_present(self, image: str) -> bool:
        """True iff the docker image TAG already exists locally. Never raises (no docker / a probe error → False)."""
        try:
            return self._run([self._docker(), "image", "inspect", image]).returncode == 0
        except (RuntimeError, OSError, subprocess.SubprocessError):
            return False

    def build_images_if_absent(self, images=None, progress=None) -> dict:
        """Build each ENGINE_IMAGES entry whose tag is ABSENT (idempotent), via its compose profile —
        so `vigil up`/`vigil services up` can make the offence/defence sandboxes ready without the operator
        remembering a separate `make strix` / `make aegis-image`. Returns {name: 'present'|'built'|
        'failed: <err>'|'unknown'}. BEST-EFFORT per image: a build failure is RECORDED, never raised — a
        missing engine image degrades a later engagement with a clear error, it is not a security gate (the
        egress gateway is the one that fails closed). `progress(name, phase)` is called if given."""
        names = list(images) if images is not None else list(ENGINE_IMAGES)
        out: dict = {}
        for name in names:
            meta = ENGINE_IMAGES.get(name)
            if not meta:
                out[name] = "unknown"
                continue
            try:
                if self._image_present(meta["image"]):
                    out[name] = "present"
                    continue
                if progress:
                    progress(name, "building")
                proc = self._run(self._compose("build", meta["service"], profiles=[meta["profile"]]),
                                 timeout=BUILD_TIMEOUT)
                if proc.returncode == 0:
                    out[name] = "built"
                else:
                    tail = ((proc.stderr or "") or (proc.stdout or "")).strip()[-400:]
                    out[name] = f"failed (rc={proc.returncode}): {tail or '(no output)'}"
            except Exception as e:  # noqa: BLE001 — best-effort: a missing image is not a gate (unlike the
                out[name] = f"failed: {e}"   # egress gateway); RECORD every failure, incl. a raised progress cb, never raise
        return out
