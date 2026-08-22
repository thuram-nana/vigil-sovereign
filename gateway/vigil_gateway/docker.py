"""
docker — pin the offense sandbox onto a locked-down network with the gateway as its only exit.

Recommended topology (Docker enforces the deny-default; the proxy enforces scope):

    ┌─ vigil_sandbox (internal: true) ─┐        ┌─ vigil_egress ─┐
    │  Strix Kali sandbox              │        │                │
    │   (STRIX_DOCKER_SANDBOX_NETWORK) │        │                │
    │            │ only reachable peer │        │                │
    │            ▼                     │        │                │
    │        vigil-gateway ────────────┼────────┼──► internet    │
    └──────────────────────────────────┘        └────────────────┘

``internal: true`` means Docker installs NO default route out of ``vigil_sandbox`` — the
sandbox physically cannot reach the internet, the operator LAN, or 169.254.169.254 except
by going through the gateway container, which runs the filtering proxy (proxy.py). Because
the sandbox reaches the world only via an HTTP proxy, it never needs external DNS itself
(the proxy resolves the CONNECT/absolute-form hostname), so name resolution is not an
escape hatch either.

The sandbox is pinned to this network by Strix's existing ``STRIX_DOCKER_SANDBOX_NETWORK``
env var — no Strix change is needed for pinning. Separately, docker_client.py is patched so
the sandbox no longer receives ``NET_ADMIN`` by default (it cannot rewrite its own
netfilter/routing), keeping only ``NET_RAW`` for SYN scanning, and only when opted in.

The nftables layer (nftables.py) is the host-side backstop for this topology and the
primary control for the alternative topology where the proxy runs on the host bridge.
"""

from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

SANDBOX_NETWORK = "vigil_sandbox"
EGRESS_NETWORK = "vigil_egress"
STRIX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"
IMAGE_REPO = "vigil-gateway"
DEFAULT_IMAGE = f"{IMAGE_REPO}:latest"
# The compose file interpolates this env var into the gateway `image:` reference (see render_compose).
# `vigil services up` sets it to the CONTENT-ADDRESSED tag the build just produced, so the running gateway
# is provably the image built from the current tree; a bare `docker compose up` by hand falls back to the
# `:latest` alias the same build also writes.
IMAGE_TAG_ENV = "VIGIL_GATEWAY_IMAGE_TAG"
# Where `vigil services up` records the runtime image pin (context digest + built image id). The A14
# pin checker (infra/supply-chain/image_pins.py --runtime-check) reads it to prove the RUNNING gateway
# still matches the current source — a check the Dockerfile/compose scanner cannot make on its own.
PIN_RELPATH = os.path.join(".vigil-live", "gateway-image-pin.json")
PIN_SCHEMA = "vigil-gateway-image-pin/1"

# sx-s2 short-lived gateway credential. The proxy's A7 client-auth secret is MINTED fresh at each bring-up
# and persisted here (0600) so the two ends can never drift: the gateway container is started with this exact
# token (VIGIL_GATEWAY_PROXY_TOKEN in the compose env) and the Strix launch pre-flight reads the SAME file to
# tell the in-sandbox Caido what Basic credential to present upstream. A per-bring-up random token is
# "short-lived" in the sense the plan means (rotated every time the gate is stood up), never a committed
# constant. Fail-SAFE: if minting/persisting fails, no token is set on either end and the proxy degrades to
# its prior no-client-auth posture (bind address + internal network + nftables backstop) — never a state
# where the gateway demands a credential the sandbox cannot present.
PROXY_TOKEN_RELPATH = os.path.join(".vigil-live", "gateway-proxy-token")

# A DETERMINISTIC bridge interface name for the sandbox network (pinned via the docker driver-opt
# `com.docker.network.bridge.name`, and passed to the firewall sidecar as VIGIL_GATEWAY_SANDBOX_IFACE).
# Without it the bridge is `br-<random>`, unknowable ahead of time, so the auto-applied backstop could
# only match by source-SUBNET — which is v4-only here and left IPv6 sandbox egress POLICY-ACCEPTED (it
# bypassed the proxy). Matching by INTERFACE is family-agnostic (governs v4 AND v6) and spoof-proof
# (NET_RAW can forge a source IP but not the arrival interface). Must be a valid iface name (<=15 chars).
SANDBOX_BRIDGE = "vigil-sbx0"
# Every docker call is timeout-bounded so a wedged daemon / pull / build can't pin the caller forever
# (esp. the console request thread on `vigil services up` from the UI). Reads are quick; build/compose-up
# may pull, so they get a generous bound.
READ_TIMEOUT = 30.0
BUILD_TIMEOUT = 600.0

# Content-address the gateway image by the build context. A container tag is a MUTABLE POINTER: after a
# `git pull` the `vigil-gateway:latest` tag still exists, so `ensure_image` returned early and
# `docker compose up -d` (which will not recreate an unchanged tag) silently kept running the OLD egress
# gate (issue #511 / W5-6). The fix: the image the gateway actually runs is tagged by a digest of its
# build context, so a source change changes the tag, forces a rebuild, and forces a recreate; an UNCHANGED
# context yields the SAME tag and does NOT rebuild (the negative control). This mirrors, for a first-party
# image, the A14 rule that upstream images are digest-pinned (infra/supply-chain/image_pins.py).

# Never let VCS / cache / venv churn perturb the context digest — none of it enters the built image, and
# including it would make the digest differ between two checkouts of the same commit. Keep this set BYTE
# IDENTICAL to infra/supply-chain/image_pins.py::_CONTEXT_IGNORE (a consistency test asserts both
# implementations agree on the real gateway context).
_CONTEXT_IGNORE = frozenset(
    {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "node_modules", ".ruff_cache"}
)


def _context_ignored(rel_parts: tuple) -> bool:
    return any(part in _CONTEXT_IGNORE for part in rel_parts)


def context_digest(context_dir) -> str:
    """A deterministic sha256 over a docker build context — the image's CONTENT ADDRESS.

    Hashes a manifest of ``(posix-relative-path, sha256(bytes))`` for every file in ``context_dir``, sorted
    by path, skipping VCS/cache/venv junk (``_CONTEXT_IGNORE``). Deterministic across checkouts of the same
    commit and across machines: it depends only on file paths + contents, never on mtime or walk order.

    This is duplicated (identically) in infra/supply-chain/image_pins.py, which is stdlib-only by design and
    must not import this package; a consistency test pins the two together.
    """
    root = Path(context_dir)
    entries: list[tuple[str, str]] = []
    for p in sorted(root.rglob("*")):
        rel_parts = p.relative_to(root).parts
        if _context_ignored(rel_parts):
            continue
        if p.is_symlink() or not p.is_file():
            continue
        rel = "/".join(rel_parts)
        entries.append((rel, hashlib.sha256(p.read_bytes()).hexdigest()))
    manifest = hashlib.sha256()
    for rel, digest in sorted(entries):
        manifest.update(rel.encode("utf-8"))
        manifest.update(b"\0")
        manifest.update(digest.encode("ascii"))
        manifest.update(b"\n")
    return manifest.hexdigest()


def content_addressed_tag(context_dir, repo: str = IMAGE_REPO) -> str:
    """The content-addressed image reference for a build context: ``vigil-gateway:ctx-<digest[:16]>``.

    Changing the build context changes this tag (so an upgrade rebuilds + recreates); an unchanged context
    yields the same tag (so nothing rebuilds). A stale running image is therefore detectable BY TAG ALONE.
    """
    return f"{repo}:ctx-{context_digest(context_dir)[:16]}"


def write_pin(pin_path, *, context_digest_hex: str, image_tag: str, image_id: str) -> dict:
    """Atomically record the runtime image pin the A14 check reads (see infra/supply-chain/image_pins.py).

    The record binds the build-context digest to the built image's content id. Written atomically (temp +
    replace) so a torn read can never present a half-written, relaxed pin.
    """
    record = {
        "schema": PIN_SCHEMA,
        "context_digest": context_digest_hex,
        "image_tag": image_tag,
        "image_id": image_id,
        "built_at": int(time.time()),
    }
    path = Path(pin_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return dict(record)


def mint_proxy_token(token_path) -> "str | None":
    """Mint a fresh short-lived gateway proxy-auth token, persist it atomically (0600), return it.

    Called by the launch path at each gateway bring-up. Returns the token on success, or ``None`` if it
    could not be written — in which case the caller sets NO token on the gateway and the proxy keeps its
    prior no-client-auth posture (never a gateway that demands a credential the sandbox cannot read back)."""
    import secrets
    token = secrets.token_urlsafe(32)
    try:
        path = Path(token_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        # Create the temp file 0600 BEFORE writing the secret (no world-readable window), then atomically
        # replace. os.open with 0o600 + O_CREAT|O_TRUNC is the portable way to fix the mode at creation.
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, (token + "\n").encode("ascii"))
        finally:
            os.close(fd)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)   # belt-and-suspenders: ensure the final file is owner-only
        except OSError:
            pass
        return token
    except OSError:
        return None


def load_proxy_token(token_path) -> "str | None":
    """Read the persisted gateway proxy-auth token, or ``None`` if absent/unreadable/empty. Fail-safe: a
    missing token means 'no client auth configured', never an error — the caller then presents none."""
    try:
        raw = Path(token_path).read_text(encoding="ascii")
    except (OSError, ValueError):
        return None
    return raw.strip() or None


def load_pin(pin_path) -> "dict | None":
    """Read the runtime image pin, or None if it is absent/unreadable/not our schema (fail-closed: the
    caller treats None as 'the runtime is invisible', never as 'verified')."""
    try:
        data = json.loads(Path(pin_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != PIN_SCHEMA:
        return None
    return data


@dataclass(frozen=True)
class SandboxNetworking:
    sandbox_network: str = SANDBOX_NETWORK
    egress_network: str = EGRESS_NETWORK
    sandbox_subnet: str = "172.31.240.0/24"
    proxy_port: int = 48081
    sandbox_bridge: str = SANDBOX_BRIDGE   # deterministic bridge iface — governs v4+v6, spoof-proof

    def strix_env(self) -> dict[str, str]:
        """The env a caller must set so Strix pins the sandbox onto the locked-down net."""
        return {STRIX_NETWORK_ENV: self.sandbox_network}

    def sandbox_gateway_ip(self) -> str:
        """The static sandbox-net address the gateway binds to (A7). The proxy binds ONLY this
        interface, not 0.0.0.0, so it is reachable from the sandbox but never from the
        world-facing egress network. Docker's bridge takes the first host address (.1); the
        gateway container takes the second (.2)."""
        hosts = ipaddress.ip_network(self.sandbox_subnet, strict=False).hosts()
        next(hosts)             # .1 — Docker's own bridge gateway
        return str(next(hosts)) # .2 — the vigil-gateway container

    def render_compose(self, *, gateway_image: str = "", charter_slug: str = "") -> str:
        """A docker-compose fragment for the gateway + the two networks.

        The Strix sandbox is NOT declared here — Strix launches it itself; it only needs
        STRIX_DOCKER_SANDBOX_NETWORK set to ``sandbox_network``.

        ``gateway_image`` (default: the content-addressed interpolation form) controls the `image:` line:
          * "" — emit ``vigil-gateway:${VIGIL_GATEWAY_IMAGE_TAG:-latest}``. `vigil services up` sets
            VIGIL_GATEWAY_IMAGE_TAG to the CONTENT-ADDRESSED tag it just built, so a source change flips the
            tag and forces `docker compose up -d` to recreate; a bare hand-run falls back to the `:latest`
            alias the build also writes. This is NOT the `${VERSION:-latest}` upstream anti-pattern the
            supply-chain doc removed: this is a FIRST-PARTY image and the var carries a content address, so
            it forces recreate-on-change rather than masking upstream drift.
          * an explicit reference — templated literally (used when printing a compose for a specific tag).

        ``charter_slug`` (default: "") controls the gateway's L7 scope source:
          * "" — emit the ENV-INTERPOLATION form ``${VIGIL_GATEWAY_CHARTER_SLUG:-}``, exactly like the proxy
            token below. This is the sx-s2 fix: the committed artifact used to ship a hardcoded empty LITERAL
            (``VIGIL_GATEWAY_CHARTER_SLUG: ""``), on which ``config.from_env`` fail-closes, so the committed
            compose brought up a gateway that exited immediately AND could never be fixed without editing the
            file. As an interpolation the launch path (``vigil services up --charter-slug`` / ``vigil up
            --services --charter-slug``, which set the var in the compose-up environment) supplies the active
            engagement's signed-charter slug, and an unset var still fail-closes (no scope ⇒ no gateway) — the
            same safe default, now with an actionable path instead of an unfixable literal.
          * an explicit slug — templated LITERALLY (used when rendering a compose pinned to one engagement).
        """
        # BOTH templated values are guarded — a quote / newline in either would let it break out of its
        # YAML scalar and inject compose directives (e.g. privileged: true). charter_slug: a simple slug;
        # gateway_image: a valid docker image reference. (Red-pen: guard the sibling too, not just one.)
        if charter_slug and not re.fullmatch(r"[A-Za-z0-9._-]+", charter_slug):
            raise ValueError("charter_slug must be a simple slug ([A-Za-z0-9._-]); refusing to template "
                             "an unsafe value into the compose file")
        # Empty ⇒ the env-interpolation form (authored here, never caller-supplied, so injection-safe and not
        # run through the slug guard above); non-empty ⇒ the validated literal slug baked in.
        charter_slug_value = charter_slug or "${VIGIL_GATEWAY_CHARTER_SLUG:-}"
        if gateway_image:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*", gateway_image):
                raise ValueError("gateway_image must be a valid docker image reference; refusing to template "
                                 "an unsafe value into the compose file")
            image_ref = gateway_image
        else:
            # The content-addressed interpolation form. `${...}` is authored HERE (never taken from a
            # caller), so it is safe to emit verbatim and is deliberately not run through the guard above.
            image_ref = f"{IMAGE_REPO}:${{{IMAGE_TAG_ENV}:-latest}}"
        bind_ip = self.sandbox_gateway_ip()
        return f"""\
# vigil-gateway egress topology. The Strix sandbox is launched by Strix with
# {STRIX_NETWORK_ENV}={self.sandbox_network}; it is not defined here.
#
# The gateway image is CONTENT-ADDRESSED (issue #511): `vigil services up` rebuilds it when the build
# context changes and sets {IMAGE_TAG_ENV} to the resulting `ctx-<digest>` tag, which compose interpolates
# below — so a source change forces a recreate and the running gateway is provably the built image. A bare
# `docker compose up` falls back to the `:latest` alias the same build writes.
#
# A7 client authentication: set VIGIL_GATEWAY_PROXY_TOKEN in your shell before `docker compose
# up` (compose interpolates ${{VIGIL_GATEWAY_PROXY_TOKEN}} below), and point the sandbox's
# proxy at http://vigil:$VIGIL_GATEWAY_PROXY_TOKEN@{bind_ip}:{self.proxy_port} so it presents
# the Basic credential. Unset = no client auth (the bind address + internal:true network are
# then the only thing keeping the proxy sandbox-only).
networks:
  {self.sandbox_network}:
    name: {self.sandbox_network}
    internal: true              # Docker installs no route out — the deny-default boundary
    driver_opts:
      # Pin the bridge iface name so the firewall sidecar can govern by INTERFACE (family-agnostic:
      # v4 AND v6) instead of a v4-only source-subnet match that leaves IPv6 egress policy-accepted.
      com.docker.network.bridge.name: {self.sandbox_bridge}
    ipam:
      config:
        - subnet: {self.sandbox_subnet}
  {self.egress_network}:
    name: {self.egress_network}

services:
  # The nftables L3/L4 BACKSTOP (S3) — a one-shot, PRIVILEGED sidecar that LOADS the host-side
  # deny-default ruleset BEFORE the proxy (hence before Strix) comes up. It runs in the HOST network
  # namespace with ONLY CAP_NET_ADMIN so `nft -f` lands in the authoritative netns, applies the ruleset,
  # and EXITS. The proxy `depends_on` its CLEAN exit (below), so a backstop that cannot load FAILS the
  # whole bring-up (`compose up --wait` returns non-zero) — the same fail-closed leg as W0-6, never a
  # silent downgrade to the sandbox running without the backstop. `apply-firewall` needs no charter scope
  # (the firewall is pure packet policy), so it runs from just these network coordinates. Rebuild the
  # image (`docker build -t {gateway_image} gateway`) so it carries `nft`; `vigil services up` does this
  # automatically only when the image is ABSENT.
  #
  # WHY user: "0" (root). The image's default user is the unprivileged `vigil` (uid 10001). For a NON-root
  # process a capability added with `cap_add` sits only in the container's permitted/bounding set — it is
  # NOT in the process's EFFECTIVE set (there are no file-capabilities on `nft`), so `nft -f` fails EPERM
  # and the backstop CAN NEVER LOAD: a FAIL-OPEN (the sandbox could come up with egress ungoverned).
  # Running the ONE-SHOT sidecar as root makes CapEff equal the container's cap set; with cap_drop [ALL] +
  # cap_add [NET_ADMIN] that CapEff is exactly {{NET_ADMIN}} — every other capability is still dropped,
  # no-new-privileges is set, and it applies the ruleset and exits. (The world-facing `vigil-gateway`
  # proxy below keeps running as the unprivileged image default with cap_drop ALL.)
  vigil-gateway-firewall:
    image: {image_ref}
    container_name: vigil-gateway-firewall
    user: "0"                   # root so cap_add NET_ADMIN is EFFECTIVE (non-root => EPERM => fail-OPEN)
    network_mode: host
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN               # the ONLY capability nft -f needs; nothing more (CapEff={{NET_ADMIN}})
    security_opt:
      - no-new-privileges:true
    read_only: true             # rootfs immutable (parity with the proxy); nft -f - reads stdin, no scratch
    restart: "no"               # one-shot: load the backstop, then exit 0
    environment:
      VIGIL_GATEWAY_GATEWAY_IP: "{bind_ip}"
      VIGIL_GATEWAY_SANDBOX_SUBNET: "{self.sandbox_subnet}"
      VIGIL_GATEWAY_PROXY_PORT: "{self.proxy_port}"
      # Govern by INTERFACE, not source-subnet: family-agnostic (drops v4 AND v6 sandbox egress to the
      # deny-default chain) and spoof-proof. A v4-only saddr match would leave IPv6 egress policy-accepted.
      VIGIL_GATEWAY_SANDBOX_IFACE: "{self.sandbox_bridge}"
    command: ["vigil-gateway", "apply-firewall"]

  vigil-gateway:
    image: {image_ref}
    container_name: vigil-gateway   # a deterministic name so `vigil services status/down` can find it
    depends_on:
      vigil-gateway-firewall:
        condition: service_completed_successfully   # fail-closed: no proxy unless the backstop loaded
    networks:
      {self.sandbox_network}:
        ipv4_address: {bind_ip}   # pinned so the proxy can bind ONLY the sandbox interface
      {self.egress_network}: {{}}   # world-facing: the only interface with a default route
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    environment:
      VIGIL_GATEWAY_PROXY_PORT: "{self.proxy_port}"
      VIGIL_GATEWAY_PROXY_HOST: "{bind_ip}"
      VIGIL_GATEWAY_PROXY_TOKEN: "${{VIGIL_GATEWAY_PROXY_TOKEN:-}}"
      VIGIL_GATEWAY_CHARTER_SLUG: "{charter_slug_value}"
    command: ["vigil-gateway", "serve-proxy", "--host", "{bind_ip}", "--port", "{self.proxy_port}"]
    healthcheck:
      # The gate is only "up" when the proxy is actually LISTENING on its pinned sandbox bind. A bad or
      # missing charter scope makes serve-proxy fail closed and exit, which this probe (and `up --wait`)
      # surface as UNHEALTHY instead of a silent exit-0-but-dead container. Read-only-safe: a bare TCP
      # connect, no writes, no third-party deps (the runtime image is stdlib-only python).
      test: ["CMD", "python", "-c", "import socket; socket.create_connection(('{bind_ip}', {self.proxy_port}), 2).close()"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s
"""

    # -- imperative network creation (alternative to compose) --------------------------

    @staticmethod
    def _docker_bin() -> str:
        d = shutil.which("docker")
        if not d:
            raise RuntimeError("docker binary not found")
        return d

    def network_exists(self, name: "str | None" = None) -> bool:
        """Public: does the given (default: the sandbox) network exist? Used by the Strix launch pre-flight,
        which must not reach into a private helper across package boundaries."""
        return self._network_exists(name or self.sandbox_network)

    def _network_exists(self, name: str) -> bool:
        proc = subprocess.run(
            [self._docker_bin(), "network", "inspect", name],
            capture_output=True, text=True, timeout=READ_TIMEOUT,
        )
        return proc.returncode == 0

    def _network_bridge_name(self, name: str) -> "str | None":
        """The pinned bridge interface name of an existing docker network (its
        ``com.docker.network.bridge.name`` driver-opt), or None if unset/uninspectable."""
        proc = subprocess.run(
            [self._docker_bin(), "network", "inspect", name,
             "-f", '{{ index .Options "com.docker.network.bridge.name" }}'],
            capture_output=True, text=True, timeout=READ_TIMEOUT,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout.strip() or None

    def ensure_networks(self) -> None:
        """Create the sandbox (internal) and egress networks if absent (idempotent).

        FAIL-CLOSED (sx-s3 MEDIUM): if the sandbox network already exists but was created WITHOUT the
        pinned bridge name (e.g. by an older VIGIL, or by hand), silently reusing it would leave the
        interface-governed backstop pointing at a bridge that does not exist — the deny-default jump then
        matches nothing and the sandbox egress rides `policy accept` ungoverned. Rather than reuse such a
        network, REFUSE with an actionable error (remove it so it can be recreated pinned)."""
        d = self._docker_bin()
        if not self._network_exists(self.sandbox_network):
            subprocess.run(
                [d, "network", "create", "--internal",
                 # pin the bridge iface name so the firewall backstop can govern by interface (v4+v6)
                 "--opt", f"com.docker.network.bridge.name={self.sandbox_bridge}",
                 "--subnet", self.sandbox_subnet, self.sandbox_network],
                check=True, capture_output=True, text=True, timeout=READ_TIMEOUT,
            )
        else:
            existing = self._network_bridge_name(self.sandbox_network)
            if existing != self.sandbox_bridge:
                raise RuntimeError(
                    f"the existing docker network {self.sandbox_network!r} pins bridge "
                    f"{existing!r}, not the required {self.sandbox_bridge!r}; the interface-governed "
                    f"nftables backstop would match no traffic against a stale bridge name. Remove it "
                    f"(`docker network rm {self.sandbox_network}`) so it is recreated with the pinned "
                    f"bridge — refusing to reuse a mis-pinned sandbox network (fail closed)."
                )
        if not self._network_exists(self.egress_network):
            subprocess.run(
                [d, "network", "create", self.egress_network],
                check=True, capture_output=True, text=True, timeout=READ_TIMEOUT,
            )

    # -- image + container lifecycle (create-if-absent bring-up) ------------------------
    # These make `vigil services up` bring the gateway topology up from nothing: build the image if it
    # is missing, then `docker compose up -d` — which itself creates ONLY what is absent (the two
    # networks + the gateway container), so the whole thing is idempotent and re-runnable.

    def _run(self, args: list[str], timeout: float = READ_TIMEOUT, env: "dict | None" = None) -> subprocess.CompletedProcess:
        # Timeout-bounded (see services.py): a wedged daemon / synchronous pull / long build must never pin
        # the caller (e.g. the console request thread) forever. subprocess kills the client + raises
        # TimeoutExpired on overrun, which the caller / `_safe` layer turns into a fail-soft error.
        # `env` (when given) MUST be a full environment (compose still needs PATH/HOME/DOCKER_HOST/…), not a
        # sparse override — the caller merges it onto os.environ.
        return subprocess.run([self._docker_bin(), *args], capture_output=True, text=True, timeout=timeout, env=env)

    def image_exists(self, image: str = DEFAULT_IMAGE) -> bool:
        return self._run(["image", "inspect", image]).returncode == 0

    def image_id(self, image: str = DEFAULT_IMAGE) -> "str | None":
        """The image's content id (`sha256:...`), or None if it cannot be resolved. This is the local
        content digest of the image config — it changes iff the built content changes, so it is what the
        runtime pin binds to and what the A14 pin-check compares the RUNNING container against."""
        proc = self._run(["image", "inspect", "-f", "{{.Id}}", image])
        if proc.returncode != 0:
            return None
        return proc.stdout.strip() or None

    def running_image_id(self, name: str = "vigil-gateway") -> "str | None":
        """The content id of the image the named container is ACTUALLY running (`sha256:...`), or None if
        there is no such container / it cannot be read. Live-only; the pure verify logic takes it as input."""
        proc = self._run(["inspect", "-f", "{{.Image}}", name])
        if proc.returncode != 0:
            return None
        return proc.stdout.strip() or None

    def ensure_image(self, context_dir, image: str = DEFAULT_IMAGE) -> bool:
        """Build the gateway image if the given tag is absent (idempotent). Returns True iff a build ran.

        Low-level helper (tag-in, build-if-absent). The bring-up path uses ``ensure_content_addressed_image``
        instead, whose tag encodes the build context so an UPGRADE forces a rebuild (issue #511)."""
        if self.image_exists(image):
            return False
        proc = self._run(["build", "-t", image, str(context_dir)], timeout=BUILD_TIMEOUT)   # long, but bounded
        if proc.returncode != 0:
            raise RuntimeError(f"docker build of {image} failed: {proc.stderr.strip()[-800:]}")
        return True

    def ensure_content_addressed_image(self, context_dir) -> "tuple[bool, str]":
        """Build the gateway image tagged by its CONTENT ADDRESS if that exact tag is absent.

        Returns ``(built, tag)`` where ``tag`` is ``vigil-gateway:ctx-<digest16>``. Rebuilds iff the build
        context changed — the tag encodes the context digest, so an UPGRADE (source change) yields a new,
        absent tag and forces a rebuild, while an UNCHANGED context yields the same, present tag and does
        NOT rebuild (the negative control that proves this is not "always rebuild"). The build also writes
        the moving ``:latest`` alias so a hand-run `docker compose up` still finds an image.
        """
        tag = content_addressed_tag(context_dir)
        if self.image_exists(tag):
            return (False, tag)
        proc = self._run(["build", "-t", tag, "-t", DEFAULT_IMAGE, str(context_dir)], timeout=BUILD_TIMEOUT)
        if proc.returncode != 0:
            raise RuntimeError(f"docker build of {tag} failed: {proc.stderr.strip()[-800:]}")
        return (True, tag)

    def container_state(self, name: str = "vigil-gateway") -> str:
        """"running" | "exited" | … (docker's own state string) | "absent" if there is no such container."""
        proc = self._run(["inspect", "-f", "{{.State.Status}}", name])
        if proc.returncode != 0:
            return "absent"
        return proc.stdout.strip() or "unknown"

    def gateway_attached(self, container: str = "vigil-gateway", network: "str | None" = None) -> bool:
        """Is the gateway container actually CONNECTED to the (default: sandbox) network?

        ``container_state == running`` + ``network_exists`` is not enough for the sandbox to reach the
        gateway: a gateway attached only to the egress network, or a sandbox network recreated after the
        gateway started, both pass those two checks yet leave the ``--internal`` sandbox with NO reachable
        peer. This inspects the container's own network membership (``NetworkSettings.Networks``) — spoof-free
        and cheap — so the Strix launch pre-flight can refuse a gateway that cannot receive the sandbox's
        forwarded traffic, instead of pinning the sandbox onto an isolated island. Fail-closed: any read
        failure returns False (unreachable-until-proven-reachable)."""
        net = network or self.sandbox_network
        proc = self._run(["inspect", "-f",
                          "{{range $k, $_ := .NetworkSettings.Networks}}{{$k}}\n{{end}}", container])
        if proc.returncode != 0:
            return False
        return net in {line.strip() for line in proc.stdout.splitlines() if line.strip()}

    def _default_pin_path(self, context_dir) -> Path:
        # The gateway build context is <repo>/gateway, so the repo root is its parent; the pin lives under
        # the same .vigil-live runtime dir the offense plane already uses.
        return Path(context_dir).resolve().parent / PIN_RELPATH

    def compose_up(self, compose_file, *, build: bool = True, context_dir=None,
                   image: str = DEFAULT_IMAGE, pin_path=None, extra_env: "dict | None" = None) -> dict:
        """Bring the gateway topology up via `docker compose up -d`, content-addressing the image so an
        UPGRADE actually takes effect (issue #511).

        With a ``context_dir``: rebuild the image iff the build context changed (``ensure_content_addressed_
        image``), run compose with ``VIGIL_GATEWAY_IMAGE_TAG`` set to that content-addressed tag (so compose
        recreates the container when the tag flips), then FAIL CLOSED if the running container's image does
        not match the image we just built, and record the runtime pin the A14 check reads. Idempotent: an
        unchanged context rebuilds nothing and recreates nothing.
        """
        built = False
        tag = image
        if build and context_dir is not None:
            built, tag = self.ensure_content_addressed_image(context_dir)
        # Point compose at the content-addressed tag. A FULL env (not a sparse override) so compose keeps
        # PATH / DOCKER_HOST / HOME etc.; the tag is the part after the repo (`ctx-<digest>` or `latest`).
        tag_only = tag.split(":", 1)[1] if ":" in tag else tag
        # ``extra_env`` (sx-s2) carries the launch-path-supplied compose interpolation values — the active
        # engagement's VIGIL_GATEWAY_CHARTER_SLUG (signed scope) and the minted VIGIL_GATEWAY_PROXY_TOKEN
        # (short-lived client credential). Merged LAST so it wins over any stale ambient value. Empty/None
        # keeps the prior behaviour byte-for-byte (the compose then interpolates the env, or its `:-` default).
        env = {**os.environ, IMAGE_TAG_ENV: tag_only, **{k: str(v) for k, v in (extra_env or {}).items()}}
        # `--wait` blocks until every service is running AND (given the vigil-gateway healthcheck) HEALTHY,
        # and returns non-zero if one never gets there — so a gateway that starts then exits (bad/missing
        # charter scope) is a compose FAILURE here rather than an exit-0-but-dead container. This is the
        # belt; the caller's own container_state() check (below, and in `vigil up`) is the suspenders.
        proc = self._run(["compose", "-f", str(compose_file), "up", "-d", "--wait"],
                         timeout=BUILD_TIMEOUT, env=env)  # may pull
        if proc.returncode != 0:
            raise RuntimeError(f"docker compose up failed: {proc.stderr.strip()[-800:]}")
        result: dict = {"image_built": built, "image_tag": tag, "gateway": self.container_state()}
        if context_dir is not None:
            result["pin"] = self._verify_and_record_pin(
                context_dir, tag, pin_path=pin_path if pin_path is not None else self._default_pin_path(context_dir))
        return result

    def _verify_and_record_pin(self, context_dir, tag, *, pin_path) -> dict:
        """FAIL CLOSED that the running gateway is provably the image we just built, then record the pin.

        The digest-mismatch guard is unconditional: if the container is running an image whose content id is
        NOT the one we just built for this context, that is a hard error (a mutable tag repointed at other
        bytes, a hand-started stale container, …) — never a silent downgrade of the egress gate. Recording
        the pin (context digest + built image id) lets the A14 runtime check later prove the RUNNING gateway
        still matches the CURRENT source without a rebuild.
        """
        built_id = self.image_id(tag)
        if not built_id:
            raise RuntimeError(f"could not resolve the built gateway image id for {tag} — refusing (fail-closed)")
        running_id = self.running_image_id()
        if running_id is not None and running_id != built_id:
            raise RuntimeError(
                f"gateway image DIGEST MISMATCH — the running container is {running_id} but the image built "
                f"from the current context ({tag}) is {built_id}; refusing (fail-closed). Recreate with "
                "`vigil services down && vigil services up`.")
        cid = context_digest(context_dir)
        record = write_pin(pin_path, context_digest_hex=cid, image_tag=tag, image_id=built_id)
        record["verified_running"] = running_id is not None
        return record

    def compose_down(self, compose_file) -> None:
        """Stop + remove the gateway container (idempotent; the networks are left in place)."""
        self._run(["compose", "-f", str(compose_file), "down"])

    def status(self, image: str = DEFAULT_IMAGE) -> dict:
        """A create-if-absent readiness snapshot: which networks/image/container already exist."""
        return {
            "networks": {self.sandbox_network: self._network_exists(self.sandbox_network),
                         self.egress_network: self._network_exists(self.egress_network)},
            "image": self.image_exists(image),
            "gateway": self.container_state(),
        }
