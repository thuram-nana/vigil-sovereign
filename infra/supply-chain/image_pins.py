#!/usr/bin/env python3
"""A14 — container base-image pin inventory, checker, and drift reporter.

A container tag is a MUTABLE POINTER. `FROM python:3.13-slim` means "whatever the registry
serves at pull time", so a retag — benign or hostile — silently changes what ships, with no
diff, no review and no signal. A digest (`@sha256:...`) is content-addressed: the daemon
verifies it or the pull fails.

This module is the single source of truth for that rule. It has four users:

  1. ``integration/tests/test_supply_chain.py`` — loads it by path and asserts, OFFLINE, that
     every base image in the repo is digest-pinned.
  2. ``python3 infra/supply-chain/image_pins.py --check`` — the same assertion as a CLI, run by
     the "A14 supply-chain gate" CI job.
  3. ``python3 infra/supply-chain/image_pins.py --drift`` — the only networked mode. Re-resolves
     each pinned TAG against the registry and reports where upstream has moved on. Its outcome is
     three-valued, never two (W3-8, issue #431): a pin whose registry the resolver CAN query and
     which has MOVED is real, resolvable drift; a pin on a registry the resolver CANNOT query
     (anything but Docker Hub) is an explicit UNKNOWN, surfaced and counted, NEVER a silent pass.
     With ``--fail-on-drift`` (what the "A14 supply-chain gate" runs) resolvable drift BLOCKS the
     job; the UNKNOWNs are reported — to stdout and to the GitHub step summary — but do not block,
     because a gate cannot honestly fail on a state it could not check. ``--fail-on-unknown``
     tightens that for an operator who wants the strictest posture.
  4. ``python3 infra/supply-chain/image_pins.py --runtime-check`` — the RUNTIME visibility gate
     (issue #511 / W5-6). The two scanners above see only DECLARED images; they cannot see the
     image the gateway is ACTUALLY running. This mode content-addresses the gateway build context,
     reads the pin ``vigil services up`` recorded, and proves the running container is the image
     built from the CURRENT source — catching the "``:latest`` never moved on upgrade" defect.
     Loud on failure; fatal only in the PRODUCTION posture. See ``check_runtime_image``.

Stdlib only, so it runs in any job without adding a dependency to the thing it is auditing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------------------
# Exemptions — each one is a rule, not a hole. Anything not covered here MUST be pinned.
# --------------------------------------------------------------------------------------

#: `FROM scratch` has no content to pin — it is the empty base.
_SCRATCH = "scratch"

#: Images built FROM THIS REPO. They never come from a registry, so there is no upstream digest to pin;
#: their provenance is the tree itself, so the DECLARED-image scanners exempt them. The gateway image is
#: instead CONTENT-ADDRESSED at build time — `vigil services up` tags it `vigil-gateway:ctx-<digest-of-the-
#: build-context>` (plus a `:latest` alias) and records a runtime pin — and the `--runtime-check` mode below
#: proves the RUNNING container is the image built from the current source. `vigil/strix-sandbox:local` is
#: built by `docker compose --profile strix build strix-sandbox`.
FIRST_PARTY_IMAGE_PREFIXES = ("vigil-gateway", "vigil/")

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

#: The registry hosts the drift resolver can query. Docker Hub is the ONLY registry with a stable,
#: unauthenticated tag->digest endpoint this module uses; anything else is honestly reported UNKNOWN
#: rather than presented as a pass (W3-8, issue #431). These are the canonical spellings of Hub.
_HUB_HOSTS = frozenset({"docker.io", "registry-1.docker.io", "index.docker.io"})


def _parse_ref(ref: str) -> tuple[str, str | None, str, str, str | None]:
    """Split a container reference into (ref, registry_host, repo_path, tag, digest).

    ``[registry[:port]/]repository[:tag][@digest]``. The registry host is the first ``/``-separated
    component IFF it looks like a host (contains ``.`` or ``:``, or is ``localhost``); otherwise the
    ref is a Docker Hub name with no explicit registry. The tag is the last ``:``-delimited segment
    of what remains AFTER the registry (so a registry port is never mistaken for a tag). Pure/stdlib.
    """
    rest = ref
    digest: str | None = None
    m = DIGEST_RE.search(rest)
    if m:
        digest = m.group(0)[1:]
        rest = rest[: m.start()]

    registry: str | None = None
    if "/" in rest:
        first, remainder = rest.split("/", 1)
        if first == "localhost" or "." in first or ":" in first:
            registry, rest = first, remainder

    if ":" in rest:
        repo_path, tag = rest.rsplit(":", 1)
    else:
        repo_path, tag = rest, "latest"
    return ref, registry, repo_path, tag, digest

# --------------------------------------------------------------------------------------
# Runtime image visibility (issue #511 / W5-6)
# --------------------------------------------------------------------------------------
# The scanners above see only DECLARED images (Dockerfile `FROM`, compose `image:`). They cannot see the
# image the gateway is ACTUALLY running: a first-party image built locally has no registry digest, and after
# `git pull` a mutable `:latest` tag can leave the OLD gateway running with no diff and no signal. So this
# module also owns a RUNTIME check: `vigil services up` content-addresses the gateway image by a digest of
# its build context and records a pin (context digest + built image id); this check re-derives the current
# context digest, reads the pin, and (given the running container's image id) proves the RUNNING gateway is
# the image built from the CURRENT source. Fail-closed: any missing/ambiguous input is NOT a pass.

#: The gateway build context, relative to the repo root (`docker build <root>/gateway`).
GATEWAY_CONTEXT_RELPATH = "gateway"
#: Where `vigil services up` records the runtime pin (mirror of vigil_gateway.docker.PIN_RELPATH).
GATEWAY_PIN_RELPATH = ".vigil-live/gateway-image-pin.json"
#: The pin record schema (mirror of vigil_gateway.docker.PIN_SCHEMA).
GATEWAY_PIN_SCHEMA = "vigil-gateway-image-pin/1"

# Keep BYTE IDENTICAL to gateway/vigil_gateway/docker.py::_CONTEXT_IGNORE. The two live in trees that must
# not import each other (this module is stdlib-only by design; the gateway package must not be a dependency
# of the thing auditing the supply chain), so the algorithm is duplicated and a consistency test in
# gateway/tests pins the two together.
_CONTEXT_IGNORE = frozenset(
    {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "node_modules", ".ruff_cache"}
)


def context_digest(context_dir) -> str:
    """A deterministic sha256 over a docker build context — the image's CONTENT ADDRESS.

    Identical to vigil_gateway.docker.context_digest: a manifest of ``(posix-relative-path, sha256(bytes))``
    for every file, sorted by path, skipping VCS/cache/venv junk; depends only on paths + contents.
    """
    root = Path(context_dir)
    entries: list[tuple[str, str]] = []
    for p in sorted(root.rglob("*")):
        rel_parts = p.relative_to(root).parts
        if any(part in _CONTEXT_IGNORE for part in rel_parts):
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


#: The gateway image repository (mirror of vigil_gateway.docker.IMAGE_REPO). Kept here so the A14
#: supply-chain job — which builds and `trivy image`-scans the gateway (W3-7 #430) — can compute the
#: content-addressed tag with NOTHING but this stdlib module (it must not import the gateway package).
GATEWAY_IMAGE_REPO = "vigil-gateway"


def content_addressed_tag(context_dir, repo: str = GATEWAY_IMAGE_REPO) -> str:
    """The content-addressed image reference for a build context: ``vigil-gateway:ctx-<digest[:16]>``.

    BYTE-IDENTICAL to vigil_gateway.docker.content_addressed_tag (a consistency test pins the two
    together, as it already does for ``context_digest``). Changing the build context changes this tag,
    so a stale image — one built from older source — is detectable BY TAG ALONE (the W3-7 #430
    acceptance criterion, and the tag the A14 CI build applies before `trivy image` scanning it).
    """
    return f"{repo}:ctx-{context_digest(context_dir)[:16]}"


@dataclass(frozen=True)
class RuntimePinResult:
    """The outcome of the runtime image-pin check. ``ok`` is the ONLY thing a gate should key on."""

    ok: bool
    reason: str
    stale: bool = False        # the pin was written for a different (older) source tree
    mismatch: bool = False     # the running container is not the image the pin recorded
    invisible: bool = False    # no pin / no running id — the runtime cannot be proven at all
    current_digest: str = ""
    pinned_digest: str = ""


def load_gateway_pin(pin_path) -> dict | None:
    """Read the runtime image pin, or None if absent/unreadable/not our schema (fail-closed: None means the
    runtime is INVISIBLE, never 'verified')."""
    try:
        data = json.loads(Path(pin_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != GATEWAY_PIN_SCHEMA:
        return None
    return data


def check_runtime_image(*, context_dir, pin, running_image_id) -> RuntimePinResult:
    """Prove the RUNNING gateway is the image built from the CURRENT source. Pure + fail-closed.

    Inputs (all live-reading is done by the caller so this stays testable):
      * ``context_dir`` — the gateway build context to re-hash NOW.
      * ``pin`` — the recorded pin dict (from ``load_gateway_pin``), or None.
      * ``running_image_id`` — the content id the container is actually running (``sha256:...``), or None.

    Fail-closed outcomes (``ok`` is False for every one):
      * no pin                              → INVISIBLE (never built/recorded; the runtime is unproven).
      * pin.context_digest != current tree  → STALE (an upgrade landed but the gateway was not rebuilt — the
                                              exact #511 defect: the old egress gate is still running).
      * no running image id                 → INVISIBLE (cannot read the container; do not assume it is fine).
      * running id != pin.image_id          → MISMATCH (a tag repointed at other bytes / a stale container).
    Only when the current tree digest matches the pin AND the running id matches the pinned id is it ``ok``.
    """
    current = context_digest(context_dir)
    if not pin:
        return RuntimePinResult(ok=False, invisible=True, current_digest=current,
                                reason="no gateway image pin recorded — run `vigil services up` (the running "
                                       "gateway image is unproven)")
    pinned_digest = str(pin.get("context_digest", ""))
    pinned_id = str(pin.get("image_id", ""))
    if pinned_digest != current:
        return RuntimePinResult(
            ok=False, stale=True, current_digest=current, pinned_digest=pinned_digest,
            reason=("gateway image is STALE — the build context changed since it was built (pin "
                    f"{pinned_digest[:16] or '?'} != current {current[:16]}); the OLD egress gate is still "
                    "running. Rebuild + recreate with `vigil services down && vigil services up`."))
    if not running_image_id:
        return RuntimePinResult(
            ok=False, invisible=True, current_digest=current, pinned_digest=pinned_digest,
            reason="cannot read the running gateway container's image id — the runtime is unproven "
                   "(is the gateway up? `vigil services status`)")
    if running_image_id != pinned_id:
        return RuntimePinResult(
            ok=False, mismatch=True, current_digest=current, pinned_digest=pinned_digest,
            reason=(f"gateway image DIGEST MISMATCH — running {running_image_id} but the pin recorded "
                    f"{pinned_id}; the container is not the built image. `vigil services down && "
                    "vigil services up`."))
    return RuntimePinResult(ok=True, current_digest=current, pinned_digest=pinned_digest,
                            reason="running gateway matches the image built from the current source")


def _running_gateway_image_id(container: str = "vigil-gateway") -> str | None:
    """Live: the content id of the image the gateway container is actually running, or None. The only
    networked/daemon-touching part of the runtime check; the pure logic above takes it as input."""
    docker = _which_docker()
    if not docker:
        return None
    try:
        proc = subprocess.run([docker, "inspect", "-f", "{{.Image}}", container],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _which_docker() -> str | None:
    from shutil import which
    return which("docker")


def _production_posture() -> bool:
    """True iff VIGIL_POSTURE selects the production gate (mirror of vigil_integration.doctor)."""
    return os.environ.get("VIGIL_POSTURE", "").strip().lower() in ("production", "prod")


@dataclass(frozen=True)
class ImageRef:
    """One place a container image is named."""

    source: str  # repo-relative path
    line: int  # 1-based
    ref: str  # the fully-substituted image reference
    context: str  # human-readable: "FROM", "ARG PYTHON_BASE", "service qdrant"

    @property
    def is_digest_pinned(self) -> bool:
        return bool(DIGEST_RE.search(self.ref))

    @property
    def is_first_party(self) -> bool:
        return self.ref.startswith(FIRST_PARTY_IMAGE_PREFIXES)

    @property
    def registry_host(self) -> str | None:
        """The registry hostname, or None when the ref uses Docker Hub's implicit default.

        A reference is ``[registry[:port]/]repository[:tag][@digest]``. The first ``/``-separated
        component is a REGISTRY only if it looks like a host — it contains a ``.`` or a ``:`` (a
        port), or is literally ``localhost``. ``ghcr.io/o/i`` and ``myreg:5000/i`` have a registry;
        ``python`` and ``owner/image`` do not (they are Docker Hub)."""
        _, host, _, _, _ = _parse_ref(self.ref)
        return host

    @property
    def is_docker_hub(self) -> bool:
        """True iff this ref resolves on Docker Hub — the only registry the drift resolver queries."""
        host = self.registry_host
        return host is None or host in _HUB_HOSTS

    @property
    def repository(self) -> str:
        """`python:3.13-slim@sha256:..` -> `library/python` (Docker Hub form).

        For a non-Hub ref the registry host is stripped and the path returned verbatim; it is not a
        Hub repository and the drift resolver never queries it (it is reported UNKNOWN instead)."""
        _, host, path, _, _ = _parse_ref(self.ref)
        if host is not None and host not in _HUB_HOSTS:
            return path
        return path if "/" in path else f"library/{path}"

    @property
    def tag(self) -> str:
        _, _, _, tag, _ = _parse_ref(self.ref)
        return tag

    @property
    def digest(self) -> str | None:
        _, _, _, _, digest = _parse_ref(self.ref)
        return digest


# --------------------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------------------

_SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache"}


def _walk(root: Path):
    for p in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p


def find_dockerfiles(root: Path) -> list[Path]:
    out = [
        p
        for p in _walk(root)
        if p.name.startswith(("Dockerfile", "Containerfile")) or p.suffix == ".dockerfile"
    ]
    return sorted(out)


def find_compose_files(root: Path) -> list[Path]:
    out = [
        p
        for p in _walk(root)
        if re.fullmatch(r"(docker-)?compose(\.[\w-]+)?\.ya?ml", p.name)
    ]
    return sorted(out)


def dockerfile_refs(path: Path, root: Path) -> list[ImageRef]:
    """Every `FROM` in one Dockerfile, with ARG substitution and build-stage awareness.

    Handles the three legitimate non-registry cases:
      * ``FROM scratch``
      * ``FROM <earlier-stage>`` (declared by ``FROM ... AS <earlier-stage>``)
      * ``FROM ${ARG}`` — resolved through the ARG's default, so the pin is checked where it
        actually lives. gateway/Dockerfile uses this shape.
    """
    rel = str(path.relative_to(root))
    args: dict[str, str] = {}
    stages: set[str] = set()
    refs: list[ImageRef] = []

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        m = re.match(r"ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)", line, re.IGNORECASE)
        if m:
            args[m.group(1)] = m.group(2)
            continue

        m = re.match(r"FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", line, re.IGNORECASE)
        if not m:
            continue
        image, stage = m.group(1), m.group(2)
        if stage:
            stages.add(stage.lower())

        context = "FROM"
        # Substitute ${ARG} / $ARG from the ARG defaults seen above this line.
        def _sub(mo: re.Match) -> str:
            return args.get(mo.group(1) or mo.group(2), mo.group(0))

        resolved = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", _sub, image)
        if resolved != image:
            varname = re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", image)
            context = f"FROM (via ARG {varname[0]})" if varname else "FROM (via ARG)"

        if resolved.lower() == _SCRATCH or resolved.lower() in stages:
            continue
        refs.append(ImageRef(source=rel, line=lineno, ref=resolved, context=context))

    return refs


def compose_refs(path: Path, root: Path) -> list[ImageRef]:
    """Every `image:` in one compose file, skipping services that `build:` locally.

    Deliberately a small indentation-aware scanner rather than a PyYAML dependency: this
    module audits the supply chain, so it should not widen it. The compose files in this repo
    are plain 2-space-indented mappings.
    """
    rel = str(path.relative_to(root))
    lines = path.read_text(encoding="utf-8").splitlines()

    # Locate the `services:` block and each service's line span.
    in_services = False
    services: list[tuple[str, int, int]] = []  # (name, start_idx, end_idx_exclusive)
    svc_indent: int | None = None
    for i, raw in enumerate(lines):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if not in_services:
            if re.match(r"^services:\s*$", raw):
                in_services = True
            continue
        if indent == 0:  # a new top-level key ends the services block
            break
        m = re.match(r"^(\s+)([\w.-]+):\s*$", raw)
        if m and (svc_indent is None or len(m.group(1)) == svc_indent):
            svc_indent = len(m.group(1))
            if services:
                services[-1] = (services[-1][0], services[-1][1], i)
            services.append((m.group(2), i, len(lines)))

    refs: list[ImageRef] = []
    for name, start, end in services:
        block = lines[start:end]
        has_build = any(re.match(r"^\s+build:", b) for b in block)
        for off, raw in enumerate(block):
            m = re.match(r"^\s+image:\s*(\S+)\s*(?:#.*)?$", raw)
            if not m:
                continue
            if has_build:
                continue  # built from this tree; no upstream digest exists
            refs.append(
                ImageRef(
                    source=rel,
                    line=start + off + 1,
                    ref=m.group(1),
                    context=f"service {name}",
                )
            )
    return refs


# --------------------------------------------------------------------------------------
# The Strix runtime (agent-sandbox) image — named in NO Dockerfile and NO compose `image:`.
# --------------------------------------------------------------------------------------
#: The offense agent pulls its sandbox image from the DEFAULT of the ``STRIX_IMAGE`` pydantic setting at
#: launch, not from a Dockerfile or a compose service. A mutable tag as that default is exactly the drift
#: this gate exists to stop — an operator who never sets ``STRIX_IMAGE`` runs whatever the registry serves
#: — so A14 must see it too. This scans the committed default (the only value in the tree; the runtime
#: layer ``sandbox_hardening.assert_runtime_image_pinned`` enforces the same rule on an env override).
STRIX_SETTINGS_REL = "vendor/strix/strix/config/settings.py"

#: ``default="<ref>", ... alias="STRIX_IMAGE"`` — anchored to the STRIX_IMAGE alias so it cannot latch
#: onto an unrelated field's default; ``[^)]*?`` stays inside the one ``Field(...)`` call.
_STRIX_IMAGE_DEFAULT_RE = re.compile(
    r"""default\s*=\s*["']([^"']+)["'][^)]*?alias\s*=\s*["']STRIX_IMAGE["']"""
)


def strix_runtime_image_refs(root: Path) -> list[ImageRef]:
    """The Strix runtime sandbox image, read from the ``STRIX_IMAGE`` setting default."""
    path = root / STRIX_SETTINGS_REL
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    m = _STRIX_IMAGE_DEFAULT_RE.search(text)
    if not m:
        return []
    line = text.count("\n", 0, m.start(1)) + 1
    return [
        ImageRef(
            source=STRIX_SETTINGS_REL,
            line=line,
            ref=m.group(1),
            context="STRIX_IMAGE default (strix runtime sandbox)",
        )
    ]


def collect(root: Path) -> list[ImageRef]:
    refs: list[ImageRef] = []
    for p in find_dockerfiles(root):
        refs.extend(dockerfile_refs(p, root))
    for p in find_compose_files(root):
        refs.extend(compose_refs(p, root))
    refs.extend(strix_runtime_image_refs(root))
    return refs


def unpinned(refs) -> list[ImageRef]:
    """Refs that MUST be digest-pinned and are not."""
    return [r for r in refs if not r.is_first_party and not r.is_digest_pinned]


# --------------------------------------------------------------------------------------
# Drift (the only networked path)
# --------------------------------------------------------------------------------------


def resolve_hub_digest(repository: str, tag: str, timeout: int = 30) -> str | None:
    """Current manifest digest for a Docker Hub tag, or None if it cannot be resolved."""
    url = f"https://hub.docker.com/v2/repositories/{repository}/tags/{tag}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - fixed host
            return json.load(resp).get("digest")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


# --------------------------------------------------------------------------------------
# Drift EVALUATION — three-valued, resolver-injected, and pure (so it is testable OFFLINE).
# The live resolver is the only networked seam; `evaluate_drift` never touches the network, so a
# negative control can prove the gate fires with a fake resolver and no PyPI/registry dependency.
# --------------------------------------------------------------------------------------

#: A pinned tag's drift outcome. Exactly one applies to each pinned, non-first-party ref.
DRIFT_MATCH = "match"                       # pin equals the live digest — nothing to do
DRIFT_MOVED = "drifted"                     # RESOLVABLE registry, pin no longer matches — this BLOCKS
DRIFT_UNKNOWN_REGISTRY = "unknown-registry"  # registry the resolver cannot query — explicit UNKNOWN
DRIFT_UNKNOWN_NETWORK = "unknown-network"    # resolver-capable registry it could not reach — UNKNOWN

DRIFT_MOVED_ADVISORY = "drifted-advisory"   # a ROLLING tag moved — surfaced, NOT blocking (see below)

_UNKNOWN = (DRIFT_UNKNOWN_REGISTRY, DRIFT_UNKNOWN_NETWORK)

# Rolling-tag drift that is ADVISORY, not blocking. A repository listed here is tracked-latest BY DESIGN,
# so a moved digest is expected upkeep, not a defect — and it is ALREADY advisory-vuln-scanned in the A14
# job, so gating a per-PR build on its daily movement would be a category error. BLOCKING drift still
# applies to every other (stable, pinned-intent) tag; only these documented rolling bases are advisory.
# Re-pin them deliberately on a cadence (read the changelog), not under a red build. Each entry needs a reason.
_ADVISORY_ROLLING_DRIFT: dict[str, str] = {
    # The Strix sandbox base: a rolling Kali distro tracked at :latest so the offensive toolchain stays
    # current. Its committed SBOM is regenerated deliberately (gen_image_sbom.py), never per-drift, and its
    # image vuln scan is already ADVISORY in the A14 job — so its drift is surfaced, not blocking.
    "kalilinux/kali-rolling": "rolling Kali distro base (strix sandbox); any tag of this rolling repo is tracked-latest by design, already advisory-vuln-scanned; SBOM regenerated deliberately, not per-drift",
}


@dataclass(frozen=True)
class Resolution:
    """What a resolver could determine about one pinned tag's CURRENT digest.

    ``supported`` answers "can this resolver even query this ref's registry?" — the distinction the old
    two-valued ``??`` collapsed. A False ``supported`` is a KNOWN limitation (non-Hub registry), not a
    transient failure; ``supported`` True with ``digest`` None is a transient/lookup failure.
    """

    supported: bool
    digest: str | None = None
    error: str = ""


@dataclass(frozen=True)
class DriftResult:
    """The per-ref verdict `evaluate_drift` produces. ``status`` is one of the DRIFT_* constants."""

    ref: ImageRef
    status: str
    current: str | None = None
    detail: str = ""

    @property
    def is_drift(self) -> bool:
        return self.status == DRIFT_MOVED

    @property
    def is_advisory_drift(self) -> bool:
        return self.status == DRIFT_MOVED_ADVISORY

    @property
    def is_unknown(self) -> bool:
        return self.status in _UNKNOWN


def hub_resolver(ref: ImageRef, timeout: int = 30) -> Resolution:
    """The live resolver: Docker Hub only. A non-Hub ref is UNSUPPORTED (an honest UNKNOWN), never a
    silent pass; a Hub ref that fails to resolve is a network/lookup UNKNOWN."""
    if not ref.is_docker_hub:
        return Resolution(
            supported=False,
            error=f"registry {ref.registry_host!r} is not queryable by the drift resolver "
                  "(Docker Hub only); pin currency for this registry is UNKNOWN, re-checked offline "
                  "against the committed digest by --check",
        )
    digest = resolve_hub_digest(ref.repository, ref.tag, timeout=timeout)
    if digest is None:
        return Resolution(
            supported=True,
            error="Docker Hub returned no digest for this tag (a deleted/renamed tag, rate-limiting, "
                  "or a network error)",
        )
    return Resolution(supported=True, digest=digest)


def evaluate_drift(refs, resolver) -> list[DriftResult]:
    """Classify every pinned, non-first-party ref into MATCH / DRIFTED / UNKNOWN. Pure: all network
    lives in ``resolver`` (``hub_resolver`` in production, a stub in tests)."""
    out: list[DriftResult] = []
    for r in refs:
        if r.is_first_party or not r.is_digest_pinned:
            continue
        res = resolver(r)
        if not res.supported:
            out.append(DriftResult(r, DRIFT_UNKNOWN_REGISTRY, detail=res.error))
        elif res.digest is None:
            out.append(DriftResult(r, DRIFT_UNKNOWN_NETWORK, detail=res.error))
        elif res.digest == r.digest:
            out.append(DriftResult(r, DRIFT_MATCH, current=res.digest))
        elif r.repository in _ADVISORY_ROLLING_DRIFT:
            out.append(DriftResult(r, DRIFT_MOVED_ADVISORY, current=res.digest,
                                   detail=f"rolling tag moved (advisory — {_ADVISORY_ROLLING_DRIFT[r.repository]})"))
        else:
            out.append(DriftResult(r, DRIFT_MOVED, current=res.digest,
                                   detail="pinned digest no longer matches the live tag"))
    return out


def _drift_summary_markdown(results: list[DriftResult]) -> str:
    """A GitHub step-summary block: resolvable drift, the documented-rolling ADVISORY moves (W3-8 #431 —
    surfaced, never blocking), and — the point of W3-8 — the explicit UNKNOWNs, so neither an advisory
    rolling move nor an unqueryable registry is INVISIBLE in the run, and nothing is a silent pass."""
    drifted = [d for d in results if d.is_drift]
    advisory = [d for d in results if d.is_advisory_drift]
    unknown = [d for d in results if d.is_unknown]
    matched = [d for d in results if d.status == DRIFT_MATCH]
    lines = ["## A14 base-image drift (W3-8)", ""]
    lines.append(f"- resolvable & up-to-date: **{len(matched)}**")
    lines.append(f"- resolvable & DRIFTED (blocking): **{len(drifted)}**")
    lines.append(f"- documented rolling base MOVED (advisory, NOT blocking): **{len(advisory)}**")
    lines.append(f"- UNKNOWN (registry not queryable / unreachable): **{len(unknown)}**")
    if drifted:
        lines += ["", "### Resolvable drift — BLOCKING", ""]
        for d in drifted:
            lines.append(f"- `{d.ref.source}:{d.ref.line}` {d.ref.repository}:{d.ref.tag} — "
                         f"pinned `{d.ref.digest}` → live `{d.current}`")
    if advisory:
        lines += ["", "### Rolling base moved — ADVISORY, not blocking (re-pin deliberately)", ""]
        for d in advisory:
            lines.append(f"- `{d.ref.source}:{d.ref.line}` {d.ref.repository}:{d.ref.tag} — "
                         f"pinned `{d.ref.digest}` → live `{d.current}` ({d.detail})")
    if unknown:
        lines += ["", "### UNKNOWN — not a pass, could not be checked", ""]
        for d in unknown:
            lines.append(f"- `{d.ref.source}:{d.ref.line}` {d.ref.ref} — {d.detail}")
    return "\n".join(lines) + "\n"


def run_drift(refs, resolver, *, fail_on_drift: bool, fail_on_unknown: bool = False,
              summary_path=None) -> int:
    """Print the three-valued drift report, optionally append a GitHub step summary, and return the
    exit code: resolvable drift blocks under ``--fail-on-drift``; UNKNOWNs block only under
    ``--fail-on-unknown`` — otherwise they are surfaced loudly but do not fail a build for a check
    that could not run."""
    results = evaluate_drift(refs, resolver)
    drifted = [d for d in results if d.is_drift]
    advisory = [d for d in results if d.is_advisory_drift]
    unsupported = [d for d in results if d.status == DRIFT_UNKNOWN_REGISTRY]
    unresolved = [d for d in results if d.status == DRIFT_UNKNOWN_NETWORK]
    matched = [d for d in results if d.status == DRIFT_MATCH]

    print("\nA14 image-pin DRIFT report — resolvable drift BLOCKS; other registries are explicit "
          "UNKNOWN, never a silent pass (W3-8)\n")
    for d in results:
        if d.status == DRIFT_MATCH:
            print(f"  ok  {d.ref.source}:{d.ref.line} {d.ref.repository}:{d.ref.tag} — pin matches the live tag")
        elif d.is_drift:
            print(f"  !!  {d.ref.source}:{d.ref.line} {d.ref.repository}:{d.ref.tag} has MOVED (resolvable — BLOCKING)")
            print(f"        pinned:  {d.ref.digest}")
            print(f"        current: {d.current}")
        elif d.is_advisory_drift:
            print(f"  ~~  {d.ref.source}:{d.ref.line} {d.ref.repository}:{d.ref.tag} has MOVED (rolling — ADVISORY, not blocking)")
            print(f"        pinned:  {d.ref.digest}")
            print(f"        current: {d.current}")
        else:
            label = "UNKNOWN (registry not queryable)" if d.status == DRIFT_UNKNOWN_REGISTRY \
                else "UNKNOWN (could not reach registry)"
            print(f"  ??  {d.ref.source}:{d.ref.line} {d.ref.ref} — {label}: {d.detail}")

    print(f"\nresolvable up-to-date: {len(matched)}   resolvable DRIFTED: {len(drifted)}   "
          f"rolling ADVISORY: {len(advisory)}   "
          f"UNKNOWN: {len(unsupported) + len(unresolved)} "
          f"({len(unsupported)} unqueryable registry, {len(unresolved)} unreachable)")

    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(_drift_summary_markdown(results))
        except OSError as exc:
            print(f"  [warn] could not write drift summary to {summary_path}: {exc}", file=sys.stderr)

    code = 0
    if drifted:
        print("\nResolvable drift is BLOCKING: re-pin deliberately (read the upstream changelog first), "
              "then commit the new image:tag@sha256:<digest>.")
        if fail_on_drift:
            code = 1
    if advisory:
        print("\nDocumented rolling bases MOVED (advisory — surfaced, NOT blocking): re-pin deliberately on "
              "a cadence (read the upstream changelog first), not under a red build. The reasoned allowlist "
              "is infra/supply-chain/image_pins.py::_ADVISORY_ROLLING_DRIFT.")
    if unsupported or unresolved:
        print("UNKNOWN registries are reported, not silently passed. They cannot be auto-checked; verify "
              "their pins by hand or set --fail-on-unknown for the strictest posture.")
        if fail_on_unknown:
            code = 1
    return code


def _runtime_check(root: Path, *, pin_path=None, production: bool = False) -> int:
    """The A14 RUNTIME-visibility gate (issue #511). Re-derive the gateway context digest, read the recorded
    pin, read the running container's image id, and prove they line up. LOUD on failure; fatal (non-zero)
    only when the production posture is armed (VIGIL_POSTURE=production/prod or --production) — otherwise it
    is advisory, so a dev box without the gateway up is not a red build."""
    context_dir = root / GATEWAY_CONTEXT_RELPATH
    pin_file = Path(pin_path) if pin_path else (root / GATEWAY_PIN_RELPATH)
    pin = load_gateway_pin(pin_file)
    running = _running_gateway_image_id()
    result = check_runtime_image(context_dir=context_dir, pin=pin, running_image_id=running)
    fatal = production or _production_posture()

    print("A14 gateway RUNTIME image-pin check (issue #511 — the running image the scanners cannot see)\n")
    print(f"  build context : {context_dir}")
    print(f"  current digest: {result.current_digest}")
    print(f"  pin file      : {pin_file}  ({'present' if pin else 'ABSENT'})")
    print(f"  running image : {running or 'UNREADABLE'}")
    if result.ok:
        print(f"\n  ok  {result.reason}")
        return 0
    label = "STALE" if result.stale else "MISMATCH" if result.mismatch else "INVISIBLE"
    banner = "REFUSED (fail-closed)" if fatal else "WARNING (advisory)"
    print(f"\n  !!  {banner} — {label}: {result.reason}", file=sys.stderr)
    if fatal:
        print("      VIGIL_POSTURE selects the PRODUCTION posture (or --production) — refusing.", file=sys.stderr)
        return 1
    print("      Not fatal outside the production posture; run `vigil services up` to rebuild + recreate.",
          file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=None, help="repo root (default: two levels up from this file)")
    ap.add_argument("--check", action="store_true", help="offline: fail if any image is unpinned")
    ap.add_argument("--drift", action="store_true", help="network: report tags that have moved")
    ap.add_argument(
        "--fail-on-drift",
        action="store_true",
        help="make --drift exit non-zero on RESOLVABLE drift (a Docker Hub pin that has moved). This "
             "IS what the A14 gate runs (W3-8): resolvable drift blocks; UNKNOWN registries do not.",
    )
    ap.add_argument(
        "--fail-on-unknown",
        action="store_true",
        help="also exit non-zero when any pin's registry could not be queried (strictest posture). "
             "Off by default: a gate cannot honestly fail on a state it could not check.",
    )
    ap.add_argument(
        "--summary-file",
        default=None,
        help="append a markdown drift summary here (default: $GITHUB_STEP_SUMMARY when set), so "
             "UNKNOWN registries are visible in the job summary and never a silent pass.",
    )
    ap.add_argument(
        "--runtime-check",
        action="store_true",
        help="prove the RUNNING gateway is the image built from the current source (issue #511). Loud "
             "warning on a stale/mismatched/invisible runtime; exits non-zero only in the PRODUCTION "
             "posture (VIGIL_POSTURE=production) or with --production.",
    )
    ap.add_argument("--production", action="store_true",
                    help="treat a failed --runtime-check as fatal (exit non-zero) even outside VIGIL_POSTURE")
    ap.add_argument("--pin", default=None, help="runtime pin path (default: <root>/.vigil-live/gateway-image-pin.json)")
    ap.add_argument(
        "--context-tag",
        action="store_true",
        help="print the CONTENT-ADDRESSED gateway image tag (vigil-gateway:ctx-<digest16>) for the "
             "current build context and exit. The A14 CI job (W3-7 #430) uses it to tag the image it "
             "builds before `trivy image`-scanning it, so a stale image is detectable by tag alone.",
    )
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[2]

    if args.context_tag:
        # Stdout is consumed by CI (`TAG=$(... --context-tag)`); keep it to the bare tag, nothing else.
        print(content_addressed_tag(root / GATEWAY_CONTEXT_RELPATH))
        return 0

    if args.runtime_check:
        return _runtime_check(root, pin_path=args.pin, production=args.production)

    refs = collect(root)
    if not refs:
        print(f"ERROR: no image references found under {root} — the scanner is broken.", file=sys.stderr)
        return 2

    if args.check or not (args.check or args.drift):
        print(f"A14 image-pin check — {len(refs)} image reference(s) under {root}\n")
        bad = unpinned(refs)
        for r in refs:
            if r.is_first_party:
                mark, note = "  --", "built from this repo (no upstream digest)"
            elif r.is_digest_pinned:
                mark, note = "  ok", "digest-pinned"
            else:
                mark, note = "FAIL", "NOT digest-pinned"
            print(f"{mark}  {r.source}:{r.line} [{r.context}] {r.ref}  ({note})")
        if bad:
            print(f"\n{len(bad)} unpinned image reference(s). Pin with image:tag@sha256:<digest>.")
            print("Resolve current digests with: python3 infra/supply-chain/image_pins.py --drift")
            return 1
        print("\nAll registry images are digest-pinned.")

    if args.drift:
        summary_path = args.summary_file or os.environ.get("GITHUB_STEP_SUMMARY")
        drift_code = run_drift(
            refs, hub_resolver,
            fail_on_drift=args.fail_on_drift,
            fail_on_unknown=args.fail_on_unknown,
            summary_path=summary_path,
        )
        if drift_code:
            return drift_code
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
