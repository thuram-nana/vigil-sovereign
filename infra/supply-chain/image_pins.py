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
     each pinned TAG against the registry and reports where upstream has moved on. Advisory by
     design: upstream retagging is not the fault of the PR being tested, so it must not turn a
     contributor's build red. It exits 0 unless it is asked to do otherwise.
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
    def repository(self) -> str:
        """`python:3.13-slim@sha256:..` -> `library/python` (Docker Hub form)."""
        name = self.ref.split("@", 1)[0].split(":", 1)[0]
        return name if "/" in name else f"library/{name}"

    @property
    def tag(self) -> str:
        name = self.ref.split("@", 1)[0]
        return name.split(":", 1)[1] if ":" in name else "latest"

    @property
    def digest(self) -> str | None:
        m = DIGEST_RE.search(self.ref)
        return m.group(0)[1:] if m else None


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


def collect(root: Path) -> list[ImageRef]:
    refs: list[ImageRef] = []
    for p in find_dockerfiles(root):
        refs.extend(dockerfile_refs(p, root))
    for p in find_compose_files(root):
        refs.extend(compose_refs(p, root))
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
        help="make --drift exit non-zero (NOT used by CI: upstream retags are not the PR's fault)",
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
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[2]

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
        print("\nA14 image-pin DRIFT report (advisory — upstream retags are not this PR's fault)\n")
        drifted = 0
        for r in refs:
            if r.is_first_party or not r.is_digest_pinned:
                continue
            current = resolve_hub_digest(r.repository, r.tag)
            if current is None:
                print(f"  ??  {r.source}:{r.line} {r.repository}:{r.tag} — could not resolve (non-Hub registry, or network)")
            elif current == r.digest:
                print(f"  ok  {r.source}:{r.line} {r.repository}:{r.tag} — pin matches the live tag")
            else:
                drifted += 1
                print(f"  !!  {r.source}:{r.line} {r.repository}:{r.tag} has MOVED")
                print(f"        pinned:  {r.digest}")
                print(f"        current: {current}")
        print(f"\n{drifted} tag(s) have moved since they were pinned.")
        if drifted:
            print("This is informational. Re-pin deliberately (and read the upstream changelog first).")
            if args.fail_on_drift:
                return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
