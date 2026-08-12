#!/usr/bin/env python3
"""A14 — container base-image pin inventory, checker, and drift reporter.

A container tag is a MUTABLE POINTER. `FROM python:3.13-slim` means "whatever the registry
serves at pull time", so a retag — benign or hostile — silently changes what ships, with no
diff, no review and no signal. A digest (`@sha256:...`) is content-addressed: the daemon
verifies it or the pull fails.

This module is the single source of truth for that rule. It has three users:

  1. ``integration/tests/test_supply_chain.py`` — loads it by path and asserts, OFFLINE, that
     every base image in the repo is digest-pinned.
  2. ``python3 infra/supply-chain/image_pins.py --check`` — the same assertion as a CLI, run by
     the "A14 supply-chain gate" CI job.
  3. ``python3 infra/supply-chain/image_pins.py --drift`` — the only networked mode. Re-resolves
     each pinned TAG against the registry and reports where upstream has moved on. Advisory by
     design: upstream retagging is not the fault of the PR being tested, so it must not turn a
     contributor's build red. It exits 0 unless it is asked to do otherwise.

Stdlib only, so it runs in any job without adding a dependency to the thing it is auditing.
"""

from __future__ import annotations

import argparse
import json
import re
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

#: Images built FROM THIS REPO. They never come from a registry, so there is no upstream
#: digest to pin; their provenance is the tree itself. `vigil-gateway:latest` is produced by
#: `docker build -t vigil-gateway:latest gateway` (see `vigil services up`), and
#: `vigil/strix-sandbox:local` by `docker compose --profile strix build strix-sandbox`.
FIRST_PARTY_IMAGE_PREFIXES = ("vigil-gateway", "vigil/")

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


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
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[2]
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
