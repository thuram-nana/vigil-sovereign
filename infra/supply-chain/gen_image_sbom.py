#!/usr/bin/env python3
"""gen_image_sbom.py — a REAL CycloneDX SBOM of the Strix sandbox CONTAINER image.

WHY THIS EXISTS. The A14 supply-chain gate produces DEPENDENCY SBOMs — the Python
closure of each environment, derived from the hash-locks
(``framework/v2/sbom.json`` via ``gen_sbom.py``; ``sbom-offense.cdx.json`` /
``sbom-sovereign.cdx.json`` via ``cyclonedx-bom``). None of them describe the
**container the offense agent actually runs targets in**. That image
(``vigil/strix-sandbox:local``, built from ``vendor/strix/containers/Dockerfile``,
``FROM kalilinux/kali-rolling``) carries ~1000 Debian packages plus a Go, npm,
pip, pipx and standalone-binary toolchain, and had **no SBOM at all** (the S5 note
in the STRIX+HEXSTRIKE programme; Part III requires *dependency + container*
SBOMs). This tool closes that gap.

HOW IT IS GENERATED — MEASURED, NOT FABRICATED. The Dockerfile is not a faithful
bill of materials: it installs whole apt sets with **no version pins**, and several
tools with ``@latest`` / ``go install ...@latest`` / ``-update-templates``, so what
actually ships is only knowable from a **built image**. So this generator
introspects the built image's own package databases — the same sources ``syft``
would read, but with **stdlib + docker only** (no syft/trivy/cyclonedx-bom on the
host), for the reason ``gen_sbom.py`` is stdlib-only: a sovereign engine must be
able to regenerate its own bill of materials with the tools it already has.

  * ``dpkg-query -W``           -> ``pkg:deb`` components (resolved name/version/arch)
  * ``/app/.venv/bin/pip``      -> ``pkg:pypi`` (the in-image Python runtime deps)
  * ``pipx runpip <app>``       -> ``pkg:pypi`` per pipx tool venv closure
  * ``npm ls -g --depth=0``     -> ``pkg:npm`` (globally installed CLI tools)
  * ``go version -m <binary>``  -> ``pkg:golang`` (module path + version per go bin)
  * ``<tool> --version``        -> ``pkg:generic`` for curl-installed binaries
                                   (gitleaks, trivy, trufflehog, caido-cli, uv)
  * ``git rev-parse HEAD``      -> ``pkg:github`` for git-cloned tools (version=commit)

HONEST LIMITATIONS (see docs/SUPPLY-CHAIN.md § 3a):
  * The resolved versions are read from a LOCALLY BUILT image; this generator
    records that image's id + created time in the SBOM, but it cannot cryptographically
    prove that image was built from exactly the committed Dockerfile (there is no
    reproducible-build attestation for the sandbox image in this repo).
  * ``--check`` runs OFFLINE (no docker): it proves the committed SBOM is present,
    real, and CURRENT WITH RESPECT TO THE DOCKERFILE + the STRIX_IMAGE runtime ref
    (its recorded ``dockerfile-sha256`` / base-image / target-image still match the
    tree). It does NOT re-introspect the image — regenerating resolved versions
    requires ``--from-image`` with docker, exactly as ``gen_sbom --check`` trusts the
    lock rather than re-resolving PyPI.
  * npm is captured at ``--depth=0`` (the tools installed), not the full node_modules
    transitive tree.

Usage (from anywhere)::

    python3 infra/supply-chain/gen_image_sbom.py            # introspect + rewrite the SBOM
    python3 infra/supply-chain/gen_image_sbom.py --from-image vigil/strix-sandbox:local
    python3 infra/supply-chain/gen_image_sbom.py --check     # OFFLINE drift guard (no docker)
    python3 infra/supply-chain/gen_image_sbom.py -o out.cdx.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

# infra/supply-chain/gen_image_sbom.py -> repo root is parents[2]
HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[2]
DOCKERFILE_REL = "vendor/strix/containers/Dockerfile"
DEFAULT_SBOM = HERE.parent / "sbom-strix-sandbox.cdx.json"
DEFAULT_IMAGE = "vigil/strix-sandbox:local"
IMAGE_PINS_PATH = HERE.parent / "image_pins.py"

GENERATOR_NAME = "gen_image_sbom.py"
GENERATOR_VERSION = "1.0.0"
SCAFFOLD_SENTINEL = "scaffold"
ZERO_TIMESTAMP = "0000-00-00T00:00:00Z"
SPEC_VERSION = "1.5"
# dpkg alone is ~1010 packages; an SBOM smaller than this is a truncated or placeholder
# capture, not the real image. A concrete floor makes "the capture silently failed" a
# red build rather than a confident, empty bill of materials.
MIN_COMPONENTS = 900
# Characters that appear only in a version RANGE, never in a resolved pin (mirrors
# test_gen_sbom.py). A resolved SBOM must carry pins, not ranges.
_RANGE_CHARS = set("<>*, ")

_PROP = "vigil"  # property namespace, mirroring gen_sbom.py's "crucible:" convention


# --------------------------------------------------------------------------------------
# image_pins reuse — single source of truth for the Dockerfile FROM ref and the
# STRIX_IMAGE runtime default. Loaded by path (stdlib file), like test_supply_chain.py.
# --------------------------------------------------------------------------------------
def _load_image_pins():
    spec = importlib.util.spec_from_file_location("vigil_a14_image_pins_for_sbom", IMAGE_PINS_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover - sibling always present
        raise SystemExit(f"gen_image_sbom: cannot load {IMAGE_PINS_PATH}")
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: image_pins defines @dataclass classes, and dataclasses resolves
    # each class's __module__ via sys.modules — an unregistered module raises AttributeError.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def dockerfile_sha256(root: Path = REPO_ROOT) -> str:
    return hashlib.sha256((root / DOCKERFILE_REL).read_bytes()).hexdigest()


def base_image_ref(root: Path = REPO_ROOT) -> str:
    """The FROM ref of the sandbox Dockerfile, via image_pins (ARG-substituted)."""
    pins = _load_image_pins()
    refs = pins.dockerfile_refs(root / DOCKERFILE_REL, root)
    if not refs:
        raise SystemExit(f"gen_image_sbom: no FROM found in {DOCKERFILE_REL}")
    return refs[0].ref


def runtime_image_ref(root: Path = REPO_ROOT) -> str:
    """The STRIX_IMAGE default the agent actually launches, via image_pins."""
    pins = _load_image_pins()
    refs = pins.strix_runtime_image_refs(root)
    return refs[0].ref if refs else ""


# --------------------------------------------------------------------------------------
# Component model
# --------------------------------------------------------------------------------------
def _norm_pypi(name: str) -> str:
    """PEP 503 normalization (lower-case; runs of -/_/. -> single -)."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


class Component:
    __slots__ = ("bom_ref", "name", "version", "purl", "props")

    def __init__(self, bom_ref: str, name: str, version: str, purl: str, props: dict) -> None:
        self.bom_ref = bom_ref
        self.name = name
        self.version = version
        self.purl = purl
        self.props = props

    def as_dict(self) -> dict:
        entry: dict[str, object] = {
            "type": "library",
            "bom-ref": self.bom_ref,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "scope": "required",
        }
        entry["properties"] = [
            {"name": f"{_PROP}:{k}", "value": v} for k, v in sorted(self.props.items())
        ]
        return entry


# --------------------------------------------------------------------------------------
# The in-container collector — emits a tab-delimited manifest to stdout. Every line is a
# record whose first field is its ECOSYSTEM token. stdlib + shell only; each command is
# guarded (set +e) so one missing toolchain never aborts the whole capture.
# --------------------------------------------------------------------------------------
_COLLECTOR = r"""
set +e
emit() { printf '%s\n' "$*"; }
if [ -r /etc/os-release ]; then
  . /etc/os-release
  emit "META	os-id	${ID}"
  emit "META	os-version	${VERSION_ID}"
  emit "META	os-pretty	${PRETTY_NAME}"
fi
emit "META	python3	$(python3 --version 2>&1 | awk '{print $2}')"
[ -x /app/.venv/bin/python ] && emit "META	app-venv-python	$(/app/.venv/bin/python --version 2>&1 | awk '{print $2}')"

# Debian/Kali packages (the OS layer).
dpkg-query -W -f='DEB\t${Package}\t${Version}\t${Architecture}\n' 2>/dev/null

# In-image Python runtime deps (the /app/.venv used by strix's caido/proxy helpers).
if [ -x /app/.venv/bin/pip ]; then
  /app/.venv/bin/pip list --format=freeze 2>/dev/null \
    | awk -F'==' 'NF==2 && $2!="" {print "PYPI\tapp-venv\t"$1"\t"$2}'
fi

# Each pipx tool has its own venv closure.
if command -v pipx >/dev/null 2>&1; then
  for app in $(pipx list --short 2>/dev/null | awk '{print $1}'); do
    pipx runpip "$app" list --format=freeze 2>/dev/null \
      | awk -F'==' -v a="$app" 'NF==2 && $2!="" {print "PYPI\tpipx:"a"\t"$1"\t"$2}'
  done
fi

# Globally installed npm CLI tools (depth 0 — the tools, not the full node_modules tree).
# Emit the raw --json output as one base64 line and decode host-side: piping into an
# in-container `python3 - <<HEREDOC` does NOT work (the heredoc, not the pipe, becomes the
# script's stdin), and base64 sidesteps all nested-quoting hazards.
if command -v npm >/dev/null 2>&1; then
  j=$(npm ls -g --depth=0 --json 2>/dev/null | base64 -w0 2>/dev/null)
  [ -n "$j" ] && emit "NPMJSON	$j"
fi

# Go binaries built with `go install` — resolve the module path + version baked in.
if command -v go >/dev/null 2>&1; then
  for b in /home/pentester/go/bin/*; do
    [ -f "$b" ] || continue
    n=$(basename "$b")
    go version -m "$b" 2>/dev/null \
      | awk -v n="$n" '$1=="mod"{print "GOLANG\t"n"\t"$2"\t"$3; exit}'
  done
fi

# Curl-installed standalone binaries — resolved version read from the tool itself.
for spec in \
  "gitleaks:gitleaks:curl-install.sh" \
  "trivy:trivy:curl-install.sh" \
  "trufflehog:trufflehog:curl-install.sh" \
  "caido-cli:caido-cli:caido.download" \
  "uv:uv:astral-install.sh"; do
  name=${spec%%:*}; rest=${spec#*:}; cmd=${rest%%:*}; src=${rest##*:}
  if command -v "$cmd" >/dev/null 2>&1; then
    ver=$("$cmd" --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [ -n "$ver" ] && emit "BIN	$name	$ver	$src"
  fi
done

# Git-cloned tools — version is the pinned commit (there is no package version).
for d in /home/pentester/tools/*/; do
  [ -d "$d/.git" ] || continue
  n=$(basename "$d")
  origin=$(git -C "$d" config --get remote.origin.url 2>/dev/null)
  commit=$(git -C "$d" rev-parse HEAD 2>/dev/null)
  [ -n "$commit" ] && emit "GIT	$n	$origin	$commit"
done
"""


def _docker() -> str:
    for cand in ("docker", "/usr/bin/docker", "/usr/local/bin/docker"):
        try:
            subprocess.run([cand, "--version"], capture_output=True, check=True)
            return cand
        except (OSError, subprocess.CalledProcessError):
            continue
    raise SystemExit("gen_image_sbom: docker not found — needed to introspect the image "
                     "(use --check for the offline drift guard instead)")


def _inspect(docker: str, image: str) -> tuple[str, str]:
    """Return (image_id, created_iso) for a locally present image, or ('', '')."""
    try:
        out = subprocess.run(
            [docker, "image", "inspect", image, "--format", "{{.Id}}\t{{.Created}}"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        image_id, _, created = out.partition("\t")
        return image_id.strip(), created.strip()
    except (OSError, subprocess.CalledProcessError):
        return "", ""


def collect_manifest(image: str) -> str:
    """Run the in-container collector against ``image`` and return its stdout."""
    docker = _docker()
    # If the image is not present locally, refuse rather than silently pulling a mutable tag.
    if not _inspect(docker, image)[0]:
        raise SystemExit(
            f"gen_image_sbom: image {image!r} is not present locally. Build it first:\n"
            f"    docker compose --profile strix build strix-sandbox\n"
            f"then re-run this generator. (This tool never pulls a mutable tag to build an SBOM.)"
        )
    proc = subprocess.run(
        [docker, "run", "--rm", "--network", "none", "--entrypoint", "/bin/bash",
         image, "-c", _COLLECTOR],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"gen_image_sbom: collector exited {proc.returncode} for {image!r}")
    return proc.stdout


# --------------------------------------------------------------------------------------
# Manifest -> components
# --------------------------------------------------------------------------------------
def parse_manifest(manifest: str) -> tuple[list[Component], dict[str, str], dict[str, int]]:
    comps: dict[str, Component] = {}
    meta: dict[str, str] = {}
    counts: dict[str, int] = {}

    def add(c: Component, eco: str) -> None:
        if c.bom_ref not in comps:
            comps[c.bom_ref] = c
            counts[eco] = counts.get(eco, 0) + 1

    os_distro = ""
    for raw in manifest.splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        kind = parts[0]
        if kind == "META" and len(parts) >= 3:
            meta[parts[1]] = parts[2]
            if parts[1] == "os-version":
                os_distro = parts[2]
            continue
        if kind == "DEB" and len(parts) >= 4:
            name, version, arch = parts[1], parts[2], parts[3]
            distro = f"kali-{os_distro}" if os_distro else "kali-rolling"
            qs = urllib.parse.urlencode({"arch": arch, "distro": distro})
            add(Component(
                bom_ref=f"deb:{name}@{version}:{arch}", name=name, version=version,
                purl=f"pkg:deb/kali/{urllib.parse.quote(name)}@{urllib.parse.quote(version)}?{qs}",
                props={"ecosystem": "deb"},
            ), "deb")
        elif kind == "PYPI" and len(parts) >= 4:
            location, name, version = parts[1], parts[2], parts[3]
            norm = _norm_pypi(name)
            add(Component(
                bom_ref=f"pypi:{norm}@{version}:{location}", name=name, version=version,
                purl=f"pkg:pypi/{norm}@{urllib.parse.quote(version)}",
                props={"ecosystem": "pypi", "location": location},
            ), "pypi")
        elif kind == "NPMJSON" and len(parts) >= 2:
            try:
                npm_doc = json.loads(base64.b64decode(parts[1]))
            except (ValueError, json.JSONDecodeError):
                continue
            for name, info in (npm_doc.get("dependencies") or {}).items():
                version = (info or {}).get("version", "")
                if not version:
                    continue
                add(Component(
                    bom_ref=f"npm:{name}@{version}", name=name, version=version,
                    purl=f"pkg:npm/{urllib.parse.quote(name)}@{urllib.parse.quote(version)}",
                    props={"ecosystem": "npm"},
                ), "npm")
        elif kind == "GOLANG" and len(parts) >= 4:
            binary, module, version = parts[1], parts[2], parts[3]
            add(Component(
                bom_ref=f"golang:{module}@{version}", name=module, version=version,
                purl=f"pkg:golang/{module}@{urllib.parse.quote(version)}",
                props={"ecosystem": "golang", "binary": binary},
            ), "golang")
        elif kind == "BIN" and len(parts) >= 4:
            name, version, source = parts[1], parts[2], parts[3]
            add(Component(
                bom_ref=f"bin:{name}@{version}", name=name, version=version,
                purl=f"pkg:generic/{urllib.parse.quote(name)}@{urllib.parse.quote(version)}",
                props={"ecosystem": "generic", "install-source": source},
            ), "generic")
        elif kind == "GIT" and len(parts) >= 4:
            name, origin, commit = parts[1], parts[2], parts[3]
            purl, props = _git_purl(name, origin, commit)
            add(Component(bom_ref=f"git:{name}@{commit}", name=name, version=commit,
                          purl=purl, props=props), "git")

    return sorted(comps.values(), key=lambda c: (c.props["ecosystem"], c.name.lower(),
                                                 c.version, c.bom_ref)), meta, counts


def _git_purl(name: str, origin: str, commit: str) -> tuple[str, dict]:
    props = {"ecosystem": "github", "vcs-url": origin}
    m = re.search(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$", origin or "")
    if m:
        owner, repo = m.group(1), m.group(2)
        return f"pkg:github/{owner}/{repo}@{commit}", props
    return f"pkg:generic/{urllib.parse.quote(name)}@{commit}?vcs_url={urllib.parse.quote(origin or '')}", props


# --------------------------------------------------------------------------------------
# SBOM assembly
# --------------------------------------------------------------------------------------
def _timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    dt = (datetime.fromtimestamp(int(epoch), tz=timezone.utc) if epoch
          else datetime.now(timezone.utc))
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_sbom(comps: list[Component], meta: dict[str, str], counts: dict[str, int], *,
               image: str, image_id: str, image_created: str, root: Path = REPO_ROOT,
               timestamp: str) -> dict:
    if len(comps) < MIN_COMPONENTS:
        raise SystemExit(
            f"gen_image_sbom: only {len(comps)} components captured (< {MIN_COMPONENTS}). "
            "The image introspection almost certainly failed part-way — refusing to write a "
            "truncated bill of materials."
        )

    base = base_image_ref(root)
    df_sha = dockerfile_sha256(root)
    os_label = f"{meta.get('os-id', '?')} {meta.get('os-version', '?')}"

    # Deterministic serial from the resolved component set (byte-stable except timestamp).
    digest_src = "\n".join(f"{c.bom_ref}" for c in comps)
    serial = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "vigil-strix-sbom:" + digest_src))

    repo, _, _ = image.partition("@")
    name = repo.split(":", 1)[0]
    version = repo.split(":", 1)[1] if ":" in repo else "latest"

    properties = [
        {"name": f"{_PROP}:sbom-generator", "value": "infra/supply-chain/gen_image_sbom.py"},
        {"name": f"{_PROP}:sbom-target-image", "value": image},
        {"name": f"{_PROP}:base-image", "value": base},
        {"name": f"{_PROP}:dockerfile", "value": DOCKERFILE_REL},
        {"name": f"{_PROP}:dockerfile-sha256", "value": df_sha},
        {"name": f"{_PROP}:os", "value": os_label},
        {"name": f"{_PROP}:component-count", "value": str(len(comps))},
        {"name": f"{_PROP}:generation-method",
         "value": "docker introspection (dpkg/pip/pipx/npm/go/binary-version); resolved from a built image"},
    ]
    if image_id:
        properties.append({"name": f"{_PROP}:image-id", "value": image_id})
    if image_created:
        properties.append({"name": f"{_PROP}:image-created", "value": image_created})
    for eco in sorted(counts):
        properties.append({"name": f"{_PROP}:count-{eco}", "value": str(counts[eco])})

    root_ref = "vigil-strix-sandbox"
    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{SPEC_VERSION}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "OBSIDIAN / VIGIL", "name": GENERATOR_NAME,
                       "version": GENERATOR_VERSION}],
            "component": {
                "type": "container",
                "bom-ref": root_ref,
                "name": name,
                "version": version,
                "description": ("Strix offense-agent sandbox container image "
                                "(vendor/strix/containers/Dockerfile, FROM kalilinux/kali-rolling). "
                                "Components resolved from the built image's own package databases."),
                "purl": f"pkg:oci/{urllib.parse.quote(name, safe='')}",
            },
            "properties": properties,
        },
        "components": [c.as_dict() for c in comps],
        "dependencies": [{"ref": root_ref, "dependsOn": [c.bom_ref for c in comps]}],
        "vulnerabilities": [],
        "compositions": [{
            "aggregate": "incomplete_first_party_only",
            "assemblies": [root_ref],
            "description": ("Installed OS (deb), pip, pipx, npm (depth 0), go and standalone-binary "
                            "components resolved from the built image. npm transitive node_modules and "
                            "any runtime-fetched data (e.g. nuclei templates) are out of scope; see "
                            "docs/SUPPLY-CHAIN.md § 3a."),
        }],
    }


# --------------------------------------------------------------------------------------
# --check — OFFLINE drift guard (mirrors gen_sbom --check)
# --------------------------------------------------------------------------------------
def _prop(doc: dict, key: str) -> str:
    for p in doc.get("metadata", {}).get("properties", []):
        if p.get("name") == f"{_PROP}:{key}":
            return str(p.get("value", ""))
    return ""


def check(sbom_path: Path, root: Path = REPO_ROOT) -> int:
    if not sbom_path.is_file():
        print(f"gen_image_sbom --check FAIL: {sbom_path} does not exist — the Strix sandbox "
              "image SBOM is missing. Generate it with:\n"
              "    python3 infra/supply-chain/gen_image_sbom.py", file=sys.stderr)
        return 1
    try:
        doc = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"gen_image_sbom --check FAIL: {sbom_path} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    problems: list[str] = []

    md = doc.get("metadata", {})
    tool_names = " ".join(t.get("name", "") for t in md.get("tools", [])).lower()
    if SCAFFOLD_SENTINEL in tool_names:
        problems.append("SBOM names a scaffold generator")
    ts = str(md.get("timestamp", ""))
    if ts == ZERO_TIMESTAMP or ts.startswith("0000-"):
        problems.append("SBOM carries the zero/sentinel timestamp")

    comps = doc.get("components", [])
    if len(comps) < MIN_COMPONENTS:
        problems.append(f"only {len(comps)} components (< {MIN_COMPONENTS}) — looks truncated/placeholder")
    for c in comps:
        v = str(c.get("version", ""))
        if not v or any(ch in _RANGE_CHARS for ch in v):
            problems.append(f"component {c.get('name')!r} has a non-resolved version {v!r}")
            break  # one is enough to fail; do not spam

    # Drift: the committed SBOM must be CURRENT with respect to the committed Dockerfile
    # and the STRIX_IMAGE runtime ref. If the Dockerfile changed, the image (and hence the
    # package set) would change, so the SBOM must be regenerated.
    recorded_df = _prop(doc, "dockerfile-sha256")
    actual_df = dockerfile_sha256(root)
    if recorded_df != actual_df:
        problems.append(
            f"dockerfile-sha256 drift: SBOM recorded {recorded_df[:12]}… but "
            f"{DOCKERFILE_REL} now hashes to {actual_df[:12]}…. Rebuild the image and regenerate "
            "the SBOM (python3 infra/supply-chain/gen_image_sbom.py)")

    recorded_base = _prop(doc, "base-image")
    actual_base = base_image_ref(root)
    if recorded_base != actual_base:
        problems.append(f"base-image drift: SBOM recorded {recorded_base!r} but the Dockerfile "
                        f"FROM is now {actual_base!r}")

    recorded_img = _prop(doc, "sbom-target-image")
    actual_img = runtime_image_ref(root)
    if actual_img and recorded_img != actual_img:
        problems.append(f"runtime-image drift: SBOM is for {recorded_img!r} but the STRIX_IMAGE "
                        f"default is now {actual_img!r}")

    if problems:
        for p in problems:
            print(f"gen_image_sbom --check FAIL: {p}", file=sys.stderr)
        return 1
    print(f"gen_image_sbom --check OK: {len(comps)} components; SBOM is current with "
          f"{DOCKERFILE_REL} and the STRIX_IMAGE runtime ref.")
    return 0


# --------------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from-image", default=None,
                    help="image ref to introspect (default: the STRIX_IMAGE runtime default, "
                         f"else {DEFAULT_IMAGE})")
    ap.add_argument("-o", "--output", type=Path, default=DEFAULT_SBOM,
                    help="where to write the SBOM (default: infra/supply-chain/sbom-strix-sandbox.cdx.json)")
    ap.add_argument("--check", action="store_true",
                    help="OFFLINE: do not write; exit 1 if the committed SBOM is missing, a "
                         "placeholder, or stale relative to the Dockerfile / STRIX_IMAGE ref")
    args = ap.parse_args(argv)

    if args.check:
        return check(args.output)

    image = args.from_image or runtime_image_ref() or DEFAULT_IMAGE
    docker = _docker()
    image_id, image_created = _inspect(docker, image)
    manifest = collect_manifest(image)
    comps, meta, counts = parse_manifest(manifest)
    doc = build_sbom(comps, meta, counts, image=image, image_id=image_id,
                     image_created=image_created, timestamp=_timestamp())
    args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    per_eco = ", ".join(f"{k}={counts[k]}" for k in sorted(counts))
    print(f"gen_image_sbom: wrote {args.output} ({len(comps)} components from {image}) [{per_eco}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
