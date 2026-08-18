#!/usr/bin/env python3
"""gen_sbom.py — regenerate ``framework/v2/sbom.json`` as a REAL CycloneDX 1.5 SBOM.

For most of this repo's history ``framework/v2/sbom.json`` was a hand-written
*scaffold*: its ``metadata.tools[0].name`` read ``"scaffold (operator regenerates
with cyclonedx-bom)"`` and its ``metadata.timestamp`` was the sentinel
``"0000-00-00T00:00:00Z"``.  Its component versions were the *ranges* from
``requirements.in`` (``pydantic>=2.10,<3``), not the *resolved pins* from the lock.
It was, in other words, a placeholder that claimed to be a bill of materials.

This script produces the real thing, with **stdlib only** — no ``pip``, no
``cyclonedx-bom``.  It reads the hash-pinned lock
(``framework/v2/requirements.lock.txt``), which is the fully-resolved, byte-stable
source of truth verified by ``bin/verify-supply-chain.sh``, and emits a valid
CycloneDX 1.5 JSON document with:

  * every resolved component at its **pinned version** (``pydantic==2.13.4``),
  * the SHA-256 file digests the lock pins for each component,
  * a ``pkg:pypi/<name>@<version>`` purl per component,
  * a real generation ``timestamp`` (overridable via ``SOURCE_DATE_EPOCH`` for
    reproducible builds),
  * ``direct`` vs ``transitive`` provenance and ``required`` vs ``optional``
    (test-only) scope, both DERIVED from the lock's own ``# via`` annotations —
    not asserted by hand,
  * the dependency graph, again from ``# via``.

Why a bespoke generator rather than only the documented ``cyclonedx-py``
(``SECURITY.md`` § 2.2)?  ``cyclonedx-py`` is a build-time tool deliberately kept
out of ``requirements.in`` (it would expand the deployed runtime attack surface),
so it is not guaranteed present on every host.  A sovereign engine must be able to
regenerate its own SBOM with nothing but the interpreter it already ships.  Both
paths read the same lock and agree on the component *set*; ``bin/verify-supply-
chain.sh`` remains the drift gate over the lock itself.

Usage (from ``engine/crucible``)::

    python3 -m framework.v2.tools.gen_sbom            # rewrite framework/v2/sbom.json
    python3 framework/v2/tools/gen_sbom.py            # same, run as a script
    python3 -m framework.v2.tools.gen_sbom --check    # exit 1 if committed sbom.json
                                                      #   drifts from the lock (no write)
    python3 -m framework.v2.tools.gen_sbom -o out.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ``requirements.lock.txt`` / ``requirements.in`` / ``sbom.json`` all live in
# framework/v2/, i.e. the parent of this tools/ package. Resolve relative to this
# file so the script works from any CWD and as either ``-m`` or a bare path.
V2_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LOCK = V2_DIR / "requirements.lock.txt"
DEFAULT_SBOM = V2_DIR / "sbom.json"

GENERATOR_NAME = "gen_sbom.py"
GENERATOR_VERSION = "1.0.0"
SCAFFOLD_SENTINEL = "scaffold"  # the token the old placeholder carried in tools[].name
ZERO_TIMESTAMP = "0000-00-00T00:00:00Z"

# The one direct dependency in requirements.in that is TEST-ONLY (its § comment there
# reads "Test-only: HttpExecutor unit tests ... Sovereign-strict CI omits this entry
# from the runtime install"). requirements.in has no machine-readable runtime/test
# split, so the single test-only root is named here; everything *reachable only
# through it* is then computed as optional below, so werkzeug (pulled in solely by
# pytest-httpserver) is optional while markupsafe (also via jinja2) stays required.
# If a future test-only direct dep is added to requirements.in, add its normalized
# name here.
TEST_ONLY_DIRECT = frozenset({"pytest-httpserver"})


def _norm(name: str) -> str:
    """PEP 503 name normalization (lower-case, runs of -/_/. collapse to a single -)."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


class Component:
    __slots__ = ("name", "version", "hashes", "via", "direct")

    def __init__(self, name: str, version: str) -> None:
        self.name = name
        self.version = version
        self.hashes: list[str] = []
        self.via: list[str] = []
        self.direct = False

    @property
    def norm(self) -> str:
        return _norm(self.name)


def parse_lock(text: str) -> list[Component]:
    """Parse a ``pip-compile --generate-hashes`` lock into resolved components.

    Records look like::

        pydantic==2.13.4 \\
            --hash=sha256:<64hex> \\
            --hash=sha256:<64hex>
            # via -r framework/v2/requirements.in

    with ``# via`` either inline (``# via httpx``) or a block::

            # via
            #   httpcore
            #   httpx
    """
    comps: list[Component] = []
    cur: Component | None = None
    in_via = False
    start_re = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)")
    hash_re = re.compile(r"--hash=sha256:([0-9a-f]{64})")

    for raw in text.splitlines():
        m = start_re.match(raw)
        if m:
            cur = Component(m.group(1), m.group(2))
            comps.append(cur)
            in_via = False
            continue
        if cur is None:
            continue
        h = hash_re.search(raw)
        if h:
            cur.hashes.append(h.group(1))
            in_via = False
            continue
        stripped = raw.strip()
        if stripped.startswith("# via"):
            rest = stripped[len("# via"):].strip()
            if rest:
                cur.via.append(rest)
            in_via = True
            continue
        if in_via and stripped.startswith("#"):
            token = stripped.lstrip("#").strip()
            if token:
                cur.via.append(token)
            continue
        in_via = False

    for c in comps:
        c.direct = any(v.startswith("-r ") or v.startswith("-c ") for v in c.via)
    return comps


def _forward_graph(comps: list[Component]) -> dict[str, set[str]]:
    """parent-name -> {child-name}, built from each component's ``# via`` parents."""
    fwd: dict[str, set[str]] = {}
    for c in comps:
        child = c.norm
        for v in c.via:
            if v.startswith("-r ") or v.startswith("-c "):
                continue  # this is the input file, not a package parent
            fwd.setdefault(_norm(v), set()).add(child)
    return fwd


def _required_norms(comps: list[Component]) -> set[str]:
    """Names reachable from a NON-test-only direct dependency = runtime-required.

    A component is optional (test-only) exactly when every path to a direct
    dependency runs solely through a TEST_ONLY_DIRECT root.
    """
    fwd = _forward_graph(comps)
    roots = {c.norm for c in comps if c.direct and c.norm not in TEST_ONLY_DIRECT}
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(fwd.get(n, ()))
    return seen


def build_sbom(lock_text: str, *, timestamp: str) -> dict:
    comps = parse_lock(lock_text)
    if not comps:
        raise SystemExit("gen_sbom: the lock parsed to zero components — refusing to "
                         "emit an empty SBOM (is requirements.lock.txt a real lock?)")
    comps.sort(key=lambda c: c.norm)
    required = _required_norms(comps)
    fwd = _forward_graph(comps)

    components = []
    for c in comps:
        entry = {
            "type": "library",
            "bom-ref": c.norm,
            "name": c.name,
            "version": c.version,
            "purl": f"pkg:pypi/{c.norm}@{c.version}",
            "scope": "required" if c.norm in required else "optional",
        }
        if c.hashes:
            entry["hashes"] = [{"alg": "SHA-256", "content": h} for h in c.hashes]
        entry["properties"] = [
            {"name": "crucible:dependency", "value": "direct" if c.direct else "transitive"}
        ]
        components.append(entry)

    root_ref = "crucible-v2"
    direct_norms = sorted(c.norm for c in comps if c.direct)
    dependencies = [{"ref": root_ref, "dependsOn": direct_norms}]
    for c in comps:
        dependencies.append({
            "ref": c.norm,
            "dependsOn": sorted(fwd.get(c.norm, set())),
        })

    # Deterministic serial number from the resolved (name, version) set so re-runs are
    # byte-stable except for the intended timestamp.
    digest_src = "\n".join(f"{c.norm}=={c.version}" for c in comps)
    serial = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "crucible-sbom:" + digest_src))

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "OBSIDIAN / CRUCIBLE",
                    "name": GENERATOR_NAME,
                    "version": GENERATOR_VERSION,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "CRUCIBLE",
                "version": "v2",
                "description": ("Sovereign-grade offensive security framework "
                                "(framework/v2). Runtime + test dependencies resolved "
                                "and hash-pinned in framework/v2/requirements.lock.txt."),
                "purl": "pkg:generic/crucible@v2",
            },
            "properties": [
                {"name": "crucible:sbom-generator",
                 "value": "framework/v2/tools/gen_sbom.py"},
                {"name": "crucible:sbom-source",
                 "value": "framework/v2/requirements.lock.txt"},
                {"name": "crucible:component-count", "value": str(len(comps))},
            ],
        },
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": [],
        "compositions": [
            {
                "aggregate": "complete",
                "assemblies": [root_ref],
                "description": ("Direct + transitive runtime and test dependencies, "
                                "fully resolved and hash-pinned in "
                                "framework/v2/requirements.lock.txt. Regenerate with "
                                "framework/v2/tools/gen_sbom.py."),
            }
        ],
    }


def _timestamp() -> str:
    """Real generation time, or SOURCE_DATE_EPOCH (reproducible-builds convention)."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _component_key_set(doc: dict) -> set[tuple[str, str]]:
    return {
        (_norm(c.get("name", "")), c.get("version", ""))
        for c in doc.get("components", [])
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lock", type=Path, default=DEFAULT_LOCK,
                    help="path to requirements.lock.txt (default: framework/v2/)")
    ap.add_argument("-o", "--output", type=Path, default=DEFAULT_SBOM,
                    help="where to write the SBOM (default: framework/v2/sbom.json)")
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if the committed SBOM's component set "
                         "drifts from the lock, or if it still carries the scaffold "
                         "sentinel / zero timestamp")
    args = ap.parse_args(argv)

    if not args.lock.is_file():
        print(f"gen_sbom: lock not found: {args.lock}", file=sys.stderr)
        return 3
    lock_text = args.lock.read_text(encoding="utf-8")

    if args.check:
        fresh = build_sbom(lock_text, timestamp=ZERO_TIMESTAMP)
        if not args.output.is_file():
            print(f"gen_sbom --check: {args.output} does not exist", file=sys.stderr)
            return 1
        committed = json.loads(args.output.read_text(encoding="utf-8"))
        tool_names = " ".join(t.get("name", "") for t in
                              committed.get("metadata", {}).get("tools", []))
        ts = committed.get("metadata", {}).get("timestamp", "")
        problems: list[str] = []
        if SCAFFOLD_SENTINEL in tool_names.lower():
            problems.append("committed SBOM still names a scaffold generator")
        if ts == ZERO_TIMESTAMP or ts.startswith("0000-"):
            problems.append("committed SBOM still carries the zero/sentinel timestamp")
        drift = _component_key_set(fresh) ^ _component_key_set(committed)
        if drift:
            problems.append("component set drifts from the lock: "
                            + ", ".join(f"{n}=={v}" for n, v in sorted(drift)))
        if problems:
            for p in problems:
                print(f"gen_sbom --check FAIL: {p}", file=sys.stderr)
            return 1
        print(f"gen_sbom --check OK: {len(committed.get('components', []))} components "
              "agree with the lock")
        return 0

    doc = build_sbom(lock_text, timestamp=_timestamp())
    args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(f"gen_sbom: wrote {args.output} "
          f"({len(doc['components'])} components from {args.lock.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
