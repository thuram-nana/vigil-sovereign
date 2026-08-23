#!/usr/bin/env python3
"""sbom_crosscheck.py — does a CycloneDX SBOM actually describe the shipped closure? (W3-5 #428)

A signed SBOM is only worth signing if it is COMPLETE: a signature over a bill of materials that
silently omits a shipped component is a confident-looking lie. The A14 gate already cross-checks
each per-run SBOM against its lock at *generation* time (``bin/verify-supply-chain.sh`` step 3).
This module is the SAME set-difference check, factored into a stdlib-only unit so it can also run
against the SBOM bytes that are actually ATTACHED TO A RELEASE — after generation, after signing —
and so the behaviour is unit-testable with a real negative control.

The check is one direction and one direction only: **every component the lock pins must appear in
the SBOM**. An SBOM that omits a shipped component FAILS. (Extra components in the SBOM — e.g. the
root application component cyclonedx-py adds — are not a defect and are reported separately, never
fatal.) Normalisation is PEP 503 on both sides, so ``ruamel.yaml`` and ``ruamel-yaml`` are the same
component.

Why a second copy of the set-difference rather than importing the gate's? ``verify-supply-chain.sh``
lives in ``engine/crucible`` (the offense subtree, which must not grow a dependency on the
surrounding monorepo) and embeds its check in bash+python; this module lives in ``infra/`` and is
stdlib-only by the same rule ``image_pins.py`` follows. The two implement the identical set
difference; the release verifier re-runs THIS check against the SBOM the gate generated, so a
divergence between the two would surface there.

Stdlib only — it runs in any job (and in the offline release verifier) without adding a dependency
to the thing it audits.

Usage::

    python3 infra/supply-chain/sbom_crosscheck.py --lock <lock.txt> --sbom <sbom.cdx.json>
    #   exit 0  iff every locked component is present in the SBOM
    #   exit 1  if any locked component is MISSING (an incomplete bill of materials)
    #   exit 2  on a usage / IO / parse error (fail-closed: a check that cannot run is not a pass)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Matches a pip-compile lock record head: ``name==version`` (the version stops at whitespace, a
# line-continuation backslash, or an environment marker ``;``). Identical in intent to the regex in
# gen_sbom.py / verify-supply-chain.sh.
_LOCK_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)")


def _norm(name: str) -> str:
    """PEP 503 name normalisation: lower-case, runs of -/_/. collapse to a single -."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def locked_components(lock_text: str) -> set[tuple[str, str]]:
    """The (normalised-name, version) set a pip-compile ``--generate-hashes`` lock pins."""
    out: set[tuple[str, str]] = set()
    for line in lock_text.splitlines():
        m = _LOCK_LINE.match(line)
        if m:
            out.add((_norm(m.group(1)), m.group(2)))
    return out


def sbom_components(doc: dict) -> set[tuple[str, str]]:
    """The (normalised-name, version) set a CycloneDX document declares under ``components``."""
    return {
        (_norm(c.get("name", "")), c.get("version", ""))
        for c in doc.get("components", [])
        if c.get("name")
    }


def missing_components(lock_text: str, sbom_doc: dict) -> list[tuple[str, str]]:
    """Locked components that DO NOT appear in the SBOM — the omissions that must fail the check.

    A non-empty return means the SBOM is an incomplete bill of materials for the locked closure:
    something the lock ships is absent from the SBOM. This is the exact condition the release gate
    (and its negative control) turns on. Returned sorted for a stable report.
    """
    locked = locked_components(lock_text)
    if not locked:
        # An empty lock cannot be cross-checked; refusing here keeps a parse failure from reading
        # as "nothing missing, all good" (fail-closed). Callers surface this as a usage error.
        raise ValueError("the lock parsed to zero pinned components — refusing a vacuous pass")
    present = sbom_components(sbom_doc)
    return sorted(locked - present)


def extra_components(lock_text: str, sbom_doc: dict) -> list[tuple[str, str]]:
    """SBOM components not in the lock — reported, never fatal (e.g. the root app component)."""
    return sorted(sbom_components(sbom_doc) - locked_components(lock_text))


def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"{path} is not a JSON object")
    return doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Cross-check a CycloneDX SBOM against a hash-pinned lock (W3-5 #428).",
    )
    ap.add_argument("--lock", type=Path, required=True,
                    help="path to a pip-compile --generate-hashes lock file")
    ap.add_argument("--sbom", type=Path, required=True,
                    help="path to a CycloneDX SBOM (JSON)")
    args = ap.parse_args(argv)

    if not args.lock.is_file():
        print(f"sbom_crosscheck: lock not found: {args.lock}", file=sys.stderr)
        return 2
    if not args.sbom.is_file():
        print(f"sbom_crosscheck: SBOM not found: {args.sbom}", file=sys.stderr)
        return 2
    try:
        lock_text = args.lock.read_text(encoding="utf-8")
        sbom_doc = _load_json(args.sbom)
        missing = missing_components(lock_text, sbom_doc)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"sbom_crosscheck: cannot cross-check: {e}", file=sys.stderr)
        return 2

    n_locked = len(locked_components(lock_text))
    if missing:
        print(f"sbom_crosscheck FAIL: {len(missing)} locked component(s) are MISSING from "
              f"{args.sbom.name} (the released SBOM is an incomplete bill of materials):",
              file=sys.stderr)
        for name, ver in missing:
            print(f"  missing: {name}=={ver}", file=sys.stderr)
        return 1

    extra = extra_components(lock_text, sbom_doc)
    print(f"sbom_crosscheck OK: all {n_locked} locked component(s) are present in "
          f"{args.sbom.name}"
          + (f" ({len(extra)} extra non-lock component(s) reported, not fatal)" if extra else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
