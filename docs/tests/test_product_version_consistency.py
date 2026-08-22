"""One product version, asserted consistent across every first-party package. (W4-1 #441)

WHY THIS TEST EXISTS. VIGIL shipped six uncoordinated version numbers — vigil-core 0.1.0,
vigil-integration 0.1.0, vigil-gateway 0.1.0, crucible 2.0.0a1, sigil 0.9.0 and the WARDEN
Rust kernel 0.9.0 — while the repo root declared none at all. There was no single fact that
said "this is the version of the product", so nothing could stop one package drifting away
from the rest, and a release could not name a coherent number. W4-1 introduces ONE product
version at the repo root (the `VERSION` file) and this test is the pin that keeps every
first-party package's DECLARED version equal to it, OFFLINE, on every pull request.

It rides the already-required "the briefing explains every agent and capability" job
(`pytest docs/tests -q`), which installs only pytest and reads files only, so this test imports
nothing beyond the standard library (`tomllib` is stdlib on the 3.13 CI runner).

WHAT IT PROVES (all offline — it never touches the network):

  (a) The product version exists exactly once, at the repo root `VERSION` file, and is a
      non-empty single line.
  (b) Every FIRST-PARTY package's declared version equals the product version. The declared
      version is read from the authoritative place for each package: the `[project].version`
      of its pyproject for the packaged Python distributions, the `__version__` attribute for
      the packages whose pyproject derives the version dynamically or that carry a runtime
      marker, and `[package].version` of Cargo.toml for the WARDEN Rust kernel.
  (c) The third-party VENDORED package `vendor/strix` (strix-agent) is DELIBERATELY EXCLUDED
      and keeps its own upstream version — a vendored dependency's version is upstream's fact,
      not the product's, and rewriting it would erase attribution. This test asserts strix is
      not swept into the product-version set.

NEGATIVE CONTROL. The comparison is a pure function, `mismatched_versions(product, declared)`,
that takes its data as arguments precisely so the perturbation can be exercised in-process, not
merely described. `test_negative_control_*` feed it a deliberately-wrong declared-version map
(one package bumped without the product version) and assert it REPORTS the divergence; the
"aligned" companion asserts it reports NONE when everything matches. If you want to see the real
thing bite by hand: change `version = "0.1.0"` to `version = "0.1.1"` in
`packages/core/vigil_core/pyproject.toml` WITHOUT editing `VERSION` ->
`test_all_first_party_versions_match_product` fails.

WHAT THIS TEST DOES NOT CLAIM. It does not force the package versions to be DERIVED from the
root at build time (a heavier, per-backend change); it asserts they are CONSISTENT with it,
which is the branch W4-1 explicitly allows. It does not police the vendored strix version.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
VERSION_FILE = REPO / "VERSION"


# --- pure helpers (data in as arguments, so the negative control runs in-process) -----------


def mismatched_versions(product: str, declared: dict[str, str]) -> dict[str, str]:
    """Return the subset of ``declared`` whose version != ``product``. Empty == consistent."""
    return {name: ver for name, ver in declared.items() if ver != product}


def _pyproject_project_version(path: Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data["project"]["version"]


def _dunder_version(path: Path) -> str:
    m = re.search(
        r"""^__version__\s*=\s*["']([^"']+)["']""",
        path.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not m:
        raise AssertionError(f"no __version__ assignment found in {path}")
    return m.group(1)


def _cargo_package_version(path: Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data["package"]["version"]


# --- the authoritative version-declaration sites of every FIRST-PARTY package ---------------
#
# Each entry maps a human label -> (repo-relative path, extractor). A package appears here ONCE,
# at the single place that is authoritative for its version. vendor/strix (strix-agent) is
# ABSENT on purpose: it is third-party vendored code that keeps its upstream version — see the
# module docstring and test_vendored_strix_is_excluded.
FIRST_PARTY_VERSION_SITES: dict[str, tuple[str, str]] = {
    # Packaged Python distributions — [project].version of their pyproject.
    "vigil-core": ("packages/core/vigil_core/pyproject.toml", "pyproject"),
    "vigil-gateway": ("gateway/pyproject.toml", "pyproject"),
    "vigil-integration": ("integration/pyproject.toml", "pyproject"),
    "crucible": ("engine/crucible/pyproject.toml", "pyproject"),
    "crucible-v2": ("engine/crucible/framework/v2/pyproject.toml", "pyproject"),
    # crucible-v2 also carries a runtime __version__ marker that must not drift from its pyproject.
    "crucible-v2 (__version__)": ("engine/crucible/framework/v2/__init__.py", "dunder"),
    # sigil's pyproject derives its version dynamically from this attribute, so the attribute IS
    # the authoritative declaration.
    "sigil": ("apps/sigil/sigil/__init__.py", "dunder"),
    # WARDEN Rust kernel — [package].version of its Cargo.toml.
    "sigil-kernel (WARDEN)": ("apps/sigil/kernel/Cargo.toml", "cargo"),
}

_EXTRACTORS = {
    "pyproject": _pyproject_project_version,
    "dunder": _dunder_version,
    "cargo": _cargo_package_version,
}


def read_declared_versions() -> dict[str, str]:
    """Read every first-party package's declared version from its authoritative file."""
    out: dict[str, str] = {}
    for label, (rel, kind) in FIRST_PARTY_VERSION_SITES.items():
        path = REPO / rel
        assert path.exists(), f"{label}: expected version file missing: {rel}"
        out[label] = _EXTRACTORS[kind](path)
    return out


def read_product_version() -> str:
    assert VERSION_FILE.exists(), (
        "the single product version is missing: create a VERSION file at the repo root (W4-1)"
    )
    raw = VERSION_FILE.read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    assert len(lines) == 1, (
        f"VERSION must be exactly one non-empty line; found {len(lines)}: {lines!r}"
    )
    return lines[0].strip()


# --- the real-tree assertions ---------------------------------------------------------------


def test_product_version_exists_and_is_wellformed():
    version = read_product_version()
    assert version, "product version is empty"
    # PEP 440-ish: digits, dots, and optional pre/dev/post suffix — kept loose on purpose.
    assert re.fullmatch(r"[0-9]+(\.[0-9]+)*([abrc]|rc|\.dev|\.post)?[0-9]*", version), (
        f"product version {version!r} is not a recognizable release version"
    )


def test_all_first_party_versions_match_product():
    product = read_product_version()
    declared = read_declared_versions()
    bad = mismatched_versions(product, declared)
    assert not bad, (
        f"package versions disagree with the product version {product!r} (VERSION file): {bad}. "
        "Bump every listed package to the product version, or bump VERSION to match."
    )


def test_vendored_strix_is_excluded():
    # The vendored third-party package must NOT be in the product-version set...
    assert not any("strix" in label for label in FIRST_PARTY_VERSION_SITES), (
        "vendor/strix is third-party vendored code and must keep its upstream version; "
        "it must not be swept into the product-version consistency set"
    )
    # ...and it must still exist and carry its own (independent) version.
    strix_pyproject = REPO / "vendor" / "strix" / "pyproject.toml"
    assert strix_pyproject.exists()
    strix_version = _pyproject_project_version(strix_pyproject)
    assert strix_version, "vendored strix should still declare its upstream version"


# --- negative controls (in-process; prove the gate is not a no-op) --------------------------


def test_negative_control_bumped_package_is_reported():
    """A single package bumped without the product version must be REPORTED as a mismatch."""
    product = "0.1.0"
    declared = {
        "vigil-core": "0.1.0",
        "vigil-gateway": "0.1.0",
        "crucible": "0.1.0",
        # someone bumped just this one, forgetting the product version:
        "sigil": "0.1.1",
    }
    bad = mismatched_versions(product, declared)
    assert bad == {"sigil": "0.1.1"}, bad


def test_negative_control_aligned_map_reports_nothing():
    product = "0.1.0"
    declared = {name: "0.1.0" for name in ("vigil-core", "gateway", "crucible", "sigil")}
    assert mismatched_versions(product, declared) == {}


def test_negative_control_multiple_drifts_all_reported():
    product = "1.0.0"
    declared = {"a": "1.0.0", "b": "2.0.0a1", "c": "0.9.0", "d": "1.0.0"}
    assert mismatched_versions(product, declared) == {"b": "2.0.0a1", "c": "0.9.0"}
