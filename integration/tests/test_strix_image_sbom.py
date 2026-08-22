"""The Strix sandbox CONTAINER image must have a real, current SBOM.

WHAT THIS GUARDS (S5 / Part III). The A14 gate produces DEPENDENCY SBOMs (the Python
closure of each env, from the hash-locks). It had none for the container the offense
agent runs targets in — ``vigil/strix-sandbox:local``, built from
``vendor/strix/containers/Dockerfile`` (~1000 Debian packages + a Go/npm/pip/pipx/binary
toolchain). ``infra/supply-chain/gen_image_sbom.py`` introspects the BUILT image and
emits ``infra/supply-chain/sbom-strix-sandbox.cdx.json`` (CycloneDX 1.5); its
``--check`` mode is an OFFLINE drift guard, and this test is that guard's caller of
record in a required job.

Every ``test_*`` asserts the committed SBOM is real and current; the ``*_actually_fires``
tests are the negative controls — they hand the guard a KNOWN-BAD document and assert it
FAILS, so a future edit cannot make these pass by weakening the guard into one that flags
nothing (the lesson from test_gen_sbom.py).

Pure stdlib + pytest. The generator it exercises imports only the standard library, and
``--check`` needs no docker — so this whole file runs on a network-free, docker-free runner
(the ``integration two-env boundary (P5)`` job). A live regeneration test that DOES need
docker is opt-in via ``VIGIL_STRIX_SBOM_DOCKER_IT=1``.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "infra" / "supply-chain" / "gen_image_sbom.py"
SBOM_PATH = REPO_ROOT / "infra" / "supply-chain" / "sbom-strix-sandbox.cdx.json"
DOCKERFILE = REPO_ROOT / "vendor" / "strix" / "containers" / "Dockerfile"


def _load_gen():
    """Load gen_image_sbom.py by path (stdlib-only, like test_supply_chain loads image_pins)."""
    assert GEN_PATH.is_file(), f"missing {GEN_PATH} — the image-SBOM generator is the source of truth"
    spec = importlib.util.spec_from_file_location("vigil_gen_image_sbom", GEN_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def gen():
    return _load_gen()


@pytest.fixture(scope="module")
def sbom():
    assert SBOM_PATH.is_file(), (
        f"the Strix sandbox image SBOM is missing: {SBOM_PATH}. Generate it with "
        "`python3 infra/supply-chain/gen_image_sbom.py`."
    )
    return json.loads(SBOM_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------
# 1. The artifact exists and is a real CycloneDX bill of materials.
# ---------------------------------------------------------------------------------------
def test_sbom_is_committed_and_is_cyclonedx(sbom) -> None:
    assert sbom.get("bomFormat") == "CycloneDX"
    assert sbom.get("specVersion") == "1.5"
    assert sbom.get("serialNumber", "").startswith("urn:uuid:")
    root = sbom.get("metadata", {}).get("component", {})
    assert root.get("type") == "container"


def test_sbom_is_not_a_placeholder(gen, sbom) -> None:
    md = sbom.get("metadata", {})
    tools = " ".join(t.get("name", "") for t in md.get("tools", [])).lower()
    assert gen.SCAFFOLD_SENTINEL not in tools, "SBOM names a scaffold generator"
    ts = str(md.get("timestamp", ""))
    assert ts and ts != gen.ZERO_TIMESTAMP and not ts.startswith("0000-"), "zero/sentinel timestamp"


def test_sbom_has_the_full_image_toolchain(gen, sbom) -> None:
    comps = sbom.get("components", [])
    assert len(comps) >= gen.MIN_COMPONENTS, f"only {len(comps)} components — looks truncated"
    ecos = {
        p["value"]
        for c in comps
        for p in c.get("properties", [])
        if p.get("name") == "vigil:ecosystem"
    }
    # The image is multi-ecosystem; a capture that dropped a whole package manager is a defect.
    for expected in {"deb", "pypi", "npm", "golang", "generic", "github"}:
        assert expected in ecos, f"no {expected} components in the image SBOM (capture incomplete?)"


def test_every_component_carries_a_resolved_version(gen, sbom) -> None:
    """A container SBOM must pin, not carry ranges (the test_gen_sbom.py invariant)."""
    for c in sbom.get("components", []):
        v = str(c.get("version", ""))
        assert v, f"{c.get('name')!r} has no version"
        assert not (set(v) & gen._RANGE_CHARS), f"{c.get('name')!r} has a non-resolved version {v!r}"
        assert c.get("purl"), f"{c.get('name')!r} has no purl"


def test_sbom_binds_to_the_dockerfile_and_runtime_image(gen, sbom) -> None:
    """The SBOM records the exact source it was generated for, so drift is detectable offline."""
    props = {p["name"]: p["value"] for p in sbom.get("metadata", {}).get("properties", [])}
    assert props.get("vigil:dockerfile") == "vendor/strix/containers/Dockerfile"
    assert props.get("vigil:dockerfile-sha256") == gen.dockerfile_sha256(REPO_ROOT)
    assert props.get("vigil:base-image") == gen.base_image_ref(REPO_ROOT)
    # The SBOM is for the image the agent actually launches (STRIX_IMAGE default).
    assert props.get("vigil:sbom-target-image") == gen.runtime_image_ref(REPO_ROOT)


# ---------------------------------------------------------------------------------------
# 2. The offline drift guard PASSES on the committed tree.
# ---------------------------------------------------------------------------------------
def test_check_passes_on_the_committed_sbom(gen) -> None:
    assert gen.check(SBOM_PATH, REPO_ROOT) == 0


# ---------------------------------------------------------------------------------------
# 3. Negative controls — the guard must FAIL on a bad SBOM, or it proves nothing.
# ---------------------------------------------------------------------------------------
def test_check_fires_on_a_missing_sbom(gen, tmp_path) -> None:
    assert gen.check(tmp_path / "absent.cdx.json", REPO_ROOT) == 1


def test_check_fires_on_dockerfile_drift(gen, tmp_path) -> None:
    doc = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    for p in doc["metadata"]["properties"]:
        if p["name"] == "vigil:dockerfile-sha256":
            p["value"] = "0" * 64  # simulate: Dockerfile changed, SBOM was not regenerated
    bad = tmp_path / "drift.cdx.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    assert gen.check(bad, REPO_ROOT) == 1


def test_check_fires_on_base_image_drift(gen, tmp_path) -> None:
    doc = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    for p in doc["metadata"]["properties"]:
        if p["name"] == "vigil:base-image":
            p["value"] = "kalilinux/kali-rolling:latest@sha256:" + "d" * 64
    bad = tmp_path / "base-drift.cdx.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    assert gen.check(bad, REPO_ROOT) == 1


def test_check_fires_on_a_placeholder(gen, tmp_path) -> None:
    doc = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    doc["components"] = doc["components"][:3]
    doc["metadata"]["timestamp"] = "0000-00-00T00:00:00Z"
    bad = tmp_path / "placeholder.cdx.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    assert gen.check(bad, REPO_ROOT) == 1


# ---------------------------------------------------------------------------------------
# 4. LIVE regeneration — opt-in (needs docker + the built image present).
# ---------------------------------------------------------------------------------------
@pytest.mark.skipif(
    os.environ.get("VIGIL_STRIX_SBOM_DOCKER_IT") != "1",
    reason="set VIGIL_STRIX_SBOM_DOCKER_IT=1 to introspect the live image (needs docker + built image)",
)
def test_regenerating_from_the_image_matches_the_committed_component_set(gen) -> None:
    image = gen.runtime_image_ref(REPO_ROOT) or gen.DEFAULT_IMAGE
    manifest = gen.collect_manifest(image)
    comps, meta, counts = gen.parse_manifest(manifest)
    fresh = {(c.name, c.version) for c in comps}
    committed = {(c["name"], c["version"]) for c in json.loads(SBOM_PATH.read_text())["components"]}
    assert fresh == committed, (
        "the live image no longer matches the committed SBOM — regenerate it with "
        "`python3 infra/supply-chain/gen_image_sbom.py`"
    )
