"""A14 — supply-chain / packaging hardening, asserted STATICALLY (no network, no daemon).

These are the checks that must hold on every commit whether or not a runner has egress, so
they live here and are collected by the ordinary `pytest integration/tests` run as well as by
the dedicated "A14 supply-chain gate" job. Everything that genuinely needs the network
(resolving digests, compiling locks, fetching a vulnerability DB) happens in that job; what is
proven here is that the RESULT of that work is committed, complete and cannot silently rot:

  * every container base image in the repo is digest-pinned (a tag is a mutable pointer);
  * every committed dependency lock is genuinely hash-pinned and covers its own input;
  * the A14 workflow still declares the SBOM step, the artifact upload and a BLOCKING scan;
  * every third-party action in EVERY workflow is SHA-pinned (W3-3, #426), not a mutable tag;
  * every vulnerability suppression carries a written justification.

The last one is the point of the whole exercise. A scan gate is only worth having if a
suppression costs someone a sentence of explanation; `.trivyignore` entries with no reason are
how a gate quietly becomes a no-op.

Pure stdlib + pytest, so this file adds nothing to the dependency surface it audits.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "supply-chain.yml"
TRIVYIGNORE = REPO_ROOT / ".trivyignore"

#: vendor/strix's live-scan extras are NOT in the offense framework lock; they have a DEDICATED
#: hash-pinned lock (exported from the committed vendor/strix/uv.lock) so `envs/build_envs.sh` can
#: install them under `--require-hashes` instead of resolving them fresh from PyPI on every operator
#: install — the largest unlocked surface in the product, co-loaded with the offense engine ([W3-6]).
STRIX_LOCK = REPO_ROOT / "infra/supply-chain/strix.lock"
STRIX_PYPROJECT = REPO_ROOT / "vendor/strix/pyproject.toml"
BUILD_ENVS = REPO_ROOT / "envs" / "build_envs.sh"

#: Every committed hash-pinned lock, and the pip-compile input it is generated from.
#: Two locks, not one: the sovereign/offense split (FATAL-2) means the two environments must
#: never share an interpreter, so they cannot share a resolution either.
LOCKS: dict[str, tuple[Path, Path]] = {
    "offense": (
        REPO_ROOT / "engine/crucible/framework/v2/requirements.in",
        REPO_ROOT / "engine/crucible/framework/v2/requirements.lock.txt",
    ),
    "sovereign": (
        REPO_ROOT / "infra/supply-chain/sovereign.in",
        REPO_ROOT / "infra/supply-chain/sovereign.lock.txt",
    ),
    # W3-2: the CI/test TOOLCHAIN (pytest + async plugin + ruff + mypy). Not a RUNTIME lock — it
    # pins the harness CI runs, which is deliberately kept out of both runtime locks (it would drag
    # test tooling into a shipped deployment). It is hash-locked, drift-checked and require-hashes
    # installed exactly like the runtime locks, so it earns the same existence/hash/coverage checks
    # here. `RUNTIME_LOCKS` below deliberately EXCLUDES it — the "tested tree == locked tree"
    # floor/require-hashes gates apply to the runtime tree, not to the harness itself.
    "ci-tooling": (
        REPO_ROOT / "infra/supply-chain/ci-tooling.in",
        REPO_ROOT / "infra/supply-chain/ci-tooling.lock.txt",
    ),
}

#: The RUNTIME dependency locks — the "tree" that ships and that CI must test against. The W3-2
#: floor / require-hashes guards key on these, NOT on the ci-tooling harness lock above.
RUNTIME_LOCKS: tuple[Path, ...] = (
    REPO_ROOT / "engine/crucible/framework/v2/requirements.lock.txt",
    REPO_ROOT / "infra/supply-chain/sovereign.lock.txt",
)

_PINNED_LINE = re.compile(r"^([A-Za-z0-9._-]+)==([^\s\\;]+)")
_REQ_NAME = re.compile(r"^([A-Za-z0-9._-]+)\s*(?:[<>=!~]|$)")


def _canon(name: str) -> str:
    """PEP 503 normalisation — `PyYAML`, `pyyaml` and `py_yaml` are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _load_image_pins():
    """Load infra/supply-chain/image_pins.py by path.

    Loaded by path rather than imported: `infra/` is not a Python package and must not become
    one just to be testable, and this keeps the module usable from CI as a plain script too.
    """
    path = REPO_ROOT / "infra" / "supply-chain" / "image_pins.py"
    assert path.is_file(), f"missing {path} — the image-pin checker is the A14 source of truth"
    name = "vigil_a14_image_pins"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: @dataclass resolves string annotations via sys.modules[__module__],
    # so a module that is executed but never registered raises during class creation.
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        del sys.modules[name]
        raise
    return mod


def _require_lock(env: str, lock: Path) -> None:
    """Fail with the regeneration command rather than a bare FileNotFoundError."""
    src, _ = LOCKS[env]
    assert lock.is_file(), (
        f"missing {lock.relative_to(REPO_ROOT)}. Generate it under Python 3.13 with:\n"
        f"  pip install pip-tools==7.6.1\n"
        f"  pip-compile --generate-hashes --no-header --strip-extras "
        f"--output-file={lock.relative_to(REPO_ROOT)} {src.relative_to(REPO_ROOT)}\n"
        f"(The 'A14 supply-chain gate' job regenerates both locks and uploads them as the "
        f"'a14-regenerated-locks' artifact, so a failing run already contains the file to commit.)"
    )


def _strip_comments(text: str) -> str:
    """Drop whole-line comments so a commented-out step cannot satisfy an assertion."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


# ======================================================================================
# 1. Container base images
# ======================================================================================


def test_scanner_finds_the_repo_s_images() -> None:
    """Guard against a vacuous pass: a scanner that finds nothing proves nothing."""
    pins = _load_image_pins()
    refs = pins.collect(REPO_ROOT)
    assert len(refs) >= 8, (
        f"the image scanner found only {len(refs)} image reference(s) under {REPO_ROOT}; "
        "the repo has at least 5 Dockerfiles and 2 compose files, so the scanner is broken "
        "and every other image assertion in this file would pass vacuously"
    )
    sources = {r.source for r in refs}
    for expected in (
        "gateway/Dockerfile",
        "engine/crucible/framework/v2/aegis/Dockerfile",
        "vendor/strix/containers/Dockerfile",
        "docker-compose.yml",
    ):
        assert expected in sources, f"{expected} was not scanned for image references"


def test_every_container_base_image_is_digest_pinned() -> None:
    """A tag is a mutable pointer; a digest is content-addressed.

    `FROM python:3.13-slim` means "whatever the registry serves at pull time", so a retag —
    benign or hostile — changes what ships with no diff and no review. Images built from this
    tree are exempt (there is no upstream digest for them); everything else must be pinned.
    """
    pins = _load_image_pins()
    bad = pins.unpinned(pins.collect(REPO_ROOT))
    assert not bad, "container images are not digest-pinned:\n" + "\n".join(
        f"  {r.source}:{r.line} [{r.context}] {r.ref}" for r in bad
    ) + (
        "\n\nPin as image:tag@sha256:<digest>. Resolve current digests with:\n"
        "  bash infra/supply-chain/resolve-image-digests.sh"
    )


def test_the_pin_check_can_actually_fail() -> None:
    """NEGATIVE CONTROL. A check that cannot fail is not a check.

    Build a throwaway tree containing one unpinned Dockerfile and one unpinned compose image
    and assert the scanner flags both — and that a service which `build:`s locally, a `FROM
    scratch` and a build-stage back-reference are NOT flagged (those exemptions are rules, and
    a rule that swallows real findings is a hole).
    """
    pins = _load_image_pins()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "Dockerfile").write_text(
            "FROM alpine:3.20\n"
            "FROM scratch AS empty\n"
            "FROM golang:1.22 AS builder\n"
            "FROM builder\n",
            encoding="utf-8",
        )
        (root / "docker-compose.yml").write_text(
            "services:\n"
            "  floating:\n"
            "    image: redis:7\n"
            "  homemade:\n"
            "    image: something:local\n"
            "    build:\n"
            "      context: .\n",
            encoding="utf-8",
        )
        refs = pins.collect(root)
        flagged = {(r.source, r.ref) for r in pins.unpinned(refs)}

        assert ("Dockerfile", "alpine:3.20") in flagged, "unpinned FROM was not flagged"
        assert ("Dockerfile", "golang:1.22") in flagged, "unpinned builder-stage FROM was not flagged"
        assert ("docker-compose.yml", "redis:7") in flagged, "unpinned compose image was not flagged"

        all_refs = {r.ref for r in refs}
        assert "scratch" not in all_refs, "`FROM scratch` has no content to pin"
        assert "builder" not in all_refs, "a back-reference to an earlier build stage is not an image"
        assert "something:local" not in all_refs, "a service with build: is built from the tree"


def test_strix_runtime_image_default_is_scanned_and_pinnable() -> None:
    """S5 — A14 must SEE the Strix runtime sandbox image.

    That image is named in no Dockerfile and no compose `image:` — the agent pulls it from the
    `STRIX_IMAGE` setting DEFAULT at launch. Before S5 the scanner never looked there, so a mutable
    upstream tag as the default (the shipped value was `ghcr.io/usestrix/strix-sandbox:1.0.0`) was an
    unpinned image the gate silently ignored. Assert the scanner now yields it, and that the committed
    default is itself acceptable (first-party or digest-pinned).
    """
    pins = _load_image_pins()
    runtime = [r for r in pins.collect(REPO_ROOT) if r.source == pins.STRIX_SETTINGS_REL]
    assert runtime, (
        "A14 does not see the Strix runtime image (STRIX_IMAGE default in "
        f"{pins.STRIX_SETTINGS_REL}); a mutable tag there would be an unpinned image the gate never checks"
    )
    assert not pins.unpinned(runtime), (
        "the committed Strix runtime image default is neither first-party nor digest-pinned: "
        + ", ".join(r.ref for r in pins.unpinned(runtime))
    )


def test_strix_runtime_image_scan_can_actually_fail() -> None:
    """NEGATIVE CONTROL for the runtime-image scanner: a mutable upstream tag is flagged, a first-party
    override is exempt, and the parser reads the value out of a real `Field(...)` shape."""
    pins = _load_image_pins()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        settings = root / pins.STRIX_SETTINGS_REL
        settings.parent.mkdir(parents=True)

        settings.write_text(
            "    image: str = Field(\n"
            '        default="ghcr.io/usestrix/strix-sandbox:1.0.0",\n'
            '        alias="STRIX_IMAGE",\n'
            "    )\n",
            encoding="utf-8",
        )
        refs = pins.strix_runtime_image_refs(root)
        assert [r.ref for r in refs] == ["ghcr.io/usestrix/strix-sandbox:1.0.0"], (
            "the parser did not read the STRIX_IMAGE default out of a Field(...) call"
        )
        assert pins.unpinned(refs) == refs, "a mutable upstream runtime tag must be flagged as unpinned"

        settings.write_text(
            "    image: str = Field(\n"
            '        default="vigil/strix-sandbox:local",\n'
            '        alias="STRIX_IMAGE",\n'
            "    )\n",
            encoding="utf-8",
        )
        first_party = pins.strix_runtime_image_refs(root)
        assert first_party and not pins.unpinned(first_party), (
            "the first-party runtime image (built from this tree) must be exempt"
        )


# ======================================================================================
# 2. Hash-locked dependencies
# ======================================================================================


@pytest.mark.parametrize("env", sorted(LOCKS))
def test_lock_exists_and_is_not_a_placeholder(env: str) -> None:
    """This repo shipped a 42-line comment-ONLY `requirements.lock.txt` for its whole history.

    It looked like a lock in every listing and pinned nothing. Assert that class of thing can
    never come back: a lock must contain actual `name==version` pins.
    """
    src, lock = LOCKS[env]
    assert src.is_file(), f"missing pip-compile input {src}"
    assert lock.is_file(), (
        f"missing {lock}. Generate it under Python 3.13 with:\n"
        f"  pip install pip-tools==7.6.1\n"
        f"  pip-compile --generate-hashes --no-header --strip-extras "
        f"--output-file={lock.relative_to(REPO_ROOT)} {src.relative_to(REPO_ROOT)}"
    )
    pinned = [m.group(1) for m in map(_PINNED_LINE.match, lock.read_text().splitlines()) if m]
    assert pinned, (
        f"{lock.relative_to(REPO_ROOT)} contains no `name==version` lines — it is a "
        f"placeholder, not a lock."
    )


@pytest.mark.parametrize("env", sorted(LOCKS))
def test_every_pinned_requirement_carries_a_hash(env: str) -> None:
    """`--require-hashes` is only as good as the weakest line.

    pip refuses the whole file if ANY requirement lacks a hash, so an unhashed line does not
    degrade the guarantee — it destroys it. Check each pin individually (a requirement's
    hashes may continue onto following `\\`-continued lines).
    """
    _, lock = LOCKS[env]
    _require_lock(env, lock)
    lines = lock.read_text(encoding="utf-8").splitlines()
    missing: list[str] = []
    i = 0
    while i < len(lines):
        m = _PINNED_LINE.match(lines[i])
        if not m:
            i += 1
            continue
        # Gather this requirement's full logical line (backslash continuations).
        block = [lines[i]]
        while block[-1].rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            block.append(lines[i])
        if "--hash=sha256:" not in "\n".join(block):
            missing.append(f"{m.group(1)}=={m.group(2)} (line {i + 1})")
        i += 1
    assert not missing, (
        f"{lock.relative_to(REPO_ROOT)} has pins with no --hash=sha256:, which makes "
        f"`pip install --require-hashes` reject the entire file:\n  " + "\n  ".join(missing)
    )


@pytest.mark.parametrize("env", sorted(LOCKS))
def test_lock_covers_every_direct_requirement(env: str) -> None:
    """A lock that silently dropped a direct dependency would leave it installed UNPINNED.

    Read the direct names out of the `.in` (following `-r` includes) and assert each one is
    pinned in the lock.
    """
    src, lock = LOCKS[env]
    _require_lock(env, lock)
    locked = {_canon(m.group(1)) for m in map(_PINNED_LINE.match, lock.read_text().splitlines()) if m}

    direct: set[str] = set()
    seen: set[Path] = set()

    def _read(p: Path) -> None:
        p = p.resolve()
        if p in seen or not p.is_file():
            return
        seen.add(p)
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith(("-r ", "--requirement ")):
                _read(p.parent / line.split(None, 1)[1].strip())
                continue
            if line.startswith("-"):
                continue
            m = _REQ_NAME.match(line)
            if m:
                direct.add(_canon(m.group(1)))

    _read(src)
    assert direct, f"parsed no direct requirements out of {src.relative_to(REPO_ROOT)}"
    missing = sorted(direct - locked)
    assert not missing, (
        f"{lock.relative_to(REPO_ROOT)} does not pin these direct requirements from "
        f"{src.relative_to(REPO_ROOT)}: {missing}. They would be installed unpinned."
    )


def test_the_supply_chain_verifier_is_executable_and_wired() -> None:
    """The verifier existed for the repo's whole history with ZERO callers.

    A verification script nothing runs verifies nothing, so assert the A14 workflow invokes
    it. Also assert it is executable — a `bash <script>` caller would mask a lost +x bit until
    someone tried to run it directly.
    """
    script = REPO_ROOT / "engine/crucible/bin/verify-supply-chain.sh"
    assert script.is_file(), f"missing {script}"
    assert script.stat().st_mode & stat.S_IXUSR, f"{script} is not executable"
    assert WORKFLOW.is_file(), f"missing {WORKFLOW}"
    assert "verify-supply-chain.sh" in _strip_comments(WORKFLOW.read_text()), (
        "the A14 workflow does not call bin/verify-supply-chain.sh — the lock-drift and "
        "SBOM cross-check would go back to being dead code"
    )


# ======================================================================================
# 3. The CI gate itself
# ======================================================================================


def test_a14_workflow_declares_every_leg_of_the_gate() -> None:
    """Stop the gate degrading into a no-op.

    Each leg below is something a future edit could quietly drop while the job stays green,
    because a job that does less still passes. Assert the legs are present by name.
    """
    assert WORKFLOW.is_file(), f"missing {WORKFLOW}"
    body = _strip_comments(WORKFLOW.read_text(encoding="utf-8"))

    required = {
        "the job itself": "A14 supply-chain gate",
        "runs on pull requests": "pull_request",
        "offline image-pin check": "image_pins.py",
        "lock drift + SBOM cross-check": "verify-supply-chain.sh",
        "hash-enforced install proof": "--require-hashes",
        "SBOM generation": "cyclonedx-py",
        "SBOM artifact upload": "actions/upload-artifact",
        "vulnerability scanner": "trivy",
        "BLOCKING scan (non-zero exit on a finding)": "--exit-code 1",
        "suppression file is honoured": "--ignorefile",
        # Trivy's pip analyzer matches by FILENAME, so without this it scans
        # requirements.txt and silently skips both `*.lock.txt` locks — i.e. exactly the
        # artifacts this whole job exists to produce.
        "the generated locks are actually scanned": "--file-patterns",
        # A gate that has never fired is indistinguishable from a gate that cannot fire.
        "negative control proving the gate fires": "negative control",
    }
    missing = sorted(f"{why} ({needle!r})" for why, needle in required.items() if needle not in body)
    assert not missing, "the A14 workflow no longer declares:\n  " + "\n  ".join(missing)


def test_a14_workflow_blocking_severity_is_at_least_critical() -> None:
    """The gate must BLOCK on at least CRITICAL. Documented threshold: HIGH + CRITICAL block.

    Find every trivy invocation that carries `--exit-code 1` and assert CRITICAL is in its
    severity set. The floor (CRITICAL still blocks) is invariant across the W3-9 raise to HIGH;
    `test_a14_gate_blocks_high_not_only_critical` asserts the raise itself. Lowering the
    blocking tier below CRITICAL should require editing this test — a decision, not a drive-by.
    """
    body = _strip_comments(WORKFLOW.read_text(encoding="utf-8"))
    blocking = [
        ln for ln in body.splitlines() if "--exit-code 1" in ln or "--exit-code=1" in ln
    ]
    assert blocking, "no blocking trivy invocation (`--exit-code 1`) in the A14 workflow"
    # The severity flag may sit on an adjacent continued line; search the surrounding block.
    lines = body.splitlines()
    for idx, ln in enumerate(lines):
        if "--exit-code 1" not in ln and "--exit-code=1" not in ln:
            continue
        window = "\n".join(lines[max(0, idx - 8) : idx + 8])
        assert "CRITICAL" in window, (
            "the blocking trivy step does not include CRITICAL in its --severity set:\n" + window
        )


def _trivy_commands(body: str) -> list[str]:
    """Reconstruct each full `trivy fs …` invocation, joining `\\`-continued lines.

    A single `run:` block can hold several trivy calls (the report, the negative control's
    fixtures, and the gate). Each is returned as one flattened, whitespace-collapsed string so
    its flags and its final scan target can be inspected together.
    """
    lines = body.splitlines()
    cmds: list[str] = []
    i = 0
    while i < len(lines):
        if "trivy fs" in lines[i]:
            block = [lines[i]]
            while block[-1].rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                block.append(lines[i])
            flat = " ".join(seg.rstrip().rstrip("\\").strip() for seg in block)
            cmds.append(re.sub(r"\s+", " ", flat).strip())
        i += 1
    return cmds


def _gate_severity(cmd: str) -> set[str] | None:
    """The severity set of a *repo-scanning* blocking trivy call, else None.

    The enforcing gate is the invocation that BLOCKS (`--exit-code 1`) and scans the repository
    root (its final target token is a bare `.`). The negative-control calls also block, but they
    scan `/tmp` fixtures, so they are deliberately excluded — this isolates the real gate.
    """
    if "--exit-code 1" not in cmd and "--exit-code=1" not in cmd:
        return None
    if not cmd.rstrip().endswith(" ."):
        return None
    m = re.search(r"--severity[= ]([A-Z,]+)", cmd)
    if not m:
        return set()
    return {s for s in m.group(1).split(",") if s}


def test_a14_gate_blocks_high_not_only_critical() -> None:
    """W3-9: the enforcing gate must block HIGH, not only CRITICAL.

    FAILS on the pre-W3-9 tree, where the repo-scanning gate is `--severity CRITICAL`: HIGH is
    absent from its severity set. This is the doc/config assertion the issue (#432) asks for —
    that the trivy severity gate is HIGH.
    """
    body = _strip_comments(WORKFLOW.read_text(encoding="utf-8"))
    gates = [sev for cmd in _trivy_commands(body) if (sev := _gate_severity(cmd)) is not None]
    assert gates, (
        "found no repo-scanning blocking trivy invocation (`--exit-code 1` scanning `.`) in the "
        "A14 workflow — the gate has gone missing"
    )
    for sev in gates:
        assert "HIGH" in sev and "CRITICAL" in sev, (
            f"the enforcing gate blocks on {sorted(sev)}; W3-9 requires HIGH and CRITICAL. "
            "The known-open HIGH backlog (aiohttp, pyasn1, cryptography in vendor/strix) must be "
            "cleared before the threshold can be raised — see docs/SUPPLY-CHAIN.md §4."
        )

    # NEGATIVE CONTROL: the detector must actually distinguish a CRITICAL-only gate. Feed it the
    # exact shape of the OLD gate and require it to report HIGH as ABSENT — otherwise this test
    # would pass vacuously on the pre-W3-9 workflow it is meant to reject.
    old_gate = "trivy fs --scanners vuln --severity CRITICAL --exit-code 1 --no-progress ."
    old_sev = _gate_severity(old_gate)
    assert old_sev == {"CRITICAL"}, f"detector misread the old CRITICAL-only gate as {old_sev}"
    assert "HIGH" not in old_sev, "negative control broken: detector cannot tell HIGH from CRITICAL"

    # And the documented threshold must agree with the code.
    doc = (REPO_ROOT / "docs" / "SUPPLY-CHAIN.md").read_text(encoding="utf-8")
    assert re.search(r"HIGH[^\n]*\bBlock", doc), (
        "docs/SUPPLY-CHAIN.md no longer states that HIGH blocks — the doc has drifted from the gate"
    )


def _uv_lock_version(text: str, name: str) -> str:
    """Read a package's pinned version out of a uv.lock without a TOML dependency."""
    m = re.search(rf'(?m)^\[\[package\]\]\nname = "{re.escape(name)}"\nversion = "([^"]+)"', text)
    assert m, f"{name} not found in vendor/strix/uv.lock"
    return m.group(1)


def _ge(version: str, floor: tuple[int, ...]) -> bool:
    """True iff `version` (numeric dotted release) is >= `floor`."""
    parts = tuple(int(p) for p in re.findall(r"\d+", version))
    return parts >= floor


def test_vendored_strix_lock_cleared_the_high_backlog() -> None:
    """W3-9: vendor/strix/uv.lock must pin the named HIGH-CVE packages at/above their fixes.

    FAILS on the pre-W3-9 tree, where aiohttp==3.14.1, pyasn1==0.6.3 and cryptography==46.0.7
    still carry the open HIGH advisories the trivy gate would block on once raised to HIGH:
      * aiohttp   >= 3.14.3  (GHSA-cq5v-8q36-5273, out-of-bounds heap read)
      * pyasn1    >= 0.6.4   (CVE-2026-59884/59885/59886, decoder DoS)
      * cryptography >= 50.0.0 (CVE-2026-69247/69249, GHSA-537c-gmf6-5ccf)
    """
    lock = REPO_ROOT / "vendor" / "strix" / "uv.lock"
    assert lock.is_file(), f"missing {lock}"
    text = lock.read_text(encoding="utf-8")

    floors: dict[str, tuple[int, ...]] = {
        "aiohttp": (3, 14, 3),
        "pyasn1": (0, 6, 4),
        "cryptography": (50, 0, 0),
    }
    below = []
    for name, floor in floors.items():
        ver = _uv_lock_version(text, name)
        if not _ge(ver, floor):
            below.append(f"{name}=={ver} (< {'.'.join(map(str, floor))})")
    assert not below, (
        "vendor/strix/uv.lock still pins packages below their HIGH-CVE fix floor, so the trivy "
        "gate cannot be raised to HIGH without going red:\n  " + "\n  ".join(below)
    )

    # NEGATIVE CONTROL: the version comparator must reject a below-floor version and accept the
    # fixed one, or the assertion above could pass on a lock that was never actually bumped.
    assert _ge("3.14.3", (3, 14, 3)) and _ge("3.14.10", (3, 14, 3))
    assert not _ge("3.14.1", (3, 14, 3)), "comparator accepts the vulnerable aiohttp 3.14.1"
    assert not _ge("46.0.7", (50, 0, 0)), "comparator accepts the vulnerable cryptography 46.0.7"


#: A `uses:` ref is SHA-pinned iff its `@`-ref is exactly 40 lowercase hex (a full commit SHA).
#: A mutable tag (`@v4`) or a branch (`@main`) is not: it is third-party code that can change
#: under a pin the workflow token already trusts. A subdirectory action such as
#: `github/codeql-action/init@<sha>` keeps the sha at the END of the ref, so anchoring on `$` is
#: correct for those too. (`WORKFLOWS_DIR` is defined once, further down, in §5.)
_SHA_PINNED_USE = re.compile(r"@[0-9a-f]{40}$")


def _workflow_files_in(workflows_dir: Path) -> list[Path]:
    """Every workflow file under `workflows_dir`, both `.yml` and `.yaml`.

    Distinct from the 0-arg `_workflow_files()` in §5 (which globs the repo's own `*.yml` only):
    this one takes a directory so the negative-control test can point it at a throwaway tree, and
    it also matches `.yaml` so a future workflow with that extension cannot slip the drift check.
    """
    return sorted(p for ext in ("*.yml", "*.yaml") for p in workflows_dir.glob(ext))


def _unpinned_action_uses(workflows_dir: Path) -> list[tuple[str, str]]:
    """Every `uses:` in every workflow under `workflows_dir` that is NOT pinned to a commit SHA.

    Whole-line comments are stripped first, so a commented-out `uses:` can neither trip the gate
    nor satisfy it. A local composite action or reusable workflow (`uses: ./…`) is first-party and
    has no upstream SHA to pin, so it is exempt — the check is about third-party code.
    """
    out: list[tuple[str, str]] = []
    for wf in _workflow_files_in(workflows_dir):
        body = _strip_comments(wf.read_text(encoding="utf-8"))
        for ref in re.findall(r"uses:\s*(\S+)", body):
            if ref.startswith((".", "/")):  # local action / reusable workflow — no upstream SHA
                continue
            if not _SHA_PINNED_USE.search(ref):
                out.append((wf.name, ref))
    return out


def test_every_workflow_action_is_sha_pinned() -> None:
    """[W3-3] #426 — EVERY `uses:` in EVERY workflow pins a full 40-char commit SHA.

    A GitHub Action reference is a supply-chain dependency like any other: `actions/checkout@v4`
    is a mutable TAG on someone else's repository, executing with the workflow's token. The
    previous gate asserted this for `supply-chain.yml` alone (three more per-workflow tests cover
    release.yml, security-scan.yml and scheduled-supply-chain-scan.yml), which left ci.yml,
    livefire.yml and branch-protection-verify.yml — 32 tag-pinned refs — outside any check at all.

    This is the drift check: it FAILS the moment any workflow (re)introduces a tag or branch ref.
    It runs in the required 'A14 supply-chain gate' and 'integration two-env boundary (P5)' jobs,
    so an unpinned action cannot merge. Its negative control lives in the test below.
    """
    assert WORKFLOWS_DIR.is_dir(), f"missing {WORKFLOWS_DIR}"
    # Guard against a vacuous pass: if the glob or parser broke and found no actions, an empty
    # `unpinned` list would be a false green. The repo's workflows reference dozens of actions.
    all_uses = [
        ref
        for wf in _workflow_files_in(WORKFLOWS_DIR)
        for ref in re.findall(r"uses:\s*(\S+)", _strip_comments(wf.read_text(encoding="utf-8")))
    ]
    assert len(all_uses) >= 30, (
        f"expected the repo's workflows to reference many actions, found only {len(all_uses)} — "
        "did the workflows dir get truncated or the `uses:` parser break?"
    )
    unpinned = _unpinned_action_uses(WORKFLOWS_DIR)
    assert not unpinned, (
        "these action references are not pinned to a full commit SHA (a tag or branch ref runs "
        "third-party code the workflow token trusts):\n  "
        + "\n  ".join(f"{name}: {ref}" for name, ref in unpinned)
        + "\nPin with:  gh api repos/<owner>/<repo>/commits/<tag> --jq .sha"
        + "   (keep the version as a trailing '# vX.Y.Z' comment)"
    )


def test_sha_pin_gate_rejects_a_tag_pinned_workflow(tmp_path: Path) -> None:
    """NEGATIVE CONTROL — prove the drift check is not a no-op.

    Point the SAME detector at a throwaway workflow that pins a mutable tag and assert it IS
    flagged; then at a SHA-pinned twin and a first-party local action and assert NEITHER is. A
    gate that never rejects anything is indistinguishable from no gate at all, and one that flags
    a correctly-pinned ref would be an unmergeable false alarm — both failure modes are asserted
    against here, in the same run.
    """
    good_sha = "11d5960a326750d5838078e36cf38b85af677262"  # a real 40-hex commit sha
    (tmp_path / "bad.yml").write_text(
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    assert ("bad.yml", "actions/checkout@v4") in _unpinned_action_uses(tmp_path), (
        "the drift check FAILED to flag a tag-pinned action — the gate is a no-op"
    )

    # And it must not cry wolf: a SHA-pinned ref and a local composite action are both acceptable.
    (tmp_path / "bad.yml").unlink()
    (tmp_path / "good.yml").write_text(
        "on: push\njobs:\n  g:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: actions/checkout@{good_sha}  # v4.4.0\n"
        "      - uses: ./.github/actions/local-thing\n",
        encoding="utf-8",
    )
    assert _unpinned_action_uses(tmp_path) == [], (
        "the drift check flagged a SHA-pinned ref or a first-party local action — false positive"
    )


# ======================================================================================
# 4. Suppressions
# ======================================================================================


def test_every_vulnerability_suppression_carries_a_justification() -> None:
    """No silent suppression. Ever.

    `.trivyignore` is optional — a repo with nothing to suppress should not have to invent
    entries. But if it exists, every id in it must be immediately preceded by a comment naming
    a reason. The point of a scan gate is that ignoring a finding costs a sentence.
    """
    if not TRIVYIGNORE.is_file():
        return  # nothing suppressed; the gate is unconditioned

    reasons = ("no-fix", "not-reachable", "vendored-test-only", "disputed", "false-positive")
    lines = TRIVYIGNORE.read_text(encoding="utf-8").splitlines()
    problems: list[str] = []

    for i, raw in enumerate(lines):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        # Walk back over the contiguous comment block directly above this entry.
        block: list[str] = []
        j = i - 1
        while j >= 0 and lines[j].lstrip().startswith("#"):
            block.append(lines[j].lstrip("# ").strip())
            j -= 1
        justification = " ".join(reversed(block))
        if not justification:
            problems.append(f"line {i + 1}: {entry!r} has no justification comment above it")
        elif not any(r in justification.lower() for r in reasons):
            problems.append(
                f"line {i + 1}: {entry!r} has a comment but no accepted reason "
                f"(one of {list(reasons)}): {justification!r}"
            )
        elif entry.split(":")[0] not in justification:
            problems.append(
                f"line {i + 1}: {entry!r} is not named in its own justification "
                f"(comment blocks drift onto the wrong entry): {justification!r}"
            )

    assert not problems, (
        ".trivyignore suppressions must each carry a justification comment naming the id and "
        "one of " + str(list(reasons)) + ":\n  " + "\n  ".join(problems)
    )


def test_the_justification_check_can_actually_fail() -> None:
    """NEGATIVE CONTROL for the suppression rule, using the real function on a fake file."""
    src = TRIVYIGNORE
    with tempfile.TemporaryDirectory() as td:
        fake = Path(td) / ".trivyignore"
        fake.write_text("CVE-2025-99999\n", encoding="utf-8")  # bare, no justification
        code = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys, importlib.util, pathlib\n"
                    f"spec = importlib.util.spec_from_file_location('t', {str(Path(__file__))!r})\n"
                    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
                    f"m.TRIVYIGNORE = pathlib.Path({str(fake)!r})\n"
                    "try:\n"
                    "    m.test_every_vulnerability_suppression_carries_a_justification()\n"
                    "except AssertionError:\n"
                    "    sys.exit(0)\n"
                    "sys.exit(1)\n"
                ),
            ],
            capture_output=True,
            cwd=str(REPO_ROOT),
            env={**os.environ, "PYTHONPATH": os.environ.get("PYTHONPATH", "")},
        )
        assert code.returncode == 0, (
            "the suppression-justification check did NOT reject a bare, unjustified id — "
            "it would let a silent suppression through.\n"
            f"stdout={code.stdout!r}\nstderr={code.stderr!r}"
        )
    assert TRIVYIGNORE == src  # the real path was not mutated for other tests


# ======================================================================================
# 3. vendor/strix's live-scan extras are hash-locked (W3-6)
#
# vendor/strix (the offense agent body) declares heavy live-scan deps — openai-agents[litellm],
# litellm, openai, docker, textual, cvss, caido-sdk-client + their transitive closure — that are
# NOT in the offense framework lock. Before this slice they resolved FRESH from PyPI on every
# operator install (envs/build_envs.sh), the largest unlocked surface in the product and co-loaded
# with the offense engine. This section proves: the closure is committed and fully hash-pinned; the
# install uses --require-hashes; no operator install path resolves it unlocked; the missing-lock
# fallback FAILS in production posture (and only warns in dev); and --require-hashes actually rejects
# a corrupted or missing hash (the gate is not a no-op).
# ======================================================================================


def _pinned_names(lock: Path) -> set[str]:
    """Canonical `name` of every `name==version` pin in a requirements lock."""
    return {
        _canon(m.group(1))
        for m in map(_PINNED_LINE.match, lock.read_text(encoding="utf-8").splitlines())
        if m
    }


def _strix_declared_runtime_deps() -> set[str]:
    """Canonical names of vendor/strix's declared `[project].dependencies` (extras/specifiers stripped)."""
    import tomllib  # stdlib >=3.11; the locks (and this repo) target 3.13

    data = tomllib.loads(STRIX_PYPROJECT.read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    # "openai-agents[litellm]==0.14.6" -> "openai-agents"; "openai>=2.26.0,<2.45" -> "openai"
    return {_canon(re.split(r"[\[<>=!~;\s]", d.strip(), maxsplit=1)[0]) for d in deps}


def _extract_bash_function(script: Path, name: str) -> str | None:
    """Return the text of a top-level bash function `name() { ... }` (closing `}` at column 0)."""
    lines = script.read_text(encoding="utf-8").splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith(f"{name}() {{")), None)
    if start is None:
        return None
    end = next((j for j in range(start + 1, len(lines)) if lines[j] == "}"), None)
    if end is None:
        return None
    return "\n".join(lines[start : end + 1])


def _build_synthetic_wheel(dst_dir: Path, name: str = "obsidianfixture", ver: str = "1.0") -> tuple[Path, str]:
    """A minimal but VALID pure-python wheel + its sha256, so pip can install it offline from a
    --find-links dir. Lets the --require-hashes gate be exercised end-to-end with no network."""

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    dist = f"{name}-{ver}.dist-info"
    files = {
        f"{name}/__init__.py": b'__version__ = "1.0"\n',
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\n".encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: obsidian\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = [f"{arc},sha256={b64(hashlib.sha256(d).digest())},{len(d)}" for arc, d in files.items()]
    record.append(f"{dist}/RECORD,,")
    files[f"{dist}/RECORD"] = ("\n".join(record) + "\n").encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for arc, d in files.items():
            z.writestr(arc, d)
    whl = dst_dir / f"{name}-{ver}-py3-none-any.whl"
    whl.write_bytes(buf.getvalue())
    return whl, hashlib.sha256(whl.read_bytes()).hexdigest()


def test_strix_lock_exists_and_is_fully_hash_pinned() -> None:
    """The committed strix lock must exist and carry a sha256 hash on EVERY pin.

    `--require-hashes` is all-or-nothing: pip rejects the whole file if a single requirement is
    unpinned or unhashed, so one hashless line does not weaken the guarantee — it removes it.
    """
    assert STRIX_LOCK.is_file(), (
        f"missing {STRIX_LOCK.relative_to(REPO_ROOT)} — vendor/strix's live-scan extras have no "
        f"hash-locked closure, so they resolve fresh from PyPI on every install. Regenerate with:\n"
        f"  bash infra/supply-chain/gen-strix-lock.sh"
    )
    lines = STRIX_LOCK.read_text(encoding="utf-8").splitlines()
    pins = [m.group(1) for m in map(_PINNED_LINE.match, lines) if m]
    assert len(pins) >= 50, (
        f"{STRIX_LOCK.relative_to(REPO_ROOT)} has only {len(pins)} pins — strix's closure is dozens "
        f"of packages; a lock this small is a placeholder or a broken export."
    )
    missing: list[str] = []
    i = 0
    while i < len(lines):
        m = _PINNED_LINE.match(lines[i])
        if not m:
            i += 1
            continue
        # A pin's hashes may sit on the same line or on following `\`-continued lines.
        has_hash = "hash=" in lines[i]
        j = i
        while lines[j].rstrip().endswith("\\"):
            j += 1
            if j < len(lines) and "hash=" in lines[j]:
                has_hash = True
        if not has_hash:
            missing.append(m.group(1))
        i = j + 1
    assert not missing, (
        f"{STRIX_LOCK.relative_to(REPO_ROOT)} has pins with NO --hash= (breaks --require-hashes for "
        f"the whole file): {missing}"
    )


def test_strix_lock_covers_strix_declared_runtime_deps() -> None:
    """A lock that silently dropped one of strix's declared deps would leave it installed unpinned.

    Every name in vendor/strix/pyproject.toml `[project].dependencies` must appear as a pin in the
    lock (mirrors the offense/sovereign 'lock covers its .in' check).
    """
    declared = _strix_declared_runtime_deps()
    pinned = _pinned_names(STRIX_LOCK)
    uncovered = sorted(declared - pinned)
    assert not uncovered, (
        f"{STRIX_LOCK.relative_to(REPO_ROOT)} does not pin these declared strix runtime deps "
        f"(they would install unpinned): {uncovered}. Regenerate: bash infra/supply-chain/gen-strix-lock.sh"
    )


def test_build_envs_installs_strix_extras_under_require_hashes() -> None:
    """The operator install path must install strix's extras from the hash lock, not resolve fresh."""
    text = _strip_comments(BUILD_ENVS.read_text(encoding="utf-8"))
    assert 'STRIX_LOCK="infra/supply-chain/strix.lock"' in text, (
        "envs/build_envs.sh does not declare STRIX_LOCK pointing at the committed strix lock"
    )
    assert '--require-hashes -r "$STRIX_LOCK"' in text, (
        "envs/build_envs.sh does not install the strix live-scan extras under --require-hashes — "
        "they would resolve fresh from PyPI on every operator install (the W3-6 defect)."
    )


def test_no_operator_install_path_resolves_strix_extras_unlocked() -> None:
    """No install path in the repo may resolve strix's extras without hashes.

    The pre-fix build installed `venv_pip "$venv" "${withdep[@]}"` — strix WITH its live-scan deps and
    NO hashes — unconditionally. That line, and its 'not hash-locked' rationale, must be gone. The
    only remaining fresh strix install is the dev-only fallback, reached solely when the strix lock is
    absent (which is fail-closed in production posture, proven separately).
    """
    text = _strip_comments(BUILD_ENVS.read_text(encoding="utf-8"))
    assert 'venv_pip "$venv" "${withdep[@]}"' not in text, (
        "the pre-fix UNCONDITIONAL unlocked strix install is still present in build_envs.sh"
    )
    # The strix install must be gated on the strix lock: --no-deps when locked (extras already pinned),
    # and the ONLY fresh (deps-from-PyPI) strix install must be the dev fallback reached AFTER
    # lock_missing_or_die has run (fail-closed in production posture).
    assert 'if [ -n "$strix_locked" ]; then' in text, "the strix install is not gated on the strix lock"
    assert '--no-deps -e "$s"' in text, (
        "when the strix lock IS present, strix must install --no-deps over the pinned extras"
    )
    fresh = [mo.start() for mo in re.finditer(r'venv_pip "\$venv" -e "\$s"', text)]
    assert len(fresh) == 1, (
        f"expected exactly one (guarded) fresh strix editable install, found {len(fresh)} — a stray "
        f"unhashed strix install may have slipped in"
    )
    guard = text.find('lock_missing_or_die "$STRIX_LOCK"')
    assert 0 <= guard < fresh[0], (
        "the fresh strix editable install is NOT preceded by the lock_missing_or_die guard — strix "
        "extras could install unlocked without the production-posture refusal"
    )
    # bootstrap.sh (the only documented install path) must delegate, never install strix itself.
    boot = REPO_ROOT / "bootstrap.sh"
    if boot.is_file():
        bt = _strip_comments(boot.read_text(encoding="utf-8"))
        assert "vendor/strix" not in bt, (
            "bootstrap.sh installs vendor/strix directly, bypassing build_envs.sh's hash lock"
        )


def test_unlocked_fallback_fails_closed_in_production_posture() -> None:
    """The missing-lock fallback must ABORT under VIGIL_POSTURE=production and only WARN otherwise.

    This executes the SHIPPED `lock_missing_or_die` from build_envs.sh (not a copy). The dev path
    exiting 0 is the NEGATIVE CONTROL: it proves the guard is posture-CONDITIONAL, not a blanket
    abort that would 'pass' vacuously, and not a no-op that never fires.
    """
    fn = _extract_bash_function(BUILD_ENVS, "lock_missing_or_die")
    assert fn is not None, (
        "build_envs.sh has no lock_missing_or_die function — the fallback is still a silent, "
        "unconditional degrade to fresh resolution (the W3-6 defect)."
    )
    script = fn + '\nlock_missing_or_die "infra/supply-chain/strix.lock" "the strix live-scan lock"\n'

    def run(posture: str | None):
        env = {k: v for k, v in os.environ.items() if k != "VIGIL_POSTURE"}
        if posture is not None:
            env["VIGIL_POSTURE"] = posture
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)

    prod = run("production")
    assert prod.returncode != 0, (
        "VIGIL_POSTURE=production did NOT refuse the missing strix lock — the unlocked fallback "
        f"still succeeds in production posture.\nstdout={prod.stdout!r}\nstderr={prod.stderr!r}"
    )
    assert "FATAL" in prod.stderr, f"production refusal is not loud: stderr={prod.stderr!r}"
    assert run("Prod").returncode != 0, "posture match is not case-insensitive (Prod should refuse)"

    # NEGATIVE CONTROL: dev / unset posture warns loudly but does NOT abort.
    for dev_posture in (None, "dev"):
        dev = run(dev_posture)
        assert dev.returncode == 0, (
            f"VIGIL_POSTURE={dev_posture!r} aborted — the guard is a blanket abort, not a posture "
            f"gate (a green production refusal would then be meaningless).\nstderr={dev.stderr!r}"
        )
        assert "warn" in dev.stderr.lower(), f"dev fallback is silent, not a loud warning: {dev.stderr!r}"


def test_require_hashes_rejects_a_corrupted_or_missing_hash() -> None:
    """NEGATIVE CONTROL for the hash gate itself: --require-hashes must REFUSE a corrupted hash and a
    missing hash, and ACCEPT the correct one. Fully offline (a hand-built wheel served from a local
    --find-links dir), so it proves the mechanism build_envs.sh relies on is not a no-op."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        find_links = root / "fl"
        find_links.mkdir()
        whl, good_sha = _build_synthetic_wheel(find_links)

        vdir = root / "venv"
        try:
            venv.create(vdir, with_pip=True)
        except Exception as exc:  # pragma: no cover — venv/ensurepip should exist in CI
            pytest.skip(f"cannot create a venv to exercise pip --require-hashes: {exc}")
        pip = vdir / ("Scripts" if os.name == "nt" else "bin") / "pip"

        def install(req_text: str):
            req = root / "req.txt"
            req.write_text(req_text, encoding="utf-8")
            return subprocess.run(
                [str(pip), "install", "--require-hashes", "--no-index",
                 "--find-links", str(find_links), "--dry-run", "-r", str(req)],
                capture_output=True, text=True,
            )

        ok = install(f"obsidianfixture==1.0 --hash=sha256:{good_sha}\n")
        assert ok.returncode == 0, (
            "the CORRECT hash was rejected — the gate is broken the other way (blanket-reject), so a "
            f"passing real lock would prove nothing.\nstdout={ok.stdout!r}\nstderr={ok.stderr!r}"
        )

        bad = install("obsidianfixture==1.0 --hash=sha256:" + ("0" * 64) + "\n")
        assert bad.returncode != 0, "a CORRUPTED hash was ACCEPTED — --require-hashes is a no-op"
        assert "sha256" in (bad.stdout + bad.stderr).lower(), "no hash-mismatch diagnostic emitted"

        mis = install("obsidianfixture==1.0\n")
        assert mis.returncode != 0, "a MISSING hash was ACCEPTED — --require-hashes is a no-op"
        assert "hash" in (mis.stdout + mis.stderr).lower(), "no missing-hash diagnostic emitted"


# ==========================================================================================
# Runtime image visibility (issue #511 / W5-6) — prove the RUNNING gateway is the image built
# from the CURRENT source, a check the Dockerfile/compose scanners cannot make.
# ==========================================================================================

def _gateway_context(root: Path) -> Path:
    return root / "gateway"


def test_runtime_check_ok_when_running_matches_current_source(tmp_path) -> None:
    pins = _load_image_pins()
    ctx = tmp_path / "gateway"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    cur = pins.context_digest(ctx)
    pin = {"schema": pins.GATEWAY_PIN_SCHEMA, "context_digest": cur,
           "image_id": "sha256:built", "image_tag": f"vigil-gateway:ctx-{cur[:16]}"}
    res = pins.check_runtime_image(context_dir=ctx, pin=pin, running_image_id="sha256:built")
    assert res.ok is True and not (res.stale or res.mismatch or res.invisible)


def test_runtime_check_flags_stale_after_an_upgrade(tmp_path) -> None:
    """THE #511 defect made observable: the source changed but the gateway was not rebuilt. The pin still
    records the OLD context digest, so the check reports STALE and is NOT ok (fail-closed)."""
    pins = _load_image_pins()
    ctx = tmp_path / "gateway"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    old = pins.context_digest(ctx)
    pin = {"schema": pins.GATEWAY_PIN_SCHEMA, "context_digest": old, "image_id": "sha256:old"}
    # an "upgrade": the build context changes but nothing rebuilt / re-pinned
    (ctx / "Dockerfile").write_text("FROM scratch\nENV UPGRADED=1\n", encoding="utf-8")
    res = pins.check_runtime_image(context_dir=ctx, pin=pin, running_image_id="sha256:old")
    assert res.ok is False and res.stale is True
    assert "STALE" in res.reason


def test_runtime_check_flags_digest_mismatch(tmp_path) -> None:
    pins = _load_image_pins()
    ctx = tmp_path / "gateway"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    cur = pins.context_digest(ctx)
    pin = {"schema": pins.GATEWAY_PIN_SCHEMA, "context_digest": cur, "image_id": "sha256:built"}
    # the tree matches the pin, but the CONTAINER runs a different image than the pin recorded
    res = pins.check_runtime_image(context_dir=ctx, pin=pin, running_image_id="sha256:OTHER")
    assert res.ok is False and res.mismatch is True
    assert "MISMATCH" in res.reason


def test_runtime_check_fail_closed_on_missing_inputs(tmp_path) -> None:
    """NEGATIVE CONTROL: the check is not a no-op. Any missing/ambiguous input is NOT a pass — no pin
    (never built) and no running id (cannot read the container) both fail closed."""
    pins = _load_image_pins()
    ctx = tmp_path / "gateway"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    cur = pins.context_digest(ctx)
    # no pin at all -> INVISIBLE
    r1 = pins.check_runtime_image(context_dir=ctx, pin=None, running_image_id="sha256:x")
    assert r1.ok is False and r1.invisible is True
    # a matching pin but the running image id is unreadable -> INVISIBLE (never assumed fine)
    pin = {"schema": pins.GATEWAY_PIN_SCHEMA, "context_digest": cur, "image_id": "sha256:built"}
    r2 = pins.check_runtime_image(context_dir=ctx, pin=pin, running_image_id=None)
    assert r2.ok is False and r2.invisible is True


def test_load_gateway_pin_rejects_foreign_schema(tmp_path) -> None:
    pins = _load_image_pins()
    p = tmp_path / "pin.json"
    p.write_text(json.dumps({"schema": "not-ours", "image_id": "sha256:evil"}), encoding="utf-8")
    assert pins.load_gateway_pin(p) is None
    p.write_text("{ not json", encoding="utf-8")
    assert pins.load_gateway_pin(p) is None
    assert pins.load_gateway_pin(tmp_path / "absent.json") is None


def test_runtime_check_cli_advisory_vs_production(tmp_path) -> None:
    """The CLI is LOUD but advisory outside production (exit 0), and REFUSES (exit non-zero) when the
    production posture is armed — matching the acceptance criterion."""
    pins = _load_image_pins()
    ctx_root = tmp_path
    (ctx_root / "gateway").mkdir()
    (ctx_root / "gateway" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    missing_pin = ctx_root / "no-pin.json"
    # advisory: no pin, no posture -> exit 0
    assert pins._runtime_check(ctx_root, pin_path=missing_pin, production=False) == 0
    # production (explicit flag) -> refuse
    assert pins._runtime_check(ctx_root, pin_path=missing_pin, production=True) == 1

# ======================================================================================
# 5. CI installs from the hash-locked files — the tested tree equals the locked tree (W3-2)
#
# The two runtime locks above prove the RESULT of resolution is committed and hashed. This
# section proves the WORKFLOWS ACTUALLY USE it. CI once installed `cryptography>=42` in six jobs
# while the project floor was `>=50` (CVE-2026-69247): the tested tree could be the vulnerable
# version the repo claimed to have left behind, and a lock nothing installs from is a document,
# not a control. These checks read every `.github/workflows/*.yml` and assert (a) no `pip install`
# admits a runtime version BELOW the locked one, and (b) every runtime dependency is installed
# under `--require-hashes` against a committed lock — never typed inline as a floating range.
#
# Pure stdlib + regex (no PyYAML): this file audits the dependency surface, it must not add to it.
# ======================================================================================

WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

#: Shell control operators that end a `pip install`'s argument list (anything after is not a spec).
_SHELL_BREAK = re.compile(r"\s(?:\|\||&&|;|\||>|>>|2>&1|<)\s")

#: A pip flag that consumes the FOLLOWING token as its argument (a path or a value, never a spec).
_FLAG_TAKES_ARG = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-f", "--find-links", "-o", "--output-file", "--index-url", "-i",
    "--extra-index-url", "--target", "-t", "--prefix", "--root", "--python-version",
}


def _workflow_files() -> list[Path]:
    assert WORKFLOWS_DIR.is_dir(), f"missing {WORKFLOWS_DIR}"
    return sorted(p for p in WORKFLOWS_DIR.glob("*.yml"))


def _logical_lines(text: str) -> list[str]:
    """Join `\\`-continued shell lines so a `pip install` split over several lines is one string."""
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        cur = lines[i]
        while cur.rstrip().endswith("\\") and i + 1 < len(lines):
            cur = cur.rstrip()[:-1].rstrip() + " " + lines[i + 1].strip()
            i += 1
        out.append(cur)
        i += 1
    return out


def _pip_install_segments(line: str) -> list[str]:
    """Every `pip install …` argument segment in one logical line (cut at the first shell operator).

    A line may hold more than one (`pip install X && pip install Y`); each is returned as the raw
    argument text AFTER `install`, with quotes stripped, up to the next shell control operator.
    """
    segs: list[str] = []
    for m in re.finditer(r"pip(?:3)?\s+install\b", line):
        tail = line[m.end():]
        tail = _SHELL_BREAK.split(tail, maxsplit=1)[0]
        segs.append(tail.replace('"', " ").replace("'", " "))
    return segs


def _specs_in_segment(seg: str) -> list[str]:
    """Requirement tokens named directly in a pip-install segment (skips flags, their args, paths)."""
    toks = seg.split()
    specs: list[str] = []
    skip_next = False
    for t in toks:
        if skip_next:
            skip_next = False
            continue
        if t in _FLAG_TAKES_ARG:
            skip_next = True
            continue
        if t.startswith("-"):
            continue
        if "/" in t or "\\" in t or "$" in t:
            continue  # a path or a shell variable — never a bare PyPI requirement
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=(?!=)", t):
            continue  # a `KEY=val` env assignment (the `=` is not part of a >=/==/<= specifier)
        if re.match(r"^[A-Za-z][A-Za-z0-9._-]*(\[[^\]]*\])?([<>=!~].*)?$", t):
            specs.append(t)
    return specs


def _spec_name_and_floor(spec: str) -> tuple[str | None, str | None]:
    """(canonical name, lower-bound version or None) for a requirement spec.

    A `>=`/`>` clause yields its version; an `==` (deliberate exact pin) or an unbounded name yields
    None — an exact pin is a decision, not a floating range that could resolve below the lock.
    """
    m = re.match(r"^([A-Za-z][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(.*)$", spec)
    if not m:
        return None, None
    name = _canon(m.group(1))
    rest = m.group(2)
    if "==" in rest:
        return name, None
    lb: str | None = None
    for cm in re.finditer(r"(?:>=|>)\s*([0-9][0-9A-Za-z.\-]*)", rest):
        lb = cm.group(1)
    return name, lb


def _release(v: str) -> tuple[int, ...]:
    """Numeric release tuple of a version string (`50.0.0` -> (50, 0, 0)); pre/post tags ignored."""
    return tuple(int(p) for p in re.findall(r"\d+", v))


def _ge_ver(a: str, b: str) -> bool:
    """True iff version `a` >= version `b`, zero-padded so `50` == `50.0.0` (not `<`)."""
    ta, tb = _release(a), _release(b)
    n = max(len(ta), len(tb))
    return ta + (0,) * (n - len(ta)) >= tb + (0,) * (n - len(tb))


def _lock_versions(lock: Path) -> dict[str, str]:
    """{canonical name: pinned version} for every `name==version` line in a requirements lock."""
    out: dict[str, str] = {}
    for line in lock.read_text(encoding="utf-8").splitlines():
        m = _PINNED_LINE.match(line)
        if m:
            out[_canon(m.group(1))] = m.group(2)
    return out


def _runtime_floors() -> dict[str, str]:
    """Merged {name: version} across the runtime locks — the authoritative version CI must not go below.

    The two locks pin every shared package identically (asserted by
    test_shared_runtime_versions_agree_across_locks); on the impossible-by-that-test conflict, the
    higher version wins so the floor can only ever be tightened, never loosened.
    """
    floors: dict[str, str] = {}
    for lock in RUNTIME_LOCKS:
        assert lock.is_file(), f"missing runtime lock {lock}"
        for name, ver in _lock_versions(lock).items():
            if name not in floors or _ge_ver(ver, floors[name]):
                floors[name] = ver
    assert "cryptography" in floors, "runtime locks pin no cryptography — the floor map is broken"
    return floors


def _install_lines(text: str) -> list[str]:
    """Comment-stripped logical lines that actually run a `pip install` (not a mention in prose)."""
    stripped = _strip_comments(text)
    return [ln for ln in _logical_lines(stripped) if re.search(r"pip(?:3)?\s+install\b", ln)]


def _floor_offenders(line: str, floors: dict[str, str]) -> list[str]:
    """Specs on this line that admit a runtime version below its locked floor."""
    bad: list[str] = []
    for seg in _pip_install_segments(line):
        for spec in _specs_in_segment(seg):
            name, lb = _spec_name_and_floor(spec)
            if name in floors and lb is not None and not _ge_ver(lb, floors[name]):
                bad.append(f"{spec} (admits {name} < locked {floors[name]})")
    return bad


def test_scanner_finds_the_repo_s_pip_installs() -> None:
    """Guard against a vacuous pass: a workflow scan that finds no installs proves nothing."""
    total = sum(len(_install_lines(wf.read_text(encoding="utf-8"))) for wf in _workflow_files())
    assert total >= 8, (
        f"the workflow scanner found only {total} `pip install` line(s); the repo's CI has many more, "
        "so the parser is broken and every install assertion below would pass vacuously"
    )


def test_no_ci_pip_install_admits_a_version_below_a_lock_floor() -> None:
    """W3-2 core: no workflow may install a runtime dependency BELOW its locked version.

    FAILS on the pre-W3-2 tree, where six ci.yml jobs (+ livefire + pre-commit) install
    `cryptography>=42` while both runtime locks pin `cryptography==50.0.0` — CI could resolve the
    42.x line that still carries CVE-2026-69247, i.e. test against the version the repo claims to
    have left behind. `pydantic>=2.10,<3` is caught the same way (locked 2.13.4).
    """
    floors = _runtime_floors()
    offenders: list[str] = []
    for wf in _workflow_files():
        for line in _install_lines(wf.read_text(encoding="utf-8")):
            for bad in _floor_offenders(line, floors):
                offenders.append(f"{wf.name}: {bad}")
    assert not offenders, (
        "these CI installs admit a runtime version BELOW the committed lock — the tested tree could "
        "differ from the shipped/locked tree (W3-2):\n  " + "\n  ".join(sorted(offenders))
        + "\n\nInstall runtime deps from the hash lock instead:\n"
        "  pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt"
    )

    # NEGATIVE CONTROL: the detector must FLAG the exact defect and PASS the fixed forms — otherwise
    # a green run here would prove nothing (it would pass on the vulnerable tree too).
    assert _floor_offenders('pip install "cryptography>=42"', floors), (
        "negative control broken: the detector does not flag cryptography>=42 against the >=50 floor"
    )
    assert not _floor_offenders("pip install cryptography>=50", floors), (
        "false positive: cryptography>=50 meets the floor and must not be flagged"
    )
    assert not _floor_offenders(
        f"pip install cryptography=={floors['cryptography']}", floors
    ), "false positive: an exact pin at the locked version must not be flagged"


def test_ci_installs_runtime_deps_only_under_require_hashes() -> None:
    """W3-2 core: a runtime dependency may be installed only from a committed lock, hash-enforced.

    A floor that merely says `>=50` still lets pip resolve whatever it likes at run time, so the
    tested tree is only pinned to the shipped tree when the install carries `--require-hashes`
    against a lock. This asserts NO workflow names a runtime-locked package inline without it.

    FAILS on the pre-W3-2 tree (the six ci.yml jobs type `pydantic … cryptography … packaging`
    directly). First-party editable installs (`-e packages/core/vigil_core`) and the strix/SDK
    extras (not in the runtime locks) are correctly exempt.
    """
    runtime_names = set(_runtime_floors())
    offenders: list[str] = []
    for wf in _workflow_files():
        for line in _install_lines(wf.read_text(encoding="utf-8")):
            if "--require-hashes" in line:
                continue  # a hash-enforced install from a lock is exactly what we want
            for seg in _pip_install_segments(line):
                for spec in _specs_in_segment(seg):
                    name, _ = _spec_name_and_floor(spec)
                    if name in runtime_names:
                        offenders.append(f"{wf.name}: installs runtime '{spec}' WITHOUT --require-hashes")
    assert not offenders, (
        "these CI installs pull a runtime dependency without --require-hashes, so the resolved "
        "version is not pinned to the committed lock (W3-2):\n  " + "\n  ".join(sorted(offenders))
        + "\n\nReplace the inline runtime list with:\n"
        "  pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt\n"
        "  pip install -e packages/core/vigil_core --no-deps"
    )

    # NEGATIVE CONTROL: an inline runtime install IS flagged; the hash-locked form is NOT.
    def _flags(line: str) -> list[str]:
        found: list[str] = []
        if "--require-hashes" in line:
            return found
        for seg in _pip_install_segments(line):
            for spec in _specs_in_segment(seg):
                nm, _ = _spec_name_and_floor(spec)
                if nm in runtime_names:
                    found.append(spec)
        return found

    assert _flags('pip install "cryptography>=50" pydantic'), (
        "negative control broken: an inline runtime install is not flagged"
    )
    assert not _flags(
        "pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt"
    ), "false positive: a --require-hashes lock install must not be flagged"
    assert not _flags("pip install -e packages/core/vigil_core --no-deps"), (
        "false positive: a first-party editable install names no runtime lock package"
    )


def test_ci_tooling_lock_is_used_under_require_hashes() -> None:
    """W3-2: the pinned CI toolchain (pytest/ruff/mypy) is a committed hash lock CI installs from.

    Its existence/hashing/coverage are enforced by the parametrized LOCKS tests above (it is a
    member of LOCKS). This asserts the WIRING: ci.yml installs it under --require-hashes, so the
    harness is pinned too, not resolved fresh.
    """
    _, lock = LOCKS["ci-tooling"]
    rel = lock.relative_to(REPO_ROOT).as_posix()
    assert lock.is_file(), (
        f"missing {rel} — generate it with:\n"
        "  pip install pip-tools==7.6.1\n"
        "  pip-compile --generate-hashes --no-header --strip-extras "
        f"--output-file={rel} infra/supply-chain/ci-tooling.in"
    )
    covered = _pinned_names(lock)
    for tool in ("pytest", "pytest-asyncio", "ruff", "mypy"):
        assert _canon(tool) in covered, f"{rel} does not pin {tool}"

    ci = _strip_comments((REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    uses = [
        ln for ln in _logical_lines(ci)
        if "--require-hashes" in ln and rel in ln
    ]
    assert uses, (
        f"no ci.yml job installs {rel} under --require-hashes — the pinned toolchain is committed "
        "but never used, so pytest/ruff/mypy still resolve fresh."
    )


def _ci_tooling_direct_names() -> set[str]:
    """Canonical names of the DIRECT toolchain requirements the ci-tooling lock is compiled from.

    These are the tools a CI job types by name (pytest, pytest-asyncio, ruff, mypy). Reading them
    from the `.in` input — rather than hardcoding — means adding a tool to the toolchain lock
    automatically extends the inline-install ban below, so the guard cannot fall behind the lock.
    """
    in_file, _ = LOCKS["ci-tooling"]
    names: set[str] = set()
    for raw in in_file.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _REQ_NAME.match(line)
        if m:
            names.add(_canon(m.group(1)))
    assert {"pytest", "ruff", "mypy"} <= names, (
        f"ci-tooling.in no longer names pytest/ruff/mypy directly (parsed {sorted(names)}) — "
        "the toolchain-install guard would go blind; fix the parser or the input."
    )
    return names


def test_ci_installs_toolchain_only_under_require_hashes() -> None:
    """W3-2 (#425): pytest/ruff/mypy are a hash lock CI installs from — never typed inline unpinned.

    The runtime-floor and runtime-require-hashes guards above key on `_runtime_floors()`, which holds
    only the shipped RUNTIME packages (cryptography, pydantic, …). The lint/type/test TOOLCHAIN
    (pytest, ruff, mypy) is deliberately NOT in a runtime lock, so those guards are structurally
    BLIND to it: `pip install "ruff==0.15.12" mypy pytest` in lint-config.yml pinned only ruff and
    resolved mypy + pytest FRESH from PyPI on every run — the same "a lock nothing installs from is a
    document, not a control" gap the runtime section closes, one class over. This asserts NO workflow
    names a ci-tooling-locked tool inline without --require-hashes, so the whole toolchain is pinned
    to the committed ci-tooling lock, not resolved at run time.

    FAILS on the pre-fix tree (lint-config.yml's inline `mypy pytest`); the fixed tree installs the
    ci-tooling lock under --require-hashes instead.
    """
    tool_names = _ci_tooling_direct_names()
    offenders: list[str] = []
    for wf in _workflow_files():
        for line in _install_lines(wf.read_text(encoding="utf-8")):
            if "--require-hashes" in line:
                continue  # installed from a committed lock, hash-enforced — exactly the fix
            for seg in _pip_install_segments(line):
                for spec in _specs_in_segment(seg):
                    name, _ = _spec_name_and_floor(spec)
                    if name in tool_names:
                        offenders.append(
                            f"{wf.name}: installs toolchain '{spec}' WITHOUT --require-hashes"
                        )
    assert not offenders, (
        "these CI installs pull a pinned toolchain package (pytest/ruff/mypy) inline instead of from "
        "the hash lock, so the version pytest/ruff/mypy actually runs is not pinned to the committed "
        "lock (W3-2 #425):\n  " + "\n  ".join(sorted(offenders))
        + "\n\nReplace the inline toolchain list with:\n"
        "  pip install --require-hashes -r infra/supply-chain/ci-tooling.lock.txt"
    )

    # NEGATIVE CONTROL: the exact pre-fix line IS flagged; the hash-locked form is NOT — so this
    # test is not a no-op that would pass on the vulnerable tree.
    def _flags(line: str) -> list[str]:
        found: list[str] = []
        if "--require-hashes" in line:
            return found
        for seg in _pip_install_segments(line):
            for spec in _specs_in_segment(seg):
                nm, _ = _spec_name_and_floor(spec)
                if nm in tool_names:
                    found.append(spec)
        return found

    assert _flags('pip install "ruff==0.15.12" mypy pytest'), (
        "negative control broken: the pre-fix inline toolchain install is not flagged"
    )
    assert not _flags(
        "pip install --require-hashes -r infra/supply-chain/ci-tooling.lock.txt"
    ), "false positive: a --require-hashes ci-tooling lock install must not be flagged"


def test_shared_runtime_versions_agree_across_locks() -> None:
    """The offense and sovereign locks must pin every SHARED package to the same version.

    W3-2's lightweight CI jobs install the (light) offense framework lock for their third-party
    runtime subset even in sovereign-side jobs — legitimate because it holds only third-party
    packages (no `framework`/`sigil`, so FATAL-2 is untouched) and the sovereign lock's heavy ML
    stack is not needed by a pure-Python test. That reuse is only sound if the shared versions are
    identical; assert it, so a future divergence (CI testing a different cryptography than ships)
    fails loudly instead of silently.
    """
    off = _lock_versions(REPO_ROOT / "engine/crucible/framework/v2/requirements.lock.txt")
    sov = _lock_versions(REPO_ROOT / "infra/supply-chain/sovereign.lock.txt")
    shared = set(off) & set(sov)
    assert "cryptography" in shared, "cryptography is not shared across the locks — check the parser"
    mismatched = {n: (off[n], sov[n]) for n in shared if off[n] != sov[n]}
    assert not mismatched, (
        "the offense and sovereign locks disagree on shared packages, so a CI job installing the "
        "offense lock would test a different version than the sovereign deployment ships:\n  "
        + "\n  ".join(f"{n}: offense={o} sovereign={s}" for n, (o, s) in sorted(mismatched.items()))
    )


def test_ci_tooling_lock_agrees_with_runtime_locks_on_shared_packages() -> None:
    """Where the CI toolchain lock and a runtime lock pin the SAME package, the versions must match.

    The converted CI jobs run two hash-enforced installs in sequence — the runtime lock, then the
    ci-tooling lock. If a shared transitive (today: packaging, typing-extensions) were pinned to
    different versions across the two, the second `--require-hashes` install would silently change
    what the first pinned, so the tested tree would no longer equal the runtime lock. Assert the
    overlap agrees, so a future ci-tooling regeneration that bumps a shared dep fails HERE (offline)
    instead of as a confusing mid-install version change on a runner.
    """
    _, tooling = LOCKS["ci-tooling"]
    tool = _lock_versions(tooling)
    conflicts: list[str] = []
    for lock in RUNTIME_LOCKS:
        rt = _lock_versions(lock)
        for name in set(tool) & set(rt):
            if tool[name] != rt[name]:
                conflicts.append(
                    f"{name}: ci-tooling={tool[name]} {lock.name}={rt[name]}"
                )
    assert not conflicts, (
        "the CI toolchain lock disagrees with a runtime lock on a shared package, so the two "
        "sequential --require-hashes installs would fight over it:\n  " + "\n  ".join(sorted(conflicts))
    )
