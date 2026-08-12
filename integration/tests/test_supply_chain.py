"""A14 — supply-chain / packaging hardening, asserted STATICALLY (no network, no daemon).

These are the checks that must hold on every commit whether or not a runner has egress, so
they live here and are collected by the ordinary `pytest integration/tests` run as well as by
the dedicated "A14 supply-chain gate" job. Everything that genuinely needs the network
(resolving digests, compiling locks, fetching a vulnerability DB) happens in that job; what is
proven here is that the RESULT of that work is committed, complete and cannot silently rot:

  * every container base image in the repo is digest-pinned (a tag is a mutable pointer);
  * every committed dependency lock is genuinely hash-pinned and covers its own input;
  * the A14 workflow still declares the SBOM step, the artifact upload and a BLOCKING scan;
  * the workflow's third-party actions are SHA-pinned;
  * every vulnerability suppression carries a written justification.

The last one is the point of the whole exercise. A scan gate is only worth having if a
suppression costs someone a sentence of explanation; `.trivyignore` entries with no reason are
how a gate quietly becomes a no-op.

Pure stdlib + pytest, so this file adds nothing to the dependency surface it audits.
"""

from __future__ import annotations

import importlib.util
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "supply-chain.yml"
TRIVYIGNORE = REPO_ROOT / ".trivyignore"

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
}

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
    """The gate must BLOCK on something. Documented threshold: CRITICAL blocks, HIGH reports.

    Find the trivy invocation that carries `--exit-code 1` and assert CRITICAL is in its
    severity set. Lowering the blocking tier below CRITICAL should require editing this test,
    i.e. it should be a decision, not a drive-by.
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


def test_a14_workflow_actions_are_sha_pinned() -> None:
    """A GitHub Action reference is a supply-chain dependency like any other.

    `actions/checkout@v4` is a mutable TAG on someone else's repository, executing with the
    workflow's token. Pin the new workflow's actions to full commit SHAs.

    HONEST SCOPE: this asserts it for the A14 workflow only. The pre-existing jobs in ci.yml
    are still tag-pinned; converting them is a separate change with a wider blast radius and
    is recorded as a follow-up in docs/SUPPLY-CHAIN.md rather than smuggled in here.
    """
    body = _strip_comments(WORKFLOW.read_text(encoding="utf-8"))
    uses = re.findall(r"uses:\s*(\S+)", body)
    assert uses, "the A14 workflow uses no actions at all — did the file get truncated?"
    unpinned = [u for u in uses if not re.search(r"@[0-9a-f]{40}$", u)]
    assert not unpinned, (
        "these action references are not pinned to a full commit SHA: "
        f"{unpinned}\nPin with:  gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha"
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
