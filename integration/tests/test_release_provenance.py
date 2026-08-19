"""W3-4 — the BUILD signs itself: release-workflow shape, asserted STATICALLY (no network).

Everywhere else in this repo the *product* signs what it emits. Until this slice the *build* of
the product signed nothing (docs/SUPPLY-CHAIN.md said so outright). `.github/workflows/release.yml`
closes that: on a tag push it builds the `vigil-core` wheel + sdist and attaches, to every
artifact, a Sigstore/cosign signature, an SLSA build-provenance attestation, and a PEP 740
attestation for the wheel — each third-party-verifiable offline.

That workflow is TAG-TRIGGERED, so it never reports on the pull request that adds it. Its
correctness therefore has to be pinned by a test that runs on every PR instead. This file is that
pin. It runs in the required "integration two-env boundary (P5)" job (it lives under
integration/tests and is not in that job's --ignore list) and asserts, offline:

  * the workflow exists and its YAML parses;
  * it is triggered by a tag push (`on: push: tags`), not by pull_request;
  * it SIGNS (sigstore/cosign), ATTESTS SLSA provenance (actions/attest-build-provenance) and
    produces PEP 740 attestations for wheels;
  * it runs the offline verifier over the artifacts it just built, and that verifier carries a
    tamper NEGATIVE CONTROL;
  * every third-party action it uses is pinned to a full commit SHA.

FAILS WITHOUT THE FIX: on a tree with no release.yml the first test errors on the missing file.
NEGATIVE CONTROL: test_the_release_shape_check_is_load_bearing feeds the SAME checker a workflow
with the signing/attest/PEP-740 legs removed and asserts each removal is caught — so a green pass
here means the legs are present, not that the checker is asleep.

Pure stdlib + PyYAML + pytest.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE = REPO_ROOT / ".github" / "workflows" / "release.yml"
VERIFIER = REPO_ROOT / ".github" / "scripts" / "verify-release-artifacts.sh"
REQUIRED_CHECKS = REPO_ROOT / ".github" / "required-status-checks.txt"


def _strip_comments(text: str) -> str:
    """Drop whole-line comments so a commented-out step cannot satisfy an assertion."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


#: Each leg is something a future edit could quietly drop while the file still parses. Keyed by a
#: human reason -> a substring that must survive comment-stripping. Case-insensitive match.
_LEGS: dict[str, str] = {
    "builds a distribution to sign": "python -m build",
    "installs cosign (sigstore)": "sigstore/cosign-installer",
    "signs every artifact with cosign": "cosign sign-blob",
    "emits SLSA build provenance": "actions/attest-build-provenance",
    "produces PEP 740 attestations for wheels": "pypi_attestations sign",
    "verifies the artifacts it just built": "verify-release-artifacts.sh",
    "the verify step carries a tamper negative control": "negative control",
}


def _missing_legs(text: str) -> list[str]:
    """Factored out so the real file and the mutation control exercise the SAME checker."""
    body = _strip_comments(text).lower()
    return [f"{why} ({needle!r})" for why, needle in _LEGS.items() if needle.lower() not in body]


def _on_block(data: dict):
    """PyYAML (YAML 1.1) parses the `on:` key as the boolean True — handle both spellings."""
    if True in data:
        return data[True]
    return data.get("on")


def _uses_refs(text: str) -> list[str]:
    return re.findall(r"uses:\s*(\S+)", _strip_comments(text))


# ======================================================================================
# 1. Existence + it parses
# ======================================================================================


def test_release_workflow_exists_and_yaml_parses() -> None:
    """FAILS WITHOUT THE FIX: no release.yml on the pre-slice tree."""
    yaml = pytest.importorskip("yaml")
    assert RELEASE.is_file(), (
        f"missing {RELEASE.relative_to(REPO_ROOT)} — the build signs nothing without it "
        "(docs/SUPPLY-CHAIN.md §'No signature verification')"
    )
    data = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    assert isinstance(data, dict) and "jobs" in data, "release.yml has no jobs block"


# ======================================================================================
# 2. It is tag-triggered (and not a pull_request workflow)
# ======================================================================================


def test_release_workflow_is_tag_triggered() -> None:
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    on = _on_block(data)
    assert isinstance(on, dict), f"release.yml `on:` is not a mapping: {on!r}"
    push = on.get("push")
    assert isinstance(push, dict) and push.get("tags"), (
        "release.yml must trigger on a TAG push (`on: push: tags: [...]`); got "
        f"on={on!r}. A signing workflow that fires on branch pushes or PRs would sign "
        "unreleased commits."
    )
    tags = push["tags"]
    assert any(str(t).startswith("v") for t in tags), (
        f"expected a version-tag pattern like 'v*' under push.tags; got {tags!r}"
    )
    # A release/signing workflow keyed on pull_request would sign every PR head — assert it is not.
    assert "pull_request" not in on, (
        "release.yml must not be pull_request-triggered — it signs release artifacts"
    )


# ======================================================================================
# 3. It signs, attests, and publishes PEP 740 — the whole point of the slice
# ======================================================================================


def test_release_workflow_signs_attests_and_publishes_pep740() -> None:
    assert RELEASE.is_file(), f"missing {RELEASE}"
    missing = _missing_legs(RELEASE.read_text(encoding="utf-8"))
    assert not missing, "release.yml no longer declares:\n  " + "\n  ".join(missing)


# ======================================================================================
# 4. It verifies what it built, with a tamper negative control living in the verifier
# ======================================================================================


def test_release_workflow_verifier_is_wired_and_has_a_negative_control() -> None:
    assert VERIFIER.is_file(), f"missing {VERIFIER}"
    assert VERIFIER.stat().st_mode & stat.S_IXUSR, f"{VERIFIER} is not executable"
    body = _strip_comments(RELEASE.read_text(encoding="utf-8"))
    assert "verify-release-artifacts.sh" in body, (
        "the release workflow does not call the offline verifier — the verify + tamper checks "
        "would be dead code"
    )
    script = VERIFIER.read_text(encoding="utf-8")
    assert "cosign verify-blob" in script and "--offline" in script, (
        "the verifier must do an OFFLINE cosign verify (third-party verifiability is the "
        "acceptance criterion)"
    )
    # The tamper negative control must actually mutate bytes and require rejection.
    assert "NEGATIVE CONTROL" in script and "tamper" in script.lower(), (
        "the verifier must carry a tamper negative control proving it is not a no-op"
    )
    assert re.search(r"NEGATIVE CONTROL FAILED", script), (
        "the verifier must FAIL when a tampered artifact passes verification"
    )


# ======================================================================================
# 5. Every action is SHA-pinned
# ======================================================================================


def test_release_workflow_actions_are_sha_pinned() -> None:
    """A `@v4` tag is a mutable pointer on someone else's repo, running with this workflow's token."""
    uses = _uses_refs(RELEASE.read_text(encoding="utf-8"))
    assert uses, "release.yml uses no actions at all — did the file get truncated?"
    unpinned = [u for u in uses if not re.search(r"@[0-9a-f]{40}$", u)]
    assert not unpinned, (
        "these action references are not pinned to a full commit SHA: "
        f"{unpinned}\nPin with:  gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha"
    )


# ======================================================================================
# 6. It stays ADVISORY — a tag-triggered job can never be a required PR check
# ======================================================================================


def test_release_workflow_is_not_listed_as_a_required_check() -> None:
    """A required check must be produced by a pull_request-triggered job; this one never is.

    Listing any release-workflow job name in required-status-checks.txt would block every PR
    forever (the job never reports on a PR). Assert none of its job names leak into that file.
    """
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    job_names = {
        j.get("name") for j in data["jobs"].values() if isinstance(j, dict) and j.get("name")
    }
    required = {
        ln.strip()
        for ln in REQUIRED_CHECKS.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    }
    leaked = job_names & required
    assert not leaked, (
        f"release.yml job name(s) {leaked} are in required-status-checks.txt; a tag-triggered "
        "job never reports on a PR, so requiring it would block every pull request forever"
    )


# ======================================================================================
# NEGATIVE CONTROL — the shape checker must bite on deliberately-broken workflow text
# ======================================================================================


def test_the_release_shape_check_is_load_bearing() -> None:
    """Feed the SAME checker a workflow with each leg removed; each removal must be caught.

    Without this, `_missing_legs` returning [] would be indistinguishable from a checker that
    matches nothing.
    """
    real = RELEASE.read_text(encoding="utf-8")
    assert _missing_legs(real) == [], "precondition: the real workflow declares every leg"

    # Drop the cosign signing lines -> signing legs must be flagged.
    no_sign = "\n".join(
        ln for ln in real.splitlines()
        if "cosign sign-blob" not in ln and "cosign-installer" not in ln
    )
    flagged = _missing_legs(no_sign)
    assert any("cosign" in f for f in flagged), (
        f"removing cosign was not detected by the shape checker; flagged={flagged}"
    )

    # Drop the provenance action -> SLSA leg must be flagged.
    no_slsa = "\n".join(ln for ln in real.splitlines() if "attest-build-provenance" not in ln)
    assert any("SLSA" in f for f in _missing_legs(no_slsa)), "removing SLSA provenance was not detected"

    # Drop the PEP 740 signer -> PEP 740 leg must be flagged.
    no_pep = "\n".join(ln for ln in real.splitlines() if "pypi_attestations sign" not in ln)
    assert any("PEP 740" in f for f in _missing_legs(no_pep)), "removing PEP 740 was not detected"

    # A comment mentioning cosign must NOT satisfy the signing leg (comment-strip is load-bearing).
    commented = re.sub(r"^(\s*)(cosign sign-blob.*)$", r"\1# \2", real, flags=re.MULTILINE)
    assert any("cosign sign-blob" in f for f in _missing_legs(commented)), (
        "a commented-out `cosign sign-blob` line still satisfied the signing leg — the "
        "comment-strip guard is not working"
    )


def test_the_sha_pin_check_is_load_bearing() -> None:
    """NEGATIVE CONTROL for the SHA-pin rule: a tag-pinned `uses:` must be flagged."""
    tag_pinned = "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n"
    uses = _uses_refs(tag_pinned)
    unpinned = [u for u in uses if not re.search(r"@[0-9a-f]{40}$", u)]
    assert unpinned == ["actions/checkout@v4"], (
        "the SHA-pin detector failed to flag a tag-pinned action reference"
    )
