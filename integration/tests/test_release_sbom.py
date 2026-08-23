"""W3-5 #428 — every release carries a SIGNED SBOM, retrievable independently of CI retention.

The defect: the only bill of materials the product produced lived in a 90-day CI artifact
(`a14-sbom-cyclonedx`), never committed and never attached to a release — so a deployed artifact had
no retrievable SBOM. `.github/workflows/release.yml` (tag push only) now, for each shipped dependency
closure (offense + sovereign):

  * generates the CycloneDX SBOM from the hash-pinned lock AND cross-checks it against that lock with
    the SAME check the A14 gate runs (`bin/verify-supply-chain.sh`);
  * cosign-signs it with the SAME keyless primitive as the release wheel (no new signing scheme — a
    vigil_core Ed25519/DSSE signature would need a long-lived key on the runner, which keyless OIDC
    exists to avoid);
  * ATTACHES it, with its offline-verifiable cosign bundle, to the GitHub RELEASE — a durable asset
    that does not expire with CI artifact retention.

The release workflow is TAG-triggered, so it never reports on the PR that changes it. Its correctness
is pinned instead by THIS file, which runs in the required "integration two-env boundary (P5)" job
(it lives under integration/tests and is not in that job's --ignore list) and asserts, offline:

  * release.yml generates + cross-checks + cosign-signs + durably attaches the SBOMs;
  * the offline release verifier re-runs the component cross-check against the attached SBOM bytes and
    carries an omit-a-component negative control;
  * the cross-check itself — infra/supply-chain/sbom_crosscheck.py — actually fails when a shipped
    component is missing from the SBOM (the functional negative control, in the same run).

FAILS WITHOUT THE FIX: on a tree whose release.yml has no SBOM steps, the shape tests error/assert.
NEGATIVE CONTROL: test_crosscheck_fails_when_a_component_is_omitted feeds the cross-check an SBOM with
a component removed and requires a non-empty result — a green pass here means the check works, not
that it is asleep.

Pure stdlib + PyYAML + pytest.
"""

from __future__ import annotations

import importlib.util
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE = REPO_ROOT / ".github" / "workflows" / "release.yml"
VERIFIER = REPO_ROOT / ".github" / "scripts" / "verify-release-artifacts.sh"
CROSSCHECK = REPO_ROOT / "infra" / "supply-chain" / "sbom_crosscheck.py"
SOVEREIGN_LOCK = REPO_ROOT / "infra" / "supply-chain" / "sovereign.lock.txt"


def _strip_comments(text: str) -> str:
    """Drop whole-line comments so a commented-out step cannot satisfy an assertion."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _load_crosscheck():
    """Load infra/supply-chain/sbom_crosscheck.py by path (it is not on the import path)."""
    assert CROSSCHECK.is_file(), f"missing {CROSSCHECK} — the SBOM cross-check is the W3-5 enforcer"
    name = "vigil_sbom_crosscheck"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, CROSSCHECK)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        del sys.modules[name]
        raise
    return mod


# ======================================================================================
# 1. release.yml generates, cross-checks, signs and DURABLY attaches the SBOMs
# ======================================================================================

#: Each leg is something a future edit could quietly drop while the file still parses. Keyed by a
#: human reason -> a substring that must survive comment-stripping. Case-insensitive match.
_SBOM_LEGS: dict[str, str] = {
    "generates SBOMs via the existing generator/cross-check": "verify-supply-chain.sh",
    "writes an SBOM into the release dir": "sbom-sovereign.cdx.json",
    "cosign-signs the SBOMs (same primitive as the wheel)": "dist/*.cdx.json",
    "attaches SBOMs to the GitHub Release (durable, not a CI artifact)": "gh release upload",
    "runs the offline verifier over what it built": "verify-release-artifacts.sh",
}


def test_release_workflow_exists_and_yaml_parses() -> None:
    yaml = pytest.importorskip("yaml")
    assert RELEASE.is_file(), f"missing {RELEASE.relative_to(REPO_ROOT)}"
    data = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    assert isinstance(data, dict) and "jobs" in data, "release.yml has no jobs block"


def test_release_workflow_generates_signs_and_durably_attaches_sboms() -> None:
    """FAILS WITHOUT THE FIX: a release.yml with no SBOM legs is missing every needle below."""
    assert RELEASE.is_file(), f"missing {RELEASE}"
    body = _strip_comments(RELEASE.read_text(encoding="utf-8")).lower()
    missing = [f"{why} ({needle!r})" for why, needle in _SBOM_LEGS.items()
               if needle.lower() not in body]
    assert not missing, "release.yml no longer declares:\n  " + "\n  ".join(missing)


def test_release_sbom_is_attached_to_the_release_not_only_a_ci_artifact() -> None:
    """The whole point of #428: durability independent of CI artifact RETENTION. A GitHub Release
    asset is durable; `actions/upload-artifact` (90-day) is not. Assert the SBOMs reach the RELEASE."""
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    body = _strip_comments(RELEASE.read_text(encoding="utf-8"))
    assert "gh release upload" in body, (
        "release.yml does not attach the SBOMs to the GitHub Release — they would live only in the "
        "90-day CI artifact this issue exists to move off of (#428)"
    )
    # The attaching job must hold `contents: write`, or `gh release upload` cannot write the asset.
    job = data["jobs"]["build-sign-attest"]
    perms = job.get("permissions", {})
    assert perms.get("contents") == "write", (
        "the release job needs `contents: write` to attach release assets; got "
        f"contents={perms.get('contents')!r}"
    )


def test_release_workflow_signs_the_sboms_with_the_existing_cosign_primitive() -> None:
    """Reuse, not invention: the SBOM is signed with cosign, exactly as the wheel is, so the SAME
    offline verifier and tamper control cover it."""
    body = _strip_comments(RELEASE.read_text(encoding="utf-8"))
    assert "cosign sign-blob" in body, "release.yml no longer cosign-signs anything"
    # The signing loop must include the SBOMs, not only the distributions.
    assert re.search(r"cosign sign-blob.*|dist/\*\.cdx\.json", body), \
        "the cosign signing loop does not include the SBOMs (dist/*.cdx.json)"
    assert "dist/*.cdx.json" in body, "the cosign signing loop does not sign the SBOMs"


# ======================================================================================
# 2. The offline verifier re-runs the cross-check against the attached bytes, with a neg control
# ======================================================================================


def test_verifier_crosschecks_the_released_sbom_with_a_negative_control() -> None:
    assert VERIFIER.is_file(), f"missing {VERIFIER}"
    assert VERIFIER.stat().st_mode & stat.S_IXUSR, f"{VERIFIER} is not executable"
    script = VERIFIER.read_text(encoding="utf-8")
    assert "sbom_crosscheck.py" in script, (
        "the release verifier does not re-run the component cross-check against the SBOM it is about "
        "to attach (#428)"
    )
    # The verifier must refuse a release that carries no SBOM (no vacuous pass), and must carry an
    # omit-a-component negative control that requires the check to FAIL.
    assert "no *.cdx.json" in script and "VACUOUS PASS" in script, (
        "the verifier does not refuse a release with no SBOM — a missing SBOM would pass silently"
    )
    assert "NEGATIVE CONTROL" in script and "dropped component" in script.lower(), (
        "the verifier lacks an omit-a-component negative control for the SBOM cross-check"
    )
    assert "NEGATIVE CONTROL FAILED" in script, (
        "the verifier must FAIL if an SBOM missing a component passes the cross-check"
    )


# ======================================================================================
# 3. The cross-check itself works — and FAILS when a component is omitted (functional neg control)
# ======================================================================================


def test_crosscheck_passes_a_complete_sbom_and_fails_an_incomplete_one() -> None:
    """POSITIVE + NEGATIVE CONTROL in one run, against the REAL sovereign lock.

    A synthetic SBOM listing every locked component cross-checks clean; the same SBOM with one
    component removed reports exactly that component as missing. This is the omit-a-component
    acceptance criterion, exercised on the enforcing function itself."""
    scc = _load_crosscheck()
    assert SOVEREIGN_LOCK.is_file(), f"missing {SOVEREIGN_LOCK}"
    lock_text = SOVEREIGN_LOCK.read_text(encoding="utf-8")
    locked = scc.locked_components(lock_text)
    assert len(locked) >= 10, f"the sovereign lock parsed to only {len(locked)} components — suspicious"

    complete = {"components": [{"name": n, "version": v} for n, v in sorted(locked)]}
    assert scc.missing_components(lock_text, complete) == [], (
        "a complete SBOM reported missing components — the cross-check is over-strict"
    )

    dropped = sorted(locked)[0]
    incomplete = {"components": [{"name": n, "version": v} for n, v in sorted(locked)
                                 if (n, v) != dropped]}
    missing = scc.missing_components(lock_text, incomplete)
    assert missing == [dropped], (
        f"NEGATIVE CONTROL: an SBOM missing {dropped} was not flagged; got {missing}"
    )


def test_crosscheck_refuses_a_vacuous_pass_on_an_empty_lock() -> None:
    """Fail-closed: an empty/garbage lock must not read as "nothing missing, all good"."""
    scc = _load_crosscheck()
    with pytest.raises(ValueError):
        scc.missing_components("# no pins here\n", {"components": [{"name": "x", "version": "1"}]})


def test_crosscheck_cli_exit_codes(tmp_path) -> None:
    """The CLI the release verifier calls: exit 0 on complete, exit 1 on an omission, exit 2 on IO.

    Exercises the actual subprocess path, so a change that broke the CLI wiring (not just the pure
    function) is caught."""
    scc = _load_crosscheck()
    lock_text = SOVEREIGN_LOCK.read_text(encoding="utf-8")
    locked = sorted(scc.locked_components(lock_text))

    complete = tmp_path / "complete.cdx.json"
    complete.write_text(json.dumps({"components": [{"name": n, "version": v} for n, v in locked]}))
    incomplete = tmp_path / "incomplete.cdx.json"
    incomplete.write_text(json.dumps(
        {"components": [{"name": n, "version": v} for n, v in locked[1:]]}))

    def run(sbom: Path) -> int:
        return subprocess.run(
            [sys.executable, str(CROSSCHECK), "--lock", str(SOVEREIGN_LOCK), "--sbom", str(sbom)],
            capture_output=True, text=True,
        ).returncode

    assert run(complete) == 0, "CLI did not exit 0 on a complete SBOM"
    assert run(incomplete) == 1, "CLI did not exit 1 on an SBOM missing a shipped component"
    assert run(tmp_path / "does-not-exist.json") == 2, "CLI did not exit 2 on a missing SBOM file"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
