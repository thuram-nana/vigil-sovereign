"""Guard: the commit-signing setup/verify tooling exists and its check is real ([W12-4] #493).

"Enforce signed commits" has two halves. The half the SERVER owns — branch protection's "Require
signed commits" on `main`, which rejects an unsigned push — is a repository-administration flip and is
NOT tested here (a repo cannot enable it from code; see docs/decisions/W12-4-enforce-signed-commits.md).
The half the REPOSITORY owns — that a contributor can configure and verify local commit signing before
they push — is what this guard pins:

  * `tools/governance/commit_signing.py` exposes `signing_config_defects(config)`, the pure check that
    decides whether a git config will produce signed commits, and it is CORRECT: it passes a fully
    configured signing setup and REJECTS one missing `commit.gpgsign` or `user.signingkey`;
  * `verify-commit-signing.sh` (the wrapper the docs point at) and `setup-commit-signing.sh` (the
    developer setup) both exist, are executable, and drive the same Python check — so there is one
    source of truth, not a shell reimplementation that could drift;
  * end-to-end, the check run against a REAL throwaway git repo returns clean when signing is configured
    and non-zero when it is not — the negative control that proves the gate is not a no-op.

FAILS WITHOUT THE CHANGE. Without `tools/governance/commit_signing.py` this module cannot import it and
collection errors red; with an empty/blank config `signing_config_defects` must report defects.

STDLIB ONLY (subprocess to a real `git`, which CI has). Framework-free and sigil-free, so it runs in the
required `integration two-env boundary (P5)` CI job. It configures signing purely as GIT CONFIG (no real
gpg/ssh key material is created or used), so it needs no signing backend installed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_GOV = _REPO / "tools" / "governance"
_MODULE = _GOV / "commit_signing.py"
_SETUP = _GOV / "setup-commit-signing.sh"
_VERIFY = _GOV / "verify-commit-signing.sh"

sys.path.insert(0, str(_GOV))
import commit_signing  # noqa: E402  (path set above; stdlib-only, imports neither trust domain)


# --------------------------------------------------------------------------------------------------
# The scripts exist and are wired to the one Python check.
# --------------------------------------------------------------------------------------------------
def test_signing_tooling_files_exist_and_are_executable():
    for p in (_MODULE, _SETUP, _VERIFY):
        assert p.is_file(), f"missing signing tool: {p.relative_to(_REPO)}"
        assert os.access(p, os.X_OK), f"not executable: {p.relative_to(_REPO)}"


def test_scripts_drive_the_single_python_check():
    verify = _VERIFY.read_text(encoding="utf-8")
    assert "commit_signing.py" in verify, "verify-commit-signing.sh must call the shared Python check"
    setup = _SETUP.read_text(encoding="utf-8")
    # The setup script must configure the three keys the check requires.
    for key in ("commit.gpgsign", "user.signingkey", "gpg.format"):
        assert key in setup, f"setup-commit-signing.sh does not configure {key}"
    # It must end by verifying, so a developer never leaves it half-configured.
    assert "verify-commit-signing.sh" in setup, "setup should hand off to the verify script"


# --------------------------------------------------------------------------------------------------
# The pure check is correct — positive and negative, in the same run.
# --------------------------------------------------------------------------------------------------
def test_signing_config_defects_passes_a_configured_setup():
    good = {"commit.gpgsign": "true", "user.signingkey": "ABC123", "gpg.format": "ssh"}
    assert commit_signing.signing_config_defects(good) == []


def test_signing_config_defects_accepts_openpgp_default_format():
    # gpg.format unset -> git's openpgp default, which is valid.
    good = {"commit.gpgsign": "true", "user.signingkey": "ABC123"}
    assert commit_signing.signing_config_defects(good) == []


def test_negative_control_unsigned_config_is_rejected():
    assert commit_signing.signing_config_defects({}), "an empty config must be rejected"
    no_sign = {"user.signingkey": "ABC123"}
    assert any("commit.gpgsign" in d for d in commit_signing.signing_config_defects(no_sign))
    no_key = {"commit.gpgsign": "true"}
    assert any("user.signingkey" in d for d in commit_signing.signing_config_defects(no_key))
    off = {"commit.gpgsign": "false", "user.signingkey": "ABC123"}
    assert any("commit.gpgsign" in d for d in commit_signing.signing_config_defects(off))


def test_negative_control_bogus_format_is_rejected():
    bad = {"commit.gpgsign": "true", "user.signingkey": "ABC123", "gpg.format": "banana"}
    assert any("gpg.format" in d for d in commit_signing.signing_config_defects(bad))


# --------------------------------------------------------------------------------------------------
# End-to-end against a REAL throwaway git repo: read_git_config + the CLI exit code.
# --------------------------------------------------------------------------------------------------
@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_end_to_end_verify_passes_when_configured_and_fails_when_not(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    # Isolate git config so the check sees ONLY this repo's config, not the developer machine's global
    # signing setup (which would otherwise leak in and make the negative control pass spuriously).
    home = tmp_path / "home"
    home.mkdir()
    iso = {
        **os.environ,
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=iso)

    # Unconfigured: read_git_config shows no signing, defects are reported, CLI exits non-zero.
    cfg0 = commit_signing.read_git_config(str(repo), env=iso)
    assert commit_signing.signing_config_defects(cfg0), f"a fresh isolated repo must not sign: {cfg0}"
    rc0 = subprocess.run(
        [sys.executable, str(_MODULE), str(repo)], capture_output=True, text=True, env=iso
    ).returncode
    assert rc0 != 0, "verify must FAIL on an unconfigured repo (negative control)"

    # Configure signing purely as git config (no real key material needed for the config check).
    subprocess.run(["git", "config", "commit.gpgsign", "true"], cwd=repo, check=True, env=iso)
    subprocess.run(["git", "config", "user.signingkey", "AAAA1111BBBB2222"], cwd=repo, check=True, env=iso)
    subprocess.run(["git", "config", "gpg.format", "ssh"], cwd=repo, check=True, env=iso)

    cfg1 = commit_signing.read_git_config(str(repo), env=iso)
    assert commit_signing.signing_config_defects(cfg1) == [], f"configured repo still flagged: {cfg1}"
    rc1 = subprocess.run(
        [sys.executable, str(_MODULE), str(repo)], capture_output=True, text=True, env=iso
    ).returncode
    assert rc1 == 0, "verify must PASS once signing is configured"
