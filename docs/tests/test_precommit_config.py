"""The pre-commit gate exists, is complete, and is really pinned — proven offline (W2-5, #422).

WHY THIS TEST EXISTS. Before this change every local commit was unchecked: no `.pre-commit-config.yaml`
existed, so the lint/secret/doc-truth checks ran only after a push, and a `git commit --no-verify`
bypassed nothing because there was nothing to bypass. This test is the pin that keeps the gate honest:
it fails on a tree WITHOUT the config, it proves every promised hook is listed, it proves the
third-party hook repos are pinned to an immutable ref (not a moving branch), and it proves the gitleaks
allowlist is a scoped set of synthetic paths rather than a blanket "off" switch.

It rides the already-required "the briefing explains every agent and capability" job (`pytest docs/tests
-q`), which installs ONLY pytest and reads files, so this test imports nothing beyond the standard
library and hand-parses the config (the file has a fixed, simple shape).

NEGATIVE CONTROLS. The pure helpers take their data as an argument precisely so a deliberately-bad
config can be fed to the SAME checker in-process and shown to be REJECTED — the gate is not a no-op.
The real TOOL-level negative controls (a planted secret caught by gitleaks, an undefined name caught by
ruff, a malformed workflow caught by yamllint) run in the advisory `.github/workflows/pre-commit.yml`
job, where the tools are installed; `test_ci_leg_carries_negative_controls` asserts those steps exist.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / ".pre-commit-config.yaml"
GITLEAKS = REPO / ".gitleaks.toml"
MYPY_HOOK = REPO / "tools" / "governance" / "mypy_can_complete.sh"
WORKFLOW = REPO / ".github" / "workflows" / "pre-commit.yml"
CANONICAL = REPO / ".github" / "required-status-checks.txt"

# The hooks the workstream (#422) requires the config to carry.
REQUIRED_HOOK_IDS = {
    "trailing-whitespace",
    "end-of-file-fixer",
    "check-yaml",           # YAML parse-validity (part of the hygiene/workflow surface)
    "ruff",                 # linter (E9/F/B)
    "gitleaks",             # secret scanning
    "mypy-sigil-can-complete",  # mypy fast subset
    "workflow-lint",        # yamllint over the workflows
    "claims-doc-truth",     # claims / doc-truth
}

# Refs that are NOT immutable — a hook pinned to one of these can change under you between runs.
_MUTABLE_REFS = {"main", "master", "head", "stable", "latest", "develop", "trunk"}


# --------------------------------------------------------------------------------------------------
# Dependency-free parse of the config (PyYAML is not installed in the briefing job).
# --------------------------------------------------------------------------------------------------
def parse_repos(text: str) -> list[dict]:
    """[{'repo': url, 'rev': str|None, 'hooks': [id, ...]}, ...] in file order."""
    repos: list[dict] = []
    cur: dict | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        m = re.match(r"^\s*-\s*repo:\s*(\S+)\s*$", line)
        if m:
            cur = {"repo": m.group(1), "rev": None, "hooks": []}
            repos.append(cur)
            continue
        if cur is None:
            continue
        r = re.match(r"^\s*rev:\s*(\S+)\s*$", line)
        if r:
            cur["rev"] = r.group(1)
            continue
        h = re.match(r"^\s*-\s*id:\s*(\S+)\s*$", line)
        if h:
            cur["hooks"].append(h.group(1))
    return repos


def all_hook_ids(text: str) -> set[str]:
    ids: set[str] = set()
    for repo in parse_repos(text):
        ids.update(repo["hooks"])
    return ids


def missing_required_hooks(text: str) -> set[str]:
    return REQUIRED_HOOK_IDS - all_hook_ids(text)


def unpinned_third_party_repos(text: str) -> list[str]:
    """Remote repos whose rev is absent or a MUTABLE ref (a moving branch, not a tag/SHA)."""
    bad: list[str] = []
    for repo in parse_repos(text):
        if repo["repo"] == "local":
            continue
        rev = repo["rev"]
        if not rev:
            bad.append(f"{repo['repo']} (no rev)")
            continue
        if rev.lower().strip("'\"") in _MUTABLE_REFS:
            bad.append(f"{repo['repo']} (mutable ref {rev!r})")
            continue
        is_tag = bool(re.match(r"^v?\d+(\.\d+)*[\w.-]*$", rev))
        is_sha = bool(re.match(r"^[0-9a-fA-F]{40}$", rev))
        if not (is_tag or is_sha):
            bad.append(f"{repo['repo']} (rev {rev!r} is neither a version tag nor a 40-hex SHA)")
    return bad


def gitleaks_allowlist_paths(text: str) -> list[str]:
    """The `paths = [...]` entries of the [allowlist] table (dependency-free)."""
    m = re.search(r"paths\s*=\s*\[(.*?)\]", text, re.S)
    if not m:
        return []
    body = m.group(1)
    out: list[str] = []
    # TOML string forms: '''triple''', "double", 'single'. Each match yields three groups; one is set.
    for triple, double, single in re.findall(r"'''(.*?)'''|\"(.*?)\"|'(.*?)'", body, re.S):
        out.append(triple or double or single)
    return out


def allowlist_is_a_blanket_disable(text: str) -> bool:
    """True if the allowlist matches EVERYTHING (a catch-all path) — i.e. secret scanning is off."""
    catch_all = {".*", "^.*$", ".+", "^.+$", "", "/", "."}
    for p in gitleaks_allowlist_paths(text):
        if p.strip() in catch_all:
            return True
    return False


# --------------------------------------------------------------------------------------------------
# The tests (real tree).
# --------------------------------------------------------------------------------------------------
def test_config_exists():
    """Fails on a tree without this change — the whole point of the workstream."""
    assert CONFIG.is_file(), ".pre-commit-config.yaml is missing from the repo root"


def test_all_required_hooks_present():
    missing = missing_required_hooks(CONFIG.read_text(encoding="utf-8"))
    assert not missing, f"the pre-commit config is missing required hooks: {sorted(missing)}"


def test_third_party_hooks_are_pinned():
    bad = unpinned_third_party_repos(CONFIG.read_text(encoding="utf-8"))
    assert not bad, "third-party hook repos must be pinned to an immutable tag/SHA, not a branch:\n" + "\n".join(bad)


def test_gitleaks_config_present_and_not_disabled():
    assert GITLEAKS.is_file(), ".gitleaks.toml is missing (gitleaks would scan with no allowlist and fail)"
    text = GITLEAKS.read_text(encoding="utf-8")
    assert "useDefault = true" in text, ".gitleaks.toml must extend the upstream default ruleset"
    assert not allowlist_is_a_blanket_disable(text), (
        "the gitleaks allowlist is a catch-all — that turns secret scanning OFF, defeating the gate"
    )
    assert gitleaks_allowlist_paths(text), "expected a scoped allowlist of synthetic-fixture paths"


def test_mypy_hook_script_is_executable():
    assert MYPY_HOOK.is_file(), f"{MYPY_HOOK} is missing"
    mode = MYPY_HOOK.stat().st_mode
    assert mode & stat.S_IXUSR, f"{MYPY_HOOK} must be executable (pre-commit runs it as a script)"


def test_ci_leg_exists_and_runs_the_same_hooks():
    """The gate re-runs in CI so `--no-verify` cannot bypass it."""
    assert WORKFLOW.is_file(), "the pre-commit CI workflow is missing (local hook could be bypassed)"
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "pre-commit run --all-files" in text, "the CI leg must run the same pre-commit hooks over the tree"


def test_ci_leg_carries_negative_controls():
    """The CI leg proves the gate is not a no-op: bad input is rejected there too."""
    text = WORKFLOW.read_text(encoding="utf-8")
    for needle in ("negative control", "gitleaks", "ruff", "workflow-lint"):
        assert needle in text, f"the CI leg is missing its {needle!r} negative control"


def test_advisory_not_in_required_set():
    """The new workflow is ADVISORY: its job name is deliberately NOT a required check (W0-1/W0-2)."""
    canonical = CANONICAL.read_text(encoding="utf-8")
    # The advisory job name must not be listed as required.
    assert "pre-commit hooks (advisory)" not in canonical, (
        "the advisory pre-commit job must not be added to the required-status-checks canonical list"
    )


# --------------------------------------------------------------------------------------------------
# Negative controls — the checkers must REPORT a bad config, not wave it through.
# --------------------------------------------------------------------------------------------------
_MINIMAL_GOOD = """
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.12
    hooks:
      - id: ruff
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
  - repo: local
    hooks:
      - id: mypy-sigil-can-complete
      - id: workflow-lint
      - id: claims-doc-truth
"""


def test_negative_control_missing_hook_is_reported():
    good = _MINIMAL_GOOD
    assert not missing_required_hooks(good), "sanity: the minimal good config lists every required hook"
    # Drop ruff -> the checker must flag it.
    bad = good.replace("      - id: ruff\n", "")
    assert "ruff" in missing_required_hooks(bad), "a config missing the ruff hook must be flagged"


def test_negative_control_unpinned_rev_is_reported():
    good = _MINIMAL_GOOD
    assert not unpinned_third_party_repos(good), "sanity: the minimal good config is fully pinned"
    bad = good.replace("    rev: v8.21.2\n", "    rev: main\n")
    flagged = unpinned_third_party_repos(bad)
    assert any("mutable ref" in f for f in flagged), f"a gitleaks repo pinned to `main` must be flagged: {flagged}"
    # And a wholly missing rev is flagged too.
    bad2 = good.replace("    rev: v5.0.0\n", "")
    assert any("no rev" in f for f in unpinned_third_party_repos(bad2)), "a repo with no rev must be flagged"


def test_negative_control_blanket_allowlist_is_reported():
    scoped = "[extend]\nuseDefault = true\n[allowlist]\npaths = [\n  '''(^|/)tests?/''',\n]\n"
    assert not allowlist_is_a_blanket_disable(scoped), "sanity: a scoped allowlist is not a blanket disable"
    blanket = "[extend]\nuseDefault = true\n[allowlist]\npaths = [\n  '''.*''',\n]\n"
    assert allowlist_is_a_blanket_disable(blanket), "a catch-all allowlist (turns scanning off) must be flagged"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
