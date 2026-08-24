"""Guard: the repository-root CODEOWNERS assigns an explicit owner to every security-critical path.

[W12-3] #492. A CODEOWNERS file requests a review from the named owners; branch protection's "Require
review from Code Owners" turns that request into a merge gate (that flip is a human/admin step — see
docs/decisions/W12-3-require-code-owner-review.md — and is deliberately NOT asserted here, because this
repository cannot enable it from code). What this repository CAN own from code is that the file itself
is correct: it lives where GitHub actually reads it, it has a catch-all, and — the point of this guard —
every security-critical trust domain carries its OWN explicit rule rather than silently inheriting the
generic `*` catch-all.

WHY EXPLICIT RULES MATTER. With a `*  @owner` catch-all, every path is nominally "owned", so a naive
"is this path covered?" check passes vacuously. The failure mode this guard exists to catch is subtler:
a second maintainer is added to `*`, and now they inherit review authority over the veracity firewall,
the egress gate, the supply-chain pins and the governance policy itself — trust roots that should be
called out, not inherited by accident. So the guard asserts each critical prefix has a rule MORE
SPECIFIC than `*` (in CODEOWNERS the last matching, most specific rule wins), that its owners are
well-formed handles, and that the path it names still exists in the tree (a rule that points at a
deleted directory is dead governance).

FAILS WITHOUT THE CHANGE. On the tree before #492's CODEOWNERS additions, `/.github/`,
`/tools/governance/`, `/infra/supply-chain/`, `/formal/` and `/packages/core/vigil_core/` had no
explicit rule — they sat under the bare catch-all — so `codeowners_coverage_defects` reports them and
`test_root_codeowners_covers_every_critical_path` is red. `git stash` the CODEOWNERS change and run this
file to see it.

STDLIB ONLY, framework-free and sigil-free (pure file reads + a small text parser), so it runs in the
required `integration two-env boundary (P5)` CI job, which collects the whole `integration/tests` tree.
Keep it out of any `--ignore` there.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# The three paths GitHub reads a repository CODEOWNERS from, in precedence order (all relative to root).
_GITHUB_CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")

# A well-formed owner token: @user, @org/team, or a bare email. Anything else (a plain word, an empty
# `@`) is a malformed rule GitHub silently ignores — the ownership it looks like it grants is not real.
_OWNER = re.compile(
    r"^(?:@[A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9._-]+)?"
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})$"
)

# The security-critical trust domains that MUST each carry their own explicit (non-catch-all) rule.
# Kept in agreement with .github/CODEOWNERS by this very test. Each is a directory that exists in-tree.
_CRITICAL_PREFIXES = (
    "/engine/crucible/framework/v2/verify/",
    "/engine/crucible/framework/v2/veracity/",
    "/integration/vigil_integration/live/",
    "/gateway/",
    "/tools/egress-guard/",
    "/.github/workflows/",
    "/.github/",
    "/tools/governance/",
    "/infra/supply-chain/",
    "/formal/",
    "/packages/core/vigil_core/",
)


def parse_codeowners(text: str) -> list[tuple[str, list[str]]]:
    """(pattern, [owners]) for each non-comment, non-blank CODEOWNERS line, in file order."""
    rules: list[tuple[str, list[str]]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        rules.append((parts[0], parts[1:]))
    return rules


def _tree_path_for_pattern(pattern: str) -> str | None:
    """Map a leading-slash directory pattern (`/tools/governance/`) to its repo-relative path.
    Returns None for the catch-all or a non-anchored glob (nothing to existence-check)."""
    if pattern == "*" or not pattern.startswith("/"):
        return None
    return pattern.strip("/")


def codeowners_coverage_defects(text: str, repo_root: Path, critical=_CRITICAL_PREFIXES) -> list[str]:
    """Return a list of human-readable defects; empty == the CODEOWNERS is sound. Pure over its inputs
    so the negative controls can perturb the text in-process.

    Reports: no catch-all; a critical prefix with no explicit (more-specific-than-`*`) rule; a
    malformed owner token on any rule; an anchored directory rule that points at a path not in the tree.
    """
    defects: list[str] = []
    rules = parse_codeowners(text)
    if not rules:
        return ["CODEOWNERS has no rules at all"]

    patterns = {p for p, _ in rules}
    if "*" not in patterns:
        defects.append("no catch-all `*` rule — paths matching no explicit rule would have NO owner")

    for pattern, owners in rules:
        if not owners:
            defects.append(f"rule {pattern!r} names no owner")
        for o in owners:
            if not _OWNER.match(o):
                defects.append(f"rule {pattern!r} has a malformed owner token {o!r} (GitHub ignores it)")

    explicit = {p for p, _ in rules if p != "*"}
    for prefix in critical:
        if prefix not in explicit:
            defects.append(
                f"security-critical path {prefix!r} has no explicit rule — it would silently inherit "
                f"the `*` catch-all instead of a called-out owner"
            )

    for pattern, _ in rules:
        rel = _tree_path_for_pattern(pattern)
        if rel is not None and not (repo_root / rel).exists():
            defects.append(f"rule {pattern!r} points at {rel!r}, which does not exist in the tree (dead rule)")

    return defects


def _active_codeowners_path(repo_root: Path) -> Path | None:
    for rel in _GITHUB_CODEOWNERS_PATHS:
        p = repo_root / rel
        if p.is_file():
            return p
    return None


# --------------------------------------------------------------------------------------------------
# Positive checks — TRUE of this repository.
# --------------------------------------------------------------------------------------------------
def test_codeowners_lives_where_github_reads_it():
    p = _active_codeowners_path(_REPO)
    assert p is not None, (
        "no CODEOWNERS at any path GitHub reads "
        f"({', '.join(_GITHUB_CODEOWNERS_PATHS)}) — a nested one enforces/requests nothing"
    )


def test_root_codeowners_covers_every_critical_path():
    p = _active_codeowners_path(_REPO)
    assert p is not None, "no root CODEOWNERS"
    defects = codeowners_coverage_defects(p.read_text(encoding="utf-8"), _REPO)
    assert not defects, "CODEOWNERS coverage defects:\n  - " + "\n  - ".join(defects)


def test_every_critical_prefix_is_a_real_directory():
    """The critical set is not aspirational — each path exists, so an explicit rule for it is meaningful."""
    missing = [pre for pre in _CRITICAL_PREFIXES if not (_REPO / pre.strip("/")).exists()]
    assert not missing, f"critical prefixes name paths that do not exist: {missing}"


# --------------------------------------------------------------------------------------------------
# Negative controls — the validator REJECTS bad CODEOWNERS in the same run, so a green tick above is
# not a constant-pass no-op.
# --------------------------------------------------------------------------------------------------
_GOOD = "\n".join(["*  @owner"] + [f"{pre}  @owner" for pre in _CRITICAL_PREFIXES]) + "\n"


def test_negative_control_missing_critical_rule_is_flagged(tmp_path):
    # Real, sound text passes (proves the check is not always-fail):
    assert codeowners_coverage_defects(_GOOD, _REPO) == []
    # Drop one critical rule -> it must be reported as inheriting the catch-all:
    dropped = "\n".join(
        ln for ln in _GOOD.splitlines() if not ln.startswith("/tools/governance/")
    ) + "\n"
    defects = codeowners_coverage_defects(dropped, _REPO)
    assert any("/tools/governance/" in d for d in defects), defects


def test_negative_control_missing_catch_all_is_flagged():
    no_star = "\n".join(f"{pre}  @owner" for pre in _CRITICAL_PREFIXES) + "\n"
    defects = codeowners_coverage_defects(no_star, _REPO)
    assert any("catch-all" in d for d in defects), defects


def test_negative_control_malformed_owner_is_flagged():
    bad = _GOOD + "/gateway/  not-an-at-handle\n"
    defects = codeowners_coverage_defects(bad, _REPO)
    assert any("malformed owner" in d for d in defects), defects


def test_negative_control_dead_rule_is_flagged():
    dead = _GOOD + "/this/path/does/not/exist/  @owner\n"
    defects = codeowners_coverage_defects(dead, _REPO)
    assert any("does not exist in the tree" in d for d in defects), defects


def test_negative_control_owner_regex_shape():
    assert _OWNER.match("@thuram-nana")
    assert _OWNER.match("@some-org/security-team")
    assert _OWNER.match("owner@example.com")
    assert not _OWNER.match("thuram-nana")   # missing @
    assert not _OWNER.match("@")             # empty handle
