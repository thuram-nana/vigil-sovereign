"""remediation.breaker — a deterministic ADVERSARIAL anti-cheat gate for a proposed fix (PCR / W6).

The oracle (rule cleared) + the real test suite are necessary but not sufficient: a "fix" can PASS both by
GAMING them rather than fixing the bug —
  * editing the very TESTS it is validated against (rewrite the assertion so it passes),
  * SKIPPING / xfail-ing tests, or disabling collection via a pytest config (a skipped/ignored test never
    fails, so the suite goes green),
  * adding a SUPPRESSION comment (``# nosec`` / ``# noqa`` / ``# type: ignore`` / ``# semgrep:ignore`` /
    ``pylint: disable`` / eslint-disable) so a suppression-aware analyzer stops reporting the finding.
None of these are caught by "rule cleared + suite passed". The breaker inspects the fix's OWN diff for these
cheat signals and, when it fires, the fix is NOT certified (no verified-no-pr, no attestation). It is a
defense-in-depth layer LAYERED ON the deterministic oracle — it never PROMOTES a fix, only demotes a cheat.

Best-effort by nature (an infinitely clever coder can find an unlisted trick), but its signals are chosen to
be near-zero-FP: each is an act a genuine vulnerability fix has essentially no reason to perform. The
test-file check consumes the CALLER's already-canonicalised changed-paths (loop.py's approved PatchFile
paths) so diff-header tricks (tab-timestamps, git path-quoting) cannot evade it. Pure stdlib; total on any
input.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# a path that is part of the TEST SUITE (dir names case-insensitive; anchored so `contests/` etc. do NOT match)
_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec)/"                       # a test/spec DIRECTORY component
    r"|(^|/)conftest\.py$"                                 # pytest conftest
    r"|(^|/)test_[^/]*\.(py|js|jsx|ts|tsx)$"               # test_*.py|js|ts
    r"|_test\.(py|go|js|jsx|ts|tsx)$"                      # *_test.py|go|js|ts
    r"|_spec\.(rb|py)$"                                    # RSpec / *_spec.py
    r"|\.spec\.[jt]sx?$|\.test\.[jt]sx?$"                  # jest x.spec.ts / x.test.ts
    r"|(Test|Tests|IT)\.java$", re.IGNORECASE)

# ADDED lines (diff `+`) that disable/skip a test IN CODE — QUALIFIED forms only (a bare `.skip(` is idiomatic
# pymongo/stream/iterator code and would be a false positive; a bare skip inside a test file is already caught
# by the test-file-edit signal).
_TEST_DISABLE = re.compile(
    r"@\s*(pytest\.mark\.(skip|skipif|xfail)|unittest\.skip\w*)\b"
    r"|\bpytest\.skip\s*\(|\bself\.skipTest\s*\("
    r"|\braise\s+(unittest\.)?SkipTest\b")

# ADDED lines that DISABLE test collection via a pytest/tox config (games "suite passed" without a test file).
# `--deselect` / `--collect-only` are pytest-EXCLUSIVE flags (safe bare); `--ignore` / `-k` are ambiguous
# (argparse `--ignore-case`, any CLI's `-k`) so they only count inside a pytest `addopts=` or `pytest ...`
# invocation — keeping this near-zero-FP.
_TEST_CONFIG_DISABLE = re.compile(
    r"--deselect\b|--collect-only\b|--ignore-glob\b"       # pytest-EXCLUSIVE flags — safe bare
    r"|\baddopts\b[^\n]*(--ignore\b|-k\b)"                 # `--ignore`/`-k` only inside pytest addopts
    r"|\bpytest\b[^\n]*--ignore\b")                        # ...or a literal pytest invocation

# ADDED lines that SUPPRESS the analyzer/linter rather than fix the code (NOT `# pragma: no cover` — that is
# a coverage marker legitimately used on defensive-only code, so flagging it is a false positive).
_SUPPRESS = re.compile(
    r"#\s*nosec\b|#\s*noqa\b|#\s*type:\s*ignore\b|#\s*semgrep\b|#\s*nosemgrep\b|"
    r"pylint:\s*disable|//\s*nosemgrep|/\*\s*eslint-disable|//\s*eslint-disable(-next)?-line")


@dataclass(frozen=True)
class BreakerVerdict:
    cheated: bool
    cheats: tuple[str, ...] = field(default_factory=tuple)

    @property
    def reason(self) -> str:
        return "; ".join(self.cheats)


def _diff_targets(diff: str) -> list[str]:
    """Repo-relative paths a unified diff MODIFIES (from `+++ b/<path>` headers). Fallback for callers that do
    not pass canonical paths; hardened to strip a trailing tab-timestamp (POSIX `diff -u`) and git path-quoting
    so a header trick cannot hide a test-file edit."""
    out: list[str] = []
    for line in diff.splitlines():
        if not line.startswith("+++ "):
            continue
        p = line[4:].split("\t", 1)[0].strip()          # drop a "\t<timestamp>" suffix
        if len(p) >= 2 and p[0] == '"' and p[-1] == '"':
            p = p[1:-1]                                  # git path-quoting: "b/x.py"
        if p in ("/dev/null", ""):
            continue
        if p.startswith(("a/", "b/")):
            p = p[2:]
        out.append(p)
    return out


def _added_lines(diff: str) -> list[str]:
    """Lines the diff ADDS (`+` but not the `+++` header)."""
    return [ln[1:] for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def inspect_fix(diff: str, *, rule_id: str = "", changed_paths: Optional["list[str]"] = None) -> BreakerVerdict:
    """Inspect a fix for cheat signals. ``changed_paths`` (the caller's already-canonicalised modified paths,
    e.g. loop.py's approved PatchFile paths) is used for the test-file check when given — this defeats
    diff-header evasion; otherwise the paths are re-parsed from the diff. Returns a :class:`BreakerVerdict`;
    ``cheated`` True (with human-readable ``cheats``) blocks certification. Total — never raises."""
    if not isinstance(diff, str) or not diff.strip():
        return BreakerVerdict(False)
    cheats: list[str] = []

    targets = list(changed_paths) if changed_paths is not None else _diff_targets(diff)
    test_files = [p for p in targets if p and _TEST_PATH.search(str(p))]
    if test_files:
        cheats.append(f"the fix EDITS test file(s) it is validated against ({', '.join(sorted(set(test_files))[:5])}) "
                      "— a vulnerability fix must change the vulnerable code, not its tests")

    added = _added_lines(diff)
    if any(_TEST_DISABLE.search(ln) for ln in added):
        cheats.append("the fix ADDS a test skip/xfail — a skipped test never fails, so 'tests passed' would be gamed")
    if any(_TEST_CONFIG_DISABLE.search(ln) for ln in added):
        cheats.append("the fix ADDS a pytest/tox config that DISABLES test collection (--ignore/--deselect/-k) "
                      "— that games 'suite passed' without touching a test file")
    if any(_SUPPRESS.search(ln) for ln in added):
        cheats.append("the fix ADDS an analyzer/linter SUPPRESSION (# nosec / # noqa / # type: ignore / "
                      "semgrep-ignore / eslint-disable) — that hides the finding instead of fixing it")
    if rule_id:
        rid = re.escape(str(rule_id))
        if any(re.search(rid, ln, re.IGNORECASE) and re.search(r"ignore|disable|suppress|allow", ln, re.IGNORECASE)
               for ln in added):
            cheats.append(f"the fix ADDS a suppression naming the finding's own rule ({rule_id})")

    return BreakerVerdict(bool(cheats), tuple(cheats))
