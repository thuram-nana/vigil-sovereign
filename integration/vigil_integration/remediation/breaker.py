"""remediation.breaker — a deterministic ADVERSARIAL anti-cheat gate for a proposed fix (PCR / W6).

The oracle (rule cleared) + the real test suite are necessary but not sufficient: a "fix" can PASS both by
GAMING them rather than fixing the bug —
  * editing the very TESTS it is validated against (rewrite the assertion so it passes),
  * SKIPPING / xfail-ing tests (a skipped test never fails, so the suite goes green),
  * adding a SUPPRESSION comment (``# nosec`` / ``# noqa`` / ``# type: ignore`` / ``# semgrep:ignore`` /
    ``pylint: disable``) so a suppression-aware analyzer stops reporting the finding.
None of these are caught by "rule cleared + suite passed". The breaker inspects the fix's OWN diff for these
cheat signals and, when it fires, the fix is NOT certified (no verified-no-pr, no attestation). It is a
defense-in-depth layer LAYERED ON the deterministic oracle — it never PROMOTES a fix, only demotes a cheat.

Deterministic + near-zero-FP: every signal is an UNAMBIGUOUS act a genuine vulnerability fix has no reason to
perform (a vuln fix edits the vulnerable code, not the tests, and never suppresses the rule). Pure stdlib.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# a path (from a `+++ b/<path>` diff header) that is part of the TEST SUITE
_TEST_PATH = re.compile(r"(^|/)(tests?/|conftest\.py$)|(^|/)test_[^/]*\.py$|_test\.py$|\.spec\.[jt]sx?$|\.test\.[jt]sx?$")

# ADDED lines (diff `+`) that disable/skip a test so the suite goes green without fixing anything
_TEST_DISABLE = re.compile(
    r"@(pytest\.mark\.(skip|xfail)|unittest\.skip)|"
    r"\bpytest\.skip\s*\(|\bself\.skipTest\s*\(|\.skip\s*\(|\bit\.skip\b|\bdescribe\.skip\b|\bxit\b|\btest\.skip\b")

# ADDED lines that SUPPRESS the analyzer/linter rather than fix the code
_SUPPRESS = re.compile(
    r"#\s*nosec\b|#\s*noqa\b|#\s*type:\s*ignore\b|#\s*semgrep\b|#\s*nosemgrep\b|"
    r"pylint:\s*disable|//\s*nosemgrep|/\*\s*eslint-disable|#\s*pragma:\s*no\s*cover")


@dataclass(frozen=True)
class BreakerVerdict:
    cheated: bool
    cheats: tuple[str, ...] = field(default_factory=tuple)

    @property
    def reason(self) -> str:
        return "; ".join(self.cheats)


def _diff_targets(diff: str) -> list[str]:
    """The repo-relative paths a unified diff MODIFIES (from `+++ b/<path>` headers; `/dev/null` skipped)."""
    out: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ "):
            p = line[4:].strip()
            if p in ("/dev/null", ""):
                continue
            if p.startswith(("a/", "b/")):
                p = p[2:]
            out.append(p)
    return out


def _added_lines(diff: str) -> list[str]:
    """Lines the diff ADDS (`+` but not the `+++` header)."""
    return [ln[1:] for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def inspect_fix(diff: str, *, rule_id: str = "") -> BreakerVerdict:
    """Inspect a fix's unified diff for cheat signals. Returns a :class:`BreakerVerdict`; ``cheated`` True (with
    human-readable ``cheats``) blocks certification. Total — never raises; an empty/garbage diff is not a cheat."""
    if not diff or not diff.strip():
        return BreakerVerdict(False)
    cheats: list[str] = []

    targets = _diff_targets(diff)
    test_files = [p for p in targets if _TEST_PATH.search(p)]
    if test_files:
        cheats.append(f"the fix EDITS test file(s) it is validated against ({', '.join(sorted(set(test_files))[:5])}) "
                      "— a vulnerability fix must change the vulnerable code, not its tests")

    added = _added_lines(diff)
    if any(_TEST_DISABLE.search(ln) for ln in added):
        cheats.append("the fix ADDS a test skip/xfail — a skipped test never fails, so 'tests passed' would be gamed")
    if any(_SUPPRESS.search(ln) for ln in added):
        cheats.append("the fix ADDS an analyzer/linter SUPPRESSION (# nosec / # noqa / # type: ignore / "
                      "semgrep-ignore / eslint-disable) — that hides the finding instead of fixing it")
    if rule_id:
        rid = re.escape(str(rule_id))
        if any(re.search(rid, ln, re.IGNORECASE) and re.search(r"ignore|disable|suppress|allow", ln, re.IGNORECASE)
               for ln in added):
            cheats.append(f"the fix ADDS a suppression naming the finding's own rule ({rule_id})")

    return BreakerVerdict(bool(cheats), tuple(cheats))
