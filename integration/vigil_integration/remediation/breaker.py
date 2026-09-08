"""remediation.breaker — a deterministic ADVERSARIAL anti-cheat gate for a proposed fix (PCR / W6).

The oracle (rule cleared) + the real test suite are necessary but not sufficient: a "fix" can PASS both by
GAMING them rather than fixing the bug —
  * editing the very TESTS it is validated against (rewrite the assertion so it passes) — whether via a plain
    hunk, a git-extended `rename`/`copy` that moves the test out of collection, or a `GIT binary patch` that
    overwrites the test's bytes (the latter two carry NO `+++`/`---` pair, yet `git apply` honors them),
  * SKIPPING / xfail-ing tests, or disabling collection via a pytest config (a skipped/ignored test never
    fails, so the suite goes green),
  * adding a SECURITY-analyzer SUPPRESSION (``# nosec`` / ``# semgrep:ignore`` / eslint-disable) so a
    suppression-aware scanner stops reporting the finding.
None of these are caught by "rule cleared + suite passed". The breaker inspects the fix's OWN diff for these
cheat signals and, when it fires, the fix is NOT certified (no verified-no-pr, no attestation). It is a
defense-in-depth layer LAYERED ON the deterministic oracle — it never PROMOTES a fix, only demotes a cheat.

Best-effort by nature (an infinitely clever coder can find an unlisted trick). Two classes of signal, with
different FP profiles:

  * Near-zero-FP signals — an act a genuine vulnerability fix has essentially no reason to perform: adding a
    test skip/xfail, a pytest collection-disable, or a security-scanner suppression; renaming/copying a test
    file away. These are scoped tightly (qualified skip forms only; pytest-only config context; security
    suppressions only, NOT type/style directives like ``# type: ignore`` / ``# noqa`` / ``pylint: disable``
    which have legitimate uses).
  * A conservative, demote-only HEURISTIC — editing a file inside a ``tests/`` / ``test/`` / ``__tests__/``
    directory. This can flag a non-test file that happens to live in a test tree (e.g. ``test/fixtures.py``);
    that is a deliberate, safe conservatism because the gate only DEMOTES (the fix is still surfaced to the
    operator, just not auto-certified), and editing anything under a dedicated test directory while fixing a
    PRODUCTION vulnerability is off-pattern. Bare ``spec/`` is deliberately NOT treated as a test dir (it
    collides with OpenAPI/AsyncAPI spec trees); RSpec is caught by the ``_spec.rb`` filename instead.

The test-file check consumes the CALLER's already-canonicalised changed-paths (loop.py's approved PatchFile
paths) so diff-header tricks (tab-timestamps, git path-quoting) cannot evade it; and it ALSO derives paths
from every ``diff --git`` header (which precedes rename, copy, ``GIT binary patch`` and mode-change blocks
alike — all of which lack a ``+++``/``---`` pair and are absent from the caller's path set). Pure stdlib;
total on any input.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# a path that is part of the TEST SUITE (case-insensitive; anchored so `contests/` etc. do NOT match). Bare
# `spec/` is intentionally absent — it collides with OpenAPI/AsyncAPI spec directories (a false positive);
# RSpec is covered by the `_spec.rb` filename suffix.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__)/"                            # a test DIRECTORY component (conservative heuristic)
    r"|(^|/)conftest\.py$"                                 # pytest conftest
    r"|(^|/)test_[^/]*\.(py|js|jsx|ts|tsx)$"               # test_*.py|js|ts
    r"|_test\.(py|go|js|jsx|ts|tsx)$"                      # *_test.py|go|js|ts
    r"|_spec\.(rb|py)$"                                    # RSpec / *_spec.py (filename — covers spec/ trees)
    r"|\.spec\.[jt]sx?$|\.test\.[jt]sx?$"                  # jest x.spec.ts / x.test.ts
    r"|(Test|Tests|IT)\.java$", re.IGNORECASE)

# A `diff --git a/<x> b/<y>` header PRECEDES EVERY git-extended block — rename, copy, `GIT binary patch`,
# mode change — including the ones that carry NO `+++`/`---` pair and are therefore absent from the caller's
# changed-paths AND from `_diff_targets`. `git apply` honors all of them, so a fix can neutralize a TEST file
# through any of them (rename it out of collection, overwrite its assertions via a binary patch) and green the
# suite. Deriving touched paths from this header is the AUTHORITATIVE catch-all. The `^` anchor matches only
# the git meta line (diff content lines start with `+`/`-`/space).
_GIT_DIFF_HDR = re.compile(r"^diff --git (.+)$")

# git-extended `rename from/to` and `copy from/to` headers (kept as an explicit secondary signal).
_GIT_RENAMECOPY = re.compile(r"^(?:rename|copy)\s+(?:from|to)\s+(.+?)\s*$")

# ADDED lines (diff `+`) that disable/skip a test IN CODE — QUALIFIED forms only (a bare `.skip(` is idiomatic
# pymongo/stream/iterator code and would be a false positive; a bare skip inside a test file is already caught
# by the test-file-edit signal).
_TEST_DISABLE = re.compile(
    r"@\s*(pytest\.mark\.(skip|skipif|xfail)|unittest\.skip\w*)\b"
    r"|\bpytest\.skip\s*\(|\bself\.skipTest\s*\("
    r"|\braise\s+(unittest\.)?SkipTest\b")

# ADDED lines that DISABLE test collection via a pytest/tox config (games "suite passed" without a test file).
# `--deselect` / `--collect-only` / `--ignore-glob` are pytest-EXCLUSIVE flags (safe bare); `--ignore` / `-k`
# are ambiguous (argparse `--ignore-case`, any CLI's `-k`) so they only count inside a pytest `addopts=` or
# `pytest ...` invocation — keeping this near-zero-FP.
_TEST_CONFIG_DISABLE = re.compile(
    r"--deselect\b|--collect-only\b|--ignore-glob\b"       # pytest-EXCLUSIVE flags — safe bare
    r"|\baddopts\b[^\n]*(--ignore\b|-k\b)"                 # `--ignore`/`-k` only inside pytest addopts
    r"|\bpytest\b[^\n]*--ignore\b")                        # ...or a literal pytest invocation

# ADDED lines that SUPPRESS a SECURITY analyzer rather than fix the code. Restricted to security-scanner
# suppressions (bandit `# nosec`, semgrep, eslint-disable) which a genuine security fix has no reason to add.
# Deliberately EXCLUDES `# type: ignore` (type checker), `# noqa` (flake8 style), `pylint: disable` and
# `# pragma: no cover` — those have legitimate uses in a real fix, so flagging them is a false positive.
_SUPPRESS = re.compile(
    r"#\s*nosec\b|#\s*semgrep\b|#\s*nosemgrep\b"
    r"|//\s*nosemgrep|/\*\s*eslint-disable|//\s*eslint-disable(-next)?-line")


@dataclass(frozen=True)
class BreakerVerdict:
    cheated: bool
    cheats: tuple[str, ...] = field(default_factory=tuple)

    @property
    def reason(self) -> str:
        return "; ".join(self.cheats)


def _unquote_path(p: str) -> str:
    """Strip git path-quoting and an `a/`/`b/` prefix from a diff-header path."""
    p = p.strip()
    if len(p) >= 2 and p[0] == '"' and p[-1] == '"':
        p = p[1:-1]                                      # git path-quoting: "b/x.py"
    if p.startswith(("a/", "b/")):
        p = p[2:]
    return p


def _diff_targets(diff: str) -> list[str]:
    """Repo-relative paths a unified diff MODIFIES (from `+++ b/<path>` headers). Fallback for callers that do
    not pass canonical paths; hardened to strip a trailing tab-timestamp (POSIX `diff -u`) and git path-quoting
    so a header trick cannot hide a test-file edit."""
    out: list[str] = []
    for line in diff.splitlines():
        if not line.startswith("+++ "):
            continue
        p = _unquote_path(line[4:].split("\t", 1)[0])   # drop a "\t<timestamp>" suffix, then unquote/deprefix
        if p in ("/dev/null", ""):
            continue
        out.append(p)
    return out


def _split_git_diff_paths(rest: str) -> list[str]:
    """Both paths named on a `diff --git a/<x> b/<y>` header. git c-quotes a path (each independently) only
    when it has unusual chars; unquoted paths never contain spaces. Best-effort for a demote-only heuristic."""
    rest = rest.strip()
    out: list[str] = []
    for q in re.findall(r'"((?:\\.|[^"\\])*)"', rest):           # c-quoted segment(s)
        try:
            dec = q.encode("utf-8", "replace").decode("unicode_escape", "replace")
        except Exception:
            dec = q
        p = _unquote_path(dec)
        if p and p != "/dev/null":
            out.append(p)
    for tok in re.findall(r'(?<!\S)[ab]/\S+', rest):            # unquoted a/… b/… tokens
        p = tok[2:]
        if p and p != "/dev/null":
            out.append(p)
    return out


def _gitdiff_header_paths(diff: str) -> list[str]:
    """Every path named on a `diff --git` header — the authoritative touched-path set that also covers files
    mutated with NO `+++`/`---` pair (rename, copy, GIT binary patch, mode change)."""
    out: list[str] = []
    for line in diff.splitlines():
        m = _GIT_DIFF_HDR.match(line)
        if m:
            out.extend(_split_git_diff_paths(m.group(1)))
    return out


def _renamecopy_paths(diff: str) -> list[str]:
    """Paths named by git-extended `rename from/to` / `copy from/to` headers (which carry NO `+++`/`---` pair,
    so they are invisible to the caller's changed-paths and to `_diff_targets`)."""
    out: list[str] = []
    for line in diff.splitlines():
        m = _GIT_RENAMECOPY.match(line)
        if not m:
            continue
        p = _unquote_path(m.group(1))
        if p and p != "/dev/null":
            out.append(p)
    return out


def _added_lines(diff: str) -> list[str]:
    """Lines the diff ADDS (`+` but not the `+++` header)."""
    return [ln[1:] for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def inspect_fix(diff: str, *, rule_id: str = "", changed_paths: Optional["list[str]"] = None) -> BreakerVerdict:
    """Inspect a fix for cheat signals. ``changed_paths`` (the caller's already-canonicalised modified paths,
    e.g. loop.py's approved PatchFile paths) is used for the test-file check when given — this defeats
    diff-header evasion; otherwise the paths are re-parsed from the diff. The diff BODY is always additionally
    scanned for git-extended ``rename``/``copy`` targets (a test file moved out of collection games the suite
    with no ``+++`` pair). Returns a :class:`BreakerVerdict`; ``cheated`` True (with human-readable ``cheats``)
    blocks certification. Total — never raises."""
    if not isinstance(diff, str) or not diff.strip():
        return BreakerVerdict(False)
    cheats: list[str] = []

    # The caller's canonical modified paths (trusted for the normal edit path) UNION every path named by a
    # git-extended block: `diff --git` headers (authoritative — covers rename/copy/binary-patch/mode-change,
    # which have NO +++/--- pair) plus the explicit rename/copy targets. This catches a fix that neutralizes a
    # TEST file through ANY git-apply-honored mechanism, not only a plain hunk edit.
    base = list(changed_paths) if changed_paths is not None else _diff_targets(diff)
    all_paths = base + _gitdiff_header_paths(diff) + _renamecopy_paths(diff)
    test_files = sorted({p for p in all_paths if p and _TEST_PATH.search(str(p))})
    if test_files:
        cheats.append(f"the fix TOUCHES test file(s) it is validated against ({', '.join(test_files[:5])}) — a "
                      "vulnerability fix must change the vulnerable code, not edit / rename / copy / "
                      "binary-patch a test out of the suite")

    added = _added_lines(diff)
    if any(_TEST_DISABLE.search(ln) for ln in added):
        cheats.append("the fix ADDS a test skip/xfail — a skipped test never fails, so 'tests passed' would be gamed")
    if any(_TEST_CONFIG_DISABLE.search(ln) for ln in added):
        cheats.append("the fix ADDS a pytest/tox config that DISABLES test collection (--ignore/--deselect/-k) "
                      "— that games 'suite passed' without touching a test file")
    if any(_SUPPRESS.search(ln) for ln in added):
        cheats.append("the fix ADDS a security-analyzer SUPPRESSION (# nosec / semgrep-ignore / eslint-disable) "
                      "— that hides the finding instead of fixing it")
    if rule_id:
        rid = re.escape(str(rule_id))
        if any(re.search(rid, ln, re.IGNORECASE) and re.search(r"ignore|disable|suppress|allow", ln, re.IGNORECASE)
               for ln in added):
            cheats.append(f"the fix ADDS a suppression naming the finding's own rule ({rule_id})")

    return BreakerVerdict(bool(cheats), tuple(cheats))
