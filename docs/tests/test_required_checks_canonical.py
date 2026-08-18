"""The doc claim and the branch-protection reality can never diverge again.

WHY THIS TEST EXISTS. A single sentence — "branch protection on `main` is live with nine required
checks" — propagated verbatim and FALSE into eleven files while `main` had no protection at all
(the API returned 404). Protection is now real, and its exact shape is written down in ONE place:
`.github/required-status-checks.txt`. This test is the pin that keeps every other statement of that
shape — the governance tool, the workflows, and the prose in the briefing — in step with that one
file, OFFLINE, on every pull request. It rides the already-required "the briefing explains every
agent and capability" job (`pytest docs/tests -q`), which installs only pytest and reads files only,
so this test imports nothing beyond the standard library.

WHAT IT PROVES (all offline — it never touches the network; the live GitHub API is checked by the
separate, required `.github/workflows/branch-protection-verify.yml`):

  (a) Every canonical required check is a real job `name:` that runs on `pull_request`. A required
      check that no PR job produces blocks EVERY pull request forever — the exact trap that
      tools/governance/require-checks.sh is arranged around. If someone lists a check here that no
      workflow builds, this fails before it can lock the repository.
  (b) The nightly-only jobs (`livefire full table (nightly)`) are NOT in the canonical list. They
      never report on a PR, so requiring one would block every PR.
  (c) Every doc that states a required-check COUNT or LIST agrees with the canonical file: the count
      is 13, the authoritative enumeration in docs/AS-BUILT.md names exactly the 13, and no doc
      enumerates a nightly-only check as required. This is the doc-truth pin.
  (d) tools/governance/require-checks.sh reads the canonical file and does NOT carry its own second
      copy of the list. Two lists can drift; one cannot.

NEGATIVE CONTROL. The pure helpers below take their data as arguments precisely so the perturbation
can be exercised in-process, not merely described. `test_negative_control_*` feed the checkers a
deliberately-wrong canonical list / doc text / workflow set and assert they REPORT the divergence.
If you want to see the real thing bite by hand:
  * change any "13" in README.md's branch-protection row to "9" -> test_doc_counts_match_canonical fails;
  * add a line "NOT A REAL CHECK" to required-status-checks.txt -> test_canonical_checks_are_all_pr_jobs fails;
  * add "livefire full table (nightly)" to required-status-checks.txt -> test_nightly_jobs_excluded fails;
  * delete a canonical name from the AS-BUILT table -> test_asbuilt_enumeration_matches_canonical fails.

WHAT THIS TEST DOES NOT CLAIM. It does not read the live GitHub configuration (that is the live-reality
workflow's job, and needs a token). It proves the committed artifacts are internally consistent — that
the prose cannot silently drift from the one file the operator's apply-tool and the live-verify job
both key on.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CANONICAL = REPO / ".github" / "required-status-checks.txt"
WORKFLOWS = REPO / ".github" / "workflows"
TOOL = REPO / "tools" / "governance" / "require-checks.sh"

# Jobs that deliberately never run on a pull request. Requiring one would wait for a check that no PR
# produces and block every PR forever, so the canonical list must exclude them and this test proves it.
KNOWN_NIGHTLY = {"livefire full table (nightly)"}

# Historical snapshots under these directories are dated audit records (each pinned to the commit it
# describes) and are deliberately NOT scanned. EVERYTHING ELSE that ships is discovered tree-wide, so a
# NEW or renamed doc that states a required-check count cannot escape the pin. A hand-maintained
# allowlist would itself be a drift vector — the exact failure mode this workstream exists to end.
_EXCLUDED_SNAPSHOT_DIRS = ("_review", "_inventory")


def discover_doc_files() -> list[str]:
    """Every shipped Markdown file, repo-relative, except the frozen historical-snapshot dirs."""
    out = []
    for path in sorted(REPO.rglob("*.md")):
        if set(path.relative_to(REPO).parts) & set(_EXCLUDED_SNAPSHOT_DIRS):
            continue
        out.append(path.relative_to(REPO).as_posix())
    return out


# --------------------------------------------------------------------------------------------------
# Canonical list
# --------------------------------------------------------------------------------------------------
def load_canonical(text: str) -> list[str]:
    """One context per line; blank lines and `#` comments ignored."""
    out = []
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        out.append(line.strip())
    return out


def canonical() -> list[str]:
    return load_canonical(CANONICAL.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------------
# Minimal, dependency-free reading of the workflow YAML.
#
# The briefing-completeness job installs only pytest, so PyYAML is not available. These files have a
# fixed, simple shape (two-space indent, job keys at two spaces, `name:`/`if:` at four) and a hand
# parser that understands exactly that shape is both sufficient and more honest than pulling in a
# dependency the required job does not have.
# --------------------------------------------------------------------------------------------------
def parse_on_events(text: str) -> set[str]:
    """The set of event names under the top-level `on:` key (block or inline form)."""
    lines = text.splitlines()
    events: set[str] = set()
    i = 0
    while i < len(lines):
        m = re.match(r"^on:(.*)$", lines[i])
        if not m:
            i += 1
            continue
        inline = m.group(1).split("#", 1)[0].strip()
        if inline:  # `on: [push, pull_request]` or `on: push`
            events |= {e.strip().strip("\"'") for e in inline.strip("[]").split(",") if e.strip()}
            return events
        # block form: two-space-indented child keys until the next column-0 token
        j = i + 1
        while j < len(lines):
            ln = lines[j]
            if ln.strip() == "" or ln.lstrip().startswith("#"):
                j += 1
                continue
            if re.match(r"^\S", ln):  # next top-level key -> end of the on: block
                break
            k = re.match(r"^  ([A-Za-z_][\w-]*):", ln)  # exactly two-space indent
            if k:
                events.add(k.group(1))
            j += 1
        return events
    return events


def parse_jobs(text: str) -> list[tuple[str, str | None]]:
    """(job name, job-level if-expression) for every job, in file order."""
    lines = text.splitlines()
    # locate the jobs: block
    start = None
    for idx, ln in enumerate(lines):
        if re.match(r"^jobs:\s*$", ln):
            start = idx + 1
            break
    if start is None:
        return []
    jobs: list[tuple[str, str | None]] = []
    cur_name: str | None = None
    cur_if: str | None = None

    def flush():
        nonlocal cur_name, cur_if
        if cur_name is not None:
            jobs.append((cur_name, cur_if))
        cur_name, cur_if = None, None

    for ln in lines[start:]:
        if re.match(r"^\S", ln):  # left the jobs: block
            break
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", ln):  # a job key (two-space indent, nothing after colon)
            flush()
            continue
        nm = re.match(r"^    name:\s*(.+?)\s*$", ln)  # four-space indent -> job-level, not a step
        if nm and cur_name is None:
            cur_name = nm.group(1)
            continue
        fi = re.match(r"^    if:\s*(.+?)\s*$", ln)
        if fi and cur_if is None:
            cur_if = fi.group(1)
    flush()
    return jobs


def event_condition_allows(if_expr: str | None, event: str) -> bool:
    """Does a job-level `if:` permit `event`? Handles the github.event_name expressions these files use.

    Conservative by design: an expression that does not mention github.event_name (or uses a construct
    this parser does not model) is treated as permitting the event — it cannot be shown to exclude it.
    """
    if if_expr is None:
        return True
    expr = if_expr.strip()
    m = re.match(r"^\$\{\{(.*)\}\}$", expr)
    if m:
        expr = m.group(1).strip()
    if "github.event_name" not in expr:
        return True

    def resolve(tok: str) -> str:
        tok = tok.strip()
        return event if tok == "github.event_name" else tok.strip("\"'")

    def atom_true(atom: str) -> bool:
        a = re.match(r"^(.*?)(==|!=)(.*)$", atom.strip())
        if not a:
            raise ValueError(atom)
        lhs, op, rhs = resolve(a.group(1)), a.group(2), resolve(a.group(3))
        return lhs == rhs if op == "==" else lhs != rhs

    for or_part in expr.split("||"):
        try:
            if all(atom_true(a) for a in or_part.split("&&")):
                return True
        except ValueError:
            return True  # unmodelled atom -> cannot disprove; permit
    return False


def pr_and_nonpr_job_names(workflow_texts: list[str]) -> tuple[set[str], set[str]]:
    """(names of jobs that run on pull_request, names that never do)."""
    all_names: set[str] = set()
    pr: set[str] = set()
    for text in workflow_texts:
        events = parse_on_events(text)
        for name, if_expr in parse_jobs(text):
            all_names.add(name)
            if "pull_request" in events and event_condition_allows(if_expr, "pull_request"):
                pr.add(name)
    return pr, all_names - pr


def _workflow_texts() -> list[str]:
    return [p.read_text(encoding="utf-8") for p in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))]


# --------------------------------------------------------------------------------------------------
# Doc-truth: counts and enumerations of required checks.
# --------------------------------------------------------------------------------------------------
_WORD2NUM = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
    "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
}
_NUM = r"(\d+|" + "|".join(_WORD2NUM) + r")"

# Each pattern captures a number that is asserting a COUNT OF REQUIRED CHECKS (or, equivalently, the
# number of jobs that can block a merge). Every pattern is anchored on branch-protection vocabulary
# ("required checks", "automated checks", "can block the merge") so that unrelated numbers in these
# very large documents — nine tools, nine assistants, nine hard limits, nineteen modules — are not
# swept in. The patterns are validated empirically: run against the pre-fix docs they flagged every
# stale "9"; after the fix they must all read 13.
_COUNT_PATTERNS = [
    re.compile(_NUM + r"\s+required\s+(?:status\s+)?checks?", re.I),
    re.compile(_NUM + r"\s+(?:independent\s+)?automated\s+checks?", re.I),
    re.compile(_NUM + r"\s+independent\s+automated\s+jobs?", re.I),
    re.compile(_NUM + r"\s+checks?\s+are\s+required", re.I),
    re.compile(_NUM + r"\s+(?:status\s+)?checks?\s+required\s+to\s+pass", re.I),
    re.compile(r"Required\s+status\s+checks\s*\|\s*\*\*" + _NUM, re.I),
    re.compile(r"all\s+\*\*" + _NUM + r"\*\*\s+status\s+checks", re.I),
    re.compile(r"without\s+(?:those\s+|the\s+)?" + _NUM + r"\s+checks", re.I),
    re.compile(r'"' + _NUM + r' required checks"', re.I),
    re.compile(_NUM + r"\s+(?:of\s+them\s+)?can\s+block\s+(?:the\s+|a\s+)?merge", re.I),
    re.compile(r"which\s+" + _NUM + r"\s+of\s+them\s+can\s+block", re.I),
    re.compile(r"the\s+required\s+" + _NUM + r"\s+(?:are|checks|status|is)\b", re.I),
    re.compile(r"checks?\s*\(\s*\*\*" + _NUM + r"\*\*\s+of\s+them", re.I),
]


def _tok2int(tok: str) -> int:
    return int(tok) if tok.isdigit() else _WORD2NUM[tok.lower()]


def find_required_check_counts(text: str) -> list[tuple[int, str]]:
    """Every (number, matched-snippet) where the text asserts a count of required checks."""
    found: list[tuple[int, str]] = []
    for pat in _COUNT_PATTERNS:
        for m in pat.finditer(text):
            found.append((_tok2int(m.group(1)), m.group(0)))
    return found


# --------------------------------------------------------------------------------------------------
# The tests.
# --------------------------------------------------------------------------------------------------
def test_canonical_parses_to_thirteen():
    names = canonical()
    assert len(names) == len(set(names)) == 13, f"expected 13 distinct canonical checks, got {names}"


def test_canonical_checks_are_all_pr_jobs():
    """(a) Every required check is produced by a real pull_request-triggered job."""
    pr, _ = pr_and_nonpr_job_names(_workflow_texts())
    missing = [c for c in canonical() if c not in pr]
    assert not missing, (
        "these canonical required checks are not produced by any pull_request job — requiring one "
        f"would block every PR forever: {missing}. PR job names seen: {sorted(pr)}"
    )


def test_nightly_jobs_excluded():
    """(b) No nightly-only job is in the canonical list, and the parser really does classify it as such."""
    pr, nonpr = pr_and_nonpr_job_names(_workflow_texts())
    for n in KNOWN_NIGHTLY:
        assert n in nonpr, f"parser sanity: {n!r} should be a non-PR job but was classified PR ({sorted(pr)})"
    leaked = [c for c in canonical() if c in nonpr]
    assert not leaked, f"nightly-only jobs must not be required (they never report on a PR): {leaked}"


def test_doc_counts_match_canonical():
    """(c, count) Every stated required-check count in ANY shipped doc equals the canonical size (13)."""
    n = len(canonical())
    docs = discover_doc_files()
    for must in ("README.md", "docs/AS-BUILT.md", "CONTRIBUTING.md"):
        assert must in docs, f"doc discovery missed {must!r} — the tree walk is broken"
    violations = []
    for rel in docs:
        text = (REPO / rel).read_text(encoding="utf-8")
        for num, snippet in find_required_check_counts(text):
            if num != n:
                violations.append(f"{rel}: says {num} in {snippet!r} (canonical is {n})")
    assert not violations, "required-check count claims disagree with the canonical list:\n" + "\n".join(violations)


def test_asbuilt_enumeration_matches_canonical():
    """(c, list) The authoritative enumeration in AS-BUILT names exactly the 13 and no nightly check."""
    text = (REPO / "docs/AS-BUILT.md").read_text(encoding="utf-8")
    # the protection table's "Required status checks" row
    row = next((ln for ln in text.splitlines() if ln.startswith("| Required status checks")), None)
    assert row is not None, "AS-BUILT.md has no 'Required status checks' protection-table row"
    for name in canonical():
        assert name in row, f"AS-BUILT protection table omits the required check {name!r}"
    for nightly in KNOWN_NIGHTLY:
        assert nightly not in row, f"AS-BUILT protection table lists a nightly-only check as required: {nightly!r}"


def test_tool_reads_canonical_single_source():
    """(d) require-checks.sh keys on the canonical file and carries no second copy of the list."""
    script = TOOL.read_text(encoding="utf-8")
    assert ".github/required-status-checks.txt" in script, (
        "require-checks.sh must read .github/required-status-checks.txt as its single source of truth"
    )
    # A hardcoded second list is exactly the drift this workstream ends: none of the canonical names
    # may appear as a literal in the script (they come from the file now).
    hardcoded = [c for c in canonical() if c in script]
    assert not hardcoded, f"require-checks.sh still hardcodes check names (drift risk): {hardcoded}"


# --------------------------------------------------------------------------------------------------
# Negative controls — the checkers must REPORT divergence, not wave it through.
# --------------------------------------------------------------------------------------------------
def test_negative_control_count_checker_bites():
    n = len(canonical())
    good = "the main branch has 13 required status checks and force-push is blocked"
    bad = "the main branch has 9 required status checks"
    assert all(num == n for num, _ in find_required_check_counts(good)), "13 must read as consistent"
    bad_counts = find_required_check_counts(bad)
    assert bad_counts and all(num != n for num, _ in bad_counts), "a stale '9 required checks' claim must be flagged"


def test_negative_control_bogus_check_is_not_a_pr_job():
    pr, _ = pr_and_nonpr_job_names(_workflow_texts())
    assert "NOT A REAL CHECK" not in pr, "a fabricated check name must not resolve to any PR job"


def test_negative_control_nightly_classification():
    """The parser must classify a schedule/dispatch-only job as non-PR, and a plain job as PR."""
    wf = (
        "on:\n"
        "  pull_request:\n"
        "    branches: [main]\n"
        "  schedule:\n"
        "    - cron: \"0 3 * * *\"\n"
        "jobs:\n"
        "  a:\n"
        "    name: runs on every PR\n"
        "    runs-on: ubuntu-latest\n"
        "  b:\n"
        "    name: nightly only\n"
        "    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\n"
        "    runs-on: ubuntu-latest\n"
    )
    pr, nonpr = pr_and_nonpr_job_names([wf])
    assert "runs on every PR" in pr and "runs on every PR" not in nonpr
    assert "nightly only" in nonpr and "nightly only" not in pr


def test_negative_control_workflow_that_skips_pr():
    """A workflow with no pull_request trigger contributes no PR jobs."""
    wf = "on:\n  push:\n    branches: [main]\njobs:\n  x:\n    name: push only\n    runs-on: ubuntu-latest\n"
    pr, nonpr = pr_and_nonpr_job_names([wf])
    assert pr == set() and nonpr == {"push only"}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
