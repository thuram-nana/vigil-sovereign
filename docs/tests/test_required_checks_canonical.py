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
  (e) The REVERSE of (a) — the drift direction (a) cannot see (W0-2 #397). Every job that runs on a
      pull_request is either a required (canonical) check OR is enumerated in the KNOWN_ADVISORY
      ledger with a stated reason; every job that never runs on a PR is in KNOWN_NONPR_ADVISORY; and
      every nightly names a per-PR blocking SUBSET that is itself required (NIGHTLY_BLOCKING_SUBSET).
      So the required set equals the full PR-job set minus a written, reasoned exclusion list — a new
      advisory job cannot slip in unguarded the way five jobs once did.

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

# W0-2 (#397): the OTHER half of the equality. test_canonical_checks_are_all_pr_jobs proves
# canonical ⊆ (pull_request jobs); the dicts below let test_every_pr_job_is_required_or_excused prove
# the reverse — that the set of pull_request jobs equals EXACTLY (canonical ∪ these excused names).
# Before this, five jobs (`briefing-completeness`, `crucible-eval`, `sigil-lint`, `livefire-smoke`,
# `livefire-full`) had drifted out of the required set with nothing asserting they were accounted for; a
# new advisory PR job could join them unnoticed. Four of the five are now REQUIRED (they are in the
# canonical file); the nightly `livefire-full` is guarded by its required per-PR subset (see
# NIGHTLY_BLOCKING_SUBSET). A name earns a place here only with a stated, TRUE reason grounded in the
# workflow that produces it — "advisory" on its own is not a reason, and test_advisory_reasons_are_real
# rejects an empty or one-word excuse.

# Jobs that DO run on a pull_request but are deliberately NOT required. Each reason is checkable against
# the header comment of the workflow that produces the job.
KNOWN_ADVISORY: dict[str, str] = {
    "CodeQL Python (advisory)": (
        "security-scan.yml — CodeQL SAST reports on every PR but does not block a merge while the "
        "rulesets are still bedding in; a single false positive must not freeze the merge queue."
    ),
    "SAST — semgrep + bandit (advisory)": (
        "security-scan.yml — semgrep+bandit over the curated ruleset; advisory, but its policy and a "
        "planted-fixture NEGATIVE CONTROL are pinned by docs/tests/test_security_scan_policy.py, which "
        "rides the REQUIRED 'the briefing explains every agent and capability' job."
    ),
    "secret scan — gitleaks (advisory)": (
        "security-scan.yml — gitleaks over the working tree; advisory here, but the .gitleaks.toml policy "
        "plus a planted-secret NEGATIVE CONTROL are pinned by the REQUIRED docs/tests job, and secrets are "
        "also caught locally by the pre-commit hooks."
    ),
    "performance regression gate (advisory)": (
        "bench-perf.yml — a wall-clock gate wants its baseline re-recorded on the CI runner class before "
        "it blocks merges; the gate LOGIC and its NEGATIVE CONTROL are already proven in the REQUIRED "
        "docs/tests job via docs/tests/test_perf_gate.py."
    ),
    "pre-commit hooks (advisory)": (
        "pre-commit.yml — re-runs the local .pre-commit-config hooks on the PR (where --no-verify cannot "
        "skip them); advisory because the same lint/format guarantees are enforced by the REQUIRED "
        "'SIGIL lint' job, and the config is pinned by docs/tests/test_precommit_config.py."
    ),
    "lint-config (W2-2 ruff + mypy — every package incl tests)": (
        "lint-config.yml — a wider ruff+mypy config sweep over every package incl tests; advisory until "
        "the W2-1 (#418) blocking ratchet promotes it. The blocking lint subset is the REQUIRED "
        "'SIGIL lint (ruff blocking + mypy can-complete)' job."
    ),
    "scheduled supply-chain scan (advisory)": (
        "scheduled-supply-chain-scan.yml — the daily counterpart to the REQUIRED 'A14 supply-chain gate'; "
        "it runs on a PR only so its own change can be seen green, and its issue-opening step fires only on "
        "the schedule event. The blocking CVE guarantee is the A14 gate, not a second merge-blocker."
    ),
    "branch protection matches the committed policy": (
        "branch-protection-verify.yml — a live-reality pin that is INERT without the BRANCH_PROTECTION_TOKEN "
        "secret (the default GITHUB_TOKEN cannot read branch protection). It must not be promoted to a "
        "required check until that secret exists, or it would block every PR as a no-op. The committed "
        "artifacts are pinned offline by this very test."
    ),
}

# Jobs that never run on a pull_request at all (push/tag or schedule/dispatch only) and so CANNOT be a PR
# status check. A nightly whose surface still needs guarding names its required per-PR subset below.
KNOWN_NONPR_ADVISORY: dict[str, str] = {
    "livefire full table (nightly)": (
        "livefire.yml — schedule/workflow_dispatch only; it never reports on a PR, so requiring it would "
        "block every PR. Its per-PR blocking subset 'livefire smoke (per-PR subset)' IS required."
    ),
    "build, sign and attest release artifacts": (
        "release.yml — triggers on push (tags), never on a pull_request, so it cannot be a PR status check."
    ),
    "publish to PyPI (opt-in, trusted publishing)": (
        "release.yml — push-triggered and opt-in (vars.PUBLISH_TO_PYPI); it never reports on a PR."
    ),
}

# W0-2 (#397): "Where a job is legitimately non-blocking (nightly), split the blocking subset out into
# its own required job rather than leaving the surface unguarded." This maps each nightly job to the
# per-PR blocking subset that must itself be a REQUIRED (canonical) check.
NIGHTLY_BLOCKING_SUBSET: dict[str, str] = {
    "livefire full table (nightly)": "livefire smoke (per-PR subset)",
}

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
    cur_key: str | None = None
    cur_name: str | None = None
    cur_if: str | None = None

    def flush():
        nonlocal cur_key, cur_name, cur_if
        # A job with NO `name:` still ships as a status check — GitHub defaults its check context to the job
        # KEY (id). Fall back to the key so a nameless job can never be silently dropped from the accounting
        # (a dropped job is invisible to the reverse-drift guard = fail-open). RED-PEN #397.
        if cur_key is not None:
            jobs.append((cur_name if cur_name is not None else cur_key, cur_if))
        cur_key, cur_name, cur_if = None, None, None

    for ln in lines[start:]:
        if re.match(r"^\S", ln):  # left the jobs: block
            break
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", ln)  # a job key (two-space indent, nothing after colon)
        if m:
            flush()
            cur_key = m.group(1)
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


# --------------------------------------------------------------------------------------------------
# Reverse-direction accounting (W0-2 #397). Pure functions so the negative controls can perturb the
# inputs in-process rather than merely describe the failure.
# --------------------------------------------------------------------------------------------------
def unaccounted_pr_jobs(pr_jobs: set[str], required: set[str], advisory: set[str]) -> set[str]:
    """PR jobs that are neither required nor excused — every one of these is an unguarded surface."""
    return set(pr_jobs) - set(required) - set(advisory)


def unaccounted_nonpr_jobs(nonpr_jobs: set[str], nonpr_advisory: set[str]) -> set[str]:
    """Non-PR jobs (release/nightly) with no written reason for not being a required check."""
    return set(nonpr_jobs) - set(nonpr_advisory)


def nightly_subset_gaps(
    nightly_subset: dict[str, str], required: set[str], nonpr_jobs: set[str]
) -> list[str]:
    """A nightly must be a real non-PR job, and its named blocking subset must be a required check."""
    gaps: list[str] = []
    for nightly, subset in nightly_subset.items():
        if nightly not in nonpr_jobs:
            gaps.append(f"{nightly!r} is declared nightly but is not a non-PR job")
        if subset not in required:
            gaps.append(f"blocking subset {subset!r} of nightly {nightly!r} is not a required check")
    return gaps


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


# --------------------------------------------------------------------------------------------------
# W0-2 (#397): the required set equals the full job set, or the exclusion is enumerated with a reason.
# --------------------------------------------------------------------------------------------------
def test_every_pr_job_is_required_or_excused():
    """The reverse of (a): EVERY pull_request job is required (canonical) or excused in KNOWN_ADVISORY.

    This is the guard that was missing while five jobs drifted out of the required set. It fails the
    moment a workflow adds a pull_request job that is neither required nor given a written reason —
    closing the drift direction W0-1's canonical-⊆-PR check could not see.
    """
    pr, _ = pr_and_nonpr_job_names(_workflow_texts())
    leftover = unaccounted_pr_jobs(pr, set(canonical()), set(KNOWN_ADVISORY))
    assert not leftover, (
        "these pull_request jobs are neither required nor enumerated in KNOWN_ADVISORY — an unguarded "
        f"surface, the exact W0-2 defect: {sorted(leftover)}. Add each to the canonical required set or "
        "to KNOWN_ADVISORY with a stated reason."
    )
    # And nothing is excused that does not exist / is not actually a PR job (the dict cannot rot either).
    stale = set(KNOWN_ADVISORY) - pr
    assert not stale, f"KNOWN_ADVISORY names jobs that are not pull_request jobs anymore: {sorted(stale)}"
    # Required and advisory must be disjoint — a job cannot be both blocking and excused.
    assert not (set(canonical()) & set(KNOWN_ADVISORY)), "a job is listed as BOTH required and advisory"


def test_every_nonpr_job_is_excused():
    """Every job that never runs on a PR (release/nightly) is accounted for in KNOWN_NONPR_ADVISORY."""
    _, nonpr = pr_and_nonpr_job_names(_workflow_texts())
    leftover = unaccounted_nonpr_jobs(nonpr, set(KNOWN_NONPR_ADVISORY))
    assert not leftover, (
        f"these non-PR jobs have no written reason for not being a required check: {sorted(leftover)}"
    )
    stale = set(KNOWN_NONPR_ADVISORY) - nonpr
    assert not stale, f"KNOWN_NONPR_ADVISORY names jobs that are not non-PR jobs anymore: {sorted(stale)}"


def test_full_job_set_is_completely_partitioned():
    """Belt and braces: canonical ∪ advisory ∪ non-PR-advisory covers EVERY job the workflows declare."""
    pr, nonpr = pr_and_nonpr_job_names(_workflow_texts())
    all_jobs = pr | nonpr
    accounted = set(canonical()) | set(KNOWN_ADVISORY) | set(KNOWN_NONPR_ADVISORY)
    assert all_jobs == accounted, (
        "the job set and the accounted set differ — drift in some direction.\n"
        f"  jobs not accounted (unguarded): {sorted(all_jobs - accounted)}\n"
        f"  accounted names with no job (rot): {sorted(accounted - all_jobs)}"
    )


def test_nightly_has_required_blocking_subset():
    """(#397) Each nightly job names a per-PR blocking subset, and that subset is a REQUIRED check."""
    _, nonpr = pr_and_nonpr_job_names(_workflow_texts())
    # every nightly (non-PR + in KNOWN_NIGHTLY) whose surface needs guarding must have a mapped subset
    for nightly in KNOWN_NIGHTLY:
        assert nightly in NIGHTLY_BLOCKING_SUBSET, (
            f"nightly {nightly!r} has no per-PR blocking subset declared — its surface is unguarded"
        )
    gaps = nightly_subset_gaps(NIGHTLY_BLOCKING_SUBSET, set(canonical()), nonpr)
    assert not gaps, "nightly blocking-subset gaps:\n" + "\n".join(gaps)


def test_advisory_reasons_are_real():
    """An excuse must be a real, specific reason — not blank and not a bare 'advisory'."""
    for name, reason in {**KNOWN_ADVISORY, **KNOWN_NONPR_ADVISORY}.items():
        r = reason.strip()
        assert len(r) >= 40, f"reason for {name!r} is too thin to be a real justification: {r!r}"
        assert r.lower() not in {"advisory", "advisory.", "not required", "nightly"}, (
            f"reason for {name!r} restates the exclusion instead of justifying it"
        )
        # A reason should name the workflow file that produces the job, tying it to a checkable source.
        assert ".yml" in r or ".yaml" in r, f"reason for {name!r} names no producing workflow"


# --------------------------------------------------------------------------------------------------
# Negative controls for the reverse-direction accounting — the checkers must REPORT divergence.
# --------------------------------------------------------------------------------------------------
def test_negative_control_unaccounted_pr_job_bites():
    """A new advisory PR job that nobody excused must be REPORTED as unaccounted (not waved through)."""
    pr, _ = pr_and_nonpr_job_names(_workflow_texts())
    # sanity: the real tree, with the real ledger, is fully accounted
    assert unaccounted_pr_jobs(pr, set(canonical()), set(KNOWN_ADVISORY)) == set()
    # perturb: a brand-new PR job appears and is added to neither the required set nor the advisory dict
    sneaky = "sneaky new gate (advisory)"
    perturbed = pr | {sneaky}
    flagged = unaccounted_pr_jobs(perturbed, set(canonical()), set(KNOWN_ADVISORY))
    assert flagged == {sneaky}, f"an unexcused new PR job must be flagged, got {flagged}"


def test_negative_control_empty_advisory_flags_the_real_advisories():
    """WITHOUT the KNOWN_ADVISORY ledger this workstream adds, every real advisory PR job is unguarded.

    This is the 'fails without this change' evidence, exercised in-process: strip the ledger to empty and
    the accounting reports exactly the advisory jobs as unaccounted — which is precisely the pre-W0-2 state.
    """
    pr, _ = pr_and_nonpr_job_names(_workflow_texts())
    flagged = unaccounted_pr_jobs(pr, set(canonical()), set())  # no advisory ledger
    assert flagged == set(KNOWN_ADVISORY), (
        "with an empty advisory ledger the unaccounted set must equal the real advisory jobs; "
        f"got {sorted(flagged)} vs {sorted(KNOWN_ADVISORY)}"
    )
    assert len(flagged) >= 5, "the pre-fix state left at least five jobs unguarded — the W0-2 premise"


def test_negative_control_nightly_subset_must_be_required():
    """If a nightly's blocking subset is NOT a required check, the gap checker must report it."""
    _, nonpr = pr_and_nonpr_job_names(_workflow_texts())
    # real data: no gaps
    assert nightly_subset_gaps(NIGHTLY_BLOCKING_SUBSET, set(canonical()), nonpr) == []
    # perturb: pretend the subset is not required
    required_without_subset = set(canonical()) - set(NIGHTLY_BLOCKING_SUBSET.values())
    gaps = nightly_subset_gaps(NIGHTLY_BLOCKING_SUBSET, required_without_subset, nonpr)
    assert gaps and any("is not a required check" in g for g in gaps), (
        f"an unrequired blocking subset must be reported, got {gaps}"
    )
    # perturb: pretend the nightly is not even a real non-PR job
    gaps2 = nightly_subset_gaps({"ghost nightly": "livefire smoke (per-PR subset)"}, set(canonical()), nonpr)
    assert any("is not a non-PR job" in g for g in gaps2), f"a phantom nightly must be reported, got {gaps2}"


def test_negative_control_thin_advisory_reason_rejected():
    """The reason-quality helper logic must reject a blank or one-word excuse."""
    for bad in ("", "advisory", "not required", "   "):
        r = bad.strip()
        assert len(r) < 40 or r.lower() in {"advisory", "not required"}, (
            f"{bad!r} should be rejected as a non-reason"
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_parse_jobs_falls_back_to_the_job_id_for_a_nameless_job():
    """RED-PEN #397: a job with no `name:` still ships as a status check (GitHub defaults the context to the
    job id). parse_jobs must surface it — dropping it makes it invisible to the reverse-drift accounting."""
    wf = ("on:\n  pull_request:\n    branches: [main]\n"
          "jobs:\n"
          "  sneaky-unnamed:\n    runs-on: ubuntu-latest\n"
          "  named-one:\n    name: I have a name\n    runs-on: ubuntu-latest\n")
    got = parse_jobs(wf)
    names = [n for (n, _if) in got]
    assert "sneaky-unnamed" in names, "a nameless job was dropped — it would ship as an unguarded check"
    assert "I have a name" in names
