# W12-1 — A pull-request template at the root path GitHub reads, and CONTRIBUTING points to it

Issue: [#490](https://github.com/thuram-nana/vigil-sovereign/issues/490) ·
Milestone: W12 — PROCESS HYGIENE. Shares its guard test with [W1-8] #417.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W12-1 -->
> A pull-request template exists at the repository-root path GitHub reads (`.github/pull_request_template.md`), and CONTRIBUTING.md directs contributors to that real path.

This claim is TRUE of the code as of W12-1.

## The defect

[`CONTRIBUTING.md`](../../CONTRIBUTING.md) tells every contributor to "fill in the PR template" —
but no template existed at a path GitHub reads. The only one present was
`engine/crucible/.github/pull_request_template.md`, nested where GitHub never looks (see [W1-8]
#417). So a new pull request opened against this repository came up **blank**: the instruction
pointed at a control that did not exist where it needed to.

## The fix

### 1. A real root template

[`.github/pull_request_template.md`](../../.github/pull_request_template.md) now exists at the
repository-root path GitHub reads, so it pre-fills into every new pull request. It is adapted to the
vigil-sovereign monorepo rather than the engine alone: the doctrine & safety checklist covers the
two-env boundary (FATAL-2), determinism on signed/decision paths, opt-in/default-OFF new powers, the
byte-identical `make gate`, a negative control for any new guard, and registering any product claim
in the claims registry.

### 2. CONTRIBUTING points to the real path

The "open a pull request" step in [`CONTRIBUTING.md`](../../CONTRIBUTING.md) now links
`.github/pull_request_template.md` explicitly and states that GitHub loads it from that root path,
so the instruction and the mechanism agree.

### 3. The inert nested template is gone

`engine/crucible/.github/pull_request_template.md` is deleted as part of [W1-8] #417.

## The guard (shared with [W1-8] #417)

[`integration/tests/test_nested_github_guard.py`](../../integration/tests/test_nested_github_guard.py)
pins both halves:

- `root_pr_template_defect` is the enforcing symbol; `test_root_pull_request_template_exists`
  asserts the root template is present and non-empty. **FAILS on a tree without the fix** (the
  pre-fix tree had no root template at all).
- `test_contributing_points_to_the_real_pr_template_path` asserts CONTRIBUTING references
  `.github/pull_request_template.md`.
- `test_negative_control_missing_root_template_is_rejected` — the **negative control**: a tree with
  a missing template, then an empty template, is rejected, and a real one passes, all in one run —
  proving the check is not a constant-pass no-op.

It runs in the required **integration two-env boundary (P5)** job.

## Honest scope

GitHub renders `.github/pull_request_template.md` into the PR description box for a web-opened pull
request; a PR opened purely over the API or `gh pr create` with an explicit body does not have it
inserted. The guard proves the file exists at the path GitHub reads and that CONTRIBUTING points
there — it does not, and offline cannot, assert GitHub's live rendering behaviour.
