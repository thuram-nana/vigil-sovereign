# W1-8 — GitHub control files live at the repository root, and a guard keeps new nested ones out

Issue: [#417](https://github.com/thuram-nana/vigil-sovereign/issues/417) ·
Milestone: W1 — CI ENFORCEMENT: make the gates actually gate. Lands with [W12-1] #490 (the root
pull-request template) so the deletion never leaves the repository with no template at all.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W1-8 -->
> No `.github/workflows/` and no pull-request template exists outside the repository root (vendored third-party trees under `vendor/` excepted), and a required-CI guard fails the build when a nested one is reintroduced.

This claim is TRUE of the code as of W1-8.

## The defect

GitHub reads a workflow, a `CODEOWNERS`, or a pull-request template from a **fixed set of paths
relative to the repository root** — `.github/workflows/`, `.github/CODEOWNERS` (or `CODEOWNERS` /
`docs/CODEOWNERS`), `.github/pull_request_template.md`, and a few siblings. A copy of any of those
nested under a subdirectory is **inert**: GitHub never reads it, so the control it appears to state
has never applied to a single pull request.

Two vendored subtrees carried exactly such inert files:

- `apps/sigil/.github/workflows/ci.yml` — a whole CI workflow that never ran on this repository;
- `engine/crucible/.github/pull_request_template.md` and `engine/crucible/.github/CODEOWNERS` — a
  PR template and a code-owners file GitHub never reads here.

This is the same class of defect the root `CODEOWNERS` was created to fix (see the header comment in
[`.github/CODEOWNERS`](../../.github/CODEOWNERS)): *a file that looks like a control and is not one.*
It matters because as-built documentation can cite such a file as a protection — a claim about a
file, not about the repository's behaviour.

## The fix

### 1. Delete the inert nested trees

`apps/sigil/.github/` and `engine/crucible/.github/` are removed. The real, root-level equivalents
already exist and are the ones GitHub reads: [`.github/workflows/`](../../.github/workflows) (the
live CI), [`.github/CODEOWNERS`](../../.github/CODEOWNERS), and — added in [W12-1] #490 —
[`.github/pull_request_template.md`](../../.github/pull_request_template.md).

### 2. A guard so a nested one cannot come back

`nested_github_offenses` in
[`integration/tests/test_nested_github_guard.py`](../../integration/tests/test_nested_github_guard.py)
walks the tree and returns every `.github/workflows/` file and every `pull_request_template.md`
that lives in a **nested** `.github/` — the two inert classes GitHub reads only from the root and
that most mislead. Three tests pin it:

- `test_no_nested_github_workflows_or_templates_outside_root` — the invariant. **FAILS on a tree
  without the fix**: pointed at the pre-fix tree it reports `apps/sigil/.github/workflows/ci.yml`
  and `engine/crucible/.github/pull_request_template.md`.
- `test_negative_control_scanner_flags_a_nested_workflow` and
  `test_negative_control_scanner_flags_a_nested_pr_template` — the **negative controls**. They point
  the same detector at a throwaway fixture tree containing a nested workflow / nested template and
  assert each is flagged, while the legitimate root workflow in the same fixture is not — proving
  the gate is neither a no-op nor a false-alarm, both asserted in the same run.

The guard is framework-free and sigil-free (pure stdlib file reads), so it runs in the required
**integration two-env boundary (P5)** job, which collects the whole `integration/tests` tree. A
reintroduced nested workflow or template therefore cannot merge to `main`.

## Honest scope

- **Vendored trees under `vendor/` are exempt.** `vendor/strix/.github/` (upstream Strix) still
  carries its own workflow and issue templates. We ship `vendor/` as a faithful upstream snapshot
  and do not rewrite it; its `.github/` is just as inert here (it changes nothing about how this
  repository behaves) but it is not one of *our* misleading controls. The exemption is scoped to a
  `vendor/` path component, and `test_negative_control_vendored_github_tree_is_exempt` proves it is
  scoped — a non-vendored nested workflow in the same tree is still flagged.
- The guard flags the two classes GitHub reads only from the root and that most mislead — nested
  workflows and nested pull-request templates. A nested `CODEOWNERS` is deleted here but not made a
  standing guard class; the root-`CODEOWNERS` requirement is enforced elsewhere, and no nested
  `CODEOWNERS` remains outside `vendor/`.
- CODEOWNERS assigns reviewers; it only *blocks* a merge when branch protection also requires code-
  owner review, which `main` does not enable today. This change removes an inert copy; it does not
  claim to turn ownership into an enforced gate.
