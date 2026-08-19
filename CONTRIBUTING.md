# Contributing to VIGIL — branch & merge policy

VIGIL is maintained by **Junior Thuram Nana** (the "Maintainer"). The `main` branch is
**protected**. This document is the authoritative repository-level statement of how changes
reach `main`. Engine-specific contribution mechanics and the full doctrine references live in
[`engine/crucible/CONTRIBUTING.md`](./engine/crucible/CONTRIBUTING.md).

---

## The one rule

> **Only the Maintainer pushes to `main` directly. Everyone else contributes through a pull
> request that the Maintainer reviews and merges.**

There is no other path into `main`. Because the branch carries required status checks, a direct
push of un-checked commits to `main` is rejected for everyone except the repository admin (the
Maintainer), who keeps an explicit override — see "What the ruleset actually enforces" below.

## How to contribute a change

1. **Fork** the repository (or, if you are a collaborator, create a **branch** — never commit
   to `main`).
2. Make your change on a feature branch, then `git push origin <branch>`.
3. **Open a pull request** against `main`. Fill in the PR template honestly.
4. The Maintainer reviews and merges. That is the way your code lands on `main`.

## What the ruleset actually enforces

Honesty matters more than an impressive list, so this states exactly what branch protection on
`main` **mechanically** enforces today, and — separately — what the Maintainer applies by hand as
policy. The two are not the same, and reading a policy as an enforced control is how a repository
ends up claiming guarantees it does not have.

**Enforced by the branch ruleset — a pull request cannot merge unless all hold:**

- all **13 required status checks are green** — the exact set is committed in
  [`.github/required-status-checks.txt`](./.github/required-status-checks.txt), and any drift is
  caught offline by `docs/tests/test_required_checks_canonical.py` and against the live settings by
  the `branch-protection-verify` workflow;
- the branch is **up to date with `main`** (`strict`) — it must be rebased on current `main`, so a
  check cannot pass against stale code;
- **`main` cannot be force-pushed over or deleted** — history cannot be rewritten to sidestep the
  checks.

Because `enforce_admins` is **off**, the Maintainer (the repository admin) retains an explicit,
attributable override and *can* merge without the checks being green. Every other contributor and
every automated agent is bound unconditionally.

**Maintainer policy, applied by hand — NOT yet enforced by the ruleset (a planned handoff):**

- the Maintainer reviews the change and resolves review conversations before merging;
- commit signing (below) is requested.

These are deliberately not turned on as required controls yet: required reviews
(`required_pull_request_reviews`) and required signed commits are a scheduled protection handoff,
not a shipped guarantee. Do not describe them as enforced.

## Signing your commits

Signed commits are **requested** — recommended for every contribution and part of the planned
protection handoff — but they are **not currently required by the branch ruleset**. Setting up
signing once (GPG or SSH) is still worth doing:

```bash
# GPG
git config --global user.signingkey <your-key-id>
git config --global commit.gpgsign true
# or SSH signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Then upload the public key to your GitHub account (Settings → SSH and GPG keys).

## Running the checks locally (pre-commit)

The repository ships a [`.pre-commit-config.yaml`](./.pre-commit-config.yaml). Install it once and the
hooks run on every `git commit`:

```bash
pipx install pre-commit    # or: pip install pre-commit
pre-commit install         # register the git hook
pre-commit run --all-files # run every hook over the whole tree
```

The hooks are:

- **ruff** — blocks on real bug classes (E9/F/B) over the SIGIL package, the same scope and config the
  `SIGIL lint` CI job blocks on;
- **mypy (fast subset)** — a *can-complete* gate on the SIGIL package (it fails only if mypy cannot
  finish — e.g. a parse / type-comment abort; pre-existing type-error debt is not gated here);
- **gitleaks** — secret scanning, reading [`.gitleaks.toml`](./.gitleaks.toml) (the upstream default
  ruleset plus an audited allowlist of synthetic test / fixture material);
- **workflow-lint** — `yamllint` over `.github/workflows/` with
  [`.github/yamllint-workflows.yaml`](./.github/yamllint-workflows.yaml);
- **trailing-whitespace / end-of-file-fixer / check-yaml** — file hygiene and YAML parse-validity;
- **claims / doc-truth** — the shipped doc-truth checks (the full suite is the required
  `the briefing explains every agent and capability` CI job).

Several hooks are deliberately **scoped** so `pre-commit run --all-files` is green on the current tree;
the scopes widen as [#419](https://github.com/thuram-nana/vigil-sovereign/issues/419) (ruff / mypy for
every package) and [#398](https://github.com/thuram-nana/vigil-sovereign/issues/398) (the claims
registry) land.

**You cannot hide a problem from review by skipping the local hook.** `git commit --no-verify` skips
the *local* run, but the advisory `pre-commit` workflow re-runs the identical hooks on your pull
request — together with negative controls that prove each gate still rejects bad input — so the checks
execute where they cannot be bypassed. That CI leg is advisory: it is intentionally not part of the
required status-check set committed in
[`.github/required-status-checks.txt`](./.github/required-status-checks.txt).

## What your change must satisfy

Every contribution is reviewed against the project's doctrine
([`engine/crucible/CLAUDE.md`](./engine/crucible/CLAUDE.md),
[`engine/crucible/DISCLAIMER.md`](./engine/crucible/DISCLAIMER.md), and
[`engine/crucible/V2-LIMITATIONS.md`](./engine/crucible/V2-LIMITATIONS.md)):

- **Authorized-use / defensive posture only** — no offensive capabilities the project
  deliberately excludes.
- **Prove-don't-guess, near-zero false positives** — new detections fire only on a re-runnable
  proof; otherwise they are LEADs, not blocks/facts.
- **`make gate` stays byte-identical** — the pinned benchmark gate must still pass unchanged
  (see [`engine/crucible/CONTRIBUTING.md`](./engine/crucible/CONTRIBUTING.md) for the exact
  pinned numbers); new `OracleKind` members stay out of the frozen `_ALL_ORACLES`.
- **Additive / opt-in, tests included and green.**

## Licensing of contributions

By opening a pull request you agree to the contribution terms in
[`LICENSING.md`](./LICENSING.md) (inbound = PolyForm Noncommercial 1.0.0, plus a grant allowing
the Licensor to also license your contribution commercially). If you cannot grant those rights,
do not submit the contribution.

<!-- Active branch ruleset: main-protection. Only the repository admin bypasses it. -->
