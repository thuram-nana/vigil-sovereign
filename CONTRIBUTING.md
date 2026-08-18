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
