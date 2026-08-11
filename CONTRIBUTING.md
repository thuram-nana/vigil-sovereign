# Contributing to VIGIL — branch & merge policy

VIGIL is maintained by **Junior Thuram Nana** (the "Maintainer"). The `main` branch is
**protected**. This document is the authoritative repository-level statement of how changes
reach `main`. Engine-specific contribution mechanics and the full doctrine references live in
[`engine/crucible/CONTRIBUTING.md`](./engine/crucible/CONTRIBUTING.md).

---

## The one rule

> **Only the Maintainer pushes to `main` directly. Everyone else contributes through a pull
> request that the Maintainer reviews and merges.**

There is no other path into `main`. Direct pushes from anyone who is not the repository owner
are rejected by the branch ruleset.

## How to contribute a change

1. **Fork** the repository (or, if you are a collaborator, create a **branch** — never commit
   to `main`).
2. Make your change on a feature branch, then `git push origin <branch>`.
3. **Open a pull request** against `main`. Fill in the PR template honestly.
4. A pull request can be merged only when **all** of the following hold:
   - the **code owner** (the Maintainer) has approved it;
   - at least **one approving review** is on the most recent push;
   - all **review conversations are resolved**;
   - the commits are **signed** (see "Signing", below);
   - the branch does not force-push over or delete protected history.
5. The Maintainer merges. That is the only way your code lands on `main`.

## Signing your commits

Signed commits are required. Set up signing once (GPG or SSH):

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
