# Contributing to CRUCIBLE — branch & merge policy

CRUCIBLE is maintained by **Junior Thuram Nana** (the "Maintainer"). The `main`
branch is **protected**. This document is the authoritative statement of how
changes reach `main`.

---

## The one rule

> **Only the Maintainer pushes to `main` directly. Everyone else contributes through
> a pull request that the Maintainer reviews and merges.**

There is no other path into `main`. Direct pushes from anyone who is not the
repository owner are rejected by the branch ruleset (see below).

## How to contribute a change (everyone except the Maintainer)

1. **Fork** the repository (or, if you are a collaborator, create a **branch** — never
   commit to `main`).
2. Make your change on a feature branch:
   ```bash
   git checkout -b my-change
   # ... edit, commit ...
   git push origin my-change
   ```
3. **Open a pull request** against `main`. Fill in the PR template honestly.
4. A pull request can be merged only when **all** of the following hold:
   - the **code owner** (the Maintainer) has approved it;
   - at least **one approving review** is on the most recent push;
   - all **review conversations are resolved**;
   - the commits are **signed** (see "Signing", below);
   - the branch does not force-push over or delete protected history.
5. The Maintainer merges. That is the only way your code lands on `main`.

## What is protected on `main`

The `main` branch ruleset enforces:

| Rule | Effect |
|---|---|
| **Require a pull request before merging** | No direct commits to `main` for non-owners. |
| **Require 1 approving review + code-owner review** | The Maintainer must approve every PR. |
| **Dismiss stale approvals on new pushes** | A new push invalidates prior approvals. |
| **Require approval of the most recent push** | The latest code must be reviewed, not just an old version. |
| **Require conversation resolution** | No merging with unresolved review threads. |
| **Require signed commits** | Every commit must be cryptographically signed. |
| **Block force pushes** | History on `main` cannot be rewritten. |
| **Block deletion** | `main` cannot be deleted. |
| **Owner bypass** | Only the repository **admin (the Maintainer)** may push to `main` directly. |

The Maintainer (repository admin) is on the ruleset **bypass list**, which is what
makes "only the owner can push to `main`" true while everyone else is routed through
pull requests.

## Signing your commits

Signed commits are required. Set up signing once:

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

Every contribution is reviewed against the project's doctrine (see
[`CLAUDE.md`](CLAUDE.md), [`DISCLAIMER.md`](DISCLAIMER.md), and
[`V2-LIMITATIONS.md`](V2-LIMITATIONS.md)):

- **Authorized-use / defensive posture only** — no offensive capabilities the project
  deliberately excludes.
- **Prove-don't-guess, near-zero false positives** — new detections fire only on a
  re-runnable proof; otherwise they are LEADs, not blocks/facts.
- **`make gate` stays byte-identical** — `python3 -m framework.v2 benchmark --gate
  --no-incumbents` must still pass `9/0/0 f1=1.000 reqs=853`; new `OracleKind`
  members stay out of the frozen `_ALL_ORACLES`.
- **Additive / opt-in, tests included and green.**

## Licensing of contributions

By opening a pull request you agree to the contribution terms in
[`LICENSING.md`](LICENSING.md) (inbound = PolyForm Noncommercial 1.0.0, plus a grant allowing the
Licensor to also license your contribution commercially). If you cannot grant those
rights, do not submit the contribution.

<!-- Active branch ruleset: main-protection (id 18831938). Only the repository admin bypasses it. -->
