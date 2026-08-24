# W12-4 — Enforce signed commits

Issue: [#493](https://github.com/thuram-nana/vigil-sovereign/issues/493) ·
Milestone: W12 — PROCESS HYGIENE.

## The goal

Every commit that lands on `main` should carry a cryptographic signature that ties it to a key the
maintainer controls, so history cannot be forged with a spoofed `author`/`committer` line. GitHub shows
signed commits as **Verified**, and branch protection can **require** them.

## Two halves — and which one is a human/admin action

Enforcing signed commits has two parts, and it is important to be honest about which one this repository
can ship from code:

1. **The server-side rule (human/admin).** Branch protection on `main` has a **"Require signed commits"**
   toggle. When it is on, GitHub rejects any push whose commits are not signed. This is a
   repository-administration setting changed through the GitHub UI (*Settings → Branches → branch
   protection rule for `main`*) or the Administration API. **A repository cannot enable it from inside
   its own tree.** So this slice does not, and must not, claim it is on.

   > **HUMAN/ADMIN ACTION (residual for #493):** Enable *Require signed commits* on the `main` branch
   > protection rule. NOTE: this will **block unsigned pushes** immediately, so it must be a deliberate
   > operator choice — every contributor (and every automation that pushes) must have signing configured
   > first, or their pushes will start failing. Roll it out only after the maintainers have run
   > `tools/governance/setup-commit-signing.sh` and registered their public keys with GitHub.

2. **The developer-side setup + verification (shipped here).** What the repository CAN own is the
   tooling a contributor uses to configure and check local signing *before* they push, so the day the
   server-side rule is flipped, nobody is surprised by a rejected push.

## The decision (what ships in this slice)

- [`tools/governance/setup-commit-signing.sh`](../../tools/governance/setup-commit-signing.sh) —
  configures this clone to sign commits, in either **SSH** (`gpg.format ssh`) or **GPG/OpenPGP** mode,
  by setting `commit.gpgsign`, `user.signingkey` (and `tag.gpgsign`). It configures LOCAL (per-repo)
  git config by default so it never silently rewrites a developer's global git, and prints how to
  register the public key with GitHub so signatures show as Verified.
- [`tools/governance/commit_signing.py`](../../tools/governance/commit_signing.py) — the single source
  of truth for the check. `signing_config_defects(config)` is a pure function that decides whether a git
  config will produce signed commits (`commit.gpgsign` truthy, `user.signingkey` set, `gpg.format` valid
  if present).
- [`tools/governance/verify-commit-signing.sh`](../../tools/governance/verify-commit-signing.sh) — a
  thin wrapper over the Python check, so there is no shell reimplementation to drift.
- `SECURITY.md` / `CONTRIBUTING.md` point contributors at the setup step.

## The claim (registered in the claims registry, id `W12-4`)

<!-- CLAIM:W12-4 -->
> **Registered claim:** A commit-signing setup script configures git to sign commits and a shared verify check (`signing_config_defects`) decides whether a working copy will produce signed commits — passing a fully configured setup and rejecting one missing `commit.gpgsign` or `user.signingkey` — so a contributor can confirm local signing before pushing; the server-side "Require signed commits" branch-protection rule that rejects an unsigned push is a documented human/admin action and is NOT claimed to be enabled.

## Why this is TRUE of the code

- [`integration/tests/test_commit_signing_setup.py`](../../integration/tests/test_commit_signing_setup.py)
  is the guard. It asserts the three tools exist and are executable, that the shell scripts drive the
  one Python check (no drifting reimplementation), and that `signing_config_defects` passes a configured
  setup and rejects one missing `commit.gpgsign`/`user.signingkey` or carrying a bogus `gpg.format`. It
  runs in the required **integration two-env boundary (P5)** CI job.
- **End-to-end**, the test drives the CLI against a REAL throwaway git repo under an isolated git
  config (so the developer machine's own global signing cannot leak in): the CLI exits non-zero on the
  unconfigured repo and zero once signing is configured.
- **Fails without the change.** Without `tools/governance/commit_signing.py` the test cannot import the
  check and collection errors red (observed). With an empty config `signing_config_defects` reports
  defects — the negative control that proves the check is not a no-op.
- The test needs **no gpg/ssh key material**: it configures signing purely as git config, because the
  claim is about the *configuration* a contributor controls, not about a cryptographic verification of
  arbitrary history (that is the server-side rule above).

## Residual

- The **"Require signed commits"** branch-protection flip (§2.1) is the single human/admin action that
  makes the server reject unsigned pushes. It is intentionally not enabled here because it blocks pushes
  the moment it is on. Issue #493 stays open pending that deliberate rollout.
