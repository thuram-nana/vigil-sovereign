# Runbook — release, upgrade and rollback

Owner-run, authorized-target framework. This runbook is the end-to-end procedure for cutting a VIGIL
release, upgrading an existing install to it, and rolling back if an upgrade goes wrong. It is **true of
the code**: every `vigil` / `sigil` / `vigil-gateway` / `python3 -m framework.v2` command below is a real
subcommand, and `docs/tests/test_release_runbook.py` (in the required "the briefing explains every agent
and capability" CI job) fails the build if any documented command stops existing — so the runbook cannot
rot away from the tooling it describes.

It concerns the release tooling added by **W4-2 (#442)** (one product `VERSION`, `--version` on every
CLI, `CHANGELOG.md`, `tools/release/changelog.py`, and the tag-triggered
`.github/workflows/release.yml`) and the crash-safe data migration added by **W5-5 (#449)**
(`vigil upgrade`).

## The claim (registered in the claims registry — [W0-3] #398, id `W4-4`)

<!-- CLAIM:W4-4 -->
> **Registered claim (W0-3 #398):** The release, upgrade and rollback runbook documents only real CLI subcommands, and a required doc test fails the build if a documented command name stops existing in the code.

Why it is TRUE of the code: `docs/tests/test_release_runbook.py` extracts every CLI subcommand this
runbook uses in its fenced code blocks and resolves each against the CLI source by AST
(`add_parser(...)` for `vigil`/`sigil`/`vigil-gateway`, the `_DISPATCH` table for `framework.v2`, and the
`_ENV` passthrough verbs for `vigil <subsystem>`). A negative control renames a command out of the
vocabulary and asserts the runbook that still names it is flagged.

## 0. What version am I running?

Every entry point answers, before any gate, on a fresh or degraded install. All four report the same
product version, an honest build id (`.dirty` for an uncommitted tree, `+unknown` off a git checkout) and
the git sha:

```
vigil --version
sigil --version
vigil-gateway --version
python3 -m framework.v2 --version
```

The product version is the single fact in the repo-root `VERSION` file (W4-1, #441); `vigil doctor`
gives the fuller install self-check.

```
vigil doctor
```

---

## 1. Release — cut a new version

A release is a signed git tag. The tag push triggers `.github/workflows/release.yml`, which builds the
`vigil-core` wheel + sdist, signs them (cosign / SLSA provenance / PEP 740), generates and signs the
CycloneDX SBOMs, verifies everything offline with a tamper negative control, and publishes a GitHub
Release for the tag carrying those artifacts and the changelog section as its notes.

1. **Bump the single product version.** Edit `VERSION` (e.g. `0.1.0` → `0.1.1`) and bump every
   first-party package to match. `docs/tests/test_product_version_consistency.py` (required CI) fails if
   any package drifts, so this step is checked, not trusted.

2. **Update the changelog.** Move the `## [Unreleased]` entries into a new `## [X.Y.Z] - DATE` section.
   You can render a section from the commit range to start from:

   ```
   python3 tools/release/changelog.py render --version X.Y.Z --from vPREV --to HEAD
   ```

   `docs/tests/test_changelog_staleness.py` (required CI) fails if the new `VERSION` — or any release tag
   — has no matching `## [X.Y.Z]` section, so a release with no changelog entry cannot merge.

3. **Verify locally before tagging.** Run the required guards and the install self-check:

   ```
   python3 -m pytest docs/tests/test_product_version_consistency.py docs/tests/test_changelog_staleness.py docs/tests/test_release_runbook.py -q
   vigil verify
   ```

4. **Tag and push.** Land the version/changelog change on `main` through a PR (branch-protected), then
   tag the merge commit and push the tag:

   ```
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

   The tag push runs `release.yml`. It never runs on pull requests (a release must not sign every PR
   head); its shape is asserted on every PR by `integration/tests/test_release_provenance.py` and
   `integration/tests/test_release_github_release.py`.

5. **Confirm the release.** The workflow attaches the signed artifacts and their `*.cosign.bundle` /
   `*.publish.attestation` side-cars to the GitHub Release, with the changelog section as the notes
   (extracted by `python3 tools/release/changelog.py notes --version X.Y.Z`).

---

## 2. Upgrade — move an existing install to a new version

VIGIL is deployed from a git checkout with two editable venvs (`.venv-offense` / `.venv-sovereign`), so
an upgrade is: get the new code, rebuild the venvs, then run the crash-safe **data** migration.

1. **Contain the running cockpit** so nothing writes mid-upgrade:

   ```
   vigil down
   ```

2. **Get the new code.** Check out the release tag (or pull `main`):

   ```
   git fetch origin
   git checkout vX.Y.Z
   ```

3. **Rebuild the two venvs + the WARDEN kernel** (idempotent; re-runnable):

   ```
   ./bootstrap.sh
   ```

   `bootstrap.sh` re-runs `envs/build_envs.sh`, which reinstalls the editable members, so `--version`
   immediately reports the new sha.

4. **Migrate the sovereign data store.** Check first (touches nothing; exit 3 means a migration is
   needed), then run it. `vigil upgrade` forwards to `sigil upgrade` in the sovereign venv and performs
   `backup → verify → migrate → verify → report`, **rolling back to the verified backup on any
   failure** — it never leaves a half-migrated store:

   ```
   vigil upgrade --check
   vigil upgrade
   ```

   (`sigil upgrade --check` / `sigil upgrade` are the same verb run directly in the sovereign venv;
   `vigil upgrade --no-backup` skips the pre-migration backup only if you have taken your own.)

5. **Verify and restart.**

   ```
   vigil --version
   sigil doctor
   vigil verify
   vigil up
   ```

---

## 3. Rollback — undo a bad upgrade

There are two independent things to roll back: the **code** and the **data**.

### 3a. Automatic data rollback (the common case)

If `vigil upgrade` fails, it has already rolled the store back to the verified pre-migration backup and
says so in its report — no action is needed for the data. Roll the **code** back to the previous version:

```
vigil down
git checkout vPREV
./bootstrap.sh
vigil --version
vigil verify
vigil up
```

### 3b. Manual data restore (if the store is damaged)

Take portable, passphrase-encrypted, off-box backups so a store can always be restored onto a fresh
`SIGIL_HOME`. A backup is also taken automatically by `vigil upgrade` before it migrates.

```
sigil backup /secure/offbox/vigil-backup.age
```

To restore, point `restore` at a **fresh** home directory; it verifies the backup before writing and
swaps it in atomically (`--force` is required to replace a non-empty home):

```
sigil restore /secure/offbox/vigil-backup.age /new/SIGIL_HOME --force
sigil verify
```

Then bring the code to the matching version (section 3a) and restart with `vigil up`.

### 3c. Emergency stop

If an upgrade or rollback goes wrong while engagements are live, hard-stop everything (this trips every
engagement's kill-switch and masks the cockpit unit — see `docs/runbooks/PANIC-AND-CONTAINMENT.md`):

```
vigil panic
```

---

## How this runbook is kept honest

| Documented behaviour | Executed / asserted by (required CI) |
|---|---|
| Every CLI command named here exists | `docs/tests/test_release_runbook.py` |
| One product version across packages | `docs/tests/test_product_version_consistency.py` |
| `--version` reports version + build id + git sha (dirty/unknown-aware) | `packages/core/vigil_core/tests/test_build_info.py` + per-CLI `test_cli_version.py` |
| `CHANGELOG.md` is not stale vs. `VERSION`/tags | `docs/tests/test_changelog_staleness.py` |
| The tag-triggered release workflow signs + attests + publishes | `integration/tests/test_release_provenance.py`, `integration/tests/test_release_github_release.py` |
| `vigil upgrade` migrates crash-safely and rolls back on failure | the W5-5 sovereign upgrade suite under `apps/sigil/tests/` |

A **manual drill** is still required for the parts CI cannot exercise end to end without a real tag and a
real second host: performing an actual `git tag` + `git push` release, and an actual
`sigil backup`/`sigil restore` onto a second machine. Record the result (date, version, operator) in the
engagement log when you run it.
