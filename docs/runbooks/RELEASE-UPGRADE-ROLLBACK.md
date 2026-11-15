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

   **The tag is the release.** A host is upgraded to exactly the commit a release tag names, and only when
   that commit is on `origin/main` (section 2.1); a branch head or an untagged commit is never deployed.

   The tag push runs `release.yml`. It never runs on pull requests (a release must not sign every PR
   head); its shape is asserted on every PR by `integration/tests/test_release_provenance.py` and
   `integration/tests/test_release_github_release.py`.

5. **Confirm the release.** The workflow attaches the signed artifacts and their `*.cosign.bundle` /
   `*.publish.attestation` side-cars to the GitHub Release, with the changelog section as the notes
   (extracted by `python3 tools/release/changelog.py notes --version X.Y.Z`).

---

## 2. Upgrade — move an existing install to a new version

A production host runs VIGIL as systemd **user** units (GO-LIVE §6): the cockpit (the one spine writer), the
customer and public edges, the console, the bridge and witnesses, and the timers that fire the money drains,
backups, checkpoints and the HA mirror. The install is editable, so an upgrade replaces the code under every
one of them: stop **all** of them, back up with the old build, build and migrate, then start exactly the units
that were running. Run every step in one shell, from the checkout (`~/vigil`); `$U` keeps this upgrade's record.

### 2.1 Pick the release by its tag

```
cd ~/vigil
git fetch origin --tags
TAG=vX.Y.Z
git merge-base --is-ancestor "$TAG^{commit}" origin/main && echo "$TAG is on main"
SHA="$(git rev-parse "$TAG^{commit}")"
U=~/vigil-upgrade-"$TAG"-"$(date +%Y%m%dT%H%M%S)"; mkdir -p "$U"
vigil --version > "$U/from-version"
```

Stop here unless the tag's commit is on `origin/main`. When your clone holds the release signer's key,
`git verify-tag "$TAG"` checks the tag's signature as well.

### 2.2 Preflight (nothing is stopped yet)

```
vigil doctor
systemctl --user is-enabled vigil-command.service
```

`vigil doctor` must exit 0: clear every hard issue first — in particular settle and money settings that
differ between the cockpit, the customer edge, the settle drain and ops-sweep. Do not upgrade a host that
`vigil panic` contained (`vigil-command.service` reads `masked`); close the incident first.

### 2.3 Quiesce: let money in flight finish

Wait until no customer engagement is running and the drains have taken every pending signal (the paths are
the defaults; use the ones your env files set):

```
ls "${VIGIL_BASE_DIR:-$HOME/vigil/.vigil-live}"/jobs/running/
ls ~/.sigil/spool/settle/incoming/ ~/.sigil/spool/findings/incoming/
ls "${SIGIL_HOME:-$HOME/.sigil}"/billing-spool/incoming/ "${SIGIL_HOME:-$HOME/.sigil}"/stripe-billing-spool/incoming/
sigil ops-sweep reservations
```

Each `incoming/` empties within a drain cycle (60 s). With `VIGIL_SETTLE_SPINE_RECORD` off, never stop while
a settle may be in progress: wait until the settle spool's `incoming/` is empty and no settle drain is
running (2.4 waits for the drain). With it on in every settling process (`vigil doctor` reports them in
agreement), a settle a stop interrupts is finished from its spine record on the settle drain's first pass
after the upgrade.

### 2.4 Stop every unit: timers first, then running oneshots, then services

```
# 1. record and stop every vigil/sigil TIMER, so no drain, backup, checkpoint or HA-mirror run starts
systemctl --user list-units --type=timer --state=active --plain --no-legend 'vigil-*' 'sigil-*' \
  | awk '{print $1}' > "$U/timers"
cat "$U/timers"                       # vigil-ha-mirror.timer (the off-host rsync of ~/.sigil) is one of them
xargs -r systemctl --user stop < "$U/timers"

# 2. wait for a oneshot that was already running (a drain pass, a backup push, a mirror rsync) to finish
while systemctl --user list-units --type=service --state=activating --plain --no-legend 'vigil-*' 'sigil-*' \
      | grep -q .; do sleep 5; done

# 3. record and stop the long-running services: the edges and the console first, the cockpit (the writer) last
systemctl --user list-units --type=service --state=running --plain --no-legend 'vigil-*' 'sigil-*' \
  | awk '{print $1}' > "$U/services"
systemctl --user stop sigil-customer.service sigil-public.service 'sigil-customer@*.service' \
  'sigil-public@*.service' vigil-command.service 'sigil-bridge@*.service' 'vigil-witness@*.service'
systemctl --user stop sigil-cockpit.service

# 4. confirm nothing is left running
systemctl --user list-units --state=active,activating --plain --no-legend 'vigil-*' 'sigil-*'
```

Step 4 lists nothing but finished oneshots (`active exited`, e.g. `vigil-bringup.service`). Stopping
`vigil-command` this way keeps its boot start, and every edge finishes the requests it already accepted
before it exits; while they are down the nginx vhosts answer customers with a 503 "briefly unavailable"
page. A system-level `aegis-saas-gateway@` instance, where one runs, is stopped and recorded the same way
with `sudo systemctl`.

### 2.5 Back up with the old build, after the writers stopped

```
ls -laR ~/.sigil/spool/ "${SIGIL_HOME:-$HOME/.sigil}"/billing-spool/ \
  "${SIGIL_HOME:-$HOME/.sigil}"/stripe-billing-spool/ > "$U/spools" 2>&1
systemctl --user start vigil-backup-push.service      # or vigil-backup.service when no off-host push is set up
systemctl --user status vigil-backup-push.service --no-pager
```

The backup unit runs `vigil backup` with your configured passphrase, base dir and destination (`--push`
verifies the copy at the destination); by hand it is
`vigil backup --out ~/vigil-backups --base-dir "$VIGIL_BASE_DIR" --push "$VIGIL_PUSH_DEST"`. It must succeed
before anything changes. The sovereign leg leaves the pending-signal spools out by design; `$U/spools`
records what was in them.

### 2.6 Get the release and build it

```
git checkout --detach "$SHA"
./bootstrap.sh
vigil --version
# install the release's version of every unit this host has installed (a release can change a unit)
for u in ~/.config/systemd/user/*.service ~/.config/systemd/user/*.timer; do
  [ -f "$u" ] && [ ! -L "$u" ] || continue
  for d in apps/sigil/deploy/systemd infra/systemd; do
    if [ -f "$d/${u##*/}" ] && ! cmp -s "$d/${u##*/}" "$u"; then
      diff -u "$u" "$d/${u##*/}" || :; cp "$d/${u##*/}" "$u"
    fi
  done
done
```

`bootstrap.sh` rebuilds the two hash-locked venvs, the WARDEN kernel and the egress guard
(`envs/build_envs.sh`) and links `~/.sigil/venv` to `.venv-sovereign`; `vigil doctor` reports that link if
it is anything else. Plain `./bootstrap.sh` does not touch the installed units, so the loop installs the
release's copy of each unit this host has and prints what changed; 2.8 reloads systemd before anything starts.
A release can change a unit in a way the code relies on — the customer edge, for example, finishes an action
the cockpit is still completing for up to 75 s, and its units allow 90 s before systemd kills it; with a unit
from an older release (20 s) a stop would cut such an action, the customer told it failed. Keep local changes in
drop-ins (`systemctl --user edit <unit>`), which the loop leaves alone. `vigil doctor` (2.9) reports an edge unit
whose stop timeout is too short, and `tools/deploy/edge-swap.sh` refuses to swap with one.

### 2.7 Migrate the sovereign data store

Check first (touches nothing; exit 3 means a migration is needed), then run it. `vigil upgrade` forwards to
`sigil upgrade` in the sovereign venv and performs `backup → verify → migrate → verify → report`,
**rolling back to the verified backup on any failure** — it never leaves a half-migrated store:

```
vigil upgrade --check
vigil upgrade
```

(`sigil upgrade --check` / `sigil upgrade` are the same verb run directly in the sovereign venv;
`vigil upgrade --no-backup` skips the pre-migration backup only if you have taken your own — 2.5 is not a
substitute for it.)

### 2.8 Start exactly the recorded units, the cockpit first

```
systemctl --user daemon-reload
systemctl --user start sigil-cockpit.service
until curl -fsS http://127.0.0.1:8733/readyz; do sleep 2; done      # the spine opens
xargs -r systemctl --user start < "$U/timers"
xargs -r systemctl --user start < "$U/services"
```

The drains' timers start after the cockpit (they settle through its spine), then every service that was
running — nothing that was not.

### 2.9 Verify

```
vigil --version
vigil doctor
sigil verify
vigil verify
vigil verify-integrity
```

Watch one drain cycle pass (`vigil alerts --status`, or `systemctl --user list-timers 'vigil-*'`) before you
call the upgrade done. If anything fails, roll back (section 3).

## 3. Rollback — undo a bad upgrade

There are two independent things to roll back: the **code** and the **data**.

### 3a. Automatic data rollback (the common case)

If `vigil upgrade` fails, it has already rolled the store back to the verified pre-migration backup and
says so in its report — no action is needed for the data. Roll the **code** back to the previous version
with the same stop and restore as the upgrade: stop every unit (2.4, recording into a new `$U` if they were
started again), check out the previous release's commit, rebuild, and start the recorded units (2.8):

```
git checkout --detach "$(git rev-parse "vPREV^{commit}")"
./bootstrap.sh
vigil --version
vigil verify
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

## 4. Deploy-verify — prove a deploy is healthy, or auto-rolls-back (W11-8, #489)

A deploy is not "done" when the new code is in place; it is done when a **post-deploy smoke** has
confirmed the running system is healthy — and if it is not, the deploy has **automatically rolled back**
to the prior version and that prior version has been re-verified intact. The `deploy_verify` pipeline
(`apps/sigil/sigil/spine/deploy_verify.py`) makes that a real, falsifiable procedure by reusing the
upgrade/rollback machinery of section 2/3.

1. **Post-deploy smoke — run `make smoke`, and honour its exit code.** After the upgrade of section 2,
   before you re-open the cockpit, run the boundary + native-verb smoke. A non-zero exit means the
   deployment is unhealthy — do NOT keep it up:

   ```
   make smoke
   ```

2. **Drive the full deploy-verify pipeline** (a healthy deploy stands; a deliberately-broken one is
   caught by the post-deploy smoke and automatically rolled back, with the prior version restored and
   its owner signature + full record set re-verified). It prints a JSON verdict and exits non-zero if the
   pipeline did not behave correctly:

   ```
   python3 -m sigil.spine.deploy_verify --smoke-cmd 'make smoke'
   ```

3. **If the smoke failed**, the pipeline has already restored the prior data plane from the pre-deploy
   verified backup (section 3a's automatic data rollback). Roll the **code** back to the previous version
   (section 3a) and re-run `make smoke` to confirm the restored version is healthy before re-opening
   `vigil up`.

The FAST, deterministic core of this pipeline — the healthy-deploy, broken-deploy-caught-and-rolled-back
negative control, and the smoke-exit-code-is-honoured proof — runs on **every PR** in the required
`SIGIL governor gates (P7 …)` job (`apps/sigil/tests/test_deploy_verify.py`). The **heavy** variant that
builds the two venvs and runs the REAL `make smoke` end to end is the scheduled
`.github/workflows/deploy-verify.yml` (honestly NOT a required check — it never reports on a PR).

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
| A deploy runs a post-deploy smoke (exit code honoured) and auto-rolls-back a broken deployment, restoring the prior version intact | `apps/sigil/tests/test_deploy_verify.py` (required `SIGIL governor gates (P7 …)` job) |

A **manual drill** is still required for the parts CI cannot exercise end to end without a real tag and a
real second host: performing an actual `git tag` + `git push` release, and an actual
`sigil backup`/`sigil restore` onto a second machine. Record the result (date, version, operator) in the
engagement log when you run it.
