# W5-7 — N-1 → N upgrade / rollback + schema-compat harness

Issue: [#451](https://github.com/thuram-nana/vigil-sovereign/issues/451) ·
Milestone: W5 — UPGRADE & DATA MIGRATION (the biggest product risk).

## The claim (registered in the claims registry — [W0-3] #398, id `W5-7`)

<!-- CLAIM:W5-7 -->
> **Registered claim (W0-3 #398):** The N-1 to N upgrade/rollback harness proves that realistic owner-signed build-(N-1) spine data upgrades to build N and rolls back to N-1 with its owner signature and the N-1 record set intact, and that the spine's schema changes are additive-only in both directions so a non-additive schema change makes the harness fail.

The fuller statement, and why it is TRUE of the code:

> A spine of realistic **owner-signed** build-(N-1) data (legacy single-file layout, records with no
> `schema_version` key) upgrades to build N (retain-all segment layout) with the **owner signature still
> verifying over the migrated store**; a build-N writer's `schema_version` == 1 records coexist with the
> legacy records under one re-signed head; and a **rollback restores the N-1 store with the original owner
> signature and the N-1 record set intact**. The forward/backward schema-compat **matrix** — an old build reads
> new data, a new build reads old data, for additive and non-additive changes — is all-green over the real
> enforcement primitives, and a **deliberately non-additive schema change makes the whole-harness verdict
> FAIL**.

## The defect this closes

There was no test that exercised a **version boundary** end to end. W5-5 ([#449]) shipped the crash-safe
migrate/rollback orchestrator (`upgrade.py`) and `test_spine_upgrade.py` proved it preserves the *unkeyed*
chain (`store.verify()`). W5-1/W5-2 ([#445]/[#446]) shipped the per-record `schema_version` and the
additive-only payload contract with their own diff/upcast tests. Nothing tied them together into the
property an operator actually depends on across a release: that a spine of **owner-signed** data survives
an N-1 → N upgrade and a rollback with the signature intact, and that the schema changes which made that
safe are provably additive-only in **both** directions. This slice is that harness.

## What "N-1" and "N" mean here

The spine plane versions along two axes, both exercised:

- **Structural layout** — legacy single-file `spine.jsonl` (N-1) → retain-all segment layout (N).
  `upgrade()` performs this migration; it is the one that physically moves bytes.
- **Per-record `schema_version`** — a pre-W5-1 record carries **no** `schema_version` key (reads back as
  `LEGACY_SCHEMA_VERSION` == 0, the N-1 shape); a build-N writer stamps `SCHEMA_VERSION` == 1. Because
  `schema_version` sits **outside** the digested `content` (like `seq`/`ts`/the chain fields), the two
  shapes are chain- and signature-identical — which is *precisely* why the migration is safe, and the
  harness proves that exclusion is **load-bearing** (`schema_version_is_load_bearing`): a hypothetical
  non-additive change that folded `schema_version` into the digest would produce a different `cert_digest`
  and break the owner signature.

## The harness (`apps/sigil/sigil/spine/upgrade_harness.py`)

A reusable, importable verification tool (like `migrate_runner` / `upgrade`), not only a test —
`python -m sigil.spine.upgrade_harness` runs it and prints the JSON verdict; `--soak` runs the heavier
variant.

- `build_n_minus_1_signed_spine(...)` — installs realistic build-(N-1) SIGNED data: a legacy single-file
  spine of hash-chained records with **no** `schema_version` key, anchored by a real owner-signed head
  (the same `vigil_core` `sign_head`/`verify_head` primitives production uses, hermetically — a fresh
  keypair + temp dirs, so no `SIGIL_HOME`/vault singletons and fully deterministic).
- `run_upgrade_rollback_roundtrip(...)` — build N-1 → `upgrade()` to N → re-verify the owner signature
  over the migrated store → build-N writer appends `schema_version` == 1 records (mixed {0,1} spine
  verifies under one head) → `restore_from_backup()` rolls back → re-verify the original signature + record
  count over the restored legacy store. `verify_signed_spine` is the per-gate check (unkeyed chain **and**
  owner signature).
- `run_compat_matrix(...)` — the forward/backward × additive/non-additive matrix over the **real**
  primitives (`SpineRecord.from_dict`, `upcast_payload`, `refuse_newer`, `diff_shapes`): a legacy record
  reads as `LEGACY_SCHEMA_VERSION`; an old payload missing a later-added optional field upcasts to its
  default; a field a newer writer added round-trips (`extra="allow"`, C5); a versioned artifact newer than
  this build is refused fail-closed, while the same version is accepted; and the payload contract permits
  no breaking drift.
- `run_full_harness(...)` — the single verdict: `ok` is True IFF the roundtrip held **and** every matrix
  cell matched **and** the payload contract shows no breaking drift. `current_shapes_override` injects a
  substitute shape set for the negative control without touching the live models.

## Tests (fail-without-the-fix + negative controls)

`apps/sigil/tests/test_upgrade_harness.py` runs in the required `SIGIL governor gates (P7 — offense gate +
authn)` CI job (that job executes the whole `apps/sigil/tests/` directory):

- **roundtrip** — the owner signature survives the migration **and** the rollback; layouts move
  legacy→segment; schema versions become {0, 1}; every record is preserved through the rollback;
- **compat matrix** — all-green, spanning both directions and both change kinds;
- **full-harness verdict** — green on the live tree;
- **negative controls (same run)** — a deliberately non-additive change (a committed field removed, or a
  field retyped) makes the whole-harness verdict **FAIL**; the signed-verify gate rejects a corrupted
  store; `refuse_newer` accepts the same version (not "refuse always"); and the additive digest exclusion
  is proven load-bearing.

Every test FAILS on a pre-W5-7 tree: `sigil.spine.upgrade_harness` does not exist, so the module import
errors (collection error). Observe it: `git stash` the harness module, run the file, see the red,
`git stash pop`.

## The fast/heavy split (honest labelling)

The **required PR job** runs the fast, deterministic core above — the schema/migration + signed-record
layer where a version boundary is actually falsifiable. A heavier **full-stack SOAK** variant
(`test_fullstack_soak_large_multisegment_spine`, a ~3000-record multi-segment spine forcing real gzip
compaction across the migration) is **opt-in via `VIGIL_UPGRADE_HARNESS_SOAK`** and wired to the scheduled
`.github/workflows/upgrade-harness-soak.yml` job — it **skips** (never silently passes) in the required
job. The soak is not claimed to run in PR CI.

## What remains (honest residual)

A true cross-git-**TAG** full-stack install — check out the previous *released* tag, install that build,
write data with it, then upgrade to HEAD and roll back — is the heaviest variant. It is **deferred until a
released N-1 tag exists**: the repo is pre-1.0 (`VERSION` == 0.1.0) with no prior release tag, so there is
no genuine N-1 build to install. The harness is structured so that variant plugs into the same
`build → upgrade → verify → rollback → verify` frame (driving the real `sigil upgrade` CLI over a built
sovereign venv) once a released tag is available; until then it is honestly not claimed. The signed-record
+ schema/migration falsifiability — where a non-additive change silently corrupts already-signed data — is
fully covered by the required job today.

[#445]: https://github.com/thuram-nana/vigil-sovereign/issues/445
[#446]: https://github.com/thuram-nana/vigil-sovereign/issues/446
[#449]: https://github.com/thuram-nana/vigil-sovereign/issues/449
