# W11-8 (#489) — deploy-verify pipeline with rollback proof

## The gap

There was no deployment/rollback VERIFICATION. The pieces existed and were proven in isolation —
W4-2 (#442) the signed release workflow, W5-5 (#449) the crash-safe migrate/rollback orchestrator,
W5-7 (#451) the N-1 → N upgrade/rollback + schema-compat harness, and `make smoke` a boundary+CLI
smoke check — but nothing tied them into the property an operator needs at a deploy:

> deploy a build, run a post-deploy smoke, and **if the smoke fails, automatically roll back to the
> prior version and prove the prior version is restored with its owner signature and every record
> intact.**

Worse, `make smoke` had **no workflow caller at all** — a broken smoke could ship unnoticed — and
there was no negative control proving a broken deployment is actually caught rather than shipped.

## What shipped

`apps/sigil/sigil/spine/deploy_verify.py` — a reusable, importable pipeline that REUSES #451's
machinery rather than re-implementing it. A **deployment** is modelled as an upgrade of a live,
owner-signed data plane: `build_n_minus_1_signed_spine` stands up the prior (currently-deployed)
version and the real `upgrade()` orchestrator "deploys" the new build (taking + verifying its own
pre-deploy backup, which is the rollback target). The **post-deploy smoke** is either a falsifiable
health probe of the deployed data plane (`spine_health_smoke` re-verifies the deployed store's owner
signature + hash chain) or any external smoke COMMAND run through `run_smoke`, whose exit code is
**honoured** (`ok` derives solely from the process return code — the default command is `make smoke`).
On a smoke failure the pipeline calls `restore_from_backup` and **re-verifies** the restore: the
original owner signature still anchors the restored store, the layout is back to the prior (legacy)
shape, and the record count + sequence set match the prior version exactly.

`deploy_verify_roundtrip` is the load-bearing function; `python -m sigil.spine.deploy_verify` (and its
`--smoke-cmd`) runs the whole pipeline and prints a JSON verdict, exit 0 IFF it behaved correctly.

## The falsifiable properties (required PR job)

`apps/sigil/tests/test_deploy_verify.py` runs in the required `SIGIL governor gates (P7 …)` job (which
runs the whole `apps/sigil/tests/` directory). It pins:

1. a HEALTHY deployment passes post-deploy smoke and STANDS (no rollback);
2. a deliberately-BROKEN deployment (its deployed store corrupted so the health smoke fails) is CAUGHT
   and AUTO-ROLLED-BACK, and the prior version is restored with owner signature + full record set intact
   — the **negative control**, proven not a no-op (the broken store fails verification BEFORE the
   rollback and the restored store passes AFTER);
3. `run_smoke` HONOURS the smoke command's exit code (0 → pass; non-zero / missing binary / timeout →
   fail), and a non-zero-exit smoke command drives the rollback while a zero-exit one lets the
   deployment stand — the `make smoke` exit-code-honoured property (#457), proven with a stand-in
   command so the required job needs neither the built venvs nor `make`.

Every test fails on a pre-W11-8 tree: the module does not exist, so the import errors.

## The honest split (heavy variant → scheduled, not required)

A real cloud staging/canary deploy cannot run on a PR runner, and the REAL `make smoke` needs the two
isolated venvs (`.venv-offense` / `.venv-sovereign`) built by `bootstrap.sh`/`make envs` — minutes,
network — which is too heavy for every PR. Per the programme doctrine, the FAST deterministic core runs
required on every PR (above), and the heavier variant is wired to
`.github/workflows/deploy-verify.yml` (schedule + `workflow_dispatch` only, honestly **NOT** a required
check). That workflow builds the venvs, runs the REAL `make smoke` through this module's `run_smoke`
(so its exit code is honoured), and then drives `python -m sigil.spine.deploy_verify --smoke-cmd 'make
smoke'`. It is enumerated with its reason in `KNOWN_NONPR_ADVISORY` of
`docs/tests/test_required_checks_canonical.py`.

`make smoke` itself is thus now CI-invoked with its exit code honoured (it never was before): a workflow
step running `make smoke` fails the job on a non-zero exit.

## Deferred (irreducible, stated honestly)

A true multi-host cloud/canary deploy against real staging infrastructure — a second host, real DNS, a
real load balancer with a canary weight — is deferred until that infrastructure exists. The pipeline is
modelled at the level where it is falsifiable on a runner (a signed data plane, a real
upgrade/rollback, a real exit-code-honoured smoke); it does not claim to have exercised a live cloud
staging environment. This is the same honest-scope posture as W5-7's deferred cross-git-TAG install.

## The claim (registered — id `W11-8`)

<!-- CLAIM:W11-8 --> The deploy-verify pipeline deploys a build by upgrading a live owner-signed data plane, runs a post-deploy smoke whose exit code is honoured, and when the smoke fails automatically rolls back to the prior version and re-verifies it is restored with the owner signature and full record set intact; a deliberately-broken deployment is caught and rolled back, and a non-zero smoke exit drives the rollback while a zero exit lets the deployment stand.
