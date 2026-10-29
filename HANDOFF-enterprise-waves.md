# HANDOFF — enterprise parallel-3 waves (2026-10-29)

Continuation doc so this work resumes in the cloud / a fresh session with zero context loss.

## State: 4 branches pushed to origin (thuram-nana/vigil-sovereign)

| Branch | What | Status |
|---|---|---|
| `strix/enterprise-tenantfound` | FOUNDATION: fail-closed `tenant_id` reconciliation in the job gate (org==tenant_id) | **PR #974 OPEN, in CI**. Red-penned (sound, 2 LOW fixed). 44 tests green. MERGE FIRST on green. |
| `strix/enterprise-identity` | owner-signed Org/Workspace + membership + `org_tenant_id` mapping (`apps/sigil/sigil/governor/orgs.py`) | WIP pushed. 28 tests green, FATAL-2 clean. **Red-pen was in flight — RE-RUN before merge.** No PR yet. |
| `strix/enterprise-kb` | per-org knowledge-base corpus (`engine/crucible/framework/v2/knowledge_base/`) | WIP pushed. 13 tests green. **RED-PEN FOUND ISSUES — FIX before merge (below).** No PR yet. |
| `strix/enterprise-ticketing` | ticketing-out GitHub Issues push (`engine/crucible/framework/v2/mcp/ticketing_{config,push}.py`) | WIP pushed. 58 tests green. **Red-pen was in flight — RE-RUN before merge.** One `OFFENSE_ACTION_PERM` route added. No PR yet. |

All four branch off main `999d6cc4`. Only `enterprise-ticketing` edits a shared seam (`vigil_core/rbac.py`), so merges are otherwise conflict-free. Merge order: **foundation → (identity ∥ kb ∥ ticketing)**.

## SHARED CONTRACT (all waves): org == `tenant_id`
Read the active tenant via `from framework.v2.common.paths import active_tenant` (validated `CRUCIBLE_TENANT`, or `None`=global). Key everything `(tenant_id, slug)`. Do NOT re-wrap `targets_root()`/`target_dir()` — per-engagement artifacts already sit under the per-tenant `CRUCIBLE_ROOT`.

## MUST-FIX before merging `enterprise-kb` (red-pen, 4 findings)
1. **HIGH — cross-tenant symlink leak.** `corpus()` → `_load_report_json(slug)` (`aggregate.py:367`) and `_build_engagement` existence checks (`:349-350`) read `report.json` with NO `_safe_target_dir`/`paths.is_within` containment gate — unlike `_findings_from_files` (:277) and `_reports` (:315) which have it. `_engagement_slugs()` uses `iterdir()`+`is_dir()` (follows symlinks). ⇒ a symlink `targets/<slug> -> /otherOrg/targets/<slug>` pulls another org's `report.json` (active_findings emitted as oracle_confirmed=True) into this org's corpus. FIX: gate the report.json read + the `:349-350` checks on `_safe_target_dir(slug) is not None` (or resolve+is_within inside `_load_report_json`), mirroring the other two readers.
2. **MED — test-gap:** the containment guard has ZERO coverage (neutralizing `is_within`/`_safe_target_dir` leaves all 13 tests green). Add a two-root symlink-escape test + a direct containment unit test.
3. **LOW — schema-drift crash:** `aggregate.py:196`/`:211` iterate `report.get("active_findings") or []` raw; a truthy non-iterable scalar (e.g. `5`) raises TypeError that crashes the WHOLE-org corpus (contract says "never fatal"). FIX: `isinstance(x, list)` guard / `_as_list()` helper.
4. (a 4th finding was reported — re-run the kb red-pen to recover its detail; its output was local-only.)

## Red-pens to RE-RUN (results were local, lost on shutdown)
- `enterprise-identity` (3-lens, heaviest — crypto owner-signed fold, cross-org isolation, FATAL-2/tests) and `enterprise-ticketing` (2-lens — egress/credential safety, fail-closed config/never-a-fact/FATAL-2/tests) red-pens were in flight. The BUILDS are preserved; re-run the adversarial red-pen before opening their PRs.

## REPRODUCIBLE ENV (cloud / fresh box — NOT the local graphify venv)
The local `/home/kali/graphify/venv` + `PYTHONPATH=packages/core/vigil_core:gateway:engine/crucible:integration:.` was a local convenience. The portable recipe is what CI uses (see `.github/workflows/ci.yml`): `pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt` ; `pip install -e packages/core/vigil_core --no-deps` ; `pip install --require-hashes -r infra/supply-chain/ci-tooling.lock.txt` ; then `PYTHONPATH=.` and `pytest integration/tests` (sovereign leg, framework ABSENT) + the offense-leg list (framework present). The sovereign keys / TPM vault are LOCAL by design (sovereignty) and are NOT in the cloud — anything needing a real key can't run there.

## Then
Merge all on green (foundation first). Two product DECISIONS deferred for the owner: (a) the org-admin funnel (who seats members without the owner key signing — `orgs.py` kept `owner` non-grantable per-org); (b) ticketing push RBAC tier (owner vs operator). After these waves: S5+ infra = the approved AWS/Firecracker/KMS-Enclave hosting (memory `vigil-strix-shell-hosting-decision`).
