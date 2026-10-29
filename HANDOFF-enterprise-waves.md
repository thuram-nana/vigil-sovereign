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

---

# RED-PEN FINDINGS + FIX PLAN (all waves red-penned 2026-10-29) — fix before merge

**MERGE IS CURRENTLY BLOCKED repo-wide** by a supply-chain gate (below), independent of the wave code. Do NOT merge anything unsound; each wave fix must be re-red-penned (the HIGHs especially).

**PROGRESS 2026-10-29 (localized fixes APPLIED + pushed):**
- KB — HIGH symlink leak + LOW schema-drift FIXED (branch `strix/enterprise-kb` @ `e34f5979`; +3 regression tests, 16 green, ruff clean). Containment now gates the report.json read + `_build_engagement` + `_engagement_slugs`; `_as_list` guards schema drift.
- Ticketing — both MEDs FIXED (branch `strix/enterprise-ticketing` @ `8ee3386c`; +4 regression tests, 61 green, ruff clean). `_parse_host` no longer echoes the raw host; `collector_scope_conflicts` disjointness now runs unconditionally.
- REMAINING (NOT rushed — careful work): the **identity HIGH** (prune-replay resurrection; needs the SnapshotState seed + prune-tripwire + docstring correction) and its reactivation MED; the **litellm/A14** vendored bump; then re-red-pen each fixed wave + merge (foundation first, after A14 is green).

## BLOCKER 0 — A14 supply-chain gate RED on EVERY branch (and main): litellm CVE
- Trivy flags **`litellm` 1.90.1 → fixed 1.95.0**, GHSA-g5ff-637f-6q2m (HIGH, arbitrary local file read), in **`vendor/strix/uv.lock`** (vendored Strix; `uv` lock, not pip). It is time-dependent (Trivy DB) so it reds main + all 5 branches; A14 is a required check, so NOTHING merges until fixed.
- Policy = bump, not suppress (there is a `.trivyignore` but the repo's doctrine is no-suppression — memory `vigil-ci-maintenance-a14-formal`). `vendor/strix/pyproject.toml` pins bare `litellm` + `openai-agents[litellm]==0.14.6`. `uv` 0.11.29 is available.
- FIX (its own small supply-chain PR, merged FIRST, then rebase the waves): `cd vendor/strix && uv lock --upgrade-package litellm` (target ≥1.95.0), confirm `openai-agents==0.14.6`'s litellm extra permits 1.95.0, re-run Trivy locally, land it. CAUTION: a vendored uv.lock regen can move many transitive pins — review the diff; this is careful, not a rush.

## FOUNDATION (`strix/enterprise-tenantfound`, PR #974) — CODE CLEAN
Red-pen sound (2 LOW already fixed). Its only red check is BLOCKER 0. Merge FIRST once A14 is green.

## KB (`strix/enterprise-kb`) — 1 HIGH + 1 MED + 2 LOW
1. **HIGH cross-tenant symlink leak** — `aggregate.py` `corpus()`→`_load_report_json` (line ~367) and `_build_engagement` existence checks (~349-350) read `report.json` with NO `_safe_target_dir`/`paths.is_within` containment gate the other two readers (`_findings_from_files` ~277, `_reports` ~315) have; `_engagement_slugs` uses `iterdir()`/`is_dir()` (follows symlinks). A symlink under `targets/` escapes to another org's root (leaked findings emitted oracle_confirmed=True). FIX: gate the report.json read + the existence checks on `_safe_target_dir(slug) is not None` (or resolve+is_within inside `_load_report_json`), mirroring the other two readers.
2. **MED test-gap** — the containment guard has ZERO coverage (neutralizing `is_within`/`_safe_target_dir` keeps all 13 green). Add a two-root symlink-escape test + a direct containment unit test.
3. **LOW schema-drift crash** — `aggregate.py` ~196/211 iterate `report.get("active_findings") or []` raw; a truthy non-iterable scalar crashes the WHOLE-org corpus. FIX: `isinstance(x, list)` / `_as_list()` guard.
4. (a 4th provenance-lens finding was reported — re-run the kb red-pen to recover; lower severity.)

## TICKETING (`strix/enterprise-ticketing`) — 4 MED (no HIGH)
1. **MED credential echo** — `ticketing_config.py` `_parse_host` (~261/266/270) echoes the RAW `host` via `{host!r}` in refusal messages; a credentialed host (userinfo/token/query) leaks into the operator-UI/log `TicketingConfigIssue.message`, contradicting its own "never echoes a secret" contract and diverging from `evidence_config._parse_http_host` (which echoes only the urlsplit hostname). FIX: redact / detect+refuse userinfo like evidence_config; add a non-echo test.
2. **MED disjointness guard untested + bypassable** — `ticketing_push.py` the `collector_scope_conflicts` sink/attack-scope disjointness refusal + default allowlist build run ONLY inside `if allowlist is None:` (~451-459); a caller-supplied allowlist SKIPS the disjointness check entirely (could POST a finding to an in-scope attack target). Not live (no dispatch handler yet). FIX: run `collector_scope_conflicts([target.host], _target_scope(slug))` unconditionally; test both paths.
3. (2 more MED — the allowlist=None coverage gap is the same root; recover the 4th from the ticketing red-pen output.)

## IDENTITY (`strix/enterprise-identity`) — 1 HIGH + MEDs (heaviest wave)
1. **HIGH prune-replay membership/org resurrection** — `orgs.py` `_fold_orgs`/`_fold_memberships` (~304-366) rebuild the anti-replay high-water ONLY from `store.iter_records()` with NO SnapshotState seed, UNLIKE `accounts._fold` (which seeds from committed SnapshotState so a hard prune can't reset the high-water). The prune tripwire `prune.stranded_active_accounts` matches ONLY `governor.account`, not `governor.org`/`governor.org_membership`, and `snapshot.py` carries no org rows. ⇒ after an owner-gated hard prune crosses a revoked membership's grant seq, the high-water resets to -inf and a replayed owner-signed active grant RESURRECTS the revoked membership (fail-OPEN). The module's ANTI-REPLAY docstring (~34-37) OVERCLAIMS ("cannot happen", "same guard accounts carries" — it is NOT). FIX (do BEFORE wiring org_role_can to any consumer): seed org+membership into SnapshotState + extend the prune tripwire to the two org signals + correct the overclaiming docstring. Mitigated now: org_role_can is unwired + prune is owner-gated. This is subtle crypto-soundness — do NOT rush.
2. **MED org-reactivation resurrects stale memberships** — `revoke_org` (~245-255) revokes only the org row, not its memberships; `membership_role` (~392) gates only on the org's CURRENT active state, so `revoke_org`→`create_org` on the SAME org_id (supported reactivation) restores every prior member's role with no fresh grant. Since org==tenant_id, reusing a decommissioned slug hands the old tenant's members roles in the new tenant. FIX: cascade-revoke memberships on revoke_org, OR epoch-gate a membership to the org's current create-grant (valid only if issued after the active incarnation). Document + test.
3. (3 more findings — mostly the same reactivation root via the cross-org lens; re-run the identity red-pen for full detail. The build is otherwise FATAL-2-clean, 28 tests, owner-signed fold faithful to accounts for the non-prune case.)

## ORDER TO EXECUTE
1. litellm/A14 bump (own PR) → unblocks all merges.
2. Foundation #974 → merge (code already clean).
3. KB: fix HIGH+MED+LOW → re-red-pen → PR → merge.
4. Ticketing: fix the 2 MED + tests → re-red-pen → PR → merge.
5. Identity: fix HIGH (snapshot-seed + prune-tripwire + docstring) + reactivation MED → re-red-pen (heaviest) → PR → merge. Do NOT rush the crypto fix.
Then the two product decisions (org-admin funnel; ticketing RBAC tier), then S5+ infra.
