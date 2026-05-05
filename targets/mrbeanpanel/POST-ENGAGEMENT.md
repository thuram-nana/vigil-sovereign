# POST-ENGAGEMENT — `mrbeanpanel.com` (first real engagement)

**Date:** 2026-05-05
**Operator:** Satoshi
**Substrate:** ClaudeCodeBackend (Claude Max OAuth, model=haiku, per-call $0.20 cap)
**Sovereignty tier:** PERMISSIVE (development-phase appropriate; would be wrong for sovereign deployment)
**Posture:** TEST
**Run shape:** reduced from directive default — 50 planner-request budget / $2 USD cap / 1800 s wall-clock; **GET-only via operator-pre-stated deny-all on destructive prompts**.
**Outcome:** completed cleanly on `max_steps=15`; pytest reports 1 passed in 10.86s.

---

## 1. Run statistics

| Metric | Value | Note |
|---|---|---|
| UTI requests | 9 | well under 50-budget |
| UTI archetype | `php-smarty-smm-panel-fork` (0.745) | matches Session 1 + 3 captures |
| Planner steps | 15 | halt reason `max_steps=15` (configured ceiling) |
| Planner dispatched | 15 | every leaf reached the executor |
| Planner succeeded | 0 | zero confirmed findings (see § 4) |
| Planner wall-clock | 10 s | 0.6 % of the 1800 s budget |
| Executor requests made | 15 | = number of leaves dispatched |
| Executor scope violations | 0 | every URL passed the gate |
| Executor budget refusals | 0 | nowhere near the 20-request executor cap |
| Executor destructive refusals | 0 | no destructive surfaces in the seeded surface set |
| Hypotheses on blackboard | 30 | 15 dispatched + 15 superseded as `refuted` |
| Findings emitted | 0 | nothing for critique-agent to fire on |
| Critiques fired | 0 | follows from zero findings |
| Tokens (URK calls) | n/a in this run | UTI's threat-model drafter ran during step 8; planner+executor used no URK in this run shape |
| Estimated cost | < $0.05 | UTI threat-model draft + scaffolder, no LLM during the planner run |

---

## 2. What the planner dispatched

Goal tree was seeded against the URL-derived surface set (`/`, `/robots.txt`, `/sitemap.xml`) × the archetype's common bug classes:

```
L-0003  IDOR    /              L-0004  IDOR    /robots.txt    L-0005  IDOR    /sitemap.xml
L-0006  SQLi    /              L-0007  SQLi    /robots.txt    L-0008  SQLi    /sitemap.xml
L-0009  XSS     /              L-0010  XSS     /robots.txt    L-0011  XSS     /sitemap.xml
L-0012  CSRF    /              L-0013  CSRF    /robots.txt    L-0014  CSRF    /sitemap.xml
L-0015  SSRF    /              L-0016  SSRF    /robots.txt    L-0017  SSRF    /sitemap.xml
```

15 GET requests issued, all 200 OK. Body sizes consistent across reissues (78909 B for `/`, 207 B for `/robots.txt`, 5081 B for `/sitemap.xml`) — the target served identical content for every probe, as expected.

---

## 3. Confirmed findings

**Zero.** This is the correct output for this run shape, not a framework bug.

`HttpExecutor` is structurally incapable of auto-claiming `success=True` (per its design — the exploit-agent decides, based on a richer evidence chain than a single GET response). With 15 GET requests and no operator-confirmation on destructive flows, no exploit could be confirmed. The framework gave honest output: "I made the requests, captured the bodies, found nothing I could confidently classify as a bug from this surface set."

The framework did not hallucinate findings. That is the critical safety property this run validated.

---

## 4. Rejected findings (calibration data)

**Zero rejected because zero proposed.** No critique data this run — the critique-agent had no findings to evaluate. A run that exercises destructive flows or richer surface enumeration would put the critique gate to work.

---

## 5. Operational issues surfaced

These are framework-level observations from this run, ranked by importance:

### 5.1 UTI scaffolds into a host-derived slug, not the operator's existing slug

UTI created `targets/mrbeanpanel-com/` (slug derived from URL host: `mrbeanpanel.com` → `mrbeanpanel-com`) instead of using the operator's existing `targets/mrbeanpanel/` engagement folder. The signed charter lives at the latter, so the live test had to be invoked with `CRUCIBLE_LIVE_HTTP_SLUG=mrbeanpanel` to point past the new-folder default.

**Recommendation:** UTI's slug derivation should accept an `existing-engagement` mode where, if `targets/<slug>/charter.md` already exists for a manually-chosen slug, UTI reuses it rather than scaffolding a parallel folder. Or: UTI prompts the operator at first run when a host-derived slug collides with an existing folder. Track for next FORGE session.

### 5.2 Planner seeds a Cartesian product across surfaces × bug-classes

The 15 dispatched leaves were every (surface, bug_class) pair, regardless of whether the bug class can plausibly reproduce against that surface. SSRF on `/robots.txt` is structurally implausible; CSRF on a static GET is meaningless. This is fine for a thin first-run smoke test, but for richer engagement the seeder should prune leaves where the bug class is incompatible with the surface's HTTP semantics.

**Recommendation:** Add a leaf-pruner heuristic: bug classes have an `applicable_methods` and `applicable_surface_kinds` declaration; seeder skips combinations that can't plausibly reproduce. Track for next FORGE session.

### 5.3 The recon-agent never fired

`observation` count on the blackboard = 0. The planner dispatched directly from the seeded goal tree without a recon-agent pass. This is consistent with how the existing test harness wires the agents (planner-driven dispatch only), but it means we never exercised the framework's hypothesis-from-observation flow against a real target.

**Recommendation:** Future engagements should wire the recon-agent so it probes the surface inventory under UTI, posts observations, and the hypothesis-agent generates URK-driven hypotheses from those — a richer signal than the seeded Cartesian product.

### 5.4 Posture detection works correctly

`parse_posture("mrbeanpanel")` returned `TEST` after the operator-marked `[x]` checkbox. The framework correctly applied TEST-posture rate limits and the `OBSIDIAN/1.0 (authorized owner-test 2026-05-05)` user-agent. Operator can correlate this UA in their access logs.

### 5.5 Charter signature gate held

The framework refused to act on the unsigned charter through three iterations of "edited and saved" before the operator's edit landed in the right file. The gate did exactly what it should: refuse, surface, wait. No active request reached the wire while the gate said no.

### 5.6 Scope gate held

All 15 URLs validated in scope (`mrbeanpanel.com` matches charter § 2). Zero scope violations. The `host_matches_scope()` parser correctly skipped the `N/A — no known mobile app` placeholder row.

### 5.7 Evidence capture worked

16 directories under `targets/mrbeanpanel/evidence/`, each containing `request.http`, `response.http`, `response.body`. The full HTTP exchange is preserved per action.

### 5.8 No framework crashes, no unexpected exceptions

Test passed cleanly. mypy stayed green. v1 canon untouched.

---

## 6. Recommendations

### Operator should validate by hand

- The fingerprint output shows `framework: perfect-panel (0.99)` — confirm the panel's actual codebase. If it's a fork that's diverged significantly, UTI's archetype-specific attack tree may have stale assumptions worth correcting.
- Look at the `/robots.txt` and `/sitemap.xml` content captured at `targets/mrbeanpanel/evidence/H-*/response.body` — even a casual review may surface admin paths or non-public endpoints worth scoping into a follow-up engagement.
- The 207-byte `robots.txt` is suspiciously terse for a site with 44k users / 967k orders. Worth checking whether `/sitemap.xml` is the only sitemap variant served (the panel may also expose `/sitemap_index.xml`, `/sitemap_users.xml`, etc.).

### Should be patched on mrbeanpanel.com immediately

**Nothing identified by this run.** Zero findings means zero immediate patches. This run was a plumbing validation, not a security review.

### Next FORGE session focus

In rough priority order:

1. **UTI slug re-use** (issue 5.1) — make UTI honour an existing engagement folder rather than scaffolding a parallel one when the operator has already created the canonical slug.
2. **Surface-aware leaf pruning** (issue 5.2) — drop leaves where bug class × surface combinations are structurally implausible. Saves request budget and reduces noise.
3. **Recon-agent wired into the live pipeline** (issue 5.3) — so a real engagement gets richer observation→hypothesis flow than the Cartesian seed.
4. **Run shape escalation** — operator's stated intent: a larger second engagement informed by this one. That run should:
   - Surface a richer attack-tree seed (URK-drafted from the threat model, not just archetype defaults).
   - Wire the recon-agent.
   - Approve a small budget of destructive-action confirmations on test accounts (per § 5 of the charter — the OBSIDIAN-TEST-* users are pre-provisioned).
   - Push the budget to the operator's original directive shape (200 / $10 / 4h) so the planner can iterate beyond the 15-step ceiling.

---

## 7. Honest framing

This engagement validated the framework's plumbing end-to-end against a real production target:

- ✓ Charter signature gate held under operator iteration
- ✓ Scope gate validated 15/15 URLs
- ✓ Posture parser correctly applied TEST defaults
- ✓ HttpExecutor issued bounded GET requests with correct UA, captured full evidence, never auto-claimed success
- ✓ Planner halted cleanly on its configured ceiling
- ✓ No framework crashes, no unexpected exceptions, no scope violations

It did **not** validate the framework's finding-discovery capability against this target. GET-only against 3 static surfaces is structurally incapable of reproducing the bug classes (IDOR/SQLi/XSS/CSRF/SSRF) the planner attempted. That validation is for the next engagement.

The framework graduates from "verified at integration test" (Sessions 3/4 against synthetic harnesses) to "verified in real engagement against an operator's production target" (this run). The most important graduation since Session 3.

---

## 8. Regression fixture

Captured at:
`framework/v2/planner/tests/fixtures/live-run/mrbeanpanel-first-engagement/`

Contents: `engagement-stdout.log`, `crucible-v2.log` (138 lines structured), `fingerprint.json`, `uti-threat-model.md`, `uti-attack-tree.md`, `run-summary.json`. Path is gitignored (`framework/v2/planner/tests/fixtures/live-run/mrbeanpanel-*/`); operator data does not commit to the public repo.

---

## 9. Engagement log addendum

Engagement remains in **state ACTIVE** at engagement-log § "Next steps queued". The first run completed. Sub-steps 15-19 (capture / docs / handoff) are this document. The engagement does not close until objectives § 8 of the charter are addressed, which this run did not attempt. Operator decides whether the next run is the same engagement (continued) or a new engagement (new charter version, fresh log).
