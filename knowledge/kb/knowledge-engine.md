# The Knowledge Engine (K1–K6)

## What it is / its job

The Knowledge Engine is how VIGIL **learns about vulnerabilities without ever
learning them into truth**. It pulls third-party vuln intelligence (NVD, OSV,
CISA KEV), ranks the leads into a propose-to-learn queue, waits for an
owner-signed ACCEPT, then *deep-learns* a lead into advisory FIND/DETECT/PREVENT
skills and — where the deterministic oracle substrate cannot yet adjudicate a
bug class — drafts a **gated proposal** for a real oracle. A bounded self-evolve
loop turns disclosed leads into a horizon of drafted capability gaps and records
calibration forecasts. Every artifact it produces is **advisory**: a lead, a
skill, a draft proposal, a forecast. **Nothing here mints a FACT** — only a
fired deterministic oracle does that (see [`architecture.md`](architecture.md)).
The whole engine is the concrete answer to "the machine cannot lie about a
finding": it is allowed to *point at* where a bug might be, and forbidden from
*asserting* one is there.

The stages, and their code homes:

| Stage | Role | Plane | Code |
|-------|------|-------|------|
| **K1** | Intel feed — pull vuln advisories as LEADS | offense | `intel/vulnfeed.py`, `intel/scheduler.py`, `intel/ticker.py` |
| **K2** | Propose — rank leads into a learn queue | offense | `knowledge_engine/proposals.py` |
| **K2b** | Owner Accept — enqueue + owner-signed approval → signed grant | sovereign | `apps/sigil/sigil/knowledge/proposals.py`, `.../learn_grant.py` |
| **K3** | Deep-learn — FIND/DETECT/PREVENT skills + gated DETECT proposal | offense | `knowledge_engine/deeplearn.py` |
| **K4** | Point-at-a-URL learner (out of scope here; sovereign scraper) | sovereign | `apps/sigil/.../scrape/learn_source.py` |
| **K5** | Self-evolve — horizon/coverage gaps → draft proposals + calibration | offense | `knowledge_engine/evolve.py`, console `evolve_data`/`run_evolve_tick` |
| **K6** | Knowledge git-sync (secret-scan-gated commit of `knowledge/`) | integration | `vigil knowledge sync` |

The cross-plane seam between K2b and K3 is a **signed inert file spool**, not a
shared process — see [Two-env boundary](#invariant-1--two-env-boundary-fatal-2) below.

---

## K1 — the intel feed

**Job:** auto-refresh vulnerability intelligence from a fixed registry of trusted
third-party sources, minting everything as an intel-tier **LEAD**, never a fact.

- `intel/vulnfeed.py`
  - `TRUSTED_VULN_SOURCES` (lines 54–58) — the *only* hosts K1 pulls from: NVD
    (`services.nvd.nist.gov`), OSV (`api.osv.dev`), CISA-KEV (`www.cisa.gov`).
    There is **no arbitrary-URL pull** here (that is K4's separate sovereign,
    scope-gated learner).
  - `build_vulnintel_transport(source, ...)` — one `GuardedHttpTransport` scoped
    to a *single concrete apex host*; refuses any other host before bytes leave,
    and refuses a source that overlaps the engagement's charter scope.
  - `refresh_vulnintel(plan, *, transport_for, ingest, seq=0, cancel=None)` — the
    pull loop. Feeds each response through the **same offline parsers the
    file-ingest path uses** (`observations_from_kev`, `live_cve_observations`),
    so a pulled advisory is an `IntelSourceKind.VULN_DB` observation ingested by
    `IntelIngest` (seq-keyed idempotent → a re-pull never double-counts). `cancel()`
    (STOP / kill-switch) is honoured before every source and every per-CVE fetch.
- `intel/scheduler.py` — `FeedSchedule` + `run_once`. A **pure** tick predicate:
  `FeedSchedule.due(now)` (line 26) is a function of an injected monotonic tick,
  `advance` returns a *new* schedule. No thread, no `sleep`, no wallclock — so the
  feed is deterministic and trivially stoppable (the caller just stops ticking).
- `intel/ticker.py` — `run_feed_daemon(...)`. The thin, stoppable daemon that
  drives the pure scheduler on real time. The only wall-time is the injectable
  `sleep` that *paces* the loop and the tick counter — **neither feeds
  oracle/graph/learning math**. Off by default: a real `refresh` is only supplied
  under an explicit `--live`.

The console read that surfaces these leads is `vulnintel_data`; the CLI mirror
that the rest of the engine consumes is `knowledge_engine/cli.py:_vuln_leads(slug)`
(reads `IntelStore` for `VULN_DB` VULNERABILITY nodes: id, severity, cvss,
`exploit_known`, cwes, bug_class).

## K2 — propose

**Job:** rank the K1 leads into a deterministic propose-to-learn queue. Pure,
read-only, authorizes nothing.

- `knowledge_engine/proposals.py:draft_proposals(vuln_leads, *, limit=50)` — sorts
  leads *known-exploited first, then severity, then CVSS, then id* (stable
  tiebreak, lines 53–61). Returns `LearnProposal(status="proposed")` — the status
  is **always** `"proposed"` here; it only becomes owner-authorized through the
  sovereign ACCEPT (K2b). No lead is promoted, no fact minted, no oracle fired,
  no graph touched.

## K2b — owner Accept (sovereign plane)

**Job:** let the owner turn a proposal into an *authorization to learn* — and
nothing more. This is the sovereign half; the offense plane only drafts.

- `apps/sigil/sigil/knowledge/proposals.py`
  - `enqueue_learn_proposal(store, proposal, ...)` — writes an ordinary
    `decision:"queued", status:"awaiting-approval"` spine record (the same shape
    A2/A3 agent proposals use), `tier="A2"`. **Enqueuing grants nothing.**
    Idempotent by `vuln_id`; bounded at `_MAX_PENDING=200` so a distinct-CVE flood
    can't pile up. `sanitize_slug` restricts the slug to `[A-Za-z0-9-_.]` (it later
    becomes a `--slug` argv value / store key / path component).
  - `pending_learn_proposals(...)` — the queue the owner acts on; resolution is
    delegated to the owner-signed `agents.approvals.pending` (a forged approval
    never drops an item).
- The **ACCEPT itself is the existing owner-signed `ApprovalQueue.approve`** over
  the record's seq — never re-implemented or weakened here. The UI entry point is
  `apps/sigil/sigil/ui/actions.py` `queue_learn` (line 49), which refuses if the
  kill-switch is engaged **or** the `autolearn` capability latch is disabled.
- `apps/sigil/sigil/knowledge/learn_grant.py` — the K2b→K3 producer.
  - `approved_learn_grants(store, trusted_pubkey)` — for each approval that
    **verifies under the owner key** (`verify_approval`), joins its `target_seq`
    back to the queued proposal and reads `(slug, vuln_id)`. A forged / replayed /
    non-owner approval verifies to False and produces no grant. Note the approval
    signature binds only `target_seq`, not the vuln_id/slug — those are re-read
    from the joined record and re-sanitized at mint.
  - `export_approved_grants(...)` — signs an inert `learn_grant` core
    `{schema,kind,slug,vuln_id,approval_seq}` and spools it. **Fail-closed:**
    exports nothing unless the sovereign kill-switch is released AND `autolearn` is
    enabled AND an owner key exists. Idempotent via an `exported/<approval_seq>.json`
    marker written *after* the spool.

## K3 — deep-learn

**Job:** turn one accepted lead into advisory skills, and resolve DETECT onto the
deterministic oracle vocabulary — drafting a **gated** proposal when it can't.
Mints no fact, bumps no priors.

- `integration/vigil_integration/learn_drain.py` — the offense-side consumer of
  the K2b spool. `LearnGrantWatcher.drain()` verifies each grant under the owner
  **public** key (`verify_grant`, single-signer detached Ed25519 over the canonical
  core), re-derives the full lead from the offense's *own* intel by `(slug,
  vuln_id)`, and calls `deep_learn`. A bad/absent signature, wrong pubkey, non-UTF-8
  or oversized file → quarantined to `rejected/`, nothing learned; a tripped per-slug
  offense kill-switch **defers** (moved back to `incoming/` to retry), never drops.
- `knowledge_engine/deeplearn.py:deep_learn(vuln_lead, *, skills_dir, now, proposals_out=None)`
  - Writes three markdown skills under `skills_dir/{find,detect,prevent}/<id>.md`
    (SkillLoader-loadable frontmatter, **no tier/authority key** — a skill is
    guidance, it authorizes nothing).
  - `_resolve_detect(...)` (lines 86–103) resolves the vuln's `bug_class` (from an
    explicit hint or the curated `_CWE_TO_BUGCLASS` map, lines 30–40) against the
    canonical `verify.verifier.BUG_CLASS_ORACLES`:
    - **mapped** → the DETECT skill names the **existing** `OracleKind`(s) that can
      adjudicate the class (advisory — *not* a claim the vuln is present). Every
      kind is re-validated via `_coerce_oracle_kind`, which raises on an invented
      kind — so K3 can never emit a mapping onto a non-existent oracle.
    - **unmapped** → `_draft_oracle_proposal(...)` authors a `status=DRAFT`
      `improve.ImprovementProposal` for a **real deterministic** oracle
      (`change_type="add_technique"`, empty patch — *described-only*). Authorize ≠
      apply; it never touches the tree and is **never a soft/LLM oracle**.
- `knowledge_engine/retrieve.py:retrieve_skillset(...)` — the read-back
  ("graph-as-skillset"): the FIND/DETECT/PREVENT skills plus matching defensive
  CATALOG operators, capped at `MAX_SKILLS=5`, path-traversal-guarded. Advisory.

## K5 — self-evolve

**Job:** a *bounded, honest* loop that scans disclosed leads → a horizon of
capability gaps → DRAFT proposals, and records calibration forecasts. It does not
forecast undiscovered CVEs, prove anything, fire an oracle, mint a fact, or
self-apply a change.

- `knowledge_engine/evolve.py`
  - `feed_to_horizon_items(...)` / `coverage_gaps(...)` — disclosure-only horizon
    plus a `COVERAGE_GAP` per disclosed bug class the oracle substrate *cannot*
    adjudicate (exactly the class K3's DETECT drafts a gated oracle proposal for).
  - `plan_evolution(vuln_leads, *, skills_dir, now, ledger=None)` — **pure /
    read-only** (writes no skill, mutates no ledger). Produces horizon+coverage
    gaps → one DRAFT `ImprovementProposal` per gap (never merged/applied), the
    `unlearned` leads, and the `studied_enough` completion signal (done = all leads
    learned **and** all gaps drafted **and** no open predictions). "Studied enough"
    means "drafted everything for the *disclosed* leads", not "the system is
    complete" — say this plainly to the operator.
  - `record_predictions(plan, ledger, *, base_seq=0)` — the calibration seam. One
    `Prediction(oracle_confirmed=False)` per proposal, `raw_score` = the gap's
    priority ∈ [0,1]. **The forecast is not an outcome.** The outcome is recorded
    *later* by a real engagement firing / not firing the mapped oracle; `pairs()`
    then feeds `brier_score`.
- Console surfaces (two-plane note: these run in the offense/console process):
  - `console/api.py:evolve_data(slug)` (line 833) — **read-only** GET: computes the
    plan over disclosed leads + committed skills, persists nothing (a fixed epoch is
    used for display-only gap timestamps so the read is deterministic).
  - `console/actions.py:run_evolve_tick(slug)` (line 674) — the **persisting** tick:
    kill-switch gated, seeds one prediction per draft proposal into the slug's
    `OutcomeLedger`, saves, then **re-plans** so `studied_enough` reflects the
    now-open predictions. It only drafts + records; it never merges/applies a
    proposal, fires no oracle, mints no fact.
- CLI mirror: `python3 -m framework.v2 knowledge {draft,learn,skills,evolve}`
  (`knowledge_engine/cli.py`). `evolve --record` is the CLI form of the persisting
  tick; every verb is kill-switch gated under `--slug`.

---

## Invariants it must preserve (and why)

### Invariant 1 — Two-env boundary (FATAL-2)

Offense (`framework.v2.knowledge_engine.*`, keyless) and sovereign
(`apps/sigil/sigil/knowledge.*`, owner key) **never co-load in one interpreter**.
They bridge *only* by the signed inert `learn_grant` file spool.

- `integration/vigil_integration/learn_drain.py` is installed in **both** venvs,
  so it imports `framework.v2` **lazily** — the imports live *inside*
  `LearnGrantWatcher._deep_learn` (lines 125–127), never at module top. Importing
  this module in a sovereign context must never pull `framework`. Verification uses
  `vigil_core` only (you don't need the offense engine to check a signature).
- The only private key material anywhere is the **owner's**, held sovereign-side.
  The offense side holds only the owner *public* key.
- The grant is a **signed pointer**, not the lead: the offense re-derives the full
  lead from its own intel, so a tampered seam can at most cause an advisory skill
  for a CVE already in the offense's scope — never a fact, never code.

**Why:** one interpreter loading both planes is a fatal collapse of the sovereign
envelope. If you add a new cross-plane hop, it must be another signed inert file /
subprocess — never a shared import.

### Invariant 2 — Oracle authority (nothing here mints a FACT)

Every K1–K5 artifact is advisory: a LEAD (K1), a `"proposed"` proposal (K2), an
approval-to-*learn* (K2b), a skill / gated DRAFT proposal (K3), a draft gap /
forecast (K5). Only a fired deterministic oracle over executor-captured non-LLM
bytes mints a signed FACT (`oracle_adapter.confirm_and_certify`). DETECT maps only
onto **existing** oracle kinds or a **gated** draft proposal for a *real*
(never soft/LLM) oracle.

**Why:** this is the moat. The engine's job is to be maximally useful *at the LEAD
tier* while being structurally incapable of asserting a finding it hasn't proven.

### Invariant 3 — Gate of record (owner-signed, fail-closed, kill-switch every step)

- K2b enqueue and the console/CLI ticks refuse when the kill-switch is engaged or
  `autolearn` is disabled; K1 `refresh_vulnintel` honours `cancel()` before every
  fetch; K3 `learn_drain` re-verifies the owner signature and defers on a tripped
  offense kill-switch.
- The **owner-signed `ApprovalQueue.approve` is the sole trust operation.**
  Enqueuing, drafting, spooling — all grant nothing. Accept authorizes *learning*,
  not a fact.

**Why:** learning is a capability, and every capability in VIGIL is behind the
conjunctive gate + owner root. A propose tick must never be reachable when STOP is
engaged or the latch is off.

### Invariant 4 — Determinism + append-only

No wallclock/rng in the scheduler, proposal ranking, evolve planning, or ledger
math. Clocks are **injected** (`now` / `seq`) and read *once* at a CLI/action
boundary (e.g. `cli.py:_evolve` reads `datetime.now` once, line 126;
`run_evolve_tick` line 694). `FeedSchedule` is a value advanced by returning a new
one. `IntelIngest` and the `OutcomeLedger` are append-only and idempotent.

**Why:** determinism is what makes an intel re-pull free of double-counting, a
draft queue reproducible, and calibration honest. A hidden clock in any of these
paths silently breaks reproducibility.

### The non-circular learning invariant (the load-bearing one)

**The learning loop can never confirm itself.** Concretely:

1. `deep_learn` **does not bump the calibrated MLS Beta priors**
   (`framework/v2/memory/priors.py`). Those priors are *"recorded after-the-fact
   based on engagement outcomes — never invented"* (priors.py, lines 10–12). A
   *learned-about* vuln is not a test *outcome*; injecting one would pollute the
   calibration.
2. K5 `record_predictions` writes forecasts with `oracle_confirmed=False`. The
   **outcome** is written later, and only by a real engagement firing (or not
   firing) the mapped oracle. The engine cannot mark its own prediction correct.
3. LLM / critic / RL / learning signals only advise, re-rank, or defer — they never
   promote a LEAD to a FACT. Promotion is the oracle's sole authority.

So the causal arrow is one-way: **oracle outcome → prior / calibration → ranking**.
Learning never flows the other way (ranking → outcome). If you ever find yourself
writing an outcome from a learned signal, or bumping a prior from a deep-learn, you
have created the circularity this invariant exists to forbid — stop.

---

## How to extend it safely

- **Add a new intel source (K1):** append a `VulnSource` to `TRUSTED_VULN_SOURCES`
  with a *concrete apex host* (no wildcard, no IP literal, never the target), a
  `mode`, and a `source_kind` that already has an offline parser. Do **not** add an
  arbitrary-URL pull — that is K4's sovereign, scope-gated surface. Test:
  `intel/tests/test_vulnfeed.py` — assert leads mint as `VULN_DB` LEADs, that a
  target-overlapping host is refused, and that a re-pull is idempotent.
- **Support a new bug class in DETECT (K3):** add the CWE→bug_class row to
  `deeplearn.py:_CWE_TO_BUGCLASS` **only if** a real deterministic `OracleKind`
  already adjudicates it (check `verify.verifier.BUG_CLASS_ORACLES`). If none does,
  leave it unmapped so K3 drafts a gated oracle proposal — do **not** force a shaky
  mapping to claim coverage, and **never** map onto a soft/LLM kind. Test:
  `knowledge_engine/tests/test_deeplearn.py` — mapped class names the real kind(s);
  unmapped class yields a `status=DRAFT` proposal and mints no fact.
- **Add a calibration/evolve signal (K5):** keep `plan_evolution` pure and pass
  `now`/`seq` in. Any prediction you record MUST be `oracle_confirmed=False`; the
  outcome path stays with real engagements. Test: `knowledge_engine/tests/test_evolve.py`
  — `plan_evolution` writes nothing, `record_predictions` is idempotent by
  `finding_id`, and `studied_enough` flips only when leads+gaps+predictions all close.
- **Add a cross-plane hop:** copy the `learn_grant`/`learn_drain` pattern —
  owner-signed inert core over a fixed field list, fail-closed verification with
  `vigil_core` only, lazy `framework.v2` import behind the boundary, and a
  content-addressed dedup marker. Never a shared import.

## Gotchas

- **The approval binds `target_seq`, not the payload.** slug/vuln_id are read by
  *joining* the verified approval back to the queued proposal and re-sanitized at
  mint (`learn_grant.approved_learn_grants`). If you ever trust slug/vuln_id
  straight off the approval record, you've opened a forgery seam.
- **`learn_drain` must not import `framework` at module scope.** It lives in both
  venvs. Keep every offense import function-local (they are, inside `_deep_learn`).
- **`evolve_data` (GET) persists nothing; `run_evolve_tick` (POST) does.** The read
  uses a *fixed epoch* for gap timestamps so it stays side-effect-free and
  deterministic — don't "fix" that to `now`.
- **Re-plan after seeding.** Both the CLI (`_evolve`) and `run_evolve_tick` re-run
  `plan_evolution` *after* `record_predictions`, so `studied_enough.done` reflects
  the now-open predictions instead of momentarily reporting `done=True` alongside
  freshly-seeded predictions.
- **A skill carries no authority.** The frontmatter is deliberately id/name/
  description/category only — an authority-claiming key would be parsed but never
  surfaced (`retrieve.py:_parse_frontmatter`). Don't add a tier/authority field.
- **"Studied enough" ≠ "complete".** It means everything is drafted for the
  *disclosed* leads in scope. Report it that way; the `EvolvePlan.studied_enough`
  note says so explicitly.

---

See also: [`architecture.md`](architecture.md) (the two planes, oracle authority,
the gate). The K4 point-at-a-URL learner is a *different, sovereign* surface
(`apps/sigil/.../scrape/learn_source.py`), and K6 knowledge git-sync is
`vigil knowledge sync|push|status` (integration) — both distinct from this engine.
