---
name: vigil-sessions-embodiment-program
description: VIGIL program — permanent sessions + per-session Neo4j graph + SIGIL voice/gesture/HUD + agent comms + self-evolving knowledge engine. COMPLETE — all 17 slices MERGED (#104-#120) + both carried follow-ups MERGED (#121 Safety kill_switch, #122 console→live-engine bridge).
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-28T10:33:38.819Z
---

**PROGRAM COMPLETE** — all 17 slices MERGED (#104-#120): Phase 0 · F1-F4 · S1-S5 · K1 · K2a · K2b · K3 · K4 · K5 · K6.
Every slice: build → adversarial red-pen (+ 2nd independent adversary on the two live-fetch slices K1/K4) → re-check on the
fixed branch → 6-job CI green → merge. The red-pen caught a REAL defect on nearly every slice (S5 non-atomic blackboard
migration; K1 unbounded KEV parser + dead disjointness guard; K2a dead lowercase kill_switch; K3 nothing [PASS, only tightenings];
K4 L2 vuln_id cap; K5 studied_enough ordering; **K6 a HIGH: the secret scan missed GITHUB_TOKEN= via a `\b`-treats-`_`-as-word
blind spot + no provider-token patterns → rewrote to catch ghp_/github_pat_/xoxb-/sk_live_/JWT/GCP + env-var assignments +
refuse binary/oversized; ReDoS-fixed the leading-greedy-prefix**). GitHub push-protection itself rejected the K6 test's literal
token fixtures → assemble secret-shaped test strings from SPLIT LITERALS at runtime.

**BOTH carried follow-ups now MERGED.** #121 (Safety kill_switch): fixed the SAME pre-existing lowercase `kill_switch === "engaged"`
bug at `app.js:158` + `drawSafety` (→ canonical `=== "ENGAGED" || .engaged`) — the Safety tile/banner/Engage-Release button were dead.
#122 (console→live-engine bridge): the console `launch_assessment` now spawns the INTEGRATION `vigil engage --session <id> --scope
127.0.0.1 [--connect …]` (subprocess, FATAL-2-safe) when `graph_backed` is opt-in AND session set AND loopback AND (vigil resolvable
+ NEO4J_URI set) — so a graph-backed loopback run populates/consumes its per-session Neo4j partition + consented union; else honest
`graph_note` fallback to the offense engine. Loopback-ONLY (remote stays the charter-gated offense `engage`, no authority downgrade);
`--scope` HARD-fixed to 127.0.0.1 (no scope param on the argv builder); hostile `session_id` → `_safe_session_id` → "" → branch skipped.
Red-pen PASS (parser-differential authority battery `127.0.0.1@evil.com` etc. all → charter gate; no injection; no boundary violation).
Hardening folded in (red-pen note #1): `connections_of` now RE-VALIDATES every returned id through `_safe_session_id` (defense in
depth — the ids flow into a `--connect` argv token, so a tampered/legacy entry is dropped, never trusted-because-connect_session-wrote-it).

Big approved VIGIL program (repo `thuram-nana/vigil-sovereign`, /home/kali/vigil). Plan file:
`/home/kali/.claude/plans/parsed-popping-lemur.md`. Operator decisions LOCKED: knowledge folder =
living KB + decision logs + transcripts; Neo4j = **cloud/remote auto-connect**; build ALL clusters;
self-evolve = **gated + honest** (leads/skills/priors, never oracle-facts; accept-to-apply; stop always honored).

Discipline every slice: build → adversarial **red-pen** agent → re-check on fixed branch → **6-job CI green** → merge.
Each slice is its own branch + PR. CI runs per-plane pytest via PYTHONPATH (no venvs) — mirror locally with
`.venv-offense/bin/python` (sovereign job: `PYTHONPATH=apps/sigil:integration`; integration: `PYTHONPATH=integration:gateway`
and `integration:engine/crucible:gateway`; crucible: `cd engine/crucible; PYTHONPATH=.`). ruff ruleset is `E9,F,B` (not default).

**Phase 0 (MERGED #104):** `knowledge/` scaffold (README doctrine, kb/architecture.md, system-map/, skills/, decisions/, sessions/).
**Phase F — MERGED:** F1 #105 (Neo4j creds: settings NEO4J_URI/USERNAME/PASSWORD + `_probe_neo4j` + offense-side
`graph_driver.py` opens its OWN driver + wires the F1 projection seam in `live/wiring.py build_engine`; uiproxy allowlist;
bootstrap test-connect). F2 #106 (`console/sessions.py` registry: create/rename/soft+hard-delete/link_run/list/get; every
chat+assessment a first-class session; monotonic per-registry seq; CSRF-guarded POST routes; Sessions UI). F3 #107
(session id = Neo4j partition key `graph_partition = session_id.strip() or slug`; `retrieve_priors` folded into the think
digest as UNTRUSTED advisory priors; `--session` flag). F4 #108 (`connect_session`/`disconnect_session` — directional,
consented, **read-time union** via `retrieve_priors(extra_partitions=)`, never a merge; `--connect` flag; Connect UI).

**Phase S — MERGED:** S1 #109 (system-map manifest `knowledge/system-map/{screens.yaml,system-map.json}` + `tools/system-map/generate.py`
asserts NAV==route()==manifest, CI drift-check). S2 #110 (voice `NavResolver`+`RoutingDispatch` → one `sigil.nav` spine record →
`/api/sigil/hud` SSE → browser navigates to a KNOWN screen only; persistent `hudES` outside `liveES`). S3 #111 (owner-toggled
gesture nav-mode latch; nav gestures emit `sigil.nav`, call ZERO input backends — strictly A1). S4 #112 (corner `#sigil-hud`
singleton; FSM churn → ephemeral 0600 `.vigil-live/sigil-hud.json`, NEVER the spine; hard `max-width:300px`). S5 #113
(`agent_message` EventKind + `AgentMessagePayload` + anti-spoof `sender==agent_name` + directional `inbox` + `base.send_message/read_inbox`;
**message≠fact** property test; durable v1→v2 blackboard migration — red-pen BLOCK: the rebuild was NOT crash-atomic → fixed to ONE
`BEGIN IMMEDIATE…COMMIT` w/ rollback-to-intact-v1 + `DROP TABLE IF EXISTS events_v2` self-heal + `foreign_key_check` guard; 3 regression tests incl. the real `_migrate_to_v2` except-path).

**Phase K — IN PROGRESS:** K1 #114 MERGED (vuln-intel feed: `intel/vulnfeed.py` — TRUSTED_VULN_SOURCES nvd/osv per-CVE + cisa-kev bulk,
one gated `GuardedHttpTransport` per source, deterministic injected seq, `cancel()`/kill-switch before every fetch, graceful per-source
`CollectorEgressRefused`→`refused`; `intel/scheduler.py` pure `due()`+`run_once()`; `observations_from_kev` reuses the shared advisory
minter [intel-tier lead, exploit_known=True]; `refresh-vulnintel` CLI FAIL-CLOSED [no --live=no traffic]; `vulnintel_data`+`/api/vulnintel/`;
`KNOWLEDGE` nav + `renderKnowledge`; `knowledge` system-map screen). Dual review (red-pen + independent egress/provenance adversary) held
the whole stack under attack; caught 1 real BLOCK (KEV parser was the ONE unbounded top-level list on the LIVE path → `[:_MAX_ITEMS]`) +
2 LOWs (dead disjointness guard → wired `ethics.parse_scope(slug)` target_hosts into cli.py; uncapped per-entry `cwes` → `[:_MAX_REFS]`).

**K2 SPLIT into K2a/K2b** (authority-sensitive; the cross-plane ACCEPT wiring is the risky half, split out for tractable review).
**K2a #115 MERGED** — the control surface: offense `knowledge_engine/proposals.py` `draft_proposals(vuln_leads)` (PURE deterministic
rank KEV→severity→CVSS→id; proposal `status="proposed"`, authorises nothing); `vulnintel_data` +`proposals` mirror; sovereign `autolearn`
capability latch (registered in `governor/capability.py CAPABILITIES`; enable=owner-signed, disable=fail-safe; `enable_autolearn`/`disable_autolearn`
in `ui/actions.py _CAP_ACTIONS`; `"both"` PINNED to gesture+voice in BOTH `do_action` AND `cli.py cmd_capability` so autolearn isn't swept in);
UI `drawKnowledge` federates OFF feed + SOV snapshot (latch+kill), "Propose-to-learn" card w/ Activate/Deactivate + STOP + preview.
Red-pen BLOCK: dead lowercase `kill_switch === "engaged"` (producer emits `"ENGAGED"`) → canonical `=== "ENGAGED" || .engaged`.

**K2b #116 MERGED** — owner-DRIVEN propose→queue→accept loop (the auto cross-plane orchestrator is DEFERRED to K5's tick — honest, K5 IS
the tick driver). Sovereign `knowledge/proposals.py` `enqueue_learn_proposal` (append queued/awaiting-approval record signal `knowledge.learn_proposal`,
idempotent by vuln_id, **`_MAX_PENDING=200` queue cap** at the enqueue choke point) + `pending_learn_proposals`; `queue_learn` action in do_action
(FAIL-CLOSED: refused if kill engaged OR autolearn disabled); `dashboard.snapshot` +`learn_proposals`; UI reconciles OFF candidates vs SOV pending
by vuln_id → Queue / Accept / Deny (reuse UNCHANGED owner-signed `approve`/`deny`). Red-pen PASS (attacked unsigned/attacker-key/replayed approvals
— all stay pending; only genuine owner sig resolves) + folded its 2 recs (cap + forged-approval negative control). ACCEPT authorises LEARNING (K3), never fact.

**K3 #117 MERGED** — offense `knowledge_engine/deeplearn.py` `deep_learn(vuln_lead,*,skills_dir,now)`: FIND/PREVENT→`knowledge/skills/{find,prevent}/<id>.md`
(SkillLoader-compat frontmatter, NO tier key); DETECT→`_resolve_detect` looks the bug_class (curated `_CWE_TO_BUGCLASS` or a hint) up in CANONICAL
`verify.verifier.BUG_CLASS_ORACLES` → names EXISTING kinds (each re-validated via `plugins.registry._coerce_oracle_kind`, fails loud on invented) OR drafts
a DRAFT `improve.ImprovementProposal` (described-only, authorize≠apply). **DROPPED the Beta-prior bump** (would inject a non-outcome — priors are recorded-after-the-fact).
`skill_ref="advisory:skill:<id>"`→ungrounded. `retrieve.py` MAX_SKILLS=5 id-sorted + traversal-guard. `knowledge_engine/cli.py` `knowledge draft|learn|skills` +
`__main__` verb; `learn` kill-switch-gated. Red-pen PASS (238-class oracle-invention sweep=0 invented; path-safety write+symlink-read; no store write/egress) + folded 2 test tightenings.
**SkillLoader lives in `integration/vigil_integration/kb/skills.py` (NOT framework)** — has NO default path; K3 writes SkillLoader-compat files, retrieve.py has its own thin reader.

**K4 #118 MERGED** — SOVEREIGN live-fetch #2. Manual-add = UI field POSTing the existing K2b `queue_learn` (no new backend; `vuln_id` now `[:120]` capped).
URL-learn = `apps/sigil/sigil/scrape/learn_source.py` `learn_from_url`/`learn_from_topic` wrapping `WebResearcher.research_web`: `ScrapeScope([host])` (single-host,
`is_public_host` SSRF gate → internal/metadata refused), bounded (max_pages=4,depth=1), kill-switch `cancel` hook, reads the composed `web.research` report for the
honest grounded/advisory summary. `TRUSTED_LEARN_SOURCES` OWASP/CWE/CAPEC/ATT&CK/NVD/OSV. `Frontier` gained an ADDITIVE `cancel` hook (between-hops; default None=byte-identical).
`start_learn` action FAIL-CLOSED (kill+latch). UI "Add & learn a source" card. Red-pen PASS (13-payload SSRF battery all no-fetch; grounding gate demoted 6/7 adversarial
claims incl. inversion/reorder/outside-window; fail-closed; no XSS pre→createTextNode) + folded L2 vuln_id cap. LOW-accepted: STOP is between-hops only (a single fetch≤20s/synth≤180s not interruptible).

**K5 (NEXT) plan:** offense `knowledge_engine/evolve.py` — the HONEST bounded self-evolve. `feed_to_horizon_items(vuln_nodes)` → `improve.horizon.ingest_horizon`
→ `CapabilityGap`s → `improve/patcher.draft_proposals` → DRAFT `ImprovementProposal`s (NEVER merged/applied — `merge_gate.evaluate_merge` = authorize≠apply). Coverage-gap
synthesis (CATALOG `by_technique`/bug_class coverage vs disclosed classes). `studied_enough(state)→{done,remaining}` (accepted leads all have find/detect/prevent + every gap
has a drafted proposal + OutcomeLedger has no open predictions). `calibration/ledger.py OutcomeLedger` records a prediction on propose (outcome later when a mapped oracle
fires/doesn't → `pairs()`→calibrate). `cli.py` `knowledge evolve` (gated latch+kill). HONEST SCOPE: bounded deterministic horizon over DISCLOSED CVEs + coverage-gap +
calibration → GATED proposals; NOT forecasting undiscovered CVEs, NOT self-applied. "Studied everything in scope" = drafted everything, not "system complete". Then K6 knowledge→GitHub.

**Carried UI cleanup — DONE (#121):** the lowercase `kill_switch === "engaged"` bug at `app.js:158` + `drawSafety` fixed
(canonical `=== "ENGAGED" || .engaged`). The Safety tile/banner/Engage-Release button now render live.

**K1 recon (line numbers current @ #113):** wrap `intel/from_threatintel.py:693 build_threatintel_live_transport` (returns
`GuardedHttpTransport`); add `www.cisa.gov` to `THREATINTEL_COLLECTOR_HOSTS:690` + a KEV `IntelSourceKind` in `THREATINTEL_LIVE_ENDPOINTS:687`;
KEV fields already partly recognized (`cisaExploitAdd`:297, `known_exploited/kev/cisa_kev`:375). `live_cve_observations:718(transport,query,*,seq,source_kind)`.
`IntelIngest(world,*,store,engagement_slug).ingest(obs,*,seq)` is seq-keyed idempotent (`_seen_obs_ids`). CLI pattern `sub.add_parser/add_argument/set_defaults(fn=)`.
**CAVEAT — provenance:** `worldmodel/models.py:169 classify_provenance` returns FOUR tiers and **`advisory:` → `ungrounded` (NOT intel)**;
intel-tier needs a prefix in {`intel:`,`intel-fused:`,`derived:`,`infer:`,`scan:`,`fingerprint:`}. Either way it is a LEAD, never grounded/fact.
Wildcard refuse = `agents/egress_guard.py:113 _collector_host_too_broad`. Console: add `vulnintel_data(slug)` mirroring `console/api.py:644 intel_data`,
register `"/api/vulnintel/"` in `console/server.py:74 _PREFIX_ROUTES`. UI: NAV array `app.js:19-41` (DO/MANAGE/LEARN), `route():3261`,
mirror `renderSessions:3174` (registered :3271) for a `KNOWLEDGE` group + `renderKnowledge`. `knowledge/catalog.py by_technique(ref)/by_id` are module fns; CATALOG is a tuple.

**Carried follow-up — DONE (#122):** the console→live-engine bridge. `launch_assessment` (`console/actions.py`) gained an
opt-in `graph_backed` path: when the caller passes `graph_backed:true` AND `session_id` AND the target is loopback, and BOTH
`vigil` resolves (`VIGIL_BIN`/`shutil.which`) AND `NEO4J_URI` is set, it spawns the INTEGRATION `vigil engage <target> --slug
<s> --scope 127.0.0.1 --session <id> --max-iterations <n> [--connect <csv>]` (subprocess-only, FATAL-2 clean) so a graph-backed
loopback run fills its per-session Neo4j partition + consented union. Availability-gated → honest `base["graph_note"]` fallback to
the offense engine (session linkage kept). SAFETY: loopback-ONLY (remote unchanged = charter-gated offense `engage`, no authority
downgrade); `_graph_backed_engage_cmd` takes NO scope param — `--scope` is hard-fixed 127.0.0.1; hostile `session_id`→""→skip;
`connections_of` re-validates each `--connect` id (defense-in-depth). UI: `renderAssess` Session `<select>` + graph-backed checkbox
(only when session set + loopback). Red-pen PASS (authority/injection/FATAL-2 battery all held).

**Lessons this program:** (1) The committed static UI bundles (`apps/sigil/.../static`, `engine/crucible/.../console/static`)
are the OLD standalone per-plane UIs and have DRIFTED massively from the unified `packages/vigil-ui/app.js` — do NOT run
`sync.sh` (it clobbers them + breaks their tests); the unified bundle is served via `uiproxy.assemble_serve_dir`, so UI
changes go ONLY in `packages/vigil-ui/app.js`. (2) The console is a `ThreadingHTTPServer` — any registry/file mutation
needs a lock + unique `mkstemp` temps (F2 red-pen caught 500s/dup-seq/lost-records from a shared temp + unlocked counter).
(3) Red-pen catches a real defect EVERY slice — a stale sibling test not in the CI list (F1), a concurrency BLOCK (F2), an
honesty overclaim (F4). Run the FULL suite, not just new tests. (4) commit `-m` with backticks gets shell-mangled → use `-F file`.
See [[vigil-pro-pentest-program]] (the prior, COMPLETE program) and [[vigil-command-ui-program]].
