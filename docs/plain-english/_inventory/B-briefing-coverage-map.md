<!-- GROUND TRUTH for the plain-English briefing. Produced by a read-only
     research pass over the repository; every claim is cited file:line.
     Writers: do not restate anything here you have not re-read in the code. -->

I have what I need. Here is the coverage map and gap analysis.

---

# VIGIL plain-English briefing — coverage map and gap census

**Read at:** `/home/kali/vigil/docs/plain-english/` on `main` @ `05b81e9f`. 15 source files + assembled `VIGIL-EXPLAINED.md` (250,222 words). Last briefing edit was `e9ef6597` (PR #302); **six PRs have landed since**, two of which ship user-visible subsystems (#306 engagement library, #301/#308 case file). The chapters cannot know about them.

Two pre-existing review artifacts are worth reading before writing anything — they overlap this task and already did some of the work:
- `/home/kali/vigil/docs/plain-english/_review/completeness.md` — a prior completeness critic pass; **Part C lists 20 subsystems in no chapter**, Part G lists what was since fixed. Written against an older revision (11,826 lines vs today's ~13,116), so its Part A findings (no index, no glossary) are **now fixed** — `00-index.md` and `00-glossary.md` exist.
- `/home/kali/vigil/docs/plain-english/_review/CASE-FILE.md` — the ground-truth investigation that *caused* the case file and engagement library to be built. It is the source material for the chapter section that does not yet exist.

---

## 1. Coverage map — what each chapter actually covers

| # | File | Words | What it actually covers (from headings + skim) |
|---|---|---|---|
| — | `00-index.md` | 13,053 | Contents, three reading routes, subject→chapter locator, the four-verdict vocabulary, a **master status ledger** (8.A fully working / 8.B proven offline / 8.C scaffolds / 8.D conditional / 8.E refused), the licence + `.gov` block warning, provenance and how to re-derive the numbers. |
| — | `00-glossary.md` | 11,749 | 13 sections: the four words, the oracle/checker, names of parts, evidence & proof, authorisation, signatures & keys, the target map, **§8 "the automated assistants, and learning"**, weakness vocabulary, status words, everyday computing, acronyms/formats, named outside programs. |
| 1 | `01-what-this-is.md` | 16,726 | The problem (claims vs evidence), the central idea (independent re-proof), sealed evidence bag, re-run offline, signature anchoring, the four words; **proving the negative**; what the system is (two halves, named parts, role of AI); who it is for; **the licence + government-domain block**; the dossier and three reports; refusals; honest status (§9.1–9.7). |
| 2 | `02-the-parts.md` | 18,100 | The one-page map; **§3.1 VIGIL, §3.2 integrity core, §3.3 CRUCIBLE, §3.4 AEGIS, §3.5 SIGIL, §3.6 STRIX, §3.7 integration layer, §3.8 gateway, §3.9 interfaces, §3.10 entitlements**; following one piece of work; the wall down the middle (FATAL-2) and how it is enforced; what runs where, ports, data locations, programmatic attack surface; self-hosted/sovereign meaning; honest status per part; a 13-term glossary. |
| 3 | `03-an-operation-end-to-end.md` | 17,007 | The 11-stage lifecycle: charter → **session** → run setup (depth, 8 capability packs, auth'd scanning) → pre-flight (usage ledger, gate chain, 4 tiers, approvals, network fence) → discovery → mapping → testing (incl. call-back relay, cost/time/traffic) → **confirming** (oracle, four words, adversarial review, sealed bag, measured confidence) → the hard negative → attack picture → report + proof bundle + dossier + signed negative → re-test/drift/fix ladder; what can stop a job. |
| 4 | `04-leads-and-facts.md` | 15,883 | LEAD vs FACT; the four-word vocabulary and smaller vocabularies; **what a checker is, and all 38 of them**; the six-stage journey of a claim (propose → oracle → admission desk → sealed bag → demotion-only firewall → offline re-check); why the AI may never promote; what happens when a check stops reproducing; **three separate confidence numbers**; the hard negative; supply chain as a finding class; what the false-alarm claim does and does not mean. |
| 5 | `05-weakness-types.md` | 21,923 | **85 named weakness types in 15 families**; 190 alternative names; **the 38 oracles grouped** (core 15, 4 defensive-AI, 3 request-only parse-proofs, 10 posture, 6 live-capture); defensive detection from the customer's own logs; which claims may be stated as a proven negative and the six deliberately not targeted; the attack library; what the catalogue does not cover. |
| 6 | `06-evidence-and-proof.md` | 21,218 | What counts as evidence; sealed bag, owner-only writes, credential masking; **sealing: fingerprints, certificates, chain, anti-rollback**; the four independent checks; the proof-carrying finding's five ordered checks; what a finding report contains; machine-readable outputs (SARIF/OpenVEX/DSSE); **handing evidence to a third party incl. the out-of-band pin and standalone verifiers**; what one changed byte does; the clean result; retention/backup/ephemeral mode; **§12 supply-chain safeguards**; reviewer checklist. |
| 7 | `07-signing-and-keys.md` | 15,343 | What a signature is (Ed25519); what gets signed; labelled seals/domain separation; **who holds which key + full key inventory**; keys at rest; **loss, escrow, replacement, revocation**; emergency stop vs keys; m-of-n thresholds and irreversible actions; the trust root and out-of-band delivery; the tamper-evident record; four anti-rollback defences; what an assessor should ask. |
| 8 | `08-safety-and-authorization.md` | 19,638 | The charter and its signature check; scope enforcement (six checks, traffic guard, network floor, categorical block list); **permission tiers**; the approval queue incl. **§4.5 the gated Strix shell**; m-of-n destruction; emergency stop (both planes); not damaging the target (postures, budgets, destructive-request halt); staying away from real people's data; the audit trail and its limits; what was refused; **§12 who could attack the system itself (9 attacker models)**; build assurance; where the limits are. |
| 9 | `09-the-screens.md` | 22,988 | **All 28 screens** in three groups (DO 11 / MANAGE 13 / LEARN 4), each with what is seen, what can be done, and a status line; the furniture on every screen; **§7 capabilities with no screen**; **§8 where the interface is honestly incomplete**; **§9 the three other human interfaces + two programmatic ways in**; **§10 the whole CLI incl. every passthrough verb**; a first session; verified counts. |
| 10 | `10-the-picture-of-the-attack.md` | 14,515 | **The offense world model**: node and edge kinds, four grounding tiers, two confidence numbers, no-clock rule, monotone growth; where the map comes from (signed record only); how a finding becomes movement; inference rules and techniques as checkable moves; the second pass after cloud; crown jewels; route ranking incl. loudness; blast radius; chokepoints and "what if we fixed it"; keeping the map honest (5 rules); what the operator sees; **§14 four different pictures named honestly**; **§15 sessions, per-session graph partitions, connecting sessions, memory across engagements**; supply chain on the same map. |
| 11 | `11-the-agents-and-learning.md` | 16,448 | What an agent is; the blackboard; **six families and a 24-worker census**; **§3 the offense investigation team — every agent with job + limits** (6 line agents, 6 reviewing agents, boundary guards, 4 executors, the confined workspace, the AI-app gauntlet); **§4 the sovereign mesh — nine agents with a table + deep-dives on SENTINEL/ARTIFICER/BASTION/OPERATOR/DELEGATE + the no-promotion rule**; §5 reasoning body, fireteam, brains, Strix; §6 the gate table; **§7 how it learns** (memory, priors, calibration, propose-never-apply, self-evolve, cross-boundary learn-grant, off by default); hard rules; self-criticism. |
| 12 | `12-tools-and-what-you-need.md` | 18,538 | Every third-party tool and what it may claim; host tools vs container tools; the narrow gate network tools run through; importing another tool's report; the MCP bridge for other tools; vendored-not-run code; benchmark method; **Part Two: hardware, cost, every credential/key, network listeners, scheduled jobs, day-one walkthrough, backup/restore/upgrade/removal, what is deliberately not automatic, what leaves the organisation, where the software comes from**; a one-page checklist. |
| 13 | `13-defence-and-source-code.md` | 16,462 | **Part 1 AEGIS**: the three answers, the inline firewall, what it refuses to block, the soft ladder, install routes, four inward detections, social-engineering scoring, the Detection Mirror, detection engineering. **Part 2 source review**: two routes, three layers, pattern list, dataflow rules, symbol index, static→testable, the review loop. **Part 3** fix ladder. **Part 4** TLS/certs/network manners/PQ exposure/channel binding. **Part 5** proving a fix worked. |

---

## 2. Topic-by-topic verdicts

### SIGIL as a whole — **MENTIONED-ONLY / thin**

One section, `02-the-parts.md` §3.5 (≈50 lines), is the *only* structural treatment. It covers: the spine, the WARDEN kernel, the A0–A3 table, one paragraph on the mesh, the sovereignty guard. Its mesh paragraph names **no agent by name**:

> "**The agent mesh.** A set of specialised assistants, each with a permanent ceiling on how dangerous an action it may ever take. They include a memory archivist, a monitoring watcher, a personal-operations assistant…"

The names arrive 9 chapters later in `11-the-agents-and-learning.md` §4. Nothing in the briefing explains SIGIL's *reason to exist* as a product — that it is a sovereign personal assistant with 43k+ spine records, on-device embeddings, its own graph, its own cockpit, its own MCP surface and a phone. Ground truth is `/home/kali/vigil/apps/sigil/README.md` §"What it is" / §"Capabilities" (lines 33–170), which is far richer than anything in the briefing.

### Each SIGIL agent by name — **PROPERLY EXPLAINED (9 of 10); one ABSENT**

`11-the-agents-and-learning.md` §4 is genuinely good: a per-agent table with job + ceiling + hard limits, then full sub-sections on SENTINEL, ARTIFICER, BASTION, OPERATOR, DELEGATE, plus the frozen no-promotion list. This is the single best-covered SIGIL topic.

**Gap:** the mesh is **10**, not 9. `/home/kali/vigil/apps/sigil/README.md` architecture diagram lists `WebResearcher(SCRIBE)` alongside the nine. It is a real subsystem — `/home/kali/vigil/apps/sigil/sigil/scrape/` (frontier, robots, ratelimit, render, researcher, scope, extract, learn_source) — and it is the engine behind point-at-a-URL learning. **"SCRIBE" and "WebResearcher" appear zero times in the briefing.** Also absent: `sigil/agents/vault.py` (the OS-keyring credential vault DELEGATE depends on) and `sigil/agents/web_engine.py`.

### Voice — **MENTIONED-ONLY**

Three passing references, all in `09-the-screens.md`: the HUD card (line 162), the capabilities toggle row (813), and one CLI verb row (1915: "`voice` | Run the speech pipeline, from a recorded file or a live microphone."). Nothing on the actual pipeline — wake word → VAD → streaming ASR → KERNEL classification → TTS, with barge-in (`/home/kali/vigil/apps/sigil/sigil/voice/`: backends, dispatch, nav, pipeline, hud_status). Nothing on why voice is a *security* surface (a spoken command becomes a tiered action).

### Gesture — **MENTIONED-ONLY, and the one substantive statement is a correction**

> "Note for accuracy: local camera-based gesture control is *not* functional; gesture input comes from a paired phone companion." (`09-the-screens.md:169-170`, repeated at 1639)

The subsystem is 10 modules (`/home/kali/vigil/apps/sigil/sigil/gesture/`) with a genuinely interesting safety story the briefing never tells: warm camera stream → landmark model → invariant-feature classifier → **debounced fail-safe FSM** → owner-**armed** session; a gesture is bounded by WARDEN to an A1 pointer move/click/scroll, and `type`/`launch` **always queue** — so *a gesture can never type a password or launch an app*. That is exactly the kind of structural limit the briefing exists to explain, and it is missing.

### The HUD — **MENTIONED-ONLY**

One paragraph, `09-the-screens.md:162-170`, as "furniture that appears on every screen". Correct as far as it goes (listening/thinking state, dismiss, off by default, `vigil up --with-voice`/`--with-gesture`) but it is described as a status card, not as the cross-plane channel it is (`packages/vigil-ui/app.js` `startSigilHud`/`updateSigilHud`, `apps/sigil/sigil/ui/server.py` `/api/sigil/hud`).

### Perception / OCR — **ABSENT**

"OCR" appears **zero times** in all 15 files. `/home/kali/vigil/apps/sigil/sigil/perception/` (9 modules) is entirely unexplained, and it carries one of the strongest honesty mechanisms in the whole codebase — the same serve-the-quote discipline the briefing praises in SCHOLAR, applied to vision:

> "the frame's captured OCR TEXT is the authoritative content of the answer — verbatim… The VLM's visual reading is ADVISORY. An object the VLM names is a LEAD, promoted to a GROUNDED claim only if the OCR corroborates it" (`perception/perceive.py`)

Also absent: the frontier-VLM hop as a **WARDEN-classified A2 data-egress event** requiring an owner approval bound to that exact egress; ambient watch being opt-in and only escalating on a *perceptual* delta so unchanged frames never leave the machine; and `recall` ("where did I last see X?").

### Knowledge engine — the vulnerability feed — **PROPERLY EXPLAINED**

`09-the-screens.md` §6.4 covers NVD/OSV/KEV sourcing, "every feed entry is an intelligence-tier LEAD, never a fact", one-shot pull vs recurring ticker with a 1min–24h interval, and the honest note that the schedule is **not persisted** so it cannot silently resurrect.

### Propose-to-learn — **PROPERLY EXPLAINED**

The card is documented in `09-the-screens.md` §6.4 (activate/deactivate, STOP/Release, queue → Accept/Deny) and the mechanism in `11-the-agents-and-learning.md` §7.4 (three computable shortfalls: missing check, low recall, low confirm-rate; the merge gate's three conjuncts; "there is deliberately no function in it that writes code").

### Deep-learn (K3, FIND/DETECT/PREVENT + graph-as-skillset) — **ABSENT as a named capability**

`docs/FEATURES.md:700-706` lists "K3 — deep-learn (FIND/DETECT/PREVENT)" and "K3 — graph-as-skillset retrieve" as distinct features. Neither the phrase "deep-learn" nor the FIND/DETECT/PREVENT triple appears anywhere in the briefing. The nearest coverage is the generic "drafts only" language in `09` §6.4.

### Point-at-a-URL learning — **MENTIONED-ONLY (one table cell + one bullet)**

The whole treatment is:

> "**Add & learn a source** *(owner…)* | A vulnerability-identifier box and a web-address box. | Add to the learn queue; or **Learn from URL**, which reports how many claims were *grounded* and how many *advisory*, the host, the page count, and up to 4,000 characters of the extracted text." (`09-the-screens.md` §6.4)

plus one verbatim-substance bullet ("fetches public pages through the scope, robots and server-side-request-forgery gate; nothing a page asserts becomes a fact"). What is missing is that this is a **whole sovereign subsystem (K4)** with a curated trusted-source list (owasp.org, cwe.mitre.org, capec.mitre.org, attack.mitre.org, nvd.nist.gov, osv.dev), a value-of-information crawl frontier, per-host rate limiting, robots compliance, a page budget, a **kill-switch `cancel` hook that aborts between hops**, and the *identical* demote-only `consolidate.gate.admit` used by ARCHIVIST — so a citation outside the fetched window is rejected. Source: `/home/kali/vigil/apps/sigil/sigil/scrape/learn_source.py` and `/home/kali/vigil/apps/sigil/sigil/scrape/`.

### Self-evolve (K5) — **PROPERLY EXPLAINED**

`11-the-agents-and-learning.md` §7.4 is strong, including the quoted-then-translated definition ("better-calibrated priors + more PROPOSED coverage, never self-applied canon") and the five-item list of what it does not do. `09` §6.4 covers the screen (horizon gaps, bug-class gaps, draft counts, Brier score with a full plain-English explanation).

### Knowledge sync (`vigil knowledge sync|push|status`) — **MENTIONED-ONLY**

One table row in `09-the-screens.md` §6.4 ("knowledge/ folder → git", Status / Regenerate + commit) plus one bullet on the secret-scan refusal. The `/home/kali/vigil/knowledge/` tree itself (kb, decisions, sessions, skills, system-map, sync.sh) is never explained as a thing — what is in it, why it is version-controlled, what the system map is for, what a "skill" is.

### Strix — **MENTIONED-ONLY→ well-covered in one place, but the coverage is lopsided**

This is the briefing's own judgment: `_review/completeness.md` **B5** says "STRIX is named as one of the four parts and is the thinnest of the four."

The one real treatment is `02-the-parts.md` §3.6 (~120 lines) and it is good on: what "vendored" means, the agent loop and its 13 tools, the Kali container and its full toolbench, `vigil strix …` routing, **codebase mode vs the engine's own arsenal**, the leads-not-facts doctrine, the demonstration→capture→oracle escape hatch with the Fact/Lead/Denied outcome table, and the fail-closed shell gate. `08-safety-and-authorization.md` §4.5 covers the shell gate in full. `09-the-screens.md` §9.1 gives its terminal UI one paragraph.

**But:** Strix appears **0 times** in ch03 (the end-to-end operation), ch04, ch05, ch06, ch08 body, ch10, ch12. A reader following an operation start-to-finish never meets it. There is no answer to "when would I actually use this, and what does a Strix run look like".

### The governed terminal — **PROPERLY EXPLAINED**

`09-the-screens.md` §4.4 is one of the best sections in the briefing: the three response modes (command/answer/route), the live pre-flight verdict badge, the allowlist-not-blocklist reasoning, and the four worked removals (`xxd` removed because one form writes to a file; `getent` removed because one form does a network lookup; `date`/`hostname` bare-form-only because with an argument they *set*; four capable utilities admitted through a positive option list). Plus:

> "on this path, reaching the network and writing to the machine are impossible by construction, not merely guarded against."

Complemented by `12-tools-and-what-you-need.md:281-289` (the `vigil terminal` CLI and the `vigil sandbox` bwrap tier) and `08` §9.1 (both produce signed redacted records). **No gap.** The only thin spot: SIGIL's *own* terminal path (OPERATOR's plan→preview→hash-bound-approval→execute→verify→rollback) is covered in ch11 §4 but never connected to this one, so a reader does not learn there are two governed terminals with different designs.

### Knowledge graph / world model — **offense: PROPERLY EXPLAINED. Sovereign: ABSENT. The distinction: ABSENT.**

Chapter 10 (14,515 words) is an excellent treatment of the **offense world model** — and §14 "Four different pictures of the same work, named honestly" already does the disambiguation work for four *offense-side* views.

The **sovereign knowledge graph** — `/home/kali/vigil/apps/sigil/sigil/graph/` — is a completely different object: a **Kùzu** deterministic entity mirror of the spine (Project / Session / Document / Commit nodes, containment edges), rebuilt by replay with an atomic swap, every node carrying an `anchor_seq` + `anchor_hash` back into the spine, with semantic node kinds (Person, Org, Decision, Commitment, `contradicts`, `decided_in`) *deliberately absent until a grounded producer exists*. Plus the ARCHIVIST nightly consolidation pass (`sigil/consolidate/`: extract → gate by re-execution → promote/demote → flag contradictions → brief → checkpoint).

The briefing's four `knowledge graph` hits are: a glossary line defining it as the *target* map; ch10's title; ch09:299 (session graph); and ch02/ch12 rows about the optional Neo4j container. **"Kùzu" appears zero times.** A reader is left believing there is one knowledge graph. There are two, they are unrelated, and one of them is the sovereign side's memory organ.

### Sessions — **PROPERLY EXPLAINED (offense), with two gaps**

`03-an-operation-end-to-end.md` §3 is strong: what a session is, what it links (runs, conversation, rebuilt picture, open threads), where it is stored, that a real one exists (`sess-A`, kind `engagement`, 88 runs), what it remembers vs deliberately does not, the load-bearing property —

> "**A session has no authority.** Creating, renaming, connecting or deleting a session changes no finding and opens no gate."

— counter-ordering not clock-ordering, soft vs hard delete, **connecting sessions as consent to advisory priors**, and the disambiguation against `knowledge/sessions`. Reinforced by `10-the-picture-of-the-attack.md` §15 (per-session graph partitions, cross-engagement memory, what memory may never do) and `09-the-screens.md` §5.1 (the screen).

**Gaps:** (a) sessions vs the new **engagement library** — the library groups by engagement slug and is the thing you return to months later; a reader will now meet two overlapping organising concepts and no chapter reconciles them. (b) SIGIL's *own* `Session` node type (a Claude Code session, ingested and titled, in the Kùzu graph) is a third meaning of the word, and the ch03 disambiguation note does not cover it.

### The memory spine — **PROPERLY EXPLAINED (as a mechanism), UNDER-EXPLAINED (as a subsystem)**

The spine's *cryptography* is covered exhaustively — `02` §3.2 and §3.5, all of ch07 (chain, signed head, anti-rollback floor, witnesses, external timestamp), `08` §9. The phrase "memory spine" is not used but "spine" is defined and used throughout.

What is missing is the spine as SIGIL's **memory**: 43k+ records; what actually gets ingested (`sigil/ingest/`: Claude Code history, live git post-commit/post-merge hooks, subagent transcripts each a titled session, curated docs — incremental and idempotent); that graph and vectors are *deterministic projections* (double-rebuild → identical); the checkpoint/prune/snapshot/migrate machinery (`sigil/spine/` is 15 modules); and field-level payload encryption (`FEATURES.md:829`, flagged there as "previously undocumented").

### Vector recall — **MENTIONED-ONLY**

Total coverage is two rows: `02-the-parts.md:917` and `00-glossary.md:501` ("Qdrant | A database that searches by similarity of meaning… the search behind the sovereign side's memory and recall"). Not covered: on-device fastembed/bge-small embeddings running **on CPU with no API and no cost** (a sovereignty claim the briefing wants to make and doesn't), the embedded no-container fallback, and the honesty property that **an absent topic returns "no grounded match" rather than a fabrication**. Separately, `11` §7.1 flags the *offense* memory's shallow lexical similarity as a known limitation — which is a different store, and the two are never distinguished.

### MCP tools — **half PROPERLY EXPLAINED, half ABSENT**

`09-the-screens.md` §5.8 is excellent on the **offense-side outward** server: exactly two tools by default, allow-list-not-blocklist, the four independent re-checks (lowest tier / no entitlement / non-destructive / no network), the deliberate exclusion of any caller-chosen file path, stdio transport with no listener, and the honest "no start/stop control here". It even flags the inward direction (VIGIL *using* someone else's MCP tool, wrapped as a labelled LEAD).

**Absent:** SIGIL's own MCP memory server — `/home/kali/vigil/apps/sigil/sigil/mcp/server.py`, **8 gated read-only cited tools** (`memory_search`, `episodic_range`, `ingest_status`, `graph_entity`, `graph_query`, `threads_open`, `commitments_due`, `contradictions_pending`) registered into Claude Code and Claude Desktop. This is arguably SIGIL's highest-leverage feature — it gives any Claude session cited recall of the owner's own history — and it appears **nowhere** in 250,000 words.

### The phone / companion — **MENTIONED-ONLY (three CLI table rows)**

Every reference: `09-the-screens.md:1911-1913` (the `mesh`, `host`, `bridge` verbs), `12-tools-and-what-you-need.md:848` ("The cockpit, and the phone bridge | Run continuously once enabled… Both refuse a public address"), and two "paired phone companion" asides about gesture. `07` and `06` mention "phone call" only as an out-of-band channel — unrelated.

**Nothing explains what the companion is or does.** Ground truth (`apps/sigil/README.md` §"The phone companion", `apps/sigil/sigil/bridge/server.py`, `sigil/mesh/registry.py`): the phone holds only its own Ed25519 device key — **the owner trust-root never leaves the desktop**; the desktop verifies and never signs on the phone's behalf; the bridge binds a WireGuard/private address only and **asserts** a public bind is refused, twice; auth is a **per-request Ed25519 signature, not a bearer token**, verified against the owner-minted authorized-device set **recomputed per request so a revocation takes effect at once**; the envelope `action` is bound to the endpoint it hit; effectful actions get a monotonic-nonce replay gate; `/api/pending` and the SSE stream carry only `{seq, tier, kind}` — never a subject, never a payload. From the installable PWA the phone can approve/deny A2·A3, **panic-halt** (fail-safe, release stays owner-only), relay a WARDEN-gated command, browse a read-only cockpit, recall on-screen history, and opt-in arm a gesture session as a remote trackpad. There is a runnable no-hardware demo at `apps/sigil/demo/companion_demo.py`.

This is a "an official can approve a live engagement action from their phone, and the key never leaves the building" story that the briefing's target audience would care about more than almost anything else in it, and it is not told.

### Every agent on both planes — **offense: PROPERLY EXPLAINED. sovereign: PROPERLY EXPLAINED minus one.**

Offense (`11` §3) covers all 8 agent classes + 3 non-class workers + the boundary guards + all 4 executors, each with limits, against `/home/kali/vigil/engine/crucible/framework/v2/agents/`. Cross-checked: `coordinator.py` is the only agent-folder module doing orchestration work that gets no row (`blackboard.py` *is* covered, as "the shared notice board", §1). The 24-worker census is explicit about its counting rule and its three honesty notes.

Sovereign (`11` §4) covers 9 of 10 — **SCRIBE/WebResearcher missing** (see above).

### The engagement library — **ABSENT (post-dates the briefing)**

Merged in `b9ca10e3` (PR #306) **after** the last briefing commit. It is now the **29th screen** — `knowledge/system-map/screens.yaml:92`:

> `id: library` · `label: Engagement Library` · group MANAGE · "Every past job you can come back to months later — newest worked first, with real dates and times, the kind of operation, the subject, and its run and finding counts; rename a job or a run (presentation only, nothing signed changes) and click through to its runs, findings, evidence and dossier."

`09-the-screens.md` says "twenty-eight screens" **eleven times** including in its own title line ("§13 The single idea behind all twenty-eight screens") and its §12 "Summary of verified counts". Every one of those counts is now wrong. Backend: `engine/crucible/framework/v2/console/api.py:180` (`library_engagements`), `:253` (`library_engagement`), tests at `console/tests/test_engagement_library.py`. The rename-is-presentation-only property ("nothing signed changes", proven against real offline proof-bundle verification in `f44ff2d9`) is exactly the kind of invariant this briefing is built to explain.

### The case file — **ABSENT (post-dates the briefing)**

Merged in `37090acd` (PR #301) and `05b81e9f` (PR #308), both after the last briefing commit. The two "case file" string hits in the chapters are unrelated (a metaphor for a session; an IDOR example).

`/home/kali/vigil/engine/crucible/framework/v2/report/case_file.py` ships **nine numbered documents inside every dossier**: `00-START-HERE.html`, `01-executive-summary.md`, `02-approach-and-scope.md`, `03-findings.md`, `04-leads.md`, `05-what-was-looked-for.md`, `06-what-to-do.md`, `07-verify-it-yourself.md`, `08-glossary.md` — under three stated rules: *meaning before mechanism*, *say the limits out loud*, *never assert what was not measured* (unrecorded values print "not recorded"). It is pure and deterministic: no wallclock, no RNG, no I/O.

This is the single most consequential omission for the stated audience. The briefing's chapters 1, 3 and 6 all promise a reader "the dossier" and describe it as a machine-readable export plus a proof bundle — which was true when they were written and is the exact deficiency `_review/CASE-FILE.md` identified and PR #301 fixed. **The briefing now under-sells the product.** Related: `f83d6e90` wires an engagement `--label` into the downloaded case file, and `8e713716` adds "an accurate signature claim" — the briefing's dossier description in ch06 §6.2 should be re-read against these.

---

## 3. Other major subsystems the briefing omits entirely

Checked against `/home/kali/vigil/docs/FEATURES.md` (260+ features, 7 domains) and the top-level tree.

**Now covered** (previously flagged in `_review/completeness.md` Part C, since fixed — do not re-report these as gaps): authenticated scanning (`09`), the out-of-band relay/Collaborator (`03`, `09`), entitlements (`02` §3.10, `07`, `08` §3.2, `12`), Intruder and Repeater (`02`, `09`, `13`), gauntlet (`02`, `11` §3.7), intake (`03`, `09`, `12`), post-quantum (`13`), fireteam (`02`, `11` §5.2), confidence engine (`02`, `04` §7), socialdefense (`13`), channel binding (`02`, `13`), the supply-chain safeguards (`06` §12, `09` §7.2, `12` §2.10).

**Still absent or one-line:**

| Subsystem | Where it lives | State |
|---|---|---|
| **SIGIL MCP memory server (8 tools)** | `apps/sigil/sigil/mcp/` | ABSENT |
| **Perception / vision / OCR / ambient watch / recall** | `apps/sigil/sigil/perception/` (9 modules) | ABSENT |
| **Voice pipeline** | `apps/sigil/sigil/voice/` (8 modules) | 3 passing mentions |
| **Gesture / SIGIL-HAND** | `apps/sigil/sigil/gesture/` (10 modules) | 2 mentions, both corrections |
| **Phone companion / bridge / PWA / device ledger** | `apps/sigil/sigil/bridge/`, `sigil/mesh/registry.py` | 3 CLI rows |
| **Sovereign Kùzu knowledge graph + ARCHIVIST consolidation** | `apps/sigil/sigil/graph/`, `sigil/consolidate/` | ABSENT |
| **Spine ingestion (Claude history, git hooks, subagent transcripts, docs)** | `apps/sigil/sigil/ingest/` (8 modules) | ABSENT |
| **SCRIBE / WebResearcher + the grounded scraper** | `apps/sigil/sigil/scrape/` (10 modules) | ABSENT by name |
| **On-device vectors (fastembed/CPU/no-API) + "no grounded match"** | `apps/sigil/sigil/vectors/` | 2 rows |
| **The mesh: host-capability ledger + device-authorization ledger** | `apps/sigil/sigil/mesh/registry.py` | ABSENT (`FEATURES.md:813` marks the device ledger "previously undocumented") |
| **Cross-platform / honest-degrading backends (macOS/Windows/Android)** | `apps/sigil/sigil/platform/` | ABSENT — a procurement-relevant honest limit |
| **The SIGIL cockpit as a current product surface** | `apps/sigil/sigil/ui/` | Described in `09` §9.1 as a **"legacy"** 5-panel page. The README calls it the current "glass cockpit". One of these is wrong — worth resolving before writing. |
| **Engagement Library (29th screen)** | `console/api.py:180+`, `screens.yaml:92` | ABSENT — post-dates briefing |
| **Case file (9 documents in every dossier)** | `report/case_file.py`, `report/adapt.py` | ABSENT — post-dates briefing |
| **`formal/`** — machine-checked models of the four core invariants | `/home/kali/vigil/formal/` (antirollback, boundary, gate, oracle-mint + `CORRESPONDENCE.md`) | One bullet in `01` §8.7. `_review/completeness.md` C16 already flags it as under-weighted; still is. |
| **Deep-learn K3 (FIND/DETECT/PREVENT, graph-as-skillset)** | `FEATURES.md:700-706` | ABSENT by name |
| **The `knowledge/` tree itself** (kb, decisions, skills, system-map) | `/home/kali/vigil/knowledge/` | One table row |
| **`tools/livefire/`** — the live-fire harnesses (K8s RBAC, GitHub secret) | `/home/kali/vigil/tools/livefire/` | The *results* are covered in `01` §9.3 and `06` §11.1; the harnesses themselves are not named |
| **`envs/`** — the two-environment build (`offense.txt` / `sovereign.txt`) | `/home/kali/vigil/envs/` | The separation is covered (`02` §5.3); the mechanism that produces it is not |

**Also worth folding in:** `_review/OUTSTANDING.md` documents 78 open items including **3 security/safety defects "written down nowhere in this repository"** and **10 that would block an agency deployment**. Three of the five anti-replay defects it names (A-1: `governor.promotion`, `governor.capability`) have since been fixed on main (`3730b1a3`, `b02ec184`, `ae95cfe3`, `934abf46`). The briefing's master status ledger (`00-index.md` §8) does not reflect either the defects or the fixes.

---

## 4. Absorb into an existing chapter vs. write a new one

**Absorbs cleanly — the structure is already there:**

- `09-the-screens.md` §5 (MANAGE) → Engagement Library as **§5.14**. Then a global sweep of "twenty-eight" → "twenty-nine" (11 occurrences incl. the §12 count table and the §13 closing line).
- `06-evidence-and-proof.md` §6.2 ("The one-click dossier") → the case file as the natural continuation; and §5.2 ("The three human documents") needs re-scoping since there are now nine more.
- `11-the-agents-and-learning.md` §4 → SCRIBE as a tenth row + a short sub-section, using the same table shape. This is a 1-hour edit.
- `10-the-picture-of-the-attack.md` §14 ("Four different pictures of the same work, named honestly") → **already the correct home** for the offense-world-model vs sovereign-knowledge-graph distinction. It becomes "Five pictures", with a pointer to the new SIGIL chapter.
- `03-an-operation-end-to-end.md` §3 (the session) → one paragraph reconciling session / engagement / library, and §12 (Stage 9, the report) → the case file in the deliverables list.
- `12-tools-and-what-you-need.md` §2.3/§2.5 → the phone/WireGuard prerequisite and the bridge listener; §2.2 → the cross-platform honest-degrading note.
- `08-safety-and-authorization.md` §4 (the approval queue) → phone-signed approval as a sub-section: it is an approval mechanism and belongs with the others.
- `01-what-this-is.md` §4.2 and `02-the-parts.md` §3.6 → three or four sentences each giving Strix a place in the operational narrative, plus a Strix mention in `03`.

**Warrants a new chapter:**

> **A new Chapter 14 — "SIGIL: the sovereign side, in full."**

Everything ABSENT above that is SIGIL-side is one coherent subsystem with one doctrine, and there is no chapter whose structure can absorb it. `02` §3.5 is a 50-line map entry; `11` §4 is an agent roster. Neither has room for the spine as memory, ingestion, the Kùzu graph, consolidation, vectors, perception/OCR, voice, gesture, the cockpit, the MCP memory server, the mesh ledgers, the phone companion, and cross-platform honesty. Attempting to spread it across `02`, `09`, `11` and `12` would give the operator exactly the outcome they are objecting to.

Recommended shape, mirroring the existing chapter idiom (a "why this chapter exists" opener, numbered sections, a "what this does not prove" column, a closing honest-status ledger):

1. Why there is a sovereign side at all (and why it is offense-free by *absence of code paths*)
2. The spine as memory — what is ingested, 43k+ records, deterministic projections
3. The knowledge graph (Kùzu) and the nightly consolidation pass — and how it differs from chapter 10's map
4. Vector recall — on-device, no API, and "no grounded match"
5. The ten agents *(cross-reference ch11 §4 rather than duplicating it)*
6. Perception: OCR is authoritative, the model is advisory; ambient watch; the frontier-egress approval
7. Voice and gesture — the pipelines, and the WARDEN ceilings that make them safe
8. The cockpit and the HUD
9. The MCP memory server — the 8 cited read-only tools
10. The mesh and the phone companion — device keys, per-request signatures, panic-halt, what never crosses the tunnel
11. Cross-platform: what is proven on Linux and what is an honest seam
12. Honest status ledger

Then update `00-index.md` §4 (contents), §6 (subject locator), §8 (master status ledger) and `00-glossary.md` §3 and §8 accordingly, and re-assemble `VIGIL-EXPLAINED.md`.

---

## 5. Gap table

Sizes assume the briefing's established density and evidence discipline (read the code, quote it, state the limit).

| # | Topic | Current coverage | Where it should live | Size |
|---|---|---|---|---|
| 1 | **The case file (9 documents)** | ABSENT — post-dates briefing | `06` §6.2 + `03` §12 + `01` §7.1 + `09` §4.8 | **1,800–2,500 w** |
| 2 | **Engagement Library (29th screen)** | ABSENT — post-dates briefing | New `09` §5.14 + fix 11 "twenty-eight" counts + `03` §3 reconciliation | **900–1,300 w** |
| 3 | **The phone companion** | 3 CLI rows | New ch14 §10 + `08` §4 sub-section + `12` §2.3/§2.5 | **2,500–3,500 w** |
| 4 | **SIGIL MCP memory server (8 tools)** | ABSENT | New ch14 §9, mirroring `09` §5.8's structure | **1,200–1,800 w** |
| 5 | **Perception / OCR / ambient / recall** | ABSENT | New ch14 §6 | **2,000–2,800 w** |
| 6 | **Sovereign knowledge graph + consolidation** | ABSENT | New ch14 §3 + a disambiguation section in `10` §14 | **2,200–3,000 w** |
| 7 | **Spine as memory + ingestion** | Crypto covered; memory not | New ch14 §2 | **1,500–2,200 w** |
| 8 | **Voice** | 3 passing mentions | New ch14 §7 | **1,200–1,800 w** |
| 9 | **Gesture / SIGIL-HAND** | 2 mentions, both corrections | New ch14 §7 | **1,200–1,800 w** |
| 10 | **SIGIL as a whole (the framing chapter)** | `02` §3.5 only | New ch14 §1 + §12; expand `02` §3.5 by ~40% | **1,500–2,000 w** |
| 11 | **SCRIBE / WebResearcher (10th agent)** | ABSENT by name | `11` §4 table row + sub-section | **500–800 w** |
| 12 | **Point-at-a-URL learning (K4)** | 1 table cell + 1 bullet | New ch14 §"the grounded scraper" + expand `09` §6.4 | **1,200–1,800 w** |
| 13 | **Vector recall** | 2 glossary/table rows | New ch14 §4 | **700–1,000 w** |
| 14 | **Mesh ledgers (host capability + device auth)** | ABSENT | New ch14 §10 + `07` §4 key inventory row | **800–1,200 w** |
| 15 | **Cross-platform honest seams** | ABSENT | New ch14 §11 + `12` §2.2 | **500–800 w** |
| 16 | **Strix — operational narrative** | Good in `02` §3.6; absent from 7 chapters | Cross-refs in `03`, `05`, `09` §4.2, `12` §1.8 | **1,000–1,500 w** |
| 17 | **The governed terminal — the *second* one** | Both covered, never connected | 3 paragraphs in `09` §4.4 + `11` §4 | **300–500 w** |
| 18 | **Deep-learn K3 (FIND/DETECT/PREVENT)** | ABSENT by name | `11` §7.4 | **600–900 w** |
| 19 | **The `knowledge/` tree + knowledge sync** | 1 table row | `12` (new sub-section) or ch14 | **700–1,000 w** |
| 20 | **`formal/` — machine-checked invariants** | 1 bullet (`01` §8.7); flagged in `_review` C16 | `06` §13 or `08` §15 | **800–1,200 w** |
| 21 | **`tools/livefire/` + `envs/`** | Results covered, mechanisms not | `12` §2.10 and `02` §5.3 | **400–700 w** |
| 22 | **HUD as a cross-plane channel** | 1 paragraph as "furniture" | New ch14 §8 | **300–500 w** |
| 23 | **Master status ledger refresh** | Stale by 6 PRs; ignores `_review/OUTSTANDING.md` | `00-index.md` §8 | **800–1,200 w** |
| 24 | **Index / glossary / cross-reference updates for all of the above** | n/a | `00-index.md` §4/§6/§8, `00-glossary.md` §3/§8 | **1,000–1,500 w** |

**Total: roughly 26,000–37,000 new words**, of which **~15,000–20,000 forms the new Chapter 14** and the rest is distributed edits. Plus a mechanical re-assembly of `VIGIL-EXPLAINED.md`.

**Suggested order:** (1) and (2) first — they are already-shipped product the briefing under-sells and each is a self-contained edit; then the new Chapter 14 as one piece (items 3–10, 12–15, 22); then the cross-chapter cross-referencing (11, 16, 17, 18); then the housekeeping (19–21, 23, 24).