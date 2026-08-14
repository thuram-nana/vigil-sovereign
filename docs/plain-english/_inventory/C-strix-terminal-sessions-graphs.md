<!-- GROUND TRUTH: Strix, the governed terminal, sessions, and the graphs. Cited file:line. -->

# Inventory: four subsystems of `/home/kali/vigil`

All paths absolute. Read-only; nothing was modified.

---

## 1. STRIX — the vendored agentic pentest tool

**One sentence:** Strix is a third-party (Apache-2.0, `usestrix/strix`) autonomous AI-hacker product vendored whole into `/home/kali/vigil/vendor/strix/`, which VIGIL runs as its "agent body" — it drives real tools inside a Kali Docker sandbox and writes its own vulnerability reports — and everything it *executes* is wrapped in a VIGIL gate it does not own.

### What it is
- Product description in its own words: `/home/kali/vigil/vendor/strix/README.md:44` — "autonomous AI penetration testing agents that act just like real hackers … run your code dynamically, find vulnerabilities, and validate them through actual proofs-of-concept."
- VIGIL's own plain-English framing already calls it "a *vendored* third-party autonomous testing tool … used as a source of **suggestions only**; nothing it says becomes a fact without passing the same checking as anything else" — `/home/kali/vigil/docs/plain-english/00-glossary.md:84`.
- Model runtime is Claude: default `anthropic/claude-opus-4-8` (`/home/kali/vigil/vendor/strix/strix/config/settings.py:23`), with an allowlist of Claude families and extended-thinking detection at `/home/kali/vigil/vendor/strix/strix/config/models.py:87-91,217-233`. VIGIL owns a dedicated CI leg for this: **"strix Claude-runtime (P8)"** at `/home/kali/vigil/.github/workflows/ci.yml:348-367`, running `vendor/strix/tests_vigil` (Anthropic price table, reasoning/thinking, dedupe fallback).

### How VIGIL drives it
Three entry points, all *subprocess*, never in-process import:
1. **`vigil strix …`** — a passthrough subsystem verb that execs `.venv-offense/bin/strix` in the offense venv: `/home/kali/vigil/integration/vigil_integration/cli.py:37` and the routing table `/home/kali/vigil/integration/vigil_integration/dispatch.py:27`. `PYTHONPATH`/`PYTHONHOME` are stripped from the child so the sovereign trust domain can never be injected (`dispatch.py:86`, described at `/home/kali/vigil/docs/FEATURES.md:116`). Both console scripts exist on this machine (`.venv-offense/bin/strix`, `.venv-sovereign/bin/sigil`).
2. **The console "codebase" launch** — `/home/kali/vigil/engine/crucible/framework/v2/console/actions.py:536-568`. It pre-flights Docker and refuses honestly if absent (`actions.py:544-547`), spawns `strix --non-interactive --target|--mount <path>` (`actions.py:548-552`), and hands the child three env vars: `VIGIL_PROOF_RUN_DIR`, `VIGIL_ENGAGEMENT`, `VIGIL_BASE_DIR` (`actions.py:566-567`).
3. **The Strix runner itself** — `/home/kali/vigil/vendor/strix/strix/core/runner.py`, which builds the root agent, the child-agent factory, the sandbox session, and the run hooks.

Findings that carry an executor capture are minted into signed proofs by the **Proof Studio sink**, installed into the running Strix process at startup: `/home/kali/vigil/integration/vigil_integration/proof/bootstrap.py:1-18` (`install_from_env` is a NO-OP without `VIGIL_PROOF_RUN_DIR`, so bare vendored Strix is unchanged).

### How it is GOVERNED — the WARDEN gate (this is the load-bearing part)
- **The chokepoint.** Every CLI invocation Strix makes — nmap, ffuf, python3, curl, agent-browser — flows through two tool names: `exec_command` and `write_stdin`. Gating those two gates *all* arbitrary execution: `/home/kali/vigil/integration/vigil_integration/warden_gate.py:322-328`.
- **The classifier.** `_strix_shell_classifier` rates those two names **A3** and everything else **A0** (`warden_gate.py:331-336`), deliberately *not* the generic offense classifier (which would rate everything A2 and freeze the agent).
- **Attachment.** `attach_from_env` composes `WardenGateHooks` onto Strix's own `ReportUsageHooks` via `compose_run_hooks` (`warden_gate.py:376-420, 423-460`); the runner calls it at `/home/kali/vigil/vendor/strix/strix/core/runner.py:244-249`.
- **ON BY DEFAULT.** Absent env ⇒ on. Only an explicit `VIGIL_WARDEN_STRIX_GATE` ∈ {`0`,`off`,`false`,`no`} turns it off (`warden_gate.py:276-286`).
- **FAIL-CLOSED (the recent change, PR #296).** Any wiring failure now raises `WardenGateUnavailable` instead of returning ungated hooks — `warden_gate.py:454-460`, with the rationale spelled out at `warden_gate.py:432-439`: *"a wiring failure is not an opt-out … continuing would leave the most dangerous surface in the system unguarded with no signal."* Correspondingly the runner narrowed its `except` to `ImportError` only (`runner.py:246`), which means exactly one thing: a bare vendored checkout with no `vigil_integration` on the path. **A briefing must say: a broken gate now stops the run.** Cross-referenced in `/home/kali/vigil/docs/AS-BUILT.md:110` and `:136`, and `/home/kali/vigil/docs/FEATURES.md:366`.
- **What happens on a gated call.** A QUEUE is *approve-then-run*, not a hard block: the hook publishes a pending request bound to the **actual command** (parsed from `ToolContext.tool_arguments`, `warden_gate.py:302-319` — an earlier bug bound a constant), waits (bounded by `VIGIL_APPROVAL_WAIT_SECONDS`, default 0) off the event loop, verifies a single-use owner-signed token, burns the nonce once, and runs that ONE call: `warden_gate.py:225-266`, approver built at `warden_gate.py:339-373`. **No authority provisioned ⇒ hard block** (`warden_gate.py:242-246`).
- The generic gate-of-record this composes into is `/home/kali/vigil/packages/core/vigil_core/vigil_core/gate.py:63-120` (first-failure-wins; only an explicit WARDEN `"auto"` may open it).

### Strix's own autonomy vs. VIGIL's gates — the distinction a briefing must not blur
Strix genuinely decides for itself: which vulnerabilities to hunt, which tools to run, and **it spawns its own subagent teams** (`create_agent`, `send_message_to_agent`, `stop_agent`, `view_agent_graph`, `wait_for_message` — `/home/kali/vigil/vendor/strix/strix/tools/agents_graph/tools.py:365`, wired at `/home/kali/vigil/vendor/strix/strix/agents/factory.py:19-26`). Its prompt instructs a root coordinator to delegate and to spawn "a specialized subagent for EACH vulnerability type × EACH component" (`/home/kali/vigil/vendor/strix/strix/agents/prompts/system_prompt.jinja:283-298`). VIGIL does **not** constrain that planning. What VIGIL constrains is the moment of execution: the shell is classified and must be owner-approved per command. Strix also writes its own vulnerability reports (`tools/reporting/tool.py`), and VIGIL treats those as **leads, never facts** — the oracle is the sole authority (`/home/kali/vigil/docs/FEATURES.md:425`).

### What it can reach; the sandbox story
- Non-shell tools that auto-run (A0): thinking, notes, todo, web_search, apply_patch, reporting, view_image, load_skill, finish (`warden_gate.py:325-326`). Note `web_search` is a real outbound capability and auto-runs.
- It also drives a Caido intercepting proxy (`vendor/strix/strix/tools/proxy/`) and `agent-browser` (Chromium, driven *through* `exec_command`, so it is gated — `/home/kali/vigil/vendor/strix/strix/tools/agent_browser/README.md:1-13`).
- Skills library: 24 vulnerability playbooks plus cloud/protocol/framework/recon/tooling sets — `/home/kali/vigil/vendor/strix/strix/skills/vulnerabilities/`.
- **Sandbox:** Docker is mandatory; backend registry defaults to docker (`/home/kali/vigil/vendor/strix/strix/runtime/backends.py:1,59`), image `vigil/strix-sandbox:local` built from a **digest-pinned** Kali base (`/home/kali/vigil/vendor/strix/containers/Dockerfile:1-12`). Sandbox tool roster (nmap, sqlmap, nuclei, ffuf, semgrep, trivy, …) is declared informational-only and explicitly **not host-installed**: `/home/kali/vigil/engine/crucible/framework/v2/tools/registry.py:234-260`.
- **Egress containment:** the sandbox is pinned to an `internal: true` Docker network whose only exit is the VIGIL gateway container, and **`NET_ADMIN` is dropped** so the sandbox cannot rewrite its own routing — `/home/kali/vigil/gateway/vigil_gateway/docker.py:1-30` and the vendor patch `/home/kali/vigil/vendor/strix/strix/runtime/docker_client.py:2,14-16,68-78`.

### Deployment reality on THIS machine (do not describe as live)
- The `vigil/strix-sandbox:local` image is **not built** (`docker images` shows 40 images, none Strix). A codebase run would refuse at the Docker pre-flight or fail to find the image.
- The sandbox/gateway network topology is a *recommended* topology wired by env var, not something currently running.

### What is deferred
- **Streaming Strix's findings onto the event spine is NOT built.** A console Strix run is recorded with `"stream": "none"` (`actions.py:556,568`) and the UI shows an honest "reports in its own sandbox" empty state (`/home/kali/vigil/docs/FEATURES.md:210`). The Fixes screen explicitly refuses because "a console Strix codebase run does not emit a signed offense spine" (`/home/kali/vigil/docs/FEATURES.md:223`). The **"extended Strix finding contract" is listed as still deferred** at `/home/kali/vigil/docs/AS-BUILT.md:297`.
- The next-generation agent body (porting Strix's Kali execution to the Claude Agent SDK with in-process MCP servers) is an interface-only scaffold: `/home/kali/vigil/engine/crucible/framework/v2/agent_body/interface.py:1-33` and `/home/kali/vigil/docs/AS-BUILT.md:266-269`.

---

## 2. THE GOVERNED TERMINAL

**One sentence:** A console screen (and a `vigil terminal` CLI verb) that lets the operator run a small, curated set of **local, read-only** commands — each classified, each queued for the operator's own approval, each executed with no shell at all, and each written to an append-only signed, redacted transcript.

### What it lets an operator do
- **Direct path:** type a command → an advisory dry-run badge → click **Run**. The Run click *is* the approval. UI at `/home/kali/vigil/packages/vigil-ui/app.js` `renderTerminal` (documented `/home/kali/vigil/docs/FEATURES.md:228-229`).
- **AI chat dock (T2b capability-router):** ask in English; Claude classifies the intent into `command` (propose a candidate string — still dry-run/allowlist-checked and still approve-then-run), `answer` (read-only, cited from a secret-redacted session context, runs nothing), or `route` (points at the gated engagement path, runs nothing) — `/home/kali/vigil/engine/crucible/framework/v2/console/actions.py:1707` (`terminal_propose`), doctrine at `actions.py:1321-1337`. **The AI proposes; the allowlist + gate + human decide.**
- **CLI:** `vigil terminal [--approve] [--base-dir] [--slug] -- <command>` — `/home/kali/vigil/integration/vigil_integration/cli.py:1448-1500`.

### How each command is classified and gated
- `terminal.run` classifies **A2** under the one shared WARDEN classifier; under the A1 offense ceiling the conjunctive gate therefore **QUEUES** it — it can never auto-run. This is asserted twice: as a gate outcome, and as a *construction invariant* inside the executor that refuses if the classifier ever drifts to auto-eligible — `/home/kali/vigil/integration/vigil_integration/live/executor.py:865-878` and `:1136-1141`.
- Without `--approve` the base gate queues and the executor denies at authorization: the command is parsed, validated and gated but **never run** (`cli.py:1479-1483`).
- `--approve` selects `rt.approval_gate`, which upgrades a WARDEN *queue* to *allow* — and **preserves a CRUCIBLE deny**: approval never widens scope — `/home/kali/vigil/integration/vigil_integration/live/wiring.py:633-650`.
- Authorization is scoped on `127.0.0.1` so the CRUCIBLE loopback scope check and the kill-switch both apply (`executor.py:1143-1149`).

### Recording and signing
- **No signer ⇒ refuse before running.** "Unrecordable = unprovable" — `executor.py:1103-1105` (and `cli.py:1477-1478`).
- Every successful run produces a signed, redacted `ExecRecord` appended to `terminal-history.jsonl` — `cli.py:1485-1494`, `_append_terminal_history` at `cli.py:1434-1446`. The record's tier is overridden to the WARDEN classification so the "never auto" property is visible on the spine (`executor.py:1163-1166`).
- Read back read-only by the console: `/home/kali/vigil/engine/crucible/framework/v2/console/actions.py:1841-1869` → route `/api/terminal/history` (`server.py:118`). Live on this machine: `/home/kali/vigil/.vigil-live/terminal-history.jsonl` (1 record).

### How the transcript reaches the case file / dossier
- `vigil dossier --terminal-history <path>` (defaults to a `terminal-history.jsonl` next to the run dir) — `/home/kali/vigil/integration/vigil_integration/cli.py:1110-1125`.
- The builder scrubs the JSONL a second time (an unparseable line is **dropped**, never shipped in the clear) and adds it as `logs/terminal-transcript.jsonl` — `/home/kali/vigil/engine/crucible/framework/v2/report/dossier.py:268-270, 946-957`, listed in the human index at `dossier.py:731-732`. It is a **session-global** log, not run-specific (`dossier.py:946-949`).

### Redaction
One vocabulary, one path: `_redact_str` / `_redact_arg_list` (Bearer tokens, key=value, flag values, URL userinfo) — `/home/kali/vigil/integration/vigil_integration/live/executor.py:31-34, 73, 480-484`. Raw stdout/stderr is returned to the caller so a deterministic oracle can re-fire over it, but **the record persists no secret** (`executor.py:31-34`).

### Sandboxing — and the honest distinction
`vigil terminal` is **not** sandboxed. Its safety is *by construction*, not by isolation: no shell is ever invoked (argv list, `shell=False`, ASCII-whitespace split only), the whole command is refused if it contains any of `; & | > < \` $ ( ) { } \n \r NUL \` (`executor.py:857-861`), and `argv[0]` must be on a curated allowlist of binaries that can neither exec, write a file, nor open a socket under *any* argv (`executor.py:793-816`). Capable binaries are handled by **allowlist, not denylist**, after a red-pen proved a spelling denylist can never be complete (GNU `getopt_long` prefix abbreviations; `date MMDDhhmm` sets the clock; a second `uniq` operand is an output file) — `executor.py:766-792`, `_FIND_SAFE_PREDICATES` `:844`, `_SORT_SAFE_FLAGS`/`_UNIQ_SAFE_FLAGS` `:824-843`, bare-only `date`/`hostname` `:818-820`. `xxd`, `env`/`printenv` and `getent` are deliberately excluded, each with a stated reason (`executor.py:806-812`).

The *sandboxed* sibling is a different verb: **`vigil sandbox`** runs an arbitrary command (pipes and all) inside a bwrap kernel-isolated, network-less, workspace-confined jail, classified **A3**, same gate + signed record, and **a missing bwrap is a clean refusal with no un-sandboxed fallback** — `/home/kali/vigil/integration/vigil_integration/cli.py:1503-1530`, `/home/kali/vigil/docs/FEATURES.md:113`.

### What it can NOT do
No network egress (every network binary absent from the allowlist), no file writes, no interpreters (`bash`/`python`/`awk` all absent), no shell metacharacters, no redirects, no globbing, no environment dumping. Pipelines *are* supported but only of allowlisted read/print stages, max 8 stages, run sequentially with no shell (`executor.py:978-1017`). It cannot auto-run — ever. And per the autonomous-loop rule, a `terminal.run` record's output is **advisory-only and never enters oracle intake**, so an autonomous terminal command can never mint a FACT (`/home/kali/vigil/docs/FEATURES.md:412`). The console's own allowlist copy is explicitly a *mirror* used only for the preview badge; a drifted copy can only mislead the preview, never let something run, because `vigil terminal` re-parses authoritatively (`actions.py:1333-1337`).

---

## 3. SESSIONS — and the three-way distinction

**One sentence:** A session is a durable, operator-named *container for one line of work* — it links the runs and the chat transcript of that work, owns a graph partition, and can be connected to other sessions so a later run can draw on their knowledge as priors.

### The three different things (a briefing must not conflate them)
| Thing | What it is | Identity | Where |
|---|---|---|---|
| **Run** | ONE execution of one tool/engine — a scan, an engage, a Strix codebase pass. Ephemeral unit of work. | `run_id` like `20260812-143355-118` | `<CRUCIBLE_ROOT>/.console/runs/<run_id>/meta.json` |
| **Engagement** | The *authorized job* — a charter slug with a signed authority, a scope, a kill-switch, and a spine. This is the safety object. | `slug` (e.g. `acme-prod`) | `targets/<slug>/`, plus the signed spine |
| **Session** | The operator's *organising* container: a named workspace grouping runs + chat + a graph partition. Grants no authority whatsoever. | `sess-A` / auto id | `<VIGIL_LIVE_DIR>/sessions/<id>/session.json` |

A run records the session it belongs to and the engagement slug it ran under; the library groups runs by the slug **recorded in the run's own meta.json**, so membership can never be asserted by a caller (`/home/kali/vigil/engine/crucible/framework/v2/console/api.py:258-260, 294-296`).

### The session registry
- `/home/kali/vigil/engine/crucible/framework/v2/console/sessions.py:1-29` (module doctrine). Persistence `<VIGIL_LIVE_DIR>/sessions/<id>/session.json`, dir 0700 / file 0600, atomic tmp+rename.
- Ordering coordinate is a **monotonic per-registry `seq`, not wallclock** (`sessions.py:11-13`); a separate `updated_ts` drives UI sort only.
- Mutations are serialised under an RLock because the console is a threading HTTP server (`sessions.py:47-54`).
- CRUD: `create_session` `:194`, `ensure_session` `:218`, `rename_session` `:230`, `delete_session` `:243` (SOFT tombstone retains chat + run metas + spine; HARD additionally drops the rebuildable graph partition — **never the spine, never a FACT**), `link_run` `:273`, `get_session` `:529`, `list_sessions` `:572`.
- **Authority: none.** "The registry mints NO facts, reads NO tier/grant, and authorizes nothing" (`sessions.py:24-26`).
- A base-dir bug was fixed so the registry always resolves absolutely next to the runs it references — a console started from another directory used to show phantom/empty run lists (`sessions.py:57-84`).

### What a session accumulates
`run_ids`, an engagement `slug`, `connections`, `created_seq`/`updated_seq`, a name — the public shape is `sessions.py:176-190`. Plus, outside the record: an append-only **chat transcript** at `<live>/chats/<id>.jsonl` (`/home/kali/vigil/engine/crucible/framework/v2/console/chat.py:1-16`; a legacy chat is *adopted* as a session by `_legacy_chat_entry`, `sessions.py:545`), and a **graph partition**.

### The per-session graph
- Every session owns a partition keyed by its id, materialised by the **default embedded, file-backed store** — no external database required (`sessions.py:15-27`, `_open_graph_store` `:324-344`).
- `project_session_graph` (`:372`) is a **pure, ONE-WAY, full rebuild** from the append-only signed spine of the session's engagement(s) — no wallclock, no RNG, so the same spine yields a byte-identical partition. It re-projects on every `link_run` (`:296-298`).
- The load-bearing invariant: nothing here is *ever* read back into a tier, grant, authorization or FACT; the store structurally exposes no such surface (`sessions.py:19-22`).
- Neo4j is an **optional** backend selected only by `VIGIL_GRAPH_BACKEND=neo4j` plus sealed creds, and **fails safe back to embedded** if it cannot be constructed (`sessions.py:334-344`).
- On disk today: `/home/kali/vigil/.vigil-live/sessions/sess-A` and `/home/kali/vigil/.vigil-live/graph/sess-A.json` — one demo session, embedded backend.

### `session-connect`
- `connect_session(A, B)` (`sessions.py:461-488`): **directional** (A reads B; B does not read A), the POST *is* the operator's consent, capped at 32 (`_MAX_CONNECTIONS` `:458`), self-connection refused. It stores only B's id in A's `connections` — a **read-time scope, not a graph merge**: nothing of B is copied, so `disconnect_session` (`:490`) re-isolates instantly.
- `connections_of` (`:507`) re-validates every id because they become subprocess argv tokens.
- Consumption: the console→live-engine bridge passes `--session <id> --connect <ids>` to `vigil engage` (`/home/kali/vigil/engine/crucible/framework/v2/console/actions.py:451,466,476`; flags defined at `/home/kali/vigil/integration/vigil_integration/cli.py:1578-1586`). Help text is precise: the session key is "a partition/organisation key only — it grants no authority."
- **Deployment caveat:** the graph-backed route is **opt-in, loopback-only, and conditional** — it needs a resolvable `vigil` entrypoint + `NEO4J_URI`; if unavailable it falls through to the ordinary engine with an honest note and keeps the session linkage (`actions.py:594-609`).

### What persists across sessions
The signed spine (the sole authority), the charter/authority/kill-switch per engagement, the run dirs and their reverifiable/evidence/proof artifacts, the chat transcripts, and the knowledge base at `/home/kali/vigil/knowledge/`. The graph partitions are explicitly **rebuildable, disposable derived state** — dropping one loses no authority (`sessions.py:20-22`).

### Handoff
`vigil dossier --session <id>` packages a whole session — each linked run's dossier, the chat transcript, the per-session graph partition pointer + counts, and the open threads — into one signed zip (`/home/kali/vigil/integration/vigil_integration/cli.py:1156-1208`). "Open threads" = the session's runs not in a terminal state, advisory only (`sessions.py:432-457`).

### The newly-added ENGAGEMENT LIBRARY (PR #306, merged `b9ca10e3`, 2026-08-13)
**One sentence:** A screen that lists every past job with a real date and a human name, so an operator returning months later can find the work again.
- Rationale and construction: `/home/kali/vigil/engine/crucible/framework/v2/console/api.py:119-135` — the old listing was an alphabetical `ls targets/` with no timestamps that returned **nothing** for a spine-only engagement. The roster is now the **union of two real sources** — the signed spine (`Blackboard.list_engagements`, `/home/kali/vigil/engine/crucible/framework/v2/agents/blackboard.py:447-472`) and the charter tree — plus the console's own runs grouped by their recorded slug.
- `list_engagements()` `api.py:179-242`; per-engagement detail + its runs `library_engagement()` `api.py:253-278`. Routes: `/api/engagements` (`server.py:106`), `/api/library/` (`server.py:135`).
- **Every timestamp is derived from something on disk; an engagement with no activity is honestly `last_activity: null` rather than back-dated** (`api.py:130-133, 231-233`). The sort tie-break was hardened after driving the real console (`api.py:233-241`).
- **Human names are presentation-only.** `/home/kali/vigil/engine/crucible/framework/v2/console/labels.py:1-27`: a label lives in ONE side-car (`.console/labels.json`), keyed by the immutable identity; nothing writes into a run dir, an evidence certificate, a reverifiable document, a dossier entry, or the signed spine — **so a renamed engagement still re-verifies byte for byte.** The spine's `labels` argument is deliberately *injected, never stored* (`blackboard.py:468-472`).
- UI: `renderLibrary` / `renderLibraryDetail` at `/home/kali/vigil/packages/vigil-ui/app.js:4775, 4865`, NAV entry `app.js:34`, dates rendered **in the viewer's own timezone** with the zone shown (`app.js:4739-4767`).
- The dossier gained a matching `--label` (commit `f83d6e90`, "wire the engagement label into the downloaded case file"; `8e713716` "cli: --label, a build timestamp by default, and an accurate signature claim").
- **Coverage gap:** the phrase "engagement library" appears **zero times** in every file under `/home/kali/vigil/docs/plain-english/`. It is genuinely new and genuinely undocumented for a lay reader.

---

## 4. THE KNOWLEDGE GRAPH(S) — there are three, not two

A briefing must not merge these. They have different schemas, different writers, different questions, and different deployment states.

### (a) The OFFENSE world model — `engine/crucible/framework/v2/worldmodel/`
**One sentence:** A single persistent, typed **attack graph of the target estate** that answers "given what we have observed, what is now reachable, by what explainable route, and which one fix breaks the most routes?"

- Purpose and rationale: `/home/kali/vigil/engine/crucible/framework/v2/worldmodel/README.md:1-26` — bespoke because no off-the-shelf schema spans web + identity + cloud *and* carries per-fact provenance and confidence.
- **Schema:** 12 node kinds (`HOST · SERVICE · ENDPOINT · WEBAPP · DATASTORE · CLOUD_RESOURCE · NETWORK_SEGMENT · PRINCIPAL · CREDENTIAL · SESSION · CONTROL · FINDING`) and 10 edge kinds (`REACHABLE_FROM · TRUSTS_FOR · HAS_GRANT · MEMBER_OF · CAN_ASSUME · VALID_ON · AUTHENTICATES_TO · SESSION_ON · CONTROL_PROTECTS · EVIDENCES`) — `README.md:66-76`, defined in `worldmodel/models.py`.
- **Two non-negotiables:** every fact carries provenance + confidence (a path is only as strong as its weakest edge, `Path.min_confidence` / `Path.provenance_chain`); and time is a monotonic sequence int, never a wallclock — so upserts and queries are deterministic and replayable (`README.md:28-42`).
- **Attacker state is first-class:** `worldmodel/attacker.py:1-24` records postconditions of confirmed primitives (assets OWNED, credentials/sessions HELD, services REACHED) as edges from one canonical attacker PRINCIPAL node — so state survives a restart and chains natively into derivation/pathsearch.
- **Attack paths / crown jewels:** `worldmodel/attack_paths.py:1-33` answers three questions — shortest/highest-confidence path from foothold to crown jewel, **chokepoint ranking** ("which single remediation breaks the most attack paths"), and reachability-bounded blast radius with a counterfactual. `worldmodel/query.py:73` `crown_jewel_paths`, `worldmodel/impact.py:80,109,152`. Business impact is optional: with `targets/<slug>/impact.yaml` levers rank by value severed, without one it degrades to an honest attack-path count (`attack_paths.py:20-25`).
- **How it is populated:** (1) the sensor family writes typed nodes/edges (`sensors/base.py:33`, plus k8s, TLS, mobile, mesh, email-auth, cicd, sbom, identity, gcp); (2) the scanner campaign's `populate_worldmodel`; (3) **`spine_projector.py`** — a pure one-way projection of the signed spine into the asset topology, where "confirmed ⇔ oracle-signed": a finding is a CONFIRMED node only if the record is a FACT carrying **both** a signed `evidence_ref` and a `signature_ref`; a bare `status="fact"` is a LEAD, so "the graph can never launder an unproven claim into a fact" (`spine_projector.py:17-40`). Belief defaults are conservative (0.9 for a grounded fact, never 1.0; 0.5 for a lead).
- **Honest bound (important):** the veracity firewall is a gate at the **writers**, not a universal gate on the graph type — `worldmodel/graph.py:add_node`/`add_edge` have **no** admission gate, and a caller that builds a node directly bypasses the firewall. This is machine-pinned by tests in both directions (`/home/kali/vigil/docs/FEATURES.md:529`).
- **Deployment state: BUILT AND LIVE, no service, no hardware.** Pure Python, file-backed JSON snapshots (`worldmodel/store.py`). Consumed by `plan.py:84-95`, `engage_fusion.py:74`, `engage_autonomous.py:71,223,335`, a CLI `python3 -m framework.v2 attack-paths` (`/home/kali/vigil/engine/crucible/framework/v2/__main__.py:175-182`, lazily imported so the scan path never loads it), and two UI screens: **Attack Graph** and **Timeline** via `/api/worldmodel/<run>` (`/home/kali/vigil/docs/FEATURES.md:211,214`; provider `api.py:589-601`, which **re-executes each finding's retained proof** and shows a stale finding as an UNGROUNDED demoted node). Sends no traffic; mutates nothing. Listed as LIVE in `/home/kali/vigil/docs/FEATURES.md:886-888`.
- **One documentation trap:** `worldmodel/README.md:104-108` still says *"Substrate + tests only this wave. The planner and verify layers consume it in a later wave."* **That is stale** — the planner, the CLI, the spine projector, impact/chokepoints and the console screens all consume it now. A briefing that quotes that README status line would be wrong.

### (b) The SOVEREIGN memory graph — Kùzu, in SIGIL
**One sentence:** A Kùzu property-graph *mirror of the sovereign memory spine* — projects, sessions, documents and commits — that lets the personal core answer "what do I know, and where in signed memory did it come from?"

- `/home/kali/vigil/apps/sigil/sigil/graph/rebuild.py:1-10`: a deterministic replay of the append-only spine in seq order into a **fresh** Kùzu DB under `staging/`, then an atomic swap into `current/`. Never edited in place; two rebuilds over the same spine produce identical node/edge sets. **Every node records the spine seq + entry_hash that minted it, so a graph answer cites memory.**
- Health is `rebuilt_seq == spine_head_seq` (`rebuild.py:29-44`).
- Reads: `apps/sigil/sigil/graph/query.py:1-26` — opens `current/` **read-only**, and the Cypher passthrough is guarded twice (a write-keyword denylist `_WRITE_KW` *and* the read-only connection). Entities carry their spine anchor.
- Node/edge kinds are structural, not semantic: projects, sessions, documents, commits (`rebuild.py:26,49-60`).
- CLI: `sigil graph [--status]` — `/home/kali/vigil/apps/sigil/sigil/cli.py:101-112, 1231-1235`.
- **Deployment state: BUILT AND ACTUALLY POPULATED on this machine.** `kuzu==0.11.3` is a declared dependency (`/home/kali/vigil/apps/sigil/pyproject.toml:39`) and is installed in `.venv-sovereign`; `~/.sigil/graph/current/db.kuzu` exists at 12 MB with a `manifest.json` (built 2026-07-17). No external service — Kùzu is embedded.

### (c) The offense-side chain graph / Neo4j read-model
**One sentence:** A derived read-model of *how an engagement unfolded* (`AttackChain → ChainStep → {Finding | Failure | Decision}`), used to feed prior context into later runs — with a real Neo4j client written but no Neo4j running.

- Pure projector + query: `/home/kali/vigil/integration/vigil_integration/graph/__init__.py:1-10` ("Neo4j is the deferred live backend; this slice is the pure projector"), `graph/model.py`, `graph/projector.py` (the ONE writer), `graph/query.py` (non-authoritative retrieval context — a lead can never be returned as a fact).
- The live binder: `/home/kali/vigil/integration/vigil_integration/live/graph_neo4j.py:1-46` — 7 stated invariants: projection-only with one writer; **CONFIRMED is a physically distinct Neo4j label** derived from the projector's oracle-grounded flag, never from a finding field, so a Lead cannot appear in a confirmed query; no authority is ever read *from* Neo4j; all Cypher is parameterised (only labels/rel-types are interpolated, from a fixed enum); fail-closed and total; secret-free via the one F3 redactor; deterministic (spine `seq`, never wallclock). The driver is injected, never imported — unit tests run against a fake session.
- The console-side equivalent store: `/home/kali/vigil/engine/crucible/framework/v2/graph/store.py:1-40` — `EmbeddedGraphStore` is `[BUILT]` and is the default; `Neo4jGraphStore` is labelled **`[BUILT client body — infra-gated deploy]`** at `store.py:315-338`: the MERGE/DETACH-DELETE Cypher is real and reviewable and its shape is tested over a fake transaction, but *"the `neo4j` driver package and a running Neo4j service are both ABSENT in this environment"*, and constructing without an injected driver raises a clear actionable error.
- **Deployment state — check performed, and the answer is: the service is absent.**
  - `docker-compose.yml:43-56` defines a digest-pinned `neo4j:5-community` behind an **optional `graph` profile**, loopback-bound only (`docker-compose.yml:14,20`).
  - On this machine a container named `vigil-neo4j` (image `neo4j:5`) exists but is **`Exited (255)` ~3 weeks ago** — not running.
  - The `neo4j` Python driver is **not installed** in `.venv-offense`.
  - The activation runbook is explicit: `/home/kali/vigil/docs/DEFERRED-INFRA.md:45-63` (provision Neo4j, export `NEO4J_URI`/`NEO4J_AUTH`, `pip install neo4j`, then run the loud-skipped `test_live_neo4j_round_trip`). `/home/kali/vigil/docs/AS-BUILT.md:295-297` lists "a running **external** Neo4j/OTLP service" as still deferred, noting the embedded file-backed store is built.
  - Consequence for the briefing: **the per-session graphs are real and working today on the embedded file-backed store; the Neo4j-backed and "graph-backed engage" paths are code-complete but not deployed.** Saying "VIGIL uses Neo4j" would be wrong.

### And what `knowledge/` is *not*
`/home/kali/vigil/knowledge/` is **not a graph.** It is a version-controlled prose + manifest knowledge base — `kb/` (living prose), `system-map/` (machine-readable screen/nav manifest SIGIL ingests to navigate by voice, CI drift-checked against the UI), `skills/{find,detect,prevent}/` (learned playbooks), `decisions/`, `sessions/` (redacted build transcripts) — `/home/kali/vigil/knowledge/README.md:1-24`. Its doctrine section is explicit and quotable: *"None of it is a fact, an authorization, or a detector oracle … Committing something here does not make it true"*, and **pushing it is the only outward-facing act in the whole knowledge flow, always explicit and operator-gated (`vigil knowledge push`); no agent and no automation ever pushes** (`README.md:26-33`).

---

## Quick status table for the briefing

| Item | Status |
|---|---|
| Strix vendored + `vigil strix` verb + console codebase launch | Built; console scripts installed |
| Strix WARDEN shell gate (on by default, fail-closed) | Built + CI-gated; the fail-closed change is recent (#296) |
| Strix Kali sandbox image `vigil/strix-sandbox:local` | **Not built on this machine** — a codebase run needs Docker + this image |
| Strix findings streaming onto the event spine | **Deferred** — `stream: "none"`, no signed offense spine emitted |
| `vigil terminal` + console Terminal screen + signed transcript | Built and exercised (a record exists on disk) |
| `vigil sandbox` (bwrap) | Built; refuses cleanly if bwrap is absent — no un-sandboxed fallback |
| Session registry, per-session graph (embedded store), session-connect | Built and working; one demo session + partition on disk |
| Graph-backed `engage --session --connect` via Neo4j | Code-complete, **opt-in and conditional**; falls back with an honest note |
| Engagement Library (dates + human names) | **New (PR #306, 2026-08-13)**; absent from every plain-English doc |
| Offense world model + attack paths + chokepoints | Built and LIVE; README status line is stale |
| SIGIL Kùzu memory graph | Built, dependency installed, database populated (12 MB, 2026-07-17) |
| Neo4j service | **Absent** — client body exists, container exited 3 weeks ago, driver not installed |