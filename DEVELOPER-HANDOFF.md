# VIGIL — Developer Handoff

**If you are inheriting this repository, start here.** This is the one page whose job is to hand the
whole system to the next engineer so the work can continue without the person who built it. It is a
*signposted reading order* — not a re-explanation. It tells you the four rules you must never break, how
to stand the system up and test it, where every subsystem lives, and which page to read next for each.

VIGIL is a provable-autonomy pentest platform. Its entire moat is one sentence: **the machine cannot lie
about a finding.** Every FACT is proven by a deterministic oracle over bytes the target actually produced,
cryptographically signed, offline-verifiable, inside a fail-closed two-plane sovereign envelope. Your job,
whatever you touch, is to keep that true.

---

## 0. The four invariants (memorize these — every change must preserve all four)

These are non-negotiable. A change that weakens any of them is a regression even if every test passes,
and most of them are enforced by tests and by the build itself. Each links to the page that goes deep.

1. **Two-env boundary / `FATAL-2`.** Offense (`.venv-offense`, *keyless*: `engine/crucible` + `vendor/strix`
   + `gateway` + `integration`) and sovereign (`.venv-sovereign`, *owner key*: `apps/sigil` +
   `packages/core/vigil_core` + `integration`) **never co-load in one interpreter.** `integration/`
   (`vigil_integration`) is installed in **both** venvs, so any module that touches `framework.v2` (the
   offense engine) must import it **lazily** (function-local `import`), never at module top level — or it
   trips the sovereign env's import-clean assertion. Planes bridge **only** by subprocess or a signed,
   inert file spool — never a shared live handle. `envs/build_envs.sh` fails loudly with `SOVEREIGNTY
   VIOLATION` if the sovereign env can even *import* offense code. Deep dive:
   [`knowledge/kb/two-env-boundary.md`](knowledge/kb/two-env-boundary.md).

2. **Oracle authority.** Only a **fired deterministic oracle** over **executor-captured, non-LLM bytes**
   mints a signed FACT. The mint point is
   `integration/vigil_integration/oracle_adapter.py:confirm_and_certify()` — it returns a `fact` only when
   the bug class is oracle-*mapped* **and** the oracle fires **and** `provenance ∈ {reproduced,
   live_redrive}`; `provenance="llm"` (the default, i.e. context the model emitted) always stays a
   **LEAD**. The LLM, critics, RL, learning, reflection, and the graph only *advise / re-rank / defer /
   abstain* — **none of them ever promotes a claim.** Deep dive:
   [`knowledge/kb/verify-and-oracles.md`](knowledge/kb/verify-and-oracles.md).

3. **Gate of record.** Every target-touching action passes one conjunctive chain, **first-failure-wins**:
   `integration/vigil_integration/conjunctive_gate.py:build_offense_gate()` composes it and
   `packages/core/vigil_core/vigil_core/gate.py:conjunctive_decide()` evaluates it — WARDEN classify →
   signed-scope + never-liftable egress floor → kill-switch → capability latch → owner approval → m-of-n
   if destructive — and only then a signed, redacted `ExecRecord` is written to the spine by
   `integration/vigil_integration/live/executor.py:execute()`. Nothing self-authorizes; any error = deny.
   Deep dive: [`knowledge/kb/gate-of-record.md`](knowledge/kb/gate-of-record.md).

4. **Determinism + append-only.** No wallclock / RNG in oracle, graph, learning, or ledger math (those
   must be reproducible byte-for-byte). Secrets are sealed **off** the spine. **Never a public bind**
   (loopback or a private/tunnel IP only). Strict `'self'` CSP on every served surface. The spine is
   append-only and hash-chained; entries are added, never rewritten. Substrate:
   [`knowledge/kb/sovereign-plane.md`](knowledge/kb/sovereign-plane.md).

> The one-line mantra from the README: *the AI proposes, the oracle proves, the gates constrain, the
> signature attests — nothing else promotes a claim to a fact.*

---

## 1. Reading order — start here → then → then

> **Where is the build RIGHT NOW?** [`docs/CONTINUATION.md`](docs/CONTINUATION.md) is the durable resume doc —
> its **STATE** tables + the dated **Session log** at the top record exactly what is merged on `main`, the most
> recent completion wave, and the non-obvious lessons a resuming dev must not re-derive (the `CRUCIBLE_ROOT`
> location, the charter scope-table format, the bwrap unix-socket egress fix, how to re-verify an `engage`
> FACT offline, and why the Bash sandbox must be disabled for a network step). Read it first to orient, then
> come back here for the deep dives.

Read these in order. The first two give you the *what* and *why*; the KB pages give you the *how* per
subsystem; the memory narratives give you the *why it was built this way and which defects review caught*.

### Step 1 — the whole system, plain-language
- [`README.md`](README.md) — the canonical top-to-bottom tour: the governing invariant, the FACT-vs-LEAD
  split, the architecture diagram, every subsystem with its real repo path, setup, running it, the `vigil
  up` UI, the repo layout, and the honest live-vs-deferred status table. Read it fully once.

### Step 2 — the doctrine of the knowledge base itself
- [`knowledge/README.md`](knowledge/README.md) and [`knowledge/CONTRIBUTING.md`](knowledge/CONTRIBUTING.md)
  — what the `knowledge/` folder is (durable, committed, read back by SIGIL) and, critically, what it is
  **not**: *nothing in `knowledge/` is a fact.* Skills, KB docs, priors are leads/advisory; the graph
  counterparts stay `intel`/`ungrounded`. Committing a file makes nothing true. Pushing is the only
  outward-facing act and is always operator-gated (`vigil knowledge push`) — **no agent ever runs `git
  commit`/`git push`.**
- [`knowledge/kb/architecture.md`](knowledge/kb/architecture.md) — the compact prose map: the two planes,
  oracle authority, the projection-only knowledge graph, and the gate. Read this before any KB deep dive.

### Step 3 — the eight (nine) per-subsystem KB deep-dive pages
These are the living, per-subsystem developer pages. Read the one that covers what you are about to touch;
read all of them before you claim to own the system. All under `knowledge/kb/`:

- [`knowledge/kb/two-env-boundary.md`](knowledge/kb/two-env-boundary.md) — **invariant 1.** The `FATAL-2`
  boundary, the lazy-import rule, how the build proves it.
- [`knowledge/kb/verify-and-oracles.md`](knowledge/kb/verify-and-oracles.md) — **invariant 2.** The
  veracity layer (`engine/crucible/framework/v2/verify/`), what "an oracle fires" means, provenance.
- [`knowledge/kb/gate-of-record.md`](knowledge/kb/gate-of-record.md) — **invariant 3.** The conjunctive
  chain, WARDEN tiers, egress floor, kill-switch, capability latch, m-of-n destruction.
- [`knowledge/kb/sovereign-plane.md`](knowledge/kb/sovereign-plane.md) — SIGIL + `vigil_core`: the owner
  key, the signed spine, sealed secrets, the WARDEN kernel, the offense-free personal core.
- [`knowledge/kb/offense-engine.md`](knowledge/kb/offense-engine.md) — CRUCIBLE (`framework/v2`): the
  crawl → attack → oracle-confirm → world-model → evidence pipeline, and AEGIS the defensive dual.
- [`knowledge/kb/live-layer.md`](knowledge/kb/live-layer.md) — the `vigil` super-CLI, the attestation-first
  OODA engine (`live/engine.py`), the governed executor, the six live connectors, and `vigil up`.
- [`knowledge/kb/console-and-ui.md`](knowledge/kb/console-and-ui.md) — the one-origin unified web UI, the
  stdlib reverse proxy that federates the two planes, and the screens.
- [`knowledge/kb/knowledge-engine.md`](knowledge/kb/knowledge-engine.md) — the self-evolving vuln-intel
  engine (K1–K6): feed → propose → owner-accept → deep-learn find/detect/prevent → gated self-evolve.
- [`knowledge/kb/proof-studio.md`](knowledge/kb/proof-studio.md) — Strix PoC → oracle-confirmed signed
  replayable FACT → client-verifiable **offline** bundle.

*(The README/ADR say "8 new pages"; there are in fact **9** committed here — `verify-and-oracles.md` is the
ninth. Read all nine.)* The pre-existing [`knowledge/kb/architecture.md`](knowledge/kb/architecture.md) is
the index above them.

### Step 4 — the program narratives (why it was built this way, and the defects review caught)
- [`docs/knowledge/memory/MEMORY.md`](docs/knowledge/memory/MEMORY.md) — the index to ~29 persistent-memory
  files that are the **complete build history + hard-won lessons** of the three source systems VIGIL fuses:
  - `sigil-phase0..9-*.md`, `sigil-production-hardening.md`, `sigil-spine-rotation.md`,
    `sigil-hardprune-program.md` — the sovereign spine, Rust WARDEN, agent mesh, voice, embodiment.
  - `anti-hallucination.md`, `intel-engine.md`, `nervous-system.md`, `enterprise-platform.md`,
    `speed-program.md`, `unified-autonomy-program.md`, `coverage-/credibility-/pcf-forge-/gap-closure-/
    prover-to-discoverer-program.md`, `crucible-beyond-sota-program.md`, `crucible-testing-and-gotchas.md`,
    `ops-console.md` — CRUCIBLE's oracle authority, veracity firewall, and every merged program + gotchas.
  - `aegis-runtime-defense-frontier.md` — AEGIS (the defensive dual; the dual-review bar).
  - **These are load-bearing.** They record *why* each design decision was made and *which defects the
    adversarial review caught each slice* — the discipline you must keep. Do not re-derive; read them.
- [`docs/knowledge/constitution-obsidian.md`](docs/knowledge/constitution-obsidian.md) — the OBSIDIAN
  operating constitution the offense side inherits (authorization, scope, the OODA loop, honesty rules).
- [`docs/knowledge/README.md`](docs/knowledge/README.md) — points further to `docs/CONTINUATION.md`,
  `docs/PLAN.md`, and `docs/research/FRONTIER.md` for the approved architecture and the frontier survey.

### Step 5 — the decisions (ADRs) that bind current work
- [`knowledge/decisions/0001-knowledge-and-embodiment-program.md`](knowledge/decisions/0001-knowledge-and-embodiment-program.md)
  — the accepted program that produced the current KB, permanent sessions, the per-session Neo4j graph +
  session-connect, SIGIL voice/gesture/HUD, agent-to-agent messaging, and the gated self-evolving knowledge
  engine. Its "Consequences / invariants preserved" section is the contract every new slice honors: the
  two-env boundary and oracle authority hold at every seam; the graph is projection-only; self-evolve is
  gated + honest (learned knowledge is leads/skills/priors, never a fact). New ADRs go here, numbered.

---

## 2. Environment setup — the two venvs (the single most important operational fact)

VIGIL is **not one environment.** The offense-free guarantee is *enforced* by two Python environments that
never share an interpreter.

```bash
git clone https://github.com/thuram-nana/vigil-sovereign.git vigil && cd vigil
bash envs/build_envs.sh      # builds BOTH venvs and VERIFIES the boundary
```

`envs/build_envs.sh` creates:

| venv | key? | installs | is |
|---|---|---|---|
| `.venv-sovereign` | **owner key** | `vigil_core` + `apps/sigil` + `integration` | SIGIL: voice, gesture, owner-signed broker, memory graph |
| `.venv-offense` | **keyless** | `vigil_core` + `engine/crucible` + `vendor/strix` + `gateway` + `integration` | CRUCIBLE: crawl, oracles, world-model, the `vigil` CLI |

The script then **asserts the boundary**: it runs the sovereign interpreter and fails with `SOVEREIGNTY
VIOLATION` if any offense module (`framework.*`, `strix`, …) is importable there. Building the sovereign env
compiles the **Rust WARDEN kernel** (`apps/sigil/kernel/`), so `rustc` + `cargo` must be present.

Prereqs: **Linux** (Kali is the reference), **Python 3.13** (CI pins it), **Rust** (sovereign side), and
optionally docker (sidecars: Neo4j/OTEL), nftables+root (full gateway netns test), the Kali tool suite
(`nmap`/`nuclei`/`httpx`/`ffuf`/`sqlmap`/`hydra`), and `ANTHROPIC_API_KEY` (live Claude step; otherwise a
keyless "replay" runs and *the provable layer never depends on the model*).

---

## 3. Build / test / CI workflow — the 6 CI jobs

CI (`.github/workflows/ci.yml`) runs **six jobs on Python 3.13**, one per trust seam. Run the matching
commands locally before you push. The key discipline: **framework (offense) and `sigil.governor` (sovereign)
tests run in separate processes** — running them in one process trips the `assert_no_offense` boundary
check (which is the boundary *working*).

| # | Job (`ci.yml`) | Covers | Local command |
|---|---|---|---|
| 1 | `vigil-core` | shared signed core: v1 byte-identical signing, threshold, tamper | `pip install -e packages/core/vigil_core pytest` then `pytest packages/core/vigil_core/tests -q` |
| 2 | `crucible-core` | offense engine: evidence, verify, worldmodel, confidence, authority, console/api, knowledge_engine | `cd engine/crucible && PYTHONPATH=. pytest framework/v2/{evidence,entitlement,common,verify,confidence,worldmodel,calibration,authority,console,api,report,knowledge_engine} -q` |
| 3 | `gateway` | egress gate: denylist, proxy socket refusals, nft render + netns ruleset load | `PYTHONPATH=gateway python -m pytest gateway/tests -q` |
| 4 | `integration` | **two-env boundary**, inert receiver, keyless worker, oracle adapter, live engine, scoped executor, proof suite — **run in two processes** (sovereign-path suite ignores the framework-dependent tests; those run with `engine/crucible` on the path) | see `ci.yml` lines ~97 and ~110 for the exact two invocations |
| 5 | `strix-vigil` | Strix Claude runtime: Anthropic price table + reasoning + dedup fallback | `PYTHONPATH=vendor/strix python -m pytest vendor/strix/tests_vigil -q` |
| 6 | `sigil-governor` | SIGIL governor: offense gate, hardening, finding receiver (two-anchor ingest), capabilities, spine seal, UI, voice/gesture/HUD nav, knowledge grants | `PYTHONPATH=apps/sigil:integration python -m pytest apps/sigil/tests/<listed> -q` |

The exact, copy-pasteable per-component command list is also in [`README.md`](README.md) §Setup and is the
authority; `ci.yml` is the machine source. When you add a test, add it to the job for its trust seam — never
cross a framework-dependent test into the sovereign-path process.

---

## 4. Repository layout — where every subsystem lives

```
vigil/
├── packages/core/vigil_core/   Shared signed core — hash-chain, canonical JSON, Ed25519, trust root,
│                               and gate.py:conjunctive_decide (the gate evaluator). Imports NO offense code.
├── apps/sigil/                 SIGIL — offense-free personal core + the Rust WARDEN kernel (kernel/).
├── engine/crucible/            CRUCIBLE offense engine + AEGIS defensive dual — framework/v2/{verify (oracles),
│                               veracity, worldmodel, evidence, authority, aegis, knowledge_engine, intel, …}.
├── vendor/strix/               Strix — vendored, Claude-migrated autonomous AI-hacker (Apache-2.0).
├── gateway/                    Host egress firewall + scope-checking proxy (network-layer scope, denylist).
├── integration/               The fusion body (F0–F12) + the live engine + the `vigil` CLI.
│   └── vigil_integration/
│       ├── agent/ safety/ tools/        reasoning loop · untrusted-input boundary · governed tools
│       ├── conjunctive_gate.py          build_offense_gate — composes the gate of record (invariant 3)
│       ├── warden_gate.py destruction_gate.py challenge_oracle.py   tiers · m-of-n · fresh challenges
│       ├── oracle_adapter.py            confirm_and_certify — the FACT mint point (invariant 2)
│       ├── offense_worker.py inert_finding.py   the keyless worker + the inert cross-plane seam
│       ├── graph/ fireteam/ chainast/ gauntlet/ fsjob/ remediation/ observability/ kb/
│       ├── attestation/ detection/ autopatch/   usage record · Detection Mirror (AEGIS) · gated auto-patch
│       ├── transparency.py scitt.py     witnessed log + offline-verifiable certificates
│       ├── live/                        engine.py, wiring.py, executor.py (execute), + connectors
│       │                                (graph_neo4j, gauntlet_subproc, otel_export, think_claude,
│       │                                 spine_vigilcore) — the unified running engine
│       └── cli.py                       the `vigil` command (engage · ledger · verify-ledger · provision · up)
├── knowledge/                  Living KB (kb/), system-map/, skills/, decisions/ (ADRs), sessions/ — see §1.
├── docs/                       README-linked deep docs: AS-BUILT(-LIVE), PLAN, CONTINUATION, architecture/,
│                               research/, and knowledge/memory/ (the program narratives, §1 step 4).
├── infra/                      The loopback target (loopback/vulnapp.py) + sidecar configs.
├── targets/                    Engagement charters (the authorization documents — read before any run).
├── envs/                       The two isolated venvs + build_envs.sh (the boundary-verifying build).
└── packages/vigil-ui/          The no-build static UI bundle served by `vigil up`.
```

Map from invariant → code owner: (1) `envs/build_envs.sh` + every lazy `framework` import; (2)
`oracle_adapter.py:confirm_and_certify` + `engine/crucible/framework/v2/verify/`; (3)
`conjunctive_gate.py:build_offense_gate` → `vigil_core/gate.py:conjunctive_decide` →
`live/executor.py:execute`; (4) `vigil_core` (spine/canonical/Ed25519) + `gateway/` (egress) +
`apps/sigil` (sealed secrets, kernel pin).

---

## 5. How to continue the work safely — the standard

- **Every slice: `build → adversarial red-pen → re-check on the fixed branch → CI green → merge.`** This is
  the discipline the memory narratives record (dual review caught a real defect *every* slice — see
  `docs/knowledge/memory/`). Do not skip the independent adversarial pass; near-zero-FP claims cannot be
  self-certified by one reviewer.
- **Touching `framework.v2` from a shared `integration` module?** Import it **lazily** (function-local),
  or you break invariant 1 and the sovereign-path CI process. There is no exception.
- **Adding a "detector"?** It is a real oracle only if it is deterministic (no clock/RNG/network in its
  decision math) and fires over target-produced non-LLM bytes. Anything an LLM judged is a **LEAD**,
  forever — map it via `oracle_adapter`, never assert it.
- **Adding a target-touching action or tool?** It must go through `build_offense_gate` /
  `conjunctive_decide` and end in a signed `ExecRecord`. Nothing self-authorizes; fail-closed on any error.
- **Adding to `knowledge/`?** It is advisory. Its graph counterpart stays `intel`/`ungrounded`. Never let a
  KB page, skill, or prior become the thing that promotes a finding. Commit/push are operator-only.
- **When in doubt, prefer fail-closed:** unknown tool → strictest WARDEN tier; missing gate → deny;
  malformed input → safest action; approval timeout → reject; telemetry/graph crash → cannot affect truth.

---

## 6. Gotchas the next engineer will hit

- **"SOVEREIGNTY VIOLATION" on build** = a top-level `import framework...`/`strix` leaked into a sovereign-
  reachable module. Make it lazy. This is the boundary doing its job, not a build bug.
- **CI job 4/6 fails only when run together** = you co-loaded framework + sigil in one process. Split them
  (see `ci.yml`); the two-process split is intentional.
- **A finding shows as LEAD you expected to be FACT** = usually `provenance="llm"` (the default) or an
  unmapped bug class. Check `oracle_adapter.py:confirm_and_certify` — provenance must be `reproduced`/
  `live_redrive` **and** the class must be oracle-mapped.
- **No `ANTHROPIC_API_KEY`** is fine — engagements run keyless "replay" and still attest-first, gate,
  oracle-confirm, and sign. The provable layer never depends on the model. Never fabricate activity to
  paper over a missing key.
- **Never a public / `0.0.0.0` bind** — `vigil up` refuses it; keep it that way. Loopback or private/tunnel
  IP only, strict `'self'` CSP.
- **`system-map.json` is generated** — never hand-edit it; edit `knowledge/system-map/screens.yaml` and run
  `knowledge/sync.sh` (CI drift-checks it against the UI).
- **The live end-to-end validation is on a loopback target** (`127.0.0.1`), not "in the field" — keep the
  honest live-vs-deferred distinction in [`docs/AS-BUILT-LIVE.md`](docs/AS-BUILT-LIVE.md); overclaiming here
  would be the exact hallucination this system exists to kill.

---

*You are inheriting an anti-hallucination system. The highest form of respect for it is to be as honest in
your commits as it is in its findings: prove, don't guess; label a lead a lead; and keep the four invariants
true at every seam.*
