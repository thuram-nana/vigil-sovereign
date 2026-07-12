# V2-LIMITATIONS

Honest accounting of where CRUCIBLE v2 falls short, where it depends
on external state, and where a determined adversary could trip it
into producing wrong or misleading output. Read this before you trust
the framework with anything that matters.

Per FORGE PROTOCOL § 4.10, the worst possible outcome is shipping
a framework that lies about its own completeness. So this document
lists every limitation we could identify; if you find one we missed,
add it here.

---

## 0. RECONCILED to `main` @ 649b530 (2026-07-11) — read this before the older sections

> The numbered sections below (§§ 1–27) were written across FORGE-PROTOCOL
> Sessions 1–8 and the "Wave 1 (2026-07-02)" hardening — **before** the
> *Unified Provable Autonomy* program (Waves 1–7) and the **AEGIS MVP** merged.
> Their per-subsystem risk notes remain broadly accurate for the subsystems they
> cover, but the *inventory* is stale. This section reconciles the honesty ledger
> to the actual tree at **`main` @ `649b530` (2026-07-11)** and is authoritative
> where it conflicts with the older text. Verify against code, not prose.

**What is now merged to `main`** (all verified against the tree): Waves 1–7 of
the Unified Provable Autonomy program and the AEGIS MVP. Concretely — the
nervous system wired advisory-only into `engage --spine` (W1); the Universal
Sensor/Producer framework + Nmap/tshark/web-scanner(Nuclei/ZAP/Burp)/cloud-IAM/
SBOM sensors (W2–W5); the `service_reachability`, `tls_weakness`, `version_range`,
and `policy_path` oracles (W2–W5); the in-house web arsenal + gated repeater
(W4); threat-intel ingest + the defense/IR purple-team pass (W5); the plugin/
capability registry, MCP tool-server (expose + consume), gated loopback API +
external-tool importers, and report automation (W6); consolidation/hygiene (W7);
and `aegis/` — the embeddable **defensive** AI-attack-detection library + the
inline **provable firewall** (request-side SQLi/cmd-injection block oracles,
response-side XSS/SSTI/path-traversal confirmation reusing the existing
`EVALUATION`/`SIDE_EFFECT` oracles, and a per-actor graduated challenge/throttle).
`verify.OracleKind` is now **24 members**: the **15** frozen offensive oracles
(the benchmark set, unchanged) **+ 9 additive members held OUT of the frozen
`_ALL_ORACLES`** (4 AEGIS detection, 2 AEGIS gateway request-side block oracles,
1 `K8S_POSTURE` sensor-fusion, 1 `SSO_ASSERTION_FORGERY` offline JWT structural-
forgery oracle, 1 `SAML_STRUCTURAL_FORGERY` offline SAML structural-forgery oracle)
— each fires only on a context key no benchmark finding carries, which is *why* the
gate stays byte-identical. AEGIS is also now **pip-installable + Docker-shippable**
(a repo-root `pyproject.toml` delivers an importable `framework.v2` + `crucible`/
`aegis` console scripts; `framework/v2/aegis/Dockerfile` runs the observe-default
gateway), and `engage --fuse-sensors` **auto-activates** when a `targets/<slug>/
fusion.json` manifest is present (default path byte-identical when it is absent). AEGIS emits **in-band XXE as a lead,
never an inline block** — the adversarial review proved a single inline exchange
cannot soundly confirm it (a reflected `/etc/passwd` example on a paste/docs page
would false-positive), so it joins blind XXE and all SSRF as belief-raising leads.

**The gate is unchanged and byte-identical.** `python3 -m framework.v2 benchmark
--gate --no-incumbents` → `crucible 9/0/0`, f1 `1.000`, 853 requests, 9 findings,
**PASS**. It scores **9 single-class findings against one in-process benchmark
app** — a false-positive/regression ruler, not a coverage claim. `make test`
(the full offline suite, 248 test files) stays green.

### The limitations that STILL hold at this commit (the honest core)

1. **The autonomous planner is now REACHABLE but still not an at-scale loop.**
   Two opt-in entrypoints now drive the planner (previously it was constructed
   only in tests): `python3 -m framework.v2 plan <slug>` projects the planner's
   crown-jewel routes + next action (greedy AND depth-2 lookahead) over a prior
   `engage --spine` engagement's world-model — a **read-only projection that
   sends no traffic and drives no tools**; and `engage --autonomous-lookahead`
   runs a bounded depth-2 beam (over the goal-tree/belief graph) driving only the
   gated `reverify_finding` / `service_reachability` tools. Default `engage`
   still runs the scanner campaign + oracle confirmation + world-model chaining,
   **not** the goal-tree planner. The at-scale, real-target, finding-discovering
   autonomous loop is **still not proven** — the one conservative real-target run
   (mrbeanpanel, 2026-05-05) emitted **0 findings**, and the lookahead ships as a
   reviewed depth-2 first slice, not proven frontier autonomy.
2. **The reasoning nervous system runs ONLY under `engage --spine`, advisory-only.**
   `_run_reasoning_pass` (`engage.py:371`) fires the multi-critic panel,
   reflection, cognitive refusal, `credit_outcome` fan-out and meta-monitor
   **iff** the spine is attached, and it can only mirror onto the spine and
   re-rank/defer — it **never** promotes/demotes a finding or drops a surface;
   the oracle stays the sole authority. Default `engage` (no `--spine`) and the
   gate do not run it.
3. **The Wave 2–5 sensors are NOT wired into the DEFAULT `engage`/`scan` path —
   only behind an opt-in flag.** The default path still imports zero `sensors`
   (the gate stays byte-identical). An opt-in `engage --fuse-sensors` flag now
   folds the offline sensor **leads** into the run world-model and promotes those
   its oracles can honestly confirm — the new `verify.k8s_posture` oracle turns a
   retained kube-bench control into a `k8s_misconfiguration` **FACT** (read-only;
   never drives kubectl / touches the API server), and the Wave-2 reachability
   oracle can confirm a `declared_service` open port via a gated, scope-checked
   handshake. Absent the flag, sensors remain reachable only via the
   `mcp`/`capabilities`(registry)/`imports`/`intel` subcommands or the direct
   API. The `--arsenal` flag wires the scanner's **in-house** arsenal, not the
   third-party sensor adapters. The one sensor the *default* `engage` reaches is
   the defender log-source, behind the opt-in `--defender-log` flag.
4. **`defender/gap_report.py` is wired only into the opt-in `--defender` pass**
   (`_run_defender_pass`, `engage.py:247,635`) — not the default loop. (Earlier
   text calling it "built but unwired" was an *under*-claim; it is wired, but
   opt-in.)
5. **The gate proves precision on a narrow surface.** 9 findings / 1 in-process
   app. It cannot and does not demonstrate breadth, autonomy, or real-target
   discovery.
6. **~27–30 of 41 test skip-markers require an external live tool / headless
   browser / live-LLM backend / live network** (nmap, tshark, nuclei, semgrep,
   joern, docker+CVE images, Chromium/CDP, `CRUCIBLE_LIVE_*`, `claude`). They are
   skipped in a stock offline environment; the offline suite is otherwise green.
7. **Whole attack surfaces are ABSENT as v2 exploitation code** — present at most
   as v1 markdown playbooks and/or passive fingerprint labels, never as active
   capability: **mobile** (Android/iOS), **Kubernetes-runtime / container-escape**,
   **microservices/service-mesh exploitation**, **SSO/SAML/OIDC exploitation**
   (no assertion-forgery / golden-SAML / JWT-forge oracle), **post-exploitation /
   lateral movement / persistence**, **data-exfiltration execution**, and
   **incident-response pivot**.
8. **No ML / numeric / SMT runtime.** Base deps: `pydantic, structlog, httpx,
   requests, PyYAML, beautifulsoup4, Jinja2, cryptography` (+ `pytest-httpserver`,
   test-only). No numpy/scipy/scikit-learn/torch/tensorflow/z3; the confidence/
   calibration/SCE math is hand-rolled stdlib. `anthropic`,
   `sentence-transformers`, and `semgrep` are **optional extras** with guarded
   imports and graceful degradation — reasoning quality without a live LLM is
   bounded (DryRun returns deterministic fixtures).
9. **The doctrine exclusions are DELIBERATE, not missing features.**
   Detection-evasion, C2 / persistence, full exploitation frameworks,
   credential-attack suites, and identity-rotation are **excluded from the
   reasoning engine by policy** (correlatable, not anti-defender — README §10).
   AEGIS is defensive-only: default `mode="observe"` is read-only and it never
   attacks.

**Last reconciled:** `main` @ `aa89a49`, 2026-07-12 (reconciled after the
3-workstream program — AEGIS depth, autonomy-loop first slices, opt-in sensor
fusion — landed as **reviewed, opt-in, gate-byte-identical** slices; items 1–3
updated to reflect the new opt-in reach). Regenerate drifting counts from the
tree.

### The 13-workstream program — since LANDED (this section was stale)

**Superseded (2026-07-12).** This section previously read "In-flight … NOT shipped
… not merged to `main`" and described only `649b530`. That is **358 commits stale**
and now *under*-states reality — the exact honesty failure this ledger exists to
prevent. Most of the 13-workstream opt-in capabilities have since merged to `main`
(e.g. `framework/v2/sensors/fuzz.py`, the engage hooks, SARIF/authn, IPv6, client-
side + k8s), followed by the AEGIS MVP + Gateway and the 3-workstream program
(AEGIS depth · autonomy loop · sensor fusion). The honest-core items above are the
current truth, reconciled at `aa89a49` (2026-07-12); consult `git log` for each
program's merge commits rather than treating any single frozen SHA as "now".

---

## 1. Subsystem inventory — DAA/DEL/SIL now ship (this section was stale)

**Corrected Wave 1 (2026-07-02).** This section previously stated that
DAA, DEL, and SIL "do not exist on disk." That is no longer true — all
three shipped in later sessions and are code-complete + module-tested
(offline). See the manifest table (rows 6/7/8) and §§ 20–22 below:

- **DEL** — `framework/v2/defender/` ships the defensive telemetry /
  self-detection subset (§ 21). No evasion generation, by policy.
- **DAA** — `framework/v2/analysis/` ships the offline pattern analyzer
  plus Semgrep taint and optional Joern CPG adapters (§ 22).
- **SIL** — `framework/v2/improve/` ships the reviewer / horizon /
  patcher / gated-merge loop (§ 20).

What remains honest to say about the whole loop:

Headlining the framework as XBOW-or-Big-Sleep-class is still incorrect.
The planner-and-agents loop has been exercised end-to-end under a live
LLM only against **fabricated executor evidence** (`RealisticExecutor`
fixtures — see § "MAO+ACP graduation" below), and the one real-target
run (mrbeanpanel, 2026-05-05) emitted **0 findings**. The subsystems
exist; the at-scale, real-target, finding-discovering autonomous loop
does not yet.  See § 0 below.

## 0. Live-LLM-path risk — Session 3 verification update

Session 3 of the FORGE PROTOCOL exercised every URK binding live
via the new `ClaudeCodeBackend` (operator's Claude Max routed
through `claude -p` subprocess; `kernel/backends/claude_code.py`).
The Session-1/2 risk that "URK live paths are unexercised" is now
**discharged for the binding layer** with the caveats below. UTI
and the planner-driven pipeline have been exercised end-to-end;
MAO+ACP graduate to **partial — see § "MAO/ACP live-path note"**
in the manifest.

Total Session 3 spend: ~$1.78 against the operator's $5 cap.

### Per-binding verification status (was: checklist; now: results)

1. **`hypothesize`** — **VERIFIED** (Session 3, claude-code/haiku, 50.6s, ~$0.10)
   - 5 hypotheses returned, `doctrine_compliant=True`.
   - 5 distinct bug classes (IDOR, auth-bypass, cache-poisoning,
     mass-assignment, race) — diversity satisfied.
   - Schema validation passed via `--json-schema` server-side and
     re-validated by Pydantic client-side.
   - Fixture: `framework/v2/kernel/tests/fixtures/live-run/01-hypothesize.json`.

2. **`critique`** — **VERIFIED, with operational note**
   - Rubber-stamp trap (Session 3, hedged claim "I think there
     might be an IDOR somewhere..."): decision=`objections`. PASS.
   - Blanket-objection trap (Session 3, strong-PoC claim with rich
     evidence chain): decision=`confirm`. PASS, but only after a
     first attempt with thin evidence returned `objections`.
   - **Operational note:** live critique-agent is genuinely
     senior-engineer rigorous. It does not rubber-stamp; it
     demands evidence proportional to the claim. Findings whose
     `summary` is rich but whose `parent_id` evidence chain is
     thin will return `objections`. This is correct behaviour.
     Implications for the deterministic test harness are noted in
     "MAO/ACP live-path note" in the manifest.
   - Fixtures: `02a-critique-hedged.json`, `02b-critique-strong.json`,
     `02b-critique-strong-retry.json`.

3. **`threat_model`** — **VERIFIED** (Session 3, claude-code/haiku, 228s, ~$0.18 — required budget bump)
   - 8 assets / 4 actors / 9 trust boundaries / 32 STRIDE threats /
     5 catastrophic outcomes against the Session-3 sample input.
   - Output is archetype-specific (names PHP-Smarty cookies,
     SMM-panel money flows, PSP webhook surfaces). Comparable in
     coverage to the hand-written reference threat-model archived
     under `targets/.archive/`; slightly less complete on operator-
     credential vectors and refresh cadence.
   - **Initial failure** at default `--max-budget-usd 0.10`:
     subprocess hit `error_max_budget_usd` after 178s. Default
     bumped to `$0.20`; passes consistently at that cap.
   - Fixture: `06-threat-model-retry.json`.

4. **`pivot`** — **VERIFIED** (Session 3, claude-code/haiku, 69.5s, ~$0.10)
   - 5 lateral moves with 5 distinct kinds (class, layer, source,
     surface, tool). `recommended=0` in range. PASS.
   - Fixture: `03-pivot.json`.

5. **`decide`** — **VERIFIED** (Session 3, claude-code/haiku, 64.9s, ~$0.10)
   - Severity=Critical, cvss_base=10.0, regulator_paragraph
     populated, immediate_surface_to_operator=True. All schema
     enums respected.
   - Fixture: `04-decide.json`.

6. **`opsec`** — **VERIFIED** (Session 3, claude-code/haiku, ~10s × 4 calls, ~$0.10)
   - All four § 7 absolutes (real-money movement, real-user
     contact, third-party attack, destructive cleanup) returned
     `allowed=False`. The load-bearing gate holds against haiku.
   - Fixture: `05-opsec-section7.json`.

### UTI live drafter — VERIFIED

UTI's `intake/drafters.py::draft_threat_model` was exercised live
in Session 3 against an operator-authorised target (now archived
under `targets/.archive/`):

- 173s wall-clock, 9 HTTP requests against the real target (under
  the 12-request budget cap from the engagement charter).
- Archetype: `php-smarty-smm-panel-fork` (score 0.75) — same
  classification Session 1 confirmed.
- Threat-model output: 208 lines, marker line `Drafted by URK
  from a live LLM call` confirms the URK path executed (not the
  skeleton fallback).
- Captured under `framework/v2/intake/tests/fixtures/live-run/`
  (regression captures retained).

### Backend-specific findings (new)

#### `ClaudeCodeBackend` — added in Session 3

Implementation: `framework/v2/kernel/backends/claude_code.py`.
Routes URK calls through the operator's Claude Code installation
via `subprocess.run(["claude", "-p", ...])`, using `--system-prompt`
to replace the default agent prompt, `--json-schema` for server-
side schema validation, `--model haiku` (default), and
`--max-budget-usd` per-call cap.

Findings from Session 3 live use:

- **Floor cost is ~$0.04 per call**, not $0.00. Even with
  `--system-prompt` replacement, Claude Code loads ~28k cache-
  creation tokens of internal context (haiku-4-5 cache creation
  $1.25/Mtok = ~$0.035 floor). Heavier bindings like
  `threat_model` need ~$0.18.  Default `_DEFAULT_PER_CALL_BUDGET_USD`
  bumped to `$0.20` to fit threat_model comfortably.
- **`--bare` mode is incompatible with OAuth/Max subscription.**
  Help text says: *"Anthropic auth is strictly ANTHROPIC_API_KEY
  or apiKeyHelper via --settings (OAuth and keychain are never
  read)."* So `--bare` cannot be used with the Max subscription
  path. Mitigation in the backend: explicit `--disallowed-tools`
  list of every Claude Code built-in (Bash, Edit, Read, Write,
  Grep, Glob, Task, WebFetch, ...) plus
  `--disable-slash-commands`. Without those, the agent enters
  `tool_use` turns and burns budget before responding.
- **Subprocess timeouts:** haiku `threat_model` runs ~3-4 minutes.
  Default timeout was 60s → bumped to 240s → bumped to 360s after
  one timeout in pipeline context.  Override via
  `CRUCIBLE_CLAUDE_CODE_TIMEOUT`.
- **Model selection:** `--model haiku` works for every binding.
  Did not test sonnet/opus this session; either should work but
  cost ~5× / ~25× more respectively.
- **Structured output extraction:** Claude Code's JSON envelope
  has `structured_output` (a parsed dict) when `--json-schema`
  is used. The backend prefers this over `result` text since
  schema validation is already done server-side.

#### `AnthropicBackend`

Still **NOT live-exercised**. ANTHROPIC_API_KEY was not provisioned
this session (operator had Max but not API credits); the chat-
exposed key from earlier in the session was burned by the harness.
The code path is unchanged; the per-binding behaviour observed
through ClaudeCodeBackend should transfer (the Pydantic schemas
and prompt templates are shared) but cannot be promised without
exercising the SDK path itself. Manifest column reflects this.

#### `OllamaBackend`

Still **NOT live-exercised**. No Ollama daemon installed.
First-use checklist from the prior version of this section
remains valid.

### MAO+ACP graduation criteria — UPDATED Session 4

Session 3 left MAO/ACP at "partial" because the deterministic test
harness produced thin Result objects.  Session 4 closed this with
`framework/v2/agents/realistic_executor.py` and a new
opt-in integration test
(`test_full_pipeline_url_to_report_live_realistic`).

Status against the original bar, Session-4 results:

- ✓ A real engagement target was used by UTI in Session 3 (now
  archived under `targets/.archive/`); the live full-pipeline test
  uses fixture-replay intake against `https://fix-target.invalid`
  plus `RealisticExecutor` for the exploit path.  No real attack
  traffic at the executor layer in the live test; only UTI hits a
  real host.
- ✓ At least one finding survived critique-agent's veto end-to-end:
  **achieved — but on synthetic evidence.**  The strong-evidence
  webhook-forgery scenario's finding was confirmed by live
  critique-agent and emitted by the reporter to `technical.md`. The
  evidence critiqued was `RealisticExecutor` **fabricated fixture
  data**, not a real request against a real target.
- ✓ At least one finding was blocked by critique-agent: the
  weak-evidence robots.txt scenario's finding was rejected by
  live critique-agent and is absent from the report.  Gate still
  discriminates.
- ✓ MLS recorded the confirmed finding with `bug_class=webhook-forgery`.
- N/A Watchdog halt on a real condition: did not fire in the run
  (the planner halted on `max_steps=30` per the test budget);
  remains verified from Session 2.
- ✓ Cost telemetry from `CallTrace` non-zero: ~$0.55 for this run
  on top of ~$1.78 from Session 3.  Total live-URK spend across
  Sessions 3+4 stays under $3.

MAO and ACP graduate to **`partial (live URK, synthetic executor
evidence)`** on the manifest — NOT an unqualified `yes`. The live-URK
critique loop is verified end-to-end and discriminates strong from
weak claims; what is NOT verified is confirmation of a finding backed
by real target evidence. See `V2-MANIFEST.md` "MAO/ACP live-path
graduation — Session 4" for the verbose narrative and its honest
qualifier.

What is **still NOT verified live**:

- ~~Real engagement against a real attackable target with a real
  exploit-running executor (rather than a synthetic harness).~~
  **Session 8.5 closed this — first real engagement against
  `mrbeanpanel.com` (operator's production SMM panel) ran end-to-end
  on 2026-05-05.** 15 GET requests, 0 scope violations, 0 destructive
  refusals, 0 findings emitted. Halted cleanly on `max_steps=15`.
  Run shape was deliberately conservative (50 / $2 / 1800 s budget,
  GET-only via destructive-deny). The framework's PLUMBING is now
  verified against a real target; FINDING-DISCOVERY at scale awaits
  a second engagement that approves destructive-action probes on
  the test accounts. See [`targets/mrbeanpanel/POST-ENGAGEMENT.md`](targets/mrbeanpanel/POST-ENGAGEMENT.md).
- The `mixed`-evidence scenario (timing-side-channel) was not
  picked up by the planner during the captured run — only the
  strong + weak scenarios fired.  The mixed scenario's behaviour
  under live critique remains tested only at the binding-unit
  level (Session 3's `02b-critique-strong-retry.json` is the
  closest analogue).

### HttpExecutor live-network gap (Session 6 — partially closed by Session 8.5 run)

**Update 2026-05-05:** the first real engagement against `mrbeanpanel.com`
ran cleanly under the reduced shape (GET-only, 15 requests, 0
violations). The plumbing-level gap is closed; the
finding-discovery-at-scale gap remains — see
[`targets/mrbeanpanel/POST-ENGAGEMENT.md`](targets/mrbeanpanel/POST-ENGAGEMENT.md)
§ 5 for issues surfaced during the run (UTI slug-collision with the
operator's pre-existing engagement folder, planner Cartesian-product
seeding, recon-agent not wired into the live pipeline). These become
the next FORGE session's priority list.

What ships:

- `framework/v2/agents/http_executor.py` — `HttpExecutor` conforming
  to the same `Executor` protocol as `DeterministicExecutor` and
  `RealisticExecutor`. Issues bounded HTTP via `httpx` with full
  evidence capture (request + response archived, redirect chain,
  body excerpt, structured event log).
- `framework/v2/agents/scope_gate.py` — pre-flight validator that
  wraps `common.ethics` primitives into a typed `ScopeDecision`.
  Charter signature, scope, destructive classifier all live here.
- 22 unit tests at `framework/v2/agents/tests/test_http_executor.py`
  exercising every gate against `pytest-httpserver`.
- Opt-in integration test `test_full_pipeline_url_to_report_live_http`
  gated on `CRUCIBLE_LIVE_HTTP=<url>`.

What's not yet exercised:

- An end-to-end run against a real authorised target. Requires
  the operator to prepare an engagement (UTI scaffold, signed
  charter, ledger attestation) and set `CRUCIBLE_LIVE_HTTP=<url>`.
- Request derivation today only covers GET-by-default with a
  `METHOD /path` prefix in `hypothesis.surface`. Bodies, custom
  headers, multi-step request chains will need a richer derivation
  layer (or operator-supplied request templates) before HttpExecutor
  exercises the full attack surface.
- Posture detection is a checkbox parser on charter § 7. If the
  charter's posture section is missing or malformed, HttpExecutor
  defaults to TEST, which is the safe default but may surprise
  operators who expected EMULATE behaviour.

### Substrate pluralism (Session 8)

**Tiered sovereignty model.** Session 7's binary strict/permissive
evolved into a four-tier ladder so most government deployments can
choose *jurisdictional* sovereignty (data residency, regional infra)
rather than pure-local — without giving up frontier reasoning quality.

| Tier | Backends permitted | Quality |
|---|---|---|
| `AIR_GAPPED` | Ollama / vLLM / llama-cpp / TGI / DryRun | Lower (local) |
| `SOVEREIGN_CLOUD` | + Bedrock / Vertex / Mistral | Frontier (Claude) or High (Mistral) |
| `TRUSTED_CLOUD` | + Anthropic-ZDR | Frontier |
| `PERMISSIVE` | + plain Anthropic / Claude Code | Frontier |

Tier set via `CRUCIBLE_SOVEREIGNTY_TIER=<name>`; legacy
`CRUCIBLE_SOVEREIGN_MODE=1` still maps to `AIR_GAPPED`. All Session
7 tests pass unchanged.

**Backends shipped — all four deferred-live this session:**

| Backend | Built against | Live-verified Session 8? | Verification cost |
|---|---|---|---|
| `BedrockBackend` | `anthropic.AnthropicBedrock` (no new deps; needs `boto3` for live) | **No** — AWS creds absent | $0 (mock) |
| `VertexBackend` | `anthropic.AnthropicVertex` (needs `google-auth` for live) | **No** — GCP creds absent | $0 (mock) |
| `MistralBackend` | httpx-direct against `api.mistral.ai/v1/chat/completions` | **No** — `MISTRAL_API_KEY` absent | $0 (mock) |
| `AnthropicBackend` ZDR variant | `CRUCIBLE_ANTHROPIC_ZDR=1` → registers as `anthropic-zdr` (trusted_cloud) | **No** — `ANTHROPIC_API_KEY` absent in this session | $0 (mock) |

**Honest framing for sovereign reviewers:**

- All four backends are code-complete and type-clean. Construction
  paths, region-allowlist enforcement, credential-resolution
  failure modes, and tier integration are exercised by 23 mock
  tests against fake SDK modules.
- The actual `complete()` round-trip against a real cloud endpoint
  has NOT been run from CRUCIBLE in Session 8. The Bedrock/Vertex
  paths use Anthropic's first-party SDK clients (`AnthropicBedrock`
  / `AnthropicVertex`) which Anthropic maintains — the failure
  modes most likely to surface are credential / quota / regional-
  availability errors, not API-shape errors. The Mistral path uses
  the documented chat-completions REST shape stable as of late
  2025; if Mistral's `response_format: {type: json_object}` field
  has changed, the parse will fail at first call.
- The operator runs the live verification on a host with the
  required credentials. The mock-test suite confirms: when those
  creds aren't present, the backend fails with a clear
  `BackendUnavailable` rather than crashing later.

**Open work (operator-roadmap):**

- Live verification of each backend on credentials-equipped CI.
- Verify Vertex region/model id format against Anthropic's current
  Vertex documentation — Vertex's prefix conventions for Claude
  model IDs evolve.
- Mistral `response_format` field stability check against the
  La Plateforme API reference.
- Update `framework/v2/kernel/tests/fixtures/sovereignty-comparison.md`
  with empirical numbers across all four substrates plus Ollama once
  credentials and a local Ollama deployment are available.

---

### Sovereignty substrate gap (Session 7)

**What ships:**

- `framework/v2/kernel/sovereignty.py` — `SovereigntyPolicy` refuses
  cloud backends at construction under `CRUCIBLE_SOVEREIGN_MODE=1`,
  reverses auto-selection to local-first
  (`ollama > vllm > llama-cpp > tgi > dryrun`).
- `framework/v2/agents/egress_guard.py` — `SovereignHttpxTransport`
  enforces an `EgressAllowlist` at runtime; off-allowlist hosts
  raise `SovereigntyViolation` before bytes leave the host.
- Source-level egress audit confirms zero "anything else" call
  sites in v2 production code; documented at
  [`framework/v2/SOVEREIGNTY-EGRESS-AUDIT.md`](framework/v2/SOVEREIGNTY-EGRESS-AUDIT.md).
- STRIDE-style self-threat-model at
  [`SOVEREIGNTY-THREAT-MODEL.md`](SOVEREIGNTY-THREAT-MODEL.md)
  covering prompt injection, MLS poisoning, planner-checkpoint
  tampering, supply-chain compromise, LLM-substrate compromise,
  and operator-credential leakage.
- Supply-chain attestation workflow:
  `framework/v2/requirements.in` (source spec),
  `framework/v2/requirements.lock.txt` (operator-regenerated),
  `framework/v2/sbom.json` (operator-regenerated CycloneDX 1.5),
  `bin/verify-supply-chain.sh` (CI verification, fail-closed).
- [`SECURITY.md`](SECURITY.md) at project root documents the trust
  delegation model, vulnerability reporting process, and a
  sovereign-deployment hardening checklist.
- 42 new tests pass (29 sovereignty policy + 13 egress guard).

**What's not yet done — operator-roadmap:**

- **Local-LLM quality verification.** Ollama not present on the
  Session 7 development host. The comparison harness at
  [`framework/v2/kernel/tests/fixtures/sovereignty-comparison.md`](framework/v2/kernel/tests/fixtures/sovereignty-comparison.md)
  ships with `<DEFERRED>` placeholders; the operator (or any
  sovereign-deployment evaluator) fills them by running the URK
  binding-verification suite against `qwen2.5-coder:32b` on an
  Ollama-equipped host. **No fake quality numbers shipped.**
- **Hash-pinned `requirements.lock.txt` and `sbom.json`.**
  Generation requires `pip-compile` and `cyclonedx-bom`, which
  this session's sandbox refused to install (correctly — it
  doesn't recognise them as in-manifest deps). Both files ship
  as structurally-correct *skeletons* with explicit
  `OPERATOR REGENERATES` markers. Sovereign deployments run
  `bin/verify-supply-chain.sh` (which installs the build-time
  tools and produces real artefacts) on their CI host.
- **Third-party security audit.** Not engineering work — operator
  roadmap.
- **Reproducible-build attestation.** Operator roadmap.
- **Institutional home.** Operator roadmap.

The framework is now a **credible candidate for sovereign use.** It
is not yet **ready for sovereign donation.** The remaining bars are
honest external-validation work, not code work.

---

## 2. URK is dry-run by default

If neither `ANTHROPIC_API_KEY` is set nor a local Ollama daemon is
running, URK falls back to `DryRunBackend`. DryRun:

- Writes the fully-rendered prompt to
  `framework/v2/.dryrun/<ts>-<schema>.txt` so the operator can
  audit what URK would have asked.
- Returns a deterministic `Pydantic` instance synthesised from a
  per-schema fixture provider in
  `framework/v2/kernel/backends/fixtures.py`.

The fixture providers are *not* an LLM substitute. They are
plausible-baseline output derived from the cognitive doc's own
worked examples plus a small static catalogue. Concretely:

- `hypothesize` returns a fixed 5-entry catalogue (IDOR /
  mass-assignment / race / SSRF / auth-bypass) surface-substituted
  from the input.
- `critique` heuristically picks `confirm` / `objections` /
  `more_evidence_needed` from keyword presence in the claim.
- `pivot` returns a fixed 5-entry lateral-move set.
- `decide` keyword-matches the finding summary to a CVSS pair.
- `opsec` keyword-matches the action summary against destructive /
  real-user-contact / heavy-traffic lists.
- `threat_model` returns a generic 3-asset / 3-actor / 2-boundary
  baseline.

The acceptance test for URK (§ 3.8) — "every cognitive document has
a function that, given a representative input, produces output
structurally consistent with what a careful operator would
produce" — passes via the DryRun fixtures, not via live LLM
reasoning. With a live backend the output quality should be
materially better; we did not measure that improvement quantitatively
in this session.

## 3. Ollama backend is untested in this environment

`ollama` is not installed on the development host, so the
`OllamaBackend` was implemented from the public Ollama HTTP API
docs and its `is_available()` probe was tested by polling
`http://localhost:11434/api/version` (returns `False, ConnectError`).
The actual call path against a running Ollama daemon was *not*
exercised end-to-end. Probable issues to check on first real use:

- Some Ollama versions expect `format: "json"` only on `/api/generate`,
  not `/api/chat`. The chat endpoint may emit prose around the JSON.
- Smaller models (qwen2.5-coder:7b, etc.) may fail the JSON-validity
  retry loop more often than the default `qwen2.5-coder:32b`.

## 4. Anthropic backend uses prompt-only structured output

The Anthropic backend asks the model to "respond with a single JSON
object validating this schema" and then parses with Pydantic. It
does not use Anthropic's tool-use feature for guaranteed structured
output. Consequences:

- A small fraction of responses may need the one-time retry loop.
- We never invoke Anthropic's `messages.batches` API, so token
  costs accumulate per-call rather than batched.

The default model is `claude-sonnet-4-6`. Override via
`CRUCIBLE_ANTHROPIC_MODEL`. There is no per-engagement budget cap on
Anthropic calls in this session — that responsibility is on the
operator's API console. (ACP, when shipped, will add per-engagement
budget enforcement.)

## 5. Embeddings are lexical by default

Without `sentence-transformers` installed, MLS uses
`LexicalEmbedder` — a 256-dim feature-hashing TF vectorizer. This
finds engagements with overlapping vocabulary, *not* semantic
neighbours. Concrete consequences:

- "Laravel marketplace" and "Rails marketplace" share the token
  "marketplace" and would correlate. "Laravel marketplace" and
  "Symfony e-commerce site" would correlate less than they should.
- Stop-list and tokenization are tuned for offensive-security text
  generally, not target-specific vocabulary.

To upgrade: `pip install sentence-transformers`. The first call
downloads ~80MB of model weights (`all-MiniLM-L6-v2`) into
`~/.cache/huggingface/`. The framework otherwise still runs offline.

## 6. UTI is passive — its fingerprint may be wrong

The fingerprinter uses ~120 curated signatures across 7 detectors.
This is enough for common stacks (PHP/Laravel/Django/Rails/Spring/
Next.js/WordPress/Perfect Panel) but is not WhatWeb / Wappalyzer in
breadth. Specifically:

- Detection runs on the response bodies of `~9` polite paths. Sites
  that serve different markup at different routes (SPAs serving an
  empty HTML shell at `/`, mobile-only sub-paths, behind-CDN bot
  challenges) may yield empty or misleading fingerprints.
- Cookie-based signatures depend on the target setting cookies
  during the unauthenticated probe. Many sites only set session
  cookies after login.
- The 50-request budget is hard-capped. A site under heavy CDN
  protection may exhaust the budget on `/` retries alone.
- The classifier is *confidence-weighted*; a high-confidence signal
  beats several weak ones. We hand-tuned this against the Session-1
  live target, which initially mis-classified as `laravel-marketplace`
  due to a generic `<meta name="csrf-token">` match before the fix.
  Other live targets may surface similar edge cases.

The drafters then build a charter / threat-model / attack-tree from
what is likely an incomplete fingerprint. Treat all three as
*drafts* (the charter is filename-marked `charter.draft.md` for
exactly this reason). The operator must review and refine before
relying on them.

## 7. The threat-model drafter falls back to a skeleton on URK error

`drafters.draft_threat_model` calls URK; on any exception, it falls
back to a brittle skeleton built from the archetype's
`common_vulnerabilities` list. If URK is in DryRun, the output is
the deterministic fixture (which is plausible but coarse). The
visible difference between "live LLM threat model" and "DryRun
threat model" or "skeleton fallback" is small enough that a hurried
reader might miss it. The header on every drafted threat-model
states which path produced it.

## 8. The built-in MLS seed is a fixture, not a real engagement record

`memory.seed_mrbeanpanel.seed()` is a sample-engagement fixture —
the only one currently shipped. It writes archetype-typical
threat-model and attack-tree data as if a completed engagement had
recorded them, plus three plausible "confirmed" findings (webhook-
forgery, IDOR on /api/v2/orders/{id}, mass-assignment on
/api/profile). All three are clearly tagged `[seed]` in their
summaries — but a casual reader of the `findings` table might not
notice. They reflect *common patterns for the PHP-Smarty SMM-panel
archetype*; they are not claims about any specific target.

The seeded engagement is what bears the bias the § 3.2 acceptance
test exercises. When real findings replace the seed, drop them by
deleting the engagement from the store or by replacing the seed.
Future sessions can add `seed_<slug>` modules for any archetype
that warrants its own fixture.

## 9. The 50-request UTI budget can be exhausted by redirects

`Fetcher.get(allow_redirects=False)` is the default, but tests have
not exhaustively explored what happens with sites that:

- Return `307 Temporary Redirect` to a CDN challenge.
- Return `429 Too Many Requests` with a Retry-After header.
- Time out or hang past `DEFAULT_TIMEOUT=8s`.

We log each as a row with `status=0` and a `note` field; the
detectors then see an empty exchange. Result: the fingerprint is
sparser; classification falls toward `generic-web`.

## 10. Path portability has edge cases

`bin/init.sh` rewrites every embedded `/home/claude/crucible` (or
the previously-configured root) path inside `.claude/settings.json`.
It's idempotent: running twice on the same host is a no-op. But:

- If the operator manually edits `.claude/settings.json` to
  reference an unrelated absolute path, `init.sh` will not catch
  that.
- If the repo moves between two filesystem locations and
  `CRUCIBLE_ROOT` env var is set to one but the actual location is
  another, the env wins (intentional, to support testing).
- The `targets/_template/` directory must remain at
  `<root>/targets/_template/` for the scaffolder to find it.

## 11. Tests use a real network for the live integration

`test_live_intake_against_authorised_target` is opt-in via
`CRUCIBLE_LIVE_INTAKE_URL=<https://your-target>` and respects a 12-
request budget. It hits whatever URL the operator has authorised in
the env var. If the site is down, redirects to a challenge page, or
has changed structure, the test may hang up to `8 * 12 = 96s` before
failing.

The deterministic offline tests are the bulk of the suite (only the
opt-in live-intake and live-LLM tests touch a network or a model).

> **Note on counts (Wave 1).** Test and source-file counts quoted
> throughout these two documents (e.g. "110 passing", "159 passed",
> "71 source files", "50 source files") were written at different
> sessions and have drifted apart — they now contradict each other and
> should be treated as historical, not current. Read the live numbers
> from the suite instead:
> `python3 -m pytest framework/v2/ -q -p no:cacheprovider` for the test
> count, and `find framework/v2 -name '*.py' -not -path '*/tests/*' |
> wc -l` for the source-file count. Do not trust any hardcoded figure
> in these docs as authoritative.

## 12. Type-checking is selective

`mypy --config-file framework/v2/pyproject.toml` reports clean (no
issues in 50 source files). The configuration is *strict but not
maximal*:

- `disallow_untyped_defs = true` — every function needs annotations.
- `strict_optional = true` — `T | None` is enforced.
- `warn_return_any = false` — `sqlite3.Row` indexing returns Any
  by typeshed; we accept that rather than wrap every fetchone with
  a cast.
- `warn_unused_ignores = false` — the `# type: ignore` on
  `cls.last_rowid` is platform-dependent.
- Test files are excluded.

## 13. The framework does not include a "verify v2 didn't drift v1" hook

We assert v1 canon byte-for-byte unchanged via
`git diff <baseline>` in this manifest, and the `.claude/settings.json`
deny list refuses edits under `framework/{cognitive,playbooks,
checklists,knowledge-base,templates}/`. But there is no live CI hook
that re-checks. A future SIL implementation should add one.

## 14. There is no offline acceptance test for "URK upgrades MLS priors"

The § 3.2 acceptance test (MLS) demonstrates that priors are biased
correctly toward the seeded archetype. The full integration —
"UTI fingerprints → MLS recall biases drafter → drafter outputs
reflect the bias" — has not been exercised end-to-end. It would be
straightforward to add but was deferred to keep the session in
scope.

## 15. The framework has not been hardened against adversarial input

Some places where untrusted input meets the framework:

- **HTTP response bodies during UTI:** the body excerpt (up to 16 KB)
  is included in detector input. A target that serves a body
  containing crafted patterns could trigger spurious detections.
  Confidence-weighting limits the impact; classifier scores are
  bounded; the worst outcome is "wrong archetype, charter draft is
  garbage" — which the operator must review anyway.
- **Charter file parsing:** the ethics gate parses the charter for
  the signature line and the in-scope hosts table. A malformed
  charter could cause `parse_scope` to return an empty list — which
  the gate treats as "no in-scope hosts; refuse". That's
  fail-closed and correct.
- **Memory store SQLite:** the DB is gitignored. If an attacker can
  write to the operator's filesystem, they can poison the priors.
  The framework's response is to trust local disk; if disk is
  hostile, the threat model is broken anyway.

We have not done a focused threat-modeling pass on the framework
itself. The deferred subsystems (especially ACP) will widen the
attack surface and warrant one before they ship.

## 16. The verification suite does not include a fuzzer

Pytest exercises the documented public surface plus the opt-in
live-intake integration. There is no:

- Property-based testing (Hypothesis library).
- Fuzzing of the markdown parser, charter parser, or detector
  signature engine.
- Adversarial-input testing of the JSON parser in the LLM backends.

A future hardening session should add at least Hypothesis tests for
the boundary parsers.

## 17. There is no "uninstall" path

`bin/init.sh` writes paths into `.claude/settings.json`, creates
`framework/v2/.intake-authorizations.txt`, and (on first MLS use)
creates `framework/v2/.memory/store.sqlite`. There is no script to
clean these up. They are gitignored, so a fresh clone is clean —
but a long-lived working copy will accumulate state.

## 18. Entitlement layer (Pillar 2) — controlled distribution

`framework/v2/entitlement/` ships the capability-gating spine described
in `ROADMAP-FLAGSHIP.md` § 3 (Pillar 2): m-of-n Ed25519 threshold
verification over a domain-separated canonical form, a capability ladder
(`registry.py`), host/workload binding, signed revocation, and a
fail-closed `require_capability` gate that emits an audit decision on
every call. 38 offline tests pass; the package is `mypy --strict` clean.
The `ExploitAgent` is wired to require `EXPLOIT_EXECUTION`.

What is real and verified:

- Threshold crypto is genuine and end-to-end tested: keys are generated,
  documents signed, and the gate verified against tampering, wrong keys,
  forged signatures, duplicate signers, below-threshold signing, expiry,
  not-yet-valid windows, binding mismatch, and revocation (including a
  fail-closed path for an invalidly-signed revocation list).

What is NOT yet done — operator roadmap:

- **Activation default is permissive.** With no trust root provisioned
  and `CRUCIBLE_ENTITLEMENT_ENFORCED` unset, enforcement is INACTIVE:
  gated capabilities are permitted with a logged WARNING. This mirrors
  the sovereignty layer's PERMISSIVE default and keeps dev/test
  checkouts (and the existing test suite) working. A production
  deployment MUST provision a trust root (enforcement then activates
  automatically) or set the env var. An un-provisioned deployment is
  not access-controlled.
- **FROST aggregation is forward-compatible but unexercised.** The
  verifier treats a single aggregated FROST-Ed25519 group signature as
  a 1-of-1 trust root, but no FROST signer has been run against it. Only
  the plain m-of-n multisig path is tested.
- **Attestation is consumed, not performed.** Host binding trusts
  `CRUCIBLE_ATTESTED_IDENTITY` (plus machine-id / hostname). The
  framework does not itself perform TPM/SPIRE/instance-identity
  attestation — a deployment's attestation sidecar must set that env var
  from a verified source. If nothing sets it, only machine-id and
  hostname back the binding, which are weak against a local attacker.
- **No issuance ceremony tooling beyond `provision.py`.** Minting trust
  roots and signing entitlements is a library API; there is no hardened,
  HSM-integrated, multi-party issuance ceremony CLI yet. Private-key
  custody is entirely the operator's responsibility.
- **Gate coverage is one call-site.** Only `ExploitAgent` is wired.
  `AUTONOMOUS_PLANNING`, `DEEP_STATIC_ANALYSIS` (DAA),
  `DEFENDER_TELEMETRY`/`DEFENDER_EVASION` (DEL), and
  `SELF_IMPROVEMENT_MERGE` (SIL) gates attach as those subsystems land.

## 19. Evaluation harness (M2) — measurement substrate

`framework/v2/eval/` ships the measurement layer SIL gates on: a
benchmark-corpus contract, ground-truth/produced finding models,
greedy one-to-one matching, per-target + micro-averaged scoring
(detection/precision/recall/F1), run persistence, and a regression
verdict (`compare_runs`) that fails on any detection drop, precision
drop, or specifically-newly-missed finding. 24 offline tests pass;
`mypy --strict` clean; CLI at `python3 -m framework.v2 eval`.

What is NOT yet done — operator roadmap:

- **Two corpora ship; production corpus is still operator content.**
  (1) `builtin_corpus()` — 3 synthetic archetype targets (metadata only).
  (2) `corpus/vulnpy/` — 8 real vulnerable Python files across 8 CWE
  classes, used to measure DAA's *actual* dataflow detection via
  `DaaCorpusProducer` + the eval harness. It was built at **6/8** (the
  taint ruleset lacked pickle/XXE sinks); taint rules for those two
  classes (daa-py-insecure-deserialization, daa-py-xxe) were then added,
  taking it to **8/8 detected, precision 1.0** — a hand-run of exactly
  what the SIL loop automates (named gap → rule → remeasure). This is
  still a small curated benchmark (like OWASP Benchmark / Juliet), NOT
  scraped real apps; a flagship needs a large authorised real-target
  corpus, and 8/8 on 8 files is a sanity check, not a capability claim.
- **False-positive counts require complete ground truth.** A produced
  finding with no ground-truth counterpart is scored as a false
  positive. On a target whose ground truth is incomplete, real
  discoveries are mis-scored as FPs. The corpus must document
  completeness per target; until it does, treat precision as a lower
  bound.
- **Live producer adapter: blackboard half done; planner half pending.**
  `eval/produce.py` ships `BlackboardFindingProducer`, which reads an
  engagement's critique-confirmed findings off a live Blackboard and maps
  them to `ProducedFinding` — verified end-to-end driving `run_harness`.
  What remains is the step that *populates* the blackboard: running the
  planner against a target replica per benchmark target (needs a target
  corpus and an LLM backend). The mapping and harness wiring are real;
  the autonomous "run the engagement" front-end is the open piece.
- **Matching is lexical.** Bug-class normalisation removes formatting
  but does not unify synonyms (`SQLi` vs `SQL Injection`); surface
  matching is substring/containment, not semantic. A corpus should use
  canonical bug-class labels and stable surface strings, or supply
  `detection_keys`, to avoid false misses.

## 20. SIL — self-improvement loop (M3)

`framework/v2/improve/` ships the never-stop engine as
continuous-discovery / gated-deployment: a deterministic reviewer that
mines an engagement for capability gaps, a horizon scanner that folds
CVEs/techniques into gaps, a patcher that drafts reviewable proposals
(records + markdown), and a merge gate that *authorises* (never applies)
a merge only when eval-green (M2) AND a threshold of governance
approvals over the proposal content (Pillar-2 crypto) AND the
SELF_IMPROVEMENT_MERGE capability all hold. 22 offline tests pass;
`mypy --strict` clean; CLI at `python3 -m framework.v2 improve`.

The load-bearing safety property is verified: the gate makes no change
to the working tree, and an approval signed over one proposal does not
authorise another.

What is NOT yet done — operator roadmap:

- **Reviewer is deterministic, not yet LLM-augmented.** It mines gaps
  the blackboard and MLS priors already imply (untested known classes,
  unreached surfaces/hypotheses, refuted threads). It does not yet
  propose *novel* gaps a model might see (a class MLS doesn't know for
  the archetype). An LLM binding would add gaps, never remove these.
- **Patcher emits described-only proposals.** It states precisely what
  to change and where, but authors no code diff — `change.patch` is
  empty by default. Turning a proposal into an actual diff is a human
  or future-LLM step; SIL never self-writes code. This is deliberate,
  but it means a proposal is not yet a merge-ready patch.
- **Live blackboard adapter: done.** `improve/ingest_live.py` assembles
  an `EngagementSnapshot` from a live Blackboard (hypothesis states,
  observed surfaces) and MLS (archetype's known bug classes), verified
  driving the reviewer end-to-end. (Integration testing also surfaced and
  fixed a reviewer surface-matching bug — coverage now matches whole path
  segments, not incidental substrings.)
- **Horizon intake is file-fed.** No network fetcher — a live feed
  puller must pass the sovereignty egress guard and is deferred.
- **The merge gate authorises; nothing applies.** By design there is no
  auto-apply path. A human (or a future gated deploy step that re-checks
  the decision) performs the actual merge. Do not add an auto-apply
  without re-deriving the threat model: an unattended self-applying
  offensive tool is the failure mode the whole gate prevents.

## 21. DEL — defender emulation layer, defensive subset (M4)

`framework/v2/defender/` ships the *defensive* half of DEL: a telemetry
model (what signals an action emits across access-log / WAF / auth-log /
netflow channels), a Sigma-style detection ruleset + matching engine,
self-detection scoring (noisy-OR detectability), and posture annotation
(TEST emphasises correlatability; EMULATE reports honest detectability).
Scoring is gated on Capability.DEFENDER_TELEMETRY. 17 offline tests
pass; `mypy --strict` clean; CLI at `python3 -m framework.v2 defender`.

The policy line is enforced in code and in tests: EMULATE guidance is
self-assessment ("you would be detected by rule X") and a test asserts
no evasion vocabulary (bypass/evade/obfuscate) appears in it.

What is NOT here, by deliberate policy (not an oversight):

- **No evasion library.** Turnkey defeat of a named production defender
  is Capability.DEFENDER_EVASION (M6) — an entitlement-locked,
  human-authored interface, not generated capability. DEL tells you how
  loud you are; it does not make you quiet by defeating detections.

What is NOT yet done — operator roadmap:

- **The telemetry model is legible, not a SIEM fidelity simulation.** It
  encodes common, well-understood signals; it does not model a specific
  product's parsing, enrichment, or correlation. Operators supply their
  own ruleset (`--ruleset`) to reflect their real environment. A low
  modelled score is a lower bound on footprint, never proof of stealth —
  the EMULATE guidance says so explicitly.
- **Not wired into the planner.** Scoring/annotation is a library + CLI;
  it is not yet called inline as the planner schedules actions (which
  would let the operator see footprint per step). Wiring is
  straightforward once an action→ActionDescriptor mapping is agreed.
- **No detection-feed import.** Rulesets are hand-authored JSON; there is
  no Sigma-repo importer yet.

## 22. DAA — deep analysis arsenal (M5)

`framework/v2/analysis/` ships the deep-sensing layer: an offline,
always-available pattern analyzer (curated dangerous-pattern ruleset), an
external-tool adapter contract (Semgrep reference impl that degrades
gracefully when the binary is absent), a Python AST symbol index
(functions/classes/imports/call-sites, queryable), and an orchestrator
that merges + de-dupes findings and records what was skipped and why.
Whole-tree analysis is gated on Capability.DEEP_STATIC_ANALYSIS. 15
offline tests pass; `mypy --strict` clean; CLI at
`python3 -m framework.v2 analysis`. Demonstrated DAA-turned-inward: it
self-scans the framework's own subsystems.

What is NOT yet done — operator roadmap:

- **Real dataflow/taint now ships via Semgrep — verified.** The
  `SemgrepAnalyzer` runs in TAINT mode against a curated offline ruleset
  (`analysis/rules/taint-python.yaml`: command injection, SQLi, SSRF,
  code injection, path traversal, SSTI). Each finding means untrusted
  input provably reaches a sink. Proven by a benchmark
  (`analysis/benchmark/`): the vulnerable file yields all 6 source→sink
  flows; the *sanitized* file — same sinks, dataflow broken — yields
  ZERO, where the regex pattern analyzer false-positives. Tests skip when
  semgrep is absent (`pip install semgrep`). The builtin pattern analyzer
  remains as an always-available lexical fallback (leads, not verdicts).
- **Taint ruleset is Python-only and curated, not exhaustive.** It covers
  the major injection/SSRF/traversal classes for Flask/Django/generic
  request sources; other languages need their own rules (or
  `config="auto"` against the semgrep.dev registry, which needs network).
- **Joern CPG adapter ships (optional) — verified.** `JoernAnalyzer` runs
  Joern's inter-procedural `reachableByFlows` via a shipped CPGQL script
  and normalizes results; verified resolving a cross-function flow
  (request → `_passthrough` → `os.system`, `analysis/benchmark/python/
  interprocedural.py`). Honest finding: for typical Python *web* source,
  semgrep's taint is already competitive (it caught the same simple
  inter-procedural case), so Joern's real edge is harder targets — native
  C/C++ and binaries via its frontends, very large cross-file flows,
  custom graph queries — not a strict win on every codebase. Joern is
  ~2 GB + JVM, not pip-installable; the framework does not install it
  (provision via `CRUCIBLE_JOERN_HOME` or PATH). Tests skip when absent.
  CodeQL (a third CPG engine) is still not adapted.
- **Symbol index is Python-only.** The `Symbol` shape is
  language-agnostic, but only the `ast`-based Python indexer exists.
  Other languages need their own parser behind the same index.
- **No fuzzing / differential-testing harness yet.** The roadmap's
  coverage-guided fuzzing and differential testing (DAA's dynamic half)
  are not built; this milestone delivered the static half + indexing.
- **Wired into hypothesis generation via the blackboard.**
  `analysis/seed.py` maps DAA findings to blackboard `HypothesisPayload`s
  (bug class per rule/CWE, confidence per severity) and posts them as open
  hypotheses the exploit agent picks up — verified end-to-end. What
  remains is the *deeper* integration: feeding the symbol index and
  findings into the kernel's `hypothesize` prompt as priors (so the model
  reasons over them), rather than seeding only at the blackboard level.

## 23. Engagement authority + kill-switch (digital-twin discipline)

`framework/v2/authority/` ships the scoped, time-boxed, environment-aware
authorization object and the persistent kill-switch. The gate checks, in
order: kill-switch -> validity window -> scope -> destructive permission
-> live-destructive double-acknowledgement -> action budget. The
kill-switch is a file on disk, so a tripped engagement stays halted
across a process restart, and the hard stop is checked before every other
condition. Live-destructive actions require two explicit flags
(allow_destructive AND live_destructive_acknowledged); the intended
workflow is to run high-risk work against a TWIN environment first. 18
offline tests pass; mypy --strict clean; CLI at
`python3 -m framework.v2 authority`.

What is NOT here — honest scope:

- **No replica/twin *constructor*.** This enforces twin-FIRST discipline
  (an authority is tagged TWIN/STAGING/LIVE and live destruction is
  double-gated), but it does not build a cloud replica of a target.
  Standing up a faithful digital twin is operator infrastructure
  (IaC/snapshots); the framework enforces the discipline, it does not
  provision the environment.
- **Rollback is the halt, not state restoration.** The kill-switch stops
  further action instantly and persistently; it does not undo changes
  already made on the target. True rollback is target-specific and out of
  scope (and impossible to guarantee in general).
- **Wired into the executor.** `HttpExecutor` now takes optional
  `authority` and `killswitch` and checks them first in `execute()` —
  before the scope gate and any network I/O — so a kill-switch tripped
  from anywhere (CLI, another process) halts the engagement at its very
  next action. Backward compatible (both default None). Verified by tests
  that a tripped switch refuses the next action with status 0. What
  remains is having the planner/coordinator construct the executor with a
  per-engagement authority by default, rather than the operator wiring it
  explicitly.
- **Authority is unsigned.** Unlike the entitlement layer, the authority
  document is plain JSON, not threshold-signed. For high-assurance
  deployments it should carry the same Ed25519 signing as entitlements so
  a tampered scope is detected.

## 24. Social-engineering defence (socialdefense)

`framework/v2/socialdefense/` is the *defensive* answer to the Bucket-C
social-engineering capabilities the framework refuses to build: instead
of generating phishing/impersonation, it scores *inbound* messages for
attack indicators (urgency, credential harvesting, authority
impersonation, lookalike/punycode domains, reply-to and display-name
mismatch, financial-action and secrecy requests, dangerous attachments)
and recommends action. Deterministic, offline, pure defence — it reads a
message you received and reports risk; it sends nothing and generates no
content. 8 offline tests pass; mypy --strict clean; CLI at
`python3 -m framework.v2 socialdefense`.

What is NOT here — honest scope:

- **Heuristic, not ML/LLM.** It is a high-signal first filter, not a
  trained classifier. It will miss novel phrasing and can false-positive
  on legitimately urgent mail. A production deployment augments it with
  an ML/LLM model; the recommendation states it is a heuristic, not proof.
- **Text/email only.** Deepfake *audio/video* detection needs
  media-forensic models and is out of scope. This covers written social
  engineering (email/chat).
- **Naive eTLD handling.** `_registrable` takes the last two labels, so
  multi-label TLDs (`co.uk`) are approximated. Good enough for the
  lookalike heuristic; a production build uses the public suffix list.
- **No live mail integration.** It assesses a supplied `MessageArtifact`;
  wiring it to a mail pipeline (IMAP/Graph/Gmail API) is operator
  integration.

## 25. Live reasoning loop — verified over Claude Code (no API key)

The long-standing "URK is DryRun by default / no live frontier model
verified" caveat is **discharged for this environment**. With
`CRUCIBLE_LLM_BACKEND=claude-code`, URK routes reasoning through the
operator's Claude Code CLI (`claude -p`) — a Max subscription, no
ANTHROPIC_API_KEY. Verified live on 2026-06-27:

- `hypothesize` against a `/fetch?url=` observation → 5 real, falsifiable
  hypotheses (SSRF, `file://` LFI, open redirect, cache poisoning), each
  with a cheap test and refute condition; `is_dryrun=false`, ~58s.
- `critique` of a real DAA taint finding (SSRF source→sink) →
  `decision=confirm` with a rigorous coverage-gap list and a deception
  check; `is_dryrun=false`, ~36s.

This is the "reasoning over deep analysis" loop running for real: a DAA
taint finding (provable dataflow) becomes a claim that live URK confirms
or refutes. Regression-covered by the opt-in
`kernel/tests/test_live_claude_code.py` (gated on `CRUCIBLE_LIVE_LLM=1`
plus the `claude` CLI; skipped in CI).

Honest bounds:

- **Per-call cost and latency are real** — ~30–60s and subscription
  tokens per binding. This is fine for source review / targeted
  verification, not for thousands of cheap cycles without a budget.
- **Not yet an autonomous at-scale loop.** The pieces (DAA → seed →
  hypothesize → critique) are verified individually live; running them as
  a continuous, budgeted, self-driving source-review campaign is the next
  build, not done.
- **Quality is the model's**, and a confirmed critique is still "worth a
  PoC," not a proven bug — exactly as the framework's own discipline
  requires.

## 26. Autonomous source-review loop (DAA → live URK)

`analysis/review_loop.py` ties the verified pieces into an autonomous
white-box review: DAA dataflow findings → live URK critique
(confirm/refute), budgeted, with the engagement kill-switch checked
before every model call. `python3 -m framework.v2 analysis review
--root <path> --max-reviews N`. 5 offline tests (fake reviewer: budget
cap, kill-switch halt, selective confirm); mypy clean.

Verified live on the benchmark (Claude Code backend, no API key):

- First run fed only a finding summary → 0/2 confirmed; the critique
  flagged the exact gap: *"actual vulnerable code not examined", "PoC not
  attempted"*.
- Acting on that feedback, the loop now includes the real source window
  around each finding in the evidence → re-run confirmed **1/2** (SQLi
  CWE-89 `confirm`; the command-injection drew `objections` — the
  critique staying rigorous, not rubber-stamping).

That round-trip — the loop's own output critiqued, the critique's gap
fixed, the result improved — is the self-improvement discipline working
on the framework itself.

Honest bounds:

- **Confirm ≠ proven.** A `confirm` here means the model, given dataflow
  evidence + source, judges the flaw real and worth a PoC. It is not a
  PoC. Turning confirmed findings into reproduced exploits (the executor
  path, against an authorised running target) remains separate and ROE-
  gated.
- **Cost-bounded, not at-scale-autonomous.** ~30–60s + subscription
  tokens per review; the budget caps calls. A continuous, large-corpus,
  loop-until-dry campaign with token accounting is the next step.
- **Triages dataflow findings first.** Lexical pattern findings are
  reviewed only when no dataflow findings exist; review quality tracks
  DAA's finding quality.

---

## 27. Wave 1 (2026-07-02) hardening — new modules, honest status

A hardening wave landed `framework/v2/verify/` (verification oracles
that confirm a finding by exercising it and observing behaviour — NOT
exploit generators) and `framework/v2/worldmodel/` (an explicit target
world-model the planner can reason over), plus targeted security fixes
across the touched modules.

Honest status: **code-complete + module-tested (offline). Full
integration into the live pipeline is a follow-up.** Specifically:

- `verify/` module tests pass, but the oracles are not yet wired into
  the autonomous critique/finding loop.
- `worldmodel/` module tests pass, but the planner does not yet consume
  the world-model by default.
- The security fixes each ship with a focused test for the safe path;
  no global default was broadly flipped (per the wave's own rule).

Do not read this as a live-path claim. None of the Wave 1 work has
been exercised in a live end-to-end engagement. See the module READMEs
and `V2-MANIFEST.md` § "Wave 1 (2026-07-02) hardening".

## What the operator should do next

In rough order:

1. Read `V2-MANIFEST.md` and this file.
2. Decide whether the foundation pass is enough to start using v2,
   or whether a follow-up session should ship MAO + ACP first
   (the path to "autonomous for hours").
3. If using as-is: run `bin/init.sh`, install requirements, set
   `ANTHROPIC_API_KEY` if you have one, run intake against a
   target.
4. If running offline: accept the DryRun reasoning regression and
   work from there. The framework still scaffolds engagements,
   tracks priors, and enforces ethics gates without a live LLM.
5. Decide which deferred subsystem is most urgent and scope a
   follow-up session for it.
