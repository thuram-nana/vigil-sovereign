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

## 1. Three subsystems are missing entirely

After Sessions 1 and 2, five subsystems ship: URK, MLS, UTI, MAO,
ACP. The remaining three — DAA, DEL, SIL — are not stubbed and not
partially implemented. They do not exist on disk.

What this means in practice:

- **No defender awareness.** Without DEL, the framework has no
  model of what telemetry its own actions would trip. EMULATE
  posture is named in URK's OpsecGuidance but no DEL substrate
  backs it.
- **No deep static analysis.** Without DAA, semgrep / CodeQL /
  Joern / API fuzzing / differential testing are absent. v1 has
  source-code-review playbook prose; v2 does not yet automate it.
- **No self-improvement.** Without SIL, the framework does not
  propose its own patches. Cross-engagement learnings stay in the
  MLS priors but no reviewer-loop emits patches for human merge.

Headlining the framework as XBOW-or-Big-Sleep-class is incorrect
even with MAO + ACP shipped: those two subsystems give the framework
a planner-and-agents loop, but the loop has been exercised only
against deterministic fixtures, never against a live LLM and never
against a live target.  See § 0 below.

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
  **achieved.**  The strong-evidence webhook-forgery scenario's
  finding was confirmed by live critique-agent and emitted by the
  reporter to `technical.md`.
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

MAO and ACP now graduate to **`live-path verified: yes`** on the
manifest.  See `V2-MANIFEST.md` "MAO/ACP live-path graduation —
Session 4" for the verbose narrative.

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

The 110 passing tests are deterministic and offline.

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

- **No benchmark corpus ships.** The harness scores against a corpus;
  none is included. A real flagship needs a curated corpus of
  authorised, known-vulnerable target replicas with complete ground
  truth. Building/curating it is engagement + content work, not code.
- **False-positive counts require complete ground truth.** A produced
  finding with no ground-truth counterpart is scored as a false
  positive. On a target whose ground truth is incomplete, real
  discoveries are mis-scored as FPs. The corpus must document
  completeness per target; until it does, treat precision as a lower
  bound.
- **No live producer adapter yet.** `run_harness` takes a
  `FindingProducer`; the production adapter that runs the planner
  against a target replica and maps blackboard findings to
  `ProducedFinding` is not written. Offline tests use deterministic
  producers. Wiring the live adapter is the bridge from "harness works"
  to "harness measures the real framework."
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
- **No live blackboard adapter.** `review_snapshot` works on an
  `EngagementSnapshot`; the thin adapter that assembles one from a live
  Blackboard + MLS recall is not wired (mirrors the eval harness's
  pending live producer). Tests use constructed snapshots.
- **Horizon intake is file-fed.** No network fetcher — a live feed
  puller must pass the sovereignty egress guard and is deferred.
- **The merge gate authorises; nothing applies.** By design there is no
  auto-apply path. A human (or a future gated deploy step that re-checks
  the decision) performs the actual merge. Do not add an auto-apply
  without re-deriving the threat model: an unattended self-applying
  offensive tool is the failure mode the whole gate prevents.

---

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
