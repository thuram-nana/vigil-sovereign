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
     5 catastrophic outcomes against the mrbeanpanel input.
   - Output is archetype-specific (names PHP-Smarty cookies,
     SMM-panel money flows, PSP webhook surfaces). Comparable in
     coverage to the hand-written reference at
     `targets/mrbeanpanel/threat-model.md`; slightly less complete
     on operator-credential vectors and refresh cadence.
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
against `mrbeanpanel.com` in Session 3:

- 173s wall-clock, 9 HTTP requests against the real target (under
  the 12-request budget cap from the existing charter).
- Archetype: `php-smarty-smm-panel-fork` (score 0.75) — same
  classification Session 1 confirmed.
- Threat-model output: 208 lines, marker line `Drafted by URK
  from a live LLM call` confirms the URK path executed (not the
  skeleton fallback).
- Captured at `framework/v2/intake/tests/fixtures/live-run/mrbean-threat-model.md`.

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

- ✓ A real engagement target was used: `mrbeanpanel.com` for UTI
  (Session 3); the live full-pipeline test uses fixture-replay
  intake against `https://fix-target.invalid` plus `RealisticExecutor`
  for the exploit path.  No real attack traffic at the executor
  layer in the live test; only UTI hits a real host.
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

- Real engagement against a real attackable target with a real
  exploit-running executor (rather than a synthetic harness).
  `RealisticExecutor` produces multi-step evidence chains that
  *resemble* real-engagement output, but the underlying actions
  are pre-baked.  An `HttpExecutor` or richer real-target executor
  is a future-session work item.
- The `mixed`-evidence scenario (timing-side-channel) was not
  picked up by the planner during the captured run — only the
  strong + weak scenarios fired.  The mixed scenario's behaviour
  under live critique remains tested only at the binding-unit
  level (Session 3's `02b-critique-strong-retry.json` is the
  closest analogue).

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
  beats several weak ones. We hand-tuned this against the
  `mrbeanpanel.com` live run, which initially mis-classified as
  `laravel-marketplace` due to a generic `<meta name="csrf-token">`
  match before the fix. Other live targets may surface similar
  edge cases.

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

## 8. The mrbeanpanel seed is a fixture, not a real engagement record

`memory.seed_mrbeanpanel.seed()` writes the existing target's
threat-model and attack-tree as if a completed engagement had
recorded them, plus three plausible "confirmed" findings (webhook-
forgery, IDOR on /api/v2/orders/{id}, mass-assignment on
/api/profile). These three finding fixtures are clearly tagged
`[seed]` in their summaries — but a casual reader of the `findings`
table might not notice. They reflect *common patterns for this
archetype* across the SMM-panel space; they are not claims about
mrbeanpanel itself.

The seeded engagement is what bears the bias the § 3.2 acceptance
test exercises. When real findings replace the seed, drop them by
deleting the engagement from the store or by replacing the seed.

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

`test_live_intake_against_mrbeanpanel` is opt-in via
`CRUCIBLE_LIVE_INTAKE=1` and respects a 12-request budget. It hits
`mrbeanpanel.com` directly. If the site is down, redirects to a
challenge page, or has changed structure since this session, the
test may hang up to `8 * 12 = 96s` before failing.

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

Pytest exercises the documented public surface plus the live mrbean
integration. There is no:

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
