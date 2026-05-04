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

## 0. Inherited unexercised-LLM-path risk

This is the single most consequential limitation in this manifest.
Read it before treating MAO or ACP as production-ready.

### What "unexercised" means here

Every URK call (`hypothesize`, `critique`, `pivot`, `decide`,
`opsec`, `threat_model`) goes through one of three backends. In
Sessions 1 and 2, no `ANTHROPIC_API_KEY` was set and no local
Ollama daemon was running.  Every URK invocation therefore landed
on `DryRunBackend`, which does **not** call any LLM — it returns a
deterministic Pydantic instance synthesised from a per-schema
fixture catalogue (`framework/v2/kernel/backends/fixtures.py`).

The Anthropic and Ollama backend code paths exist in source, pass
mypy, pass import-time smoke checks, and were written from the
public API documentation.  Neither has been called against a live
model in any session of the FORGE PROTOCOL.

### Which subsystems sit on top of this risk

Every subsystem that calls URK inherits the gap:

| Subsystem | Calls URK from | Inherited risk |
|---|---|---|
| **UTI** | `intake/drafters.py` `draft_threat_model` calls `urk_threat_model` | Threat-model drafts are DryRun fixtures unless the operator sets credentials.  The drafter falls back to a skeleton on URK exception, so failures here are visible but reasoning quality is bounded. |
| **MAO**: hypothesis-agent | `agents/hypothesis_agent.py::step` calls `urk_hypothesize` per Observation | Every Observation generates exactly the 5-entry static bug-class catalogue from the fixture, surface-substituted.  Real LLM hypothesis generation is unverified end-to-end. |
| **MAO**: critique-agent | `agents/critique_agent.py::_review` calls `urk_critique` per pending Finding | Critique decisions are made by a keyword heuristic (claim length, presence of "reproduced"/"confirmed"/"working PoC").  Real critique-agent veto behaviour against an LLM that argues for confirm-or-not is unverified. |
| **ACP**: planner | indirectly, via the agents above | Planner search ordering depends on hypothesis prior_p_success and on whether critique-agent confirms.  Both are DryRun-driven today.  Watchdog and budget enforcement do not depend on URK and are exercised. |

### Concrete checklist for the first live URK invocation

Before MAO or ACP can credibly claim to be running on a live model,
the following must each be exercised once and the output sanity-
checked.  Each item names the entry point, the input shape, and the
*specific* failure modes to watch for.

1. **`hypothesize`** — `framework/v2/kernel/hypothesize.py::hypothesize`
   - Input: an observation string and surface from a real engagement.
   - Verify: `HypothesisSet.doctrine_compliant()` returns `True`
     (≥5 hypotheses).  The DryRun fixture always returns 5; a live
     model could return fewer or hedge with prose around the JSON.
   - Failure modes to watch:
     - Model emits prose around the JSON → the parser's fence-strip
       handles markdown fences but not arbitrary preambles.  The
       retry-once loop should catch it; check the engagement log
       for `kernel.anthropic.parse_retry` events.
     - Model emits fewer than 5 hypotheses → schema accepts ≥3, so
       parse succeeds but doctrine compliance fails.  Check
       `result.doctrine_compliant()` after every call.
     - Model returns the same bug class for all 5 → diversity
       check (3 distinct classes) is in the test suite but not in
       the runtime invariant.

2. **`critique`** — `framework/v2/kernel/critique.py::critique`
   - Input: a claim string and an evidence string from a confirmed
     hypothesis end-to-end.
   - Verify: `decision` is one of `confirm` / `objections` /
     `more_evidence_needed`; `deception_check` is non-empty.
   - Failure modes to watch:
     - Model rubber-stamps every claim as `confirm` → the
       critique-agent's gate becomes a no-op.  Send three
       deliberately hedged claims ("I think the IDOR might be
       exploitable, status was 200") and confirm at least one
       comes back as `objections` or `more_evidence_needed`.
     - Model refuses every claim as `objections` → the planner
       starves of confirmed findings.  Send a deliberately strong
       claim with reproducible PoC text and confirm it returns
       `confirm`.

3. **`threat_model`** — `framework/v2/kernel/threat_model.py::threat_model`
   - Input: a target name + business context + archetype + light
     fingerprint.
   - Verify: assets / actors / trust_boundaries are all non-empty
     and reasonable for the archetype; attack tree is non-trivial.
   - Failure modes to watch:
     - Model returns a generic template that doesn't reflect the
       archetype's specifics.  Compare the output against
       `targets/mrbeanpanel/threat-model.md` (the hand-written
       reference) and look for missing money-flow assets.
     - Model exceeds `max_tokens=8000` and truncates JSON → parse
       fails, drafter falls back to skeleton.  Visible because
       skeleton headers are different from rendered headers.

4. **`pivot`** — `framework/v2/kernel/pivot.py::pivot`
   - Input: a stuck-thread description + last observation + posture.
   - Verify: `len(moves) >= 3`, `recommended` index is valid,
     `kinds` are diverse (≥3 distinct).
   - Failure modes: model returns moves all of one kind; or all
     low-confidence; or recommends an out-of-range index.

5. **`decide`** — `framework/v2/kernel/decide.py::decide`
   - Input: a finding summary + endpoint + impact.
   - Verify: `severity` is one of the five enum values; `cvss_base`
     in [0, 10]; `regulator_paragraph` non-empty.
   - Failure modes: model invents non-CVSS strings; severity that
     doesn't match the impact narrative.

6. **`opsec`** — `framework/v2/kernel/opsec.py::opsec`
   - Input: action summary + posture.
   - Verify: `allowed=False` when the action contains keywords from
     `framework/cognitive/opsec-discipline.md` § 7 absolutes (real
     user contact, real-money movement, third-party attack,
     destructive cleanup, etc.).  This is *load-bearing* — a model
     that wrongly returns `allowed=True` on a § 7 action is a
     critical failure.
   - The DryRun fixture catches the keywords with a heuristic; a
     live model is more flexible but may also be more permissive.
     Send each § 7 absolute exactly as written and confirm
     `allowed=False`.

### Backend-specific failure modes

In addition to the per-binding issues above:

- **AnthropicBackend** (`kernel/backends/anthropic.py`):
  - The structured-output strategy is "tell the model to emit a
    JSON object validating this schema, retry once on parse error".
    It does not use Anthropic's `tool_use` for guaranteed structured
    output.  First live use should monitor parse-retry rate; if
    the retry-once loop fires on >10% of calls, switch to tool-use.
  - Model name defaults to `claude-sonnet-4-6`.  Override via
    `CRUCIBLE_ANTHROPIC_MODEL`.  No automatic fallback to a
    different model on rate limits or 5xx — the BackendError
    propagates to the caller.
  - Token usage is captured from `rsp.usage` but not budget-checked
    *inside* the backend; ACP charges the token budget at the leaf
    level only.  A single leaf could consume more tokens than its
    estimate.  First live run, audit `kernel.anthropic.complete`
    log entries for `tokens_out` outliers.

- **OllamaBackend** (`kernel/backends/ollama.py`):
  - Probe checks `/api/version` and `/api/tags` to confirm the
    configured model is pulled.  Has not been verified against a
    live daemon.  First-use checklist:
    1. Confirm `python3 -m framework.v2 status` shows the backend
       as `✓ ollama  ready (vX.Y.Z, model=qwen2.5-coder:32b)`.
    2. Confirm `python3 -m framework.v2 kernel hypothesize
       --observation "test"` returns a valid HypothesisSet.
    3. Confirm `kernel.ollama.complete` log entries show non-zero
       `tokens_in` / `tokens_out`.
  - The chat endpoint uses `format: "json"` to enforce JSON output
    server-side.  Some Ollama versions ignore this on `/api/chat`
    (only honour it on `/api/generate`).  If the parse-retry rate
    is high, swap to `/api/generate`.

### What "live-path verified" must include before MAO+ACP claim it

The MANIFEST splits "code complete" from "live-path verified".  For
MAO+ACP to graduate from `partial` to `yes` on the live-path
column, all of the following must be true:

- A real engagement (mrbeanpanel.com or another in-scope target)
  has been planned and run end-to-end with `ANTHROPIC_API_KEY`
  set or with a working Ollama daemon.
- The engagement produced at least one finding that survived
  critique-agent's veto.
- The engagement produced at least one finding that was *blocked*
  by critique-agent (i.e. the critique gate is not a rubber stamp).
- The engagement's postmortem in `targets/<slug>/postmortem.md`
  shows non-trivial archetype priors updated in MLS.
- The watchdog halted at least once on a real condition (or, if
  no halt occurred, the engagement log shows a clean run with
  watchdog metrics).
- Cost telemetry from `CallTrace` is non-zero across the binding
  mix.

Until then, the manifest correctly states MAO and ACP as **partial
— DryRun only**.

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
