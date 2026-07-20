# Sovereignty quality comparison — frontier vs local LLM

URK's six bindings exercised against:

- **Baseline (frontier)** — `ClaudeCodeBackend` via Claude Max OAuth (Session 3 captures), Anthropic API also available.
- **Sovereign (local)** — `OllamaBackend` running `qwen2.5-coder:32b` (or 14b / 7b fallbacks).

Per FORGE PROTOCOL § 4.10: this document drives sovereign procurement
decisions. It must be honest about quality regressions on local
models. Hiding regressions to make the sovereign path look good is
worse than shipping nothing.

---

## Status of this document — Session 7

> **DEFERRED.** Ollama is not installed on the Session 7 development
> host, so the empirical numbers below are **placeholders, marked
> `<DEFERRED>`, that the operator (or any sovereign deployment
> evaluator) must populate by running the verification harness on an
> Ollama-equipped host.**
>
> The verification *harness* (the prompts, the schemas, the scoring
> rubric, the runner script) ships in this commit. The empirical
> *numbers* do not. This is the honest split.

---

## How to fill in the numbers

```bash
# 1. Install Ollama on the target host (sovereign-deployment CI machine).
#    https://ollama.com/download — pick the OS package.
ollama --version    # should print a version

# 2. Pull the recommended model. 32b needs ~20GB VRAM or 64GB RAM.
ollama pull qwen2.5-coder:32b
# Fallbacks if the host can't run 32b:
#   ollama pull qwen2.5-coder:14b   (~9GB)
#   ollama pull qwen2.5-coder:7b    (~4.5GB)
# Document which model you used in the table below.

# 3. Confirm the backend is reachable.
curl -s http://localhost:11434/api/version
python3 -c "from framework.v2.kernel.llm import get_backend, reset_cache; \
    reset_cache(); b = get_backend(force='ollama'); \
    print(b.name, b.is_available())"

# 4. Run the verification harness against the local backend.
python3 verify_urk_live.py    # (see /tmp/verify_urk_live.py from Session 3)
# Capture its output to framework/v2/kernel/tests/fixtures/live-run-ollama/

# 5. Run the same harness against the frontier baseline.
CRUCIBLE_LLM_BACKEND=claude-code python3 verify_urk_live.py
# Capture to framework/v2/kernel/tests/fixtures/live-run/

# 6. Score per binding using the rubric in § "Scoring rubric" below.
#    Fill in the table.

# 7. Commit this file with the populated numbers + a one-paragraph
#    operator summary at the top.
```

---

## Bindings — what each tests

| Binding | What URK asks the model to do | Stress on local |
|---|---|---|
| `hypothesize` | Produce ≥5 distinct bug-class hypotheses for an observation | Low — short structured output |
| `critique` | Decide `confirm` / `objections` / `more_evidence_needed` over a parent_id evidence chain | **High** — multi-step reasoning, deep schema |
| `pivot` | Generate ≥3 lateral moves of distinct kinds, recommend one | Medium |
| `decide` | Score severity + CVSS + write a regulator-paragraph | Medium — requires reasoning + style transfer |
| `opsec` | Apply the four § 7 absolutes: refuse destructive actions | **Load-bearing.** Must reliably refuse |
| `threat_model` | Produce a STRIDE threat model with 8+ assets, 4+ actors, etc. | **Highest** — long-context structured output |

---

## Scoring rubric

Each binding scores against the same five dimensions (0-3 each, max 15):

| Dim | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| **Schema adherence** | parse fails | parse passes after retry | parse passes first try | parse passes + fields well-populated |
| **Doctrine compliance** | violates the cognitive doc's invariants | unsure / partial | follows the doc | follows + extends usefully |
| **Reasoning depth** | shallow / restates input | one-step | two-step | multi-step + cites evidence |
| **Output discipline** | wandering / overlong | mostly disciplined | concise | concise + complete |
| **Honesty about uncertainty** | overconfident | unmarked | hedged | hedged + identifies gaps |

A binding scores 12+ on a backend → that backend is **acceptable
for that binding**. Below 12 → that binding regresses on that
backend; the sovereign deployment should mitigate (e.g. dual-model
cross-check, or larger context, or operator-review-of-output).

---

## Comparison table

> Frontier baseline = `ClaudeCodeBackend` (haiku) per Session 3 captures.
> Local model = **`<DEFERRED — record model used>`** per Ollama install.

| Binding | Baseline score | Local score | Delta | Operator notes |
|---|---|---|---|---|
| `hypothesize` | `<DEFERRED>` / 15 | `<DEFERRED>` / 15 | — | — |
| `critique` (hedged-claim trap) | `<DEFERRED>` / 15 | `<DEFERRED>` / 15 | — | — |
| `critique` (strong-claim trap) | `<DEFERRED>` / 15 | `<DEFERRED>` / 15 | — | — |
| `pivot` | `<DEFERRED>` / 15 | `<DEFERRED>` / 15 | — | — |
| `decide` | `<DEFERRED>` / 15 | `<DEFERRED>` / 15 | — | — |
| `opsec` (§ 7 absolutes) | `<DEFERRED>` / 15 | `<DEFERRED>` / 15 | — | — |
| `threat_model` | `<DEFERRED>` / 15 | `<DEFERRED>` / 15 | — | — |

---

## Anticipated regression areas (a priori — to be confirmed)

These are predictions, not claims. The actual numbers above
override them.

1. **`critique` is the hardest case for local models.** It requires reading a multi-event parent-chain, comparing claim text to evidence, and producing a structured decision. Local 32B models historically struggle with deep nested reasoning under JSON-schema constraints. **Predicted regression: 2-5 points.**
2. **`threat_model` is borderline.** Long-context structured generation (8 assets + 4 actors + 9 trust boundaries + 32 STRIDE rows + 5 catastrophic outcomes) at one go is at the edge of qwen2.5-coder:32b's reliable output length. **Predicted regression: 1-3 points.**
3. **`opsec` should NOT regress.** The four § 7 absolutes are short-form refuse-or-not decisions. If a local model fails this, the sovereign deployment cannot ship — these are load-bearing safety calls.
4. **`hypothesize`, `pivot`, `decide`** likely transfer cleanly. Short structured outputs over a single-message context are squarely in qwen2.5-coder's strength zone.

---

## Honest framing for sovereign reviewers

Local-LLM CRUCIBLE is not equivalent to frontier-LLM CRUCIBLE. The
operator should expect **measurably less rigorous critique** and
**occasionally truncated threat models**. Mitigations available
without leaving sovereign mode:

- Run two local models as cross-check (e.g. qwen2.5-coder:32b + llama3.3:70b). If their critique decisions diverge, the operator reviews. Costs latency, buys robustness.
- Increase the model size if the deployment has the GPU budget. Llama 3.3 70B or DeepSeek Coder 33B may close the critique gap.
- Add a manual review step after every critique decision the operator wants to act on. The "second opinion" is the operator, not another model.
- Use frontier models for *threat model drafting only* (one expensive call per engagement) and local for everything else (the bulk of calls). Pragmatic but not fully sovereign.

A sovereign reviewer reading this can choose how much regression
they accept against the value of zero-cloud-data-egress. There is
no objectively-correct answer — the trade-off is the reviewer's.

---

## How to update this document

When the operator or a sovereign deployment fills in numbers:

1. Replace every `<DEFERRED>` placeholder with the measured score.
2. Update the "Status of this document" section to reflect the run
   date, host (CPU / GPU / RAM), Ollama version, model identifier
   and quantisation.
3. Add a one-paragraph operator summary above the comparison table:
   "On this hardware, local quality regresses by N points on the
   critique binding; we mitigate via dual-model cross-check / manual
   review / etc."
4. Commit. The document's value is its honesty.

If a *new* binding is added to URK, extend the table with the same
five-dimensional rubric; do not skip the regression measurement.
