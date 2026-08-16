# Chat — what it is for

## The organising idea

Every other screen in this system is about **certainty**. Findings, Proof Studio, Report, Replay
Proof, Evidence — each one displays things that have already been confirmed by a deterministic oracle
over real evidence.

Chat is the only room where **uncertainty** lives. It is where an operator says "that authentication
flow smells wrong" before anything has been proven, brings in a codebase they were handed an hour
ago, and thinks out loud.

That is its job, and it gives one test for every feature ever proposed for this screen:

> **Does this help a hunch become either a proof or a dead end, faster?**

A general-purpose assistant bolted to a scanner fails that test. So does a chatbot that answers
confidently from its own knowledge. What passes is anything that shortens the distance between
*suspicion* and *evidence*.

## The loop it should close, and does not

The operating doctrine is a cycle: observe → orient → hypothesise → test → update. Chat is the
natural home for the middle of that cycle, and today it drops the thread at every stage.

An operator asks a question, gets an answer, and **the answer evaporates**. Nothing is recorded, so
nothing can be closed. The next session starts cold. The constitution requires hypotheses to be
written down precisely because a hypothesis nobody recorded gets re-walked forever.

**A hypothesis should be a first-class object minted from a conversation**: a statement, what would
confirm it, what would refute it, and a status. When an oracle later fires, the hypothesis closes
itself, and the chat can say: *the thing you suspected on Tuesday is now confirmed — here is the
proof*. That single thread is what makes a chat an engagement's memory rather than a transcript.

## The four sources, and why they must look different

An answer here can only ever come from four places:

| Source | What it means |
|---|---|
| **Evidence in this engagement** | a confirmed finding, a run, a captured exchange |
| **Material you attached** | a file in the codebase or document you uploaded |
| **A linked chat** | prior reasoning you explicitly connected |
| **The model's own inference** | nothing backs it but the model |

They must be **visibly distinguishable in the interface** — not merely requested in a prompt.
Rendering the fourth in the same register as the first is the single most damaging thing this screen
could do, because the whole product rests on the difference between *advised* and *confirmed*. The
model may reason freely; it may never let its reasoning wear evidence's clothes.

## What the chat should be able to see

Today it sees findings and recent runs. The most valuable question an operator can ask is **"what
have we not covered?"** — and this engine is unusually able to answer it, because it records what it
refused and why. That knowledge is not currently offered to the conversation.

It should see: the scope and the phase, what is confirmed and what is still a lead, the attack path
picture and its chokepoints, **what was attempted and refused, with the reason**, coverage gaps, and
the kill-switch state. An assistant that knows the engagement's shape can say "you have never touched
the password-reset flow"; one that sees a finding list cannot.

## What it should be able to do

One action is reachable today: launch an assessment. But the operator's actual next step is usually
narrower — re-verify this finding, run this one tool, build the dossier, check whether that fix
held. Every one of those is **already gated**. Chat should be able to propose any of them, and none
of them should be reachable except through the same approve-then-run gate as everywhere else.

Chat proposes. The gate decides. That asymmetry is what lets the conversation be free.

## Coverage must never be implied

A model has finite context, so a large codebase is read in part. That is fine — and it must be said.
"I read 47 of 312 files, here they are, run the full scan to cover the rest" is honest and useful.
Silence implies whole-repository coverage and is a lie the operator cannot detect.

The gated real scan is the honest route to completeness, and should be one click from any answer
grounded in attached code.

## Sovereignty is a first-class choice, not a preference

Choosing a local model means an uploaded client codebase **never leaves the machine**. For a reviewer
handed sensitive third-party source, that is not a settings detail — it is the difference between a
usable tool and an unusable one. The model picker should say what each choice means at the moment of
choosing, and a failure to reach a local model must never fall back to a cloud one.

## What Chat must refuse to be

- **Not a general assistant.** Asked something unrelated to the engagement, it should say so rather
  than helpfully answering. The discipline is what makes the rest of its output worth trusting.
- **Not a place where facts are minted.** Nothing said here is ever a fact; only a fired oracle over
  real evidence produces one.
- **Not a place that hides what it does not know.** "The context does not contain the answer" is a
  complete and respectable response.

## The shape of a good interaction

> The operator drops in a zip and asks whether the authentication has weaknesses.
>
> The chat reads what fits, **says what it read and what it skipped**, and answers with three
> observations — each tagged to the file it came from. It records two hypotheses, each with what
> would confirm it. It offers, in one click: run the full gated scan, run one specific tool, or
> record the hypothesis and move on.
>
> Two days later an oracle fires. The hypothesis closes, and the chat can point at the proof.

That is the whole feature: **the continuity of reasoning across an engagement, and the shortest
honest path from suspicion to evidence.**

---

## What is built, against this charter

This charter is now largely executed. The table maps each idea above to what shipped; the section after
it names — as the constitution requires — what is an honest follow-up rather than softening the claim.
Every slice merged only after an adversarial red-pen, and the sharp ones each caught (and fixed) a real
defect before merge (SSRF-to-metadata on the clone, a kill-switch bypass on a mutating edit, a name-based
"local" model that would have egressed under a "nothing leaves this machine" label, a fireteam whose
"show its work" feature read a field that did not exist, a streamed turn that could double-record on a
mid-stream disconnect).

| Charter idea | What shipped | PRs |
|---|---|---|
| Hypotheses as first-class objects, auto-closing on an oracle fire | `console/hypotheses.py` — append-only JSONL, minted from a chat turn, reconciled against confirmed FACTs on every turn + reload; path-segment-precise match; a confirmed close requires a non-empty finding ref | #345 |
| The four sources, visibly distinct | per-claim source legend (attached / linked-chat / model), a Lead badge on every model answer; evidence's confirmed register is never worn by inference | #343–#344 |
| Seeing the engagement's shape ("what have we not covered?") | scope / phase, confirmed-vs-lead totals, attack-path + chokepoints, **refusals-with-reason**, coverage, kill-switch — fed read-only to the reasoner | #344–#345 |
| Propose gated actions, not just launch | model-proposed next-actions render as inert chips; a click routes through the SAME approve-then-run gate | #343 |
| Coverage never implied | a "read N of M files" footer rides every attachment-grounded answer AND its record; the gated scan is one click away | #343 |
| Sovereignty a first-class choice | E3 — a per-session model picker showing each option's trust class + consequence; a **local** pick routes through the provider layer with **no cloud failover**, and its endpoint-loopback is ENFORCED before the "nothing leaves this machine" claim, not merely asserted | #351 |
| Chat as the agentic operator, steerable | the chat drives the integration OODA engine (reason → gate → tool → oracle → checkpoint); its live steps stream in-thread; a message can be added to a running engagement (advisory — re-runs no completed tool, relaxes no scope) | #346 |
| Change + test a codebase; clone a repo; show diffs | the codebase agent — a gated, SSRF-hardened clone, dev-mode edits reviewed as unified diffs (apply is A2-gated, git-apply clone-only), and tests run in the network-isolated sandbox (A3, signed) — all operable from chat | #347–#350 |
| Deploy multiple agents on different tasks, oracle-bounded | the engine deploys gated, bounded (≤A2, never self-approving) fireteams whose facts are minted only by the oracle; each member's steps stream to the feed, attributed by role | #352 |
| Deep reasoning: research / plan / think | ask / research / plan modes (extended thinking); the reply is a LEAD in every mode | #344 |
| Streamed replies (the typing feel) | F1 — a pure question turn streams tokens over SSE; a local pick answers non-streamed (no egress); the persisted record is byte-identical to a non-streamed turn (one shared finish path) | #353 |
| A coherent screen for all of it | F2 — the run-options grouped into one labeled panel, set apart from the message composer | #354 |

### Honest follow-ups (built to a real edge, and named — not softened)

- **Fireteam escalations: surfaced (live + structured); sign-and-run is the remaining scoped tier.** An
  over-cap member edge never runs — it is emitted to the console live feed as a `member.escalation` step
  (E1) AND recorded as a STRUCTURED, durable row on the run report (`RunReport.fireteam_escalations`:
  wave_id / member_id / seq / tool / target / requested_tier / reason / status — G1 Tier A), so the
  operator can review exactly what is pending after a wave and a later tier can read it. What remains is
  genuinely tiered, not a quick win: **Tier B (sign)** — publish each escalation through the existing
  approval-token/broker stack and feed a signed-approval `ApproverFn` into `ConfirmationRegistry.resolve`
  (the registry already fail-closes to REJECTED without one); **Tier C (run)** — actually EXECUTE an
  approved edge, which needs a new escalated-edge runner that lifts the member A2 cap for exactly that
  token-bound action. Tier C deliberately touches the one boundary the fireteam design makes hard (a
  member is `≤A2`, never self-approving), so it is authorized solely by the owner token and constrained to
  the single bound action — a real slice, not a config flag.
- **Secret redaction differs by surface — and the difference is stated, not implied away.** The E1
  fireteam feed IS deterministically scrubbed: every member step record passes the shared F3 scrubber
  (`redact_tool_args`, in `fireteam/spine_queue.py`) before it reaches the feed, so structured secret
  forms (`api_key=`, `Bearer …`, `user:pass@host`, `--flag …`) are masked — leaving only the documented
  prose/vocabulary residual (a secret written in prose, or a key-name gap like `sess=` vs `session`).
  The F1 chat reasoning ANSWER is **not** run through that scrubber in the LIVE view: the deterministic
  scrubber runs on the model's INPUT (the session-context block) and on the E1 feed, not on the model's
  free-text answer as it streams. So a structured secret an operator uploaded can appear verbatim in the
  live chat answer and its on-disk transcript — acceptable for a single-operator, loopback, same-origin
  tool reasoning over its own operator's data. **But every point where the transcript LEAVES the operator's
  own view is already scrubbed:** the session dossier scrubs it (`report.dossier.build_session_dossier` →
  `_scrub_jsonl_file`, key-name + value-level; regression-tested by
  `test_no_secret_leaks_into_the_session_dossier`), and a linked chat feeding another model's context is
  scrubbed (`actions._linked_chat_summaries` → `_redact_ctx` + `scrub_log_event`). Uploaded attachment
  bytes are sent to the model UNredacted by design — that is the operator's own consented egress (they
  attached the file to have it analysed; redacting it would defeat the analysis). So the residual is
  strictly operator-local (live view + on-disk transcript); scrubbing those too is optional hardening, not
  a leak.
- **A mid-stream disconnect reloads the saved answer; it never double-charges.** If a streamed reply's
  connection drops *after* the server committed the turn, the client reloads the persisted record (no
  re-send); a pre-response failure falls back to `/api/chat/send` exactly once.
- **The first follow-up in a purely conversational chat answers non-streamed** (the reason-to-stream
  decision runs before the turn is appended); every subsequent turn streams. Benign, conservative.

The doctrine held throughout: **chat proposes, the gate decides; nothing said here is a fact until an
oracle fires; a local model means nothing leaves the machine; and the model's reasoning never wears
evidence's clothes.**
