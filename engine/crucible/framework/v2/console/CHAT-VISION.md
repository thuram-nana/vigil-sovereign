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
