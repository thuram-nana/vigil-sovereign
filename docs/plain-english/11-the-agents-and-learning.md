# The Automated Assistants, And How The System Improves

This chapter explains two things that often get talked about loosely and should not be.

The first is what the system means by an **agent**. In this system an agent is not a general-purpose
robot that "does security". It is a narrow, specialised automated worker with one job, one output
format, and a written set of things it is not allowed to do — enforced by the code, not by a policy
document.

The second is what the system means by **learning**. It does learn from experience. But the learning
is deliberately confined to one thing: deciding *where to look next*. It is structurally prevented
from changing *what the system claims to be true*. Those two ideas are kept apart on purpose, and
this chapter shows exactly where the wall between them sits.

Both matter to a buyer for the same reason. The value of this system is that its conclusions can be
trusted and independently re-checked. Anything that could let an automated worker — or an
accumulated running average of past experience — quietly manufacture a conclusion would destroy that
value. So the design pushes all of the automation into "propose" and none of it into "decide".

**One word used throughout this chapter.** A **prior** is simply a running tally of how something has
worked out before, kept so the system can make a sensible guess about how it will work out next time.
"This kind of check has found something 3 times in 20 attempts on this kind of target" is a prior. It
is a starting expectation, not a conclusion, and in this system it is never allowed to become one.

---

## 1. What an agent is here, in plain words

Think of a hospital, not a robot.

In a hospital, a phlebotomist draws blood. That is the whole job. The phlebotomist does not diagnose
you, does not prescribe, and does not decide whether you are ill. A radiologist reads the scan and
writes an opinion, but does not treat you. A pathologist runs the laboratory test that actually
settles whether the sample contains the thing everyone suspects. And a separate person entirely — a
consultant with authority — signs off before anything irreversible happens to you.

The system is built the same way. Each agent has:

- **A mandate.** One job, written into the code as a fixed attribute of that agent.
- **A ceiling.** The highest level of consequence it is permitted to reach. Anything above that
  ceiling is not refused quietly — it is parked in a queue for a human to approve.
- **A single output channel.** Agents do not call each other. They write notes onto one shared,
  permanent record, and other agents read that record.
- **A structural inability to do the things it must not do.** Where possible, the forbidden action
  is not blocked by a check; the code path simply does not exist. The clearest example: the
  communications agent that drafts emails has no method anywhere in it that sends anything. There is
  no "send" function to disable, misconfigure, or trick.

Two further points are essential to understanding everything below.

**No agent decides what is true.** Truth in this system is decided by an *oracle* — a small
deterministic automatic test that re-runs over the saved evidence and either fires or does not. An
agent can propose, suggest, argue, or object. It cannot promote its own claim into a confirmed fact.
That separation is covered in depth in the chapter on how the system proves its findings; here it is
enough to know that agents sit entirely on the "propose" side of that line.

**No agent authorises its own actions.** Anything that touches a real system goes through a
permission gate that combines several independent checks. An agent submits a proposed action and
receives a decision. It never marks its own action as approved. Where the code enforces this, it
does so by refusing to call the execution step at all unless the gate returned an explicit yes.

### The shared notice board

Agents on the investigation side communicate through one append-only log, called the *blackboard* or
*event spine*. "Append-only" means entries can be added but never edited or erased. A correction is a
new entry that points at the one it replaces, so the original stays visible.

Three things make that log the backbone of the whole design:

- **Every entry carries its parentage.** Each note records the identifier of the note it was derived
  from. A confirmed finding can therefore be walked backwards: finding → result → action → plan →
  hypothesis → observation. You can always ask "why does the system believe this?" and get a chain,
  not an assertion.
- **The database itself refuses edits.** Beyond the software rule, the storage layer has triggers
  that reject any attempt to update or delete a row.
- **Entries are typed.** There is a fixed list of note kinds, and each kind has a required shape that
  is validated before it can be stored. Fifteen kinds exist in the current code: observation,
  hypothesis, plan, action, result, finding, critique, decision, reward, critic verdict, reflection,
  refusal, tool call, tool result, and agent message. (The module's own older summary document, kept
  alongside the code for developers, still describes the original eight; the code is the current
  list, and it was counted directly from the code for this chapter.)

Note that *refusal* is a first-class kind of entry. When the system declines to do something, or
declines to conclude something, that refusal is written down permanently alongside everything else.
Refusals are treated as evidence, not as failures to be hidden.

---

## 2. The families of assistants

There are six distinct groups, and they exist in different parts of the product for different
reasons. The last one is not made of agents at all — it is the confined workspace an agent is made to
work inside — but it belongs in the same list, because it is the machinery that makes several of the
limits in this chapter real rather than declared.

| Family | Where it lives | What it is for |
|---|---|---|
| The investigation team | The offensive engine (`engine/crucible/framework/v2/agents/`) | Finding and proving security weaknesses in a system the customer owns and has authorised testing on. Described in section 3. |
| The owner's personal mesh | The sovereign side (`apps/sigil/sigil/agents/`) | Running the owner's own operational life and their own defensive posture — briefings, monitoring, research, files, their own infrastructure. Never offensive. Described in section 4. |
| The reasoning body and the parallel team | The integration layer (`integration/vigil_integration/agent/` and `fireteam/`) | Driving a general "think, act, observe" loop and, when asked, running several bounded specialists in parallel. Described in section 5. |
| Proposal-only planners ("brains") and third-party bodies | `integration/vigil_integration/brains/`, `vendor/strix/` | Suggesting what tools to run in what order. They compute nothing that counts as a fact. Described in section 5. |
| The sensor family for testing a customer's own AI application | `integration/vigil_integration/gauntlet/` | Attacking an artificial-intelligence product the customer owns — trying to talk it into ignoring its instructions, revealing its secrets, or producing harmful output. Built, with an important honesty caveat. Described in section 3.7. |
| The confined workspace agents work inside | `integration/vigil_integration/fsjob/` | Not agents. The files-and-background-jobs machinery an automated worker is forced to act through, so that it physically cannot reach outside the folder it was given. Described in section 3.6. |

The two main families — the investigation team and the personal mesh — are kept in separate operating
system processes with separate software environments, and there is a guard that refuses to start the
personal-side process if any offensive module has been loaded into it. The reason is simple: the
personal mesh handles the owner's own credentials and life, and it must never be able to reach the
offensive machinery.

### How many automated workers there are, in total

Chapter 9 gives the reader a screen count so the shape of the interface can be held in mind. The same
is useful here. The figures below were counted directly from the code while this chapter was written,
and the counting rule is stated so a reviewer can repeat it.

| Group | Count | What was counted |
|---|---:|---|
| Investigation team — agents proper | **8** | The eight classes in the offensive agents folder that are built as agents: recon, hypothesis, exploit, critique, reporter, memory, the critic panel, and reflection. |
| Investigation team — further automated workers in the same folder | **3** | The refusal decision, the chain builder, and the impact re-proof layer. These do a worker's job but are not written as agent classes, so they are counted separately rather than quietly folded in. |
| The owner's personal mesh | **9** | Nine named agents, listed individually in section 4. |
| The connective layer | **4** | The general reasoning body; the parallel-team member; the one included proposal-only planner; and the vendored third-party agentic tool. |
| **Total named, permanent automated workers** | **24** | |

Three notes keep that number honest.

- The critic panel is counted as **one** agent, but it runs **three** separate reviewing lenses inside
  itself. Counting lenses instead would give 26.
- The parallel-team member is counted as **one**, because it is a template rather than a named
  personality: a wave is capped at five members with at most three running at once, and the members
  are created for the job and then finish.
- The AI-application sensor family and the confined workspace are **not** counted, because neither is
  an agent. They are, respectively, a set of tests and a place to work.

---

## 3. The investigation team — every agent, its job, its limits

This team works like an assembly line where each station adds one thing and passes it on through the
shared notice board.

The line runs: **look → guess → try → challenge → write up**, with a librarian copying results into
long-term memory.

Sections 3.1 to 3.5 cover the agents themselves. Sections 3.6 and 3.7 cover two things on the
offensive side that are *not* agents but that belong here: the confined workspace an agent is made to
work inside, and the family of tests aimed at a customer's own artificial-intelligence application.

### 3.1 The line agents

| Agent | Its job, in plain words | Its limits |
|---|---|---|
| **Recon agent** | Requests pages and endpoints on the target and writes down what came back — the status, the content type, the server banner, a short excerpt. One request per step. | Does not attack anything. Does not form theories. Does not write findings. Works through a fetching component with a hard cap of 50 requests per intake by default. If a request errors or the budget runs out, it records that as an observation rather than skipping silently. |
| **Hypothesis agent** | Reads each new observation and writes down candidate explanations — "if this application had weakness X, this is what I would see". It is required to produce at least five per observation. | Posts theories only. Confirms nothing. Ignores observations that were themselves low-confidence error records. |
| **Exploit agent** | Takes an open theory and tests it: writes a plan, asks an executor to carry out one action, records the action, records the result, and — only if the result looks like a real bug — writes a candidate finding marked "pending review". | **It never touches a tool directly.** It is handed an executor object and can only ask that. It never promotes its own finding into the report; the reviewer must clear it first. |
| **Critique agent** | The adversarial reviewer. For every pending finding, it walks the provenance chain back to the raw evidence and asks "could this be wrong, and how?" Then it marks the finding confirmed or objected-to. | **Not optional.** Nothing reaches the report without passing through it. Where a finding carries retained machine evidence, the deterministic oracle is the authority and this reviewer is demoted to advisory: if no oracle fires, the finding is not confirmed no matter what the reviewer says. The reviewer cannot rubber-stamp something the oracle refused. |
| **Reporter agent** | Turns confirmed findings into the technical report on disk. | Deliberately conservative. Will not include findings the reviewer flagged. Never touches the executive summary or the remediation plan. Regenerates the whole report each time so the output always matches the current record. |
| **Memory agent** | The librarian. Copies engagement events into the long-term memory store so future engagements can consult them. | Write-through only. Keeps a cursor so a restart does not double-write. |

The forcing rule about five hypotheses deserves a word of explanation, because it looks arbitrary.
The most common failure in security testing is not testing a theory badly; it is never generating the
theory at all. Requiring five candidate explanations per observation is a deliberate anti-tunnel-vision
device borrowed from the project's own written testing doctrine. It costs little and it stops the
system from committing to the first idea it had.

### 3.2 The reviewing and self-checking agents

These sit alongside the line rather than in it.

| Agent | Its job | Its limits |
|---|---|---|
| **Critic panel** | Three independent automatic reviewers examine the same finding through three different lenses and vote. | A verdict may only be *endorse*, *object* or *abstain*. Critics can push a claim down; they can never push one up. |
| **Panel aggregation** | Turns the three verdicts into one outcome. | A single serious objection demotes the claim on its own. Wide disagreement produces an abstention, not a forced verdict. |
| **Reflection agent** | Mid-run self-examination: it notices dead threads and stalls, and writes notes that re-orient the next cycle. | May re-rank or defer. **May never gate out or skip an attack surface.** Deterministic: no language model, no clock, no randomness. |
| **Cognitive refusal** | An explicit "I decline to conclude this" decision, recorded as a permanent typed entry. | Only ever demotes. Never promotes. Never gates a surface. |
| **Chain synthesizer** | Builds multi-step attack stories — "leak a credential here, use it to log in there, reach the database". | Only a step the automatic test confirmed is written down as real. Unproven steps stay theories. |
| **Impact re-proof** | Re-runs the minimal proof of an already-confirmed finding, so the operator can see for themselves that it is real. | Seven gates must all say yes, against a local test target, with a human approving that exact action. |

Each of those rows carries detail that matters, so the rest of this section gives it in full.

#### The three lenses of the critic panel

- **Grounding.** It re-runs the finding's own proof and endorses only if the proof reproduces.
- **Provenance.** It objects if a finding claims to have been machine-verified but carries no
  re-checkable proof behind the claim.
- **Calibration.** It objects if a "confirmed" finding carries a confidence of exactly 1.0 — that is,
  a claim of absolute certainty — and it abstains if a verified finding carries no measured
  confidence at all.

Three limits apply to all three lenses. A verdict may only be *endorse*, *object* or *abstain*: the
word "confirm" is not a permitted value, and the code raises an error if anyone tries to use it, with
the message that only a fired automatic test confirms. Critics may advise, and may push a claim down;
they can never push one up. And a critic that crashes abstains, rather than taking the whole panel
down with it.

#### What the panel does with disagreement

A single serious objection stands on its own and demotes the claim — it is not averaged away against
two endorsements. If the reviewers disagree with each other beyond a set threshold, the panel
**abstains** and routes the item to "needs more evidence" rather than forcing a verdict. Disagreement
is treated as information about the item, not as noise to be smoothed out.

#### Why reflection is the most tightly bounded agent in the system

The reflection agent reads the record and notices two things: a theory that produced no finding (a
dead thread), and a stall (many actions taken, nothing confirmed). It then writes reflection notes
that re-orient the next cycle.

It may re-rank the order of work, and it may defer something. It may never gate out or skip an attack
surface. Its own stall message literally reads "pivot: re-rank to a different surface/technique (do
not skip any)". It is deterministic — no language model, no clock, no random number generator — so
the same record always produces the same reflections. It never touches the proof path.

The cognitive refusal component sits beside it with the same posture. If a finding claims machine
verification but will not reproduce when its proof is re-run, it is routed to "needs evidence" rather
than asserted. It is fail-closed by construction — like a drawbridge held up by power, if the check
cannot be completed the answer is no.

#### What the chain synthesizer is allowed to write down

Each step of a multi-step story must be individually carried out and judged by the automatic test.
**Only a confirmed step is written into the system's picture of the target as real.** Unproven steps
stay theories. A route to a critical asset is reported only when every step along it was
independently confirmed. The chain's certificate is the ordered list of each step's evidence, each
piece separately re-checkable.

#### What the impact re-proof layer will not do

Beyond the seven gates set out below, its exclusions are written into the code as categories it must
refuse rather than build: it creates no new attack inputs, establishes no persistence, and performs
no movement from one machine to another. Evasion, remote command-and-control and implants are listed
by name under the instruction "refuse, never build". If the saved proof no longer reproduces, the
layer records a refusal instead of asserting impact.

#### A word on the calibration critic

The calibration reviewer's job needs one sentence of explanation, because it is unusual. Most software
treats "confirmed" as meaning "certain" and records a confidence of 1.0 — a perfect hundred per cent.
This system treats that number as a warning sign rather than a result. A hundred per cent is a figure
nobody measured; it was assigned by the software to itself. The code's own phrase for it is blunt: a
**laundered number** — a value that has been dressed up as a measurement without ever having been
measured. So the reviewer objects when it sees one, and, separately, abstains when a verified finding
carries no measured confidence at all rather than inventing a figure to fill the gap.

#### A word on the name "impact re-proof"

The file that implements this is called `tier3_validation.py`, and its own notes call it the "Tier-3
validation layer". That name has been avoided in the plain-English table above for one reason: it
would be badly misread. This chapter uses a four-level scale — A0 to A3 — for how consequential an
action is, and A3 is the most dangerous level. **The "Tier-3" in that filename is unrelated to that
scale.** It is an internal development codename for the most tightly-gated slice of offensive work,
and it is not a permission level.

The permission facts are the opposite of what the name suggests. This layer asks for exactly the same
clearance the exploit agent already holds, and no more. The system's clearance ladder has four rungs —
baseline, standard, offensive and advanced — and this layer sits on the third, "offensive", never on
the highest. The code lists the three highest-clearance capabilities by name and states that it never
requests any of them, and there are tests whose whole purpose is to prove those code paths are
unreachable from here.

The seven gates it must clear, in the order the code evaluates them, and the first failure stops
everything and writes a permanent refusal:

1. **The emergency stop.** Checked first. Engaged, or unreadable, means refuse.
2. **A deliberate switch-on.** This layer is off by default, and stays completely inert until an
   operator turns it on for that process. Nothing about the running system changes until they do.
3. **The finding must already be confirmed** by the automatic test, and must still carry the saved
   evidence that test fired on. An unconfirmed finding is refused.
4. **The target must be inside the signed engagement charter.**
5. **The target must resolve to this machine only.** If the address is anything other than the local
   machine, or cannot be resolved at all, it is refused.
6. **The clearance check.** Denied means a refusal is recorded and the code stops loudly, never
   silently.
7. **A human says yes to this specific action.** No answer, or no interactive terminal, means no.

### 3.3 The agents that guard the boundary

| Component | What it does |
|---|---|
| **Scope gate** | A pre-flight check on any network action. It confirms an engagement charter file exists, that the charter carries a real operator signature rather than a placeholder, that the target host matches the charter's in-scope list, and that a destructive action has been classified as such. A refusal becomes a permanent record rather than a crash. |
| **Egress guard** | A deny-by-default allowlist at the network library layer, described in the code as belt-and-braces: if a future code change or a compromised software dependency introduced a new outbound path, it raises rather than quietly connecting. |
| **Record integrity components** | Three small modules that add a tamper-evident cryptographic chain over the shared log, write entries into it, and credit outcomes back to the learning layer. Signing keys are only used at provisioning time; the running system only verifies. |

### 3.4 The executors — how any action actually reaches the outside world

The exploit agent cannot open a network connection. It is handed an *executor* — a separate component
whose only job is to carry out one action and report what happened. Four exist side by side:

| Executor | Used for | What it returns |
|---|---|---|
| Deterministic | Unit tests | A fixed answer from a lookup table. |
| Realistic | Integration tests | Detailed synthetic evidence for three pre-baked scenarios, rich enough that a serious reviewer accepts or rejects it for the right reasons. |
| HTTP | Real engagements | An actual response — status, body excerpt, evidence directory, timing. |
| Verification probe | Producing evidence the automatic test can adjudicate | Two ordinary page requests to this machine only — one plain, one altered — and the pair of real responses, saved so the automatic test can compare them. |

The fourth one is worth a sentence, because it closes a gap that would otherwise be serious. The
automatic tests are the sole authority on whether a finding is real, but a test can only judge
evidence that someone actually collected. This executor is the collector. It sends exactly two page
requests — a normal one and a deliberately altered one — captures both real replies, and hands the
pair over. It refuses any address that is not this machine. It mints no other test inputs, runs no
attack logic, and decides nothing; the code's own words are "It DECIDES nothing. It reports
observations; the oracle is the authority."

The real one passes every single action through six gates. None is bypassable without changing the
code. If any one refuses, the request never leaves the machine and a refusal is written to the record.

1. **A charter file must exist** for this target.
2. **The charter must be signed** by a real named operator. A draft charter is not enough.
3. **The host must be in the charter's scope table.**
4. **Destructive actions require confirmation.** Anything that writes or deletes, and any URL
   containing tokens such as `/admin`, `/delete`, `/upload` or `/payment/`, prompts the operator with
   a 30-second timeout. No answer, or no interactive terminal, means deny.
5. **A per-engagement request budget**, default 100, counted across the executor's lifetime.
   Exhaustion halts the run cleanly.
6. **A speed limit and an identifying label on every request**, both chosen by the operating posture
   written into the charter. These are the same three postures described in chapter 8, and they are
   stated here in the same terms so the two chapters can be read together.

| Posture | Minimum gap between requests | Identifying label on requests |
|---|---|---|
| **TEST** (the default) | 0.2 seconds — about five requests a second | `OBSIDIAN/1.0 (authorized owner-test <date>)` — deliberately identifiable |
| **AUDIT** | 1 second | The same identifiable label, plus a `control-test` marker |
| **EMULATE** | 5 seconds, plus a random extra wait of up to 3 seconds | A realistic web-browser label |

The random extra wait in the third posture is what software people call **jitter**. It means the pause
between requests is not always exactly the same length; a small random amount is added each time. A
perfectly regular request every five seconds is obviously a machine. A real person browsing a website
does not arrive on a metronome. That posture exists for one purpose only — testing whether a
customer's own defence team can spot a realistic-looking attack — and it is the only posture that does
not announce itself.

Two details are worth pausing on. First, the executor **never claims success by itself** — it returns
what happened and the exploit agent decides. Second, the speed limits and the identifying label in the
two normal postures exist because the operator must be able to search their own logs afterwards and
find every request the system made. The system is designed to be *findable in the logs*, not stealthy.
The one posture that does hide is the exception, it must be chosen deliberately in the charter with a
written reason, and it carries extra limits of its own.

There is also a general tool invoker for non-network tools, which runs the same style of chain in a
deliberate order: kill-switch, then entitlement, then charter scope, then destructive confirmation,
then egress allowlist. Every invocation writes its intent to the permanent record *before* it runs,
so even a refused action leaves a trace of having been attempted.

### 3.5 An honest note on this team's operating status

This matters and should not be glossed.

- The **deterministic** parts of this team — the critic panel, reflection, cognitive refusal, the
  scope and egress gates, the record integrity layer, the executors' gate chain — run without any
  language model at all and are exercised by the test suite.
- The **language-model-driven** parts — the hypothesis agent and the critique agent — call a shared
  reasoning layer with a name: the **Universal Reasoning Kernel**. It is worth knowing what it is,
  because it appears again in section 9. The project keeps its testing doctrine as a set of written
  documents in plain prose — how to form a hypothesis, how to critique a conclusion, how to change
  direction when stuck, how to judge severity, how to behave on someone else's network, how to build
  a threat model. The kernel turns each of those written sections into a callable function: it loads
  the relevant piece of the doctrine, asks the language model, and forces the answer back into a
  strict, checked shape rather than accepting free text. Six such functions exist today.

  When no language model is configured, the kernel falls back to a deterministic "dry run" mode. In
  dry-run mode it writes out the exact question it *would* have asked, so the question itself can be
  audited, and returns a fixed plausible answer from a catalogue of pre-written examples. The
  project's own limitations document is explicit that those examples "are not a language model
  substitute". Nine ways of connecting a real language model are shipped alongside the dry-run one,
  two of which run entirely on the operator's own hardware; none of them is required for the
  deterministic parts of the system to run.
- The live reasoning path **has** been exercised for real. The limitations document records a live
  run on 2026-06-27 producing five genuine falsifiable hypotheses for a real observation, and a live
  critique of a real dataflow finding, with honest cost and latency bounds noted (roughly 30–60
  seconds and real subscription cost per call).
- The full autonomous, real-target, finding-discovering loop is **not** claimed. The same document
  states plainly that the planner-and-agents loop has been exercised end to end under a live model
  mainly against fabricated executor evidence, and that the one real-target run of that loop
  (2026-05-05) produced zero findings. Its words: "The subsystems exist; the at-scale, real-target,
  finding-discovering autonomous loop does not yet."
- In the production engine, the default scanning path is a **fixed pipeline** — crawl, audit, confirm,
  chain, score — and it never even loads the autonomous module. The autonomous cycle is opt-in behind
  a flag. When it does run, the only agents wired into it are the **deterministic** ones: the critic
  panel and reflection. The code comments that the language-model-backed critique agent is
  "deliberately NOT wired here to keep the in-loop nervous system deterministic and network-free",
  and names wiring it as a documented future step.

The confirmed findings this product stands behind come from the deterministic scanning and oracle
path, not from an autonomous language-model agent loop. That distinction is the honest one.

### 3.6 The confined workspace — how an agent is stopped from leaving its folder

Several limits in this chapter come down to the same promise: "this automated worker can only touch
files inside the folder it was given". That promise is easy to state and surprisingly hard to keep,
so it is worth showing the mechanism rather than asserting the policy.

**Why the obvious approach is not enough.** The natural way to keep a program inside a folder is to
work out the full, final path of the file it asked for, then check that the answer starts with the
folder's own path. If it does, open the file. That check is correct at the instant it is made — and
that is the problem. Between the moment the check passes and the moment the file is opened, the file
can be swapped. It is the same weakness as a nightclub door where the bouncer checks your ID, hands it
back, and then lets you walk to a second door where nobody checks anything. In the gap, the person who
was checked and the person who walks in can be two different people. Security people call this a
time-of-check-to-time-of-use gap.

The specific trick that exploits it here is a **symbolic link** — a file that is not really a file, but
a signpost pointing somewhere else. If an attacker can replace one folder in the path with a signpost
in the instant between the check and the open, the "confined" write lands wherever the signpost points.

**What the system does instead.** The confinement component in the integration layer refuses to work
from a path written as text at all. It walks the path one step at a time:

- First it checks the requested path on paper, before touching the disk: no null characters, not an
  absolute path, no upward steps that would climb out of the folder, and bounded in length and depth.
  Anything that fails here is refused before a single file is opened.
- Then it opens each folder in the path in turn, and — this is the point — each step is opened
  *relative to the folder it already has open*, not by re-reading the text of the path. Each step is
  opened with an instruction to the operating system that means "if this turns out to be a signpost,
  fail rather than follow it".
- Any signpost anywhere in the path, at any point, is refused outright. The code is explicit about why
  it does not try to inspect a signpost's destination and decide whether it is safe: against an
  attacker who can swap things mid-walk, that contest is unwinnable, so a signpost is simply never
  treated as safe here.
- Finally, the operation itself — the read, the write, the delete — is performed against the folder
  the walk actually ended on, not against the text of the path a second time. There is no second door.

**What is built on top of it.** In the same toolkit: every change to a file is recorded as a signed,
append-only entry carrying the file's content fingerprint before and after, and every change is
reversible, with the undo itself recorded as a further signed entry. If a change cannot be signed, it
is refused or rolled back — there is no unsigned change. Unpacking an archive is hardened against the
three classic archive attacks: entries that try to write outside the folder, entries that are
signposts, and small archives that expand to enormous ones. Background jobs are re-checked against the
same permission boundary a direct call would face, so an agent can never get a tool run by putting it
in the background that it could not have run directly. And a captured-traffic search tool is read-only,
with every result treated as a lead rather than a fact.

**Its honest status.** The confinement component is built, tested, and in use — but the part of it
that is in live use is narrower than the description above, and the difference matters. The automatic
patch-writing loop puts every file path a language model proposes through this component's
written-on-paper checks, so that a proposed fix cannot smuggle in an absolute path, an upward step, or
a path outside the repository. That is a real dependency in a real code path. The step-by-step folder
walk described above, and the recorded reversible file operations, the background job registry, and
the captured-traffic search built on top of it, are **built and tested but not currently wired to any
running agent**. They are capabilities in the product, not components of today's default run.

**One thing it is not.** This confinement component is *not* the mechanism behind the OPERATOR agent's
"scope rings" described in section 4. Those are two different pieces of code in two different halves of
the product, doing the same job in different ways. The OPERATOR's own mechanism resolves the requested
path fully, checks the resolved answer is inside an allowed folder, and then hands that already-resolved
path back to the caller so the caller opens exactly what was checked and never re-reads the original
text — its own way of closing the second-door gap. A reviewer should treat them as two separate pieces
of work with two separate sets of tests.

### 3.7 Testing a customer's own AI application

If a customer has built a product around an artificial-intelligence assistant, that assistant is itself
an attack surface. It can be talked into ignoring the instructions its owner gave it, into revealing
its own confidential setup instructions, into leaking the data it was trained on or has access to, or
into producing content its owner would never sanction. A security assessment that ignored it would be
incomplete.

The system carries a purpose-built family of tests for exactly this. It works by driving four
well-known open-source AI red-teaming programs — garak, PyRIT, Giskard and promptfoo — from outside,
never by loading them into itself. They are run as separate programs and their reports are read back
in, so their heavy and mutually incompatible software requirements stay out of the system, and the
boundary between them is a natural place to strip the environment and cut off network access.

**The rule that matters.** Every result the outside tool reports is sorted into one of two routes,
depending on how the tool decided it:

| How the tool judged it | Route | Why |
|---|---|---|
| By a fixed rule — the answer contained a specific string, matched a fixed pattern, or was sorted by a fixed classifier | **Can become a proven fact.** An independent automatic test re-runs over the tool's saved output, with a fresh unpredictable one-time challenge, and only a confirmation from that test produces a signed fact. | The judgement can be reproduced exactly by someone else. |
| By asking another AI to be the judge | **Always a lead. Never a fact, under any circumstances.** | An AI's opinion is not reproducible, and it is exactly the kind of claim this whole system exists to refuse to launder into a certainty. |

The second row is enforced structurally, not by policy: for an AI-judged result the code returns "lead"
*before it ever calls the automatic test*. There is no path — not a maximum-severity rating, not a
perfect success rate, not even a compromised or hostile automatic test that returned a strong-looking
proof — by which an AI-judged result can be turned into a fact. The success-rate figure the tools
produce is treated as a statistic for the report and never as grounds for promotion.

The categories covered map onto the industry's standard list of AI-application weaknesses. Fourteen
distinct categories are recognised. Nine can produce a proven fact: prompt injection, jailbreak,
encoding-based bypasses, data disclosure, personal-data leakage, supply-chain issues, training-data
leakage, system-prompt leakage, and misinformation. Five are lead-only by design, because the only way
to judge them is a matter of opinion: harmful generation, toxicity, hallucination, bias, and ethical
violations. Anything the tool reports that does not map to a known category also falls to lead-only,
rather than being guessed at.

**The honest status, stated plainly.** All of this machinery is built and tested. **None of the four
outside tools is installed in the current environment, and this machine has no network access to
install them.** The live adapter is written and wired, and when it asks for a tool that is not present
it reports, truthfully, that the tool is unavailable and returns nothing at all — no findings, no
estimates, no fabricated result. The project's own deferred-work register says the same in its own
words: this slice mints no fact from any of those four tools. On top of that, the shipped default
setting for this family restricts it to targets on the local machine only. So: **a built and tested
capability, deliberately not yet exercised against a live AI application, awaiting the tools being
provisioned by an operator.** Chapters 1, 2 and 12 record the same status.

---

## 4. The owner's personal mesh — nine agents, each with a ceiling

This second family runs on the sovereign side. It never performs offensive work. Its purpose is to
run the owner's own operations and watch the owner's own infrastructure.

Everything here is organised around a four-level scale of consequence, which the system calls tiers.

| Tier | Meaning | What happens |
|---|---|---|
| **A0** | Observe or answer. Nothing changes. | Applies automatically. |
| **A1** | A reversible internal act — writing a report, a brief, a record. | Applies automatically. This is the automatic bar. |
| **A2** | Externally visible or only partly reversible — sending something, writing to a calendar. | **Queued for a human.** |
| **A3** | Destructive, financial, or security-relevant. | **Explicit human approval, every time. Never automatic.** |

Every agent proposes actions carrying a tier, and every agent also has its own **ceiling**. A proposal
applies automatically only if it is at or below the automatic bar **and** at or below that agent's own
ceiling. The default ceiling for a new agent is A1.

### The nine agents

| Agent | Its job | Its ceiling and hard limits |
|---|---|---|
| **ARCHIVIST** | Maintains the world model: ingests information, consolidates it nightly, keeps the picture true. Reports how many facts it promoted, how many it demoted for lack of grounding, and how many contradictions it found. | Ceiling A1. Deleting a source record is A3 and, in the code's own words, "effectively never". |
| **SENTINEL** | Perception and monitoring: see everything, report only what matters. Watches the record for bursts of activity and unresolved contradictions, and watches local system health such as low disk. | Ceiling A1 — it writes event records only. Its named failure mode is noise, so it is budgeted. Set out below, under "Three more of the nine, in a little more detail". |
| **STEWARD** | Personal operations: the morning briefing, the commitment ledger, recurring admin. The briefing lists due commitments, open threads, flagged contradictions, and a recent-activity summary. | Ceiling A2 — calendar writes queue until trust is granted. **Every line in the briefing is cited to a specific record number**, and it is composed only from grounded memory. |
| **ENVOY** | Communications: triages inbound messages into urgent, normal, informational, or spam, and **drafts** outbound replies. | Ceiling A2, hard, with **no promotion path ever**. Enforced structurally: there is no method in it that transmits anything. There is deliberately no send function. It writes draft records marked "awaiting-approval". A human sends them, or does not. |
| **ARTIFICER** | Engineering: drives a headless coding assistant against a code repository to own a coding task end to end. | Ceiling A2. **It never pushes code**, and it **runs the tests before claiming it is done**. Set out below, under "Three more of the nine, in a little more detail". |
| **SCHOLAR** | Research and analysis: long-horizon research and sourced synthesis. | Ceiling A1 — research touches no external state. Its discipline is evidential: every claim must carry a source **and a verbatim quote**, and the quote must actually appear in the cited source and be specific enough to matter. A claim that does not verify against its own source is **demoted, not asserted**. |
| **BASTION** | Defensive posture over the owner's **own** infrastructure only: certificate expiry, dependency vulnerability exposure, uptime. | Ceiling A1 — it observes and never fixes anything. **No exploitation, no port sweep, no third-party target.** Set out below, under "A word on BASTION". |
| **OPERATOR** | Opens folders and files and runs terminal commands on request, one transaction at a time. | Ceiling A2. It is the agent that touches the owner's own machine, so it carries the most machinery of any of the nine. Its rules are set out in full below, under "The OPERATOR in detail". |
| **DELEGATE** | The owner's account and identity manager: manages the owner's own credentials and, with per-action approval, creates accounts, logs in, fills forms, submits. | Ceiling A2, and permanently barred from ever being promoted. It is the agent that acts in the world under the owner's name, so its rules are also set out in full below, under "The DELEGATE in detail". |

### Three more of the nine, in a little more detail

Three rows above carry rules that do not compress into a table cell. OPERATOR and DELEGATE, the two
most consequential of the nine, have a full section each after this one.

**SENTINEL, and the discipline of not crying wolf.** Its ceiling is A1: it writes event records and
nothing else. The failure mode it names for itself is noise — a monitor that reports everything is a
monitor nobody reads — so it is budgeted twice over. Each candidate alert is scored for importance and
must clear a threshold (0.5 by default), and each run may raise only a limited number of alerts (ten
by default), highest importance first. Alerts held back by those limits are **counted**, so the owner
can see that suppression happened rather than being quietly left with a short list. Live watchers for
mail, calendar and service uptime are described in the project's own documentation as optional
additions rather than parts of the default installation.

**ARTIFICER, and the rule about running the tests.** Its ceiling is A2, so its output queues for a
human. **It never pushes code**: pushing to a protected branch, deploying, and adding a new dependency
are all A3, the level that always needs explicit approval. Before it will claim a task is done, it
runs the project's tests — a change whose tests fail is reported as failing, not shipped — and it
guards against test commands that would pass trivially, which is the obvious way an automated worker
could otherwise appear to succeed. What it hands back is a branch on the local machine plus a
plain-language summary, for a person to review.

**BASTION, and the limits of a defensive scanner.** BASTION is the only agent in this family that
looks at infrastructure, so its limits deserve to be spelled out rather than compressed.

**It observes and never fixes.** Its ceiling is A1, which is the level for a reversible internal act
such as writing a record. It writes findings about the owner's own systems; it does not change them.

**Membership of a list is the authorisation.** The owner keeps an inventory of their own assets — a
web address and port for a certificate check, a dependency manifest, a service to check is up. Being
on that list is what permits BASTION to look at it. Anything not on the list is refused, and the
refusal is written to the permanent record as a typed refusal entry, with the reason.

**It will not be redirected.** When it fetches a certificate from one of the owner's own hosts, it
refuses to follow a redirection. The reasoning is written into the code: the destination of a
redirection is chosen by the server being checked, which may itself be compromised, and that
destination is not on the owner's list. Following it would let a routine check reach a machine nobody
authorised.

**It never invents a vulnerability.** A dependency is reported only when its version provably falls
inside a published advisory's affected range. If the version or the advisory's bounds cannot be read
with certainty, the result is *no finding* — recorded honestly as something not assessed, rather than
guessed at in either direction.

### The OPERATOR in detail

This is the agent that opens files and runs commands on the owner's own computer. Everything about it
is arranged around one idea: **the owner approves a specific thing, and that exact thing is what
happens — or nothing happens.**

**The transaction.** Every job runs as a six-step sequence: plan, preview, approve, execute, verify,
roll back. The preview stage changes nothing at all; it produces a description of exactly what would
be done. The approval is bound to the content of that preview. Before executing, the agent produces
the preview a second time and compares. If anything has changed in between — the file, the command,
the state of the machine — it stops rather than proceeding on an approval that no longer describes
reality.

**The permission level is worked out, never declared.** The agent does not get to say how dangerous its
own step is. Each step's tool is classified by a separate component, and that component defaults to the
strictest answer when it does not recognise something. The requirement is then worked out again from
the preview at the moment of execution, so a step cannot be classified as harmless early and turn into
something else later.

**Two rings.** The owner configures two nested areas of the file system:

- a **readable ring** — the agent may read here, and may write here with approval;
- a narrower **automatic-write ring** inside it — the only place a reversible write may go ahead
  without asking.

A write or delete that lands inside the readable ring but outside the automatic-write ring is queued
for a human rather than applied. **If either ring is left empty, everything is refused.** That default
is deliberate and is the opposite of the usual convention, where an unconfigured guard tends to permit
everything.

**Undo.** Before it changes a file, the agent saves the original contents, so it can put them back.
When a restore does not work, or when a command that cannot be undone has already run, it says so
plainly instead of reporting success.

### The DELEGATE in detail

This is the agent that acts in the world under the owner's name — creating an account, logging in,
filling in a form, submitting it. It is the most sensitive of the nine, and it is designed so that the
dangerous version of itself cannot be built out of it.

**Every real action needs a fresh, specific human approval.** Creating an account, logging in,
submitting a form, and making a purchase are all at the highest consequence level. The agent's overall
ceiling is A2, and it is on the permanent list of agents that can never be promoted to act on their own.

**It cannot pretend to be anyone else.** There is no setting, parameter or field anywhere in it for
acting as another person. Values that go into a form resolve only from the owner's own credential
store, and any other kind of source is refused at the preview stage — so the owner never approves a
field the agent would quietly drop, and no unrecognised source can reach execution.

**When it is blocked, it stops — and that is treated as a good result.** Websites push back on
automated activity in three common ways, and the agent watches for all three before it does anything:

| What it sees | What it means in plain words |
|---|---|
| A CAPTCHA | The "prove you are human" puzzle — a picture grid, a checkbox, distorted letters. |
| A `403` response | The site's way of saying *forbidden*: it understood the request and is refusing it. |
| A `429` response | The site's way of saying *too many requests*: slow down or stop. |

When it sees any of these, it stops and reports the block to the owner as a **positive control** — that
is, as evidence that the site's own defences are working, which is a useful finding rather than an
obstacle. Crucially, there is no code path in it for escalating to a full web browser to get around a
block. It speaks only the simple request-and-response protocol. So the idea "drive a real browser to
beat the CAPTCHA" is not forbidden by a rule that could be relaxed; there is nothing there to call.

**One approval buys exactly one action.** A step that has already been carried out cannot be carried
out again. An approval therefore cannot be replayed into a stream of repeated form submissions.

**A cap on account creation.** There is a limit on how many accounts may be created per service. It is
checked when the plan is previewed and checked again at the moment of execution, so a batch previewed
before any of it ran cannot outrun the cap.

**Credentials are fetched at the last possible instant.** A password is read from the owner's
credential store only at the moment of execution, into temporary memory. It never appears in the
proposal, is never written to the permanent record, and is never logged. What the permanent record
binds to instead is a description: the service, the address, a fingerprint of the page, the *names* of
the fields, references to vault entries rather than their contents, fingerprints of any literal values,
and the version number of the credential store. If the address changes, or the page changes, or a
password is rotated, or a typed-in value is edited, that description no longer matches and the approval
stops verifying.

### The permanent no-promotion rule

Two of these agents can be given more autonomy over time. Two never can.

The code holds a frozen list — ENVOY and DELEGATE — with the comment "outbound + account actions stay
human-gated forever". It is checked when a promotion is granted **and** mirrored in the read surface
that lists current promotions, so a revoked or refused grant cannot show up in the interface as though
it were live. The user interface states the same rule in plain words on the approvals screen: "ENVOY
and DELEGATE can never be promoted", and the server returns an explicit error if someone tries, so a
refused grant cannot be mistaken for a success.

### Where the operator sees this

Two screens. An **Activity** screen shows, read-only, which agents are active, how many records each
produced recently, and each agent's action budget. An **Approvals and Safety** screen shows what is
waiting for sign-off, the current set of agent promotions with grant and revoke controls, and the
kill-switch. The browser itself holds no signing key — approvals are signed on the server with the
owner's key — and the offensive-side approval queue is displayed read-only, with the exact command to
sign it offered for copying.

---

## 5. The reasoning body, the parallel team, and the planners

Between the two families sits the connective layer.

### 5.1 The reasoning body

This is the general "think, act, observe, repeat" loop. The design problem it solves is that the
open-source pattern it is modelled on lets a language model propose an action and *also* assert that
the action succeeded, then stores that assertion as a finding. This system re-plumbs the same shape
so that cannot happen. Three guarantees, in the code's own structure:

- **Parsing is fail-closed.** The model's raw response is parsed into a strict typed decision and
  *downgraded* to the safest still-valid action on any malformation. A broken request to deploy a
  parallel team never becomes a deploy; a total parse failure pauses for a human. The result is
  explicitly labelled a non-authoritative proposal.
- **Every action-bearing step goes through the permission gate.** The gate is conjunctive — tier and
  authority and, for destructive actions, multi-party approval must all pass. Escalating the
  engagement phase or deploying a parallel team additionally requires a signed human approval. A
  structurally invalid step is denied, not guessed at.
- **The model's success claims become leads, never facts.** If the model says an exploit succeeded, a
  deterministic oracle is re-fired over the retained raw output. Only the oracle's confirmation, with
  a signed evidence reference, produces a fact.

Alongside it sit **cognition governors**: stall detectors, loop detectors, and an honesty auditor.
The honesty auditor is the interesting one — it cross-checks the model's self-reported "I made
progress" against the measured change in state, and downgrades a dishonest progress claim. As the
code puts it, the model cannot lie its way to looking productive. A second governor detects a run of
near-identical, suspiciously fast responses, which usually means the input is being short-circuited
before it ever reaches the component under test; the correct conclusion there is **inconclusive**,
not "tested and safe". That is a deliberate defence against a hallucinated clean result.

The doctrine on these governors is stated in their own file header and is unambiguous: they are
budget and scheduling governors only. They may re-rank, defer, hint, or block an expensive next call.
They may never promote or suppress a fact, and the module does not import or modify a finding at all.

A **checkpoint** component snapshots a run into the signed permanent record so it can be rebuilt and
re-verified later, on the principle that a fact can never be reconstructed without its evidence.

### 5.2 The parallel team ("fireteam")

When a job benefits from several specialists working at once, the system can run a bounded team. The
guarantees the package exists to enforce, all fail-closed:

- A member carries a **capped consequence tier that can never reach the destructive level**, and
  forbidden actions — deploying further teams, escalating the phase, reaching the network — are
  **structurally stripped** out of a member's decision rather than merely rejected.
- A member **cannot escalate itself** or authorise its own dangerous tool. An over-cap or destructive
  request becomes a queued escalation resolved only by a signed operator approval.
- Each member runs under a **credit and deadline budget** driven by an injected counter rather than
  the clock, so runs are bounded and reproducible.
- **All members' writes to the permanent record pass through a single writer**, so the signed chain
  is never interleaved, and records are scrubbed of secrets.
- The roll-up step collects member findings as **leads** and promotes **only** those the oracle
  re-confirmed.

### 5.3 Proposal-only planners ("brains")

A brain looks at a target profile and proposes which tools to run, with what settings, in what order.
The package's own definition: a brain is propose-only; it computes no facts, authorises nothing, and
touches no network.

One brain is included. It is a clean-room reimplementation of a third-party planning model. The
third-party code itself is vendored in a **non-runnable, quarantined** form, with an automated build
check that fails the build if any part of the product imports it. The reimplementation deliberately
omits the original's evasion and stealth features, its credential-poisoning capability, its
web-firewall tampering, and its live exploitation and persistence stages — removed by construction
rather than stripped afterwards. A runtime guard rejects any evasion-flavoured parameter that ever
appears in a proposed tool invocation.

### 5.4 The third-party agent, and an honest scaffold

`vendor/strix` is a vendored third-party open-source agentic penetration-testing tool, carried with
its own licence and attribution. Its role inside this system is as **one of the proposing agents**: it
runs on the offensive side only, and its outputs have to survive the oracle like anything else. Its
ability to run arbitrary shell commands is placed behind the permission gate, and its container is
constrained by the network gateway.

**An honest note on that gate, which a reviewer should not skip.** The gate is *on by default* —
not an optional extra somebody has to remember to switch on — and its attachment fails closed. There
are exactly two ways it can end up absent, and both are deliberate:

1. Someone sets the environment variable that turns it off. This is the deliberate, visible case.
2. The tool is run from a bare copy of the third-party code, without the integration package present.
   In that situation it is standalone software, not part of this system, and there is no governed run
   to protect.

Anything else — a broken installation, a version mismatch, a bug introduced by a later change — makes
the run **stop**, with an explicit error, rather than continue. An earlier version of this code caught
any error at that point and carried on with the unguarded original behaviour, so that a wiring fault
would never stop a scan. That was a fail-open path on the arbitrary-command surface — described
elsewhere in this briefing as the single most dangerous in the system — and it has been removed. The
trade is deliberate and worth naming: a fault in this wiring now costs an availability failure rather
than a silent loss of control.

There is also an `agent_body` interface, and the honest description is in its own file: **it is a
scaffold — an interface only**. It changes no behaviour and wires no engine. It exists to name the
contract a future replacement reasoning body would have to satisfy, so a different planner could be
swapped in without relaxing any safety property. Its three non-negotiable clauses are worth quoting
in plain form: nothing self-authorises; the oracle is the sole authority on whether a finding is real;
an absent or ambiguous permission decision is treated as deny. The class is abstract and cannot be
instantiated.

---

## 6. The gates that bound every agent

These are not agents. They are the fences every agent runs inside. Two of them carry a status caveat
that a reader must not have to hunt for. The hard guardrail is built and tested but was not found to
be called anywhere on the live path — it is marked as such in the table and explained immediately
after it. Parts of the path-confinement toolkit are likewise built and tested but not wired to any
running agent; section 3.6 says which parts, and section 10 repeats it.

| Gate | What it enforces |
|---|---|
| **Tier classifier** | Classifies every action into the four consequence levels, danger-first, with **anything unrecognised falling to the strictest level**. Implemented once in a compiled component and mirrored byte-faithfully in the shared library, pinned by shared test vectors so the two can never drift. |
| **Offensive-tool gate** | Raises every offensive tool above the automatic-approval line, so an autonomous agent can never fire one by itself — it always queues for a human. |
| **Conjunctive gate** | Combines authority (in scope, not halted, within budget), consequence tier, and multi-party approval for destructive actions. **First failure wins, and any error inside any check is a denial.** Only an explicit "auto" verdict passes. |
| **Egress gate** | A firewall plus a forward proxy that together drop everything from the sandbox except the approved path, refuse hosts outside the charter's scope, and refuse a host whose resolved address is on the internal-address denylist. |
| **Destruction gate** | Multi-party threshold approval with a mandatory owner signer fixed at deployment, approvals bound to a specific action, a dead-man's-switch window, and single-use tokens. |
| **Challenge oracles** | A fresh unpredictable one-time challenge per proof, so a recorded attack cannot be replayed to fake a finding. |
| **Per-action approval** | Single-use approval tokens bound to one action, owner-signed, with an expiry and an atomic single-use ledger. |
| **Sovereignty guard** | Refuses to run the personal-side process if any offensive module has been loaded into it. |
| **Path confinement** | Two separate components, one on each side of the product, that stop an automated worker touching a file outside the folder it was given — and that close the gap between checking a path and using it. Described in section 3.6. |
| **Hard guardrail** *(built and tested; live wiring not verified — see below)* | A refusal, which cannot be switched off, of an entire category of targets by name: government, military, educational and intergovernmental addresses. |

### The one gate in that table that is not proven to be running

The hard guardrail must be described precisely, because chapters 1, 3 and 8 describe it the same way
and a reader comparing them should find no daylight between them.

**What it is.** A single component whose only power is to say no. It refuses government addresses
(`.gov` and its national equivalents), military addresses (`.mil`), educational addresses (`.edu`,
`.ac.uk` and equivalents) and `.int`, plus an explicit list of exactly **186** named intergovernmental
organisation addresses that sit on ordinary endings such as `.org` and would otherwise slip past a
rule based on the ending alone. It takes no configuration, consults no artificial intelligence,
touches no network, and cannot be turned off. It can only refuse; it never authorises anything.

**What is honest about its status.** Reading the whole repository for this briefing, the only
references to it outside the component itself and its own tests are the two lines that make it
importable. **No code on the live engagement path calls it.** So it should be described as a built
and tested safety component whose wiring into the running system has not been verified — not as a
control that is demonstrably stopping anything today. The controls that are certainly on the live path
are the signed charter scope check, the permission gate, and the network fence.

**What follows for an agency.** As written, the guardrail would refuse an agency's own estate: it
matches on the name of the target, not on who owns it, so a `.gov` host would be refused whether the
agency was assessing someone else's system or its own. Chapters 3 and 8 set out what an agency would
have to change, and why that change should be a deliberate, recorded decision rather than a
configuration setting.

---

## 7. How the system learns

The system does get better with use. There are five distinct mechanisms, and it is worth being
precise about what each one actually changes.

The one-sentence summary: **learning changes the order in which the system spends its effort, the
honesty of the confidence numbers it displays, and the drafts it puts in front of a human. It never
changes what counts as proven.**

### 7.1 What it remembers between jobs

A persistent memory store records, for every engagement: the engagement itself, findings,
hypotheses, test inputs, **dead ends**, running tallies of what has worked on each kind of target,
and playbook outcomes. Every new engagement can query it.

Its read interface answers three practical questions: which past targets look like this one, which
theories won on targets like this, and which specific test payloads have historically worked for this
class of weakness on this kind of target. Dead ends are recorded deliberately, so the system does not
re-walk a thread it already exhausted.

Two honest bounds, both stated in the system's own documentation:

- **Similarity matching is shallow by default.** The default text-matching component finds past
  engagements with *overlapping vocabulary*, not genuinely similar meaning. A better component
  upgrades it automatically if it is installed. The project documents this as a known limitation
  rather than describing it as semantic search.
- **Recall results carry their sources.** Every result carries the engagement and finding identifiers
  it came from. The project's rule is blunt: an invented running tally is a fatal bug, and these
  functions only return what is actually in the database.

#### Reference material the system reads — and why reading is never learning

Separately from that memory of past jobs, the system carries a small library of reference material:
a searchable corpus of offensive-security write-ups, and a set of written playbooks stored as ordinary
documents. An automated worker can look things up in it.

This is a genuine security problem, and the code treats it as one. Reference material is *text written
by somebody else*. If a language model reads it as though it were an instruction, then anyone who can
get a paragraph into that library can steer the system. This is the attack the industry calls prompt
injection, and it is the same class of problem as a con artist handing a clerk a form with extra
instructions written in the margin.

Three rules apply, and they are worth reading as a worked example of the discipline this document
argues for throughout:

- **Every retrieved passage is wrapped in an explicit "untrusted" marker** before the model ever sees
  it. The module's own words: library content "is a prompt-injection channel, never a fact and never
  an authorization".
- **A playbook grants nothing.** Loading one adds advisory context to the model's prompt. It confers
  no permission level and authorises no action. Playbooks are loaded by identifier through a guard
  that refuses any path outside the playbook folder, and the number that can be loaded is capped.
- **Search ranking is deterministic.** Results are ordered by a fixed word-overlap calculation. A
  language model is consulted only to break a genuine tie, and only then.

There is also a spending and rate meter in the same layer. It is explicitly non-authoritative: it can
only ask for something to be *postponed*. It never decides whether a finding is true — that is the
automatic test's job — and it never authorises an action — that is the permission gate's job.

Success rates are deliberately computed in a way that refuses to be impressed by small numbers. One
success out of one attempt is recorded as roughly two-thirds, not as a hundred per cent — because one
coin toss coming up heads is not evidence that a coin always does. Only as the number of attempts
grows does the recorded rate approach the observed rate.

**How that is done, in plain words.** Before counting anything at all, the system pretends it has
already seen one success and one failure that never happened. It then adds the real results on top.
So a single real success is counted as two successes out of three attempts — roughly two-thirds — and
a single real failure as one out of three. Those two invented starting results are a fixed, tiny
weight: after twenty real attempts they barely move the number, and after two hundred they are
invisible. Their only purpose is to stop a thin record producing a confident-looking figure. This is
a standard and long-established statistical convention for exactly this problem, and the same form is
used everywhere in the code that a success rate is stored.

The rates are recorded after the fact from what really happened; the file says plainly that they are
"never invented".

### 7.2 Learning where to look first

The system keeps a running score for each combination of "what kind of target is this" and "which
check should I try". It draws from those scores to pick what to try next, in a way that naturally
balances trying the thing that has worked before against occasionally exploring a check it knows
little about.

The important properties:

- **Reproducible.** Every random draw comes from an explicitly supplied random-number source. There
  is no hidden global randomness and no reading of the clock. The same scores and the same source
  produce the same choice, every time.
- **Isolated.** Learning about one kind of target never moves the scores for another kind.
- **Warm-startable.** Scores serialise to plain sorted text so they carry across runs.
- **Honest about its own weaknesses.** The module documents that it treats outcomes as independent
  and applies no time-decay, so very old evidence counts as much as fresh evidence; and that similar-
  but-not-identical target fingerprints do not share evidence.

And the limit that matters: what this learns from is *check productivity* — did the deterministic
test fire. The code states why that is legitimate: because this component **orders effort**. It never
gates a surface out and never promotes a finding.

The same mechanism is reused, opt-in, by a coverage-guided scheduler that prioritises payload
families which surface previously-unseen target behaviour. That module carries an explicit "what this
is not" section: it is not an evasion engine. It explores the *target's* response behaviour; it does
not hide from a defender, rotate identity, or shape traffic. Correlatable traffic and a stable
identifiable agent string are preserved exactly as the operating doctrine requires.

### 7.3 Learning how confident to be

There used to be a hardcoded number: a confirmed finding carried a confidence of exactly 1.0, forever,
regardless of what happened to it afterwards. This layer replaces that constant with a probability
**learned from what findings actually turned out to be**, and it measures its own reliability.

- **It is never 1.0.** Probabilities are clamped below certainty. The stated discipline is that a
  detector never claims certainty it cannot have.
- **The boost that machine confirmation earns is measured, not assumed.** The system learns
  empirically how often oracle-confirmed findings really did turn out to be exploitable. If confirmed
  findings historically turned out to be false alarms, that learned figure shrinks and confirmation
  stops meaning certainty.
- **Sparse data degrades to honesty, not to invention.** With fewer than eight usable outcomes, the
  calibration collapses to a pass-through that changes nothing. The stated reason: "We do not invent
  reliability we have not measured." With too few confirmed outcomes, no confirmation bonus is learned
  at all — the file calls this "honest silence over an invented number".
- **Unknown ground truth is excluded entirely.** Outcomes are labelled exploitable, remediated, false
  positive, or **disputed**. Disputed items are excluded from every calculation and every metric. "We
  do not guess ground truth we do not have."
- **Reproducible.** Ordering is by a supplied counter, never a clock, so every calculation is
  byte-stable and replayable.

There is one more anti-circularity rule here, and it is the strongest statement of its kind in the
codebase. When an outcome is fed back to the learners, the label "this was genuinely exploitable" is
only assigned on **genuine corroboration from at least two distinct kinds of automatic test**.
Everything else is labelled disputed and excluded. And critically: **a silent test is never
automatically labelled a false positive**, because that would be the test grading its own homework.
Real "exploitable" and "false alarm" labels come only from an independent judge, and there are exactly
two: a set of deliberately planted test cases whose right answers are already known, or the operator.
Neither of them is the machinery being graded.

The same file states that signals from language models and from the critic panel **never enter this
path at all**.

### 7.4 Learning what it cannot do yet — and proposing, never applying

Several components look for the system's own weaknesses and write down what they find. **Every one of
them proposes. Not one of them applies a change to the system by itself.** Three do the main work and
are described first; the others follow.

The first mines three real, computable shortfalls:

- a **missing check** — a weakness class the verification layer knows how to adjudicate but which no
  active check produces evidence for. The confirmation machinery exists; the producer does not.
- **low recall** — a class that a ground-truth benchmark shows the scanner missing.
- **low confirm-rate** — a class whose findings mostly resolved as not exploitable, which is a
  precision problem.

Each becomes a structured written proposal. The suggested verification method is taken from the
verifier's own routing table, so a proposal can never suggest a check the system cannot actually run.
The file states there is deliberately no function in it that writes code or modifies the framework.

The second is the gate where deployment is held. A proposal may be merged only when **all three** of
these hold: the deployment holds the specific self-improvement capability; the candidate build passed
its regression tests; and at least a threshold number of governance authorisers have signed the
proposal's exact content. Even then, the gate **only authorises** — it does not touch the working
tree. The file explains why in one line: "An uncertifiable, unattributable, self-mutating offensive
tool is exactly what this gate exists to prevent."

There is a further set of checks behind that gate which is not about learning at all, but which any
proposal would eventually have to pass, because it applies to every change to this software. The
project's build-and-release safeguards were accepted into the released version on 12 August 2026 and
now run against every proposed change: every third-party package is pinned to an exact version and to
a fingerprint of the exact file; every starting container image is pinned by its contents rather than
by a movable label; a bill of materials records what went into the build; and an automated
vulnerability check blocks a change outright on a CRITICAL finding while reporting lesser ones as
advice. Chapter 6 describes those safeguards in full, including the boundaries the project has written
down rather than glossed. The point for this chapter is narrow: a self-improvement proposal is not a
private path into the product. It arrives at the same door as any other change.

The third is the bounded self-evolution loop, which is unusually candid about itself. It scans
publicly *disclosed* vulnerability information, derives capability gaps, and turns them into **draft**
proposals. It records its predictions so they can be scored later against what real engagements
actually find. Its own list of things it does not do: it does not forecast undiscovered
vulnerabilities, does not prove any vulnerability exists, does not fire a verification test, does not
mint a fact, and does not apply a change to itself.

Its own definition of getting smarter is worth quoting and then translating. The code says: "better-
calibrated priors + more PROPOSED coverage, never self-applied canon." In plain words: *getting
smarter means my running expectations about what works get closer to what really happens, and I write
down more suggestions for things the system cannot yet test — it never means I get to decide, on my
own authority, what the system now treats as settled truth.* "Canon" here is the settled body of what
the system holds to be true; "self-applied" would mean writing into it without anyone else's
agreement. That is exactly what this component is forbidden to do.

It is also candid about what its own completion signal means. When it reports that it has "studied
everything in scope", that means every publicly disclosed weakness it was given has been drafted
against — not that the system is complete.

A related component turns engagement history into capability gaps — a weakness class that memory
associates with this kind of target but which nothing this run even tried, a discovered surface no
theory touched, a theory that was never executed, a thread that was tried and could not be confirmed.
Another explicitly refuses to fabricate: a proposal's code change is left **empty** unless a human
fills it, on the stated basis that describing a change precisely without pretending to have written
code you did not write is the honest output.

#### The one place where the system does build a new check for itself

There is a component that goes one step further than a written proposal, and because "the tool writes
its own tests" is exactly the sentence that should worry a reviewer, it is described here with its
limits attached.

It can assemble a new **check** for a weakness class the system currently has no producer for. What
it assembles is not new program code. It is a filled-in form: a test input, the shape of the automatic
test that will judge the result, and the name of the weakness class — chosen from a small fixed set of
patterns the system already knows how to run. Weakness classes whose confirmation needs something
target-specific, or an out-of-band channel, are declined outright, and the component returns nothing
rather than improvising.

Before such a check may even be *proposed*, it must pass a two-sided examination: it is run against a
deliberately vulnerable practice target and against a safe twin of that target, and it is accepted
only if it confirms on the vulnerable one **and** stays silent on the safe one. That is the standard
form of a control experiment — a test that fires on everything proves nothing. After that, it still
goes through the merge gate described above: the capability, a green test run, and threshold
governance signatures.

Two honest bounds. First, the safety does not rest on this component being clever: the automatic test
remains the sole judge of any confirmation, so a poorly synthesised check cannot manufacture a false
finding — at worst it wastes effort, which the two-sided examination is there to catch. Second, its
status: the component is built and tested, and is exported by its package, but no live scan path calls
it today. It is a capability that a human would have to invoke, not something running by itself in the
background.

### 7.5 Learning across the boundary between the two sides

There is exactly one path by which the owner's personal side can cause the offensive side to learn
anything, and it is deliberately narrow.

When the owner **approves** a queued learning proposal, the personal side signs a small inert
envelope — essentially a signed pointer, not the content — and drops it into a shared directory. The
producer exports nothing at all unless the kill-switch is released **and** a specific automatic-learning
capability is switched on.

The offensive side drains that directory, verifies each envelope under the **owner's public key**, and
then re-derives the actual content **from its own intelligence store** using the identifier in the
envelope. The result is a set of advisory notes, mapped only onto verification methods that already
exist. It mints no fact and moves no statistical prior.

The failure behaviour is fail-closed at every step: a bad or absent signature, the wrong key, a
malformed file, or any error at all moves the file to a rejected folder and **nothing is learned**. If
the offensive side's own kill-switch is engaged, the grant is *deferred* and moved back to be retried,
never silently dropped. The signed fields are reconstructed from a fixed list before the signature is
checked, so a hostile extra field cannot ride along inside the signed bytes.

The threat is bounded and stated plainly in the code: a tampered version of this channel could at
most cause an advisory note about a vulnerability that was already in the offensive side's scope. It
could never cause a false fact and never cause code to run.

### 7.6 Learning is off by default

Persisting anything learned from a run is an explicit opt-in flag. The help text says so and says
why: it modifies the target's directory. With the flag off, a run leaves the learned state untouched.
Under the fully ephemeral mode — used when nothing at all should persist — the flag is forced off
before anything opens, along with the permanent record and the outcome ledger.

---

## 8. The hard rules on learning

This is the list a reviewer should check. Each one is a real constraint in the code, with the place it
lives.

| Rule | Where it is enforced or stated |
|---|---|
| Learning may **never** promote a claim into a fact. The claim-admission layer can only demote or abstain. | The veracity firewall; the truth bridge; the reasoning body; the runtime doctrine. |
| The effort-ranking mechanism may **never** gate out an area or promote a finding. It only orders effort. | The reward fan-out. |
| Reflection may **never** gate or skip an attack surface. It may only re-rank or defer. | The reflection agent; the runtime doctrine. |
| A silent verification test may **never** be automatically recorded as a false positive. | The reward fan-out: two distinct corroborating test kinds are required, otherwise the outcome is "disputed" and excluded. |
| Language-model and critic signals may **never** enter the reward path. | The reward fan-out. |
| Critics may object or abstain. "Confirm" is not a value a critic can return. | The critic panel — the type itself rejects it. |
| Cognitive refusal only demotes or routes to needs-evidence. It never promotes, and never gates an area. | The cognitive refusal module. |
| A calibrated confidence may never reach certainty, and below eight measured outcomes it changes nothing. | The calibration layer. |
| Self-improvement may not apply itself. A merge needs the capability, a green regression run, and threshold governance signatures — and even then it only *authorises*; a human applies. | The merge gate. |
| The self-evolution loop drafts only. It never merges, never mints a fact, never fires a verification test. | The self-evolve module. |
| Cross-boundary learning grants mint no fact, shift no running tally, map only onto verification methods that already exist, and require both the kill-switch released and the automatic-learning capability enabled. | The producer and consumer of the learning seam. |
| Reference material fed to a language model is never treated as fact or as permission. Every retrieved passage is wrapped in an explicit "untrusted" marker before the model sees it. | The knowledge and skills layer. |
| Parallel team members may not escalate their own consequence tier or authorise their own dangerous tool, and their cap can never reach the destructive level. | The parallel team package. |
| The world model and the calibration layer never read the clock; they order by a supplied counter. | The world model and calibration documentation. |
| Observability reports; it never gates. | The observability layer. |

The single most important sentence in that table is the third one. It is easy to build a system that
learns "this area never yields anything, stop looking there" — and that is precisely how an automated
tester quietly stops covering something it was told to cover, while its reports still look complete.
This system forbids that specific behaviour by name. Coverage is mandatory; an area can be
deprioritised, never silently dropped. Its own stall-response message spells it out: re-rank to a
different technique, **do not skip any**.

---

## 9. Self-criticism and second opinions

Four mechanisms, layered.

### 9.1 The standing doctrine

There is a short written doctrine that the system states is in force on every reasoning call, above
any individual task, and that wins when a task instruction conflicts with it.

It is worth saying where this doctrine physically lives, because it is not a poster on a wall. It is
loaded by the Universal Reasoning Kernel — the shared reasoning layer introduced in section 3.5. Every
time the system asks a language model to think about something, the kernel loads the relevant written
section of the doctrine and sends it as part of the question. The doctrine is therefore not advice a
developer is expected to remember; it is text that is mechanically attached to every reasoning
request. Its six rules, in plain terms:

1. **Prove, don't guess.** A claim is a fact only when a deterministic test has fired. The reasoning
   layer advises; the test confirms. Never label something confirmed on your own confidence, a model
   vote, a critic's endorsement, or a plausible story. When no test can settle a claim, say so and
   treat it as a labelled hypothesis.
2. **Reflect in the loop.** Run fast observe-orient-hypothesise-test-update cycles. Re-orient by
   re-ranking or deferring — never by skipping an authorised area.
3. **Submit to the critics.** Before concluding, submit the conclusion to adversarial critique from
   several angles. A single well-founded objection demotes the claim. When critics disagree, abstain
   rather than assert through the disagreement.
4. **Refuse honestly.** Refuse to conclude what cannot be grounded. Refusals are evidence: record
   them, never hide them. Hard limits — scope, authorisation, destruction, real user data — are never
   relaxed to make progress.
5. **Vote against yourself.** On judgments no test will ever settle, prefer the answer that is stable
   across independent attempts. Disagreement between your own attempts lowers confidence or triggers
   abstention. **It may never raise confidence, and it never overrides a test.**
6. **Learn, don't fabricate.** Never fabricate a confidence, a coverage guarantee, or a corroboration
   you do not have. A number you did not measure is not evidence: label a placeholder as a
   placeholder, a heuristic as a heuristic, an estimate as an estimate.

**What this doctrine is, and what it is not.** It is instruction given to a language model. Attaching
it to every request makes the standard consistent and auditable — anyone can read exactly what the
model was told — but text in a request is guidance, not a guarantee, in the same way that a written
procedure handed to a new member of staff is not the same thing as a locked door. The code is candid
about this too: if the doctrine document were missing, the block would simply be empty and the request
would still go out. The rules in the list above are made *binding* by machinery elsewhere, described
throughout this chapter — the automatic tests that alone decide truth, the deterministic critic panel,
the refusal component, the permission gates, and the re-execution firewall in section 9.4. The
doctrine tells the model what standard it is being held to; the machinery enforces it whether the
model cooperates or not.

### 9.2 The second opinion — the critic panel

Three independent automatic reviewers with different lenses, as described earlier: does the proof
still reproduce, does a claim of machine verification carry actual re-checkable proof, and is the
confidence a real measured number rather than a hardcoded certainty.

The aggregation rule is the interesting part. It is not a majority vote in the ordinary sense. A
single serious objection stands on its own. And if the reviewers disagree with each other past a
threshold, the panel **abstains** and routes to "needs more evidence". The design treats disagreement
between reviewers as a signal that the item is not settled — the opposite of averaging the
disagreement away.

These reviewers are deterministic: no model calls, no network, no cost. That makes them replayable —
you can re-run them over the same record and get the same verdicts.

### 9.3 Voting against yourself

This is not a seventh function of the Universal Reasoning Kernel described in section 3.5. It is a
*mode* in which four of its six functions can be run — hypothesis generation, severity judgement,
changing direction, and threat modelling — and it is the mechanism behind rule 5 of the doctrine above.

For judgments no automatic test can ever settle — the severity of an issue, its business impact, the
plausibility of a multi-step attack story, the generation of reconnaissance theories — there is
nothing to re-fire. So the system uses a different device: ask several times, then group the answers
by what they actually *decide* rather than by how they are worded, and either return the answer the
attempts agree on or abstain when they do not. Grouping by decision rather than by wording matters: two
answers written in completely different sentences may reach the same conclusion, and the system must
count those as agreement, not as a disagreement caused by prose style.

The reasoning is stated directly in the code: a lone confident fabrication and a stable fact look
identical in a single sample; across several they do not, because a fabrication scatters and a real
inference clusters.

The hard rule attached to it: this applies **only** where no automatic test exists. Where a test can
settle the claim, the system stays single-shot, because a self-consistency vote must never promote a
claim that a test refused. The mechanism produces an abstention signal and a confidence penalty. It
never manufactures confidence.

### 9.4 The re-execution firewall

There is one further layer, and because this briefing leans on it hard it is described here exactly —
including where it does *not* reach.

**What it does.** It takes a claim — typically "this finding is a proven fact" — and refuses to
believe what the claim says about itself. Instead it re-runs the evidence the claim cites and sees
whether the same answer comes out. The everyday parallel is a laboratory that will not accept
somebody else's certificate of analysis and insists on re-testing the retained sample.

**Two bindings that are easy to overlook.** The proof must be *bound to the claim it backs*: a proof
of one kind of weakness cannot support a claim about a different kind. And a claim that asserts a fact
must name what it is about — in the code's own words, an unbound proof grounds nothing.

**It can only take claims down.** It can turn a fabricated "confirmed" into "ungrounded". It can never
promote a claim that a test refused. Claims that do not survive are relabelled as ungrounded
commentary — labelled, but never dropped from the record. That is what makes a fabricated finding
structurally unshippable rather than merely discouraged.

**Where it is wired, stated precisely.** This is the point at which a briefing can easily overclaim,
so here is the position as the code has it, checked directly for this chapter. The layer runs:

- during an engagement, as each finding is admitted against the system's accumulated picture of the
  target;
- at report generation, through a single shared grounding authority that both the reporting agent and
  the scan orchestrator call, so a report and the agent grade the same finding identically;
- in the defensive half of the platform, sitting between the automatic test and the final verdict;
- in the grounding critic, in the refusal component, in the agent tool surface, and in the scanner's
  own report path.

At report time it is also fail-closed: if the re-check cannot be completed at all — any error, for any
reason — the finding is not rendered as a fact. It is presented as a lead.

**Where it does not reach.** It is **not** today a single universal checkpoint that every claim in the
system crosses. The main exception is the system's internal picture of the target — the map described
in chapter 10. Entries are written into that map without being routed through this layer. Instead,
each entry is labelled according to where it came from, using the very same shared classifier the
firewall itself consults when deciding what counts as proof. So the definition of "grounded" is
identical in both places; the difference is that the map's write path *applies the label* where the
firewall *re-runs the proof*.

One more honest note, because it is the kind of thing a reviewer will find. The component's own
internal comment still describes it as a building block exercised only by its own tests. **That
comment is out of date**, and this chapter states what the code does rather than what the comment
says. Chapter 4 gives the fuller treatment, and the same discrepancy has been flagged to the
engineers.

---

## 10. Honest status summary

Because this chapter describes automation, it is worth restating plainly what is running, what is
built but not yet exercised in the field, and what is a scaffold.

**Fully working and exercised:**

- The append-only shared record with parentage links, database-level refusal of edits, typed entries,
  and a tamper-evident cryptographic chain.
- The deterministic reviewing agents: the three-lens critic panel with abstain-on-disagreement,
  reflection, and cognitive refusal. These are the agents actually wired into the opt-in autonomous
  cycle in the production engine.
- The gate chain on real actions: charter presence, charter signature, scope, destructive
  confirmation, request budget, rate limiting and an identifiable agent string; plus the general tool
  invoker's kill-switch, entitlement, scope, destructive-confirm and egress chain.
- The consequence-tier system, agent ceilings, and the queue-for-human behaviour on the personal side,
  including the structurally enforced permanent no-promotion rule for the two most sensitive agents.
- The learning mechanisms themselves — the memory store, the effort-ranking scores, the calibration
  layer with its sparse-data fallback and its exclusion of unknown ground truth, and the
  proposal-drafting components — all deterministic and all reproducible.

**Built, but honestly bounded:**

- The language-model-driven agents (hypothesis generation and adversarial critique) run in a
  deterministic dry-run mode when no model is configured, and the project documents that the dry-run
  fixtures are not a model substitute. The live reasoning path has been exercised for real with
  recorded results, cost and latency.
- The full autonomous, real-target, finding-discovering agent loop is **not** claimed. The project's
  own limitations document records that it has largely been exercised against fabricated executor
  evidence and that its one real-target run produced zero findings. The confirmed findings the product
  stands behind come from the deterministic scanning and verification path.
- Live monitoring sources for the personal-side monitoring agent (mail, calendar, uptime probes) are
  described as optional additions rather than defaults.
- The live client that would speak to an external tool-server is a pending seam; the manifest and
  validation layer around it is built.
- The family for testing a customer's own AI application (section 3.7) is built and tested, including
  its live adapter and its rule that an AI-judged result can never become a fact. **None of the four
  outside red-teaming programs it drives is installed here, and there is no network access to install
  them.** When a tool is absent the adapter returns nothing rather than estimating. This is a
  capability awaiting provisioning by an operator, and it has minted no facts.
- The confined workspace (section 3.6) is built and tested throughout. The part in live use is its
  written-on-paper path checks, relied on by the automatic patch-writing loop. The step-by-step folder
  walk, the recorded reversible file operations, the background job registry, and the captured-traffic
  search are **not currently wired to any running agent**.
- The gate over the vendored third-party tool's arbitrary-command surface (section 5.4) is on by
  default and fails closed: an error while attaching it stops the run rather than letting the scan
  continue ungated. The two ways it is legitimately absent are both deliberate — the explicit
  environment opt-out, and a bare copy of the vendored tool run outside this system.
- The re-execution firewall (section 9.4) is wired into real production paths — the engagement run,
  report generation, the defensive pipeline, the grounding critic, the refusal component, the agent
  tool surface and the scanner's report path — and it is fail-closed at report time. It is **not** yet
  the single universal checkpoint every claim in the system crosses: the write path into the system's
  internal picture of the target labels entries by their origin, using the shared classifier, rather
  than re-running their proofs.
- The categorical hard guardrail (section 6) is built and tested and cannot be switched off, but no
  live call site was found on the running assessment path. It should be treated as a shipped safety
  component whose wiring has not been verified, not as a control demonstrably blocking anything today.
  Chapters 1, 3 and 8 record the same status.
- The component that assembles a new check for a coverage gap (section 7.4) is built and tested, and
  must pass a vulnerable-target and safe-twin examination before it may even be proposed. No live scan
  path calls it; a person would have to invoke it.
- The build-and-release safeguards behind every change to this software — exact-version and
  exact-file pinning of third-party packages, container images pinned by contents, a bill of
  materials, and a check that blocks a change on a CRITICAL vulnerability — were accepted into the
  released version on 12 August 2026 and now run on every proposed change. The project records the
  boundaries that remain: the eight older build jobs still install loose version ranges rather than
  the fixed lists, and one bill-of-materials file is still a placeholder, which was confirmed directly
  in the released version. Chapter 6 has the detail.

**Scaffold, and labelled as such in the code:**

- The pluggable next-generation reasoning-body interface. It is an interface only, cannot be
  instantiated, and changes no behaviour. It exists so a future body could be swapped in without
  relaxing any safety property.

The reason to state all of this rather than round it up is the same reason the system refuses to round
up its findings. A reviewer who checks these claims against the code should find them accurate,
including the unflattering ones.
