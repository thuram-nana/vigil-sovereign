# How To Read This Briefing: Contents, Status, And Glossary

*This is the front page of the VIGIL briefing. It is not a chapter about the system; it is the map
of the other thirteen. It tells you who the briefing is for, how long it is, what order to read it
in, and where each subject lives. It also carries three things that exist nowhere else in the set: a
single consolidated statement of what is finished and what is not, a glossary of every technical word
the chapters use, and a plain account of how the briefing was written and how to check it. Read this
page first. It takes about twenty minutes and will save you several hours.*

---

## 1. What this briefing is

This is a written description of a security testing system called **VIGIL**, prepared for a reader
who is senior, intelligent, and not a software engineer. It was written by reading the system's
actual source code, not its marketing material.

**The set is fourteen files: this index, and thirteen chapters.** The file names carry the order —
`01-…` through `13-…`. Each chapter takes one subject and covers it in full. This page is the only
place the set is enumerated, so if you were handed a single chapter on its own, this is the page that
tells you what the rest of it is.

**The briefing has one governing rule, and it is the same rule the product itself is built around:**
never say more than the evidence supports. Where something is finished, the briefing says so. Where
something is built but has never been used against a real outside system, the briefing says that
instead, and names exactly what it is waiting for. Where something is deliberately not built, the
briefing says why. That distinction is drawn on every page, and section 8 of this index collects
every instance of it into one table.

**Who it is written for.** Government officials, policy leads, procurement officers, auditors,
oversight bodies, and senior security managers who need to understand what this system does, what it
proves, what it does not prove, and what it would cost them to run. No software background is
assumed. Every technical word is explained the first time it is used, and again in the glossaries at
sections 11 and 12.

**What it does not contain.** It is not a user manual, not an installation guide, and not a sales
document. It does not tell you how to attack anything. It contains no working attack instructions.

**Two neighbouring folders.** Alongside the chapters sit two working folders that are *not* part of
the briefing. `_review/` holds the three independent review notes described in section 10.1.
`_inventory/` holds the raw working inventories compiled from the code while the chapters were being
written. Both are kept so that a reader can see the workings, not just the result.

---

## 2. What the system is, in one paragraph

So that this page stands on its own:

VIGIL is a system that attacks computer systems its operator owns, or has written permission to
test, in order to find the weaknesses before a real attacker does. It uses artificial intelligence
to decide what to try next. It does **not** use artificial intelligence to decide what is true. A
suspicion becomes a confirmed finding only when a small, separate, non-intelligent **checker** —
a fixed program that gives the same answer every time — re-proves it from the evidence that was
captured at the time. That evidence and that proof are then sealed into a signed document. Anyone can
re-run the check later, on their own machine, with no internet connection, and — for the largest part
of the check — without installing any of VIGIL's software at all. If the check does not come out the
same, the claim is withdrawn automatically. About any given question the system may say only four
things: **proved**, **suspected**, **conclusively disproved**, or **could not tell**. "Probably fine"
is not an available answer.

Chapter 1 expands this paragraph into a full account of the problem and the design.

---

## 3. How long the briefing is

| | Approximate size | Rough reading time |
|---|---|---|
| The thirteen chapters together | About **213,000 words**, roughly 18,900 lines | Fourteen to eighteen hours |
| A typical chapter | 13,000 to 21,000 words | One to one and a half hours |
| The longest chapter (9, the screens) | About 20,700 words | About an hour and a half |
| The shortest chapter (7, signatures and keys) | About 13,100 words | About an hour |
| This index | About 13,000 words | About twenty minutes |

**These figures are a snapshot, and they are rounded on purpose.** The chapters were still being
revised on the day this page was compiled, and the total grew by several thousand words during the
writing of this section alone. Treat the numbers as an indication of scale, not as a fixed fact. To
get the current figures, count the words in the folder — on an ordinary Linux or Mac command line,
`wc -w docs/plain-english/*.md` prints one line per file and a total.

Nobody is expected to read all of it in order. Section 5 gives three routes through it.

---

## 4. The contents

Each chapter is a separate file in this folder and is written to be read on its own. That is why
some ideas — particularly the four verdict words in section 7 below — are re-explained in several
chapters. If you are reading straight through, you may skip those repetitions.

Word counts are rounded snapshots, for planning your time only.

| # | File | Title | What it answers | Approx. |
|---|---|---|---|---|
| 1 | `01-what-this-is.md` | What This System Is, And The Problem It Solves | What is it, why does it exist, what makes it different, the two conditions a government reader must settle first (licensing, and a built-in refusal to test government hosts), what it refuses to do, and what is honestly unfinished | 16,000 w |
| 2 | `02-the-parts.md` | The Parts Of The System And How They Fit Together | The named components, the wall between the attacking half and the key-holding half, what runs on which machine, where the information is actually stored, the programmatic ways in, and why possessing the software is not possessing the capability | 14,000 w |
| 3 | `03-an-operation-end-to-end.md` | How A Security Assessment Runs, From Start To Finish | The whole job in eleven stages: written permission, the session, set-up, pre-flight, discovery, mapping, testing, confirmation, the attack picture, the report, the re-test — and everything that can stop it mid-way | 16,000 w |
| 4 | `04-leads-and-facts.md` | Leads And Facts: How The System Decides Something Is Real | The single most important chapter. What separates a suspicion from a proved finding, why the artificial intelligence is never allowed to make that call, what "confidence" means, and precisely which problem this does *not* solve | 15,000 w |
| 5 | `05-weakness-types.md` | Every Type Of Weakness The System Can Find | The complete catalogue: 85 named categories of weakness, the 38 confirming checkers, defensive detection from the customer's own logs, which claims may be stated as a proved *absence*, the attack library behind it, and what the catalogue does not cover | 20,000 w |
| 6 | `06-evidence-and-proof.md` | Evidence: How It Is Collected, Shown, And Independently Re-Checked | What is captured, how it is sealed, what a report contains, exactly how a stranger re-checks it offline, what happens if a byte is altered, how evidence is kept and destroyed, and the safeguards over the system's own build | 20,000 w |
| 7 | `07-signing-and-keys.md` | Signatures And Keys: Who Vouches For A Result | Digital signatures in plain terms, who holds which key, how keys are protected, what happens when one is lost, several-people-must-approve, the trust root, rollback defences, and where the guarantees stop | 13,000 w |
| 8 | `08-safety-and-authorization.md` | Safety, Authorization, And What The System Refuses To Do | Written authorisation, scope enforcement, permission tiers, human approval, the emergency stop, not harming the target, the complete list of deliberate refusals — then the question turned round: who could attack VIGIL itself, and how its own build is assured | 18,000 w |
| 9 | `09-the-screens.md` | Every Screen, And How An Operator Uses It | A guided tour of all 28 screens, the capabilities that have no screen at all, an honest list of every control that does less than it appears to, the other ways in, and the command line | 21,000 w |
| 10 | `10-the-picture-of-the-attack.md` | The Knowledge Graph: Building A Picture Of The Target | How the system draws a living map of the target, labels where every entry came from, works out attack routes, and identifies the single fixes that break the most attacks | 14,000 w |
| 11 | `11-the-agents-and-learning.md` | The Automated Assistants, And How The System Improves | Every automated assistant, the ceiling on what each may do without a human, the gates that bound them, and how the system learns without ever being allowed to promote its own claims | 14,000 w |
| 12 | `12-tools-and-what-you-need.md` | The Tools It Uses, And What You Need To Run It | The 33 outside tools and what each is permitted to claim; then the complete shopping list — licence, hardware, accounts, credentials, network access, day one, backup and restore, and what leaves your organisation | 17,000 w |
| 13 | `13-defence-and-source-code.md` | The Defensive Side, Source-Code Review, And Network Handling | Five subjects: the defensive firewall, reading a customer's source code, producing a fix, encrypted connections and certificates, and proving a fix actually worked | 16,000 w |

---

## 5. Three ways to read it

Pointers below name a chapter and the **title of a section inside it**, not a section number. Section
numbers move when a chapter is revised; titles are stable. If a title has changed, search the chapter
for the nearest wording.

### Route A — thirty minutes, to decide whether this is worth your time

1. Section 2 of this page (one paragraph on what the system is).
2. Section 8 of this page (the master status ledger — what is finished and what is not).
3. Chapter 1, the section headed **"The short version"**.
4. Chapter 4, the section headed **"The chapter in one page"**.

That gives you the claim, the evidence for the claim, and the honest limits, in four short reads.

### Route B — half a day, to brief a minister or write a procurement recommendation

Read Route A, then, in this order:

1. **Chapter 1** in full — the problem, the design, the two conditions a government reader must
   settle first, and the honest status.
2. **Chapter 4** in full — why a finding from this system is different from a finding from any other.
3. **Chapter 8** in full — authorisation, scope, refusals, who could attack the system itself, and
   where the limits genuinely are.
4. **Chapter 6**, the sections headed **"Handing the evidence to an independent third party"** and
   **"A reviewer's checklist"** — how an outside party checks the evidence, and the checklist to work
   through.
5. **Chapter 12, Part Two** — what you actually need: licence, machines, accounts, credentials,
   network access, and what it costs to keep running.
6. **Section 9 of this page** — the two facts that affect a government buyer before anything else.

### Route C — the full read, in the order the chapters are numbered

The numbering is a deliberate sequence: what it is (1), what it is made of (2), what it does (3),
how it decides what is true (4), what it can find (5), what it produces (6), who vouches for it (7),
what stops it (8), what it looks like (9), how it reasons about a whole estate (10), what it
automates (11), what it needs (12), and what it does on the defensive side (13).

If you are technical and want to verify rather than understand, read chapters 4, 6, 7 and 8, then
section 10 of this page.

---

## 6. Where to find each subject

The chapters were written separately and cross-refer to each other by description rather than by
number. This table is the key. It names the chapter and the **title of the section**, because
section numbers shift as chapters are revised.

| If you want to know about… | Go to |
|---|---|
| The core idea: what makes a finding trustworthy | Ch. 1, "The one central idea"; Ch. 4 throughout |
| Proving that something is *not* there (a clean result) | Ch. 1, "Proving the negative — the harder half"; Ch. 4, "Why 'we found nothing' is much harder than 'we found something'"; Ch. 5, Part 4; Ch. 6, "The clean result" |
| The four verdict words, in detail | Ch. 4, "There are four words, not two" (also section 7.1 of this page) |
| The named components and how they divide | Ch. 2, "The parts, one by one" |
| The separation between the attacking half and the key-holding half | Ch. 2, "The wall down the middle"; Ch. 8, "Two halves that cannot become one" |
| Why having the software is not the same as being allowed to use it | Ch. 2, "Entitlements"; Ch. 8, "The attacker who obtains a copy of the software"; Ch. 9, "Capabilities that have no screen at all" |
| What runs on which machine, and where the information is stored | Ch. 2, "What runs where, and where the information is kept"; Ch. 9, "Before the tour" |
| The programmatic ways in (what a security reviewer should count as attack surface) | Ch. 2, "The programmatic surface"; Ch. 8, "The programmatic ways in"; Ch. 9, "The other ways into the system" |
| A whole job, stage by stage | Ch. 3 throughout |
| The written authorisation document (the charter) | Ch. 3, "Stage 0 — Written authorisation"; Ch. 8, "Nothing happens without a written authorisation" |
| Threat model and attack tree (the planning artefacts) | Ch. 3, "Stage 2 — Setting up the run"; Ch. 9, "Capabilities that have no screen at all" (target intake) |
| Sessions, and what the system remembers between jobs | Ch. 3, "Stage 1 — The session"; Ch. 9, Group MANAGE; Ch. 10, "Per-job maps, and memory across jobs" |
| Testing behind a login (supplying the target's own test accounts) | Ch. 5, the access-control and business-logic families; Ch. 12, "Accounts, credentials and keys" |
| The call-back relay needed to prove "blind" weaknesses on a remote target | Ch. 9, "Capabilities that have no screen at all"; Ch. 5, Part 2; Ch. 6, "The clean result" |
| The fuzzing engine and the manual request replayer | Ch. 9, "Capabilities that have no screen at all"; Ch. 13, Part 4 |
| Feeding in another security tool's results | Ch. 9, "Capabilities that have no screen at all"; Ch. 12, Part One |
| What "confidence" means and how it is calculated | Ch. 4, "What 'confidence' means here" |
| The complete catalogue of weakness categories | Ch. 5, Part 1 |
| The confirming checkers, one by one | Ch. 5, Part 2 |
| Defensive detection from the customer's own logs | Ch. 5, Part 3; Ch. 13, Part 1 |
| Evidence: what is captured and how it is sealed | Ch. 6, "What counts as evidence" through "Sealing" |
| What a finding report contains | Ch. 6, "What a finding report contains for a human reader" |
| How an outside party re-checks the evidence with no VIGIL software | Ch. 6, "Handing the evidence to an independent third party"; Ch. 7, "The trust root" |
| What happens if someone alters one byte | Ch. 6, "What happens if a single byte is changed" |
| How long evidence is kept, how it is destroyed, backup and restore | Ch. 6, "Looking after the evidence over time"; Ch. 12, "Keeping it running" |
| Digital signatures explained in plain terms | Ch. 7, "What a digital signature actually is" |
| Who holds which key, and how keys are protected | Ch. 7, "Who holds which key" and "How keys are protected while sitting on disk" |
| Losing a key, backing one up, replacing one, withdrawing one | Ch. 7, "Losing a key, backing one up, replacing one, withdrawing one" |
| Several people having to approve an irreversible action | Ch. 7, "'Several people must approve'"; Ch. 8, "Irreversible actions need several people" |
| Scope enforcement and how the system refuses | Ch. 8, "Scope enforcement" |
| Permission tiers, and the human approval queue | Ch. 8, "Permission tiers" and "The approval queue" |
| The emergency stop | Ch. 8, "The emergency stop"; Ch. 7, "Emergency stop, and where it sits relative to keys" |
| Not damaging the systems under test | Ch. 8, "Not damaging the systems under test"; Ch. 13, Part 4 |
| Staying away from real people's data | Ch. 8, "Staying away from real people's data" |
| The complete list of deliberate refusals | Ch. 8, "What the project has deliberately refused to build"; Ch. 1, "What the system deliberately refuses to do" |
| Who could attack VIGIL itself | Ch. 8, "Turning the question round" |
| How the product's own software is built and released | Ch. 8, "How the product's own build is assured"; Ch. 6, "Evidence about the system's own build"; Ch. 12, "Where the software itself comes from" |
| Every screen in the interface | Ch. 9, Groups DO, MANAGE and LEARN |
| Controls that do less than they appear to | Ch. 9, "Where the interface is honestly incomplete" |
| The command line, and the other interfaces | Ch. 9, "The other ways into the system" and "The command line" |
| The map of the target and attack routes | Ch. 10 throughout |
| "Crown jewels", blast radius, and chokepoints | Ch. 10, sections of those names |
| Every automated assistant and its ceiling | Ch. 11, "The investigation team", "The owner's personal mesh", "The reasoning body" |
| How the system learns, and the hard rules on learning | Ch. 11, "How the system learns" and "The hard rules on learning" |
| The outside tools and what each may claim | Ch. 12, Part One |
| Licence, hardware, accounts, credentials, network access | Ch. 12, Part Two |
| Backup, restore, upgrade and removal | Ch. 12, "Keeping it running" |
| What leaves your organisation | Ch. 12, "What leaves your organisation, and what stays" |
| The defensive firewall | Ch. 13, Part 1 |
| Reading a customer's source code (and the two different routes) | Ch. 13, Part 2 |
| Producing and proving a fix | Ch. 13, Parts 3 and 5 |
| Encrypted connections, certificates, quantum-era exposure | Ch. 13, Part 4 |
| **What is finished and what is not** | **Section 8 of this page** |
| **Every technical word, defined** | **Sections 11 and 12 of this page** |

---

## 7. The vocabulary the whole briefing depends on

### 7.1 The four words the system is allowed to say

Every conclusion the system reaches is one of exactly four. Nothing else is permitted; this is
enforced by the structure of the software, not by editorial policy.

| Word | What it means | What it takes to say it |
|---|---|---|
| **FACT** | Proved. The stated thing was established against the named target, at the stated time, from evidence the system captured itself. | A fixed, non-intelligent checker re-derived it from that evidence, and the sealed document re-checks correctly offline. |
| **LEAD** | Suspected. Something points this way; it was not proved. | Anything weaker: another tool's assertion, a pattern match, an opinion from an artificial intelligence model. |
| **CLEAN** | Conclusively disproved. Under the stated conditions, the thing is not there. | A real channel to look through, evidence that was actually readable, and a checker capable of a sound negative. |
| **INCONCLUSIVE** | We could not tell. | Everything else. This is a real answer, never rounded towards CLEAN. |

Two consequences a senior reader should hold on to:

- **CLEAN is harder to earn than FACT**, deliberately. A false alarm wastes a day. A false all-clear
  means nobody ever looks again.
- **FACT and CLEAN are both bounded.** They describe what was established during a specific look at a
  specific configuration. Neither is a timeless property of the target. The bound is written inside
  the signed document, where it cannot be dropped by whoever quotes it.

### 7.2 The checker, and the other words you will see for it

The most important thing in the whole system is a small, fixed, non-intelligent program that looks at
saved evidence and answers one narrow question the same way every time.

**The briefing's standard word for it is "checker."** That word is used consistently in the chapters
that introduce the idea — it appears well over a hundred times in chapter 4 alone — and it is the
word to carry with you.

You will nonetheless meet other words, for three legitimate reasons, and this table exists so you do
not spend the briefing wondering whether there are several different mechanisms. There is one.

| Word you may see | Why it appears |
|---|---|
| **oracle** | This is the software's *own* name for the thing. It appears in the code, on some screens, and in the machine-readable outputs, so the briefing keeps it wherever it quotes what the system itself says. It is an unfortunate name — it suggests prophecy, and this is the opposite of prophecy — but the briefing does not rename what the screens display. |
| **judge**, as a verb ("the checker judges the captured bytes") | Ordinary English for what it does. It never means a person or an artificial intelligence exercising discretion. |
| **automatic test**, **deterministic test**, **decision procedure** | Descriptive phrases, used where the emphasis is on the property being relied on: that it runs by itself, and that it gives the same answer every time. |
| **assay**, **litmus paper**, **breathalyser** | Analogies, not names. All three carry the same point: the answer does not depend on who runs the test or how they feel about the result. They are accurate and worth carrying with you. |

### 7.3 The words the briefing uses for status

These five phrases appear throughout. They are used consistently and they mean different things.

| Phrase | Meaning |
|---|---|
| **Fully working, exercised end to end** | Built, and actually run through from beginning to end on this machine, producing real output. |
| **Built and proven offline** | Built, and proven correct against recorded sample data standing in for a live system. Never yet pointed at a real outside system. |
| **Live fire** | Running a built capability against a real system rather than against recorded sample data. For a cloud account that means somebody else's system, and awaits their credential; for Kubernetes the system creates a real cluster of its own, and has done so. |
| **Scaffold** | An interface exists; the thing behind it is not implemented. The system reports a clear error rather than returning a plausible-looking answer. |
| **Refused** | Deliberately not built, for a stated reason. Not an oversight. |

---

## 8. The master status ledger

Each of the thirteen chapters ends with its own honest account of what is finished. Those accounts
are consistent with each other but they differ in detail and in what they include. This section is
the consolidated version — one table, covering the whole system, with a pointer to the chapter that
explains each item.

Everything marked "verified for this index" below was re-derived from the repository while this page
was written; the method is in section 10.

### 8.A Fully working, and exercised end to end

| Capability | Where it is explained |
|---|---|
| The core proving pipeline: propose, capture evidence, check automatically, admit, sign, re-verify offline | Ch. 3, "Stage 7 — Confirming"; Ch. 4, "The journey of a claim"; Ch. 6, "What counts as evidence" through "The four independent checks" |
| The 15 always-available confirming checkers, run against a real web application on this machine. Pointed at a deliberately *safe* twin of the same application, the system correctly finds nothing — a shipped control demonstrating it does not rubber-stamp | Ch. 1, "What is working end to end"; Ch. 5, Part 5 |
| Service reachability, encryption weakness, software-version-in-advisory-range, and web achieved-state confirmations against real captures | Ch. 5, Part 5; Ch. 6, "Honest status" |
| Signing, sealed certificates, the tamper-evident chained record, and offline re-verification | Ch. 6, "Sealing"; Ch. 7 throughout |
| The standalone offline checkers, which contain none of VIGIL's own code and re-implement the published format from its specification | Ch. 2, "Honest status of the parts"; Ch. 6, "Handing the evidence to an independent third party" |
| The evidence package handed to a third party: reports, machine-readable exports, certificates, fingerprints | Ch. 6, "What a finding report contains" and "The machine-readable outputs" |
| Written authorisation, scope enforcement, permission tiers, the human approval queue, the emergency stop | Ch. 8, sections 1 to 6 |
| The append-only signed record of everything the system did, and its resistance to editing | Ch. 8, "The audit trail"; Ch. 11, "Honest status summary" |
| The 28-screen interface (reachable through the bring-up command only — see 8.D) | Ch. 9 throughout |
| The map of the target: pins, connections, provenance labels, route finding, crown jewels, blast radius, chokepoints | Ch. 10, "What is fully working" |
| The deterministic reviewing assistants: the critic panel, reflection, refusal | Ch. 11, "Self-criticism and second opinions" |
| The learning machinery: the memory store, effort ranking, calibration, proposal drafting — all reproducible, none able to promote a claim | Ch. 11, "How the system learns" and "The hard rules on learning" |
| The defensive firewall: watch-only and enforcing modes, proof-backed block classes, graduated soft responses, offline re-checkable certificates, kill switch | Ch. 13, Part 1 |
| Defensive detections of attacks on an artificial-intelligence application, each with a stated false-alarm control | Ch. 13, Part 1 |
| Defensive procedures over the customer's own access, authentication and connection logs, each with a benign twin | Ch. 13, Part 1 |
| Source-code review: built-in pattern analysis always; two outside analysers when the operator installs them | Ch. 13, Part 2 |
| Encrypted-connection assessment: the system's own gated handshake, deprecated protocols, weak-cipher markers, certificate checks | Ch. 13, Part 4 |
| Fix verification: four signed answers, controls for liveness, freshness, positive control and repetition, and a standalone third-party checker containing none of this system's code | Ch. 13, Part 5 |
| A signed, reproducible comparison against three other tools, run on this machine on 4 August 2026, with its own fairness caveats attached | Ch. 1, "What is working end to end"; Ch. 12, Part One |

**Machine-checked mathematical proofs.** The system's four core safety properties are each written
out as a formal mathematical model and checked exhaustively by a model checker — a program that
explores every possible sequence of events the model allows, rather than sampling a few. Verified for
this index, the four are: an action may run automatically only if every condition holds at once; a
claim may be called proved only if a checker actually fired; the attacking half and the key-holding
half never load into the same running program; and the durable high-water mark of the record never
moves backwards. Each model ships with a deliberately **broken twin** — identical except that one
safeguard has been removed — which the checker must report as failing. That makes the check red in
both directions: red if a real safeguard regresses, and red if a broken twin stops being caught,
which would mean the check had become empty. This runs on every proposed change as a build job named
`formal-verification`. The honest scope, stated by the project itself, is that this is **model-level
assurance that faithfully abstracts the enforcing code — not a proof extracted from the code**. The
mapping from each model to the exact part of the code it abstracts is written down in the project's
own correspondence document.

**The automated build-and-test pipeline.** Verified for this index: every proposed change runs
through eight independent jobs before it can be accepted — the shared integrity core; the offensive
engine's own tests; the outbound-network gate; the integration layer; the vendored agent's runtime;
the sovereign side's permission gates; the formal proofs above; and the permission kernel written in
a compiled language. A ninth job, in a separate pipeline, is the supply-chain gate described
immediately below. All nine are registered as *required* checks on the main line of
development, which also blocks force-pushing and deletion. Administrator enforcement is
deliberately off, so the repository's owner keeps an explicit override and can merge without
them; every other contributor and every automated agent is bound unconditionally. Chapter 8's section "How the product's own build is assured" gives the full
account.

**Safeguards over the system's own software supply chain.** This work applies the prove-don't-guess
discipline to the third-party components VIGIL itself is built from. It reached the released software
on the day this briefing was compiled, which is why four chapters were revised to describe it as
delivered rather than pending; section 10.2 explains that history. As verified directly for this
index, in the released version the following are true:

- **Every third-party package is pinned twice** — to an exact version, and to the cryptographic
  fingerprint of the exact file. There are **1,816 fingerprints** across the two separate package
  lists the two halves of the system use: 640 covering the offensive engine's 26 packages, and 1,176
  covering the sovereign side's 56. Those totals are the *full* set — the packages the project asked
  for (ten and two respectively) plus everything those packages themselves pull in, which is where
  supply-chain attacks actually land. A fingerprint is a short code computed from a file's entire
  content: change one byte and the code changes completely, so a substituted package is refused
  rather than installed. There are several fingerprints per package because a package is published
  in more than one form.
- **The build proves the fingerprints actually work**, by performing a real installation in
  fingerprint-checking mode. A list of fingerprints that the installer would reject is a document,
  not a control.
- **Every starting container image is pinned by content fingerprint** rather than by a movable name.
  Nine image references exist; the eight that come from an outside registry are all fingerprint-
  pinned, and the ninth is built from this repository and so has no outside fingerprint to pin.
- **A component inventory (a "software bill of materials") is regenerated from each package list**
  and cross-checked against it item by item.
- **A vulnerability scan fails the build on anything rated CRITICAL**, and reports everything rated
  HIGH without blocking. That gate carries its own control: before the real scan runs, the identical
  configuration is pointed at a fixture containing packages with known critical flaws and *must*
  fail. A green result therefore cannot come from a misconfigured scanner.
- **Every exemption must name one of five permitted reasons** — no fix published upstream, the
  vulnerable path is not reachable here, present only in test material, the advisory is disputed, or
  the scanner misidentified the component — and give a written justification. An automated test
  enforces the rule. Verified for this index: **the exemption list is currently empty**, so every
  critical finding blocks.

### 8.B Built and proven offline; live fire awaits something only the customer can supply

This is the category most easily misread in either direction. The project's own formulation is the
one to use: **built, gated, and proven offline; live fire awaits operator-supplied credentials, by
design.** Calling these unfinished understates the system. Calling them field-proven overstates it.
One entry has since left this category, and the table marks it: the two container-platform
(Kubernetes) confirmations are now proven against a real cluster the system creates and owns, so
they wait on nobody.

| Capability | What it is waiting for | Where explained |
|---|---|---|
| **The four cloud exploitation confirmations** (the six listed in full below, less the two container-platform ones) | The customer supplying their own cloud credentials. A credential is a thing only the account owner can issue, and the system is built not to obtain one any other way. **The two container-platform (Kubernetes) confirmations are no longer in this category:** both are proven against a real single-node cluster the system stands up, owns and destroys — the dangerous binding confirmed with a certificate that re-verifies offline, the benign ones correctly left as leads. What that run does not cover is enumeration of bindings across a cluster, and a managed provider's control plane (EKS, GKE, AKS) | Ch. 1, "Cloud and Kubernetes exploitation"; Ch. 5, Part 5; Ch. 6, "Honest status"; Ch. 9, "Capabilities that have no screen at all"; Ch. 10, "What is fully working"; Ch. 12, "Honest status" |
| Cloud and container-platform **posture** collection for the major providers — reading how an account is *configured*, rather than what was achieved against it | Operator-supplied read-only credentials | Ch. 3, "What is fully working"; Ch. 12, "Honest status" |
| The destructive automatic-fix step that opens a proposed code change | The operator provisioning the several-signer keys and a code-hosting access token | Ch. 7, "Honest status summary"; Ch. 8, "Irreversible actions need several people"; Ch. 13, Part 3 |
| The several-must-approve gate for irreversible actions | The same several-signer keys. The mechanism itself is built and tested | Ch. 7, "Honest status summary" |
| Artificial-intelligence red-teaming tools as a source of proved facts | Those tools are absent from this environment and could not be installed without network access | Ch. 1, "Built, tested against recorded data…"; Ch. 11, "Honest status summary" |
| An external graph database and an external telemetry collector | The services being stood up. The built-in file-based equivalents work; attempting to use the external ones raises a clear error rather than silently degrading | Ch. 2, "Honest status of the parts"; Ch. 10, "What is fully working" |
| Speaking to an outside tool server over the model-context protocol | The client connection step. The description and validation layer around it is built | Ch. 3, "What is fully working"; Ch. 11, "Honest status summary" |
| A field record across diverse real targets | Access to such targets. The mechanism is built; the record is not | Ch. 1, "Built, tested against recorded data…" |
| Continuous automatic re-proof of a fixed finding | It is a deployable loop and timer; it becomes an operating property once an operator enables the timer on a host | Ch. 13, Part 5 |

**The six cloud and container-platform confirmations, named.** All six are complete and merged into
the released software. The four cloud ones are proven with recorded sample evidence offline; the two
container-platform (Kubernetes) ones are proven against a real cluster the system stands up itself.
Verified for this index, they are registered as six separate evidence routes:

| Confirmation | What it establishes |
|---|---|
| Instance-metadata credential capture | A credential was actually retrieved from the internal service a cloud machine uses to hand out credentials, **and actually worked** — not merely that the service was reachable |
| Exposed-secret validity | A password or key found where it should not be is **currently valid**, rather than expired or revoked |
| Google service-account impersonation | One machine identity was able to act as a different, more privileged identity |
| Identity privilege escalation | A strict, achieved increase in privilege — the step taken, not a path drawn on a diagram |
| Container-cluster access control, tier one | An anonymous, unauthenticated caller is bound to a dangerous built-in role |
| Container-cluster access control, tier two | A dangerous permission verb, or the cluster's default identity, has been granted rights it should not have |

**A safety property worth stating alongside them.** All six are deliberately kept **outside** the
frozen 15-member set of checkers that an unknown weakness class may fall back on. None of the six can
fire during an ordinary scan. Each runs only when its own producer is called explicitly over a
retained capture. Verified for this index.

**One of the six must be described differently.** The **identity privilege escalation** confirmation
works entirely offline, by re-deriving the answer from the customer's own retained account
configuration. It **never executes the escalation, and never will** — the stated principle is that a
defensive verification tool does not perform the attack it is verifying. It is therefore not awaiting
live fire in the sense the other three cloud confirmations are. But one clause must be added so this is not misread: it
still needs a *real* configuration capture from a *real* account, and getting one still requires the
customer's read-only cloud credentials. What it will never need is to perform the escalation itself.

**What the live validation actually covered.** The complete end-to-end run was performed against a
purpose-built, deliberately vulnerable application on the machine's own internal address. The project
states this plainly in its own words: proven on a local target, *not* "proven in the field." A single
live run against an outside, vendor-published, deliberately vulnerable practice site is also on
record, producing two confirmed findings, both re-checked offline, with a deliberately altered byte
correctly rejected. The chapters report that as a documented claim read from the project's own
records, not as a run observed while writing.

### 8.C Scaffolds, which refuse rather than pretend

| Item | The honest position | Where explained |
|---|---|---|
| Hardware-grade confidential-computing attestation | The interface exists. A software-based and chip-based path works today and reports itself as *not* hardware-backed. The specialised-silicon versions deliberately raise an error rather than returning a plausible answer. Needs the hardware | Ch. 1, "Scaffolded, and honestly labelled as such"; Ch. 2, "Honest status of the parts"; Ch. 8, "What the project has deliberately refused to build" |
| General automatic patch generation for memory-safety bugs in compiled programs | The narrow path — confirm a crash, then prove the fix by the original checker going silent — is built. Generating the patch itself is research-gated and raises an error | Ch. 1, "Scaffolded, and honestly labelled as such"; Ch. 3, "What is fully working" |
| The next-generation reasoning body | An interface only. It cannot be created and changes no behaviour. It exists so a future replacement could be fitted without relaxing any safety property | Ch. 1, "Scaffolded, and honestly labelled as such"; Ch. 11, "Honest status summary" |

### 8.D Bounded or conditional guarantees, stated as conditional

These are working capabilities whose guarantee has a stated edge. None of them is a defect; all of
them are places where a reader could otherwise assume more than is delivered.

| Guarantee | Its stated bound | Where explained |
|---|---|---|
| Resistance to the record being shown differently to different parties | *Prevented* only when a strict majority of distinct independent witnesses countersign. Below that threshold it remains *detectable* but not prevented, and the software exposes the two checks separately so they cannot be blurred | Ch. 2, "Honest status of the parts"; Ch. 7, "Honest status summary" |
| Witness independence | A deployment property, not a software one. Distinct keys are not distinct operators. The project's own trust document is marked "DRAFT — design, not a guarantee" | Ch. 2, "Honest status of the parts"; Ch. 7, "Honest status summary" |
| Protection against rolling the record back to an older state | Defends against an attacker who can overwrite the log but not the floor file, and against an outside checker holding a newer floor. An attacker with full control of the same machine who rewrites both is closed only by an external witness | Ch. 7, "Rolling back to an older state" |
| The machine-checked mathematical proofs | Model-level assurance that faithfully abstracts the enforcing code — not a proof extracted from the code itself | Ch. 1, "Deliberately limited by design"; section 8.A above |
| A "nothing exploitable here" certificate | Means non-exploitability by the checks that actually ran, over the surface actually reached, as of the stated freshness bound. Endpoints never discovered are outside what the claim covers | Ch. 2, "Honest status of the parts"; Ch. 6, "The clean result" |
| The general claim-checking firewall that re-executes every cited proof | The underlying building block is in place, with its runtime wiring being phased in. It is **not today a universal checkpoint every claim must cross**, though the report layer does route every finding through it at render time | Ch. 5, Part 5; Ch. 6, "Honest status"; Ch. 10, "What is fully working" |
| Keys protected at rest | Sealed to a hardware security chip where one is present and provisioned; otherwise owner-only files with a loud warning at start-up. Not verified on any specific deployment host | Ch. 6, "Honest status"; Ch. 7, "How keys are protected while sitting on disk" |
| Purpose labels that stop a signature being reused in the wrong context | Applied to ten labelled document types; explicitly **not yet applied** to the offensive engagement record and the usage ledger, which the project names as the next hardening step | Ch. 7, "Honest status summary" and Appendix A |
| Withdrawing a delegated permission | There is **no** way to withdraw a delegation before it expires; the expiry window *is* the exposure. There is no scheduled automatic key rotation; rotation is an operator action | Ch. 7, "Losing a key, backing one up, replacing one, withdrawing one" |
| The external time anchor | The mechanism is built and tested. Genuine independence requires a third-party authority; the shipped default is a local self-signed one | Ch. 7, "Honest status summary" |
| The categorical refusal list for government, military, educational and intergovernmental domains | The list exists and is complete. **It has no live call site** — nothing on the running path invokes it — and it matches domain names only, not bare numeric addresses. See section 9.2 | Ch. 1, "A built-in refusal to test government hosts"; Ch. 3, "Stage 3 — Pre-flight"; Ch. 8, "Scope enforcement" |
| The 28-screen interface | Reachable only through the bring-up command. Pointing a browser directly at the two internal ports reaches older interfaces | Ch. 9, "Where the interface is honestly incomplete" |
| The keyboard command palette visible on every screen | Non-functional. Clicking it says it is on the roadmap. This is the one clearly non-working visible control | Ch. 9, "Where the interface is honestly incomplete" |
| The fully autonomous, real-target, finding-discovering loop | **Not claimed.** The project's own limitations record states it has largely been exercised against fabricated evidence and that its one real-target run produced zero findings. The findings the product stands behind come from the deterministic scanning and confirmation path | Ch. 11, "Honest status summary" |
| Saying "this dependency is *not* vulnerable" (as opposed to "this one is") | Needs non-pinned version constraints resolved and snapshot coverage recorded. Named as outstanding work | Ch. 13, Part 2 |
| Claiming a fix at the stronger of the two freshness levels | Structurally unattainable for a fix: once the vulnerable path is removed, nothing can travel through it to prove the point. The system caps at the weaker level and returns "could not tell" to anyone demanding more, rather than returning a falsely strong answer | Ch. 13, Part 5 |

### 8.E Deliberately refused

The full account is chapter 8, "What the project has deliberately refused to build", with chapter 1's
three refusal groups alongside it. In summary, the system will not: evade defenders or operate
stealthily; rotate network addresses or use proxy chains; poison local-network name resolution to
harvest credentials; treat exploit frameworks or password crackers as sources of proof; run cloud
account exploitation frameworks; leave persistence or backdoors behind; perform lateral movement or
implant anything after gaining a foothold; attack a third party even when a weakness could pivot into
one; let any tool's own output count as proof; display a fabricated status for a tool it does not
actually launch; let an artificial intelligence judgement become a fact; modify its own attacking
code without human sign-off; generate phishing or impersonation content; block traffic on the
defensive side merely because it is suspicious; allow the control panel to widen its own authority;
return a plausible answer where the hardware cannot deliver the guarantee; or report "we found
nothing" when something prevented it from looking properly.

Three further permanent refusals are recorded in chapter 13: blocking certain attack classes inline
where a single response cannot supply the confirmation; three named artificial-intelligence attack
detections that are permanently suspicion-only because the underlying signal cannot support more; and
any working bypass for a named commercial defence product.

### 8.F How this ledger relates to the chapters' own

This table is a consolidation, not a replacement. Every chapter's own status section carries detail
this page omits, and the per-chapter sections are the authoritative ones. They are:

| Chapter | Its own status section |
|---|---|
| 1 | "Honest status: built, proven, and deliberately deferred" |
| 2 | "Honest status of the parts" |
| 3 | "What is fully working, what is built but not yet used in the field, and what is planned" |
| 4 | "The same discipline, applied to the system's own supply chain"; "Why this eliminates the false-alarm problem — and precisely what it does not do" |
| 5 | Part 5, "What is fully working today, what is built but not yet fired in anger" |
| 6 | "Honest status: built, proven, and live-fired"; "Evidence about the system's own build" |
| 7 | "Honest status summary" |
| 8 | "What the project has deliberately refused to build"; "Where the limits genuinely are" |
| 9 | "Capabilities that have no screen at all"; "Where the interface is honestly incomplete" |
| 10 | "What is fully working, what is built but not yet fired at a live third party" |
| 11 | "Honest status summary" |
| 12 | "Honest status: built, but not yet fired at a live outside system" |
| 13 | "What A Reviewer Should Take Away" |

---

## 9. Two things a government reader should see before chapter 1

### 9.1 The licence excludes government use without a commercial agreement

This is a first-order procurement fact and it is easy to miss.

The software is dual-licensed. It may be used either under a free, source-available noncommercial
licence (the PolyForm Noncommercial Licence 1.0.0), or under a commercial licence from the copyright
holder. Attached to both is a supplemental term that specifically addresses government use. The stock
noncommercial licence would normally count a government institution as a permitted noncommercial
user. Verified directly for this index, the supplemental term reverses that: use of the software
**by, for, on behalf of, or funded by** any government, government agency, department, ministry,
state-owned enterprise or other public-sector body is **not** a permitted noncommercial use and
requires a separate commercial licence — even where the use would otherwise be noncommercial.

In plain terms: a government agency cannot use this system under the free licence. It must obtain a
commercial licence first. Third-party components bundled with the system keep their own separate
licences, which the supplemental term does not alter.

Chapter 1, "Licensing: public-sector use is not covered by the free licence", is the chapter
reference.

### 9.2 There is a categorical block on government, military, educational and intergovernmental domains

The system contains a hard-coded refusal list that cannot be switched off by configuration. Verified
directly for this index, it matches by name any address ending in one of **14 suffix patterns** —
government suffixes including national variants such as `.gov.uk`, `.gouv.fr`, `.gob.mx`, `.govt.nz`,
`.go.jp` and `.gv.at`; military suffixes such as `.mil` and `.mil.br`; educational suffixes such as
`.edu`, `.edu.au` and `.ac.uk`; and the `.int` suffix used by international organisations — plus
**186 named intergovernmental organisation domains** that sit on ordinary endings such as `.org` and
`.eu`. The matching first normalises look-alike full-stop characters, so a domain written with an
unusual Unicode dot cannot slip past, and it reads a web address two different ways so that a
disagreement between browsers cannot be used to evade it.

Its purpose is obvious and defensible: it makes it structurally harder for the tool to be pointed at
a nation's public infrastructure by accident, by a mistyped address, or by text on a web page
manipulating an automated assistant.

**Four things must be said about it plainly.**

First, **as written, this component would refuse to test a government or military host — including an
agency's own estate, tested with its own authorisation.**

Second, **there is no supported route to change that today.** The component takes no settings, reads
no configuration file, and has no switch. Testing an agency's own government estate by domain name
would require a deliberate change to the software itself — either amending the compiled-in patterns
and named list, or adding a narrow, explicitly authorised exception path. Neither exists. The honest
answer is that this is unresolved product work, to be agreed with the copyright holder alongside the
commercial licence. Chapter 1's section "A built-in refusal to test government hosts — and what an
agency would have to change" now states this, together with what would be lost by making the change
and which existing controls would have to replace it: a signed authorisation naming only the agency's
own estate, and an outbound network gate permitting only those addresses.

Third, **the component matches domain names, not numeric addresses.** A target supplied as a bare
numeric internet address is not covered by this list at all. Such targets are governed by the written
authorisation and the outbound network gate instead.

Fourth, **the component has no live call site.** This was verified directly for this index: outside
its own package, the safety package that re-exports it, its own tests, and two research documents,
nothing in the system calls it. So today it does not actually block anything on the running path. The
controls that *are* demonstrably active before any target is touched are the signed written
authorisation, the scope check, the permission classifier, the combined authorisation gate, and the
outbound network gate.

An agency evaluating this system should raise the second point as its first operational question, and
should treat any answer as product work that has not yet been done rather than as an existing option.
Chapter 8, "Scope enforcement", is the authoritative account.

---

## 10. How this briefing was written, and how to check it

### 10.1 Method and provenance

- **What was read.** The source code, configuration and documentation in the repository at
  `/home/kali/vigil`, together with the project's own written doctrine documents. Not its marketing
  material, and — where the two disagreed — not its own documentation either.
- **The version.** The first draft of the thirteen chapters was written against the version of the
  software recorded as commit `1487e03a`, dated 12 August 2026. This index, and the revised chapters,
  were written against `dc2994d6`, dated the same day, which is four recorded changes later. A
  "commit" is simply a numbered snapshot of the software; quoting it lets a reader check exactly the
  same version that was read.
- **How numbers were obtained.** Counts were re-derived from the code by running extraction over the
  relevant parts, not copied from documentation. Where the code and the documentation disagreed, the
  chapters follow the code and say the documentation is stale.
- **What was not done.** No chapter re-ran the system's own historical test runs. Where a chapter
  reports a past result — the tool comparison, the single live external run — it says explicitly that
  it is reporting a recorded claim rather than an observed run.
- **The review.** After the first draft, the whole set was put through three separate reviews, each
  with a single narrow brief and each conducted as a fresh read of all thirteen chapters against the
  code: **honesty** (does any statement claim more than the code supports?), **plain English** (would
  a non-technical senior reader actually follow it?), and **completeness** (does it cover everything,
  and are there gaps a reader would trip over?).
  Their notes are kept, unedited, in the `_review/` folder beside the chapters, and the chapters were
  then revised against them. Two consequences a reader should know about: the reviewers found real
  errors — miscounts, one invented detail, several places where a software-team phrase had been left
  in front of a lay reader — and those were corrected rather than smoothed over; and this index exists
  because the completeness reviewer judged the absence of any contents page to be the single thing
  most likely to make a reader give up.
- **The standard word for the checker changed during revision.** The plain-English reviewer's first
  recommendation was that the set stop using several different words for the one most important
  object. It now standardises on **checker**. Section 7.2 records the words you will still meet, and
  why.

### 10.2 One thing changed in the repository while the briefing was being written

This is disclosed because leaving it out would make part of the set read as more cautious than the
facts now warrant, and because a reader who checked would find the discrepancy and reasonably wonder
what else had drifted.

The safeguards over the system's own software supply chain — described in section 8.A above — were
written and working, but **not yet part of the released software**, at the version the first draft
was written against. Verified directly: at commit `1487e03a` the build pipeline configuration and the
policy document were genuinely absent, and the committed package list contained no fingerprints and
labelled itself a placeholder. Roughly an hour later, at commit `dc2994d6`, that work was folded into
the released software. The chapters have been revised to describe the delivered state.

**One detail remains different from the released state**, and it is stated here rather than glossed:
the component inventory file committed inside the offensive engine is *still* a labelled placeholder,
with a zeroed date and the word "scaffold" in it. The real inventories are regenerated by the build
each time and published as build outputs rather than committed to the repository. Anyone quoting the
briefing on this point should check the current state first.

### 10.3 How to re-derive the load-bearing numbers yourself

Every count in this briefing can be reproduced. These are the ones the argument rests on. Each was
re-derived for this index at the version named above.

| Claim | How to check it |
|---|---|
| 38 kinds of confirming checker | Count the members of the `OracleKind` list in `engine/crucible/framework/v2/verify/models.py` |
| 15 always-available checkers in the frozen fallback set | Count `_ALL_ORACLES` in `engine/crucible/framework/v2/verify/verifier.py`; observe that the six cloud and container-platform kinds are not among them |
| 85 named weakness categories, 190 alternative spellings, 275 accepted names in total | Read the class-to-checker map and the alias map in `engine/crucible/framework/v2/verify/verifier.py` |
| 26 evidence routes; all 26 may prove a weakness; only 6 may prove an absence; 17 carry named outstanding work | Read `docs/capability-matrix/evidence-branches.json` |
| The six cloud and container-platform exploitation routes | The same file: the routes whose names begin `cloud_exploit.` and `k8s_exploit.` |
| 28 screens | Compare the navigation list in `packages/vigil-ui/app.js` with `knowledge/system-map/system-map.json`. An automated check fails the build if the two disagree |
| 186 named intergovernmental domains, and 14 government/military/educational suffix patterns | Read `integration/vigil_integration/safety/hard_guardrail.py` |
| That the categorical block has no live call site | Search the repository for `assert_not_hard_blocked` and observe that the only matches are its own package, the safety package that re-exports it, its tests, and two research documents |
| The four machine-checked safety properties, and their deliberately broken twins | Read `formal/README.md` and `formal/CORRESPONDENCE.md`, then run `bash formal/check.sh` |
| The eight build-and-test jobs, and the ninth supply-chain gate | Read `.github/workflows/ci.yml` and `.github/workflows/supply-chain.yml` |
| 1,816 package fingerprints | Count the lines containing `--hash=sha256:` in `engine/crucible/framework/v2/requirements.lock.txt` (640) and `infra/supply-chain/sovereign.lock.txt` (1,176) |
| That every outside container image is pinned by content | Run `python3 infra/supply-chain/image_pins.py --check` |
| That the vulnerability gate can actually fire, and that its exemption list is empty | Read the "negative control" step in `.github/workflows/supply-chain.yml`, and read `.trivyignore` |
| The licence position on government use | Read the supplemental term at the top of `LICENSE` |
| That a report re-verifies offline | Run the engine's own verification command over a report file; it succeeds only if every certificate reproduces and matches its claim |
| That the written claim-discipline rules are enforced | A dedicated test runs on every change. Its own limits are documented: it validates the declarations and the admission behaviour; it does **not** prove that every code path routes through admission. That last property rests on human adversarial review and is marked as such |

---

## 11. Glossary — the plain-English terms

Terms are listed alphabetically. Where a chapter defines one at length, the chapter is named.

| Term | What it means |
|---|---|
| **Achieved state** | Evidence that something was actually *done*, rather than that it was configured in a way that would allow it. "This credential worked" rather than "this permission looks too broad". |
| **Admission** | The single controlled doorway a claim must pass through to become a proved finding. No individual part of the system may issue a certificate on its own. |
| **Attack tree** | A drawing of the ways an attacker could reach a goal, branching from the goal back to the possible starting points. Produced as a planning document at the start of a job. (Ch. 3) |
| **Authenticated testing** | Testing the parts of an application that only appear after you log in. It requires the customer to supply genuine test accounts; most of a real application's surface is behind a login. (Ch. 5, Ch. 12) |
| **Benign twin** | A deliberately harmless copy of a test input or a log entry, used to check that a detector fires on the real thing and stays silent on the safe one. |
| **Blackboard** | The shared working notice-board the automated assistants read from and write to. Entries can be added, never edited or erased. See also *spine*. |
| **Branch (of evidence)** | Also called an **evidence route** or **evidence window**. One specific way of seeing something — "in the reply's headers" as opposed to "in the page body". Different windows support different strengths of claim. Nothing to do with the software-development sense of the word. (Ch. 5) |
| **Canonical form** | One fixed, byte-for-byte way of writing a document down, so that two copies of the same content are identical and a signature over one is a signature over the other. The word is also used for the master list of weakness names — the one spelling everything else maps onto. |
| **Charter** | The written, signed authorisation for one engagement: what may be tested, by whom, and until when. Nothing runs without one. (Ch. 3, Ch. 8) |
| **Chokepoint** | A single weakness that, if fixed, breaks the largest number of possible attack routes. (Ch. 10) |
| **Clean-capable** | Said of an evidence route that is sound enough to support "we looked and it is *not* there", not merely "we looked and found it". Only 6 of 26 routes qualify. |
| **Conclusive** | A flag recorded against an observation, meaning the look was good enough to support a negative answer. Without it, "found nothing" can only be reported as "could not tell". |
| **Container** | A packaged, isolated copy of a program and everything it needs to run, kept separate from the rest of the machine. |
| **Coverage denominator** | What a "clean" claim was measured *out of*. A clean result covers only the surface actually reached. Anything never discovered is outside the denominator and outside the claim. |
| **Crown jewel** | A thing on the map that actually matters to the organisation — the customer database, the payment system — as distinct from a machine that merely happens to be reachable. (Ch. 10) |
| **Deterministic** | Same input, same answer, every time, on any machine. A recipe, not a chef: no judgement, no mood, no improvisation. |
| **Digest pin** | Naming a component by the fingerprint of its exact contents rather than by a label someone else can move. "This exact file", not "whatever is currently called latest". |
| **Dossier** | The single self-contained archive produced at the end of a job: the reports, the machine-readable exports, every certificate, the record of what the system did, and a fingerprint for every item. |
| **Entitlement** | A signed permission slip that decides which capabilities a particular installation may use at all. It is tied to one machine, it expires, and it can be withdrawn. It is the answer to "if this software is copied or stolen, what can the thief do with it?" — the answer being: only the safe baseline. (Ch. 2, Ch. 8, Ch. 9) |
| **Fail-closed** | If a safety check cannot be completed — an error, an unreadable file, a missing answer — the result is "no". Like a drawbridge held up by power: cut the power and it falls shut. (Ch. 8) |
| **Fingerprint (also hash, digest)** | A short code computed from a file's entire content. Change one byte and the code changes completely. It cannot be worked backwards to recover the file. (Ch. 6) |
| **Fixture evidence** | Recorded sample data used in place of the real thing, so a capability can be proven without a live target. (Ch. 9) |
| **Freshness bound** | How recently the observation was made, stated inside the signed document. A proved finding is "as of" a moment, not forever. |
| **Freshness levels F1 and F2** | Two strengths of "this really came from the live target just now". The stronger one requires a fresh challenge to come back through the very same channel the original weakness used. For a *fixed* weakness the stronger level is unattainable in principle, so the system caps at the weaker one rather than overstating. (Ch. 13) |
| **Fuzzing** | Sending very many variations of a test input at the same place and watching for the one response that behaves differently from all the others. The industry calls the tool that does this an "Intruder". Here the sifting is done automatically rather than by a person reading a table. (Ch. 9) |
| **Hash-locking** | Recording, for every third-party package the software installs, the fingerprint of the exact file — so a substituted package is refused rather than installed. (Section 8.A) |
| **Idempotent** | Running it twice does nothing extra; it is safe to press again. (Ch. 9) |
| **Insertion point** | A specific place in a request where a test input can be put — a form field, a header, part of the address. |
| **Kill switch** | A file on disk that, while it exists, causes every action to be refused. Because it is a file, tripping it survives a crash or a restart. (Ch. 8) |
| **Lead** | See section 7.1. A suspicion, never dressed up as more. |
| **Live fire** | Running a built capability against a real system rather than a stand-in. Proven for Kubernetes on a cluster the system creates itself; awaiting the customer's credential for cloud. |
| **Loopback** | The address a computer uses to talk to itself. No machine anywhere else can reach it. (Ch. 9) |
| **m-of-n** | Several named key-holders, of whom a set number must agree before something happens. Like a vault needing two managers' keys at once. (Ch. 7) |
| **Monotonic** | It can only ever move forward, never back. Used of the record's high-water mark. |
| **Negative control** | Deliberately pointing a check at something known to be bad, to prove the check can still fail. Without it, a clean result and a broken check look identical. |
| **Oracle** | The software's own name for the **checker** — the small, fixed, non-intelligent program that decides whether a claim is proved. See section 7.2. |
| **Oracle context** | The exact evidence that was saved at the time, kept so the same check can be run again later and produce the same answer. |
| **Out-of-band** | Delivered through a completely different channel from the thing it protects — a website, a letter, a phone call — so that faking one does not fake the other. (Ch. 7) |
| **Out-of-band relay** | A small server the operator hosts themselves, which sits and waits for the target to call out to it. Some weaknesses are invisible from the front and can only be proved by the target making that outward call. Without a relay, those checks are skipped rather than guessed. (Ch. 9) |
| **Payload** | The test input the system deliberately sends, to see how the target reacts. |
| **Positive control** | A check that the test itself still works. If the same test fires correctly on something known to be broken, then its silence on the real target means something. Without it, silence might just mean the test was misconfigured. |
| **Post-exploitation** | What an intruder does *after* getting in — moving sideways, staying resident, planting tools. The system deliberately does none of it; see section 8.E. |
| **Posture** | An assessment of how a system is *configured*, as opposed to what an attacker actually achieved against it. Weaker but safer; it reads an inventory rather than touching the live account. |
| **Provenance** | The recorded history of where a piece of evidence came from and how it was obtained. Every entry on the system's map carries one. |
| **Provenance tier** | How strong that history is — from "a checker proved it" at the top, down to "something inferred it" at the bottom. A weaker tier can never overwrite a stronger one. (Ch. 10) |
| **Pull request** | A proposed code change raised so that a human can review it before it becomes part of the software. (Ch. 8) |
| **Replayer** | Capturing one request to the target, editing it by hand, and sending it again. The industry calls this a "Repeater". Here it never opens a raw connection of its own: every replay goes through the same permission chain as everything else, and every refusal is recorded. (Ch. 9, Ch. 13) |
| **Residual** | A remaining doubt that the evidence cannot rule out, written down explicitly rather than left implied. |
| **Seam** | A deliberately narrow joint between two parts of the system, built so that only inert data crosses it and never running code. |
| **Sink** | The place a piece of data ends up — a database query, a page a browser will run, a file the server reads. A weakness usually means untrusted input reaching a sink. |
| **Spine** | The append-only signed record of everything that happened. Entries can be added, never edited or erased. (Ch. 2) |
| **Symbol index** | A map of a codebase: every function and variable, where it is defined, and everywhere it is used. Built when the system is reading source code. (Ch. 13) |
| **Tiers A0 to A3** | Four levels of how much damage an action could do, from harmless (A0) to destructive or irreversible (A3). The lowest two may run automatically; the higher two must be queued for a human. (Ch. 8) |
| **Topology** | The shape of the network: which machines exist and what connects to what. |
| **Vendored** | A copy of somebody else's software kept inside this one, with its original licence and credits intact. |

---

## 12. Glossary — acronyms, standards and formats

These appear in the chapters, sometimes without expansion. None of them needs to be understood to
follow the argument.

| Short form | What it stands for, and what it is |
|---|---|
| **AI** | Artificial intelligence. In this briefing it always means a large language model — software that produces plausible text — never a checker. |
| **API** | Application Programming Interface. A way for one program to call another directly, without a person clicking anything. |
| **ASN.1** | Abstract Syntax Notation One. An old, precise format for writing down structured data, used inside cryptographic certificates. |
| **ATT&CK (MITRE)** | A public catalogue of the techniques real attackers use, maintained by the MITRE Corporation. Used to label what a detection would catch. |
| **AWS, Azure, GCP** | The three largest cloud providers: Amazon Web Services, Microsoft Azure, Google Cloud Platform. |
| **Brier score** | A standard way of measuring whether stated confidence is honest. If you say "70% sure" a hundred times, roughly seventy should turn out right. |
| **CAPEC** | Common Attack Pattern Enumeration and Classification. A public catalogue of attack patterns, companion to CWE. |
| **CIDR** | Classless Inter-Domain Routing. The standard shorthand for writing a *range* of network addresses. |
| **CVE** | Common Vulnerabilities and Exposures. The public numbering system for individual known software vulnerabilities. |
| **CVSS** | Common Vulnerability Scoring System. The industry's standard 0-to-10 severity score. |
| **CWE** | Common Weakness Enumeration. A public catalogue of *kinds* of software weakness, as distinct from individual instances. |
| **CycloneDX** | A standard file format for listing every component inside a piece of software. |
| **DNS** | Domain Name System. The internet's address book, turning a name into a numeric address. |
| **DOM** | Document Object Model. The live structure of a web page inside a browser, as opposed to the text the server sent. |
| **DSSE** | Dead Simple Signing Envelope. A standard wrapper that binds a signature to both the content and its stated purpose. |
| **Ed25519, RSA** | Two families of digital-signature mathematics. This system signs with the first. |
| **F1 score** | A single number combining two measures: how many of the things reported were real, and how many of the real things were found. (Not to be confused with freshness level F1 in section 11.) |
| **HTTP / HTTPS** | The language browsers and web servers speak. The "S" means the conversation is encrypted. |
| **IAM** | Identity and Access Management. The part of a cloud account that decides who may do what. |
| **ISO 27001** | An international standard for managing information security. |
| **JSON / YAML** | Two plain-text formats for writing structured data that both people and programs can read. |
| **K8s** | A common abbreviation for Kubernetes, the software that runs and coordinates containers across many machines. |
| **LLM** | Large Language Model. The kind of artificial intelligence this system uses to decide what to try next — and never to decide what is true. |
| **MCP** | Model Context Protocol. A standard way for an artificial-intelligence assistant to call outside tools. |
| **MD5, SHA-1, SHA-256** | Three fingerprinting algorithms. The first two are broken and their presence is itself a finding; the third is the one this system uses. |
| **Merkle tree** | A way of fingerprinting a large collection so that one short code covers everything, and any single item can be proved to belong without revealing the rest. |
| **OpenVEX** | A standard format for stating whether a known vulnerability actually affects a particular product. |
| **OWASP** | Open Worldwide Application Security Project. A non-profit that publishes widely used lists of the most important web application security risks. |
| **PCI-DSS** | Payment Card Industry Data Security Standard. The security rules that apply to handling card payments. |
| **RBAC** | Role-Based Access Control. Granting permissions to named roles, and then putting people or programs into those roles. |
| **RFC 3161** | The internet standard for a trusted timestamp — a third party attesting that a document existed at a given moment. |
| **RFC 6962** | The internet standard behind public transparency logs, which make it possible to prove an entry is in a log without downloading the log. |
| **SARIF** | Static Analysis Results Interchange Format. A standard file format for tool findings, readable by most code-review platforms. |
| **SBOM** | Software Bill of Materials. An itemised list of every component inside a piece of software. |
| **SCITT** | Supply Chain Integrity, Transparency and Trust. A standards effort for making supply-chain claims verifiable. |
| **SIEM** | Security Information and Event Management. The product a defender uses to collect and search their own logs. |
| **Sigma** | An open format for writing detection rules that work across different log-monitoring products. |
| **SOC 2** | An auditing standard covering how a service provider handles customer data. |
| **SPA** | Single-Page Application. A website that loads once and then rewrites itself as you use it, rather than fetching a new page each time. |
| **SSO** | Single Sign-On. Logging in once to reach many systems. |
| **TLA+ / TLC** | A formal language for writing down exactly what a system must never do, and the program that checks every possible case exhaustively. Used for the four proofs in section 8.A. |
| **TLS (formerly SSL)** | Transport Layer Security. The encryption behind the padlock in a web browser. |
| **TPM** | Trusted Platform Module. A small dedicated security chip on a computer's motherboard that can hold a key the rest of the machine cannot read out. |
| **URL** | The address of a page or service on the web. |
| **VPN** | Virtual Private Network. An encrypted tunnel that makes a remote machine behave as though it were on your own network. |
| **XML** | An older structured text format, still used inside many document and certificate standards. |

---

## 13. Conventions, and the known rough edges in this edition

Stated so that a careful reader is not left wondering.

- **Each chapter is written to be read alone.** That is why the four verdict words, and the
  distinction between a suspicion and a proved finding, are re-explained in several chapters. If you
  are reading straight through, skip the repetitions.
- **This page is the only place the set is enumerated.** The chapters are identified by their file
  names and their titles. If you were sent a single chapter, sections 4 and 6 above tell you what the
  rest of the set contains.
- **Pointers in this index name a chapter and a section title, not a section number.** Section
  numbers move whenever a chapter is revised; titles are far more stable. If a quoted title has
  changed, search the chapter for the nearest wording.
- **The confirming program is called a "checker".** The other words you will meet for it — including
  the software's own word, "oracle" — are listed in section 7.2. They are one object.
- **Some software vocabulary survives, and means this.** "Part of the released software" means the
  work is in the version customers get. "Written and working but not yet folded into the released
  version" means it exists and passes its tests but is not yet in that version. "Recorded sample
  data standing in for the real thing" is what the chapters mean by fixture evidence. "A proposed
  code change raised for a human to review" is what a pull request is.
- **A few tables list software identifiers** — short machine names written in lower case with
  underscores, and file paths. Where a plain-English column sits beside them, the plain column carries
  the meaning and the identifier can be ignored. They are kept so a technical colleague can find the
  exact thing being described.
- **Where the code and the project's own documentation disagreed, the chapters follow the code** and
  say the documentation is stale. Two such cases are called out explicitly: an internal document
  understating the number of screens, and a status table describing a safety gate as off by default
  when the code has it on.
- **The set was independently reviewed and then revised.** The review notes are in `_review/`, kept
  unedited. Where a reviewer's finding could not be closed by better writing — because it named
  genuine unfinished product work — the finding is recorded as unfinished rather than smoothed away.
  The clearest example is section 9.2 above.
- **Nothing in this briefing has been rounded up.** Where a capability is partial, it is described as
  partial. Where a guarantee has an edge, the edge is stated in the same place as the guarantee, not
  in a footnote.
