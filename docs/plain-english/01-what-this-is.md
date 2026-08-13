# What This System Is, And The Problem It Solves

*Chapter 1 of the VIGIL briefing — a set of thirteen chapters written for a senior reader with no
software background. Every statement in this chapter was checked against the working code. The
chapters were written against the repository as it stood at version `1487e03a` on 12 August 2026;
this chapter was then revised against version `dc2994d6` the same day, which is the version that
includes the build-and-release safeguards described in section 9.4. Where something is built but has
not yet been used against a live third-party system, it says so.*

*Two navigation notes. A full contents list for the set, with a suggested reading order and a note on
how the briefing was written, is at the end of this chapter (section 11). The set also has front
matter — `00-index.md`, "How To Read This Briefing" — which carries the same contents list, a
consolidated glossary, and a single master status table covering all thirteen chapters at once. A
reader who wants one page rather than one chapter should start there.*

---

## A note on one word, before anything else

This briefing keeps returning to one small object, so it is worth naming it once, clearly.

A **checker** is a small, fixed program — *not* artificial intelligence — that looks at evidence
already collected and answers one narrow question: *is this specific weakness present in this
material, yes or no?* It has no opinions, no memory, no discretion and no imagination. It is closer
to a laboratory assay or a litmus paper than to a person forming a judgement.

The project's own name for a checker, in the software and on some of its screens, is an **oracle**.
The later chapters of this briefing were written at different times and also call the same object a
*judge*, a *referee*, an *automatic test*, a *decision procedure* and an *assay*. **All six words
mean the same one thing.** In this chapter the word is **checker**; "oracle" appears only where the
software's own vocabulary is being quoted directly.

---

## The short version

*This section is about three pages. It is the whole argument in miniature; the rest of the chapter is
the evidence behind it.*

**What it is.** VIGIL is a security testing system. Its job is to attack computer systems that its
operator owns, or has explicit written permission to test, in order to find the weaknesses before a
real attacker does. It uses artificial intelligence to decide what to try next. It does **not** use
artificial intelligence to decide what is true.

**The problem it solves.** Security tools — and AI security tools especially — produce large numbers
of claims. Some are real. Some are not. Nobody downstream can tell which is which without redoing
the work by hand. That makes the output expensive to use and impossible to rely on in front of an
auditor, a regulator, a court, or a minister.

**The one idea that makes it different.** In VIGIL, a claim is not a finding until a small,
separate, non-AI **checker** has independently re-proved it from the evidence the system saved at the
time. A checker is deliberately simple: it has no network access, no clock and no randomness, so it
gives the same answer every time it is run. It is a recipe, not a chef — follow it twice with the
same ingredients and you get the same dish, with no judgement, no mood and no improvisation. The
evidence and the proof are then sealed into a signed certificate. Anyone can re-run that check
later, on their own machine, with no internet connection — and, for the largest part of the check,
without installing any of VIGIL's software at all. If the check does not come out the same, the
claim is withdrawn automatically.

**What that buys.** A finding stops being a claim you have to believe and becomes a receipt you can
re-test. Verifying a result becomes a mechanical replay that takes seconds, rather than a fresh
investigation that takes days.

**The honesty rule.** About any given question the system may say only four things: **FACT**
(proved), **LEAD** (suspected, not proved), **CLEAN** (conclusively disproved), and **INCONCLUSIVE**
(we could not tell). "Probably fine", "no issues found" and "secure" are not permitted outputs. This
is enforced by the structure of the software, not by a style guide. CLEAN is held to a *higher*
standard than FACT, because a false all-clear is more dangerous than a false alarm: nobody goes back
to look again.

**What it produces at the end of a job.** A single self-contained archive file — the **dossier**. It
holds three written reports (an executive summary, a technical report, and a prioritised remediation
plan), machine-readable exports, the signed proof for every proven finding, the tamper-evident
record of everything the system did, and a list of digital fingerprints for every item, so that
altering any part of it is detectable.

**What it refuses to do.** It will not call something proved on the AI's say-so. It will not report
"clean" when it could not actually see. It will not touch a target that is not named in a signed
authorisation document. It will not let its own automated learning promote a claim or grant itself
permission. It will not modify its own attacking code without human sign-off. And it will not obtain
credentials it was not given.

**Status, stated plainly.** The core proving machinery is built and has been run from end to end. The
six cloud and Kubernetes exploitation confirmations are complete and are part of the released
software. ("Kubernetes" is the standard system for running and coordinating large numbers of software
containers; it is the control layer under most modern cloud deployments.) The two Kubernetes ones
have been proven against a real Kubernetes cluster that the system stands up, owns and destroys
itself. The four cloud ones have been proven against saved evidence with no internet connection, and
what remains for those four is the act of pointing them at a live third-party cloud account, which
waits on that customer's own credentials, by design.
Safeguards over the system's own build and release — pinning exactly which third-party software the
system is built from, and blocking a build that pulls in a critical known vulnerability — were folded
into the released software during the day this was written; section 9.4 gives the exact position,
including the one part of it that is still a placeholder. Every deferral is named individually in
section 9, and none is presented as a completed field deployment.

**Two conditions a government reader must know up front**, both covered in full in section 6:

- **Licensing.** The licence shipped with this software excludes government and public-sector use
  from its free terms. Any use by, for, on behalf of, or funded by a government body requires a
  separate commercial licence from the copyright holder. This is a commercial matter, not a technical
  one, and it is the first thing a procurement reader should settle. Note that chapter 12 — the
  chapter that lists what an operator needs in order to run the system — does not repeat this point;
  section 6.1 below is where it lives.
- **A built-in refusal to test government hosts.** The software ships with a component designed to
  refuse `.gov`, `.mil`, `.edu` and `.int` addresses outright. Section 6.2 states exactly what it is,
  what an agency would have to change to test its own estate, and — importantly — the honest finding
  that this component does not appear to be connected to the live testing path today.

---

## 1. The problem this system exists to solve

### 1.1 Security testing produces claims, not evidence

When an organisation has its systems tested for weaknesses, what comes back is a report: a list of
statements of the form "this part of your system has this weakness, and here is roughly why we think
so." That report is a set of *claims*.

The person receiving it is then in an awkward position. Acting on a claim costs money and engineering
time. Ignoring a claim risks a breach. But to *check* a claim, they generally have to repeat the
original investigation — find the right person, rebuild the test, and see whether it still happens.
Checking is nearly as expensive as the original work.

So in practice, claims are believed or disbelieved on the reputation of whoever produced them. That
is not evidence. It is testimony.

Underneath this sits one structural fault. In almost every security tool, the component that
*decides* a finding is real and the component that *collected the evidence* are the same thing. The
scanner looks at a response, forms a judgement, and writes down the judgement. The raw material is
usually discarded, or kept in a form nobody can mechanically re-check. Once that happens the claim
can never again be tested independently. All that survives is the opinion — and an opinion cannot be
audited, cannot be handed to a third party, cannot be re-checked after a staff change, and cannot be
defended two years later in front of someone asking why a particular risk was accepted.

### 1.2 Automated tools make the problem worse, not better

Automated scanning tools have always produced a mixture of real problems and false alarms. A false
alarm is a report of a weakness that does not exist. Every one of them consumes the time of a skilled
person who must investigate and dismiss it.

Recent AI-driven security tools have made this sharply worse. A large language model — the kind of AI
that generates fluent text — is very good at producing a confident, well-written description of a
security flaw that is not there. This is not a rare malfunction; it is the ordinary failure mode of
the technology when it is asked to render a verdict. A fabricated finding reads exactly like a real
one.

The project's own survey of the field (`docs/research/FRONTIER.md`) puts the false-positive rates of
tools that let the AI decide the verdict at between 35 and 90 per cent, and records that the `curl`
open-source project ended its bug-bounty programme in January 2026 because of the volume of
AI-generated false reports. Those two figures come from that survey document, which cites external
sources; they are reproduced here as the project's stated motivation and have **not** been
independently re-measured for this briefing.

The important point does not depend on the exact numbers. It is structural: the more of the work you
hand to a system designed to sound certain, the less able you are to check it. When a large fraction
of reports are false, the rational response of the receiving team is to stop reading them. The tool
that produces the most findings becomes the tool that produces the most work and the least security.

### 1.3 The second problem: an AI that can act

There is a related danger that has nothing to do with truth and everything to do with control.

A security testing tool is, by its nature, a tool for attacking computers. When such a tool is driven
by an AI that can also run programs and reach the network, two failure modes appear:

- The AI can be *tricked*. Text on a target website can contain instructions aimed at the AI reading
  it. This is called prompt injection. A tricked agent may try to reach systems it was never
  authorised to touch — the operator's internal network, a cloud provider's internal credential
  service, or an innocent third party.
- The AI can simply be wrong about what is in bounds, and act on that error at machine speed.

Politely instructing the AI to behave is not a control. The project's phrase for its answer is
*"permission is infrastructure, not prompt"*: the boundaries are enforced by ordinary, non-AI code and
by firewall rules on the network, in places the AI cannot reach or argue with.

### 1.4 The hardest problem of all: proving that nothing is wrong

There is a third problem, and it is the one most security reporting quietly avoids.

Saying "we found a weakness here" is a claim about one specific thing. One good observation settles
it. Saying "there is no weakness here" is a claim about *every possible way* the weakness could have
shown itself. It cannot be settled by observation alone — you also have to show you were in a
position to see the problem if it had been there. A silent smoke detector means nothing if the
battery is out.

Most tools blur this. If a test does not trigger, the surface is quietly listed as fine. But there
are two completely different reasons a test does not trigger:

1. The weakness genuinely is not there. That is real information.
2. The tool could not see. The page could not be read, the response was cut short, the encoding was
   unsupported, there was no usable channel of observation at all. That is *no* information.

Folding case 2 into case 1 produces a false all-clear. VIGIL's governing document states the
consequence bluntly:

> Asserting a vulnerability that is not there destroys trust in every finding. Asserting safety that
> was not established is worse, because nobody goes looking again.

---

## 2. The one central idea

### 2.1 A claim only counts when an independent checker re-proves it

Everything in this system follows from a single rule, which the project calls its governing
invariant:

> The AI and every tool only **propose**. Only a deterministic oracle mints a signed **fact**. Only
> the conjunctive gate **authorises** an action. Only the egress gate lets a packet **leave**.

That is the software's own wording. In ordinary language: four separate authorities decide four
different things, and **none of them is the AI**.

- The AI suggests what to try, and what a result might mean. It never decides that something is true.
- A small, plain, non-AI **checker** decides whether something is true. (This is the "deterministic
  oracle" in the sentence above. *Deterministic* means it always gives the same answer to the same
  question — a recipe, not a chef.)
- A separate permission check — the "conjunctive gate" — decides whether an action may happen at all.
  *Conjunctive* simply means that every one of its conditions must pass at once; one failure refuses
  the whole action.
- A separate network gate — the "egress gate" — decides whether a single packet of data may leave the
  machine. *Egress* means outbound: traffic on its way out.

### 2.2 An analogy: the laboratory test

Think about how a medical diagnosis is handled properly.

A doctor examines a patient and forms a *suspicion*. That suspicion is valuable — it directs where to
look — but it is not the diagnosis. A sample is taken and sent to a laboratory. The laboratory does
not care what the doctor suspected. It runs a defined procedure on the sample and reports what the
procedure says. The sample is retained. If the result is challenged, it can be re-tested by a
different laboratory, and the two results compared.

The doctor's suspicion is a **lead**. The laboratory result over a retained sample is a **fact**.

This system is built exactly that way:

| In medicine | In this system |
|---|---|
| The doctor's suspicion | The AI's proposal — always a **lead**, never a finding |
| The sample taken from the patient | The **retained evidence** — the exact material the real target produced |
| The laboratory test | The **checker** — a small, fixed checking procedure |
| The signed laboratory report | The **evidence certificate** — cryptographically signed |
| Re-testing the sample elsewhere | **Offline re-verification** by any third party |
| Chain of custody | The **append-only record** — entries can be added, never quietly changed |

The analogy holds in the uncomfortable direction too. A laboratory can only test for the things it
has a test for. This system is equally blunt about that: a suspected problem for which it holds no
checker stays a lead forever. It is never promoted because it sounds convincing.

### 2.3 What a checker is, in plain terms

A **checker** is a small program with one job: look at the evidence that was saved and decide, by a
fixed procedure, whether one specific dangerous condition is present. (The software's own name for it
is an *oracle*.)

Every checker, by design and by a rule stated in the code:

- is **pure** — its answer depends only on the evidence it was handed;
- is **deterministic** — the same evidence always produces the same answer;
- performs **no network activity** — it never contacts the target; it only judges material someone
  else already collected;
- reads **no clock** and uses **no randomness** — nothing about *when* it runs can change the answer;
- works entirely **offline**, with no internet connection.

Those restrictions are what make the guarantee possible. Because a checker cannot be influenced by
anything except the evidence in front of it, running it a second time — next week, on a different
machine, by a different organisation — must produce the identical answer. If it does not, something
has been altered, and that is precisely what the check is for.

There is one more design rule that matters more than it sounds: **a missing input is a skip, never an
assumed pass**. If the evidence a test needs is absent, the checker declines to answer. It never
treats absence as a clean result.

**How many checkers there are.** These counts were re-derived directly from the source code for this
briefing rather than copied from the project's documentation. Anyone can repeat that; section 11.1
says how.

| Count | What it counts |
|---|---|
| **38** | Distinct kinds of checker. |
| **40** | Individual checking functions implementing those 38 kinds. |
| **85** | Named categories of security weakness the system recognises. |
| **275** | Names it will accept in total for those 85 categories — the 85 proper names plus 190 alternative spellings used by other vendors and standards bodies, each mapped onto one of the 85 so nothing is double-counted. |

No checker may claim complete certainty. Its confidence figure is capped at 0.99, on the project's
stated principle that "a deterministic oracle never claims certainty it cannot have."

**A structural safety property, which matters more than it sounds.** Suppose the system meets a
claimed weakness belonging to a category it does not recognise. In that case it may fall back only on
a frozen set of **15** general-purpose checkers — and even then, a weakness in an unrecognised
category can never be confirmed at all. The remaining 23 checkers are specialised. Each one runs only
when a very specific kind of evidence is present, of a kind an ordinary website scan never produces.

Two consequences follow, and both are the sort of property a security reviewer should want:

- Adding a new capability to the system cannot change what an existing scan does.
- A checker built to confirm a stolen cloud credential can never fire by accident during a routine
  website test.

### 2.4 The sealed evidence bag

For a checker's answer to be checkable later, the evidence it judged has to be kept exactly as it
was.

Every confirmed finding therefore retains a copy of the precise material the checker looked at — the
raw responses the real target produced, the specific values compared, the markers used. The project
calls this the *oracle context*. It is the sealed evidence bag: the same sample, kept, so the same
test can be run again.

The physical analogy has one improvement in software. The bag's digital fingerprint is written into
the signed certificate, so a bag that has been opened and altered no longer matches its own
paperwork. Swapping the evidence and keeping the signature does not work, because the signature
covers the fingerprint of the evidence.

### 2.5 Anyone can re-run the check, later, offline

This is the practical payoff, and it exists in three increasing degrees.

**Degree one — the operator re-checks.** A single command re-runs every proof in a report against its
saved evidence. It reports success only if every certificate reproduces its claimed result and
matches the claimed confidence to within a very small tolerance; otherwise it fails and flags the
mismatch as possible tampering.

**Degree two — a recipient re-checks with VIGIL's own tooling.** The system can export a proof bundle
or a full dossier that a client, auditor or regulator verifies on their own machine, offline.

**Degree three — a recipient re-checks with no VIGIL software at all.** The project publishes a
written specification of the proof format and ships standalone verifier programs that deliberately
import **none** of VIGIL's own code — only the Python standard library and one cryptographic library,
written from the published specification. This is the strongest form, because it does not require the
verifier to trust any part of the system being verified. That verifier contains no offensive
capability whatsoever, never contacts the network, and exits with a plain success-or-failure code.

The limits of that third degree are stated openly in the verifier's own code and must be carried
forward here. The VIGIL-free verifier checks the signature; the separately supplied fingerprint of
the signing authority (explained in section 2.6 below); the binding between the signature and the
evidence; the integrity of every stored item; and the integrity of the append-only record. It does
**not** re-run the checker itself — re-running a checker needs that checker's own code, which is a
VIGIL component. So the fully independent step proves the evidence is authentic and unaltered;
re-running the test procedure over that evidence is a second step, and it uses VIGIL's tooling.

### 2.6 A signature is only as good as its anchor

Each proof is signed cryptographically. Chapter 7 covers signing properly; two points belong here
because they change how a reader should interpret a certificate.

First, a signature proves that whoever holds a particular key produced these exact bytes, and that
the bytes have not changed since. It does not, by itself, prove *who* that is.

Second, the system therefore requires that the identity of the signing authority — its *trust root*,
meaning the one key everything else traces back to — be pinned **out of band**. "Out of band" means
published separately, by the operator, through some channel other than the package being checked: a
website, a letter, a signed email. It works the way a notary's specimen signature works. You do not
verify a notarised document by comparing its signature with the copy of the signature printed on the
same document; you compare it with the register held somewhere else. A verifier here does the same,
comparing the fingerprint it was handed separately against the one inside the package. This closes
the obvious attack, which is to alter the evidence and re-sign it with a freshly made key: the
forger's key will not match the separately published fingerprint, and the package is refused before
any signature is even examined.

The user interface reflects this. A fingerprint that came from inside the bundle is labelled
"self-asserted, in-bundle — NOT a pin", and an unpinned trust root is displayed in a neutral state,
never a green one.

### 2.7 The proof is re-run at every stage, not inherited

This is the part that is easy to underestimate.

In a normal software pipeline, each stage trusts the stage before it. Component A says "confirmed",
component B writes "confirmed" into the report. That is *string trust*: passing a word along.

This system does not do that. The proof is **re-executed** at every point where trust could otherwise
be inherited:

1. **At confirmation.** The checker runs over the retained evidence and must fire with a confidence of
   at least 0.70.
2. **At admission.** The result is checked against a published register that declares, per kind of
   evidence, whether that kind of evidence may produce a fact at all. If it may not, the result is
   demoted to a lead regardless of how strongly the checker fired.
3. **At certification.** A certificate is built and signed, binding the verdict to the fingerprint of
   the evidence.
4. **At claim admission.** A separate component re-runs the cited proof again, and checks that the
   evidence genuinely belongs to that claim — for instance, that a proof of one kind of weakness has
   not been relabelled as a different, more serious kind. This component is built so that it can
   *only* demote a claim or abstain. It has no path to promote anything.
5. **At report time.** Before a human reads it, every finding is graded once more by re-executing its
   own proof. A finding recorded as confirmed whose proof no longer reproduces is printed as a
   demoted lead, with the reason attached — never as a fact.
6. **Whenever anyone wants, afterwards.** The same check can be run by the customer, by an auditor,
   or by an adversary, offline.

The phrase used inside the codebase is *proof by re-execution, not string trust*. A useful way to
hold it in mind: the system does not remember that something was true. It re-proves it, every time it
needs to say so.

*One precise honesty note about stage 4.* The component at stage 4 — the project calls it the
anti-hallucination firewall — is built, is exercised by its own tests, and **is genuinely used at real
points in the running system**. Reading the code for this briefing, it is called when findings are
admitted during an engagement, at the shared point through which the report layer grades every
finding before printing it, on the defensive side's confirmation path, by the automatic critic that
checks whether a claimed proof really re-grounds, and by the component that refuses a claim the AI
cannot support.

What it is **not** is a single universal doorway that literally every statement in the system must
pass through. One significant route does not go through it: entries added to the system's internal map
of the target are graded by a shared labelling function instead. So the honest description is "used at
several real checkpoints, including report generation — not one universal choke point". It should not
be described as the latter.

A reader comparing chapters should know that the component's own source file still carries an
out-of-date note calling itself "caller-less" and "exercised only by its tests". That note is stale;
the call sites above are real and were read directly. Chapters 4 and 6 of this briefing describe the
position correctly. Stages 1, 2, 3, 5 and 6 above involve no such qualification.

### 2.8 The four words

Because the whole design turns on not overstating, the system restricts itself to a closed set of
four verdicts. This is enforced by the structure of the program, not by convention: the verdict is a
fixed list of four options in the code, so no fifth value can reach the output.

| Verdict | What it means in plain English | What it takes to say it |
|---|---|---|
| **FACT** | The stated problem was **established**, for that target, those inputs, that system state, during that observation window. | A VIGIL-owned automatic checker re-derived it over evidence VIGIL itself captured live through an authorised channel, and the certificate re-verifies offline. |
| **LEAD** | Something suggests this, but we did not prove it. | Any weaker signal: another tool's assertion, a rule of thumb, the AI's opinion, or a pattern match over material the system cannot fully read. |
| **CLEAN** | The stated problem was **conclusively ruled out**, for that target, those inputs, that system state, during that observation window. | There was a real channel of observation, the relevant evidence was actually available, and a conclusive check ruled the problem out. |
| **INCONCLUSIVE** | We could not tell. | Everything else. A first-class result, reported as such, never rounded towards CLEAN. |

Two things are worth pausing on.

**FACT and CLEAN are both bounded observations, not timeless properties.** A live system changes. A
verdict describes what was established during a specific observation of a specific configuration. It
works like a vehicle roadworthiness certificate: it says the vehicle passed a defined set of tests on
a stated date, not that the vehicle is safe forever. The project treats this as costing CLEAN nothing
— a conclusive refutation under stated conditions is exactly what a defender needs — while keeping
the claim honest about what a single observation can support.

**A claim from the AI cannot become a FACT by a side door.** The saved evidence carries a note of
where it came from. (The technical word for that note, used throughout this briefing and the
software, is *provenance*: simply the record of a thing's origin, like the ownership history attached
to a painting.) If that origin is the AI itself, the finding is demoted to a LEAD *even if a checker
fires over it* — because evidence shaped by the AI is an AI-influenced route to a fact. Only evidence
captured by the system's own governed execution path qualifies.

---

## 3. Proving the negative — the harder half

### 3.1 Why "we found nothing" is a stronger claim than "we found something"

"There is a problem here" is settled by one good observation. "There is no problem here" is a claim
about every way the problem could have appeared, and so it additionally requires proof that the
system was in a position to see it.

The system encodes this directly. Each individual test result carries an honesty flag recording
whether the check had a real, observable channel and reached a definite verdict. A test that simply
failed to trigger, with no channel to observe through, is marked not-conclusive — and a
not-conclusive non-trigger yields INCONCLUSIVE, never CLEAN.

The rule as written in the code: *a payload that was sent, with no checker able to adjudicate the
result, is inconclusive, never clean.* A **payload**, here and throughout the briefing, simply means
the test input the system deliberately sends to a target to see how it reacts — the equivalent of the
reagent a laboratory adds to a sample. To *adjudicate* is to reach a definite yes-or-no verdict. So
the rule reads: if we poked it and had no way of telling what happened, we say we could not tell.

There is one further structural safeguard. When several individual results are combined into an
overall answer, an **empty set of results combines to INCONCLUSIVE, not CLEAN**. Nothing examined is
not the same as nothing found.

### 3.2 Only some evidence sources are allowed to say CLEAN

The system keeps a public register of every distinct **source of evidence** it can draw a verdict
from. A source of evidence is one specific window onto the target — for example, "the summary
information the server sends back with a page" is one window, and "the visible text of the page
itself" is a different one. The same weakness seen through two different windows counts as two
sources, because the two windows do not offer the same view. (The software's own word for one of
these windows is a *branch*, which other chapters use.)

Each entry in the register declares, separately:

- whether that source may produce a signed FACT;
- whether *nothing happening* at that source may be reported as CLEAN;
- what conditions must hold for the evidence to be usable at all;
- an honest written statement of what that source cannot see.

Verified for this briefing by reading the register itself: it currently holds **26** sources of
evidence. **All 26** may produce a FACT. Only **6** may produce a CLEAN — and all six of those look at
message headers, the network connection itself, or the encryption handshake, all of which the system
can read completely from beginning to end. Every source that depends on reading the body of a page,
interpreting an exported configuration file, or capturing a live cloud response may currently say
only FACT, LEAD or INCONCLUSIVE.

This register is not documentation. It governs behaviour while the system runs: a verdict from a
source that is not in the register is refused outright; a source not marked as able to produce a fact
is demoted to LEAD even when its check fires; a source not marked as able to produce a clean result
returns INCONCLUSIVE instead of CLEAN.

An example makes the distinction concrete. An *open redirect* is a page that can be made to forward a
visitor to an attacker's website. When that is detected from the summary information the server sends
back with the page, the source may produce both a FACT and a CLEAN, because that summary information
can be read in full. When the same problem is detected from the visible body of the page, the source
may produce a FACT but **not** a CLEAN — and the register states why in one line: nothing happening
cannot distinguish "the document contains no redirect" from "we could not read the document".

### 3.3 A capability gap must be named, not quietly dropped

The register also records, for each source, what it *must become*. Any gap between today's capability
and that target must name the specific engineering work that closes it. A gap with no named work
fails the automated check that runs on every code change. Lowering a target at all requires a written
argument that the capability is not achievable, not merely inconvenient.

The stated purpose of this rule is to prevent the most common way an honesty policy decays: quietly
redefining every inconvenient capability as out of scope, so that every sentence stays technically
true while the product becomes honest about doing less and less. The project's governing document
opens with the principle in one line: *"This document raises the system; it does not lower the
claim."*

### 3.4 The negative results the system does ship

Three signed documents carry negative claims. Each states its own limit *inside* the signed contents,
so the limit cannot be stripped off and the result read more broadly than it deserves. Here they are
in summary, with a short explanation of each below.

| Document | What it establishes in one line |
|---|---|
| **Coverage certificate** | Which places were actually examined, and whether a relevant checker really ran there. |
| **Certificate of Non-Exploitability** | A per-item verdict of CLOSED, OPEN or UNPROVEN for a named target. |
| **Remediation certificate** | That a weakness which provably worked is now provably dead. |

**The coverage certificate.** For each place the system tested, this records whether a relevant
checker actually ran and reached a verdict. That turns a surface where nothing was reported from
"merely untested" into "provably tested and clean". Its stated limit is important and is written
inside the signed contents: it certifies coverage of the surfaces the system actually *reached*, not
proof that it reached the whole application. The boundaries of the exploration are named in the
document itself — how many pages were visited, how deep it went, whether the list of things still to
examine was cut short, and whether the run's budget ran out.

**The Certificate of Non-Exploitability** (the project also calls it the posture certificate). This is
a signed, item-by-item statement of CLOSED, OPEN or UNPROVEN, tied to an owner-signed statement of
which target it applies to. CLOSED carries a precise and narrow meaning: not exploitable *by this
family of checkers, over the surface actually reached, as of the stated date.* It never means "secure
against everything". UNPROVEN never quietly counts as CLOSED. And the system structurally refuses to
issue a CLOSED that cannot name the specific checker that conclusively ruled the problem out.

**The remediation certificate.** This establishes that a weakness which was proven to work no longer
does: the original checker went silent over freshly captured material from the fixed system. Silence
only counts as a fix when it is controlled, so three conditions apply. A known-good twin test must
still fire, proving the test rig is alive rather than broken — the same reason a laboratory runs a
positive control alongside the real sample. The target must genuinely have answered. And only a fixed
list of 13 checker types is accepted as sound to certify a fix by silence; every excluded type has a
written reason for its exclusion. All four possible outcomes are signed, so an inconclusive result
cannot be discarded and the remainder re-read as a success.

---

## 4. What the system actually is

### 4.1 One product, two deliberately separated halves

VIGIL is a single body of software containing two things most products would never put in the same
box:

- an **offensive** security engine that attacks authorised targets; and
- a **sovereign personal assistant** that runs on the operator's own machine, remembers their work,
  and can act on their files, terminal, screen and accounts with permission — and which has, by
  construction, **no offensive capability at all**.

They are kept apart by a boundary that is structural rather than procedural. They run as two separate
programs, in two separate software environments, which never share a running process. The personal
side's environment does not contain the attacking code at all — so the rule "the personal assistant
cannot load offensive code" holds because the code is not installed there, not because something
remembers to check. A dedicated automated proof, run on every code change, builds a real isolated
environment and demonstrates that the offensive code genuinely cannot be reached from the owner's
side. It also includes a deliberate negative control: it loads the offensive code on purpose and
confirms the guard fires, so the guard cannot be trivially passing.

The two halves are joined by exactly one channel, and it carries **data only, never running code**. A
finding crosses as a signed, inert message: the receiving side parses it as plain data, checks size
and shape, and verifies the signatures before writing anything. Crucially, the offensive half **holds
no owner signing key at all** — this is declared in the project's own configuration file, which
records the offence environment as a keyless trust domain. It can package a confirmed finding; it can
never mint a trusted record.

The plain-language safety argument: *the half that attacks holds no key and cannot be loaded into the
half that does; findings cross as signed inert bytes, never as running code.*

### 4.2 The named parts

| Name | What it is | Plain-English role |
|---|---|---|
| **VIGIL** | The whole product. | One control surface over the two separated halves. |
| **CRUCIBLE** | The offensive engine. | *Crawls* an authorised target — that is, follows its links page by page to build a list of everything reachable, the way a search engine indexes a website — then probes and attacks its inputs, and calls something a weakness only when a checker fires over the target's real output. |
| **AEGIS** | The defensive counterpart — the same proving core pointed inward at the operator's own systems. | Detects and proves attacks against the operator's own applications, using the operator's own logs, and issues a re-verifiable certificate rather than an alert. |
| **SIGIL** | The sovereign personal side. | An offence-free local assistant with a signed, append-only memory. Every action it takes is classified into a permission tier. |
| **STRIX** | A *vendored* third-party testing tool — meaning a copy of somebody else's software kept inside this one, under its original Apache-2.0 licence and with its original attribution intact. | One of the *proposing* agents. Its output must survive the same checking as anything else. |
| **The gateway** | The outbound network gate. | A deny-by-default firewall plus a filtering relay that together decide whether any packet may leave. "Deny by default" means nothing gets out unless it has been specifically permitted. |
| **The shared core** | A small, self-contained library both halves stand on. | The single implementation of the signed record, the cryptography, the permission classifier and the authorisation gate — so the two halves cannot drift apart. |

Each of these is described properly in chapter 2, on the parts of the system.

### 4.3 The role of the AI

The reasoning is done by Claude, Anthropic's AI. It reads a target, forms a model of it, generates
hypotheses, and proposes what to try next — the same way a skilled human tester brainstorms.

It is never believed. Its output is parsed conservatively: if the AI's response is malformed, the
system degrades it to the safest possible action rather than guessing at the intent, and a total
parse failure pauses for a human. Its analytical conclusions enter the record as LEADs. A claim by
the AI that an attack succeeded triggers the automatic checker to re-run over the raw captured
output; only the checker's confirmation produces a fact.

One more rule applies to the AI's cousins. A panel of automatic critics reviews findings; their
possible verdicts are *endorse*, *object* or *abstain* — deliberately never *confirm*. Critics can
advise, or make the gate stricter, or decline to answer. They cannot promote anything.

### 4.4 The permission side, in brief

Nothing that touches a target happens without passing a combined check where **every** condition must
hold simultaneously: the action must be inside a signed engagement authorisation that has not expired
and has not exhausted its budget; a classifier must rate the action as safe enough to run
automatically; and for destructive actions, a threshold of independent signers including the owner
must have authorised that specific action. Any failure in any condition, and any *error* in any
condition, is a refusal. There is also a kill switch: a file on disk which, while it exists, causes
every action to be refused — and because it is a file rather than a setting held in memory, tripping
it survives a crash or a restart. The check is written so that any uncertainty about whether the
switch exists reads as "halted".

That last property has a name used throughout this briefing: **fail-closed**. It means that when a
safety check cannot be completed — because of an error, an unreadable file, a missing component — the
answer is *no*, not "carry on". Think of a drawbridge held up by an electric motor: cut the power and
it falls shut. A safety check that says "allowed" when it breaks is worse than no check at all,
because it manufactures false confidence.

Chapter 8 covers the gates in full; the point for this chapter is that they are ordinary code and
firewall rules, not instructions to the AI.

---

## 5. Who it is for

The project states its intended users as:

- **Professional security testers** — the people paid to attack a client's systems with permission —
  who are tired of sifting a scanner's confident noise. Every finding arrives with a proof that can be
  replayed, so sorting the real from the false becomes a replay rather than a fresh investigation.
- **Independent researchers who report weaknesses for a reward** and need a report that cannot be
  waved away: a signed proof package that the recipient can check on their own machine with no
  internet connection, rather than a screenshot.
- **Security researchers** who want a working environment in which a claim is only as good as its
  re-execution, and where the tool's own blind spots are measured rather than hidden.
- **Defenders and auditors** who need evidence that survives scrutiny — a permanent, signed record of
  exactly what was tested, what was proven, and what was skipped, to which entries can be added but
  never quietly changed.

To that list a government reader should add a fifth, which is the one this design most
distinguishes: **an oversight, assurance or procurement function that needs to know what a
supplier's security claim is actually worth.** Because the proof travels with the finding and can be
checked without the tool that produced it, a customer can verify a supplier's security report without
trusting the supplier — and without trusting the vendor of this system either.

### 5.1 What a user needs to be able to do

Running the system requires a competent technical operator. It is not a self-service product for a
non-technical user. It installs on hardware the operator controls, has a web interface and a command
line, and expects the operator to hold and protect signing keys.

**Verifying its output, by contrast, is deliberately easy and deliberately cheap.** A third party
needs one small program and a single command, and for the largest part of the check needs none of
this system's software at all.

---

## 6. Two conditions a government reader must settle first

Both of these are real, both are in the repository, and neither is comfortable to write in a briefing
document. They are given their own section — rather than a footnote inside "who it is for" — because
they are the two questions a public-sector reader will need answered before any of the rest matters,
and because omitting them would be exactly the kind of quiet misrepresentation this system exists to
prevent.

### 6.1 Licensing: public-sector use is not covered by the free licence

The first-party code — the parts written by this project rather than borrowed from others — is
**dual-licensed**. That means the copyright holder offers it under two alternative sets of terms, and
the user takes whichever one applies to them:

- the **PolyForm Noncommercial 1.0.0** licence, free of charge, for non-commercial purposes; or
- a **commercial licence** from the copyright holder, required for commercial or production use.

The free licence carries a supplemental term that **excludes government and public-sector use**. In
the licence's own words, use by, for, on behalf of, or funded by any government, government agency,
department, ministry, military, intelligence body, law-enforcement body, public authority,
state-owned enterprise or other public-sector entity is **not** a permitted non-commercial purpose
and requires a separate commercial licence — even where the use would otherwise be entirely
non-commercial.

Two details matter for a procurement reader:

- The stock PolyForm Noncommercial licence, in its unmodified published form, actually *does* list
  government institutions as permitted non-commercial users. This project's supplemental term is
  written specifically to reverse that, and is stated to override any contrary provision in the
  licence text beneath it. So a reader who checks the standard licence alone will reach the wrong
  conclusion.
- Third-party components kept inside the product — the vendored testing tool STRIX, for example — keep
  their own separate licences (Apache-2.0 in that case). The government exclusion is a term of the
  first-party code.

This paragraph is a plain-language summary written for orientation. The binding terms are the licence
files themselves (`LICENSE` and `LICENSE-COMMERCIAL.md` in the repository), and the licensing question
is a commercial matter to settle with the copyright holder, not a technical one.

**Where else to look.** Chapter 12 is the chapter a buyer would naturally read to build a shopping
list of what is needed to run the system: hardware, credentials, external tools, and so on. It does
**not** mention licensing. Within the thirteen chapters, this section is the only place the licensing
position is stated; the set's front matter (`00-index.md`, section 9.1) repeats it for the same
reason. A procurement reader should carry it forward into any requirements list themselves, because
no chapter will do it for them.

### 6.2 A built-in refusal to test government hosts — and what an agency would have to change

The software ships with a component whose only job is to refuse an entire category of targets
outright, before the written authorisation or any permission gate is even consulted.

**What it blocks.** Government addresses (`.gov` and its national equivalents such as `.gov.uk`,
`.gouv.fr`, `.gob.mx`, `.govt.nz`, `.go.jp`, `.gv.at`), military addresses (`.mil`, `.mil.br`),
educational addresses (`.edu`, `.edu.au`, `.ac.uk` and equivalents), and international-organisation
addresses (`.int`) — plus **186** explicitly named intergovernmental organisation addresses that sit
on ordinary endings such as `.org` or `.eu` and would otherwise slip through. That list covers the
United Nations system and its regional commissions, the specialised agencies, international courts and
tribunals, the World Bank group, European Union institutions, regional bodies, development banks,
arms-control and treaty organisations, major international scientific facilities, climate and
environment funds, the Red Cross and Red Crescent movement, river-basin commissions, and standards
bodies.

**Why it exists.** Defence in depth. If the AI is manipulated by text on a web page, or the operator
mistypes an address, the intent is that neither mistake can ever redirect an automated attacking agent
at a government or military host. It is written as a pure refusal: it can only block, never authorise,
and it never grants permission to anything.

**Why it is hard to fool.** Two details, both worth understanding because they show the standard of
engineering:

- It folds *look-alike characters*. Several characters in the international character set look like a
  full stop and are treated as one by web browsers, but are not the same character to ordinary text
  processing — so `un。org`, written with a Japanese full stop, would evade a naive list. The component
  converts these to ordinary dots before matching.
- It reads the address **two different ways**. Two widely used pieces of web-client software genuinely
  disagree about how to interpret a backslash inside a web address, and a block list that matches only
  one interpretation is bypassable by whoever uses the other. This one blocks if *either* reading
  reaches a protected host.

**For a national agency, this cuts both ways, and must be stated clearly.**

- It is a strong safety property: a tricked or misconfigured agent cannot be pointed at a government
  or military host by name.
- It is a practical constraint: pointing the system at an agency's *own* `.gov` estate by domain name
  would require this refusal to be deliberately changed.
- It matches on **domain names, not numeric addresses**. A target given as a bare numeric internet
  address is not covered by this list at all; such targets are governed by the written authorisation
  and the outbound network gate instead.

**What an agency would actually have to change, stated plainly.** The component takes no settings and
has no switch. It is a fixed list plus a set of address-ending patterns compiled into the software,
and it consults no configuration file. So testing an agency's own `.gov` estate by domain name is not
a matter of setting an option; it would require **a deliberate change to the software** — either
amending the patterns and the named list, or adding a narrow, explicitly authorised exception route
into the component. Neither exists today.

What would be lost by making that change is precisely the property the component provides: the
guarantee that no chain of errors or manipulation can ever aim the system at a government host by
name. Any agency making that change should expect to replace it with an equivalent control — for
instance, a signed authorisation naming only its own estate, and an outbound network gate configured
to permit only those addresses. Both of those controls already exist and are described in chapter 8.

To be direct about the state of this: **the briefing cannot tell you that a supported route exists,
because none does.** This is unresolved and would need product work, agreed with the copyright holder
alongside the commercial licence discussed in section 6.1.

**Verification note, and it matters.** The component exists, can only ever deny, and is covered by its
own test file including deliberate evasion attempts. Reading the code for this briefing, its main
function is exported from the safety package and exercised by those tests — but a search of the whole
repository found **no call to it from any live path**: not the scanning engine, not the gates. The
honest description today is therefore *a shipped and tested safety component whose connection to the
live path could not be verified*, not *an active control*. A reviewer can confirm this in a minute by
searching the repository for `assert_not_hard_blocked` and observing that the only matches are its own
definition and its tests.

The controls that *are* demonstrably active before any target is touched are the signed written
authorisation, the scope check, the permission classifier, the combined authorisation gate, and the
outbound network gate. Chapter 8, section 2.5, is the authoritative account of this component and
should be read alongside this section.

---

## 7. What you get at the end of a job

### 7.1 The dossier

A completed engagement can be packaged into a single archive file with one command. Verified from the
code that builds it, that archive contains:

- **Three written reports** (below).
- **Machine-readable exports** of the findings, in two standard formats (JSON, and SARIF — a format
  that software-development tools can read directly, so findings can be loaded straight into an
  engineering team's own systems).
- **The proof package** for every proven finding, checkable with no internet connection.
- **The engagement log**, with any secrets automatically stripped out before it is written.
- **The signed record** of everything the system did, in a form where each entry seals the one before
  it, so a page cannot be removed or altered without breaking the chain.
- **Any drift record** — a note of changes observed between one run and the next.
- **A readable index page** that prints the exact command a recipient types to re-verify the package.
- **A manifest** listing every item with its digital fingerprint, plus a signature over that manifest
  and the fingerprint of the signing authority to be checked against a separately published copy.

Three properties of that archive are enforced in code:

- **Tampering shows.** Change a single character anywhere in any item and the manifest check fails.
  Re-sign the whole thing under a different key and the separately published fingerprint refuses it
  before any signature is even examined.
- **Honesty about signing.** If no signing authority is available at the time, the archive can still
  be checked for internal consistency by its fingerprints, but is explicitly marked as **not** signed
  for authenticity. A run that produced no proven finding carries no proof package and says so plainly
  rather than shipping an empty one.
- **The same inputs always produce the same package.** Build it twice from the same material and the
  fingerprints match, so a recipient can confirm they were given the same package as everyone else.
  There is no hidden timestamp buried in the fingerprinted content that would make two identical
  packages look different.

### 7.2 The three reports

| Report | Audience | What it contains |
|---|---|---|
| **Executive summary** | Non-technical decision-makers. | Leads with plain-language impact. The "what we found" section lists **only proven facts** as confirmed. Unproven leads live in a separate, clearly labelled section and are never written as things an attacker can do. |
| **Technical report** | The engineering team. | Per-finding detail, reproduction steps and remediation, with a verification block that either shows the automatic proof (which checker fired, the calibrated confidence, and the fingerprint of the re-runnable certificate) or labels the item a LEAD. |
| **Remediation roadmap** | The person planning the work. | Fix order by impact against effort, over proven findings only. Leads are listed separately and are never inserted into the fix order. |

All three are produced by a fixed procedure with no clock and no randomness: the same findings render
identically every time, unless the operator explicitly asks for a timestamp.

One detail worth noting for a reader used to security reports: the confidence figure attached to a
finding is not a fixed 1.0. It is a probability learned from recorded past outcomes and capped at
0.999, on the stated principle that a detector never claims a certainty it cannot have. Where there
is too little historical data to learn a reliable figure, the system does not invent one — it degrades
to a pass-through rather than manufacturing a number.

### 7.3 How a third party checks it

The intended workflow for a recipient is:

1. Obtain the publisher's trust-root fingerprint — the fingerprint of the one key everything traces
   back to — through a channel other than the archive itself: a website, a letter, a signed email.
   This is the anchor, and it is deliberately *not* the copy of the key shipped inside the package.
2. Run the standalone verifier program against the archive, supplying that fingerprint.
3. Read the exit code. Zero means sound. Anything else means not sound, and it says which check
   failed.

No network connection is required. No account is required. The tool that produced the evidence does
not need to be installed, trusted, or even to still exist.

---

## 8. What the system deliberately refuses to do

Each of these is a refusal built into the code, not a policy statement. They are grouped by what they
protect.

### 8.1 Refusals that protect the truth of the output

| Refusal | Where it comes from |
|---|---|
| The AI may never promote its own claim to a fact. | The governing invariant; the confirmation path; the safety-net layer that can only demote. |
| Evidence whose origin is the AI is demoted to a LEAD even when a checker fires over it. | The origin check ("provenance", the record of where a thing came from) on the route from evidence to fact. |
| Automatic critics may object or abstain, but the verdict type has no "confirm" option. | The critic panel's verdict type. |
| A checker that stayed silent may not be automatically recorded as a false alarm — that would be the checker judging itself. | The record the system keeps of how its own past guesses turned out, which it uses to learn. Before it will label a past attempt a success, at least two *different kinds* of checker must have fired on the same evidence; one checker alone leaves the attempt marked "disputed" and excluded from the learning. |
| The system's own learning may re-order what it tries first, but may never gate off a surface, grant permission, or decide something is true. | The learning components' stated limits: the ordering mechanism "orders effort" only; in-loop reflection may re-rank or defer, never skip a surface. |
| A weakness category the system has never heard of can never be confirmed, even if a fallback checker happens to fire. | The confirmation step, which fails closed on unknown categories and says so in its written rationale. |
| A proof for one category of weakness cannot be relabelled as another and still verify. | The re-verification step refuses a category that differs from the one the retained evidence adjudicates. |
| "Probably safe", "no issues found" and "secure" are not available outputs. | The verdict vocabulary is a closed set of four. |

### 8.2 Refusals that protect the target and third parties

| Refusal | Where it comes from |
|---|---|
| Nothing may touch a target without a signed authorisation document naming that target, and a record of who did what, and when, written *before* anything runs rather than after. | The authorisation gate and the usage ledger. |
| A stop switch, once tripped, survives a crash or restart, and any uncertainty about whether it is tripped reads as tripped. | The kill switch, which reports "halted" unless absence can be positively determined. |
| Three kinds of network destination can never be re-enabled by any authorisation: the address a computer uses to talk to itself, the addresses machines use to find each other on a local network, and the internal service that hands out a cloud machine's credentials. The stated reason is that naming any of these is far more likely to be a manipulation attempt or a mistake than a genuine intention. | The outbound block list, which is the single shared source of truth for both the firewall and the filtering relay. |
| The isolated space the attacking tools run in has no route to the internet other than the gate. An agent that switches off its own relay setting gains nothing, because the host machine drops the packets anyway. That isolated space is also stripped of the privilege needed to rewrite its own firewall rules. | The firewall rules, and the configuration of the *container* — the sealed, pre-packaged operating environment the attacking tools run inside. |
| Third-party services — payment processors, identity providers, hosting providers, content delivery networks, email providers — are out of scope by default. The operator's own connection to them may be tested; the third party itself may not. | The engagement doctrine and the written authorisation's scope table. |
| The system never makes itself reachable from the public internet. A deployment placed behind a public web address without an access key is refused outright. | The deployment guard, and the interface's rule of listening only on the address the machine uses to talk to itself. |
| The checker that tests whether a cloud identity could grant itself more power deliberately never *performs* that escalation. It re-derives the answer from the saved configuration instead. | That evidence source's own design note: a defensive verification checker never executes the attack it is verifying. |
| Attempting to slip past a customer's own protective filters is off by default, must be switched on for a specific engagement, is capped in volume, runs through the governed execution path, and is framed as a way to demonstrate that a filter *can* be bypassed — not as a weapon for going further. Getting past the filter is not itself a finding unless a checker then fires. | The evasion module's own documentation. |

### 8.3 Refusals that protect the operator

| Refusal | Where it comes from |
|---|---|
| The offensive half holds no owner signing key, so it cannot forge a trusted record even if fully compromised. | The environment declaration and the keyless worker. |
| The personal assistant has no offensive capability, and the component that handles outbound communication has **no send method at all** — it can only write drafts marked as awaiting approval. There is no path to promote it. | The agent design and the structural no-promotion list. |
| The component that can act on the owner's own online accounts has no impersonation parameter of any kind, and stops when it meets a block rather than trying to defeat it. One approval authorises exactly one action, so an approval can never be replayed. | The same agent design. |
| The system cannot change its own attacking code by itself. It may draft proposals for its own improvement, but accepting one requires a specific granted permission, a passing run of the full existing test suite, **and** signatures from several independent governance holders — and even then the gate only *authorises*; a human being applies the change. | The improvement gate, whose stated purpose is to prevent "an uncertifiable, unattributable, self-mutating offensive tool". |
| Signing keys are used for signing only when the system is first set up. The running system only ever *checks* signatures; it does not hold the means to create new ones. | The cryptography module's stated split. |
| The system does not obtain credentials it was not given. For cloud testing, access exists only because the account owner supplied it. | The design of the cloud capabilities — and the direct reason testing against live third-party accounts is deferred. |
| Where a component is missing, the system says so rather than simulating it. A required tool that is present but is actually a different program of the same name is reported as such, not as installed; an optional database that is not running causes its output to be left out with a clear message. | The tool registry and the database connector, whose code comment states that it never fakes a connection. |

---

## 9. Honest status: built, proven, and deliberately deferred

This section exists because the project's own doctrine requires it, and because a national agency
must not be misled about the difference between a capability that exists in code and a capability
that has been exercised against a live system.

Three phrases are used consistently below, and it is worth fixing their meaning before the lists:

- **Part of the released software.** The work is finished and folded into the main version of the
  product that an operator would install.
- **Written and working, but not yet folded into the released version.** The code exists and can be
  read and run, but sits in a separate working copy awaiting final review — in the same way a finished
  chapter is not yet a published book.
- **Proven against recorded sample data.** The capability has been demonstrated end to end using
  saved material standing in for the real thing, rather than against a live outside system. The
  project's own word for that saved material is *fixture evidence*: a saved, unchanging copy of the
  sort of material the real thing produces, kept so that a test can be run over it repeatedly and get
  the same answer.

**One note about the middle phrase, because it affects how this briefing should be read against its
companions.** At the time of this revision, nothing described in this chapter is in that middle state.
The one item that was — the build-and-release safeguards in section 9.4 — moved into the released
software during the day of writing, and section 9.4 has been rewritten to say so. Earlier drafts of
chapters 6, 9 and 12 describe that same work as still awaiting that step. They were accurate when
written. If the copy you are holding still says so, section 9.4 is the later reading, and the front
matter (`00-index.md`, section 10.2) records the change explicitly. Naming a drift like this, rather
than quietly tidying it away, is what the project's own rules require.

### 9.1 What is working end to end

- The core proving pipeline: propose, capture, check automatically, admit, sign, re-verify with no
  internet connection.
- The 15 general-purpose checker types against a live web target. (These 15 are the frozen fallback
  set described in section 2.3. They are not the same thing as the 11 standard opening checks that
  chapter 3 describes a run as always performing — that is a different list, of tests to *try*, not of
  checkers that confirm.) The project ships a negative control for this: pointed at a deliberately
  *safe* version of the same application, the confirmation step returns nothing — demonstrating that
  the confirming authority does not rubber-stamp.
- Network reachability, encryption weakness, software-version-in-advisory-range, and the web
  achieved-state checks against real captures.
- The permission gates; the signed record that can be added to but never quietly edited; the usage
  record and the ability to replay it; the dossier; and the route by which a recipient re-checks
  everything without an internet connection.
- A signed, reproducible benchmark run on the project's own machine on 4 August 2026. On a
  purpose-built application with 11 planted weaknesses and 5 deliberately safe controls, the engine
  reported 11 true positives, 0 false positives and 0 misses; the three comparison tools scored 0, 2
  and 0 true positives with 0, 7 and 8 false positives respectively. The benchmark document itself
  carries fairness caveats which must be carried forward: the ground-truth manifest uses the engine's
  own naming vocabulary, so its perfect score is *partly a home-field artifact*, and the honest,
  portable claim is the narrow one — every finding reported was automatically confirmed and offline
  re-verifiable, and none of the five safe controls was flagged. It is explicitly **not** a claim of
  finding everything, and not a general superiority claim.

### 9.2 What the live validation actually covered

The project states this itself, and the wording matters: the full end-to-end validation ran against a
**purpose-built deliberately vulnerable application on the machine's own loopback address** — proven
on a local target, not "proven in the field."

A live external run is also recorded against a vendor-published deliberately vulnerable test site,
producing two automatically confirmed findings, re-verified offline two out of two, with a
deliberately altered byte correctly rejected. That record is reported in the project's own
documentation; I read the claim, not the run.

### 9.3 Cloud and Kubernetes exploitation: complete; Kubernetes proven against a real cluster,
cloud awaiting the customer's credentials

Six capabilities covering cloud and Kubernetes exploitation are **complete and part of the released
software**. (Kubernetes, as noted in the short version above, is the standard system for running and
coordinating large numbers of containers; it is the control layer under most modern cloud
deployments.) They are:

| Capability | In plain terms |
|---|---|
| Metadata credential capture | A machine's cloud metadata service handed out a credential, and that credential really worked. |
| Exposed-secret validity | A secret found lying exposed is a *currently valid, working* credential — not merely a string that looks like one. |
| Service-account impersonation (Google Cloud) | One cloud identity can borrow another's identity, confirmed by the borrowed identity answering. |
| Identity privilege escalation | An identity's permissions let it grant itself more power than it started with. |
| Kubernetes access control, first tier | An anonymous, unauthenticated caller is attached to a dangerous built-in administrative role. |
| Kubernetes access control, second tier | A role genuinely *grants* dangerous powers — proven by reading the role's actual rules, not merely matching its name. |

All six are connected from end to end: the detection logic, the evidence handling, the verdict
routing, the certificates, the entry in the permanent record and the safety gates are all built and
registered. The two Kubernetes confirmations have been proven against a **real Kubernetes cluster**;
the four cloud ones are proven against recorded sample data with no internet connection. None of them
carries any recorded engineering gap — and under this repository's own enforcement rule, a gap between
what a capability does today and what it must eventually do *must* name the concrete work that closes
it, or an automated test fails. All six record no such work outstanding.

**The two Kubernetes confirmations are no longer waiting. The four cloud ones are.** That
distinction is recent, so it is set out precisely rather than summarised.

*Kubernetes.* Both tiers are now proven against a **real Kubernetes cluster** rather than against
recorded sample data. A script in the repository stands up a genuine single-node cluster — k3s version
1.31.5, in a container reachable only on the machine's own internal address — which the system
creates, owns, and destroys afterwards. It plants known-dangerous *and* known-benign access rules in
that cluster, captures what the real Kubernetes interface returns, and puts those real bytes through
exactly the path any other finding takes: automatic checker, admission, certificate, offline
re-verification. The dangerous case — an anonymous, unauthenticated caller bound to the cluster's full
administrative role — is confirmed, and its signed certificate re-verifies with no network. The benign
cases in the same cluster are correctly **not** confirmed, including the one that matters most: the
namespace's own default identity bound to the built-in `admin` role, whose real rules genuinely do
grant read access to secrets. That is the single most common legitimate arrangement in Kubernetes, and
a detector without a subject test would report it as critical on a completely ordinary cluster. This
one keeps it a lead. The script asserts every one of those expectations and exits with an error if any
of them fails, so it is a proof rather than a demonstration — and because the cluster is created
rather than borrowed, a customer, an auditor or a sceptic can re-run the whole thing on their own
machine and watch it happen.

Two things that run does **not** cover, stated so the claim is not read wider than it is. First, the
script reads the objects it planted, by name; it does not exercise a scope-gated **enumeration**
capability that discovers access rules across a whole cluster under authorisation. Second, the cluster
is one the system stood up itself, so a **managed provider's control plane** — Amazon EKS, Google GKE,
Azure AKS — is not exercised: the same Kubernetes interface, reached by a different access path.

*Cloud.* For the four cloud confirmations, what remains deferred is still the act of pointing them at
a live third-party cloud account. That waits on the customer supplying their own cloud credentials. It
is a deliberate design position, not an unfinished feature: a credential is a thing only the account
owner can supply, and the system is built not to obtain one any other way.

The honest sentence, which should not be softened in either direction: *for the four cloud
confirmations the logic, the evidence handling, the certificates and the safety gates are built and
proven against recorded sample data, and pointing them at a live third-party cloud account awaits that
customer's own credentials; for the two Kubernetes confirmations the same machinery has been run
against a real cluster and held.* Describing any of the six as "unfinished" understates the system.
Describing the cloud ones as "field-proven in customer clouds"
overstates it.

Four properties of these six capabilities are worth stating for a security-conscious reader, because
they are what makes the deferral safe rather than merely pending:

- **They cannot fire by accident.** None of the six checkers is in the frozen fallback set, so nothing
  on the ordinary scanning path can produce one. Each fires only when its producer is called
  deliberately over an authorised capture. An autonomous loop cannot wander into using a cloud
  credential.
- **The captures are secret-safe.** The credential itself is checked and fingerprinted in the
  computer's working memory and then thrown away. What is kept is only a blanked-out structural
  record, the fingerprint, and non-secret notes on where it came from — and yet the certificate still
  re-verifies with no internet connection and no live secret present anywhere in it.
- **Scope is checked before any network activity.** Cloud targets are authorised by cloud-native
  identity — the exact account, project or subscription named in full — rather than by the address of
  the cloud provider's shared interface, because authorising an interface everyone shares would
  authorise everyone's account. A wildcard or blank entry authorises nothing.
- **The transport must prove where it went.** The checker requires evidence of which address each
  call actually reached, that encryption was verified, and that no proxy or redirect intervened. A
  hand-written record can never become a fact.

One of the six must be described differently, and this distinction matters. The **identity privilege
escalation** capability is offline **by design, permanently**. It re-derives the escalation from the
operator's own retained configuration and compares what the identity could reach before and after. It
never executes the escalation, and never will — the project's stated principle is that a defensive
verification tool does not perform the attack it is verifying. It is not awaiting live fire in the
sense the three remaining cloud confirmations are: not performing the action *is* the design.

**But one clause must be added, or a reader will take that too far.** This capability still needs a
real capture of a real account's permission rules to work on. That capture comes from the customer's
own cloud account — either from the system's own read-only collection of a cloud account's settings,
or from an export the customer's staff produce themselves — and both of those require the customer's
read-only credentials, which section 9.5 lists as still outstanding. To date the capability has been
demonstrated only over saved sample captures. So the honest position is: *it still needs a real set of
permission rules from a real account, which needs the customer's read-only credentials; what it will
never need is to carry out the escalation itself.*

The capability also states its own boundary. The conclusion is drawn from the permission rules
present in the capture. A rule attached elsewhere and not captured — for example one attached to the
thing being reached, rather than to the identity doing the reaching — could still override it.

### 9.4 Build and release safeguards — now part of the released software

Everything else in this chapter is about proving that what the system *did* is true. This section is
about the other half of the problem: proving that what the system is *built from* is what was chosen.

Modern software is assembled, not written from nothing. A system like this one stands on dozens of
pieces of other people's software, fetched from public repositories, each of which stands on more.
Those are the parts an attacker can change without ever touching this project's own code — and the
change would arrive silently, with nothing for a reviewer to look at. The safeguards below exist to
close that route. They have four parts.

- **Pinning the exact file of every third-party package.** Each piece of third-party software the
  system installs is fixed not just by its version number but by the cryptographic fingerprint of the
  exact file. The difference is the difference between ordering "the second edition" and ordering a
  copy whose every page has been checked against a reference: two files can carry the same version
  number and differ; two files with the same fingerprint cannot. Installation then runs in a mode that
  refuses the **whole** list if any single package is unpinned or any fingerprint fails to match.
  There is no partial acceptance, and that is deliberate — one unchecked package in a list of
  otherwise-checked packages does not weaken the guarantee, it removes it. The two
  isolated halves of the product get separate lists, because they must never share a software
  environment.
- **Pinning the base images the containers are built from.** A container — the sealed, pre-packaged
  operating environment introduced in section 8.2 — starts from a *base image* published by somebody
  else. Those base images are pinned by content fingerprint rather than by a name tag. The reasoning is
  written into the code: a tag is a movable label — it means "whatever the publisher is serving at the
  moment you fetch it" — so re-labelling it, innocently or maliciously, changes what ships with
  nothing for anyone to review. A fingerprint is not movable: either the downloaded content matches it
  or the download fails.
- **A software bill of materials.** This is a standard-format inventory listing every component the
  build contains, in the same spirit as an ingredients list on food packaging. One is generated for
  each of the two halves from that half's pinned list, cross-checked against that list component by
  component — so a generator that quietly dropped a package fails the build rather than producing a
  confident-looking, wrong inventory — and published as an output of the build. These inventories are
  deliberately **generated per build rather than committed** into the project, on the stated ground
  that a file regenerated on every run is churn that reviewers learn to skip past; the pinned list is
  the committed source of truth.
- **A vulnerability gate that blocks on CRITICAL.** Every proposed change is scanned against a
  database of publicly known vulnerabilities. Anything rated CRITICAL **fails the build and blocks the
  change**. Anything rated HIGH is reported in full but does not block. The reasoning is written into
  the build configuration itself: a gate whose list of exceptions must grow without limit to stay green
  is theatre, and a gate that goes red for reasons its author cannot fix is a gate that gets switched
  off. Every exception carries a written justification naming one of five permitted reasons, and an
  automatic test rejects an exception that does not.

Three design choices in that work show the same judgement that runs through the rest of the system.
The drift check — which asks whether the publishers have moved on since a pin was taken — is
**advisory and never blocks**, on the stated ground that somebody else re-labelling their image is not
a defect in the change under review. The scanning tool is itself pinned by version *and* by the
fingerprint of the file downloaded, because installing a security scanner from an unpinned address
would be its own supply-chain hole. And the tools that do the pinning and generate the inventory are
deliberately kept *out* of the software the system actually deploys, because adding a package-pinner
and an inventory generator to a running system expands what an attacker can reach without expanding
what the system does.

**Honest status, checked directly in the released version.** This work is **part of the released
software**. It was folded in during the day this chapter was written — the earlier drafts of this
briefing describe it as still awaiting that step, and they are now behind. Verified by reading the
released version directly:

| Piece | State in the released version |
|---|---|
| Pinned package lists | Two of them. The offensive half's list pins **26** packages with **640** file fingerprints; the sovereign half's pins **56** packages with **1,176** — **1,816** fingerprints in total. These are real fingerprints, not placeholders. |
| Container base images | Pinned by content fingerprint in all five container build files, and in three of the four service definitions. The fourth service is built from this project's own code, which is one of two stated exemptions — the other being a starting point that has no content to pin at all. Both are rules rather than holes: there is no outside publisher's fingerprint to pin to. An automated check also flags any unpinned image, and carries a deliberately unpinned example to prove the check still fires. |
| Bill of materials | Generated per build from each pinned list, cross-checked against it, and published as a build output. |
| Vulnerability gate | Present, with CRITICAL blocking and HIGH advisory, the exception list requiring written justifications, and a **negative control** — the gate is deliberately pointed at a small set of packages known to contain critical vulnerabilities and is required to fail on them. Without that, a gate that reports nothing is indistinguishable from a scanner that is silently broken. |
| Written policy document | Exists (`docs/SUPPLY-CHAIN.md`). An earlier draft of this chapter recorded it as missing; that is no longer true. |
| Offline half of the checks | Runs in the ordinary automated test suite as well as in the dedicated gate, so it holds even on a machine with no internet connection. |

**One item is genuinely still a placeholder, and it is named rather than glossed.** Inside the
offensive engine there is an older committed inventory file which labels itself, in its own contents,
as a scaffold awaiting regeneration. It predates this work — it arrived with the engine itself — and
the new build gate does not regenerate it, because the inventories that matter are the ones generated
per build from the pinned lists and published as build outputs. It is stale rather than misleading:
it declares its own status instead of passing itself off as real, which is the intended discipline
working correctly. Anyone quoting this section should check that file's current state first.

**One limit on how this was verified.** The files, the pinned lists, the policy document and the build
configuration were read directly in the released version. The parts of the gate that need an internet
connection — resolving fingerprints, downloading the vulnerability database, proving a clean install
from the pinned list — are declared in that configuration and run on the project's build service. This
briefing read the configuration; it did not sit and watch a run. That distinction is the same one this
chapter applies to everything else.

There is a related capability that must not be confused with this one, because the two point in
opposite directions. VIGIL already applies prove-don't-guess to known vulnerabilities in software
components *as a finding about a customer's systems*. When any scanner reports that a customer is
running a component with a published vulnerability — a **CVE**, meaning an entry in the public,
internationally used catalogue of Common Vulnerabilities and Exposures — VIGIL treats that report as a
LEAD. It becomes a fact only when VIGIL's own fixed comparison program re-derives that the exact
version installed really does fall inside the range the published advisory names as affected, checked
against a fixed, deliberately refreshed copy of the advisory database. The sections above describe
securing **VIGIL's own** build. Same subject matter, opposite direction.

### 9.5 Built, tested against recorded data, but not yet fired at a live third-party system

Each of the following has its code built and proven against saved data. None has produced a live
result, and each names what it is waiting for.

| Capability | Waiting on |
|---|---|
| Collecting the security configuration of cloud accounts (AWS, Azure, Google Cloud) and Kubernetes clusters | Read-only credentials that only the account owner can supply. |
| The part of the automatic-fix feature that proposes an actual change to a customer's code | The operator setting up the several signing keys required, and an access token for the code-hosting service. |
| Treating the output of AI red-teaming tools as a source of fact | Those tools are not present in this environment and could not be installed, because the environment has no network access. |
| A live external graph database and a live telemetry collector — two optional external services | The services themselves being set up and running. The equivalent local store, which keeps the same data in files on the machine, is built and works; asking for the external one when it is absent produces a clear error rather than quietly falling back. |
| Registering an outside organisation's tool server and calling its tools over the **Model Context Protocol** — a published standard by which one AI system can discover and call tools offered by another | The final connecting piece. Everything around it is built: the description of what each outside server offers, the checks that validate it, the stripping of secrets, and the rule that an unregistered tool is refused everywhere by default. The module's own note calls the live connection "the one real seam" and a later piece of work. Separately, the *other* direction — VIGIL offering a small, fixed set of its own capabilities to an outside AI system, behind the same permission gates — is built. |
| A track record across a wide range of real customer targets | Access to those targets. The mechanism is built; the record of use is not. |

### 9.6 Scaffolded, and honestly labelled as such

A *scaffold* here means the outline of a capability is in place — the surrounding machinery, the
plumbing and the point at which it would connect — but the capability itself is not implemented.
Crucially, in each case the unimplemented part reports an error when called rather than returning a
fabricated answer.

- **Hardware-grade proof of what a machine is running.** The purpose is to let a remote party verify
  that a computer is running the software it claims, using a tamper-resistant chip rather than the
  computer's own word for it. Today a software-based check works, and so does one using a **TPM** — a
  Trusted Platform Module, a small dedicated security chip present in most modern business computers.
  Both report themselves honestly as *not* backed by the specialised, higher-assurance hardware. The
  backends for that specialised hardware deliberately raise an error instead of pretending. Completing
  this needs confidential-computing hardware that the project does not have.
- **Automatically writing a fix for a memory-safety crash in a compiled program.** One narrow path is
  built and works: confirming that a crash is real, and then proving a proposed fix worked because the
  original checker went silent over fresh material. Generating the fix itself — writing the corrected
  code automatically — is unbuilt research, and the code raises an error rather than pretending.
- **A next-generation body for the AI agents**, intended to run them through a newer software
  development kit with tools offered in-process. This is **interface only**: the shape of the
  connection is defined, and nothing behind it is implemented. It would need that development kit and
  a running testing container, neither of which is present.

### 9.7 Deliberately limited by design, not by omission

- Several areas of defensive detection can produce a LEAD but never a proven fact, **on purpose**,
  because the underlying records simply do not contain enough to prove anything from. They are:
  traffic from a compromised machine calling home to an attacker; suspicious activity in the corporate
  directory of user accounts; the audit trail of actions taken inside a cloud account; and the theft
  of an active login session by deception. This limit is written into the code, not merely into the
  documentation.
- Any judgement made by another AI is always a LEAD, never a fact.
- One class of detection based on measuring how long a system takes to respond was **downgraded** from
  fact to unproven lead following an internal audit, and has been kept downgraded since.
- The permanent record can be published in a form outside parties can check. Its resistance to being
  shown *differently to different parties* is a **conditional** guarantee, not an absolute one. That
  attack is genuinely *prevented* only when a strict majority of independent witnesses countersign the
  record. Below that threshold it remains *detectable* but not prevented. The project also notes,
  correctly, that separate keys are not the same thing as separate organisations — real independence
  between witnesses is a property of how a customer deploys the system, not of the software.
- The protection against secretly rewinding the record to an earlier state is honest about its bound.
  It defends against an attacker who can overwrite the record but not the small separate marker file
  that tracks how far the record has advanced, and against an outside checker holding a more recent
  copy of that marker. An attacker with full control of the same machine, who rewrites both, is closed
  off only by an external witness.
- The system carries formal, machine-checked mathematical proofs of its four core safety properties.
  These are, in the project's own words, *model-level assurance that faithfully abstracts the
  enforcing code — not a proof extracted from the code itself*. In plain terms: a precise mathematical
  description of the rules was written, and a proof-checking program confirmed the rules cannot be
  violated. That is a strong result about the design; it is not the same as proving the code exactly
  matches the description, and the project says so. Each proof ships with a deliberately broken twin
  that the proof-checker must report as failing, so the check cannot be passing for empty reasons.

---

## 10. Why this design is worth the cost

Everything described above makes the system slower and narrower than a conventional scanner. Fewer
things become findings. Many suspicions stay leads forever. Whole categories of question return
INCONCLUSIVE where a competitor would return a confident answer.

That trade is the product.

A tool that finds real problems but also asserts things it has not established is worth **less** than
one that finds fewer problems and never misstates them — because the first one's output has to be
re-investigated from scratch, and the second one's output can be checked in seconds. Re-running an
engagement is the expensive part. Re-checking a signed certificate is not.

For a government reader the practical consequences are these:

- **A finding can be acted on without re-doing the work.** The proof travels with it.
- **A report can be checked in a room with no internet connection.** Verification is offline by
  design.
- **A supplier's security claim can be tested without trusting the supplier** — and without trusting
  the vendor of this system either, because the largest part of the verification runs without any of
  its software.
- **An "all clear" means something specific and bounded**, and the bound is written inside the signed
  document rather than in a footnote someone can drop.
- **The gaps are visible.** Where the system cannot yet prove something, it names the work that would
  let it. That is a far better position for an oversight function than a tool that quietly narrows its
  own definitions until every claim it makes is technically true.

---

## 11. How to check this chapter, and where to go next

### 11.1 How this chapter was written

Every count in this chapter was re-derived from the source code, rather than copied from the project's
own documentation. That distinction matters: documentation goes stale, and in several places the
project's documentation was found to be behind its code — this chapter's own earlier draft included,
which is why section 9.4 was rewritten before publication. Anyone can repeat the exercise, and the
table below says how.

| Claim | How to re-check it |
|---|---|
| 38 checker kinds, 85 weakness categories, 190 alternative spellings, 275 accepted names, frozen fallback set of exactly 15 | Run the extraction script recorded in the project's own inventory notes against the verification module. |
| 26 evidence sources, 26 able to produce a proven fact, 6 able to produce a proven "clean" | Read `docs/capability-matrix/evidence-branches.json`. |
| 186 named intergovernmental domains on the categorical refusal list | Count the entries in the blocked-domain set in `integration/vigil_integration/safety/hard_guardrail.py`. |
| The build-and-release safeguards are in the released version (section 9.4) | Confirm that the change delivering them has been merged into the released version of the software, and that `docs/SUPPLY-CHAIN.md`, `.github/workflows/supply-chain.yml` and `.trivyignore` are present there. |
| 640 and 1,176 file fingerprints in the two pinned package lists (section 9.4) | Count the `--hash=sha256:` lines in `engine/crucible/framework/v2/requirements.lock.txt` and `infra/supply-chain/sovereign.lock.txt`. |
| The one remaining placeholder inventory (section 9.4) | Open `engine/crucible/framework/v2/sbom.json` and read the status property it sets on itself. |
| The benchmark scoreline | Read `BENCHMARK.md`, including its fairness caveats, and re-derive from the signed artefact it cites. |
| Re-verification of a report with no internet connection | `python3 -m framework.v2 verify <report.json>`, which exits successfully only if every certificate reproduces and matches its claim. |
| The registry rules are enforced at run time | A dedicated test file runs on every code change. Its own limits are documented: it validates the declarations and the admission behaviour; it does **not** prove that every path through the system routes via admission. That last property rests on adversarial human review and is marked as such. |
| The categorical refusal list has no connection to the live path (section 6.2) | Search the repository for `assert_not_hard_blocked` and observe that the only references are its own definition, its tests, and documentation. |
| The anti-hallucination component *is* used at real points (section 2.7) | Search the code for `admit_finding` and `admit_for_report` and read the places that call them. |

Two rows in that table are unfavourable to the product. They are included because the project's
governing rule is that a claim must be true today, and where a claim is not yet true the gap must be
named as engineering work rather than resolved by quietly softening the claim. A briefing about a
system whose value rests on not overstating cannot itself overstate.

### 11.2 The rest of the briefing

This chapter is one of thirteen. It is the entry point; the others go deeper on a single subject
each and can be read in any order.

| Chapter | Subject | What it answers |
|---|---|---|
| **1** *(this one)* | What this is, and the problem it solves | Why the system exists, the one central idea, the licensing and government-host conditions, and the honest status of everything. |
| **2** | The parts of the system, and how they fit together | What CRUCIBLE, AEGIS, SIGIL, STRIX, the gateway and the shared core each are; the wall between the offensive and personal halves; what runs where. |
| **3** | How a security assessment runs, from start to finish | The eleven stages of a job, from the written authorisation through discovery, testing, confirmation and reporting to re-testing after the fix. |
| **4** | Leads and facts: how the system decides something is real | The single most important distinction in the product, examined closely: the four verdicts, the journey of a claim, and exactly what this approach cannot do. |
| **5** | Every type of weakness the system can find | The full catalogue of the 85 named categories and the 38 checkers, with what each can and cannot prove. |
| **6** | Evidence: how it is collected, shown, and independently re-checked | What counts as evidence, how it is sealed, the four checks a certificate must pass, and how to hand a package to an independent third party. |
| **7** | Signatures and keys: who vouches for a result | What a digital signature is, what exactly gets signed, who holds which key, the trust root, and rotation and revocation. |
| **8** | Safety, authorisation, and what the system refuses to do | The written authorisation, scope enforcement, permission tiers, approvals, the emergency stop, and the audit trail. **The authoritative account of the government-host refusal discussed in section 6.2 is here, in its section 2.5.** |
| **9** | Every screen, and how an operator uses it | A tour of all 28 screens of the interface, plus the command line and the other three interfaces. |
| **10** | The knowledge graph: building a picture of the target | How the system assembles a map of an estate, works out chains of attack, and identifies the single fixes that break the most attacks. |
| **11** | The automated assistants, and how the system improves | Every AI agent, its job and its hard limits; how the system learns; and the strict bounds on what learning is allowed to change. |
| **12** | The tools it uses, and what you need to run it | The catalogue of external tools, the credentials and keys an operator must supply, and the practical prerequisites. Note that it does **not** cover licensing; section 6.1 above is the only chapter section that does. |
| **13** | The defensive side, source-code review, and network handling | What AEGIS proves from a customer's own logs, how source code is reviewed, encrypted connections and certificates, and how a fix is proven to have worked. |

**A suggested route for a reader with limited time.** Roughly a two-hour read, covering the argument,
the guarantees and the limits, in this order:

1. **This chapter.** The argument and the honest status of everything.
2. **Chapter 4**, leads and facts. The conceptual heart: how the system decides something is real.
3. **Chapter 8**, safety and authorisation. Where an oversight function's questions are answered.
4. **Chapter 6**, sections 12 and 13. A reviewer's checklist for the evidence and how to re-check it.

**And a route by first question**, so that no chapter is left without a signpost:

- **Is this commercially available to us?** Section 6.1 above, then chapter 12.
- **Can we point it at our own estate?** Section 6.2 above, then chapter 8, section 2.5.
- **What are the pieces, and where does each run?** Chapter 2, then chapter 3 for how a job actually
  proceeds.
- **What can it actually find?** Chapter 5 for the full catalogue, chapter 10 for how individual
  findings are assembled into a picture of an estate.
- **Who vouches for a result, and what if a key is lost?** Chapter 7.
- **How much of this is the AI, and what is it allowed to do?** Chapter 11.
- **What does an operator see and press?** Chapter 9.
- **What does it do for defence, for source code, and for encrypted connections?** Chapter 13.
