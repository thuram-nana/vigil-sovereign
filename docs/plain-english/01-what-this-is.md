# What This System Is, And The Problem It Solves

*Chapter 1 of the VIGIL briefing — a set of fourteen chapters written for a senior reader with no
software background. Every statement in this chapter was checked against the working code. The
chapters were written against the repository as it stood at version `1487e03a` on 12 August 2026;
this chapter was then revised against version `dc2994d6` the same day, which is the version that
includes the build-and-release safeguards described in section 9.4. It was revised a second time on
13 August 2026 against version `05b81e9f`, which is the version described from here on. That second
revision changed the status picture and nothing else of substance: a second result against a real
outside system (section 9.3), an honest count of how strong the evidence behind each checker actually
is (section 9.2), the plain-language case file now built into the delivered archive (section 7.1),
and two further refusals that landed alongside them (sections 8.2 and 8.3). A third revision, running
into 14 August 2026, added a permanent **proving range** on the operator's own machine, described in
section 2.9, on which the system's instruments are made to demonstrate that they can stay silent as
well as speak; and an honest account, in section 9.8, of how far the system's control over its
outside tools has actually been proven. That account began considerably weaker than the interface was
reporting. It now stands at **ten proving results across nine tools, every one of them passing** — the
tenth added when the password-guessing tool was finally made to attack a real login form rather than
only the simpler challenge a browser answers on the user's behalf. Every gap was closed by building
the missing part rather than by softening the words. The smaller figures this chapter carried along
the way — three tools proven, then six, then nine — were accurate on the day each was written, and the
progression is left visible on the page rather than tidied into a single confident number, because a
document that shows its own movement is easier to trust than one that appears to have always been
right. Where something is built but has not yet been used against a live third-party system, it says
so.*

*Two navigation notes. A full contents list for the set, with a suggested reading order and a note on
how the briefing was written, is at the end of this chapter (section 11). The set also has front
matter — `00-index.md`, "How To Read This Briefing" — which carries the same contents list, a
consolidated glossary, and a single master status table covering all fourteen chapters at once. A
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
software. ("Kubernetes" is the standard system for running and coordinating large numbers of
software containers; it is the control layer under most modern cloud deployments.) **Three of the six
have now been fired at something real rather than at saved evidence, and the three are not of equal
weight.** The two Kubernetes ones have been proven against a real Kubernetes cluster that the system
stands up, owns and destroys itself — real infrastructure, but the project's own, not a third party's
estate. The third — proving that an exposed secret is a *currently valid, working*
credential — is the only one of the six to have judged material from a real outside system: it has
been proven against the real GitHub service, using the operator's own credential,
for the one type of credential that test covers; the same capability's Amazon Web Services half is
built but has never been pointed at real Amazon infrastructure, and nothing about the GitHub result
carries across to it. The remaining confirmations have been proven against saved evidence with no
internet connection, and what remains for them is the act of pointing them at a live third-party
cloud account, which waits on that customer's own credentials, by design. One of those remaining
confirmations is a deliberate permanent exception: the identity privilege-escalation one never
carries out the escalation it is establishing, so what it awaits is a real set of permission rules to
read, not a live attack. Section 9.3 sets all of this out capability by capability.

Across the system as a whole the honest count is this. Of the 38 kinds of checker, **3** have been
run over material that a real outside system produced, **2** over material from real infrastructure
the system creates and destroys itself, **13** over material a real program on the system's own
machine produced, and **20** only over saved sample material. Section 9.2 sets that count out in
full, including the one place where a stricter reader would reasonably move two of them and make the
figures 3, 2, 11 and 22.

**How the instruments themselves are checked, and what that exposed.** A detector that only ever says
"found something" is worthless, so every test the system relies on must also be shown to stay
**silent** where the weakness is absent. The system now has a permanent place to demonstrate that: six
deliberately vulnerable applications running on the operator's own machine — the five published ones
pinned by their exact contents, so none can change underneath a result — five of them shown to hold
the weakness by putting a harmless request beside an attacking one, and the sixth honestly recorded as
**not probed** rather than credited with a weakness nobody demonstrated. Section 2.9 describes it, and
it matters beyond its own subject, because running things rather than inspecting them found a series
of faults that had been invisible for months. A scanner whose output the system could not read, so
every scan silently produced nothing. A tool that re-reported a real weakness against a hardened
control and thereby manufactured a **false positive**. A web scanner that, pointed at a plain web
address, examined only the page it started on and returned a clean report identical to the sound
control's — a clean report that meant "I did not look", which is the worst thing a security tool can
produce. A tool that was disguising itself as a different random browser on every request, in a system
whose entire promise is that the operator can find its traffic in their own records. A scanner
reaching out to two different outsiders — one for results, one to fetch a database — and the safeguard
written to stop it, which the tool's own vocabulary defeated. And a tool called by one fixed program
name, so a machine that installs it under one of its other names would have been told the tool was
usable and then failed. Section 9.8 lists all of it. It also states the honest position on the
system's control of its own outside tools: nine tools can have a command line built for them, and the
**ten proving results over those nine now all pass** — the password-guessing tool has two, because
attacking a real login form and answering a browser's own challenge share almost nothing. That is a
statement about the instruments, not about anybody's estate, and seven of the ten reached it only
after the faults in section 9.8 were found and fixed.

Safeguards over the system's own build and release — pinning exactly which third-party software the
system is built from, and blocking a build that pulls in a critical known vulnerability — were folded
into the released software during the day this was written; section 9.4 gives the exact position,
including the one part of it that is still a placeholder. Every deferral is named individually in
section 9, and none is presented as a completed field deployment.

**Two conditions a government reader must know up front**, both covered in full in section 6:

- **Licensing.** The licence shipped with this software excludes government and public-sector use
  from its free terms. Any use by, for, on behalf of, or funded by a government body requires a
  separate commercial licence from the copyright holder. This is a commercial matter, not a technical
  one, and it is the first thing a procurement reader should settle. Section 6.1 below sets it out in
  full; chapter 12, the chapter that lists what an operator needs in order to run the system, now
  states it as well, at the head of both its requirements section and its one-page checklist.
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

A reader comparing chapters should know that this position was, until recently, misdescribed by the
component's own source file, which carried an out-of-date note calling itself "caller-less" and
"exercised only by its tests" long after real parts of the running system had been connected to it.
That note has since been corrected, and an automatic test now fails the build if such a phrase
reappears while the component does have real callers — and, in the other direction, if a module that
does call it is dropped from the list. The project treats a note that outlives its phase as the same
class of defect as an overclaim, because it understates what is true. If an older copy of this
briefing, or of a companion chapter, still repeats the "caller-less" note, that copy is behind.
Chapters 4 and 6 of this briefing describe the position correctly. Stages 1, 2, 3, 5 and 6 above
involve no such qualification.

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

### 2.9 The control that must stay silent — and the proving range it runs on

Everything above concerns what happens when a checker fires. The harder question is what happens when
it does not, and it is the question most security products never answer about themselves.

**A detector that only ever says "found something" is worthless.** It cannot be told apart from a
detector that says "found something" no matter where it is pointed — and there is exactly one
experiment that tells them apart: point the same detector at a place where the weakness is *absent*
and require it to stay quiet. That experiment has a name, and it is worth a government reader
learning it, because it is the single question that separates a measuring instrument from a rubber
stamp. It is called a **negative control**.

The logic is the logic of a laboratory blank. A laboratory that only ever tested real samples, and
reported a positive on every one, would be believed until the day somebody sent it a tube of
distilled water. So a serious laboratory runs the blank alongside the sample, every time. The blank
is not paperwork. **The blank is what makes the positive mean anything.**

This system applies the rule in both directions, and both are worth naming, because they answer
different questions:

| The control | The question it answers |
|---|---|
| A **positive** control — a twin known to be weak, which the test must flag | Was the instrument working at all? |
| A **negative** control — a twin known to be sound, which the test must leave alone | Is the instrument reacting to the weakness, or to everything? |

There is a third condition, easy to overlook, which does most of the real work. **Silence only counts
as evidence when the instrument can be shown to have been running while it stayed silent.** A scanner
that never reached the sound twin also reports nothing, and reports it in identical words. So each
control run must additionally demonstrate that it was alive: that the scanner still found the
harmless things it was always going to find, still explored the site, still tested the field it was
asked to test. Silence from a working instrument is a result. Silence from a dead one is the absence
of a result, and nothing in the output distinguishes the two.

That third condition is not a theoretical nicety, and section 9.8 records the day it stopped being
one. Pointed at a plain web address, one of the web scanners crawled the site, found the page where
the weakness lived, and then attacked only the page it had started on — sending not a single request
at the parameter that actually carried the flaw. It returned a report identical to the sound
control's. **A clean report that means "I did not look" is the worst output a security tool can
produce**, because it is indistinguishable, to everyone downstream, from the one output the whole
product exists to earn: a clean report that means "I looked, and there is nothing there."

**Where those controls are run.** The operator's own machine now carries a permanent **proving range**
built for this purpose. It consists of six deliberately vulnerable applications — programs written and
published to be attacked, so that testing tools can be measured against a known answer. Five of the
six are published openly by their authors for exactly that purpose and are widely used for training
and tool evaluation: OWASP Juice Shop, the Damn Vulnerable Web Application, OWASP WebGoat, OWASP
Mutillidae, and a deliberately vulnerable programming interface called VAmPI. The sixth is this
project's own small target. Four properties matter, and each is the sort of thing an agency should
look for before believing any measurement:

- **Everything runs locally, on the operator's own machine.** Nothing belonging to anyone else is
  touched, and no public practice site on the internet is contacted. The written authorisation for
  this work names each application individually.
- **Each of the five published applications is pinned by content digest** — that is, by a fingerprint
  of its exact contents rather than by a name. A name is a movable label: whoever publishes the
  application can point it at different contents tomorrow, and every result ever measured against it
  silently stops being reproducible, with nothing for anyone to notice. A fingerprint cannot move —
  either what arrives matches it or the range refuses to start, and a starting check confirms that no
  entry has been added without one. The sixth needs no fingerprint: it is a small program held in
  this project's own repository, where its exact contents are already a matter of record.
- **The confinement is built in rather than remembered** — it holds by construction rather than by
  convention. The file that records the range **cannot express a host address** at all; only one piece
  of code turns a range entry into a running application, and it writes the machine's own internal
  address in itself. After start-up the confinement is re-read from the container system's own view,
  then from the machine's list of listening connections — and then *measured*: the range tries to
  reach the application from the machine's outward-facing address and requires the attempt to be
  **refused**. A confinement one has only read about is a claim. A connection that is refused is a
  measurement.
- **Each application is verified by difference, never by assertion.** The range does not ask an
  application whether it is vulnerable. It sends a harmless request and an attacking one and compares
  the two answers. On one of the applications the ordinary search returns 46 products and the attacked
  search returns 56 — the same 46, plus 10 the application deliberately conceals. That difference is
  the evidence. "The reply contained the word *error*" is not.

**And one of the six reports that it was not probed.** One application keeps its weaknesses behind a
per-lesson state that only exists after a user registers and starts that lesson, so no single
unauthenticated request could establish anything about them. The range therefore brings it up, confirms
it answers, and says in as many words that it has **not** demonstrated a weakness in it. That is not a
loose end: the range's own consistency check refuses a target that has neither a probe nor a written
reason for having none, so "not probed" cannot be arrived at silently. **An honest "not probed" is
worth more than a weakness nobody demonstrated**, and this briefing would rather report the awkward
row than a tidier one.

The same discipline is applied to the tools that read source code rather than network traffic. For
those, the range generates two bodies of code: one seeded with deliberate weaknesses and fabricated
credentials in the shapes such tools look for, and a **clean twin** — the same application written
safely, with no credentials in it at all. Anything reported against the twin is, by construction, a
false alarm. Both bodies of code carry a recorded fingerprint that is re-checked every time they are
generated, so an edit to the generator cannot quietly change the material a tool was scored against.

**What the range does and does not establish, stated plainly.** It establishes that the system's
instruments work: that a tool really runs, really finds the planted weakness, that the system can
really read what the tool returned, and that the same tool stays quiet on sound material while
demonstrably still running. It establishes nothing whatever about any customer's systems. And nothing
a third-party tool reports on the range is a fact in this system's sense — those results enter as
leads, exactly as they would in a real job, and only a checker over first-party evidence mints a fact.
Section 9.8 gives the honest status of that work, including how much of it is finished.

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
list of what is needed to run the system: hardware, credentials, external tools, and so on. It now
covers the licensing position too, in its section 2.1 and again in its one-page checklist, where it
is placed **before** everything else on the grounds that it is a conversation to start early rather
than a formality to tidy up later. So a procurement reader will meet this point in both places; the
set's front matter (`00-index.md`, section 9.1) states it a third time. Earlier drafts of this
chapter said chapter 12 was silent on licensing. That was true when written and is no longer.

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
- **A plain-language case file**: nine documents, numbered so that the reading order is obvious from
  the file names alone — a start-here page, an executive summary, the approach and scope (including
  what was *not* examined), the proven findings, the unproven leads, the catalogue of what the system
  can confirm and where this run stood against it, what to do about the findings, how to verify the
  package yourself, and a glossary. These are built from the same graded findings as the three
  reports below, so the two cannot disagree about what was proven. Three rules are written into the
  code that produces them: meaning before mechanism; state the limits out loud; and never assert what
  was not measured — where a value was not recorded, the documents say "not recorded" rather than
  filling the gap. If that rendering fails for any reason, the archive still carries its machine
  records and its proof, and notes plainly that the case file is missing rather than shipping the gap
  in silence.
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
| The autonomous testing agent's ability to run arbitrary commands is governed by a permission check that is on by default and cannot be skipped by accident. If that check cannot be connected for any reason, the run **stops** rather than continuing ungoverned. There is exactly one way to run without it, and it is a deliberate, visible setting the operator has to set on purpose. | The gate on the agent's command shell. Its own code records why this was changed: the previous version quietly carried on when the gate failed to connect, which produced an ungoverned command shell with no signal at all to the operator — in its own words, "an accident, not a decision, and indistinguishable from a healthy governed run". |

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
| Where the system is allowed to send its reasoning is governed by a sovereignty setting with four levels, consulted **before** any connection to an AI model is built. At the most restrictive level nothing leaves the machine: only models running locally may be used, the connection is refused before it is created, and the AI vendor's software is never even loaded. The middle levels permit only providers within a stated jurisdiction, and then — on an explicit written declaration by the operator — a service contracted not to retain data. An unrecognised level name, an unrecognised model service, a policy that cannot be loaded, or a failure inside the check itself each resolve to a refusal, never to permission. The level can also be locked at start-up, so that a later change to the machine's settings cannot loosen it part-way through a job. | The model-egress gate and the sovereignty policy. **One thing an operator must know:** when nothing is configured, the level in force is the most permissive one — it is the development default. A deployment that requires sovereignty has to set it, and should lock it. |

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
- The 15 general-purpose checker types. (These 15 are the frozen fallback set described in section
  2.3. They are not the same thing as the 11 standard opening checks that chapter 3 describes a run
  as always performing — that is a different list, of tests to *try*, not of checkers that confirm.)
  Twelve of the fifteen have been run over material that a real running system produced. The other
  three have only ever been run over saved sample material: the two that reach their verdict by
  statistics rather than by direct observation, and the one that checks whether an installed version
  falls inside a published advisory's affected range. Section 9.2 gives the equivalent count for all
  38 checker types, and names the one of these twelve where a stricter reader would reasonably
  disagree — a cloud checker exercised against a simulator rather than a real cloud account. The
  project ships a negative control for this: pointed at a deliberately *safe*
  version of the same application, the confirmation step returns nothing — demonstrating that the
  confirming authority does not rubber-stamp.
- Network reachability, encryption weakness and the web achieved-state checks against real
  captures. The version-in-advisory-range check is deliberately not in that list: it is one of the
  three named above, and while it is fully built and able to state a proven finding, the material it
  judges is a list of installed components the operator supplies, and every run so far has judged a
  sample list.
- The permission gates; the signed record that can be added to but never quietly edited; the usage
  record and the ability to replay it; the dossier; and the route by which a recipient re-checks
  everything without an internet connection.
- The proving range described in section 2.9: six deliberately vulnerable applications on the
  operator's own machine, five of them pinned by content fingerprint, five of them shown to hold their
  weakness by comparing a harmless request with an attacking one — and the sixth honestly reported as
  not probed. Its purpose is to make the system's *instruments* demonstrate that they stay silent where
  there is nothing to find. It proves nothing about any customer's systems, and nothing it produces is
  a fact in this system's sense.
- **Ten proving results across the nine outside tools whose command lines the engine composes itself,
  every one of them passing** on that range: the engine built the command, the tool ran against a live
  target, an engine reader turned what came back into the system's own record, the planted weakness was
  reported where it was planted, and the same driver stayed silent on a sound control that was
  demonstrably still being tested. Nine tools and ten results because the password-guessing tool has
  one for each of the two quite different kinds of login it can attack, the second of them a real login
  form. Section 9.8 gives the honest bounds: it is a statement about the instruments and not about
  anybody's estate, everything those tools report remains a lead, and two of the nine cannot be reached
  by the ordinary route as the production wiring stands today.
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

Two further live exercises have since been added, and both differ from that
record in a way that matters: each is a script kept in the repository, which a sceptic can run for
themselves, rather than an account of a past run that has to be taken on trust. They differ from each
other too, and the difference is the whole point of the grades below. One stands up a real Kubernetes
cluster — infrastructure the project itself builds and destroys — and puts what that cluster returns
through the whole path. The other reaches a genuinely outside system: it uses the operator's own
GitHub credential against the real GitHub service. Both are described in section 9.3.
Neither is run as part of the automatic tests, and that is deliberate: there are no credentials
there, and a live test that invents a result when it cannot actually run is worse than no live test
at all. Each script instead insists on every one of its expectations and stops with an error if any
of them fails.

**The honest count, checker by checker.** The sharpest question to ask about a system like this is
not "how many things can it check for" but "how much of that has ever been tried against something
real". Each of the 38 checker types is counted below exactly once, at the strongest evidence it has
ever been run over, so the four figures add up to 38.

| How strong the evidence behind it is | Count | Which ones |
|---|---|---|
| Run over material a **real outside system** produced | **3** | Two general-purpose web checkers — one that compares how a system answers a true statement against a false one, one that establishes that a state which should have been unreachable was reached — from the external run recorded above; plus the exposed-secret validity checker, from the GitHub script. |
| Run over material from **real infrastructure the system creates and owns** | **2** | The two Kubernetes access-control checkers, against the real cluster described in section 9.3. |
| Run over material a **real program on this machine** produced — a real network connection, a real web browser, a real compiled program | **13** | Listed individually in chapter 5. |
| Run only over **saved sample material** | **20** | Listed individually in chapter 5. |

Four qualifications, because a bare count invites two opposite misreadings.

- **The last row is not twenty blind spots.** Two of the twenty judge the *request the system sent*
  rather than the answer that came back, so a real connection would add nothing to what they prove.
  Six re-derive a configuration file offline and make no network call at all by design; for those,
  "saved sample material" and "a real export from a real customer" differ only in who wrote the file.
  Two reach their verdict by statistics rather than by observation, so what matters is whether the
  procedure is correct — and the saved material exercises the cases where it must *refuse*. One more,
  the identity privilege-escalation checker, will never move, because it never performs the
  escalation it is verifying and so has no live form to await; section 9.3 explains that position.
  That leaves nine which genuinely await either a real capture or a real deployment to run over: two
  cloud confirmations waiting on a customer's credentials, the two that prove a login credential is
  forgeable from a captured artefact offline, the four defensive checkers that judge an operator's
  own application and its records, and the check that an installed version falls inside a published
  advisory's affected range. Chapter 5 grades all 38 individually and reaches the same four totals
  by its own route.
- **Two of the thirteen deserve an asterisk.** They were exercised against a cloud simulator that
  runs inside the same program rather than against a real cloud provider. That is materially better
  than a hand-written file — it drives the real cloud-provider code path and the real shapes of
  answer, including deliberately misleading cases — and materially weaker than a real account. A
  reader who declines to credit a simulator should read the four figures as **3, 2, 11 and 22**. This
  briefing credits it, and states the convention here rather than leaving it buried.
- **The three in the top row are not equally strong.** Two of them rest on the run recorded in the
  project's own documentation, which this briefing read as a claim rather than watched. The third,
  the GitHub one, is a script anyone can run against their own account. That is the higher standard,
  and it is the one the project should be held to for the rest.
- **A count of evidence strength is not a count of coverage.** These figures say how firmly each
  checker has been exercised. They say nothing about how much of a given customer's estate a run
  would reach — that is what the coverage certificate in section 3.4 is for.

### 9.3 Cloud and Kubernetes exploitation: complete; three fired at something real, the rest awaiting the customer's credentials

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
registered. Three of the six have now been fired at something real, and the three are not of equal
weight: the two Kubernetes ones against a **real Kubernetes cluster the system stands up, owns and
destroys itself** — real infrastructure, but the project's own rather than a third party's estate —
and exposed-secret validity against the **real GitHub service**, which is the only one of the six to
have judged material produced by a real outside system. The rest are proven against recorded sample
data with no internet connection. None of the
six carries any recorded engineering gap — and under this repository's own enforcement rule, a gap
between what a capability does today and what it must eventually do *must* name the concrete work
that closes it, or an automated test fails. All six record no such work outstanding.

**Three of the six are no longer waiting. The rest are.** That distinction is recent, and one of the
three is true of only part of its capability, so it is set out precisely rather than summarised.

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

Three things that run does **not** cover, stated so the claim is not read wider than it is. First, the
script reads the objects it planted, by name; it does not exercise a scope-gated **enumeration**
capability that discovers access rules across a whole cluster under authorisation. Second, the cluster
is one the system stood up itself, so a **managed provider's control plane** — Amazon EKS, Google GKE,
Azure AKS — is not exercised: the same Kubernetes interface, reached by a different access path.
Third, the evidence was captured with the standard Kubernetes command-line tool and handed to the
checking path, rather than collected by the system's own permission-gated collector. That collector
exists, is restricted, and refuses outright unless the cluster it actually connected to is one the
operator declared in writing — but the software library it needs is not installed on this machine, so
it was not the thing exercised here.

*Exposed-secret validity.* This capability answers a question that matters more than it sounds: a
secret found lying about in a file, a page or a code repository *looks* alarming, but the only
question that counts is whether it still works. The capability has now been proven against the real
GitHub service. A script in the repository takes the operator's own GitHub credential from the
standard GitHub command-line tool, passes it straight into the harness without ever writing it to a
file, placing it where the machine's process list would show it, or putting it in the environment,
and drives the real, permission-gated production component over the real network against GitHub's own
least-privileged identity endpoint — the call that reads who you are and changes nothing. The valid
credential is confirmed from a genuine reply by the real service, and the signed certificate
re-verifies offline. Three controls in the same run are correctly *not* confirmed, and they are the
point of the exercise rather than a footnote: a fake credential of the same *shape*, sent live to the
same real endpoint, which GitHub itself rejects — establishing against the real provider that looking
like a credential is not the same as being one; the same confirmed capture with its confirming
address swapped for an attacker-controlled host, and for a look-alike address, which must not be
allowed to manufacture a fact; and the same capture where the credential and the confirming call no
longer refer to the same secret. The permission gates are exercised on the same live path too: with
the emergency stop tripped, and with the target outside the authorised scope, the run halts before
any network call is made at all.

Two limits on that result, and the first must not be blurred. **Only the GitHub half of this
capability is proven live.** The same capability's Amazon Web Services half — recognising an Amazon
access key and confirming it against Amazon's own identity service — is built, and its
request-signing code is checked against Amazon's own independent implementation, but it has **never**
been run against real Amazon infrastructure. It still needs a real access key that only the account
owner can supply, and nothing about the GitHub run transfers to it. Second, this capability
*validates* a credential the operator supplied; it does not go hunting for exposed secrets across a
customer's estate. That is a different capability and it is not covered here.

*The rest.* For the remaining cloud confirmations — the metadata-credential capture and the Google
service-account impersonation — what remains deferred is still the act of pointing them at a live
third-party cloud account. That waits on the customer supplying their own cloud credentials. It is a
deliberate design position, not an unfinished feature: a credential is a thing only the account owner
can supply, and the system is built not to obtain one any other way.

The honest sentence, which should not be softened in either direction: *for the remaining cloud
confirmations the logic, the evidence handling, the certificates and the safety gates are built and
proven against recorded sample data, and pointing them at a live third-party cloud account awaits that
customer's own credentials; for the two Kubernetes confirmations the same machinery has been run
against a real cluster and held; and for exposed-secret validity it has been run against a real
outside provider and held, for one of the two kinds of credential it recognises.* Describing any of
the six as "unfinished" understates the system. Describing the remaining cloud ones as "field-proven
in customer clouds" overstates it. Describing exposed-secret validity as live-proven without naming
which half overstates it too.

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
  hand-written record can never become a fact. Until the work described in this section, those facts
  about the connection could only ever be supplied by a stand-in used in testing — which is the
  precise reason no cloud capability had ever fired against a real provider. There is now a real
  network binding, and its single rule is that every one of those facts is *derived from the
  connection* rather than asserted: encryption counts as verified only when the connection really
  carries a validated certificate; "no proxy" is recorded only when the software can positively
  demonstrate it could not have used one; a redirect is reported rather than followed; the address is
  read from the live connection while the answer is still arriving, rather than looked up again
  afterwards; and an over-long reply is marked as cut short and never interpreted, so a truncated —
  and therefore unsound — answer can never reach a checker. Each of those, when it cannot be
  established, takes the value that makes the checker **refuse**.

One of the six must be described differently, and this distinction matters. The **identity privilege
escalation** capability is offline **by design, permanently**. It re-derives the escalation from the
operator's own retained configuration and compares what the identity could reach before and after. It
never executes the escalation, and never will — the project's stated principle is that a defensive
verification tool does not perform the attack it is verifying. It is not awaiting live fire in the
sense the cloud confirmations still awaiting a customer's credentials are: not performing the action
*is* the design.

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
| Confirming that an exposed **Amazon Web Services** access key is a valid, working credential — the other half of the capability whose GitHub half is proven live in section 9.3 | A real access key that only the account owner can supply. The code is built and its request-signing is checked against Amazon's own independent implementation, but it has never been run against real Amazon infrastructure. |
| Collecting the security configuration of cloud accounts (AWS, Azure, Google Cloud) and Kubernetes clusters | Read-only credentials that only the account owner can supply. For Kubernetes there is a second prerequisite: the permission-gated collector needs a software library that is not installed on the machine this briefing was written on, which is why the live cluster run in section 9.3 captured its evidence with the standard command-line tool instead. |
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

### 9.8 The outside tools: how far control over them is actually proven

Alongside its own checkers, the system drives a set of well-known outside security tools. This section
gives the honest position on that, because the honest position turned out to be materially weaker than
what the system's own interface was reporting — and because the way that was discovered is itself the
most useful thing in the section.

**The tools are now present, and were verified by running them.** Thirteen tools sit on the operator's
own machine, and the last three of them arrived on the day of this revision. **Twelve** were confirmed
by launching them and reading the version each printed, rather than by observing that a file of that
name exists — a distinction that matters more than it sounds, because on this kind of machine a
different program of the same name commonly occupies the one an operator expects, and the system now
steps past such an impostor to find the genuine tool rather than declaring the tool unusable. The
thirteenth is a graphical program the system deliberately never launches merely to read a version, so
its presence is established by resolving the program itself.

Separately, the system ships a **sealed working environment** — a pre-packaged operating environment,
of the kind described in section 8.2, in which the vendored third-party agent runs its jobs — carrying
a further twenty-four tools. **That environment had never been built**, and the instruction the project
published for building it could not have produced it on any machine. It has now been **built for the
first time**, and all twenty-four tools inside it were confirmed present by running each one. Getting
there required fixing two faults in the build itself, and both are worth recording because neither
could have been found by reading:

- **The published build command could never have worked.** It was recorded in three separate places
  and named the wrong starting folder — the *build context*, meaning the set of files the build is
  allowed to see — so it failed partway through on a file it could not find. Nobody had ever run it.
- **One step of the build resolved a tool version over the network at build time**, asking the
  internet which release was newest while the build was running. That had two consequences. It made
  two builds a day apart produce different contents, which defeats the point of pinning everything
  else, as section 9.4 describes; and, because the request carried no credentials, it ran into the
  publisher's hourly limit for anonymous requests, came back empty, turned the download that followed
  it into a not-found error, and killed the build two-thirds of the way through — with a message that
  named the download rather than the limit that caused it. The version is now written down in the
  recipe and is changed deliberately.

**How the system says it drives a tool, and the three it was refusing wrongly.** The screen that lists
the tools applies a deliberate rule: a tool is admitted to the working set only if the system has some
way of actually driving it, and one it cannot drive is refused with a stated reason rather than listed
as available. The rule was right; its knowledge was incomplete. It knew of only two ways a tool could
be driven — from a written command-line playbook the AI reads, and from a typed argument builder the
engine composes itself — and reported both of them under one label. The engine in fact drives tools
three further ways as well: through a **sensor**, through a **source-code analyser**, and through the
**headless browser** it uses to confirm weaknesses that appear only once a page has run.

The consequence was that **three tools the engine visibly launches during ordinary work were being
refused as undrivable** — the one that captures network traffic, the one that performs deep analysis
of source code, and the browser — because an engine-side driver was the only route each of them had.
The screen now recognises every route, and — the improvement that matters most to a reader — it states
**how each tool is driven** under four labels rather than merely stating that it is driven. A tool the
engine launches itself as part of a scan is a different kind of control from a tool whose command line
the AI composes from written instructions, and an operator deserves to see which of the two they have.
The lists behind those labels are not maintained by hand: an automatic check reads the real source of
each driver and fails the build if a tool has been added to one and forgotten here.

**The tool that would have failed on somebody else's machine.** A related fault sat one level below
that screen, and it is worth setting out because it is the kind that never shows up on the machine it
was written on. Some security tools install under more than one program name: the version packaged by
one operating system uses one name, the version published by the tool's own authors uses another. The
system keeps a catalogue recording, for each tool, every name it is known to install under — and the
screen that reports which tools are present resolves through that catalogue correctly. Two of the
command builders did not. They called the tool by a single fixed name. On the machine this was written
on that name happened to be right, so everything looked well; on a machine where the operator had
installed the same tool from its authors instead, the screen would have reported the tool present and
controllable and every attempt to run it would have failed to start. The two builders now resolve
through the recorded names, record in the permanent run record which of the names actually ran, and
refuse — naming every name they tried — when none is installed. And because the fault had already
occurred once and been fixed in a way too narrow to catch its second occurrence one builder away, the
guard was rewritten to cover the whole class: **an automatic check now compares every builder's
invocation against the catalogue and fails the build on any disagreement** — a tool that exists today,
or one added tomorrow.

**The part to be most careful about: how much of this is actually proven.** Nine of the tools have a
**typed command builder** — code inside the engine that constructs and validates that tool's command
line itself, rather than letting the AI write it. A builder that produces a plausible-looking command
line proves nothing at all, so the standard applied here is deliberately severe. Five things must all
hold, and a result is refused if any one of them is missing:

| The condition | Why it is there |
|---|---|
| **The engine builds the command**, not the exercise | An exercise that writes its own command line is testing itself |
| **The tool actually runs** against a live target and returns real output | The commonest failure in this whole area is a driver that has never once been run |
| **That output is read back into the engine's own record** | A tool whose output nothing in the system can read has not been driven end to end, however well it ran |
| **The planted weakness is reported where it was planted** | Otherwise the run proves only that the tool executed |
| **The same driver stays silent on a sound control that is demonstrably still being tested** | The negative control, plus the liveness condition from section 2.9 — silence from a dead instrument is not evidence |

**Where the nine stood at the start of the day**, because the distance travelled is the part worth
knowing and because the starting position was materially weaker than the interface implied:

| Of the nine tools with a typed command builder | Count | The position that morning |
|---|---|---|
| Proven all the way through against a live target | **3** | The port scanner, the template-driven vulnerability scanner, and the injection confirmation tool. These met every condition above, negative control included. |
| Had **no way for the system to read their output at all** | **3** | The engine could build the command and launch the tool — and then discarded every byte it returned. The tool ran, the run appeared to succeed, and nothing whatever reached the system. |
| Had **never been executed** | **3** | These three were listed by the interface as controllable while the engine's own permission manifest — the list that decides which tools may run in each phase of a job — did not name them at all, so every attempt to call them was refused. They shipped unreachable. |

**Where they stand now: ten proving results across the nine tools, and every one of them passes.**
Readers were written for the first three, from the output the real programs actually emit rather than
from their documentation; the second three were given a route through the permission manifest and a
proving result of their own. The last run of the exercise on this machine drove every one, each
against the weak target and then against the sound control, and every expectation held.

**Ten results and nine tools, because one tool needed two.** The password-guessing tool can attack two
quite different kinds of login, and inside the tool they share almost no machinery. One is the plain
challenge a browser answers on the user's behalf — the small grey box that appears before a page
loads. The other is an ordinary login form on a web page, which is what practically every real service
actually uses, and which requires the tool to submit the form, read the page that comes back, and
decide from its wording whether the password worked. For a long while only the first of the two had a
control to be tested against, so the table showed one confident green line for a tool that had never
been shown to work against the commoner and harder of its two jobs. The capability had been built and
tested against a saved copy of the tool's own output long before it met a real form. **Testing what a
command line looks like is how a driver that has never worked gets shipped.** It now has a result of
its own: a real login form on a control server, a real password recovered from it, and — on the
hardened twin — the same attack completing and recovering nothing.

That second result required an extra safeguard worth describing, because it is the sharpest instance
in this chapter of the third condition in section 2.9. Measured on this machine, the password-guessing
tool attacking a twin whose login page had been *removed altogether* prints exactly the same console
output as a correct negative control: the module engaged, the attack completed, no password found, no
error of any kind. Its own reporting cannot tell "I tried every password and none worked" apart from
"I never reached a login page." So the control server is asked instead. It counts what actually
arrived, and the result holds only if the login form processed every password the attacker offered,
including the one that cracks the weak twin, and refused all of them. **Only the target knows whether
it was ever asked to check a password.**

Both of that tool's results carry one further check, which is worth naming because it concerns
something an agency will care about independently: **a password the tool recovers must not end up in
what the system keeps.** The tool cracks a real password and prints it, and that raw printout is the
material a checker would examine, so it stays as it is. But the two things the system *retains* — the
observations it derives and the signed record of the run — are searched, on every one of the four
runs, for the credentials the exercise handed the tool. If the search cannot be performed conclusively
— because the captured output was truncated, say — the result fails rather than passes. An invariant
that cannot be checked is not an invariant that holds.

The intermediate states are worth recording because each step was a real fault found and fixed rather
than a threshold lowered: the first run of the exercise proved one driver, a later one three, a later
one six, then nine, and the last one all ten.

**Do not read that as "the system drives nine tools in the field."** Four limits travel with the
claim, and chapter 12 sets them out in full. The targets are deliberately vulnerable applications on
the operator's own machine, so **none of this is a result about anybody's estate**. Everything those
nine tools report is a lead and never a fact. The exercise needs the local range standing, so it is
run deliberately by a person rather than on every change — though it does report any builder that
has no proving result, so a new driver cannot arrive unproven and unnoticed. And two of the nine, the
two destructive ones, cannot be reached by the ordinary route at all as the production wiring stands
today: the exercise supplies the extra authorisation itself and prints a note saying it had to,
which is a gap in *reaching* those two drivers rather than a hole in the gate that stopped them. A
reader who wants the number for themselves can obtain it directly: the proving exercise asserts
every one of its expectations and stops with an error the moment reality stops matching the claim.
Section 11.1 says how to run it.

#### 9.8.1 The safeguard that was itself wrong — the strongest argument in this document

One of the findings belongs on its own, because it is not a fault in a tool. It is a fault in a
*safeguard*, and it is the clearest demonstration in this briefing of why a system should check its own
claims by running them rather than by reading them.

The written authorisation governing all of this work carries a hard limit: **nothing may leave the
machine**. No tool, no name lookup, no callback. Everything is local; that is the entire point of a
range on the operator's own hardware.

One of the web-application scanners broke that limit by default, and nobody had noticed because it
took no decision to do so. Left to pick its own set of tests, it ran one that asks an **outside
service — a web address belonging to the tool's own authors** — to report back what it had seen.
Every scan, against every target, was quietly talking to a third party.

Removing that one test was not enough, and the second discovery is the useful one. A different test
in the same default set reaches a **different outside address, for an entirely different reason**: it
wants a reference database of technology signatures, finds no copy stored locally, and downloads one.
It is nobody's idea of a test that phones home. It waits for no callback and needs no accomplice. It
simply fetches a file from a stranger's server, on its own initiative, on every run.

So the system was given a guard: a list of the tests that must never be run. **And that guard was
itself unsound.** The setting it policed is not a list of test names. It is a small language, and it
also accepts **group names** — ordinary words such as "all" and "common" — which the tool expands into
sets of tests by itself. Measured against the installed version: asking for "all" produces thirty-six
tests, including all three of the forbidden ones; asking for "common" produces sixteen, including one
of them. Both are perfectly ordinary words. Neither matched anything on the list of forbidden names.
**The entire prohibition could have been reopened with three letters**, while the test written to
prevent exactly that went on passing, because it had only ever tried the literal names.

The guard is now the other way round: a list of what is **allowed**. Every test on it has been read
individually and confirmed to attack only the target it was pointed at, with no outside party
involved anywhere. Everything else is refused outright — a group name, an unfamiliar test, or a test
that a future version of the tool has not yet invented.

**The general lesson, which a reader will meet again in other systems: a list of forbidden things is
not a guard when the vocabulary belongs to somebody else.** The tool decides what its own words mean,
and it can add new ones in any release. A list of permitted things is a guard, because an unfamiliar
word fails it by default rather than passing through it.

One honest cost of that choice is worth recording, because the project paid it within hours. The
refusal is **total**: one unrecognised word cancels the whole request rather than narrowing it. So a
*safe* test accidentally left off the permitted list is a defect too, not a cautious default. Exactly
that happened — one ordinary test was omitted, and a scanner that had been proven end to end went
straight to a flat refusal, whose stated reason named the arguments rather than the list that had
rejected them. The test was read, confirmed to contact nobody, and added.

#### 9.8.2 Measurement, not assertion: how "nothing leaves the machine" was established

"Nothing leaves the machine" is precisely the kind of claim this briefing will not make by
inspection, and the reason is the whole subject of this section: both of the contacts above were
behaviour the tools chose for themselves, so neither appeared anywhere in the system's own
instructions for a reviewer to find.

So it was measured. The engine's own commands were run inside an **isolated network in which the only
route off the machine's own internal address leads nowhere at all**, with every packet recorded on the
way. Anything a tool tried to send to the outside world had nowhere to go and was captured.

A trap that catches nothing is worth exactly as much as a detector that only ever fires, so the trap
was itself controlled *before* it was believed: it was pointed at two occasions where a leak was known
to be present, and required to see each one. It did.

| The two deliberate leaks | What each one establishes |
|---|---|
| An ordinary look-up of a name on the internet, made on purpose. The trap recorded **exactly the two enquiries such a look-up makes**, and nothing else. | The trap can see the smallest thing anyone would want it to see, and it does not invent traffic that was never sent. Both halves matter: a trap that over-counts is as useless as one that misses. |
| A scan run with **one of the guards deliberately taken out**. One web scanner ships a test that drives a **real browser**, and the browser, on starting, looks up an address belonging to its own vendor: **sixteen such lookups in a single forty-one-second scan.** | The scanner's own two quieten-down settings do not cover this and were never going to: they suppress the *tool* contacting its authors, and a browser contacting its vendor is a different thing entirely. The browser is now pointed at a program location that cannot exist, so none starts. Repeated with the guard back in place: **zero packets left the machine**, the scan still reported the weakness it was there to find, and the only thing lost was one test that could not have run under this authorisation at all. |

Only then was the trap's silence worth anything — and the trap then caught something **nobody was
looking for**. A second tool runs a built-in **check for a newer version of itself** before it has sent
a single packet at the target: it contacts two outside services, which cost four name look-ups per run
on a machine that remembers previous answers and six on one that does not. Switch on the command-line
setting that suppresses that check and the count is zero. That setting had been carried as a matter of
tidiness; it is **load-bearing rather than cosmetic**, and this is how that was established rather than
assumed.

Every figure above comes from that measurement rather than from anything written in the software, so a
reader checking them should re-run the measurement rather than search the code for the numbers. Two
limits belong with the result and none should be trimmed. The trap is an exercise a person runs, not
part of the automated build; what the build checks is narrower and more durable — that the exact
commands still carry those settings, **now pinned for every one of the three tools concerned**, the
last of the three having gone unpinned until this was written. The measurement was made on this machine
against these versions of these tools, and a new version can acquire a new outbound habit, so the only
way to know is to measure again. As for the tool whose version check the trap caught unlooked-for: the
suppressing setting now travels on **all three of its routes into the engine** — the typed command
builder, the scanning component, and the template runner — and each of the three is pinned by its own
automated test, so a future edit that dropped it on any route would fail the build. The traffic it
would otherwise send goes to that tool's own publisher and carries nothing whatever about the target,
and it is written down here rather than left for a reader to find.

#### 9.8.3 The defects found by running things rather than reading them

Not one of the faults below was visible to the system's own automated tests; each was invisible to
unit tests that examined the *shape* of a command rather than what happened when it was issued, and
each was found by running the thing. They are set out as a credibility asset rather than as an
embarrassment: a project that finds these and prints them is in a materially better position than one
that has never looked.

| What was found | What it teaches |
|---|---|
| A scanner whose output the system could not read. Every scan produced no observations at all, while the run reported success. | **A command that looks correct is not a working tool.** The command line was well-formed; it simply asked the tool for its human-readable output while the reader expected the machine-readable form. |
| A tool that **re-reported a confirmed weakness** from one application against a *different, hardened* one, thereby **manufacturing a false positive**. The tool keeps a stored session filed under the machine's name; on this machine every practice application shares one name, so a genuine result about one was resumed from that stored session and re-served as a result about another. | A result that is a replay of stored state is not a measurement in *either* direction. It is at once a false alarm about the sound target and a fabricated confirmation about it, and nothing in the output says so. This is exactly the failure a negative control exists to catch — and it is what caught it. |
| A scanner that opened a network listener on a port already in use, exited about ten seconds later, and wrote no report. The system reported that the scan had found nothing. | **A silent no-op is indistinguishable from a clean result**, which is the single confusion this whole product exists to prevent. The operator was told there was nothing there, when the truth was that nothing had been looked at. |
| **A scanner that only ever examined its starting point.** Given a plain web address, it crawled the site, found the page carrying the weakness — and then attacked only the page it had been handed, sending **not one request** at the parameter where the flaw actually was. It returned a clean report identical to the sound control's. Given the full address *including* the parameter, the very same command found the injection. Multiplying its time budget fivefold changed nothing: the limit was structural, not temporal. | **The worst output a security tool can produce is a clean report that means "I did not look"**, because nothing downstream can tell it apart from the one output the product exists to earn. The scanner is now driven by an explicit scan plan — crawl first, then attack **everything the crawl found** rather than the one page it started from. On the same target and the same budget the observations rose from none of that kind to fifteen, including both an injection of script and an injection of database instructions. It also now **fails loudly** when it cannot reach the target at all, rather than producing an empty report that reads as clean. |
| **A tool impersonating a different random browser on every request** — a setting it turns on by itself, which nobody had written down anywhere. | This is the exact inversion of what the system promises. An authorised test must be **correlatable**: the operator has to be able to look through their own records afterwards and pick out precisely which traffic was the test's. A tool quietly behaving like an evader, inside a system whose whole claim is that it is authorised and auditable, is a defect even though it breaks no rule and trips no gate. It now identifies itself by name on every request, with the same identity the rest of the engine uses, so a defender sees one consistent actor instead of a crowd of invented visitors. **The system is auditable precisely because it does not hide.** |
| **A tool contacting outsiders, twice over — and the safeguard against it defeated by the tool's own vocabulary.** Set out in full in section 9.8.1 above. | **A list of forbidden things is not a guard when the vocabulary belongs to somebody else.** The permitted list replaced it. |
| **A tool invoked by one fixed program name** while the system's own catalogue records the other names it installs under. The screen therefore reported it usable on a machine where every run of it would have failed to start. | A claim about a tool has to be true on *somebody else's* machine, not just on the one it was written on. This had already happened once and been fixed too narrowly to catch its recurrence one component away, so the guard now covers the whole class: any tool whose invocation disagrees with the catalogue fails the build. |
| Three tools the interface listed as controllable while the engine refused every single call. | A claim of control has to hold at *every* layer. Refusing a tool honestly on one screen while a different component silently blocks it is the same false claim of control, moved one level down. |
| A capability the operator selected being accepted and then silently discarded — and, in the single-tool mode, an unrecognised selection throwing away the valid one behind it, so the run started with no capability at all. | A request that cannot be honoured must be **refused by name, before anything starts**. The alternative is what happened here: the operator watches a run they believe is doing one thing, and the report looks complete while the work was narrower than they were told. |
| Whole capability selections dropped on several routes — including the one an operator uses most often, a quick scan of a target on their own machine. | The same lesson at a larger scale. The system now states, both in the run's own permanent record and in what it hands back to the screen, exactly which selections **were not applied**, which were, and why. |

**What every one of them has in common, and why an agency should weigh it.** They divide into two
kinds, and neither kind could have been found by reading.

Several were **defaults** — behaviour the tool chose for itself, which therefore appeared nowhere in
this system's own instructions to be read at all. The random browser identity, the two outside
contacts, and the scanner that attacked only the page it was handed are all of that kind: nobody wrote
them, nobody chose them, and no amount of reviewing the commands the system issues would have shown
them, because they are not in those commands.

The rest were **assumptions that happened to be true on the machine they were written on** — a program
name that was right here and wrong elsewhere, a stored session that collides only when every target
shares one address, an output format the reader expected and the command never asked for. Each is
correct in exactly the environment it was authored in, which is precisely the environment its author
tests in.

**Both kinds are invisible to inspection and visible only to execution**, which is why every automated
test passed over them and why they surfaced within hours once the tools were actually run against
targets with known answers. A reader assessing any security product should ask of it the question this
exercise asked here: not "what does the documentation say the tool does", but **"what happened the
last time somebody ran it and checked?"** The number of faults matters far less than whether the
question was ever asked — and whether the answers were printed or quietly corrected.

**Two things this work does not change**, stated so the section is not read more widely than it
deserves. First, the count of checkers in section 9.2 is untouched: nothing an outside tool reports is
a fact in this system — on the proving range or anywhere else. Such results enter as leads at
deliberately low confidence, and only a checker over first-party evidence mints a fact. That is
precisely why weak control over the tools was an honesty problem rather than a soundness one: no false
finding could have reached a report through this route, but the interface was describing a capability
the engine did not have. Second, none of this is evidence about any customer's estate. It is evidence
about the instruments.

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
| The Kubernetes result against a real cluster (section 9.3) | Run `tools/livefire/k8s_rbac_livefire.sh`. It needs the container software Docker, downloads a real Kubernetes distribution, prints the cluster's real version and every expectation it checks, and exits with an error if any of them fails. |
| The GitHub result against the real provider, and the fact that only half of that capability is proven (section 9.3) | Run `tools/livefire/secret_github_livefire.sh` with your own GitHub account signed in; it skips cleanly and says so if you are not signed in. Its own opening comment states, unprompted, which half it does not cover. |
| Which capabilities have been fired at something real and which have not (section 9.2) | Read the `limitation` field of each entry in `docs/capability-matrix/evidence-branches.json`. Each one states in its own words what has and has not been exercised live, including the split between the GitHub and Amazon halves. |
| Neither live result is run by the automatic tests (section 9.2) | Read the same two scripts' opening comments, which state the reason: there are no credentials in the automated environment, and a live test that fabricates a result when it cannot run is worse than none. |
| The most permissive sovereignty level is the one in force by default (section 8.3) | Read the function that resolves the level from the machine's settings in `engine/crucible/framework/v2/kernel/sovereignty.py`: with nothing configured it returns the permissive level, and with an unrecognised name it returns the strictest. |
| The nine documents in the case file, and what happens if they cannot be produced (section 7.1) | Read the list at the top of `engine/crucible/framework/v2/report/case_file.py`, then the point in `report/dossier.py` where it is built into the archive and the note recorded if it fails. |
| The proving range: six applications, five pinned by content fingerprint, one honestly not probed (section 2.9) | Read `tools/livefire/range_targets.json`, then run `tools/livefire/range.sh up all` and `tools/livefire/range.sh verify`. The verify step prints, for each application, the harmless request beside the attacking one and the difference between them, and prints `NOT PROBED` with its written reason for the one that is not probed. |
| That the range's confinement is enforced rather than remembered (section 2.9) | Read the four assertions in `tools/livefire/range_targets.py` — the file cannot express an address, and the binding is re-read from the container system, then from the machine's listening sockets, then measured by requiring a connection from the machine's outward-facing address to be refused. |
| That a target without a weakness probe must carry a written reason (section 2.9) | Run `python3 tools/livefire/range_targets.py check`, then delete the explanatory note from the manifest entry and run it again. |
| The clean twin used to score source-code tools, and its recorded fingerprint (section 2.9) | Run `tools/livefire/range.sh up src`; it regenerates both bodies of code and fails if either fingerprint no longer matches the one recorded in the manifest. |
| The ten proving results over the nine typed command builders (section 9.8) | Run `tools/livefire/tool_drivers_livefire.sh`. It drives each one through the engine's own executor twice — once against the weak target, once against the sound control — and prints, per result, whether it ran, whether an engine reader could parse its output, and whether it stayed silent on the control. It exits with an error the moment an expectation fails, and it reports any builder that has no proving result at all. |
| That the password-guessing tool is proven against a real login form, not only against a browser's own challenge (section 9.8) | The same exercise. Two of its ten results name that tool, one per kind of login. The form result additionally reads the control server's own counters, so its silence is confirmed by what the target saw rather than only by what the tool printed. |
| That the guard on the scanner's tests is a permitted list rather than a forbidden one (section 9.8.1) | Read `integration/tests/test_wapiti_no_egress.py`. It asks for the group names "all" and "common" and requires the whole request to be refused; reverting the guard to a list of forbidden names makes that test fail while everything else stays green. |
| That every tool is invoked under a name the catalogue records (section 9.8) | Read `integration/tests/test_builder_binary_resolution.py`. It derives the check from the catalogue itself, so it covers tools added in future, and it carries its own controls that fail if the check has quietly stopped reading anything. |
| The four ways the system can drive a tool, and the three that were wrongly refused (section 9.8) | Read `engine/crucible/framework/v2/tools/profile.py`; the drift-guard tests beside it read the real source of each driver and fail the build if the lists disagree. |
| The twenty-four tools in the sealed working environment (section 9.8) | Build it with `docker compose --profile strix build strix-sandbox`, then run each name in `SANDBOX_TOOLS` in `engine/crucible/framework/v2/tools/registry.py` inside the image. |

Two rows in that table are unfavourable to the product. They are included because the project's
governing rule is that a claim must be true today, and where a claim is not yet true the gap must be
named as engineering work rather than resolved by quietly softening the claim. A briefing about a
system whose value rests on not overstating cannot itself overstate.

### 11.2 The rest of the briefing

This chapter is one of fourteen. It is the entry point; the others go deeper on a single subject
each and can be read in any order.

| Chapter | Subject | What it answers |
|---|---|---|
| **1** *(this one)* | What this is, and the problem it solves | Why the system exists, the one central idea, why a detector must be shown to stay silent as well as to speak, the licensing and government-host conditions, and the honest status of everything. |
| **2** | The parts of the system, and how they fit together | What CRUCIBLE, AEGIS, SIGIL, STRIX, the gateway and the shared core each are; the wall between the offensive and personal halves; what runs where. |
| **3** | How a security assessment runs, from start to finish | The eleven stages of a job, from the written authorisation through discovery, testing, confirmation and reporting to re-testing after the fix. |
| **4** | Leads and facts: how the system decides something is real | The single most important distinction in the product, examined closely: the four verdicts, the journey of a claim, and exactly what this approach cannot do. |
| **5** | Every type of weakness the system can find | The full catalogue of the 85 named categories and the 38 checkers, with what each can and cannot prove. |
| **6** | Evidence: how it is collected, shown, and independently re-checked | What counts as evidence, how it is sealed, the four checks a certificate must pass, and how to hand a package to an independent third party. |
| **7** | Signatures and keys: who vouches for a result | What a digital signature is, what exactly gets signed, who holds which key, the trust root, and rotation and revocation. |
| **8** | Safety, authorisation, and what the system refuses to do | The written authorisation, scope enforcement, permission tiers, approvals, the emergency stop, and the audit trail. **The authoritative account of the government-host refusal discussed in section 6.2 is here, in its section 2.5.** |
| **9** | Every screen, and how an operator uses it | A tour of all 29 screens of the interface, plus the command line and the other three interfaces. |
| **10** | The target knowledge graph: building a picture of the attack | How the system assembles a map of an estate, works out chains of attack, and identifies the single fixes that break the most attacks. It is called the *target* knowledge graph because there are three different maps in this system, and chapter 14 describes a second one. |
| **11** | The automated assistants, and how the system improves | Every AI agent, its job and its hard limits; how the system learns; and the strict bounds on what learning is allowed to change. |
| **12** | The tools it uses, and what you need to run it | The catalogue of external tools, the credentials and keys an operator must supply, and the practical prerequisites — including the licensing position, which its section 2.1 now covers in full alongside section 6.1 above. |
| **13** | The defensive side, source-code review, and network handling | What AEGIS proves from a customer's own logs, how source code is reviewed, encrypted connections and certificates, and how a fix is proven to have worked. |
| **14** | The sovereign side, in full | The other half of the product: the part that holds the owner's key, keeps the owner's memory as a tamper-evident record, governs the offensive engine, and contains no attacking capability at all. Voice, gesture, the phone companion, the memory server, and an honest account of which of those is actually running. |

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
- **How do you know its instruments work at all?** Section 2.9 above, on negative controls and the
  proving range, then section 9.8 on how far its control over the outside tools has been proven.
- **Who vouches for a result, and what if a key is lost?** Chapter 7.
- **How much of this is the AI, and what is it allowed to do?** Chapter 11.
- **What does an operator see and press?** Chapter 9.
- **What does it do for defence, for source code, and for encrypted connections?** Chapter 13.
- **What is the other half of the product — the part that holds the key rather than the one that
  attacks?** Chapter 14.
