# Leads And Facts: How The System Decides Something Is Real

## Why this chapter exists

Every security testing tool produces a list. The hard question is never "did the
tool produce a list?" — it is "which items on the list are true?"

In ordinary practice that question is answered by people. A tool reports a few
hundred alarms. A skilled analyst opens each one, tries to reproduce it by hand,
decides whether it is real, and throws most of them away. The expensive part of
security testing is not the testing. It is the human triage afterwards, and the
quiet erosion of trust that happens when a team learns from experience that most
of what the tool says is noise.

The system described in this briefing takes a different approach. It does not try
to be cleverer at guessing. It changes what a result *is*. Every statement the
system makes falls into one of a small, fixed set of categories. The strongest of
those categories can only be reached by a mechanical procedure that anybody else
can run again, on their own computer, without the system present and without
trusting it.

That mechanism is the subject of this chapter. It is the core of the product. If a
reader takes only one idea away from this briefing, it should be this one.

---

## 1. The two words that matter

### A LEAD is a suspicion. It is labelled as a suspicion.

A LEAD is something worth looking at that has **not** been proved. It might come
from an outside scanning tool that said "I think there is a problem here". It
might come from a pattern match, a rule of thumb, or the artificial intelligence
component reasoning about what it has seen. It might also come from a report
produced by a completely different vendor's tool, which the operator deliberately
loads in (described in section 5).

A LEAD is genuinely useful. It tells the operator where to point attention. But
the system never dresses a LEAD up as anything more than it is, and it never
counts a LEAD in the same column as a proven result.

### A FACT is something the system proved to itself, and can prove again.

A FACT is a claim that survived a specific mechanical test. The system:

1. captured the evidence itself, through a channel it controls;
2. kept an exact copy of that evidence;
3. ran an automatic, fixed procedure over that copy, which came out positive;
4. sealed the evidence and the result together in a signed package;
5. and can hand that package to a stranger, who can repeat step 3 on their own
   machine and get the same answer.

The one-sentence version, taken from the system's own internal description:

> A LEAD is anything anyone said. A FACT is a verdict the system re-derived
> itself, over evidence the system retained, which anyone can re-derive again
> offline.

The gap between the two is closed only by **doing the check again**. It is never
closed by believing a message, a label, a score, or a summary.

### The analogy: a hunch versus a laboratory test

A doctor examines a patient and says "I think this might be an infection." That is
a hunch. It is informed, it is valuable, and it directs what happens next. It is
not a diagnosis.

The doctor takes a blood sample. The sample goes to a laboratory. A machine runs a
fixed test on that sample and prints a result. The sample is kept. If anyone
doubts the result, the sample can be sent to a second laboratory, which runs the
same fixed test and either confirms the result or does not.

In this system:

| In the medical analogy | In this system |
|---|---|
| The doctor's hunch | A LEAD |
| The blood sample | The retained evidence |
| The laboratory machine | A **checker** — a small automatic checking program, described in section 3 |
| The printed test result | A FACT |
| The sealed, labelled sample tube and the chain-of-custody form | The signed evidence certificate |
| A second laboratory re-running the same test on the same sample | Offline re-verification |
| "This test cannot be run on this sample" | INCONCLUSIVE |
| "The test was capable of detecting it, and it was not there" | CLEAN |

The analogy holds in one more important way. A laboratory test does not tell you
whether the patient will get better. It tells you one narrow thing about one
sample at one moment. The same is true here, and the system is deliberate about
saying so.

### One object, two names: a checker is an oracle

There is one small piece of machinery at the centre of this whole product: a
tiny, fixed, non-intelligent program that looks at saved evidence and answers one
narrow question, always the same way.

**This briefing calls that program a checker. The software calls the same program
an oracle. A checker and an oracle are the same thing.** There is one mechanism
here with two names, and the two names are interchangeable everywhere in this
document. Other chapters of this briefing sometimes reach for a plainer image —
an automatic test, a laboratory assay, a mechanical judge — and those are
descriptions of this same one program, not other pieces of machinery.

The reason both words appear at all is that "oracle" is the name written into the
source code, printed on the screens, and used in the system's own technical
documents. This briefing does not rename what the screens say, so where a screen
or a code comment is quoted directly, the word "oracle" appears inside the
quotation. In this chapter's own prose the word is always **checker**.

The name in the software is an unfortunate one — "oracle" suggests prophecy, and
this program is the opposite of prophecy. It is a fixed procedure with no
judgement in it at all. Read "oracle" as "checker" every time you meet it.

Two other words are used constantly in this chapter and are worth fixing in mind
now.

- **Deterministic** means: same input, same answer, every time, on any machine. It
  is a recipe, not a chef. Follow it twice with the same ingredients and you get
  the same dish — no judgement, no mood, no improvisation. Everything the system
  is able to prove rests on this property.
- **Fail-closed** means: if a check cannot be completed — an error, a missing
  file, an unreadable answer — the result is "no". Like a drawbridge held up by
  power: cut the power and it falls shut. The system is built to fail towards
  caution, never towards a comfortable answer.

---

## 2. There are four words, not two

The system's output vocabulary is not "vulnerable / not vulnerable". It has four
values, and no fifth value is possible.

| Verdict | Plain meaning | What it takes to say it |
|---|---|---|
| **FACT** | We established this. | An automatic, fixed check re-derived the result from evidence the system captured itself through an authorised channel, and the sealed package re-checks correctly when opened again later. |
| **LEAD** | Something suggests this. We did not prove it. | Anything weaker: an outside tool's assertion, a rule of thumb, a pattern match over text the system cannot fully parse, or the artificial intelligence's opinion. |
| **CLEAN** | We looked, we were able to see, and it was not there. | A real channel existed, the evidence was genuinely readable for this particular question, and a decisive automatic check refuted the claim. |
| **INCONCLUSIVE** | We could not tell. | Everything else. This is a first-class answer, never rounded towards CLEAN. |

Two properties of this list deserve a procurement officer's attention.

**First, the list is closed by construction.** In the software these four values
are a fixed, enumerated type — a list of permitted answers that the program
itself refuses to extend. A fifth value cannot appear in output, because there is
no way to write one. "Probably safe", "no issues found", "looks secure" are not
available words. This is a property of the machinery, not a style guideline that
reviewers have to police.

**Second, FACT and CLEAN are bounded observations, not permanent properties.**
They are like a vehicle roadworthiness certificate: the certificate says the
vehicle passed a defined set of checks on a stated date. It does not say the
vehicle is safe forever. The system's own written doctrine states this directly —
a verdict describes what was established about a specific target, in a specific
configuration, over a specific observation interval. A live system changes. The
system never claims to have described the target forever.

There is one further rule that matters more than it looks. The system's written
doctrine says:

> Asserting a vulnerability that is not there destroys trust in every finding.
> Asserting safety that was not established is **worse**, because nobody goes
> looking again.

That is why INCONCLUSIVE exists as a full answer, with its own place in reports,
rather than being quietly merged into CLEAN. Section 8 of this chapter explains
why "we found nothing" is a much harder claim to earn than "we found something".

### The smaller vocabularies

Alongside the four main verdicts there are several shorter fixed vocabularies
used by specific parts of the system, each held to the same discipline: the
permitted answers are written into the software, and nothing else can be said.
Three of them belong to the offensive side and are set out below; a fourth, used
by the defensive side when it inspects a single incoming request, is described in
chapter 13.

**When recording whether a probe actually settled anything** (used to build the
coverage record described in section 8):

| The answer | What it means in plain words |
|---|---|
| A finding | The check ran and something was there. |
| Clean | The check ran, it could genuinely have seen the problem, and the problem was not there. |
| Inconclusive | The check did not settle the question. |

**When issuing the "certificate of non-exploitability"** described in section 8,
each combination of surface and weakness type gets exactly one of:

| The answer | What it means in plain words |
|---|---|
| Open | A checker fired. The weakness is there. |
| Closed | A checker had a live channel to the real target, was capable of seeing this weakness, and did not fire. |
| Unproven | The test was attempted but nothing adjudicated it, or that part of the target was never reached at all. |

**When checking, after a repair, whether a fix actually worked:**

| The answer | What it means in plain words |
|---|---|
| Remediated | The exploit that provably worked before is now provably dead. |
| Still vulnerable | The same checker fired again over freshly captured evidence. It is not fixed. |
| Inconclusive | The re-test happened but did not earn either answer. |
| Refused | The re-test was not permitted to start at all — for example the authorisation had expired, the target was out of the agreed scope, or the requested test was of a kind this authorisation does not cover. |

That last one deserves a note. "Refused" is not a result about the customer's
software; it is the system declining to act. It is recorded, signed and reported
exactly like the others, so a refusal can never be quietly dropped and re-read as
a pass.

**And the fourth vocabulary, for completeness.** When the defensive side inspects
a single incoming request in the live traffic path, it answers *confirmed* (a
checker fired, and a certificate exists), *lead* (suspicious, not proved, always
forwarded) or *clear* (no checker fired and the softer signals were below the
noise band). The same discipline applies, and the same caution: "clear" means
nothing was proved, not that nothing is wrong. Chapter 13 sets this out in full.

---

## 3. What a checker is, in plain words

A **checker** in this system is a small automatic checking program. It is
deliberately stupid. It has no opinion, no memory, no imagination, and no access
to the outside world. It is handed a copy of evidence somebody else already
collected, it applies one narrow fixed rule to that evidence, and it says yes or
no.

(As stated in section 1, the software's own word for a checker is *oracle*. The
two words mean one and the same program. Where this section says "checker", the
code and the screens say "oracle".)

The rules every checker must obey are written into the software, and they are the
reason the whole scheme works:

- **It is pure.** It performs no input and no output. It cannot read a file, open
  a network connection, or write anything anywhere.
- **It never sends traffic.** It reads, it judges, it returns. It is incapable of
  touching the target. It only ever judges evidence someone else already
  collected.
- **It is deterministic.** The same evidence produces the same answer, every time,
  on every machine.
- **It has no clock and no randomness.** Its answer cannot depend on the time of
  day or on chance. That is exactly what makes a second party's repeat run
  meaningful.
- **A missing input is a skip, never an assumed pass.** If a checker needs a piece
  of evidence and that piece is not present, the checker does not run. It does not
  quietly decide "probably fine". This is the fail-closed rule from section 1.

A useful mental picture: a checker is the litmus paper, not the chemist. It is the
breathalyser, not the police officer. It cannot be persuaded, it cannot be
flattered, and it does not know what answer anyone was hoping for.

### There are 38 of them, and each proves one narrow thing

In the version of the software read for this briefing there are **38 kinds of
checker**, implemented by **40 distinct procedures** — two of the kinds have two
procedures each, chosen by which evidence is present. Each one answers a single,
tightly defined question.

Just as important as what each one proves is what each one **refuses** to prove.
That refusal is written into the code as a deliberate design constraint. It is not
left to a reviewer's interpretation.

**How to read the rest of this section.** What follows is the complete list of all
38, grouped the way the software groups them. It is a reference, not an argument.
A general reader does not need to recognise any individual checker, and nothing
later in this briefing depends on remembering them. What matters is the *shape*:
every entry has a narrow question, and a written statement of what it will not
say. If you read only one column, read the last one. Each group is introduced with
the handful of plain-English terms it needs.

---

#### Group 1 — the fifteen core checkers

These fifteen are a frozen set. They are the only ones the system will try when it
meets a category of weakness it does not recognise, and that set cannot be
extended by adding new checkers later. In the software they are one flat list of
fifteen; they are split into four themed sub-tables below purely to make them
readable.

**1a. Checkers that compare two recorded answers.** These work by sending a
harmless request and a probing one and comparing what came back.

| Checker | The one question it answers | What it deliberately does not prove |
|---|---|---|
| Differential response | Are these two recorded answers from the target genuinely, materially different? | *Why* they differ. One non-difference proves nothing. |
| Boolean inference | Over repeated rounds, does the "true" case reliably differ from the "false" case, while the two "false" cases agree with each other? | Anything about a page that simply changes on every request — that trips a built-in control. If neither statistical boundary is reached, the answer is inconclusive, never a guess. |
| Timing | Does a real statistical test on repeated timing measurements show a genuine shift, large enough to matter? | Anything based on a fixed delay threshold or a single averaged comparison. It needs at least five measurements on each side. |

**1b. Checkers that follow a marker the tester planted.** The tester puts a unique
made-up value into a request and watches where it turns up. In these entries a
*marker* is that value — a harmless string of characters chosen so that it could
not appear by coincidence.

| Checker | The one question it answers | What it deliberately does not prove |
|---|---|---|
| Side effect | Did the tester's unique marker end up somewhere it must never reach? | That the marker is dangerous where it landed. That is a different checker's job. |
| Out-of-band callback | Did a connection arrive from the outside carrying the secret token minted for this one finding? | Anything without that token. No token, no result. |
| Reflection context | Did the marker land in a position where a web browser would actually run it as code? | An appearance that is escaped, commented out, or plain text. Those are inert and correctly do not fire. |
| Browser execution | Did injected code actually run inside a real browser, proved by a signal that only the driving test harness could have registered? | A test input that was echoed back but never ran. The code describes this as the strongest available evidence for this class. |

**1c. Checkers that read what the target actually did.**

| Checker | The one question it answers | What it deliberately does not prove |
|---|---|---|
| Achieved state | Do the raw recorded values that came back actually satisfy a dangerous condition? | A partial match. Partial matches are informational only and do not fire. |
| Evaluation | Did the server actually *compute* an injected sum — the answer appears, the sum itself does not survive, and a harmless control does not contain the answer? | A test input that was merely echoed back without being computed. |
| Error signature | Did a malformed input provoke a distinctive, product-specific database or parser error that a harmless control did not provoke? | A generic "error" word, or a page that always shows an error message. |
| Sanitizer signal | Does the captured program output contain a genuine memory-corruption or crash marker? | An ordinary handled error. A plain error trace alone earns only moderate confidence. |

**1d. Checkers that judge the machine and the software on it.**

| Checker | The one question it answers | What it deliberately does not prove |
|---|---|---|
| Service reachability | Did the system itself complete a real network connection to this machine and port? | Anything taken from another scanner's "port open" row. |
| Encryption weakness | Did a real encrypted connection actually settle on an obsolete method or a weak cipher — or is a certificate signed with a broken method? | That the server would accept *every* obsolete option. It is limited to what a modern client still negotiates. |
| Version range | Does a specific pinned software version provably fall inside a specific published security advisory's affected range? | That the matching advisory is exploitable here. Absence from the snapshot is not absence of risk. |
| Permission path | Does a real permission route exist, re-derived step by step through the retained permission map, with the ordered chain of steps kept as evidence? | Another tool's judgement that something is "over-privileged". That is never trusted. |

---

#### Group 2 — four checkers for the operator's own application, pointed inward

These belong to the defensive half of the platform: they watch the customer's own
live application for signs it is being attacked, rather than attacking someone
else's.

Two terms first. An **AI assistant feature** means any part of the customer's
application that passes user text to an artificial-intelligence model and shows
the answer. A **planted secret** means a made-up password-like string of random
characters that the operator deliberately puts inside the application's hidden
instructions, purely so that its appearance elsewhere is unmistakable evidence
that those instructions leaked.

| Checker | The one question it answers | What it deliberately does not prove |
|---|---|---|
| Prompt injection | Did an injected instruction visibly flip the assistant's behaviour compared with a clean control run — a refusal reversed, a sensitive action triggered, or a boundary marker echoed only under the injection? | The mere presence of override wording such as "ignore the above". Users legitimately paste that. It stays a LEAD. |
| System prompt disclosure | Did the planted secret appear word-for-word in the application's own AI output? | That an attack caused it. A benign request, or the application's own diagnostic mode, can produce the same. |
| Automated access | Did a client fetch a decoy page that no human-facing page links to? | That it was hostile. Link-preview bots, page pre-loaders and uptime monitors trip it too, and an operator's allowed list overrides it. |
| Credential stuffing | Did one source achieve a statistically significant number of successful logins across accounts it had never touched before, after correcting for how many sources were examined? | A burst of *failures*. Failed attempts produce no statistical round at all, so this can never confirm on failures alone. |

---

#### Group 3 — three checkers that read the request alone

These form an inline protective layer in front of a customer's application. They
judge an incoming request on its own, without needing to see what the application
then did with it. Each proves that a **structured attack attempt** occurred — that
the submitted text is unmistakably an attempt to break out of a data field into
command territory — never that the attempt worked.

| Checker | The one question it answers | What it deliberately does not prove |
|---|---|---|
| Database-query break-out | Does this submitted value provably close a database text field and start adding instructions of its own? | Exploitation. An application that handles the value safely is still safe. Ordinary text containing an apostrophe never fires. |
| Operating-system command break-out | Does this submitted value contain an unmistakable construct for running a command on the machine? | Exploitation. Common look-alike text does not fire. |
| Document-database operator injection | Was a known database instruction word smuggled in as a *field name*, where a plain value was expected? | Exploitation. A curated allowed list deliberately excludes words that have innocent everyday uses, so a price written as `$5.00` and similar do not fire. |

---

#### Group 4 — ten checkers that re-derive a conclusion from a retained file

Each of these reads a configuration file, an export or a package that the operator
supplied. **None of them makes any network call at all.** They are the equivalent
of an auditor reading a filed document rather than visiting the site.

The terms this group needs, in plain words:

- **A cluster** — a group of machines managed together as one pool that runs the
  organisation's software. The common software for doing this is called
  Kubernetes.
- **A single-sign-on login token** — the small signed pass that a website hands
  your browser after you log in, and that your browser presents on every later
  page so you are not asked to log in again.
- **A federation document** — the signed message that one organisation's login
  service sends to another organisation's application to say "this person is who
  they claim to be". It is how "log in with your corporate account" works between
  two separate companies.
- **A service mesh** — the connective layer that governs how an organisation's
  internal software components are allowed to talk to each other.
- **A build pipeline** — the automatic assembly line that takes a developer's code
  and turns it into the running product. It is highly privileged: whoever controls
  the assembly line controls what ships.
- **An identity provider export** — a downloaded list of an organisation's user
  accounts, their privileges, and their login-security settings.
- **Multi-factor authentication** — requiring a second proof at login beyond the
  password, such as a code from a phone or a hardware key.

| Checker | The one question it answers | What it deliberately does not prove |
|---|---|---|
| Cluster posture | Did an industry benchmark check hard-fail *and* does the recorded value literally contain a dangerous setting? | A warning that calls for manual review. A failure with no recorded value, or whose value shows the *secure* setting, does not fire. |
| Cluster workload posture | Is an anonymous, unauthenticated identity attached to one of the dangerous built-in cluster-wide roles? | A harmless public-information attachment, or a role merely *named* "admin". |
| Single-sign-on token forgeability | Can this captured login token be forged offline from the token alone — because it has no signature, a guessable secret, or a known signature-confusion flaw? | A normal token whose key is unknown. This proves *forgeability*, with no traffic sent. Whether the target would *accept* a forgery is a separate class. |
| Federation-document structural forgery | Does this captured federation document show a coarse structural defect that a validly signed one cannot have? | Full cryptographic signature processing. That is explicitly out of scope unless the operator supplies trusted certificates and an optional software library is present. |
| Cloud posture | Does one recorded cloud setting show an explicitly insecure state — encryption switched off on a sensitive store, an explicit "public" flag, a wildcard or anonymous party named in the policy, or a named outside account? | A setting whose value is simply unknown. Unknown is never treated as insecure. The "outside account" rule fires only when the owner's own account list was supplied; the owner is never guessed. |
| Service-mesh posture | Does the retained configuration *declare* a permissive state — mutual authentication made optional or switched off, or an allow-everyone rule? | The posture that actually applies when the system runs. Rule precedence is not worked out, and a setting inherited from elsewhere is never promoted. |
| Build-pipeline posture | Does the pipeline file contain a dangerous construct — a third-party step pinned to a moveable label rather than an exact version, a checkout of untrusted code, or an untrusted value pasted into a command? | That the pipeline *was* exploited. No code is downloaded and no pipeline is run. |
| Mobile posture | Does the mobile application have a private cryptographic key built into it that actually loads as a valid, unencrypted private key? | Almost every other mobile signal. An adversarial review concluded that the other candidate rules depend on device behaviour the packaged app does not record, so they remain LEADs. |
| Email authentication posture | Does the domain's *published* anti-spoofing policy provably permit forged mail — missing, set to "monitor only", or permissive? | Whether any individual message was genuine. That cannot be soundly re-derived offline. A sub-domain inheriting a strict parent policy does not fire. |
| Identity posture | In an identity-provider export, is a privileged account explicitly recorded as having no second login factor, or a credential explicitly recorded as never rotated or past its own stated maximum age? | Behavioural anomaly detection, which is a matter of probability. A *missing* multi-factor field is a refusal — an absent field is not proof of absence. |

---

#### Group 5 — six checkers for the exploitation chain

These are the strongest class. Each one judges a capture made by a separate,
individually authorised action — for example, actually retrieving a credential, or
actually calling an interface with it to see whether it works. The checker itself
still never touches the network; a separate, gated component does the capture and
hands over the recording.

Two terms this group needs:

- **The instance-metadata service** — a small internal information service that
  cloud providers make available to every virtual machine they run. It hands out
  the machine's own access credentials. It is the classic prize in a cloud
  break-in, because reaching it from outside turns a minor flaw into stolen keys.
- **A service account** — a login identity belonging to a piece of software rather
  than to a person.

| Checker | The one question it answers | What it deliberately does not prove |
|---|---|---|
| Active exposure | Did a single bounded request carrying no credentials at all come back successful, with real content in it? | Anything taken from an audit tool's "public" flag. It does not fire on a redirect, on "present but protected", on "not found", or on an empty response. |
| Instance-metadata credential capture | Were both halves observed — a properly formed cloud credential whose recorded source is genuinely the metadata service, *and* a confirming call that returned a real identity with no failure marker anywhere? | That the exact captured credential produced that confirming call. A credential retrieved but not confirmed stays a LEAD. |
| Exposed-secret validity | Is an exposed secret still live — a recognised type, whose confirming call authenticated as a real identity, cryptographically tied to that call, over a validated connection, at an address on a fixed allowed list? | Anything about the secret's content, which is stored only as a redacted "it was here" marker. An address not on the allowed list can never produce a result. |
| Cloud service-account impersonation | Did one identity mint a short-lived pass *as* a named second service account, with a confirming call at an approved address echoing back that second identity? | Any claim about where the pass came from. An echo of a different identity does not confirm. |
| Permission-escalation primitive | Does the retained configuration *unconditionally* permit a known privilege-raising move that strictly increases reach — proved by an explicit difference between two computed sets of what is reachable? | That anyone carried it out. Any restricting condition, exclusion, explicit denial or boundary contributes nothing at all, and a target already reachable without the move is not an escalation. |
| Cluster dangerous-permission grant | Do a retained permission attachment *and* its separately retained role definition together hand a dangerous capability to an identity an attacker could occupy — with the link between the two re-checked rather than trusted? | Anything outside a strict eligibility test. An anonymous identity may confirm on any dangerous shape, but a default or merely-logged-in identity may confirm only on a full wildcard grant and only cluster-wide, because ordinary legitimate roles otherwise look similar. |

---

### Why the newer checkers cannot fire by accident

There is a structural safeguard here that deserves a plain statement. Only the
fifteen core checkers are in the fallback set used for an unrecognised category.
Every checker added since then can be reached **only** through an explicit,
reviewed entry in a routing table, and each one requires a specific piece of
evidence that no ordinary web scan ever produces.

The consequence matters for anyone assessing change risk: **adding a new checker
to the system cannot change what an existing scan does.**

---

## 4. The journey of a claim, step by step

Here is what actually happens between "something looks odd" and "this is a FACT".

### Stage 1 — somebody proposes

A proposal can come from a built-in check, from a sensor, from an outside tool
the system ran, from a third-party report the operator loaded in, or from the
artificial intelligence component. At this stage it is only a proposal. It arrives
with a retained copy of whatever evidence was collected.

### Stage 2 — the checker runs

The system looks up the claimed category of weakness and selects the checkers that
are allowed to prove that category. It runs only those whose required evidence is
actually present. The rest are skipped, and recorded as skipped.

A proposal becomes "confirmed" only when **both** of the following hold:

- at least one checker fired at a strength of **0.70 or above** on the internal
  scale; and
- the claimed category of weakness is one the system's vocabulary recognises.

That second condition is a hard safeguard against invented findings. The system
accepts **275** distinct spellings of weakness category, mapping onto **85**
canonical categories. If a claim names a category outside that vocabulary it
**cannot** be confirmed — even if a general-purpose checker fires over the
evidence. The software says so explicitly in the recorded reasoning, so the
refusal is visible and auditable rather than silent.

One more rule is worth stating because it is counter-intuitive and deliberate:
**a checker that does not fire cannot veto one that does.** When several checkers
examine the same evidence and one of them fires, the silent ones are recorded as
"dissent" for the audit trail. They are not treated as a refutation. The reason is
that the checkers are individually one-sided: each is built to be right when it
says yes, and to say nothing when it cannot tell.

### Stage 3 — the admission desk

Firing a checker is not enough. The result then passes through a single admission
point, which consults a **registry of evidence windows** — a reviewed declaration
file listing every distinct route by which the system can reach a conclusion.

An **evidence window** (the software calls it a *branch*) is the specific opening
through which a particular claim may be proved. "In the response headers" is one
window; "in the body of the page" is another; "in a configuration file the
operator supplied" is a third. The same problem seen through different windows
supports different strengths of claim, which is why each window is registered and
governed separately.

In the version read for this briefing there are **26** registered windows. For
each one the registry declares, separately:

- may this window produce a FACT?
- may a non-firing seen through this window be reported as CLEAN?
- what conditions must hold for this particular observation?
- what is this window's honest limitation, in writing?
- if the window is not yet as capable as it should be, what is the **named
  engineering work** that would close the gap?

The admission desk then applies these rules:

- An **unregistered** window is a fatal error. It cannot produce a verdict at all.
  This exists so a newly added evidence route cannot silently inherit the
  authority to declare facts.
- If the window's declared conditions did not hold **for this specific
  observation**, the answer is INCONCLUSIVE. A condition that is declared but
  simply absent from the observation counts as *not held*: an unknown is not a
  yes.
- If a checker fired and the window is fact-capable, the answer is FACT. If a
  checker fired but the window is **not** fact-capable, the answer is LEAD — with
  the window's written limitation attached as the stated reason.
- If nothing fired and the result was not decisive, the answer is INCONCLUSIVE.
- If nothing fired, the result *was* decisive, and the window is clean-capable,
  the answer is CLEAN. Otherwise INCONCLUSIVE, again with the written limitation
  attached.

Conditions are checked per window rather than globally, and this matters. "The
body of the response was readable" is meaningless to a conclusion drawn from a
response header, and decisive to one drawn from the document. A single captured
exchange can legitimately produce a header-derived CLEAN and a body-derived
INCONCLUSIVE at the same time, and the system reports both rather than blending
them into one comfortable answer.

The admission desk also has a specific anti-forgery property, and it is worth an
analogy because the mechanism is easy to misread.

An admitted verdict can only be created at the desk itself, while the applicant is
standing there. The authority to create one lasts exactly as long as that one
transaction and then disappears. It is not attached to the finished document as a
mark that travels with it.

The difference matters. If the authority were a mark on the document — a stamp, a
sticker, a badge — then anyone holding a genuinely stamped document could
photocopy it, alter the wording, and still be holding something that carries a
genuine-looking stamp. That is exactly what an internal adversarial review found
when the authority was held that way: a verdict could be copied, edited into a
FACT, and still present a valid mark. The design was changed so that the authority
lives only in the moment of issue. Creating one of these verdicts directly,
copying one, or saving one and reloading it from a file all now fail loudly rather
than producing something that looks admitted.

**What this cannot stop, and why that is contained.** The software is honest about
the limit. A sufficiently determined programmer with access to the running program
could, in principle, forge one of these approvals in the computer's memory — and
that is true of any protection of this kind, in any software. So the design does
not rely on it. Instead, the last step catches it anyway: before a proven finding
is sealed and signed, the checker is run again over the saved evidence. A forged
approval that never went through the proper route simply does not reproduce, and
cannot be sealed.

Finally, when several window results are summarised together, the summary is
conservative: any FACT makes the family a FACT; otherwise any LEAD makes it a
LEAD; otherwise any INCONCLUSIVE makes it INCONCLUSIVE; only if every window was
CLEAN is the family CLEAN. An **empty** set composes to INCONCLUSIVE, not CLEAN.
Nothing examined is not the same as nothing found.

### Stage 4 — the sealed evidence bag

A confirmed result is packaged into a signed **evidence certificate**. Opening
that package later and checking it is sound only if **all four** of the following
hold:

1. **Authenticity** — the package carries a valid multi-party cryptographic
   signature over its exact contents. More than one authorised key must sign.
2. **Binding** — the package's recorded fingerprint of the evidence matches the
   fingerprint of the evidence actually presented alongside it. A signature cannot
   be lifted off one set of evidence and pasted onto another.
3. **File integrity** — every raw file listed in the package still matches its
   recorded fingerprint. A package that *claims* attached files but is checked
   without access to them fails closed; it is never waved through.
4. **Reproduction** — the checker runs again over the retained evidence and
   produces the same verdict.

The root of trust is pinned **out of band** — meaning it is obtained through a
completely separate channel from the package itself. The verifier compares the
signing authority against a fingerprint the operator published separately, not
against the copy shipped inside the bundle. This is the same idea as checking a
notary's seal against the public register of notaries, rather than against the
certificate the notary handed you. It closes the obvious attack: a forger who
tampers with the evidence and re-signs it with their own fresh key is rejected
before any signature is even checked.

The package also records the **exact version of the checker** that produced the
verdict. That version is a fingerprint computed over the checker's own source code
*plus every helper function and constant its decision procedure reaches*. Editing
a helper or a single constant changes the version. So if the checker's logic
changed after the certificate was issued, a verifier can detect it, and the
stricter verification path treats that mismatch as a failure rather than shrugging
it off. If the source code is not available — for example in a frozen deployment —
the verifier reports that it cannot confirm the version, rather than guessing.

### Stage 5 — the demotion-only firewall

There is a further layer whose only power is to **take claims down**. It re-runs
every ground a claim cites and labels the claim accordingly: contradicted,
ungrounded, grounded-as-hypothesis, or grounded-as-fact. It can turn a fabricated
"confirmed" into "ungrounded". It can never promote a claim that the checker
refused.

Its checks include several bindings that are easy to overlook and hard to work
around:

- A checker proof must fire again **for the claim's own category**. A proof of one
  weakness cannot be used to support a claim about a different one.
- A certificate must certify **that** category.
- A claim that came from a rehearsal or dry run may stand only on re-executable
  proof, never on its own reasoning.
- A fact claim must name its subject. In the system's own words: *an unbound proof
  grounds nothing.*
- The confidence reported for a fact is the **re-executed** number, not the number
  the proposer supplied.

A claim that fails all of this is **stamped, not deleted**. It is presented as
labelled analyst commentary. The design principle is stated in the code: the
operator loses framing, never information.

**An honest note about how widely this layer is applied.** This component was
originally written as a standalone building block, and a comment inside it still
says it is only exercised by its own tests. **That comment is now out of date**,
and this briefing states what is actually true in the code rather than what the
comment says. The layer has real call sites today, including:

- every confirmed finding during a live engagement run, checked against the
  system's accumulated picture of the target;
- report generation, through a single shared grounding authority that the
  reporting agent and the scan orchestrator both use;
- the defensive half of the platform, where it sits between the checker and the
  final verdict;
- an internal critic that grades whether a claim is grounded;
- a refusal component that declines to assert things that are not grounded;
- and one of the tools the AI agents can call.

What is **not** yet true is the strongest version of the claim: it is not today a
single universal choke point through which *every* claim in the system passes.
Notably, writes into the system's internal map of the target use a shared
provenance classifier rather than passing through this admission function. So the
correct summary is: a real, working, widely called layer, not yet a single
universal gateway. This briefing preserves that distinction rather than smoothing
it over in either direction.

### Stage 6 — anyone can check it again, offline

This is the step that makes the rest meaningful.

Because the checkers are pure and deterministic, a sealed certificate can be
re-checked by anybody, offline, with **no access to the target** and **no trust in
the tool that produced it**. The recipient reconstructs the retained evidence,
runs the same fixed procedure, and compares.

The re-check is strict in two ways that matter:

- It verifies not just that the checker fires again, but that it produces the
  **same checker identity and the same confidence number**, to within one part in
  a million. A mismatch is annotated as possible tampering.
- It refuses a category mismatch at the boundary. If someone takes evidence that
  proves one weakness and relabels the finding as a more serious one, the re-check
  refuses, rather than silently re-confirming under the evidence's own original
  category.

There is a command-line tool for this. It exits with a success code **only if
every certificate in the file reproduces and matches its claim**, and with a
failure code otherwise. That means the check can be wired into an automated build
process: a report that no longer verifies stops the build.

For a purchasing agency the practical consequence is this: **you do not have to
take the vendor's word, and you do not have to re-run the engagement.** Re-running
an engagement is the expensive part. Re-checking a signed certificate is not.

---

## 5. Why the artificial intelligence is never allowed to promote a claim

Where this briefing says "the artificial intelligence", the technology in question
is a **large language model** — often abbreviated **LLM**. That is a program
trained on very large amounts of text, which produces text in response to text.
It is the same family of technology as the familiar public chat assistants. Its
strengths are reading unfamiliar material, proposing explanations and deciding
what to look at next. Its weakness, for this purpose, is that it produces fluent
output whether or not the output is true, and it cannot be re-run to the same
answer.

The system uses it for what it is good at: reading unfamiliar systems, generating
hypotheses, deciding where to look next, drafting explanations. It is never
allowed to decide that something is true.

The rule is: **the model proposes; the checker confirms.**

Several independent mechanisms enforce this. They are worth listing separately,
because any one of them alone would be a weak promise.

**1. Where the evidence came from is tracked, and AI-supplied evidence cannot mint
a fact.** Every retained piece of evidence carries a label recording its origin —
its *provenance*, meaning the recorded history of where it came from and how it
was obtained. A signed FACT is minted only when that label is one of two non-AI
values: evidence rebuilt from raw captured tool output, or evidence re-driven
directly against the authorised target. The default label — meaning the evidence
is the model's own extracted summary — is **demoted to a LEAD even if the checker
fires over it**. The reasoning recorded in the code is precise: a context the model
crafted, which then happens to fire, is an AI-influenced route to a fact, so that
route is closed. The checker still runs, so the LEAD is still informative about
what fired; it is simply never signed.

**2. Invented categories cannot survive.** The vocabulary of weakness categories
is enforced as a data type in the software, so a fabricated category name fails at
the moment a structured AI output is read into any field that asserts a provable
subject. Exploratory hypotheses may legitimately range wider; fields that claim
proof may not.

**3. Relabelling is defeated at two independent places.** The strict verification
path checks that the checker which fired is a *valid confirmer for the claimed
category*, and the offline re-check refuses a category that does not match the
evidence's own.

**4. Conversation and command output are advisory only.** Terminal and agent
output never enters the checker's input.

**5. The critique layer can only lower.** The AI critique panel is explicitly
advisory. The checker is the authority; a critique demotes or advises, and never
promotes.

**6. The same rule applies to outside tools, not just to AI.** The system can
drive well-known third-party security tools. A separate reviewed matrix records,
tool by tool, whether that tool's output may ever back a proven fact. In the
version read for this briefing it holds **33** entries. Only **two** — the network
mapper `nmap` and the encryption scanner `sslscan` — are marked as able to back a
fact, and even then only through the system's own independent re-drive and its own
checker. **Seventeen** entries are excluded outright as offensive,
credential-attacking or destructive tooling that may never be a source of proof.
Everything else is lead-only: the tool may say where to look, and its say-so never
becomes a fact.

Two well-known tools illustrate the distinction sharply. The system *can* be asked
to run `sqlmap`, a database-injection tool, under its strictest authorisation
gates — but `sqlmap`'s output can never become a proven fact. When the system
confirms a database injection, it does so with its own authorised re-drive and its
own checker. Structural rules in the validating test prevent a tool entry from
escaping this by relabelling its own category, and a name-based backstop forces
exclusion for known offensive programs regardless of what an entry claims about
itself.

**7. The same rule applies to another AI acting as the judge.** This is the
sharpest illustration of the whole principle, because it is the case where the
temptation to cheat is greatest.

There is a component for testing a customer's *own* AI application — driving
established AI red-teaming tools against it and collecting what they report. Those
tools decide whether an attack "worked" in one of two ways. Some use a mechanical
rule: does the answer contain this exact string, does it match this pattern, does
a fixed classifier flag it. Others ask **a second AI model to be the judge** and
give an opinion.

The system routes on exactly that distinction:

- A mechanical rule can be re-run by the system's own checker, over a freshly
  minted one-time challenge value. If that re-run confirms, it may become a signed
  FACT.
- A verdict from an AI judge **is always a LEAD, permanently**. The code returns
  from that path *before* any checker is even called, so the promotion route is
  structurally unreachable. The stated reason is exact: an AI judge's verdict can
  never be re-executed into a deterministic proof, and piping one into a signed
  fact would launder a guess into the permanent record.

Two details show this was thought through rather than asserted. First, the
"attack success rate" these tools report is treated as a *descriptive measure
only*, never as grounds for promotion — a category judged by an AI judge stays a
LEAD even at a maximum success rate. Second, an *unrecognised* attack category
defaults to the AI-judge path, which is the always-a-LEAD path. The open-source
component this was adapted from does the opposite, defaulting an unknown category
onto the promotable path; the system deliberately inverts that, so an
unclassified case can never reach the promotion route.

**Honest status of this component.** It is built, tested and gated. The external AI
red-teaming tools it drives are not present in the environment examined and could
not be installed without network access, so this capability has been proven with
recorded sample data standing in for the real tools, not with a live run against
them.

**8. The same rule applies to another vendor's report.** An agency will usually
already own security tools. The system can deliberately load in an export from
one — from any of eight supported formats, including the widely used Nuclei, ZAP,
Burp, `sqlmap`, Nikto and Wapiti tools, the industry-standard SARIF interchange
format, and a plain generic format for anything else.

What happens to that import is the doctrine applied to somebody else's work.
Every imported item becomes a labelled **observation** in the system's internal
map — a real, collected lead — carrying an origin label that classifies it as
collected intelligence, never as proof. In the code's own words, it is
deliberately *not* recorded as a finding, because "finding" is reserved for what
one of the system's own checkers re-verified. Each imported item is explicitly
flagged as a lead and as unverified. A tool that confirms by exploiting (such as
`sqlmap`) earns a slightly higher credibility rating than a purely heuristic
scanner, and is still only a lead until the system's own checker fires.

Three further properties are worth noting for an assurance reader: the import
performs no network activity and runs nothing; importing the same report twice
produces exactly the same result and adds nothing the second time; and nothing in
this path runs at all unless an operator explicitly invokes it. A single import is
capped at 5,000 items.

---

## 6. What happens when a check stops reproducing

This is the question that separates a genuine verification system from a
verification-flavoured one. It is easy to prove something once. The discipline is
in what happens afterwards.

The system's answer is that a proof is **re-executed at the moment it is used**,
not read from a stored flag.

**At report generation.** When a technical report is produced, every finding's
retained evidence is run through its checker *at that moment*. The stored
"confirmed" flag is not trusted. The report then places findings into three
explicitly separate columns, with a plain-English explanation of each printed at
the top of the report:

- **Checker-confirmed** — the proof still reproduces; it is a proven fact. (The
  report prints this as "oracle-confirmed", using the software's own word for a
  checker.)
- **AI-advisory** — there was never a mechanical signal at all; it is a lead. (The
  report prints this as "LLM-advisory". LLM is the abbreviation for large language
  model, explained at the start of section 5.)
- **Demoted** — it *was* recorded as confirmed, but its retained proof did **not**
  reproduce when the report was generated.

The demoted category is never merged into the advisory one. The report tells the
reader, in words, to treat a demoted item as a lead and to investigate *why* the
evidence no longer reproduces. Internally the two are both "not proven", and are
kept as separate labels only so the reader can see which kind of unproven it is.
Something is also withheld rather than merely labelled: for an unproven item the
supporting evidence is not attached to the rendered output at all, so the
component that grades the report structurally *cannot* dress it up as a fact.

**In the system's internal map of the target.** When results are written into the
system's internal knowledge map, the same re-execution happens. A finding whose
proof fires again is written with an origin label the map classifies as grounded.
A finding whose proof does **not** fire again is written with a downgraded origin
label that the map classifies as ungrounded, plus an explicit searchable marker
recording that it was demoted. The consequence, stated in the code, is that the
internal map never carries a fact-grade entry whose proof does not currently
reproduce. If the grading itself cannot be performed for any reason, the result is
treated as not-a-fact. It fails towards caution.

**At the offline re-check.** The command-line verifier reports each certificate
individually and exits with a failure code if any single one of them fails to
reproduce or fails to match its claim.

**Under tampering.** The four independent certificate checks are what catch
deliberate interference. Editing the evidence breaks the fingerprint binding.
Editing the certificate breaks the signature. Editing an attached raw file breaks
that file's fingerprint. Editing the claimed confidence breaks the reproduction
comparison. Swapping in a friendly signing authority is refused by the
out-of-band fingerprint pin.

The pattern across all of these is the same: **a claim is never quietly kept, and
never quietly deleted.** It is downgraded, in the open, with a stated reason.

---

## 7. What "confidence" means here

The word "confidence" is used loosely across the security industry, so it needs a
precise definition. In fact this system computes three different numbers that all
get called confidence in ordinary speech, and they answer three different
questions.

An analogy holds them apart. Imagine a clinic.

- The **first** number is the reading on the instrument — how strong was this
  particular signal, in this particular test.
- The **second** number is the clinic's audit record — how often have readings
  like this one turned out, in the end, to be right.
- The **third** number is the physician's reasoned assessment — given this
  reading, what else could explain it, how likely is each explanation, and what
  single further test would settle the matter.

They are different questions, and the system keeps them separate. Critically,
**none of the three can promote anything.** Only a checker firing over retained
evidence can do that.

### 7.1 The first number: confidence inside a checker

Each checker returns a number between 0 and 1 describing the strength of the
**specific signal it observed**. It is not a general estimate of the tool's
reliability, and it is not a probability that the finding matters commercially.

Where a checker has several independent corroborating dimensions, it combines them
so that agreement raises the number and no single weak dimension can dominate. The
combination is **hard-capped at 0.99**. The comment in the source states the
principle directly: *a deterministic oracle never claims certainty it cannot have.*

A finding is confirmed at **0.70 or above**. Below that the signal is recorded but
does not confirm.

Two further properties make the number trustworthy rather than decorative:

- The number is **part of the proof**. Re-verification checks that the recomputed
  confidence matches the claimed one to within one part in a million. A changed
  number is treated as possible tampering, not as a rounding difference.
- The number reported for a fact is the **re-executed** value, not the value the
  proposer supplied.

### 7.2 The second number: the learned calibration

There is a second and quite different kind of confidence in the system: a learned
estimate of how likely a finding is to turn out genuinely exploitable, fitted from
recorded outcomes rather than hardcoded.

The design of this layer is instructive, because it is where a vendor would most
easily cheat, and the system's own documentation is blunt about it:

- The estimate is **never 1.0**. It is clamped at 0.999, on the same "never
  certain" discipline.
- It is **learned, not asserted**. Even the boost that a checker-confirmed finding
  receives is the measured rate among checker-confirmed findings. In the
  documentation's own words: if confirmed findings historically turned out to be
  false positives, that learned prior shrinks and confirmation stops meaning
  certainty.
- With fewer than **eight** usable resolved outcomes there is not enough data to
  calibrate honestly, so the layer degrades to a pass-through that changes
  nothing. The learned boost needs at least three checker-confirmed outcomes
  before it is fitted at all. The stated principle: do not invent reliability that
  has not been measured.
- Outcomes labelled "disputed" — meaning the ground truth is unknown — are
  excluded from every fit and every quality measure. The system does not guess
  ground truth it does not have.
- The labelling is deliberately non-circular. A finding is automatically labelled
  genuinely exploitable only on corroboration by at least **two distinct kinds of
  checker**. Everything else is marked disputed and excluded. And critically: **a
  silent checker is never automatically labelled a false positive** — that would
  be the checker grading its own homework. AI and critique signals never enter
  this path at all.

The honest boundary on this layer: it informs prioritisation and display. It does
not promote anything. A learned probability never turns a LEAD into a FACT.

### 7.3 The third number: the competing-explanations assessment

The third layer is the most distinctive, and the previous edition of this chapter
omitted it.

A scanner says "cross-site scripting, confidence 0.9". A scientist asks three
different questions: how likely is this really, what *else* could explain what we
saw, and what single further test would settle it? This layer turns each confirmed
finding into exactly that.

For each confirmed finding it builds:

- **an explicit starting assumption** — how likely this kind of bug is before the
  evidence is considered;
- **a set of competing innocent explanations**, chosen for that specific weakness
  class. For cross-site scripting the competitor is "the input was echoed back but
  safely escaped, so it does not run". For a broken-access-control finding it is
  "the record was returned, but the caller was genuinely authorised to see it".
  For the prompt-injection detection it is "a harmless edge-case prompt that
  happens to quote override wording, with behaviour unchanged against the
  control". The set always includes a residual "none of these" possibility, so the
  explanations cover the whole space and cannot silently omit the true one;
- **an evidence ledger**, in which each piece of evidence is weighted by how much
  more likely it is if the bug is real than if the innocent explanation is true,
  discounted by the reliability of its source and by how independent it is of the
  other evidence. A checker firing moves the odds far more than a passive
  indicator does;
- and from those, **a probability for each explanation** that sums to one across
  them all, **a range around the headline number** that narrows as evidence
  accumulates, and **the single most valuable next observation** — the one test
  that would move the answer most. The code's own summary of the effect is that it
  turns "cross-site scripting detected, confidence 1.0" into "probability 0.992;
  best alternative explanation 'reflected but escaped' 0.006; one more
  execution-context observation would exceed 0.999."

Where this is actually used, stated precisely:

- It runs on every governed engagement, over each confirmed finding, and the
  resulting probability is printed beside that finding in the engagement's own
  output.
- The defensive half of the platform uses it as an honest false-alarm guard: the
  probability, the range and the leading alternative explanation are attached to
  every verdict it issues.
- It is calculated by pure reasoning over evidence already collected. It sends no
  traffic.
- It is best-effort by design: if it fails for any reason the engagement continues
  unaffected, because it has no authority over the outcome.

And the boundary, stated as plainly as the capability: **this layer does not
override the checker.** The checker remains the sole authority on whether
something is confirmed. This layer only expresses how confident that confirmation
leaves us, in terms that name their own competitors. A high probability here
cannot turn a LEAD into a FACT.

---

## 8. Why "we found nothing" is much harder than "we found something"

This asymmetry is the single most under-appreciated point in security testing, and
this system is built around it.

Think of a smoke detector that has been silent all year. That silence means one of
two very different things: either there was no fire, or the battery is dead. The
silence alone does not tell you which. Before silence can be read as safety, you
have to prove the detector was working.

Stated formally: "we found something" is an **existential** claim — one positive
observation settles it. "We found nothing" is a **universal** claim: it asserts
something about every way the problem could have shown itself. To earn it, you
must first prove that your observation channel was **capable of seeing the problem
had it been there**.

Absence of a positive signal is not proof of absence.

The system encodes this in a specific flag. A checker's answer is marked
*decisive* only when the checker genuinely had a working channel and rendered a
definite verdict — for example, a repeated statistical test that reached its
"refute" boundary, a timing test with enough measurements that found no shift, a
definite proposition evaluated over observed values, or a test input **observed
arriving at its destination and neutralised there**.

It is **not** decisive when a one-sided checker merely failed to fire with no
observable channel — a single comparison over indistinguishable answers, or a
marker that simply never appeared. That is the dead battery. Such a non-signal is
inconclusive, never clean.

The rule that flows from this is stated in the code as the line the system exists
to hold: **a test input sent with no adjudicating channel is inconclusive, never
clean.**

The practical consequence for a reader assessing the product: **only 6 of the 26
registered evidence windows may currently say CLEAN at all.** All six are derived
from response headers, from the network connection itself, or from the encryption
handshake — places where "nothing was there" can be established without ambiguity.
A closed network port, for example, is a genuine channel-confirmed negative. Every
window derived from the body of a document, from a parsed configuration file, or
from a live capture may currently say only FACT, LEAD, or INCONCLUSIVE.

That is a deliberately narrow claim, and the reason it stays narrow is
instructive. The gap for each window is recorded as **named engineering work**,
and a test enforces that the name exists. Seventeen of the twenty-six windows
carry such a note. Reading them, the pattern is consistent: what stands between
the system and a clean verdict is almost never better detection. It is a
**completeness proof**. To say "there is no redirect in this document" the system
must first be able to read *every* document correctly, including every compression
format and character encoding, without cutting anything short. To say "this
cluster has no dangerous permission grant" it must first prove that the export it
was handed listed *every* grant.

The project's written doctrine also forbids the obvious escape route. A capability
gap may not be closed by editing the claim downwards. The claim stands and the
engineering is expected to rise to meet it, and a gap without named work fails the
enforcement test. Lowering a *target* — declaring that a capability is not
achievable at all, rather than merely not built yet — requires writing down the
argument for why it is unachievable. Six windows carry such an argument today, and
in every case the argument is the same: proving the *absence* of a capturable
credential, a valid secret, an impersonation route, or an escalation route is a
different capability — a complete inventory with a completeness proof — and not
this window's job. The clean side of the question is routed to the
configuration-reading windows rather than abandoned.

### The negative results the system does ship

Despite that narrowness, the system does produce three kinds of evidence-backed
negative statement.

**A coverage certificate.** For each combination of surface, parameter and
weakness class that the audit actually reached, it records whether an applicable
checker actually **ran and adjudicated**. This turns a silent area from "merely
untested" into "provably tested". It is signed. Its honest scope is written word
for word into the signed contents: it certifies coverage of the surfaces the
scanner *reached*, and it is explicitly **not** a proof that it reached
everything. The limits that bounded the crawl are cited inside it, so a reader
cannot mistake reach for the whole application.

**A posture certificate — a "certificate of non-exploitability".** This is a
signed projection of the coverage record into open, closed or unproven per
combination (defined in section 2), bound to an owner-signed statement of what the
target is. It can be checked by a third party with no copy of the system
installed. Its stated meaning is bounded and printed inside the signed document:
"closed" means non-exploitability **by that family of checkers, over the surface
actually reached, as of the stated freshness date** — never "secure against
everything". A structural rule refuses to issue a "closed" that names no decisive
checker, and "unproven" never counts as "closed". Even its stronger verification
tier carries a written limit: re-execution proves the binding between the verdict
and the retained evidence; it does not by itself prove that the retained evidence
reflects the live target. Section 10 describes that limit, and the in-house work
aimed squarely at it.

**A remediation certificate.** After a fix, this establishes that the exploit
which provably worked is now provably dead: the original checker went silent over
freshly captured evidence from the repaired build, cross-bound to the original
positive certificate. All four possible outcomes are signed, so an inconclusive
reason cannot be stripped out and re-read as success. Silence only counts as a fix
when it is *controlled*: a positive-control twin must still fire, proving the test
harness is alive, and the target must have genuinely answered — measured only on
response fields the target itself produced, never on fields the testing side set.
A fail-closed list of exactly **13** checker kinds is the only set for which
silence is a sound negative; every excluded kind carries a written reason, and an
unrecognised category fails closed.

---

## 9. The same discipline, applied to the system's own supply chain

A **supply chain**, in software, means the same thing it means in manufacturing:
the chain of outside suppliers whose parts end up inside the finished product. No
modern product is written entirely by the people who sell it. It is assembled from
hundreds of components written by other people and fetched automatically when the
product is built.

A point worth making plainly for an agency assessing a supplier: the
prove-don't-guess rule is not applied only to the customer's systems. It is
applied in two places at once — to other people's components when the system
reports a weakness in them, and to the components of the system itself.

### 9.1 Components as a category of finding

**This is built and working today.** When any scanner reports
"this package version is affected by this published security advisory", that is a
LEAD — another tool's assertion. An **advisory** here is a public notice, of the
kind a manufacturer issues for a faulty part, saying "this component, between these
two versions, has this flaw". It becomes a FACT only when the system's own
deterministic comparator re-derives that the concrete pinned version genuinely
falls inside the advisory's affected range. That comparator is pure and
fail-closed: a version it cannot parse, or a range it cannot parse, does **not**
confirm — so a scanner's say-so cannot be laundered into a fact, and a mangled
range cannot fabricate one. The advisory data it reasons over is a **pinned, dated
snapshot** held alongside the software and refreshed deliberately, so a confirmed
dependency finding re-verifies offline from its certificate, months later, without
an internet connection.

The honest limit on that window is recorded in the same place as everything else:
a dependency finding of this kind may produce a FACT but may **never** produce a
CLEAN. Absence from a pinned advisory snapshot is not absence of vulnerability,
and version constraints expressed as ranges rather than exact pins are skipped
rather than guessed at. The named work required to make "no advisory matched" a
bounded negative is written down.

### 9.2 The safeguards on the system's own build and release

The other half of the problem is not what the system finds in the customer's
software. It is what goes into the system itself. Almost every part of a modern
product is assembled from components written by other people, and those components
are fetched automatically when the product is built. An attacker who can quietly
change one of them changes what ships, without ever touching the supplier's own
work. Four measures address that, and they are **part of the released software**.

**1. Every outside component is locked to a fingerprint.** A fingerprint here is a
short code computed from the exact bytes of a file: change one byte anywhere and
the code changes completely. The system keeps a written list of every outside
component it uses, at an exact version, each with its fingerprint recorded. At
installation time the installer is run in a mode that refuses the whole list if any
single component is missing a fingerprint or arrives with the wrong one. It is the
difference between "fetch me a copy of this book" and "fetch me the copy whose
every page matches this record". There are two such lists, because the product has
two halves — the attacking half and the key-holding half — which are deliberately
never allowed to run inside the same program and therefore cannot share one list.
The attacking half's list pins **26** outside components; the key-holding half's
list pins **56**.
The build proves this is a working control, not a document, by actually performing
a clean installation from each list in the refuse-on-mismatch mode.

**2. The machine images are pinned to exact content, not to a moveable label.** The
system's parts run inside prepared machine images downloaded from public
libraries. Those are normally referred to by a label such as "the latest version",
and a label can be repointed at different content by whoever publishes it, with no
visible change on the supplier's side. Every such image is instead named by its
content fingerprint, so it either arrives byte-for-byte as chosen or the download
fails. A check that runs without network access confirms every image reference is
pinned in this way. In the version read for this briefing it examines **nine**
image references: eight are pinned to exact content, and the ninth is exempt with a
written reason — it is built from this project's own code, so there is no outside
publisher to pin against.

**3. A bill of materials is published for every build.** This is a
machine-readable list of every component that went into the product, in a
published standard format that other software can read. It is produced fresh from
the locked list at each build and published alongside it. It is deliberately
regenerated rather than stored, because the locked list is the authoritative
record and a stored copy would drift from it. The build cross-checks the generated
bill against the locked list component by component, so a faulty generator that
silently dropped a component fails the build instead of producing a
confident-looking, incomplete list.

**4. A release gate stops the build on a critical known vulnerability.** Every
proposed change is scanned against public vulnerability databases. A finding of
**critical** severity fails the build, and the change cannot be released. A finding
of **high** severity is reported in full in the build record but does not block.
That threshold is a deliberate, written policy rather than a convenience: a gate
whose exception list has to keep growing to stay green stops meaning anything.
Every exception must carry a written justification naming one of five permitted
reasons, and a test fails the build if any exception is added without one. The
exception list is currently empty.

Two details show the same prove-don't-guess discipline turned on the safeguards
themselves.

- **The gate is proved capable of firing.** A gate that reports nothing is
  indistinguishable from a gate that is broken and cannot report. So immediately
  before the real scan, the build runs the *identical blocking configuration*
  against a small purpose-made sample containing components with known critical
  vulnerabilities, and requires it to fail. If that sample passes, the build stops
  with an explicit message that the gate below it is meaningless. This is the same
  negative-control idea as the safe-twin application in section 10, applied to the
  supplier's own release process.
- **The scanning tool and the build steps are themselves pinned.** The
  vulnerability scanner is fetched at a fixed version and checked against the
  recorded fingerprint of its download before it is installed, because fetching a
  security tool from an unpinned address would be its own weakness. The reusable
  build steps, which are third-party code running with access to the project's
  build system, are pinned to exact revisions rather than moveable labels, and a
  test enforces that this stays true.

**Status, stated plainly.** All four measures, the negative control and the
enforcing tests are **part of the released software**. They reached the released
version on 12 August 2026, after the main body of this chapter had been checked, so
this section was deliberately re-checked against the released version rather than
against a draft. The parts that need no internet connection — the image-pinning
check and the written assertions — also run in the ordinary build, so they hold on
a machine with no network access.

A reviewer does not have to take that on trust. The threshold, the permitted
reasons for an exception and the list of pinned images are written down in the
project's own supply-chain policy document, and the job that enforces them is
readable alongside it.

**The honest limits of these four measures**, in the same spirit as everywhere else
in this chapter:

- A **high**-severity vulnerability is reported, not blocked. Medium and low
  severities are not surfaced by this gate at all.
- The check for whether an upstream label has been repointed since it was pinned is
  advisory: it reports, it does not block. Re-pinning is meant to be a deliberate
  act after reading the publisher's change notes, not something done under the
  pressure of a failing build.
- The bill of materials is produced per build and published with that build. It is
  not stored in the project's source tree.
- These are safeguards on how the product is assembled. They are not a claim that
  every component is free of undiscovered flaws — no such claim is available to
  anyone.

That distinction is stated here rather than glossed, for the same reason every
other boundary in this document is stated: the value of the product is that its
claims can be checked.

---

## 10. Why this eliminates the false-alarm problem — and precisely what it does not do

### The claim

A finding exists in this system's output **because a checker fired over evidence
the system captured**. There is no path from "the tool thought so" to a reported
finding. That is a structural property, not a tuning achievement.

The result: the class of failure where a security tool reports a problem that was
never there is closed by construction — at the cost of the system reporting fewer
things, and openly marking a great deal as unproven.

The trade is deliberate and stated in the project's own doctrine: a tool that
finds real problems but also asserts things it has not established is worth *less*
than a tool that finds fewer problems and never misstates them, because the first
tool's output has to be re-investigated from scratch and the second tool's output
can be re-checked cheaply.

### The evidence for the claim

**A shipped negative control.** The system includes a reproducible self-test. It
stands up a deliberately vulnerable miniature web application on the local
machine, sends one harmless request and one probe request, and feeds the two real
answers through the checker. Pointed at that vulnerable application it produces a
confirmed finding. Pointed at a **safe twin** — the same application built the
correct way — it produces **nothing**.

This test was executed during the preparation of this chapter. The vulnerable twin
confirmed through the differential-response checker at confidence 0.971, citing
the specific observed divergence between the two answers. The safe twin returned
nothing at all. That is the negative control which demonstrates the confirmation
authority does not simply rubber-stamp whatever it is handed.

**A measured benchmark on a labelled corpus.** The project ships a signed
scorecard from a real run on its own machine. A self-contained labelled
application plants 11 known bugs and includes 5 deliberately safe controls that
must never be flagged. On that corpus the system found all 11 and flagged none of
the 5 safe controls. Three widely used incumbent tools were run against the same
application on the same machine for comparison.

The project's own reading of that table is careful, and this briefing preserves
the caution rather than the headline:

- The comparison's "false positive" column mixes two different things — genuine
  false alarms, and real detections that an incumbent made under a different label
  or at a coarser location. It should not be read as "noise a human must triage".
- The strict matching rules use this system's own vocabulary and its own location
  granularity, so its perfect score is partly a **home-field artefact**. The
  portable claim is the narrow one: every finding it reports is checker-confirmed
  and offline re-verifiable, and it flagged none of the clean controls.
- One of the three incumbents is a single-purpose database-injection tool scored
  on a multi-category board. Its score is not evidence that the tool is broken.
- This is a soundness demonstration. **It is not a claim of superiority and not a
  claim of completeness.**

This briefing does not repeat any industry-wide false-positive statistics. Figures
of that kind appear in some of the project's outward-facing documents but were
recorded in the internal verification pass as not independently verified, and they
are therefore omitted here.

### What this approach cannot do

An agency reading this must have the limits as clearly as the strengths.

**It does not find everything.** Never raising a false alarm and never missing a
real problem are two entirely different properties. Zero false alarms says nothing
whatsoever about what was missed. The system measures its miss rate separately and
reports a miss as a genuine shortfall rather than hiding it.

**A FACT is bounded, not eternal.** It describes a specific target, in a specific
configuration, over a specific observation window — the roadworthiness certificate
from section 2. A system that changes tomorrow is not described by today's
certificate. The freshness date is carried inside the signed document for exactly
this reason.

**A FACT is not a statement of business impact.** It establishes that a technical
condition held. Whether that condition matters to a particular organisation, and
how much, is a separate judgement that the system supports but does not make
mechanically.

**Each checker proves one narrow thing and refuses the rest.** The tables in
section 3 list those refusals deliberately. A checker that proves a login token is
*forgeable* has said nothing about whether the target would *accept* a forgery,
and the system keeps those as distinct categories rather than blending them into a
more impressive-sounding claim.

**Most evidence windows cannot yet say "clean".** Only 6 of 26. Everything else
can say only FACT, LEAD or INCONCLUSIVE. An agency looking for a blanket assurance
of safety will not get one from this system today, and the reasons are documented
window by window alongside the named work that would change it.

**The demotion-only firewall is not yet a universal gateway.** It is a working
layer with real call sites — the engagement run, report generation, the defensive
pipeline, the grounding critic, the refusal component and an agent tool — but it
is not the single point through which every claim in the system passes. Section 4,
stage 5 gives the detail, including the fact that the module's own internal
comment understates its current use.

**Re-execution proves a binding, not the world — and there is in-house work aimed
directly at that.** This limit needs stating carefully, because it is the one the
briefing repeats most often and the one where an agency should press hardest.

*The limit.* Where retained values were supplied by a producer rather than
captured by the system through its own authorised channel, re-running the checker
proves that the verdict follows from the evidence. It does not, by itself, prove
that the evidence faithfully reflects the live target. Put bluntly: re-execution
proves the system did not *reason* dishonestly. On its own it does not prove the
system did not *fabricate the recording*. The posture certificate states this
limit inside itself.

*The work aimed at it.* The project has built the mechanism that attacks this
limit, and its status must be described precisely. The idea is to tie a captured
answer to the specific encrypted session it arrived on, and have that pairing
counter-signed by an independent party — a **notary**, in the same sense as a
notary who witnesses a signature. What exists today:

- an evidence object that carries the encrypted session's own binding material
  together with the fingerprint of the captured answer;
- a counter-signature by a notary key over that pair;
- a live capture path that pulls the session binding from a real encrypted
  connection;
- and a standalone offline verifier, mirrored inside the vendor-free verification
  script that ships to third parties, which rejects a package with no
  counter-signature, a counter-signature from any key other than the one the
  recipient pinned out of band, answer bytes that do not match the bound
  fingerprint, or a binding taken from a different session.

What this does **not** establish, in the module's own words rather than this
briefing's: the notary in the current build is software that the system itself
runs. The system could therefore hand its own notary a fabricated pairing and have
it counter-signed. So this proves the **mechanism and the verifier shape**, not
genuine unforgeability. Genuine unforgeability needs two further things: a notary
that takes part in setting up the encrypted connection itself, rather than being
told about it afterwards; and a notary operated by an organisation independent of
the vendor. The specialist software for the first does not exist in this
environment, and the second is an arrangement between organisations rather than a
piece of software. At the exact point in the code where an independent outside
notary would connect, the project has deliberately placed a component that always
refuses, rather than a stand-in that would appear to work. The module also carries
an explicit instruction not to upgrade this to a proven fact.

*(For a technical reviewer: the first of those two is the technique family
published under the names zkTLS, MPC-TLS and TLSNotary.)*

There is one further honest point. This mechanism is not yet attached to the
ordinary evidence an everyday scan retains; it exists as a standalone capability
exercised by its own tests.

So the limit as stated stands today. But it is treated by the project as a target
to be closed, not as a permanent excuse, and a reader should ask about progress on
it rather than assume it is unattended.

**The four cloud exploitation capabilities are built and proven offline but have
not yet been fired at a live third-party account. The two cluster ones have now
been proven against a real cluster.** This is the most important honesty statement
in the chapter, and it is stated the way the project's own records state it.

Six confirmation capabilities cover this ground: capturing a cloud
instance-metadata credential; confirming that an exposed secret is still valid;
confirming cloud service-account impersonation; confirming a permission-escalation
route; and two tiers of cluster permission checking — an anonymous privileged
attachment, and a dangerous-capability or default-service-account grant. **All six
are complete and wired end to end**: the component that performs the capture, the
evidence route, the admission rules, the certificate minting, and the writing into
the system's internal map.

The four cloud ones are proven using recorded sample data standing in for a real
cloud account, and their proofs re-verify offline like any other. The two cluster
ones are proven against a **real Kubernetes cluster**: a repository script stands
up a genuine single-node cluster the system creates, owns and destroys, plants
known-dangerous *and* known-benign permission arrangements in it, captures what the
real cluster interface returns, and adjudicates those bytes through the ordinary
production path — the anonymous privileged attachment confirmed with a certificate
that re-verifies offline, and the benign arrangements in the same cluster correctly
left as leads. What that run does not cover is a scope-gated capability that
*enumerates* permission arrangements across a whole cluster, and a managed
provider's control plane such as Amazon EKS, Google GKE or Azure AKS.

What remains deferred for three of them is the act of **pointing them at a live
third-party cloud account**. That waits on the customer supplying their own
credentials — a laboratory cloud credential. The detection logic, the evidence
handling, the certificates and the safety gates are all built and proven; only the
live firing is pending, by design. The project's own note is unambiguous, and this
chapter repeats rather than softens it: there is no live fact yet for those
capabilities. Under the project's own enforcement rule — that any gap between
current and intended capability must name the engineering work that closes it, or a
test fails — none of these six carries any named engineering gap. The remaining
deferral is operational, not technical.

The permission-escalation capability must be described differently and is not
"awaiting live fire". It is a deliberate offline re-derivation over the customer's
own retained permission configuration. Never executing the escalation is the
design, not a limitation: a defensive verification checker does not carry
out the attack it is confirming.

**One capability is dormant unless enabled.** The stronger cryptographic path for
federation-document forgery only activates if the operator supplies trusted
identity-provider certificates and an optional software library is present. Full
cryptographic signature processing for that document format is explicitly out of
scope.

---

## 11. The chapter in one page

- The system speaks exactly four words about any claim: **FACT**, **LEAD**,
  **CLEAN**, **INCONCLUSIVE**. No fifth word is possible; the vocabulary is closed
  in the software itself.
- A **LEAD** is a suspicion, honestly labelled. It directs attention. It is never
  counted as proof.
- A **FACT** is a claim that a small, deliberately simple automatic checking
  program re-derived from evidence the system captured and kept — and that anyone
  can re-derive offline, with no target and no trust in the system.
- That checking program is called a **checker** throughout this briefing and an
  **oracle** in the software; **the two words mean the same program.** It is pure
  and deterministic, and has no network, no clock, no randomness and no opinion. It
  judges evidence someone else collected. It never sends anything. A missing input
  is a skip, never an assumed pass. There are 38 of them, each proving one narrow
  thing, each with written refusals.
- The **AI proposes; the checker confirms.** Evidence originating from the model is
  demoted to a LEAD even when a checker fires over it. Invented categories are
  rejected as a matter of type. Relabelling is refused at two independent points.
  The same rule binds everything else that could speak: of 33 catalogued outside
  tools only two may ever back a fact, and even then only through the system's own
  re-drive; a verdict from a second AI acting as a judge is *permanently* a lead,
  with the promotion path structurally unreachable in the code; and another
  vendor's imported report enters as labelled observations that can never become
  findings.
- A proof is **re-executed when it is used**, not read from a stored flag. A
  finding whose proof no longer reproduces is **demoted in the open**, with a
  stated reason, in the report and in the system's internal map. It is never
  quietly kept and never quietly deleted.
- **Three numbers are all called confidence, and they answer different questions:**
  the strength of the specific signal observed (capped at 0.99, threshold to
  confirm 0.70, re-executed and checked as part of the proof); the measured rate
  at which findings like this have historically turned out real (never asserted,
  switched off below eight resolved outcomes); and a competing-explanations
  assessment that names the innocent alternative and the single most decisive next
  test. **None of the three can promote anything.**
- **"Nothing is wrong" is a harder claim than "something is wrong"** — the silent
  smoke detector may simply have a dead battery — and the system treats it that
  way. Only 6 of 26 evidence windows may currently say CLEAN. The rest report
  INCONCLUSIVE rather than implying safety, and each gap is recorded with the
  named engineering work that would close it.
- **The same discipline applies to the components the system is built from.** A
  scanner's advisory match is a LEAD until a deterministic comparator re-derives it
  from a pinned advisory snapshot. The equivalent safeguards on the system's own
  build and release — fingerprint-locked components, machine images pinned to exact
  content, a published bill of materials, and a gate that stops the build on a
  critical vulnerability — are **part of the released software**, and the gate is
  itself proved capable of firing by a deliberately vulnerable sample it must
  reject.
- **What this cannot do.** Six limits, each stated in full in section 10:

  - It does not find everything. Never raising a false alarm says nothing about
    what was missed.
  - A verdict is bounded in time and in configuration. It is not a permanent
    property of the target.
  - It does not judge business impact. That is a human judgement the system
    supports rather than makes.
  - Re-execution proves that the verdict follows from the evidence. On its own it
    does not prove that the evidence reflects the live target. The countermeasure
    for that is built as a working mechanism, but its independent witness is the
    system's own software today, not an outside party.
  - The four cloud exploitation capabilities are complete, wired end to end and
    proven offline against recorded sample data, but have not yet been fired at a
    live third-party account. That waits on a customer supplying their own cloud
    credentials. The two cluster ones are no longer in that position: they are
    proven against a real Kubernetes cluster the system stands up, owns and
    destroys itself. None of the six carries any outstanding engineering work; the
    remaining deferral is operational, not technical.
  - The demotion-only firewall is a working layer with real call sites rather than
    a single universal gateway.

  All of these are recorded in the project's own files, and are repeated here
  rather than smoothed over.

---

## How the numbers in this chapter were checked

Every factual statement in this chapter was checked against the system's source
code and declaration files in the version of the software read for this briefing.
The counts below were re-derived mechanically from the code rather than copied
from documentation.

| Number | What it counts |
|---|---|
| 4 | Permitted verdicts — FACT, LEAD, CLEAN, INCONCLUSIVE |
| 38 | Kinds of checker |
| 40 | Distinct checker procedures implementing those 38 kinds |
| 15 | Checkers in the frozen core set used for an unrecognised category |
| 85 | Canonical weakness categories |
| 275 | Recognised spellings mapping onto those 85 |
| 26 | Registered evidence windows |
| 6 | Of those 26, the windows that may say CLEAN |
| 17 | Of those 26, the windows carrying named outstanding engineering work |
| 33 | Catalogued outside tools |
| 2 | Of those 33, the tools that may back a fact (`nmap`, `sslscan`) |
| 17 | Of those 33, the tools excluded outright as offensive or destructive |
| 8 | Third-party report formats the system can import as leads |
| 0.70 | The confidence threshold to confirm a finding |
| 0.99 | The hard cap on a checker's confidence |
| 0.999 | The hard cap on the learned calibration estimate |
| 8 | Minimum resolved outcomes before the learned calibration engages |
| 13 | Checker kinds for which silence is a sound negative after a fix |
| 2 | Locked lists of outside components — one for the attacking half, one for the key-holding half (section 9.2) |
| 26 and 56 | Outside components pinned by those two lists respectively |
| 9 | Machine-image references checked for content pinning — 8 pinned, 1 exempt because it is built from this project's own code |
| 5 | Permitted written reasons for excusing a vulnerability finding at the release gate; the exception list is currently empty |

The negative-control self-test described in section 10 was executed during the
writing of this chapter. The build-and-release safeguards in section 9.2 were
re-checked against the released software after the rest of the chapter was
written, because that work reached the released version on 12 August 2026.

*Version reference for a technical reviewer: the main body was read at revision
`1487e03a` of the source code; section 9.2 was re-checked at revision `dc2994d6`,
the point at which the build-and-release safeguards became part of the released
software.*
