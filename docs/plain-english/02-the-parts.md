# The Parts Of The System And How They Fit Together

This chapter explains what the system is made of. It names each part, says in plain
words what that part is for, and shows how the parts work together. It then explains
the most important design decision in the whole system: the wall that separates the
part that attacks computers from the part that holds the owner's private information
and private keys. Finally it explains what runs on whose machine, where the
information is kept, and what "self-hosted" and "sovereign" mean in practice for an
organisation that is not permitted to send its data to an outside company.

No software knowledge is assumed. Technical words are explained the first time they
appear.

---

## 0. One word you will meet on every page

The load-bearing idea in this whole product is a small program called a **checker**.

> A **checker** is a small, fixed program that looks at saved evidence and answers one
> narrow question — always the same way, with no judgement and no intelligence. It
> cannot reach the network and it cannot read the clock. Give it the same evidence
> twice and it gives the same answer twice.

The closest everyday comparison is a laboratory test. A blood sample is drawn once and
kept. The test is a fixed procedure run over that sample. The doctor's opinion is not
the result; the test is the result, and anyone with the sample and the procedure can
run it again.

The software's own name for a checker is an **oracle**, and that word appears in the
code, in some screen labels and in file names. This briefing says "checker" in the
body text and keeps "oracle" for quoted code and the glossary. They are the same
thing.

Two other phrases recur and are worth fixing now:

- **Fail-closed.** If a safety check cannot be completed — an error, an unreadable
  file, a missing answer — the result is "no". Think of a drawbridge held up by
  electricity: cut the power and it falls shut. It never falls open.
- **Deterministic.** Same input, same answer, every time, on any machine. A recipe,
  not a chef.

---

## 1. The one-page map

It helps to think of the system as an organisation with departments. Each department
has one job, a clear boundary, and a defined way of handing work to the next
department.

| Part | Think of it as | What it is for |
|---|---|---|
| **VIGIL** | The organisation itself | The whole product. One command, one record, one set of rules, covering everything below. |
| **The shared integrity core** (`vigil_core`) | The registry and notary office | The small, carefully-guarded foundation that seals records, checks signatures, and decides whether an action is permitted. Both halves of the system stand on it. |
| **CRUCIBLE** | The testing laboratory | The offensive engine. It probes a system the owner has authorised, tries real attacks against it, and refuses to call anything a vulnerability unless a checker confirms it. |
| **AEGIS** | The alarm and inspection department | The defensive twin. The same proving machinery pointed inward at the owner's own systems, to detect attacks and to prove from the target's own logs that an attack actually happened. |
| **SIGIL** | The private office | The personal, sovereign side. It holds the owner's key, keeps the owner's working record, and can act on the owner's own files and accounts. It contains no attack capability at all. |
| **STRIX** | An outside contractor | A third-party open-source hacking tool, kept inside the system in a fenced-off area. It may suggest things. It may not certify anything. |
| **The integration layer** | The operations floor | The connective tissue: the `vigil` command, the safety gates, the bridge where a suggestion becomes a proven fact, and the running loop that drives an assessment from start to finish. |
| **The gateway** | The guarded exit door | A network barrier that decides which packets are allowed to leave the machine at all. |
| **The interfaces** | The front desk | The web screens and the command line through which a human drives everything. |
| **The live-fire harnesses** | The proving ground | Not part of the running system, but part of what is shipped: two runnable scripts that point a finished capability at something real instead of at saved evidence — one at a real outside service, one at real infrastructure the project stands up and destroys — assert exactly what should and should not happen, and can be re-run by a customer or an auditor on their own machine. |

Everything in that table exists as real code in one single repository. Every claim in
this chapter was read out of that code or out of the project's own documents.

---

## 2. Why the system is split into parts at all

Most security tools are one program. That is simpler to build, and it is the wrong
shape for this problem.

The reason is a hazard that security engineers call the *confused deputy*. Imagine a
building where the same member of staff is given both the master key to the vault and
the job of testing whether burglars can get in. If someone tricks that person during
the burglary test — feeds them a forged instruction, say — the trick now reaches the
vault, because the same person holds both. The safe design is to give the vault key to
someone who is never in the building during a break-in test.

The system applies that logic literally:

- The half that attacks things **holds no owner key at all**. It physically cannot
  sign anything as the owner, so a compromised attacking program can never authorise
  itself to do more.
- The half that holds the owner key **does not contain the attacking code** — not
  disabled, not switched off, but *not installed*, so there is nothing to switch on.
- The two halves are joined by exactly one narrow channel that carries **data only**,
  never instructions.

The rest of the architecture follows from that decision. The project's internal name
for this rule is the "two-environment boundary", and its own developer handover
document lists it as invariant number one of the system.

---

## 3. The parts, one by one

### 3.1 VIGIL — the whole

VIGIL is the name of the complete product: a single body of code containing both the
offensive engine and the sovereign personal side, kept in two separate running
programs. The rule it states about itself, repeated in code comments and in the
project README, is:

> The AI and every tool only propose. Only a deterministic oracle mints a signed fact.
> Only the conjunctive gate authorises an action. Only the egress gate lets a packet
> leave.

In plain English, that sentence names four different authorities and makes clear that
the artificial intelligence is none of them:

- **"Only propose"** — the AI can suggest an action or suggest that something is a
  vulnerability. A suggestion has no weight on its own.
- **"A deterministic oracle"** — a checker, as defined in section 0. It either proves
  the finding from the evidence collected, or it does not. It is the only thing in the
  system permitted to declare a finding true. (The checkers and what each can prove
  are covered in their own chapters.)
- **"The conjunctive gate"** — a checkpoint that has to answer several separate
  questions all in the affirmative before an action may run. Any one failure stops it.
- **"The egress gate"** — a network barrier standing between the tools and the outside
  world.

A single command, `vigil`, is the entrance to all of it. It has its own built-in
actions (starting an assessment, verifying a record, exporting an evidence package,
bringing the web interface up, running a health check, and so on), and it can also pass
a command through to any of the sub-systems.

### 3.2 The shared integrity core — the notary's office

**In one line:** the small, boring, heavily-scrutinised foundation that makes records
tamper-evident and decides whether an action is allowed.

This is deliberately the smallest part of the system, because everything else depends
on it. It contains no attack code and no personal-assistant code — it imports neither —
and that purity is precisely what lets both halves share it without contaminating each
other.

What lives in it:

| Component | Plain-English purpose |
|---|---|
| The chain | Makes the record tamper-evident. Every entry carries a fingerprint of the entry before it, so altering an old page breaks every page after it — like a bound ledger with sequentially-numbered, cross-referenced pages rather than a loose stack of paper. |
| Canonical formatting | "Canonical" here means one fixed way of writing a thing down. The same information always produces byte-for-byte identical text, so a signature over it means one unambiguous thing. Without this rule, two people could sign what looks like the same document and produce different signatures. |
| The signature primitives | The standard digital-signature mathematics (Ed25519), taken from a well-known cryptography library rather than home-made. It also supports "m-of-n" signing, meaning an action needs, say, three out of five named signers. |
| The authorisation gate | The single, definitive checkpoint composition used by both halves, so there are not two subtly different sets of rules. |
| The danger classifier | The single, definitive rule for how dangerous an action is (see A0–A3 below). |
| Key storage | How private keys are stored on disk: owner-only file permissions, encrypted at rest when a vault is set up, and a refusal to quietly create a new identity if it cannot open the existing one. |
| The anti-rollback floor | A durable marker of how far the record has advanced, so an attempt to replace the record with an older, shorter version is refused. |
| Delegation, capability and entitlement objects | The paperwork of the system. A *delegation* ties the offensive side's signing keys back to the owner. A *capability* lets a named third party be granted a narrow, checkable right to re-verify a result. An *entitlement* is a signed licence deciding which of the system's dangerous powers may run at all on this machine — explained in section 3.10, because it is the answer to "what could a thief do with a stolen copy?". |

Two design choices in this core deserve highlighting because they recur throughout the
system:

1. **The running system only ever *verifies* signatures. It does not sign.** The
   ability to create signatures is confined to a separate provisioning step, run
   deliberately by the operator.
2. **Errors mean "no".** Throughout, an unexpected condition produces a refusal, never
   a permission. If the system cannot positively determine that it is allowed to do
   something, it does not do it.

### 3.3 CRUCIBLE — the offensive engine

**In one line:** the laboratory that attacks an authorised target and refuses to call
anything a vulnerability until a checker confirms it from the real evidence.

CRUCIBLE is the largest and oldest part of the system. Its working method is: crawl and
probe the authorised target, attack its inputs with genuine attack inputs, capture
exactly what the target sent back, and then hand that captured evidence to a checker
that decides. It then reasons over the confirmed facts to work out chains of attack,
and packages everything into sealed, tamper-evident evidence.

The engine is large. The tables below are the complete list of its internal
departments, grouped so they can be read rather than merely scanned. Every one of them
is a real directory of code in the repository.

**The departments that decide what is true.** These are the ones that matter most; the
rest of the engine exists to feed them.

| Department | What it does |
|---|---|
| The verification layer | The checkers themselves — the only thing that can turn a claim into a fact. In the version read for this briefing the code declares **38** distinct kinds of check (for example: proving a database was successfully manipulated, proving injected content actually executed in a page, proving a weak encryption setting was negotiated, proving a cloud permission genuinely allows escalation). |
| The veracity layer | An anti-fabrication barrier. Given a claim, it re-runs the check the claim cites and refuses to admit the claim if the check does not reproduce. It can only ever *downgrade* a claim; it has no power to upgrade one. Where it is used is described honestly below the table. |
| The world model | A persistent map of what has been observed and what is therefore reachable, where every fact carries where it came from and how confident the system is in it. |
| The confidence engine | Treats a conclusion the way a scientist treats a claim rather than the way a scanner treats a verdict: an explicit starting assumption, a ledger of evidence each weighted for how much it really tells you, a set of competing explanations that must add up to one hundred per cent, and a computed answer to "what single further observation would most change my mind?" |
| Calibration | Learning, from recorded outcomes, how much confidence a given signal actually deserves — replacing invented confidence numbers with measured ones. |

**The departments that do the testing.**

| Department | What it does |
|---|---|
| The scanner | The active attack toolkit — the crawler, the browser driver, the checks for individual weakness classes, race conditions, request smuggling, single-sign-on flaws, business-logic abuse and so on. |
| Intruder | The fuzzing engine: the second axis of testing. The scanner sends one fixed test input per weakness class; Intruder sends *many* inputs across marked positions in a request and then automatically picks out the one abnormal response. The equivalent commercial tool leaves that spotting job to a human staring at a results table; here a statistical outlier detector does it. |
| Repeater | A gated "capture, edit, resend" tool for an operator working by hand — the single most dangerous thing an operator can do manually, put behind every one of the system's safety rules. Never a raw network connection: every replay goes through the same fail-closed gate chain, the target is scope-checked twice (once by the caller, once by the executor), and every refusal is itself recorded as evidence. It deliberately does not disguise itself: the recognisable identifying label is forced on, and any operator-supplied replacement is stripped. |
| Sensors | Adapters that drive real external tools (network scanning, certificate inspection, packet capture, software bills of materials, and readers for cloud accounts and for Kubernetes — the standard software for running large numbers of containers across many machines). |
| The deep analysis arsenal | Source-code analysis: a built-in offline pattern analyser that always works, plus adapters for external analysers that are used when installed and honestly reported as skipped when not. It also builds a searchable index of every function, class, import and call site, which is the raw material the reasoning layer turns into hypotheses. |
| Defender emulation | Answers one question about the system's own actions: "if we do this, what traces would it leave, and which defensive rules would spot it?" This is what lets an authorised exercise also measure the defenders. |

**The departments that reason, remember and plan.**

| Department | What it does |
|---|---|
| The agents | A team of specialised automatic workers (reconnaissance, hypothesis generation, exploitation, adversarial critique, reporting) that communicate only by posting to a shared append-only record. |
| The reasoning kernel | The piece that turns the written doctrine into callable functions. Each function loads the relevant section of the written doctrine, asks the language model, and forces the answer back into a strict form. Its functions are: generate hypotheses, critique, pivot when stuck, decide severity, advise on operational discipline, and build a threat model. |
| The planner | Owns the shape of an engagement: a best-first search over a tree of goals, with budget enforcement, pruning of dead branches, a watchdog that bounds each step, and a checkpoint written to disk every sixty seconds so that stopping and resuming loses no progress. |
| Memory and learning | Priors carried between assessments — what tends to work against targets that look like this one. |
| Intelligence | Gathering and reconciling information about a target from permitted sources. |
| The technique knowledge graph | Turns the public catalogues of attacker techniques from prose a human reads into typed operations a planner can check and chain, with stated preconditions and effects. |
| The graph view | A rebuildable picture of the record, kept in a file, used to draw the maps on the screens. It is strictly one-way: information flows from the record into the picture and never back. It authorises nothing and can declare nothing true. |
| The self-improvement loop | Runs continuously to find what the engine missed and to draft candidate improvements. It never applies them to itself. A change reaches the engine only through a human-governed gate. |
| The knowledge engine | Reasons over vulnerability-intelligence leads and drafts proposals for the owner. A proposal authorises nothing; the owner must accept it, and accepting authorises *learning*, never the minting of a fact. |
| Evaluation | Benchmarks, regression tests and recall baselines that measure the engine against known answers. Its purpose is stated plainly in the code: self-improvement is unfalsifiable without measurement. |

**The departments that produce, package and expose the work.**

| Department | What it does |
|---|---|
| Engagement authority and the emergency stop | The two controls that bound a piece of work. The *authority* is the machine-readable form of the operator's signed permission slip: which systems are in scope, for how long, whether the target is a live system or a stand-in copy, whether destructive actions are permitted at all, and how many actions may be spent. Every action is checked against it. The *emergency stop* is a durable hard halt: once tripped, nothing further is authorised, and it stays tripped even if the program is restarted. |
| The evidence layer | Sealed evidence: certificates over confirmed findings, the hash chain, the manifest of raw files, and the packaging for offline audit. |
| Machine attestation | Produces a signed statement about the machine the engine is running on — what it is and that its own files are unaltered. Honest limit, stated in its own code: today's statement is produced in software (optionally helped by the machine's security chip). The versions that would use special processor hardware to prove the same thing more strongly are deliberately written to refuse rather than to pretend. |
| The external-tool roster | The single catalogue of the outside command-line tools the engine can drive, together with a live check of which are actually installed on this machine. The same roster is used by the installer and by the "Tools" screen, so what the screen shows and what the installer installs cannot drift apart. |
| Reporting | The generated technical report, the client dossier, per-finding "how to check this yourself" instructions, standards mapping, and the **case file** — a numbered pack of plain-English documents written for the non-specialist who receives a dossier. Described below the tables. |
| Target intake | Turns a single web address into a fully prepared engagement folder — a draft authorisation document, a draft threat model, a draft attack tree, and a fingerprint of the target's technology. It does this with a deliberately polite, capped, unauthenticated look at the public files a site publishes about itself. It never removes a gate: nothing is prepared without the operator's attested authorisation, and no active testing happens until the operator signs the authorisation document. |
| Importers | Ingest another vendor's report — from the common scanners and proxies, or a generic findings file — into the system's own map as leads. The doctrine is applied without exception: a third party's finding is marked as unverified, is never recorded as a proven finding, and becomes one only if one of this system's own checkers re-proves it. Re-importing the same report twice changes nothing. |
| The capability registry | One machine-readable catalogue over the engine's several separate rosters (sensors, internal tools, checkers, operators, commands), so an outside integrator can discover what capabilities exist, what each produces, and what permission tier each needs — without changing how any of them run. Listing a capability is not permission to use it. |
| Entitlements | The signed licence system described in section 3.10. |
| The console | The operations screen and the registry of named work sessions. |
| The programmatic interface | An optional local-only service that lets an operator's own software drive and observe the engine. It runs only if the operator starts it, answers only on this machine, and exposes no capability that is not already gated. |
| The model-context seam | A standard connector that lets other AI tools call this engine's safe capabilities, and lets this engine call out to other such tools — with every call routed through the same fail-closed gate chain. |
| Social-engineering defence | The deliberate inverse of a capability the project refuses to build. Rather than *generating* phishing, it scores messages the operator has *received* for the indicators of a social-engineering attack (urgency, credential harvesting, impersonation of authority, look-alike domains, mismatched reply addresses, demands for secrecy, dangerous attachments) and returns a weighted risk score. Its own code insists the output is a lead for a human, never a verdict, because phishing detection is inherently probabilistic. |

**One honest note on the veracity layer, because it is easy to overstate.** Some
descriptions of this component say it re-checks every claim "at every hand-off". That is
stronger than what is wired today, and this briefing does not say it. The accurate
statement, checked against the code for this chapter, is in three parts.

*First, it is genuinely in use.* It is called at seven real places in the working
software — not only in its own tests. Those places are: admitting each finding during an
engagement; rendering the report (the reporting path routes every finding through it);
the defensive pipeline; the tool surface the automatic workers use; the scanner's own
report path; the grounding critic; and the refusal path. At each of those points its
demote-only property holds: it can strip a claim of the status "fact", and it has no
mechanism at all for granting that status to a claim the checker refused.

*Second, it is not yet a single universal checkpoint.* One important path does not run
through it: writing a node into the system's internal map of the target. That path
reaches the same shared judgement about where a piece of information came from, but by a
different route, so the claim "everything crosses this one barrier" is not yet true.
Chapters 4 and 6 describe it in exactly these terms; this chapter is consistent with
them deliberately.

*Third, the component's own written comment inside the code used to be out of date* — it
described itself as connected to nothing but its tests, long after real parts of the running
system had been wired to it. That has been corrected: the comment now lists its callers, and
an automated test fails the build in **both** directions — if the retired "connected to
nothing but its tests" phrasing reappears while those callers exist, and equally if a module
that does call it is dropped from the list. The project treats a note that outlives its phase
as the same class of defect as an overclaim, because it understates what is true. Both the
overstatement and the former understatement are recorded here so that a reader who goes to
the code is not misled in either direction.

**The case file, because it is the part a reader of this briefing would actually be
handed.** A dossier already proved things; until recently it did not *explain* them. It
held a machine-readable export and a cryptographic proof bundle — exactly the right
evidence and, in the words of the code, "exactly the wrong reading material for the people
a dossier is usually handed to." The case-file builder writes the part they read. It is
generated into every dossier, and it is **nine numbered documents**, numbered so that the
reading order is obvious from the file names:

| File | What it contains |
|---|---|
| `00-START-HERE.html` | The one page to open first. It explains every other file in the archive. |
| `01-executive-summary.md` | What was done, what was found, what it means, what to do first. |
| `02-approach-and-scope.md` | How the work was done — and what was **not** examined. |
| `03-findings.md` | Every proven finding, in plain language. |
| `04-leads.md` | What was observed or suspected but **not** proven. |
| `05-what-was-looked-for.md` | Every weakness category the engine can confirm, and this run's position against each. |
| `06-what-to-do.md` | The remediation order, prioritised. |
| `07-verify-it-yourself.md` | The exact commands to re-check the result, and what a pass and a failure look like. |
| `08-glossary.md` | Every technical term used anywhere in the dossier. |

Every one of the nine is written on every build, including when it has nothing to report,
because "a document that says 'none' is information; a missing document is a gap the reader
has to wonder about."

Three rules run through the whole pack, and they are the same doctrine as the rest of the
system: *meaning before mechanism* — every section opens with what something means for the
organisation and only then how it works; *say the limits out loud* — a proven finding states
what it proves **and** what it does not, and a section on what was tested is followed
immediately by what was not; and *never assert what was not measured* — where a value was
not recorded, the documents print "not recorded" rather than a plausible-looking figure.
The builder is a pure calculation over the run's own recorded facts: no clock, no
randomness, no reaching out to anything.

Four supporting modules do the work behind it, and one of them carries the most important
honesty control in the pack:

- **The catalogue** answers the question a list of findings cannot: three findings out of
  three categories examined is a very different document from three out of ninety. It is
  derived **from the engine's own registry of weakness categories**, not from a
  hand-written list, so a category added to the engine appears on the next build and one
  removed disappears. Its status column has exactly three values — *confirmed*, *reported*
  (a lead), and *not recorded*. There is deliberately **no "examined and found clean"
  state**, because the run record does not support one: a scan writes down what it found,
  not the list of checks it attempted. Inferring "examined and clean" from an absence would
  convert a gap in the record into an assurance, which the code names as "the single most
  dangerous thing a security document can do." The missing capability is written down as a
  specific, fixable gap rather than left vague.
- **The plain-language vocabulary** holds one shared set of sentences translating the
  engine's internal terms, so the finding write-ups and the catalogue cannot describe the
  same category two different ways. Its descriptions are generic, long-established
  knowledge about a *kind* of weakness, and the documents keep that strictly apart from
  what was demonstrated on the system examined. Where no description is on file it says so
  and reproduces the engine's own wording rather than inventing a friendlier one.
- **The run facts** module reads only what the run actually wrote — start, finish,
  duration, settings, and what those settings mean was *not* covered. Anything with no
  recorded source is printed as "not recorded"; nothing is estimated or back-calculated.
  Times are in UTC and labelled as such, because the recipient of a dossier is often in a
  different country from the machine that produced it.
- **The authorisation reader** locates and reports the engagement charter — who authorised
  the work, which systems, what was out of scope. The rule it enforces is that a missing
  charter must be *stated*, never omitted: "a dossier without this section documents
  activity that a lawyer cannot distinguish from an attack."

An operator may attach a human name to a run — "Acme, Q3 external review" — and that name
appears as the title of these documents in a pack built afterwards. It is presentation only:
it is stored in one side-car file of its own, and there is no code path from it to a
certificate, an evidence digest, the sealed proof bundle or the signed record. The pack's own
list of hashes covers its documents, titles included, so a pack rebuilt under a new name is a
different file — but the proof inside it, and every certificate already delivered, re-verify
to exactly the same result.

CRUCIBLE is driven from the command line and currently exposes **31** sub-commands.
When an AI model operates it, it does so under a written standing doctrine — a
constitution for the operator persona, held in the repository as a document, covering
authorisation, evidence discipline, honesty about uncertainty, and hard stops.

### 3.4 AEGIS — the defensive side

**In one line:** the same prove-don't-guess machinery, pointed inward at the owner's
own systems.

AEGIS is not a separate application. It is CRUCIBLE's instruments turned around. It
exists in three places, with three distinct jobs:

1. **An embeddable detection library.** Software an organisation can place inside its
   own AI-powered application to detect attacks against that application. It processes
   incoming activity, looks for signals, and only issues a "confirmed" verdict when a
   checker fires and the anti-fabrication barrier re-admits the result.

2. **A detection-engineering department.** Tools for writing and assessing detection
   rules, modelling which log sources exist, and reporting where coverage has gaps. Its
   own code states plainly that its built-in rule set is "a sensible baseline of
   well-known detections, not a claim to model any specific product" — it does not
   pretend to replicate any particular commercial monitoring system.

3. **The Detection Mirror.** The most distinctive piece. For an offensive action the
   system just performed, a matching defensive checker reads the *target's own logs*
   and proves that the attack is visible there. The output is not an alert; it is
   a signed certificate that a third party can re-check offline.

Three honesty constraints are written into the AEGIS code itself, not just its
documentation, and an agency reader should know them:

- **A verdict of "clear" does not mean "safe."** It means no checker fired and
  the signals were below the threshold. The design document says so explicitly.
- **Every detection proof ships with a "benign twin"** — a legitimate look-alike
  activity that must *not* trigger it. If the benign twin triggers, the work is blocked
  from release. This is a false-alarm control built into the development process.
- **Only some areas can currently be proven.** The embeddable library can confirm four
  classes today:

  | Class | What it means in plain words |
  |---|---|
  | System-prompt disclosure | The application was tricked into revealing the hidden written instructions that govern its behaviour — the equivalent of a member of staff being talked into reading out their standing orders. |
  | Prompt injection | Instructions were smuggled into the application inside ordinary-looking content, so that the application obeyed the attacker rather than its owner. |
  | Automated access | The traffic came from a program pretending to be a person. |
  | Credential stuffing | Someone tried large numbers of username-and-password pairs stolen from elsewhere, hoping some are reused here. |

  Everything else the library reports is a lead. For the Detection Mirror, two planes
  are proven — the network edge (reconnaissance and injection, from access and flow
  logs) and authentication telemetry (from the authentication log). Other planes —
  outbound command-and-control traffic, identity directories, cloud audit trails, and
  session phishing — are honest placeholders with no ingested telemetry and therefore
  no proof. This is stated in the code, not only in the marketing text.

  A note to prevent an apparent contradiction later in this briefing: those four
  classes belong to the **embeddable library**. AEGIS also ships an inline protective
  gateway that sits in front of an application, and that gateway has its own, larger
  set of provable classes. The defence chapter lists them. Different surfaces,
  different lists; both are honest.

### 3.5 SIGIL — the sovereign, personal side

**In one line:** an assistant that runs on the owner's own hardware, remembers the
owner's work in a tamper-evident record, can act on the owner's own files and accounts
under strict permission tiers, and contains no offensive capability whatsoever.

SIGIL is the part that holds the owner's private key. It is the "private office" of the
organisation: it keeps the books, drafts the correspondence, and files the findings —
and it is never in the room when an attack test is running.

Its main pieces:

- **The record ("spine").** An append-only, hash-chained, signed log of the owner's
  working history. "Append-only" means entries can be added but never edited or erased.
  Nothing is edited; a correction is a new entry that supersedes the old one, and the
  old one remains visible. Answers cite the exact record entry they came from. The
  project calls this record the *spine*, and that word is used throughout the briefing.
- **The WARDEN kernel.** A small program written in Rust — a language chosen for
  predictable, safe behaviour — whose only job is to classify how dangerous a requested
  action is. It is the classifier of record. A second, byte-for-byte faithful copy of
  the same logic lives in the shared core so both halves classify identically, and the
  two copies are pinned to a shared set of test cases loaded by *both* so they cannot
  silently drift apart.
- **The permission tiers, A0 to A3.** Every action is placed in one of four bands:

  | Tier | Meaning | What happens |
  |---|---|---|
  | **A0** | Observe or answer only — read, search, list, view | Runs automatically |
  | **A1** | A reversible internal change — write a note, a draft, a report | Runs automatically, and is logged |
  | **A2** | Externally visible or semi-reversible — send, publish, upload, export | Queued for the owner's approval |
  | **A3** | Destructive, financial, or security-sensitive — delete, pay, touch keys, credentials, firewalls, production | Explicit approval required, never automatic |

  Two properties matter. First, classification is by whole words, not fragments, so
  "overwrite" is not mistaken for "write". Second, **anything the classifier does not
  recognise falls to the strictest tier**. Unknown means dangerous.

- **The signed governance ledgers.** Five kinds of record, appended to the same
  tamper-evident history, decide the live state of the system's own controls: whether the
  emergency stop is engaged, which assistants have been promoted to act with less
  supervision, which capabilities are switched on, which devices are permitted to approve
  things, and what each machine in the owner's mesh declares it can do. Each is signed by
  the owner, and the newest record wins.

  That last property carried a defect worth describing, because it is a good illustration
  of a class of problem signatures alone do not solve, and it was closed. An *old* record is
  still a genuinely signed record. Re-appending one verbatim would therefore resurrect a
  state the owner had since revoked — a promotion that had been withdrawn, a capability that
  had been switched off, a device that had been de-authorised — and every check the system
  had would pass, because the signature really is the owner's and the chain really does
  extend cleanly. Each of the five now carries the moment it was issued **inside** the signed
  material, so it cannot be re-stamped, and each keeps a high-water mark of the newest record
  it has honoured. A record at or below that mark is ignored as a replay.

  Two details show the care taken. Only the *dangerous* direction is guarded: engaging the
  emergency stop, disabling a capability, withdrawing a promotion and revoking a device all
  carry a fixed lowest value and are honoured exactly as before — because putting a freshness
  guard on a fail-*safe* direction would turn it into a fail-*open* one, where an attacker
  could suppress a revocation by replaying nothing at all. And the freshness value is parsed
  defensively even though it is signed, because a signature makes a value authentic, not
  sane: a "not a number" would poison the guard permanently, so it and infinity are both
  mapped to the bottom rather than trusted.

- **The agent mesh.** A set of specialised assistants, each with a permanent ceiling on
  how dangerous an action it may ever take. They include a memory archivist, a
  monitoring watcher, a personal-operations assistant that produces a daily brief with
  every line cited to a record entry, a communications assistant, a background coding
  assistant, a researcher, a defensive posture checker for the owner's own
  infrastructure only, a files-and-terminal operator, and an account manager for the
  owner's own accounts.

  Several of their limits are structural rather than promised. The communications
  assistant has no method that transmits anything — there is deliberately no "send"
  function in it, so it can only ever produce drafts. The coding assistant never pushes
  code and runs the tests before claiming it is finished. The researcher demotes any
  claim that does not verify word-for-word against its cited source. The posture checker
  works only from an allow-listed inventory of the owner's own assets and refuses
  anything else. Two of these assistants — the communications one and the account
  manager — are on a permanent no-promotion list in the code, meaning no amount of
  accumulated trust can ever let them act without a human.

- **The sovereignty guard.** A function that runs when SIGIL starts and raises an error
  if any offensive module has been loaded into the process. It is described further in
  section 5.

### 3.6 STRIX — the vendored third-party agent

**In one line:** an outside contractor's tool, kept in the building, allowed to make
suggestions, not allowed to sign anything.

**What "vendored" means.** A vendored component is a copy of somebody else's software
kept inside this one, with its original licence and credits intact, rather than
downloaded fresh each time it is used. Keeping the copy means the operator knows
exactly what code they are running and can inspect it; it also means the operator, not
the original author, controls when it changes.

STRIX is an existing open-source autonomous hacking tool (Apache-2.0 licensed) that has
been copied into the repository this way. It is not a VIGIL invention and the project
does not present it as one.

**What it actually does.** STRIX is an AI agent that works the way a human penetration
tester works, in a loop: it thinks, it picks one of a fixed set of tools, it uses the
tool, it reads the result, and it goes round again. Reading its code, the tools
available to that loop are: a driven web browser, a connection to an intercepting proxy
that records web traffic and can replay it, a command shell, a note-taker, a to-do list,
a "spawn a helper agent" facility, a code-patch applier, a report writer, a web search,
a skill loader that pulls in written playbooks, an image viewer, and an explicit "I am
finished" signal. That set is why it can be pointed at either a running website or a
body of source code.

**Where it runs.** Inside a container — an isolated, disposable software box — built
from a Kali Linux image preloaded with the standard security tools. Each engagement gets
its own throwaway container. Its only route to the network is through the gateway
described in section 3.8. Its ability to rewrite its own network rules is removed.

**What is in that box.** The image recipe was read for this chapter. It installs a
working penetration-testing bench: tools that map a network and its open services; tools
that walk a website and list its addresses; a template-driven vulnerability scanner and
its template library; a database-injection tool; a web-application scanner; a
web-interception proxy; tools that hunt for hidden files and undeclared web-form
parameters; a tool that identifies protective front-ends; two tools that hunt for
credentials accidentally left in source code and in repository history; a
container-and-dependency vulnerability scanner; source-code analysers, including a
general pattern analyser, a Python-specific one, and two syntax-tree search tools; a
tool for tampering with web login tokens; a scriptable browser; and the ordinary
command-line utilities a tester uses to read files and sift text. Nothing in that list
is a VIGIL invention; the value VIGIL adds is the fence around them and the refusal to
treat their output as proof.

**How an operator reaches it.** Typing `vigil strix …` routes the request into the
offensive environment and starts the tool there. That routing is done by a small,
fixed lookup table, so this verb can never resolve into the environment that holds the
owner's key (section 5.3).

**Two different ways to look at source code, and they are not equivalent.** The system
can read a body of source code by two separate routes, and a reader — or an operator
choosing an option on a screen — should know which one they are getting.

- **The engine's own analysis arsenal** (listed in section 3.3) runs inside CRUCIBLE. It
  applies a built-in offline pattern analyser, optionally hands the code to external
  analysers when they are installed, and builds a searchable index of every function,
  class, import and call site. Its results feed the engine's hypothesis machinery.
- **STRIX's own codebase mode** runs inside the container described above: the agent is
  pointed at a local folder or a code repository and reads and reasons over it with the
  loop described above. This is the route behind the "Scan a codebase" option in the
  assessment wizard, whose own on-screen wording names the tool.

The trust properties differ, and that is the point. The first path can feed a checker.
The second produces leads only, for the reason given next.

**The honest caveat, stated in the project's own deployment guide, is important enough
to repeat verbatim in substance:** STRIX output is **leads, not proven facts**. The
guide instructs the operator to treat STRIX results as investigative leads to confirm,
not as proven findings.

*Why* that is so, in plain terms: the promotion path that turns a suspicion into a
signed fact runs over CRUCIBLE's own retained evidence records — the exact request and
response bytes, kept in the shape a checker can be re-run over. STRIX's agent loop
produces free-form narrative output that is not captured in that shape, so there is
nothing for a checker to re-fire over. Rather than pretend, the system declines to
promote it. That is the doctrine applied to a component the project did not write.

**But a lead is not a dead end, and this is where STRIX earns its place.** There is one
specific route by which STRIX's work can reach the standard of proof, and it does not
involve trusting a word STRIX says. The distinction is between STRIX's *narrative* — its
account of what it did and what it concluded, which nothing can re-check — and a
*demonstration*, meaning a small script that actually performs the attack. A narrative
can only ever be a lead.

A demonstration is different, because when it runs, VIGIL's own capture machinery records
the raw exchange with the target: the actual bytes sent and the actual bytes that came
back. Those bytes are attached by the capture path and never by the model, and it is
their presence that makes the attempt eligible for proof at all. They are then handed to
a checker, exactly as any other evidence would be. The code makes the separation
explicit: the evidence a fact rests on is assembled *only* from captured bytes, and
anything whose origin is the language model is refused as a basis for a fact by a rule
written into the module rather than left to the caller.

Three outcomes are possible, and the operator sees which one occurred:

| Outcome | Plain meaning |
|---|---|
| **Fact** | A checker fired over the captured bytes of the reproduction, the weakness class is one this system has a checker for, and the evidence came from the capture path rather than the model. Only this outcome crosses into the signed record. |
| **Lead** | The demonstration did not reproduce, or the weakness class has no checker, or the material was not in a re-checkable shape. This is recorded as an honest failure to prove, not quietly dropped and not quietly upgraded. |
| **Denied** | The demonstration script itself contained content the system refuses to handle — techniques for evading detection, for persisting on a machine, for destroying data, for spreading itself, or for exfiltrating credentials. It is screened out first, set aside in quarantine, and never minted, shown or replayed — *even if the checker would have fired*. A dangerous "proof" is not stored merely because it is true. |

The operator sees these on the "Proof Studio" screen, one card per attempt, with a count
of how many became facts, how many stayed leads, and how many were refused. So the
division of labour is: STRIX may be creative, and the deterministic machinery decides
what is true — the same rule this system applies to its own AI.

**One further note on the safety gate around it.** The most dangerous thing
inside STRIX is its command shell, because a shell can run anything. VIGIL attaches
its own permission gate to that shell; the gate is on by default — turning it off
requires an explicit setting — and the attachment itself fails closed. If anything
goes wrong while attaching the gate, the run **stops**, with an error naming the gate
as the reason, rather than carrying on with an ungoverned shell. A wiring fault is
treated as an accident, not as permission. There are exactly two ways a run proceeds
without the gate, and both are deliberate: the explicit setting that switches it off,
and running a bare copy of STRIX on its own, outside this system, where there is no
governed run to protect and the vendored copy is meant to behave exactly as its
authors shipped it. Chapter 8, section 4.5 sets this out in full.

### 3.7 The integration layer — the operations floor

**In one line:** the connective tissue that turns a pile of capable components into one
governed running system.

This is where the `vigil` command lives, and where the safety machinery sits.

A word that appears repeatedly below: a **seam** is the single joint where two parts
meet. Naming a seam is a design commitment — it means everything crossing between those
two parts must pass through that one place, where it can be checked, rather than through
a hundred informal connections nobody can audit.

| Area | Plain-English purpose |
|---|---|
| The reasoning loop | Drives an assessment step by step. It reads the AI's proposed next action, interprets it fail-closed (a malformed instruction becomes the *safest* possible action, never a dangerous one), routes it through the gates, and treats every claim of success as a lead until a checker re-fires over the captured evidence. |
| The phase machine | The rule that an assessment moves through named stages — looking, mapping, testing, confirming — and that each stage has its own permission ceiling. Moving up a stage is not something the AI can do for itself: it needs a signed operator approval. This is what stops a run that began as a polite look-around from drifting into an attack because the model talked itself into it. |
| The usage-attestation ledger | The answer to "who used this tool, when, and against what". Before an engagement or a gated action may proceed, the system writes a signed, tamper-evident entry naming the operator (their login, their configured identity, the fingerprint of their key, and the machine name), the action, the target, and the time. It is fail-closed: no entry, no run. The recorded time carries a counter that can only ever go forward, so an entry cannot be back-dated. |
| Input safety | The boundary for untrusted text. Anything an attacker could have influenced is wrapped and marked as inert data; a non-disableable hard block refuses categorically forbidden targets; a pre-filter guards against tricking the system into fetching a forbidden internal address. |
| The tool boundary | Every tool call is subordinated to a chain: which phase of the assessment are we in, what danger tier is this tool, and what does the gate say. An unregistered or out-of-phase tool is refused before the gate is even asked. |
| The gates | The conjunctive gate, the offensive-tool tier gate, and the multi-person destruction gate. |
| Challenge checkers | The defence against a replayed or invented proof. Each confirmation issues a *fresh random secret* and accepts the finding only if the live target's response contains that exact secret. A recording of an earlier test, or an answer a language model made up, cannot satisfy a challenge it has never seen. The verdict itself is cryptographically bound to the specific challenge, so no other component can forge a "verified" stamp. |
| The truth bridge | The single, specific place where a proposal can become a signed fact — and only if the weakness class has a checker *and* that checker fires over the retained evidence. |
| The inert seam | The one narrow channel between the offensive side and the sovereign side (section 5.3). |
| Fireteam | The project's name for governed parallel workers — several specialist helpers running at once. Each is capped below the destructive tier, cannot raise its own cap, cannot authorise its own dangerous tool, and all their writes to the record are funnelled through a single writer so the signed chain is never interleaved. An over-cap request becomes a queued escalation that only a signed operator approval can release. |
| The AI-gauntlet | Drives the established open-source tools for red-teaming AI systems, and routes each result by how it was judged. A result judged by a deterministic rule is re-executed by a challenge checker and can become a signed fact. A result judged by *another language model* is **always** a lead and can never be promoted, no matter how confident the judge was. This is the system's central rule applied to a model acting as a judge. |
| Governed files, jobs and traffic | The mechanism behind the file-and-terminal assistant's promises. A path can never escape its sandbox: the code walks the directory tree opening one level at a time and refusing to follow signposts, so a shortcut file swapped in at the last instant cannot redirect a write. Every file change is a signed, append-only, reversible record with before-and-after fingerprints. A backgrounded job re-checks the tool's permission before it runs, so backgrounding cannot be used to escape a refusal. Captured web traffic is read-only. |
| The knowledge tools | A searchable corpus of offensive tradecraft, a loader for written playbooks, and a spending meter. None is an authority: every retrieved passage is wrapped and marked untrusted, because a knowledge base is a route by which an attacker could plant instructions; a playbook grants no permission; and the spending meter can only slow things down, never decide what is true. |
| The reasoning-chain record | A structured, reversible record of the whole reasoning conversation, which can be shortened over time without deleting anything: a summary is a *new* entry that cites the exact range of original entries it covers, and the originals stay. Summaries are permanently tagged as summaries and can never be mistaken for facts. |
| Channel binding | Work aimed at the system's most-stated residual limit — see below. |
| Remediation and auto-patch | Proving a fix. The system signs "remediated" only after the original attack proof is re-run against the fixed system and comes back silent. |
| Proof of posture | The signed *negative* — a certificate that a specific weakness class was checked on a specific surface and was not found, with an explicit statement of what was and was not covered. |
| Offline certificates | The transparency log, external timestamping, witness co-signatures, and the standardised statement formats that let an outside party check a result without trusting the operator. |
| The detection sentinels | The working parts of the Detection Mirror (section 3.4): fixed tests that read the logs the protected systems really produced and prove that an offensive action is visible in them. The sentinels only read; they wield no tool and send no traffic. Their output is a signed certificate that re-checks offline, never an alert. The honest bound stated in section 3.4 applies here: only two kinds of log are proven today, and the rest are marked as placeholders with no data behind them. |
| The attack-chain memory | A picture of how findings link into chains, built only from the signed record and kept strictly separate from it. It marks confirmed and merely-suspected items differently; a refuted lead is retired rather than deleted, so the history of what was believed remains visible. Nothing read out of this picture can grant a permission or create a fact. |
| Telemetry and tracing | An emit-only operational record of what the engine did and how long it took, tied to the identity of the signed record entries so an operator can follow a trace and an auditor can follow the record and the two line up. Two events are first-class: every refusal by the permission gate, and every confirmation or refutation by a checker. |
| The brain slot | A socket into which a different reasoning engine can be plugged. The code states its own limits: a plugged-in reasoning engine is propose-only, computes no facts, self-authorises nothing, and touches no network. |
| The live network transport | The real network connection through which the cloud and exposed-secret confirmations reach the outside world — and, until recently, the missing piece. Each of those confirmations was written against a *seam*: a named joint where a real connection would be plugged in. For a period the only thing ever plugged into that joint was a stand-in used by the tests, which is exactly why none of those confirmations had ever fired against a real provider. This is the real binding, and it is described in its own right below the table. |
| The live layer | The unified running engine and its connectors to real tools, real gates, the real record, and the optional external services. |

**A note on the live network transport, because it is the difference between "built" and
"has actually fired."** Several of the system's cloud confirmations depend on facts about
the *connection itself* — was the encryption genuinely verified, could anything have sat
in the middle, which machine actually answered. A checker refuses to confirm unless those
facts hold. The defining rule of this component is that every one of them is **derived
from the connection, never asserted**:

- **Encryption verified** counts as true only when the request was an encrypted one, the
  connection really carries an encryption session, that session yields a certificate from
  the far end — which a computer only produces when the certificate chain was actually
  validated — and the local settings really are set to validate. Any step that cannot be
  established makes it false.
- **No intermediary** is recorded only when the software can be positively shown unable to
  have one: it was built to ignore the machine's ambient proxy configuration entirely and
  carries no proxy routes of its own. "We could not tell" is recorded as *there might have
  been one* — the honest negative that makes the checker refuse.
- **A redirection is reported, not followed.** Being sent somewhere else is evidence about
  the target, not an instruction to chase.
- **The far end's address is read from the live connection** while the answer is still
  arriving, rather than looked up again afterwards. A second look-up can return a different
  address than the one the bytes came from, which would be evidence about the wrong thing.
- **The answer is read up to a fixed limit**, and an over-long one is marked as cut short
  and is never interpreted. Half an answer cannot honestly establish an identity, and a
  partial reading would be evidence about bytes the system does not have.

Every field fails to the value that makes the checker **refuse** rather than the value that
lets it fire. Where a credential must be used to make a confirming call, it is bound into
the connection through a factory the runner calls with the exact secret it fingerprinted,
so the fingerprint stamped on the confirming call cannot silently describe a different
credential from the one that authenticated. The connection also identifies itself with a
fixed, recognisable label naming this as an authorised owner-test, so the operator — and
the provider — can find exactly this traffic in their own logs. There is no rotation and no
disguise.

**A note on channel binding, because it addresses a limit this briefing states
repeatedly.** Re-running a checker over saved evidence proves that the verdict follows
from the evidence. It does not, by itself, prove that the evidence is what the target
really sent — a dishonest producer could in principle have fabricated the saved
response. The channel-binding work attacks exactly that: it ties the saved response
bytes to one specific encrypted session with the target, and has an independent notary
co-sign the pair, so an outside checker can confirm the bytes came from the target
without trusting the producer at all. Honest status: the mechanism and the
producer-free offline verifier are built and tested; the notary's *independence* is a
deployment assumption, not something software can prove.

### 3.8 The gateway — the guarded exit door

**In one line:** a barrier that decides whether a packet is allowed to leave the
machine at all, standing outside the reach of the software it is containing.

It works in two layers over one shared list of forbidden destinations:

- **A deny-by-default host firewall.** From the sandbox, everything is dropped except
  two destinations: the gateway's own forwarding proxy and the gateway's own name
  resolver. Because there is no direct route out, an agent that changes its own settings
  to bypass the proxy gains nothing — the packets are dropped by the host regardless.
- **A filtering forward proxy.** For each connection: the destination must be inside the
  authorised scope; the name is resolved once; if *any* address it resolves to is on the
  forbidden list the entire connection is refused; and the connection is then pinned to
  the exact address that was validated, so the destination cannot be swapped after the
  check.

The forbidden list has two tiers. One is **hard**: the machine's own internal address
range, the neighbour-only range that includes the address cloud providers use to hand
out credentials to their own machines, broadcast and reserved ranges, and their
next-generation equivalents including the disguised forms that wrap an old-style
address inside a new-style one. The code states the reason plainly: an authorisation
document cannot re-enable these, because listing them is far more likely to be an
injection or a mistake than a genuine intention to let the agent read the host's cloud
credentials. The second tier is **conditional**: private internal networks are denied
unless the exact address appears in the authorisation.

### 3.9 The interfaces — how a person drives it

There are **three** distinct web interfaces in the repository plus **one** vendored
terminal interface. A reader who assumes "the interface" is a single thing will be
wrong.

Before the table, one address needs explaining, because it appears throughout this
chapter and the next:

> **`127.0.0.1` means "this computer and no other."** It is the address a computer uses
> to talk to itself. A machine anywhere else on the internet cannot reach it. The number
> after the colon — `:8770`, `:8787` — is simply which door on that machine to knock at,
> so that several programs on the same machine can each answer separately.

| Interface | What it is | Where it listens |
|---|---|---|
| **VIGIL COMMAND** | The primary product interface: a single application of 29 screens covering assessment, live monitoring, findings, proof, reports, fixes, defence, approvals, charter, keys, tools, system status, compliance, assurance, governance, the engagement library, trust centre, manual, and knowledge. | Served by the `vigil up` reverse proxy at `127.0.0.1:8770` |
| **The CRUCIBLE operations console** (older) | A 22-screen console from an earlier generation, still present and still served when the console is hit directly. It began as a purely read-only view; it has since gained a set of operator action buttons (see the note below). | `127.0.0.1:8787` |
| **The SIGIL cockpit** (older) | A single minimal page from an earlier generation. | `127.0.0.1:8733` |
| **The STRIX terminal interface** | The vendored third-party tool's own text interface. | The terminal |

**On the older console's actions.** Its own module description still calls it
"read-only", which is now only half true, and an agency reader should have the accurate
picture. It today carries **33** operator action routes. What they do is
tightly bounded, and the code says so: launching an assessment hands the request to the
*same* gated command-line machinery a hand-typed engagement uses, spawned as a separate
program; it cannot widen scope (scope comes from the signed authorisation document and
is never passed in from the screen); a remote engagement without a signed authorisation
is refused; re-verifying a report is pure recomputation over retained evidence and sends
no traffic; and the console can *trip* the emergency stop but deliberately has no way to
*clear* it, because clearing must be a deliberate act elsewhere. Every action route also
refuses a request that did not come from the console's own page in the operator's
browser, and the console will not serve any of its programmatic addresses without a
credential at all — there is no configuration, not an unset variable and not a blank one,
under which that requirement switches itself off.

Two of the thirty-three are the newest and are worth naming, because they are an
instructive example of the system's own rule applied to something as mundane as a name.
The console keeps an **engagement library**: the list of past jobs, so an operator coming
back months later can find work by a human name — "Acme, Q3 external review" — rather than
by a machine identity such as `20260812-143355-118`. Those two routes attach that name to
an engagement or to a single run. The name is stored in one side-car file of its own, keyed
by the unchanged machine identity, and nothing in that code path writes into a run folder,
an evidence certificate, the sealed proof bundle or the signed record. Renaming therefore
writes exactly one file and rewrites nothing that already exists, so every proof already
delivered still re-verifies to byte-identical results. A run's name has one deliberate onward
use: a dossier downloaded after that run is renamed is titled by the human name, which changes
how the pack reads and nothing about what it proves. The human name is presentation; the
identity and the proof are untouched.

**An honest note on the version read for this briefing.** The project's own packaging
contract says the unified 29-screen interface should also be copied into the two older
interfaces' directories. In the version read here, that copy has not happened — a change
that did it was added to the released software and then withdrawn again, because it
broke the sovereign side's tests. The practical consequence: the 29-screen interface is
reachable **only** through the `vigil up` command. Opening the console or the cockpit
directly gives the older interface instead.

The command line is the other way in. Beyond the `vigil` command itself there are
dedicated commands for the offensive engine, the defensive side, the gateway, the
sovereign side, and the vendored tool — each of which, when invoked through `vigil`, is
routed to the correct isolated environment automatically.

### 3.10 Entitlements — why possessing the software is not possessing the capability

Every government buyer of an offensive tool asks the same question: *if this software is
copied, stolen, or walks out of the building on a laptop, what can the thief do with
it?*

The system has a direct answer, and it is a genuine part of the design rather than a
policy document. The engine's most dangerous capabilities do not run merely because the
code is present on the disk. They run only against a signed licence — the project calls
it an **entitlement** — which must be:

- **threshold-signed** by a named governance group (several signers, of whom a set
  number must agree);
- **host-bound**, meaning it names the machines it is valid on;
- **unexpired**, with a validity window;
- **unrevoked**, checked against a revocation list.

A copy of the code with no matching entitlement yields only what the project calls the
*safe baseline core*.

There are **11** gated capabilities arranged on a ladder of **4** clearance levels. A
higher level permits everything a lower one does, plus more:

| Level | Capability | Plain meaning |
|---|---|---|
| Baseline | Core reasoning | Think, plan and write — the cognitive functions. Always available. |
| Baseline | Passive intake | Look at what a target publishes about itself, politely and without attacking. Always available. |
| Standard | Active reconnaissance | Actively probe inside an authorised scope. |
| Standard | Autonomous planning | Run the goal-tree planner rather than being driven step by step. |
| Standard | Defensive response | Let the AEGIS protective gateway actively *block* a proven attack rather than only report it. |
| Offensive | Exploit execution | Actually attempt an exploit for a single hypothesis. |
| Offensive | Deep static analysis | Run the white-box source-code arsenal. |
| Offensive | Defender telemetry | Score what traces the system's own actions would leave. |
| Advanced | Full-chain exploitation | Chain multiple weaknesses into one attack path. |
| Advanced | Defender evasion | Human-authored evasion work. |
| Advanced | Self-improvement merge | Authority to fold a proposed engine improvement into the engine. |

The evaluation order when a deployment is enforcing is fail-closed and first-failure-wins:
check the signatures, then the validity window, then the machine binding, then the
revocation list, then whether the licence actually grants the capability being asked
for. Denial raises an error that cannot be silently swallowed. The two baseline
capabilities are always available, even when an entitlement is present but invalid — the
safe core never depends on a licence.

**The honest status, which matters.** Enforcement is **not** switched on by default. If
no governance trust root has been provisioned on the machine and the enforcement setting
is unset, enforcement is *inactive*: the baseline runs, gated capabilities are permitted,
every such grant is written to the log as a warning, and the system reports itself as
ungoverned. This is deliberate, so that a development copy works without ceremony. It
means an agency deployment that wants the "a stolen copy is inert" property must
provision the trust root, or set the enforcement flag, as a deployment step. The
interface shows which state the machine is in, labelled "governed" or "ungoverned".

### 3.11 The live-fire harnesses — the parts that prove the parts

**In one line:** two runnable scripts that point a finished capability at something real —
one at a real outside service, one at real infrastructure the project stands up and destroys
— assert exactly what should and should not happen, and can be re-run by anyone.

Most of what a security product claims about itself is proven against *recorded sample
data* — realistic material written by hand, standing in for the real thing. That proves the
logic. It does not prove that the capability has ever touched a real system. These two
scripts close that distance, and they are deliberately built as **proofs rather than
demonstrations**: every expectation in them is asserted, and the script exits with an error
if any one of them fails.

There are exactly two of them in the repository today, both under `tools/livefire/`, and
each is a shell script paired with a program:

| Harness | What it fires at | What it proves |
|---|---|---|
| Kubernetes access control | A real single-node Kubernetes cluster the script itself creates, in a container reachable only on this machine's own address, and destroys afterwards | Both Kubernetes confirmations, over bytes a real Kubernetes interface produced |
| Exposed-secret validity | The real, public `api.github.com`, using the operator's own credential against the operator's own identity | The GitHub row of the exposed-secret confirmation, over bytes the real provider returned |

**The Kubernetes harness.** It downloads and starts a real cluster, waits for it to become
ready, plants four access rules in it — one genuinely dangerous and three benign — captures
what the real interface returns for each, and puts those real bytes through the ordinary
production path. Then it destroys the cluster. Two engineering details are worth naming
because they are what separate a proof from a demonstration. First, it does not merely
report; it *asserts*, and any deviation is an error. Second, it **refuses to draw a
conclusion at all** until the cluster has finished assembling its built-in roles: those
roles' permissions are not written into the object, they are filled in by the cluster
shortly after start-up, and reading one too early returns an empty rule list. An empty rule
list would make the most important control pass for entirely the wrong reason — because
nothing was read, rather than because the control held. Section 8 sets out what the four
planted rules were and which were confirmed.

**The GitHub harness.** It drives the real capture machinery over the real network
connection described in section 3.7, against the least-privileged call the provider offers:
"who am I?", which reads an identity and changes nothing. Four things happen in a single
run: a valid credential is confirmed and its certificate re-verifies with no network; a
bogus credential of the *same shape*, sent live to the same real address, is answered by
the provider itself with a rejection and correctly remains a lead — the difference between
looking like a credential and being one, measured against the real provider rather than
assumed; the same confirmed capture stops being a fact the instant its confirming address is
swapped for an attacker's host or a look-alike, and the machinery's own outbound-safety
floor refuses to send the live credential there in the first place; and a capture whose
credential and confirming call carry different fingerprints — "some other secret
authenticated" — is likewise not confirmed. The two refusal gates are exercised for real on
the same live path: with the emergency stop tripped, and with the scope check denying, the
run stops before any network call is made and produces nothing to adjudicate.

**The credential never touches the disk.** It is piped straight into the harness, so it is
never written to a file, never placed where the machine's process list would show it, and
never put into the environment. The script contains no command tracing anywhere, because
tracing would print the credential. The harness then asserts that the credential does not
appear in the capture, in the checker's working record, or in the signed certificate.

**Neither harness runs in the automated build, and that is deliberate.** There are no
credentials in the build environment, and — in the project's own words — "a live-fire that
fabricates a result when it cannot run is worse than no live-fire." The GitHub one detects
a missing or unauthenticated credential and stops cleanly, saying so, rather than reporting
anything.

**Why they matter more than a vendor demonstration.** Both were built so that the customer,
the auditor or a sceptical evaluator runs the identical script on their own machine and
watches the identical result, rather than taking anyone's word for it. The Kubernetes one
borrows nobody's infrastructure; the GitHub one borrows nobody's account.

**What neither harness covers, said plainly.** Each stops slightly short of the complete
production path, and the difference should be stated here rather than left to be discovered.
The Kubernetes one captures using the ordinary Kubernetes command-line tool inside the shell
script and hands the resulting evidence straight to the confirmation machinery; it does not
travel through the system's own gated, scope-checked reader for a live cluster. That reader
exists and refuses unless the cluster it actually reached is one the operator declared in
writing, but the software it needs is not installed on the machine this briefing was written
on, so it was not exercised. The GitHub one *does* drive the real production capture
machinery over the real network connection — the stronger of the two — but on its
*permitted* legs the permission check and the scope check were stand-ins supplied by the
harness rather than a signed authorisation document read from disk. The *refusal* legs were
genuine, which is what demonstrates that the gate bites; no signed authorisation was loaded
in that run. Section 8 covers separately what the Kubernetes result does and does not
establish about clusters in general.

---

## 4. How the parts fit together: following one piece of work

The clearest way to see the connections is to follow a single assessment from beginning
to end. Each step names the department that owns it.

1. **Authorisation.** The operator writes a charter — a plain document naming the
   systems in scope, the operator's attestation that they own or are permitted to test
   them, the hard limits, and the stop conditions. Scope is parsed from a numbered table
   of in-scope hosts. If the parsed scope is empty, the system fails closed: an
   authority that authorises nothing is treated as a parsing error, not as permission.
   Defaults are conservative — destructive actions off, a bounded validity window
   (eight hours by default), and a finite action budget. (The target-intake department
   can *draft* this document from a web address; the operator must still sign it.)

2. **The usage record is written first.** Before anything runs, the system writes a
   signed record of who is running this, when, and against what. No record, no run.

3. **The AI proposes one step.** This is a suggestion with no authority. It is
   interpreted fail-closed: garbage becomes the safest available action.

4. **The gate decides.** The conjunctive gate asks several questions at once and needs
   all of them answered yes: is the emergency stop clear; are we inside the authorised
   time window; is this target in scope; is this action permitted for its danger tier;
   and, if the action is destructive, is there a multi-person approval with the owner
   among the signers. First failure wins. Any error in any check is a refusal.

5. **The exit door decides.** Even an allowed action must get past the gateway, which
   independently checks the destination and refuses anything on the forbidden list.

6. **A real tool runs against the real target,** and its raw output is captured and
   retained.

7. **The checker decides the truth.** The retained evidence is handed to a checker. If
   it fires, the finding becomes a fact and receives a sealed certificate. If it does
   not, the finding is recorded as an honest lead. The AI has no vote at this step.

8. **Everything is written to the append-only record** — the allowed actions, the
   refused ones, the facts, and the leads.

9. **Optionally, the defensive twin runs.** The Detection Mirror reads the target's own
   logs and proves the attack was visible there, producing a second, defensive
   certificate.

10. **Evidence is packaged.** Certificates, the chain, the raw artefacts and the reports
    are assembled into a self-contained package a third party can verify offline.

11. **Confirmed findings cross into the private office.** The offensive side, holding no
    owner key, can only *package* a confirmed finding into a signed data envelope. The
    sovereign side validates that envelope and appends it under the owner's signature.

Notice the shape: the AI appears once, at step 3, as a source of suggestions. Every
other step is deterministic machinery or a human decision.

---

## 5. The wall down the middle

### 5.1 What is kept apart from what

The system is installed as **two separate program environments** that never share a
running process:

| Environment | Contains | Forbidden to contain | Key held |
|---|---|---|---|
| **Sovereign** | The shared integrity core, SIGIL, the integration layer | The offensive engine, the vendored hacking tool | The owner's private key |
| **Offensive** | The shared integrity core, CRUCIBLE, the vendored hacking tool, the gateway, the integration layer | — | **None** (no owner key) |

This is declared in the repository's top-level configuration file as machine-readable
data, not merely as prose. The sovereign environment's declaration explicitly lists what
it forbids; the offensive environment's declaration explicitly records that it runs with
no owner signing key.

The integration layer is installed in both. That is deliberate — it is the connective
tissue — and it is why many of its files are required to load the offensive engine only
lazily, when actually needed, so that merely importing them in the sovereign
environment does not drag the offensive engine in.

### 5.2 Why the separation matters

Three concrete risks are addressed:

- **A compromised attacking program cannot escalate itself.** Every governance action
  that matters — releasing an emergency stop, promoting an assistant's trust level,
  approving a queued action — must be signed by the owner's key. The offensive side does
  not have that key, so anything it forges simply fails verification and is ignored.
- **An attacking program cannot reach into the personal record.** It cannot load the
  personal side's code, and the only channel between them carries data, not
  instructions.
- **Prompt injection cannot cross the wall.** If an attacker plants malicious
  instructions in a web page that the AI reads during a test, the worst it can influence
  is a proposal on the offensive side — which still has to clear the gates, the exit
  door, and the checker, none of which take instructions from text.

### 5.3 How the separation is enforced automatically

It is not a policy that someone has to remember. Six independent mechanisms enforce it:

1. **Absence, not configuration.** In the sovereign environment the offensive packages
   are simply *not installed*. There is nothing to disable and nothing to re-enable by
   mistake. The environment build script constructs both environments from explicit
   member lists and then checks the boundary.

2. **A hardcoded routing table.** When a person types a command, a small routing module
   decides which environment runs it. That module is deliberately written in plain
   standard library code that imports neither side; it looks the verb up in a fixed
   table and starts the correct program as a separate operating-system process. An
   offensive verb can never resolve into the sovereign environment or the reverse.
   Routing is by construction, not by inspection.

3. **A runtime guard.** The sovereign side calls a function at start-up that scans the
   list of loaded modules and raises an error if any offensive module is present. It
   fails closed.

4. **Environment hygiene when starting child programs.** When the sovereign side starts
   an offensive child process, the variables that could inject one side's code into the
   other are stripped. Credentials are passed through a closed allow-list. One key —
   the owner key that authorises destructive code changes — is on a hard exclusion list
   and is removed from the child's environment entirely, so a keyless offensive process
   can never receive it.

5. **The inert seam.** The single channel between the halves carries only data:
   - The offensive-side worker **refuses an owner key at construction**. Keylessness is
     enforced, not merely conventional. It can package a confirmed finding into a signed
     envelope; it can never mint a trusted record.
   - The receiving side parses the envelope with a plain data reader only — never any
     mechanism that could execute code — and bounds its size and shape.
   - Trust is established by **two independent anchors**: first, the finding's
     multi-signature is checked against a trust root that is itself derived from an
     owner-signed delegation; only then is the record appended under the owner's own
     signature. The offensive side proves *what* was found; the owner attests *when* it
     entered the personal record. Neither can forge the other's half.

6. **Tests, including a negative control.** An automated test suite proves the boundary
   three ways: it parses every sovereign package's declared dependencies (including
   optional ones and build-time ones, so nothing can be smuggled in as a build
   requirement); it builds a real sovereign environment and demonstrates from inside it
   that the offensive modules cannot be loaded; and — critically — it deliberately loads
   an offensive module and confirms the guard *fires*. Without that last test the guard
   could be passing for the trivial reason that it does nothing.

#### Machine-checked models of the four core rules

Beyond those six mechanisms, the repository contains machine-checked mathematical models
of the system's four core rules. This is the strongest assurance evidence in the project
and it deserves more than a sentence.

**What a model check is, in plain words.** The engineers write the rule down as a
precise mathematical description of a deliberately *tiny* version of the system — two or
three of each kind of thing, small counters — and then a program called a model checker
explores **every possible sequence of events** in that tiny world and reports whether the
rule can ever be broken. Ordinary tests sample a handful of situations chosen by a human;
a model check exhausts the space. The language used here is TLA+, and the checker is
TLC — both long-established tools for this purpose.

**The deliberately broken twin.** For each rule there is a second model, identical except
that the one guard doing the work has been removed. The checker must report that twin as
*failing*. This is a control against the most embarrassing failure a proof can have: a
check that passes because it is not actually checking anything. The verification script
fails if any real model regresses **or** if any broken twin stops being caught.

**The four rules:**

| Rule | What it says | What the broken twin removes |
|---|---|---|
| The conjunctive gate | An action that touches a target runs automatically only if all of these hold at once: the authority is in force (emergency stop clear, inside the time window, target in scope, under budget), the danger tier is one that may run automatically, and — if the action is destructive — an owner-inclusive multi-person quorum is present. Any error refuses. | The clause that denies a destructive action lacking a quorum. The checker then finds a sequence in which a destructive action runs with no owner approval. |
| The checker is the sole authority | A claim becomes a fact **only** because a deterministic checker fired over real bytes from the target. AI proposals, critic endorsements and re-ranking may create or keep a lead, and the anti-fabrication barrier may demote — but none of them may mint a fact. | The restriction on who may set the status to "fact". The checker then finds a sequence in which a non-checker declares something true. |
| The two-environment boundary | No single running process ever loads both offensive and sovereign code; an offensive process never holds the owner signing key; and a confirmed finding crosses between them as inert signed data carrying no capability. | The refusal to co-load. The checker then finds a sequence in which both sides are loaded together. |
| The anti-rollback floor | The durable high-water mark never goes backwards. A signed record head is accepted only if its entry count is at least the recorded floor; a shorter one is refused and nothing is written. | The entry-count guard. The checker then finds a sequence in which a truncated record is accepted and the high-water mark drops. |

**The honest scope, stated by the project itself.** A companion document,
`CORRESPONDENCE.md`, maps each model to the exact code file and line it abstracts, and
states the limit plainly: this is machine-checked assurance about the **design** — a
model that faithfully abstracts the enforcing code — **not** a proof extracted from the
running code itself. The link between model and code is a human-argued abstraction. The
project explicitly declines to say "the code is formally verified." A continuous
integration job runs the whole check on every change, and it can be reproduced offline
on a machine with no internet connection using a pre-supplied copy of the checking tool.

### 5.4 What the separation does not claim

Honesty requires stating the edges:

- It does not claim the offensive side is harmless. It is a real offensive engine. It is
  bounded by authorisation, gates and an exit door — not by being weak.
- It does not claim protection against an attacker who already has full control of the
  machine as the owner's own user account or as system administrator. Some guarantees,
  notably the local anti-rollback floor, are explicitly stated in the code to be
  defeated by an attacker with that level of access who rewrites both the record and the
  floor together; the defence against that case is an outside witness, covered in the
  chapter on proof.
- It does not claim the vendored third-party tool is held to the same standard. Its
  output is leads.

---

## 6. What runs where, and where the information is kept

Everything runs on machines the operator controls. There is no hosted service, no
vendor-operated back end, and no place where results are uploaded by default.

### 6.1 The running programs and the doors they answer at

| Piece | Where it runs | What it listens on |
|---|---|---|
| The sovereign side (SIGIL) | The operator's machine, as its own program | Its cockpit on `127.0.0.1:8733` |
| The offensive engine (CRUCIBLE) | The same machine, as a separate program with no owner key | Operations console on `127.0.0.1:8787`; gated action interface on `127.0.0.1:8799` |
| The unified web interface | Served by the `vigil up` proxy on the same machine | `127.0.0.1:8770` |
| The vendored hacking tool (STRIX) | Inside a container on the same machine | No direct network route; only the gateway |
| The gateway | The same machine, in front of the container | Proxy on `127.0.0.1:48081` by default |
| Optional supporting services (vector store, graph database, telemetry collector) | Containers on the same machine | Published on `127.0.0.1` only |

The two main programs run **natively**, not in containers, and the compose file explains
why: the offensive side must drive the machine's container system in order to run the
vendored tool, and putting the offensive side itself in a container would mean handing
it administrator-equivalent control of that container system — which would *weaken* the
two-process boundary rather than strengthen it. Containers are used for the stateful
supporting services and for the disposable attack sandbox, not for the trust boundary.

### 6.2 Where the information lives

A data-residency reviewer's first question is not "what ports" but "what is stored, in
what, and where". Everything below is on the operator's own disk.

| Store | What it holds | What form it takes |
|---|---|---|
| The engagement record (the "spine") | The signed, append-only history: actions taken, actions refused, decisions, facts, leads | Signed record files under the working directory, plus a separate usage ledger recording who ran what, when, against what |
| The event blackboard | Every observation each automatic worker posted during an engagement — the shared notice-board they coordinate through | A small file-based database (SQLite) inside the engine's own folder. The database itself refuses edits and deletions of the events table at the storage level, not merely in the code that uses it |
| The memory and learning store | Past engagements, findings, hypotheses, test inputs, dead ends, and the priors carried into future work | A second small file-based database inside the engine's own folder |
| The evidence tree | The raw captured exchanges — the actual bytes sent and received — filed per action | Ordinary files in a folder per engagement and per action |
| The session registry | Named lines of work: a name the operator chose plus pointers to the runs that belong to it. It stores operator free text and pointers, never a secret | One small structured file per session; the folder is owner-only and the files are owner-only |
| The per-session map | A graph view of one session, for the screens and for handover | One file per session, rebuilt from the record |
| Keys and secrets | The owner key, the offensive side's own record key, the governance key, and any configured credentials | Owner-only files; encrypted at rest when the machine's security chip vault is set up (see 7.5) |
| The engagement-library labels | The human names an operator has attached to past jobs, so work can be found again by name months later | One small owner-only side-car file under the console's own folder, keyed by the unchanged machine identity. It reaches no certificate and no proof bundle, and renaming rewrites nothing that already exists; a run's name does title a dossier downloaded afterwards |
| Reports, certificates and audit packages | The output the operator hands to someone else, including the nine-document case file | Ordinary files under the engagement folder |

A word used above: a **projection** is a copy of information rearranged into a more
convenient shape. The per-session map is a projection of the signed record. That has a
precise consequence the code enforces deliberately: the projection is built from the
record and **nothing** in it is ever read back into a permission, a trust level or a
fact. It exposes no method that could do so. It is a lens, never a source. Deleting a
projection loses no authority, because it can be rebuilt from the record, byte for byte,
by a process that uses no clock and no randomness.

**Optional container services**, all published only on this machine, all pinned to exact
image versions so that bringing them up is reproducible:

| Service | What it is for | How it is turned on |
|---|---|---|
| Vector store (Qdrant) | The similarity search behind memory and recall. The sovereign side also has a built-in fallback that needs no container at all | The default; ports 6333 and 6334 |
| Graph database (Neo4j) | An optional external home for the per-session knowledge graph | Only under the "graph" profile; ports 7474 and 7687 |
| Telemetry collector (OpenTelemetry) | An optional receiver for operational metrics | Only under the "observability" profile; port 4318 |
| The attack sandbox image | Build-only. It builds the Kali Linux image the vendored tool runs each engagement inside, so nothing is downloaded at run time | Only under the "strix" profile; it is never meant to be left running |

### 6.3 The programmatic surface — what a reviewer should count as attack surface

There are more ways in than "screens and command line", and a reviewer inventorying the
product's own exposure should know all of them. By default every one of these answers
only on this machine; the single exception is that the unified proxy may deliberately be
bound to a private or tunnel address, and never to a publicly reachable one (see 6.5).

| Surface | What it offers | Notes |
|---|---|---|
| The operations console (`:8787`) | **37** read-only addresses returning structured data — status, engagements, runs, sessions, the engagement library, benchmark, memory, tools, capabilities, defensive status, telemetry, certificates, posture, governance, coverage, world model, reports, and more — plus a live event stream that tails the log | Every one requires the console's session credential. Also carries the **33** operator action routes described in section 3.9 |
| The gated action interface (`:8799`) | A small deliberate interface for an operator's own software: read the status, engagements, runs, one engagement's authority, report, world model, evidence and intelligence; and two actions — invoke a tool, or import another tool's report | Every action goes through the same fail-closed authority, entitlement, scope and egress chain as a local action. It runs only if the operator starts it, and exposes no ungated capability |
| The unified proxy (`:8770`) | The single origin a human points a browser at. It forwards `/sovereign/*` to the cockpit, `/offense/api/v1/*` to the gated action interface, and everything else under `/offense/*` to the console | Pure standard-library code that imports neither trust domain, so one program never holds both |
| The model-context server | Lets other AI tools call this engine's safe capabilities | Runs over a direct program-to-program channel, not a network port |
| The sovereign cockpit (`:8733`) | The sovereign side's own page and its own action interface | The only surface on the machine that holds the owner key |

Two protections apply across the web surfaces: an action request is accepted only if it
carries a marker the product's own page sets and an ordinary web form cannot, and the
name in the request must match an allow-list — together these stop a malicious website
the operator happens to visit from quietly driving the local product in their browser.

### 6.4 Running it unattended

The repository ships ready-made definitions for the standard Linux mechanism that runs a
program automatically on a schedule. They are installed by the operator into their own
user account, not system-wide:

| Unit | What it does | The honest residual, as stated in the file itself |
|---|---|---|
| Posture re-proof (a service plus a timer) | On each cadence, re-scans the authorised target, re-mints the signed "we checked and did not find it" certificate, and appends it to the signed series | Freshness is only as current as the last time the timer fired, and the target must be reachable |
| Continuous re-proof (a service plus a timer) | On each cadence, re-proves the retained evidence corpus and appends a fresh signed, witnessed entry to the attestation log | "Continuously re-proven" means "re-proven on this cadence", not "provably true at this instant" |
| Witness co-signer (a template, one instance per witness) | Runs one independently-keyed witness that co-signs an append-only checkpoint series and refuses a fork. A *third party* is meant to run one of these | The unit refuses to bind to a public address; it will bind only to this machine, a private network, or a private tunnel address, and produces no signature otherwise |

This is what turns "the system *can* re-prove posture" into "the system *does* re-prove
posture on a stated cadence" — an operating property rather than a capability. Installing
them is an operator step.

### 6.5 Properties of the network posture, all verified in code

- **Nothing binds a public network interface.** The offensive console raises an error if
  asked to listen on anything other than this machine's own address. The unified proxy
  refuses a public bind up front: it permits this machine's own address, ordinary private
  network ranges, the address range used by common private mesh networks, and private
  next-generation ranges — and explicitly refuses "all interfaces" and any globally
  reachable address. That last check uses a positive allow-list rather than an "is it
  private?" test, because the standard library mislabels certain transition address
  formats as private.
- **Remote access is by tunnel, not by exposure.** The documented way to reach the
  interface from elsewhere is an encrypted tunnel plus a reverse proxy terminating
  transport encryption, with the domain added to an anti-rebinding allow-list. If a
  domain is configured without a shared secret protecting the gated interface, the
  command refuses to start unless an explicit "insecure" flag is passed.
- **The web interface is a driver, not an authority.** It never creates a finding and
  never passes a scope argument to a spawned process; every action it offers re-invokes
  the same gated command-line machinery. Whether something is displayed as a proven fact
  or a lead is rendered strictly from whether a checker confirmed it.
- **Ports are checked before anything starts.** The bring-up command refuses cleanly if
  a port is occupied, rather than leaving orphaned background programs behind.

### 6.6 What the host machine needs

From the deployment guide: Python 3.12 or 3.13 (a hard requirement), the Rust toolchain
(to build the permission kernel; the bootstrap script offers a user-level installation),
Docker (optional for the core, required for the vendored tool), and a Trusted Platform
Module — a small security chip present in most modern business hardware — which is
optional but strongly advised (see 7.5).

A single bootstrap script takes a fresh machine to a working installation in six steps.
Those steps are *idempotent* — running the script again does nothing extra and is safe;
it is like pressing a lift button twice — and each step is fail-closed, so a step that
cannot complete stops the installation rather than continuing in a half-configured
state.

### 6.7 Two operational notes for a deployment

Stated plainly, because silence would be misleading:

- **Backup and restore.** A documented, purpose-built backup-and-restore procedure
  **does** ship. `vigil backup` writes an off-box, passphrase-encrypted backup of **both**
  planes as two *separate* encrypted files (never a merged archive — one process holding
  both planes' secrets would breach the two-env boundary), each with a signed file manifest;
  `vigil restore` verifies every part's manifest **before** it writes a byte and refuses to
  report success on a chain that does not re-verify. It is deliberately anti-rollback-aware:
  the durable floor is part of what is captured, so a restore lands the high-water mark
  rather than tripping it, and the identity keys are re-wrapped for fresh hardware. (Sources:
  `integration/vigil_integration/backup.py`, `apps/sigil/sigil/backup.py`, the `backup`/
  `restore` verbs in `integration/vigil_integration/cli.py`, and the scheduled/off-host units
  under `infra/systemd/vigil-backup*`.) What stays a **deployment decision** — not a missing
  feature — is the key-management policy for the never-stored backup passphrase, and running
  the tested restore drill before go-live.
- **Multiple analysts sharing one deployment.** The design as read is single-operator:
  one owner key, one owner identity, one approval queue. Per-analyst attribution beyond
  the signed usage record, and what it would mean for several analysts to share a
  machine, are not addressed in the code read for this chapter.

---

## 7. What "self-hosted" and "sovereign" mean here

For an agency that cannot send data to outside companies, the relevant questions are:
what leaves the building, what is optional, and what happens if the answer is "nothing
may leave".

### 7.1 What never leaves by default

The code, the record, the evidence, the keys, the reports and the audit packages all
live on the operator's machines. There is no telemetry to a vendor. The verification of
a result — checking signatures, checking the chain, re-deriving a verdict from retained
evidence — is pure local computation that needs no network at all.

### 7.2 The one genuinely external dependency, and its ladder

The only part that would ordinarily reach an outside company is the large language model
that generates proposals. The system treats that as a policy decision and gives the
operator an explicit four-rung ladder, selected by a single setting:

| Setting | What is permitted | Trade-off, as stated in the code |
|---|---|---|
| **Air-gapped** | Locally-run models only. A cloud model is refused *before the client that would call it is constructed*. ("Air-gapped" is the security term for a machine with no connection to any outside network at all — as if separated by a gap of air.) | Highest sovereignty; lowest reasoning quality. |
| **Sovereign cloud** | Local, plus models hosted in a named jurisdiction (a major cloud provider's model service with a regional restriction, or a European provider). Direct consumer model interfaces are refused. | Frontier quality with data-residency guarantees. |
| **Trusted cloud** | Adds enterprise offerings with contractual zero-data-retention, and requires the operator to attest explicitly that the key in use is such a key. Direct consumer interfaces are still refused. | Contractual rather than jurisdictional assurance. |
| **Permissive** | Anything. This is the development default. | No policy enforcement. |

An unrecognised model backend is conservatively treated as the least sovereign category,
so it is refused under every restrictive setting. Locally-hosted options include a
self-hosted model server, a local model runner, and a deterministic replay mode that
needs no model at all.

**Where the setting is enforced, and what "refused" means precisely.** This is worth
stating exactly, because it recently changed. The setting used to govern the engine's
own catalogue of model backends but *not* the model call inside the running assessment
loop — so an operator could configure a sovereign tier and still have the path that
actually drives an engagement reach a cloud model. That gap is closed. The setting is now
consulted at every place in the offensive half that can call a model:

| Where a model can be called | What now happens under a restrictive setting |
|---|---|
| The engine's model-backend catalogue — every backend the reasoning functions use | The tier is checked inside the routine that builds a backend, before the vendor's software library is loaded |
| The reasoning loop's "propose the next step" call during a live assessment | Checked before the client is built; on a refusal the step becomes an inert pause that asks the operator |
| The code-fix proposer | Same check, same refusal |
| The operations console's natural-language command box | Refused with the policy's own message; the ordinary typed command line is unaffected, because it does not use a model at all |

"Refused" is literal rather than cosmetic. The check happens **before the model client is
constructed and before the vendor's software library is even loaded**, so on a refusal
nothing is imported, nothing is built, and no bytes leave the machine. The code's own
words for this are that "the client is never constructed, the SDK is never imported, and
nothing leaves the host."

It is fail-closed at four separate points, and each one is a decision someone had to make
the safe way round: an unrecognised setting name resolves to the *strictest* tier, not the
most permissive; an unrecognised model backend is classified as the least sovereign
category; if the policy code cannot be loaded at all, then any configured tier refuses
rather than proceeding unchecked; and an error *inside* the gate is itself a refusal, never
a permission. A refusal does not crash the assessment — it returns the safest available
action, a pause that asks the operator what to do, carrying the policy's own explanation of
which tier refused and which setting would change it.

Three bounds on that statement, all of which matter:

- **An optional seal.** By default the setting is re-read on each call, which is convenient
  in development but means a change to the machine's configuration mid-assessment would
  take effect immediately. A separate opt-in setting latches the tier once for the life of
  the running program, so a later change cannot relax it part-way through a job. It can
  only pin the tier, never loosen it.
- **It governs the offensive half.** The sovereign side's own optional use of a model — the
  feature that describes a screen or camera image — is not on this ladder, and should not
  be described as if it were. It is governed separately and, in one respect, more strictly:
  sending a private image off the machine is classified as an externally-visible action
  under the A0–A3 tiers, and it will not upload until an owner approval exists that is
  bound by fingerprint to that exact image and that exact question, so the approval of one
  upload cannot be replayed to authorise another.
- **The vendored third-party agent is not on this ladder either.** STRIX (section 3.6) has
  its own separate model setting, and its code contains no reference to this policy at all.
  Its containment is of a different kind — it runs inside the disposable container whose only
  route out is the gateway — but an agency intending to enforce a model-sovereignty policy
  should treat the vendored agent's model choice as a separate configuration item to be set,
  not as something the ladder covers for them.

### 7.3 No credential is strictly required to run

This is worth stating plainly because it is unusual. The system runs with no keys at
all:

- With no model key, an assessment still runs: it still writes the usage record first,
  and then completes by proposing nothing. The code's own description is that it "never
  fabricates activity."
- The project's example configuration file states that no secrets are required to bring
  the stack up; the commented entries are optional overrides.
- Every deterministic layer — the checkers, the signing and verification, the gate
  chain, the offline verifiers — is ordinary code that needs no external service.

The trade is honest and explicit: without a model, the system loses its ability to
generate and prioritise creative hypotheses. It loses none of its ability to prove,
verify, or refuse.

### 7.4 What does reach outside when the operator enables it

For completeness, every outbound dependency the system can have, and what enabling it
means:

| Optional dependency | What it is for | Consequence of enabling |
|---|---|---|
| A cloud-hosted model | AI reasoning | Prompt content reaches the model provider, subject to the sovereignty ladder above |
| Read-only cloud credentials (AWS, Azure, Google Cloud, Kubernetes) | Checking the posture of the operator's own cloud accounts | The system talks to those cloud providers as the operator |
| A source-control token | Raising a proposed code change for a human to review — the software industry's name for this is "opening a pull request" | The system can create a code-change request in the operator's repository. Nothing is changed without a human approving it |
| A remote graph database | Storing the per-session knowledge graph externally | Graph data leaves for that database. If it is not configured or is unreachable, the rebuilt view is simply omitted — the code states it "never fakes a connection" |
| A telemetry collector | Exporting operational metrics | Metrics leave for that collector |
| A voice service | Spoken output on the sovereign side | Audio text reaches that provider. This key is explicitly never passed to the offensive side |
| A web-research provider | Live research during a code review | Search queries leave |
| An external timestamping authority | Proving a record existed no later than a given time | A fingerprint — not content — is sent for countersigning |
| Independent witnesses | Countersigning the record so an outside party need not trust the operator | Checkpoint fingerprints are shared with the witnesses |

Two of these deserve a note.

**First, the credential-handling path itself is hardened.** Some cloud credentials are
files rather than short strings. When one of those is needed by a child program, the
system writes it to a fixed-name, owner-only file in an owner-only directory, and hands
the child only the *path* — never the content, which is always removed from the child's
environment whether or not the file was written. The write itself is defended against a
trick called *symbolic-link substitution*. A symbolic link is a signpost file that points
at a different file. An attacker who can plant a signpost where the system is about to
write a secret could redirect that secret into a location of their choosing. The code
therefore refuses a signposted directory, deletes any pre-existing name, and creates a
brand-new file with an option that fails outright rather than following a signpost
planted at the last instant — then confirms the new file has no second name pointing at
it. If any of that fails, the credential is simply not written, and the collector then
fails closed with no cloud identity.

**Second, on the traffic to the target.** The *purpose* of a security assessment is to
send traffic to the authorised target, so of course packets go to that target. What the
design guarantees is that they go *only* there, and never to the machine's own internal
addresses or to a cloud metadata service.

### 7.5 Keys at rest

If the machine has a Trusted Platform Module and its tools are installed, the bootstrap
seals a key-encryption key to *that specific machine*. All secrets and private keys are
then encrypted at rest, and moving the disk to another machine makes them unopenable by
design. If the chip is absent, **keys are stored in plain text at rest**. The deployment
guide says so directly and calls that acceptable only on a trusted single-user machine;
on a shared or hosted machine it instructs the operator to install the chip support or
use a virtual equivalent first. The bootstrap prints a loud warning; it never silently
degrades confidentiality without saying so. When the vault is enabled and the chip later
cannot unseal, reads fail closed — there is no silent fall-back to plain text.

---

## 8. Honest status of the parts

Different parts of the system are at different stages. The project maintains a written
claim-discipline doctrine for exactly this reason, and this section applies it. That
doctrine has an unusual rule worth naming, because it explains the shape of what
follows: when a review finds that the product claims more than it delivers, the required
response is to *build the capability up to the claim*, or to write down exactly what
work is blocking it. Quietly softening the claim is not permitted. The consequence for a
reader is that the honest gaps listed here are a short, specific list of named
dependencies, not a vague hedge.

Two further notes on the wording. First, it avoids software-delivery vocabulary on
purpose: "part of the released software" means it is in the version an operator installs
today. Everything described in this chapter is part of the released software unless the
text says otherwise, and where something is not, the reason is given. Second, "proven
offline" means proven against recorded sample data standing in for the real thing —
which proves the logic and the handling of evidence, and does not prove anything about
any particular live account.

**Fully working and exercised on this system:**

- The two-environment separation and every mechanism that enforces it.
- The shared integrity core: chain, signatures, canonical formatting, the gate, the
  danger classifier, key storage, the anti-rollback floor.
- The offensive engine, its checkers, and its evidence and reporting layers — including the
  nine-document plain-English case file that is generated into every dossier (section 3.3).
  (The anti-fabrication barrier is real and in use, but it is *bounded* rather than
  universal; it therefore appears in its own group below rather than here.)
- The real network connection through which the cloud and exposed-secret confirmations reach
  the outside world (section 3.7), and the two live-fire harnesses that drive them
  (section 3.11). This is a recent and consequential change: until it existed, the only thing
  ever plugged into that joint was a stand-in used by the tests, which is precisely why none
  of those capabilities had ever fired at a real provider. Both harnesses have now been run —
  one against a real Kubernetes cluster, one against the real GitHub service.
- The gate chain, the emergency stop, the permission tiers, the approval queue with
  single-use owner-signed tokens, and the exit-door gateway.
- The sovereign side's record, its permission kernel, and its agent mesh.
- The sealed evidence package and the standalone offline verifiers, which contain no
  VIGIL code at all and re-implement the published format from its specification.
- The unified 29-screen interface, reachable through the bring-up command.
- The machine-checked models of the four core rules, together with their deliberately
  broken twins and the document mapping each model to the code it abstracts. All four
  models and all four broken twins are checked automatically on every change, as a
  required step in the project's continuous-integration pipeline, and can be re-run
  offline.

**Working and in use, but bounded — and the bound is stated:**

- **The anti-fabrication barrier** (the veracity layer, section 3.3). It is wired into
  seven real paths in the working software — admitting findings during an engagement,
  rendering the report, the defensive pipeline, the automatic workers' tool surface, the
  scanner's own report path, the grounding critic, and the refusal path — and at every
  one of them it can only take status away, never grant it. What it is **not**, today, is
  a single universal checkpoint that every claim in the system must cross: writing into
  the internal map of the target reaches the same underlying judgement about where a
  piece of information came from, but by a different route. Anyone quoting this briefing
  should quote that bounded form, not a universal one.

**The safeguards on how the software itself is built and shipped:**

An agency reader is buying a *supply chain*, not only a program, so the safeguards below
concern what goes into the product rather than what the product does. They are part of
the released software and they run on every proposed change to it.

| Safeguard | What it means in plain words | Status |
|---|---|---|
| Dependency hash-locking | Every third-party software library the system uses is pinned to an exact, fingerprinted copy — 640 fingerprints on the offensive side and 1,176 on the sovereign side, covering not just the libraries chosen directly but everything they in turn pull in. The installer is run in a mode that refuses the whole list outright if any item is unpinned or any fingerprint fails to match. The pipeline proves this by actually performing that installation, so the list cannot rot into a document nobody checks. | Working; runs on every change |
| Container base-image pinning | A container is built on top of a base image named by a label such as "latest". A label is a movable pointer: whoever publishes it can change what it points at, and a build would silently pick up the change. Every base image here is instead named by the fingerprint of its exact content, so a substitution fails rather than succeeds silently. Nine image references exist in the repository; the eight that come from outside are all fingerprint-pinned, and the ninth is built from this repository and so has no outside publisher to pin. A separate, advisory check reports where the outside world has since moved on. | Working; nine of nine accounted for |
| A bill of materials | A published inventory of everything inside the shipped software — the software equivalent of an ingredients list. One is generated during the build for each of the two halves, cross-checked item by item against the pinned list so the two can never disagree, and published with the build. Honest detail: an older placeholder inventory file still sits inside the engine's own folder; it is a leftover, not the artefact the build produces. | Working; one stale placeholder file remains |
| A vulnerability gate that blocks | Every build scans the pinned libraries against a public vulnerability database. A finding rated *critical* stops the change from being accepted. Findings rated *high* are reported in full but do not block, and the reason is written down in the pipeline itself: a gate whose exception list must grow without limit to stay green stops meaning anything. Every exception carries a written justification, and an automated test fails if one does not. | Working; blocks on critical |
| A negative control on that gate | The most valuable part, and the one most products omit. A gate that never fires is indistinguishable from a gate that cannot fire. Before the real scan runs, the pipeline deliberately points the same blocking configuration at a sample known to contain critical vulnerabilities and requires it to fail. If that deliberate failure does not occur, the pipeline stops and says so, because the green tick that follows would otherwise be meaningless. | Working; proven to be able to fail |

**Built, and proven on a local target — but not a field record:**

- The complete end-to-end assessment loop was validated against a purpose-built target
  running on the machine's own internal address. The project README says so in its own
  words: proven on a local target, not "proven in the field." A live external run against
  a vendor-published deliberately-vulnerable test site is also recorded in the project's
  documents, with two confirmed findings re-verified offline; that record was read as a
  documented claim in this pass, not re-executed.

**The six cloud and Kubernetes exploitation confirmations: complete. Three of the six have
now been fired at real infrastructure — though one of those three only for one of the two
kinds of credential it handles. The other three await the customer's credentials, and one of
them never fires at anything, by design.**

This item is set out at length rather than listed in a table, because it is the single
part of the system most easily misrepresented — and it can be misrepresented in either
direction, which is why both are named below.

Most security tooling, looking at a cloud account, reports *settings*: this permission is
too broad, this store is readable. That is worth reporting, but it is a statement about
configuration, not about consequence. This system additionally contains six
confirmations that a weakness was not merely present but actually *achieved*:

| Confirmation | What it establishes, in plain terms |
|---|---|
| **Instance-metadata credential capture** | A machine running in a cloud has an internal service that hands out credentials to whatever is running on it. This confirms a credential was actually retrieved from that service and actually worked — not merely that the service could be reached. |
| **Exposed-secret validity** | A password or key found lying somewhere it should not be is only a real problem if it still works. This confirms the secret is currently valid, by using it once to ask "who am I?", rather than assuming it is live. It covers two kinds of credential, and the two are at different stages — see below, because the difference must not be blurred. |
| **Google service-account impersonation** | One machine identity was able to obtain a working token as a different, more privileged identity, and that token was confirmed with one call. |
| **Identity privilege escalation** | The captured permission rules, read together with the limits that are supposed to constrain them, unconditionally permit a named identity to gain privilege it should not have. |
| **Kubernetes access control, tier one** | On a container cluster, an anonymous, unauthenticated caller is bound to a dangerous built-in role. |
| **Kubernetes access control, tier two** | A dangerous permission verb, or the cluster's default identity, has been granted rights it should not have. This one reads and parses the permission rules themselves, rather than pattern-matching a name. |

**What is complete.** All six are finished and part of the released software. Each is
built from two halves: a fixed automatic checker — the same non-AI kind of test that
adjudicates every other result in this system — and a system-owned capture step that
produces the evidence the checker judges. Each also carries a written statement of
what its result does and does not mean; each is bounded to the one thing captured, and
none of the six claims to prove the *absence* of a problem elsewhere in the account.

**Kubernetes: proven against a real cluster.** The two Kubernetes confirmations are no
longer proven only against recorded sample data. A script in the repository stands up a
real single-node Kubernetes cluster — k3s version 1.31.5, in a container reachable only
on the machine's own internal address — which the system creates, owns and destroys
afterwards. It plants known-dangerous and known-benign access rules in it, captures what
the real Kubernetes interface returns, and puts those real bytes through the ordinary
production path: checker, admission, certificate, offline re-verification. The dangerous
case — an anonymous, unauthenticated caller bound to the full administrative role — is
confirmed and its certificate re-verifies with no network. The benign cases in the same
cluster are correctly not confirmed, including the namespace's own default identity bound
to the built-in `admin` role, whose real rules do grant read access to secrets: the
commonest legitimate arrangement in Kubernetes, which a detector without a subject test
would wrongly call critical. The script asserts every expectation and exits with an error
if any fails, so it is a proof rather than a demonstration, and anyone can re-run it.

What that run does **not** cover, said plainly: it reads the objects it planted, by name,
so it does not exercise a scope-gated **enumeration** capability that discovers access
rules across a whole cluster; and the cluster is one the system stood up itself, so a
**managed provider's control plane** (Amazon EKS, Google GKE, Azure AKS) — the same
interface reached by a different access path — is not exercised.

**Exposed-secret validity: proven against a real third-party provider — for one kind of
credential, and not the other.** This is the sharpest honesty point in the chapter and it
must not be smoothed over, in either direction.

The confirmation covers two kinds of credential: a GitHub personal access token, and an
Amazon Web Services access key. **The GitHub one has been fired at the real, public
`api.github.com`.** The harness described in section 3.11 drives the real capture machinery
over the real network connection, using the operator's own credential against the operator's
own identity, and the result is confirmed with a certificate that re-verifies offline. Three
controls were measured in the same run against the same real provider: a bogus credential of
the identical *shape*, sent live, was rejected by GitHub itself and correctly remained a
lead — structure is not validity, and here that is measured rather than assumed; the same
confirmed capture stopped being a fact the instant its confirming address was swapped for an
attacker's host or a look-alike, with the machinery's own outbound-safety floor refusing to
send the live credential there at all; and a capture whose credential and confirming call
carried different fingerprints was likewise not confirmed. Both refusal gates were exercised
on the same live path and stopped the run before any network call was made.

**The Amazon row of the same capability has never touched real Amazon Web Services.** Its
dispatch and its request-signing are built and proven — the signing implementation is checked
against Amazon's own independently-written one — but it still needs a real, customer-supplied
access key. **Nothing from the GitHub run transfers to it.** Anyone quoting this briefing
should name the row rather than the capability.

**Cloud: what is deferred, and why.** For the remaining cloud capabilities — metadata
credential capture, Google service-account impersonation, identity privilege escalation, and
the Amazon row just described — what has not yet happened is **real-world live fire against a
third-party cloud account**. That step waits on the customer supplying their own read-only
cloud credentials. The detection logic, the evidence handling, the certificates and the
safety gates are all built and proven; only the act of pointing them at a live third-party
account is pending, by design. The capture modules say so in their own written notes, in
almost these words.

One of the four — identity privilege escalation — is different in an instructive way, and
the difference should not be glossed. It reasons over a *captured copy* of the permission
rules and never performs the escalation. It is therefore not waiting to be "fired" at
anything: not performing the action is the design. It does still need a real copy of a
real account's permission rules, and obtaining that still needs the customer's read-only
credentials. What it will never need is to actually take the privileged step.

Two framings should both be avoided because each is wrong in a different direction.
Saying the capabilities are unfinished understates the system: they are built, gated, and
proven. Saying the cloud ones have been field-proven in customer clouds overstates it:
most have not been pointed at one. The accurate statement, used throughout this briefing,
is: **the two Kubernetes confirmations are proven against a real cluster the system stands
up itself; the GitHub row of exposed-secret validity is proven against the real, public
GitHub service; and the remaining cloud work — metadata credential capture, Google
service-account impersonation, identity privilege escalation, and the Amazon row of
exposed-secret validity — is built, gated, and proven offline, with live fire awaiting
customer-supplied credentials, by design.**

There is a design point worth drawing out for a procurement reader, and the three parts
illustrate it from different sides. For the remaining cloud capabilities it would have been
easy to demonstrate against an account of our own and call the matter field-proven; that was
not done, because a demonstration on an account the customer cannot re-create is a claim,
not evidence. For Kubernetes the same principle pointed the other way: a cluster *can* be
created from nothing in a few seconds on any machine, so the proof was built to create
one — and the value of that proof is precisely that the customer, or an auditor, can run
the identical script and watch the identical result, rather than take our word for it. The
GitHub proof is the same test applied to a service nobody can stand up themselves: it was
built to use *the evaluator's own* account and the least-privileged call the service offers,
so it too can be re-run by anyone, on their own credential, without borrowing ours. The
common rule in all three is that a proof only counts if the person being asked to believe it
can reproduce it.

**Other things built, but deliberately not yet fired against live third-party systems:**

| Item | Blocking dependency, as stated in the repository |
|---|---|
| The destructive code-change leg (raising a proposed code change for human review) | The operator must provision the several key-holders whose agreement is required, and a source-control token |
| Live cloud and Kubernetes posture collection (the *settings* review, as distinct from the six confirmations above) | Requires operator-supplied read-only credentials |
| A running external graph database or telemetry collector | The software that talks to them is built; the deployment is deferred |
| Live AI red-teaming tools as evidence sources | The harness that drives them is built and gated; the tools themselves are absent from this environment |
| A live connection to an external tool-plug-in server | The connecting half is pending |

**Scaffolded, and honestly marked as such:**

- Hardware-based confidential-computing attestation: the hardware backends deliberately
  raise an error; a software and chip-based attestation path works today and reports
  itself as not hardware-backed.
- General automated patch synthesis for memory-safety bugs in compiled programs: the
  crash-confirmation and fix-proved-by-silence path is built; the synthesis step is
  research-gated and raises.
- The next-generation agent body: an interface only.

**Built, but switched off unless the operator turns it on:**

- Entitlement enforcement (section 3.10). The whole licence system is built and tested,
  but enforcement is inactive until a governance trust root is provisioned or the
  enforcement setting is set. Until then the system runs its dangerous capabilities and
  logs each grant as a warning while reporting itself ungoverned. An agency that wants
  the "a stolen copy is inert" property must complete that provisioning step.

**Conditional guarantees, stated as conditional:**

- The transparency log's resistance to showing two different versions of the record to
  two different parties is *prevented* only when a strict majority of distinct witnesses
  countersign. Below that threshold it remains *detectable* but not prevented, and the
  code exposes the two checks separately so the difference cannot be blurred.
- The independence of those witnesses is a deployment assumption, not something software
  can prove. The project's own trust document is marked "DRAFT — design, not a
  guarantee" and says plainly: distinct keys are not distinct operators; if the producer
  holds all the witness keys, the quorum is theatre.
- Channel binding (section 3.7) removes the need to trust the producer's honesty about
  what the target sent — but only as far as the notary is genuinely independent, which is
  again a deployment assumption.
- A certificate that a weakness was *not* found means non-exploitability by the checkers
  that ran, over the surface actually reached, as of the stated freshness bound. It never
  means "secure against everything." Endpoints that were never discovered are outside
  what was measured: if the system examined forty pages of an application and never found
  the forty-first, the certificate says nothing whatever about that forty-first page, and
  is careful to say so.

---

## 9. A short glossary

The names of the parts:

| Name | Meaning |
|---|---|
| **VIGIL** | The whole product. |
| **CRUCIBLE** | The offensive engine inside VIGIL. |
| **AEGIS** | The defensive twin: the same proving machinery pointed inward. |
| **SIGIL** | The sovereign, offence-free personal side that holds the owner's key. |
| **STRIX** | A vendored third-party autonomous hacking tool, used as a source of leads only. |
| **WARDEN** | The permission classifier that sorts every action into tiers A0 to A3. |
| **OBSIDIAN** | The written operating doctrine for the AI when it drives the offensive engine. |
| **Fireteam** | The subsystem that runs several governed specialist workers in parallel. |

The technical words used in this chapter:

| Term | Meaning |
|---|---|
| **Checker** (the software calls it an **oracle**) | A small, fixed program that looks at saved evidence and answers one narrow question, always the same way. No intelligence, no network, no clock. The only thing permitted to declare a finding true. |
| **FACT / LEAD** | A finding a checker confirmed, versus a finding that is only suspected. |
| **Deterministic** | Same input, same answer, every time. A recipe, not a chef. |
| **Fail-closed** | If a check cannot be completed, the answer is no. A drawbridge held up by power. |
| **The spine** | The append-only, signed record. Entries can be added, never edited or erased. |
| **The charter** | The document that authorises an assessment and defines its scope. |
| **The gateway** | The deny-by-default network exit barrier. |
| **The two-environment boundary** | The wall between the offensive side and the sovereign side. |
| **Seam** | The single joint where two parts meet, so that everything crossing between them can be checked in one place. |
| **Canonical** | One fixed way of writing something down, so the same information always produces byte-for-byte identical text. |
| **Projection** | A copy of information rearranged into a more convenient shape. Derived from the record, disposable, rebuildable, and never allowed to feed a decision. |
| **`127.0.0.1` (loopback)** | The address a computer uses to talk to itself. No other machine can reach it. |
| **Container** | An isolated, disposable software box that a program runs inside. |
| **Vendored** | A copy of somebody else's software kept inside this one, with its original licence and credits. |
| **Idempotent** | Running it twice does nothing extra. Safe to press again. |
| **Air-gapped** | A machine with no connection to any outside network at all. |
| **Entitlement** | A signed, machine-bound, expiring licence that decides which dangerous capabilities may run on this installation. |
| **m-of-n** | Several named key-holders, of whom a set number must agree. A vault needing two managers' keys at once. |
| **Pull request** | The software industry's term for a proposed code change raised so a human can review it before it becomes part of the software. |
| **Kubernetes** | The standard software for running large numbers of containers across many machines. |
| **Live fire** | Running a capability against a real system rather than against a stand-in. Three confirmations are proven this way today: both Kubernetes ones, against a real cluster the system creates and destroys itself, and the GitHub row of exposed-secret validity, against the real public GitHub service. The remaining cloud confirmations are complete and proven against stand-in data, and await live fire on the customer's own account by design. |
| **Case file** | The pack of nine numbered plain-English documents generated into every dossier, written for the non-specialist who receives it: what was done, what was found, what was **not** examined, what to do, and how to check the result independently. |
| **Recorded sample data** (the software calls it a *fixture*) | Saved, realistic data used in place of a live system, so a test proves the logic without touching anyone's account. Like testing a smoke alarm with a test button rather than a fire. |
| **Fingerprint** (of a file, a message or an image) | A short value computed from the content, such that any change to the content changes the value. Used throughout to detect substitution. Sometimes called a hash or a digest. |
| **Bill of materials** | A published list of everything inside a piece of software, item by item, with versions. The ingredients list on the packet. |
| **Negative control** | A deliberate test that something *fails* when it should. It is how you prove a safety check is actually checking, rather than passing because it does nothing. A smoke alarm you never test may simply be dead. |
| **Attestation** | A signed statement about a state of affairs — who ran something and when, or what a machine is and that its files are unaltered. |
| **Denominator** | In a coverage statement, the "out of how many". Saying forty pages were checked means little until you know whether the application has forty pages or four hundred; the denominator is that second number, and undiscovered pages are outside it. |

Detailed treatment of the checkers, the categories of weakness the system can find, the
signing and offline-verification machinery, and the screens themselves are each covered
in their own chapters.
