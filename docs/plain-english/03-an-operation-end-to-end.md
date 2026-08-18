# How A Security Assessment Runs, From Start To Finish

This chapter follows one complete job in order, as a story.

A "security assessment" here means: the operator points the system at a computer system
they own or have written permission to test, and the system tries to find real weaknesses
in it — the way a burglar would test a building the owner asked them to test. At the end,
the owner receives a report and a sealed evidence package.

The chapter walks through every stage: getting written permission, setting up the job,
looking around, mapping what is there, testing, confirming, drawing the attack picture,
producing the report, and re-testing after the repairs are made. At each stage it says
three things:

- what the **operator** (the human running the job) does,
- what the **system** does by itself,
- what **safety checks** happen.

Three words are used throughout and are worth fixing now.

- A **FACT** is something the system proved to itself, mechanically, and can prove again
  later to a stranger. Think of a laboratory test result with the sample kept in the
  freezer.
- A **LEAD** is something that merely looks suspicious. A tip-off. It might be a
  third-party tool's opinion, a rule-of-thumb pattern match, or the artificial
  intelligence's own guess. A lead is written down and shown to the operator, but it is
  never presented as proven.
- A **checker** is the small, fixed, non-intelligent program that turns the first into the
  second. It looks at saved evidence and answers one narrow question — always the same way,
  with no judgement and no opinion. The software's own name for a checker is an **oracle**,
  and that word appears in the code and on some screens; this chapter says "checker".

The whole design of the job is arranged around keeping facts and leads apart, and the
checker is the thing that decides which is which.

A few other everyday-looking words are used here in a specific sense. They are glossed the
first time each appears, but it is worth having them together:

| Word | What it means here |
|---|---|
| **Payload** | The test input the system deliberately sends, to see how the target reacts. Not a cargo. |
| **Provenance** | The recorded history of where a piece of evidence came from and how it was obtained. |
| **Deterministic** | Same input, same answer, every time, on any machine. A recipe, not a chef — no mood, no improvisation. |
| **Fail-closed** | If a safety check cannot be completed, the answer is "no". Like a drawbridge held up by power: cut the power and it falls shut. |
| **Sink** | The place a piece of data finally ends up — a database query, a page a browser will run, a file the server opens. Most weaknesses are untrusted input reaching a sink. |

---

## 1. The shape of a job

A complete assessment moves through eleven stages, numbered 0 to 10. They are a structure, not a rigid
conveyor belt — in practice the middle stages overlap, and the system may loop back as it
learns. But no job is considered finished until every stage has been passed.

| # | Stage | The plain question it answers |
|---|---|---|
| 0 | Charter | Are we allowed to do this, to what exactly, and until when? |
| 1 | Session | Which body of work does this belong to? |
| 2 | Set-up | What are we running, how deep, and with which tools? |
| 3 | Pre-flight | Who is running this, and does every step pass the gates? |
| 4 | Discovery | What exists at this target? |
| 5 | Mapping | Where are the doors, windows and moving parts? |
| 6 | Testing | Do any of them actually give way? |
| 7 | Confirming | Can we prove that mechanically, and prove it again later? |
| 8 | Attack picture | How do the proven weaknesses chain into real damage? |
| 9 | Report + evidence | What does the owner receive, and can a third party check it? |
| 10 | Re-test | After the repairs, is it actually fixed? |

### How this maps to the engine's own written lifecycle

The engine carries its own written lifecycle document, and it describes the work in the
same spirit — "a structure that guarantees nothing is forgotten", not "a sequence of locked
doors". But it is not the same list. The engine's lifecycle has **twelve** stages, numbered
0 to 11, and the eleven stages above are the ones the software itself performs during a run.
Three of the engine's stages are human-and-doctrine work around the run rather than steps
the software executes, and it is more honest to name them than to fold them away.

| Engine's stage | Where it is in this chapter |
|---|---|
| 0. Charter — authorisation and intent | Section 2 |
| **1. Threat model — where will adversaries push** | **Not a stage of a run.** Covered in section 2, under the intake helper, which drafts it |
| 2. Recon — passive then active | Section 6 |
| 3. Attack-surface mapping | Sections 6 and 7 |
| 4. Vulnerability hunting, per domain | Section 8 |
| 5. Exploitation — confirm impact, chain bugs | Sections 9 and 11 |
| **6. Post-exploitation** | **Deliberately not built.** Explained below |
| 7. Source-code review | Not covered here; it is chapter 13's subject |
| 8. Reporting | Section 12 |
| 9. Remediation validation — the re-test | Section 13 |
| 10. Continuous testing | Section 13, the drift comparison |
| **11. Engagement closure** | **Not a stage of a run.** Explained below |

**Stage 1, the threat model.** Before testing anything, a professional tester writes down
what an attacker would want, who would attack, where trust boundaries sit, and then draws
an "attack tree" — a diagram whose root is the attacker's goal and whose leaves are
specific things to try. The engine's doctrine makes this stage 1 and produces two documents
for it. In this system the *drafting* of both is automated by the intake helper described
in the next section; reviewing them and deciding priorities remains the operator's job.

**Stage 6, post-exploitation.** This is the question most agencies ask second: once the
system is inside, what does it do? The honest answer is that it deliberately does not go
in. Establishing a foothold, moving sideways to other machines, installing anything that
survives a reboot, and running a remote command-and-control channel are all **excluded by
policy, not missing by accident**. The engine's own written list of limitations puts
post-exploitation, lateral movement, persistence and data-exfiltration execution among the
surfaces that are, in its words, "present at most as v1 markdown playbooks and/or passive
fingerprint labels, never as active capability". The narrowest offensive layer in the whole
system states its exclusions in its own source: "It mints no new payloads, drives no
weaponization, establishes no persistence, and performs no lateral movement" — and then
lists detection-evasion, command-and-control, implants, full-chain exploitation,
credential-attack suites and identity rotation under the heading "refuse, never build".
What that layer *does* do is re-run the proof the checker
already fired on, to show the operator the finding is real. For an agency, this is a
constraint to plan around: the system proves a door opens; it does not walk through the
building.

**Stage 11, engagement closure.** After the reports are delivered, the doctrine requires a
closing pass: confirm every piece of test data the assessment created has been cleaned up,
rotate any credentials that were shared for the engagement, archive the working folder, and
update the threat model with what was actually learned so the next re-test starts from it.
This is written procedure carried out by the operator, with the system's records as the
evidence — it is not an automated step, and this chapter does not claim it is.

---

## 2. Stage 0 — Written authorisation: the charter

### Why it exists

Security testing is, technically, an attack. The only thing separating a legitimate
assessment from a crime is written permission from the system's owner, with the boundaries
spelled out. So the system refuses to treat permission as a spoken assurance or a checkbox
on a screen. Permission is a **document**, and the document is machine-readable.

That document is called the **charter**.

### What the operator does

The operator writes a charter file for the target. It lives in a predictable place — a
folder per target, with the charter inside it (`targets/<name>/charter.md`). **Three** real,
signed charters exist in the repository today, counted rather than remembered: `loopback`,
`testphp` and `testasp`. There is a fourth target folder, `_practice`, but it contains only
an explanatory document and no charter — which is the rule working rather than a gap, because
a folder without a charter is a folder nothing can be run against.

A charter contains, at minimum:

- **A numbered table of in-scope hosts.** This is the part the machine actually reads. Each
  row names a specific machine or web address that may be touched, and what it is.
- **An operator attestation.** A written statement, in the operator's own words, that they
  own the target or hold authority over it, and that the authorisation is current.
- **Hard limits.** Things that may never happen. In the real loopback charter these
  include "every tool must resolve its target to the local machine", "no external network
  traffic at all", and "no real data".
- **Soft limits.** Throttling, quiet hours, tagging rules for any test data created.
- **Stop conditions.** The circumstances under which the job halts immediately.
- **Objectives.** What success would look like.

Here is the flavour of a real one, quoted from the `loopback` charter in the repository:

> **Nothing else is in scope.** Only `127.0.0.0/8` may be touched by any tool.

That is not decoration. The scope table is parsed by the software and becomes the fence.

(`127.0.0.0/8` is a way of writing a whole block of internet addresses at once. The part
after the slash says how much of the address is fixed; here it means every address
beginning with 127, which is the range a computer uses to talk to itself and which no other
machine on earth can reach. This shorthand is called **CIDR** — classless inter-domain
routing — and it appears again later, where the system deliberately refuses to accept it.)

### The operator does not have to start from a blank page

Writing a charter from nothing is the part of this work most likely to be done badly, so
the system will draft one. A helper called the **Universal Target Intake** takes a single
web address and produces a scaffolded engagement folder: a **charter draft**, a **draft
threat model**, a **draft attack tree** (the diagram of what an attacker would try, from
their goal downwards), a structured fingerprint of what the site appears to be built from,
and a starting list of pages worth attention.

It works by looking at the target very politely. It reads the site's front page and a short
list of standard, publicly-intended locations — the file that tells search engines what not
to index, the site map, the file that publishes a security contact, the standard sign-in
discovery document, and a handful of common paths such as a login page or an admin path.
Seven small detectors turn what comes back into a picture of the technology in use; that
picture is matched against nine known site shapes (a WordPress site, a shop, a modern
single-page application, and so on) to choose the most likely one, which in turn seeds the
draft attack tree.

Its restraint is written into its own documentation as a list of things it never does:

> Never logs in. Never submits forms. Never fuzzes. Never scans. Never makes more than 50
> requests per intake. Fails closed: missing authorization, ambiguous ownership, suspected
> unauthorized target → halts and surfaces to the operator.

("Fuzzes" means bombarding an input with many malformed values to see what breaks. "Fails
closed" is the drawbridge rule from the opening list: if it cannot satisfy itself that it is
allowed, it stops.)

Three properties matter for an agency reader:

- **It still refuses without permission.** The operator must first record an authorisation
  for that host, one line per host, in the intake's own ledger. A host that is not listed is
  refused before a single request leaves.
- **It cannot sign anything.** The draft is written to a file named `charter.draft.md` and
  the code will not overwrite a real `charter.md`. The operator must read the draft, correct
  it, move it into place, and sign it. Nothing active runs until they do.
- **It is deliberately slow and small.** No more than 50 requests, one at a time, with a
  pause of about a third of a second between them. Every request carries a label naming the
  software that sent it, and the label says in plain words that this is an authorised
  owner-test — so the site's own logs show who was knocking. It is a polite knock, not a
  search.

The value is that the on-ramp is not "write a legal document from scratch"; it is "check
and sign a draft". The authorisation itself is not automated, and by design cannot be.

### What the system does

The operator turns the charter into a signed permission slip with one command
(`vigil provision`). The system reads the numbered host table, builds an
**engagement authority** from it, and signs it. From that moment the authority — not the
charter text, and certainly not anything typed into a web page — is what the gates check.

The defaults are deliberately cautious:

| Setting | Default | Meaning in plain terms |
|---|---|---|
| Destructive actions | Off | Nothing that breaks, deletes or spends is permitted unless explicitly turned on |
| Validity window | 8 hours | The permission slip expires. An old slip is not a permission slip |
| Action budget | 1,000 actions | The job cannot run forever or run away |
| Empty scope | Refused | A permission slip authorising nothing is treated as a mistake, not as a free pass |

That last row matters more than it looks. If the scope table fails to parse — a typo, a
broken table — the system does not quietly proceed with an empty fence. It refuses.

### Cloud and Kubernetes are authorised differently, on purpose

If the target is a cloud account rather than a website, the charter carries an extra,
separate section. The reason is subtle and important.

Cloud services share web addresses. Millions of customers' accounts all sit behind the
same handful of Amazon or Google addresses. So authorising the *address* would
accidentally authorise every other customer in the world who shares it. The system
therefore authorises cloud work by **account identity** — the specific tenant or account
number — and the number must be written out exactly. A blank, a `*`, or the word `any`
authorises **nothing at all**, by design.

### The safety checks at this stage

- **The kill switch.** Every job has a stop button that works by creating a file on disk.
  While that file exists, every action is refused. Because it is a file and not a memory
  setting, tripping it survives a crash, a restart, or the machine being rebooted.
  Clearing it is a separate, deliberate, logged act by the operator.
  The check is also deliberately paranoid: the code treats the switch as **tripped**
  unless it can positively determine the file is absent. If it cannot read the disk, if
  permission is denied, if there is an input/output error — all of those read as
  "halted", never as "carry on".
- **The console cannot widen the fence.** The web interface has a Charter screen, and it
  can set up a permission slip for the local machine only. For a real remote target it
  *verifies* the charter and walks the operator through the out-of-band ceremony, printing
  the exact command to run — with the instruction to run it on a trusted machine that
  holds the owner's key, not in the browser. The screen structurally cannot mint or widen
  a remote permission.

---

## 3. Stage 1 — The session: what it is and what it remembers

### Why it exists

Real security work is not one command. It is weeks of work with pauses in it: a scan on
Monday, a follow-up on Wednesday, a conversation with the engine about what to try next,
a re-test after the developers ship a fix. Without somewhere to put all of that, each run
starts from nothing and the operator carries the continuity in their head.

A **session** is that container.

### What a session is, in plain terms

A session is a named folder for one line of work. It is closest to a case file. It links
together:

- the individual **runs** (each execution of the engine),
- the **conversation** with the engine about that line of work,
- a **picture** of what has been learned, rebuilt from the permanent record,
- the **open threads** — the unfinished lines of enquiry.

The engine's own description of the change that introduced it: a session "used to be only
a chat transcript", and was promoted to "a durable, renamable, deletable object the
operator manages".

Sessions are stored on the operator's own machine, in a per-session folder, with the
folder readable only by the operator's own account and the file readable only by the
operator. There is a real one on this machine right now: a session named `sess-A`, of kind
`engagement`, with 88 runs linked to it.

### What a session remembers — and what it deliberately does not

A session remembers **organisation**: which runs belong together, what the conversation
said, what is unfinished. It also owns a **knowledge picture** — a graph of what was seen
and how things connect — but that picture is a rebuilt projection, not an original. It is
recomputed from the permanent signed record of the runs. Feed the same record in and you
get the same picture out, byte for byte.

That leads to the single most important property of sessions, which is worth stating
plainly because it is a security property, not a convenience:

> **A session has no authority.** Creating, renaming, connecting or deleting a session
> changes no finding and opens no gate. The registry mints no facts, reads no permission
> level, and authorises nothing.

The graph store the session uses is built so that this is *structurally* true rather than
merely promised — it exposes no operation that could grant a permission or promote a
claim. The picture can be thrown away and rebuilt at any time, and nothing is lost,
because the signed record it is built from is untouched.

Two consequences the operator sees directly:

- **Ordering is by a counter, not by the clock.** Sessions and the events in them are
  ordered by a number that only ever increases. A wall-clock time is stored too, but only
  to sort a list on screen. This means the record cannot be reshuffled by changing a
  machine's clock.
- **Deleting is safe.** A soft delete hides the session from the list and keeps
  everything. A hard delete additionally removes the registry entry and throws away the
  rebuildable picture — but it never touches the signed record and never removes a proven
  finding.

### Connecting sessions

The operator can **connect** one session to another. This is consent to let a new run draw
on the earlier session's accumulated picture. The connected material arrives labelled with
where it came from and is treated as **advisory background only** — a hint about where to
look. It can never become a fact by virtue of having come from another session. Facts are
minted in exactly one place, described in stage 7.

A note to avoid confusion: the word "session" is also used inside the project for
something unrelated — redacted transcripts of the engineering sessions that built the
software, kept under a separate `knowledge/sessions` folder. Those are development
history, not assessments.

### Run, session, engagement — three words that are not synonyms

Three words in this chapter sound interchangeable and are not, and the interface now groups
work by all three. A reader who runs them together will misread both the screens and the
report, so they are separated here once.

| Word | What it is | How it is named | Can it change a finding or open a gate? |
|---|---|---|---|
| **Run** | One execution of the engine against one subject: a start, a finish, a status, its own findings and its own evidence. It is the only one of the three that sends any traffic anywhere. | A machine identity stamped with the date, the time and a sequence number | It is where findings are *made*. Everything the system proves, it proves inside a run |
| **Session** | The thread of work that links runs together, with the conversation and the rebuilt picture — the subject of this section. | A short name the operator chooses | **No.** Creating, renaming, connecting or deleting one changes nothing |
| **Engagement** | The named piece of client work: one authorisation over one subject, which may hold many sessions and many runs across months. It is what a charter authorises and what the final report is about. | A short machine-safe name shared by the charter, the working folder and the permanent record | **No.** The charter beneath it authorises; the name itself decides nothing |

**The engagement is the one an operator comes back to months later**, and it now has a
screen of its own — an Engagement Library listing every past job, most recently worked
first, with real dates and times, what kind of operation each was, what subject it was
pointed at, and how many runs and findings it holds, with the proven count shown separately.
Three properties of that screen matter, because each one is a restraint:

- **Nothing on it is invented.** The list is the union of two real sources: the permanent
  signed record's own roster of jobs, and the folder of charters and working material on
  disk. Every date shown is derived from something actually on disk. A job with no activity
  at all is shown honestly as having none, and is never back-dated to look recent.
- **Renaming cannot invalidate a proof.** A human name — "Acme, Q3 external review" — is
  stored in one small file beside the machine identity, and nothing on that path writes into
  a run's folder, an evidence certificate, the sealed proof bundle or the signed record. It
  rewrites nothing that already exists, so a package already delivered still verifies exactly
  as it did. One effect is deliberate: a case file downloaded *after* a run is renamed is
  titled by the human name, so the person opening it months later recognises the job. The
  proof inside is identical either way. The screen states the property on the page: renaming
  "touches no signed byte, so every certificate still verifies".
- **Membership cannot be asserted.** Which runs belong to which job is decided by what each
  run recorded about itself at the time it ran, not by anything the person browsing can
  claim. Nobody can move a run into a job it does not belong to from the screen.

From a job the operator clicks through to its runs, and from a run to its findings, its
evidence and its dossier. What the library adds is **navigation, not authority** — the same
property the session has, for the same reason.

**A fourth meaning, on the other side of the wall.** The owner's personal side uses the word
"session" for something different again: one ingested conversation with an AI assistant. The
owner's own working history is read into their permanent personal record — each conversation,
and each delegated helper's transcript as a titled session of its own — and mirrored as a
node in the owner's personal memory. Those are a record of the owner's past work, not of an
assessment. They hold no findings and touch no target, and they are different again from the
folder of development transcripts mentioned just above.

---

## 4. Stage 2 — Setting up the run

### What the operator does

There are two equivalent front doors.

**The web console.** A five-step wizard called "New Assessment", with a running plain-English
summary of what is about to happen shown alongside it:

1. **What do you want to assess?** Six choices: a codebase, a website or API (an
   application programming interface — the machine-to-machine door into a service, used by
   other software rather than by a person in a browser), a single tool run, a full
   autonomous suite, a cloud or Kubernetes posture review, or the defensive mode where the
   system sits in front of an application the operator runs and watches for attacks against
   it.
2. **Where is it?** The fields change to match the choice — a source-code path, a log
   file, a cloud account label, or a target address. Every non-defensive mode also
   requires the operator to tick a statement reading, in full: *"I am authorized to test
   this target (I own it or have written permission)."* An optional free-text objective
   can be added, labelled in the screen itself: *"Guides the reasoning; never widens
   scope."*
3. **Scope.** For a remote target, the list of authorised hosts is shown as chips. Address
   *ranges* are rejected outright with the message "No CIDR — use a literal host or a
   `*.wildcard`". As above, a range such as `10.0.0.0/8` is shorthand for millions of
   addresses at once; a range is a blunt instrument that authorises machines nobody has
   looked at, so only a named host, or a named domain with a wildcard for its
   sub-addresses, is accepted.
4. **How should it run?** Depth (quick, standard, deep), and either "let the AI choose the
   tools" or a manual pick from the real catalogue of capabilities, each labelled with its
   permission level. There is a checkbox to propose fixes after discovery, with the hint
   that fixes are proposed and queue for approval.
5. **Model and keys.** Which reasoning model to use, whether to run without any model at
   all, which session to file the run under, and — for a local target with a session
   chosen — whether the run should feed that session's knowledge picture.

**The command line.** The same job can be started with a single command
(`vigil engage <address>`), which takes the same choices as options: the engagement name,
the authorised hosts, the session, any connected sessions, an iteration limit, and whether
the operator gives standing approval for offensive tools.

### What "depth" actually changes

Depth is not a vague dial. Each setting maps to specific, published limits, and the
software refuses to go past them regardless of what the reasoning model wants:

| Depth | A remote assessment | A local test on the operator's own machine |
|---|---|---|
| Quick | 60 requests allowed for the whole run | 20 pages, and only the pages judged most likely to matter |
| Standard (the default) | 200 requests | 60 pages |
| Deep | 500 requests | 150 pages |

For a run driven through a session's accumulated knowledge, depth also sets how many
think-and-act cycles the system may take: 6 for quick, 12 for standard, 20 for deep.

These are ceilings on the *work*, sitting underneath the ceilings on the *permission* (the
8-hour window and the 1,000-action budget on the permission slip itself). Whichever runs
out first stops the run.

### The eight capability packs

When the operator turns off "let the AI choose the tools", they pick from a fixed list of
eight capability packs. Each maps to an already-gated option of the same underlying
command; the list is defined once in the software so the screen cannot invent one. Each
carries a tier label, meaning roughly how intrusive it is (T1 lightest, T3 heaviest):

("XSS" here is **cross-site scripting** — making a website serve an attacker's code to
another visitor's browser, so it runs with that visitor's privileges.)

| Pack | Tier | What it adds |
|---|---|---|
| Recon (reconnaissance) | T1 | Looks around the authorised surface — pages, parameters, what the site is built from |
| In-browser XSS leads | T2 | Reads the site's own browser-side code for places a page could be made to run an attacker's script. Produces leads, never facts |
| Browser XSS | T2 | Drives a real browser to confirm a script actually executes |
| Single-page-application crawl | T2 | Walks an application whose pages are drawn by the browser rather than sent whole by the server, which an ordinary crawler cannot see |
| Single sign-on / federated identity | T2 | Probes the standard "sign in with your other account" flows for the weaknesses specific to them |
| Access control | T2 | Tests whether one user can reach another user's data. Requires the operator to supply the second identity |
| GraphQL denial-of-service | T3 | Bounded probes of a query interface (GraphQL is a common way of letting a client ask for exactly the data it wants) that can be asked to do far too much work at once |
| Host arsenal | T3 | Runs recognised outside tools — a port scanner, a template-driven scanner — each one still passing through the whole permission stack |

### Testing behind a login

Most of a real application's surface sits behind a sign-in page. A tool that only tests the
front door reports on a small fraction of the system, so it is worth being precise about
what this one can do.

**On the command line, today, with a second identity.** The access-control pack takes an
authenticated second identity from the operator — literally the header a browser would send
to prove who it is — plus the references of the objects that identity legitimately owns. The
system then acts as the attacker and compares what it gets against what the rightful owner
sees. The software is explicit that this cannot be automated away — such a test "is
fundamentally a TWO-IDENTITY experiment (act as the attacker, compare against what a
*different* identity legitimately sees)", and of the identity and the object references it
says flatly "there is no honest way to autodiscover those". The second identity travels
through exactly the same gated channel as everything else. With no references supplied, the
pack runs nothing and says so, rather than pretending. A refusal from the application — the
correct behaviour — does not fire, so a properly protected page is never reported as a
weakness.

**Staying logged in during a scan.** There is a separate, built component that wraps the
ordinary sending channel in a signed-in session: it keeps the small pieces of data a site
uses to recognise a returning visitor, performs the login sequence, notices when the site
has logged it out (a refusal, or a "you are signed out" marker in the page), and signs in
again before retrying. The crawler and the testing engine both accept it in place of the
plain channel, so both then work as a logged-in user. It adds no new permission: it sends
only through the same scope-checked, kill-switch-checked channel.

**The honest boundary.** That login-session component is built and covered by tests, but in
the version read for this briefing it has no caller on the standard run path, and the
five-step console wizard has **no field for a target application's test credentials**.
Reaching it today means driving the engine as a software component rather than through the
wizard. An agency planning an authenticated assessment should expect to use the command
line and supply the identity there, and should treat "point the wizard at it and it will log
in for you" as not yet true.

### What the system does

Launching from the console does **not** run a special privileged path. It spawns exactly
the same gated command the operator would have typed. The code that handles the launch
says so directly: it "cannot relax scope (scope is charter-signed, never an argument here)
nor bypass a gate".

This is worth restating because it is the difference between a real control and a
decorative one: **the scope typed into the browser is never passed to the engine.** It is
validated for honesty and displayed, and then discarded. The fence the engine actually
enforces is the one signed into the charter.

The authorisation tick-box in step 2 is a deliberate act of attention by the operator — it
disables the Launch button until it is ticked. It is not itself the authorisation. The
authorisation is the signed charter.

---

## 5. Stage 3 — Pre-flight: before a single packet leaves

### The usage record is written first

Before any action against a target, the system writes a signed record of **who, when and
what** — the operating-system login, the configured name and email, the operator key
fingerprint, the machine name; the time, plus a counter that can only ever go up; and the
action, target and phase.

If that record cannot be written — no signer available, an unbound operator, a disk
failure — the engine receives a refusal and **cannot proceed**. There is no "run now,
record later".

The counter is what stops back-dating. A record can never be inserted claiming to be older
than one already there. The whole chain of records can be re-checked afterwards
(`vigil verify-ledger`), and the system is honest about the one thing that check cannot do
on its own: because a valid *prefix* of a chain is internally consistent, checking the
chain alone cannot prove that the most recent records were not deleted. To catch that, the
operator pins the expected head and count somewhere outside the system, and the check is
run against those.

### Every single action passes a chain of gates

Each individual action — every tool run, every request — must satisfy **all** of the
following. The first failure wins, and any error anywhere is treated as a refusal.

1. **The engagement authority**, checked in this order: is the kill switch tripped? Is the
   permission window still open? Is this target inside the scope? Is this action
   destructive, and if so is destruction permitted? Is it destructive against a live
   system without a second acknowledgement? Is the action budget spent?
2. **The permission tier** (described next) must come back as an explicit "auto". Anything
   else — including an answer the gate does not recognise — is a refusal.
3. **For destructive actions only**, a threshold authorisation: several distinct
   authorisers must have signed, and one of them must be the owner.

### The four permission tiers

Every action the system might take is classified into one of four tiers by a single
classifier of record. It is written twice — once in Rust, the language the small fast core
is built in, and once in Python, the language the rest of the system uses. The two copies
are pinned to one shared file of known questions and their correct answers, so they cannot
drift apart and quietly start disagreeing.

| Tier | What belongs here | What happens |
|---|---|---|
| **A0** | Known-safe looking and answering: read, search, list, view, inspect | Runs automatically |
| **A1** | Reversible internal writing: draft, note, report, commit to a branch | Runs automatically |
| **A2** | Externally visible or half-reversible: send, publish, upload, export, download | Queues for the operator |
| **A3** | Destructive, financial, or touching dangerous material — secrets, credentials, keys, identity policy, firewalls, production, administrator accounts | Requires explicit, signed authorisation every time |

Three mechanical details make this hard to fool:

- Classification splits the action name into **whole words**, so "overwrite" is not read
  as "write" and "forget" is not read as "get".
- **Danger is checked first**, and anything not positively recognised falls to the
  strictest tier. Unknown means dangerous, not safe.
- The word-splitting also splits on invisible control characters, so a hidden character
  cannot be used to smuggle a dangerous word past the check.

For offensive work specifically, the ceiling is set to A1 by default. Because the ceiling
is A1, **anything classified A2 or A3 queues for the owner and can never run by itself.**
A curated list of harmless reconnaissance tool names stays eligible to run automatically;
everything else queues.

### How an approval actually works

There are two modes, and the difference in assurance is stated openly in the code.

- **Standing approval** — one option that blanket-approves every queued action for the
  whole run. Lower assurance, and honest about it.
- **Per-action signed approval** — the default for offensive tools. The operator's
  signature covers the exact tool, the exact target, and a short fingerprint computed from
  the exact action — a code derived from the whole of it, which changes completely if any
  part of it changes. It is checked against an owner key fixed at deployment time. It expires within a bounded
  window, so a pre-signed "sleeper" approval left lying around is void. And it is
  **single-use**: the record of use is created with an operating-system primitive that
  guarantees exactly one of many simultaneous attempts can win.

One property is worth spelling out for a reader worried about an over-eager approval
process: **an approval never widens the fence.** It only satisfies the human half of the
gate for an action that the authority check has already found to be in scope. If the
authority check says no, an approval does not change it.

### The network fence

Two layers stand between an offensive tool and the outside world, both driven by the same
scope:

- A **deny-by-default firewall**. From inside the tool sandbox, everything is dropped
  except the system's own proxy and its own name resolution. Cloud metadata addresses,
  link-local and reserved addresses are hard-dropped.
- A **checking proxy**. For each connection: the host must be inside the charter scope;
  the name is resolved once; if any resolved address is on the deny list the connection is
  refused; and the exact validated address is then pinned for the connection, so the
  answer cannot be swapped between the check and the connection.

The deny list is a single shared source of truth, and it deliberately covers the several
ways of disguising one internet address as another, so that a well-known trick for reaching
the address at which cloud providers hand out account credentials does not slip past. (An
internet address can be written in more than one notation, and a check that recognises only
one spelling is bypassed by using another. This one recognises them all.)

### One categorical floor, stated honestly

The codebase also contains a **hard guardrail**: a list of categorically-never targets
(government, military, educational and intergovernmental domains), evaluated with no
artificial intelligence, no network and no settings involved, and written so it cannot be
switched off. Its stated purpose is that an attempt to manipulate the AI through poisoned
text, or an operator's typo, can never redirect an autonomous agent at, say, a government
host.

Honest note for a reader in a national agency — three things, plainly:

1. **It is built and tested, but its live wiring is not proven.** The component exists and
   has its own tests, and it is a "deny only" rule that never authorises anything. In the
   reading done for this chapter, no live call site was found on the running assessment path
   outside the safety package's own exports. It should therefore be described as a built and
   tested safety component, not as a proven live block. The controls definitely on the live
   path are the signed charter scope and the two-layer network fence above.
2. **As written, it would refuse to test a government estate.** The block works on the name
   of the target, not its numeric address, and it covers `.gov` and its national equivalents,
   `.mil`, education domains, and a list of named intergovernmental organisations.
3. **So an agency assessing its own systems has to deal with it deliberately.** The module
   takes no configuration and has no off switch; changing the behaviour means changing the
   code and re-releasing it, as a visible, reviewable act. This chapter does not pretend
   there is a supported setting for it, because there is not. Chapter 8 covers this
   component in full, including exactly which endings it matches and how it resists
   look-alike spellings; an agency should settle the question there before planning a
   domain-named engagement against its own estate.

---

## 6. Stage 4 — Discovery: finding out what is there

### Passive discovery: asking about the target, not touching it

The first pass gathers what is publicly knowable without touching the target at all. The
sources are public, third-party, passive services: a name-resolution service reached over
an encrypted web connection, a certificate transparency log (the public register of
issued web certificates), the domain registration lookup service, and a routing statistics
service.

The wording in the code is precise about the distinction: these sources "are queried
**about** the target; they are never the target."

Three safety properties:

- Live collection is a **deliberate opt-in**, not a default and not a one-click button in
  the console. The console's own intelligence panel ingests bundled offline examples only,
  and says so on screen: *"Live collection is a charter-gated engagement decision, never a
  one-click button, so this control cannot egress."*
- The transport used for live collection has an allowlist containing exactly those source
  addresses, and it **refuses to even be constructed** if that allowlist overlaps the
  target scope. The reconnaissance channel and the attack channel cannot be the same
  channel.
- Every response handler is **total**: malformed or unexpected data yields "found nothing",
  never a crash and never an invented answer.

Responses can optionally be mirrored to disk, so one authorised live collection becomes a
permanent offline example set for deterministic replay afterwards.

### Choosing where to look next

Reconnaissance has a budget, and different sources cost different amounts and pay off
differently. The system ranks each possible next query by **how much it expects to learn
per unit of cost**. This is not "run the cheapest source": a source we are already
near-certain about scores low even when it is cheap, and an uncertain expensive source can
outrank it. Where prior engagements have recorded which sources paid off against similar
targets, those priors feed in. The planner itself fetches nothing; it produces an ordered
list, and something else executes it.

### Turning a discovered asset into a place to look

A discovered domain or host sits in the knowledge picture but is not automatically
something the testing loop will touch. A separate, explicit step promotes an in-scope
asset into a **place to look**. Three properties are enforced:

1. **In scope by construction.** A host is promoted only if it matches the signed charter
   scope using the *exact same test* that the per-request gate will apply later. And this
   narrowing is defence in depth, not the authority: every probe against a promoted
   address is still re-checked at the gate.
2. **A lead, never a fact.** The promoted item carries a label recording where it came
   from — its provenance — marking it as intelligence. It is "a place to LOOK, not a
   finding".
3. **Deterministic and off the gate path.** The promotion is a pure calculation over the
   knowledge picture and the parsed scope.

### Active discovery: walking the application

For a web target, a crawler walks the application from a starting address: fetching pages,
parsing out links and forms, resolving them, checking them against scope, and turning them
into requests the testing engine can use.

Four design choices make it a real crawler rather than a decorative one:

- **Locations, not addresses.** A page is remembered by its method, host, path and the
  *names* of its parameters. So `?id=1` and `?id=2` are one location. This avoids the
  classic trap where a crawler drowns in a calendar or a list of identifiers, while still
  finding each genuinely distinct page once.
- **Scope is enforced during the walk.** Off-host links and non-web links are never
  fetched and never queued, so a crawl of an authorised target cannot wander onto a third
  party.
- **Forms become requests.** A form is parsed into its method, its resolved destination
  and its filled-in fields, so surface reachable only through a form is tested too.
- **Bounded and predictable.** The walk is **breadth-first**: it visits everything one step
  from the starting page, then everything two steps away, and so on — rather than following
  the first link as deep as it goes before coming back. That means a shallow, wide site is
  covered evenly instead of the crawler disappearing down one corridor. Links are followed
  in the order they appear in the page, no clock and no randomness are consulted, and there
  are hard limits on how many pages and how many steps out it may go (by default, 200 pages
  and 8 steps for the component itself; a run started from the console sets lower numbers
  still). Because nothing in it is random, two runs over the same site walk it the same way.

In parallel, a reconnaissance agent probes paths and writes down **observations**. It is
explicitly not allowed to exploit anything, and it works within a request budget.

---

## 7. Stage 5 — Mapping: building the picture

Everything observed goes into a persistent, typed picture of the target — the **world
model**. It answers one question: *given what we have observed, what is now reachable, and
by what explainable route?*

The motivating example, from the code's own design notes, is a chain like this: a web
address leaks a credential; the credential is valid for a particular identity; that
identity can assume a cloud role; that role fronts a database.

Two rules are non-negotiable in that picture:

1. **Every fact carries where it came from and how confident we are.** Provenance is the
   identifier of the observation that asserted it. Confidence is a number between 0 and 1.
   A whole path is only as strong as its weakest link, and the chain of provenance travels
   with it — so an attack path is auditable rather than merely asserted.
2. **Time is a counter, never a clock.** The picture never reads the machine's time, so
   merging, ordering and every query are deterministic and replayable: the same inputs
   always produce the same result.

Re-observing something never lowers the confidence in it, and the higher-confidence
assertion donates its provenance.

Alongside the mapping, a hypothesis agent watches for new observations and generates
**at least five hypotheses per observation**. This is a deliberate forcing function drawn
from the project's own written doctrine: the class of weakness most testers miss is the one
they never thought to look for. The hypothesis agent proposes; it confirms nothing.

---

## 8. Stage 6 — Testing

### What the engine actually does

Given one request, the audit engine enumerates every place an attacker could insert
something — each parameter, each path segment, each header, each form field — and fires
every applicable test into each of them, then hands the responses to the confirmation
layer.

The engine sends nothing itself. The thing that sends is injected into it, and in
production that is the scope-checked, charter-checked, kill-switch-checked, rate-limited
executor. So the authorisation stays enforced no matter what the engine decides to try. A
request budget bounds the whole sweep so an autonomous run cannot blow up.

### What it tests for

**Eleven seed tests always run.** These are the always-on core, verified by reading the
source. Each is given here with what it means in ordinary terms:

| Test | The weakness it looks for, in plain words |
|---|---|
| Boolean-inference database injection | The system asks the site a question whose answer is true, then one whose answer is false, and sees whether the page changes. If it does, the site is letting an outsider steer its database queries — even though it never shows an error |
| Reflected cross-site scripting | A harmless marker is sent in and comes back inside the page in a place where a visitor's browser would execute it. That means an attacker can make a page run their code in someone else's browser |
| Template-expression evaluation (two forms) | Pages are usually assembled from templates with blanks filled in. If a sum written in the template's own notation comes back *worked out*, the server evaluated the visitor's input as instructions. Two common notations are tested, `{{ }}` and `${ }` |
| Path traversal | An input that names a file is nudged to point outside the folder it should be confined to, to see whether the server will hand back files it was never meant to serve |
| Error-based database injection | A deliberately malformed input makes the site print a database engine's own error message, which both proves the injection and identifies the database |
| Open redirect | The site is asked to bounce the visitor onwards to another address. If it will bounce them anywhere, it can be used to make a phishing link look like it belongs to the organisation |
| Server-side request forgery (call-back) | The site is asked to fetch something from a chosen address. If the server itself makes that call, an outsider can use it to reach the organisation's internal network |
| External-entity injection (call-back) | Uploaded structured data is given an instruction to go and fetch an outside file. If the server obeys, it can be made to read local files or reach inward |
| Remote code execution (call-back) | An input is shaped so that, if the server pastes it into a command, the server will run a command of the attacker's choosing |
| Unsafe deserialisation (call-back) | Data the server unpacks back into working objects is given a booby-trapped entry that reaches out when unpacked — the family that made the Log4Shell incident famous |

(The table has ten rows for eleven tests: the template-expression row is two separate tests,
one for each notation.)

The last four are **call-back** tests. They are called that because the proof is not
anything you can see in the reply; the proof is that *something contacted infrastructure the
tester controls*. Their status is covered next, because it is a real prerequisite an
operator must plan for.

Beyond the eleven:

- **172 further tests are defined as data**, not code, in a library of description files.
- **85 canonical categories of weakness** are recognised — "canonical" meaning one agreed
  master name for each — and each is mapped to the mechanical checks that are allowed to
  confirm it. A further 190 alternative spellings map onto those master names, so a finding
  cannot be double-counted under two vocabularies.
- Additional modules exist for specific surfaces — modern single-page applications,
  application programming interfaces of the GraphQL kind, single sign-on, race conditions,
  request smuggling, access control, business logic — and are engaged when the relevant
  surface exists.

### The call-back relay: a prerequisite worth knowing before you start

Four of the eleven always-on tests can only be proven by an inbound contact. The system
therefore has to own something for the target to contact.

By default it runs a tiny receiver on the operator's own machine, on an address no other
machine can reach. This works perfectly when the thing being tested is running on that same
machine — which is exactly the case in the local validation the project reports. It cannot
work against a genuinely remote target: a remote server told to fetch "the address this
computer uses to talk to itself" will contact *itself*, not the tester.

For remote work, the system ships its own relay — the sovereign equivalent of the hosted
"collaborator" service that commercial testing tools rent to their customers. The operator
runs it, with one command, on a machine they own; that machine must itself be listed in the
signed charter, and the engagement runner **refuses a relay host that is not in scope**.
The relay only records who contacted it and on which one-time token; reading those records
requires a shared secret, compared in a way that does not leak it; and the scanner refuses
to talk to a remote relay over an unencrypted connection, because the secret and the
recorded contacts must not cross the network in the clear.

The consequence for planning is concrete, and worth stating baldly:

> Against a remote target, if the operator has not stood up a relay on a charter-listed
> machine they own, those four tests do not run. They are **skipped, never guessed** — the
> report will not claim the weaknesses are absent. But an agency that runs a remote
> assessment, sees no server-side request forgery and no remote code execution findings, and
> concludes the application is clean of them, has misread the result.

One further limit, disclosed in the code rather than hidden: the relay covers contacts that
arrive as ordinary web requests. A weakness that only causes a name lookup, with no web
request following, needs a name-service-capable relay, which is documented as a future
extension and is not silently implied.

### Two further ways of testing, both built, neither on the default path

The eleven seed tests place one fixed input per weakness class. There are two other tools in
the box, and honesty requires describing both their capability and their current wiring.

**The fuzzing engine.** Its purpose is the other axis: instead of one input per class, it
sends *many* inputs across marked positions in a request — a list of candidate values,
number ranges, brute-force sequences, flipped bits, altered capitalisation, dates — and then
finds the one response that does not look like the others. In commercial tools that final
triage is done by a person scrolling a table of hundreds of rows; here an outlier detector
does it automatically, so brute-force, enumeration and race-condition attacks run without a
human eyeballing results. It sends only through the same gated channel and stops at a
request limit so an automatic fuzz cannot run away.

**The replay tool.** This is the equivalent of the single most-used manual instrument in
professional testing: capture one request to an in-scope target, edit it by hand, and send
it again. Here it is framed defensively. It never opens a raw network connection of its own;
every replay goes through the same permission chain as everything else. It requires an
offensive-tier grant to run at all; the target is scope-checked twice, at the point of asking
and again at the point of sending; a tripped kill switch, a missing grant or an out-of-scope
target refuses the replay and the refusal is recorded as evidence. It forces the system's own
recognisable identifying string onto the request and strips any the operator supplied — the
doctrine is "correlatable, not evasive", so the owner can always find this traffic in their
own logs. And what comes back is an observation, never a finding: it becomes a fact only if
a checker re-confirms it.

**The honest status of both.** In the version read for this briefing, neither is driven by
the default run. The fuzzing engine's payload vocabulary *is* used on the live path — the
component that decides which family of inputs to spend the next request on draws from it —
but the fuzzing engine itself has no caller outside its own tests. The replay tool's own
documentation says it plainly: it is "OFF the scanner-benchmark path and imported by nothing
in the default engage/scan flow — it is an opt-in operator/engine capability". Neither has a
screen of its own or a command of its own. They are built, tested, and gated by construction;
they are not yet a button an operator presses.

### The outside agent, and where it fits in a job

Everything in this stage so far is the engine's own machinery: fixed tests, fired by fixed
code, into positions the mapping stage found. One of the four named parts of the system is
not like that at all. It is a complete third-party penetration-testing agent — somebody
else's product, kept as a copy inside this one — that works the way a human tester works:
think, choose a tool, run it, read what came back, go round again. Chapter 2 describes what
it is, what is in its toolbox and where it runs. This section places it in the job: when an
operator reaches for it, what a run using it looks like, and what its output is worth.

**When an operator reaches for it.** There are two routes to it, and they are not the same.

| Route | What it starts | What it is for |
|---|---|---|
| The **"scan a codebase"** choice in the assessment wizard | The agent, running without a terminal display, pointed at a folder of source code on the operator's machine or at a repository address, with the operator's written objective handed to it as its instruction | A body of source code. The engine's own tests need something that answers on the network — an address to walk, forms to fill, parameters to nudge. Source code answers nothing, so the fixed tests have nothing to fire at |
| The **passthrough command** | The vendored tool directly, in the offensive environment, with the operator's own arguments passed through untouched | Anything the operator wants to point it at. The tool itself accepts a web address, a domain name, a numeric network address, a repository or a local folder. The wizard offers only the source-code case; the command line offers the rest |

Its planning is genuinely its own. It decides which classes of weakness to hunt, and it
spawns its own helper agents to hunt them in parallel. The system does not constrain that
choice at all. What the system constrains is the moment anything is **executed** — which is
the subject of the gate described two paragraphs below.

**What a run with it looks like.** Not like an engine run. Four differences meet the
operator immediately:

- **It needs a container.** The agent will not run without one, and the console checks for
  the container system before starting rather than hanging: if it is not running, the run is
  refused with a message saying so. The container is built from a Kali Linux base pinned to
  an exact content fingerprint rather than a moving label, so two builds a week apart cannot
  quietly ship different tools into the box that executes offensive actions.
- **It costs model time.** The agent is driven step by step by a large language model, and
  every step of the loop is a call to it. The models it names as recommended are all
  commercial hosted ones, so in the default configuration every step costs money; the
  settings screen can route it to a different provider. The engine's own measured
  11-second benchmark run, quoted below, used no artificial intelligence at all. These are
  different cost shapes and an agency budgeting for both should not average them.
- **There is no live picture.** An engine run streams every action onto the Live screen as
  it happens. This one reports inside its own sandbox, and the run is recorded as having no
  stream at all. Rather than show an empty timeline, the interface says so: *"a codebase run
  reports inside its sandbox — no re-checkable web report is captured here."*
- **Its findings do not land on the permanent signed record.** That has a visible downstream
  consequence, and the system does not paper over it: the automated repair ladder in stage 10
  **refuses** to act on such a run, and its refusal names exactly what is missing and what
  would produce it — the same job run through the engine's own governed path, which does
  write the signed record.

**What it produces are leads, not facts.** This is the single most important sentence about
it, and chapter 2 explains the mechanism. The operational consequence is what matters here: a
person reading the agent's own report is reading **suspicion**, and the number of things it
reports is not the number of things proved. Nothing it writes is carried into the assessment
report as a finding on its own word. The system's own deployment guidance instructs the
operator to treat its results as investigative leads to confirm.

**One thing it does can cross into proof, and it is not anything it says.** The distinction
is between the agent's narrative — its account of what it did and what it concluded, which
nothing can re-check — and a *demonstration*, meaning something that actually performs the
attack against the target. When a demonstration runs, the capture machinery records what the
target itself sent back: real response bytes, attached by the capture path and never by the
model. Those bytes are screened for dangerous content first, and then handed to a checker
exactly as any other evidence would be. If the checker fires, the result is a fact and
crosses into the signed record; if it does not, the honest answer is recorded — not
reproduced — and it stays a lead. The operator sees the three outcomes counted on the Proof
Studio screen, one card per attempt, and the offline-verifiable bundle can only be exported
when at least one fact exists. Two limits belong with that: the automatic capture works by
correlating the exchange out of the intercepting proxy's own records, so the proxy has to be
in the loop for it to happen, and **no run of this agent has been performed on the machine
this briefing was written on** — no run of that kind appears in the console's stored history.
One obstacle that used to stand in the way is gone: the sealed working environment such a run
requires had never been built anywhere, and could not have been built from the instruction the
project published, and it has since been built here for the first time. So what is missing now
is the run, not the means to start one. The route is built and tested. It has not been
exercised here.

**Its shell is the most dangerous surface in the system, and the gate in front of it fails
closed.** Everything the agent does that runs a program — every command-line tool it invokes,
the browser it drives — passes through one thing: a shell that can run any command at all.
The project treats that as the most dangerous surface anywhere in the system, and gates
exactly it. Every call to that shell is classified at the top danger level, which means it
never runs automatically: the exact command is published as a pending request, and it runs
only if the owner signs a single-use approval bound to that exact command. The agent's
other built-in tools — its notes, its to-do list, its report writer and its skill loader
among them — are left to run freely, so the agent stays useful rather than frozen. If no
approval authority has been set up, the shell call is refused. And the waiting window is zero
by default, which has a blunt practical meaning worth stating: **an unattended run of this
agent gets nothing past the shell gate.** The operator either watches it and signs, or sets a
waiting window deliberately.

Stated precisely, that gate covers **arbitrary command execution**, which is not the same as
covering everything. Chapter 8, section 4.5 names every tool it leaves running automatically;
most of them are inert — private reasoning, notes, a to-do list, a report writer. Three are
not inert: they act outside the agent's own head without an owner's signature, and an agency
assessing this system is entitled to know what bounds each one instead.

| The tool that bypasses the shell gate | What bounds it instead |
|---|---|
| A web search | The container's network arrangement described in chapter 2 |
| A replay of an already-captured request back at the target, through the intercepting proxy | The same network arrangement, and the fact that the request was already captured |
| A patch tool that edits files directly | The container: the agent is given this file-editing capability unconditionally and it is classified as safe to run automatically, so it writes without an owner's signature — but it writes inside the agent's own container, not on the operator's machine |

The shell gate is a gate on running programs, not a gate on everything the agent can do.

The fail-closed part is the one to hold on to. If the gate cannot be attached at all — a
wiring fault, a broken installation, anything — the run **stops**. It does not carry on
ungated. The code gives the reason in one line:

> A broken gate is not an opt-out; the run stops instead.

There are exactly two ways a run proceeds without the gate, and both are deliberate: an
explicit setting that switches it off, and running the outside tool entirely on its own,
outside this system, where there is no governed run to protect. Chapter 8, section 4.5 sets
the mechanism out in full.

### How the system decides what to try first

There is a learning component that ranks which test is most likely to land on a target that
looks like this one. It uses a standard technique for balancing "do the thing that has
worked before" against "try something we know little about" — the same problem a doctor
faces choosing between a proven treatment and a promising new one. Each possible test keeps a
running tally of how often it has found something. Before each choice, the system draws one
plausible success rate for each option from that tally, and picks the highest draw. Options
with a good record are chosen often; options with a thin record still get their turn. The
tally is updated only from mechanically-confirmed outcomes.

Three limits are enforced on that learning and stated in the code:

- Every draw comes from a random-number source that is **handed in**, not a global one. The
  same records and the same source produce the same choice, so the run is replayable.
- Learning about one kind of target never moves the numbers for another kind.
- Most importantly: the learner **orders effort**. It "never gates a surface or promotes a
  finding". It can change what is tried first. It cannot decide that something is true, and
  it cannot decide that something need not be tested.

### What the operator sees while this happens

The console's Live screen shows every action as it happens: a status line, an elapsed
timer, a stop button, and four counters — actions, facts, leads and refusals. Alongside
those runs a reasoning diagram in seven lanes (observe, orient, plan, act, result, finding,
review) and a filterable timeline.

Clicking any row opens the full detail, including the raw record. A lead carries an
explicit note on screen: *"A LEAD is a proposal. It becomes a FACT only when a
deterministic oracle re-executes and confirms it."*

Two controls sit on this screen: **Stop run**, which trips the kill switch for that
engagement, and **Approve / Deny** for each pending approval.

There is also an inbox tab showing messages passed between agents. It carries its own
banner: *"Advisory coordination only. These are agent-to-agent messages — NOT evidence. No
fact-building path reads them."*

### What a real run costs: time, traffic and money

Buyers ask three practical questions that a description of the machinery does not answer:
how long does it take, how much traffic does it make, and what does the artificial
intelligence cost. Here is what can be said honestly.

**One measured number exists, and it is small.** In the project's own signed benchmark, run
on this machine against a purpose-built vulnerable application with eleven planted
weaknesses and five deliberately clean controls, the engine finished in **11.1 seconds**
using **38.9 megabytes** of memory, found all eleven, and raised nothing on any of the five
clean controls. For comparison, on the same application on the same machine, one established
tool took 12.4 seconds and another 8.3. Three caveats belong with that number and are stated
in the benchmark document itself: the application is deliberately small (the walk is capped
at 25 pages, four steps deep), that run used **no artificial intelligence and no call-back
relay** — it is the deterministic scanner alone — and the comparison is a demonstration of
soundness on a home-built course, not a claim of general superiority. It is a real
measurement of a small target. It is not an extrapolation to a large estate and should not
be read as one.

**For anything larger, the honest answer is arithmetic, not experience.** The system's
speed is dominated by two things the operator sets: how many requests it may send, and how
fast it is allowed to send them. The pacing comes from the engagement's declared **posture**
— a deliberate choice, ticked in the charter itself, about how much load to place on
someone's live system. Worth knowing: if no posture is ticked, the system uses TEST, which is
the **fastest** of the three. It assumes the target is a machine that exists to be tested. An
operator pointing the system at a real production service should tick AUDIT deliberately
rather than rely on the default.

| Posture | Minimum gap between requests | Requests per second | 200 requests takes at least |
|---|---|---|---|
| TEST — a system that exists for testing | 0.2 seconds | 5 | about 40 seconds |
| AUDIT — a real system, treated gently | 1 second | 1 | about 3.5 minutes |
| EMULATE — imitating a real adversary's tempo | 5 seconds, plus up to 3 more at random | roughly 1 every 6.5 seconds | about 22 minutes |

Multiply the row by the depth setting to get the floor. A **quick** remote assessment is 60
requests; **standard** is 200; **deep** is 500. So a deep assessment in the gentle AUDIT
posture cannot finish in less than about 8 minutes of pacing, and a deep assessment at real
adversary tempo cannot finish in less than about 54 minutes — before the target's own
response time, which is out of the system's control, is added. Those are floors, not
forecasts.

**Throughput is bounded on purpose, at several levels at once.** The permission slip caps
the whole engagement at 1,000 actions by default and expires after 8 hours. The sending
component caps a single engagement at its request budget and records every refusal when the
budget runs out. The crawler caps pages and depth. The intake helper caps itself at 50
requests. None of these are performance tuning; they exist so that an autonomous run cannot
quietly become a load test on somebody's production system.

**The artificial-intelligence cost.** Three things are true and should not be blurred:

1. **The system can run with no model at all.** The wizard has an option for it, and the
   scanner that produces proven facts needs no model to work — as the benchmark above
   demonstrates. An organisation that wants zero external AI spend, or zero data leaving its
   own network, can have it, at the cost of the reasoning that decides what to try next.
2. **When a model is used, the number of calls is bounded by the run, not by the target's
   size.** A run driven through a session's accumulated knowledge takes at most 6, 12 or 20
   think-and-act cycles depending on depth, and each cycle is roughly one reasoning call plus
   at most one action. Each reply is capped at about 4,000 word-pieces — the units a language
   model counts in, and the units providers charge for.
3. **The system does not meter money.** This is the honest gap. There is no cost tracking in
   currency anywhere in the code that was read for this chapter. The console's "Budget today"
   tile counts **actions per agent**, not spend. An organisation that needs a hard financial
   ceiling must set it at their model provider's account, not inside this product. What the
   product bounds is work — actions, requests, cycles, pages, time — and it bounds that
   tightly.

---

## 9. Stage 7 — Confirming: the moment a claim becomes a fact

This is the heart of the system, so it is worth going slowly.

### The mechanical checker

The component that turns a suspicion into a proven fact is a set of small, strictly-bounded
checking functions. Their contract is written into their own documentation and holds for
every one of them:

> pure · deterministic · no input/output · no clock · no random numbers · offline.

In ordinary words, that list means: a checker works only from what it is handed; it gives
the same answer every time; it cannot read or write anything on the machine; it cannot look
at the date; it does not roll dice; and it needs no network.

They do not send traffic. They do not talk to the target. They examine evidence somebody else
already collected. Give the same evidence to the same checker and you get the same verdict,
today, next year, on somebody else's laptop.

The analogy is a laboratory. The scanner is the nurse who takes the blood sample. The checker
is the assay — the laboratory test itself. The test never meets the patient; it examines the
sample. And because the sample is kept, the test can be run again by anyone.

There are **38 such checkers** in the version of the software read for this briefing,
verified by counting them in the source. They cover things like: two responses being genuinely
distinguishable; a unique marker reaching somewhere it must never reach; a marker landing
in a position where a browser would actually execute it; a real browser genuinely running
injected code; a server having genuinely evaluated an injected expression; a
database-engine-specific error message that a control page does not also produce; a
statistically valid timing difference; a completed network handshake; a genuinely
negotiated weak encryption setting; a version provably inside a published advisory's
affected range; a real permission path re-derived by walking the retained policy graph.

Several deliberately narrow themselves. A few examples, quoted in spirit from the source:

- The timing checker is worth describing in full, because it is a good illustration of the
  discipline. Some weaknesses show up only as a delay: an attacker cannot see the answer, so
  they make the server pause for a few seconds when the answer is "yes". Common tools declare
  a finding when one response is slower than a fixed number of seconds — which is why they
  raise false alarms on a busy network. This checker instead needs **three** things at once.
  First, a proper statistical test showing the delayed requests really are slower than the
  ordinary ones, at a strict threshold (a one-in-a-hundred chance of being fooled by luck),
  using a method that makes no assumption about how network delays are shaped. Second, an
  **effect-size floor**: the measured difference must be at least half of the delay that was
  deliberately injected (or a quarter of a second where the injected delay is unknown). A
  difference that is statistically real but tiny — ordinary network drift — is refused, and
  the measure used resists a single slow request manufacturing an apparent shift. Third, and
  optionally, a **dose-response** check: ask for a two-second delay and a one-second delay,
  and the observed difference must roughly double. A slow proxy adds a constant amount and
  cannot fake that. It needs at least five measurements on each side before it will speak at
  all.
- The reflection checker fires only when the marker comes back in a place a browser would
  actually *run*. If the site sends it back neutralised, inside a comment, or as plain
  visible text, the checker correctly stays silent — the marker came back, but it could not
  do any harm there.
- The error-signature checker requires a control page that does **not** show the same
  error signature. So an application that prints its internal error details on every page,
  including undisturbed ones, does not become a finding.
- The call-back checker fires only on an inbound contact carrying that specific finding's
  own one-time secret word. Contacts without it — passing internet noise, another test's
  traffic — do not count.
- The network-reachability checker deliberately refuses to raise its own confidence on the
  grounds of which port it dialled, because that would be using its own choice as evidence
  for its own conclusion.

### The rules around the checkers

- **A finding is confirmed only if at least one applicable checker fires at 0.70 confidence
  or above** — verified in the source.
- **No checker may claim certainty.** Confidence inside a checker is capped at 0.99.
- **A missing input is a skip, never a pass.** If the evidence a checker needs is absent, it
  simply does not run. It never assumes.
- **A silent checker cannot veto a firing one.** A non-firing checker is recorded as dissent,
  never as a refutation.
- **An unrecognised category of weakness can never be confirmed**, even if a fallback checker
  fires — and the refusal says so loudly in its own reasoning text.
- The fallback set used for unrecognised categories is **frozen at the original 15**. Every
  checker added since is reachable only through an explicit mapping. This means adding a new
  checker cannot silently change what an ordinary scan does.

### The four words the system is allowed to say

The verdict vocabulary is a closed list of exactly four. "Only these four appear" is a
property of the type system, not a convention.

| Verdict | Plain meaning | What it takes to say it |
|---|---|---|
| **FACT** | We proved it | A mechanical checker re-derived it over evidence the system itself captured through a gated channel, and the certificate re-checks offline |
| **LEAD** | Something suggests it; we did not prove it | Any weaker signal — a third-party tool's assertion, a heuristic, an artificial intelligence's opinion |
| **CLEAN** | We proved it is *not* there | A real observation channel existed, the evidence was meaningfully available, and a conclusive checker refuted it |
| **INCONCLUSIVE** | We could not tell | Everything else — a first-class answer, never rounded towards CLEAN |

Both FACT and CLEAN are explicitly bounded observations about a moment in time, not
timeless properties of the target.

Three anti-forgery properties of the admission step deserve mention:

1. An admitted verdict **can only be created inside the admission function**. An earlier
   review found that carrying the authorisation as an ordinary field let a copy operation
   forge a FACT with a valid token attached; the authorisation was therefore moved
   somewhere a copy cannot carry it. Direct construction, copying and serialising all
   raise an error.
2. Preconditions are checked per evidence window and per observation. A precondition that is
   declared but simply absent from the observation counts as **not held** — "an unknown is
   not a yes".
3. Combining several results is conservative: any FACT makes the group a FACT; failing
   that, any LEAD makes it a LEAD; failing that, any INCONCLUSIVE wins; only if everything
   is CLEAN is the group CLEAN. **An empty set combines to INCONCLUSIVE, not CLEAN** —
   because "nothing examined is not the same as nothing found".

### What the artificial intelligence is allowed to do

The reasoning model proposes. It never confirms. Three specific rules:

- To mint a fact, the checker must have fired at 0.70 or above, **and** the weakness category
  must be one with a mapped checker, **and** the evidence must carry a provenance of either
  "reproduced" or "live re-drive". Evidence whose provenance is the model itself is
  **demoted to a lead even when the checker fires** — because evidence the model shaped is a
  route to a fact that runs through the model.
- Output from the local terminal or from an agent is advisory only and never enters the
  checking path at all.
- Where a claim came from a dry run, any ground that is not independently re-executable is
  stripped from it.

### Adversarial review before promotion

Every finding is reviewed by a critique agent before it is promoted. The agent walks the
provenance chain backwards from the result to the action to the hypothesis, and marks the
finding accordingly. This step is explicitly described as **not optional** — "the guard
against confident hallucination".

There is also a panel of differentiated mechanical critics. Their verdict type is
`endorse | object | abstain`. There is deliberately **no `confirm`**. Critics can advise,
object more strongly, or abstain — and when they disagree, the aggregate abstains rather
than asserting through the disagreement.

### The sealed evidence bag

Every confirmed finding retains the exact evidence the checker examined. From that, a signed
**evidence certificate** is produced. It is sound only if all four of the following hold:

1. **Authenticity** — several signatures, made over the content written out in one agreed,
   character-for-character form, so that two people signing the same thing sign identical
   bytes.
2. **Binding** — the fingerprint of the evidence recorded in the certificate matches the
   evidence actually presented, so a genuine signature cannot be lifted off one set of
   evidence and attached to another.
3. **File integrity** — every raw file listed still produces the fingerprint recorded for
   it.
4. **Reproduction** — the checker re-fires over the retained evidence and matches the claimed
   verdict.

The trust root is pinned **outside the package**, by a fingerprint the operator publishes
separately — not by the copy of the trust file shipped alongside the bundle. A forger who
re-signs tampered evidence with a fresh key is therefore rejected before any signature is
even checked.

Two further protections:

- **Category binding.** Retained evidence adjudicates its own category of weakness. If a
  finding's label is changed — evidence for a database injection relabelled as remote code
  execution — the re-check refuses at the boundary. Relabelling cannot manufacture a
  scarier finding.
- **Staleness is detectable.** Each checker has a version computed from its own source code
  *plus* every helper and constant its decision reaches. Change a helper or a constant and
  the version changes. The version is signed into the certificate, and a mismatch is
  treated as a failure rather than waved through. If the source is unavailable — a frozen
  deployment — the checker reports that it cannot confirm, rather than guessing.

### Confidence is measured, not asserted

A confirmed finding used to be recorded with confidence exactly 1.0, forever. That constant
was replaced with a probability learned from recorded outcomes.

- It is **never 1.0.** Probabilities are capped at 0.999 — "a detector never claims
  certainty it cannot have."
- With fewer than eight recorded outcomes the calibration degrades to a pass-through:
  "We do not invent reliability we have not measured."
- Outcomes marked *disputed* are excluded from every calculation: "We do not guess ground
  truth we do not have."
- Critically, a checker that stayed silent is **never** automatically recorded as a false
  alarm — that would be the checker grading its own homework.

---

## 10. Why "we found nothing" is the hardest sentence in the report

This deserves its own short section, because it is where most security tools quietly
overclaim, and where this system's answer is unusual.

Proving something **is** wrong needs one positive observation. Proving something **is not**
wrong is a claim about every way the problem could have shown up. Absence of a signal is
not proof of absence.

The everyday version: a smoke detector that stays quiet all night tells you nothing at all
if its battery is dead. Silence is only evidence when you know the alarm was working and
pointed at the right room.

So the system separates a silent test into two very different outcomes:

- **CLEAN** — the checker had a real, observable channel and definitely refuted the
  possibility. A closed network port is a genuine example: a refused connection really is a
  channel-confirmed negative. The alarm was working, in the right room, and stayed quiet.
- **INCONCLUSIVE** — the test input was sent, but no checker had a channel capable of seeing
  the problem if it had been there. This is **never** rounded up to clean. The comment in the
  source is blunt: "a payload sent with no adjudicating channel is inconclusive, never
  clean." Nobody knows whether the battery was in.

That second case is exactly what the call-back relay described in section 8 governs. Without
a relay, the four blind tests have no room to listen in, so their silence is inconclusive —
by design, and visibly so in the report.

Today, of the 26 registered **evidence branches**, all 26 can produce a FACT and only **6**
are permitted to say CLEAN — verified by counting the registry file. An evidence branch is
one specific window through which a claim may be seen: "in the reply's headers" is a
different window from "in the body of the page". The window decides what strength of claim is
possible. All six clean-capable ones are derived from response headers, the network
handshake, or the encryption handshake — narrow, structured places where an absence really is
observable. Every branch derived from the body of a page, from an exported configuration
file, or from a live cloud capture may say FACT, LEAD or INCONCLUSIVE, but **may not say
CLEAN**.

The registry that records this is enforced by a test, and its rules are strict in a
direction that is unusual: where a branch cannot yet do something, the entry **must** name
the concrete engineering work that would close the gap. A gap without named work fails the
test. In the project's own words, this means "a capability can never be quietly abandoned
by downgrading the claim". Lowering the *target* itself requires a written argument that
the capability is not achievable at all.

Seventeen of the 26 branches currently carry named blocking work.

---

## 11. Stage 8 — Building the attack picture

Individually proven weaknesses are useful. What a defender actually needs is the chain.

Over the map built from the signed record, the system answers three questions:

1. **How does an attacker get from a foothold to something valuable, and by the most
   credible route?**
2. **Which single repair breaks the most attack paths?** This is computed properly — exact
   single-cut and bridge detection over the graph — rather than guessed. It is the one
   lever to pull first.
3. **What can an attacker at that foothold actually reach, and how much does cutting the
   top choke point reduce it?**

Two honesty properties:

- Business impact is **optional**. If the operator supplies a file describing what each
  asset is worth, the ranking is by value severed. Without one, the model degrades
  gracefully to treating every valuable asset as worth the same, and the ranking becomes an
  honest count of attack paths — rather than a fabricated monetary figure.
- Where the system synthesises a multi-step chain, **only a mechanically-confirmed step
  asserts its edge into the map.** Unproven steps remain hypotheses.

Everything here is read-only and deterministic: the same map produces the same document,
so the analysis is a reproducible artefact rather than a one-off.

The console renders this as an attack graph on the Findings screen, plus a replay slider
that scrubs through the graph's growth. Paths and choke points are only highlighted once
they are fully formed at that point in the replay — "no premature path highlight". The
replay sends no traffic; it is pure reconstruction.

---

## 12. Stage 9 — The report and the evidence package

### Three documents

The system writes three documents, in a simple text format that displays as a formatted
report. Each is produced purely from the graded findings — no clock and no randomness are
consulted while writing them — so the same findings produce an identical document every
time. A date stamp is the only thing that can vary, and the operator has to ask for it.

| Document | Audience | What it leads with |
|---|---|---|
| **Executive** | Business owners, non-technical reviewers | Plain-language impact. "What we found" lists **only proven facts**. Leads live in their own clearly labelled section and are never stated as things an attacker can do |
| **Technical** | The engineering team | Per finding: how to reproduce it, how to fix it, and a verification block that either shows the mechanical proof — which checker fired, the measured confidence (never 1.0), and the short fingerprint identifying the re-runnable certificate — or labels the finding a lead |
| **Remediation roadmap** | The technical lead or planner | Impact against effort, ordered, over proven findings only. Leads are listed separately and never inserted into the fix order |

### Per-finding "how do I check this myself"

Each finding also carries its own verification block, generated deterministically from the
finding itself. It sends no traffic and reads no target.

The block is split honestly by grade. A **fact** names the checker that fired, its reasoning,
and points at the real re-executable proof, with the exact command. It even warns about a
specific confusing case: running the checker over a *rendered* report rather than the raw
retained evidence can show a calibration difference, and the block explains that this is
expected rather than tampering. A **lead** has no re-executable proof, so its block says
"how to CONFIRM this lead" and never implies the finding is proven.

Neither version of the block invents a command or a capability the tool does not have.

### Compliance mapping

Confirmed facts are mapped onto the standard frameworks that auditors and regulators work
from. Because this is where those names first appear in this briefing, each is spelled out:

| Framework | What it is |
|---|---|
| **OWASP** (Open Worldwide Application Security Project) | The standard catalogue of web application risks |
| **CWE** (Common Weakness Enumeration) | The standard catalogue of software weakness types, maintained by MITRE |
| **PCI-DSS** (Payment Card Industry Data Security Standard) | The payment-card security standard |
| **SOC 2** (Service Organization Control 2) | A common organisational security certification, widely required of suppliers |
| **ISO 27001** | The international standard for an information-security management system |
| **MITRE ATT&CK** (Adversarial Tactics, Techniques and Common Knowledge) | The standard catalogue of real-world attacker techniques |

A proven finding shows its mapped controls. A row that is not proven shows no control
mapping at all — only the sentence: *"advisory note only — a lead / unmapped class asserts
no control coverage."* A suspicion is never allowed to claim, or to deny, that a regulatory
control is satisfied. Many tools quietly count suspicions towards compliance coverage. This
one refuses.

### The proof bundle and the dossier

The operator can export a **proof bundle**: the confirmed facts with their retained
evidence, packaged so that a third party can re-check them **offline, with the system not
installed**, using a printed command. The export screen shows the trust-root fingerprint
with the instruction to publish it out of band, so that a bundle re-signed under a
different key is refused.

The **dossier** is one step further: a single self-contained archive holding the three
reports, the machine-readable exports, the offline-verifiable proof bundle, the scrubbed
engagement log, the signed record chain, any drift record, and a readable index page.

It also carries the **case file**: nine numbered plain-language documents written for the
non-specialist who receives the archive — a start-here page, an executive summary, the
approach and scope (including what was *not* examined), the proven findings, the unproven
leads, the catalogue of what the engine can confirm with this run's position against each,
what to do about the findings, how to verify the package yourself, and a glossary. They are
built from the same graded findings as the three reports, so the two cannot disagree about
what was proven, and where a value was not recorded they print "not recorded" rather than
filling the gap. If that rendering fails for any reason, the archive still ships with its
machine records and its proof intact and notes plainly that the case file is missing.

Four properties, taken from the code's own description:

- **Tamper-evident.** A manifest lists every entry with its hash; a multi-signature over
  the manifest and a trust-root fingerprint file anchor authenticity. Flip any byte and the
  manifest check fails. Re-sign under another key and the externally-pinned fingerprint
  refuses.
- **Honest about its own limits.** If no signer is available, the dossier is still
  hash-checkable but is **marked as not authenticity-signed** rather than quietly passing.
  A run with no confirmed fact carries no proof bundle and says so plainly — "a LEAD is a
  lead".
- **Path-safe.** Every entry is confined to a safe relative path; no absolute paths, no
  parent-directory escapes, and symbolic links are never followed.
- **Deterministic.** Sorted entries, a fixed entry timestamp, and no clock in the hashed
  content. Two builds over the same inputs produce identical manifest hashes.

A whole **session** can also be packaged this way — every run in it, each independently
re-verifiable, plus the conversation, the graph pointer and the open threads, in one signed
handover archive.

### The signed negative

There is one further artefact: the **Certificate of Non-Exploitability**. This is the
signed statement of what was proven *absent*.

Its rule is deliberately strict, and it is worth stating in ordinary words. The certificate
deals in single, narrow claims. Each claim is about one place tested, one input tested, and
one kind of weakness — for example, "the search box on the results page, the search term,
database injection". For any one such claim the system may write **closed** only if all
three of these are true at once:

1. at least one test of that exact combination came back as a definite "not here", rather
   than merely producing nothing;
2. that test can name which checkers actually reached a verdict on it — a silence from a
   checker that never ran does not count towards anything;
3. no test of that combination fired.

If any one of the three fails, the answer is **unproven**, and unproven never counts as
closed. The project's own summary of why, in its own words, is that this distinction is
"the difference between a sound negative and an omniscience lie".

For a technical reviewer, the rule as written in the source reads:

> a claim is CLOSED iff, for its (surface, param, class), at least one probe's coverage
> verdict is `clean` AND that clean probe names a non-empty `oracle_kinds_run` (the
> conclusive oracle(s) that adjudicated it) AND no probe fired. … UNPROVEN never counts as
> CLOSED — that is the difference between a sound negative and an omniscience lie.

("iff" is the mathematician's shorthand for "if and only if" — meaning the three conditions
are not merely enough, they are also required. A `clean` row that names no checker is treated
as a forged or tampered certificate and is refused outright.)

Its honest bound is written **inside the part that is signed**, so a reader cannot separate
the claim from its limits — the caveat cannot be edited off without breaking the signature.
The bound says: closed means not exploitable *by that family of checkers*, over the surface
that was *actually reached*, as of the date the evidence was collected. It never means
"secure against everything". A useful comparison is a roadworthiness certificate: it says
the vehicle passed the specified tests on that date, not that it is safe forever. The
certificate also records the limits of the search itself — how many pages were walked, how
deep, whether the list of pages still to visit was cut short, whether the request budget ran
out — so nobody can mistake what was reached for the whole application.

There are two levels at which a third party can check it, both offline and with nothing
installed:

1. **Check the seals.** Verify the signature; verify it against a fingerprint published
   separately rather than the copy inside the package; confirm the certificate is bound to
   the coverage record it claims to summarise; and confirm it is bound to the target the
   owner named. This proves the document is genuine and unaltered.
2. **Re-do the reasoning.** The certificate carries, for each "not here" result, the exact
   decision rule and the exact values observed. A small standalone checking program re-runs
   the rule over those values and sees whether it reaches the same verdict. This proves the
   verdict really follows from the evidence, rather than merely being asserted alongside it.

Even the second level states its own limit, in the certificate's own text: re-running the
rule proves the verdict matches the evidence. It does not prove the evidence reflects the
live target — the recorded values still came from the party that produced them. Being sure
of *that* needs a fresh run against the live system, or trust in the operator's signed
capture.

### Anyone can re-check the work

The console has a screen where a report can simply be pasted in and the retained proofs
re-fired **offline** — pure re-computation, no target, no traffic. Each finding comes back
as reproduced, contradicted, or ungrounded. A tampered proof shows as contradicted, never
as a green reproduction.

The same thing is available as a command (`python3 -m framework.v2 verify <report.json>`),
which exits successfully only if **every** certificate reproduces and matches its claim.

This is the practical answer to "why should we believe your tool?" The answer is: do not.
Re-run the proofs yourself.

---

## 13. Stage 10 — Re-testing after the fix

### Drift between two runs

Once the developers have shipped repairs, the operator re-runs the assessment and compares.
The comparison is deliberately narrow: it diffs the set of **mechanically-confirmed facts**,
and a finding only counts as confirmed if its retained evidence **still re-fires**. A
finding that is merely listed — no certificate, or a certificate that no longer reproduces
— cannot enter the comparison at all.

The result has three parts:

- **Regressions** — a fact that newly appears. A new exposure.
- **Fixed** — a fact that has disappeared.
- **Stable** — proven in both.

The diff is a pure set comparison with no clock and no randomness, so the drift result
itself re-verifies. There is a mode that exits with a failure code if anything drifted,
which is how this becomes an automatic regression gate in a build pipeline.

The console shows this on its Assurance screen, with the doctrine stated on the screen
itself: each run's certificates are **re-fired, never re-attacked**, and a lead is never
counted.

### Proving a fix, rather than assuming one

Separately, there is a stronger claim available: a **remediation certificate**, which says
"the exploit that provably worked is now provably dead".

It is earned the only sound way: the **same** checker that confirmed the original finding is
re-fired against the **patched** build's freshly re-captured bytes, and the certificate is
signed only if that checker goes **silent**.

Silence alone is not enough, and the system knows it. Silence only counts as a fix when it
is controlled:

- A **positive control** must still fire — proving the test harness is alive and would have
  detected the problem if it were still there. Silence from a broken harness proves
  nothing.
- The target must have **answered** — measured only on values the target itself produced,
  never on fields the testing side set.
- The check is repeated according to a per-category policy.

And silence is only a sound negative for a permitted list of **13** checker types — a list
that is **fail-closed**, meaning anything not explicitly on it is refused rather than
allowed through. Everything else is excluded, each with a written reason: timing, credential
stuffing, prompt injection, system-prompt disclosure, signals from tools that detect memory
misuse, version ranges, permission paths, all posture checkers, the single-sign-on forgery
checkers, automated access, network reachability, active exposure and weak encryption. Race
conditions and request smuggling are excluded because they are phenomena that do not
reproduce reliably enough for silence to mean anything. A category the list does not
recognise is refused.

There are four possible states, and **all four are signed**: remediated, still vulnerable,
inconclusive, refused. Signing all four matters: an inconclusive reason cannot be stripped
off and re-read as a success.

### Why a proven fix is graded one notch below a proven failure

This is a subtle point and the system is unusually honest about it, so it is worth
unpacking.

Whenever the system re-tests, it wants to be sure it is looking at a fresh answer from the
live system rather than an old recording played back. It does this by inventing a one-off
nonsense word for that run — a **challenge** — and slipping it into the request. There are
two grades of proof that the answer is fresh:

- **The lower grade:** the target answered this run, and the one-off word came back
  somewhere in the reply. That proves something responded now. It does not prove *what*
  handled it — a caching layer or a gateway in front of the application could echo the word
  back without the application ever seeing it.
- **The higher grade:** the one-off word came back *through the faulty channel itself* —
  embedded inside the very database error message that proves the weakness. That is much
  stronger, because only the flawed path could have produced it.

Now the asymmetry. When a weakness is **still present**, the higher grade is achievable: the
flaw is still there, so the challenge can travel through it and come back inside the
error. When a weakness has been **fixed**, the higher grade is impossible in principle —
the flawed path no longer exists, so nothing can come back through it. Any echo of the
challenge is then just an ordinary reflection, which a gateway could fake.

This is what the source means by the compressed phrase "a fixed **sink's** traversal is
unprovable". The *sink* is the dangerous destination the input used to reach — the database
query, the file the server opens. Once the flaw is repaired, the input no longer travels to
it, so you cannot prove a journey that no longer happens.

The system therefore caps a "remediated" verdict at the lower freshness grade, and says so
in its own comments — calling it "a fundamental limit, not a downgrade". A checker
configured to demand the higher grade for a remediation gets **inconclusive**, never a
false pass. And the residual risks of the lower grade are disclosed rather than hidden: at
that grade the system cannot distinguish a genuine fix from a filter in front of the
application that blocks the attack characters, nor from a gateway that strips the parameter
before the application sees it. Ruling those out needs further work that is named and
deferred, not quietly assumed away.

The verification component itself is written to **raise rather than claim** in every
ambiguous case. If there is no way to exercise the fix, if the re-capture yields nothing
reproducible, if the weakness is one whose proof lives in the *request* rather than the
server's response, or if no signer is wired — every one of those paths refuses, and the
caller records "unverified". None of them can produce a false "silent".

### The fix ladder

The console's Fixes screen shows what to repair after discovery, the ordered gated process
an automated fix follows, and the highest-impact choke points from the map.

Its stated constraints:

- **Only mechanically-confirmed findings are eligible.** Unproven leads are never
  auto-fixed.
- The action on that screen is **non-destructive and never raises a proposed code change**
  for review.
- Loading the screen copies, builds and raises nothing. The gated ladder runs only on the
  operator's explicit Apply click, and even then only into a **throwaway copy** of the source —
  the original tree is never touched. Raising a proposed code change is never done from the
  screen at all: that stays a separately provisioned and authorised command-line act.

The one destructive path that is wired is raising a proposed code change for a human to
review, and it is off by default. Turning it on requires all of: a signed authorisation, an
authority trust root, at least one mandatory signer including the owner, the durable
single-use record, and a platform access token supplied in the environment. The finding it
operates on must have its origins recorded and checkable — either a signed sealed envelope
or a fact rebuilt from the signed record after an integrity audit. **A raw file containing a
finding is never accepted.**

That destructive path is honestly recorded in the project's own status ledger as **built and
proven offline, but never yet used against a live system** — live use requires the operator
to provision the several signing keys it demands.

---

## 14. What can stop the job, at any moment

A short summary of every brake, because a national agency reader will want them in one
place.

| Brake | How it works | Survives a crash? |
|---|---|---|
| **Kill switch** | A file on disk, per engagement. While it exists, every action is refused. Reads as tripped unless absence can be positively determined | Yes |
| **Stop run button** | The Live screen trips the kill switch for that engagement | Yes |
| **Time window** | The permission slip expires (8 hours by default) | Yes |
| **Action budget** | A finite count of actions (1,000 by default from the provisioning command) | Yes |
| **Scope** | Every action re-checked against the signed host list; the network fence enforces the same list independently at two layers | Yes |
| **Permission tier** | Anything above the ceiling queues for a human; unknown actions fall to the strictest tier | Yes |
| **Destruction quorum** | Several distinct signers including the owner, bound to the specific action, time-boxed, single-use | Yes |
| **Approval expiry** | An approval token has a bounded lifetime; a pre-signed sleeper is void | Yes |
| **Refusal recording** | A refusal is written to the permanent record as evidence, not hidden | Yes |

The last row reflects a written rule in the project's operating doctrine: *"Refusals are
EVIDENCE — record them, never hide them. Hard limits — scope, authorization, destruction,
real user data — are inviolable and are never relaxed to make progress."*

---

## 15. What is fully working, what is built but not yet used in the field, and what is planned

Honesty about this distinction is the product's stated core value. The project maintains
its own ledger of it. The relevant entries for the workflow described in this chapter:

**Fully working and exercised end to end**

- The complete web-application pipeline — permission slip, session, discovery, crawl, test,
  mechanical confirmation, signed certificate, offline re-verification, report and dossier.
- The end-to-end validation was performed against a **purpose-built vulnerable target on
  the local machine**. The project's own README states it plainly: "proven on a local
  target, *not* 'proven in the field.'"
- A live **external** run against a vendor-published deliberately-vulnerable practice site
  is also recorded, with two confirmed facts, both re-verified offline, and a
  deliberately-tampered byte rejected. This chapter reports that as a recorded claim read
  from the project's documentation, not as a run observed while writing it.
- **The six cloud and Kubernetes exploitation confirmations are finished software.** All six
  — capturing a credential from a cloud machine's own credential service, showing an exposed
  secret is still a working one, one Google identity acting as another, an identity granting
  itself more power than it started with, and both tiers of container-platform access control
  (an anonymous caller bound to a dangerous role, and a dangerous permission or the default
  identity granted rights it should not have) — are written, reviewed, folded into the
  released software and wired from end to end. **Three of the six have now been fired at
  something real, and the three are not of equal weight.** The **two container-platform
  (Kubernetes)** ones are proven against a real single-node cluster the system stands up, owns
  and destroys itself — real infrastructure, but the project's own rather than a third party's:
  the dangerous binding is confirmed with a certificate that re-verifies offline, and the benign
  arrangements in the same cluster are correctly left as leads. The third, and the only one of
  the six to have judged material from a real outside system, is **exposed-secret validity**,
  which has been run against the real GitHub service using the operator's own credential
  against GitHub's own least-privileged identity endpoint — confirmed, its certificate
  re-verified offline, while a bogus credential of the same shape sent live to the same real
  address was rejected by GitHub itself and correctly stayed a lead. **That one splits, and the
  split must not be blurred:** only the GitHub half of that capability is proven live; its
  Amazon Web Services half is built and unit-tested but has never touched real Amazon
  infrastructure, and nothing from the GitHub run transfers to it. The remaining cloud
  confirmations are proven offline against recorded sample data standing in for a live cloud
  account. What has *not* happened for those is the final step of pointing them at a live
  third-party cloud account; that is the entry in the next list, and it waits on the
  customer's own credentials by design.
- **The safeguards around how this software is built and shipped.** These protect the supply
  chain — the parts an attacker could change without ever touching this project's own code.
  Four of them, delivered together: every third-party software package the system installs is
  pinned to an exact version *and* to a fingerprint of the exact file, so a package swapped at
  the download stage fails to install rather than installing quietly; every container base
  image is pinned to its exact content rather than to a movable label such as "latest"; a bill
  of materials — the itemised list of everything inside what is shipped — is generated for
  each of the two environments and cross-checked against the pinned list, so a generator that
  silently dropped an item fails the build instead of producing a confident, wrong inventory;
  and an automated vulnerability check runs on every proposed change and **blocks** it if any
  dependency carries a critical, publicly known flaw. That last gate is itself proved to work:
  immediately before it runs for real, the same configuration is run against a sample known to
  contain a critical flaw and *must* fail. If it passes, the build stops with the message that
  the gate below cannot fail, so its green tick means nothing. A gate that has never fired is
  not evidence of anything. These are properties of the build pipeline rather than buttons an
  operator presses, so a reviewer should read the build configuration rather than look for a
  control in the interface.

**Built, proven offline, but deliberately not yet used against a live third-party system**

Each of these is honestly marked in the repository, with the specific blocking dependency
named. Two framings should both be avoided: this is not "unfinished", and it is not
"field-proven". It is built, gated, and proven against recorded sample data standing in for
the real thing — and live use awaits credentials the operator must supply, by design.

| Capability | What is blocking live use |
|---|---|
| **Live fire** against a real third-party cloud account, for the cloud exploitation confirmations that still await it: the metadata-credential capture, the Google service-account impersonation, the identity-privilege-escalation re-derivation, and the **Amazon Web Services half** of exposed-secret validity. The software itself is complete, merged and proven offline — see the entry in the list above; what is outstanding is only the act of pointing it at a live third-party cloud account. (Three confirmations are no longer on this list: the **two Kubernetes** ones, proven against a real single-node cluster the system stands up, owns and destroys itself, with the dangerous binding confirmed and re-verified offline and the benign ones correctly not confirmed; and the **GitHub half** of exposed-secret validity, proven against the real GitHub service. What the Kubernetes run does not cover is enumeration of bindings across a cluster, and a managed provider's control plane such as EKS, GKE or AKS.) | Waiting on the customer supplying their own cloud credentials for an authorised laboratory account. One of them, the identity-privilege-escalation confirmation, is a different case worth stating precisely: it never performs the escalation, so there is nothing about it that awaits a live attack — but it still has to be given a real export of an account's permission rules, and obtaining that from a real account still needs the customer's read-only credentials |
| Cloud posture collectors for the three major providers and Kubernetes | Waiting on operator-supplied read-only credentials; all validated by live probes when present |
| The destructive automated-fix leg that raises a proposed code change | Operator must provision the several signing keys and a platform access token |
| Artificial-intelligence red-teaming tools as a source of facts | Those tools are absent from this environment. The routing that would govern them is built: a deterministic check can confirm; another AI acting as a judge is **always** recorded as a lead |
| The live external graph database and telemetry service | The client software is built and the local fallback works; the external service is not deployed |
| A live connection to an outside tool server | The description file and its validation are built; the connecting client is pending. (This uses the **Model Context Protocol**, an open convention for letting an AI system call tools that live outside it.) This is the *outbound* direction — VIGIL calling somebody else's tools. The opposite direction is a different thing and is not pending: the sovereign side's own memory server offers eight read-only tools to an assistant the owner already uses, and chapter 14 records it as live. |

Two capabilities in this chapter belong in this category as well, and are described where
they appear: the **fuzzing engine** and the **replay tool** (section 8) are built, tested and
gated by construction, but are not driven by the default run and have no screen or command of
their own. The **stay-logged-in session component** (section 4) is in the same position.

**Started, honestly marked as incomplete, or waiting on research**

- **Hardware-backed proof that the software was not tampered with.** Some computers contain
  a small dedicated chip that can vouch for what is running on the machine. The parts of the
  code that would talk to such a chip **deliberately produce an error** rather than returning
  a convincing-looking answer they cannot support. A software-only version does work today,
  and is labelled on its face as not hardware-backed.
- **Automatically writing a patch for a compiled program.** The general version of this
  deliberately refuses rather than guessing. One narrow version *is* built: catching a crash
  with a tool that detects memory misuse, then proving the repair by showing the same checker
  now stays silent.
- **A track record across many different real targets.** The machinery for producing one is
  built. The record itself does not exist, and depends on being given access to such targets.

**One conditional guarantee, stated as conditional**

The system keeps a public, append-only record of what it has published — a transparency log,
in the same family as the public registers used for website certificates. The specific attack
it must resist is being shown in two different versions to two different parties. That attack
is **prevented** only when a strict majority of separate witnesses countersign the record.
Below that threshold, the inconsistency is still *detectable* after the fact, but it is not
*prevented*. The project also notes that separate signing keys are not the same thing as
separate organisations, so the independence of those witnesses is an assumption about how a
deployment is arranged, not something the software can prove.

**One deliberately downgraded claim, kept downgraded**

Timing-based detections of request smuggling are recorded as unconfirmed **leads**, not
facts.

---

## 16. What to take away

A complete assessment here is a chain, and every link in it is either something a stranger
can re-derive for themselves or something plainly labelled as unproven. The chain runs like
this.

Written permission becomes a signed permission slip. The permission slip gates every single
action. The actions produce evidence, captured through a channel that was checked before it
opened. The evidence is examined by small fixed programs that anyone can run again. Those
verdicts are sealed into certificates a stranger can re-check offline — without installing
this software, and without trusting the people who made it. And after the repairs are made,
the same checker going silent, while a control test proves the equipment still works, is
what earns the word "fixed".

Everything else in the report is called a lead, and is never dressed up as anything more.
