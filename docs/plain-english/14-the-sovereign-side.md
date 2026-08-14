# The Sovereign Side, In Full

*Chapter 14 of the VIGIL briefing. The other chapters describe the half of the system that
tests other people's computers. This one describes the half that holds the owner's key, keeps
the owner's memory, and governs the first half. It is the part of the system a reader is most
likely to have been told nothing about.*

## 1. Why there is a sovereign side at all


### 1.1 The problem it solves, before any mechanism

An offensive testing engine is a powerful thing to have running on a network. Someone has to be
able to say *start*, *stop*, *not that target*, and *yes, this finding is now part of the official
record* — and that someone must not be the engine itself. If the same running program holds both
the attacking capability and the authority to authorise attacking, then anyone who subverts the
attacking half has, in the same motion, taken the authority. There is nothing left to appeal to.

So the authority is put somewhere else: in a second system, on the same machine, that holds the
owner's signing key and has **no offensive capability of any kind**. That second system is called
SIGIL, and it is what this chapter is about.

Once such a system exists, a second use for it becomes obvious. The person running an engagement
needs to remember what was done and decided — not in their head, and not in a chat window that
forgets between sessions, but in something durable they can search and cite months later. They
also need a safe, governed way to let an assistant touch their own files, their own terminal, and
their own accounts. Building that inside the attacking program would be indefensible. Building it
inside the key-holding program, which is already the trusted half, is the natural place for it.

**SIGIL is therefore two things at once: the owner's personal assistant, and the offensive
engine's governor.** Those two jobs share one property — both need the owner's key, and neither
may ever be able to run an attack.

### 1.2 What the personal half is, in the owner's terms

The project's own one-line description is *a local-first, sovereign personal AI orchestrator*.
Translated: an assistant that runs on hardware the owner controls, keeps its memory on that
machine, and never needs an outside service to answer a question about the owner's own history.

It is driven from four places — by voice, from a local web cockpit in a browser, from inside any AI
coding session through a memory bridge, and from a phone over a private network link. Every one of
those routes lands in the same permission machinery; none of them is a privileged back door. The
later sections of this chapter take each in turn. (The project's own summary line adds a fifth, a
keyboard-shortcut palette. In the code the palette is a command-line interface, and a global
keyboard shortcut is listed in the permission kernel's own notes as a later phase that has not been
built — so this briefing counts four.)

The project states five governing rules for it. In its own words, and translated immediately:

| The rule, as written | What it means |
|---|---|
| "Every action carries a proof of authorization." | Nothing happens because an assistant decided it should. Something happens because a check that the assistant does not control said it may. |
| "Memory is append-only." | The record is added to, never rewritten. A correction is a new entry, and the old one stays visible. |
| "Local-first." | The record, the keys, the search index and the entity map all live on the owner's own machine. The record, the keys and the entity map sit in a directory only the owner's account can open; on this machine the search index is the exception, and section 2.6 says why. |
| "Cascade, not monolith." | Cheap and local first; an expensive frontier model only when the cheap route is not good enough, and only through a gate. |
| "Prove, don't guess." | An answer cites the exact stored entry it came from. An uncited claim is shown as commentary, not asserted as fact. |

Then a sixth line, marked non-negotiable: **SIGIL has no offensive capability.** That is not a
promise about intent. It is a statement about what code is present, and the rest of this section
explains why the difference matters more than it might sound.

### 1.3 The governing half — what "authority" actually consists of

The sovereign side is built to hold a permission latch the offensive engine must pass before it
acts, kept on the sovereign side's own record, and that latch behaves in a deliberately lopsided
way:

- **Its resting state is "no."** With nothing on the record at all, the answer is no. There is no
  configuration in which it starts out permissive.
- **Only the owner can say yes,** and the yes must be bound to exactly the job being run — it
  names that authorised engagement and carries a fingerprint of the authorisation document — and
  it carries an expiry time. A permission granted for one job authorises nothing for another. An
  expired permission authorises nothing at all.
- **Anyone can say no.** Closing the latch is the safe direction, so a closing event counts
  whoever produced it. Opening it is the dangerous direction, so an opening event counts only if
  it verifies against the owner's stored key.
- **A yes cannot be reused.** Each permission carries an issue time, and the check refuses any
  permission whose issue time does not exceed the highest already seen — so a genuine permission,
  captured and replayed after a shutdown, reopens nothing.
- **The answer is never remembered.** Because the permission expires, a cached "open" would
  outlive its own validity — nothing is appended to the record at the moment of expiry to
  invalidate it. So the check is re-derived from the record every single time it is asked.

**One limit belongs with that description, and it is the same limit chapter 7 states about the
host-advertisement record.** The latch is real code, with real tests and a build job of its own that
must pass before any change is accepted — but **it has no caller in the shipped commands or
interfaces.** Nothing on the offensive side reads it today, and no shipped command opens or closes
it. What the offensive engine does pass before every action is the separate authorisation chain
chapters 3 and 8 describe, and that chain runs on the offensive side: the signed engagement
authority, the danger-tier classifier, an emergency stop of its own, and — for anything irreversible
— the several-must-approve gate. One of those four is genuinely sovereign in origin even though it
runs there: the danger-tier classifier is a single shared component, faithful to the sovereign
permission kernel, precisely so the two halves cannot drift into disagreeing about what counts as
dangerous. So the sovereign latch is the designed governing seam, built and guarded ahead of the
production writer that will use it. It is not a control operating in daily use, and this briefing
does not describe it as one.

Alongside it sit the emergency stop, the queue of actions waiting for the owner's signature, and
the desk that receives confirmed findings from the offensive side and files them into the personal
record — and those three are wired and in use. Chapters 7 and 8 cover the signing and the
authorisation machinery in full; what matters here is the shape the design is built to. **The
powerful half asks. The half with the key answers. The half with the key cannot attack anything.**
The third of those is enforced today by the code that is present. The first two are enforced today
for approvals and for the findings desk, and are built-but-unwired for the latch above.

### 1.4 The wall, seen from the operator's chair

Chapter 2 sets out the six mechanisms that keep the two halves apart. This section describes the
same wall from the other side of the desk: what the operator does, what they can never
accidentally do, and what it costs them.

**What the operator installs.** Two separate program environments, built from two explicit lists.
One list contains the shared integrity core, the personal system, and the connective layer. The
other contains the shared core, the offensive engine, the vendored third-party agent, the exit
gateway, and the same connective layer. The offensive packages are simply **not present** in the
first list.

**What the operator types.** One command word, then a subsystem name. A small routing module —
written so that it imports neither half — looks the name up in a fixed table and starts the
correct program as a **separate operating-system process**. There is no flag that changes which
environment a verb runs in. Routing is decided by the table, not by anything the operator or a
compromised process can influence at the time.

**What the operator can never do by accident.** They cannot start a session that has both halves
loaded, because the routing table has no entry that would produce one. They cannot enable the
offensive engine inside the personal environment, because **there is no setting for it** — the
code is not installed there. They cannot pass one side's code into the other's process through the
environment, because the variables that could do that are stripped when one side starts the other,
and the key that authorises destructive code changes is deleted outright from an offensive child's
environment.

**Why "cannot be loaded" is stronger than "must not be loaded."** A policy needs three things to
work: a place where it is checked, a person who configured it correctly, and no pressure to waive
it. All three fail eventually. Absence needs none of them. The distinction is between a locked
door and a building that has no such room. Asking the personal environment to load an offensive
module produces the same result as asking it to load a program that was never written: it is not
there.

On top of that absence sits a guard — a check that runs when each of the personal system's
subsystems is loaded. There are twelve such checkpoints, one at the entrance to each subsystem:
among them the agent mesh, the governor, the voice and gesture pipelines, the device registry, the
memory bridge, the nightly consolidation pass, the web-reading path, the perception layer and the
cockpit. Each scans the list of modules already loaded into the running process and raises an error
if any belongs to either forbidden family: the offensive engine, or the vendored third-party agent. The guard is not the wall. **The guard is the smoke
alarm that proves the wall is still there** — and, because it fails closed, a process that somehow
did contain both halves would stop rather than continue.

An alarm that never sounds is indistinguishable from an alarm that does not work, so the test suite
deliberately loads an offensive module and requires the guard to fire. Without that negative
control the guard could be passing for the trivial reason that it does nothing.

**What it costs.** Real friction, accepted deliberately.

| The cost | What it means day to day |
|---|---|
| Two environments to build, and two to keep updated | A dependency upgrade is done twice. A half-built environment produces a clear refusal and an instruction, not a confusing failure. |
| No shared memory between the halves | Nothing can be handed across as a live object. Anything crossing must be written as a file of inert data and read back. |
| No single script can do both jobs | Automation that spans the two halves has to be written as two programs and a file between them. |
| A confirmed finding takes extra steps to become part of the personal record | It is packaged, signed, carried across as data, checked against a trust root the owner blessed, and only then written under the owner's own signature. |

That last row is the point of the whole arrangement, stated as a cost. **The offensive side proves
what was found; the owner's side attests when it entered the personal record. Neither can forge
the other's half.**

---

## 2. The record as memory


### 2.1 One object, two jobs

Chapter 7 describes the record as a tamper-evident ledger — a chain in which each entry fixes a
fingerprint of the one before it, capped by a signed statement of how many entries exist. All of
that is true and is not repeated here.

What that chapter does not say is that **the same object is the system's memory.** There is no
separate database of "what the owner has been doing" sitting beside the ledger. The ledger *is*
the memory. When the assistant answers a question about a decision made in March, it is reading
entries out of the same append-only file whose integrity the chapter on signing is describing, and
it hands back the entry number so the answer can be checked.

That choice has a consequence worth stating plainly: **a memory that cannot be quietly edited is a
memory whose answers can be audited.** If an assistant could revise its own recollection, a
citation would prove nothing. Here a citation is a position in a chain, and altering that position
breaks the chain at exactly that point.

### 2.2 What actually goes into it

Four sources feed the record from the outside world.

| Source | What is captured | How it stays current |
|---|---|---|
| **The owner's AI coding sessions** | Each session's transcript, read line by line rather than loaded whole, and split into separate typed entries: what was said, the assistant's reasoning, each tool request, each tool result. Bookkeeping noise is filtered out. | A per-file counter records how many entries of that transcript are already stored, so a re-run resumes rather than re-reading a growing file from the top. |
| **Sub-assistant transcripts** | The full working record of assistants spawned inside a session — the detail of delegated work that never appears in the parent conversation. Each becomes its own titled, recallable thread, with the parent session recorded on every entry. | The same per-file counter. |
| **Version-control commits** | Commit messages, subject and body, from an allow-listed set of code repositories, appended oldest-first so the record's numbering tracks chronology. | Live: a small hook installed in each repository runs on every commit and every merge. Each repository's last-recorded commit is remembered, so the hook appends only what is new. |
| **Curated documents** | The owner's own hand-written programme notes, split into overlapping passages so the whole document is searchable, not just its opening. | **Not automatic and not de-duplicated.** This source is opt-in on the command line, and running it again appends the passages again. |

That last cell is a correction to the project's own summary, which describes all four sources as
incremental and repeatable without duplication. Three of them are. The curated-document pass is
not: it has no counter, and the write path performs no duplicate detection, so a second run with
that option produces a second copy of every passage. It is the one source that is a deliberate
manual act rather than a background one, which limits the exposure — but the briefing should not
repeat the tidier claim.

Everything the system does to itself also lands in the same record: agent proposals, refusals,
governance events, the morning brief, approvals and their resolutions, drafts, research reports,
fetched web pages, terminal transactions, and the periodic cross-anchoring of the authorisation
kernel's own log. There are twenty-three defined kinds of entry in total. **There is no side
channel — an action that leaves no entry did not happen as far as every downstream view is
concerned.**

### 2.3 How large it is — and what this machine actually shows

The project's own documentation describes a record holding upwards of 43,000 entries. That figure
is real, and it is also a figure about *one machine after months of use*, not a property of the
software. The record grows with what is fed into it.

Because this briefing's value rests on being checkable, here is what the status check on the
machine this was written on reports, in full:

| What the check reports | Value |
|---|---|
| Entries in the live record file | **16** |
| Next entry number to be issued | 16 |
| Passages held in the meaning-search index | **13,667** |
| Highest entry number that index has seen | **43,350** |
| Entry number at which the entity map was last rebuilt | **43,332** |
| Chain integrity | Passes — "16 entries link cleanly" |
| Signed cap on the record | **Absent** — the check says so, and names the command that would create one |

Those numbers do not agree, and the honest reading is that **the record file in use today is not
the one the two derived views were built from.** At some point the live file was replaced or
reset; the search index and the entity map, which live outside it, kept what they had. The entity
map's stored health note still says it was in step with a record of 43,332 entries, covering one
project, 160 sessions, 534 commits and 16 documents.

Two things are worth taking from that rather than glossing over it.

**First, the system reports both numbers side by side instead of reconciling them.** The status
tool prints the live count and the index's high-water mark as separate facts, and prints in plain
words that no signed cap is present. A design that quietly showed one number would have hidden
exactly the discrepancy that matters. This is the same discipline the rest of the briefing
praises, applied to the system's own health.

**Second, a lower index count is normal even in a healthy installation.** The search index is a
*filtered* view by choice: only entry kinds worth recalling by meaning are embedded — messages,
decisions, commitments, documents, session headers, briefs and commits. Raw tool requests and tool
results, which the code notes make up roughly two-thirds of a coding transcript and are bulky and
of low recall value, are deliberately left out and reached instead by asking for a range of entry
numbers. So the index is expected to hold fewer items than the record. The 16-versus-43,350 gap on
this machine is a different matter and is not that.

### 2.4 Nothing is edited — only superseded

Every entry can carry a pointer to an earlier entry that it replaces. Both remain in the file, in
their original positions, and the newer one wins when a view is derived. There is no update
operation and no delete operation on the write path.

This is not a theoretical property; it is how ordinary corrections are handled:

- When the infrastructure checker finds that a previously reported certificate or dependency
  problem has been fixed, it writes a **resolution that supersedes the stale finding**, so the
  morning brief shows the current state and a fixed problem does not linger as though it were
  live.
- When a queued action is approved or denied, the resolution supersedes the queued entry.
- When a paired device is withdrawn, the withdrawal supersedes its authorisation.
- When a file change is rolled back, the rollback entry supersedes the entry that carried out the
  change.

In every case the earlier entry is still there to read. **What changes is which entry is
current — never what the older entry says.**

**On deletion, the honest position.** The project has built the machinery for a cold-archive
prune: copying a sealed prefix of the record into an archive, folding everything that prefix
carried into one signed summary entry, and verifying that the archive can be re-attached. Every
part of that is present and tested — and it is **deliberately not wired up**. The code says so
itself: nothing in the archive machinery deletes a live entry or commits a new head, and the
loader that would read a folded summary returns the empty value universally, so every consumer
still scans from the very beginning of the record. **As shipped, no entry is ever removed.** The
remaining step, the crash-safe switchover that would actually delete, is held back behind explicit
owner sign-off.

There is one blunt exception that belongs in the same paragraph for honesty's sake: the owner can
run a reset that clears the record file, the ingestion counters and the search index outright. It
is an explicit, named command, not something an assistant can reach, and it deliberately does
**not** lower the durable anti-rollback mark that sits outside the record directory — so a reset
followed by a re-sign will report a rollback rather than passing quietly, until the owner
deliberately re-seeds that mark.

### 2.5 Everything else is a view, thrown away and rebuilt

The record is the only source of truth. The two things built on top of it — an entity map of
projects, sessions, documents and commits, and a search index that finds passages by meaning —
are **projections**: derived views that can be deleted and reconstructed from the record they were
built from, and that no one is allowed to edit directly.

The entity map is rebuilt by replaying the record from the beginning, in entry order, into a fresh
empty database, and then putting the finished copy in place of the old one, so no reader ever sees
a half-built view. Section 3.3 sets out exactly what that swap does and does not guarantee. Two
properties make the map trustworthy:

- **The derivation is extraction-free.** No language model is involved in building it. The map is
  assembled by structural rules over what the entries already say, which is why the same record
  always produces the same map. A test in the suite replays one record twice and requires the two
  derived results to be identical. (What that test pins is the derivation step; nothing in the
  project claims two database files are byte-for-byte identical.)
- **Every node cites its origin.** Each entity carries the entry number and entry fingerprint that
  produced it, so an answer taken from the map can be traced back to a line of the record and read
  in its original context.

The map also carries its own honesty check: it stores the highest entry number it replayed
alongside the record's current head, and reports whether the two match. That is the field which,
on the machine described above, shows the view to be stale — and it shows it because the check
exists.

The search index follows the same rule from the other direction: one point per eligible entry,
keyed by that entry's number and carrying its fingerprint, so **every retrieval is citable**. It
is built incrementally, only over entries above the last one indexed. And it refuses one specific
lie: if the index's backend is unreachable, the code raises an error rather than reporting "I have
indexed nothing" — because reporting an outage as emptiness would silently trigger a complete
re-embedding of the whole corpus. Sections 3 and 4 of this chapter take the map and the index in
detail.

### 2.6 What the record looks like on disk

The whole of the personal system's state lives in one directory readable only by the owner's own
account: the record, the keys, the entity map, the working caches.

**The search index is the exception on this machine, and an assessor should know it.** The owner has
moved it into a small search server of its own, reached over a loopback port that carries no password
or key of any kind, and its files are written by that server rather than by the owner's account. Every
indexed passage keeps a copy of the entry's text, so any account on this machine — not only the
owner's — can read the indexed text straight off that port, whatever the directory's permissions say.
That is a property of how this deployment was configured, not of the design; the shipped default keeps
the index in a file inside the same private directory, with no server and no port at all.

The content of an entry can additionally be encrypted at rest, field by field — the human text is
sealed while the bookkeeping fields stay readable, so the safety checks that scan the record for
things like the emergency-stop state keep working without any key at all, and the integrity chain
still verifies without one because the fingerprint covers the stored form. **This is opt-in and it
is off unless a key vault has been provisioned**; with no vault, entries are stored as plain text
exactly as before. On the machine described above no vault is provisioned, and the entries are
plain text.

## 3. The knowledge graph, and the nightly pass that keeps it true


### 3.1 What a graph is for, before any mechanism

The owner's record is a single line of entries in the order they happened — the right shape for
proving nothing has been altered, and the wrong shape for answering a question. "What have I done on
this project?" cannot be answered by reading forty thousand entries from the beginning.

So the sovereign side keeps a second thing beside the record: **a small map of the named things the
record talks about, and how they connect.** It holds four kinds of thing and one kind of connection.

| The thing | What it is in plain words |
|---|---|
| **A project** | A body of work — in practice one code repository and everything done in it. |
| **A working session** | One sitting at the machine with an assistant, first message to last, with a title. |
| **A document** | A curated note or reference the owner deliberately put into memory. |
| **A commit** | One saved change to the code, with author, date and one-line subject. |

The only connection recorded is **belongs to this project** — nothing cleverer, and section 3.5
explains why that absence is deliberate. On the machine this briefing was written on, the map holds
**one project, 160 working sessions, 534 commits and 16 documents, joined by 710 connections, over
10,061 counted messages** — what it returned when queried during the writing of this section.

### 3.2 The map is a mirror, and never a source

**The map is not a place where facts are stored. It is a picture regenerated from the record.** It is
built by replaying the record from the first entry to the most recent, counting what it sees, and
writing the result into a fresh, empty database. Nothing is written into it that was not read out of
the record a moment earlier. Three consequences follow, and all three matter to an assessor.

**It can be thrown away without loss — as long as the record it was replayed from is still there.**
Delete the map and nothing is gone; rebuild it from that record and it comes back. Anything that can
be destroyed and regenerated at will cannot be where the truth lives. **That condition does not hold
on this machine**, and it is the one caveat an assessor must carry out of this section: the map here
was replayed from a record of 43,332 entries, and the record now sitting at the standard location is
a different, sixteen-entry file. Deleting the map on this machine would not be undone by a rebuild.
Section 2.3 sets out how that drift arose and how the system reports it.

**It contains no judgement.** No model reads anything during a rebuild. There is no extraction, no
inference, no summarising: the rebuild counts and links, it does not interpret. That is why two
rebuilds over the same record produce the same map. The project's test pins the step that guarantees
it — one record replayed twice, with the derived entities required to come out identical — rather
than comparing two finished database files.

**It can therefore be checked by a stranger.** An assessor who does not trust the map can rebuild it
from the record it was replayed from and compare; a discrepancy there would be a fault in the
software, not a difference of opinion. On this machine that comparison is not available, for the
reason just given — the record at the standard location is no longer the one the map came from.

### 3.3 The swap, and what happens if the power fails halfway through

A rebuild does not touch the map in use. It builds an entirely new one alongside, under a staging
name, and only when that is complete does it put the new one in place with a single rename.

The code's own comment calls this an "atomic-ish swap", and the honest description is weaker than
*atomic* implies: the old copy is removed immediately before the rename, so there is a brief moment
when no map is in place. **What a reader gets in that moment is not a partial answer but a refusal**
— the reading path checks the map exists and, when it does not, replies that the graph has not been
built yet and names the command that rebuilds it.

Two failures are worth naming. If the owner's sealing key is locked, entries cannot be read and the
rebuild fails — **before the old map is torn down**, not after. And if power is lost between the
removal and the rename, the map is simply absent until the next rebuild: nothing is lost that the
record the rebuild was reading cannot produce again — which, on this machine, is the qualification
section 3.2 just made.

### 3.4 Every answer points back at the record

Each session, document and commit in the map carries two extra fields: **the number of the record
entry that first produced it, and that entry's fingerprint.** They are why a map answer is worth
anything — the reader can take the number, go back to the record, read the original entry and confirm
the fingerprint matches. Asking the map about a project returns its sessions, commits and documents
each carrying a record number, so every line of the answer can be checked against a tamper-evident
source.

**One honest exception.** The project itself carries no record number. It holds a name and four
tallies — how many sessions, commits, documents and messages belong to it — and could not sensibly
carry an anchor, because it is not minted by any single entry; it is a count over the others. The
exact claim is therefore that **every session, document and commit cites the record entry that minted
it, and the project is a tally over those, resolvable through its members rather than in its own
right.** The system's internal note that each structural node stores an anchor is a shade broader
than the code delivers, and this document follows the code.

The map can also be questioned directly, in a query language, by the owner and by any assistant the
owner has connected to their memory — and that reading path has two independent guards. A word filter
refuses any question containing a word that creates, changes or deletes, erring heavily toward
refusing. Behind it, **the map is opened read-only**, so a question that slipped past the filter would
still be refused by the database itself. The first guard is convenience; the second is the guarantee.

### 3.5 What the map deliberately does not have — and why that is the evidence

A reader who has seen other "knowledge graph" products will notice what is missing. There is no
*person*. No *organisation*. No *decision*. No *commitment*. No *contradicts* link, no *depends on*
link, no *was decided in* link. The whole semantic layer such products lead with is absent — on
purpose, and the code says so in the same breath as it lists the missing kinds: they are
**intentionally absent until a grounded producer exists for them.**

Translated: a thing may appear in this map only if it can be derived from the record mechanically,
without a model's judgement. A commit is in the record; counting it is arithmetic. A *person* is not
— deciding that two mentions of a name refer to one human being is interpretation, and interpretation
is what this map exists to be free of. Until a producer exists that can mint such a thing under the
same prove-don't-guess discipline as everything else, the kind does not exist at all.

**For this audience, that absence is the strongest evidence in the section.** A system that ships a
weaker version of the impressive feature, marked approximate, is asking to be trusted. One that
declines to ship it, and writes down why, has told the assessor something about every other claim in
the document. The constraint is the product.

One consequence must be stated so it is not mistaken later: **the facts the nightly pass promotes —
decisions, commitments, contradictions — live on the record and are served from the record, not as
entries in the map.**

### 3.6 The nightly pass, in six moves

The agent that owns memory runs one pass over everything added since it last ran. It has six moves
and does nothing else. Five of them produce its findings; the sixth closes the book on them.

| Move | What happens |
|---|---|
| **Extract** | A reader — a model, or an offline keyword matcher — goes over a window of the owner's own conversational entries and proposes candidate durable facts: decisions taken, commitments made, things named, positions reversed. |
| **Gate** | Every candidate is checked by re-reading the record. This is the whole of section 3.7, and the only thing in the pass that decides anything. |
| **Promote or demote** | A candidate that passes becomes a new, permanently recorded fact. One that fails is **also written down** — as an honest refusal, with the reason. |
| **Flag** | Where the record shows the owner reversing an earlier position, that opposition is recorded as a flagged contradiction naming both sides. |
| **Brief** | A short readable summary: open loops, commitments with due dates, contradictions awaiting review — composed only from facts that passed the gate, each cited. |
| **Seal** | The pass re-signs the record's head with the owner's key and advances the durable anti-rollback mark that sits outside the record directory. This is the move an agency should notice: it is what makes everything the pass just wrote tamper-evident from that moment on, and it is on by default — the shipped nightly service runs the pass without turning it off. Neither the signature nor the mark exists on this machine today, which is the same drift section 2.3 reports: the record they would have covered was replaced after the last pass ran. |

Two structural details matter. The pass fixes the record's high-water mark before it starts, so **it
can never feed its own output back into itself** as fresh evidence; and it works in bounded batches,
so the window the checker verifies against is **exactly the window the reader was shown** — a
citation to anything outside it is, by definition, invented.

### 3.7 The centrepiece: the gate grounds the quote, not the sentence

Here is the design almost everyone builds first, and why it fails. A model reads the owner's records
and writes a one-line summary of what it found; to make sure the summary is not invented, the system
checks that the words of the summary all appear in the record it cites. That sounds airtight. It is
not, and the project proved it is not with a red-team re-check on its own code.

Take a real entry: *"we have decided we should NOT deploy to prod on friday."* Now the model's
summary: *"deploy to prod on friday."* Every word of it appears in the record, so it passes the
containment check cleanly. **It also means precisely the opposite of what the owner said.** All the
extractor had to do was drop one word; reordering does the same job. The code states the finding in
one sentence: a token-subset check over the model's statement **is not entailment**.

The fix is not a better checker. The fix is to stop serving the model's sentence at all.

**What the gate certifies, and what the system then hands to the owner, is the verbatim span of the
owner's own record** — the actual words, negation and word order intact. The model's summary
survives, but only in an advisory slot beside the fact, never presented as the finding. The code's
own sentence is the clearest statement of the guarantee in the sovereign half:

> "By certifying and serving the verbatim quote instead, a fabricated or inverted statement can never
> be presented as a grounded fact — **the owner only ever sees their own words.**"

In plain English: **on this path the assistant is structurally incapable of telling the owner
something the owner did not say.** It can fail to find things; it can offer a useless quotation. What
it cannot do is compose a sentence and have that sentence served as the owner's own history. The
project's test suite carries this exact attack: the inverted summary above is fed in, and the test
asserts that what comes back still contains the word "not" and that the model's sentence appears only
as an advisory summary.

**What it takes to ground.** A candidate is admitted only if all three of these hold.

| Condition | In plain words |
|---|---|
| **It cites, and cites inside the window** | It must name the record entries it rests on, and every one must be inside the exact batch the reader was shown. Citing an entry it was never given is a fabricated citation, full stop. |
| **The quotation is really there** | The cited entry is **re-fetched from the record** — never the reader's copy of it — and the quotation must appear word for word. What is served is the record's own text, not the reader's transcription. |
| **The quotation is specific enough to mean something** | It must carry at least two substantial words, not common filler. A trivial fragment that appears everywhere grounds nothing. |

A flagged contradiction is held to a higher bar than anything else: it must verify **two distinct
record entries**, with a real quotation from each side, because a claim that the owner contradicted
themselves is a claim about two moments and needs evidence from both.

**The gate can only ever demote.** No input to it can turn a failing candidate into a passing one. The
model's own confidence score is carried along and written down beside the fact, and takes no part
whatever in the decision — a candidate offered with total confidence and no verifiable quotation is
refused exactly as firmly as a diffident one. Where a fact does carry a strength number, that number
is a **corroboration count — one, plus the number of distinct record entries that independently
re-verified it**. It comes from the record, not from the model's self-assessment.

**A demotion is recorded, not discarded.** A failed candidate is written to the record as a refusal
carrying the reason — cited outside the window; quotation not found; quotation too trivial — so the
owner can see what was proposed and rejected, and how much.

**And demote-only does not mean demote-permanently.** The pass keeps two separate ledgers, things
already promoted and things already refused, so that a fact refused on one run can still be promoted
on a later run if better evidence turns up.

### 3.8 What the pass will not do

**It flags contradictions; it never settles them.** A contradiction record names the conflicting
entries and the quotations from each side, and stops. Which position stands is the owner's decision.

**It does not guess at contradictions structurally.** The obvious cheap trick — two decisions about
the same subject means a contradiction — is rejected in the code as unsound, because it cannot
distinguish reversing a decision from restating it. Only opposition the reader actually judged, and
the gate then verified on both sides, is flagged.

**It never removes anything from the record.** Deleting a source entry sits at the highest
consequence level and the agent's own account of how often that happens is "effectively never".
Everything the pass writes is an addition; a revised fact supersedes an earlier one by pointing at it,
and both remain. Its ceiling is the reversible-internal-act level. Everything it *finds* becomes an
entry — facts, refusals, contradiction flags, a brief. The only two things it writes anywhere else
are the sixth move above: the signature over the record's head, and the anti-rollback mark. Both are
seals over what is already there; neither is a claim about the owner.

### 3.9 What is running here, and what is not

**The scheduled nightly run is shipped, not installed here.** The system ships a service definition
and a timer that runs the pass at 03:17 local time, catches up on the next wake if the machine was
off, and staggers the start by up to fifteen minutes so a fleet does not stampede. On the machine
this briefing was written on, **that timer is not installed** — the check for it returns "not found"
— and the pass has been run by hand, its position marker recording entry 43,332 as the last one
consolidated. The nightly cadence is a documented option the owner enables, not a running fact of
this installation.

**The default reader is deliberately weak.** The owner chooses who does the extracting: a headless
run of a coding assistant on their existing subscription, a metered interface, a wholly local model,
an offline keyword matcher, or a recorded fixture used in tests. **The default is the offline keyword
matcher**, because it costs nothing and sends nothing anywhere; the code calls it a conservative weak
fallback and names the assistant-driven reader as the real one. That is the right default for a
system whose gate treats the reader as untrusted anyway — but out of the box the pass finds cue
phrases, not nuance.

**On this machine the pass has produced no live facts.** Asked for the owner's open loops during the
writing of this section, the system returned an empty list and said so — which, given that the record
at the standard location currently holds sixteen entries beginning on 29 July 2026, is the correct
answer rather than a fault.

**The same gate is reused elsewhere.** Every claim a fetched web page produces runs through this
identical check, so nothing a page asserts becomes a fact either. One admission desk, not one per
feature.

---

## 4. Recall by meaning


### 4.1 The two ways to find something

Searching by word finds what was written. Searching by **meaning** finds what was meant — so that a
question about "the decision on where to keep the vectors" finds the conversation that said "let's go
with the embedded store", which shares almost no words with it.

The mechanism in one sentence: a small language model turns each record entry into a list of 384
numbers standing for its meaning, the question is turned into a list the same way, and entries whose
lists point in nearly the same direction as the question's are the answer. Nothing is being reasoned
about — it is a geometric comparison.

### 4.2 It runs on the owner's own processor, and costs nothing per question

**The model that does the converting runs on this machine's ordinary processor.** No graphics card is
required, and no request is made to any outside service, on indexing or on asking. There is no
per-question charge, no rate limit, no account, and no third party who learns what the owner asked
their own memory. The code says it in six words: *no API, no GPU, no cost.*

**One honest qualification.** The model file is not conjured from nothing: about 65 megabytes is
downloaded from a public model repository the first time it is needed, and kept in whatever cache
directory the embedding library has been pointed at. **By default that directory sits under the
machine's temporary path, which on this machine is held in memory and emptied at every restart** — so
the fetch repeated on 13 August even though the index itself had been built on 17 July. The accurate
claim is therefore **one fetch of a fixed file per restart, and nothing crossing the boundary in
between**, not "never touches the network at all" and not "fetched once, forever". For a sealed
deployment there are two steps, not one: bring that file in on media, *and* point the cache at a
directory that survives a reboot. Do only the first and the machine will reach for the network again
on its next start.

**Where the numbers are kept is also on the machine.** The shipped default is a file-backed store
running inside the program itself — no server, no container, no port. On the machine used here the
owner has instead configured a small search server on the loopback address, the same machine talking
to itself. Both are local; neither sends anything out. They differ in who on the machine can read
them, though, and section 2.6 sets that out: the server's port asks for no password, so the indexed
text is readable by any account on this host, which the shipped file-backed store is not.

### 4.3 Not everything is indexed for meaning

Only the entry kinds worth recalling by meaning are converted: messages, promoted decisions and
commitments, documents, session titles, briefs and commits. The raw traffic of an assistant using its
tools — the majority of any working transcript by volume, and almost worthless as recall — is
deliberately **not** indexed. It is not lost; it stays on the record, read directly by asking for a
range of entries around a known point. On this machine the meaning index holds **13,667 entries**,
roughly a third of the record it was built from, which is what that policy predicts.

### 4.4 An absent topic returns "no grounded match", not an invention

This is the honesty property of the section, and it is enforced in code rather than asked for in a
prompt. Every result carries a similarity score, and the system holds two thresholds set against the
measured behaviour of this particular model: results below the lower one are discarded as noise, and
**if the best surviving result is below the higher one, the system reports that memory has nothing.**

What it returns in that case is not a bare empty list for an assistant to fill in from imagination.
It is an empty list **plus an instruction**: no strongly-grounded match; do not fabricate; tell the
owner memory has nothing solid on this, and suggest rephrasing. The refusal is the payload.

Both directions were exercised live while this section was being written:

| The question asked | What came back |
|---|---|
| How the consolidation gate grounds a quotation | Eight real record entries, with entry numbers, fingerprints, dates, sessions and similarity scores running from 0.79 down to 0.71 |
| The migratory patterns of the Arctic tern | No results, and the instruction not to fabricate |

The second row is the one that matters. **The characteristic failure of an assistant with a memory is
answering confidently about something it has no record of.** Here that outcome is not discouraged but
unavailable: the search layer hands back a refusal instead of thin material.

### 4.5 Every hit is citable

A result is not a paragraph of text. It is a record entry, arriving with its entry number, its
fingerprint, when it happened, which session and project it belongs to, its similarity score and its
text — so an assistant answering from it can cite it and the person reading the answer can check it.
The tool says exactly that in the description the assistant reads: each result is a tamper-evident
record entry, cite its number when you answer.

### 4.6 The limits, stated plainly

**Similarity is not support.** A high score means a passage is *about* the same thing as the
question; it does not mean the passage *supports* any claim about it. All the grounding work is done
by the gate in section 3. Recall by meaning is how material is found, never why it is believed.

**The thresholds are calibrated, not proven.** The code records that with this model in-corpus
questions score around 0.72 to 0.78 and absent topics around 0.55 to 0.62, and the cut sits between
them. That is a well-grounded engineering judgement about one specific model, not a mathematical
guarantee; swapping the model would mean re-measuring both numbers.

**The index is a view, and on this machine it is a view of an earlier record.** Like the map in
section 3, it can be rebuilt from the record — and the state of this machine makes the point
concrete: **the record file at the standard location currently holds sixteen entries and begins on 29
July 2026, while the map was built on 17 July from a record that ran to entry 43,332 and the meaning
index holds entries up to number 43,350.** The views and the record are out of step, and a recall hit
here returns entry numbers that cannot presently be resolved against the record at that path.

That is the architecture behaving as designed, not a defect being confessed, because **both views
publish their own staleness**: the map compares the highest entry it replayed against the record's
current head, and the memory-health tool reports the record's size and the index's high-water mark
side by side — which is how the discrepancy above was found. A system whose derived views can
silently disagree with the source can be quietly wrong; this one is built so that the disagreement is
a number on the screen.

## 5. The agents — and exactly how many of them there are


The sovereign side does its work through a small set of named assistants. Each writes its own name
onto every record it produces, and each carries a permanent **ceiling** — the highest level of
consequence it may ever reach, whatever it is asked to do and whoever asks. Chapter 11 already sets
that roster out properly: what each assistant is for, what it may never do, and the full rules for
the two most consequential of them.

**This section does not repeat chapter 11.** It gives a reader arriving here a place to look, and
settles two questions of fact chapter 11 leaves open: how many of these assistants there actually
are, and whether one of them exists at all.

### The roster, at a glance

A reminder, not a treatment. The third column is the one thing it adds to chapter 11's version:
whether an assistant runs in the routine sweep or only when a person asks for it.

| Assistant | Ceiling | Runs | In one line |
|---|---|---|---|
| **ARCHIVIST** | A1 | On request | Consolidates the record: promotes what is grounded in the owner's own words, demotes what is not. |
| **SENTINEL** | A1 | Routine sweep | Watches; reports only what clears an importance threshold and a per-run alert budget. |
| **STEWARD** | A2 | Routine sweep | Composes the unprompted morning briefing, every line cited to a record number. |
| **ENVOY** | A2, never promotable | Routine sweep | Sorts inbound messages and **drafts** outbound ones. There is no send function in it. |
| **SCHOLAR** | A1 | On request | Sourced research. A claim whose quotation is not verbatim in its cited source is demoted, not asserted. |
| **ARTIFICER** | A2 | On request | Drives a coding assistant in a separate copy of the repository. Runs the tests before claiming success; never pushes. |
| **BASTION** | A1 | Routine sweep, if an inventory exists | Checks the owner's own listed infrastructure. Observes; never fixes. |
| **OPERATOR** | A2 | On request | Files and terminal on the owner's own machine, one approved transaction at a time. |
| **DELEGATE** | A2, never promotable | On request | Acts under the owner's name — accounts, logins, forms — with a fresh approval per action. |
| **PERCEPTION** | A1 | On request | Answers screen and camera questions. Captured text is authoritative; the model's reading stays advisory. |

Two of the ten sit on a frozen list barring them from ever being granted more autonomy: ENVOY and
DELEGATE. The comment beside that list is blunt — outbound actions and account actions "stay
human-gated forever."

### Where the full treatment is

**Chapter 11, section 4** carries the real roster: a job-and-limits table, then full sub-sections on
SENTINEL's discipline of not crying wolf, ARTIFICER's rule about running the tests, BASTION's limits
as a defensive scanner, and the chapter's two longest treatments — OPERATOR's six-step transaction
and DELEGATE's per-action approvals. Read that section first.

### The count: ten named identities, of which chapter 11 covers nine

Chapter 11 says nine, and for what it describes, nine is right — but the number needs stating
precisely, because a reader who counts differently will think the document is sloppy.

Nine assistant types live in the folder the system calls its agent mesh: ARCHIVIST, SENTINEL,
STEWARD, ENVOY, SCHOLAR, ARTIFICER, BASTION, OPERATOR and DELEGATE. Those are the nine chapter 11
describes.

There is a **tenth** named identity. The perception assistant is built on exactly the same
foundation as the other nine — the same base class, the same routing through the governor, the same
outcome written to the same record — and it declares its own name, **PERCEPTION**, and its own
ceiling, A1. It simply lives in a different folder, alongside the screen-capture and camera code it
serves. Nothing about it is second-class: a record it writes carries its name the way a record from
SENTINEL carries SENTINEL's.

The honest formulation, and the one this chapter uses, is: **nine assistants in the mesh, plus a
perception assistant — ten named identities that can write to the owner's record.** Chapter 11
originally named only the nine; it now carries the same note, so the two chapters agree, and the
perception section of this chapter gives the full treatment.

### The one that does not exist: there is no separate web-research assistant

A reader looking at the system's own architecture diagram, or at the folder of web-crawling code,
may reasonably conclude there is an eleventh assistant devoted to research on the open web — the
project's diagram even gives it a name of its own.

**There is not.** The web-research component is built as a *specialisation of SCHOLAR*. It adds one
capability — crawl a scoped set of public pages, store each fetched page as its own cited record,
then push every resulting claim through the identical demote-only admission check the nightly
consolidation uses — and inherits everything else. Critically, it **declares no name of its own**,
so every record it writes is signed as SCHOLAR's. It runs at SCHOLAR's A1, and it has no entry on
the frozen no-promotion list because it is not a separate thing to promote.

The practical consequence for an auditor: searching the record, the promotion policy, or the list of
never-promotable assistants for a distinct web-research name returns nothing at all. **Describe it
as SCHOLAR's web-research mode.** Describing it as its own assistant would put a component in this
briefing that does not exist in the software — the one kind of error this document cannot afford.

---

## 6. Seeing the screen, and why the reading is not trusted


The sovereign side can look at the owner's own screen, or at a frame from the owner's own camera, and
answer a question about it. That sounds like the most ordinary feature in the chapter, and it carries
the most careful rules about truth in the whole system — because looking at a picture is the one place
where a machine is most likely to describe something that is not there.

Two quite different things happen when a frame is captured. First, software reads the letters out of
the picture — **optical character recognition**, usually shortened to OCR, the technology behind
scanning a document and getting editable text back. Second, an AI **vision model** — a model that takes
an image and describes it in ordinary prose — is asked what it sees. The system treats those two
outputs as different *kinds* of thing, permanently, and never lets one become the other.

### 6.1 The rule, written into the code three times

**The captured text is authoritative. The model's reading is advisory.** That single sentence is
written into three separate parts of the perception code — the subsystem's own front page, the agent
that answers the question, and the small module that decides what may be called grounded. It is stated
in the code as:

> "the CAPTURED TEXT … is the AUTHORITATIVE ground truth; the VLM's visual reading is ADVISORY only,
> never asserted as the screen's content."

In plain terms: the words the OCR actually read off the picture are what the answer is made of. The
vision model's prose is shown, but it is shown under a heading that says it is a guess about the image
and has not been checked against anything.

This is the same discipline the research agent uses on documents — serve the quote, never the
paraphrase — applied to a picture, and it is what that discipline looks like when the source is a
screen rather than a web page.

### 6.2 A lead, and what it takes to become a grounded claim

When the vision model says *"a Firefox window, a laptop, a coffee mug"*, each of those objects is a
**lead** — a thing worth looking into, asserted by nobody. A lead is promoted to a **grounded claim**
only if the same distinctive word appears, letter for letter, in the text the OCR read off the frame.
Words too short or too common to mean anything — under three characters, or ordinary connecting words —
do not count for this purpose, which is the same rule the memory system uses when it decides whether a
quote is specific enough to be worth anything.

And here is the part that matters most, and that most systems get wrong. A promoted claim is **phrased
as corroboration, never as a fact about the world**. The code's own example is the wording it produces:

> "corroborated by on-screen text 'Firefox'"

— never *"there is physically a Firefox."* The distinction is not pedantry. All the system has actually
established is that the word appeared on the screen: not that a browser is running, not that the window
is real rather than a picture of a window. The claim is kept exactly as strong as the evidence behind
it, and no stronger.

The answer the owner gets back is a short document with three clearly separated parts:

| Part of the answer | What it contains | What it is worth |
|---|---|---|
| **On-screen text** | The lines the OCR read, reproduced verbatim | Authoritative. This is the ground truth the answer is made of. |
| **Corroborated objects** | Each object the model named that the captured text independently confirms, each carrying the actual on-screen words that confirm it | Grounded, and phrased as corroboration — never as a statement about the physical world. |
| **The model's visual reading** | The vision model's prose, whole and unedited | **Advisory.** Labelled in the answer itself as a guess about the image, not verified against captured text. |

They are never merged. There is no fourth section in which a helpful summary blends them together.

### 6.3 With no captured text, nothing is grounded — by construction

If the OCR read nothing — a photograph with no writing in it, a machine with no OCR software installed,
a failed read — then there is nothing to corroborate against, and **every object the model named stays
a lead**. Not some of them; all of them. An image-only frame can never produce a grounded claim, in any
circumstance, because the half of the design that does the grounding produced nothing.

The answer says so on its face. Instead of the authoritative section it prints a line stating that no
text was captured, that the frame was image-only, and that there is therefore nothing grounded to
serve. The one-line label written onto the permanent record is equally blunt: an image with an
unverified reading and no OCR.

This is worth pausing on, because it is the shape of the whole system in miniature. When the trusted
input is missing, the output does not quietly fall back to the untrusted one. **It falls back to saying
less.**

### 6.4 Text on a screen can be hostile

A screen is not a neutral surface. It shows web pages, emails and documents written by other people,
some of whom would be delighted if what they wrote could be mistaken for the system's own conclusions.
This is the attack usually called prompt injection: put words on a surface an AI reads, and get them
treated as instructions or as findings.

The perception answer defends against it with a small, very effective piece of formatting discipline.
No line that anyone outside the machine could have influenced is allowed to start at the left-hand
margin. Only the program's own lines go there — the title, the section headings, and the line
recording which frame this was and how much text came off it. **Every captured line and every line of
the model's reading is written with a short indent guard in front of it**, so a line of screen text
can never begin at the margin. A page that contains the exact heading "On-screen text (authoritative — captured verbatim from
the frame)" therefore appears in the answer indented and quoted, as content, and does not become a
section boundary. The boundary is unforgeable not because the system checks for forgery attempts, but
because the forged version is structurally incapable of occupying the position that matters.

The vision model's own prose is indented the same way, and the code is explicit about why: the reading
is *the most attacker-influenceable channel of the three* — a compromised local model, or an honest
model faithfully transcribing hostile words it saw on the screen, both arrive by that route. Two tests
in the suite construct exactly that attack — a hostile reading containing both heading lines verbatim —
and confirm that the finished answer contains precisely one real authoritative heading and that the
hostile copies appear indented, as quoted content.

One further detail about what gets stored. The permanent record of a perception carries the captured
text, the model's reading, the corroborated objects and the leads as **sealed fields** — encrypted at
rest, so an auditor reading the log without the key sees that a perception happened and how much text
was involved, but not what was on the owner's screen. The short label that stays readable is
deliberately a description of the event, never a sample of its content.

### 6.5 Ambient watching — and the fact that nothing leaves an unchanged screen

There is a second mode, in which the system watches a stream of frames rather than answering one
question. It is **opt-in**: it does not run unless it is started. Starting it and stopping it each
write a marker to the permanent record, so a period of ambient watching is visible afterwards as a
bounded, timestamped span with a count of how many times it escalated.

The mechanism that makes it tolerable is the definition of "something changed". It is not a comparison
of the pixels — comparing pixels means a cursor blink or a compression artefact counts as a change, and
a watcher that fires on everything is a watcher that has to send everything somewhere. Instead the
comparison is over **the distinctive words the OCR read**: a change is a meaningful divergence in that
set of words, or the arrival of enough new words to matter even on a busy screen. A single new warning
line on a screen already full of text still fires; the same screen re-rendered slightly differently
does not.

**That improvement is only available where the OCR produced words.** With no text on either frame the
comparison falls back to comparing the raw images, which is exactly the cruder behaviour it was
written to replace — a re-rendered screen then does count as a change. On this machine, where no OCR
is installed, the fallback is what would run, so the ambient loop here has the older behaviour and not
the better one.

The consequence is the sentence worth remembering: **an unchanged frame produces nothing at all.** No
reading, no record, no request. It does not leave the machine, because nothing is done with it.

The ambient loop also refuses outright to run with a model that uploads. Not "asks first" — refuses,
and writes the refusal to the record. Continuous watching and off-machine upload are never combined on
an automatic path.

**An honest limit the reader should have.** Ambient watching has no shipped way to start it: no
command-line switch, no button in the interface. It exists as a capability other code can call, and it
is exercised by the test suite. And "indicator" in the code's own description means a marker written to
the permanent log at start and stop — not a lamp on the machine and not a light on a camera. A reader
who pictured a hardware indicator should replace that picture with an audit-trail entry.

### 6.6 Recall — "where did I last see that?"

The most useful thing built on top of all this is a question the owner can ask their own machine:
*where did I last see this?* The system searches its perception history, finds the most recent event
whose **captured text** contains the subject, and serves back the actual line — the owner's own screen
text, verbatim — with the record number it came from, the time, and the frame's fingerprint. It reads
history and writes nothing.

It never serves the vision model's reading. A thing the model once claimed to see, which the OCR never
confirmed, is not a sighting and cannot be recalled as one.

There is one further restriction that is easy to miss and is exactly right. **All of the subject's
distinctive words must appear on a single line.** The test that pins this behaviour uses a frame
containing "AWS console open" on one line and "far below: secret bucket keys" on another, and asks for
"AWS bucket". Both words are somewhere on that screen. The answer is *no sighting*, because the only
thing recall is permitted to hand back is a verbatim line, and no line on that screen shows what was
asked about. Serving either line would misrepresent the frame. The same request against a screen
showing "AWS bucket browser view" returns that line, because that line genuinely contains the subject.

### 6.7 Sending a frame to an outside model: the egress gate

There are two vision models in the design. One runs entirely on the owner's own machine and sends
nothing anywhere. The other is a frontier model — better at describing images, and reached by
**uploading the picture to another company's service**. The code refuses to treat that as a quality
setting:

> "Sending a screen/camera frame to the frontier … VLM uploads private bytes off the owned machine —
> that is A2 data-egress, not a free 'try local then frontier' quality bump."

In plain words: a screenshot of the owner's desktop may contain anything that was open at that moment.
Sending it out is an externally visible act with consequences that cannot be taken back, and it is
classified as one.

**The classification is worked out, not declared.** The perception agent does not get to state how
serious the upload is. The name of the action is handed to the same fail-closed classifier the rest of
the system uses, and that classifier answers. Run directly against the classifier on this machine, the
upload action returns the externally-visible tier with the verdict *queued* — the agent's own opinion
never enters into it. If the classifier cannot be reached at all, the answer is the most restricted
tier, not the least.

**The approval is bound to that exact upload.** Before anything is sent, the system computes a
fingerprint over the image's fingerprint together with the question being asked, and the owner's
approval must match it. An approval of a *different* upload — a different screen, or the same screen
with a different question — does not match and authorises nothing. There is no general "yes, you may
use the frontier model" permission to be obtained once and reused.

**Absent an approval, the request queues and nothing is uploaded.** The request is written to the
permanent record as awaiting approval, and what comes back is that awaiting-approval record rather
than a description of the frame. The part that makes the gate liveable is that **the local reading
path is untouched**: the owner runs the ordinary on-machine question and gets the on-machine answer,
exactly as they would have. What waiting costs them is the outside model's opinion, and nothing else,
until they have said yes to that specific frame.

Two structural refusals sit around the gate. The ordinary question-answering path and the ambient loop
both check the model they were handed and **refuse an uploading model outright**, writing a note or a
refusal rather than performing the upload. So the only route to an upload is the gated one; there is no
second door to close.

And one property that is stronger than a rule, because it cannot be granted away. Trust in this system
can be extended to an agent over time, letting some of its externally-visible work go through without
asking. That mechanism requires the action to be at or below the agent's **permanent ceiling**. The
perception agent's ceiling is the reversible-internal-act level, and an upload sits one level above it.
**No grant of trust can therefore ever make a frame upload automatic** — not by promoting the agent,
not by any setting. Each upload needs its own approval, permanently. Under the emergency stop a *new*
upload is not even queued: it is refused outright and the refusal recorded, while the local,
on-machine perception keeps working, because observation is the one thing the halt is designed to
leave alive. **One boundary of the stop should be stated exactly, because an agency will plan around
it.** The halt is what stops a request from being *raised*; it is not consulted again when an upload
the owner has already approved is carried out. So engaging the stop does not by itself cancel an
approval already given for a particular frame — the way to withdraw that is to withdraw the approval,
not to pull the halt.

Who may sign the approval: the owner's own key, or a device key the owner has explicitly authorised —
which is how an approval can be given from the paired phone. The device ledger and what the phone can
and cannot do are covered later in this chapter.

### 6.8 What is actually running on this machine — and why the gap is safe

Everything above is built and tested. Nineteen tests cover this subsystem specifically, and they pass:
that an image-only frame grounds nothing; that hostile screen text and a hostile model reading cannot
forge a section boundary; that a queued upload uploads nothing; that an upload runs only after a
verified approval bound to that exact frame and question; that an approval of a different upload does
not authorise it; that both automatic paths refuse an uploading model; that jitter is not a change but
a small meaningful addition is; and that scattered words are not a sighting.

What is **not** live is the hardware and software chain that feeds it. Checked directly on this
machine:

| What perception needs | State on this machine | Consequence |
|---|---|---|
| Something to take a screenshot | **Present** — one of the four utilities the capture code recognises is installed, and a graphical display is running | The grab step is available here. It has not been exercised: capturing the operator's own screen to prove a documentation point is not a reasonable thing to do. |
| A camera | **Present** — a USB camera is attached, and the video tool the code uses is installed | Same: available, deliberately not exercised. |
| **OCR software** | **ABSENT** | **This is the one that matters.** No OCR means no captured text, which means no authoritative half, which means **nothing can be grounded at all**. |
| A local vision model | **ABSENT** | The on-machine advisory reading comes back empty rather than invented. |
| The operating system's own description of the screen | **Not wired** | The richest source of screen text — what the accessibility layer knows about every window and button, without any character recognition at all — is a documented, deliberately unfinished seam. |

So the honest status is: **built, tested, and not live on this machine** — and the missing piece is
precisely the authoritative one.

That is a worse-sounding sentence than it deserves to be, because of what the failure actually produces.
A perception system whose reader is missing does not describe screens badly. It describes screens
**advisorily** — every object the model names stays a lead, the answer prints "no text captured", and
the record says plainly that this was an unverified reading with no OCR. There is no configuration in
which a missing sensor produces a confident false statement about what was on the owner's screen. The
grounding rule was written so that absence degrades into silence rather than into invention, and on
this machine that is not a claim about the design — it is the observable behaviour.

**What this section does not establish.** It does not establish that the OCR, once installed, reads any
particular screen correctly; character recognition makes its own mistakes, and a mistake it makes
becomes part of the authoritative half. It does not establish that a corroborated object is physically
present — only that its name appeared in the text read off the frame. It does not establish that an
approved frontier reading is accurate; that reading stays labelled advisory after the upload exactly as
it was before. And it says nothing about any screen but the owner's own: this subsystem observes the
owner's own screen and the owner's own camera, and has no path to any other.

## 7. Speaking to it, and pointing at it


There are two ways to reach the sovereign side that are not a keyboard: talking to it, and moving a
hand in front of a camera. Both sound like novelties. They are neither novelties nor conveniences —
they are **control surfaces**, and the only question that matters about a control surface is what
authority it carries.

The answer, in both cases, is **none of its own**. A spoken request is not a faster route to a
dangerous action; it is the same route with a microphone bolted to the front. A gesture is not a
shortcut past the approval queue; it is a pointer movement inside a session the owner had to unlock
with a key. What follows elaborates those two sentences, and says frankly which parts are running on
this machine and which are not.

---

### Voice is not a privileged channel

This is the load-bearing property, and it belongs before any description of microphones. When speech
is recognised, the resulting text is handed to **the same program that handles a typed request** — the
small, fast component that classifies what is being asked, decides what permission level it needs, and
writes a signed entry into the tamper-evident record of actions. The code's own summary: "voice is
just another interface onto the one authorized path."

The consequence is precise. **Saying something out loud buys exactly what typing it would buy.** If
the classified action is at one of the two automatic levels, it runs and a signed record is written.
If it is at either gated level it does not run: a record is written marking it awaiting approval, and
the spoken reply is a plain refusal — the action needs approval and was not carried out. A spoken
sentence cannot reach a level a typed sentence could not.

Three further details are worth an assessor's attention:

- **The record is written either way.** A permitted action and a blocked one both produce a chained,
  signed entry. If that entry cannot be written the program does not shrug: it prints a loud integrity
  warning and exits with a failure code, so no wrapper can read the result as a clean success. "The
  action happened but was not audited" is treated as an incident, not a logging inconvenience.
- **The program that does this can be fingerprint-checked before it runs.** Once the owner has taken
  its fingerprint, it is compared against that owner-signed fingerprint on every use, and a binary
  that fails the check **is not executed at all**; the spoken reply says so and tells the owner how to
  re-fingerprint it deliberately. The check is opt-in, and **on the machine this chapter was checked
  against no fingerprint has been taken**: with none on file the system prints a loud warning that the
  program is unpinned and then runs it unverified. That is the documented posture before setup rather
  than a silent failure, and it is one owner command away from being switched on — but until it is,
  this particular protection is present and dormant here.
- **There is a separate switch for voice alone.** The live microphone loop refuses to start when the
  owner-signed voice setting is off, and is checked again mid-conversation, so turning voice off
  part-way through stops it. Typed requests are deliberately *not* affected — turning off voice
  control never breaks the keyboard.

An honest scope note, because it is easy to imagine more than is there. With an ordinary spoken
sentence that program does one of three things: answers from the owner's own memory, escalates to a
reasoning model, or records the request as an intent for the agent mesh to pick up. **It holds no
general-purpose tool executors of its own.** The things that actually touch files, terminals, accounts
and infrastructure are the agents, each with its own ceiling and approval path. Voice reaches those
the way everything else does — by asking, and waiting.

### The pipeline, and why it can be tested with no audio hardware

The speech loop is a four-state machine:

| State | What is happening | How it leaves |
|---|---|---|
| **Waiting** | Nothing is being captured for meaning. | A trigger moves it to listening. |
| **Listening** | Audio is being collected as an utterance. | Enough trailing silence after real speech ends it; a timeout with no speech at all returns it to waiting; an absolute cap always ends it. |
| **Thinking** | The captured audio is transcribed and handed to the permission-gated path. | Immediately, once there is an answer. |
| **Speaking** | The answer is being played back in chunks. | Playback finishes; **or the owner starts talking over it**. |

Talking over the assistant mid-answer — "barge-in" — is the acceptance bar the design set itself, and
it is handled with deliberate stubbornness: a single cough or click does not abort the answer. Only
**four consecutive frames of detected speech** count as a genuine interruption, at which point
playback is cancelled and the machine returns to listening, keeping the frames that caused the
interruption so the first words are not lost.

The property that matters for evaluation is this: **the machine is driven one small frame of audio at
a time — twenty thousandths of a second each — and every one of its timings is counted in frames
rather than read from a clock.** Nothing in it depends on real time passing, and it holds no audio or
machine-learning components itself; those are supplied from outside. So the whole behaviour is
reproducible with no microphone and no speaker: feed it a recorded file, or a scripted list of "this
frame is speech, this one is not", and it does the same thing every time.

That is not theoretical. On this machine, with no working audio path in the loop and no hand-tracking
model installed, **ninety-six tests covering the speech and gesture pipelines run and pass** —
including the interruption behaviour, the absolute listening cap, and the case where the detector is
stuck reporting speech on ambient noise.

**The honest limit on real hardware.** In a room with an open microphone and a real speaker, the
assistant hears itself, and the code says so plainly rather than hiding it: interruption handling
needs acoustic echo cancellation or output ducking, and without either the live loop should be run
**half-duplex** — microphone muted while speaking. The doctrine sentence is blunt about where the fix
lives: "hysteresis alone does not defeat sustained self-echo — echo cancellation is the real fix and
is a runtime and hardware concern, not a state-machine one." **The state machine is finished; the room
is not solved.**

### Navigating by voice — the narrowest capability in the system

There is one thing a spoken phrase can do that a typed one usually would not: change which screen the
owner is looking at. It deserves precision, because it is the smallest capability in this document and
its smallness is the point.

**What it does:** on an unambiguous command naming a known screen, it writes one signal into the
owner's record, which the interface is watching, and the owner's own browser switches screens. That is
the entire effect.

**What it does not do**, in the code's words: "it runs no tool, touches no target, and cannot type or
launch." It reaches nothing outside the browser tab the owner already has open.

**When it is allowed:** only while the voice setting is on and the emergency stop is off. If either
fails, the phrase is not treated as navigation at all — it falls through to the ordinary path, which
applies its own gate. Navigation can never be a way round the switch or the stop.

**How strictly it matches.** One leading verb is stripped ("open", "show me", "go to", "switch to" and
a few more), then a trailing "screen", "page" or "tab"; the remainder must then match a screen's short
name, its printed label, or one of its listed alternative names — **exactly**. And then the decisive
rule:

> **Zero matches, or more than one match, produces no navigation at all.**

An ambiguous phrase does not guess and does not pick a favourite; it is handed on as an ordinary
question. That is what stops it hijacking real speech: a sentence that merely contains the word
"findings" is a question about findings, not a command to open a screen.

**Where the list of screens comes from.** Not from the model, and not from anything the speaker says.
It is a committed list of the interface's real screens, checked in the build against the interface's
own navigation menu, so — in the code's words — the system "can only navigate to screens that actually
exist." The browser applies the same discipline at the other end: an incoming screen name is checked
against its own list of known screens before anything moves, so an unrecognised or malicious name
navigates nowhere.

**One separation worth naming here.** The on-screen indicator showing whether the assistant is idle,
listening, thinking or speaking changes several times a sentence, and that churn is **never** written
to the signed record; it goes to a small owner-only file instead. *Audit* is what was authorised and
done; *telemetry* is what a light on the front panel shows.

### Voice: what is built, what needs hardware, what is not built

| Component | Honest status |
|---|---|
| The four-state machine, full-duplex handling, interruption | **Built and tested**, offline, against recorded audio files and scripted frames. |
| Detecting that someone is speaking | **Built and working** — a simple loudness measure with no model. A better model-based detector is an optional upgrade; **its library is not installed on this machine**. |
| **Hands-free wake word** | **NOT BUILT.** What is there fires after a few consecutive loud frames. The code calls it "a stand-in for the real custom-'SIGIL' … model (which needs training data)." Loudness is not word recognition. **"Say SIGIL and it wakes up" does not exist.** The optional real wake-word library is also not installed here. |
| Turning speech into text | A cloud service is the command-line default. A local transcription model is supported, but **it is not installed in the sovereign environment on this machine** — and the small model it would load was never fully downloaded, so even where the library is present the weights are a half-finished file. On this host the local route therefore falls through to a visible placeholder saying no model is installed. **It does not invent a transcript.** |
| Turning text into speech | The cloud service is the default; a local alternative exists in the code but **its library is not installed here**; the honest fallback is silence of realistic length, so the loop still runs and can still be interrupted. |
| The live microphone loop | **Cannot start on this machine.** The optional audio-device package is not installed in the sovereign environment, so the live loop cannot open a microphone or a speaker regardless of what hardware is attached. Everything above was exercised through files and scripted frames. |

**The sovereignty point an agency will care about most.** The cloud transcription option sends the
**captured audio** off the machine; the cloud speech option sends the **reply text** off the machine.
Both are third-party services, both are the current command-line defaults, and a key for them is
configured on this host. The code marks each with an explicit note that a third party is involved and
names the local alternative. **Neither is required by the design** — a local transcription model and
a local synthesiser are both supported, and the silent fallback is always available.

**But neither local option can run on the machine this chapter was checked against, and that must be
said plainly, because it is the sentence an agency will act on.** The transcription library is not
installed in the sovereign environment the shipped command actually uses; the small model it would
load was never fully downloaded, so even the copy of the library that does exist elsewhere on this
host has nothing to load; and the local synthesiser's library is not installed either. The local
route therefore returns the honest placeholder rather than a transcript, and the local speech route
returns silence. **On this host the only working speech services are the two commercial ones.** Both
gaps close with a package installation and a completed download — this is a deployment gap, not a
design gap — but until they are closed, sovereignty over voice is a property of the design and not of
this deployment, and a deployment that leaves the defaults alone is sending audio to a commercial
provider. That must be a decision rather than an accident.

---

### Pointing at it: the one sentence to remember

> **A gesture alone can never type a password or launch a program.**

That is not a policy in a manual; it is the shape of the code, and it comes from two enforcement
layers that must be read together.

**Layer one: nothing is injected outside an owner-armed session.** Arming locally **requires the owner
key** — there is no way to arm it without the owner identity — and arming writes a signed record, so
the fact that gesture control was authorised at a particular moment is itself tamper-evident evidence,
with the indicator lit while it lasts. The session lives only in the memory of the owner's own running
process, carries a deadline, and ends on disarm, on losing sight of the hand, or on expiry. **With no
live session, injection is refused.** If the owner has turned the gesture setting off, arming is
refused outright, loudly, and the refusal is recorded.

**Layer two: every intent's permission level is worked out, never declared.** Each gesture is turned
into an honest name for what it would do, and that name is classified by the same fail-closed
component that classifies everything else on the sovereign side. The result:

| Gesture intent | Level | What happens |
|---|---|---|
| Pointer move | Reversible internal act | Injected inside the live session. Not recorded individually — see below. |
| Click | Reversible internal act | Injected inside the live session, and recorded. |
| Scroll | Reversible internal act | Injected inside the live session, and recorded. |
| Drag | Reversible internal act | Injected inside the live session, and recorded. |
| **Typing text** | **Externally visible** | **Queued for a verified owner or device approval bound to that exact action. Never injected automatically.** |
| **A key combination** | **Externally visible** | **Queued, as above.** |
| **Launching an application** | **Externally visible** | **Queued, as above.** |

The classifier's design is what makes this hold. Input injection has no honest safe verb in its
vocabulary, so it is **dangerous by default**; the four pointer names and three keyboard names are
exact-name exceptions checked **after** the dangerous-word pass, so a dangerous word anywhere in a
name always wins. The bare words "move" and "type" are deliberately never added to the general
vocabulary, so an unrelated tool whose name contains them stays at the strictest level.

A limit stronger than the design claims, found by reading the injection routine itself: **no gesture can
reach the keyboard at all.** The routine that reaches the operating system has branches only for move,
drag, click and scroll, and nothing anywhere in the system carries out an approved typing intent. A
queued item is therefore a *record of an intent*, not a keystroke waiting on a timer — approving it
releases no stored password into the keyboard, because nothing would carry it out.

Be precise about what that does and does not say, because a checker will look. The input layer
underneath *does* have a typing method and a key-combination method, and on this machine the tool they
would drive is installed — so those two are code that exists and would work if something called them.
Nothing does: no gesture path calls either one. Launching an application is absent in the stronger
sense — no input layer implements it at all.

### Ambiguity does nothing

A gesture becomes an intent only after passing a debouncing machine built on the same frame-counted
principle as the speech loop. A discrete gesture fires only after **four consecutive identical
readings** that are both **confidently classified** and **clearly ahead of the runner-up
interpretation**, followed by a cooldown before another can fire. If confidence is low, or the best
and second-best interpretations are close, the reading is treated as neutral, the counter resets and
**nothing happens**. Eight frames with no hand in view produce a "hand lost" signal and the session
disarms itself.

The audit discipline mirrors the speech layer. Arming, disarming and discrete actions go on the signed
record; pointer movements at thirty frames a second do not, because records at that rate would
overwhelm an append-only log, so they are treated as telemetry. And when the underlying input
mechanism cannot actually inject anything, the record does not lie about it: it says the action was
**not** injected because the input path is inert. **A log entry claiming an injection that physically
did not happen is treated as a defect, not an acceptable approximation.**

### Five ways a live gesture session dies within a frame or two

Every frame, before anything can be injected, five conditions are checked in order. Each is bounded to
roughly one or two frames — **not to the session deadline** — so an owner who wants it stopped does
not wait.

| What the owner (or the system) does | What happens |
|---|---|
| Engages the emergency stop — including from the phone | Session disarms; nothing is injected. |
| Turns the gesture setting off, from the interface, the command line or the phone | Session disarms; nothing is injected. |
| Revokes the device that armed the session — a lost or stolen phone | That device's in-flight session disarms immediately, rather than running to its deadline. |
| Nothing is armed | Injection refused. |
| The session's deadline passes | Session disarms. |

The mechanism is worth a sentence, because it is why the guarantee is real rather than aspirational:
the checks re-read the record **only when the record has grown**, and engaging the stop, flipping the
setting or revoking a device each *append* something — which is exactly what triggers the re-read. A
pure stream of pointer movements appends nothing, so a thirty-frames-a-second loop does no repeated
scanning at all. Every one of these checks fails toward *stopping*: if the system cannot determine
whether a device is still authorised, it treats it as revoked.

### The honest status of gesture — the largest caveat in this chapter

**On-box camera gesture control is not operational, and this document will not describe it as though
it were.** Three independent confirmations, all in the code:

1. The hand-tracking stage reports itself as working only when a checksum-pinned model file is present.
   When it is not, its detection routine is a **documented no-op that always returns an empty result**
   — never a fabricated hand.
2. The daemon that would run the camera loop warns loudly at startup that local camera gesture is not
   operational for want of a model, and that "the loop will process frames but can never fire a
   gesture intent."
3. The project's own feature inventory states flatly that local camera gesture is not functional and
   that gesture input is the phone companion.

**Verified on this machine: the model directory does not exist.** The runtime that would execute such
a model is installed; there is no model for it to run.

Three further limits a sceptical reader would find:

- **There is no shipped command that starts the local gesture daemon.** The function exists and is
  driven by the test suite; the sovereign command-line interface offers no verb that launches it. The
  "with gesture" switch on the system's bring-up command is **not a process at all** — it flips the
  navigate-by-gesture setting on, one shot, and exits.
- **The phone-as-trackpad path is built and unit-tested but not wired end to end in this tree.** The
  design is deliberately private: the phone runs its own hand detection and sends **tiny landmark
  measurements, never the owner's pictures**, which is why that path can honestly declare it uploads
  nothing; the decoder is strict, any malformation yields an honest empty result rather than a
  fabricated hand, and stale, duplicated, reordered and foreign-session batches are dropped. But the
  phone bridge's list of permitted actions does not include a landmark stream, and nothing outside the
  test suite feeds landmarks into the loop. **What is wired end to end from the phone is the signed
  request to *arm* a session** — signed with the phone's own key, re-verified in full by the desktop
  for freshness, the emergency stop, the gesture setting, replay, a single live session, and a
  deliberately shorter deadline than a local arm. The phone's own screen says as much: this only
  records a signed request; it is not armed yet; the desktop decides.
- **Injection on this machine would be limited to one display system**, because only one of the two
  supported injection tools is present. A machine with neither is honestly inert and says so in the
  record instead of claiming success.

Finally, **navigating by gesture is a mode, not a capability.** Unlike the voice and gesture settings,
which default to on, it defaults to **off** and is entered only by explicit owner action. While on, a
live armed session's swipes and pinch change screens instead of scrolling and clicking — reached only
after all five per-frame checks above, and mapped to **no input action at all**, so the operating
system is untouched.

### What both surfaces have in common

Voice and gesture make the same argument twice: **a new way of asking is not a new authority.** The
microphone gets no permission table of its own; it borrows the one every other path uses and inherits
the signed record with it. The camera does not decide what a wave of a hand is worth; the same
fail-closed classifier that refuses to auto-approve an unknown command name also refuses to let a hand
gesture become a keystroke.

Both are governed by a switch with a deliberate asymmetry. **Turning either capability off always
takes effect**, even unsigned — off is the safe direction, and the worst a forged "off" can do is
inconvenience the owner. **Turning either back on requires the owner's signature** and a strictly
increasing stamp inside the signed portion, so a genuine "on" captured last week cannot be replayed
after the owner switched it off. If the setting cannot be read at all, it resolves to off.

That, rather than the hands-free demonstration, is the part worth taking away.

## 8. The cockpit and the status overlay


### 8.1 What this is, and why it matters

The sovereign side has its own small web program — the system calls it the **cockpit** — serving two
things: a read view of the permanent record, and one narrow channel through which the owner can
change something.

Its most important property comes before any mechanism. **Every item shown on screen can be clicked,
and clicking it re-checks that item's integrity there and then rather than repeating what was
cached.** The reply carries either a verified marker or the specific reason the check failed. Ask for
a record that does not exist and the reply says so in words — *"no grounded record — not fabricated"*
— rather than showing an empty screen a reader might mistake for an answer.

### 8.2 How the cockpit protects itself

Four properties, all enforced in the program rather than in a configuration file a deployment could
get wrong:

| Property | What it means in plain words |
|---|---|
| **It refuses a public address** | The program will not start on an address reachable from the wider internet, or on the catch-all "listen everywhere" address. To serve a real domain name an operator puts a separate front door in front of a private address: the tunnel or proxy is the network boundary, never the listener. |
| **A session pass-phrase printed to the terminal** | Generated at start-up, so only somebody at the machine can pick it up. The served page carries it; a page belonging to any other website cannot read it. |
| **Reading and acting are separate planes** | Reading needs the pass-phrase. Acting needs the pass-phrase **and** an exactly-matching record of which page the request came from **and** an approved address in the request header — the combination that defeats a hostile website re-pointing a name at a private address. |
| **The signing key never enters the browser** | The browser sends a request; the *server* signs. A stolen browser session cannot walk away with the ability to sign. |

Two smaller details show the same instincts. The "ask a question" route is a *read* that starts a real
reasoning process, so it carries the full action gate — classification follows what a request does,
not where it sits in the menu. And the ordinary access log is deliberately switched off, because the
pass-phrase can travel in a web address for the live feed and would otherwise be written to disk.

### 8.3 A contradiction in this briefing, resolved

Chapter 9 of this briefing used to call this cockpit **legacy** — "an older design", "a single page
with five panels". The sovereign side's own documentation calls it the **current** interface, its
"glass cockpit". Both statements sat in the repository at once, and a document whose value is
checkability cannot leave that standing. Here is the resolution, from the code; chapter 9 has since
been corrected to carry it.

**Two different things share the name:** the cockpit *program*, and the cockpit's own *page*. Three
pieces of evidence settle which is which.

1. **Starting the whole product starts this program first, and the product refuses to run without
   it.** The launcher brings up three back-end programs; the cockpit is the first, and if it does not
   come up and announce its session pass-phrase the launcher prints an error and stops.
2. **The modern unified interface is a client of this program.** It makes sixteen calls to
   sovereign-plane addresses, every one served here: the summary read that fills the dashboards, the
   settings read, the **single** owner-signed channel through which every owner-plane change in the
   whole interface passes, the governance event stream, and the status-overlay stream below. Remove
   this program and the modern interface loses its entire sovereign half.
3. **The five-panel page does still exist and is still served** at the program's own root address —
   approval queue, agent activity and budgets, a capability panel, a live event feed, a detail
   overlay.

The precise statement is therefore: **the sovereign cockpit is the current and load-bearing back end
of the modern interface; its own five-panel page is a superseded front end that is still shipped and
still served.** The word "legacy" is right about the page and wrong about the program; the sovereign
documentation is right about the program and overstates the page. A reviewer who meets the
five-panel page should read it as a fallback that still works, not as the product's face.

### 8.4 The status overlay, and why it is a cross-plane channel

The **overlay** is a small card in the corner of the unified interface showing what the sovereign
assistant is doing right now — listening, thinking, speaking — with the line it heard or is saying.
It can be minimised to a dot or dismissed, and a new interaction brings a dismissed card back.

Described that way it sounds like decoration. It is not: it is **the one live channel that crosses
from the sovereign side to the unified interface**, and it carries two kinds of traffic from two
different places. **Navigation signals** come from the signed permanent record — when the owner says
"go to findings" or makes a navigating gesture, the sovereign side appends a signal, the cockpit
tails the record and passes it on, and the interface changes screen. Nothing is typed and no program
is launched; the signal is a request to the owner's own browser, and that is its entire power.
**State events** — the listening/thinking/speaking updates — come from a small scrap file.

The navigation half is deliberately hemmed in. **The interface will navigate only to a screen that
exists in its own navigation list**, and the membership test is built on a lookup object created with
no inherited properties at all — so a signal naming one of the internal property names every ordinary
object carries cannot come back "true" and steer the browser somewhere it should not go. A garbled or
spoofed signal navigates nowhere.

### 8.5 Why fast-changing state goes to a scrap file and not the record

This design point generalises far beyond an overlay.

The speech state machine changes state many times in a single exchange, and the gesture layer moves
the pointer about **thirty times a second**. Written to the signed, append-only history, either would
render it useless — the code says so in as many words: thirty-per-second records "would swamp the
append-only log". A reviewer months later would be scrolling past hundreds of thousands of cursor
positions looking for the three decisions that mattered. So the system draws a hard line between
**telemetry** and **audit**:

| | Telemetry | Audit |
|---|---|---|
| **What it is** | What is happening right now | What was decided, and by whom |
| **Where it goes** | A small file readable only by the owner's own account, replaced whole each time so a reader never sees a half-written state | The signed, hash-linked, append-only record |
| **What survives** | Only the latest value — nothing is history | Everything, permanently, in order |
| **If writing fails** | Swallowed on purpose, so telemetry can never break the thing it reports on | A failure to append is a real failure |

The code is blunt about that file's status: *"The file is ephemeral state, not a record of truth."*
The reader ignores it entirely if it is oversized or unreadable, and passes it on only when it
changes.

The consequence for an auditor is the thing to hold on to. **The permanent record contains what was
decided, not what was displayed.** A ten-minute spoken conversation adds a handful of entries, not
tens of thousands. The same split governs gestures: arming, disarming and discrete actions are
recorded; per-frame pointer movement is not.

### 8.6 What is honest about this today

The channel is built, wired at both ends and tested; the cockpit's tests and the status-file tests
were run on this machine during the preparation of this section and passed. Its two **producers**
belong to this chapter's earlier sections: the listening/thinking/speaking events exist only while a
live speech loop is running, which needs a microphone; the navigation signals come from speech or a
gesture session, on-box camera gesture being inert here for want of a model file. **Neither producer
has been run against live hardware on this machine.**

---

## 9. The memory server — giving any assistant cited recall


### What this is, before how it works

An owner who has worked for years through an AI assistant has a very large amount of history —
decisions taken, reasons given, things promised, things built — and almost none of it is available
when it is needed. It sits in transcripts nobody can search.

The sovereign side turns that history into a searchable, tamper-evident record. **This section is
about the small piece of software that hands that record back to any AI assistant the owner is
already using, in a form the assistant is asked to cite.** The effect is simple: a new conversation
can begin with the assistant already knowing what the owner decided eight months ago, *and being
able to point at the exact record where the owner decided it* — rather than producing a confident
paraphrase of something that may never have happened.

The mechanism is a protocol met earlier in this briefing. MCP — the Model Context Protocol — is a
published standard by which an AI assistant can discover and call tools living inside somebody
else's software. Chapter 9 describes the *engine's* MCP server, which answers "what does VIGIL let
an outside AI do?" This section describes a **second, entirely separate server on the sovereign
side**, answering a different question: **what does the owner's own memory let an outside AI read?**
Conflating the two would be a serious misreading, so they are distinguished in full below.

### The eight tools

The server announces itself to an assistant as the sovereign side's memory, and offers exactly eight
tools. All eight read. None of them acts.

| The tool, in plain words | The question it answers | What comes back |
|---|---|---|
| **Search memory** | "What do I know about this?" | Records matched by meaning rather than keyword, each carrying its record number, content fingerprint, date, session and project. |
| **Read a stretch of the record** | "What actually happened around this point?" | A contiguous run of records in numbered order — messages, tool calls, commits, documents — optionally filtered to one kind, capped at 200. The raw stream, not a search. |
| **Memory health** | "How much is stored, how much is searchable, does the record still hold together?" | Counts of stored and indexed records, the model used to make them searchable, and — on request — whether the integrity chain and the signed anchor on its end still verify. |
| **Look up an entity** | "Show me this project, session, commit or document, and what surrounds it." | The entity with its neighbours, each carrying the record number that produced it, so any part of the answer follows back into the raw record. |
| **Query the structure** | A structured question over the memory graph. | Columns and rows. Read-only; see below. |
| **Open threads** | "What is still unresolved for me?" | Current grounded decisions and commitments that nothing later has superseded, most stale first, each cited. |
| **Commitments due** | "What have I promised, and by when?" | Grounded promises with a due date, earliest first, reduced to the latest version per subject so a rescheduled deadline never serves the old date. |
| **Contradictions pending** | "Where have I contradicted myself?" | Subjects with more than one live decision, each naming the conflicting record numbers — **flagged for the owner, never resolved automatically**. |

The last three carry a property worth stating on its own. What they serve as the *content* of an
answer is the **verbatim quotation from the owner's own record**; the assistant's sentence about it
travels alongside in a separate field, labelled a summary. The code comment is explicit that the
model's sentence "is served only as an advisory summary (never the fact)". In plain terms: **the
owner is shown their own words, and the machine's paraphrase is visibly marked as the machine's.**

### What "cited" means here, exactly

Every result carries a record number and, in most cases, a content fingerprint. Together those
identify one line of the append-only record uniquely, and the record is hash-chained, so an altered
line does not survive verification. That is what makes a citation worth anything: the owner can go
and look, and can tell whether what they are looking at has been changed.

The tools also carry, in the text the assistant reads before calling them, an instruction to cite.
The status of that instruction needs stating precisely: **it is a description the assistant reads,
not a mechanism that constrains it.** Nothing here can force an assistant to quote its citations
honestly. What *is* mechanical is that the citation is present in every result — so an uncited
answer can be spotted, and a wrong one can be checked.

### The empty answer that admits it is empty

This is the design point that most distinguishes the memory server from ordinary retrieval.

Search by meaning always returns *something*: the nearest thing in the collection, however far away.
That is exactly the condition under which an AI assistant fabricates — handed three weakly related
fragments and a question, it will write a fluent answer.

So the search tool does not simply return its best matches. It applies a **grounding threshold**,
and the code records the measured behaviour that sets it: with the model in use, a genuinely present
topic scores roughly 0.72 to 0.78, an absent topic roughly 0.55 to 0.62. The threshold sits at 0.66,
between the two; individual results below 0.55 are discarded as noise outright. If the best match
falls below the threshold, the tool returns **an empty list and a note** saying memory genuinely has
nothing solid on this, and telling the assistant to say so rather than invent an answer.

This is the sovereign side's version of the rule that governs the whole system: **an honest "I do
not know" is a correct answer, and a fluent guess is a defect.**

### There is no way to write

The strongest safety property of this server is the absence of something. **Not one of the eight
tools appends to, alters, or removes a line from the owner's record.** There is no write path to be
guarded, gated or bypassed, because there is no write path at all.

Two precisions, because an overstatement here would be worse than useless:

- The eight tools are the eight functions written into that one file. There is no configuration file
  that adds a ninth and no request a caller can make that widens the set. This is a stronger
  arrangement than an allowlist that can be edited, though it is also less flexible.
- One side effect does exist, and it is not on the record. When the server first opens its
  similarity index it will create that index's empty container if none is there — an empty container
  in a *separate* database. It cannot put anything into the signed record.

The structured-query tool deserves its own note, being the only one that takes a whole query written
by the caller. It is guarded twice. First, a keyword check refuses anything containing a create,
set, delete, merge, drop, alter, copy, install or attach instruction — a blocklist, which is the
weaker kind of guard, the kind that fails when somebody thinks of a word nobody listed. Second, and
load-bearing, **the database itself is opened in read-only mode**, so a write instruction slipping
past the wordlist is still refused by the database. The code says exactly this: writes are refused
"both by a keyword guard and by the read-only connection."

### It refuses to share a program with the offensive half

The moment this server loads, before anything else, it checks whether any part of the offensive
engine — the assessment engine or the third-party agent body — has been loaded into the same running
program. If any has, it **refuses to start**, naming the offending parts in the error.

That is the wall down the middle of this system, enforced inside a single running program rather
than by a rule someone is trusted to follow. The owner's private memory server cannot be running in
the same process as the tooling that attacks things.

### The two MCP servers, distinguished

A reader who has met chapter 9's server may assume this is the same thing seen from another angle.
It is not. They share a transport and a protocol and nothing else.

| | The engine's server (chapter 9, section 5.8) | The sovereign memory server (this section) |
|---|---|---|
| Which half of the system | The offensive engine | The sovereign side |
| The question it answers | What may an outside AI **do** with this engine? | What may an outside AI **read** of the owner's own memory? |
| How many tools | **Two** by default | **Eight**, fixed |
| Can the set be widened? | Yes — by a deliberate operator act | No — the set is the code |
| What the tools do | Re-check a finding's evidence; describe a declared service | Search, read and summarise the owner's own record |
| How safety is achieved | Every call re-passes the full permission chain, plus a four-property re-check, on top of the allowlist | Nothing to gate: no tool acts, and the graph database is opened read-only |
| What a result is labelled | An observation — a lead, never a proven fact | A citation — a record number and fingerprint |
| Transport | On-host standard input and output; no network listener | Identical |
| How it is started | A command-line act; no start/stop control in the interface | Registered in the assistant's own configuration; the assistant starts it |

The sentence to carry away: **one server lets an outside assistant ask the engine to check
something; the other lets an outside assistant read the owner's memory and cite it. Neither can
write.**

### Honest status

**This is live, and it was exercised while this section was written.** The server is registered on
this machine and its eight tools were attached to the session that produced this text. Two were
called. The health tool returned real counts; the search tool, asked about a technical topic from
the owner's own history, returned three ranked records with dates, projects, session identifiers,
content fingerprints and scores above the grounding threshold. This is not a scaffold.

**But the memory it is serving, on this machine, at this moment, is in two pieces that do not agree,
and the briefing must say so.** The signed, hash-chained record on this host currently holds
**sixteen entries** — governor and settings events, and one commit. Its chain verifies cleanly. The
similarity index beside it holds **13,667 entries, numbered up to 43,350**, retained from an earlier
and much larger record. The consequence is concrete and checkable: a search returns citations
numbered in the tens of thousands, and **those record numbers do not exist in the current signed
record**, so a sceptic following one would find nothing there. The tools that read the signed record
directly — the range reader and the three consolidation tools — will accordingly find little or
nothing until the ingestion and consolidation passes are run again on this machine.

This is a state-of-this-host observation, not a design flaw: the search index is a rebuildable
projection, and rebuilding it from the record it was built from is routine. What is not routine is
rebuilding it *here*, because that record is no longer the one at the standard location — so on this
machine the index, like the entity map in section 3.2, is the last copy of what it holds and should
not be deleted on the assumption that a rebuild would bring it back. It also means **the figure of roughly
43,000 records in the project's own documentation describes a record that is not the one on this
machine today**, and no reader should be given that number as a present fact.

Four further limits, stated plainly:

- **The record is not currently anchored.** The health tool reports no signed head, with the
  instruction to run the signing command to anchor it. The chain of sixteen entries links cleanly;
  the signature that would distinguish honest growth from truncation has not been applied.
- **There is no test file for the server itself.** Of eighty-three test files on the sovereign side,
  none exercises it. What the eight tools are built on — the record store, the consolidation
  queries, the graph, the index — is tested; the eight-function wrapper around them is covered by
  use, not by a test.
- **The server has no authentication of its own, and needs none.** It speaks over the standard input
  and output of a program the assistant starts, on the same machine, as the owner's own account. No
  network listener means no remote surface, and the security boundary is the owner's user account:
  anyone who could reach this server could already read the same files directly.
- **It is all-or-nothing, and it unseals.** There is no per-topic filter and no redaction stage. Any
  assistant configured with this server can read everything in the owner's memory. Content sealed on
  disk is unsealed for display when the key is available — and shown still-sealed, rather than
  crashing or guessing, when it is not. **Configuring this server is a decision to give an AI
  assistant the owner's whole history**, and should be put to an approving authority in those terms.

## 10. The mesh, and the phone


### 10.1 The plain-English version

**An authorised official can approve a live action from their phone, and the owner's master key never
leaves the desktop.**

Every mechanism below exists to make that sentence literally true rather than approximately true. A
phone gets lost, stolen, sold and handed to a repair shop; a design that puts the master key on it —
even encrypted, even behind a fingerprint — has made the phone into the crown jewels. This one does
not. And one correction before the mechanism, because the natural phrase is the wrong one: **the
phone does not "control" the desktop.** It *signs requests, and the desktop verifies them*. That is
not pedantry — everything the phone is not allowed to do follows from it.

### 10.2 What the phone holds

The phone holds exactly one secret: **its own key**, and nothing else. That key is created in the
phone's own browser the first time the companion app is opened, in a mode that tells the browser to
use it for signing but never to hand it back — not to a website, not to the companion app itself, not
to anything. The phone then displays its public half plus a short human-readable fingerprint; the
owner, at the desktop, compares that fingerprint against what the desktop computes and authorises the
device once, as an entry in a signed ledger on the permanent record. The desktop's own master key
stays on the desktop. In the code's words: *"the phone signs, the server only verifies."*

The companion app is a normal installable web app served by the desktop. It requires a browser whose
built-in cryptography supports the signature scheme in use — recent versions of the major browsers —
and if it does not find it, **the app says so plainly and refuses to operate** rather than dropping
to something weaker. That is a real deployment constraint, and it is written down as one.

### 10.3 There is no password on the wire

A security reviewer should look here first. **There is no shared secret travelling between the phone
and the desktop at all** — no password, no bearer token, no key that could be captured in transit and
reused.

**Authentication *is* the signature.** Every request the phone makes carries a small signed envelope,
and the desktop rebuilds, byte for byte, exactly what the phone claims to have signed. Because the
two sides are written in different programming languages, the rule for producing those bytes is a
formal agreement between them with a fixed worked example pinned in the tests — get it wrong by one
character and every signature is rejected, which is the right failure direction.

Seven properties then bound what a captured request can do:

| Property | What it protects against |
|---|---|
| **The authorised-device list is recomputed on every single request** | A revoked phone stops working on its *next* request — revocation is immediate by construction, not by a timer. One bound, stated plainly: the live notification feed is checked when it opens and not again, so a revoked phone that simply holds an open feed keeps receiving three-field notices until it disconnects. The companion app re-signs that feed every ninety seconds, which closes the gap for an honest client; a hostile one need not. |
| **The signed request names the one thing it authorises, checked against the door it arrived at** | A captured request for the low-sensitivity queue listing cannot be re-aimed at the route returning the owner's own recorded on-screen text. A lesser permission cannot be pointed at a greater one. |
| **Each request carries a timestamp, checked against a two-minute window** | A captured request goes stale. |
| **Requests that *change* something also carry a counter that must beat the highest ever recorded for that phone — checked and recorded together, under a lock** | The same captured request can never be replayed, not even by two copies racing at the same instant. |
| **The listener refuses any publicly reachable address** | A misconfiguration cannot expose the service, because it will not start. The private tunnel is the boundary. |
| **The check for modern internet addresses is a positive list, not a "not public" test** | Two globally routable transition ranges are misclassified as private by the standard library the code would otherwise have trusted. |
| **The transport certificate is self-signed, its fingerprint printed once and stable across restarts** | The owner compares it once, on the phone. A change later means interception, not a restart. |

One honest limit sits inside that list. Requests that only *read* are bound by the freshness window
and by their permission scope, but they consume no counter — a read changes nothing, and recording
every one would write to the permanent history on every screen refresh. So a captured read request
could in principle be replayed **within two minutes, by someone already inside the private tunnel, to
re-read the same thing.** That is the stated bound, not an accident.

### 10.4 What crosses the tunnel, and what does not

The notification feed and the pending-items list carry **three fields and no more**: a sequence
number, a consequence level, and a kind. The code's own summary is *"never a subject, never a
payload, never a secret."*

So from the feed and the queue the phone learns that item 412 is awaiting approval, at the higher of
the two supervised levels, and that it is a draft message. **Those two routes tell it nothing more —
not who the message is to, not what it says.** Approving from that queue is approving a *numbered
item*. That is a deliberate confidentiality choice and equally a usability limit — an approver
working from a phone is confirming a decision they already understand, not reading a case for the
first time.

Two other routes do return content, and the code marks both out as different from the queue:

| The route | What it returns |
|---|---|
| "Where did I last see this?" | The owner's own verbatim recorded on-screen text — never a paraphrase |
| "Show me record number N" | That one record's stored contents in full; for a queued draft, that means the recipient, the subject and the body |

Each of the two carries its own separate permission, which a lesser request cannot be re-aimed at —
and the companion app does use the second one: tapping an item in the queue fetches the record behind
it and displays its contents. So the honest sentence is narrower than "the phone never sees the
case". **The phone is never *sent* the case unasked; reading it is a second request, separately
permitted, that any still-authorised phone can make.** Approving and reading are different acts with
different scopes, which is the property that matters when a phone goes missing: revoke the device and
both stop.

### 10.5 What the phone can do, and what it cannot

| The phone **can** | Notes |
|---|---|
| Approve or deny a queued item at the two supervised levels | The phone signs; the desktop verifies and only then records. Approvals can be signed **with no connection at all** and queued, flushing when the tunnel returns. |
| **Panic-halt** the whole agent mesh | Signed like every other request from the phone — the desktop still checks the phone's key, the freshness window and the replay counter before it acts, and a failure at any of those halts nothing. What needs no signature is the halt *entry once it is on the record*: see below. |
| Relay a typed command to the reasoning kernel | Through the same classification gate and signed action log as a command typed at the desktop or spoken aloud. |
| Browse a read-only view | Queue, summary, budgets, recent agent activity, one record at a time, memory-graph health. |
| Recall grounded on-screen history | Verbatim captured text, never a paraphrase or a model's guess. |
| Arm a gesture session | Opt-in, off by default. The signed request to *arm* is wired end to end; the trackpad it would arm is not — nothing yet carries hand movement from the phone to the desktop. See below. |

| The phone **cannot** | Why |
|---|---|
| **Release a halt** | Halting is the safe direction, so the check that folds up the record honours *any* halt entry it finds there, whoever wrote it — a nuisance halt is at worst an inconvenience. Un-halting is the dangerous direction: a release counts only if it verifies against the owner's own key and its issue time exceeds every release already honoured, and it stays with the owner at the desktop. The switch is deliberately asymmetric. The asymmetry is in how the *record* is read, not in how the phone's door is guarded — the door checks a signature either way. |
| **Sign as the owner** | The master key is never used on this path at all. |
| **Widen a gesture's authority** | Pointer movement, clicking, scrolling and dragging stay at the reversible level; typing, key combinations and launching an application always queue for a separate approval. A gesture, from a phone or a camera, can never type a password or start a program. |
| **Be shown anything sensitive on the feed** | Three fields only. Reading the case behind an item is a separate request under its own permission, never something the feed pushes out. |
| **Upload the owner's pixels** | See below. |
| **Keep an armed gesture session through a revocation** | A revoked phone's *in-flight* session dies within about one or two frames of video, not when its time limit expires. (The one thing a revoked phone can hold on to is an already-open notification feed — three fields, until it disconnects.) |

### 10.6 The trackpad, and the pixels that never leave the phone

Using a phone as a trackpad is the one place where the design could easily have leaked something
serious — a camera feed of the owner's room, streamed to a desktop. The design refuses that, and the
desktop half of the refusal is built and tested.

**The design puts the hand detection on the phone and sends only the result.** What the desktop is
built to accept is a small batch of landmark coordinates — at most two hands, exactly twenty-one
points each — described in the code as *"landmark data, never owner pixels"*. Because the recognition
would already have happened on the phone, the desktop's declaration that this source sends nothing
off the machine is honest rather than aspirational, and the strict gate refusing any vision component
that would upload imagery lets this one through for a real reason. A malformed batch decodes to an
honest *nothing* rather than a fabricated hand; batches from another session, duplicated, out of
order or stale are dropped; and the tracker keeps a single number rather than a growing list, so a
flood cannot exhaust memory.

**What does not exist yet is the sender.** The companion app contains no hand detection of any kind,
the phone bridge has no door through which a batch of landmarks could arrive, and the desktop loop
that would consume them is driven only by the test suite — no shipped command starts it. So no
landmarks cross the tunnel on this machine, and none can until three pieces are built: a detector in
the app, a route to receive a batch, and a command that starts the desktop loop. What is built and
tested is the *receiving* contract, described above, and it is described here because a reader who
met the privacy design without meeting this limit would take an intention for a running fact.

Arming such a session shows the pattern the whole design uses. **The phone signs an arm request. The
desktop only *records* it.** The gesture daemon then re-verifies everything independently — device
still authorised, request fresh within thirty seconds, never used before, no other session live, halt
switch not engaged — and it is that re-verification, not the request's arrival over the network, that
arms anything. A phone-armed session also gets a deliberately **shorter life than one armed at the
desktop**: five minutes against thirty. This remote-arm path widens trust, and is off by default.

### 10.7 What is proven here, and what has not been done here

**Proven on this machine.** Ninety-five automated tests covering the phone bridge, the signed
envelope, the companion app, the transport certificate, remote recall, device pairing, the remote
landmark stream, the status file and the cockpit were run during the preparation of this section and
all passed.

**Demonstrated end to end on this machine.** There is a runnable demonstration that needs **no phone
and no tunnel**: it stands up the real bridge program on the machine's own internal address and
drives it exactly as a phone would, with a stand-in phone key signing every request. It was run to
completion here and walked the whole flow — pair, approve a queued action, relay a command, recall
on-screen history, arm a gesture session, panic-halt — with the real transport, the real signature
checks and every real gate. Only the tunnel and the phone app are stood in for; everything else is
the shipped code.

**Not done here.** No phone has ever been paired with this machine: the device ledger on its
permanent record contains no entry, and no transport certificate has ever been minted — which means
**the phone bridge has never been served for real on this host**. The companion app is shipped and
the walkthrough for a real tunnel is written down; neither has been exercised against a physical
handset here. Read the phone story as *proven in code and proven in a faithful loopback rehearsal,
and not yet demonstrated on a real device in this environment*.

---

## 11. What is proven on one platform, and what is a seam


### 11.1 The sentence, without euphemism

The sovereign side's own documentation ends with this: the other operating-system backends and the
browser-based web engine "are honest, documented seams (Linux is the proven path)." That is
procurement-relevant, so it is repeated without softening. **Linux is the proven path; everything
else in this part of the system is an interface with a deliberately incomplete implementation behind
it.** A seam is neither a bug nor vapour — it is a place where the shape of the work is defined, the
surrounding machinery already talks to it, and the platform-specific piece has not been written.
Naming them lets a deployment plan route around them rather than discover them.

### 11.2 Where each platform actually stands

| Capability | Linux | macOS | Windows | A phone running the core itself |
|---|---|---|---|---|
| **Screen capture** | Via one of four common screenshot tools — **one of which is installed on this machine**, with a graphical display running, so the grab step is available here. What is missing is downstream: the text reader that would make a grab groundable | Via the operating system's own built-in capture command | Via an optional add-on package that may or may not be installed | Via the system capture command, which is usually unavailable without deep device access |
| **Camera capture** | Via the standard video device | **Not built** — declared an honest gap, with the optional tool named for anyone who wants it | **Not built** — honest gap | Via an optional add-on package |
| **Cursor and keyboard injection** | Two possible tools; one is present on this machine, which limits injection to one of the two display systems | **Interface only.** It permanently reports itself unavailable and does nothing | **Interface only.** Same | **Not offered at all**, and honestly declared as such |

Two things in that table deserve pulling out.

**Nothing fabricates a result.** Every capture path returns *nothing* when its tool is missing, rather
than an empty picture or a guess. The two unfinished injection backends neither crash nor pretend:
they report themselves unavailable and do nothing. That matters because of what then appears in the
permanent record — when the injection backend is inert, the record says the action was **not**
injected and names the reason. It does not say "injected".

**A phone running the core is described as a phone.** Such a phone reports itself to the operating
system as Linux; without a dedicated check it would be handed the Linux backend and would claim
capabilities it does not have. That check exists, and the resulting description honestly declares
that a phone does not inject keyboard and mouse events into a desktop.

### 11.3 The browser that was deliberately not built

The documentation lists "the browser-based web engine" alongside the platform backends as a seam. The
code is more specific, and where the two differ the code is what a reviewer can check. A browser
could have appeared in two places, and they are in different states.

**On the research path** there is a defined interface for rendering a page that runs its own code,
with exactly one shipped implementation: one that returns nothing. A page that only assembles itself
in a browser is therefore an *honest gap* — the system reports that it could not read it, rather than
silently reading half of it. The accompanying note explains why the obvious implementation was not
written: a real browser follows redirections, loads material from third parties and executes the
page's own code, all of which would go around the pinned-address protections the fetching layer
depends on. It lists the conditions any future implementation would have to meet, and ends by calling
itself a design note rather than a shipped capability.

**On the account-acting path it is stronger than a seam — it is a structural absence.** The agent that
logs into the owner's own accounts speaks only the plain request-and-response protocol; there is no
browser code path in it at all. When it meets a "prove you are human" challenge and stops, its failure
to escalate to a real browser is not a rule that could be relaxed. There is nothing there to call.

### 11.4 What this means for a buyer

**Deploy on Linux** — that is where the whole path has been exercised, and it is the vendor's own
assessment as well as this document's. **The hardware-facing capabilities are the ones that vary, and
they degrade loudly:** screen capture, camera capture and cursor injection differ by platform, and
every one reports its own absence rather than working around it. And **no claim is made from
measurement about macOS or Windows** — the parts of the sovereign side that are pure calculation over
the permanent record carry no platform-specific code and one would expect them to run, but they have
not been exercised on either platform here, and this briefing does not assert what it has not seen.

## 12. Learning from a page the owner points at

Everything described so far in this chapter learns from material the owner already has: their
assistant transcripts, their code commits, their documents, their screen. There is one route that
deliberately goes outward. The owner can hand the system a web address, and it will read that page —
and a very small number of pages linked from it — and file what it found into the permanent record.

This is the capability in the sovereign side that sounds most alarming when it is described, and it is
the one where the design's central rule does the most work. The rule is stated once and then held to
without a single exception: **nothing a web page asserts ever becomes a fact.** A page is a source of
quotations. It is never a source of truth.

It is worth being blunt about why that distinction is load-bearing here in particular. The open web is
precisely the place where a naive system would learn something false, and learn it *with confidence*.
A page can say anything at all. A language model asked to summarise a page produces fluent, assured,
well-organised prose whether the page was a national standards body or a forum post written by
somebody guessing — and produces equally assured prose about things the page never said, because
producing plausible sentences is what such a model does. A system that let a summariser's output flow
into its own memory as knowledge would, sooner or later, hold a confident belief that came from
nowhere and cite nothing. This route is built on the assumption that this *will* happen, and arranges
matters so that when it does, the false claim arrives already labelled as unbacked.

### 12.1 What the owner does, and what comes back

On the knowledge screen, when automatic learning is switched on, a card appears with two boxes. The
first takes a vulnerability identifier and adds it to the queue of things the owner may later approve
for study. The second takes a web address, next to a button marked **Learn from URL**.

There is a second way in, in the layer behind the screen: instead of an address the owner can name a
**topic**, and the system reads a short curated list of public reference sites rather than a site of
the owner's choosing. That route is built and tested. Stated plainly: **the shipped interface has no
box for it.** The address box is what a user of the screen can actually reach today; the topic route is
reachable from the layer the screen talks to.

What comes back is deliberately a set of counts before it is a set of sentences:

| What the card shows | What it means |
|---|---|
| **N grounded** | claims that are backed by a passage found word for word on a page that was actually fetched |
| **N advisory** | claims the writing model produced that **no** fetched passage backs — kept, displayed, and explicitly not relied upon |
| The host, and the page count | which site was read, and how many of its pages were successfully fetched |
| Up to four thousand characters of the extract | the composed write-up itself: the grounded quotations first, the advisory claims under a heading that says nothing backs them, and a list of the addresses that were *not* fetched, each with its reason |

Two things about that presentation deserve underlining. **The grounded and advisory counts are shown
side by side, as peers, before any prose is shown at all.** The owner's first impression of a learning
run is therefore a ratio — how much of what the model wrote survived checking — rather than a
readable paragraph that invites belief. And **the addresses that were skipped are part of the output**,
not omitted as noise. A crawl that quietly stopped at its budget and reported only what it read would
misrepresent its own coverage; here, the number of addresses that were discovered and then dropped is
always reported, and the first twelve are listed with the reason each was dropped — outside the
permitted site, forbidden by the site's own rules, over the per-site cap, a fetch that failed, or
simply beyond the page budget. Beyond twelve the list stops and the count carries the rest, so a
reader always knows how much they are not being shown.

### 12.2 What it will and will not do to a website

The fetching layer is not a security tool and is not built like one. Three properties define it.

**It reads and never writes.** Every request is an ordinary retrieval — the kind a browser makes when
you open a page. There is no code path in this layer that submits a form, sends data, or attempts
anything a site owner would recognise as probing. The whole sovereign side additionally refuses to
start at all if any part of the offensive engine has been loaded into the same running program; that
check runs the moment the web-reading component is loaded, and it fails loudly rather than continuing.
The consequence worth stating for a reviewer: **this is not the attack tool wearing a different hat.
It is a different piece of software, in a process the attack tool is structurally forbidden to be in.**

**It identifies itself, and never varies.** Every request carries one fixed identifying string that
names the system and says it is authorised owner research. That string is never rotated, never
randomised, and never disguised. This is a deliberate inversion of what a stealthy crawler does, and
it follows the same doctrine as the rest of the system: the point is that the *other* side's logs
should be able to pick this traffic out and attribute it, not that they should fail to.

**It is polite by construction, not by intention.** A minimum interval is enforced between two
requests to the same site — and if the site publishes its own preferred delay, the longer of the two
wins. Requests to one site are taken one at a time. A fetch gives up after twenty seconds and stops
reading a page after about two megabytes, so a slow or enormous page cannot hold the run open or fill
memory.

### 12.3 The four gates every single fetch passes

Before any connection is opened, a candidate address is checked four times. Each check can only
refuse; none of them can widen what an earlier one allowed.

| Gate | What it does | What it is for |
|---|---|---|
| **The permitted-site list** | An empty list permits nothing. For a pointed-at address the list contains exactly one entry: the site of the address the owner typed. The address must also use ordinary web addressing, and the site name is put into one canonical form before it is compared | So a crawl that starts at one site can never wander onto another, and so two spellings of the same site cannot be used to smuggle past the check or to split its rate-limit budget |
| **The private-network check** | The site name is looked up once; **every** address it resolves to must be a public one; and the connection is then pinned to that exact address. Redirections are refused outright, and any proxy configured in the surrounding environment is ignored | This is the one that stops a web address being used to reach the machine's own insides. Without it, a hostile or merely careless address could point at the machine's own loopback, at a neighbouring server on the internal network, or at the fixed internal address cloud providers use to hand out credentials. Pinning matters as much as looking up: a name that answers "public" to the check and "internal" a moment later, when the connection is made, is a known trick, and it does not work here |
| **The site's own rules** | The file a site publishes to tell automated readers which parts of it are off limits is fetched — through the same private-network-checked fetcher, never by the shortcut the standard library offers, which would make its own unchecked request — and then respected. A forbidden address is dropped and recorded, never fetched | Respect, never evasion. And note which way the ambiguity falls: if that file cannot be read because the site returned an error, a refusal or a rate-limit response, **the entire site is treated as forbidden for the rest of the run.** A missing or empty file means the site has no restrictions, which is the standard reading |
| **The per-site pace** | The wait computed above is taken before the request goes out | So a run cannot become a burst of traffic against somebody else's server |

Only after all four is a socket opened.

### 12.4 It is small on purpose

A pointed-at learning run fetches **at most four pages, and follows links at most one step from the
address the owner gave.** That is far tighter than the general research path, which allows
twenty-five pages and three steps.

The reason is not caution for its own sake. **This runs while the owner is waiting.** The button is a
synchronous action: the owner presses it, the request goes out, and the answer comes back into the
same card. A deep crawl behind a button is a hung interface. So the budget is set to something that
finishes, and the honest consequence — that a large site is read shallowly — is reported rather than
hidden.

Within that small budget the order is chosen rather than arbitrary. Candidate links are ranked by how
much their link text and address path overlap with the distinctive words of the question being asked,
with a penalty for each step away from the starting page. The effect is that four pages are spent on
the four pages most likely to contain a passage worth quoting, instead of on the first four links in
the page's markup. A repeat of the same address in a different spelling is recognised and not fetched
twice.

### 12.5 The emergency stop actually stops it

The emergency stop is checked twice on this path, and the second check is the one that matters.

**Before the run starts,** the action is refused outright if the stop is engaged, or if automatic
learning has been switched off. Nothing is fetched.

**During the run,** the stop is handed to the crawl as a cancel signal, and it is consulted *between
page fetches* — before each next page is taken off the queue. When it trips, the crawl abandons what
is left, records the stop as an entry in that same list of dropped addresses so the run ends on the
record rather than merely ending short, and returns what it had. **The practical difference is the difference between a stop that takes effect
now and a stop that takes effect when the work would have finished anyway.** A crawl of four pages
against a slow site, each with a politeness wait in front of it, can run for a noticeable stretch; a
stop that only bit at the end would let every remaining page be fetched after the owner had already
demanded a halt.

There is a second, weaker safety net behind that one, worth understanding because it is what protects
the *other* research path described below. Whatever a run produces, the write-up it wants to file goes
through the same permission gate every automated worker's output goes through, and that gate refuses
under the emergency stop — writing a refusal into the record instead. So a halted run cannot file its
findings. But refusing the write does not un-send the requests. Stopping the fetching is a separate
thing, and it is the thing the cancel signal does.

### 12.6 The keystone: a page is quoted, never believed

Everything above is perimeter. This is the part that makes the capability safe to have at all.

Each page that is successfully fetched is written into the permanent record as its own entry, before
any claim about it is considered. That entry carries the address, the response code the site gave, a
fingerprint of the body received, how many steps from the start it was, and the readable text of the
page. The set of entry numbers created by that step defines a **window** — the exact set of pages this
run actually read.

Then, and only then, a writing model is shown those same page texts and asked to produce claims. Each
claim it produces must carry two things: the entry number of the page it came from, and a quotation
from that page.

Every one of those claims is then put through **the identical admission check that governs the owner's
own memory** — the same check described earlier in this chapter, the one the nightly consolidation
pass uses on the owner's transcripts and documents. Not a similar check written for the web. The same
one. It admits a claim only if all of the following hold:

- the entry it cites is **inside the window** — a claim citing a page this run did not fetch is
  rejected outright, which closes the obvious trick of a model inventing a plausible-looking source;
- the quotation appears **word for word** in that entry, **re-read from the record** rather than taken
  from the model's own copy of it — so a model that quietly edits a sentence while quoting it grounds
  nothing;
- the quotation is **specific enough to mean something** — it must carry at least two distinctive,
  non-trivial words, so a common fragment cannot be used to attach a claim to a page that happens to
  contain it.

And what is then served as the grounded result is **the page's own passage, not the model's sentence
about it.** The model's wording is treated as a pointer to evidence, never as the evidence.

The check has one further property that is the whole reason it can be trusted in this position: **it
can only demote.** There is no input to it that promotes anything, and the model's own stated
confidence is not one of its inputs at all. A claim the model was certain about and a claim it was
hesitant about are checked identically. Anything that fails is not deleted — it is recorded as
advisory commentary, visible, attributable, and marked as backed by nothing.

Put the pieces together and the guarantee is simple to state and simple to audit. **The strongest
thing a web page can achieve in this system is to have one of its own sentences quoted back, with a
citation to a stored copy of the page that fetched it.** It cannot cause the system to assert
anything. It cannot cause the system to act. It cannot enter the owner's memory as knowledge. The
worst case for a hostile page is that it gets quoted — and a quotation, attributed to its source, is
exactly what a careful human researcher would take from an unfamiliar website too.

### 12.7 Learning by topic: references, never targets

When the owner names a topic instead of an address, the system does not go looking for sources. It
reads from a short, fixed, curated list written into the software: the Open Web Application Security
Project's main site and its cheat-sheet series; three MITRE catalogues — of weakness types, of attack
patterns, and of attacker techniques; the United States national vulnerability database; and the
open-source vulnerability database. Seven sites, all of them public reference works.

Two points about that list matter more than its contents.

**These are references, never targets.** The system reads their documentation the way a person reads a
manual. Nothing about their presence on this list makes them subject to any kind of testing, and the
web-reading layer has no ability to test anything in any case. The distinction is the same one drawn
elsewhere in this briefing between a source of information and a system under assessment, and it is
worth keeping crisp: a list of sites the system may *read* is not a list of sites it may *touch*.

**The list is fixed, and the other gates still apply.** A topic run cannot be steered onto a site the
owner did not choose, because there is no step in which anything chooses a site — the seven are
written into the software. And each of the seven still passes the public-address check, the site's own
rules and the pacing gate on every fetch, exactly as a pointed-at address does.

### 12.8 Honest status of this route

Four things are true about this capability on this machine, and all four should be said plainly.

**The general research path does not have this cancel wiring.** A prior reviewer reported this, and
checking the code confirms it: the typed command that performs general scoped web research constructs
its crawl without a stop signal, and with the wider budget — twenty-five pages, three steps, fifteen
per site. **The emergency stop therefore does not abort a general research crawl that is already under
way.** It still refuses the write-up at the permission gate, so a halted run files nothing and a
refusal is recorded instead; but the pages it had queued are still fetched. The pointed-at learning
route and the general research route are not equivalent in this respect, and only the former stops
promptly. Wiring the same signal into the general path is a small change and an obvious one; it has
not been made.

**This has not been exercised against a live outside site here.** The permanent record on this machine
contains no fetched-page entries at all — not one — which is the direct check, and it comes back
empty. The automated tests around this route are thorough about the *logic*: they drive it with a
stand-in fetcher returning a fixed page and confirm that a genuine quotation grounds, that a fabricated
quotation is demoted, that a citation to a page outside the window is rejected, that an internal
address is refused, that the stop aborts the crawl, and that the action is refused when the stop is
engaged or automatic learning is off. What they do not do is open a socket. **The grounding behaviour
is verified; the network behaviour of this specific route is verified only against a stand-in.**

**The interface exposes one of the two routes.** The address box is on the screen; the topic route is
not, and reaching it means going to the layer behind the screen.

**A page that assembles itself in the browser cannot be read.** As set out earlier in this chapter,
the component that would run a page's own code has exactly one shipped implementation, and it returns
nothing — deliberately, because a real browser would go around the pinned-address protection this
whole route depends on. A modern site that renders itself entirely in the browser will therefore yield
little or no text, and the run will report a thin result rather than inventing a thick one.

## 13. Honest status: what is working, what is built but not live, and what is absent

This chapter has described a lot of capability. A reader deciding whether to trust a system needs to
know which parts of it are actually running, and the answer is not uniform. The table below is the
whole chapter reduced to that one question, checked against this machine rather than against the
project's own documentation — which, in two places, turned out to be describing an earlier state.

**Read the middle column as the important one.** "Built and tested but not live here" is not a
euphemism for "does not work". It means the logic exists, has automated tests, and is waiting on a
piece of software or hardware that is not installed. It is a different thing from "absent", and a
very different thing from "working", and this document will not blur the three.

| Capability | Status on this machine | What it is waiting on |
|---|---|---|
| The signed record, and the chain over it | **Working** | — |
| Ingesting assistant transcripts, sub-agent transcripts and code commits | **Working**, and safe to re-run | — |
| Ingesting curated documents | **Working, but not safe to re-run** — it has no cursor and no duplicate detection, so running it twice files everything twice | A fix; it is opt-in, so nothing does this automatically |
| The entity map (the sovereign knowledge graph) | **Built and populated** — a real database of about twelve megabytes | — |
| The nightly pass that grounds a claim in a quotation | **Working when it is run** — nothing schedules it here; the scheduled-run definition ships with the software but has not been installed on this machine, so "nightly" is the intended cadence, not the current one | Installing that scheduled run, if the pass is to happen without being asked |
| Recall by meaning | **Working** — about 13,700 entries indexed, computed on this machine's own processor with no outside service and no per-question cost | — |
| The nine agents | **Built and tested; halted on this machine** — each one runs, holds its ceiling and writes its own name onto the record, but the emergency stop is engaged here, and while it is, the governing check denies every agent action above plain observation | The owner releasing the stop. The record's own release entry predates the anti-replay hardening and no longer verifies, so it is not honoured; a fresh owner-signed release clears it |
| The perception agent | **Built and tested; not live here** — it runs and is a named identity on the record like the other nine, but the reader that supplies the authoritative half of its answer is not installed, so every reading it produces stays a lead. The halt above binds it too | The text-recognition program, and the owner releasing the stop |
| Learning from a page the owner points at | **Built and tested, never run against a live site here** — the record holds no fetched-page entries at all; the tests drive it with a stand-in fetcher | A run against a real address. The grounding behaviour it depends on is exercised and holds |
| The memory server that gives an assistant cited recall | **Live** — its eight tools are attached to the assistant session that wrote this chapter | — |
| Capturing a screen or a camera frame | **Available** — a screen-capture utility and a camera are both present | — |
| Reading the text in a captured image | **Absent** — the text-recognition program is not installed | That program |
| The local advisory image reader | **Absent** — not installed | That program |
| Watching the screen continuously | **Built, with no way to start it** — there is no command-line option that turns it on | A command to launch it |
| The voice loop | **Built and tested, cannot start here** — the audio-device library both the microphone and the speaker need is not installed | That library, plus a microphone and speaker |
| Hands-free waking by saying its name | **Not built** — the current trigger reacts to sound level, which is not the same thing | A trained model for the word |
| Interrupting it mid-sentence, on real speakers | **Built and tested from recordings** | Echo cancellation, or run it one direction at a time |
| On-camera hand gestures | **Built, and cannot fire** — the hand-tracking model is not present, so the detector is a deliberate no-op | That model |
| The phone as a remote trackpad | **Built and tested on the desktop side only; not wired end to end** — the decoding of a landmark batch, the dropping of replayed, reordered and foreign batches, and the full re-verification of a signed arm request all have tests, but nothing carries hand movement from a phone to a desktop, here or anywhere in this software | A hand detector in the companion app, a door on the phone bridge to receive landmark batches, and a command that starts the desktop gesture loop |
| The cockpit | **Working** | — |
| The status overlay | **Built, wired at both ends and tested** — but neither of its two producers has run against live hardware here: the listening/thinking/speaking events exist only while a live speech loop is running, and the navigation signals come from speech or from a gesture session that is actually producing movement | A microphone; or, for the gesture half, everything the trackpad row above is waiting on |
| The phone companion and its app | **Built**, with a demonstration that runs with no phone and no network tunnel | A phone, for real use |
| Everything above, on macOS, Windows or Android | **Not proven** — Linux is the tested path; the others are honest, documented gaps | Work, and testing |

### 13.1 The four things a careful reader should press on

**The agent mesh is halted on this machine.** The emergency stop is engaged here, and while it is,
the governing check denies every agent action above plain observation. The record does carry a
release, written before the guard against replayed decisions existed, and it no longer verifies
against the shape the check now requires — so it is ignored, exactly as a stale release should be,
and the halt stands. Nothing on the sovereign agent side is doing work on this host until the owner
signs a fresh release. That is the fail-safe direction behaving as designed, and it is also the
reason a reader should not read the agent rows above as "running today".

**The projections are ahead of the record on this machine.** The meaning-search index and the entity
map were built from a record containing tens of thousands of entries. The signed chain in use today
holds sixteen. The chain itself verifies — it is internally consistent — but a search can return a
citation whose entry number does not resolve against it. That matters more than it first appears,
because *citing the source* is the property this whole design rests on. The honest statement is that
the grounding **mechanism** is sound and tested, and that on this machine the indexes and the chain
have drifted apart and should be rebuilt before anyone relies on a citation resolving.

**The record has no signed head here.** The chain links cleanly, but nothing has yet signed a
statement of the form "this is the record, and it ends here". Without that, growth and truncation
look alike to an outside checker. Chapter 7 explains why that signature matters; on this machine it
has not been made.

**Absence of a reader is not absence of risk, but it is absence of capability.** With no
text-recognition program installed, nothing seen on a screen can become a grounded claim at all —
every reading stays advisory by construction. That is the design behaving correctly under a missing
component rather than degrading quietly, and it is worth understanding as the pattern this whole
side of the system follows: **when a piece is missing, the honest failure is the default one.**
