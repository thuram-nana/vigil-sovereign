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
| "Local-first." | The record, the keys, the search index and the entity map all live in a private directory on the owner's own machine. |
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

On top of that absence sits a guard — a check that runs when each of the personal system's main
subsystems is loaded (the agent mesh, the governor, the voice pipeline, the gesture pipeline, the
device registry, and the memory bridge). It scans the list of modules already loaded into the
running process and raises an error if any belongs to either forbidden family: the offensive
engine, or the vendored third-party agent. The guard is not the wall. **The guard is the smoke
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
are **projections**: derived views that can be deleted and reconstructed from the record alone,
and that no one is allowed to edit directly.

The entity map is rebuilt by replaying the record from the beginning, in entry order, into a fresh
empty database, and then swapping the finished copy into place in one step so no reader ever sees
a half-built view. Two properties make it trustworthy:

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
account: the record, the keys, the search index, the entity map, the working caches.

The content of an entry can additionally be encrypted at rest, field by field — the human text is
sealed while the bookkeeping fields stay readable, so the safety checks that scan the record for
things like the emergency-stop state keep working without any key at all, and the integrity chain
still verifies without one because the fingerprint covers the stored form. **This is opt-in and it
is off unless a key vault has been provisioned**; with no vault, entries are stored as plain text
exactly as before. On the machine described above no vault is provisioned, and the entries are
plain text.
