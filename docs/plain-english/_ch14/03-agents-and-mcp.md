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
perception assistant — ten named identities that can write to the owner's record.** The word
"PERCEPTION" appears nowhere in chapter 11; that is a gap there, not a contradiction, and the
perception section of this chapter closes it.

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
projection, and rebuilding it from the record is routine. But it means **the figure of roughly
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
