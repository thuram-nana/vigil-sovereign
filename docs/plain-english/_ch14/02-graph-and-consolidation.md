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

**It can be thrown away without loss.** Delete the map and nothing is gone; rebuild it and it comes
back. What can be destroyed and regenerated at will cannot be where the truth lives.

**It contains no judgement.** No model reads anything during a rebuild. There is no extraction, no
inference, no summarising: the rebuild counts and links, it does not interpret. That is why two
rebuilds over the same record produce the same map, and the project's own tests assert exactly that.

**It can therefore be checked by a stranger.** An assessor who does not trust the map can rebuild it
from the same record and compare; a discrepancy would be a fault in the software, not a difference of
opinion.

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
removal and the rename, the map is simply absent until the next rebuild: nothing is lost, because it
held nothing not derived from the record.

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
link. The whole semantic layer such products lead with is absent — on purpose, and the code says so
in the same breath as it lists the missing kinds: they are **intentionally absent until a grounded
producer exists for them.**

Translated: a thing may appear in this map only if it can be derived from the record mechanically,
without a model's judgement. A commit is in the record; counting it is arithmetic. A *person* is not
— deciding that two mentions of a name refer to one human being is interpretation, and interpretation
is what this map exists to be free of. Until a producer exists that can mint such a thing under the
same prove-don't-guess discipline as everything else, the kind does not exist at all.

**For this audience, that absence is the strongest evidence in the section.** A system that ships a
weaker version of the impressive feature, marked approximate, is asking to be trusted. One that
declines to ship it, and writes down why, has told the assessor something about every other claim in
the document. The constraint is the product.

One consequence must not be mistaken later: **the facts the nightly pass promotes — decisions,
commitments, contradictions — live on the record and are served from the record, not as entries in
the map.**

### 3.6 The nightly pass, in five moves

The agent that owns memory runs one pass over everything added since it last ran. It has five moves
and does nothing else.

| Move | What happens |
|---|---|
| **Extract** | A reader — a model, or an offline keyword matcher — goes over a window of the owner's own conversational entries and proposes candidate durable facts: decisions taken, commitments made, things named, positions reversed. |
| **Gate** | Every candidate is checked by re-reading the record. This is the whole of section 3.7, and the only thing in the pass that decides anything. |
| **Promote or demote** | A candidate that passes becomes a new, permanently recorded fact. One that fails is **also written down** — as an honest refusal, with the reason. |
| **Flag** | Where the record shows the owner reversing an earlier position, that opposition is recorded as a flagged contradiction naming both sides. |
| **Brief** | A short readable summary: open loops, commitments with due dates, contradictions awaiting review — composed only from facts that passed the gate, each cited. |

Two structural details matter. The pass fixes the record's high-water mark before it starts, so **it
can never feed its own output back into itself** as fresh evidence; and it works in bounded batches,
so the window the checker verifies against is **exactly the window the reader was shown**.

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
counts **how many distinct record entries independently re-verified it**: corroboration from the
record, not self-assessment by the model.

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
and both remain. Its ceiling is the reversible-internal-act level, and its whole output is entries:
facts, refusals, contradiction flags, a brief.

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
identical check, so nothing a page asserts becomes a fact either.

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
their own memory. The code says it in five words: *no API, no GPU, no cost.*

**One honest qualification.** The model file is not conjured from nothing: about 65 megabytes is
downloaded once from a public model repository the first time it is needed, and cached on disk
thereafter — which happened on this machine during the writing of this section. The accurate claim is
therefore **one fetch of a fixed, cacheable file at install time and nothing crossing the boundary
after that**, not "never touches the network at all". For a sealed deployment, that one file is the
thing to bring in on media.

**Where the numbers are kept is also on the machine.** The shipped default is a file-backed store
inside the program itself — no server, no container, no port. On the machine used here the owner has
instead configured a small search server on the loopback address, the same machine talking to itself.
Both are local; neither sends anything out.

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

What it returns is not a bare empty list for an assistant to fill in from imagination. It is an empty
list **plus an instruction**: no strongly-grounded match; do not fabricate; tell the owner memory has
nothing solid on this, and suggest rephrasing. The refusal is the payload.

Both directions were exercised live while this section was being written:

| The question asked | What came back |
|---|---|
| How the consolidation gate grounds a quotation | Three real record entries, with entry numbers, fingerprints, dates, sessions and similarity scores of 0.78, 0.73 and 0.73 |
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
