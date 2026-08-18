# Signatures And Keys: Who Vouches For A Result

## Why this chapter exists

A security report is normally just a claim. Someone tested something, wrote down what they
found, and you are asked to believe them. If you want to check the claim, you have to repeat
the whole investigation.

This system is built on a different bargain. When it says "this weakness is real", it hands
you an object you can check yourself, later, offline, without running any of its software and
without trusting the people who produced it. That only works if two questions have clear
answers:

1. **Who produced this, and has anyone altered it since?**
2. **Why should I believe the copy I am holding is the real one, and not a convincing fake?**

Digital signatures answer the first question. Trust roots, chained records and out-of-band
pinning answer the second. This chapter explains both in plain terms, says exactly what is
signed, who holds which keys, where those keys live, how they are protected, what happens if
one of them is lost or has to be replaced, when several people must agree before something
happens, which signed permissions decide what the software is allowed to do at all, and —
honestly — which of these arrangements are fully working today and which are built and proven
in testing but not yet exercised against outside parties.

If you read only one section, read section 6 (what happens when a key is lost) and section 9
(why the check only means something if one number reaches you separately). Those are the two
places where a well-built signing scheme is most often let down in practice, by the people
running it rather than by the software.

If you are assessing a live installation rather than reading for background, turn first to
**section 13**. It is a short numbered list of the questions the software cannot answer for
you, because the answers are facts about a particular installation and the people running it,
not facts about code. **Section 4** carries the full inventory of every key in one table — where
each one sits, who can read it, what it vouches for, and what breaks if it is lost — followed by
a second table saying, for each signed thing, exactly what an outsider needs and what performs
the check. **Appendix A** lists every purpose label in the source exhaustively, so the claims in
this chapter can be checked against the code rather than against a summary.

One part of this chapter describes work delivered in the current release and is worth flagging at
the front, because it corrects a belief a reader would reasonably have formed from everything
above: **a genuine signature was not, on its own, enough**. The owner's decisions about what the
system may do are stored as signed entries in an append-only record, and an old, genuinely signed
entry could be added to that record a second time to resurrect a permission the owner had since
withdrawn — a revoked phone re-armed as an approver, a halted system un-halted. Nothing was
forged; the replayed entry carried the owner's real signature. The guard that closes this, and
the reasoning behind why only one direction of each decision is guarded, is at the end of
**section 11**, under "Replaying a single signed permission".

---

## 1. What a digital signature actually is

Think of an old-fashioned wax seal on a letter.

- The **stamp** that presses the wax is kept locked away. Only its owner has it.
- The **impression** it leaves is public. Anyone can look at it and recognise it.
- If someone opens the letter and changes a word, the seal is broken and everyone can see.

A digital signature is that idea done properly, with two important improvements:

- **It is tied to the exact contents.** The signature is computed from the document *and*
  from the private stamp together. Change a single character of the document and the
  signature stops matching. You cannot peel the seal off one letter and stick it on another.
- **The impression cannot be copied into a forgery.** With a wax seal, a skilled forger who
  studies the impression can carve a matching stamp. With a digital signature, knowing what
  the signature looks like tells you nothing useful about how to make another one. Checking
  is easy for everyone; producing is impossible for anyone without the private half.

Two more things are worth being clear about, because they are often misunderstood:

- **A signature does not hide anything.** The document stays readable. Signing proves origin
  and integrity; it is not encryption. (Encryption is used separately, to protect keys when
  they are sitting on disk — see section 5.)
- **A signature proves authenticity, not freshness.** A correctly signed document from last
  year is still correctly signed today. On its own, a signature cannot tell you that you are
  looking at the *latest* version rather than an old one someone kept and replayed. That gap
  is real, it is taken seriously here, and section 11 is entirely about how it is closed.

### The specific method used

The system uses Ed25519, a widely deployed public-key signature method, through the
`cryptography` library maintained by the Python Cryptographic Authority. The code says so
explicitly and states the rule it follows: *"We do not roll our own crypto."*

In plain words: the project does not write its own cryptographic mathematics. Writing your own
is one of the best-known ways to get security badly wrong — the mistakes are subtle, they do
not show up in testing, and they are usually found by an attacker rather than by the author. So
the system uses the same standard, heavily reviewed implementation that banks, browsers and
governments already rely on, and writes none of that mathematics itself.

One discipline is worth naming because it limits the damage a compromise could do: **the
running system only ever checks signatures; it never creates them.** Creating signatures is a
set-up activity, done deliberately by a person with the private key. The code that produces
signatures is labelled "provisioning only" in the core cryptography module.

### Who checks the borrowed mathematics — the build and release safeguards

Borrowing a standard library is the right decision, but it moves a question rather than
answering it: if the signature mathematics comes from someone else, what guarantees that the
copy installed on the machine is the copy that was chosen, and that it has not since been found
to be flawed?

That is a different problem from everything else in this briefing. The rest of the system
proves what it *did*. This is about proving what it is *built from* — the parts an attacker can
change without ever touching this project's own code: a base system image quietly re-pointed at
different contents, a third-party package swapped at install time, a scanner that was never
really looking.

Four safeguards answer it. They are part of the released software, and each is enforced
automatically whenever a change is proposed, so they cannot be skipped by a person in a hurry.

- **Every third-party package is locked to an exact version and to a fingerprint of the exact
  file.** Installation is run in a mode that requires a fingerprint for every single package
  and refuses the whole installation if even one is missing. There are two such lock files, one
  for each half of the system, because the two halves deliberately never share an installation.
- **Base system images are referenced by content, not by a moving label.** A label such as
  "latest" is a pointer that someone else can re-aim at different contents at any time, with no
  visible change on this side. Every image is instead named by a fingerprint of its exact
  contents, so the download either matches or fails. Two exemptions are written down as rules
  rather than left as holes: an empty starting image, which has no contents to fingerprint, and
  images this project builds itself, which have no outside version to point at.
- **A bill of materials is produced for each half.** This is a machine-readable parts list, in
  the widely used CycloneDX format, naming every component that goes into an installation. It
  is generated from the lock file and then checked back against it item by item, so a
  parts-list generator that silently dropped a component fails the build instead of producing a
  confident-looking but wrong list.
- **A vulnerability gate blocks on the most serious findings.** Every proposed change is
  scanned against the public catalogue of known flaws in third-party software. A finding rated
  **critical blocks the change outright** — it cannot be accepted. Findings rated high are
  reported in full but are advisory. The scanner itself is pinned to an exact version and to
  the fingerprint of its own download, because installing a security scanner from an unpinned
  address would be its own supply-chain hole. Any decision to set a particular finding aside
  has to carry a written justification naming that finding, and an automatic test fails the
  build if one does not — so a suppression costs somebody a sentence of explanation rather than
  a silent line in a file.

One detail is worth singling out, because it is the difference between a real gate and a
decorative one. A gate that has never once refused anything is indistinguishable from a gate
that is misconfigured to find nothing. So immediately before the real check runs, the same
blocking configuration is run against a deliberately planted set of known-critical packages,
and it **must fail**. If that planted case passes, the job stops with the message that the gate
below it cannot fail and its green tick therefore means nothing.

**A worked example, and an honest one.** On its first run this gate found a real published flaw
— rated high — in the very signature library this chapter rests on. The project's own version
ceiling forbade taking the fix, so the gate reported it as advisory and it was written down as
follow-up work rather than quietly ignored. Raising that ceiling and moving every declaration
onto the fixed release was then done as its own separate change, and **that change has now
landed.** Every first-party declaration of the signature library names the fixed release: the
engine's requirement, the shared core's, the sovereign side's pinned version, and the input to
the sovereign lock file. The same run recorded no critical findings and eight high ones, most of
them inside the third-party agent that this project keeps a copy of rather than in its own code.
That is the honest shape of the control: **critical stops the line; high is surfaced, tracked and
fixed deliberately, not suppressed.**

Two qualifications on that, because a briefing that claimed the flaw was simply "gone" would be
overstating it.

- **The copy of the third-party agent still lags.** The project's own supply-chain document
  records that the vendored agent's lock file still names an older release of the signature
  library, along with two other advisory findings. That copy is not what signs anything in this
  chapter — the signing paths use the first-party declarations — but it is in the tree, and the
  gate reports it every run rather than hiding it.
- **A declaration is not an installation.** I checked the two virtual environments on the machine
  this was written on. The offensive one has the fixed release installed. The sovereign one still
  had the previous release installed at the time of writing. That is a property of one machine
  that has not been rebuilt since the change, not of the code — but it is exactly the kind of gap
  an assessor should check on the host in front of them rather than infer from a requirements
  file.

---

## 2. What exactly gets signed

Not one thing. A signed object is produced at every point where the system makes a statement
that someone might later have to rely on.

| Signed object | What it is, in plain words |
|---|---|
| **The engagement authority** | The signed charter that arms a run at all: which hosts are in scope, from when until when, whether destructive actions are permitted, and how many actions the run may take. A run refuses to start on an unsigned or altered one. This is the document that turns "the software is installed" into "the software is permitted to act here". |
| **Evidence certificate** | One per confirmed weakness. It carries the fingerprint of the exact evidence collected, which automatic test confirmed it, the list of raw files kept, and a plain-language note on how to re-check it. |
| **Chained record entries and the signed "head"** | The running log of certificates, plus a signed summary that fixes how many entries exist and what the last one was. This is what makes silently rewriting history detectable. |
| **Usage ledger** | Who ran the tool, when, and what they pointed it at. Every entry is signed and linked to the one before it. |
| **Execution records** | Every command run through the governed local terminal or the sandbox produces a signed, secret-scrubbed record of what ran. |
| **Permission-kernel action records** | On the owner's side, every single tool invocation the permission kernel decides about — the time, the tool, a fingerprint of its arguments, the permission tier, the decision, who approved, and a fingerprint of the result — written as a record that is both individually signed and chained to the one before it. Section 10 describes the chaining. |
| **Governance events** | The owner's signed decisions about what the system itself may do, written onto the owner's own record: tripping and clearing the emergency stop, granting and withdrawing an agent's permission to act without asking, switching a physical capability such as gesture or voice control on and off, authorising and revoking a phone as an approver, a host advertising what it is capable of, and opening or closing the sovereign gate the offensive side is designed to pass before it acts. These are the records section 11 describes the replay guard for. Two of them — the host advertisement and that sovereign gate — are record types with no production writer yet; both are noted where they appear below. |
| **Device request envelopes** | Every request the owner's phone makes to the desktop, and every approval it gives, signed by the phone's own key. There is no shared password on the wire: the signature *is* the authentication. |
| **Transparency checkpoints and witness counter-signatures** | A public summary of the log's state at a moment in time, and other parties' counter-signatures on it. Three separate signed forms exist and are deliberately kept apart: a producer's signed submission asking a witness to counter-sign, a witness's plain counter-signature, and a witness's counter-signature that also commits to the time it saw the summary. |
| **Remediation certificates** | The signed statement that a previously proven weakness is now fixed, re-derived by running the original test again and requiring it to stay silent. Three related signed objects sit around it: the fix statement itself, a re-proof certificate produced each time the check is repeated, and a signed freshness challenge that stops an old re-proof being passed off as a recent one. |
| **Posture certificates** | The signed statement that, over a specific bounded surface, an applicable test had a live channel and did *not* fire. |
| **Authority-envelope certificates** | The signed statement that the automated operator stayed inside its authorised bounds. |
| **Owner delegations** | The owner's signed statement that a particular working key is allowed to act in a particular role, for a particular scope, until a particular time. |
| **Per-action approval tokens** | The owner's signed permission for one specific queued action. |
| **Destruction authorisations** | The multi-party signed permission for one specific irreversible action. |
| **Identity attestations and capabilities** | The owner's signed statement of what counts as "the real target", and a signed, narrowable permission slip letting an outside auditor re-run a check legally. A third signed object in the same family proves that whoever presents such a slip really is its holder, rather than someone who copied it. |
| **Detection certificates** | Signed results from the defensive side of the system. |
| **Call-back receipts** | Some weaknesses can only be shown by making the target reach out to a listener the system controls. When that happens the listener signs a receipt for the connection it received, so the fact that the target called out is provable later from the receipt rather than from an assertion. |
| **Channel-binding co-signatures** | A separate party's signature tying a captured response to one specific encrypted session, so that a reader does not have to take the producer's word that the target sent those bytes. Section 11 states honestly what this does and does not currently establish. |
| **The anti-rollback floor and the witness roster** | Two small owner-signed control files: the high-water mark of how far the record has ever got (section 11), and the list of outside witnesses the owner accepts. |
| **Self-improvement proposals** | When the system proposes a change to its own code, the approval that lets that change merge is a signature over the proposal's content — its target, the change type, and a fingerprint of the patch. Because the signature covers the content and not the whole document, a later status or timestamp change does not invalidate it, and an approval cannot be moved onto a different proposal. |
| **Dossier manifests** | The list of file fingerprints inside a downloadable evidence package. |
| **Supply-chain statements** | Signed machine-readable statements about whether a known published flaw in some third-party component actually affects this software. They use two open formats built for that job: **OpenVEX** (short for "Vulnerability Exploitability eXchange" — an agreed way of publishing "this published flaw does / does not actually affect our product"), carried inside a **SCITT**-style signed statement ("Supply Chain Integrity, Transparency and Trust", an internet-standards effort for signed, independently checkable supply-chain claims). One part of the standard's compact binary encoding is deliberately not built; section 11 says so. These statements are about *published flaws in components*; the separate safeguards that control what the software is built from in the first place are in section 1. |
| **Capability grants** (the code calls them "entitlements") | A signed permission slip saying which of the system's more dangerous capabilities a particular institution may run, on which machines, from which date until which date, and — if the issuer chooses to narrow it that far — under which named operator. Inside the level granted, the issuer may also list a shorter set of specific capabilities, so a grant can be cut to the minimum a job needs. It is signed by the authorised signers named in the deployment's trust list, meeting whatever number that list requires — several signers, not one, in a properly separated deployment. Section 4 explains the whole arrangement and says who holds those keys; section 6 covers what happens if they are lost. |
| **Capability revocation lists** | A signed list of capability grants that have been withdrawn. It carries a serial number that may only go up, so an older list cannot be replayed to quietly un-withdraw something. A grant may also be marked as *requiring* a revocation list, and such a grant refuses to run when the list is missing or unreadable — so deleting the list cannot re-enable anything. That marking sits inside the signed part of the grant, so it cannot be switched off without breaking the signature; it is off unless the issuer sets it. |

### Labelled seals: why a signature cannot be moved between purposes

A seal that just says "approved" is dangerous. If the same seal is used on passports and on
cheques, an approved passport becomes an approved cheque.

The system avoids this by mixing a short fixed **purpose label** into the bytes before
signing. A signature made for one purpose mathematically cannot verify as another.

Ten of these labels — the ones that cross the boundary between the two halves of the system, and
so must never drift into two spellings — are held in **one shared registry**, so that two parts
of the system cannot independently invent the same label. Those ten are:

- evidence certificates and the signed summaries that cap the record,
- the owner-side anti-rollback floor (section 11 explains what that is),
- the list of accepted outside witnesses,
- an owner delegation to a working key,
- a witness's counter-signature on a published summary,
- a multi-party authorisation of an irreversible act,
- the owner's statement of what counts as the real target,
- a re-verification permission slip issued to an outside auditor,
- a narrowing of an existing permission slip,
- proof that the holder of a permission slip really is its holder.

**The shared registry is not the whole population.** Counting every purpose label actually
present in the source, there are **twenty-four distinct signing labels** and two further labels
used to separate fingerprints rather than signatures. The other fourteen signing labels are
declared next to the code that uses them, and each carries a comment naming what it must not be
confusable with. Appendix A lists all twenty-six exhaustively, with the exact machine-readable
text of each, so an assessor can check the code against this chapter rather than against a
sample. A general reader does not need that table; the property it establishes is the whole
point, and it is one sentence long: *no signature in this system can be lifted out of the
purpose it was made for.*

**Where the labelling is not applied, and what is used instead.** The shared registry is honest
about this in its own notes rather than leaving it to be discovered. Three surfaces sign
without a purpose label:

- the offensive engagement log and the usage ledger each sign a plain content fingerprint — a
  fixed-length string of hexadecimal digits — so what keeps them apart is that the fingerprints of
  different content are different, not a label;
- the owner-side governance events sign a canonical rendering of a small structured object,
  which is a different *shape* from a fingerprint string and therefore cannot be confused with
  one, but is not separated from other structured objects by a label.

I found one further case the registry does not mention: the manifest inside a downloadable
evidence package is signed over its own raw bytes, with no purpose label. In practice those bytes
are a distinctively formatted structured document that no other signing path produces, so the
same shape argument applies — but it is one more place where separation rests on shape rather
than on an explicit label. The registry's own notes call adding a per-purpose label to these
surfaces "the natural next hardening". That is an accurate description of a gap, written down by
the people who built it.

---

## 3. The questions asked of every signed result

When the system, or an outside party, checks a certificate over a confirmed weakness, it does
not simply ask "is the signature valid". It asks a set of separate questions, and the result
counts as sound only if **all** of them pass.

1. **Authenticity.** Do enough of the recognised signing keys actually vouch for these exact
   bytes? (See section 8 on "enough".)
2. **Binding.** Does the fingerprint recorded inside the certificate match the evidence
   actually presented alongside it? This is what stops a genuine signature being lifted off
   one piece of evidence and pasted onto another.
3. **Artifact integrity.** Does every raw captured file still hash to the value recorded when
   it was signed? If the certificate claims files but no evidence folder is supplied to check
   them, the answer is *refuse* — an unchecked claim never passes.
4. **Primary artifact re-check.** Where a certificate opted into binding one specific
   captured file, the raw bytes must be supplied and re-hashed. A signed digest alone only
   proves the certificate *contains* a digest; recomputing from the bytes proves the
   certificate is bound to *those* bytes. If the bytes are not supplied, it **fails closed** —
   that phrase, used throughout this chapter, means that when a check cannot be completed the
   answer is "no". Like a drawbridge held up by power: cut the power and it falls shut.
5. **Reproduction.** The original automatic test is run again over the retained evidence and
   must reach the same verdict. Silence or a different verdict withdraws the claim.
6. **Claim grounding.** Any sentence in the written report that was bound into the
   certificate as a *fact* must re-qualify as a fact against that same evidence. A sentence
   relabelled to a different category of weakness does not ground, and the whole certificate
   fails.
7. **Known shape.** If the certificate is in a version of the format this checker does not
   model, it refuses rather than guessing.

Two further signals are reported but deliberately **not** folded into the pass/fail verdict,
and the code explains why:

- **Has the test itself changed since this was signed?** If the automatic test's code has
  been updated, that is flagged. It is not treated as a failure, because rejecting every older
  certificate after an upgrade would destroy the ability to reproduce old results. The
  reproduction step above already re-ran the *current* test, so you are told whether the
  finding still holds.
- **Is this still current?** Freshness is only asserted against an authenticated external
  timestamp. If no such timestamp is supplied, freshness is reported as *not asserted* —
  never silently as "fresh".

---

## 4. Who holds which key

There are two separate halves of this system running as two separate programs, and the key
arrangement follows that split.

### The owner key — the top of the tree

The **owner key** lives on the sovereign side (the personal, defensive half of the system, in
`apps/sigil`). It is a single key pair, stored under the owner's home directory, with the
private half held in the vault described in section 5. It is the only key that signs:

- approvals of queued actions,
- delegations to any other key,
- the owner-side record's summary head and its anti-rollback floor,
- governance events such as granting a permission or releasing an emergency stop.

The private half never leaves the sovereign side. Where a web interface is involved, the
design invariant is written into the source: *"The browser never holds key material: it sends
an authenticated REQUEST … and the SERVER signs with the persisted owner key."*

### The offensive side holds no owner authority

The offensive engine — the half that actually touches a target — **does not hold the owner
key**. It holds two working identities of its own, each a stable key pair created once and
kept in a file readable only by its owner account:

- an **engagement-record key**, which signs the running log of an engagement, the execution
  records, and detection certificates;
- a **governance key**, which is the signer of record on evidence certificates.

These are deliberately two keys, not one, so that authorising one never widens the other.

### How the owner blesses those working keys — the delegation ceremony

Because the offensive side generates its own keys, something has to connect them back to the
owner. That is a deliberate two-step ceremony:

1. On the offensive side, `vigil identity` writes out a small file containing **only the
   public halves** of the two working keys. The code comment is explicit: *"Writes ONLY public
   keys — never a private key crosses."*
2. On the owner's side, `sigil delegate-offense` reads that file, prints the exact keys it is
   about to bless so the operator can eyeball them, and signs two delegations: one for the
   engagement-record role and one for the governance role. Each names a role, a scope, and an
   expiry time.

The command carries an unusually blunt warning, and it is warranted: the owner's tool has no
way to authenticate where that file came from. If an attacker swaps the file in transit, the
owner would bless the attacker's key. The instruction is therefore to move the file over an
authenticated channel, or to confirm the printed key fingerprints out of band before signing.
This is a genuine human step in the chain, and it is stated as one rather than papered over.

### The two operator signing keys that live in the environment

Two further owner-held keys are used for the highest-consequence approvals. Both are read
from environment variables and **never from the command line** (a command line is visible to
other processes and lands in shell history):

- `VIGIL_APPROVAL_OWNER_KEY` — signs one queued action at a time.
- `VIGIL_DESTRUCTION_OWNER_KEY` — signs one irreversible action at a time.

Both are printed exactly once when created and are not stored by the command that creates
them. And there is a hard rule enforced in the process-launching code: the destruction signing
key is **stripped from the environment of every child process** the system starts, even if the
operator happens to have it exported in their own shell. The comment explains the reasoning —
without that strip, an offensive process could inherit the key and authorise its own
irreversible action.

### The keys that decide what the software is allowed to do at all

One further set of keys sits outside the engagement entirely, and it answers a question every
buyer of an offensive tool asks: *if this software is copied or stolen, what can the thief do
with it?*

The most dangerous functions do not run merely because the code is present on a disk. They run
only against a signed permission slip — a **capability grant** — issued by a set of authorised
signers the deploying institution controls. The grant names the institution, the level of
capability allowed, the machines it may run on, and an expiry date. Without a matching grant,
only the safe baseline remains available.

The keys that sign those grants are deliberately kept off every machine that runs the system.
The issuing tooling describes them as the institution's crown jewels and says plainly that they
never belong on a machine that runs the software and never in the source code. The running
system can only ever *check* a grant; it has no ability to create one. Issuing is a separate
ceremony, on a separate machine, by the institution — not a command an operator can reach.

**Three documents, none of which is a secret.** The secret is the signing key, and it is not on
the machine at all. Everything the deployment holds could be read by an outsider without harm.
What matters is whether it can be *changed*.

| Document | What it is | How it arrives |
|---|---|---|
| The **trust list** | The public list of which signers the deployment recognises, and how many of them must agree. It is not itself a signed object; it is the thing everything else is measured against. | Installed once, by hand, out of band, when the deployment is set up. It is public information — nothing is lost if it is read, only if it is silently changed. |
| The **grant** | The signed permission slip for one institution: level, machines, dates, and optionally a named operator and a narrower list of specific capabilities. | Issued by the institution's authorisers and placed on the deployment. |
| The **revocation list** | A signed list of grant identifiers that have been withdrawn. | Re-issued by the same authorisers whenever something is withdrawn. |

**What the system checks, in order, before it lets a gated function run.** Each step fails
closed: any error, any missing or damaged file, any mismatch is a refusal, never a shrug.

1. **Signatures.** Enough distinct recognised authorisers have signed these exact bytes.
2. **Dates.** The present moment lies inside the grant's own valid-from and valid-until dates.
3. **Machine.** The running machine presents one of the identifiers the grant is bound to.
4. **Operator.** If the grant names an operator, the running process presents a matching
   operator identity. Presenting none at all is a refusal, not a pass.
5. **Withdrawal.** The grant does not appear on the signed revocation list, and the list itself
   has not been rewound (see below).
6. **Scope.** The particular function being asked for is inside what the grant actually confers.

**How the machine binding works, stated exactly.** The system does not itself measure the
machine's hardware. It *consumes* an attested identity that the deployment's own attestation
infrastructure supplies through an environment setting — the kind of identity a workload
attestation service or a hardware-chip attestation stack produces. Where none is supplied, it
falls back to the machine's installation identifier and, weakest of all, its hostname. The
division of labour is deliberate and written down: attestation infrastructure is the
institution's job; refusing to run off an identity the grant was not bound to is the software's
job. An assessor should ask which of those three identifiers a deployment is actually relying
on, because a hostname is a label anyone can set.

**How withdrawal is protected against being undone.** A revocation list carries a serial
number, and the highest serial ever accepted is remembered on the machine. A validly signed but
older list — the sort of thing an attacker would keep precisely to un-withdraw a grant later —
is refused as a replay. Separately, a grant may be marked at issue time as *requiring* a
revocation list, in which case an absent or unreadable list denies the grant rather than
allowing it; that marking sits inside the signed part of the grant, so it cannot be switched off
without breaking the signature.

**What a thief actually gets.** The gate recognises eleven named capabilities on a ladder of
four levels. Only the bottom level runs with no grant at all.

| Level | What it covers |
|---|---|
| **Baseline** — always available, grant or no grant | Internal reasoning, and passive fingerprinting: looking at information already given to it. Nothing that reaches out and touches a target. |
| **Standard** | Active probing inside an authorised scope; autonomous planning; and, on the defensive side, actively blocking an attack that has already been proven against the operator's own application. |
| **Offensive** | Running a single confirmed exploitation attempt; the deep white-box source-code analysis arsenal; and scoring how visible the system's own actions would be to a defender. |
| **Advanced** — the most dangerous, and locked | Chaining several weaknesses into one route; the reserved slot for defender evasion; and authority to merge the system's own self-improvement proposals. |

Two clarifications on that last row, because it is the row a reader will worry about. The
system does **not** generate evasion: the project's own manifest records the defensive analysis
layer as knowing what alarms an action would trip while deliberately not producing ways around
them, and any such work is reserved as human-authored and separately granted. And the
self-improvement rung is authority to accept a proposal, not authority to write itself into
production unreviewed.

So the honest answer to "what can a thief do with a stolen copy" is: on a properly governed
deployment, reasoning and passive inspection, and nothing that touches anyone else's system.

**Four honest qualifications.**

1. **The trust list itself is not signed, and it is the root of this whole arrangement.** The
   grant and the withdrawal list are signed, so altering either one is detected immediately. The
   trust list is different: it is what those signatures are checked *against*, so it cannot be
   checked against anything else. It is written as an owner-only file, and the deployment can be
   configured to read it from a read-only location, but anyone who can rewrite that file can add
   their own name to the list of recognised signers and then issue themselves a grant. Guarding
   it is an operating-system and physical-access question, not a cryptographic one. This is the
   same shape as the trust root of section 9, and the same honest limit applies.
2. **Enforcement switches on when the trust list is installed.** Until then the deployment is
   what the code calls "ungoverned": the baseline runs, the gated functions are permitted rather
   than refused, and every such permission is recorded as a warning. This default keeps a
   development copy working without ceremony. A government deployment should install the trust
   list, and an assessor should check that it has.
3. **Deleting the trust list turns enforcement off, unless it is pinned on.** A trust list that
   is present but damaged fails closed and denies everything gated — but a trust list that is
   simply *absent* reads as "not a governed deployment". An operator who wants enforcement to
   survive that has to set the deployment's enforcement setting explicitly, which forces the
   governed state on and denies gated functions when there is nothing to verify against. This is
   the same class of asymmetry as the anti-rollback floor in section 11, and it is stated here
   rather than left to be discovered.
4. **The decision is worked out once per run.** The check happens when the software starts and
   the answer is reused for that run. A withdrawal therefore takes effect the next time the
   software is started, not in the middle of a run already under way.

The full account of which functions sit at which level, and how this gate composes with scope
and approval, belongs to the safety and authorisation chapter. This chapter covers the keys.

### Signing keys are not the same as service credentials

It is worth separating two things that both get called "keys".

- **Signing keys** are the subject of this chapter. They vouch for results.
- **Service credentials** — an API key for a language-model provider, a read-only cloud
  credential, a repository token — are what the system uses to talk to outside services. They
  prove nothing about a result.

Service credentials are handled through a closed list of permitted names, so the interface
cannot be tricked into storing an arbitrary environment variable. They are sealed on the
machine through an ordered set of backends (the operating system's keyring where present, the
sealed store where a hardware chip is provisioned, otherwise an owner-only file), and they are
**never returned to the browser** — only a fingerprint and a health status are shown. A key
that has stopped working is displayed as failing rather than quietly green.

### The complete key inventory

The prose above describes the important keys one at a time. Because officials and security
officers usually want the whole picture on one page, here is every signing key and shared
secret the system uses, where each one physically lives, who can read it, what it vouches for,
and what breaks if it is lost. Section 6 explains the recovery options in full.

"Owner-only file" below means a file on disk that the operating system will only let the one
account that created it open, and which is encrypted at rest once the hardware vault of section
5 has been set up.

| Key or secret | Where it lives | Who can read it | What it vouches for | If it is lost |
|---|---|---|---|---|
| **Owner key** (the root of everything) | Owner-only file under the owner's home directory on the sovereign side (`~/.sigil/spine/keys/`) | The owner's own account on that one machine | Approvals, delegations to every other key, the owner-side record's summary and its anti-rollback floor, governance decisions | The most serious loss. Nothing already signed becomes invalid, but no new delegation or approval can be signed until a new owner key is created — and every party who pinned the old owner key must be given the new one. Recoverable only from the encrypted off-box backup (section 6). |
| **Record data key** | Owner-only file beside the owner key | The owner's account | Nothing — it is an encryption key, not a signing key. It scrambles the contents of the owner-side record. | The stored record cannot be read back. Included in the off-box backup. |
| **Permission-kernel key** | A file beside the permission kernel's own action log, under the owner's home directory (`~/.sigil/warden/`). Created automatically the first time the kernel opens | The account the kernel runs as | Every action record the permission kernel writes — one per tool invocation — and the signed summary that fixes the log's length | The existing action log can no longer be verified under a freshly-created key. The permission-kernel dir (its action log, this key, and the tool registry) **is now included in the off-box backup** and its key is restored owner-only (0600), so a machine loss no longer costs the action log — but a key *rotation* still means records signed under the old key verify only under the old public key. Nothing already published elsewhere is affected. |
| **Device keys** (the owner's phone, and any other approving device) | On the device itself. The device generates its own key and **never holds the owner key** | Each device separately | Each request that device makes to the desktop, and each approval it gives to a queued action | That device can no longer request or approve anything. The owner revokes it and pairs a replacement. Nothing else is affected. A revocation must itself be owner-signed, but once signed it carries no freshness requirement of any kind, so a lost phone can always be disarmed (section 11). |
| **Engagement-record key** (called the "spine" key in code) | Owner-only file in the working directory of the offensive engine (`offense-spine.key`) | The account running the offensive engine | The running log of an engagement, the record of every command executed, and defensive detection certificates | The existing engagement log cannot be continued: a new key does not verify the earlier lines of the same log file. Start a fresh engagement and re-issue the owner delegation (section 6). |
| **Governance key** | Owner-only file in the same working directory (`offense-governance.key`) | The account running the offensive engine | Evidence certificates for confirmed weaknesses, and the engagement's authority record | Already-issued certificates still verify (they are checked against the public half, which travels with the evidence). New certificates need a new key plus a new owner delegation. |
| **Operator key** | Owner-only file in the same working directory of the offensive engine (`operator.key`) | The account running the offensive engine | The usage ledger: who ran the tool, when, against what | The existing usage ledger cannot be extended by the new key. Past entries still verify against the retained public half. |
| **Approval signing key** | Not stored at all. Printed once when created; the operator keeps it and supplies it through an environment variable (`VIGIL_APPROVAL_OWNER_KEY`) | Whoever the operator gave it to | One queued action at a time | Re-run the provisioning command with the override flag. This rotates the key and voids any approvals signed by the old one. |
| **Irreversible-action signing keys** (owner plus co-signers) | Not stored. Printed once at creation; the owner's copy is supplied through an environment variable (`VIGIL_DESTRUCTION_OWNER_KEY`), co-signers keep theirs on their own machines | Each holder separately | One irreversible action at a time; several holders must sign | Re-run provisioning and distribute a fresh set. Nothing already done is affected — these authorise a single action each and are single-use. |
| **Self-witness key for the continuous re-checking log** | Owner-only file in the offensive working directory (`reprove-witness.key`) | The account running that service | Its own counter-signatures on the continuous re-proof log | That log's continuity claim restarts from the new key. |
| **Witness keys** (one per outside witness) | On each witness's own machine, in an owner-only file it creates on first run and then keeps. A witness that minted a fresh key per request would be worthless, so persistence is deliberate | Each witness operator separately | That witness's counter-signature that a new published summary genuinely continues the previous one it saw — and, in the timed form, the time at which it saw it | That witness drops out of the quorum. If enough drop out that the required number can no longer be met, no new summary can be witnessed until replacements are enrolled. Past counter-signatures still verify. |
| **Producer submission key** | The producing side, alongside its other working keys | The account running the producer | The producer's own signature on a request asking a witness to counter-sign. It exists so a witness can tell a genuine submission from anything else that reaches its network port, and refuse the rest at the door | New submissions are refused by any witness that pinned the old key, until the new key is distributed. Nothing already witnessed is affected. |
| **Notary key** | On a notary's machine | The notary operator | A co-signature tying a captured response to one specific encrypted session — the mechanism that is meant to let a reader stop trusting the producer's report of the wire | The independent leg of that evidence is lost; the rest of the evidence package is unaffected. Section 11 states honestly that today the shipped notary is software this system runs, so this key does not yet establish independence. |
| **Capability-grant signing keys** ("authorisers") | Deliberately **not** on any machine that runs the system. The project's own guidance calls them "the institution's crown jewels" and says they belong on a separate issuing machine, ideally inside a dedicated sealed key device that performs signatures without ever revealing the key | The issuing institution only | Capability grants and revocation lists (section 2) | New grants cannot be issued until enough authorisers are restored or replaced, and the trust list on each deployment has to be re-provisioned. Existing unexpired grants keep working. |
| **Capability trust list** (public, not a secret — listed here because losing it matters) | A small file in the deployment's own permission folder, which can be pointed at a read-only mount or a separately protected path | Written by the operator at set-up; readable by the account running the engine | Nothing. It is the list of authorisers the deployment recognises, and the number of them that must agree. Everything else about capability grants is measured against it | Deleting it does not break any signature — but it switches capability enforcement **off** unless the deployment's enforcement setting is explicitly pinned on. Re-install it from the institution's copy. A damaged file, unlike a missing one, denies every gated function. |
| **Sealed master key** (the key that encrypts all the above at rest) | Never on disk in usable form. Sealed inside the machine's hardware security chip; only two scrambled files, useless anywhere else, sit on disk | Nobody — it can only be used, on that one machine, through the chip | Nothing. It is an encryption key. | Everything it sealed becomes unreadable on that machine (that is the point). Recovery is from the off-box backup, which is encrypted under a passphrase instead. See section 6. |
| **Gated-interface password** | An operator-chosen password supplied through the environment | Whoever the operator tells | Nothing. It is a password that gates the controlled interface, not a signing key. | Choose a new one. No proof is affected. |
| **Call-back relay password** | An operator-chosen password supplied through the environment | Whoever the operator tells | Nothing. It gates the out-of-band call-back listener. | Choose a new one. No proof is affected. |

Two observations worth drawing out of that table:

- **Losing a private key never invalidates work already signed.** Checking a signature uses
  only the public half, and the public half travels inside the evidence package. Section 6
  states the one practical caveat.
- **Only two keys have no recovery path other than the off-box backup**: the owner key and the
  master key that seals things to one machine. Everything else can be regenerated and
  re-blessed by the owner.
- **The backup now covers both the trust root and the permission kernel.** The permission
  kernel's own key — the one signing the log of every tool invocation — is included, restored
  owner-only. The three offensive working keys are covered by a **separate** offense backup file
  (the two planes are never packaged into one archive — see 6.2). Section 6.2 states the boundary
  in full.

### Every stored secret is sealed under its own purpose

Section 5 explains that one master key wraps everything held at rest. That is not the whole
arrangement. Each stored secret is also bound, at the moment it is sealed, to a short label
naming *which* secret it is. The label is folded into the mathematics of the sealing, so a blob
sealed as one thing cannot be opened as another even with the correct master key. An attacker who
could swap two files on disk therefore cannot make the system read the operator's key where it
expects the governance key; the swap simply fails to open.

Nine such labels exist in the source, one for each thing the system holds at rest:

| Sealed item | Kept where |
|---|---|
| The owner private key | Sovereign side |
| The key that encrypts the owner-side record | Sovereign side |
| Individual fields inside that record | Sovereign side |
| Service credentials such as an API key | Sovereign side |
| The whole encrypted off-machine backup | Wherever the operator puts it |
| The offensive engagement-record key | Offensive side |
| The offensive governance key | Offensive side |
| The operator key | Offensive side |
| The self-witness key for the continuous re-checking log | Offensive side |

The comments in the source say why each label is distinct in almost identical words each time:
"a blob sealed here can never be opened as another secret". It is the same discipline as the
purpose labels on signatures in section 2, applied to storage instead of to signing.

### How an outsider checks each signed thing

The point of all of this is that someone who does not work for the operator can check the claims.
The table below says, for each signed object, what an outside checker needs and what performs the
check. "Public keys only" means no private key of any kind is required.

| Signed object | What an outsider needs | What performs the check |
|---|---|---|
| Evidence certificate | The evidence package, the trust-root fingerprint received separately (section 9), and public keys only | The standalone checker `verify_pcf.py`, which imports none of this system's code. Or the system's own `verify_certificate`, which additionally re-runs the original test |
| Chained record entries and the signed head | The saved chain files and public keys only | The same standalone checker, or the system's own bundle verifier |
| Owner-side personal record | The record files and the owner public key | The sovereign side's own `sigil verify` |
| Offensive engagement record | The saved record, the owner public key, and the owner-signed delegation naming the working key | `vigil verify`, which derives the key it trusts from the delegation rather than being handed one |
| Engine reasoning chain | Two small saved files plus the owner-signed delegation | The same command's blackboard check, which reads only those files and public keys — no database, no engine |
| Usage ledger | The ledger file and the retained operator public key | `vigil verify-ledger`. Honestly noted: this one is **not** tied back to the owner today |
| Continuous re-proof log | The log, its signed summary, and trust anchors the checker pins itself | Its own verifier. Also not owner-tied today; the anchors must be supplied out of band |
| Remediation and re-proof certificates | The fix-lifecycle package and public keys only | The standalone checker `verify_vf.py`, again importing none of this system's code |
| Permission-kernel action records | The action log and the kernel's recorded public key | The kernel's own verify routine |
| Transparency checkpoints | The published summaries and each witness's public key | `verify_witnessed` for "a quorum signed", and a separate `verify_split_view_resistant` for the stronger claim — deliberately two functions, so a caller must state which claim it is making |
| Channel-binding co-signature | The captured response and the notary public key, pinned out of band | `verify_channel_binding_evidence` |
| Capability grants and revocation lists | The grant, the list, and the deployment's trust list | The engine's own gate, which runs the checks in the fixed order given earlier in this section |
| Dossier manifest | The downloaded package | Recompute each file's fingerprint against the manifest, then check the signatures against the trust root the package carries — and compare that trust root's fingerprint against the one received separately |

**The one thing no standalone checker does** is re-run the original automatic test. That needs the
test's own code, which lives inside the engine. So an outsider working with the standalone
checkers alone establishes origin, integrity, binding and chain continuity; reproducing the
finding itself requires the software. Both standalone files say this in their own opening
comments rather than letting a reader assume otherwise.

---

## 5. How keys are protected while sitting on disk

Three layers, in increasing strength.

**Permissions.** Every private key file is created readable and writable by its owner account
only, and the file is created that way from the very first byte rather than being tightened
afterwards — the code comment notes this is so the key is "never briefly world-readable".
Writes are atomic (written to a temporary file, flushed, then renamed into place), so a crash
or power cut can never leave a half-written key.

**Encryption at rest under a machine-bound master key.** A single 32-byte master key wraps
every stored secret and private key. The wrapping uses authenticated encryption, which means
any bit-flip, truncation, wrong key, or attempt to open a blob under the wrong purpose label
fails outright rather than returning something plausible.

**Hardware custody of that master key.** The master key itself is sealed to the machine's
Trusted Platform Module — a small tamper-resistant chip on the motherboard, the same kind of
component that protects disk-encryption keys on a modern laptop. The abbreviation for it is
**TPM**, and the rest of this briefing uses that short form. Sealing means the encrypted blob
on disk is **useless on any other machine**. Copy the disk, and the secrets do not come with
it.

Four design choices in that vault deserve mention because they are the ones that usually go
wrong elsewhere:

- **It is opt-in and cannot leave the system unusable.** Until it is set up once, the vault is
  switched off and everything behaves exactly as before, with a loud "unsealed" status shown.
- **Migration is non-destructive.** When an existing plaintext key file is first sealed, the
  sealed copy is verified to open correctly *before* the plaintext is replaced. A migration
  cannot lose a key.
- **It fails closed.** If the hardware chip later cannot open the sealed blob — a moved disk,
  missing tooling — reads fail with an explicit "locked" error. The code states there is
  **no silent fallback to plaintext**.
- **It never quietly mints a replacement identity.** If a stored key pair is sealed but
  cannot be opened, the loader propagates the failure rather than generating a fresh key. A
  fresh key would silently orphan every record the old key ever signed.

**Honest statement about the hardware layer.** The sealing path is written and tested against
a simulated chip. On a real machine it switches on once the standard TPM command-line tools are
installed and the operator's account is allowed to reach the chip. On a machine with no TPM,
the deployment guide says plainly that keys are **unencrypted on disk** (protected by file
permissions only), that this is acceptable on a trusted single-user machine but not on a shared
or internet-hosted one, and that the set-up script prints a loud warning rather than silently
degrading. I have not verified whether a TPM is present and set up on any particular
deployment — that is a property of the machine, not of the software, and an assessor should
check it directly on the host in question.

Because sealing binds secrets to one physical machine, it also creates a disaster-recovery
question: what happens when that machine dies. That question has a real answer, and section 6
is devoted to it.

### A specific class of forged key that is refused outright

There is a known trap in this family of signature mathematics. A small number of special
public keys are "weak" in a way that lets **anyone** produce a signature that verifies under
them, with no private key at all. If such a key were ever accepted into a list of trusted
signers, the whole scheme would collapse for that key.

The core rejects them. Before any public key is used, it is checked against a published list
of these weak points and against a rule that bars a second, non-standard way of writing the
same key (which would otherwise let one key have several different-looking identities). The
comment records what the attack would be: a signature that is literally all zeroes verifying
for any message. The project's own history notes this was found by an adversarial review that
went four levels deep on an earlier fix.

There is a matching floor in the counting logic: even a hand-edited trust list claiming a
threshold below one can never be satisfied by zero valid signatures. A bundle with no
signatures must never verify.

---

## 6. Losing a key, backing one up, replacing one, withdrawing one

This is the section where honesty matters most, because key loss, rotation and revocation are
where signing schemes usually overpromise. It answers, in order, the questions a security
officer asks in the first meeting: does work already signed survive a lost key; is there a
backup or an escrow; what do I actually do when a particular key is gone; how is a key
replaced; what is built; and what is simply not there.

### 6.1 If a key is lost, does the work it already signed stop being valid?

**No.** This is the single most important thing to understand, and it follows from how
signatures work.

Checking a signature never requires the private key. It requires only the **public** half —
the impression, not the stamp. Every evidence package carries the list of public keys it was
signed under, and the checker compares that list against the fingerprint the operator published
separately (section 9). So an evidence bundle issued last year still verifies today even if
every private key that made it has since been destroyed, stolen or replaced.

Concretely: a certificate issued in March, checked in November on an auditor's laptop, using
the standalone checker and the fingerprint from the operator's website, verifies exactly as it
did in March. Losing the private key changes nothing about it.

**The one practical caveat, stated plainly.** The published fingerprint is a fingerprint *of
the list of signing keys*. If the operator changes that list — adds a key, removes one, rotates
one — the fingerprint of the new list is different. Old packages carry the old list and check
against the old fingerprint; new packages carry the new list and check against the new one.
That means the operator must **keep publishing the historical fingerprints**, not overwrite
them, or a recipient holding an older package will find that the only fingerprint on the
operator's website no longer matches it. Nothing in the software enforces this; it is an
operational duty, and it belongs in the operator's key-management procedure. An assessor should
ask to see it.

### 6.2 Is there an escrow or a backup? What is actually in it?

**There is no key escrow.** No copy of any private key is held by the vendor, by a third party,
or in any recovery service. That is a deliberate property: a copy held by someone else is a
copy that can be compelled or stolen.

**There is a portable, passphrase-encrypted backup**, and it exists precisely because the
hardware sealing of section 5 binds secrets to one physical machine. The code's own opening
line names the problem: sealing to a machine's chip means "a dead disk is unrecoverable from
the vault alone — the whole audit ledger and all memory would be lost". Be precise about the
word *off-machine*: by default the backup is written to the **same host's disk** (`~/vigil-backups`),
and the scheduled timer runs it **air-gapped** (no network). That file is *portable* (it restores
on new hardware) and *encrypted*, but it is not genuinely off-**host** until it is copied to
another machine. That copy is a **separate, opt-in step** — see honest limit 4.

The backup command packages, into one encrypted file:

- the owner-side record itself (all of it, with its signed summary),
- the anti-rollback floor and the software-integrity manifest,
- the **permission-kernel directory** — its signed action log, its own signing key, and the tool
  registry — with the kernel key restored owner-only (0600),
- the **owner private key**, and the key that encrypts the record's contents.

Two properties make it safe to keep off the machine:

- **It is encrypted under a passphrase the operator chooses**, using a deliberately slow
  key-derivation step so that guessing the passphrase is expensive. Without the passphrase the
  file is unreadable noise. The passphrase is never stored anywhere — the code says lose it and
  the backup is unrecoverable **by design**. That is the price of the file being safe to keep
  in a different building.
- **A restore verifies before it writes.** The file carries an owner-signed list of the
  fingerprint of every packaged item. On restore, the passphrase must decrypt the file, that
  signed list must verify, and every item must match its recorded fingerprint — all **before a
  single file is written**. After writing, the restored record's internal chain is re-checked,
  and the restore refuses to report success on an inconsistent record. It also refuses any
  packaged filename that tries to escape the destination folder.

Restoring onto new hardware re-seals the recovered secrets under the **new** machine's chip if
one is present, so the recovered system is protected again rather than left in the open.

Four honest limits on the backup:

1. **It can now be scheduled.** The standalone `sigil backup` is still a manual command, but the
   unified `vigil backup` verb takes a passphrase-encrypted local backup of **both** planes, and a shipped systemd
   user timer (`infra/systemd/vigil-backup.timer`) fires it on a daily cadence with retention
   (keep the last N, and anything within N days). Freshness is only ever as current as the last
   fire of that timer, and the timer carries the passphrase in a `0600` environment file — which
   is weaker than typing it interactively, so the example file spells out the trade-off and the
   systemd-credentials alternative. An assessor should still ask where the backup file is kept
   and confirm a test restore has been done.
2. **The two planes are backed up as two SEPARATE encrypted files — never one merged archive.**
   The sovereign file covers the owner side (owner key, record, floor, integrity manifest, and now
   the permission-kernel dir). The offensive engine's working keys — the engagement-record key, the
   governance key, the operator key — plus its spine and its collected evidence are covered by a
   **separate** offense backup file, whose internal manifest is signed by the offensive governance
   key. They are deliberately never packaged together, because one process holding both planes'
   secrets at once would breach the two-process trust boundary. Each file needs its own passphrase.
   Be precise about what that governance signature buys on the offense file: because the signature
   lives *inside* the passphrase-encrypted body and restore checks it against the key carried in the
   same body, by default anyone who holds the passphrase could re-sign a substitute manifest — so
   **by default the offense file's authenticity is passphrase-possession, exactly like the sovereign
   file** (the passphrase is the real root of trust, next point). To get genuine governance-key
   authenticity you must **pin** the expected governance public key out of band at restore time
   (`vigil restore --expect-governance-pubkey <base64>`); with that pin, a passphrase-holder who does
   not also hold the governance *private* key cannot pass off a forged backup. The governance key's
   own tie to the owner remains the owner-signed delegation.
3. **The passphrase becomes the root of trust for that file.** Anyone holding both the backup
   file and its passphrase holds the owner key. It should be treated with the same seriousness
   as the key itself — ideally split between two custodians or held in a safe.
4. **Off-*host* replication is a separate, opt-in step — the scheduled backup is local and
   air-gapped.** The daily timer writes to the same host's disk with no network, so on its own it
   does not survive that host being destroyed. To get a genuine second copy on another machine,
   run `vigil backup --push <dest>` (or the shipped, network-enabled `vigil-backup-push.service` /
   `.timer`, kept separate from the air-gapped local unit). Push copies **only the already-encrypted
   files** (ciphertext) plus the fingerprint manifest — no plaintext and no passphrase ever leave
   the host — and the pushed copy is itself a valid restore source. Only a local-directory transport
   ships today (a mounted remote filesystem, an sshfs mount, or a removable disk); rsync/scp/object-
   store backends are structured to slot in behind the same contract. The **remote's** own security
   (who can read that directory) is the operator's responsibility, and an assessor should confirm a
   test restore has been done *from the pushed copy*, not only the local one.

### 6.3 What to do when a specific key is lost

| What was lost | What still works | What to do |
|---|---|---|
| **The owner key**, with a backup available | Everything already signed still verifies | Restore the backup onto the replacement machine, then run the verification command against the restored copy to confirm the recovered owner signature. |
| **The owner key**, with no backup | Everything already signed still verifies, forever, against the old public key | There is no recovery path. A new owner identity must be created; every party who pinned the old owner key must be given the new one out of band; and every delegation must be re-issued. Be aware of one sharp edge: the software does not treat a missing owner key as an error — the next owner-signing command simply creates a new one. Nothing announces "the owner key is gone", so an operator can rotate their own trust root by accident. Keeping the backup is the guard against this. |
| **The machine, or the TPM chip in it** | Everything already published still verifies | The sealed copies on that disk are permanently unreadable, by design. Restore the off-box backup onto the new machine. Without a backup, the record and the owner key are gone; published evidence is unaffected. |
| **The permission kernel's own key** | Everything already published elsewhere still verifies | If the whole machine is lost, restore the off-box backup — the permission-kernel dir (its key, action log, and tool registry) is now packaged in it, restored owner-only, so the log is recoverable. If instead the key alone is *rotated*, the kernel creates a fresh one the next time it opens, and records signed under the old key verify only under the old public key. Still note the log's length and last fingerprint somewhere outside the machine as a cross-check. |
| **A device key** (a lost or stolen phone) | Everything else is unaffected | Revoke the device on the owner's side, then pair a replacement. The revocation is honoured from the moment it is written; the desktop bridge recomputes the authorised set on every single request rather than caching it, so a revoke bites immediately rather than at the next restart. |
| **A witness key** | Every counter-signature that witness already gave still verifies | Enrol a replacement witness and re-publish the roster. If losses take the set below the required number, no new summary can be witnessed until that is fixed — which is the intended behaviour of a several-must-sign scheme. |
| **The engagement-record key** | Everything already signed still verifies | Generate a fresh one (it is created automatically when absent), export its public half, and have the owner re-issue the delegation. Do not try to continue the old engagement's log with a new key — the earlier lines of that file will not verify under it. Start a new engagement. |
| **The governance key** | Every previously issued evidence certificate still verifies | Generate a fresh one, export its public half, have the owner re-issue the delegation, and publish the new key-list fingerprint alongside the old one. |
| **An approval or irreversible-action signing key** | Nothing already done is affected | Re-run the relevant provisioning command and distribute the new keys. Approvals signed by the old key stop being accepted; that is the intended effect. |
| **A capability-grant signing key** | Existing unexpired grants keep working | Issue a replacement authoriser set and re-provision the trust list on each deployment. If enough authorisers are lost that the signing threshold can no longer be met, no new grants can be issued at all until that is fixed — which is the intended behaviour of a several-must-sign scheme. |
| **The capability trust list, or the signed revocation list** (not keys, but the same class of operational event) | Every signature already made is unaffected, and existing grants are unchanged | Re-install both from the institution's own copies. Note the asymmetry, which mirrors the floor below: a **damaged** trust list denies every gated function, while a **missing** one silently returns the deployment to the ungoverned state unless enforcement has been explicitly pinned on. A grant issued with the "revocation list required" marking refuses to run while that list is missing, so for those grants a lost list fails safe rather than open. One more thing to know: the small local note recording the highest revocation serial seen so far is what stops an older, genuinely signed list being replayed to un-withdraw something. Delete that note and an older list becomes acceptable again — so treat it as part of the deployment, and re-check the current serial after any restore. |
| **The anti-rollback floor file** (not a key, but the same class of operational event) | The record and its signatures are unaffected | Be aware of the asymmetry: a **corrupt** floor is treated as an error and fails closed, but an **absent** floor is treated as "no floor yet" and the rollback check is simply skipped until it is re-established. So a deleted floor silently switches that one protection off rather than announcing itself. After a legitimate restore, the operator re-seeds it with the dedicated reset command, which is the only path allowed to lower it, requires an explicit confirmation flag, and re-signs the record with the owner key so the re-seeded floor is not left unsigned. |

### 6.4 How a key is actually replaced — the procedure

There is no scheduled or automatic rotation. Replacing a key is an operator action, and these
are the steps the software supports.

**The two offensive working keys (engagement-record and governance).**

1. Stop the offensive engine.
2. Move the existing key file out of the working directory and keep it somewhere safe. (Keeping
   it is not needed for checking old evidence — that uses the public half — but it costs
   nothing and removes any doubt.)
3. Run the identity command. It creates a fresh key pair on first use and writes out a small
   file containing **only the public halves**.
4. Move that file to the owner's machine **over a channel you can authenticate**, or read the
   printed fingerprints aloud to the owner and have them confirm. This step is the human link
   in the chain and section 4 explains why it matters.
5. On the owner's machine, run the delegation command. It prints the exact keys it is about to
   bless, then signs a delegation for each role with a chosen scope and expiry.
6. Publish the new fingerprint of the key list next to the old one, and re-pin the owner's
   public key with anyone who verifies your evidence.

**The approval key.** (This is the separate owner-held key used to approve one queued action at
a time — not the sovereign owner key that roots everything.) Re-run its provisioning command
with the override flag. The command refuses to overwrite an existing authority without it, and
warns in plain terms that re-provisioning replaces that key and invalidates any approvals
signed by the old one. The new private key is printed once and is not stored anywhere.

**The irreversible-action quorum.** Re-run the quorum provisioning command with the number of
signers and the threshold you want. It prints each signer's private key once, and writes only
the public list to disk. Distribute the co-signer keys to their holders on their own machines —
keeping them all on one machine reduces the scheme to a solo owner with extra steps.

**The owner key.** There is no rotation command. In practice this means creating a new owner
identity, re-issuing every delegation from it, and re-distributing the new owner public key to
everyone who pinned the old one. Because that is a manual and consequential exercise, the
delegation windows should be sized so that this is rare — which is the reasoning the code
itself gives for short windows.

**The capability-grant authorisers.** Issuance is deliberately a separate ceremony on a
separate machine and is not exposed as a casual command. The runtime side only ever verifies
grants; it can never create one.

### 6.5 What is built and working

- **The approval key can be rotated** (procedure in 6.4). Re-running the provisioning command
  refuses to overwrite an existing authority unless an explicit override flag is passed, and
  warns in plain terms that re-provisioning **rotates the owner key and invalidates any tokens
  signed by the old key**.
- **Delegations expire.** Every owner delegation carries a hard expiry. Past it, the
  delegation is refused. The owner chooses the window; the tool validates that the number is
  finite and sensible.
- **The engagement-record delegation is shaped to permit rotation.** It is fixed at "one of
  several" — one signature required, but several authorised keys may be listed. That is
  precisely the shape that lets an old key and a new key both be valid during a changeover.
  The code explains why it refuses any other threshold there: the engagement record is signed
  by a single key, so demanding more signatures would be mathematically unsatisfiable, and
  accepting such a delegation would let a checker silently water down the owner's intent.
- **Re-verification permission slips are revocable and narrowable.** The permission slips
  minted for outside auditors carry a revocation identifier, and the checker is handed a list
  of revoked identifiers. A holder can also *narrow* a slip and pass it on — never widen it —
  so a permission can be delegated down a chain without the owner re-signing.
- **Every irreversible authorisation is single-use.** Once spent, it cannot be spent again
  (section 8 explains the mechanism).
- **Capability grants expire on their own, and can be withdrawn early.** Every grant carries a
  valid-until date, so a grant nobody renews simply lapses. Before that date, the issuing
  institution withdraws one by re-issuing a signed revocation list naming it; an older list
  cannot be replayed over a newer one, and a grant can be issued so that it refuses to run at
  all whenever no list is present. This is the one place in the system where a signed permission
  *can* be cancelled before it expires — unlike the owner delegations described in 6.6.

### 6.6 What does not exist, stated plainly

- **There is no key escrow and no vendor-held recovery copy.** The encrypted off-box backup of
  6.2 is the only recovery route, it is created by an explicit operator command, and its
  passphrase is unrecoverable if forgotten.
- **A delegation cannot be cancelled before it expires.** The code says so in its own words:
  *"a delegation has no pre-expiry revocation, so [the expiry time] is its only bound — the
  owner sizes that window to the shortest practical horizon."* If a working key is compromised, the
  mitigations available are to wait out the window, to stop honouring that delegation at the
  checkers you control, and to re-key. There is no published revocation list for delegations.
- **A permission slip already in flight can still be used.** The code names this as the
  known, stated gap: a capability spent inside its validity window, before news of the
  revocation reaches the checker, still works.
- **I did not find an automatic re-keying schedule** for the owner key, the engagement-record
  key, or the governance key. Rotation of those is an operator action, following the procedure
  in 6.4, not a scheduled process. An assessor should treat key-rotation cadence as an
  operational policy question to put to the operator, not as something the software enforces.
- **A daily backup timer now ships** (`vigil-backup.timer`, driving `vigil backup` over both
  planes with retention), so unattended off-box backup is a feature the software drives — though
  there is still no automatic *rotation* command for the owner key itself; rotation remains a
  procedure an operator runs. The timer's freshness is only as current as its last fire.
- **Withdrawing a capability grant is not instantaneous, and nothing distributes it for you.**
  Two limits, both stated rather than smoothed over. The new revocation list has to reach the
  deployment: the software reads it from the deployment's own files and never fetches it from
  anywhere, so delivering it is the institution's job. And because the capability decision is
  worked out once when the software starts, a withdrawal takes effect at the next start rather
  than interrupting a run already in progress. For an urgent stop mid-run, the emergency stop of
  section 7 is the instrument, not revocation.

---

## 7. Emergency stop, and where it sits relative to keys

Separate from keys, but worth one paragraph because officials always ask: there is an
emergency stop that is a file on disk. While it exists, every action is refused, and because
it is a file rather than a memory flag, **tripping it survives a crash or a restart**.
Clearing it is a separate, explicit, logged act by the operator. Its check is deliberately
paranoid: it reports "halted" unless the file's absence can be positively established, so a
permission error or a disk fault reads as *stopped*, never as *go*. Authorisation, scope and
the gate chain are covered in their own chapter; this is noted here only because no signature
overrides it.

---

## 8. "Several people must approve" — thresholds and m-of-n

### The idea

Some bank vaults need two managers to turn their keys at the same time. Neither can open it
alone. That is a threshold scheme: **m** signatures out of **n** authorised holders.

The system uses this shape in two different places, and it is important not to confuse them.

### Where it is used for evidence

Evidence certificates and the signed head of the record are verified against a governance
trust list with a threshold. The checking routine counts **distinct** authorised signers with
valid signatures and compares that to the threshold. Repeated signatures from the same
identity are ignored, so one holder cannot pad a quorum. In a small single-operator
deployment this threshold is typically one; the mechanism supports more.

### Where it is *required*: irreversible actions

The strongest gate in the system applies only to actions that destroy something or that would
be wide-reaching and hard to undo. An action of that kind runs only when **all** of the
following hold:

1. The engagement's own authority says the action is in bounds (and the emergency stop is not
   tripped).
2. The classifier that grades every action returns exactly "automatic" — anything unrecognised
   or dangerous is not.
3. **A threshold authorisation exists, signed by a quorum of distinct authorisers, and the
   owner is among them.**

That third condition has five properties, each of which fails closed — any error, any
malformed input, any missing piece is a refusal:

| Property | What it means in plain words |
|---|---|
| **Threshold** | Enough distinct recognised signers must have signed. Duplicate identities are barred at the cryptographic core. |
| **Mandatory owner** | The owner must be one of the signers, and *which identity counts as the owner is fixed at deployment time*, not supplied with the request. The reasoning is written down: the automated worker is itself a registered signer, so a request-supplied owner name could simply be renamed to the worker's own. A worker-plus-policy quorum without the owner authorises nothing. |
| **Action binding** | The authorisation names the engagement, the target, how damaging the action is classed as being, and a specific action identifier. It cannot be replayed to authorise a different action. |
| **Dead man's switch** | The authorisation has a bounded lifetime. The signing command opens a ten-minute window by default and refuses outright to sign anything whose total window would exceed **fifteen minutes** — the same fifteen-minute ceiling described in the safety chapter. A long-lived pre-signed "sleeper" authorisation is void; a quorum must sign close in time to execution. |
| **Single use** | Spending an authorisation is an atomic reservation: a marker file is created with an exclusive-create operation, and of any number of simultaneous callers holding the same authorisation, exactly one wins. The marker is flushed to disk, so a spent authorisation stays spent across a restart. |

### The honest limits of that gate

- **The gate never sees the command itself.** The action identifier is an opaque string to it.
  Binding it to the real command depends on the signer computing that identifier from the
  command and the executor deriving it the same way. The code states this outright: *"the gate
  never sees the command and cannot enforce that."*
- **The default threshold is one.** The provisioning command defaults to a solo owner, and
  warns that at threshold one, whoever holds the owner key can authorise alone. Genuine
  separation of duties requires the operator to provision additional signers and to keep those
  keys on different machines. That is a deployment decision, not something the software does
  for you.
- **One file-writing detail is not itself single-use.** The command that signs an
  authorisation writes its output file with create-or-truncate rather than exclusive-create,
  so it overwrites any earlier file at that path. Single use is enforced downstream by the
  spent-marker ledger, not by that write. This correction was found by the project's own
  adversarial honesty pass and is recorded in its feature documentation.
- **True single-signature aggregation is deferred.** The scheme delivers the
  several-must-agree security property. A more compact form (where the several signatures are
  mathematically combined into one) is described as a size-and-verification refinement that
  does not change the security property, and is deliberately not built.

### Deployment status of the irreversible path

The only destructive action wired today is **raising a proposed code change for a human to
review** — in software terms, opening a pull request with a suggested fix. Nothing is changed
in the customer's software by the system: a person still has to read the proposal and accept
it. It is off by default. Turning it on requires, all together: a signed authorisation, a trust
anchor, at least one mandatory signer including the owner, the spent-marker ledger, and a
repository access token in the environment. With all of the optional legs off, the run is a
non-destructive dry run that only proposes.

**Status: built, tested, and not yet fired in the field.** Live use requires the operator to
provision the multi-party quorum keys and supply a repository token. That is stated in the
project's own deferred-work register and should not be presented as a completed field
deployment.

---

## 9. The trust root, and why it must reach you separately

This is the single most important idea in the chapter, and the easiest to get wrong.

### The problem

Suppose someone hands you a sealed letter, and in the same envelope, a card showing what the
seal is supposed to look like. You compare the seal to the card. They match. What have you
learned?

Nothing. A forger who made both the letter and the card would also produce a match.

Exactly the same trap exists digitally. An evidence package contains signatures and it
contains a file listing the keys that are supposed to have made them. Checking one against the
other proves only internal consistency. It proves nothing about origin.

### The fix

The list of authorised signing keys is called the **trust root**. The system computes a short
fingerprint of that list — a fixed-length code that changes the moment any key is added,
removed or altered.

The operator publishes that fingerprint **out of band**: through a channel completely separate
from the evidence package itself. A website under the operator's control, a signed contract
annexe, a printed page handed over in a meeting, a value read out on a phone call. The point
is that the fingerprint and the package must not travel together, so that compromising one
does not compromise the other.

The checker is then given the expected fingerprint explicitly, with the
`--trust-root-fingerprint` option. The code makes the ordering matter: the fingerprint
comparison happens **before any signature is checked**, and a mismatch means refusal. The
comment states the purpose directly — *"so a bundle that ships its own attacker-generated
trust root cannot self-authenticate."*

### The interface refuses to fake this

The system's Trust Center screen shows the result of an offline re-verification as **three**
states, not two:

- matches the out-of-band pin (confirmed),
- does **not** match the pin (refuted),
- **trust root unpinned — no out-of-band pin supplied, origin not bound.**

That third state is deliberately never shown as green. A signature that verifies against an
unpinned trust root proves only that nobody tampered with the package after it was signed. The
screen says so on its face rather than letting a green tick imply more.

### Checking without installing anything

Two standalone checkers are shipped as ordinary readable files:

- **The proof-bundle checker** re-checks a package of proven findings. It imports **no** part of this system — not
  the engine, not the shared core, not the integration layer, not the vendored agent. It uses
  only the Python standard library and one signature library, and it is written from the
  published wire specification. It even has a `--prove-standalone` mode that demonstrates, in
  a clean interpreter, that none of this system's modules are even reachable. It proves the
  fingerprint pin, the signatures, the binding, the file integrity, and the chain. It exits 0
  only if sound, 2 if not sound, 3 on a usage error, so it can be dropped straight into
  someone else's automated pipeline. Its header states it plainly: *"Verification only — this
  file contains no offensive capability."*
- **The fix-lifecycle checker** does the same for the repair story — weakness present, then
  proven fixed, then still proven, witnessed no later than a given time — again with none of
  this system's code. A side-by-side test proves it agrees byte-for-byte with the in-house
  checkers on real evidence and on a battery of deliberately tampered copies.

(For an assessor who wants to find them: the two files are `verify_pcf.py` and `verify_vf.py`,
shipped in the specification folder alongside the written wire format they implement.)

**The one thing they honestly do not do:** they do not re-run the original automatic test.
Re-running it requires the test's own code, which lives in the engine. So a standalone check
establishes authenticity, binding, integrity and chain; reproduction is the one layer that
needs the system installed. Both files say this in their own opening comments rather than
letting a reader assume otherwise.

---

## 10. The tamper-evident running record

### The idea

Picture a bound ledger where each new page begins by writing down a fingerprint of the
previous page. Tear a page out, swap two pages, or alter a figure, and the fingerprints stop
lining up at exactly the point where the tampering happened.

That is what the chained record does. Each entry records its position, a fingerprint of the
entry before it, and a fingerprint of the certificate it covers. Checking walks the whole
chain and reports the exact position of any break, distinguishing:

- an entry deleted or reordered (the link to the previous entry does not match),
- an entry altered (the entry's own fingerprint does not match its contents),
- a gap in the numbering.

### Why a chain alone is not enough

A chain catches changes in the middle. It does not, by itself, catch someone simply chopping
the end off — a shortened chain is still perfectly self-consistent.

So the chain is capped by a **signed head**: a small signed statement fixing three things —
how many entries exist in total, what position the last one holds, and the fingerprint of the
final entry. Truncate the log and it no longer matches its head.

### And why even that is not enough

At the level of a whole evidence bundle, the check goes further. The list of certificate
fingerprints in the chain must equal **exactly** the certificates actually present, in order.
That single equality closes suppression, injection and reordering at once — you cannot quietly
drop the inconvenient finding and leave a chain that still looks valid.

Three further bundle-level rules, each fail-closed:

- Every finding reference must be unique, so the evidence supplied for one certificate cannot
  be silently applied to another.
- All components must belong to one named engagement; a bundle mixing two engagements is
  refused. (One narrow limit is disclosed in the code: a certificate with a blank engagement
  name can still ride inside a named bundle. It is documented as defence-in-depth only, since
  it still requires a validly signed head over the mixed chain.)
- A derived "attack path" — a route stitched together from several findings — is not
  individually signed, so it counts only when a validly signed head anchors it *and* every
  finding it cites is present and itself verified. A route with nothing under it is refused as
  unsupported.

### There is more than one record, and the system says who signs each

The system keeps several separate append-only records, split across the two halves of the
system. Rather than leave that implicit, there is a single registry naming, for each record,
who legitimately signs it, whether its trust reaches the owner **today**, and whether an
outsider holding only public keys can check it from saved files.

| Record | Signed by | Trust reaches the owner today? | Checkable offline from files? |
|---|---|---|---|
| Owner-side personal record | The owner key | Yes | Yes |
| Offensive finding authority | Governance key, owner-delegated | Yes | Yes |
| Offensive engagement record | Engagement-record key, owner-delegated | Yes | Yes |
| Offensive usage ledger | A stable operator key | **No** — not owner-delegated today | Yes |
| Continuous re-proof log | Governance key | **No** — its trust anchors are pinned by the checker out of band instead | Yes |
| Engine reasoning chain | Governance key, owner-delegated | Yes | Yes |

The registry enforces an honesty rule on itself: a record may be marked as reaching the owner
**if and only if** it names the specific piece of code that performs that check. Merely being
*capable* of delegation is not enough. The comment is explicit: *"this module does not pretend
the tie is enforced before it is."* An automated self-check refuses to start if any entry
claims a tie it cannot name — and equally refuses if an entry under-claims one it can.

### On the owner's side, individual actions are signed too

The sovereign half runs a small kernel that records every tool invocation — time, agent, tool,
a fingerprint of the arguments, the permission tier, the decision, the approver, a fingerprint
of the result — with each record **both individually signed and chained**. The timestamp is
part of what gets fingerprinted, so timestamps themselves are tamper-evident. A separately
signed head fixes the log's length.

---

## 11. Rolling back to an older state — and the defences against it

### The attack

This is the subtle one, and the system's own comments describe it better than most vendor
documentation would.

A signature proves authenticity, not freshness. Suppose an attacker with write access to the
disk kept a copy of a genuine, correctly signed summary from a month ago — before some
inconvenient finding was recorded. They replace today's log with the older, shorter, genuinely
signed version and replace today's summary with the older, genuinely signed summary. Every
signature checks out. The record has been silently rewound.

The same weakness has a second, sharper form: instead of rewinding the whole record, replay one
old signed *permission* into an otherwise honest record. That form, and the guard added for it,
are covered at the end of this section under "Replaying a single signed permission". A reader
short of time should go there first, because it is the form that affects who is allowed to do
what, rather than what is on file.

### Defence one: a durable floor

The system keeps a small **high-water floor** file recording the highest state the record has
ever reached: how many entries, and the last position. A validly signed summary that sits
below the floor is rejected as a rollback.

Several details in that file matter:

- **The entry count is the primary guard**, not the position number. Positions are counted
  from zero, so a log with one entry and an empty log both report position zero. A one-to-zero
  truncation would slip past a position-only check. The count cannot be fooled that way.
- **A corrupt or malformed floor raises an error rather than being read as absent.** Reading
  a damaged floor as "no floor" would silently switch the whole protection off.
- **A symbolic link at the floor's path is refused as possible tampering**, and that check
  runs before the existence check, because a dangling link would otherwise read as "no file".
- **Advancing the floor takes a cross-process lock, re-reads the prior value inside the lock,
  and refuses to move downward.** Without the lock, two simultaneous writers could each read a
  stale value and the later write could roll the floor backwards.
- The file is written atomically at owner-only permissions and flushed to disk.

### The honest limit of the floor, stated by the code itself

The floor is a **local, unsigned file**. The module's own header says: *"A SAME-HOST attacker
with the owner's UID (or root) defeats the local verify path by rewriting the log AND this
floor together."*

So the guarantee it actually delivers is:

- **It does hold** against an attacker who can overwrite the log but not the floor.
- **It does hold** for any outside checker that retained a newer floor of its own.
- **It does hold** against routine operational accidents — on the owner side the floor lives
  deliberately *outside* the record directory, so a reset that wipes the record directory
  cannot lower the floor.
- **It does not hold** against a fully dishonest producer who rewrites everything on their own
  machine. That case is closed only by an outside witness, not by this file.

The code adds what the floor gives unconditionally: it can only ever move forward, it refuses
any instruction that would move it back, and it survives a crash in the middle of a write —
even when several parts of the system try to move it at the same moment. No honest process ever
lowers it. (What to do if the floor file is *lost* rather than attacked is in section 6.3.)

### Defence two: tying freshness to something that visibly grows

On the owner's side there is a second mechanism. The action log's summary is cross-recorded
into the separately signed, actively growing personal record, and the checker rejects any
on-disk summary whose count is below the highest ever recorded there. Rolling back the action
log then requires also rolling back the personal record — which is loud, because the owner's
recent memory would vanish and the ingest position would break. The comment is candid about
the residual: a complete double wipe plus a fresh key evades detection, but it changes the
visible public key, and *"hardware/remote monotonic state is the only absolute defence for a
local audit log."* ("Monotonic" simply means a number that can only ever go up, never down.)
In plain words: the only complete answer is a counter that lives somewhere
the attacker cannot rewind — inside a hardware chip, or on a machine they do not control — and
that can only ever count upward.

### Defence three: outside witnesses

A **witness** is an independent party that watches the log's public summaries. When a new
summary arrives, the witness checks that it is a genuine continuation of the last one it saw —
the count and position only grow, and the chain of summaries links back — and only then adds
its own signature. An honest, stateful witness never signs two conflicting versions of
history.

What this buys, precisely:

- **Non-equivocation**: two different parties cannot be shown two different histories.
- **A time bound**: "this existed no later than T".

What it does **not** buy, and the documentation insists on saying so: a witness does **not**
attest that any finding is true, that a fix holds, or that any test fired. It attests only to
continuity of the record. *"Conflating 'witnessed' with 'true' would be an overclaim."*

Three further honest points:

- **Protection against two different histories is conditional, not automatic.** It holds only
  when the witnesses form a **strict majority** — more than half must sign. Below that, in
  particular the one-witness case that the trust model permits, two separate groups could each
  sign a different version of history without any single witness contradicting itself. Only
  after-the-fact detection remains. The code provides two distinct checks: one proves *a*
  quorum signed; the other proves the set was a strict majority.
- **Distinct keys are not distinct people.** The trust document states it bluntly: *"If the
  producer P holds all the witness keys, the quorum is theater."* No amount of cryptography
  can establish that witnesses are independently operated. That is a deployment fact an
  assessor must verify by looking at who runs them.
- **The trust document is explicitly marked "DRAFT — design, not a guarantee"**, and says that
  designing a witnessed transparency layer is squarely a "don't roll your own" area where
  external review is warranted before real-world reliance.

**Status:** the witness protocol and a deployable witness service are working. The service
refuses to listen on a public address, caps and times the size of anything submitted to it,
guards against a browser being tricked into submitting on someone's behalf, and rejects an
unsigned or wrongly signed submission at the door so it can never poison the record. A third
party can run one. **Genuine independence of witnesses remains a deployment assumption, not
something the software proves** — and the project's own register lists third-party
independence as an outstanding item.

### Defence four: an external timestamp

The strongest form of "this existed no later than T" does not depend on witness honesty at
all: a trusted timestamping authority signs a fingerprint of the checkpoint.

This is implemented as a real RFC 3161 timestamp — RFC 3161 is the long-standing internet
standard for exactly this service, the digital equivalent of a post office date stamp. It is
produced and checked by handing the work to the standard `openssl` command-line tool rather
than by hand-written code that picks the token apart. The stated reason is "don't roll your own
ASN.1". ASN.1 — short for **Abstract Syntax Notation One** — is the technical rulebook
describing how such a token is laid out as bytes; it is notoriously fiddly, and hand-written
readers for it are a classic source of security bugs. So
the system uses the mature standard tool instead of writing its own. Two design points are
important:

- The claimed time is read **only from the signature-covered part of the token**, never from
  a surrounding text rendering whose unsigned portion a producer could rewrite to back-date,
  and never from the checker's own clock.
- The timestamp is attached alongside the checkpoint rather than inside it, so adding one does
  not change the checkpoint's fingerprint and the record stays byte-for-byte reproducible.

When such an anchor is present and verifies against a pinned authority certificate, its time
**supersedes** the witnesses' median estimate.

**Status, stated by the code:** *"CAPABILITY, not a VERIFIED FACT of independence."* The
mechanism is built and tested, but the default timestamping authority is a self-signed local
one, which proves only that the mechanism works. Genuine independent time requires an
operator-configured third-party authority or a public timestamping calendar.

**A documentation discrepancy an assessor should know about:** the trust-gradient document
still lists a hard external time anchor under "the deferred frontier", while the time-anchor
module implements the mechanism and describes it as built. These two statements are in
tension. The safe reading, and the one consistent with both, is: **the mechanism is built; the
independence it would provide is not established until a third-party authority is
configured.**

### Replaying a single signed permission

Everything above concerns the *record* being rewound. This concerns a *permission* being
resurrected, and it is the more consequential of the two, because it changes what the system is
allowed to do rather than what it has written down. It was closed by a change delivered in this
release.

**How the owner's decisions are stored.** The owner's side does not keep a settings file saying
what is currently switched on. It keeps an append-only record, and each of the owner's decisions
is a signed entry in it. To find out whether the emergency stop is currently tripped, or whether a
particular agent is currently allowed to act without asking, the system reads that record from the
beginning and applies each verified entry in turn. The last valid entry wins. This is the right
design: there is no separate settings file for an attacker to edit, every decision is signed, and
the whole history of who allowed what and when is preserved and tamper-evident.

**Why a genuine signature was not enough.** A signature answers "who wrote this". It does not
answer "when does this count" or "how many times does this count". Consider the sequence a
security officer would expect to be safe:

1. The owner authorises the phone as an approver. That is a genuine, owner-signed entry.
2. Months later, the phone is lost. The owner revokes it. That is another genuine, owner-signed
   entry, and after it the phone approves nothing.

Now suppose someone who can append to that record — not forge a signature, merely add a line —
kept a copy of step 1. They append those exact bytes again, unchanged. Every check the system had
passes. The signature is real, because it *is* the owner's real signature. The record's internal
chain of fingerprints extends cleanly, because a genuine new line has genuinely been added. And
the reading rule says the last valid entry wins — so the phone is authorised again.

Three plausible-sounding fixes do not work, and the source explains each:

- **Refusing a signature seen before** fails, because the signature method used here is
  deterministic. If the owner legitimately grants, revokes, and grants again, the second genuine
  grant produces byte-for-byte the same signature as the first. A duplicate filter would swallow a
  real decision.
- **Using the entry's position in the record** fails, because the position is assigned when the
  line is appended, after signing. A replayed line simply receives a fresh, higher position.
- **Reading a clock inside the checking code** fails for a subtler reason. A timestamp the
  checking module generates itself is a timestamp an attacker replaying that module's own output
  can rely on. The authority over "when" has to sit with whoever holds the owner key.

**What was changed.** Each of these decisions now carries an issue time *inside the signed part*
of the entry — not beside it, where it could be re-stamped without breaking the signature. And the
reading rule now keeps a high-water mark: for each thing being decided about, it remembers the
highest issue time it has ever honoured. An entry counts only if its issue time is strictly higher
than that mark, and honouring one raises the mark past it, so an entry cannot even be replayed
against itself.

The issue time is supplied by whoever holds the owner key, not read by the module. On the command
line, the operator's own terminal stamps it. In the web interface, the *server* stamps it, and the
source says exactly why it is not taken from the browser: a caller-chosen value could be set
absurdly far in the future, which would pin the high-water mark so high that the owner could never
issue a real decision again, or absurdly low, which would render the guard useless.

**Which decisions are covered.** Five kinds of record gained the guard in this change. A sixth —
the sovereign gate the offensive side is designed to pass before it acts — already had it, and was
the pattern the other five were built to match. That sixth carries the same honest note as the host
advertisement above: it is built, tested and guarded, and it has no caller in the shipped commands
or interfaces, so it is a record type the system knows how to write and read safely and does not
write in normal operation. Chapter 14 sets out what the offensive side does pass instead.

| Decision record | What a replay would have resurrected |
|---|---|
| Clearing the emergency stop | A halted system, un-halted |
| Granting an agent permission to act without asking | A withdrawn permission, restored |
| Switching a physical capability on — gesture control, voice control, or the drafting of proposed lessons | A capability the owner had switched off, back on |
| Authorising a device as an approver | A lost, stolen or sold phone, re-armed as a full approver |
| A host advertising what it is capable of | Capabilities a machine had truthfully given up — including the ability to drive keyboard and mouse input, and to stream a camera — reinstated |

The device row is the one to lead with in a briefing. That single list of authorised devices is
what six separate parts of the system consult before accepting an approval — the source names
them: the approval queue itself, the gesture remote-arm path, the desktop bridge, the automated
actor gate, the operator gate, and the outbound-data gate. Reading the tree I found a seventh, the
gate on accepting a proposed lesson into the system's own knowledge. One replayed line would have
re-armed a revoked phone across all of them at once.

**Only the dangerous direction is guarded, and that is deliberate.** Tripping the emergency stop,
withdrawing an agent's permission, switching a capability off, and revoking a device are the
*safe* directions. Those carry a fixed issue time and are subject to no freshness test at all.
Two of them go further and are honoured even without a valid signature — tripping the emergency
stop, and switching a capability off — on the same reasoning: a forged halt is at worst a
nuisance, while a halt that fails to land is a real loss of control. The other two, withdrawing an
agent's permission and revoking a device, do still require the owner's signature; the source notes
that difference rather than treating the four as one rule. The reasoning behind all of this is
worth stating plainly to an official, because it looks
at first like an omission: if a revocation had to be fresher than everything before it, then a
revocation issued from a machine with a lagging clock would be silently ignored — and a security
control that can fail to switch something *off* is far worse than one that can be replayed to
switch something off twice. Replaying a revocation merely revokes an already-revoked thing.
Guarding a fail-safe direction would convert it into a fail-open one.

One row does not follow that pattern, and the source explains why: a host advertising its own
capabilities has no safe direction, because an advertisement is the only kind of entry there is.
So every advertisement is checked for freshness.

Two honest notes on that last row. First, the guard is real code with real tests, but the
advertisement function has **no caller in the shipped commands or interfaces** — the only callers
anywhere in the source are its own tests. So it is a record type the system knows how
to write and how to read safely, and does not currently write in normal operation. Second, the
capabilities it would resurrect are not trivial ones: they include the ability to drive keyboard
and mouse input on a machine, and to stream its camera. Guarding the record before it has a
production writer is the right order to do things in, and it should be described that way rather
than as a defence in daily use.

**Fail-closed against a signed but nonsensical value.** The owner can sign any number, including a
malformed or infinite one. The parser that reads the issue time treats anything unparseable, and
anything not a finite number, as the lowest possible value. The source names the specific danger
this avoids, and it is a good illustration of how a guard can be turned into its opposite: a
"not-a-number" value stored as the high-water mark would make every subsequent comparison against
it false, so *every* later replay would be accepted. An infinite value would do the reverse and
permanently brick the ability to issue a real decision. Both are mapped to the bottom instead, so
such an entry is honoured at most once and then blocks its own replay.

**One detail that shows the guard was checked against the rest of the system.** There is separate,
partly-built work to *prune* the record — archiving old entries away and replacing them with a
folded summary of what they established, so the file does not grow without bound. That summary now
carries the high-water marks. Had it not, the first prune would have reset every mark to zero and
made every archived permission replayable again: the guard would have been silently undone by
unrelated housekeeping. The comment saying so appears at each of the five sites. Worth noting for
accuracy: the pruning machinery is present but the shipped version prunes nothing, so this is a
gap closed before it could open rather than one closed after the fact.

**Status.** Built and covered by its own test suite, which I ran: 67 tests, all passing. The
guard is enforced in the reading path, which is the path every decision goes through, so it is
active for any deployment running this version. What it protects against is an attacker who can
*append* to the owner's record — for instance a compromised component with write access to it —
not one who has the owner's private key. Someone holding the owner key does not need to replay
anything; they can sign a fresh decision.

### Deferred by name

Anchoring a checkpoint fingerprint into the Bitcoin blockchain via OpenTimestamps is designed
but not built; it needs a live external calendar service. Encoding the supply-chain statements
in the full standard binary format is likewise deferred; the current implementation uses the
governance root plus witnesses, which the project describes in-repo as stronger.

---

## 12. Honest status summary

| Capability | Status |
|---|---|
| Ed25519 signing and verification through a standard maintained library | **Fully working.** |
| Rejection of weak and non-standard public keys | **Fully working**, with a documented adversarial-review origin. |
| Purpose labels preventing a signature being reused across contexts | **Working** for twenty-four distinct signing purposes, ten of them held in a shared registry and the rest declared beside the code that uses them (Appendix A lists all of them). Explicitly **not applied** to three surfaces — the offensive engagement record, the usage ledger and the owner-side governance events — which the registry names as the next hardening, plus the evidence-package manifest, which it does not name. On all four, separation rests on the shape of what is signed rather than on a label. |
| Anti-replay guard on the owner's signed decisions | **Working**, delivered in this release. Five kinds of decision record gained an issue time inside the signed part and a per-item high-water mark; a sixth already had one. Only the dangerous direction is guarded, deliberately. Covered by its own test suite, which I ran: 67 tests, all passing. It defends against an attacker who can append to the owner's record, not against one holding the owner's private key. |
| Permission-kernel action log: every tool invocation individually signed and chained | **Working.** Present and populated on the machine this was written on. Its key and log are **now included** in the off-box backup (the key restored owner-only), so the action log is recoverable evidence after a machine loss — a key rotation still leaves old records verifiable only under the old public key. |
| Evidence certificates: authenticity, binding, file integrity, reproduction, claim grounding, known shape | **Fully working.** |
| Chained record with signed head; detection of deletion, reorder, alteration, truncation, suppression, injection | **Fully working as a mechanism.** Not exercised on the owner's own record here: on the machine this was written on the chain links cleanly over sixteen entries, but nothing has signed a head, so on that host growth and truncation are not yet distinguishable. Signing one is a single operator command. |
| Standalone offline checkers with no dependency on this system | **Fully working**, with the honest exception that they cannot re-run the original test. |
| Out-of-band trust-root pinning, refusing a self-supplied trust root | **Fully working**, including a deliberately non-green "unpinned" state in the interface. |
| Owner delegation ceremony tying working keys back to the owner | **Working**, with a human step (authenticating the identity file) that is stated, not hidden. |
| Per-action owner approval: action-bound, key-pinned, time-bounded, single-use | **Fully working.** |
| Several-must-approve gate for irreversible actions | **Built and tested; not yet fired in the field.** Live use awaits operator-provisioned quorum keys and a repository token. |
| Encryption of keys at rest under a hardware-sealed master key | **Built and fail-closed. Not active on the machine this was written on.** The TPM chip is present, but the standard command-line tools that reach it are not installed, so no master key has been provisioned and no sealed store exists. The owner private key on that host is 44 bytes of plaintext behind file permissions only — owner-read-only, in an owner-only directory. This is exactly the posture the code documents as the default before the vault is set up, and it reports the unsealed state rather than hiding it. Nothing here is a defect in the software; it is a one-time operator setup step that has not been performed on this host. **Do not describe at-rest encryption as active in this deployment.** |
| Signed, host-bound, expiring capability grants gating the most dangerous functions | **Working**, and honestly bounded: enforcement switches on once a deployment provisions a trust list of authorised signers. With no trust list provisioned the deployment is "ungoverned" — the baseline runs, gated functions are permitted, and every such grant is logged as a warning. A government deployment should provision the trust list; an assessor should check that it has. |
| Binding a capability grant to particular machines, and optionally to a named operator | **Working.** A gated function is refused when the running machine cannot present an identifier the grant was bound to. The software does not itself measure the hardware: it consumes an attested identity the deployment supplies, and falls back to the machine's installation identifier or, weakest, its hostname. How strong that binding really is depends on which of the three a deployment relies on. |
| Withdrawing a capability grant before it expires | **Working** — a signed revocation list, protected against an older list being replayed over a newer one, and a grant may be issued so that a missing list denies it outright. Two honest limits: the issuing institution must deliver the new list to the deployment (nothing fetches it), and the decision is re-evaluated when the software next starts, not mid-run. |
| Build and release safeguards: exact-version and fingerprint locking of every third-party package, content-pinned base images, a generated parts list checked back against the lock, and a gate that blocks on critical published flaws | **Working and part of the released software**, enforced automatically on every proposed change, with a deliberately planted failing case run first to prove the gate can still refuse. Honestly bounded: it blocks on **critical** findings only. High findings are reported and tracked rather than suppressed — including one in this chapter's own signature library, whose fix **has now been delivered** across every first-party declaration. Two residuals, both stated rather than smoothed over: the vendored copy of the third-party agent still names an older release, and on the machine this was written on the sovereign virtual environment had not yet been rebuilt onto the fixed one. |
| Encrypted, signed, off-machine backup of the owner key and the owner-side record (and now the permission-kernel dir) | **Working**, verified before anything is written on restore. A shipped systemd user timer (`vigil-backup.timer`) now schedules `vigil backup` daily across both planes with retention; the standalone `sigil backup` remains available manually. |
| Key escrow or a vendor-held recovery copy | **Does not exist, by design.** The backup and its passphrase are the only recovery path. |
| Documented replacement procedure for each key | **Supported by the commands described in section 6.4**; the owner key has no rotation command and is replaced by re-issuing every delegation from a new identity. |
| Anti-rollback floor | **Working**, with a clearly stated limit against a same-host attacker holding owner privileges. |
| Witness protocol and deployable witness service | **Working.** Genuine independence of witnesses is a **deployment assumption**, not a proven property. Trust document marked DRAFT. |
| External RFC 3161 time anchor | **Mechanism built and tested.** Independence requires a third-party authority; the shipped default is a local self-signed one. Documentation is inconsistent on this point. |
| Pre-expiry revocation of a delegation | **Does not exist.** Expiry is the only bound, stated in the code. |
| Revocation of a re-verification permission slip already in flight | **Known gap**, stated in the code. |
| Compact single-signature aggregation of a quorum | **Deferred.** Does not change the security property delivered. |
| Blockchain anchoring of checkpoints | **Deferred**; needs a live external service. |
| Scheduled automatic key rotation | **Not found in the code.** Rotation is an operator action. |

---

## 13. What an assessor should ask the operator

These are the questions that the software cannot answer for you, because they are facts about
a deployment rather than about code:

1. **Where is the owner private key, physically, and who can reach that machine?** Everything
   else roots there.
2. **Is a TPM present and set up on the host?** If not, the keys are protected by file
   permissions alone.
3. **Where do you publish the trust-root fingerprint, and how would a recipient know they got
   the real one?** If the answer is "in the package", the pin is decorative.
4. **Do you keep the historical fingerprints published after you rotate a key?** If not, an
   older evidence package will look unverifiable to a recipient who checks it later (6.1).
5. **When did you last take the encrypted off-box backup, where is that file, and who holds
   the passphrase?** There is no escrow: that file and that passphrase are the whole recovery
   plan. Ask to see evidence of a test restore, not just of a backup.
6. **What is your written procedure if the owner key or the machine is lost?** The honest
   answer, if there is no backup, is that there is no recovery — and the delegation windows
   should be sized accordingly.
7. **What is the threshold for irreversible actions, and who holds the other keys?** A
   threshold of one is a solo owner, however impressive the mechanism sounds.
8. **Who operates the witnesses?** If the answer is "we do", the witness quorum proves
   continuity but not independence, and the documentation says so.
9. **How short are the delegation windows?** Since there is no pre-expiry revocation, the
   window length *is* the exposure if a working key is lost.
10. **Is a third-party timestamping authority configured?** If not, time bounds rest on witness
    honesty.
11. **Is a capability-grant trust list installed on this deployment, how many authorisers must
    sign, and where do their keys live?** Without a trust list the deployment runs "ungoverned"
    and the gated functions are permitted rather than blocked. If the authoriser keys sit on the
    same machine that runs the software, the separation the scheme is built for does not exist.
12. **If someone deleted that trust list tonight, would this deployment notice?** A missing list
    reads as "not a governed deployment" unless the enforcement setting has been explicitly
    pinned on. Ask whether it has been, and ask to see the deployment's own status command
    reporting the governed state.
13. **Which machine identity are your capability grants bound to?** An identity produced by a
    real attestation service is a strong binding. A hostname is a label anyone can set.
14. **How would you withdraw a grant in a hurry, and how quickly would it bite?** The withdrawal
    list has to be delivered to the deployment, and it is honoured the next time the software
    starts. For an immediate stop, the instrument is the emergency stop of section 7 — ask who
    can trip it and how they would.
15. **Ask separately about the build.** Which version of the signature library is installed
    here; does your build refuse a change that carries a critical published flaw; and can you
    show a run where that gate actually refused something? A gate that has never refused
    anything and a gate that cannot refuse anything look identical from the outside. Ask for the
    *installed* version on this host, not the version named in a requirements file — the two can
    differ on a machine that has not been rebuilt, and on the machine this chapter was written on
    they did.
16. **Who or what can append to the owner's record, other than the owner?** The replay guard of
    section 11 exists because appending is a weaker capability than signing, and a genuine
    signature does not on its own establish that an entry still counts. Ask which components hold
    write access to that record, and treat each of them as part of the trusted base.
17. **Are the clocks on the machines that issue owner decisions correct and monotonic?** The
    freshness value that makes the replay guard work is supplied by whoever holds the owner key,
    from that machine's clock. A clock that jumps backwards on the issuing machine will cause a
    legitimate later decision to be refused as stale until the clock catches up. This is a
    fail-safe direction — a refusal, not a false approval — but an operator should know it can
    happen, and should not be surprised into thinking the system is broken.
18. **Is your permission-kernel action log part of your backup and retention plan?** It is
    individually signed and chained, and it is the record of every tool invocation. It **is now**
    included in the encrypted off-box backup (its key restored owner-only), so a machine loss no
    longer costs it — confirm the daily backup timer is enabled and that you have tested a restore.
19. **Where does the evidence for a completed engagement live once the engagement is over?** The
    off-box backup covers the owner's side. Finished evidence packages are ordinary files and are
    the operator's to archive, the way any other case record would be. Ask to see where they go
    and how long they are kept.

---

## Appendix A. The exact purpose labels

Section 2 explains why every signature carries a short fixed label naming what it is for, so
that a signature made for one purpose can never be accepted as another. A general reader does
not need these tables. They are here so that an assessor can check the claims in section 2
against the code, exhaustively rather than against a sample. Every label below was read out of
the source; none is inferred from documentation.

### A.1 The ten held in the shared registry

These are the labels that cross the boundary between the two halves of the system, and are
therefore kept in one place so the two halves cannot drift into two spellings of one purpose.

| Purpose label in the code | What it seals |
|---|---|
| `crucible-evidence-v1` | Evidence certificates and signed chain heads |
| `sigil-floor-v1` | The owner-side anti-rollback floor |
| `sigil-witness-roster-v1` | The list of accepted witnesses |
| `vigil-delegation-v1` | An owner delegation to a working key |
| `vigil-transparency-checkpoint-v1` | A witness counter-signature on a checkpoint |
| `vigil-destruction-authorization-v1` | A multi-party authorisation of an irreversible act |
| `vigil-identity-attestation-v1` | The owner's statement of what the real target is |
| `vigil-capability-v1` | A re-verification permission slip |
| `vigil-capability-attenuation-v1` | A narrowing of an existing permission slip |
| `vigil-capability-wielder-pop-v1` | Proof that the holder of a permission slip really is its holder |

### A.2 The fourteen declared beside the code that uses them

Each of these is declared next to its own use, and each carries a comment naming what it must
not be confusable with.

| Purpose label in the code | What it seals |
|---|---|
| `crucible-authority-v1` | The signed engagement authority — scope, dates, budget, whether destructive actions are permitted |
| `crucible-entitlement-v1` | A capability grant: which of the dangerous functions an institution may run, on which machines, until when |
| `crucible-revocation-v1` | The signed list of capability grants that have been withdrawn |
| `crucible-proposal-v1` | An approval of a proposed change to the system's own code, signed over the proposal's content |
| `vigil-peraction-approval-v1` | The owner's permission for one specific queued action |
| `vigil-oob-receipt-v1` | A receipt for a connection the target made to a listener the system controls |
| `vigil-zktls-channel-binding-v1` | A notary's co-signature tying captured bytes to one encrypted session |
| `vigil-authority-envelope-v1` | The statement that the automated operator stayed inside its bounds |
| `vigil-remediation-cert-v2` | The certificate that a proven weakness is now fixed |
| `vigil-remediation-prove-cert-v1` | One re-proof that the fix still holds |
| `vigil-remediation-freshness-challenge-v1` | The challenge that stops an old re-proof being passed off as recent |
| `vigil-attestation-witness-time-v1` | A witness counter-signature that also commits to the time it observed the summary — deliberately distinct from the plain counter-signature above, so a timeless one can never be presented as a timed one |
| `vigil-witness-producer-submit-v1` | The producer's own signature on a request asking a witness to counter-sign |
| `vigil-remediation-v1` | The fix oracle's signed statement that the original test stayed silent against the patched build |

### A.3 Two further labels that separate fingerprints rather than signatures

These are not signing labels. They are mixed into a fingerprint so that the result is not a bare
hash of a secret — a bare hash of a low-entropy secret could be confirmed by guessing — and so
that fingerprints belonging to two different capabilities can never collide even for identical
input.

| Label in the code | What it separates |
|---|---|
| `vigil.e1.imds.credential-fingerprint.v1` | The fingerprint binding a captured cloud instance credential to the call that proved it usable |
| `vigil.e5.secret.credential-fingerprint.v1` | The fingerprint binding a captured exposed secret to the call that proved it valid |

### A.4 The at-rest sealing labels

Section 4 explains that each stored secret is bound to a label naming which secret it is, so a
blob sealed as one thing cannot be opened as another. All sealing shares one outer domain,
`vigil-core/sealing/v1`, with these nine per-item labels folded in beneath it.

| Label in the code | What it binds |
|---|---|
| `sigil/owner.priv` | The owner private key |
| `sigil/spine.dek` | The key that encrypts the owner-side record |
| `sigil/spine-field/v1` | Individual fields inside that record |
| `sigil/secrets.kv` | Service credentials, such as an API key |
| `sigil/backup/v1` | The encrypted off-machine backup |
| `vigil/offense-spine.key` | The offensive engagement-record key |
| `vigil/offense-governance.key` | The offensive governance key |
| `vigil/operator.key` | The operator key behind the usage ledger |
| `vigil-reprove-self-witness-v1` | The self-witness key for the continuous re-checking log |

### A.5 What carries no label

For completeness, the four signing surfaces that carry no purpose label, restating section 2:
the offensive engagement record, the usage ledger, the owner-side governance events, and the
manifest inside a downloadable evidence package. The first three are named as a gap by the
registry itself, which calls closing them "the natural next hardening". The fourth I found by
reading the code and did not find named anywhere as a gap. On all four, what keeps signatures
apart is the shape of what is signed — a fixed-length fingerprint string, or a structured object
of a particular form — rather than an explicit label.
