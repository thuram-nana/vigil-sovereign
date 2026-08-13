# Evidence: How It Is Collected, Shown, And Independently Re-Checked

## The problem this chapter solves

Almost every security testing tool in existence works the same way: it looks at a
system, and then it *tells you* what it thinks. The output is a list of assertions.
"This login page is vulnerable to SQL injection." "This server is misconfigured."
"This application is clean."

You are then asked to believe it.

That is a problem for a buyer, and it is a much bigger problem for a regulator, an
auditor, a court, or a national agency. When a report says "we found a critical
weakness", the only way to check it is to hire someone else to repeat the whole
investigation. When a report says "we found nothing", there is usually no way to check
it at all — because "nothing" leaves no trace.

The system described in this document is built on a different premise:

> A result should be a **portable object whose truth a third party can re-derive for
> themselves** — not an assertion you have to trust.

This chapter explains, in ordinary language, how that works in practice. It covers:

1. What "evidence" actually means here, and how it is captured and stored.
2. How evidence is sealed so that tampering is detectable.
3. What a **finding report** contains for a human reader.
4. What an **evidence certificate** is, and the four independent things it proves.
5. How a completely independent third party — with no access to this system, no
   internet connection, and no reason to trust the operator — can confirm a result on
   their own computer.
6. Exactly what happens if anyone changes a single byte of the evidence.
7. What a **clean result** ("we found no exploitable weakness") means here, why it is
   far harder to produce than finding a problem, and how the system avoids the
   temptation to fake it.
8. The one weakness in this whole design that the system cannot close by itself — the
   fact that the evidence was collected by the party making the claim — and the
   countermeasure that has been built for it.
9. How evidence is looked after over time: how much disk it takes, how long it is kept,
   how it is destroyed, and how it is backed up and restored without breaking any of the
   guarantees above.
10. What is fully working today, and what is built but has not yet been exercised
    against live third-party systems.
11. The safeguards applied to the system's **own** build and release, so that what it is
    assembled from can be shown to be what was chosen.

Everything stated below was read directly from the source code and the project's own
documents. Where a capability is real but has not yet been fired at a live external
system, this chapter says so plainly. That honesty is not a caveat bolted on at the
end. It is the product.

**A note on two words used throughout.** *Deterministic* means the system behaves like a
recipe rather than a chef: follow it twice with the same ingredients and you get exactly
the same dish, with no judgement, no mood, and no improvisation. *Fail-closed* means the
answer is "no" whenever a check cannot be completed — like a drawbridge held up by
electricity, which falls shut when the power is cut rather than staying open. Both ideas
appear on almost every page below.

---

## 1. What counts as evidence

### 1.1 Evidence is the raw traffic, not the conclusion

When the system tests a web application, it sends a request and receives a response.
Those two things — the exact bytes sent, and the exact bytes received — are the
evidence. Not a summary of them. Not a description of them. The bytes themselves.

For each individual action the system takes, it writes three files into a dedicated
folder for that action:

| File | Plain meaning |
|---|---|
| `request.http` | The exact request that was sent: method, address, and headers. |
| `response.http` | The exact response line and headers that came back. |
| `response.body` | The full raw body of the response, byte for byte, untouched. |

These live under a per-engagement folder, one sub-folder per action, at
`targets/<engagement>/evidence/<action-id>/`. In the code's own words, "those bytes are
the ground truth a finding rests on."

For tests that are not web requests — a network handshake, a certificate inspection, a
configuration file exported from a cloud account, a Kubernetes manifest — the evidence
is the equivalent raw artifact: the handshake record, the parsed certificate, the
exported document. The principle does not change. The evidence is the thing that was
actually observed, retained in full.

### 1.2 The "retained evidence" that the automatic test judged

Alongside the raw files, the system retains a second, structured object. The code calls
it the **oracle context**. In plain terms it is *the exact set of inputs that the
automatic pass/fail test looked at when it made its decision*.

An analogy: a laboratory tests a blood sample and reports a result. The raw files above
are the sample. The retained evidence is the specific measurements the laboratory's
instrument read off that sample and fed into its decision rule. Keeping both means a
second laboratory can re-read the instrument output *and* re-examine the original
sample.

This matters because of how the decision is made, which is the subject of the next
point.

### 1.3 The automatic test is a pure calculation, and that is what makes re-checking possible

The system's decision-makers are called **oracles**. The word is the project's own; it
simply means a small, fixed, automatic test that looks at retained evidence and answers
one question: did this specific dangerous condition occur, yes or no?

Each of these tests obeys a strict contract, stated in the code and enforced by its
design:

- It is **pure**: given the same evidence it always produces the same answer.
- It performs **no network activity**. It never sends traffic. It only judges evidence
  somebody else already collected.
- It reads **no clock** and uses **no randomness**.
- It works entirely **offline**.
- A missing input produces a **skip**, never an assumed pass.

This is the single most important engineering decision in the whole system. Because the
decision procedure is a pure calculation over retained inputs, *anyone* who has the
inputs and the calculation can re-run it and must get the same answer. That is what
turns a claim into a proof. It is a recipe, not a chef.

In the version of the software read for this briefing, the system has **38 distinct
kinds of automatic test** and a vocabulary of **85 named weakness classes**, each mapped
to the specific tests that are allowed to confirm it.[^rev]

[^rev]: Software is identified by a short code for the exact snapshot of the source it was
built from. Sections 1 to 11 were read at snapshot `1487e03a`. Section 12 describes work
that reached the released software while this chapter was being written, and was read at
snapshots `dc2994d6` and `ff790b80`. They are recorded so that a reader can re-derive
every count in this chapter from exactly the same source the author used.

**One term used constantly below: an "evidence branch".** The project's own word for a
single, named route by which a particular kind of claim is allowed to be proved — in
plainer words, *the specific window through which one kind of problem may be observed*.
"The redirect-header branch" means: this claim may only be established by reading the
redirect address in a response header, and by nothing else. Twenty-six such windows are
registered, and section 9.3 lists which of them are allowed to produce a clean result.

### 1.4 The four words the system is allowed to say

The system's output vocabulary is deliberately tiny and closed. Only four verdicts
exist, and they are enforced by the programming language's type system, not by
convention:

| Verdict | Plain meaning |
|---|---|
| **FACT** | We established this. An automatic test re-derived it from evidence this system captured itself, and the certificate re-checks offline. |
| **LEAD** | Something suggests this, but we did not prove it. Any weaker signal belongs here — another tool's opinion, a rule of thumb, an AI model's suggestion. |
| **CLEAN** | We conclusively ruled this out, for this target, these inputs, and this observation window. |
| **INCONCLUSIVE** | We could not tell. This is a first-class answer, never rounded toward "clean". |

Both FACT and CLEAN are explicitly *bounded observations about a moment in time*, not
timeless properties of the system under test. The right mental image is a vehicle
roadworthiness certificate: it says the vehicle passed a named set of checks on a stated
date. It does not say the vehicle is safe forever, and it says nothing about the checks
that were not on the list.

---

## 2. Collection and storage: the sealed evidence bag

### 2.1 The analogy, and where it is accurate

Physical forensic practice uses a sealed evidence bag. An item is placed in the bag, the
bag is sealed, the seal is labelled, and every subsequent handover is recorded. If the
seal is broken, everyone knows. The bag does not prevent tampering; it makes tampering
*visible*.

That is precisely the model here, with one significant upgrade. A physical seal proves
the bag was not opened. A cryptographic seal proves something stronger: it proves the
*contents* were not altered, even by someone who could open the bag, and it can be
checked by anyone, anywhere, at any later time, without the original sealer being
present.

The upgrade matters, because the party a regulator most needs protection from is not a
stranger — it is the party who produced the evidence in the first place.

### 2.2 The evidence is written owner-only

Captured traffic can contain login cookies, authorisation headers, session tokens, and
real response bodies. On a shared machine, a world-readable copy of that is a credential
leak that outlives the engagement.

The system therefore:

- Sets a restrictive file-creation policy at start-up, so that every file the process (or
  any program it starts) creates can be read and written **only by the account that ran
  it**, and every folder it creates can be opened only by that same account. Other users
  of the same computer — including other people's programs — get nothing.
- Additionally applies those same restrictions explicitly at the sensitive stores, as a
  second layer.
- Only ever *tightens*: if the surrounding environment is already stricter, the stricter
  setting is kept.
- Never treats this as fatal. On a filesystem that cannot express these permissions (a
  Windows or network mount), the write still happens; the system does not refuse to
  work.

There is also an **ephemeral mode**. When it is active, the captured traffic is
re-rooted onto temporary in-memory storage, so that captured requests and responses —
which may carry authorisation headers and bodies — never touch the real disk at all.

### 2.3 Credentials are masked before the evidence is written; the proof is not

There is a genuine tension here. Masking too much destroys the evidence. Masking too
little leaks secrets. The system resolves it with a deliberate, narrow rule.

Every web request carries a set of short labelled lines at the top, called *headers*,
before the main content. Some of those lines carry the caller's identity — the equivalent
of the pass you show at a door. Before the human-readable request and response files are
written to disk, the system blanks out the *contents* of exactly twelve of those lines
and replaces them with a fixed placeholder, leaving the label and the surrounding shape
intact, so a reader can still see that a credential was present without seeing what it
was.

The twelve are the standard ways a caller proves who it is: the general-purpose
authorisation line and its proxy equivalent; browser session cookies, in both directions;
application keys under their four common names; the two names used for the token that
protects a form against forgery by another website; the temporary security token used by
Amazon Web Services; and the key used by this system's own out-of-band relay. A technical
reader will recognise them as `authorization`, `proxy-authorization`, `cookie`,
`set-cookie`, `x-api-key`, `api-key`, `x-auth-token`, `x-session-token`, `x-csrf-token`,
`x-xsrf-token`, `x-amz-security-token` and `x-relay-key`; a general reader does not need
to recognise any of them, only the shape of the rule.

Three properties of that rule are worth stating explicitly:

- **It masks by name, never by guesswork.** The system does not scan free text looking
  for things that "look like a token". As the code puts it, over-masking a response body,
  or a *payload* that came back reflected in the page, "would destroy the very proof a
  finding rests on". (A **payload** is simply the test input the system deliberately sends
  — the equivalent of the probe a locksmith pushes into a lock to see how it responds. Much
  of the proof of a weakness consists of seeing exactly where that probe reappeared.)
- **The raw response body is never touched.** It is protected by the owner-only file
  permissions instead. This is deliberate: the body is frequently the evidence.
- **The masking is deterministic.** The same input always produces the same output, with
  no clock and no randomness involved. This matters because the file fingerprints described in
  the next section are computed *after* masking. If masking were unpredictable, the
  seals would not be stable.

The rule's summary line in the code is a good one-sentence statement of the policy: it
masks *the credential that authenticated the request*, not *the vulnerability evidence
that request produced*.

### 2.4 Live secrets never enter a certificate

For the cloud and credential-related capabilities, the discipline goes further. A
captured credential is validated and fingerprinted **in memory** and then discarded. What
is retained is a masked structural record, a one-way fingerprint, and non-secret
*provenance* — the record of where a thing came from: which addresses answered, whether the
connection was properly encrypted, and whether any redirection or intermediary was
involved. No live secret is written into a capture or a
certificate. The certificate still re-verifies offline; it simply does so without ever
carrying the secret itself.

---

## 3. Sealing: fingerprints, certificates, and the chain

### 3.1 The seal on each item: a content fingerprint

**One word, used the same way for the rest of this chapter.** Every raw evidence file is
**fingerprinted**. A fingerprint is a short, fixed-length code computed from the whole
content of a file. Change one byte anywhere in the file and the code changes completely
and unpredictably. It cannot be worked backwards to recover the file, and it cannot
practically be forged — nobody can craft a different file that produces the same code.

Software people call the same thing a *hash* or a *digest*, and the particular published
method used throughout this system is named `sha256`. Those words all name one object.
This chapter says **fingerprint** every time, and shows the other words only where they
appear inside a file name or a command that a reader would have to type.

The useful image is the tamper-evident seal on a medicine bottle, with one improvement:
this seal is computed *from the contents*. You do not have to trust that it was applied
honestly, because you can recompute it yourself from the bottle in front of you and see
whether it matches.

The system records, for each raw file, its relative path and its fingerprint. That list
is called the **artifact manifest**. Files are listed in sorted order so that the
manifest is stable and reproducible. On verification, each file is fingerprinted again
and any file that was altered, truncated, or removed is flagged.

Two hardening details are worth noting for a security-literate reader: verification
opens each file in a way that refuses to follow a symbolic link substituted at the last
moment, refuses anything that is not an ordinary file, and caps how many bytes it will
read (256 MB) so that a hostile package cannot force unbounded work.

### 3.2 The seal on the whole result: the evidence certificate

The **evidence certificate** is the central object of the entire system. It is one
signed, self-contained statement about one confirmed finding.

A useful analogy is a laboratory report that has been countersigned by the laboratory's
director. But it is a better report than most, because it does not merely state a
conclusion; it carries, bound into the same signature:

| What the certificate carries | Plain meaning |
|---|---|
| Which engagement, and a sequence number | Where this result sits in the ordered record of the engagement. |
| The finding reference | Which specific finding this is about. |
| The weakness class | What kind of problem is being claimed (for example "SQL injection"). |
| The surface | Which part of the system — which address, which input field. |
| Which automatic test fired | The named decision procedure that produced the verdict. |
| The confidence | A number, never 1.0 — see below. |
| The fingerprint of the retained evidence | A fingerprint of the exact inputs the test judged. |
| The artifact manifest | Every raw file, with its own fingerprint. |
| The version of the automatic test | A fingerprint of the test's own decision procedure at the moment the certificate was issued. |
| A "how to verify" note | A plain-language, per-finding instruction for re-checking it. |
| The producing tool's version | When an external tool proposed the finding. Honestly labelled as the tool's *asserted* version string, not a proof of which program actually ran. |
| A declared validity window | An optional freshness policy in seconds. Zero means no declared expiry. |
| Artifact identity and scope | For results derived from an exported document: which document, what scope it covered, when it was captured, by which collector, and whether the capture was complete. |

Two design points deserve emphasis.

**Confidence is never certainty.** Inside an automatic test, confidence is combined
across corroborating signals and then clamped to a maximum of **0.99**. The code's own
comment is the right summary: "a deterministic oracle never claims certainty it cannot
have." A finding is only treated as confirmed when a test fires at **0.70 or above**.
Separately, the report layer's calibrated probability — learned from measured outcomes,
not hardcoded — is capped at **0.999** for the same reason.

**The certificate carries no clock.** There is no timestamp inside the signed bytes. This
is deliberate: it means two runs over identical evidence produce byte-identical
certificates, which is what makes independent reproduction possible. Time-related
information (an external timestamp, witness countersignatures) is carried *alongside* the
certificate, never inside its signed core.

### 3.3 The signature: who stands behind the certificate

A digital signature is the modern equivalent of a wax seal pressed with a signet ring.
Anyone can look at the seal and confirm which ring made it; nobody can make that seal
without the ring. Unlike wax, a digital seal also covers the *words* — alter one letter of
the document and the seal no longer matches.

The certificate is signed using Ed25519, a standard, widely reviewed digital signature
scheme, through the well-established `cryptography` library. The project states plainly
that it does not write its own cryptography.

The signature is a **threshold signature**: it requires *m of n* named authorisers. The
operator decides how many key-holders must agree before a certificate is considered
authentic.

Three further properties:

- **Signing is a provisioning-only activity.** The running system only ever *verifies*.
  The keys that sign are handled separately, offline.
- **Signed bytes are domain-separated.** Each kind of signed object is tagged with a
  distinct prefix (for example `crucible-evidence-v1`). This means a signature over one
  kind of object can never be lifted and replayed as a signature over a different kind.
- **Weak and malformed public keys are rejected.** There is a family of mathematically
  degenerate values that look like signature-checking keys but are not real ones; the worst
  of them make a single fixed signature appear valid against *any* message at all. The key
  loader refuses them, along with keys written in a non-standard form. That closes a known
  forgery technique, and the fix came out of a deliberately adversarial internal review
  that went four levels deep.

### 3.4 The chain: you cannot quietly delete a finding

An individual sealed certificate proves that *that* finding was not altered. It does not,
by itself, prove that no finding was removed from the report.

The system solves this with a **hash chain** — the industry's name for a chain of
fingerprints in which each link covers the link before it. Think of a bound ledger in which every page
is numbered and each page begins by quoting the previous page's serial number. You cannot
tear out page four without page five saying so, and you cannot slip a new page in without
breaking the numbering. Each entry here records its position, the fingerprint of the
previous entry, and the fingerprint of its certificate — and then fingerprints all three
together. Each link therefore depends on every link before it.

The practical consequence, in plain terms:

- **Delete a finding** and the following link's "previous" fingerprint no longer matches.
  The verifier reports a chain break at that position and names it: *entry deleted or
  reordered*.
- **Alter a finding** and its own entry fingerprint no longer matches. The verifier
  reports: *entry tampered*.
- **Insert a finding** and the sequence numbers no longer run consecutively. The verifier
  reports a sequence gap.

The whole chain is then anchored by a **signed head** — one signed statement covering the
end of the chain and its length.

### 3.5 Anti-rollback: you cannot substitute an older, genuinely-signed report

A subtler attack: hand over a real, correctly signed report from last month, one that
happens not to contain the finding you would rather not discuss.

The verifier can keep a small durable file recording the largest report it has ever seen
— the number of entries and the last sequence number. A later report that is smaller is
refused. The entry *count* is the primary guard, because the sequence number reads zero
for both an empty chain and a one-record chain, so a one-to-zero truncation would slip
past a sequence-only check. A file that exists but is malformed causes a refusal rather
than being silently read as "no floor", because reading it as absent would fail open and
defeat the whole guarantee.

**This guarantee is stated with its honest limit, in the code itself.** The high-water
file is a local, unsigned, owner-only file. An attacker who already has the owner's
account (or root) on the same machine can rewrite the log *and* the floor together and
defeat the local check. What it does guarantee unconditionally is that the recorded figure
only ever goes up, never down; that an attempt to lower it is refused rather than accepted;
that the update survives a crash or a power cut without being left half-written; and that
two programs updating it at the same time cannot corrupt each other. It genuinely protects
against (a) an attacker who can overwrite the log but not the floor, and (b) any outside
verifier who kept a newer floor of their own. A fully dishonest producer who rewrites
everything is closed only by an outside witness — described in section 7.5 — and the
project says so rather than pretending otherwise.

---

## 4. The four independent checks a certificate must pass

When a certificate is verified, four separate things are checked. **A certificate is
sound only if all four hold.**

| # | Check | What it rules out |
|---|---|---|
| 1 | **Authenticity** | The threshold signature validates against the operator's governance keys. Rules out: a certificate somebody else wrote. |
| 2 | **Binding** | The certificate's recorded fingerprint matches the fingerprint of the retained evidence actually presented. Rules out: taking a genuine signature and attaching it to different evidence. |
| 3 | **Artifact integrity** | Every raw file in the manifest still produces its recorded fingerprint. Rules out: editing the captured traffic after the fact. |
| 4 | **Reproduction** | The automatic test is re-run over the retained evidence and produces the same verdict. Rules out: a signed statement that simply is not true. |

Check 4 is the one that distinguishes this system from ordinary signed reporting. Most
signed security reports prove *who said it*. This proves *that it is so*, by redoing the
determination.

The difference is the difference between a police officer's written opinion that a driver
seemed drunk and a breathalyser reading with the instrument's calibration record attached.
The first asks you to trust a person. The second can be re-examined by anyone, including
someone who thinks the officer was lying.

### 4.1 Reproduction in detail, and the two things it refuses

The re-verification step reconstructs the retained evidence, re-runs the same pure test,
and confirms that:

- the verdict reproduces, and
- it matches the claimed test and the claimed confidence, to within one part in a million.

A mismatch is annotated in the output as "DIFFERS from the claimed certificate
(tampered?)".

There is a second, less obvious refusal that is load-bearing. **The retained evidence
adjudicates its own weakness class.** If someone takes a genuine proof of one problem and
relabels the finding as a different, more alarming problem — presenting evidence of a
database injection as evidence of full remote code execution — the re-execution boundary
refuses. The proof cannot re-confirm as the relabelled class.

The operator-facing command is:

```
python3 -m framework.v2 verify <report.json>
```

It exits with status 0 if and only if every certificate reproduces *and* matches its
claim, and 2 otherwise. That makes it usable as an automated gate in a build pipeline.

### 4.2 Detecting a changed test procedure

There is one more way a signed proof could go stale without anyone tampering with it: the
automatic test itself could be edited after the certificate was issued.

The system stamps into the signed certificate a **version fingerprint of the test's own
decision procedure**. This is not merely a fingerprint of the entry function. It is a fingerprint computed over
the test's own source text in a fixed normalised form, *plus every helper function and
fixed value its decision procedure reaches* — an address list, a pattern, a marker string.
In the code's words, "the entry function alone no longer hides a changed procedure."

A verifier compares that stamp against the current value. A mismatch is treated
**fail-closed** — refused, not warned about. And if the source is unavailable at all (a
frozen deployment), the version reads as empty and the verifier **reports that it cannot
confirm, rather than guessing**.

### 4.3 The proof-carrying finding: five ordered checks

The portable, published form of a single finding is called a **Proof-Carrying Finding**.
Verifying one runs five ordered, fail-closed steps, each delegating to a real primitive
rather than a re-implementation:

1. **Vocabulary.** The claimed weakness class must be one of the known classes. An
   invented class is rejected at step 1.
2. **Signature.** The threshold signature over the domain-separated bytes must validate —
   plus a *view-consistency* check, so that a wrapper cannot present a misleading summary
   of the certificate it encloses. The code calls this defeating "a lying wrapper".
3. **Evidence fingerprint integrity.** The evidence presented still matches the fingerprint recorded
   inside the signature.
4. **Reproduction**, plus the test-version staleness check above.
5. **Claim-grounding.** The test that fired must be a valid confirmer *for the class being
   claimed*. This is the step that defeats relabelling.

---

## 5. What a finding report contains for a human reader

Sealed proofs are for machines and auditors. People still have to read something.

### 5.1 Every finding is re-tested at the moment the report is written

This is a small design decision with large consequences. A finding is **not** trusted
because it was once recorded as confirmed. When a report is generated, each finding's
retained evidence is re-run through the same authority, right then, and graded into one
of three states:

| Grade | Plain meaning | How it is presented |
|---|---|---|
| **Fact** | The finding's own automatic test re-fired now. | Presented as proven, with its re-runnable certificate reference. |
| **Demoted** | It was recorded as confirmed, but the retained proof no longer reproduces — altered evidence, a relabelled class, or a stub. | Presented as a **lead**. Never as a fact. |
| **Lead** | There was never a deterministic signal — for instance an AI model's suggestion. | Presented as a lead to verify. |

The "demoted" grade exists so the reader knows the difference between "this was never
proven" and "this *claimed* a proof that no longer holds". Both are treated as unproven;
only the label differs.

Crucially, the fields that make a finding look authoritative — which test fired, the
confidence, the certificate reference — are populated **only** for a fact. For a lead they
are empty, so that no rendering step can accidentally dress an unproven lead in a proven
finding's clothing.

### 5.2 The three human documents

| Document | Audience | Contents |
|---|---|---|
| **Executive summary** | Business owners, decision-makers, non-technical reviewers | Leads with plain-language impact. "What we found" lists only proven facts as confirmed. Leads live in their own clearly labelled section and are never stated as things an attacker *can* do. |
| **Technical report** | The engineering team that has to fix it | Per finding: a summary and reproduction, the remediation guidance, and a verification block that either shows the deterministic proof (which test fired, the calibrated confidence, and the re-runnable certificate fingerprint) or plainly labels the finding a lead. |
| **Remediation roadmap** | A technical lead or project planner | Findings ordered by impact against effort, over **proven findings only**. Leads are listed separately and are never inserted into the fix order. |

All three are **deterministic**: no clock, no randomness. Given the same findings, they
render byte-for-byte identically every time. A timestamp is the single source of
variation and is opt-in — the operator has to ask for one.

### 5.3 The per-finding "how to verify and fix this" block

Each finding carries its own instruction block, generated from the finding itself rather
than from a class-level template.

- For a **fact**, it names the test that fired and its reasoning, and points at the real
  re-executable proof with the actual command. It also warns honestly about a specific
  and confusing case: running the verifier over a *rendered* report rather than the raw
  retained material can show a difference caused by confidence calibration, and that
  difference is **expected, not tampering**.
- For a **lead**, it explains how to *confirm* the lead and never implies the finding is
  proven, because a lead carries no certificate to re-check.

The code notes explicitly that neither version of the text invents a command-line option or a
capability the tool does not have.

### 5.4 Standards and compliance mapping, with a hard honesty rule

Organisations are held to published control frameworks — the lists of things an auditor,
a regulator, or a card-payment scheme requires them to have in place. Each finding's
weakness class is mapped to the frameworks it implicates, so that a finding can be
answered in the language the organisation is already audited against.

| Framework | What it is, in plain words | Version mapped |
|---|---|---|
| **OWASP Top 10** | The Open Worldwide Application Security Project is a non-profit that publishes, every few years, a consensus list of the ten most serious categories of web-application weakness. It is the most widely quoted starting list in the industry. | 2021 edition |
| **CWE** | The Common Weakness Enumeration is a public catalogue, run by the US non-profit MITRE, that gives every known *kind* of software flaw a permanent number — so two vendors describing the same flaw can be shown to mean the same thing. | Version 4.x identifiers |
| **PCI DSS** | The Payment Card Industry Data Security Standard: the rules the card schemes require of any organisation that stores or handles card payments. Failing it has direct commercial consequences. | Version 4.0 |
| **SOC 2** | A widely used assurance report defined by the American Institute of Certified Public Accountants, in which an external auditor tests an organisation against five "Trust Services Criteria" — security, availability, processing integrity, confidentiality and privacy. Customers routinely demand one before buying. | 2017 criteria, 2022 revision |
| **ISO/IEC 27001 Annex A** | The international standard for information-security management, published jointly by the International Organization for Standardization and the International Electrotechnical Commission. Annex A is its checklist of specific controls an organisation must consider. | 2022 edition |
| **MITRE ATT&CK** | A public, structured catalogue — again from MITRE — of the actual techniques real attackers have been observed using, each with an identifier. It lets a defender describe an incident in the same vocabulary the rest of the industry uses. | Version 15, Enterprise. Weaknesses in artificial-intelligence and language-model features map instead to MITRE ATLAS, the equivalent catalogue for attacks on AI systems. |

The honesty rule here is structural, not editorial. A mapping is *data* — the controls a
weakness of that class *would* implicate. It becomes an **assertion of coverage** only for
a finding the automatic test actually proved. A lead, or a demoted finding, is capped at
an advisory note with no controls asserted. A record that merely *claims* to have been
oracle-verified is not trusted; the test has to re-fire.

The coverage matrix that summarises this distinguishes three states that are commonly and
dangerously blurred together: tested-and-proven, tested-with-no-finding, and **not
tested**. A control is only ever marked as tested-and-clear when its class is explicitly
in the set of classes that were actually tested.

### 5.5 What the operator sees on screen

The operator-facing interface presents the same graded material, with the honesty rules
visible rather than buried. The relevant screens:

- **Findings.** Five views: the findings table, an attack graph, an evidence view, a
  coverage view, and an investigation replay. Opening a finding shows its verdict,
  severity, class, surface, which test fired, the confidence, its CVSS score and vector
  (the Common Vulnerability Scoring System — the industry-standard way of scoring how
  serious a weakness is, giving both a number out of ten and a short coded string showing
  how that number was arrived at), whether a re-runnable certificate exists, the impact, the test's
  reasoning, a "how to verify and test" section, the remediation, references, and a
  button to re-verify the whole run offline. A lead carries an explicit note: "A LEAD is
  a proposal. It becomes a FACT only when a deterministic oracle re-executes and confirms
  it."
- **Evidence.** One card per certificate with a four-state badge — **Sound**, **Tampered**,
  **Claim mismatch**, or **No certificate** — each accompanied by an explicit sentence
  saying *why*. One of the summary tiles reads "Traffic sent = 0, pure re-run", because
  this view sends nothing to the system under test.
- **Client Report.** Described in the interface as "A LIVE, always-current report: every
  finding is re-verified OFFLINE on load, so a FACT is a re-checkable certificate — not a
  stale PDF, and not the AI's word." One button downloads the complete dossier.
- **Proof Studio.** Exports a client-verifiable bundle. On success it displays the bundle
  location, the trust-root fingerprint with the instruction to publish it through a
  separate channel, and the exact command a third party runs to verify offline.
- **Replay the Proof.** Paste in a report and re-run its retained proofs offline. Pure
  re-computation: no target, no traffic, nothing minted. A tampered proof shows as
  contradicted, never as a green reproduction.
- **Proof of Posture.** The clean-result certificate, discussed in section 9, shown
  together with the figure its coverage is out of, and its stated residual limitations.
- **Assurance.** Compares the proven-fact set of two runs to show regressions (newly
  proven exposures) and fixes (no longer proven). Only proven facts enter the comparison.

Empty states are deliberately non-fabricating. The posture screen, when there is nothing
to show, says: "Nothing here is fabricated," and tells the operator the command that would
produce a real certificate.

---

## 6. The machine-readable outputs

Other systems — ticketing, code scanning, supply-chain tooling, a security operations
centre — need structured data rather than prose. The following are produced.

| Output | Format | Notes |
|---|---|---|
| Structured findings export | A data file (JSON) in this system's own published layout | Every finding states its grounding: proven fact, demoted, or lead. A fact carries its certificate reference, the confirming test, and its calibrated confidence. |
| Code-scanning export | SARIF 2.1.0 — the Static Analysis Results Interchange Format, the industry-standard file that automated build systems already know how to read | **Only a proven fact is levelled by its severity; a lead is capped at the lowest level ("note") and tagged as a lead** — so an unproven lead can never *block* a build pipeline, yet is still visible. |
| Proof bundle | A directory | The signed certificates plus chain and signed head, the public trust root, the re-verifiable report, and the raw captured bytes. This is the package a third party verifies. |
| Proof-Carrying Finding certificates | A data file per finding, with a published description of its exact layout | The portable per-finding format. Its published layout descriptions are generated from the real code, not written by hand, so the specification cannot drift away from what the software actually produces. |
| A signed statement in the industry's own formats | Three published standards used together — see below | Lets other organisations' software-inventory tools read a finding from this system without special handling. A confirmed finding is recorded as "affected"; an unconfirmed lead is recorded as "under investigation" and is **never** asserted as "affected". |
| Run dossier | A single `.zip` archive | Everything a run produced, in one tamper-evident archive. Detailed below. |
| Drift record | JSON | The difference in the proven-fact set between two runs. |
| Coverage certificate | Signed JSON | What was actually exercised. See section 9. |
| Posture certificate | Signed JSON | The clean result. See section 9. |
| Remediation certificate | Signed JSON | Proof that a previously proven problem is now provably dead. See section 9. |
| Usage-attestation ledger | Signed, hash-chained | Who ran what, when, replayable and verifiable through the command line. |
| Outbound push | A data file sent to an address the operator nominates, or a short message to a chat channel | Entirely opt-in; nothing is sent unless the operator supplies a destination. It refuses to be redirected elsewhere and will talk to no address other than exactly the one configured. The pushed document carries **no test inputs, no retained evidence, and no personal data** — only a certificate fingerprint — so pushing a report does not leak the evidence. |

### 6.1 The three standards used for the "industry format" statement

The row above names three published standards. A general reader does not need to
recognise them, but a procurement or assurance reader may, so they are set out here in
plain terms rather than left as initials.

| Standard | What it does, in plain words |
|---|---|
| **DSSE** (Dead Simple Signing Envelope) | A standard envelope for signing a document. Its value is that the envelope binds the *type* of the document into the signed material, so a signature over one kind of statement can never be peeled off and re-used on a different kind. |
| **OpenVEX** | A standard way of saying, in a form other companies' tools already read, "this published vulnerability does — or does not — affect this particular piece of software". It exists because a raw list of vulnerabilities tells a customer nothing about whether they are actually exposed. |
| **RFC 6962 Merkle inclusion receipt** | RFC 6962 is the published internet standard behind Certificate Transparency, the public tamper-evident registers that record issued web certificates. A *Merkle* structure is a way of combining many fingerprints into a single summary fingerprint, such that a short receipt proves one specific entry is genuinely inside the register — without the checker needing a copy of the whole register. Here it proves this statement really was entered in the log, at that position. |

The same terms recur in the world of software inventories: an **SBOM** (software bill of
materials) is a machine-readable ingredients list for a piece of software, and
**CycloneDX** is one of the two widely used published formats for writing one. Both are
returned to in section 12.

### 6.2 The one-click dossier

The dossier is designed for the moment an operator has to hand the whole engagement to
somebody else. It is a single self-contained `.zip` containing, where present:

- the three human reports;
- the structured data export and the build-system export described above;
- the complete offline-verifiable proof bundle;
- the engagement log, with secrets scrubbed;
- the transcript of any commands run through the governed terminal, redacted at source
  and scrubbed again;
- the governance-signed record chain;
- any drift record;
- a readable `index.html` summarising exactly what the run produced;
- a `README.md`;
- a `MANIFEST.json` listing every entry with its fingerprint;
- and, when a governance signer is available, a `MANIFEST.sig.json` (a threshold
  signature over the manifest bytes) and a `TRUST-ROOT-FINGERPRINT.txt`.

Four properties make it usable as an evidential artifact:

1. **Tamper-evident.** Flip any byte in any entry and the manifest check fails. Re-sign
   the whole thing under a different key and the fingerprint pin (section 7.2) refuses.
2. **Honestly labelled.** If no governance signer was available at build time, the
   dossier is still integrity-checkable by fingerprints but is marked **not
   authenticity-signed** — in the archive's own text, in plain words. It does not pretend.
3. **Path-safe.** Every entry is confined to a safe relative path. No absolute paths, no
   parent-directory escapes, and symbolic links are never followed. An unsafe path drops
   its artifact rather than escaping the archive.
4. **Deterministic.** Sorted entries, a fixed archive timestamp, and no clock in the
   fingerprinted content. Two builds over the same inputs produce identical manifest fingerprints.

A run with no proven fact carries no proof bundle, and the dossier says so plainly. A lead
is a lead.

---

## 7. Handing the evidence to an independent third party

This is the section a regulator, an auditor, or an opposing expert should read most
carefully.

### 7.1 The scenario

You are handed a package. You have no access to the operator's systems. You have no
internet connection. You have no reason to trust the operator, the vendor, or the tool.
You have a computer, Python, and one standard cryptography library.

**Can you determine for yourself whether the claimed result is genuine?**

For the cryptographic and integrity layers, yes, fully. For the final layer —
re-executing the automatic test itself — you need the open-source verifier, and the
project says so explicitly rather than blurring the line.

### 7.2 The step that makes this zero-trust: the out-of-band fingerprint

Every package contains a copy of the operator's **trust root** — the public keys and the
threshold that define who is allowed to sign. That copy, by itself, proves nothing. Anyone
who handed you the package could have generated a fresh key, re-signed everything, and
shipped a matching trust root.

So the package also prints a **fingerprint** of that trust root, and the verifier accepts a
fingerprint you supply on the command line.

The analogy: you are handed a notarised document. The notary's seal is on it, and the
notary's registration number is printed on it. That proves nothing on its own. What proves
something is looking up the registration number **on the notary's own published register**
— a source independent of the document you were handed — and confirming it matches.

The operator publishes their fingerprint through an independent channel: their website, a
signed communication, a contractual annex. You compare. Only then does any signature check
mean anything.

The system treats this as load-bearing rather than optional, and the two verification paths
handle a *missing* pin differently, in each case honestly:

- The standalone verifier shipped inside an audit package **fails closed**. Without the
  out-of-band fingerprint the package is reported NOT SOUND and the program exits non-zero.
  The docstring states the reasoning: "A forgotten pin can never surface as a clean SOUND /
  exit-0."
- The main framework's verification command, given no pin, prints a loud warning stating
  that exit 0 proves internal consistency and reproduction **but not authenticity**, and
  prints the exact fingerprint to obtain out of band and re-run with. It does not silently
  imply authenticity it has not checked.

### 7.3 What the standalone verifiers are, and what they prove

Three verification programs exist, all shipped as readable source.

**`verify_pcf.py` — the positive proof.** It imports **no** code from this system: not the
offensive engine, not the shared core, not the integration layer, not the third-party
agentic tool kept as a copy inside this project, not the gateway. It uses only the Python standard library and one Ed25519 library. Every byte
format it checks was re-implemented from the **published wire specification** and JSON
schemas, not by importing the producer's code — which is what makes it an independent
check rather than a mirror.

It proves, offline, with no target and no network:

| Layer | What it establishes |
|---|---|
| Fingerprint | The trust root matches your out-of-band pin. |
| Authentic | Each certificate's threshold signature validates against the pinned root. |
| Bound | Each certificate's recorded fingerprint matches the retained evidence presented. |
| Artifacts | Each raw captured file still produces its recorded fingerprint. |
| Chained | The hash chain and signed head bind the whole set — nothing suppressed, injected, or reordered — anchored and not rolled back. |

Exit status 0 means SOUND; 2 means NOT SOUND; 3 means a usage or file error. The file
states of itself: "Verification only — this file contains no offensive capability. It never
writes (except an optional anti-rollback high-water file), never phones home, and is
deterministic."

You can also *prove the environment is clean*. Passing `--prove-standalone` makes the
verifier first assert that none of the producer's modules is imported, **or even
importable**, in the running interpreter, exiting non-zero otherwise. The project's own
conformance test runs it exactly this way — a fresh subprocess, the system Python, a neutral
working directory, and a module search path that excludes the engine, the integration layer,
and the shared core.

**`verify_offline.py` — shipped inside every audit package.** The same discipline, packaged
with the evidence so an audit team does not have to obtain anything separately. It re-derives
authenticity, binding, artifact integrity, chain and anti-suppression, and the trust-root pin
— and fails closed without the pin.

**`verify_vf.py` — the remediation lifecycle.** The counterpart for the negative and
continuous case. It re-derives, with zero producer code, the whole lifecycle *vulnerable →
proven-fixed → still-proven, witnessed no later than a stated time*: the signed
fix-certificate's authenticity, that the recorded verdict agrees with the recorded state, the
cross-binding that stops a valid certificate from another run being spliced in, the signed
and hash-chained series of re-proof checkpoints with its anti-rollback floor, and the
witnessed time bound.

### 7.4 The one layer that needs the open-source verifier — stated plainly

The standalone verifiers **do not re-run the automatic test** for the general case.
Re-executing a full decision procedure requires that procedure's code, which is
framework-specific. That step is done with the open-source verifier:

```
python -m framework.v2 evidence verify \
    --report reverifiable.json --bundle . --trust-root trust-root.json \
    --evidence-root evidence --trust-root-fingerprint sha256:<the pinned value>
```

The project states the consequence rather than glossing it: after the standalone step alone,
what you still trust is **the signer's honesty about each verdict**. The reproduction step is
what removes that. The verifier itself is open source and can be obtained and audited
separately.

There is one deliberate exception. The **posture** family of tests — the ones that judge an
exported cloud, Kubernetes, service-mesh, or build-pipeline configuration — are pure, offline
functions of their retained inputs. Six of those decision procedures have been re-implemented
faithfully inside `verify_vf.py`, producer-free, so those results **do** re-fire with zero
producer code, and a parity test pins each re-implementation to the original so the two can
never silently diverge.

So the honest summary of what a third party can establish alone is:

| Question | Standalone, no producer code | With the open-source verifier |
|---|---|---|
| Was this signed by the operator's real governance keys? | Yes | Yes |
| Was the evidence altered after signing? | Yes | Yes |
| Was a finding removed, added, or reordered? | Yes | Yes |
| Is this an older report substituted for a newer one? | Yes | Yes |
| Does the automatic test genuinely produce this verdict over this evidence? | Only for the posture family | Yes, for all families |

### 7.5 The external-audit package

For a formal audit there is a purpose-built package containing:

- the signed certificates with the chain and signed head;
- the retained evidence that the binding check re-fingerprints and compares against;
- the re-verifiable report that the reproduction step consumes;
- the public trust root and its fingerprint file;
- the raw captured bytes, in their original folder structure;
- the standalone verification program, shipped inside the package;
- a small text file recording the fingerprint of that verification program, so an auditor
  can compare the copy inside the package against the copy published separately — a
  verifier shipped inside the thing it verifies cannot vouch for itself, and the package
  says so;
- the engagement's scope and authorisation documents, so the audit is bounded by the same
  permission the testing was;
- and a step-by-step procedure for the auditor.

#### What that procedure actually asks the auditor to do

The procedure is short. Reproduced in substance from the file the package generates:

**Step 0 — obtain the operator's key fingerprint through a channel that is not this
package.** The copy of the trust root inside the package is a convenience copy only.
Compare the operator's independently published fingerprint against the one in the package.
If they differ, stop: somebody re-signed the package under a different key.

**Step 1 — run the standalone verifier, with that fingerprint pinned.** It needs no
network, no target, and none of this system's software. It re-derives authenticity, the
binding between certificate and evidence, the integrity of the raw captured files, and the
chain that proves nothing was deleted, inserted or reordered. Exit status 0 means sound; a
single flipped byte anywhere makes it non-zero.

**Step 2 (optional, and it is the step that removes the last dependence on trust) — run
the reproduction step** with the open-source verifier, obtained and audited separately.
This re-fires each automatic test over the retained evidence. The package's own text
states why the step exists: after step 1 alone, what an auditor still trusts is the
signer's honesty about each verdict.

The package then states, in its own words, what the auditor may and may not conclude:
after step 1, authenticity, binding, integrity and anti-suppression, with no trust in this
system's tooling beyond the verifier just read; after step 2, all of that plus
reproduction. Two people with a laptop can complete steps 0 and 1 in well under an hour;
step 2 takes as long as it takes to obtain and read the open-source verifier, which is a
deliberate, one-off cost an auditor pays once and re-uses.

The project names its own residual limit here without being asked to: "we PREPARE the package;
we cannot BE the third party." Independence of the audit is something only an external team can
supply.

The same honesty is applied to the **witness** mechanism, which is the answer to the "fully
dishonest producer" case. Independent witnesses can countersign that a record series only ever
grew and never forked. The project's own trust document is marked "DRAFT — design, not a
guarantee" and states the assumption code cannot enforce: **distinct keys are not distinct
operators**. If the producer holds all the witness keys, the quorum is theatre. It further states
that a witness does *not* attest that any finding is true, that a remediation holds, or that a
test fired — only that the log is continuous, plus a time bound. "Conflating 'witnessed' with
'true' would be an overclaim." The transport and protocol are working; genuine independence of
witnesses is a deployment decision, and is recorded as an open item rather than claimed.

---

## 8. What happens if a single byte is changed

This is the question that decides whether any of the above is worth anything. The answer, case
by case:

| What is changed | What happens |
|---|---|
| One byte of a captured request or response file | Its fingerprint no longer matches the manifest entry. **Artifact integrity fails.** |
| One byte of the retained evidence the test judged | Its fingerprint no longer matches the fingerprint recorded in the signed certificate. **Binding fails.** In most cases the test also no longer produces the claimed verdict, so **reproduction fails** too. |
| One byte of the certificate itself | The certificate is written out in one fixed, standard arrangement before it is signed, so that the same content always produces exactly the same bytes. Change any of them and the signature no longer validates. **Authenticity fails.** |
| Re-sign the tampered evidence with a fresh key, and ship a matching trust root | The trust root's fingerprint no longer matches the value the operator published out of band. **Refused before any signature is even checked.** |
| Delete a finding from the set | The next chain link's "previous" fingerprint mismatches. **Chain break: entry deleted or reordered.** |
| Insert or reorder a finding | Sequence numbers no longer run consecutively. **Chain break: sequence gap.** |
| Substitute an older, genuinely signed, smaller report | The durable high-water floor refuses it as a rollback. |
| Present two certificates under the same finding reference | Duplicate references are **refused up front**, rather than relying on the fingerprint check to catch it later. |
| Relabel a finding's weakness class to something more alarming | The re-execution boundary refuses: the retained evidence adjudicates its own class. The claim-grounding check independently requires the firing test to be a valid confirmer for the claimed class. |
| Overstate the claimed confidence by more than one part in a million | Flagged as differing from the claimed certificate, with "tampered?" in the annotation. |
| Edit the automatic test's own code after the certificate was issued | The signed test-version fingerprint no longer matches the current one. Treated **fail-closed**. |
| Wrap a genuine certificate in a summary that misrepresents it | The view-consistency check in step 2 of the proof-carrying-finding verification rejects it. |
| Point the verifier at a hostile package that swaps a file for a symbolic link, or an enormous file | The verifier opens files in a way that refuses symbolic links and non-ordinary files, confines every path inside the package, and caps how much it will read. |

A single flipped byte anywhere flips the verdict to NOT SOUND. That property is not an aspiration
— it is what the tests assert.

### 8.1 The tamper battery

This behaviour is verified by an adversarial test suite rather than by assertion. The
differential test takes genuinely minted artifacts and then applies a battery of single-byte and
single-field tampers: flipping a recorded state, removing a signer, pinning the wrong key,
truncating the series, rolling back the floor, dropping or corrupting a witness signature,
reducing a quorum below a strict majority, and further tampers that are re-signed so that they
exercise the deeper checks that run *after* signature validation.

The standalone verifier and the in-tree verifier must agree on every single case. **Any
disagreement fails the test**, on the grounds that a disagreement means either the published
specification is ambiguous or one of the two has a bug. The test also asserts byte-for-byte
parity between the way the independent program writes these objects out and the way the real
producer does, and
proves standalone cleanliness by running the verifier in an interpreter that cannot import any
producer module.

### 8.2 What tamper-evidence does not do

Stated plainly, so nobody is misled:

- It does not stop tampering. It makes tampering **detectable**.
- It does not, by itself, defeat a producer who controls the whole machine and rewrites the
  record, the chain, and the local anti-rollback floor together. That case is closed only by an
  independent outside witness or by an outside verifier who retained a newer floor.
- A signature proves *who signed*. It does not prove the signer was honest about the verdict.
  Only the reproduction step removes that dependence — and for the general case, reproduction
  requires the open-source verifier.
- Re-execution proves the verdict is the correct function of the retained evidence. It does
  **not** prove the retained evidence reflects the live system, because the retained values were
  supplied by the producer. There are only two ways to establish that independently: somebody
  else re-runs the test against the live system, or the capture itself is tied to the target's
  own encrypted conversation, so that the bytes cannot have come from anywhere else. **The
  system has built the second of those**, and section 8.3 describes both what it does and the
  precise sense in which it is not yet a closure. The project states the limit on the face of
  its own certificates rather than in a footnote.

### 8.3 The hardest residual: the evidence was collected by the party making the claim

This is the single limitation this document repeats most often, and it deserves its own
treatment rather than a bullet point.

Everything above proves that the *verdict* follows correctly from the *evidence*. Nothing
above proves that the evidence is what the target actually sent. A dishonest operator with
complete control of their own machine could, in principle, write out a response the target
never produced, seal it, sign it, and hand over a package in which every check passes —
because every check is a check on internal consistency, not on the outside world.

The ordinary answer to this is procedural: a second party re-runs the test against the live
system for themselves. That works, but it costs a fresh engagement.

The project has built a mechanism aimed directly at the problem, and its honest status
matters as much as its design, so both are stated here.

**The idea.** When a browser or a program talks to a website over an encrypted connection,
that specific conversation has a unique cryptographic value derived from the encryption keys
both sides agreed on — a value nobody outside that conversation can reproduce. The mechanism
captures that value, pairs it with the fingerprint of the response bytes, and has a **notary**
— a separate party holding its own signing key — countersign the pair. The result is an
object that says: *these exact bytes came out of that exact encrypted conversation, and a
party other than the producer vouches for it.* A separate offline checking program then
confirms three things without trusting the producer at all: that the bytes presented really
do produce the fingerprint that was signed; that the countersignature is valid over the pair; and
that the countersigning key is a notary key the checker obtained independently, not one the
package asserted for itself. Bytes from a different conversation, different bytes, or a
missing countersignature are all rejected.

**What is actually built.** The evidence object, the countersigning step, the capture of the
live encrypted-session value using the operating system's own standard encryption tool, and
the producer-free offline checking program are all written, wired together, and covered by a
nine-case test suite that includes deliberate forgery attempts: a fabricated conversation with
no valid countersignature, a countersignature over a *different* conversation, a
countersignature over *different* bytes, a tampered body, the wrong notary key, and an empty
session value. All are rejected.

**What it does not yet establish, stated in the project's own terms.** The notary in the
shipped version is a piece of software that this system runs and hands the session value to.
That means the producer could, in principle, fabricate a pair and have "its own" notary sign
it. What the work therefore proves today is **the mechanism and the shape of the check** — not
genuine unforgeability. The project's own status document classifies it as a *capability*
rather than a verified fact, and names precisely what would be needed to close it: first, a
class of cryptographic tooling in which the notary participates in setting up the encrypted
conversation itself, so the producer cannot forge the record even in principle; and second, a
notary operated by a genuinely independent third party. The first is not present in this
environment and cannot be built out of the standard encryption tool alone; the second is a
deployment decision, not a coding one. The code marks the place where a third-party notary
would connect, and the project explicitly instructs its own maintainers not to upgrade the
claim until both exist.

**And one more thing a careful reader should be told rather than left to discover.** This
mechanism is a self-contained capability with its own tests and its own offline checker. It is
**not** currently applied to every finding the system produces as a matter of course — an ordinary
confirmed finding today carries the producer-signed response bytes described earlier in this
chapter, not a notary-countersigned session binding. The place in the live re-testing code where
the stronger step would attach is marked in the source as the deferred frontier, using those words.

The honest summary for an agency reader: **this residual is real, it is disclosed on the face
of the certificates, a countermeasure exists and is tested, it is not yet on the default path,
and it is not yet strong enough to be claimed as a closure.** Until it is, the sound way to remove
the residual is the procedural one — an independent party running the test themselves against the
live system.

---

## 9. The clean result: proving there is nothing exploitable

### 9.1 Why "nothing found" is much harder than "something found"

There is a logical asymmetry at the heart of security testing, and most tools ignore it.

"We found a problem" is an **existential** claim. One positive observation settles it. Show the
request, show the response, show the proof.

"There is no problem" is a **universal** claim. It asserts something about every way the problem
could have shown itself. To make it honestly you need to establish that the observation channel
was *capable of seeing the problem had it been there*.

An accurate medical analogy: a positive test result establishes a condition. A *negative* result
establishes nothing at all unless you also know (a) that the test can detect that condition, (b)
that the correct sample was taken, and (c) which conditions the test does not cover. A
laboratory that reports "healthy" from a test that was never actually run on the sample is worse
than useless — it stops anyone from looking again.

The same point, more bluntly: a smoke detector with a dead battery is silent all night. Silence
from an instrument means nothing until you have shown the instrument was working and pointed at
the right room. Everything in this section is machinery for showing exactly that.

The project's own doctrine document states this in one line:

> "Asserting a vulnerability that is not there (**false FACT**) destroys trust in every finding.
> Asserting safety that was not established (**false CLEAN**) is worse, because nobody goes
> looking again."

### 9.2 The mechanism: "was there a channel?"

Every result from an automatic test carries a flag the code calls `conclusive`. It is set only
when the test genuinely had an **observable channel** and rendered a definite verdict. That means
one of:

- a positive result (always conclusive — a firing test is definite by construction); or
- a **channel-confirmed negative**: a sequential statistical test that reached its *refute*
  boundary; a timing test with an adequate sample that found no shift; a definite proposition
  evaluated over actually-observed values; or a payload that was **observed reaching its
  destination but neutralised** — for example a marker that was reflected into a position where
  it cannot execute, or a template expression that came back echoed rather than computed.

It is **false** for a one-sided test that merely did not fire with nothing to observe — a single
comparison between two indistinguishable responses, a marker or an error or a callback that is
simply absent. The code's own comment: "absence of a positive channel is not proof the surface is
safe."

That flag drives a three-way verdict for every probe:

| Probe verdict | Meaning |
|---|---|
| **finding** | An applicable test fired. |
| **clean** | An applicable test ran, had a channel, and did not fire. |
| **inconclusive** | The payload was sent but no test adjudicated. **Never counted as clean.** |

And the composition rule is conservative: within a family of related observations, any FACT wins;
otherwise any LEAD wins; otherwise any INCONCLUSIVE wins; only if *all* are CLEAN is the family
CLEAN. **An empty set composes to INCONCLUSIVE, not CLEAN.** In the code's phrase: "nothing
examined is not the same as nothing found."

### 9.3 The registry: which results are allowed to say "clean" at all

Every way the system can reach a conclusion is registered in a single declared file, and that
registry is enforced both by an automated test and, at run time, by the admission gate that
issues verdicts. An unregistered route is a fatal error, not a silent pass.

In the version read for this briefing there are **26 registered observation windows**. All 26 may produce a
FACT. **Only 6 may currently produce a CLEAN**, and every one of those six draws its conclusion
from a response header, a transport-level handshake, or a TLS handshake — the places where the
observation is complete and unambiguous:

| What the observation window looks at | Why that is a complete observation | Registry name |
|---|---|---|
| Where a site says it is sending the visitor next | The forwarding address is a single line the server itself wrote. It is either hostile or it is not; there is nothing hidden. | `open_redirect.location_header` |
| Whether a site tells browsers that another website may read its data while logged in | The permission is granted or refused in the server's own reply lines. Nothing is left to interpretation. | `cors.reflected_origin_with_credentials` |
| Where a site sends the visitor when an attacker supplies a false site name | Same complete observation as the first row, under a deliberately hostile input. | `host_header.location_header` |
| Where a single-sign-on flow sends the user after logging in | Again a forwarding address the server itself wrote, in its own reply. | `oidc_redirect_uri.location_header` |
| Whether a network service answers at all | A refused connection is itself a definite answer — a closed door is not an ambiguous door. | `service_reachability.tcp_handshake` |
| Which encryption a modern client and the server actually agree to use | The system makes a real connection and records what was agreed. Agreement is observable in full. | `tls_weakness.tls_handshake` |

Every observation window that draws its conclusion from the **body** of a response, from an
**exported document**, or from a **live capture** may currently say FACT, LEAD, or INCONCLUSIVE —
but not CLEAN.

### 9.4 The rule that stops a capability from being quietly abandoned

This is the part most likely to be misread as a weakness. It is the opposite.

The registry records, for every observation window, both what is true **today** and what that
window **must become**. Where there is a gap, the registry **requires** a named piece of engineering
work that would close it. A gap with no named work fails an automated check, and a change carrying
one cannot be accepted into the software.

The consequence is structural: a capability can never be quietly abandoned by downgrading the
claim to match a shortfall. Seventeen of the 26 windows currently carry named outstanding work.
Lowering a *target* — declaring that a capability is not achievable at all — requires an explicit
written argument, not a convenience.

The project's own doctrine document opens by naming this failure mode directly: "the failure mode
of every 'do not overclaim' rule is a ratchet: each inconvenient capability gets quietly redefined
as out of scope, every sentence stays technically true, and the product becomes honest about doing
less and less. That is not the goal and it is not permitted here."

Reading the named blocking work is instructive, because almost none of it is about *detecting
better*. It is about **completeness**. Most of the entries have the same shape: before the system
may say "there is nothing here", it must first be able to show that it was looking at the whole
thing, and at the same thing a browser or an administrator would see.

| Observation window | What a clean result would additionally require |
|---|---|
| A forwarding instruction written into the page itself | Three separate guarantees that the page examined is the page a browser would see: a faithful copy of the published rules for working out which alphabet a page is written in, rather than an approximation; compression tools whose exact versions are recorded inside the proof; and an assurance that the page was read to the end rather than cut short. |
| A forwarding instruction assembled by the page's own code as it runs | Reading the code cannot prove absence: a destination assembled while the page is running never appears literally anywhere in the source. Closing this needs a real browser, driven automatically, watching where the page actually goes. |
| A vulnerable component in the customer's software | Resolving version requirements that name a range rather than one version, and recording which snapshot of the published advisory data was used — so that "no advisory matched" becomes a statement bounded by a known list rather than an open-ended one. |
| Container-platform benchmark controls | A list stating which controls were expected for each kind of machine, checked against what the exported configuration actually contained. |
| Container-platform role assignments | Proof that the export listed *every* assignment, and that the set of roles treated as dangerous is itself complete. |
| Service-mesh configuration | Listing every logical area and every workload, and working out the setting that actually applies to each one after inheritance. |
| Build-pipeline configuration | Listing every pipeline *plus* every reusable pipeline and shared step it calls, followed all the way down. |
| Cloud configuration, whether read from files or from a live account | Proving the capture listed the resource's full set of permissions, with every related setting resolved and cross-linked. |

Three of those notes are about **where the system inserted its test values**, not about what it was
able to detect. The live re-testing currently places test values in the part of a web address after
the question mark, and in the segments of the address path. Values carried in cookies, in
form-submission bodies, or in structured data bodies are **not yet tried** — so a forwarding
weakness reachable only through those is reported as currently unexamined, and never as clean.

### 9.5 The three negative artifacts that are shipped

Three signed documents exist for the negative case. Each is described below in turn, because each
carries a real limitation that a summary line would hide.

| Artifact | In one line |
|---|---|
| **Coverage certificate** | What was actually examined, and for each thing examined, whether a real test reached a verdict. |
| **Posture certificate** — also called the *Certificate of Non-Exploitability* | A signed per-item statement of CLOSED, OPEN or UNPROVEN, with its own limits written inside the signature. |
| **Remediation certificate** | "The attack that provably worked is now provably dead" — with controls proving the test was still capable of firing. |

#### 9.5.1 The coverage certificate

For each surface, each input, and each weakness class that the assessment actually reached, this
records whether an applicable test genuinely ran and reached a verdict. That is what turns a silent
area of the application from *merely untested* into *provably tested and clear*. It is signed in the
same way as everything else — multiple named authorisers, over a fixed byte-for-byte layout, with the
key fingerprint published separately.

**Its honest bound is written verbatim inside the signed material**, so it cannot be separated from
the conclusion. It certifies coverage of the surfaces the scanner *reached*. It is **not** proof that
those were all the surfaces. Alongside the count of things found, the certificate carries what that
count is out of — the exploration limits, whether the list of pages still to visit was cut short, and
whether the effort budget ran out. A reader therefore cannot mistake "everything we reached" for
"everything there is".

#### 9.5.2 The posture certificate

This is the signed clean result. Per surface, per input, per weakness class it states one of three
things: **CLOSED**, **OPEN**, or **UNPROVEN**. It is tied to a statement, signed by the system's
owner, of what the target actually is — so a certificate cannot be quietly re-pointed at a different
system. It carries the same "out of what" figure and its own residual limitations inside the signed
material.

Two levels of checking are shipped:

- **Binding.** A third party re-checks the signature, the independently obtained key fingerprint, and
  the two bindings — certificate to results, and certificate to the owner's statement of what the
  target is — entirely offline, with none of this software installed.
- **Re-executable.** The certificate additionally carries each clean test's decision rule *as data*,
  together with the values that were observed, so the standalone checking program can work the verdict
  out again for itself rather than accepting it.

**Its honest bounds.** CLOSED means non-exploitability *by this family of automatic tests, over the
surface actually reached, as of the stated freshness limit*. It never means "secure against
everything". Endpoints that were never discovered are outside the figure entirely. A structural rule
refuses to issue a CLOSED that cannot name a test which conclusively reached that answer, and
**UNPROVEN never counts as CLOSED**. And even at the re-executable level, the retained values were
still supplied by the producer — so re-execution proves the verdict matches the evidence, not that the
evidence matches the live system. That is the residual discussed at length in section 8.3.

#### 9.5.3 The remediation certificate

This is the document for "we fixed it — prove it". The *original* automatic test, the one that fired
before, is re-run over freshly captured bytes from the patched system, and must now stay silent. The
result is cross-tied to the original positive certificate, so a certificate from a different run
cannot be substituted.

Four outcomes are possible — REMEDIATED, STILL VULNERABLE, INCONCLUSIVE, REFUSED — and **all four are
signed**. That matters: it means the reason attached to an inconclusive result cannot be stripped off
and the remainder re-read as success.

**Silence only counts as a fix when it is controlled.** Three things must hold at once. A deliberately
vulnerable twin — a positive control — must still trigger the test, proving the equipment is alive.
The target must actually have answered, measured only on parts of the response the *target* produced
and never on anything the tester set. And the check must repeat according to a policy set per weakness
class.

**Only 13 kinds of automatic test are on the list for which silence counts as a sound negative**, and
the list is closed: anything not on it is refused rather than assumed. In plain terms, the 13 are:

| Kind of test | What its silence would mean |
|---|---|
| Error signature | The application no longer returns the distinctive database error that only a successful injection produces. |
| Side effect | The action no longer leaves its mark in the place it previously changed. |
| Differential response | Two requests that should look identical no longer come back measurably different. |
| Boolean inference | The application no longer answers the attacker's true/false probing, so data can no longer be read out one answer at a time. |
| Reflection context | The tester's marker no longer lands anywhere in the page where it would be executed. |
| Browser execution | A real browser no longer executes the injected code. |
| Evaluation | An expression the tester supplied is no longer computed by the server. |
| Achieved state | The end state the attack aimed at is no longer reached. |
| Predicate | The stated proposition no longer holds over the values actually observed. |
| Out-of-band callback | The target no longer calls back to a listener the tester controls. |
| Database break-out | The target's query parser no longer treats tester-supplied text as commands. |
| Command break-out | The same, for operating-system commands. |
| Document-database break-out | The same, for the newer style of database. |

Everything else is excluded, each with a written reason recorded in the code: timing and
credential-stuffing tests, because they are statistical judgements over a sample, where silence is
merely an absence of evidence; prompt-injection and system-prompt-disclosure tests, because although
the judgement is deterministic, the thing being judged is the unpredictable output of a language model;
crash-detection, because one of its cases is a genuinely non-repeatable timing race; dependency-version
and every configuration-posture family, plus single-sign-on signature forgery and automated-access
detection, because these read exported documents rather than re-running a live attack; and network
reachability, exposure and encryption-strength checks, because a sound way to prove "the connection
really happened" has not yet been built for them. Race conditions and request-smuggling classes are
excluded on the separate ground that a genuine flaw may simply not show itself on a given attempt. An
unrecognised class is refused outright.

Two invariants those entries rest on are preserved in the code as warnings to future maintainers.
Differential response qualifies **only** because no certifiable class currently decides anything on
*how long a response took* — if one ever does, silence becomes unsound for it. And boolean inference
and out-of-band callback silence is sound **only** because a positive control must fire first, proving
the effort budget was adequate before any silence is credited.

**A deliberate asymmetry in freshness.** A **still-vulnerable** verdict can reach the higher level of
freshness assurance, because a fresh, unpredictable challenge value can ride along with the working
attack and come back through the *same* channel the original signal used. A **remediated** verdict is
capped at the lower level, and the reason is fundamental rather than an oversight: a fixed system
produces no signal at all, so a fresh value appearing anywhere in a silent response got there by
ordinary echoing — which a chatty application, or an intermediate device such as a caching server, can
produce without the underlying flaw existing. A verifier that demands the higher level for a
remediation is given INCONCLUSIVE, never a falsely strong result.

### 9.6 Where the clean answer is deliberately routed elsewhere

**Six** of the twenty-six observation windows — covering five capability areas — carry an explicit
written declaration that they will **never** be allowed to produce a clean result, together with the
argument for it. Counted individually, they are:

1. Capturing a working credential from a cloud machine's own credential service.
2. Confirming that a secret found lying exposed is a currently working credential.
3. Confirming that one Google Cloud identity can act as another.
4. Confirming that an identity's own permissions let it give itself more power than it started with.
5. Confirming that an anonymous caller is attached to a dangerous administrative role on a container
   platform.
6. Confirming that a role on that platform genuinely grants dangerous powers, established by reading
   the role's actual rules.

Items 5 and 6 are two separate windows onto the same capability area — access control on container
platforms — which is why six windows cover five areas. The first of the two reaches its answer by
reading who a role has been given to; the second by reading what that role actually permits. They are
counted separately because the registry registers them separately, and a reader re-deriving the count
from the registry file will find six entries, not five.

The argument, in plain English, is the same in each case and is worth reproducing: these windows
confirm an *achieved effect* over a single, deliberately scoped capture. Proving the **absence** of a
capturable credential, or a valid secret, or an impersonation path, or a dangerous role binding, is a
*different capability* — it requires a complete enumeration together with a proof that the enumeration
was complete — and that belongs to the configuration-posture windows. The clean side is therefore
**routed** to a different mechanism, not abandoned.

---

## 10. Looking after the evidence over time

Everything above is about the moment evidence is created and the moment it is checked. An agency
also has to live with it: store it, budget disk for it, destroy it when policy says so, and be able
to recover it after a failure without quietly destroying the guarantees. This section answers those
questions, including where the honest answer is "there is no built-in mechanism; the operator must
supply the policy".

### 10.1 Where it lives and how much of it there is

Captured traffic lives in ordinary files and folders, one folder per engagement and one sub-folder
per recorded action, underneath the framework's own working directory. Nothing about it is exotic:
it can be listed, copied, and archived with the operating system's normal tools.

The volume is modest, because the system records the exact bytes of individual requests and
responses rather than video, whole-network recordings, or disk images. The figures below were
measured directly, with the operating system's own disk-usage command, across the real engagement
folders this engine had produced on the machine used to prepare this chapter. They are examples,
not a guarantee about any particular target:

| Engagement size | Recorded actions | Evidence on disk |
|---|---:|---:|
| A small test run | 3 | about 52 kilobytes |
| A medium engagement | 36 | about 1.9 megabytes |
| The largest engagement present | 191 | about 3.1 megabytes |

That works out at roughly fifteen to fifty-five kilobytes per recorded action, the variation being
mostly the size of the response bodies retained. The complete engagement folder — evidence plus
reports, notes and logs — was between two and three and a half megabytes for the two largest
engagements on that machine. For planning purposes, an organisation running many engagements should
expect single-digit megabytes each, not gigabytes. The stores that can grow larger over time are the
event record and the optional supporting databases, which are covered in the architecture chapter,
not the evidence tree.

### 10.2 How long it is kept: there is no automatic retention period

Stated plainly, because it matters to a records-management reviewer: **the system's stated default
is to persist, and it applies no retention period and performs no scheduled deletion.** Evidence
written to disk stays there until somebody removes it. Reading the full list of commands the system
offers, there is no command whose purpose is to expire, archive, or delete an engagement's evidence.

That is a deliberate default — the project's own wording is that "persist-by-default is the
doctrine", because an operator needs to search, re-verify and report against material after the run
has ended — but it is not a retention *policy*, and an agency should not read it as one. **An
organisation with a data-retention obligation must apply its own policy and its own tooling to
these folders.** They are ordinary files; a scheduled deletion job or an archive-and-purge process
from the organisation's existing estate will work on them without any cooperation from this system.

Two consequences worth stating in the same place:

- Deleting an engagement's evidence does **not** invalidate certificates that have already been
  handed to a third party. Those packages carry their own copies of the captured bytes. It does mean
  the operator can no longer re-run the artifact-integrity or reproduction checks locally.
- Because the evidence contains captured traffic, the retention decision is a **personal-data**
  decision, not merely a storage one. See section 2 for what is masked before writing and what
  deliberately is not.

### 10.3 Destroying it: the ephemeral mode, and manual deletion

Two routes exist.

**Delete the folder.** Because the evidence tree is ordinary files owned by one account, deletion is
whatever the organisation's normal secure-deletion procedure is.

**Never write it at all.** The system has an explicit **ephemeral mode**, switched on per run, for
work on a sensitive target, on a client's own machine, or on a shared host. When it is active:

- the write location for captured evidence, the audit log and the run store is moved onto in-memory
  storage rather than the disk;
- on exit, that whole area is removed **and its absence is verified** — a leftover file is treated as
  a failure rather than shrugged off, because "leaves nothing on disk" is the entire promise. A
  safety net removes it even when the program exits badly;
- the stores that cannot be moved into memory — the persistent event record, the learning files — are
  switched off up front, before anything opens them, rather than being written and cleaned up
  afterwards;
- and the run is forced onto a data-handling tier that refuses AI providers which retain submitted
  data.

Everything is restored exactly on exit, and a run that does not ask for ephemeral mode is unaffected
by its existence.

### 10.4 Backup and restore — including the one trap

This is where an otherwise routine operations task can silently damage a guarantee, so it is worth
reading carefully.

**What has to be copied.** Five things, and a backup that omits any of them is incomplete:

| Item | Why it matters |
|---|---|
| The engagement's evidence folder | The raw captured bytes the artifact-integrity check re-fingerprints. |
| The signed certificates, the chain and the signed head | The proofs themselves. |
| The public trust root | The list of keys and the threshold. Public, but needed to check anything. |
| The private signing keys | Without them no new certificate can ever be issued. Their handling is the subject of the signing-and-keys chapter. |
| The anti-rollback floor file | The small durable record of the largest report ever seen. See the trap below. |

**Restoring evidence and certificates is safe.** Every guarantee in this chapter is derived from the
content of the files themselves, and verification is performed against *public* keys. A certificate
restored from a backup verifies exactly as it did before, on any machine, with no state carried over.
Restoring does not require the original signer to be present or even to still exist.

**The trap is the anti-rollback floor.** That file is the system's memory of the largest report it
has ever accepted, and it exists precisely so that a smaller, older, genuinely signed report cannot be
substituted later. Its behaviour is deliberately asymmetric, and both halves matter during a restore:

- If the file is **present but unreadable or malformed**, verification **refuses outright**. Rollback
  protection whose own state cannot be trusted must not quietly degrade into no protection at all.
- If the file is **absent**, that is read as a legitimate first-ever verification, and rollback
  checking is simply skipped until the floor has been re-established.

The operational consequence follows directly. **Restoring a backup that does not include the floor
file, or restoring an old copy of it over a newer one, silently lowers or removes rollback
protection.** Nothing will error; a subsequent verification of a smaller, older report will simply
pass. The system's own code notes the same limit from the attacker's side: the floor is a local,
unsigned file, so a party who controls the machine can rewrite the record and the floor together. The
countermeasure in both cases is the same — an outside party who keeps a floor of their own, or an
independent witness, as described in section 7.5.

Practical guidance, drawn from that behaviour:

1. Treat the floor file as part of the backup set, and never restore an older copy over a newer one.
2. When restoring onto a fresh machine, restore the floor along with the chain, not afterwards.
3. If the floor is genuinely lost, say so rather than papering over it: verification will still prove
   authenticity, binding, artifact integrity, reproduction and chain continuity. Only the "is this an
   older report substituted for a newer one" check is affected, and it can be re-established by
   verifying the current, complete report once.

**There is no single-command backup for the offensive engagement material**, and that should not be
overstated into one. It is ordinary files, backed up with ordinary tools.

**The sovereign side does have one.** The other half of the platform — the part that keeps the owner's
signing identity and its own long-running record — ships explicit `backup` and `restore` commands
producing a portable, passphrase-encrypted file that can be recovered onto **new hardware**. This
exists because the owner's key can be sealed to a particular machine's security chip, which would make
a dead disk unrecoverable. The design is worth noting because it shows the discipline applied to
operations as well as to findings:

- The whole backup is encrypted under a key derived from an owner passphrase, so the file itself
  discloses nothing.
- Inside it, a list of every packaged file with its fingerprint is signed by the owner. On restore,
  that signature and every individual file fingerprint are checked **before a single file is written**.
- After writing, the restored record's internal chain is re-checked, and a restore will not report
  success over an inconsistent record.
- The restore targets a **fresh** location, so a caught failure leaves only a discardable directory.
- The passphrase is never stored. Lose it and the backup is unrecoverable — deliberately, because that
  is what makes an off-site copy safe to hold.

---

## 11. Honest status: what is working, what is proven offline, and what is deferred

The heading is deliberately flat, because the honest position is mixed and a reader skimming
headings should not take away a stronger claim than the text supports. **None of the cloud and
container-platform confirmations described below has been pointed at a live third-party cloud
account.** All six are built and wired end to end. The two container-platform ones are proven
against a real Kubernetes cluster the system stands up, owns and destroys itself, so they wait on
nobody; the four cloud ones are proven against recorded sample data, three of them waiting on a
customer supplying credentials to their own account, while the fourth deliberately never carries out
the action it detects, which 11.1 explains. The web-facing tests, the signing and certificate
machinery, and the packaging are a different matter entirely, and the table below says which is
which, one line at a time.

The project maintains an explicit ledger distinguishing three states: fully working end to end;
built and proven offline but not yet exercised against a live third-party system; and deliberately
not built. This chapter reproduces it rather than smoothing it over.

### 11.1 The cloud and Kubernetes confirmations: complete, what is still deferred, and what no
longer is

Because this is the point most likely to be misread in either direction, it is worth stating
before the table.

Three terms first, because they recur below. *Kubernetes* (often abbreviated to "K8s") is the
industry-standard software for running large numbers of application containers across a fleet of
machines. *IAM* stands for identity and access management: the part of a cloud account that decides
who is allowed to do what. *RBAC* stands for role-based access control: the same idea expressed as
named roles that are granted to identities.

Six cloud and Kubernetes exploitation confirmations are **complete and part of the released
software**. In plain terms, each proves that something was actually *achieved*, not merely that a
setting looked wrong:

1. A credential was taken from a cloud machine's own credential service — and it really worked.
2. A secret found lying exposed is a **currently working** credential, not just a string that looks
   like one.
3. One Google Cloud identity can act as another.
4. An identity's permissions let it give itself more power than it started with.
5. On a container platform, an anonymous caller — anyone at all — is attached to a dangerous
   administrative role.
6. On the same platform, a role genuinely grants dangerous powers, proven by reading the role's
   actual rules rather than trusting its name.

Each has its own deterministic offline test plus a capture-and-admission component owned by this
system. All six are wired end to end. The **two Kubernetes** confirmations (5 and 6 above) are proven
against a **real Kubernetes cluster**; the **four cloud** ones are proven offline against **recorded
sample data standing in for the real thing**.

**Kubernetes, stated exactly.** A script in the repository stands up a real single-node cluster — k3s
version 1.31.5, in a container reachable only on the machine's own internal address — which the system
creates, owns and destroys afterwards. It plants known-dangerous and known-benign access rules in that
cluster, captures what the real Kubernetes interface returns, and adjudicates those real bytes through
the same path as any other finding: automatic checker, admission, certificate, offline re-verification.
An anonymous, unauthenticated caller bound to the full administrative role is confirmed and its signed
certificate re-verifies with no network. The benign arrangements in the same cluster are correctly not
confirmed — including the namespace's own default identity bound to the built-in `admin` role, whose
real rules genuinely do grant get, list and watch on secrets. That is the commonest legitimate
delegation in Kubernetes, and it is exactly the case a detector without a subject test gets wrong on an
ordinary cluster. The script asserts every one of those expectations and exits with an error if any
fails, so it is a proof rather than a demonstration, and a third party can re-run it on their own
machine. **Two things it does not cover:** a scope-gated *enumeration* capability that discovers access
rules across a whole cluster (the script reads the objects it planted, by name), and a **managed
provider's control plane** — Amazon EKS, Google GKE, Azure AKS — which is the same interface reached by
a different access path.

What remains outstanding for the four **cloud** confirmations is **use against a real third-party cloud
account**, which waits on the customer supplying their own cloud credentials. The detection logic, the
evidence handling, the certificates and the safety gates are all built and proven. Only the act of
pointing them at a live third-party account is pending, and that is by design: this system does not
acquire other people's cloud credentials for itself.

Two consequences a procurement or oversight reader should take from that:

- The remaining deferral is **operational, not technical**. The capability register records **no
  outstanding engineering work** against these six, which — under the registry's own enforcement
  rule that any capability gap must name the engineering that closes it — means there is no
  engineering gap recorded, by construction rather than by assertion.
- The permission-escalation capability must be described differently from the other cloud ones. It is
  a pure offline re-derivation over the operator's own retained permissions document and
  **deliberately never carries out the escalation**, because a defensive verification test does not
  perform the attack it is detecting. It is not "waiting to be used in anger"; not firing it is the
  design.

A related, purely practical point: these six have **no dedicated screen and no dedicated
command-line verb**. They are library entry points the engine's verification path calls, and a
confirmed result from any of them surfaces through the ordinary proven-fact path — the live view,
the findings table, the certificate browser, the proof studio, the report, and the run-to-run
comparison. What the interface offers for cloud is a separate, authorisation-gated **posture**
assessment that reads an imported inventory rather than the live account.

| Capability | Status |
|---|---|
| The core automatic tests against a live web target | **Working end to end.** The test harness stands up a real vulnerable application on the local machine and confirms findings against it. Pointed at a safe twin of the same application, it returns nothing — a shipped negative control proving the authority does not rubber-stamp. |
| Network reachability, encryption weakness, vulnerable dependency, and the web achieved-state windows | **Fact-capable against real captures**; reachability and TLS are also clean-capable. |
| Signing, certificates, chain, and offline re-verification | **Working.** Exercised by the standalone conformance test in an environment where none of this software is importable. |
| The dossier, proof bundle, and audit package | **Working**, including the honest unsigned labelling when no governance signer is available. |
| Taking a credential from a cloud machine's own credential service | **Built and proven offline against recorded sample data; not yet fired at a live third-party cloud account**, which waits on the customer supplying a laboratory credential of their own. Every part is built: the component that runs it, the observation window, the admission route, the certificate, and the entry on the system's internal map. In the project's own words: "There is no live FACT yet." |
| Confirming an exposed secret is a currently working credential | Same: **complete and proven offline against recorded sample data; live use deferred** on a credential the customer supplies. |
| Google Cloud identity impersonation | Same: **built and wired offline; live use deferred** on credentials the customer supplies. |
| Container-platform role-binding and verb-grant confirmation (both tiers) | **Proven against a real Kubernetes cluster**, not only offline: a repository script stands up a genuine single-node cluster the system owns and destroys, plants dangerous and benign access rules, and adjudicates the real API responses through the production path — the dangerous binding confirmed with a certificate that re-verifies offline, the benign ones (including the namespace default identity bound to the built-in `admin` role, whose real rules do grant secret reads) correctly left as leads. Not covered by that run: enumeration of bindings across a cluster, and a managed provider's control plane (EKS, GKE, AKS). |
| Proving an identity can escalate its own permissions | A pure offline re-derivation over the operator's own retained permissions document, which **deliberately never performs the escalation** — a defensive verification test does not carry out the attack it is detecting. This one is not "awaiting live use"; not firing it is the design. |
| The stronger single-sign-on signature check | **Dormant** unless the operator supplies trusted identity-provider certificates and an optional library is available. The full, notoriously intricate rules for reducing a signed identity document to a single agreed byte-for-byte form before checking its signature are explicitly out of scope, and the chapter on identity says so too. |
| The general-purpose claim firewall | Its own documentation states it is currently the **primitive**, exercised by its tests, with runtime wiring phased in. It is **not today a universal gate that every claim in the system crosses.** The report layer *does* route every finding through it at render time. |
| Independent witnesses and external time anchoring | Transport and protocol **working**; genuine independence of the witnesses is a **deployment trust assumption** the code cannot prove, and is recorded as an open item. |
| Keys sealed at rest to hardware | **Working** where a Trusted Platform Module is present; the deployment guide is explicit that without one, keys are plaintext at rest, that this is acceptable on a trusted single-user machine and not on a shared host, and that the bootstrap prints a loud warning rather than silently degrading. |

**All six** of the cloud and Kubernetes exploitation capabilities share one further safety property
worth stating to any agency reader: **not one of them can fire during an ordinary scan.** There are
no exceptions among the six, and the point is worth being precise about, because "most of them"
would leave a reader wondering which one was the exception.

Two independent mechanisms produce that result. First, when the system meets a weakness class it
does not recognise, it falls back to a fixed set of general-purpose tests. That set is frozen at
fifteen members, and an automated tripwire fails the build if any newer test — including all six of
these — ever leaks into it. Second, each of the six keys on a specific piece of retained evidence
that no ordinary scan, benchmark, or engagement produces; with nothing of that shape in front of
them, they have nothing to judge. They fire only when their own component is invoked explicitly
over a deliberately gated capture. An autonomous loop cannot wander into using a cloud credential.

---

## 12. Evidence about the system's own build: the supply-chain safeguards

Everything above is about proving what the system *did*. There is a second half of the problem,
and a national agency will ask about it: proving that what the system is *built from* is what
was chosen.

These are the parts an attacker can change without ever touching this project's own code. A
starting container image quietly repointed at different contents. A compromised software package
pulled in indirectly, three levels down a chain of dependencies nobody reads. An external build
step repointed at a different version of itself. None of those produce a change anybody reviews,
and none of them leave a trace in the source code.

### Status of this section — read this before the five subsections below

**The work described in 12.1 to 12.5 is part of the released software, and the checks below now
run against every proposed change to it.** It was accepted into the released version on
12 August 2026 — the same day this chapter was written, and after the chapter's first draft, which
is why an earlier version of this text described the work as finished but not yet released, in the
way that a finished chapter is not yet a published book. It is released now.

That was confirmed directly, in the released version, at the time this revision was made: the
starting container images carry content fingerprints, both dependency lists carry a cryptographic
fingerprint on every entry, the automated build gate exists with its blocking step and its
self-test, and the written policy document is present. Section 12.7 gives the commands to repeat
those four checks without taking anybody's word for them.

Three boundaries belong in this same place rather than further down, so that nobody reads the five
subsections as a claim of completeness:

1. **The eight older build jobs still install loose version ranges rather than the fixed lists.**
   So the fixed lists are *checked* on every proposed change, but they are not yet what those older
   jobs *test against*. Converting them is named as the next follow-up and was deliberately kept out
   of this change rather than smuggled into it.
2. **Only the new gate's own external build steps are pinned to exact versions.** The eight older
   jobs still refer to theirs by a movable label. Same reason.
3. **The vulnerability gate blocks on the most severe class of finding, and had none to block on the
   day it landed.** It did report eight findings of the next severity down, across three packages,
   all advisory and none suppressed. The project's own document singles out one of them as "a real,
   actionable first-party finding" — a genuine issue in a component this software itself depends on,
   not merely one in third-party material kept alongside it.

   **That one has since been fixed.** The gate surfaced it on its first run; the repository's own
   version ceiling had been forbidding the published upstream fix; and a separate change, accepted
   into the released software less than half an hour later, raised that ceiling at all eight places
   it was declared, across both environments, so that no environment can resolve back onto the
   vulnerable release. That sequence — the gate finds a real issue in the project's own dependencies,
   the issue is recorded as advisory rather than quietly suppressed, and the issue is then fixed in
   its own reviewed change — is the control working once, in public. It is offered here as evidence,
   not as an assurance. The remaining advisory findings are in third-party material kept alongside
   this software, and the project's own written follow-up list names upgrading them and then raising
   the blocking threshold.

   Whether a gate that has never had anything to block means anything at all is a fair question in
   general, and section 12.4 sets out the separate answer built for it.

A reader verifying this independently should check the released software rather than taking either
this chapter's or the project's word for it. Section 12.7 sets out the four checks to run.

### 12.1 Starting container images are pinned by content, not by name

Modern software often ships inside a *container*: a sealed box holding the application together
with the operating-system pieces it needs. Every container is built starting from somebody else's
image, and that starting image is normally referred to by a label.

A label such as "Python 3.13, slim edition" is a **movable pointer**. It means "whatever the
supplier is serving under that label at the moment of the build". Re-pointing that label — whether
innocently or maliciously — silently changes what ships, with no difference for anybody to review
and no signal that anything happened.

A **content fingerprint** is different: it names the exact contents. The container system either
gets exactly those contents or the build fails outright.

Every starting image in the repository is pinned by content fingerprint. There are eight of them,
and they were checked individually in the released software: the gateway image, the defensive-side
image, the two evaluation-corpus images, the container used by the vendored agentic tool, and the
three supporting service images used in local deployment.

Two exemptions are written down as rules rather than left as unexplained holes: an *empty* starting
image has no content to pin, and images built from this repository itself have no external supplier
to pin to — their origin is the source tree. An automated test carries a deliberate counter-example
proving the checker still objects to an unpinned image, so a checker that had quietly stopped
working would be caught.

Floating "latest version" references hidden behind configuration variables were removed outright.
The reasoning is recorded: a floating reference behind a variable is exactly the drift the pinning
exists to stop, it made local deployment unreproducible, and nothing in the repository ever set
those variables. The versions chosen were the ones "latest" already resolved to on the day, so the
change altered nothing about how the software behaves.

Checking for **drift** — whether a supplier's label has since moved on to different contents — is
deliberately advisory and does not fail a build. The reasoning is worth reproducing: a supplier
re-pointing a label is not a defect in whatever change is under review, and a gate that turns red
for reasons its author cannot fix is a gate that gets switched off. Re-pinning is a deliberate act
taken after reading the supplier's release notes, not something done under the pressure of a broken
build.

### 12.2 Every third-party package is pinned to an exact file

Software is assembled from packages downloaded from public repositories. Two things can go wrong:
the version can drift, and the file itself can be swapped for a different one carrying the same
version number.

Both are closed the same way. Every third-party package the system installs is pinned to an exact
version **and** to a cryptographic fingerprint of the exact file, and the installation is performed
in a mode that requires those fingerprints to match. If a package file is substituted anywhere
between the public repository and the machine, the installation fails rather than proceeding.

There are two separate fixed lists rather than one, because the offensive engine and the sovereign
side must never share a running environment — a separation described in the architecture chapter —
and therefore cannot share a set of resolved packages either. Only third-party packages are on the
lists; the parts written by this project are installed from the source tree itself and have no
downloaded file to fingerprint.

The automated gate proves five things about each list, and the fifth is the one most similar
controls omit:

1. The human-written source specification can actually be resolved into a concrete set of packages.
2. The fixed list exists, contains real exact-version entries, and **every** entry carries a
   fingerprint. (Fingerprint checking is all-or-nothing: a single entry without one does not weaken
   the guarantee, it removes it, because the installer refuses the whole file.)
3. The fixed list is up to date with respect to that source specification.
4. The fixed list covers every package the specification directly names, so nothing is quietly
   installed unpinned.
5. Installing from the fixed list into a clean, empty environment **actually succeeds**. A list full
   of fingerprints that the installer rejects is a document, not a control.

The out-of-date check is deliberately narrow: it fails only when the source specification changed
and the fixed list was not regenerated. It does **not** fail merely because somebody published a
newer version of something today. The reasoning is again about keeping the control alive rather than
impressive — a check that turns red because of unrelated activity elsewhere in the world forces
whoever is on duty to upgrade dependencies under time pressure, which is how a security gate ends up
switched off. Available upgrades are reported separately, as information.

### 12.3 A software bill of materials

A **bill of materials** is a machine-readable list of every component that goes into a build — the
equivalent of the ingredients list on a food package. Customers, and increasingly regulators, ask
for one so they can answer "are we affected?" when a vulnerability is announced in some widely used
component.

One is produced for each of the two environments, in CycloneDX — one of the two widely used
published formats for writing such a list — and published as an output of the build.

It is **generated at build time rather than stored in the source repository**, because the fixed
package list is the stored source of truth, and a regenerated file checked in on every build is
noise that reviewers learn to skip past. The gate cross-checks the generated bill against the fixed
list, component for component, so a generator that silently dropped packages fails the build rather
than producing a confident-looking and wrong list.

One point of honesty about the source tree: an older placeholder file of the same name remains in
the repository from an earlier stage of the project, and it is plainly labelled inside itself as a
scaffold rather than a real bill of materials. It is not what the build produces and it is not what
the gate checks. A reader who finds it should not mistake it for the generated article.

### 12.4 A vulnerability gate that blocks on a CRITICAL finding

Every proposed change to the software is scanned against public vulnerability data.

| Severity | Behaviour |
|---|---|
| **CRITICAL** | **Blocks.** The build job fails and the change cannot be accepted. |
| HIGH | Reported in full in the build log. Advisory. |
| MEDIUM and LOW | Not surfaced by this gate. |

The scanner itself is pinned by version **and** by the fingerprint of its own downloaded release
archive, on the explicit reasoning that installing a security scanner from an unpinned location
would be its own supply-chain hole.

**The gate is proved to be capable of firing.** This is the part that deserves an agency reader's
attention, because it is the same discipline the rest of this chapter applies to findings. The gate
currently passes with nothing suppressed, because the software presently has no CRITICAL findings.
That is the right outcome — and it is indistinguishable from a scanner that has been misconfigured
into reporting nothing at all: a mistyped option, a severity word that matches nothing, a component
type the scanner silently skipped. So immediately before the real gate runs, the build runs the
**exact same blocking configuration against a deliberately planted set of packages with known
CRITICAL vulnerabilities, and requires it to fail.** If that passes, the build stops with an error
saying, in effect, "the gate below cannot fail, so its green tick means nothing". A gate that has
never fired is not evidence of anything.

One real configuration detail is recorded in the project's own document because it nearly made the
gate hollow: the scanner recognises dependency files by their *file name*, and by default it did not
recognise the two fixed lists this work exists to produce. The option that makes it read them is
described as "load-bearing, not tuning".

**The threshold choice is argued rather than assumed.** This repository deliberately keeps a copy of
a third-party penetration-testing toolchain and a systems-level component, and scans their
dependency files too. A gate that blocked on HIGH across that surface would need an exception list
large enough that nobody reads it — and an exception list nobody reads is worse than no gate,
because it converts findings into apparent approval. Blocking on CRITICAL while reporting HIGH in
full keeps the blocking set small enough that every entry is a decision somebody actually made. The
measured backlog when the gate first ran was eight advisory findings across three packages — small
enough, the project notes, to make raising the threshold genuinely reachable rather than
aspirational. The one of those that affected a component this software itself depends on has since
been fixed, as described in the status note at the top of this section.

**Every suppression must cost a sentence.** An entry that tells the scanner to ignore a finding must
carry a written justification directly above it, naming one of five permitted reasons: no fix has
been published upstream; the vulnerable code path is not reachable in the way this repository uses
the package; the component is present only in third-party or test material and never in anything
shipped; the advisory is disputed upstream; or the scanner has misidentified the component. An
automated test enforces this, with a deliberate counter-example proving it rejects a bare identifier
with no reason attached. The suppression list is presently empty.

### 12.5 External build steps are pinned to exact versions

The reusable steps a build pipeline calls are themselves somebody else's code, and they run with the
build's own credentials — which makes them one of the most attractive targets in the whole chain. In
the new gate, every one of them is pinned to an exact, immutable version identifier rather than to a
movable label, with the human-readable version left beside it as a comment, and a test asserts this
stays true.

The boundary, repeated from the status note above: **this applies to the new gate only.** The eight
older build jobs still refer to their external steps by movable label. Converting them is a separate
change with a wider blast radius — one wrong identifier and every job in the repository fails at once
— and it was deliberately kept out rather than smuggled in.

### 12.6 What these safeguards do not prove

The project's own document includes a section titled "what this does not prove", which is the correct
instinct. Reproduced in substance:

- **The eight older build jobs still install loose version ranges** rather than the fixed lists. So
  the lists are *checked* on every proposed change but are not yet what those jobs *test against*.
  Named as the next follow-up.
- **Software ecosystems other than Python** present in the tree are scanned for vulnerabilities but
  are not regenerated or fingerprint-verified by this gate; they are somebody else's artifacts.
- **Fingerprints prove a file did not change between being chosen and being installed. They do not
  prove it was published by whoever you believe published it.** That requires a publisher signature
  scheme, which is not wired in here and is listed as a later follow-up.
- **Starting-image drift is re-checked against one image supplier only.** An image hosted elsewhere
  is reported as unchecked rather than silently passed.
- **Drift and HIGH-severity findings are surfaced, not enforced.** That is a deliberate trade, argued
  above, not an oversight.

### 12.7 How to check this for yourself

The claims in this section are re-derivable in a few minutes by anyone with a copy of the software.
Nothing here needs the authors' cooperation.

- **Are the starting images pinned?** Run the repository's own offline checker, which reports any
  unpinned image and exits non-zero.
- **Are the packages pinned to exact files?** Open either fixed list and confirm that every entry
  carries a version *and* a fingerprint. In the released version read for this revision, the
  offensive engine's list held 26 exact-version entries carrying 640 fingerprint lines between them,
  with **no entry lacking a fingerprint**. There are several fingerprints per entry because a package
  is published in more than one packaged form, and any of them may legitimately be the one installed.
- **Does the gate exist and does it block?** Read the build definition. The blocking step, the
  planted-vulnerability self-test that runs immediately before it, and the fingerprint-pinned scanner
  installation are all in plain text.
- **Is the written policy honest?** The project's own supply-chain document carries the same "what
  this does not prove" section reproduced above, plus the current findings and the named follow-ups.

### 12.8 One word, two opposite meanings — do not conflate them

The system also has a **product** capability that reads a **customer's** dependency list against a
fixed snapshot of published advisories, in order to confirm that a specific vulnerable component is
present in the customer's software. That is this system testing somebody else's software, and it
applies the same prove-don't-guess discipline: a vulnerability match reported by any scanner is a
**lead** until the deterministic comparator re-derives, offline, that the concrete pinned version
really does fall inside the advisory's affected range — and refuses rather than guesses when it
cannot tell.

Sections 12.1 to 12.5 are about securing **this system's own** build. Same subject matter, opposite
direction. A reader should not read a claim about one as a claim about the other.

---

## 13. A reviewer's checklist

If you are handed a result from this system and asked to form an independent view, this is the
procedure:

1. **Obtain the trust-root fingerprint from the operator through a channel independent of the
   package** — their published register, a contractual annex, a separately signed communication.
   Do not use the copy inside the package for anything except comparison.
2. **Run the standalone verifier with that fingerprint pinned.** Confirm it exits sound. If you
   want to be certain the verifier is not secretly using the producer's code, run it with the
   `--prove-standalone` option, which refuses to proceed unless none of the producer's modules is
   even importable.
3. **Change one byte and run it again.** Confirm it fails. This takes thirty seconds and tells you
   more about the system than any amount of documentation.
4. **Run the reproduction step** with the open-source verifier to remove your dependence on the
   signer's honesty about each verdict.
5. **Read the "out of what" figure, not just the findings.** How many pages were reached. How many
   inputs were tried. Whether the exploration was cut short. Whether the effort budget ran out. A
   result is bounded by what was reached, and the certificate tells you what that was.
6. **Read the limitations paragraph on any clean or posture certificate.** It is written into the
   signed material precisely so it cannot be separated from the conclusion. CLOSED means
   non-exploitability by a named family of tests over a reached surface at a stated time. It does
   not mean secure.
7. **Check the registry of observation windows** for the ones your result depends on: what they are
   capable of today, what they must become, and what named engineering work is outstanding.
8. **Treat every LEAD as unproven.** The system is explicit about the distinction and never
   promotes across it. Neither should a reader.
9. **Ask what the evidence retention arrangement is.** The system applies none of its own. If the
   answer is "we keep everything indefinitely", that is a decision somebody should have made
   deliberately, and section 10.2 explains why the software will not make it for them.
10. **Ask separately about the build.** Request the bill of materials for the release you were
    given, the fixed dependency list it was built from, and the record of the vulnerability gate for
    that change. Those answer a different question from the findings — not "is this result true?"
    but "is this the software you think it is?" — and both questions matter.

---

## 14. Summary

- Evidence here means the **actual bytes** exchanged with the system under test, retained in full,
  written owner-only, with credential header values masked by name — and never the response body,
  because the body is usually the proof.
- Every result is decided by a **pure, deterministic, offline test** that reads no clock and uses
  no randomness. That is the property that makes independent re-checking possible at all.
- Each confirmed result is sealed into a **signed evidence certificate** that binds the verdict,
  the exact evidence, the raw file fingerprints, and the version of the test's own decision
  procedure.
- Certificates are linked into a **hash chain** with a signed head and an anti-rollback floor, so
  that removing, adding, reordering, or substituting an older report is detectable.
- A certificate is sound only if **all four** of authenticity, binding, artifact integrity, and
  reproduction hold.
- A **completely independent third party**, offline, with none of this software installed, can
  establish authenticity, binding, integrity, chain and anti-rollback using a standalone verifier
  built from a published specification — provided they pin the trust-root fingerprint obtained out
  of band. Re-running the automatic test itself requires the open-source verifier, and the project
  says so plainly instead of blurring it.
- **A single flipped byte anywhere flips the verdict to NOT SOUND**, and that is asserted by an
  adversarial tamper battery in which the standalone and in-tree verifiers must agree on every
  case.
- A **clean result** is treated as a much stronger claim than a finding, because it is. It is
  produced only where the observation channel was demonstrably capable of seeing the problem. Only
  6 of 26 registered observation windows may currently say "clean", every gap has named engineering
  work attached to it, and the certificate carries its own "out of what" figure and its residual
  limits inside the signed material. A further **six** windows carry a written declaration that they
  will never be clean-capable, because proving those absences is a different capability that is
  routed to the configuration-posture windows instead.
- **The one residual this design cannot close by itself** is that the evidence was collected by the
  party making the claim. A countermeasure — binding the captured bytes to the target's own
  encrypted session and having a separate party countersign — is **built and tested**, but the
  notary in the shipped version is software this system runs, so the project classifies it as a
  demonstrated mechanism rather than a closure, and says so on the face of its own status document.
- **Evidence is looked after by the operator, not by the software.** It is a few megabytes per
  engagement, written owner-only, kept indefinitely by default — there is no retention period and
  no deletion command — destroyable either by deleting the folder or by running in a mode that
  never writes it at all. Restoring a backup is safe for evidence and certificates, and there is one
  genuine trap: restoring an old or missing anti-rollback record silently weakens the "no older
  report substituted" guarantee without raising any error.
- The six cloud and Kubernetes exploitation confirmations are **complete and part of the released
  software** and wired end to end. **The two Kubernetes ones are proven against a real Kubernetes
  cluster** the system stands up, owns and destroys itself — the dangerous binding confirmed with a
  certificate that re-verifies offline, the benign ones in the same cluster correctly left as leads
  — with cluster-wide discovery of bindings and a managed provider's control plane (Amazon EKS,
  Google GKE, Azure AKS) outside what that run shows. The four cloud ones are proven offline against
  recorded sample data standing in for the real thing, and **three of them await use against a real
  third-party cloud account**, which waits on the customer supplying credentials to their own
  account — the detection logic, evidence handling, certificates and safety gates are all built and
  proven, and only the act of pointing them at a live outside account is pending. The fourth, the
  permission-escalation check, deliberately never carries out the escalation at all; that is a
  design decision rather than a gap. **None of the six can fire during an ordinary scan**, by two
  independent mechanisms. Other capabilities are similarly labelled as
  built-but-not-yet-used-against-a-live-outside-system in the registry, in the code, and in this
  chapter.
- The system's **own build** is hardened on the same principle: starting images pinned by content
  rather than by a movable name, packages pinned to exact files by cryptographic fingerprint, a
  generated bill of materials cross-checked against that fixed list, and a vulnerability gate that
  blocks a change on a CRITICAL finding while reporting HIGH in full — with a planted-vulnerability
  self-test proving the gate is capable of firing. **That work is part of the released software**,
  accepted into it on the day this chapter was written. Section 12 gives the boundaries that still
  apply — chiefly that eight older build jobs have not yet been converted onto the fixed dependency
  lists — and the commands to re-check every claim in it independently.
