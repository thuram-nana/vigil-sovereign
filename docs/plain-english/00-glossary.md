# Glossary: Every Term In Plain English

This glossary covers every term a non-technical reader will meet in this briefing. Each entry is one
or two plain sentences. Nothing here assumes any software background.

**How to use it.** The entries are grouped by subject rather than listed in one long alphabetical
run, because most of the confusing words in this document belong to a small number of families, and
seeing a family together is easier than meeting its members one at a time. The groups are:

1. The four words the system is allowed to say
2. The one object everything turns on — the checker
3. The names of the parts
4. Evidence, proof, and re-checking
5. Authorisation, permission and safety
6. Signatures, keys and cryptography
7. The map of the target
8. The automated assistants, and learning
9. The vocabulary of weaknesses
10. Words about status: what is finished, what is not
11. Everyday computing words
12. Acronyms, standards and file formats
13. Named outside programs you will meet

Two conventions are worth knowing before you start.

- **Where the software's own word differs from the briefing's word, both are given.** The briefing
  does not rename what the screens display, so occasionally you will meet the software's own
  vocabulary. Every such pair is listed here.
- **British and American spellings both appear** in the chapters (authorisation / authorization, for
  example) because parts of the software use one and parts of the writing use the other. They mean
  the same thing.

---

## 1. The four words the system is allowed to say

Every conclusion the system reaches about a security question is one of exactly four words. There is
no fifth. This is enforced by the structure of the software: the list of possible verdicts is a
fixed, closed set in the code, so a phrase like "probably fine" cannot reach the output.

| Term | What it means |
|---|---|
| **FACT** | Proved. The stated weakness was established against the named target, at the stated time, from evidence the system captured itself. To say it, a fixed non-intelligent checker must have re-derived the result from that saved evidence, and the sealed document must re-check correctly with no internet connection. |
| **LEAD** | Suspected, not proved. Something points this way — another tool said so, a pattern matched, an artificial-intelligence model formed an opinion — but nothing was established. A lead is never written up as something an attacker can do. |
| **CLEAN** | Conclusively disproved. Under the stated conditions, on the surface actually examined, the weakness is not there. Harder to earn than FACT, deliberately. |
| **INCONCLUSIVE** | We could not tell. A real answer in its own right, reported as such, and never quietly rounded towards CLEAN. |

| Term | What it means |
|---|---|
| **Bounded** | Said of a FACT or a CLEAN: it describes what was established during one specific look at one specific configuration, not a timeless property. Like a vehicle roadworthiness certificate, which says the vehicle passed defined tests on a stated date. |
| **Demotion** | Moving a claim down — usually from FACT to LEAD — because its proof no longer holds up. Several parts of the system can demote a claim; none of them can promote one. |
| **Promotion** | Moving a claim up, to FACT. Only a checker firing over captured evidence can do this. Neither the artificial intelligence, nor the system's own learning, nor any outside tool has a route to it. |
| **False alarm (false positive)** | A reported weakness that does not actually exist. Every one costs a skilled person time to investigate and dismiss. Reducing these is the central purpose of the design. |
| **False all-clear (false negative)** | Reporting that something is safe when it is not. Treated throughout as the more dangerous of the two errors, because nobody goes back to look again. |

---

## 2. The one object everything turns on — the checker

| Term | What it means |
|---|---|
| **Checker** | A small, fixed, non-intelligent program that looks at saved evidence and answers one narrow question the same way every time. It has no opinions, no memory, no discretion, no internet access and no clock. Closer to a laboratory assay or a litmus paper than to a person forming a judgement. This is the briefing's standard word. |
| **Oracle** | The software's own name for a checker. It appears in the code, on some screens and in the machine-readable outputs, so the briefing keeps it wherever it quotes what the system itself says. It is an unfortunate name — it suggests prophecy, and this is the opposite of prophecy — but it is one object, not a second mechanism. |
| **Judge, referee, automatic test, deterministic test, decision procedure, assay** | Other words the chapters use for the same one object, depending on which property is being emphasised. None of them ever means a person or an artificial intelligence exercising discretion. |
| **Deterministic** | Same input, same answer, every time, on any machine. A recipe, not a chef: no judgement, no mood, no improvisation, no different answer on a Tuesday. |
| **Pure** | Said of a checker: its answer depends only on the evidence it was handed, and on nothing else — not the time, not a random number, not anything fetched from the network. |
| **Fires** | Ordinary shorthand for "the checker returned a positive answer". A checker that "stayed silent" returned nothing. |
| **Confidence** | A number a checker attaches to its answer. A finding is treated as confirmed only when a checker fires at 0.70 or above, and no checker may report more than 0.99 — the system's stated principle is that a mechanical test never claims certainty it cannot have. |
| **Skip, never an assumed pass** | The rule that if the evidence a checker needs is missing, the checker declines to answer rather than treating absence as good news. |
| **Frozen fallback set** | The fixed group of fifteen general-purpose checkers that may be used when the system meets a weakness category it does not recognise. Because the set is frozen, adding a new capability to the system cannot change what an existing scan does. |
| **Specialised checker** | Any of the remaining checkers. Each runs only when a very specific kind of evidence is present — of a kind an ordinary website scan never produces — so, for example, a checker built to confirm a stolen cloud credential cannot fire by accident during a routine website test. |

---

## 3. The names of the parts

| Name | What it is |
|---|---|
| **VIGIL** | The whole product: one control surface over two deliberately separated halves, one offensive and one personal. |
| **CRUCIBLE** | The offensive engine inside VIGIL. It explores an authorised target, probes it, and calls something a weakness only when a checker fires over the target's real output. |
| **AEGIS** | The defensive counterpart — the same proving machinery pointed inward at systems the customer runs. It detects and proves attacks using the customer's own records, and issues a re-checkable certificate rather than an alert. |
| **RAMPART** | The name used inside the code for AEGIS's inline protective gateway — the part that sits in the live traffic path in front of a web application and can block. Its stated distinguishing feature is not that it blocks, but that every block comes with a certificate anyone can re-run. |
| **SIGIL** | The sovereign, personal side: an assistant that runs on the owner's own hardware, remembers the owner's work in a tamper-evident record, can act on the owner's files and accounts under strict permission tiers, and contains no offensive capability at all. |
| **STRIX** | A *vendored* third-party autonomous testing tool (see "vendored") kept inside the product under its original Apache-2.0 licence. It is used as a source of suggestions only; nothing it says becomes a fact without passing the same checking as anything else. |
| **WARDEN** | The permission classifier: the component that sorts every proposed action into one of four danger tiers. |
| **OBSIDIAN** | The written operating doctrine given to the artificial intelligence when it drives the offensive engine — how to think, what to record, what never to do. |
| **The shared integrity core** | A small self-contained library that both halves stand on: the single implementation of the signed record, the cryptography, the permission classifier and the authorisation gate, so the two halves cannot drift apart. Think of it as the notary's office both sides use. |
| **The gateway (network)** | The outbound network gate: a deny-by-default firewall plus a filtering relay that together decide whether any packet may leave the machine. "Deny by default" means nothing gets out unless specifically permitted. |
| **The gateway (defensive)** | A different thing with a similar name: AEGIS's inline protective gateway, described under RAMPART above. Where the briefing means the network exit barrier it says so; where it means the defensive one it says "inline gateway" or "inline firewall". |
| **Fireteam** | The project's name for governed parallel workers — several bounded specialist helpers running at once, each capped below the destructive tier and unable to raise its own cap. |
| **Detection Mirror** | The part of AEGIS that takes an offensive action the system has just performed and proves, from the target's own logs, that the attack is visible there. The output is a signed certificate, not an alert. |
| **Proof Studio** | The screen on which the operator turns a confirmed finding into a package a client can check independently. |
| **Proof of Posture** | The screen and the certificate for the signed *negative* — a statement that a specific weakness class was checked on a specific surface and was not found, with an explicit statement of what was and was not covered. |
| **Trust Center** | The screen that displays the result of an independent, offline re-verification of a package, including whether the identity of the signer was anchored properly. |
| **Knowledge Engine** | The screen and subsystem that reasons over incoming vulnerability intelligence and drafts proposals for the owner. A proposal authorises nothing. |
| **Universal Target Intake** | A helper that takes a single piece of information about a target and drafts the paperwork for an engagement, so the operator does not start from a blank page. |
| **Command / VIGIL COMMAND** | The primary product interface: a single web application of twenty-eight screens covering assessment, learning and management. |
| **Ops Console** | An older, separate interface belonging to the offensive engine, of twenty-two screens, still present alongside the main one. |
| **Cockpit** | The sovereign side's own small web page, served on the operator's own machine at the address `127.0.0.1:8733`. It is where the owner's signing key, the approvals queue, the emergency stop and the stored service credentials live. |
| **Dashboard** | A word used in two ways. In the software it is the name of one read-only view over the signed record. In ordinary usage it means any summary screen. This briefing avoids the second sense; where it means the product's main interface it says "VIGIL COMMAND". |
| **Unified proxy** | The single web address a person points a browser at — `127.0.0.1:8770` on the operator's own machine — which passes each request on to whichever part of the system owns it. It exists so that one human faces one front door rather than three separate ones. It is brought up only by the operator's own "bring it all up" command. |

---

## 4. Evidence, proof, and re-checking

| Term | What it means |
|---|---|
| **Evidence** | The raw material the target actually produced — the exact replies, the exact values compared, the markers used — not the conclusion drawn from it. |
| **Retained evidence / oracle context** | The saved copy of exactly what the checker looked at, kept so the same test can be run again later and produce the same answer. This is the sealed evidence bag of the analogy. |
| **Fixture evidence / recorded sample data** | Saved, realistic material used in place of a live system, so a capability can be proved without touching anyone's real account. Like testing a smoke alarm with its test button rather than with a fire. |
| **Fingerprint (also hash, digest)** | A short code computed from a file's entire contents. Change one byte and the code changes completely, and it cannot be worked backwards to recover the file. Used throughout to detect substitution. |
| **Evidence certificate** | The signed document that binds a verdict to the fingerprint of the evidence it was drawn from. Altering the evidence breaks the match. |
| **Proof-Carrying Finding** | The portable, published form of a single finding: the finding, its evidence, its proof and its signature travelling together as one file, in a format whose specification is published so that others can write their own readers. |
| **Certificate of Non-Exploitability (posture certificate)** | A signed, item-by-item statement of CLOSED, OPEN or UNPROVEN for a named target. CLOSED has a narrow meaning: not exploitable by that family of checkers, over the surface actually reached, as of the stated date. It never means "secure against everything". |
| **Coverage certificate** | A signed record of which places were actually examined and whether a relevant checker really ran there — turning "nothing was reported here" into "this was provably tested". |
| **Remediation certificate** | A signed record that a weakness which provably worked no longer does. |
| **Dossier** | The single self-contained archive produced at the end of a job: the three reports, the machine-readable exports, every certificate, the record of what the system did, and a fingerprint for every item. |
| **Proof bundle** | A smaller package covering one finding or a selected set, exported so a recipient can check it on their own machine. |
| **Manifest** | The list inside an archive naming every item and its fingerprint, so that altering any single item is detectable. |
| **Offline verification** | Re-checking a result on a disconnected machine, with no internet connection, no account, and no contact with the people who produced it. |
| **Re-execution, not string trust** | The system's governing habit: rather than passing the word "confirmed" from one stage to the next, each stage re-runs the proof itself. The phrase to hold onto is that the system does not remember something was true — it re-proves it every time it needs to say so. |
| **Standalone verifier** | A small separate program that checks a package while importing none of this system's own code — only the standard library of its programming language and one cryptography library, written from the published specification. It contains no offensive capability and never touches the network. |
| **Evidence branch (also evidence window, evidence route)** | One specific way of seeing something — "in the reply's summary headers" as opposed to "in the body of the page". Different windows support different strengths of claim. Nothing to do with the software-development sense of the word "branch". |
| **Clean-capable** | Said of an evidence window sound enough to support "we looked and it is *not* there", rather than merely "we looked and found it". Only six of the twenty-six registered windows qualify. |
| **Conclusive** | A flag recorded against an observation meaning the look was good enough to support a negative answer. Without it, "found nothing" can only be reported as "could not tell". |
| **Coverage denominator** | What a clean claim was measured *out of*. Saying forty pages were checked means little until you know whether the application has forty pages or four hundred. Anything never discovered is outside the denominator and outside the claim. |
| **Freshness bound** | How recently the observation was made, stated inside the signed document, so a proved finding is "as of" a moment rather than forever. |
| **Freshness levels F1 and F2** | Two strengths of "this really came from the live target just now". The stronger one requires a fresh challenge to return through the very same channel the original weakness used. For a *fixed* weakness the stronger level is unattainable in principle, so the system caps at the weaker one rather than overstating. |
| **Positive control** | A check that the test itself still works: if the same test fires correctly on something known to be broken, then its silence on the real target means something. A smoke alarm you never test may simply be dead. |
| **Negative control** | Deliberately pointing a check at something known to be safe (or a safeguard at something known to be bad) to prove the check can still come out the other way. Without it, a clean result and a broken test look identical. |
| **Benign twin** | A deliberately harmless look-alike of a test input or a log entry, used to confirm a detector fires on the real thing and stays silent on the safe one. |
| **Residual** | A remaining doubt the evidence cannot rule out, written down explicitly rather than left implied. |
| **Provenance** | The recorded history of where a piece of evidence came from and how it was obtained — like the ownership history attached to a painting. |
| **Marker (also canary)** | A short, unique, harmless string of characters the system invents for one test only. If that exact string later turns up somewhere it should never be, the system knows precisely which test put it there. |
| **Payload** | The test input the system deliberately sends to see how the target reacts — the equivalent of the reagent a laboratory adds to a sample. |
| **Sink** | The place a piece of data finally ends up doing something: a database query, a command run on the server, a file the server opens, a part of a page a browser will execute. A weakness almost always means untrusted input reaching a sink. |
| **Insertion point** | A specific place in a request where a test input can be put — a form field, a header, part of the web address. |
| **Out of band** | Through a completely separate channel from the thing it concerns. An "out-of-band callback" means the customer's server made a connection to a machine the system controls — proof that something ran, arriving by a different road. |
| **Out-of-band relay** | A small server the operator hosts themselves that waits for a target to call out to it. Some weaknesses are invisible from the front and can only be proved this way. Without a relay, those checks are skipped rather than guessed. |
| **Tamper-evident** | Built so that alteration shows. Not the same as tamper-proof: the system does not claim a determined party cannot change a file, only that changing it will be detected. |
| **Hash chain** | The mechanism behind that. Each entry in the record begins by writing down the fingerprint of the entry before it, so removing or altering an old page breaks every page after it. The same idea as a bound ledger with sequentially numbered pages. Described in full in section 6 under "Chain". |
| **Ledger** | An ordinary word used in this briefing in its ordinary sense: a bound book of entries in order, which is what the system's records behave like. Two specific ledgers are named — the **usage ledger** (who ran the tool, when, and against what) and the **spend ledger** (which one-time authorisations have already been used up). |
| **Chain of custody** | The evidence-handling idea borrowed from law: an unbroken, recorded account of who held a piece of evidence and when, so that its integrity can be argued about later. Here it is provided by the append-only record rather than by signatures on a paper form. |

---

## 5. Authorisation, permission and safety

| Term | What it means |
|---|---|
| **Operator** | The person running the system. A competent technical professional; this is not a self-service product for a non-technical user. |
| **Owner** | The person who holds the top-level signing key and grants permissions. On the personal side, the individual the assistant works for. |
| **Charter** | The written, signed authorisation for one engagement: what may be tested, by whom, and until when. Nothing runs without one. |
| **Attestation** | A signed statement about a state of affairs — for example the operator's declaration that they own or have permission to test the named systems. |
| **Scope** | The set of targets an authorisation covers. Read literally: anything not named is refused, and an empty answer means refuse rather than allow. |
| **Engagement** | One authorised piece of work against one set of targets. |
| **Session** | A named, continuing body of work that can span several runs, keeping its own map of the target and its own history. |
| **Gate** | Any control that must be passed before an action happens. Every gate in this system can only say no. |
| **Conjunctive gate** | The combined permission check in which *every* condition must pass at once. One failure — or one error — refuses the whole action. |
| **Egress gate** | The control that decides whether a single packet of data may leave the machine. "Egress" simply means outbound. |
| **Fail-closed** | If a safety check cannot be completed — an error, an unreadable file, a missing answer — the result is "no". Like a drawbridge held up by an electric motor: cut the power and it falls shut. A check that says "allowed" when it breaks is worse than no check at all. |
| **Fail-open / best-effort** | The opposite: if the control cannot be applied, the work continues without it. The briefing names each place where this is the behaviour, and says whether it is a deliberate choice or a weakness. Two are deliberate choices: the defensive firewall forwards traffic rather than blocking it when its own inspection fails, on the stated rule that the firewall never takes your application down; and the confidence layer, which has no authority over any outcome, is skipped if it errors. The gates that decide whether an action may run fail *closed* — including the attachment of the gate on the vendored agent's shell, which stops the run rather than continuing without it. |
| **Tiers A0 to A3** | Four levels of how much damage an action could do: A0 observe only, A1 a reversible internal act, A2 externally visible or only partly reversible, A3 destructive, financial or security-relevant. The lowest two may run automatically; the higher two are queued for a human. |
| **Ceiling** | The highest tier a particular automated worker is allowed to reach. An agent cannot raise its own ceiling. |
| **Approval queue** | Where an action that exceeds what may run automatically waits for a person. The default is that each such action is approved individually and the approval is signed. |
| **Standing approval** | The weaker alternative: a blanket permission for a class of actions, offered but not the default. |
| **Kill switch (emergency stop)** | A file on disk which, while it exists, causes every action to be refused. Because it is a file rather than a setting held in memory, tripping it survives a crash or a restart, and any uncertainty about whether it exists reads as "halted". |
| **Dead-man's switch** | A cap on how long an authorisation for a dangerous action stays valid, so an approval left lying around expires by itself. |
| **Entitlement** | A signed permission slip that decides which capabilities a particular installation may use at all. It is tied to one machine, it expires, and it can be withdrawn. It answers the question "if this software is copied or stolen, what can the thief do with it?" — the answer being: only the safe baseline. |
| **Hard guardrail** | A categorical refusal of an entire class of targets by name — government, military, educational and intergovernmental addresses — which takes no settings and cannot be switched off. Built and tested; the briefing states plainly that no connection from it to the live testing path could be verified. |
| **Network floor** | A small list of network destinations that no authorisation can ever unlock: the address a computer uses to talk to itself, the addresses machines use to find each other on a local network, and the internal service that hands a cloud machine its credentials. |
| **Loopback** | The address a computer uses to talk to itself, usually written `127.0.0.1`. No other machine can reach it. |
| **Posture (pacing)** | How gently the system knocks: three operating speeds, from a slow, cautious pace against a live production system to a faster one against a purpose-built test system. Not to be confused with "posture" in the configuration sense below. |
| **Request budget** | A hard cap on how many requests a single piece of work may send, counted for the life of that work. |
| **Action budget** | A hard cap on how many actions an authorisation permits in total, independent of the request budget. |
| **Test artefact** | Anything the assessment created on the target — an account, an order, a file. Each is tagged so it can be found and removed afterwards. |
| **Ephemeral mode** | A setting under which captured material is not written to disk at all, for engagements where nothing should persist. |
| **m-of-n** | Several named key-holders, of whom a set number must agree before something happens. Like a vault that needs two managers' keys at once. |
| **Post-exploitation** | What an intruder does *after* getting in — moving sideways to other machines, staying resident, planting tools. The system deliberately does none of it. The plain summary: it proves a door opens; it does not walk through the building. |
| **Sandbox / container** | A packaged, isolated copy of a program and everything it needs to run, kept separate from the rest of the machine. The attacking tools run inside one, with no route to the internet except through the gate. |
| **Prompt injection** | Text placed on a web page or in a document that is aimed at the artificial intelligence reading it, in order to give it instructions. The reason the system's boundaries are ordinary code and firewall rules rather than instructions to the AI. |
| **Permission is infrastructure, not prompt** | The project's own phrase for that answer: the boundaries are enforced in places the AI cannot reach or argue with. |
| **Quorum** | The required group of separate signers. Where an action needs *m-of-n*, the quorum is the set that actually signed. The briefing states the limit of the idea plainly: separate keys are not the same as separate people or organisations, so if one party holds them all, the quorum is a formality rather than a control. |
| **Checkpoint** | Used in two different senses, and the briefing distinguishes them. A *permission* checkpoint is a place an action must pass through to be allowed — the same thing as a gate. A *progress* checkpoint is a saved marker written to disk while long work runs, so that an interrupted job can resume rather than start again. |
| **Playbook** | A written procedure describing how to test a particular kind of thing. Loading one adds advice to what the AI is reading; it grants no permission and authorises no action, and only files inside the designated playbook folder can be loaded. |
| **Penetration test (pentest)** | The established industry name for an authorised, deliberate attempt to break into a system in order to find its weaknesses before a real attacker does. It is what this system automates the evidence-handling side of. |
| **Triage** | The human work of going through a list of reported issues and deciding which are real and which matter. The briefing's central claim about cost is that this, rather than the testing itself, is where most of an organisation's security effort is actually spent. |
| **Throttling / pacing** | Deliberately slowing down. The system waits a fixed gap between requests so that testing does not behave like an attack on the target's availability. See "Posture (pacing)" above. |
| **Rate limit** | A cap the *target* imposes on how many requests it will accept in a period. Meeting one is normal, and the system paces itself to stay under it. |
| **Service credential (API key)** | A secret string that lets this system use somebody else's service — for example an artificial-intelligence provider, or a read-only view of a cloud account. They are supplied by the customer, stored on the owner's side, and each one is listed in the briefing with what it unlocks and what it cannot do. |

---

## 6. Signatures, keys and cryptography

| Term | What it means |
|---|---|
| **Key** | A secret number used to produce or check a digital signature. It comes as a pair: a private half that is kept secret and used to sign, and a public half that anyone may hold and use to check. |
| **Digital signature** | A short piece of mathematics attached to a document, proving that whoever holds a particular private key produced these exact bytes and that the bytes have not changed since. It does not, by itself, prove *who* that key-holder is. |
| **Trust root** | The one key everything else traces back to. Every other key in the system is blessed by it, directly or through a chain. |
| **Out-of-band pin** | The step that makes independent checking meaningful: the recipient obtains the trust root's fingerprint through a channel other than the package itself — a website, a letter, a signed email — and checks the package against that. It works the way a notary's specimen signature works: you do not verify a notarised document against the signature printed on the same document. |
| **Delegation** | The ceremony by which the owner's key blesses a working key, so that day-to-day signing does not require the top key to be present. |
| **Revocation** | Withdrawing a key's authority. The briefing states which forms of this exist and which do not. |
| **Rotation** | Replacing a key with a new one on a planned schedule. |
| **Escrow** | A safeguarded backup copy of a key, held so that losing the original does not lose everything it protects. |
| **Purpose label (domain separation)** | A short fixed tag mixed into the bytes before signing, so a signature made for one purpose cannot be lifted and re-used as though it were made for another. |
| **Canonical form** | One fixed, byte-for-byte way of writing a document down, so that two copies of the same content are identical and a signature over one is a signature over the other. |
| **Chain (append-only record)** | A record in which each entry seals the one before it, so a page cannot be removed or altered without breaking every seal after it. |
| **Spine** | The system's name for that append-only signed record of everything that happened. Entries can be added; they can never be edited or erased. |
| **Blackboard** | The shared working notice-board the automated assistants read from and write to. Also append-only. |
| **High-water mark / anti-rollback floor** | A small separate marker file recording how far the record has advanced, so that quietly rewinding the record to an earlier state is detectable. Its limits are stated openly: an attacker with full control of the same machine who rewrites both is closed off only by an outside witness. |
| **Monotonic** | Only ever moves forward, never back. Used of that high-water mark. |
| **Witness** | An outside party that countersigns the record, so that showing different versions of it to different people becomes detectable — and, where a strict majority of independent witnesses countersign, prevented. The project notes that separate keys are not the same as separate organisations: real independence is a property of how a customer deploys the system. |
| **Transparency log** | A published, append-only log that others can check, and in which membership of a single entry can be proved without downloading the whole thing. |
| **Merkle tree** | The mathematical structure that makes that possible: one short code covers a whole collection, and any single item can be proved to belong without revealing the rest. |
| **Timestamp authority** | An independent third party that attests a document existed at a given moment. |
| **Threshold signature** | See *m-of-n*: a signature that only counts when enough separate key-holders have contributed. |
| **Keyless trust domain** | The formal statement that the offensive half of the product holds no owner signing key at all. It can package a confirmed finding; it can never mint a trusted record, even if fully compromised. |
| **Root of trust** | The same thing as *trust root*, above. Both phrases appear; they mean the one key, or the one secret, that everything else depends on. Where an encrypted backup is concerned, the passphrase is the root of trust, because nothing else protects the file. |
| **Append-only** | A record to which entries may be added but from which nothing may be removed or edited. The property the system's history and its shared notice-board both have. |
| **Immutable** | Cannot be changed after it is written. Used of individual entries in an append-only record. |
| **Nonce / single-use marker** | A value that may be used once and only once. It is how the system stops a genuine, correctly-signed permission slip from being presented a second time. |

---

## 7. The map of the target

| Term | What it means |
|---|---|
| **Knowledge graph** | The living map the system builds of a target: the things it found, and the connections between them. Sometimes just "the map" or "the picture". |
| **Node (a pin on the map)** | One thing: a host, a web address, an account, a credential, a data store, a defensive control. |
| **Edge (a connection)** | One relationship between two things: "this account can reach that database", "this weakness affects that page". |
| **Provenance tier** | How strong the history behind a map entry is — from "a checker proved it" at the top, down to "something inferred it" at the bottom. A weaker tier can never overwrite a stronger one. |
| **Attack path (route, chain)** | A sequence of steps by which an attacker could get from where they start to something that matters. Stitched together from individual proven findings. |
| **Hop** | One step along such a route. Routes are capped at six hops. |
| **Crown jewel** | A thing on the map that actually matters to the organisation — the customer database, the payment system — as distinct from a machine that merely happens to be reachable. |
| **Blast radius** | What a single foothold actually exposes: everything an attacker could reach once they hold one particular thing. |
| **Chokepoint** | A single weakness that, if fixed, breaks the largest number of possible attack routes. The most useful output of the map for someone planning work. |
| **Technique** | A named attacker move, taken from the public catalogues, written down in a form a program can check and chain — with stated preconditions and stated effects. |
| **Attack tree** | A diagram drawn at the start of a job whose root is the attacker's goal and whose branches are the possible ways to reach it. A planning document. |
| **Threat model** | The written analysis of what an attacker would want, who would attack, and where the trust boundaries sit. |
| **Loudness** | How noticeable a route would be to a defender. Used to prefer a quiet route when the operator asks for one. |
| **Drift** | The differences observed between one run and the next: what appeared, what disappeared, what changed. |
| **Projection** | A copy of information rearranged into a more convenient shape. Derived from the record, disposable, rebuildable, and never allowed to feed a decision. |

---

## 8. The automated assistants, and learning

| Term | What it means |
|---|---|
| **Agent** | Here, a narrow specialised automated worker with one job, one output format, and a written set of things it is not allowed to do — enforced by the code, not by a policy document. Not a general-purpose robot. |
| **Artificial intelligence (AI)** | In this briefing it always means a large language model — software that produces fluent, plausible text. It is used to decide what to try next. It is never used to decide what is true. |
| **Large language model (LLM)** | The technical name for that kind of software. Its ordinary failure mode is to produce a confident, well-written description of something that is not there, which is precisely why the design keeps it away from verdicts. |
| **Propose** | What the AI and every external tool are allowed to do: suggest. Nothing more. |
| **Critic** | An automatic reviewer that examines a finding. Its possible verdicts are deliberately *endorse*, *object* or *abstain* — there is no *confirm* option, so a critic can make the bar higher but never promote anything. |
| **Reflection** | The system pausing to re-examine its own work in progress. It may re-order what to try next or defer something; it may never skip a surface or decide something is true. |
| **Refusal** | The path by which the system declines to make a claim the evidence does not support. |
| **Calibration** | Learning, from recorded past outcomes, how much confidence a given kind of signal actually deserves. Capped so it never reaches certainty, and it degrades to a plain pass-through rather than inventing a number when there is too little history. |
| **Prior** | A learned starting expectation — for example, how often a particular kind of signal has turned out to be real in the past. |
| **Learning (what it may change)** | Confined to deciding *where to look next*. It is structurally prevented from changing what the system claims to be true, from closing off a surface, and from granting itself permission. It is also off unless deliberately switched on. |
| **Proposal** | A drafted suggestion for the system's own improvement. Accepting one requires a specific granted permission, a passing run of the full existing test suite, and signatures from several independent governance holders — and even then a human being applies the change. |
| **Brain** | A pluggable planner that can propose what to do next. A proposal from a brain is still only a proposal. |
| **Reasoning body** | The general "think, act, observe" loop the AI runs inside, with each action passing the same gates as everything else. |
| **Executor** | The narrow component through which any action actually reaches the outside world, so that all the gates sit in one place rather than being scattered. |
| **Seam** | A deliberately narrow joint between two parts of the system, built so that only inert data crosses it and never running code. |
| **Hallucination** | The characteristic failure of a large language model: producing a confident, fluent, entirely invented statement. It is the specific danger the whole design is built around, which is why a model's opinion can never become a fact here. |
| **Veracity layer (anti-fabrication barrier)** | The component that takes a claim, re-runs the check the claim cites, and refuses to admit the claim if the check does not reproduce. It can only ever lower a claim; it has no power to raise one. The briefing is careful about its reach: it is wired into several real paths, including report generation, but it is not today a single universal checkpoint that every claim in the system must cross. |

---

## 9. The vocabulary of weaknesses

The full catalogue of 85 named categories is in chapter 5, with a plain meaning for each. These are
the terms that recur throughout the rest of the briefing.

| Term | What it means |
|---|---|
| **Weakness type (the code calls it a bug class)** | A named category of security flaw, such as "SQL injection". It is a label, nothing more. |
| **Injection** | The general family in which the customer's software takes text from an outsider and, instead of treating it as plain data, treats part of it as an instruction. |
| **SQL injection** | Injection into a database query. In the worst case it reads, changes or deletes the entire database, including every customer record. |
| **Blind injection** | The same flaw where the answers are invisible, so an attacker reconstructs the data one yes-or-no question at a time, or by measuring how long the server takes to reply. Slow, but complete. |
| **Command injection** | The attacker's text is executed as a command on the server's operating system. Effectively a foothold on the machine. |
| **Remote code execution** | The general category for "the attacker runs their own code on the customer's server". The most severe outcome in web security. |
| **Cross-site scripting** | The attacker's script runs inside another user's browser session — used to steal sessions, impersonate staff, or silently alter what a user sees. |
| **Server-side request forgery** | The attacker makes the customer's own server fetch a web address of the attacker's choosing. The standard route from the outside into a private internal network, and the standard route to cloud credentials. |
| **Path traversal** | The attacker walks up the directory tree and reads files the application never meant to serve: password files, configuration, private keys. |
| **Deserialization** | The server rebuilds a data structure from attacker-supplied data and, in doing so, runs attacker logic. A classic route to full server compromise. |
| **Template injection** | The customer's page-building engine evaluates an expression the attacker supplied. Frequently escalates to running code. |
| **Access control weakness** | Being able to do or see something you should not be allowed to — for example reading another customer's record by changing a number in a web address. |
| **Business logic weakness** | The software works exactly as written, and what is written is exploitable — for example applying a discount twice. |
| **Open redirect** | A page that can be made to forward a visitor to an attacker's website, which makes a phishing link look legitimate. |
| **Attempted injection (request-only)** | A separate, narrower judgement used by the protective inline gateway: proof that a hostile construct was genuinely sent. It makes no claim that the application was actually exploited — a properly built application receives these harmlessly every day. |
| **Memory safety** | A family of flaws in compiled software where a program reads or writes memory it should not, often leading to a crash and sometimes to an attacker running code. |
| **Supply chain** | Everything the software is assembled from: other people's components, fetched from public repositories, each standing on more. An attacker who changes what your build pulls in never has to touch your own code. |
| **Software bill of materials** | An itemised inventory of every component inside a piece of software — the ingredients list on the packet. |
| **Pinning (digest pin, hash-locking)** | Naming a component by the fingerprint of its exact contents rather than by a label somebody else can move. "This exact file", not "whatever is currently called latest". |
| **Vulnerability gate** | A check in the build that scans everything the software depends on against a public list of known vulnerabilities, and blocks the change if anything of the most severe class is found. |
| **CVE** | One entry in the public, internationally used catalogue of individual known software vulnerabilities. A report that a customer runs a component with a published vulnerability is treated as a lead until the system re-derives, mechanically, that the exact installed version really does fall in the affected range. |
| **Authenticated testing** | Testing the parts of an application that only appear after you log in. It requires the customer to supply genuine test accounts, and most of a real application's surface is behind a login. |
| **Fuzzing** | Sending very many variations of a test input at the same place and watching for the one response that behaves differently from the others. |
| **Replayer (the industry calls it a "repeater")** | Capturing one request to the target, editing it by hand, and sending it again. Here every replay goes through the same permission chain as everything else, and every refusal is recorded. |
| **Honeypot path** | A decoy address that no legitimate user would ever visit, so that anything fetching it is provably an automated crawler rather than a person. |
| **Posture (configuration)** | An assessment of how a system is *configured*, as opposed to what an attacker actually achieved against it. Weaker but safer: it reads an inventory rather than touching the live account. |
| **Achieved state** | The opposite: evidence that something was actually *done*. "This credential worked", rather than "this permission looks too broad". |
| **Detection engineering** | The defensive discipline of writing and assessing the rules that make an attack visible in an organisation's own monitoring. |
| **Attack surface** | Everything about a system an outsider can reach and therefore try to attack. |
| **Reconnaissance** | The first stage of any assessment: finding out what is there — which machines, which addresses, which pages, which services. No attack is attempted; the point is to know the shape of what you are looking at. |
| **Exploit (verb and noun)** | To make a weakness actually do something, and the piece of input that achieves it. This system proves a weakness is real with the smallest possible demonstration and then stops. |
| **Privilege escalation** | Turning limited access into greater access — an ordinary user account becoming an administrator, or a restricted cloud permission being used to grant itself more. |
| **Lateral movement** | Moving sideways from one compromised machine to others inside the same network. The system deliberately does not do it. |
| **Persistence (attacker sense)** | An intruder arranging to remain on a machine after a reboot or a password change. The system deliberately does not do it. |
| **Backdoor / implant** | Something an intruder leaves behind to get back in later. The system plants none. |
| **Weaponization** | Turning a proven weakness into a reliable attack tool. The system stops before this step, by design. |
| **Patch (verb and noun)** | The correction a software supplier issues for a flaw, and the act of applying it. "Unpatched" means a known correction exists and has not been applied. |
| **Hardening** | Changing a system's configuration to reduce what an attacker can do to it, as opposed to fixing a specific flaw. |
| **Subdomain** | A named part of a larger internet domain — for example `mail.example.com` under `example.com`. Organisations frequently forget the ones they stopped using, and forgotten ones are a common way in. |
| **Same-origin policy** | The browser's basic safety rule: a page from one website may not read data belonging to another. Several weakness categories are, at bottom, ways of getting around it. |
| **Port scan** | Knocking on each numbered door of a machine in turn to see which are open and what answers. |
| **Breach / incident** | A breach is an actual unauthorised access to data or systems; an incident is any event a security team has to respond to. This system is a testing system, not an incident-response system. |
| **Compliance** | Meeting the requirements of a standard, a regulator or a contract. The system can map its results onto published control frameworks, and it applies a hard rule when it does: an unproven suspicion is never counted towards a control. The output is explicitly not a certification, an accreditation, or a statement of compliance with anything. |

---

## 10. Words about status: what is finished, what is not

These five phrases are used consistently throughout the briefing and they mean different things.
Reading them precisely is the difference between an accurate picture and a misleading one.

| Phrase | Meaning |
|---|---|
| **Fully working, exercised end to end** | Built, and actually run from beginning to end on this machine, producing real output. |
| **Built and proven offline** | Built, and proven correct against recorded sample data standing in for a live system. Never yet pointed at a real outside system. |
| **Live fire** | The act of running a built capability against a real system rather than against recorded sample data. Where that real system must belong to somebody else — a cloud account — several capabilities in this system are complete and await it by design, because they need a credential only the customer can supply. Where the system can create the real thing itself, it does: the Kubernetes confirmations are proven against a genuine cluster the system stands up, owns and destroys, which is also what makes that proof re-runnable by anyone. |
| **Scaffold** | An interface exists; the thing behind it is not implemented. The system reports a clear error rather than returning a plausible-looking answer. |
| **Refused** | Deliberately not built, for a stated reason. Not an oversight. |

| Term | What it means |
|---|---|
| **Capability, not a deployment** | Something the software can do, which has not yet been done in the field. The briefing marks these rather than blurring them into "working". |
| **Blocking work** | The specific piece of engineering that would close a named gap. The project's own rule is that a gap must name it; a gap with no named work fails an automated check. |
| **Part of the released software** | The work is finished and folded into the version an operator would install. |
| **Written and working, but not yet released** | The code exists, can be read and run, and passes its tests, but is not yet in that version — in the same way a finished chapter is not yet a published book. |
| **Branch / merged / main line** | Software-development vocabulary that occasionally survives into the text. A *branch* is a separate working copy of the software; *merging* it into the *main line* is the step that makes the work part of what customers get. |
| **Pull request** | A proposed change to the software, raised so that a human reviews it before it becomes part of the product. |
| **Claim discipline** | The project's written rule that a claim must be true today, and that where a claim is not yet true the gap must be named as engineering work rather than resolved by quietly softening the claim. |

---

## 11. Everyday computing words

| Term | What it means |
|---|---|
| **Target** | The computer system being tested. |
| **Host** | One machine, identified by a name or a numeric address. |
| **Endpoint** | One specific address on a system that accepts requests — a page, a form, a service. |
| **Request and response** | The two halves of a web conversation: what the browser asks for, and what the server sends back. |
| **Header** | The summary information attached to a request or a response, separate from the visible content. Because headers can be read completely from beginning to end, several of the system's strongest claims rest on them. |
| **Body** | The visible content itself — the page text, the data. |
| **Crawl** | Following a site's links page by page to build a list of everything reachable, the way a search engine indexes a website. |
| **Port** | A numbered door on a machine. Different services listen at different doors. |
| **Proxy** | Software that sits between two parties and passes traffic along, usually so it can be inspected or filtered. |
| **Firewall** | Software or hardware that decides which network traffic is allowed through. |
| **Web application firewall** | A firewall specifically for web traffic, which blocks requests that look like attacks. |
| **Container** | A packaged, isolated copy of a program and everything it needs to run. |
| **Base image** | The starting point a container is built from, published by somebody else. |
| **Kubernetes** | The standard software for running and coordinating large numbers of containers across many machines. It is the control layer under most modern cloud deployments. |
| **Cloud account** | An organisation's holding with a cloud provider, inside which its machines, storage and permissions live. |
| **Metadata service** | An internal service inside a cloud environment that hands a machine its credentials on request. A frequent target, and permanently on the network floor. |
| **Credential** | Anything that proves identity to a system: a password, a key, a token. |
| **Token** | A time-limited credential issued after a successful login, used instead of re-sending a password. |
| **Session (a user's)** | A logged-in period. Stealing a session token lets an attacker act as that user without knowing the password. |
| **Single sign-on** | Logging in once to reach many systems. |
| **Repository** | The stored, version-controlled collection of a project's source code and documents. |
| **Source code** | The human-readable text a program is written in, before it is turned into something a machine runs. |
| **Symbol index** | A map of a codebase: every function and variable, where it is defined, and everywhere it is used. |
| **Static analysis** | Reading source code to find problems without running it. In this system its output is always a lead, never a fact. |
| **Dataflow analysis** | Following a piece of data through a program to see where it ends up. |
| **Air-gapped** | A machine with no connection to any outside network at all. |
| **Self-hosted / sovereign** | Run entirely on hardware the organisation controls, with nothing sent to an outside company. |
| **Idempotent** | Running it twice does nothing extra; it is safe to press again. |
| **Vendored** | A copy of somebody else's software kept inside this one, with its original licence and credits intact. |
| **Telemetry** | Measurement data a system produces about itself. |
| **Log** | The record a system keeps of what happened to it. The defensive side reads these to prove an attack was visible. |
| **Dual-licensed** | Offered under two alternative sets of terms, with the user taking whichever applies to them. Relevant here because the free terms exclude government and public-sector use. |
| **Open source** | Software whose source code is published, so anyone may read it, check it and usually re-use it under stated terms. Publishing source code is not the same as giving unrestricted permission to use it; see "dual-licensed". |
| **Command line (terminal)** | The typed way of driving a computer: you type an instruction, press return, and read the reply, instead of clicking. Several of this system's capabilities are available only this way and have no screen, and the briefing says which. |
| **Cookie** | A small piece of data a website asks a browser to keep and send back on every later request. It is normally how a site remembers you are logged in, which is why stealing one is equivalent to stealing a session. |
| **Authentication vs authorisation** | Two words that sound alike and mean different things. *Authentication* is proving who you are (logging in). *Authorisation* is what you are then allowed to do. A great many real weaknesses are failures of the second while the first works perfectly. |
| **Python** | The programming language most of this system is written in. It matters in only one place in this briefing: the independent verification program uses nothing but this language's own standard toolkit plus one cryptography library, which is what makes it checkable by an outsider. |
| **Interpreter** | The program that runs code written in a language such as Python. The briefing mentions it when describing a test that starts a *clean* interpreter — one that cannot reach any of this system's own code — to prove the verification program really does stand alone. |
| **Binary** | A program in the compiled form a machine runs, as opposed to readable source code. |
| **Service (daemon)** | A program that runs continuously in the background waiting to be asked for something, rather than being started for one task and finishing. |
| **Virtual machine** | A whole simulated computer running inside a real one, used to keep work isolated. |
| **Version control** | The system that keeps a project's full history of changes, who made each one and when. A *commit* is one recorded change; a *branch* is a separate line of work; *merging* brings a branch into the main line. |
| **Schema** | The written definition of what shape a piece of structured data must have — which fields exist, and what kind of value each may hold. Used here to make outputs machine-checkable rather than free text. |
| **Test suite** | The full set of automatic tests a project runs against itself. A *regression* is a fault that a change introduces into something that previously worked; the suite exists to catch these. |
| **Profile (deployment)** | A named selection of optional components to start — for example one that includes the optional graph database and telemetry collector, and one that does not. |

---

## 12. Acronyms, standards and file formats

None of these needs to be understood to follow the argument. They are listed because they appear in
the briefing, sometimes only in a table or a quoted phrase.

| Short form | What it stands for, and what it is |
|---|---|
| **AI** | Artificial intelligence. In this briefing it always means a large language model, never a checker. |
| **API** | Application Programming Interface. A way for one program to call another directly, without a person clicking anything. |
| **ASN.1** | Abstract Syntax Notation One. An old, precise format for writing down structured data, used inside cryptographic certificates. |
| **ATT&CK (MITRE)** | A public catalogue of the techniques real attackers use, maintained by the MITRE Corporation. Used to label what a detection would catch. |
| **AWS, Azure, GCP** | The three largest cloud providers: Amazon Web Services, Microsoft Azure, Google Cloud Platform. |
| **BOLA / IDOR** | Broken Object Level Authorization / Insecure Direct Object Reference. Two names for the same flaw: changing an identifier in a request and getting somebody else's data. |
| **Brier score** | A standard way of measuring whether stated confidence is honest. If you say "70 per cent sure" a hundred times, roughly seventy should turn out right. |
| **CAPEC** | Common Attack Pattern Enumeration and Classification. A public catalogue of attack patterns, companion to CWE. |
| **CIDR** | Classless Inter-Domain Routing. The standard shorthand for writing a *range* of network addresses. |
| **CORS** | Cross-Origin Resource Sharing. The browser rules that decide which other websites may read a site's data. Misconfiguring them exposes data to any site. |
| **CSRF** | Cross-Site Request Forgery. Tricking a logged-in user's browser into performing an action they did not intend. |
| **CVE** | Common Vulnerabilities and Exposures. The public numbering system for individual known software vulnerabilities. |
| **CVSS** | Common Vulnerability Scoring System. The industry's standard 0-to-10 severity score. |
| **CWE** | Common Weakness Enumeration. A public catalogue of *kinds* of software weakness, as distinct from individual instances. |
| **CycloneDX** | A standard file format for listing every component inside a piece of software. |
| **DNS** | Domain Name System. The internet's address book, turning a name into a numeric address. |
| **DOM** | Document Object Model. The live structure of a web page inside a browser, as opposed to the text the server sent. |
| **DSSE** | Dead Simple Signing Envelope. A standard wrapper that binds a signature to both the content and its stated purpose. |
| **Ed25519, RSA** | Two families of digital-signature mathematics. This system signs with the first. |
| **F1 score** | A single number combining two measures: how many of the things reported were real, and how many of the real things were found. Not to be confused with freshness level F1. |
| **GraphQL** | A modern style of interface in which the caller specifies exactly what data it wants. It brings its own family of weaknesses. |
| **HTTP / HTTPS** | The language browsers and web servers speak. The "S" means the conversation is encrypted. |
| **IAM** | Identity and Access Management. The part of a cloud account that decides who may do what. |
| **IMDS** | Instance Metadata Service. The cloud metadata service described above. |
| **IPv4 / IPv6** | The two formats of numeric internet address in use at once: the older four-number form, and the newer, longer form. |
| **ISO 27001** | An international standard for managing information security. |
| **JSON / YAML** | Two plain-text formats for writing structured data that both people and programs can read. |
| **JWT** | JSON Web Token. A common format of login token, carried by the browser and checked by the server. |
| **K8s** | A common abbreviation for Kubernetes. |
| **LDAP** | Lightweight Directory Access Protocol. The query language of corporate directory services, which holds staff accounts. |
| **LLM** | Large Language Model. See section 8. |
| **MCP** | Model Context Protocol. A published standard by which one artificial-intelligence system can discover and call tools offered by another. |
| **MD5, SHA-1, SHA-256** | Three fingerprinting algorithms. The first two are broken, and their presence is itself a finding; the third is the one this system uses. |
| **Merkle tree** | See section 6. |
| **NoSQL** | A family of modern databases that do not use the traditional query language. They have their own injection weaknesses. |
| **OIDC** | OpenID Connect. The standard behind "log in with…" buttons, in which one system vouches for a user's identity to another. |
| **OpenVEX** | A standard format for stating whether a known vulnerability actually affects a particular product. |
| **OWASP** | Open Worldwide Application Security Project. A non-profit that publishes widely used lists of the most important web application security risks. |
| **PCI-DSS** | Payment Card Industry Data Security Standard. The security rules that apply to handling card payments. |
| **RBAC** | Role-Based Access Control. Granting permissions to named roles, and then putting people or programs into those roles. |
| **RCE** | Remote Code Execution. See section 9. |
| **RFC 3161** | The internet standard for a trusted timestamp — a third party attesting that a document existed at a given moment. |
| **RFC 6962** | The internet standard behind public transparency logs. |
| **SAML** | An older single-sign-on standard, still widespread in large organisations. |
| **SARIF** | Static Analysis Results Interchange Format. A standard file format for tool findings, readable by most code-review platforms. |
| **SBOM** | Software Bill of Materials. See section 9. |
| **SCITT** | Supply Chain Integrity, Transparency and Trust. A standards effort for making supply-chain claims verifiable. |
| **SIEM** | Security Information and Event Management. The product a defender uses to collect and search their own logs. |
| **Sigma** | An open format for writing detection rules that work across different log-monitoring products. |
| **SOC 2** | An auditing standard, defined by the American Institute of Certified Public Accountants, covering how a service provider handles customer data. |
| **SPA** | Single-Page Application. A website that loads once and then rewrites itself as you use it. |
| **SQL** | Structured Query Language. The standard language for talking to a traditional database. |
| **SSO** | Single Sign-On. Logging in once to reach many systems. |
| **SSRF / SSTI / XSS / XXE** | Server-Side Request Forgery, Server-Side Template Injection, Cross-Site Scripting, XML External Entity. Four weakness families, each defined in section 9 or in chapter 5. |
| **TLA+ / TLC** | A formal language for writing down exactly what a system must never do, and the program that checks every possible case exhaustively. Used for this system's four machine-checked proofs, which are model-level assurance rather than proofs extracted from the code itself. |
| **TLS (formerly SSL)** | Transport Layer Security. The encryption behind the padlock in a web browser. |
| **TPM** | Trusted Platform Module. A small dedicated security chip on a computer's motherboard that can hold a key the rest of the machine cannot read out. |
| **URL** | Uniform Resource Locator: the address of a page or service on the web. |
| **VPN** | Virtual Private Network. An encrypted tunnel that makes a remote machine behave as though it were on your own network. |
| **WAF** | Web Application Firewall. See section 11. |
| **OpenTelemetry (often shortened to "otel")** | An open standard for collecting measurement data about how a system is running. Optional here, and started only under a deployment profile that asks for it. |
| **XML** | An older structured text format, still used inside many document and certificate standards. |

---

## 13. Named outside programs you will meet

The system drives a number of well-known third-party programs, and stores its own working data in
some standard ones. The names below are the ones that appear outside chapter 12. **Chapter 12
carries the complete roster** — every tool the system may run, which of them may contribute to a
proven finding, which may only suggest where to look, and which are excluded entirely — and it is
the authoritative list. Nothing here changes that: a tool's own output is a suggestion, and only two
of them (`nmap` and `sslscan`) can contribute to a proven finding at all, and then only because the
system re-does their work itself and judges its own record.

| Name | What it is, in plain terms |
|---|---|
| **`nmap`** | Knocks on a machine's network doors to see which are open and what is listening behind them. |
| **`sslscan`** | Checks what encryption settings a server will accept when a browser connects. |
| **`nuclei`** | Runs a large library of community-written checks for known weaknesses. Its results are suggestions only. |
| **`sqlmap`** | A well-known tool that automates attacking databases through a web site. Excluded from this system entirely; the system proves database-injection weaknesses with its own controlled test instead. |
| **`nikto`, `wapiti`, `ZAP`** | Three widely used web scanners. All three appear as report formats this system can read in and file as suggestions. The first two also appear as comparison tools in the published benchmark described in chapter 1. |
| **Burp Suite** | The best-known commercial web-testing proxy. The system can read its reports as suggestions. It is not required, and is deliberately not bundled. |
| **`semgrep`** | Reads source code looking for dangerous patterns. Its output is always a suggestion, never a proven finding. |
| **`trivy`** | Reads a project's list of software components and flags ones with published vulnerabilities. |
| **`gitleaks`, `trufflehog`** | Two tools that search a codebase for passwords and keys accidentally left in it. |
| **`chromium`** | A web browser run without a window, so the system can see a page exactly as a real browser would render it. |
| **`caido-cli`** | A tool for recording and replaying web traffic. |
| **Docker** | The standard way of packaging a program with everything it needs and running it in isolation. Optional for the core of this system; required for the vendored third-party testing tool. |
| **Neo4j** | A database designed for storing things and the connections between them. An optional external home for the map the system builds of a target. It is started only under the deployment profile that asks for it, it holds no secret, and it grants no permission. |
| **SQLite** | A database that lives in a single ordinary file, needing no separate server. Used for local working storage — for example the shared notice-board the automatic workers coordinate through. |
| **Qdrant** | A database that searches by similarity of meaning rather than by exact words. It is the search behind the sovereign side's memory and recall, and there is a built-in fallback that needs no separate container at all. |
| **Terraform** | A widely used text format for describing cloud infrastructure. It appears here as one of the languages the source-code review can read. |
| **Strix** | See section 3. A third-party autonomous testing tool kept inside the product under its original licence, used as a source of suggestions only. |
