# VIGIL: The Complete Guide In Plain English

*A complete briefing on the VIGIL security system, written for a senior reader with no software
background. Every statement in it was checked against the working software. Where something is built
but has not yet been used against a live outside system, it says so. Where something is deliberately
not built, it says that too.*

*This edition describes the software as it stood on **13 August 2026**, at the recorded version
`05b81e9f`. Two earlier versions are named because parts of the text were first written against them:
`1487e03a`, of 12 August 2026, against which the first draft of chapters 1 to 13 was written, and
`dc2994d6` of the same day, which is the version that first included the build-and-release safeguards
described in Chapter 1. Everything was then re-checked against `05b81e9f`, and Chapter 14 was written
new against it. Those version markers are recorded so that any statement here can be re-checked
against the exact software it describes.*

*What changed at the current version, so that a reader comparing editions can see it at a glance: a
second cloud capability was fired at something real, and it is the first of them to have judged
material from a genuinely outside system; an honest count appeared of how strong
the evidence behind each of the system's 41 confirming checkers actually is; a plain-language case
file became part of every delivered archive; an anti-replay guard was added to the owner's signed
decisions; the interface reached twenty-nine screens; and Chapter 14 was added, covering the half of
the product that holds the owner's key rather than the half that attacks.*

---

## Who this document is for, and how to read it

This document is written for intelligent senior readers who do not work in software: officials,
policy leads, procurement officers, legal and compliance staff, auditors, and the technical
evaluators who advise them. It assumes no knowledge of programming, security testing or
cryptography. Every technical word is explained in plain English the first time it is used, and every
one of them is also collected in the glossary at the end.

It is long, because it is complete rather than a summary. Nobody is expected to read all of it. The
routes below are the intended way in.

### If you have thirty minutes

Read the executive summary on the next page, then **Chapter 1**. Chapter 1 contains the whole
argument, the two conditions a public-sector reader must settle first, and an honest account of what
is finished and what is not.

### If you are an executive or a policy lead

1. **Chapter 1** — what the system is and the problem it solves.
2. **Chapter 4** — how the system decides something is real. This is the conceptual heart, and it is
   the chapter that explains why the output can be trusted differently from an ordinary security
   report.
3. **Chapter 10** — how individual findings are assembled into a picture of what an attacker would
   actually reach, and which single fixes break the most attacks.

### If you are a technical evaluator

1. **Chapter 2** — the parts of the system and the wall between them.
2. **Chapter 3** — one complete job from start to finish.
3. **Chapter 5** — the full catalogue of what it can find, with the honest limit of each item.
4. **Chapter 6** — evidence: how it is collected, sealed and independently re-checked.
5. **Chapter 13** — the defensive side, source-code review, and encrypted connections.
6. **Chapter 12** — the external tools it drives, and the practical prerequisites.
7. **Chapter 14** — the sovereign half: the part that holds the owner's key, keeps the owner's
   memory, and governs the offensive engine — and an honest account of which of its capabilities are
   actually running.

### If you are in procurement

1. **Chapter 1, section 6** — the licensing position and the built-in refusal to test government
   hosts. Both are commercial or product questions that must be settled before anything else.
2. **Chapter 12** — everything an organisation must supply: hardware, credentials, keys, network
   access, and what is deliberately not automatic.
3. **Chapter 9** — what an operator actually sees and presses, and which capabilities have no screen.
4. **Chapter 3**, under "What a real run costs: time, traffic and money" — the practical cost of a
   run in hours, in network traffic, and in money.

### If you are in legal, compliance or oversight

1. **Chapter 8** — written authorisation, scope enforcement, permission tiers, human approval, the
   emergency stop, and the audit trail.
2. **Chapter 7** — who vouches for a result, who holds which key, and what happens when one is lost.
3. **Chapter 6, sections 7 to 13** — handing evidence to an independent third party, what tamper
   evidence does and does not prove, evidence retention, and a reviewer's checklist.
4. **Chapter 5, Part 4** — which claims the system is permitted to state as a proved *absence*, and
   why that is deliberately harder than proving a problem exists.
5. **Chapter 14, sections 1 and 2** — where the authority to start, stop and attest actually sits,
   and why the record that holds it cannot be quietly edited.

### Three things to know before you start

- **Each chapter was written to be read on its own.** That is why a few core ideas — the four
  verdicts, the difference between a suspicion and a proved finding — are re-explained in several
  chapters. If you are reading straight through, skip the repetitions.
- **One small object recurs on almost every page.** The briefing calls it a **checker**: a small,
  fixed, non-intelligent program that looks at saved evidence and answers one narrow question the
  same way every time. The software's own name for it is an **oracle**, and some chapters also call
  it a judge, a referee, an automatic test or an assay. These are all one thing, not several. The
  glossary lists every such pair of names.
- **The honesty language is precise and worth reading precisely.** "Fully working", "built and proven
  offline", "live fire", "scaffold" and "refused" mean five different things throughout, and they are
  defined in the glossary under "Words about status".

### The companion file

A separate front-matter page, `00-index.md`, sits alongside this document in the same folder. It
carries a single consolidated status ledger covering all fourteen chapters at once, a note on how the
briefing was written, and instructions for re-deriving the load-bearing numbers from the software
directly. A reader who wants one page of status rather than one chapter should start there.

---

## Executive summary

**What it is.** VIGIL is a security testing system. Its job is to attack computer systems that its
operator owns, or has explicit written permission to test, in order to find the weaknesses before a
real attacker does. It uses artificial intelligence to decide what to try next. It does **not** use
artificial intelligence to decide what is true.

**The problem it solves.** Security tools produce claims, not evidence. Nobody downstream can tell
which claims are real without repeating the original investigation, so in practice claims are
believed or disbelieved on the reputation of whoever produced them. Recent AI-driven tools have made
this worse: fabricated findings read exactly like real ones. The result is that a security report is
testimony rather than evidence, and testimony is expensive to use and impossible to defend in front
of an auditor, a regulator or a minister.

**The one idea that makes it different.** In this system a claim is not a finding until a small,
separate, non-intelligent **checker** has independently re-proved it from the evidence the system
captured at the time. That checker has no network access, no clock and no randomness, so it gives the
same answer every time it runs. The evidence and the proof are then sealed into a signed certificate.
Anyone can re-run the check later, on their own machine, with no internet connection — and, for the
largest part of the check, without installing any of this system's software at all. If the check does
not come out the same, the claim is withdrawn automatically. The system does not remember that
something was true; it re-proves it every time it needs to say so.

**What the system is allowed to say.** Exactly four things: **FACT** (proved), **LEAD** (suspected,
not proved), **CLEAN** (conclusively disproved) and **INCONCLUSIVE** (we could not tell). "Probably
fine", "no issues found" and "secure" are not available outputs, and that restriction is enforced by
the structure of the software rather than by editorial policy. CLEAN is deliberately held to a higher
standard than FACT, because a false alarm wastes a day while a false all-clear means nobody ever
looks again.

**What it produces.** A single self-contained archive — the dossier — holding three written reports
(an executive summary, a technical report and a prioritised remediation plan), machine-readable
exports, the signed proof for every proven finding, the tamper-evident record of everything the
system did, and a fingerprint for every item, so that altering any part of it is detectable.

**The other half.** The product is not only an attacking engine. It ships as two deliberately
separated halves running as two separate programs, and the second one — which holds the owner's
signing key, keeps the owner's working memory as a tamper-evident record, and decides whether the
first one may act at all — contains no attacking capability whatsoever. That separation is what makes
the guarantees above worth anything: the half that attacks holds no key with which to forge a record,
and cannot be loaded into the half that does. Chapter 14 describes that half in full, including an
honest account of which of its capabilities are actually running on the machine this was written on
and which are built, tested, and waiting on hardware or software that is not installed.

**What bounds it.** Nothing touches a target without a signed written authorisation naming that
target. Every action passes a permission check in which every condition must hold at once, and any
failure — or any error — is a refusal. Actions are sorted into four danger tiers; the dangerous ones
are queued for a human, and irreversible ones require several independent signatures including the
owner's. A kill switch, held as a file on disk, halts everything and survives a restart. The
offensive half of the product holds no owner signing key at all, so it cannot forge a trusted record
even if it is completely compromised.

**Honest status.** The core proving pipeline is built and has been run from end to end on the
project's own machine, against a purpose-built deliberately vulnerable application — proven on a
local target, not proven in the field. A signed benchmark on that application reported eleven true
positives, no false positives and no misses, against comparison tools scoring zero, two and zero true
positives with zero, seven and eight false positives; the benchmark document's own fairness caveats
are carried forward in Chapter 1 and should be read with it. One live external run against a
vendor-published deliberately vulnerable test site is recorded.

The sharpest question to ask of a system like this is not how many things it can check for, but how
much of that has ever been tried against something real. Of its 41 kinds of confirming checker,
**three** have judged material a real outside system produced, **two** material from real
infrastructure the system builds and destroys for the purpose, **thirteen** material a real program
on the project's own machine produced, and **twenty** only saved sample material. Chapter 1 sets that
count out in full, including the one convention a stricter reader would apply differently.

Six cloud and container-platform exploitation confirmations are complete and part of the released
software, and three of the six have now been fired at something real, though not all at the same
kind of thing: the two container-platform (Kubernetes) ones against a real Kubernetes cluster the
system stands up, owns and destroys itself — real infrastructure, but the project's own rather than a
third party's estate — and the GitHub half of the exposed-secret check against the real GitHub
service, the only one of the six to have judged material from a real outside system, using the
evaluator's own credential against the least-privileged call that service offers. That
third one splits, and the split is not smoothed over anywhere in this document: the same capability's
Amazon Web Services half has never touched real Amazon infrastructure, and nothing from the GitHub
run transfers to it. The remaining cloud confirmations are proven against recorded sample data with
no internet connection, and what remains for them is the act of pointing them at a live third-party
cloud account, which waits on that customer's own credentials by design, because the system is built
not to obtain a credential any other way.

Safeguards over the system's own build are part of the released software, with one inventory file
inside the offensive engine still a self-declared placeholder. Several further capabilities are
scaffolds — the outline exists and the unimplemented part returns a clear error rather than a
plausible-looking answer — and each is named individually rather than folded into a general claim of
completeness.

**Two conditions a public-sector reader must settle first.** The free licence shipped with this
software **excludes government and public-sector use**; any use by, for, on behalf of, or funded by a
government body requires a separate commercial licence from the copyright holder. And the software
ships with a component designed to refuse government, military, educational and intergovernmental
addresses outright — a strong safety property, but also a practical constraint, because pointing the
system at an agency's own estate by domain name would require a deliberate change to the software,
and no supported route for that exists today. Both are covered in full in Chapter 1, section 6, and
the second is covered authoritatively in Chapter 8, section 2.5, including the honest finding that
this component could not be shown to be connected to the live testing path.

**Why the design is worth its cost.** Everything above makes the system slower and narrower than a
conventional scanner. Fewer things become findings; many suspicions stay suspicions; whole categories
of question return "we could not tell" where a competitor would return a confident answer. That trade
is the product. A finding can be acted on without re-doing the work, because the proof travels with
it. A report can be checked in a room with no internet connection. A supplier's security claim can be
tested without trusting the supplier — and without trusting the vendor of this system either. An "all
clear" means something specific and bounded, and the bound is written inside the signed document
where nobody can drop it. And where the system cannot yet prove something, it names the work that
would let it, rather than quietly narrowing its own definitions until every claim it makes is
technically true.

---

## Contents


**[Chapter 1. What This System Is, And The Problem It Solves](#chapter-1-what-this-system-is-and-the-problem-it-solves)**

- [A note on one word, before anything else](#a-note-on-one-word-before-anything-else)
- [The short version](#the-short-version)
- [1. The problem this system exists to solve](#1-the-problem-this-system-exists-to-solve)
- [2. The one central idea](#2-the-one-central-idea)
- [3. Proving the negative — the harder half](#3-proving-the-negative--the-harder-half)
- [4. What the system actually is](#4-what-the-system-actually-is)
- [5. Who it is for](#5-who-it-is-for)
- [6. Two conditions a government reader must settle first](#6-two-conditions-a-government-reader-must-settle-first)
- [7. What you get at the end of a job](#7-what-you-get-at-the-end-of-a-job)
- [8. What the system deliberately refuses to do](#8-what-the-system-deliberately-refuses-to-do)
- [9. Honest status: built, proven, and deliberately deferred](#9-honest-status-built-proven-and-deliberately-deferred)
- [10. Why this design is worth the cost](#10-why-this-design-is-worth-the-cost)
- [11. How to check this chapter, and where to go next](#11-how-to-check-this-chapter-and-where-to-go-next)

**[Chapter 2. The Parts Of The System And How They Fit Together](#chapter-2-the-parts-of-the-system-and-how-they-fit-together)**

- [0. One word you will meet on every page](#0-one-word-you-will-meet-on-every-page)
- [1. The one-page map](#1-the-one-page-map)
- [2. Why the system is split into parts at all](#2-why-the-system-is-split-into-parts-at-all)
- [3. The parts, one by one](#3-the-parts-one-by-one)
- [4. How the parts fit together: following one piece of work](#4-how-the-parts-fit-together-following-one-piece-of-work)
- [5. The wall down the middle](#5-the-wall-down-the-middle)
- [6. What runs where, and where the information is kept](#6-what-runs-where-and-where-the-information-is-kept)
- [7. What "self-hosted" and "sovereign" mean here](#7-what-self-hosted-and-sovereign-mean-here)
- [8. Honest status of the parts](#8-honest-status-of-the-parts)
- [9. A short glossary](#9-a-short-glossary)

**[Chapter 3. How A Security Assessment Runs, From Start To Finish](#chapter-3-how-a-security-assessment-runs-from-start-to-finish)**

- [1. The shape of a job](#1-the-shape-of-a-job)
- [2. Stage 0 — Written authorisation: the charter](#2-stage-0--written-authorisation-the-charter)
- [3. Stage 1 — The session: what it is and what it remembers](#3-stage-1--the-session-what-it-is-and-what-it-remembers)
- [4. Stage 2 — Setting up the run](#4-stage-2--setting-up-the-run)
- [5. Stage 3 — Pre-flight: before a single packet leaves](#5-stage-3--pre-flight-before-a-single-packet-leaves)
- [6. Stage 4 — Discovery: finding out what is there](#6-stage-4--discovery-finding-out-what-is-there)
- [7. Stage 5 — Mapping: building the picture](#7-stage-5--mapping-building-the-picture)
- [8. Stage 6 — Testing](#8-stage-6--testing)
- [9. Stage 7 — Confirming: the moment a claim becomes a fact](#9-stage-7--confirming-the-moment-a-claim-becomes-a-fact)
- [10. Why "we found nothing" is the hardest sentence in the report](#10-why-we-found-nothing-is-the-hardest-sentence-in-the-report)
- [11. Stage 8 — Building the attack picture](#11-stage-8--building-the-attack-picture)
- [12. Stage 9 — The report and the evidence package](#12-stage-9--the-report-and-the-evidence-package)
- [13. Stage 10 — Re-testing after the fix](#13-stage-10--re-testing-after-the-fix)
- [14. What can stop the job, at any moment](#14-what-can-stop-the-job-at-any-moment)
- [15. What is fully working, what is built but not yet used in the field, and what is planned](#15-what-is-fully-working-what-is-built-but-not-yet-used-in-the-field-and-what-is-planned)
- [16. What to take away](#16-what-to-take-away)

**[Chapter 4. Leads And Facts: How The System Decides Something Is Real](#chapter-4-leads-and-facts-how-the-system-decides-something-is-real)**

- [Why this chapter exists](#why-this-chapter-exists)
- [1. The two words that matter](#1-the-two-words-that-matter)
- [2. There are four words, not two](#2-there-are-four-words-not-two)
- [3. What a checker is, in plain words](#3-what-a-checker-is-in-plain-words)
- [4. The journey of a claim, step by step](#4-the-journey-of-a-claim-step-by-step)
- [5. Why the artificial intelligence is never allowed to promote a claim](#5-why-the-artificial-intelligence-is-never-allowed-to-promote-a-claim)
- [6. What happens when a check stops reproducing](#6-what-happens-when-a-check-stops-reproducing)
- [7. What "confidence" means here](#7-what-confidence-means-here)
- [8. Why "we found nothing" is much harder than "we found something"](#8-why-we-found-nothing-is-much-harder-than-we-found-something)
- [9. The same discipline, applied to the system's own supply chain](#9-the-same-discipline-applied-to-the-systems-own-supply-chain)
- [10. Why this eliminates the false-alarm problem — and precisely what it does not do](#10-why-this-eliminates-the-false-alarm-problem--and-precisely-what-it-does-not-do)
- [11. The chapter in one page](#11-the-chapter-in-one-page)
- [How the numbers in this chapter were checked](#how-the-numbers-in-this-chapter-were-checked)

**[Chapter 5. Every Type Of Weakness The System Can Find](#chapter-5-every-type-of-weakness-the-system-can-find)**

- [What this chapter is](#what-this-chapter-is)
- [How to read every entry in this chapter](#how-to-read-every-entry-in-this-chapter)
- [Part 1 — The 88 named types of weakness](#part-1--the-85-named-types-of-weakness)
- [Part 2 — The 38 tests that turn a suspicion into a proven finding](#part-2--the-38-tests-that-turn-a-suspicion-into-a-proven-finding)
- [Part 3 — Defensive detection: proving an attack happened from the customer's own logs](#part-3--defensive-detection-proving-an-attack-happened-from-the-customers-own-logs)
- [Part 4 — Which claims may be stated as a proven negative](#part-4--which-claims-may-be-stated-as-a-proven-negative)
- [Part 5 — What is fully working today, what is built but not yet fired in anger](#part-5--what-is-fully-working-today-what-is-built-but-not-yet-fired-in-anger)
- [Part 6 — The attack library behind the catalogue](#part-6--the-attack-library-behind-the-catalogue)
- [Part 7 — What this catalogue does not cover](#part-7--what-this-catalogue-does-not-cover)
- [Appendix A — The full vocabulary mapping](#appendix-a--the-full-vocabulary-mapping)

**[Chapter 6. Evidence: How It Is Collected, Shown, And Independently Re-Checked](#chapter-6-evidence-how-it-is-collected-shown-and-independently-re-checked)**

- [The problem this chapter solves](#the-problem-this-chapter-solves)
- [1. What counts as evidence](#1-what-counts-as-evidence)
- [2. Collection and storage: the sealed evidence bag](#2-collection-and-storage-the-sealed-evidence-bag)
- [3. Sealing: fingerprints, certificates, and the chain](#3-sealing-fingerprints-certificates-and-the-chain)
- [4. The four independent checks a certificate must pass](#4-the-four-independent-checks-a-certificate-must-pass)
- [5. What a finding report contains for a human reader](#5-what-a-finding-report-contains-for-a-human-reader)
- [6. The machine-readable outputs](#6-the-machine-readable-outputs)
- [7. Handing the evidence to an independent third party](#7-handing-the-evidence-to-an-independent-third-party)
- [8. What happens if a single byte is changed](#8-what-happens-if-a-single-byte-is-changed)
- [9. The clean result: proving there is nothing exploitable](#9-the-clean-result-proving-there-is-nothing-exploitable)
- [10. Looking after the evidence over time](#10-looking-after-the-evidence-over-time)
- [11. Honest status: what is working, what is proven offline, and what is deferred](#11-honest-status-what-is-working-what-is-proven-offline-and-what-is-deferred)
- [12. Evidence about the system's own build: the supply-chain safeguards](#12-evidence-about-the-systems-own-build-the-supply-chain-safeguards)
- [13. A reviewer's checklist](#13-a-reviewers-checklist)
- [14. Summary](#14-summary)

**[Chapter 7. Signatures And Keys: Who Vouches For A Result](#chapter-7-signatures-and-keys-who-vouches-for-a-result)**

- [Why this chapter exists](#why-this-chapter-exists-1)
- [1. What a digital signature actually is](#1-what-a-digital-signature-actually-is)
- [2. What exactly gets signed](#2-what-exactly-gets-signed)
- [3. The questions asked of every signed result](#3-the-questions-asked-of-every-signed-result)
- [4. Who holds which key](#4-who-holds-which-key)
- [5. How keys are protected while sitting on disk](#5-how-keys-are-protected-while-sitting-on-disk)
- [6. Losing a key, backing one up, replacing one, withdrawing one](#6-losing-a-key-backing-one-up-replacing-one-withdrawing-one)
- [7. Emergency stop, and where it sits relative to keys](#7-emergency-stop-and-where-it-sits-relative-to-keys)
- [8. "Several people must approve" — thresholds and m-of-n](#8-several-people-must-approve--thresholds-and-m-of-n)
- [9. The trust root, and why it must reach you separately](#9-the-trust-root-and-why-it-must-reach-you-separately)
- [10. The tamper-evident running record](#10-the-tamper-evident-running-record)
- [11. Rolling back to an older state — and the defences against it](#11-rolling-back-to-an-older-state--and-the-defences-against-it)
- [12. Honest status summary](#12-honest-status-summary)
- [13. What an assessor should ask the operator](#13-what-an-assessor-should-ask-the-operator)
- [Appendix A. The exact purpose labels](#appendix-a-the-exact-purpose-labels)

**[Chapter 8. Safety, Authorization, And What The System Refuses To Do](#chapter-8-safety-authorization-and-what-the-system-refuses-to-do)**

- [Why this chapter exists](#why-this-chapter-exists-2)
- [1. Nothing happens without a written authorisation](#1-nothing-happens-without-a-written-authorisation)
- [2. Scope enforcement: how the system refuses, and how it fails safe](#2-scope-enforcement-how-the-system-refuses-and-how-it-fails-safe)
- [3. Permission tiers: sorting actions by how much damage they could do](#3-permission-tiers-sorting-actions-by-how-much-damage-they-could-do)
- [4. The approval queue: where a human says yes](#4-the-approval-queue-where-a-human-says-yes)
- [5. Irreversible actions need several people](#5-irreversible-actions-need-several-people)
- [6. The emergency stop](#6-the-emergency-stop)
- [7. Not damaging the systems under test](#7-not-damaging-the-systems-under-test)
- [8. Staying away from real people's data](#8-staying-away-from-real-peoples-data)
- [9. The audit trail: everything is written down, and the record resists editing](#9-the-audit-trail-everything-is-written-down-and-the-record-resists-editing)
- [10. What the project has deliberately refused to build](#10-what-the-project-has-deliberately-refused-to-build)
- [11. Two halves that cannot become one](#11-two-halves-that-cannot-become-one)
- [12. Turning the question round: who could attack the system itself](#12-turning-the-question-round-who-could-attack-the-system-itself)
- [13. How the product's own build is assured](#13-how-the-products-own-build-is-assured)
- [14. Where the limits genuinely are](#14-where-the-limits-genuinely-are)
- [15. How an inspector can check this without taking anyone's word](#15-how-an-inspector-can-check-this-without-taking-anyones-word)

**[Chapter 9. Every Screen, And How An Operator Uses It](#chapter-9-every-screen-and-how-an-operator-uses-it)**

- [1. Before the tour: how the operator gets to a screen at all](#1-before-the-tour-how-the-operator-gets-to-a-screen-at-all)
- [2. The furniture that appears on every screen](#2-the-furniture-that-appears-on-every-screen)
- [3. Two words that appear on almost every screen: FACT and LEAD](#3-two-words-that-appear-on-almost-every-screen-fact-and-lead)
- [4. Group DO — the eleven screens for doing the work](#4-group-do--the-eleven-screens-for-doing-the-work)
- [5. Group MANAGE — the fourteen screens for running the system](#5-group-manage--the-fourteen-screens-for-running-the-system)
- [6. Group LEARN — the four screens for understanding and staying current](#6-group-learn--the-four-screens-for-understanding-and-staying-current)
- [7. Capabilities that have no screen at all](#7-capabilities-that-have-no-screen-at-all)
- [8. Where the interface is honestly incomplete](#8-where-the-interface-is-honestly-incomplete)
- [9. The other ways into the system](#9-the-other-ways-into-the-system)
- [10. The command line — the same system, typed instead of clicked](#10-the-command-line--the-same-system-typed-instead-of-clicked)
- [11. What a first session actually looks like](#11-what-a-first-session-actually-looks-like)
- [12. Summary of verified counts](#12-summary-of-verified-counts)
- [13. The single idea behind all twenty-nine screens](#13-the-single-idea-behind-all-twenty-nine-screens)

**[Chapter 10. The Target Knowledge Graph: Building A Picture Of The Attack](#chapter-10-the-target-knowledge-graph-building-a-picture-of-the-attack)**

- [1. Why the system draws a map at all](#1-why-the-system-draws-a-map-at-all)
- [2. The two building blocks: things, and connections between things](#2-the-two-building-blocks-things-and-connections-between-things)
- [3. Every entry on the map carries a label saying where it came from](#3-every-entry-on-the-map-carries-a-label-saying-where-it-came-from)
- [4. How the map grows without ever forgetting](#4-how-the-map-grows-without-ever-forgetting)
- [5. Where the map comes from: the signed record, and nothing else](#5-where-the-map-comes-from-the-signed-record-and-nothing-else)
- [6. How a confirmed finding becomes part of the picture](#6-how-a-confirmed-finding-becomes-part-of-the-picture)
- [7. Working out the chains](#7-working-out-the-chains)
- [8. "Crown jewels": the things that actually matter](#8-crown-jewels-the-things-that-actually-matter)
- [9. Ranking the routes](#9-ranking-the-routes)
- [10. Blast radius: what a foothold actually exposes](#10-blast-radius-what-a-foothold-actually-exposes)
- [11. Chokepoints: which single fix breaks the most attacks](#11-chokepoints-which-single-fix-breaks-the-most-attacks)
- [12. Keeping the map honest](#12-keeping-the-map-honest)
- [13. What the operator actually sees](#13-what-the-operator-actually-sees)
- [14. Five different pictures, named honestly](#14-five-different-pictures-named-honestly)
- [15. Per-job maps, and memory across jobs](#15-per-job-maps-and-memory-across-jobs)
- [16. The software supply chain on the same map](#16-the-software-supply-chain-on-the-same-map)
- [17. What is fully working, what is built but not yet fired at a live third party](#17-what-is-fully-working-what-is-built-but-not-yet-fired-at-a-live-third-party)
- [18. Summary in plain terms](#18-summary-in-plain-terms)
- [Notes and source references](#notes-and-source-references)

**[Chapter 11. The Automated Assistants, And How The System Improves](#chapter-11-the-automated-assistants-and-how-the-system-improves)**

- [1. What an agent is here, in plain words](#1-what-an-agent-is-here-in-plain-words)
- [2. The families of assistants](#2-the-families-of-assistants)
- [3. The investigation team — every agent, its job, its limits](#3-the-investigation-team--every-agent-its-job-its-limits)
- [4. The owner's personal mesh — nine agents, each with a ceiling](#4-the-owners-personal-mesh--nine-agents-each-with-a-ceiling)
- [5. The reasoning body, the parallel team, and the planners](#5-the-reasoning-body-the-parallel-team-and-the-planners)
- [6. The gates that bound every agent](#6-the-gates-that-bound-every-agent)
- [7. How the system learns](#7-how-the-system-learns)
- [8. The hard rules on learning](#8-the-hard-rules-on-learning)
- [9. Self-criticism and second opinions](#9-self-criticism-and-second-opinions)
- [10. Honest status summary](#10-honest-status-summary)

**[Chapter 12. The Tools It Uses, And What You Need To Run It](#chapter-12-the-tools-it-uses-and-what-you-need-to-run-it)**

- [Part One — The Tools It Uses](#part-one--the-tools-it-uses)
- [Part Two — What You Need To Run It](#part-two--what-you-need-to-run-it)
- [A one-page checklist](#a-one-page-checklist)
- [The one thing to take away](#the-one-thing-to-take-away)

**[Chapter 13. The Defensive Side, Source-Code Review, And Network Handling](#chapter-13-the-defensive-side-source-code-review-and-network-handling)**

- [The words used throughout this chapter](#the-words-used-throughout-this-chapter)
- [Part 1 — The Defensive Side (AEGIS)](#part-1--the-defensive-side-aegis)
- [Part 2 — Reading The Source Code](#part-2--reading-the-source-code)
- [Part 3 — Producing And Verifying A Fix](#part-3--producing-and-verifying-a-fix)
- [Part 4 — Encrypted Connections, Certificates, And Network Manners](#part-4--encrypted-connections-certificates-and-network-manners)
- [Part 5 — Proving A Fix Actually Worked](#part-5--proving-a-fix-actually-worked)
- [What A Reviewer Should Take Away](#what-a-reviewer-should-take-away)

**[Chapter 14. The Sovereign Side, In Full](#chapter-14-the-sovereign-side-in-full)**

- [1. Why there is a sovereign side at all](#1-why-there-is-a-sovereign-side-at-all)
- [2. The record as memory](#2-the-record-as-memory)
- [3. The knowledge graph, and the nightly pass that keeps it true](#3-the-knowledge-graph-and-the-nightly-pass-that-keeps-it-true)
- [4. Recall by meaning](#4-recall-by-meaning)
- [5. The agents — and exactly how many of them there are](#5-the-agents--and-exactly-how-many-of-them-there-are)
- [6. Seeing the screen, and why the reading is not trusted](#6-seeing-the-screen-and-why-the-reading-is-not-trusted)
- [7. Speaking to it, and pointing at it](#7-speaking-to-it-and-pointing-at-it)
- [8. The cockpit and the status overlay](#8-the-cockpit-and-the-status-overlay)
- [9. The memory server — giving any assistant cited recall](#9-the-memory-server--giving-any-assistant-cited-recall)
- [10. The mesh, and the phone](#10-the-mesh-and-the-phone)
- [11. What is proven on one platform, and what is a seam](#11-what-is-proven-on-one-platform-and-what-is-a-seam)
- [12. Learning from a page the owner points at](#12-learning-from-a-page-the-owner-points-at)
- [13. Honest status: what is working, what is built but not live, and what is absent](#13-honest-status-what-is-working-what-is-built-but-not-live-and-what-is-absent)

**[Glossary: Every Term In Plain English](#glossary-every-term-in-plain-english)**

- [1. The four words the system is allowed to say](#1-the-four-words-the-system-is-allowed-to-say)
- [2. The one object everything turns on — the checker](#2-the-one-object-everything-turns-on--the-checker)
- [3. The names of the parts](#3-the-names-of-the-parts)
- [4. Evidence, proof, and re-checking](#4-evidence-proof-and-re-checking)
- [5. Authorisation, permission and safety](#5-authorisation-permission-and-safety)
- [6. Signatures, keys and cryptography](#6-signatures-keys-and-cryptography)
- [7. The map of the target](#7-the-map-of-the-target)
- [8. The automated assistants, and learning](#8-the-automated-assistants-and-learning)
- [9. The vocabulary of weaknesses](#9-the-vocabulary-of-weaknesses)
- [10. Words about status: what is finished, what is not](#10-words-about-status-what-is-finished-what-is-not)
- [11. Everyday computing words](#11-everyday-computing-words)
- [12. Acronyms, standards and file formats](#12-acronyms-standards-and-file-formats)
- [13. Named outside programs you will meet](#13-named-outside-programs-you-will-meet)

---
