# Completeness review — `docs/plain-english/`

**Reviewer role:** completeness critic. Two questions only: (1) does the briefing cover everything
the reader asked for, and (2) are there gaps a reader would trip over?

**Scope reviewed:** all 13 chapters, `01-what-this-is.md` … `13-defence-and-source-code.md`
(13,116 lines / 139,097 words), read end to end.

**Method:** read every chapter in full, then checked each claimed-absent capability against the
repository at `/home/kali/vigil` (HEAD `1487e03a`) with `ls` / `grep` / module docstrings, so every
"this is missing" below names a real subsystem that exists in the tree and quotes its own source.

**Not in scope:** whether the statements that *are* present are accurate — that is the accuracy
critic's job. I flag an accuracy-adjacent issue only where an omission makes a *present* statement
misleading (D3.1, C5, C15).

**Supersedes** the previous version of this file, which was written against an earlier revision
(11,826 lines). Findings that have since been fixed are recorded in Part G so the fix is not undone.

---

## Verdict in one paragraph

This is an unusually strong set. Sixteen of the reader's twenty-two requested topics are covered to a
standard I would call exhaustive, and the honesty discipline is applied consistently — every chapter
carries its own built / deferred / refused ledger and the ledgers are specific rather than
decorative. The gaps are of four kinds: **(1) no document-level front matter** — 139,000 words with
no index, no reading order and no entry point, which is the single thing most likely to make a
reader give up; **(2) one operationally decisive question the document raises three times and answers
nowhere** — whether an agency can point this at its own `.gov` estate; **(3) an under-covered
"backend / operate it" story**, which the reader explicitly asked for; and **(4) roughly twenty real
subsystems in the tree that appear in no chapter at all**, several of which — authenticated scanning,
the out-of-band relay, the entitlement system — are not merely omitted features but *missing
prerequisites* whose absence makes the described product harder to use and narrower than it is.

---

## Part A — Document-level gaps (highest priority)

### A1. There is no index, contents page, or reading order. **[BLOCKING for a briefing]**

A reader is handed a folder of 13 files named `01-…` to `13-…` totalling **139,097 words** — roughly
a nine-to-ten-hour read. There is:

- no `00-index.md` / `README.md` for the set;
- no statement of who it is for, what it covers, how long it is, or what order to read it in;
- no per-chapter one-line summary so a reader can jump to the answer they need;
- no short executive route ("if you read only three sections, read these") — which is exactly what a
  senior official at a national agency will want, and the material for it already exists in ch01's
  "In one page", ch04 §11 and ch06 §13;
- no statement of the commit, date, or method the briefing was written against **at the document
  level**. Individual chapters do this inconsistently: ch04 and ch06 name commit `1487e03a`; ch01
  §10 says counts were "re-derived from the source code at the repository's current state"; ch09
  §12 says "read out of the source code during the writing of this chapter"; chs 02, 03, 05, 07, 08,
  10, 11, 12, 13 say nothing;
- no "how to verify this document" page, even though ch01 §10 and ch06 §12 each contain most of one.

**Only chapter 1 identifies itself as part of a series** (`*Chapter 1 of the VIGIL briefing.*`).
Chapters 2–13 carry no chapter number and no series framing. Verified: `grep -n "Chapter [0-9]"`
matches only `01-what-this-is.md:3`.

### A2. Cross-references never say *which* chapter.

Every forward reference is of the form "covered in its own chapter" / "covered in their own
chapters" — 13 instances across chs 01, 02, 07, 10, 11 and 13, plus many looser variants. A reader
who wants the signing detail promised in ch01 §2.6 has to guess it is chapter 7. Once an index
exists these should all become "see chapter 7".

Ch01's closing paragraph is the acute case: as the de-facto entry point it names **eight** of the
twelve remaining chapters and silently omits four — evidence (06), safety and authorisation (08),
the agents and learning (11), and defence / source code / TLS (13).

### A3. No consolidated glossary.

Ch02 §9 has a good 13-term glossary of the proper nouns, but it is buried at the end of chapter 2,
and ch09 §6.3 records that the *in-app* manual has a glossary the briefing does not reproduce. Terms
defined in passing and then used across many chapters have no single home: *oracle context*, *spine*,
*blackboard*, *evidence branch*, *conclusive flag*, *coverage denominator*, *residual*, *freshness
bound* (and F1/F2), *provenance tier*, *crown jewel*, *chokepoint*, *posture*, *m-of-n*,
*out-of-band pin*, *benign twin*, *positive control*, *A0–A3*, *entitlement*, *fail-closed*,
*sink*, *payload*, *insertion point*.

The four verdict words are (re)defined from scratch in **seven** separate chapters (01 §2.8, 03 §9,
04 §2, 05 "How to read", 06 §1.4, 09 §3, 13 intro). That is defensible for standalone reading and
wasteful without an index that says the chapters are standalone.

### A4. No master status ledger.

Every chapter ends with its own honest-status section — the right instinct, done well. But there are
**13 partial ledgers and no consolidated one**, and they differ in granularity and membership:

- The cloud/K8s live-fire deferral appears in the ledgers of chs 01, 02, 03, 04, 05, 06, 09, 10 and
  12 — nine times, with nine slightly different wordings.
- Formal verification (`formal/`) appears in **no status table anywhere**, despite being the
  strongest assurance artefact in the repository (see C16).
- The CI pipeline appears in no chapter at all.

A national-agency reader wants one table: *fully working / built-and-proven-offline but not
live-fired / scaffold-that-raises / deliberately refused*, with a chapter pointer for each. It can be
assembled entirely from material that already exists.

### A5. The most consequential fact for this audience is raised three times and resolved nowhere. **[BLOCKING]**

The categorical `.gov` / `.mil` / `.edu` / `.int` block is discussed in three chapters:

- ch01 §5.2 — "a practical constraint: pointing the system at an agency's own `.gov` estate by domain
  name would require that floor to be changed";
- ch03 §5 — "an agency intending to assess its own `.gov` estate should expect to have to deal with
  it explicitly";
- ch08 §2.5 — "as written, the module would refuse to test a `.gov` or `.mil` host. An agency wanting
  to test its own systems with this tool would need that behaviour deliberately and explicitly
  revisited rather than quietly worked around."

All three also report that the module could not be found on the live engagement path. So the reader
is told three times, in three different chapters, that (a) there is a hard block on exactly their own
estate, (b) it may not actually be wired, and (c) something would have to be "revisited". **They are
never told what that revision is, who does it, whether it is supported, or what happens to the
guarantee if it is done.** For the stated audience this is the first operational question, and the
document raises it repeatedly and answers it in none of its 139,000 words.

This needs one authoritative subsection — most naturally in ch08 §2.5, referenced from ch01 §5.2,
ch03 §5 and ch12's checklist — stating plainly: what the block is, whether it is currently
load-bearing, exactly what an agency must change to test its own estate, what is lost by changing it,
and what compensating control replaces it. If the honest answer is "this is unresolved and needs
product work", say that.

---

## Part B — Requested-topic coverage matrix

| Reader asked for | Covered in | Assessment |
|---|---|---|
| Features and how they work | distributed | **Partial** — ~20 real subsystems missing, see Part C |
| **Backend** | 02 §6, 09 §1.2 | **Thin — the weakest requested topic.** See B1 |
| Frontend and every screen | 09 | Exhaustive |
| The parts (STRIX / AEGIS / CRUCIBLE / SIGIL) | 02 | Exhaustive for three; **STRIX is thin** — see B5 |
| Oracles | 04 §3, 05 Part 2 | Exhaustive |
| Tools integrated and usable | 12 Part 1 | Exhaustive on the catalogue; **silent on ingesting other tools' output** (C9) |
| APIs/keys needed for an operation | 12 §2.3 | Exhaustive on credentials; **misses two real prerequisites** (C1, C2) |
| How security is handled | 08 | Exhaustive **outward**; thin on VIGIL's own attack surface (B2) and silent on the entitlement system (C3) |
| Sessions | 03 §3, 09 §5.1, 10 §15 | Adequate but scattered across three chapters; no single home |
| Every agent type | 11 | Exhaustive for the three documented families; two families missing (C6, C12) |
| Knowledge graph | 10 | Exhaustive |
| How findings are made | 03 §9, 04 §4 | Exhaustive |
| Signing | 07 | Exhaustive |
| Key management | 07 | Exhaustive except **key loss / recovery** — see B3 |
| Offline verification outside the system | 06 §7, 07 §9 | Exhaustive |
| How evidence is generated and presented | 06 | Exhaustive except retention / backup (D6.2) |
| What leads are / how things become leads | 04 | Near-exhaustive; **one whole lead-production path missing** (C9) |
| Every bug class and its use | 05 | Near-exhaustive; **three families missing** (C4, C7, C8) |
| How the system learns | 11 §7 | Exhaustive |
| **How codebase scanning works** | 13 Part 2 | **Thin relative to the explicit ask** — see B4 |
| TLS | 13 Part 4 | Exhaustive on the target; **silent on post-quantum exposure** (C7) and on VIGIL's own TLS posture |
| **Offensive side end to end** | 03 | **Missing three stages and two whole test-generation axes** — see B6 |

### B1. "Backend" is the weakest-covered requested topic.

What exists: ch09 §1.2 names three processes and four ports; ch02 §6 has a "what runs where" table;
ch02 §3.2 describes the shared core's contents. What a reader asking for "the backend" cannot find:

- **The HTTP API surface.** Verified: `grep -ril "/api/\|HTTP API"` across all 13 chapters returns
  **nothing**. Every screen in ch09 is described by what it *shows*, never what it *calls*. There is
  also a fourth, separate programmatic server — the loopback-only gated API daemon (C10) — that no
  chapter mentions at all. A reviewer asking "what is the server-side attack surface of this product"
  has nothing to read.
- **Where state lives, and in what.** The evidence tree (`targets/<engagement>/evidence/<action-id>/`)
  is well covered in ch06 §1.1. Nothing describes the databases: the SQLite event spine / blackboard,
  the memory-learning store, the session registry, and the three optional container services in
  `docker-compose.yml` (Qdrant vector store, Neo4j, an OTel collector). Ch02 §6 names them as
  "optional supporting services (vector store, graph database, telemetry collector)" and ch12 calls
  Qdrant "the optional memory database" — but no chapter says **what each store holds**, which is the
  question a data-residency reviewer asks. Verified: `grep -ril qdrant` and `grep -ril embedding`
  match no chapter.
- **Deployment as a service.** `infra/systemd/` ships unit and timer files. Ch13 Part 5 says the
  re-prove "timer definition is built and deployable" without naming the units; the posture and
  witness units are unmentioned. Verified: `grep -ril systemd` matches no chapter.
- **Backup, restore, upgrade, uninstall.** Verified absent. No chapter says what to back up (the
  spine? the floor file? the keys? the evidence tree?), how to upgrade, or whether a signed chain
  survives an upgrade. This is load-bearing here in a way it is not for ordinary software, because
  ch06 §3.5 and ch07 §11 both explain that the anti-rollback floor *refuses* a smaller state — so a
  naive restore is an operational incident the document never warns about.
- **Multi-operator use.** Verified absent. The whole set reads as single-operator. A government
  reader will ask whether five analysts can share a deployment and how per-analyst attribution works
  beyond the usage attestation.

**Recommendation:** a new chapter ("What runs, where state lives, and how to operate it"), or a
substantial new section in ch02 plus an operations section in ch12. Do not scatter it further.

### B2. "How security is handled" covers outward safety, not the product's own threat model.

Ch08 is excellent on *not harming the target*. The inverse — *who could attack VIGIL, how, and what
stops them* — is answered only in fragments the reader must assemble: the CSRF marker header and Host
check (ch09 §1.4, two sentences, in the screens chapter); loopback-only binds and the IPv6 allow-list
(ch02 §6, ch09 §1.2); the CSP exemption for the legacy console (ch09 §9); the sandbox's read-only
host config residual (ch08 §12.7); symlink and size hardening in the verifier (ch06 §3.1); the
two-environment boundary (ch02 §5).

Missing entirely from ch08: the **entitlement system** (C3) — which is the actual answer to "what
stops a stolen copy of this software from being a working offensive tool" — and any account of how
the product's own build is assured beyond the supply-chain sections in chs 06 §11 and 12 §2.9.

### B3. Key loss and recovery is never answered. **[a reader will definitely trip here]**

Ch07 is otherwise the most rigorous chapter in the set. It correctly states that the key loader
*refuses to mint a replacement identity* if a sealed keypair cannot be opened, "because a fresh key
would silently orphan every record the old key ever signed" (§5). It never answers the obvious
follow-up. Verified: `grep -ril "recovery\|escrow\|lost key"` matches ch07 only at §13's line about
delegation windows.

- What does an operator do if the owner private key is lost, the TPM fails, or the machine dies?
- Is there an escrow or backup procedure, and if so how does it not defeat the TPM sealing?
- Do previously issued certificates still verify? (They should — verification is against public keys —
  but the document never says so, and after §5's warning a reader will assume the worst.)
- What is the response if the anti-rollback floor is lost, as opposed to corrupted? Ch06 §3.5 says a
  malformed floor raises rather than reading as absent, so a lost floor is an operational event with
  no documented procedure.

§13's assessor questions ask "where is the owner private key, physically" but never "and what is your
recovery plan". If the honest answer is "there is no recovery path; size your delegation windows
accordingly", say that — it is consistent with the document's discipline and far better than silence.

Secondary: §4 describes key holders in prose. A table (key → where on disk → who can read it → what
it signs → what happens if it is lost) would stop a reader losing the thread across owner key /
engagement-record key / governance key / `VIGIL_APPROVAL_OWNER_KEY` / `VIGIL_DESTRUCTION_OWNER_KEY` /
auto-patch key / the two shared secrets / the entitlement authoriser set.

### B4. Codebase scanning is thin relative to an explicit reader request.

Ch13 Part 2 covers the three analyser layers (built-in patterns / Semgrep taint / Joern), the
static-finding→hypothesis conversion, and the AI review loop with its honest "confirmed means
something different here" warning. Good material. What a reader asking "how does codebase scanning
work" cannot find:

- **Which languages** each layer supports. Only C/C++ is named, as a Joern strength.
- **How many built-in patterns**, over which languages. Every other catalogue in the document is
  counted; this one is not.
- **The symbol index.** It appears in the document exactly **once** — as the words "symbol index" in
  ch13's closing summary table — and is never explained in the body. A reader meets an undefined term
  inside a summary of something they never read about.
- **Repository secret scanning.** `trufflehog` and `gitleaks` appear once, in ch12's list of 24 tools
  inside the Strix container, with no link to codebase scanning — even though "exposed secret" is a
  class ch05 covers on the runtime side (`secret_credential_validity`).
- **Which of the two codebase paths runs when.** Ch13 Part 2 describes the `analysis` pipeline;
  ch13's last paragraph of Part 2 and ch09 §4.2 describe a "Scan a codebase" wizard mode that drives
  **Strix in Docker** and is lead-only. These are different mechanisms with different trust
  properties, and the document never contrasts them. **A reader choosing "Scan a codebase" in the
  wizard cannot tell which one they are getting.** This is the clearest reader-trips gap outside
  Part A.

### B5. STRIX is named as one of the four parts and is the thinnest of the four.

The reader explicitly asked for "the parts (STRIX, AEGIS, CRUCIBLE, SIGIL)". AEGIS gets ch13 Part 1;
CRUCIBLE gets chs 03–06; SIGIL gets ch02 §3.5 plus ch11 §4. STRIX gets ch02 §3.6 (20 lines), a
paragraph in ch09 §9, ch11 §5.4, and scattered lines in ch12 §§1.4/1.7. Nowhere does the document
say what STRIX actually *does*: how its agent loop works, what a codebase scan through it looks like,
what its 24 in-container tools are used for, how its findings appear to the operator, or why the
oracle layer does not run over its output (the last is asserted in ch02 §3.6 but never explained).
Given that it is the entry point for the "Scan a codebase" mode (B4), a reader who chooses that mode
is driving a component the briefing has not described.

### B6. The offensive end-to-end story drops three lifecycle stages and two test-generation axes.

Ch03 §1 presents ten stages and states that the engine's own `ENGAGEMENT-LIFECYCLE.md` "is described
in the same terms". It is not the same list. The engine's lifecycle has twelve stages, and ch03 has
no counterpart for three of them:

| Engine stage | In ch03? |
|---|---|
| **1. Threat model — where will adversaries push** (deliverables `threat-model.md`, `attack-tree.md`) | **Absent.** Verified: `grep -ril "threat model"` and `grep -ril "attack tree"` match **no chapter**. |
| **6. Post-exploitation (per ROE)** | **Absent as a stage.** The word appears once, in ch08 §3.1's tool-phase manifest. |
| **11. Engagement closure** | **Absent.** |

Threat modelling is stage 1 of the engine's own doctrine and produces two named artefacts; a
penetration-testing briefing that never mentions a threat model or an attack tree has a visible hole.
Post-exploitation matters more: it is the question a national agency asks second ("what does it do
once it is in?"), and the honest answer — that lateral movement, persistence and implants are
*hard-excluded* (ch11 §3.2's Tier-3 validation "creates no new attack payloads, establishes no
persistence, performs no lateral movement… refuse, never build"; ch08 §10's refusals table) — is a
**strength** that is currently scattered across two chapters and never presented as the answer to
that question.

The two missing test-generation axes are the Intruder fuzzing engine (C4) and the Repeater (C5).

---

## Part C — Real subsystems that appear in no chapter

Each verified present in the tree; quoted phrases are from the module's own docstring or README.
Ordered by consequence to the reader, not by size.

### C1. Authenticated scanning. **[most consequential omission in Part C]**

`engine/crucible/framework/v2/scanner/session.py` — "Most of a real app's attack surface is behind a
login… `AuthSession` wraps a raw `send` into an authenticated one that carries a cookie jar, performs
a login sequence, detects when the session has gone (a 401/403 or a logged-out marker), and
re-authenticates before retrying — Burp's session-handling in one composable object."

Verified: `grep -ril "authenticated scan\|re-auth\|cookie jar"` matches **no chapter**. Ch05 says the
access-control tests "require the operator to supply two genuine identities", which is the only hint
anywhere that the system can hold an identity at all. Ch12's day-one sequence and its "complete list"
of 17 credentials never mention supplying the *target application's* test-account credentials, and
ch09's five-step New Assessment wizard tour never shows where they would go.

Consequence: a reader finishes the briefing believing the product tests only the unauthenticated
surface of a web application. That materially **understates** the product, and it means an operator
following ch12's day-one sequence would run a first engagement against an application's front door
and never reach the interesting part.

Belongs in: ch03 Stage 2 (set-up) and Stage 6 (testing), ch05 (as a precondition on the access-control
and business-logic families), ch09 §4.2 (the wizard), and ch12 §2.3 and the one-page checklist.

### C2. The out-of-band relay (the self-hosted "Collaborator"). **[missing prerequisite]**

`engine/crucible/framework/v2/verify/oob.py` and `verify/collaborator.py` — "`verify.oob.OOBReceiver`
binds loopback only, so it confirms blind classes (SSRF, XXE, OOB SQLi, deserialization/JNDI) **ONLY
when the target is co-resident on the same host**. A real remote target's blind fetch cannot reach
loopback. This module is the sovereign answer to that gap — a Collaborator you HOST, not one you
rent"; the relay must run "on a host they own and have put on the engagement's charter allowlist".

Verified: `grep -ril collaborator` matches **no chapter**. Ch03 §8 gives this one clause — "The four
out-of-band ones run only when a call-back receiver is present — without one they are **skipped,
never guessed**" — and ch12 lists an "out-of-band callback secret" in its credential table with the
note "Authenticates certain call-back tests."

Consequence: four of the eleven always-on seed checks (SSRF, XXE, RCE, unsafe deserialization) plus
every OOB-confirmed class silently do nothing against a **remote** target unless the operator has
first stood up a relay on a charter-allowlisted host they own. That is a hard prerequisite for a whole
severity band of findings, and it appears in neither ch12 §2.5 (network access), nor ch12 §2.6 (day
one), nor the one-page checklist, nor ch09's wizard tour. An operator would run a remote engagement,
get no SSRF or RCE findings, and have no way to know why.

### C3. The entitlement system — controlled distribution and capability gating. **[missing governance story]**

`engine/crucible/framework/v2/entitlement/` — "Pillar 2: controlled distribution and capability
gating. The framework's most dangerous capabilities do not run merely because the code is present on
disk. They run only against a **threshold-signed, host-bound, unexpired, unrevoked entitlement**
issued by a governance authoriser set. Possession of the code without a matching entitlement yields
only the **safe baseline core**." There is a `crucible entitlement` CLI verb, a policy module, a
registry of capabilities and tiers, and a provisioning path.

Verified: the word "entitlement" appears in chs 01, 09 and 11 only as passing references —
"GOVERNED — capability entitlement is ENFORCED" (ch09 §5.13), `AEGIS_RESPOND` and
`DEEP_STATIC_ANALYSIS` (ch13), "entitlement" as one link in a gate chain (ch11 §3.4). **No chapter
explains what the system is.** A reader is never told: which capabilities are entitlement-gated, what
the safe baseline core can and cannot do, who the governance authoriser set is, that entitlements are
host-bound and expire, or that they can be revoked.

Consequence: this is the direct answer to the question every government buyer of an offensive tool
asks — *"if this software is copied or stolen, what can the thief do with it?"* — and the answer is
unusually good (only the safe baseline core). The briefing does not give it. It also leaves ch09
§5.13's GOVERNED/UNGOVERNED badge and ch13's `AEGIS_RESPOND` downgrade as unexplained jargon.

Belongs in: a new section in ch08 (or ch02 §3), referenced from ch09 §5.13, ch12 §2.3 and ch13.

### C4. Intruder — the fuzzing engine.

`engine/crucible/framework/v2/intruder/` — "the fuzzing engine (Burp Intruder, driven autonomously).
The scanner's checks place a *fixed* payload per bug class. Intruder is the other axis: many payloads
across marked positions, with the results triaged for the one anomalous response. Burp leaves that
triage to a human eyeballing a table; here an outlier detector does it, so brute-force, enumeration,
and race attacks run zero-manual." Three parts: payload-set generators (lists, numbers, brute-force,
null-payloads for race, bit-flipper, case/blocks, dates, runtime file), the four attack-type
combinatorics (sniper / battering-ram / …), and the triage.

Verified: no chapter mentions it (`grep -i intruder` matches only the burglar analogy in chs 08, 10
and 13). Ch03 §8 ("what it tests for") and ch05 Part 6 ("the attack library behind the catalogue")
both present the 11 seed checks plus 172 data-defined payloads as the whole test-generation story.
This is the second axis, and the automated-triage claim is a good illustration of the product thesis.

### C5. Repeater — the gated intercepting repeater.

`engine/crucible/framework/v2/repeater/` — "The Burp-Repeater equivalent, framed DEFENSIVELY: capture
a base HTTP request to an in-scope target, edit it, and REPLAY it — but never through a raw socket.
Every replay is routed through the existing fail-closed gate chain… ENTITLEMENT-GATED (Tier-2)…
SCOPE-GATED at BOTH the invoker and the executor… every refusal is recorded as evidence…
CORRELATABLE, NOT EVASIVE."

Ch13 refers to it once as "the replay tool — which lets an operator capture, edit, and re-send a
request" inside a paragraph making a point about user-agent stripping. It is never named, never
explained as a capability, and an operator is never told how to reach it (it is not among the 28
screens or the 26 `vigil` verbs). It is also a clean worked example of every safety property the
document argues for, applied to the single most dangerous thing an operator can do by hand.

### C6. gauntlet — the AI-Gauntlet offensive-LLM sensor family.

`integration/vigil_integration/gauntlet/` — drives garak / PyRIT / Giskard / promptfoo behind an
injected subprocess boundary and routes each candidate by OWASP-LLM `oracle_kind`: "`contains` /
`classifier` / `regex` (DETERMINISTIC) → an injected randomized-challenge oracle re-executes → a
confirmed one mints a signed FACT; **`judge_llm` (NON-DETERMINISTIC) → ALWAYS a LEAD, never
auto-promoted.**"

Two consequences. **(a)** Ch05 has no bug-class family for testing a *customer's own AI application*
offensively — Family 14 is explicitly the four *defensive* detections ("used in the system's
*defensive* mode, pointed inward"). For a chapter titled "Every Type Of Weakness The System Can Find",
that is an omission a reader with an LLM deployment will notice immediately. **(b)** The
`judge_llm` → always-LEAD rule is the cleanest available illustration of ch04's central thesis — the
same rule applied to *another model acting as a judge* — and it is unused.

The only trace in the document is a deferred-status line in chs 01, 03 and 12 ("AI red-teaming tools
as a source of facts — those tools are absent from this environment"), which tells a reader the
capability does not exist rather than that it is built, gated and awaiting the tools.

### C7. Post-quantum cryptography exposure.

`engine/crucible/framework/v2/scanner/quantum_era.py` — "quantum-AWARE crypto exposure + attack-path
portfolio optimizer. **Neither runs, simulates, or requires a quantum computer.** The name
'quantum-era' describes the *threat model* of capability (1), not the hardware. 1. POST-QUANTUM CRYPTO
EXPOSURE — a pure classifier over TLS primitive names plus a live stdlib-`ssl` probe."

Verified: `grep -ril quantum` matches **no chapter**. Ch13 Part 4 is a thorough treatment of TLS —
four deprecated protocols, ten weak-cipher markers, broken signature hashes, undersized keys — and
says nothing about post-quantum readiness. For a national-agency audience in 2026, PQ migration is an
active procurement and accreditation question, and silence on it reads as absence. The module is also
a good example of the document's own honesty discipline (it names itself carefully and disclaims the
hardware in its first paragraph), which makes leaving it out doubly unfortunate.

### C8. Session-token randomness analysis.

`engine/crucible/framework/v2/scanner/sequencer.py` — "session-token / nonce randomness analysis…
collect N tokens and detect the *clear* weaknesses that make a token guessable — it is
sequential/incrementing, it repeats, most of its characters are constant, or it draws on a tiny
alphabet — and report a lower-bound entropy estimate."

Not in ch05's catalogue, not in ch03's testing stage, not anywhere. Predictable session tokens are a
classic authentication finding and a reader auditing coverage against a standard checklist will look
for it.

### C9. imports — ingesting other tools' output as leads.

`engine/crucible/framework/v2/imports/` (and a `crucible imports` verb) — "Adapters that ingest a
THIRD-PARTY security tool's export (a Nuclei / ZAP / Burp / sqlmap report, or a generic findings JSON)
INTO the shared world-model as provenance-tagged OBSERVATIONS / leads — never as facts… It is
deliberately NOT a `FINDING` node — a FINDING is reserved for what a [deterministic oracle proved]."

Verified: `grep -ril importer` matches no chapter. This is directly responsive to two requested
topics — "the tools integrated and usable" and "what leads are and how things become leads" — and to
the practical question of how VIGIL slots into an agency's existing toolchain. Ch12 Part 1 describes
tools VIGIL *runs*; it never says VIGIL can also consume the output of tools an organisation already
runs, under the same lead-not-fact discipline. Ch04's account of where leads come from is
correspondingly incomplete.

### C10. api — the loopback-only gated API daemon.

`engine/crucible/framework/v2/api/` — "the LOOPBACK-ONLY, GATED external API / daemon… a programmatic
seam over CRUCIBLE for an operator to drive/observe it… every action through the SAME fail-closed
authority/entitlement/scope/egress chain as a local action… DEFAULT-SAFE: nothing runs unless the
operator starts it, it binds loopback only, and it exposes NO ungated capability."

Ch09 §9 frames the system as having exactly two ways in (screens, CLI) and lists "the three other
interfaces in the box" (all user interfaces). There are two further programmatic entry points — this
daemon and the MCP stdio server — and the MCP server has an entire screen (ch09 §5.8) without ever
being listed as an interface. A reviewer inventorying attack surface, or an integrator asking "can we
drive this from our own orchestration", will trip.

### C11. intake — the Universal Target Intake.

`engine/crucible/framework/v2/intake/` (and a `crucible intake` verb) — "Convert any web URL into a
fully scaffolded engagement folder under `targets/<slug>/`, with a **charter draft, draft threat
model, draft attack tree**, and a fingerprint JSON. Every step honours the ethics gates: no
scaffolding without operator-attested authorization; no active testing until the operator signs
charter.md." The pipeline runs a polite capped fetcher (50 requests, no auth, no fuzz) over
`robots.txt`, `sitemap.xml`, `security.txt`, the OIDC discovery document and a handful of standard
paths, then seven detectors → a fingerprint → a stack classifier → an archetype.

Ch03 Stage 0 and ch12 Step 6 both tell the operator to write the charter by hand from scratch. The
product automates the *draft* while preserving the signature gate, and the briefing does not say so —
so the described on-ramp is meaningfully harder than the real one. This is also where the missing
threat model and attack tree (B6) would naturally enter the document.

### C12. fsjob — governed filesystem / job / traffic tooling.

`integration/vigil_integration/fsjob/` — includes "the race-free path-confinement kernel… Traversal /
absolute / symlink / SYMLINK-RACE / NUL are all refused via an `openat` walk with `O_NOFOLLOW`, and
every fs operation runs over the safe fd, not a re-resolved string — **closing the TOCTOU the source's
`.resolve()` approach left open**", plus signed, append-only, *reversible* mutations with pre/post
state.

Ch11 §4 describes the OPERATOR agent's "two scope rings" and its journal-and-rollback behaviour as
policy. This is the mechanism that makes them sound, and it is exactly the class of detail the
document is otherwise excellent at surfacing.

### C13. confidence — the Scientific Confidence Engine.

`engine/crucible/framework/v2/confidence/` — "Makes every conclusion behave like a scientist's claim
instead of a scanner's verdict. A `ScientificHypothesis` carries an explicit prior, an `Evidence`
ledger (each datum weighted by likelihood-ratio × reliability × independence), a set of competing
`alternatives` (+ a residual 'none of these' mass, so the explanations are MECE), and… a Bayesian
posterior by log-odds accumulation, a credible interval that tightens with evidence, and **the single
highest-value next observation ('what would change my mind')**."

Verified: `grep -ril "Bayes\|credible interval\|Scientific Confidence"` matches no chapter. Ch04 §7
("What 'confidence' means here") carefully distinguishes two kinds — the in-oracle signal strength
and the separately learned calibration — and stops. There is a third, and it is the most
intellectually distinctive thing in the codebase for an assurance reader: an explicit prior, MECE
alternatives, and a machine-computed "what would change my mind". Its absence also makes ch04 §7 read
as complete when it is not.

### C14. socialdefense — defensive detection of social-engineering attacks.

`engine/crucible/framework/v2/socialdefense/` (and a `crucible socialdefense` verb) — "the inverse of
the Bucket-C capabilities the framework refuses to build: instead of *generating* phishing or
impersonation, this scores *inbound* content for the indicators of a social-engineering attack, to
protect an organisation's people. It is pure defence… Deterministic and offline: a curated indicator
set (urgency, credential harvesting, authority impersonation, lookalike domains, sender/reply-to
mismatch, financial-action requests, secrecy requests, dangerous attachments) yields a weighted risk
score and a recommendation", explicitly "*leads for a human or a downstream classifier*, not verdicts
— phishing detection is probabilistic, and the recommendation says so."

Absent from ch13, the defensive chapter — yet ch09 §9 lists "social defense" as a legacy-console
screen, so a reader meets the name with no explanation anywhere. It is also a strong illustration of
the doctrine (build the defensive inverse of the offensive capability you refuse to ship) and of the
lead/fact discipline applied to a genuinely probabilistic domain.

### C15. channel_binding — binding evidence to the target's own TLS session.

`integration/vigil_integration/channel_binding.py` — "bind a finding's response bytes to a TLS SESSION
so a third party can confirm the TARGET (not the producer/VIGIL) produced them… A retained
`oracle_context` today carries the target's response *bytes* and a producer signature over them. That
proves VIGIL *asserts* those bytes came from the target — it does NOT stop a dishonest producer from
FABRICATING a response the target never sent… Z1's goal is a fact whose response bytes are tied to a
specific TLS session and CO-SIGNED by a NOTARY, so the standalone verifier confirms them OFFLINE
without trusting the producer."

This attacks **the single residual limit the document states most often**: "re-execution proves the
verdict follows from the evidence, not that the evidence reflects the live target" (ch04 §10, ch06
§8.2, ch06 §9.5, ch05 Part 4). Ch06 §8.2 even writes the sentence that should introduce it —
"Establishing that independently requires a fresh live re-run, **or a capture channel bound to the
target's own cryptographic identity**" — without saying the system has one.

This is an *under*-claim, so it does not mislead. But for a completeness brief it is the most valuable
omission in the set: the document repeatedly names a weakness whose in-tree countermeasure it never
mentions. It needs an honest status line (built; notary independence is a deployment assumption),
not silence.

### C16. formal — machine-checked models of the four core invariants.

`formal/` — TLA⁺ specifications for the conjunctive gate, oracle sole-authority, the two-environment
boundary and the anti-rollback floor, each with a deliberately broken twin the checker must report as
failing, plus a `CORRESPONDENCE.md` mapping each model to the code it abstracts, and a CI job.

Ch01 §8.7 now gives this one bullet and correctly states the honest scope ("model-level assurance
that faithfully abstracts the enforcing code — not a proof extracted from the code itself") and the
broken-twin design. Ch02 §5.3 gives one paragraph. **Neither names the four invariants**, neither
mentions `CORRESPONDENCE.md`, and it appears in **no status table**. This is the strongest assurance
evidence in the repository and the briefing gives it three sentences. (Improved since the previous
review — see Part G — but still under-weighted.)

### C17–C20. Smaller, verified, and worth a line each

| # | Subsystem | Path | Why it belongs |
|---|---|---|---|
| C17 | **kernel — the Universal Reasoning Kernel** | `framework/v2/kernel/` | "turns the v1 cognitive prose (`framework/cognitive/*.md`) into typed, callable functions backed by an LLM. Every binding loads the relevant section of the cognitive doc, prompts the LLM, and parses the response into a Pydantic schema." Ch11 §9.1 quotes the standing doctrine at length without saying what loads it, and ch11 §3.5 refers to "a reasoning layer that falls back to a deterministic dry run" without naming it. The bindings include `hypothesize`, `critique`, `pivot`, `opsec` and `consistency` — the last being the mechanism behind ch11 §9.3's "voting against yourself". |
| C18 | **kb — corpus RAG, skills loader, llm_guard** | `integration/vigil_integration/kb/` | "EVERY result body is wrapped in the F1 `[UNTRUSTED]` envelope — KB content is a prompt-injection channel, never a fact and never an authorization", plus a markdown skills loader behind an `is_relative_to` path-traversal guard. Relevant to ch11 §7 (how the system learns) and to the prompt-injection story in chs 01 §1.3 and 08. |
| C19 | **plugins — the unified capability registry** | `framework/v2/plugins/` (and `crucible capabilities`) | "One deterministic catalog over the framework's several independent rosters (sensors, internal tools, oracles, operators, CLI commands) so a third party — or a future MCP server / HTTP API / SDK — can DISCOVER what capabilities exist, what each produces, its gating tier, its graceful-absent behaviour — WITHOUT changing how any of them execute." Ch09 §5.7 says the Brain's Catalog tab renders "the real capability catalogue"; the machine-readable registry behind it, which is the literal answer to "what can this thing do", is never explained. |
| C20 | **scanner/lateral.py — post-fusion lateral movement** | `framework/v2/scanner/lateral.py` | "The pre-fusion chaining… runs BEFORE sensor fusion, so it never sees the cloud / IAM facts the fusion oracles confirm. This module closes that gap: AFTER fusion, it bridges the GROUNDED cloud oracle facts into attacker-traversable edges, then re-runs the SAME deterministic path search." Ch10 §6.4 covers what the six cloud confirmations project onto the map and ch10 §7 covers the inference rules, but the second, post-fusion path search that actually surfaces internal lateral routes is missing from the chapter that owns attack paths. |

Also verified present and unmentioned, lower priority: `eval/` (the evaluation harness that produces
the recall numbers chs 04 §10 and 11 §7.4 rely on), `chainast/` (a reversible AST over the reasoning
chain with append-only Merkle-cited compaction — arguably a fourth "map" for ch10 §14's honest
three-maps table), `scanner/adaptive.py` genetic payload synthesis (chs 08 §7.6 and 13 cover the WAF
bypass *ladder* but not the evolutionary search behind it), `scanner/check_synthesis.py`
(eval-gated synthesis of a runnable new check — directly relevant to ch11 §7.4's
"proposes, never applies"), `scanner/targeting.py`, and `remediation_binary/`.

---

## Part D — Per-chapter findings

### `01-what-this-is.md` — near-complete; four fixes

- **D1.1** As the de-facto entry point, it should carry (or point at) the contents list, the reading
  order and the method statement (A1). Its closing paragraph currently names eight of the twelve
  remaining chapters and omits 06, 08, 11 and 13 (A2).
- **D1.2** §5.2 carries the `.gov`/`.mil` constraint and hands the reader a problem with no
  resolution (**A5**). This chapter should state the position and point at the authoritative
  subsection.
- **D1.3** §5.2 also carries the **licensing** position — PolyForm Noncommercial with a supplemental
  term excluding government and public-sector use without a commercial licence. This is a
  first-order procurement fact and it appears **only here**, inside a section titled "Who it is for".
  Ch12 — the chapter a buyer reads to build their shopping list — never mentions licensing. Verified:
  `grep -i licen 12-*.md` returns two hits, both about STRIX's Apache licence and vendor telemetry.
- **D1.4 (minor)** §8.1 says "the 15 original checker types against a live web target" while ch03 §8
  says "11 seed tests always run". Both are correct (15 frozen fallback oracles vs 11 seed checks)
  but the adjacent numbers with similar framing invite conflation; one clarifying clause fixes it.

### `02-the-parts.md` — the map of the system is not complete

- **D2.1** §3.3's table is introduced as CRUCIBLE's "main internal departments" and omits `intruder`
  (C4), `repeater` (C5), `socialdefense` (C14), `intake` (C11), `imports` (C9), `entitlement` (C3),
  `api` (C10), `plugins` (C19), `confidence` (C13), `kernel` (C17), `eval` and `analysis`. Because
  this table is the reader's map of the product, every subsystem in Part C surfaces here first as a
  missing row.
- **D2.2** §3.7's integration-layer table omits `gauntlet` (C6), `fsjob` (C12), `channel_binding`
  (C15), `kb` (C18) and `chainast`.
- **D2.3** §3.6 (STRIX) is 20 lines for one of the four parts the reader named — see **B5**.
- **D2.4** §6 "What runs where" is the closest thing to a backend account and stops at processes and
  ports — see **B1**. Data stores, the API surface, the systemd units and the container profiles all
  belong here or in a new chapter.
- **D2.5** §5.3's formal-methods paragraph should name the four invariants and `CORRESPONDENCE.md`
  (C16); §8's status section omits formal verification and CI entirely (A4).
- **D2.6** §3.2's shared-core table is a good place to introduce the entitlement objects (C3)
  alongside the delegation and capability objects already listed.

### `03-an-operation-end-to-end.md` — the spine of the document; five additions

- **D3.1** §1 claims the ten stages match the engine's own `ENGAGEMENT-LIFECYCLE.md` "in the same
  terms". They do not: the engine has a **threat-model stage (1)**, a **post-exploitation stage (6)**
  and an **engagement-closure stage (11)** that ch03 has no counterpart for — see **B6**. This is the
  one finding in this review that is also an accuracy problem: the sentence asserting equivalence
  should either be corrected or the stages added.
- **D3.2** Stage 0 tells the operator to write the charter by hand and does not mention the Universal
  Target Intake scaffolder (C11), so the on-ramp described is harder than the real one.
- **D3.3** Stage 2 (set-up) and Stage 6 (testing) never mention **authenticated scanning** (C1) —
  the single biggest coverage-shaping decision an operator makes.
- **D3.4** Stage 6 lists the 11 seed checks, the 172 data-defined payloads and the surface-specific
  modules, but not the Intruder fuzzing engine (C4) or the Repeater (C5); and it does not state the
  **out-of-band relay prerequisite** (C2) that four of those eleven checks depend on against a remote
  target.
- **D3.5** No timing, throughput or cost expectations anywhere. The chapter has the *bounds*
  (1,000-action budget, 100-request executor budget, 0.2 s pacing) but never turns them into "here is
  what a real run looks like" — how long a quick/standard/deep run takes, roughly how many requests
  it issues, what the AI spend is. Ch09's Home screen has a "Budget today" tile, so the reader learns
  cost exists and is never told what it is.

### `04-leads-and-facts.md` — the strongest chapter; three additions

- **D4.1** §7 ("What 'confidence' means here") presents two kinds of confidence as the complete
  picture. There is a third — the Scientific Confidence Engine with explicit priors, MECE
  alternatives, a credible interval and a computed "what would change my mind" (C13).
- **D4.2** §10 ("What this approach cannot do") states "re-execution proves a binding, not the world"
  as a standing limit. The in-tree channel-binding / notary work (C15) is aimed precisely at it and is
  not mentioned, so the limit reads as more irreducible than the project itself treats it.
- **D4.3** §1 and §5 enumerate where leads come from (outside tools, pattern matches, the AI). The
  `imports` path — deliberately ingesting a Nuclei / ZAP / Burp / sqlmap export as provenance-tagged
  observations that can never become FINDING nodes (C9) — is a whole lead-production route that is
  missing, and it is a good one: it is the doctrine applied to another vendor's report.
- **D4.4 (minor)** §5.6 makes the point that outside tools are held to the same rule as the AI. The
  gauntlet's `judge_llm` → always-LEAD routing (C6) is the same rule applied to *another model acting
  as a judge*, which is a sharper example and is available in-tree.

### `05-weakness-types.md` — near-exhaustive; three missing families

- **D5.1** **No family for testing a customer's own AI application offensively.** Family 14 is
  explicitly the four *defensive* detections. For a chapter titled "Every Type Of Weakness The System
  Can Find", the reader needs either the offensive LLM family (C6) or an explicit "out of scope, and
  here is why".
- **D5.2** **No post-quantum crypto exposure** (C7) in Family 8 (network exposure, encryption and
  supply chain).
- **D5.3** **No session-token predictability** (C8) in Family 3 or Family 4.
- **D5.4** Part 6 ("The attack library behind the catalogue") presents the 11 seed checks and 172
  payload definitions as the whole generation story; Intruder's payload-set vocabulary, position
  marking and outlier triage (C4) is the other half.
- **D5.5** The "switched off by default" table at the end of Part 6 is excellent and should carry two
  more rows: the out-of-band classes require a relay for a remote target (C2), and the access-control
  and business-logic families require an authenticated session (C1).
- **D5.6 (minor)** Part 7 ("What this catalogue does not cover") is the right home for one line on
  post-exploitation being refused by design (B6) — currently a reader has to find it in ch08 §10 and
  ch11 §3.2.

### `06-evidence-and-proof.md` — outstanding; three gaps

- **D6.1** Channel binding (C15). §8.2's fourth bullet already writes the sentence that should
  introduce it; this is the chapter that owns the limit.
- **D6.2** **Evidence lifecycle and custody over time** is missing: retention period, disposal,
  roughly how much disk an engagement consumes, and — most importantly — how the evidence tree, the
  chain, the signed head and the anti-rollback floor are **backed up and restored** without breaking
  the guarantees. §3.5 explains that the floor refuses a smaller state, which makes a naive restore an
  incident the document never warns about. The opposite case (`--ephemeral`) is well covered.
- **D6.3 (minor)** §7.5 names the audit package's `RUNBOOK.md` but does not summarise the auditor's
  procedure or how long it takes; §12's reviewer checklist nearly does this and could absorb it.

### `07-signing-and-keys.md` — outstanding; two gaps

- **D7.1** **Key loss and disaster recovery is never answered** — see **B3**. Highest-priority single
  omission in the chapter set after Part A.
- **D7.2** §2's "what exactly gets signed" table and §4's key-holder account omit the **entitlement**
  objects (C3), which are threshold-signed by a governance authoriser set, host-bound, expiring and
  revocable — i.e. they belong in both. Add the key-inventory table described in B3.
- **D7.3 (minor)** §6 correctly states that no scheduled rotation exists and that rotation is an
  operator action; it does not give the *procedure* for rotating the governance or engagement-record
  keys, so an operator reading it cannot act on it.

### `08-safety-and-authorization.md` — outstanding outward; three additions

- **D8.1** §2.5 must become the authoritative resolution of the `.gov`/`.mil` question — see **A5**.
  It currently states the problem better than anywhere else and still stops at "would need to be
  deliberately and explicitly revisited".
- **D8.2** The **entitlement system** (C3) is absent from §3 (permission tiers), from §5 (irreversible
  actions) and from §10 (what the project refuses to build) — even though it is the mechanism that
  makes "possession of the code is not possession of the capability" true, and even though ch09
  §5.13's GOVERNED/UNGOVERNED badge and ch13's `AEGIS_RESPOND` gate both depend on it.
- **D8.3** No consolidated threat model of VIGIL itself — see **B2**. The material exists scattered
  across chs 02, 06, 08 and 09; it needs one home, and the loopback API daemon (C10) belongs in it.
- **D8.4** §10's refusals table is the natural home for a plain "and post-exploitation?" row (B6):
  no lateral movement, no persistence, no implants, refused by construction.

### `09-the-screens.md` — the most complete chapter in the set; four additions

- **D9.1** §9 ("the three other interfaces in the box") and §10.2 ("which to use for what") between
  them claim to present every way to drive the system, and omit the **loopback API daemon** (C10) and
  the **MCP stdio server** as *entry points* — the latter having a whole screen (§5.8) without ever
  being listed as an interface.
- **D9.2** §10.1 lists all 26 `vigil` verbs and then reports that `crucible` has 31 subcommands,
  `sigil` 38, `aegis` 3 and `gateway` 6 — **78 subcommands that are listed nowhere in the briefing.**
  Several are the only entry point to capabilities no chapter covers: `intake`, `imports`,
  `socialdefense`, `entitlement`, `api`, `kernel`, `capabilities`, `collaborator`, `calibration`,
  `plan-integrity`, `drift`, `attack-paths`. A reader asked for "every feature"; a large part of the
  remainder lives here.
- **D9.3** §7 ("Two capabilities that have no screen at all") is exactly the right device and covers
  only two. On the evidence of Part C it should cover at least: the OOB relay (C2), entitlement
  provisioning (C3), Intruder (C4), Repeater (C5), intake (C11), imports (C9) and socialdefense
  (C14). §8 currently claims to give "the **complete** set of places where the interface shows
  something that does not do what a reader might assume", which will not survive a reader who finds
  `crucible socialdefense` and then looks for the screen named in §9.
- **D9.4** §4.2's five-step wizard tour never shows where **target-application credentials** for an
  authenticated scan would be supplied (C1). If the wizard genuinely has no field for them, that is
  an interface gap belonging in §8.
- **D9.5 (minor)** Nothing on browser support or accessibility. A government buyer will ask about the
  latter specifically; if it has not been assessed, "not assessed" is the honest entry for §8.

### `10-the-picture-of-the-attack.md` — near-complete; one addition

- **D10.1** §6.4 covers what the six cloud confirmations project onto the map and §7 covers the
  inference rules and the twelve techniques, but the **post-fusion lateral-movement pass** (C20) —
  which re-runs the path search *after* sensor fusion specifically so cloud/IAM facts can create
  traversable edges — is missing from the chapter that owns attack paths. §17's status table should
  gain a line for it.
- **D10.2 (minor)** §14's honest three-maps table could name `chainast` as a fourth representation of
  the same history.

### `11-the-agents-and-learning.md` — near-complete; three additions

- **D11.1** §2's families table and the agent inventories omit `gauntlet` (C6) and `fsjob` (C12).
  `fsjob` in particular is the mechanism behind the OPERATOR agent's scope rings described in §4.
- **D11.2** §9.1 quotes the standing doctrine in full without naming the component that loads it —
  the Universal Reasoning Kernel (C17) — and §9.3's "voting against yourself" is that kernel's
  consistency binding. §3.5's "a reasoning layer that falls back to a deterministic dry-run mode" is
  the same thing, unnamed.
- **D11.3** §7 ("How the system learns") does not mention the knowledge/skills layer (C18), whose
  `[UNTRUSTED]`-envelope rule is a good worked example of the prompt-injection discipline the
  document argues for elsewhere.
- **D11.4 (minor)** No total agent count anywhere. The chapter gives "nine" for the sovereign mesh and
  lists the offensive line agents and reviewers without a total, while ch09's top bar carries a live
  "agents" counter. A summary count, as ch09 §12 does for screens, would let a reader hold the shape
  of the system.

### `12-tools-and-what-you-need.md` — near-complete; five operations gaps

- **D12.1** **The out-of-band relay is missing from every list of what an operator needs** (C2) —
  §2.3's "complete list", §2.5 (network access), §2.6 (day one), and the one-page checklist. It is a
  hard prerequisite for a whole class of findings against a remote target.
- **D12.2** **Target-application credentials for authenticated scanning are missing** from §2.3 and
  the checklist (C1). §2.3 presents 17 entries as "the complete list" of credentials the system
  accepts, which is true of *its own* credential store and misleading as an answer to "what do I need
  to run an operation".
- **D12.3** **Licensing is absent** from the chapter a buyer reads to work out what they need
  (D1.3). The public-sector exclusion belongs in §2.1's short answer or the closing checklist.
- **D12.4** **Backup / restore, upgrade path and uninstall** are absent from the day-one sequence and
  the checklist (B1), as is any mention of the entitlement a governed deployment needs (C3) and of
  `intake` as the easier on-ramp (C11).
- **D12.5** §2.5 lists inbound as "none" and enumerates outbound destinations, but omits the loopback
  API daemon and the MCP stdio server from the local surfaces (C10), and does not mention the systemd
  timers as things that will run on a schedule once enabled.
- **D12.6 (minor)** §2.2 honestly says no sizing figures are published. Pair that with the missing
  runtime and cost expectation (D3.5) so a reader gets one coherent "what will this cost me to run"
  answer rather than two separate silences.

### `13-defence-and-source-code.md` — carries four subjects and is the thinnest per subject

- **D13.1** Codebase scanning — see **B4** (languages, pattern count, the unexplained **symbol
  index**, repository secret scanning, and above all the unexplained split between the `analysis`
  pipeline and the Strix-in-Docker "Scan a codebase" mode).
- **D13.2** `socialdefense` (C14) is missing from the defensive chapter although ch09 exposes the
  name.
- **D13.3** Part 4 (TLS) is silent on **post-quantum crypto exposure** (C7) and on **VIGIL's own TLS
  posture** for its outbound calls (model providers, cloud APIs, the four passive-recon services) —
  except the one documented exception for the crypto-posture probe and the requirement that the IMDS
  runner report verification-on. A short "our own connections" paragraph closes the latter, and
  channel binding (C15) belongs here too.
- **D13.4** The three-install-methods table does not say **which detections are available on which
  method**. Ch09 §4.10 tells the reader, in a screen caveat, that "canary and prompt-injection
  detection for an AI application is the in-process SDK path, not this reverse proxy" — a
  load-bearing distinction that the chapter owning AEGIS does not make. A defender choosing the
  reverse proxy because it needs "no code changes" would get the wrong four detections.
- **D13.5** Part 5 names the re-prove timer but not the shipped units, which are what an operations
  team actually deploys (B1).
- **D13.6** Part 3 (producing a fix) describes the ladder well; the **Repeater** (C5) — the operator's
  manual counterpart to all of this, and an entitlement-gated Tier-2 capability — is mentioned only
  as "the replay tool" in Part 4.
- **D13.7 (structural)** Four unrelated subjects in one chapter is why each is thinner than its peers
  elsewhere. If the set is ever renumbered, defence (AEGIS + Detection Mirror + socialdefense +
  detection engineering) and codebase review deserve separate chapters, and TLS + network manners
  could fold into ch08.

---

## Part E — Suggested priority order

1. **A1 / A2 / A3 / A4** — index, chapter-numbered cross-references, glossary, master status ledger.
   Cheapest work, largest effect on a first-time reader.
2. **A5** — one authoritative answer to the `.gov`/`.mil` question. It is the first thing this
   audience will ask and the document currently raises it three times and answers it nowhere.
3. **C1 + C2** — authenticated scanning and the out-of-band relay. Both are *prerequisites*, not
   features: their absence makes the described product both harder to use and narrower than it is.
4. **C3** — the entitlement system, i.e. the controlled-distribution story.
5. **B3 (D7.1)** — key loss and recovery. A security officer will ask in the first meeting.
6. **B1 (D2.4, D9.2, D12.4)** — the backend / operate-it story.
7. **B4 (D13.1)** — codebase scanning, especially the two-paths ambiguity.
8. **B6 (D3.1)** — the three dropped lifecycle stages, and post-exploitation stated as a refusal.
9. **C15 (D4.2 / D6.1 / D13.3)** — channel binding, so the most-repeated residual is stated with its
   in-tree countermeasure.
10. **C4 / C5 / C6 / C7 / C8 / C9 / C11 / C13 / C14** — the missing subsystems, in the chapters that
    own them.
11. **C16 (D2.5)** — formal verification, promoted from three sentences to a proper account.
12. **B2 (D8.3)** — VIGIL's own threat model.
13. Everything marked *(minor)*.

---

## Part F — What I checked and did not flag

A completeness review should say where it looked and found nothing.

- **Numeric consistency across chapters is good.** 38 oracles / 40 procedures / 15 frozen core /
  85 classes / 190 synonyms / 275 names / 26 branches / 6 clean-capable / 17 with named blocking work
  / 33 catalogued tools (2 fact-capable, 14 lead-only, 17 excluded) / 13 remediation-sound kinds /
  12 detection procedures (13 table rows) / 11 seed checks / 172 payload definitions / 28 screens /
  26 native verbs / 31 crucible subcommands / 38 sigil subcommands / 24 container tools / 22 node
  types / 24 edge types / 12 techniques / 9 sovereign agents — all agree wherever they repeat. The
  only collision risk is 15-oracles vs 11-seed-checks (D1.4).
- **Verdict vocabulary** is used consistently. No chapter admits a fifth word, and no chapter
  describes a LEAD as anything stronger than a suspicion.
- **Status honesty** is applied uniformly: every chapter distinguishes built / built-but-not-live-fired
  / scaffold-that-raises / refused, and deferred items name their blocking dependency. I found no
  instance of a deferred capability being described as complete, and the cloud/K8s position is stated
  in the required both-directions form ("calling them unfinished understates; calling them
  field-proven overstates") in every chapter that raises it.
- **The requested topics not listed in Part B as thin** — oracles, leads, evidence, signing, offline
  verification, screens, knowledge graph, agents, learning, keys, how findings are made — are covered
  to a standard that needs no additions beyond the specific items above.
- **Chapter 10** is the most internally complete chapter in the set; its only gap is C20.

---

## Part G — Findings from the previous revision that are now fixed

Recorded so a later edit does not undo them.

- The supply-chain safeguards (hash-locked dependencies, digest-pinned base images, SBOM, the
  CRITICAL-blocking gate) are now covered in ch06 §11, ch12 §2.9 and ch09 §7.2, each with an honest
  "not yet on the main line at the time of writing" note and a "what this does not prove" section.
- Formal verification has moved from a single clause to a bullet in ch01 §8.7 that states the
  model-level scope and the broken-twin design (still under-weighted — C16).
- Ch09 §7 now exists as a device for capabilities that have no screen, and §8 as a device for places
  the interface is incomplete. Both are the right shape; they need more rows (D9.3).
- The cloud/Kubernetes six are now stated consistently across nine chapters in the required
  both-directions form.
