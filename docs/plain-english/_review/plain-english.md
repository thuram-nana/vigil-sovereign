# Plain-English Review — VIGIL Briefing, Chapters 01–13

**Reviewer role:** plain-language editor, acting on behalf of a senior reader with **no technical
background** — someone who can follow a careful argument but has never written software, never
configured a server, and does not know what a "branch", a "sink" or a "payload" is.

**Scope:** every chapter in `/home/kali/vigil/docs/plain-english/` — `01-what-this-is.md` through
`13-defence-and-source-code.md`, 13,116 lines, read end to end.

**Method:** full read, plus mechanical counts across the set (naming variants per chapter, first use
of each acronym in reading order, spelling variants, sentence lengths, symbol characters).

**Note:** this supersedes the earlier version of this file, which reviewed an earlier state of the set
(11,826 lines). Several of its findings have been acted on — chapter 01 in particular now explains
"oracle" at first use and reads cleanly. The naming problem it identified as critical has **not** been
fixed and has widened from six names to ten.

---

## 0. Verdict in one paragraph

This is a strong set of documents and, on tone, an unusually disciplined one: **there is no decorative
emoji anywhere, and the salesy language amounts to about a dozen sentences out of some 4,900.** The
honesty apparatus — the "what this does not prove" columns, the built-versus-deferred ledgers, the
refusal to round anything up — is the best thing in the set and must not be touched. Several chapters
(07, 08, 11, and the second half of 12) are close to publishable as they stand, and the best
explanatory devices in the set (the smoke detector with a dead battery, the wax seal, the notary's
public register, the bound ledger, the floor plan, the breathalyser, the single-flipped-byte table) are
genuinely excellent writing.

The problems are almost all of one kind: **the chapters were written separately and never harmonised
as a set.** The most important object in the whole product — the small deterministic checking program —
is given **ten different plain-English names** across thirteen chapters. About a dozen pieces of core
jargon (`sink`, `payload`, `provenance`, `fail-closed`, `vendored`, `denominator`, `canonical`, `seam`,
`monotonic`, `spine`) are used hundreds of times and defined nowhere. Roughly twenty acronyms appear
before, or entirely without, expansion. There is no glossary of technical terms and no reading order.
And — the most expensive failure, because of *where* it lands — the honesty passages, the single most
important content in the briefing for a national agency, are written in software-delivery vocabulary
("merged into the main line", "in the working tree", "on its own delivery branch", "fixture evidence")
that the target reader cannot parse at all.

A reader going front to back will not fail to understand the product. But they will stall repeatedly,
and several of the stalls happen exactly where the reader can least afford to lose the thread.

**Effort estimate.** The cross-cutting fixes in §1 are perhaps a day and a half of editing and would
resolve roughly three-quarters of the problem. The chapter-specific items in §2 are mostly small. §3
gives worked rewrites for the ten worst passages. §4 is a draft shared glossary. §5 lists what must
*not* be changed.

---

## 1. Cross-cutting problems

Ordered by how much damage each does to a non-technical reader.

### 1.A — The central object of the product has ten names *(CRITICAL)*

The deterministic, non-AI checking program is the load-bearing idea of the entire briefing. Measured
across the set, here is what each chapter calls it:

| Chapter | Dominant word | Count | Other names also used in the same chapter |
|---|---|---:|---|
| 01 | **oracle** | 24 | "checking program" (3), "judge" (5) |
| 02 | **proof programme** | 19 | "oracle" (5) |
| 03 | **judge** / "mechanical judge" | 44 | "oracle" (1), "assay" (3) |
| 04 | **referee** | 77 | "oracle" (17), "judge" (8), "decision procedure" (1) |
| 05 | **oracle** / "test" | 10 | "judge" (7), "automatic test" (3), "decision procedure" (3) |
| 06 | **automatic test** | 22 | "oracle" (5), "judge" (5), "decision procedure" (7) |
| 07 | **automatic test** | 4 | — |
| 08 | "deterministic checker" | — | "judge" (3) |
| 09 | **deterministic test** | 14 | "oracle" (15) |
| 10 | **automatic test** | 6 | "oracle" (7), "assay" (2) |
| 11 | **oracle** | 16 | "automatic test" (4) |
| 12 | **judge** / "fixed automatic test" | 6 | — |
| 13 | **assay** | 41 | "judge" (9), "oracle" (2) |

Ten distinct names: *oracle · checking program · proof programme · judge · mechanical judge · referee ·
automatic test · deterministic test · decision procedure · assay*. Worse, several chapters use two or
three interchangeably **within the same chapter**, so the reader cannot even resolve it locally.
Chapter 04 uses "referee" 77 times and "oracle" 17 times and never puts the two words in the same
sentence to say they are the same thing.

A specialist shrugs at this. A non-technical reader concludes there are several different mechanisms
and spends the rest of the briefing trying to work out how they relate.

**Recommendation.** Pick one and enforce it everywhere.

- Use **"the checker"** as the standing plain-English noun. It is short, it takes a plural and an
  adjective naturally ("the thirty-eight checkers", "the checker fired"), and it carries no false
  connotation. ("Oracle" suggests prophecy — chapter 04 line 142 says so itself. "Judge" and "referee"
  suggest discretion, which is the opposite of the point. "Assay" is unfamiliar to most readers. "Proof
  programme" is a phrase, not a word, and reads awkwardly in the plural.)
- Introduce it once, in chapter 01, in a form the set already uses well:
  *"a **checker** — a small, fixed, non-AI program that looks at saved evidence and answers one narrow
  question. The project's own name for it is an **oracle**, and that word appears in the software and on
  some screens."*
- Then say **"checker"** in body text everywhere, and reserve `oracle` for quoted code, quoted screen
  text, and the glossary.
- Keep the good analogies attached to it — the laboratory assay (ch13), litmus paper and the
  breathalyser (ch04 line 167), the lab test over a retained sample (ch01, ch04, ch12). Those are
  *analogies for* the checker, not *names for* it, and they work.

This single change is worth more to the target reader than everything else in this review combined.

### 1.B — There is no glossary of technical terms, and no reading order *(HIGH)*

The set opens directly at chapter 01 with no front matter. There is no `00-index.md`, no statement of
who the briefing is for, no per-chapter one-line summary, no suggested reading order, and no glossary.

Chapter 02 §9 has "A short glossary of the names" — but it defines only the **product** names (VIGIL,
CRUCIBLE, AEGIS, SIGIL, STRIX, WARDEN, OBSIDIAN, spine, charter, gateway). It defines none of the
technical vocabulary the reader actually trips on.

**Recommendation.** Add a short `00-index.md` (one page: who it is for, what order to read it in, one
line per chapter) and a `14-glossary.md` covering the terms in §1.C and §1.D. Draft entries are in §4.
Then, in each chapter, the *first* use of a glossary term gets a five-word gloss and the rest do not.

### 1.C — Core jargon used hundreds of times and defined nowhere *(HIGH)*

Verified by searching the whole set. None of these is ever defined in plain English:

| Term | First use in reading order | Times used | Why the reader stalls |
|---|---|---:|---|
| **payload** | ch01 line 380 | ~23 | Reader thinks of a rocket or a lorry. It means "the test input the system sends". |
| **provenance** | ch01 line 664 | ~27 | Never once defined. Chapter 10 §3 comes closest but never says the word means "the record of where a thing came from". |
| **sink** | ch03 line 964 | 18 | Completely opaque. "A fixed sink's traversal is unprovable" (ch03, ch13) is unreadable. |
| **fail-closed** | ch02 line 297 | ~27 | Defined properly only in ch08 §2.1 and ch09 §5.13 — six and seven chapters after first use. |
| **vendored** | ch01 line 478 | ~23 | Means "a copy of somebody else's software kept inside ours". Chapter 02 §3.6 gestures at it; nobody defines it. |
| **denominator** | ch02 line 720 | 10 | "Undiscovered endpoints are outside the denominator" is a mathematical metaphor with no explanation. |
| **canonical / canonicalisation** | ch02 line 115 | ~24 | Used for three different ideas: byte-identical formatting, the master list of weakness names, and XML signature processing. |
| **seam** | ch02 line 283 | 7 | "the inert seam", "the one remaining seam", "the learning seam" — a metaphor never introduced. |
| **spine** | ch02 (glossary only) | 10 | Defined in ch02's glossary, then used bare in ch09 ("the reasoning spine", "spine activity") and ch10/11. |
| **monotonic** | ch07 line 645 | 5 | "monotonic, downgrade-refusing, crash-safe advancement" — three unexplained adjectives in a row. |
| **idempotent** | ch02 line 567 | 4 | Defined well in ch09 line 973 — seven chapters late. |
| **topology** | ch10 line 286 | 3 | "that would fabricate topology". |
| **branch** (an evidence route) | ch01 onward | ~90 | The worst-chosen word in the set. Readers think of a tree, a bank, or software version control. Chapter 05 line 706 has the right image — *"the specific window through which a particular claim may be proved"* — but only chapter 05 uses it. |

**Recommendation.** Gloss each on first use, once, in five words or fewer, and add it to the glossary.
For **branch** specifically, either rename it throughout to **"evidence window"** (much clearer, and
already half-adopted in ch05) or promote ch05's one-line definition to the first use in ch01.

### 1.D — Acronyms used before, or entirely without, expansion *(HIGH)*

First use in reading order, verified mechanically:

| Acronym | First use | Expanded there? | Expanded anywhere? |
|---|---|---|---|
| OWASP, CWE, PCI-DSS, SOC 2, ISO 27001, MITRE ATT&CK | ch03 lines 828–829 | **No** | Yes — ch09 §5.10, six chapters later, and well |
| CVE | ch01 line 838 | **No** | Never expanded in the set |
| IAM | ch05 line 329 | **No** | Half-expanded once, ch06 §10.1 ("identity-and-access") |
| RBAC | ch05 line 524 | **No** | Never |
| K8s | ch09 line 229 | **No** | Never (Kubernetes itself is explained, ch05) |
| MCP / Model Context Protocol | ch01 line 853, ch03 line 1052 | **No** | Yes — ch09 §5.8 |
| TLS / SSL | ch05 line 304 | **No** | Partly, ch13 Part 4 (the padlock explanation is good) |
| DSSE, OpenVEX, RFC-6962, Merkle | ch06 line 547 | **No** | Never |
| SCITT | ch07 line 89 | **No** | Never |
| CycloneDX | ch06 line 1113 | **No** | Never |
| ASN.1 | ch07 line 705 | **No** | Never |
| CVSS | ch06 §5.5 as "severity scoring vector" | Never named | Never |
| Brier score | ch09 line 1253 | **No** | Never |
| F1 (with precision/recall) | ch09 line 908 | Partly | True/false positives and negatives are defined well; F1 is not |
| CIDR | ch03 line 243 | Adjacent gloss ("address ranges") | ch09 same |
| Sigma | ch13 line 322 | **Yes, well** | — |
| SARIF | ch01 line 599 | **Yes, well** | — |
| TPM | ch02 line 566 | **Yes, well** | — |

**Recommendation.** Two rules. (1) Every acronym is expanded at first use *in the set*, with a
five-word gloss, and used bare thereafter. (2) Move the excellent framework explanations already
written in ch09 §5.10 forward to ch03 §12, where the reader meets them first.

### 1.E — The honesty passages are written in software-delivery vocabulary *(HIGH — highest cost)*

This is the most damaging problem after §1.A, because of where it lands.

The single most important thing this briefing does for a national agency is state precisely what is
built, what is proven, and what is deferred. Those passages are currently written in the private
vocabulary of a software team:

- ch01 §8.4: *"They are in-flight working-tree changes on a delivery branch and are **not yet merged
  into the main line**."*
- ch06 §11.7: *"This work was being delivered on the day this chapter was written, **on its own
  branch**, and had not yet been merged into the main line… Verified directly **in the working tree**."*
- ch12 §2.9: *"This work is being delivered now and **lands on the main line as it merges**… Still **in
  flight** at that moment…"*
- ch04 §9: *"They were **not yet observable on the main line of the repository** at the version
  examined."*
- Everywhere: *"proven with **fixture evidence** offline"* (ch01 §8.3, ch04 §10, ch06 §10.1, ch10 §17,
  ch12 §2.10). "Fixture" is explained exactly once, in ch09 line 1303, as "recorded sample data standing
  in for a live cloud account". That gloss is good and should have been in chapter 01.
- ch02/ch07: *"opening a **pull request**"* — explained once, in ch08 §5.1, well. Chapters 02 and 07 use
  it earlier with no gloss.

A reader who does not know what a "branch" or a "working tree" is cannot tell whether "not yet merged
into the main line" means *nearly done*, *not really there*, or *someone forgot*. That is the one place
in the document where ambiguity is unacceptable.

**Recommendation.** Replace the vocabulary, everywhere, with plain equivalents — using identical
wording each time so the reader recognises the situation on sight:

| Instead of | Write |
|---|---|
| "merged into the main line" | "part of the released software" |
| "on its own branch / in flight / in the working tree" | "written and working, but not yet folded into the released version" |
| "fixture evidence" | "recorded sample data, standing in for the real thing" |
| "opening a pull request" | "raising a proposed code change for a human to review" |
| "at the version examined / at commit `1487e03a`" | "in the version of the software read for this briefing" (keep the commit reference as a footnote) |

### 1.F — Raw code identifiers put in front of a lay reader *(MEDIUM)*

Throughout the set, tables use software identifiers as the *label* column. Sometimes there is a plain
gloss alongside, which is fine. Often there is not, and the reader gets nothing:

- **ch05 lines 497–556** — the synonym table: **sixty rows** of `snake_case` identifiers
  (`graphql_alias_overloading` also accepted as `graphql_alias`, `graphql_alias_abuse`,
  `graphql_aliasing`) with **no plain English at all**. A non-technical reader gains literally nothing
  and will lose several minutes to it.
- **ch06 §9.3 lines 877–885** — `open_redirect.location_header`,
  `cors.reflected_origin_with_credentials`, `oidc_redirect_uri.location_header`,
  `tls_weakness.tls_handshake`. The plain-English column beside them already carries the meaning.
- **ch06 lines 935–938** and **ch13 lines 806–811** — the thirteen checker kinds listed as bare names
  (`error_signature`, `side_effect`, `differential_response`, `boolean_inference`, `reflection_context`,
  `dom_execution`, `predicate`, `oob_callback`…).
- **ch10 lines 200–205** — the four grounding tiers explained through their *source-string prefixes*
  (`oracle:`, `cert:`, `intel-fused:`, `derived:`, `infer:`, `fingerprint:`, `demoted:`). The tier names
  already carry the meaning; the prefixes are noise.
- **ch07 lines 101–112** — the purpose-label table (`crucible-evidence-v1`,
  `vigil-capability-wielder-pop-v1`).
- **ch08 lines 675–678** — twenty-three raw path fragments (`/admin`, `/drop`, `/payout`, `/sudo`…).
- **ch13** — raw internal permission constants `AEGIS_RESPOND` (line 197), `DEEP_STATIC_ANALYSIS`
  (line 428); verifier filenames `verify_pcf.py` / `verify_vf.py` in body prose (ch07, ch13).
- **ch06 line 164** — `0600` and `0700` file-permission codes.
- **ch09 line 1473** — "Requires the sandboxing tool `bwrap`."
- **ch10** — source file paths inline in body prose (lines 21–22, 841, 874–876).

**Recommendation.** Three fixes. (1) Move ch05's synonym table to an appendix behind one sentence:
*"Different vendors and standards bodies use different words for the same weakness. The system accepts
190 alternative spellings and maps every one onto the 85 names above, so a finding cannot be
double-counted. The full mapping is in Appendix A; a general reader does not need it."* (2) Wherever a
table has both an identifier column and a plain column, **drop the identifier column** or move it to
the right-hand edge. (3) Put file paths and commit references in footnotes, not in the sentence.

### 1.G — The best analogies are stranded in one chapter each; several abstract ideas have none *(MEDIUM)*

The set contains genuinely first-rate explanatory images. The problem is that each appears once and is
never reused when the same idea comes round again:

| Analogy | Where it is | Where it is also needed but absent |
|---|---|---|
| Smoke detector with a dead battery (silence ≠ safety) | ch01 line 140 | ch03 §10, ch04 §8, ch05 Part 4, ch06 §9.1, ch13 Part 5 — all re-argue this abstractly, as "existential vs universal claims" |
| Notary's public register (out-of-band pin) | ch07 §9 | ch01 §2.6, ch04 §4, ch06 §7.2, ch09 Proof Studio |
| Bound ledger with cross-referenced pages (hash chain) | ch07 §10, ch02 line 114 | ch06 §3.4 |
| Wax seal (digital signature) | ch07 §1 | ch06 §3.3 |
| Laboratory test over a retained sample | ch01, ch03, ch04, ch12, ch13 | Well reused — this one works |
| Floor plan and pins (the map) | ch10 §1–2 | — |
| Breathalyser vs an officer's opinion (certificate vs alert) | ch13 line 89 | ch06 §4 would benefit |

And these abstract ideas have **no analogy anywhere in the set**:

- **Determinism.** Used on nearly every page; never made concrete. Suggested: *"It is a recipe, not a
  chef. Follow it twice with the same ingredients and you get the same dish — no judgement, no mood, no
  improvisation."*
- **Fail-closed.** Used ~27 times. Suggested: *"Like a drawbridge held up by power: cut the power and it
  falls shut. If the check cannot be completed, the answer is no."*
- **The two different confidence numbers** (ch04 §7, ch10 §3.2, ch11 §7.3). Genuinely subtle and
  genuinely confusing — one is "how strong was this particular signal", the other is "how often do
  findings like this turn out to be real". Chapter 10's patient-file image is good but arrives after the
  mechanism. Suggested, up front: *"One number describes the reading on the instrument. The other
  describes how often instruments like this have turned out to be right. They are different questions."*
- **A bounded observation** (FACT and CLEAN describe a moment, not a property). Suggested: *"like a
  roadworthiness certificate — it says the vehicle passed on that date, not that it is safe forever."*
- **Evidence branch / window** — see §1.C.

### 1.H — Table cells used as paragraphs *(MEDIUM)*

Several tables have single cells running to 150–250 words. A table is a scanning device; a cell that
long defeats the format and is harder to read than the same words as prose.

Worst offenders: **ch05 lines 809–810** (two cells of ~190 and ~230 words), **ch06 lines 931–933**
(three cells of ~180–210 words each), **ch11 line 246** (the OPERATOR row, ~150 words containing eight
separate rules), **ch08 line 62** (nine hard limits in one 120-word cell), **ch13 line 917** (~90
words), **ch09 line 1388**, **ch12 line 910**, **ch01 lines 433–435** (90–130 words each).

**Recommendation.** Anything over about 40 words becomes a short prose subsection under a heading, with
the table reduced to a two-line summary pointing at it.

### 1.I — Inconsistent spelling, and three inconsistent namings of the same thing *(MEDIUM)*

Measured across the set:

| Chapter | British `-ise` | American `-ize` |
|---|---:|---:|
| 01, 02, 04, 11, 12 | 16–37 | 0 |
| **03** | 8 | **28** |
| **09** | 15 | **26** |
| 05 | 20 | 5 |
| 06 | 5 | 2 |
| 07, 08, 10, 13 | 21–61 | 1–2 |

Chapters **03** and **09** are predominantly American ("authorization", "authorized", "organization")
while the rest of the set is British. Chapters 05 and 06 are mixed internally. In a document going to a
national agency this reads as carelessness and undercuts the impression of precision that everything
else in the set works to build.

Three substantive naming inconsistencies also need fixing:

1. **The operating postures.** Chapter 11 line 172 calls them "the **aggressive** posture… the audit
   posture… the emulation posture", and states them as *rates* (5 per second, 1 per second, 0.2 per
   second). Chapters 08 (§7.1) and 13 (Part 4) call them **TEST / AUDIT / EMULATE** and state them as
   *gaps* (0.2 seconds, 1 second, 5 seconds). The underlying numbers are consistent; the presentation is
   exactly inverted and the first posture has two different names. A lay reader will not connect them
   and may reasonably conclude there are two different systems of pacing.
2. **The count of protected government domains.** Chapter 01 (lines 561 and 931) says **186**; chapter
   08 line 325 says **"roughly two hundred"**. Pick one and use it in both.
3. **Chapter 05's own opening.** Line 12 says *"**Three** counts frame the whole chapter. All **three**
   were re-derived…"* and is immediately followed by a table of **seven** rows. A careful reader notices
   this in the first thirty seconds of the chapter.

*(A fourth, internal to chapter 10, is listed under §2.)*

### 1.J — Tone: no emoji, and only a handful of salesy lines *(LOW — but list them)*

**On emoji: the set is clean.** A search for decorative emoji across all thirteen chapters returns
**none**. What the search does find is (a) process arrows `→` in chapters 06, 10, 11 and 13 —
legitimate and helpful, and (b) interface symbols quoted from the screens in chapter 09: `✔` `✖` `⚠`
(lines 474–476), `✕` (690), `⤓` (559), `⌘K` (125, 1381). These are quotations of what is on screen, so
they are defensible, but `⌘` is a Macintosh keyboard symbol many readers cannot name and `⤓` is
obscure. Add the word alongside: *"a download symbol (⤓)"*, *"the tick badge (✔)"*.

**Salesy or off-register sentences** — the complete list I would cut or soften:

| Where | Text | Problem |
|---|---|---|
| ch12 line 381 | "included **because practitioners reach for it, not to dunk on it**" | Slang. Wrong register for a national-agency briefing. |
| ch13 line 156 | "**A competitor would ship all three as blocking features.**" | Competitive jab; unnecessary — the paragraph is already convincing. |
| ch09 line 1149 | "**Most software would show a tick.**" | Same. |
| ch10 line 687 | "A remediation plan that only reports its wins **is a sales document**; this one reports the residual risk in the same breath." | Selling by disparaging selling. |
| ch11 lines 693–694 | "**That is the property being sold.**" | Explicitly commercial framing in a chapter's closing sentence. |
| ch12 lines 988–991 | "**That is not thinness.** It is the shape of a system whose value comes not from how much it runs, but from what it is willing to put its name to." | Marketing cadence. |
| ch09 lines 855–857, 897–898 | "the kind of detail that separates a real inventory from a checklist"; "a small thing that tells a reviewer a great deal about how the whole system is built" | Editorialising on the reader's behalf. |
| ch09 line 1207 | "this is the screen that **distinguishes this product from a scanner**" | Product-comparison framing. |
| ch08 lines 1068–1071 | "is making a claim **about its character** rather than its features" | Character claims are the one thing a briefing should leave to the evidence. |
| ch05 line 78 | "This is the distinguishing feature of the system and **the reason a national agency should care**." | Telling the reader what to care about. |

**A tonal repetition worth naming.** The construction *"X is the product"* appears as a closing flourish
in chapters 01 (§9), 04 (§10), 06 (opening), 09 (§13) and 11. On first reading it is effective. By the
fifth it reads as a slogan — which is exactly the impression the briefing is trying to avoid. Keep it in
**one** place (chapter 01) and let the others end on the substance.

---

## 2. Chapter by chapter

### 01 — What This Is *(strongest chapter; light work)*

Genuinely good. The one-page opening, the four-word verdict table, the medical-laboratory table and the
smoke-detector line are the best writing in the set.

- **line 140** — the smoke-detector image should be lifted verbatim into chapters 03, 04, 05, 06 and 13,
  each of which re-argues the same point abstractly.
- **lines 226–239** — the counts paragraph is very number-dense ("38 distinct kinds… 40 checking
  functions… 85 named categories (with 190 additional spellings… giving 275 accepted names in total)…
  15… 23"). Nine numbers in eleven lines. Split into two sentences and footnote the parenthetical.
- **line 380** first use of **payload**; **line 478** first use of **vendored**; **line 664** first use
  of **provenance**; **line 751** first use of **fixture evidence**; **line 838** first use of **CVE** —
  all unglossed. See §1.C and §1.D.
- **§8.4, lines 825–834** — the delivery-status paragraph is written entirely in developer vocabulary.
  Rewrite at §3.6. This is the highest-priority fix in the chapter.
- **lines 433–435** — the three-artefact table has cells of 90–130 words. See §1.H.
- **lines 943–948** — the closing "related chapters" paragraph is one 84-word semicolon chain. Make it a
  bulleted list; it is doing the job of a contents page.

### 02 — The Parts *(moderate work)*

The confused-deputy analogy (lines 43–49) and the "organisation with departments" frame are excellent.

- **"proof programme" (19 uses)** — a name used in no other chapter. See §1.A.
- **lines 344–347 and 532–539** — two tables of internal addresses (`127.0.0.1:8770`, `:8787`, `:8733`,
  `:48081`). The reader is not told what `127.0.0.1` means until **chapter 09 line 33**, where it is
  explained beautifully. Move that one sentence here: *"`127.0.0.1` is the address a computer uses to
  talk to itself; no machine anywhere else can reach it."*
- **line 297** first use of **fail-closed**; **line 567** "six **idempotent**, fail-closed steps"; **line
  628** "opening a **pull request**"; **line 720** "outside the **denominator**"; **line 115**
  "**Canonical** formatting" — all unglossed. See §1.C.
- **lines 349–355** — the "honest note on the current state of the tree" is important and well judged,
  but uses "merged and then reverted" without explanation, and "the tree" in the heading is developer
  vocabulary.
- **§9's glossary is names-only.** Extend it, or point at the new set-level glossary.

### 03 — An Operation End To End *(most work of any chapter)*

The strongest narrative structure in the set — the stage table (lines 39–51) and the "permission slip"
metaphor are excellent — but it contains the worst passage in the set and departs from house style.

- **"judge" (44 uses)** — see §1.A.
- **lines 871–876** — the `CLOSED iff …` blockquote. The single worst passage for the target reader: it
  uses the logician's "iff", a mathematical tuple `(surface, parameter, class)`, and code formatting, in
  a quotation the reader is explicitly told to read closely. Rewrite at §3.1.
- **line 316** — *"one in the fast systems language the kernel is written in, one in the language the
  rest of the system uses"*. This circumlocution is harder to read than the plain fact, which chapter 02
  already states: it is written twice, once in Rust and once in Python. Say so.
- **line 535** — "a standard statistical **bandit** method" with no gloss. Rewrite at §3.7.
- **lines 828–829** — first appearance of OWASP / CWE / PCI-DSS / SOC 2 / ISO 27001 / MITRE ATT&CK, none
  expanded. Chapter 09 §5.10 expands all six, well, in three sentences. Move that text here.
- **lines 371–373** — *"the various ways an internet-protocol-version-4 address can be written inside a
  version-6 address"* is a laboured way of saying "the several ways of disguising an internet address".
- **line 964** — "a fixed **sink's** traversal is unprovable" is unreadable without a definition.
- **line 1052** — "an external tool server of the **Model Context Protocol** kind" — undefined.
- **Spelling:** predominantly American in an otherwise British set. See §1.I.
- **lines 1082–1089** — the closing "one sentence to take away" really is one sentence: 105 words, seven
  semicolons. A good summary trapped in an unreadable shape. Break it into five short sentences.

### 04 — Leads And Facts *(moderate work; conceptually the best chapter)*

The medical analogy table (lines 73–83) is the clearest thing in the whole set.

- **"referee" (77 uses) alongside "oracle" (17 uses)** — the worst single instance of §1.A. The two
  words never appear in the same sentence being equated.
- **lines 187–252** — five tables, ~40 rows, many rows over 45 words. The "what it deliberately does not
  prove" column is the best idea in the briefing and deserves better presentation: shorten the rows and
  split the tables under sub-headings.
- **lines 132–136** — three "smaller closed vocabularies" given as raw code values (`finding`, `clean`,
  `OPEN`, `CLOSED`, `UNPROVEN`, `REMEDIATED`, `STILL_VULNERABLE`). Give the plain words instead.
- **lines 351–356** — *"a sufficiently low-level programming trick could still fabricate such an object
  in memory, as it could against any in-process guard of this kind"*. Honest, correct, and entirely
  opaque. Rewrite at §3.9.
- **line 845** — "mathematically **orthogonal** to completeness". The next sentence already explains it
  ("Zero false alarms says nothing whatsoever about what was missed"). Delete the word.
- **lines 969–979** — the closing italic paragraph is a 97-word list of thirteen numbers in a single
  sentence. Make it a table or a bulleted list.
- **"branch"** used ~40 times for an evidence route. See §1.C.

### 05 — Weakness Types *(moderate work; reference chapter)*

Correctly framed as a catalogue, with good reader guidance at the top.

- **lines 12–24 — a slip a reader will notice in the first minute.** "Three counts frame the whole
  chapter. All three were re-derived…" sits directly above a table of seven rows. See §1.I item 3.
- **lines 497–556** — the 60-row synonym table. See §1.F; move to an appendix.
- **line 586** — *"a one-sided rank test at a stated significance level, plus a minimum effect size,
  plus (optionally) a dose-response check that a larger injected delay produces a proportionally larger
  observed delay"*. Rewrite at §3.4.
- **line 587** "a sequential statistical test over repeated rounds"; **line 604** "a formal correction
  across the number of distinct sources examined" — same problem, less severe.
- **lines 761–763** — "observed reaching the **sink**", "a **blind sink**". Undefined.
- **lines 808–810** — three table cells of 120–230 words. See §1.H.
- **lines 866–882** — the "distribution across weakness types" table has an empty column pair in the
  middle and renders as a confusing five-column grid. Rebuild as a simple two-column table.
- **line 903** — "Requires a real **headless browser**". Chapter 12 defines this ("a web browser run
  without a window") seven chapters later.
- **lines 329–331** — `iam_privilege_escalation`, `iam_escalation_primitive`: "IAM" never expanded.
- **lines 266, 630** — "full cryptographic **canonicalisation** … is out of scope" is used twice as a
  limit statement and never explained, so the reader cannot judge how big the limit is.
- **Good and worth promoting:** line 706's definition of an evidence branch as *"the specific window
  through which a particular claim may be proved"* is the best sentence about branches in the set.

### 06 — Evidence And Proof *(moderate work; most valuable chapter for an auditor)*

The single-flipped-byte table (§8) is the best explanatory device in the whole briefing. §12's
reviewer's checklist is the second best.

- **line 547** — *"DSSE envelope carrying OpenVEX, with an RFC-6962 Merkle inclusion receipt"*. Four
  unexplained terms in twelve words. Rewrite at §3.2.
- **§9.3, lines 877–885** — the CLEAN-capable branch table led by raw identifiers. See §1.F.
- **lines 931–933** — three table cells of ~180–210 words. See §1.H.
- **lines 935–938** — the thirteen checker kinds as bare names. Either give each a three-word plain
  gloss or say *"thirteen kinds, listed in Appendix B"*.
- **Four words for one thing.** "Hash", "digest", "fingerprint" and "`sha256`" are all used for the same
  object (lines 220–233, 252, 571, 758). Settle on **fingerprint**, define it once at line 220 (the
  existing definition there is excellent), and use the others only in quoted code.
- **line 164** — `0600` / `0700` permission codes. The plain sentence beside them already says
  "readable and writable only by the account that ran it". Drop the codes.
- **line 367** — "to within one part in a million (a tolerance of `1e-6`)". The parenthetical adds
  nothing for this reader.
- **line 1113** — "the industry-standard **CycloneDX** format", unexplained.
- **§11.7, lines 1176–1185** — developer vocabulary in the honesty passage. See §1.E and §3.6.
- **§12 item 9** ("Ask separately about the build") is excellent and should be signposted from chapter 01.

### 07 — Signatures And Keys *(light work; near-publishable)*

The cleanest chapter in the set. The wax seal (§1), the notary's register (§9) and §13's "what an
assessor should ask the operator" are models the other chapters should copy.

- **line 89** — "(SCITT / OpenVEX)" — two unexpanded acronyms in a table cell.
- **lines 101–112** — the purpose-label table's identifier column is noise for this reader; the plain
  column carries everything.
- **line 344** — quotes the raw field name `not_after`. The sentence already says "expiry".
- **line 645** — "monotonic, downgrade-refusing, crash-safe advancement". Three unexplained adjectives.
  Suggested: *"it can only ever move forward, it refuses to be moved back, and it survives a crash
  mid-write."*
- **line 705** — "don't roll your own **ASN.1**".
- **line 433** — "opening a **pull request**", used before chapter 08 explains it.
- **§13 should be signposted from chapter 01.** It is the most immediately actionable page in the set
  for a non-technical decision-maker and is currently buried at the end of chapter 07.

### 08 — Safety And Authorization *(light work)*

The laboratory-door analogy (lines 32–36) is the best framing device in the set: *"The scientist's
intentions are not the safety system. The doors are."* §12 (honest limits) and §13 (how an inspector
checks) are exemplary.

- **line 62** — the hard-limits table cell runs nine prohibitions together in one 120-word sentence.
  Make it a nested list.
- **lines 323–331** — the domain-suffix list followed by a 90-word run-on naming a dozen categories of
  intergovernmental body. Summarise: *"…plus roughly two hundred named international organisations —
  United Nations bodies, development banks, international courts, treaty organisations, the Red Cross
  movement and standards bodies among them."*
- **lines 675–678** — twenty-three raw path fragments. Replace with a one-line characterisation and
  footnote the list.
- **line 325** — "roughly two hundred" contradicts chapter 01's "186". See §1.I.
- Uses "judge" three times against its own "deterministic checker". Harmonise per §1.A.

### 09 — The Screens *(most work after chapter 03)*

The longest chapter, and the most useful for anyone who will actually operate the system. §1.1's
explanation of `127.0.0.1` and the session token is the single best plain-English passage in the set —
and it arrives in chapter 9, three chapters after the reader first meets the address.

- **Spelling:** predominantly American in an otherwise British set. See §1.I.
- **Symbols:** `⌘K`, `✔`, `✖`, `⚠`, `✕`, `⤓`. Defensible as screen quotations; add the word alongside.
- **lines 1546–1566 — the "Summary of verified counts" table.** Rows such as "`sigil` subcommands — 38",
  "`crucible` subcommands — 31", "`vigil-gateway` subcommands — 6" are technically correct and
  practically meaningless to this reader; they tell them nothing they can act on. Keep the rows that
  carry meaning (28 screens, 4 owner-only, 2 tools exposed to an outside AI, 6 cloud confirmations, 0
  with a screen of their own, 1 non-functional control) and move the rest to an appendix.
- **line 1253** — "**Brier score**" with no gloss. Either explain it in six words ("a standard score for
  how well-calibrated predictions are") or cut it.
- **line 908** — "**F1** with precision and recall". True/false positives and negatives are defined
  clearly two lines later, which is good; F1 is not defined at all.
- **line 61** — "private tunnel ranges (**Tailscale and WireGuard** style addresses)" — two brand names
  with no explanation.
- **line 234** — "a checkbox to **bind-mount** instead of copy for very large repositories".
- **line 1473** — "Requires the sandboxing tool `bwrap`."
- **line 1391** — "32 **captures** exist on disk"; the same sentence later says "screenshot". Use one
  word.
- **Salesy lines:** 855–857, 897–898, 1149, 1207, 1540. See §1.J.
- **§7.1 (lines 1284–1343) is outstanding** — the clearest and most honest statement of the cloud
  position anywhere in the set, including the "two framings should both be avoided" paragraph. That
  paragraph should become the canonical wording used in chapters 01, 04, 06, 10 and 12.

### 10 — The Picture Of The Attack *(light-to-moderate work)*

The best-structured chapter in the set. The floor-plan opening, the pins-and-arrows vocabulary and the
"which single fix breaks the most attacks" section are excellent.

- **lines 200–205** — the grounding-tier table explained through source-string prefixes. Rewrite at §3.10.
- **The chapter abandons its own vocabulary.** It teaches "pins" and "arrows" (§2), then reverts to
  "nodes" and "edges" at lines 631, 806–807 and 818. Finish the substitution, or say once, explicitly,
  "the software calls these nodes and edges".
- **line 286** — "that would fabricate **topology**".
- **line 661** — quotes *"a **high-betweenness** non-bridge is the best single lever"*. The preceding
  paragraph already explains centrality in plain words, so the quotation adds jargon and nothing else.
  Either drop it or gloss "betweenness" as "how many routes run through it".
- **lines 631–633** — the sample rendered line uses `host:foothold`, "41 nodes", and "62.0 of 118.0"
  without restating that the impact figure is relative rather than monetary. §8.2 says so; the example
  does not repeat it, and the example is what a reader will quote.
- **lines 21–22, 841, 874–876** — source file paths inline in body prose. Footnote them.
- **§12.4's honesty note (lines 770–778)** is well done and consistent with the same note in chapters
  01, 04 and 06 — good.

### 11 — The Agents And Learning *(lightest work; very clear)*

The shortest chapter and among the clearest. The hospital analogy (§1) is excellent, and §8's table of
hard rules on learning is the kind of thing an oversight reader will photocopy.

- **line 104** — "This team is called **MAO** (Multi-Agent Orchestration) in the code". The acronym is
  introduced and then never used again. Cut it.
- **lines 170–173** — the posture names and rates conflict with chapters 08 and 13. See §1.I item 1.
- **line 246** — the OPERATOR row is a ~150-word cell containing eight distinct rules. See §1.H.
- **line 407** — *"successes plus one, over attempts plus two"*. A formula with no explanation of why.
  Rewrite at §3.8.
- **line 466** — "an **evaluation corpus**" — say "a set of test cases with known answers".
- **line 76** — "(The module's own older README still describes the original eight…)". "README" is
  developer vocabulary; say "the module's own older summary document".
- **lines 693–694** — "That is the property being sold." See §1.J.

### 12 — Tools And What You Need *(moderate work; §2.8 is the set's most useful section)*

Well organised, and §2.8 ("What leaves your organisation, and what stays") is the single most useful
page in the briefing for a government buyer.

- **lines 858–867** — the six-confirmations sentence runs to roughly 95 words with five semicolon-linked
  clauses, and it is the most important honesty statement in the chapter. Rewrite at §3.3.
- **line 381** — "not to **dunk on** it". Slang. See §1.J.
- **lines 988–991** — the closing paragraph. See §1.J.
- **§2.9, lines 823–839** — developer vocabulary in the honesty passage. See §1.E and §3.6.
- **line 453** — *"Configurations that work by running a local program are refused for safety; use a
  token or certificate instead."* Technically precise, entirely opaque. Suggested: *"A cluster
  configuration file that works by launching a helper program on your machine is refused — the system
  will not run somebody else's program just to log in. Supply a token or a certificate instead."*
- **lines 243–248** — 24 raw tool names in a run-on list. Add a lead-in: *"You do not need to recognise
  these names; they are listed so an operator knows exactly what is inside the sealed environment."*
- **line 434** — "There are 17 entries" appears before the reader knows what a "closed list of the
  credentials it will accept" is for; the table that follows is good.
- **Good:** the blood-test analogy (lines 48–53) and the benchmark caveats (lines 365–392) are both
  models of the right register.

### 13 — Defence And Source Code *(moderate work)*

The breathalyser analogy (line 89), the "clear does not mean safe" section, and the fix-verification
controls table (lines 775–779) are all excellent. The controls table in particular is the clearest
explanation in the set of why silence is not proof.

- **"assay" (41 uses)** — a tenth name for the checker. The *analogy* is good; the *name* conflicts with
  every other chapter. See §1.A.
- **lines 596–611** — the weak-cipher table: ten rows of names (`RC4`, `3DES`/`DES-CBC3`,
  `EXPORT`/`EXP-`, `ADH`/`AECDH`/`ANON`, `IDEA`, `SEED`) that a non-technical reader cannot use for
  anything. Rewrite at §3.5.
- **lines 620–623** — *"RSA or DSA below 2048 bits, or an elliptic curve below 224 bits… less than the
  roughly 112-bit security level that the US standards body has required since 2013"*. Impenetrable
  without a comparator. Suggested addition: *"In plain terms: the lock is too small. The numbers are the
  minimum sizes every standards body has required since 2013."*
- **lines 806–811** — the thirteen assay kinds as bare `snake_case` names.
- **lines 197, 428** — raw internal permission constants `AEGIS_RESPOND`, `DEEP_STATIC_ANALYSIS`.
- **line 156** — "A competitor would ship all three as blocking features." See §1.J.
- **lines 866–871** — the verifier filename `docs/proof-carrying-finding/verify_vf.py` in body prose.
- **line 917** — a ~90-word table cell.
- **Good:** the "what is explicitly not blocked" list (lines 130–137) — an apostrophe in a surname,
  `AT&T`, a price written `$5.00` — is the most persuasive single passage in the set for any reader who
  has ever been blocked by a badly configured firewall. Consider referencing it from chapter 01.

---

## 3. The ten worst passages, with suggested rewrites

### 3.1 — Chapter 03, lines 871–876 *(the worst passage in the set)*

**Now:**

> a claim is CLOSED iff, for its (surface, parameter, class), at least one probe's coverage verdict is
> `clean` AND that clean probe names a non-empty set of judges that adjudicated it AND no probe fired. …
> UNPROVEN never counts as CLOSED — that is the difference between a sound negative and an omniscience
> lie.

**Suggested:**

> The rule is deliberately strict, and it is worth stating in ordinary words. For any one place tested,
> one input tested, and one kind of weakness, the system may write **"closed"** only if all three of
> these are true at once:
>
> 1. at least one test came back with a definite "not here" — not merely a silence;
> 2. that test can name which checkers actually reached a verdict on it — silence from a checker that
>    never ran does not count;
> 3. no test fired at all.
>
> If any one of those fails, the answer is **"unproven"**, and unproven never counts as closed. The
> project's own summary of why: that distinction is the difference between an honest negative and a
> claim to know everything.

*(The original quotation can stay as a footnote for a technical reader. It should not be the version the
general reader is asked to parse.)*

### 3.2 — Chapter 06, line 547

**Now:**

> | Standards-native signed statement | DSSE envelope carrying OpenVEX, with an RFC-6962 Merkle
> inclusion receipt | Expresses a finding in a vocabulary that supply-chain and SBOM tooling already
> understands. |

**Suggested:**

> | A signed statement in the industry's own format | Three published standards used together: a
> standard signed wrapper, a standard way of saying "this published vulnerability does / does not affect
> this software", and a standard receipt proving the statement was entered in a tamper-evident register.
> | Lets other companies' software-inventory tools read a VIGIL finding without special handling. The
> standards are named in Appendix B for anyone who needs them. |

### 3.3 — Chapter 12, lines 858–867 *(the most important honesty passage in that chapter)*

**Now:** one sentence of roughly 95 words listing six capabilities with five semicolons.

**Suggested:**

> Six confirmations are complete and part of the released software, wired end to end. In plain terms,
> each proves that something was actually *achieved*, not merely that a setting looked wrong:
>
> 1. A credential was taken from a cloud machine's own credential service — and that credential really
>    worked.
> 2. A secret found lying exposed is a **currently working** credential, not just a string that looks
>    like one.
> 3. One Google Cloud identity can act as another.
> 4. An identity's permissions let it give itself more power than it started with.
> 5. On a container platform, an anonymous caller — anyone at all — is attached to a dangerous
>    administrative role.
> 6. On the same platform, a role genuinely grants dangerous powers, proven by reading the role's actual
>    rules rather than trusting its name.
>
> All six are proven offline against recorded sample data. The detection logic, the evidence handling,
> the certificates and the safety gates are built and proven.

### 3.4 — Chapter 05, line 586

**Now:**

> A real hypothesis test: a one-sided rank test at a stated significance level, plus a minimum effect
> size, plus (optionally) a dose-response check that a larger injected delay produces a proportionally
> larger observed delay. Needs at least five samples per arm.

**Suggested:**

> A genuine statistical test, not a stopwatch. It requires three things at once: that the slow responses
> are *reliably* slower than the normal ones (not merely slower on average, which one unlucky
> measurement can produce); that the difference is large enough to matter, not just large enough to
> detect; and — where it can — that asking for a *longer* delay produces a *proportionally* longer wait,
> which is what a genuine injected delay does and a busy server does not. It needs at least five
> measurements on each side before it will say anything.

### 3.5 — Chapter 13, lines 596–611

**Now:** a ten-row table of cipher names (`RC4`, `RC2`, `3DES`/`DES-CBC3`, `DES-CBC`, `EXPORT`/`EXP-`,
`NULL`, `ADH`/`AECDH`/`ANON`, `MD5`, `IDEA`, `SEED`) with terse reasons.

**Suggested lead-in, before the table:**

> The table below lists the specific names the system looks for. **A general reader does not need to
> recognise any of them** — they are the trade names of encryption methods that were once standard and
> are now known to be breakable. What matters is the shape of the rule: the system does not guess, and it
> does not object to modern encryption. It reports a weakness only when the server *actually agreed* to
> use one of these, in a real connection the system made itself and kept a record of. Three deserve a
> plain word each: `NULL` means no encryption at all; the `ANON` family means the server does not prove
> who it is, so anyone can stand in the middle; and `EXPORT` refers to encryption deliberately weakened
> by 1990s export law.

### 3.6 — The delivery-status paragraphs *(ch01 §8.4, ch04 §9, ch06 §11.7, ch12 §2.9)*

**Now (chapter 01):**

> The container pinning, the dependency lock specification, the offline assertions, the rewritten
> verification script and the continuous-integration job containing the CRITICAL-blocking gate all exist
> and are readable. They are in-flight working-tree changes on a delivery branch and are **not yet merged
> into the main line**.

**Suggested:**

> All five pieces exist and can be read today: the container pinning, the dependency lock, the offline
> checks, the rewritten verification script, and the automated build gate that blocks on a critical
> vulnerability.
>
> They are **written and working, but not yet folded into the released version of the software.** In the
> same way that a finished chapter is not yet a published book, this work sits in a separate working copy
> awaiting final review. A reviewer should confirm it has reached the released version before describing
> it as running.

*(Use identical wording in all four chapters, so the reader recognises the situation each time.)*

### 3.7 — Chapter 03, line 535

**Now:** "It uses a standard statistical bandit method: each option carries a running record of hits and
misses, one sample is drawn per candidate, and the highest sample wins."

**Suggested:**

> It uses a standard technique for balancing "do the thing that has worked before" against "try something
> we know little about" — the same problem a doctor faces choosing between a proven treatment and a
> promising new one. Each possible test keeps a running tally of how often it has found something. Before
> each choice, the system draws one plausible success rate for each option from that tally and picks the
> highest draw. Options with a good record are chosen often; options with a thin record still get their
> turn.

### 3.8 — Chapter 11, line 407

**Now:** "The success rates it stores are computed the conservative way — successes plus one, over
attempts plus two — which means a single lucky hit never produces a confident-looking rate."

**Suggested:**

> Success rates are deliberately computed in a way that refuses to be impressed by small numbers. One
> success out of one attempt is recorded as roughly two-thirds, not as a hundred per cent — because one
> coin toss coming up heads is not evidence that a coin always does. Only as the number of attempts grows
> does the recorded rate approach the observed rate.

### 3.9 — Chapter 04, lines 351–356

**Now:**

> Its own comment records that a sufficiently low-level programming trick could still fabricate such an
> object in memory, as it could against any in-process guard of this kind. That path is *contained*
> rather than relied upon…

**Suggested:**

> The software is honest about what this cannot stop. A sufficiently determined programmer with access to
> the running program could, in principle, forge one of these approvals in the computer's memory — and
> that is true of any protection of this kind, in any software. So the design does not rely on it.
> Instead, the last step catches it anyway: before a proven finding is sealed and signed, the checker is
> run again over the saved evidence. A forged approval that never went through the proper route simply
> does not reproduce, and cannot be sealed.

### 3.10 — Chapter 10, lines 200–205 *(the grounding tiers)*

**Now:** a four-row table whose third column lists source-string prefixes (`oracle:`, `cert:`, `intel:`,
`intel-fused:`, `derived:`, `infer:`, `scan:`, `fingerprint:`, `llm`, `assume`, `guess`, `unverified`,
`advisory`, `demoted`).

**Suggested:** keep the four tier names and the meanings, and replace the third column with plain
sources:

| Tier | Meaning | What produces entries of this kind |
|---|---|---|
| **grounded** | A checker fired over saved evidence, or a signed certificate exists. | The confirmation step; a signed evidence certificate; a proven finding. |
| **intel** | Genuine information that was collected, or worked out from collected information — but not proof. | Background research; scanning; conclusions reasoned out from other observations. |
| **ungrounded** | The AI said so, or somebody assumed it, or a claim that has since been withdrawn. | AI output; assumptions; anything demoted after its proof stopped reproducing. |
| **unclassified** | The source does not match any of the above. | Anything else. |

*(A footnote can carry the prefixes for a technical reviewer.)*

---

## 4. A draft shared glossary

Entries a `14-glossary.md` would need, written to the register the set already uses well. Terms already
defined well somewhere in the set are marked with their source, so the wording can be lifted rather than
reinvented.

| Term | Suggested plain definition |
|---|---|
| **Checker** *(the standing name — see §1.A)* | A small, fixed program that looks at saved evidence and answers one narrow question, always the same way. It has no intelligence, cannot reach the network, and cannot read the clock. The software calls it an *oracle*. |
| **Fail-closed** | If a safety check cannot be completed — an error, an unreadable file, a missing answer — the result is "no". Like a drawbridge held up by power: cut the power and it falls shut. |
| **Deterministic** | Same input, same answer, every time, on any machine. A recipe, not a chef. |
| **Payload** | The test input the system deliberately sends, to see how the target reacts. |
| **Sink** | The place a piece of data ends up — a database query, a page a browser will run, a file the server reads. A weakness usually means untrusted input reaching a sink. |
| **Provenance** | The recorded history of where a piece of evidence came from and how it was obtained. |
| **Evidence branch (window)** | One specific way of seeing something — "in the response headers" as opposed to "in the page body". A different window can support a different strength of claim. *(from ch05 line 706)* |
| **Fingerprint (hash, digest)** | A short code computed from a file's whole content. Change one byte and the code changes completely. It cannot be worked backwards. *(from ch06 line 220)* |
| **Out of band** | Delivered through a completely different channel from the thing it protects — a website, a letter, a phone call — so that faking one does not fake the other. *(from ch07 §9)* |
| **Loopback / `127.0.0.1`** | The address a computer uses to talk to itself. No machine anywhere else can reach it. *(from ch09 line 33)* |
| **Charter** | The written, signed authorisation for one engagement: what may be tested, by whom, and until when. Nothing runs without one. *(from ch02 §9)* |
| **Vendored** | A copy of somebody else's software kept inside this one, with its original licence and credits. |
| **Idempotent** | Running it twice does nothing extra; it is safe to press again. *(from ch09 line 973)* |
| **Fixture evidence** | Recorded sample data used in place of the real thing, so a capability can be proven without a live target. *(from ch09 line 1303)* |
| **Pull request** | A proposed code change raised so a human can review it before it becomes part of the software. *(from ch08 §5.1)* |
| **The spine** | The append-only signed record of everything that happened. Entries can be added, never edited or erased. *(from ch02 §9)* |
| **Monotonic** | It can only ever move forward, never back. |
| **Denominator** | What a coverage claim was measured *out of*. A "clean" result covers only what was actually reached — that is its denominator. |
| **m-of-n** | Several named key-holders, of whom a set number must agree. Like a vault needing two managers' keys at once. *(from ch07 §8)* |
| **Kill switch** | A file on disk that, while it exists, causes every action to be refused. Because it is a file, tripping it survives a crash or a restart. |

---

## 5. What should not be changed

Listing this explicitly, because a plain-language pass can do real damage if applied indiscriminately.

1. **Every "what this does not prove" column, every honest-status ledger, every named deferral.** These
   are the reason the document is worth reading. Make them *easier to read* (see §1.E); never shorten
   them.
2. **The four-word verdict vocabulary** (FACT / LEAD / CLEAN / INCONCLUSIVE) and its consistent use
   across all thirteen chapters. It is applied correctly everywhere I checked.
3. **The numbers.** The counts — 38 checkers, 40 procedures, 15 frozen, 85 categories, 190 synonyms, 275
   names, 26 evidence routes, 6 clean-capable, 17 with named outstanding work, 33 catalogued tools, 2
   fact-capable, 17 excluded, 13 certifiable-by-silence, 28 screens — are **consistent across every
   chapter that states them**. That consistency is itself an argument for the document's care and should
   survive any edit. (The two exceptions to fix are in §1.I: 186 vs "roughly two hundred", and chapter
   05's "three counts" over a seven-row table.)
4. **The refusal to claim field-proven status for the cloud capabilities.** Chapter 09 §7.1's
   formulation — *"built, gated, and proven offline; live fire awaits operator-supplied credentials, by
   design"*, with the explicit warning that both the "unfinished" and the "field-proven" framings are
   wrong — is the best wording in the set and should become the canonical sentence in every chapter that
   touches the subject.
5. **The best analogies**, listed in §1.G. They should be reused more, not replaced.
