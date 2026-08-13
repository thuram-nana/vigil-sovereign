# Honesty & accuracy review — `docs/plain-english/`

**Role:** adversarial fact-checker. Every substantive claim in the thirteen chapters was checked against
the code in `/home/kali/vigil` at `1487e03a` (`main`), plus the in-flight supply-chain branch
`a14-supply-chain` @ `4567f5ab` (worktree `/home/kali/vigil-wt-a14`). The hunt was for (a) overclaims —
"done / proven / live / deployed" where the code shows partial, deferred, awaiting-credentials, or
capability-not-deployment; (b) invented detail — features, screens, numbers, tool names that do not
exist; (c) claims a non-expert would read as a stronger guarantee than the system gives.

> **Note on provenance of this file.** Two independent honesty passes were run over these chapters and
> both wrote here. This document is the **merged** result. Where the two passes disagreed, the
> disagreement was re-adjudicated against source and the resolution is recorded inline (see §3, which
> reverses one pass's headline finding, and §6, which corrects the other's identification of a missing
> branch). Findings unique to one pass are marked **[pass A]** or **[pass B]**; findings both passes
> reached independently are unmarked.

**Headline: the briefing is in unusually good shape.** Of ~150 discrete numeric/structural claims
re-derived from source across the two passes, **essentially all were exactly right**, including every
load-bearing count (38 oracle kinds / 40 oracle functions / 85 bug classes / 190 aliases / 275 accepted
names / 15 frozen fallback / 26 evidence branches / 6 clean-capable / 17 with blocking work / 6 with a
downgrade rationale / 13 silence-certifiable kinds / 33 catalogued tools of which 2 fact-capable and 17
excluded / 28 UI screens / 22 legacy console screens / 31 CRUCIBLE subcommands / 26 `vigil` verbs / 38
`sigil` verbs / 15 blackboard event kinds / 22 node kinds / 24 edge kinds / 12 techniques (6 core + 6
extended) / 12 detection procedures in 13 rows / 17 credential slots of which 12 probeable / 6 required
+ 7 optional host tools / 24 sandbox tools / 11 seed checks / 172 library entries / 32 screenshots /
186 IGO domains / 2 MCP tools / 25 sovereign actions / 900 s dead-man cap / 0.99, 0.999, 0.70, 0.95,
0.92, 0.90 thresholds / 0.2-1.0-5.0+3.0 s posture pacing / request budget 100 / intake budget 50 at
0.3 s / AEGIS 0.40/0.50/0.55/0.66 / detection thresholds 15, 12, 3, 5, 3, 8, 8+2).

Notably, in **every** case where a chapter's number disagreed with a `_inventory/` file, the chapter was
right and the inventory was stale (31 vs 28 CRUCIBLE subcommands; 26 vs 24 `vigil` verbs; 38 `sigil`
verbs where a naive grep says 36). The chapters were genuinely re-derived, as they claim.

**One claim was re-executed rather than read.** Chapter 4 §10 states the shipped negative control
confirmed "through the differential-response referee at confidence 0.971" on the vulnerable twin and
"returned nothing at all" on the safe twin. Running `confirm_against_local_target` against both
handlers in `.venv-offense`:

```
VULN: (<OracleKind.DIFFERENTIAL_RESPONSE: 'differential_response'>, 0.9711)
SAFE: None
```

Exact match, including oracle kind and confidence to three decimals.

**Bottom line.** Two findings need real edits before this goes to an agency (§1 and §2). The rest are
factual slips, cross-chapter inconsistencies, or wording that under- or over-shoots the code by a
modest margin. **No chapter contains a fabricated feature, screen, tool, or capability, and no chapter
presents a deferred capability as field-proven.** Two of the defects make the system look *worse* than
it is; one implies a safety gap that does not exist.

**Chapters 4 and 10 need no changes** and should be treated as the standard the others are brought up to.

---

## Severity key

| | Meaning |
|---|---|
| **HIGH** | An agency reader would take away a stronger guarantee than the system gives. |
| **MEDIUM** | Factually wrong, self-contradictory across chapters, or understates in a way a reviewer would catch and lose trust over. |
| **LOW** | Precision / consistency fix. |

---

## 1. MEDIUM-HIGH — Ch06 §11: supply-chain hardening written in the present indicative for work that is not on `main`

**File:** `06-evidence-and-proof.md` §11.1–§11.5.

**The claims, as written:**

- §11.1: *"**Every** base image in the repository **is** pinned this way…"*; *"Floating `latest` references
  hidden behind environment variables **were removed outright**."*
- §11.2: *"**Every** third-party software package the system installs **is** pinned to an exact version
  **and** to a cryptographic fingerprint of the exact file, and installation **is performed** with hash
  checking required."*
- §11.3: *"One **is generated** for each of the two environments … and **published** as a build artifact."*
- §11.4: a CRITICAL-blocking gate with a pinned scanner and five permitted suppression reasons.
- §11.5: *"In the new gate **every one of them is pinned** to an exact commit."*

**What `main` @ `1487e03a` actually shows:**

| Claim | State on `main` |
|---|---|
| base images digest-pinned | **False.** `vendor/strix/containers/Dockerfile:1` = `FROM kalilinux/kali-rolling:latest`; `aegis/Dockerfile:15` = `FROM python:3.11-slim`; `eval/corpus_apps/_smoke/Dockerfile:3` and `_cve/st-2014-3744/Dockerfile:1` = `FROM node:22-bookworm`. No `@sha256:` anywhere. |
| floating `latest` behind env vars removed | **False.** `docker-compose.yml:26` = `qdrant/qdrant:${QDRANT_VERSION:-latest}`; `:51` = `otel/opentelemetry-collector:${OTEL_VERSION:-latest}`. |
| dependencies hash-locked | **False.** `requirements.lock.txt` on `main` contains **zero** hashes; its own header reads *"This skeleton is intentionally NOT a real lock."* |
| SBOM generated + published | **Not as described.** `sbom.json` `metadata.tools[0].name` is literally `"scaffold (operator regenerates with cyclonedx-bom)"`, timestamp `0000-00-00T00:00:00Z`. |
| CRITICAL gate / `.trivyignore` / pinned actions | **Absent from `main`.** `.github/workflows/` contains only `ci.yml`. |

The work is real but lives **only on the unmerged branch `a14-supply-chain`** (`5f730b5d`, `4567f5ab`),
which adds `.github/workflows/supply-chain.yml`, `.trivyignore`, `infra/supply-chain/`,
`docs/SUPPLY-CHAIN.md` and two populated locks. `git diff --stat main..a14-supply-chain` = 17 files,
+3566 lines. The branch is pushed (`origin/a14-supply-chain`) but **not merged**.

**Why this matters.** §11.7 *does* disclose the branch situation honestly — but it sits ~130 lines and
six subsections after the claims. Under this project's own Claim-Discipline rule 3 (*"Any document that
claims a capability must state the boundary of that capability **in the same place**"*), five
subsections of unqualified indicative prose with the boundary six subsections downstream is exactly the
*"scope inflation is the most common way honest text becomes dishonest"* failure the doctrine names.

**Recommended fix (raises nothing, lowers nothing):**

1. Move the §11.7 status paragraph to the **top of §11** as a bold banner: *"Status at the time of
   writing: this work is complete on its own branch (`a14-supply-chain`) and had **not** been merged to
   `main`. Verify the current branch state before relying on any of §11.1–§11.5."*
2. Change the tense in §11.1–§11.5 to "**on that branch**, every base image is pinned…". One clause per
   subsection is enough.
3. §11.7's *"Verified directly in the working tree at the time of writing"* should name the tree
   (`branch a14-supply-chain`), because it is not true of `main`.

Chapter 4 §9 already handles this correctly (*"They were not yet observable on the main line of the
repository at the version examined for this chapter"*), and ch9 §7.2 handles it correctly by declining
to enumerate. Chapter 6 should be brought to the same standard.

---

## 2. MEDIUM-HIGH — Ch08 §4.5: the Strix shell gate is default-ON but **best-effort / fail-open**, and the chapter says the opposite  **[pass A]**

**File:** `08-safety-and-authorization.md` §4.5 (weaker form in ch02 §3.6, ch11 §5.4, ch12 §1.7).

**The claim:** *"That shell is routed through the approval queue, and the gate is **on by default**.
There is an explicit environment setting to turn it off, **which means turning it off is a deliberate,
visible act rather than an accident.**"*

The chapter is right that the gate is default-ON, and right to flag `docs/AS-BUILT.md` §2.1 as the stale
document. But `vendor/strix/strix/core/runner.py:237–242` reads (verified verbatim):

```python
# A wiring error also falls back to the base hooks so it never stops a scan (best-effort);
# the gate is default-ON, not opt-in.
try:
    from vigil_integration.warden_gate import attach_from_env
    hooks = attach_from_env(hooks)
except Exception:  # noqa: BLE001 — never let WARDEN wiring stop a scan
    pass
```

There are **three** ways the gate ends up absent, and only one is the deliberate opt-out:

1. the explicit env opt-out (`VIGIL_WARDEN_STRIX_GATE` in `{0,off,false,no}`) — deliberate, as stated;
2. `vigil_integration` not importable (a bare vendored checkout);
3. **any exception during wiring** — swallowed by a bare `except Exception: pass`, leaving the arbitrary
   `exec_command` / `write_stdin` shell **ungated with no signal to the operator**.

Case 3 is precisely "an accident", on the surface the chapter itself calls *"the single most dangerous
surface in the whole system, because it can run anything."* **This is the one place in the briefing
where a safety property is stated more strongly than the code delivers**, and it is the finding to fix
first.

**Recommended fix.** Add to §4.5: *"The gate is attached best-effort: it is default-on, but if the
integration package cannot be imported or the wiring raises, the code deliberately falls back to the
ungated hooks rather than stopping the scan. A deployment relying on this gate should confirm at runtime
that it attached, rather than assuming it did."* Then soften "rather than an accident" to "rather than a
silent default". Ch12 §1.7 needs the same caveat or a cross-reference.

---

## 3. MEDIUM — The veracity firewall: the module docstring is **stale**, and the chapters disagree with each other in *both* directions

**Files:** `01` §2.7; `02` §3.3 and §8; `04` §4-stage-5 and §10; `05` Part 5 table; `06` §10.1 table;
`10` §12.4 and §17; `11` §9.4 and §10.

> **Adjudication note.** The two passes reached opposite conclusions here — pass B graded ch2/ch11 a
> HIGH overclaim; pass A found the underlying docstring stale. Re-checked against source: **pass A is
> right**, and pass B's HIGH is withdrawn. The finding below is the reconciled version.

Five chapters faithfully reproduce `veracity/firewall.py:27–30`:

> *"NOTE ON PHASING: this is the caller-less PRIMITIVE (veracity P0). Runtime enforcement is wired in
> the subsequent phases … **Until then `admit()` is exercised only by its tests**; that is by design,
> not a gap."*

**That docstring is out of date.** `admit()` / `admit_finding` / `claim_from_finding` have real
production call sites today (all verified by grep, excluding `veracity/` itself and all test files):

| Call site | What it gates |
|---|---|
| `framework/v2/engage.py:232,237` | per-finding admission against the chained world model |
| `framework/v2/report/grounding.py:7,41–51` | `admit_for_report` — the shared reporting authority |
| `framework/v2/aegis/pipeline.py:132` | the AEGIS oracle-then-firewall gate |
| `framework/v2/agents/critics.py:68–70` | the grounding critic |
| `framework/v2/agents/cognitive_refusal.py:42–44` | the refusal path |
| `framework/v2/agents/tools/builtin.py:55–56` | the agent tool surface |
| `framework/v2/scanner/report.py:130–131` | the scanner's own report path |

The *substantive* claim — "it is not today a single universal choke point every claim in the system
crosses" — **remains defensible**: the world-model write path is not routed through `admit()`
(`worldmodel/` reuses the shared `classify_provenance` instead). What is **wrong** is *"exercised only
by its tests"* and *"later phases are still being connected"*.

So the chapters are inconsistent in both directions:

- **Under-claiming from the stale docstring:** ch01 §2.7 (strongest form), ch05 Part 5, ch10 §12.4.
- **Over-claiming past what is wired:** ch02 §3.3 (*"**At every hand-off** it re-runs the proof that a
  claim cites"*) and ch11 §9.4 (*"**Underneath all of it** sits the claim-admission choke point.
  **Every claim** that wants to be treated as a fact is re-checked"*). "At every hand-off" and "every
  claim" are still not true, because the world-model write path is not routed through it — and ch11 §10
  omits the firewall from its "Built, but honestly bounded" list entirely.
- **Correct:** ch04 §5 (*"it is called at specific real points — including report generation and writing
  findings into the system's internal map"*) and ch06 §10.1 (*"The report layer **does** route every
  finding through it at render time"*).

**Recommended fix.** Align all seven on ch04/ch06's wording: the firewall is wired into real production
paths (engage, reporting, AEGIS, critics, refusal, scanner report), and it is *not* yet a single
universal checkpoint because the world-model write path uses the shared provenance classifier instead.
Drop "later phases are still being connected" from ch01 §2.7; drop "at every hand-off" from ch02 §3.3;
qualify ch11 §9.4 and add a row to its §10.

**Separately, flag to the engineers:** `veracity/firewall.py`'s own docstring should be corrected. These
chapters are correctly quoting a stale source, which is how a documentation defect propagates into a
briefing.

---

## 4. MEDIUM — Ch01 §8.4 and Ch12 §2.9 carry a **stale snapshot** of today's supply-chain work, stated as a direct observation  **[pass B]**

Both chapters describe the branch state as of earlier today, and both have since drifted.

**Ch01 §8.4**, under the heading *"Honest status, checked directly in the working tree today"*:

> Two artefacts inside that tree — the compiled dependency lock for the offensive half, and the
> committed bill of materials — are still the placeholder versions … A supporting policy document
> referenced by the workflow (`docs/SUPPLY-CHAIN.md`) did not exist in the tree at the time of writing.

**Ch12 §2.9:**

> Still in flight at that moment: the accompanying written policy document, and the generated,
> fingerprint-bearing dependency lists themselves.

Both are now false:

- `docs/SUPPLY-CHAIN.md` **exists** on the delivery branch (11,227 bytes).
- Commit `4567f5ab` ("A14: commit the two real hash-locked dependency locks") replaced the offence lock;
  `requirements.lock.txt` now carries **640** `--hash=sha256:` lines, and
  `infra/supply-chain/sovereign.lock.txt` is 103 KB of pinned hashes.
- **One** artefact is still a placeholder: `engine/crucible/framework/v2/sbom.json`
  (`crucible:sbom-status = SCAFFOLD`, `0000-00-00T00:00:00Z`).

Direction of error is conservative — but ch01's paragraph *explicitly claims to have been checked in the
tree today*, which is Claim-Discipline rule 7 (*"Never state a test result you have not just observed"*).
And ch06 §11.7 already carries the current wording, so three chapters now give three different snapshots
of the same branch, taken hours apart.

**Recommended fix.** Make ch06 §11.7 the single source (once §1 above is applied to it), have ch01 and
ch12 point at it, and add a one-line publication checklist to the review folder:

> Before publishing, run `git -C /home/kali/vigil-wt-a14 log --oneline -3`, `ls infra/supply-chain/
> docs/SUPPLY-CHAIN.md .github/workflows/`, and check whether `a14-supply-chain` has merged to `main`.

**As of this review: not merged.**

---

## 5. MEDIUM — Ch06 §10.1: "Five of the six … none can fire during an ordinary scan" (it is all six)  **[pass B]**

**File:** `06-evidence-and-proof.md` §10.1, closing paragraph.

> **Five of the six** cloud and Kubernetes exploitation capabilities share one further safety property
> worth stating to any agency reader: **none of them can fire during an ordinary scan.** They are
> deliberately excluded from the fallback set of tests an unknown weakness class may run…

All **six** E-series oracle kinds sit outside the frozen 15-member `_ALL_ORACLES` (re-derived):
`IMDS_CREDENTIAL_CAPTURE`, `SECRET_CREDENTIAL_VALIDITY`, `GCP_SA_IMPERSONATION`,
`IAM_ESCALATION_PRIMITIVE`, `K8S_RBAC_VERB_GRANT`, and `K8S_WORKLOAD_POSTURE` (E4 Tier 1). Chapter 1
§8.3 states it correctly: *"**None** of the six checkers is in the frozen fallback set."*

Graded MEDIUM not because the chapter overclaims but because of what "five of the six" implies to the
reader it is written for: that **one** cloud-credential oracle *can* fire during an ordinary scan — and
the chapter does not say which. That is a worse impression than the truth, and it contradicts ch01.

**Fix:** "All six … none of them can fire during an ordinary scan."

---

## 6. LOW-MEDIUM — the "five vs six" E-series count is resolved differently in four chapters

The registry has **six** exploitation branches; **six** carry a `target_downgrade_rationale`; **all six**
oracle kinds sit outside the frozen fallback; **five** of the six producers carry a "Real-transport
LIVE-FIRE … is deferred" docstring — the sixth, `live/iam_escalation_verify.py`, does not (verified
across all seven E-series modules). Every "five" in the set should resolve to one of those.

| Location | Says | Should say |
|---|---|---|
| `05` §"The five branches whose negative is deliberately not targeted" | heading "five"; body correctly says *"Six branches (covering five capability areas)"* | fix the **heading** to six |
| `06` §9.6 | *"**Five** of the exploitation-confirmation branches…"* then lists five | six — the omitted one is **`k8s_exploit.rbac.dangerous_verb_grant`** (pass A misidentified this as `cloud_exploit.iam.privilege_escalation`; re-checked, the IAM branch **is** in ch06's list and the K8s verb-grant branch is not) |
| `03` §15 | *"the **five** achieved-effect branches"* | six, five of which await live fire |
| `06` §10.1 | "Five of the six" | all six (see §5 above) |

Ch04 §10 and ch09 §7.1 already do this correctly and can be copied verbatim.

---

## 7. LOW-MEDIUM — Ch03 §2: "Four real charters exist in the repository today"  **[pass B]**

> Four real charters exist in the repository today: `loopback`, `testphp`, `testasp`, and a practice one.

There are **three**. `find targets -name charter.md` returns exactly `targets/loopback/charter.md`,
`targets/testphp/charter.md`, `targets/testasp/charter.md`. `targets/_practice/` contains a single file,
`README.md` — no charter. This is invented detail in a chapter that opens by promising every statement
was checked.

**Fix:** "Three real charters … plus a practice folder that carries a README rather than a charter."

---

## 8. LOW-MEDIUM — Ch08 §1.1: the charter template has fifteen sections, not fourteen, and does not contain "2b"  **[pass B]**

Two slips in the same table:

1. *"The standard charter template runs to **fourteen** numbered sections."*
   `engine/crucible/targets/_template/charter.md` has **fifteen**; the fifteenth is
   `## 15. Engagement closure`, which the table then omits entirely.
2. The table lists **"2b. Cloud scope"** as a section of the standard template. **No charter in the tree
   contains a `## 2b` heading** — not the template, not `loopback`, `testphp` or `testasp`. It exists
   only as a pattern the parser recognises (`live/cloud_scope.py:115`,
   `r"^##\s*2b\.\s*Cloud scope\b"`). An operator who opens the template expecting to find it will not,
   and will conclude the briefing was written from documentation rather than from the artefact.

**Fix.** Say fifteen and add the closure row; present 2b as the additive section the parser recognises
and the operator adds when a cloud target is in scope — which is what it is, and is still a good story.

---

## 9. LOW — Ch13, "What AEGIS can prove and block today": the 3+3 lead-in contradicts its own 4+3 table  **[pass A]**

**File:** `13-defence-and-source-code.md`, Part 1.

The lead-in reads *"**Three** of these are judged from the incoming request alone; three require seeing
what the application sent back."* The table beneath has **seven** rows, of which **four** say "The
request alone" (`sqli_attempt`, `command_injection_attempt`, `nosql_injection_attempt`,
`automated_access`). The paragraph immediately after the table then says *"The **first four** prove that
a structured attack attempt occurred"* — contradicting the lead-in.

**Code:** `aegis/inspect.py:10–14` lists four request-side classes (honeypot → `automated_access`, plus
`_REQUEST_PAYLOAD_CLASSES` at `:37` = the three parse-proofs); `inspect_response()` at `:389ff` covers
`xss` (`:419`), `ssti` (`:436`), `path_traversal` (`:461`). The table is right; the lead-in is wrong.
**Fix:** "Four of these … three require …".

---

## 10. LOW — Ch13 opening: "Four of the 38 belong to the defensive side" (there are seven)  **[pass B]**

Chapters 4 and 5 both place **seven** oracles on the defensive side: the four AI/abuse detections
(`PROMPT_INJECTION`, `SYSTEM_PROMPT_DISCLOSURE`, `AUTOMATED_ACCESS`, `CREDENTIAL_STUFFING`) **plus** the
three request-only break-out oracles, which ch04 §3 describes as *"three referees that read the request
alone… an inline protective layer"*.

Chapter 13 then lists those same three break-out classes two sections later as AEGIS's request-side
blocking classes — so the chapter contradicts its own next page.

**Fix:** "Seven of the 38 belong to the defensive side: four AI-and-abuse detections and three
request-only break-out judgements."

**Related, and worth one clause:** ch02 §3.4 says the embeddable AEGIS library *"can confirm four
classes today"* while ch13 lists seven for the inline gateway. Both are correct — they are different
surfaces (SDK pipeline vs. RAMPART inline gateway) — but neither chapter says so. One cross-reference in
ch13 ("these are the inline gateway's classes; the embeddable SDK's four are listed in chapter 2")
removes the apparent contradiction.

---

## 11. LOW — Ch09 §8: the "documentation drift" row misstates the drift  **[pass A]**

Claim: *"Two internal documents are stale on the screen count: one file says '21 screens' and another
says '22'."*

**Actual:** both stale files say **21**, in five places — `packages/vigil-ui/README.md:6`, `:35`, `:102`
and `knowledge/kb/console-and-ui.md:11`, `:25`. No file claims 22 for the unified UI; 22 is the
*correct* count for the legacy CRUCIBLE console.

Everything else in that row is right: `knowledge/system-map/screens.yaml` has exactly 28 ids, and `NAV`
in `packages/vigil-ui/app.js:19–54` has 11 DO + 13 MANAGE + 4 LEARN = 28. **Fix:** "two internal
documents still say '21 screens'".

---

## 12. LOW — Ch09 §5.8: MCP exposure described as a "fixed set" when it is a widenable default  **[pass A]**

Claim: *"The list is a fixed set in the source code, is the same for every engagement, and fails closed."*

**Code:** `mcp/server.py:67` — `DEFAULT_EXPOSE_ALLOW = frozenset({"reverify_finding",
"declared_service"})`, with the comment *"the ONLY capabilities advertised/permitted over MCP **unless
the operator explicitly widens it**"*; `ExposePolicy.__init__` accepts an `allow=` override.

The "exactly two tools" count and the fail-closed property are both correct, and the defence-in-depth
re-check (Tier-1 / no capability / non-destructive / no egress, all read defensively so a raising
attribute means non-exposable) is real. Only "fixed set" overstates immutability. **Fix:** "a
fail-closed **default** allowlist of exactly two, which an operator can widen explicitly".

---

## 13. LOW — Ch11 §6 lists the hard guardrail as an active fence  **[pass B]**

**File:** `11-the-agents-and-learning.md` §6.

> | **Hard guardrail** | A non-disableable categorical refusal of certain target classes. |

Presented in a table headed *"the fences every agent runs inside"*, with no qualification. Chapters 1
§5.2, 3 §5 and 8 §2.5 all state — correctly, and re-confirmed here — that `assert_not_hard_blocked` has
no live call site anywhere outside its own package export, its test file, and these documents. Listing
it beside the conjunctive gate and the egress gate as an operating control contradicts three other
chapters.

**Fix.** Add the same one-clause note the other three chapters use: shipped and tested; wiring into the
live path not verified.

---

## 14. LOW — Ch05: two claims that overshoot what the code establishes  **[pass B]**

**a) "near-zero false positive" asserted as a property.**

> The permission-rule test uses a deliberately narrow eligibility gate, **which is the reason it is
> near-zero false positive.**

"near-zero-FP" is the code's own self-description (`verify/oracles.py:6235`, *"the SUBJECT-GATED
eligibility that is the near-zero-FP fix"*). It is a design rationale, not a measured false-positive
rate, and no measurement of one exists in the repository. Stating it flat in an agency briefing asserts
a quantitative property the project has not established.

**Fix.** Attribute it (*"which the code describes as its near-zero-false-positive fix"*) or describe
what the gate does — anonymous subjects may confirm on any dangerous shape; default-SA and
`system:authenticated` only on a full cluster-wide wildcard — and drop the rate claim. The mechanism is
impressive on its own and does not need the number.

**b) the accreditation framing in Part 4.**

> "We proved this weakness is not present" is what allows a system to be **accredited**, a control to be
> signed off, or a recently-patched service to be returned to production.

Nothing in the repository supports a claim that a posture certificate participates in any accreditation
regime, and an agency reader is exactly the audience who will read it as one. The sentence is *about*
negative claims in general, but its placement makes it read as a statement about this product's
certificate. **Fix:** reframe to what the certificate is — a signed, coverage-bounded,
offline-re-checkable negative — and let the reader draw the procurement conclusion.

---

## 15. LOW — Ch06 §10's heading says "live-fired"  **[pass B]**

> ## 10. Honest status: built, proven, and **live-fired**

Nothing in section 10 is live-fired against a third party; the section's entire content is the opposite,
and it says so carefully and well. A reader skimming headings in a briefing document takes away exactly
the wrong claim. (Compare ch12 §2.10: *"Honest status: built, but not yet fired at a live outside
system"* — correct.) **Fix:** "Honest status: what is working, what is proven offline, and what is
deferred."

---

## 16. LOW — "roughly two hundred" IGO domains, where every other count is exact

**Files:** `01` §5.2; `08` §2.5.

Actual: `len(_EXACT_BLOCKED_DOMAINS)` in `safety/hard_guardrail.py` = **186**. Defensible rounding, but
these chapters otherwise give exact, re-derivable counts for everything and ch01 §10 explicitly invites
the reader to re-derive them. An inexact number in that company reads as an estimate someone did not
check. **Fix:** say 186 in both.

---

## 17. LOW — Ch01 §8.3: "not awaiting live fire" for IAM privilege escalation needs one more clause  **[pass B]**

> The **identity privilege escalation** capability is offline **by design, permanently**. … It is not
> awaiting live fire; not performing the action *is* the design.

The distinction is **real and correctly identified** — `iam_escalation_verify.py` is the only one of the
six E-series producers with no "LIVE-FIRE … deferred" sentence, and it genuinely never executes the
escalation.

But the module's first line reads: *"A cloud/CSPM sensor (or an operator IAM export) produces a RETAINED
IAM-policy capture"*. Getting that capture from a real account still requires the customer's read-only
cloud credentials — which §8.5 of the same chapter lists as outstanding. A non-expert reads "not
awaiting live fire" as "this one already works against a real cloud account".

**Fix.** Keep the distinction; add the clause: *it still needs a real IAM capture, which needs the
customer's read-only credentials; what it will never need is to execute the escalation.*

---

## 18. LOW — two status sections omit the supply-chain safeguards entirely  **[pass B]**

Ch02 §8 ("Honest status of the parts") and ch03 §15 ("What is fully working…") both enumerate status
across the system and neither mentions the build-and-release safeguards, which every other status
section covers (ch01 §8.4, ch04 §9, ch06 §11, ch09 §7.2, ch12 §2.9). Conspicuous in ch02, whose subject
is *the parts*.

**Related, same two chapters:** both list the E-series only under a "not yet fired" heading without
recording that all six are complete, merged and fixture-proven offline — the underclaim half of the
ratchet the doctrine prohibits. Ch12 §2.10's paragraph is the best-calibrated version in the set and
should be reused.

---

# Chapters requiring no changes

## `04-leads-and-facts.md`

Every checkable statement survived. Counts re-derived: 38 kinds / 40 procedures; 15 frozen; 85 / 190 /
275; 26 branches, 26 fact-capable, 6 clean-capable, 17 with blocking work; 33 catalogued tools, 2
fact-capable (`nmap`, `sslscan`), 17 excluded; 0.70 / 0.99 / 0.999; minimum 8 resolved outcomes; 13
silence-sound kinds; **6** branches with a `target_downgrade_rationale` — the only place in the set that
gets the six/five distinction right in both directions. The Group 1–5 oracle tables (15 + 4 + 3 + 10 +
6 = 38) are accurate down to the individual refusals. §10's negative control was **re-executed** and
reproduces exactly. The veracity phasing is marked in three places, the E-series framing is correct, and
the supply-chain status is correctly scoped to `main`.

## `10-the-picture-of-the-attack.md`

22 node kinds and 24 edge kinds match `NodeKind` / `EdgeKind` one-for-one and in order. 12 techniques:
`knowledge/catalog.CATALOG` = 6 (`unauth-endpoint-read`, `credential-reuse`, `token-replay`,
`ssrf-internal-reach`, `role-assumption`, `deserialization-to-code-exec`) and
`catalog_ext.EXTENDED_CATALOG` = 6 (`credential-leak-capture`, `datastore-secret-extraction`,
`host-takeover`, `lateral-pivot`, `token-leak-capture`, `session-theft-takeover`) — the chapter's
plain-English names map to these exactly. Strict-mode floor 0.2; fallback confidences 0.9 / 0.5; four
grounding tiers; six-hop cap. §12.4's separation of the *live* map-building re-execution from the
not-yet-universal primitive is the model fix for finding §3 above.

One nit, not worth a change alone: §7.1's "Four are shipped as the standard set" is 2 in
`derivation.DEFAULT_RULES` plus 2 in `attacker.ATTACKER_RULES`, which the module docstring says to
compose. Accurate in substance; if the chapter is touched anyway, say "four across two composed sets".

## `07-signing-and-keys.md`

Checked hardest because it is where a signing chapter usually overpromises, and it does not. The ten
domain-separation labels match `spine_domains.DOMAIN_TAGS` exactly and in order, and the chapter
correctly reports the two segments carrying **no** tag. The six-row record table matches the `DOMAINS`
tuple entry for entry, including both `owner_rooted=False` rows. Worth noting: the module's own
*docstring* is stale there — it claims the offence spine is `owner_rooted=False` while the `DOMAINS`
data says `True` (a real consumer, `spine_verify.verify_offense_spine`, now exists). **The chapter
followed the data rather than the prose, which is the correct call** — and is the same class of defect
as finding §3. All honest gaps are real and stated: no pre-expiry delegation revocation; in-flight
capabilities still spend; no scheduled key rotation; the `O_CREAT|O_TRUNC` write on
`authorize-destruction`; the RFC-3161 anchor as *"CAPABILITY, not a VERIFIED FACT of independence"*.

## `09-the-screens.md`

The most number-dense chapter and, apart from findings §11 and §12 above, faultless: 28 screens (11 DO
/ 13 MANAGE / 4 LEARN); 26 native `vigil` verbs (31 `add_parser` entries minus 5 nested); 31 CRUCIBLE;
38 `sigil` (36 declared + `approve`/`deny` added in a loop at `cli.py:1300`); 6 gateway; 3 aegis; 2 MCP
tools, and they are exactly *"one that re-verifies a finding, and one that describes a declared
service"*; 25 sovereign bridge actions (8 base + 8 capability + 9 settings); 32 screenshots with exactly
MCP Servers, System & Services and Proof of Posture missing; 22 legacy console screens; 5 cockpit
panels; 13 manual sections.

**§7.1 is the best-calibrated passage in the entire set** on the E-series, and closes with both failure
modes named: *"Saying the capability is unfinished understates the system … Saying it has been
field-proven in customer clouds overstates it."* Other chapters should borrow it.

---

# Things checked and found accurate (so a re-reviewer does not redo them)

- **Every count in the headline paragraph.** Re-derived from source, not from docs. Ch04's closing
  provenance paragraph and ch01 §10 are both accurate about *how* they were derived.
- **The benchmark.** 11 planted / 5 controls / 11-0-0 for crucible, and comparators at 0, 2, 0 TP and
  0, 7, 8 FP (sqlmap 0/0, wapiti 2/7, nikto 0/8), match `BENCHMARK.md` §2. All chapters that quote it
  (01 §8.1, 04 §10, 12 §1.8) carry the fairness caveats rather than the headline alone, including the
  paper's own *"partly a home-field artefact"*.
- **The hard guardrail's wiring caveat** (ch01 §5.2, ch03 §5, ch08 §2.5). Re-traced: the only references
  outside the module and its test are `safety/__init__.py`. Correct, and correctly repeated three times.
- **The six cloud/K8s confirmations.** All six branches exist, all `fact_capable`, all six carry
  `target_downgrade_rationale`, all six have `blocking_work: null`, and all six oracle kinds sit outside
  `_ALL_ORACLES`. Ch04 §10, ch05 Part 5, ch06 §10.1 and ch09 §7.1 all state the position correctly and
  all four correctly single out `iam_escalation_primitive` as design-not-deferral.
- **Standalone verifiers.** `verify_pcf.py` imports only stdlib + `cryptography`; its *"what it does NOT
  do: re-run the oracle"* matches chapters 04/06/07/13. The posture oracles re-implemented producer-free
  in `verify_vf.py` (`_POSTURE_ORACLE_DISPATCH`) are exactly **six**, as ch06 §7.4 states.
- **Key/domain infrastructure.** 10 domain tags; 6 spine domains with `owner_rooted` matching ch07 §10
  exactly; 900 s dead-man cap on both `approval_token.py:144` (`max_token_lifetime = 900.0`) and the
  destruction policy.
- **The `sess-A` / 88-runs claim** (ch03 §3) — real on-disk state (`run_ids` length 88), not a fixture.
- **The external testasp run** matches `docs/AS-BUILT-LIVE.md:126`, and ch01 §8.2 correctly labels it
  *"I read the claim, not the run"*.
- **Ch12's credential table.** All 17 names and the 12-probeable split match `SECRET_META` exactly (the
  first 17 entries, before `CLOUD_CONFIG_META`; `"probe": True` appears exactly 12 times).
- **Ch12's tool tables.** Every tool name in all three tables (2 / 14 / 17) matches
  `docs/capability-matrix/hexstrike.json`; 24 sandbox tools; the `sqlmap`/`hydra` "excluded yet
  launchable" apparent contradiction is true and correctly explained.
- **Ch13's TLS numbers.** 14 weak-cipher markers matching `_WEAK_CIPHER_TOKENS` name-for-name and in
  order; four deprecated protocols; 0.95 / 0.92 / 0.95 / 0.90 confidences; the `control-test` AUDIT
  user-agent suffix; the certificate-validation-disabled rationale correctly paired with the opposite
  requirement on the IMDS runner.
- **Ch11's rate-limit arithmetic.** "5/s, 1/s, 0.2/s with jitter" correctly inverts `_RATE_PROFILES`'
  seconds-between-requests. Easy to get wrong; it is right.
- **Ch11's citations to `V2-LIMITATIONS.md` / `V2-MANIFEST.md`.** The 2026-06-27 live-hypothesis run
  (5 falsifiable hypotheses, `is_dryrun=false`, ~58 s) and the 2026-05-05 `mrbeanpanel.com` real-target
  run that produced **0 findings** both exist and are quoted faithfully, including *"The subsystems
  exist; the at-scale, real-target, finding-discovering autonomous loop does not yet."*
- **The UI-vendoring revert** (`d6a80b2d` / `a12961fe`, *"it broke the SIGIL sovereign plane (CI red)"*)
  — ch02 §3.9 and ch09 §1.3 are both accurate.
- **The AS-BUILT staleness call.** `docs/AS-BUILT.md` §2.1 does still say the Strix gate is *"gateable,
  **not** gated by default"*, which the code contradicts; the chapters are right to follow the code.
- **Ch03's remaining counts:** 11 seed checks (`DEFAULT_CHECKS`, exactly the eleven named, four OOB
  checks skipped without a receiver); 172 library entries; the compliance frameworks (OWASP 2021, CWE,
  PCI DSS v4.0, SOC 2 AICPA TSC 2017, ISO 27001, ATT&CK v15 + ATLAS); 8-hour / 1,000-action defaults.

---

# What neither pass found

Stated explicitly, because an adversarial review that reports only defects is not calibrated:

- **No invented feature, screen, tool, command or capability.** Every screen, verb, tool name, oracle,
  branch identifier, port, threshold and file path checked exists.
- **No case of a deferred capability presented as field-proven.** The E-series framing is correct in all
  thirteen chapters.
- **No case of a LEAD-grade capability described as producing facts.** The Strix leads-only caveat, the
  33-tool matrix, the static-analysis lead-only rule, the AI-critique caveat, the four unmonitored
  detection planes and the LEAD-only `waf_probe` / scanner-path-burst grades are all correct.
- **No inflated count.** Where a chapter disagreed with an inventory file, the chapter was right.
- **No suppressed limitation.** The unwired categorical guardrail, the local-only anti-rollback floor,
  the conditional split-view resistance, "distinct keys are not distinct operators", the model-level
  (not code-extracted) formal proofs, the zero-finding real-target agent run, the `O_CREAT|O_TRUNC`
  destruction write, the ZDR-attestation gap, and the manual covering 13 of 28 screens are all
  disclosed — several in more than one chapter.

---

# One note on tone, not accuracy

Chapters 01, 03, 05, 08 and 09 each contain a first-person verification note (*"in the reading done for
this chapter, no live call site was found…"*, *"this test was executed during the preparation of this
chapter…"*). These are the most valuable sentences in the briefing and should survive editing. They are
also the reason this review found so little: the authors marked their own uncertainty rather than
smoothing it.

The two substantive findings (§1 and §2) are both cases where that discipline lapsed — a status caveat
placed too far from its claim, and a fail-open path not carried forward from a code comment. Finding §3
is a third variety worth naming for the engineers: a chapter can be *scrupulously* accurate about a
source and still be wrong, because the source itself had gone stale. Two of the stalest artefacts in the
repository (`veracity/firewall.py`'s phasing note and `spine_domains.py`'s `owner_rooted` note) were
faithfully propagated into the briefing by chapters that were doing everything right.
