# TRUTHENOVATION — truth first, then innovation

> This system's moat is honesty: *it never lets an AI's word become a fact.* The harshest audit it can face is
> therefore an audit of **its own claims**. This document is that audit, and the program that turns every honest
> gap into a verified fact — while refusing to call anything "done" that software alone cannot make true.
>
> **Truthenovation = truth-first, then innovate.** No claim outruns what is *deployed and measured*; no innovation
> is shipped as reality until its verification passes. Where a property is irreducibly external, hardware, or
> social, we build the deployable mechanism and **state the residual**, because pretending otherwise is the exact
> overclaim this program exists to kill.

This is a living scoreboard. An item flips from **CAPABILITY / OVERCLAIM** to **VERIFIED FACT** only when its
verification below passes and `TRUTHENOVATION.md` is updated to say so. Companion: [`AS-BUILT.md`](AS-BUILT.md)
(status map), [`FEATURES.md`](FEATURES.md) (per-`file:line` catalog), [`VISION.md`](VISION.md) (roadmap),
[`proof-carrying-finding/TRUST-GRADIENT.md`](proof-carrying-finding/TRUST-GRADIENT.md) (the remediation gradient).

---

## 1. The truth discipline (binding rules)

Every claim in every VIGIL doc, screen, and comment is written under these six rules. A claim that violates one
is a bug to fix, not prose to defend.

1. **State-tag every claim: BUILT · DEPLOYED · MEASURED.** *Built* = code exists + tests pass. *Deployed* = wired
   and running in the real path (not only in tests). *Measured* = there is a number from a real run. Prose may not
   present a BUILT capability as if it were DEPLOYED or MEASURED.
2. **Soundness is not completeness.** "No false positive" (a fired oracle mints a fact) says **nothing** about "no
   false negative" (missed bugs). A soundness guarantee must never be worded to imply completeness.
3. **A capability is not an operating property.** "Continuously re-proven" requires a *running loop*; "witnessed"
   requires *deployed independent witnesses*; "time-anchored" requires an *actual anchor*. A primitive plus a
   manual CLI is a capability, not an operating property — say which.
4. **Zero-trust has a scope — name whom you still trust.** "Re-derivable by a third party" must name the layer
   that still needs VIGIL (oracle re-execution) and the producer (byte-authenticity for non-OOB classes).
5. **Present tense = wired-and-running today.** Anything else is future/roadmap/deferred and is tagged as such.
6. **Every claim maps to enforcing code (`file:line`) — or it is not a claim.** A property that only a comment or
   a diagram asserts is an aspiration, not a guarantee.

---

## 2. The brutal ledger (the honest state, 2026-08)

A code-grounded audit (three read-only research passes, `file:line` throughout). Five truths:

### Truth 1 — soundness, not completeness (the recall blind spot)
The tool **cannot lie about what it found; it makes no claim, and takes no measurement, about what it missed.**
Discovery rests on the Strix LLM (whose "coverage" is prompt exhortations — `vendor/strix/.../system_prompt.jinja:145,268,292`)
plus a *bounded, opt-in* recon feed (frontier cap 64 `intel/frontier.py:32`; crawl 20 pages / depth 3
`intel/expand.py:27-30`). There is **no coverage oracle** — `scanner/coverage.py` is a bandit *ranking* heuristic
that deliberately *saturates* (`coverage.py:16-18,60-67`). **M1 update (#213):** recall of the **deterministic
scanner** is now MEASURED, signed, committed, and CI-gated — **11/11** on a broadened planted loopback corpus for
the on-path oracle classes (xss, boolean/error SQLi, open-redirect, path-traversal, ssti, host-header, cors, three
exposures), with a byte-reproducible, offline-verifiable accuracy-core baseline and an explicit recall-floor gate
(`eval/recall_baseline.py`, `eval/baselines/recall-accuracy-core.json`, `eval/gate.py`); the old *"3 synthetic
targets + 8 files … a sanity check"* framing (`V2-LIMITATIONS.md:879-906`) is **superseded for the deterministic
scanner**. What stays unmeasured — and is stated as such — is recall of the **LLM-driven `engage`/planner** on
diverse real targets (*"the open piece,"* H3) and a *coverage* oracle for provable **exercise over the reached surface** (M2 — coverage can prove a surface was probed-and-adjudicated, never that a bug is absent). The same blind spot from the other
direction: a target can **poison the analyst's PLAN/coverage** (Q4) — the veracity firewall only ever *demotes*,
so a claim the poisoned analyst never made is invisible (`veracity/firewall.py:14,178-180`); the kernel fencing is
"a tripwire, not a sanitiser" and guards the *verdict*, not the *plan* (`kernel/binding.py:38-49`).

### Truth 2 — capability ≠ operating reality
- **Witnessed:** the *protocol* ships (`transparency.py`, `remediation/attestation_witness.py`); **zero independent
  witnesses are deployed** — the only callers are tests holding all keys in one process, and the code states
  independence is *"a deployment assumption the code cannot check"* (`attestation_witness.py:61-73`). At the
  trust-model-blessed `threshold==1`, equivocation is *detectable, not prevented* (`transparency.py:11-22`).
- **Continuously re-proven:** **no scheduler exists**; `append_tick` is called *only from tests*; `drift --watch`
  is a manual CLI defaulting to `--cycles 1` (`drift.py:383-384`). "As of the last time someone ran the command."
- **Time-anchored:** quorum-median only; the RFC3161/OpenTimestamps anchor is *"a designed, deferred hook"*
  (`WITNESS-TRUST.md:104-108`, `transparency.py:29`).
- Neo4j (`graph/store.py:266-297`), OTLP (`live/otel_export.py`), and SEV-SNP/TDX (`attestation/provider.py:136-179`)
  all raise `NotImplementedError` / fail-soft; every validated run omitted graph + telemetry.

### Truth 3 — demo, not field record
The field validation is one loopback target + `testasp.vulnweb.com` (via *differential/achieved-state* oracles,
**not** the `error_signature` class the loopback proof used) + `testphp.vulnweb.com` (offline at run time). No
diverse real targets; no independent FP/FN rate (the "35–90% false positive" figures are competitors', from
VIGIL's *own* survey — `FRONTIER.md`). Refs: `README.md:485-494`, `AS-BUILT.md:93`, `AS-BUILT-LIVE.md:46-64`.

### Truth 4 — bounded "zero-trust"
The standalone verifier checks signatures/binding/chain but **never re-fires the oracle** (needs VIGIL). ~~The
live-`engage` seam is LEAD-only~~ (**FIXED by T2, #207** — it now mints via a gated live re-drive). ~~Only ~15 of
32 oracle kinds fire by default~~ (**CLARIFIED + FIXED by T4, #209**: the 15 was the unknown-class *fallback set*;
each non-default kind fires on its own surface — AEGIS gateway or engage sensors — and T4 fixed the one real
re-verifiability asymmetry (k8s RBAC) + wired the 2 forgery producers). Producer byte-unforgeability (zkTLS) is
**still un-started (Phase Z)**. So "re-derive without trusting VIGIL *or* the producer" holds today only for
**OOB classes** (the Tier-2 token + independent signed collector receipt) — the remaining live bound of this
truth until Z1.

### Truth 5 — the anti-overclaim system overclaims (O1–O9)
| # | The claim | The reality | Refs |
|---|---|---|---|
| **O1** | firewall "sits at every boundary and re-executes a claim's cited proof" | *"NOT today a universal live choke point… exercised only by its tests"* | `README.md:228` vs `FEATURES.md:513-517` |
| **O2** | live `vigil engage` mints signed FACTs from re-fired oracles | the live seam is LEAD-only; live-redrive→FACT is deferred | `README.md:428,441` vs `FEATURES.md:419-421,525` |
| **O3** | "the external network-egress run is now DONE" | `AS-BUILT-LIVE.md` §3 still lists it as *deferred* (stale) | `README.md:494,750` vs `AS-BUILT-LIVE.md:122-133` |
| **O4** | "hardware-anchored" attestation | that's the TPM *counter* for the usage ledger; TEE `hardware_backed` is always `False` | `README.md:156,327` vs `DEFERRED-INFRA.md:70-74` |
| **O5** | "single-use tokens" (destruction gate) | destruction single-use is a non-atomic caller `is_consumed` check | `README.md:223,311` vs `FEATURES.md:799` |
| **O6** | "no existing tool combined more than two of these" / "35–90% FP" | grounded solely in VIGIL's own survey; presented as fact | `README.md:96,145` |
| **O7** | SIGIL "phases 0–9 complete and merged" | not independently validated in offense-side docs; implicitly Linux-only | `README.md:283` |
| **O8** | Detection Mirror "for each offensive move, a detection oracle" | only the *edge* plane mints FACTs; detection FACTs are non-crossable to a non-wildcard receiver | `README.md:205,265` vs `AS-BUILT-LIVE.md:104-112` |
| **O9** | "everything… offline-verifiable, forever" | ~~`crucible-blackboard-chain` is registered *not publicly verifiable*~~ → **RESOLVED (T3/T3b):** every engage run **that enters the OODA loop** now persists an owner-rooted, public-key-only offline-verifiable `spine-head.json`+`spine-chain.json` (universal across OODA runs, not fireteam-only). Honest scope: an attest-refused run persists nothing (UNVERIFIABLE); the chain proves integrity/order/owner-root of posted summaries, not finding re-verification or completeness; graph/telemetry remain honestly out of the signed spine | `README.md:157,716` vs `FEATURES.md:775` |

---

## 3. The innovation roadmap — every gap → the change that makes it a FACT

State tags: **OVERCLAIM** (worded beyond the code) · **CAPABILITY** (built, not operating/measured) · **SPEC** (design
only) · **UN-STARTED** · **VERIFIED FACT** (verification below passes). Each slice: build → adversarial red-pen →
CI-green → merge → update this scoreboard.

### PHASE T — truth-debt as CODE (make today's claims true)
| Slice | Turns this… | …into this fact | State |
|---|---|---|---|
| T1 | O1 | **VERIFIED FACT (#206).** Every fact-rendering boundary re-executes the proof: the report + console-findings paths already did; T1 added the dossier fact-set gate, the world-model finding-node gate (`demoted:` → UNGROUNDED when a proof doesn't re-fire), and the stored-projection attack-graph gate (`chain_findings(verify=True)` at `/api/worldmodel/`). A recorded-confirmed finding whose retained proof no longer re-fires (tampered / bug_class-flipped / absent) grants **zero** grounded fact, node, edge, or attack path — red-pen-verified across every stored-projection call site, no bypass. | ✅ VERIFIED FACT |
| T2 | O2/live-seam | **VERIFIED FACT (#207).** The live `engage` loop mints a signed FACT from a gated live RE-DRIVE (`provenance="live_redrive"`) whose `oracle_context` is the target's FRESH wire bytes — the LLM proposes the exploit, the oracle over fresh bytes decides. Fabricated LLM context, gate refusal, non-reproduction, and wrong-class all yield a LEAD (red-pen-verified, PASS). Honest limit stated: for `error_based_sqli` the single-response mint establishes the target emitted a datastore-error signature on the exploit request, not payload-causation (a same-run differential control is the disclosed hardening). | ✅ VERIFIED FACT |
| T3 | O9 | **VERIFIED FACT — with a disclosed limit (#208).** The `crucible-blackboard-chain` now has a real owner-rooted, file-backed, offline-verify path: a run that posted blackboard events persists a governance-signed `spine-head.json` + `spine-chain.json`, and `verify_blackboard_chain` verifies them **public-key-only, DB-free, framework-free**, deriving the root from an owner-signed `OFFENSE_GOVERNANCE_ROLE` delegation. Red-pen forced 13/13 forge/tamper axes to fail closed. **HONEST LIMIT (red-pen-required disclosure):** the live OODA loop does not itself post to the blackboard (only the fireteam path, after an approved escalation, does), so a *typical OODA-only run persists nothing and the segment is honestly `UNVERIFIABLE`, never a fake "verified."* So O9 holds for the blackboard chain **for runs that produced blackboard events**; making every run populate+persist it is the disclosed **T3b** follow-up (now DONE — see T3b below). | ✅ VERIFIED FACT (universal via T3b) |
| T4 | "narrow oracle surface" (C3/C4) | **VERIFIED FACT (#209).** The audit's "15 of 32 fire by default" was about the *unknown-class fallback set* — each non-default kind DOES fire on its own surface (7 on the AEGIS gateway, 8 on engage sensors); there was **no** dropped-field gap for a web-scanned surface. T4 fixed the two REAL defects: (a) the k8s RBAC oracle fired via a direct call outside the `confirm`/`_run`/`oracle_version` substrate (bespoke non-enum strings) → now a first-class `OracleKind.K8S_WORKLOAD_POSTURE` that re-verifies through the registry like every sibling; (b) the JWT + SAML **forgery** oracles had full plumbing but no producer → now wired (`JwtForgeryCheck`/`SamlForgeryCheck`) over CAPTURED bytes, zero-traffic, minting re-verifiable facts that assert *proven* forgeability (alg=none / cracked weak HMAC / signature-strippable SAML — a strong/RS256/properly-signed artifact does NOT fire). Red-pen PASS; `_ALL_ORACLES`==15 frozen; `make gate` byte-identical. | ✅ VERIFIED FACT |
| T5 | C8 "Strix hard-block" | **VERIFIED FACT (#210).** C8 was STALE: the approve-then-run queue was already wired + tested (#178) — a non-AUTO Strix shell call routes to the per-action, single-use, owner-signed approval broker and RUNS on a valid token (only fail-safe paths raise). The finding came from a **stale class docstring** (`warden_gate.py:165-175`) that still said "deferred / hard-block", contradicting the code — now corrected, plus the two stale FEATURES.md spots (368/783). The one genuine gap fixed: the async `on_tool_start` called the blocking poll-and-wait approver directly → now offloaded off the event loop (`run_in_executor`) so a live interactive approval window doesn't stall the async runner. Co-located positive/negative/fail-closed tests added. | ✅ VERIFIED FACT |
| T6 | O5 | **VERIFIED FACT (#211).** The generic destruction gate's single-use was a non-atomic caller `is_consumed` CHECK (a TOCTOU: two concurrent authorizations could both pass before either marked consumed). Added `consume_authorization` — the atomic sibling of the M2 `consume_token`: it runs the full `authorize_destruction` check THEN atomically burns the authorization's nonce via the O_EXCL `NonceLedger.try_consume`. Of N concurrent consumers of one authorization **exactly one wins** (16-thread test); a lost race / ledger error / malformed ledger / blank nonce → fail-closed DENY; an INVALID authorization returns BEFORE the burn (no grief-burn of a victim nonce). Wired into `conjunctive_gate` (via `destruction_ledger`) + `require_destruction_authorization`; the already-atomic `vigil patch --open-pr` leg is byte-identical, and the pure `authorize_destruction` remains for callers that own their own burn. | ✅ VERIFIED FACT |
| T3b | O9 (universal) | **VERIFIED FACT.** O9 is now universal across OODA runs: every live `engage` run **that enters the OODA loop** populates + persists the offline-verifiable blackboard chain, not only a fireteam wave. The live OODA loop (`live/engine.py`) gained a framework-free `spine_post` seam driven at each hook point (decision · hypothesis · observation · tool_call · tool_result · finding · refusal); `live/wiring.py:_build_spine_poster` (FATAL-2 — framework imports function-local) builds an `agents.spine_sink.SpineSink` on the SAME default `open_blackboard()` DB + `config.slug` that `_persist_blackboard_chain` reads, so a plain OODA-only run (no fireteam) now writes `spine-head.json` + `spine-chain.json` and `verify_blackboard_chain` returns VERIFIED + owner-rooted (tamper → FAILED). Determinism preserved (nothing wallclock/rng enters the signed chain — `event_digest` excludes `posted_at`); the None-seam path stays byte-identical (no framework ⇒ NO-OP). **Honest scope (red-pen-required):** (a) a run refused at the attest-first gate *before* the loop posts nothing → honestly `UNVERIFIABLE` (never a fake verified); (b) the chain proves integrity/order/owner-root of the POSTED engine-authored **summaries** — NOT a finding's oracle re-verification (that is the separate proof re-execution, T1/T2) nor a complete record of everything the run did; (c) it is the engagement's cumulative append-only history (grows on re-engage of a slug; per-run byte-reproducibility is for a fresh slug). | ✅ VERIFIED FACT (scoped to OODA-entering runs) |
| T7 | O3/O4/O6/O8 | **RECONCILED (#212).** O3 — the stale `AS-BUILT-LIVE.md` bullet that called the external run "outstanding" is corrected to the truth (the testasp external engagement is DONE: 2 FACTs re-verified 2/2 offline + tamper rejected, via the differential/achieved-state oracles since testphp was offline; the real Kali/garak/PyRIT toolchain (R4) is the part still outstanding). O8 — the Detection Mirror "for each offensive move" is scoped to the **edge plane** (recon/injection/credential — logs that exist); C2/identity/cloud/session-phishing are honest LEADs by design. O4 — a clarifying note distinguishes the TPM usage-ledger **counter** (hardware-anchored when present) from **TEE attestation** (software-only on commodity hardware; Phase H). O6 — the competitor figures were ALREADY attributed to "our own survey" (no change needed). | ✅ RECONCILED |

### PHASE M — measure, then PROVE, completeness
| Slice | Gap | Fact | State |
|---|---|---|---|
| M1 | recall unmeasured | a signed, reproducible measured recall/FN number on a planted-bug corpus | ✅ **VERIFIED FACT (#213)** — deterministic-scanner recall **11/11** (precision 1.0, fp 0) on an 11-bug loopback corpus (on-path classes incl. new ssti + host-header); committed **byte-reproducible + offline-verifiable** signed accuracy-core (out-of-band-**pinned** trust root; a fresh-key re-sign of a tampered baseline is rejected) + an explicit **recall-floor** gate. Red-pen caught HIGH (unpinned trust root) + MEDIUM (CORS-on-safe-controls dishonesty) + LOW — all fixed & re-checked CLEAN. **Scope:** the *deterministic scanner* on a *planted* corpus — LLM-engage recall on real targets stays H3. |
| M2 | no coverage oracle | a signed coverage certificate that a surface/param/sink was *exercised* — provable **exercise over the reached surface** (never absence) | ✅ **VERIFIED FACT (#214)** — the scanner now RETAINS negative-probe evidence at the `engine.audit` seam (`OracleSignal.conclusive` — a non-fire counts only when an applicable oracle actually had a channel to observe) → `ScanReport.exercised_probes` → `verify/coverage_oracle.py` emits a deterministic, **signed, offline-verifiable** cert grading each (surface,param,class) `finding` / `clean` / **`inconclusive`**, so *provably-tested-clean* is finally distinguishable from *merely-untested* (`tested_clear` wired live into `standards.coverage_matrix`). Red-pen caught HIGH (a one-sided oracle's channel-blind non-fire mis-stamped `clean`) — fixed at root + independently re-checked CLEAN (inert-input classes now grade `inconclusive`; benchmark bucket 0→53). **Scope (in the signed bytes):** coverage of the REACHED surface only, bounded by max_pages/max_depth/frontier.truncated/budget — NOT proof of absence, NOT surface completeness (undiscovered surface = discovery/recall, H3). **Residual:** the class→control `tested_clear` roll-up in `standards.py` is coarser than the per-probe `oracle_kinds_run` evidence (a future granularity slice). |
| M3 | plan un-defended (Q4) | a signed plan-integrity attestation + a steer-content detector → a skipped surface is visible | ✅ **VERIFIED FACT (#216)** — the plan is now a first-class, **signed, offline-verifiable** artifact (`verify/plan_integrity.py`): the committed (surface,class) set · **discovered − exercised** surfaces each tagged an honest reason (budget/config/unprobed) · a steer-signal list. The **planner channel is FENCED** (`kernel/hypothesize.py`: target-derived surface/observation now ride the same untrusted fence as the critique path — a crafted surface can no longer carry planner instructions), closing the audit's *"the fence guards the verdict, never the plan."* A **steer-content detector** (`scanner/steer_detect.py`) LISTS scope-claiming content (`X-Robots-Tag`, `<meta robots>`, "do not test"/"out of scope") — it never blocks or obeys. Red-pen (3 lenses) verified the fence is real (not a no-op), scope-honest, and list-only; caught a MEDIUM (method-blind skip diff hid an unprobed POST behind a probed GET) + a LOW dedup-docstring overclaim, both fixed. **Scope (in the signed bytes):** proves OBSERVABLE facts only — it NEVER concludes "poisoned," a discovered-unprobed surface may be a legitimate skip, and undiscovered surface is recall/H3. |

### PHASE A — operationalize assurance (capability → operating property)
| Slice | Gap | Fact | State |
|---|---|---|---|
| A1 | median-clock time | a checkpoint carries a verifiable RFC3161/OTS external timestamp | UN-STARTED |
| A2 | no re-proof loop | a running re-proof service re-proves the corpus on a cadence + appends witnessed ticks | CAPABILITY |
| A3 | no witnesses deployed | N independent witness processes co-sign a real series; a third party can run one | CAPABILITY (+ irreducible independence → §4) |

### PHASE Z — the zero-trust endgame
| Slice | Gap | Fact | State |
|---|---|---|---|
| Z1 | producer byte-forgery | a fact whose response bytes are producer-unforgeable (zkTLS/TLSNotary), checkable standalone | UN-STARTED |

### PHASE F — formal assurance
| Slice | Gap | Fact | State |
|---|---|---|---|
| F1 | invariants tested, not proven | a machine-checked TLA+/Alloy model of the 4 core invariants + a CI model-check | UN-STARTED |

### PHASE R — finish the disclosed residuals
| Slice | Gap | Fact | State |
|---|---|---|---|
| R1 | differential remediation spec-only | the #203 spec implemented; a blocking WAF → INCONCLUSIVE, not a false REMEDIATED | SPEC |
| R2 | sanitizing-WAF residual | direct-to-origin re-drive distinguishes a sanitizer from a fix | UN-STARTED |
| R3 | binary patch-synthesis stubbed | a synthesized memory-safety patch verified by oracle silence | CAPABILITY (confirm/silence only) |
| R4 | external topology unexercised | a real external-tool run mints a gated oracle-confirmed FACT through the sandboxed topology | CAPABILITY |

---

## 4. The honest irreducible frontier (software cannot make these perfect)

For each: we ship the **deployable mechanism**; the **residual** stays true until a hardware/social/deployment fact
outside the code is satisfied. Claiming these "done" in software would be the overclaim this whole program kills.

| Item | Mechanism we ship | The irreducible residual |
|---|---|---|
| **H1 — hardware confidentiality** | TEE providers that activate when SEV-SNP/TDX is present | on commodity PCs it stays software-attested (integrity + origin only); confidentiality **needs silicon** |
| **H2 — external graph/telemetry** | the Neo4j/OTLP client bodies + a validated run against a live service | "deployed" **needs a running external service** the operator stands up |
| **H3 — field record** | the M1 harness + a runbook for diverse authorized targets | a genuine field record **accrues over real authorized engagements**; not manufacturable in a lab |
| **H4 — third-party audit** | a reproducible external-audit package (bundle + verifier + scope) | the audit itself **needs an external team**; we prepare, we cannot *be* the third party |
| **A3 residual — witness independence** | a deployable witness service any third party can run | *genuine* independence **needs third-party operators**; distinct keys ≠ distinct operators |

---

## 5. The honesty test (run this against every claim before it ships)

1. Is the verb present-tense? Then is it **wired-and-running today** (not test-only, not a manual CLI)?
2. Does it map to enforcing **`file:line`**?
3. Is it a **soundness** claim being worded as **completeness**?
4. Is it a **capability** being worded as an **operating property** (running loop / deployed peers / real anchor)?
5. If "re-derivable / zero-trust": have I **named whom you still trust**?
6. Is it **DEPLOYED** and **MEASURED**, or only **BUILT**? Tag it accordingly.
7. If it depends on hardware/third-parties/real-world runs: have I **stated the irreducible residual**?

A claim that cannot pass all seven is downgraded to its true state or removed — every time.

---

*Status: program opened 2026-08. This scoreboard is updated as each slice's verification passes; nothing here is
called a fact before then.*
