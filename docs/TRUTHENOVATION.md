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
that deliberately *saturates* (`coverage.py:16-18,60-67`). Recall is measured only on 3 synthetic targets + 8
files — the code's own words, *"a sanity check, not a capability claim"* (`V2-LIMITATIONS.md:879-906`); the
front-end that would measure recall on a real surface is *"the open piece."* The same blind spot from the other
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
The standalone verifier checks signatures/binding/chain but **never re-fires the oracle** (needs VIGIL). Only ~15
of 32 oracle kinds fire by default (`verifier.py:445-461`, `FEATURES.md:437,471`). The live-`engage` seam is
LEAD-only (`provenance="llm"` → demoted even when the oracle fires; `wiring.py:687-723`, `oracle_adapter.py:139-147`).
Producer byte-unforgeability (zkTLS) is un-started. So "re-derive without trusting VIGIL *or* the producer" holds
today only for **OOB classes** (the Tier-2 token + independent signed collector receipt).

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
| **O9** | "everything… offline-verifiable, forever" | `crucible-blackboard-chain` is registered *not publicly verifiable*; graph/telemetry omitted every run | `README.md:157,716` vs `FEATURES.md:775` |

---

## 3. The innovation roadmap — every gap → the change that makes it a FACT

State tags: **OVERCLAIM** (worded beyond the code) · **CAPABILITY** (built, not operating/measured) · **SPEC** (design
only) · **UN-STARTED** · **VERIFIED FACT** (verification below passes). Each slice: build → adversarial red-pen →
CI-green → merge → update this scoreboard.

### PHASE T — truth-debt as CODE (make today's claims true)
| Slice | Turns this… | …into this fact | State |
|---|---|---|---|
| T1 | O1 | **VERIFIED FACT (#206).** Every fact-rendering boundary re-executes the proof: the report + console-findings paths already did; T1 added the dossier fact-set gate, the world-model finding-node gate (`demoted:` → UNGROUNDED when a proof doesn't re-fire), and the stored-projection attack-graph gate (`chain_findings(verify=True)` at `/api/worldmodel/`). A recorded-confirmed finding whose retained proof no longer re-fires (tampered / bug_class-flipped / absent) grants **zero** grounded fact, node, edge, or attack path — red-pen-verified across every stored-projection call site, no bypass. | ✅ VERIFIED FACT |
| T2 | O2/live-seam | live `engage` mints a re-fired FACT over live bytes (live-redrive→FACT), offline-re-verified | OVERCLAIM |
| T3 | O9 | the blackboard chain is owner-rooted + publicly verifiable by a no-VIGIL reader | OVERCLAIM |
| T4 | narrow oracle surface | every applicable oracle kind is reachable in scan/engage/benchmark; k8s_rbac wired | CAPABILITY |
| T5 | Strix hard-block | a non-AUTO shell call queues for approval and runs on approval | CAPABILITY |
| T6 | O5 | destruction single-use is an atomic check-and-consume (O_EXCL ledger) | OVERCLAIM |
| T7 | O3/O4/O6/O8 | the doc-only residue reconciled to the truth after the code lands | OVERCLAIM |

### PHASE M — measure, then PROVE, completeness
| Slice | Gap | Fact | State |
|---|---|---|---|
| M1 | recall unmeasured | a signed, reproducible measured recall/FN number on a real planted-bug corpus | UN-STARTED (harness) |
| M2 | no coverage oracle | a coverage certificate that a surface/param/sink was *exercised* — provable absence | UN-STARTED |
| M3 | plan un-defended (Q4) | a signed plan-coverage attestation + a poison detector → a skipped surface is visible | UN-STARTED |

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
