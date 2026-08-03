<div align="center">

# VIGIL — The Provable Adversary

### Provable Offensive Security

**Proof, not findings.**

*An autonomous adversary that doesn't ask you to trust it.*

</div>

---

## The 25%

Call VIGIL an "autonomous pentesting tool" and you've described maybe a quarter of it.

Yes — it is an AI that, given a target you're authorized to test, hunts real vulnerabilities on its own: it crawls, reasons about attack surface, forms hypotheses, fires payloads, and chains bugs into attack paths. That part is real, and it works.

But an AI that hands you a list of findings you then have to *believe* is the easy part. Every "AI hacker" being shipped right now does that. And every one of them has the same fatal flaw: **you cannot tell its truth from its confident hallucination without redoing the work by hand.** The more autonomous they get, the worse the problem gets — you're trusting a black box that is *designed* to sound sure of itself.

VIGIL is built on the opposite bet.

## The 75%

The other three-quarters of VIGIL exists to make one thing true: **you never have to trust it.** Four properties, and every one is enforced by non-AI code you can read:

### 1. It's *provable* — a finding is evidence, not a claim

A claim becomes a **fact** in VIGIL only when a **deterministic oracle** — a plain, non-AI program — re-fires over data the *real target* produced. The AI is only ever allowed to *propose where to look and what a result might mean*. It can never promote its own output to a fact. Not its confidence, not a critic's endorsement, not a plausible story.

- The anti-hallucination layer (`engine/crucible/framework/v2/veracity/firewall.py`) **only ever DEMOTES or abstains** — it can turn a fabricated "confirmed" into an ungrounded lead, and it can never do the reverse.
- Every fact carries a retained `oracle_context` and **re-executes offline**: `python3 -m framework.v2 verify <report.json>` re-runs each proof — *"pure, offline, deterministic"* (`framework/v2/__main__.py`). A third party can replay it on their own machine, with **no VIGIL, no vendor, and no trust in us** required.

The difference is concrete. A normal scanner tells you *"there's SQL injection here."* VIGIL hands you a **signed proof** that re-fires the oracle over the target's own bytes — a receipt anyone can re-run. Findings stop being claims and become **evidence**.

### 2. It's *self-governing* — autonomy behind fail-closed cryptographic gates

Autonomy is only safe if it can't act without authorization. Nothing target-touching or destructive happens in VIGIL unless it passes a **conjunctive gate** — every condition must hold, and the default is *closed*:

- a signed engagement **charter** + a who/when/what usage **attestation** minted *before* anything runs;
- the **WARDEN** classifier-of-record deciding whether an action may run autonomously or must queue for approval (`integration/vigil_integration/warden_gate.py`);
- and, for destructive / high-blast-radius actions, an **m-of-n threshold** signed by a quorum of *distinct, independent* authorizers, bound to the specific action, single-use, with a dead-man's-switch (`integration/vigil_integration/destruction_gate.py`, `conjunctive_gate.py`).

The AI cannot widen its own scope, cannot self-authorize a destructive action, and cannot escape the gate. The web UI can never mint a charter or lift a scope floor.

### 3. It's *self-measuring* — it signs how good it is, and admits what it missed

Most tools tell you what they *found*. Almost none will tell you, honestly and provably, what they **might have missed** — because that number is embarrassing. VIGIL measures its own completeness and **signs the result**:

- a **measured recall** number over a planted corpus — reproducible, and committed as a signed, offline-verifiable baseline (`framework/v2/eval/recall_baseline.py`);
- a **coverage certificate** that distinguishes *provably-tested-clean* (an oracle actually ran and cleared it) from *merely-untested* (`framework/v2/verify/coverage_oracle.py`) — so a silent surface can no longer masquerade as a clean one;
- and — landing now — a **plan-integrity attestation** that makes a skipped surface *visible* and flags target content that tries to steer the analyst's plan (tracked in [`docs/TRUTHENOVATION.md`](TRUTHENOVATION.md) → M3).

A tool that will hand you a signed statement of its own blind spots is telling you it has nothing to hide.

### 4. It's *sovereign* and *tamper-evident* — on your metal, with your keys

VIGIL fuses **offense** (the CRUCIBLE engine) and **defense** (the AEGIS layer) over one control plane, running on hardware you own. Every meaningful action is written to a **hash-chained, Ed25519-signed event spine** that cannot be secretly edited or reordered (`framework/v2/agents/spine_chain.py`) — append-only, witnessed, and time-anchored. You hold the signing keys. The record is yours, and it's provable.

---

## The one rule

Everything above collapses into a single sentence that runs through the entire system:

> **Nothing the AI says is treated as true, and no action the AI wants to take is allowed to happen, unless a separate, deterministic (non-AI) checker *proves* it — and every proof and every action is cryptographically *signed* and written to a record that can *never* be secretly edited.**

The AI *proposes*. An **oracle** *proves*. A **gate** *authorizes*. Everything is *signed and logged*. **You keep the keys.**

---

## The honest boundary — why this is credible

A manifesto that only sold you the dream would betray the exact discipline that makes VIGIL worth using. So here is what it does **not** claim — stated as plainly as the rest:

- **Soundness is not completeness.** VIGIL's guarantees are all of the form *"no false positive"* — a fired oracle means a real bug. That says nothing on its own about *"no false negative."* It **measures** its recall and coverage (above) rather than *assuming* them, and it marks the gap honestly.
- **A capability is not an operating property.** Where a property depends on deployment (independent witnesses, continuous re-proving, external time anchors), VIGIL ships the mechanism and **names what still has to be stood up** — it does not pretend a capability that exists in code is a fact about your running system.
- **Some things are irreducibly external, and we refuse to call them done in software.** Hardware-grade confidentiality needs a TEE (SEV-SNP/TDX silicon). *Genuine* witness independence needs third-party operators. A real-world field record accrues over authorized engagements; it can't be manufactured in a lab. A third-party audit needs a third party. For each, VIGIL builds the deployable mechanism and **states the residual truthfully.**

This is tracked as a living scoreboard in [`docs/TRUTHENOVATION.md`](TRUTHENOVATION.md), where every claim carries a **BUILT / DEPLOYED / MEASURED** state tag and maps to enforcing code, or it isn't a claim. The whole point of a system built to refuse the AI's word is that it must refuse its *own* marketing too.

---

## Why "the future is here"

The industry is racing in one direction: **more autonomy.** More agents, more automation, more of the loop handed to a model that is very good at sounding certain. That race has an unpriced cost — the more the machine decides, the less you can check.

VIGIL is a bet on the direction the industry will *have* to turn toward next: **not more autonomy you have to trust, but autonomy that proves itself.** Verifiable findings. Fail-closed governance. Signed self-measurement. An immutable record. The moment security work has to stand up in front of an auditor, a regulator, a customer, or a court, *"the AI said so"* stops being an answer — and *"here is the proof, re-run it yourself"* is the only thing that does.

That's the category shift. VIGIL is the reference implementation of it, and it exists today.

---

## Who it's for

- **Red teams & pentesters** who are tired of triaging a scanner's confident noise — every VIGIL finding arrives with a re-runnable proof, so triage becomes *replay*, not *re-investigate*.
- **Bug-bounty hunters** who need a report a triager can't wave away — hand over a signed, offline-verifiable proof bundle instead of a screenshot.
- **Security researchers** who want a substrate where a claim is only as good as its re-execution, and where the tool's own blind spots are measured, not hidden.
- **Defenders & auditors** who need evidence that survives scrutiny — an immutable, signed record of exactly what was tested, what was proven, and what was skipped.

---

<div align="center">

**Don't trust the finding. Replay the proof.**

*VIGIL — The Provable Adversary.*

[← Back to the README](../README.md) · [The truth scoreboard →](TRUTHENOVATION.md) · [What's built vs. deployed →](AS-BUILT-LIVE.md)

</div>
