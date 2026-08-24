# Deliberate refusals — what VIGIL will not build, and why

A reviewer evaluating an offensive-security engine usually has to *discover* its limits.
VIGIL states them up front, because in this product they are **design strengths, not gaps**.
Each refusal below is a capability VIGIL could have built, deliberately did not, and *keeps out*
of the code with a test that fails the build if it ever reappears.

The governing rule is [CLAIM-DISCIPLINE](CLAIM-DISCIPLINE.md): a claim is only made when it is
**true of the code**. So every refusal here is paired with the code that makes it true and the
test that proves it stays true — not a promise, an invariant.

> **Three of these are machine-checked claims in the registry.** The capability-absence guarantee is
> registered as `W16-STD-8b`, the rejected-x5c-oracle guarantee as `W16-STD-8`, and the
> client-side posture-weakness (clickjacking/CSRF/postMessage) guarantee as `W16-STD-5`
> ([`docs/claims/registry.json`](claims/registry.json)); the registry guard fails CI if either the
> enforcing code or its proving test is removed.

---

## Why refuse at all?

VIGIL is sold to an operator who runs it **against systems they own and have authorized**. In that
setting the value is *completeness and provable discipline*, not raw offensive reach. A capability
that (a) helps an attacker evade the customer's own defenses, (b) establishes attacker infrastructure
inside the customer's estate, or (c) cannot be turned into a **near-zero-false-positive proof** is a
capability that makes the product *worse* for its actual buyer. Refusing it is the senior-operator
move, and it is auditable here.

---

## The eight refusals

### 1. No detection-evasion / anti-defender / stealth

**What is refused.** No stealth mode, no proxy/VPN/IP-rotation, no WAF-tamper or payload-obfuscation
knobs, no "defeat the customer's EDR" tooling. VIGIL's traffic is *correlatable on purpose*: a stable
identity so the operator can grep their own logs and find exactly VIGIL's requests.

**Why it is a strength.** A tool that evades the customer's own detection is not a tool a customer
should buy — it degrades the very telemetry an authorized owner-test exists to validate. Evasion also
trades away correlatability, which is the property that lets an operator attribute every byte to the
engagement.

**Where it lives in the code.**
- The clean-room decision brain forbids evasion knobs by construction: `_assert_drift_free`
  (`integration/vigil_integration/brains/hexstrike_brain.py`) searches every proposed tool + params
  with the `_EVASION_TOKENS` regex — `stealth | tamper | --proxy | vpn | rotate | evade | obfuscat |
  space2comment | …` — and raises a fail-closed `DriftError` if any slipped in.
- The live tool executor presents one stable, recognizable identity and does **no** rotation
  (`integration/vigil_integration/live/live_transport.py`: "No rotation, no evasion.";
  `imds_runner.py`: "correlatable, NO evasion").
- The proof-content gate **DENYs** persisting a detection-evasion PoC at all
  (`integration/vigil_integration/proof/content_gate.py`, category `detection_evasion`).
- AEGIS is "not anti-defender" (`engine/crucible/framework/v2/aegis/AEGIS-DESIGN.md`).

### 2. No C2 / persistence / implants

**What is refused.** No command-and-control channel, no beacon/implant, no persistence mechanism
(cron/systemd/registry-Run/authorized-keys backdoors), no post-foothold "stay resident" tooling.

**Why it is a strength.** Establishing durable attacker infrastructure inside an authorized target is
the step most likely to cause a real incident, survive the engagement, and be indistinguishable from a
genuine compromise. An owner-test proves *exploitability*; it must not leave a foothold behind.

**Where it lives in the code.**
- The doctrine-maximum offensive slice hard-excludes it in writing and in behavior:
  `engine/crucible/framework/v2/agents/tier3_validation.py` — "establishes no persistence" and
  "C2 / persistence / implants" under *WHAT IS DELIBERATELY NOT BUILT HERE (hard-excluded … refuse,
  never build)*.
- The proof-content gate **DENYs** persistence and self-propagating payloads
  (`content_gate.py`, categories `persistence`, `self_propagating`).
- The tool-governance boundary treats C2-framework tool *names* only as things to **floor at A3 +
  m-of-n and gate** — never as things VIGIL ships or runs
  (`integration/vigil_integration/tools/governance.py`, `_DESTRUCTIVE_TOOLS`).
- Detection planes that would need C2 telemetry are **LEAD-only by design**, never FACTs
  (`integration/vigil_integration/detection/telemetry.py`, domain `c2`).

### 3. No lateral movement

**What is refused.** No execution of movement between hosts — no psexec/wmiexec/smbexec, no session
pivoting, no credential relay, no "own the next box" tooling.

**Why it is a strength.** Same reasoning as C2/persistence: unattended lateral execution against a
live estate is where an owner-test turns into an outage or a real breach. VIGIL proves *reachability*
without *traversing* it.

**Honest precision (this is the subtle one).** VIGIL **reasons about** internal lateral-movement
*routes* — `engine/crucible/framework/v2/scanner/lateral.py` runs a deterministic path search over the
world model and surfaces attacker→crown-jewel paths. That module does **no network I/O, spawns no
process, and "mints NO facts"** — it is attack-path *analysis*, the defensive-planning dual of
execution, not lateral movement itself. Naming that analysis "lateral movement" in a UI/CLI label
would be imprecise; the CLI reference calls it *lateral-path analysis* for exactly this reason.

**Where it lives in the code.**
- `tier3_validation.py` — "performs no lateral movement" (hard-excluded).
- `scanner/lateral.py` — pure, deterministic path *reasoning*; the module docstring states it "mints
  NO facts and invents NO trust."
- Lateral/relay/credential-theft tool *names* are, again, only classified for gating in
  `tools/governance.py` (`_DESTRUCTIVE_TOOLS`) — VIGIL neither vendors nor executes them, and imports
  no offense-execution library (impacket / pypsexec / winrm / paramiko / …).

### 4. AEGIS is defensive-only

**What is refused.** AEGIS (the embeddable dual of the offensive engine) never attacks anyone. It
protects the operator's **own** app, defaults to `observe` (read-only), and a hard block rides **only**
on a fired oracle — a lead never blocks and belief never blocks.

**Why it is a strength.** A defensive product that can be turned around into an attack tool is a
liability. Keeping AEGIS provably offense-free is what lets it be embedded in a production request path.

**Where it lives in the code.**
- `engine/crucible/framework/v2/aegis/gateway.py` — "DEFENSIVE ONLY. Protects the operator's OWN app;
  never attacks anyone; not anti-defender."
- `engine/crucible/framework/v2/aegis/__init__.py` and `middleware.py` — default `observe` mode never
  blocks or challenges; `response_policy.py` — "a LEAD never blocks and belief NEVER blocks."
- The passive OOB belief-elevation path is a *translator, not a generator* — it never injects a
  request (proven byte-identical in review).

### 5. The scan stays serial

**What is refused.** VIGIL's vulnerability scan sends its probes **serially** (one request at a time)
by default — it does not mass-parallelize requests at a target for speed.

**Why it is a strength.** Serial, predictable, throttled traffic respects the customer's production,
preserves fail-fast (a mis-configured target aborts before a sibling request egresses), and keeps the
engagement correlatable. Speed at the cost of a 5xx storm on a customer's box is the wrong trade for an
owner-test.

**Honest precision.** Two *bounded, documented* exceptions exist and are not general parallel scanning:
- **Opt-in parallel recon** (Speed X5) fans out *recon collectors across different hosts*, is
  **default-serial** (`CRUCIBLE_RECON_MAX_WORKERS=1`) and **byte-identical to serial** when enabled
  (`engine/crucible/framework/v2/intel/ingest.py:39-48`).
- **The single-packet race engine** (`scanner/race.py`) deliberately fires N concurrent requests at
  *one action* — because firing them concurrently is the definition of the race-condition test it
  performs; it is a check, not a scan strategy.

**Where it lives in the code.** `integration/vigil_integration/live/executor.py` — "the engine loop is
serial"; `intel/ingest.py` — "Default-serial keeps the doctrine of predictable, no-surprise traffic."

### 6. hexstrike-ai is vendored NON-RUNNABLE

**What is refused.** The upstream hexstrike-ai offensive execution framework (a Flask API with ~156
tool-execution routes, `shell=True` subprocess calls, a base64 `exec()` payload builder, a MITM proxy,
live NVD/GitHub calls) is **not runnable** in this repo. Running it would bypass VIGIL's conjunctive
gate, egress gate, and charter scope entirely.

**Why it is a strength.** VIGIL reuses hexstrike-ai's *decision model* (design credit, attributed) as a
clean-room, propose-only brain — and keeps the ungated upstream server out of every execution path.

**Where it lives in the code.**
- The upstream runnable modules exist **only** as `.reference` blobs
  (`vendor/hexstrike-ai/hexstrike_server.py.reference`, `hexstrike_mcp.py.reference`) — Python cannot
  import them; `vendor/` is never on `PYTHONPATH`; see `vendor/hexstrike-ai/UPSTREAM.md`.
- The clean-room reuse is `integration/vigil_integration/brains/hexstrike_brain.py` — propose-only,
  with all evasion/stealth, credential-poisoning, and live-exploit/persistence stages removed.
- Enforced by `integration/tests/test_vendor_hexstrike_quarantine.py`: no VIGIL source imports
  hexstrike, no runnable copy exists anywhere in the repo, and attribution is present.

### 7. A JWT x5c (embedded-key) forgery oracle was built and REJECTED in review as unsound

**What is refused.** An oracle that flags a JWT as *structurally forgeable* because its own embedded
verification key (a `jwk` or `x5c` header) verifies the token. It was built, adversarially reviewed,
and **not merged**.

**The unsoundness argument (recorded verbatim in the code).** An embedded self-verifying key is **not
offline-provable as a forgery**: a legitimate CA-chained `x5c` is the **RFC 7515 §4.1.6 norm** (the
leaf *is* the cert whose key signed the JWS; the relying party validates the chain to a trusted CA —
unknowable from the token alone), and legitimate flows embed a self-verifying `jwk` **by design** (DPoP
proofs, SIOP id_tokens). The review minted a CA-issued-leaf token (issuer≠subject) and it fired
identically to a self-signed forgery at confidence 0.99 — i.e. it would false-positive on real
Azure/enterprise/DPoP tokens. Since an oracle only ever emits FACTs, a branch that cannot be
near-zero-FP offline is **dropped**, not demoted; it can be at most a belief-raising RISK INDICATOR
(a future AEGIS lead), never a confirmed FACT.

**Why it is a strength.** Killing a plausible-looking oracle *before merge* because it cannot be made
sound is the anti-hallucination discipline working as designed. It is recorded so the branch is not
re-added by a well-meaning future contributor.

**Where it lives in the code.**
- The rejection breadcrumb is a permanent comment in the surviving oracle:
  `engine/crucible/framework/v2/verify/oracles.py` (`jwt_forgery_oracle`, the *DELIBERATELY NOT a fire
  path* block).
- The lesson is recorded in `engine/crucible/V2-LIMITATIONS.md` and mirrored in the SAML crypto
  reviewer's note (`verify/adapter.py`, `verify/tests/test_saml_forgery_crypto.py`).
- A regression test keeps it rejected (see below).

### 8. No achieved-state clickjacking oracle — the client-side weaknesses are proven as POSTURE, not exploit

**What is refused.** An *achieved-state* clickjacking oracle — one that would emit a FACT because a page
"was framed" or a UI-redress was staged. It was in fact **built** once (a framable + password-field
predicate) and, under adversarial review, found to **false-positive on 8 variants** — a password marker
inside an HTML comment / `<script>` string / `<textarea>`, a `text/plain` page, a disabled/hidden field,
or a page framing-protected via meta-CSP or a multi-header XFO the regex missed — so it was **reverted /
demoted to a lead** (recorded in `docs/knowledge/memory/prover-to-discoverer-program.md`). It is refused
because a single-response achieved-state signal cannot be made near-zero-false-positive: legitimate apps
are framed all the time (intentional embeds, partner iframes, a page whose own design permits framing),
so "the page was framed" is not proof of an exploit. The same reasoning governs CSRF and postMessage — a
live "the forged request went through" / "the message was delivered" signal cannot distinguish a real
cross-origin exploit from a SameSite-protected endpoint or an intentional same-app broadcast.

**What is BUILT instead (the sound dual, W16-STD-5).** VIGIL proves the *posture weakness* — the MISSING
or WEAK DEFENSE — from a RETAINED artifact ALONE, which IS near-zero-FP and offline-re-verifiable. These
are the always-applicable constitution *client-side* classes (constitution §V: XSS, CSRF, clickjacking,
postMessage); XSS already had an oracle, and these complete the row:
- **clickjacking** — `clickjacking_posture_oracle` (kind `CLICKJACKING_POSTURE`) fires only when a
  retained response ships NEITHER a framing X-Frame-Options (DENY/SAMEORIGIN) NOR a CSP `frame-ancestors`
  directive — a pure header check, exactly what a browser enforces.
- **CSRF** — `csrf_posture_oracle` (kind `CSRF_POSTURE`) fires only on a control-differential: a
  state-changing request accepted with a valid anti-CSRF token AND accepted with the token removed/forged
  (the synchronizer token is not enforced). It proves the token is not enforced, NEVER that a cross-site
  attack succeeded.
- **postMessage** — `postmessage_posture_oracle` (kind `POSTMESSAGE_POSTURE`) fires only on a wildcard `*`
  targetOrigin send, or a message handler that consumes `event.data` with no origin check — a sound static
  check over the retained source.

Each proves a POSTURE WEAKNESS (a missing/weak defense), never a proven achieved-state exploit — the
honest, near-zero-FP claim an oracle FACT requires.

**Why it is a strength.** The SAME anti-hallucination discipline as refusal 7: a plausible-looking
achieved-state oracle that cannot be made near-zero-FP is not shipped as a FACT-emitter; its sound
posture-weakness dual is. Recorded so a future contributor does not re-add the FP-prone achieved-state
form.

**Where it lives in the code.**
- The three oracles live in `engine/crucible/framework/v2/verify/oracles.py`; their kinds in
  `verify/models.py`; the confirmation seam (ingest + adjudicate an imported finding) in
  `verify/client_side_posture.py`.
- The "DELIBERATELY NOT an achieved-state oracle" breadcrumb is a permanent comment on the
  `CLICKJACKING_POSTURE` member in `verify/models.py` and in `verify/oracles.py`.
- Negative-control regression tests keep the posture oracles SOUND and present:
  `verify/tests/test_client_side_posture.py` (a page/handler/endpoint that HAS the defense is not
  confirmed; one that LACKS it is).

---

## The guarantees, as machine-checked claims

<!-- CLAIM:W16-STD-8b -->
VIGIL ships no detection-evasion, C2/persistence, lateral-movement, or credential-theft execution capability in its own first-party code, and a capability-absence test fails the build if such a capability is added.
The guard is `scan_tree_for_offense_capability`
(`integration/tests/test_deliberate_refusals.py`): an AST scan of the first-party source trees that
flags (a) any import of an offense-execution library and (b) any process-spawn/exec call whose literal
arguments name a C2 / lateral-movement / credential-theft tool or an evasion knob. It runs in the
required **integration two-env boundary (P5)** CI job, asserts the real tree is clean, and — as its
negative control — plants a fixture module that *does* carry such a capability and asserts the same
scanner flags it. Adding a real capability that contradicts a refusal turns the test red.

<!-- CLAIM:W16-STD-8 -->
The JWT embedded-key (jwk/x5c) forgery oracle was built and rejected in review as unsound; jwt_forgery_oracle deliberately does not fire on a token whose own embedded key verifies it, and a regression test keeps that refusal true.
The regression guard is in
`engine/crucible/framework/v2/verify/tests/test_jwt_forgery.py` (the `…embedded_jwk…` /
`…embedded_x5c…` non-fire tests), with the live control that a genuinely forgeable `alg=none` token
*does* fire — proving the oracle is not a dead no-op. It runs in the required
**CRUCIBLE core on vigil_core** CI job.

<!-- CLAIM:W16-STD-5 -->
The three client-side posture-weakness oracles (clickjacking, CSRF, postMessage) each prove a MISSING or WEAK client-side defense from a retained artifact alone — never an achieved-state exploit — so the FP-prone achieved-state clickjacking oracle stays refused, and per-class negative-control tests keep each posture oracle sound (a page/handler/endpoint that HAS the defense is not confirmed; one that LACKS it is).
The oracles are `clickjacking_posture_oracle` / `csrf_posture_oracle` / `postmessage_posture_oracle`
(`engine/crucible/framework/v2/verify/oracles.py`), routed via their `CLICKJACKING_POSTURE` /
`CSRF_POSTURE` / `POSTMESSAGE_POSTURE` rows and reachable only through a retained `*_control` context no
benchmark finding carries (so the gate stays byte-identical). The negative-control regression tests live
in `verify/tests/test_client_side_posture.py` and run in the required **CRUCIBLE core on vigil_core** CI
job.

---

## What this list is *not*

It is not a claim that VIGIL is safe against everything, nor that these are the *only* things it does
not do. It is the enumerated set of **deliberate** refusals — capabilities within easy reach that were
consciously declined — each grounded in code and held by a test. For the broader honest boundary of
what VIGIL proves and does not prove, see [`docs/POSTURE.md`](POSTURE.md),
[`docs/AS-BUILT-LIVE.md`](AS-BUILT-LIVE.md), and [`docs/limitations/`](limitations/).
