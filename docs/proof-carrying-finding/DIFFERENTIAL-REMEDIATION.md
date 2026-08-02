# Differential remediation — narrowing the silent-case interposer residual (design-first)

> **Status: design, not yet built — and revised once already after adversarial review.** This is the reviewed
> security-engineering design for part of the disclosed SILENT (REMEDIATED) residual in `TRUST-GRADIENT.md`. A
> first draft over-claimed; a red-pen pass found a false-REMEDIATED counterexample (an in-flight *sanitizing*
> interposer) and a forgeable clause construction. This revision states the **narrow** adversary it actually
> defeats and discloses the ones it does not. It is written to be reviewed and independently checked **before**
> the adapter is built, as `REMEDIATION-SEMANTICS.md` / `PROTOCOL.md` / `WITNESS-TRUST.md` preceded their
> drivers. It invents no new oracle, but it DOES require one new freshness verifier (§5) — called out honestly.

## 1. The residual, precisely — and split into sub-cases

VF-1a.3 (`#202`) made the error-signature remediation honest: a REMEDIATED verdict is F1, and an F2-demanding
verifier gets `INCONCLUSIVE`. But F1 cannot distinguish a real fix from an in-flight mitigation that neutralizes
the exploit while leaving the origin vulnerable-if-reached-directly. That "in-flight mitigation" is **not one
residual but three**, and this design closes only the first:

- **(a-block) a *blocking/diverting* payload-discriminating WAF** — blocks the exploit's metacharacters (403, a
  block page, a redirect). **This design closes it.**
- **(a-sanitize) a *sanitizing/virtual-patching* interposer** — does NOT block; it escapes/strips the
  metacharacters in-flight (a common ModSecurity/gateway transform), so the origin receives inert data and
  answers normally. **This design does NOT close it** (§7) — it is a false-REMEDIATED source and must be
  disclosed as mitigated-by-edge, exactly like (b).
- **(b) a param-stripping edge** — drops the injectable param entirely (§7).

The mechanism for (a-block) is a **matched decoy**: a probe *indistinguishable to a content-inspecting WAF* from
the exploit, so the WAF cannot pass one while blocking the other, combined with a boolean signal whose
**genuine** form reflects the origin's own data — so a *blocking* WAF is detected (it blocks the decoy too) and a
real fix is separable from it. The signal is not interposer-*unforgeable* (§2), but its forgeries only ever
over-report STILL_VULNERABLE, never a false REMEDIATED.

## 2. The signal, and the precise (bounded) adversary model

The signal is the **boolean differential** already computed in `framework/v2/verify/oracles.py`:

- `differential_response_oracle(baseline, mutated, discriminator)` — quantifies whether two responses differ
  (dimensions `status`/`length`/`lexical`/`structural`/`marker`; `expect: "differ" | "same"`). Note the default
  dimension set does **not** include `structural`; a caller must request dimensions explicitly (see §4).
- `boolean_inference_oracle(probe_rounds, …)` — per round, the Bernoulli signal is
  **(TRUE clause differs from FALSE clause) AND (the two FALSE clauses agree)**, accumulated under a Wald
  **SPRT** that terminates in one of THREE outcomes: `confirm`, `refute`, or `inconclusive` (no boundary
  reached). The second half of the per-round signal is a genuine per-round *dynamic-page control*.

**What an interposer can and cannot forge — precisely (and it is NOT "cannot forge the differential").** Over
plaintext HTTP the three probes are always *lexically separable* — `true` and `false_a` must differ in bytes to
carry opposite booleans, and `false_a`/`false_b` differ only in the inert marker. So a **non-executing lexical
interposer can fabricate a firing** by partitioning the probes on surface form (return X for `true`, Y for both
`false`s) with zero origin queries. Data-dependence does **not** prevent this (a *constant* tautology is merely
even easier — a SQL-parsing WAF evaluates it directly). The boolean firing is therefore **not
interposer-unforgeable**. What data-dependence and the oracle actually buy is bounded and *one-directional*:

  * a **fabricated firing only ever OVER-REPORTS STILL_VULNERABLE** — the conservative "go investigate" verdict,
    never a false all-clear. Suppressing the signal to force a false REMEDIATED is the separately-disclosed
    sanitizing / cache case (§7), not something this forgery adds.
  * a **genuine firing reflects the origin's own data** (the data-dependent predicate), so a *real* differential
    is real evidence the sink executed. The channel simply cannot tell a genuine firing from a lexically-forged
    one from the response bytes alone, and so must treat STILL_VULNERABLE as *"the origin executes the injection
    OR an interposer is fabricating a differential — either way, not remediated,"* never as proof-of-vuln.

The property is thus: **unforgeable in the REMEDIATED direction only up to the disclosed §7 residuals**, and in
the STILL_VULNERABLE direction it is a safe over-approximation, not an unforgeable proof. It is emphatically
**NOT** producer-unforgeable (a producer fabricating the origin's bytes is the OOB Tier-2 / zkTLS frontier, §7),
and does **not** defeat a *sanitizing* interposer (§1 a-sanitize), which lets the probe reach the origin as inert
data.

## 3. The matched-decoy triple (+ baseline), with DATA-DEPENDENT clauses

Per round, through the **same injectable parameter**, carrying the run `challenge` only as an inert freshness
marker (never as the discriminating predicate):

| probe | clause shape (illustrative) | metachar profile | purpose |
|---|---|---|---|
| `baseline` | benign value, NO metacharacters, carries `<c>` | none | the inert-handled / un-WAF'd response shape |
| `true`  | `… ' AND (SELECT SUBSTR(@@version,1,1))>'' -- <c>` (a predicate TRUE on the live DB) | full exploit metachars | the TRUE clause — **data-dependent** |
| `false_a` | `… ' AND (SELECT SUBSTR(@@version,1,1))>'~~~' -- <c>` (same predicate, FALSE) | full exploit metachars | a FALSE clause — **data-dependent** |
| `false_b` | `… ' AND (SELECT SUBSTR(@@version,1,1))>'~~~' -- <c2>` (FALSE, different marker) | full exploit metachars | the dynamic-page control twin |

`true`/`false_a`/`false_b` are **metacharacter-identical in class** (all carry `'`, `AND`, `SELECT`, `--`), so a
content-inspecting WAF that blocks one blocks all — the matched decoy. They differ in a **data-dependent
predicate** the origin's DB must evaluate, so a *genuine* firing reflects origin data. This does **not** stop a
non-executing interposer from *lexically* fabricating a firing (§2) — but a fabricated firing only over-reports
STILL_VULNERABLE, never REMEDIATED. The exact predicate is per-DB-family and is an implementation concern; the
design constraint is only that it be data-dependent and that `<c>` never be the thing that flips the boolean.

## 4. The four-way attribution (the state machine)

Given the live responses, adjudicated by the **existing** oracles (never a new judgement), with the discriminator
scoped **per comparison**:

1. **`boolean_inference_oracle` returns `decision == "confirm"` (FIRES)** → the sink executes the injection this
   run **OR** an interposer is lexically fabricating the differential (§2) → **STILL_VULNERABLE** (a safe
   over-approximation — "not remediated, investigate", never a false all-clear). The boolean-signal comparison
   (`true` vs `false`) MUST use a **lexical-sensitive** discriminator (a real injection may change only reflected
   *text*, invisible to `status`+`structural` alone).

2. **`decision == "refute"` (DECISIVELY indistinguishable) *and* the metachar probes REACHED THE ORIGIN** →
   **REMEDIATED**. "Reached the origin" is the WAF-closure test:
   `differential_response_oracle(baseline, false_a, discriminator={dimensions:[status,structural], expect:"same"})`
   must hold — the metachar-bearing probe is handled like the benign baseline (a normal page), i.e. NOT turned
   into a block page. Responses MUST carry a `status` (else that dimension is silently dropped and the test
   weakens). Because the decoy is metachar-identical to the exploit, a WAF that would block the exploit blocks
   `false_a` → it differs from `baseline` → this test fails → no REMEDIATED. **The cert records
   `origin_reached: true`, meaning ONLY "a baseline-shaped 200 came back for a metachar payload" — it does NOT
   mean the metacharacters reached the sink intact** (a sanitizer defeats that, §7).

3. **`decision == "refute"` *and* the metachar probes were BLOCKED/diverted** (`false_a` differs from
   `baseline`) → **INCONCLUSIVE** (`Reason.INTERPOSER_SUSPECTED`, new) — a blocking WAF/edge is interposing.

4. **`decision == "inconclusive"` (SPRT reached no boundary)** → **INCONCLUSIVE** (`Reason.INSUFFICIENT_ROUNDS`)
   — *absence of evidence is not evidence of a fix.* REMEDIATED requires a **decisive refute**, never a
   non-decision (HIGH-3). Likewise any probe that cannot be built, is not delivered, or yields a malformed round
   → the whole run is INCONCLUSIVE: `boolean_inference_oracle` silently `continue`s past malformed rounds, so the
   **adapter/driver** (not the oracle) MUST enforce this fail-closed obligation (HIGH-4).

The positive control: the **retained** vulnerable probe-rounds must still fire `boolean_inference_oracle`
(harness capability); the live control is a real fetch this run (VF-1a.3) and, for this channel, MUST observe
its fresh benign marker reflected (not mere reachability) so a query-stripping cache is caught (LOW-1).

**Soundness of REMEDIATED — and its exact boundary.** A false REMEDIATED requires the decoy pair to reach the
origin, be handled with no differential, yet the origin be vulnerable-if-reached-directly. With a *working
data-dependent* pair this happens in exactly one way: an **in-flight sanitizer** (a-sanitize) neutralizes the
metacharacters so the origin sees inert data. A *blocking* WAF cannot cause it (blocked → step 3 INCONCLUSIVE); a
non-executing interposer cannot fake the *firing* direction either (data-dependent clause, §2). So the design is
sound against a **blocking** content-discriminating WAF and against a non-executing interposer, and is **unsound
against a sanitizing one** — which is therefore disclosed (§7), not claimed closed.

## 5. Freshness in the differential channel — needs a NEW verifier

The challenge rides the probes as an inert marker. For **STILL_VULNERABLE**, a firing whose rounds carry the
fresh challenge should earn **F2** (the sink's boolean behaviour exercised this run) — but this is **not
delivered by existing code**: the merged F2 gate calls `_challenge_in_firing_signature`
(`prove_driver.py`), which is hard-wired to the **error-signature** channel (it re-fires `error_signature_oracle`
and checks the matched *error line*). A boolean firing has no error line, so the existing gate **caps a
differential firing to F1**. Delivering F2 here requires a **new** verifier — "the fresh challenge marker is
present in the judged clauses of the firing rounds" — which §9 lists as new work. Until it exists, the
differential channel is honestly **F1 for both verdicts** (STILL_VULNERABLE@F1, REMEDIATED@F1+`origin_reached`).
For **REMEDIATED**, F2 stays unattainable regardless (a fixed sink is not traversable, per VF-1a.3), and
`origin_reached` is **not** a freshness level and **not** an interposition proof beyond (a-block).

## 6. Downgrade resistance & invariants

- Only the **existing** `boolean_inference_oracle` / `differential_response_oracle` mint the judgement (oracle
  authority); the adapter arranges probes, the driver sequences them and owns the fail-closed obligation (§4.4).
- REMEDIATED requires (decisive SPRT `refute`) **AND** (the WAF-closure baseline test passes) **AND** (every
  round delivered and well-formed) — no flag skips any of these.
- FATAL-2 (framework imports function-local), determinism (driver supplies `now`/`run_id`/nonces; the two false
  markers derive from the challenge, not RNG; the data-dependent predicate is a fixed template, not RNG),
  fail-closed (any unbuildable/undelivered/ambiguous probe → INCONCLUSIVE), one signed causal-chain cert.

## 7. What this does NOT close (honest, disclosed)

- **(a-sanitize) an in-flight sanitizing / virtual-patching interposer.** It escapes or strips the
  metacharacters, the origin answers inertly, the WAF-closure test passes, the boolean refutes → a REMEDIATED
  **indistinguishable from a real code fix**, with `origin_reached: true`. This is the BLOCK the review caught. It
  is **mitigated-by-edge, not fixed-in-code** — a scope question (is the sanitizer part of the system-under-test,
  and permanent?). The cert MUST NOT present it as a clean fix beyond what `origin_reached` literally asserts;
  distinguishing it needs an origin-side observation the response channel cannot provide (side-effect / OOB
  Tier-2 / direct-to-origin re-drive bypassing the edge).
- **(b) a param-stripping edge** that drops the injectable param → all probes collapse to baseline → looks
  REMEDIATED. Same mitigated-by-edge scope bucket (an all-stripping non-echoing edge fails the live-marker
  reflection control → INCONCLUSIVE).
- **A structurally-matched 200 block page** (a WAF block page shaped like the baseline "no results") can pass the
  WAF-closure test if the discriminator is out-tuned — REMEDIATED soundness against a block-page WAF is therefore
  *heuristic* (raises the bar), not an invariant. Disclosed; the corpus (§8) must include a 200-block-page WAF.
- **A cache/CDN keyed on less than the full URL** (query-stripping) serves one body for all probes → caught only
  by the live-marker-reflection control (§4); stated as a dependency, tested in §8.
- **Producer byte-forgery** of the origin's data for all probes — the OOB Tier-2 / zkTLS frontier.

## 8. Adversarial test plan (loopback servers, the VF-1a.3 harness)

1. **genuine fix** — parameterized origin: data-dependent `true ≈ false`, both match baseline, SPRT `refute` →
   **REMEDIATED**, `origin_reached=true`.
2. **still vulnerable, clean path** — injectable origin: `true ≠ false`, `false_a ≈ false_b`, SPRT `confirm` →
   **STILL_VULNERABLE**.
3. **blocking payload-discriminating WAF over a vulnerable origin** — 403/block-page for metachar probes,
   baseline passes → `false_a` differs from baseline → **INCONCLUSIVE** (`INTERPOSER_SUSPECTED`). *The acceptance
   test for the (a-block) closure.*
4. **sanitizing WAF over a vulnerable origin** — escapes quotes in-flight → origin inert → refute + closure
   passes → REMEDIATED. Assert the cert carries only `origin_reached` and the (a-sanitize) residual is surfaced
   (NOT a clean-fix claim). *The BLOCK-1 disclosure, pinned as a test so the honesty cannot silently regress.*
5. **SQL-parsing interposer, constant-clause variant** — assert that a constant-clause construction is forgeable
   (a regression guarding the §3 requirement that clauses be data-dependent).
6. **dynamic page** — every response differs → `false_a ≠ false_b` trips the per-round control → not a false
   STILL_VULNERABLE.
7. **SPRT-inconclusive** — too few/noisy rounds, no boundary → **INCONCLUSIVE** (`INSUFFICIENT_ROUNDS`), never
   REMEDIATED.
8. **200 block page ≈ baseline** — a structurally-close block page; assert the status/structural discriminator
   still separates it, and document the residual if a chosen block page defeats it.
9. **query-stripping cache** — identical body for all probes → the live-marker-reflection control fails →
   **INCONCLUSIVE**.
10. **malformed/undelivered round** — one probe fetch fails → whole run **INCONCLUSIVE** (fail-closed in the
    adapter/driver, not silently dropped by the oracle).
11. **text-only differential** — a vulnerable origin whose true/false differ only in reflected text → the
    lexical-sensitive boolean discriminator still fires (guards HIGH-4.1).
12. **determinism / FATAL-2** — no RNG in the markers or the predicate template; no module-scope framework import.

## 9. Implementation order (design-first → reviewed slices)

1. **This spec (revised)** — reviewed to convergence first.
2. `DifferentialHttpAdapter` (a second `LiveTargetAdapter`) — builds baseline + data-dependent
   true/false_a/false_b from a `clause_template` (data-dependent predicate + `{challenge}` inert marker),
   gated-fetches them, assembles the `probe_rounds` context, runs the WAF-closure `differential_response_oracle`
   check, and **fail-closes the whole run** on any undelivered/malformed probe. Positive control = retained
   firing rounds; live control observes fresh-marker reflection.
3. Driver support — `prove_remediation` gains a channel abstraction so a "trial" may be a round bundle judged by
   `boolean_inference_oracle`; REMEDIATED requires SPRT `decision == "refute"` (not merely `fired == False`) +
   the WAF-closure gate; new `INTERPOSER_SUSPECTED` / `INSUFFICIENT_ROUNDS` reasons. Error-signature channel
   unchanged.
4. **New differential-channel freshness verifier** (§5) — "the fresh marker is in the judged clauses of the
   firing rounds" — to lift a genuine differential firing from F1 to F2. Separate, reviewed slice.
5. Adversarial red-pen against the §8 corpus (esp. the sanitizing-WAF disclosure and the constant-clause
   regression) → CI → merge.
6. `TRUST-GRADIENT.md` updated: **(a-block) moves from deferred to closed**; **(a-sanitize), (b), block-page,
   and producer byte-forgery remain the disclosed frontier** — the residual list gets *more* precise, not shorter
   by sleight of hand.

## 10. One-line trust statement (for the tin, once built)

> A differential-channel REMEDIATED means: under the recorded authorization/identity/freshness, a
> metacharacter-bearing **data-dependent** boolean pair drew a **decisively indistinguishable** (SPRT-refuted)
> response and a baseline-shaped 200 came back (`origin_reached`) — so a **blocking** content-discriminating WAF
> is ruled out, and the injection no longer executes at the sink **as observed through this edge**. It does
> **not** rule out an in-flight **sanitizing** interposer, an edge that **strips the parameter**, a
> structurally-matched 200 block page, or a producer that fabricates the origin's bytes — all reported honestly,
> none presented as a clean code fix. (The *complementary* STILL_VULNERABLE verdict is a safe over-approximation,
> not an unforgeable proof: a non-executing interposer can lexically fabricate a firing — §2 — but only ever
> over-reports "not remediated," never a false all-clear.)
