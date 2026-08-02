# Differential remediation — closing the payload-discriminating-WAF residual (design-first)

> **Status: design, not yet built.** This is the reviewed security-engineering design for the one remaining
> disclosed residual of the SILENT (REMEDIATED) case in `TRUST-GRADIENT.md` — a *payload-discriminating WAF*
> that blocks the exploit's metacharacters while a real fix and a WAF-block look identical at F1. It is written
> to be reviewed and independently checked **before** the adapter is built, exactly as `REMEDIATION-SEMANTICS.md`
> / `PROTOCOL.md` / `WITNESS-TRUST.md` preceded their drivers. It grounds every claim in primitives that already
> exist — no new oracle is invented.

## 1. The residual, precisely

VF-1a.3 (`#202`) made the error-signature remediation honest: a REMEDIATED verdict is reported at **F1**, and a
verifier that demands F2 gets `INCONCLUSIVE`. But F1 does not distinguish, from a real fix:

- **(a) a payload-discriminating WAF** — it blocks the exploit's metacharacters (`'`, `--`, `UNION`, …) while
  passing a benign request. The exploit is then silent because it was *blocked*, not *fixed*; the live positive
  control's benign marker sails through, so the run reads `REMEDIATED@F1` over a still-vulnerable origin.
- **(b) a param-stripping edge fronting a request-echoing gateway** — treated separately in §7.

This document closes **(a)**. The mechanism is a **matched decoy**: a probe that is *indistinguishable to a
content-inspecting WAF* from the exploit, so the WAF cannot let one through while blocking the other, combined
with a signal that **only an executing sink can produce** and **no interposer can forge**.

## 2. The interposer-unforgeable signal (already built)

The signal is the **boolean differential** the framework already computes in
`framework/v2/verify/oracles.py`:

- `differential_response_oracle(baseline, mutated, discriminator)` — quantifies whether two responses differ
  (status / length / lexical / structural / marker), with an `expect: "differ" | "same"` mode.
- `boolean_inference_oracle(probe_rounds, …)` — per round, the Bernoulli signal is

  > **(TRUE clause differs from FALSE clause)  AND  (the two FALSE clauses agree)**

  accumulated under a Wald **SPRT** (robust to caching / per-request tokens / dynamic pages). The first half is
  the boolean signal; the second is a *dynamic-page control* — a page that simply changes every request trips
  the control and cannot masquerade as a bug.

**Why an interposer cannot forge it.** A WAF, CDN, cache, or request-echoing gateway does not hold the origin's
data and cannot evaluate an injected boolean clause against it. It therefore cannot produce a response that
differs for `… AND 1=1` but is stable for two `… AND 1=2` variants. The boolean differential is, like the
error-signature firing, **as attributable as the oracle itself** — not byte-unforgeable against a producer that
fabricates the origin's data (that remains the OOB Tier-2 / zkTLS frontier, §7), but unforgeable against an
*interposer* that cannot execute the injection. That is exactly the adversary residual (a) is about.

## 3. The matched-decoy triple (+ baseline)

Per round the differential adapter sends, through the **same injectable parameter**, carrying the run
`challenge` in a data position:

| probe | payload shape | metachar profile | purpose |
|---|---|---|---|
| `baseline` | a benign value, NO injection metacharacters | none | what an un-WAF'd, inert-handled request looks like |
| `true`  | `… ' AND '<c>'='<c>' -- ` (tautology, true) | full exploit metachars | the TRUE clause |
| `false_a` | `… ' AND '<c>'='<c>x' -- ` (contradiction) | full exploit metachars | a FALSE clause |
| `false_b` | `… ' AND '<c2>'='<c2>y' -- ` (contradiction, different literal) | full exploit metachars | the dynamic-page control twin |

`true` / `false_a` / `false_b` are **metacharacter-identical in class** — a content-inspecting WAF that blocks
one blocks all three (they all carry `'`, `AND`, `--`). This is the *matched decoy*: the WAF cannot pass the
inert probes while blocking the exploit, because they are the same kind of payload.

## 4. The three-way attribution (the state machine)

Given the four live responses, adjudicated by the **existing** oracles (never a new judgement):

1. **`boolean_inference_oracle([{true, false_a, false_b}, …])` FIRES** → the sink executes the injection this
   run → **STILL_VULNERABLE**. Freshness: the challenge rides the clauses, so a firing over probes carrying the
   fresh nonce is **F2** (the boolean sink behaviour was exercised this run), on the same "as-attributable-as-
   the-oracle" footing VF-1a.3 established for the error channel.

2. **boolean SILENT *and* the metachar probes REACHED THE ORIGIN** → **REMEDIATED**. "Reached the origin" is the
   WAF-closure test: `differential_response_oracle(baseline, false_a, expect="same")` must hold — the
   metacharacter-bearing probe is handled like the benign baseline (a normal "no results" page), i.e. it was
   **not** turned into a block page. Because the decoy is metachar-identical to the exploit, a WAF that would
   block the exploit would also block `false_a` → it would differ from `baseline` → this test fails → we do
   **not** mint REMEDIATED. So a silent-because-blocked path can no longer be read as a fix.

3. **boolean SILENT *and* the metachar probes were BLOCKED / diverted** (`false_a` differs from `baseline` in a
   block-page way) → **INCONCLUSIVE** (`Reason.INTERPOSER_SUSPECTED`, new) — a WAF/edge is interposing; silence
   is not attributable to a fix. Never a false REMEDIATED.

The positive control is unchanged in spirit: the **retained** vulnerable probe-rounds must still fire
`boolean_inference_oracle` (harness capability), and the live control is a real fetch this run (VF-1a.3).

**Why REMEDIATED is sound even against a signature-specific WAF.** A false REMEDIATED would require the decoy
pair to reach a *vulnerable* origin yet produce *no* differential — impossible for a correctly-constructed
boolean pair (a true tautology and a false contradiction differ at a vulnerable sink). So the only routes to
REMEDIATED are (i) the decoy reaches the origin and is handled inertly (genuinely fixed) or — if a WAF passes
the decoy but blocked the exploit — the decoy, reaching a still-vulnerable origin, **fires** the boolean oracle
→ STILL_VULNERABLE, not REMEDIATED. The design therefore does not depend on the WAF blocking the decoy; it
depends only on a *working* boolean pair.

**Implementation caution (block-page vs baseline discriminator).** Step 2's `expect="same"` test must actually
detect a WAF block page as *differing* from the benign baseline. A WAF that returns a `200` block page
lexically close to the app's own "no results" page could slip past a loose discriminator and be read as
"reached the origin." The baseline MUST be chosen to mirror the *inert-injection* response shape (a benign
search that returns the same "no results" page a parameterized injection would), and the discriminator MUST
include `status` + `structural` dimensions, not lexical length alone. This is a tuning obligation the
implementation slice owns and the adversarial corpus (§8.3) must exercise with a 200-block-page WAF, not only a
403.

## 5. Freshness in the differential channel

The challenge is embedded in the clause literals (`'<c>'='<c>'`). For **STILL_VULNERABLE**, a firing boolean
differential whose rounds carry the fresh challenge earns **F2** — the sink's boolean behaviour was exercised
with this run's nonce (the differential channel's analogue of the error-line same-line check). For
**REMEDIATED**, freshness stays **F1** (a fixed sink cannot be *traversed*, §1 of VF-1a.3 still holds), **but**
the certificate additionally attests `origin_reached: true` — a distinct, honestly-scoped property meaning "the
metacharacter payloads reached the origin and were handled inertly (WAF ruled out for class (a))." `origin_reached`
is **not** a freshness bump and **not** an interposition-proof beyond (a); it is recorded so a consumer can tell
a differential-channel REMEDIATED (WAF-closed) from an error-channel REMEDIATED (WAF-open).

## 6. Downgrade resistance & invariants

- Only the **existing** `boolean_inference_oracle` / `differential_response_oracle` mint the judgement — oracle
  authority is preserved; the adapter only *arranges* the probes and the driver *sequences* them.
- The WAF-closure test (step 2) is **mandatory** for a differential-channel REMEDIATED — there is no flag to
  skip it (contrast the removed `require_injectable_param_live`; this one is sound because the decoy is
  metachar-identical, so a passing decoy genuinely rules out a content-discriminating WAF).
- FATAL-2 (framework imports function-local), determinism (the driver supplies `now`/`run_id`/nonces; the two
  false literals are derived from the challenge, not RNG), fail-closed (any probe that cannot be built or judged
  → INCONCLUSIVE, never REMEDIATED), single signed causal-chain cert (as VF-1a).

## 7. What this does NOT close (honest, deferred)

- **(b) a param-stripping edge that drops the injectable param entirely.** Then `true`/`false_a`/`false_b` all
  collapse to the same benign request → no differential AND they match the baseline → the run reads REMEDIATED.
  This is "mitigated-by-edge, not fixed-in-code": from the client's vantage the param is not injectable through
  that edge, but the origin may be vulnerable if reached directly. It is a **scope question** (is the WAF/edge
  part of the system-under-test?), not a soundness bug — disclosed, and reported with `origin_reached: true`
  only when a benign baseline genuinely round-trips the param (an all-stripping edge that does not echo the
  param at all fails even the baseline round-trip and yields INCONCLUSIVE).
- **Byte-forgery by a malicious producer** — a producer that fabricates the origin's data for all four probes.
  This is the general zkTLS/TLSNotary frontier and the OOB Tier-2's domain; the differential channel is
  interposer-unforgeable, not producer-unforgeable.

## 8. Adversarial test plan (loopback servers, the VF-1a.3 harness)

Each against a real `ThreadingHTTPServer`, driven through the gated `HttpExecutor`:

1. **genuine fix** — parameterized origin: `true ≈ false`, both match baseline → **REMEDIATED**, `origin_reached=true`.
2. **still vulnerable** — injectable origin: `true ≠ false`, `false_a ≈ false_b` → boolean FIRES → **STILL_VULNERABLE@F2**.
3. **payload-discriminating WAF over a vulnerable origin** — blocks metachar probes (block page), passes
   baseline: `false_a` differs from `baseline` → **INCONCLUSIVE** (`INTERPOSER_SUSPECTED`), *never* REMEDIATED.
   This is the residual (a) closed — the acceptance test of the whole slice.
4. **dynamic page** — every response differs: `false_a ≠ false_b` trips the within-same control → boolean does
   not fire spuriously → not a false STILL_VULNERABLE.
5. **param-stripping edge** — drops the param: all probes ≈ baseline → **REMEDIATED**, but the cert marks the
   (b) residual honestly (documented, not hidden); an all-stripping non-echoing edge → INCONCLUSIVE.
6. **freshness** — a firing round carrying the fresh nonce → F2; a firing round whose nonce is absent from the
   judged clauses → capped to F1 (the challenge must ride the clauses).
7. **determinism / FATAL-2** — no RNG in the two false literals; no module-scope framework import.

## 9. Implementation order (design-first → reviewed slices)

1. **This spec** — reviewed first.
2. `DifferentialHttpAdapter` (a second `LiveTargetAdapter`) — builds the baseline + true/false_a/false_b probes
   from a `clause_template` carrying `{challenge}`, gated-fetches them, assembles the `probe_rounds` context the
   `boolean_inference_oracle` re-fires over, and runs the step-2 WAF-closure `differential_response_oracle`
   check. Positive control = retained firing rounds.
3. Driver support — `prove_remediation` gains a channel abstraction so a "trial" may be a *round bundle*
   (true/false_a/false_b) judged by `boolean_inference_oracle`, plus the mandatory WAF-closure gate and the
   `INTERPOSER_SUSPECTED` state; the error-signature channel is unchanged.
4. Adversarial red-pen (try to forge a differential without an executing sink; get REMEDIATED past a WAF; get
   STILL_VULNERABLE from a dynamic page) → CI → merge.
5. `TRUST-GRADIENT.md` updated: residual (a) moves from "deferred" to "closed by the differential channel";
   (b) and byte-forgery remain the disclosed frontier.

## 10. One-line trust statement (for the tin, once built)

> A differential-channel REMEDIATED means: under the recorded authorization/identity/freshness, a
> metacharacter-bearing boolean-injection pair **reached the origin and was handled inertly** (a
> content-discriminating WAF is ruled out), and the interposer-unforgeable boolean-differential oracle went
> **silent** across the protocol-required rounds — so the original injection no longer executes at the sink.
> It does not rule out an edge that strips the parameter (mitigated-by-edge, a scope question) or a producer
> that fabricates the origin's bytes (the OOB/zkTLS frontier).
