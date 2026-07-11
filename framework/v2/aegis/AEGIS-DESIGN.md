# AEGIS — MVP Design (finalized, as built)

*The defensive dual of CRUCIBLE: an embeddable AI-attack-detection API powered by the
prove-don't-guess core pointed inward at the operator's OWN app. Additive package
`framework/v2/aegis/`, built ON `verify/`. This document reflects the code as shipped and the
five doctrine fixes (G1, P1, P2, PR1, PR2/PR3) baked in.*

See the design-research trilogy for the full rationale:
`framework/v2/docs/aegis/AEGIS-DESIGN-RESEARCH.md`, `AEGIS-DOCTRINE-CRITIQUE.md`,
`AEGIS-SIGNAL-CATALOG.md`, `AEGIS-CRUCIBLE-REUSE-MAP.md`.

---

## 1. What the MVP ships

Two surfaces where a deterministic oracle genuinely promotes a signal to a re-runnable
certificate — everything else is roadmap (LEAD-only or deferred):

| Class | Confirmed via | Honest attack_class | Certificate |
|---|---|---|---|
| **System-prompt disclosure** | a planted high-entropy canary appears VERBATIM in the app's own LLM output | `system_prompt_disclosure` | retains sentinel + redacted span (PR1) |
| **Prompt injection** | an injected directive PROVABLY flipped a structurally-detectable behavior vs a clean control | `prompt_injection` | retains the (control, treatment) behavior pair |
| **Automated access** | a non-interactive client fetched a seeded honeypot resource no human UI links | `automated_access` | retains the requested path + honeypot set |

A structural-override marker with no canary / no behavior delta stays a **LEAD**
(`decision="lead"`). "No oracle fired and signals below band" is **`decision="clear"`** —
which is *not* "safe", and is documented as such.

## 2. The pipeline (as built — `aegis/pipeline.py::detect`)

```
raw telemetry (dict / JSON / TelemetryEnvelope)
  → boundary.ingest        untrusted-input hardening + keyed-HMAC PII redaction (§5)
  → sensors.observations   provenance-tagged intel.Observation(s) — a LEAD (GROUNDING_INTEL)
  → actor_graph.observe     per-actor Beta belief via intel.project.project_observation
  → OracleVerifier.confirm  a deterministic AEGIS oracle fires over retained FindingContext
  → veracity.admit          re-executes the ground bound to the class; can ONLY demote
  → confidence.assess_finding  posterior vs the MECE benign twin (the honest FP guard)
  → Verdict {decision, attack_class, certificate, band, top_alternative, provenance, action, refutation}
```

Two invariants (enforced by `Verdict`'s model validator + the pipeline):
- `decision == "confirmed"` ⇔ `certificate is not None` (the offline-re-runnable proof).
- `provenance == "grounded:…"` ⇒ an oracle fired **and** `admit()` re-admitted it as a fact.

Fully deterministic: a pure function of the redacted input + the caller's monotonic `seq`.
Same evidence → byte-identical `Verdict` → identical `certificate.cert_id` (a content hash).

## 3. Reuse (unchanged) vs. NEW

- **Reused unchanged:** `verify/verifier.py` (`OracleVerifier.confirm`), `verify/adapter.py`
  (`FindingContext` translator), `verify/reverify.py` (`reverify_context` — the offline cert),
  `veracity/firewall.py` (`admit()` only-demotes), `intel/project.py::project_observation`
  (Beta belief keystone), `worldmodel` Beta node, `confidence/decision.py::assess_finding`
  (SCE posterior). None of these were modified.
- **NEW oracle bodies** in `verify/oracles.py` (NOT `aegis/` — avoids an aegis↔verify import
  cycle; `verify/` never imports `aegis/`): `system_prompt_disclosure_oracle`,
  `prompt_injection_oracle`, `honeypot_hit_oracle` — pure, deterministic, no wallclock/rng.
- **NEW additive vocabulary** (appends, never rewrites): 3 `OracleKind` members + 3
  `BUG_CLASS_ORACLES` rows + aliases (`verify/`), 2 `IntelSourceKind` members (`intel/`), 3
  MECE `_ALTERNATIVES`/twin rows (`confidence/`).
- **NEW `aegis/` package:** the inbound SDK/HTTP boundary, the two sensors, the bounded
  actor-graph (windowing/eviction — the one genuinely new continuous-loop concern), the guard
  (canary/honeypot), the pipeline, and a light WSGI/HTTP middleware.

## 4. The five doctrine fixes (all mandatory, all in)

- **G1 — frozen `_ALL_ORACLES`.** `verify/verifier.py::_ALL_ORACLES` is an EXPLICIT tuple of
  the 15 pre-AEGIS members, NOT `tuple(OracleKind)`. So appending the AEGIS members cannot grow
  the unknown-class fallback `oracles_for()` returns — AEGIS oracles reach `confirm()` ONLY via
  their explicit `BUG_CLASS_ORACLES` rows. `test_gate_byte_identical.py` asserts the fallback
  path (not just known classes) is unchanged after `import aegis`.
- **P1 — honeypot ⇒ `automated_access`, never "scraping".** The confirmed class is the proven
  fact (automated access). `automated_scraping` is an ALIAS onto `automated_access`. An
  operator crawler allowlist makes a known-good fetch **REFUTES** (a non-firing, belief-
  lowering signal), never a confirmation.
- **P2 — canary-only ⇒ `system_prompt_disclosure`.** `prompt_injection` is reserved for the
  control-vs-treatment behavior-delta path. The sentinel must be a high-entropy random token
  (≥ 16 chars, ≥ 2.5 bits/char) so a substring match cannot be coincidental.
- **PR1 — honest class-1 retention.** The class-1 certificate retains the random sentinel and a
  bounded, boundary-redacted matched span in **plaintext** — because `reverify_context` re-fires
  on verbatim substrings. The sentinel is a dedicated random token (never proprietary prompt
  text, never raw PII); "only hashes survive" does NOT hold for class 1 and we say so.
- **PR2/PR3 — keyed identifiers + ReDoS-safe matchers.** Identifiers are pseudonymised with a
  keyed HMAC (per-deployment secret) over a /24 (v4) / /48 (v6) IP coarsening — not a brute-
  forceable bare hash. Structural-override markers are matched by linear substring scan over a
  length-capped input; PII redaction uses bounded, non-backtracking patterns after a length cap.

## 5. Doctrine & safety

Defensive only (never attacks); correlatable; not anti-defender. Default `mode="observe"` is
read-only — the pipeline invokes no response Tool. Any enforce-mode action rides ONLY on a
confirmed certificate (D1), and `challenge/throttle/block` Tools remain roadmap behind the
`aegis.respond` entitlement + `invoke_tool` gate. A fabricated actor absent from the world-model
is `UNGROUNDED` at `admit()`. `Verdict.attack_class` is a verify `KnownBugClass`, so a
hallucinated class is parse-rejected; `Verdict.decision` is a three-valued `Literal`, never a
bare boolean.

## 6. Roadmap (NOT built)

Credential-stuffing (SPRT), stored/indirect injection (RAG), model extraction, phishing/UGC,
synthetic identity — each rides the same pipeline adding at most one sensor + one oracle.
Classes 7 (human-mimic bots), single-input evasion, and membership-inference remain **LEAD-only,
permanently** — shipping them as verdicts would be the "AI detects AI" hype the doctrine forbids.
