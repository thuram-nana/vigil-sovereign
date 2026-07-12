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
| **Credential stuffing / ATO** | a source's UNSEEN-`(account, source)` auth SUCCESSES cross the Wald SPRT AND survive a Holm-Bonferroni family-wise control across identities | `credential_stuffing` | retains the ordered auth-outcome window (keyed-HMAC pseudonyms) |

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

*Credential-stuffing / ATO is now BUILT* (the `credential_stuffing` oracle: a Wald SPRT over each
source's unseen-`(account, source)` auth successes + a Holm-Bonferroni family-wise control across
identities; the `AuthTelemetrySensor` + `Surface.AUTH`; the MECE benign twin is NAT/CGNAT bulk —
a failed-only burst yields no SPRT round and stays a LEAD). Still roadmap:

Stored/indirect injection (RAG), model extraction, phishing/UGC,
synthetic identity — each rides the same pipeline adding at most one sensor + one oracle.
Classes 7 (human-mimic bots), single-input evasion, and membership-inference remain **LEAD-only,
permanently** — shipping them as verdicts would be the "AI detects AI" hype the doctrine forbids.

## 7. Product depth — the inline provable firewall (W1, as built)

The `aegis/gateway.py` reverse-proxy gained more web-attack coverage, every block still riding on a
fired oracle + a re-runnable certificate (D1); everything unprovable inline stays a LEAD or a
graduated soft response, never a hard block.

**Shipped as a BLOCK (response-side proof, `inspect_response`).**
- **SSTI** — a template-wrapped pure-arithmetic payload (`{{7*7}}`, `${7*7}`, `<%=..%>`, `#{..}`,
  `*{..}`, `@(..)`) confirmed via `evaluation_oracle`: the response carries the COMPUTED result while
  the raw expression is GONE. A reflected/HTML-encoded template (raw survives) never fires; a
  non-arithmetic `{{var}}` is not a candidate; a 1-digit result is skipped. Near-zero FP.
- **Path traversal / LFI** — a request value that walks the path toward a sensitive file, confirmed
  via `side_effect_oracle` when a strict anchored `/etc/passwd` root-line (uid/gid 0, 7 colon fields)
  surfaces. Bounded retained snippet → small certificate.

**Shipped as a LEAD (honest — confirmation is out-of-band), `inspect_request`.**
- **SSRF** — a value that is an internal / link-local / cloud-metadata-host URL or a dangerous
  non-HTTP scheme (`file`/`gopher`/`dict`/…).
- **XXE** — a request body whose DOCTYPE declares a `SYSTEM`/`PUBLIC` external entity.
- **Roadmap** to promote these to a proven BLOCK: the OOB block-path — reuse `verify/oob.py`'s
  `OOB_CALLBACK` oracle (mint a per-request correlation token, plant it in the payload, confirm on an
  inbound hit against the token). Deliberately NOT forced inline: a single response cannot prove the
  app dereferenced the resource near-zero-FP. A LEAD that can't be a near-zero-FP block is a success.

**Graduated challenge/throttle on per-actor belief (G5, `aegis/response_policy.py`).** The gateway's
inline `ActorGraph` accumulates a per-actor Beta belief; when its lower credible bound crosses a
SUSTAINED threshold (challenge at `lcb≥0.40`, throttle at `lcb≥0.50`, both needing `≥3` observations),
a sustained-suspicious actor gets an availability-first, retryable `challenge` then `throttle` (HTTP
429) — NEVER a hard block on belief alone (a fired oracle's certificate is the only thing that
blocks). Gated by enforce + `AEGIS_RESPOND`; observe only tracks. Provable blocks always win over a
belief-driven challenge; belief is fed exactly once per request with its strongest verdict.

**Header/cookie injection surface.** `candidate_values` also yields decoded Cookie values and a
bounded, curated allowlist of free-text request headers (`user-agent`, `referer`, `x-forwarded-*`,
…), so the request-side parse-proof oracles (`sqli_attempt`/`command_injection_attempt`) cover
header/cookie injection. Structured/hop-by-hop/credential headers are excluded; the near-zero-FP
oracles keep a normal `User-Agent` / `python-requests/2.25.1` / XFF IP list from tripping.
