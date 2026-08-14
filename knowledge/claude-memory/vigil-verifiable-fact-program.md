---
name: vigil-verifiable-fact-program
description: "VIGIL VF program — portable verify-by-re-execution security facts (remediation cert, protocol, identity/capability); design-first after user critique"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-08-02T17:16:37.712Z
---

VIGIL **Verifiable Security Fact (VF)** program (repo thuram-nana/vigil-sovereign, @ /home/kali/vigil).
The world-first thesis: turn a security claim from an assertion-you-must-trust into a **portable object whose
truth a third party re-derives by re-execution** — witnessed, time-anchored, continuously re-proven, and (for
OOB classes) self-authenticating. Plan file: `/home/kali/.claude/plans/parsed-popping-lemur.md`.

**Trust gradient shipped on the tin (non-negotiable honesty):** (1) vs an HONEST producer — every verdict
re-derived by re-execution, tamper-evident, witnessed, time-bounded, continuously re-proven; (2) vs a
DISHONEST producer — only OOB-observable classes, via target's secret-token callback + independent collector;
(3) DEFERRED frontier (never claimed active) — general byte-authenticity vs a malicious producer = zkTLS/
TLSNotary. `live_redrive` is a DEAD provenance value (declared, zero producers) — do not claim live re-drive
exists until VF-1a driver is built.

**Critical user correction (design-first):** "primitives exist, rest is glue" was WRONG. The missing work is
real security engineering: a security protocol, formal state semantics, identity design, authorization design,
witness trust assumptions, negative-proof controls, and adversarial interoperability testing. Build design-first
(spec → reviewed code), not wiring.

MERGED so far:
- **#186** RemediationCertificate — portable verify-by-re-execution NEGATIVE proof (exploit that worked is now
  provably dead, earned by oracle SILENCE). `integration/vigil_integration/remediation/remediation_cert.py`.
- **#187** negative-proof controls (positive-control twin must still FIRE + liveness, signed into whole cert so
  none can be stripped) + state-semantics spec (`docs/proof-carrying-finding/REMEDIATION-SEMANTICS.md`).
- **#188** security PROTOCOL spec (`docs/proof-carrying-finding/PROTOCOL.md`) — parties/trust, object binding
  chain, 3 modes (R replay / L live-nonce / W witnessed), freshness, downgrade-resistance, capability model.
- **#189** adversarial CONFORMANCE corpus (`integration/tests/test_remediation_conformance.py`) — 13-vector
  labeled MUST-ACCEPT/MUST-REJECT matrix; foundation for the VF-1d VIGIL vs VIGIL-free differential.
- **#190** IDENTITY + CAPABILITY as real signed `vigil_core` objects (`packages/core/vigil_core/vigil_core/
  capability.py`): `IdentityAttestation` (owner-attested acceptable-identity policy; `identity_matches` =
  conjunctive-over-dimensions, any-of-within → anti-transplant), `Capability` (owner-minted, bound to identity
  by digest, class-allowlist, non_destructive, window, rate, revocation, audience), biscuit-style **narrow-only
  attenuable** (delegate down a chain, widen/reorder/wrong-signer refused), + `WielderProof` proof-of-possession
  and the one-call `authorize_reverification` gate. New domain tags identity/capability/attenuation/wielder-pop.

**Red-pen loop lesson (crypto-grade #190):** the RE-CHECK on the fixed branch caught what the first fix missed.
Pass1 HIGH = fail-OPEN default (`wielder_pubkey=None` skipped the check). Pass2 BLOCK = the "fix" was theater —
`audience` is a PUBLIC key in the inert bytes, so a bare `wielder==audience` string compare authenticates
nothing (thief copies it) AND the docstring OVERCLAIMED it. Pass3 PASS = real proof-of-possession (wielder
signs a fresh caller-supplied challenge bound to cap_digest with the audience PRIVATE key; verified against the
EFFECTIVE post-attenuation audience). Lesson: an authz "binding" over a value present in the bearer's own bytes
proves nothing — require a signature by a PRIVATE key. Challenge freshness is the caller's responsibility, stated
explicitly (parallel to `now` must come from a trusted clock). Run red-pen until it PASSes; never merge crypto
on the first green.

- **#192** VF-1a.1 prove-driver PROTOCOL CORE (`integration/vigil_integration/remediation/prove_driver.py`):
  the `vigil remediate --prove` orchestrator — four states REMEDIATED/STILL_VULNERABLE/INCONCLUSIVE/REFUSED
  (REFUSED=testing-must-not-begin vs INCONCLUSIVE=testing-happened-claim-not-earned), causal-chain freshness
  challenge, immutable EffectiveAuthorization + atomic budget, F0-F4 freshness (F2 VERIFIED from judged
  evidence, not adapter-asserted), identity sampled 4×, downgrade resistance, full signed causal-chain cert.
  Live side behind an injected `LiveTargetAdapter` (fake in tests). Built to the operator's detailed brief.

**prove-driver red-pen loop (5 rounds, the decisive-slice lesson):** the COMPOSITION layer is where soundness
breaks, exactly as the operator predicted. Each round found a real deeper defect: (1) fail-OPEN default
(wielder_pubkey=None skipped); (2) the "fix" was theater — `audience` is a PUBLIC key in the bearer's own
bytes, so a wielder==audience string-compare authenticates nothing → real PROOF-OF-POSSESSION (sign a fresh
challenge with the audience PRIVATE key); (3) certifiability used a PRIVATE taxonomy diverging from the
verifier → DERIVE from `canonical_bug_class`+`BUG_CLASS_ORACLES`; (4) "statistical=TIMING only" missed
CREDENTIAL_STUFFING (SPRT over a sampled campaign) — but NOT boolean_inference (deterministic per-round);
(5) a BLOCKLIST of non-deterministic kinds fails UNSAFE (missed request_smuggling desync + prompt_injection's
stochastic LLM channel) → INVERT to a fail-CLOSED ALLOWLIST of audited deterministic-per-observation oracle
kinds + a race/desync phenomenon guard. Round-5 PASS/converged. KEY PRINCIPLES: oracle silence is a sound
negative iff a present vuln CERTAINLY re-fires a comparable honest re-drive (deterministic per-observation over
a reliable channel); for a security gate, ALLOWLIST beats blocklist (unaudited defaults safe); the liveness
heuristic must key on TARGET-produced fields (a `{connected:False}` capture dict is NOT "answered"); the
positive-control fire is load-bearing for boolean/oob silence.

- **#193** VF-1a.2 REAL live-HTTP re-drive adapter (`integration/vigil_integration/remediation/live_adapter.py`
  `LiveHttpAdapter`): re-drives the original exploit through CRUCIBLE's gated `HttpExecutor.gated_fetch` against a
  genuine stdlib loopback server (real sockets, signed in-scope charter — gate ENFORCED not bypassed); the
  original oracle re-fires over the FRESH wire bytes → all four states (patched→REMEDIATED w/ verifying
  cross-bound cert, vulnerable→STILL_VULNERABLE, down/no-echo→INCONCLUSIVE, expired-cap→REFUSED). GOTCHA: the
  Kali-tool `executor.execute` can't capture HTTP bodies (use CRUCIBLE `HttpExecutor.gated_fetch`); the original
  REQUEST is NOT retained (only response-side ctx) → positive control = the RETAINED original firing bytes
  (harness-capability only); `pytest_httpserver` absent in `.venv-offense` → stdlib `http.server`. Red-pen PASS
  (can't-fabricate-REMEDIATED + gate enforced held) + 4 LOW honesty notes ALL FIXED: **the freshness nonce on a
  SEPARATE param proves F1 (responsive) NOT F2 (exploit-path traversed)** — a reflect-only edge/WAF/down-origin
  gateway can yield REMEDIATED@F1, disclosed; a verifier requiring F2 gets INCONCLUSIVE (honesty enforced not
  hidden). LIVE positive control + genuine F2 = the VF-1a.3 follow-up. LESSON: honest freshness LABELING (F1 vs
  F2) is the operator's F0-F4 point — a bare nonce echo ≠ vulnerable-path exercised; never overclaim the level.

- **#194** VF-1a `vigil remediate --prove` CLI (`_cmd_remediate` in `integration/vigil_integration/cli.py`):
  operator-facing four-state live remediation proof. Loads a provenance-grounded finding (signed spine/envelope,
  never raw JSON), reads the retained positive control + channel from `proofs/reverifiable.json`, reconstructs
  the exploit request (fail-closed — refuses if not retained), re-drives live via LiveHttpAdapter, prints the
  four states + writes the signed cert + inline-re-verifies (a REMEDIATED that doesn't re-verify → non-zero).
  Downgrade-resistant (`--prove` only; no skip flags). Red-pen BLOCK: the sole-entry fallback in
  `_match_reverifiable_entry` substituted ANOTHER finding's positive control (→false REMEDIATED) → fixed to
  require an EXACT check_id match when a ref is known; re-check LOW: empty-ref spine fact reached the same path →
  `_cmd_remediate` now refuses an empty finding ref. HONEST LIMIT: the error_signature translator doesn't retain
  the request-side value, so the CLI refuses unless the reverifiable entry carries request_payload/payload_param
  (persisting the request side in `proof/run.py` = follow-up); reverifiable.json is trusted-AS-LOCAL (unsigned).

**VF-1a COMPLETE end-to-end (core → live adapter → CLI).** LESSON: even the CLI PLUMBING had a real
provenance BLOCK (cross-finding control substitution) the adversarial pass caught — never skip red-pen on
"just wiring." A blocklist fails unsafe; an allowlist + exact-match + fail-closed is the robust shape.

- **#195** VF-2a OOB token verification (dishonest-producer tier, MERGED). `oob_callback_oracle(hits,
  expected_token)` in `engine/crucible/framework/v2/verify/oracles.py` ~1439 now fires ONLY when a hit's token
  EQUALS the finding's registered per-finding secret (constant-time hmac.compare_digest); fail-closed with no
  registered token. The token is retained on the context (`FindingContext.oob_token` in `verify/adapter.py`;
  producer threads it at `scanner/checks.py` ~280 `from_oob(expected_token=token)`; verifier passes
  `ctx.get("oob_token")` ~677) → offline re-verify enforces it too (closed the gap where a fabricated
  reverifiable.json re-confirmed). Red-pen PASS. HONEST LIMIT (in the oracle docstring): token-equality defeats
  a fabricated/unrelated callback but NOT a fully-dishonest producer who forges the whole context → that needs
  VF-2b. Legacy tokenless OOB contexts now correctly INDETERMINATE on re-verify (demote-only hardening).

- **#196** VF-2b INDEPENDENT receipt-signing OOB collector (MERGED, F4 — the dishonest-producer defeat).
  `OOBReceiver(collector_keypair=...)` (`engine/crucible/framework/v2/verify/oob.py`) signs each observed hit's
  receipt core `{token, client_ip, received_at, method, path}` (domain `vigil-oob-receipt-v1`) with ITS OWN key
  as it observes it; `verify_oob_receipt(hit, collector_pubkey=PIN)` checks it against a caller-PINNED collector
  key (OUT-OF-BAND — a key from the producer context is void). `oob_callback_oracle(hits, expected_token,
  collector_pubkey=None)` gains an F4 gate: pinned key → token-match AND verifying receipt required; `None` =
  VF-2a token-only tier; empty pin = F4-requested-fail-closed. Red-pen PASS (no forge/replay without the key;
  binds all 5 fields; pin discipline enforced; weak-key rejected). HONEST BOUNDARY (in code): collector
  INDEPENDENCE is a deployment assumption; F4 is a caller-pinned capability, NOT enforced on the default
  engage/scan/verify gate (no out-of-band pin there) — wiring the pin into the prove-driver F4 floor is the
  follow-up. LESSON: the pinned key must be OUT-OF-BAND (like the PCF trust-root fingerprint); a receipt whose
  verifying key rides in the producer-controlled context proves nothing.

**BOTH TRUST-GRADIENT TIERS REALIZED:** tier-1 (honest producer) = VF-1a live re-drive; tier-2 (dishonest
producer, OOB classes) = VF-2a token + VF-2b independent signed receipt. Deferred frontier (never claimed
active) = general byte-authenticity vs a malicious producer for arbitrary classes (zkTLS).

- **#197** VF-2c observed-TLS-SPKI target binding (MERGED). `tls_spki_sha256(cert_der)` in `verify/tls.py`
  (leaf SPKI DER hash) wired into `capture_tls_handshake`; `live_adapter.identity_sample()` returns the observed
  `tls_spki_sha256` alongside `host` for HTTPS (same gated handshake reachability uses); the owner's
  IdentityAttestation policy pins acceptable SPKI(s) → a different key → REFUSED (anti-transplant). Red-pen PASS
  (two-key anti-transplant proven; all 10 gate-refusal strings classify REFUSE; no SPKI fabrication; HTTP gated
  fetch runs first). Honest limit: binds WHICH KEY answered, not byte-authenticity (channel-binding deferred).
- **#198** VF-1b Continuous Attestation Log (MERGED — "continuously re-proven"). `vigil_core/highwater.py`
  (namespace-pure durable floor: entry_count PRIMARY monotonic guard, upward-only advance under flock, re-load
  inside lock, corrupt→fail-closed, bool-rejected) + `integration/.../remediation/attestation_log.py`
  (`append_tick` admits only an authentic prove-cert then rebuilds+signs the chain, verify_head(prev_highwater)
  + check_highwater BEFORE persist, floor advanced LAST; `verify_log` rebinds head↔rebuilt-chain + floor +
  re-verifies EVERY tick; series present→proven-fixed→still-proven→regressed). Red-pen BLOCK (verify_log's
  empty-log short-circuit returned True BEFORE loading the floor → N→0/1→0 truncation accepted as clean) →
  FIXED: load floor first; empty log + floor entry_count>0 = rollback. LESSON: an empty log is validly "empty"
  to the in-band signature — the DURABLE FLOOR is the only catch for a FULL truncation; consult it before any
  empty short-circuit.

- **#199** VF-1c witnessed, time-bounded checkpoint (MERGED — out-of-band anti-rollback + no-later-than-T).
  `integration/.../remediation/attestation_witness.py`: a TIMED layer atop the merged transparency primitives
  (reuses `is_split_view_resistant` exactly). Each witness folds its observed time τ into a sig under a DISTINCT
  domain `vigil-attestation-witness-time-v1` (timeless↔timed non-interchangeable). `verify_timed_witnessed`:
  split-view-resistant gate → per-sig verify w/ decoded-key dedup (unknown/weak/MALFORMED ignored, never
  crashes) → distinct-verifying ≥ threshold (raisable via `min_distinct_signers` toward n) → no-later-than T =
  median(n//2). Red-pen BLOCK (verify_one outside try/except → a malformed sig CRASHED the offline verifier) +
  HIGH (the "majority of WITNESSES" claim overclaimed — a dishonest PRODUCER CURATES the presented sigs, so
  only the SIGNING quorum's honest-majority matters; a roster minority floor(t/2)+1 can shift T) → BOTH FIXED
  (guard verify_one; min_distinct_signers knob; corrected docstring/reason/WITNESS-TRUST §4 — the clock bound is
  STRICTLY WEAKER than non-equivocation; hard time → external RFC3161/OTS anchor §5). LESSON: T's soundness is
  over the PRESENTED signing quorum (producer-curated), not the roster.

- **#200** VF-1d standalone VIGIL-free differential verifier (MERGED — the capstone). `docs/proof-carrying-
  finding/verify_vf.py`: stdlib + cryptography ONLY (`--prove-standalone` asserts vigil unimportable — blocklist
  names the REAL packages incl. `vigil_gateway`). Re-derives the WHOLE lifecycle offline (prove-cert →
  attestation series → witnessed checkpoint): both canonicalizers (ensure_ascii False for most, True for the
  embedded rem-cert — pinned on a NON-ASCII payload), 4 domain tags, m-of-n + weak-key blocklist,
  version-conditional chain head + anti-rollback, split-view-resistant timed-witness quorum + median T.
  Differential test: standalone verdict EQUALS VIGIL verdict on 34 tamper rows + byte-parity + a stripped-env
  subprocess run. Red-pen PASS. DOCUMENTED BOUNDARY (honest): verify_vf checks signatures/binding/structure,
  NEVER re-fires the oracle (framework-only) — a governance-signed REMEDIATED whose embedded ctx would NOT
  re-fire silent is accepted standalone but rejected by VIGIL; the test excludes that one case + no standalone
  string says "remediated/silent".

- **#201** VF-3 the CAPSTONE — end-to-end lifecycle demo + EXPLICIT trust-gradient doc (MERGED). (A)
  `integration/tests/test_vf_end_to_end.py`: ONE test walking the WHOLE lifecycle against a REAL loopback target
  and handing every artifact to the STANDALONE verifier — vulnerable→STILL_VULNERABLE (presence, tick 0);
  patched→REMEDIATED (live re-drive, oracle silent, F1, cross-bound cert, tick 1); patched again→REMEDIATED
  (tick 2); verify_log series present→proven-fixed→still-proven; a 2-of-3 strict-majority witness quorum (full
  roster demanded, min_distinct_signers=3) → no-later-than T=median=2000; then `verify_vf.verify_bundle` (ZERO
  vigil code, OOB-pinned roots) CONFIRMS the whole bundle AND each layer, then REJECTS every tamper (flip state /
  truncate a tick / drop a witness sig). (B) `docs/proof-carrying-finding/TRUST-GRADIENT.md` — the operator's
  locked "state the trust gradient explicitly": three tiers, each property with the code that enforces it + the
  assumption/attacker that breaks it, no overclaim. **Red-pen caught a real BLOCK in the honesty artifact
  itself:** the "bound to THE target / OBSERVED TLS SPKI / not transplantable" row was stated UNIVERSALLY, but
  `live_adapter.identity_sample` records `tls_spki_sha256` ONLY for https — a plain-HTTP target degrades to
  host-only (transplantable across same-host), and the flagship demo runs over HTTP loopback so it never calls
  `tls_spki_sha256` at all. FIXED (doc-only; code already honest): row qualified SPKI-strong-for-HTTPS/host-only-
  for-HTTP + a new Tier-1 honest-limit stating the http→host-only degradation + that the demo never exercises
  SPKI. LOW: demo's "3-of-3" print label corrected to "2-of-3 strict-majority, full roster demanded". LESSON:
  red-pen the HONESTY DOC as hard as the code — an overclaim in the trust-gradient doc, where "honesty IS the
  product", is itself a BLOCK; a universal property claim must carry the protocol/transport precondition the code
  actually requires.

- **#202** VF-1a.3 genuine F2 (nonce through the exploit path) + LIVE positive control — AND fixed a #192 F2
  overclaim (MERGED). (1) `LiveHttpAdapter.payload_template` ("...{challenge}...", str.replace not str.format —
  literal-brace safe) weaves the run challenge INTO the exploit payload; the driver credits F2 ONLY when the
  trial FIRES **and** the challenge is reflected IN the matched datastore-error LINE (`_challenge_in_firing_
  signature` calls `error_signature_oracle` ITSELF to locate the match — never a duplicated signature list — then
  same-line containment). (2) **Fixed a #192 overclaim (operator-confirmed reclassification):** #192 credited
  F2_PATH_TRAVERSED to a REMEDIATED (SILENT) verdict from a merely-reflected nonce — but reflection≠sink-
  traversal (an echoer/edge fakes it), contradicting the operator's "a bare nonce echo ≠ vulnerable code path
  exercised." Silent now caps at F1; an F2-demanding verifier of a remediation → INCONCLUSIVE (sink-traversal
  unprovable once the sink is gone). (3) `run_positive_control` is now a REAL gated fetch this run (channel
  exercised live, not asserted from retained bytes). **F2 is honestly "as attributable as the error_signature
  oracle's own firing" — NOT byte-unforgeable (that's the OOB Tier-2/zkTLS frontier).** RESIDUALS disclosed +
  tested (never a false-strong F2 → INCONCLUSIVE under an F2 floor): payload-discriminating WAF + param-stripping
  edge fronting a request-echoing gateway. **Red-pen dual-pass caught a real BLOCK + HIGH + LOW, ALL from ONE
  root cause it named: both new closures inferred a CAUSAL property (sink processed the nonce / app received the
  param) from a POSITIONAL fact (bytes present SOMEWHERE in the response).** BLOCK = `require_injectable_param_
  live` yielded a FALSE REMEDIATED over a still-vulnerable origin behind a request-reflecting edge (`marker in
  body` can't tell app- from edge-reflection) → flag REMOVED, `injectable_param_live` demoted to informational-
  only, case moved to the deferred frontier. HIGH = F2 was `fired-anywhere ∧ challenge-anywhere` (decoupled) →
  a static error-banner + separate-line reflection forged STILL_VULNERABLE@F2 → same-line-with-the-matched-
  signature gate. LOW + a THIRD-pass stale-comment catch (a comment above the fixed gate still reasserted
  "unforgeable proof the sink processed it" + the OLD decoupled semantics). LESSON: **a positional fact (bytes
  present) is not a causal proof (came through the sink / reached the app); dress it as one and it forges;** and
  the honesty sweep must include INLINE COMMENTS sitting on the corrected code, not just docstrings + docs.

- **#203** VF differential-remediation SPEC (design-first, docs-only, MERGED — NO code yet). `docs/proof-
  carrying-finding/DIFFERENTIAL-REMEDIATION.md`: the plan to narrow the silent-case interposer residual with a
  MATCHED-DECOY DIFFERENTIAL — a metachar-identical DATA-DEPENDENT boolean true/false pair (a content WAF can't
  treat differently) judged by the EXISTING `boolean_inference_oracle` ((true≠false)∧(false_a≈false_b) under
  SPRT) + a mandatory baseline WAF-closure test + a decisive-SPRT-REFUTE requirement. **Design-first review
  earned its keep BEFORE any code: red-pen caught a BLOCK + 4 HIGH + 2 LOW in the DESIGN.** BLOCK = an in-flight
  SANITIZING interposer (escapes quotes, doesn't block) → origin sees inert data → false REMEDIATED
  indistinguishable from a fix (my "impossible" claim was wrong) → residual SPLIT: (a-block) blocking WAF CLOSED,
  (a-sanitize) sanitizing NOT (disclosed, pinned as a test). HIGH-1 (2 passes) = constant clauses `'c'='c'` are
  forgeable by a SQL-parsing interposer → DATA-DEPENDENT clauses; then even those are LEXICALLY forgeable by a
  non-executing interposer over plaintext HTTP → the firing is NOT interposer-unforgeable, only a SAFE
  over-approximation (a forged firing over-reports STILL_VULNERABLE, NEVER a false REMEDIATED). HIGH-2 = F2 not
  deliverable (the merged `_challenge_in_firing_signature` is error-channel-specific → caps a differential firing
  to F1) → new verifier needed. HIGH-3 = SPRT inconclusive≠refute (minting REMEDIATED on a non-decision is
  fail-open). HIGH-4 = discriminator scope (boolean=lexical / closure=status+structural) + oracle silently skips
  malformed rounds → adapter must fail-close. LESSON: **design-first review catches soundness holes for the cost
  of a doc edit, not a revert; a "matched decoy" only defeats a BLOCKING interposer — a SANITIZING one lets the
  probe through as inert data; and over plaintext HTTP probes are always lexically separable so a differential is
  never interposer-unforgeable (only a safe over-approximation in the STILL_VULNERABLE direction).** STATUS:
  spec merged; IMPLEMENTATION (adapter+driver channel+new F2 verifier) **DEFERRED per operator** (2026-08-02) —
  honest scope is narrow (closes only the blocking-WAF sub-case; sanitizing-WAF/param-strip/byte-forgery stay
  open), so the spec captures the design and the residual stays disclosed in TRUST-GRADIENT.md; revisit if the
  threat model puts blocking-WAF-fronted origins in scope.

**VF PROGRAM COMPLETE — flagship + standalone verifier + end-to-end demo + explicit trust-gradient docs + F2**
(18 PRs #186-202; every crypto/composition slice red-penned to convergence — the dual/triple-pass red-pen caught
a real defect on nearly every one). All trust-gradient properties realized & honestly bounded: re-execution ·
portable · live-vs-real · dishonest-producer(OOB) · observed-target-binding (HTTPS-strong/HTTP-host-only) ·
continuously-re-proven · witnessed+time-anchored · third-party-re-derivable-with-ZERO-vigil-code · genuine F2 for
the firing case (as-attributable-as-the-oracle). Deferred frontier (NEVER claimed active): general byte-
authenticity vs a malicious producer (zkTLS/TLSNotary), the RFC3161/OTS external time anchor, and — for the
SILENT case — a matched-decoy differential to tell a payload-discriminating WAF / request-echoing edge from a
real fix (both cap to INCONCLUSIVE under an F2 floor today, never a false-strong verdict).

Repo policy: NO `Co-Authored-By: Claude` ([[vigil-authorship-contributors]]). Never overclaim beyond the
deterministic layer. See [[vigil-government-complete-program]] (the prior, completed A/B/L/P/C program).
