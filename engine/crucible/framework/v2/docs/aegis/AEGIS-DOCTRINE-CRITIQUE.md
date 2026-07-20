I have enough grounding in the real code to render the verdict. Here's my critique.

---

# AEGIS — Doctrine & Safety Review

Grounded against the actual moat: `verify/verifier.py`, `veracity/firewall.py`, `intel/project.py`, `verify/reverify.py`, `verify/models.py`, `Makefile`. The reuse claims are broadly accurate — `admit()` genuinely only-demotes (`firewall.py:105`, re-executes each ground bound to the claim's own `bug_class`), `reverify_context(verifier=None)` genuinely replays offline against the default `OracleVerifier` (`reverify.py:95`), `require_known_bug_class` genuinely parse-rejects OOV classes (`verifier.py:205`), and `project_observation` is genuinely order-independent (`project.py:39`, commutative Beta). The design's spine is sound. The problems are at the edges.

## (a) Anti-defender / offensive / evasion drift

**Mostly clean, one real exposure.** The adapter-as-translator framing holds, default `mode="observe"` is read-only, and nothing acts without riding `invoke_tool`. But:

**D1 — Enforce-mode actions on spoofable actor-refs are a false-attribution DoS.** `ActorRef{ip_hash, session, principal}` is attacker-controllable (X-Forwarded-For, session fixation, submitted username_hash). In `enforce` mode a `throttle`/`block` keyed on a belief lets attacker A poison the belief for victim B's actor-ref and get B blocked — the SDK becomes a weapon against the operator's own users. The roadmap (§7.7) adds these actions without gating on proof.
*Fix:* Any enforce action must require `decision=="confirmed"` (a live certificate), never a LEAD or a bare belief. Document actor-ref as untrusted/spoofable; bind enforce to the strongest available identity and rate-limit self-throttle. Keep §7.7's actions permanently behind the `aegis.respond` entitlement + confirmed-only precondition, asserted in a test.

## (b) Prove-don't-guess violations

**Two overclaims where the oracle proves less than the label asserts.**

**P1 — The honeypot oracle confirms *automation*, not *attack*.** §6.7 emits `decision="confirmed", attack_class="automated_scraping"` on any fetch of the hidden robots-disallowed path. Set-membership over retained paths only proves *a non-interactive client fetched a resource no human UI links* — which is also true of link-unfurl bots (Slack/Twitter/iMessage previews), browser speculative-prefetch, corporate proxies, AV URL scanners, and the operator's own uptime monitors. Calling that a confirmed *scraping attack* is exactly the "AI detects AI" overclaim the doctrine forbids, and it will generate confirmed-tier FPs on benign automation.
*Fix:* The confirmed `attack_class` must be the proven fact — `automated_access` / `honeypot_fetch` (add as its own known_bug_class). "Adversarial scraping" stays a LEAD unless corroborated (e.g., honeypot hit **and** JA4↔UA contradiction **and** rate). Ship an operator allowlist for known-good crawlers/monitors so their fetches are polarity-REFUTES, not confirmations.

**P2 — Canary-in-output proves *leakage occurred*, not *injection caused it*.** The certificate for class 1 confirms the sentinel appeared in output. That is a real security event, but attributing it to `prompt_injection` (an adversarial *cause*) is stronger than the substring oracle proves — the app's own debug path echoing the system prompt, or a benign user asking "repeat your instructions," produces the same substring. The design already has the honest tool (control-vs-treatment behavior-delta, `evaluation_oracle` at `oracles.py:840`); the canary-substring-alone path skips it.
*Fix:* `attack_class="system_prompt_disclosure"` for the canary-substring-only certificate (proven: the secret leaked); reserve `prompt_injection` for the control-vs-treatment path where an injected directive provably flipped behavior vs. a control turn. Require the canary to be a high-entropy random sentinel (collision-resistant) so a substring match can't be coincidental.

## (c) PII / untrusted-input / privacy

**Three concrete issues.**

**PR1 — The `canary_ids`-only claim is internally inconsistent, and the honest version stores plaintext.** §3.2 says "AEGIS receives only `system_prompt_id` + `canary_ids` + observed output — so the oracle re-fires deterministically without AEGIS ever storing the operator's prompt." A substring oracle cannot match a canary it doesn't hold — an *id* is not matchable, and `reverify_context` (`reverify.py:95`) re-runs over the retained `oracle_context`, which for `side_effect`/`evaluation` oracles must contain the **verbatim** marker + observed span (`verifier.py:_run` requires `marker`+`observed_sink` strings). So the certificate necessarily retains the canary sentinel value and the matched output span *in plaintext* — contradicting both "AEGIS never stores it" and §5's `retain="hashes"`. Hashes cannot substring-match; the reverify contract forces plaintext here.
*Fix:* State plainly that class 1's certificate retains (a) the random sentinel value and (b) a bounded, PII-redacted matched span — plaintext, because the oracle needs verbatim substrings to re-fire. Justify it: the sentinel is a dedicated random token (not proprietary prompt text), rotated, and the span is minimized/redacted. Drop the "only hashes survive" claim for class 1.

**PR2 — Unsalted `ip_hash` is not anonymization.** IPv4 is 32 bits; an unkeyed hash is brute-forceable in seconds (full rainbow table is trivial). §5's "hashed IPs, no raw IPs" gives a false privacy guarantee (and fails GDPR's pseudonymization bar).
*Fix:* Use a keyed HMAC with a per-deployment secret (or truncation to /24-equivalent) for all identifier hashing; rotate the key; document that the hash is pseudonymous-under-key, reversible without it.

**PR3 — AEGIS inspects untrusted content it must not be injectable by.** Correctly noted in §5, but the boundary must also cover the *canary-match and marker-regex path*: attacker-controlled model output feeds the substring/regex oracles. Ensure regex is bounded (no catastrophic backtracking on adversarial input — a ReDoS DoS vector on the operator's request path) and the reverify cache key (`reverify.py:_cache_key`, canonical JSON) can't be poisoned by non-serializable content (it already falls back to live re-fire — good).
*Fix:* Add ReDoS-safe (linear) matchers for the structural-override markers; cap output-span length before regex; add a test with an adversarial output payload targeting the matcher.

## (d) Additive / default-safe / byte-identical on `make gate`

**One real GO-blocking gap — the design's own test does not cover it.**

**G1 — Appending members to the shared `OracleKind` enum silently changes the unknown-class fallback.** `_ALL_ORACLES = tuple(OracleKind)` (`verifier.py:165`), and `oracles_for` returns `_ALL_ORACLES` for any class not in `BUG_CLASS_ORACLES` (`verifier.py:235`). §4.2 / `registry.py` propose "new OracleKind members." The moment those are added to the enum, `_ALL_ORACLES` grows, so **every unknown-class finding in the benchmark now runs the AEGIS oracles** — they skip for lack of inputs, but they land in `confirm()`'s `skipped` list and in `_rationale(...)`'s enumerated `kinds`. If the gate/benchmark JSON serializes rationale or oracle sets per finding, output is **not** byte-identical. The design's `test_gate_byte_identical.py` only checks `oracles_for()` for *pre-existing known* classes (which read from the unchanged `BUG_CLASS_ORACLES.get()`) — it never checks the `_ALL_ORACLES` fallback, so the test would pass while the gate output drifts.
*Fix:* Keep AEGIS oracle kinds **out of the unknown-class fallback**: either give AEGIS its own enum/verifier subclass, or freeze `_ALL_ORACLES` to the pre-AEGIS member tuple explicitly (not `tuple(OracleKind)`). Extend `test_gate_byte_identical.py` to assert `_ALL_ORACLES` and `oracles_for("<some-unknown-class>")` are identical before/after `import aegis`. (The metric-only gate may absorb this, but the design *asserts byte-identical JSON* — hold it to that.)

**G2 — `known_bug_classes()` unions `frozenset(BUG_CLASS_ORACLES) | _ALIASES | ...` (`verifier.py:190`).** Adding AEGIS rows to `BUG_CLASS_ORACLES` grows this set — intended and fine — but confirm the growth is *exactly* the AEGIS classes and that no pre-existing alias now normalizes into an AEGIS class. Add that assertion (design mentions "grew by exactly the AEGIS classes" — make it enumerate them).

## (e) Overclaimed detectability / hype

**Largely honest — the threat-model table's LEAD/CONFIRMED split is the design's best feature.** Classes 6/7/9 are correctly held as permanent LEADs, and saying so is genuinely the product. The two remaining overclaims are P1 (honeypot = "attack") and P2 (canary = "injection") above; fixing those makes the catalog honest. One residual: §2 rates class 4 agentic-scraping detectability "Medium/confirmed-via-honeypot" — after P1's fix, the *confirmed* cell is "automated access," not "scraping," so soften the headline accordingly.

---

## Verdict: **REVISE** (small, bounded — not a redesign)

The architecture is doctrine-sound and the moat reuse is real. But the first-build slice ships two confirmed-tier overclaims (P1 honeypot=attack, P2 canary=injection), one internally-contradictory privacy claim that the reverify contract actually forces open (PR1), a weak-anonymization claim (PR2), and one byte-identical gap the design's own test misses (G1). None require rearchitecting; all are relabeling, a retention-honesty edit, a keyed-hash, and a frozen-fallback + one extra assertion.

**Gating fixes required before GO on the MVP:**
1. **G1** — freeze `_ALL_ORACLES` / isolate AEGIS oracle kinds from the unknown-class fallback; test the fallback path, not just known classes.
2. **P1** — confirmed honeypot class = `automated_access`, not `automated_scraping`; add crawler/monitor allowlist (polarity-REFUTES).
3. **P2** — canary-substring-only ⇒ `system_prompt_disclosure`; reserve `prompt_injection` for the behavior-delta path; high-entropy sentinel.
4. **PR1** — replace "only hashes survive / never stores the canary" with the honest "class-1 cert retains the random sentinel + a redacted matched span in plaintext, because the oracle re-fires on verbatim substrings."
5. **PR2** — keyed HMAC (not bare hash) for all identifier pseudonymization.

**Non-gating (roadmap):** D1 (confirmed-only precondition on any enforce action) before §7.7 ships; PR3 (ReDoS-safe matchers) with the class-1 oracle.