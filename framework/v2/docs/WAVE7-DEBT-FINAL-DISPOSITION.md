# Wave-7 debt — FINAL disposition (closeout)

*Wave 7-F — the Wave-7 closeout. For every item Wave-7 (`W7B-LIBRARY-CONSOLIDATION.md`,
`FINGERPRINT-STACKS.md`) recorded as debt or deferral, this note assigns a FINAL status:*

- **DONE** — completed in the Wave-7 body of work (which PR/commit).
- **COMPLETED-NOW** — completed byte-identically in this closeout.
- **PERMANENT-DEFERRAL** — provably cannot be completed without changing observable
  behaviour (moving the gate `reqs`/`found`, drifting a float, or losing coverage). Under
  Wave-7's rule a proven permanent deferral is a SUCCESS, not unfinished work.

The hard invariant across all of this is the regression gate, byte-identical before/after:

```
python3 -m framework.v2 benchmark --gate --no-incumbents
BEFORE: crucible | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 | 8.92 | 853 | 43.4 | 9   → gate: PASS
AFTER:  crucible | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 | 8.89 | 853 | 43.4 | 9   → gate: PASS
```

`tp/fp/fn`, `precision/recall/f1`, `reqs=853`, `found=9`, and `gate: PASS` are identical;
only `time_s` (wallclock, not part of the gate) and RSS jitter differ.

---

## Item-by-item

| # | Debt item | Source | FINAL status |
|---|-----------|--------|--------------|
| 1 | Remove the two legacy OOB JSON mirrors of code seeds (`command-injection-oob`, `blind-xxe-oob`) | W7-B | **DONE** (Wave-7 W7-B) |
| 2 | Remove `scanner/library_entries/ssrf.json` (`ssrf-oob`) | W7-B (deferred) | **COMPLETED-NOW** (this PR) |
| 3 | Collapse the two Beta learners into ONE function | nervous-system / W7 | **PERMANENT-DEFERRAL** (float non-associativity) |
| 4 | Collapse `DEFAULT_CHECKS ↔ JSON` request-sending duplicates (`boolean-sqli`, `reflected-xss`) | W7-B deferral (a) | **PERMANENT-DEFERRAL** (moves `reqs`) |
| 5 | Collapse injection micro-variant skew (per-DB / per-template-engine coverage matrix) | W7-B deferral (b) | **PERMANENT-DEFERRAL** (moves `reqs` / loses coverage) |
| 6 | Unify the two fingerprint stacks (`scanner/fingerprint.py` ↔ `intake/fingerprint/`) | Wave 7-D | **PERMANENT-DEFERRAL** (behaviour-changing; dedicated future effort) |

---

### 1 — Two legacy OOB JSON mirrors — DONE (Wave-7 W7-B)

`command_injection.json` (`command-injection-oob`) and `blind_xxe.json` (`blind-xxe-oob`)
were exact behavioural duplicates of the `RCE_OOB` / `XXE_OOB` code seeds and had no id
collision with any code seed (`rce-oob` / `xxe-oob`), so nothing looked them up. Removed in
the Wave-7 body; gate stayed `853 | 9`. No action here.

### 2 — `ssrf.json` (`ssrf-oob`) removal — COMPLETED-NOW (this PR)

**Why W7-B deferred it.** `ssrf.json`'s id `ssrf-oob` is *identical* to the `SSRF_OOB` code
seed's id, and `scanner/report.py::_meta_for` enriches a finding's report
severity/remediation/references by `check_id` (`lib.get(check_id)`). So this JSON was the
**report-metadata source** for out-of-band SSRF findings — it carried `CAPEC-664` and richer
remediation prose that the per-class fallback `_CLASS_META["ssrf"]` does not. A naive delete
would make `lib.get("ssrf-oob")` return `None`, fall through to `_CLASS_META["ssrf"]`, and
**silently drop CAPEC-664 and change the remediation text** on any `enable_oob=True` report.
The gate never fires it (gate runs OOB off), so the regression would have been silent.

**The byte-identical path taken.** Migrate that EXACT metadata into a new, **check-id-scoped**
map `scanner/report.py::_CHECK_META`, consulted in `_meta_for` **only when
`lib.get(check_id) is None`** (i.e. exactly when the JSON is gone) and **before** the per-class
fallback. It is keyed by `check_id`, not `bug_class`, so it can affect *only* the one check
that owns that id:

```python
_CHECK_META = {
    "ssrf-oob": ("High",
        "Do not let user input drive server-side fetches. Enforce an allowlist of permitted "
        "hosts/schemes, block requests to internal/link-local ranges and the cloud metadata "
        "endpoint, and disable unneeded URL schemes.",
        ["CWE-918", "CAPEC-664"]),
}
```

Then delete `scanner/library_entries/ssrf.json`.

**Proof of byte-identity (the exact test the task asked for).** An `ssrf-oob` `AuditFinding`
was rendered through `build_report` both ways — main (JSON present) vs this branch (JSON gone
+ `_CHECK_META`) — and the emitted `severity` / `references` / `remediation` diffed:

```
severity:    High                                  (unchanged)
references:  ["CWE-918", "CAPEC-664"]               (unchanged — CAPEC-664 retained)
remediation: "Do not let user input drive ...URL schemes."   (unchanged, byte-for-byte)
diff(before, after) == ∅   → BYTE-IDENTICAL
```

**No collateral change to other ssrf findings.** Because the map is `check_id`-scoped, a
*different* ssrf finding (any `check_id` with no library entry and not in `_CHECK_META`) still
falls through to `_CLASS_META["ssrf"]` exactly as before — verified in the same run:
`_meta_for("some-other-ssrf", "ssrf", …) == _CLASS_META["ssrf"]` (`["CWE-918"]`, the generic
prose), unchanged. This is the safer route the task flagged: `_CLASS_META["ssrf"]` itself was
**not** touched, so no other ssrf path can be affected.

**Gate.** `ssrf-oob` is an `oob` entry (0 requests when the gate runs `enable_oob=False` — the
engine hits `if self.oob is None: continue` before probing), and its bug class stays represented
by the `SSRF_OOB` code seed + the richer surviving OOB library entries (`m2-inj-ssrf-*`), so the
rank/order of request-sending checks is unchanged. Gate `853 | 9` before == after (above).

**Regression tests** (`scanner/tests/test_report_check_meta.py`): pin the migrated values to the
JSON's originals; assert `_meta_for("ssrf-oob", …)` over the live post-removal library returns
them; assert the map does not leak to other ssrf findings; assert the rendered report still
carries CAPEC-664 + prose; assert `_meta_for` returns a fresh list (mutation safety).
`scanner/tests/test_library.py` updated: `ssrf-oob` is now asserted **absent** from the library.

### 3 — Beta two-learner single-function collapse — PERMANENT-DEFERRAL

`common/beta.py` holds two forms of the same Beta(1,1) posterior mean:
`beta_mean(alpha, beta) = alpha/(alpha+beta)` (the bandit's rank key, canonical params) and
`beta_mean_from_counts(s, a) = (s+1)/(a+2)` (the `memory.priors` Laplace mean, raw counts).
"Collapse into one" means routing the count form through `beta_mean(s+1, (a-s)+1)`.

**Concrete float proof it cannot be done bit-identically.** The numerator `s+1` is identical;
the denominator is not. Direct form computes `a + 2` (one add); the reassociated form computes
`(s+1) + ((a-s)+1)`. IEEE-754 addition is not associative, so for fractional effective counts
these differ in the last bit(s). A sweep of 1830 fractional pairs `s,a ∈ {0.0…5.9}` found **159
that differ**, e.g.:

```
s=0.1, a=0.4:  direct=0.45833333333333337   reassociated=0.4583333333333333   (3 ULP)
               denom_direct = 2.4            denom_reassoc = 2.4000000000000004
s=0.1, a=1.7:  differ by 31 ULP
```

The shipped pair used by the guard test is `(s,a) = (1/7, 6/7)`, which also diverges.

**Why the last bit is load-bearing.** `memory.priors.SmoothedPrior` carries *fractional*
effective counts — transferred priors accumulate `succ += w * float(nb.successes)` — and
`beta_mean_from_counts` is its `.mean`, a **rank key**. A one-bit drift there could reorder
bandit arms and thus move the gate `reqs`. The two forms are therefore genuinely
non-interchangeable and must both exist. **Do not force this.**

**Regression guard (already in the suite):**
`common/tests/test_beta.py::test_count_form_denominator_is_not_reassociated` asserts
`beta_mean_from_counts(1/7,6/7) == (s+1)/(a+2)` **and** `!= beta_mean(s+1,(a-s)+1)` with exact
`==` — so any future attempt to collapse the helper fails the suite.

### 4 — `DEFAULT_CHECKS ↔ JSON` request-sending duplicates — PERMANENT-DEFERRAL

`boolean_sqli.json` (`boolean-sqli`, `differential`) and `reflected_xss.json` (`reflected-xss`,
`reflection`) each duplicate a code seed (`BOOLEAN_SQLI` / `REFLECTED_XSS`), but unlike the OOB
mirrors they are **request-sending** and **selected** on the gate. The roster is additive
(`active_checks = DEFAULT_CHECKS + selected_library`) and the engine de-dups only *after* a
confirmation, so at every non-confirming point BOTH the seed and the JSON entry send their
requests. Dropping either lowers `reqs` below 853. Converging them needs a source-of-truth
refactor (one runtime check per class on the `use_library` path) — a deliberate change to
request counts, out of scope for byte-identical hygiene. Permanent under the byte-identity rule.

### 5 — Injection micro-variant skew — PERMANENT-DEFERRAL

The library's exact-payload-duplicate groups (`m2-sqli-*-boolean-numeric` = `1 OR 1=1`;
`m2-ssti-{freemarker,generic,mako}` = `${31337*31337}`; etc.) are the per-DB-engine /
per-template-engine coverage matrix. Each selected variant is a **distinct request-sending**
check on the gate; collapsing a group to one entry removes requests and lowers `reqs`. The one
`oob` group (`m2-inj-ssrf-http-scheme` vs `m3-blind-ssrf-header-forwarded`) sends 0 requests but
carries *different* `insertion_kinds` (all points vs `header_value`) — collapsing it loses real
header-driven-SSRF coverage, i.e. it is not redundancy. Either way, not byte-identical-safe.
Permanent under the byte-identity rule; a real convergence is a coverage/behaviour change.

### 6 — Fingerprint stack unification — PERMANENT-DEFERRAL (dedicated future effort)

`FINGERPRINT-STACKS.md` establishes that `scanner/fingerprint.py` (on the gate path — its
`Fingerprint.tokens` + `matches_predicate` decide, per check, `applies_when`) and
`intake/fingerprint/` diverge at every concrete layer: signature data model, matcher semantics
(regex vs substring; parsed `<meta generator>` vs raw-body regex), aggregation math (strongest
vs diminishing-returns `1−Π(1−cᵢ)`), stack-only capabilities, and even canonical tech names
(`next.js`/`nextjs`, `asp.net`/`aspnet`, …). The safe-extraction set is empty: no row, helper,
or constant is byte-for-byte identical across the two and safely extractable, and the scanner
side's output is exactly what the gate is locked to. This is **not** a byte-identical closeout —
it is a versioned, behaviour-*changing* project (define a neutral schema, reconcile the
vocabulary, port behind adapters, add a characterization/golden test before cutover). It remains
a dedicated future effort; `scanner/fingerprint.py`'s output does not move here.

---

## What shipped in this closeout

- **Completed byte-identically:** `ssrf.json` removed; `scanner/report.py::_CHECK_META` added
  as the code-level, check-id-scoped metadata source for `ssrf-oob` (CAPEC-664 + prose retained).
- **Confirmed permanent (with proof):** Beta single-fn collapse (float non-associativity —
  159/1830 fractional pairs drift; guard test present), items 4 & 5 (move `reqs`), fingerprint
  unification (behaviour-changing, safe-extraction set empty).
- **Tests:** `scanner/tests/test_report_check_meta.py` added; `scanner/tests/test_library.py`
  updated (asserts `ssrf-oob` absent); Beta guard already in `common/tests/test_beta.py`.
- **Gate:** `crucible | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 | 853 | 9` — PASS, before == after.

## Residual risk

- `_CHECK_META` and the shipped `_CLASS_META["ssrf"]` prose are deliberately DISTINCT; the tests
  pin both and assert they differ, so a future edit that accidentally points `ssrf-oob` at the
  class fallback (re-dropping CAPEC-664) fails the suite.
- No other code path reads the library `ssrf-oob` entry: `_meta_for` is the sole `check_id`-keyed
  consumer; the OOB *detection* is owned by the `SSRF_OOB` code seed in `DEFAULT_CHECKS` (present
  on every `use_library` path) and the richer `m2-inj-ssrf-*` library entries (untouched).
