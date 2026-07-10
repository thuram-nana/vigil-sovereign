# The two fingerprint stacks — design note & deferral record

*Wave 7-D — behavior-preserving hygiene. Status: **unification DEFERRED**, both stacks
retained. This note is the record of why.*

CRUCIBLE carries two independent technology-fingerprinting implementations. The Wave-7
roadmap flags them as "two fingerprint stacks" — apparent duplication worth reconciling.
This note is the result of investigating that: it maps what the two stacks share (little,
and only at the level of *shape* and *domain knowledge*), documents every way they diverge,
and records the decision to **keep both** because no part is provably-identical enough to
extract without moving the gate-locked scanner output.

## The two stacks

| | `scanner/fingerprint.py` | `intake/fingerprint/` |
|---|---|---|
| Role | Aims the **scan** — the check library gates on it | **Pre-scan** UTI intake classification |
| Consumers | `scanner/campaign.py`, `scanner/__init__.py`, `intel` | `intake/intake.py` → `stack_classifier` → scaffolding |
| On the gate path? | **Yes — output is benchmark-locked** | No |
| Input type | `scanner.passive.Response` | `intake.models.HTTPExchange` |
| Output type | `Fingerprint` / `TechMatch` (`scanner.fingerprint`) | `DetectionResult` / `Detection` → `Fingerprint` (`intake.models`) |

The scanner stack's output is consumed as `Fingerprint.tokens` + `matches_predicate(...)`
to decide, per check, `applies_when`. The regression gate is byte-locked to that behaviour:

```
crucible | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 | reqs 853 | found 9   → gate: PASS
```

Any change that moves `scanner.fingerprint`'s output can move which checks fire, which moves
that row. That is the invariant this deferral protects.

## Why they cannot be merged byte-identically

The two stacks share a *shape* — "a declarative table of signatures evaluated by a small
matching loop" — and overlapping *domain knowledge* (both know nginx, WordPress, Django,
Cloudflare…). But every concrete layer below that shape diverges, and each divergence is
output-affecting:

1. **Signature data model.**
   - scanner: `Signature(name, category, confidence, header|cookie|generator|path|body, note)`
     — exactly one matcher field is set (enforced at import by `_validate_library`); the
     matcher *kind* is encoded by *which field* is non-`None`.
   - intake: `Signature(label, where, name, pattern, confidence, evidence, category)` — the
     matcher kind is encoded by the `where` string, built via `hdr()/cookie()/body()/path()`.

2. **Matcher semantics** (the deepest divergence).
   - scanner: a header value is **always a regex** (`re.search(value_re, value, re.I)`, empty ⇒
     presence); `cookie` regexes match cookie **names** parsed from Set-Cookie/Cookie; `generator`
     regexes match `<meta name=generator>` content parsed with `html.parser`; `path` is a
     **literal lowercased substring** searched in the body *or any header value*; `body` is `re.search`.
   - intake: `_matches` treats a plain `str` pattern as a **case-insensitive substring** and a
     compiled `Pattern` as `.search()`; `cookie` matches an exact key of `ex.cookies` (plus a
     `name=` substring in Set-Cookie); `path` matches the **URL path component**; it also has
     `url` and `status` matchers the scanner has no equivalent for; generator detection is a
     raw-body regex, with **no HTML parsing**.

3. **Aggregation math.**
   - scanner `_merge`: one match per `(name, category)` = the **strongest** confidence, evidence
     unioned in first-seen order.
   - intake `evaluate`: **diminishing-returns** `confidence = 1 − Π(1 − cᵢ)` per label — multiple
     weak signals compound into a strong one.

4. **Capabilities present in only one stack.**
   - scanner-only: `IMPLICATIONS` (framework/CMS ⇒ runtime language), favicon hashing
     (`fingerprint_favicon`), the `matches_predicate` gating grammar, and a fixed `CATEGORIES` set.
   - intake-only: `auth` / `api` / `payment` categories, security-header detection
     (`hsts`, `csp`, `xfo`, …), and a much larger label set.

5. **Divergent canonical names for the same technology.** The two stacks disagree on the token
   they emit for identical tech: `next.js`/`nextjs`, `asp.net`/`aspnet`,
   `mod_security`/`modsecurity`, `imperva`/`incapsula`, `f5-big-ip`/`f5-bigip`, `java`/`javaee`.
   Reconciling the vocabulary **alone** would move at least one stack's output — and the scanner
   side of that vocabulary is exactly what the gate is locked to.

Even where the two agree most closely — WordPress via `<meta generator>`, both at confidence
`0.95` — the match *input* differs (parsed meta content vs. raw body), the regex differs, the
evidence string differs, and the aggregation differs. There is no row, helper, or constant that
is byte-for-byte identical across the two and safely extractable.

## Decision

**Defer the unification; retain both stacks.** The safe-extraction set is empty: there is no
provably-identical shared code or data whose extraction would leave `scanner.fingerprint`'s
output byte-identical. Wave-7's rule is explicit — a held-back item whose omission keeps the
scan-path output frozen is the correct outcome, not a failure.

No code under `scanner/fingerprint.py` or `intake/fingerprint/` is changed by this note; the
gate row above is therefore unchanged by construction.

## If someone unifies these later (a dedicated, gated change — not hygiene)

A real merge is possible but is a behaviour-*changing* project, not behaviour-preserving
cleanup. The safe sequence:

1. Define a neutral signature schema able to express both stacks' matchers (regex-vs-substring,
   header/cookie/generator/path/body/url/status) and both aggregation modes.
2. Reconcile the canonical-name vocabulary (pick one token per tech) — this *will* move intake
   output and possibly scanner output; treat it as a versioned change to both.
3. Port each stack onto the shared schema behind adapters, keeping each side's aggregation and
   input coercion.
4. **Before** cutting the scanner over, add a characterization/golden test that pins the current
   `scanner.fingerprint` output on a fixed corpus, and require it green across the cutover; run
   the benchmark gate and confirm the `crucible | 9 | 0 | 0 | … | 853 | 9` row is unchanged.

Until that dedicated work happens, the duplication is intentional and cheaper than the risk of
moving the gate.
