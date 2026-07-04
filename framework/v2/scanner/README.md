# scanner — autonomous web-audit engine (Burp-parity track)

Burp Suite is a testing **engine** plus a **human operator**. CRUCIBLE already
has the operator's judgment layer (the `verify` oracles, `worldmodel`, `planner`,
`calibration`, governance). This package builds the engine and drives it with the
planner instead of a human, so the crawl→scan→confirm loop runs zero-manual.

## What ships here (complete, tested — not a scaffold)

- **`insertion.py` — the insertion-point engine.** `RequestTemplate` parses a raw
  HTTP request into *every* markable position Burp knows — URL path segments,
  query values and names, urlencoded-body values and names, cookies, request
  headers, and nested JSON values and keys — and renders a payload into exactly
  one point, rebuilding the request with correct percent-encoding, a corrected
  `Content-Length`, and everything else byte-preserved. Pure and deterministic;
  no network, no clock. This replaces the old single hardcoded-parameter probe.

- **`checks.py` — the active-check library.** A `Check` knows, for a bug class,
  what to place into one insertion point and how to shape the observed responses
  into a `verify.FindingContext`. Two strategies cover the oracle-observable
  classes: `DifferentialCheck` (boolean/logic diff → differential oracle) and
  `MarkerReflectionCheck` (unique canary → side-effect oracle). A check emits
  evidence; it never decides confirmation. Seed set: boolean-SQLi, reflected-XSS,
  SSTI/error-based reflection, path-traversal. Add a class by declaring a check —
  no new oracle needed.

- **`engine.py` — the audit engine.** `AuditEngine.audit(request, checks)`
  enumerates the insertion points, fires each check into each, and confirms via
  the deterministic oracle layer. A finding is emitted **only** when a real
  oracle signal fires — so every result is signal-anchored (the precision
  property Burp's Tentative/Firm heuristics lack). De-duplicated per
  (bug_class, point) and bounded by a request budget.

## The prove-don't-guess contract, generalised

The old confirmation path proved one thing on one parameter. This generalises it
to *N checks × M insertion points on a live target*, unchanged in principle: the
oracle — never the LLM, never a heuristic — is the confirmation authority. The
end-to-end test (`tests/test_engine_e2e.py`) drives a loopback target vulnerable
only on one parameter and confirms findings there and **nothing** on the safe
control.

## Boundary

The engine sends nothing itself: a `send` callable is injected. In production
that is the scope / charter / kill-switch / egress / rate-gated executor, so
authorization stays enforced; in tests it is a loopback client against an
operator-owned target. Payloads are verification probes (differential terms,
unique markers, traversal tokens), not weaponized exploits.

## What this unblocks next

A crawler to populate insertion targets from a live app, and the fuzzing
combinatorics + payload-processing + OOB producer that turn the remaining
oracle-routed bug classes into live producers. Each rides this same
insertion → check → oracle spine.
