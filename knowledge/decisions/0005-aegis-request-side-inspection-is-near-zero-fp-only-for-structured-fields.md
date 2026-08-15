# ADR 0005 — AEGIS request-side inspection is near-zero-FP ONLY for structured field values

- **Status:** Accepted (implemented; PR #334 + the reland #338)
- **Scope:** VIGIL AEGIS gateway (`engine/crucible/framework/v2/aegis/inspect.py`)
- **Tests:** `engine/crucible/framework/v2/aegis/tests/test_body_inspection.py`

## Context

AEGIS's inline gateway blocks a request only when a deterministic `verify/` oracle CONFIRMS an attack
over the request. Those request-side oracles (SQLi string-literal break-out, command-injection construct,
NoSQL operator-as-key) are **near-zero-FP by construction — but only for a single STRUCTURED injection
point**: a query param, a JSON leaf value, a cookie, a curated header. Their guarantee is that a *benign
value at a named injection point* does not carry injection syntax.

A change extended candidate extraction to body types that previously bypassed inspection entirely
(multipart/form-data, text/plain, XML). The red-pen proved this broke the invariant and produced FALSE
POSITIVES that block benign traffic in enforce mode:

- **text/plain** is the default `Content-Type` for `fetch(url, {body})` and `sendBeacon`. Feeding a whole
  multi-line document to the oracles means a benign note/comment containing a line like
  `cat /etc/os-release`, or prose quoting `'; DROP TABLE users; --`, becomes a **confirmed block**. The
  cmdi oracle treats `\n` as a shell separator — sound for one param value, wrong for a document.
- **XML** text-node extraction via regex mis-handles CDATA / comments / attributes with `>`, feeding
  malformed fragments to the oracles → benign XML blocks.
- The multi-line-value FP is **pre-existing** for query/urlencoded/JSON fields too (a multi-line
  urlencoded field already trips cmdi) — so it is a property of the oracle applied to multi-line values,
  not something a new body type may "inherit" onto a free-text surface.

## Decision

**Only structured, named injection points are inspected on the request side. Free-text/document bodies
are NOT.**

- **KEEP multipart/form-data**, at explicit PARITY with the existing urlencoded/JSON form surface — a
  multipart text field is the same named injection point, same oracle, same contract. It introduces no
  new FP class (a test asserts multipart and urlencoded give the identical verdict on the same value).
  FILE parts (a `filename`/`filename*` Content-Disposition param, matched by `_MULTIPART_FILENAME_RE` so
  `filename =` and RFC-5987 `filename*=` are caught) are skipped — their bytes are not a string surface.
  A field merely NAMED `filename` is still inspected (the regex is `;`-anchored to the param, not the
  name), or an attacker would evade by naming their field `filename`.
- **DROP text/plain and XML document bodies** from request-side extraction. They are free text, not a
  structured injection point; the near-zero-FP contract does not hold. The sound path to catch a payload
  posted as a raw body is **response-side confirmation** (does the app's own answer show exploitation) —
  the existing G4 response oracles — not request-side prose-matching. Named as future work, not forced.
- **Per-source starvation caps** (query 96 / body 96 / header+cookie 64, summing to the 256 global) so a
  flood of one surface (classically hundreds of junk query params) can never starve the others out of
  inspection.

## Consequences

- This is a **coverage** decision (which surfaces get inspected), not a change to the attack-class list.
  AEGIS request-side still confirms the same classes; it is not a general WAF (no IDOR/CSRF/auth-bypass;
  SSRF/XXE stay leads).
- The invariant to preserve forever: **do not hand a request-side oracle a whole multi-line/free-text
  body.** If you widen extraction again, widen it only to named structured fields, and add benign
  negative controls (a benign form, a benign text note, a benign XML doc, a hostile-looking file part)
  that assert `action != "block"`.
- **A false positive on a defensive gate is the cardinal AEGIS sin** — it drops a legitimate request to
  the operator's own app. It cannot be self-certified; it is caught by the near-zero-FP negative controls
  + the adversarial red-pen, and both are mandatory for any change to `inspect.py`.

## Operational footnote (how the pre-fix version reached main once)

The FP-fix and its re-check hardening were pushed to the PR branch *after* the PR had already been
merged (branch merged while review was still in flight; CI was down for a billing outage). The orphaned
fix commits never re-merged, so `main` briefly ran the FP-vulnerable version until it was re-landed as a
fresh PR. Lesson recorded in [`../sessions/`](../sessions/): a merged PR whose fixes were pushed
post-merge is silently stale — verify by CONTENT (grep the file in `origin/main`), not by the "merged"
label.
