# W16-STD-1 — Insertion coverage, WHATWG encoding conformance, and the negatives-capable count

Status: implemented (falsifiable core). Programme: W16-STD (coverage / CLEAN gaps).

The live web re-drive used to build a bare GET template, so it only ever probed the URL query and path. A
redirect reachable ONLY from a cookie, a urlencoded body, or a JSON body was never probed — invisible to
adjudication, which reads to a consumer as "nothing there", and let the clean-capable redirect header
branches assert a CLEAN that was a latent false-CLEAN. This slice closes that gap for `open_redirect`,
pins the WHATWG charset determination with a conformance corpus, and pins the count of branches that may
assert a bounded negative.

## Insertion coverage

<!-- CLAIM:W16-STD-1a -->
The live web re-drive probes redirect parameters across five insertion surfaces (URL query value, URL path
segment, Cookie value, urlencoded-body value and JSON-body value), synthesising the cookie, urlencoded and
JSON carriers with the correct method and Content-Type, so a redirect reachable ONLY from a cookie,
urlencoded body or JSON body is found and minted as a signed FACT, and a clean target's CLEAN is bounded to
the named insertion surfaces.

The synthesised carriers live in `integration/vigil_integration/live/web_redrive.py:_redirect_templates`; the
`OpenRedirectCheck` predicate is surface-agnostic and fires only on a real navigation to the unique canary
HOST, so no benign-twin baseline is needed for soundness. A CLEAN over the synthesised cookie/body surfaces
is bounded to the probed candidate redirect-parameter names (the URL's own query names plus a small fixed
set), which the `WebRedriveResult.coverage_statement` names explicitly.

## WHATWG encoding determination + conformance corpus

<!-- CLAIM:W16-STD-1b -->
The WHATWG charset determination is a fixed label table, not a regex, pinned by an independent conformance
corpus: every label resolves to the byte-faithful codec the WHATWG Encoding Standard prescribes or is refused
as INCONCLUSIVE, labels a browser rejects such as utf-7 and EBCDIC are refused rather than decoded, and the
latin1 family resolves to windows-1252, proven against
docs/capability-matrix/whatwg-encoding-conformance.json.

## Negatives-capable count

<!-- CLAIM:W16-STD-1c -->
Exactly six evidence branches are declared able to assert a bounded negative (a CLEAN), pinned by name in a
test, so the ladder cannot silently gain or lose absence-authority; the three redirect header branches among
them assert their bounded negative across the cookie, urlencoded-body and JSON-body insertion surfaces as
well as query and path.

The issue framed this as "6 of 26": at issue time the ladder held 26 branches, 6 of them clean-capable. The
ladder has since grown past 26, so the load-bearing number pinned in the test is the count of clean-capable
branches (6), not the total.

## Honest residuals (not delivered by this slice)

- **Headless-browser `render_dom`** — the body-derived branches (`open_redirect.body_markup`,
  `open_redirect.js_sink`, `host_header.body_emission`, `oidc_redirect_uri.body_markup`) remain NOT
  clean-capable: a redirect assembled at runtime never appears literally in source, so proving its absence
  needs actual navigation observation. `playwright` is not installed in the build sandbox, so this stays a
  named blocking_work item on those branches, not a claim.
- **Streaming brotli/zstd decoders** — `body_decode` refuses `br`/`zstd`/chained encodings as
  UNSUPPORTED (INCONCLUSIVE, never an empty-body CLEAN); `brotli`/`zstandard` are not installed in the
  sandbox, and adjudication must not depend on which optional modules a host happens to have, so a vendored,
  version-pinned, bounded streaming decoder remains blocking_work.
- **OIDC non-query redirect_uri** — the opt-in SSO `OidcRedirectUriCheck` still supplies `redirect_uri` as a
  query parameter; extending it to cookie/body carriers mirrors `_redirect_templates` and is a named residual.
- **Candidate parameter-name bound** — the CLEAN over the synthesised cookie/body surfaces is bounded to the
  probed candidate redirect-parameter names, not every possible body parameter name; the coverage statement
  states this bound.
