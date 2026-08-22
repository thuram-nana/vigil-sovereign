# W16-4 — The default check corpus is disclosed, and a default-run CLEAN is bounded by it

Issue: [#509](https://github.com/thuram-nana/vigil-sovereign/issues/509) ·
Milestone: W16 — DECLARED-LIMITATION BURNDOWN.

## The decision

There are two check rosters in the scanner:

- **The built-in seed roster** — `scanner.checks.DEFAULT_CHECKS`, **11 point checks** across **10
  bug classes** (`boolean_sqli`, `xss`, `ssti`, `path_traversal`, `error_based_sqli`,
  `open_redirect`, `ssrf`, `blind_xxe`, `command_injection`, `deserialization`). Every check is
  oracle-anchored and confirms end to end. This roster is the **default check corpus**: it runs on
  every `scan` and `engage` with no flag.
- **The declarative check library** — `scanner.library`, **~172 entries across 23 bug classes**.
  Its POINT checks add 12 bug classes the seed roster does not cover (`nosqli`, `ldap_injection`,
  `xpath_injection`, `el_injection`, `sqli`, `time_based_sqli`, `time_based_command_injection`,
  `time_based`, `lfi`, `xxe`, `rce`, `auth_bypass`); its two REQUEST-level classes
  (`exposure`, `sensitive_exposure`) are probed once per host and sit outside the point-check
  corpus below. The library is fingerprint-scoped (a stack-specific payload never fires off-stack)
  and the `TIMING` oracle fires only here. It runs **only under `--library`** (`use_library=True`).

**We keep `--library` OFF by default in the two CLI entry points** (`scanner/cli.py`,
`engage.py`), deliberately, rather than flipping the default on:

- The library is stack-scoped, so a default run over an un-fingerprinted or thin crawl would add
  latency (fingerprint pass + ~172 applicability evaluations + the TIMING oracle's timing probes)
  for little gain on a target it cannot fingerprint. Defaulting it on is a **runtime-cost / benchmark
  byte-identity** change the make-gate protects, and is out of scope for an honesty slice.
- The console/UI path is different and **does** default the library on: `console.actions.launch_scan`
  takes `use_library=True` and appends `--library` to the spawned command, because a UI scan is a
  deliberate "scan this thing" action, not a scripted default.

Because the default corpus is a **thin slice** of the shipped corpus (10 of 22 point-check bug
classes; 11 of ~183 checks), the honesty requirement is that **a default run must never let its
absence of findings read as a corpus-wide negative.** That is the code change this slice lands.

## The claim (register in the claims registry, [W0-3] #398)

> A default (`--library`-off) `scan`/`engage` run **discloses** the fraction of the check corpus it
> exercised, and **bounds** its verdict by it: for every point-check bug class the run committed NO
> check for (every library-only point class — `nosqli`, `ldap_injection`, `xpath_injection`,
> `el_injection`, `sqli`, `time_based_sqli`, `time_based_command_injection`, `time_based`, `lfi`,
> `xxe`, `rce`, `auth_bypass`) the per-class verdict is **`inconclusive`**, never `clean`. A CLEAN
> from a default run is therefore **not** a corpus-wide negative (`clean_is_corpus_wide == False`);
> only a `--library` run that exercises the whole corpus can report a corpus-wide CLEAN.

This claim is TRUE of the code as of W16-4:

- **The bounded verdict** — `ScanReport.verdict_by_class()`
  (`engine/crucible/framework/v2/scanner/campaign.py`) maps every corpus bug class to exactly one of
  `finding` / `clean` / `inconclusive`. A class is `inconclusive` unless it is in
  `committed_check_classes` (the classes the active point-check roster actually committed to at plan
  time) or has a confirmed finding. `ScanReport.coverage_bounds()` summarises it over the fixed
  corpus (`corpus_classes`, `classes_exercised`, `classes_inconclusive`, `clean_is_corpus_wide`).
- **The corpus** — `scanner.campaign._corpus_bug_classes()` derives the corpus from the loaded
  registry (`DEFAULT_CHECKS` ∪ `scanner.library` POINT checks), never a hardcoded number, so the
  disclosure tracks the library as entries are added/removed. Today it is **22 distinct point-check
  classes** (10 built-in ∪ 12 library-only).
- **The disclosure surfaces** — the machine JSON report (`scanner.report.build_report`) carries a
  `verdict_by_class` map and a `coverage_verdict` block; the HTML note and the operator-facing text
  line (`scanner.report.coverage_line`, printed by both `scan` and `engage`) both state
  "adjudicated N/M bug classes; a CLEAN here is NOT corpus-wide — K classes INCONCLUSIVE".
- **Scope** — the corpus disclosed is the **point-check** corpus. The always-on request-level
  roster (CORS / Host-header / JWT / GraphQL-introspection) is a separate set outside this
  disclosure; its findings still surface as `finding` in `verdict_by_class` when they occur.

## Migration / behaviour safety — no default flip

The default `scan`/`engage` roster is **unchanged**: no check is added or removed, no extra traffic
is sent, and the make-gate benchmark stays byte-identical. The bounded verdict is **additive** —
new report keys (`verdict_by_class`, `coverage_verdict`) and a longer text/HTML coverage note. The
existing `coverage()` object (`built_in_run` / `library_available` / `library_run` /
`full_coverage`) is untouched, so every consumer that already read it keeps working.

## Acceptance-criterion residual (honest)

The AC clause "**if** the library is defaulted on, the runtime cost is measured and the TIMING
oracle is proven to fire" is **N/A by decision**: we did NOT default the library on in the CLI (see
above), so there is no default-run runtime-cost delta to measure. The TIMING oracle continues to
fire only under `--library`, which the disclosure now states explicitly. Registering the claim in a
first-class code claims registry is deferred to [W0-3] #398 (not yet landed); until then this
decision record + the doc-truth test below IS the registration, following the W5-1 precedent.

Pinned by `engine/crucible/framework/v2/scanner/tests/test_w16_4_coverage_honesty.py` (runs in the
required `CRUCIBLE core` CI job, which executes the whole `framework/v2` tree). The suite includes:
a negative-control test that a target vulnerable to a library-only class (`nosqli`) is reported
`inconclusive` — never `clean` — by a default run; a no-op-gate control that an *exercised* class
(`boolean_sqli`) is reported `clean` and that adding the class to the committed roster flips the
verdict; a test that FAILS on a tree without this change (the new methods/keys do not exist); and a
doc-truth test that this ADR's stated corpus numbers match the code at runtime.
