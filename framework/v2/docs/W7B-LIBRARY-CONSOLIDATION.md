# W7-B — library / seed-check consolidation + injection micro-variant rebalance

Wave-7 *behavior-preserving hygiene*. Goal: remove genuine duplication between the
code seed set (`scanner/checks.py::DEFAULT_CHECKS`) and the data-driven library
(`scanner/library_entries/*.json`), and rebalance near-duplicate injection
micro-variants — **without changing which checks fire on the benchmark**.

The hard constraint is the regression gate:

```
python3 -m framework.v2 benchmark --gate --no-incumbents
crucible | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 | … | 853 | … | 9   (gate: PASS)
```

`reqs` (853) and `found` (9) must be **byte-identical** before and after. They are.

## How the benchmark roster is built (why byte-identity is so tight)

`BenchmarkCrucibleAdapter` (`eval/benchmark_run.py`) runs `WebScanCampaign` with
`use_library=True`, `library_entries = [e for e in load_library() if e.oracle.kind
!= "timing"]`, `enable_oob=False`, and `insertion_kinds=(QUERY_VALUE,)`. The active
roster the engine sweeps is **additive**:

```python
active_checks = tuple(self.checks) + tuple(point_lib)   # campaign.py
#               ^ DEFAULT_CHECKS      ^ fingerprint-selected library entries
```

The engine (`engine.py::AuditEngine.audit`) de-dups only by **`(bug_class, point.id)`
after a confirmation** (`seen.add(key)` runs only once a finding is confirmed). So at
a point where a bug class does *not* confirm, **every** check of that class runs and
sends its requests. Consequences that pin the roster:

* **Request-sending kinds** — `differential`, `reflection`, `evaluation`,
  `error_signature`, `content`, `signature` — each selected entry contributes
  requests on every non-confirming point. Removing any selected one lowers `reqs`.
* **`oob` kind sends ZERO requests here**: with `enable_oob=False` the engine hits
  `if self.oob is None: continue` *before* probing (engine.py). OOB checks never
  send, never confirm, and never touch the bandit on this run.
* **`timing` kind** is filtered out of the roster entirely.

Benchmark fingerprint tokens: `{java, jetty, language, server}` → 132 of 162
non-timing entries are selected (30 gated out); 52 of the selected are `oob`.

**Therefore the only byte-identical-safe removals are entries that send 0 requests on
the gate (oob / timing / not-selected).** A removal is *also* genuine hygiene only if
a functionally-identical check survives (no coverage lost).

## Shipped (provably byte-identical + coverage-preserving)

Removed **two** legacy OOB JSON mirrors of `DEFAULT_CHECKS` — the clearest case of
"same check defined in both code and data", where the JSON id ALSO never collides with
a code-seed id (so nothing looks the JSON entry up):

| removed JSON (id)                         | code seed it duplicated              | payload |
|-------------------------------------------|--------------------------------------|---------|
| `command_injection.json` (`command-injection-oob`) | `RCE_OOB` (`rce-oob`, class `command_injection`) | `;curl {callback};` |
| `blind_xxe.json` (`blind-xxe-oob`)        | `XXE_OOB` (`xxe-oob`, class `blind_xxe`)          | `<?xml …><!ENTITY x SYSTEM "{callback}">…` |

**`ssrf.json` (`ssrf-oob`) was NOT removed — DEFERRED.** It duplicates the `SSRF_OOB`
code seed's *detection*, but unlike the other two its id `ssrf-oob` is **identical** to
the code seed's id, and `scanner/report.py::_meta_for` looks up a finding's report
`references`/`remediation` by `check_id` (`lib.get(check_id)`). So this library entry is
the source of the SSRF-OOB report metadata (`references: [CWE-918, CAPEC-664]` + its
remediation prose). Removing it would make `lib.get("ssrf-oob")` return `None` and fall
back to `report._CLASS_META["ssrf"]`, which drops `CAPEC-664` and changes the remediation
text — an **observable report change** on any `enable_oob=True` run (caught by the Wave-7
behavior-preservation review; the gate never fires it because the gate runs OOB off, and
no test asserts it, so the change would have been silent). Behavior-preservation is the
hard constraint, so `ssrf-oob` stays until its report metadata is first migrated into
`_CLASS_META` (or the code seed) under its own gated change. **[UPDATE — Wave 7-F closeout:
that migration is now DONE. The exact metadata moved into a new check-id-scoped
`report._CHECK_META["ssrf-oob"]` (not `_CLASS_META`, so no other ssrf finding is affected),
`ssrf.json` was removed, and the rendered OOB-SSRF report is byte-identical (CAPEC-664 + prose
retained). See `WAVE7-DEBT-FINAL-DISPOSITION.md`.]** `command-injection-oob` /
`blind-xxe-oob` have no such collision (their code seeds use ids `rce-oob` / `xxe-oob`),
so `lib.get()` for the removed ids was always `None` — their removal changes no report.

Why the two removals are safe:

* **Gate byte-identical** — all three are `oob` (0 requests on the gate). Their bug
  classes stay represented (by the code seeds + 49 remaining library OOB entries), so
  the rank/order of the request-sending checks is unchanged. Verified: `reqs` 853→853,
  `found` 9→9, verdict unchanged, `gate: PASS`.
* **No coverage lost** — the identical payloads live on in `DEFAULT_CHECKS`, which is
  `self.checks` on **every** path that sets `use_library=True` (engage / scan / corpus
  / benchmark). No path constructs `WebScanCampaign`/`AuditEngine` with `use_library`
  *and* an empty `checks=()` (the only `checks=()` call sites are request-check unit
  tests). The richer per-scheme / per-vector OOB library entries (`m2-inj-ssrf-*`,
  `m3-blind-*`, `m2-inj-cmdi-*`, `m2-inj-xxe-*`, …) are untouched.
* **Tests** — `test_library.py::test_seed_has_the_named_minimum_entries` keeps asserting
  `ssrf-oob` (still shipped) and adds the surviving richer OOB entries
  (`m2-inj-ssrf-http-scheme`, `m2-inj-xxe-external-dtd`, `m2-inj-cmdi-pipe-curl`) in place
  of the two removed bare-callback ids; `test_compile_oob_yields_oob_check` was repointed
  to `m2-inj-ssrf-http-scheme`. Intent (library ships OOB entries per class; an oob entry
  compiles to an `OOBCheck`) is preserved. The
  campaign-integration tests self-adjust (they recompute expectations from
  `load_library()`), so they needed no change.

`docs/CHECK-AUTHORING.md` still shows `command-injection-oob` / `blind-xxe-oob` as
**format illustrations** of the `oob` oracle; they teach the JSON shape and do not
claim to be shipped files, so they were left as-is.

## Deferred (identified, NOT changed — each would move `reqs` or lose coverage)

### (a) Remaining DEFAULT_CHECKS ↔ JSON duplicates that SEND requests

| JSON entry (id)                | duplicates code seed        | gate reason to defer |
|--------------------------------|-----------------------------|----------------------|
| `boolean_sqli.json` (`boolean-sqli`) | `BOOLEAN_SQLI` (`differential`) | Selected + request-sending. It and the code seed both run on every non-confirming query point; dropping either lowers `reqs`. |
| `reflected_xss.json` (`reflected-xss`) | `REFLECTED_XSS` (`reflection`) | Same — one of 18 selected `xss` reflection checks; removing lowers `reqs` on every non-XSS point. |

`time_based_sqli.json` (`time-based-sqli`, `timing`) is **not** a DEFAULT_CHECKS
duplicate (there is no timing code seed) and is the only generic timing-SQLi seed, so
it is intentionally kept.

Converging (a) safely would need a source-of-truth refactor (e.g. `DEFAULT_CHECKS`
compiling the corresponding library entries, or vice-versa) so exactly one runtime
check exists per class on the `use_library` path — a behavior change to request
counts, out of scope for byte-identical hygiene.

### (b) Injection micro-variant skew — exact/near-duplicate library entries

Exact payload-duplicate groups within the library (same oracle + same payload,
different id). All the request-sending ones are selected on the gate and pinned by
`reqs`:

| group (ids)                                                                 | oracle | defer reason |
|-----------------------------------------------------------------------------|--------|--------------|
| `m2-sqli-{mssql,mysql,oracle,pg,sqlite}-boolean-numeric` (`1 OR 1=1`)       | differential | all 5 selected + request-sending; collapsing to one lowers `reqs` by 4×2×(non-confirming points). |
| `m2-inj-authbypass-or-true`, `m2-sqli-mysql-boolean-squote`, `m2-sqli-mysql-boolean-wp-gated` (`' OR '1'='1'-- -`) | differential | 2 of 3 selected + request-sending → `reqs` moves. |
| `m2-sqli-oracle-boolean-squote`, `m2-sqli-pg-boolean-django-gated`, `m2-sqli-pg-boolean-squote` (`' OR '1'='1'--`) | differential | request-sending → `reqs` moves. |
| `m2-sqli-mssql-boolean-aspnet-gated`, `m2-sqli-mssql-boolean-squote`, `m2-sqli-sqlite-boolean-squote` (`' OR 1=1--`) | differential | request-sending → `reqs` moves. |
| `boolean-sqli`, `wp-author-sqli` (`x' OR '1'='1`)                            | differential | `wp-author-sqli` is `tech:wordpress`-gated (not selected on the gate) but is a distinct WordPress-vector seed asserted by a test; removing loses that coverage, not hygiene. |
| `m2-ssti-{freemarker,generic,mako}` (`${31337*31337}`)                      | evaluation | all 3 selected + request-sending → `reqs` moves. |
| `m2-ssti-jinja2`, `m2-ssti-twig` (`{{31337*31337}}`)                        | evaluation | request-sending → `reqs` moves. |
| `m2-inj-ssrf-http-scheme`, `m3-blind-ssrf-header-forwarded` (`http://{callback}`) | oob | byte-identical-removable (0 requests), **but** the two carry different `insertion_kinds` (all points vs `header_value`), i.e. different intentional insertion surfaces — removing the header-scoped one loses real header-driven-SSRF coverage. Not genuine redundancy. |

The differential/evaluation groups above are the real "skew" — but they are the
per-DB-engine / per-template-engine coverage matrix, and each selected variant is a
distinct benchmark request. Collapsing them (e.g. one entry with a unioned
`applies_when`) is a coverage/behavior change that moves `reqs`, so it is deferred:
byte-identity is the hard constraint and a held-back item is the correct outcome here.

## Verification

* Gate BEFORE: `crucible | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 | 853 | 9` — `gate: PASS`
* Gate AFTER:  `crucible | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 | 853 | 9` — `gate: PASS`
* `python3 -m pytest framework/v2 -q` — green (only live-tool-gated skips).
