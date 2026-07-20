# CRUCIBLE — Authoring a Check

How to add coverage **without touching engine code**. A check used to be Python
(a `DifferentialCheck`, a `MarkerReflectionCheck`, ...). In CRUCIBLE a check is
**data**: a JSON `LibraryEntry` dropped into
`framework/v2/scanner/library_entries/`. Adding a bug class is authoring one file,
not editing the engine.

For the surrounding design see [ARCHITECTURE.md](./ARCHITECTURE.md); for running
scans see [OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md).

---

## The golden rule

> **Every library entry is adjudicated by a deterministic oracle.** The entry
> carries a *payload* and an *oracle contract*; the oracle — never the entry, never
> an LLM — decides whether the finding is confirmed. Precision is preserved because
> the same oracle that gates a hand-written check gates yours.

An entry that cannot route to an oracle can never confirm. Two things must line up
(§4): your `oracle.kind` (which concrete check runs and what evidence it produces)
and your `bug_class` (which oracle family the verifier selects). Get those
consistent and the engine does the rest.

---

## 1. Anatomy of a `LibraryEntry`

The schema lives in `scanner/library.py` (`LibraryEntry`, `OracleSpec`), Pydantic
v2 with `extra="forbid"` — a typo is a **load-time error**, never a silent no-op.

```jsonc
{
  "id":            "unique-stable-id",          // required; also the compiled check id
  "bug_class":     "boolean_sqli",              // required; selects the oracle set (§4)
  "title":         "Human-readable name",       // required
  "severity":      "High",                       // Critical | High | Medium | Low | Info
  "applies_when":  {"always": true},            // fingerprint predicate (§3); default = always
  "insertion_kinds": ["query_value", "json_value"], // scope to positions; [] = all (metadata)
  "oracle":        { "kind": "...", "..." : "..." }, // the payload + which check runs it (§2)
  "references":    ["CWE-89", "CAPEC-7"],        // ids that justify the class
  "remediation":   "How to fix the class.",      // shown on the finding
  "payload_family":"sql-tautology"               // optional grouping tag
}
```

Field rules worth knowing:

- **`severity`** must be one of `Critical | High | Medium | Low | Info`.
- **`applies_when`** defaults to `{"always": true}`. It is a single-operator
  predicate object (§3); an empty `{}` also means "always".
- **`insertion_kinds`** are `InsertionKind` values — `url_path_seg`,
  `query_value`, `query_name`, `body_form_value`, `body_form_name`,
  `cookie_value`, `header_value`, `json_value`, `json_key`, `body_whole`. You may
  spell them lower (`query_value`) or upper (`QUERY_VALUE`). Empty list = all;
  it's a hint the selector reads, not something the compiled check enforces.
- **`id`** must be unique across the whole library. Duplicate ids are a load error.

---

## 2. Every oracle kind, with a real example

`oracle.kind` selects one of seven concrete check shapes and dictates which params
are required. `extra="forbid"` means an irrelevant param is a load error, and the
after-validator enforces the required ones (including the `{marker}`/`{callback}`
placeholder position). All examples below are real entries from
`scanner/library_entries/`.

### `differential` → boolean/logic differential

Requires `benign` and `probe`. Confirmed by the differential-response oracle
(status/length/lexical/structural divergence) — or, over repeated rounds, the SPRT
boolean-inference oracle.

```json
{
  "id": "boolean-sqli",
  "bug_class": "boolean_sqli",
  "title": "Boolean-based blind SQL injection",
  "severity": "High",
  "applies_when": {"always": true},
  "insertion_kinds": ["query_value", "body_form_value", "json_value"],
  "oracle": {
    "kind": "differential",
    "benign": "crucible-benign-term",
    "probe": "x' OR '1'='1"
  },
  "references": ["CWE-89", "CAPEC-7"],
  "remediation": "Use parameterised queries so user input is bound as a value and can never alter query structure.",
  "payload_family": "sql-tautology"
}
```

### `reflection` → marker reflection (`{marker}`)

Requires `payload_template` **containing `{marker}`**. The engine substitutes a
unique canary; the oracle fires only when the marker lands in an **executable**
context (for `xss`, the reflection-context oracle parses the response — an
HTML-encoded reflection is correctly inert) or in a sink it should not reach (for
`path_traversal`/`lfi`, the side-effect oracle).

```json
{
  "id": "reflected-xss",
  "bug_class": "xss",
  "title": "Reflected cross-site scripting",
  "severity": "High",
  "applies_when": {"always": true},
  "insertion_kinds": [],
  "oracle": {
    "kind": "reflection",
    "payload_template": "\"'><x{marker}>"
  },
  "references": ["CWE-79", "CAPEC-591"],
  "remediation": "Contextually output-encode all user-controlled data and set a strict Content-Security-Policy.",
  "payload_family": "html-breakout"
}
```

### `oob` → blind out-of-band callback (`{callback}`)

Requires `payload_template` **containing `{callback}`**. The engine substitutes a
per-finding unique callback URL; the OOB oracle fires on an inbound interaction on
that token (see the OOB section of [OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md)).

```json
{
  "id": "command-injection-oob",
  "bug_class": "command_injection",
  "title": "OS command injection (out-of-band)",
  "severity": "Critical",
  "applies_when": {"always": true},
  "insertion_kinds": [],
  "oracle": {
    "kind": "oob",
    "payload_template": ";curl {callback};"
  },
  "references": ["CWE-78", "CAPEC-248"],
  "remediation": "Never pass user input to a shell. Invoke programs with an argument vector; validate against a strict allowlist.",
  "payload_family": "shell-breakout"
}
```

A body-embedded example (blind XXE) shows the placeholder inside a document:

```json
{
  "id": "blind-xxe-oob",
  "bug_class": "blind_xxe",
  "title": "Blind XML external entity injection (out-of-band)",
  "severity": "High",
  "applies_when": {"always": true},
  "insertion_kinds": ["body_whole"],
  "oracle": {
    "kind": "oob",
    "payload_template": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"{callback}\">]><r>&x;</r>"
  },
  "references": ["CWE-611", "CAPEC-201"],
  "remediation": "Disable external entity and DTD processing in every XML parser.",
  "payload_family": "external-entity"
}
```

### `timing` → statistical time-based blind

Requires `benign`, `sleep_payload`, and `injected_ms` (> 0). The timing oracle
runs a one-sided Mann-Whitney U test plus a Hodges-Lehmann effect-size floor (and,
when given a dose, a scaling check) — so jitter cannot manufacture a confirmation.

```json
{
  "id": "time-based-sqli",
  "bug_class": "time_based_sqli",
  "title": "Time-based blind SQL injection",
  "severity": "High",
  "applies_when": {"always": true},
  "insertion_kinds": ["query_value", "body_form_value"],
  "oracle": {
    "kind": "timing",
    "benign": "1",
    "sleep_payload": "1' AND SLEEP(5)-- -",
    "injected_ms": 5000
  },
  "references": ["CWE-89", "CAPEC-7"],
  "remediation": "Use parameterised queries so an injected conditional SLEEP() cannot execute.",
  "payload_family": "sql-sleep"
}
```

### `evaluation` → server evaluated an injected expression (SSTI / EL)

Requires `probe_expr` and `expected_result`. The evaluation oracle fires only when
the *computed* result appears **and** the raw expression does **not** (a surviving
template string means it was reflected, not evaluated). Use a distinctive product
so the value cannot coincidentally appear.

```json
{
  "id": "m2-ssti-jinja2",
  "bug_class": "ssti",
  "title": "Server-side template injection — Jinja2 (evaluated 31337*31337)",
  "severity": "Critical",
  "applies_when": {"category": "python"},
  "oracle": {
    "kind": "evaluation",
    "probe_expr": "{{31337*31337}}",
    "expected_result": "982007569"
  },
  "references": ["CWE-1336", "CWE-94", "CAPEC-242"],
  "remediation": "Do not pass user input into a template as template source; pass user data only as rendered variables.",
  "payload_family": "ssti-jinja2"
}
```

### `error_signature` → datastore/parser error (error-based injection)

Requires `error_probe` (a syntax-breaking payload). `benign` is optional (defaults
to `crucible-benign-term`) and supplies a control so a page that *always* shows a
stack trace is not mistaken for an injection. The error-signature oracle matches
known engine-specific error strings (MySQL/Postgres/MSSQL/Oracle/SQLite/Mongo/
LDAP/XPath), not a generic "error".

```json
{
  "id": "m2-errsqli-single-quote",
  "bug_class": "error_based_sqli",
  "title": "Error-based SQL injection — a lone single quote",
  "severity": "High",
  "applies_when": {"always": true},
  "oracle": {
    "kind": "error_signature",
    "error_probe": "'",
    "benign": "crucible-benign-term"
  },
  "references": ["CWE-89", "CAPEC-7"],
  "remediation": "Use parameterised queries; disable verbose database errors in production.",
  "payload_family": "error-based-single-quote"
}
```

### `signature` → path probe (framework/CMS exposure) — **request-level**

Requires `probe_path` and `signature`; `http_method` defaults to `GET`. This is
the one **request-level** kind: it GETs a known path once per host and confirms
when the distinctive signature appears (adjudicated via the achieved-state oracle
for the `exposure` class). See §5 for point-level vs request-level.

```json
{
  "id": "m5-fw-spring-actuator-env",
  "bug_class": "exposure",
  "title": "Spring Boot Actuator /env exposed (secrets)",
  "severity": "High",
  "applies_when": {"category": "java"},
  "oracle": {
    "kind": "signature",
    "probe_path": "/actuator/env",
    "signature": "propertySources"
  },
  "references": ["CWE-200", "CWE-16"],
  "remediation": "Restrict Actuator endpoints; do not expose /env, /heapdump, /threaddump publicly.",
  "payload_family": "exposure-spring-actuator-env"
}
```

---

## 3. `applies_when` — the fingerprint predicate

The predicate gates the entry against the target's **fingerprint token set**. The
fingerprinter (`scanner/fingerprint.py`) classifies the crawl's responses into a
flat set of tokens — the union of technology **names** and their **categories**
(`server`, `language`, `framework`, `cms`, `cdn`, `waf`, `api_gateway`,
`analytics`, `other`). Framework/CMS detections imply their runtime language
(WordPress → `php`, Django → `python`, Rails → `ruby`, Spring → `java`, Express →
`node`, ...), so a language token is present for gating even when no banner leaked.

Grammar (single-operator object; `{}` or omitted = always):

| Predicate | Applies when |
|-----------|--------------|
| `{"always": true}` | unconditionally (`false` never applies) |
| `{"tech": "wordpress"}` | the token is in the set |
| `{"category": "php"}` | the token is in the set |
| `{"any": [p, ...]}` | ANY sub-predicate applies |
| `{"all": [p, ...]}` | EVERY sub-predicate applies |
| `{"not": p}` | the sub-predicate does not |

`tech` and `category` differ only in intent — both are plain set-membership over
the tokens (bare `wordpress` or namespaced `tech:wordpress` both match). A
malformed predicate is a **load error**, never a silent `false` that quietly
disables the check.

Examples straight from the library:

```jsonc
{"applies_when": {"category": "php"}}                      // php_lfi: only PHP stacks
{"applies_when": {"any": [ {"tech": "django"},             // Django/Rails/Postgres stacks
                           {"tech": "rails"},
                           {"tech": "postgresql"} ]}}
{"applies_when": {"any": [ {"tech": "wordpress"},          // WordPress/MySQL stacks
                           {"tech": "mysql"} ]}}
```

Scoping is *precision, not just noise reduction*: a fingerprint-gated Postgres
payload never fires at a MySQL app, so the wrong-dialect probe cannot even run.
Always-on entries (`{"always": true}`) are always included.

---

## 4. `bug_class` must route to an oracle

This is the load-bearing consistency requirement. The flow:

1. Your `oracle.kind` compiles to a concrete check (`compile_entry` in
   `library.py`): `differential → DifferentialCheck`, `reflection →
   MarkerReflectionCheck`, `oob → OOBCheck`, `timing → TimingCheck`, `evaluation →
   EvaluationCheck`, `error_signature → ErrorSignatureCheck`, `signature →
   PathProbeCheck`.
2. That check runs and produces an **oracle context** carrying specific evidence
   keys.
3. The verifier (`verify/verifier.py`) reads your `bug_class`, looks it up in
   **`BUG_CLASS_ORACLES`**, and runs the oracle kinds it maps to. An oracle only
   runs if its inputs are present; a finding is `confirmed` only when one fires at
   ≥ 0.70.

So your `bug_class` must map (in `BUG_CLASS_ORACLES`, directly or via an alias in
`_ALIASES`) to the `OracleKind` your chosen `oracle.kind` actually feeds:

| `oracle.kind` | Produces (context) | Oracle kind that adjudicates | Example `bug_class` → routes to |
|---------------|--------------------|------------------------------|---------------------------------|
| `differential` | baseline, mutated | `DIFFERENTIAL_RESPONSE` (or `BOOLEAN_INFERENCE`) | `boolean_sqli`, `nosqli`, `xpath_injection` |
| `reflection` (xss) | marker, observed_sink | `REFLECTION_CONTEXT` | `xss` |
| `reflection` (file) | marker, observed_sink | `SIDE_EFFECT` | `path_traversal`, `lfi` |
| `oob` | oob_hits | `OOB_CALLBACK` | `ssrf`, `command_injection`, `blind_xxe` |
| `timing` | baseline/treatment latencies | `TIMING` | `time_based_sqli` |
| `evaluation` | eval_expected, eval_observed | `EVALUATION` | `ssti`, `el_injection` |
| `error_signature` | error_observed | `ERROR_SIGNATURE` | `error_based_sqli`, `sqli` |
| `signature` | achieved-state predicate | `ACHIEVED_STATE` | `exposure` |

Use a `bug_class` that already exists as a canonical key or an alias (the map is
extensive — `sql_injection`, `blind_sqli`, `server_side_request_forgery`,
`os_command_injection`, `cross_site_scripting`, `directory_traversal`, ... all
fold onto canonical keys). If you genuinely need a **new** class, add it to
`BUG_CLASS_ORACLES` (or `_ALIASES`) in `verifier.py` so it routes to the right
oracle — this is the one place a new class touches engine code, and it is a
one-line data addition, not new logic.

> **Honest caveat.** An *unrecognised* `bug_class` does not silently fail: the
> verifier falls back to trying *every* oracle and will still confirm via whichever
> one your check fed. But you lose the explicit intent, and a future oracle that
> shares those inputs could fire in a way you did not mean. Always route a new
> class explicitly rather than lean on the fallback.

---

## 5. Point-level vs request-level

- **Point-level** checks fuzz **one insertion point** (a query value, a JSON leaf,
  a header). Every kind except `signature` is point-level. They run against each
  insertion point of each discovered request.
- **Request-level** checks probe the **whole host/endpoint once**. Only
  `signature` (path probes) is request-level; the campaign runs it a single time
  per host, not once per parameter, so it never re-confirms the same exposure N
  times.

`split_checks(entries)` in `library.py` routes the two automatically
(`REQUEST_LEVEL_KINDS = {"signature"}`). You don't wire this yourself — just know
that a `signature` entry needs no `insertion_kinds` (it targets a path, not a
point).

---

## 6. Test a new entry

No engine code changes, so testing is fast:

```bash
# 1. The library validates on load — a malformed entry raises a LibraryError
#    that names the offending file. This alone catches schema typos, a bad
#    predicate, a missing {marker}/{callback}, or a duplicate id.
python3 -c "from framework.v2.scanner.library import load_library; \
            print(len(load_library()), 'entries loaded OK')"

# 2. Check your predicate selects against the stack you intend.
python3 -c "from framework.v2.scanner.library import load_library, select_entries; \
            e=load_library(); \
            sel=select_entries(e, {'php','language','wordpress','cms'}); \
            print([x.id for x in sel])"

# 3. End-to-end against a deliberately-vulnerable LOOPBACK app: the entry should
#    produce a confirmed finding, and a safe control must NOT be flagged.
python3 -m framework.v2 scan http://127.0.0.1:8000/ --targeted

# 4. Re-verify the resulting certificate reproduces offline.
python3 -m framework.v2 verify /path/to/report.json
```

For a rigorous precision/recall number there is a local WAVSEP-style harness,
`scanner/benchmark.py`: a deliberately-vulnerable loopback app plus a ground-truth
manifest that scores true/false positives, false negatives, precision, recall and
F1 — including *safe controls a precise scanner must leave alone*. Use it to prove
a new entry adds recall without costing precision.

---

## 7. Checklist before you commit an entry

- [ ] `id` is unique and stable (it is also the compiled check's id).
- [ ] `oracle.kind` matches the evidence you actually want to prove the bug with.
- [ ] The required params for that kind are present; `{marker}`/`{callback}` is in
      the right placeholder if the kind needs it.
- [ ] `bug_class` routes (in `BUG_CLASS_ORACLES` or `_ALIASES`) to the oracle kind
      your check feeds — §4.
- [ ] `applies_when` scopes the entry to the stack(s) where the bug is possible;
      no over-broad `{"always": true}` for a stack-specific payload.
- [ ] `severity`, `references` (CWE/CAPEC), and `remediation` are filled — a
      finding must explain itself.
- [ ] `load_library()` loads clean and the entry confirms on a loopback vuln app
      while leaving safe controls alone.

---

## See also

- [ARCHITECTURE.md](./ARCHITECTURE.md) — how the library, fingerprint scoping, and
  oracle layer fit together.
- [OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md) — running the scans that exercise your
  entry, and reading the results.
