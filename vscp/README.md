# VSCP — the Vigil Sovereign Control Plane

VSCP is a **sibling application** to the VIGIL assessment product. Per the operator
decision for [#500] (W13-7), it lives as a sibling folder in this workspace with its
**own runtime, dependencies, migrations and CI**, and it is **provably isolated** from the
product:

- **Separate database.** VSCP's store lives under its own data dir (`~/.vscp` by default,
  or `$VSCP_HOME`), never inside a product data plane (`~/.sigil`, `~/.vigil`,
  `.vigil-live`). `vscp.config.VscpConfig` *refuses to construct* if any VSCP path overlaps
  a product data root — fail-closed, not by convention.
- **Separate credentials / isolated signing.** VSCP mints authorizations with its **own**
  Ed25519 key at its own path, reusing `vigil_core` crypto — never the product's owner key.
- **No path to assessment findings.** VSCP imports only the standard library and the
  shared, offense-free `vigil_core` substrate. It never imports `framework`, `strix`,
  `sigil`, or `vigil_integration` (whose package `__init__` eagerly loads finding code). A
  runtime `read_assessment_finding()` is an **unconditional refusal**, and every
  authorization request passes a findings-boundary gate that denies any finding reference.
- **Read-only reviewers, per route.** A reviewer is the read-only `viewer` role from the
  shared RBAC-of-record. Every mutating route requires a permission the reviewer lacks;
  `vscp.rbac_routes.reviewer_readonly_report()` proves it over the whole route table.

## Reuse, not reimplementation

VSCP references the existing gate / crypto / chain / RBAC primitives from `vigil_core`. Its
authorization facade (`vscp.gate` + `vscp.authorization`) **sequences existing deciders** —
the RBAC-of-record and the findings boundary — and holds no policy of its own, mirroring the
`sovereign_bridge` invariant (W13-2): *a facade, never a second policy engine*.

## CI-enforced isolation

The load-bearing isolation proof runs in the **required** `integration two-env boundary
(P5)` CI job — `integration/tests/test_vscp_isolation.py`. It asserts separate DB +
credentials, the import isolation (with a negative control proving the scanner is not a
no-op), the findings-read refusal, and the reviewer-write refusal. VSCP's own broader suite
runs in the additive `vscp-ci.yml` workflow.

## What is delivered vs staged

Delivered: the isolated skeleton (config + isolation guards), the deployment registry, the
trust-authority registry, and signed/hash-chained authorization issuance, plus the CI
isolation proof, findings boundary, and per-route reviewer-read-only enforcement.

Staged (see `ROADMAP.md`): policy/build registries, attestation, revocation workflows,
fleet monitoring, event ingestion, and the reviewer console UI. These are **not** claimed as
complete.

## CLI

```
vscp-ctl doctor    # print isolated paths + run the import-isolation self-scan
vscp-ctl routes    # print the route->permission table + reviewer read-only check
vscp-ctl migrate   # open the VSCP store, applying migrations
```

[#500]: https://github.com/thuram-nana/vigil-sovereign/issues/500
