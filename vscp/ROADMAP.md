# VSCP roadmap — delivered vs staged (W13-7 / #500)

This document is the honest scope boundary for VSCP. The isolation guarantee and the core
registries are **real and CI-enforced today**; the fuller control-plane feature set is
**staged** and must not be claimed as complete until its own slice lands (behaviour +
fail-without-fix test + negative control + required-CI + registry entry, per the shared
programme bar).

## Delivered in this slice (real, CI-enforced)

| Capability | Module | Proof |
|---|---|---|
| Isolated sibling folder (own runtime/deps/migrations/CI) | `vscp/` (pyproject, migrations, `.github/workflows/vscp-ci.yml`) | structure asserted by `integration/tests/test_vscp_isolation.py` |
| Separate DB + credentials, fail-closed | `vscp/vscp/config.py` | `test_vscp_isolation.py` (+ negative control: product-path config refused) |
| No import path to assessment findings | `vscp/vscp/isolation.py` | `test_vscp_isolation.py` AST scan (+ negative control: synthetic `framework` import flagged) |
| No finding read (runtime) | `vscp/vscp/findings_boundary.py` | `test_vscp_isolation.py` (`read_assessment_finding` refuses) |
| Reviewer read-only, per route | `vscp/vscp/rbac_routes.py` | `test_vscp_isolation.py` (`reviewer_readonly_report` + reviewer write refused) |
| Deployment registry | `vscp/vscp/registries/deployment.py` | `vscp/tests/test_registries.py` |
| Trust-authority registry | `vscp/vscp/registries/trust_authorities.py` | `vscp/tests/test_registries.py` |
| Authorization issuance (signed, hash-chained, gated) | `vscp/vscp/authorization.py` | `vscp/tests/test_registries.py` |

## Staged (NOT delivered — do not claim as complete)

Each is an incremental slice to build against the same bar. None exist as working code yet.

1. **Policy registry** — versioned control-plane policies bound to deployments.
2. **Build registry** — provenance of governed build artifacts (SBOM/attestation refs).
3. **Attestation ingestion** — verifying signed posture/attestation from fielded deployments.
4. **Revocation workflows** — the authorization ledger has a `revoked_at` column and a
   `POST /vscp/authorizations/*/revoke` route mapped; the *workflow* (quorum, propagation,
   re-verification) is staged.
5. **Fleet monitoring** — health/heartbeat/drift across registered deployments.
6. **Event ingestion** — an inbound, inert, signed event seam (mirroring the product's
   inert-finding spool pattern, but for control-plane events — never findings).
7. **Reviewer console (UI)** — a read-only reviewer surface over the read routes. The
   route permissions are defined and enforced today; the UI is staged.

## Isolation is a permanent invariant, not a phase

Every staged item MUST preserve the isolation guarantee: it may reuse `vigil_core`, but it
must never import `framework` / `strix` / `sigil` / `vigil_integration`, never read an
assessment finding, and never share the product's database or signing material. The
`integration/tests/test_vscp_isolation.py` scan covers the whole `vscp/vscp` tree, so a new
module that breaks isolation fails the required CI job.
