# W13-7 — VSCP is a SIBLING application with CI-ENFORCED ISOLATION from the assessment product

Issue: [#500](https://github.com/thuram-nana/vigil-sovereign/issues/500) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme).
Unblocks [W13-9] #502 (the reviewer package's "three client instruments" input).

## The operator decision

VSCP (the Vigil Sovereign Control Plane) lives as a **sibling folder** (`vscp/`) in this
workspace with its **own runtime, dependencies, migrations and CI**. It must **not** read
assessment findings and must **not** share signing material with the product. Isolation is
proven by a CI test and negative controls, not asserted by convention.

The programme's four-part bar:

- (a) VSCP runs as a sibling folder with its OWN runtime, deps, migrations and CI;
- (b) a CI test asserts ISOLATION: separate DB + credentials, NO import path or network path
  to assessment findings, isolated signing;
- (c) negative control: a VSCP attempt to read an assessment finding is REFUSED, and a
  reviewer role attempting a write is REFUSED;
- (d) reviewer roles are read-only, asserted per route.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W13-7 -->
> VSCP is a SIBLING application under `vscp/` with its own runtime, dependencies (only the shared offense-free `vigil_core` substrate), migrations and CI, and it is ISOLATED from the assessment product: its database and Ed25519 signing key resolve strictly outside every product data root and `VscpConfig` REFUSES at construction any path that overlaps one (separate DB + isolated signing, fail-closed); no VSCP source file imports `framework`, `strix`, `sigil`, or `vigil_integration` (whose package init eagerly loads assessment-finding code), enforced by an AST import scan over the whole `vscp/vscp` tree with a negative control that flags a planted forbidden import; a VSCP attempt to read an assessment finding is REFUSED unconditionally and any authorization request referencing a finding is denied by a boundary gate; and reviewer roles are the read-only `viewer` of the shared RBAC-of-record, refused every write per route. The isolation proof runs in the REQUIRED `integration two-env boundary (P5)` job; VSCP's own broader suite runs in the additive `vscp-ci.yml` workflow.

This claim is TRUE of the code as of W13-7:

- **Sibling folder, own runtime/deps/migrations/CI** — `vscp/pyproject.toml` (package
  `vigil-vscp`, `dependencies = ["vigil-core"]`), `vscp/vscp/migrations/0001_initial.sql`
  (its own schema, applied by `vscp/vscp/store.py`), and `.github/workflows/vscp-ci.yml`
  (its own workflow). `test_vscp_is_a_sibling_folder_with_its_own_runtime_deps_migrations_and_ci`
  pins all four and that the deps never include the offense seam/engine.
- **Separate DB + credentials, isolated signing (fail-closed)** — `vscp/vscp/config.py`.
  `product_data_roots()` enumerates the product planes (`.vigil-live`/`VIGIL_BASE_DIR`,
  `~/.sigil`/`SIGIL_HOME`, `~/.vigil`); `VscpConfig.__post_init__` runs `_validate()`, which
  RAISES `VscpIsolationError` if the data dir, db path, or signing-key path overlaps any of
  them in either direction. VSCP mints authorizations with its OWN key
  (`load_or_create_signing_key`) at its OWN path, reusing `vigil_core` Ed25519 — never the
  product owner key. Pinned by `test_separate_db_and_credentials` with the negative control
  `test_config_refuses_overlap_with_product_data_root_negative_control` (a config pointed
  inside a product plane is refused; a disjoint one is accepted).
- **No import path to assessment findings** — `vscp/vscp/isolation.py`.
  `scan_tree_for_import_violations` AST-parses every `*.py` under `vscp/vscp` and flags any
  import root that is not stdlib, not `vigil_core`, and not `vscp` — with `framework`,
  `strix`, `sigil`, and `vigil_integration` explicitly forbidden. `vigil_integration` is
  forbidden WHOLESALE on purpose: its package `__init__` eagerly imports
  `vigil_integration.inert_finding`, so importing any of its submodules — even the
  `sovereign_bridge` facade — would create a live import path to assessment-finding code.
  VSCP therefore reuses the gate/crypto/chain primitives from `vigil_core` directly.
  Pinned by `test_no_import_path_to_assessment_findings` with the negative control
  `test_import_scanner_is_not_a_no_op_negative_control` (a planted `framework` import is
  flagged; stdlib and `vigil_core` are not).
- **A finding read is REFUSED; a reviewer write is REFUSED** — `vscp/vscp/findings_boundary.py`
  `read_assessment_finding` raises `FindingsAccessDenied` unconditionally, and
  `finding_boundary_gate` denies any request referencing a finding.
  `vscp/vscp/authorization.py` `authorize_action` composes the findings-boundary gate then
  the RBAC-of-record; a reviewer's write returns DENY (`denied_by == "rbac"`) and
  `issue_authorization` raises before signing anything. Pinned by
  `test_reading_an_assessment_finding_is_refused` and
  `test_reviewer_write_is_refused_but_operator_is_allowed` (which also drives a real,
  isolated VSCP sqlite store: a reviewer cannot register a deployment, an operator can).
- **Reviewer read-only, per route** — `vscp/vscp/rbac_routes.py` maps every route to a
  permission from the shared vocabulary; the reviewer is the read-only `viewer`.
  `reviewer_readonly_report()` proves, over the whole table, that every mutating route is
  above the reviewer and every read route requires only `read`. Pinned by
  `test_reviewer_is_read_only_per_route` with the negative control
  `test_reviewer_readonly_report_is_not_a_no_op_negative_control` (an injected mutating route
  mapped to `read` is caught).

## A facade, not a second policy engine (the CRITICAL CONSTRAINT)

VSCP references the existing gate/crypto/chain/RBAC primitives from `vigil_core`; its
authorization facade (`vscp/vscp/gate.py` + `authorization.py`) SEQUENCES existing deciders —
the RBAC-of-record and the findings boundary — and holds no policy of its own, in the same
spirit as `sovereign_bridge` (W13-2). It cannot import the product `sovereign_bridge` module
directly precisely because doing so would breach the isolation this slice enforces (that
module lives in `vigil_integration`, whose `__init__` loads finding code), so VSCP composes
the same underlying gate-of-record primitives that `sovereign_bridge` itself delegates to.

## The test that fails without this change (observed, not assumed)

`integration/tests/test_vscp_isolation.py` imports the `vscp` package and drives the checkers.
On a tree without `vscp/` it errors at collection. On the real tree, the isolation assertion
BITES: appending `from vigil_integration import sovereign_bridge` to a VSCP source file (the
subtle facade-import trap) makes `test_no_import_path_to_assessment_findings` fail with
`AssertionError: VSCP has forbidden/off-allowlist imports: [... root='vigil_integration' ...]`.
The negative controls in the same run prove the gates are not no-ops (a planted `framework`
import is flagged; a config pointed at a product plane is refused; an injected reviewer-writable
route is caught).

## Where the tests run — a required CI job

`integration/tests/test_vscp_isolation.py` lives under `integration/tests`, collected by the
REQUIRED `integration two-env boundary (P5)` job's sovereign leg (it is framework-free — it
imports nothing offense-side, neither `importorskip`s `framework` nor is `--ignore`d, so it
runs there by construction). VSCP's own broader suite (`vscp/tests`) runs in the additive
`vscp-ci.yml` workflow.

## Honest residual — what is delivered vs staged

Delivered and CI-enforced: the isolated skeleton (config + isolation guards), the deployment
registry, the trust-authority registry, and signed/hash-chained authorization issuance, plus
the isolation proof, findings boundary, and per-route reviewer-read-only.

Staged, NOT claimed complete (see `vscp/ROADMAP.md`): policy/build registries, attestation
ingestion, revocation workflows, fleet monitoring, event ingestion, and the reviewer console
UI. Each is an incremental slice to build against the same programme bar and must preserve the
isolation invariant.

The additive `vscp-ci.yml` workflow is a NEW check; making it a REQUIRED status check needs a
branch-protection admin change the orchestrator applies separately. The load-bearing isolation
proof does not depend on that: it runs in the already-required P5 job.

> **Registration:** this claim is entry `W13-7` in `docs/claims/registry.json`; the marker
> above is its `source` anchor.
