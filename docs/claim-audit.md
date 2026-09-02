<!-- CLAIM:W15-3 -->
# Claim-vs-enforcement audit manifest (W15-3 #395)

**Registered claim (W15-3 #395):** Every enforcement-flavoured claim enumerated in `docs/audit/claim-audit.json` carries a verdict (TRUE, SCOPED, FALSE, or UNVERIFIABLE) and a deciding code reference that resolves, every FALSE or SCOPED verdict is pinned by a claims-registry entry, and all eight audited surfaces are represented — or the build goes red.

This is the human rendering of the machine-checkable manifest [`docs/audit/claim-audit.json`](audit/claim-audit.json). The guard [`docs/tests/test_claim_vs_enforcement_audit.py`](tests/test_claim_vs_enforcement_audit.py) validates every row against the code and fails the build on any drift; it runs in the **required** `the briefing explains every agent and capability` CI job. The load-bearing FALSE families from the interim run are recorded in [`docs/claims/CLAIM-VS-ENFORCEMENT-AUDIT.md`](claims/CLAIM-VS-ENFORCEMENT-AUDIT.md).

## Scope (honest)

Machine-checkable manifest for the claim-vs-enforcement audit. It classifies the enforcement-flavoured claims (claims that assert the code enforces / gates / blocks / refuses / requires / verifies / signs something) on the buyer- and reviewer-facing surfaces named by #395: README.md, docs/AS-BUILT.md, docs/POSTURE.md, CONTRIBUTING.md, docs/SUPPLY-CHAIN.md, the in-app Manual (packages/vigil-ui/manual.js), the served remediation ladder (console/api.py::_REMEDIATION_LADDER, rendered by the Fixes screen), and the in-app authorization/legal text (there is NO dedicated in-app Legal PAGE; the legal/authorization text is the New-Assessment authorization gate + Charter screen in packages/vigil-ui/app.js and the README license section). Each entry carries a verdict (TRUE/SCOPED/FALSE/UNVERIFIABLE) and the deciding code_ref. Every FALSE or SCOPED verdict names a claims-registry entry that pins it. Honest bound: this is the enforcement-flavoured claim set, not a verbatim classification of every sentence in the 100 KB README; the load-bearing FALSE families from the interim audit are recorded in docs/claims/CLAIM-VS-ENFORCEMENT-AUDIT.md.

## Verdict tally

| Verdict | Count |
|---|---|
| TRUE | 45 |
| SCOPED | 7 |
| FALSE | 0 |
| UNVERIFIABLE | 3 |
| **total** | **55** |

## FALSE claims found and FIXED in this PR

Two self-verifiable claims were FALSE against the live code and are corrected in this change (preferring a doc fix over a known-false registration, per the programme bar). Each is now TRUE and pinned:

| id | source | was | now enforced/pinned by |
|---|---|---|---|
| CA-FIX-1 | `README.md:668` | `that registry is not yet built in this tree` | REGISTRY-SELF + docs/tests/test_claims_registry.py |
| CA-FIX-2 | `docs/AS-BUILT.md:308` | `--unshare-net` | integration/tests/test_sandbox_exec.py::test_argv_shape_enforces_the_floors |

## The audited claims

Each row: the surface, the `path:line` the claim lives at, the verdict, the deciding code reference, and (for FALSE/SCOPED) the claims-registry entry that pins it.

| id | surface | source | verdict | code reference | registry pin | rationale |
|---|---|---|---|---|---|---|
| CA-RDM-01 | README | `README.md:136` | TRUE | `integration/vigil_integration/oracle_adapter.py`::`certify_to_scitt` | n-a | The oracle bridge turns a proposal into a signed FACT only when the class is oracle-mapped AND the deterministic oracle fires; else a labelled lead. |
| CA-RDM-02 | README | `README.md:255` | TRUE | `engine/crucible/framework/v2/veracity/firewall.py` | n-a | The veracity firewall re-executes a cited proof and can only demote a claim, never promote one. |
| CA-RDM-03 | README | `README.md:247` | TRUE | `integration/vigil_integration/warden_gate.py`::`kernel_classifier` | n-a | The Rust WARDEN classifier is danger-first and by whole words; an unknown action classifies to the strictest tier. |
| CA-RDM-04 | README | `README.md:248` | TRUE | `integration/vigil_integration/conjunctive_gate.py`::`build_offense_gate` | n-a | The conjunctive gate evaluates authority AND tier AND (destructive) threshold; first failure wins and any exception is a DENY. |
| CA-RDM-05 | README | `README.md:277` | TRUE | `integration/vigil_integration/offense_worker.py`::`KeylessOffenseWorker` | n-a | The offense-side worker is keyless by construction, so it can never mint a trusted record. |
| CA-RDM-06 | README | `README.md:329` | TRUE | `integration/vigil_integration/challenge_oracle.py`::`oracle_for` | n-a | Fresh per-run challenges are scoped to BUG_CLASS_CHALLENGE; oracle_for returns None for any other class. The claim states this condition inline, so it is TRUE as written. |
| CA-RDM-07 | README | `README.md:340` | TRUE | `gateway/vigil_gateway/nftables.py` | n-a | The egress gate is a deny-by-default nftables firewall + scope proxy; the sandbox's only route out is the charter-scoped proxy. |
| CA-RDM-08 | README | `README.md:496` | TRUE | `integration/vigil_integration/live/executor.py`::`_TERMINAL_ALLOWLIST` | n-a | The governed terminal admits only local read/inspect binaries; network/interpreter/writer binaries are absent from the allowlist and therefore denied. The generated README allowlist block equals _TERMINAL_ALLOWLIST exactly (verified). |
| CA-RDM-09 | README | `README.md:497` | TRUE | `integration/vigil_integration/live/executor.py`::`execute_terminal` | n-a | terminal.run classifies A2 under the A1 offense ceiling so the conjunctive gate always QUEUES; the operator Run click is the approval. |
| CA-RDM-10 | README | `README.md:658` | SCOPED | `packages/core/vigil_core/vigil_core/doctor.py`::`REQUIRED_CONTROLS` | W9-4 | The production refuse-to-start gate is OPT-IN (inert unless VIGIL_POSTURE=production). Registry W9-4 pins it default=off. |
| CA-RDM-11 | README | `README.md:666` | SCOPED | `integration/vigil_integration/live/egress_guard.py` | W10-8 | The seccomp egress supervisor is off-by-default/opt-in; FORCED ON only under the production posture. Registry W10-8 pins it default=off. |
| CA-RDM-12 | README | `README.md:743` | TRUE | `integration/vigil_integration/uiproxy.py`::`bind_ok` | n-a | The stdlib reverse proxy binds loopback or a private/tunnel address only; bind_ok refuses 0.0.0.0/unspecified/globally-routable. |
| CA-RDM-13 | README | `README.md:864` | UNVERIFIABLE | n-a | n-a | A claim about a past external live-fire run against testasp.vulnweb.com; the offline re-verify of THOSE bytes needs the evidence store / a run and cannot be re-derived from the repo source alone. |
| CA-RDM-14 | README | `README.md:894` | TRUE | `engine/crucible/framework/v2/common/ethics.py`::`require_in_scope` | n-a | Authorization-only posture is code-enforced: require_in_scope applies the categorical protected-domain floor then host_matches_scope; an out-of-scope host is denied. |
| CA-ASB-01 | AS-BUILT | `docs/AS-BUILT.md:86` | TRUE | `packages/core/vigil_core/vigil_core/crypto.py`::`load_public_key` | n-a | load_public_key rejects non-canonical (y>=p) and low-order Ed25519 public keys, closing a keyless forgery against every threshold check. |
| CA-ASB-02 | AS-BUILT | `docs/AS-BUILT.md:88` | TRUE | `integration/vigil_integration/offense_worker.py`::`KeylessOffenseWorker` | n-a | Inert seam: findings cross as validated signature-checked inert data; the offense worker holds no owner key. |
| CA-ASB-03 | AS-BUILT | `docs/AS-BUILT.md:90` | TRUE | `integration/vigil_integration/conjunctive_gate.py`::`build_offense_gate` | n-a | Every target-touching action passes CRUCIBLE-authority AND WARDEN (+ destructive threshold); first failure wins; any error is a DENY. |
| CA-ASB-04 | AS-BUILT | `docs/AS-BUILT.md:91` | TRUE | `integration/vigil_integration/oracle_adapter.py`::`certify_to_scitt` | n-a | P9 oracle confirmation: a proposal becomes a signed FACT only if the deterministic oracle fires over the retained context and the class is oracle-mapped, else a labelled lead. |
| CA-ASB-05 | AS-BUILT | `docs/AS-BUILT.md:114` | TRUE | `integration/vigil_integration/warden_gate.py`::`attach_from_env` | n-a | The Strix shell gate is ON BY DEFAULT and fail-closed: attach_from_env raises WardenGateUnavailable on any wiring failure and stops the run. |
| CA-ASB-06 | AS-BUILT | `docs/AS-BUILT.md:124` | TRUE | `integration/vigil_integration/live/sandbox_exec.py`::`_BWRAP_BASE_FLAGS` | n-a | The sandbox.exec runner runs inside bwrap with --unshare-all (net/pid/ipc/uts/cgroup/user); the network unshare is the load-bearing egress floor. |
| CA-ASB-07 | AS-BUILT | `docs/AS-BUILT.md:308` | TRUE | `integration/vigil_integration/live/sandbox_exec.py`::`_BWRAP_BASE_FLAGS` | n-a | Corrected in W15-3 (#395) from a stale --unshare-net. _BWRAP_BASE_FLAGS uses --unshare-all; pinned by test_sandbox_exec.py::test_argv_shape_enforces_the_floors. |
| CA-ASB-08 | AS-BUILT | `docs/AS-BUILT.md:123` | TRUE | `integration/vigil_integration/live/approval_token.py`::`ApprovalToken` | n-a | The per-action approval token is single-use, action-bound, owner-signed; the gate burns the nonce atomically (O_EXCL ledger). A replayed/rebound/expired token is refused. |
| CA-ASB-09 | AS-BUILT | `docs/AS-BUILT.md:141` | TRUE | `engine/crucible/framework/v2/kernel/sovereignty.py`::`current` | n-a | Every model-egress site routes through kernel.sovereignty (fail-closed); the doc honestly states the DEFAULT tier is still PERMISSIVE, so the claim is TRUE as written. |
| CA-ASB-10 | AS-BUILT | `docs/AS-BUILT.md:146` | TRUE | `engine/crucible/framework/v2/verify/oracles.py`::`iam_escalation_oracle` | n-a | E2 proves the grant path exists via a differential of BFS closures and does not use it; a design commitment, not a missing feature. |
| CA-ASB-11 | AS-BUILT | `docs/AS-BUILT.md:179` | SCOPED | `integration/vigil_integration/destruction_gate.py`::`DestructionAuthority` | W9-5 | The multi-signer destruction quorum is REQUIRED only under VIGIL_POSTURE=production; outside production a 1-of-1 is permitted. Registry W9-5 pins the production-only condition. |
| CA-ASB-12 | AS-BUILT | `docs/AS-BUILT.md:153` | TRUE | `engine/crucible/framework/v2/verify/oracles.py`::`imds_credential_capture_oracle` | n-a | The E-series oracles exist and are fixture-proven offline; the doc honestly discloses no live cloud FACT is claimed, so the disclosure is TRUE as written. |
| CA-PST-01 | POSTURE | `docs/POSTURE.md:16` | TRUE | `integration/vigil_integration/posture/certificate.py` | n-a | A CLOSED posture status requires an applicable oracle with a live channel that did NOT fire (coverage verdict clean, non-empty oracle_kinds_run). |
| CA-PST-02 | POSTURE | `docs/POSTURE.md:32` | TRUE | `docs/proof-carrying-finding/verify_vf.py`::`main` | n-a | The offline binding-tier verifier re-checks the coverage-projection binding; a CLOSED with no conclusive oracle is refused, offline with no VIGIL installed. |
| CA-PST-03 | POSTURE | `docs/POSTURE.md:33` | TRUE | `docs/proof-carrying-finding/verify_vf.py`::`main` | n-a | Honest bound stated in the signed bytes: the offline verifier does not re-fire the oracle; re-firing needs a VIGIL coverage re-run. |
| CA-PST-04 | POSTURE | `docs/POSTURE.md:46` | TRUE | `integration/vigil_integration/posture/certificate.py` | n-a | CLOSED carries its coverage denominator and residual verbatim in the signed bytes; it never means secure-against-everything. |
| CA-PST-05 | POSTURE | `docs/POSTURE.md:73` | TRUE | `integration/vigil_integration/posture/authority.py` | n-a | The Authority-Envelope conformance proof re-derives offline; a forged conformant verdict or an executed action outside the envelope is refused. |
| CA-CTB-01 | CONTRIBUTING | `CONTRIBUTING.md:39` | TRUE | `.github/required-status-checks.txt` | n-a | The canonical file lists exactly 14 checks (verified); test_required_checks_canonical.py asserts every doc count/list agrees with it. |
| CA-CTB-02 | CONTRIBUTING | `CONTRIBUTING.md:45` | UNVERIFIABLE | n-a | n-a | Whether the LIVE branch blocks force-push/deletion is a GitHub setting, not code; offline it is asserted by branch-protection-verify.yml against the API, not re-derivable from repo source. |
| CA-CTB-03 | CONTRIBUTING | `CONTRIBUTING.md:57` | TRUE | `.github/required-status-checks.txt` | n-a | The doc explicitly states required reviews and required signed commits are NOT enforced; the canonical file's header says the same and lists no such control. An honest negative claim. |
| CA-CTB-04 | CONTRIBUTING | `CONTRIBUTING.md:112` | TRUE | `.pre-commit-config.yaml` | n-a | The advisory pre-commit workflow re-runs the identical hooks on the PR, so a --no-verify local skip does not bypass the check. |
| CA-CTB-05 | CONTRIBUTING | `CONTRIBUTING.md:128` | TRUE | `Makefile` | n-a | The pinned benchmark gate must still pass unchanged; make gate is a byte-identical regression spine. |
| CA-SUP-01 | SUPPLY-CHAIN | `docs/SUPPLY-CHAIN.md:367` | TRUE | `integration/tests/test_supply_chain.py` | n-a | CRITICAL findings block; trivy exits non-zero. Asserted statically by test_supply_chain.py in required jobs. |
| CA-SUP-02 | SUPPLY-CHAIN | `docs/SUPPLY-CHAIN.md:368` | TRUE | `integration/tests/test_supply_chain.py` | n-a | HIGH now blocks (raised in W3-9 once the vendored HIGH backlog cleared); the gate-severity tests pin HIGH,CRITICAL. |
| CA-SUP-03 | SUPPLY-CHAIN | `docs/SUPPLY-CHAIN.md:482` | TRUE | `integration/tests/test_supply_chain.py`::`test_every_workflow_action_is_sha_pinned` | n-a | Every uses: in every workflow is a 40-hex SHA; the drift test fails on any tag/branch ref, with a negative control. |
| CA-SUP-04 | SUPPLY-CHAIN | `docs/SUPPLY-CHAIN.md:89` | SCOPED | `infra/supply-chain/image_pins.py`::`main` | W3-8 | Posture updated (W3-8): resolvable Docker Hub drift on a digest-pinned base is ADVISORY (surfaced, not blocking) since the pin already gives a reproducible build; an UNPINNED image still BLOCKS via --check, --fail-on-drift still blocks when armed (proven by the negative control), and an UNKNOWN registry blocks only under --fail-on-unknown. Registry W3-8 pins the posture. |
| CA-SUP-05 | SUPPLY-CHAIN | `docs/SUPPLY-CHAIN.md:566` | TRUE | `integration/tests/test_supply_chain.py` | n-a | A deliberate, disclosed trade: MEDIUM and below are surfaced not enforced; HIGH/CRITICAL block. TRUE as written. |
| CA-SUP-06 | SUPPLY-CHAIN | `docs/SUPPLY-CHAIN.md:132` | TRUE | `integration/tests/test_supply_chain.py` | n-a | pip rejects the whole file if one line lacks a hash; every runtime dep is installed under --require-hashes, asserted by test_supply_chain.py. |
| CA-SUP-07 | SUPPLY-CHAIN | `docs/SUPPLY-CHAIN.md:529` | TRUE | `infra/supply-chain/verify_native_locks.py` | n-a | Build backends are hash-locked in build-backends.lock.txt; verify_native_locks.py checks offline that every direct native dep is pinned in its lock. |
| CA-MAN-01 | MANUAL | `packages/vigil-ui/manual.js:21` | TRUE | `integration/vigil_integration/conjunctive_gate.py` | n-a | Nothing offensive fires on its own; a target-touching/destructive action queues and, on approval timeout, auto-rejects (fail-safe). |
| CA-MAN-02 | MANUAL | `packages/vigil-ui/manual.js:23` | TRUE | `integration/vigil_integration/oracle_adapter.py`::`certify_to_scitt` | n-a | Only an oracle firing over data the real target produced makes a finding a FACT; the AI's opinion stays a LEAD. |
| CA-MAN-03 | MANUAL | `packages/vigil-ui/manual.js:27` | TRUE | `integration/vigil_integration/uiproxy.py`::`bind_ok` | n-a | No part of VIGIL opens itself to the open internet; the proxy binds loopback/private only (bind_ok refuses a public bind). |
| CA-MAN-04 | MANUAL | `packages/vigil-ui/manual.js:42` | TRUE | `engine/crucible/framework/v2/common/ethics.py`::`host_matches_scope` | n-a | host_matches_scope supports literal / *.wildcard / IPv6-literal only; a CIDR entry is not a supported range, and a non-match returns False (deny). Verified. |
| CA-MAN-05 | MANUAL | `packages/vigil-ui/manual.js:85` | TRUE | `integration/vigil_integration/destruction_gate.py`::`DestructionAuthority` | n-a | Opening a PR is gated by an owner-inclusive m-of-n authorization that is single-use, action-bound, and time-boxed. |
| CA-MAN-06 | MANUAL | `packages/vigil-ui/manual.js:106` | TRUE | `engine/crucible/framework/v2/aegis/boundary.py` | n-a | AEGIS Enforce blocks only PROVEN attacks and needs an entitlement; without it it downgrades to Observe, and inspection failure fails open so real traffic still flows. TRUE as written. |
| CA-LAD-01 | LADDER | `engine/crucible/framework/v2/console/api.py:601` | SCOPED | `engine/crucible/framework/v2/console/api.py`::`_REMEDIATION_LADDER` | REM-LADDER | The served ladder shows the tier the WARDEN gate really assigns for each stage; a LEAD can never trigger a code change. Registry REM-LADDER pins ladder<->gate agreement. |
| CA-LAD-02 | LADDER | `engine/crucible/framework/v2/console/api.py:611` | SCOPED | `engine/crucible/framework/v2/console/api.py`::`remediate_plan` | REM-LADDER | The clone/edit/build stages are A2 (above the A1 offense auto-ceiling) so they QUEUE for owner approval; the served tier is the tier the gate really assigns. Registry REM-LADDER. |
| CA-LAD-03 | LADDER | `engine/crucible/framework/v2/console/api.py:626` | SCOPED | `engine/crucible/framework/v2/console/api.py`::`_REMEDIATION_LADDER` | REM-LADDER | open-pr is OFF by default, refused from the console, and needs --open-pr + a token + a separate owner-inclusive m-of-n authorization. Registry REM-LADDER. |
| CA-LEG-01 | LEGAL | `packages/vigil-ui/app.js:2135` | TRUE | `packages/vigil-ui/app.js` | n-a | The in-app New-Assessment authorization gate carries an explicit authorization checkbox; the binding enforcement is the signed charter/scope (next row). |
| CA-LEG-02 | LEGAL | `packages/vigil-ui/app.js:2140` | TRUE | `engine/crucible/framework/v2/authority/gate.py`::`authorize_action` | n-a | The UI text honestly says the checkbox is not the control; authorize_action enforces the signed charter scope (kill-switch, validity window, scope, destructive controls, budget). |
| CA-LEG-03 | LEGAL | `README.md:882` | UNVERIFIABLE | `LICENSE` | n-a | A licensing term (Government-Use Supplemental Term in LICENSE). Its enforcement is legal, not code; there is no code gate that keys on the licensee's sector. |

## SCOPED / FALSE verdicts to file as tracking issues (for the orchestrator)

Per the no-network constraint, these are enumerated here for the orchestrator to file. Every one is already PINNED by an existing claims-registry entry (so it cannot silently drift); the issue is for milestone tracking.

| id | verdict | registry pin | proposed milestone | note |
|---|---|---|---|---|
| CA-RDM-10 | SCOPED | W9-4 | W9 | unless **all eight** of these production preconditions hold |
| CA-RDM-11 | SCOPED | W10-8 | W10 | off-by-default and opt-in outside production |
| CA-ASB-11 | SCOPED | W9-5 | W9 | REQUIRES a genuine multi-signer quorum |
| CA-SUP-04 | SCOPED | W3-8 | W3 | resolvable drift on an already-digest-pinned base is ADVISORY |
| CA-LAD-01 | SCOPED | REM-LADDER | W17 | ONLY an oracle-confirmed FACT with signed evidence is eligible. |
| CA-LAD-02 | SCOPED | REM-LADDER | W17 | above the A1 offense auto-ceiling, so it QUEUES for |
| CA-LAD-03 | SCOPED | REM-LADDER | W17 | OFF by default and NEVER run from this console: |

_Generated from `docs/audit/claim-audit.json`; keep them in sync (the guard checks every row is rendered here with its verdict)._
