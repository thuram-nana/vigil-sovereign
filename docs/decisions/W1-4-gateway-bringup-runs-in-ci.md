# W1-4 — The gateway container bring-up test actually runs in CI

Issue: milestone W1 — CI ENFORCEMENT, item **W1-4** (#413) ·
Registered in the claims registry ([W0-3] #398, id `W1-4`).

## The defect

`gateway/tests/test_docker_bringup.py::test_real_docker_build_and_fail_closed` was gated on
`VIGIL_GATEWAY_DOCKER_IT=1`, an environment variable **set nowhere**. So the container that carries the
egress gate had no *executed* bring-up proof — and a skipped proof and a passing proof are the same
colour on a dashboard. The same silent-skip shape hid four other live/hardware proofs.

## The fix

1. **Run it.** `VIGIL_GATEWAY_DOCKER_IT=1` is now set in a dedicated step of the **required**
   `gateway egress gate (P6)` job, whose GitHub-hosted `ubuntu-latest` runner ships a working Docker
   daemon and Docker Hub egress (the job already pulls apt). The step runs the bring-up test with `-rA`
   so its node id appears in the run report.
2. **Never a silent green.** The test skips **loudly** (a visible, documented skip — not a pass) when the
   daemon or registry are genuinely unavailable, and it is **red** only on a real fail-OPEN (the image
   builds but does not require the scope source). Every docker call is timeout-bounded.
3. **Guard the whole class.** `gateway/tests/test_env_gated_tests_run_in_ci.py` asserts that every
   environment variable a test's `skipif` consults is EITHER set by a CI workflow (so the test runs) OR a
   documented `_CANNOT_RUN_ON_HOSTED_CI` exemption. The four live/hardware proofs (`VIGIL_LIVE_SYSTEMD`,
   `VIGIL_STRIX_SBOM_DOCKER_IT`, `CRUCIBLE_LIVE_FULL_PIPELINE`, `CRUCIBLE_LIVE_HTTP`,
   `CRUCIBLE_LIVE_INTAKE_URL`) that genuinely cannot run on a hermetic hosted runner are documented
   exemptions with real reasons — a LOUD, reasoned skip, never a silent green.

## The claim (registered in the claims registry — [W0-3] #398, id `W1-4`)

<!-- CLAIM:W1-4 -->
> **Registered claim (W0-3 #398):** Every environment variable a test's skipif consults is either set by a CI workflow so the test runs, or a documented cannot-run-on-hosted-CI exemption, and a guard turns the build red otherwise; the gateway container bring-up test's VIGIL_GATEWAY_DOCKER_IT gate is set by the required gateway job.

## Why this is TRUE of the code

- **Enforced by** `_env_gates_without_a_setter` in `gateway/tests/test_env_gated_tests_run_in_ci.py`: it
  returns every env var that gates a test's `skipif`, is set by no workflow, and is not a documented
  exemption. `test_no_test_is_gated_on_an_env_var_no_workflow_sets` asserts that set is empty, and
  `test_the_gateway_bringup_gate_is_set_by_a_workflow` asserts the bring-up gate is set by a workflow
  rather than merely exempted. This runs in the **required** `gateway egress gate (P6)` job.
- **Negative control.** `test_env_gate_guard_is_not_vacuous_negative_control` proves the predicate fires
  when a gated var is set by no workflow and unexempted, and clears when a workflow sets it or it is
  documented-exempt — so the guard is neither a no-op nor always-red.
- **Residual (honest).** The bring-up test builds the gateway image from a Docker Hub base; on a runner
  where that pull is genuinely unavailable it skips LOUDLY (documented) rather than blocking every PR. Its
  EXECUTION therefore depends on the hosted runner having docker + registry access; the guard that keeps
  the gate wired is unconditional.
