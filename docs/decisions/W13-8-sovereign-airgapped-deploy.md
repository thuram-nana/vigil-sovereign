# W13-8 — Sovereign / air-gapped deployment: four customer-sovereignty properties, each a FACADE over an existing mechanism

Issue: [#501](https://github.com/thuram-nana/vigil-sovereign/issues/501) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme).

A customer must be able to run VIGIL entirely on their own terms: install it air-gapped, hold the only keys
that can enable or disable it, prove its identity to an auditor without ever depending on that auditor to
operate, and know exactly what telemetry could leave the box. This slice ships four properties toward that,
each built as a **thin facade over an already-reviewed mechanism** — the W13-2 `sovereign_bridge` rule
("a facade over existing gates, never a second policy engine") applied to *deployment*. No new signing,
verification, or trust math is introduced.

Package: `integration/vigil_integration/sovereign_deploy/` (`bundle.py`, `trust.py`, `attest.py`,
`telemetry.py`). Import-clean (FATAL-2): stdlib + `vigil_core` only — it loads in the sovereign process, and
`integration/tests/test_two_env_boundary.py` names it in its in-process probe.

## Property 1 — offline signed bundles install + verify with NO network

Facade over `vigil_core.signed_build_manifest` (the m-of-n signed build manifest with its six explicit,
fail-closed integrity states and the same `verify_threshold` the signed spine head uses). `assemble_bundle`
lays the signed manifest and the customer trust root beside the artifacts as one transferable directory;
`install_bundle` verifies it OFFLINE and enforces the no-network posture *in code* — the verification runs
inside `no_network`, which swaps every outbound socket primitive for one that raises, so a phone-home
anywhere in the verify path would fail loudly instead of silently depending on a network the air-gapped host
does not have.

<!-- CLAIM:W13-8-1 -->
> Offline, signed deployment bundles install and verify with NO network: `install_bundle` verifies every shipped artifact against a manifest signed under the customer's trust root inside a `no_network` block that makes any outbound socket call raise, and only a manifest that verifies with every artifact matching yields an installed bundle — a tampered, missing, unsigned, or non-customer-signed bundle is fail-closed and NOT installed.

Enforced by `sovereign_deploy/bundle.py::install_bundle`; proved by
`integration/tests/test_sovereign_deploy_bundle.py` (a real signed bundle installs VALID with the socket
layer patched to raise; tampered → MODIFIED, missing → MISSING, unsigned → UNSIGNED_BUILD, non-customer
signature → UNKNOWN_BUILD are each rejected in the same run).

## Property 2 — the trust anchor is CUSTOMER-controlled; there is NO vendor kill switch

Facade over the customer `TrustRoot`. Whether a deployment is operational is a pure function of the
customer's own bundle verifying under the customer's own anchor — `deployment_operational` takes no vendor
input, reads no vendor env var, makes no remote call. There is nowhere to feed a vendor "revoke"/"kill"
signal, so no vendor-held anchor can disable a deployment; `SOLE_OPERATIONAL_AUTHORITY` names the one
authority (`"customer-trust-root"`) and `vendor_key_is_powerless` shows a vendor's key is disjoint from the
operational authorities.

<!-- CLAIM:W13-8-2 -->
> The deployment trust anchor is customer-controlled and there is no vendor kill switch: whether a deployment is operational is a pure function of the customer's own bundle verifying under the customer's own trust root, `deployment_operational` takes no vendor input of any kind, and no vendor-held key is among the operational authorities — so no vendor-held anchor can disable a deployment.

Enforced by `sovereign_deploy/trust.py::deployment_operational`; proved by
`integration/tests/test_sovereign_deploy_trust.py` (operational iff the customer bundle verifies; a vendor
"disallow"/kill env var cannot disable it, contrasted with a straw-man vendor-gated design; an AST scan of
the package finds no vendor-control/phone-home identifier; NEGATIVE CONTROL — a tampered / non-customer-signed
bundle is NOT operational, and a vendor key placed among the anchors is NOT powerless).

## Property 3 — challenge-response attestation rejects a REPLAY, and never blocks an operation

Facade over `vigil_core.crypto` (Ed25519) and the fresh-nonce discipline of `challenge_oracle`. An auditor
issues a fresh single-use nonce; the deployment signs it; `verify_attestation` accepts only a valid
signature over a nonce it has not seen — a replayed valid response is `REJECTED_REPLAY`. The load-bearing
sovereignty half: attestation is advisory and OFF the critical path. `run_operation` runs the operation
unconditionally, so a failed, rejected, or unreachable attestation never blocks it — the operator's OWN
local usage-attestation ledger (`vigil_integration.attestation`) is the fail-closed control; a vendor's is
not.

<!-- CLAIM:W13-8-3 -->
> Challenge-response attestation rejects a replayed challenge — a captured valid response presented against an already-consumed single-use nonce is `REJECTED_REPLAY` — and a failed, rejected, or unreachable attestation never blocks an individual operation: `run_operation` runs the operation regardless of the attestor, so there is no per-operation dependency on a vendor service.

Enforced by `sovereign_deploy/attest.py::verify_attestation` (with `run_operation` for the fail-open half);
proved by `integration/tests/test_sovereign_deploy_attest.py` (a fresh challenge VERIFIES, a replay is
`REJECTED_REPLAY`; a dark/rejected attestor does not block the operation while a VERIFIED attestation cannot
rescue a failing one — proving independence; forged/untrusted/malformed inputs never VERIFY; and the
operation-authorization path does not import the attestation module).

## Property 4 — schema-allowlisted telemetry with an explicit no-collect list

The emission-time complement to the metrics collector (`vigil_integration.telemetry`) and the F3 redaction
vocabulary (`vigil_core.redact`). `build_telemetry_payload` emits only field names on
`TELEMETRY_SCHEMA_ALLOWLIST` (an unknown field is dropped — allowlist, not denylist) and scrubs every
`NO_COLLECT_FIELDS` name at every nesting level (defense in depth). The two lists are disjoint by
construction (asserted at import).

<!-- CLAIM:W13-8-4 -->
> Telemetry is schema-allowlisted with an explicit no-collect list: `build_telemetry_payload` emits only field names on the allowlist (an unknown field is dropped) and scrubs every no-collect field at every nesting level, the two lists are disjoint by construction, and a planted no-collect field is absent from the emitted payload.

Enforced by `sovereign_deploy/telemetry.py::build_telemetry_payload`; proved by
`integration/tests/test_sovereign_deploy_telemetry.py` (NEGATIVE CONTROL — a planted no-collect field is
absent from the payload at top level, nested in an engagement row, and as a count-map label; an allowlisted
field survives so the scrubber is not a no-op; the two lists are disjoint and non-empty).

## Where the tests run — a required CI job

All four proving-test files live under `integration/tests/` and import `framework` nowhere, so they run in
the SOVEREIGN leg of the **required** check `integration two-env boundary (P5)` (`required-status-checks.txt`)
— collected by `python -m pytest -rs integration/tests`, not `--ignore`d. No new required check is minted.

## The claims (registered in the claims registry, W0-3 #398)

The four blockquotes above each carry a claim marker (`W13-8-1` … `W13-8-4`) and are registered in
`docs/claims/registry.json`; `docs/tests/test_claims_registry.py` fails the build if any claim's enforcing
symbol or proving test is missing or its proving test stops running in a required job.

## Honest scope

- `install_bundle`'s offline guarantee is user-space self-verification against a manifest signed by a key the
  running process trusts (the customer's). Like `signed_build_manifest`, it is a tamper-DETECTION aid for an
  honest operator, not a containment boundary against a hostile administrator who controls the same host and
  could replace files, manifest, trust root and verifier together; the out-of-band trust-root pin
  (`VIGIL_BUILD_TRUST_ROOT_SHA256`) is the only mitigation this offers there, and only as strong as the
  channel that delivers the pin.
- `no_network` forbids ALL socket use inside its block (not merely non-loopback), which is sufficient because
  the reused verifier needs no sockets at all; a future consumer that legitimately needs loopback IPC inside
  an offline op would need a narrower guard.
- The `ReplayGuard` is in-memory by default; a durable auditor persists the consumed-nonce set. Replay
  rejection is only as long-lived as the guard the caller keeps.
