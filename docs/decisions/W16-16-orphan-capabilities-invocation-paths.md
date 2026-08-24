# W16-16 (#522) — orphaned capabilities get an invocation path

**Status:** implemented.
**Context:** the readiness audit (`docs/plain-english/_review/OUTSTANDING.md` A-8) found real, tested
capabilities reachable from no command, route, or button — "we built six cloud-exploitation confirmations
that nothing can currently call." A capability nothing can invoke is dead code wearing a claim. This decision
records what was genuinely orphaned, how each was resolved, and the structural guard that keeps a new orphan
from shipping.

## Verify-before-build: the measured state (as of this change)

| Capability | State found | Resolution |
|---|---|---|
| `vigil posture` | **already wired** — a first-class dispatch verb (#546, `cli.py:_cmd_posture`) | none (registered) |
| `web_redrive` | **already wired** — invoked by the proof-minting pipeline (`proof/run.py:_web_redrive_mint`) inside `vigil engage` | none (registered) |
| `secret_verify` (E5) | partially wired — a `tools/livefire` harness calls it | **`vigil cloud-exploit secret`** |
| `rbac_verify` / `grant_verify` (K8s T1/T2) | partially wired — a `tools/livefire` harness calls them | **`vigil cloud-exploit k8s-rbac[-grant]`** |
| `imds_verify` (E1) | **ORPHAN** — imported only by its own tests | **`vigil cloud-exploit imds`** |
| `gcp_impersonation_verify` (E3) | **ORPHAN** — imported only by its own tests | **`vigil cloud-exploit gcp-sa`** |
| `iam_escalation_verify` (E2) | **ORPHAN** — imported only by its own tests | **`vigil cloud-exploit iam-escalation`** |
| H4 audit package (`build_audit_package`) | **ORPHAN** — imported only by `evidence/__init__.py`'s re-export + tests | **`python3 -m framework.v2 evidence audit-package`** |
| AI-Gauntlet (`run_gauntlet_report`) | **ORPHAN** — no caller outside its own package + tests | **`vigil gauntlet`** (live runner honestly deferred, see below) |
| ~20 builtin sensors | **not orphaned** — see "sensors" below | documented + registered |

## The six cloud/Kubernetes exploitation confirmations → `vigil cloud-exploit`

Each confirmation re-derives a FACT over an ALREADY-CAPTURED, WARDEN-gated evidence dict — it sends no live
traffic. The verb `vigil cloud-exploit <imds|secret|gcp-sa|iam-escalation|k8s-rbac|k8s-rbac-grant> --capture
<file.json>` reads the retained capture, resolves the run's governance signers (or `--signer` / `--no-sign`),
runs the confirmation, prints a typed verdict, and on a FACT writes a signed certificate that re-verifies
OFFLINE (`vigil verify` / the veracity firewall). A malformed/partial capture is admitted a LEAD/INCONCLUSIVE,
never a FACT.

**Residual (honest):** the LIVE capture — actually reaching the metadata endpoint / STS / kube-apiserver — is
the credential-gated `tools/livefire` half and needs real cloud/K8s credentials on an authorized host. This
verb is the pure, offline re-derivation half; it is a real invocation path regardless of whether a live
capture is available.

## The H4 external-audit package → `evidence audit-package`

`python3 -m framework.v2 evidence audit-package --report <r> --out <dir> --signer <k> --trust-root <tr>`
assembles a self-contained package (signed certs + chain + SCOPE/CHARTER/RUNBOOK + evidence + a standalone
`verify_offline.py`). **Residual (honest, already documented in the shipped RUNBOOK):** the standalone verifier
proves authenticity + binding + integrity + chain with NO VIGIL import; *reproduction* (re-firing each oracle)
still needs the open-source VIGIL verifier. The verb is a real invocation path; the residual is a property of
H4 itself, not of the wiring.

## The AI-Gauntlet → `vigil gauntlet`

`vigil gauntlet --tool garak --target http://127.0.0.1:PORT [--runner-cmd <wrapper>]` drives the offensive-LLM
red-team sensor against an owner-authorized loopback target (egress-pinned; a non-loopback target is refused)
and prints its honest report. **Residual (honest):** the live garak/PyRIT runner image is deferred infra
(`docs/DEFERRED-INFRA.md` — "the LLM-red-team tools"). WITHOUT `--runner-cmd` (or if the tool is not
installed) the adapter reports `available: false` and mints ZERO findings — it never fabricates one. The verb
(the invocation path) exists regardless of the deferred runner; FACT vs LEAD is decided by the deterministic
oracle inside the sensor, never by ASR.

## The ~20 builtin sensors — MCP is NOT the sole interface

The builtin sensors (`sensors.builtin.register_builtin_sensors`: nmap, nuclei, zap, burp, tshark, sbom, mobsf,
cloud posture/inventory, kube-bench, cicd, cert-scan, android-manifest, mesh, email-auth, identity, fuzz, …)
are **registered in a `ToolRegistry`, not orphaned.** Their invocation paths are:

1. **The engagement reasoning loop** — `engage_autonomous.py` drives them from `default_registry()`; every
   invocation passes `run_sensor`'s kill-switch / entitlement / scope / egress gate chain. This is the primary
   interface. There is deliberately **no per-sensor `vigil <sensor>` verb**: the reasoning OS *orchestrates*
   the sensors (it selects and sequences them); exposing each as a standalone verb would bypass the planner
   that decides when a sensor is in-scope.
2. **The capability catalog verb** — `python3 -m framework.v2 capabilities [--kind sensor]` (i.e.
   `vigil crucible capabilities`) enumerates every installed sensor, so an operator can see the whole roster.
3. **A SAFE SUBSET via MCP** — the `framework.v2 mcp` EXPOSE server advertises ONLY the Tier-1,
   entitlement-free, non-destructive, no-egress sensors (an allowlist; the active nmap/nuclei/zap/burp/cloud
   sensors are *not* MCP-exposed). Every MCP-exposed sensor is the SAME registry object the engage loop uses,
   so **MCP is an additional read-only surface, never the sole interface.**

**Decision on (d):** MCP is *not* the intended sole interface for any sensor; there are zero MCP-only sensors.
"Registration is not invocation" is already the documented model (`tools/profile.py`) — the sensors are
invoked through the engagement loop and enumerable through the `capabilities` verb, with a safe subset
additionally reachable over MCP.

## The structural guard (criteria b + c)

`integration/tests/test_capability_invocation_paths.py` enumerates the registered capabilities and asserts
each has ≥1 real invocation path:

* the cloud/K8s confirmations are enumerated **automatically** from `docs/capability-matrix/evidence-branches.json`
  (any branch whose `implementation_refs` name a `live/*_verify.py:<fn>` producer), so a NEW confirmation with
  no caller reddens CI with no test edit;
* the named product capabilities are enumerated from `docs/capability-matrix/invocation-paths.json`;
* "has a caller" is decided by the **Python AST** (a `Name`/`Attribute`/`ImportFrom`, never a comment or
  docstring, and re-export `__init__.py` facades are excluded) — so deleting the real call that wires a shipped
  capability reddens the test even if a prose mention survives. `test_ast_detector_is_not_a_no_op` is the
  self-contained negative control.

The guard is framework-free and runs in the required P5 "integration two-env boundary" job; the verb
behaviour is proved end-to-end by `integration/tests/test_cloud_exploit_verb.py` (offense leg) and
`engine/crucible/framework/v2/evidence/tests/test_audit_package_cli.py` (CRUCIBLE-core job).

## Registered claim

<!-- CLAIM:W16-16 --> Every registered exploitation-confirmation capability, the H4 audit package, and the AI-Gauntlet is invocable from the product, and a framework-free structural CI guard enumerates the registered capabilities from the capability matrix and reddens when any becomes orphaned (its only references its own module and tests), using an AST caller-detector that ignores docstring mentions and re-export facades, with a self-contained negative control proving the detector is not a no-op.
