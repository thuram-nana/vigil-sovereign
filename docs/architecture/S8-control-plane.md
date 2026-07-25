# S8 — control plane + entrypoint reconciliation (unification capstone)

## The two user-facing entrypoints

The fused system presents exactly **two** commands, one per trust domain:

| Command | venv | Trust domain | Holds the owner key? |
|---------|------|--------------|----------------------|
| `vigil` | `.venv-offense` | offense control plane | no (keyless) |
| `sigil` | `.venv-sovereign` | sovereign personal core | yes |

`vigil` is **the** control plane. It exposes every subsystem through one surface without ever co-loading both
trust domains in one interpreter (the FATAL-2 boundary):

- **Native verbs** run in-process, offense-side: `engage`, `ledger`, `verify-ledger`, `verify`, `provision`,
  `identity`, `detect`.
- **Passthrough verbs** `exec` the subsystem's own console-script in its **fixed** venv (S1 dispatcher):
  - `vigil sigil …` → `.venv-sovereign/bin/sigil` — the **only** sovereign route.
  - `vigil crucible|aegis|strix|gateway …` → `.venv-offense/bin/…` — offense-side.

## Internal console scripts (not user-facing entrypoints)

`crucible`, `aegis`, `strix`, and `vigil-gateway` remain installed as console scripts **inside the offense
venv**, but they are **internal**: reach them through `vigil <verb>`, which routes to the correct venv by
construction. Invoking them directly bypasses the unified control plane (and, for anything sovereign, would be
the wrong venv entirely). `sigil` is the sovereign user-facing entrypoint (it holds the owner key); `vigil` is
the offense/unified one. This is the reconciliation of the pre-fusion ~8 entrypoints down to two.

## The whole-control-plane boundary guard

`integration/tests/test_control_plane_boundary.py` is the regression guard that keeps the routing invariant
true as verbs are added:

- every passthrough verb resolves to a **fixed** environment — the only sovereign route is `vigil sigil`, and
  no offense verb can ever resolve into `.venv-sovereign` (or vice-versa);
- native and passthrough verbs are **disjoint** (no collision can shadow a native verb or leave one
  unreachable);
- the dispatcher is **pure stdlib, exec-only** (AST-checked): it imports neither `framework`/`strix` nor
  `sigil`, so exec-ing across venvs never co-loads both trust domains in one interpreter.

Together with `integration/tests/test_two_env_boundary.py` (the dependency-graph + real-venv proof that the
sovereign side cannot import the offense engine) and `envs/build_envs.sh`, this pins the LOCKED two-process
boundary end to end.

## Adding a verb — the rule

A new offense capability is a **native** `vigil` verb (in-process, offense-side) or an offense **passthrough**
(fixed to `.venv-offense`). A new sovereign capability is a `sigil` subcommand, reached as `vigil sigil <x>`.
Never add a passthrough that routes a sovereign verb to the offense venv or an offense verb to the sovereign
venv — the guard above will fail the build if you do.
