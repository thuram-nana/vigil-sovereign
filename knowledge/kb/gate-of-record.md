# The gate of record — the conjunctive authorization chain

## What it is

Every target-touching action in VIGIL — a scan, a fetch, a subprocess spawn, a destructive
operation — passes through **one** authorization composition before a single byte leaves the box.
That composition is the *gate of record*: a pure, fail-closed **conjunction** of independent checks,
**first-failure-wins**, where any error in any conjunct is a `DENY` (never caught-and-continued) and
**only an explicit WARDEN `"auto"` may open the gate**, so a new or unexpected outcome can never
silently `ALLOW`. Nothing self-authorizes; a kill-switch and a never-liftable egress floor always win.
This is invariant #3 of the platform (see [`architecture.md`](architecture.md#the-gate-authorization-model)).

The composition core lives in the **neutral shared** `vigil_core` so BOTH the offense and sovereign
processes import the *same* primitive without a boundary-illegal dependency (before unification S6 it
lived in the offense seam, unreachable to the sovereign side without dragging in the offense engine).
Each process injects its own trust-domain-appropriate thunks.

## Authoritative code paths (the order of checks)

The chain, outermost to innermost:

1. **Pure core** — `packages/core/vigil_core/vigil_core/gate.py:conjunctive_decide()` (line 63).
   Takes two thunks (`crucible_authorize`, `warden_decide`) plus, for a destructive action, a third
   (`destruction_authorize`). Evaluation order, first-failure-wins:
   - `crucible_authorize()` first — its kill-switch step is the absolute stop. Any deny **or raise** →
     `DENY` (gate.py:74-80).
   - `warden_decide()` second — a classifier/gate error is a `DENY`, never a silent pass (gate.py:82-86).
   - `destruction_authorize()` third, **only when `destructive=True`** — a destructive action with no
     destruction gate wired, an errored gate, or an unauthorized result is a `DENY` (gate.py:91-109).
     The authorized check is a **strict `is True` identity test** (gate.py:102), not truthiness.
   - Verdict: `ALLOW` only if `war.outcome == "auto"` (gate.py:111-115); `QUEUE` if in-envelope but
     WARDEN needs owner approval (gate.py:116-117); **any other or unrecognised** WARDEN outcome →
     `DENY` (gate.py:118-120).

2. **Offense wrapper** — `integration/vigil_integration/conjunctive_gate.py:build_offense_gate()`
   (line 71). Wires the three real thunks and returns a per-call
   `gate(tool_name, target_url, destructive=False, *, destruction_action=None, destruction_signed=None)`.
   - Refuses a `None` trust root (conjunctive_gate.py:106-111) — a `None` root would load the CRUCIBLE
     authority **unsigned**, so a tampered scope/window/destructive flag would pass. This was flagged as
     the single biggest fail-open in the seam map.
   - Imports `framework` **lazily** inside the thunk (conjunctive_gate.py:123) so the module stays
     import-clean for the sovereign env, which never calls it — the two-env boundary
     (see [`architecture.md`](architecture.md#the-two-planes-the-locked-safety-boundary)).
   - Loads the authority *verified* via `load_authority_for_gate(slug, trust_root=...)`
     (conjunctive_gate.py:126).
   - **Cross-binds** the destruction leg: the quorum-signed action must name the SAME `target` and
     `engagement_slug` the CRUCIBLE half is scoping (conjunctive_gate.py:148-157), so one `ALLOW` cannot
     pair an in-envelope scope check for target A with a quorum that only authorized target B.
   - The shared `now` is adapted per-leg — a datetime for CRUCIBLE, an epoch float for destruction
     (`_as_datetime`/`_as_epoch`, conjunctive_gate.py:46-68). Feeding one `now` to the leg it was not
     typed for was a confirmed gate bug.

3. **CRUCIBLE authority half** — `engine/crucible/framework/v2/authority/gate.py:authorize_action()`
   (line 60). *Its own* internal order, first-failure-wins (gate.py:79-127):
   1. **kill-switch tripped** → `HALTED` (the absolute stop, checked first, line 80)
   2. outside validity window → `EXPIRED` (lines 87-94)
   3. target host not in `authority.scope` → `out_of_scope` (lines 97-101)
   4. destructive & authority does not permit it → `destructive` (lines 104-108)
   5. destructive on a `LIVE` environment without a second ack → `live_destructive` (lines 109-117)
   6. action budget exhausted → `budget` (lines 120-123)
   7. otherwise → `allowed` (line 126)

   The scope it enforces comes from `load_authority_for_gate()` (gate.py:159): with a `trust_root`
   supplied it takes the **verified** (threshold-signed) load path — an unsigned or tampered document
   fails closed (`AuthorityUnsigned`) and cannot arm an engagement (gate.py:183-185).

4. **Kill-switch** — `engine/crucible/framework/v2/authority/killswitch.py` (`KillSwitch`, line 29).
   A **file on disk**, so a tripped switch survives a crash or restart — there is no in-memory halt a
   reboot could quietly undo. `is_tripped()` (line 44) is fail-closed: it returns CLEAR **only** when
   `os.stat` proves the file genuinely absent (`ENOENT` and friends); any other error (permission
   denied, symlink loop, I/O error) reads as TRIPPED (killswitch.py:56-71). Clearing is a separate,
   logged operator act (`clear()`, line 99).

5. **WARDEN tool gate** — `integration/vigil_integration/warden_gate.py:decide_tool()` (line 70).
   Gates a tool by its **class/name**, not its target (target authorization is the egress gateway's
   job). The SIGIL kernel classifier maps a tool name to a tier `A0..A3` (danger-first, fail-closed to
   A3); an empty/unknown name or garbage classifier output → `A3` `deny` (warden_gate.py:85-93). A
   **raise-only floor** (default `A2`, `DEFAULT_FLOOR` line 42) is applied `max()`-wise
   (`_tier_max`, lines 66-67, 95) — the floor can only ever **raise** a tool's tier, never lower it.
   AUTO iff `tier <= A1 (AUTO_BAR)` **and** `tier <= ceiling` (line 97); the offense ceiling default is
   `A1` (`DEFAULT_CEILING` line 43), so with an A2 floor **every offense tool queues** — offense never
   auto-runs unless the operator explicitly lowers the floor for a twin/staging target.

6. **Threshold-destruction gate (I4)** —
   `integration/vigil_integration/destruction_gate.py:authorize_destruction()` (line 216). The
   highest-consequence gate: a single autonomous (prompt-injectable) worker must never perform an
   irreversible action on its own authority. Requires an **owner-inclusive m-of-n** quorum over the
   exact signed bytes. Five fail-closed properties (destruction_gate.py:229-279):
   - **well-formedness** — exact-type checks, not `isinstance` (`_well_formed`, line 191; the exact-type
     guard at line 199) so a behavior-overriding subclass cannot decouple the binding from the bytes;
   - **action binding** — `auth.matches(action)` (line 242);
   - **validity window** + **dead-man's-switch** (a sleeper authorization exceeding
     `max_authorization_lifetime` is void, lines 246-255);
   - **single-use** — a caller-supplied `is_consumed` nonce check, no permissive default (lines 258-264);
   - **m-of-n threshold + mandatory owner** — `verify_threshold` over the exact bytes, then every
     `mandatory_signer_id` must be among the valid signers (lines 266-277). The mandatory set and quorum
     `trust_root` live in the **immutable, deployment-time** `DestructionAuthority` (lines 78-96), never
     in per-call request data — a worker cannot rename `owner_key_id` to its own.

7. **The never-liftable egress floor** — `gateway/vigil_gateway/denylist.py:is_egress_denied()`
   (line 176). Pure, deterministic (no DNS, no I/O, no clock). Three tiers, checked in this order:
   - **Tier 1a — absolute floor** (metadata `169.254.169.254`, link-local, multicast, reserved,
     unspecified, and their IPv6/embedded-IPv4 forms): checked **first** and **never liftable by any
     scope or opt-in** (denylist.py:204-208). A charter listing one is treated as an injection/mistake,
     not intent.
   - **Tier 1b — loopback**: hard-denied by default; liftable only for an opted-in owner-executor whose
     signed allow-set contains the exact resolved IP (`loopback_allowed_if_scoped`, lines 211-216).
   - **Tier 2 — private/RFC1918/CGNAT/ULA**: denied unless the exact resolved IP is charter-authorized
     (lines 218-221), with an `is_global` backstop (lines 223-227).

   Embedded-IPv4 forms (`::ffff:a.b.c.d`, 6to4, NAT64, `::a.b.c.d`) are unwrapped and re-checked under
   the v4 rules (`_embedded_ipv4`, line 126) so `::ffff:169.254.169.254` cannot slip past a v6-only
   check. `is_hard_denied()` (line 232) renders the static nftables drop set.

## The signed, redacted ExecRecord (the spine write)

An allow is not the end — the action must be **recordable**, or it does not run.
`integration/vigil_integration/live/executor.py:execute()` (line 610, real body `_execute` line 643)
is the choke point. Its own deny-by-default order (executor.py:643-709):

1. refuse if no `signer` is wired — an unrecordable call is unprovable, refused **before any subprocess**
   (executor.py:651-652);
2. refuse an unknown tool (no argv builder, line 654);
3. **egress pin** — `_resolve_scoped_target` (line 283) resolves via `getaddrinfo` and pins the exact
   resolved IP, refusing anything outside the authorized egress **before authorization and before any
   spawn**. With a signed `scope` the host must be in-scope AND clear the never-liftable floor
   (executor.py:347-359); with no scope it is loopback-only, the fail-closed default (executor.py:329-345);
4. **authorize** via `tools/governance.py:authorize_tool_call()` (line 176), which runs the phase gate,
   the tier classification, and then the injected `gate(tool_name, target, destructive)` — scoped on the
   **executor-resolved** hostname, NOT the LLM's proposed string (governance.py:195-221, executor.py:671-674);
5. build a **host-pinned argv LIST** (never a shell string) that reconstructs the target from validated
   components only, so a smuggled second host (`127.0.0.1@evil.com`) cannot survive (executor.py:400-580);
6. run via the injected `run` (`subprocess.run`, `shell=False`), then write a signed, redacted
   `ExecRecord` (`_build_record`, line 594).

The `ExecRecord` (executor.py:192) carries only **redacted** argv/stdout/stderr plus `stdout_sha256`/
`stderr_sha256` content hashes over the RAW captured streams (lines 207-214) — no raw secret ever lands
on the append-only spine. The RAW streams are returned to the caller unredacted **only** so the
deterministic oracle can re-fire over them (`ExecResult`, line 229); the caller feeds only `record`
(redacted) to the spine. `signing_bytes()` (line 217) is canonical (sorted keys, tight separators) so
any caller derives byte-identical signing material. `seq`/`now` are injected deterministic coordinates —
no wallclock/RNG on this path (invariant #4).

## Invariants this subsystem must preserve (and why)

- **Conjunction, first-failure-wins, fail-closed.** Every conjunct must be reachable only via the pure
  core, and any raise inside a thunk must map to `DENY`. If you catch-and-continue anywhere, a broken or
  adversarial conjunct silently opens the gate. Pinned by `packages/core/vigil_core/tests/test_gate.py`
  (a raised conjunct → DENY; unrecognised WARDEN outcome → DENY; missing destruction gate → DENY).
- **Only `"auto"` opens; the strict `is True` on the destructive leg.** A truthy-but-not-`True`
  `authorized` (e.g. `"no"`, `1`, a non-empty list from a buggy/adversarial gate) must NOT open an
  irreversible action (gate.py:102; `test_destructive_truthy_but_not_True_is_refused`).
- **The scope floor cannot be widened by request data.** CRUCIBLE scope is loaded **verified** against
  the governance `trust_root`; the never-liftable egress floor is charter-independent. The `now` passed
  to `build_offense_gate` must be a **trusted-caller** value, never agent/attacker-derived
  (conjunctive_gate.py:94-97) — an attacker-chosen `now` on an out-of-window authority would honor it.
- **The kill-switch is on disk and fail-closed-ambiguous.** Persistence across restart and
  TRIPPED-on-ambiguous-stat are load-bearing — a stealthier or crash-based bypass is the failure mode
  a naive `is_file()` would open.
- **Every allow is a signed, redacted spine record; no signer → no run.** The record is the provable
  link from an action to the bytes the oracle judged. A cleartext secret on the spine or an unrecorded
  run breaks the audit chain and the "the machine cannot lie about a finding" moat.

### How the UI can never widen scope

The console/UI (and the LLM agent) only *propose* a target string. The scope the gate actually enforces
is loaded from the **signed engagement authority** every time, verified against the governance trust
root — `_offense_scope_source` (`live/wiring.py:212`) re-loads it per call and returns an **empty**
scope (deny every target, including loopback) on any load/verify failure. `_build_gate`
(`live/wiring.py:459`) passes only `prov.trust_root` and the operator kill-switch into
`build_offense_gate`; there is no code path by which a UI field, an LLM tool argument, or a request body
alters `authority.scope`. To widen scope you must re-issue the authority document with a threshold of
**governance signatures** — an unsigned or tampered edit fails closed at `load_verified_authority`.
Even the standing-approval knobs (`offense_ceiling`, `owner_approves_offense`, wiring.py:198-209) only
authorize *queued* tools to auto-run; CRUCIBLE scope is enforced regardless, so an out-of-scope target
is denied even with approval granted.

## How to extend it safely

- **Adding a new target-touching action?** Route it through the existing `gate(...)` thunk returned by
  `build_offense_gate` — do not write a second authorization path. If it spawns anything, go through
  `executor.execute()` so you inherit the egress pin, the argv-list build, and the signed record.
- **Adding a new tool?** Register a per-tool argv builder in `executor.py:_BUILDERS` (line 573). Copy an
  existing builder (`_build_nmap`, line 484): reconstruct the target from the validated `_Pinned`
  components only, refuse smuggled hosts and unsafe/missing options by returning `None`, and mark any
  inline-secret argv position so `_redact_argv` masks it (see `_build_hydra`, line 544). Add tests
  mirroring `integration/tests/test_live_executor.py` and `test_executor_scoped.py`.
- **Adding a new conjunct?** Add it as another thunk in `conjunctive_decide` (keep the pure core pure —
  no `framework`/`strix`/kernel imports leak in) and wire the real dependency lazily in
  `build_offense_gate`. It must be **fail-closed** (raise → DENY) and must not be able to *upgrade* a
  deny to an allow — a conjunct can only ever refuse. Add tests to
  `packages/core/vigil_core/tests/test_gate.py` and `integration/tests/test_conjunctive_gate.py`.
- **Touching the egress floor?** Never move a Tier-1a range out of `_ALWAYS_DENY_NONLOOPBACK_NETS`, and
  never make it liftable by scope. Add coverage to `gateway/tests/test_denylist.py`, including the
  embedded-IPv4 evasion forms.
- **Touching the destruction gate?** Keep `DestructionAuthority` immutable and deployment-sourced, keep
  the exact-type (`type(x) is C`) guards, and keep every property fail-closed. Tests:
  `integration/tests/test_destruction_gate.py`.

## Gotchas

- **`vigil_integration.conjunctive_gate` re-exports the pure core** (conjunctive_gate.py:37-43) for
  back-compat. Import the *primitive* (`conjunctive_decide`, `GateVerdict`, …) from either module — they
  are byte-identical — but `build_offense_gate` is offense-only and imports `framework` lazily; **never**
  call it from the sovereign env.
- **A `None` trust root is a hard refusal, not a compat default** (conjunctive_gate.py:106-111). Do not
  "temporarily" pass `None` — it loads the authority unsigned.
- **WARDEN gates the tool *class*, the gateway/egress gates the *target*.** They are orthogonal. Do not
  try to make WARDEN target-aware; scope belongs to the CRUCIBLE authority + the denylist floor.
- **The floor only ever raises a tier** (`_tier_max`). Setting a lower `floor` string cannot make a
  dangerous tool auto-run below its classified tier; it can only relax the *offense minimum*.
- **`now` must come from the trusted caller.** The per-call `gate(...)` has no `now` argument by design —
  the only setter is `build_offense_gate`'s trusted caller (conjunctive_gate.py:94-97). Do not thread a
  request-derived timestamp in.
- **A destructive action with any of `destruction_authority`/`destruction_action`/`destruction_signed`/
  `is_consumed` missing engages no threshold thunk → `conjunctive_decide` DENIES** (conjunctive_gate.py:
  139-141). An irreversible action never slips through on the two base gates alone.
- **The RAW streams in `ExecResult` are for the oracle only.** Feed only `ExecResult.record` (redacted)
  to the spine; never persist `stdout`/`stderr` (executor.py:249-250).

## See also

- [`architecture.md`](architecture.md) — the two planes, oracle authority, and where the gate sits.
- The pure core lives in `vigil_core` so both planes share it — the two-env boundary is *why* it moved
  out of the offense seam (conjunctive_gate.py:9-16).
