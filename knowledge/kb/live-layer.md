# The live layer — the `vigil` super-CLI, the OODA engine, the governed executor, and `vigil up`

## What it is

The **live layer** is the runtime that turns a chartered target into an honest, signed report. It lives
in `integration/vigil_integration/` and has four load-bearing parts: (1) the `vigil` **super-CLI**
(`cli.py` + `dispatch.py`) — one command surface over the two isolated trust planes, routing each
subsystem verb into its own venv by subprocess; (2) the **OODA engine** (`live/engine.py`) — a pure,
attestation-first observe→think→gate→execute→oracle→checkpoint loop over injected seams; (3) the
**governed executor** (`live/executor.py`) — the deny-by-default choke point that spawns exactly six
whitelisted Kali tools against a pinned egress and captures their RAW bytes for the oracle; (4) the
**live factory + federation** (`live/wiring.py` binds the engine to real seams; `uiproxy.py` serves the
whole UI at one origin via `vigil up`). Everything here is **offense-side** — it runs only in
`.venv-offense`, never holds the owner key, and reaches `framework.v2.*` only through lazy,
function-local imports so importing `vigil_integration` in the sovereign venv stays clean.

This page assumes the four system invariants (two-env boundary, oracle authority, gate of record,
determinism + append-only). See [`architecture.md`](architecture.md) for the whole-system framing.

---

## 1. The super-CLI: `cli.py` + `dispatch.py`

`vigil` is the single entry point. Its `main()` (`cli.py:main()`, ~line 830) does one thing before
argparse ever runs: if `argv[0]` is a **passthrough (subsystem) verb**, it forwards to
`dispatch.dispatch` and returns — argparse never sees it, so the sub-CLI's own flags pass through
opaquely (`cli.py:836-838`).

### Native verbs (handled in-process, offense-side)

Each is a `_cmd_*` function wired to a subparser in `build_parser()` (`cli.py:585`):

| Verb | Function | Job |
|------|----------|-----|
| `engage <url>` | `_cmd_engage` (`cli.py:87`) | the attestation-first OODA loop against an authorized target |
| `engage-instruct <slug> <text>` | `_cmd_engage_instruct` (`cli.py:70`) | queue an **advisory** mid-run operator instruction (fires nothing) |
| `provision` | `_cmd_provision` (`cli.py:54`) | mint + sign a CRUCIBLE authority for a slug |
| `verify` | `_cmd_verify` (`cli.py:359`) | per-segment offense-spine integrity + owner-tie view |
| `ledger who\|when` / `verify-ledger` | `_cmd_ledger` / `_cmd_verify_ledger` | replay/verify the usage-attestation chain |
| `detect` | `_cmd_detect` (`cli.py:432`) | run the Detection Mirror over log files (defensive oracle plane) |
| `patch` | `_cmd_patch` (`cli.py:129`) | the gated auto-patch ladder over a **provenance-grounded** finding |
| `provision-destruction` / `authorize-destruction` | — | mint + sign the m-of-n quorum for `patch --open-pr` |
| `proof-export` | `_cmd_proof_export` (`cli.py:462`) | assemble a client-verifiable, offline proof bundle |
| `up` / `down` | `_cmd_up` / `_cmd_down` (`cli.py:496`) | bring the whole UI up at one origin / stop it |
| `knowledge` / `learn-drain` | — | operator-gated `knowledge/` git sync / drain the sovereign→offense learn spool |

`_cmd_engage` builds an `EngineConfig` from the flags (note `--scope` is split to a tuple and defaults
to `("127.0.0.1",)` — it is signed into the authority and enforced end-to-end), calls
`build_engine(cfg)`, then `engine.engage(url, objective=...)`, and prints an honest facts-vs-leads
report (`cli.py:96-126`). A refused engagement exits non-zero.

### Subsystem verbs: per-verb venv routing (`dispatch.py`)

`dispatch.py` is the two-env boundary made mechanical. It is **pure stdlib and exec-only** — it imports
neither `framework`/`strix` nor `sigil`. The `_ENV` table (`dispatch.py:23-29`) is a *hardcoded*
verb→(environment, console-script) map:

```
sigil    → (sovereign, "sigil")            # holds the owner key
crucible → (offense,   "crucible")         # the raw CRUCIBLE arsenal
aegis    → (offense,   "aegis")            # the defensive dual
strix    → (offense,   "strix")            # the agent body
gateway  → (offense,   "vigil-gateway")    # the host egress gate
```

`resolve(verb)` (`dispatch.py:58`) returns `<root>/.venv-<env>/bin/<script>`; `dispatch()`
(`dispatch.py:67`) `subprocess.run`s it, inheriting stdio, and returns its exit code. Two properties are
non-negotiable here:

- **Routing is by construction, not inspection.** An offense verb can never resolve into the sovereign
  venv, or vice-versa, because the table is static. This is why FATAL-2 (co-loading the two trust
  domains in one interpreter) cannot happen through the CLI.
- **The child gets a clean env.** `dispatch()` strips `PYTHONPATH`/`PYTHONHOME` before the exec
  (`dispatch.py:86`) so a parent-side `PYTHONPATH=engine/crucible` can never inject the *other* trust
  domain's modules into the child. `argv` is a **list** (no shell) — subsystem args pass through with no
  injection surface.

**When you touch this:** never add a native verb that imports `framework.v2.*`/`strix`/`sigil` at module
scope. Do the import lazily inside the `_cmd_*` function (every existing native verb does — see the
function-local imports at the top of each). If you add a subsystem, add a row to `_ENV` and build the
console-script in that venv; nothing else changes.

---

## 2. The OODA engine (`live/engine.py`)

`VigilEngine.engage()` (`live/engine.py:168`) is one **attestation-first** loop over a set of injected
seams (`EngineSeams`, `live/engine.py:89`). The engine is deliberately pure: every external capability is
a seam typed as a simple callable, every seam is `Optional`, and **a `None` seam fails closed at its
point of use** (never a fake pass — see the per-field docstrings, `live/engine.py:93-105`). This is what
makes the whole engine unit-testable with fakes and impossible to accidentally wire "open".

The loop, in order (`live/engine.py:168-282`):

0. **Attest first** (`_attest_run`, `live/engine.py:286`). With `require_attestation=True` (the deep-core
   rule), no attestation seam / a denied attestation → the whole engagement is a **recorded refusal**,
   before any target traffic. No attestation → no run.
1. **Think** (`_think`) — the LLM proposes exactly one structured `LLMDecision`. A think error degrades
   to the safest `ASK_USER`, never an action from noise.
2. **Authorize the edge** — `authorize_edge(decision, state, gate=...)` (from `agent/react.py:155`). A
   `queue` outcome is WARDEN's human leg: an offense tool (≥A2), a phase escalation, or a fireteam
   deploy **does not auto-run on the LLM's word** — it proceeds only if `_approved(...)` finds a valid
   signed operator approval, else the run pauses `awaiting_approval` (`live/engine.py:213-233`). A
   `deny` is recorded and the loop **pivots** (never gives up the run).
3. **Execute** — `_run_tool(...)` calls the governed executor seam. A non-`ran` result is a recorded
   refusal.
4. **Oracle intake** (`live/engine.py:258-266`) — the load-bearing anti-hallucination seam.
   `intake_result(raw, analysis, oracle=...)` re-fires the deterministic oracle over the **RAW captured
   stdout**; the LLM's `exploit_succeeded` claim is a **LEAD** until the oracle mints a signed evidence
   ref, at which point it becomes a **FACT**. `apply_intake` folds facts/leads into state.
5. **Project → govern → emit → checkpoint** — FACT-only graph projection (F4), advisory re-rank (F5,
   never gates truth), telemetry span (emit-only), then an append-only signed spine checkpoint (F2b).

After the loop, `_run_detection` (`live/engine.py:439`) runs the AEGIS Detection Mirror over the
target's own logs — an offense FACT paired with a detection FACT. The result is a `RunReport`
(`live/engine.py:122`) that keeps `facts` (oracle-confirmed, signed) and `leads` (proposals) **strictly
distinct**.

**Invariants this file preserves and why:**
- *Only the oracle mints a FACT.* The engine never records a fact from `exec_res.stdout` directly — it
  passes it through `intake_result`, and even a fireteam wave "fact" is admitted only if it carries a
  signed `evidence_ref`, else it degrades to a lead (`_deploy_fireteam`, `live/engine.py:377-384`). If
  you route any new confirmation path, it must go through the oracle seam or carry a signed ref.
- *Fail-closed by construction.* Every seam adapter (`_think`, `_run_tool`, `_project`, `_checkpoint`,
  …) is wrapped so an exception becomes a deny / no-op, never a crash and never a pass. Preserve this
  when adding a seam: catch broadly, degrade to the safe outcome.
- *Determinism.* The engine carries its own `seq` counter and takes no wallclock/RNG in its decision
  math; timestamps live only in the redacted data fields downstream.

---

## 3. The governed executor (`live/executor.py`) — six tools, RAW byte capture

`execute(tool_name, tool_args, phase, ...)` (`live/executor.py:610`, real body `_execute`,
`live/executor.py:643`) is the choke point where a proposed tool call becomes a subprocess — or a deny.
**No byte of a subprocess spawns until every stage passes, fail-closed.** The pipeline
(`_execute`, `live/executor.py:643-709`):

0. **Recordability.** No signer wired → refuse before any spawn (`live/executor.py:651`): an
   unrecordable call is unprovable, so it is not run.
1. **Egress pin** (`_resolve_scoped_target`, `live/executor.py:283`). The target host is derived from
   `tool_args`, resolved with `socket.getaddrinfo`, and the **exact resolved IP is pinned**
   (resolve-once-pin-exact-IP = TOCTOU / DNS-rebind defence). Two modes: with a signed `scope` (threaded
   from the authority by wiring) the host must be in-scope **and** clear the never-liftable egress floor
   (`is_egress_denied(..., loopback_allowed_if_scoped=True)`); with `scope=None` (the fail-closed
   default / unit tests) it is **loopback-only** — every resolved address must be IPv4 `127.0.0.0/8`
   (even IPv6 `::1` is refused). A smuggled second host resolves out-of-scope / to a denied IP and dies
   here.
2. **Authorization** (`authorize_tool_call`, `tools/governance.py:176`) — the phase→WARDEN-tier gate ∧
   the injected conjunctive gate ∧ the m-of-n leg for a destructive tool. Crucially it scopes on the
   **executor-validated hostname** (`_scope_target`, `live/executor.py:373`), *not* the LLM's proposed
   string (AUDIT-G4) — the sovereign decision is made against ground truth. Proceed only on
   `verdict.allowed`.
3. **Argv build + run.** A per-tool builder constructs an argv **list** (never a shell string) from the
   *validated* `_Pinned` components only, so a smuggled `127.0.0.1@evil.com` / `127.0.0.1 evil.com`
   can never reach a non-loopback host. The argv runs through the injected `run` (default
   `subprocess_runner`, `live/executor.py:149`: `shell=False`, timeout + output cap).
4. **Signed, redacted record.** RAW stdout/stderr are hashed; a **redacted** copy (F3 vocabulary +
   tool-specific secret positions masked) is written into a signed append-only `ExecRecord`
   (`live/executor.py:192`, canonical `signing_bytes()` at `:217`). The **RAW** output is returned to the
   caller (in `ExecResult.stdout`) so the oracle can re-fire — the spine record persists no secret.

### The six whitelisted tools

`_BUILDERS` (`live/executor.py:573`) is an exhaustive allowlist — an unknown tool is denied at
`live/executor.py:654-656`. Each builder pins the loopback host and refuses smuggled hosts / unsafe or
missing options (returns `None` → deny):

| Tool | Builder | Notes |
|------|---------|-------|
| `nmap` | `_build_nmap` (`:484`) | `-Pn -n`, validated `-p` port spec, optional `-sV`; host is the pinned `127.0.0.0/8` literal |
| `httpx` | `_build_httpx` (`:497`) | `-json -silent`, URL reconstructed from validated components |
| `nuclei` | `_build_nuclei` (`:503`) | `-jsonl`, `-tags`/`-severity` accepted only as safe CSV tokens |
| `ffuf` | `_build_ffuf` (`:515`) | requires a real **local** wordlist file (`_local_file` refuses a URL); injects `/FUZZ` if absent |
| `sqlmap` | `_build_sqlmap` (`:527`) | `--batch`, bounded `--level`/`--risk`; **destructive** |
| `hydra` | `_build_hydra` (`:544`) | requires a service token; inline `-p` password position is masked in the record; **destructive** |

**Invariants and why:**
- *Two independent gates, both must pass.* Egress pin (step 1) is enforced *before* authorization (step
  2), and the executor re-checks the gate itself (defence in depth vs. the engine). Neither alone is
  sufficient — non-loopback/out-of-scope denies before the spawn; a gate deny/None/exception denies the
  spawn.
- *No shell, ever.* argv is always a list built from validated components. Do not add an option that
  interpolates a caller string into a host/URL position, and never introduce `shell=True`.
- *Total on hostile input.* `tool_args`/model/log data is attacker-influenceable; every path degrades to
  a deny and `execute` never raises (the outer `try` at `live/executor.py:634` converts any internal
  error to a deny).
- *Determinism + no secret on the spine.* The crypto helpers use no wallclock/RNG; `seq`/`now` are
  injected coordinates; the record stores only hashes + redacted text.

---

## 4. The live factory (`live/wiring.py`) — `build_engine`, gate wiring, the tool manifest

`build_engine(config)` (`live/wiring.py:233`) is the offense-side factory that binds the pure engine's
seams to the real sovereign machinery. It is the single place the "which real thing backs this seam"
decisions live, and it degrades honestly — **a missing sidecar leaves a seam `None` (deny / no-fact /
no-run), never faked.** What it wires:

- **attest** → `require_attestation` over the box's persisted operator key + a durable JSONL ledger
  writer (its own append-only hash-chain).
- **gate** → `_build_gate` (`live/wiring.py:459`) calls `conjunctive_gate.build_offense_gate` over the
  signed CRUCIBLE authority's `trust_root`, with the kill-switch wired in. `None` trust_root or a build
  failure → `None` gate → **every tool call denied**.
- **run_tool** → `live/executor.execute`, pre-wired with the gate, a real Ed25519 spine signer
  (`exec_signer`), the tool/destructive manifests, and the signed-authority `offense_scope`
  (`live/wiring.py:305-316`). An owner-approved offense tool runs under `_approval_gate` (`:483`), which
  upgrades a WARDEN `queue` to `allow` but **preserves a CRUCIBLE `deny`** — approval never widens scope.
- **oracle** → `_build_oracle` (`live/wiring.py:503`) → `oracle_adapter.confirm_and_certify`
  (`oracle_adapter.py:81`). Note the AUDIT-G4 posture: the LLM-provenanced `oracle_context` is passed
  `provenance="llm"`, so the oracle still fires (the LEAD is honestly labelled) but an LLM-emitted
  context **cannot mint a signed FACT** — minting a FACT requires reproducing from the executor-captured
  RAW output (`provenance="reproduced"`/`"live_redrive"`).
- **checkpoint** → `VigilCoreSpine.write_state` (append-only, signed). **detect** → the Detection Mirror.
  **project**/**emit** → wired only when Neo4j / an OTLP collector are present, else omitted.

### `DEFAULT_TOOL_VIEW` — the tool→phase manifest

`DEFAULT_TOOL_VIEW` (`live/wiring.py:51`) is the fail-closed phase gate: an unlisted tool, or a tool used
outside its listed phases, is **denied**. `DEFAULT_DESTRUCTIVE_VIEW` (`live/wiring.py:61`,
`sqlmap`/`hydra`/`metasploit`) is authoritative for the m-of-n threshold-destruction leg.
`default_classify` (`live/wiring.py:67`) derives the WARDEN tier from the one shared classifier of record
(`vigil_core.warden_tiers.has_danger_token`) so it can never drift from the sovereign side.

```
nmap/httpx/nuclei/ffuf/curl : [informational, exploitation]
sqlmap                      : [exploitation, post_exploitation]   (destructive)
hydra                       : [exploitation, post_exploitation]   (destructive)
```

**When you add a tool** you must touch **three** places or it fails closed: (1) an argv builder in
`_BUILDERS` (`live/executor.py:573`), (2) a `DEFAULT_TOOL_VIEW` row (`live/wiring.py:51`) with its
allowed phases, and (3) `DEFAULT_DESTRUCTIVE_VIEW` if it can change target state. Add the builder's
smuggled-host / unsafe-option refusal cases to `integration/tests/` alongside the existing executor
tests; add a phase-gate deny test for the out-of-phase case. Copy the shape of an existing recon builder
(`_build_nuclei`) or destructive builder (`_build_hydra`, which shows the secret-position masking
pattern).

---

## 5. `vigil up` — one-origin federation (`uiproxy.py`)

`run_up(...)` (`uiproxy.py:660`) brings the whole VIGIL COMMAND UI up at **one origin** behind a
self-contained stdlib reverse proxy, federating the two trust planes. Like `dispatch`, this module is
**pure stdlib and exec-only** — it imports neither `framework`/`strix` nor `sigil`; the three backends
run as separate OS processes spawned via `dispatch.resolve` in their own venvs, so a single interpreter
never co-loads the two trust domains.

The proxy (`uiproxy.py:route`, `:192`) is the only human-facing listener; it forwards to three loopback
backends:

```
browser ─▶ vigil up proxy (default 127.0.0.1:8770)
             ├─ /sovereign/*      ▶ 127.0.0.1:8733   sigil serve      (SOVEREIGN_PORT, the cockpit)
             ├─ /offense/api/v1/* ▶ 127.0.0.1:8799   crucible api     (API_PORT, gated action plane)
             └─ /offense/*        ▶ 127.0.0.1:8787   crucible console (CONSOLE_PORT, read + SSE plane)
```

Ports are fixed constants (`uiproxy.py:59-63`). The `/offense` split is deliberate: the console (8787)
and the gated api (8799) both use an `/api/` prefix, so the api is disambiguated by its own `/api/v1`
sub-prefix, and everything else under `/offense` goes to the console (see the routing note in the module
docstring, `uiproxy.py:24-32`).

Key behaviors: `run_up` spawns the sigil cockpit first and captures its printed session token
(`_await_token`), then the console + api children (bridging the operator's chosen LLM key/model from the
sovereign side into the keyless offense children via a subprocess, never logged — `_resolve_offense_llm_env`,
`uiproxy.py:530`), then `assemble_serve_dir` (`:153`) writes the runtime bundle (0700 dir, 0600
token-bearing `index.html`) and the proxy serves it. `vigil down` (`run_down`, `:868`) terminates the
tracked pids.

**Invariants and why:**
- *Never a public bind.* `bind_ok` (`uiproxy.py:101`) — a pure-stdlib reimplementation of sigil's
  `daemon.bind_ok` (so this path imports no sigil) — allows only loopback / RFC1918 / CGNAT / IPv6
  ULA+link-local, and **refuses `0.0.0.0`, unspecified, and any globally-routable address**. It uses a
  positive IPv6 allowlist because Python mislabels Teredo/6to4 as private. A public domain is an
  allowlist *string* (`--domain`), fronted by the operator's TLS proxy — never a bind.
- *Strict `'self'` CSP.* `_BUNDLE_CSP` (`uiproxy.py:80`) is `default-src 'self'` with no inline
  script/handlers; the app is CSP-native.
- *Fail-closed hosting.* A `--domain` deploy with no `CRUCIBLE_API_KEY` is refused (`uiproxy.py:679`)
  unless `--insecure-no-api-key` is passed — otherwise the gated offense api would be internet-exposed
  unauthenticated.
- *The offense children never receive the destruction signing key.* `_OFFENSE_ENV_ALLOWLIST`
  (`uiproxy.py:440`) hard-excludes `VIGIL_DESTRUCTION_OWNER_KEY` — a keyless offense process must not be
  able to self-authorize a destructive PR. Base64 file-content creds are materialised to 0600 files with
  fixed names (`_materialise_file_secrets`, `:478`) and the child gets only the path.

**When you touch this:** add a new backend by adding a fixed port constant + a `route()` branch; keep it
loopback-bound and reach it only from the proxy. Never widen `bind_ok`. Never add an env var to
`_OFFENSE_ENV_ALLOWLIST` without confirming a keyless process is *supposed* to hold it.

---

## Gotchas (things that will bite a new dev)

- **Lazy imports are not optional.** Any function that imports `framework.v2.*` / `strix` / `sigil` must
  do so **function-locally**. Module-scope imports of those in a file the sovereign venv loads (anything
  reachable from `vigil_integration.__init__`) break the two-env boundary. `wiring.py` puts every
  `framework.v2.*` import inside a function for exactly this reason (see the header docstring,
  `live/wiring.py:20-24`).
- **A `None` seam is a *feature*, not a bug.** Absence = fail-closed at the point of use. Do not "fix" a
  `None` seam by faking a pass; wire the real dependency or leave it denied.
- **RAW vs redacted is a hard split.** `ExecResult.stdout`/`stderr` are RAW — feed *only* these to the
  oracle. The spine record (`ExecRecord.stdout`) is redacted — never hand it to the oracle, and never
  put RAW bytes on the spine.
- **The default scope is loopback-only.** `execute(..., scope=None)` (every unit test, every direct
  caller) refuses anything that is not IPv4 `127.0.0.0/8`. Only `build_engine` threads a signed
  `offense_scope` that widens this — and even then the metadata/link-local floor is never liftable.
- **`default_classify` labels a tier; the gate's floor/ceiling decide the outcome.** A recon tool is
  `A1` (auto-eligible only if the ceiling allows), everything else `A2`, a danger-token name `A3`. The
  label is corrected to match the kernel, but the final allow/queue/deny still comes from the
  conjunctive gate.
- **`--session` is a partition key, not authority.** It scopes the Neo4j graph partition and prior
  reuse; it grants nothing and never widens scope. Naming a session exactly equal to an unrelated slug
  merges their (advisory, non-authoritative) partitions.
- **Offense `verify` and sovereign `verify` are separate by design.** `vigil verify` covers only the
  offense spine; the sovereign spine is `vigil sigil verify` — a single process cannot co-load both
  trust domains.

---

## The gate chain (for reference)

Every target-touching action passes the conjunctive chain, first-failure-wins:

```
vigil_core/gate.py:conjunctive_decide
  ◂ conjunctive_gate.py:build_offense_gate   (live/wiring.py:_build_gate)
      WARDEN classify → signed-scope + never-liftable egress floor → kill-switch
      → capability latch → owner approval → m-of-n if destructive
  ▸ a signed, redacted ExecRecord on the spine   (live/executor.py:_build_record → ExecRecord)
```

Related: [`architecture.md`](architecture.md) ·
[`../decisions/0001-knowledge-and-embodiment-program.md`](../decisions/0001-knowledge-and-embodiment-program.md).
</content>
</invoke>
