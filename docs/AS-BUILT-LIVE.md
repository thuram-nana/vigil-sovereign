# VIGIL-LIVE — AS-BUILT (honest, live vs deferred)

This records what the VIGIL-LIVE program (§12 of the fusion plan) actually built and validated **live**
against the loopback target, and — with equal care — what is **LEAD-only** or **deferred**. Nothing
here is claimed beyond what the deterministic layer enforces. Everything below was exercised end-to-end
on `127.0.0.1` on 2026-07-21.

The governing invariant is unchanged going live: **the LLM/tools only PROPOSE; only the CRUCIBLE oracle
mints a signed FACT; only the conjunctive gate authorizes an action; only the loopback egress pin lets a
packet out.**

---

## 1. What is LIVE (validated end-to-end)

### The unified engine (`vigil engage`) — one attestation-first OODA loop
`integration/vigil_integration/live/engine.py` + `live/wiring.py` + `cli.py`. A single loop wires the F2
ReAct core through EVERY subsystem and the **real** sovereign seams (no thunks): attest → think → parse
fail-closed → classify+authorize the edge → execute → oracle re-fire → sign FACT (else LEAD) → project →
govern → observe → checkpoint → loop; then the Detection Mirror. A real live run:

```
$ vigil engage http://127.0.0.1:18080/search?q=1 --approve-offense \
      --access-log .../access.log --auth-log .../auth.log
attestation      : 2ad99e97f1c69fded…                 # WS-6 usage record minted BEFORE any action
iterations       : 3   decisions: use_tool, use_tool, complete
tool calls       : 2  (ran=2, denied=0)               # both ran through the REAL gate chain
FACTS (oracle-confirmed, signed): 1                   # SQLi confirmed by boolean_inference over context
LEADS (proposals, unconfirmed)  : 0
detection mirror : facts=7  leads=1                   # 7 signed detection certs over the REAL logs
checkpoints      : 2                                  # state snapshotted to the signed spine
```

Proven live (both by the run above and by `tests/test_engine_live.py`, which runs in CI's
offense process):

| Property | Enforced by | Evidence |
|---|---|---|
| **Attestation-first (WS-6)** — no attestation → no run | `attestation.ledger.require_attestation` | `engage` refuses with an empty run if the ledger cannot be minted+durably written |
| **Real gate (F2/F3)** — in-scope 127.0.0.1 is IN-ENVELOPE, out-of-scope is a hard DENY | `conjunctive_gate.build_offense_gate` over a signed CRUCIBLE authority | `gate("httpx","127.0.0.1")→queue (crucible_allowed=True)`; `gate("httpx","example.com")→deny (crucible_allowed=False)` |
| **No auto-fire of offense tools** — an autonomous agent may never auto-run an A2+ tool | WARDEN (`AUTO_BAR=A1`, offense floor `A2`) | every offense tool QUEUES; it runs only with the operator's `--approve-offense` (the human leg) |
| **Oracle mints the FACT, not the LLM (F2)** — a claimed exploit is a LEAD until the deterministic oracle re-fires | `oracle_adapter.confirm_and_certify` → `boolean_inference` | a firing SQLi `oracle_context` → 1 signed FACT; a non-firing context → stays a LEAD |
| **Scope can't be widened by approval** | `_approval_gate` upgrades only WARDEN `queue`, never a CRUCIBLE `deny` | out-of-scope stays denied even with `--approve-offense` |
| **Signed spine checkpoint (F2b)** | `live.spine_vigilcore.VigilCoreSpine.write_state` | 2 append-only, hash-chained, Ed25519-signed snapshots per run |

### L1 — a real `error_signature` (error-based SQLi) FACT, re-verified 3/3 offline, ZERO external deps
`framework/v2/verify/oracles.py::error_signature_oracle` (`OracleKind.ERROR_SIGNATURE`). `error_based_sqli`
routes to this oracle first. Over the loopback vulnapp (`infra/loopback/vulnapp.py`, a string-concatenated
**SQLite** query), the **first-party executor captured the datastore-error bytes** — the SQLite
`unrecognized token` error a broken injection (`?q=admin'`) surfaces — and the oracle minted a **signed
`error_based_sqli` FACT** alongside a `boolean_sqli` FACT (`differential_response`) and an `xss` FACT
(`reflection_context`); **all three re-verified 3/3 offline**, with **no Caido and no Docker** in the loop.
Reproduce it yourself (the vulnapp bound to `127.0.0.1:18080`):

```
python3 -m framework.v2 scan "http://127.0.0.1:18080/search?q=1" --format json \
    --reverifiable-out /tmp/loopback-rev.json
python3 -m framework.v2 verify /tmp/loopback-rev.json
#  → [OK] error_signature conf=0.880 matches-claim ... re-verified 3/3 certificate(s)
```

This proves the whole error-based pipeline end-to-end on a local target with zero external dependency.
`targets/testphp/charter.md` provisions the **byte-identical external run** against Acunetix's published
`testphp.vulnweb.com` — the same oracle path, but it needs outbound network egress (see §3).

### The deep-core usage ledger (WS-6) — WHO / WHEN / WHAT, non-repudiable
`vigil ledger who|when` and `vigil verify-ledger`. The ledger is the signed spine (kind
`usage_attestation`); it verifies across multiple engagements as one unbroken chain:

```
$ vigil ledger who
  seq=0  os=kali  git=Water Hacker  host=kali  key=349311e69bf1f574…  did=engage → http://127.0.0.1:18080/…  (phase=informational)
  seq=1  os=kali  git=Water Hacker  host=kali  key=349311e69bf1f574…  did=engage → http://127.0.0.1:18080/…  (phase=informational)
$ vigil ledger when
  seq=0  at=2026-07-21T22:27:23…  monotonic=1  (TPM-anchored)
  seq=1  at=2026-07-21T22:27:24…  monotonic=2  (TPM-anchored)
$ vigil verify-ledger
  ledger: 2 records — VERIFIED: link, sign, and never back-date (monotonic non-decreasing)
```

The time is **TPM-anchored** (the box has a TPM; the monotonic counter is hardware-grounded), so a
record cannot be back-dated; it degrades to the software hash-chain when the TPM op is unavailable
(never weaker than the chain).

### The AEGIS Detection Mirror (WS-4) — dual certs over the target's own telemetry
`detection/`. Run over the loopback app's real `access.log` + `auth.log`, the edge-plane oracles minted
**7 signed detection FACTs + 1 LEAD** (sqli/xss/path-traversal/cmd structure, forced-browsing,
scanner-fingerprint, brute-force/spray), each with a re-verifiable PCF certificate and a mandatory
passing benign twin. This closes the self-proving loop: one run produces an **offense FACT** (the SQLi
the engine confirmed) paired with **detection FACTs** (what that class of attack looks like defensively).

### Live substrate (WS-0)
`infra/loopback/vulnapp.py` (a genuine controlled-SQLi/XSS/traversal target on `127.0.0.1:18080` writing
CLF access + auth logs), `targets/loopback/charter.md` (scope `127.0.0.1` only), the OTel sidecar config.

### The six live binders (WS-1) + phase 32 auto-patch (WS-3)
Merged in PR #29 and wired into the engine: the governed loopback-pinned executor, the projection-only
Neo4j writer, the garak/PyRIT subprocess adapter, the OTLP exporter, the live Claude think-step, the real
`vigil_core` spine checkpointer, and the AIxCC auto-patch loop (finding→patch→gated PR→fix-verification
oracle; timeout → REJECT).

---

## 2. What is LEAD-only (the 🟡 bucket — honest by design, not a gap)

- **Detection telemetry/egress planes** (C2, identity-graph, cloud, session-phish): we do not have the
  DC/CloudTrail/NetFlow logs these need, so they are **LEAD-only / deferred** exactly as the AEGIS doc
  §7 states. Only the edge plane (recon + injection + credential) mints FACTs here.
- **`judge_llm` AI-Gauntlet ASR** (F8): a non-deterministic LLM-judge result **never** auto-promotes to a
  FACT; it stays a LEAD until a deterministic `oracle_kind` reconfirms.
- **Cognition governors** (F5): re-rank/defer only — they never gate a finding's truth.

---

## 3. What is DEFERRED to further owner infra (the ⏳ bucket — logic + wiring built; the live *external* piece not stood up)

- **A running *external* graph DB / telemetry collector**: an **embedded, file-backed graph store is now
  BUILT** — `framework/v2/graph/store.py`'s `EmbeddedGraphStore` projects the spine one-way into
  nodes/edges (canonical, no wallclock/RNG, no authority surface) and needs no external database. Only the
  **live external** service is deferred: `Neo4jGraphStore` sits behind the same interface as a `[SCAFFOLD]`
  (every method raises) and the OTLP exporter (`live/otel_export.py`) still wants a running collector. The
  engine degrades these seams to no-op without affecting a run's truth.
- **Live *external* tool execution / a running external red-team service**: the loopback live-fire **did**
  execute real tools and mint + re-verify a real FACT — L1's `error_signature` FACT was minted over
  executor-captured datastore-error bytes and re-verified 3/3 offline, **no Caido and no Docker** (§1). What
  is outstanding is a live **external, network-egress** engagement: real subprocess Kali tools and
  garak/PyRIT (F8) against an off-box target. `targets/testphp/charter.md` provisions the byte-identical
  external run against `testphp.vulnweb.com`; it needs outbound egress the authoring sandbox lacked. (In CI
  the deterministic echo runner validates the gate/oracle/spine wiring without the binaries — byte-identical
  either way.)
- **Live-API-key Claude think-step**: genuinely not exercised live — used in **replay** (keyless) mode here
  (no `ANTHROPIC_API_KEY`). The live path (`live/think_claude.think`) builds a real client when a key is
  present; the provable layer never depends on the model.
- **Signed per-action operator approval token**: genuinely not built — `--approve-offense` encodes the
  operator's *standing* approval for their own chartered loopback. The cryptographic per-action
  signed-approval mechanism (the I4 destruction-gate quorum) plugs into the same seam unchanged.
- **TEE / confidential-computing hardware** (I4): hardware-gated — the software/TPM attestation provider is
  built (§5); SEV-SNP/TDX stay stubbed.

---

## 4. How to run it

```bash
# 1. provision a signed CRUCIBLE authority for the loopback slug (scope = literal 127.0.0.1)
PYTHONPATH=integration:engine/crucible:gateway vigil provision --slug loopback --scope 127.0.0.1

# 2. run an engagement (keyless replay; --approve-offense = the operator's human leg)
vigil engage http://127.0.0.1:18080/search?q=1 --approve-offense \
    --replay decisions.json --access-log <access.log> --auth-log <auth.log>

# 3. prove who used the tool, when, against what — and verify the chain
vigil ledger who ; vigil ledger when ; vigil verify-ledger
```

CI validates the whole loop: the injected-seam engine tests run in the main integration process
(`test_engine.py`, 17 tests), and the live validation over the REAL gate + oracle runs in the offense
process (`test_engine_live.py`, 5 tests, `PYTHONPATH=integration:engine/crucible:gateway`).

---

## 5. Moonshots — now SCAFFOLDED (the 🌙 bucket, upgraded from "blocked")

Each moonshot is no longer merely blocked: it now ships a **built, tested interface plus a working
software fallback / narrow path**, with only the hardware/research frontier stubbed (the stub raises —
nothing is overclaimed). The honest per-item activation runbook is
[`DEFERRED-INFRA.md`](DEFERRED-INFRA.md).

- **Agent body** — `framework/v2/agent_body/interface.py`. `AgentBody` is an interface-only contract
  (`think → propose → gate → execute → learn`) that structurally enforces gate-before-execute. `[SCAFFOLD —
  research-gated]`: a next-gen body still needs the research engine (Claude-Agent-SDK port + a live Kali
  container).
- **Attestation** — `framework/v2/attest/provider.py`. `SoftwareAttestationProvider` **works today** (an
  Ed25519/TPM quote proving integrity + origin; `hardware_backed=False` always; a real trust decision still
  pins the signer out-of-band). `[hardware-gated]`: `SevSnpAttestationProvider` / `TdxAttestationProvider`
  raise until confidential-computing silicon is present.
- **Binary / memory-safety auto-patch** — `framework/v2/remediation_binary/tier.py`. `SanitizerSilenceTier`
  drives the **existing** sanitizer oracle to `confirm_crash` and to earn `remediated_if_silent` (proven by
  oracle *silence*, never asserted). `[research-gated]`: `synthesize_patch` raises — the generative
  localise-and-patch CRS (LLM-guided fuzzing + concolic/SMT) is unbuilt.

The binary CRS, a real TEE, and a next-generation body still genuinely need research/hardware — this
section upgrades the moonshots' status from *blocked* to *scaffolded*, not to *shipped*.

---

## 6. The governed local Terminal + AI chatbot (T2/T3 — MERGED, PR #157)

Now on `main`. A **local-only** inspection shell (it never touches the engagement target) with a
plain-English **AI chatbot** on top, built on the same governing invariant: **the AI proposes; the
allowlist + WARDEN gate + owner approval decide.**

- **`execute_terminal`** (`live/executor.py`) — the authoritative path. Order, all fail-closed: no signer
  wired ⇒ refuse *before* running (an unrecordable command is unprovable) → parse with **NO shell** (refuse
  the whole command on any shell metacharacter, then split on whitespace into an argv list, `shell=False`)
  → **allowlist-validate** to local read/print binaries only (`ls cat head tail wc stat pwd whoami id uname
  echo df du ps uptime grep cut tr`; `find` via a read-only *predicate* allowlist `_FIND_SAFE_PREDICATES`
  where the exec/write predicates `-exec`/`-delete`/`-fprint*`/… are refused **by omission**; `date`/`hostname`
  admitted **bare-only**) → confine `cwd` (no `..`/NUL, must exist) → classify **WARDEN A2** and authorize
  through the conjunctive gate scoped on `127.0.0.1` (A2 **QUEUES** under the A1 ceiling — **never auto**) →
  on approval, run under a timeout + output cap → write a **signed, redacted `ExecRecord`** to the spine.
  Network egress and host-writes are impossible **by construction** — no allowlisted binary can open a socket,
  spawn an interpreter, or mutate a file — so there is nothing to IP-pin. The test suite's **hostile red-pen
  battery** (network binaries, interpreters, writers, shell metacharacters, unsafe `find` predicates, and
  coreutils option-abbreviation bypasses such as `sort --compress=curl` / `--out=`) is **refused across the
  board.**
- **`build_terminal_runtime`** (`live/wiring.py`) — reuses the exact building blocks `build_engine` uses
  (signed CRUCIBLE authority → conjunctive gate at the A1 ceiling → the standing `_approval_gate` →
  vault-sealed spine keypair as the `ExecRecord` signer), loopback-scoped. `gate=None` ⇒ deny every command;
  `signer=None` ⇒ refuse before running.
- **The AI chatbot** (`console/actions.py`) — `terminal_propose(intent)` has Claude return **exactly one**
  candidate command, which is **re-parsed + allowlist-checked exactly like a typed command** (`terminal_dryrun`);
  a hallucinated / prompt-injected off-allowlist command (`rm -rf /`, `curl evil.com`) is **refused here and
  can never run**. `terminal_run` shells `vigil terminal <command> --approve` — the UI **Run** click *is* the
  operator approval. No `ANTHROPIC_API_KEY` ⇒ an honest `need_key` state ("add a key or type a command
  directly"); the direct terminal needs no LLM. The console's `_TERM_*` allowlist is an **advisory mirror**
  for the dryrun badge only (a drifted copy can only mislead the *preview* — `vigil terminal` re-parses with
  the authoritative allowlist at run time; the offense console must not import the executor — FATAL-2).
- **CLI** — `vigil terminal <command> [--approve]` (`_cmd_terminal`). Without `--approve` the command is
  parsed, gated, and **QUEUED** but never run; `--approve` upgrades the A2 queue to allow. Prints the
  `ExecResult` JSON and returns 0 iff it ran. **UI** — the **Terminal** screen (`renderTerminal`, DO group)
  with an *Ask in plain English* card (AI proposes → Run / Edit / Cancel), an *Or type a command* card (live
  dryrun badge), a *SIGNED* output pane, and a read-only signed *history* — the **22nd** screen.
- **Opt-in WARDEN-gating of the Strix `exec_command` shell** (T3): the vendored Strix agent's arbitrary shell
  is now WARDEN-**gateable** via `VIGIL_WARDEN_STRIX_GATE` — **opt-in / gateable, NOT gated by default.**

The *session-omniscient* advanced layer (**T2b** — session Q&A, cross-session knowledge fusion, ASK/DO modes,
a minimize/maximize chat dock, a signed replayable transcript exported in the one-click dossier, teach-mode)
is **roadmap**, not built — see [`VISION.md`](VISION.md).
