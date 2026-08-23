# H6 — One normalized Observation record every EXECUTION emits

Programme: STRIX + HEXSTRIKE full production wiring · Slice H6 (`parsed-popping-lemur.md` §H6).
Builds on Phase 0.3 (`integration criterion 4`).

## The claim

> Every external-tool EXECUTION emits ONE normalized record —
> `vigil_integration.live.observation.Observation` — carrying the full provenance set: tool identity +
> **trusted binary digest**, asserted version, target, **args digest**, backend, outcome class,
> raw-output digest, **artifact refs**, normalized proposals, truncation state, and **error/refusal
> reason**. The record is a PROPOSAL/provenance carrier; it structurally cannot hold a FACT.

This is TRUE of the code as of H6:

- **One record, every path.** `run_external_tool` attaches an `Observation` on all four refused paths
  (pre-flight gate, scope gate, loopback-only guard, capability boundary) and on the ran/errored path —
  never a bare `list[ProposedService]`. The four refused paths now thread their refusal reason into
  `error_reason` (previously dropped). Asserted by
  `test_external_tool_runner.py::test_run_attaches_a_canonical_observation` (refused + ran + errored) and
  `::test_local_backend_attests_a_real_host_binary_digest`.
- **Trusted binary digest is real, not a placeholder.** The EXEC BACKEND attests it (the only layer that
  knows where the bytes are): `LocalSubprocessBackend` hashes the resolved host executable that runs;
  `DockerTopologyBackend` reports the digest-pinned `@sha256:` image ref (the bytes that run inside the
  container — the host cannot hash a binary inside a container, so this is the honest attestation).
  Threaded through `ToolOutcome.binary_sha256` → `Observation.binary_sha256`; `""` when the backend
  cannot attest it, never fabricated.
- **Deterministic digests, no wallclock.** `binary_sha256` (file/image bytes), `args_sha256` (injective
  length-prefixed framing over the exact argv), `raw_output_sha256` (injective framing over stdout+stderr).
- **It cannot mint.** The record has NO field that can hold a verdict, signature, or confirmed finding, and
  `outcome_class` is structurally one of `ran`/`errored`/`refused` — never `fact`. Asserted by
  `test_observation.py::test_observation_structurally_cannot_hold_a_fact`. A FACT is minted ONLY by the
  runner's own oracle re-drive crossing `verdict.admit()`; the parser/normalizer emits proposals and LEADs
  and never a FACT (the FP-0 brain canary `test_brain_engine.py` stays `fact_count == 0`).

## Honest partial convergence — why only ONE of the three converges

Three unrelated classes shared the name `Observation`. They are **genuinely different concerns**; merging
them would be lossy, so H6 converges the one record every EXECUTION emits and leaves the other two distinct
(the §H6 instruction: "honest partial convergence beats a lossy merge").

| Class | Concern | Shape | Verdict |
|---|---|---|---|
| `live.observation.Observation` | **What a tool EXECUTION emits** — the normalized run record. | tool/binary/args/output digests, proposals, outcome class. | **Converged (this slice).** The "one record every execution emits." |
| `intel.models.Observation` | **An atomic INTEL datum** that enters the world-model graph. | Admiralty reliability × credibility, polarity (affirms/refutes), subject→relation→object claim, monotonic `seq`. | **Left distinct.** It is the graph-claim currency of the reasoning layer, not a tool run. It has no tool-identity/argv/binary concept, and the run record has no subject/relation/polarity/belief concept. A run record can *feed* an intel datum (via a collector), but they are not one record. |
| `agent_body.interface.Observation` | **The read-only INPUT to the agent-body cycle** (`think → propose → gate → execute → learn`). | a `state: dict` snapshot of "what the body currently sees". | **Left distinct.** It is a research-gated SCAFFOLD that changes no behaviour, and it is the cycle's INPUT, whereas the live record is a tool run's OUTPUT. Forcing an adapter here would merge input with output. |

Convergence target (`live.observation.Observation`) has exactly two consumers today — its producer
(`external_tool.py`) and its tests — so extending the record migrated every consumer with it; no adapter
shim was needed and no caller's behaviour changed.

## FATAL-2 / safety notes

- `live/observation.py` remains **stdlib-only** (no framework import — sovereign-loaded). Digest helpers use
  `hashlib` only.
- `external_tool.py` computes `binary_sha256` with `hashlib`/`shutil` (already imported); no new framework
  import. The runner's framework imports stay function-local.
- Schema bumped `vigil-observation/1` → `/2`. The record is NOT hashed into any certificate (the cert's
  `tool_version` is unchanged), so certificate bytes are unaffected — the brain still mints **0** facts.
