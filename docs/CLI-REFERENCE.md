<!-- CLAIM:W16-STD-7-cli-coverage -->
# CRUCIBLE CLI & subsystem reference (W16-STD-7 #533)

This page is the briefing's answer to two questions an operator and a reviewer both ask, and which the
prose chapters left unanswered (limitations inventory §17.16 / §17.17): **what can I actually run, and
what are the parts?** Every command the product exposes is listed here with a one-line, code-grounded
description, in three groups: the **`vigil` native verbs** (§C, 41 of them), the **passthrough verbs**
that route into a subsystem's own CLI (§D, 5 of them — including `crucible`), and the **CRUCIBLE
subcommands** reached through the `crucible` passthrough (§A, 32) plus the CRUCIBLE **subsystems** (§B).
Together they are the ~78 invokable commands the acceptance criteria for W16-STD-7 name. Every CRUCIBLE
subcommand and every CRUCIBLE subsystem is listed here with a one-line, code-grounded description.

Both directions are kept honest by required CI checks (`the briefing explains every agent and capability`)
that enumerate the command sets **from the code** and fail the build when a new one is undocumented — or
when this page documents one the code does not have:

- [`docs/tests/test_briefing_documents_every_subcommand.py`](tests/test_briefing_documents_every_subcommand.py)
  pins §A/§B against the CRUCIBLE `_DISPATCH` dict (`engine/crucible/framework/v2/__main__.py`) and the
  importable sub-packages of `framework/v2`.
- [`docs/tests/test_w16_std7_docs_completeness.py`](tests/test_w16_std7_docs_completeness.py) pins §C/§D
  against the `vigil` argparse sub-parsers (`integration/vigil_integration/cli.py`) and the passthrough
  table (`integration/vigil_integration/dispatch.py` `PASSTHROUGH_VERBS`).

## How to invoke a subcommand

Every subcommand below runs two equivalent ways:

```
vigil crucible <subcommand> [args]          # via the vigil super-CLI passthrough
python3 -m framework.v2 <subcommand> [args] # directly, from engine/crucible with PYTHONPATH=.
```

`vigil <subcommand>` (without `crucible`) is **not** the same: only the native `vigil` verbs run that way;
CRUCIBLE subcommands are reached only through the `crucible` passthrough. (This is the exact trap
[`docs/tests/test_documented_commands_and_screen_count.py`](tests/test_documented_commands_and_screen_count.py)
locks shut.)

## A. CRUCIBLE subcommands (`crucible <name>`)

| Subcommand | What it does |
|---|---|
| `crucible intake` | Normalise an external report / input into the intel graph (the intake pipeline). |
| `crucible memory` | Query and maintain the semantic memory store (embeddings + recall). |
| `crucible intel` | The reason-over-intelligence engine: entity resolution, gated live collectors (crt.sh / DoH / RDAP), the VOI recon planner. |
| `crucible knowledge` | The knowledge / grants engine over the knowledge base. |
| `crucible kernel` | Inspect the low-level engine backends and resolved paths (the CRUCIBLE kernel). |
| `crucible entitlement` | The licence / entitlement system — what a copied or stolen build is allowed to do. |
| `crucible eval` | The evaluation harness: corpus runs, the committed recall/precision baselines, determinism, soak. |
| `crucible improve` | Self-improvement: propose playbook / kernel changes from observed coverage gaps. |
| `crucible defender` | Defensive-analysis surface (the blue-team read of a target). |
| `crucible analysis` | Post-run analysis utilities over an engagement's world model. |
| `crucible authority` | The charter / scope / authority objects that bound every engagement. |
| `crucible socialdefense` | Social-engineering defence analysis. |
| `crucible scan` | The contained / loopback scanner (checks, campaign, opt-in CDP browser passes). |
| `crucible engage` | The full autonomous engagement (the OODA loop) against a chartered target. |
| `crucible plan` | READ-ONLY planner projection over a prior `engage --spine` engagement's world model. Sends no traffic. |
| `crucible verify` | Offline re-verify a signed evidence bundle by **re-firing the oracle** over its retained material. |
| `crucible plan-integrity` | Offline-verify a signed plan-integrity attestation (committed / discovered / skipped / steer-signals). |
| `crucible drift` | Continuous drift: diff the oracle-CONFIRMED fact set between two runs (re-firing each run's certs). |
| `crucible capabilities` | List / manage the capability plugins (the plugin registry). |
| `crucible aegis` | The AEGIS defensive dual (embeddable runtime-defence oracles). |
| `crucible evidence` | Inspect / export / verify the signed evidence tree. |
| `crucible erase-evidence` | W16-8 right-to-erasure: crypto-shred an engagement's at-rest credential-bearing evidence without breaking the append-only spine. |
| `crucible report` | Assemble the executive / technical / remediation reports from the findings. |
| `crucible attack-paths` | READ-ONLY graph triage over the asset topology: shortest attack path, chokepoints, blast radius. |
| `crucible collaborator` | The out-of-band (OOB) collaborator relay used by blind SSRF/XXE/RCE/deserialization checks. |
| `crucible benchmark` | Run the signed benchmark corpus. |
| `crucible calibration` | The confidence-calibration report (predicted vs measured). |
| `crucible console` | The local read-only Ops Console web UI (loopback). |
| `crucible mcp` | The MCP server exposing engine tools over the Model Context Protocol. |
| `crucible api` | The HTTP API server exposing engine operations over HTTP. |
| `crucible imports` | Import external scan outputs / artifacts into the engine. |
| `crucible status` | One-shot environment summary: reachable backends, resolved paths, installed optional deps. |

## B. CRUCIBLE subsystems (the importable sub-packages of `framework/v2`)

Some of these are the module behind a subcommand above; others are internal seams a reader still needs
named so the briefing is not silent about half the system.

| Subsystem (`framework/v2/<pkg>`) | What it is |
|---|---|
| `aegis` | The AEGIS defensive dual — embeddable runtime-defence oracles (`crucible aegis`). |
| `agent_body` | The pluggable agent-body interface (X3) — an interface only; no runtime wired yet. |
| `agents` | The autonomous engagement agents: the OODA `engage` runner, the HTTP executor, the reporter. |
| `analysis` | Post-run analysis utilities (`crucible analysis`). |
| `api` | The HTTP API server (`crucible api`). |
| `attest` | Attestation providers (software/TPM built; SEV-SNP/TDX stubbed) and the monotonic time anchor. |
| `authority` | Charter / scope / authority objects that bound every engagement (`crucible authority`). |
| `calibration` | The confidence-calibration report (`crucible calibration`). |
| `common` | Shared internal plumbing (paths, canonical-JSON helpers, errors, umask) used across the engine. |
| `confidence` | The confidence model that scores a finding before the oracle adjudicates the bytes. |
| `console` | The local read-only Ops Console web UI (`crucible console`). |
| `defender` | The defensive-analysis surface (`crucible defender`). |
| `entitlement` | The licence / entitlement system (`crucible entitlement`). |
| `eval` | The evaluation harness — corpus, baselines, determinism, soak (`crucible eval` / `crucible benchmark`). |
| `evidence` | The signed evidence tree — inspect / export / verify (`crucible evidence`). |
| `graph` | The embedded graph store projecting the append-only spine into nodes/edges (`EmbeddedGraphStore`; Neo4j sits behind a deploy gate). |
| `imports` | Import external scan outputs / artifacts (`crucible imports`). |
| `improve` | Self-improvement — propose playbook / kernel changes from coverage gaps (`crucible improve`). |
| `intake` | Normalise external inputs into the intel graph (`crucible intake`). |
| `intel` | The reason-over-intelligence engine: entities, gated live collectors, recon planner (`crucible intel`). |
| `intruder` | The request-fuzzing / payload-iteration surface (a Burp-Intruder analogue). |
| `kernel` | The low-level engine backends and paths (`crucible kernel`). |
| `knowledge` | The knowledge-base content and assets the engine reads. |
| `knowledge_engine` | The knowledge / grants engine (`crucible knowledge`). |
| `mcp` | The MCP server exposing engine tools over the Model Context Protocol (`crucible mcp`). |
| `memory` | The semantic memory store — embeddings + recall (`crucible memory`). |
| `planner` | The read-only planner projection over an engagement's world model (drives `crucible plan`). |
| `plugins` | The capability-plugin registry (`crucible capabilities`). |
| `remediation_binary` | The binary / memory-safety auto-patch tier (X2: one narrow real class; symbolic repair stubbed). |
| `repeater` | The single-request replay surface (a Burp-Repeater analogue; `repeat_request`). |
| `report` | Assemble the executive / technical / remediation reports (`crucible report`). |
| `scanner` | The contained scanner — checks, campaign, CDP browser passes, lateral-path analysis (fact-free attack-path reasoning, not lateral-movement execution — see [`docs/DELIBERATE-REFUSALS.md`](DELIBERATE-REFUSALS.md) §3) (`crucible scan`). |
| `sensors` | The universal sensors / oracle feed (Nmap / TLS / cloud-IAM / SBOM / threat-intel). |
| `socialdefense` | Social-engineering defence analysis (`crucible socialdefense`). |
| `tools` | Internal tooling / generators used by the engine and its tests. |
| `veracity` | The veracity (anti-hallucination) firewall — RE-EXECUTION, not string trust. |
| `verify` | Offline re-verification — re-fire the oracle over retained certs (`crucible verify` / `drift` / `plan-integrity` / `collaborator`). |
| `worldmodel` | The asset topology / world model projected from the signed spine (drives `crucible attack-paths`). |

<!-- CLAIM:W16-STD-7-vigil-cli-coverage -->
## C. `vigil` native verbs (`vigil <name>`)

These are the verbs the `vigil` super-CLI implements itself (the sub-parsers of
`integration/vigil_integration/cli.py`). They run in-process on the sovereign/integration side (unlike the
`crucible …` passthrough, which forwards to the offense engine). The set below is the authoritative list;
a new sub-parser that is not documented here turns the required check red.

| Verb | What it does |
|---|---|
| `vigil engage` | Run an engagement against an owner-authorized target (loopback or remote). |
| `vigil engage-instruct` | Add a mid-run, natural-language instruction to a LIVE engagement (advisory). |
| `vigil ledger` | Query the usage-attestation ledger (who / when). |
| `vigil verify-ledger` | Verify the usage-attestation ledger's integrity. |
| `vigil verify` | Verify the offense spine segments (per-segment, owner-tie-aware). |
| `vigil verify-integrity` | Continuously verify the spine hash-chain integrity (chain, signed-head freshness, anti-rollback floor, clock skew). |
| `vigil provision` | Mint + sign a CRUCIBLE authority for a loopback slug. |
| `vigil identity` | Export the offense stable identity PUBLIC keys (spine + governance) for owner delegation. |
| `vigil patch` | Run the gated auto-patch ladder over a provenance-grounded confirmed finding. |
| `vigil remediate` | Run the four-state live remediation proof (`--prove`) over a provenance-grounded finding. |
| `vigil reprove` | The continuous re-proof service — loop the four-state live re-proof on a cadence, appending signed results. |
| `vigil floor` | The offense anti-rollback floor ↔ witnessed-checkpoint anchor (`floor witness …`). |
| `vigil witness` | The deployable loopback witness co-sign service (`witness serve --port … --key …`). |
| `vigil approve` | Per-action owner approval for offense tools — sub-verbs `provision-authority` \| `list` \| `sign`. |
| `vigil fireteam` | (W17-7) The Tier-B over-cap escalation resolve loop — sub-verbs `list` \| `approve` (sovereign owner-signs) \| `resolve` (offense applies the signed approval / sweeps deadline expiries). Without a signed approval an escalation still auto-rejects at its deadline (fail-closed). |
| `vigil enroll-cosigner` | (W9-5) Phase 1 — generate a destruction key locally + emit a PUBLIC enrolment request (pubkey + proof-of-possession). |
| `vigil assemble-destruction` | (W9-5) Phase 2 — assemble the m-of-n trust root from public enrolment requests. |
| `vigil request-destruction` | (W9-5) Coordinator — mint the shared unsigned authorization each signer signs detached. |
| `vigil sign-destruction` | (W9-5) Per-signer — sign the shared request DETACHED with this host's key. |
| `vigil combine-destruction` | (W9-5) Coordinator — combine per-host detached signatures into the single-use signed authorization. |
| `vigil provision-destruction` | Mint the m-of-n destruction quorum keys for `vigil patch --open-pr` (prints keys once). |
| `vigil authorize-destruction` | Sign ONE destructive action (from a `vigil patch` dry run) into the single-use signed authorization. |
| `vigil escrow-passphrase` | (W7-7) OPT-IN — split the off-box backup passphrase m-of-n (Shamir split-knowledge) so any `m` of `n` holders can recover it; off by default (a named sovereignty trade-off). |
| `vigil recover-passphrase` | (W7-7) Recover an escrowed backup passphrase from a THRESHOLD set of share files; fail-closed below threshold. |
| `vigil proof-export` | Assemble a client-verifiable proof bundle from a run's oracle-confirmed FACTs (offline, zero-trust re-verify). |
| `vigil dossier` | Compile everything a run produced into one self-contained, tamper-evident `.zip`. |
| `vigil posture` | Certificate of Non-Exploitability — mint (`attest`), `verify` offline, or `serve` a signed posture bundle. |
| `vigil detect` | Run the Detection Mirror over log files (the defensive oracle plane). |
| `vigil cloud-exploit` | Confirm a retained cloud/K8s exploitation capture (`imds`/`secret`/`gcp-sa`/`iam-escalation`/`k8s-rbac`/`k8s-rbac-grant`) → typed verdict + (on a FACT) a signed, offline-re-verifiable certificate. Sends no live traffic. |
| `vigil gauntlet` | Drive the live AI-Gauntlet (offensive-LLM red-team sensor: garak/PyRIT) against an owner-authorized loopback target; honest empty result when no runner is wired. |
| `vigil up` | Bring the whole unified UI up at one origin (self-contained reverse proxy). |
| `vigil down` | CONTAIN a running `vigil up`: stop + disable the systemd unit, then kill the backends + proxy. |
| `vigil services` | Docker bring-up: create the egress gateway + qdrant/neo4j/otel services if none exist (idempotent). |
| `vigil doctor` | Read-only readiness report: prerequisites (binaries, both venvs, writable dirs), UI ports, docker services. |
| `vigil alerts` | Heartbeat-staleness alarms for every HA / scheduled unit (backup, off-host push, drill, HA sync, integrity, posture, reprove). |
| `vigil unit-heartbeat` | Record that a scheduled unit ran (a systemd `ExecStopPost` hook the alerts monitor reads). |
| `vigil telemetry` | Live assurance/metrics collector over the signed spine (G2): fact/lead/refusal/tool snapshots. |
| `vigil panic` | EMERGENCY HARD-STOP: trip every engagement's kill-switch, then mask + stop the command unit and every cadence sidecar. |
| `vigil emergency-stop` | Enter RESTRICTED MODE — a safe landing state between fully-operational and `vigil panic`. |
| `vigil backup` | Off-box backup of BOTH planes → two SEPARATE encrypted files (never a merged archive). |
| `vigil restore` | Restore a two-plane `vigil backup` dir — refuses an unsigned manifest, authenticates against the host trust anchor by default. |
| `vigil upgrade` | Automated crash-safe data migration of the sovereign spine: backup → verify → migrate → verify → report, with rollback. |
| `vigil knowledge` | Operator-gated sync of the living `knowledge/` folder to git (regenerate + secret-scan + commit). |
| `vigil learn-drain` | Drain the sovereign→offense learn-grant spool (the K2b→K3 deep-learn bridge; fail-closed). |
| `vigil sandbox` | Run an arbitrary command inside a network-isolated, workspace-confined bwrap sandbox (A3 → queued for approval). |
| `vigil terminal` | Run a governed LOCAL read/inspect command through the gate (A2 → queued for approval, never auto). |

## D. Passthrough verbs (route into a subsystem's own CLI)

`vigil <verb> …` for these five verbs does not run in-process — it EXECs the subsystem's own console-script
in that subsystem's isolated environment (`integration/vigil_integration/dispatch.py` `PASSTHROUGH_VERBS`),
so the two trust domains are never co-loaded in one interpreter.

| Verb | Routes to |
|---|---|
| `vigil crucible` | The offense engine — every CRUCIBLE subcommand in §A (`vigil crucible engage`, `vigil crucible scan`, …). |
| `vigil sigil` | The sovereign personal core (holds the owner key). |
| `vigil aegis` | The AEGIS defensive dual (`detect` / `gateway` / `demo`). |
| `vigil strix` | The vendored agent body, run through the VIGIL runtime adapter (sandbox-net pin, model/sovereignty gate). |
| `vigil gateway` | The host egress gate. |

## E. The HTTP API and the web surfaces

CRUCIBLE also exposes an HTTP surface (`crucible api`, the loopback gated API) and several dedicated web
surfaces (the `vigil up` command-UI proxy, the Ops Console, the AEGIS gateway, the posture endpoint, the
witness service, the MCP server). All of them are documented in [`docs/HTTP-API.md`](HTTP-API.md).

For the full behaviour and honest scope of each, see [`docs/FEATURES.md`](FEATURES.md) and
[`docs/AS-BUILT.md`](AS-BUILT.md); for the deferred pieces and their activation runbooks see
[`docs/DEFERRED-INFRA.md`](DEFERRED-INFRA.md). For a map of the whole documentation set see
[`docs/INDEX.md`](INDEX.md); for a plain-language dictionary of the terms above see
[`docs/GLOSSARY.md`](GLOSSARY.md).
