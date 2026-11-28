# AEGIS FORGE domain map

This map ties each AEGIS **functional domain** to the **code that implements it** and
to the **slices** (plan §9.3) that build it out. It is an AS-0 governance artifact:
every per-PR stage-0 charter must name the FORGE domain it touches (plan §11.5), and
FORGEMASTER checks concurrency — disjoint manifests, no shared hot file, no shared
token — against the slice-graph JSON before two slices build in parallel (plan §11,
"Concurrency is allowed only when all hold").

Scope note. AEGIS is **wire, don't rebuild** (plan §9.1 rule 10): it reuses the one
VIGIL platform's substrate rather than standing up a second control plane. So a
domain's code lives partly in the AEGIS package
(`engine/crucible/framework/v2/aegis/`) and partly in the shared sovereign plane
(`apps/sigil/`, `packages/core/vigil_core/`, `infra/`). Every path below was verified
to exist in the tree on the AS-0 branch unless explicitly marked **(to build)** with
its owning slice; a to-build path is named so the reuse base is visible, not invented.

Publication note. This file records *where decided architecture lives*. It names no
unfixed weakness and no attack technique (plan §4.7).

---

## Hot sets and tokens (the concurrency keys)

From plan §9.4. A slice may hold at most one of each per wave; two slices that share a
hot file or a token cannot merge in the same wave.

| Key | Meaning | Anchoring files |
|-----|---------|-----------------|
| **GW** | Gateway data plane | `aegis/{gateway,cli,monitoring_authority_check,monitoring_report,boundary}.py` |
| **UI** | Monitoring UI | `apps/sigil/sigil/ui/custui.py`, `.../customer_app/{app.js,guide.js}` |
| **SPOOL** | Drain/spool | `apps/sigil/sigil/inbound/monitoring_spool.py` |
| **FLEET** | Placement/reconciler | `aegis_fleet.py` **(to build — AS-6a)** |
| **MA** | Authority (control plane) | `apps/sigil/sigil/governor/monitoring_authority.py` |
| **SC** | Supply chain | image + closure (AS-28) |
| **INFRA** | AWS platform | `infra/aws/…` |
| **CON** | Contract evaluator | AS-4b |
| **RBAC** | Roles | `apps/sigil/.../governor` RBAC (AS-27b) |
| **VERIFY** (token) | Oracle/verifier core | `engine/crucible/framework/v2/verify/`, `aegis/registry.py` |
| **GP** (token) | Gate path | needs `make gate` evidence (`Makefile`) |

---

## Domain 1 — Gateway / inspection (data plane)

The keyless inline "provable firewall": it sits in front of the tenant's app, runs the
**same** deterministic `verify/` oracles the offensive engine uses (pointed inward),
and blocks only on a fired oracle's certificate.

| Role | Path | Verified |
|------|------|:---:|
| Inline reverse-proxy handler | `engine/crucible/framework/v2/aegis/gateway.py` | yes |
| Request/response oracle inspection | `engine/crucible/framework/v2/aegis/inspect.py` | yes |
| Untrusted-input ingest boundary (hardening + PII redaction) | `engine/crucible/framework/v2/aegis/boundary.py` | yes |
| `detect()` signal→observation→oracle→verdict flow | `engine/crucible/framework/v2/aegis/pipeline.py` | yes |
| Inbound observation producers (Sensor protocol) | `engine/crucible/framework/v2/aegis/sensors.py` | yes |
| WSGI shim + raw `/aegis/detect` boundary | `engine/crucible/framework/v2/aegis/middleware.py` | yes |
| Per-request keyless authority check | `engine/crucible/framework/v2/aegis/monitoring_authority_check.py` | yes |
| Inert metadata-only report sealing | `engine/crucible/framework/v2/aegis/monitoring_report.py` | yes |
| Proof-carrying edge (signed PCF cert per block) | `engine/crucible/framework/v2/aegis/rampart.py` | yes |
| Graduated challenge/throttle (per-actor belief) | `engine/crucible/framework/v2/aegis/response_policy.py` | yes |
| Passive OOB→belief correlation | `engine/crucible/framework/v2/aegis/oob_correlator.py` | yes |
| Shared oracle/verifier core (reused) | `engine/crucible/framework/v2/verify/` | yes |

- **Hot set:** GW. **Tokens:** VERIFY (via `verify/` + `aegis/registry.py`).
- **Slices:** AS-27a break-glass (**merged**, PR #1228) · AS-2j isolated unit · AS-2c
  gateway v2 · AS-2d broker+lock · AS-2e hygiene · AS-3b v2 emission · **AS-5a capacity
  (built — `aegis/capacity.py` per-caller/global load-shedding admission; soft 503 +
  Retry-After, never a block; default-OFF `VIGIL_AEGIS_CAPACITY`)** · **AS-5c probe socket
  (built — `aegis/probe_socket.py` LOCAL owner-only AF_UNIX operational probe socket surfacing the effective mode +
  the AS-5a capacity/admission snapshot off the data-plane HTTP port; read-only, never a block; default-OFF
  `VIGIL_AEGIS_PROBE_SOCKET`)** · **AS-5d outcomes+receipts (built — `aegis/receipts.py` append-only,
  hash-linked ENFORCEMENT-OUTCOME receipt ledger recording the disposition of each enforced request
  [allowed / shed / blocked-by-a-fired-oracle], surfaced read-only on the AS-5c probe snapshot; a receipt
  RECORDS what enforcement did and is never itself a block/verdict; default-OFF `VIGIL_AEGIS_RECEIPTS`)** ·
  **AS-5e impact budget (built — `aegis/impact_budget.py` deterministic READ-ONLY rollup over the AS-5d
  receipt chain: over a bounded recent window it measures the DENIED ratio [shed + blocked] vs a configured
  budget ceiling + a bounded per-reason breakdown, surfaced read-only on the AS-5c probe snapshot; MEASURES,
  never acts — never mutates the ledger and never drives an admit/shed/allow/block decision; inert unless the
  AS-5d receipts dep is also armed; default-OFF `VIGIL_AEGIS_IMPACT_BUDGET`)** · **AS-5b attribution
  (built — `aegis/attribution.py` deterministic READ-ONLY denial-SOURCE rollup: reads the AS-5a per-caller
  buckets and reports which sources drive the current shed/denial pressure [concentration + constrained count +
  a bounded top-N of the heaviest sources as ADDRESS-FREE opaque ids, never a raw caller address], paired with
  the AS-5e per-reason breakdown, surfaced read-only on the AS-5c probe snapshot; MEASURES, never acts — never
  mutates a bucket/receipt and never drives an admit/shed/allow/block decision; inert unless its AS-5a capacity +
  AS-5e impact [and thus AS-5d receipts] deps are also armed; default-OFF `VIGIL_AEGIS_ATTRIBUTION`)** ·
  AS-13b scope. GW chain order: 27a → 2j → 2c → 2d → 2e → 3b →
  5a → 5c → 5d → 5e → 5b → 13b (plan §9.4 chains).

## Domain 2 — Authority / entitlement (control plane)

Who is authorized, in what mode, for how long. The owner signs; the data plane
verifies keyless. The capability wall (own ≠ offense-test ≠ observe ≠ block) is
realized by distinct signing domains.

| Role | Path | Verified |
|------|------|:---:|
| Shared `SignedMonitoringAuthority` contract | `packages/core/vigil_core/vigil_core/monitoring_authority.py` | yes |
| Owner-side authority minting | `apps/sigil/sigil/governor/monitoring_authority.py` | yes |
| Subscription / publish of grants | `apps/sigil/sigil/governor/monitoring_subscription.py` | yes |
| Monitoring secrets (sealing) | `apps/sigil/sigil/governor/monitoring_secrets.py` | yes |
| Domain-separated signing tags (the capability wall) | `packages/core/vigil_core/vigil_core/spine_domains.py` | yes |
| Authority machinery (charter, signing, gate, killswitch, counsel) | `engine/crucible/framework/v2/authority/` | yes |
| Entitlement (`AEGIS_RESPOND` binding/policy/registry) | `engine/crucible/framework/v2/entitlement/` | yes |
| The lease analog the gateway check mirrors | `engine/crucible/framework/v2/launch_lease.py` | yes |
| Kill-switch (control plane) | `apps/sigil/sigil/governor/killswitch.py` | yes |
| Offline enforce-release signer | `enforce_release.py` **(to build — AS-29)** | — |

- **Hot set:** MA. **Tokens:** —. **UI chain** carries the enforce-release step.
- **Slices:** AS-2a authority contracts · AS-2f sovereign v2 · AS-2h sealing · AS-7a
  licence gate · AS-29 enforce release · AS-27b override + `manage_defense`.

## Domain 3 — Drain / spool (sovereign ingest of data-plane reports)

The gateway holds no key; it spools inert reports to the sovereign plane, which drains
them under strict per-tenant domains with quarantine and no global scan.

| Role | Path | Verified |
|------|------|:---:|
| Monitoring report drain | `apps/sigil/sigil/inbound/monitoring_spool.py` | yes |
| Billing spool (reclaim source for drain hardening) | `apps/sigil/sigil/inbound/billing_spool.py` | yes |
| Spool watcher | `apps/sigil/sigil/inbound/spool_watcher.py` | yes |
| Completion spool (sibling pattern) | `apps/sigil/sigil/inbound/completion_spool.py` | yes |

- **Hot set:** SPOOL.
- **Slices:** AS-3a drain strictness (strict domains; quarantine; no global scan) ·
  AS-3c drain hardening (accept-set; DRR; dedup; append-rate budget) · AS-9b receiver.
  SPOOL chain: 3a → 3c → 9b.

## Domain 4 — Fleet / placement (reconciler + where units run)

Reuses the one platform's **frozen shard-assignment mechanics** for placement
(ADR [0002](adr/0002-H1-zones-orchestration-placement.md)); a reconciler renders
placement, never enforcement, and renders enforcement only after a release.

| Role | Path | Verified |
|------|------|:---:|
| Frozen placement mechanics (reused) | `apps/sigil/sigil/governor/shard_assignment.py` | yes |
| Live-migration epoch bump | `apps/sigil/sigil/governor/shard_migration.py` | yes |
| Routing-edge verification | `apps/sigil/sigil/governor/shard_routing.py` | yes |
| Fleet model (authority side) | `engine/crucible/framework/v2/authority/fleet.py` | yes |
| AEGIS fleet / reconciler + worker-kind registry | `aegis_fleet.py` **(to build — AS-6a)** | — |
| AWS platform (zones, keys, roles, EIPs, edge) | `infra/aws/…` **(platform CFN to build — AS-26/AS-34)** | dir yes; platform empty |

- **Hot set:** FLEET. **Tokens:** INFRA (for the AWS stacks).
- **Slices:** AS-6a placement+reconciler · AS-6c edge automation · AS-6e rolling ·
  AS-26 OPS-1 (staging platform) · AS-34 production + rollout. FLEET chain:
  6a → 29 → 6e → 27b; INFRA chain: 26 → 6c → 34.

## Domain 5 — Ingest / receiver (inbound findings/telemetry endpoint)

The inbound side a provider or a detection mirror posts into — behind its own
distribution, with caps and authenticated transport.

| Role | Path | Verified |
|------|------|:---:|
| Finding receiver (offense spine; DM-signer extends it) | `apps/sigil/sigil/inbound/finding_receiver.py` | yes |
| AEGIS ingest service (own distribution; caps; HMAC/mTLS) | `apps/aegis-ingest/` **(to build — AS-9b)** | — |
| Connector secrets broker | `connector_secrets.py` **(AS-9a, on consumer registry)** | yes |
| AWS CloudTrail telemetry source (provider reader; pushes LEADs through the AS-9b receiver) | `framework/v2/aegis/cloudtrail_source.py` **(AS-17b, built)** | yes |
| IdP (Okta System Log) sign-in/audit telemetry source (provider reader; pushes LEADs through the AS-9b receiver) | `framework/v2/aegis/idp_source.py` **(AS-17c, built)** | yes |
| Telemetry-provider runtime (unified append-only provider inventory + fault-isolated fan-out over the armed sources) | `framework/v2/aegis/provider_runtime.py` **(AS-10a, built)** | yes |
| SIEM/notify connector emitter (the broker CONSUMER side) | `notify.py` **(AS-20 — outbound SIEM/notify push client)** | yes |

- **Hot set:** SPOOL (receiver shares the spool chain tail).
- **Slices:** AS-9a broker · AS-9b receiver · AS-20 notify/SIEM emitter (the connector
  CONSUMER — reuses the AS-9a broker to STAMP an outbound credential; adds no OracleKind,
  opens no serve route) · AS-31 Detection Mirror (DM-signer, cert v2 defense delegation at
  `finding_receiver.py`) · **AS-17b AWS CloudTrail telemetry source (built)** — the engine-leg
  provider reader normalizes CloudTrail, pushes INERT LEADs through the AS-9b receiver (no new
  customer route → no Gate-5 census row), and tamper-evidences each record via AS-9c anchor-1;
  DEFAULT-OFF `VIGIL_AEGIS_CLOUDTRAIL`. · **AS-17c IdP sign-in/audit telemetry source (built)** —
  the sibling engine-leg reader for identity-provider (Okta System Log) telemetry; same INERT-LEAD /
  AS-9b-receiver / AS-9c-anchor-1 path, DEFAULT-OFF `VIGIL_AEGIS_IDP`. · **AS-10a telemetry-provider
  runtime (built)** — the unified, append-only provider INVENTORY (EDR + CloudTrail + IdP
  descriptors, each class-5 `detected_without_enforcement` / `reported`) plus a fault-isolated
  fan-out over the armed sources; adds no OracleKind / fleet WorkerKind, DEFAULT-OFF
  `VIGIL_AEGIS_PROVIDER_RUNTIME`.

## Domain 6 — Benchmark (scorecard engine for comparative claims)

Comparative claims are earned, not asserted (ADR [0004](adr/0004-E3-competitive.md)):
every "rivals X" claim needs a signed scorecard against a real competitor on the same
scenarios. The benchmark runs **lazily, off the gate path**.

| Role | Path | Verified |
|------|------|:---:|
| Benchmark harness / runner | `engine/crucible/framework/v2/eval/benchmark_run.py` | yes |
| OWASP benchmark | `engine/crucible/framework/v2/eval/owasp_benchmark.py` | yes |
| Eval gate / corpus / A·B | `engine/crucible/framework/v2/eval/{gate.py,corpus.py,ab.py}` | yes |
| Benchmark narrative (root) | `BENCHMARK.md` | yes |
| AEGIS benchmark (commit-reveal corpora; signed scorecard) | `aegis_bench.py` **(to build — AS-23a)** | — |

- **Tokens:** GP (gate path; needs `make gate` evidence).
- **Slices:** AS-23a early benchmark (arms A/B/G1/G2; CRS & claims gates) · AS-23b full
  benchmark · AS-8 content + coverage.

## Domain 7 — Evidence / records (the DONE record + audit export)

The signed, offline-re-verifiable record is the only thing that makes a capability
DONE (ADR [0005](adr/0005-EV-evidence.md)); the claims registry structurally cannot
hold it (plan §13.2).

| Role | Path | Verified |
|------|------|:---:|
| Audit package / offline verifier | `engine/crucible/framework/v2/evidence/{audit_package.py,audit_offline_verifier.py}` | yes |
| Manifest / claims / chain / certify / retention | `engine/crucible/framework/v2/evidence/{manifest,claims,chain,certify,retention,pcf}.py` | yes |
| Run record (`verification_manifest run`) | `tools/verification_manifest.py` | yes |
| Shared oracle/verifier core (VERIFY token) | `engine/crucible/framework/v2/verify/`, `aegis/registry.py` | yes |
| AS-25 trust root | `docs/evidence/aegis-tt/trust-root.json` **(to build — AS-25)** | — |
| AS-25 verifier | `integration/tests/IT/test_aegis_tt_demonstrations.py` **(to build — AS-25)** | dir yes |

- **Tokens:** VERIFY, GP.
- **Slices:** AS-25 DONE records (signed binding over `verification_manifest`) ·
  AS-11b evidence locker (CertRef; offline verify; flip fails) · AS-14 verification.

## Domain 8 — UI / console (tenant surface + operator console)

The honest, truthful monitoring surface. Customer routes go in the **Gate-5 census**;
operator routes in `ui-wiring-matrix.json` (plan §9.1 rule 2).

| Role | Path | Verified |
|------|------|:---:|
| Customer UI wiring | `apps/sigil/sigil/ui/custui.py` | yes |
| Customer SPA | `apps/sigil/sigil/ui/customer_app/{app.js,guide.js,index.html}` | yes |
| Operator console (api/server/actions) | `engine/crucible/framework/v2/console/` | yes |
| Operator route wiring matrix | `docs/capability-matrix/ui-wiring-matrix.json` | yes |

- **Hot set:** UI.
- **Slices:** AS-4a overclaims copy · AS-2f/2g/2k sovereign v2 / binding+publish /
  settings · **AS-21a retest guard (built — the guarded Re-arm on `#/monitoring/settings`:
  a confirmed renew of a host's authority to the full standard window, reusing the gated
  `monitoring/authorize`; default-OFF `VIGIL_CUSTOMER_MONITORING_ENABLED`)** · AS-3d
  health+ack · AS-4b contract+preview · AS-27b override · AS-6d onboarding. UI chain:
  4a → 2f → 2g → 2k → 21a → 29 → 3d → 4b → 27b → 6d.

---

## Cross-domain: detection content & governance substrate

Two supporting areas that every domain leans on:

| Area | Path | Verified | Note |
|------|------|:---:|------|
| Detection content (Sigma/rules/efficacy) | `engine/crucible/framework/v2/defender/` | yes | AS-17a Sigma v2; AS-17b AWS CloudTrail normalizer + gated `detect_format` (`parse_cloudtrail`); AS-17c IdP (Okta System Log) normalizer + gated `detect_format` (`parse_idp`); AS-7b Coraza |
| CODEOWNERS trust domains (`_CRITICAL_PREFIXES`) | `.github/CODEOWNERS`, `integration/tests/test_codeowners_coverage.py` | yes | AS-0: `aegis/`, `verify/`, `veracity/`, `vigil_core/` are critical prefixes |
| Slice graph (acyclicity, levels, disjoint manifests) | `engine/crucible/framework/v2/aegis/slice_graph.json` + `aegis/tests/test_aegis_slice_graph.py` | yes | AS-0 graph gate (72 slices, 24 waves) |

---

## References

- Plan §9 (program, slices, hot sets, chains), §11 (parallelization & merge),
  §4.7 (publication split) — `parsed-popping-lemur.md`.
- [`AS-0-CURRENT-WORK-INVENTORY.md`](AS-0-CURRENT-WORK-INVENTORY.md) — what exists vs.
  what each slice builds.
- [`CHARTER-TEMPLATE.md`](CHARTER-TEMPLATE.md) — the per-tenant authorization whose
  controls these domains implement.
- [`AEGIS-CRUCIBLE-REUSE-MAP.md`](AEGIS-CRUCIBLE-REUSE-MAP.md) — the reuse rationale
  behind "wire, don't rebuild".
- ADRs [0002](adr/0002-H1-zones-orchestration-placement.md) (platform/zones),
  [0003](adr/0003-E1-engines.md) (engines), [0004](adr/0004-E3-competitive.md)
  (competitive/benchmark), [0005](adr/0005-EV-evidence.md) (evidence).
