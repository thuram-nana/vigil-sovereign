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
| **CON** | Contract evaluator | AS-4b (built — `vigil_core/contract_eval.py`) |
| **RBAC** | Roles | `packages/core/vigil_core/vigil_core/rbac.py` (AS-27b built — `manage_defense`) |
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
  `VIGIL_AEGIS_PROBE_SOCKET`)** · AS-5d/5e/5b
  outcomes · AS-13b scope. GW chain order: 27a → 2j → 2c → 2d → 2e → 3b →
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
  licence gate · **AS-29 enforce release (built — the UI-chain increment: the customer
  **Release to enforce** control on `#/monitoring/settings`, a confirmed in-place release
  of a host from the always-safe Observe base into enforce/Respond, reusing the gated
  `monitoring/authorize` write in the enforce mode `block` with no `window_s`; shown only
  on a Respond-entitled plan and only while the host is in Observe; default-OFF
  `VIGIL_CUSTOMER_MONITORING_ENABLED`. The offline release signer `enforce_release.py`
  above [separate release root, D30] remains future work on this slice)** · **AS-27b
  override + `manage_defense` (built — the `manage_defense` RBAC capability in
  `vigil_core/rbac.py` [owner + founder, disjoint from offense and from billing-only
  org_admin] + the read-only defense-control evaluator `vigil_core/defense_control.py`
  grading, over the SAME gated monitoring reads, each host's live-enforcement posture and
  whether an authorized safe-direction STAND-DOWN [the `override`] would apply; surfaced on
  the customer **Defense control** screen `#/monitoring/control`, which stands nothing down —
  a real stand-down stays behind the owner-signed gate; default-OFF
  `VIGIL_CUSTOMER_MONITORING_ENABLED`. The FLEET-level override/relocate over the AS-6a/AS-6e
  reconciler remains future work on this slice)**.

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
  `monitoring/authorize`; default-OFF `VIGIL_CUSTOMER_MONITORING_ENABLED`)** ·
  **AS-29 enforce release (built — the guarded Release to enforce on
  `#/monitoring/settings`: a confirmed release of a Respond-entitled host from Observe
  into enforce/Respond, reusing the gated `monitoring/authorize` in the `block` mode with
  no `window_s`; default-OFF `VIGIL_CUSTOMER_MONITORING_ENABLED`)** ·
  **AS-3d health+ack (built — a Host health section + a per-viewer Acknowledge on the
  `#/monitoring` screen, DERIVED entirely from the two reads the screen already makes
  [`monitoring` grants/hosts + `monitoring/events`]: an honest health badge [live authority;
  lapsed proof] and last-report fact, plus a client-side mark-as-seen of a host's latest
  confirmed attack — no route, no write, no new authority; default-OFF
  `VIGIL_CUSTOMER_MONITORING_ENABLED`)** ·
  **AS-4b contract+preview (built — the AS-4b protection-contract EVALUATOR
  [`vigil_core/contract_eval.py`: the headline as the FLOOR of the six dimensions, enforcement
  `effective` as the fail-closed AND of its terms, and a per-host enforce/observe preview] + a
  READ-ONLY **Protection preview** screen `#/monitoring/preview` that renders the SERVER's grade,
  over the SAME gated monitoring reads, of what AEGIS does now [observe] and what releasing to
  enforce WOULD add [derived from the provider registry], whether a release would be permitted and
  why not — it mints/arms/releases nothing [the Release stays behind AS-29's gate], owns its own
  read `api/customer/monitoring/preview`, manager-only, no button, default-OFF
  `VIGIL_CUSTOMER_MONITORING_ENABLED`)** · **AS-27b override (built — the read-only
  **Defense control** screen `#/monitoring/control`, the SAFE-direction mirror of AS-4b:
  per host the manager can act on, whether AEGIS is enforcing now and whether an authorized
  stand-down [the safe-direction override] would apply, graded by `vigil_core/defense_control.py`
  over the SAME gated monitoring reads; `manage_defense` [vigil_core/rbac.py] names who may
  OPERATE the live defense. Stands nothing down, renders no button, owns its read
  `api/customer/monitoring/control`, default-OFF `VIGIL_CUSTOMER_MONITORING_ENABLED`)** ·
  AS-6d onboarding. UI chain: 4a → 2f → 2g → 2k → 21a → 29 → 3d → 4b → 27b → 6d.

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
