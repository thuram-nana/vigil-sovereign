# AS-0 current-work inventory

An honest accounting of what AEGIS code **exists in the tree today** versus the
**72-slice production program** still to build (plan §9.3). This is an AS-0 governance
artifact: it exists so that progress is never overstated — a slice that compiles, or
whose engine is installed, reads as "implemented but not validated" until its signed
record exists (the five states, ADR [0005](adr/0005-EV-evidence.md); plan §13.7).

Every number and path below was derived by listing and counting the tree on the AS-0
branch, not from memory. Nothing here describes an unfixed weakness or an attack
technique (plan §4.7).

---

## 1. What exists today: the AEGIS package (`engine/crucible/framework/v2/aegis/`)

AEGIS starts from **one partially built path** — an inline gateway per `(org, host)`
using VIGIL's deterministic oracles, hosted nowhere and below the production bar
(ADR [0001](adr/0001-scope.md), "Context"). That code is real and tested; it is not
yet DONE in the §13.1 sense (no end-to-end run through VIGIL on staging with a signed
record).

**Size (measured):**

| Part | LOC |
|------|----:|
| Modules (19 `.py`, non-test) | 4,624 |
| Tests (40 files) | 7,430 |
| `slice_graph.json` (AS-0 graph gate) | — |
| **Package total** | **~11.5K** |

### 1.1 Modules (each with its one-line job)

| Module | LOC | What it does |
|--------|----:|--------------|
| `gateway.py` | 868 | The inline reverse-proxy "provable firewall": inspects each request with the deterministic `verify/` oracles and blocks only under a fired oracle + release; carries the AS-27a break-glass. |
| `inspect.py` | 653 | Turns a live HTTP request (and, in the response-side classes, its proxied response) into a `Verdict` by running the same oracles the offensive engine uses, pointed inward. |
| `cli.py` | 469 | The `python3 -m framework.v2 aegis` entry (additive, off the gate path): `detect` one envelope, or run the `gateway`. |
| `models.py` | 279 | The typed surface (pydantic `extra="forbid"`): `ActorRef`, `Surface`, `Verdict`, `CertRef`, `LLMInteraction`, `AuthActivity`, `AegisConfig` — honesty properties enforced by construction. |
| `boundary.py` | 273 | The untrusted-input ingest boundary: treats all tenant-forwarded content as hostile, fails closed on malformed input, redacts PII. |
| `integrate.py` | 247 | The AEGIS→engagement adapter (an additional, opt-in sink): folds a `detect()` verdict into the shared engagement `WorldModel` and event spine so the unified report/evidence tools compose the defensive dual, carrying the verdict's own certificate (prove-don't-guess preserved); never changes `detect`'s default behaviour. |
| `oob_correlator.py` | 229 | Passive OOB→belief correlation: the gateway forwards byte-for-byte and never injects; a real callback elevates belief only, never blocks. |
| `sensors.py` | 208 | The inbound producers implementing `sensors.base.Sensor`: mint observations (`intel:` tier), never facts. |
| `pipeline.py` | 194 | `detect()`: the signal → observation → scored → oracle → verdict flow, assembled from reused CRUCIBLE machinery. |
| `__init__.py` | 193 | The embeddable `Aegis` facade: config, LLM-guard, per-actor belief graph, `observe`/`observe_auth`/`llm_turn`. |
| `monitoring_authority_check.py` | 169 | The keyless per-request authority check: verify-only, holds no key; the defensive analog of the customer launch-lease verify. |
| `monitoring_report.py` | 169 | Seals each verdict as an inert, metadata-only report under a per-`(tenant,host)` report secret and spools it to the sovereign plane. |
| `middleware.py` | 160 | The light WSGI shim + the raw `/aegis/detect` HTTP boundary (passive honeypot watch for the MVP). |
| `response_policy.py` | 149 | Graduated challenge/throttle from the per-actor Beta belief — a soft, retryable 429; a hard block is never belief-driven. |
| `guard.py` | 92 | The LLM guard + honeypot seeding: mints a high-entropy canary the app plants, and the honeypot/crawler registry. |
| `rampart.py` | 79 | The proof-carrying edge: a real signed PCF certificate for every inline block, re-runnable offline. |
| `actor_graph.py` | 74 | The per-actor Beta belief via the reused `project_observation` keystone (corroboration/refutation for free). |
| `registry.py` | 63 | The additive vocabulary AEGIS registers into the shared verifier/world-model — appends only, never rewrites. |
| `demo_app.py` | 56 | Holds the bundled labelled benchmark app open on a fixed port so a defender has a ready-made upstream to try the gateway in front of. |

### 1.2 Tests (40 files, 7,430 LOC)

The gate-invariance and byte-identity suites are load-bearing for AS-0: they prove the
AEGIS package stays **off the default scan/engage/gate path** so `make gate` is
byte-identical (plan §9.1 rule 1; `aegis/__init__.py` doctrine). Notable:
`test_gate_byte_identical.py`, `test_gate_invariants.py`,
`test_default_observe_is_read_only.py`, `test_determinism.py`,
`test_certificate_reverifies_offline.py`, `test_verdict_never_hallucinates_class.py`,
`test_gateway_breakglass.py` (AS-27a), and `test_aegis_slice_graph.py` (the AS-0 graph
gate).

### 1.3 Related code the program builds on (already in the tree)

AEGIS is "wire, don't rebuild" (plan §9.1 rule 10), so much of the substrate exists on
the shared sovereign plane and is reused rather than recreated. See
[`FORGE-DOMAIN-MAP.md`](FORGE-DOMAIN-MAP.md) for the full map; the load-bearing pieces:

- `packages/core/vigil_core/vigil_core/monitoring_authority.py` + `spine_domains.py` —
  the shared authority contract and the domain-separated signing tags (the capability
  wall).
- `apps/sigil/sigil/governor/{monitoring_authority,monitoring_subscription,monitoring_secrets,killswitch,shard_assignment}.py`
  — owner-side minting, publish, sealing, kill-switch, frozen placement mechanics.
- `apps/sigil/sigil/inbound/{monitoring_spool,billing_spool,finding_receiver,spool_watcher}.py`
  — drain/spool and the inbound receiver.
- `engine/crucible/framework/v2/{verify,evidence,entitlement,authority,eval,console,defender}/`
  — the oracle core, the evidence/record model, the `AEGIS_RESPOND` entitlement, the
  authority machinery, the benchmark harness, the operator console, and the detection
  content engine.

---

## 2. Program status: the 72 slices

The program is **72 reviewable slices across 24 dependency waves**
(`slice_graph.json`; plan §9.3/§9.4). The slice graph records each slice's wave,
merge-dependencies, hot sets, tokens and cross-customer flag — it does **not** record
build status, so status below is stated only where it is independently grounded (git
history and the tree), never guessed.

### 2.1 Done / merged

| Slice | What | Evidence |
|-------|------|----------|
| **AS-27a** break-glass | Kill-switch exception ⇒ tripped; an unreadable control plane fails toward *not-blocking*; last-known-good else observe on a mode-file error. | **Merged — PR #1228** (`claude/aegis-as27a-breakglass`); code in `aegis/gateway.py`, tests in `aegis/tests/test_gateway_breakglass.py`. |

### 2.2 In progress — AS-0 governance (this wave)

AS-0 is the governance foundation (wave 0). Landed on this branch
(`claude/aegis-as0-governance`) in part 1: the slice-graph JSON + its gate test, the
CODEOWNERS trust-domain coverage (`_CRITICAL_PREFIXES`), and the five ADRs (scope, H1
platform/zones, E1 engines, E3 competitive, EV evidence) — commit
`AEGIS AS-0 (part 1): slice-graph gate + CODEOWNERS trust domain + ADRs`.

This document and its two siblings complete the remaining AS-0 artifacts named in the
plan §9.3 AS-0 row:

- [`CHARTER-TEMPLATE.md`](CHARTER-TEMPLATE.md) — the per-tenant monitoring/authorization
  charter template (defensive posture).
- [`FORGE-DOMAIN-MAP.md`](FORGE-DOMAIN-MAP.md) — functional domains → code locations.
- `AS-0-CURRENT-WORK-INVENTORY.md` — this file.

Still open in the AS-0 row (built by this or a sibling AS-0 PR, tracked in the plan,
not asserted done here): the §4.7 threat model split + drift test, the trace JSON, the
`make gate`/`gate-zero-fp` baseline + corpus sha256 on the blackboard, the 15 required
check names, the N-A expected-RED, and the E1 record.

### 2.3 To build — the remaining 70 slices

Everything else is **to build**. Grouped by the §9.4 waves (merge order is serial in
§9.5; a slice may start once its merge-dependencies have merged). This is the program
map, not a status claim — none below has a signed DONE record.

| Wave | Slices (to build) |
|-----:|-------------------|
| 1 | AS-25 DONE records · AS-1a TT-CI rig · AS-2a authority contracts · AS-7a licence gate · AS-3a drain strictness · AS-4a overclaims copy · AS-2l proof cascade |
| 2 | AS-2b schemas · AS-2i backup · AS-2h sealing · AS-28 closure+image · AS-2j isolated unit · AS-2f sovereign v2 |
| 3 | AS-2c gateway v2 · AS-6a placement+reconciler |
| 4 | AS-26 OPS-1 · AS-2d broker+lock · AS-30 job substrate |
| 5 | AS-1b TT-STG runs · AS-2g binding+publish · AS-2e hygiene · AS-3c drain hardening · AS-17a Sigma v2 · AS-9a broker · AS-6c edge automation |
| 6 | AS-2k settings · AS-3b v2 emission · AS-9c anchors · AS-9b receiver |
| 7 | ~~AS-21a retest guard~~ (BUILT — customer-app Monitoring-settings **Re-arm** guard on `#/monitoring/settings`: a confirmed, in-place renew of a host's monitoring authority back to the full standard window, in its current mode, reusing the EXISTING gated `monitoring/authorize` write with no `window_s` — the privilege-raising counterpart to AS-2k's shorten-only; default-OFF `VIGIL_CUSTOMER_MONITORING_ENABLED`) · ~~AS-5a capacity~~ (BUILT — `aegis/capacity.py` per-caller availability-first load-shedding admission plane; default-OFF `VIGIL_AEGIS_CAPACITY`) · ~~AS-17b CloudTrail~~ (built) · ~~AS-10b EDR~~ (built) · ~~AS-20 notify/SIEM~~ (BUILT — `aegis/notify.py` broker-sealed outbound emitter; default-OFF `VIGIL_AEGIS_NOTIFY`) |
| 8 | ~~AS-29 enforce release~~ (BUILT — the UI-chain enforce-release increment: the customer-app Monitoring-settings **Release to enforce** guard on `#/monitoring/settings`, a confirmed, in-place release of a host from the always-safe Observe base into enforce/Respond, reusing the EXISTING gated `monitoring/authorize` write in the enforce mode `block` with no `window_s` — the mode-raising counterpart to AS-21a's window-raising Re-arm; shown only on a plan that entitles Respond and only while the host is still in Observe, refused otherwise; the armed window stays bounded by the server cap, mints no new authority, opens no new edge route; default-OFF `VIGIL_CUSTOMER_MONITORING_ENABLED`. The offline release signer `enforce_release.py` [Domain 2, separate release root] remains future work on this slice) · ~~AS-5c probe socket~~ (BUILT — `aegis/probe_socket.py` LOCAL owner-only AF_UNIX operational probe socket: read-only, metadata-only effective-mode + AS-5a capacity/admission snapshot, OFF the data-plane HTTP port; never a block; default-OFF `VIGIL_AEGIS_PROBE_SOCKET`) · ~~AS-10a provider runtime~~ (BUILT — `aegis/provider_runtime.py`: unified append-only provider inventory [EDR+CloudTrail+IdP] + fault-isolated fan-out; default-OFF `VIGIL_AEGIS_PROVIDER_RUNTIME`) · ~~AS-17c IdP~~ (BUILT — `aegis/idp_source.py` Okta-System-Log sign-in/audit telemetry reader + `defender.logsource.parse_idp`; default-OFF `VIGIL_AEGIS_IDP`) |
| 9 | ~~AS-3d health+ack~~ (BUILT — the UI-chain health+ack increment on the customer-app **Monitoring** screen `#/monitoring`: a **Host health** section + a per-viewer **Acknowledge**, built ENTIRELY over the two reads the screen already makes [`api/customer/monitoring` grants + verified hosts, `api/customer/monitoring/events` gateway-reported attacks] — it adds no route, no write, no flag and no new authority. Health is honest and grounded: an armed host shows "Watching · mode", a manager's armed host whose ownership proof lapsed shows "Proof of control lapsed" [it cannot be renewed until re-verified], and the last-report line is a plain fact [the events stream is ATTACK reports, not a telemetry heartbeat, so "no events" reads "No attacks reported yet", never "telemetry down"]. Acknowledge is a PER-VIEWER mark-as-seen in browser storage [namespaced by user, capped — the notification-centre read-state pattern], makes no server call and says so. Default-OFF `VIGIL_CUSTOMER_MONITORING_ENABLED`) · ~~AS-5d outcomes+receipts~~ (BUILT — `aegis/receipts.py` append-only, hash-linked ENFORCEMENT-OUTCOME receipt ledger [allowed / shed / blocked], surfaced read-only on the AS-5c probe snapshot; records what enforcement did, never a block; default-OFF `VIGIL_AEGIS_RECEIPTS`) · ~~AS-6e rolling~~ (BUILT — `aegis/aegis_fleet_rolling.py`: the staged, health-gated ROLLING reconcile over AS-6a's big-bang — converges the fleet in deterministic `max_surge` batches, admitting the next batch only once the prior rolled workers land HEALTHY (injected `RolloutHealth`), where AS-6a rolls the whole fleet in one pass; renders NO enforcement (release-gating stays in AS-6a) and adds NO WorkerKind/OracleKind; engine-plane (FATAL-2), off the `aegis/__init__` / `__main__` gate path; default-OFF `VIGIL_AEGIS_FLEET_ROLLING`, byte-identical no-op when off. Reuses an additive `hold_keys` seam on `FleetReconciler.reconcile` [default-empty → AS-6a byte-identical]) |
| 10 | ~~AS-4b contract+preview~~ (BUILT — the UI-chain contract+preview increment: the AS-4b protection-contract EVALUATOR in the core [`vigil_core/contract_eval.py`: FILLS + GRADES the AS-2b protection contract — the headline as the FLOOR of the six dimensions, enforcement `effective` as the fail-closed AND of its terms — and a per-host enforce/observe PREVIEW] + a customer-facing **Protection preview** screen `#/monitoring/preview`. The screen is READ-ONLY: per host the manager can act on, the server-side evaluator GRADES, over the SAME already-gated monitoring state `monitor_list` reads [active grants, proof-current hosts, Respond entitlement], what AEGIS does now [observe: detect + report] and what releasing to enforce WOULD add [block before execution; withhold the response — DERIVED from the provider registry, never hard-coded], whether a release would be permitted now and, honestly, why not [no Respond plan / proof of control lapsed / already enforcing / not armed], and what AEGIS does NOT inspect. It MINTS nothing, ARMS nothing and opens no release — the actual Release stays behind AS-29's owner-signed gate; it owns its own read `api/customer/monitoring/preview`, manager-only [a read-only role sees an honest note, never the hosts or the plan], renders NO button, and is default-OFF behind the SAME `VIGIL_CUSTOMER_MONITORING_ENABLED` [off → the route is the home screen as any unknown route, the read 404s]. The full §4.5 V1–V7 contract grading beyond the headline floor + enforcement `effective` remains future work on this slice) · ~~AS-5e ImpactBudget~~ (BUILT — `aegis/impact_budget.py` deterministic READ-ONLY impact-budget rollup over the AS-5d receipt chain: over a bounded recent window it measures the DENIED ratio [shed + blocked, enforcement's availability cost] vs a configured ceiling + a bounded per-reason breakdown, surfaced read-only on the AS-5c probe snapshot; MEASURES, never acts — never mutates the ledger and never drives an admit/shed/allow/block decision; inert unless the AS-5d `VIGIL_AEGIS_RECEIPTS` dep is also armed; default-OFF `VIGIL_AEGIS_IMPACT_BUDGET`) |
| 11 | ~~AS-27b override+`manage_defense`~~ (BUILT — the DEFENSE-CONTROL increment: the `manage_defense` RBAC capability in the core [`vigil_core/rbac.py`: owner + founder, NOT a billing-only org_admin — defense-authz != billing-authz, and disjoint from offense_authority] + the AS-27b core EVALUATOR [`vigil_core/defense_control.py`: grades, read-only, whether a host is enforcing live blocking now and whether an authorized STAND-DOWN — the safe-direction `override`, which only REDUCES enforcement, never widens scope — would apply] + a customer-facing **Defense control** screen `#/monitoring/control`, the SAFE-direction mirror of AS-4b. The screen is READ-ONLY: per host the manager can act on, the server-side evaluator grades over the SAME already-gated monitoring state `monitor_list` reads; `can_manage` [manage_monitoring] gates the host rows and `can_manage_defense` [manage_defense — the founder, under the founder kill-switch] only names who may OPERATE the live defense. It MINTS nothing, ARMS nothing and STANDS NOTHING DOWN — a real stand-down stays behind the owner-signed gate; it owns its own read `api/customer/monitoring/control`, renders NO button, and is default-OFF behind the SAME `VIGIL_CUSTOMER_MONITORING_ENABLED` [off → the route is the home screen as any unknown route, the read 404s]. The FLEET leg — a live fleet-level override/relocate over the AS-6a/AS-6e reconciler — remains future work on this slice [AS-6e's rolling reconciler is not in this branch's base]) · ~~AS-5b attribution~~ (BUILT — `aegis/attribution.py` deterministic READ-ONLY denial-SOURCE attribution rollup: reads the AS-5a per-caller buckets [the only plane with per-caller state] and reports which sources hold the current shed/denial pressure — concentration + constrained count + a bounded top-N of the heaviest sources as ADDRESS-FREE opaque ids, never a raw caller address — paired with the AS-5e denied-reason breakdown [the "what"], surfaced read-only on the AS-5c probe snapshot; MEASURES, never acts — never mutates a bucket/receipt and never drives an admit/shed/allow/block decision; inert unless its AS-5a `VIGIL_AEGIS_CAPACITY` + AS-5e `VIGIL_AEGIS_IMPACT_BUDGET` [and thus AS-5d `VIGIL_AEGIS_RECEIPTS`] deps are also armed; default-OFF `VIGIL_AEGIS_ATTRIBUTION`) |
| 12 | ~~AS-6d onboarding~~ (BUILT — the UI-chain TENANT-ONBOARDING increment, the final link (chain ...->4b->27b->6d): a customer-facing **AEGIS onboarding** screen `#/monitoring/onboarding` that COMPOSES the already-built monitoring surfaces (it re-implements none of them) into a guided flow. The AS-6d core evaluator [`vigil_core/onboarding.py`: `onboarding_journey` — a pure, deterministic grader] computes, over the SAME already-gated monitoring state `monitor_list`/`monitor_preview`/`monitor_control` read [hosts with a current ownership proof, active grants + any enforcing, Respond entitlement], a LINEAR journey from a connected (proven) host to a monitored (observe) one — prove a host → choose an AEGIS plan → turn monitoring on — surfacing exactly one next action at a time as a plain NAV link to the screen that performs it [Assets / Billing / Monitoring, the existing gated `monitoring/authorize` toggle], and once a host is monitored surfacing the AS-4b Protection preview + AS-27b Defense control read-only views as the explore-next links. It owns its own read `api/customer/monitoring/onboarding`, manager-only [a read-only role sees an honest note, never the steps], renders no write [pure nav], MINTS/ARMS/RELEASES nothing, and is STRICT default-OFF behind a NEW second gate `VIGIL_CUSTOMER_AEGIS_ONBOARDING` **on top of** `VIGIL_CUSTOMER_MONITORING_ENABLED` [either off → the route is the home screen as any unknown route, the read 404s, byte-identical]. The guided owner-manual onboarding beyond this in-app flow remains future work on this slice) · ~~AS-7b Coraza+pipeline~~ (BUILT — `aegis/coraza_source.py` deterministic READ-ONLY Coraza/CRS front-WAF SUPPLY-CHAIN ATTESTATION + typed `rule_refs` lead admission: composes the AS-7a §7 licence gate [is the `coraza-v3` engine + `coreruleset-crs-4x` corpus licence-admitted for service use?] and an AS-28-style STDLIB corpus PIN [is the CRS rule corpus pinned to a known digest?] into `admissible = licensed AND pinned`; a Coraza v3 DetectionOnly hit's `rule_refs` are normalized ADDRESS-FREE [scrubbed/bounded/sorted, never a client address, URI, or matched data] and admitted as a LEAD only over an admissible corpus — a drifted/tampered or unlicensed corpus fails closed and raises NO belief; surfaced read-only on the AS-5c probe snapshot; MEASURES, never acts — never mutates the ledger/corpus and never drives an admit/shed/allow/block decision, a CRS hit is a LEAD never a block [only a fired oracle blocks]; inert unless a CRS corpus is configured; default-OFF `VIGIL_AEGIS_CORAZA`) |
| 13 | AS-8 content+coverage · ~~AS-31 Detection Mirror~~ (BUILT — `aegis/detection_mirror.py` deterministic READ-ONLY DETECTION MIRROR: a reflected, metadata-only view of the detection posture that UNIFIES its three merged deps — the AS-30 provider runtime [the detection SOURCE catalog, via `build_provider_runtime_registry`], the AS-7b Coraza/CRS attestation [the detection CONTENT admissibility + the `admit_rule_refs` lead gate], and the AS-3b v2-emission AS-2e output-hygiene leak gate [`is_hygiene_clean`/`contains_raw_ip`] — reached by RELATIVE import, never re-implemented. `summary` reflects the cataloged detection sources × the admissible CRS content leads [address-free, bounded, sorted, de-duplicated, hygiene-clean] + a deterministic posture `digest`; `reflect(source, refs)` admits one detection hit as a LEAD only over a CATALOGED source AND ADMISSIBLE content [a dotted-quad that survives the AS-7b charset scrub is DROPPED by the AS-3b gate], else `()` fail closed. Surfaced read-only on the AS-5c probe snapshot; MEASURES/REFLECTS, never acts — never mutates the inventory/ledger/corpus and never drives an admit/shed/allow/block decision, a mirrored detection hit is a LEAD never a block [only a fired oracle blocks]; inert unless its AS-7b `VIGIL_AEGIS_CORAZA` dep [+ a configured CRS corpus] is also armed; default-OFF `VIGIL_AEGIS_DETECTION_MIRROR`) · ~~AS-10c kit~~ (BUILT — `aegis/detection_kit.py` deterministic READ-ONLY detection-content KIT supply-chain packaging attestation: composes the CRS-derived + Sigma-derived rules a tenant would SHIP (the `pushed-rules` bundle) into ONE bundled, tamper-evident "kit" — the AS-7a §7 licence gate over the DISTRIBUTION bundle [`licensed`; attribution/NOTICE obligations tracked, non-blocking], the AS-7b CRS corpus pin + address-free normalize/admit primitives [reused by relative import], and an AS-28-style stdlib Sigma corpus pin over the AS-17a DEPLOYABLE rules [`SigmaCorpus.from_rules`] → `admissible = licensed AND crs_pinned AND sigma_pinned`, sealed by a single `kit_digest` binding both corpus pins + the licence-ledger digest + the kit identity; a kit hit's `rule_refs` are admitted as a LEAD only over an admissible kit [a drifted/tampered or unlicensed kit fails closed and raises NO belief]; surfaced read-only on the AS-5c probe; MEASURES, never acts — a kit rule_ref is a LEAD never a block; default-OFF `VIGIL_AEGIS_KIT`) · AS-34 production+rollout |
| 14 | AS-23a early benchmark · ~~AS-18a 1b observe~~ (BUILT — `aegis/observe_1b.py` deterministic READ-ONLY 1b OBSERVE view: the OBSERVE leg of deployment path 1b [AEGIS consumes the tenant's OWN existing CDN/WAF telemetry; the enforcement point stays at the tenant's edge, and AEGIS says so honestly] that UNIFIES its three merged deps — the AS-9b receiver [the RECEIVED EVENTS: a path-1b edge finding's `source` + `rule_refs`], the AS-31 detection mirror [the REFLECTION: `DetectionMirrorMeter.reflect`/`.summary`, reached by COMPOSITION — an injected meter], and the AS-4b contract evaluator [the GRADE: `headline_floor` over the Headline ladder, reached by a LAZY import], never re-implemented. `observe(events)` reflects each received event through the AS-31 mirror into admissible leads [address-free, bounded, sorted, de-duplicated, hygiene-clean — fail-closed `()` over an uncataloged source / inadmissible content / empty intake] and grades the observe posture [the AS-30 source catalog × the AS-7b content admissibility × the intake corroboration] into an honest headline STRUCTURALLY capped at `observing`; `snapshot` surfaces the standing observe posture read-only on the AS-5c probe snapshot. REFLECTS/GRADES, never acts — never mutates the inventory/ledger/corpus/spool and never drives an admit/shed/allow/block decision, a reflected finding is a LEAD never a block [only a fired oracle blocks], the 1b ENFORCE leg is the separate AS-18b slice; engine-plane [FATAL-2, stdlib-only at module scope], OFF the eager `aegis/__init__`/`__main__` path [lazy import], byte-identical no-op when off; inert unless its AS-31 `VIGIL_AEGIS_DETECTION_MIRROR` dep [+ AS-7b `VIGIL_AEGIS_CORAZA` + a configured CRS corpus] is also armed; default-OFF `VIGIL_AEGIS_OBSERVE_1B`) · AS-11a incidents |
| 15 | AS-11b locker · AS-12 ledger · AS-33 AI adviser · AS-22 mirror IDS |
| 16–19 | AS-13a executor · AS-13b scope · AS-13c actions UI · AS-14 verification |
| 20–23 | AS-21 virtual patching · AS-32 real-tenant verification · AS-19 containment · AS-18b 1b enforce · AS-15 recovery+drift · AS-16 lifecycle · AS-23b full benchmark · AS-24 final handoff |

**Critical path (plan §9.4):** 0 → 27a → GW chain → 5b → 7b → 8/31 → 11a → 12 → 13a →
13b → 13c → 14 → 21 → 18b/15 → 16/23b → 24 — 24 waves.

### 2.4 Program DONE

Program DONE = **every slice DONE or externally blocked, and the rollout procedure
rehearsed and recorded** (plan §13.4). A capability is DONE only when TT-A (with TT-B
co-located as the cross-tenant control) uses it end to end through VIGIL on TT-STG
built from merged IaC, at production grade, proven by a signed AS-25 record
(ADR [0001](adr/0001-scope.md) DONE standard). "Blocked" is reserved for external
prerequisites with a reproducible check (plan §14.3). Go-live is a separate owner act.

---

## References

- Plan §9.3 (slices), §9.4 (waves/chains/critical path), §13 (final acceptance),
  §4.7 (publication split) — `parsed-popping-lemur.md`.
- `engine/crucible/framework/v2/aegis/slice_graph.json` — the 72-slice/24-wave graph
  (AS-0 gate); `aegis/tests/test_aegis_slice_graph.py` — its acyclicity/levels test.
- ADRs [0001](adr/0001-scope.md) (scope & DONE standard), [0005](adr/0005-EV-evidence.md)
  (evidence/record model).
- [`FORGE-DOMAIN-MAP.md`](FORGE-DOMAIN-MAP.md),
  [`CHARTER-TEMPLATE.md`](CHARTER-TEMPLATE.md),
  [`DEPLOYMENT.md`](DEPLOYMENT.md).
