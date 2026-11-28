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
| 9 | ~~AS-3d health+ack~~ (BUILT — the UI-chain health+ack increment on the customer-app **Monitoring** screen `#/monitoring`: a **Host health** section + a per-viewer **Acknowledge**, built ENTIRELY over the two reads the screen already makes [`api/customer/monitoring` grants + verified hosts, `api/customer/monitoring/events` gateway-reported attacks] — it adds no route, no write, no flag and no new authority. Health is honest and grounded: an armed host shows "Watching · mode", a manager's armed host whose ownership proof lapsed shows "Proof of control lapsed" [it cannot be renewed until re-verified], and the last-report line is a plain fact [the events stream is ATTACK reports, not a telemetry heartbeat, so "no events" reads "No attacks reported yet", never "telemetry down"]. Acknowledge is a PER-VIEWER mark-as-seen in browser storage [namespaced by user, capped — the notification-centre read-state pattern], makes no server call and says so. Default-OFF `VIGIL_CUSTOMER_MONITORING_ENABLED`) · AS-5d outcomes+receipts · AS-6e rolling |
| 10 | ~~AS-4b contract+preview~~ (BUILT — the UI-chain contract+preview increment: the AS-4b protection-contract EVALUATOR in the core [`vigil_core/contract_eval.py`: FILLS + GRADES the AS-2b protection contract — the headline as the FLOOR of the six dimensions, enforcement `effective` as the fail-closed AND of its terms — and a per-host enforce/observe PREVIEW] + a customer-facing **Protection preview** screen `#/monitoring/preview`. The screen is READ-ONLY: per host the manager can act on, the server-side evaluator GRADES, over the SAME already-gated monitoring state `monitor_list` reads [active grants, proof-current hosts, Respond entitlement], what AEGIS does now [observe: detect + report] and what releasing to enforce WOULD add [block before execution; withhold the response — DERIVED from the provider registry, never hard-coded], whether a release would be permitted now and, honestly, why not [no Respond plan / proof of control lapsed / already enforcing / not armed], and what AEGIS does NOT inspect. It MINTS nothing, ARMS nothing and opens no release — the actual Release stays behind AS-29's owner-signed gate; it owns its own read `api/customer/monitoring/preview`, manager-only [a read-only role sees an honest note, never the hosts or the plan], renders NO button, and is default-OFF behind the SAME `VIGIL_CUSTOMER_MONITORING_ENABLED` [off → the route is the home screen as any unknown route, the read 404s]. The full §4.5 V1–V7 contract grading beyond the headline floor + enforcement `effective` remains future work on this slice) · AS-5e ImpactBudget |
| 11 | AS-27b override+`manage_defense` · AS-5b attribution |
| 12 | AS-6d onboarding · AS-7b Coraza+pipeline |
| 13 | AS-8 content+coverage · AS-31 Detection Mirror · AS-10c kit · AS-34 production+rollout |
| 14 | AS-23a early benchmark · AS-18a 1b observe · AS-11a incidents |
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
