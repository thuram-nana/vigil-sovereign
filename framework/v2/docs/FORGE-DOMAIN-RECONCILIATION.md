# FORGE — the 20 domains reconciled against what already exists

FORGE (`/FORGE.md`) sequences 20 AEGIS defensive capability domains. Much of the substrate — and several
whole domains — is **already built** in `framework/v2/`. FORGEMASTER reads this first so it never rebuilds
what exists; it drives a stream only for a **genuinely-unbuilt** domain, and reuses the existing oracle /
sensor / evidence primitives everywhere else.

Every confirmed finding now emits a **real signed PCF v0.1 certificate** (`evidence/pcf.py`,
`evidence pcf-export`/`pcf-verify`), so any domain built from here produces re-runnable proof by construction.

## Inventory (the substrate a new domain reuses)
- **30 oracle kinds** (`verify/models.py::OracleKind`) — the provable defensive facts: 15 frozen
  offensive (`_ALL_ORACLES`, the benchmark authority) + 15 additive (AEGIS/posture/forgery kinds,
  each reachable only via its own explicit `BUG_CLASS_ORACLES` row). Additive registration via
  `aegis/registry.py`; the frozen `_ALL_ORACLES` stays 15, so `make gate` is byte-identical.
- **18+ sensors** (`sensors/`) — `declared_service, nmap, tshark, sbom_vuln, kube_bench, cloud_import/pull,
  mesh_config, cicd_workflows, mobsf_static, android_manifest, tls_cert, nuclei/zap/burp web, fuzz_harness,
  email_auth` (the last is Domain 10's, added by this reconciliation).
- **Evidence + crypto**: signed m-of-n Ed25519 certs, tamper-evident chain, veracity firewall, PCF export.
- **World-model, calibration, report/SARIF, entitlement/sovereignty** — all present.

## Domain-by-domain status

| # | Domain | Status | What exists / what's left |
|---|--------|--------|----------------------------|
| 2 | Attack-surface assessment | **substantially built** | scanner engine + `nmap`/web sensors + web bug-class oracles; AEGIS reuses read-only, charter-bound. Left: exposure-oracle framing as self-assessment. |
| 3 | Vulnerability assessment | **BUILT** | `sbom_vuln` sensor + `VERSION_RANGE` oracle. |
| 16 | Supply-chain security | **BUILT** (= domain 3) | same `VERSION_RANGE` path; vendor-access-as-facts is the only add. |
| 5a | AI-deployment defence | **BUILT (MVP)** | 4 AEGIS classes (`PROMPT_INJECTION, SYSTEM_PROMPT_DISCLOSURE, AUTOMATED_ACCESS, CREDENTIAL_STUFFING`) + the AEGIS gateway. Left: broaden for gov LLM systems. |
| 8 | Cloud posture | **BUILT** | `CLOUD_POSTURE` oracle + `cloud_import`/`cloud_pull` sensors. |
| 11 | OT/ICS posture | **partially built** | `K8S_POSTURE` + `MESH_POSTURE` oracles + `kube_bench`/`mesh_config` sensors. Left: passive OT sensors (deliberately last). |
| 4 | Telemetry collection | **partially built** | sensor framework + `declared_service/nmap/tshark/cloud/web`. Left: log/EDR/identity/email sensors. |
| 6 | Indigenous threat intel | **partially built** | `intel/` subsystem (collectors, projection). Left: national-telemetry re-verification. |
| 9 | Endpoint health & drift | **partially built** | `SANITIZER_SIGNAL` + `fuzz_harness`. Left: EDR adapters, malware-fact oracle. |
| 12 | Incident management | **substrate built** | signed evidence bundles + hash-linked spine. Left: case lifecycle. |
| 19 | Cross-ministry federation | **substrate built** | m-of-n threshold Ed25519 + offline-verifiable certs (now PCF). Left: cross-ministry exchange. |
| 13 | Situational awareness | **partially built** | world-model + report rollups over facts. Left: tiered national views. |
| 15 | Compliance management | **partially built** | report standards-mapping seam. Left: ISO/NIST/CIS evidence export over facts. |
| 14,17,18,20 | Risk/gov · exec/AI decision support · resilience | **unbuilt** (Phase 4) | reasoning/report substrate exists; domain logic unbuilt. |
| **7** | **Identity posture & anomaly** | **UNBUILT** | `ACHIEVED_STATE` predicate primitive exists; no identity sensor/predicates. A clean Phase-2 wedge. |
| **10** | **Email security (SPF/DKIM/DMARC)** | **BUILT** | `EMAIL_AUTH_POSTURE` oracle (`verify/oracles.py::email_auth_posture_oracle`) + seam (`verify/email_auth.py`) + sensor (`sensors/email_auth.py::EmailAuthSensor`, Tier-1, offline, operator-supplied DNS export) + fusion (`engage_fusion.py::_reverify_email_auth`, opt-in via `engage --fuse-sensors`). Proves a published DNS policy (DMARC/SPF TXT records) permits spoofing — no DMARC anywhere in the RFC 7489 §6.6.3 chain / `p=none` / SPF `+all`. **Message-level SPF/DKIM/DMARC verification stays explicitly out of scope** (DKIM canonicalisation and SPF include/macro chains are a semantic layer this cannot soundly re-derive offline; an `Authentication-Results` header would be string trust) — those remain LEADs. Cleared a two-independent-reviewer adversarial gate (RED-PEN + an independent multi-lens sweep); see `V2-LIMITATIONS.md` §28 for the full honest-limitations ledger (producer-attested `is_org_domain`, conservative misses on malformed input, not verified live). |

### This session's additions (extend the posture/crypto domains, not new domains)
`TLS_WEAKNESS` (weak cert signature + undersized key + live-TLS feed), `MOBILE_POSTURE` (embedded private key +
unguarded exported provider), `CICD_POSTURE` (workflow), `MESH_POSTURE` (config feed) — all under domains
8/11/16 (posture + supply-chain), all with sensors wired into `engage --fuse-sensors`.

## The first stream

**Domain 10 — email SPF/DKIM/DMARC posture — DONE.** Built as the demonstration that the PCF foundation
makes a domain real functionality: a pure deterministic oracle over retained DNS policy records (DMARC/SPF
TXT), with an obvious benign twin (a hardened `p=reject`/`-all` domain that never fires), no offense, and a
real, signed, offline-re-runnable PCF v0.1 certificate by construction (`verify/tests/test_email_auth.py::
test_a_confirmed_finding_emits_a_real_pcf_certificate_that_verifies_offline`). Scope was narrowed from the
original "SPF/DKIM/DMARC verification" framing to **published-policy posture only** — message-level
SPF/DKIM/DMARC *verification* (an `Authentication-Results` header, DKIM canonicalisation, SPF include
chains) was ruled a semantic layer this cannot soundly re-derive offline and stays a LEAD, never asserted.
Remaining genuinely-unbuilt wedge: **Domain 7 — identity posture & anomaly** (see the table above).
