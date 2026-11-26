# AEGIS monitoring charter — `<tenant-slug>` / `<protected-host>`

**Version:** 1.0
**Status:** Draft → Final (owner-signed)
**Date:** YYYY-MM-DD
**Last updated:** YYYY-MM-DD

This is the binding authorization document for AEGIS to **monitor and, under a
separate release, defend** one tenant's own web host. It is the defensive dual of
the OBSIDIAN engagement charter (`framework/templates/charter.md`): where that
charter authorizes offense *against* a target, this one authorizes AEGIS to sit in
front of the tenant's *own* application and inspect the traffic it already receives.

AEGIS is the defensive section of the one VIGIL platform operated by SIGIL SARL
(ADR [0001](adr/0001-scope.md)); it is never a separate product or deployment. This
template describes the **fields** of a charter and the **decided controls** that make
one binding. It is public-safe: it records the authorization model and its
mitigations, never an unfixed weakness or an attack recipe (plan §4.7; ADR README,
"Publication rule").

> **Authorization is binding; nothing acts without it.** The same principle the
> OBSIDIAN constitution states for offense governs AEGIS: a monitoring grant is a
> signed, bounded capability, and **enforcement is a second, separate owner act**.
> No AEGIS production act is delegated to an agent — the owner deploys, flips modes,
> places tenants, and signs releases (plan §10).

---

## 0. How this charter binds (not just prose)

A filled charter is the human-readable face of machinery that enforces it
cryptographically. The owner's attestation (§1) authorizes the owner to mint a
**`SignedMonitoringAuthority`** — the owner-signed, per-`(org_id, exact host)` grant
whose domain-separated tag is `vigil-monitoring-authority-v1`
(`packages/core/vigil_core/vigil_core/spine_domains.py`). The data plane verifies that
grant **keyless, per request** (`aegis/monitoring_authority_check.py`) and holds no
signing key of its own. Consequences that follow by construction, not by promise:

- **The mode is inside the signed bytes.** An `observe` grant cannot be flipped to
  `block` without a fresh owner signature.
- **`block` is necessary, not sufficient.** Even under a block-mode grant, the data
  plane still gates every enforcing action behind a separate **EnforceRelease**
  (slice AS-29) and the `AEGIS_RESPOND` entitlement (`framework/v2/entitlement/`).
- **The grant can never replay as something else.** The capability wall
  (own ≠ offense-test ≠ observe ≠ block) is realized by distinct signing domains, so a
  monitoring grant can never act as a testing or spend authority, or vice-versa.

Fill every field below. An unfilled field fails closed: an empty scope authorizes
nothing.

---

## 1. Owner attestation

I, **`<owner / authorized representative>`**, attest:

- I am the legal owner or authorized representative of the hosts listed in §3.
- I have the authority to authorize inline runtime monitoring and defensive
  enforcement of those hosts.
- I understand that AEGIS inspects the live request/response traffic of the host it
  is placed in front of, and that in `enforce` mode it may block a request that a
  deterministic oracle proves is an attack.
- I understand AEGIS is **fail-open**: an inspection error, a tripped kill-switch, or
  an unproven request forwards; an upstream that is down returns an honest `502`,
  never a synthetic block (DEPLOYMENT.md, "The honest promise").
- I authorize AEGIS to operate within the limits stated in this charter, and I
  understand that enforcement additionally requires a release I sign separately.

Owner signature: `<name>`    Date: `__________`

> The signature of record is the owner-signed `SignedMonitoringAuthority` minted from
> this charter, not this ink block. This block attests intent; §8 binds it.

---

## 2. Tenant

| Field | Value |
|-------|-------|
| Tenant slug | `<tenant-slug>` |
| `org_id` (== `CRUCIBLE_TENANT`) | `<org-id>` |
| Billing / plan tier | `<tier>` |
| Primary owner contact | `<name / channel>` |
| Secondary contact | `<name / channel>` |

Tenant identifiers are opaque hashes everywhere they leave the sovereign plane;
metrics and reports never carry a raw tenant name or a raw client IP
(plan §10, "Monitoring"; §4). One charter authorizes **one `(org_id, host)`**; a
second host is a second charter and a second grant.

## 3. Protected hosts (in scope)

The exact hosts AEGIS is authorized to sit in front of and inspect. A grant binds
**one exact host** — a wildcard authorizes nothing.

| Protected host | Upstream origin | Connection path | Notes |
|----------------|-----------------|-----------------|-------|
| `<app.example.com>` | `<origin the gateway forwards to>` | `<1a managed gateway / 1b existing CDN-WAF>` | Primary app |

- **Path 1a (managed gateway):** SIGIL places an inline keyless gateway per
  `(org, host)`; the tenant points DNS / their load-balancer at it. The gateway
  forwards only the request path+query to the fixed upstream (no forward-SSRF),
  strips hop-by-hop headers, and adds `X-Forwarded-For` (DEPLOYMENT.md §1).
- **Path 1b (existing CDN/WAF):** AEGIS consumes the tenant's existing
  Cloudflare/CDN telemetry (ADR [0004](adr/0004-E3-competitive.md)); the enforcement
  point is the tenant's edge, and AEGIS says so honestly.

A host discovered during onboarding that is **not** listed here is **conditionally in
scope**: it is surfaced to the owner and waits for an explicit charter amendment (§11)
before any placement. "Just add the apex too" is not authorization.

## 4. Authorized zones and paths

AEGIS runs inside the one VIGIL platform's internal zone model
(ADR [0002](adr/0002-H1-zones-orchestration-placement.md): Z1 edge … Z4 sandbox).
This section states where, within the tenant's own surface, inspection and
enforcement are authorized.

| Scope item | Value |
|-----------|-------|
| Inspected surface | Request query + a bounded header/cookie surface; request body; proxied response (for the response-side classes) |
| Authorized path prefixes | `<e.g. /, or a specific /app prefix>` |
| Excluded path prefixes | `<e.g. /healthz, /webhooks/stripe — never inspected or enforced>` |
| Honeypot / tripwire paths | `<seeded paths no human UI links; a fetch proves automation>` |
| Edge posture | CloudFront + Shield are the *pipes*, **not** an AEGIS enforcement point (ADR 0004) |

Excluded prefixes are honored in both modes. The inspected surface is bounded by
design: the ingest boundary treats all tenant-forwarded content as hostile, fails
closed on malformed input, and redacts PII at the boundary
(`aegis/boundary.py`; AEGIS-CRUCIBLE-REUSE-MAP.md §"New infrastructure").

## 5. Mode

AEGIS always starts in **observe** and is promoted to **enforce** only by a separate
owner act.

- [ ] **observe** (default) — read-only. Inspects and forwards, blocking nothing;
      logs a verdict (opaque, metadata-only) for every proven attack it *would* block.
      The owner watches for false positives against real traffic before promoting.
- [ ] **enforce** — a request that a deterministic oracle proves is an attack is
      blocked with a re-runnable certificate; everything unproven forwards.

Selected: `<observe | enforce>`.

Enforce requires **all** of:

1. A block-mode `SignedMonitoringAuthority` for this `(org, host)` (§8).
2. A separately **owner-signed EnforceRelease** scoped to the attack classes and the
   placement (slice AS-29). The first release covers only VIGIL-confirmed classes.
3. The `AEGIS_RESPOND` entitlement granted to this deployment
   (`framework/v2/entitlement/`).
4. A clear kill-switch (§6).

Detection is always available; only *blocking* is gated (DEPLOYMENT.md, "Operating it
safely"). A governed deployment without the release and entitlement runs observe-only
and logs *why*.

## 6. Kill-switch (break-glass)

The kill-switch is the owner's instant off-ramp and is **availability-first**
(slice AS-27a, merged; `aegis/gateway.py`).

| Field | Value |
|-------|-------|
| Gateway slug | `<--slug name for this placement>` |
| Kill-switch control path | `<operator-controlled control dir>` |
| Who may trip | Owner; on-call with `manage_defense` (plan §10, on-call matrix) |

Decided behavior:

- Tripping the kill-switch for this slug drops the gateway to pass-through **without
  taking the app down**.
- A kill-switch subsystem that is present but **unreadable** fails *toward
  not-blocking* (pass-through), never toward blocking — the break-glass default.
- A mode-file error falls back to last-known-good, else to `observe`.
- When enforcement is dropped this way, the governed SaaS response is honest about
  it ("proof not retained" / "Stopped by SIGIL"), never a silent downgrade.

## 7. Data handling

| Field | Value |
|-------|-------|
| Verdict/report content | Inert, **metadata-only** monitoring reports (no raw payloads) sealed per-`(tenant, host)` with a dedicated report secret, distinct from the deployment secret (`aegis/monitoring_report.py`) |
| Tenant identifiers | Opaque hashes outside the sovereign plane (plan §10) |
| Client addresses | Not emitted in metrics; attribution surfaces a viewer address only after a secret verifies, over the socket (slice AS-5b) |
| PII | Redacted at the ingest boundary (`aegis/boundary.py`) |
| Secrets / IPs in logs | Never in journald or snapshots (slice AS-2e, "UI-safe stderr; HMAC snapshots") |
| Certificate re-verification | Every block ships a certificate an auditor re-runs offline, with no app and no trust in AEGIS (`aegis/rampart.py`; DEPLOYMENT.md) |
| Evidence retention / legal hold | Per the evidence model (ADR [0005](adr/0005-EV-evidence.md)); export is offline-verifiable, a 1-byte flip fails |
| Backup exclusions | Monitoring state is excluded from the paths that would resurrect a revoked grant (slice AS-2i) |

## 8. Binding record (filled at provisioning, not by the tenant)

| Field | Value |
|-------|-------|
| Signing domain | `vigil-monitoring-authority-v1` (owner key) |
| `(org_id, host)` | `<org-id>` / `<protected-host>` |
| Mode in signed bytes | `<observe \| block>` |
| Lease window | `<issued_at … expiry>` (bounded; renewal ≥14 days before expiry — plan §10 SLOs) |
| Epoch | `<monotonic epoch; bumped on every live move>` |
| EnforceRelease ref (enforce only) | `<release id / separate root>` |
| Published-authority location | `<verify-only published grant path>` |

Revocation is signed and bounded: a revocation takes effect within the SLO
(≤5 min, bounded by the lease; plan §10). A lapsed lease is pass-through, not a
fail-closed outage (plan §8, "Lease lapse"). Offboarding cascades: revoke → proofs
→ unpublish → retire → snapshot → delete → purge (slice AS-16), and re-onboarding
needs fresh proof.

## 9. Non-goals and refusals

By accepting this charter the owner accepts that AEGIS, by doctrine, will **not**:

- Attack anyone, evade a defender, or act as a stealth tool — it is defensive only
  and correlatable by design (`aegis/__init__.py` DOCTRINE; DEPLOYMENT.md,
  "What AEGIS will never do").
- Block on a guess. A hard block rides **only** on a fired oracle's re-runnable
  certificate; belief and leads never block (DEPLOYMENT.md; AEGIS-DESIGN-RESEARCH.md).
- Claim completeness. Coverage is the measured list of classes with oracles; the
  forbidden-terms lint rejects "universal/zero-FP/fully protected/`protected`"
  claims (plan §13.6).
- Treat a CloudFront/Shield edge as an AEGIS enforcement point (ADR 0004).

## 10. Communication plan

| Channel | Use | Response time |
|---------|-----|---------------|
| `<channel>` | Coverage / onboarding questions | `<within 4 hours>` |
| `<channel>` | Enforcement incidents, kill-switch | `<within 1 hour>` |
| `<channel>` | Emergency stop | `<immediate, ack required>` |

## 11. Amendments

Any change to the protected hosts, authorized paths, mode, or data handling requires:

1. The owner updates this charter (new/modified field) and increments the version.
2. A fresh owner-signed `SignedMonitoringAuthority` (and, for enforce, a fresh
   EnforceRelease) — the old signature does not carry the change, because the mode and
   scope are inside the signed bytes.
3. An entry on the signed event spine recording the change and the authorization.

AEGIS never assumes an expansion was authorized because a related host was mentioned.
The signed grant is the source of truth.

## 12. Closure

The engagement for this `(org, host)` is closed when the owner offboards the tenant:
the AS-16 cascade runs, a legal hold (if any) is respected before purge, the tenant
removes their CNAME, and placement is released. A closed charter cannot be resurrected
by a restored backup (slice AS-2i) — re-onboarding starts a new charter and a new
proof.

---

## References

- Plan §4.7 (publication split), §8 (states), §10 (SIGIL operations), §13 (final
  acceptance) — `parsed-popping-lemur.md`.
- ADRs [0001](adr/0001-scope.md) (scope), [0002](adr/0002-H1-zones-orchestration-placement.md)
  (platform/zones), [0004](adr/0004-E3-competitive.md) (competitive/edge),
  [0005](adr/0005-EV-evidence.md) (evidence model).
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — the honest-promise deployment guide.
- [`FORGE-DOMAIN-MAP.md`](FORGE-DOMAIN-MAP.md) — where each control lives in code.
- `framework/templates/charter.md` — the OBSIDIAN (offensive) charter this mirrors.
- Code: `aegis/monitoring_authority_check.py`, `aegis/monitoring_report.py`,
  `aegis/gateway.py`, `aegis/boundary.py`, `aegis/rampart.py`,
  `packages/core/vigil_core/vigil_core/spine_domains.py`.
