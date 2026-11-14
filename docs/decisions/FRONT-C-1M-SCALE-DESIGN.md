# Front C — 1,000,000 users: design (owner-authorised 2026-11-10)

**Status:** reported to the owner before any build slice, as the program discipline requires, and **authorised by
the owner on 2026-11-10** ("I authorise the 1m users plan"): ONE sovereign spine, the S0 trust model and the
S0-first order (§7 items 1, 2 and 4). The **scale targets (§7 item 3) are still the owner's to set** — S4 cannot
pass or fail without them. Build status lives in `HANDOFF-SESSION.md`. **S0 is built and merged, default-OFF:**
S0a–S0c (#1068–#1070) and S0d (#1072, #1073, #1074, #1075 and the S0d-3 PR) — every request-path fold on the verified
cache, the fresh-store tail fast path, the rebuild-and-compare audit, start-up warm-up, `sigil verify` / `vigil
doctor`. Every number below was measured on this repository, on one
container, single process — the extrapolations are stated as such.

## 1. Bottom line

The first wall between today's VIGIL and a million users is **not** horizontal sharding. It is the sovereign
plane's **read path**: every customer request recomputes its answer by folding the signed spine from the start and
**re-verifying every record's Ed25519 signature on every read**. Measured, that is ~160–200 µs per record, so a
single login lookup costs ~3 minutes at 1M customers (§2). Fix that first (a *verified fold index*, §4.S0); keep
ONE sovereign spine (it is what keeps money exactly-once and the global EC-5 cap exact); and shard only the
**offense execution fleet**, which D2 already half-built (§4.S2).

## 2. Measured baseline

| Measurement | Result | Method |
|---|---|---|
| Customer lookup (`CustomerRegistry.by_email`) | 102 ms @ 500 customers, 324 ms @ 2,000 → **~160–200 µs per record**, linear | real `SpineStore` + owner-signed `create`, 3 lookups averaged |
| Extrapolated to 1M customers | **~160–200 s per login lookup** | linear (the fold is a full scan; the cost is per-record signature verification) |
| Folds per customer request | `admit_customer` = **2 full folds** (orgs + memberships), plus the action's own (wallet, billing, cost …) | code trace: `orgs.org_role_can → membership_role → _fold_orgs + _fold_memberships` |
| Signed append (single writer) | **~1.1 ms** → ~900 appends/s per process before group-commit concurrency | same harness, `create` |
| What appends | every provisioner WRITE (incl. each login: `provision.audit`) and every money record; READS append nothing | code trace (`_audit`, `_customer_read`) |

Why it is O(N): `SnapshotState` (the hard-prune seed) is built but **pruning is not wired**, so every fold starts
at genesis; folds are pure functions of the spine with no cache. The design already made every fold
**associative** (`spine/snapshot.py`) — which is exactly the property an incremental index needs.

## 3. The walls, in the order they are hit

1. **W1 — sovereign read path (blocks first, ~10⁴–10⁵ customers).** O(N) signature-verifying folds on every
   request. Page latency grows linearly with the total customer + money history.
2. **W2 — single sovereign writer (watch, likely fine).** ~900 signed appends/s/process (more with group commit,
   C1a/C1b). At 1M users the write rate is ~logins + mutations: e.g. one login/user/day ≈ 12/s average, peaks
   maybe 10–50× ≈ 120–600/s — under the ceiling but close at peak. Measure before acting.
3. **W3 — offense execution fleet.** D2 already gives one-tenant-per-process workers and *requires* one
   `CRUCIBLE_ROOT` per tenant (`common/tenant.py`). Missing: who decides which worker host owns which tenant, a
   per-shard job queue + credit-lease seam, routing, and a way to move a tenant.
4. **W4 — global money (already safe if W1–W3 are done right).** Reserve / settle and the EC-5 global pool are
   folds over the SOVEREIGN spine. As long as that spine is not split, the global cap cannot be breached N× and
   `(slug, nonce)` exactly-once holds — sharding the execution fleet does not touch them.

## 4. Recommended architecture (synthesis of the three candidate angles)

The original design run framed three angles: (A) self-contained cells / shard-per-node, (B) global routing + an
owner-signed shard-assignment record, (C) minimal-diff consistent-hash pre-sharding over D2. Recommendation:
**B's signed assignment + C's minimal diff for the offense fleet, and NO cell split of the sovereign plane.**
A is rejected for the money/authority plane: per-cell sovereign spines split the EC-5 pool (a per-cell cap lets
the global cap be breached N×) and turn every cross-cell money move into a distributed transaction.

**S0 — verified fold index (the prerequisite; no topology change).** Each registry (customers, credentials,
orgs, memberships, wallet, billing/invoices, cost, …) keeps a materialized state plus `applied_through_seq` and
the chain `entry_hash` at that seq. A read folds only the records after the high-water — each signature is
verified **once, at ingest**, not on every read. The spine stays the only source of truth: the index is a cache,
bound to a chain head (a tampered or stale index is detected by re-checking the head and is rebuilt from the
spine), and `sigil verify` / `vigil doctor` can rebuild-and-compare. Default-OFF behind a flag, with an
equivalence test per registry (`index fold == full fold`, for random prefixes and after crash/restart).
Expected effect: a login lookup goes from O(N) (~minutes at 1M) to O(1)/O(log N) (sub-millisecond).

**S1 — write path (measure first).** Instrument appends/s by signal in production-shaped load. Only if the
measured peak approaches the ceiling: tune group commit, then batch-sign (one signature per committed group —
an invariant-touching change that would need its own owner review). No change proposed now.

**S2 — offense fleet sharding.** (a) An owner-signed `ShardAssignment{org_id → shard_id, epoch}` spine record
(new domain tag in `vigil_core/spine_domains.py`, signed by the Provisioner, verified keylessly at the routing
edge — mirrors the lease / authority records). (b) A shard = a set of worker processes on one host, each tenant
with its own `CRUCIBLE_ROOT` (D2's existing requirement, enforced by `assert_tenant_fleet_isolated`) and its own
job queue + credit-lease seam under the shard's base dir. (c) The launch path reads the assignment from the S0
index and publishes the lease to that shard's seam; a missing or mismatched assignment fails CLOSED. (d) An org-A
job delivered to a shard that does not own org A is refused by the existing `authorize_job._reconcile_tenant`
check — isolation only gets stronger. Default: one shard = today's single node, byte-identical.

**S3 — online tenant migration.** Reuse the pause/resume substrate (PR-1…5): pause the tenant → drain in-flight
(no new reservations; running jobs settle) → copy the tenant root + verify → append a signed `ShardAssignment`
with `epoch+1` → resume on the new shard. Reversible until the epoch bump; money exactly-once is preserved by the
`(slug, nonce)` settle idempotency; no spine fork (the sovereign spine is untouched; the tenant's engine spine
moves with its root).

**S4 — scale-acceptance gate (closing slice).** A load harness driving N tenants × M concurrent engagements to
**owner-set** targets, proving: no sovereign-spine fork; isolation holds during a live migration; the EC-5 cap is
never breached; no paid job stranded by a migration or node loss; exactly-once across the fleet. Production
multi-shard stays flag-held until it is green (the owner flips it, like `VIGIL_CUSTOMER_PROD_EXECUTION`).

**S0 retroactive review (2026-11-11).** Eight independent lenses, each finding verified by a refuter and a
reproducer. Kept on full scans by design and confirmed sound: the sovereign `OffenseGate` and the eval
capability-grant / offense-attestation folds (owner ceremonies, off the per-request path; no cached read feeds a
decision they gate). Contract made explicit: a cached read must equal the full verified fold on the same bytes —
the same answer, or the same raise — so a read that is not contiguous and complete is never cached, and a reader
returns an immutable value or a copy.

## 5. The six invariants

| Invariant | Recommended design |
|---|---|
| 1. The signed spine never forks | ONE sovereign spine, unchanged; engine spines are per-tenant and move whole. S0 is a cache, never a second chain. |
| 2. Isolation only gets stronger | One `CRUCIBLE_ROOT` per tenant (already required) + shard ownership check on top of `_reconcile_tenant`. |
| 3. FATAL-2 | The assignment is verified keylessly at the edge; no offense code enters the sovereign plane; S0 is sovereign-only. |
| 4. Money exactly-once + EC-5 pool | Reserve / settle / pool stay folds over the single sovereign spine (exact by construction); S0 changes HOW they are read, not WHAT is folded — equivalence-tested. |
| 5. Default-OFF / fail-closed | S0 flag-gated with fallback to the full fold; missing assignment ⇒ refuse; single-shard default byte-identical. |
| 6. Online, reversible migration | S3: pause → drain → copy+verify → signed epoch bump → resume; reversible before the bump. |

## 6. Slice plan (each PR-sized, default-OFF, mutation-verified)

1. **S0a** fold-index substrate (head binding, rebuild, tamper detection) + `customers` (`by_email`), flag-gated,
   with an equivalence + crash test. Re-measure the §2 benchmark.
2. **S0b** orgs + memberships (removes the 2 folds from every `admit_customer`).
3. **S0c** wallet, billing, invoices, cost ledger + EC-5 pool reads (money folds — red-pen hardest).
4. **S0d** remaining folds; `sigil verify` / `vigil doctor` rebuild-and-compare.
5. **S1** append-rate instrumentation (read-only); decide on batch-signing only with data. **Built:**
   `sigil spine append-rate` (`apps/sigil/sigil/spine/append_rate.py`) — appends/s overall and by payload signal
   (or kind / source), with the peak as the most appends in ANY W-second interval (exact timestamps, not
   clock-aligned buckets), folded from the records' own `ts`. Nothing is added to the append path. `ts` is
   outside the signed chain and an ingest supplies the event's own time, so the report is capacity telemetry,
   never evidence; it holds no threshold (`--ceiling` takes the operator's own measured figure — the targets
   stay §7.3).
6. **S2a** `ShardAssignment` record + keyless verify; **S2b** routing; **S2c** per-shard queue + lease seam.
7. **S3** migration (pause → drain → copy → epoch bump → resume), with a kill-mid-migration test.
8. **S4** scale-acceptance gate to the owner's targets.

## 7. Owner decisions

1. ✅ **Keep ONE sovereign spine** (rejecting per-cell sovereign spines) — the basis of §5 rows 1 and 4.
   Authorised 2026-11-10.
2. ✅ **S0's trust model:** the fold index is a cache of the signed spine, bound to a chain head, never
   authoritative; on any doubt the code falls back to the full verified fold. Authorised 2026-11-10.
3. ⏳ **Set the scale targets** for S4 (users, concurrent engagements, p99 login / page latency, appends/s at
   peak). These are capacity numbers — the owner's, not the agent's. **Still open.**
4. ✅ **Order:** S0 first (it is useful at any scale and unblocks every later measurement). Authorised 2026-11-10.
