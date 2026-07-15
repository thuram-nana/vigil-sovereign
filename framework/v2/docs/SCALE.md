# CRUCIBLE — scale characterization

CRUCIBLE's accuracy gate (`benchmark`) proves *detection quality* on a small labelled app; it never
exercised *scale*. `eval/soak.py` (the soak harness) closes that gap: a self-contained loopback app that
serves N in-scope endpoints, driven by a real `WebScanCampaign`, measuring throughput / memory and — the
load-bearing part — the **determinism-under-load** fingerprint.

Run it:

```
python3 -m framework.v2.eval.soak --endpoints 200 [--max-requests M]
```

## The load-bearing invariant: replay-determinism holds at scale

The `ScanReport` is a **pure function of its inputs**. This is what the byte-identical gate and the
Phase-1 discoverer's frontier/fold both rest on. `eval/tests/test_soak.py::
test_scan_is_replay_deterministic_at_scale` proves it: two full scans of the same N-endpoint surface
produce the byte-identical `scan_fingerprint` (findings + surface counts; wall-clock and the loopback's
ephemeral port excluded). No wall-clock, no RNG, no scheduling order leaks into the result.

## Measured (loopback, single host)

| endpoints | pages | audit reqs | elapsed | throughput | peak RSS |
|-----------|-------|-----------|---------|------------|----------|
| 25        | 26    | 1,104     | 11.2 s  | ~99 req/s  | 97 MB    |
| 100       | 101   | 4,404     | 44.7 s  | ~99 req/s  | 102 MB   |

Two facts the numbers show:

- **Throughput is FLAT at ~99 req/s** regardless of endpoint count. On loopback (no network latency) this
  is the *serial scan's* per-request processing ceiling on this host — the audit loop issues one request
  at a time through one shared `AuditEngine`/budget. Against a real target, network RTT dominates and the
  effective rate is lower; the serial design means the ceiling scales with per-request latency, not with
  the host's cores.
- **Memory is modest and sub-linear** (97→102 MB from 25→100 endpoints). The world-model + spine footprint
  grows slowly with discovered surface; it is not the scaling constraint at these sizes.

## Where the single-host design caps (by construction)

These are deliberate: they are exactly what keeps the determinism contract above true.

- **Serial scan.** `scanner/campaign.py`'s audit loop is a single `for req in all_requests:` over one
  shared `AuditEngine` with one shared active-traffic budget. This is the throughput cap and the reason
  the report is order-stable. A parallel audit path would reintroduce scheduling-order nondeterminism the
  byte-identical gate forbids — so it is NOT done.
- **Single-host SQLite event spine.** `agents/blackboard.py` is one WAL SQLite file per host with a single
  logical clock (append-only, trigger-enforced). One writer; no cross-host ordering. There is **no
  multi-host event bus** — that would break the single logical clock the spine's hash-chain verification
  depends on.
- **Whole-log chain verification.** `agents/spine_chain.py` verifies the entire event log (fail-closed on
  any incomplete read); `blackboard.replay` pages to a 100k limit. Verification cost is O(log size), so a
  very long-running engagement's spine is the memory/time pressure point, not endpoint count.
- **Recon is default-serial.** `intel/ingest.py` runs collectors serially by default (predictable, no-
  surprise traffic).

## The safe concurrency win (stays byte-identical)

`intel/ingest.py` already has the one concurrency lever that preserves determinism: set
`CRUCIBLE_RECON_MAX_WORKERS > 1` to fan recon collectors through a thread pool whose results are **ingested
in input order**, so the outcome is byte-identical to the serial loop while overlapping the (network-bound)
third-party lookups. This is the template for any future concurrency: parallelize the *I/O wait*, but
ingest/fold in a fixed order so the result stays a pure function of inputs.

## What is deliberately NOT done

- A parallel *audit* path (would break scan-order determinism → the byte-identical gate).
- A multi-host / shared event bus (would break the single logical clock → the spine's chain verification).

Either is a separate, explicit design decision — not a drop-in — and would need its own determinism
contract before it could land. The soak harness is the tool to measure the tradeoff when that day comes.
