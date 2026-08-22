# W11-4 — resource exhaustion fails closed on the audit/spine writer

**Milestone:** W11 — TESTING DEPTH · **Issue:** #485 · **Registers in:** W0-3 #398.

## The claim under test

VIGIL's most load-bearing audit-trail claim is *fail-closed on an unwritable audit*. Until W11-4 that
claim had no test under the resource-exhaustion conditions it names: no RLIMIT, OOM, disk-full or
fd-exhaustion test existed, despite the writer's contract asserting that a failed durable append surfaces
rather than being swallowed.

<!-- CLAIM:W11-4 --> The audit/spine writer fails closed on an unwritable audit: when the append-only signed spine cannot durably accept a record, `VigilCoreSpine.writer` raises rather than returning as if the action were audited, and it never advances its append point on a failed write.

## Where it is enforced

`integration/vigil_integration/live/spine_vigilcore.py` — `VigilCoreSpine.writer` (reached ergonomically
via `write_state`). The durable append (`_append_line`) is not wrapped in a swallow: any `OSError`
(ENOSPC / ENOTDIR / EMFILE), `MemoryError`, or `SpineWriteError` propagates to the caller, and the
in-memory append point (`_last_entry`) is advanced only *after* a successful write. A caller therefore
can never mistake a failed audit write for a persisted one.

## How it is proven

`integration/tests/test_spine_resource_exhaustion_failclosed.py` puts the writer into each named state
and asserts it raises AND does not advance the append point, each with a negative control that the SAME
operation succeeds when the resource is available:

| State | How the state is forced | Test |
|-------|-------------------------|------|
| Unwritable audit sink | spine path's parent is a regular file → `open("a")` raises `ENOTDIR` (uid-independent) | `test_unwritable_audit_sink_refuses_the_action` |
| Disk-full (`ENOSPC`) | the append write is monkeypatched to raise `OSError(ENOSPC)` — **this test pins this claim** | `test_disk_full_enospc_refuses_and_does_not_advance` |
| FD exhaustion (`RLIMIT_NOFILE`) | a forked child lowers `RLIMIT_NOFILE` and exhausts the fd table → `open` raises `EMFILE` | `test_fd_exhaustion_rlimit_nofile_refuses` |
| OOM (bounded) | the append write is monkeypatched to raise `MemoryError` (deterministic stand-in for `RLIMIT_AS`/OOM) | `test_oom_memoryerror_on_append_refuses_and_does_not_advance` |

The failure is *observed*, not assumed: on a tree where `_append_line` swallows the durability failure
(a simulated fail-open regression), all four tests fail.

The tests run in the required `integration two-env boundary (P5)` CI job.

## Scope note

The WARDEN Rust kernel action-log already pins the unwritable-audit fail-closed claim from the *kernel*
side (`apps/sigil/kernel/tests/fail_closed.rs`, exit-4-on-unauditable with a healthy-home control). W11-4
adds the resource-exhaustion states (RLIMIT / OOM / ENOSPC / fd) against the Python audit/spine writer,
which is where they can be exercised deterministically without root.
