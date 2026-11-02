"""
jobs.launch_runner — assemble the customer-launch EXECUTION path (slice K4-3).

:func:`make_engage_scan_runner` wires the one durable, authorized execution path for a customer launch: a
:class:`SecurityJobQueue` + a :class:`JobRunner` whose gate is :func:`build_customer_launch_gate` and whose
worker is :func:`make_engage_worker`. Execution happens SOLELY through ``JobRunner.run_one`` (claim →
authorize → run UNDER the per-slug run lease → complete), reusing the queue's exactly-once delivery dedup,
per-slug serialization, and ``requeue_stale`` crash recovery. No new execution system — it plugs the engage
worker into the SAME runner the W4 codescan path uses.

The caller enqueues produced jobs via ``runner.queue.enqueue(job)`` (the K4-2 ``LaunchTrigger`` produces
them) and drives them with ``runner.run_one()`` / ``runner.drain()``.

Integration-layer code: ``.queue`` / ``.runner`` / ``.authorize`` / ``.engage_worker`` at module scope (each
defers ``framework`` lazily) — NO ``framework`` at module scope, NO ``sigil`` import (two-env boundary).
"""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from .authorize import build_customer_launch_gate
from .engage_worker import make_engage_worker
from .queue import SecurityJobQueue
from .runner import JobRunner


def make_engage_scan_runner(
    root: "str | os.PathLike",
    *,
    base_dir: Any = None,
    trust_root: Any = None,
    killswitch: Any = None,
    now: Any = None,
    run: "Optional[Callable[..., Any]]" = None,
    profile_kwargs: "Optional[dict[str, Any]]" = None,
    prod_execution_enabled: "Optional[Callable[[], bool]]" = None,
    assert_tenant: "Optional[Callable[[], None]]" = None,
) -> JobRunner:
    """Build the customer-launch ``JobRunner`` (its ``.queue`` is the durable ``SecurityJobQueue`` at
    ``root``). The gate is the conjunctive customer-launch decision (verified customer authority ∧ owner-
    signed lease pre-check ∧ K4 prod-flag ∧ scope/window/kill-switch); the worker drives CRUCIBLE's existing
    governed engage path. ``run`` / ``prod_execution_enabled`` / ``trust_root`` / ``assert_tenant`` are
    injectable for tests; production uses the real engine, the real pinned owner root, the real flag, and the
    default tenant boundary. Execution is only ever via ``run_one`` — the queue exposes no run-a-callback."""
    queue = SecurityJobQueue(root)
    gate = build_customer_launch_gate(
        trust_root=trust_root, killswitch=killswitch, now=now, base_dir=base_dir,
        prod_execution_enabled=prod_execution_enabled)
    worker = make_engage_worker(
        base_dir=base_dir, trust_root=trust_root, run=run, profile_kwargs=profile_kwargs,
        prod_execution_enabled=prod_execution_enabled, now=now)
    kwargs: "dict[str, Any]" = {"queue": queue, "gate": gate, "worker": worker}
    if assert_tenant is not None:
        kwargs["assert_tenant"] = assert_tenant
    return JobRunner(**kwargs)
