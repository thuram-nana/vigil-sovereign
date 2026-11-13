"""Front C S0d — start-up WARM-UP and periodic AUDIT of the verified fold caches (`spine/fold_cache.py`).

WARM-UP. A cache is built by the first read of its fold in a process: O(spine) — about 2.5 minutes at 1M records
(design §7). `warm_all(store)` makes that first read for every cached registry, once, in a background thread the
cockpit starts at boot (`start_background`), so it is never paid by a request. Requests that arrive before it
finishes are simply served by whichever path is ready (a concurrent first read builds the cache itself; the
warm-up then finds it built).

AUDIT. `audit(store)` makes the same reads under `fold_read.auditing()`: every cached fold is rebuilt from the spine
with that read's own fresh build and compared with the cached state (match / MISMATCH / skipped / empty). The background thread re-runs it every
`VIGIL_FOLD_CACHE_AUDIT_S` seconds (default 6 h; 0 = start-up warm-up only) and writes the result atomically to
`config.FOLD_AUDIT_PATH`, which `vigil doctor` reads (a MISMATCH is a hard issue there) and `sigil verify` prints.
A rebuild costs what a cold start costs, which is why the default interval is long; reads keep being served while
it runs (the fresh fold is computed outside the entry lock). A MISMATCH discards that cache entry — the spine is
the source of truth, so the next read rebuilds from it — and the report keeps the evidence. Nothing here writes
the spine.

Everything here is a no-op unless `VIGIL_FOLD_CACHE_ENABLED` is on. FATAL-2: sovereign-side.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .. import config
from ..reuse import assert_no_offense
from . import fold_read

assert_no_offense()

__all__ = ["audit", "start_background", "warm_all", "write_report"]

_log = logging.getLogger(__name__)
_STARTED: "set[str]" = set()
_STARTED_LOCK = threading.Lock()


def _warmers(store) -> "list[tuple[str, Callable[[], Any]]]":
    """One cached read per cached fold, each through the registry's public read path or its `_cached` hook, under
    the persisted owner identity (exactly the registries the request paths construct)."""
    from ..ui import assessments, margin
    from . import (accounts, asset_ownership, budget, capability, cost_ledger, customer_credentials, customers,
                   invoices, killswitch, metering, monitoring_authority, monitoring_subscription, orgs, postpaid,
                   promotion, report_unlock, subscription, trial_claim, wallet)
    from .identity import owner_pubkey

    def touch(registry) -> Callable[[], Any]:
        return lambda: registry._cached(lambda v: None)

    own = asset_ownership.AssetOwnershipRegistry(store, owner_key=None)
    return [
        ("customers", touch(customers.CustomerRegistry(store, owner_key=None))),
        ("orgs", touch(orgs.OrgRegistry(store, owner_key=None))),
        ("wallet", touch(wallet.WalletRegistry(store, owner_key=None))),
        ("plan ledger", touch(metering.PlanCreditLedger(store, owner_key=None))),
        ("subscriptions", touch(subscription.SubscriptionRegistry(store, owner_key=None))),
        ("monitoring subscriptions",
         touch(monitoring_subscription.MonitoringSubscriptionRegistry(store, owner_key=None))),
        ("accounts", touch(accounts.AccountsRegistry(store, owner_key=None))),
        ("customer credentials", touch(customer_credentials.CustomerCredentialRegistry(store, owner_key=None))),
        ("invoices", touch(invoices.InvoiceRegistry(store, owner_key=None))),
        ("trial claims", touch(trial_claim.TrialClaimRegistry(store, owner_key=None))),
        ("report unlocks", touch(report_unlock.ReportUnlockRegistry(store, owner_key=None))),
        ("cost ledger", touch(cost_ledger.CostEnvelopeLedger(store, owner_key=None))),
        ("postpaid accounts", touch(postpaid.PostpaidRegistry(store, owner_key=None))),
        ("postpaid arrears", touch(postpaid.PostpaidArrearsLedger(store, owner_key=None))),
        ("promotion", touch(promotion.PromotionPolicy(store, owner_key=None))),
        ("ownership proofs", lambda: own._proofs_cached(lambda v: None)),
        ("ownership challenges", lambda: own._challenges_cached(lambda v: None)),
        ("monitoring authority", touch(monitoring_authority.MonitoringAuthorityRegistry(store, owner_key=None))),
        ("kill switch", lambda: killswitch.KillSwitch(store, owner_key=None).is_engaged()),
        ("capabilities", lambda: capability.CapabilityGate(store, owner_key=None).state_all()),
        ("agent budget", lambda: budget.BudgetLedger(store).spent("", _dt.datetime.now(_dt.timezone.utc)
                                                                  .strftime("%Y-%m-%d"))),
        ("assessments", lambda: assessments._indexed(store, "findings", ())),
        ("margin settles", lambda: margin._settle_events(store, owner_pubkey())),
    ]


def warm_all(store) -> "list[dict]":
    """Make the first (O(spine)) read of every cached fold now. Never raises: a fold that fails to warm is
    reported and simply builds on its first request instead. No-op (empty) with the cache off."""
    if not config.fold_cache_enabled():
        return []
    out = []
    for name, warm in _warmers(store):
        t0 = time.monotonic()
        try:
            warm()
            out.append({"fold": name, "status": "warm", "seconds": round(time.monotonic() - t0, 3)})
        except Exception as exc:  # noqa: BLE001 — warm-up must never take the process down
            _log.warning("fold cache warm-up failed for %s: %s", name, exc)
            out.append({"fold": name, "status": "error", "error": f"{type(exc).__name__}: {exc}"})
    return out


def audit(store) -> dict:
    """Rebuild every cached fold of `store` and compare (see `fold_cache.FoldCache.audit`), through each registry's
    own read path. `ok` is False iff any fold reported a MISMATCH. No-op (`folds` empty) with the cache off."""
    errors = []
    with fold_read.auditing() as found:
        if config.fold_cache_enabled():
            for name, read in _warmers(store):
                try:
                    read()
                except Exception as exc:  # noqa: BLE001 — one failing fold must not hide the others' results
                    errors.append({"fold": name, "status": "error", "error": f"{type(exc).__name__}: {exc}"})
    results = [found[k] for k in sorted(found)] + errors
    return {"ok": not any(r.get("status") == "MISMATCH" for r in results),
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "pid": os.getpid(), "spine": str(getattr(store, "path", "")),
            "interval_s": config.fold_cache_audit_interval(), "folds": results}


def write_report(report: dict, path: Optional[Path] = None) -> Path:
    """Write `report` atomically (0600) for `vigil doctor` / `sigil verify` to read."""
    p = Path(path) if path is not None else config.FOLD_AUDIT_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, p)
    return p


def _run(store_factory: Callable[[], Any], interval: float, stop: threading.Event) -> None:
    try:
        warm_all(store_factory())
    except Exception:  # noqa: BLE001 — logged by warm_all; never kill the worker
        _log.exception("fold cache warm-up failed")
    while interval > 0 and not stop.wait(interval):
        if not config.fold_cache_enabled():
            continue
        try:
            report = audit(store_factory())
            if stop.is_set():
                return                            # stopped mid-audit: never write after the owner stopped us
            write_report(report)
            if not report["ok"]:
                _log.error("fold cache audit MISMATCH: %s",
                           [r for r in report["folds"] if r.get("status") == "MISMATCH"])
        except Exception:  # noqa: BLE001 — an audit failure is logged; the next interval retries
            _log.exception("fold cache audit failed")


def start_background(store_factory: Callable[[], Any], *, name: str = "cockpit") -> Optional[threading.Event]:
    """Start the warm-up (+ periodic audit) daemon thread once per process and spine, iff the fold cache is on.
    `store_factory` returns a fresh `SpineStore` for the spine the process serves. Returns the stop event (tests),
    or None when nothing was started (cache off, or already running for this spine)."""
    if not config.fold_cache_enabled():
        return None
    try:
        ident = str(Path(store_factory().path).resolve())
    except Exception:  # noqa: BLE001 — an unresolvable store: nothing to warm
        return None
    with _STARTED_LOCK:
        if ident in _STARTED:
            return None
        _STARTED.add(ident)
    stop = threading.Event()
    worker = threading.Thread(target=_run, args=(store_factory, config.fold_cache_audit_interval(), stop),
                              name=f"fold-cache-{name}", daemon=True)
    stop.thread = worker                          # type: ignore[attr-defined]  # tests join it after stop.set()
    worker.start()
    return stop
