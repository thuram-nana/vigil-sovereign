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
A report describes the caches of the process that wrote it, named by a per-process `instance` nonce (a PID is not a
name: a container's cockpit is PID 1 on every start). The cockpit holds an exclusive lock on the sibling
`fold_cache_audit.lock` while it runs, so another process (`sigil verify` in an init container, a restarted cockpit)
can tell whether that writer is still running from the lock alone, across PID namespaces on a shared SIGIL_HOME.
A rebuild costs what a cold start costs, which is why the default interval is long; reads keep being served while
the fresh fold is computed (outside the entry lock), but the final by-value compare runs UNDER that fold's entry
lock, so its reads wait for it — O(the folded state; seconds at 1M customers, once per fold per audit). A MISMATCH discards that cache entry — the spine is
the source of truth, so the next read rebuilds from it — and the report keeps the evidence. Nothing here writes
the spine.

Everything here is a no-op unless `VIGIL_FOLD_CACHE_ENABLED` is on. FATAL-2: sovereign-side.
"""
from __future__ import annotations

import datetime as _dt
import fcntl
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .. import config
from ..reuse import assert_no_offense
from . import fold_read

assert_no_offense()

__all__ = ["audit", "hold_report_lock", "instance_id", "report_is_live", "start_background", "supersede_dead_report",
           "warm_all", "write_report"]

_log = logging.getLogger(__name__)
_STARTED: "set[str]" = set()
_STARTED_LOCK = threading.Lock()
_INSTANCE: "list[str]" = [""]              # this process's report identity, drawn on first use
_HELD: "dict[str, int]" = {}               # resolved lock path -> the fd that holds it, kept open for life
_HELD_LOCK = threading.Lock()
_LOCK_TRIES = 20                           # a prober holds the lock for microseconds; retry it briefly
_LOCK_RETRY_S = 0.05


def instance_id() -> str:
    """This process's audit-report identity: a random nonce drawn once per process (a forked child draws its own).
    It names the writer of a report where its PID cannot: a container's cockpit has the same PID on every start."""
    if not _INSTANCE[0]:
        _INSTANCE[0] = secrets.token_hex(16)
    return _INSTANCE[0]


def _forget_in_child() -> None:
    """After a fork the child is another process: it draws its own instance and closes its inherited copies of the
    report lock WITHOUT unlocking them (the parent still holds the lock), so a child that outlives the cockpit never
    keeps the cockpit's report live."""
    _INSTANCE[0] = ""
    fds = list(_HELD.values())
    _HELD.clear()
    _HELD_LOCK.release()
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


os.register_at_fork(before=_HELD_LOCK.acquire, after_in_parent=_HELD_LOCK.release, after_in_child=_forget_in_child)


def _lock_path(path: Optional[Path] = None) -> Path:
    """The lock beside the report (`fold_cache_audit.json` -> `fold_cache_audit.lock`)."""
    return (Path(path) if path is not None else config.FOLD_AUDIT_PATH).with_suffix(".lock")


def _holds_lock(path: Optional[Path] = None) -> bool:
    with _HELD_LOCK:
        return str(_lock_path(path).resolve()) in _HELD


def hold_report_lock(path: Optional[Path] = None) -> bool:
    """Take the exclusive lock beside the audit report and keep it for the life of this process (the kernel drops it
    when the process dies, in any PID namespace). The process that holds it is the running cockpit, so a report's
    writer is still running iff the lock is held. Returns True iff this process holds it (False when another
    running process does, or the lock cannot be taken)."""
    lp = _lock_path(path)
    key = str(lp.resolve())
    with _HELD_LOCK:
        if key in _HELD:
            return True
        try:
            lp.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(lp, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            _log.warning("fold cache: cannot open the audit report lock %s: %s", lp, exc)
            return False
        for attempt in range(_LOCK_TRIES):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if attempt + 1 < _LOCK_TRIES:
                    time.sleep(_LOCK_RETRY_S)        # a probe (shared, momentary) or another running cockpit
                continue
            except OSError as exc:
                _log.warning("fold cache: cannot lock the audit report lock %s: %s", lp, exc)
                break
            _HELD[key] = fd
            return True
        os.close(fd)
        return False


def _release_report_lock(path: Optional[Path] = None) -> None:
    """Drop this process's hold on the report lock (tests; a cockpit keeps it until it exits)."""
    with _HELD_LOCK:
        fd = _HELD.pop(str(_lock_path(path).resolve()), None)
    if fd is not None:
        os.close(fd)


def _lock_held_elsewhere(path: Optional[Path] = None) -> bool:
    """Whether ANOTHER running process holds the report lock. Probes with a shared, non-blocking lock it releases at
    once, and never creates the file. When it cannot tell (the lock cannot be opened or probed) it answers True:
    the report then stays live, so a recorded MISMATCH keeps counting (fail closed)."""
    try:
        fd = os.open(_lock_path(path), os.O_RDONLY)
    except FileNotFoundError:
        return False                               # never taken: no cockpit has run with this report
    except OSError:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError:                                # EWOULDBLOCK: held; anything else: cannot tell
        return True
    finally:
        os.close(fd)                               # releases the probe's own shared lock
    return False


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
            "pid": os.getpid(), "instance": instance_id(), "spine": str(getattr(store, "path", "")),
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


def _pid_alive(pid: Any) -> bool:
    """True iff `pid` names a running process (False for anything that is not a positive int)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:                                # EPERM: it exists, under another user
        return True
    return True


def report_is_live(report: dict, path: Optional[Path] = None) -> bool:
    """A report describes the caches of the process that wrote it, and those die with it. True iff that process
    is this one or is still running — only then does a recorded MISMATCH describe a cache that still serves.

    The writer is named by its `instance` nonce, never by its PID alone. This process wrote it iff the nonce is
    ours. Otherwise its writer is running iff the report lock (`hold_report_lock`) is held by another process: when
    THIS process holds that exclusive lock, no other cockpit is running, so the writer is gone. A report written
    before reports carried an instance falls back to its PID, but this process's own PID never makes it live (this
    process would have written its instance)."""
    inst = report.get("instance")
    if not isinstance(inst, str) or not inst:
        pid = report.get("pid")
        return pid != os.getpid() and _pid_alive(pid)
    if inst == instance_id():
        return True
    if _holds_lock(path):
        return False
    return _lock_held_elsewhere(path)


def supersede_dead_report(path: Optional[Path] = None) -> bool:
    """At process start: if the last report was written by a process that is GONE, replace it with an empty one for
    this process that keeps the old verdict under `superseded` (its caches died with it; this process rebuilds
    from the spine). Without this a recorded MISMATCH outlived every restart and kept `vigil doctor` (a HARD issue)
    and `sigil verify` failing until someone deleted the file by hand. A report from a LIVE process is left alone.
    `vigil doctor` and `sigil verify` show a superseded MISMATCH as a note; a report that itself only carries one
    (a restart before any audit) hands it on, so a run of restarts does not drop it. This process takes the report
    lock first, so the report it writes is live. Returns True iff it replaced one."""
    p = Path(path) if path is not None else config.FOLD_AUDIT_PATH
    try:
        old = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(old, dict):
        return False
    hold_report_lock(p)
    if report_is_live(old, p):
        return False
    folds = [f for f in old.get("folds", []) if isinstance(f, dict)]
    verdict = {"pid": old.get("pid"), "ts": old.get("ts"), "ok": old.get("ok"),
               "mismatched": [f.get("fold") for f in folds if f.get("status") == "MISMATCH"]}
    earlier = old.get("superseded")
    if not verdict["mismatched"] and isinstance(earlier, dict) and earlier.get("mismatched"):
        verdict = earlier
    write_report({"ok": True, "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                  "pid": os.getpid(), "instance": instance_id(), "spine": old.get("spine", ""),
                  "interval_s": config.fold_cache_audit_interval(), "folds": [],
                  "cache_enabled": config.fold_cache_enabled(), "superseded": verdict}, p)
    return True


def start_background(store_factory: Callable[[], Any], *, name: str = "cockpit") -> Optional[threading.Event]:
    """Start the warm-up (+ periodic audit) daemon thread once per process and spine, iff the fold cache is on.
    `store_factory` returns a fresh `SpineStore` for the spine the process serves. Returns the stop event (tests),
    or None when nothing was started (cache off, or already running for this spine). Either way it first
    supersedes a report left by a process that is gone (`supersede_dead_report`). With the cache on it holds the
    report lock for the life of the process (`hold_report_lock`): the reports it writes are live while it runs."""
    try:
        supersede_dead_report()
    except Exception:  # noqa: BLE001 — never block a cockpit start on the report file
        _log.exception("could not supersede the previous fold-cache audit report")
    if not config.fold_cache_enabled():
        return None
    hold_report_lock()
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
