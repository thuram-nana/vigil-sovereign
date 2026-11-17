"""W5 — the low-balance EMAIL: once per crossing, to the org's billing administrators, sent from the cockpit.

``config.low_balance_alert_enabled()`` (``VIGIL_BILLING_LOW_BALANCE_ALERT``, default OFF) starts a background sweep in
the cockpit (``ui/server.py::serve``; the process that sends the account emails). Every ``interval_s`` it asks
``governor.low_balance`` about every org with wallet activity, and for each org that is low it sends one email per
crossing — the KEY is the org plus its last top-up, so the next top-up re-arms it:

  * the crossing is CLAIMED with a marker file named ``sha256(org NUL key)`` in ``$SIGIL_HOME/customer/
    billing-alerts/`` (0700; the file 0600, ``O_NOFOLLOW``, held under an exclusive ``flock`` while it is sent), so two
    sweeps — threads or processes — never send it twice;
  * the marker records how many attempts were made and whether one was delivered (never an address): an email the
    sender could not hand over is retried on the next sweeps, at most ``_MAX_ATTEMPTS`` times in all;
  * the recipients are the org's active members whose role may manage billing (``manage_billing``: founder,
    org_admin), at the address of their customer account;
  * the copy states the threshold in credits and nothing else — never an estimate, a money amount or an engine name.

The notification centre shows the same condition at read time (``provision.customer_notifications``,
``billing:low_balance:<key>``). Tests inject a sender (the ``NullEmailSender`` sends nothing). FATAL-2: sovereign-side.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

_log = logging.getLogger(__name__)

_MAX_ATTEMPTS = 3
_DEFAULT_INTERVAL_S = 60.0
SUBJECT = "Your VIGIL credit balance is low"


def alerts_dir() -> Path:
    """``$SIGIL_HOME/customer/billing-alerts`` (resolved at call time)."""
    home = Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))
    return home / "customer" / "billing-alerts"


def email_body(threshold: int) -> str:
    """The email text: the threshold in credits, what to do, and when it is sent — nothing else."""
    return (f"The available credit balance of your VIGIL workspace is below {int(threshold)} credits.\n\n"
            "Top up on the Billing page to keep your assessments running.\n\n"
            "You get this email once each time the balance falls below that line; your next top-up re-arms it.\n")


class LowBalanceAlerts:
    """One sweep over the orgs, sending each crossing's email once. Registries are injected for tests; in production
    they default to the owner-identity registries over ``store`` (reads only: nothing here signs)."""

    def __init__(self, store, *, sender, directory: "Optional[Path]" = None, wallet=None, meter=None, invoices=None,
                 orgs=None, customers=None):
        from ..governor.customers import CustomerRegistry
        from ..governor.invoices import InvoiceRegistry
        from ..governor.metering import CreditMeter, PlanCreditLedger
        from ..governor.orgs import OrgRegistry
        from ..governor.subscription import SubscriptionRegistry
        from ..governor.wallet import WalletRegistry
        self.store = store
        self.sender = sender
        self.dir = Path(directory) if directory is not None else alerts_dir()
        self.wallet = wallet if wallet is not None else WalletRegistry(store)
        self.meter = meter if meter is not None else CreditMeter(self.wallet, PlanCreditLedger(store),
                                                                 SubscriptionRegistry(store))
        self.invoices = invoices if invoices is not None else InvoiceRegistry(store)
        self.orgs = orgs if orgs is not None else OrgRegistry(store)
        self.customers = customers if customers is not None else CustomerRegistry(store)

    def recipients(self, org_id: str) -> "list[str]":
        """The addresses of the org's active members who may manage its billing (one per address, sorted)."""
        from vigil_core.rbac import role_can
        out: "set[str]" = set()
        for m in self.orgs.memberships(org_id):
            if getattr(m, "state", "active") != "active" or not role_can(m.role, "manage_billing"):
                continue
            acct = self.customers.customer(m.username)
            email = getattr(acct, "email", "") if acct is not None else ""
            if email:
                out.add(email)
        return sorted(out)

    def _send(self, to: str, body: str) -> bool:
        try:
            return bool(self.sender.send(to, SUBJECT, body))
        except Exception:  # noqa: BLE001 — a sender fault is "not delivered", never a crash of the sweep
            _log.warning("the low-balance email could not be handed to the sender", exc_info=True)
            return False

    def alert(self, lb, *, now: float) -> dict:
        """Send ``lb``'s email unless its crossing was already delivered (or its attempts are spent)."""
        import fcntl
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = hashlib.sha256(f"{lb.org_id}\0{lb.key}".encode("utf-8")).hexdigest() + ".json"
        fd = os.open(str(self.dir / name), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        row: "dict[str, Any]" = {"org_id": lb.org_id, "key": lb.key}
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {**row, "status": "busy"}
            raw = os.read(fd, 65536)
            try:
                st = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                st = {"attempts": _MAX_ATTEMPTS}                # an unreadable marker is never re-sent
            if not isinstance(st, dict):
                st = {"attempts": _MAX_ATTEMPTS}
            if st.get("sent") is True:
                return {**row, "status": "already_sent"}
            av = st.get("attempts", 0)              # a fresh (empty) marker starts at 0; only a corrupt one is spent
            attempts = av if isinstance(av, int) and not isinstance(av, bool) else _MAX_ATTEMPTS
            if attempts >= _MAX_ATTEMPTS:
                return {**row, "status": "gave_up"}
            to = self.recipients(lb.org_id)
            body = email_body(lb.threshold)
            delivered = sum(1 for addr in to if self._send(addr, body))
            rec = {"v": 1, "attempts": attempts + 1, "sent": delivered > 0, "recipients": len(to), "at": float(now)}
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, json.dumps(rec, sort_keys=True).encode("utf-8"))
            return {**row, "status": "sent" if delivered else "unsent", "recipients": len(to)}
        finally:
            os.close(fd)

    def sweep(self, now: float) -> "list[dict]":
        """Check every org with wallet activity; send the email of each low one whose crossing is not yet delivered."""
        from ..governor.low_balance import low_balance
        out: "list[dict]" = []
        for bal in self.wallet.balances():
            lb = low_balance(bal.org_id, now=now, meter=self.meter, wallet=self.wallet, invoices=self.invoices)
            if lb is not None:
                out.append(self.alert(lb, now=now))
        return out


_STARTED: "set[str]" = set()
_STARTED_LOCK = threading.Lock()


def start_background(store_factory: Callable[[], Any], *, interval_s: float = _DEFAULT_INTERVAL_S,
                     sender=None) -> "Optional[threading.Event]":
    """Start the low-balance email sweep once per process and spine, iff ``config.low_balance_alert_enabled()``.
    Returns the stop event (tests), or None when nothing was started. A sweep that fails is logged and retried at the
    next interval; it never takes the cockpit down."""
    from .. import config
    if not config.low_balance_alert_enabled():
        return None
    try:
        ident = str(Path(store_factory().path).resolve())
    except Exception:  # noqa: BLE001 — an unresolvable store: nothing to sweep
        return None
    with _STARTED_LOCK:
        if ident in _STARTED:
            return None
        _STARTED.add(ident)
    stop = threading.Event()

    def _run() -> None:
        while not stop.wait(float(interval_s)):
            try:
                LowBalanceAlerts(store_factory(), sender=sender if sender is not None else config.email_sender()
                                 ).sweep(time.time())
            except Exception:  # noqa: BLE001 — a failed sweep is retried at the next interval
                _log.exception("the low-balance email sweep failed (retried at the next interval)")

    worker = threading.Thread(target=_run, name="billing-alerts", daemon=True)
    stop.thread = worker                          # type: ignore[attr-defined]  # tests join it after stop.set()
    worker.start()
    return stop
