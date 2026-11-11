"""Audit E1b — the owner-signed PENDING plan-checkout record behind the second-plan guard.

The CHK-1b double-billing guard (``Provisioner._org_has_live_plan``) reads only DRAINED subscriptions, and a plan
charge reaches the subscription registry only once its webhook drains — which can lag a paid checkout by a drain
tick, or by the ~15 min NET-2b transient-verify parking window. Until then a second (third, ...) plan checkout for
the same org was created and could be paid: two processor subscriptions, the customer billed twice.

``PendingPlanCheckouts.claim`` records, per ORG, the plan checkout being opened, BEFORE the outbound processor
call. A second plan checkout for the same org is refused while that record is live; once the first plan drains, the
drained subscription refuses it instead (``_org_has_live_plan``), so the record only has to bridge the undrained
gap. Pinned properties:

  * TAMPER-EVIDENT — the record is OWNER-SIGNED (``governor.authn.signed_payload`` over the org, price, tx_ref and
    its window), the same signature the provisioner puts on every owner record. Neither the keyless customer edge
    nor anyone without the owner key can forge or alter one (e.g. back-date it to look expired, or move it to
    another org). A record that does not verify, or is unreadable / not JSON, REFUSES the plan checkout with an
    operator-readable reason (fail-closed): it is never trusted. Such a record is only reaped once its FILE is
    older than the TTL (no live checkout's window can still depend on it, and whoever could alter its mtime could
    delete it outright) — so an owner-key rotation or a disk fault cannot lock an org out for ever either.
  * EXPIRING, but never before the link it guards is dead — ``expires_at = created_at + ttl_s``. A plan checkout
    asks the processor for a hosted-payment SESSION of ``PLAN_LINK_SESSION_MIN`` minutes (after which the processor
    closes the payment page and fails any uncompleted transaction), so the link cannot be paid after that; the
    default ``DEFAULT_TTL_S`` covers that session PLUS ``DRAIN_LAG_S`` (a payment completed in the session's last
    second still has to clear the 60 s drain timer and up to ~15 min of NET-2b parking before its plan is drained
    and ``_org_has_live_plan`` takes over). So an ABANDONED checkout does not lock the org out of buying a plan
    for ever, and a record can only lapse once its link can no longer bill. An expired, verified record is
    replaced by the next claim.
  * EXCLUSIVE across processes — the read-decide-write runs under an exclusive ``flock`` on ``<dir>/.claim.lock``,
    and a new record is published with ``os.link`` (an atomic exclusive create of a fully-written file), so two
    racing POSTs — in one cockpit process or several — can never both claim.
  * CLOCK SKEW — the decision is "live iff now < expires_at" on the owner-signed window; a record whose
    ``created_at`` lies in the future (the clock moved backwards) stays live (refuses) and says so in the reason.
  * TOP-UPS are never claimed: only the plan branch of ``billing_checkout`` calls this.
  * DELETION fails closed: the file lives under SIGIL_HOME, so a local writer could delete it — but the provisioner
    also writes each CREATED plan checkout (its tx_ref and this record's ``expires_at``) to the tamper-evident spine
    audit and refuses a new plan checkout while such a row is still within its window, so deleting the file does
    not reopen the second-plan window (see ``Provisioner._spine_live_plan_checkout``).

``release`` drops a record only if it is still THIS checkout's (same tx_ref) — used when the processor refused the
checkout, so a customer who never received a link can retry at once. Fail-closed throughout: no owner key, no
``flock``, or an I/O fault refuses the claim (an over-refusal, never a second subscription).

FATAL-2: sovereign-side (``assert_no_offense`` at import); stdlib + the sovereign ``governor.authn`` signer only.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

try:
    import fcntl  # noqa: E402  POSIX advisory lock: cross-PROCESS serialization of claim()/release()
except ImportError:  # pragma: no cover - non-POSIX: claim() then fails closed
    fcntl = None  # type: ignore[assignment]

from ..governor.authn import signed_payload, verify_signed  # noqa: E402

SIGNAL = "provision.pending_plan_checkout"
_CORE = ("signal", "org_id", "price_id", "tx_ref", "created_at", "expires_at")
# The hosted-payment session a PLAN checkout asks the processor for (minutes; the processor's ceiling is 1440).
PLAN_LINK_SESSION_MIN = 30
# The worst-case lag from a payment completed at the session's last second to its plan being DRAINED: the 60 s
# drain timer + NET-2b parking (5 s doubling to a 300 s cap over 8 attempts, ~915 s), with ample margin.
DRAIN_LAG_S = 30 * 60.0
DEFAULT_TTL_S = PLAN_LINK_SESSION_MIN * 60.0 + DRAIN_LAG_S
_LOCK_NAME = ".claim.lock"
_MAX_BYTES = 8192


class PendingCheckoutRefused(Exception):
    """A plan checkout may not be opened now. ``str(exc)`` is safe to show the customer; ``detail`` is the
    operator-readable reason (for the audit) and ``code`` a short machine outcome."""

    def __init__(self, message: str, *, code: str, detail: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.detail = detail or message


def _num(v: object) -> Optional[float]:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


class PendingPlanCheckouts:
    """One owner-signed marker per org (named ``sha256("org:" + org_id)`` — no traversal, no cross-org collision)
    under ``path``. ``owner_key`` signs, ``trusted_pubkey`` verifies (production: the deployment owner identity)."""

    def __init__(self, path: "str | os.PathLike", *, owner_key, trusted_pubkey: Optional[str],
                 ttl_s: float = DEFAULT_TTL_S) -> None:
        self.dir = Path(path)
        self.owner_key = owner_key
        self.trusted_pubkey = trusted_pubkey
        self.ttl_s = float(ttl_s)

    def _marker(self, org_id: str) -> Path:
        return self.dir / hashlib.sha256(f"org:{org_id}".encode("utf-8")).hexdigest()

    def _locked_fd(self) -> int:
        """Open + exclusively flock the claim lock; raises OSError (the caller fails closed)."""
        if fcntl is None:  # pragma: no cover - non-POSIX
            raise OSError("no flock on this platform")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(self.dir / _LOCK_NAME), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            raise
        return fd

    def _read(self, marker: Path, org_id: str) -> "tuple[Optional[dict], str]":
        """(record, problem): (None, "") when absent; (rec, "") when it VERIFIES for this org; (None, why) when
        it exists but cannot be trusted (unreadable, not JSON, bad signature, foreign org, malformed window)."""
        try:
            fd = os.open(str(marker), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return None, ""
        except OSError as exc:
            return None, f"unreadable ({type(exc).__name__})"
        try:
            raw = os.read(fd, _MAX_BYTES)              # bounded: a larger (never written) file fails to parse below
        except OSError as exc:
            return None, f"unreadable ({type(exc).__name__})"
        finally:
            os.close(fd)
        try:
            rec = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None, "not valid JSON"
        if not isinstance(rec, dict):
            return None, "not a JSON object"
        if not verify_signed(rec, _CORE, self.trusted_pubkey):
            return None, "owner signature does not verify"
        if rec.get("signal") != SIGNAL or rec.get("org_id") != org_id:
            return None, "signed for a different purpose or org"
        ca, ea = _num(rec.get("created_at")), _num(rec.get("expires_at"))
        if ca is None or ea is None or not ea > ca:
            return None, "malformed validity window"
        return rec, ""

    def claim(self, org_id: str, price_id: str, tx_ref: str, *, now: float) -> dict:
        """Record THIS org's pending plan checkout (``tx_ref``), or raise ``PendingCheckoutRefused``. Exclusive
        across threads and processes; see the module docstring for the refusal cases. Returns ``{"record": the
        signed record, "replaced": ""|why}`` — ``replaced`` names a stale UNVERIFIABLE record it reaped (for the
        audit)."""
        org_id, price_id, tx_ref, t = str(org_id), str(price_id), str(tx_ref), float(now)
        if self.owner_key is None or not self.trusted_pubkey:
            raise PendingCheckoutRefused(
                "plan checkout is unavailable right now (contact support)", code="refused_pending_unsigned",
                detail="the owner signing key is unavailable, so the pending plan-checkout record cannot be signed")
        marker = self._marker(org_id)
        try:
            fd = self._locked_fd()
        except OSError as exc:
            raise PendingCheckoutRefused(
                "plan checkout is unavailable right now (contact support)", code="refused_pending_io",
                detail=f"pending plan-checkout lock unavailable ({type(exc).__name__})") from None
        try:
            rec, problem = self._read(marker, org_id)
            replaced = ""
            if problem:
                try:
                    stale = t - os.stat(marker, follow_symlinks=False).st_mtime > self.ttl_s
                except OSError:
                    stale = False
                if stale:
                    os.unlink(marker)                  # an untrusted record older than any live window: reap it
                    replaced = f"reaped stale pending record {marker.name[:16]}... ({problem})"
                    problem = ""
            if problem:
                raise PendingCheckoutRefused(   # (the detail fits the 160-char audit reason; org_id is its own field)
                    "plan checkout is unavailable for this workspace (contact support)",
                    code="refused_pending_invalid",
                    detail=f"pending record {marker.name[:16]}... is {problem} (never trusted); inspect and remove it "
                           f"to unblock")
            if rec is not None:
                ea, ca = float(rec["expires_at"]), float(rec["created_at"])
                if t < ea:
                    skew = " (created in the future: the clock moved backwards)" if ca > t else ""
                    raise PendingCheckoutRefused(
                        f"a plan checkout for this workspace is already in progress — complete it, or wait up to "
                        f"{max(1, int((ea - t + 59) // 60))} min for it to expire, before starting another (a "
                        f"second subscription is refused rather than billed)",
                        code="refused_pending_plan",
                        detail=f"pending plan checkout until {ea:.0f}{skew}: {rec.get('tx_ref')}")
                os.unlink(marker)                      # a VERIFIED, EXPIRED record: the abandoned checkout lapses
            core = {"signal": SIGNAL, "org_id": org_id, "price_id": price_id, "tx_ref": tx_ref,
                    "created_at": t, "expires_at": t + self.ttl_s}
            payload = signed_payload(core, self.owner_key)
            tmp = self.dir / f".{marker.name}.{secrets.token_hex(8)}.tmp"
            wfd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                try:
                    os.write(wfd, json.dumps(payload, sort_keys=True).encode("utf-8"))
                    os.fsync(wfd)
                finally:
                    os.close(wfd)
                os.link(tmp, marker)                   # atomic EXCLUSIVE create of a fully-written record
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            return {"record": payload, "replaced": replaced}
        except OSError as exc:
            raise PendingCheckoutRefused(
                "plan checkout is unavailable right now (contact support)", code="refused_pending_io",
                detail=f"pending plan-checkout record could not be written ({type(exc).__name__})") from None
        finally:
            os.close(fd)

    def pending(self, org_id: str, *, now: float) -> bool:
        """Read-only: True iff a plan checkout for the org is in progress — a verified record still inside its window,
        OR a record that cannot be trusted (fail-closed: ``claim`` would refuse it too). For the offers read, so the
        UI does not offer a plan that checkout would refuse. Takes no lock (a stale answer is only a UI hint)."""
        rec, problem = self._read(self._marker(str(org_id)), str(org_id))
        return bool(problem) or (rec is not None and float(now) < float(rec["expires_at"]))

    def release(self, org_id: str, tx_ref: str) -> bool:
        """Drop the org's pending record iff it is still THIS checkout's (verified, same ``tx_ref``). Best-effort:
        False on any fault — the record then simply expires (the safe direction)."""
        marker = self._marker(str(org_id))
        try:
            fd = self._locked_fd()
        except OSError:
            return False
        try:
            rec, problem = self._read(marker, str(org_id))
            if problem or rec is None or rec.get("tx_ref") != str(tx_ref):
                return False
            os.unlink(marker)
            return True
        except OSError:
            return False
        finally:
            os.close(fd)
