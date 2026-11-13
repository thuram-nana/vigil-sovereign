"""Audit E1b — the owner-signed PENDING plan-checkout record behind the second-plan guard.

The CHK-1b double-billing guard (``Provisioner._org_has_live_plan``) reads only DRAINED subscriptions, and a plan
charge reaches the subscription registry only once its webhook drains — a drain tick after it is spooled, ~15 min
of NET-2b transient-verify parking, or, once the drain QUARANTINES it (a transient verify failure with NET-2b off,
or its retry budget spent), only when an operator re-drives it: that lag has NO upper bound. Until then a second
(third, ...) plan checkout for the same org was created and could be paid: two processor subscriptions, the
customer billed twice.

``PendingPlanCheckouts.claim`` records, per ORG, the plan checkout being opened, BEFORE the outbound processor
call. A second plan checkout for the same org is refused while that record is live; once the first plan drains, the
drained subscription refuses it instead (``_org_has_live_plan``). In between, a record whose window has ended
LAPSES ONLY when the billing spool shows no undrained webhook for its tx_ref (``undrained``). Pinned properties:

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
    default ``DEFAULT_TTL_S`` covers that session PLUS ``DRAIN_LAG_S`` of margin for the processor to deliver the
    webhook of a payment completed in the session's last second. So an ABANDONED checkout does not lock the org out
    of buying a plan for ever. (The session bound is the processor's to honour; see ``billing.create_checkout``.)
  * A PAID-BUT-UNDRAINED plan never lapses on time alone — the window says nothing about whether the link was
    paid. Before an expired record is replaced (and before the provisioner lets an expired spine-audited plan
    checkout go), ``undrained`` reads the billing spools READ-ONLY (Flutterwave's and Stripe's: the provisioner's
    checkout serves either processor) — every stage where a spooled webhook waits
    undrained: ``incoming/``, ``working/``, ``retry/`` (NET-2b parking) and ``rejected/`` (quarantine) — and the
    second plan is refused while a webhook for that earlier tx_ref sits there (``processed/`` is drained: a minted
    plan is ``_org_has_live_plan``'s, a definitive no-op was not paid). Fail-closed: no spool wired or found, a stage
    that cannot be listed, or an envelope that cannot be read or attributed to a tx_ref refuses too. The offers read
    (``pending``) reports such a record as pending, so the UI never re-offers a plan that checkout would refuse.
  * EXCLUSIVE across processes — the read-decide-write runs under an exclusive ``flock`` on ``<dir>/.claim.lock``,
    and a new record is published with ``os.link`` (an atomic exclusive create of a fully-written file), so two
    racing POSTs — in one cockpit process or several — can never both claim.
  * CLOCK SKEW — the decision is "live iff now < expires_at" on the owner-signed window; a record whose
    ``created_at`` lies in the future (the clock moved backwards) stays live (refuses) and says so in the reason.
  * TOP-UPS are never claimed: only the plan branch of ``billing_checkout`` calls this.
  * DELETION fails closed: the file lives under SIGIL_HOME, so a local writer could delete it — but the provisioner
    also writes each CREATED plan checkout (its tx_ref and this record's ``expires_at``) to the tamper-evident spine
    audit and refuses a new plan checkout while such a row is still within its window, or while an expired one's
    webhook waits undrained (see ``Provisioner._spine_plan_checkouts``), so deleting the file does not reopen the
    second-plan window.

``release`` drops a record only if it is still THIS checkout's (same tx_ref) — used when the processor refused the
checkout, so a customer who never received a link can retry at once. Fail-closed throughout: no owner key, no
``flock``, or an I/O fault refuses the claim (an over-refusal, never a second subscription).

FATAL-2: sovereign-side (``assert_no_offense`` at import); stdlib + the sovereign ``governor.authn`` signer only.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Iterable, Optional, Sequence

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
# A MARGIN, not a bound: time for the webhook of a payment completed at the session's last second to reach the
# billing spool (and, normally, to drain: the 60 s drain timer + NET-2b parking, ~915 s). It does NOT bound the
# drain lag — a quarantined webhook waits for an operator — which is why an expired record still refuses while
# ``undrained`` finds its webhook in the spool. Only a webhook that has not reached the spool yet is covered by
# this margin alone.
DRAIN_LAG_S = 30 * 60.0
DEFAULT_TTL_S = PLAN_LINK_SESSION_MIN * 60.0 + DRAIN_LAG_S
_LOCK_NAME = ".claim.lock"
_MAX_BYTES = 8192
# Where a spooled billing webhook waits UNDRAINED (``inbound.billing_spool``'s layout): written to ``incoming/``,
# claimed into ``working/``, parked in ``retry/`` (NET-2b), quarantined in ``rejected/``. ``processed/`` is drained.
_SPOOL_STAGES = ("incoming", "working", "retry", "rejected")
_MAX_ENVELOPE = 256 * 1024                 # the proxy's / the drain's envelope cap
_SPOOL_PASSES = 3                          # a webhook the drain moves mid-scan is caught by a re-read (see below)
UNCONFIRMED_MESSAGE = ("a payment for an earlier plan checkout of this workspace has not been confirmed yet — a "
                       "second plan is refused until it is (contact support if this persists)")


def billing_spool_dirs() -> "list[Path]":
    """Every place this deployment's billing-webhook spools can be, resolved NOW. Flutterwave: the proxy's
    ``VIGIL_BILLING_WEBHOOK_SPOOL`` (the writer), the drain's ``VIGIL_BILLING_SPOOL`` and the runbook default
    ``$SIGIL_HOME/billing-spool``. Stripe (the same checkout seam serves it): the proxy's
    ``VIGIL_STRIPE_WEBHOOK_SPOOL``, the drain unit's ``VIGIL_STRIPE_BILLING_SPOOL`` and its default
    ``$SIGIL_HOME/stripe-billing-spool``. ``undrained`` scans each one that exists (more places can only refuse
    more)."""
    from ..config import _resolve_home
    out: "list[Path]" = []
    home = _resolve_home()
    for envs, default in ((("VIGIL_BILLING_WEBHOOK_SPOOL", "VIGIL_BILLING_SPOOL"), "billing-spool"),
                          (("VIGIL_STRIPE_WEBHOOK_SPOOL", "VIGIL_STRIPE_BILLING_SPOOL"), "stripe-billing-spool")):
        for env in envs:
            raw = os.environ.get(env, "")
            if raw.strip():
                out.append(Path(raw.strip()))
        out.append(home / default)
    return out


_STRIPE_ENVELOPE_SCHEMA = "vigil.webhook.stripe.v1"   # ``inbound.billing_spool.StripeEnvelopeV1``


def _str_at(obj: object, *keys: str) -> Optional[str]:
    """The non-empty string at ``obj[k0][k1]...``, or None."""
    for k in keys:
        obj = obj.get(k) if isinstance(obj, dict) else None
    return obj if isinstance(obj, str) and obj else None


def _stripe_body_tx_ref(body: object) -> Optional[str]:
    """The checkout reference a Stripe event body carries: a Checkout Session's ``client_reference_id`` /
    ``metadata.tx_ref``, or an invoice's subscription metadata ``tx_ref`` (``parent.subscription_details`` on newer
    API versions, ``subscription_details`` on older ones). None when none is present OR two of them disagree (an
    envelope this cannot attribute to ONE tx_ref refuses, like any other)."""
    data = body.get("data") if isinstance(body, dict) else None
    obj = data.get("object") if isinstance(data, dict) else None
    refs = {r for r in (_str_at(obj, "client_reference_id"), _str_at(obj, "metadata", "tx_ref"),
                        _str_at(obj, "parent", "subscription_details", "metadata", "tx_ref"),
                        _str_at(obj, "subscription_details", "metadata", "tx_ref")) if r is not None}
    return refs.pop() if len(refs) == 1 else None


def _envelope_tx_ref(path: Path) -> Optional[str]:
    """The tx_ref of one spooled billing envelope — a Flutterwave body's ``data.tx_ref``, or for the Stripe envelope
    schema the reference ``_stripe_body_tx_ref`` reads — or None when it cannot be attributed (unreadable, over the
    envelope cap, not the envelope / body JSON, no tx_ref). Never follows a symlink (O_NOFOLLOW), never blocks on a
    FIFO (O_NONBLOCK: it reads as empty) and never reads more than the cap + 1 bytes. RAISES ``FileNotFoundError``
    when the file vanished since it was listed (the drain moved it)."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        raise
    except OSError:
        return None
    try:
        chunks: "list[bytes]" = []
        while sum(map(len, chunks)) <= _MAX_ENVELOPE:
            b = os.read(fd, _MAX_ENVELOPE + 1)
            if not b:
                break
            chunks.append(b)
    except OSError:
        return None                                # e.g. a directory named *.json
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > _MAX_ENVELOPE:
        return None                                # the drain refuses it unread too: it can never be minted as is
    try:
        env = json.loads(raw.decode("utf-8"))
        body = json.loads(base64.b64decode(env["body_b64"], validate=True))
        ref = _stripe_body_tx_ref(body) if env.get("schema") == _STRIPE_ENVELOPE_SCHEMA else body["data"]["tx_ref"]
    except (UnicodeDecodeError, ValueError, binascii.Error, KeyError, TypeError):
        return None
    return ref if isinstance(ref, str) and ref else None


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
                 ttl_s: float = DEFAULT_TTL_S,
                 billing_spools: "Optional[Sequence[str | os.PathLike]]" = None) -> None:
        self.dir = Path(path)
        self.owner_key = owner_key
        self.trusted_pubkey = trusted_pubkey
        self.ttl_s = float(ttl_s)
        # the billing-webhook spool(s) ``undrained`` reads (production: ``billing_spool_dirs()``). None ⇒ an expired
        # record can never be confirmed unpaid, so it never lapses (fail-closed).
        self.billing_spools = None if billing_spools is None else [Path(d) for d in billing_spools]

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

    def _spool_pass(self, wanted: "set[str]") -> "tuple[str, Optional[frozenset]]":
        """ONE read of every undrained stage: (why, None) when a wanted tx_ref waits there or a stage / envelope
        cannot be read or attributed (fail-closed); ("", None) when a listed file vanished mid-pass; else ("",
        the listing)."""
        roots = [d for d in (self.billing_spools or ()) if d.is_dir()]
        if not roots:
            return (f"no billing spool found (looked in {', '.join(str(d) for d in self.billing_spools or ())})"
                    if self.billing_spools else "no billing spool is wired"), None
        seen: "set[tuple[str, str]]" = set()
        stable = True
        for root in roots:
            for stage in _SPOOL_STAGES:
                try:
                    names = sorted(e.name for e in os.scandir(root / stage) if e.name.endswith(".json"))
                except FileNotFoundError:
                    continue                       # never created: nothing has waited there
                except OSError as exc:
                    return f"billing spool {stage}/ is unreadable ({type(exc).__name__})", None
                for name in names:
                    try:
                        ref = _envelope_tx_ref(root / stage / name)
                    except FileNotFoundError:
                        stable = False             # moved by the drain mid-pass: the next pass sees it settled
                        continue
                    if ref is None:
                        return f"billing spool {stage}/{name[:24]} cannot be attributed to a tx_ref", None
                    if ref in wanted:
                        return f"its webhook waits undrained in billing spool {stage}/: {ref}", None
                    seen.add((f"{root}/{stage}", name))
        return "", (frozenset(seen) if stable else None)

    def undrained(self, tx_refs: "Iterable[str]") -> str:
        """Why one of these EARLIER plan checkouts (``tx_refs``) may have been PAID but not yet DRAINED — "" only
        when the billing spool proves no webhook for any of them is waiting in ``incoming/``, ``working/``,
        ``retry/`` or ``rejected/``. Read-only. FAIL-CLOSED: no spool wired or found, a stage that cannot be listed,
        or an envelope that cannot be read or attributed to a tx_ref returns a reason (it could be one of them).
        The drain moves envelopes between stages while this reads (``retry/`` -> ``incoming/`` -> ``working/`` ->
        ``retry/``|``rejected/``), so one pass could miss a moving file: "" is returned only once two consecutive
        passes saw the same files, and a spool that keeps changing refuses."""
        wanted = {str(r) for r in tx_refs if r}
        if not wanted:
            return ""
        prev: "Optional[frozenset]" = None
        for _ in range(_SPOOL_PASSES):
            why, listing = self._spool_pass(wanted)
            if why:
                return why
            if listing is not None and listing == prev:
                return ""
            prev = listing
        return "the billing spool kept changing while it was read"

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
                # A VERIFIED, EXPIRED record lapses only when its link was not paid-but-undrained: the window alone
                # cannot tell an abandoned checkout from a paid one whose webhook the drain has not minted yet.
                why = self.undrained((str(rec.get("tx_ref") or ""),))
                if why:
                    raise PendingCheckoutRefused(UNCONFIRMED_MESSAGE, code="refused_pending_unconfirmed",
                                                 detail=f"expired pending record kept: {why}")
                os.unlink(marker)                      # the abandoned checkout lapses
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
        """Read-only: True iff a plan checkout for the org is in progress — a verified record still inside its window
        or expired with its webhook still undrained (``undrained``), OR a record that cannot be trusted (fail-closed:
        ``claim`` would refuse each of these too). For the offers read, so the UI does not offer a plan that checkout
        would refuse. Takes no lock (a stale answer is only a UI hint)."""
        rec, problem = self._read(self._marker(str(org_id)), str(org_id))
        if problem:
            return True
        if rec is None:
            return False
        return float(now) < float(rec["expires_at"]) or bool(self.undrained((str(rec.get("tx_ref") or ""),)))

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
