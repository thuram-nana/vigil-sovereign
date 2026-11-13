"""billing_spool — the SOVEREIGN-side drain of the inbound BILLING-WEBHOOK inert seam (SaaS Slice C).

The stdlib ``vigil up`` proxy (``vigil_integration.uiproxy``) receives ``POST /webhooks/billing``, authenticates
the Flutterwave ``verif-hash`` header (constant-time, an anti-flood pre-filter), and writes ONE inert
``vigil.webhook.billing.v1`` envelope — ``{schema, body_b64}`` — to ``<spool>/incoming/``. It NEVER mints,
forwards, or spawns, and it stores only the RAW webhook body: NEVER the ``verif-hash`` value, which equals the
secret. This module drains that spool: for each envelope it base64-decodes the body and runs it through
``BillingSigner.ingest``, which does the ``verif-hash`` compare + the MANDATORY server-side transaction
re-verify + the owner-signed mint. The RE-VERIFY is the authoritative gate — a forged / replayed / unverifiable
body mints nothing — so this seam is fail-closed by construction even though the body arrived unauthenticated at
rest.

The ``sig_header`` passed to ``ingest`` is the webhook secret (resolved OFF-SPINE from the env, the SAME value the
proxy validated the inbound header against). The proxy already authenticated the inbound ``verif-hash``; supplying
the secret here simply lets ``ingest`` run its single verify->mint path, whose real authority is the re-verify.
The secret stays in the env on the sovereign host and is NEVER written to the spool. That is the default
``FlutterwaveEnvelopeV1`` reader; a provider whose signature binds each delivery and its time instead passes its own
``EnvelopeReader`` (one schema per drain; an envelope of any other schema is quarantined, never read).

BOUNDARY INVARIANTS (mirror ``inbound/spool_watcher.py`` — treat every byte as hostile):
  * SOVEREIGN-only: imports NO ``framework`` / ``strix`` (``assert_no_offense`` at import); the mint is the
    injected ``BillingSigner``'s, under the owner key it holds.
  * FAIL-CLOSED: any validation / decode / ingest failure moves the file to ``rejected/`` with a ``.reason``
    sidecar and appends NOTHING. A well-formed body that ``ingest`` maps to a NO-OP (unverified, or an unknown
    catalog price) is NOT an error — it is archived without spining (nothing was minted).
  * IDEMPOTENT twice over: content-addressed spool dedup (``processed/<sha256>``) AND ``BillingSigner.ingest``'s
    own ``event_id`` idempotency — a duplicate Flutterwave delivery credits exactly once.
  * HOSTILE-FILE-HARDENED: ``O_NOFOLLOW`` + ``O_NONBLOCK`` + ``S_ISREG`` + size cap + UTF-8 decode, so a planted
    symlink / FIFO / device / oversized / non-UTF-8 blob is quarantined, never followed, and never hangs.

VERIFIER CONTRACT (so a genuinely-paid transaction is never silently buried). The proxy 202s a delivery as soon
as it spools, so the provider will NOT redeliver — this drain is the only thing that will ever try to mint it.
``ingest`` returns None for TWO very different situations: a DEFINITIVE no-op (the transaction re-verified but is
not a successful, catalog-mapped mint) and a FAILED verify. The injected transaction verifier MUST therefore
distinguish them: it RAISES on a transient / ambiguous failure (network error, timeout, 5xx, a rate limit) and
returns None / a non-"successful" object ONLY for a DEFINITIVE answer. Under that contract a transient failure
propagates as an exception and this drain QUARANTINES the envelope to ``rejected/`` (recoverable — it can be
moved back to ``incoming/`` and re-drained once the provider is reachable), whereas a definitive no-op archives
to ``processed/`` (correctly final).

NET-2b (#73, DEFAULT-OFF behind ``VIGIL_NET_RECOVERY_ENABLED``): a provider blip should not need an operator. With
the flag ON, a failure the egress marks RETRY-CURABLE (``FlutterwaveEgressError.transient`` — a transport fault or
an HTTP 408/425/429/5xx; nothing else, so a forged / malformed / plan-alarm / spine failure still quarantines on
sight) is DEFERRED to ``retry/`` with a small ``<name>.state`` ledger, and re-admitted to ``incoming/`` on the
SHARED NET-2 schedule (``live.net_recovery``: 5 s doubling to 5 min, at most 8 retries per envelope ≈ 15 min).
Once that bound is spent the envelope is QUARANTINED exactly as before (and the unit alarms), so a provider that
stays down still reaches an operator. Nothing is minted on a deferred pass, and a re-admitted envelope re-enters
the SAME claim / sha256-dedup / ``event_id``-idempotent path, so a retry can never double-credit. Fail-safe: an
unreadable ledger, a bad clock, or a failed move resolves toward quarantine (today's behaviour), never an unbounded
retry; and every pass re-admits ``retry/`` whatever the flag, so turning it OFF strands nothing. The bound is per
PAYMENT: the ledger is keyed by file name and belongs to the PARKED envelope, so a same-named twin delivered while
the original waits (the proxy dedups a redelivery only against ``incoming/``) is quarantined + alarmed WITHOUT
touching that ledger — a redelivery can never hand the parked payment a fresh budget. OFF and with no
``retry/`` directory the drain is byte-identical to before. A verifier that instead swallowed a transient error into None would let the
drain treat a real payment as a final no-op and bury it — which is why the contract is RAISE-on-transient. The
backstop for any residual gap is periodic RECONCILIATION (sweep recent tx_refs against the provider and mint any
missed) — the provider's CAP_RECONCILE capability, a later slice. This is a money-SAFE direction either way: the
failure mode is under-crediting a paid tenant (recoverable), never over-crediting an unpaid one.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor.billing import BillingSigner  # noqa: E402  (the EVIDENCE->owner-signed-FACT boundary this feeds)

_MAX_BYTES = 256 * 1024                     # mirror the proxy's envelope cap; a larger file is rejected unread
_ENVELOPE_SCHEMA = "vigil.webhook.billing.v1"
_STRIPE_ENVELOPE_SCHEMA = "vigil.webhook.stripe.v1"
_STRIPE_SIG_MAX = 2048                      # mirrors the proxy's Stripe-Signature cap
_RECEIVED_AT_FUTURE_SKEW_S = 300.0          # a receive time later than the drain's clock by more than this is refused
_MAX_DECODED_BODY = 192 * 1024              # decoded-body cap: the proxy caps the raw body at 128K, whose base64
#                                             envelope stays under the 256K read cap above; 192K is the ceiling a
#                                             256K envelope can decode to (defense-in-depth, fail-closed).


class BillingSpoolError(RuntimeError):
    """A fail-closed refusal while draining one billing-webhook envelope (nothing was spined)."""


def decode_envelope_body(obj: "dict[str, Any]") -> bytes:
    """The raw webhook body of one parsed envelope: ``body_b64`` must be strict base64 and decode to at most
    ``_MAX_DECODED_BODY`` bytes, or this raises BillingSpoolError (quarantine; nothing is spined)."""
    body_b64 = obj.get("body_b64")
    if not isinstance(body_b64, str):
        raise BillingSpoolError("envelope missing body_b64")
    try:
        raw = base64.b64decode(body_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BillingSpoolError(f"body_b64 is not valid base64: {exc}") from exc
    if len(raw) > _MAX_DECODED_BODY:
        raise BillingSpoolError("decoded webhook body exceeds the size cap")
    return raw


class EnvelopeReader:
    """Turns one parsed inert envelope of exactly ``schema`` into the ``(raw_body, sig_header, now)`` that
    ``BillingSigner.ingest`` verifies. A provider whose signature binds the delivery (and its time) supplies its own
    reader; the drain checks the schema BEFORE calling ``read``, so a reader only ever sees its own envelopes."""

    schema: str = ""

    def read(self, obj: "dict[str, Any]", *, drain_now: float) -> "tuple[bytes, str, float]":
        raise NotImplementedError


class FlutterwaveEnvelopeV1(EnvelopeReader):
    """The ``vigil.webhook.billing.v1`` envelope (``{schema, body_b64}``). Flutterwave's ``verif-hash`` header IS
    the static secret, so the proxy stores the body only and the drain supplies the off-spine secret as the
    signature header, at the drain's own clock (the authority is the server-side transaction re-verify)."""

    schema = _ENVELOPE_SCHEMA

    def __init__(self, secret: Optional[str]) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("verif_hash (the off-spine webhook secret) is required — fail-closed without it")
        self._secret = secret

    def read(self, obj: "dict[str, Any]", *, drain_now: float) -> "tuple[bytes, str, float]":
        return decode_envelope_body(obj), self._secret, drain_now


class StripeEnvelopeV1(EnvelopeReader):
    """The ``vigil.webhook.stripe.v1`` envelope the proxy's ``/webhooks/stripe`` writes: ``{schema, body_b64,
    stripe_signature, received_at}``. Stripe signs each delivery with its time, so the drain re-verifies that HMAC
    AT THE RECEIVE TIME (a run that drains later than the 300 s tolerance still verifies, and a body cannot be
    re-signed at rest without the secret). The receive time must be a positive finite number no later than the
    drain's clock plus a small skew; the header must be an ASCII string within the proxy's cap."""

    schema = _STRIPE_ENVELOPE_SCHEMA

    def read(self, obj: "dict[str, Any]", *, drain_now: float) -> "tuple[bytes, str, float]":
        raw = decode_envelope_body(obj)
        sig = obj.get("stripe_signature")
        if not isinstance(sig, str) or not sig or len(sig) > _STRIPE_SIG_MAX or not sig.isascii():
            raise BillingSpoolError("envelope missing or malformed stripe_signature")
        received = obj.get("received_at")
        if isinstance(received, bool) or not isinstance(received, (int, float)) or not math.isfinite(received) \
                or received <= 0 or received > float(drain_now) + _RECEIVED_AT_FUTURE_SKEW_S:
            raise BillingSpoolError("envelope missing or implausible received_at")
        return raw, sig, float(received)


class BillingSpoolWatcher:
    """Drains an inbound billing-webhook spool through ``BillingSigner.ingest`` onto the owner-signed spine,
    fail-closed. Construction mirrors ``inbound.spool_watcher.SpoolWatcher`` (same on-disk claim/dedup/quarantine
    contract and the same hostile-file hardening)."""

    def __init__(self, signer: BillingSigner, *, spool_dir: str | os.PathLike, verif_hash: Optional[str] = None,
                 now_fn: Callable[[], float] = time.time, envelope_reader: Optional[EnvelopeReader] = None) -> None:
        if not isinstance(signer, BillingSigner):
            raise ValueError("a BillingSigner is required — the drain never mints on its own")
        # Exactly one source of the (body, signature, time) triple: the Flutterwave secret (the default V1 reader,
        # byte-identical to before) OR an explicit reader. Both, or neither, is a misconfiguration -> refuse.
        if envelope_reader is None:
            envelope_reader = FlutterwaveEnvelopeV1(verif_hash)      # validated inside (None / "" refused)
        elif verif_hash is not None:
            raise ValueError("pass verif_hash OR envelope_reader, not both — fail-closed on an ambiguous drain")
        if not isinstance(envelope_reader, EnvelopeReader) or not isinstance(envelope_reader.schema, str) \
                or not envelope_reader.schema:
            raise ValueError("envelope_reader must be an EnvelopeReader with a non-empty schema")
        self.signer = signer
        self._reader = envelope_reader
        self._now = now_fn
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"       # a file is CLAIMED here (out of incoming) before ingest
        self.processed = self.spool / "processed"   # doubles as the dedup ledger: <sha256> present ⇒ handled
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        # NET-2b: envelopes awaiting a bounded transient-verify retry. Created ONLY by a deferral (flag ON), so an
        # OFF drain leaves the spool tree byte-identical.
        self.retry = self.spool / "retry"

    # -- ingest one envelope (fail-closed) ---------------------------------------------------------
    def _ingest_text(self, text: str) -> Optional[int]:
        """Parse one inert billing envelope, decode the raw body, and run it through the signer. Returns the
        appended spine seq, or None when the signer mints nothing (unverified / unknown price / no-op — NOT an
        error). Raises BillingSpoolError on a malformed envelope (a refusal; nothing is spined)."""
        try:
            obj = json.loads(text)
        except ValueError as exc:
            raise BillingSpoolError(f"not valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise BillingSpoolError("envelope is not a JSON object")
        if obj.get("schema") != self._reader.schema:
            raise BillingSpoolError(f"unexpected envelope schema {obj.get('schema')!r}")
        raw, sig_header, now = self._reader.read(obj, drain_now=float(self._now()))
        # The authoritative verify->mint path. ingest does the signature check (for Flutterwave: the verif-hash
        # vs the injected secret) + the MANDATORY server-side re-verify + the owner-signed mint, and is itself
        # idempotent by event_id. None ⇒ the webhook did not re-verify / carried no catalog entitlement ⇒ nothing
        # minted (safe no-op).
        return self.signer.ingest(raw, sig_header, now=float(now))

    def _quarantine(self, path: Path, reason: str) -> None:
        dest = self.rejected / path.name
        try:
            os.replace(path, dest)
        except OSError:
            dest = self.rejected / (path.name + ".orphan")
        try:
            (self.rejected / (dest.name + ".reason")).write_text(reason[:2000], encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _read_regular(path: Path) -> str:
        """Read a REGULAR file without following a symlink or blocking on a FIFO, decoded UTF-8. Mirrors
        ``SpoolWatcher._read_regular``: O_NOFOLLOW rejects a symlink at open, O_NONBLOCK returns instead of
        blocking on a writer-less FIFO, S_ISREG + the size cap reject anything but a bounded regular file, and a
        non-UTF-8 decode is normalised to OSError — so the caller's single ``except OSError`` quarantines every
        hostile-file case and ``drain()`` never hangs or crashes on one bad file."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file (symlink/FIFO/device refused)")
            if st.st_size > _MAX_BYTES:
                raise OSError(f"file exceeds {_MAX_BYTES} bytes")
            chunks, remaining = [], _MAX_BYTES + 1
            while remaining > 0:
                b = os.read(fd, remaining)
                if not b:
                    break
                chunks.append(b)
                remaining -= len(b)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if len(data) > _MAX_BYTES:
            raise OSError(f"file exceeds {_MAX_BYTES} bytes")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OSError(f"not valid UTF-8: {exc}") from exc

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _reclaim_working(self) -> None:
        """Crash recovery (money nothing-lost) — the parity this drain was missing vs its finding/settle siblings.
        ``drain`` CLAIMS a file into ``working/`` (atomic rename out of ``incoming/``) BEFORE it ingests; if the
        daemon dies between that claim and the archive, the file is STRANDED in ``working/`` — out of ``incoming/``
        so no future drain sees it, and not in ``processed/`` so it was never minted. A genuinely-paid webhook is
        then SILENTLY LOST (the proxy already 202'd it, so the provider never redelivers). Move every such file
        back to ``incoming/`` at the START of each drain so the next pass re-processes it. Re-ingest is idempotent
        TWICE over — the ``processed/<sha256>`` dedup marker AND ``BillingSigner.ingest``'s own ``event_id`` — so a
        file reclaimed AFTER it already minted credits exactly once. NEVER unlink on a failed move: a webhook that
        cannot be reclaimed stays in ``working/`` for the next sweep rather than being destroyed (under-crediting a
        paid tenant is recoverable; destroying a paid webhook is not)."""
        try:
            stale = list(self.working.glob("*.json"))
        except OSError:
            return
        for f in stale:
            if f.name.startswith(".tmp-"):
                continue
            try:
                os.replace(f, self.incoming / f.name)
            except OSError:
                pass   # leave it in working/ for a later sweep — never destroy a paid webhook

    # -- NET-2b: bounded auto-retry of a transient provider failure (default-OFF) ---------------------
    @staticmethod
    def _recovery_on() -> bool:
        """``VIGIL_NET_RECOVERY_ENABLED`` via the shared NET-2 reader. Any import / read fault reads OFF (today's
        quarantine-on-sight behaviour) — the fail-safe direction."""
        try:
            from vigil_integration.live.net_recovery import recovery_enabled
            return recovery_enabled() is True
        except Exception:  # noqa: BLE001 — a missing / broken reader must never turn retries ON
            return False

    @staticmethod
    def _is_transient(exc: BaseException) -> bool:
        """True ONLY for a failure the outbound egress explicitly marked retry-curable. Anything else — a raw
        ``OSError`` from a spine write, ``UnaccountedPayment`` (the plan alarm), a guard refusal — is NOT."""
        from ..governor.flutterwave_egress import FlutterwaveEgressError
        from ..governor.stripe_egress import StripeEgressError
        return isinstance(exc, (FlutterwaveEgressError, StripeEgressError)) and exc.transient is True

    def _state_path(self, name: str) -> Path:
        return self.retry / (name + ".state")

    def _read_attempts(self, name: str) -> Optional[int]:
        """Retries already spent on ``name`` (0 when it has no ledger). None when a ledger EXISTS but cannot be
        trusted (unreadable / malformed / out of range) — the caller treats that as the budget being spent."""
        sp = self._state_path(name)
        if not sp.exists() and not sp.is_symlink():
            return 0
        try:
            obj = json.loads(self._read_regular(sp))
            n = obj["attempts"]
        except Exception:  # noqa: BLE001 — ANY fault (a deeply nested ledger raises RecursionError) => untrusted
            return None
        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
            return None
        return n

    def _is_parked(self, name: str) -> bool:
        """Whether an envelope called ``name`` is waiting in ``retry/`` right now."""
        parked = self.retry / name
        return parked.exists() or parked.is_symlink()

    def _clear_state(self, name: str) -> None:
        """Drop ``name``'s retry ledger once the envelope it BELONGS to is final (archived, deduped or
        quarantined). The ledger is keyed by file name, and while an envelope of that name is parked in
        ``retry/`` it is THAT envelope's budget: finalising a same-named TWIN (the proxy dedups a redelivery only
        against ``incoming/``, so one can arrive while the original is parked) must leave it alone — otherwise
        every twin would hand the parked payment a fresh budget and the bound would be per DELIVERY, not per
        payment. The parked envelope's own final pass (it has left ``retry/`` by then) still clears it."""
        if self._is_parked(name):
            return
        self._safe_unlink(self._state_path(name))

    def _readmit_retries(self, *, recovery_on: bool) -> None:
        """Move every DUE envelope in ``retry/`` back to ``incoming/`` (flag OFF: every one, so turning the flag
        off strands nothing). A ledger that is unreadable, a clock that RAISES, or a time that cannot be compared
        re-admits NOW — the bound is enforced at the next failure, where an untrusted ledger counts as spent (and
        an envelope the clock cannot stamp is quarantined by its ingest). A remaining wait LONGER than the
        schedule's cap (a wall clock stepped backwards, or a tampered ``next_at``) is impossible by construction
        and also re-admits NOW, so no paid webhook can sit parked — healthy, un-alarmed — for longer than one
        capped delay. A collision with a same-named file already in ``incoming/`` waits a pass (never overwrites
        a pending webhook)."""
        if not self.retry.is_dir():
            return
        try:
            parked = sorted(self.retry.glob("*.json"))
        except OSError:
            return
        now: Any = None
        try:
            now = self._now()
        except Exception:  # noqa: BLE001 — a clock that RAISES proves nothing "not yet due" => re-admit NOW
            pass
        # A bool / NaN / non-number ``now`` (the None of a raising clock included) fails the window test below, or
        # makes ``float(now)`` raise into that test's own except (an int too large for a float raises OverflowError)
        # — either way the envelope is re-admitted NOW.
        cap = None
        if recovery_on:
            try:
                from vigil_integration.live.net_recovery import BoundedBackoff
                cap = BoundedBackoff().cap
            except Exception:  # noqa: BLE001 — without the schedule nothing can be proven "not yet due"
                cap = None
        for f in parked:
            if f.name.startswith(".tmp-"):
                continue
            if recovery_on and cap is not None:
                try:
                    due_at = json.loads(self._read_regular(self._state_path(f.name)))["next_at"]
                    if (isinstance(due_at, (int, float)) and not isinstance(due_at, bool)
                            and 0.0 < float(due_at) - float(now) <= cap):
                        continue                         # not yet due (and a plausible wait) — leave it parked
                except Exception:  # noqa: BLE001 — ANY fault (OverflowError, RecursionError included) proves nothing
                    pass                                 # untrusted ledger -> re-admit now (bound enforced later)
            dest = self.incoming / f.name
            if dest.exists() or dest.is_symlink():
                continue
            try:
                os.replace(f, dest)
            except OSError:
                pass                                     # stays parked for a later pass — never destroyed

    def parked_count(self) -> int:
        """How many webhooks currently wait in ``retry/`` for a bounded NET-2b retry (0 when there is none)."""
        try:
            return sum(1 for f in self.retry.glob("*.json") if not f.name.startswith(".tmp-"))
        except OSError:
            return 0

    def _defer(self, claimed: Path, exc: BaseException) -> str:
        """Park a transiently-failed envelope for a bounded retry. Returns ``"deferred"`` when parked, else a
        quarantine REASON (the bound is spent, or the deferral itself could not be made safely)."""
        from vigil_integration.live.net_recovery import BoundedBackoff
        name = claimed.name
        # Never clobber a DIFFERENT parked webhook of the same name (quarantine = recoverable). Checked BEFORE the
        # ledger is read: while an envelope is parked the ledger is ITS budget, not this twin's to be judged by.
        if self._is_parked(name):
            return (f"rejected (transient {type(exc).__name__}; a same-named envelope is already awaiting a "
                    f"NET-2b retry — not overwritten): {exc}")
        attempts = self._read_attempts(name)
        policy = BoundedBackoff()
        if attempts is None:
            return (f"rejected (transient {type(exc).__name__} and an untrusted NET-2b retry ledger — not "
                    f"retried): {exc}")
        policy.attempts = attempts
        if policy.exhausted:
            return (f"rejected (transient {type(exc).__name__} persisted through {attempts} bounded NET-2b "
                    f"retries): {exc}")
        # ``_defer`` runs INSIDE drain()'s catch-all handler, so nothing here may raise: a clock that RAISES, or
        # returns an int too large for a float (``float`` raises OverflowError), quarantines like any other
        # unreadable clock — it never escapes drain() and leaves the envelope to be re-verified on every pass.
        try:
            now = self._now()
            t = float("nan") if isinstance(now, bool) or not isinstance(now, (int, float)) else float(now)
        except Exception:  # noqa: BLE001
            t = float("nan")
        if t != t or t in (float("inf"), float("-inf")):
            return f"rejected (transient {type(exc).__name__}; clock unreadable — not retried): {exc}"
        parked = self.retry / name
        state = {"attempts": attempts + 1, "next_at": t + policy.next_delay(),
                 "last_error": f"{type(exc).__name__}: {exc}"[:500]}
        try:
            self.retry.mkdir(parents=True, exist_ok=True)
            os.chmod(self.retry, 0o700)
            tmp = self.retry / (".tmp-" + name + ".state")
            tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self._state_path(name))      # ledger FIRST: a crash before the park below leaves the
            os.replace(claimed, parked)                  # file in working/ (reclaimed next pass, budget counted)
        except OSError as oexc:
            return f"rejected (transient {type(exc).__name__}; NET-2b deferral failed: {oexc}): {exc}"
        return "deferred"

    def drain(self) -> dict:
        """Process every file currently in ``incoming/`` once. Returns {minted, noop, rejected, deduped, seqs}.

        Begins with a crash-recovery sweep (``_reclaim_working``) that returns any file stranded in ``working/``
        by a crashed prior drain back to ``incoming/`` — so a mid-drain crash loses no paid webhook.

        For each file: CLAIM it (atomic rename into ``working/``) BEFORE acting, so a failed archive or a re-run
        can never re-read it from ``incoming/`` and double-process. Read it as a bounded regular UTF-8 file, then
        dedup on the sha256 of the READ BYTES (not the producer filename). A byte-identical envelope already
        handled (``processed/<sha256>`` exists) is archived WITHOUT re-ingesting. Otherwise run the signer; a
        mint (seq) or a safe no-op (None) both archive to ``processed/`` (handled). ANY failure ⇒ ``rejected/``,
        nothing appended. Never raises on one bad file; never blocks on a hostile one."""
        self._reclaim_working()                          # crash recovery: re-admit any working/ file a prior
        #                                                  drain claimed-but-never-archived (money nothing-lost)
        recovery_on = self._recovery_on()
        self._readmit_retries(recovery_on=recovery_on)   # NET-2b: due parked envelopes rejoin incoming/
        minted, noop, rejected, deduped, seqs = 0, 0, 0, 0, []
        deferred = 0
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue                                 # a producer's in-flight temp; skip until renamed in
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)                 # atomic CLAIM: leaves incoming/ before we act
            except OSError:
                continue                                 # gone / raced away
            try:
                text = self._read_regular(claimed)
            except OSError as exc:
                self._quarantine(claimed, f"unreadable / not a bounded regular UTF-8 file: {exc}")
                rejected += 1
                continue
            marker = self.processed / (hashlib.sha256(text.encode("utf-8")).hexdigest() + ".json")
            if marker.exists():
                try:
                    os.replace(claimed, marker)          # archive the duplicate over its identical marker
                except OSError:
                    self._safe_unlink(claimed)
                self._clear_state(claimed.name)
                deduped += 1
                continue
            try:
                seq = self._ingest_text(text)
            except BillingSpoolError as exc:
                self._quarantine(claimed, f"rejected (fail-closed): {exc}")
                self._clear_state(claimed.name)
                rejected += 1
                continue
            except Exception as exc:  # noqa: BLE001 — any unexpected error is still a refusal, never an append
                reason = f"rejected (unexpected {type(exc).__name__}): {exc}"
                if recovery_on and self._is_transient(exc):
                    outcome = self._defer(claimed, exc)  # NET-2b: park for a bounded retry, nothing minted
                    if outcome == "deferred":
                        deferred += 1
                        continue
                    reason = outcome
                self._quarantine(claimed, reason)
                self._clear_state(claimed.name)
                rejected += 1
                continue
            # handled (minted or a safe no-op). Archive to the dedup marker. If the archive fails the record is
            # already spined (if it minted) AND the file is in working/ (NOT incoming/), so it is never
            # re-drained -> no double-ingest either way.
            try:
                os.replace(claimed, marker)
            except OSError:
                self._safe_unlink(claimed)
            self._clear_state(claimed.name)
            if seq is None:
                noop += 1
            else:
                minted += 1
                seqs.append(seq)
        out = {"minted": minted, "noop": noop, "rejected": rejected, "deduped": deduped, "seqs": seqs}
        if recovery_on:
            out["deferred"] = deferred                   # NET-2b only: the OFF result shape is unchanged
        return out

    def watch(self, *, interval: float = 2.0, stop: Optional["object"] = None) -> None:
        """Drain in a loop until ``stop`` (a threading.Event) is set. A single bad drain NEVER kills the money
        daemon: an unexpected error OUTSIDE the per-file loop (a transient spine / IO / directory fault) is
        reported to stderr and the loop continues — so the billing-ingress daemon survives a transient blip
        instead of dying silently and stranding every subsequent webhook in ``incoming/`` with no operator."""
        import sys as _sys
        while True:
            try:
                self.drain()
            except Exception as exc:  # noqa: BLE001 — the watch loop must survive any single-drain failure
                _sys.stderr.write("vigil billing-drain: WARNING drain error (continuing): "
                                  f"{type(exc).__name__}: {exc}\n")
            waiter = getattr(stop, "wait", None)
            if stop is not None and waiter is not None:
                if waiter(interval):
                    return
            else:
                time.sleep(interval)
