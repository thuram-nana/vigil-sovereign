"""completion_spool — the SOVEREIGN-side drain of the engagement-completion SETTLE seam (K4-5b).

The keyless offense worker emits a governance-signed ``EngagementCompletion{engagement_slug, nonce, outcome}``
to a cross-plane settle spool (``integration/.../jobs/completion_signal.py``). This drain — owner-side, which
alone may mint a refund — VERIFIES each signal against the owner-signed ``OFFENSE_GOVERNANCE_ROLE``
delegation (the trust root is DERIVED from the delegation, never handed in blindly — same as
``finding_receiver.from_delegation``), reads the published ``CreditLaunchLease`` for the slug, binds the
signal's nonce to the lease, derives the billable units FLAT-PER-RUN from the OWNER-SIGNED lease's
``units_reserved`` (the signal carries NO amount), and calls the idempotent ``LaunchGate.settle_launch`` —
so a completed run settles to consumption (reserve-before / settle-after) and settle stays owner-keyed.

Construction mirrors ``inbound.billing_spool.BillingSpoolWatcher`` / ``inbound.spool_watcher.SpoolWatcher``:
the same on-disk atomic-claim / sha256-dedup / hostile-file hardening, so a malformed or hostile envelope is
quarantined and never crashes or hangs ``drain()``, and a byte-identical replay is deduped (defence in depth
over ``settle_launch``'s own ``(slug, nonce)`` idempotency). FAIL-CLOSED: a bad delegation refuses the whole
drain at construction; a forged/unverifiable/out-of-scope/nonce-mismatched signal is quarantined, nothing
settled. SOVEREIGN plane: imports ``sigil`` + ``vigil_core`` + the import-clean credit-lease seam; no
``framework``/offense import (``assert_no_offense`` at import enforces it).

Red-pen fold (K4-5b): (A) the settle/tombstone WRITE now shares the drain's ``base_dir`` with the lease READ
(the gate is built ``LaunchGate(store, base_dir=...)``), so a completed run's tombstone lands in the SAME
tree the drain reads — a later differently-outcomed completion for the same ``(slug, nonce)`` can no longer
re-settle (the double-refund the split enabled); (B) the owner-signed delegation is RE-VERIFIED against the
current clock on EVERY ``drain()`` (not cached from construction, mirroring ``spool_watcher``), so a long-lived
watcher stops settling the moment the delegation lapses — an expired/retired governance key can no longer
mint refunds / confirm charges; (C) a non-tautological TENANT cross-check binds the owner-signed lease's own
``(org_id, scope_host)`` back to the delegated ``cust_`` slug (``_customer_slug``), so a lease filed under a
mismatched slug is refused; (D) ``_read_regular`` reads to EOF (a short read can no longer truncate a valid
envelope); (K) ``_reclaim_working`` recovers a file stranded by a mid-drain crash so a settlement is never
silently lost.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys as _sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate

from ..reuse import assert_no_offense

assert_no_offense()  # SOVEREIGN plane: this settle-drain must never pull the offense engine (FATAL-2)

_SEAM_SCHEMA = "vigil-engagement-completion-seam-v1"
_MAX_BYTES = 65_536                                   # a completion envelope is small; bound hostile files


class CompletionSpoolError(RuntimeError):
    """A malformed/unverifiable completion envelope (a refusal; nothing is settled)."""


class CompletionSpoolDeferred(CompletionSpoolError):
    """The completion cannot be settled YET (PRICING M1c): the run's model meter has a request in flight or cannot
    be written right now, or the metered pricing configuration is not set. Nothing is settled; the file goes back to
    ``incoming/`` and the next drain retries it (never quarantined, never a guessed charge). ``config`` marks a wait
    on the pricing configuration: no retry clears it until the owner fixes the deployment, so it is alarm-worthy."""

    def __init__(self, msg: str, *, config: bool = False) -> None:
        super().__init__(msg)
        self.config = config


class CompletionSpoolWatcher:
    """Drains an inbound engagement-completion settle spool through ``settle_launch``, fail-closed. The
    governance trust root is DERIVED from an owner-signed ``OFFENSE_GOVERNANCE_ROLE`` delegation — verified at
    construction (fail-fast on a wrong owner / wrong role / already-expired delegation) AND RE-DERIVED against
    the current clock on every ``drain()`` (so an expired delegation stops admitting mid-lifetime; no settle is
    ever driven under an un-owner-delegated or lapsed key)."""

    def __init__(self, store: SpineStore, *, spool_dir: "str | os.PathLike", owner_pubkey: str,
                 delegation: Any, scope: str, base_dir: Optional[str] = None,
                 now_fn: Callable[[], float] = time.time) -> None:
        if not owner_pubkey:
            raise ValueError("owner_pubkey is required — a settle spool cannot be drained without the owner root")
        from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, DelegationError, verify_delegation
        self._owner_pubkey = str(owner_pubkey)
        self._delegation = delegation
        self.scope = str(scope)
        self._now = now_fn
        # Construction-time fail-fast: a wrong-owner / wrong-role / already-expired delegation refuses the
        # whole watcher now (never cached for later use — drain() re-derives the root per call, finding B).
        try:
            verify_delegation(delegation, trusted_owner_pubkey=self._owner_pubkey, now=int(now_fn()),
                              role=OFFENSE_GOVERNANCE_ROLE, scope=self.scope)
        except DelegationError as exc:
            raise ValueError(
                f"offense-governance delegation invalid — refusing to drive any settle under it: {exc}") from exc
        self.store = store
        # (A) RESOLVE the seam base ONCE and share it between the lease READ and the gate's settle/tombstone
        # WRITE, so they can never diverge. Previously the gate was built with no base_dir, so its revoke wrote
        # to $VIGIL_BASE_DIR while the read used this base_dir — with the two differing, the lease was never
        # tombstoned in the read tree and a second differently-outcomed completion re-settled (double refund).
        self._base_dir = str(base_dir) if base_dir is not None else (
            os.environ.get("VIGIL_BASE_DIR") or ".vigil-live")
        self._gate = LaunchGate(store, base_dir=self._base_dir)
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"       # a file is CLAIMED here (out of incoming) before acting
        self.processed = self.spool / "processed"   # dedup ledger: <sha256> present ⇒ already handled
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        # E3bc: the spool lock the drain's two REVERSE moves (working/ -> incoming/) take exclusively and the
        # abandoned-lease sweep takes SHARED across its incoming/working/rejected globs — so the sweep's in-lock
        # completion re-check can never miss a completion moved between two of its globs. Created HERE, by the
        # drain's own uid, so a sweep run as another uid (root) never leaves a lock file the drain cannot open.
        try:
            fd = os.open(str(self.spool / ".spool.lock"),
                         os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
            os.close(fd)
        except OSError:                          # an unusable lock fails closed at use (files stay in working/)
            _sys.stderr.write("vigil settle-drain: WARNING the completion spool lock cannot be created\n")

    # -- the current governance root (re-derived per drain against the live clock, finding B) ------
    def _current_root(self) -> Optional[Any]:
        """Re-derive the governance trust root from the owner-signed delegation against the CURRENT clock. An
        expired / now-invalid delegation returns ``None`` (the drain then settles NOTHING this round and leaves
        ``incoming/`` untouched, so a renewed delegation settles them later — a transient hold, never a drop)."""
        from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, DelegationError, verify_delegation
        try:
            return verify_delegation(self._delegation, trusted_owner_pubkey=self._owner_pubkey,
                                     now=int(self._now()), role=OFFENSE_GOVERNANCE_ROLE, scope=self.scope)
        except DelegationError:
            return None

    def _spool_lock(self) -> Any:
        """The EXCLUSIVE spool lock (``<spool>/.spool.lock``) held by the drain's reverse moves only — never across a
        settle (so the drain and the sweep can never deadlock on it and the settle lock). A leaf lock: bounded wait,
        fail-closed (``seam_lock.locked_file``)."""
        from vigil_integration.live.seam_lock import locked_file
        return locked_file(self.spool / ".spool.lock", shared=False, wait_s=5.0)

    # -- one envelope → settle (fail-closed) -------------------------------------------------------
    def _settle_one(self, text: str, root: Any) -> Optional[dict]:
        """Verify one completion envelope (against the freshly-derived ``root``) and settle its lease. Returns
        the ``settle_launch`` result dict on a settle, or ``None`` on a safe no-op (no published lease for the
        slug — nothing to settle). Raises ``CompletionSpoolError`` on any refusal (malformed / unverifiable /
        out-of-scope / nonce-mismatch / tenant-mismatch); nothing is settled."""
        from vigil_core import EngagementCompletion, SignedEngagementCompletion, verify_engagement_completion
        from vigil_integration.live.credit_lease_broker import read_credit_lease
        try:
            obj = json.loads(text)
        except ValueError as exc:
            raise CompletionSpoolError(f"not valid JSON: {exc}") from exc
        if not isinstance(obj, dict) or obj.get("schema") != _SEAM_SCHEMA:
            raise CompletionSpoolError(f"unexpected envelope schema {obj.get('schema') if isinstance(obj, dict) else '?'!r}")
        try:
            signed = SignedEngagementCompletion(
                document=EngagementCompletion.model_validate(obj.get("document")),
                signatures=obj.get("signatures") or [])
        except Exception as exc:  # noqa: BLE001 — a malformed document/signatures block is a refusal
            raise CompletionSpoolError(f"malformed completion document/signatures: {exc}") from exc
        ok, reason = verify_engagement_completion(signed, root)
        if not ok:
            raise CompletionSpoolError(f"completion signal does not verify under the delegated governance root: {reason}")
        doc = signed.document
        # SCOPE-BIND (exact-match unless a wildcard delegation), mirroring FindingReceiver.ingest.
        if self.scope != "*" and doc.engagement_slug != self.scope:
            raise CompletionSpoolError(
                f"completion engagement_slug {doc.engagement_slug!r} is outside the delegated scope {self.scope!r}")
        bundle = read_credit_lease(self._base_dir, doc.engagement_slug)
        if bundle is None:
            return None                              # no published lease (already settled/absent) → safe no-op
        lease_doc = bundle.signed_lease.document
        # NONCE BIND: the completion must name THIS lease's launch, so a completion for an old lease can never
        # settle a newer re-lease of the same slug.
        if str(lease_doc.nonce) != str(doc.nonce):
            raise CompletionSpoolError(
                f"completion nonce {doc.nonce!r} != published lease nonce {lease_doc.nonce!r} (stale/mismatched)")
        # (C) NON-TAUTOLOGICAL TENANT CROSS-CHECK: the owner-signed lease's OWN (org_id, scope_host) must hash
        # back to the slug it is filed under / the delegated scope (cust_<h> == _customer_slug(org, host)). This
        # is the real cross-tenant guard — settle_launch's expect_org_id is derived from the same lease and so
        # can never fire from this caller; this binds the authentic signed org+host to the delegated scope, so a
        # lease filed under a mismatched slug (or any org/host that does not hash to this scope) is refused.
        from sigil.ui.target_authorization import _customer_slug
        if _customer_slug(str(lease_doc.org_id), str(lease_doc.scope_host)) != str(doc.engagement_slug):
            raise CompletionSpoolError(
                f"published lease (org={lease_doc.org_id!r}, host={lease_doc.scope_host!r}) does not hash to the "
                f"completion slug {doc.engagement_slug!r} — refusing a tenant-mismatched settle")
        consumed, guard = self._settle_inputs(doc.outcome.value, lease_doc)
        result = self._gate.settle_launch(
            signed_lease=bundle.signed_lease.model_dump(mode="json"), consumed_units=consumed,
            now=self._now(), expect_org_id=lease_doc.org_id, refuse_if=guard,
            basis=f"completion:{doc.outcome.value}")
        if not result.get("ok"):
            if result.get("retry"):                    # a request still in flight, a meter / lock busy right now
                raise CompletionSpoolDeferred(f"settle_launch deferred: {result.get('error')}")
            if result.get("refused"):                  # the in-lock pricing guard changed: re-priced next drain
                raise CompletionSpoolDeferred(f"settle refused: {result.get('refused')}")
            raise CompletionSpoolError(f"settle_launch refused: {result.get('error')}")
        # NTF-3: project the just-settled outcome to a tenant-visible notification record. On a FRESH settle
        # (``action == "launch_settled"``) — and on a re-drive that FINISHED a completion's recorded settlement a
        # crash interrupted (``rolled_forward`` with a ``completion:`` basis: the first drive died before it got
        # here). Never on a plain ``launch_already_settled`` re-drive (no second record), and never for a
        # roll-forward a cancel or the sweep decided. STRICTLY SEPARATE from the settle decision above: the append
        # is best-effort and fail-safe (``_record_outcome`` swallows every error), so it can NEITHER fail NOR double
        # the settle (which has already committed), mirroring how FDX-2 keeps findings-crossing out of the settle
        # signal; the notification centre de-dups an at-least-once double-append by ``(slug, nonce)``. The record
        # carries NO amount — it is ADVISORY (money-doctrine clean) and NEVER alters the charge/refund.
        # org_id/slug/host come from the VERIFIED owner-signed lease, never the signal body.
        basis = str(result.get("basis") or "")
        if result.get("action") == "launch_settled":
            self._record_outcome(lease_doc, doc)
        elif result.get("rolled_forward") and basis.startswith("completion:"):
            self._record_outcome(lease_doc, doc, outcome=basis.split(":", 1)[1])   # the RECORDED outcome
        return result

    def _record_outcome(self, lease_doc: Any, completion: Any, *, outcome: Optional[str] = None) -> None:
        """Best-effort tenant-scoped ``assessment_outcome`` projection for the customer notification centre
        (NTF-3). The ``org_id`` / ``engagement_slug`` are taken from the VERIFIED owner-signed lease (never the
        signal body); the terminal ``outcome`` from the governance-verified completion. Carries NO amount —
        advisory only, never a money figure. FAIL-SAFE: any store/append error is swallowed (logged), so this
        projection can NEVER fail or double the settle, which has already committed. The record's stable
        ``(slug, nonce)`` identity lets the notification centre de-dup an at-least-once double-append."""
        try:
            self.store.append(
                kind="assessment_outcome", source="sigil", actor="settle-drain",
                payload={
                    "engagement_slug": str(lease_doc.engagement_slug),
                    "org_id": str(lease_doc.org_id),
                    "outcome": str(outcome) if outcome is not None else str(completion.outcome.value),
                    "nonce": str(lease_doc.nonce),
                    "ts": float(self._now()),
                })
        except Exception:  # noqa: BLE001 — advisory projection: an append failure never breaks/doubles the settle
            import logging
            logging.getLogger(__name__).warning(
                "NTF-3 assessment-outcome record append failed (advisory; settle unaffected)", exc_info=True)

    def _consumed_for(self, outcome: str, lease_doc: Any) -> int:
        """The billable units for ONE verified lease's terminal ``outcome`` (see :meth:`_settle_inputs`)."""
        return self._settle_inputs(outcome, lease_doc)[0]

    def _settle_inputs(self, outcome: str, lease_doc: Any) -> "tuple[int, Optional[Callable[[], Optional[str]]]]":
        """``(consumed, refuse_if)`` for ONE verified lease's terminal ``outcome``: the billable units, and the
        settle's in-lock precondition (None except where the price was read from a record that can change before
        the settle takes its lock — a metered FAILED run's paused-past-expiry record, below).

        The billable units for ONE verified lease's terminal ``outcome``. The mode is the LAUNCH's, decided when it
        was published (its grant, metered marker or meter on disk — ``LaunchGate._launch_was_metered``), never the
        flag now: a launch published flat settles by the flat per-run rule (:meth:`_consumed`), byte-identical. A
        launch published metered (PRICING M1c, design §4.3-§4.4) has its model gateway meter CLOSED first (no request
        is admitted after it, from any process), then:

          * ``completed`` ⇒ ``min(reserved, max(floor, ceil(confirmed cost x markup / $0.01)))`` — the customer pays
            for what the run used, never more than the reservation they approved;
          * ``canceled`` ⇒ the owner's named policy (``VIGIL_BILLING_CANCEL_SETTLEMENT``): ``metered`` as above, or
            ``refund`` = 0;
          * anything else (``failed``, VIGIL's side) ⇒ 0, except a launch the customer held paused through the end
            of its window (lifted only after it closed, so the re-drive the window refuses ends as ``failed``): it
            settles like a paused, abandoned launch — what it used, or 0 when it used nothing.

        Only CONFIRMED spend is billed: unconfirmed spend (a lost record, the unreported part of a cut-off response)
        is VIGIL's cost. The meter is keyed by the verified lease's own ``(engagement_slug, nonce)`` — never a wire
        value. A request still in flight, a meter that cannot be written right now, or an unset pricing setting
        DEFERS the settle (:class:`CompletionSpoolDeferred`, retried next drain); a meter whose hash chain is broken
        REFUSES it (quarantined for a human) — never a guessed charge."""
        from .. import config
        reserved = int(lease_doc.units_reserved)
        try:
            metered = self._gate._launch_was_metered(str(lease_doc.engagement_slug), str(lease_doc.nonce))
        except OSError as exc:
            raise CompletionSpoolDeferred(f"the run's billing mode could not be read: {exc}") from exc
        if not metered:
            return self._consumed(outcome, reserved), None
        from vigil_core import model_metering as mm
        from vigil_core.model_grant import meter_id
        from ..model_gateway import GrantMeter, MeterBusy
        try:
            totals = GrantMeter(config.MODEL_METER_DIR).close(
                meter_id(str(lease_doc.engagement_slug), str(lease_doc.nonce)), now=float(self._now()))
        except MeterBusy as exc:
            raise CompletionSpoolDeferred(str(exc)) from exc
        except OSError as exc:
            raise CompletionSpoolDeferred(f"the run's model meter could not be closed: {exc}") from exc
        except ValueError as exc:
            raise CompletionSpoolError(f"the run's model meter is broken: {exc}") from exc
        guard: "Optional[Callable[[], Optional[str]]]" = None
        if str(outcome) not in ("completed", "canceled"):
            # A FAILED run is free (VIGIL's failure) — unless the customer held it paused through the end of its
            # window and lifted the pause only afterwards: its re-drive is then refused by the window and ends here
            # as FAILED, so it settles by the paused-and-abandoned rule (owner decision 2026-11-13: charged for what
            # it used; nothing used -> nothing charged). An unreadable record defers rather than guessing.
            held = self._paused_past_expiry(lease_doc)
            if held is None:
                raise CompletionSpoolDeferred("the launch's paused-past-expiry record could not be read")

            def _pause_guard() -> Optional[str]:
                # E3bc: re-read INSIDE the settle's critical section — a late resume recorded after the read above
                # re-prices the settle (deferred: the next drain charges it under D4), never refunds it.
                now = self._paused_past_expiry(lease_doc)
                if now is None:
                    return "pause_unknown"
                return "pause_changed" if bool(now) != bool(held) else None

            guard = _pause_guard
            if not held or (totals.requests == 0 and totals.cost_nano == 0):
                return 0, guard
        try:
            if str(outcome) == "canceled" and mm.cancel_settlement() == "refund":
                return 0, guard
            return mm.credits_for_cost(totals.cost_nano, markup=mm.billing_markup(), floor=mm.run_floor_credits(),
                                       cap=reserved), guard
        except mm.MeteringError as exc:
            raise CompletionSpoolDeferred(f"metered settle waits on its pricing configuration: {exc}",
                                          config=True) from exc

    def _paused_past_expiry(self, lease_doc: Any) -> "Optional[bool]":
        try:
            from vigil_integration.live.credit_lease_pause import paused_past_expiry
            return paused_past_expiry(self._base_dir, str(lease_doc.engagement_slug), str(lease_doc.nonce))
        except Exception:  # noqa: BLE001 — an import or read failure is "cannot tell", never an answer
            return None

    @staticmethod
    def _consumed(outcome: str, reserved: int) -> int:
        """FLAT-PER-RUN, recomputed authoritatively from the OWNER-SIGNED lease (never the signal): a
        ``completed`` run consumes the full reserved units; ``canceled``/``failed`` consume 0 (full refund).
        ``settle_launch`` additionally clamps to the signed reserved, so this can never over-charge."""
        return int(reserved) if str(outcome) == "completed" else 0

    # -- hostile-file hardening (mirrors BillingSpoolWatcher) --------------------------------------
    @staticmethod
    def _read_regular(path: Path) -> str:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file (symlink/FIFO/device refused)")
            if st.st_size > _MAX_BYTES:
                raise OSError(f"file exceeds {_MAX_BYTES} bytes")
            # (D) read to EOF — a single os.read may short-read and truncate a valid envelope (mirrors the
            # sibling spool_watcher / billing_spool / webhook_drain read loops).
            chunks: "list[bytes]" = []
            remaining = _MAX_BYTES + 1
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
    def _safe_unlink(path: Path) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _reclaim_working(self) -> None:
        """(K) Crash recovery: move any file stranded in ``working/`` (a claim interrupted before it was
        archived / quarantined — a mid-drain crash) back to ``incoming/`` so it is reprocessed. The downstream
        dedup (processed/ sha256 + ``settle_launch``'s own ``(slug, nonce)`` idempotency) makes a re-process
        safe, so this can never double-settle a completed one — it only ensures a settlement is never SILENTLY
        LOST (which, for a refund/charge, is money)."""
        try:
            with self._spool_lock():                 # E3bc: never between two of the sweep's in-lock globs
                try:
                    stale = list(self.working.glob("*.json"))
                except OSError:
                    return
                for f in stale:
                    try:
                        os.replace(f, self.incoming / f.name)
                    except OSError:
                        self._safe_unlink(f)
        except OSError:
            return                                   # left in working/: the sweep reads it as pending; retried next drain

    def drain(self) -> dict:
        """Process every file in ``incoming/`` once. Returns ``{settled, noop, rejected, deduped}``. Begins with
        a crash-recovery sweep of ``working/`` (finding K) and a per-drain RE-VERIFY of the delegation against
        the current clock (finding B: an expired delegation settles NOTHING and leaves ``incoming/`` untouched
        for a later renewed drain). Each file is atomically CLAIMED into ``working/`` before acting (a re-run
        never double-processes), read as a bounded regular UTF-8 file, and deduped on the sha256 of the READ
        BYTES. A settle or a safe no-op both archive to ``processed/`` (handled); any failure → ``rejected/``,
        nothing settled. Never raises on one bad file; never blocks on a hostile one."""
        self._reclaim_working()
        root = self._current_root()
        if root is None:
            _sys.stderr.write("vigil settle-drain: WARNING offense-governance delegation is not currently valid "
                              "(expired / out-of-horizon) — settling nothing this drain (will retry on renewal)\n")
            return {"settled": 0, "noop": 0, "rejected": 0, "deduped": 0}
        settled = noop = rejected = deduped = deferred = deferred_config = 0
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)
            except OSError:
                continue
            try:
                text = self._read_regular(claimed)
            except OSError as exc:
                self._quarantine(claimed, f"unreadable / not a bounded regular UTF-8 file: {exc}")
                rejected += 1
                continue
            marker = self.processed / (hashlib.sha256(text.encode("utf-8")).hexdigest() + ".json")
            if marker.exists():
                try:
                    os.replace(claimed, marker)
                except OSError:
                    self._safe_unlink(claimed)
                deduped += 1
                continue
            try:
                result = self._settle_one(text, root)
            except CompletionSpoolDeferred as exc:
                try:
                    with self._spool_lock():         # E3bc: never between two of the sweep's in-lock globs
                        os.replace(claimed, src)     # back to incoming/: the next drain retries it
                except OSError:
                    pass                             # left in working/: the next drain's reclaim returns it
                _sys.stderr.write(f"vigil settle-drain: deferred {src.name}: {exc}\n")
                deferred += 1
                deferred_config += int(exc.config)
                continue
            except CompletionSpoolError as exc:
                self._quarantine(claimed, f"settle refused: {exc}")
                rejected += 1
                continue
            except Exception as exc:  # noqa: BLE001 — any unexpected error quarantines; never sinks the drain
                self._quarantine(claimed, f"unexpected settle error: {type(exc).__name__}: {exc}")
                rejected += 1
                continue
            if result is None:
                noop += 1
            else:
                settled += 1
            try:
                os.replace(claimed, marker)          # archive as handled (dedup ledger)
            except OSError:
                self._safe_unlink(claimed)
        out = {"settled": settled, "noop": noop, "rejected": rejected, "deduped": deduped}
        if deferred:
            out["deferred"] = deferred               # PRICING M1c only: the flat result shape is unchanged
        if deferred_config:
            out["deferred_config"] = deferred_config
        return out

    def watch(self, *, interval: float = 2.0, sleep: Optional[Callable[[float], None]] = None) -> None:
        """Drain in a loop forever (Ctrl-C / SIGTERM to stop). A single bad drain NEVER kills the daemon: an
        unexpected error is reported to stderr and the loop continues. The delegation is re-verified against the
        live clock each ``drain()`` (finding B), so a long-lived watcher stops settling when it lapses. ``sleep``
        is injectable for tests."""
        _sleep = sleep or time.sleep
        while True:
            try:
                self.drain()
            except Exception as exc:  # noqa: BLE001 — the watch loop must survive any single-drain failure
                _sys.stderr.write("vigil settle-drain: WARNING drain error (continuing): "
                                  f"{type(exc).__name__}: {exc}\n")
            _sleep(interval)
