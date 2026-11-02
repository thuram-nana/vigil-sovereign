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
``framework``/offense import.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable, Optional

from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate

_SEAM_SCHEMA = "vigil-engagement-completion-seam-v1"
_MAX_BYTES = 65_536                                   # a completion envelope is small; bound hostile files


class CompletionSpoolError(RuntimeError):
    """A malformed/unverifiable completion envelope (a refusal; nothing is settled)."""


class CompletionSpoolWatcher:
    """Drains an inbound engagement-completion settle spool through ``settle_launch``, fail-closed. The
    governance trust root is DERIVED from an owner-signed ``OFFENSE_GOVERNANCE_ROLE`` delegation at
    construction (an invalid delegation refuses the whole drain — no settle is ever driven under an
    un-owner-delegated key)."""

    def __init__(self, store: SpineStore, *, spool_dir: "str | os.PathLike", owner_pubkey: str,
                 delegation: Any, scope: str, base_dir: Optional[str] = None,
                 now_fn: Callable[[], float] = time.time) -> None:
        if not owner_pubkey:
            raise ValueError("owner_pubkey is required — a settle spool cannot be drained without the owner root")
        from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, DelegationError, verify_delegation
        try:
            self._root = verify_delegation(delegation, trusted_owner_pubkey=owner_pubkey,
                                           now=int(now_fn()), role=OFFENSE_GOVERNANCE_ROLE, scope=scope)
        except DelegationError as exc:
            raise ValueError(
                f"offense-governance delegation invalid — refusing to drive any settle under it: {exc}") from exc
        self.store = store
        self.scope = str(scope)
        self._base_dir = base_dir
        self._now = now_fn
        self._gate = LaunchGate(store)
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"       # a file is CLAIMED here (out of incoming) before acting
        self.processed = self.spool / "processed"   # dedup ledger: <sha256> present ⇒ already handled
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    # -- one envelope → settle (fail-closed) -------------------------------------------------------
    def _settle_one(self, text: str) -> Optional[dict]:
        """Verify one completion envelope and settle its lease. Returns the ``settle_launch`` result dict on a
        settle, or ``None`` on a safe no-op (no published lease for the slug — nothing to settle). Raises
        ``CompletionSpoolError`` on any refusal (malformed / unverifiable / out-of-scope / nonce-mismatch);
        nothing is settled."""
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
        ok, reason = verify_engagement_completion(signed, self._root)
        if not ok:
            raise CompletionSpoolError(f"completion signal does not verify under the delegated governance root: {reason}")
        doc = signed.document
        # SCOPE-BIND (exact-match unless a wildcard delegation), mirroring FindingReceiver.ingest.
        if self.scope != "*" and doc.engagement_slug != self.scope:
            raise CompletionSpoolError(
                f"completion engagement_slug {doc.engagement_slug!r} is outside the delegated scope {self.scope!r}")
        bundle = read_credit_lease(self._base_dir if self._base_dir is not None
                                   else os.environ.get("VIGIL_BASE_DIR") or ".vigil-live", doc.engagement_slug)
        if bundle is None:
            return None                              # no published lease (already settled/absent) → safe no-op
        lease_doc = bundle.signed_lease.document
        # NONCE BIND: the completion must name THIS lease's launch, so a completion for an old lease can never
        # settle a newer re-lease of the same slug.
        if str(lease_doc.nonce) != str(doc.nonce):
            raise CompletionSpoolError(
                f"completion nonce {doc.nonce!r} != published lease nonce {lease_doc.nonce!r} (stale/mismatched)")
        consumed = self._consumed(doc.outcome.value, int(lease_doc.units_reserved))
        result = self._gate.settle_launch(
            signed_lease=bundle.signed_lease.model_dump(mode="json"), consumed_units=consumed,
            now=self._now(), expect_org_id=lease_doc.org_id)
        if not result.get("ok"):
            raise CompletionSpoolError(f"settle_launch refused: {result.get('error')}")
        return result

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
            data = os.read(fd, _MAX_BYTES + 1)
        finally:
            os.close(fd)
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

    def drain(self) -> dict:
        """Process every file in ``incoming/`` once. Returns ``{settled, noop, rejected, deduped}``. Each file
        is atomically CLAIMED into ``working/`` before acting (a re-run never double-processes), read as a
        bounded regular UTF-8 file, and deduped on the sha256 of the READ BYTES. A settle or a safe no-op both
        archive to ``processed/`` (handled); any failure → ``rejected/``, nothing settled. Never raises on one
        bad file; never blocks on a hostile one."""
        settled = noop = rejected = deduped = 0
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
                result = self._settle_one(text)
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
        return {"settled": settled, "noop": noop, "rejected": rejected, "deduped": deduped}