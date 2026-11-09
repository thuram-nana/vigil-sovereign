"""K2 — the keyless offense-side CREDIT-LAUNCH-LEASE precondition for a CUSTOMER engagement.

A customer launch (a ``cust_`` engagement slug) must present a VERIFIED owner-signed ``CreditLaunchLease`` on
the cross-plane seam before the engage path arms — a SEPARATE conjunct from the ``EngagementAuthority`` (G0).
This module:

  * VERIFIES the public owner-signed lease against the OUT-OF-BAND-PINNED owner key (the authority root the
    engage path already pins — NEVER the seam-carried ``trust_root``, which a seam-writer could forge), and
  * BINDS it to THIS engagement (``engagement_slug``), THIS target host (``scope_host``), THIS tenant
    (``org_id`` == the process ``CRUCIBLE_TENANT``), within its ``[not_before, not_after)`` window, and
  * CONSUMES it SINGLE-USE via a strict per-slug ``issued_at`` high-water floor (the arm is the one
    authoritative consume; a replay of the same/older lease refuses, a genuine re-lease — newer ``issued_at`` —
    passes and advances the floor). KNOWN LIMITATION (tracked, K-hardening): ``issued_at`` is the owner-signed
    WALL-CLOCK time, not a monotonic counter, so two genuine re-leases minted in the same millisecond, or a
    re-lease after a backward clock step, collide on the integer floor and the later (separately-signed,
    separately-debited) lease is refused as a 'replay' — a within-tenant, fail-CLOSED availability loss
    (credits recoverable via cancel), never a replay / fail-open hole. The sound fix is to key single-use on
    the lease ``nonce`` (the model's single-use token), a deliberate anti-replay-substrate change.

It holds NO key and makes NO money decision (the sovereign plane reserved the credits + minted the lease; the
offense plane only checks it before traffic). Operator / greenfield runs (a non-``cust_`` slug) require NO
lease — :func:`is_customer_slug` is False for them, so the engage hook is a byte-identical no-op. FATAL-2:
module-scope imports are stdlib only; the vigil_core / vigil_integration-seam / offense authority+tenant reads
are lazy inside the function (no ``sigil`` import, ever).
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

_FLOOR_DIRNAME = ".credit-lease-highwater"


def _safe_slug(slug: Any) -> str:
    """A filesystem-safe engagement-slug component for the floor path: no separators / ``..`` / control chars.
    Returns "" if unsafe (``cust_<24hex>`` in practice; this is defence-in-depth)."""
    s = str(slug or "").strip()
    if not s or "/" in s or "\\" in s or ".." in s or any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        return ""
    return s


def _base_dir() -> str:
    """The cross-plane seam base — the SAME ``VIGIL_BASE_DIR`` the authority seam uses (defaults to the live
    base), so the lease co-locates with its G0 EngagementAuthority."""
    return os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"


def is_customer_slug(slug: Any) -> bool:
    """True iff ``slug`` is a customer engagement (``cust_`` prefix). The engage hook consults a lease ONLY for
    these; every operator / greenfield slug is untouched (byte-identical). NOTE: this is a CONVENTION, not a
    structural binding — the sovereign plane always mints customer slugs as ``cust_<hash>``, so it holds in
    practice, but (a) an operator who explicitly names a ``cust_`` slug is fail-CLOSED-blocked (asked for a
    lease operators never mint) and (b) were a future customer-launch driver (K4) to arm a customer engagement
    under a NON-``cust_`` slug, this conjunct would be silently skipped. K4 MUST bind lease-required-ness to a
    structural customer marker (the customer EngagementAuthority / tenant), not this prefix, and reserve the
    ``cust_`` prefix against operator use — a hard K4 prerequisite (tracked)."""
    return isinstance(slug, str) and slug.startswith("cust_")


def customer_engagement_requires_lease(slug: Any, *, trust_root: Any = None) -> bool:
    """STRUCTURAL replacement for :func:`is_customer_slug` as the lease‑required gate (K4‑0): an engagement
    requires a customer ``CreditLaunchLease`` iff it is a CUSTOMER engagement, determined from the OWNER‑SIGNED
    ``EngagementAuthority`` (``issued_by`` starts ``"customer:"`` — baked into the signed bytes by
    ``add_customer_target``), with the ``cust_`` prefix kept as a fail‑closed FAST‑PATH. This closes the two
    holes the ``is_customer_slug`` docstring flagged: (a) ``cust_`` is RESERVED against operator use
    (``add_target`` refuses a ``cust_`` slug, so a verified NON‑customer authority can never carry one), and
    (b) a customer authority under a NON‑``cust_`` slug STILL requires a lease (the K2 conjunct can no longer
    be skipped by renaming the slug).

      * ``cust_`` prefix  → True (fast‑path; no authority load; preserves today's fail‑closed ``cust_``
        behaviour even when no owner root / authority is loadable — matches the K2 arm tests);
      * otherwise         → True iff a VERIFIED owner‑signed authority for ``slug`` is customer‑issued; ANY
        load/verify failure (operator / greenfield: no verifiable customer authority) → False, so those paths
        stay byte‑identical (no lease consulted, no raise).

    Verify‑only, keyless, fail‑closed; never raises. ``trust_root`` is injectable for tests; production uses
    the pinned owner root (``load_authority_root``), exactly as the lease verify does."""
    if is_customer_slug(slug):
        return True
    try:
        from .authority.store import load_authority_root, load_verified_authority
        root = trust_root if trust_root is not None else load_authority_root()
        if root is None:
            return False
        doc = load_verified_authority(str(slug), root)
        return str(getattr(doc, "issued_by", "")).startswith("customer:")
    except Exception:  # noqa: BLE001 — no verifiable customer authority ⇒ not a customer engagement (byte-identical)
        return False


def _advance_floor(base: Any, safe_slug: str, seq: int) -> "tuple[bool, str]":
    """STRICT single-use floor: refuse ``seq <= prior`` (a replay of this/an older lease), else advance to
    ``seq``. The load→strict-check→advance runs under :func:`highwater_lock`, so two concurrent arms of the same
    lease cannot both pass. Fail-closed on a corrupt/un-persistable floor (an arming precondition must never
    proceed when its anti-replay state cannot be trusted or recorded)."""
    from vigil_core.highwater import (
        HighWaterDowngrade, HighWaterError, advance_highwater, highwater_lock, load_highwater,
    )
    path = Path(base) / _FLOOR_DIRNAME / f"{safe_slug}.json"   # safe_slug already forbids separators/..
    try:
        with highwater_lock(path):
            try:
                prior = load_highwater(path)
            except HighWaterError as e:
                return False, f"credit-lease single-use floor is corrupt/tampered (fail-closed): {e}"
            # STRICT (<=) — check_highwater/advance_highwater are >=, which would let a same-issued_at replay
            # re-arm; the explicit <= is what makes the lease single-use (a re-lease has a strictly newer
            # issued_at, so it still advances).
            if prior is not None and int(seq) <= int(prior.get("last_seq", -1)):
                return False, "replay refused — this lease (or an older one) was already consumed (single-use)"
            head = SimpleNamespace(entry_count=int(seq), last_seq=int(seq))
            try:
                advance_highwater(path, head, _locked=True)
            except (OSError, HighWaterError, HighWaterDowngrade) as e:
                return False, f"cannot persist the credit-lease single-use floor (fail-closed): {e}"
    except OSError as e:
        return False, f"credit-lease single-use floor lock failed (fail-closed): {e}"
    return True, "ok"


def _verify_and_bind_lease(slug: str, host: str, tenant: Optional[str], *,
                           base: Any, t: float, check_pause: bool = True) -> "tuple[bool, str, Any]":
    """Owner-pinned VERIFY + BIND of the seam lease for ``slug`` — everything :func:`verify_customer_launch_lease`
    does EXCEPT the single-use consume. Returns ``(ok, reason, doc)``: on success ``(True, "ok", <lease doc>)``
    (so a caller can read ``doc.units_reserved``), else ``(False, <reason>, None)``. Fail-CLOSED; never raises.
    This is the ONE owner-pinned verify+bind shared by the arm (``verify_customer_launch_lease``) and the keyless
    ceiling read (:func:`read_verified_launch_units`), so they agree by construction — the ceiling a run arms is
    read from the SAME verified lease the arm consumes, never from an unverified seam/wire value."""
    safe = _safe_slug(slug)
    if not safe:
        return False, "unsafe engagement slug", None
    try:
        from .authority.store import load_authority_root
        owner_root = load_authority_root()        # OUR pinned owner key — NOT the seam-carried trust_root
    except Exception as e:  # noqa: BLE001 — a malformed/absent root is fail-closed
        return False, f"owner authority trust root unreadable (fail-closed): {type(e).__name__}", None
    if owner_root is None:
        return False, "no owner authority trust root to verify the lease against (fail-closed)", None
    try:
        from vigil_core import verify_credit_launch_lease
        from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease
    except Exception as e:  # noqa: BLE001
        return False, f"lease seam/verify unavailable (fail-closed): {type(e).__name__}", None
    bundle = read_credit_lease(base, safe)
    if bundle is None:
        return False, "no credit-launch lease on the seam for this engagement", None
    try:
        ok, reason = verify_credit_launch_lease(bundle.signed_lease, owner_root)
    except Exception as e:  # noqa: BLE001
        return False, f"lease verify raised (fail-closed): {type(e).__name__}", None
    if not ok:
        return False, f"lease does not verify under the owner key: {reason}", None
    doc = bundle.signed_lease.document
    if doc.engagement_slug != safe:
        return False, f"lease engagement_slug {doc.engagement_slug!r} != engagement {safe!r}", None
    if doc.scope_host != host:
        return False, f"lease scope_host {doc.scope_host!r} != target host {host!r}", None
    if not tenant or doc.org_id != tenant:
        return False, f"lease org_id {doc.org_id!r} != this process tenant {tenant!r}", None
    try:
        nb, na = doc.not_before.timestamp(), doc.not_after.timestamp()
    except Exception as e:  # noqa: BLE001
        return False, f"lease window unreadable (fail-closed): {type(e).__name__}", None
    if not (nb <= t < na):
        return False, "lease is outside its validity window", None
    # K4-1 / K5: a lease whose (slug, nonce) was SETTLED/CANCELED is no longer a runnable launch capability —
    # refuse on BOTH the arm (consume=True) and the enqueue pre-check (consume=False). Belt-and-braces beyond
    # the seam tombstone (which already removes the bundle so read_credit_lease returns None in the common
    # case); this catches a stale/re-published copy.
    try:
        if is_lease_settled(base, safe, doc.nonce):
            return False, "lease has been settled/canceled (no longer a runnable launch capability)", None
    except Exception as e:  # noqa: BLE001 — FAIL-CLOSED (K4-1 red-pen): if settlement status is UNREADABLE we
        # REFUSE rather than fall through to consume. is_lease_settled is total today (absent/malformed ⇒ False,
        # never raises), so this pins a latent fail-OPEN coupling in the arming precondition — it is not a
        # behaviour change on any currently-reachable input, and the arm must never proceed when its
        # anti-replay/revocation state cannot be trusted.
        return False, f"credit-lease settlement status unreadable (fail-closed): {type(e).__name__}", None
    # pause/resume PR-2: a lease whose (slug, nonce) is PAUSED is a REVERSIBLE operator halt — REFUSE the verify
    # as a PARALLEL re-check to the settled conjunct above, on BOTH the arm (consume=True) and the enqueue
    # pre-check (consume=False). Because this is the ONE shared verify+bind chokepoint and the refusal returns
    # BEFORE verify_customer_launch_lease reaches _advance_floor, a pause NEVER advances/burns the single-use
    # issued_at floor: a later clear_lease_pause (resume) RE-ARMS the SAME lease and still passes the identical
    # owner-pin + bind + window checks. DEFAULT-OFF: with no pause marker is_lease_paused is False, so behaviour
    # is byte-identical to today. FATAL-2: the vigil_integration.live import stays LAZY inside the function (never
    # at module scope), exactly as the broker import above, so the two-plane boundary + test_two_env_boundary hold.
    # pause/resume PR-3: ``check_pause=False`` is passed ONLY by :func:`read_verified_launch_nonce`, the
    # in-flight cooperative-halt nonce read — it must surface THIS lease's nonce to DRIVE the pause lookup even
    # while the lease is paused (the nonce is a property of the lease, not of its pause state), so it skips this
    # re-check. Every arm / enqueue path keeps the default ``check_pause=True`` → byte-identical to PR-2.
    if check_pause:
        try:
            from vigil_integration.live.credit_lease_pause import is_lease_paused
            if is_lease_paused(base, safe, doc.nonce):
                return False, "lease is paused (operator halt; resume to re-arm)", None
        except Exception as e:  # noqa: BLE001 — FAIL-CLOSED: is_lease_paused is total (an existing-but-corrupt
            # marker already returns True/halt), so this backstops the same latent-coupling class the settled
            # re-check does — if the pause store or its import ever raised, REFUSE rather than fall through to consume.
            return False, f"credit-lease pause status unreadable (fail-closed): {type(e).__name__}", None
    return True, "ok", doc


def verify_customer_launch_lease(slug: str, host: str, tenant: Optional[str], *,
                                 base_dir: Any = None, now: Optional[float] = None,
                                 consume: bool = True) -> "tuple[bool, str]":
    """Return ``(ok, reason)``. True iff a current owner-signed lease on the seam for ``slug`` VERIFIES
    owner-pinned, BINDS (engagement_slug==slug, scope_host==host, org_id==tenant, window covers ``now``), AND
    (when ``consume``) passes+advances the strict single-use floor. Fail-CLOSED; never raises. ``consume`` is
    True at the engine ARM (the one authoritative consume); a driver-enqueue PRE-CHECK (K4) passes
    ``consume=False`` so it does not burn the single use."""
    base = base_dir if base_dir is not None else _base_dir()
    t = time.time() if now is None else float(now)
    ok, reason, doc = _verify_and_bind_lease(slug, host, tenant, base=base, t=t)
    if not ok:
        return False, reason
    if consume:
        # ms resolution REDUCES (does not eliminate) same-second re-lease collisions on the integer floor;
        # same-ms re-leases and backward clock steps still collide — see the KNOWN LIMITATION in the module
        # docstring (fail-closed; the sound fix keys single-use on the nonce, tracked for the K-hardening pass).
        return _advance_floor(base, _safe_slug(slug), int(float(doc.issued_at) * 1000))
    return True, "ok"


def read_verified_launch_units(slug: str, host: str, tenant: Optional[str], *,
                               base_dir: Any = None, now: Optional[float] = None) -> Optional[int]:
    """EC-3 — the OWNER-SIGNED, keyless per-run ceiling input: the ``units_reserved`` from the VERIFIED +
    BOUND credit-launch lease for ``slug`` (the SAME owner-pinned verify+bind the arm uses), or ``None`` when
    there is no lease that verifies/binds. Verify-ONLY — it does NOT consume the single-use floor (the engine
    arm's ``verify_customer_launch_lease(consume=True)`` remains the one authoritative consume), so reading the
    ceiling never burns the launch. Fail-CLOSED: any missing / forged / wrong-host / wrong-tenant / expired /
    settled lease ⇒ ``None`` (no ceiling derivable ⇒ the run is left unarmed by the caller). Never raises.

    The engine multiplies this by :data:`vigil_core.ENVELOPE_TOKENS_PER_CREDIT` to get the token ceiling, so
    the hard run budget enforces the SAME reserved envelope the sovereign plane minted — one shared constant,
    no money number in the engine, no drift test."""
    base = base_dir if base_dir is not None else _base_dir()
    t = time.time() if now is None else float(now)
    ok, _reason, doc = _verify_and_bind_lease(slug, host, tenant, base=base, t=t)
    if not ok or doc is None:
        return None
    try:
        return int(doc.units_reserved)
    except (TypeError, ValueError):   # a doc that validated already has units_reserved>=1; defence-in-depth
        return None


def read_verified_launch_nonce(slug: str, host: str, tenant: Optional[str], *,
                               base_dir: Any = None, now: Optional[float] = None) -> Optional[str]:
    """pause/resume PR-3 — the OWNER-SIGNED, keyless lease NONCE for ``slug`` from the VERIFIED + BOUND
    credit-launch lease (the SAME owner-pinned verify + bind the arm uses: owner-key signature, slug / host /
    tenant / window, and the K4-1 settlement re-check), or ``None`` when no lease verifies / binds. Verify-ONLY
    — it NEVER consumes the single-use floor (the engine arm's ``verify_customer_launch_lease(consume=True)``
    stays the one authoritative consume), so reading the nonce never burns the launch. Never raises.

    It passes ``check_pause=False`` DELIBERATELY: the nonce is the key the in-flight cooperative-halt check
    (``is_lease_paused(slug, nonce)``) looks a pause up BY, so it must be readable even while the lease is paused
    — otherwise a pause arriving in the narrow window between the enqueue gate's pass and this read would leave
    the running engagement with NO halt binding. A settled / wrong-host / wrong-tenant / expired / forged lease
    still ⇒ ``None`` (those are NOT runnable launches); only the reversible PAUSE conjunct is skipped here."""
    base = base_dir if base_dir is not None else _base_dir()
    t = time.time() if now is None else float(now)
    ok, _reason, doc = _verify_and_bind_lease(slug, host, tenant, base=base, t=t, check_pause=False)
    if not ok or doc is None:
        return None
    try:
        n = str(doc.nonce)
    except (TypeError, ValueError, AttributeError):   # a doc that validated already carries a nonce; defence-in-depth
        return None
    return n or None
