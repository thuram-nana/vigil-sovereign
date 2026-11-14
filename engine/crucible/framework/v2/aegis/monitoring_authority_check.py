"""AEGIS-SaaS AE-2 — the keyless gateway's PER-REQUEST monitoring-authority check (verify-only; holds NO key).

The defensive analog of ``launch_lease.verify_customer_launch_lease``. The sovereign provisioner (AE-1) mints an
owner-signed ``SignedMonitoringAuthority`` per (org, host) and publishes it, verify-only, as one file in the
published-authority directory. This module answers ONE question for the data plane: *is AEGIS authorized to
monitor this tenant's traffic to this exact host right now, and in which mode?*

Trust model (fail-CLOSED; never raises):
  * the artifact on disk is UNTRUSTED bytes — it is verified against OUR pinned owner authority root
    (``authority.store.load_authority_root``), never against any trust root the artifact might carry;
  * the signed document must BIND the exact ``org_id`` and the exact (normalized) ``host`` asked about, and the
    window must cover ``now`` (half-open ``[not_before, not_after)``);
  * any missing/malformed/oversized/non-regular file, an unreadable or absent owner root, a bad signature, a
    wrong org/host, or an out-of-window grant is a refusal with a reason.

This module decides AUTHORIZATION and MODE only. It performs NO blocking and changes no gateway behaviour:
OBSERVE never blocks, and a BLOCK grant is NECESSARY-NOT-SUFFICIENT — enforcement gating is AE-3.

FATAL-2: engine-side; imports nothing from the sovereign plane (``sigil``). The published-directory contract and
the file-naming rule are replicated here verbatim; ``tests/test_monitoring_authority_check.py`` asserts the
naming rule is byte-identical to ``apps/sigil/sigil/governor/monitoring_authority.monitoring_filename``.
"""
from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = ["MonitoringDecision", "check_monitoring_authority", "monitoring_filename", "normalize_host",
           "published_dir"]

PUBLISH_DIR_ENV = "VIGIL_MONITORING_PUBLISH_DIR"
_MAX_ARTIFACT_BYTES = 64 * 1024
_MAX_ID_LEN = 253


@dataclass(frozen=True)
class MonitoringDecision:
    ok: bool
    mode: Optional[str]     # "observe" | "block" when ok, else None
    reason: str


def _deny(reason: str) -> MonitoringDecision:
    return MonitoringDecision(ok=False, mode=None, reason=reason)


def monitoring_filename(org_id: str, host: str) -> str:
    """MUST stay byte-identical to the sovereign ``governor.monitoring_authority.monitoring_filename`` (lockstep
    test). A hash, so no org/host string can traverse the directory."""
    return hashlib.sha256(f"{org_id}\x00{host}".encode("utf-8")).hexdigest() + ".json"


def published_dir() -> Path:
    """The directory the sovereign provisioner publishes into (same contract as ``config.monitoring_publish_dir``):
    ``VIGIL_MONITORING_PUBLISH_DIR`` if set, else ``$VIGIL_BASE_DIR`` (or ``.vigil-live``)/aegis/monitoring_authority."""
    override = (os.environ.get(PUBLISH_DIR_ENV) or "").strip()
    if override:
        return Path(override)
    from vigil_core.seam_base import resolve_seam_base
    return Path(resolve_seam_base()) / "aegis" / "monitoring_authority"


def normalize_host(raw: str) -> Optional[str]:
    """Lower-case a request host, drop a ``:port`` and a trailing dot. None for anything that is not a plain DNS
    name (empty, whitespace/control chars, brackets/IP-literal form, path characters, over-long). The signed
    document must then match this value EXACTLY — so a normalization mismatch can only REFUSE, never widen."""
    if not isinstance(raw, str):
        return None
    h = raw.strip().lower()
    if not h or "[" in h or "]" in h:
        return None
    if h.count(":") == 1:
        h, _, port = h.partition(":")
        if not port.isdigit():
            return None
    elif ":" in h:
        return None
    h = h.rstrip(".")
    if not h or len(h) > _MAX_ID_LEN:
        return None
    if any(c in h for c in "/\\@?#%") or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in h):
        return None
    return h


def _read_regular_file(path: Path) -> Optional[bytes]:
    """Read at most the cap from a REGULAR file without following a symlink or blocking on a FIFO."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_ARTIFACT_BYTES:
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            data = f.read(_MAX_ARTIFACT_BYTES + 1)
        return data if len(data) <= _MAX_ARTIFACT_BYTES else None
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def check_monitoring_authority(org_id: str, host: str, *, publish_dir: "Optional[Path | str]" = None,
                               now: Optional[float] = None) -> MonitoringDecision:
    """Is monitoring authorized for (``org_id``, ``host``) at ``now``? Verify-only, fail-closed, never raises."""
    try:
        return _check(org_id, host, publish_dir=publish_dir, now=now)
    except Exception as e:  # noqa: BLE001 — the data-plane gate must never crash open or raise
        return _deny(f"monitoring-authority check raised (fail-closed): {type(e).__name__}")


def _check(org_id, host, *, publish_dir, now) -> MonitoringDecision:
    if not isinstance(org_id, str) or not org_id or len(org_id) > _MAX_ID_LEN \
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in org_id):
        return _deny("invalid tenant id")
    h = normalize_host(host)
    if h is None:
        return _deny("invalid host")
    t = time.time() if now is None else float(now)

    # OUR pinned owner root — never a trust root carried by the artifact.
    try:
        from ..authority import store as _authority_store
        owner_root = _authority_store.load_authority_root()
    except Exception as e:  # noqa: BLE001
        return _deny(f"owner authority trust root unreadable (fail-closed): {type(e).__name__}")
    if owner_root is None:
        return _deny("no owner authority trust root to verify against (fail-closed)")

    base = Path(publish_dir) if publish_dir is not None else published_dir()
    raw = _read_regular_file(base / monitoring_filename(org_id, h))
    if raw is None:
        return _deny("no published monitoring authority for this tenant and host")

    try:
        from vigil_core.monitoring_authority import SignedMonitoringAuthority, verify_monitoring_authority
        signed = SignedMonitoringAuthority.model_validate_json(raw)
    except Exception as e:  # noqa: BLE001
        return _deny(f"published monitoring authority is malformed (fail-closed): {type(e).__name__}")

    ok, why = verify_monitoring_authority(signed, owner_root)
    if not ok:
        return _deny(f"monitoring authority does not verify under the owner key: {why}")

    doc = signed.document
    if doc.org_id != org_id:
        return _deny("monitoring authority is bound to a different tenant")
    if doc.host != h:
        return _deny("monitoring authority is bound to a different host")
    try:
        nb, na = doc.not_before.timestamp(), doc.not_after.timestamp()
    except Exception as e:  # noqa: BLE001
        return _deny(f"monitoring authority window unreadable (fail-closed): {type(e).__name__}")
    if not (nb <= t < na):
        return _deny("monitoring authority is outside its validity window")
    mode = getattr(doc.mode, "value", doc.mode)
    if mode not in ("observe", "block"):
        return _deny("monitoring authority carries an unknown mode")
    return MonitoringDecision(ok=True, mode=str(mode), reason="authorized")
