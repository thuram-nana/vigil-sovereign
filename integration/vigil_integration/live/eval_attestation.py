"""eval_attestation — the import-clean seam + OFFENSE-side verifier for the M-11.1 EvalOffenseAttestation.

The SOVEREIGN governor (``apps/sigil/sigil/governor/eval_offense_attestation.py``) owner-signs an
EvalOffenseAttestation — bound to ``(engagement_slug, charter_id, charter_hash, environment)``, auto-expiring,
anti-replay, and COUNTER-SIGNED by a distinct owner-enrolled EVALUATOR — appends it to the sovereign spine,
and MIRRORS the public signed records here. The OFFENSE plane reads them back and VERIFIES them against the
pinned owner key before it will ARM weaponized offense on a LIVE target.

This module is the TRANSPORT + the fail-closed VERIFIER; it holds NO private key and is the mirror image of
``authorization_broker`` (same atomic-write + path-safety discipline) plus a fold that mirrors the sovereign
``EvalOffenseAttestation.state`` — honouring any revoke, rejecting a forged owner sig, a missing/forged
evaluator PoP, a wrong charter/environment, an expired, or a replayed (``issued_at`` below the high-water)
record.

  ``<base>/eval-offense-attestations/<slug>.json`` — the owner-signed record list::

      { "schema_version": 1, "kind": "vigil-eval-offense-attestation-v1", "slug": "<slug>",
        "records": [ { ...owner-signed attestation payload incl. sig/pubkey/evaluator_sig... }, ... ] }

Public-safe: only PUBLIC keys + signatures + the (owner-authored) binding cross. No private key, ever.
FATAL-2 / import-clean: ``vigil_core`` + stdlib + relative imports only — the OFFENSE plane never imports the
sovereign governor, and this module never imports ``framework``/``strix``/``sigil``.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any, Iterable, Optional

from vigil_core import IntegrityError, canonical_json, verify_one
from vigil_core.spine_domains import DOMAIN_TAGS

__all__ = [
    "SIGNAL",
    "eval_attestations_root",
    "eval_attestation_path",
    "write_eval_attestations",
    "read_eval_attestations",
    "verify_live_offense_attested",
]

SIGNAL = "governor.eval_offense_attestation"
_DOMAIN_KEY = "eval-offense-attestation"

_DIRNAME = "eval-offense-attestations"
_SCHEMA = "vigil-eval-offense-attestation-v1"
_SCHEMA_VERSION = 1

# The owner-authenticated CORE — byte-identical to the sovereign governor's ``_CORE``. The offense plane only
# ever RECONSTRUCTS this from the published payload to recompute the signing bytes; it never mints one.
_CORE = (
    "signal", "state", "engagement_slug", "charter_id", "charter_hash", "evaluator_pubkey",
    "environment", "not_after", "issued_at", "allow_destructive",
)


# ---------------------------------------------------------------------------------------------------
# paths + safe id component (mirrors authorization_broker._safe_component / _atomic_write_json)
# ---------------------------------------------------------------------------------------------------


def eval_attestations_root(base_dir: Any) -> Path:
    return Path(base_dir) / _DIRNAME


def _safe_component(value: Any) -> str:
    s = str(value or "").strip()
    if not s or "/" in s or "\\" in s or ".." in s:
        return ""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s):
        return ""
    return s


def _contained_child(root: Path, filename: str) -> Optional[Path]:
    root_real = os.path.realpath(str(root))
    name = os.path.basename(filename)
    if name != filename:
        return None
    final = os.path.realpath(os.path.join(root_real, name))
    if not final.startswith(root_real + os.sep):
        return None
    if os.path.dirname(final) != root_real:
        return None
    return Path(final)


def eval_attestation_path(base_dir: Any, slug: str) -> Optional[Path]:
    safe = _safe_component(slug)
    if not safe:
        return None
    return _contained_child(eval_attestations_root(base_dir), f"{safe}.json")


def _atomic_write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    tmp = path.parent / (path.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(path))
    finally:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------------
# the seam (public-safe signed record list)
# ---------------------------------------------------------------------------------------------------


def write_eval_attestations(base_dir: Any, slug: str, records: Iterable[dict]) -> Path:
    """Write the public signed eval-offense-attestation record list for ``slug``. Raises ValueError on an
    unsafe slug (never writes outside the dir). The records carry only public material (sigs + public keys +
    the owner-authored binding)."""
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe eval-offense-attestation slug: {slug!r}")
    path = _contained_child(eval_attestations_root(base_dir), f"{safe}.json")
    if path is None:
        raise ValueError(f"unsafe eval-offense-attestation slug (escapes dir): {slug!r}")
    obj = {
        "schema_version": _SCHEMA_VERSION,
        "kind": _SCHEMA,
        "slug": safe,
        "records": [dict(r) for r in records if isinstance(r, dict)],
    }
    _atomic_write_json(path, obj)
    return path


def read_eval_attestations(base_dir: Any, slug: str) -> list[dict]:
    """Read the published signed record list for ``slug`` (public material only; the CALLER verifies against
    the pinned owner key). ``[]`` if absent, unsafe, or malformed (fail-closed — an unreadable list is 'no
    attestation', never a partial-trust default)."""
    path = eval_attestation_path(base_dir, slug)
    if path is None or not path.is_file():
        return []
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(obj, dict) or obj.get("kind") != _SCHEMA:
        return []
    recs = obj.get("records")
    if not isinstance(recs, list):
        return []
    return [r for r in recs if isinstance(r, dict)]


# ---------------------------------------------------------------------------------------------------
# the fail-closed OFFENSE-side fold (mirrors sovereign EvalOffenseAttestation.state, pinned-key variant)
# ---------------------------------------------------------------------------------------------------


def _canon(core: dict) -> bytes:
    m = canonical_json(core)
    return m if isinstance(m, (bytes, bytearray)) else str(m).encode("utf-8")


def _pop_signing_bytes(core: dict) -> bytes:
    return DOMAIN_TAGS[_DOMAIN_KEY] + _canon({k: core.get(k) for k in _CORE})


def _as_issued_at(value) -> float:
    """Parse an anti-replay ``issued_at`` FAIL-CLOSED (mirrors governor.authn.as_issued_at): unparseable or
    NON-FINITE → 0.0 (the bottom), so a NaN can never poison the high-water into accepting replays."""
    import math
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) else 0.0


def _as_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0  # unparseable expiry → already-expired (fail-closed)


def _verify_owner(payload: dict, trusted_owner_pubkeys: frozenset) -> bool:
    """True iff ``payload`` carries a valid OWNER signature (over ``_CORE``) by one of the pinned owner
    pubkeys. Mirrors governor.authn.verify_signed, but the trusted key is the OFFENSE-pinned owner key (the
    authority trust root) rather than the sovereign persisted identity. Fail-closed on any malformed input."""
    pk = payload.get("pubkey")
    sig = payload.get("sig")
    if not pk or not isinstance(pk, str) or pk not in trusted_owner_pubkeys:
        return False
    if not sig or not isinstance(sig, str):
        return False
    core = {k: payload.get(k) for k in _CORE}
    try:
        return verify_one(pk, _canon(core), sig)
    except (IntegrityError, TypeError):
        return False


def _verify_pop(payload: dict) -> bool:
    """True iff the ADDITIVE evaluator PoP verifies, by ``payload['evaluator_pubkey']``, over the
    domain-tagged core. Fail-closed."""
    pk = payload.get("evaluator_pubkey")
    sig = payload.get("evaluator_sig")
    if not pk or not isinstance(pk, str) or not sig or not isinstance(sig, str):
        return False
    core = {k: payload.get(k) for k in _CORE}
    try:
        return verify_one(pk, _pop_signing_bytes(core), sig)
    except (IntegrityError, TypeError):
        return False


def verify_live_offense_attested(
    base_dir: Any, *, engagement_slug: str, trusted_owner_pubkeys: Iterable[str], now: float,
    charter_hash: Optional[str] = None, environment: str = "live",
) -> tuple[bool, str]:
    """``(attested, reason)``. The OFFENSE plane's fail-closed check that a verified EvalOffenseAttestation
    covers ``engagement_slug`` at ``now`` — reading the PUBLIC signed records from the seam and verifying them
    against the pinned owner key(s). Mirrors the sovereign fold: honour ANY revoke; reject a forged owner sig,
    a missing/forged evaluator PoP, a wrong charter (when ``charter_hash`` given) / environment / destructive
    echo, an expired, or a replayed (``issued_at`` below the high-water) record. NEVER raises."""
    pinned = frozenset(p for p in (trusted_owner_pubkeys or ()) if isinstance(p, str) and p)
    if not pinned:
        return False, "no pinned owner key — cannot verify any eval-offense attestation (fail-closed)"
    records = read_eval_attestations(base_dir, engagement_slug)
    attested = False
    reason = "default-unattested: no owner-signed eval-offense attestation on the seam"
    max_issued = float("-inf")
    for payload in records:
        if not isinstance(payload, dict) or payload.get("signal") != SIGNAL:
            continue
        if payload.get("engagement_slug") != engagement_slug:
            continue
        st = payload.get("state")
        if st == "revoked":
            attested, reason = False, "revoked by a governance event"
        elif st == "attested":
            if charter_hash is not None and payload.get("charter_hash") != charter_hash:
                continue
            if payload.get("environment") != environment:
                continue
            if payload.get("allow_destructive") is not False:
                continue
            if not _verify_owner(payload, pinned):
                continue
            if not _verify_pop(payload):
                continue
            issued = _as_issued_at(payload.get("issued_at"))
            if issued <= max_issued:
                continue
            max_issued = issued
            signed_na = _as_float(payload.get("not_after"))
            if now < signed_na:
                attested, reason = True, "owner-signed + evaluator-PoP attested, unexpired"
            else:
                attested, reason = False, "owner-signed attestation but EXPIRED"
    return attested, reason


def owner_pubkeys_of(trust_root: Any) -> frozenset:
    """The pinned owner pubkeys carried by a governance ``trust_root`` (framework entitlement TrustRoot or
    vigil_core TrustRoot — both expose ``authorizers[].public_key_b64``). ``frozenset()`` if none / malformed
    (→ the verifier fails closed)."""
    try:
        return frozenset(
            a.public_key_b64 for a in getattr(trust_root, "authorizers", [])
            if getattr(a, "public_key_b64", None)
        )
    except Exception:  # noqa: BLE001 — a malformed trust root yields no keys → fail-closed
        return frozenset()
