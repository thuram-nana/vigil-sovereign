"""eval_attestation — the import-clean seam + OFFENSE-side verifier for the M-11.1 EvalOffenseAttestation.

The SOVEREIGN governor (``apps/sigil/sigil/governor/eval_offense_attestation.py``) owner-signs an
EvalOffenseAttestation — bound to ``(engagement_slug, charter_id, charter_hash, environment)``, auto-expiring,
anti-replay, and COUNTER-SIGNED by a distinct owner-enrolled EVALUATOR — appends it to the sovereign spine,
and MIRRORS the public signed records here. The OFFENSE plane reads them back and VERIFIES them against the
pinned owner key before it will ARM weaponized offense on a LIVE target.

This module is the TRANSPORT + the fail-closed VERIFIER; it holds NO private key and is the mirror image of
``authorization_broker`` (same atomic-write + path-safety discipline) plus a fold that mirrors the sovereign
``EvalOffenseAttestation.state`` — honouring any revoke, rejecting a forged owner sig, a missing/forged
evaluator PoP, an evaluator that is NOT DISTINCT from the owner (a self-attestation whose
``evaluator_pubkey`` is itself a pinned owner key — the M-11.1 two-party control refuses it, so the owner's
OWN pinned key cannot stand in as the evaluator; organizational independence of the evaluator key is an
enrollment/operational property, not cryptographically enforced (the evaluator key is held by the independent evaluator, enrolled via the owner-run ceremony)),
a wrong environment, an expired, or a replayed
(``issued_at`` below the high-water) record. The CHARTER is checked ONLY when a ``charter_hash`` is supplied;
the three arm sites supply none, so the charter binding here is the MINT-TIME consent recorded inside the
owner-signed core, NOT an arm-time guarantee — the separately owner-signed EngagementAuthority is the
enforced-scope boundary at arm time.

  ``<base>/eval-offense-attestations/<slug>.json`` — the owner-signed record list + the publish SEAL::

      { "schema_version": 1, "kind": "vigil-eval-offense-attestation-v1", "slug": "<slug>",
        "records": [ { ...owner-signed attestation payload incl. sig/pubkey/evaluator_sig... }, ... ],
        "seal":    { "kind": "vigil-eval-offense-attestation-seal-v1", "slug": "<slug>", "seq": <int>,
                     "sig": "...", "pubkey": "<owner pubkey>" } }   # sig signs slug+seq+the top-level records (not restated in the seal)

TAMPER-EVIDENCE OF THE LIST ITSELF: each record is individually owner-signed, but ``_CORE`` carries neither
the record's LIST position nor the list MEMBERSHIP, and the fold honours a ``revoke`` POSITIONALLY — so an
attacker WITHOUT the owner key could re-arm a revoked-but-unexpired, genuinely owner-signed attestation by
DROPPING the revoke record, REORDERING the list, or ROLLING BACK to a pre-revoke published file. The SIGIL
governor therefore owner-signs a ``seal`` over the WHOLE ordered list + a monotonic publish ``seq``; the
offense verifier re-derives the seal bytes over the records it read (a drop/reorder no longer verifies) and
enforces ``seq`` against a durable high-water (a rollback is a seq below the last-seen one). The sovereign fold
needs none of this — it reads the append-only hash-chained spine, which the offense plane cannot fold at arm
time (sovereign-private at SIGIL_HOME; the two-env boundary forbids importing the governor; no filesystem
access in a two-host eval deploy — the reason this seam + the governor's publish mirror exist in the first
place). The seal gives the loose seam nearly the property the spine has: owner-signed + monotonic, drop/reorder-evident UNCONDITIONALLY and rollback-
refusing — with one honest gap vs the hash-chained spine: the rollback high-water floor is a local UNSIGNED
file, so a same-host attacker who can rewrite BOTH the seam AND the floor can still roll back; point
``VIGIL_EVAL_OFFENSE_HIGHWATER_DIR`` at offense-private storage + an out-of-band witness to close it (a deploy
requirement), exactly as the sovereign floor documents.

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
    "seal_core",
    "seal_signing_bytes",
    "build_seal",
]

SIGNAL = "governor.eval_offense_attestation"
_DOMAIN_KEY = "eval-offense-attestation"

_DIRNAME = "eval-offense-attestations"
_SCHEMA = "vigil-eval-offense-attestation-v1"
_SCHEMA_VERSION = 1

# -- tamper-evidence SEAL (M-11.1 red-pen residual 12/13 + rollback) --------------------------------
# The published seam is a LOOSE file whose record-LIST order and membership were unauthenticated: each
# record is individually owner-signed over ``_CORE`` (which carries neither list position nor membership),
# and the fold honours a ``revoke`` POSITIONALLY, so an attacker WITHOUT the owner key could resurrect a
# revoked-but-unexpired, genuinely owner-signed attestation by DROPPING the revoke record, REORDERING the
# list (revoke-before-attest), or ROLLING BACK to a pre-revoke published file. None of these forge a record;
# they only re-expose a previously-valid one — but that re-arms all three offense sites.
#
# The SOVEREIGN governor folds the APPEND-ONLY, hash-chained, HEAD-anchored spine, so it is immune to all
# three. The OFFENSE plane cannot fold that spine at arm time: it lives at SIGIL_HOME (sovereign-private),
# the two-env boundary forbids importing the sovereign governor to re-derive it, and in a two-host eval
# deploy the offense plane has no access to it — the whole reason this seam + the governor's ``_publish``
# mirror exist. So the SIGIL governor (the owner key) additionally mints an owner-signed SEAL over the
# WHOLE ordered record list PLUS a monotonic publish ``seq``, and the offense plane VERIFIES it here (public
# material only; FATAL-2): a DROP/REORDER makes the seal no longer verify over the records read, and a
# ROLLBACK is a ``seq`` below the last-seen durable high-water. This gives the published seam the SAME
# tamper-evidence the sovereign spine has (owner-signed, monotonic, rollback-refusing).
_SEAL_KIND = "vigil-eval-offense-attestation-seal-v1"
_SEAL_DOMAIN_KEY = "eval-offense-attestation-seal"
_SEAL_CORE = ("kind", "slug", "seq", "records")
# Durable offense-side high-water floor for the rollback guard. Lives OUTSIDE the record-list directory so a
# deployment can point it at offense-PRIVATE storage (``VIGIL_EVAL_OFFENSE_HIGHWATER_DIR``); it defaults to a
# sibling dir under the seam base. HONEST LIMIT (parity with the sovereign spine floor, apps/.../spine/floor.py
# §1.3): a same-host attacker who can rewrite BOTH the seam file AND this floor together defeats the LOCAL
# rollback check — closed only by an out-of-band witness. The floor unconditionally gives downgrade-refusing,
# crash-safe, last-writer-MONOTONIC advance, so no replay below a seq the offense plane has already verified is
# ever accepted.
_HIGHWATER_DIRNAME = ".eval-offense-highwater"
_HIGHWATER_ENV = "VIGIL_EVAL_OFFENSE_HIGHWATER_DIR"

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
# the owner-signed SEAL over the ordered record list (minted SIGIL-side; verified offense-side)
# ---------------------------------------------------------------------------------------------------


def _normalize_records(records: Iterable[dict]) -> list[dict]:
    """The canonical published record list — EXACTLY what :func:`write_eval_attestations` persists and
    :func:`read_eval_attestations` returns, so the seal signs/verifies over identical bytes on both planes."""
    return [dict(r) for r in records if isinstance(r, dict)]


def seal_core(slug: str, seq: Any, records: Iterable[dict]) -> dict:
    """The authenticated CORE of the publish SEAL: the seal kind, the slug, the monotonic publish ``seq``, and
    the WHOLE ordered record list. Signing the full ordered list (not a digest) binds membership AND order, so
    ANY drop/reorder changes the signed bytes; carrying ``seq`` binds the rollback high-water into the same
    signature. ``seq`` is coerced to int so sign and verify canonicalize byte-identically."""
    return {"kind": _SEAL_KIND, "slug": str(slug), "seq": int(seq), "records": _normalize_records(records)}


def seal_signing_bytes(slug: str, seq: Any, records: Iterable[dict]) -> bytes:
    """The exact bytes the OWNER signs for the publish seal: the fresh ``eval-offense-attestation-seal`` domain
    tag followed by the canonical JSON of the seal core. Domain separation means neither a record's owner sig
    nor its evaluator PoP (nor any other owner signature) can ever verify as a seal, and vice-versa."""
    core = seal_core(slug, seq, records)
    m = canonical_json({k: core.get(k) for k in _SEAL_CORE})
    cb = m if isinstance(m, (bytes, bytearray)) else str(m).encode("utf-8")
    return DOMAIN_TAGS[_SEAL_DOMAIN_KEY] + cb


def build_seal(slug: str, seq: Any, records: Iterable[dict], *, sign_fn, pubkey: str) -> dict:
    """Mint the published seal. ``sign_fn`` is a callable ``(bytes) -> str`` holding the OWNER private key
    (supplied by the SIGIL governor; this import-clean module never holds a key — FATAL-2). The signature is
    over the FULL core (slug + seq + the whole ordered record list, via :func:`seal_signing_bytes`), but the
    stored seal dict is COMPACT — ``{kind, slug, seq, sig, pubkey}`` — since the records already live once in
    the published object's ``records`` and the verifier recomputes the signing bytes over them."""
    return {
        "kind": _SEAL_KIND, "slug": str(slug), "seq": int(seq),
        "sig": sign_fn(seal_signing_bytes(slug, seq, records)), "pubkey": str(pubkey),
    }


def _verify_seal(seal: Any, slug: str, records: list[dict], pinned: frozenset) -> tuple[bool, int, str]:
    """``(ok, seq, reason)``. Fail-closed. A valid seal is a dict carrying an OWNER signature (by one of the
    pinned owner pubkeys) over the ``eval-offense-attestation-seal`` domain-tagged core for exactly this
    ``slug`` and exactly the ordered ``records`` read from the seam — so a DROPPED or REORDERED record makes
    the recomputed signing bytes no longer match the signature. Returns the monotonic ``seq`` for the rollback
    guard on success. NEVER raises (a hostile seam payload may carry any JSON type)."""
    if not isinstance(seal, dict):
        return False, 0, ("no owner-signed seal over the published list (unsealed) — fail-closed: an "
                          "unauthenticated record list could be silently dropped/reordered off-seam")
    if seal.get("kind") != _SEAL_KIND or seal.get("slug") != slug:
        return False, 0, "seal kind/slug mismatch (possible tamper)"
    pk, sig = seal.get("pubkey"), seal.get("sig")
    if not pk or not isinstance(pk, str) or pk not in pinned:
        return False, 0, "seal is not signed by a pinned owner key (forged/untrusted)"
    if not sig or not isinstance(sig, str):
        return False, 0, "seal signature missing/malformed"
    seq_raw = seal.get("seq")
    if not isinstance(seq_raw, int) or isinstance(seq_raw, bool) or seq_raw < 0:
        return False, 0, "seal seq is missing/invalid (possible tamper)"
    # Recompute the signing bytes over the slug + seq + the EXACT ordered records read from the seam. A
    # drop/reorder changes these bytes, so the owner signature (minted over the full ordered list) fails.
    try:
        ok = verify_one(pk, seal_signing_bytes(slug, seq_raw, records), sig)
    except (IntegrityError, TypeError):
        return False, 0, "seal signature does not verify (malformed, or list dropped/reordered off-seam)"
    if not ok:
        return False, 0, "seal signature does not verify (record list dropped/reordered off-seam)"
    return True, int(seq_raw), "seal verified over the ordered list"


# ---------------------------------------------------------------------------------------------------
# the durable offense-side rollback high-water (reuses the shared vigil_core anti-rollback floor)
# ---------------------------------------------------------------------------------------------------


def _highwater_path(base_dir: Any, slug: str) -> Optional[Path]:
    safe = _safe_component(slug)
    if not safe:
        return None
    d = os.environ.get(_HIGHWATER_ENV) or str(Path(base_dir) / _HIGHWATER_DIRNAME)
    return Path(d) / f"{safe}.json"  # ``safe`` already forbids separators / .. / control chars


def _check_and_advance_highwater(base_dir: Any, slug: str, seq: int) -> tuple[bool, str]:
    """Enforce (and advance) the durable monotonic rollback floor for ``slug``. Refuses a publish whose
    owner-signed ``seq`` is BELOW the highest the offense plane has already verified (a replay of an older
    pre-revoke published state). Fail-closed on a corrupt/tampered floor or an un-persistable advance — an
    arming precondition must never proceed when its anti-rollback state cannot be trusted or recorded."""
    from types import SimpleNamespace

    from vigil_core.highwater import (
        HighWaterDowngrade,
        HighWaterError,
        advance_highwater,
        check_highwater,
        load_highwater,
    )

    path = _highwater_path(base_dir, slug)
    if path is None:
        return False, "unsafe slug for the eval-offense high-water floor"
    try:
        prior = load_highwater(path)
    except HighWaterError as e:
        return False, f"eval-offense high-water floor is corrupt/tampered (fail-closed): {e}"
    head = SimpleNamespace(entry_count=int(seq), last_seq=int(seq))
    ok, msg = check_highwater(head, prior)
    if not ok:
        return False, f"ROLLBACK refused — replay of an older published state: {msg}"
    try:
        advance_highwater(path, head)
    except HighWaterDowngrade as e:
        # A concurrent advance already wrote a HIGHER floor — this publish is stale; refuse (fail-closed).
        return False, f"ROLLBACK refused — a higher high-water was recorded concurrently: {e}"
    except (OSError, HighWaterError) as e:
        return False, f"cannot persist the eval-offense high-water floor (fail-closed): {e}"
    return True, "within the durable high-water floor"


# ---------------------------------------------------------------------------------------------------
# the seam (public-safe signed record list + owner-signed seal)
# ---------------------------------------------------------------------------------------------------


def write_eval_attestations(base_dir: Any, slug: str, records: Iterable[dict],
                            *, seal: Optional[dict] = None) -> Path:
    """Write the public signed eval-offense-attestation record list for ``slug``, plus the owner-signed
    ``seal`` over that ordered list (minted SIGIL-side via :func:`build_seal`). Raises ValueError on an unsafe
    slug (never writes outside the dir). This module holds NO key: it merely TRANSPORTS the owner-signed seal
    (FATAL-2). A ``None`` seal writes an UNSEALED list — the offense verifier then refuses to arm (fail-closed),
    so a sealed publish is required to arm. The records + seal carry only public material (sigs + public keys +
    the owner-authored binding)."""
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe eval-offense-attestation slug: {slug!r}")
    path = _contained_child(eval_attestations_root(base_dir), f"{safe}.json")
    if path is None:
        raise ValueError(f"unsafe eval-offense-attestation slug (escapes dir): {slug!r}")
    obj: dict = {
        "schema_version": _SCHEMA_VERSION,
        "kind": _SCHEMA,
        "slug": safe,
        "records": _normalize_records(records),
    }
    if isinstance(seal, dict):
        obj["seal"] = dict(seal)
    _atomic_write_json(path, obj)
    return path


def _read_published(base_dir: Any, slug: str) -> Optional[dict]:
    """Read the published object (records + seal) for ``slug`` in ONE read, so the fold and the seal verify
    over the SAME bytes (no records/seal TOCTOU). ``None`` if absent, unsafe, or malformed (fail-closed)."""
    path = eval_attestation_path(base_dir, slug)
    if path is None or not path.is_file():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("kind") != _SCHEMA:
        return None
    return obj


def read_eval_attestations(base_dir: Any, slug: str) -> list[dict]:
    """Read the published signed record list for ``slug`` (public material only; the CALLER verifies against
    the pinned owner key). ``[]`` if absent, unsafe, or malformed (fail-closed — an unreadable list is 'no
    attestation', never a partial-trust default)."""
    obj = _read_published(base_dir, slug)
    if obj is None:
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


def _verify_pop(payload: dict, trusted_owner_pubkeys: frozenset) -> bool:
    """True iff the ADDITIVE evaluator PoP verifies, by ``payload['evaluator_pubkey']``, over the
    domain-tagged core AND the evaluator key is DISTINCT from every pinned owner key. Fail-closed.

    The distinctness guard is the M-11.1 two-party control (red-pen §11.4 BLOCK 1): an owner key can never
    stand in as the independent evaluator, so an ``evaluator_pubkey`` that is itself a pinned owner key is a
    SELF-attestation and is refused here regardless of whether its PoP signature is otherwise valid. This is
    the defense-in-depth layer; the caller (:func:`verify_live_offense_attested`) also refuses it explicitly
    with an auditable reason, so BOTH an edit to the caller AND an edit here would have to drop the guard for
    a self-attestation to arm. Comparison is exact-string membership, which IS canonical here: a verifiable
    Ed25519 pubkey has exactly ONE accepted encoding (``crypto._b64decode_exact`` refuses non-canonical pad
    bits and ``_reject_weak_public_key`` refuses a non-canonical ``y``), and the pins use the same strings."""
    pk = payload.get("evaluator_pubkey")
    sig = payload.get("evaluator_sig")
    if not pk or not isinstance(pk, str) or not sig or not isinstance(sig, str):
        return False
    if pk in trusted_owner_pubkeys:
        return False  # self-attestation: the "evaluator" is a pinned owner key, not an independent co-signer
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
    a missing/forged evaluator PoP, an evaluator that is NOT DISTINCT from the owner (``evaluator_pubkey`` in
    the pinned owner keys — a SELF-attestation; the M-11.1 two-party control refuses it, so the owner's OWN
    pinned key cannot stand in as the evaluator — organizational independence of the evaluator key is an
    enrollment/operational property, not cryptographically enforced — the evaluator key is held by the independent evaluator org)),
    a wrong environment / destructive echo, an
    expired, or a replayed (``issued_at`` below the high-water) record. The CHARTER is checked ONLY when a
    ``charter_hash`` is supplied; the three arm sites supply none, so the charter binding here is the MINT-TIME
    consent carried in the owner-signed core, NOT an arm-time guarantee — the separately owner-signed
    EngagementAuthority is the enforced-scope boundary at arm time. NEVER raises."""
    pinned = frozenset(p for p in (trusted_owner_pubkeys or ()) if isinstance(p, str) and p)
    if not pinned:
        return False, "no pinned owner key — cannot verify any eval-offense attestation (fail-closed)"
    obj = _read_published(base_dir, engagement_slug)
    if obj is None:
        return False, "default-unattested: no owner-signed eval-offense attestation on the seam"
    records = [r for r in obj.get("records", []) if isinstance(r, dict)]
    # TAMPER-EVIDENCE GATE (before the positional fold): the published record LIST must carry a valid
    # owner-signed seal over EXACTLY these ordered records — closing the red-pen 12/13 DROP/REORDER of the
    # revoke record — and its monotonic seq must not be below the durable high-water — closing a ROLLBACK
    # (replay of an older pre-revoke published state). Both refusals are fail-closed and happen BEFORE any
    # record is honoured, so a tampered list can never re-arm a revoked attestation. (The SOVEREIGN fold is
    # immune without this because it reads the append-only hash-chained spine, not this loose seam.)
    seal_ok, seq, seal_reason = _verify_seal(obj.get("seal"), engagement_slug, records, pinned)
    if not seal_ok:
        return False, f"publish seal invalid: {seal_reason}"
    hw_ok, hw_reason = _check_and_advance_highwater(base_dir, engagement_slug, seq)
    if not hw_ok:
        return False, hw_reason
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
            # M-11.1 TWO-PARTY DISTINCTNESS (red-pen §11.4 BLOCK 1): the evaluator identity MUST be DISTINCT
            # from the owner authority. `_verify_owner` just proved this record is a genuine owner-signed
            # attestation; if its `evaluator_pubkey` is itself a pinned owner key, the "co-sign" is the owner
            # signing both slots — the two-party control has collapsed to the owner key alone, letting a
            # unilateral or compromised owner arm weaponized LIVE offense with NO independent evaluator. Refuse
            # fail-closed with an auditable reason. Exact membership IS the canonical comparison the pins use
            # (a verifiable Ed25519 pubkey has exactly one accepted encoding — crypto._b64decode_exact refuses
            # non-canonical pad bits, _reject_weak_public_key refuses a non-canonical y), and it catches the
            # evaluator matching ANY pinned owner key, not only the one that signed this record.
            if payload.get("evaluator_pubkey") in pinned:
                return False, (
                    "evaluator must be DISTINCT from the owner — refusing self-attestation "
                    "(evaluator_pubkey is a pinned owner key; the M-11.1 two-party control requires an "
                    "independent evaluator co-sign, not the owner key alone)")
            if not _verify_pop(payload, pinned):
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
