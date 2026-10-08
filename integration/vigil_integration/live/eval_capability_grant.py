"""eval_capability_grant — the import-clean seam + OFFENSE-side verifier for the M-11 EvalCapabilityGrant.

The SOVEREIGN governor (``apps/sigil/sigil/governor/eval_capability_grant.py``) owner-signs an
EvalCapabilityGrant — bound to ``(engagement_slug, target, allowed_gate_overrides, max_covered_actions)``,
anti-replay via a monotonic ``issued_anchor``, and COUNTER-SIGNED by a distinct owner-enrolled EVALUATOR with
a FRESH PoP over the GRANT core — appends it to the sovereign spine, and MIRRORS the public signed records
here. The OFFENSE plane reads them back and VERIFIES them against the pinned owner key before it will inject
ANY gate-veto-lifting ACK into ``authority.gate.authorize_action``.

This module is the TRANSPORT + the fail-closed VERIFIER; it holds NO private key and is the mirror image of
``eval_attestation`` (same atomic-write + path-safety + owner-SEAL + rollback-high-water discipline) plus a
fold that mirrors the sovereign ``EvalCapabilityGrant.state`` — honouring any revoke, rejecting a forged owner
sig, a missing/forged evaluator PoP (RE-VERIFIED FRESH over the grant core — FIX B), an evaluator that is NOT
DISTINCT from the owner (a self-grant), a WRONG target, a non-enum override token, or a replayed
(``issued_anchor`` below the high-water) record.

WHAT THE VERIFIER RETURNS (and what it does NOT): a :class:`GrantVerdict` naming WHICH of the three CLOSED-ENUM
gate vetoes this grant lifts (``witness_ok`` / ``blast_ok``) and the defensive ``containment_caps`` for the
M4.3 preview path. :func:`grant_overrides` turns a verified verdict into the gate ACKS ONLY — a
``witness_quorum_ack`` and a ``blast_radius_ack`` — and NEVER a ``witness_quorum_fn`` (the VETO itself is wired
unconditionally from the operator posture, INDEPENDENT of any grant; the grant only ever LIFTS an existing
veto, never creates one — adversary fix D). The never-liftable floors (egress floor, m-of-n destruction
quorum, GET-only write baseline) are not enum members and no ack this module returns can touch them.

BUDGET (FIX C2/F — honest ceiling): ``max_covered_actions`` is a signed, PoP-bound field so it is tamper-
evident and attributable, but a spine-anchored monotonic covered-action count surviving restart was NOT
feasible to wire durably this slice, and the resettable ``http_executor`` process counter is explicitly NOT
used (it would be a trivial reset-to-arm fail-open). So the budget-auto-void claim is DROPPED: the grant's
REAL durable ceiling is (a) owner REVOKE (published to this seam on offense-gate/engagement close too — FIX
C1), (b) the per-engagement KILL-SWITCH, (c) the signed ENGAGEMENT SCOPE, and (d) the covering
EvalOffenseAttestation's ``not_after`` (enforced independently at arm by ``verify_live_offense_attested``).
A caller that CAN vouch a durable, spine-anchored count may pass it as ``actions_covered``; when it does and
the count has reached ``max_covered_actions`` the grant is VOID. ``None`` (the default, and what the live
wiring passes) means no durable count is available ⇒ the budget leg does not void (the four durable
conditions above still bound it).

FIX E — override attribution: when a grant-derived ack LIFTS a gate, :func:`grant_overrides` appends a distinct
``authority.override_applied`` event (binding ``{action, grant_id, gate, witness set / blast verdict}``) to an
append-only offense-side audit ledger, so every EXERCISED override is attributable (full-capability stays fully
audited). The emit is best-effort and NEVER changes the ack verdict.

Public-safe: only PUBLIC keys + signatures + the (owner-authored) binding cross. No private key, ever.
FATAL-2 / import-clean: ``vigil_core`` + stdlib + relative imports only.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from vigil_core import IntegrityError, canonical_json, verify_one
from vigil_core.spine_domains import DOMAIN_TAGS

__all__ = [
    "SIGNAL",
    "ALLOWED_OVERRIDES",
    "GrantVerdict",
    "eval_capability_grants_root",
    "eval_capability_grant_path",
    "write_eval_capability_grants",
    "read_eval_capability_grants",
    "verify_eval_capability_grant",
    "grant_overrides",
    "seal_core",
    "seal_signing_bytes",
    "build_seal",
]

SIGNAL = "governor.eval_capability_grant"
_DOMAIN_KEY = "eval-capability-grant"
_SEAL_DOMAIN_KEY = "eval-capability-grant-seal"

ALLOWED_OVERRIDES = frozenset({"witness_quorum", "blast_veto", "containment_preview"})

_DIRNAME = "eval-capability-grants"
_SCHEMA = "vigil-eval-capability-grant-v1"
_SCHEMA_VERSION = 1
_SEAL_KIND = "vigil-eval-capability-grant-seal-v1"
_SEAL_CORE = ("kind", "slug", "seq", "records")
_HIGHWATER_DIRNAME = ".eval-grant-highwater"
_HIGHWATER_ENV = "VIGIL_EVAL_GRANT_HIGHWATER_DIR"
_OVERRIDE_LEDGER_DIRNAME = "eval-capability-grant-overrides"

# Byte-identical to the sovereign governor's ``_CORE``. The offense plane only ever RECONSTRUCTS this from the
# published payload to recompute the signing bytes; it never mints one.
_CORE = (
    "signal", "state", "engagement_slug", "target", "allowed_gate_overrides", "issued_anchor",
    "max_covered_actions", "evaluator_pubkey",
)


@dataclass(frozen=True)
class GrantVerdict:
    """Which CLOSED-ENUM gate vetoes a verified in-scope grant lifts. ``granted`` is the overall verdict;
    ``witness_ok`` / ``blast_ok`` say whether the grant lifts the 6c / 6b veto; ``containment_caps`` is the
    defensive containment allowlist pre-authorized for the M4.3 PREVIEW path only. ``grant_id`` + ``reason``
    carry attribution/diagnosis. A non-granted verdict lifts nothing (all flags False / caps empty)."""
    granted: bool
    reason: str
    witness_ok: bool = False
    blast_ok: bool = False
    containment_caps: "tuple[str, ...]" = ()
    grant_id: str = ""
    allowed_gate_overrides: "tuple[str, ...]" = ()
    max_covered_actions: int = 0


# ---------------------------------------------------------------------------------------------------
# paths + safe id component (mirrors eval_attestation)
# ---------------------------------------------------------------------------------------------------


def eval_capability_grants_root(base_dir: Any) -> Path:
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


def eval_capability_grant_path(base_dir: Any, slug: str) -> Optional[Path]:
    safe = _safe_component(slug)
    if not safe:
        return None
    return _contained_child(eval_capability_grants_root(base_dir), f"{safe}.json")


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


def _normalize_records(records: Iterable[dict]) -> list:
    return [dict(r) for r in records if isinstance(r, dict)]


def seal_core(slug: str, seq: Any, records: Iterable[dict]) -> dict:
    return {"kind": _SEAL_KIND, "slug": str(slug), "seq": int(seq), "records": _normalize_records(records)}


def seal_signing_bytes(slug: str, seq: Any, records: Iterable[dict]) -> bytes:
    core = seal_core(slug, seq, records)
    m = canonical_json({k: core.get(k) for k in _SEAL_CORE})
    cb = m if isinstance(m, (bytes, bytearray)) else str(m).encode("utf-8")
    return DOMAIN_TAGS[_SEAL_DOMAIN_KEY] + cb


def build_seal(slug: str, seq: Any, records: Iterable[dict], *, sign_fn, pubkey: str) -> dict:
    return {
        "kind": _SEAL_KIND, "slug": str(slug), "seq": int(seq),
        "sig": sign_fn(seal_signing_bytes(slug, seq, records)), "pubkey": str(pubkey),
    }


def _verify_seal(seal: Any, slug: str, records: list, pinned: frozenset) -> "tuple[bool, int, str]":
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
    return Path(d) / f"{safe}.json"


def _check_and_advance_highwater(base_dir: Any, slug: str, seq: int) -> "tuple[bool, str]":
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
        return False, "unsafe slug for the eval-capability-grant high-water floor"
    try:
        prior = load_highwater(path)
    except HighWaterError as e:
        return False, f"eval-capability-grant high-water floor is corrupt/tampered (fail-closed): {e}"
    head = SimpleNamespace(entry_count=int(seq), last_seq=int(seq))
    ok, msg = check_highwater(head, prior)
    if not ok:
        return False, f"ROLLBACK refused — replay of an older published state: {msg}"
    try:
        advance_highwater(path, head)
    except HighWaterDowngrade as e:
        return False, f"ROLLBACK refused — a higher high-water was recorded concurrently: {e}"
    except (OSError, HighWaterError) as e:
        return False, f"cannot persist the eval-capability-grant high-water floor (fail-closed): {e}"
    return True, "within the durable high-water floor"


# ---------------------------------------------------------------------------------------------------
# the seam (public-safe signed record list + owner-signed seal)
# ---------------------------------------------------------------------------------------------------


def write_eval_capability_grants(base_dir: Any, slug: str, records: Iterable[dict],
                                 *, seal: Optional[dict] = None) -> Path:
    safe = _safe_component(slug)
    if not safe:
        raise ValueError(f"unsafe eval-capability-grant slug: {slug!r}")
    path = _contained_child(eval_capability_grants_root(base_dir), f"{safe}.json")
    if path is None:
        raise ValueError(f"unsafe eval-capability-grant slug (escapes dir): {slug!r}")
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
    path = eval_capability_grant_path(base_dir, slug)
    if path is None or not path.is_file():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("kind") != _SCHEMA:
        return None
    return obj


def read_eval_capability_grants(base_dir: Any, slug: str) -> list:
    obj = _read_published(base_dir, slug)
    if obj is None:
        return []
    recs = obj.get("records")
    if not isinstance(recs, list):
        return []
    return [r for r in recs if isinstance(r, dict)]


# ---------------------------------------------------------------------------------------------------
# the fail-closed OFFENSE-side fold (mirrors sovereign EvalCapabilityGrant.state, pinned-key variant)
# ---------------------------------------------------------------------------------------------------


def _canon(core: dict) -> bytes:
    m = canonical_json(core)
    return m if isinstance(m, (bytes, bytearray)) else str(m).encode("utf-8")


def _pop_signing_bytes(core: dict) -> bytes:
    return DOMAIN_TAGS[_DOMAIN_KEY] + _canon({k: core.get(k) for k in _CORE})


def _as_issued_anchor(value) -> float:
    import math
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) else 0.0


def _normalize_overrides(overrides) -> list:
    if isinstance(overrides, str):
        items = [overrides]
    else:
        try:
            items = list(overrides or [])
        except TypeError:
            items = []
    return sorted({str(x) for x in items})


def _verify_owner(payload: dict, trusted_owner_pubkeys: frozenset) -> bool:
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
    """RE-VERIFY the FRESH evaluator PoP (FIX B) over the GRANT core — never a reused attestation sig. Also
    refuses an ``evaluator_pubkey`` that is itself a pinned owner key (a self-grant). Fail-closed."""
    pk = payload.get("evaluator_pubkey")
    sig = payload.get("evaluator_sig")
    if not pk or not isinstance(pk, str) or not sig or not isinstance(sig, str):
        return False
    if pk in trusted_owner_pubkeys:
        return False  # self-grant: the "evaluator" is a pinned owner key, not an independent co-signer
    core = {k: payload.get(k) for k in _CORE}
    try:
        return verify_one(pk, _pop_signing_bytes(core), sig)
    except (IntegrityError, TypeError):
        return False


def verify_eval_capability_grant(
    base_dir: Any, *, engagement_slug: str, target: str, trusted_owner_pubkeys: Iterable[str],
    actions_covered: Optional[int] = None, spine_head: Any = None,
) -> GrantVerdict:
    """The OFFENSE plane's fail-closed check that a verified EvalCapabilityGrant covers
    ``engagement_slug``/``target`` — reading the PUBLIC signed records from the seam and verifying them against
    the pinned owner key(s). Mirrors the sovereign fold: honour ANY revoke; reject a forged owner sig, a
    missing/forged FRESH evaluator PoP (FIX B), a self-grant, a WRONG target, a non-enum override token, or a
    replayed (``issued_anchor`` below the high-water) record. The seal gate + rollback high-water run BEFORE any
    record is honoured (a dropped/reordered/rolled-back list cannot re-arm a revoked grant). NEVER raises.

    ``actions_covered`` (FIX C2/F): an OPTIONAL durable, spine-anchored covered-action count the CALLER vouches
    for; when supplied and >= ``max_covered_actions`` the grant is VOID (budget exhausted). ``None`` ⇒ the
    budget leg does not void (the resettable process counter is deliberately NOT used; the durable ceiling is
    revoke + kill-switch + scope + the covering attestation's not_after). ``spine_head`` is accepted for API
    symmetry and reserved for a future durable-count wiring."""
    pinned = frozenset(p for p in (trusted_owner_pubkeys or ()) if isinstance(p, str) and p)
    if not pinned:
        return GrantVerdict(False, "no pinned owner key — cannot verify any eval-capability-grant (fail-closed)")
    obj = _read_published(base_dir, engagement_slug)
    if obj is None:
        return GrantVerdict(False, "default-ungranted: no owner-signed eval-capability-grant on the seam")
    records = [r for r in obj.get("records", []) if isinstance(r, dict)]
    seal_ok, seq, seal_reason = _verify_seal(obj.get("seal"), engagement_slug, records, pinned)
    if not seal_ok:
        return GrantVerdict(False, f"publish seal invalid: {seal_reason}")
    hw_ok, hw_reason = _check_and_advance_highwater(base_dir, engagement_slug, seq)
    if not hw_ok:
        return GrantVerdict(False, hw_reason)

    granted = False
    reason = "default-ungranted: no owner-signed eval-capability-grant on the seam"
    grant_id = ""
    overrides: tuple = ()
    mca = 0
    max_issued = float("-inf")
    for payload in records:
        if not isinstance(payload, dict) or payload.get("signal") != SIGNAL:
            continue
        if payload.get("engagement_slug") != engagement_slug:
            continue
        st = payload.get("state")
        if st == "revoked":
            granted, reason, grant_id, overrides, mca = False, "revoked by a governance event", "", (), 0
        elif st == "granted":
            if payload.get("target") != target:
                continue  # grant bound to a DIFFERENT target — no effect on this action
            if not _verify_owner(payload, pinned):
                continue
            if payload.get("evaluator_pubkey") in pinned:
                # self-grant: the evaluator is a pinned owner key — the two-party control has collapsed. Refuse
                # fail-closed (defense-in-depth with the sovereign mint refusal).
                return GrantVerdict(
                    False,
                    "evaluator must be DISTINCT from the owner — refusing self-grant (evaluator_pubkey is a "
                    "pinned owner key; the two-party control requires an independent evaluator co-sign)")
            if not _verify_pop(payload, pinned):
                continue
            toks = _normalize_overrides(payload.get("allowed_gate_overrides"))
            if not toks or any(t not in ALLOWED_OVERRIDES for t in toks):
                continue  # empty / non-enum override token — a record written outside the ceremony; no effect
            issued = _as_issued_anchor(payload.get("issued_anchor"))
            if issued <= max_issued:
                continue  # REPLAY / stale re-append
            max_issued = issued
            try:
                mca = int(payload.get("max_covered_actions") or 0)
            except (TypeError, ValueError):
                mca = 0
            granted = True
            reason = "owner-signed + evaluator-PoP granted"
            overrides = tuple(toks)
            # The grant id is the (stable) record evaluator sig head — enough to attribute an exercised
            # override to this exact signed grant without carrying a private value.
            grant_id = str(payload.get("sig") or "")[:16]

    if not granted:
        return GrantVerdict(False, reason)

    # BUDGET leg (FIX C2/F) — enforced ONLY against a caller-vouched durable count; never the process counter.
    if isinstance(actions_covered, int) and not isinstance(actions_covered, bool) and mca > 0:
        if actions_covered >= mca:
            return GrantVerdict(
                False,
                f"eval-capability-grant budget exhausted ({actions_covered} >= {mca} covered actions)",
                grant_id=grant_id, allowed_gate_overrides=overrides, max_covered_actions=mca)

    return GrantVerdict(
        granted=True, reason=reason,
        witness_ok=("witness_quorum" in overrides),
        blast_ok=("blast_veto" in overrides),
        containment_caps=(_containment_caps() if "containment_preview" in overrides else ()),
        grant_id=grant_id, allowed_gate_overrides=overrides, max_covered_actions=mca,
    )


def _containment_caps() -> "tuple[str, ...]":
    """The DEFENSIVE containment allowlist a ``containment_preview`` grant pre-authorizes for the M4.3
    PREVIEW / V2-prepare path ONLY. The real actuator stays DECLINED/frontier — this is a named allowlist a
    preview can read, never an authorization to actuate. Resolved lazily from the engine's defensive-kinds
    registry when present (offense plane), else the fixed vocabulary (keeps this module import-clean)."""
    try:
        from framework.v2.agent_body.defensive import defensive_kinds  # type: ignore
        caps = tuple(sorted(defensive_kinds()))
        if caps:
            return caps
    except Exception:  # noqa: BLE001 — offense engine not present / any import issue → the fixed vocabulary
        pass
    return ("block_ip", "isolate_endpoint", "quarantine_host", "revoke_session")


# ---------------------------------------------------------------------------------------------------
# override attribution ledger (FIX E) + the gate ACKS (never a witness_quorum_fn — fix D)
# ---------------------------------------------------------------------------------------------------


def _override_ledger_path(base_dir: Any, slug: str) -> Optional[Path]:
    safe = _safe_component(slug)
    if not safe:
        return None
    return Path(base_dir) / _OVERRIDE_LEDGER_DIRNAME / f"{safe}.jsonl"


def _emit_override_applied(base_dir: Any, slug: str, event: dict) -> None:
    """FIX E: append a distinct ``authority.override_applied`` event to an append-only offense-side audit
    ledger, binding {action, grant_id, gate, witness set / blast verdict}. Best-effort (an unwritable ledger
    never changes the ack verdict), append-only + fsync'd so an exercised override survives restart and is
    attributable. Keyless + stdlib-only (FATAL-2)."""
    try:
        path = _override_ledger_path(base_dir, slug)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        line = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        finally:
            pass
    except OSError:
        pass


def grant_overrides(
    verdict: GrantVerdict, *, base_dir: Any = "", engagement_slug: str = "",
):
    """Turn a verified :class:`GrantVerdict` into the gate ACKS ONLY: ``(witness_quorum_ack,
    blast_radius_ack, containment_caps)``. It NEVER returns a ``witness_quorum_fn`` — the VETO itself is wired
    unconditionally from the operator posture, INDEPENDENT of the grant (adversary fix D); the grant only ever
    LIFTS an already-present veto.

    Each ack is a callable matching the gate's ack signature ``(request, verdict) -> bool``. It returns True
    (lifting the veto for THIS action) iff the grant permits that specific override; when it lifts, it emits a
    distinct ``authority.override_applied`` attribution event (FIX E). A non-granted verdict yields acks that
    always return False (nothing is lifted) and empty caps — so an absent/expired/revoked grant is fail-closed
    exactly as passing no acks."""
    g = verdict if isinstance(verdict, GrantVerdict) else GrantVerdict(False, "no verdict")
    grant_id = g.grant_id

    def _target_of(request) -> str:
        return str(getattr(request, "target", "") or "")

    def witness_quorum_ack(request, wq) -> bool:
        if not (g.granted and g.witness_ok):
            return False
        _emit_override_applied(base_dir, engagement_slug, {
            "event": "authority.override_applied",
            "gate": "6c", "grant_id": grant_id,
            "action_target": _target_of(request),
            "action_kind": str(getattr(request, "action_kind", "") or ""),
            "bug_class": str(getattr(request, "bug_class", "") or ""),
            "witness_kinds_present": list(getattr(wq, "kinds", ()) or ()),
            "required_n": int(getattr(wq, "required", 0) or 0),
        })
        return True

    def blast_radius_ack(request, bv) -> bool:
        if not (g.granted and g.blast_ok):
            return False
        try:
            incremental = float(getattr(bv, "incremental_blast", 0.0) or 0.0)
        except (TypeError, ValueError):
            incremental = 0.0
        _emit_override_applied(base_dir, engagement_slug, {
            "event": "authority.override_applied",
            "gate": "6b", "grant_id": grant_id,
            "action_target": _target_of(request),
            "action_kind": str(getattr(request, "action_kind", "") or ""),
            "incremental_blast": incremental,
            "newly_reachable_jewels": list(getattr(bv, "newly_reachable_jewels", ()) or ()),
        })
        return True

    caps = tuple(g.containment_caps) if g.granted else ()
    return witness_quorum_ack, blast_radius_ack, caps


def owner_pubkeys_of(trust_root: Any) -> frozenset:
    """The pinned owner pubkeys carried by a governance ``trust_root`` (mirrors eval_attestation)."""
    try:
        return frozenset(
            a.public_key_b64 for a in getattr(trust_root, "authorizers", [])
            if getattr(a, "public_key_b64", None)
        )
    except Exception:  # noqa: BLE001
        return frozenset()
