"""fleet_monitor — a read-only cross-VM FLEET roll-up over the per-box telemetry projection (VIGIL WS3).

The per-box projection (:mod:`vigil_integration.telemetry`) folds ONE instance's signed spine into a
fact/lead/refusal/tool snapshot. This module folds a ROSTER of N such instances into ONE operator view:
per-instance (attested target + attestation summary + engagement/command counts + spine-event tallies)
plus a fleet-wide total.

It inherits telemetry's invariants exactly:

  * PURE + DETERMINISTIC — no wallclock, no RNG. Every collection it emits is sorted, so
    ``json.dumps(fold_roster(...), sort_keys=True)`` is byte-identical on re-run of the same roster.
  * ONE-WAY — it is a projection of what the oracle + gate already recorded. Nothing here is ever read
    back into authority: it mints no fact, derives no tier/grant, and is never an input to a gate. It is
    an operator VIEW only.
  * HONEST — an absent/unreadable snapshot contributes an empty, explicitly-flagged section, never a
    crash; an absent/unreadable/unchecked attestation is reported with its true status and is NEVER
    counted as verified or clean (no inconclusive->clean laundering in the roll-up). This view does not
    re-run signature verification (``vigil verify-ledger`` is the per-box cryptographic authority); a
    present ledger is reported ``present_unverified`` unless an upstream verdict is supplied.

Two capabilities, kept in one module because they share the roster vocabulary:

  * :func:`fold_roster` / :func:`fold_instance` — the read-only aggregator (``vigil fleet status``).
  * :func:`fan_out_kill` — the fleet KILL-SWITCH fan-out DRIVER (``vigil fleet kill``): per instance it
    invokes the per-box containment (``run_panic``) and applies an OWNER-SIGNED entitlement revocation.
    Destruction/kill stays owner-authorized — the m-of-n signing of the revocation is unchanged and the
    revoke leg is fail-closed without one. The driver only DRIVES the existing primitives.

Import-clean: stdlib + the framework-free attestation reader at module scope; the containment primitive
(``uiproxy``) and the entitlement issuer (``framework``) are lazy-imported inside the fan-out defaults, so
importing this module crosses no trust boundary.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .attestation.ledger import read_ledger

_SCHEMA = 1

# The attestation status vocabulary, widest-trust first. Each is DISTINCT in the roll-up: only ``verified``
# ever counts as verified; ``present_unverified`` / ``absent`` / ``error`` are their own buckets and are
# never collapsed into it (the anti-laundering invariant).
_ATT_STATUSES = ("verified", "failed", "present_unverified", "absent", "error")
_SNAP_STATUSES = ("ok", "absent", "error")


@dataclass(frozen=True)
class FleetInstance:
    """One roster entry. ``snapshot``/``attestation`` feed the read-only roll-up; ``base_dir``/
    ``revocation_path`` feed the kill fan-out. Every field after the id defaults, so a status-only or a
    kill-only roster is well-formed.

    ``snapshot``  — a telemetry snapshot as a dict, a path to a snapshot JSON file, or an opened
                    blackboard (anything exposing ``replay``, folded via ``telemetry.collect_snapshot``).
    ``attestation`` — a usage-attestation ledger path, a list of records, or an upstream summary dict
                    carrying an explicit verdict; ``None`` when the instance supplied none.
    ``base_dir``  — the engagement home the per-box ``run_panic`` contains (kill fan-out).
    ``revocation_path`` — where the owner-signed revocation is written on that instance (kill fan-out).
    """

    instance_id: str
    snapshot: Any = None
    attestation: Any = None
    base_dir: str = ""
    revocation_path: str = ""


# --------------------------------------------------------------------------------------------------
# Resolution — turn an (attacker-influenceable, possibly-absent) source into data, total.
# --------------------------------------------------------------------------------------------------


def _resolve_snapshot(src: Any) -> tuple[dict, str]:
    """Resolve a snapshot source into ``(snapshot_dict, status)`` where status is one of ``_SNAP_STATUSES``.
    Total: a missing file is ``absent``; an unreadable/malformed source is ``error``; neither is ever a
    crash and neither is ever reported as a zero-but-ok box."""
    if src is None:
        return {}, "absent"
    if isinstance(src, dict):
        return src, "ok"
    if isinstance(src, (str, os.PathLike)):
        p = Path(src)
        if not p.is_file():
            return {}, "absent"
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — unreadable / non-JSON snapshot ⇒ honest error section
            return {}, "error"
        return (obj, "ok") if isinstance(obj, dict) else ({}, "error")
    if hasattr(src, "replay"):
        try:
            from .telemetry import collect_snapshot
            return collect_snapshot(src), "ok"
        except Exception:  # noqa: BLE001 — a blackboard whose projection raises ⇒ honest error section
            return {}, "error"
    return {}, "error"


def _fold_snapshot_metrics(snap: dict) -> dict:
    """Project ONE resolved telemetry snapshot into the fleet per-instance counters. Reads only the
    ``totals`` roll-up + the ``engagements`` list that :func:`telemetry.collect_snapshot` already produced
    (never re-deriving them), so the fleet view can only reflect what the per-box projection recorded."""
    totals = snap.get("totals")
    totals = totals if isinstance(totals, dict) else {}
    engs = snap.get("engagements")
    eng_count = len(engs) if isinstance(engs, list) else 0
    by_kind = totals.get("by_kind")
    by_kind = by_kind if isinstance(by_kind, dict) else {}

    def _int(key: str) -> int:
        try:
            return int(totals.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    return {
        "engagements": eng_count,
        "commands": _int("tool_calls"),      # a "command" is a gated tool/action call on the spine
        "spine_events": _int("events"),
        "facts": _int("facts"),
        "leads": _int("leads"),
        "refusals": _int("refusals"),
        "findings": _int("findings"),
        "messages": _int("messages"),
        "by_kind": {str(k): int(v) for k, v in sorted(by_kind.items())},
        "last_event_id": _int("last_event_id"),
    }


def _blank_attestation(status: str) -> dict:
    """An attestation block carrying a status but NO data (absent/error). ``verified`` is ``None`` — the
    tristate's honest 'not verified in this view', never ``False`` (which would assert a failed check that
    did not run) and never clean."""
    return {"status": status, "present": False, "records": 0, "attested_targets": [],
            "operators": [], "head": None, "verified": None}


def _summarize_records(records: Iterable[Any]) -> dict:
    """Structural (NOT cryptographic) summary of attestation records: the distinct attested targets, the
    distinct operator signing fingerprints, the record count, and the chain head (the highest-``seq``
    record's ``record_hash``). ``verified`` is ``None`` — this view reports PRESENCE, not a signature
    verdict (``vigil verify-ledger`` is the per-box authority). Total over models or dict rows."""
    targets: set[str] = set()
    operators: set[str] = set()
    head: Optional[str] = None
    head_seq = -1
    count = 0
    for r in records:
        count += 1
        tgt = _rec_field(r, "target")
        if tgt:
            targets.add(tgt)
        fp = _operator_fp(r)
        if fp:
            operators.add(fp)
        try:
            seq = int(_rec_field(r, "seq") or 0)
        except (TypeError, ValueError):
            seq = 0
        rh = _rec_field(r, "record_hash")
        if rh and seq >= head_seq:
            head_seq = seq
            head = rh
    return {"status": "present_unverified", "present": True, "records": count,
            "attested_targets": sorted(targets), "operators": sorted(operators),
            "head": head, "verified": None}


def _rec_field(rec: Any, name: str) -> Any:
    """Read a field from a record that may be a pydantic model OR a dict, total."""
    if isinstance(rec, dict):
        return rec.get(name)
    return getattr(rec, name, None)


def _operator_fp(rec: Any) -> str:
    """The operator signing fingerprint of a record (model or dict), total; '' when absent."""
    op = _rec_field(rec, "operator")
    if op is None:
        return ""
    if isinstance(op, dict):
        return str(op.get("key_fingerprint") or "")
    return str(getattr(op, "key_fingerprint", "") or "")


def _normalize_summary(d: dict) -> dict:
    """Carry an UPSTREAM attestation summary (e.g. from a box that already ran ``vigil verify-ledger``)
    through faithfully. The verdict is honored ONLY when ``verified`` is an explicit bool; any other shape
    is reported ``present_unverified`` (``verified=None``) — this view never promotes an unchecked summary
    to verified/clean."""
    verified = d.get("verified")
    records = d.get("records")
    try:
        records = int(records or 0)
    except (TypeError, ValueError):
        records = 0
    targets = d.get("attested_targets")
    targets = sorted({str(t) for t in targets}) if isinstance(targets, (list, tuple, set)) else []
    operators = d.get("operators")
    operators = sorted({str(o) for o in operators}) if isinstance(operators, (list, tuple, set)) else []
    head = d.get("head")
    head = str(head) if isinstance(head, str) and head else None
    if verified is True:
        status = "verified"
    elif verified is False:
        status = "failed"
    else:
        status, verified = "present_unverified", None
    return {"status": status, "present": bool(records) or status in ("verified", "failed"),
            "records": records, "attested_targets": targets, "operators": operators,
            "head": head, "verified": verified}


def _resolve_attestation(src: Any) -> dict:
    """Resolve an attestation source into the canonical, honest attestation block. Total.

    A dict is an upstream summary (carried via :func:`_normalize_summary`). A path is a ledger file: an
    ABSENT file is ``absent`` (NOT verified — a missing always-on ledger is an evidence gap, mirroring
    ``_load_and_verify_ledger``'s fail-closed doctrine), a readable one is summarized structurally and
    reported ``present_unverified``. A list is treated as records. Anything else is ``error``."""
    if src is None:
        return _blank_attestation("absent")
    if isinstance(src, dict):
        return _normalize_summary(src)
    if isinstance(src, (str, os.PathLike)):
        if not Path(src).is_file():
            return _blank_attestation("absent")
        try:
            records = read_ledger(src)
        except Exception:  # noqa: BLE001 — unreadable ledger ⇒ honest error, never a crash, never clean
            return _blank_attestation("error")
        return _summarize_records(records)
    if isinstance(src, (list, tuple)):
        return _summarize_records(src)
    return _blank_attestation("error")


# --------------------------------------------------------------------------------------------------
# The read-only aggregator (vigil fleet status).
# --------------------------------------------------------------------------------------------------


def fold_instance(entry: FleetInstance) -> dict:
    """Fold ONE roster instance into its per-instance view: id, attested target(s), attestation summary,
    engagement/command counts, spine-event tallies, and the honest snapshot/attestation statuses. PURE +
    DETERMINISTIC (no wallclock/RNG)."""
    snap, snap_status = _resolve_snapshot(entry.snapshot)
    metrics = _fold_snapshot_metrics(snap)
    att = _resolve_attestation(entry.attestation)
    return {
        "instance_id": str(entry.instance_id),
        "snapshot_status": snap_status,
        "attested_targets": list(att["attested_targets"]),
        "attestation": att,
        **metrics,
    }


def _roll_up(instances: list) -> dict:
    """Fold the per-instance views into the fleet total. Numeric counters sum; ``by_kind`` merges;
    ``last_event_id`` is a max. Statuses are TALLIED into per-status buckets that always sum to the
    instance count — ``attestation.verified`` counts ONLY the ``verified`` status, so an absent/error/
    unchecked instance can never inflate the fleet 'verified' number (the anti-laundering invariant)."""
    num_keys = ("engagements", "commands", "spine_events", "facts", "leads", "refusals",
                "findings", "messages")
    totals: dict = {k: 0 for k in num_keys}
    by_kind: dict = {}
    last_event_id = 0
    att_by_status = {s: 0 for s in _ATT_STATUSES}
    snap_by_status = {s: 0 for s in _SNAP_STATUSES}
    att_records = 0
    att_present = 0
    att_targets: set[str] = set()
    for inst in instances:
        for k in num_keys:
            totals[k] += int(inst.get(k, 0) or 0)
        for kk, vv in (inst.get("by_kind") or {}).items():
            by_kind[kk] = by_kind.get(kk, 0) + int(vv)
        last_event_id = max(last_event_id, int(inst.get("last_event_id", 0) or 0))
        snap_by_status[_bucket(inst.get("snapshot_status"), _SNAP_STATUSES)] += 1
        att = inst.get("attestation") or {}
        att_by_status[_bucket(att.get("status"), _ATT_STATUSES)] += 1
        att_records += int(att.get("records", 0) or 0)
        att_present += 1 if att.get("present") else 0
        att_targets.update(str(t) for t in (att.get("attested_targets") or []))
    totals["by_kind"] = {str(k): int(v) for k, v in sorted(by_kind.items())}
    totals["last_event_id"] = last_event_id
    totals["instances"] = len(instances)
    totals["snapshots"] = {"by_status": snap_by_status}
    totals["attestation"] = {
        "by_status": att_by_status,
        "verified": att_by_status["verified"],   # ONLY the verified bucket — never absent/error/unchecked
        "present": att_present,
        "records": att_records,
        "attested_targets": sorted(att_targets),
    }
    return totals


def _bucket(value: Any, allowed: tuple) -> str:
    """Map a status string onto its bucket; an unknown/missing value falls to ``error`` (fail-safe —
    an unrecognized status is never silently dropped or counted as a good one)."""
    v = str(value or "")
    return v if v in allowed else "error"


def fold_roster(roster: Iterable[FleetInstance], *, generated_at: Optional[Any] = None) -> dict:
    """Fold a roster of instances into ONE fleet roll-up: ``{schema, instances[], totals}``. Instances are
    emitted in ``instance_id`` order so the output is DETERMINISTIC and byte-identical on re-run (an
    OPTIONAL ``generated_at`` is the only injectable stamp, defaulting to None — there is no wallclock).
    PURE + ONE-WAY: an operator view, never an input to a gate."""
    instances = [fold_instance(e) for e in roster]
    instances.sort(key=lambda d: d["instance_id"])
    snap: dict = {"schema": _SCHEMA, "instances": instances, "totals": _roll_up(instances)}
    if generated_at is not None:
        snap["generated_at"] = generated_at
    return snap


# --------------------------------------------------------------------------------------------------
# Roster loading (for the CLI) — a JSON file of instance descriptors.
# --------------------------------------------------------------------------------------------------


def instance_from_mapping(d: dict) -> FleetInstance:
    """Build a :class:`FleetInstance` from one roster-file entry. ``instance_id`` is required; the rest
    default. Unknown keys are ignored (forward-compatible). Raises ``ValueError`` on a missing/blank id."""
    iid = str(d.get("instance_id") or "").strip()
    if not iid:
        raise ValueError("every roster instance needs a non-empty 'instance_id'")
    return FleetInstance(
        instance_id=iid,
        snapshot=d.get("snapshot"),
        attestation=d.get("attestation"),
        base_dir=str(d.get("base_dir") or ""),
        revocation_path=str(d.get("revocation_path") or ""),
    )


def load_roster(path: str) -> list:
    """Load a roster JSON file — ``{"instances": [{instance_id, snapshot?, attestation?, base_dir?,
    revocation_path?}, ...]}`` (a bare list is also accepted) — into a list of :class:`FleetInstance`.
    Raises ``ValueError`` on a malformed file so the CLI fails LOUD rather than folding a silent empty."""
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"roster file not found: {path}")
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"roster file is not readable JSON ({path}): {e}")
    rows = obj.get("instances") if isinstance(obj, dict) else obj
    if not isinstance(rows, list):
        raise ValueError("roster must be a list of instances or an object with an 'instances' list")
    out = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"roster instance #{i} must be an object")
        out.append(instance_from_mapping(row))
    return out


# --------------------------------------------------------------------------------------------------
# The fleet KILL-SWITCH fan-out DRIVER (vigil fleet kill).
# --------------------------------------------------------------------------------------------------


def _default_panic(*, base_dir: str) -> int:
    """The per-box containment primitive: the framework-free process/unit HARD-STOP in ``uiproxy``.
    Lazy-imported so this module stays import-clean."""
    from .uiproxy import run_panic
    return run_panic(base_dir=base_dir)


def _default_revoke(signed_revocation: Any, revocation_path: str) -> Any:
    """Apply an ALREADY-SIGNED revocation on one instance — the entitlement-revoke primitive from the
    offense engine's issuer. Lazy-imported (framework) so the two-env boundary holds at module scope. This
    only DISTRIBUTES the owner-signed document; it never signs, so the m-of-n authorization is unchanged."""
    from framework.v2.entitlement.provision import write_revocation
    p = Path(revocation_path) if revocation_path else None
    return write_revocation(signed_revocation, p)


def _panic_leg(entry: FleetInstance, panic_fn: Callable) -> dict:
    base = str(getattr(entry, "base_dir", "") or "")
    try:
        rc = panic_fn(base_dir=base)
    except Exception as e:  # noqa: BLE001 — one instance's containment failure must not stop the fan-out
        return {"ok": False, "status": "error", "error": f"{type(e).__name__}: {e}"}
    rc_int = int(rc) if isinstance(rc, int) else (0 if rc is None else 1)
    return {"ok": rc_int == 0, "status": "contained" if rc_int == 0 else "incomplete", "rc": rc_int}


def _revoke_leg(entry: FleetInstance, signed_revocation: Any, revoke_fn: Callable) -> dict:
    if signed_revocation is None:
        # Fail-closed: the revoke leg REQUIRES an owner-signed revocation. Destruction/kill authorization
        # (m-of-n) is unchanged — this driver never fabricates it.
        return {"ok": False, "status": "refused",
                "reason": "no owner-signed revocation supplied; the revoke leg is fail-closed "
                          "(m-of-n owner authorization is required and unchanged)"}
    path = str(getattr(entry, "revocation_path", "") or "")
    try:
        applied = revoke_fn(signed_revocation, path)
    except Exception as e:  # noqa: BLE001 — one instance's revoke failure must not stop the fan-out
        return {"ok": False, "status": "error", "error": f"{type(e).__name__}: {e}"}
    return {"ok": True, "status": "applied",
            "path": str(applied) if applied is not None else (path or None)}


def fan_out_kill(
    roster: Iterable[FleetInstance],
    *,
    signed_revocation: Any = None,
    reason: str = "vigil fleet kill",
    panic_fn: Optional[Callable] = None,
    revoke_fn: Optional[Callable] = None,
) -> dict:
    """Drive the fleet kill-switch across a roster: for each instance invoke the per-box containment
    (``run_panic``) and apply the OWNER-SIGNED entitlement revocation.

    Owner-authorization is UNCHANGED: the revocation must already be signed to the trust root's m-of-n
    threshold (minted out of band by :func:`entitlement.provision.sign_revocation`, surfaced as the
    ``vigil sign-revocation`` ceremony). This driver only DISTRIBUTES it — passing ``signed_revocation=None``
    runs containment but fails the revoke leg closed per instance. Containment never blocks on the revoke
    outcome, and one instance's failure never stops the rest. ``panic_fn``/``revoke_fn`` are injectable for
    tests (defaults call the real primitives). DETERMINISTIC given the injected functions — no wallclock/RNG;
    instances are reported in ``instance_id`` order."""
    panic_fn = panic_fn if panic_fn is not None else _default_panic
    revoke_fn = revoke_fn if revoke_fn is not None else _default_revoke
    # Sort the entries by id BEFORE driving them, so the side-effect order (the actual containment calls)
    # is a stable id order independent of the roster's listing order — a deterministic fan-out.
    entries = sorted(roster, key=lambda e: str(getattr(e, "instance_id", "") or ""))
    results = []
    for entry in entries:
        results.append({
            "instance_id": str(getattr(entry, "instance_id", "") or ""),
            "panic": _panic_leg(entry, panic_fn),
            "revoke": _revoke_leg(entry, signed_revocation, revoke_fn),
        })
    totals = {
        "instances": len(results),
        "panic_ok": sum(1 for r in results if r["panic"].get("ok")),
        "revoke_ok": sum(1 for r in results if r["revoke"].get("ok")),
        "revoke_refused": sum(1 for r in results if r["revoke"].get("status") == "refused"),
        "revoke_error": sum(1 for r in results if r["revoke"].get("status") == "error"),
    }
    return {"schema": _SCHEMA, "reason": str(reason), "revocation_supplied": signed_revocation is not None,
            "instances": results, "totals": totals}
