"""Partial-results PREVIEW: the ONE server-side projection that locks finding detail for a trial org.

A trial-preview org (one that received the `trial-preview:<org>` grant and has not bought credits) sees every
finding's existence, title, estimated severity, location and confidence; exactly ONE finding is shown in full.
The rest omit their proof and fix. Everything here runs on the SERVER before a response leaves the provisioner —
the edge relays only `{org_id, ip}` and the SPA only renders — so the lock is never a client-side filter.

WHO IS LOCKED (`preview_locked`): `VIGIL_TRIAL_PREVIEW_ENABLED` AND the org holds the `trial-preview:<org>`
grant AND the org is not unlocked (`governor.report_unlock`). Legacy-trial, paying, postpaid and pre-existing
orgs are never locked. Turning the flag off unlocks every trial org (the emergency rollback).

THE ONE REVEAL: the earliest-landed finding (lowest spine seq) over the org's EVER-proven slug set (the proof
fold's signed issued map, so an expired or revoked-then-re-proven host cannot mint a second reveal). It is pinned
by append-only order: a severity-table edit, confidence, outcome order or a failed run can never move it.

DERIVED DISPLAY FIELDS. Real certificates carry no title / severity / summary today, so they are derived here,
with no engine import: severity is the certificate's own value when present (basis `certificate`), else the
conservative MAXIMUM for the class from the sovereign table below (basis `estimated`); an unknown class shows
`unrated` and ranks above medium. A derived severity is never presented as signed. Locked rows keep the label
"oracle-confirmed — proof locked": the FACT record is never altered.

FATAL-2: sovereign-side, stdlib only, `assert_no_offense` at import.
"""
from __future__ import annotations

import copy
from typing import Any, Iterable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

LOCKED_LABEL = "oracle-confirmed — proof locked"
# Keys a locked row OMITS entirely (never set to null): the fix + offline re-verify command, the report claims,
# the oracle context digest, the artifact manifest and the summary.
LOCKED_OMIT = ("how_to_verify", "report_claims", "oracle_context_digest", "artifact_manifest", "summary")
# Keys a locked row may carry (an allowlist: anything else is dropped).
_LOCKED_KEEP = ("engagement_slug", "finding_ref", "bug_class", "surface", "confidence")

SEVERITIES = ("critical", "high", "unrated", "medium", "low", "info")   # rank order, most severe first

# The sovereign bug_class -> CONSERVATIVE MAXIMUM severity table (under-rating is the dangerous direction). An
# estimate for display only; the owner ratifies it. Classes not listed show `unrated` (never dropped).
CLASS_SEVERITY: "dict[str, str]" = {
    "rce": "critical", "command_injection": "critical", "sqli": "critical", "error_based_sqli": "critical",
    "boolean_sqli": "critical", "time_based_sqli": "critical", "ssti": "critical", "use_after_free": "critical",
    "imds_credential_capture": "critical", "saml_structural_forgery": "critical", "request_smuggling": "critical",
    "ssrf": "high", "idor": "high", "path_traversal": "high", "xss": "high", "stored_xss": "high",
    "dom_xss": "high", "cross_site_websocket_hijacking": "high", "nosql_injection_attempt": "high",
    "sqli_attempt": "high", "privilege_path": "high", "business_logic": "high", "request_race": "high",
    "system_prompt_disclosure": "high", "postmessage_exploited": "high", "exposure": "high",
    "cloud_misconfiguration": "high", "identity_misconfiguration": "high", "k8s_misconfiguration": "high",
    "k8s_workload_misconfiguration": "high", "mesh_misconfiguration": "high", "static_taint": "high",
    "crash": "high",
    "open_redirect": "medium", "graphql_introspection": "medium", "weak_tls": "medium",
    "weak_crypto_artifact": "medium", "static_broken_crypto": "medium",
    "service_reachable": "low", "probe": "info",
}

# Generic, class-level guidance shown for an estimated critical / high finding, so a non-paying customer can
# still act on a serious one. Never the finding's own fix or re-verify command.
_GUIDANCE = {
    "critical": "A critical class of weakness was confirmed on this host. Restrict exposure of the affected "
                "surface now and review its input handling and access controls; the full proof and fix are in "
                "the unlocked report.",
    "high": "A high-impact class of weakness was confirmed on this host. Review the affected surface's input "
            "handling and authorization checks; the full proof and fix are in the unlocked report.",
}


def preview_locked(store, org_id: str, *, wallet=None, unlocks=None) -> bool:
    """True iff `org_id`'s finding detail is locked: the preview flag is on, the org received the preview trial,
    and it is not unlocked. Fail-safe in the open direction for everyone else (never locks a non-trial org)."""
    from .. import config
    if not config.trial_preview_enabled() or not isinstance(org_id, str) or not org_id:
        return False
    if wallet is None:
        from ..governor.wallet import WalletRegistry
        wallet = WalletRegistry(store, owner_key=None)
    if not wallet.has_grant_entry(org_id, f"trial-preview:{org_id}"):
        return False
    if unlocks is None:
        from ..governor.report_unlock import ReportUnlockRegistry
        unlocks = ReportUnlockRegistry(store, owner_key=None)
    if unlocks.is_unlocked(org_id):
        return False
    # An org the owner moved to a postpaid (enterprise) account is a paying customer, whatever it started as:
    # never locked, never held to the trial launch rules.
    from ..governor.postpaid import PostpaidRegistry
    return not PostpaidRegistry(store, owner_key=None).is_postpaid(org_id)


def derived_severity(row: dict) -> "tuple[str, str]":
    """(severity, basis): the certificate's own severity when it carries a known one, else the class maximum
    (estimated), else `unrated`."""
    own = str(row.get("severity") or "").strip().lower()
    if own in SEVERITIES and own != "unrated":
        return own, "certificate"
    sev = CLASS_SEVERITY.get(str(row.get("bug_class") or ""))
    return (sev, "estimated") if sev else ("unrated", "estimated")


def derived_title(row: dict) -> str:
    t = row.get("title")
    if isinstance(t, str) and t.strip():
        return t
    return f"{row.get('bug_class') or 'finding'} at {row.get('surface') or 'unknown surface'}"


def reveal_seq(rows: Iterable["tuple[int, dict]"], ever_slugs: "set[str]") -> Optional[int]:
    """The spine seq of the ONE revealed finding: the lowest seq among findings whose slug is in the org's
    ever-proven slug set. The reveal is pinned to that ONE record — never to its finding_ref, which is not unique
    (several findings can share a check id or class). None when there is none (a run with no findings consumes
    nothing)."""
    best: Optional[int] = None
    for seq, row in rows:
        if row.get("engagement_slug") not in ever_slugs:
            continue
        if best is None or seq < best:
            best = seq
    return best


def lock_row(row: dict, host: Optional[str]) -> dict:
    """The locked projection of one finding row (a NEW dict; the input is not modified)."""
    out = {k: copy.deepcopy(row[k]) for k in _LOCKED_KEEP if k in row}
    sev, basis = derived_severity(row)
    out.update(host=host, title=derived_title(row), severity=sev, severity_basis=basis, locked=True,
               label=LOCKED_LABEL)
    if basis == "estimated" and sev in _GUIDANCE:
        out["class_guidance"] = _GUIDANCE[sev]
    return out


def apply_preview(rows: "list[tuple[int, dict]]", *, revealed: Optional[int],
                  host_of: "dict[str, str]") -> "list[tuple[int, dict]]":
    """Project EVERY row (before pagination): the revealed finding stays full (a deep copy, plus host/title/
    severity), every other row is locked. Returns new (seq, row) pairs; the inputs are never modified."""
    out = []
    for seq, row in rows:
        host = host_of.get(str(row.get("engagement_slug")))
        if revealed is not None and seq == revealed:
            full = copy.deepcopy(row)
            sev, basis = derived_severity(row)
            full.update(host=host, title=derived_title(row), severity=sev, severity_basis=basis, locked=False)
            out.append((seq, full))
        else:
            out.append((seq, lock_row(row, host)))
    return out


def severity_counts(rows: Iterable[dict]) -> "dict[str, int]":
    counts = {s: 0 for s in SEVERITIES}
    for row in rows:
        counts[derived_severity(row)[0]] += 1
    return counts


def preview_block(*, can_buy: bool) -> "dict[str, Any]":
    return {"locked": True, "can_buy": bool(can_buy), "copy_key": "trial_preview"}
