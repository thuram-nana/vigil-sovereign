"""The unified customer CONNECT surface — one screen to connect a site, a repo or a cloud account, and a
single-asset ownership POLL that resumes a half-finished proof (consumer PR-C).

A PURE, READ-ONLY tenant-scoped projection that composes the THREE already-built connect substrates behind one
Search-Console-smooth read, plus a focused single-host poll the connect screen uses to auto-select a method,
resume where the customer left off, and know when to auto-re-check:

  * SITES — ``governor.asset_ownership`` (DNS-TXT / well-known / meta-tag ownership proof).
  * REPOS — ``governor.connected_repos`` (owner-signed connected GitHub repositories).
  * CLOUD — ``governor.cloud_connect`` (owner-signed READ-ONLY cloud-account grants).

TENANT-SCOPED BY CONSTRUCTION (the IDOR defense, identical to ``ui.assessments``): every read is resolved
SERVER-SIDE from ``org_id`` (the hop-bound session principal, never a client slug/host) against folds keyed per
(org_id, …). The repo ``slug`` is the one-way ``_customer_slug(org_id, repo)`` hash, so one tenant's connect
view can never surface another tenant's asset.

CONNECTING RECORDS AN OWNER-VERIFIED ASSET; IT NEVER AUTHORIZES OFFENSE. This module only READS connection
state; even the write paths it fronts (ownership verify, cloud verify) mint only owner-verified RECORDS, never
an ``EngagementAuthority`` and never a posture scan. A live run still rides the unchanged
``customer_prod_execution_enabled()`` owner gate + host-ownership proof + owner-signed authority chain, and a
cloud grant is read-only. A FACT is minted ONLY by the oracle — never by a connect action or this read.

FATAL-2: ``assert_no_offense()`` at import; governor + ui-local reads only, no ``engine/crucible`` import.
"""
from __future__ import annotations

from typing import Any

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor import asset_ownership as _own  # noqa: E402
from ..governor.cloud_connect import CloudConnectRegistry  # noqa: E402
from ..governor.connected_repos import ConnectedRepoRegistry  # noqa: E402

# The Search-Console default method the connect screen pre-selects when the customer has not already proven the
# host another way — a meta tag in the homepage <head> is the lowest-friction of the three.
_DEFAULT_METHOD = _own.METHOD_META_TAG

# The reason text the poll returns beside the auto-re-check hint, per status. Stated plainly for the customer.
_RECHECK_REASON = {
    "verified": "verified — no re-check needed",
    "expired": "the ownership proof lapsed — re-publish the token and re-check",
    "pending": "awaiting the published token — re-check now",
    "none": "no challenge yet — start by issuing one",
    "invalid": "not a verifiable host",
}


def _methods_block(host: str, token: str) -> dict[str, Any]:
    """The placement instructions for ALL three ownership methods, derived from (host, token). The connect screen
    shows these so the customer can pick/resume any method; ``customer_ownership_poll`` auto-selects one."""
    marker = _own.expected_marker(token)
    return {
        _own.METHOD_META_TAG: {"meta_tag": _own.meta_tag(token)},
        _own.METHOD_DNS_TXT: {"dns_name": _own.dns_txt_name(host), "dns_value": marker},
        _own.METHOD_WELL_KNOWN: {"well_known_url": _own.well_known_url(host), "well_known_body": marker},
    }


def customer_ownership_poll(store, org_id: str, host: str, *, now: float) -> dict[str, Any]:
    """The single-host ownership POLL behind the connect screen — RESUME a half-finished proof, AUTO-SELECT a
    method, and know when to AUTO-RE-CHECK. A pure, tenant-scoped read (``org_id`` is the session principal,
    resolved server-side; the host is validated + normalised exactly as a record is, so a value for another
    tenant/host is never surfaced). Never raises; a malformed host returns ``status="invalid"``.

    Returns ``{org_id, host, status, selected_method, recheck{due,reason}, …}`` where ``status`` is:
      * ``verified`` — an active, owner-signed proof UNEXPIRED at ``now`` (carries ``method`` / ``verified_at`` /
        ``expires_at``); ``recheck.due`` is False;
      * ``expired``  — an active proof whose owner-signed expiry has passed (carries the same fields); re-check due;
      * ``pending``  — an outstanding challenge, not yet verified (carries ``methods`` placement + ``marker`` so
        the customer resumes exactly where they left off); re-check due;
      * ``none``     — no challenge and no proof (the UI offers "start"); not due;
      * ``invalid``  — the host is not a verifiable DNS name (carries ``detail``); not due.

    ``selected_method`` auto-selects: the method that already proved the host when there is a proof (so re-proving
    stays on the same method), else the Search-Console default (meta-tag). Present for every non-invalid status so
    the UI's method picker is pre-filled even on ``none``."""
    reg = _own.AssetOwnershipRegistry(store, owner_key=None)
    try:
        h = _own._check_host(host)
    except ValueError as e:
        return {"org_id": org_id, "host": str(host or ""), "status": "invalid", "detail": str(e),
                "recheck": {"due": False, "reason": _RECHECK_REASON["invalid"]}}
    n = float(now)
    proof = reg.proof(org_id, h)
    challenge = reg.challenge(org_id, h)
    if proof is not None and n < proof.expires_at:
        status = "verified"
    elif proof is not None:
        status = "expired"
    elif challenge is not None:
        status = "pending"
    else:
        status = "none"
    out: dict[str, Any] = {"org_id": org_id, "host": h, "status": status}
    if proof is not None:
        out["method"] = proof.method
        out["verified_at"] = float(proof.verified_at)
        out["expires_at"] = float(proof.expires_at)
    # AUTO-SELECT: stay on the proving method when there is one, else the Search-Console default (meta-tag).
    out["selected_method"] = proof.method if proof is not None else _DEFAULT_METHOD
    # RESUME: when a challenge is outstanding surface every method's placement + the marker the customer publishes.
    if challenge is not None and challenge.token:
        out["methods"] = _methods_block(h, challenge.token)
        out["marker"] = _own.expected_marker(challenge.token)
    # AUTO-RE-CHECK: due iff the proof is not currently good (awaiting a token, or lapsed) — the UI polls verify.
    out["recheck"] = {"due": status in ("pending", "expired"), "reason": _RECHECK_REASON[status]}
    return out


def _repos_block(store, org_id: str) -> list[dict[str, Any]]:
    """The org's connected repositories, tenant-scoped, projected through a stable allowlist (never a raw record):
    ``{repo, slug, block_threshold, monthly_limit_credits}``. ``slug`` is the one-way ``_customer_slug`` hash, so
    a repo of another tenant can never appear here. Reads only this org's rows (``repos_of_org``)."""
    from .target_authorization import _customer_slug
    out: list[dict[str, Any]] = []
    for doc in ConnectedRepoRegistry(store, owner_key=None).repos_of_org(org_id):
        out.append({"repo": doc.repo, "slug": _customer_slug(org_id, doc.repo),
                    "block_threshold": doc.block_threshold.value,
                    "monthly_limit_credits": int(doc.monthly_limit_credits)})
    return out


def connect_overview(store, org_id: str, *, now: float) -> dict[str, Any]:
    """The ONE-screen connect read for ONE org: its connected SITES, REPOS and CLOUD accounts, each tenant-scoped
    to ``org_id`` (the session principal, server-side) and projected through a stable allowlist. PURE read — no
    lock, no mint, no owner key. Composes the three substrates' own tenant-scoped reads:

      * ``sites``  — ``AssetOwnershipRegistry.assets_overview`` (verified / expired / pending per host, with the
        current challenge's placement when one is outstanding);
      * ``repos``  — this org's connected repositories (:func:`_repos_block`);
      * ``cloud``  — ``CloudConnectRegistry.cloud_overview`` (connected / expired per read-only cloud account).

    Assumes the caller already authorized ``org_id`` for the read (the provisioner's ``_customer_read`` gate). The
    counts are the org's true totals; another tenant's assets are structurally absent from every leg. No estimate,
    no cost, no engine/model name ever appears — connecting records an asset, it never prices or tests one."""
    n = float(now)
    sites = _own.AssetOwnershipRegistry(store, owner_key=None).assets_overview(org_id, now=n)
    repos = _repos_block(store, org_id)
    cloud = CloudConnectRegistry(store, owner_key=None).cloud_overview(org_id, now=n)
    return {"org_id": org_id, "sites": sites, "repos": repos, "cloud": cloud}
