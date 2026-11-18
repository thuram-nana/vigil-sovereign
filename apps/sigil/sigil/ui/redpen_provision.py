"""redpen_provision — the SOVEREIGN Fix-this / Retest provisioner actions + the dedicated action seam (R5).

The Code screen (C6) exposes two customer actions on a reproduced Red-Pen finding; this module is the sovereign
logic + admit gate behind them, kept OUT of ``provision.py`` so C6 owns that file (the ``Provisioner`` adds thin
wrappers that call :func:`redpen_fix_this` / :func:`redpen_retest`). Both actions are behind the master flag
``config.redpen_enabled()`` (default OFF ⇒ refuse) and gated on the NEW per-org ``manage_code`` permission
(decision O-4 — in ``founder`` + the owner-granted ``operator``, never ``org_admin``; a customer can still grant
only viewer/analyst/org_admin, so ``manage_code`` rides with the owner-authorized operator).

  * **Fix this** (:func:`redpen_fix_this`) — a sensitive action (it opens a PR on the customer's repository):
    flag → ``admit_customer(manage_code)`` → E3c step-up → ``reserve_redpen_review`` (which re-verifies the
    owner-signed CONNECTED-REPO RECORD — the authorization of record, O-3 — plus the wallet floor and the per-repo
    monthly limit, and METERS the codefix model spend with no estimate) → publish the fix marker. The offense fix
    worker re-checks every authority (the ``"pr"`` grant + the signed-spine fact), writes + re-reviews the patch,
    and opens a PR from a fix branch — VIGIL never merges.
  * **Retest** (:func:`redpen_retest`) — read-only re-run of a finding's proof (deterministic DAA re-scan, no
    model, no credits): flag → ``admit_customer(manage_code)`` → verify the connected-repo record → publish the
    retest marker. No step-up, no reservation (nothing is written and nothing is charged).

Sovereign→offense is the dedicated ``redpen-actions`` seam (a published JSON marker, the
``vigil_core.redpen_action`` wire contract), SEPARATE from the review credit-launch-lease seam so the review
trigger never mistakes a Fix/Retest for a review. The marker is an untrusted trigger; the offense plane re-checks
the authority where the action writes.

FATAL-2: SOVEREIGN-only (``assert_no_offense`` at import); imports only ``vigil_core`` + sovereign siblings +
stdlib. No ``framework`` import, no key crosses — a published marker is public-safe (slug, repo, finding ref).
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import (  # noqa: E402
    REDPEN_ACTION_SEAM_SUBDIR, REDPEN_FIX_ACTION, REDPEN_RETEST_ACTION, check_connected_repo, redpen_action_marker,
)
from vigil_core.seam_base import resolve_seam_base  # noqa: E402

from .provision import ProvisionDenied  # noqa: E402

_MANAGE_CODE = "manage_code"


# ---- the dedicated action seam (publish side) -------------------------------------------------------


def _action_seam_dir(base_dir: Any = None) -> Path:
    """The ``redpen-actions`` directory under the shared seam base (the ONE channel the offense trigger reads)."""
    return Path(resolve_seam_base(base_dir)) / REDPEN_ACTION_SEAM_SUBDIR


def _safe_marker_name(nonce: str, action: str) -> str:
    """A path-safe marker filename from (action, nonce) — single component, no separator/traversal. The nonce is
    a URL-safe token and the action a fixed word, so this is injective enough for the seam; the offense trigger
    recomputes the content-addressed exactly-once delivery id itself."""
    safe = "".join(c for c in f"{action}-{nonce}" if c.isalnum() or c in ("-", "_"))[:120]
    return (safe or "redpen") + ".json"


def publish_redpen_action(*, action: str, slug: str, repo: str, nonce: str, finding_ref: str = "",
                          finding_refs: "Optional[list[str]]" = None, commit: str = "",
                          base_dir: Any = None) -> str:
    """Publish ONE Red-Pen action marker to the dedicated seam and return its path. The payload is built + validated
    by the shared ``redpen_action_marker`` wire contract (fail-closed ``ValueError`` on a bad action / missing
    slug-repo-nonce / a fix with no finding_ref). Written atomically (tmp + ``os.replace``) so the offense trigger
    never reads a half-written marker. Public-safe fields only — no key, no secret, no currency amount."""
    marker = redpen_action_marker(action=action, slug=slug, repo=repo, nonce=nonce, finding_ref=finding_ref,
                                  finding_refs=finding_refs, commit=commit)
    seam = _action_seam_dir(base_dir)
    seam.mkdir(parents=True, exist_ok=True)
    dest = seam / _safe_marker_name(nonce, marker["redpen_action"])
    fd, tmp = tempfile.mkstemp(prefix=".redpen-action-", suffix=".tmp", dir=str(seam))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(marker, fh, separators=(",", ":"), sort_keys=True)
        os.replace(tmp, dest)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return str(dest)


# ---- the gated provisioner actions ------------------------------------------------------------------


def _require_flag() -> None:
    from .. import config
    if not config.redpen_enabled():
        raise ProvisionDenied("Red-Pen is off (VIGIL_REDPEN_ENABLED) — refusing (fail-closed)")


def _admit_manage_code(orgs: Any, requester: str, org_id: str) -> None:
    """The admit GATE both actions share — ``manage_code`` on the requester's SESSION org (decision O-4). A
    customer may grant only viewer/analyst/org_admin, so a tenant cannot self-grant ``manage_code``; it rides with
    the founder / owner-granted operator. Fail-closed ``ProvisionDenied`` when not admitted."""
    if not orgs.admit_customer(username=requester, org_id=org_id, permission=_MANAGE_CODE):
        raise ProvisionDenied("requester may not manage code review for this org (needs the manage_code permission)")


def redpen_fix_this(
    *,
    requester: str,
    org_id: str,
    repo: str,
    finding_ref: str,
    orgs: Any,
    launch_gate: Any,
    now: Any,
    require_stepup: Optional[Callable[[Any], None]] = None,
    mfa_at: Any = 0.0,
    nonce: Optional[str] = None,
    base_dir: Any = None,
) -> dict:
    """Trigger a "Fix this" for ONE reproduced finding on a CONNECTED repository. Order (each conjunct fail-closed):
    flag → ``admit_customer(manage_code)`` → E3c step-up (a fix opens a PR — sensitive) → ``reserve_redpen_review``
    (re-verifies the connected-repo record + wallet floor + monthly limit and METERS the model spend, no estimate)
    → publish the fix marker on the dedicated seam. Returns ``{ok, action, slug, repo, finding_ref, nonce,
    units_reserved, marker}``. Raises ``ProvisionDenied`` on any refused conjunct; nothing is published on a refusal.

    The offense fix worker re-checks the authority where it WRITES (the owner-signed ``"pr"`` grant + the signed-
    spine fact) and re-reviews the patch before the PR — so this trigger grants no bypass. ``require_stepup`` is the
    provisioner's E3c check (``Provisioner._require_stepup``); omitted ⇒ no step-up (direct/test caller)."""
    _require_flag()
    ref = str(finding_ref or "").strip()
    if not ref:
        raise ProvisionDenied("a fix must name exactly one finding to remediate (finding_ref is required)")
    _admit_manage_code(orgs, requester, org_id)
    if require_stepup is not None:
        require_stepup(mfa_at)   # E3c: AFTER admit (no-op unless enforcement is on)
    non = str(nonce) if nonce is not None else secrets.token_urlsafe(16)
    res = launch_gate.reserve_redpen_review(org_id=org_id, repo=repo, now=now, depth="quick", nonce=non)
    if not res.get("ok"):
        raise ProvisionDenied(str(res.get("error") or "the fix could not be reserved"))
    slug = str(res.get("slug") or "")
    repo_ref = str(res.get("repo") or repo)
    marker = publish_redpen_action(action=REDPEN_FIX_ACTION, slug=slug, repo=repo_ref, nonce=non,
                                   finding_ref=ref, base_dir=base_dir)
    return {"ok": True, "action": REDPEN_FIX_ACTION, "slug": slug, "repo": repo_ref, "finding_ref": ref,
            "nonce": non, "units_reserved": res.get("units_reserved"), "marker": marker}


def redpen_retest(
    *,
    requester: str,
    org_id: str,
    repo: str,
    orgs: Any,
    store: Any,
    now: Any,
    finding_ref: Optional[str] = None,
    finding_refs: "Optional[list[str]]" = None,
    nonce: Optional[str] = None,
    base_dir: Any = None,
    trusted_pubkey: Optional[str] = None,
    _connected: Optional[Callable[[str, str], Any]] = None,
) -> dict:
    """Trigger a "Retest" of one-or-more findings on a CONNECTED repository — a read-only re-run of each finding's
    proof (deterministic DAA re-scan; no model, no credits, no PR). Order (fail-closed): flag →
    ``admit_customer(manage_code)`` → verify the owner-signed CONNECTED-REPO RECORD (the authorization of record)
    → publish the retest marker. Returns ``{ok, action, slug, repo, finding_refs, nonce, marker}``. Raises
    ``ProvisionDenied`` on any refused conjunct; nothing is published on a refusal. No step-up and no reservation
    (nothing is written and nothing is charged).

    ``_connected(org_id, repo) -> record|None`` is the connected-repo lookup seam (default: the owner-pinned
    ``ConnectedRepoRegistry`` over ``store``, a pure read — the signing key is never touched)."""
    _require_flag()
    refs: "list[str]" = []
    seen: set[str] = set()
    for v in list(finding_refs or []) + ([finding_ref] if finding_ref else []):
        s = str(v or "").strip()
        if s and s not in seen:
            seen.add(s)
            refs.append(s)
    if not refs:
        raise ProvisionDenied("a retest must name at least one finding (finding_ref / finding_refs)")
    _admit_manage_code(orgs, requester, org_id)
    try:
        repo_ref = check_connected_repo(repo)
    except ValueError as e:
        raise ProvisionDenied(str(e)) from e

    connected = _connected
    if connected is None:
        from ..governor.connected_repos import ConnectedRepoRegistry
        reg = ConnectedRepoRegistry(store, owner_key=None, trusted_pubkey=trusted_pubkey)
        connected = reg.active
    record = connected(org_id, repo_ref)
    if record is None:
        raise ProvisionDenied(f"{repo_ref} is not connected (org {org_id}): connect the repository before a "
                              "retest — the owner-signed connection is the authorization")

    from .target_authorization import _customer_slug
    slug = _customer_slug(str(getattr(record, "org_id", org_id)), repo_ref)
    non = str(nonce) if nonce is not None else secrets.token_urlsafe(16)
    marker = publish_redpen_action(action=REDPEN_RETEST_ACTION, slug=slug, repo=repo_ref, nonce=non,
                                   finding_refs=refs, base_dir=base_dir)
    return {"ok": True, "action": REDPEN_RETEST_ACTION, "slug": slug, "repo": repo_ref, "finding_refs": refs,
            "nonce": non, "marker": marker}


__all__ = ["publish_redpen_action", "redpen_fix_this", "redpen_retest"]
