"""Customer issue-tracker SYNC — open a tracker issue for an oracle-minted FACT finding, auto-close on a proven fix.

READ-ONLY CONSUMER of the finding spine (PR-D, Area 3 — SHIPPED OFF). Two invariants carry the whole module:

  * FACT-ONLY. An issue is opened ONLY for a ``kind="finding"`` record the ORACLE minted — a row carrying a signed
    ``engagement_slug`` AND a ``finding_ref`` (the marks of the ``ui.assessments`` finding projection).
    :func:`_require_fact_finding` is the hard gate: :func:`open_issue` calls it and RAISES :class:`NotAFactFinding`
    on anything else, so a free-form NOTICE, a LEAD, or a hand-built dict can NEVER become a tracker issue. A
    notification is never a FACT source, and FACT-only here is the symmetric rule for the issue direction.

  * AUTO-CLOSE ON CLEARED. When a finding's NEWEST retest verdict is ``fixed`` (the WARDEN-written ``finding_retest``
    record — the oracle-backed cleared signal, surfaced as ``row["retest"]["status"]`` by
    ``ui.assessments.overlay_retests``, NOT a notice), :func:`plan_issue_actions` emits a CLOSE for exactly that
    finding's open issue. Keyed on the full :func:`finding_identity` ``(engagement_slug, finding_ref,
    oracle_context_digest)``, so a verdict closes the issue of the finding whose proof was re-run — never a sibling
    sharing its ``finding_ref``.

The issue CONTENT is built by ``notify_channels.render_finding_notice`` (the SAME inert-field allowlist + the
no-model-identifier backstop), so a customer's tracker never shows an internal field or which model was used.

FATAL-2: ``assert_no_offense()`` at import; stdlib + sovereign siblings only; never imports engine/crucible or
``ui`` (keeps the governor layer below ui — the identity helper is defined locally, mirroring
``ui.assessments.finding_identity``). This module NEVER writes the finding spine.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, Sequence

from ..reuse import assert_no_offense

assert_no_offense()

from .. import config  # noqa: E402
from . import notify_channels as _nc  # noqa: E402  (the shared allowlist/no-model-id renderer + the SSRF guard)

TRACKER_GITHUB = "github"
TRACKER_JIRA = "jira"
TRACKER_LINEAR = "linear"
_TRACKERS = frozenset({TRACKER_GITHUB, TRACKER_JIRA, TRACKER_LINEAR})

STATE_OPEN = "open"
STATE_CLOSED = "closed"


class NotAFactFinding(ValueError):
    """Raised when something that is NOT an oracle-minted FACT finding is handed to the issue path (a notice, a
    LEAD, a malformed row). The hard enforcement of FACT-ONLY: a notification can never become an issue."""


def finding_identity(row: dict[str, Any]) -> "tuple[str, str, str]":
    """``(engagement_slug, finding_ref, oracle_context_digest)`` — the identity a tracker issue is keyed by.
    Mirrors ``ui.assessments.finding_identity`` (a stable 3-tuple contract; defined locally to keep governor below
    ui). ``finding_ref`` alone is not unique, so the retained-proof digest is part of the identity: a retest closes
    exactly the finding whose proof was re-run, never a sibling sharing its ref."""
    return (str(row.get("engagement_slug") or ""), str(row.get("finding_ref") or ""),
            str(row.get("oracle_context_digest") or ""))


def _require_fact_finding(row: Any) -> "tuple[str, str, str]":
    """Return the identity of ``row`` iff it is an oracle-minted FACT finding projection (a dict with a non-empty
    str ``engagement_slug`` AND ``finding_ref``), else raise :class:`NotAFactFinding`. This is the FACT-ONLY gate:
    a notice / LEAD / free-form dict is refused CLOSED before any issue is opened."""
    if not isinstance(row, dict):
        raise NotAFactFinding("issue sync requires a finding record, not " + type(row).__name__)
    slug, ref, digest = finding_identity(row)
    if not slug or not ref:
        raise NotAFactFinding(
            "refusing a non-FACT input to issue sync (no signed engagement_slug + finding_ref) — a notice/LEAD can "
            "never open an issue; only an oracle-minted finding may")
    return (slug, ref, digest)


def _is_cleared(row: dict[str, Any]) -> bool:
    """True iff this finding's newest retest verdict is ``fixed`` (the oracle-backed cleared signal overlaid by
    ``ui.assessments.overlay_retests``). A missing/other verdict is NOT cleared (fail-closed: never auto-close an
    issue without a proven fix)."""
    retest = row.get("retest")
    return isinstance(retest, dict) and retest.get("status") == "fixed"


# ---- the issue link + the plan -------------------------------------------------------------------------------
@dataclass(frozen=True)
class IssueLink:
    """The record that ONE finding has ONE tracker issue. ``state`` ∈ {open, closed}. Keyed (in the registry) by
    the finding's :func:`finding_identity`, per (org) — tenant-isolated exactly as the finding read is."""

    identity: "tuple[str, str, str]"
    tracker: str
    issue_key: str
    state: str = STATE_OPEN

    def as_json(self) -> dict[str, Any]:
        return {"identity": list(self.identity), "tracker": self.tracker, "issue_key": self.issue_key,
                "state": self.state}

    @staticmethod
    def from_json(obj: Any) -> "Optional[IssueLink]":
        if not isinstance(obj, dict):
            return None
        ident = obj.get("identity")
        tracker, key, state = obj.get("tracker"), obj.get("issue_key"), obj.get("state")
        if (not isinstance(ident, list) or len(ident) != 3 or not all(isinstance(x, str) for x in ident)
                or not isinstance(tracker, str) or not isinstance(key, str)):
            return None
        return IssueLink(identity=(ident[0], ident[1], ident[2]), tracker=tracker, issue_key=key,
                         state=state if state in (STATE_OPEN, STATE_CLOSED) else STATE_OPEN)


@dataclass(frozen=True)
class IssueAction:
    """A planned sync action: OPEN a new issue for ``finding``, or CLOSE the ``link``'ed issue of a cleared one."""

    op: str                                   # "open" | "close"
    identity: "tuple[str, str, str]"
    finding: Optional[dict[str, Any]] = None  # present for an open
    link: Optional[IssueLink] = None          # present for a close


def plan_issue_actions(findings: Sequence[dict[str, Any]], *,
                       existing: "dict[tuple[str, str, str], IssueLink]") -> list[IssueAction]:
    """PURE. From a tenant's FACT-finding page + its existing issue links, the sync actions:

      * a finding with NO link and NOT cleared        → OPEN (a live finding gets an issue)
      * a finding with an OPEN link and now CLEARED    → CLOSE (auto-close on the proven fix)
      * everything else                                → nothing (already-open live, already-closed, or a finding
                                                         cleared before it ever got an issue — nothing to open/close)

    A row that is not a FACT finding is SKIPPED here (defence in depth — the input is already a finding projection;
    :func:`open_issue` additionally RAISES on a non-FACT, so the hard gate is on the write path). Deterministic
    order (the input order), so a drain's output is stable."""
    actions: list[IssueAction] = []
    for row in findings:
        try:
            identity = _require_fact_finding(row)
        except NotAFactFinding:
            continue
        link = existing.get(identity)
        cleared = _is_cleared(row)
        if link is not None and link.state == STATE_OPEN:
            if cleared:
                actions.append(IssueAction(op="close", identity=identity, link=link))
        elif link is None and not cleared:
            actions.append(IssueAction(op="open", identity=identity, finding=dict(row)))
    return actions


# ---- the issue CONTENT (allowlisted, no model id — reuses the notice renderer) --------------------------------
@dataclass(frozen=True)
class IssueContent:
    title: str
    body: str
    labels: list[str] = field(default_factory=list)


def build_issue_content(finding: dict[str, Any]) -> IssueContent:
    """The tracker issue title/body/labels for ONE FACT finding, built from ``notify_channels.render_finding_notice``
    (the SAME inert-field allowlist + the no-model-identifier backstop). PURE. Refuses a non-FACT via the shared
    FACT gate first, so content is only ever built for a real finding."""
    _require_fact_finding(finding)
    notice = _nc.render_finding_notice(finding)
    sev = notice.fields.get("severity", "")
    labels = ["vigil-finding"]
    if sev:
        labels.append(f"severity:{sev}")
    bug = notice.fields.get("bug_class")
    if bug:
        labels.append(f"class:{bug}")
    return IssueContent(title=notice.subject, body=notice.body, labels=labels)


# ---- the tracker client seam ---------------------------------------------------------------------------------
class IssueTrackerClient(Protocol):
    """A per-tenant issue-tracker binding. ``create`` opens an issue and returns its tracker key (e.g. a GitHub
    issue number as a string); ``close`` closes one and returns True iff accepted. An implementation MUST route its
    egress through the host allowlist (``config.NOTIFY_ISSUE_API_ALLOWLIST``) — see :class:`GithubIssueClient`."""

    tracker: str

    def create(self, *, title: str, body: str, labels: Sequence[str]) -> str: ...

    def close(self, issue_key: str) -> bool: ...


class GithubIssueClient:
    """A GitHub issues client over the HARDENED, allowlisted ``governor.github_app_egress`` (https + exact-host
    ``api.github.com`` pin + redirect-blocking). ``repo`` is ``owner/name``; ``bearer`` is a short-lived
    installation token the caller provisions (this client never mints one). ``transport`` is the egress's injectable
    test seam (a FAKE GitHub, no network) — it still passes through the egress guard."""

    tracker = TRACKER_GITHUB
    _REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")

    def __init__(self, repo: str, bearer: str, *, transport: Any = None) -> None:
        if not isinstance(repo, str) or not self._REPO_RE.match(repo) or ".." in repo:
            raise ValueError("GithubIssueClient requires a well-formed 'owner/name' repo")
        if not isinstance(bearer, str) or not bearer:
            raise ValueError("GithubIssueClient requires an installation bearer token")
        self.repo = repo
        self._bearer = bearer
        self._transport = transport

    def create(self, *, title: str, body: str, labels: Sequence[str]) -> str:
        from . import github_app_egress as egress
        payload: dict[str, Any] = {"title": title, "body": body, "labels": list(labels)}
        res = egress.request("POST", f"/repos/{self.repo}/issues", bearer=self._bearer, json_body=payload,
                             transport=self._transport)
        number = res.get("number") if isinstance(res, dict) else None
        if number is None:
            raise _nc.OutboundRefused("GitHub issue create returned no number")
        return str(number)

    def close(self, issue_key: str) -> bool:
        from . import github_app_egress as egress
        key = str(issue_key).strip()
        if not key.isdigit():
            raise ValueError("GitHub issue key must be the numeric issue number")
        egress.request("PATCH", f"/repos/{self.repo}/issues/{key}", bearer=self._bearer,
                       json_body={"state": "closed"}, transport=self._transport)
        return True


# ---- the write path (FLAG-GATED, FACT-gated) -----------------------------------------------------------------
def open_issue(client: IssueTrackerClient, finding: dict[str, Any]) -> IssueLink:
    """Open a tracker issue for ONE FACT finding and return its :class:`IssueLink`. FLAG-GATED (refuses when notify
    is off) and FACT-GATED (:func:`_require_fact_finding` RAISES on a notice/LEAD before any egress) — the hard
    guarantee that only an oracle-minted finding ever becomes an issue."""
    if not config.customer_notify_enabled():
        raise _nc.OutboundRefused("refusing to open an issue: customer notify is disabled (VIGIL_CUSTOMER_NOTIFY off)")
    identity = _require_fact_finding(finding)      # RAISES NotAFactFinding on a non-FACT
    content = build_issue_content(finding)
    issue_key = client.create(title=content.title, body=content.body, labels=content.labels)
    return IssueLink(identity=identity, tracker=client.tracker, issue_key=str(issue_key), state=STATE_OPEN)


def close_issue(client: IssueTrackerClient, link: IssueLink) -> IssueLink:
    """Close the tracker issue of a cleared finding and return the updated (closed) :class:`IssueLink`. FLAG-GATED.
    Idempotent: an already-closed link is returned unchanged without an egress."""
    if not config.customer_notify_enabled():
        raise _nc.OutboundRefused("refusing to close an issue: customer notify is disabled (VIGIL_CUSTOMER_NOTIFY off)")
    if link.state == STATE_CLOSED:
        return link
    client.close(link.issue_key)
    return IssueLink(identity=link.identity, tracker=link.tracker, issue_key=link.issue_key, state=STATE_CLOSED)


# ---- the per-tenant issue-link registry (file-backed, atomic; tenant-isolated) -------------------------------
def _org_marker_name(org_id: str) -> str:
    from ..reuse import sha256_hex
    return "issues_" + sha256_hex(("issue-links\x00" + str(org_id)).encode("utf-8"))[:32]


class IssueLinkRegistry:
    """Per-(org) ``finding_identity -> IssueLink`` store on the filesystem (one 0600 JSON marker per org, named by a
    one-way hash of the org id). Tenant-isolated by construction: a read/write scopes to ONE org's own marker, so
    one tenant's issue links are structurally unreachable by another. FLAG-GATED writes. Mirrors
    ``notify_channels.NotifyChannelRegistry``."""

    def __init__(self, path: "str | Any") -> None:
        from pathlib import Path
        self.dir = Path(path)

    def _marker(self, org_id: str) -> Any:
        return self.dir / _org_marker_name(org_id)

    def links_of(self, org_id: str) -> "dict[tuple[str, str, str], IssueLink]":
        """This org's issue links (its own marker only) — never another tenant's. Fail-soft: a missing/corrupt
        marker reads as no links."""
        if not isinstance(org_id, str) or not org_id:
            return {}
        try:
            raw = self._marker(org_id).read_text(encoding="utf-8")
            obj = json.loads(raw)
        except (OSError, ValueError):
            return {}
        items = obj.get("links") if isinstance(obj, dict) else None
        out: "dict[tuple[str, str, str], IssueLink]" = {}
        for entry in items or []:
            link = IssueLink.from_json(entry)
            if link is not None:
                out[link.identity] = link
        return out

    def put(self, org_id: str, link: IssueLink) -> None:
        """Upsert ONE issue link for ``org_id`` (keyed by its finding identity). FLAG-GATED. Atomic rewrite of the
        org's marker (0600, O_EXCL tmp + rename)."""
        import os
        import secrets
        if not config.customer_notify_enabled():
            raise _nc.OutboundRefused("refusing an issue-link write: customer notify is disabled")
        if not isinstance(org_id, str) or not org_id:
            raise _nc.OutboundRefused("refusing an issue-link write with an empty org id")
        links = self.links_of(org_id)
        links[link.identity] = link
        rec = {"org_marker": _org_marker_name(org_id), "links": [v.as_json() for v in links.values()]}
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = self._marker(org_id)
        tmp = marker.with_name(f"{marker.name}.{secrets.token_hex(8)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp), flags, 0o600)
        try:
            os.write(fd, json.dumps(rec).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, marker)
