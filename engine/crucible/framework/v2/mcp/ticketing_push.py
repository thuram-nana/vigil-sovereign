"""
mcp.ticketing_push — the OPERATOR-ONLY egress adapter that pushes an oracle-verified finding OUT to a
ticketing system (this slice: GitHub Issues), pinned to the never-liftable egress FLOOR.

This is the PUSH-direction sibling of :mod:`mcp.evidence_transport` / :mod:`mcp.evidence_sensor`. Where the
evidence connector CONSUMES (pulls a LEAD in), this NOTIFIES (pushes a finding out). It reuses the SAME
egress primitive — :class:`agents.egress_guard.SovereignHttpxTransport` (name allowlist always on + the
never-liftable Tier-1a L3/L4 ADDRESS floor + anti-rebinding pin), constructed EXACTLY as
:class:`mcp.evidence_transport.FloorPinnedHttpTransport` constructs it — so every outbound byte clears the
floor, no redirect is ever followed, and the operator's bearer token is sent only as an ``Authorization``
header, never in the URL / a log / a repr / an error.

DOCTRINE — a pushed finding is a ONE-WAY NOTIFICATION, NEVER round-tripped back in as a FACT:
  * OUTBOUND-ONLY. ``push`` POSTs one issue and returns a :class:`PushReceipt` — a notification RECORD
    (issue number + URL + the ``(tenant_id, slug)`` scope key). The ticketing system's response is parsed
    ONLY for that receipt; it is NEVER turned into an :class:`intel.models.Observation`, a Finding, or a
    ``GroundingToken.oracle``. This module imports NONE of the intel / grounding / finding-confirm
    machinery, and exposes NO ``normalize`` / ``confirm`` / ``reverify`` / ``promote`` / ``run`` seam, so a
    sensor pipeline cannot pick its output up as a lead either. (Only a CRUCIBLE oracle mints a FACT; this
    is a pure disclosure sink — a record, never a fact.)
  * OFF BY DEFAULT. Nothing is pushed unless the operator has provisioned a ticketing target
    (``targets/<slug>/ticketing-targets.json`` — see :mod:`mcp.ticketing_config`). ``push_finding`` refuses
    (fail-closed) when no matching target is provisioned.
  * ORACLE-VERIFIED ONLY. ``push`` refuses a finding whose ``verified_by_oracle`` is not True — an LLM-
    advisory lead is never disclosed to an external tracker as if it were confirmed.
  * SECRET OFF-SPINE. The API token is resolved OUT-OF-BAND from the env-var NAMED by the target's
    ``auth_env`` at request time (never from the config file, never stored on the spine, never logged). A
    missing token is refused at request time (we never push unauthenticated).
  * (tenant_id, slug) KEYING. The receipt and the best-effort audit record are keyed by the active tenant
    (``org``) + the engagement slug — the shared enterprise-wave contract.

Stdlib + framework/vigil_core only (``httpx`` is the shared egress dependency the guard itself uses); no
sigil import, no integration-layer import. ``build_engagement_allowlist`` / ``egress_guard`` imports are
module-level because this module lives ON the offense plane (same as ``evidence_sensor``); it never imports
``sigil.*``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from ..agents.egress_guard import (
    EgressAllowlist,
    SovereignHttpxTransport,
    build_engagement_allowlist,
    collector_scope_conflicts,
)
from ..common import paths
from ..common.errors import SovereigntyViolation
from .protocol import MAX_MESSAGE_BYTES
from .ticketing_config import TicketingTarget, find_ticketing_target

__all__ = [
    "TicketingPushError",
    "TicketFinding",
    "PushReceipt",
    "GithubIssuesPusher",
    "render_issue_body",
    "push_finding",
]

# A stable, recognisable User-Agent (the operator wants to grep their tracker/logs for our traffic — this
# is a notification to their OWN system, correlatable by construction). GitHub's API also REQUIRES a UA.
_USER_AGENT = "VIGIL-ticketing/1.0 (authorized owner-test; one-way notification)"
_GITHUB_API_VERSION = "2022-11-28"
_MAX_TITLE = 256  # GitHub issue title hard cap


class TicketingPushError(Exception):
    """A structured, fail-closed failure of a ticketing push: not provisioned, missing/invalid token, a
    non-oracle-verified finding, a non-2xx HTTP status (a redirect included), an oversized request/response,
    or malformed JSON. NEVER carries a secret (token / userinfo) in its message."""


# =============================================================================
# The OUT-bound notification payload (decoupled from the pydantic FindingPayload)
# =============================================================================


@dataclass(frozen=True)
class TicketFinding:
    """The minimal, framework-decoupled view of a finding this connector pushes OUT. Built from a
    ``FindingPayload``-like object OR a plain mapping via :meth:`from_finding` (duck-typed), so the adapter
    never hard-depends on the heavy pydantic model. ``verified_by_oracle`` gates the push — only an oracle-
    confirmed finding is disclosed to an external tracker."""

    finding_slug: str
    title: str
    severity: str = ""
    bug_class: str = ""
    surface: str = ""
    summary: str = ""
    impact: str = ""
    cvss_vector: str = ""
    verified_by_oracle: bool = False
    oracle_kind: str | None = None

    @staticmethod
    def _get(obj: Any, key: str, default: Any = "") -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @classmethod
    def from_finding(cls, obj: Any) -> "TicketFinding":
        """Duck-type a finding (a pydantic ``FindingPayload``, a dataclass, or a dict) into a
        :class:`TicketFinding`. Missing fields default empty; ``verified_by_oracle`` defaults False
        (fail-closed — an unknown finding is treated as unverified and will be refused by ``push``)."""
        g = cls._get
        slug = str(g(obj, "finding_slug", "") or g(obj, "slug", "") or "unknown")
        return cls(
            finding_slug=slug,
            title=str(g(obj, "title", "") or ""),
            severity=str(g(obj, "severity", "") or ""),
            bug_class=str(g(obj, "bug_class", "") or ""),
            surface=str(g(obj, "surface", "") or ""),
            summary=str(g(obj, "summary", "") or ""),
            impact=str(g(obj, "impact", "") or ""),
            cvss_vector=str(g(obj, "cvss_vector", "") or ""),
            verified_by_oracle=bool(g(obj, "verified_by_oracle", False)),
            oracle_kind=(str(g(obj, "oracle_kind", None)) if g(obj, "oracle_kind", None) else None),
        )


@dataclass(frozen=True)
class PushReceipt:
    """The record of ONE outbound notification. This is a RECORD, never a FACT: it carries only notification
    metadata + the ``(tenant_id, slug)`` scope key, no belief / credibility / grounding / oracle field, and
    ``is_fact`` is permanently False. There is no code path that ingests it back into the world-model."""

    ok: bool
    target_id: str
    tenant_id: str | None
    slug: str
    finding_slug: str
    issue_number: int | None = None
    issue_url: str | None = None
    direction: str = "outbound"
    is_fact: bool = False  # a notification is NEVER a fact — pinned, inert, structural

    def audit_record(self) -> dict:
        """A NON-SECRET, ``(tenant_id, slug)``-keyed audit record for this push (for an append-only log /
        operator UI). Carries no token and no FACT semantics — it is a disclosure receipt."""
        return {
            "kind": "ticketing_push_notification",
            "direction": "outbound",
            "is_fact": False,
            "tenant_id": self.tenant_id,
            "slug": self.slug,
            "target_id": self.target_id,
            "finding_slug": self.finding_slug,
            "ok": self.ok,
            "issue_number": self.issue_number,
            "issue_url": self.issue_url,
        }


# =============================================================================
# Issue body rendering (pure, deterministic, secret-free)
# =============================================================================


def render_issue_body(finding: TicketFinding, *, tenant_id: str | None, slug: str) -> str:
    """Render a finding into a deterministic GitHub-Markdown issue body. Pure + secret-free: it echoes only
    the finding's own non-secret fields plus the ``(tenant_id, slug)`` provenance line, and states plainly
    that this is a one-way notification (not a round-tripped FACT)."""
    lines = [
        f"**Severity:** {finding.severity or 'n/a'}",
        f"**Bug class:** {finding.bug_class or 'n/a'}",
        f"**Surface:** {finding.surface or 'n/a'}",
    ]
    if finding.cvss_vector:
        lines.append(f"**CVSS:** {finding.cvss_vector}")
    lines.append(f"**Oracle-verified:** {finding.verified_by_oracle}"
                 + (f" ({finding.oracle_kind})" if finding.oracle_kind else ""))
    lines.append("")
    lines.append("## Summary")
    lines.append(finding.summary or "_(no summary provided)_")
    lines.append("")
    lines.append("## Impact")
    lines.append(finding.impact or "_(no impact statement provided)_")
    lines.append("")
    lines.append("---")
    lines.append(f"Filed by the VIGIL ticketing-OUT connector for finding `{finding.finding_slug}` "
                 f"(engagement tenant=`{tenant_id or 'default'}`, slug=`{slug}`). "
                 f"This is a ONE-WAY notification — it is never round-tripped back in as a FACT.")
    return "\n".join(lines)


# =============================================================================
# The GitHub Issues push adapter (floor-pinned, token off-spine)
# =============================================================================


def _bracket_host(host: str) -> str:
    """Bracket a bare IPv6 literal for a URL authority (``::1`` -> ``[::1]``); leave IPv4 / hostnames as-is."""
    return f"[{host}]" if (":" in host and not host.startswith("[")) else host


class GithubIssuesPusher:
    """Push a finding OUT to a GitHub-Issues-compatible API, through the sovereign egress guard + the
    never-liftable L3/L4 egress floor. Constructed exactly like
    :class:`mcp.evidence_transport.FloorPinnedHttpTransport` (same ``SovereignHttpxTransport`` wiring), so
    the name allowlist is ALWAYS enforced and every connect resolves-once / validates-all / dials-only-
    validated. Fail-closed everywhere; the bearer token is header-only and never leaks."""

    def __init__(
        self,
        target: TicketingTarget,
        allowlist: EgressAllowlist,
        *,
        token: str | None,
        slug: str = "",
        timeout_s: float = 30.0,
        max_bytes: int = MAX_MESSAGE_BYTES,
        inner: "httpx.BaseTransport | None" = None,
        resolver: Callable[..., object] | None = None,
    ) -> None:
        if not isinstance(target, TicketingTarget):
            raise TicketingPushError("target must be a TicketingTarget")
        if not isinstance(allowlist, EgressAllowlist):
            raise TicketingPushError("allowlist must be an EgressAllowlist")
        if target.kind != "github_issues":
            raise TicketingPushError(f"unsupported ticketing kind {target.kind!r} (this slice: github_issues)")
        self._target = target
        self._url = f"https://{_bracket_host(target.host)}/repos/{target.repo}/issues"
        # Validate the composed URL is a well-formed absolute http(s) URL with a host (fail-closed) —
        # defence-in-depth over the config layer, which already validated host + repo.
        self._url = self._validate_url(self._url)
        self._bearer = self._validate_token(token)
        self._slug = str(slug) or target.slug
        self._timeout_s = float(timeout_s)
        self._max_bytes = max(1, int(max_bytes))
        # Build the egress guard EXACTLY as FloorPinnedHttpTransport does: sovereign_only=False so the
        # operator's name allowlist is enforced in every mode; the never-liftable L3/L4 floor pins every
        # connect. ``inner`` is the test seam (NAME control only, no network backend).
        self._sov = SovereignHttpxTransport(
            allowlist, inner=inner, sovereign_only=False, slug=self._slug, resolver=resolver)
        self._client = httpx.Client(
            transport=self._sov, timeout=self._timeout_s, follow_redirects=False)

    # ---------------------------------------------------------------- construction-time validation

    @staticmethod
    def _validate_url(url: str) -> str:
        try:
            parsed = httpx.URL(str(url))
        except Exception as e:  # malformed URL => refuse to construct (fail-closed)
            raise TicketingPushError(f"invalid ticketing API URL: {type(e).__name__}") from e
        if parsed.scheme not in ("http", "https") or not parsed.host:
            raise TicketingPushError("ticketing API URL must be an absolute http(s) URL with a host")
        return str(parsed)

    @staticmethod
    def _validate_token(token: str | None) -> str | None:
        if token is None:
            return None
        t = str(token)
        if not t:
            return None
        if any(c in t for c in "\r\n"):
            # A newline in a header value is a request-splitting primitive; refuse rather than send it.
            raise TicketingPushError("API token must not contain CR/LF (header-injection guard)")
        return t

    # ---------------------------------------------------------------- the push

    def push(self, finding: TicketFinding, *, labels: "tuple[str, ...]" = ()) -> PushReceipt:
        """Push ``finding`` as ONE GitHub issue and return a :class:`PushReceipt` (a record, never a FACT).

        Fail-closed refusals (all :class:`TicketingPushError`): a finding that is not oracle-verified; a
        missing/empty token (we never push unauthenticated); an oversized request/response; a non-2xx HTTP
        status (a redirect is a non-2xx — never followed); malformed JSON. An egress refusal raises
        :class:`SovereigntyViolation` (re-raised unchanged — fail-closed)."""
        if not isinstance(finding, TicketFinding):
            raise TicketingPushError("finding must be a TicketFinding (use TicketFinding.from_finding)")
        if not finding.verified_by_oracle:
            # ORACLE-VERIFIED ONLY: an LLM-advisory / unconfirmed lead is never disclosed as a ticket.
            raise TicketingPushError(
                f"refusing to push finding {finding.finding_slug!r}: not oracle-verified "
                f"(only a deterministic-oracle-confirmed finding is pushed OUT)")
        if not self._bearer:
            # Refuse AT REQUEST TIME (not construction): the token is resolved out-of-band and may be absent.
            raise TicketingPushError(
                f"refusing to push finding {finding.finding_slug!r}: no API token resolved from env var "
                f"{self._target.auth_env!r} (we never push to a ticketing system unauthenticated)")

        title = (f"[VIGIL][{finding.severity or 'Finding'}] {finding.title or finding.finding_slug}")[:_MAX_TITLE]
        body = render_issue_body(finding, tenant_id=self._target.tenant_id, slug=self._slug)
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = list(labels)

        try:
            raw_body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except Exception as e:
            raise TicketingPushError(f"issue payload is not JSON-serializable: {type(e).__name__}") from e
        if len(raw_body) > self._max_bytes:
            raise TicketingPushError("outbound issue payload exceeds the maximum size")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
            "User-Agent": _USER_AGENT,
            "X-GitHub-Api-Version": _GITHUB_API_VERSION,
            "Authorization": f"Bearer {self._bearer}",
        }

        raw = bytearray()
        try:
            with self._client.stream("POST", self._url, content=raw_body, headers=headers) as response:
                status = int(response.status_code)
                if status // 100 != 2:
                    # follow_redirects=False => a 3xx arrives here UNFOLLOWED; any non-2xx is a failure.
                    raise TicketingPushError(
                        f"ticketing API returned HTTP {status} (no redirect is ever followed)")
                for chunk in response.iter_bytes():
                    raw += chunk
                    if len(raw) > self._max_bytes:
                        raise TicketingPushError("ticketing API response exceeds the maximum size")
        except SovereigntyViolation:
            raise                       # egress floor / name-allowlist refusal — fail closed, never soften
        except TicketingPushError:
            raise
        except httpx.HTTPError as e:    # connect/timeout/protocol/read errors — never leak the token/body
            raise TicketingPushError(
                f"HTTP transport error talking to the ticketing API: {type(e).__name__}") from e

        issue_number, issue_url = self._parse_receipt_fields(bytes(raw))
        return PushReceipt(
            ok=True, target_id=self._target.id, tenant_id=self._target.tenant_id, slug=self._slug,
            finding_slug=finding.finding_slug, issue_number=issue_number, issue_url=issue_url)

    @staticmethod
    def _parse_receipt_fields(raw: bytes) -> tuple[int | None, str | None]:
        """Parse ONLY the receipt fields (issue number + html_url) from the API response. Defensive: a
        malformed / non-object body yields ``(None, None)`` — the push still SUCCEEDED (2xx), the receipt is
        just thinner. The response is NEVER otherwise interpreted (no FACT, no ingestion)."""
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return None, None
        if not isinstance(obj, dict):
            return None, None
        num = obj.get("number")
        url = obj.get("html_url")
        return (int(num) if isinstance(num, int) else None,
                url if isinstance(url, str) and url else None)

    def close(self) -> None:
        """Close the underlying ``httpx.Client`` (idempotent; never raises)."""
        try:
            self._client.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        # Secret-redacting: show ONLY the origin (scheme://host) + repo — never the bearer.
        try:
            u = httpx.URL(self._url)
            origin = f"{u.scheme}://{u.host}" + (f":{u.port}" if u.port else "")
        except Exception:
            origin = "<url>"
        return (f"GithubIssuesPusher(origin={origin!r}, repo={self._target.repo!r}, "
                f"token={'<set>' if self._bearer else None})")


# =============================================================================
# The high-level library API (OFF by default; fail-closed; (tenant_id, slug)-keyed audit)
# =============================================================================

def _default_pusher_factory(
    target: TicketingTarget, allowlist: EgressAllowlist, token: str | None, slug: str,
) -> GithubIssuesPusher:
    return GithubIssuesPusher(target, allowlist, token=token, slug=slug)


def append_push_audit(
    slug: str, receipt: PushReceipt, *, root: "str | None" = None,
) -> None:
    """Best-effort append of ONE ``(tenant_id, slug)``-keyed audit record to
    ``targets/<slug>/ticketing-pushes.jsonl`` (append-only, owner-only). NEVER raises — an audit failure
    must not fail the push. ``root`` is a test/deployment override of the crucible root; ``None`` uses the
    real per-tenant layout (``paths.target_dir``)."""
    try:
        if root is None:
            d = paths.target_dir(slug)
        else:
            from pathlib import Path
            d = Path(root) / "targets" / slug
        line = json.dumps(receipt.audit_record(), ensure_ascii=False, sort_keys=True) + "\n"
        try:
            paths.secure_dir(d)
        except Exception:
            d.mkdir(parents=True, exist_ok=True)
        with open(d / "ticketing-pushes.jsonl", "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def push_finding(
    slug: str,
    target_id: str,
    finding: Any,
    *,
    labels: "tuple[str, ...]" = (),
    token_resolver: Callable[[str], "str | None"] = os.environ.get,
    allowlist: "EgressAllowlist | None" = None,
    root: "str | None" = None,
    audit_root: Any = None,
    pusher_factory: "Callable[..., GithubIssuesPusher] | None" = None,
) -> PushReceipt:
    """Push an oracle-verified ``finding`` OUT to the operator-provisioned ticketing target ``target_id``
    for engagement ``slug``. The one high-level entry point for the ticketing-OUT connector.

    OFF BY DEFAULT + fail-closed (all raise :class:`TicketingPushError`): no matching target provisioned
    (the connector stays off); no token resolvable from the target's ``auth_env`` (never push
    unauthenticated); a non-oracle-verified finding (refused by ``push``). An egress refusal raises
    :class:`SovereigntyViolation` unchanged.

    ``allowlist``      the engagement :class:`EgressAllowlist` the push dials through; defaults to
                       ``build_engagement_allowlist(slug, collector_hosts=[target.host])`` so the transport
                       permits exactly the provisioned ticketing host (the egress axis is DISJOINT from the
                       attack target scope — a host overlapping the charter scope is DROPPED, fail-closed).
    ``token_resolver`` resolves ``auth_env`` (an env-var NAME) to the token VALUE out-of-band; defaults to
                       ``os.environ.get`` (never the config file, never logged).
    ``root``           deployment/test override of the crucible root the config is read from.
    ``audit_root``     where the best-effort ``(tenant_id, slug)``-keyed audit record is appended; ``None``
                       uses the real layout, ``False`` skips the audit (hermetic tests), else a root path.
    ``pusher_factory`` TEST SEAM — ``(target, allowlist, token, slug) -> pusher``; defaults to the
                       production floor-pinned :class:`GithubIssuesPusher`.
    """
    target = find_ticketing_target(slug, target_id, root=root)
    if target is None:
        raise TicketingPushError(
            f"no ticketing target {target_id!r} is provisioned for engagement {slug!r} "
            f"(the ticketing-OUT connector is OFF until the operator provisions one)")

    token = token_resolver(target.auth_env) if target.auth_env else None
    if not token:
        raise TicketingPushError(
            f"no API token resolved from env var {target.auth_env!r} for ticketing target {target_id!r} "
            f"(we never push to a ticketing system unauthenticated)")

    # The egress axis is DISJOINT from the attack scope: a ticketing sink must never be a host under attack.
    # Enforce this UNCONDITIONALLY — even when the CALLER supplies its own allowlist (which would otherwise
    # skip the build_engagement_allowlist drop), so a conflicting host ALWAYS fails CLOSED, not just on the
    # default path.
    if collector_scope_conflicts([target.host], _target_scope(slug)):
        raise TicketingPushError(
            f"ticketing host for {target_id!r} overlaps the engagement attack scope — refusing "
            f"(a ticketing sink must be disjoint from the target you are attacking)")
    if allowlist is None:
        # No explicit allowlist ⇒ build the floor-pinned default (which also drops a conflicting collector host).
        allowlist = build_engagement_allowlist(slug=slug, collector_hosts=[target.host])

    tf = finding if isinstance(finding, TicketFinding) else TicketFinding.from_finding(finding)
    factory = pusher_factory or _default_pusher_factory
    pusher = factory(target, allowlist, token, slug)
    try:
        receipt = pusher.push(tf, labels=labels)
    finally:
        try:
            pusher.close()
        except Exception:
            pass

    if audit_root is not False:
        append_push_audit(slug, receipt, root=(None if audit_root is None else str(audit_root)))
    return receipt


def _target_scope(slug: str) -> tuple[str, ...]:
    """The engagement's attack-target hosts (for the disjointness check), read defensively — an absent
    charter yields ``()`` (the check then never conflicts), never a crash."""
    try:
        from ..common import ethics
        return tuple(ethics.parse_scope(slug))
    except Exception:
        return ()
