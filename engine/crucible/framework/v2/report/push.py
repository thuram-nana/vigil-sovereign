"""report.push — deliver a graded report to an operator-configured OUTBOUND sink (webhook / Slack).

OUTBOUND, and SAFE BY CONSTRUCTION:

  * OPT-IN — nothing is ever pushed unless the operator explicitly supplies a sink URL.
  * NEVER raw egress — :func:`push_report` builds a JSON payload and hands it to an INJECTED ``send``;
    in production that is :func:`push_via_urllib`, a bounded POST to EXACTLY the operator's sink URL that
    REFUSES redirects (no redirect-to-internal SSRF) and any other host. The payload builder does no I/O.
  * PROVEN-FACT DISCIPLINE — the payload is built from the GRADED report, so a proven FACT is levelled by
    its severity and a LEAD is clearly marked (or dropped with ``facts_only``) — the SAME grounding
    discipline as the SARIF/JSON export, so a downstream ticket/alert is never dressed from an unproven
    lead. The export doc carries NO raw payloads / oracle contexts / PII (only a certificate DIGEST), so
    pushing it does not leak evidence.
  * CORRELATABLE — a recognisable ``User-Agent``; the operator can find the push in their sink's logs.
  * BEST-EFFORT — a send error is caught and reported, never raised (a failed push never sinks a run).

Sinks: ``webhook`` (POST the export doc as-is — the universal primitive that Jira/DefectDojo/SIEM/a
custom endpoint accept) and ``slack`` (a compact Slack ``{"text": ...}`` message). Jira/DefectDojo REST
with per-tool auth are a thin follow-up over the same gated ``send``.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.request
from typing import Any, Callable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .export import build_export_doc
from .generate import ReportMeta
from .grounding import grade_findings

# Correlatable, no stealth (doctrine): the operator greps their sink's logs and finds CRUCIBLE's push.
_PUSH_UA = "OBSIDIAN/1.0 (authorized owner-test report-push)"
_PUSH_TIMEOUT = 10.0
_SLACK_MAX_LINES = 25


class PushConfig(BaseModel):
    """How + where to push. ``headers`` carries the operator's own auth (a bearer token / Jira basic auth)
    — CRUCIBLE never invents credentials."""

    model_config = ConfigDict(extra="forbid")

    sink: str = Field(default="webhook", description='"webhook" | "slack"')
    url: str = Field(min_length=1, description="The operator-configured sink URL (the ONLY egress).")
    headers: dict[str, str] = Field(default_factory=dict)
    facts_only: bool = Field(default=False, description="Push only proven FACTs (drop leads entirely).")
    dry_run: bool = Field(default=False, description="Build the payload but do NOT send (preview).")


class PushResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pushed: bool
    sink: str
    url: str
    status: int | None = None
    facts: int = 0
    leads: int = 0
    note: str = ""
    payload: dict | None = None   # populated on dry_run so the operator can inspect before sending


def _is_fact(finding_dict: dict) -> bool:
    prov = finding_dict.get("provenance")
    return bool(prov.get("is_fact")) if isinstance(prov, dict) else False


def _filter_facts_only(doc: dict) -> dict:
    """Return a copy of the export doc with only the proven-FACT findings (leads dropped)."""
    out = dict(doc)
    out["findings"] = [f for f in doc.get("findings", []) if _is_fact(f)]
    return out


def _slack_message(doc: dict) -> dict:
    """A compact Slack ``{"text": ...}`` — facts first, capped, never leaking evidence."""
    summ = doc.get("summary", {}) if isinstance(doc.get("summary"), dict) else {}
    target = str((doc.get("target") or doc.get("meta", {}).get("target") or "target"))
    lines = [f"*CRUCIBLE — {target}*: "
             f"{summ.get('facts', 0)} confirmed fact(s), {summ.get('leads', 0)} lead(s)"]
    for f in doc.get("findings", [])[:_SLACK_MAX_LINES]:
        mark = "✅ FACT" if _is_fact(f) else "• lead"
        loc = f.get("surface") or "?"
        lines.append(f"{mark}  [{f.get('severity', '?')}] {f.get('bug_class', '?')} — {loc}")
    return {"text": "\n".join(lines)}


def _payload_from_graded(graded: list, config: PushConfig, meta: ReportMeta | None) -> dict:
    """Shape the outbound payload from already-graded findings (no re-grading)."""
    doc = build_export_doc(graded, meta)
    if config.facts_only:
        doc = _filter_facts_only(doc)
    if config.sink == "slack":
        return _slack_message(doc)
    return doc


def build_push_payload(findings: Any, config: PushConfig, *, meta: ReportMeta | None = None) -> dict:
    """Grade ``findings`` and shape the outbound payload for ``config.sink``. Pure (no I/O); deterministic
    given ``meta``. A ``webhook`` sink gets the full export doc (facts levelled, leads marked); a ``slack``
    sink gets a compact text message. ``facts_only`` drops leads first in BOTH cases."""
    return _payload_from_graded(grade_findings(list(findings or [])), config, meta)


def _ip_is_internal(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    """True iff an IP is non-public: loopback / link-local (incl. 169.254.169.254) / private / unique-local /
    reserved / multicast / unspecified. These predicates already cover IPv4 10/8, 172.16/12, 192.168/16,
    127/8, 169.254/16 and IPv6 ::1, fe80::/10, fc00::/7 — so an attacker-chosen metadata / loopback / RFC-1918
    destination is rejected."""
    return bool(ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified)


def _ip_literal(host: str) -> "ipaddress.IPv4Address | ipaddress.IPv6Address | None":
    """Return the IP object if ``host`` is an IP LITERAL (an IPv6 literal arrives already de-bracketed from
    ``urlsplit().hostname``), else ``None`` (it is a DNS name)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def url_host_is_internal_literal(url: str) -> bool:
    """Is the URL's host an INTERNAL IP LITERAL? A DNS name returns ``False`` (resolving it is deferred to the
    send-time :func:`assert_external_destination` guard — no DNS at this static check). Used for a fail-closed
    construction check on a statically-configured sink (a literal ``http://169.254.169.254/`` /
    ``http://127.0.0.1:<port>/`` never arms)."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    ip = _ip_literal(host)
    return ip is not None and _ip_is_internal(ip)


def assert_external_destination(url: str) -> None:
    """Fail-closed SSRF host guard: raise ``ValueError`` when the URL's host is an internal IP literal, OR a
    DNS name that resolves (via :func:`socket.getaddrinfo`) to ANY internal address (reject if the IP-literal
    host OR any resolved address is internal). A name that does not resolve is also refused (fail-closed).
    The residual sub-second DNS-rebind TOCTOU between this resolve and the socket connect is accepted by the
    one tenant caller (blind, POST-only; see :mod:`framework.v2.aegis.notify`)."""
    host = urlsplit(url).hostname
    if not host:
        raise ValueError("push URL has no host (SSRF guard, fail-closed)")
    literal = _ip_literal(host)
    if literal is not None:
        if _ip_is_internal(literal):
            raise ValueError(f"push URL host {host!r} is an internal address (SSRF guard)")
        return
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"push URL host {host!r} did not resolve (SSRF guard, fail-closed)") from exc
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]          # drop any IPv6 scope-id before parsing
        try:
            resolved = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise ValueError(
                f"push URL host {host!r} resolved to an unparseable address (SSRF guard)") from exc
        if _ip_is_internal(resolved):
            raise ValueError(
                f"push URL host {host!r} resolves to internal address {addr} (SSRF guard)")


def push_via_urllib(url: str, headers: dict[str, str], body: dict, *, timeout: float = _PUSH_TIMEOUT,
                    block_internal: bool = False) -> dict:
    """The production gated sender: a bounded JSON POST to EXACTLY ``url`` — redirects DISABLED (no
    redirect-to-internal SSRF), a hard timeout, and only http(s). Returns ``{"status": int}``. The
    operator-configured ``url`` is the sole permitted egress; nothing else is contacted.

    ``block_internal`` (DEFAULT ``False`` — the operator-trusted report-push path is UNCHANGED) additionally
    runs :func:`assert_external_destination` BEFORE building/sending the request, refusing an internal /
    loopback / cloud-metadata destination. The tenant egress (``aegis.notify``) binds it ``True`` so a
    tenant-configured notify-url cannot be turned into a blind-SSRF probe of the shared gateway's internals."""
    if not (isinstance(url, str) and url.startswith(("http://", "https://"))):
        raise ValueError("push URL must be http(s)")
    if block_internal:
        assert_external_destination(url)                 # fail-closed BEFORE any request is built or sent
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", _PUSH_UA)
    for k, v in (headers or {}).items():
        req.add_header(str(k), str(v))

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a: Any, **k: Any):  # noqa: D401 - refuse every redirect
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured sink, no redirects
        return {"status": getattr(resp, "status", 0) or 0}


def push_report(findings: Any, config: PushConfig, *,
                send: Callable[..., dict] | None = None, meta: ReportMeta | None = None) -> PushResult:
    """Build the payload and (unless ``dry_run``) deliver it via the gated ``send`` (default
    :func:`push_via_urllib`). Best-effort: any send error is caught into ``PushResult(pushed=False)``.
    ``send(url, headers, body)`` performs the one gated egress. Grading + payload build are INSIDE the
    best-effort guard too, so even a malformed finding returns a ``PushResult``, never raises."""
    try:
        graded = grade_findings(list(findings or []))
        n_facts = sum(1 for g in graded if g.is_fact)
        n_leads = len(graded) - n_facts
        payload = _payload_from_graded(graded, config, meta)
    except Exception as e:  # a malformed finding must not sink the run either
        return PushResult(pushed=False, sink=config.sink, url=config.url,
                          note=f"payload build failed: {type(e).__name__}: {e}")

    if config.dry_run:
        return PushResult(pushed=False, sink=config.sink, url=config.url, facts=n_facts, leads=n_leads,
                          note="dry-run: payload built, not sent", payload=payload)
    sender = send or push_via_urllib
    try:
        res = sender(config.url, config.headers, payload)
        status = int(res.get("status", 0)) if isinstance(res, dict) else 0
        ok = 200 <= status < 300
        return PushResult(pushed=ok, sink=config.sink, url=config.url, status=status,
                          facts=n_facts, leads=n_leads,
                          note=("delivered" if ok else f"sink returned HTTP {status}"))
    except Exception as e:  # best-effort: a failed push never sinks the run
        return PushResult(pushed=False, sink=config.sink, url=config.url, facts=n_facts, leads=n_leads,
                          note=f"push failed: {type(e).__name__}: {e}")
