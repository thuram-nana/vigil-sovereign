"""Customer Notifications OUTBOUND channels + the SSRF-guarded delivery egress (PR-D, Area 3 — SHIPPED OFF).

READ-ONLY CONSUMER of the oracle-minted finding spine. This module DELIVERS an already-minted FACT finding to a
tenant's configured out-of-band channels (email / Slack / Discord / a generic webhook). It is the OUTBOUND twin of
the IN-APP notification centre (``ui.provision.customer_notifications``, which a customer READS inside the app) and
it is NOT ``bridge.notifier`` (that is the operator PHONE-push for A2/A3 approval items — a different subject).

LOAD-BEARING INVARIANTS (a false-green here is a real breach):

  * A NOTIFICATION IS NEVER A FACT SOURCE. This module only READS inert finding records and SENDS bytes to a
    channel; it NEVER appends ANY record to the spine (no ``store.append`` anywhere). A FACT is minted ONLY by the
    oracle — the delivery path has no spine write at all (``test_notify_channels`` greps this module's AST to prove
    it: no ``append`` call, no ``kind="finding"`` literal).

  * OWNER-REVIEWED OUTBOUND ALLOWLIST + SSRF GUARD. Every outbound URL passes :func:`guard_outbound_url` BEFORE a
    socket opens: https-only, no embedded userinfo, default port, the HOST on the OWNER-reviewed allowlist (an exact
    host in ``config.NOTIFY_WEBHOOK_HOST_ALLOWLIST`` or an allowed suffix in
    ``config.NOTIFY_WEBHOOK_HOST_ALLOWLIST_SUFFIXES``), AND every address the host resolves to is PUBLIC (a private /
    loopback / link-local / cloud-metadata ``169.254.169.254`` / ULA / CGNAT / reserved / unspecified address is
    REFUSED). A tenant SUPPLIES a webhook URL, but it can therefore never point the delivery egress at an internal
    or metadata host.

  * NO MODEL IDENTIFIER to a customer. The rendered notice is projected through a FIXED allowlist of inert finding
    fields (:data:`_NOTICE_FIELDS`) — never a raw record dump — and :func:`_assert_no_model_identifier` is a
    backstop that refuses a payload carrying a model-family token.

FATAL-2: ``assert_no_offense()`` at import; stdlib (``urllib`` / ``ipaddress`` / ``socket``) + sovereign siblings
only; never imports engine/crucible (the finding record is already inert JSON on the spine).
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence
from urllib.parse import urlsplit

from ..reuse import assert_no_offense

assert_no_offense()

from .. import config  # noqa: E402  (owner-reviewed allowlists + the master flag; read at call time)

# ---- channel kinds -------------------------------------------------------------------------------------------
CHANNEL_EMAIL = "email"
CHANNEL_SLACK = "slack"
CHANNEL_DISCORD = "discord"
CHANNEL_WEBHOOK = "webhook"
_URL_CHANNELS = frozenset({CHANNEL_SLACK, CHANNEL_DISCORD, CHANNEL_WEBHOOK})
_CHANNEL_KINDS = frozenset({CHANNEL_EMAIL, *_URL_CHANNELS})

# Slack/Discord are pinned to their own provider hosts (a tenant's Slack webhook is always on hooks.slack.com; a
# Discord webhook on discord.com/discordapp.com) — tighter than the generic-webhook allowlist, so a "slack" channel
# can never be pointed at an arbitrary allowlisted host.
_SLACK_HOSTS = frozenset({"hooks.slack.com"})
_DISCORD_HOSTS = frozenset({"discord.com", "discordapp.com"})

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}$")
_EMAIL_MAX = 254
_MAX_RESPONSE_BYTES = 256 * 1024
_DEFAULT_TIMEOUT_S = 10.0
_TRANSIENT_HTTP = frozenset({408, 425, 429})

# The stable, inert finding fields a customer notice may carry (an allowlist, never a raw record dump) — exactly the
# subset of the ``ui.assessments`` projection that is safe to egress. NO model identifier, NO internal digest, NO
# amount. The rendered notice is built from ONLY these, so a future internal cert field can never leak to a channel.
_NOTICE_FIELDS = ("finding_ref", "bug_class", "surface", "severity", "title", "summary", "engagement_slug")
# A backstop over the RENDERED notice (the field allowlist is the primary control; none of the fields above carries a
# model id by construction). A match fails delivery CLOSED — a customer must never be shown which model was used.
_MODEL_ID_TOKENS = ("anthropic", "claude", "opus-", "sonnet-", "haiku-", "gpt-", "gpt4", "gemini-", "llama-",
                    "mistral-", "model_id", "model-id")


class OutboundRefused(RuntimeError):
    """A fail-closed outbound refusal (an SSRF-guard rejection, a disabled flag, a bad channel). ``transient`` is
    True only for a failure a later retry may cure (a transport fault / HTTP 408/425/429/5xx); everything else is
    definitive. The message never contains a delivery credential."""

    transient: bool = False


def _refuse(message: str, *, transient: bool = False) -> OutboundRefused:
    exc = OutboundRefused(message)
    exc.transient = transient
    return exc


# ---- the SSRF / allowlist guard ------------------------------------------------------------------------------
Resolver = Callable[[str], Sequence[str]]
#: CGNAT 100.64.0.0/10 — carrier-grade NAT, not globally routable, a classic SSRF pivot. ``is_global`` already
#: excludes it on current CPython, but we reject it explicitly so the guard does not depend on that detail.
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def _default_resolver(host: str) -> list[str]:
    """Every address ``host`` resolves to (A + AAAA), as strings. Raises ``OSError`` on a lookup failure, which the
    guard turns into a fail-closed refusal (an unresolvable host is never delivered to)."""
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [str(sa[0]) for (*_head, sa) in infos if sa and sa[0]]


def _is_public_address(ip_text: str) -> bool:
    """True iff ``ip_text`` is a single, globally-routable PUBLIC address. Unwraps an IPv4-mapped / 6to4 IPv6 to its
    embedded v4 first, then rejects every non-public category (private / loopback / link-local incl. the
    ``169.254.169.254`` metadata address / multicast / reserved / unspecified / CGNAT). Fail-closed: an unparseable
    value is NOT public."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _is_public_address(str(ip.ipv4_mapped))
        if ip.sixtofour is not None:
            return _is_public_address(str(ip.sixtofour))
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_V4:
        return False
    # is_global is the positive restatement: an address allocated for the public internet. Required in addition to
    # the negative checks above so a brand-new special range (not yet flagged by a category) still fails closed.
    return bool(getattr(ip, "is_global", False))


def _host_allowed(host: str, allow_hosts: "frozenset[str]", allow_suffixes: "frozenset[str]") -> bool:
    """True iff ``host`` EQUALS an allowlisted exact host OR ends with (``.`` + an allowed suffix). The dot boundary
    is required, so ``discord.com.evil.test`` is NOT admitted by the ``discord.com`` suffix (it ends with
    ``.evil.test``), while ``canary.discord.com`` and bare ``discord.com`` are."""
    h = host.lower().rstrip(".")
    if h in allow_hosts:
        return True
    return any(h == s or h.endswith("." + s) for s in allow_suffixes)


def guard_outbound_url(url: str, *, allow_hosts: "frozenset[str]", allow_suffixes: "frozenset[str]" = frozenset(),
                       resolver: Optional[Resolver] = None) -> str:
    """Refuse an outbound URL that is not safe to deliver to, returning its validated lower-cased host otherwise.
    The ONE place an outbound target is admitted. Checks, in order (fail-closed): https scheme; no embedded
    userinfo; default port (443/omitted); the host on the OWNER-reviewed allowlist (exact or suffix); and EVERY
    address the host resolves to is PUBLIC (:func:`_is_public_address`). ``resolver`` defaults to DNS
    (:func:`_default_resolver`) and is injected in tests. An empty resolution, or a single internal address among
    many, REFUSES the whole URL — a tenant webhook can never reach an internal / metadata host."""
    if not isinstance(url, str) or not url:
        raise _refuse("refusing an empty outbound URL")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise _refuse(f"refusing a non-https outbound URL (scheme {parts.scheme!r})")
    if "@" in (parts.netloc or ""):
        raise _refuse("refusing an outbound URL carrying userinfo")
    try:
        port = parts.port
    except ValueError:
        raise _refuse("refusing an outbound URL with a malformed port") from None
    if port not in (None, 443):
        raise _refuse(f"refusing an outbound URL with a non-default port ({port})")
    host = (parts.hostname or "").lower()
    if not host:
        raise _refuse("refusing an outbound URL with no host")
    if not _host_allowed(host, allow_hosts, allow_suffixes):
        raise _refuse(f"refusing outbound delivery to non-allowlisted host {host!r}")
    resolve = resolver or _default_resolver
    try:
        addrs = list(resolve(host))
    except OSError as exc:
        raise _refuse(f"refusing outbound delivery to unresolvable host {host!r} ({exc})", transient=True) from None
    if not addrs:
        raise _refuse(f"refusing outbound delivery to host {host!r} that resolves to no address")
    for a in addrs:
        if not _is_public_address(a):
            raise _refuse(
                f"refusing outbound delivery to host {host!r}: resolves to non-public address (SSRF guard)")
    return host


def _webhook_allowlist() -> "tuple[frozenset[str], frozenset[str]]":
    """The generic-webhook (host, suffix) owner-reviewed allowlists, read from ``config`` at call time."""
    return (frozenset(config.NOTIFY_WEBHOOK_HOST_ALLOWLIST),
            frozenset(config.NOTIFY_WEBHOOK_HOST_ALLOWLIST_SUFFIXES))


# ---- the channel value object --------------------------------------------------------------------------------
@dataclass(frozen=True)
class NotifyChannel:
    """One validated outbound channel a tenant has configured. Construction is NOT validation — call
    :meth:`validate` (the registry does, before storing, and :func:`deliver` does, before sending)."""

    kind: str
    target: str           # a URL for slack/discord/webhook; an email address for email
    label: str = ""       # a human label (never egressed; display only)

    def validate(self, *, resolver: Optional[Resolver] = None) -> "NotifyChannel":
        """Validate this channel fail-closed and return it, or raise ``OutboundRefused`` / ``ValueError``. STATIC
        checks always run (scheme/host/allowlist for a URL, format for an email); the PUBLIC-address check runs only
        when ``resolver`` is supplied (the registry stores on static validation; delivery re-validates WITH a
        resolver, so a DNS result that changed since config time is caught at send)."""
        if self.kind not in _CHANNEL_KINDS:
            raise _refuse(f"unknown channel kind {self.kind!r}")
        if not isinstance(self.target, str) or not self.target:
            raise _refuse(f"channel {self.kind!r} has an empty target")
        if self.kind == CHANNEL_EMAIL:
            e = self.target.strip()
            if len(e) > _EMAIL_MAX or not _EMAIL_RE.match(e):
                raise _refuse("refusing a malformed email channel target")
            return self
        if self.kind == CHANNEL_SLACK:
            guard_outbound_url(self.target, allow_hosts=_SLACK_HOSTS, resolver=resolver)
        elif self.kind == CHANNEL_DISCORD:
            guard_outbound_url(self.target, allow_hosts=_DISCORD_HOSTS, resolver=resolver)
        else:  # CHANNEL_WEBHOOK — the generic owner-reviewed allowlist
            hosts, suffixes = _webhook_allowlist()
            guard_outbound_url(self.target, allow_hosts=hosts, allow_suffixes=suffixes, resolver=resolver)
        return self

    def _guard_for_send(self, resolver: Optional[Resolver]) -> str:
        """Re-run the full guard (WITH the public-address check) at send time and return the validated host."""
        if self.kind == CHANNEL_SLACK:
            return guard_outbound_url(self.target, allow_hosts=_SLACK_HOSTS, resolver=resolver)
        if self.kind == CHANNEL_DISCORD:
            return guard_outbound_url(self.target, allow_hosts=_DISCORD_HOSTS, resolver=resolver)
        hosts, suffixes = _webhook_allowlist()
        return guard_outbound_url(self.target, allow_hosts=hosts, allow_suffixes=suffixes, resolver=resolver)

    def as_json(self) -> dict[str, str]:
        return {"kind": self.kind, "target": self.target, "label": self.label}

    @staticmethod
    def from_json(obj: Any) -> "Optional[NotifyChannel]":
        if not isinstance(obj, dict):
            return None
        kind, target = obj.get("kind"), obj.get("target")
        if not isinstance(kind, str) or not isinstance(target, str):
            return None
        label = obj.get("label")
        return NotifyChannel(kind=kind, target=target, label=label if isinstance(label, str) else "")


# ---- the notice (the delivered content) ----------------------------------------------------------------------
@dataclass(frozen=True)
class Notice:
    """The rendered, channel-agnostic content of ONE finding delivery — built ONLY from the inert
    :data:`_NOTICE_FIELDS`. ``subject`` + ``body`` serve email; ``fields`` serves the chat/webhook renderers."""

    subject: str
    body: str
    fields: dict[str, str]


def _assert_no_model_identifier(*texts: str) -> None:
    """Backstop: refuse CLOSED if any rendered text carries a model-family token. The field allowlist is the
    primary guarantee (no allowlisted finding field holds a model id); this catches a future carrier regression."""
    for text in texts:
        low = str(text).lower()
        for tok in _MODEL_ID_TOKENS:
            if tok in low:
                raise _refuse(f"refusing to deliver a notice carrying a model-identifier token {tok!r}")


def render_finding_notice(finding_row: dict[str, Any]) -> Notice:
    """Project ONE inert finding row (a ``ui.assessments`` projection) into a deliverable :class:`Notice`, using
    ONLY :data:`_NOTICE_FIELDS` (never a raw dump). The subject/body are plain text safe for any channel; the
    model-identifier backstop runs over the rendered output. PURE — no I/O, no spine access."""
    fields = {f: str(finding_row[f]) for f in _NOTICE_FIELDS if finding_row.get(f) is not None}
    severity = fields.get("severity", "finding")
    title = fields.get("title") or fields.get("bug_class") or "Security finding"
    subject = f"[VIGIL] {severity}: {title}"
    lines = [f"A new {severity} finding was confirmed on your assessment.", "", f"Title: {title}"]
    for key in ("bug_class", "surface", "finding_ref", "summary"):
        if key in fields:
            lines.append(f"{key.replace('_', ' ').title()}: {fields[key]}")
    body = "\n".join(lines)
    _assert_no_model_identifier(subject, body, *fields.values())
    return Notice(subject=subject, body=body, fields=fields)


# ---- channel-shaped payloads ---------------------------------------------------------------------------------
def _slack_payload(notice: Notice) -> dict[str, Any]:
    return {"text": f"*{notice.subject}*\n{notice.body}"}


def _discord_payload(notice: Notice) -> dict[str, Any]:
    # Discord caps content at 2000 chars; the notice is small, but bound it fail-closed.
    return {"content": f"**{notice.subject}**\n{notice.body}"[:1900]}


def _webhook_payload(notice: Notice) -> dict[str, Any]:
    # A stable generic JSON envelope a customer's own handler can parse. Inert allowlisted fields only.
    return {"type": "vigil.finding", "subject": notice.subject, "fields": dict(notice.fields)}


# ---- the delivery egress -------------------------------------------------------------------------------------
HttpPost = Callable[[str, bytes, dict[str, str]], int]
EmailSend = Callable[[str, str, str], bool]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a 3xx — urllib would replay the POST (and any header) onto a target the one-shot guard never
    re-checked. Returning None makes a 3xx a fail-closed ``HTTPError``."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _urllib_post(url: str, body: bytes, headers: dict[str, str]) -> int:
    """The single real outbound POST (a redirect-blocking opener; https + host pinned by the guard that ran first).
    Also the seam the tests patch to stand in a FAKE channel with NO network. Returns the HTTP status; a transport
    fault / 5xx raises a transient ``OutboundRefused``, a 4xx a definitive one."""
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with _OPENER.open(req, timeout=_DEFAULT_TIMEOUT_S) as r:   # noqa: S310 — https + host pinned by the guard
            r.read(_MAX_RESPONSE_BYTES + 1)
            return int(getattr(r, "status", 0) or 0)
    except urllib.error.HTTPError as exc:
        code = exc.code if isinstance(exc.code, int) else 0
        raise _refuse(f"channel POST returned HTTP {code}",
                      transient=(code in _TRANSIENT_HTTP or code >= 500)) from None
    except urllib.error.URLError as exc:
        raise _refuse(f"channel POST transport error: {exc.reason}", transient=True) from None


@dataclass(frozen=True)
class DeliveryResult:
    """The outcome of ONE channel delivery. ``ok`` True iff accepted. ``transient`` marks a retryable failure. No
    spine record is EVER written — delivery is send-only."""

    ok: bool
    kind: str
    status: int = 0
    transient: bool = False
    detail: str = ""


def deliver(channel: NotifyChannel, notice: Notice, *, http_post: Optional[HttpPost] = None,
            email_send: Optional[EmailSend] = None, resolver: Optional[Resolver] = None) -> DeliveryResult:
    """Deliver ONE :class:`Notice` to ONE :class:`NotifyChannel`. FLAG-GATED: refuses CLOSED unless
    ``config.customer_notify_enabled()`` (so with the flag off NOTHING is delivered and no socket opens). Re-runs
    the FULL SSRF guard (WITH a resolver) before any URL POST — a config-time-valid host that now resolves to an
    internal address is refused at send. ``http_post`` / ``email_send`` are injected transports (defaults: stdlib
    urllib / none); unset ``email_send`` means an email channel reports not-delivered (no silent SMTP dependency).
    NEVER writes the spine."""
    if not config.customer_notify_enabled():
        raise _refuse("refusing delivery: customer notify is disabled (VIGIL_CUSTOMER_NOTIFY off)")
    if channel.kind == CHANNEL_EMAIL:
        channel.validate()  # static shape re-check (a malformed email channel is a config error — raises)
        if email_send is None:
            return DeliveryResult(ok=False, kind=channel.kind, detail="no email sender configured")
        ok = bool(email_send(channel.target, notice.subject, notice.body))
        return DeliveryResult(ok=ok, kind=channel.kind, detail="sent" if ok else "not delivered")
    # URL channels: the SSRF guard + the POST both convert an OutboundRefused into a not-ok result, so a refusal
    # (incl. a host that now resolves to an internal address — the send-time SSRF re-check) never raises OUT of
    # delivery; the drain counts it and moves on. No socket opens unless the guard passed first.
    try:
        channel.validate()                         # static shape re-check
        host = channel._guard_for_send(resolver)    # the full SSRF guard — BEFORE any socket
        if channel.kind == CHANNEL_SLACK:
            payload = _slack_payload(notice)
        elif channel.kind == CHANNEL_DISCORD:
            payload = _discord_payload(notice)
        else:
            payload = _webhook_payload(notice)
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "VIGIL-Notify"}
        post = http_post or _urllib_post
        status = int(post(channel.target, body, headers))
    except OutboundRefused as exc:
        return DeliveryResult(ok=False, kind=channel.kind, transient=exc.transient, detail=str(exc))
    ok = 200 <= status < 300 or (status == 0 and (http_post or _urllib_post) is not _urllib_post)
    return DeliveryResult(ok=ok, kind=channel.kind, status=status, detail=f"host={host} status={status}")


# ---- the per-tenant channel registry (file-backed, atomic; mirrors ui.email_channel ledgers) -----------------
def _org_marker_name(org_id: str) -> str:
    """A tenant-namespaced, non-reversible file name for ``org_id``'s channel config (never the raw org id on
    disk) — the IDOR-safe key, exactly as the finding read scopes by the one-way ``_customer_slug`` hash."""
    from ..reuse import sha256_hex
    return "notify_" + sha256_hex(("notify-channels\x00" + str(org_id)).encode("utf-8"))[:32]


class NotifyChannelRegistry:
    """Per-(org) outbound channel configuration on the filesystem (one 0600 JSON marker per org, named by a one-way
    hash of the org id — tenant-isolated by construction: a read scopes to ONE org's own marker, so one tenant's
    config is structurally unreachable by another). Every channel is :meth:`NotifyChannel.validate`-d (static:
    scheme/host/allowlist/format) BEFORE it is stored, so a config that would egress to a non-allowlisted or
    malformed target can never be persisted. FLAG-GATED writes.

    HONEST LIMIT: this stores the tenant's declared config file-backed (as ``EmailTokenLedger`` /
    ``LoginRateLimiter`` do), NOT yet as an owner-signed spine record with the asymmetric-auth ceremony
    ``connected_repos`` uses. The actual outbound-SSRF control is the owner-reviewed host allowlist + the guard at
    send time (enforced regardless of how the config was stored); the owner-signed channel-config record is the
    hardening follow-on. See ``honest_todo``."""

    def __init__(self, path: "str | Any", *, max_channels: int = 16) -> None:
        from pathlib import Path
        self.dir = Path(path)
        self.max_channels = int(max_channels)

    def _marker(self, org_id: str) -> Any:
        return self.dir / _org_marker_name(org_id)

    def channels_of(self, org_id: str) -> list[NotifyChannel]:
        """This org's configured channels (its own marker only) — never another tenant's. Fail-soft: a missing /
        corrupt marker reads as no channels (never raises). A stored entry that no longer validates STATICALLY is
        dropped from the read (defence in depth: a config the allowlist no longer admits is not delivered to)."""
        if not isinstance(org_id, str) or not org_id:
            return []
        try:
            raw = self._marker(org_id).read_text(encoding="utf-8")
        except (OSError, ValueError):
            return []
        try:
            obj = json.loads(raw)
        except ValueError:
            return []
        items = obj.get("channels") if isinstance(obj, dict) else None
        out: list[NotifyChannel] = []
        for entry in items or []:
            ch = NotifyChannel.from_json(entry)
            if ch is None:
                continue
            try:
                out.append(ch.validate())   # static validation — a now-disallowed target is dropped, never served
            except (OutboundRefused, ValueError):
                continue
        return out

    def set_channels(self, org_id: str, channels: Sequence[NotifyChannel]) -> list[NotifyChannel]:
        """Replace ``org_id``'s channel set with ``channels`` (each STATICALLY validated first — an invalid one
        raises and NOTHING is written). FLAG-GATED: refuses when notify is off. Returns the stored channels.
        Atomic write (0600, O_EXCL tmp + rename), mirroring ``EmailTokenLedger._write_atomic``."""
        import os
        import secrets
        if not config.customer_notify_enabled():
            raise _refuse("refusing to configure channels: customer notify is disabled (VIGIL_CUSTOMER_NOTIFY off)")
        if not isinstance(org_id, str) or not org_id:
            raise _refuse("refusing a channel config with an empty org id")
        chans = list(channels)
        if len(chans) > self.max_channels:
            raise _refuse(f"refusing more than {self.max_channels} channels for one org")
        validated = [c.validate() for c in chans]   # raises BEFORE any write if ANY channel is invalid
        rec = {"org_marker": _org_marker_name(org_id), "channels": [c.as_json() for c in validated]}
        marker = self._marker(org_id)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = marker.with_name(f"{marker.name}.{secrets.token_hex(8)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp), flags, 0o600)
        try:
            os.write(fd, json.dumps(rec).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, marker)
        return validated
