"""
verify.reachability_cloud — prove a *publicly-configured* cloud resource is ANONYMOUSLY reachable.

Slice C3. The cloud collectors produce POSTURE facts — "this bucket is publicly exposed" is an
anonymous grant path the ``policy_path`` oracle re-derived over the retained export. That is a
statement about *configuration*. This module turns it into a statement about *reachability*: a
bounded, GATED, UNAUTHENTICATED HTTP GET is CAPTURED against the resource's public endpoint, and the
pure ``anonymous_reachable_oracle`` judges the RETAINED response ALONE — "posture says public" becomes
"PROVEN anonymously reachable". Because the capture is JSON-safe and the oracle is deterministic, a
confirmed exposure RE-VERIFIES OFFLINE from its certificate (``verify.reverify``) with no network and
no trust in the collector — exactly like every other oracle, and exactly like ``verify.reachability``.

The active GET is GATED and BOUNDED, fail-closed by construction, and mirrors ``capture_handshake``:

    slug present  ->  kill-switch  ->  single-host (http/https, no embedded creds)
                  ->  ACTIVE_RECON entitlement  ->  charter scope on the URL host

It is UNAUTHENTICATED by construction: no ``Authorization`` header, no cookies, no ``.netrc``, no
credentials in the URL, and env proxies are disabled so the probe is a direct anonymous request — we
are proving PUBLIC (anonymous) reachability, never authenticated access. A refusal (or any connect
error) returns a ``status: None`` capture with a reason — it never raises and never fabricates a
response. One attempt, a hard timeout, a bounded body read, redirects NOT followed (a 3xx is captured
as-is, not chased into a 200). ``connect`` is injectable so the capture + oracle path is fully
testable OFFLINE with no socket.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .adapter import FindingContext
from .models import VerificationResult
from .reachability import _is_single_host
from .verifier import OracleVerifier

_DEFAULT_TIMEOUT = 4.0
_MAX_BODY_BYTES = 65536
_SNIPPET_BYTES = 256
# A recognizable, credential-free UA so the operator can correlate the probe in their logs (CLAUDE.md
# §VI.4). It carries NO authentication — this is an anonymous request by construction.
_USER_AGENT = "OBSIDIAN/1.0 (authorized owner-test active-exposure)"

# A bucket/container/account label safe to interpolate into a provider URL: a DNS-label-ish token that
# CANNOT smuggle a different host or path (no '/', '@', ':', '?', whitespace, or leading '.'/'-'). The
# charter-scope gate is the real authority; this is defense-in-depth on URL construction.
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# Defense-in-depth redaction for the audit-trail snippet ONLY (the oracle never reads the snippet, so
# over-masking is safe). A public bucket LISTING can echo object keys; mask any credential-shaped token.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"A(?:KIA|SIA|IDA|ROA|GPA|CCA|NPA|NVA|PKA|QUA|SCA|IPA|RGA)[0-9A-Z]{12,}"),  # AWS key ids
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(?:secret|token|password|api[_-]?key|credential)s?\s*[=:]\s*\S+"),
    re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}"),  # long base64/hex secret runs
)


# ---------------------------------------------------------------------------
# per-provider public-endpoint URL construction — pure + total
# ---------------------------------------------------------------------------


def _clean_label(value: Any) -> str:
    """A lowercased bucket/container/account label safe to place in a provider URL, or ``""`` if it is
    empty or carries any character that could smuggle a different host/path. Pure + total."""
    v = str(value or "").strip().lower()
    return v if _LABEL_RE.match(v) else ""


def s3_public_url(bucket: str) -> str:
    """The endpoint an anonymous client hits to test public READ of an S3 bucket: the virtual-hosted
    bucket-listing root. An anonymous GET returns the ``ListBucketResult`` XML iff the bucket grants
    ``s3:ListBucket`` to ``AllUsers``. Pure/total: a malformed bucket name yields ``""``."""
    b = _clean_label(bucket)
    return f"https://{b}.s3.amazonaws.com/" if b else ""


def gcs_public_url(bucket: str) -> str:
    """The endpoint an anonymous client hits to test public READ of a GCS bucket: the XML-API bucket
    root. An anonymous GET returns the object listing iff the bucket grants ``storage.objects.list`` to
    ``allUsers``. Pure/total: a malformed bucket name yields ``""``."""
    b = _clean_label(bucket)
    return f"https://storage.googleapis.com/{b}" if b else ""


def azure_blob_url(account: str, container: str) -> str:
    """The endpoint an anonymous client hits to test public READ of an Azure Blob container: the
    container-listing operation. An anonymous GET returns the ``EnumerationResults`` XML iff the
    container's public-access level is ``container``. Pure/total: a malformed account/container yields
    ``""``."""
    a = _clean_label(account)
    c = _clean_label(container)
    return f"https://{a}.blob.core.windows.net/{c}?restype=container&comp=list" if (a and c) else ""


# ---------------------------------------------------------------------------
# the fail-closed gate (mirror capture_handshake._authorize)
# ---------------------------------------------------------------------------


def _authorize(url: str, slug: str) -> str | None:
    """Fail-closed pre-flight for the active anonymous GET. Returns a refusal reason, or None to
    proceed. Mirrors the tool invoker's gate order (kill-switch -> entitlement -> scope) for a raw HTTP
    GET, and adds the URL-shape checks that keep the probe anonymous and single-target.

    An active probe is ALWAYS bound to an engagement: an empty ``slug`` (no charter context) is
    refused, the target must be a single http/https host in that charter's scope, and the URL must not
    embed credentials — there is no un-scoped or authenticated anonymous probe."""
    if not slug:
        return "an active probe requires an engagement slug (no charter context = no authorization)"
    try:
        from ..authority import KillSwitch
        if KillSwitch(slug).is_tripped():
            return "kill-switch tripped"
    except Exception as e:                       # a failing check REFUSES (fail-closed)
        return f"kill-switch check failed (fail-closed): {e}"
    try:
        parts = urlsplit(url)
    except Exception as e:
        return f"could not parse URL (fail-closed): {e}"
    if (parts.scheme or "").lower() not in ("http", "https"):
        return "url must be http(s)"
    # embedded userinfo would make the request authenticated — refuse (anonymous probe only)
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        return "url must not embed credentials (anonymous probe only)"
    host = (parts.hostname or "")
    if not host or not _is_single_host(host):
        return "target must be a single host (no CIDR/range/list/flag)"
    try:
        from ..entitlement import require_capability
        from ..entitlement.models import Capability
        require_capability(Capability.ACTIVE_RECON)
    except Exception as e:
        return f"active_recon not entitled: {e}"
    try:
        from ..common import ethics
        ethics.require_in_scope(slug, url)   # validates the URL's hostname against the charter scope
    except Exception as e:
        return f"out of charter scope: {e}"
    return None


# ---------------------------------------------------------------------------
# the default connector (a real, bounded, UNAUTHENTICATED GET) + capture normalisation
# ---------------------------------------------------------------------------


def _http_get(url: str, timeout: float) -> tuple[int | None, Any, bytes]:
    """The default connector: ONE bounded, UNAUTHENTICATED HTTP GET. No credentials of any kind — no
    ``Authorization`` header, no cookies, no ``.netrc`` (urllib never consults it), env proxies
    disabled (a direct probe), and redirects NOT followed (a 3xx is returned as-is, never chased). A
    non-2xx is a RESPONSE, not an error: its real status + body are returned so the oracle can judge
    them. Returns ``(status, headers, body_bytes)``; raises only on a genuine transport failure (the
    caller turns that into a ``status: None`` capture)."""
    import urllib.error
    import urllib.request

    if (urlsplit(url).scheme or "").lower() not in ("http", "https"):  # defense-in-depth vs file:// etc.
        raise ValueError("refusing non-http(s) scheme")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
            return None   # do not follow — the 3xx surfaces as an HTTPError we capture verbatim

    # build_opener with an EMPTY ProxyHandler (no env proxies) and NO auth handler -> anonymous, direct.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 (scheme validated http/https above)
            status = getattr(resp, "status", None)
            if status is None:
                status = resp.getcode()
            headers = list(resp.headers.items()) if resp.headers else []
            body = resp.read(_MAX_BODY_BYTES)
    except urllib.error.HTTPError as e:   # 3xx (not followed) / 4xx / 5xx — a real response, captured
        headers = list(e.headers.items()) if getattr(e, "headers", None) else []
        try:
            body = e.read(_MAX_BODY_BYTES)
        except Exception:
            body = b""
        return int(e.code), headers, body
    return (int(status) if status is not None else None), headers, body


def _content_type(headers: Any) -> str:
    """The ``Content-Type`` header value (case-insensitive), or ``""``. Total over a dict or an iterable
    of pairs."""
    if isinstance(headers, Mapping):
        items: Any = headers.items()
    else:
        items = headers if isinstance(headers, (list, tuple)) else ()
    for pair in items:
        try:
            k, v = pair
        except (TypeError, ValueError):
            continue
        if str(k).strip().lower() == "content-type":
            return str(v).strip()
    return ""


def _redact_snippet(raw: bytes) -> str:
    """A bounded (<=256 byte), single-line, credential-redacted preview of the body for the audit trail.
    The oracle NEVER reads this — it judges ``status`` + ``body_len`` — so aggressive masking here is
    safe and cannot affect a verdict."""
    text = bytes(raw[:_SNIPPET_BYTES]).decode("utf-8", "replace")
    text = "".join(ch if (ch.isprintable() or ch == " ") else " " for ch in text)
    for pat in _SECRET_PATTERNS:
        text = pat.sub("<redacted>", text)
    return text.strip()[:_SNIPPET_BYTES]


def _finalize_capture(url: str, status: Any, headers: Any, body: Any) -> dict:
    """Normalise a connector result into the JSON-safe retained capture the oracle judges."""
    try:
        status_i: int | None = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_i = None
    if isinstance(body, (bytes, bytearray)):
        raw = bytes(body)
    elif body is None:
        raw = b""
    else:
        raw = str(body).encode("utf-8", "replace")
    raw = raw[:_MAX_BODY_BYTES]
    return {"url": str(url or ""), "status": status_i, "body_len": len(raw),
            "snippet": _redact_snippet(raw), "content_type": _content_type(headers)[:128],
            "authenticated": False}


def capture_anonymous_get(
    url: str,
    *,
    slug: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
    connect: Callable[[str, float], tuple[int | None, Any, bytes]] | None = None,
) -> dict:
    """Reproduce a bounded, gated, UNAUTHENTICATED GET to ``url`` and return the JSON-safe capture the
    oracle judges: ``{url, status, body_len, snippet, content_type, authenticated}``. Fail-closed: a
    gate refusal or a connect failure returns ``status: None`` with a reason — never an exception, never
    a fabricated response. ``connect`` is injectable for tests (``(url, timeout) -> (status, headers,
    body)``); the default is a real bounded, credential-free GET."""
    base = {"url": str(url or ""), "status": None, "body_len": 0, "snippet": "",
            "content_type": "", "authenticated": False}
    refusal = _authorize(str(url or ""), slug)
    if refusal is not None:
        return {**base, "error": refusal}
    conn = connect or _http_get
    try:
        status, headers, body = conn(str(url), timeout)
    except Exception as e:
        return {**base, "error": f"{type(e).__name__}: {e}"[:200]}
    return _finalize_capture(str(url), status, headers, body)


# ---------------------------------------------------------------------------
# the pure oracle (routes through the SAME verifier machinery as confirm_reachable)
# ---------------------------------------------------------------------------


def anonymous_capture_context(capture: dict) -> dict:
    """The verifier context for a captured anonymous GET — routes to the active-exposure oracle."""
    return FindingContext.from_anonymous_capture(capture).to_verifier_context()


def confirm_anonymous_reachable(
    capture: dict, *, verifier: OracleVerifier | None = None
) -> VerificationResult:
    """Judge a captured anonymous GET with the deterministic oracle: ``confirmed`` iff an UNAUTHENTICATED
    request reproduced an HTTP 2xx with a present body over the concrete URL. The retained ``capture`` is
    JSON-safe, so the same verdict re-verifies offline from the finding's certificate via
    ``verify.reverify`` — modelled precisely on ``confirm_reachable``."""
    return (verifier or OracleVerifier()).confirm(anonymous_capture_context(capture))
