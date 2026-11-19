"""The LIVE cloud-connect fetcher (consumer PR-C): the trusted sovereign reader that produces the observation the
cloud-connect verdict (``governor.cloud_connect``) judges. SHIPPED OFF BY DEFAULT — ``config.cloud_connect_fetcher``
builds it only when the cloud leg is on AND the owner has provisioned VIGIL's connector identity.

WHAT IT OBSERVES (AWS, the classic cross-account read-only grant). Under VIGIL's connector credentials it:
  1. calls ``sts:AssumeRole`` on the customer's role ARN with the ISSUED external id — this must succeed;
  2. calls ``sts:GetCallerIdentity`` with the temporary credentials that returned — the account the role LANDS IN
     (only that account's IAM controller can create a role there that trusts VIGIL);
  3. calls ``sts:AssumeRole`` on the SAME role with a FRESH RANDOM external id (the same-shape NEGATIVE CONTROL) —
     this must be DENIED. A role that admits an arbitrary external id does not enforce the ``sts:ExternalId``
     condition, so ANY VIGIL tenant could name it (the confused-deputy hole) — the verdict refuses it.
It returns ``{assumed_with_external_id, account, control_external_id, control_denied}`` and decides nothing: the
deterministic verdict lives in ``governor.cloud_connect.cloud_grant_refusal``. The temporary credentials are used
for exactly one GetCallerIdentity call and are never stored, logged or returned.

EGRESS (mirrors ``governor.github_app_egress``): stdlib ``urllib`` only (FATAL-2 clean, no vendor SDK); an https-only
+ exact-host allowlist guard BEFORE any socket opens (``config.AWS_STS_EGRESS_ALLOWLIST`` — no endpoint override, so
the credential-holding egress can only reach AWS STS); a redirect-BLOCKING opener (a 3xx can never relay a signed
request); a bounded response read; an XML parse that refuses any DTD. The customer supplies only a role ARN, which is
format-checked and travels as a signed form PARAMETER, never as a URL.

ERRORS: every failure is a ``CloudFetchError``. Its ``str()`` is this module's own fixed wording (it reaches the
customer); the AWS error code/message and library text ride separately in ``detail`` for the operator audit only.
AccessDenied on step 1 means the role does not trust VIGIL with the issued external id (the customer's fix); any other
AWS error code, an HTTP 5xx or a transport fault is INCONCLUSIVE and fails closed — a control whose answer is anything
but an explicit ``AccessDenied`` is never counted as denied (VIGIL's own bad credentials also answer HTTP 403, with a
different code).

FATAL-2: sovereign-side, stdlib only, ``assert_no_offense()`` at import; no framework/strix import.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote, urlsplit

from ..reuse import assert_no_offense

assert_no_offense()

_STS_HOST = "sts.amazonaws.com"                 # the global STS endpoint (no override; the allowlist pins it)
_STS_URL = f"https://{_STS_HOST}/"
_STS_REGION = "us-east-1"                       # the SigV4 signing region of the global endpoint
_STS_SERVICE = "sts"
_STS_VERSION = "2011-06-15"
_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8"
_USER_AGENT = "VIGIL-cloud-connect"             # a generic, non-identifying client name (never a person/org)
_DEFAULT_TIMEOUT_S = 5.0                        # per blocking socket op of an STS call (connect, read); the edge's
#                                                 hop budget outwaits all three calls' worst case (3 x 2 x 5 s)
_MAX_RESPONSE_BYTES = 64 * 1024                 # an STS answer is a few hundred bytes
_SESSION_NAME = "vigil-connect"                 # what the customer's CloudTrail shows (correlatable, not hidden)
_DURATION_S = 900                               # the STS minimum: the credentials serve one GetCallerIdentity
_DENIED_CODE = "AccessDenied"

# An IAM role ARN in the aws partition: 12-digit account, role path+name (IAM's own charset), bounded.
_ROLE_ARN_RE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}")
# The external ids VIGIL issues are URL-safe base64 (secrets.token_urlsafe); AWS allows [\w+=,.@:/-]{2,1224}.
_EXTERNAL_ID_RE = re.compile(r"[A-Za-z0-9+=,.@:/_-]{2,1224}")


class CloudFetchError(Exception):
    """A cloud-connect observation could not be made. ``str(e)`` is the fetcher's OWN fixed reason and is what the
    provisioner shows the customer; ``detail`` (AWS code/message, library text) goes only to the operator audit."""

    def __init__(self, message: str, *, detail: str = "") -> None:
        super().__init__(message)
        self.detail = str(detail)[:500]


# ---------------------------------------------------------------------------------------------------------------
# AWS Signature Version 4 (pure; no clock, no network) — pinned in tests against AWS's published test-suite vector
# and against vectors botocore produced for the exact STS requests this module sends.
# ---------------------------------------------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _canonical_query(query: str) -> str:
    """The SigV4 canonical query string: each name/value URI-encoded (RFC 3986 unreserved kept), sorted."""
    if not query:
        return ""
    pairs = []
    for part in query.split("&"):
        k, _, v = part.partition("=")
        pairs.append((quote(k, safe="-_.~"), quote(v, safe="-_.~")))
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def sigv4_authorization(*, method: str, host: str, path: str, query: str, headers: Mapping[str, str], body: bytes,
                        region: str, service: str, access_key_id: str, secret_access_key: str,
                        amz_date: str) -> str:
    """The ``Authorization`` header value for one request under AWS SigV4. ``headers`` are the headers to SIGN
    (``host`` and ``x-amz-date`` must be among them; names are lower-cased here); ``amz_date`` is
    ``YYYYMMDD'T'HHMMSS'Z'``. Pure and deterministic."""
    signed = {str(k).strip().lower(): " ".join(str(v).split()) for k, v in headers.items()}
    if "host" not in signed or "x-amz-date" not in signed:
        raise ValueError("SigV4 needs the host and x-amz-date headers signed")
    names = sorted(signed)
    canonical_headers = "".join(f"{n}:{signed[n]}\n" for n in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join([method.upper(), path or "/", _canonical_query(query), canonical_headers,
                                   signed_headers, _sha256_hex(body)])
    date = amz_date[:8]
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                _sha256_hex(canonical_request.encode("utf-8"))])
    k = _hmac(("AWS4" + secret_access_key).encode("utf-8"), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    k = _hmac(k, "aws4_request")
    signature = hmac.new(k, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return (f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, "
            f"Signature={signature}")


def _form(params: "list[tuple[str, str]]") -> bytes:
    """An application/x-www-form-urlencoded body (RFC 3986 encoding, the encoding the AWS query protocol expects)."""
    return "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in params).encode("ascii")


def _amz_date(epoch: float) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(float(epoch)))


# ---------------------------------------------------------------------------------------------------------------
# The guarded egress (mirrors github_app_egress: guard -> redirect-blocking open -> bounded read)
# ---------------------------------------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a 3xx (a signed request is never relayed elsewhere): the 3xx becomes a non-2xx HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _do_open(req, timeout):
    """The single outbound open point (redirects blocked) — also the seam the tests patch to stand in a FAKE STS."""
    return _OPENER.open(req, timeout=timeout)   # noqa: S310 — https + host pinned by _guard; redirects blocked


def _allowlist() -> frozenset:
    """The STS egress host allowlist, read from ``config`` at call time. Empty ⇒ every host refused."""
    from .. import config
    return frozenset(h.lower() for h in config.AWS_STS_EGRESS_ALLOWLIST)


def _guard(url: str) -> None:
    """Refuse a non-https scheme, userinfo, a non-default port, or an off-allowlist host BEFORE any socket opens."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise CloudFetchError("the cloud check could not be made", detail=f"non-https STS URL {parts.scheme!r}")
    if "@" in (parts.netloc or ""):
        raise CloudFetchError("the cloud check could not be made", detail="STS URL carries userinfo")
    try:
        port = parts.port
    except ValueError:
        raise CloudFetchError("the cloud check could not be made", detail="malformed STS port") from None
    if port not in (None, 443):
        raise CloudFetchError("the cloud check could not be made", detail="non-default STS port")
    host = (parts.hostname or "").lower()
    if host not in _allowlist():
        raise CloudFetchError("the cloud check could not be made", detail=f"non-allowlisted STS host {host!r}")


def _post(url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> "tuple[int, bytes]":
    """One guarded POST: ``(status, body)``, the body bounded. An HTTP error status is RETURNED (its AWS error
    document is what tells AccessDenied from a fault); only a transport failure raises."""
    _guard(url)
    req = urllib.request.Request(url, data=body, method="POST", headers=dict(headers))
    try:
        with _do_open(req, timeout) as r:
            raw = r.read(_MAX_RESPONSE_BYTES + 1)
            status = int(getattr(r, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(_MAX_RESPONSE_BYTES + 1) or b""
        except Exception:  # noqa: BLE001 — an unreadable error body is an empty one
            raw = b""
        status = int(exc.code) if isinstance(exc.code, int) else 0
    except Exception as exc:  # noqa: BLE001 — any transport fault fails closed, never a crash
        raise CloudFetchError("AWS could not be reached to make the cloud check; try again shortly",
                              detail=f"{type(exc).__name__}: {exc}") from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise CloudFetchError("the cloud check could not be made", detail="STS response exceeded the size cap")
    return status, raw


def _xml(raw: bytes):
    """Parse an STS XML answer, refusing any DTD/entity declaration (the answers carry none). None on any fault."""
    import xml.etree.ElementTree as ET
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        return None
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None


def _find(root, name: str) -> str:
    """The text of the first descendant element whose local name is ``name`` ("" when absent) — namespace-agnostic."""
    if root is None:
        return ""
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""
        if tag == name:
            return (el.text or "").strip()
    return ""


class AwsStsConnectFetcher:
    """Observe an AWS cross-account read-only grant under VIGIL's connector identity (see the module docstring).
    ``transport`` is an injectable ``(url, headers, body, timeout) -> (status, body)`` for offline tests (a FAKE STS
    that still goes through the guard); ``clock`` supplies the signing time."""

    def __init__(self, *, access_key_id: str, secret_access_key: str, session_token: str = "",
                 timeout: float = _DEFAULT_TIMEOUT_S,
                 transport: "Optional[Callable[[str, Mapping[str, str], bytes, float], tuple[int, bytes]]]" = None,
                 clock: Callable[[], float] = time.time) -> None:
        if not access_key_id or not secret_access_key:
            raise ValueError("the AWS connector credentials are required")
        self._key_id = str(access_key_id)
        self._secret = str(secret_access_key)
        self._token = str(session_token or "")
        self._timeout = float(timeout)
        self._transport = transport
        self._clock = clock

    def __repr__(self) -> str:                    # never render a credential
        return "AwsStsConnectFetcher(<connector credentials redacted>)"

    def _call(self, params: "list[tuple[str, str]]", *, key_id: str, secret: str, token: str) -> "tuple[int, Any]":
        body = _form(params)
        amz_date = _amz_date(self._clock())
        signed = {"host": _STS_HOST, "x-amz-date": amz_date, "content-type": _CONTENT_TYPE}
        if token:
            signed["x-amz-security-token"] = token
        auth = sigv4_authorization(method="POST", host=_STS_HOST, path="/", query="", headers=signed, body=body,
                                   region=_STS_REGION, service=_STS_SERVICE, access_key_id=key_id,
                                   secret_access_key=secret, amz_date=amz_date)
        headers = {"Content-Type": _CONTENT_TYPE, "X-Amz-Date": amz_date, "Authorization": auth,
                   "User-Agent": _USER_AGENT, "Accept": "text/xml"}
        if token:
            headers["X-Amz-Security-Token"] = token
        if self._transport is not None:
            _guard(_STS_URL)                       # a fake STS still exercises the egress pin
            try:
                status, raw = self._transport(_STS_URL, headers, body, self._timeout)
            except CloudFetchError:
                raise
            except Exception as exc:  # noqa: BLE001 — a transport fault fails closed
                raise CloudFetchError("AWS could not be reached to make the cloud check; try again shortly",
                                      detail=f"{type(exc).__name__}: {exc}") from None
        else:
            status, raw = _post(_STS_URL, headers, body, self._timeout)
        return int(status), _xml(bytes(raw or b""))

    def _assume(self, role_arn: str, external_id: str) -> "tuple[str, dict]":
        """AssumeRole: ``("ok", creds)`` | ``("denied", {})`` (an explicit AccessDenied). Anything else raises."""
        status, root = self._call([("Action", "AssumeRole"), ("Version", _STS_VERSION), ("RoleArn", role_arn),
                                   ("RoleSessionName", _SESSION_NAME), ("ExternalId", external_id),
                                   ("DurationSeconds", str(_DURATION_S))],
                                  key_id=self._key_id, secret=self._secret, token=self._token)
        if status == 200:
            creds = {"key_id": _find(root, "AccessKeyId"), "secret": _find(root, "SecretAccessKey"),
                     "token": _find(root, "SessionToken")}
            if not all(creds.values()):
                raise CloudFetchError("the cloud check could not be made", detail="AssumeRole answer had no credentials")
            return "ok", creds
        code = _find(root, "Code")
        if status == 403 and code == _DENIED_CODE:
            return "denied", {}
        raise CloudFetchError("the cloud check could not be completed; try again shortly",
                              detail=f"AssumeRole HTTP {status} {code}: {_find(root, 'Message')}")

    def _caller_account(self, creds: dict) -> str:
        status, root = self._call([("Action", "GetCallerIdentity"), ("Version", _STS_VERSION)],
                                  key_id=creds["key_id"], secret=creds["secret"], token=creds["token"])
        account = _find(root, "Account")
        if status != 200 or not re.fullmatch(r"[0-9]{12}", account):
            raise CloudFetchError("the cloud check could not be completed; try again shortly",
                                  detail=f"GetCallerIdentity HTTP {status} {_find(root, 'Code')}")
        return account

    def assume(self, *, provider: str, account_id: str, role_ref: str, external_id: str, control_external_id: str,
               now: Any = None) -> dict:
        """Observe the grant (module docstring): ``{assumed_with_external_id, account, control_external_id,
        control_denied}``. Raises ``CloudFetchError`` (fail closed) on a malformed input, a role that does not trust
        VIGIL with the issued external id, or any inconclusive answer. ``now`` is accepted for interface symmetry
        with the ownership fetcher (the signing clock is ``clock``)."""
        if str(provider or "") != "aws":
            raise CloudFetchError("only AWS accounts can be connected", detail=f"provider {provider!r}")
        role = str(role_ref or "").strip()
        m = _ROLE_ARN_RE.fullmatch(role)
        if not m:
            raise CloudFetchError("give the role's full ARN, e.g. arn:aws:iam::123456789012:role/VigilSecurityAudit")
        if m.group(1) != str(account_id or ""):
            raise CloudFetchError("the role ARN names a different AWS account than the one you are connecting")
        ext, ctl = str(external_id or ""), str(control_external_id or "")
        if not _EXTERNAL_ID_RE.fullmatch(ext) or not _EXTERNAL_ID_RE.fullmatch(ctl) or hmac.compare_digest(ext, ctl):
            raise CloudFetchError("the cloud check could not be made", detail="bad external id / control id")
        outcome, creds = self._assume(role, ext)
        if outcome != "ok":
            raise CloudFetchError("VIGIL could not assume the role with the external id shown — check the role's "
                                  "trust policy (the principal and the sts:ExternalId condition) and try again")
        account = self._caller_account(creds)
        creds.clear()                              # the temporary credentials served their one call
        control, _ = self._assume(role, ctl)       # the same role, a fresh random id: must be explicitly DENIED
        return {"assumed_with_external_id": ext, "account": account, "control_external_id": ctl,
                "control_denied": control == "denied"}
