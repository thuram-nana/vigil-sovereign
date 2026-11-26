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

WHAT IT OBSERVES (GCP, a cross-project service-account IMPERSONATION grant — NAME-bound). Under VIGIL's connector
service-account credentials (``GcpImpersonationConnectFetcher``) it:
  1. authenticates VIGIL's connector SA — signs a service-account assertion JWT (RS256 over the connector SA private
     key) and exchanges it at ``oauth2.googleapis.com`` for a connector access token;
  2. computes the EXACT, challenge-bound SA email from the project + the unguessable external id (``vgl-`` + a
     SHA-256 tag — see ``_gcp_expected_sa_email``, never customer-steered), and calls
     ``iamcredentials:generateAccessToken`` on THAT email. A 200 is the WHOLE positive proof: an SA whose NAME
     encodes THIS challenge exists in the project (only the project admin could create a name derived from the
     unguessable external id), VIGIL holds ``roles/iam.serviceAccountTokenCreator`` on it, and it is in the claimed
     project (VIGIL built the email from ``account_id``). A 403/404 is the customer's fix (create the SA + grant);
     anything else is INCONCLUSIVE and fails closed.
The confused-deputy closure is the unguessable per-challenge NAME. There is deliberately NO metadata read (reading an
SA's own resource under its impersonated token 403s — a target SA has no self-read) and NO never-created "control SA"
(a never-created SA is ALWAYS denied in real GCP, so it can never catch a blanket grant — a vacuous control). It
returns ``{impersonated, expected_email, project, external_id}`` and decides nothing: the deterministic verdict lives
in ``governor.cloud_connect.cloud_grant_refusal`` (its gcp branch). The connector token is used for exactly this
impersonation and is never stored, logged or returned.

ERRORS: every failure is a ``CloudFetchError``. Its ``str()`` is this module's own fixed wording (it reaches the
customer); the AWS/Google error code/message and library text ride separately in ``detail`` for the operator audit
only. AccessDenied on the AWS step-1 assume (or a 403 PERMISSION_DENIED on the GCP target impersonation) means the
grant is absent (the customer's fix); any other error code, an HTTP 5xx or a transport fault is INCONCLUSIVE and fails
closed — a control whose answer is anything but an explicit denial/not-found is never counted as denied (VIGIL's own
bad credentials also answer HTTP 403, with a different code).

FATAL-2: sovereign-side, ``assert_no_offense()`` at import; no framework/strix import. The AWS leg is stdlib-only; the
GCP leg additionally uses the sovereign ``cryptography`` dep (the same library ``governor.github_app`` uses) for the
one RSA-SHA256 JWT signature — ``cryptography`` is NOT an offense engine, so FATAL-2 holds.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
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


# ---------------------------------------------------------------------------------------------------------------
# GCP service-account IMPERSONATION leg (confused-deputy-safe cross-project proof-of-control). The connector SA
# assertion JWT is RS256-signed with the sovereign ``cryptography`` dep; everything else is stdlib ``urllib`` with
# the same guarded-egress discipline as the AWS leg (guard -> redirect-blocking open -> bounded read).
#
# PROOF (NAME-BINDING): VIGIL computes, from the (trusted) project + the unguessable external id, the EXACT
# service-account id the customer must create — local part ``vgl-`` + a SHA-256 tag of a domain-separated external
# id (deterministic, lowercase, inside GCP's 6-30 char SA-id rule). VIGIL impersonates THAT email; a 200 proves, in
# one call, that (a) an SA whose NAME encodes THIS challenge exists in the project — only the project admin could
# create a name derived from the unguessable external id — (b) VIGIL holds roles/iam.serviceAccountTokenCreator on
# it, and (c) the SA is IN ``account_id`` (VIGIL built the email from ``account_id``). The confused-deputy closure is
# the unguessable per-challenge NAME (a malicious VIGIL tenant cannot guess another customer's external id, so cannot
# make VIGIL impersonate a matching-named SA in a project it does not control) — NOT a negative control. No metadata
# read and no never-created "control SA" are made: the first would 403 in real GCP (a target SA has no self-read),
# and the second is vacuous (a never-created SA is ALWAYS denied, so it could never catch a blanket grant).
#
# VIGIL-LIMIT:LIMIT-cloud-connect-gcp-livefire — request construction, RS256 signing, JSON parsing and the verdict
# are covered OFFLINE in full; the live GCP round-trip (token exchange + generateAccessToken on the challenge-named
# SA) is not exercised in CI, as the hash-locked CI env has no live GCP project / connector SA.
# ---------------------------------------------------------------------------------------------------------------

_OAUTH_HOST = "oauth2.googleapis.com"
_OAUTH_TOKEN_URL = f"https://{_OAUTH_HOST}/token"
_IAMCREDS_HOST = "iamcredentials.googleapis.com"
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_JSON_CONTENT_TYPE = "application/json; charset=utf-8"
_GCP_JWT_LIFETIME_S = 300          # the connector assertion's iat..exp window — a short, conservative bound
_IMPERSONATION_LIFETIME = "300s"   # the minted impersonation token's lifetime (the generateAccessToken body)

# A GCP project id: a lowercase letter, then [a-z0-9-], 6-30 chars total, no trailing hyphen. (The target SA email
# is VIGIL-COMPUTED, never customer-parsed, so no SA-email regex is needed on this leg.)
_GCP_PROJECT_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_GCP_DENIED_STATUS = frozenset({"PERMISSION_DENIED", "NOT_FOUND"})

# The challenge-bound SA id derivation (DUPLICATED byte-for-byte in governor.cloud_connect, pinned equal by a test —
# the same pattern as the AWS role-ARN regex). "vgl-" + 20 lowercase hex of a domain-separated SHA-256 of the
# external id = 24 chars, which always satisfies GCP's SA-id rule (^[a-z][a-z0-9-]{4,28}[a-z0-9]$, 6-30 chars).
_GCP_SA_ID_DOMAIN = "vigil-cloud-connect-gcp-sa-id:v1:"


def _gcp_expected_sa_id(external_id: str) -> str:
    return "vgl-" + hashlib.sha256((_GCP_SA_ID_DOMAIN + str(external_id)).encode("utf-8")).hexdigest()[:20]


def _gcp_expected_sa_email(project: str, external_id: str) -> str:
    return f"{_gcp_expected_sa_id(external_id)}@{project}.iam.gserviceaccount.com"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_rs256(signing_input: bytes, pem: str) -> bytes:
    """An RSA-SHA256 (PKCS#1 v1.5) signature over ``signing_input`` with the connector SA private-key PEM. Uses the
    sovereign ``cryptography`` dep (imported here, function-local — the module stays import-light). Any
    unreadable/encrypted/non-RSA key fails closed with a secret-free detail."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception as exc:  # noqa: BLE001 — any unreadable/encrypted/garbage PEM is a fail-closed refusal
        raise CloudFetchError("the cloud check could not be made",
                              detail=f"connector key not a readable unencrypted PEM ({type(exc).__name__})") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CloudFetchError("the cloud check could not be made", detail="connector key is not an RSA key")
    return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def _gcp_allowlist() -> frozenset:
    """The GCP egress host allowlist, read from ``config`` at call time. Empty ⇒ every host refused."""
    from .. import config
    return frozenset(h.lower() for h in config.GCP_EGRESS_ALLOWLIST)


def _gcp_guard(url: str) -> None:
    """Refuse a non-https scheme, userinfo, a non-default port, or an off-allowlist host BEFORE any socket opens
    (mirrors ``_guard``; the per-endpoint allowlist pins the three Google hosts this leg may reach)."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise CloudFetchError("the cloud check could not be made", detail=f"non-https Google URL {parts.scheme!r}")
    if "@" in (parts.netloc or ""):
        raise CloudFetchError("the cloud check could not be made", detail="Google URL carries userinfo")
    try:
        port = parts.port
    except ValueError:
        raise CloudFetchError("the cloud check could not be made", detail="malformed Google port") from None
    if port not in (None, 443):
        raise CloudFetchError("the cloud check could not be made", detail="non-default Google port")
    host = (parts.hostname or "").lower()
    if host not in _gcp_allowlist():
        raise CloudFetchError("the cloud check could not be made", detail=f"non-allowlisted Google host {host!r}")


def _json_body(raw: bytes):
    """Parse a Google JSON answer into a dict ({} on any fault / non-object). JSON carries no DTD/entity surface."""
    try:
        v = json.loads(bytes(raw or b"").decode("utf-8"))
    except Exception:  # noqa: BLE001 — a malformed body is an empty object (fail-closed at the call site)
        return {}
    return v if isinstance(v, dict) else {}


def _gcp_request(method: str, url: str, headers: Mapping[str, str], body, timeout: float) -> "tuple[int, bytes]":
    """One guarded request to a Google endpoint: ``(status, body)``, the body bounded. An HTTP error status is
    RETURNED (its Google error document tells PERMISSION_DENIED from a fault); only a transport failure raises."""
    _gcp_guard(url)
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=dict(headers))
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
        raise CloudFetchError("Google could not be reached to make the cloud check; try again shortly",
                              detail=f"{type(exc).__name__}: {exc}") from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise CloudFetchError("the cloud check could not be made", detail="Google response exceeded the size cap")
    return status, raw


class GcpImpersonationConnectFetcher:
    """Observe a GCP cross-project service-account impersonation grant under VIGIL's connector SA (module docstring).
    ``transport`` is an injectable ``(method, url, headers, body, timeout) -> (status, body)`` for offline tests (a
    FAKE Google that still goes through ``_gcp_guard``); ``clock`` supplies the JWT signing time. SAME ``assume``
    signature as ``AwsStsConnectFetcher`` so the provisioner dispatches either behind one seam."""

    def __init__(self, *, connector_email: str, private_key_pem: str, timeout: float = _DEFAULT_TIMEOUT_S,
                 transport: "Optional[Callable[[str, str, Mapping[str, str], Any, float], tuple[int, bytes]]]" = None,
                 clock: Callable[[], float] = time.time) -> None:
        if not connector_email or not private_key_pem:
            raise ValueError("the GCP connector credentials are required")
        self._email = str(connector_email)
        self._key_pem = str(private_key_pem)
        self._timeout = float(timeout)
        self._transport = transport
        self._clock = clock

    def __repr__(self) -> str:                    # never render the connector key
        return "GcpImpersonationConnectFetcher(<connector credentials redacted>)"

    def _call(self, method: str, url: str, body, headers: Mapping[str, str], *, bearer) -> "tuple[int, Any]":
        hdrs = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
        hdrs.update(dict(headers or {}))
        if bearer:
            hdrs["Authorization"] = "Bearer " + str(bearer)
        if self._transport is not None:
            _gcp_guard(url)                        # a fake Google still exercises the egress pin
            try:
                status, raw = self._transport(method, url, hdrs, body, self._timeout)
            except CloudFetchError:
                raise
            except Exception as exc:  # noqa: BLE001 — a transport fault fails closed
                raise CloudFetchError("Google could not be reached to make the cloud check; try again shortly",
                                      detail=f"{type(exc).__name__}: {exc}") from None
        else:
            status, raw = _gcp_request(method, url, hdrs, body, self._timeout)
        return int(status), _json_body(bytes(raw or b""))

    def _connector_token(self) -> str:
        """Step 1: a connector access token from the SA assertion JWT (RS256), exchanged at oauth2.googleapis.com."""
        now = int(self._clock())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {"iss": self._email, "sub": self._email, "aud": _OAUTH_TOKEN_URL, "scope": _CLOUD_PLATFORM_SCOPE,
                  "iat": now, "exp": now + _GCP_JWT_LIFETIME_S}
        seg = (_b64url(json.dumps(header, separators=(",", ":")).encode("ascii")) + "." +
               _b64url(json.dumps(claims, separators=(",", ":")).encode("ascii")))
        assertion = seg + "." + _b64url(_sign_rs256(seg.encode("ascii"), self._key_pem))
        body = _form([("grant_type", _JWT_BEARER_GRANT), ("assertion", assertion)])
        status, data = self._call("POST", _OAUTH_TOKEN_URL, body, {"Content-Type": _FORM_CONTENT_TYPE}, bearer=None)
        token = data.get("access_token")
        if status != 200 or not isinstance(token, str) or not token:
            raise CloudFetchError("the cloud check could not be completed; try again shortly",
                                  detail=f"token exchange HTTP {status} {data.get('error')}")
        return token

    def _generate_token(self, sa_email: str, bearer: str) -> "tuple[str, str]":
        """generateAccessToken on ``sa_email``: ``("ok", token)`` | ``("denied", "")`` (an explicit 403
        PERMISSION_DENIED / 404 NOT_FOUND). Anything else raises (INCONCLUSIVE, fail closed)."""
        url = (f"https://{_IAMCREDS_HOST}/v1/projects/-/serviceAccounts/"
               f"{quote(sa_email, safe='@._-')}:generateAccessToken")
        body = json.dumps({"scope": [_CLOUD_PLATFORM_SCOPE], "lifetime": _IMPERSONATION_LIFETIME}).encode("utf-8")
        status, data = self._call("POST", url, body, {"Content-Type": _JSON_CONTENT_TYPE}, bearer=bearer)
        if status == 200:
            token = data.get("accessToken")
            if not isinstance(token, str) or not token:
                raise CloudFetchError("the cloud check could not be made",
                                      detail="generateAccessToken answer carried no token")
            return "ok", token
        err = data.get("error") if isinstance(data.get("error"), dict) else {}
        code = str(err.get("status") or "")
        if status in (403, 404) and code in _GCP_DENIED_STATUS:
            return "denied", ""
        raise CloudFetchError("the cloud check could not be completed; try again shortly",
                              detail=f"generateAccessToken HTTP {status} {code}")

    def assume(self, *, provider: str, account_id: str, role_ref: str, external_id: str, control_external_id: str = "",
               now: Any = None) -> dict:
        """Observe the grant (module docstring): ``{impersonated, expected_email, project, external_id}``. VIGIL
        computes the EXPECTED, challenge-bound SA email from ``account_id`` + ``external_id`` (never customer-steered),
        requires the submitted ``role_ref`` to equal it (so the recorded grant is the SA that was proven), and
        impersonates THAT email. A 200 is the whole positive proof. Raises ``CloudFetchError`` (fail closed) on a
        malformed input, a submitted SA that is not the one shown, a grant VIGIL cannot use yet (403/404 — the
        customer's fix), or any inconclusive answer. ``control_external_id`` / ``now`` are accepted for interface
        symmetry with the AWS fetcher; GCP binds the challenge by SA NAME and needs no negative control."""
        if str(provider or "") != "gcp":
            raise CloudFetchError("only GCP projects can be connected here", detail=f"provider {provider!r}")
        project = str(account_id or "").strip()
        if not _GCP_PROJECT_RE.fullmatch(project):
            raise CloudFetchError("give the GCP project id you are connecting, e.g. my-company-prod")
        ext = str(external_id or "")
        if not _EXTERNAL_ID_RE.fullmatch(ext):
            raise CloudFetchError("the cloud check could not be made", detail="bad external id")
        expected_email = _gcp_expected_sa_email(project, ext)          # computed from TRUSTED (project, external id)
        submitted = str(role_ref or "").strip()
        if not hmac.compare_digest(submitted, expected_email):
            raise CloudFetchError("create and connect the exact service account shown on the connect screen "
                                  f"({expected_email})")
        connector = self._connector_token()                            # step 1: VIGIL's connector access token
        outcome, _tok = self._generate_token(expected_email, connector)  # step 2: impersonate the challenge-named SA
        if outcome != "ok":
            raise CloudFetchError("VIGIL could not impersonate the service account shown — create exactly that "
                                  "service account and grant VIGIL's connector the "
                                  "roles/iam.serviceAccountTokenCreator role on it, then try again")
        return {"impersonated": True, "expected_email": expected_email, "project": project, "external_id": ext}
