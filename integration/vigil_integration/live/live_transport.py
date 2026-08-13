"""live_transport — the REAL network binding for the E-series ``Transport`` seam (E1 / E3 / E5).

``imds_runner`` defines the seam every achieved-effect cloud runner reaches the network through::

    Transport = Callable[[str, str], TransportResult]          # (method, url) -> TransportResult

…and until now the ONLY implementations were mocks in the unit tests, which is exactly why no E-series
runner had ever fired against a real provider. This module is that missing binding: a real httpx client
that performs the request AND — the part that actually matters — reports the transport-provenance fields
the oracle's anti-laundering gate checks (``oracles._confirming_call_trusted``) **truthfully**.

THE ONE RULE HERE: every provenance field is DERIVED FROM THE CONNECTION, never asserted.

  * ``tls_verified`` — True only when the request was https, the connection really carries a TLS object,
    that TLS object yields a peer CERTIFICATE (``getpeercert()`` returns ``{}`` unless the chain was
    validated), and our SSL context is genuinely verifying (``CERT_REQUIRED`` + ``check_hostname``). Any
    step we cannot establish ⇒ False.
  * ``via_proxy`` — False only when we can AFFIRMATIVELY show the client cannot interpose one: the client
    was built with ``trust_env=False`` (so no ambient ``HTTP(S)_PROXY`` / ``ALL_PROXY`` / ``NO_PROXY`` env
    can silently redirect us) and carries NO proxy mounts. If we cannot establish that ⇒ True, i.e. the
    honest negative that makes the oracle refuse.
  * ``redirected`` — the client is built with ``follow_redirects=False``; a 3xx is REPORTED as redirected
    rather than followed, and any non-empty redirect history also counts.
  * ``resolved_peer`` — the ACTUAL peer of the socket that carried this response
    (``extensions["network_stream"].get_extra_info("server_addr")``), read while the response is still
    streaming. It is deliberately NOT a DNS re-resolution afterwards: a re-resolution can return a
    different address than the one the bytes came from, which would be evidence about the wrong thing.
  * body — read BOUNDED (``_MAX_BODY``, the same cap ``imds_runner.response_digest`` hashes under). A body
    that exceeds the cap is reported truncated and is NOT parsed as JSON, so a truncated (therefore
    unsound) identity echo can never reach an oracle.

FAIL CLOSED: no field ever defaults to the permissive value. A missing network stream, an exception while
introspecting the socket, an http:// URL, an over-long body — each degrades to the value that makes the
oracle REFUSE, never to the one that lets it fire.

CREDENTIAL FACTORIES. A confirming call must authenticate with the captured credential, so the credential
has to reach the transport. It does so through a FACTORY — ``CredentialTransport = (secret) -> Transport``
— rather than the caller pre-building an authenticated transport. That is not a style choice: it lets the
runner bind the EXACT string it fingerprinted into the transport it then calls, so the fingerprint stamped
on the confirming call cannot silently describe a different credential than the one that authenticated.
Two are provided: ``bearer_transport_factory`` (GitHub) and ``sigv4_transport_factory`` (AWS STS).

FATAL-2 / purity: module scope is stdlib only; ``httpx`` is imported FUNCTION-LOCALLY, so importing this
module co-loads neither the offense engine nor a network stack.
"""

from __future__ import annotations

import hashlib
import hmac
import ssl
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote, urlsplit

from .imds_runner import TransportResult

# The bounded read. Matches ``imds_runner._MAX_BODY`` (the cap ``response_digest`` hashes under), so the
# digest we retain is a digest of bytes we actually held, never of a silently-truncated prefix.
_MAX_BODY = 65536
_DEFAULT_TIMEOUT = 20.0
# Correlatable by construction (constitution §VI.4): the operator must be able to grep their logs — and
# the provider's audit log — and find exactly this traffic. No rotation, no evasion.
_USER_AGENT = "OBSIDIAN/1.0 (authorized owner-test; VIGIL E-series live capture)"

# A transport factory bound to a credential: (plaintext secret) -> Transport.
CredentialTransport = Callable[[str], Callable[[str, str], TransportResult]]


class TransportUnavailable(RuntimeError):
    """Raised when a genuinely-verifying transport cannot be constructed (httpx absent, or an SSL context
    that is not actually verifying). We refuse to hand back a transport that would have to lie."""


# ======================================================================================================
# provenance extraction — each helper answers ONE question about the connection that carried the bytes
# ======================================================================================================

def _verifying_ssl_context() -> ssl.SSLContext:
    """A genuinely-verifying SSL context, or refuse. ``create_default_context`` is already
    CERT_REQUIRED + check_hostname; we re-assert it rather than assume, and never relax it."""
    ctx = ssl.create_default_context()
    try:                                   # prefer certifi's bundle when present; the system store otherwise
        import certifi                     # noqa: PLC0415
        ctx.load_verify_locations(certifi.where())
    except Exception:                      # noqa: BLE001 — no bundle is fine; the default store still verifies
        pass
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise TransportUnavailable("refusing to build a transport whose SSL context does not verify")
    return ctx


def _network_stream(response: Any) -> Any:
    """The httpcore network stream that carried this response, or None. Total (never raises)."""
    try:
        return response.extensions.get("network_stream")
    except Exception:                      # noqa: BLE001 — no stream ⇒ no provenance ⇒ fail closed
        return None


def resolved_peer_of(response: Any) -> str:
    """The ACTUAL peer address the response bytes came from — ``getpeername()`` on the live socket, via
    ``server_addr``. Empty string when it cannot be established (⇒ the oracle refuses:
    ``confirming_call_peer_unrecorded``). NOT a DNS re-resolution: that would describe a different
    connection than the one we made."""
    stream = _network_stream(response)
    if stream is None:
        return ""
    try:
        addr = stream.get_extra_info("server_addr")
    except Exception:                      # noqa: BLE001
        return ""
    if isinstance(addr, (tuple, list)) and addr:
        return str(addr[0]).strip()
    if isinstance(addr, str):
        return addr.strip()
    return ""


def tls_verified_of(response: Any, context: Optional[ssl.SSLContext], scheme: str) -> bool:
    """Whether THIS connection's certificate chain was genuinely validated. True requires ALL of: an https
    request; a real TLS object on the carrying socket; a NON-EMPTY peer certificate from it (CPython returns
    ``{}`` from ``getpeercert()`` when the peer was not validated); and a context that is verifying with
    hostname checking. Anything we cannot establish ⇒ False. Never asserted from ``verify=True`` alone."""
    if scheme.lower() != "https":
        return False
    if context is None or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        return False
    stream = _network_stream(response)
    if stream is None:
        return False
    try:
        ssl_object = stream.get_extra_info("ssl_object")
    except Exception:                      # noqa: BLE001
        return False
    if ssl_object is None:
        return False
    try:
        return bool(ssl_object.getpeercert())
    except Exception:                      # noqa: BLE001
        return False


def via_proxy_of(client: Any) -> bool:
    """Whether a proxy could have interposed. False ONLY when we can affirmatively show it could not: the
    client carries no proxy mounts AND was built with ``trust_env=False`` (no ambient proxy env is read).
    Anything else — including 'we could not tell' — is True, the honest negative that makes the oracle
    refuse (``confirming_call_transport_not_direct``)."""
    mounts = getattr(client, "_mounts", None)
    if not isinstance(mounts, dict) or mounts:
        return True
    trust_env = getattr(client, "trust_env", None)
    if trust_env is None:
        trust_env = getattr(client, "_trust_env", None)
    return trust_env is not False


def redirected_of(response: Any) -> bool:
    """Whether the request met a redirect. True on any 3xx (we do NOT follow it — it is reported), and on
    any non-empty redirect history. Errs toward True when the status cannot be read."""
    try:
        history = response.history
    except Exception:                      # noqa: BLE001
        return True
    if history:
        return True
    try:
        return 300 <= int(response.status_code) < 400
    except Exception:                      # noqa: BLE001
        return True


def _read_bounded(response: Any, limit: int) -> "tuple[bytes, bool]":
    """Read at most ``limit`` bytes. Returns ``(body, truncated)``. We deliberately pull one byte past the
    limit so truncation is DETECTED rather than silently producing a short body that looks complete."""
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            break
    body = b"".join(chunks)
    return (body[:limit], True) if len(body) > limit else (body, False)


def _parse_json(body: bytes, truncated: bool) -> Optional[Mapping[str, Any]]:
    """The parsed body, or None. A TRUNCATED body is never parsed: half a JSON document cannot honestly
    supply an identity echo, and a partial parse would be evidence about bytes we do not have."""
    if truncated or not body:
        return None
    import json                            # noqa: PLC0415
    try:
        parsed = json.loads(body.decode("utf-8", "replace"))
    except Exception:                      # noqa: BLE001
        return None
    return parsed if isinstance(parsed, Mapping) else None


# ======================================================================================================
# the transport itself
# ======================================================================================================

class LiveTransport:
    """A real, single-purpose ``Transport``: callable as ``(method, url) -> TransportResult``.

    Constructed with proxies disabled, redirects NOT followed, and TLS verification on — and it reports
    what the connection actually did rather than what it was configured to do. Close it when finished
    (or use it as a context manager); a transport built with a credential should be closed promptly so the
    authenticated connection is not left pooled.
    """

    def __init__(self, *, headers: Optional[Mapping[str, str]] = None,
                 content: Optional[bytes] = None,
                 signer: Optional[Callable[[str, str, bytes], Mapping[str, str]]] = None,
                 timeout: float = _DEFAULT_TIMEOUT, max_body: int = _MAX_BODY) -> None:
        try:
            import httpx                    # noqa: PLC0415 (FATAL-2: function/consumer-local)
        except ImportError as exc:          # pragma: no cover - environment-dependent
            raise TransportUnavailable("httpx is not installed; no live transport is available") from exc
        self._context = _verifying_ssl_context()
        self._headers = {"User-Agent": _USER_AGENT, **dict(headers or {})}
        self._content = content
        self._signer = signer
        self._max_body = int(max_body)
        # trust_env=False: no ambient proxy/CA env can interpose. follow_redirects=False: a 3xx is
        # EVIDENCE, not something to chase. verify=<verifying context>: a real chain validation.
        self._client = httpx.Client(verify=self._context, trust_env=False, follow_redirects=False,
                                    timeout=timeout, mounts={})

    # -- lifecycle ------------------------------------------------------------------------------------
    def close(self) -> None:
        try:
            self._client.close()
        except Exception:                   # noqa: BLE001 — closing must never mask a result
            pass

    def __enter__(self) -> "LiveTransport":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # -- the Transport call ---------------------------------------------------------------------------
    def __call__(self, method: str, url: str) -> TransportResult:
        scheme = (urlsplit(url).scheme or "").lower()
        content = self._content if method.upper() not in ("GET", "HEAD") else None
        headers = dict(self._headers)
        if self._signer is not None:
            headers.update(self._signer(method, url, content or b""))
        request = self._client.build_request(method, url, headers=headers, content=content)
        response = self._client.send(request, stream=True)
        try:
            # Read the provenance while the response is still STREAMING: the socket is live here, so
            # getpeername()/the TLS object describe the connection that actually carried these bytes.
            # Once the response is released back to the pool this is no longer reliably answerable.
            peer = resolved_peer_of(response)
            tls = tls_verified_of(response, self._context, scheme)
            redirected = redirected_of(response)
            body, truncated = _read_bounded(response, self._max_body)
            status = int(response.status_code)
        finally:
            response.close()
        return TransportResult(status=status, body=body, resolved_peer=peer, tls_verified=tls,
                               via_proxy=via_proxy_of(self._client), redirected=redirected,
                               json=_parse_json(body, truncated))


def live_transport(*, headers: Optional[Mapping[str, str]] = None, content: Optional[bytes] = None,
                   timeout: float = _DEFAULT_TIMEOUT) -> LiveTransport:
    """An unauthenticated real transport (the plain IMDS/metadata GET leg of E1)."""
    return LiveTransport(headers=headers, content=content, timeout=timeout)


# ======================================================================================================
# credential-bound factories — (secret) -> Transport
# ======================================================================================================

def bearer_transport_factory(*, headers: Optional[Mapping[str, str]] = None, scheme: str = "Bearer",
                             timeout: float = _DEFAULT_TIMEOUT) -> CredentialTransport:
    """A factory that binds a bearer secret into a real transport. Used for the GitHub PAT confirming call
    (``GET https://api.github.com/user`` with ``Authorization: Bearer <token>``).

    The secret lives ONLY inside the returned transport's header map — it is never logged, never returned,
    and never reaches a ``TransportResult``."""
    def factory(secret: str) -> LiveTransport:
        merged = {"Accept": "application/vnd.github+json",
                  "X-GitHub-Api-Version": "2022-11-28", **dict(headers or {})}
        merged["Authorization"] = f"{scheme} {secret}"
        return LiveTransport(headers=merged, timeout=timeout)
    return factory


# -- AWS SigV4 (stdlib hmac/hashlib; no boto3) ---------------------------------------------------------
_STS_BODY = b"Action=GetCallerIdentity&Version=2011-06-15"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sigv4_headers(*, method: str, url: str, body: bytes, access_key_id: str, secret_access_key: str,
                   session_token: str, region: str, service: str, now: datetime) -> dict:
    """AWS Signature Version 4 for one request. Pure + deterministic given ``now``, so it is testable
    offline against AWS's published worked example rather than only against the live service."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    canonical_uri = quote(parts.path or "/", safe="/~")
    canonical_qs = parts.query or ""
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = _sha256_hex(body)

    signed: list[tuple[str, str]] = [("content-type", "application/x-www-form-urlencoded"),
                                     ("host", host), ("x-amz-date", amz_date)]
    if session_token:
        signed.append(("x-amz-security-token", session_token))
    signed.sort()
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in signed)
    signed_header_names = ";".join(k for k, _ in signed)

    canonical_request = "\n".join([method.upper(), canonical_uri, canonical_qs, canonical_headers,
                                   signed_header_names, payload_hash])
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, credential_scope,
                                _sha256_hex(canonical_request.encode("utf-8"))])
    k_date = _hmac(("AWS4" + secret_access_key).encode("utf-8"), date_stamp)
    signature = hmac.new(_hmac(_hmac(_hmac(k_date, region), service), "aws4_request"),
                         string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out = {"Content-Type": "application/x-www-form-urlencoded", "X-Amz-Date": amz_date,
           "Accept": "application/json",
           "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, "
                             f"SignedHeaders={signed_header_names}, Signature={signature}")}
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    return out


def sigv4_transport_factory(*, access_key_id: str, session_token: str = "", region: str = "us-east-1",
                            service: str = "sts", body: bytes = _STS_BODY,
                            timeout: float = _DEFAULT_TIMEOUT,
                            clock: Optional[Callable[[], datetime]] = None) -> CredentialTransport:
    """A factory that binds an AWS SECRET ACCESS KEY into a real SigV4-signing transport, for the
    ``sts:GetCallerIdentity`` confirming call. ``access_key_id`` is the NON-secret identifier and is
    supplied here; the SECRET is supplied to the returned factory, exactly like the bearer case.

    ``Accept: application/json`` makes STS answer with the JSON envelope, so the identity echo can be
    extracted without an XML parser. NOT exercised by the GitHub live-fire — it needs a real AWS key."""
    def factory(secret: str) -> LiveTransport:
        def signer(method: str, url: str, content: bytes) -> Mapping[str, str]:
            # Sign EXACTLY the bytes that will be sent (``content`` is what ``LiveTransport`` hands us),
            # never a substituted default — a signature over bytes we did not send is not a signature.
            return _sigv4_headers(method=method, url=url, body=content,
                                  access_key_id=access_key_id, secret_access_key=secret,
                                  session_token=session_token, region=region, service=service,
                                  now=(clock or (lambda: datetime.now(timezone.utc)))())
        return LiveTransport(content=body, signer=signer, timeout=timeout)
    return factory
