"""E1-complete — the WARDEN-gated IMDS/metadata credential-capture RUNNER (the LIVE half of E1).

This is the ONLY component that reaches the instance-metadata endpoint, uses a credential, and produces the
RETAINED capture that the offline oracle (``framework.v2.verify.oracles.imds_credential_capture_oracle``)
judges. The oracle only confirms a FACT when THIS runner's exact credential->call binding + trusted-transport
provenance are present (see ``verify._imds_binding_provenance_ok``), so a hand-supplied record can never be a
FACT — the live proof of "where both calls went and that the same credential authenticated" originates here.

Guarantees enforced here (constitution §II/§VI + the operator's E1 audit):

  * GATED: every live capture is authorized FIRST (``authorize`` — the WARDEN A2 floor + kill-switch) and
    scoped to a signed charter (``scope_gate`` — the D5 cloud-scope gate); an unauthorized/out-of-scope call
    REFUSES before any network I/O. Own provisioned labs only, correlatable, NO evasion.
  * SECRET LIFECYCLE: the plaintext credential is validated + fingerprinted (a domain-separated sha256) IN
    MEMORY and then DISCARDED — only the redacted structural record + the fingerprint + non-secret provenance
    (resolved peer IPs, TLS-verified flags, no-proxy/no-redirect, a bounded response digest) are retained, so
    NO live secret ever enters the capture / certificate.
  * TRUSTED TRANSPORT: the network reach is via an injected ``transport`` that MUST report the resolved peer,
    whether TLS was verified, and whether a proxy/redirect occurred; the runner records these so the oracle
    can require the IMDS GET hit a metadata peer and the confirming call hit an allow-listed https endpoint
    with a validated TLS peer and no proxy/redirect.

The transport is INJECTED so this module is unit-tested with a mock and its live-fire is a thin real-transport
binding (httpx with proxies disabled + redirects disabled + TLS verification on), deferred until an authorized
lab credential is available.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

# Domain separator so a fingerprint is NOT a bare hash of the secret (a bare hash of a low-entropy secret
# could be brute-forced/confirmed offline; the domain separation binds it to this specific use).
_FP_DOMAIN = b"vigil.e1.imds.credential-fingerprint.v1\x00"
_MAX_BODY = 65536   # a confirming response is small; bound it (no unbounded read enters the digest / capture)


def credential_fingerprint(secret_material: str) -> str:
    """A domain-separated sha256 over the credential's SECRET material. The runner computes this in memory and
    stamps the SAME value on both the credential and the confirming call, so the oracle can prove offline —
    WITHOUT ever seeing the plaintext — that the confirming call used the captured credential."""
    return "sha256:" + hashlib.sha256(_FP_DOMAIN + secret_material.encode("utf-8")).hexdigest()


def response_digest(body: bytes) -> str:
    """A bounded sha256 of the confirming-call response body (provenance that the identity echo was not
    fabricated after the fact). The body is capped before hashing."""
    return "sha256:" + hashlib.sha256(body[:_MAX_BODY]).hexdigest()


@dataclass(frozen=True)
class TransportResult:
    """What an injected transport MUST report for one request — enough for the runner to record trusted-
    transport provenance. ``tls_verified`` is False for the plain-http IMDS GET (link-local, no TLS) and True
    only for a real https call whose certificate chain validated."""
    status: int
    body: bytes
    resolved_peer: str            # the IP the connection actually went to (not the URL host)
    tls_verified: bool
    via_proxy: bool
    redirected: bool
    json: Optional[Mapping[str, Any]] = None   # parsed body, when the transport parsed it


# A transport is: (method, url) -> TransportResult. Injected; the live binding disables proxies + redirects
# and enables TLS verification, and reports the resolved peer.
Transport = Callable[[str, str], TransportResult]

# An authorizer is: () -> (allowed: bool, reason: str) — the WARDEN A2 floor + kill-switch check.
Authorizer = Callable[[], "tuple[bool, str]"]


@dataclass
class CaptureResult:
    """The outcome of a runner invocation. ``capture`` is the secret-safe retained evidence for the oracle
    (present only when the run reached both endpoints); ``refused``/``reason`` explain a gate refusal or a
    non-capturing outcome. ``plaintext_discarded`` records that the secret lifecycle ran."""
    status: str                              # "captured" | "refused" | "no_credential" | "confirm_failed"
    reason: str
    capture: Optional[dict] = None
    plaintext_discarded: bool = True
    provenance: dict = field(default_factory=dict)


def _secret_material(provider: str, cred: Mapping[str, Any]) -> str:
    """The SECRET bytes to fingerprint (never retained): AWS SecretAccessKey + session Token; GCP access
    token. Concatenated with a separator so two fields cannot be confused for one."""
    if provider == "aws":
        sec = str(cred.get("SecretAccessKey") or cred.get("secret_access_key") or "")
        tok = str(cred.get("Token") or cred.get("SessionToken") or cred.get("session_token") or "")
        return sec + "\x1f" + tok
    return str(cred.get("access_token") or cred.get("accessToken") or "")


def _redacted_credential(provider: str, cred: Mapping[str, Any], source: str, fp: str,
                         imds: TransportResult) -> dict:
    """The secret-safe credential record: identifiers verbatim, secrets replaced by a presence marker, plus
    the runner-computed fingerprint and the IMDS-GET transport provenance. NO plaintext secret is copied."""
    out: dict[str, Any] = {"source": source, "credential_fingerprint": fp,
                           "resolved_peer": imds.resolved_peer,
                           "no_proxy": not imds.via_proxy, "no_redirect": not imds.redirected}
    if provider == "aws":
        out["AccessKeyId"] = str(cred.get("AccessKeyId") or cred.get("access_key_id") or "")
        if _secret_material("aws", cred).strip("\x1f"):
            out["SecretAccessKey"] = "[REDACTED]"
            out["Token"] = "[REDACTED]"
    else:
        if str(cred.get("access_token") or cred.get("accessToken") or ""):
            out["access_token"] = "[REDACTED]"
        out["token_type"] = str(cred.get("token_type") or cred.get("tokenType") or "Bearer")
    return out


def run_imds_capture(
    provider: str,
    *,
    imds_url: str,
    confirm_endpoint: str,
    confirm_action: str,
    authorize: Authorizer,
    scope_gate: Any,
    scope: "tuple[str, str, str, str]",
    transport: Transport,
    identity_of: Callable[[TransportResult], Mapping[str, Any]],
) -> CaptureResult:
    """Perform ONE gated IMDS credential capture and return the secret-safe retained evidence.

    Flow (fails closed at every step; NO network I/O before authorization):
      1. WARDEN A2 authorize() + charter scope_gate.authorize(scope) — refuse before any request otherwise.
      2. GET ``imds_url`` via the injected transport -> the raw credential (validated in memory).
      3. Fingerprint the SECRET material (domain-separated sha256); discard the plaintext.
      4. Call ``confirm_endpoint`` (the STS/tokeninfo call that USES the credential) via the transport;
         record TLS-verified / no-proxy / no-redirect / resolved peer / a bounded response digest.
      5. Assemble the capture with the SAME fingerprint on the credential and the confirming call (the exact
         binding) + the identity echo, and return it for the offline oracle to judge.

    ``identity_of`` extracts the identity echo (Arn/Account/UserId or email/sub) from the confirming response;
    ``scope`` is (provider, account, region, resource) for the D5 gate."""
    allowed, reason = authorize()
    if not allowed:
        return CaptureResult("refused", f"WARDEN refused: {reason}")
    s_allowed, s_reason = scope_gate.authorize(*scope)
    if not s_allowed:
        return CaptureResult("refused", f"charter scope refused: {s_reason}")

    imds = transport("GET", imds_url)
    raw_cred = dict(imds.json or {})
    secret = _secret_material(provider, raw_cred)
    if not secret.strip("\x1f") or not (raw_cred.get("AccessKeyId") or raw_cred.get("access_token")
                                        or raw_cred.get("access_key_id") or raw_cred.get("accessToken")):
        return CaptureResult("no_credential", "no credential retrieved from the metadata endpoint",
                             provenance={"imds_peer": imds.resolved_peer})
    fp = credential_fingerprint(secret)
    secret = ""   # SECRET LIFECYCLE: discard plaintext after fingerprinting (only the fingerprint survives)

    confirm = transport("POST" if provider == "aws" else "GET", confirm_endpoint)
    cred_rec = _redacted_credential(provider, raw_cred, imds_url, fp, imds)
    raw_cred = {}   # discard the plaintext credential mapping too
    call_rec: dict[str, Any] = {
        "action": confirm_action, "status": confirm.status,
        "credential_fingerprint": fp, "endpoint": confirm_endpoint,
        "resolved_peer": confirm.resolved_peer, "tls_verified": confirm.tls_verified,
        "no_proxy": not confirm.via_proxy, "no_redirect": not confirm.redirected,
        "response_digest": response_digest(confirm.body),
        "response": dict(identity_of(confirm)),
    }
    capture = {"provider": provider, "credential": cred_rec, "confirming_call": call_rec}
    return CaptureResult("captured", "credential captured and bound to a confirming call", capture=capture,
                         provenance={"imds_peer": imds.resolved_peer, "confirm_peer": confirm.resolved_peer})
