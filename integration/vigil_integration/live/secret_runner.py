"""E5 — the WARDEN-gated exposed-secret VALIDATION runner (the LIVE half of E5).

This is the ONLY component that USES an exposed secret and produces the RETAINED capture the offline oracle
(``framework.v2.verify.oracles.exposed_secret_validity_oracle``) judges. The oracle confirms a FACT only when
THIS runner's exact secret->call binding + trusted-transport provenance are present (see
``verify._confirming_call_trusted``), so a hand-written record can never be a FACT: the live proof of "the
call went where we say it went and the SAME secret authenticated" originates here. Structure mirrors
``imds_runner`` deliberately — the two are the same shape of evidence for two different achieved effects.

Guarantees enforced here (constitution §II/§VI + the E-series audit):

  * GATED, BEFORE ANY I/O, IN ORDER: ``authorize()`` (the WARDEN A2 floor + kill-switch), then the D5 cloud
    ``scope_gate``. A refusal returns a REFUSED result and NEVER a capture — there is nothing to adjudicate,
    so there is nothing to launder. No network call is built, let alone sent, before both gates pass.
  * SECRET LIFECYCLE: the plaintext secret is fingerprinted (a domain-separated sha256) and the runner's
    reference DISCARDED before the confirming call is issued. Only the NON-SECRET identifier (an AWS
    AccessKeyId; a GitHub token PREFIX), a presence marker, the fingerprint, and non-secret transport
    provenance are retained. The plaintext never enters the capture, a log, or a return value.
  * THE BINDING IS CONSTRUCTED, NOT ASSUMED: the runner receives a ``credential_transport`` FACTORY —
    ``(secret) -> Transport`` — and calls it with the exact string it just fingerprinted. A caller cannot
    hand in a transport authenticated with some OTHER credential and have this runner stamp a fingerprint
    that describes a credential the call did not use.
  * EXFIL FLOOR: the runner refuses to send a live secret anywhere except that secret type's confirming
    endpoint, over https. This MIRRORS the oracle's anti-laundering allow-list, and it exists for a
    different reason than the oracle's: the oracle is protecting the FACT, this is protecting the operator's
    credential. The oracle remains the sole adjudicator — a capture that somehow reached a non-allow-listed
    host would still be refused there.

Dispatch is by secret type, against the per-type confirming endpoint the oracle's recognizer table already
defines (``oracles._SECRET_RECOGNIZERS``): ``github_pat`` -> ``GET https://api.github.com/user``;
``aws_access_key`` -> ``sts:GetCallerIdentity`` at ``sts[.<region>].amazonaws.com``. Both are built. Only
GitHub is exercisable without a provisioned cloud credential, and the live-fire harness
(``tools/livefire/secret_github_livefire.sh``) exercises exactly that row and claims nothing about the other.

FATAL-2 / purity: stdlib only at module scope, so importing this co-loads no offense engine.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

from .imds_runner import Authorizer, Transport, TransportResult, response_digest

# Domain separator: a fingerprint is NOT a bare hash of the secret (a bare hash of a low-entropy secret could
# be confirmed offline by brute force). Distinct from E1's domain, so an E1 credential fingerprint and an E5
# secret fingerprint can never collide across capabilities even for identical bytes.
_FP_DOMAIN = b"vigil.e5.secret.credential-fingerprint.v1\x00"

# A transport factory bound to a credential: (plaintext secret) -> Transport. See the module docstring —
# this shape is what makes the fingerprint<->call binding a checked property of this runner.
CredentialTransport = Callable[[str], Transport]

# --------------------------------------------------------------------------------------------------
# The per-type table. This MIRRORS the oracle's closed recognizer set (``oracles._SECRET_RECOGNIZERS``)
# and must not drift from it: the ``action`` strings are compared (case-folded) by the oracle, and the
# ``confirm_host`` patterns are the same anti-laundering allow-list. ``test_secret_runner`` asserts the
# two tables agree, so a one-sided edit fails the suite rather than silently producing unconfirmable
# captures. It is duplicated rather than imported because this module must stay offense-import-free.
# --------------------------------------------------------------------------------------------------
_GITHUB_PREFIX_RE = re.compile(r"^(gh[posru]_|github_pat_)")
_AWS_KEY_ID_RE = re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$")
_AWS_STS_HOST_RE = re.compile(r"^sts(\.[a-z0-9-]+)?\.amazonaws\.com$")


def secret_fingerprint(secret_material: str) -> str:
    """A domain-separated sha256 over the SECRET material. The runner computes this in memory and stamps the
    SAME value on the credential record and the confirming call, so the oracle can prove offline — WITHOUT
    ever seeing the plaintext — that the confirming call used the captured secret."""
    return "sha256:" + hashlib.sha256(_FP_DOMAIN + secret_material.encode("utf-8")).hexdigest()


def _github_identifier(secret: str) -> str:
    """The NON-SECRET identifier for a GitHub token: its structural PREFIX (``ghp_`` / ``gho_`` /
    ``github_pat_`` / …) and nothing more. The token body IS the secret and is never retained."""
    match = _GITHUB_PREFIX_RE.match(secret)
    return match.group(0) if match else ""


def _github_identity(result: TransportResult) -> dict:
    """The identity echo from ``GET /user``: login + id, the two fields the oracle's extractor reads. Only
    those two are retained — a full user object is noise in a certificate, and every extra field is another
    thing to have to justify."""
    body = result.json or {}
    out: dict[str, Any] = {}
    if body.get("login") not in (None, ""):
        out["login"] = body["login"]
    if body.get("id") not in (None, ""):
        out["id"] = body["id"]
    return out


def _aws_identity(result: TransportResult) -> dict:
    """The identity echo from ``sts:GetCallerIdentity``. With ``Accept: application/json`` STS answers with
    a nested envelope, so unwrap it to the flat ``Arn``/``Account``/``UserId`` the oracle's extractor reads;
    a flat body (some endpoints, and fixtures) is taken as-is."""
    body: Mapping[str, Any] = result.json or {}
    nested = body.get("GetCallerIdentityResponse")
    if isinstance(nested, Mapping):
        inner = nested.get("GetCallerIdentityResult")
        if isinstance(inner, Mapping):
            body = inner
    return {k: body[k] for k in ("Arn", "Account", "UserId") if body.get(k) not in (None, "")}


_SECRET_TYPES: "dict[str, dict[str, Any]]" = {
    "github_pat": {
        "method": "GET",
        "endpoint": lambda region: "https://api.github.com/user",
        "action": "github:GET /user",
        "identifier": _github_identifier,          # derived from the secret (its prefix)
        "identity": _github_identity,
        "host_ok": lambda host: host == "api.github.com",
    },
    "aws_access_key": {
        "method": "POST",
        "endpoint": lambda region: (f"https://sts.{region}.amazonaws.com/" if region
                                    else "https://sts.amazonaws.com/"),
        "action": "sts:GetCallerIdentity",
        "identifier": None,                        # the AccessKeyId is supplied; it is NOT the secret
        "identity": _aws_identity,
        "host_ok": lambda host: _AWS_STS_HOST_RE.match(host) is not None,
    },
}

SUPPORTED_SECRET_TYPES = tuple(sorted(_SECRET_TYPES))


@dataclass
class SecretCaptureResult:
    """The outcome of one runner invocation. ``capture`` is the secret-safe retained evidence for the oracle
    (present only when the confirming call was actually issued); ``refused``/``reason`` explain a gate or
    safety refusal. ``plaintext_discarded`` records that the secret lifecycle ran."""

    status: str = "captured"        # "captured" | "refused" | "no_secret" | "unsupported_secret_type"
    reason: str = ""
    capture: Optional[dict] = None
    plaintext_discarded: bool = True
    provenance: dict = field(default_factory=dict)


def _endpoint_permitted(secret_type: str, endpoint: str) -> "tuple[bool, str]":
    """The EXFIL FLOOR: may this runner send a live secret of this type to this endpoint? https only, and
    only to the type's confirming host. Fails closed on anything unparseable. This does not adjudicate
    anything — the oracle still decides what is a FACT — it decides where a real credential may travel."""
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return False, "confirming endpoint is unparseable"
    if parts.scheme != "https" or not parts.hostname:
        return False, "confirming endpoint is not https — refusing to send a credential in the clear"
    if not _SECRET_TYPES[secret_type]["host_ok"](parts.hostname.lower()):
        return False, (f"confirming endpoint host {parts.hostname!r} is not the allow-listed confirming "
                       f"host for a {secret_type} secret — refusing to send a live credential to it")
    return True, "endpoint permitted"


def run_secret_validation(
    secret_type: str,
    *,
    secret: str,
    source: str,
    authorize: Authorizer,
    scope_gate: Any,
    scope: "tuple[str, str, str, str]",
    credential_transport: CredentialTransport,
    identifier: str = "",
    region: str = "",
    endpoint: str = "",
) -> SecretCaptureResult:
    """Perform ONE gated exposed-secret validation and return the secret-safe retained evidence.

    Flow (fails closed at every step; NO network I/O before both gates pass):
      1. ``authorize()`` — the WARDEN A2 floor + kill-switch. Refused ⇒ return, no capture.
      2. ``scope_gate.authorize(*scope)`` — the D5 signed-charter cloud scope. Refused ⇒ return, no capture.
      3. Resolve the type's confirming endpoint and apply the EXFIL FLOOR (https + the type's allow-listed
         host). Refused ⇒ return, no capture: a live secret is never sent anywhere else.
      4. Derive the NON-SECRET identifier, fingerprint the SECRET (domain-separated sha256), bind that exact
         string into the transport via ``credential_transport(secret)``, then DISCARD the plaintext.
      5. Issue the confirming call; record the resolved peer / TLS-verified / no-proxy / no-redirect flags
         and a bounded response digest exactly as the transport reported them.
      6. Assemble the capture with the SAME fingerprint on the credential and the confirming call, plus the
         identity echo, and return it for the offline oracle to judge.

    ``source`` is where the secret was exposed; it is retained as EVIDENCE only — E5 asserts VALIDITY, not
    provenance, so the source is never a firing gate (the source-semantics inversion vs E1). ``identifier``
    is required for ``aws_access_key`` (the AccessKeyId, a public identifier); for ``github_pat`` it is
    derived from the token's prefix. ``endpoint`` overrides the default confirming endpoint (still subject
    to the exfil floor). Never raises on bad input — it refuses."""
    spec = _SECRET_TYPES.get(secret_type)
    if spec is None:
        return SecretCaptureResult("unsupported_secret_type",
                                   f"{secret_type!r} is not a supported secret type "
                                   f"{SUPPORTED_SECRET_TYPES}")

    allowed, reason = authorize()
    if not allowed:
        return SecretCaptureResult("refused", f"WARDEN refused: {reason}")
    scope_allowed, scope_reason = scope_gate.authorize(*scope)
    if not scope_allowed:
        return SecretCaptureResult("refused", f"charter scope refused: {scope_reason}")

    if not (secret or "").strip():
        return SecretCaptureResult("no_secret", "no secret material supplied — nothing to validate")

    confirm_endpoint = endpoint or spec["endpoint"](region)
    permitted, endpoint_reason = _endpoint_permitted(secret_type, confirm_endpoint)
    if not permitted:
        return SecretCaptureResult("refused", endpoint_reason,
                                   provenance={"attempted_endpoint": confirm_endpoint})

    derive = spec["identifier"]
    non_secret_id = derive(secret) if derive is not None else str(identifier or "")

    fingerprint = secret_fingerprint(secret)
    transport = credential_transport(secret)   # the EXACT string just fingerprinted is bound in here
    secret = ""                                # SECRET LIFECYCLE: only the fingerprint survives the call

    confirm = transport(spec["method"], confirm_endpoint)

    credential_record = {
        "identifier": non_secret_id,
        "secret": "[REDACTED]",                # a PRESENCE marker; the value never leaves the transport
        "credential_fingerprint": fingerprint,
        "source": source,
    }
    call_record: dict[str, Any] = {
        "action": spec["action"],
        "status": confirm.status,
        "credential_fingerprint": fingerprint,
        "endpoint": confirm_endpoint,
        "resolved_peer": confirm.resolved_peer,
        "tls_verified": confirm.tls_verified,
        "no_proxy": not confirm.via_proxy,
        "no_redirect": not confirm.redirected,
        "response_digest": response_digest(confirm.body),
        "response": spec["identity"](confirm),
    }
    capture = {"secret_type": secret_type, "credential": credential_record,
               "confirming_call": call_record}
    return SecretCaptureResult(
        "captured", "exposed secret bound to a confirming call", capture=capture,
        provenance={"confirm_peer": confirm.resolved_peer, "confirm_status": confirm.status})
