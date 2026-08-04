"""channel_binding — bind a finding's response bytes to a TLS SESSION so a third party can confirm the
TARGET (not the producer/VIGIL) produced them (TRUTHENOVATION Z1, "producer byte-unforgeability" / zkTLS).

THE PROBLEM Z1 ATTACKS
----------------------
A retained ``oracle_context`` today carries the target's response *bytes* and a producer signature over them.
That proves VIGIL *asserts* those bytes came from the target — it does NOT stop a dishonest producer from
FABRICATING a response that the target never sent. The remaining trust in every non-OOB oracle class is
exactly this: "the producer honestly reported the wire" (``TRUTHENOVATION.md`` Truth 4). Z1's goal is a fact
whose response bytes are tied to a specific TLS session and CO-SIGNED by a NOTARY, so the standalone verifier
confirms them OFFLINE without trusting the producer.

WHAT THIS MODULE BUILDS (the mechanism + the verifier shape)
------------------------------------------------------------
1. **A channel-binding evidence object.** :class:`ChannelBinding` carries the TLS session-binding material —
   RFC 5705 / RFC 8446 EXPORTER keying material (``tls-exporter``) or a transcript hash over the handshake
   (``tls-transcript``) — that ties the bytes to ONE specific TLS session, not free-floating.
   :class:`ChannelBoundResponse` pairs that binding with ``response_sha256`` (the sha256 of the finding's
   response bytes). The tuple ``(session-binding, response-hash)`` is the thing a notary co-signs.
2. **A SOFTWARE-EMULATED notary co-signature.** A NOTARY Ed25519 key (reusing ``vigil_core`` — no new dep)
   co-signs the domain-separated canonical channel-bound-response. The verifier trusts ONLY a PINNED notary
   public key (supplied out-of-band), never a producer-asserted one.
3. **A standalone OFFLINE verifier shape** (mirrored VIGIL-free in ``docs/proof-carrying-finding/verify_vf.py``)
   that, given the pinned notary key, checks: the carried bytes hash to the bound ``response_sha256``; the
   notary co-signature is valid over the (session-binding, response-hash) tuple; the co-signing key is the
   pinned notary. A response for a DIFFERENT session, a DIFFERENT set of bytes, or with NO valid notary
   co-signature is REJECTED — without ever trusting the producer.

TLS session capture (:func:`capture_tls_channel_binding`) uses the system ``openssl s_client -keymatexport``
to pull the RFC 5705 exporter for a live host; it is network-gated (the deterministic test uses a fixed
test-vector binding, and unit-tests the exporter PARSER on canned output).

HONEST VERDICT (TRUTHENOVATION Rule 1/3/4 — the A1 pattern) — CAPABILITY, not a VERIFIED FACT of
producer-unforgeability. The channel-binding evidence object + notary co-sign + offline verifier are BUILT
and TESTED, and they establish the VERIFIER SHAPE and the mechanism. But the notary here is SOFTWARE that
VIGIL runs and hands the session binding to — so VIGIL (the producer) can fabricate a ``(session, bytes)``
tuple and have "its" notary sign it. That proves the MECHANISM only, NOT genuine byte-unforgeability.

IRREDUCIBLE RESIDUAL (state it plainly, do NOT overclaim): genuine producer-unforgeability needs (a) a real
**zkTLS / MPC-TLS / TLSNotary** toolchain in which the notary PARTICIPATES in the TLS handshake (co-deriving
the session secrets), so it can attest the transcript WITHOUT the producer being able to forge it; AND (b) a
**THIRD-PARTY notary operator** independent of VIGIL. Those tools (``tlsn``/``py-ecc``/``petlib``/``zksk``)
are ABSENT here (no network to install) and cannot be built with ``openssl`` alone. :class:`RemoteNotary`
marks the third-party seam; its independence cannot be exercised offline (mirrors A1's ``RemoteTSA``). Do NOT
flip Z1 to VERIFIED FACT for an unforgeability property a software notary cannot establish.

FATAL-2: sovereign-safe — this module imports ONLY stdlib + ``subprocess`` + ``vigil_core`` (the shared core).
No ``framework.*``, no ``strix.*``, no ``sigil`` import; ``openssl`` is an external process, not a Python dep.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional, Protocol

from vigil_core import KeyPair, canonical_json, generate_keypair, sign, verify_one

# Domain separation for the notary co-signature bytes. A signature over this domain can never be replayed as
# any other VIGIL signature (evidence certs, prove-certs, witness co-signs all use distinct domains).
_CHANNEL_BINDING_DOMAIN = b"vigil-zktls-channel-binding-v1\x00"

SCHEMA = "vigil-zktls-channel-binding-v1"

# The session-binding kinds we understand. ``tls-exporter`` (RFC 5705 / RFC 8446 §7.5) is the RECOMMENDED
# channel binding: a value derived from the session master secret + a label, unique to one TLS session.
# ``tls-transcript`` is a hash over the handshake transcript. ``test-vector`` is a fixed deterministic
# binding used by the offline mechanism test (no live TLS session).
_KNOWN_KINDS = ("tls-exporter", "tls-transcript", "test-vector")

# The default RFC 5705 exporter label VIGIL uses when pulling a channel binding from a live session.
DEFAULT_EXPORTER_LABEL = "EXPORTER-vigil-zktls-channel-binding"
DEFAULT_EXPORTER_LEN = 32


class ChannelBindingError(RuntimeError):
    """Capturing a live TLS channel binding failed (openssl absent/error, host unreachable, or no exporter
    in the output). Fail-closed: a caller must treat this as "no binding", never as a silent pass."""


@dataclass(frozen=True)
class ChannelBinding:
    """The TLS session-binding material that ties response bytes to ONE specific TLS session.

    ``binding_hex`` is the hex of the RFC 5705 exporter keying material (``kind="tls-exporter"``) or of a
    handshake-transcript hash (``kind="tls-transcript"``). ``host``/``port`` name the endpoint the session
    was to; ``tls_version`` records the negotiated version. Two different sessions produce different
    ``binding_hex`` — that is what makes a co-signed response non-transplantable to another session."""

    kind: str
    binding_hex: str
    host: str
    port: int
    tls_version: str = ""
    exporter_label: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "binding_hex": self.binding_hex,
            "host": self.host,
            "port": int(self.port),
            "tls_version": self.tls_version,
            "exporter_label": self.exporter_label,
        }

    @staticmethod
    def from_dict(d: dict) -> "ChannelBinding":
        return ChannelBinding(
            kind=str(d.get("kind", "")),
            binding_hex=str(d.get("binding_hex", "")),
            host=str(d.get("host", "")),
            port=int(d.get("port", 0)),
            tls_version=str(d.get("tls_version", "")),
            exporter_label=str(d.get("exporter_label", "")),
        )


@dataclass(frozen=True)
class ChannelBoundResponse:
    """The tuple a notary co-signs: a TLS session binding + the sha256 of the finding's response bytes.

    ``response_sha256`` is ``sha256(response_bytes).hexdigest()`` — the bytes themselves ride in the evidence
    envelope (``response_b64``) so a verifier can independently recompute and confirm the hash matches."""

    binding: ChannelBinding
    response_sha256: str

    def to_dict(self) -> dict:
        return {"binding": self.binding.to_dict(), "response_sha256": self.response_sha256}

    @staticmethod
    def from_dict(d: dict) -> "ChannelBoundResponse":
        return ChannelBoundResponse(
            binding=ChannelBinding.from_dict(d.get("binding") or {}),
            response_sha256=str(d.get("response_sha256", "")),
        )


@dataclass(frozen=True)
class NotaryCosign:
    """A notary's Ed25519 co-signature over a :class:`ChannelBoundResponse`. ``notary_public_key_b64`` is the
    key that signed; a verifier accepts it ONLY when it equals the out-of-band PINNED notary key."""

    notary_key_id: str
    notary_public_key_b64: str
    signature_b64: str

    def to_dict(self) -> dict:
        return {
            "notary_key_id": self.notary_key_id,
            "notary_public_key_b64": self.notary_public_key_b64,
            "signature_b64": self.signature_b64,
        }

    @staticmethod
    def from_dict(d: dict) -> "NotaryCosign":
        return NotaryCosign(
            notary_key_id=str(d.get("notary_key_id", "")),
            notary_public_key_b64=str(d.get("notary_public_key_b64", "")),
            signature_b64=str(d.get("signature_b64", "")),
        )


def channel_bound_signing_bytes(cbr: dict) -> bytes:
    """The exact bytes a notary signs / a verifier checks: the domain tag + the canonical channel-bound
    response. ``cbr`` is a :meth:`ChannelBoundResponse.to_dict`. Byte-identical to the standalone verifier's
    ``channel_bound_signing_bytes`` (same domain + ``canonical_json``)."""
    return _CHANNEL_BINDING_DOMAIN + canonical_json(cbr)


def notary_cosign(cbr: ChannelBoundResponse, *, notary_keypair: KeyPair, key_id: str) -> NotaryCosign:
    """Co-sign a channel-bound response with the NOTARY key. (Software-emulated notary — see the module
    HONEST VERDICT; this proves the mechanism, not third-party unforgeability.)"""
    sig = sign(notary_keypair.private_key_b64, channel_bound_signing_bytes(cbr.to_dict()))
    return NotaryCosign(
        notary_key_id=key_id,
        notary_public_key_b64=notary_keypair.public_key_b64,
        signature_b64=sig,
    )


@dataclass(frozen=True)
class ChannelBindingEvidence:
    """The offline-verifiable Z1 evidence envelope: the channel-bound response, the notary co-signature, and
    the actual response bytes (base64) so a third party can recompute the bound hash without the producer."""

    channel_bound_response: dict
    notary_cosign: dict
    response_b64: str
    schema: str = SCHEMA

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "channel_bound_response": self.channel_bound_response,
            "notary_cosign": self.notary_cosign,
            "response_b64": self.response_b64,
        }

    @staticmethod
    def from_dict(d: dict) -> "ChannelBindingEvidence":
        return ChannelBindingEvidence(
            schema=str(d.get("schema", "")),
            channel_bound_response=dict(d.get("channel_bound_response") or {}),
            notary_cosign=dict(d.get("notary_cosign") or {}),
            response_b64=str(d.get("response_b64", "")),
        )


def build_evidence(
    response_bytes: bytes, binding: ChannelBinding, *, notary_keypair: KeyPair, key_id: str
) -> ChannelBindingEvidence:
    """Bind ``response_bytes`` to ``binding``, have the NOTARY co-sign the tuple, and package the offline-
    verifiable envelope (carrying the bytes so a verifier can recompute the bound hash). Self-checks that the
    fresh envelope verifies against the notary's own key before returning (fail-closed)."""
    import base64

    response_sha256 = hashlib.sha256(response_bytes).hexdigest()
    cbr = ChannelBoundResponse(binding=binding, response_sha256=response_sha256)
    cosign = notary_cosign(cbr, notary_keypair=notary_keypair, key_id=key_id)
    ev = ChannelBindingEvidence(
        channel_bound_response=cbr.to_dict(),
        notary_cosign=cosign.to_dict(),
        response_b64=base64.b64encode(response_bytes).decode("ascii"),
    )
    ok, reason = verify_channel_binding_evidence(
        ev.to_dict(), notary_public_key_pin_b64=notary_keypair.public_key_b64
    )
    if not ok:
        raise ChannelBindingError(f"freshly built channel-binding evidence did not self-verify: {reason}")
    return ev


def verify_channel_binding_evidence(
    evidence: dict, *, notary_public_key_pin_b64: str
) -> "tuple[bool, str]":
    """Offline check that ``evidence`` binds its carried response bytes to a TLS session under a co-signature
    from the PINNED notary — WITHOUT trusting the producer. Returns (ok, reason), FAIL-CLOSED. Byte-identical
    to the standalone ``verify_vf.verify_channel_binding_evidence``. Checks, in order:

      1. SCHEMA — the envelope declares the Z1 schema;
      2. PIN — the co-signing key equals the out-of-band pinned notary key (the ONLY trust anchor; a
         producer-asserted notary key that is not the pin is REJECTED);
      3. BYTES↔HASH — the carried ``response_b64`` bytes hash to the bound ``response_sha256`` (a swapped or
         tampered body is REJECTED — the bound hash is what the notary signed);
      4. BINDING well-formed — a known ``kind`` with a non-empty ``binding_hex`` (a free-floating response
         with no session binding is REJECTED);
      5. CO-SIGNATURE — the notary's Ed25519 signature verifies over the domain-separated (session-binding,
         response-hash) tuple. A co-signature over a DIFFERENT session or DIFFERENT bytes changes these bytes
         and so FAILS here.

    HONEST LIMIT (module HONEST VERDICT): passing proves the notary co-signed THIS (session, bytes) tuple and
    the bytes match — but a SOFTWARE notary VIGIL runs can be handed a fabricated tuple, so this establishes
    the verifier SHAPE + mechanism, NOT genuine producer-unforgeability (needs zkTLS/MPC-TLS + a 3rd party)."""
    import base64
    import binascii

    if not isinstance(evidence, dict):
        return False, "evidence is not an object"
    if evidence.get("schema") != SCHEMA:
        return False, f"wrong schema (expected {SCHEMA!r})"
    if not notary_public_key_pin_b64:
        return False, "no notary public-key pin supplied (fail-closed: the pin is the only trust anchor)"

    cosign = NotaryCosign.from_dict(evidence.get("notary_cosign") or {})
    if not cosign.signature_b64:
        return False, "no notary co-signature present (a producer-fabricated response is rejected)"
    # PIN gate: trust ONLY the out-of-band pinned notary key, never the envelope-asserted one.
    if cosign.notary_public_key_b64 != notary_public_key_pin_b64:
        return False, "co-signing key is not the pinned notary key (untrusted / producer-supplied signer)"

    cbr_dict = evidence.get("channel_bound_response") or {}
    cbr = ChannelBoundResponse.from_dict(cbr_dict)

    # BYTES↔HASH: recompute the response hash from the carried bytes — the bytes must be the ones the notary
    # bound. A tampered body (or a body swapped under a stale hash) fails here.
    try:
        body = base64.b64decode(str(evidence.get("response_b64", "")), validate=True)
    except (binascii.Error, ValueError):
        return False, "response_b64 is not valid base64"
    if hashlib.sha256(body).hexdigest() != cbr.response_sha256:
        return False, "carried response bytes do not hash to the bound response_sha256"

    # BINDING must be a real TLS session binding, not free-floating.
    if cbr.binding.kind not in _KNOWN_KINDS:
        return False, f"unknown session-binding kind {cbr.binding.kind!r}"
    if not cbr.binding.binding_hex:
        return False, "empty session binding (response is not tied to any TLS session)"

    # CO-SIGNATURE over the domain-separated (session-binding, response-hash) tuple. Reconstruct the signing
    # bytes from the DECLARED tuple; a cosign minted over a different session/bytes will not verify here.
    msg = channel_bound_signing_bytes(cbr.to_dict())
    try:
        ok = verify_one(notary_public_key_pin_b64, msg, cosign.signature_b64)
    except Exception:  # malformed key/sig material → fail-closed
        return False, "malformed notary key/signature material"
    if not ok:
        return False, "notary co-signature does not verify over the (session-binding, response-hash) tuple"
    return True, (
        f"channel-bound response verified: {cbr.binding.kind} binding to {cbr.binding.host}:"
        f"{cbr.binding.port}, notary-cosigned by pinned key {cosign.notary_key_id} (MECHANISM — a software "
        f"notary is not producer-unforgeable; see Z1 residual)"
    )


# ============================================================================
# Live TLS session capture (network-gated) + the exporter parser (unit-tested offline).
# ============================================================================
_OPENSSL = "openssl"


def openssl_available() -> bool:
    """True iff a usable ``openssl`` binary is on PATH (needed to pull a live TLS exporter)."""
    return shutil.which(_OPENSSL) is not None


_KEYMAT_RE = re.compile(r"Keying material:\s*([0-9A-Fa-f]+)")
_PROTO_RE = re.compile(r"Protocol\s*:\s*(\S+)")


def parse_keying_material(openssl_output: str) -> Optional[str]:
    """Parse the RFC 5705 exporter hex from ``openssl s_client -keymatexport`` output (the ``Keying
    material:`` line). Returns lowercase hex, or None if absent/odd-length (fail-closed). Pure + deterministic
    so the offline test exercises the capture SHAPE without a live TLS session."""
    m = _KEYMAT_RE.search(openssl_output or "")
    if not m:
        return None
    hexval = m.group(1).lower()
    if len(hexval) == 0 or len(hexval) % 2 != 0:
        return None
    return hexval


def parse_tls_version(openssl_output: str) -> str:
    m = _PROTO_RE.search(openssl_output or "")
    return m.group(1) if m else ""


def capture_tls_channel_binding(
    host: str,
    port: int = 443,
    *,
    exporter_label: str = DEFAULT_EXPORTER_LABEL,
    exporter_len: int = DEFAULT_EXPORTER_LEN,
    timeout: int = 30,
) -> ChannelBinding:
    """Capture a LIVE TLS session's RFC 5705 exporter keying material for ``host:port`` via
    ``openssl s_client -keymatexport <label> -keymatexportlen <n>``, returning a ``tls-exporter``
    :class:`ChannelBinding`. NETWORK-GATED (the deterministic test uses a fixed test-vector binding instead).
    FAIL-CLOSED: raises :class:`ChannelBindingError` on a missing openssl, an unreachable host, or output
    with no exporter.

    HONEST LIMIT: the exporter is a value VIGIL derives from ITS OWN TLS session with the target. A software
    notary that VIGIL then hands it to gains no independent view of the handshake — genuine unforgeability
    needs the notary to PARTICIPATE in the TLS session (MPC-TLS/zkTLS). This capture proves the binding is a
    real session value; it does not, by itself, make the response producer-unforgeable."""
    if not openssl_available():
        raise ChannelBindingError("openssl is not available — cannot capture a live TLS channel binding")
    args = [
        _OPENSSL, "s_client", "-connect", f"{host}:{port}", "-servername", host,
        "-keymatexport", exporter_label, "-keymatexportlen", str(int(exporter_len)),
    ]
    try:
        r = subprocess.run(
            args, input="", capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise ChannelBindingError(f"openssl s_client to {host}:{port} failed: {e}") from e
    out = r.stdout + r.stderr
    hexval = parse_keying_material(out)
    if hexval is None:
        raise ChannelBindingError(
            f"no RFC 5705 exporter in openssl output for {host}:{port} "
            f"(handshake may have failed or the peer does not support the exporter)"
        )
    return ChannelBinding(
        kind="tls-exporter",
        binding_hex=hexval,
        host=host,
        port=int(port),
        tls_version=parse_tls_version(out),
        exporter_label=exporter_label,
    )


class Notary(Protocol):
    """A notary that co-signs a channel-bound response. The SOFTWARE emulation is :class:`LocalNotary`; the
    genuine-independence seam is :class:`RemoteNotary` (a third-party zkTLS/TLSNotary operator)."""

    @property
    def public_key_b64(self) -> str: ...

    def cosign(self, cbr: ChannelBoundResponse) -> NotaryCosign: ...


@dataclass
class LocalNotary:
    """The DEFAULT software-emulated notary — the mechanism/CI authority. It holds an Ed25519 keypair and
    co-signs any channel-bound response handed to it.

    HONEST RESIDUAL: a software notary VIGIL runs proves the MECHANISM only — it can be handed a fabricated
    (session, bytes) tuple and will sign it, so it establishes NO producer-unforgeability. Genuine
    unforgeability needs :class:`RemoteNotary` — a THIRD-PARTY zkTLS/MPC-TLS notary that PARTICIPATES in the
    TLS handshake (co-deriving the session secrets) so the producer cannot forge the transcript."""

    key_id: str = "vigil-local-notary"
    keypair: KeyPair = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.keypair is None:
            self.keypair = generate_keypair()

    @property
    def public_key_b64(self) -> str:
        return self.keypair.public_key_b64

    def cosign(self, cbr: ChannelBoundResponse) -> NotaryCosign:
        return notary_cosign(cbr, notary_keypair=self.keypair, key_id=self.key_id)


@dataclass(frozen=True)
class RemoteNotary:
    """The GENUINE-INDEPENDENCE seam: a real third-party zkTLS/MPC-TLS/TLSNotary operator that participates in
    the TLS handshake and co-signs the attested transcript. NOT buildable here — the toolchain
    (``tlsn``/``py-ecc``/``petlib``/``zksk``) is ABSENT and cannot be emulated with ``openssl`` alone. Present
    only to mark the residual seam (mirrors A1's ``RemoteTSA``); calling it always fails closed offline, so no
    test can pretend a software notary establishes third-party unforgeability.

    ``notary_public_key_b64`` is the third-party notary's key, PINNED out-of-band; ``endpoint`` is its
    MPC-TLS coordination URL."""

    endpoint: str
    notary_public_key_b64: str

    @property
    def public_key_b64(self) -> str:
        return self.notary_public_key_b64

    def cosign(self, cbr: ChannelBoundResponse) -> NotaryCosign:  # noqa: ARG002
        raise ChannelBindingError(
            "RemoteNotary requires a real zkTLS/MPC-TLS notary toolchain (absent here) — the genuine "
            "producer-unforgeability path cannot be exercised offline (Z1 residual)"
        )
