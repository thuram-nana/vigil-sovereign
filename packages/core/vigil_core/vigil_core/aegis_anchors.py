"""AEGIS AS-9c — the two-anchor TAMPER-EVIDENCE contract for ingested AEGIS records.

The AEGIS analog of the P10 ``finding_receiver`` two-anchor seam (``apps/sigil/.../inbound/
finding_receiver.py``): the sovereign personal record ingests an AEGIS connector/provider record
(an :class:`vigil_core.aegis_schemas.AegisEventV2` or any other AS-2b :class:`CanonicalModel`), and
an ingested record is a FACT only when it is provably bound to TWO INDEPENDENT anchors, neither
forgeable by the other. ``finding_receiver`` lives sovereign-side and binds an m-of-n GOVERNANCE
signature (anchor-1) to the owner-signed spine head (anchor-2); AEGIS records do not carry a
governance m-of-n signature — they carry a PRODUCER identity, the AS-9a per-(org, connector) sealed
connector secret. This module re-expresses the SAME two-anchor logic over that producer identity,
PURELY (``vigil_core`` + stdlib only), so it is a FATAL-2 cross-plane contract like AS-2b/AS-2g and
safe to import on either plane.

Two anchors make an ingested AEGIS record trustworthy end-to-end:

  * Anchor-1 (PRODUCER) — proves WHO produced the record. A domain-separated HMAC-SHA256 over the
    record's CANONICAL BYTES (:meth:`CanonicalModel.canonical_bytes`), keyed by the AS-9a
    per-(org, connector) sealed connector secret (the AS-2h ``secret_mac`` under
    ``SecretKind.CONNECTOR``), and tied to the broker's non-reversible ``secret_ref`` fingerprint
    (:func:`connector_secret_ref`, byte-identical to ``aegis.connector_secrets.connector_secret_ref``).
    Only a holder of THAT connector's secret can mint it; a wrong-secret, tampered-body, or
    wrong-connector (confused-deputy) record is REFUSED. Verified HERE, with ``vigil_core`` alone.
  * Anchor-2 (OWNER / SPINE) — proves WHEN it entered the personal record and that it has not been
    tampered or reordered since. Once the record is appended to the owner-signed spine (its
    ``cert_digest`` is the record's :meth:`CanonicalModel.digest`), it is covered by the owner's
    Ed25519-signed :class:`SignedChainHead` (``apps/sigil/.../spine/checkpoint.py``, SOVEREIGN root);
    tamper/reorder/truncation then breaks the owner-signed head (:func:`vigil_core.chain.verify_head`).

Separation of authority: the producer proves WHAT connector emitted the record (anchor-1); the owner
attests WHEN it entered the record and seals its order (anchor-2). Neither can forge the other's — a
connector secret cannot sign the owner head, and the owner head cannot mint a connector HMAC.

PROVE-DON'T-GUESS, FAIL-CLOSED: an anchored record is a FACT only when BOTH anchors verify
(:attr:`AnchorVerification.trustworthy`); ANY single-anchor failure ⇒ refused. The verify functions
never raise on hostile input — they return ``(False, reason)`` — and the strict
:func:`require_trustworthy` is the fail-closed wrapper that raises :class:`AegisAnchorError`.

DETERMINISM: every byte on the anchored path is a pure function of its inputs — NO wall-clock, NO RNG,
NO env/flag. The same record maps to byte-identical anchor digests, so a producer and the sovereign
re-verifier compute the same tag. This is a PURE INERT CONTRACT (the AS-2b stance "ships the CONTRACTS,
wires nothing"): importing it adds no oracle/class to any registry and has no runtime effect on any
signed/request path, so ``make gate`` stays byte-identical.

FATAL-2: imports only ``vigil_core`` siblings + the stdlib. No ``sigil``, no ``framework``, no
``strix`` — safe on both planes (the same discipline ``finding_receiver`` keeps by never importing the
offense engine).
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Final

from .aegis_schemas import CanonicalModel
from .aegis_sealing import (
    SealedSecret,
    SecretKind,
    SealingError,
    connector_aad,
    open_secret,
    secret_mac,
)
from .chain import verify_head
from .models import ChainEntry, SignedChainHead, TrustRoot
from .sealing import SealError

__all__ = [
    "ANCHOR1_SCHEME",
    "AegisAnchorError",
    "ProducerAnchor",
    "AnchorVerification",
    "connector_secret_ref",
    "record_cert_digest",
    "produce_producer_anchor",
    "verify_producer_anchor",
    "open_and_verify_producer_anchor",
    "verify_owner_anchor",
    "verify_anchored_record",
    "verify_anchored_record_sealed",
    "require_trustworthy",
]

#: The anchor-1 construction token. A distinct, versioned label so a later anchor-1 scheme (a different
#: MAC/signature) is introduced by APPENDING a token, never by silently reinterpreting an old tag.
ANCHOR1_SCHEME: Final[str] = "aegis-anchor1-hmac-sha256-v1"

_FINGERPRINT_CHARS: Final[int] = 16  # mirrors aegis.connector_secrets._FINGERPRINT_CHARS (non-reversible)
_SECRET_REF_ALPHABET: Final[frozenset[str]] = frozenset("0123456789abcdef")


class AegisAnchorError(Exception):
    """A two-anchor CONTRACT was violated fail-closed: a malformed anchor at construction, or the strict
    :func:`require_trustworthy` was handed a record that is not bound to BOTH anchors. Leaks no secret
    material (it names org / connector / ``secret_ref`` only, never a credential value or a tag)."""


def connector_secret_ref(org: str, connector_id: str, epoch: int) -> str:
    """The non-reversible, deterministic fingerprint of a connector credential's identity — the SHA-256 of
    its AS-2h connector AAD at ``epoch``, truncated. RE-EXPRESSED here (not imported) so this contract stays
    ``vigil_core``-only (FATAL-2); it is BYTE-IDENTICAL to ``aegis.connector_secrets.connector_secret_ref``
    (the same :func:`vigil_core.aegis_sealing.connector_aad` input, the same truncation), so a handle issued
    by the AS-9a broker and an anchor verified here agree on the fingerprint by construction. Pure: no clock,
    no RNG. Raises :class:`AegisAnchorError` on a malformed component / epoch."""
    if not isinstance(org, str) or not org:
        raise AegisAnchorError("org must be a non-empty str")
    if not isinstance(connector_id, str) or not connector_id:
        raise AegisAnchorError("connector_id must be a non-empty str")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise AegisAnchorError("epoch must be a non-negative int")
    try:
        aad = connector_aad(org, connector_id, epoch=epoch)
    except SealingError as exc:
        raise AegisAnchorError(f"invalid connector identity for secret_ref: {exc}") from exc
    return hashlib.sha256(aad).hexdigest()[:_FINGERPRINT_CHARS]


def record_cert_digest(record: CanonicalModel) -> str:
    """The content id the record is anchored under on the owner-signed spine — the sha256 of its canonical
    bytes (:meth:`CanonicalModel.digest`). The ``cert_digest`` of its :class:`ChainEntry`, so anchor-2 can
    confirm THIS record (not merely A record) is covered by the owner head. Pure + deterministic."""
    return record.digest()


@dataclass(frozen=True)
class ProducerAnchor:
    """Anchor-1: the producer attestation that travels WITH an ingested AEGIS record. Value object; carries
    NO secret bytes — only the connector identity ``(org, connector_id, epoch)``, the non-reversible
    ``secret_ref`` fingerprint, and the HMAC ``tag_hex`` over the record's canonical bytes. Safe to log /
    append to the spine. A tampered anchor is detected by :func:`verify_producer_anchor` (the tag will not
    recompute); ``__post_init__`` rejects only STRUCTURAL malformations fail-closed."""

    org: str
    connector_id: str
    epoch: int
    secret_ref: str
    tag_hex: str
    scheme: str = ANCHOR1_SCHEME

    def __post_init__(self) -> None:
        if not isinstance(self.org, str) or not self.org:
            raise AegisAnchorError("ProducerAnchor.org must be a non-empty str")
        if not isinstance(self.connector_id, str) or not self.connector_id:
            raise AegisAnchorError("ProducerAnchor.connector_id must be a non-empty str")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or self.epoch < 0:
            raise AegisAnchorError("ProducerAnchor.epoch must be a non-negative int")
        if not isinstance(self.secret_ref, str) or not self.secret_ref:
            raise AegisAnchorError("ProducerAnchor.secret_ref must be a non-empty str")
        if not isinstance(self.tag_hex, str) or not self.tag_hex:
            raise AegisAnchorError("ProducerAnchor.tag_hex must be a non-empty str")
        if not isinstance(self.scheme, str) or not self.scheme:
            raise AegisAnchorError("ProducerAnchor.scheme must be a non-empty str")

    def redacted(self) -> dict[str, str]:
        """A value-free dict for a log / report / spine line — by construction it holds no secret (the HMAC
        ``tag_hex`` is a one-way function of the secret, never the secret itself)."""
        return {
            "org": self.org,
            "connector_id": self.connector_id,
            "epoch": str(self.epoch),
            "secret_ref": self.secret_ref,
            "scheme": self.scheme,
        }


@dataclass(frozen=True)
class AnchorVerification:
    """The result of a two-anchor check. ``trustworthy`` is True IFF BOTH anchors verify (prove-don't-guess);
    the per-anchor booleans + ``reason`` say which conjunct failed, for an honest fail-closed log."""

    trustworthy: bool
    anchor1_ok: bool
    anchor2_ok: bool
    reason: str


def produce_producer_anchor(record: CanonicalModel, *, org: str, connector_id: str, epoch: int,
                            secret: bytes) -> ProducerAnchor:
    """MINT anchor-1 for ``record`` under a connector's opened secret (producer-side; the producer holds the
    secret). The tag is the AS-2h domain-separated HMAC-SHA256 ``secret_mac`` over the record's canonical
    bytes, keyed by ``secret`` and bound to ``(CONNECTOR, org, connector_id, epoch)`` — so a tag made for one
    connector/epoch can never validate under another (confused-deputy wall), and a one-byte change to the
    record changes the canonical bytes and the tag. Deterministic: no clock, no RNG. Raises
    :class:`AegisAnchorError` on a malformed input (the secret bound is enforced by ``secret_mac``)."""
    payload = _canonical_bytes(record)
    try:
        tag = secret_mac(secret, SecretKind.CONNECTOR, org, connector_id, epoch, payload)
    except SealingError as exc:
        raise AegisAnchorError(f"cannot mint anchor-1 for connector {connector_id!r}: {exc}") from exc
    return ProducerAnchor(
        org=org, connector_id=connector_id, epoch=epoch,
        secret_ref=connector_secret_ref(org, connector_id, epoch), tag_hex=tag.hex())


def verify_producer_anchor(record: CanonicalModel, anchor: ProducerAnchor, *, secret: bytes) -> tuple[bool, str]:
    """VERIFY anchor-1: ``(ok, reason)``, True iff ``anchor.tag_hex`` is the valid connector-secret HMAC over
    ``record``'s canonical bytes under ``secret`` for ``anchor``'s declared ``(org, connector_id, epoch)``.
    Fail-closed and NEVER raises on hostile input. Conjuncts (each refuses):

      1. the anchor's ``scheme`` is :data:`ANCHOR1_SCHEME` (an unknown scheme is not silently accepted);
      2. ``anchor.secret_ref`` is well-formed and self-consistent — it EQUALS
         :func:`connector_secret_ref` of the anchor's own ``(org, connector_id, epoch)`` (the anchor cannot
         lie about which credential identity it used);
      3. the recomputed ``secret_mac`` tag equals ``anchor.tag_hex`` in CONSTANT TIME.

    A wrong-secret, a tampered body (canonical bytes differ), or a wrong-connector anchor (the tag was made
    under a different connector's secret, so the recompute under THIS connector's ``secret`` mismatches) all
    land on conjunct 3 ⇒ refused. ``secret`` is the connector's opened credential (see
    :func:`open_and_verify_producer_anchor` for the sealed-store path)."""
    if anchor.scheme != ANCHOR1_SCHEME:
        return False, f"anchor-1: unknown scheme {anchor.scheme!r} (expected {ANCHOR1_SCHEME!r})"
    ref = anchor.secret_ref.strip().lower()
    if len(ref) != _FINGERPRINT_CHARS or any(c not in _SECRET_REF_ALPHABET for c in ref):
        return False, f"anchor-1: secret_ref {anchor.secret_ref!r} is not a {_FINGERPRINT_CHARS}-char hex fingerprint"
    try:
        expected_ref = connector_secret_ref(anchor.org, anchor.connector_id, anchor.epoch)
    except AegisAnchorError as exc:
        return False, f"anchor-1: malformed connector identity — {exc}"
    if not hmac.compare_digest(ref, expected_ref):
        return False, ("anchor-1: secret_ref does not match the declared (org, connector, epoch) — "
                       "the anchor misstates which credential identity it used")
    try:
        got = bytes.fromhex(anchor.tag_hex)
    except ValueError:
        return False, "anchor-1: tag_hex is not valid hex"
    try:
        want = secret_mac(secret, SecretKind.CONNECTOR, anchor.org, anchor.connector_id, anchor.epoch,
                          _canonical_bytes(record))
    except Exception:  # noqa: BLE001 — any crypto/model failure is a fail-closed refusal
        return False, "anchor-1: HMAC recomputation failed (malformed secret or record)"
    if not hmac.compare_digest(want, got):
        return False, ("anchor-1: connector-secret HMAC does not verify — refusing the record "
                       "(wrong secret, tampered body, or wrong connector)")
    return True, f"anchor-1 verified: produced by connector {anchor.connector_id!r} (secret_ref {ref})"


def open_and_verify_producer_anchor(record: CanonicalModel, anchor: ProducerAnchor, *,
                                    sealed: SealedSecret, kek: bytes) -> tuple[bool, str]:
    """VERIFY anchor-1 by opening the AS-9a SEALED connector credential first (the sovereign-side path): open
    ``sealed`` transiently under ``kek``, then :func:`verify_producer_anchor` under the opened secret.
    Fail-closed and never raises. The sealed credential MUST be exactly this connector's at this epoch — a
    :class:`SealedSecret` of kind ``CONNECTOR`` whose ``(org, scope, epoch)`` equals the anchor's
    ``(org, connector_id, epoch)`` — else the presented credential is the WRONG connector's (confused-deputy)
    and is refused BEFORE any open. A SealError on open (tamper / wrong-KEK / AAD mismatch) is a refusal that
    names no secret bytes."""
    if not isinstance(sealed, SealedSecret):
        return False, "anchor-1: sealed credential must be a SealedSecret"
    if sealed.kind is not SecretKind.CONNECTOR:
        return False, f"anchor-1: sealed credential is kind {sealed.kind.value!r}, not a connector credential"
    if sealed.org != anchor.org or sealed.scope != anchor.connector_id or sealed.epoch != anchor.epoch:
        # The sealed credential presented is not this (org, connector, epoch)'s — a confused-deputy ask to
        # verify connector X's record under connector Y's sealed secret. Refuse before opening anything.
        return False, ("anchor-1: sealed credential binds "
                       f"({sealed.org!r}, {sealed.scope!r}, e{sealed.epoch}) but the anchor declares "
                       f"({anchor.org!r}, {anchor.connector_id!r}, e{anchor.epoch}) (wrong connector)")
    try:
        secret = open_secret(kek, sealed)
    except (SealError, SealingError):
        return False, (f"anchor-1: sealed credential for connector {anchor.connector_id!r} "
                       f"(secret_ref {anchor.secret_ref}) failed to open (fail-closed)")
    return verify_producer_anchor(record, anchor, secret=secret)


def verify_owner_anchor(record: CanonicalModel, entries: list[ChainEntry], head: SignedChainHead,
                        trust_root: TrustRoot, *, prev_highwater: int | None = None) -> tuple[bool, str]:
    """VERIFY anchor-2: ``(ok, reason)``, True iff ``record`` is covered by the OWNER-signed spine head.
    Fail-closed and never raises on hostile input. Conjuncts (each refuses):

      1. the owner head verifies over ``entries`` (:func:`vigil_core.chain.verify_head`): the chain links
         cleanly (a reorder breaks ``prev_hash``, a tamper breaks ``entry_hash``), the head's
         ``head_hash`` / ``last_seq`` / ``entry_count`` match (truncation/rollback caught), the owner
         threshold signature is valid, and — if ``prev_highwater`` is given — ``last_seq`` has not rolled
         back below it;
      2. ``record``'s :func:`record_cert_digest` appears as a ``cert_digest`` among ``entries`` — so a valid
         head over OTHER records does not launder THIS record in.

    Once both hold, tampering with or reordering the stored record detectably breaks the owner-signed head."""
    try:
        ok, reason = verify_head(head, entries, trust_root, prev_highwater=prev_highwater,
                                 genesis_prev=head.base_prev_hash)
    except Exception as exc:  # noqa: BLE001 — malformed head/sig/key material is a fail-closed refusal
        return False, f"anchor-2: owner head verification failed — {type(exc).__name__}"
    if not ok:
        return False, f"anchor-2: owner-signed head does not verify — {reason}"
    try:                                     # a non-canonical / hostile record is a fail-closed refusal, not a raise
        digest = record_cert_digest(record)
    except Exception as exc:  # noqa: BLE001 — honour the "never raises on hostile input" contract, as anchor-1 does
        return False, f"anchor-2: record digest failed — {type(exc).__name__}"
    if not any(hmac.compare_digest(e.cert_digest, digest) for e in entries):
        return False, "anchor-2: record is not present in the owner-anchored chain (not covered by the head)"
    return True, "anchor-2 verified: record is anchored by the owner-signed spine head"


def verify_anchored_record(record: CanonicalModel, anchor: ProducerAnchor, *, secret: bytes,
                           entries: list[ChainEntry], head: SignedChainHead, trust_root: TrustRoot,
                           prev_highwater: int | None = None) -> AnchorVerification:
    """The combined two-anchor check: :func:`verify_producer_anchor` (anchor-1, under the opened ``secret``)
    AND :func:`verify_owner_anchor` (anchor-2). ``trustworthy`` is True IFF BOTH hold — ANY single-anchor
    failure ⇒ refused (prove-don't-guess, fail-closed). Never raises on hostile input."""
    a1_ok, a1_why = verify_producer_anchor(record, anchor, secret=secret)
    a2_ok, a2_why = verify_owner_anchor(record, entries, head, trust_root, prev_highwater=prev_highwater)
    return _combine(a1_ok, a1_why, a2_ok, a2_why)


def verify_anchored_record_sealed(record: CanonicalModel, anchor: ProducerAnchor, *,
                                  sealed: SealedSecret, kek: bytes, entries: list[ChainEntry],
                                  head: SignedChainHead, trust_root: TrustRoot,
                                  prev_highwater: int | None = None) -> AnchorVerification:
    """As :func:`verify_anchored_record`, but anchor-1 opens the AS-9a SEALED connector credential under
    ``kek`` first (:func:`open_and_verify_producer_anchor`) — the sovereign-side path that needs no plaintext
    secret in hand. ``trustworthy`` IFF both anchors hold. Never raises on hostile input."""
    a1_ok, a1_why = open_and_verify_producer_anchor(record, anchor, sealed=sealed, kek=kek)
    a2_ok, a2_why = verify_owner_anchor(record, entries, head, trust_root, prev_highwater=prev_highwater)
    return _combine(a1_ok, a1_why, a2_ok, a2_why)


def require_trustworthy(verification: AnchorVerification) -> None:
    """The strict fail-closed wrapper: raise :class:`AegisAnchorError` unless ``verification.trustworthy``
    (BOTH anchors verified). Callers that must treat an un-anchored record as a hard stop use this; callers
    that want an honest ``(ok, reason)`` read the :class:`AnchorVerification` directly."""
    if not verification.trustworthy:
        raise AegisAnchorError(f"record is not trustworthy — {verification.reason}")


def _combine(a1_ok: bool, a1_why: str, a2_ok: bool, a2_why: str) -> AnchorVerification:
    trustworthy = a1_ok and a2_ok
    if trustworthy:
        reason = f"both anchors verified ({a1_why}; {a2_why})"
    else:
        failed = "; ".join(w for ok, w in ((a1_ok, a1_why), (a2_ok, a2_why)) if not ok)
        reason = f"refused — {failed}"
    return AnchorVerification(trustworthy=trustworthy, anchor1_ok=a1_ok, anchor2_ok=a2_ok, reason=reason)


def _canonical_bytes(record: CanonicalModel) -> bytes:
    """The one serialisation anchor-1 signs: the record's deterministic canonical bytes. Raises
    :class:`AegisAnchorError` fail-closed if ``record`` is not an AS-2b canonical value object."""
    if not isinstance(record, CanonicalModel):
        raise AegisAnchorError("record must be a vigil_core.aegis_schemas.CanonicalModel (AS-2b value object)")
    return record.canonical_bytes()
