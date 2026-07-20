"""
scitt — standards-native, offline-verifiable finding certificates (VIGIL I2-family, plan §8-C).

Expresses a VIGIL confirmed-finding certificate as an IETF SCITT-style SIGNED STATEMENT (a DSSE
envelope) carrying an OpenVEX statement as the finding vocabulary, plus a RECEIPT with a real
RFC-6962 Merkle inclusion proof binding the statement to the transparency log. A client / regulator /
court can then verify a finding OFFLINE and FOREVER — no VIGIL service, no network: just the payload,
the DSSE signatures against the governance trust root, the inclusion proof against the log root, and
(when anchored) the I2 witnessed checkpoint that attests that root.

Why DSSE (not raw COSE/CBOR): DSSE's Pre-Authentication Encoding (PAE) is pure/stdlib and
unambiguously binds the payload TYPE to the payload, so a statement signature can never be replayed
as a raw evidence signature (different signed bytes) — the same domain-separation property, standards-
shaped. Full COSE_Sign1/CBOR is a serialization refinement; the security property is identical.

OpenVEX gives the finding a portable vocabulary (vulnerability + product + status) a scanner or SBOM
tool already understands. Honesty invariant preserved: a CONFIRMED finding (oracle fired) is status
``affected``; an unconfirmed lead is ``under_investigation`` — NEVER asserted as ``affected``.

Import-clean: ``vigil_core`` + this package's ``transparency`` (both vigil_core-only) — no
``framework.*``/``strix.*``; the verification is sovereign-safe and runs in either environment.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Iterable, Optional

from vigil_core import (
    Signature,
    TrustRoot,
    canonical_json,
    sha256_hex,
    sign,
    verify_threshold,
)

from .transparency import Checkpoint, WitnessedCheckpoint, verify_split_view_resistant

_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
OPENVEX_MEDIA_TYPE = "application/vnd.openvex+json"  # the DSSE payloadType

STATUS_AFFECTED = "affected"                  # oracle-confirmed
STATUS_UNDER_INVESTIGATION = "under_investigation"  # an honest lead, never asserted affected


# --- OpenVEX finding vocabulary ----------------------------------------------------------------


def openvex_statement(cert: dict, *, author: str, timestamp: str, confirmed: bool) -> dict:
    """Build an OpenVEX statement from a VIGIL finding certificate. ``timestamp`` is caller-supplied
    (no wallclock here — deterministic + testable). A confirmed finding is ``affected``; anything
    else is ``under_investigation`` (the honesty invariant — an unconfirmed lead is never affected)."""
    status = STATUS_AFFECTED if confirmed else STATUS_UNDER_INVESTIGATION
    return {
        "@context": _OPENVEX_CONTEXT,
        "@id": f"vigil:vex:{cert['engagement_slug']}:{cert['finding_ref']}",
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": f"{cert['bug_class']}:{cert['finding_ref']}"},
                "products": [{"@id": f"vigil:engagement:{cert['engagement_slug']}"}],
                "status": status,
                # VIGIL provenance: the retained oracle context a re-run must reproduce, and the score.
                "vigil_oracle_context_digest": cert["oracle_context_digest"],
                "vigil_confidence": cert["confidence"],
            }
        ],
    }


# --- DSSE signed statement ---------------------------------------------------------------------


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: ``DSSEv1 SP len(type) SP type SP len(body) SP body``. Binds
    the payload TYPE into the signed bytes, so a statement signature is domain-separated from any raw
    evidence/checkpoint signature."""
    t = payload_type.encode("utf-8")
    return b" ".join([b"DSSEv1", str(len(t)).encode(), t, str(len(payload)).encode(), payload])


@dataclass(frozen=True)
class SignedStatement:
    """A DSSE envelope over a canonical OpenVEX payload, signed m-of-n by the governance trust root."""

    payload_type: str
    payload_b64: str
    signatures: tuple[Signature, ...] = ()

    def to_envelope(self) -> dict:
        return {
            "payloadType": self.payload_type,
            "payload": self.payload_b64,
            "signatures": [{"keyid": s.key_id, "sig": s.signature_b64} for s in self.signatures],
        }


def build_signed_statement(
    statement: dict, signers: Iterable[tuple[str, str]]
) -> SignedStatement:
    """Provisioning helper: canonicalize the OpenVEX statement, PAE it, and have each
    (key_id, private_key_b64) sign — the m-of-n governance signature over a DSSE envelope."""
    payload = canonical_json(statement)
    msg = _pae(OPENVEX_MEDIA_TYPE, payload)
    sigs = tuple(Signature(key_id=kid, signature_b64=sign(priv, msg)) for kid, priv in signers)
    return SignedStatement(OPENVEX_MEDIA_TYPE, base64.b64encode(payload).decode(), sigs)


def _decoded_payload(ss: SignedStatement) -> Optional[bytes]:
    try:
        return base64.b64decode(ss.payload_b64, validate=True)
    except (ValueError, binascii.Error):
        return None


def verify_signed_statement(ss: SignedStatement, *, trust_root: TrustRoot) -> bool:
    """Offline m-of-n verification of a signed statement over its DSSE PAE. Fail-closed."""
    if not isinstance(ss, SignedStatement):
        return False
    payload = _decoded_payload(ss)
    if payload is None:
        return False
    try:
        return verify_threshold(
            _pae(ss.payload_type, payload), list(ss.signatures), trust_root
        ).satisfied
    except Exception:
        return False


def statement_digest(ss: SignedStatement) -> str:
    """The transparency-log leaf identity of a signed statement: sha256 over its canonical DSSE
    envelope (type + payload + the exact signatures as registered)."""
    return sha256_hex(canonical_json(ss.to_envelope()))


# --- RFC 6962 Merkle transparency log ----------------------------------------------------------


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two STRICTLY less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _mth(leaves: "list[bytes]") -> bytes:
    """RFC 6962 Merkle Tree Hash over a list of raw leaf data."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _split(n)
    return _node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def _audit_path(m: int, leaves: "list[bytes]") -> "list[bytes]":
    """RFC 6962 inclusion proof for leaf index m, root-ward (deepest sibling first, top-level last)."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if m < k:
        return _audit_path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _audit_path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def _rebuild_root(leaf: bytes, m: int, n: int, path: "list[bytes]") -> Optional[bytes]:
    """Reconstruct the tree root from a leaf hash at index m of a tree of size n, consuming ``path``
    in the same (top-level-last) order ``_audit_path`` produced it. None on any shape mismatch."""
    if m < 0 or m >= n:
        return None
    if n <= 1:
        return leaf if not path else None
    if not path:
        return None
    k = _split(n)
    sibling, rest = path[-1], path[:-1]
    if m < k:
        left = _rebuild_root(leaf, m, k, rest)
        return _node_hash(left, sibling) if left is not None else None
    right = _rebuild_root(leaf, m - k, n - k, rest)
    return _node_hash(sibling, right) if right is not None else None


def verify_inclusion(data: bytes, m: int, n: int, audit_path: "list[bytes]", root: bytes) -> bool:
    """True iff ``data`` is the leaf at index m of an RFC-6962 tree of size n with the given root."""
    return _rebuild_root(_leaf_hash(data), m, n, audit_path) == root


@dataclass(frozen=True)
class Receipt:
    """A SCITT-style receipt: an offline inclusion proof that a signed statement is in the log."""

    statement_digest: str
    leaf_index: int
    tree_size: int
    audit_path: tuple[str, ...]
    root: str


class StatementLog:
    """Append-only RFC-6962 Merkle log of registered signed statements. Its ``root`` is what an I2
    witnessed checkpoint anchors (so the witness quorum attests the whole set — split-view resistant
    over the statement log too)."""

    def __init__(self) -> None:
        self._leaves: list[bytes] = []

    def register(self, ss: SignedStatement) -> int:
        self._leaves.append(bytes.fromhex(statement_digest(ss)))
        return len(self._leaves) - 1

    def size(self) -> int:
        return len(self._leaves)

    def root(self) -> str:
        return _mth(self._leaves).hex()

    def receipt(self, leaf_index: int) -> Receipt:
        return Receipt(
            statement_digest=self._leaves[leaf_index].hex(),
            leaf_index=leaf_index,
            tree_size=self.size(),
            audit_path=tuple(p.hex() for p in _audit_path(leaf_index, self._leaves)),
            root=self.root(),
        )


def verify_receipt(
    receipt: Receipt, statement: SignedStatement, *, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Offline: the statement's m-of-n signature verifies, the receipt binds THIS statement, and the
    inclusion proof reconstructs the log root. Fail-closed with a reason."""
    if not isinstance(receipt, Receipt) or not verify_signed_statement(statement, trust_root=trust_root):
        return False, "statement signature invalid or malformed receipt"
    digest = statement_digest(statement)
    if receipt.statement_digest != digest:
        return False, "receipt does not bind this statement"
    try:
        path = [bytes.fromhex(p) for p in receipt.audit_path]
        root = bytes.fromhex(receipt.root)
    except (ValueError, TypeError):
        return False, "malformed receipt proof material"
    if not verify_inclusion(bytes.fromhex(digest), receipt.leaf_index, receipt.tree_size, path, root):
        return False, "merkle inclusion proof invalid"
    return True, "offline-verified: signed statement included in the transparency log"


def verify_anchored_receipt(
    receipt: Receipt,
    statement: SignedStatement,
    witnessed: WitnessedCheckpoint,
    *,
    trust_root: TrustRoot,
    witness_trust_root: TrustRoot,
) -> tuple[bool, str]:
    """The full offline story: the receipt verifies (signature + inclusion) AND the log root it
    proves against is exactly the ``merkle_root`` of an I2 checkpoint that a split-view-resistant
    witness quorum countersigned. Ties SCITT provenance to the transparency log's tamper-evidence."""
    ok, reason = verify_receipt(receipt, statement, trust_root=trust_root)
    if not ok:
        return False, reason
    if not isinstance(witnessed, WitnessedCheckpoint) or not isinstance(witnessed.checkpoint, Checkpoint):
        return False, "malformed witnessed checkpoint"
    if witnessed.checkpoint.merkle_root != receipt.root:
        return False, "checkpoint does not anchor this log root"
    if not verify_split_view_resistant(witnessed, witness_trust_root=witness_trust_root):
        return False, "checkpoint is not backed by a split-view-resistant witness quorum"
    return True, "offline-verified: statement included in a witness-anchored transparency log"
