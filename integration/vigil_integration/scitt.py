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

# A valid RFC-6962 inclusion proof for a tree of size n has ceil(log2(n)) siblings; 64 bounds any
# conceivable log (2**64 leaves) and caps _rebuild_root recursion well under the interpreter limit.
_MAX_PROOF_DEPTH = 64

# The certificate fields the OpenVEX statement needs; a cert missing any is refused (fail-closed).
_REQUIRED_CERT_FIELDS = ("engagement_slug", "finding_ref", "bug_class", "oracle_context_digest", "confidence")


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
    if not isinstance(ss.payload_b64, str):
        return None  # a non-str payload (e.g. DSSE "payload": null) → fail closed, never raise
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
    envelope (type + payload + signatures). Signatures are sorted by (keyid, sig) so the digest is
    stable regardless of signature order — a genuine statement always binds its own receipt."""
    envelope = {
        "payloadType": ss.payload_type,
        "payload": ss.payload_b64,
        "signatures": sorted(
            ({"keyid": s.key_id, "sig": s.signature_b64} for s in ss.signatures),
            key=lambda d: (d["keyid"], d["sig"]),
        ),
    }
    return sha256_hex(canonical_json(envelope))


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
    receipt: Receipt,
    statement: SignedStatement,
    *,
    trust_root: TrustRoot,
    expected_root: str,
) -> tuple[bool, str]:
    """Offline: the statement's m-of-n signature verifies, the receipt binds THIS statement, and the
    inclusion proof reconstructs a log root that MATCHES the ``expected_root`` the verifier
    independently trusts. ``expected_root`` is REQUIRED — a receipt carries its own ``root``, so
    without pinning it to a root you obtained out-of-band (a witnessed I2 checkpoint, or a trusted
    log operator) an attacker could self-manufacture a receipt over their own root. Fail-closed."""
    if not isinstance(receipt, Receipt):
        return False, "malformed receipt"
    if not isinstance(expected_root, str) or receipt.root != expected_root:
        return False, "receipt root does not match the pinned (independently trusted) root"
    if not verify_signed_statement(statement, trust_root=trust_root):
        return False, "statement signature invalid"
    digest = statement_digest(statement)
    if receipt.statement_digest != digest:
        return False, "receipt does not bind this statement"
    if (not isinstance(receipt.leaf_index, int) or isinstance(receipt.leaf_index, bool)
            or not isinstance(receipt.tree_size, int) or isinstance(receipt.tree_size, bool)):
        return False, "malformed receipt index/size"
    # A valid proof has depth ceil(log2(tree_size)); anything past _MAX_PROOF_DEPTH is implausible for
    # any real log (2**64 leaves) and would only recurse _rebuild_root toward RecursionError — deny it.
    if not isinstance(receipt.audit_path, (tuple, list)) or len(receipt.audit_path) > _MAX_PROOF_DEPTH:
        return False, "receipt proof is malformed or implausibly deep"
    try:
        path = [bytes.fromhex(p) for p in receipt.audit_path]
        root = bytes.fromhex(receipt.root)
        included = verify_inclusion(bytes.fromhex(digest), receipt.leaf_index, receipt.tree_size, path, root)
    except (ValueError, TypeError, RecursionError):
        return False, "malformed receipt proof material"
    if not included:
        return False, "merkle inclusion proof invalid"
    return True, "offline-verified: signed statement included under the pinned log root"


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
    if not isinstance(witnessed, WitnessedCheckpoint) or not isinstance(witnessed.checkpoint, Checkpoint):
        return False, "malformed witnessed checkpoint"
    try:
        resistant = verify_split_view_resistant(witnessed, witness_trust_root=witness_trust_root)
    except Exception:
        return False, "malformed witness material — fail closed"
    if not resistant:
        return False, "checkpoint is not backed by a split-view-resistant witness quorum"
    # the pinned root IS the witness-attested checkpoint root — verify_receipt compares receipt.root
    # to it, so a receipt over any other (self-manufactured) root is refused.
    ok, reason = verify_receipt(
        receipt, statement, trust_root=trust_root, expected_root=witnessed.checkpoint.merkle_root
    )
    if not ok:
        return False, reason
    return True, "offline-verified: statement included in a witness-anchored transparency log"


def mint_finding_statement(
    cert: dict,
    signers: Iterable[tuple[str, str]],
    *,
    confirmed: bool,
    author: str,
    timestamp: str,
    log: "Optional[StatementLog]" = None,
) -> "tuple[SignedStatement, Optional[Receipt]]":
    """The bridge from a confirmed-finding certificate to a registered, offline-verifiable SCITT
    statement: build the OpenVEX statement (``confirmed`` drives affected vs under_investigation — the
    honesty invariant), sign it m-of-n as a DSSE statement, and (when a ``log`` is given) register it
    and return an inclusion receipt. Fail-closed: a non-dict cert, a cert missing a required field, or
    empty signers is refused. ``timestamp`` is caller-supplied (no wallclock — deterministic)."""
    if not isinstance(cert, dict):
        raise TypeError("cert must be a dict of certificate fields")
    # presence AND non-null: a null oracle_context_digest/finding_ref would mint a signed statement
    # with null provenance (honest-but-useless) — refuse it so the statement is always meaningful.
    missing = [f for f in _REQUIRED_CERT_FIELDS if cert.get(f) is None]
    if missing:
        raise ValueError(f"certificate missing required field(s) (absent or null): {missing}")
    signer_list = list(signers)
    if not signer_list:
        raise ValueError("mint_finding_statement requires governance signers (m-of-n)")
    statement = openvex_statement(cert, author=author, timestamp=timestamp, confirmed=confirmed)
    signed = build_signed_statement(statement, signer_list)
    if log is None:
        return signed, None
    index = log.register(signed)
    return signed, log.receipt(index)
