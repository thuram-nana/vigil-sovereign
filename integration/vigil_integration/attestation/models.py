"""
attestation.models — the typed records of the always-on usage-attestation ledger (VIGIL WS6).

Every field here is signed DATA, not a decision input: the chain order is ``(seq, prev_hash)`` alone —
``at`` (the wall WHEN) and ``monotonic`` (the anti-back-dating anchor) are bound and signed but never
used to order the chain, so the ledger math carries no wallclock/RNG. Each model is ``extra="forbid"``
and totally-defaulted where safe, so a malformed/attacker-influenceable row (a torn spine line, a forged
JSON blob) either validates into a well-formed record or is rejected — it can never smuggle an unknown
field past the boundary.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from vigil_core.models import Signature

# The ``prev_hash`` of the genesis attestation in a ledger — the same all-zero sentinel the shared
# spine chain uses (``vigil_core.models._GENESIS_PREV``), kept identical so the two chains speak one
# genesis vocabulary.
GENESIS_PREV: str = "0" * 64


class OperatorIdentity(BaseModel):
    """WHO used the tool. Binds the OS login, the git ``user.name``/``user.email``, an Ed25519 key
    FINGERPRINT (sha256-hex of the operator's raw public key — the non-repudiation handle a signature's
    ``key_id`` must match), and the hostname. Every field defaults to ``""`` so a partially-resolvable
    box never raises; :meth:`is_bound` is the fail-closed test the ledger applies before it will mint or
    accept a record — an identity with no signing fingerprint AND no human handle is not an operator."""

    model_config = ConfigDict(extra="forbid")

    os_login: str = ""
    git_name: str = ""
    git_email: str = ""
    key_fingerprint: str = ""   # sha256-hex of the operator's raw Ed25519 public key (the signing key_id)
    hostname: str = ""

    def is_bound(self) -> bool:
        """A genuine binding needs the signing-key fingerprint (the cryptographic non-repudiation anchor)
        AND at least one human handle (login / git name / git email). Fail-closed: an all-empty or
        fingerprint-less identity is NOT bound, so it can neither mint nor pass verification."""
        return bool(self.key_fingerprint.strip()) and bool(
            self.os_login.strip() or self.git_name.strip() or self.git_email.strip()
        )


class MonotonicAnchor(BaseModel):
    """The anti-back-dating anchor for one record. ``value`` never decreases across a ledger (a TPM
    monotonic counter when present, else a persisted software counter); ``grounded`` records which
    source produced it. It is signed DATA — proof an entry could not have been minted before an earlier
    one — never a chain-ordering key."""

    model_config = ConfigDict(extra="forbid")

    value: int = Field(ge=0)
    grounded: str = "software"   # "tpm" | "software"


class UsageAttestation(BaseModel):
    """One signed, hash-chained, append-only record binding WHO (``operator``) did WHAT
    (``action``/``target``/``phase``) WHEN (``at`` + ``monotonic``/``grounded``).

    ``record_hash`` is the sha256 of the canonical signed content (the chain link — a later record's
    ``prev_hash`` equals it). ``signature`` is an Ed25519 signature over the domain-tagged signing bytes
    of that same content; its ``key_id`` MUST equal ``operator.key_fingerprint`` (identity ↔ signature
    binding). Every free-string field (``action``/``target``/``phase``/``at``) is redacted through the
    one F3 vocabulary at mint time, so no credential is ever committed to the ledger."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0)
    prev_hash: str = GENESIS_PREV
    operator: OperatorIdentity
    action: str = ""
    target: str = ""
    phase: str = ""
    at: str = ""                       # the wall WHEN — an injected DATA field, never read from the clock
    monotonic: int = Field(ge=0)       # the anti-back-dating anchor value (never decreases along a ledger)
    grounded: str = "software"         # "tpm" | "software"
    record_hash: str = Field(min_length=1)
    signature: Signature               # Ed25519 over the signing bytes; key_id == operator.key_fingerprint


class WhoEntry(BaseModel):
    """One row of the ``ledger_who`` replay: WHO did WHAT at each ``seq`` (non-repudiation view)."""

    model_config = ConfigDict(extra="forbid")

    seq: int
    action: str
    target: str
    phase: str
    operator: OperatorIdentity


class WhenEntry(BaseModel):
    """One row of the ``ledger_when`` replay: WHEN each ``seq`` happened (wall ``at`` + monotonic anchor)."""

    model_config = ConfigDict(extra="forbid")

    seq: int
    at: str
    monotonic: int
    grounded: str
