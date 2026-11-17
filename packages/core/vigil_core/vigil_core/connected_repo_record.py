"""Connected-repo schema, canonical signing bytes, and an owner-side signer (Red-Pen R2).

The FATAL-2-clean integrity core for a CONNECTED GITHUB REPOSITORY — the SOVEREIGN AUTHORIZATION OF RECORD that
a tenant (``org_id``) connected ONE repository (``github.com/org/repo``) under ONE GitHub App installation, with
a per-repo merge-blocking ``threshold`` and an optional monthly spending ``limit``. Defined ONCE here in the
shared core so the sovereign plane (which holds the owner key and mints the record after a ``manage_code``
request) and any later verifier agree BY CONSTRUCTION over the exact bytes, never by a drift-catching test.

It is a DISTINCT capability from an asset-ownership PROOF, a monitoring grant and an offense-test
``EngagementAuthority``: connecting a repository you administer on GitHub is the white-box, owner-authorized
basis for VIGIL to REVIEW that repository's pull requests — ``own-a-repo != own-a-host != observe != offense-test``.
The distinct domain tag (``connected-repo`` in :data:`spine_domains.DOMAIN_TAGS`) makes that separation
CRYPTOGRAPHIC: a connected-repo signature can never satisfy an ownership-proof, monitoring, credit-lease or
engagement-authority check, or vice-versa.

The settings live INSIDE the owner-signed canonical bytes, so a tenant cannot lift a monthly ``limit`` or relax a
merge-blocking ``threshold`` without a FRESH owner signature, and ``issued_at`` is the per-(org, repo) anti-replay
high-water (a captured record can never resurrect a disconnected repository: its ``issued_at`` sits at or below the
high-water). Pure, validated data + Ed25519 over a domain-separated canonical core — the owner private key is used
only inside :func:`sign` and is never persisted or returned. Mirrors ``monitoring_authority.py`` /
``credit_lease.py`` exactly (same canonical form, same fail-closed verify)."""
from __future__ import annotations

import enum
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot
from .spine_domains import DOMAIN_TAGS

# Domain-separation prefix — distinct from authority / monitoring / credit-lease / every other signed purpose, so
# a connected-repo signature can never be replayed as (or satisfied by) any other kind. Sourced from the ONE
# registry; never change without a schema bump + migration (it invalidates every existing signature).
_CONNECTED_REPO_DOMAIN = DOMAIN_TAGS["connected-repo"]

# A canonical GitHub repository reference: ``github.com/<owner>/<repo>`` — the single form the slug, the egress
# path builder and the review lease all key on. Owner / repo are GitHub's own charset (alnum, ``-``, ``_``, ``.``),
# each 1..100 chars, no ``..``/``/`` traversal past the two segments. Lower-cased host, case-preserved owner/repo.
_REPO_RE = re.compile(r"github\.com/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})")


def check_repo(repo: object) -> str:
    """Validate + normalise a connected-repo reference to ``github.com/<owner>/<repo>`` (fail-closed ValueError).
    Rejects a scheme, a port, a query/fragment, extra path segments, ``.git`` suffix, ``..`` traversal or
    whitespace, so the reference is one unambiguous literal the egress path builder and the slug can trust."""
    r = str(repo or "").strip()
    if r.endswith(".git"):
        r = r[: -len(".git")]
    if not _REPO_RE.fullmatch(r) or ".." in r:
        raise ValueError("repo must be of the form github.com/<owner>/<repo> (no scheme, port, query, "
                         "extra path segment or '..')")
    return r


def repo_owner_name(repo: str) -> "tuple[str, str]":
    """``(owner, name)`` of a validated ``github.com/<owner>/<repo>`` reference — what the egress path builder
    (``/repos/{owner}/{repo}/...``) needs. Validates first (never trusts an un-checked string)."""
    _, owner, name = check_repo(repo).split("/", 2)
    return owner, name


class BlockThreshold(str, enum.Enum):
    """Which reproduced-FACT severities make the "VIGIL Red-Pen" check block the merge (owner decision, §12).

      * ``NONE`` — never block (review comments only; the check is always neutral/success).
      * ``CRITICAL_HIGH`` — block on a reproduced Critical or High FACT (the default).
      * ``MEDIUM_UP`` — block on a reproduced Medium or higher FACT.

    Only reproduced FACTs are ever posted (decision O-1); LEADs stay on the dashboard. The threshold is inside the
    signed bytes, so a tenant cannot relax it without a fresh owner signature."""

    NONE = "none"
    CRITICAL_HIGH = "critical_high"
    MEDIUM_UP = "medium_up"


class ConnectedRepoRecord(BaseModel):
    """The per-tenant, per-repository connection + policy the Red-Pen reserve/metering spine checks."""

    model_config = ConfigDict(extra="forbid")

    org_id: str = Field(min_length=1, description="The tenant this connection authorizes reviews for.")
    installation_id: int = Field(ge=1, description="The GitHub App installation id the sovereign mints "
                                 "short-lived per-repo access tokens from (never the App key itself).")
    repo: str = Field(min_length=1, description="The single repository, github.com/<owner>/<repo> (bound here so a "
                      "connection cannot be re-aimed at another repository).")
    block_threshold: BlockThreshold = Field(
        default=BlockThreshold.CRITICAL_HIGH,
        description="Which reproduced-FACT severities block the merge check (none | critical_high | medium_up).")
    monthly_limit_credits: int = Field(
        default=0, ge=0, description="The per-repo per-calendar-month spending ceiling in CREDITS; 0 = no limit. "
        "At the limit the enqueue/charge gate refuses NEW reviews and lets an in-flight review finish (O-2). "
        "Inside the signed bytes: a tenant cannot lift it without a fresh owner signature.")
    issued_at: float = Field(default=0.0, description="Mint anchor / per-(org, repo) anti-replay high-water on the "
                             "minting spine (a captured record cannot resurrect a disconnected repository).")
    note: str = Field(default="")

    @field_validator("repo")
    @classmethod
    def _check_repo(cls, v: str) -> str:
        return check_repo(v)


class SignedConnectedRepoRecord(BaseModel):
    """A connected-repo record plus governance signatures over its canonical form, verified against the owner
    ``TrustRoot``. A tampered org / installation / repo / threshold / limit / issued_at is detected (every field is
    in the signed bytes)."""

    model_config = ConfigDict(extra="forbid")

    document: ConnectedRepoRecord
    signatures: list[Signature] = Field(min_length=1)


def connected_repo_signing_bytes(record: ConnectedRepoRecord) -> bytes:
    """The exact bytes a signer signs / a verifier checks: the domain tag followed by the compact, sorted-key
    UTF-8 JSON of the document (byte-identical shape to ``monitoring_authority_signing_bytes`` / credit-lease)."""
    return _CONNECTED_REPO_DOMAIN + canonical_json(record.model_dump(mode="json"))


def sign_connected_repo_record(document: ConnectedRepoRecord, signers: dict[str, str]) -> SignedConnectedRepoRecord:
    """Sign a connected-repo record with each ``key_id -> private_key_b64``. Sovereign-side (the OWNER signs);
    the private key is used only inside :func:`sign` and never persisted or returned."""
    msg = connected_repo_signing_bytes(document)
    signatures = [Signature(key_id=key_id, signature_b64=sign(priv_b64, msg)) for key_id, priv_b64 in signers.items()]
    return SignedConnectedRepoRecord(document=document, signatures=signatures)


def verify_connected_repo_record(signed: SignedConnectedRepoRecord, trust_root: TrustRoot) -> "tuple[bool, str]":
    """Return ``(ok, reason)``. True iff at least the threshold of DISTINCT trust-root authorisers validly signed
    the record's canonical form. Verify-only (no private material). Fail-CLOSED and contract-honouring: never
    raises. Rejects a quorum-collapsing trust root (duplicate authorizer public keys under distinct key_ids)
    exactly as the authority / monitoring / credit-lease primitives do, and a malformed / weak-key signature is a
    refusal, never an uncaught crash in the fold."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(connected_repo_signing_bytes(signed.document), signed.signatures, trust_root)
    except (IntegrityError, TypeError, ValueError) as e:   # ValueError: a document that cannot be UTF-8 encoded
        return False, f"connected-repo signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason
