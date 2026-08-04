"""remediation.attestation_witness — VF-1c: a WITNESSED, TIME-BOUNDED checkpoint over the
Continuous Attestation Log head.

VF-1b (:mod:`remediation.attestation_log`) closes rollback against an attacker who can overwrite the
tick log + head but NOT the durable high-water floor. Its HONEST LIMIT is stated in that module: a
*fully-dishonest same-host producer* who rewrites the log, the head, AND the floor together defeats the
LOCAL verify path (it re-reads the floor from the same attacker-controlled disk). VF-1c closes that last
gap OUT-OF-BAND: an independent witness QUORUM co-signs the attestation-series head, so

  * **non-equivocation** — two verifiers cannot be shown divergent series (the operator cannot obtain a
    strict-majority quorum for two forks at one height without a witness equivocating), and
  * a **time bound** — each witness folds its own observed civil time ``τ_i`` INTO the signed bytes, and
    the quorum's *no-later-than* ``T = median(τ_i)``.

This module builds ONLY the *timed* layer on top of the already-verified, un-timed transparency
primitives — it re-uses :class:`transparency.Checkpoint`, :func:`transparency.checkpoint_of`, and
(exactly, for the quorum-shape gate) :func:`transparency.is_split_view_resistant`. It NEVER
re-implements the quorum-shape / distinct-canonical-key logic, and NEVER re-implements crypto (Ed25519
sign/verify come from ``vigil_core``).

Design of record: ``docs/proof-carrying-finding/WITNESS-TRUST.md`` §2 (independence + collusion) and §4
(the clock model). Read them before changing anything here.

--------------------------------------------------------------------------------------------------------
DOMAIN SEPARATION (why a timeless witness sig can NEVER be replayed as a timed one)
--------------------------------------------------------------------------------------------------------
:mod:`transparency` signs an UN-timed checkpoint under ``_WITNESS_DOMAIN`` =
``b"vigil-transparency-checkpoint-v1\\x00"``. This module signs a TIMED checkpoint under a DISTINCT tag,
``_ATTESTATION_WITNESS_TIME_DOMAIN`` = ``b"vigil-attestation-witness-time-v1\\x00"``, prepended to a
payload that *also* embeds ``observed_time``. Because Ed25519 binds the whole message, a signature made
over the transparency (timeless) bytes verifies ONLY against those bytes; presenting it as a
:class:`TimedWitnessSignature` (with any ``observed_time``) recomputes the message under the timed
domain + the embedded time and the verify fails. The converse holds too: a timed sig can never stand in
for a timeless transparency co-signature. The two layers are cryptographically non-interchangeable.

--------------------------------------------------------------------------------------------------------
THE QUORUM + MEDIAN RULE (exactly)
--------------------------------------------------------------------------------------------------------
* QUORUM SHAPE (fail-closed gate): :func:`transparency.is_split_view_resistant` must hold — a STRICT
  MAJORITY (``2*threshold > n``) over ``n`` DISTINCT, canonical Ed25519 keys (empty set, any duplicate
  public key, any non-canonical ``y >= p`` or low-order key → False). Without it, split-view PREVENTION
  is impossible (§2) and we refuse to emit a time bound.
* QUORUM COUNT: the number of DISTINCT verifying witnesses (deduplicated by the DECODED 32-byte public
  key, mirroring :func:`is_split_view_resistant`) must be ``>= threshold``. A signature whose ``key_id``
  is unknown to the trust root, whose key is weak/malformed, or whose signature does not verify is
  IGNORED (never counted) — fail-closed.
* NO-LATER-THAN ``T`` = the ``(n//2)``-th element of the SORTED distinct-verifying observed times, where
  ``n`` is the count of distinct verifying witnesses PRESENTED. For odd ``n`` this is the exact median; for
  even ``n`` it is the UPPER of the two central values (deterministic, integer, no averaging). The MEDIAN is
  sound ONLY under a strict-majority-HONEST **signing quorum** — and that is NOT a majority of the roster:
  the verifier judges the sigs it is HANDED, and a fully-dishonest PRODUCER curates them (it can drop honest
  sigs and present only its chosen quorum). So as few as ``floor(t/2)+1`` colluding signers — a roster
  MINORITY for a large ``n`` — can shift ``T`` (back- or post-date), potentially below the non-equivocation
  tolerance (``2t-n-1``). The code CANNOT check signer honesty. Mitigations: raise ``min_distinct_signers``
  toward ``n`` (a strict verifier demands the full roster, so the producer cannot drop honest signers), and —
  for a HARD time guarantee — the external RFC3161/OTS anchor over the checkpoint hash (WITNESS-TRUST §5),
  which supersedes this median. The non-equivocation guarantee (below) is STRICTLY STRONGER than this clock
  bound; do not conflate them.

--------------------------------------------------------------------------------------------------------
HONEST LIMIT (do NOT overclaim — WITNESS-TRUST §4)
--------------------------------------------------------------------------------------------------------
``T`` bounds WHEN THE HEAD WAS WITNESSED — i.e. that the attestation-series head existed and was
presented to the quorum no later than ``T`` — under two assumptions the CODE CANNOT check: (a) the
distinct keys are held by INDEPENDENT, mutually-distrusting operators (a green ``is_split_view_resistant``
proves distinct *keys*, not distinct *operators*), and (b) a strict-majority-honest quorum with bounded
inter-witness clock skew. It is a quorum civil-time bound with NO external service — WEAKER than a single
trusted RFC3161/OpenTimestamps anchor over the checkpoint hash (the designed, deferred hook, WITNESS-TRUST
§5), which when built SUPERSEDES this median-clock bound. Crucially, ``T`` does NOT prove WHEN THE ORACLE
RE-FIRED: a producer can present an OLD head to honest witnesses today and get a recent ``T`` — that
truthfully says "this head was witnessed today", NOT "a fresh re-verification ran today". Re-proof
freshness lives in the tick record itself (VF-1b) and in the target-echoed nonce (VF-1a); this layer
never lets a recent witness time stand in for a stale re-proof.

FATAL-2: module scope pulls ONLY stdlib + ``vigil_core`` + ``..transparency`` (all import-clean — no
``framework.v2``, no ``strix.*``, and deliberately NOT ``.attestation_log``/``.prove_driver`` so a
timed-witness build in the sovereign env never co-loads the offense engine). Determinism: no wallclock /
rng in the signed math — every ``observed_time`` is a CALLER INPUT (each witness's clock reading), never
read from the wall clock here.
"""
from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from vigil_core import (
    IntegrityError,
    SignedChainHead,
    TrustRoot,
    canonical_json,
    sign,
    verify_one,
)
from vigil_core.crypto import KeyPair, load_public_key

from ..transparency import Checkpoint, checkpoint_of, is_split_view_resistant
from ..time_anchor import anchor_checkpoint, verify_anchor

# A DISTINCT domain tag from transparency's ``_WITNESS_DOMAIN`` so a timeless witness signature can NEVER
# be replayed as a timed one (and vice-versa) — see the module docstring's DOMAIN SEPARATION section.
_ATTESTATION_WITNESS_TIME_DOMAIN = b"vigil-attestation-witness-time-v1\x00"

# The attestation log persists its governance-signed head here (mirrors attestation_log._HEAD_FILE); we
# read it directly rather than importing attestation_log, to keep this module's scope free of prove_driver.
_HEAD_FILE = "head.json"

_PathLike = Union[str, Path]


def _timed_signing_bytes(cp: Checkpoint, observed_time: int) -> bytes:
    """The exact bytes a witness signs for a TIMED co-signature: the distinct timed domain tag over a
    canonical payload that binds BOTH the checkpoint identity AND the witness's observed time. Because
    ``observed_time`` is inside the signed message, a witness cannot later have its reported time altered
    without invalidating its signature, and the timeless transparency bytes are a different message."""
    return _ATTESTATION_WITNESS_TIME_DOMAIN + canonical_json(
        {"checkpoint": cp.to_dict(), "observed_time": int(observed_time)}
    )


class TimedWitnessSignature(BaseModel):
    """One witness's TIMED co-signature: its ``key_id``, the civil time ``observed_time`` it folded into
    the signed bytes, and the Ed25519 ``signature_b64`` over :func:`_timed_signing_bytes`."""

    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(min_length=1)
    observed_time: int
    signature_b64: str = Field(min_length=1, description="base64(64-byte Ed25519 signature).")


def timed_cosign(
    cp: Checkpoint, *, witness_keypair: KeyPair, key_id: str, observed_time: int
) -> TimedWitnessSignature:
    """Produce one witness's TIMED co-signature over ``cp`` at the witness's ``observed_time``.

    ``observed_time`` is the witness's clock reading, supplied by the caller (determinism: never read
    from the wall clock in the signed math). It is folded INTO the signed bytes, so the pair
    (checkpoint, time) is atomically bound by this signature."""
    signature_b64 = sign(witness_keypair.private_key_b64, _timed_signing_bytes(cp, int(observed_time)))
    return TimedWitnessSignature(key_id=key_id, observed_time=int(observed_time), signature_b64=signature_b64)


class TimedWitnessedCheckpoint(BaseModel):
    """A checkpoint over the attestation-series head plus the TIMED witness co-signatures gathered over
    it. ``checkpoint`` is the public :meth:`Checkpoint.to_dict` summary (offline-serialisable for the
    VIGIL-free verifier); ``witness_signatures`` are the per-witness timed co-signatures.

    ``external_time_anchor`` (A1) is an OPTIONAL SIDECAR: base64 of a real RFC3161 TSA token
    (:func:`time_anchor.anchor_checkpoint`) minted over :func:`transparency.checkpoint_hash` of THIS
    checkpoint. It is a SIDECAR by construction — it is NOT inside ``checkpoint`` (so ``checkpoint_hash``
    is unchanged by anchoring), NOT inside the timed-witness signed bytes (:func:`_timed_signing_bytes`),
    and NOT inside the attestation-log tick-chain digest — so chain determinism is preserved (two runs
    yield byte-identical chains though token bytes vary with genTime). When present AND verifiable against
    a pinned TSA cert, its genTime SUPERSEDES the quorum-median no-later-than bound (see
    :func:`verify_timed_witnessed`)."""

    model_config = ConfigDict(extra="forbid")
    checkpoint: dict
    witness_signatures: list[TimedWitnessSignature] = Field(default_factory=list)
    external_time_anchor: Optional[str] = Field(
        default=None, description="base64(DER RFC3161 TimeStampResp) over checkpoint_hash — SIDECAR (A1)."
    )

    def as_checkpoint(self) -> Checkpoint:
        """Reconstruct the strongly-typed :class:`Checkpoint` from the stored public dict."""
        return Checkpoint(**self.checkpoint)


def verify_timed_witnessed(
    cp: Checkpoint,
    timed_sigs: "list[TimedWitnessSignature]",
    *,
    witness_trust_root: TrustRoot,
    min_distinct_signers: "Optional[int]" = None,
    external_time_anchor: "Optional[Union[bytes, str]]" = None,
    tsa_cert_pin: "Optional[str]" = None,
) -> "tuple[bool, Optional[int], str]":
    """Verify a strict-majority witness quorum TIMED-co-signed ``cp`` and return its no-later-than bound.

    Returns ``(ok, no_later_than_T, reason)``, FAIL-CLOSED at every step:

      1. **Quorum SHAPE** — refuse unless :func:`transparency.is_split_view_resistant` holds (a strict
         majority ``2*threshold > n`` over ``n`` distinct, canonical, non-low-order keys). Otherwise
         split-view prevention is impossible and no time bound is emitted:
         ``(False, None, "not split-view resistant: sub-majority / duplicate / weak witness key")``.
      2. **Verify + de-duplicate** — for each timed sig, resolve the authorizer by ``key_id`` and
         ``verify_one`` over :func:`_timed_signing_bytes` (each sig commits to its OWN ``observed_time``).
         Collect the DISTINCT verifying witnesses, deduplicated by the DECODED 32-byte public key
         (mirroring :func:`is_split_view_resistant`), and their observed times. An unknown ``key_id`` /
         weak-or-malformed key / non-verifying signature is IGNORED — never counted.
      3. **Quorum COUNT** — the number of distinct verifying witnesses must be ``>= threshold``, else
         ``(False, None, "quorum not met")``.
      4. **Time bound** — the median ``T`` = the ``(n//2)``-th element of the sorted distinct-verifying
         observed times (exact median for odd ``n``; upper-median for even ``n`` — deterministic, integer).
         A single dishonest witness's extreme ``τ`` cannot move a strict-majority-honest median.
      5. **External anchor (A1) — SUPERSEDES the median.** If ``external_time_anchor`` (a base64 or raw
         DER RFC3161 token) AND ``tsa_cert_pin`` are supplied, the token is verified against the pinned
         TSA cert over :func:`transparency.checkpoint_hash` of ``cp`` (:func:`time_anchor.verify_anchor`).
         On success its genTime becomes the no-later-than ``T`` — a single externally-trusted timestamp
         that does NOT depend on witness honesty/clocks. On FAILURE (tampered checkpoint → different hash;
         wrong/unpinned TSA cert; malformed token) the whole verify FAILS CLOSED — a present-but-bad anchor
         is never silently ignored. When no anchor is supplied, behaviour is unchanged: the median stands.

    NOTE (WITNESS-TRUST §4, and the docstring HONEST LIMIT): the median ``T`` bounds when the head was
    WITNESSED, not when the oracle re-fired, and independence of operators is a deployment assumption the
    code cannot verify; the external anchor's genTime is the stronger, witness-honesty-independent bound —
    but a *local* self-signed TSA proves only the MECHANISM, not third-party independence (A1 residual)."""
    # 1. quorum shape — reuse the merged strict-majority / distinct-canonical-key gate exactly.
    if not is_split_view_resistant(witness_trust_root):
        return False, None, "not split-view resistant: sub-majority / duplicate / weak witness key"

    by_id = {a.key_id: a for a in witness_trust_root.authorizers}
    # Map DECODED-key -> observed_time for each DISTINCT verifying witness (dedup mirrors is_split_view_resistant:
    # two key_ids sharing a pubkey collapse to one witness — but that case is already rejected at step 1).
    distinct_verified: dict[bytes, int] = {}
    for ts in timed_sigs:
        authorizer = by_id.get(ts.key_id)
        if authorizer is None:
            continue  # key_id not in the trust root — ignore, fail-closed
        try:
            decoded_key = load_public_key(authorizer.public_key_b64).public_bytes_raw()
        except IntegrityError:
            continue  # weak / non-canonical / malformed authorizer key — ignore, fail-closed
        if decoded_key in distinct_verified:
            continue  # already counted this witness (same decoded key) — never double-count
        try:
            verified = verify_one(
                authorizer.public_key_b64, _timed_signing_bytes(cp, ts.observed_time), ts.signature_b64
            )
        except (IntegrityError, TypeError, ValueError):
            # A MALFORMED / wrong-length / non-base64 signature must be IGNORED, never raised — a single bad
            # sig (from a relay, a corrupt tick, or a hostile producer appending garbage) must not crash the
            # offline verifier this layer exists to serve. Fail-closed: drop it, never count it.
            continue
        if verified:
            distinct_verified[decoded_key] = int(ts.observed_time)

    # 3. quorum count. Default requirement is the trust-root threshold; a strict verifier can raise it via
    #    ``min_distinct_signers`` (e.g. to n, the full roster) to blunt the CURATION attack in the note below —
    #    a dishonest producer choosing WHICH sigs the verifier sees cannot then drop honest signers.
    required = witness_trust_root.threshold
    if min_distinct_signers is not None:
        required = max(required, int(min_distinct_signers))
    if len(distinct_verified) < required:
        return False, None, f"quorum not met (need {required} distinct verifying witnesses, got {len(distinct_verified)})"

    # 4. no-later-than T = the (n//2)-th of the sorted distinct-verifying observed times (upper-median for
    #    even n; exact median for odd n). HONEST BOUND — this is sound ONLY if the PRESENTED signing quorum is
    #    strict-majority HONEST. That is NOT the same as a majority of the roster: a fully-dishonest PRODUCER
    #    curates which sigs the verifier sees (it can drop honest sigs and present only its chosen quorum), so
    #    as few as floor(t/2)+1 colluding signers — a roster MINORITY for a large n — can shift T (back- or
    #    post-date), possibly below the non-equivocation tolerance (2t-n-1). The code CANNOT check signer
    #    honesty; for a HARD time guarantee use the external RFC3161/OTS anchor over the checkpoint hash
    #    (WITNESS-TRUST §5), or raise ``min_distinct_signers`` toward n. See the module HONEST LIMIT.
    observed = sorted(distinct_verified.values())
    median_T = observed[len(observed) // 2]

    # 5. external RFC3161 anchor (A1) — SUPERSEDES the median when present + verifiable against the pin.
    #    A present-but-unverifiable anchor is FATAL (fail-closed): a caller that attaches an anchor is
    #    asserting the stronger bound, so a tampered checkpoint / wrong TSA cert must NOT fall back silently
    #    to the weaker median. The token is a SIDECAR (not in any signed digest); genTime is read from the
    #    SIGNED token, never the verifier wall clock.
    if external_time_anchor is not None and tsa_cert_pin is not None:
        try:
            token = (
                base64.b64decode(external_time_anchor, validate=True)
                if isinstance(external_time_anchor, str)
                else external_time_anchor
            )
        except (binascii.Error, ValueError):
            return False, None, "external time anchor present but not valid base64 (fail-closed)"
        anchor_ok, anchored_T = verify_anchor(cp, token, tsa_cert_pin=tsa_cert_pin)
        if not anchor_ok or anchored_T is None:
            return (
                False,
                None,
                "external time anchor present but did NOT verify against the pinned TSA cert over "
                "checkpoint_hash (tampered checkpoint / wrong TSA cert / malformed token) — fail-closed",
            )
        return (
            True,
            anchored_T,
            f"{len(distinct_verified)} distinct witness(es) co-signed; no-later-than T={anchored_T} = "
            f"RFC3161 external anchor genTime (SUPERSEDES the quorum-median {median_T}; witness-honesty-"
            f"independent — a local self-signed TSA proves the MECHANISM only, third-party independence is "
            f"the A1 residual)",
        )

    return (
        True,
        median_T,
        f"{len(distinct_verified)} distinct witness(es) co-signed; no-later-than T={median_T} = median of "
        f"the PRESENTED signing quorum's clocks (sound only if that quorum is strict-majority honest — a hard "
        f"time guarantee needs the external anchor)",
    )


def verify_timed_witnessed_checkpoint(
    twc: TimedWitnessedCheckpoint, *, witness_trust_root: TrustRoot,
    min_distinct_signers: "Optional[int]" = None,
    tsa_cert_pin: "Optional[str]" = None,
) -> "tuple[bool, Optional[int], str]":
    """Convenience: verify a bundled :class:`TimedWitnessedCheckpoint` (reconstructs the typed checkpoint
    from its public dict, then delegates to :func:`verify_timed_witnessed`). If the bundle carries a SIDECAR
    ``external_time_anchor`` AND ``tsa_cert_pin`` is supplied out-of-band, the anchor's genTime supersedes
    the median (A1) — and a present-but-unverifiable anchor then fails closed. If an anchor is present but
    NO pin is supplied, the verifier opts out of the stronger check and the honest median bound is returned
    (never the anchored T without verifying it) — no overclaim, just the weaker bound."""
    return verify_timed_witnessed(
        twc.as_checkpoint(), twc.witness_signatures, witness_trust_root=witness_trust_root,
        min_distinct_signers=min_distinct_signers,
        external_time_anchor=twc.external_time_anchor, tsa_cert_pin=tsa_cert_pin,
    )


def _load_attestation_head(log_dir: _PathLike) -> SignedChainHead:
    """Load the governance-signed attestation-log head persisted at ``<log_dir>/head.json`` (written by
    :mod:`remediation.attestation_log`). Read-only; we never write the log from here."""
    p = Path(log_dir) / _HEAD_FILE
    if not p.exists():
        raise FileNotFoundError(f"no attestation head at {p} (nothing to witness)")
    return SignedChainHead.model_validate_json(p.read_text(encoding="utf-8"))


def witness_attestation_head(
    log_dir: Optional[_PathLike] = None,
    *,
    witnesses: "list[tuple[KeyPair, str]]",
    observed_times: "list[int]",
    head: Optional[SignedChainHead] = None,
    tsa: "Optional[object]" = None,
) -> TimedWitnessedCheckpoint:
    """Emit a :class:`TimedWitnessedCheckpoint` over the Continuous Attestation Log head.

    Load the attestation head (either ``head`` directly, or from ``<log_dir>/head.json``), summarise it
    into a :class:`transparency.Checkpoint` via :func:`transparency.checkpoint_of`, and have each witness
    :func:`timed_cosign` it with its own ``observed_time``.

    ``witnesses`` is a list of ``(KeyPair, key_id)`` and ``observed_times`` is the PARALLEL list of each
    witness's clock reading (caller inputs — no wall-clock read here). If ``tsa`` (a
    :class:`time_anchor.TSA` — e.g. a :class:`time_anchor.LocalTSA` for CI/mechanism, or a
    :class:`time_anchor.RemoteTSA` for third-party independence) is supplied, a real RFC3161 token is minted
    over ``checkpoint_hash(cp)`` and attached as the SIDECAR ``external_time_anchor`` (base64) — it does NOT
    change the checkpoint, its signed bytes, or any chain digest. The result is NOT self-adjudicating: the
    caller MUST pass it (with the witness ``TrustRoot`` — and, for the anchor, the TSA cert — pinned
    out-of-band) through :func:`verify_timed_witnessed` / :func:`verify_timed_witnessed_checkpoint`, which
    enforce the strict-majority quorum and compute the no-later-than bound (anchor genTime superseding the
    median when a valid anchor + pin are present)."""
    if len(witnesses) != len(observed_times):
        raise ValueError(
            f"witnesses ({len(witnesses)}) and observed_times ({len(observed_times)}) must be parallel"
        )
    if head is None:
        if log_dir is None:
            raise ValueError("witness_attestation_head: provide either a head or a log_dir")
        head = _load_attestation_head(log_dir)

    cp = checkpoint_of(head)
    sigs = [
        timed_cosign(cp, witness_keypair=kp, key_id=key_id, observed_time=int(t))
        for (kp, key_id), t in zip(witnesses, observed_times)
    ]
    anchor_b64: Optional[str] = None
    if tsa is not None:
        # openssl is invoked lazily by anchor_checkpoint (only when a TSA is supplied) — importing
        # time_anchor itself needs no openssl, so the timed-witness core stays loadable without it.
        anchor_b64 = base64.b64encode(anchor_checkpoint(cp, tsa=tsa)).decode("ascii")
    return TimedWitnessedCheckpoint(
        checkpoint=cp.to_dict(), witness_signatures=sigs, external_time_anchor=anchor_b64
    )
