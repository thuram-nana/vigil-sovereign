"""
common.context_sealing — seal, AT REST, the credential/PII-bearing fields of a retained
offline-re-verifiable ``oracle_context`` WITHOUT breaking offline re-verification (Wave-A2).

THE PROBLEM. A confirmed FACT persists a re-verifiable ``oracle_context`` so that
``python3 -m framework.v2 verify <reverifiable.json>`` can re-fire the deterministic oracle
offline. Two arms retain captured SECRET / raw-response material in that context, and it was
stored in PLAINTEXT at rest, protected only by ``chmod 0o600``:

  * the **exposure secret-signature arm** (``live.runtime_redrive``) puts the leaked
    credential in ``observed_evidence.secret_value`` and ``observed_evidence.secret_assignment``,
    and the WHOLE ``.env`` body it was read from in ``observed_evidence.body``.

  * the **error-signature arm** (``proof.run._strix_errsig_redrive``) retains the RAW response
    bytes the datastore/parser error was matched in (``error_observed``) and its benign twin
    (``error_control``).

THE LOAD-BEARING DETERMINATION (measured, not assumed — see the Wave-A2 tests). Every one of
these fields is LOAD-BEARING: the deterministic oracle RE-FIRES over it during verify.

  * exposure — ``runtime_redrive._secret_value_predicates`` is a JSON-AST conjunction that binds
    ``body``, ``secret_assignment`` AND ``secret_value`` (``contains(body, secret_assignment)``,
    ``contains(secret_assignment, secret_value)``, ``min_len(secret_value, …)``, …). Blind-
    redacting ANY of the three makes the conjunction fail → the certificate no longer re-fires.
    And the leaked value is INTRINSIC to ``body`` (the oracle re-fires ``icontains(body, sig)``),
    so it can never be removed by redaction while keeping re-verifiability.

  * error-signature — ``error_signature_oracle`` re-fires by matching the engine-error signature
    IN ``error_observed`` and its ABSENCE in ``error_control``. Redacting either breaks the fire.

Because the material is load-bearing, it is **not** a non-load-bearing duplicate that could be
dropped: blind redaction would break re-verification. It is therefore SEALED (crypto-shredding,
``common.crypto_shred.EvidenceKeyring``): encrypted under a per-engagement DEK held OUTSIDE the
append-only spine, so it is

  * unreadable at rest (the sealed JSON carries no plaintext secret),
  * RECOVERABLE IN-ENGAGEMENT for re-verify (verify unseals with the local DEK, then re-fires
    the pure oracle over the byte-identical plaintext), and
  * UNRECOVERABLE after ``framework.v2 erase-evidence`` shreds the DEK (the correct post-erasure
    state — verify then reports the finding as no-longer-reproducible, fail-closed).

The sealing is DETERMINISTIC in SHAPE (only the AES-GCM nonce is random), so a non-secret
context is returned byte-identical and untouched. This module is the SINGLE source of truth for
which fields are sealed and how; both the persist side (``proof.run``) and the verify side
(``verify.reverify``) call it.

Offense-plane, sigil-free, offline. No network, no wallclock.
"""

from __future__ import annotations

import copy
from typing import Any

from .crypto_shred import EvidenceKeyring, is_sealed

# ---------------------------------------------------------------------------------------------------
# The fields that carry captured secret / raw-response material, by their location in oracle_context.
# A field is sealed IFF it is a non-empty string AND the context is secret-bearing (see below).
# ---------------------------------------------------------------------------------------------------

# Under ``oracle_context["observed_evidence"]`` (the exposure secret-signature arm). ``control_body``
# is DELIBERATELY excluded: it is the benign random-path body (carries no secret) and the predicate
# needs it in the clear for the ``not icontains(control_body, sig)`` differential clause.
_OBSERVED_EVIDENCE_FIELDS: tuple[str, ...] = ("body", "secret_assignment", "secret_value")

# At the top level of ``oracle_context`` (the error-signature arm): the raw observed response bytes
# and the raw benign-control bytes.
_TOPLEVEL_FIELDS: tuple[str, ...] = ("error_observed", "error_control")

# A context is SECRET-BEARING (and therefore sealed) IFF a MARKER field is present. Keying on the
# marker — rather than on any field name — leaves every other retained context (boolean/timing/xss/
# ssti/dom/web-differential …) byte-identical at rest and never touched by this module.
_EXPOSURE_MARKER = "secret_value"      # under observed_evidence
_ERRSIG_MARKER = "error_observed"      # top level


def context_carries_secret(oracle_context: Any) -> bool:
    """True iff ``oracle_context`` is one this module seals (an exposure secret-signature context
    or an error-signature context). Total on garbage."""
    if not isinstance(oracle_context, dict):
        return False
    oe = oracle_context.get("observed_evidence")
    if isinstance(oe, dict) and isinstance(oe.get(_EXPOSURE_MARKER), str) and oe.get(_EXPOSURE_MARKER):
        return True
    v = oracle_context.get(_ERRSIG_MARKER)
    return isinstance(v, str) and bool(v)


def _has_sealed_field(oracle_context: Any) -> bool:
    """True iff any KNOWN sealable field is already a sealed (``evs1:``) token. Targeted — never a
    whole-context scan — so a plaintext body that merely begins ``evs1:`` in some other key is not
    mistaken for a seal."""
    if not isinstance(oracle_context, dict):
        return False
    oe = oracle_context.get("observed_evidence")
    if isinstance(oe, dict):
        for k in _OBSERVED_EVIDENCE_FIELDS:
            if is_sealed(oe.get(k)) if isinstance(oe.get(k), str) else False:
                return True
    for k in _TOPLEVEL_FIELDS:
        v = oracle_context.get(k)
        if isinstance(v, str) and is_sealed(v):
            return True
    return False


def seal_oracle_context(oracle_context: Any, engagement: str, *,
                        keyring: EvidenceKeyring | None = None) -> Any:
    """Return ``oracle_context`` with its secret-bearing fields SEALED under the engagement DEK.

    A COPY is sealed and returned; the input is NEVER mutated (the plaintext context the signed
    certificate was minted over — retained in ``res.contexts`` / the in-memory mint result — stays
    intact). A context that carries no secret (:func:`context_carries_secret` is False) is returned
    UNCHANGED (identity) so every non-secret retained context is byte-identical at rest.

    RAISES on a sealing failure (unsafe engagement id, keystore I/O). The caller persists inside a
    best-effort ``try/except`` whose failure path simply does not write the artifact — so a sealing
    failure FAILS CLOSED (the plaintext secret is never written) rather than leaking it, at the cost
    of that one re-verifiable artifact (the signed certificate in ``res.facts`` is unaffected)."""
    if not context_carries_secret(oracle_context):
        return oracle_context
    kr = keyring or EvidenceKeyring()
    out = copy.deepcopy(oracle_context)
    oe = out.get("observed_evidence")
    if isinstance(oe, dict):
        for k in _OBSERVED_EVIDENCE_FIELDS:
            v = oe.get(k)
            if isinstance(v, str) and v and not is_sealed(v):
                oe[k] = kr.seal_text(engagement, v)
    for k in _TOPLEVEL_FIELDS:
        v = out.get(k)
        if isinstance(v, str) and v and not is_sealed(v):
            out[k] = kr.seal_text(engagement, v)
    return out


def unseal_oracle_context(oracle_context: Any, engagement: str, *,
                          keyring: EvidenceKeyring | None = None) -> Any:
    """Return ``oracle_context`` with every sealed (``evs1:``) field decrypted back to its EXACT
    original plaintext, so the pure oracle re-fires byte-identically.

    If NO field is sealed, the input is returned UNCHANGED (identity) — the plaintext re-verify path
    is 100% untouched. RAISES ``crypto_shred.CryptoShredError`` / ``EvidenceShredded`` if a sealed
    field cannot be recovered (DEK shredded, wrong engagement, or tampered ciphertext); the caller
    treats that as fail-closed (the finding does not re-confirm)."""
    if not _has_sealed_field(oracle_context):
        return oracle_context
    kr = keyring or EvidenceKeyring()
    out = copy.deepcopy(oracle_context)
    oe = out.get("observed_evidence")
    if isinstance(oe, dict):
        for k in _OBSERVED_EVIDENCE_FIELDS:
            v = oe.get(k)
            if isinstance(v, str) and is_sealed(v):
                oe[k] = kr.unseal_text(engagement, v)
    for k in _TOPLEVEL_FIELDS:
        v = out.get(k)
        if isinstance(v, str) and is_sealed(v):
            out[k] = kr.unseal_text(engagement, v)
    return out


__all__ = [
    "context_carries_secret",
    "seal_oracle_context",
    "unseal_oracle_context",
]
