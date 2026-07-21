"""
vigil_integration.attestation — the always-on usage-attestation ledger (VIGIL WS6).

The operator's deep core for non-repudiation: a signed, hash-chained, append-only ledger that can always
determine WHEN this tool was used and BY WHOM. Every engagement/gated action mints an attestation FIRST
via :func:`require_attestation` (fail-closed: no attestation ⇒ the engine cannot proceed), binding the
operator identity (OS login + git name/email + operator Ed25519 key fingerprint + hostname), an attested
time (the wall ``at`` plus a TPM-or-software MONOTONIC anchor that never decreases, so nothing can be
back-dated), and the action/target/phase. :func:`verify_ledger` re-checks the whole chain + every
signature; :func:`ledger_who` / :func:`ledger_when` replay it.

Sovereign posture: the signer, monotonic anchor, ledger writer, and trust-anchor key resolver are all
INJECTED callables (unit-testable with no live kernel/TPM); the chain order is ``(seq, prev_hash)`` alone
so no wallclock/RNG touches the chain math (Ed25519 signing is deterministic); every public function is
total on malformed input and secret-free (``action``/``target`` are redacted through the one F3
vocabulary). Reuses the ``vigil_core`` crypto/canonical/chain seam.
"""

from __future__ import annotations

from .anchor import (
    DEFAULT_STATE_DIR,
    TpmProbe,
    read_monotonic_anchor,
)
from .identity import (
    DEFAULT_KEYPAIR_FILE,
    ResolveKeyFn,
    SignerFn,
    fingerprint,
    load_or_create_operator_keypair,
    operator_key_resolver,
    operator_signer,
    resolve_operator,
)
from .ledger import (
    AttestationVerdict,
    LedgerVerification,
    WriterFn,
    append_attestation,
    ledger_when,
    ledger_who,
    make_ledger_writer,
    read_ledger,
    record_usage,
    require_attestation,
    verify_ledger,
)
from .models import (
    GENESIS_PREV,
    MonotonicAnchor,
    OperatorIdentity,
    UsageAttestation,
    WhenEntry,
    WhoEntry,
)

__all__ = [
    # models
    "OperatorIdentity", "MonotonicAnchor", "UsageAttestation", "WhoEntry", "WhenEntry", "GENESIS_PREV",
    # minting + the fail-closed gate
    "record_usage", "require_attestation", "AttestationVerdict",
    # verification + replay
    "verify_ledger", "LedgerVerification", "ledger_who", "ledger_when",
    # durable ledger persistence
    "append_attestation", "read_ledger", "make_ledger_writer", "WriterFn",
    # live wiring (operator identity, keypair, signer, trust anchor, monotonic anchor)
    "resolve_operator", "load_or_create_operator_keypair", "operator_signer", "operator_key_resolver",
    "fingerprint", "read_monotonic_anchor", "SignerFn", "ResolveKeyFn", "TpmProbe",
    "DEFAULT_STATE_DIR", "DEFAULT_KEYPAIR_FILE",
]
