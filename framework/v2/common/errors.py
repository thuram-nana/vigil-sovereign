"""
common.errors — typed exception hierarchy for CRUCIBLE v2.

Exceptions are typed because the agent reasons about them. A bare
RuntimeError is an opaque blob; CharterNotSigned is a load-bearing
ethics signal. Catch the specific class, never the base.

EthicsViolation subclasses must propagate to the CLI; they are not
recoverable in code.
"""

from __future__ import annotations


class CrucibleError(Exception):
    """Root of v2's exception hierarchy."""


class CrucibleRootNotFound(CrucibleError):
    """No CRUCIBLE_ROOT set, and CLAUDE.md not found by walking up."""


# ---------------------------------------------------------------------------
# Ethics layer.  Never silently catch these.
# ---------------------------------------------------------------------------


class EthicsViolation(CrucibleError):
    """Anything that crosses an authorization or scope boundary."""


class CharterMissing(EthicsViolation):
    """A target has no charter file at all."""


class CharterNotSigned(EthicsViolation):
    """The charter file exists but the signature line is unfilled."""


class OutOfScope(EthicsViolation):
    """An action's target is not in the charter's in-scope allowlist."""


class AuthorizationMissing(EthicsViolation):
    """UTI was asked to draft against a URL with no operator attestation."""


class DestructiveActionRefused(EthicsViolation):
    """Operator declined a destructive-action prompt, or the prompt
    timed out and default-deny fired."""


class BudgetExhausted(EthicsViolation):
    """Per-engagement HTTP request budget has been spent. Further
    requests refused until the operator raises the cap or starts a
    new engagement."""


class SovereigntyViolation(EthicsViolation):
    """An action would route data or trust through non-sovereign
    infrastructure (cloud LLM, third-party telemetry endpoint, etc.)
    while the framework is running in sovereign mode
    (CRUCIBLE_SOVEREIGN_MODE=1).

    Raised at backend instantiation and at runtime egress-guard hooks
    so a misconfigured deployment fails closed at startup, not after
    the first prompt has already left the host."""


# ---------------------------------------------------------------------------
# Subsystem-level errors.  Recoverable in some contexts.
# ---------------------------------------------------------------------------


class IntakeBudgetExceeded(CrucibleError):
    """UTI's per-intake request cap was hit."""


class FingerprintInconclusive(CrucibleError):
    """Fingerprinter could not classify with any confidence."""


class BackendUnavailable(CrucibleError):
    """Configured LLM backend is not reachable / not installed."""


class BackendError(CrucibleError):
    """LLM backend was reachable but returned a failure."""


class MemoryStoreError(CrucibleError):
    """MLS-layer error (storage, embedding, recall)."""


class SchemaMismatch(MemoryStoreError):
    """SQLite schema is older than expected; run migrate."""
