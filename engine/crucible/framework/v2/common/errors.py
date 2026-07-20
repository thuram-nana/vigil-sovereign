"""
common.errors — typed exception hierarchy for CRUCIBLE v2.

Exceptions are typed because the agent reasons about them. A bare
RuntimeError is an opaque blob; CharterNotSigned is a load-bearing
ethics signal. Catch the specific class, never the base.

EthicsViolation subclasses must propagate to the CLI; they are not
recoverable in code.
"""

from __future__ import annotations

from vigil_core import IntegrityError  # the shared integrity-error base (raised by the shared crypto layer)


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


class EngagementHalted(EthicsViolation):
    """The engagement's kill-switch is tripped. Every action is refused,
    fail-closed and persistently, until a new authority is issued. This
    is the hard stop — it survives process restart."""


class AuthorityExpired(EthicsViolation):
    """The engagement authority is outside its not_before..not_after
    window. Time-boxed authority has lapsed; re-authorise to continue."""


class SovereigntyViolation(EthicsViolation):
    """An action would route data or trust through non-sovereign
    infrastructure (cloud LLM, third-party telemetry endpoint, etc.)
    while the framework is running in sovereign mode
    (CRUCIBLE_SOVEREIGN_MODE=1).

    Raised at backend instantiation and at runtime egress-guard hooks
    so a misconfigured deployment fails closed at startup, not after
    the first prompt has already left the host."""


# ---------------------------------------------------------------------------
# Entitlement layer (Pillar 2 — controlled distribution).
#
# These gate dangerous capabilities behind a threshold-signed, host-bound
# entitlement. EntitlementViolation subclasses are EthicsViolations: a
# denied capability is an authorization-boundary crossing and must never
# be silently caught. See ROADMAP-FLAGSHIP.md § 3 (Pillar 2) and
# framework/v2/entitlement/.
# ---------------------------------------------------------------------------


class EntitlementViolation(EthicsViolation):
    """A gated capability was requested but the entitlement does not
    authorize it. Base class — callers catch the specific subclass."""


class EntitlementMissing(EntitlementViolation):
    """A gated capability was requested while enforcement is active but
    no entitlement document is provisioned. Fail closed: only baseline
    capabilities run without an entitlement."""


class EntitlementInvalid(EntitlementViolation):
    """An entitlement document is present but failed verification —
    bad/insufficient threshold signatures, canonical-form mismatch, or
    a malformed trust root. Treated as hostile: gated capabilities are
    denied with the failure reason."""


class EntitlementExpired(EntitlementViolation):
    """The entitlement is outside its not_before..not_after window."""


class EntitlementRevoked(EntitlementViolation):
    """The entitlement id appears on a validly-signed revocation list."""


class EntitlementBindingMismatch(EntitlementViolation):
    """The entitlement is bound to host/workload identifiers that do not
    match the machine the framework is running on. Possession of the
    entitlement on an un-attested host grants nothing."""


class CapabilityNotGranted(EntitlementViolation):
    """The entitlement is valid, current, and host-bound, but its
    capability tier does not include the requested capability."""


class EntitlementError(CrucibleError, IntegrityError):
    """Recoverable entitlement-layer error (file parse, store I/O) that
    is NOT itself an authorization decision. Also a vigil_core `IntegrityError`
    so the shared crypto layer's raises and CRUCIBLE's `except CrucibleError`
    both catch it. Distinct from
    EntitlementViolation so loaders can surface a clear cause without
    implying a capability was denied."""


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


class BackendOverloaded(BackendError):
    """A transient LLM backend failure that survived in-backend retry/backoff — rate
    limited (429), overloaded (529), a 5xx, or a connection/timeout. Distinct from a
    plain BackendError (a permanent/parse failure) so the dispatch layer can FAIL OVER
    to the next permitted backend in-tier rather than aborting the call (Speed X4)."""


class MemoryStoreError(CrucibleError):
    """MLS-layer error (storage, embedding, recall)."""


class EvalError(CrucibleError):
    """Evaluation-harness error — corpus load/parse, malformed ground
    truth, or a run record that fails schema validation. The eval layer
    measures capability; it makes no trust decision, so this is a plain
    recoverable CrucibleError, never an EthicsViolation."""


class SchemaMismatch(MemoryStoreError):
    """SQLite schema is older than expected; run migrate."""
