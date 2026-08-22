"""capability_token — a nine-field-bound, single-use, owner-signed CAPABILITY TOKEN validated at the
EXECUTOR boundary, immediately before the thing that acts runs (W13-5 #498).

WHY THIS EXISTS
---------------
An authorization decision is made far from the thing that acts (the gate chain runs, an owner approves,
a plan is composed), so by the time the OFFENSE executor actually launches a tool the decision can be
**stale, replayed, or reused for a DIFFERENT operation**. This module closes that window: the executor
validates a token bound to the EXACT operation it is about to run, right before it runs it, and burns a
single-use nonce so the same authorization cannot fire twice or be transplanted onto another operation.

NOT A SECOND POLICY ENGINE (the programme's HARD CONSTRAINT). This module makes NO authorization
decision — it does not decide who may do what. The gate chain (``conjunctive_gate`` /
``sovereign_bridge`` / ``require_capability`` / WARDEN tiers) already did. A capability token is the
owner-signed RECEIPT of that decision, bound to a concrete operation; this module only VALIDATES that a
presented token matches the operation the executor is about to run and CONSUMES its nonce exactly once.
That is exactly the discipline :mod:`approval_token` already uses for a per-action approval — this is its
sibling at the executor boundary, with the fuller nine-field binding W13-5 specifies.

THE NINE BOUND FIELDS (all signed; the executor validates every one against the operation it is about to
run — a mismatch on any is a fail-closed DENY):

  1. ``deployment``     — which deployment this authorization was minted for (a token for deployment A
                          cannot authorize an operation running in deployment B).
  2. ``engagement``     — the engagement/charter slug (no cross-engagement transplant).
  3. ``operation_hash`` — :func:`operation_hash` over (tool, target, args): binds the CONCRETE invocation
                          including flags, so a token for ``sqlmap … --dump`` cannot run ``… --os-shell``.
  4. ``target``         — the NORMALIZED target the tool runs against (a distinct, legible field so a
                          "different target" refusal is directly assertable).
  5. ``tool``           — the tool identity.
  6. ``danger_class``   — the WARDEN danger class of the operation (a recon token cannot fire an exploit).
  7. ``policy_digest``  — a digest of the policy under which the grant was issued: a token minted under an
                          old/other policy is refused (the executor pins the policy it is enforcing under).
  8. ``expiry``         — the ``not_after`` bound; a token past expiry is void (a stale decision cannot act).
  9. ``nonce``          — a single-use nonce burned in the EXISTING O_EXCL :class:`nonce_ledger.NonceLedger`
                          at the executor boundary, so a replayed token loses the atomic race and is refused.

(An additional signed ``not_before``/issued-at bounds the validity window from below and, with the
policy's ``max_token_lifetime``, is the dead-man's-switch against a pre-signed long-lived sleeper token.)

FAIL-CLOSED on every axis, first failure wins, any error is a DENY (never an exception a caller could
swallow into an allow): malformed input, schema mismatch, ANY of the nine bindings mismatching the
operation, outside the validity window, an over-long (sleeper) window, a key_id that is not the pinned
deployment owner key, an already-consumed nonce, a forged/tampered signature. The nonce burn happens ONLY
after signature + all nine bindings + window pass, so an invalid token can never grief-burn a victim's
nonce; and the burn is the SERIALIZATION POINT (the ``O_EXCL`` create), so of N concurrent presentations
of the same token exactly one wins and every replay loses.

FATAL-2 / import-clean: ``vigil_core`` + stdlib only (no ``framework.*`` / ``strix.*`` / ``sigil.*``).
Verification uses the PUBLIC key only, so this module is safe to import in either environment; minting
(which needs the private key) is a sovereign-side act.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace as _dc_replace
from numbers import Real
from typing import Any, Callable

from vigil_core import IntegrityError, canonical_json, sign, verify_one
from vigil_core.crypto import load_public_key

from .nonce_ledger import NonceLedger

# A fresh domain tag: a capability token can NEVER be replayed as a per-action approval, a destruction
# authorization, an evidence certificate, or any other signed artifact — and vice versa.
_CAPABILITY_DOMAIN = b"vigil-executor-capability-token-v1\x00"
_CAPABILITY_SCHEMA = "vigil-executor-capability"

# The seven operation-identifying fields the token binds to the operation the executor is about to run.
# (``expiry``/``not_before``/``nonce`` are validity mechanics, not operation identity.)
_BOUND_OPERATION_FIELDS = (
    "deployment", "engagement", "operation_hash", "target", "tool", "danger_class", "policy_digest",
)


def _is_real(x: object) -> bool:
    # a genuine real number, but NOT bool (bool is an int subclass; a boolean window is malformed)
    return isinstance(x, Real) and not isinstance(x, bool)


def operation_hash(tool: str, target: str, tool_args: Any) -> str:
    """A stable ``sha256:`` digest binding the CONCRETE operation — tool, target, AND its args (flags) — so
    a token minted for one invocation cannot authorize a different one even against the same host.
    Deterministic (``canonical_json`` sorts keys); total (a non-serialisable ``tool_args`` raises TypeError,
    which every caller here turns into a DENY)."""
    body = canonical_json({"tool": str(tool), "target": str(target), "args": tool_args})
    return "sha256:" + hashlib.sha256(body).hexdigest()


def policy_digest(policy: Any) -> str:
    """A stable ``sha256:`` digest of the policy under which a grant is issued/enforced. The executor pins
    the digest of the policy it is enforcing under; a token whose ``policy_digest`` differs was minted under
    a different policy and is refused. Deterministic + total."""
    body = canonical_json({"policy": policy})
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class CapabilityAuthority:
    """Immutable, deployment-time trust config: the OWNER's pinned public key + its key_id. The
    verification key is bound HERE, never taken from the token — a per-call key_id could be renamed to a
    compromised worker's own registered id (the I4 free-``owner_key_id`` BLOCK class). Validated
    fail-closed at construction: a non-canonical / low-order / malformed public key is rejected by
    ``load_public_key`` here, before any verify uses it."""

    owner_key_id: str
    owner_public_key_b64: str

    def __post_init__(self) -> None:
        if not (isinstance(self.owner_key_id, str) and self.owner_key_id):
            raise ValueError("CapabilityAuthority needs a non-empty owner_key_id")
        if not (isinstance(self.owner_public_key_b64, str) and self.owner_public_key_b64):
            raise ValueError("CapabilityAuthority needs the owner public key")
        load_public_key(self.owner_public_key_b64)  # rejects non-canonical / low-order / malformed keys


@dataclass(frozen=True)
class CapabilityGrant:
    """The concrete operation the executor is about to run, described by the SEVEN operation-identifying
    bound fields. The executor builds this from what it is actually about to do (deployment/engagement it
    runs under, the operation_hash of the exact invocation, the normalized target, the tool, the danger
    class, and the digest of the policy it enforces under) and checks the presented token against it."""

    deployment: str
    engagement: str
    operation_hash: str
    target: str
    tool: str
    danger_class: str
    policy_digest: str


@dataclass(frozen=True)
class CapabilityToken:
    """What the owner signs: the seven operation-identifying bound fields + a bounded validity window
    (``not_before``/``expiry``) + a single-use ``nonce`` + the signer ``key_id``. ``signature_b64`` covers
    every OTHER field (the signing payload), so any tamper of any bound field fails verification."""

    deployment: str
    engagement: str
    operation_hash: str
    target: str
    tool: str
    danger_class: str
    policy_digest: str
    not_before: float
    expiry: float
    nonce: str
    key_id: str
    signature_b64: str
    schema: str = _CAPABILITY_SCHEMA

    def signing_payload(self) -> dict:
        """The exact fields the signature covers — every field EXCEPT the signature, in a fixed shape.
        ``canonical_json`` sorts keys, so this re-serialises byte-for-byte."""
        return {
            "schema": self.schema,
            "deployment": self.deployment,
            "engagement": self.engagement,
            "operation_hash": self.operation_hash,
            "target": self.target,
            "tool": self.tool,
            "danger_class": self.danger_class,
            "policy_digest": self.policy_digest,
            "not_before": self.not_before,
            "expiry": self.expiry,
            "nonce": self.nonce,
            "key_id": self.key_id,
        }

    def matches(self, grant: "CapabilityGrant") -> bool:
        """True iff every one of the seven operation-identifying bound fields equals the grant's."""
        return all(getattr(self, f) == getattr(grant, f) for f in _BOUND_OPERATION_FIELDS)


@dataclass(frozen=True)
class CapabilityPolicy:
    """The dead-man's-switch bound. A token whose window exceeds ``max_token_lifetime`` seconds is VOID —
    the owner cannot pre-sign a long-lived sleeper capability."""

    max_token_lifetime: float = 900.0  # 15 minutes


DEFAULT_POLICY = CapabilityPolicy()


@dataclass(frozen=True)
class CapabilityDecision:
    authorized: bool
    reason: str
    nonce: str = ""  # on authorized=True, the nonce that was (verify) checkable / (consume) burned


class CapabilityRefused(RuntimeError):
    """A capability token did not authorize the operation at the executor boundary — the operation must not
    proceed. Fail-closed; must never be silently caught (it is the executor-boundary leg of the gate)."""


def token_signing_bytes(token: CapabilityToken) -> bytes:
    return _CAPABILITY_DOMAIN + canonical_json(token.signing_payload())


def mint_capability_token(
    grant: CapabilityGrant,
    *,
    owner_private_key_b64: str,
    key_id: str,
    nonce: str,
    not_before: float,
    expiry: float,
) -> CapabilityToken:
    """Provisioning/test helper (SOVEREIGN-side — needs the private key): build + owner-sign a token bound
    to ``grant``. The private key is used ONLY here; it never crosses to the offense executor/verifier."""
    token = CapabilityToken(
        deployment=grant.deployment,
        engagement=grant.engagement,
        operation_hash=grant.operation_hash,
        target=grant.target,
        tool=grant.tool,
        danger_class=grant.danger_class,
        policy_digest=grant.policy_digest,
        not_before=float(not_before),
        expiry=float(expiry),
        nonce=str(nonce),
        key_id=str(key_id),
        signature_b64="",
    )
    sig = sign(owner_private_key_b64, token_signing_bytes(token))
    # dataclasses.replace (not a {**__dict__, "signature_b64": sig} splat): the string-literal field name
    # tripped gitleaks' generic-api-key heuristic (a false positive on "signature_b64"); replace() binds the
    # field by keyword with no quoted literal and is the idiomatic frozen-dataclass update.
    return _dc_replace(token, signature_b64=sig)


def _well_formed(grant: object, token: object) -> str:
    """"" if the inputs are structurally sound, else a deny reason. EXACT-type checks (``type(x) is C``),
    not ``isinstance``: a caller-supplied subclass could override ``matches``/``signing_payload`` to
    decouple the binding from the signed bytes, so only the concrete records are accepted."""
    if type(grant) is not CapabilityGrant or type(token) is not CapabilityToken:
        return "malformed grant or token"
    for name in _BOUND_OPERATION_FIELDS:
        if type(getattr(grant, name)) is not str:
            return f"grant field {name!r} is not a string"
    for name in (*_BOUND_OPERATION_FIELDS, "nonce", "key_id", "schema", "signature_b64"):
        if type(getattr(token, name)) is not str:
            return f"token field {name!r} is not a string"
    if not _is_real(token.not_before) or not _is_real(token.expiry):
        return "token window is not numeric"
    return ""


def verify_capability_token(
    token: CapabilityToken,
    grant: CapabilityGrant,
    *,
    authority: CapabilityAuthority,
    now: float,
    is_consumed: Callable[[str], bool],
    policy: CapabilityPolicy = DEFAULT_POLICY,
) -> CapabilityDecision:
    """Fail-closed decision on whether ``token`` authorizes ``grant`` (the operation the executor is about to
    run) right now, validating ALL nine bound fields. First failure wins; any error is a DENY, never an
    exception a caller might swallow into an allow. ``is_consumed`` is REQUIRED (no permissive default) — pass
    the ledger-derived single-use check. This is a PURE check (it does NOT burn); use
    :func:`consume_capability_token` for the atomic check-and-burn at the executor boundary."""
    reason = _well_formed(grant, token)
    if reason:
        return CapabilityDecision(False, reason)
    if not _is_real(now):
        return CapabilityDecision(False, "now is not numeric")
    if type(authority) is not CapabilityAuthority:
        return CapabilityDecision(False, "malformed capability authority")

    # (schema) a token minted for a different signed-artifact shape is refused.
    if token.schema != _CAPABILITY_SCHEMA:
        return CapabilityDecision(False, f"unexpected token schema {token.schema!r}")

    # (bindings 1-7) the owner signed THIS exact operation — deployment, engagement, operation_hash,
    # target, tool, danger_class, policy_digest — not another. Report WHICH field mismatched.
    for name in _BOUND_OPERATION_FIELDS:
        if getattr(token, name) != getattr(grant, name):
            return CapabilityDecision(
                False, f"token does not match this operation: {name} bound to "
                       f"{getattr(token, name)!r}, operation is {getattr(grant, name)!r}")

    # (binding 8: expiry) validity window (nan compares False → deny).
    if not (token.not_before <= now <= token.expiry):
        return CapabilityDecision(False, "outside the token validity window (expired/early)")

    # dead-man's-switch: a bounded, sane, non-sleeper window.
    if not (token.expiry > token.not_before):
        return CapabilityDecision(False, "non-positive token window")
    if (token.expiry - token.not_before) > policy.max_token_lifetime:
        return CapabilityDecision(False, "token window exceeds max lifetime (sleeper-token bound)")

    # key pin — the token must name the deployment owner key; a per-call key_id can never self-authorize.
    if token.key_id != authority.owner_key_id:
        return CapabilityDecision(
            False, f"token key_id {token.key_id!r} is not the pinned owner key {authority.owner_key_id!r}")

    # (binding 9: nonce) single-use (advisory early-reject; the AUTHORITATIVE burn is
    # consume_capability_token's atomic try_consume).
    if not token.nonce:
        return CapabilityDecision(False, "token has no nonce (single-use undecidable)")
    try:
        if is_consumed(token.nonce):
            return CapabilityDecision(False, "token already consumed (replay)")
    except Exception:  # noqa: BLE001 — a single-use check error is fail-closed
        return CapabilityDecision(False, "single-use check errored — fail closed")

    # signature — over the exact signed bytes, against the PINNED owner public key. A forged / wrong-key /
    # tampered token fails here. verify_one already bars non-canonical / low-order keys.
    try:
        ok = verify_one(authority.owner_public_key_b64, token_signing_bytes(token), token.signature_b64)
    except (IntegrityError, TypeError, ValueError):
        return CapabilityDecision(False, "malformed signature/key material — fail closed")
    if not ok:
        return CapabilityDecision(False, "token signature is invalid (forged/tampered)")

    return CapabilityDecision(True, "owner-authorized (capability token, nine-field bound)", nonce=token.nonce)


def consume_capability_token(
    token: CapabilityToken,
    grant: CapabilityGrant,
    *,
    authority: CapabilityAuthority,
    now: float,
    ledger: NonceLedger,
    policy: CapabilityPolicy = DEFAULT_POLICY,
) -> CapabilityDecision:
    """Atomic check-AND-burn AT THE EXECUTOR BOUNDARY: verify ``token`` authorizes ``grant`` against all nine
    bound fields, then ATOMICALLY spend its nonce via ``ledger`` (the ``O_EXCL`` create is the serialization
    point, so of concurrent presentations of the same token exactly one wins). The burn happens ONLY after
    signature + all nine bindings + window pass, so an invalid token can never grief-burn a victim's nonce. A
    token that loses the atomic race (a concurrent/prior spend) is a DENY (replay). Any ledger error is a DENY
    (never authorize a burn we could not exclusively reserve). NOTE: the burn is at the AUTHORIZATION point —
    a token whose downstream execution then fails is spent (re-approve); this is the safe direction for
    single-use (a token can never fire an operation twice)."""
    if type(ledger) is not NonceLedger:
        return CapabilityDecision(False, "malformed nonce ledger")
    decision = verify_capability_token(
        token, grant, authority=authority, now=now, is_consumed=ledger.is_consumed, policy=policy
    )
    if not decision.authorized:
        return decision
    try:
        won = ledger.try_consume(token.nonce)
    except Exception:  # noqa: BLE001 — a ledger I/O error / blank nonce is fail-closed
        return CapabilityDecision(False, "nonce burn errored — fail closed")
    if not won:
        return CapabilityDecision(False, "token already consumed (lost the single-use race — replay)")
    return CapabilityDecision(True, "owner-authorized (capability token, single-use spent)", nonce=token.nonce)


def require_capability_token(
    token: CapabilityToken, grant: CapabilityGrant, *, ledger: NonceLedger, **kwargs: Any
) -> str:
    """Raise :class:`CapabilityRefused` fail-closed unless ``token`` authorizes ``grant`` (atomic burn at the
    executor boundary). Returns the spent nonce. MUST NOT be wrapped in a bare ``except``. ``authority`` must
    come from immutable deployment config, never from the token."""
    decision = consume_capability_token(token, grant, ledger=ledger, **kwargs)
    if not decision.authorized:
        raise CapabilityRefused(decision.reason)
    return decision.nonce
