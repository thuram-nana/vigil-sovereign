"""approval_token — a per-action, single-use, owner-signed approval token (VIGIL M2).

WHAT THIS REPLACES
------------------
Today ``wiring._approval_gate`` upgrades a WARDEN ``queue`` (in-envelope, owner-approval-needed) to
``allow`` on the strength of a STANDING boolean flag (``owner_approves_offense`` / ``--approve``): once set,
it blanket-approves EVERY queued offense action for the run. This module is the high-assurance alternative:
an approval authorizes EXACTLY ONE specific action — bound to its ``(tool_name, target, action_digest)`` —
is signed by the owner, is valid only inside a bounded window, and can be spent only ONCE.

It is the 1-of-1 sibling of :mod:`destruction_gate` (which is m-of-n for irreversible actions) and reuses
the SAME disciplines, all fail-closed (first failure wins; any error / malformed input is a DENY, never a
raise a caller could swallow into an allow):

  1. **Action binding** — the signed token names the exact action (tool, target, and an ``action_digest``
     that also covers the args). It cannot be replayed to authorize a DIFFERENT action.
  2. **Pinned owner key** — the signature is verified against the owner public key in the immutable,
     deployment-time :class:`ApprovalAuthority`, and the token's ``key_id`` MUST equal the authority's.
     The verification key is NOT a per-call string: a per-call ``key_id`` could be renamed to a
     compromised worker's own registered id (the I4 free-``owner_key_id`` BLOCK class), so it is fixed at
     deployment and a mismatch is a DENY.
  3. **Dead-man's-switch** — the validity window is bounded (``not_before``/``not_after`` and a
     policy-capped lifetime). A pre-signed, long-lived "sleeper" token is void.
  4. **Single-use** — the token carries one nonce. :func:`verify_token` CHECKS an injected ``is_consumed``
     (advisory early-reject) and returns the nonce; :func:`consume_token` performs the ATOMIC
     check-and-burn via :class:`nonce_ledger.NonceLedger` (the ``O_EXCL`` create is the serialization
     point), so of any number of concurrent callers of the SAME token exactly one wins and every replay
     loses. The burn happens ONLY after signature + binding + window all pass, so an invalid token can
     never grief-burn a victim's nonce.

A token NEVER widens scope: it upgrades a WARDEN ``queue`` to ``allow`` ONLY. A CRUCIBLE ``deny``
(out-of-scope / tripped kill-switch / budget) is a ``deny``, not a ``queue`` — the gate wrapper
(:func:`live.wiring.build_approval_gate`) leaves it untouched, so a token can neither lift the kill-switch
nor authorize an out-of-scope action.

FATAL-2 / import-clean: ``vigil_core`` + stdlib only (no ``framework.*`` / ``strix.*`` / ``sigil.*``).
Verification uses the PUBLIC key only, so this module is safe to import in either environment; minting
(which needs the private key) is a sovereign-side act.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from numbers import Real
from typing import Any, Callable

from vigil_core import IntegrityError, canonical_json, sign, verify_one
from vigil_core.crypto import load_public_key

from .nonce_ledger import NonceLedger

# A fresh domain tag: a per-action approval signature can NEVER be replayed as a destruction authorization,
# an evidence certificate, a transparency checkpoint, or any other signed artifact in the system.
_APPROVAL_DOMAIN = b"vigil-peraction-approval-v1\x00"
_APPROVAL_SCHEMA = "vigil-peraction-approval"


def _is_real(x: object) -> bool:
    # a genuine real number, but NOT bool (bool is an int subclass; a boolean window is malformed)
    return isinstance(x, Real) and not isinstance(x, bool)


def action_digest(tool_name: str, target: str, tool_args: Any) -> str:
    """A stable ``sha256:`` digest binding the FULL action — tool, target, AND its args — so a token minted
    for ``sqlmap @ host --dump`` cannot authorize ``sqlmap @ host --os-shell``. Deterministic
    (``canonical_json`` sorts keys); total (a non-serialisable ``tool_args`` raises TypeError, which every
    caller here turns into a DENY)."""
    body = canonical_json({"tool_name": str(tool_name), "target": str(target), "args": tool_args})
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class ApprovalAuthority:
    """Immutable, deployment-time approval trust config: the OWNER's pinned public key + its key_id. The
    verification key is bound here, never taken from the request — a per-call key could be renamed to a
    worker's own id (the I4 free-``owner_key_id`` BLOCK class). Validated fail-closed at construction: a
    non-canonical / low-order / malformed public key is rejected by ``load_public_key`` here, before any
    verify uses it."""

    owner_key_id: str
    owner_public_key_b64: str

    def __post_init__(self) -> None:
        if not (isinstance(self.owner_key_id, str) and self.owner_key_id):
            raise ValueError("ApprovalAuthority needs a non-empty owner_key_id")
        if not (isinstance(self.owner_public_key_b64, str) and self.owner_public_key_b64):
            raise ValueError("ApprovalAuthority needs the owner public key")
        load_public_key(self.owner_public_key_b64)  # rejects non-canonical / low-order / malformed keys


@dataclass(frozen=True)
class ApprovalAction:
    """The concrete action an offense worker wants to run. ``action_digest`` should be
    :func:`action_digest` over the exact tool+target+args so the token binds to *this* action."""

    tool_name: str
    target: str
    action_digest: str


@dataclass(frozen=True)
class ApprovalToken:
    """What the owner signs: the exact action, a bounded validity window, a single-use nonce, and the
    signer key_id. ``signature_b64`` covers every OTHER field (the signing payload), so any tamper fails."""

    tool_name: str
    target: str
    action_digest: str
    not_before: float
    not_after: float
    nonce: str
    key_id: str
    signature_b64: str
    schema: str = _APPROVAL_SCHEMA

    def signing_payload(self) -> dict:
        """The exact fields the signature covers — every field EXCEPT the signature, in a fixed shape.
        ``canonical_json`` sorts keys, so this re-serialises byte-for-byte."""
        return {
            "schema": self.schema,
            "tool_name": self.tool_name,
            "target": self.target,
            "action_digest": self.action_digest,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "nonce": self.nonce,
            "key_id": self.key_id,
        }

    def matches(self, action: ApprovalAction) -> bool:
        return (
            self.tool_name == action.tool_name
            and self.target == action.target
            and self.action_digest == action.action_digest
        )


@dataclass(frozen=True)
class ApprovalPolicy:
    """The dead-man's-switch bound. A token whose window exceeds ``max_token_lifetime`` seconds is VOID —
    the owner cannot pre-sign a long-lived sleeper."""

    max_token_lifetime: float = 900.0  # 15 minutes


DEFAULT_POLICY = ApprovalPolicy()


@dataclass(frozen=True)
class ApprovalDecision:
    authorized: bool
    reason: str
    nonce: str = ""  # on authorized=True, the nonce the caller must record as consumed on execution


class ApprovalRefused(RuntimeError):
    """A per-action approval was not satisfied — the action must not proceed. Fail-closed; must never be
    silently caught (it is the human leg of the conjunctive gate)."""


def token_signing_bytes(token: ApprovalToken) -> bytes:
    return _APPROVAL_DOMAIN + canonical_json(token.signing_payload())


def mint_token(
    action: ApprovalAction,
    *,
    owner_private_key_b64: str,
    key_id: str,
    nonce: str,
    not_before: float,
    not_after: float,
) -> ApprovalToken:
    """Provisioning/test helper (SOVEREIGN-side — needs the private key): build + owner-sign a token for
    ``action``. The private key is used ONLY here; it never crosses to the offense verifier."""
    token = ApprovalToken(
        tool_name=action.tool_name,
        target=action.target,
        action_digest=action.action_digest,
        not_before=float(not_before),
        not_after=float(not_after),
        nonce=str(nonce),
        key_id=str(key_id),
        signature_b64="",
    )
    sig = sign(owner_private_key_b64, token_signing_bytes(token))
    return ApprovalToken(**{**token.__dict__, "signature_b64": sig})


def _well_formed(action: object, token: object) -> str:
    """"" if the inputs are structurally sound, else a deny reason. EXACT-type checks (``type(x) is C``),
    not ``isinstance``: a caller-supplied subclass could override ``matches``/``signing_payload`` to
    decouple the action-binding from the signed bytes, so only the concrete records are accepted."""
    if type(action) is not ApprovalAction or type(token) is not ApprovalToken:
        return "malformed action or token"
    for name in ("tool_name", "target", "action_digest"):
        if type(getattr(action, name)) is not str:
            return f"action field {name!r} is not a string"
    for name in ("tool_name", "target", "action_digest", "nonce", "key_id", "schema", "signature_b64"):
        if type(getattr(token, name)) is not str:
            return f"token field {name!r} is not a string"
    if not _is_real(token.not_before) or not _is_real(token.not_after):
        return "token window is not numeric"
    return ""


def verify_token(
    token: ApprovalToken,
    action: ApprovalAction,
    *,
    authority: ApprovalAuthority,
    now: float,
    is_consumed: Callable[[str], bool],
    policy: ApprovalPolicy = DEFAULT_POLICY,
) -> ApprovalDecision:
    """Fail-closed decision on whether ``token`` authorizes ``action`` right now. First failure wins; any
    error is a DENY, never an exception a caller might swallow into an allow. ``is_consumed`` is REQUIRED
    (no permissive default) — pass the ledger-derived single-use check. Returns the nonce to consume on
    success. This is a PURE check (it does NOT burn); use :func:`consume_token` for the atomic
    check-and-burn."""
    reason = _well_formed(action, token)
    if reason:
        return ApprovalDecision(False, reason)
    if not _is_real(now):
        return ApprovalDecision(False, "now is not numeric")
    if type(authority) is not ApprovalAuthority:
        return ApprovalDecision(False, "malformed approval authority")

    # (1) schema — a token minted for a different signed-artifact shape is refused.
    if token.schema != _APPROVAL_SCHEMA:
        return ApprovalDecision(False, f"unexpected token schema {token.schema!r}")

    # (2) action binding — the owner signed THIS exact action (tool, target, args-digest), not another.
    if not token.matches(action):
        return ApprovalDecision(False, "token does not match this action (binding)")

    # (3) validity window (nan compares False → deny).
    if not (token.not_before <= now <= token.not_after):
        return ApprovalDecision(False, "outside the token validity window (expired/early)")

    # (4) dead-man's-switch: a bounded, sane, non-sleeper window.
    if not (token.not_after > token.not_before):
        return ApprovalDecision(False, "non-positive token window")
    if (token.not_after - token.not_before) > policy.max_token_lifetime:
        return ApprovalDecision(False, "token window exceeds max lifetime (dormant-token bound)")

    # (5) key pin — the token must name the deployment owner key; a per-call key_id can never self-authorize.
    if token.key_id != authority.owner_key_id:
        return ApprovalDecision(
            False, f"token key_id {token.key_id!r} is not the pinned owner key {authority.owner_key_id!r}"
        )

    # (6) single-use (advisory early-reject; the AUTHORITATIVE burn is consume_token's atomic try_consume).
    if not token.nonce:
        return ApprovalDecision(False, "token has no nonce (single-use undecidable)")
    try:
        if is_consumed(token.nonce):
            return ApprovalDecision(False, "token already consumed (replay)")
    except Exception:  # noqa: BLE001 — a single-use check error is fail-closed
        return ApprovalDecision(False, "single-use check errored — fail closed")

    # (7) signature — over the exact signed bytes, against the PINNED owner public key. A forged / wrong-key
    #     / tampered token fails here. verify_one already bars non-canonical / low-order keys.
    try:
        ok = verify_one(authority.owner_public_key_b64, token_signing_bytes(token), token.signature_b64)
    except (IntegrityError, TypeError, ValueError):
        return ApprovalDecision(False, "malformed signature/key material — fail closed")
    if not ok:
        return ApprovalDecision(False, "token signature is invalid (forged/tampered)")

    return ApprovalDecision(True, "owner-approved (per-action token)", nonce=token.nonce)


def consume_token(
    token: ApprovalToken,
    action: ApprovalAction,
    *,
    authority: ApprovalAuthority,
    now: float,
    ledger: NonceLedger,
    policy: ApprovalPolicy = DEFAULT_POLICY,
) -> ApprovalDecision:
    """Atomic check-AND-burn: verify ``token`` authorizes ``action``, then ATOMICALLY spend its nonce via
    ``ledger`` (the ``O_EXCL`` create is the serialization point, so concurrent callers of the same token —
    exactly one wins). The burn happens ONLY after signature + binding + window all pass, so an invalid
    token can never grief-burn a victim's nonce. A token that loses the atomic race (a concurrent/prior
    spend) is a DENY (replay). Any ledger error is a DENY (never authorize a burn we could not exclusively
    reserve). NOTE: the burn is at the AUTHORIZATION point — a token whose downstream execution then fails
    is spent (re-approve); this is the safe direction for single-use."""
    if type(ledger) is not NonceLedger:
        return ApprovalDecision(False, "malformed nonce ledger")
    decision = verify_token(
        token, action, authority=authority, now=now, is_consumed=ledger.is_consumed, policy=policy
    )
    if not decision.authorized:
        return decision
    try:
        won = ledger.try_consume(token.nonce)
    except Exception:  # noqa: BLE001 — a ledger I/O error / blank nonce is fail-closed
        return ApprovalDecision(False, "nonce burn errored — fail closed")
    if not won:
        return ApprovalDecision(False, "token already consumed (lost the single-use race — replay)")
    return ApprovalDecision(True, "owner-approved (per-action token, single-use spent)", nonce=token.nonce)


def require_approval(
    token: ApprovalToken, action: ApprovalAction, *, ledger: NonceLedger, **kwargs: Any
) -> str:
    """Raise :class:`ApprovalRefused` fail-closed unless ``token`` authorizes ``action`` (atomic burn).
    Returns the spent nonce. MUST NOT be wrapped in a bare ``except``. ``authority`` must come from
    immutable deployment config, never from the request."""
    decision = consume_token(token, action, ledger=ledger, **kwargs)
    if not decision.authorized:
        raise ApprovalRefused(decision.reason)
    return decision.nonce
