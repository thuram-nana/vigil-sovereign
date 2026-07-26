"""destruction_provision — generate + sign the m-of-n destruction quorum for `vigil patch --open-pr`.

The destructive PR leg needs three provisioned artifacts (see live/trusted_finding.py + destruction_gate.py):
  1. a ``DestructionAuthority`` = a ``TrustRoot`` (the signer PUBLIC keys + an m-of-n threshold) plus the
     MANDATORY signer ids (must include the owner);
  2. a per-action ``SignedDestructionAuthorization`` — the owner (+ any co-signers) sign ONE concrete
     destructive action, inside a short window, with a single-use nonce;
  3. a durable single-use nonce ledger (created on first use by the ledger itself).

This module builds (1) once and signs (2) per patch. It is the "how to get the quorum keys" step behind
`vigil provision-destruction` / `vigil authorize-destruction`. Import-clean: ``vigil_core`` + the offense-
local ``destruction_gate`` only — NO framework/strix/sigil.

SECURITY MODEL (be honest about it):
  * m-of-n means "m of the n registered keys must sign, and the owner MUST be one of them." Its protection
    is real ONLY when the n private keys live in DIFFERENT places — the owner's key here, each co-signer's
    key on their own machine. Then this machine alone cannot authorize a destructive PR.
  * With threshold=1 and only the owner key (the solo default), whoever holds the owner key can authorize —
    still single-use + window-bounded + action-bound + off-by-default, but NOT separation of duties. Use
    ``--signers N --threshold M`` (M>1) and keep co-signer keys off this box for that.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class GeneratedAuthority:
    """The output of provisioning: the public trust-root JSON to keep, the private signing keys to
    distribute (shown ONCE), and the mandatory signer ids to enforce."""

    trust_root_json: str                     # public — safe to store / hand to the offense verifier
    private_keys: tuple[tuple[str, str], ...]  # (key_id, private_key_b64) — SECRET; distribute + then forget
    mandatory_signer_ids: tuple[str, ...]
    threshold: int


def generate_authority(*, threshold: int = 1, worker_count: int = 0, owner_id: str = "owner") -> GeneratedAuthority:
    """Mint a fresh destruction quorum: one owner key + ``worker_count`` co-signer keys, an m-of-n
    ``TrustRoot`` at ``threshold``, and the owner bound as the mandatory signer. Fail-closed on a threshold
    outside ``1..n``. The private keys are returned to be shown once and distributed — never persisted here."""
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair

    owner_id = str(owner_id or "owner").strip() or "owner"
    n = 1 + max(0, int(worker_count))
    if not (1 <= int(threshold) <= n):
        raise ValueError(f"threshold {threshold} out of range for {n} signer(s)")

    ids = [owner_id] + [f"worker{i + 1}" for i in range(max(0, int(worker_count)))]
    if len(set(ids)) != len(ids):
        raise ValueError("signer ids must be unique (owner id collides with a worker id)")
    keys = {kid: generate_keypair() for kid in ids}
    authorizers = [AuthorizerKey(key_id=kid, name=kid, public_key_b64=keys[kid].public_key_b64) for kid in ids]
    tr = TrustRoot(threshold=int(threshold), authorizers=authorizers)
    return GeneratedAuthority(
        trust_root_json=tr.model_dump_json(),
        private_keys=tuple((kid, keys[kid].private_key_b64) for kid in ids),
        mandatory_signer_ids=(owner_id,),
        threshold=int(threshold),
    )


def sign_action(*, action_id: str, engagement_slug: str, target: str,
                signer_private_keys: "list[tuple[str, str]]", now: float,
                window_s: float = 600.0, nonce: str) -> str:
    """Sign ONE destructive action with the given ``(key_id, private_key_b64)`` signers and return the
    ``{"authorization": {...}, "signatures": [...]}`` JSON that ``load_signed_authorization`` consumes.

    The window is ``[now-30, now+window_s]`` (a small back-skew for clock jitter). ``window_s`` MUST keep the
    total window within the gate's 900s dead-man's-switch — enforced fail-closed here. ``nonce`` must be a
    fresh unguessable value (the caller supplies it so it can also record/track it); a blank nonce is refused.
    """
    from ..destruction_gate import DEFAULT_POLICY, DestructionAuthorization, sign_authorization

    if not str(nonce or "").strip():
        raise ValueError("a non-empty single-use nonce is required")
    if not str(action_id or "").strip() or not str(target or "").strip():
        raise ValueError("action_id and target are required")
    if not signer_private_keys:
        raise ValueError("at least one signer private key is required (the owner)")
    not_before = float(now) - 30.0
    not_after = float(now) + float(window_s)
    if (not_after - not_before) > DEFAULT_POLICY.max_authorization_lifetime:
        raise ValueError(
            f"window {(not_after - not_before):.0f}s exceeds the {DEFAULT_POLICY.max_authorization_lifetime:.0f}s "
            "dead-man's-switch limit — use a shorter --window-s")

    auth = DestructionAuthorization(
        action_id=str(action_id), engagement_slug=str(engagement_slug), target=str(target),
        blast_class="destructive", not_before=not_before, not_after=not_after, nonce=str(nonce))
    signed = sign_authorization(auth, [(str(kid), str(priv)) for kid, priv in signer_private_keys])
    return json.dumps({
        "authorization": auth.signing_payload(),
        "signatures": [{"key_id": s.key_id, "signature_b64": s.signature_b64} for s in signed.signatures],
    }, sort_keys=True)


def fresh_nonce() -> str:
    """A fresh, unguessable single-use nonce (stdlib ``secrets``; no wallclock/RNG-on-decision concern —
    this is provisioning, not the deterministic decision path)."""
    import secrets
    return "dn-" + secrets.token_hex(16)


def load_worker_key_file(spec: str) -> "tuple[str, str]":
    """Parse a ``key_id=/path/to/keyfile`` co-signer spec and read the private key from the FILE (never argv,
    so a co-signer key never lands in the process table / shell history). Returns ``(key_id, private_key_b64)``."""
    from pathlib import Path

    s = str(spec or "")
    if "=" not in s:
        raise ValueError(f"--worker-key must be key_id=/path/to/keyfile, got {spec!r}")
    kid, path = s.split("=", 1)
    kid = kid.strip()
    if not kid:
        raise ValueError("--worker-key needs a non-empty key_id before '='")
    try:
        priv = Path(path.strip()).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"could not read worker key file for {kid!r}: {exc}") from exc
    if not priv:
        raise ValueError(f"worker key file for {kid!r} is empty")
    return (kid, priv)


def default_paths(base_dir: str) -> "dict[str, str]":
    """The default provisioning locations under ``base_dir`` that `vigil patch --open-pr` auto-discovers."""
    from pathlib import Path

    base = Path(base_dir)
    return {
        "trust_root": str(base / "destruction-trust-root.json"),
        "signed": str(base / "signed-authorization.json"),
        "ledger": str(base / "destruction-nonces"),
    }


def write_trust_root(base_dir: str, trust_root_json: str) -> str:
    """Persist the PUBLIC trust-root JSON (0644 is fine — no secrets) at the default path; returns the path."""
    from pathlib import Path

    p = Path(default_paths(base_dir)["trust_root"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(trust_root_json, encoding="utf-8")
    return str(p)


def _read_trust_root_ids(trust_root_json: str) -> Optional[Any]:
    """Return the parsed trust root (for the CLI to echo the registered signer ids), or None if unparseable."""
    from vigil_core import TrustRoot

    try:
        return TrustRoot.model_validate_json(trust_root_json)
    except Exception:  # noqa: BLE001 — display helper only
        return None
