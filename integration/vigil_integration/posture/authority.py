"""posture.authority — the Authority-Envelope certificate (the accountability twin of Proof-of-Posture).

A signed, deterministic, third-party-offline-re-verifiable proof that an autonomous agent took ONLY
actions its owner-signed authority permitted. It composes:

  * an owner-signed AUTHORITY ENVELOPE — engagement + the permitted scope hosts + the permitted action
    kinds + a validity window (what the agent was allowed to do);
  * the run's ACTION LEDGER — the WHO/WHEN/WHAT of every gated action + its conjunctive-gate outcome;
  * a CONFORMANCE PROOF — every EXECUTED action is provably inside the envelope (target in scope, action
    kind allowed, within the window). Re-derived at verify, so a forged "conformant" claim detached from
    the ledger is refused.

As autonomous agents act on real systems, "prove your agent stayed within its authority" becomes a
liability / insurance / regulatory need with no machine-verifiable answer today. This is that answer.

HONEST RESIDUAL (in the signed bytes): it proves conformance over the RECORDED, append-only ledger — a
tamper-evident record, NOT omniscient capture. An action the agent never recorded is not provable here;
the append-only anti-rollback spine bounds that, but the guarantee is "no recorded action left the
envelope", not "the agent recorded every action it took".

FATAL-2 / sovereign-safe: vigil_core + stdlib only; the m-of-n signing envelope is a function-local
import (mirrors posture.certificate).
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlsplit

from vigil_core import canonical_json
from vigil_core.crypto import IntegrityError, sign, verify_one

AUTHORITY_SCHEMA = "vigil-authority-envelope-certificate/1"
_ENVELOPE_DOMAIN = b"vigil-authority-envelope-v1\x00"

AUTHORITY_RESIDUAL = (
    "Proves that every RECORDED, EXECUTED action stayed inside the owner-signed authority envelope "
    "(scope ∧ action-kind ∧ window). It is a proof over the append-only, tamper-evident action ledger — "
    "NOT a proof that the agent recorded every action it took (omniscient capture is not claimable). A "
    "standalone verifier re-checks the owner signature, the m-of-n certificate signature, and re-derives "
    "conformance offline with no VIGIL installed."
)


class AuthorityError(Exception):
    """A malformed / forged / non-conformant authority certificate — fail-closed."""


def _envelope_core(env: dict) -> dict:
    """The owner-signed core of an authority envelope (order-independent)."""
    return {
        "schema_version": env.get("schema_version", 1),
        "owner_pubkey": env.get("owner_pubkey"),
        "engagement": env.get("engagement"),
        "scope_hosts": sorted(str(h) for h in (env.get("scope_hosts") or [])),
        "action_allowlist": sorted(str(a) for a in (env.get("action_allowlist") or [])),
        "not_before": int(env.get("not_before", 0)),
        "not_after": int(env.get("not_after", 0)),
    }


def sign_authority_envelope(owner_key, *, engagement: str, scope_hosts: list[str],
                            action_allowlist: list[str], not_before: int, not_after: int) -> dict:
    """Owner-sign an authority envelope. Fail-closed on an empty engagement / scope / allowlist."""
    if not str(engagement).strip() or not scope_hosts or not action_allowlist:
        raise AuthorityError("an authority envelope needs a non-empty engagement, scope, and action allowlist")
    env = {
        "schema_version": 1, "owner_pubkey": owner_key.public_key_b64, "engagement": str(engagement),
        "scope_hosts": [str(h) for h in scope_hosts], "action_allowlist": [str(a) for a in action_allowlist],
        "not_before": int(not_before), "not_after": int(not_after),
    }
    env["sig"] = sign(owner_key.private_key_b64, _ENVELOPE_DOMAIN + canonical_json(_envelope_core(env)))
    return env


def verify_authority_envelope(env: dict, *, trusted_owner_pubkey: str, engagement: str) -> bool:
    """Verify the envelope was owner-signed for ``engagement`` (fail-closed)."""
    if not isinstance(env, dict) or env.get("owner_pubkey") != trusted_owner_pubkey:
        raise AuthorityError("authority envelope is not by the trusted owner key")
    if env.get("engagement") != engagement:
        raise AuthorityError(f"envelope engagement {env.get('engagement')!r} != required {engagement!r}")
    sig = env.get("sig")
    if not sig:
        raise AuthorityError("authority envelope is unsigned")
    try:
        ok = verify_one(str(trusted_owner_pubkey), _ENVELOPE_DOMAIN + canonical_json(_envelope_core(env)), str(sig))
    except (IntegrityError, TypeError) as e:
        raise AuthorityError(f"envelope signature malformed: {e}") from e
    if not ok:
        raise AuthorityError("authority envelope signature does not verify against the owner key")
    return True


def _host(target: str) -> str:
    return urlsplit(target).hostname or (target or "")


def _executed(a: dict) -> bool:
    # an action "took effect" if it ran, or the gate authorized it (allow/executed) — never a deny/queue.
    return bool(a.get("executed")) or str(a.get("gate_outcome", "")).lower() in ("allow", "auto", "executed")


def derive_conformance(env: dict, actions: list[dict]) -> dict:
    """Re-derive the conformance proof: every EXECUTED action must be inside the envelope (host in scope,
    action kind allowed, within the window). The SOLE derivation — the verifier re-runs it."""
    scope = set(env.get("scope_hosts") or [])
    allow = set(env.get("action_allowlist") or [])
    nb, na = int(env.get("not_before", 0)), int(env.get("not_after", 0))
    violations: list[dict] = []
    n_exec = 0
    for a in actions:
        if not _executed(a):
            continue
        n_exec += 1
        reasons = []
        if _host(str(a.get("target", ""))) not in scope:
            reasons.append("target out of scope")
        if str(a.get("action_kind", "")) not in allow:
            reasons.append("action kind not permitted")
        at = int(a.get("at", 0))
        if na and not (nb <= at <= na):
            reasons.append("outside the authority window")
        if reasons:
            violations.append({"seq": a.get("seq"), "action_kind": a.get("action_kind"),
                               "target": a.get("target"), "reasons": reasons})
    return {"conformant": not violations, "violations": violations,
            "n_actions": len(actions), "n_executed": n_exec}


def build_authority_certificate(envelope: dict, actions: list[dict], *,
                                residual: str = AUTHORITY_RESIDUAL) -> dict:
    """Build the deterministic authority-envelope certificate (a plain dict)."""
    conf = derive_conformance(envelope, actions)
    return {
        "schema": AUTHORITY_SCHEMA,
        "envelope": envelope,
        "actions": [dict(a) for a in actions],
        "conformance": conf,
        "residual": residual,
    }


def sign_authority_certificate(cert: dict, path, *, signers, authorizers, threshold) -> dict:
    from framework.v2.eval.benchmark_run import sign_scorecard  # noqa: PLC0415 (FATAL-2: function-local)
    from pathlib import Path

    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(canonical_json(cert))
    return sign_scorecard(p, signers=signers, authorizers=authorizers, threshold=threshold)


def verify_authority_certificate(path, sig_env: dict, *, trust_root_fingerprint: Optional[str],
                                 owner_pubkey: str, engagement: str) -> bool:
    """Offline-verify (in-tree; the standalone verify_vf mirrors it). Fail-closed:
      1. the m-of-n governance signature over the canonical bytes + the out-of-band pin;
      2. the owner-signed envelope (for engagement);
      3. conformance re-derives byte-identically AND is conformant (no executed action left the envelope).
    """
    from framework.v2.eval.benchmark_run import verify_scorecard  # noqa: PLC0415 (FATAL-2: function-local)
    import json
    from pathlib import Path

    cert = json.loads(Path(path).read_text(encoding="utf-8"))
    if not verify_scorecard(path, sig_env, trust_root_fingerprint=trust_root_fingerprint):
        return False
    verify_authority_envelope(cert.get("envelope") or {}, trusted_owner_pubkey=owner_pubkey, engagement=engagement)
    rederived = derive_conformance(cert.get("envelope") or {}, cert.get("actions") or [])
    if rederived != cert.get("conformance"):
        raise AuthorityError("conformance does not match the re-derivation from the recorded ledger")
    if not rederived["conformant"]:
        raise AuthorityError(f"NON-CONFORMANT: {len(rederived['violations'])} executed action(s) left the envelope")
    return True
