"""Witness co-sign plumbing over the signed spine head (audit G3(b)).

The spine head is owner-signed and anti-rollback is guarded IN-BAND by the monotonic ``last_seq`` and
OUT-OF-BAND by the durable ``floor.json``. But ``floor.py`` documents its own HONEST LIMIT: a same-host
attacker holding the owner UID/key can rewrite ``head.json`` AND ``floor.json`` together, and a purely
LOCAL verify reads both fresh from that same attacker-controlled disk — so it cannot catch the rollback.
The named successor to close that gap is an OUT-OF-BAND WITNESS (this module, G3(b)).

What this adds, being honest about exactly what it does and does not guarantee:

  * ``emit_checkpoint`` summarises the current signed head into a compact, PUBLIC ``Checkpoint`` (the I2
    transparency-log primitive, ``vigil_integration.transparency``), has it WITNESS-co-signed, and returns
    a portable ``WitnessedCheckpoint`` the operator RETAINS OFF-BOX (a USB stick, another machine, a
    remote commit, or — when it lands — the paired phone over WireGuard).
  * ``verify_against_external`` proves the CURRENT head is a genuine APPEND-ONLY EXTENSION of an
    EXTERNALLY-RETAINED witnessed checkpoint. THIS is the anti-rollback the local floor cannot provide:
    the anchor is a copy the attacker never touched (it lives off-box). Two layers: (a) ``consistent``
    rejects a rollback BELOW the retained height (record count / last_seq cannot shrink, no same-height
    fork); (b) because ``head_hash`` hash-chains the whole prefix, the current chain's entry at the
    retained ``last_seq`` must carry the retained ``head_hash`` — a match PROVES records ``0..last_seq`` are
    byte-identical (a real superset), a mismatch CATCHES a higher-count history rewrite that the pairwise
    check alone cannot (a rewrite that grows the count while altering an old record). Honest limit: if the
    retained point is below the current prune base, the superset proof needs the archive/Merkle root and
    the check is REFUSED (fails closed, `ok=False`) — never silently passed, because ``base_seq`` is an
    attacker-signed field and a claimed-high prune base must not become an escape hatch.

HONEST GUARANTEE BOUNDARY (do NOT overclaim — the whole point of a witness is the property it provides):
  - The anti-rollback comes from EXTERNAL RETENTION, not from a local sidecar. A witnessed checkpoint kept
    only in ``SIGIL_HOME`` is rolled back together with the spine and adds NOTHING over the floor. So only
    ``verify_against_external`` against an off-box-retained copy is load-bearing.
  - At the default witness set (owner-only, threshold 1 — or any sub-majority) this is rollback DETECTION
    via retention, NOT split-view PREVENTION. Prevention (an operator cannot obtain a witness quorum for
    two forks at one height) needs a STRICT MAJORITY of INDEPENDENT witness keys, AND — uncheckable by code
    — those keys must be held by independent parties. ``guarantee_label`` never claims prevention it cannot
    establish: a single owner-only witness is arithmetic strict-majority (2*1>1) but is the head signer
    itself, so it is labelled DETECTION; a >=2-key strict-majority set is labelled CONDITIONAL prevention.
  - The LIVE co-sign transport (hand a checkpoint to a paired device over the bridge and get its signature
    back) is DEFERRED. Until it lands, an independent witness co-signs via ``cosign_envelope`` on ITS OWN
    box and the envelope is shuttled back — the manual, honest stand-in.

Dependency-injected + config-free (the CLI is the sole config boundary), so every path is testable without
global state. Import-clean and sovereign-safe: reuses ``vigil_integration.transparency`` (``vigil_core``
only, pulls no offense engine — the same boundary-safe pattern as ``inbound.finding_receiver`` importing
``vigil_integration.inert_finding``).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vigil_integration.transparency import (
    Checkpoint,
    Witness,
    WitnessedCheckpoint,
    checkpoint_hash,
    checkpoint_of,
    consistent,
    is_split_view_resistant,
    verify_witnessed,
)

from ..reuse import (
    AuthorizerKey,
    KeyPair,
    Signature,
    TrustRoot,
    canonical_json,
    sign,
    verify_chain,
    verify_one,
)
from .atomicio import atomic_write_text

_ENVELOPE_SCHEMA = 1
_ROSTER_SCHEMA = 1
# Domain tag for the owner signature over the witness ROSTER — distinct from the head/floor/checkpoint
# domains so a roster signature can never be replayed as any of those.
_ROSTER_DOMAIN = b"sigil-witness-roster-v1\x00"


class WitnessError(Exception):
    """A witnessed checkpoint could not be emitted, cosigned, loaded, or verified. Fail-closed: every
    load/verify path refuses on a wrong scope, a malformed envelope, a bad roster signature, or a
    checkpoint that is not an append-only extension of the retained anchor."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise WitnessError(msg)


# --------------------------------------------------------------------------- envelope (de)serialisation

def dump_witnessed(wc: WitnessedCheckpoint, *, scope: str) -> str:
    """Serialise a WitnessedCheckpoint to a portable JSON envelope, bound to ``scope`` so a checkpoint
    from a different store is not accepted on verify."""
    return json.dumps({
        "schema": _ENVELOPE_SCHEMA,
        "scope": scope,
        "checkpoint": wc.checkpoint.to_dict(),
        "witness_signatures": [{"key_id": s.key_id, "signature_b64": s.signature_b64}
                               for s in wc.witness_signatures],
    }, sort_keys=True, separators=(",", ":"))


def load_witnessed(data: str) -> tuple[WitnessedCheckpoint, str]:
    """Parse + strictly validate a witnessed-checkpoint envelope. Returns (WitnessedCheckpoint, scope).
    Fail-closed on any malformed shape — never a bare exception from a crafted file."""
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as e:
        raise WitnessError(f"corrupt witnessed-checkpoint envelope: {e}") from e
    _require(isinstance(obj, dict), "witnessed-checkpoint envelope is not a JSON object")
    scope = obj.get("scope")
    cp_raw = obj.get("checkpoint")
    sigs_raw = obj.get("witness_signatures")
    _require(isinstance(scope, str), "envelope is missing its scope")
    _require(isinstance(cp_raw, dict), "envelope is missing its checkpoint")
    _require(isinstance(sigs_raw, list), "envelope is missing its witness_signatures")
    try:
        cp = Checkpoint(
            last_seq=int(cp_raw["last_seq"]),
            entry_count=int(cp_raw["entry_count"]),
            head_hash=str(cp_raw["head_hash"]),
            merkle_root=str(cp_raw["merkle_root"]),
            prev_checkpoint_hash=str(cp_raw["prev_checkpoint_hash"]),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise WitnessError(f"malformed checkpoint fields: {e}") from e
    sigs = []
    for s in sigs_raw:
        _require(isinstance(s, dict), "a witness signature is not an object")
        kid, sig = s.get("key_id"), s.get("signature_b64")
        _require(isinstance(kid, str) and isinstance(sig, str), "a witness signature is malformed")
        sigs.append(Signature(key_id=kid, signature_b64=sig))
    return WitnessedCheckpoint(cp, tuple(sigs)), scope


# ----------------------------------------------------------------------------------- the witness roster

def _roster_core(scope: str, threshold: int, authorizers: list[dict]) -> dict:
    return {"schema": _ROSTER_SCHEMA, "scope": scope, "threshold": int(threshold),
            "authorizers": [{"key_id": str(a["key_id"]), "public_key_b64": str(a["public_key_b64"])}
                            for a in authorizers]}


def load_roster(path: Path, *, owner_pub: str, scope: str) -> dict | None:
    """The owner-signed witness roster core, or None if none configured. Fail-closed: raises on a corrupt
    file, a wrong-scope roster, or a signature that does not verify against the owner key (so a tampered
    roster is rejected, never silently trusted)."""
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise WitnessError(f"corrupt witness roster: {e}") from e
    _require(isinstance(obj, dict), "witness roster is not a JSON object")
    core, sig = obj.get("core"), obj.get("sig")
    _require(isinstance(core, dict) and isinstance(sig, str), "witness roster is missing its signed core")
    _require(core.get("scope") == scope, f"witness roster is for scope {core.get('scope')!r}, not {scope!r}")
    auths = core.get("authorizers")
    thr = core.get("threshold")
    _require(isinstance(auths, list) and isinstance(thr, int) and thr >= 1, "witness roster is malformed")
    try:
        canonical = _roster_core(str(core["scope"]), int(thr), list(auths))
    except (KeyError, TypeError, ValueError) as e:
        raise WitnessError(f"malformed witness roster core: {e}") from e
    try:
        ok = verify_one(owner_pub, _ROSTER_DOMAIN + canonical_json(canonical), sig)
    except Exception as e:  # noqa: BLE001 — malformed key/sig → fail-closed
        raise WitnessError(f"witness roster signature is malformed: {e}") from e
    if not ok:
        raise WitnessError("witness roster signature does not verify against the owner key (tamper)")
    return canonical


def set_roster(authorizers: list[dict], threshold: int, *, path: Path, owner_key: KeyPair,
               scope: str) -> dict:
    """Owner-sign + durably write the witness roster. ``authorizers`` = [{key_id, public_key_b64}, ...].
    Only the owner (the spine trust root) may set who the trusted witnesses are."""
    if threshold < 1:
        raise WitnessError("threshold must be >= 1")
    if not authorizers:
        raise WitnessError("a witness roster needs at least one authorizer")
    if threshold > len(authorizers):
        raise WitnessError(f"threshold {threshold} exceeds the {len(authorizers)} configured witnesses")
    core = _roster_core(scope, threshold, authorizers)
    sig = sign(owner_key.private_key_b64, _ROSTER_DOMAIN + canonical_json(core))
    atomic_write_text(path, json.dumps({"core": core, "sig": sig}, sort_keys=True), prefix=".witness-")
    return core


def witness_trust_root(roster: dict | None, *, owner_pub: str, owner_key_id: str) -> TrustRoot:
    """The TrustRoot the witness signatures are verified against. If a roster is configured, use it;
    otherwise DEFAULT to the owner key alone at threshold 1 — which makes emit/verify work out of the box
    but provides only rollback DETECTION. Adding INDEPENDENT witness keys (a paired device) to reach a
    strict majority is what upgrades it to (conditional) prevention (see ``guarantee_label``)."""
    if roster is None:
        return TrustRoot(threshold=1,
                         authorizers=[AuthorizerKey(key_id=owner_key_id, name=owner_key_id,
                                                    public_key_b64=owner_pub)])
    return TrustRoot(threshold=int(roster["threshold"]),
                     authorizers=[AuthorizerKey(key_id=a["key_id"], name=a["key_id"],
                                                public_key_b64=a["public_key_b64"])
                                  for a in roster["authorizers"]])


def guarantee_label(tr: TrustRoot) -> str:
    """The HONEST guarantee for this witness set. Detection (via external retention) is the baseline and
    always holds. Prevention is only claimed — and only CONDITIONALLY — when the set is a strict majority
    of at least two DISTINCT keys: a single owner-only witness is arithmetic-'strict-majority' (2*1>1) but
    is the head signer itself, so it provides NO independence. Even with >=2 keys, prevention holds ONLY IF
    the keys are custodied by INDEPENDENT parties, which code cannot verify (per the transparency module's
    stated trust assumption), so the label says 'IF independently held' rather than asserting prevention."""
    if is_split_view_resistant(tr) and len(tr.authorizers) >= 2:
        return ("split-view prevention IF the witness keys are held by independent parties "
                "(strict-majority set; independence is not checkable here)")
    return ("rollback DETECTION only (the off-box retained copy is the anchor; add independent witnesses "
            "at strict majority for prevention)")


# ----------------------------------------------------------------------------- persisted emitter tip

def load_tip(path: Path) -> WitnessedCheckpoint | None:
    if not path.exists():
        return None
    try:
        wc, _scope = load_witnessed(path.read_text(encoding="utf-8"))
    except (OSError, WitnessError) as e:
        raise WitnessError(f"corrupt witness tip {path}: {e}") from e
    return wc


def save_tip(wc: WitnessedCheckpoint, path: Path, *, scope: str) -> None:
    atomic_write_text(path, dump_witnessed(wc, scope=scope), prefix=".witness-tip-")


# ----------------------------------------------------------------------------------------------- emit

def emit_checkpoint(head: Any, witnesses: list[Witness], *, tip_path: Path, scope: str) -> WitnessedCheckpoint:
    """Summarise ``head`` into the next checkpoint (linked to the persisted tip so the meta-chain survives
    restarts), gather witness co-signatures, persist the new tip, and return the WitnessedCheckpoint.

    Mirrors ``CheckpointEmitter.emit`` but with the emitter's in-memory tip made DURABLE: idempotent on an
    unchanged head position, refuses a non-append-only head (``consistent``), and gathers the willing
    witnesses atomically (decide who signs before any state mutates)."""
    if not witnesses:
        raise WitnessError("emit needs at least one witness to co-sign the checkpoint")
    tip = load_tip(tip_path)
    prev = "" if tip is None else checkpoint_hash(tip.checkpoint)
    cp = checkpoint_of(head, prev_checkpoint_hash=prev)
    if tip is not None:
        last = tip.checkpoint
        if (cp.entry_count, cp.last_seq, cp.head_hash) == (last.entry_count, last.last_seq, last.head_hash):
            return tip                                  # idempotent: unchanged position, no second mint
        ok, why = consistent(last, cp)
        if not ok:
            raise WitnessError(f"refusing to emit an inconsistent checkpoint: {why}")
    willing, seen = [], set()
    for w in witnesses:                                 # atomic gather: pick the willing set, then co-sign
        if w.key_id in seen:
            continue
        seen.add(w.key_id)
        if w.would_accept(cp)[0]:
            willing.append(w)
    wc = WitnessedCheckpoint(cp, tuple(w.cosign(cp) for w in willing))
    save_tip(wc, tip_path, scope=scope)
    return wc


def cosign_envelope(data: str, *, witness_key_id: str, witness_priv_b64: str) -> str:
    """Add THIS witness's signature to a checkpoint envelope and return the updated envelope. Run on the
    INDEPENDENT witness's own box (the manual, honest stand-in for the deferred live co-sign transport):
    the operator emits, ships the envelope here, this appends a signature, and the envelope is shuttled
    back for retention. De-duplicates by key_id (a re-cosign replaces this witness's prior signature)."""
    wc, scope = load_witnessed(data)
    sig = Witness(witness_key_id, witness_priv_b64).cosign(wc.checkpoint)
    kept = tuple(s for s in wc.witness_signatures if s.key_id != witness_key_id)
    return dump_witnessed(WitnessedCheckpoint(wc.checkpoint, kept + (sig,)), scope=scope)


# --------------------------------------------------------------------------------------------- verify

def verify_against_external(data: str, *, head: Any, entries: list, scope: str,
                            trust_root: TrustRoot) -> tuple[bool, str]:
    """The load-bearing anti-rollback check: is the CURRENT local head a genuine append-only EXTENSION of
    an EXTERNALLY-RETAINED witnessed checkpoint? Fail-closed. Steps:

      (1) the envelope's scope must be this store's;
      (2) a trusted witness quorum must have signed it (else it is not a trustworthy anchor);
      (3) no rollback below the retained height — ``consistent`` rejects a shrunk record count, a
          rolled-back last_seq, and a same-height-different-head fork;
      (4) GENUINE-EXTENSION PROOF (this is what makes 'append-only extension' true, not just asserted):
          because ``head_hash`` is ``entries[-1].entry_hash`` and each ``entry_hash`` hash-chains
          ``(seq, prev_hash, cert_digest)`` over the WHOLE prefix, the retained ``head_hash`` is a
          cryptographic commitment to records ``0..retained.last_seq``. So the CURRENT chain's entry at
          ``seq == retained.last_seq`` must carry that exact ``entry_hash``: a match PROVES the prefix is
          byte-identical (a real superset); a mismatch is a HISTORY REWRITE that step (3)'s pairwise check
          cannot see (a higher-count rewrite grows the count while altering an old record). HONEST SCOPE:
          if the retained point is below the current PRUNE BASE (records since archived out of the live
          window), the live entries cannot carry that proof — the check is REFUSED (``ok=False``), NOT
          passed. ``base_seq`` is an attacker-signed head field, so a claimed-high prune base fails closed
          rather than skipping the proof. The provided ``entries`` are themselves bound to the authenticated
          head (clean hash-chain, tip == ``head.head_hash`` at ``head.last_seq``) before the proof, so a
          forged/unvalidated entries list cannot smuggle a matching hash.

    The message states which split-view guarantee holds (conditional prevention only at a strict-majority
    set of >=2 independent witnesses; otherwise detection)."""
    wc, wc_scope = load_witnessed(data)
    if wc_scope != scope:
        return False, f"external checkpoint is for scope {wc_scope!r}, not this store's {scope!r}"
    if not verify_witnessed(wc, witness_trust_root=trust_root):
        return False, ("external checkpoint is not signed by a trusted witness quorum "
                       "(tamper, or its witnesses are not in this store's roster)")
    ret = wc.checkpoint
    cur = checkpoint_of(head, prev_checkpoint_hash=checkpoint_hash(ret))
    ok, why = consistent(ret, cur)
    if not ok:
        return False, f"ROLLBACK/FORK: current head rolled back below the retained checkpoint — {why}"
    if ret.entry_count == 0:
        return True, (f"current head (count {cur.entry_count}, last_seq {cur.last_seq}) shows NO ROLLBACK "
                      f"below the retained checkpoint (count 0, nothing to bind). {guarantee_label(trust_root)}")
    # FAIL-CLOSED if the retained point is below the current PRUNE BASE: the superset proof would need the
    # archive / cumulative Merkle root, which the compact head does not carry. `base_seq` is an
    # attacker-SIGNED head field, so a claimed-high base_seq must NEVER become a silent pass — a security
    # backstop that cannot complete refuses rather than asserts safety (else a same-host owner-key attacker
    # rewrites the whole anchored history simply by declaring it "pruned").
    base_seq = int(getattr(head, "base_seq", 0) or 0)
    if ret.last_seq < base_seq:
        return False, (f"CANNOT VERIFY (refused): the retained point (last_seq {ret.last_seq}) is below the "
                       f"current prune base (base_seq {base_seq}); the superset proof needs the archive/Merkle "
                       f"root, not the live window — retain a fresher checkpoint or verify against the archive")
    # Bind the provided entries to the AUTHENTICATED head — do not trust an unvalidated caller. The live
    # window must be a clean hash-chain whose tip is EXACTLY head.head_hash at head.last_seq, so the
    # entry_hash matched at the retained seq is the genuine chain hash there, not an injected fake entry.
    if not entries:
        return False, "CANNOT VERIFY (refused): no live chain provided for the current head"
    genesis = getattr(head, "base_prev_hash", None)
    chain_ok, _reason = (verify_chain(list(entries), genesis_prev=genesis) if genesis is not None
                         else verify_chain(list(entries)))
    if (not chain_ok
            or str(getattr(entries[-1], "entry_hash", "")) != str(getattr(head, "head_hash", ""))
            or int(getattr(entries[-1], "seq", -1)) != int(getattr(head, "last_seq", -2))):
        return False, "CANNOT VERIFY (refused): the provided entries are not the head's authenticated live chain"
    # (4) genuine-extension proof via the hash-chained entry at the retained height
    match = next((e for e in entries if int(getattr(e, "seq", -1)) == ret.last_seq), None)
    if match is None:
        return False, (f"HISTORY REWRITE: the current chain has no record at the retained last_seq "
                       f"{ret.last_seq} (the count grew but the retained record is gone)")
    if str(getattr(match, "entry_hash", "")) != ret.head_hash:
        return False, (f"HISTORY REWRITE: the current record at seq {ret.last_seq} does not carry the "
                       f"retained head_hash — records at/below the retained height were altered")
    return True, (f"current head (count {cur.entry_count}, last_seq {cur.last_seq}) shows NO ROLLBACK below "
                  f"the retained checkpoint (count {ret.entry_count}); the current record at seq {ret.last_seq} "
                  f"carries the retained head_hash, proving records 0..{ret.last_seq} are byte-identical "
                  f"(a genuine append-only extension). {guarantee_label(trust_root)}")
