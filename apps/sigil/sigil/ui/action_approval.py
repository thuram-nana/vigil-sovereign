"""action_approval — the OWNER-SIGNED, fail-closed per-action approval GATE store (the hands behind the gate).

This is VIGIL's action-approval gate: the Allow/Block human-in-the-loop checkpoint that pauses a running
engagement before a RISKY action and resumes it only on an explicit, owner-signed Allow. It is the SOVEREIGN,
ADDITIVE layer that composes with the existing confirm-then-launch flow (``engagement_flow`` /
``customer_flow_step``), the step-up gate (``_require_stepup``) and the CRUCIBLE safety stack — it REPLACES
none of them. Doctrine, enforced BY CONSTRUCTION:

  * DEFAULT-BLOCK. The engagement proceeds ONLY when :func:`gate_step` finds and atomically SPENDS a live
    owner-signed Allow for the exact action; with no Allow it PAUSES and records the ask. A pending request
    that is never answered (or that times out) yields no grant, so the action never runs — default-block on
    timeout, fail-closed, by shape.
  * BOUNDED, SINGLE-USE, OWNER-SIGNED ALLOW. An Allow is an owner-signed per-action token bound to this exact
    ``(action, scope, parameters)`` via :mod:`vigil_integration.live.approval_token` — the SAME hardened
    primitive the offense plane uses: pinned owner key, dead-man's-switch window, single-use nonce. It never
    widens scope or authority; it authorizes ONE action ONCE. A forged / replayed / tampered Allow is INERT
    (the signature, the key-pin, the binding and the burnt nonce all fail-close independently).
  * TAMPER-EVIDENT, OWNER-SIGNED EVIDENCE. Every decision (requested / allowed / blocked / timed_out /
    consumed) is appended to a per-org, append-only, hash-chained, OWNER-SIGNED evidence log, LWW-high-water
    guarded (:mod:`vigil_core.highwater`) so a truncated / rolled-back / forged trail is refused. The audit
    trail proves WHO approved WHAT, with the risk/scope context.
  * TENANT ISOLATION. Every store lives under a DOMAIN-SEPARATED one-way hash of the org_id; an approval is
    bound to its engagement SLUG (``_customer_slug(org, host)``) and its org. One org can neither see nor
    answer another's approvals — the per-org path makes it structurally impossible, not a runtime filter.

FATAL-2: sovereign-only; it imports ONLY ``vigil_core`` + the import-clean ``vigil_integration.live.*``
approval primitives (proven framework-free) + stdlib, and ``assert_no_offense`` at import. The owner PRIVATE
key is used only to mint an Allow / sign an evidence record and never leaves this process.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import stat
import threading
from collections import namedtuple
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import canonical_json, sha256_hex, sign, verify_one
from vigil_core.highwater import (
    HighWaterError, advance_highwater, check_highwater, load_highwater,
)

# --- domain separation (a signature / hash here can never be confused with any other artifact) --------------
_ORG_FP_CONTEXT = b"vigil-action-approval-org\x00"
_EVIDENCE_CHAIN_DOMAIN = b"vigil-action-approval-evidence-chain-v1\x00"
_EVIDENCE_SIG_DOMAIN = b"vigil-action-approval-evidence-sig-v1\x00"
_GENESIS_PREV = "0" * 64

# --- bounds ------------------------------------------------------------------------------------------------
GRANT_TTL_SECONDS = 300.0        # an Allow is valid for 5 min (<= approval_token's 900s dead-man's bound)
REQUEST_TTL_SECONDS = 900.0      # a pending ask expires (default-BLOCK) after 15 min unanswered
_MAX_PENDING = 256               # per-org ceiling on open requests (defence in depth)
_MAX_FIELD = 1024                # per-string-field character cap
_MAX_TEXT = 4096                 # the steer-text parameter cap
_ID_RE = re.compile(r"\Aappr_[0-9a-f]{32}\Z")   # a safe approval-id token — never '..' / separators
_SYMLINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK})

_SAVE_LOCK = threading.Lock()                   # serialises evidence appends + the pending/grant writes

# The decision kinds recorded on the evidence spine.
DECISION_REQUESTED = "requested"
DECISION_ALLOWED = "allowed"
DECISION_BLOCKED = "blocked"
DECISION_TIMED_OUT = "timed_out"
DECISION_CONSUMED = "consumed"

_Head = namedtuple("_Head", ("entry_count", "last_seq"))   # the monotonic head the high-water floor anchors


class ApprovalStoreError(RuntimeError):
    """A structural fault in the approval store (unreadable/tampered on-disk state). Raised so the caller
    fails CLOSED rather than proceeding on an unverifiable trail."""


# ---------------------------------------------------------------------------- owner key + paths (fail-closed) --
def _owner_keypair():
    from ..governor.identity import ensure_owner_keypair
    return ensure_owner_keypair()


def _owner_pub() -> "Optional[str]":
    """The CURRENT owner public key the evidence spine is signed under — read-only, NEVER minting (a verify
    path must not generate trust; that is what ``owner_pubkey()`` is for, vs the signing ``ensure_owner_keypair``).
    None when no owner identity is present, in which case a non-empty trail is refused: an unresolvable anchor
    verifies nothing."""
    from ..governor.identity import owner_pubkey
    return owner_pubkey()


def _trusted_owner_pubkeys() -> "frozenset[str]":
    """The owner public keys an evidence record may legitimately be signed under: the CURRENT owner key PLUS
    every PRIOR owner key in the cross-signed ``key_history`` succession — so a record appended BEFORE an
    owner-key rotation still verifies (not orphaned), while any key OUTSIDE the owner succession is rejected.

    WHY A SET AND NOT A PER-SEQ WINDOW: the sibling owner-signed stores (monitoring authority, the prune folds)
    verify each GOVERNANCE-SPINE record under the owner key valid AT ITS SEQ (``key_resolver.at(seq)``). This
    evidence spine is a PER-ORG, append-only log with its OWN local seq space — those seqs are NOT governance
    spine seqs, so that per-seq window does not map onto it. We therefore pin to the owner-key SET (current ∪
    succession priors), the documented honest fallback: it fully closes the attacker-re-sign forgery (a non-
    owner key is never in the set) and keeps a rotated owner key's historical records verifiable, at the cost
    of not distinguishing WHICH owner epoch signed a given evidence line (acceptable — this trail is audit-only,
    off the authorization path). Fail-soft: if the governance spine / succession cannot be read the set is just
    the current owner key (correct for an un-rotated install; still rejects any non-owner key). Empty ONLY when
    there is no owner identity at all (fail-closed — the caller then refuses a non-empty trail)."""
    cur = _owner_pub()
    keys: "set[str]" = {cur} if cur else set()
    try:
        from ..governor import key_history as _kh
        from ..spine.store import SpineStore
        keys |= set(_kh.key_resolver(SpineStore(), current=cur).all_pubkeys)
    except Exception:  # noqa: BLE001 — no spine / unreadable or forked history ⇒ current owner key only
        pass
    return frozenset(k for k in keys if k)


def _root() -> Path:
    """The approval store root, resolved from ``SIGIL_HOME`` at CALL time (the ``resolve_live_dir`` /
    ``resolve_seam_base`` pattern), under the canonical ``customer_action_approval`` dir name. In production
    ``SIGIL_HOME`` is fixed for the process, so this equals ``config.CUSTOMER_ACTION_APPROVAL_DIR``; resolving
    at call time means the store follows a per-process home override instead of a value frozen at import (which
    would otherwise write to the default home when ``SIGIL_HOME`` is set only after config is imported)."""
    from .. import config
    home = os.environ.get("SIGIL_HOME")
    base = Path(home) if home else Path(config.SIGIL_HOME)
    return base / config.CUSTOMER_ACTION_APPROVAL_DIR.name


def _org_fp(org_id: str) -> str:
    """The domain-separated one-way hash that names ``org_id``'s approval dir — no org_id ever lands in a
    path, and this namespace can never collide with another per-org hashed namespace."""
    return hashlib.sha256(_ORG_FP_CONTEXT + org_id.encode("utf-8")).hexdigest()


def _org_dir(org_id: str) -> Path:
    d = _root() / _org_fp(org_id)
    return d


def _is_text(v: object) -> bool:
    if not isinstance(v, str):
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _slug_for(org_id: str, host: str) -> str:
    """The tenant-namespaced engagement slug for (org, host) — the SAME ``_customer_slug`` the launch gate
    re-derives, so an approval is bound to exactly the engagement it gates and another tenant's slug is
    unreachable."""
    from .target_authorization import _customer_slug
    return _customer_slug(str(org_id), str(host))


def _action_params(params: "Optional[dict]") -> dict:
    """A canonical, bounded projection of the action's parameters — the exact inputs the Allow binds to, so a
    grant for ``instruct 'focus on auth'`` can never authorize ``instruct 'wipe prod'``. Only known,
    string-typed, length-capped fields survive; anything else is dropped (the binding is over a closed shape)."""
    out: dict = {}
    for k in ("host", "depth", "product_id", "text"):
        v = (params or {}).get(k)
        if isinstance(v, str) and _is_text(v):
            out[k] = v[: (_MAX_TEXT if k == "text" else _MAX_FIELD)]
    return out


def _action_binding(org_id: str, host: str, action: str, params: "Optional[dict]"):
    """The ``(ApprovalAction, slug, tool_name, action_digest)`` this gate binds an Allow to. ``tool_name`` is
    namespaced ``engage:<action>``; ``target`` is the engagement slug; ``action_digest`` covers the tool, the
    slug AND the bounded parameters — so the owner-signed token authorizes EXACTLY this action, scope and
    inputs, nothing else."""
    from vigil_integration.live.approval_token import ApprovalAction, action_digest
    slug = _slug_for(org_id, host)
    tool_name = f"engage:{str(action)}"
    digest = action_digest(tool_name, slug, {"params": _action_params(params)})
    return ApprovalAction(tool_name=tool_name, target=slug, action_digest=digest), slug, tool_name, digest


def _authority():
    from vigil_integration.live.approval_token import ApprovalAuthority
    kp = _owner_keypair()
    return ApprovalAuthority(owner_key_id="owner", owner_public_key_b64=kp.public_key_b64), kp


def _nonce_ledger(org_id: str):
    from vigil_integration.live.nonce_ledger import NonceLedger
    return NonceLedger(_org_dir(org_id) / "nonces")


# ---------------------------------------------------------------------------- atomic JSON read/write (0600) ----
def _read_json(path: Path) -> "Optional[dict]":
    """The JSON object at ``path`` in full, or None when absent / a symlink (never followed). Raises
    ApprovalStoreError on a present-but-unreadable/corrupt/non-object file (fail-closed — a corrupt approval
    record must never read as absent)."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno in _SYMLINK_ERRNOS:
            return None
        raise ApprovalStoreError(f"approval record at {path} could not be opened ({e.errno})") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ApprovalStoreError(f"approval record at {path} is not a regular file")
        raw = os.read(fd, 1 << 20)
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise ApprovalStoreError(f"approval record at {path} is not valid JSON") from None
    if not isinstance(doc, dict):
        raise ApprovalStoreError(f"approval record at {path} is not a JSON object")
    return doc


def _write_json(path: Path, obj: dict) -> None:
    from ..spine.atomicio import atomic_write_text
    d = path.parent
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    atomic_write_text(path, json.dumps(obj, sort_keys=True))


# ---------------------------------------------------------------------------- the evidence spine --------------
def _evidence_path(org_id: str) -> Path:
    return _org_dir(org_id) / "evidence.jsonl"


def _floor_path(org_id: str) -> Path:
    return _org_dir(org_id) / "evidence.floor.json"


def _evidence_content(rec: dict) -> dict:
    """The signed/chained CONTENT of an evidence record — every field EXCEPT the chain + signature envelope.
    ``sign`` (append) and ``verify`` (read) both route through here so they cover identical bytes."""
    return {k: v for k, v in rec.items() if k not in ("entry_hash", "sig", "pub", "prev")}


def _entry_hash(prev: str, content: dict) -> str:
    return sha256_hex(_EVIDENCE_CHAIN_DOMAIN + canonical_json({"prev": prev, "content": content}))


def _evidence_sig_bytes(prev: str, entry_hash: str, content: dict) -> bytes:
    return _EVIDENCE_SIG_DOMAIN + canonical_json({"prev": prev, "entry_hash": entry_hash, "content": content})


def _read_evidence(org_id: str) -> list:
    """Every evidence record for ``org_id`` in seq order, or [] when none. Raises ApprovalStoreError on a
    symlinked/corrupt log (fail-closed)."""
    p = _evidence_path(org_id)
    try:
        if p.is_symlink():
            raise ApprovalStoreError("approval evidence log is a symlink (possible tamper)")
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as e:
        raise ApprovalStoreError(f"approval evidence log unreadable ({e})") from None
    out: list = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            raise ApprovalStoreError("approval evidence log has a corrupt line (possible tamper)") from None
        if not isinstance(obj, dict):
            raise ApprovalStoreError("approval evidence log has a non-object line (possible tamper)")
        out.append(obj)
    return out


def _append_evidence(org_id: str, content: dict, *, now: float) -> dict:
    """Append ONE owner-signed, hash-chained evidence record for ``now`` and advance the LWW high-water floor.
    MUST hold :data:`_SAVE_LOCK`. Fail-closed: a rollback/corrupt log raises before the write; the floor refuses
    to move downward. Returns the written record."""
    from ..spine.atomicio import atomic_write_text
    recs = _read_evidence(org_id)
    kp = _owner_keypair()
    # verify the existing chain tip UNDER THE PINNED OWNER KEY before extending it, so a trail re-signed under a
    # NON-owner key (its own pub embedded) cannot be quietly appended onto / blessed — even though this path
    # already holds the owner keypair. The current signing key is always unioned into the pinned set so a
    # genuine tip never spuriously fails the guard (belt-and-suspenders over the read-only owner-pub resolve).
    prev = _GENESIS_PREV
    seq = 0
    if recs:
        ok, why = _verify_chain(recs, _trusted_owner_pubkeys() | {kp.public_key_b64})
        if not ok:
            raise ApprovalStoreError(f"refusing to append onto a non-owner-signed / broken evidence chain: {why}")
        last = recs[-1]
        prev = str(last.get("entry_hash") or "")
        seq = int(last.get("seq", -1)) + 1
    body = {**content, "seq": seq, "at": float(now)}
    eh = _entry_hash(prev, _evidence_content(body))
    sig = sign(kp.private_key_b64, _evidence_sig_bytes(prev, eh, _evidence_content(body)))
    rec = {**body, "prev": prev, "entry_hash": eh, "sig": sig, "pub": kp.public_key_b64}
    d = _org_dir(org_id)
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    # rewrite the whole (append-only) log atomically — approvals are human-paced, so O(n) rewrite is cheap and
    # crash-safe; the high-water floor + chain catch any removal/truncation a rewrite could be abused for.
    atomic_write_text(_evidence_path(org_id),
                      "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs + [rec]))
    # advance the owner-signed, downgrade-refusing floor to the new head (last-writer-MONOTONIC).
    try:
        advance_highwater(_floor_path(org_id), _Head(entry_count=len(recs) + 1, last_seq=seq), signer=kp)
    except HighWaterError:
        # a concurrent advance already wrote a higher floor, or the floor is corrupt — the record is durable;
        # the floor stays at the higher mark (monotonic). Never lower it; never fail the recorded decision.
        pass
    return rec


def _verify_one_of(trusted_pubkeys: "frozenset[str]", msg: bytes, sig: str) -> bool:
    """True iff ``sig`` verifies under at least ONE pinned owner key. The verification key always comes from the
    PINNED set, never from the record itself — a record can never name the key that would validate it."""
    for pk in trusted_pubkeys:
        try:
            if verify_one(pk, msg, sig):
                return True
        except Exception:  # noqa: BLE001 — malformed key/sig material ⇒ this key simply does not verify it
            continue
    return False


def _verify_chain(recs: list, trusted_pubkeys: "frozenset[str]") -> "tuple[bool, str]":
    """Pure check that ``recs`` is a contiguous hash chain EACH LINK OF WHICH is signed by a PINNED OWNER KEY
    (``trusted_pubkeys`` — the sovereign owner key the module signs with, plus its ``key_history`` succession
    priors), NOT by the key embedded in the record. Each record links the prior entry_hash, re-hashes to its
    stored entry_hash, carries an embedded ``pub`` that MUST equal one of the pinned owner keys, and has a
    signature that MUST verify under a pinned owner key.

    This is the fix for the audit-integrity defect: verifying under the record's OWN embedded pub let a chain
    re-signed under an ATTACKER keypair (its own pub embedded) verify as valid. Pinning the verification key to
    the owner set makes such a re-signed / planted trail INERT — the attacker key is not pinned and the attacker
    signature does not verify under the owner key — while a genuine owner-signed (or owner-succession) record
    still verifies. A forged / reordered / tampered record also fails the chain/hash checks, independently."""
    prev = _GENESIS_PREV
    for i, r in enumerate(recs):
        if not isinstance(r, dict):
            return False, f"record {i} is not an object"
        content = _evidence_content(r)
        if str(r.get("prev") or "") != prev:
            return False, f"record {i} does not chain (prev mismatch)"
        eh = _entry_hash(prev, content)
        if str(r.get("entry_hash") or "") != eh:
            return False, f"record {i} entry_hash does not match its content (tamper)"
        pub, sig = r.get("pub"), r.get("sig")
        if not isinstance(pub, str) or not isinstance(sig, str):
            return False, f"record {i} is missing its signature"
        # OWNER-PIN: the embedded pub is accepted ONLY when it IS a pinned owner key, and the signature is
        # verified against the pinned owner key(s) — the record's own embedded key is never the trust anchor.
        if pub not in trusted_pubkeys:
            return False, f"record {i} is not signed by the owner key (embedded key is not a pinned owner key)"
        if not _verify_one_of(trusted_pubkeys, _evidence_sig_bytes(prev, eh, content), sig):
            return False, f"record {i} signature does not verify under the pinned owner key (forged)"
        prev = eh
    return True, "ok"


def verify_evidence(org_id: str, *, trusted_pubkey: "Optional[str]" = None) -> "tuple[bool, str]":
    """Verify the whole evidence trail for ``org_id``: the OWNER-SIGNED hash chain AND the LWW high-water floor
    (a rolled-back / truncated trail is refused). The chain is pinned to the OWNER key BY DEFAULT: when
    ``trusted_pubkey`` is NOT supplied the owner public key (and its ``key_history`` succession priors) is
    resolved here, so the DEFAULT call is FAIL-CLOSED — a chain re-signed under an attacker's own keypair does
    NOT verify even though its hashes and the high-water floor are self-consistent (an equal-length re-sign that
    the floor alone would let pass). ``trusted_pubkey`` is an optional override that pins to EXACTLY that one key
    (explicit callers / tests). Total; never raises (a store fault is returned as ``(False, reason)``)."""
    try:
        recs = _read_evidence(org_id)
    except ApprovalStoreError as e:
        return False, str(e)
    trusted = frozenset({trusted_pubkey}) if trusted_pubkey is not None else _trusted_owner_pubkeys()
    if recs and not trusted:
        return False, "no owner key is available to verify the evidence trail against (fail-closed)"
    ok, why = _verify_chain(recs, trusted)
    if not ok:
        return False, why
    # high-water: a valid chain that nonetheless sits BELOW the durable floor is a rollback/truncation.
    try:
        hw = load_highwater(_floor_path(org_id))
    except HighWaterError as e:
        return False, f"high-water floor unreadable (possible tamper): {e}"
    head = _Head(entry_count=len(recs), last_seq=(int(recs[-1]["seq"]) if recs else 0))
    ok, why = check_highwater(head, hw)
    if not ok:
        return False, why
    return True, "ok"


def read_evidence(org_id: str) -> list:
    """The org's recorded approval decisions as UI-safe dicts (the chain/sig envelope stripped), oldest first.
    Tenant-scoped by the per-org path. Lenient read of the content; verification is :func:`verify_evidence`."""
    try:
        recs = _read_evidence(org_id)
    except ApprovalStoreError:
        return []
    return [_evidence_content(r) for r in recs]


# ---------------------------------------------------------------------------- pending requests ----------------
def _pending_dir(org_id: str) -> Path:
    return _org_dir(org_id) / "pending"


def _granted_path(org_id: str, approval_id: str) -> Path:
    return _org_dir(org_id) / "granted" / (approval_id + ".json")


def _list_pending_raw(org_id: str) -> list:
    d = _pending_dir(org_id)
    out: list = []
    try:
        names = sorted(p.name for p in d.glob("*.json"))
    except OSError:
        return out
    for name in names:
        try:
            doc = _read_json(d / name)
        except ApprovalStoreError:
            continue
        if isinstance(doc, dict) and _ID_RE.match(str(doc.get("approval_id") or "")):
            out.append(doc)
    return out


def _find_pending(org_id: str, slug: str, action_digest: str, *, now: float) -> "Optional[dict]":
    """An existing, UN-EXPIRED pending request for this exact (slug, action_digest), or None."""
    for p in _list_pending_raw(org_id):
        if (str(p.get("slug") or "") == slug and str(p.get("action_digest") or "") == action_digest
                and float(p.get("expires_at") or 0.0) > now):
            return p
    return None


@dataclass(frozen=True)
class GateOutcome:
    """The result of one :func:`gate_step`. ``allow`` True ⇒ a live owner Allow was spent (single-use) and the
    caller may run the action. ``allow`` False ⇒ PAUSED: ``approval`` carries the UI card (id, risk, reason)."""

    allow: bool
    approval: "Optional[dict]" = None
    reason: str = ""


def gate_step(org_id: str, host: str, action: str, *, risk, params: "Optional[dict]" = None,
              requested_by: str = "", now: float) -> GateOutcome:
    """The GATE decision for a risky ``action``. ATOMIC under :data:`_SAVE_LOCK`:

      1. a live owner-signed Allow for THIS exact action+scope+params is found and CONSUMED (single-use burn):
         record a ``consumed`` evidence line and return ``allow=True`` — the caller runs the action ONCE.
      2. else ensure a pending request exists (idempotent on (slug, action_digest); a fresh one carries a fresh
         single-use nonce), record a ``requested`` evidence line the first time, and return ``allow=False`` with
         the approval card. DEFAULT-BLOCK: with no live Allow the action does not run.

    A replayed / expired / forged Allow is INERT (``consume_token`` fail-closes; a spent grant file is cleared
    and the gate re-asks). The owner PRIVATE key is used only to sign evidence, never written out."""
    from vigil_integration.live.approval_token import consume_token
    action_obj, slug, tool_name, digest = _action_binding(org_id, host, action, params)
    authority, _kp = _authority()
    with _SAVE_LOCK:
        gp = _granted_path(org_id, _pending_id_for(slug, digest, org_id))
        # (1) a stored Allow? consume it (atomic single-use). A grant file is named by the SAME deterministic
        # id a pending request would carry for this action, so the lookup is O(1).
        grant = _load_grant(gp)
        if grant is not None:
            decision = consume_token(grant, action_obj, authority=authority, now=float(now),
                                     ledger=_nonce_ledger(org_id))
            if decision.authorized:
                _unlink(gp)                              # spent — single-use; a replay finds nothing
                _append_evidence(org_id, {"decision": DECISION_CONSUMED, "approval_id": _file_id(gp),
                                          "slug": slug, "host": str(host), "action": str(action),
                                          "action_digest": digest, "actor": str(requested_by)[:_MAX_FIELD],
                                          "risk": _risk_dict(risk)}, now=now)
                return GateOutcome(allow=True, reason="owner-approved (single-use grant spent)")
            # the stored token did not authorize (expired / already consumed / tampered) — it is INERT; clear
            # it so the gate re-asks for a fresh Allow (default-block until a live one is granted).
            _unlink(gp)
        # (2) no live Allow — ensure a pending ask and PAUSE (default-block).
        existing = _find_pending(org_id, slug, digest, now=now)
        if existing is not None:
            return GateOutcome(allow=False, approval=_card(existing, risk), reason="awaiting owner approval")
        pend = _record_request(org_id, host, slug, action, digest, risk, requested_by, now=now)
        _append_evidence(org_id, {"decision": DECISION_REQUESTED, "approval_id": pend["approval_id"],
                                  "slug": slug, "host": str(host), "action": str(action),
                                  "action_digest": digest, "requested_by": str(requested_by)[:_MAX_FIELD],
                                  "risk": _risk_dict(risk)}, now=now)
        return GateOutcome(allow=False, approval=_card(pend, risk), reason="awaiting owner approval")


def _pending_id_for(slug: str, digest: str, org_id: str) -> str:
    """The DETERMINISTIC approval-id for a (slug, action_digest) under this org — stable so the grant file and a
    re-proposed pending request address the same slot (idempotent), yet org-namespaced so ids never collide
    across tenants. Shape ``appr_<32hex>`` (a safe single path component)."""
    h = hashlib.sha256(b"vigil-action-approval-id\x00" + org_id.encode("utf-8") + b"\x00"
                       + slug.encode("utf-8") + b"\x00" + digest.encode("utf-8")).hexdigest()
    return "appr_" + h[:32]


def _record_request(org_id: str, host: str, slug: str, action: str, digest: str, risk, requested_by: str,
                    *, now: float) -> dict:
    if len(_list_pending_raw(org_id)) >= _MAX_PENDING:
        raise ApprovalStoreError("too many outstanding approval requests for this org")
    approval_id = _pending_id_for(slug, digest, org_id)
    rec = {"approval_id": approval_id, "slug": slug, "host": str(host)[:_MAX_FIELD], "action": str(action),
           "action_digest": digest, "nonce": secrets.token_hex(16),
           "requested_by": str(requested_by)[:_MAX_FIELD], "created_at": float(now),
           "expires_at": float(now) + REQUEST_TTL_SECONDS, "risk": _risk_dict(risk)}
    _write_json(_pending_dir(org_id) / (approval_id + ".json"), rec)
    return rec


def _risk_dict(risk) -> dict:
    if hasattr(risk, "as_dict"):
        return risk.as_dict()
    return dict(risk) if isinstance(risk, dict) else {}


def _card(pend: dict, risk) -> dict:
    """The UI-safe pending-approval card (no nonce, no key) for the operator's Allow/Block prompt."""
    return {"approval_id": str(pend.get("approval_id") or ""), "host": str(pend.get("host") or ""),
            "action": str(pend.get("action") or ""), "created_at": pend.get("created_at"),
            "expires_at": pend.get("expires_at"), "risk": _risk_dict(risk) or _risk_dict(pend.get("risk"))}


# ---------------------------------------------------------------------------- the Allow / Block answer ---------
def _load_grant(path: Path):
    doc = _read_json(path)
    if doc is None:
        return None
    from vigil_integration.live.approval_token import ApprovalToken
    try:
        return ApprovalToken(**{k: doc[k] for k in (
            "tool_name", "target", "action_digest", "not_before", "not_after", "nonce", "key_id",
            "signature_b64")}, schema=str(doc.get("schema", "vigil-peraction-approval")))
    except (KeyError, TypeError):
        return None


def _file_id(path: Path) -> str:
    name = path.name
    return name[:-5] if name.endswith(".json") else name


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


@dataclass(frozen=True)
class AnswerResult:
    ok: bool
    decision: str
    approval_id: str = ""
    already: bool = False
    reason: str = ""


def answer(org_id: str, requester: str, approval_id: str, *, allow: bool, now: float) -> AnswerResult:
    """Record the operator's Allow or Block for one pending approval. TENANT-SCOPED (``org_id`` from the
    session, never a body field). IDEMPOTENT: a repeat for an already-answered id returns the prior outcome and
    mints no second grant. On ALLOW, an owner-signed, single-use, time-boxed Allow is minted bound to the exact
    action and dropped in ``granted/`` for :func:`gate_step` to spend; on BLOCK, NO grant is written (the gate
    stays closed — default-block) and the refusal is recorded. Fail-closed: an unknown/invalid id is refused.

    STEP-UP for a HIGH-risk Allow is enforced by the CALLER (the provisioner's ``_require_stepup``) BEFORE this
    is reached — this records the owner-signed decision; it never bypasses the step-up gate."""
    aid = str(approval_id or "").strip()
    if not _ID_RE.match(aid):
        return AnswerResult(ok=False, decision="", reason="invalid approval id")
    with _SAVE_LOCK:
        pend = _read_json(_pending_dir(org_id) / (aid + ".json"))
        gp = _granted_path(org_id, aid)
        if pend is None:
            # already resolved — idempotent: a live grant ⇒ previously allowed; none ⇒ previously blocked/consumed.
            if _read_json(gp) is not None:
                return AnswerResult(ok=True, decision=DECISION_ALLOWED, approval_id=aid, already=True)
            return AnswerResult(ok=True, decision=DECISION_BLOCKED, approval_id=aid, already=True,
                                reason="no such pending approval (already answered)")
        slug = str(pend.get("slug") or "")
        host = str(pend.get("host") or "")
        action = str(pend.get("action") or "")
        digest = str(pend.get("action_digest") or "")
        if not allow:
            _unlink(_pending_dir(org_id) / (aid + ".json"))
            _append_evidence(org_id, {"decision": DECISION_BLOCKED, "approval_id": aid, "slug": slug,
                                      "host": host, "action": action, "action_digest": digest,
                                      "actor": str(requester)[:_MAX_FIELD], "risk": _risk_dict(pend.get("risk"))},
                             now=now)
            return AnswerResult(ok=True, decision=DECISION_BLOCKED, approval_id=aid)
        # ALLOW — mint the owner-signed, single-use, time-boxed per-action token bound to THIS action.
        if _read_json(gp) is not None:                   # idempotent: already allowed, do not re-mint
            return AnswerResult(ok=True, decision=DECISION_ALLOWED, approval_id=aid, already=True)
        from vigil_integration.live.approval_token import ApprovalAction, mint_token
        kp = _owner_keypair()
        action_obj = ApprovalAction(tool_name=f"engage:{action}", target=slug, action_digest=digest)
        token = mint_token(action_obj, owner_private_key_b64=kp.private_key_b64, key_id="owner",
                           nonce=str(pend.get("nonce") or ""), not_before=float(now),
                           not_after=float(now) + GRANT_TTL_SECONDS)
        _write_json(gp, {"tool_name": token.tool_name, "target": token.target,
                         "action_digest": token.action_digest, "not_before": token.not_before,
                         "not_after": token.not_after, "nonce": token.nonce, "key_id": token.key_id,
                         "signature_b64": token.signature_b64, "schema": token.schema})
        _unlink(_pending_dir(org_id) / (aid + ".json"))
        _append_evidence(org_id, {"decision": DECISION_ALLOWED, "approval_id": aid, "slug": slug, "host": host,
                                  "action": action, "action_digest": digest,
                                  "actor": str(requester)[:_MAX_FIELD], "not_after": token.not_after,
                                  "risk": _risk_dict(pend.get("risk"))}, now=now)
        return AnswerResult(ok=True, decision=DECISION_ALLOWED, approval_id=aid)


def sweep_timeouts(org_id: str, *, now: float) -> int:
    """Clear every pending request whose window has elapsed and record a ``timed_out`` (default-BLOCK) decision
    for each. Returns how many timed out. Idempotent / total: a swept request simply no longer gates the action
    (no grant was ever minted, so the action stays blocked). Called on the read path so the audit trail shows
    the default-block without needing a separate daemon."""
    n = 0
    with _SAVE_LOCK:
        for p in _list_pending_raw(org_id):
            if float(p.get("expires_at") or 0.0) > now:
                continue
            aid = str(p.get("approval_id") or "")
            if not _ID_RE.match(aid):
                continue
            _unlink(_pending_dir(org_id) / (aid + ".json"))
            _append_evidence(org_id, {"decision": DECISION_TIMED_OUT, "approval_id": aid,
                                      "slug": str(p.get("slug") or ""), "host": str(p.get("host") or ""),
                                      "action": str(p.get("action") or ""),
                                      "action_digest": str(p.get("action_digest") or ""),
                                      "risk": _risk_dict(p.get("risk"))}, now=now)
            n += 1
    return n


def list_pending(org_id: str, *, now: float) -> list:
    """The org's OPEN approval requests as UI-safe cards (expired ones swept to default-block first). Tenant-
    scoped by the per-org path — one org can never see another's."""
    sweep_timeouts(org_id, now=now)
    return [_card(p, p.get("risk")) for p in _list_pending_raw(org_id)
            if float(p.get("expires_at") or 0.0) > now]


def pending_for(org_id: str, approval_id: str) -> "Optional[dict]":
    """The raw pending request for ``approval_id`` under ``org_id`` (its ``risk`` drives the step-up decision),
    or None. Tenant-scoped by the per-org path; the id is validated to a safe token before any path join."""
    aid = str(approval_id or "").strip()
    if not _ID_RE.match(aid):
        return None
    try:
        return _read_json(_pending_dir(org_id) / (aid + ".json"))
    except ApprovalStoreError:
        return None
