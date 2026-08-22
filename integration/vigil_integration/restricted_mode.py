"""
restricted_mode — a safe LANDING STATE between fully-operational and fully-stopped (W13-6 #499).

The gap this closes: before now the system had exactly two states — fully operational, or the
``vigil panic`` HARD-STOP (kill-switches tripped *and* the process/units contained). An integrity
failure therefore had no safe middle ground: it either kept running on a spine it could no longer
trust, or it took the whole process down and lost the ability to DIAGNOSE and EXPORT EVIDENCE about
what went wrong. RESTRICTED MODE is that middle ground:

  * every TARGET-TOUCHING / MUTATING action is REFUSED, and
  * read-only DIAGNOSIS, EVIDENCE ACCESS, AUDIT EXPORT and AUTHORIZATION REPAIR still work,
  * the process stays UP (unlike ``vigil panic``, which also kills the process/units).

HARD CONSTRAINT — this module is a FACADE over the EXISTING machinery, never a second policy engine
(the exact anti-pattern the red-pen caught in ``vigil patch``):

  * The REFUSAL of a mutating/target-touching action is NOT decided here. Entering restricted mode
    TRIPS the existing per-engagement KILL-SWITCH (``framework.v2.authority.killswitch.KillSwitch`` —
    the same primitive ``vigil panic`` trips), and the ALREADY-EXISTING conjunctive gate-of-record
    (``authorize_action`` → ``conjunctive_gate`` → ``sovereign_bridge``) denies every gated action
    while the kill-switch is tripped, fail-closed and persistently (the kill-switch file survives a
    restart). There is no new gate and no new refusal path. :func:`restricted_mode_permits` only
    NAMES the reduced surface (the read-only actions the mode is designed to keep) so a caller/test
    can assert it PER CAPABILITY — it makes no authorization decision and touches no target.

  * The TRANSITIONS (enter/leave) are recorded on a hash-chained append-only ledger built from the
    SAME ``vigil_core`` chain primitive the signed spine uses (``append_entry`` over
    ``digest_payload``), so entering/leaving is recorded on the chain, tamper-evident, and survives a
    restart (the current mode is the last transition on disk). This is a RECORD, not a decision.

  * The INTEGRITY CHECK reuses the existing :mod:`integrity_verifier` (``verify_integrity``) — on a
    FAIL it transitions to restricted mode instead of crashing or continuing.

Two-env boundary (FATAL-2). The module core imports only stdlib + ``vigil_core`` + the import-clean
:mod:`integrity_verifier`, so it loads in BOTH the offense and the sovereign process exactly like
``vigil_core.gate``. The ONLY offense coupling — tripping the ``framework`` kill-switch — is a
function-LOCAL import inside :func:`trip_all_killswitches`, reachable only when actually entering the
mode offense-side. Importing this module never co-loads ``framework``/``strix``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from vigil_core import ChainEntry, append_entry, digest_payload, verify_chain

from . import integrity_verifier as _iv

__all__ = [
    "RESTRICTED_ACTIONS",
    "restricted_mode_permits",
    "Transition",
    "record_transition",
    "record_refusal",
    "read_transitions",
    "is_restricted",
    "current_state",
    "enumerate_engagement_slugs",
    "killswitches_all_tripped",
    "trip_all_killswitches",
    "guarded_authorize",
    "enter_restricted_mode",
    "leave_restricted_mode",
    "enforce_integrity_or_restrict",
]

# ── the reduced surface restricted mode is DESIGNED to keep ─────────────────────────────────────────
# These are the read-only diagnostic / recovery action-kinds that MUST keep working when the system has
# dropped into restricted mode. They are NOT offense capabilities (every framework
# ``entitlement.Capability`` is a target-touching / exploit capability and is therefore REFUSED here);
# they are the operational actions an operator needs to understand and repair the box. Naming them is a
# declaration of the mode's surface, not an authorization decision — the refusal of everything else is
# enforced by the kill-switch/gate, never by this list.
DIAGNOSTICS = "diagnostics"                 # doctor / readyz / verify-integrity — read-only inspection
EVIDENCE_EXPORT = "evidence_export"         # read + export existing evidence (no new target contact)
AUDIT_EXPORT = "audit_export"               # export the spine / attestation / alarm audit trail
AUTHORIZATION_REPAIR = "authorization_repair"  # repair/rotate authority + CLEAR the kill-switch (recovery)

RESTRICTED_ACTIONS: frozenset[str] = frozenset(
    {DIAGNOSTICS, EVIDENCE_EXPORT, AUDIT_EXPORT, AUTHORIZATION_REPAIR}
)


def _action_id(action: Any) -> str:
    """Normalize an action to its stable string id. A framework ``Capability`` (or any enum) stringifies
    via its ``.value``; a bare string is taken as-is. This reads an identity — it decides nothing."""
    val = getattr(action, "value", None)
    return val if isinstance(val, str) else str(action)


def restricted_mode_permits(action: Any) -> bool:
    """Is ``action`` one of the read-only diagnostic/recovery actions restricted mode keeps open?

    True ONLY for a member of :data:`RESTRICTED_ACTIONS`; everything else — every mutating /
    target-touching action, including EVERY offense ``entitlement.Capability`` — is False. This is a
    membership test over the declared surface, fail-closed by construction: an unknown action is NOT
    permitted. It makes no authorization decision (the kill-switch/gate does that) and never contacts a
    target; it only lets a caller/test assert the mode's surface per capability."""
    return _action_id(action) in RESTRICTED_ACTIONS


# ── the hash-chained event ledger (recorded on the chain, survives restart) ─────────────────────────
# The SAME chain carries three event kinds, so a refusal cannot be excised without breaking the very
# chain that also carries the enter/leave transitions:
#   * ENTER / LEAVE — a mode TRANSITION (a record, never a decision), and
#   * REFUSE        — one action REFUSED while the gate is closed (recorded per-refusal, so the audit
#                     shows EACH refused action while restricted, not only the enter transition).
ENTER = "enter"
LEAVE = "leave"
REFUSE = "refuse"
_TRANSITION_ACTIONS = frozenset({ENTER, LEAVE})
_LEDGER_DIRNAME = "restricted-mode"
_LEDGER_FILENAME = "transitions.jsonl"
_KIND = "vigil-restricted-mode-transition-v1"


@dataclass(frozen=True)
class Transition:
    """One recorded ledger event. ``action`` is :data:`ENTER`, :data:`LEAVE` or :data:`REFUSE`; the rest
    is signed-adjacent DATA (never an ordering key — the chain order is ``(seq, prev_hash)`` alone). For a
    REFUSE event ``trigger`` is the gate's denial code and ``reason`` names the refused action/target."""

    seq: int
    action: str
    trigger: str
    reason: str
    at: str
    entry_hash: str

    @property
    def entered(self) -> bool:
        return self.action == ENTER

    @property
    def is_transition(self) -> bool:
        """A mode transition (enter/leave), as opposed to a per-refusal audit record."""
        return self.action in _TRANSITION_ACTIONS


def _ledger_path(base_dir: str | os.PathLike) -> Path:
    return Path(base_dir) / _LEDGER_DIRNAME / _LEDGER_FILENAME


def _now_iso(now: Optional[float]) -> str:
    ts = datetime.now(timezone.utc) if now is None else datetime.fromtimestamp(now, tz=timezone.utc)
    return ts.isoformat()


def _content(*, seq: int, action: str, trigger: str, reason: str, at: str) -> dict:
    """The exact payload whose digest binds the chain link — a pure function of the fields, so a reader
    re-derives byte-identical bytes. ``kind`` domain-separates it from every other chain-link payload."""
    return {
        "action": action,
        "at": at,
        "kind": _KIND,
        "reason": reason,
        "seq": seq,
        "trigger": trigger,
    }


def read_transitions(base_dir: str | os.PathLike) -> list[Transition]:
    """Read the transitions ledger and RE-VERIFY the hash chain. Returns the transitions in order.

    A ledger whose chain does not verify (a deleted/reordered/forged/edited line) is a tampered audit
    trail: this RAISES ``ValueError`` rather than returning a plausible-but-false history — the caller
    must not trust a tampered ledger's notion of the current mode. A malformed line likewise raises. An
    absent ledger is an empty history (never entered), not an error."""
    path = _ledger_path(base_dir)
    if not path.is_file():
        return []
    entries: list[ChainEntry] = []
    transitions: list[Transition] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines()):
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            if not isinstance(rec, dict):
                raise ValueError("transition line is not a JSON object")
            seq = int(rec["seq"])
            action = str(rec["action"])
            trigger = str(rec["trigger"])
            reason = str(rec["reason"])
            at = str(rec["at"])
            prev_hash = str(rec["prev_hash"])
            cert_digest = str(rec["cert_digest"])
            entry_hash = str(rec["entry_hash"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"restricted-mode ledger line {lineno} is malformed: {exc}") from exc
        # Bind the chain link to the exact payload bytes: any edit to the recorded content forces a
        # different digest, so the stored entry_hash would no longer verify below.
        want_digest = digest_payload(_content(seq=seq, action=action, trigger=trigger, reason=reason, at=at))
        if cert_digest != want_digest:
            raise ValueError(f"restricted-mode ledger line {lineno}: record digest mismatch (tampered)")
        entries.append(ChainEntry(seq=seq, prev_hash=prev_hash, cert_digest=cert_digest, entry_hash=entry_hash))
        transitions.append(Transition(seq=seq, action=action, trigger=trigger, reason=reason, at=at,
                                      entry_hash=entry_hash))
    ok, why = verify_chain(entries)
    if not ok:
        raise ValueError(f"restricted-mode ledger chain is broken: {why}")
    return transitions


def _append_event(base_dir: str | os.PathLike, *, action: str, trigger: str, reason: str,
                  now: Optional[float] = None) -> Transition:
    """Append one event (enter/leave/refuse) to the hash-chained ledger and return it. The new link
    chains onto the verified tail (a tampered ledger raises here too — we never chain onto a broken
    history), so every event, refusals included, is on the same tamper-evident chain."""
    existing = read_transitions(base_dir)          # re-verifies the chain before we extend it
    prior_entries = [ChainEntry(seq=t.seq, prev_hash="", cert_digest="", entry_hash=t.entry_hash)
                     for t in existing]             # only entry_hash/seq are consulted by append_entry
    seq = len(existing)
    at = _now_iso(now)
    cert_digest = digest_payload(_content(seq=seq, action=action, trigger=trigger, reason=reason, at=at))
    link = append_entry(prior_entries, cert_digest)
    record = {
        "action": action,
        "at": at,
        "cert_digest": link.cert_digest,
        "entry_hash": link.entry_hash,
        "kind": _KIND,
        "prev_hash": link.prev_hash,
        "reason": reason,
        "seq": link.seq,
        "trigger": trigger,
    }
    path = _ledger_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return Transition(seq=link.seq, action=action, trigger=trigger, reason=reason, at=at,
                      entry_hash=link.entry_hash)


def record_transition(base_dir: str | os.PathLike, *, action: str, trigger: str, reason: str,
                      now: Optional[float] = None) -> Transition:
    """Append one enter/leave TRANSITION to the hash-chained ledger and return it."""
    if action not in _TRANSITION_ACTIONS:
        raise ValueError(f"transition action must be {ENTER!r} or {LEAVE!r}, not {action!r}")
    return _append_event(base_dir, action=action, trigger=trigger, reason=reason, now=now)


def record_refusal(base_dir: str | os.PathLike, *, action: Any, target: str, denial_code: str,
                   reason: str = "", now: Optional[float] = None) -> Transition:
    """Record ONE refused action on the same hash-chained ledger as the transitions — so an audit shows
    EACH action refused while the gate is closed, not only the enter transition. This is a RECORD, not a
    decision: the refusal itself is made by the existing kill-switch/gate; here we only append its audit
    line. ``trigger`` carries the gate's ``denial_code`` and ``reason`` names the refused action/target."""
    action_id = _action_id(action)
    detail = f"refused {action_id!r} on {target!r}"
    if reason:
        detail = f"{detail}: {reason}"
    return _append_event(base_dir, action=REFUSE, trigger=(denial_code or "refused"), reason=detail,
                         now=now)


def current_state(base_dir: str | os.PathLike) -> Optional[Transition]:
    """The most recent mode TRANSITION (or None if the system has never entered restricted mode). REFUSE
    audit records are skipped — they never change the mode. Because the ledger is on disk, this reflects
    the mode ACROSS a restart."""
    transitions = read_transitions(base_dir)
    for t in reversed(transitions):
        if t.is_transition:
            return t
    return None


def is_restricted(
    base_dir: str | os.PathLike,
    *,
    gate_closed_fn: Optional[Callable[[], bool]] = None,
    authority_dir: Optional[str | os.PathLike] = None,
    ks_path_for: Optional[Callable[[str], Path]] = None,
    killswitch_cls: Any = None,
) -> bool:
    """True iff the system is genuinely in restricted mode — i.e. the last transition is an ENTER AND the
    LIVE gate is closed.

    The last transition is the RECORD of intent; the kill-switch/gate is the ENFORCEMENT. Reading only
    the ledger would let this report ``restricted`` while an operator had already cleared the kill-switch
    (a recovery step that clears the gate but records no LEAVE), i.e. while the gate was OPEN. That is
    exactly the state a safety check must not misreport. So this ALSO consults the SAME live kill-switch
    the refusal path consults (:func:`killswitches_all_tripped`): if any known engagement's gate is open,
    this returns False. The invariant it upholds: **reported-restricted implies the gate is closed.**

    ``gate_closed_fn`` (and the ``authority_dir`` / ``ks_path_for`` / ``killswitch_cls`` DI seams,
    mirroring :func:`enter_restricted_mode`'s ``trip_fn``) let a caller/test drive the live-gate read
    without the full offense install; the default reads the real offense kill-switches."""
    last = current_state(base_dir)
    if not (last and last.entered):
        return False
    if gate_closed_fn is not None:
        return bool(gate_closed_fn())
    closed, _count = killswitches_all_tripped(
        authority_dir=authority_dir, ks_path_for=ks_path_for, killswitch_cls=killswitch_cls
    )
    return closed


# ── the stop primitive — the EXISTING kill-switch, shared with `vigil panic` ─────────────────────────
def enumerate_engagement_slugs(authority_dir: str | os.PathLike) -> list[str]:
    """Enumerate every engagement slug the offense engine knows in ``authority_dir`` — one per
    ``<slug>.authority.json`` (provisioned) or ``<slug>.halt`` (already tripped). Pure filesystem read,
    no framework import. Sorted for determinism. An absent/non-dir path is an empty set."""
    adir = Path(authority_dir)
    slugs: set[str] = set()
    if adir.is_dir():
        for f in adir.glob("*.authority.json"):
            slugs.add(f.name[: -len(".authority.json")])
        for f in adir.glob("*.halt"):                 # a slug already halted is re-affirmed
            slugs.add(f.name[: -len(".halt")])
    return sorted(slugs)


def killswitches_all_tripped(
    *,
    authority_dir: Optional[str | os.PathLike] = None,
    ks_path_for: Optional[Callable[[str], Path]] = None,
    killswitch_cls: Any = None,
) -> tuple[bool, int]:
    """Read the LIVE gate state via the SAME ``KillSwitch`` primitive the refusal path consults, and
    return ``(all_tripped, count)`` over every engagement the offense engine knows.

    This is the read-side twin of :func:`trip_all_killswitches`: it makes NO decision and trips nothing —
    it reports whether the gate is actually closed right now. ``all_tripped`` is True iff EVERY enumerated
    engagement's kill-switch is currently tripped; if even one is clear (e.g. an operator cleared it
    during recovery), it is False — the gate is open for that engagement. With no engagement provisioned
    the result is vacuously ``(True, 0)``: there is nothing a gate could authorize.

    The ``framework`` import is function-LOCAL (FATAL-2) and only runs on the default path; inject
    ``killswitch_cls`` (with ``authority_dir`` / ``ks_path_for``) to drive it without the offense install.
    A ``KillSwitch.is_tripped()`` is itself fail-closed (an ambiguous stat reads as TRIPPED)."""
    if killswitch_cls is None:
        from framework.v2.authority.killswitch import KillSwitch as killswitch_cls  # noqa: N806
        from framework.v2.common import paths as _paths

        adir = Path(authority_dir) if authority_dir is not None else _paths.authority_dir()
    else:
        adir = Path(authority_dir) if authority_dir is not None else Path(".")
    slugs = enumerate_engagement_slugs(adir)
    if not slugs:
        return (True, 0)
    all_tripped = True
    for slug in slugs:
        path = ks_path_for(slug) if ks_path_for is not None else None
        try:
            if not killswitch_cls(slug, path=path).is_tripped():
                all_tripped = False
        except Exception:  # noqa: BLE001 — cannot prove a switch is clear ⇒ fail closed (treat as tripped)
            continue
    return (all_tripped, len(slugs))


def trip_all_killswitches(reason: str, *, authority_dir: Optional[str | os.PathLike] = None,
                          ks_path_for: Optional[Callable[[str], Path]] = None) -> list[str]:
    """Trip the persistent, fail-closed kill-switch for EVERY engagement the offense engine knows — the
    SAME ``framework.v2.authority.killswitch.KillSwitch`` primitive ``vigil panic`` trips. This is the
    ONLY offense coupling in the module, so its ``framework`` imports are function-LOCAL (FATAL-2): it is
    reachable only when the mode is actually entered offense-side. Returns the slugs actually tripped.

    ``authority_dir`` / ``ks_path_for`` are dependency-injection seams (mirroring ``KillSwitch(path=)``)
    so the wiring is testable against a real KillSwitch at a temp path without the full install."""
    from framework.v2.authority.killswitch import KillSwitch
    from framework.v2.common import paths as _paths

    adir = Path(authority_dir) if authority_dir is not None else _paths.authority_dir()
    slugs = enumerate_engagement_slugs(adir)
    tripped: list[str] = []
    for slug in slugs:
        try:
            path = ks_path_for(slug) if ks_path_for is not None else None
            KillSwitch(slug, path=path).trip(reason)  # idempotent: the first reason is preserved
            tripped.append(slug)
        except Exception:  # noqa: BLE001 — one bad slug must never stop the rest of the stop
            continue
    return tripped


# ── the transitions ─────────────────────────────────────────────────────────────────────────────────
def enter_restricted_mode(
    *,
    base_dir: str | os.PathLike,
    trigger: str,
    reason: str = "",
    now: Optional[float] = None,
    trip_fn: Optional[Callable[[str], Sequence[str]]] = None,
    trip_kwargs: Optional[dict] = None,
) -> Transition:
    """Enter restricted mode: TRIP the existing kill-switches (so the existing gate refuses every gated
    action) and RECORD the enter transition on the hash-chained ledger. The process is left running —
    diagnosis/export stay available. Returns the recorded :class:`Transition`.

    ``trigger`` names WHY we entered (e.g. ``"integrity"``, ``"emergency_stop"``, ``"operator"``).
    ``trip_fn`` defaults to :func:`trip_all_killswitches`; it is injectable so the transition ledger can
    be exercised without the offense kill-switch, and so a real KillSwitch at a temp path can be driven
    in a test. The record is written even if the trip surfaces nothing (no engagement provisioned yet)."""
    stop = trip_fn if trip_fn is not None else trip_all_killswitches
    ks_reason = reason or f"restricted mode ({trigger})"
    try:
        stop(ks_reason, **(trip_kwargs or {}))
    except Exception:  # noqa: BLE001 — a stop-side failure must not prevent recording that we tried
        pass
    return record_transition(base_dir, action=ENTER, trigger=trigger, reason=ks_reason, now=now)


def leave_restricted_mode(
    *,
    base_dir: str | os.PathLike,
    reason: str = "",
    cleared_by: str = "operator",
    now: Optional[float] = None,
) -> Transition:
    """Record a deliberate LEAVE transition on the chain. Note: like the kill-switch, actually CLEARING
    the tripped kill-switches is a separate, explicit operator act (``authorization_repair``) — leaving
    restricted mode records the intent/audit event; it never silently re-arms the target-touching path."""
    return record_transition(base_dir, action=LEAVE, trigger=f"cleared_by:{cleared_by}",
                             reason=reason or "leave restricted mode", now=now)


# ── per-refusal audit: record EACH action the closed gate refuses ────────────────────────────────────
def guarded_authorize(
    authority: Any,
    request: Any,
    *,
    killswitch: Any,
    base_dir: str | os.PathLike,
    actions_taken: int = 0,
    now: Any = None,
    authorize_fn: Optional[Callable[..., Any]] = None,
) -> Any:
    """Authorize ONE action through the EXISTING authority gate and, when the gate REFUSES it because the
    kill-switch is tripped (denial code ``halted`` — the restricted-mode / panic stop), record that
    refusal on the hash-chained ledger before returning.

    This adds NO new gate and makes NO authorization decision: the decision is entirely the existing
    ``authorize_action``'s; this wrapper only appends the per-refusal audit line the objection asks for,
    so an audit shows EACH action refused while the gate is closed — not only the enter transition. The
    ``framework`` import is function-LOCAL (FATAL-2); inject ``authorize_fn`` to drive it in a test."""
    if authorize_fn is None:
        from framework.v2.authority.gate import authorize_action as authorize_fn  # noqa: N806
    decision = authorize_fn(authority, request, killswitch=killswitch, actions_taken=actions_taken,
                            now=now)
    if not getattr(decision, "allowed", True) and getattr(decision, "denial_code", "") == "halted":
        # A refusal by the CLOSED gate (kill-switch tripped) — the restricted-mode enforcement path.
        record_refusal(
            base_dir,
            action=getattr(request, "action_kind", None) or getattr(request, "target", "action"),
            target=str(getattr(request, "target", "")),
            denial_code=str(getattr(decision, "denial_code", "halted")),
            reason=str(getattr(decision, "reason", "")),
        )
    return decision


# ── the integrity trigger ────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class IntegrityGuardResult:
    """The outcome of an integrity guard pass. ``report`` is the underlying :class:`IntegrityReport`;
    ``restricted`` is True iff this pass DROPPED the system into restricted mode."""

    report: Any
    restricted: bool
    transition: Optional[Transition]


def enforce_integrity_or_restrict(
    *,
    home: str | os.PathLike,
    base_dir: str | os.PathLike,
    now: Optional[float] = None,
    head_trust_root: Any = None,
    trip_fn: Optional[Callable[[str], Sequence[str]]] = None,
    trip_kwargs: Optional[dict] = None,
) -> IntegrityGuardResult:
    """Run the EXISTING integrity audit over ``home``; on a FAILURE, transition to restricted mode
    rather than crashing or continuing. Never raises for an integrity failure — an integrity break is a
    handled, recorded transition, not an exception. Returns an :class:`IntegrityGuardResult`.

    A clean audit leaves the mode untouched (fully operational). A FAILED audit enters restricted mode
    (trigger ``"integrity"``) with a reason naming the failed checks, and records it on the chain."""
    report = _iv.verify_integrity(home, now=now, head_trust_root=head_trust_root)
    if report.ok:
        return IntegrityGuardResult(report=report, restricted=False, transition=None)
    failed = ", ".join(f"{c.check}={c.detail}" for c in report.failures) or "integrity check failed"
    transition = enter_restricted_mode(
        base_dir=base_dir, trigger="integrity", reason=f"integrity failure: {failed}", now=now,
        trip_fn=trip_fn, trip_kwargs=trip_kwargs,
    )
    return IntegrityGuardResult(report=report, restricted=True, transition=transition)
