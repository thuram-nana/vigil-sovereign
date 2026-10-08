"""
conjunctive_gate — every target-touching offense action must pass BOTH gates (VIGIL P7 Slice 3).

Two orthogonal, conjunctive checks over one signed spine (plus a THIRD for destructive actions):

  * CRUCIBLE authority — "is THIS target/action inside the signed engagement envelope RIGHT NOW?"
    (killswitch → validity window → scope → destructive → live-destructive → budget; fail-closed).
    Its killswitch step has absolute precedence, so it is checked FIRST.
  * WARDEN tool gate — "what TIER is this tool-class, and must the owner approve it?"
    (raise-only A2 floor → auto / queue / deny; see warden_gate.decide_tool).
  * Threshold-destruction (I4) — for a DESTRUCTIVE/high-blast action ONLY: "is there an owner-inclusive
    m-of-n authorization for exactly this action?" (see destruction_gate). Orthogonal to WARDEN's tier
    approval — an irreversible action needs the quorum even if WARDEN would auto-allow the class.

First failure wins; ANY error in any half is a DENY (never caught-and-continued). The verdict
is the conjunction: ALLOW only if CRUCIBLE in-envelope AND WARDEN auto AND (if destructive) threshold-
authorized; QUEUE if in-envelope + destruction-satisfied but WARDEN needs owner approval; DENY otherwise.

The composition core (:func:`conjunctive_decide`) is pure — both halves are injected as thunks — so it is
fully testable without CRUCIBLE or the kernel. As of unification S6 that pure core (``conjunctive_decide`` +
``GateVerdict``/``CrucibleResult``/``DestructionOutcome``) lives in the neutral shared ``vigil_core.gate`` so
BOTH processes import the SAME gate-of-record primitive; this module RE-EXPORTS it (back-compat for every
existing importer of ``vigil_integration.conjunctive_gate``) and adds the OFFENSE wrapper.
:func:`build_offense_gate` wires the real CRUCIBLE ``authorize_action`` (loaded via the governance trust root
— the seam map flagged a ``None`` trust root as the biggest fail-open) and the real WARDEN classifier; its
``framework`` import is LAZY so this module stays import-clean for the sovereign side (which never calls it).
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

# The pure gate-of-record composition now lives in the neutral shared core (S6). Re-exported here so every
# existing `from vigil_integration.conjunctive_gate import ...` keeps working, byte-identical semantics.
from vigil_core.gate import CrucibleResult, DestructionOutcome, GateVerdict, conjunctive_decide
from vigil_core.metrics import record_gate_verdict

from .warden_gate import DEFAULT_CEILING, DEFAULT_FLOOR, ToolDecision, decide_tool

__all__ = [
    "GateVerdict", "CrucibleResult", "DestructionOutcome", "conjunctive_decide", "build_offense_gate",
]


def _as_datetime(now: Any) -> "datetime | None":
    """The CRUCIBLE leg (authorize_action) wants a timezone-aware datetime (or None → it uses utcnow). A
    single ``now`` shared with the destruction leg (which wants an epoch float) must be adapted per-leg —
    this was the confirmed gate bug: one ``now`` broke whichever leg it wasn't typed for."""
    if now is None or isinstance(now, datetime):
        return now
    if isinstance(now, (int, float)) and not isinstance(now, bool):
        try:
            return datetime.fromtimestamp(float(now), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return None                                # unusable → authorize_action defaults to utcnow (safe)


def _as_epoch(now: Any) -> float:
    """The destruction leg (authorize_destruction) wants an epoch float (it rejects None/datetime/bool as
    'not numeric'). None/unusable → the real wall-clock, which is correct for the not_before/not_after
    dead-man's-switch window (this is not the deterministic learning path)."""
    if isinstance(now, datetime):
        return now.timestamp()
    if isinstance(now, (int, float)) and not isinstance(now, bool):
        return float(now)
    return time.time()


# --- M4.2 pre-action blast-radius VETO (defense-in-depth) ----------------------------------------
#
# The authority gate (`framework.v2.authority.gate.authorize_action`) already carries an OPT-IN,
# DEFAULT-OFF blast-radius veto conjunct, but until now it had NO production caller — only tests
# injected a predictor. These helpers wire the REAL predictor into `build_offense_gate` so a
# CONSEQUENTIAL (state-changing / destructive) action that would newly expose crown jewels worth
# more than a per-engagement ceiling is REFUSED before it runs. Strictly defense-in-depth: it can
# only REFUSE, never promote; it is ADVISORY (reads a read-only forward world-model query, mints no
# FACT, is no oracle input); and it NEVER touches the non-consequential (read-only) hot path — for a
# read it is not even constructed. Every `framework`/`worldmodel` import below is LAZY (offense env
# only), so this module stays import-clean for the sovereign plane (FATAL-2).


def _host_of(target: str) -> str:
    """The bare hostname of a target URL/host (stdlib only — keeps the module sovereign-safe)."""
    parsed = urlparse(target if "://" in target else "https://" + target)
    return (parsed.hostname or "").strip()


def _load_engagement_world(slug: str):
    """The engagement's persisted attack-graph, projected from the signed spine at
    ``targets/<slug>/worldmodel-spine.json`` (the SAME canonical slug path the attack-paths triage
    reads). Returns ``None`` when no spine exists yet — a normal, benign state in which the veto has
    no basis to refuse and therefore stays DISARMED (it never fabricates a refusal from no evidence).
    A spine that is present but corrupt is allowed to raise: any error in the CRUCIBLE gate half is a
    DENY (fail-closed), so a broken world-model refuses the consequential action rather than waving it
    through. Read-only: the projection never mutates the spine and sends no traffic."""
    from framework.v2.common import paths as _paths
    from framework.v2.worldmodel.attack_paths import _load_spine
    from framework.v2.worldmodel.spine_projector import project_spine, records_from_dicts

    spine_path = Path(_paths.target_dir(slug)) / "worldmodel-spine.json"
    if not spine_path.is_file():
        return None
    rows = _load_spine(spine_path)
    return project_spine(records_from_dicts(rows))


def _effective_blast_ceiling(slug: str, explicit: float | None):
    """Resolve the per-engagement veto ceiling: a trusted-caller ``explicit`` value wins; otherwise
    the engagement's own ``targets/<slug>/impact.yaml`` (``blast_ceiling`` key). ``None`` ⇒ the veto
    stays OFF for this engagement (byte-identical to pre-M4.2)."""
    if explicit is not None:
        return float(explicit)
    try:
        from framework.v2.worldmodel.impact import blast_ceiling_for_slug
    except ImportError:
        # CRUCIBLE world-model half not present on this plane (integration-only / the two-env
        # keyless boundary): the veto has no impact model to reason over, so it stays DISARMED
        # (None ⇒ byte-identical to pre-M4.2). The destruction quorum + authority gate still
        # protect the action; fail-closed is reserved for a world-model that is present-but-corrupt.
        return None
    return blast_ceiling_for_slug(slug)


def _build_blast_radius_fn(slug: str, target_url: str, world_provider):
    """Build the read-only predictor the authority gate consults for ONE consequential action, or
    ``None`` when there is no world-model to reason over (⇒ the veto is left disarmed for this call).

    The action is modelled as OPENING attacker reachability to the target host: the predictor asks
    "if the attacker (``attacker:self``) could now reach ``host:<target>``, which crown jewels does
    that NEWLY expose, and what is their summed business worth?" — ``impact.predict_action_blast_radius``
    over the engagement impact model, an AUGMENTED read-only BFS that never writes the graph. The
    returned ``ForwardBlastResult`` structurally satisfies the gate's ``BlastRadiusVerdict`` Protocol
    (``incremental_blast`` + ``newly_reachable_jewels``). ``world_provider`` is an injection seam (a
    callable returning a WorldModel) so the wiring is testable without a spine on disk; absent it the
    default loads the engagement spine."""
    from framework.v2.worldmodel.attack_paths import (
        DEFAULT_ATTACK_EDGE_KINDS,
        DEFAULT_OBJECTIVE_KINDS,
    )
    from framework.v2.worldmodel.attacker import ATTACKER_ID
    from framework.v2.worldmodel.impact import ImpactModel, predict_action_blast_radius

    world = (world_provider or (lambda: _load_engagement_world(slug)))()
    if world is None:
        return None

    impact = ImpactModel.from_slug(slug)
    host = _host_of(target_url)
    target_node = f"host:{host}" if host else target_url
    opened = [(ATTACKER_ID, target_node)]
    obj_kinds = list(DEFAULT_OBJECTIVE_KINDS)
    edge_kinds = list(DEFAULT_ATTACK_EDGE_KINDS)

    def predict(_req):
        return predict_action_blast_radius(
            world, ATTACKER_ID, opened, obj_kinds, edge_kinds=edge_kinds, impact=impact)

    return predict


def build_offense_gate(
    *,
    slug: str,
    trust_root: Any,
    classify: Callable[[str], str],
    floor: str = DEFAULT_FLOOR,
    ceiling: str = DEFAULT_CEILING,
    killswitch: Any = None,
    actions_taken: int = 0,
    now: Any = None,
    destruction_authority: Any = None,
    is_consumed: Callable[[str], bool] | None = None,
    destruction_ledger: Any = None,
    base_dir: str = "",
    blast_ceiling: float | None = None,
    world_provider: Callable[[], Any] | None = None,
) -> Callable[..., GateVerdict]:
    """Return ``gate(tool_name, target_url, destructive=False, *, destruction_action=None,
    destruction_signed=None) -> GateVerdict`` wired to the REAL gates — including the I4 threshold-
    destruction conjunct for destructive actions.

    Offense-side only: imports ``framework`` lazily (this module never runs in the sovereign env).
    ``trust_root`` MUST be the governance TrustRoot — the CRUCIBLE authority is loaded verified,
    so a tampered scope/window/destructive-flag is rejected at load (the map's biggest fail-open).
    A ``None`` trust_root is refused: it would load the authority UNSIGNED, so it fails closed here.

    ``now`` MUST be a TRUSTED-caller value (a datetime, an epoch float, or None → real clock) — NEVER
    request/agent/attacker-derived data. It is load-bearing for the CRUCIBLE validity-window and the
    destruction dead-man's-switch: an in-window value passed for an out-of-window authority would honor it.
    The live wiring passes no ``now`` (→ None → real clock), and the per-call ``gate(...)`` has no ``now``
    argument, so the only path that sets it is the trusted caller here.

    Destructive actions are threshold-gated: pass a ``destruction_authority`` (immutable
    :class:`destruction_gate.DestructionAuthority` from deployment config) and, for the single-use leg,
    EITHER a ``destruction_ledger`` (a :class:`nonce_ledger.NonceLedger`) OR a bare ``is_consumed``
    check at build time, and per-call the ``destruction_action`` + ``destruction_signed`` quorum
    authorization. A destructive call missing the authority, the action/signed pair, AND both single-use
    inputs engages no threshold gate → ``conjunctive_decide`` DENIES it (fail-closed — an irreversible
    action never slips through on the two base gates alone).

    SINGLE-USE (O5 fix): a ``destruction_ledger`` routes the destruction conjunct through
    :func:`destruction_gate.consume_authorization` — the ATOMIC check-AND-burn whose ``O_EXCL`` marker
    create is the serialization point, so of N concurrent callers of ONE authorization exactly one wins
    (this is the surface a caller wiring destruction for REAL execution MUST use). A bare ``is_consumed``
    (no ledger) keeps the legacy PURE check (:func:`destruction_gate.authorize_destruction`), which
    carries the documented TOCTOU and is retained ONLY for a caller that owns its own atomic burn;
    prefer ``destruction_ledger``. If BOTH are given, the atomic ledger path wins.

    BLAST-RADIUS VETO (M4.2, defense-in-depth): a CONSEQUENTIAL (destructive) action is additionally
    refused — code ``blast_radius`` on the CRUCIBLE leg — when its predicted INCREMENTAL blast radius
    (the summed worth of the crown jewels it would NEWLY expose) exceeds a per-engagement ceiling.
    The ceiling is ``blast_ceiling`` if the trusted caller passes one, else the engagement's own
    ``targets/<slug>/impact.yaml`` (``blast_ceiling`` key); absent both the veto is DEFAULT-OFF and
    every decision is byte-identical to before. It is armed ONLY for a destructive action and ONLY
    when a world-model exists — a read (``destructive=False``) never resolves a ceiling, loads the
    graph or builds a predictor, so the read hot path is untouched. ADVISORY and REFUSE-ONLY: it can
    never promote, mints no FACT and is no oracle input; the predictor is a read-only forward query.
    ``world_provider`` (a callable returning the WorldModel) is an injection seam for testing; by
    default the engagement's signed spine at ``targets/<slug>/worldmodel-spine.json`` is projected.
    """
    if trust_root is None:
        raise ValueError(
            "build_offense_gate requires the governance trust_root: a None trust_root loads the "
            "CRUCIBLE authority UNSIGNED/unverified, so a tampered scope/window/destructive flag "
            "would pass the gate. Fail-closed refusal."
        )

    def gate(
        tool_name: str,
        target_url: str,
        destructive: bool = False,
        *,
        destruction_action: Any = None,
        destruction_signed: Any = None,
    ) -> GateVerdict:
        def crucible_authorize() -> CrucibleResult:
            # Lazy import keeps the module import-clean; only reachable in env-offense.
            from framework.v2.authority.gate import authorize_action, load_authority_for_gate
            from framework.v2.authority.models import ActionRequest

            authority = load_authority_for_gate(slug, trust_root=trust_root)  # verified, fail-closed
            # M-11.1 HARD PRECONDITION (arm site 3/3): a LIVE authority may ARM only when a verified,
            # owner-signed, evaluator-countersigned EvalOffenseAttestation covers this engagement on the
            # shared seam. Checked here so EVERY target-touching offense action on a LIVE authority re-verifies
            # it (defense-in-depth with the console launch gate + the engage trust-root pin). The offense plane
            # only VERIFIES the PUBLIC signed material against the pinned owner key (this gate's trust_root) —
            # it never imports the sovereign governor nor holds the owner key (FATAL-2). TWIN/STAGING are
            # byte-identical (no new check fires). Fail-closed: no attestation ⇒ DENY.
            _env = getattr(authority, "environment", None)
            if getattr(_env, "value", str(_env)) == "live":
                from .live.eval_attestation import (
                    owner_pubkeys_of,
                    verify_live_offense_attested,
                )
                _base = base_dir or os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"
                _ok_att, _att_reason = verify_live_offense_attested(
                    _base, engagement_slug=slug,
                    trusted_owner_pubkeys=owner_pubkeys_of(trust_root), now=_as_epoch(now))
                if not _ok_att:
                    return CrucibleResult(
                        allowed=False, reason=f"LIVE arm refused (M-11.1 hard precondition): {_att_reason}")
            req = ActionRequest(target=target_url, action_kind="offense", destructive=destructive)

            # M4.2 pre-action blast-radius VETO — defense-in-depth, consulted BEFORE a
            # CONSEQUENTIAL (destructive/state-changing) action ONLY. A read (destructive=False)
            # never resolves a ceiling, never loads the world-model and never builds a predictor,
            # so the read hot path pays NOTHING and stays byte-identical. The veto is armed only
            # when a per-engagement ceiling is configured AND a world-model exists to reason over;
            # otherwise both kwargs are None and authorize_action is byte-identical to before.
            blast_fn = None
            blast_ceil = None
            if destructive:
                blast_ceil = _effective_blast_ceiling(slug, blast_ceiling)
                if blast_ceil is not None:
                    blast_fn = _build_blast_radius_fn(slug, target_url, world_provider)
                    if blast_fn is None:
                        blast_ceil = None   # no world-model → leave the veto disarmed (not a refusal)

            # 1b / adversary fix D: wire the witness-quorum VETO (gate conjunct 6c) UNCONDITIONALLY from the
            # operator posture/policy config — INDEPENDENT of any grant. The veto must EXIST whether or not a
            # grant is present (otherwise 6c would only exist when a grant bypasses it, which is unsound); the
            # grant later injects ONLY the ACK that lifts it, never the fn. Absent an operator policy (env
            # unset ⇒ DISABLED), the predicate is inapplicable ⇒ 6c is a no-op ⇒ byte-identical to before.
            from framework.v2.authority.witness_quorum_gate import witness_quorum_predicate
            from framework.v2.veracity.witness_quorum import load_quorum_config
            wq_fn = witness_quorum_predicate(load_quorum_config())

            # 2e: a VALID, in-scope EvalCapabilityGrant for THIS engagement/target injects ONLY the gate ACKS
            # (never a witness_quorum_fn — fix D). Absent/expired/revoked ⇒ no acks ⇒ the 6b/6c vetoes ENFORCE
            # (fail-closed). A grant can lift ONLY the CLOSED-ENUM 6b/6c vetoes; the never-liftable floors
            # (egress / m-of-n destruction quorum / GET-only write) are separate conjuncts it never feeds.
            _grant_base = base_dir or os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"
            wq_ack = None
            bl_ack = None
            try:
                from .live.eval_capability_grant import (
                    grant_overrides,
                    owner_pubkeys_of as _grant_owner_pubkeys_of,
                    verify_eval_capability_grant,
                )
                _gverdict = verify_eval_capability_grant(
                    _grant_base, engagement_slug=slug, target=target_url,
                    trusted_owner_pubkeys=_grant_owner_pubkeys_of(trust_root),
                    actions_covered=None)   # FIX C2/F: no durable spine-anchored count this slice ⇒ budget off
                if _gverdict.granted:
                    wq_ack, bl_ack, _caps = grant_overrides(
                        _gverdict, base_dir=_grant_base, engagement_slug=slug)
            except Exception:  # noqa: BLE001 — any grant-verify error ⇒ NO acks ⇒ the vetoes enforce (fail-closed)
                wq_ack = None
                bl_ack = None

            decision = authorize_action(
                authority, req, killswitch=killswitch, actions_taken=actions_taken,
                now=_as_datetime(now),          # CRUCIBLE leg wants a datetime (or None)
                blast_radius_fn=blast_fn, blast_ceiling=blast_ceil, blast_radius_ack=bl_ack,
                witness_quorum_fn=wq_fn, witness_quorum_ack=wq_ack,
            )
            return CrucibleResult(allowed=bool(decision.allowed), reason=decision.reason)

        def warden_decide() -> ToolDecision:
            return decide_tool(tool_name, classify=classify, floor=floor, ceiling=ceiling)

        # Wire the real threshold-destruction thunk ONLY when the full context is present; otherwise
        # a destructive action reaches conjunctive_decide with no gate → DENY (fail-closed). The
        # single-use leg needs EITHER an atomic ledger (preferred, real execution) OR a bare is_consumed.
        destruction_authorize = None
        if destructive and destruction_authority is not None and destruction_action is not None \
                and destruction_signed is not None \
                and (destruction_ledger is not None or is_consumed is not None):
            from .destruction_gate import authorize_destruction, consume_authorization

            # Cross-bind the two halves: the quorum-authorized action MUST be the SAME target and
            # engagement the CRUCIBLE half is scoping (and the executor will act on). Without this a
            # single ALLOW could pair an in-envelope scope check for target A with a quorum that only
            # authorized destruction of target B. Fail-closed on any divergence.
            if (getattr(destruction_action, "target", None) != target_url
                    or getattr(destruction_action, "engagement_slug", None) != slug):
                def destruction_authorize() -> Any:  # type: ignore[misc]
                    return DestructionOutcome(
                        authorized=False,
                        reason=(f"authorization target/engagement "
                                f"({getattr(destruction_action, 'engagement_slug', None)!r}/"
                                f"{getattr(destruction_action, 'target', None)!r}) does not match the "
                                f"gate ({slug!r}/{target_url!r})"),
                    )
            elif destruction_ledger is not None:
                # REAL execution: ATOMIC check-AND-burn via the durable NonceLedger — the O_EXCL create
                # is the serialization point, so concurrent callers of ONE authorization → exactly one
                # wins and every replay is DENIED (closes the O5 check-only TOCTOU).
                def destruction_authorize() -> Any:  # type: ignore[misc]
                    return consume_authorization(
                        destruction_action, destruction_signed,
                        authority=destruction_authority,
                        now=_as_epoch(now),      # destruction leg wants an epoch float
                        ledger=destruction_ledger,
                    )
            else:
                # Back-compat: a caller supplying only a pure is_consumed (no ledger) keeps the
                # check-only decision. This leg carries the documented TOCTOU — such a caller MUST own
                # its own atomic burn at/after execution (as build_destruction_quorum does).
                def destruction_authorize() -> Any:  # type: ignore[misc]
                    return authorize_destruction(
                        destruction_action, destruction_signed,
                        authority=destruction_authority,
                        now=_as_epoch(now),      # destruction leg wants an epoch float
                        is_consumed=is_consumed,
                    )

        # Emit-only telemetry (W6-3): COUNT a DENY into the gate-denial metric. record_gate_verdict
        # returns the verdict UNCHANGED and never raises, so the authorization result is untouched.
        return record_gate_verdict(conjunctive_decide(
            crucible_authorize=crucible_authorize,
            warden_decide=warden_decide,
            destructive=destructive,
            destruction_authorize=destruction_authorize,
        ))

    return gate
