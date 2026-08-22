"""vigil_core.doctor — the ONE doctor check registry, shared by BOTH trust planes.

`vigil doctor` (the offense / integration plane) and `sigil doctor` (the sovereign plane) used to be two
disjoint self-checks with no shared code, no shared idea of what "a failed control" means, and — for
`sigil doctor` — an exit code `make smoke` threw away with `|| true`. This module is the single source of
truth they now share:

  * ``REQUIRED_CONTROLS`` — the ordered registry of security-posture controls that are REQUIRED under the
    opt-in production posture, each with the state(s) that count as engaged and the one-line requirement
    text used in an operator refusal. Both doctors read the SAME spec, so they can never drift on which
    controls matter or what "good" looks like.
  * ``evaluate(...)`` — the shared exit decision for that posture gate: fail-closed, opt-in (inert unless
    the production posture is armed), returning a JSON-safe verdict both entry points render identically.
  * ``overall_ok(...)`` — the generic "did every REQUIRED check pass?" roll-up each entry point uses to
    turn its own registry of checks (prerequisites, sovereign self-checks, the posture gate) into ONE
    honest exit code — so neither doctor can silently discard a failure again.

PURE STDLIB, namespace-pure: like ``vigil_core.posture`` (which it builds on) this module imports nothing
from ``framework`` / ``strix`` / ``sigil`` / ``vigil_integration``, so either trust domain may import it
without dragging a dependency across the two-env boundary (FATAL-2). The plane-specific PROBING (docker,
systemctl, the on-disk sovereign vault, the framework entitlement root) stays in the caller; only the
registry and the decision live here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

from .posture import production_posture

# ── the shared production-posture control registry ────────────────────────────────────────────────────
# (control, good-states, requirement text). ORDER is the plan's five conditions plus W10-7's legacy-token.
# Each `good_states` set is exactly the state(s) a doctor's posture probe reports when the control is
# actually ENGAGED. This is the SINGLE source of truth: `vigil_integration.doctor` imports it as
# `_PRODUCTION_GATE`, and `sigil doctor` reads it to render + gate on the same controls — so the two entry
# points can never disagree on which controls are required or what counts as satisfied.
REQUIRED_CONTROLS: "tuple[tuple[str, frozenset, str], ...]" = (
    ("vault", frozenset({"SEALED"}),
     "secrets must be SEALED at rest — run `sigil vault provision` (keys rest as plaintext until then)"),
    ("sovereignty", frozenset({"AIR_GAPPED", "SOVEREIGN_CLOUD", "TRUSTED_CLOUD"}),
     ("the sovereignty tier must be raised OFF PERMISSIVE — set CRUCIBLE_SOVEREIGNTY_TIER "
      "(AIR_GAPPED / SOVEREIGN_CLOUD / TRUSTED_CLOUD)")),
    ("entitlement", frozenset({"ACTIVE"}),
     ("capability-entitlement enforcement must be ACTIVE — provision the trust root, or set "
      "CRUCIBLE_ENTITLEMENT_ENFORCED=1")),
    ("backups", frozenset({"ON"}),
     ("the backup/reprove timers must be ENABLED — install + `systemctl --user enable --now` the "
      "infra/systemd/*.timer units")),
    ("charter", frozenset({"PRESENT"}),
     ("a signed charter + EngagementAuthority must be PRESENT — provision one under targets/ and pin it "
      "with VIGIL_ENGAGEMENT")),
    ("legacy-owner-token", frozenset({"DISABLED"}),
     ("the legacy embedded shared owner token must be DISABLED — set SIGIL_LEGACY_OWNER_TOKEN=0 so the "
      "cockpit requires per-user proof-of-possession auth (the fail-open shared token is refused; the sigil "
      "server also refuses it at runtime under this posture)")),
)


def _state_of(raw) -> "tuple[str, str]":
    """Normalise a caller-supplied control value into ``(state, detail)``. Accepts a ``(state, detail)``
    tuple, a ``{"state", "detail"}`` mapping (a `_collect_posture` entry), a bare state string, or None
    (⇒ the fail-closed UNKNOWN)."""
    if raw is None:
        return "UNKNOWN", ""
    if isinstance(raw, Mapping):
        return str(raw.get("state", "UNKNOWN")), str(raw.get("detail", ""))
    if isinstance(raw, (tuple, list)):
        state = str(raw[0]) if raw else "UNKNOWN"
        detail = str(raw[1]) if len(raw) > 1 else ""
        return state, detail
    return str(raw), ""


def evaluate(control_states: Mapping[str, object], *, armed: "Optional[bool]" = None) -> dict:
    """The shared PRODUCTION-posture gate decision, keyed off ``REQUIRED_CONTROLS``.

    ``control_states`` maps each control id to its current value — a ``(state, detail)`` tuple, a
    ``{"state","detail"}`` mapping, or a bare state string. ``armed`` overrides whether the gate is live;
    when None it is read from the environment via ``vigil_core.posture.production_posture`` (the single
    source of truth), so both trust planes arm identically.

    Returns a JSON-safe dict::

        {armed, posture, ok, controls:[{control,state,detail,required,requirement,met}], unmet:[...]}

    FAIL-CLOSED: a control absent from ``control_states``, or reporting any state outside its required
    good-set (``UNKNOWN`` included), is UNMET. OPT-IN: when NOT armed the gate is inert — ``ok`` is True and
    ``unmet`` is empty regardless of state, so a start path can gate on ``not result['ok']`` and stay
    byte-identical to before when the posture is unset. Never raises."""
    posture_raw = production_posture()
    is_armed = (posture_raw is not None) if armed is None else bool(armed)
    controls: list = []
    unmet: list = []
    for control, good, requirement in REQUIRED_CONTROLS:
        state, detail = _state_of(control_states.get(control))
        met = state in good
        entry = {"control": control, "state": state, "detail": detail,
                 "required": sorted(good), "requirement": requirement, "met": met}
        controls.append(entry)
        if not met:
            unmet.append(entry)
    ok = (not is_armed) or (not unmet)
    return {"armed": is_armed, "posture": posture_raw, "ok": ok,
            "controls": controls, "unmet": (unmet if is_armed else [])}


@dataclass(frozen=True)
class Check:
    """One registry check result: ``id`` names the control, ``ok`` is its pass/fail, ``required`` marks it
    as exit-flipping (a failed REQUIRED check turns the doctor's exit non-zero; an advisory one never
    does), and ``state`` / ``detail`` carry the human line. Used by each entry point to build ONE honest
    exit code from its own mix of checks."""
    id: str
    ok: bool
    required: bool = True
    state: str = ""
    detail: str = ""


def overall_ok(checks: "Iterable[Check]") -> bool:
    """True IFF every REQUIRED check passed. Advisory checks (``required=False``) never flip the result —
    so an optional dependency being absent (no kernel binary, no keyring, an unreachable Qdrant) is
    reported but does NOT fail the doctor, while a real required-control failure does. The one roll-up both
    entry points use, so 'stop discarding exit codes' means the same thing on both sides."""
    return all(c.ok for c in checks if c.required)
