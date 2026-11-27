"""engagement_flow - the PURE server-side state machine behind the chat-driven engagement control surface.

A customer drives a whole engagement from ONE box: pick a verified domain (verifying it via DNS / well-known if
none is verified yet), launch an assessment after an EXPLICIT spend confirmation, watch step-by-step progress,
and steer / pause / resume / cancel the running run - all without leaving the box. This module is the per-(org,
session) state machine that decides, from the org's OWN live ownership + launch reads and ONE classified signal,
which EXISTING sovereign provisioner action the next transition should call. It MINTS nothing, launches nothing
and holds no key: it only NAMES the next step; the provisioner (``customer_flow_step``) is the hands that call
the already-built, already-gated actions (``customer_assets``, ``target_challenge``, ``target_verify``,
``launch_reserve``, ``launch_start``, ``launch_instruct``, ``launch_pause`` / ``launch_resume`` /
``launch_cancel``, ``launch_activity``).

The machine moves over these states, in order:

    need_domain -> need_verify -> verifying -> ready -> awaiting_confirm -> reserving -> running -> done

  * need_domain      - no host chosen yet; the box asks for a domain (and may show the org's assets).
  * need_verify      - a host is chosen but not owner-proven (unregistered or an expired proof): the next step
                       issues an ownership challenge.
  * verifying        - a challenge is outstanding; the customer publishes it and then asks to verify, which is
                       gated on the EXPLICIT "I am authorized to test this asset" affirmation (never inferred).
  * ready            - the host is owner-proven and no run is active: a launch may be proposed.
  * awaiting_confirm - a launch was asked on a verified host; the box shows the SERVER-decided depth/product and
                       waits for an EXPLICIT spend confirm before any credit is reserved.
  * reserving        - the confirmed launch reserves credits (``launch_reserve``) and keeps the signed lease, then
                       starts it (``launch_start``). The lease is persisted between the two by the existing
                       ``customer_launches.remember`` / ``forget`` (``launch_reserve`` keeps it, ``launch_start``
                       forgets it) - never re-invented here.
  * running          - the engagement is live; its step-by-step activity feed is the existing ``launch_activity``
                       read, and steer / pause / resume / cancel forward to the existing controls.
  * done             - the run finished.

Money / safety doctrine, enforced here BY CONSTRUCTION (not by the model's good behaviour):
  * NEVER reserve on the typed command alone. A launch intent on a verified host advances to AWAITING_CONFIRM
    and the provisioner surfaces the server-decided depth/product (``_launch_choices`` - a depth, never an
    amount); only an EXPLICIT ``confirm`` signal advances to the reserve-then-start transition.
  * The "I am authorized to test this asset" affirmation on verify is REQUIRED and never inferred: :func:`decide`
    withholds the verify transition until the signal carries an explicit ``authorized is True``; the provisioner
    passes it straight to ``target_verify`` (which fail-closes without it).
  * A control (steer / pause / resume / cancel) is forwarded ONLY when the box's current host matches an ACTIVE
    lease the session org holds - the host↔lease match is validated before any forward (the provisioner reads the
    lease from that matched launch row).

FATAL-2: sovereign-only, pure-stdlib, ``assert_no_offense`` at import. It imports no offense plane and no mint
primitive; the live-activity feed is reached only through the sovereign ``launch_activity`` read the provisioner
already exposes. It is a DECISION module: :func:`derive_state` and :func:`decide` are pure and side-effect-free.
"""
from __future__ import annotations

from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

# The ordered flow states (a tuple so a test can pin the exact set AND order; a reorder or a dropped state reds it).
NEED_DOMAIN = "need_domain"
NEED_VERIFY = "need_verify"
VERIFYING = "verifying"
READY = "ready"
AWAITING_CONFIRM = "awaiting_confirm"
RESERVING = "reserving"
RUNNING = "running"
DONE = "done"
STATES = (NEED_DOMAIN, NEED_VERIFY, VERIFYING, READY, AWAITING_CONFIRM, RESERVING, RUNNING, DONE)

#: The allowlisted control intents the flow forwards to the already-gated launch controls (host↔lease matched).
CONTROL_INTENTS = ("steer", "pause", "resume", "cancel")
#: The intents that ask only to WATCH (a pure read of the live activity feed).
WATCH_INTENTS = ("status", "watch")

#: The actions :func:`decide` may name - each maps 1:1 to an EXISTING provisioner action the provisioner calls,
#: except "reserve_start" (the reserve-then-start pair run under one explicit confirm) and "none" (no call).
ACTIONS = ("none", "assets", "challenge", "verify", "reserve_start", "activity",
           "instruct", "pause", "resume", "cancel")


def _asset_status(assets: "Optional[list]", host: str) -> str:
    """The ownership status (``verified`` / ``pending`` / ``expired``) of ``host`` in the org's own assets read, or
    ``""`` when the host is not among the org's assets at all. Pure lookup; the rows are the org's own
    (``customer_assets`` is already tenant-scoped), so there is no cross-tenant leg here."""
    for a in assets or []:
        if isinstance(a, dict) and str(a.get("host") or "").strip().lower() == host:
            return str(a.get("status") or "")
    return ""


def _active_launch(launches: "Optional[dict]", host: str) -> "Optional[dict]":
    """The org's ACTIVE launch row (reserved / running / paused) for ``host`` from the launches projection, or
    None. The row carries the signed ``lease`` only for a member who may run assessments (the projection decides
    that), so a control the requester may not drive simply has no lease to forward."""
    for row in (launches or {}).get("launches", []) or []:
        if isinstance(row, dict) and str(row.get("host") or "").strip().lower() == host:
            return row
    return None


def _has_finished(launches: "Optional[dict]", host: str) -> bool:
    for row in (launches or {}).get("finished", []) or []:
        if isinstance(row, dict) and str(row.get("host") or "").strip().lower() == host:
            return True
    return False


def derive_state(assets: "Optional[list]", launches: "Optional[dict]", host: str) -> dict:
    """The STABLE state of the session's engagement for ``host``, read from the org's OWN live ownership
    (``assets``) and launch (``launches``) projections. PURE: no key, no I/O, no mutation. ``host`` empty ⇒
    ``need_domain``. Returns ``{state, host, status, active, finished}`` where ``active`` is the org's active
    launch row for the host (or None) and ``status`` is its ownership status."""
    h = str(host or "").strip().lower()
    if not h:
        return {"state": NEED_DOMAIN, "host": "", "status": "", "active": None, "finished": False}
    status = _asset_status(assets, h)
    active = _active_launch(launches, h)
    finished = _has_finished(launches, h)
    if status == "verified":
        if active is not None and str(active.get("state") or "") in ("running", "paused"):
            state = RUNNING
        elif active is not None:                 # a reserved-but-not-started lease is ready to start
            state = READY
        elif finished:
            state = DONE
        else:
            state = READY
    elif status == "pending":
        state = VERIFYING                        # a challenge is outstanding; publish it, then verify
    else:                                        # "expired" or the host is not registered at all
        state = NEED_VERIFY
    return {"state": state, "host": h, "status": status, "active": active, "finished": finished}


def decide(signal: dict, derived: dict) -> dict:
    """Decide the ONE next transition for ``signal`` given the ``derived`` state. PURE: it executes nothing and
    mints nothing - it NAMES the existing provisioner action the provisioner should call, or BLOCKS with a short
    reason and what the box must collect next. Returns ``{action, state, blocked, need}``:

      * ``action`` - one of :data:`ACTIONS`; the existing provisioner action the transition calls.
      * ``state``  - the state the box should show (the resulting state, or the blocked current state).
      * ``blocked``- a short reason when the transition cannot proceed, else None.
      * ``need``   - what the box must collect next (``domain`` / ``verify`` / ``authorized`` / ``confirm`` /
        ``running_launch``), else None.

    The authorized affirmation and the spend confirm are read from the signal EXPLICITLY (``is True``), never
    inferred from text, and NEVER does a launch intent alone reach a reserve: it stops at ``awaiting_confirm``."""
    intent = str(signal.get("intent") or "")
    state = str(derived.get("state") or NEED_DOMAIN)
    host = str(derived.get("host") or "")
    verified = str(derived.get("status") or "") == "verified"
    active = derived.get("active")
    active_state = str((active or {}).get("state") or "")

    if intent in WATCH_INTENTS:
        # a pure read of the live activity feed when a run is live; otherwise nothing to show (not an error).
        return {"action": "activity" if active is not None else "none", "state": state,
                "blocked": None, "need": None}

    if intent == "verify":
        if not host:
            return {"action": "assets", "state": NEED_DOMAIN, "blocked": "name a domain to verify",
                    "need": "domain"}
        if verified:
            return {"action": "none", "state": READY, "blocked": None, "need": None}   # already proven
        # With a proof method chosen, this is the VERIFY verdict - gated on the explicit authorization affirmation
        # (never inferred). Without a method, this is the challenge issuance (what to publish).
        if str(signal.get("method") or ""):
            if signal.get("authorized") is not True:
                return {"action": "none", "state": VERIFYING,
                        "blocked": "confirm you are authorized to test this asset", "need": "authorized"}
            return {"action": "verify", "state": READY, "blocked": None, "need": None}
        return {"action": "challenge", "state": VERIFYING, "blocked": None, "need": None}

    if intent == "launch":
        if not host:
            return {"action": "assets", "state": NEED_DOMAIN, "blocked": "name a domain to assess",
                    "need": "domain"}
        if not verified:
            return {"action": "none", "state": NEED_VERIFY,
                    "blocked": "verify ownership of this domain before launching", "need": "verify"}
        if active is not None and active_state in ("running", "paused"):
            return {"action": "none", "state": RUNNING,
                    "blocked": "an assessment is already running on this host", "need": None}
        if signal.get("confirm") is not True:
            # NEVER reserve on the typed command alone: stop at awaiting_confirm, carrying the server-decided
            # depth/product for the box to show, until the customer explicitly confirms the spend.
            return {"action": "none", "state": AWAITING_CONFIRM,
                    "blocked": "confirm the assessment before it reserves credits", "need": "confirm"}
        return {"action": "reserve_start", "state": RESERVING, "blocked": None, "need": None}

    if intent in CONTROL_INTENTS:
        # a control is forwarded ONLY when the box's host has an ACTIVE lease for this org (the host↔lease match);
        # the provisioner reads the signed lease from that matched row and forwards to the already-gated control.
        if active is None:
            return {"action": "none", "state": state,
                    "blocked": "no active assessment on this host to control", "need": "running_launch"}
        action = {"steer": "instruct", "pause": "pause", "resume": "resume", "cancel": "cancel"}[intent]
        return {"action": action, "state": state, "blocked": None, "need": None}

    # Anything else - including an advice intent that somehow reached the flow - takes NO action here. Advice is
    # the command layer's read-only path (customer_assistant_ask); the flow never launches off a non-action intent.
    return {"action": "none", "state": state, "blocked": None, "need": None}


def resolve_product_id(choices: "Optional[list]", *, product_id: str = "", depth: str = "") -> str:
    """The launch PRODUCT the reserve should use, resolved from what the SERVER offers (``_launch_choices`` →
    ``[{product_id, depth}]``): an explicit ``product_id`` the server offers wins; else the first offered product
    whose ``depth`` matches the requested ``depth``; else ``""`` (the server-decided default launch). A product
    id or depth the server does NOT offer resolves to ``""`` rather than being passed through - the customer names
    a product/depth the server offers, never an amount, and an unoffered one is never silently reserved."""
    offered = [c for c in (choices or []) if isinstance(c, dict)]
    pid = str(product_id or "").strip()
    if pid and any(str(c.get("product_id") or "") == pid for c in offered):
        return pid
    d = str(depth or "").strip().lower()
    if d:
        for c in offered:
            if str(c.get("depth") or "").strip().lower() == d:
                return str(c.get("product_id") or "")
    return ""


def offered_depth(choices: "Optional[list]", product_id: str) -> "Optional[str]":
    """The depth the server offers for ``product_id`` (so the box can show it in the awaiting_confirm step), or
    None when the product is not offered."""
    for c in choices or []:
        if isinstance(c, dict) and str(c.get("product_id") or "") == str(product_id or ""):
            d = c.get("depth")
            return str(d) if d is not None else None
    return None
