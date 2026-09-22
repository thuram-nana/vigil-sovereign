"""
scanner.stored_xss — STORED / second-order XSS confirmed by EXECUTION in a real browser.

Reflected DOM-XSS (``scanner.browser_xss``) injects a payload into ONE request and
observes it execute in the SAME response. Stored (a.k.a. second-order / persistent)
XSS is different in kind: the attacker WRITES a payload at surface **A** (a comment,
a profile field, a support ticket — a *state-changing* request), and it executes
later when a DIFFERENT surface **B** (an admin queue, a public thread, a preview
page) RENDERS the persisted value. The write and the execution are two requests, on
two surfaces, possibly by two identities.

This module proves it end to end, with the same unforgeable signal
``scanner.browser_xss`` uses:

  1. mint a UNIQUE execution canary per ``(write-surface A, render-surface B,
     payload)`` — so the canary cannot pre-exist in the target and a hit is
     attributable to THIS write;
  2. WRITE the payload at surface A through the caller-supplied **gated write**
     (the Wave-0.3 per-action approval path: an owner-signed, single-use, action-
     bound token authorises the one state-changing POST). This module holds NO key
     and issues NO write itself — a run without an approval authority (no
     ``--approve-mutations`` / no provisioned owner authority) supplies **no** gated
     write, and then this module writes NOTHING and mints NOTHING. That is
     GET-only fail-closed: the absence of a write path yields **no stored-XSS FACT**,
     never a false CLEAN (we could not test, so we do not clear the surface);
  3. navigate render-surface B in a real headless DOM (``scanner.cdp``) with the
     ``__crucible_xss`` binding registered — the SAME binding ``browser_xss`` uses,
     which only the driver registers, so a call carrying the canary is unforgeable
     proof the injected script ran;
  4. fire the ``dom_execution`` oracle (``verify.oracles.dom_execution_oracle``,
     ``OracleKind.DOM_EXECUTION``, conf 0.97) **only** when the SAME canary surfaces
     in a ``Runtime.bindingCalled`` EXECUTION callback on B — i.e. actual JavaScript
     execution, **not** the canary merely appearing in B's HTML as text (a
     textContent-escaped store, a reflecting-but-inert render, or an echo with no
     script all produce no binding call and correctly do not fire).

The confirmation is a ``verify.FindingContext`` (``from_dom_execution``, bug_class
``stored_xss``), so a browser-confirmed stored-XSS carries the same re-verifiable
certificate every other CRUCIBLE finding does — the retained ``oracle_context``
re-fires the pure oracle offline. NO new ``OracleKind`` is introduced: this reuses
``DOM_EXECUTION``, which is already in the frozen ``_ALL_ORACLES``.

Soundness is total (a fire means the SAME canary VIGIL wrote at A executed on B);
**coverage** is the limit — an ``(A, B)`` pair VIGIL never crawls stays a LEAD, never
a false negative. Requires a browser (``scanner.cdp.cdp_available``); with none, the
caller skips the dynamic path — a browser check never guesses.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from ..verify.adapter import FindingContext
from .cdp import CdpBrowser, CdpError

# The binding a payload calls on execution — the SAME one ``browser_xss`` registers.
# Only the driver registers it, so a call carrying the canary is unforgeable proof the
# injected script ran on the render surface.
_BINDING = "__crucible_xss"

# A GatedWrite performs the ONE state-changing write at surface A and returns True iff
# the write was AUTHORISED (per-action approval granted) AND performed. It routes
# through the Wave-0.3 approval broker OUTSIDE this module — the scanner stays keyless.
# ``None`` (no approval authority / no --approve-mutations) means GET-only fail-closed:
# this module then writes nothing and mints nothing (never a false CLEAN).
GatedWrite = Callable[[str, str], bool]  # (write_surface_A, payload) -> performed?

# Execution payloads — identical in shape to ``browser_xss``: each renders the canary
# and, if it reaches an executable position on B, calls the binding. Event-handler
# payloads execute even when inserted via innerHTML (where a raw <script> would not);
# the breakout and javascript:-URI forms cover attribute and URL-sink render contexts.
_PAYLOAD_TEMPLATES: tuple[str, ...] = (
    "<img src onerror=window.{b}('{c}')>",
    "<svg onload=window.{b}('{c}')>",
    "\"><img src onerror=window.{b}('{c}')>",
    "'><svg onload=window.{b}('{c}')>",
    "</script><img src onerror=window.{b}('{c}')>",
    "javascript:window.{b}('{c}')",
)


@dataclass
class StoredXssResult:
    """One stored-XSS attempt: the payload, the write/render surfaces, the unique
    canary, whether the gated write was performed, whether the browser RAN it on the
    render surface, and the re-verifiable oracle context."""

    payload: str
    canary: str
    write_surface: str
    render_surface: str
    written: bool
    executed: bool
    context: FindingContext
    bug_class: str = "stored_xss"


def _canary(write_surface: str, render_surface: str, template: str) -> str:
    """A UNIQUE execution canary per ``(A, B, payload)``.

    The ``(A|B|template)`` digest makes it deterministic-per-pair (so a re-run over the
    same surfaces is attributable), and the fresh ``token_hex`` makes it unforgeable
    and impossible to pre-exist in the target. Kept >6 chars so the oracle accepts it
    as a reliable marker."""
    digest = hashlib.sha256(f"{write_surface}|{render_surface}|{template}".encode("utf-8")).hexdigest()[:8]
    return f"sxss{digest}{secrets.token_hex(4)}"


def confirm_stored_xss(
    write_surface: str,
    render_surface: str,
    *,
    gated_write: Optional[GatedWrite],
    browser: CdpBrowser | None = None,
    payloads: tuple[str, ...] = _PAYLOAD_TEMPLATES,
    settle: float = 0.8,
) -> list[StoredXssResult]:
    """Prove stored XSS from write-surface ``A`` to render-surface ``B``.

    For each payload: mint a unique canary, WRITE it at ``write_surface`` via the
    gated (owner-approved, single-use, action-bound) ``gated_write``, then render
    ``render_surface`` in a real headless DOM and observe whether the injected script
    EXECUTED (called the ``__crucible_xss`` binding with that canary).

    ``result.executed`` (and the ``dom_execution`` oracle over ``result.context``) is
    True only when the browser actually ran the injected script on B — never on mere
    reflection/echo. A shared ``browser`` may be passed to amortise launch cost;
    otherwise one is started and torn down here.

    **Fail-closed:** ``gated_write is None`` (no approval authority / GET-only default)
    ⇒ this returns ``[]`` immediately — nothing is written and nothing is minted. That
    is deliberately an EMPTY result (we could not perform the write, so the surface is
    untested), NOT a CLEAN verdict. A gated_write that returns False for a specific
    payload (the per-action approval was refused) records ``written=False`` and an
    empty, non-firing context for that payload — again no FACT, never a CLEAN.

    Raises :class:`CdpError` only if no browser is available (the caller then skips)."""
    if gated_write is None:
        # GET-only fail-closed: no write authority provisioned ⇒ we cannot perform the
        # state-changing write at A, so there is nothing to render at B. Return an empty
        # result set — no FACT, and crucially NOT a CLEAN (an untested surface is not a
        # clear one). The caller keeps the (A,B) pair a LEAD / INCONCLUSIVE.
        return []

    own = browser is None
    br = browser or CdpBrowser().start()
    results: list[StoredXssResult] = []
    try:
        sess = br.session()
        sess.add_binding(_BINDING)
        for template in payloads:
            canary = _canary(write_surface, render_surface, template)
            payload = template.format(b=_BINDING, c=canary)
            # (1) WRITE at surface A via the gated per-action approval path. A False return
            #     means the approval was refused / the write did not happen ⇒ no state
            #     change ⇒ no FACT (never a false CLEAN).
            try:
                written = bool(gated_write(write_surface, payload))
            except Exception:  # noqa: BLE001 — a write failure is fail-closed (no state change, no FACT)
                written = False
            if not written:
                results.append(StoredXssResult(
                    payload=payload,
                    canary=canary,
                    write_surface=write_surface,
                    render_surface=render_surface,
                    written=False,
                    executed=False,
                    context=FindingContext.from_dom_execution([], canary, bug_class="stored_xss"),
                ))
                continue
            # (2) RENDER surface B in a real CDP session and observe EXECUTION. navigate()
            #     clears the event buffer, so binding_calls reflects this render of B.
            try:
                sess.navigate(render_surface, settle=settle)
                calls = sess.binding_calls(_BINDING)
            except CdpError:
                calls = []
            ctx = FindingContext.from_dom_execution(calls, canary, bug_class="stored_xss")
            results.append(StoredXssResult(
                payload=payload,
                canary=canary,
                write_surface=write_surface,
                render_surface=render_surface,
                written=True,
                executed=any(canary in c for c in calls),
                context=ctx,
            ))
    finally:
        if own:
            br.stop()
    return results


def stored_xss_finding(result: StoredXssResult, *, check_id: str = "") -> dict:
    """Build the finding dict (carrying the retained ``oracle_context``) for a
    stored-XSS result, ready for the STD-WIRING admission choke
    (``verdict.admit(\"stored_xss.dom_execution\", ...)`` →
    ``oracle_adapter.certify_admitted(provenance=\"live_redrive\")``).

    The ``oracle_context`` is the pure, re-verifiable bundle the ``dom_execution``
    oracle re-fires over offline; ``framework.v2 verify`` re-runs it and
    ``reverify.matches_claim`` rejects any tamper (a mutated canary no longer matches
    the binding call)."""
    return {
        "check_id": check_id or f"stored_xss:{result.write_surface}->{result.render_surface}",
        "bug_class": "stored_xss",
        "title": "Stored / second-order XSS (browser-confirmed execution on the render surface)",
        "severity": "High",
        "surface": f"write:{result.write_surface} render:{result.render_surface}",
        "summary": (
            "a payload written at one surface executed in a real browser DOM when a "
            "different surface rendered the persisted value"
        ),
        "oracle_context": result.context.to_verifier_context(),
    }
