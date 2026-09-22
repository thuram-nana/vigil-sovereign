"""
Stored / second-order XSS confirmation (Wave 2.1) — result-handling + oracle wiring
without a browser, plus the red-pen non-fire fixtures.

The live browser path is skip-gated on a real Chromium (see
``test_stored_xss_browser.py``); this file drives ``scanner.stored_xss`` with a STUB
browser + a fake gated-write seam so the write→render→execution logic and the
deterministic ``dom_execution`` oracle are verified deterministically. It proves:

  * a FACT on a planted stored-XSS (a payload written at A that EXECUTES on B);
  * SILENCE on the benign twin (a textContent/escaped store) and the red-pen
    fixtures (a reflecting-but-inert B, an echo with no script) — no binding call,
    so the oracle correctly does not fire;
  * GET-only fail-closed: no gated write ⇒ nothing written, nothing minted, and
    crucially NOT a CLEAN;
  * the retained ``oracle_context`` re-fires and round-trips (a re-verifiable
    certificate), and a tampered canary no longer confirms.
"""

from __future__ import annotations

import re

import pytest

from framework.v2.scanner.stored_xss import (
    StoredXssResult,
    _BINDING,
    confirm_stored_xss,
    stored_xss_finding,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES, OracleVerifier, normalize_bug_class

_CANARY_RE = re.compile(r"sxss[0-9a-f]{16}")


# ---------------------------------------------------------------------------
# Stub browser + a fake gated write. The gated write PERSISTS the payload; the
# stub session models the render surface B: only a 'execute' surface fires the
# binding (the persisted payload reaches an executable position); every other
# render mode (escape / reflect-inert / text) produces NO binding call.
# ---------------------------------------------------------------------------


class _Store(dict):
    last: str = ""


def _gated_write(store: _Store, *, allow: bool = True):
    def gw(url: str, payload: str) -> bool:
        if not allow:
            return False
        store[url] = payload
        store.last = payload
        return True
    return gw


class _StubSession:
    """Models render-surface B. ``mode='execute'`` = the persisted payload reaches
    an executable position and calls the binding with its canary; anything else
    (escape / reflect / text) = the value is inert, so no binding call."""

    def __init__(self, store: _Store, mode: str) -> None:
        self._store = store
        self._mode = mode
        self.bound: list[str] = []

    def add_binding(self, name: str) -> None:
        self.bound.append(name)

    def navigate(self, url: str, *, settle: float = 0.4, timeout: float = 15.0) -> None:
        return None

    def binding_calls(self, name: str) -> list[str]:
        if self._mode != "execute":
            return []
        m = _CANARY_RE.search(self._store.last)
        return [m.group(0)] if m else []


class _StubBrowser:
    def __init__(self, store: _Store, mode: str) -> None:
        self._store = store
        self._mode = mode

    def start(self) -> "_StubBrowser":
        return self

    def session(self) -> _StubSession:
        return _StubSession(self._store, self._mode)

    def stop(self) -> None:
        return None


def _run(mode: str, *, allow_write: bool = True, gated=None):
    store = _Store()
    gw = gated if gated is not None else _gated_write(store, allow=allow_write)
    return confirm_stored_xss(
        "http://127.0.0.1:9/guestbook",
        "http://127.0.0.1:9/guestbook/view?name=guest",
        gated_write=gw,
        browser=_StubBrowser(store, mode),
        settle=0.0,
    ), store


# ---------------------------------------------------------------------------
# 1. Oracle wiring: stored_xss maps to DOM_EXECUTION (not the old xss alias)
# ---------------------------------------------------------------------------


def test_stored_xss_routes_to_dom_execution_not_reflection() -> None:
    assert normalize_bug_class("stored_xss") == "stored_xss"      # NOT aliased to "xss"
    assert normalize_bug_class("second_order_xss") == "stored_xss"
    assert normalize_bug_class("persistent_xss") == "stored_xss"
    assert BUG_CLASS_ORACLES["stored_xss"][0] is OracleKind.DOM_EXECUTION
    assert OracleVerifier().oracles_for("stored_xss")[0] is OracleKind.DOM_EXECUTION


# ---------------------------------------------------------------------------
# 2. FACT on a planted stored-XSS; SILENT on the benign twin + red-pen fixtures
# ---------------------------------------------------------------------------


def test_planted_stored_xss_executes_and_the_context_confirms() -> None:
    results, _store = _run("execute")
    assert results and all(isinstance(r, StoredXssResult) for r in results)
    assert all(r.written for r in results)
    assert all(r.executed for r in results)                  # every payload ran on B
    r = results[0]
    assert r.bug_class == "stored_xss" and _CANARY_RE.fullmatch(r.canary)
    outcome = OracleVerifier().confirm(r.context.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.DOM_EXECUTION and s.fired for s in outcome.signals)
    # round-trips through serialization (portable certificate)
    rebuilt = FindingContext.model_validate(r.context.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_benign_twin_textcontent_escaped_store_never_fires() -> None:
    results, _store = _run("escape")
    assert results and all(r.written for r in results)
    assert not any(r.executed for r in results)
    assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed


def test_red_pen_reflecting_not_executing_render_never_fires() -> None:
    results, _store = _run("reflect")            # B reflects the value inert (attribute/text), no script runs
    assert results and not any(r.executed for r in results)
    assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed


def test_red_pen_echo_without_a_script_never_fires() -> None:
    results, _store = _run("text")               # B echoes A's data as plain text, no execution
    assert results and not any(r.executed for r in results)
    assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed


# ---------------------------------------------------------------------------
# 3. GET-only fail-closed: no write path ⇒ nothing minted, and NOT a CLEAN
# ---------------------------------------------------------------------------


def test_no_gated_write_is_fail_closed_no_attempt_no_fact() -> None:
    # No approval authority / no --approve-mutations ⇒ no gated write supplied ⇒ the
    # module writes NOTHING and returns an EMPTY result set (not a CLEAN verdict).
    results = confirm_stored_xss(
        "http://127.0.0.1:9/guestbook",
        "http://127.0.0.1:9/guestbook/view?name=guest",
        gated_write=None,
        browser=_StubBrowser(_Store(), "execute"),
        settle=0.0,
    )
    assert results == []


def test_refused_approval_writes_nothing_and_does_not_confirm() -> None:
    # The gated write is present but the per-action approval is REFUSED for every
    # payload ⇒ written=False, no state change, no FACT (never a false CLEAN).
    results, store = _run("execute", allow_write=False)
    assert results and not any(r.written for r in results)
    assert not any(r.executed for r in results)
    assert store == {} or store.get("http://127.0.0.1:9/guestbook") is None
    assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed


def test_gated_write_that_raises_is_fail_closed() -> None:
    def boom(url: str, payload: str) -> bool:
        raise RuntimeError("broker unavailable")

    results, _store = _run("execute", gated=boom)
    assert results and not any(r.written for r in results)
    assert not any(r.executed for r in results)


# ---------------------------------------------------------------------------
# 4. Tamper rejection: a mutated canary no longer confirms
# ---------------------------------------------------------------------------


def test_a_tampered_canary_no_longer_confirms() -> None:
    results, _store = _run("execute")
    r = results[0]
    ctx = r.context.model_dump()
    ctx["dom_canary"] = "sxss" + "0" * 16          # a different canary than the one in the binding call
    tampered = FindingContext.model_validate(ctx)
    assert not OracleVerifier().confirm(tampered.to_verifier_context()).confirmed


def test_stored_xss_finding_carries_the_retained_oracle_context() -> None:
    results, _store = _run("execute")
    finding = stored_xss_finding(results[0])
    assert finding["bug_class"] == "stored_xss"
    octx = finding["oracle_context"]
    assert octx.get("dom_canary") and octx.get("dom_binding_calls")
    # the finding's own retained context re-fires the oracle
    assert OracleVerifier().confirm(octx).confirmed
