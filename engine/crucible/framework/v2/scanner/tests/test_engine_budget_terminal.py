"""
Regression: the gated executor's PER-ENGAGEMENT request budget is a TERMINAL stop
for the whole audit sweep — not a soft refusal the sweep ignores and keeps probing
past.

The live defect (meridian engage, --request-budget 200 --library): once the gated
executor's 200-request budget was spent, ``HttpExecutor.gated_fetch`` returned every
further probe as a SOFT refusal ``{"status": 0, "refused": "per-engagement request
budget 200 exhausted"}`` (never an exception). The AuditEngine's own ``BudgetExceeded``
is a SEPARATE counter (``max_requests``) that never observed that refusal, so the sweep
kept issuing refused probes across the entire crawl-expanded surface — and each blind
OOB check (SSRF / XXE / RCE / deserialization; the ``--library`` blind-cmdi entries
``;dig`` / ``;curl`` / ``;ping -c1`` / ``${{IFS}}`` / ``%0acurl`` / ``$(wget …)``) still
paid its full ``poll_deadline`` (2.0s) polling for a callback a refused request can never
produce. The run logged ~9000 budget.exhausted events and never reached finalize, so zero
facts were promoted.

These tests are fully offline and carry no wall-clock in their logic (OOB
``poll_deadline``/``poll_interval`` are pinned to 0.0 so even the PRE-FIX path returns
immediately instead of sleeping).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from framework.v2.scanner.engine import (
    AuditEngine,
    BudgetExceeded,
    _is_request_budget_refusal,
)
from framework.v2.scanner.checks import OOBCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind

# A URL with several query params => several QUERY_VALUE insertion points. If budget
# exhaustion were NOT terminal, the sweep would issue one probe PER point.
_MULTI_POINT_URL = "http://127.0.0.1:19010/documents/download?a=1&b=2&c=3&d=4&e=5"

_OK = {"status": 200, "body": "", "headers": [], "latency_ms": 0.0}


def _budget_flipping_send(ok_count: int):
    """A send that admits the first ``ok_count`` requests, then returns the executor's
    exact per-engagement budget-exhaustion refusal for every request after — mirroring
    ``HttpExecutor.gated_fetch`` once the shared budget is spent. Counts its calls."""
    state = {"n": 0}

    def send(_req: object) -> dict:
        state["n"] += 1
        if state["n"] <= ok_count:
            return dict(_OK)
        return {
            "status": 0, "body": "", "headers": [], "latency_ms": 0.0,
            "refused": f"per-engagement request budget {ok_count} exhausted",
        }

    send.state = state  # type: ignore[attr-defined]
    return send


class _FakeOOB:
    """Minimal OOBReceiver surface. ``poll`` never reports a hit (a refused request makes
    no callback) and counts its invocations so a test can prove the sweep stopped BEFORE
    polling the refused probe."""

    collector_pubkey = None

    def __init__(self) -> None:
        self.polls = 0

    def register_token(self):
        return ("tok", "http://127.0.0.1:0/cb/tok")

    def poll(self, _token):
        self.polls += 1
        return []


def _cmdi_oob_check() -> OOBCheck:
    # The real ``--library`` blind-cmdi shape, but with the poll loop pinned to 0.0 so the
    # test never sleeps on EITHER branch.
    return OOBCheck(
        id="rce-oob-test", bug_class="command_injection",
        payload_template=";curl {callback};", poll_deadline=0.0, poll_interval=0.0,
    )


def test_executor_budget_refusal_is_terminal_for_the_sweep() -> None:
    """The sweep STOPS at the first per-engagement budget refusal instead of probing the
    remaining insertion points. PRE-FIX this asserts 5 sends (one per point); POST-FIX it
    is exactly ok_count admitted + 1 refused that trips the terminal stop."""
    req = HttpRequest(method="GET", url=_MULTI_POINT_URL, headers=[])
    send = _budget_flipping_send(ok_count=2)
    oob = _FakeOOB()
    engine = AuditEngine(send, max_requests=0, oob=oob)  # 0 => engine's OWN budget unbounded

    findings = engine.audit(
        req, checks=(_cmdi_oob_check(),), insertion_kinds=(InsertionKind.QUERY_VALUE,),
    )

    assert send.state["n"] == 3, f"expected 2 admitted + 1 refused stop, got {send.state['n']}"
    assert findings == []
    # The refused (3rd) probe tripped the stop in _counted_send, BEFORE OOBCheck.probe could
    # reach its poll loop — so only the 2 admitted probes ever polled.
    assert oob.polls == 2, f"a refused probe still polled the OOB receiver: {oob.polls}"
    assert engine._budget_exhausted is True


def test_subsequent_audits_short_circuit_with_zero_traffic() -> None:
    """Once the shared engine has seen budget exhaustion, a later audit() on a fresh
    endpoint (the campaign's next ``for req in all_requests`` iteration) issues ZERO sends
    — so the run drains the remaining surface instantly and reaches finalize."""
    send = _budget_flipping_send(ok_count=1)
    oob = _FakeOOB()
    engine = AuditEngine(send, max_requests=0, oob=oob)

    engine.audit(HttpRequest(method="GET", url=_MULTI_POINT_URL, headers=[]),
                 checks=(_cmdi_oob_check(),), insertion_kinds=(InsertionKind.QUERY_VALUE,))
    after_first = send.state["n"]
    assert engine._budget_exhausted is True

    engine.audit(HttpRequest(method="GET", url="http://127.0.0.1:19010/records/search?q=1&r=2",
                             headers=[]),
                 checks=(_cmdi_oob_check(),), insertion_kinds=(InsertionKind.QUERY_VALUE,))

    assert send.state["n"] == after_first, "a later endpoint still issued refused traffic"


def test_budget_exceeded_passes_through_a_blind_check_broad_except() -> None:
    """BudgetExceeded must survive the OOB checks' ``except Exception: pass`` — otherwise a
    blind probe swallows the terminal stop and pays its full poll_deadline. Pinned by the
    base class AND exercised through the real OOBCheck.probe."""
    assert issubclass(BudgetExceeded, BaseException)
    assert not issubclass(BudgetExceeded, Exception)

    oob = _FakeOOB()
    check = _cmdi_oob_check()
    req = HttpRequest(method="GET", url="http://127.0.0.1:19010/x?p=1", headers=[])
    from framework.v2.scanner.insertion import RequestTemplate

    template = RequestTemplate(req)
    point = template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))[0]

    def _raising_send(_req: object):
        raise BudgetExceeded()

    with pytest.raises(BudgetExceeded):
        check.probe(template, point, _raising_send, oob)
    assert oob.polls == 0, "OOBCheck swallowed the terminal stop and still polled"


def test_scope_refusal_is_not_mistaken_for_budget_exhaustion() -> None:
    """A non-budget status-0 refusal (scope / destructive / egress) must NOT trip the
    sweep-wide stop — only the global request budget is terminal. The sweep probes every
    point as before."""
    req = HttpRequest(method="GET", url=_MULTI_POINT_URL, headers=[])
    calls = {"n": 0}

    def scope_refusing_send(_req: object) -> dict:
        calls["n"] += 1
        return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0,
                "refused": "target out of scope (charter)"}

    @dataclass(frozen=True)
    class _PointCheck:
        id: str = "custom-cmdi"
        bug_class: str = "command_injection"

        def probe(self, template, point, send):
            send(template.render(point, "x"))
            return None

    engine = AuditEngine(scope_refusing_send, max_requests=0)
    engine.audit(req, checks=(_PointCheck(),), insertion_kinds=(InsertionKind.QUERY_VALUE,))

    assert calls["n"] == 5, f"scope refusal wrongly stopped the sweep at {calls['n']}"
    assert engine._budget_exhausted is False


def test_is_request_budget_refusal_matcher() -> None:
    assert _is_request_budget_refusal(
        {"status": 0, "refused": "per-engagement request budget 200 exhausted"})
    # negatives: admitted response, dry-run (no 'refused'), other status-0 refusals
    assert not _is_request_budget_refusal({"status": 200, "body": "ok"})
    assert not _is_request_budget_refusal({"status": 0, "body": ""})  # dry-run: no note
    assert not _is_request_budget_refusal({"status": 0, "refused": "out of scope"})
    assert not _is_request_budget_refusal({"status": 0, "refused": "destructive action declined"})
    assert not _is_request_budget_refusal("not a dict")
