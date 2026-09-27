"""
The gate corpus's boolean-SQLi NEGATIVE CONTROLS — and the proof they are load-bearing.

The gate is asymmetric: a new false positive fails CI. That only means something if the
corpus actually contains a surface a WRONG detector would fire on. This module pins the
three controls that make the planted ``boolean_sqli`` FACT at ``/users?name`` mean
something, and it is written so that DELETING ANY OF THEM FAILS A TEST — the cautionary
case being that ``/users/safe`` could previously be disconnected from ``_ROUTES`` with
nothing at all going red.

WHY ``/users/safe`` IS NOT ENOUGH ON ITS OWN. The parameterised twin refutes a detector
that fires on it, and that is all it does. It CANNOT discriminate a payload-SHAPE reader
from an INJECTION reader, because a shape reader does not fire there either: measured,
the bare ``DifferentialCheck`` confirms on ``/users`` and returns ``None`` on
``/users/safe``, and it is definitionally a shape reader — it was reproduced minting
against a WAF-tautology static page and against a strict-input-validation static page,
neither with a database. Discriminating needs a surface where the payload SHAPE is
present and the INJECTION is not.

``/locations?city`` and ``/lookup?term`` are those surfaces. Both are STATIC pages with
NO DATABASE and no query of any kind; the only thing input can change is whether a
filter rejects it. So:

  * a bare benign-vs-payload differential SEES A CHANNEL on both (200 static vs
    403/400 rejected) — asserted positively below, because a control that no wrong
    detector would fire on is inert and proves nothing;
  * the SOUND SPRT must REFUSE on both, because the filters key on payload SHAPE and
    reject always-TRUE and always-FALSE clauses IDENTICALLY, so the two truth clusters
    never separate.

These assertions are POSITIVE about the refusal: they require that the detector really
ran (non-empty SPRT rounds, full clause sets per round) and THEN declined — never merely
that no finding happened to appear, which is also what a 404 or a disconnected route
would produce.

Both control routes are OFF-MANIFEST in ``benchmark_corpus``, so anything reported on
them is a false positive by construction and the gate's ``fp`` column catches it.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

import pytest

from framework.v2.eval.benchmark_app import benchmark_corpus, serve
from framework.v2.eval.benchmark_run import BOOLEAN_SQLI_SOUND
from framework.v2.scanner.checks import BOOLEAN_DISCRIMINATOR, boolean_clause_families
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.oracles import differential_response_oracle
from framework.v2.verify.verifier import OracleVerifier

TRUES, FALSES = boolean_clause_families()[0]

# The two DISCRIMINATING controls: (path, param, a benign value the filter accepts).
_CONTROLS = (
    ("/locations", "city", "lisbon"),   # CRS-942130-shaped tautology rule over a static page
    ("/lookup", "term", "widget"),      # strict input validation over a static page
)


@pytest.fixture(scope="module")
def base() -> str:
    with serve() as url:
        yield url


def _fetch(base: str, path: str, param: str, value: str) -> tuple[int, bytes]:
    url = f"{base}{path}?{param}=" + urllib.parse.quote(value, safe="")
    try:
        with urllib.request.urlopen(url, timeout=10) as r:  # noqa: S310 (loopback)
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _point(base: str, path: str, param: str):
    tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}{path}?{param}=x"))
    point = next(p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                 if p.name == param)
    return tpl, point


def _as_dict(resp) -> dict:
    return resp if isinstance(resp, dict) else resp.__dict__


def _sprt(base: str, path: str, param: str):
    """Run the GATE'S OWN sound detector and return (context, confirmed-or-None)."""
    tpl, point = _point(base, path, param)
    ctx = BOOLEAN_SQLI_SOUND.probe(tpl, point, loopback_send)
    got = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx,
                          verifier=OracleVerifier())
    return ctx, got


def _assert_detector_really_ran(ctx, where: str) -> None:
    """The POSITIVE half of a refusal claim: the SPRT examined this surface.

    Without this, 'no finding' is indistinguishable from 'the route 404s', 'the check
    was never wired', or 'the fixture was deleted' — which is exactly the hole that let
    ``/users/safe`` be removable with zero tests failing."""
    rounds = ctx.probe_rounds or []
    assert rounds, f"{where}: the sound detector produced NO SPRT rounds — it never examined this surface"
    for i, r in enumerate(rounds):
        assert len(r["trues"]) == len(TRUES), (
            f"{where}: round {i} carried {len(r['trues'])} always-TRUE clauses, expected {len(TRUES)}")
        assert len(r["falses"]) == len(FALSES), (
            f"{where}: round {i} carried {len(r['falses'])} always-FALSE clauses, expected {len(FALSES)}")
        assert len(r["true_repeats"]) == len(TRUES) and len(r["false_repeats"]) == len(FALSES), (
            f"{where}: round {i} is missing its byte-identical determinism repeats")


# ---------------------------------------------------------------------------
# The two discriminating controls.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "param", "benign"), _CONTROLS)
def test_control_route_is_connected_and_static(base, path, param, benign) -> None:
    """The fixture EXISTS, serves 200 on benign input, and its body does NOT depend on
    the input — it is a static page with no database. Deleting the route from
    ``_ROUTES`` turns the 200 into a 404 and fails here."""
    status, body = _fetch(base, path, param, benign)
    assert status == 200, f"{path}?{param}={benign} returned {status}, expected 200 (route disconnected?)"
    other_status, other_body = _fetch(base, path, param, "osaka-42")
    assert other_status == 200 and other_body == body, (
        f"{path} is not static: two different accepted inputs produced different responses, "
        "so it is not a no-database control")


@pytest.mark.parametrize(("path", "param", "benign"), _CONTROLS)
def test_control_is_shape_readable_so_it_is_not_an_inert_fixture(base, path, param, benign) -> None:
    """A control only discriminates if a WRONG detector would fire on it.

    A bare benign-vs-payload differential must SEE A CHANNEL here — 200-static against
    403/400-rejected. This is the assertion that keeps the control honest: if a future
    edit makes the filter invisible, the fixture silently stops proving anything, and
    this test says so instead."""
    tpl, point = _point(base, path, param)
    benign_resp = _as_dict(loopback_send(tpl.render(point, benign)))
    payload_resp = _as_dict(loopback_send(tpl.render(point, TRUES[0])))
    assert differential_response_oracle(benign_resp, payload_resp, BOOLEAN_DISCRIMINATOR).fired, (
        f"{path}?{param} is INERT: a bare differential sees no channel here, so this fixture "
        "cannot discriminate a payload-shape reader from an injection reader")


@pytest.mark.parametrize(("path", "param", "benign"), _CONTROLS)
def test_control_has_no_truth_value_partition(base, path, param, benign) -> None:
    """The filter rejects always-TRUE and always-FALSE clauses IDENTICALLY.

    All 14 clauses must land on ONE response. If any TRUE/FALSE pair separated, the
    page would carry a real boolean channel and would no longer be a negative control."""
    landings = {_fetch(base, path, param, c) for c in (*TRUES, *FALSES)}
    assert len(landings) == 1, (
        f"{path}?{param}: the 14 clauses landed on {len(landings)} distinct responses — a truth-value "
        "partition exists here, so this is no longer a no-database negative control")


@pytest.mark.parametrize(("path", "param", "benign"), _CONTROLS)
def test_sound_detector_examined_the_control_and_refused(base, path, param, benign) -> None:
    """THE POINT OF THE SLICE. The sound SPRT must RUN against a surface a shape reader
    fires on, and then REFUSE — not skip it, not 404 on it, not silently produce nothing."""
    ctx, got = _sprt(base, path, param)
    _assert_detector_really_ran(ctx, f"{path}?{param}")
    assert got is None, (
        f"FALSE FACT: the sound detector CONFIRMED boolean_sqli on {path}?{param} "
        f"(via {got.confirmed_by.value if got else '?'}) — a static page with no database, "
        "behind a filter that keys on payload shape")


@pytest.mark.parametrize(("path", "param", "benign"), _CONTROLS)
def test_control_is_off_manifest_so_any_finding_is_a_false_positive(base, path, param, benign) -> None:
    """Off-manifest by construction: the gate's ``fp`` column is what catches a
    regression here, and that only works while these are NOT ground truth."""
    located = {e.location for e in benchmark_corpus(base).expected}
    assert not any(loc.startswith(path) for loc in located), (
        f"{path} was added to the ground-truth manifest — it is a NEGATIVE control and must stay "
        "off-manifest, or a false positive on it would be scored as a true positive")


# ---------------------------------------------------------------------------
# The parameterised twin — the liveness assertion that was missing.
# ---------------------------------------------------------------------------


def test_users_safe_twin_is_connected_and_serves_the_same_rendering(base) -> None:
    """``/users/safe`` must be REACHABLE. Before this test the route could be deleted
    from ``_ROUTES`` and nothing anywhere went red — the gate simply lost a surface and
    still passed."""
    status, body = _fetch(base, "/users/safe", "name", "guest")
    assert status == 200, f"/users/safe returned {status} — the safe twin is disconnected"
    assert b"User lookup" in body, "/users/safe is not serving the shared _users_body rendering"


def test_users_safe_twin_collapses_all_fourteen_clauses_onto_one_body(base) -> None:
    """The bound parameter admits no clause of any shape: all 7 always-TRUE and all 7
    always-FALSE probes must land on ONE identical body, so no truth-value partition
    exists on the twin."""
    landings = {_fetch(base, "/users/safe", "name", c) for c in (*TRUES, *FALSES)}
    assert len(landings) == 1, (
        f"/users/safe separated the clauses into {len(landings)} responses — the twin is no longer "
        "parameterised, so it has stopped being a negative control")
    (status, _body), = landings
    assert status == 200


def test_sound_detector_examined_the_twin_and_refused(base) -> None:
    ctx, got = _sprt(base, "/users/safe", "name")
    _assert_detector_really_ran(ctx, "/users/safe?name")
    assert got is None, "FALSE FACT: the sound detector confirmed boolean_sqli on the parameterised twin"


# ---------------------------------------------------------------------------
# The positive control, so the whole file cannot pass by refusing everything.
# ---------------------------------------------------------------------------


def test_the_planted_bug_still_confirms_via_boolean_inference(base) -> None:
    """Without this, every assertion above is satisfied by a detector that never fires.
    ``/users?name`` is a REAL sqlite3 injection and must confirm — and specifically via
    BOOLEAN_INFERENCE, never via a differential."""
    ctx, got = _sprt(base, "/users", "name")
    _assert_detector_really_ran(ctx, "/users?name")
    assert got is not None, "the planted boolean_sqli at /users?name no longer confirms"
    assert got.confirmed_by.value == "boolean_inference", (
        f"the planted boolean_sqli confirmed via {got.confirmed_by.value}, not boolean_inference")


def test_the_planted_bug_partitions_all_seven_clause_shapes(base) -> None:
    """The fixture is a REAL engine, not a shape matcher: every one of the seven
    syntactically-varied families must separate, every TRUE response agreeing with
    every other TRUE and every FALSE with every FALSE. (The two-regex fixture this
    replaced managed 1 of 7 — literal equality only.)"""
    t = {_fetch(base, "/users", "name", c) for c in TRUES}
    f = {_fetch(base, "/users", "name", c) for c in FALSES}
    assert len(t) == 1, f"the always-TRUE clauses did not agree: {len(t)} distinct responses"
    assert len(f) == 1, f"the always-FALSE clauses did not agree: {len(f)} distinct responses"
    assert not (t & f), "the TRUE and FALSE clusters overlap — no truth-value partition"
