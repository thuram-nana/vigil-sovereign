"""W10-1 (#473): the runtime egress allowlist is WIRED on every target-traffic HttpExecutor.

WHY THIS TEST EXISTS. The runtime egress allowlist (``agents/egress_guard.py`` — the
``SovereignHttpxTransport`` installed as gate 6 of the fail-closed stack, README §9.14) is only
enforced on ``HttpExecutor`` traffic when the executor is constructed with a non-None
``egress_allowlist``. Before this change NO shipped caller set it — ``engage``'s scan + discovery
executors and the repeater's replay executor all built the client with the plain transport — so the
"6th gate" the README claims fires on *every* target-touching request was, for target traffic, never
installed on any real path. The claim was true only of the source-level default (``= None``) and the
sole live-intel collector (default-OFF behind ``--live``).

THREE guards, matching the acceptance criteria:

  1. STRUCTURAL (fails without the fix): every non-dry-run ``HttpExecutor(...)`` construction in the
     production framework tree must pass ``egress_allowlist=`` — so a NEW unwired caller turns CI
     red. On a tree without the fix the three real sites lack the keyword and this fails.

  2. NEGATIVE CONTROL for the egress gate: an executor whose allowlist does not permit the target
     host refuses the request under sovereign mode BEFORE any bytes leave the box — proving the
     transport is a real gate, not a no-op, and that it fires INDEPENDENTLY of (and after) the scope
     gate. Built exactly as ``engage`` / the repeater build it (``build_engagement_allowlist``).

  3. NEGATIVE CONTROLS for the two ALWAYS-ON target-traffic gates, each proven to refuse on its own:
     the protected-domain floor (a ``.gov``/``.mil`` host is refused categorically — by the scope
     gate AND, unconditionally, by the transport even in permissive mode) and the signed charter
     scope (an out-of-scope host, and a missing/unsigned charter, are each refused). These hold on
     EVERY tier; the allowlist's narrower reach (refusal only under sovereign mode) is the honest
     framing the docs now carry.

Every scenario runs against localhost ``pytest-httpserver`` or is pure AST/scope-gate logic; no
request ever leaves the test host.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from framework.v2.agents import HttpExecutor
from framework.v2.agents.egress_guard import (
    EgressAllowlist,
    SovereignHttpxTransport,
    build_engagement_allowlist,
)
from framework.v2.agents.models import HypothesisPayload, PlanPayload
from framework.v2.agents.scope_gate import validate_action
from framework.v2.common import paths as _paths
from framework.v2.kernel import sovereignty


_V2_ROOT = Path(__file__).resolve().parents[2]

_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def isolated_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    targets_root = tmp_path / "targets"
    targets_root.mkdir()

    def build_charter(slug: str, host: str) -> Path:
        td = targets_root / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(
            _CHARTER.format(slug=slug, host=host), encoding="utf-8",
        )
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(
        _paths, "charter_path", lambda s: targets_root / s / "charter.md",
    )
    return build_charter


def _hyp(surface: str) -> HypothesisPayload:
    return HypothesisPayload(
        handle="H-1", surface=surface, bug_class="probe",
        given="x", if_action=surface, then_observation="y",
        because_model="z", refute_on="n/a", cheap_test="one curl",
    )


_PLAN = PlanPayload(plan_id="P-1", targets_hypothesis="H-1", next_action="probe")


def _deny(_q: str, _t: float) -> bool:
    return False


# ---------------------------------------------------------------------------
# 1. STRUCTURAL — every target-traffic HttpExecutor construction sets the allowlist
# ---------------------------------------------------------------------------


def _iter_production_py() -> list[Path]:
    out: list[Path] = []
    for p in _V2_ROOT.rglob("*.py"):
        parts = p.parts
        if "tests" in parts or p.name.startswith("test_"):
            continue
        out.append(p)
    return out


def _kw(call: ast.Call, name: str) -> ast.keyword | None:
    for k in call.keywords:
        if k.arg == name:
            return k
    return None


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_none(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _httpexecutor_calls() -> list[tuple[Path, ast.Call]]:
    found: list[tuple[Path, ast.Call]] = []
    for path in _iter_production_py():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:  # a broken production file is a different problem
            pytest.fail(f"could not parse production module {path}: {exc}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "HttpExecutor":
                found.append((path, node))
    return found


def test_every_target_traffic_httpexecutor_installs_the_egress_allowlist():
    """Enumerate EVERY ``HttpExecutor(...)`` construction in the production tree. A site that sends
    traffic (i.e. not ``dry_run=True``) MUST pass a non-None ``egress_allowlist=`` — otherwise the
    egress gate is not installed on that target-traffic path and a new unwired caller has silently
    re-opened the hole. This test FAILS on a tree without the W10-1 wiring (the scan/discovery/
    repeater executors carried no allowlist)."""
    calls = _httpexecutor_calls()
    # Walk sanity: the three real callers + the type-narrowing stub must be seen; a walk that finds
    # nothing (a refactor that moved/renamed the class) must fail loudly, not pass vacuously.
    assert len(calls) >= 4, (
        f"expected >= 4 HttpExecutor construction sites in the production tree, found {len(calls)}; "
        f"the structural walk is not seeing the callers it is meant to guard"
    )

    offenders: list[str] = []
    for path, call in calls:
        rel = path.relative_to(_V2_ROOT)
        egress = _kw(call, "egress_allowlist")
        wired = egress is not None and not _is_none(egress.value)
        dry = _is_true(_kw(call, "dry_run").value) if _kw(call, "dry_run") else False
        if not wired and not dry:
            offenders.append(f"{rel}:{call.lineno} (no egress_allowlist= and not dry_run=True)")

    assert not offenders, (
        "target-traffic HttpExecutor construction(s) do not install the runtime egress allowlist "
        "(W10-1 #473 — wire egress_allowlist=build_engagement_allowlist(...) or mark dry_run=True):\n"
        + "\n".join(offenders)
    )


def test_engage_and_repeater_are_among_the_wired_sites():
    """Pin the specific target-traffic paths named in #473: engage's scan + discovery executors and
    the repeater's replay executor. Each production module must carry at least one WIRED
    construction, so a future edit that drops the allowlist on one of them (while leaving another)
    is still caught here even if the count-based guard above still passes."""
    by_file: dict[str, int] = {}
    for path, call in _httpexecutor_calls():
        egress = _kw(call, "egress_allowlist")
        if egress is not None and not _is_none(egress.value):
            rel = str(path.relative_to(_V2_ROOT))
            by_file[rel] = by_file.get(rel, 0) + 1

    assert by_file.get("engage.py", 0) >= 2, (
        f"engage.py must wire the allowlist on BOTH the scan and discovery executors; "
        f"wired sites seen: {by_file.get('engage.py', 0)}"
    )
    assert by_file.get("repeater/tool.py", 0) >= 1, (
        f"repeater/tool.py must wire the allowlist on the replay executor; "
        f"wired sites seen: {by_file.get('repeater/tool.py', 0)}"
    )


# ---------------------------------------------------------------------------
# 2. NEGATIVE CONTROL — the egress gate refuses an out-of-allowlist target (not a no-op)
# ---------------------------------------------------------------------------


def test_engage_style_executor_installs_the_sovereign_transport(
    isolated_engagement, httpserver: HTTPServer,
):
    """Built exactly as ``engage`` builds it — ``egress_allowlist=build_engagement_allowlist(slug)``
    — the executor's httpx client rides the ``SovereignHttpxTransport``. This is the object-level
    proof that the wiring installs a real gate (the structural test proves engage.py passes it)."""
    isolated_engagement("alpha", httpserver.host)
    ex = HttpExecutor(
        engagement_slug="alpha",
        base_url=httpserver.url_for("/"),
        prompt_callback=_deny,
        egress_allowlist=build_engagement_allowlist(slug="alpha"),
    )
    try:
        client = ex._client()
        assert isinstance(client._transport, SovereignHttpxTransport)
        # the allowlist carries THIS engagement's charter scope (the target host)
        assert ex.egress_allowlist is not None
        assert ex.egress_allowlist.permits(httpserver.host)
    finally:
        ex.close()


def test_egress_gate_refuses_out_of_allowlist_target_under_sovereign_mode(
    isolated_engagement, httpserver: HTTPServer,
):
    """NEGATIVE CONTROL for gate 6. The charter scopes the httpserver host (so the SCOPE gate would
    pass), but the egress allowlist deliberately permits only a different host. Under sovereign mode
    the transport refuses the request BEFORE any bytes leave — a graceful refusal outcome, nothing
    contacted — proving the egress gate fires independently of, and after, the scope gate."""
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/probe").respond_with_data("ok")

    # scope permits httpserver.host; the egress allowlist permits ONLY an unrelated host + llm hosts
    disjoint = EgressAllowlist(target_hosts=("allowed.example",), llm_hosts=(), extra_hosts=())
    assert not disjoint.permits(httpserver.host)  # precondition: target is out of the allowlist

    prev = sovereignty._active_policy
    sovereignty.set_policy(sovereignty.SovereigntyPolicy(strict=True))
    try:
        ex = HttpExecutor(
            engagement_slug="alpha",
            base_url=httpserver.url_for("/"),
            prompt_callback=_deny,
            egress_allowlist=disjoint,
        )
        out = ex.execute(_hyp("/probe"), _PLAN)
        ex.close()
    finally:
        sovereignty.set_policy(prev)

    assert out.success is False
    assert "egress guard" in out.note
    assert len(httpserver.log) == 0                 # nothing ever left the host
    assert ex.stats()["scope_violations"] == 1


def test_repeater_replay_executor_carries_the_egress_allowlist(
    isolated_engagement, monkeypatch, httpserver: HTTPServer,
):
    """The other wired target-traffic path: the gated intercepting repeater. After a replay, the
    executor the tool built for the slug carries a non-None ``egress_allowlist`` whose client rides
    the sovereign transport — so the repeater's replays are backstopped by gate 6 too."""
    from framework.v2 import entitlement
    from framework.v2.repeater import Repeater, RepeaterRequest

    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/api/x").respond_with_data("ok")

    rep = Repeater(slug="alpha", prompt_callback=_deny)
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/api/x")))
    try:
        assert ex.ok and ex.sent
        built = rep._tool._executors["alpha"]
        assert built.egress_allowlist is not None
        assert built.egress_allowlist.permits(httpserver.host)
        assert isinstance(built._client()._transport, SovereignHttpxTransport)
    finally:
        rep.close()


# ---------------------------------------------------------------------------
# 3. NEGATIVE CONTROLS — the two ALWAYS-ON target-traffic gates each refuse independently
# ---------------------------------------------------------------------------


def test_protected_domain_floor_refuses_independently(isolated_engagement):
    """Gate that ALWAYS holds (#1 of the two). A government/military host is refused categorically —
    by the scope gate (``refusal_kind='hard_blocked'``) even when the charter would otherwise scope
    it, AND, unconditionally, by the egress transport even in PERMISSIVE mode (the floor runs above
    the passthrough). This is the protected-domain floor described in the docs."""
    # Charter deliberately scopes a protected host: the floor must still refuse (it runs first).
    isolated_engagement("alpha", "nsa.gov")
    decision = validate_action(slug="alpha", method="GET", target_url="https://nsa.gov/x")
    assert not decision.allowed
    assert decision.refusal_kind == "hard_blocked"

    # And the transport refuses a protected host unconditionally — even in permissive (non-strict)
    # mode, where the sovereign allowlist below it would otherwise pass everything through. The
    # categorical floor raises HardBlockError (not the sovereign-allowlist SovereigntyViolation),
    # ABOVE the passthrough, so it fires regardless of tier or allowlist contents.
    import httpx
    from vigil_core.hard_guardrail import HardBlockError

    prev = sovereignty._active_policy
    sovereignty.set_policy(sovereignty.SovereigntyPolicy(strict=False))  # PERMISSIVE
    try:
        # allowlist that would PERMIT nsa.gov if the floor did not run first
        transport = SovereignHttpxTransport(EgressAllowlist(target_hosts=("nsa.gov",)))
        req = httpx.Request("GET", "https://nsa.gov/x")
        with pytest.raises(HardBlockError):
            transport.handle_request(req)
    finally:
        sovereignty.set_policy(prev)


def test_signed_charter_scope_refuses_independently(isolated_engagement):
    """Gate that ALWAYS holds (#2 of the two). An in-scope charter still refuses an OUT-OF-scope
    host (``out_of_scope``), and a MISSING charter refuses too (``charter_missing``) — the signed
    charter scope, reached unconditionally by the executor on every request regardless of tier."""
    isolated_engagement("alpha", "in-scope.example")
    out_of_scope = validate_action(
        slug="alpha", method="GET", target_url="https://evil.example/x",
    )
    assert not out_of_scope.allowed
    assert out_of_scope.refusal_kind == "out_of_scope"

    # A slug with no charter at all fails closed (never silently allowed).
    missing = validate_action(slug="no-such-slug", method="GET", target_url="https://x.example/")
    assert not missing.allowed
    assert missing.refusal_kind in {"charter_missing", "charter_unsigned"}
