"""Claim 5 — the shared negative-control corpus for the protected-domain hard-guard.

ONE parametrized corpus of protected / evasion / allowed hosts, run against EVERY target-touching entry
point the guard is wired into, plus the toggle truth table. This is the anti-drift acceptance gate: if a
future refactor drops the guard from a hook, or inverts the fail-safe polarity, or lets the toggle relax
charter scope, a row here goes red.

The hooked covering set (each toggle-gated by ``protected_guard_enabled()``, default ON):

  * A1  framework.v2.common.ethics.require_in_scope            (raising: HardBlockError)
  * A2  framework.v2.agents.scope_gate.validate_action         (return: ScopeDecision refusal_kind="hard_blocked")
  * A3  framework.v2.agents.egress_guard.handle_request        (raising, ABOVE the permissive passthrough)
  * B1  vigil_integration.live.executor._resolve_scoped_target (return: (None, reason) — total fn)
  * B2  vigil_integration.live.external_tool.ScopeGate.authorize(return: (False, reason))
  * B3  vigil_integration.live.live_transport.LiveTransport.__call__ (raising)
  * B4  vigil_integration.remediation.codefix.run_codefix      (return: result status "clone-denied")
  * C1  framework.v2.common.ethics.require_authorized_intake    (raising: HardBlockError — the intake
        front door; intake fetches via raw httpx in intake/http.py, so A3 does not cover it)

Framework-dependent (A1/A2/A3), so it is behind ``importorskip('framework')`` → it SKIPS in the sovereign
CI leg and MUST be listed in the offense leg of .github/workflows/ci.yml (enforced by
test_ci_framework_tests_run_in_offense_leg.py). Run:
  PYTHONPATH=integration:engine/crucible:gateway pytest integration/tests/test_protected_guard_corpus.py -q
"""
from __future__ import annotations

import socket

import pytest

# Framework-dependent: skip cleanly where `framework` is not importable (the sovereign leg / FATAL-2).
pytest.importorskip("framework.v2.common.ethics")
pytest.importorskip("framework.v2.agents.scope_gate")
pytest.importorskip("framework.v2.agents.egress_guard")

import httpx

from framework.v2.agents import scope_gate
from framework.v2.agents.egress_guard import EgressAllowlist, SovereignHttpxTransport
from framework.v2.common import ethics
from framework.v2.common.errors import SovereigntyViolation
from framework.v2.kernel.sovereignty import SovereigntyPolicy, set_policy

from vigil_core.hard_guardrail import HardBlockError, protected_guard_enabled
from vigil_gateway.scope_source import StaticScopeSource
from vigil_integration.live.executor import _resolve_scoped_target
from vigil_integration.live.external_tool import ScopeGate
from vigil_integration.live.live_transport import LiveTransport
from vigil_integration.remediation.codefix import CodeFixRequest, EditBlock, run_codefix
from vigil_integration.remediation.triage import TriageFinding

_ENV = "VIGIL_ALLOW_PROTECTED_DOMAINS"

# Hosts the categorical floor MUST refuse (guard ON): a TLD, an IGO exact match, a subdomain, a
# unicode-dot homoglyph, and a userinfo-smuggle (real host after the last '@').
_PROTECTED = ["defense.gov", "un.org", "data.un.org", "un。org", "http://127.0.0.1@un.org/"]
# Hosts the floor MUST NOT over-block: an ordinary host, and a protected name used only as USERINFO
# (the real host is evil.com).
_ALLOWED = ["evil.com", "http://un.org@evil.com/"]

_FLOOR = "floor"   # the categorical protected-domain floor fired
_PASS = "pass"     # the floor did NOT fire (something else may still refuse — that is fine here)


# ---------------------------------------------------------------------------------------------------
# hermetic helpers (no real DNS, no real sockets)
# ---------------------------------------------------------------------------------------------------
def _fake_getaddrinfo(mapping):
    def _f(host, port=None, *a, **k):
        ips = mapping.get(host)
        if ips is None:
            raise socket.gaierror("hermetic: unresolvable")
        if isinstance(ips, str):
            ips = [ips]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in ips]
    return _f


class _ReachedNetwork(Exception):
    """Sentinel: control reached the transport's network layer (⇒ the guard did NOT block)."""


class _FakeHttpxClient:
    def build_request(self, *a, **k):
        raise _ReachedNetwork()

    def send(self, *a, **k):
        raise _ReachedNetwork()

    def close(self):
        pass


class _V:
    def __init__(self, allowed=True, outcome="allow", reason="ok"):
        self.allowed, self.outcome, self.reason = allowed, outcome, reason


def _allow_gate(tool, target, destructive):
    return _V()


def _as_url(raw: str) -> str:
    return raw if "://" in raw else "https://" + raw + "/"


def _as_repo(raw: str) -> str:
    return raw if "://" in raw else "https://" + raw + "/repo.git"


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    # permissive sovereignty (so A3's floor is proven to fire ABOVE the permissive passthrough), and an
    # all-unresolvable DNS default so a non-floored path never does a real lookup. Individual truth-table
    # tests re-patch getaddrinfo with an explicit mapping (a later setattr wins).
    set_policy(SovereigntyPolicy(strict=False))
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({}))
    yield
    set_policy(None)


# ---------------------------------------------------------------------------------------------------
# the per-hook adapters — each returns _FLOOR (the categorical floor fired) or _PASS (it did not)
# ---------------------------------------------------------------------------------------------------
def _a1(raw):
    try:
        ethics.require_in_scope("no-such-slug-claim5", _as_url(raw))
        return _PASS
    except HardBlockError:
        return _FLOOR
    except Exception:                      # OutOfScope / charter refusal ⇒ the floor did not fire
        return _PASS


def _a2(raw):
    d = scope_gate.validate_action(slug="no-such-slug-claim5", method="GET", target_url=_as_url(raw))
    return _FLOOR if d.refusal_kind == "hard_blocked" else _PASS


def _a3(raw):
    allow = EgressAllowlist(target_hosts=("evil.com", "un.org", "data.un.org", "defense.gov", "127.0.0.1"))
    t = SovereignHttpxTransport(allowlist=allow,
                                inner=httpx.MockTransport(lambda request: httpx.Response(204)),
                                sovereign_only=True)
    req = httpx.Request("GET", _as_url(raw))
    try:
        t.handle_request(req)
        return _PASS
    except HardBlockError:
        return _FLOOR
    except SovereigntyViolation:           # allowlist refusal (not the floor)
        return _PASS


def _b1(raw):
    res, reason = _resolve_scoped_target(_as_url(raw), scope=StaticScopeSource(["placeholder.example"]))
    return _FLOOR if (res is None and "permanently blocked" in reason) else _PASS


def _b2(raw):
    sg = ScopeGate(scope=StaticScopeSource([]), resolver=_fake_getaddrinfo({}))
    ok, reason = sg.authorize(raw)
    return _FLOOR if (not ok and "permanently blocked" in reason) else _PASS


def _b3(raw):
    lt = LiveTransport()
    lt._client.close()
    lt._client = _FakeHttpxClient()        # a real dial would leave the host; the sentinel proves reach
    try:
        lt("GET", _as_url(raw))
        return _PASS
    except HardBlockError:
        return _FLOOR
    except _ReachedNetwork:                 # control passed the guard and reached the transport ⇒ not floored
        return _PASS


def _b4(raw):
    finding = TriageFinding(ref="f1", title="t", bug_class="sqli", severity="high",
                            target="app.py", confirmed=True, evidence_ref="cert:x")
    req = CodeFixRequest(remediation_id="rem-x", finding=finding, target_repo=_as_repo(raw))
    res = run_codefix(req, [EditBlock(path="src/app.py")], gate=_allow_gate)
    return _FLOOR if (res.status == "clone-denied" and "hard scope floor" in (res.reason or "")) else _PASS


def _c1(raw):
    # C1: the intake front door — the FIRST target-touching lifecycle step, which fetches via raw httpx
    # (intake/http.py), NOT the HttpExecutor, so A3 never covers it. The floor sits in
    # ethics.require_authorized_intake, before the authorization ledger is consulted. An ALLOWED host
    # instead raises AuthorizationMissing (not in the ledger) ⇒ the floor did not fire ⇒ _PASS.
    try:
        ethics.require_authorized_intake(_as_url(raw))
        return _PASS
    except HardBlockError:
        return _FLOOR
    except Exception:                      # AuthorizationMissing / other ⇒ the floor did not fire
        return _PASS


_PATHS = {"A1": _a1, "A2": _a2, "A3": _a3, "B1": _b1, "B2": _b2, "B3": _b3, "B4": _b4, "C1": _c1}


# ---------------------------------------------------------------------------------------------------
# the corpus assertions
# ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("path", sorted(_PATHS))
@pytest.mark.parametrize("host", _PROTECTED)
def test_guard_on_refuses_every_protected_host_on_every_path(path, host, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)         # unset ⇒ guard ON (fail-safe default)
    assert protected_guard_enabled() is True
    assert _PATHS[path](host) == _FLOOR, f"{path} failed to floor-block protected host {host!r}"


@pytest.mark.parametrize("path", sorted(_PATHS))
@pytest.mark.parametrize("host", _ALLOWED)
def test_guard_on_does_not_overblock_allowed_hosts_on_every_path(path, host, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)         # guard ON, but an allowed host must still pass the floor
    assert _PATHS[path](host) == _PASS, f"{path} over-blocked allowed host {host!r}"


def test_protected_guard_enabled_fail_safe_polarity(monkeypatch):
    # Fail-safe: anything that is not an explicit affirmative ⇒ guard ON (protected).
    for junk in ("", "   ", "0", "off", "false", "no", "maybe", "grbl", "2"):
        monkeypatch.setenv(_ENV, junk)
        assert protected_guard_enabled() is True, junk
    monkeypatch.delenv(_ENV, raising=False)
    assert protected_guard_enabled() is True
    for yes in ("1", "true", "yes", "on", "TRUE", "On", " yes "):
        monkeypatch.setenv(_ENV, yes)
        assert protected_guard_enabled() is False, yes


def test_guard_off_disables_the_floor_but_not_scope(monkeypatch):
    # Turning the toggle OFF skips ONLY the categorical pre-filter on both a raising and a return path.
    monkeypatch.setenv(_ENV, "1")
    assert protected_guard_enabled() is False
    assert _a1("defense.gov") == _PASS      # raising path: no HardBlockError when OFF
    assert _b1("defense.gov") == _PASS      # return path: no "permanently blocked" reason when OFF


def test_guard_off_b1_executor_truth_table(monkeypatch):
    # OFF ⇒ .gov allowed ONLY in signed scope; scope + egress floor still decide (toggle never relaxes them).
    monkeypatch.setenv(_ENV, "1")
    # (a) in signed scope, public IP → allowed (pinned)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({"test.gov": "93.184.216.34"}))
    res, reason = _resolve_scoped_target("http://test.gov/", scope=StaticScopeSource(["test.gov"]),
                                         allowed_ips=frozenset({"93.184.216.34"}))
    assert res is not None, reason
    # (b) NOT in signed scope → REFUSED by scope.matches (the key negative control: scope not relaxed)
    res, reason = _resolve_scoped_target("http://test.gov/", scope=StaticScopeSource(["other.example"]),
                                         allowed_ips=frozenset({"93.184.216.34"}))
    assert res is None and "not in the signed authority scope" in reason
    # (c) in scope but resolves to cloud metadata → still REFUSED by the never-liftable egress floor
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({"test.gov": "169.254.169.254"}))
    res, reason = _resolve_scoped_target("http://test.gov/", scope=StaticScopeSource(["test.gov"]),
                                         allowed_ips=frozenset({"169.254.169.254"}))
    assert res is None and "always-denied" in reason


def test_guard_off_b2_external_tool_truth_table(monkeypatch):
    monkeypatch.setenv(_ENV, "1")
    # (a) in scope, public IP → authorized
    sg = ScopeGate(scope=StaticScopeSource(["test.gov"]), resolver=_fake_getaddrinfo({"test.gov": "93.184.216.34"}))
    ok, reason = sg.authorize("test.gov")
    assert ok is True, reason
    # (b) out of scope → refused by scope (not relaxed)
    sg = ScopeGate(scope=StaticScopeSource(["other.example"]), resolver=_fake_getaddrinfo({"test.gov": "93.184.216.34"}))
    ok, reason = sg.authorize("test.gov")
    assert ok is False and "not in the charter scope" in reason
    # (c) in scope but metadata IP → refused by the egress floor
    sg = ScopeGate(scope=StaticScopeSource(["test.gov"]), resolver=_fake_getaddrinfo({"test.gov": "169.254.169.254"}))
    ok, reason = sg.authorize("test.gov")
    assert ok is False and "egress denied" in reason
