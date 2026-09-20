"""
Tests for W4.D — the GATED intercepting repeater.

Two layers:

  * PURE data shapes (``RepeaterRequest`` / ``mutate`` / ``normalize_headers`` / ``base_url_of``) —
    deterministic, no I/O.
  * GATED replay — every scenario runs against a ``pytest-httpserver`` on localhost (no request
    ever leaves the test host) with a synthetic signed in-scope charter written under ``tmp_path``
    and ``paths`` monkeypatched to point there (mirrors ``agents/tests/test_http_executor.py`` and
    ``sensors/tests/test_nmap_sensor.py``). The tests are strict about the gates: an out-of-scope
    target, a missing entitlement, an unsigned charter, and a tripped kill-switch must each refuse
    and send NOTHING; the correlatable UA must be forced; evidence + transcript + spine must record.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from framework.v2.common import paths as _paths
from framework.v2.repeater import (
    Repeater,
    RepeaterExchange,
    RepeaterRequest,
    base_url_of,
    mutate,
    normalize_headers,
)


# ---------------------------------------------------------------------------
# charter + isolation fixtures (mirror test_http_executor.isolated_engagement)
# ---------------------------------------------------------------------------


_SIGNED_CHARTER_TEMPLATE = """\
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


def _write_charter(*, target_dir: Path, slug: str, host: str, signed: bool = True) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    text = _SIGNED_CHARTER_TEMPLATE.format(slug=slug, host=host)
    if not signed:
        text = text.replace("Signed: `tester`", "Signed: `<name>`")
    (target_dir / "charter.md").write_text(text, encoding="utf-8")


@pytest.fixture()
def isolated_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Provision an isolated targets/<slug>/ and route the executor's charter / evidence / log /
    kill-switch paths under tmp_path. Returns a builder the test calls to materialise a charter."""
    targets_root = tmp_path / "targets"
    targets_root.mkdir()

    def build_charter(slug: str, host: str, *, signed: bool = True) -> Path:
        td = targets_root / slug
        _write_charter(target_dir=td, slug=slug, host=host, signed=signed)
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets_root / f"{s}.halt")
    return build_charter


@pytest.fixture()
def grant_exploit(monkeypatch: pytest.MonkeyPatch):
    """Grant the EXPLOIT_EXECUTION entitlement deterministically (independent of ambient trust-root
    provisioning), mirroring the nmap tests' ACTIVE_RECON grant."""
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _allow(_q: str, _t: float) -> bool:
    return True


def _deny(_q: str, _t: float) -> bool:
    return False


# ---------------------------------------------------------------------------
# PURE data shapes
# ---------------------------------------------------------------------------


def test_capture_normalizes_method_and_headers() -> None:
    req = RepeaterRequest.capture(
        "http://alpha.example/a", method="post",
        headers={"X-A": "1", "X-B": "2"}, body="payload",
    )
    assert req.method == "POST"
    assert req.url == "http://alpha.example/a"
    assert req.headers == (("X-A", "1"), ("X-B", "2"))
    assert req.body == "payload"
    assert req.header_list() == [["X-A", "1"], ["X-B", "2"]]


def test_normalize_headers_handles_dict_pairs_none_and_malformed() -> None:
    assert normalize_headers(None) == ()
    assert normalize_headers({"A": "1"}) == (("A", "1"),)
    assert normalize_headers([("A", "1"), ["B", "2"]]) == (("A", "1"), ("B", "2"))
    # malformed elements (not exactly 2-item pairs) are skipped, not raised
    assert normalize_headers([("A", "1"), ("bad",), ("C", "3", "x")]) == (("A", "1"),)


def test_mutate_is_pure_and_edits_fields_and_headers() -> None:
    base = RepeaterRequest.capture(
        "http://alpha.example/a", method="GET",
        headers={"User-Agent": "spoof", "X-Keep": "k"},
    )
    edited = mutate(
        base, method="post", url="http://alpha.example/b", body="B",
        set_headers={"x-keep": "k2", "X-New": "n"}, drop_headers=["User-Agent"],
    )
    # base is untouched (immutability -> audit trail preserved)
    assert base.method == "GET" and base.url == "http://alpha.example/a" and base.body is None
    assert ("User-Agent", "spoof") in base.headers
    # edited reflects every change; set_headers is case-insensitive (last wins), UA dropped
    assert edited.method == "POST" and edited.url == "http://alpha.example/b" and edited.body == "B"
    names = dict(edited.headers)
    assert names.get("x-keep") == "k2" and names.get("X-New") == "n"
    assert not any(k.lower() == "user-agent" for k, _ in edited.headers)


def test_mutate_body_sentinel_distinguishes_clear_from_unchanged() -> None:
    base = RepeaterRequest.capture("http://alpha.example/a", body="orig")
    assert mutate(base).body == "orig"              # omitted -> unchanged
    assert mutate(base, body=None).body is None     # explicit None -> cleared
    assert mutate(base, body="new").body == "new"


def test_base_url_of_strips_path_and_defaults_https() -> None:
    assert base_url_of("http://h:8080/a/b?x=1#f") == "http://h:8080"
    assert base_url_of("alpha.example/a") == "https://alpha.example"


# ---------------------------------------------------------------------------
# GATED replay — the load-bearing safety tests
# ---------------------------------------------------------------------------


def test_in_scope_replay_succeeds_through_the_gate_chain(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/api/orders/1").respond_with_data(
        '{"order_id": 1}', status=200, content_type="application/json",
    )
    rep = Repeater(slug="alpha", prompt_callback=_deny)
    req = RepeaterRequest.capture(httpserver.url_for("/api/orders/1"))
    ex = rep.replay(req)
    rep.close()

    assert ex.ok and ex.sent and not ex.refused
    assert ex.status == 200
    assert "order_id" in (ex.response or {}).get("body", "")
    # the (request, response) pair is recorded in the transcript (audit trail)
    assert len(rep.transcript()) == 1 and rep.transcript()[0] is ex
    # on-disk evidence archive was written by the gated executor
    evidence_root = _paths.target_dir("alpha") / "evidence"
    assert evidence_root.exists()
    captured = list(evidence_root.iterdir())
    assert captured, "expected at least one evidence/<action_id>/ dir"
    files = {p.name for p in captured[0].iterdir()}
    assert {"request.http", "response.http", "response.body"} <= files


def test_out_of_scope_replay_is_refused_and_sends_nothing(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    # in-scope host is alpha.example; the replay points at the local httpserver (a DIFFERENT host)
    isolated_engagement("alpha", "alpha.example")
    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.refused and not ex.sent and ex.response is None
    assert ex.gate == "scope"
    assert len(httpserver.log) == 0                 # nothing ever left the host
    assert len(rep.transcript()) == 1               # the refusal is still recorded


def test_unsigned_charter_refuses_replay(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host, signed=False)
    httpserver.expect_request("/x").respond_with_data("ok")
    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.refused and ex.gate == "scope" and not ex.sent


# ---------------------------------------------------------------------------
# W16-2 — the OFFENSIVE repeater PINS the governance trust root (parity with engage.py)
#
# helpers: route the authority store + governance trust root under tmp (deterministic regardless
# of any real deployment material on the box) and build EngagementAuthority docs.
# ---------------------------------------------------------------------------


def _isolate_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, trust_root: bool):
    """Route ``authority_path`` and ``trust_root_path`` under ``tmp_path``. When ``trust_root`` is
    True, provision a 1-of-1 governance trust root (so the repeater loads a provisioned authority
    VERIFIED); else the trust-root path is left ABSENT so ``load_trust_root()`` returns None.
    Returns ``(authority_path, signer)`` where ``signer`` is ``{kid: priv}`` (empty if no root)."""
    from framework.v2.common import paths as _p
    from framework.v2.entitlement import provision

    apath = tmp_path / "alpha.authority.json"
    trpath = tmp_path / "trust-root.json"
    arpath = tmp_path / "authority-root.json"
    monkeypatch.setattr(_p, "authority_path", lambda s: apath)
    monkeypatch.setattr(_p, "trust_root_path", lambda: trpath)
    # Phase 0.1 decouple: the repeater gate reads the authority root via _engage_authority_trust_root,
    # which now loads the DEDICATED authority-root store (not the entitlement trust root) — provision THERE.
    monkeypatch.setattr(_p, "authority_root_path", lambda: arpath)
    signer: dict = {}
    if trust_root:
        from framework.v2.authority.store import write_authority_root
        ak, priv = provision.new_authorizer("a0", "Authoriser 0")
        write_authority_root(provision.build_trust_root([ak], threshold=1))
        signer = {"a0": priv}
    return apath, signer


def _repeater_authority(host: str, *, not_before=None, not_after=None,
                        allow_destructive: bool = True, max_actions: int = 10_000):
    from datetime import datetime, timedelta, timezone

    from framework.v2.authority.models import EngagementAuthority, TargetEnvironment
    now = datetime.now(timezone.utc)
    return EngagementAuthority(
        engagement_slug="alpha",
        environment=TargetEnvironment.TWIN,
        scope=[host],
        not_before=not_before or (now - timedelta(hours=1)),
        not_after=not_after or (now + timedelta(hours=1)),
        allow_destructive=allow_destructive,
        max_actions=max_actions,
    )


def test_expired_authority_refuses_replay(
    isolated_engagement, grant_exploit, httpserver: HTTPServer, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review-fix regression, now under the W16-2 signed regime: the repeater PINS the governance
    # trust root, so a SIGNED EngagementAuthority is loaded VERIFIED and its CLOSED time-box refuses
    # a replay through the same authority gate as the production engage path — even though the
    # charter still lists the host and the kill-switch is untripped.
    from datetime import datetime, timezone

    from framework.v2.authority.signing import sign_authority
    from framework.v2.authority.store import save_signed_authority

    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    apath, signer = _isolate_auth(tmp_path, monkeypatch, trust_root=True)
    save_signed_authority(sign_authority(_repeater_authority(
        httpserver.host,
        not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2020, 1, 2, tzinfo=timezone.utc),   # window closed years ago
    ), signer), apath)

    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.refused and not ex.sent               # the closed authorization window refuses the replay
    assert len(httpserver.log) == 0                 # nothing ever left the host


def test_repeater_refuses_unsigned_authority_when_trust_root_present(
    isolated_engagement, grant_exploit, httpserver: HTTPServer, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """W16-2 FAIL-BEFORE / PASS-AFTER + NEGATIVE CONTROL for the OFFENSIVE repeater path.

    A governance trust root is provisioned and an attacker-writable UNSIGNED authority granting the
    world (in scope, destructive, a huge budget, a wide-open window) is written. With the W16-2 pin
    the repeater loads the authority VERIFIED — an unsigned doc fails that load, the executor's
    ``_authority_gate`` fails closed, and NOT ONE request reaches the server.

    NEGATIVE CONTROL / fail-before: reverting only the repeater pin (``trust_root=None``) restores
    the old ``load_authority`` path — the unsigned doc is TRUSTED and the replay reaches the server,
    so ``len(httpserver.log) == 0`` flips to non-empty. That is the assertion that proves the pin,
    not some unrelated gate, is doing the work."""
    from framework.v2.authority.store import save_authority

    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    apath, _ = _isolate_auth(tmp_path, monkeypatch, trust_root=True)
    # attacker-writable UNSIGNED authority granting itself the world (in-window, in-scope).
    save_authority(_repeater_authority(httpserver.host, allow_destructive=True,
                                       max_actions=1_000_000), apath)

    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.refused and not ex.sent, "unsigned authority was TRUSTED — the repeater did not pin the trust root"
    assert len(httpserver.log) == 0, "a request leaked despite an unverifiable (unsigned) authority"


def test_repeater_refuses_tampered_signed_authority(
    isolated_engagement, grant_exploit, httpserver: HTTPServer, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A validly-signed authority whose on-disk document is then tampered (scope widened, budget
    inflated) must fail the verified load and be refused before any I/O."""
    import json

    from framework.v2.authority.signing import sign_authority
    from framework.v2.authority.store import save_signed_authority

    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    apath, signer = _isolate_auth(tmp_path, monkeypatch, trust_root=True)
    save_signed_authority(sign_authority(_repeater_authority(httpserver.host), signer), apath)
    blob = json.loads(apath.read_text(encoding="utf-8"))
    blob["document"]["scope"] = ["*"]
    blob["document"]["max_actions"] = 1_000_000
    apath.write_text(json.dumps(blob), encoding="utf-8")

    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.refused and not ex.sent
    assert len(httpserver.log) == 0, "tampered signed authority was trusted — a request leaked"


def test_repeater_accepts_correctly_signed_authority(
    isolated_engagement, grant_exploit, httpserver: HTTPServer, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NEGATIVE CONTROL for the refusals above: the pinned gate is NOT a blanket deny. A correctly-
    signed, in-window, in-scope authority is ACCEPTED and the (non-destructive) replay reaches the
    server."""
    from framework.v2.authority.signing import sign_authority
    from framework.v2.authority.store import save_signed_authority

    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok", status=200)
    apath, signer = _isolate_auth(tmp_path, monkeypatch, trust_root=True)
    save_signed_authority(sign_authority(_repeater_authority(httpserver.host), signer), apath)

    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.ok and ex.sent and not ex.refused, "a correctly-signed authority was refused — the gate is a no-op deny"
    assert ex.status == 200
    assert len(httpserver.log) == 1


def test_repeater_refuses_when_authority_provisioned_but_no_trust_root(
    isolated_engagement, grant_exploit, httpserver: HTTPServer, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An EngagementAuthority is provisioned but NO governance trust root is discoverable to verify
    it. ``_engage_authority_trust_root`` raises ``EngagementRefused``; the repeater must fail the
    replay CLOSED (gate ``authority``) rather than build an UNPINNED executor that would apply the
    authority unsigned — the exact fail-open W16-2 closes, now also on the offensive repeater path."""
    from framework.v2.authority.store import save_authority

    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    apath, _ = _isolate_auth(tmp_path, monkeypatch, trust_root=False)   # trust-root path left ABSENT
    save_authority(_repeater_authority(httpserver.host), apath)          # authority IS provisioned

    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.refused and ex.gate == "authority" and not ex.sent
    assert len(httpserver.log) == 0, "an unpinned-but-provisioned authority leaked a request"


def test_repeater_greenfield_no_authority_still_replays(
    isolated_engagement, grant_exploit, httpserver: HTTPServer, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NEGATIVE CONTROL against over-blocking: greenfield (no authority document, no trust root)
    resolves to a None trust root, so the documented kill-switch-only path is preserved and a
    legitimate replay still reaches the server — the fix does not break the normal path."""
    from framework.v2.engage import _engage_authority_trust_root

    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok", status=200)
    _isolate_auth(tmp_path, monkeypatch, trust_root=False)   # neither authority nor trust root exists

    assert _engage_authority_trust_root("alpha") is None     # greenfield -> no pin

    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.ok and ex.sent and not ex.refused, "greenfield replay was broken — no request reached the server"
    assert ex.status == 200
    assert len(httpserver.log) == 1


def test_unentitled_replay_is_refused_and_sends_nothing(
    isolated_engagement, httpserver: HTTPServer, monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")

    from framework.v2 import entitlement

    def _deny_cap(cap):
        raise RuntimeError(f"not entitled to {cap}")

    monkeypatch.setattr(entitlement, "require_capability", _deny_cap)
    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.refused and ex.gate == "entitlement" and not ex.sent
    assert len(httpserver.log) == 0                 # entitlement gate fired BEFORE any request


def test_tripped_kill_switch_refuses_replay_and_sends_nothing(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("operator halt")

    rep = Repeater(slug="alpha")
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    assert ex.refused and ex.gate == "kill-switch" and not ex.sent
    assert len(httpserver.log) == 0


def test_destructive_replay_default_denies_and_sends_nothing(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/api/orders", method="POST").respond_with_data("ok")
    # POST is destructive -> the executor's per-request destructive-confirm prompts; default-deny.
    rep = Repeater(slug="alpha", prompt_callback=_deny)
    ex = rep.replay(RepeaterRequest.capture(
        httpserver.url_for("/api/orders"), method="POST", body="{}"))
    rep.close()

    assert ex.refused and ex.gate == "http-gate"
    assert "destructive" in ex.note.lower()
    assert len(httpserver.log) == 0


def test_destructive_replay_proceeds_when_operator_allows(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/api/orders", method="POST").respond_with_data(
        '{"ok": true}', status=201, content_type="application/json")
    rep = Repeater(slug="alpha", prompt_callback=_allow)
    ex = rep.replay(RepeaterRequest.capture(
        httpserver.url_for("/api/orders"), method="POST", body="{}"))
    rep.close()

    assert ex.ok and ex.sent and ex.status == 201


def test_correlatable_ua_is_forced_and_operator_ua_is_stripped(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    rep = Repeater(slug="alpha")
    # operator tries to spoof a browser UA (identity rotation / evasion) — it MUST be stripped
    ex = rep.replay(RepeaterRequest.capture(
        httpserver.url_for("/x"),
        headers={"User-Agent": "Mozilla/5.0 EvilBrowser", "X-Test": "keep"}))
    rep.close()

    assert ex.ok
    received_uas = [r[0].headers.get("User-Agent", "") for r in httpserver.log]
    assert received_uas, "expected a logged request"
    assert all("OBSIDIAN" in ua for ua in received_uas), received_uas
    assert all("EvilBrowser" not in ua for ua in received_uas), received_uas
    # a non-identity header the operator set is preserved (legitimate app testing)
    assert any(r[0].headers.get("X-Test") == "keep" for r in httpserver.log)


def test_per_engagement_budget_is_shared_across_replays(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    rep = Repeater(slug="alpha", request_budget=2)
    req = RepeaterRequest.capture(httpserver.url_for("/x"))
    e1 = rep.replay(req)
    e2 = rep.replay(req)
    e3 = rep.replay(req)          # third replay exceeds the shared budget
    rep.close()

    assert e1.ok and e2.ok
    assert e3.refused and e3.gate == "http-gate" and "budget" in e3.note.lower()
    assert rep.stats()["requests_made"] == 2


def test_dry_run_exercises_gates_but_touches_no_network(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    rep = Repeater(slug="alpha", dry_run=True)
    ex = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    # gates passed (not refused) but the executor never issued the request
    assert not ex.refused
    assert len(httpserver.log) == 0


def test_replay_records_tool_call_and_result_on_the_spine(
    isolated_engagement, grant_exploit, httpserver: HTTPServer, tmp_path: Path,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.agents.spine_sink import SpineSink
    bb = open_blackboard(db_path=tmp_path / "spine.sqlite")
    rep = Repeater(slug="alpha", sink=SpineSink(bb, "alpha"))
    rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    calls = bb.read(engagement="alpha", kinds=["tool_call"])
    results = bb.read(engagement="alpha", kinds=["tool_result"])
    bb.close()
    assert len(calls) == 1 and calls[0].payload["tool"] == "http_repeater"
    assert calls[0].payload["capability"] == "exploit_execution"
    assert len(results) == 1 and results[0].payload["ok"] is True
    assert results[0].parent_id == calls[0].id       # provenance edge


def test_refused_replay_records_a_refusal_on_the_spine(
    isolated_engagement, grant_exploit, httpserver: HTTPServer, tmp_path: Path,
) -> None:
    isolated_engagement("alpha", "alpha.example")     # httpserver is out of scope
    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.agents.spine_sink import SpineSink
    bb = open_blackboard(db_path=tmp_path / "spine.sqlite")
    rep = Repeater(slug="alpha", sink=SpineSink(bb, "alpha"))
    rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    rep.close()

    refusals = bb.read(engagement="alpha", kinds=["refusal"])
    bb.close()
    assert refusals and refusals[0].payload["gate"] == "scope"
    assert len(httpserver.log) == 0


# ---------------------------------------------------------------------------
# prove-don't-guess — a repeater response becomes a finding only via an oracle
# ---------------------------------------------------------------------------


def test_target_url_must_equal_scope_gated_url() -> None:
    # A caller that diverges the scope-gated target from the issued URL is refused (fail-closed):
    # the tool never issues a URL that was not the one the scope gate validated.
    from framework.v2.agents.tools import ToolContext, invoke_tool
    from framework.v2.repeater import build_repeater_registry
    registry, tool = build_repeater_registry()
    # bypass the façade to force a divergent target/url pair straight at the tool
    res = tool.run(
        {"target": "http://alpha.example/a", "url": "http://alpha.example/b"},
        ToolContext(slug="alpha"),
    )
    tool.close()
    assert not res.ok and "must equal" in res.note


def test_baseline_probe_pair_builds_oracle_context_not_a_finding(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/item", query_string="id=1").respond_with_data(
        "welcome user", status=200)
    httpserver.expect_request("/item", query_string="id=1'").respond_with_data(
        "sql error near", status=500)
    rep = Repeater(slug="alpha")
    baseline = rep.replay(RepeaterRequest.capture(httpserver.url_for("/item") + "?id=1"))
    probe = rep.replay(RepeaterRequest.capture(httpserver.url_for("/item") + "?id=1'"))
    rep.close()

    assert baseline.sent and probe.sent
    # the pair is EVIDENCE for the deterministic differential oracle — never a finding on its own
    oracle_context = baseline.oracle_context_with(probe, bug_class="boolean_sqli")
    assert isinstance(oracle_context, dict)
    assert oracle_context.get("bug_class") == "boolean_sqli"
    assert oracle_context.get("baseline") and oracle_context.get("mutated")
    # a repeater exchange is not a finding type
    assert isinstance(baseline, RepeaterExchange)


def test_oracle_context_requires_captured_responses_on_both_sides(
    isolated_engagement, grant_exploit, httpserver: HTTPServer,
) -> None:
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/x").respond_with_data("ok")
    rep = Repeater(slug="alpha")
    sent = rep.replay(RepeaterRequest.capture(httpserver.url_for("/x")))
    # a refused exchange has no response to adjudicate
    refused = RepeaterExchange(request=RepeaterRequest.capture("http://x/y"), refused=True, gate="scope")
    rep.close()
    with pytest.raises(ValueError):
        sent.oracle_context_with(refused)
