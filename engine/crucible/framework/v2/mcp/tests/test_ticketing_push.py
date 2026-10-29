"""
Tests for mcp.ticketing_push — the OPERATOR-ONLY ticketing-OUT push adapter (GitHub Issues).

These assert the adapter's security contract WITHOUT real network I/O (an injected ``MockTransport``):
  * a fake POST SUCCEEDS and is shaped as a bounded Bearer POST to the issues endpoint;
  * ORACLE-VERIFIED ONLY — a non-oracle-verified finding is refused before any byte;
  * NO TOKEN → refused at request time (we never push unauthenticated);
  * a ``169.254.169.254`` host and a scoped name that RESOLVES to metadata/RFC1918 are refused by the
    never-liftable FLOOR; an off-allowlist host is refused by the NAME control;
  * a redirect is NEVER followed; a non-2xx is an error; the bearer never appears in ``repr``;
  * the high-level ``push_finding`` is OFF-by-default (refuses when nothing is provisioned), resolves the
    token off-spine, and keys the receipt + audit by ``(tenant_id, slug)``;
  * STRUCTURAL: a pushed finding NEVER becomes a FACT (no intel/sensor/grounding import, no promotion seam).

The floor refusals hold under the pure-stdlib backstop; the success/name/redirect cases go through an
injected ``MockTransport``, so nothing here touches the network.
"""

from __future__ import annotations

import ast
import json
import socket
from pathlib import Path

import pytest

# httpx + vigil_core (the egress deps) — importorskip per the two-env test guidance.
pytest.importorskip("framework.v2.agents.egress_guard")

import httpx  # noqa: E402

from framework.v2.agents.egress_guard import EgressAllowlist, SovereignHttpxTransport  # noqa: E402
from framework.v2.common.errors import SovereigntyViolation  # noqa: E402
from framework.v2.mcp import ticketing_push as TP  # noqa: E402
from framework.v2.mcp.ticketing_config import TicketingTarget  # noqa: E402

_HOST = "api.github.com"


def _target(**over) -> TicketingTarget:
    kw = dict(id="gh", kind="github_issues", host=_HOST, repo="acme/widgets",
              auth_env="GH_TOKEN", tenant_id="acme", slug="alpha")
    kw.update(over)
    return TicketingTarget(**kw)


def _allow(*hosts: str) -> EgressAllowlist:
    return EgressAllowlist(extra_hosts=hosts or (_HOST,))


def _finding(**over) -> TP.TicketFinding:
    kw = dict(finding_slug="001-sqli", title="SQLi in /login", severity="High",
              bug_class="injection", surface="/login", summary="A classic.", impact="Full DB read.",
              cvss_vector="CVSS:3.1/AV:N", verified_by_oracle=True, oracle_kind="differential_response")
    kw.update(over)
    return TP.TicketFinding(**kw)


def _mock(handler):
    return httpx.MockTransport(handler)


def _created_resp(request: httpx.Request) -> httpx.Response:
    return httpx.Response(201, json={"number": 42, "html_url": "https://github.com/acme/widgets/issues/42"})


# ----------------------------------------------------------- success + request shaping (fake, no network)


def test_fake_push_succeeds_and_is_a_bounded_bearer_post() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = request.read()
        return _created_resp(request)

    p = TP.GithubIssuesPusher(_target(), _allow(), token="op-secret-123", inner=_mock(handler))
    try:
        receipt = p.push(_finding())
    finally:
        p.close()

    assert receipt.ok is True and receipt.issue_number == 42
    assert receipt.issue_url == "https://github.com/acme/widgets/issues/42"
    assert receipt.target_id == "gh" and receipt.tenant_id == "acme" and receipt.slug == "alpha"
    assert receipt.direction == "outbound" and receipt.is_fact is False

    assert captured["method"] == "POST"
    assert captured["url"] == "https://api.github.com/repos/acme/widgets/issues"
    assert captured["headers"]["authorization"] == "Bearer op-secret-123"
    assert captured["headers"]["accept"] == "application/vnd.github+json"
    assert "user-agent" in captured["headers"] and "VIGIL" in captured["headers"]["user-agent"]
    body = json.loads(captured["body"].decode())
    assert body["title"].startswith("[VIGIL][High]") and "SQLi" in body["title"]
    assert "one-way notification" in body["body"].lower()
    assert "labels" not in body          # no labels by default (avoids a 422 on a non-existent label)


def test_labels_are_sent_only_when_provided() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return _created_resp(request)

    p = TP.GithubIssuesPusher(_target(), _allow(), token="t", inner=_mock(handler))
    try:
        p.push(_finding(), labels=("vigil", "security"))
    finally:
        p.close()
    assert captured["body"]["labels"] == ["vigil", "security"]


def test_201_with_unparseable_body_still_succeeds_thin_receipt() -> None:
    # The push ALREADY succeeded (2xx); a junk body just yields a thinner receipt — never a crash.
    p = TP.GithubIssuesPusher(_target(), _allow(), token="t",
                              inner=_mock(lambda r: httpx.Response(201, content=b"not json")))
    try:
        receipt = p.push(_finding())
    finally:
        p.close()
    assert receipt.ok is True and receipt.issue_number is None and receipt.issue_url is None


# ----------------------------------------------------------- oracle-verified + token gates (fail-closed)


def test_non_oracle_verified_finding_is_refused_before_any_byte() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _created_resp(request)

    p = TP.GithubIssuesPusher(_target(), _allow(), token="t", inner=_mock(handler))
    try:
        with pytest.raises(TP.TicketingPushError) as exc:
            p.push(_finding(verified_by_oracle=False))
        assert "oracle-verified" in str(exc.value).lower()
        assert calls == []                 # refused before the inner transport
    finally:
        p.close()


def test_missing_token_is_refused_at_request_time() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _created_resp(request)

    # constructs fine (token resolved out-of-band may be absent); the REFUSAL is at push time.
    p = TP.GithubIssuesPusher(_target(), _allow(), token=None, inner=_mock(handler))
    try:
        with pytest.raises(TP.TicketingPushError) as exc:
            p.push(_finding())
        assert "unauthenticated" in str(exc.value).lower()
        assert calls == []
    finally:
        p.close()


# ----------------------------------------------------------- floor refusals (fail-closed, no socket)


def _resolver(*addrs: str):
    def fake(host, port, proto=0):  # noqa: ANN001
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, 1, 6, "", (a, port or 0))
                for a in addrs]
    return fake


def test_metadata_host_is_refused_fail_closed() -> None:
    # host=169.254.169.254, even forced onto the name allowlist, is refused before any socket (inner=None).
    p = TP.GithubIssuesPusher(_target(host="169.254.169.254"), _allow("169.254.169.254"), token="t")
    try:
        with pytest.raises(SovereigntyViolation):
            p.push(_finding())
    finally:
        p.close()


def test_scoped_name_resolving_to_metadata_is_refused_by_the_floor() -> None:
    p = TP.GithubIssuesPusher(_target(), _allow(), token="t", resolver=_resolver("169.254.169.254"))
    try:
        with pytest.raises(SovereigntyViolation) as exc:
            p.push(_finding())
        assert "egress floor" in str(exc.value).lower()
    finally:
        p.close()


def test_scoped_name_resolving_to_rfc1918_is_refused_by_the_floor() -> None:
    p = TP.GithubIssuesPusher(_target(), _allow(), token="t", resolver=_resolver("10.0.0.5"))
    try:
        with pytest.raises(SovereigntyViolation):
            p.push(_finding())
    finally:
        p.close()


# ----------------------------------------------------------- name control + redirects (fake inner)


def test_off_allowlist_host_is_refused_before_any_byte() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return _created_resp(request)

    # the allowlist permits only a DIFFERENT host; the target host is off-allowlist.
    p = TP.GithubIssuesPusher(_target(), _allow("elsewhere.example"), token="t", inner=_mock(handler))
    try:
        with pytest.raises(SovereigntyViolation) as exc:
            p.push(_finding())
        assert "sovereign mode" in str(exc.value).lower()   # the NAME control, not the floor
        assert calls == []
    finally:
        p.close()


def test_redirect_is_never_followed() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://elsewhere.example/moved"})

    p = TP.GithubIssuesPusher(_target(), _allow(_HOST, "elsewhere.example"), token="t",
                              inner=_mock(handler))
    try:
        with pytest.raises(TP.TicketingPushError) as exc:
            p.push(_finding())
        assert "302" in str(exc.value)
        assert calls == ["https://api.github.com/repos/acme/widgets/issues"]
    finally:
        p.close()


def test_non_2xx_status_is_an_error() -> None:
    p = TP.GithubIssuesPusher(_target(), _allow(), token="t",
                              inner=_mock(lambda r: httpx.Response(401, json={"message": "Bad credentials"})))
    try:
        with pytest.raises(TP.TicketingPushError) as exc:
            p.push(_finding())
        assert "401" in str(exc.value)
    finally:
        p.close()


# ----------------------------------------------------------- bounds, URL + token hygiene


def test_oversize_request_is_refused_and_never_sent() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _created_resp(request)

    p = TP.GithubIssuesPusher(_target(), _allow(), token="t", inner=_mock(handler), max_bytes=64)
    try:
        with pytest.raises(TP.TicketingPushError):
            p.push(_finding(summary="A" * 500))
        assert calls == []
    finally:
        p.close()


def test_oversize_response_is_refused() -> None:
    big = b'{"number":1,"html_url":"' + b"A" * 5000 + b'"}'
    p = TP.GithubIssuesPusher(_target(), _allow(), token="t",
                              inner=_mock(lambda r: httpx.Response(201, content=big)), max_bytes=256)
    try:
        with pytest.raises(TP.TicketingPushError):
            p.push(_finding())
    finally:
        p.close()


def test_crlf_in_token_is_refused_at_construction() -> None:
    with pytest.raises(TP.TicketingPushError):
        TP.GithubIssuesPusher(_target(), _allow(), token="good\r\nX-Injected: 1")


def test_bad_allowlist_and_target_types_refused_at_construction() -> None:
    with pytest.raises(TP.TicketingPushError):
        TP.GithubIssuesPusher(_target(), allowlist={"not": "an allowlist"}, token="t")  # type: ignore[arg-type]
    with pytest.raises(TP.TicketingPushError):
        TP.GithubIssuesPusher({"not": "a target"}, _allow(), token="t")  # type: ignore[arg-type]


def test_unsupported_kind_refused_at_construction() -> None:
    with pytest.raises(TP.TicketingPushError):
        TP.GithubIssuesPusher(_target(kind="jira"), _allow(), token="t")


def test_bearer_token_never_appears_in_repr() -> None:
    p = TP.GithubIssuesPusher(_target(), _allow(), token="super-secret-token-value",
                              inner=_mock(_created_resp))
    try:
        assert "super-secret-token-value" not in repr(p)
        assert "<set>" in repr(p) and "acme/widgets" in repr(p)
    finally:
        p.close()


def test_ipv6_host_is_bracketed_in_the_url() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return _created_resp(request)

    # ::1 is a loopback literal — the floor permits loopback, but we use inner=mock anyway (name-only).
    p = TP.GithubIssuesPusher(_target(host="::1"), _allow("::1"), token="t", inner=_mock(handler))
    try:
        p.push(_finding())
    finally:
        p.close()
    assert captured["url"] == "https://[::1]/repos/acme/widgets/issues"


# ----------------------------------------------------------- wiring (structural)


def test_wiring_is_sovereign_name_enforced_and_no_redirects() -> None:
    p = TP.GithubIssuesPusher(_target(), _allow(), token="t", inner=_mock(_created_resp))
    try:
        assert isinstance(p._sov, SovereignHttpxTransport)
        assert p._sov._sovereign_only is False          # the operator allowlist is ALWAYS enforced
        assert p._client.follow_redirects is False       # no redirect is ever followed
    finally:
        p.close()


# ----------------------------------------------------------- TicketFinding.from_finding duck-typing


def test_from_finding_duck_types_dict_and_object() -> None:
    d = {"finding_slug": "003-xss", "title": "XSS", "severity": "Medium", "verified_by_oracle": True,
         "oracle_kind": "sanitizer_signal"}
    tf = TP.TicketFinding.from_finding(d)
    assert tf.finding_slug == "003-xss" and tf.verified_by_oracle is True and tf.oracle_kind == "sanitizer_signal"

    class _F:  # a FindingPayload-like object
        finding_slug = "004-ssrf"
        title = "SSRF"
        severity = "High"
        verified_by_oracle = False
    tf2 = TP.TicketFinding.from_finding(_F())
    assert tf2.finding_slug == "004-ssrf" and tf2.verified_by_oracle is False  # default-false fail-closed


def test_from_finding_defaults_unknown_to_unverified() -> None:
    tf = TP.TicketFinding.from_finding({"title": "bare"})
    assert tf.finding_slug == "unknown" and tf.verified_by_oracle is False


# ----------------------------------------------------------- the high-level push_finding orchestrator


def _write_cfg(root: Path, slug: str, entries: list) -> None:
    d = root / "targets" / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "ticketing-targets.json").write_text(json.dumps(entries), encoding="utf-8")


_OK_CFG = [{"id": "gh", "kind": "github_issues", "host": _HOST, "repo": "acme/widgets",
            "auth_env": "GH_TOKEN"}]


def test_push_finding_off_by_default_when_not_provisioned(tmp_path: Path) -> None:
    # no config file at all → the connector is OFF → refuse (fail-closed), never a silent no-op push.
    with pytest.raises(TP.TicketingPushError) as exc:
        TP.push_finding("alpha", "gh", _finding(), root=tmp_path, allowlist=_allow(), audit_root=False)
    assert "provisioned" in str(exc.value).lower()


def test_push_finding_refuses_when_token_env_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_cfg(tmp_path, "alpha", _OK_CFG)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(TP.TicketingPushError) as exc:
        TP.push_finding("alpha", "gh", _finding(), root=tmp_path, allowlist=_allow(), audit_root=False)
    assert "no api token" in str(exc.value).lower()


def test_push_finding_resolves_token_offspine_and_keys_by_tenant_slug(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CRUCIBLE_TENANT", "acme")
    monkeypatch.setenv("GH_TOKEN", "env-resolved-token")
    _write_cfg(tmp_path, "alpha", _OK_CFG)

    seen: dict = {}

    class _FakePusher:
        def __init__(self, target, allowlist, token, slug):
            seen["token"] = token
            seen["slug"] = slug
            seen["target_tenant"] = target.tenant_id
            self._t = target

        def push(self, tf, labels=()):
            return TP.PushReceipt(ok=True, target_id=self._t.id, tenant_id=self._t.tenant_id,
                                  slug=self._t.slug, finding_slug=tf.finding_slug, issue_number=7,
                                  issue_url="u")

        def close(self):
            pass

    receipt = TP.push_finding(
        "alpha", "gh", _finding(), root=tmp_path, allowlist=_allow(),
        pusher_factory=lambda t, a, tok, s: _FakePusher(t, a, tok, s), audit_root=False)

    assert seen["token"] == "env-resolved-token"     # resolved off-spine from GH_TOKEN, not the config
    assert seen["target_tenant"] == "acme"           # (tenant_id, slug) stamped on the loaded target
    assert receipt.tenant_id == "acme" and receipt.slug == "alpha"
    assert receipt.is_fact is False and receipt.issue_number == 7


def test_push_finding_end_to_end_with_mock_transport(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_TENANT", "acme")
    monkeypatch.setenv("GH_TOKEN", "env-token")
    _write_cfg(tmp_path, "alpha", _OK_CFG)

    def factory(target, allowlist, token, slug):
        return TP.GithubIssuesPusher(target, allowlist, token=token, slug=slug, inner=_mock(_created_resp))

    receipt = TP.push_finding("alpha", "gh", _finding(), root=tmp_path, allowlist=_allow(),
                              pusher_factory=factory, audit_root=str(tmp_path))
    assert receipt.ok and receipt.issue_number == 42 and receipt.tenant_id == "acme"

    # the best-effort audit record landed, keyed by (tenant_id, slug), and is NOT a fact.
    audit = (tmp_path / "targets" / "alpha" / "ticketing-pushes.jsonl").read_text().strip()
    rec = json.loads(audit)
    assert rec["tenant_id"] == "acme" and rec["slug"] == "alpha"
    assert rec["is_fact"] is False and rec["direction"] == "outbound"
    assert rec["target_id"] == "gh" and rec["finding_slug"] == "001-sqli"


def test_append_push_audit_is_keyed_and_never_raises(tmp_path: Path) -> None:
    r = TP.PushReceipt(ok=True, target_id="gh", tenant_id="acme", slug="alpha",
                       finding_slug="001-sqli", issue_number=1, issue_url="u")
    TP.append_push_audit("alpha", r, root=str(tmp_path))
    rec = json.loads((tmp_path / "targets" / "alpha" / "ticketing-pushes.jsonl").read_text().strip())
    assert rec["tenant_id"] == "acme" and rec["slug"] == "alpha" and rec["is_fact"] is False
    # never raises even on a bogus root
    TP.append_push_audit("alpha", r, root="/this/does/not/exist/\x00bad")


# ----------------------------------------------------------- STRUCTURAL: a pushed finding is NEVER a FACT


_FORBIDDEN_IMPORT_TOKENS = ("intel", "sensor", "grounding", "ingest")


def _imported_modules(src: str) -> set[str]:
    """Every module name imported by the source (top-level AND function-local), via AST (ignores comments
    + docstrings, so the module's own doctrine prose about 'grounding'/'facts' never false-positives)."""
    tree = ast.parse(src)
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mods.add(node.module or "")
            mods.update(f"{node.module or ''}.{a.name}" for a in node.names)
    return mods


def test_push_module_imports_no_fact_ingestion_machinery() -> None:
    """The one-way doctrine, made structural: ticketing_push imports NONE of the intel / sensor / grounding
    / ingest machinery — so there is no code path by which a pushed finding (or the API response) could be
    turned back into an Observation/Finding/FACT. (Only a CRUCIBLE oracle mints a fact.)"""
    src = Path(TP.__file__).read_text(encoding="utf-8")
    for mod in _imported_modules(src):
        low = mod.lower()
        assert not any(tok in low for tok in _FORBIDDEN_IMPORT_TOKENS), \
            f"ticketing_push must not import fact-ingestion machinery, found import of {mod!r}"


def test_pusher_exposes_no_promotion_or_sensor_seam() -> None:
    # no normalize/confirm/reverify/promote/run — a sensor pipeline cannot treat the pusher as a lead source.
    for attr in ("normalize", "confirm", "_reverify", "reverify", "promote", "run"):
        assert not hasattr(TP.GithubIssuesPusher, attr), attr
    # the receipt is an inert record: no belief/credibility/grounding/oracle field; is_fact pinned False.
    fields = set(TP.PushReceipt.__dataclass_fields__)
    assert not (fields & {"belief", "credibility", "reliability", "grounding", "oracle_kind",
                          "observation", "finding", "confidence"})
    r = TP.PushReceipt(ok=True, target_id="gh", tenant_id=None, slug="s", finding_slug="f")
    assert r.is_fact is False and r.direction == "outbound"
    assert r.audit_record()["is_fact"] is False


def test_push_finding_enforces_disjointness_even_with_a_caller_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """red-pen MED: the ticketing-sink / attack-scope disjointness refusal now runs UNCONDITIONALLY — a
    caller-supplied allowlist must NOT bypass it (else a finding could be filed INTO a host under attack)."""
    monkeypatch.setenv("CRUCIBLE_TENANT", "acme")
    monkeypatch.setenv("GH_TOKEN", "t")
    _write_cfg(tmp_path, "alpha", _OK_CFG)
    monkeypatch.setattr(TP, "_target_scope", lambda slug: (_HOST,))   # attack scope CONTAINS the ticketing host

    def factory(target, allowlist, token, slug):
        raise AssertionError("the pusher must not be constructed when disjointness refuses")

    with pytest.raises(TP.TicketingPushError, match="attack scope"):
        TP.push_finding("alpha", "gh", _finding(), root=tmp_path, allowlist=_allow(),
                        pusher_factory=factory, audit_root=False)      # a caller allowlist no longer bypasses it


def test_push_finding_allowlist_none_refuses_a_conflicting_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """red-pen MED coverage: the allowlist=None path also refuses a conflicting host (before any default build)."""
    monkeypatch.setenv("CRUCIBLE_TENANT", "acme")
    monkeypatch.setenv("GH_TOKEN", "t")
    _write_cfg(tmp_path, "alpha", _OK_CFG)
    monkeypatch.setattr(TP, "_target_scope", lambda slug: (_HOST,))
    with pytest.raises(TP.TicketingPushError, match="attack scope"):
        TP.push_finding("alpha", "gh", _finding(), root=tmp_path, audit_root=False)   # no explicit allowlist
