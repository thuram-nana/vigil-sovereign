"""
Tests for mcp.evidence_config — the OPERATOR-ONLY external-MCP evidence-server egress allowlist.

The config is a SEPARATE provisioning axis (operator infra, disjoint from the attack target scope),
default-EMPTY and fail-closed: an absent/malformed file, an unsafe slug, or a bad entry degrades to an
empty/partial list — never a crash, never a wildcard host, never a half-registered entry. A credential is
referenced ONLY by env-var NAME (``auth_env``); an inline secret is refused. Pure stdlib + the file; no
real host is reached and no secret is ever resolved here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.mcp import evidence_config as EC


def _write(root: Path, slug: str, payload: object) -> Path:
    """Write the operator config to ``<root>/targets/<slug>/mcp-evidence-servers.json``."""
    d = root / "targets" / slug
    d.mkdir(parents=True, exist_ok=True)
    p = d / EC.EVIDENCE_SERVERS_FILENAME
    p.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return p


# --- default-empty / fail-closed -------------------------------------------------------------------


def test_absent_file_is_empty_default(tmp_path: Path) -> None:
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert servers == [] and issues == []
    assert EC.load_evidence_servers("alpha", root=tmp_path) == []


def test_unsafe_slug_fails_closed(tmp_path: Path) -> None:
    for bad in ("../evil", "a/b", ".hidden", "x\\y", "c:evil"):
        servers, issues = EC.load_evidence_servers_with_issues(bad, root=tmp_path)
        assert servers == [] and issues and issues[0].code == "unsafe_slug"


def test_malformed_json_is_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", "{ this is not json ")
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert servers == [] and issues and issues[0].code == "malformed_file"


def test_non_list_payload_is_malformed(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", {"id": "x", "transport": "stdio", "command": "x"})
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert servers == [] and issues and issues[0].code == "malformed_file"


def test_load_never_raises_on_garbage(tmp_path: Path) -> None:
    # A grab-bag of hostile shapes must each degrade, never throw.
    for payload in ("", "[", "null", "42", '[1, "x", true, null]', '[{"id": 123}]'):
        _write(tmp_path, "alpha", payload)
        EC.load_evidence_servers("alpha", root=tmp_path)  # must not raise


# --- parse a valid file ----------------------------------------------------------------------------


def test_parse_valid_file_stdio_and_http(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        {"id": "schema_db", "transport": "stdio", "command": "mcp-postgres",
         "args": ["--readonly", "--dsn-env", "EV_DSN"]},
        {"id": "logs_http", "transport": "http", "url": "http://10.0.0.9:8931/mcp",
         "auth_env": "EV_LOGS_TOKEN", "allowed_tools": ["get_logs", "get_logs"]},
    ])
    servers = EC.load_evidence_servers("alpha", root=tmp_path)
    assert [s.id for s in servers] == ["schema_db", "logs_http"]

    stdio = servers[0]
    assert stdio.transport == "stdio" and stdio.command == "mcp-postgres"
    assert stdio.args == ("--readonly", "--dsn-env", "EV_DSN")
    assert stdio.url is None and stdio.host is None

    http = servers[1]
    assert http.transport == "http" and http.url == "http://10.0.0.9:8931/mcp"
    assert http.host == "10.0.0.9"              # exact IP literal extracted
    assert http.auth_env == "EV_LOGS_TOKEN"     # NAME, not a value
    assert http.allowed_tools == ("get_logs",)  # de-duped, order-stable
    assert http.command is None and http.args == ()


def test_http_host_may_be_ip_literal_or_single_hostname(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        {"id": "ipv4", "transport": "http", "url": "http://192.168.10.4:9000/mcp"},
        {"id": "ipv6", "transport": "http", "url": "http://[::1]:7000/"},
        {"id": "host1", "transport": "http", "url": "https://evidence-db:8443/mcp"},
    ])
    servers = EC.load_evidence_servers("alpha", root=tmp_path)
    assert {s.id: s.host for s in servers} == {
        "ipv4": "192.168.10.4", "ipv6": "::1", "host1": "evidence-db"}


# --- reject: duplicate / reserved id ---------------------------------------------------------------


def test_duplicate_id_rejected_first_wins(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        {"id": "dup", "transport": "http", "url": "http://10.0.0.1/mcp"},
        {"id": "DUP", "transport": "http", "url": "http://10.0.0.2/mcp"},  # case-insensitive collision
    ])
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert [s.id for s in servers] == ["dup"]                      # first wins
    assert servers[0].host == "10.0.0.1"
    assert any(i.code == "duplicate_id" for i in issues)


def test_reserved_id_rejected(tmp_path: Path) -> None:
    # `oracle` is the sole FACT authority — an evidence LEAD source must never be able to claim it.
    for rid in ("oracle", "vigil", "Nmap", "system"):
        _write(tmp_path, "alpha", [{"id": rid, "transport": "stdio", "command": "x"}])
        servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
        assert servers == [] and any(i.code == "reserved_id" for i in issues), rid


def test_bad_id_rejected(tmp_path: Path) -> None:
    for bad in ("-leading-hyphen", "has space", "has/slash", "", 123):
        _write(tmp_path, "alpha", [{"id": bad, "transport": "stdio", "command": "x"}])
        servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
        assert servers == [] and any(i.code == "bad_id" for i in issues), bad


# --- reject: over-broad host, wildcard host --------------------------------------------------------


def test_over_broad_host_rejected(tmp_path: Path) -> None:
    # bare '*', whole-TLD wildcard, public-suffix wildcard — the _collector_host_too_broad footguns.
    for url in ("http://*/mcp", "http://*.com/mcp", "http://*.co.uk/mcp"):
        _write(tmp_path, "alpha", [{"id": "x", "transport": "http", "url": url}])
        servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
        assert servers == [], url
        assert any(i.code in ("over_broad_host", "wildcard_host") for i in issues), url


def test_wildcard_host_rejected_even_when_not_too_broad(tmp_path: Path) -> None:
    # A private-base wildcard (`*.internal.example.com`) is NOT "too broad" by the collector rule, but the
    # http evidence host must be a SINGLE hostname/IP literal so the egress floor can pin it — so reject.
    assert EC._host_too_broad("*.internal.example.com") is False      # strictly tighter than the mirror
    _write(tmp_path, "alpha", [
        {"id": "wild", "transport": "http", "url": "https://*.internal.example.com/mcp"}])
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert servers == [] and any(i.code == "wildcard_host" for i in issues)


def test_bad_url_scheme_and_missing_host_rejected(tmp_path: Path) -> None:
    for url in ("file:///etc/passwd", "ftp://host/x", "http:///nohost", "not a url"):
        _write(tmp_path, "alpha", [{"id": "x", "transport": "http", "url": url}])
        servers = EC.load_evidence_servers("alpha", root=tmp_path)
        assert servers == [], url


# --- secrets stay references -----------------------------------------------------------------------


def test_auth_env_is_a_name_not_a_value(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        {"id": "s", "transport": "http", "url": "http://10.0.0.5/mcp", "auth_env": "EV_TOKEN"}])
    servers = EC.load_evidence_servers("alpha", root=tmp_path)
    assert servers[0].auth_env == "EV_TOKEN"
    # The record carries NO token field, and its repr leaks no secret (only the env-var NAME).
    assert not hasattr(servers[0], "token")
    assert "EV_TOKEN" in repr(servers[0])
    assert "secret" not in repr(servers[0]).lower()


def test_inline_secret_key_rejected(tmp_path: Path) -> None:
    # Exact-match keys PLUS compound names a bare exact set misses — auth_token/authToken/auth-token all
    # normalise to "authtoken" (caught by the "token" stem), client_secret/x_api_key/api_token likewise.
    for secret_key in ("token", "auth", "password", "bearer", "api_key", "apiKey", "authorization",
                       "auth_token", "authToken", "auth-token", "api_token", "client_secret", "x_api_key"):
        entry = {"id": "s", "transport": "http", "url": "http://10.0.0.5/mcp", secret_key: "sk-SECRET"}
        _write(tmp_path, "alpha", [entry])
        servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
        assert servers == [], secret_key
        assert any(i.code == "inline_secret" for i in issues), secret_key
        # the secret VALUE must never appear in a surfaced issue message
        assert all("sk-SECRET" not in i.message for i in issues), secret_key


def test_auth_env_itself_is_not_mistaken_for_an_inline_secret(tmp_path: Path) -> None:
    # The ONE sanctioned reference must survive the stem check: "auth_env" normalises to "authenv", which
    # contains no secret stem (bare "auth" stays EXACT-match, never a substring stem).
    _write(tmp_path, "alpha", [
        {"id": "s", "transport": "http", "url": "http://10.0.0.5/mcp", "auth_env": "EV_TOKEN",
         "allowed_tools": ["fetch"]}])
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert len(servers) == 1 and servers[0].auth_env == "EV_TOKEN"
    assert not any(i.code == "inline_secret" for i in issues)


def test_url_query_or_fragment_rejected_as_inline_secret(tmp_path: Path) -> None:
    # A query/fragment is an inline-secret vector (?api_key=…) that would ride in the stored URL and leak
    # via repr/log; an MCP JSON-RPC endpoint needs neither. Refused at the source; the secret never echoes.
    for url in ("http://10.0.0.5/mcp?api_key=sk-INURL-SECRET", "http://10.0.0.5/mcp#frag"):
        _write(tmp_path, "alpha", [{"id": "s", "transport": "http", "url": url, "allowed_tools": ["t"]}])
        servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
        assert servers == [], url
        assert any(i.code == "inline_secret" for i in issues), url
        assert all("INURL-SECRET" not in i.message for i in issues), url


def test_url_userinfo_rejected_as_inline_secret(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        {"id": "s", "transport": "http", "url": "http://user:hunter2@10.0.0.5:8080/mcp"}])
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert servers == [] and any(i.code == "inline_secret" for i in issues)
    assert all("hunter2" not in i.message for i in issues)   # never echo the password


def test_bad_auth_env_rejected(tmp_path: Path) -> None:
    for bad in ("sk-not-a-name!", "has space", "9starts_with_digit", "a-b"):
        _write(tmp_path, "alpha", [
            {"id": "s", "transport": "http", "url": "http://10.0.0.5/mcp", "auth_env": bad}])
        servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
        assert servers == [] and any(i.code == "bad_auth_env" for i in issues), bad


# --- stdio / allowed_tools / transport -------------------------------------------------------------


def test_missing_required_fields_rejected(tmp_path: Path) -> None:
    cases = [
        ({"id": "s", "transport": "stdio"}, "missing_command"),
        ({"id": "s", "transport": "http"}, "missing_url"),
        ({"id": "s", "transport": "websocket", "url": "http://h/"}, "bad_transport"),
        ({"id": "s", "transport": "stdio", "command": "x", "args": "notalist"}, "bad_args"),
    ]
    for entry, code in cases:
        _write(tmp_path, "alpha", [entry])
        _servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
        assert any(i.code == code for i in issues), (entry, code)


def test_allowed_tools_validated(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        {"id": "ok", "transport": "stdio", "command": "x", "allowed_tools": ["a", "b", "a"]},
        {"id": "bad1", "transport": "stdio", "command": "x", "allowed_tools": "nope"},
        {"id": "bad2", "transport": "stdio", "command": "x", "allowed_tools": ["", "b"]},
    ])
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert [s.id for s in servers] == ["ok"]
    assert servers[0].allowed_tools == ("a", "b")                 # de-duped
    assert sum(i.code == "bad_allowed_tools" for i in issues) == 2


def test_one_bad_entry_does_not_sink_the_good_ones(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        {"id": "good1", "transport": "http", "url": "http://10.0.0.1/mcp"},
        {"id": "oracle", "transport": "stdio", "command": "x"},         # reserved → dropped
        {"id": "good2", "transport": "stdio", "command": "mcp-logs"},
    ])
    servers = EC.load_evidence_servers("alpha", root=tmp_path)
    assert [s.id for s in servers] == ["good1", "good2"]


def test_too_many_servers_capped(tmp_path: Path) -> None:
    entries = [{"id": f"s{i}", "transport": "stdio", "command": "x"} for i in range(EC._MAX_SERVERS + 5)]
    _write(tmp_path, "alpha", entries)
    servers, issues = EC.load_evidence_servers_with_issues("alpha", root=tmp_path)
    assert len(servers) == EC._MAX_SERVERS
    assert any(i.code == "too_many_servers" for i in issues)


# --- egress-host projection + the default (root=None) path -----------------------------------------


def test_evidence_egress_hosts_projection(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        {"id": "h1", "transport": "http", "url": "http://10.0.0.1:9000/mcp"},
        {"id": "stdio1", "transport": "stdio", "command": "x"},          # contributes no egress host
        {"id": "h2", "transport": "http", "url": "https://evidence-db/mcp"},
    ])
    servers = EC.load_evidence_servers("alpha", root=tmp_path)
    assert EC.evidence_egress_hosts(servers) == ("10.0.0.1", "evidence-db")


def test_default_path_uses_paths_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # root=None falls back to paths.target_dir(slug); confirm the fallback reads the real layout.
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    d = tmp_path / "beta"
    d.mkdir(parents=True, exist_ok=True)
    (d / EC.EVIDENCE_SERVERS_FILENAME).write_text(
        json.dumps([{"id": "s", "transport": "http", "url": "http://10.0.0.7/mcp"}]), encoding="utf-8")
    servers = EC.load_evidence_servers("beta")
    assert [s.id for s in servers] == ["s"] and servers[0].host == "10.0.0.7"


# --- best-effort drift guard against the mirrored egress_guard helper ------------------------------


def test_host_too_broad_mirrors_egress_guard() -> None:
    """The ``_host_too_broad`` + ``_PUBLIC_2LABEL_SUFFIXES`` here are a hand-copy of egress_guard's. If
    egress_guard imports in this env, assert they still agree (catches silent drift). Skips if the
    guard's heavier deps (httpx / vigil_core) are unavailable — the copy is self-contained regardless."""
    eg = pytest.importorskip("framework.v2.agents.egress_guard")
    assert EC._PUBLIC_2LABEL_SUFFIXES == eg._PUBLIC_2LABEL_SUFFIXES
    sample = ["*", "*.*", "*.com", "*.internal", "*.co.uk", "*.amazonaws.com",
              "api.example.com", "10.0.0.5", "", "evidence-db", "*.gov.uk"]
    for h in sample:
        assert EC._host_too_broad(h) == eg._collector_host_too_broad(h), h
