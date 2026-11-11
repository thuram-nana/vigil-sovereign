"""
Tests for mcp.ticketing_config — the OPERATOR-ONLY ticketing-OUT target allowlist.

The config is a SEPARATE provisioning axis (operator infra, disjoint from the attack target scope),
default-EMPTY and fail-closed: an absent/malformed file, an unsafe slug, an unsafe tenant, or a bad entry
degrades to an empty/partial list — never a crash, never a wildcard host, never a half-registered entry. A
credential is referenced ONLY by env-var NAME (``auth_env``, REQUIRED here); an inline secret is refused.
Every record is keyed by ``(tenant_id, slug)``. Pure stdlib + the file; no host reached, no secret resolved.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.mcp import ticketing_config as TC


def _write(root: Path, slug: str, payload: object) -> Path:
    """Write the operator config to ``<root>/targets/<slug>/ticketing-targets.json``."""
    d = root / "targets" / slug
    d.mkdir(parents=True, exist_ok=True)
    p = d / TC.TICKETING_TARGETS_FILENAME
    p.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return p


def _ok_entry(**over: object) -> dict:
    entry = {"id": "gh", "kind": "github_issues", "host": "api.github.com",
             "repo": "acme/widgets", "auth_env": "GH_TOKEN"}
    entry.update(over)
    return entry


# --- default-empty / fail-closed -------------------------------------------------------------------


def test_absent_file_is_empty_default(tmp_path: Path) -> None:
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert targets == [] and issues == []
    assert TC.load_ticketing_targets("alpha", root=tmp_path) == []


def test_unsafe_slug_fails_closed(tmp_path: Path) -> None:
    for bad in ("../evil", "a/b", ".hidden", "x\\y", "c:evil"):
        targets, issues = TC.load_ticketing_targets_with_issues(bad, root=tmp_path)
        assert targets == [] and issues and issues[0].code == "unsafe_slug"


def test_malformed_json_is_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", "{ this is not json ")
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert targets == [] and issues and issues[0].code == "malformed_file"


def test_non_list_payload_is_malformed(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", _ok_entry())
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert targets == [] and issues and issues[0].code == "malformed_file"


def test_load_never_raises_on_garbage(tmp_path: Path) -> None:
    for payload in ("", "[", "null", "42", '[1, "x", true, null]', '[{"id": 123}]'):
        _write(tmp_path, "alpha", payload)
        TC.load_ticketing_targets("alpha", root=tmp_path)  # must not raise


# --- parse a valid file ----------------------------------------------------------------------------


def test_parse_valid_github_issues_target(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [_ok_entry()])
    targets = TC.load_ticketing_targets("alpha", root=tmp_path)
    assert len(targets) == 1
    t = targets[0]
    assert t.id == "gh" and t.kind == "github_issues"
    assert t.host == "api.github.com" and t.repo == "acme/widgets"
    assert t.auth_env == "GH_TOKEN"          # NAME, not a value
    # no token field; repr leaks no secret (only the env-var NAME is present)
    assert not hasattr(t, "token")
    assert "secret" not in repr(t).lower()


def test_host_may_be_ip_literal_or_single_hostname(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        _ok_entry(id="ipv4", host="10.0.0.9"),
        _ok_entry(id="ipv6", host="::1"),
        _ok_entry(id="host1", host="ghe-internal"),
    ])
    targets = TC.load_ticketing_targets("alpha", root=tmp_path)
    assert {t.id: t.host for t in targets} == {"ipv4": "10.0.0.9", "ipv6": "::1", "host1": "ghe-internal"}


# --- (tenant_id, slug) keying ----------------------------------------------------------------------


def test_records_are_keyed_by_tenant_and_slug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_TENANT", "acme")
    _write(tmp_path, "beta", [_ok_entry()])
    t = TC.load_ticketing_targets("beta", root=tmp_path)[0]
    assert t.tenant_id == "acme" and t.slug == "beta"
    assert t.scope_key == ("acme", "beta")


def test_unsharded_tenant_is_none_default_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    _write(tmp_path, "beta", [_ok_entry()])
    t = TC.load_ticketing_targets("beta", root=tmp_path)[0]
    assert t.tenant_id is None and t.scope_key == (None, "beta")


def test_unsafe_tenant_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # a set-but-unsafe CRUCIBLE_TENANT must not silently load into the default scope — refuse (fail-closed).
    monkeypatch.setenv("CRUCIBLE_TENANT", "../evil")
    _write(tmp_path, "beta", [_ok_entry()])
    targets, issues = TC.load_ticketing_targets_with_issues("beta", root=tmp_path)
    assert targets == [] and any(i.code == "unsafe_tenant" for i in issues)


# --- reject: duplicate / reserved / bad id ---------------------------------------------------------


def test_duplicate_id_rejected_first_wins(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        _ok_entry(id="dup", repo="a/one"),
        _ok_entry(id="DUP", repo="a/two"),  # case-insensitive collision
    ])
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert [t.id for t in targets] == ["dup"]
    assert targets[0].repo == "a/one"
    assert any(i.code == "duplicate_id" for i in issues)


def test_reserved_id_rejected(tmp_path: Path) -> None:
    for rid in ("oracle", "vigil", "System", "self"):
        _write(tmp_path, "alpha", [_ok_entry(id=rid)])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == [] and any(i.code == "reserved_id" for i in issues), rid


def test_bad_id_rejected(tmp_path: Path) -> None:
    for bad in ("-leading-hyphen", "has space", "has/slash", "", 123):
        _write(tmp_path, "alpha", [_ok_entry(id=bad)])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == [] and any(i.code == "bad_id" for i in issues), bad


# --- reject: bad kind ------------------------------------------------------------------------------


def test_unknown_kind_rejected(tmp_path: Path) -> None:
    for kind in ("jira", "gitlab_issues", "", None, "github"):
        _write(tmp_path, "alpha", [_ok_entry(kind=kind)])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == [] and any(i.code == "bad_kind" for i in issues), kind


# --- reject: over-broad / wildcard / bad host ------------------------------------------------------


def test_over_broad_host_rejected(tmp_path: Path) -> None:
    for host in ("*", "*.com", "*.co.uk"):
        _write(tmp_path, "alpha", [_ok_entry(host=host)])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == [], host
        assert any(i.code in ("over_broad_host", "wildcard_host") for i in issues), host


def test_wildcard_host_rejected_even_when_not_too_broad(tmp_path: Path) -> None:
    # A private-base wildcard is NOT "too broad" by the mirror rule, but a ticketing host must be a SINGLE
    # hostname/IP literal so the egress floor can pin it — so reject.
    assert TC._host_too_broad("*.internal.example.com") is False
    _write(tmp_path, "alpha", [_ok_entry(host="*.internal.example.com")])
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert targets == [] and any(i.code == "wildcard_host" for i in issues)


def test_host_with_scheme_or_port_rejected(tmp_path: Path) -> None:
    # an operator pasting a URL / host:port into 'host' is refused (the floor pins a bare host).
    for host in ("https://api.github.com", "api.github.com:443", "api.github.com/x"):
        _write(tmp_path, "alpha", [_ok_entry(host=host)])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == [], host
        assert any(i.code == "bad_host" for i in issues), host


def test_missing_host_rejected(tmp_path: Path) -> None:
    entry = _ok_entry()
    del entry["host"]
    _write(tmp_path, "alpha", [entry])
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert targets == [] and any(i.code == "missing_host" for i in issues)


# --- reject: bad repo (path-injection hygiene) -----------------------------------------------------


def test_bad_repo_rejected(tmp_path: Path) -> None:
    for repo in ("noslash", "a/b/c", "/leading", "trailing/", "../evil", "a/..",
                 "a/b c", "a b/c", "a/.", "-bad/repo", ""):
        _write(tmp_path, "alpha", [_ok_entry(repo=repo)])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == [], repo
        assert any(i.code in ("bad_repo", "missing_repo") for i in issues), repo


def test_valid_repo_shapes_accepted(tmp_path: Path) -> None:
    for repo in ("acme/widgets", "a/b", "Org-123/repo.name_v2", "x/.github"):
        _write(tmp_path, "alpha", [_ok_entry(repo=repo)])
        targets = TC.load_ticketing_targets("alpha", root=tmp_path)
        assert [t.repo for t in targets] == [repo], repo


# --- secrets stay references -----------------------------------------------------------------------


def test_missing_auth_env_rejected(tmp_path: Path) -> None:
    entry = _ok_entry()
    del entry["auth_env"]
    _write(tmp_path, "alpha", [entry])
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert targets == [] and any(i.code == "missing_auth_env" for i in issues)


def test_inline_secret_key_rejected(tmp_path: Path) -> None:
    for secret_key in ("token", "auth", "password", "bearer", "api_key", "apiKey", "authorization",
                       "auth_token", "authToken", "pat", "client_secret", "x_api_key",
                       # re-red-pen LOW: connector-specific compound credential names that previously slipped
                       # the blocklist (gh_pat is THE GitHub-Issues credential; access_key / creds too).
                       "gh_pat", "github_pat", "access_key", "accessKey", "creds"):
        entry = _ok_entry()
        entry[secret_key] = "sk-SECRET"
        _write(tmp_path, "alpha", [entry])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == [], secret_key
        assert any(i.code == "inline_secret" for i in issues), secret_key
        assert all("sk-SECRET" not in i.message for i in issues), secret_key


def test_auth_env_itself_is_not_mistaken_for_an_inline_secret(tmp_path: Path) -> None:
    # "auth_env" normalises to "authenv" — contains no secret stem; the ONE sanctioned reference survives.
    _write(tmp_path, "alpha", [_ok_entry(auth_env="GH_TOKEN")])
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert len(targets) == 1 and targets[0].auth_env == "GH_TOKEN"
    assert not any(i.code == "inline_secret" for i in issues)


def test_bad_auth_env_rejected(tmp_path: Path) -> None:
    for bad in ("sk-not-a-name!", "has space", "9starts_with_digit", "a-b"):
        _write(tmp_path, "alpha", [_ok_entry(auth_env=bad)])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == [] and any(i.code == "bad_auth_env" for i in issues), bad


# --- resilience: one bad entry does not sink the good ones + caps -----------------------------------


def test_one_bad_entry_does_not_sink_the_good_ones(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        _ok_entry(id="good1", repo="a/one"),
        _ok_entry(id="oracle", repo="a/two"),       # reserved → dropped
        _ok_entry(id="good2", repo="a/three"),
    ])
    targets = TC.load_ticketing_targets("alpha", root=tmp_path)
    assert [t.id for t in targets] == ["good1", "good2"]


def test_too_many_targets_capped(tmp_path: Path) -> None:
    entries = [_ok_entry(id=f"t{i}", repo=f"a/r{i}") for i in range(TC._MAX_TARGETS + 5)]
    _write(tmp_path, "alpha", entries)
    targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
    assert len(targets) == TC._MAX_TARGETS
    assert any(i.code == "too_many_targets" for i in issues)


# --- egress-host projection + find + the default (root=None) path ----------------------------------


def test_ticketing_egress_hosts_projection(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [
        _ok_entry(id="h1", host="api.github.com", repo="a/one"),
        _ok_entry(id="h2", host="10.0.0.9", repo="a/two"),
        _ok_entry(id="h3", host="api.github.com", repo="a/three"),  # dup host de-duped
    ])
    targets = TC.load_ticketing_targets("alpha", root=tmp_path)
    assert TC.ticketing_egress_hosts(targets) == ("api.github.com", "10.0.0.9")


def test_find_ticketing_target(tmp_path: Path) -> None:
    _write(tmp_path, "alpha", [_ok_entry(id="gh")])
    assert TC.find_ticketing_target("alpha", "GH", root=tmp_path).id == "gh"   # case-insensitive
    assert TC.find_ticketing_target("alpha", "nope", root=tmp_path) is None
    assert TC.find_ticketing_target("alpha", "", root=tmp_path) is None


def test_default_path_uses_paths_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # root=None falls back to paths.target_dir(slug); confirm the fallback reads the real layout.
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    d = tmp_path / "gamma"
    d.mkdir(parents=True, exist_ok=True)
    (d / TC.TICKETING_TARGETS_FILENAME).write_text(json.dumps([_ok_entry()]), encoding="utf-8")
    targets = TC.load_ticketing_targets("gamma")
    assert [t.id for t in targets] == ["gh"] and targets[0].slug == "gamma"


# --- best-effort drift guard against the mirrored evidence_config / egress_guard helpers -----------


def test_host_too_broad_mirrors_evidence_config() -> None:
    """``_host_too_broad`` + ``_PUBLIC_2LABEL_SUFFIXES`` here are a hand-copy of evidence_config's (itself a
    copy of egress_guard's). Assert they still agree (catches silent drift). Skips if evidence_config's deps
    are unavailable — the copy is self-contained regardless."""
    ec = pytest.importorskip("framework.v2.mcp.evidence_config")
    assert TC._PUBLIC_2LABEL_SUFFIXES == ec._PUBLIC_2LABEL_SUFFIXES
    sample = ["*", "*.*", "*.com", "*.internal", "*.co.uk", "*.amazonaws.com",
              "api.github.com", "10.0.0.5", "", "ghe-internal", "*.gov.uk"]
    for h in sample:
        assert TC._host_too_broad(h) == ec._host_too_broad(h), h


def test_credentialed_host_refused_without_echoing_the_secret(tmp_path: Path) -> None:
    """red-pen MED: a host carrying inline credentials is refused (fail-closed) AND the secret is NEVER echoed
    into the operator-facing issue message (the message lands in the operator UI / log)."""
    for bad in ("https://ghp_LEAKEDTOKEN12345@api.github.com", "user:SUPERSECRETpw@api.github.com",
                "api.github.com/?access_token=ghp_QUERYLEAK"):
        _write(tmp_path, "alpha", [{"id": "gh", "kind": "github_issues", "host": bad,
                                    "repo": "acme/widgets", "auth_env": "GH_TOKEN"}])
        targets, issues = TC.load_ticketing_targets_with_issues("alpha", root=tmp_path)
        assert targets == []                                        # refused (fail-closed)
        blob = " ".join(i.message for i in issues)
        for secret in ("LEAKEDTOKEN12345", "SUPERSECRETpw", "QUERYLEAK"):
            assert secret not in blob                               # the secret is NEVER echoed
