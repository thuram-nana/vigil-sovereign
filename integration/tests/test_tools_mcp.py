"""F3 slice-1 — the governed MCP tool boundary: the ported registry (trust-tiered validation, secret
redaction, least-privilege phase inversion) and the sovereign authorization boundary (fail-closed phase
gate → WARDEN tier → injected conjunctive gate). The through-line: a tool call NEVER auto-proceeds
without the gate's `allow`, an unregistered/out-of-phase tool is denied before the gate is consulted,
and a destructive tool floors at A3 + m-of-n."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_integration.agent.state import Phase
from vigil_integration.tools import (
    BearerAuth,
    MCPServer,
    ToolSpec,
    authorize_tool_call,
    authorized_tool_names,
    default_phases_for,
    is_destructive_tool,
    is_tool_allowed_in_phase,
    manifest_tool_phase_view,
    parse_user_servers,
    redact_for_api,
    redact_tool_args,
    set_builtin_tool_names,
    set_current,
    to_client_config,
    tool_call_tier,
    validate_servers,
)
from vigil_integration.tools.mcp_registry import _mask_secret


def _srv(sid="s1", transport="stdio", tools=None, phases=None, **kw):
    base = dict(id=sid, name=sid, transport=transport)
    if transport == "stdio":
        base["command"] = kw.pop("command", "run")
    else:
        base["url"] = kw.pop("url", "https://mcp.example/sse")
    if phases is not None:
        base["default_phases"] = phases
    if tools is not None:
        base["tools"] = tools
    base.update(kw)
    return MCPServer.model_validate(base)


def _tool(name="scan", phases=None):
    return ToolSpec(name=name, purpose="p", when_to_use="w", args_format="a", description="d",
                    default_phases=phases)


# --- registry: schema + sovereign inversions -------------------------------------------------

def test_default_phases_is_least_privilege_not_all():
    # SOVEREIGN INVERSION: an undeclared server is informational-only, not all-phases (redamon fails open).
    s = _srv()
    assert s.default_phases == ["informational"]
    assert s.effective_phases_for("anything") == ["informational"]


def test_transport_field_requirements():
    with pytest.raises(Exception):
        MCPServer.model_validate({"id": "x", "name": "x", "transport": "sse"})       # url required
    with pytest.raises(Exception):
        MCPServer.model_validate({"id": "x", "name": "x", "transport": "stdio"})     # command required
    assert _srv(transport="sse").url
    assert _srv(transport="stdio").command


def test_duplicate_tool_within_server_rejected():
    with pytest.raises(Exception):
        _srv(tools=[_tool("dup"), _tool("dup")])


def test_bearer_auth_requires_a_token():
    with pytest.raises(Exception):
        BearerAuth()
    assert BearerAuth(token="t").token == "t"
    assert BearerAuth(token_env_var="V").token_env_var == "V"


def test_effective_phases_tool_overrides_server():
    s = _srv(phases=["informational"], tools=[_tool("recon"), _tool("exploit", phases=["exploitation"])])
    assert s.effective_phases_for("recon") == ["informational"]     # falls back to server
    assert s.effective_phases_for("exploit") == ["exploitation"]    # tool overrides


# --- registry: trust-tiered validation -------------------------------------------------------

def test_validate_rejects_duplicate_id_and_cross_server_tool_collision():
    a = _srv("dup", tools=[_tool("t1")])
    b = _srv("dup", tools=[_tool("t2")])            # duplicate id
    c = _srv("other", tools=[_tool("t1")])          # cross-server tool-name collision with a
    valid, errors = validate_servers([a, b, c])
    codes = {e.code for e in errors}
    assert "duplicate_id" in codes
    assert "duplicate_tool_name" in codes
    assert a in valid and b not in valid and c not in valid   # broken servers dropped, never half-registered


def test_validate_user_supplied_reserved_and_builtin_collisions():
    set_builtin_tool_names({"fs_read"})
    try:
        reserved = _srv("nmap", tools=[_tool("myscan")])                 # reserved system id
        shadow = _srv("ok", tools=[_tool("fs_read")])                    # shadows a builtin tool
        valid, errors = validate_servers([reserved, shadow], is_user_supplied=True)
        codes = {e.code for e in errors}
        assert "system_id_collision" in codes and "builtin_name_collision" in codes
        assert valid == []
        # the same servers are FINE when shipped as system presets (is_user_supplied=False)
        valid2, errors2 = validate_servers([reserved, shadow], is_user_supplied=False)
        assert {e.code for e in errors2} == set() and len(valid2) == 2
    finally:
        set_builtin_tool_names(set())


def test_parse_user_servers_payload_and_schema_errors():
    assert parse_user_servers(None) == ([], [])
    _, errs = parse_user_servers({"not": "a list"})
    assert errs and errs[0].code == "invalid_payload"
    valid, errors = parse_user_servers([{"id": "good", "name": "g", "transport": "stdio", "command": "c"},
                                        {"id": "bad", "name": "b", "transport": "sse"}])  # missing url
    assert [s.id for s in valid] == ["good"]
    assert any(e.code == "schema_invalid" for e in errors)


# --- registry: secret redaction --------------------------------------------------------------

def test_mask_secret_keeps_shape_hides_body():
    assert _mask_secret("") == ""
    assert _mask_secret("abcd") == "••••"
    assert _mask_secret("supersecrettoken").endswith("oken") and "supersecret" not in _mask_secret("supersecrettoken")


def test_redact_for_api_masks_token_headers_env_keeps_keys():
    s = _srv("h", transport="sse", url="https://x/sse", auth=BearerAuth(token="TOKENVALUE1234"),
             headers={"X-Api-Key": "HEADERSECRET99"})
    s2 = _srv("e", transport="stdio", command="c", env={"CRED": "ENVSECRET1234"})
    out = redact_for_api([s, s2])
    assert out[0]["auth"]["token"].endswith("1234") and "TOKENVALUE" not in out[0]["auth"]["token"]
    assert "X-Api-Key" in out[0]["headers"] and "HEADERSECRET" not in out[0]["headers"]["X-Api-Key"]
    assert "CRED" in out[1]["env"] and "ENVSECRET" not in out[1]["env"]["CRED"]


# --- registry: client-config + state store ---------------------------------------------------

def test_to_client_config_shapes_and_disabled_skip(monkeypatch):
    monkeypatch.setenv("MCP_TOK", "plainascii")
    sse = _srv("a", transport="sse", url="https://x/sse", auth=BearerAuth(token_env_var="MCP_TOK"))
    stdio = _srv("b", transport="stdio", command="run", args=["--x"], env={"E": "1"})
    disabled = _srv("c", transport="stdio", command="run", enabled=False)
    cfg, warnings = to_client_config([sse, stdio, disabled])
    assert cfg["a"]["headers"]["Authorization"] == "Bearer plainascii"
    assert cfg["b"]["command"] == "run" and cfg["b"]["args"] == ["--x"] and cfg["b"]["env"] == {"E": "1"}
    assert "c" not in cfg          # disabled skipped
    assert warnings == []


def test_default_phases_for_unknown_tool_is_denied():
    # SOVEREIGN INVERSION: a tool declared by no enabled server → [] (deny in every phase).
    set_current([_srv("reg", tools=[_tool("known", phases=["informational", "exploitation"])])])
    try:
        assert default_phases_for("known") == ["informational", "exploitation"]
        assert default_phases_for("never_registered") == []
        assert manifest_tool_phase_view()["known"] == ["informational", "exploitation"]
    finally:
        set_current([])


# --- governance: destructive classification --------------------------------------------------

def test_is_destructive_tool():
    for d in ("metasploit", "metasploit_console", "hydra", "sqlmap", "nuclei", "kali_shell",
              "execute_code", "msf_console", "http_dos", "reverse_shell", "wpscan_brute"):
        assert is_destructive_tool(d), d
    for safe in ("nmap", "httpx", "subfinder", "gau", "amass", "fs_read", "cve_intel", None, 5):
        assert not is_destructive_tool(safe), safe


# --- governance: fail-closed phase gate + tier -----------------------------------------------

def test_is_tool_allowed_in_phase_fail_closed():
    view = {"recon": ["informational"], "pwn": ["exploitation", "post_exploitation"]}
    assert is_tool_allowed_in_phase("recon", Phase.INFORMATIONAL, view=view) is True
    assert is_tool_allowed_in_phase("recon", Phase.EXPLOITATION, view=view) is False   # out of phase
    assert is_tool_allowed_in_phase("pwn", Phase.EXPLOITATION, view=view) is True
    assert is_tool_allowed_in_phase("unregistered", Phase.INFORMATIONAL, view=view) is False  # deny unknown
    assert is_tool_allowed_in_phase("recon", "bogus_phase", view=view) is False        # deny unknown phase
    assert is_tool_allowed_in_phase("recon", Phase.INFORMATIONAL, view=None) is False  # deny bad view


def test_tool_call_tier_maps_phase_and_floors_destructive():
    assert tool_call_tier("nmap", Phase.INFORMATIONAL) == "A1"
    assert tool_call_tier("nmap", Phase.EXPLOITATION) == "A2"
    assert tool_call_tier("nmap", Phase.POST_EXPLOITATION) == "A3"
    assert tool_call_tier("metasploit", Phase.INFORMATIONAL) == "A3"   # destructive floors at A3
    assert tool_call_tier("nmap", "bogus") == "A3"                     # unknown phase → strictest


# --- governance: the authorization boundary (the sovereign seam) ------------------------------

def _gate(outcome="allow", allowed=None, reason="ok", raises=False):
    def g(tool_name, target, destructive):
        if raises:
            raise RuntimeError("gate exploded")
        a = (outcome == "allow") if allowed is None else allowed
        return SimpleNamespace(outcome=outcome, allowed=a, reason=reason)
    return g


def test_authorize_denies_out_of_phase_before_consulting_gate():
    view = {"pwn": ["exploitation"]}
    called = {"n": 0}

    def spy(tool_name, target, destructive):
        called["n"] += 1
        return SimpleNamespace(outcome="allow", allowed=True, reason="should not be reached")

    v = authorize_tool_call("pwn", {}, Phase.INFORMATIONAL, gate=spy, view=view)
    assert v.allowed is False and v.outcome == "deny"
    assert called["n"] == 0                     # gate never consulted for an out-of-phase tool


def test_authorize_fail_closed_without_gate_or_on_error():
    view = {"recon": ["informational"]}
    assert authorize_tool_call("recon", {}, Phase.INFORMATIONAL, gate=None, view=view).outcome == "deny"
    err = authorize_tool_call("recon", {}, Phase.INFORMATIONAL, gate=_gate(raises=True), view=view)
    assert err.allowed is False and "gate error" in err.reason


def test_authorize_allows_only_when_gate_says_allow():
    view = {"recon": ["informational"]}
    ok = authorize_tool_call("recon", {"url": "http://t"}, Phase.INFORMATIONAL, gate=_gate("allow"), view=view)
    assert ok.allowed is True and ok.outcome == "allow" and ok.tier == "A1"
    denied = authorize_tool_call("recon", {}, Phase.INFORMATIONAL, gate=_gate("deny"), view=view)
    assert denied.allowed is False and denied.outcome == "deny"
    queued = authorize_tool_call("recon", {}, Phase.INFORMATIONAL, gate=_gate("queue", allowed=False), view=view)
    assert queued.allowed is False and queued.outcome == "queue"


def test_authorize_malformed_gate_cannot_present_as_allow():
    # a gate claiming outcome="allow" but allowed=False must NOT be read as allowed (derive from allowed).
    view = {"recon": ["informational"]}
    v = authorize_tool_call("recon", {}, Phase.INFORMATIONAL, gate=_gate("allow", allowed=False), view=view)
    assert v.allowed is False and v.outcome == "deny"


def test_authorize_destructive_floors_a3_and_requires_quorum():
    view = {"metasploit": ["exploitation", "post_exploitation"]}
    v = authorize_tool_call("metasploit", {"target": "http://t"}, Phase.EXPLOITATION,
                            gate=_gate("allow"), view=view)
    assert v.tier == "A3" and v.destructive is True and v.requires_quorum is True


def test_redact_tool_args_masks_secrets_only():
    args = {"url": "http://t", "api_key": "SECRETKEY1234", "password": "hunter2pass", "count": 5}
    out = redact_tool_args(args)
    assert out["url"] == "http://t" and out["count"] == 5
    assert "SECRETKEY" not in out["api_key"] and "hunter2" not in out["password"]
    assert redact_tool_args("not-a-dict") == {}


def test_authorized_tool_names_lists_only_in_phase_sorted():
    view = {"z_recon": ["informational"], "a_recon": ["informational"], "pwn": ["exploitation"]}
    assert authorized_tool_names(Phase.INFORMATIONAL, view=view) == ["a_recon", "z_recon"]
    assert authorized_tool_names(Phase.EXPLOITATION, view=view) == ["pwn"]
    assert authorized_tool_names("bogus", view=view) == []


# --- RED-PEN regressions (F3 slice-1 round 1) ------------------------------------------------

def test_is_destructive_covers_missed_families():
    # BLOCK-1: the floor missed obviously-destructive tools across families. A false negative is the
    # dangerous direction (runs below A3, no quorum, and misinforms the gate).
    for d in ("msfvenom", "msfcli", "msfdb",
              "slowloris", "hulk", "goldeneye", "torshammer", "slowhttptest",
              "empire", "cobaltstrike", "cobalt_strike", "sliver", "mythic", "havoc", "brute_ratel",
              "crackmapexec", "cme", "netexec", "impacket", "responder", "psexec", "secretsdump",
              "evil-winrm", "mimikatz",
              "netcat", "nc", "ncat", "socat", "chisel", "ligolo", "webshell",
              "patator", "ncrack", "crowbar", "hashcat", "john",
              "commix", "xsser",
              "app_reverse_shell", "http_bruteforce", "x_reverse_tcp", "y_bind_shell"):
        assert is_destructive_tool(d), d
    # over-match direction stays safe: benign read-only tools are NOT flagged destructive
    for safe in ("exploitdb", "cve_intel", "dos_report", "nmap", "httpx", "subfinder", "gau", "amass"):
        assert not is_destructive_tool(safe), safe


def test_manifest_declared_destructive_is_authoritative_raise():
    # BLOCK-1: the operator's manifest declaration must force destructive even for an unknown name.
    assert is_destructive_tool("totally_custom_tool", declared=True) is True
    view = {"custom_pwn": ["exploitation"]}
    dview = {"custom_pwn": True}
    v = authorize_tool_call("custom_pwn", {"target": "http://t"}, Phase.EXPLOITATION,
                            gate=_gate("allow"), view=view, destructive_view=dview)
    assert v.tier == "A3" and v.destructive is True and v.requires_quorum is True
    # and the manifest view can only RAISE — it never lowers the known-name floor
    v2 = authorize_tool_call("metasploit", {}, Phase.EXPLOITATION, gate=_gate("allow"),
                             view={"metasploit": ["exploitation"]}, destructive_view={"metasploit": False})
    assert v2.destructive is True


def test_redact_tool_args_covers_common_and_nested_and_inline_secrets():
    # BLOCK-2: the spine is immutable — a leaked credential is permanent. Cover the key names, nested
    # dicts, and inline secrets the exact-match allowlist missed.
    args = {
        "client_secret": "CLIENTSECRET1234", "refresh_token": "REFRESHTOKEN1234",
        "private_key": "PRIVATEKEY123456", "x-api-key": "XAPIKEY1234567", "pat": "PATVALUE1234",
        "aws_secret_access_key": "AWSSECRET1234",
        "headers": {"Authorization": "Bearer NESTEDSECRET1234"},
        "cmd": "curl -H 'Authorization: Bearer INLINESECRET1234' http://t",
        "url": "http://t", "count": 5,
    }
    out = redact_tool_args(args)
    for k, raw in (("client_secret", "CLIENTSECRET"), ("refresh_token", "REFRESHTOKEN"),
                   ("private_key", "PRIVATEKEY"), ("x-api-key", "XAPIKEY"), ("pat", "PATVALUE"),
                   ("aws_secret_access_key", "AWSSECRET")):
        assert raw not in str(out[k]), k
    assert "NESTEDSECRET" not in str(out["headers"])         # nested dict descended
    assert "INLINESECRET" not in out["cmd"]                  # inline secret scrubbed
    assert out["url"] == "http://t" and out["count"] == 5    # non-secret structure preserved
    # a benign key that merely contains "author" is NOT over-masked
    assert redact_tool_args({"author": "alice"})["author"] == "alice"


def test_redact_tool_args_covers_cli_arg_values():
    # RE-CHECK re-opened BLOCK-2: CLI credential conventions leaked to the immutable spine —
    # `["--api-key", VALUE]` list form and the space-separated `--flag value` string form.
    assert "sk-SUPERSECRET99" not in str(redact_tool_args({"args": ["--api-key", "sk-SUPERSECRET99"]}))
    assert "hunter2password" not in str(redact_tool_args({"argv": ["--password", "hunter2password"]}))
    assert "X99SECRET" not in str(redact_tool_args({"exec": {"argv": ["--client-secret", "X99SECRET"]}}))
    assert "sk-SPACEKEY999" not in redact_tool_args({"cmd": "app --api-key sk-SPACEKEY999"})["cmd"]
    kept = redact_tool_args({"command_line": "mytool --token sk-X --verbose runthing"})["command_line"]
    assert "sk-X" not in kept and "runthing" in kept       # secret masked, non-secret flag/value kept
    # a non-secret flag's value is NOT masked
    assert redact_tool_args({"args": ["--output", "report.txt"]})["args"] == ["--output", "report.txt"]


def test_redact_tool_args_covers_crypto_key_material():
    # RE-CHECK residual + BLOCK-B: crypto key material in snake_case, camelCase, AND no-separator forms
    # must all mask — driven THROUGH redact_tool_args (the spine path), not the helper in isolation.
    for k in ("ssh_key", "master_key", "signing_key", "gpg_key", "encryption_key", "jwt", "session_id",
              "masterKey", "sshKey", "sessionKey", "encryptionKey", "sessionId", "apiKey", "clientSecret",
              "authToken", "accessToken", "masterkey", "sshkey", "gpgkey"):
        assert "CRYPTOSECRET1234" not in str(redact_tool_args({k: "CRYPTOSECRET1234"})), k
    # but a benign identifier (incl. a word that merely ends in "key") is not over-masked
    for k in ("keyword", "monkey", "donkey", "turkey", "whiskey", "keyboard", "description", "hostname",
              "author_name", "authority", "oauth"):
        assert redact_tool_args({k: "benign"})[k] == "benign", k


def test_redact_tool_args_masks_url_userinfo_on_spine_path():
    # BLOCK-A (re-opened HIGH): a scheme://user:pass@host basic-auth credential in a tool_arg VALUE must
    # mask when driven THROUGH redact_tool_args — the scrubber was previously only on the API path.
    for k, val, secret in (("url", "https://admin:SUPERSECRETPW99@target/x", "SUPERSECRETPW99"),
                           ("target", "http://user:HUNTER2PASS@10.0.0.1/", "HUNTER2PASS"),
                           ("target_url", "https://u:P4ss@[::1]:8443/api", "P4ss"),
                           ("note", "connect to https://root:R00TPW9@host", "R00TPW9")):
        assert secret not in str(redact_tool_args({k: val})), k
    # the host/username/path are kept (a reference, not a secret)
    assert "target" in redact_tool_args({"url": "https://admin:PW@target/x"})["url"]


def test_redact_url_userinfo_edge_cases():
    from vigil_integration.tools.mcp_registry import _redact_url_userinfo
    assert "PWONLY" not in _redact_url_userinfo("https://:PWONLY@host/x")      # empty username
    assert "ss@host" not in _redact_url_userinfo("https://admin:p@ss@host/x")  # '@' inside the password
    assert _redact_url_userinfo("https://host/x") == "https://host/x"          # no userinfo unchanged


def test_redact_tool_args_inline_vocabulary_matches_key_scrubber():
    # FINAL BLOCK: the inline `param=value` scrubber must recognize the SAME secret vocabulary as the
    # key scrubber (`_is_secret_key`) — a name that is a secret key must also mask inline. Driven THROUGH
    # redact_tool_args (the spine path). Covers URL query strings (incl. the first param after '?', which
    # a scheme-colon bug used to swallow), Cookie headers, and serialized JSON bodies.
    cases = {
        "client_secret query": {"url": "https://idp/token?client_id=x&client_secret=Q_CLIENTSECRET99"},
        "bare key first param": {"target": "https://api/v1?key=Q_BAREKEY99"},
        "access_key query": {"url": "https://h/p?access_key=Q_ACCESSKEY99"},
        "jwt query": {"url": "https://h/p?jwt=Q_JWT99"},
        "session query": {"u": "https://h/p?session=Q_SESSION99"},
        "auth query": {"target": "https://h/p?auth=Q_AUTH99"},
        "cookie header": {"raw": "GET / HTTP/1.1\nCookie: session=Q_COOKIESESS99"},
        "credential prose": {"note": "login with credential=Q_CRED99 now"},
        "json body": {"body": '{"client_secret":"Q_JSONCS99"}'},
    }
    for name, args in cases.items():
        out = redact_tool_args(args)
        assert not any(c in str(out) for c in ("Q_CLIENTSECRET99", "Q_BAREKEY99", "Q_ACCESSKEY99",
                       "Q_JWT99", "Q_SESSION99", "Q_AUTH99", "Q_COOKIESESS99", "Q_CRED99", "Q_JSONCS99")), name
    # a non-secret param name (client_id) keeps its value; a base64 token value with '/' is not truncated
    assert "KEEPME123" in redact_tool_args({"url": "https://h?client_id=KEEPME123&api_key=X"})["url"]
    assert "ab/cd" not in redact_tool_args({"body": "token=ab/cd+efSECRET99"})["body"]  # full value masked


def test_redact_tool_args_masks_spaced_quoted_secret_value():
    # FINAL BLOCK (self-found before the reviewer's process stalled): a secret VALUE containing a space
    # truncated at the space, leaking the tail. A spaced secret is always QUOTED (JSON/shell) — mask the
    # whole quoted content, spaces included. Driven THROUGH redact_tool_args.
    for args in ({"body": '{"password":"ab SPACETAIL99"}'},
                 {"cmd": 'app --password="ab SPACETAIL99"'},
                 {"body": "cfg key='a b SPACETAIL99'"},
                 {"headers": {"Authorization": "Basic dXNlcjpwYXNz SPACETAIL99"}}):
        assert "SPACETAIL99" not in str(redact_tool_args(args)), args
    # a benign quoted string under a non-secret key is preserved (no over-mask, no data loss)
    assert "hello world" in str(redact_tool_args({"body": '{"title":"hello world"}'}))


def test_redact_for_api_covers_url_args_command():
    # BLOCK-3: model_dump also emits url/args/command — mask secrets there too.
    s_url = _srv("u", transport="sse", url="https://admin:SUPERSECRETPW@mcp.example/sse")
    s_args = _srv("a", transport="stdio", command="run",
                  args=["--api-key", "ghp_SUPERSECRETTOKEN123456", "--url", "https://api.example"])
    s_inline = _srv("i", transport="stdio", command="serve --token=CMDINLINESECRET99")
    out = redact_for_api([s_url, s_args, s_inline])
    assert "SUPERSECRETPW" not in out[0]["url"] and "mcp.example" in out[0]["url"]
    assert "ghp_SUPERSECRETTOKEN123456" not in " ".join(out[1]["args"])
    assert "--url" in out[1]["args"] and "https://api.example" in out[1]["args"]   # non-secret arg kept
    assert "CMDINLINESECRET99" not in out[2]["command"]


def test_boundary_is_total_on_unhashable_and_mixed_inputs():
    # BLOCK-4: the boundary is documented "never raises" — malformed tool_name / view must not crash.
    view = {"x": ["informational"]}
    assert is_tool_allowed_in_phase(["a", "b"], Phase.INFORMATIONAL, view=view) is False   # unhashable
    assert is_tool_allowed_in_phase({"k": 1}, Phase.INFORMATIONAL, view=view) is False
    v = authorize_tool_call([1, 2], {}, Phase.INFORMATIONAL, gate=_gate("allow"), view=view)
    assert v.allowed is False and v.outcome == "deny"                                      # fail-closed deny
    assert authorized_tool_names(Phase.INFORMATIONAL, view={5: ["informational"], "a": ["informational"]}) == ["a"]


def test_validate_reserved_and_builtin_checks_case_insensitive():
    # BLOCK-5: a case-variant must not dodge the reserved-id / builtin-name check.
    set_builtin_tool_names({"fs_read"})
    try:
        upper_reserved = _srv("NMAP", tools=[_tool("x")])
        upper_builtin = _srv("ok", tools=[_tool("FS_READ")])
        _, errors = validate_servers([upper_reserved, upper_builtin], is_user_supplied=True)
        codes = {e.code for e in errors}
        assert "system_id_collision" in codes and "builtin_name_collision" in codes
    finally:
        set_builtin_tool_names(set())
