"""WS1a (SOVEREIGN CONSOLE) — the structured, actionable dependency preflight.

`vigil doctor` gains a per-item `dependencies` report ({name, kind, present, required, detail,
how_to_install}) that names EXACTLY what is missing and the command to install it, plus the docker
DAEMON check the old doctor lacked (it checked only that the docker binary existed) and endpoint-aware
service detection (a differently-named external container serving the port is no longer a false
"absent"). The whole section is INFORMATIONAL — it never flips the doctor `ok` exit gate.
"""
from vigil_integration import doctor as dmod
from vigil_integration.services import RootServices


_REQUIRED_KEYS = {"name", "kind", "present", "required", "detail", "how_to_install"}


def test_dependencies_report_is_structured_and_every_missing_item_is_actionable(monkeypatch):
    monkeypatch.setattr(dmod, "_image_present", lambda *a, **k: False)   # no real docker subprocess
    deps = dmod._dependencies_report(dmod.Path("/no/such/repo"), has_docker=True, daemon_up=True, compose_ok=True)
    assert isinstance(deps, list) and deps
    for d in deps:
        assert _REQUIRED_KEYS <= set(d)
        assert isinstance(d["present"], bool) and isinstance(d["required"], bool)
        # the load-bearing invariant: a MISSING dependency ALWAYS carries a concrete install command
        # (so the operator never sees a red row with no remedy); a PRESENT one carries none.
        if d["present"]:
            assert d["how_to_install"] == ""
        else:
            assert d["how_to_install"].strip(), f"missing dependency {d['name']!r} has no install command"
    kinds = {d["kind"] for d in deps}
    names = {d["name"] for d in deps}
    assert "docker daemon" in names                                   # the check doctor lacked
    assert "image" in kinds                                           # engine images (strix/aegis)
    assert "offense-tool" not in kinds                                # offense tools = the registry's shadow-aware job


def test_docker_daemon_down_marks_the_daemon_absent_and_leaves_images_unprobed():
    deps = dmod._dependencies_report(dmod.Path("/x"), has_docker=True, daemon_up=False, compose_ok=True)
    by = {d["name"]: d for d in deps}
    assert by["docker daemon"]["present"] is False
    assert "systemctl start docker" in by["docker daemon"]["how_to_install"]
    images = [d for d in deps if d["kind"] == "image"]
    assert images and all(d["present"] is False and "cannot probe" in d["detail"] for d in images)


def test_no_docker_at_all_reports_docker_as_optional_and_omits_the_daemon_row():
    deps = dmod._dependencies_report(dmod.Path("/x"), has_docker=False, daemon_up=None, compose_ok=False)
    by = {d["name"]: d for d in deps}
    assert "docker" in by and by["docker"]["required"] is False        # docker is optional (embedded fallback)
    assert "docker daemon" not in by                                   # nothing to say with no docker binary


def test_install_hints_are_non_empty_shell_commands():
    for key, how in dmod._INSTALL.items():
        assert how.strip(), f"install hint {key} is empty"
    # the docker install line uses DISTRO packages only — no docker.com-repo-only package that would abort
    # the && chain (and leave the daemon un-enabled) on a stock box (red-pen F2).
    assert "docker-compose-plugin" not in dmod._INSTALL["docker"]
    assert "docker-compose-v2" in dmod._INSTALL["docker"]


def test_collect_daemon_down_is_a_NOTE_never_a_hard_issue(tmp_path, monkeypatch):
    # Mirror the known ok-True setup, then force docker present + daemon DOWN: the dependency preflight
    # must surface it as an advisory NOTE and must NOT add a hard issue (docker is optional).
    for v, tool in ((".venv-offense", "vigil"), (".venv-sovereign", "sigil")):
        b = tmp_path / v / "bin"; b.mkdir(parents=True); (b / tool).write_text("#!/bin/sh\n")
    monkeypatch.setattr(dmod, "_writable", lambda p: True)
    monkeypatch.setenv("VIGIL_BIN", str(tmp_path / ".venv-offense" / "bin" / "vigil"))
    monkeypatch.delenv("CRUCIBLE_LLM_BACKEND", raising=False)
    _real_which = dmod.shutil.which
    monkeypatch.setattr(dmod.shutil, "which",
                        lambda n: "/usr/bin/" + n if n == "docker" else _real_which(n))
    monkeypatch.setattr(dmod, "_docker_daemon_running", lambda *a, **k: False)
    monkeypatch.setattr(dmod, "_image_present", lambda *a, **k: False)
    report = dmod.collect(tmp_path)
    assert report["docker_daemon"] is False
    assert any("daemon is not answering" in n for n in report["notes"])
    assert not any("daemon" in i for i in report["issues"])            # note, NEVER a hard issue
    assert report["ok"] is True                                        # the dependency section never flips ok


def test_status_is_endpoint_aware(monkeypatch, tmp_path):
    # A differently-named EXTERNAL container serving the port (e.g. sigil-qdrant on 6333) must read as
    # reachable, not the misleading compose-scoped "absent".
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    rs = RootServices(tmp_path)
    monkeypatch.setattr(rs, "ps", dict)                                # this compose project has no container
    monkeypatch.setattr(RootServices, "_port_open",
                        staticmethod(lambda port, host="127.0.0.1", timeout=0.5: port == 6333))
    st = rs.status()
    assert st["qdrant"]["state"] == "absent" and st["qdrant"]["reachable"] is True
    assert st["neo4j"]["reachable"] is False


def test_port_open_guards_falsy_and_probes_real_sockets():
    # Exercise the REAL _port_open (not monkeypatched): falsy guard + a genuinely closed port + an open one.
    import socket
    assert RootServices._port_open(None) is False
    assert RootServices._port_open(0) is False
    free = socket.socket(); free.bind(("127.0.0.1", 0)); closed_port = free.getsockname()[1]; free.close()
    assert RootServices._port_open(closed_port) is False               # nothing listens → connection refused
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); open_port = srv.getsockname()[1]
    try:
        assert RootServices._port_open(open_port) is True              # something listens → reachable
    finally:
        srv.close()


def test_render_surfaces_install_commands_and_external_reachability():
    report = {
        "binaries": {}, "docker_daemon": True,
        "dependencies": [{"name": "egress-guard", "kind": "binary", "present": False, "required": False,
                          "detail": "seccomp egress guard", "how_to_install": "make -C tools/egress-guard"}],
        "docker_services": {"qdrant": {"state": "absent", "purpose": "vector memory", "reachable": True}},
    }
    txt = dmod.render(report)
    assert "make -C tools/egress-guard" in txt
    assert "a process is answering on the port" in txt
    assert "external container" not in txt          # no false "container"/identity claim (red-pen F4)
