"""`vigil services` root-service bring-up (create-if-absent) + `vigil doctor` readiness report.

RootServices is exercised against a FAKE docker (subcommand-keyed subprocess) so the create-if-absent
logic + compose argv (profiles, env-file) are CI-testable without a daemon. doctor.collect()'s deterministic
prerequisite logic (venvs / writable dirs / the ok gate) is tested against a temp repo root.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vigil_integration import doctor as dmod
from vigil_integration import services as smod
from vigil_integration.services import RootServices


class FakeDocker:
    def __init__(self, *, ps_rows=None, up_rc=0):
        self.ps_rows = ps_rows or []
        self.up_rc = up_rc
        self.calls: list[list[str]] = []

    def run(self, cmd, capture_output=True, text=True, **kw):
        self.calls.append(list(cmd))
        sub = cmd[1:]                     # drop the docker binary
        if "ps" in sub:
            return SimpleNamespace(returncode=0, stdout="\n".join(json.dumps(r) for r in self.ps_rows),
                                   stderr="")
        if "up" in sub:
            return SimpleNamespace(returncode=self.up_rc, stdout="", stderr=("boom" if self.up_rc else ""))
        return SimpleNamespace(returncode=0, stdout="", stderr="")


@pytest.fixture
def fake(monkeypatch, tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    def _install(**kw):
        fd = FakeDocker(**kw)
        monkeypatch.setattr(smod.shutil, "which", lambda name: "/usr/bin/docker")
        monkeypatch.setattr(smod.subprocess, "run", fd.run)
        return fd, RootServices(tmp_path)
    return _install


# --------------------------- RootServices: create-if-absent + argv ---------------------------

def test_up_is_idempotent_compose_up_with_profiles(fake, tmp_path):
    fd, root = fake()
    root.up(["qdrant", "neo4j"])                     # neo4j needs the `graph` profile
    up = [c for c in fd.calls if "up" in c][0]
    assert "up" in up and "-d" in up and "qdrant" in up and "neo4j" in up
    assert "--profile" in up and "graph" in up        # profile-gated service → profile flag present
    assert "--env-file" not in up                     # the fixture repo has no .env → flag absent
    # when a repo .env DOES exist, it is passed through
    (root.repo_root / ".env").write_text("X=1\n", encoding="utf-8")
    root.up(["qdrant"])
    assert "--env-file" in [c for c in fd.calls if "up" in c][-1]


def test_up_raises_on_compose_failure(fake):
    fd, root = fake(up_rc=1)
    with pytest.raises(RuntimeError, match="docker compose up"):
        root.up(["qdrant"])


def test_status_reports_absent_and_running(fake):
    fd, root = fake(ps_rows=[{"Service": "qdrant", "State": "running"}])
    st = root.status()
    assert st["qdrant"]["state"] == "running"
    assert st["neo4j"]["state"] == "absent"           # no row → absent
    assert st["otel-collector"]["state"] == "absent"
    assert st["qdrant"]["port"] == 6333


def test_ps_parses_json_array_shape(monkeypatch, tmp_path):
    # compose v2 may emit a JSON ARRAY instead of NDJSON — both must parse.
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    def _run(cmd, capture_output=True, text=True, **kw):
        if "ps" in cmd[1:]:
            return SimpleNamespace(returncode=0,
                                   stdout=json.dumps([{"Service": "qdrant", "State": "running"}]), stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(smod.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(smod.subprocess, "run", _run)
    assert RootServices(tmp_path).ps().get("qdrant") == "running"


def test_up_ignores_unknown_services(fake):
    fd, root = fake()
    assert root.up(["not-a-real-service"]) == {}      # closed set — never composes an unknown service
    assert not [c for c in fd.calls if "up" in c]


# --------------------------------- doctor.collect / render ---------------------------------

def test_doctor_flags_missing_venvs(tmp_path):
    # a bare repo (no venvs) → ok False, an actionable issue naming the venv.
    report = dmod.collect(tmp_path)
    assert report["ok"] is False
    assert any("venv" in i for i in report["issues"])
    assert "ui_ports" in report and "docker_services" in report        # the report is complete
    assert isinstance(dmod.render(report), str) and "readiness" in dmod.render(report)


def test_doctor_ok_when_prereqs_present(tmp_path, monkeypatch):
    # fake both venvs; force the dir checks writable → ok True (docker services absent doesn't flip ok).
    for v in (".venv-offense", ".venv-sovereign"):
        b = tmp_path / v / "bin"
        b.mkdir(parents=True)
        (b / ("vigil" if v.endswith("offense") else "sigil")).write_text("#!/bin/sh\n")
    monkeypatch.setattr(dmod, "_writable", lambda p: True)
    # a RESOLVABLE `vigil` is now a hard prerequisite (else Terminal Run + the agentic bridge degrade);
    # point VIGIL_BIN at the faked offense entrypoint so only the pre-existing checks decide `ok`.
    monkeypatch.setenv("VIGIL_BIN", str(tmp_path / ".venv-offense" / "bin" / "vigil"))
    monkeypatch.delenv("CRUCIBLE_LLM_BACKEND", raising=False)   # auto backend → never a hard fail
    report = dmod.collect(tmp_path)
    assert report["ok"] is True and report["issues"] == []


def test_doctor_port_free_and_writable_helpers(tmp_path):
    import socket
    assert dmod._writable(tmp_path) is True
    assert dmod._writable(tmp_path / "does" / "not" / "exist") is True   # nearest existing parent writable
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 0))
    s.listen(1); port = s.getsockname()[1]
    try:
        assert dmod._port_free(port) is False
    finally:
        s.close()


def test_root_services_up_is_timeout_bounded(monkeypatch, tmp_path):
    # BLOCK-1: `compose up` (may pull an image) must be timeout-bounded so it can't hang the caller.
    from types import SimpleNamespace
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    seen = []

    def _run(cmd, capture_output=True, text=True, **kw):
        seen.append(kw.get("timeout"))
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(smod.shutil, "which", lambda n: "/usr/bin/docker")
    monkeypatch.setattr(smod.subprocess, "run", _run)
    RootServices(tmp_path).up(["qdrant"])
    up_timeouts = [seen[i] for i, _ in enumerate(seen)]
    assert up_timeouts and all(t is not None and t > 0 for t in up_timeouts)   # no unbounded call
    assert max(up_timeouts) >= 300                                             # `up` gets a generous bound


# ---------------------- W17-15: `vigil` on $PATH + the LLM-backend probe ----------------------
#
# `vigil` MUST be resolvable or two visible features degrade SILENTLY: the console Terminal Run button
# errors, and the agentic/fireteam engage bridge falls back to the non-agentic offense engine (console
# actions._vigil_bin → subprocess). doctor now surfaces that (a HARD issue naming both) and probes the
# resolved LLM backend + endpoint, distinguishing a reachable local daemon from an unreachable one.

def _seed_venvs(root):
    for v in (".venv-offense", ".venv-sovereign"):
        b = root / v / "bin"
        b.mkdir(parents=True)
        (b / ("vigil" if v.endswith("offense") else "sigil")).write_text("#!/bin/sh\n")


def test_doctor_fails_when_vigil_not_on_path_naming_both_features(tmp_path, monkeypatch):
    # both venvs + writable dirs present, so ONLY the vigil-entrypoint gate can flip `ok`.
    _seed_venvs(tmp_path)
    monkeypatch.setattr(dmod, "_writable", lambda p: True)
    monkeypatch.delenv("VIGIL_BIN", raising=False)
    monkeypatch.delenv("CRUCIBLE_LLM_BACKEND", raising=False)
    real_which = dmod.shutil.which
    monkeypatch.setattr(dmod.shutil, "which", lambda n: None if n == "vigil" else real_which(n))

    report = dmod.collect(tmp_path)
    assert report["ok"] is False                                    # the silence is now a hard failure
    assert report["vigil_entrypoint"]["resolved"] is False
    vissue = [i for i in report["issues"] if "vigil" in i and "$PATH" in i]
    assert vissue, "doctor must raise a `vigil` on $PATH issue"
    # names BOTH degraded features by name — the whole point of the fix (no more silent degradation).
    assert "Terminal Run" in vissue[0] and "agentic/fireteam" in vissue[0]
    assert "!! vigil" in dmod.render(report)

    # NEGATIVE CONTROL: the SAME tree, but `vigil` IS resolvable via VIGIL_BIN → the gate passes, `ok`
    # returns True, and no vigil-$PATH issue is raised. Proves the gate is not a constant-fail no-op.
    monkeypatch.setattr(dmod.shutil, "which", real_which)
    monkeypatch.setenv("VIGIL_BIN", str(tmp_path / ".venv-offense" / "bin" / "vigil"))
    ok_report = dmod.collect(tmp_path)
    assert ok_report["vigil_entrypoint"]["resolved"] is True
    assert ok_report["vigil_entrypoint"]["source"] == "VIGIL_BIN"
    assert not any("vigil" in i and "$PATH" in i for i in ok_report["issues"])
    assert ok_report["ok"] is True


def test_llm_backend_probe_distinguishes_reachable_from_unreachable(monkeypatch):
    import socket
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "ollama")            # pin a local backend → deterministic

    # UNREACHABLE (negative control): a closed loopback port (bound then released).
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed_port = s.getsockname()[1]; s.close()
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", f"http://127.0.0.1:{closed_port}")
    down = dmod._probe_llm_backend()
    assert down["backend"] == "ollama" and down["local"] is True
    assert down["endpoint"] == f"http://127.0.0.1:{closed_port}"    # the probe REPORTS the resolved endpoint
    assert down["reachable"] is False                              # an unreachable local backend

    # REACHABLE: a live loopback listener on a different ephemeral port.
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1); up_port = srv.getsockname()[1]
    try:
        monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", f"http://127.0.0.1:{up_port}")
        up = dmod._probe_llm_backend()
        assert up["backend"] == "ollama" and up["reachable"] is True
        assert up["endpoint"] == f"http://127.0.0.1:{up_port}"
    finally:
        srv.close()

    # the two states are actually DISTINGUISHED (not a constant reachability value).
    assert down["reachable"] is not up["reachable"]


def test_llm_backend_probe_reports_backend_and_endpoint_and_refuses_nonloopback(monkeypatch):
    # a cloud override reports the backend without any local probe (reachable is not-applicable → None).
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "anthropic")
    cloud = dmod._probe_llm_backend()
    assert cloud["backend"] == "anthropic" and cloud["local"] is False and cloud["reachable"] is None
    assert cloud["source"] == "CRUCIBLE_LLM_BACKEND"

    # a NON-loopback local endpoint is REFUSED, never probed (would send the prompt off-host).
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "ollama")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://10.0.0.5:11434")
    remote = dmod._probe_llm_backend()
    assert remote["reachable"] is None and "REFUSES" in remote["detail"]
    assert remote["endpoint"] == "http://10.0.0.5:11434"           # reported, but not dialled


def test_doctor_notes_unreachable_local_backend_but_does_not_flip_ok(tmp_path, monkeypatch):
    import socket
    _seed_venvs(tmp_path)
    monkeypatch.setattr(dmod, "_writable", lambda p: True)
    monkeypatch.setenv("VIGIL_BIN", str(tmp_path / ".venv-offense" / "bin" / "vigil"))
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "ollama")
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", f"http://127.0.0.1:{closed}")

    report = dmod.collect(tmp_path)
    # an unreachable LOCAL backend is ADVISORY (a cloud pick needs no daemon) — a note, never a hard fail.
    assert report["ok"] is True
    assert any("not answering" in n for n in report["notes"])
    assert report["llm_backend"]["reachable"] is False

    # NEGATIVE CONTROL: a reachable local backend produces NO such note.
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1); up = srv.getsockname()[1]
    try:
        monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", f"http://127.0.0.1:{up}")
        ok_report = dmod.collect(tmp_path)
        assert not any("not answering" in n for n in ok_report["notes"])
        assert ok_report["llm_backend"]["reachable"] is True
    finally:
        srv.close()


def test_env_example_documents_ollama_host_matching_the_engine():
    # DOC-TRUTH: `.env.example` must document CRUCIBLE_OLLAMA_HOST, and the documented default must equal
    # doctor's mirror constant, which must equal the engine's REAL default (derived from think_claude's
    # source so the three cannot drift apart).
    import pathlib
    repo = pathlib.Path(dmod.__file__).resolve().parents[2]
    env_example = (repo / ".env.example").read_text(encoding="utf-8")
    assert "CRUCIBLE_OLLAMA_HOST" in env_example
    assert dmod._OLLAMA_DEFAULT_HOST in env_example
    think = (pathlib.Path(dmod.__file__).resolve().parent / "live" / "think_claude.py").read_text(encoding="utf-8")
    assert f'"CRUCIBLE_OLLAMA_HOST", "{dmod._OLLAMA_DEFAULT_HOST}"' in think, \
        "doctor's Ollama default drifted from think_claude._configured_local_endpoint"
