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
