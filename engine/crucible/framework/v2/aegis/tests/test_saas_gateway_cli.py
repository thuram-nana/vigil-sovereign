"""AEGIS-SaaS AE-6 — managed-deployment gateway CLI flags (secret from a 0600 file, never argv)."""
from __future__ import annotations

import os

import pytest

from framework.v2.aegis import cli as C
from framework.v2.aegis import gateway as G

SECRET = "a" * 64


def _secret_file(tmp_path, content=SECRET, mode=0o600, name="report.secret"):
    p = tmp_path / name
    p.write_text(content + "\n")
    os.chmod(p, mode)
    return p


class _Stop(Exception):
    pass


@pytest.fixture
def captured(monkeypatch):
    seen = {}

    def fake(upstream, **kw):
        seen.update(kw, upstream=upstream)
        raise _Stop()

    monkeypatch.setattr(G, "serve_gateway", fake)
    for k in list(os.environ):
        if k.startswith("AEGIS_GW_"):
            monkeypatch.delenv(k)
    return seen


def test_loader_reads_stripped_secret(tmp_path):
    assert C.load_monitoring_secret(str(_secret_file(tmp_path))) == SECRET.encode()


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660])
def test_loader_refuses_group_or_world_readable(tmp_path, mode):
    with pytest.raises(ValueError, match="owner-only"):
        C.load_monitoring_secret(str(_secret_file(tmp_path, mode=mode)))


def test_loader_refuses_short_secret(tmp_path):
    with pytest.raises(ValueError, match="16 bytes"):
        C.load_monitoring_secret(str(_secret_file(tmp_path, content="  short  ")))


def test_loader_refuses_symlink(tmp_path):
    real = _secret_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        C.load_monitoring_secret(str(link))


def test_loader_refuses_fifo(tmp_path):
    f = tmp_path / "fifo"
    os.mkfifo(f, 0o600)
    with pytest.raises(ValueError, match="regular"):
        C.load_monitoring_secret(str(f))


def test_loader_refuses_oversized(tmp_path):
    with pytest.raises(ValueError, match="too large"):
        C.load_monitoring_secret(str(_secret_file(tmp_path, content="x" * 5000)))


def test_flags_wire_tenant_host_spool_and_file_secret(tmp_path, captured):
    sf = _secret_file(tmp_path)
    with pytest.raises(_Stop):
        C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--saas-tenant", "org_a",
                "--saas-host", "app.example.com", "--monitoring-spool", str(tmp_path / "spool"),
                "--monitoring-secret-file", str(sf)])
    assert captured["saas_tenant"] == "org_a"
    assert captured["saas_host"] == "app.example.com"
    assert captured["monitoring_spool"] == str(tmp_path / "spool")
    assert captured["monitoring_secret"] == SECRET.encode()


def test_default_is_legacy_gateway(captured):
    with pytest.raises(_Stop):
        C.main(["gateway", "--upstream", "http://127.0.0.1:9"])
    for k in ("saas_tenant", "saas_host", "monitoring_spool", "monitoring_secret"):
        assert captured.get(k) is None


def test_bad_secret_file_exits_2_without_serving(tmp_path, captured, capsys):
    sf = _secret_file(tmp_path, mode=0o644)
    rc = C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--saas-tenant", "org_a",
                 "--saas-host", "app.example.com", "--monitoring-spool", str(tmp_path / "s"),
                 "--monitoring-secret-file", str(sf)])
    assert rc == 2 and captured == {}
    assert SECRET not in capsys.readouterr().err


def test_real_gateway_refusals_exit_2(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("AEGIS_GW_"):
            monkeypatch.delenv(k)
    # spool without a tenant: the real serve_gateway refuses; the CLI exits 2 instead of a traceback
    sf = _secret_file(tmp_path)
    assert C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--port", "0",
                   "--monitoring-spool", str(tmp_path / "s"), "--monitoring-secret-file", str(sf)]) == 2
    # tenant without a host
    assert C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--port", "0",
                   "--saas-tenant", "org_a"]) == 2
