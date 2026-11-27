"""AEGIS-SaaS AE-6 — managed-deployment gateway CLI flags (secret from a 0600 file, never argv)."""
from __future__ import annotations

import os

import pytest

from framework.v2.aegis import cli as C
from framework.v2.aegis import gateway as G

SECRET = "a" * 64


def _secret_file(tmp_path, content=SECRET, name="report.secret"):
    p = tmp_path / name
    p.write_text(content + "\n")
    os.chmod(p, 0o600)
    return p


def _report_loose_mode(monkeypatch, target, extra_bits):
    """Make the loader SEE group/world permission bits on ``target`` without ever writing a permissive secret
    file to disk: ``os.fstat`` reports the extra bits for that inode only (the file itself stays 0600)."""
    real = os.fstat
    ino = os.stat(target).st_ino

    def fstat(fd):
        st = real(fd)
        if st.st_ino != ino:
            return st
        fields = list(st)
        fields[0] = st.st_mode | extra_bits
        return os.stat_result(fields)
    monkeypatch.setattr(os, "fstat", fstat)


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


@pytest.mark.parametrize("extra_bits", [0o040, 0o004, 0o044, 0o060])
def test_loader_refuses_group_or_world_readable(tmp_path, monkeypatch, extra_bits):
    sf = _secret_file(tmp_path)
    _report_loose_mode(monkeypatch, sf, extra_bits)
    with pytest.raises(ValueError, match="owner-only"):
        C.load_monitoring_secret(str(sf))


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
        C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--secret", "a-real-deployment-secret-key",
                "--saas-tenant", "org_a",
                "--saas-host", "app.example.com", "--monitoring-spool", str(tmp_path / "spool"),
                "--monitoring-secret-file", str(sf)])
    assert captured["saas_tenant"] == "org_a"
    assert captured["saas_host"] == "app.example.com"
    assert captured["monitoring_spool"] == str(tmp_path / "spool")
    assert captured["monitoring_secret"] == SECRET.encode()


def test_default_is_legacy_gateway(captured):
    with pytest.raises(_Stop):
        C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--secret", "a-real-deployment-secret-key"])
    for k in ("saas_tenant", "saas_host", "monitoring_spool", "monitoring_secret"):
        assert captured.get(k) is None


def test_bad_secret_file_exits_2_without_serving(tmp_path, captured, capsys, monkeypatch):
    sf = _secret_file(tmp_path)
    _report_loose_mode(monkeypatch, sf, 0o044)
    rc = C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--saas-tenant", "org_a",
                 "--saas-host", "app.example.com", "--monitoring-spool", str(tmp_path / "s"),
                 "--monitoring-secret-file", str(sf)])
    assert rc == 2 and captured == {}
    assert SECRET not in capsys.readouterr().err


# ---- AS-2j (N-A fix): the deployment/pseudonymization secret from a 0600 file / credential, never the env ----

def test_deployment_secret_file_loads_into_config_not_from_env(tmp_path, captured):
    """--deployment-secret-file reads the pseudonymization secret from a 0600 file (so it never sits in the
    process environment / /proc/<pid>/environ). The loaded secret reaches AegisConfig.deployment_secret."""
    sf = _secret_file(tmp_path, name="gw.secret")
    with pytest.raises(_Stop):
        C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--deployment-secret-file", str(sf)])
    # The file secret reaches the config as RAW BYTES (never UTF-8-decoded) — identical handling to the
    # sibling report secret (see `monitoring_secret == SECRET.encode()` above), so random-byte provisioning works.
    assert captured["config"].deployment_secret == SECRET.encode()


def test_deployment_secret_file_wins_over_env_secret(tmp_path, captured, monkeypatch):
    """The hardened unit passes the secret ONLY through LoadCredential; a stray AEGIS_GW_SECRET in the env must
    not override the file source (the file is the isolated path)."""
    sf = _secret_file(tmp_path, content="f" * 48, name="gw.secret")
    monkeypatch.setenv("AEGIS_GW_SECRET", "e" * 48)   # set AFTER the fixture cleared AEGIS_GW_*
    with pytest.raises(_Stop):
        C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--deployment-secret-file", str(sf)])
    assert captured["config"].deployment_secret == b"f" * 48


def test_deployment_secret_file_via_env_var(tmp_path, captured, monkeypatch):
    sf = _secret_file(tmp_path, content="g" * 40, name="gw.secret")
    monkeypatch.setenv("AEGIS_GW_SECRET_FILE", str(sf))
    with pytest.raises(_Stop):
        C.main(["gateway", "--upstream", "http://127.0.0.1:9"])
    assert captured["config"].deployment_secret == b"g" * 40


def test_default_off_without_the_flag_is_unchanged(tmp_path, captured, monkeypatch):
    """Byte-identical when off: with no file source, the legacy AEGIS_GW_SECRET env path is used verbatim."""
    monkeypatch.setenv("AEGIS_GW_SECRET", "h" * 40)
    with pytest.raises(_Stop):
        C.main(["gateway", "--upstream", "http://127.0.0.1:9"])
    assert captured["config"].deployment_secret == "h" * 40


# A fixed 32-byte RAW RANDOM secret (what the runbook's `head -c 32 /dev/urandom` yields). 0xff + lone
# continuation bytes make it never valid UTF-8 — the exact input the pre-fix `.decode("utf-8")` crashed on.
_NON_UTF8_SECRET = b"\xff\xfe\x80\x81\x82\x83\x84\x85" * 4


def test_deployment_secret_file_accepts_non_utf8_random_bytes(tmp_path, captured):
    """REGRESSION (AS-2j N-A): the runbook provisions the deployment secret as RAW RANDOM BYTES
    (`head -c 32 /dev/urandom`), which are not valid UTF-8. The pre-fix loader `.decode("utf-8")` crashed on
    them, so the documented provisioning path was broken (it exited 2 / never served). After the fix the raw
    bytes reach AegisConfig.deployment_secret and the gateway serves — identical handling to the report secret.
    """
    assert len(_NON_UTF8_SECRET) == 32
    with pytest.raises(UnicodeDecodeError):             # the bytes are non-UTF-8 (the pre-fix crash path)
        _NON_UTF8_SECRET.decode("utf-8")
    sf = tmp_path / "gw.secret"
    sf.write_bytes(_NON_UTF8_SECRET)
    os.chmod(sf, 0o600)
    with pytest.raises(_Stop):                           # _Stop => serve_gateway was reached (load OK, no exit 2)
        C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--deployment-secret-file", str(sf)])
    assert captured["config"].deployment_secret == _NON_UTF8_SECRET
    # and the raw-bytes secret actually keys the pseudonymization HMAC: deterministic, non-empty, no crash.
    from framework.v2.aegis.boundary import hmac_id
    h = hmac_id("alice", secret=captured["config"].deployment_secret)
    assert h and h == hmac_id("alice", secret=_NON_UTF8_SECRET)


def test_bad_deployment_secret_file_exits_2_without_serving_or_leaking(tmp_path, captured, capsys, monkeypatch):
    sf = _secret_file(tmp_path, name="gw.secret")
    _report_loose_mode(monkeypatch, sf, 0o044)        # group/world readable -> fail-closed
    rc = C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--deployment-secret-file", str(sf)])
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
