"""AEGIS-SaaS AE-6 — sovereign per-(org, host) monitoring report-secret provisioning + resolver + drain CLI."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import time
from pathlib import Path

import pytest

from sigil import cli
from sigil.governor import monitoring_secrets as M
from sigil.inbound import monitoring_spool as S
from sigil.inbound.monitoring_spool import MonitoringSpoolWatcher
from sigil.spine.store import SpineStore


@pytest.fixture
def sdir(tmp_path):
    return tmp_path / "secrets"


def test_provision_writes_owner_only_random_secret_with_hashed_name(sdir):
    p = M.provision_report_secret("org_a", "app.example.com", sdir)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(sdir.stat().st_mode) == 0o700
    assert "org_a" not in p.name and "example" not in p.name
    sec = M.resolve_report_secret("org_a", "app.example.com", sdir)
    assert sec is not None and len(sec) == 64
    p2 = M.provision_report_secret("org_b", "app.example.com", sdir)
    assert p2 != p and M.resolve_report_secret("org_b", "app.example.com", sdir) != sec


def test_provision_refuses_overwrite_unless_rotate(sdir):
    M.provision_report_secret("org_a", "app.example.com", sdir)
    old = M.resolve_report_secret("org_a", "app.example.com", sdir)
    with pytest.raises(FileExistsError):
        M.provision_report_secret("org_a", "app.example.com", sdir)
    assert M.resolve_report_secret("org_a", "app.example.com", sdir) == old
    M.provision_report_secret("org_a", "app.example.com", sdir, rotate=True)
    assert M.resolve_report_secret("org_a", "app.example.com", sdir) != old


@pytest.mark.parametrize("org,host", [("", "app.example.com"), ("a\x00b", "app.example.com"),
                                      ("org_a", "http://x/"), ("org_a", "10.0.0.1"), ("org_a", "")])
def test_provision_refuses_bad_org_or_host(sdir, org, host):
    with pytest.raises(ValueError):
        M.provision_report_secret(org, host, sdir)


def test_resolver_is_exact_pair_and_fail_closed(sdir):
    M.provision_report_secret("org_a", "app.example.com", sdir)
    assert M.resolve_report_secret("org_b", "app.example.com", sdir) is None
    assert M.resolve_report_secret("org_a", "www.example.com", sdir) is None
    assert M.resolve_report_secret("org_a", "bad host", sdir) is None
    assert M.resolve_report_secret("org_a", "app.example.com", sdir / "nope") is None


def test_resolver_refuses_group_readable_symlink_short_oversized(sdir):
    p = M.provision_report_secret("org_a", "app.example.com", sdir)
    os.chmod(p, 0o640)
    assert M.resolve_report_secret("org_a", "app.example.com", sdir) is None
    os.chmod(p, 0o600)
    p.write_text("short\n")
    assert M.resolve_report_secret("org_a", "app.example.com", sdir) is None
    p.write_text("x" * 5000)
    assert M.resolve_report_secret("org_a", "app.example.com", sdir) is None
    real = sdir / "real"
    real.write_text("y" * 64)
    os.chmod(real, 0o600)
    p.unlink()
    p.symlink_to(real)
    assert M.resolve_report_secret("org_a", "app.example.com", sdir) is None


def test_secret_file_format_matches_gateway_loader_rule(sdir):
    # the gateway's --monitoring-secret-file loader uses the stripped file bytes; so does the resolver
    p = M.provision_report_secret("org_a", "app.example.com", sdir)
    assert M.resolve_report_secret("org_a", "app.example.com", sdir) == p.read_bytes().strip()


# ---- drain integration + CLI ------------------------------------------------------------------------
class _Auth:
    def __init__(self, active):
        self.active = set(active)

    def active_at(self, org, host, *, now):
        return object() if (org, host) in self.active else None


def _spool_report(spool: Path, org, host, secret: bytes, name="r1.json"):
    rep = {"schema": S.REPORT_SCHEMA, "org_id": org, "host": host, "ts": time.time(), "decision": "confirmed",
           "attack_class": "sqli_attempt", "action": "observe", "confidence": 0.97, "provenance_tier": "grounded",
           "certificate_sha256": "0" * 64, "report_id": hashlib.sha256(name.encode()).hexdigest()[:32]}
    body = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    mac = hmac.new(secret, S.REPORT_DOMAIN + body.encode(), hashlib.sha256).hexdigest()
    (spool / "incoming").mkdir(parents=True, exist_ok=True)
    (spool / "incoming" / name).write_text(json.dumps({"schema": S.REPORT_SCHEMA, "body": body, "mac": mac}))


def test_resolver_drives_drainer_per_pair(sdir, tmp_path):
    M.provision_report_secret("org_a", "app.example.com", sdir)
    M.provision_report_secret("org_b", "app.example.com", sdir)
    sa = M.resolve_report_secret("org_a", "app.example.com", sdir)
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    spool = tmp_path / "spool"
    w = MonitoringSpoolWatcher(store, spool_dir=spool, secret_for=M.resolver(sdir),
                               authority=_Auth({("org_a", "app.example.com"), ("org_b", "app.example.com")}))
    _spool_report(spool, "org_a", "app.example.com", sa, "ok.json")
    _spool_report(spool, "org_b", "app.example.com", sa, "forged.json")   # org_a's secret claiming org_b
    r = w.drain()
    assert r["recorded"] == 1 and r["rejected"] == 1
    assert [e["org_id"] for e in S.monitoring_events(store, "org_a")] == ["org_a"]
    assert S.monitoring_events(store, "org_b") == []


def _isolate_cli_spine_gate(monkeypatch):
    # The CLI's REAL startup migration gate still runs — it is NOT stubbed. It is only pointed at a FRESH, empty
    # spine for these tests, because the shared default spine may be left in a legacy layout by other tests in a
    # full run (cross-test pollution unrelated to these verbs; the gate's own behaviour is in test_spine_upgrade).
    import sigil.spine.upgrade as _up
    fresh = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    monkeypatch.setattr(_up, "SpineStore", lambda: fresh)


def test_cli_verbs_are_default_off(monkeypatch, tmp_path, capsys):
    _isolate_cli_spine_gate(monkeypatch)
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED", raising=False)
    for argv in (["monitoring-secret", "--org", "o", "--host", "app.example.com", "--secrets-dir", str(tmp_path)],
                 ["monitoring-drain", "--spool", str(tmp_path / "s"), "--secrets-dir", str(tmp_path)]):
        with pytest.raises(SystemExit) as e:
            cli.main(argv)
        assert e.value.code == 2
    assert list(tmp_path.iterdir()) == []


def test_cli_provision_then_drain(monkeypatch, tmp_path, capsys):
    _isolate_cli_spine_gate(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    sdir = tmp_path / "secrets"
    cli.main(["monitoring-secret", "--org", "org_a", "--host", "app.example.com", "--secrets-dir", str(sdir)])
    out = capsys.readouterr().out
    sec = M.resolve_report_secret("org_a", "app.example.com", sdir)
    assert sec.decode() not in out                                       # path printed, never the secret
    with pytest.raises(SystemExit):
        cli.main(["monitoring-secret", "--org", "org_a", "--host", "app.example.com", "--secrets-dir", str(sdir)])

    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    monkeypatch.setattr(cli, "SpineStore", lambda: store)
    import sigil.governor.monitoring_authority as MA
    monkeypatch.setattr(MA, "MonitoringAuthorityRegistry",
                        lambda st, owner_key=None: _Auth({("org_a", "app.example.com")}))
    spool = tmp_path / "spool"
    _spool_report(spool, "org_a", "app.example.com", sec, "a.json")
    _spool_report(spool, "org_a", "app.example.com", b"z" * 64, "bad.json")
    cli.main(["monitoring-drain", "drain", "--spool", str(spool), "--secrets-dir", str(sdir)])
    assert "1 recorded, 1 rejected" in capsys.readouterr().out
    assert len(S.monitoring_events(store, "org_a")) == 1


def test_resolver_refuses_fifo_even_with_secret_bytes_waiting(sdir):
    p = M.provision_report_secret("org_a", "app.example.com", sdir)
    p.unlink()
    os.mkfifo(p, 0o600)
    w = os.open(str(p), os.O_RDWR | os.O_NONBLOCK)      # a hostile writer with secret-shaped bytes queued
    try:
        os.write(w, b"f" * 64)
        assert M.resolve_report_secret("org_a", "app.example.com", sdir) is None
    finally:
        os.close(w)


# ---- export (CodeQL fold: the CLI never prints the secret's location; export to an operator-chosen file) ------
def test_export_writes_an_atomic_0600_copy(tmp_path):
    sdir = tmp_path / "s"
    M.provision_report_secret("org_a", "app.example.com", sdir)
    dest = tmp_path / "out" / "gw.secret"
    M.export_report_secret("org_a", "app.example.com", sdir, dest)
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert dest.read_bytes().strip() == M.resolve_report_secret("org_a", "app.example.com", sdir)


def test_export_refuses_unprovisioned_existing_and_symlink_destinations(tmp_path):
    sdir = tmp_path / "s"
    with pytest.raises(ValueError):
        M.export_report_secret("org_a", "app.example.com", sdir, tmp_path / "x")
    M.provision_report_secret("org_a", "app.example.com", sdir)
    dest = tmp_path / "gw.secret"
    M.export_report_secret("org_a", "app.example.com", sdir, dest)
    with pytest.raises(FileExistsError):
        M.export_report_secret("org_a", "app.example.com", sdir, dest)
    M.export_report_secret("org_a", "app.example.com", sdir, dest, overwrite=True)
    real = tmp_path / "victim"
    real.write_text("keep")
    link = tmp_path / "link.secret"
    os.symlink(real, link)
    with pytest.raises(ValueError):
        M.export_report_secret("org_a", "app.example.com", sdir, link, overwrite=True)
    assert real.read_text() == "keep"
    with pytest.raises(ValueError):
        M.export_report_secret("org_a", "app.example.com", sdir, tmp_path, overwrite=True)   # a directory


def test_cli_output_never_contains_the_secret_or_its_location(monkeypatch, tmp_path, capsys):
    _isolate_cli_spine_gate(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    sdir = tmp_path / "secrets"
    dest = tmp_path / "staging" / "gw.secret"
    cli.main(["monitoring-secret", "--org", "org_a", "--host", "app.example.com", "--secrets-dir", str(sdir),
              "--export-to", str(dest)])
    out = capsys.readouterr()
    text = out.out + out.err
    sec = M.resolve_report_secret("org_a", "app.example.com", sdir)
    assert sec.decode() not in text
    assert M.secret_filename("org_a", "app.example.com") not in text and str(sdir) not in text
    assert dest.read_bytes().strip() == sec
    with pytest.raises(SystemExit) as e:                                    # errors name only the exception type
        cli.main(["monitoring-secret", "--org", "org_a", "--host", "app.example.com", "--secrets-dir", str(sdir)])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "FileExistsError" in err and str(sdir) not in err
    with pytest.raises(SystemExit) as e:
        cli.main(["monitoring-secret", "--org", "org_a", "--host", "app.example.com", "--secrets-dir", str(sdir),
                  "--export-only"])
    assert e.value.code == 2


def test_cli_export_only_reexports_without_rotating(monkeypatch, tmp_path, capsys):
    _isolate_cli_spine_gate(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    sdir = tmp_path / "secrets"
    M.provision_report_secret("org_a", "app.example.com", sdir)
    before = M.resolve_report_secret("org_a", "app.example.com", sdir)
    dest = tmp_path / "gw.secret"
    cli.main(["monitoring-secret", "--org", "org_a", "--host", "app.example.com", "--secrets-dir", str(sdir),
              "--export-only", "--export-to", str(dest)])
    assert M.resolve_report_secret("org_a", "app.example.com", sdir) == before
    assert dest.read_bytes().strip() == before
