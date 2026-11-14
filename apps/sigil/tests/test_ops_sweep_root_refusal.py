"""E3bc — ``ops-sweep reservations --apply`` refuses to run as root over directories the services own.

A root sweep would create seam settlement markers and their locks, spine segment files or meter state as root inside
the services' directories, after which the services cannot write them and their settles fail. So, running as root,
``--apply`` fails fast — nothing settled — unless the seam and the spine directories (and, where they exist, the
settlement-marker, completion-spool and model-meter directories) are owned by root, and says to run it as the service
user. Report-only sweeps and a non-root ``--apply`` are unchanged.

Mutation-verify targets (each neuter turns a NAMED test red):
  * the refusal dropped from the CLI                          -> test_ops_sweep_apply_as_root_refuses_over_...
  * the ownership check dropped                               -> test_root_apply_refusal_needs_root_owned_directories

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_ops_sweep_root_refusal.py
"""
from __future__ import annotations

import argparse
import os

import pytest

from sigil import ops_sweeps
from test_settle_one_pass_evidence import (  # noqa: F401  (_iso: the autouse isolation fixture)
    NOW, _avail, _base, _iso, _published, _reserve, _seat, _spool, _store,
)
from vigil_integration.live.credit_lease_broker import is_lease_settled


@pytest.fixture
def record_on(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")


def test_root_apply_refusal_needs_root_owned_directories(tmp_path):
    mine = tmp_path / "mine"
    mine.mkdir()
    if os.geteuid() == 0:
        os.chown(mine, 1000, 1000)                                         # a service user's directory
    missing = tmp_path / "missing"
    assert ops_sweeps.root_apply_refusal([("seam directory", "/")], euid=0) is None
    assert "is owned by uid" in ops_sweeps.root_apply_refusal([("seam directory", mine)], euid=0)
    assert "does not exist" in ops_sweeps.root_apply_refusal([("spine directory", missing)], euid=0)
    assert ops_sweeps.root_apply_refusal([("seam directory", "/")], [("completion spool", missing)], euid=0) is None
    assert "is owned by uid" in ops_sweeps.root_apply_refusal([("seam directory", "/")], [("spool", mine)], euid=0)
    assert ops_sweeps.root_apply_refusal([("seam directory", mine), ("spine", missing)], euid=1000) is None


def test_ops_sweep_apply_as_root_refuses_over_the_services_directories(record_on, monkeypatch, capsys):
    import sigil.cli as cli
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=1, nonce="A" * 16)    # abandoned once the TTL has passed
    if os.geteuid() == 0:
        os.chown(_base(), 1000, 1000)                                      # the seam belongs to the service user
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("VIGIL_OPS_SWEEP_APPLY_ENABLED", "1")
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    ns = argparse.Namespace(sweep_cmd="reservations", ttl=50.0, apply=True, base_dir="", completion_spool=_spool(),
                            checkouts="", spool="", now=NOW + 3 * 3600)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_ops_sweep(ns)
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert "--apply refused: running as root" in err and "seam directory" in err and "service user" in err
    assert _avail(s) == 700 and not is_lease_settled(_base(), rA["slug"], rA["nonce"]) and _published(rA)
