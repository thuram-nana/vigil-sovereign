"""MONEY-4 (readiness slice #69): a drain that QUARANTINED something must not read HEALTHY.

Every inbound spool drain (findings, billing webhooks, engagement-completion SETTLES) already moves a
failed / forged / out-of-scope envelope to ``rejected/`` instead of appending it — but the drain still
*exited 0*, so the ``unit-heartbeat`` ExecStopPost hook recorded ``ok=true`` and the staleness dead-man
reported the unit HEALTHY. A buried settle (a completed customer run never charged / never refunded), a
buried paid webhook (the customer paid, no credit), or a buried crossed finding (an oracle-confirmed result
lost to its tenant) raised NO alarm — the only trace was a file nobody watches.

This pins the fix: ``sigil.inbound.quarantined_count`` counts the STANDING quarantine (off disk, every run —
not this run's transient reject count), and each drain CLI exits non-zero (1) while it is > 0, so systemd
records a non-``success`` SERVICE_RESULT -> the heartbeat writes ``ok=false`` -> the dead-man reports the
unit FAILED (and ``vigil alerts`` exits non-zero) until a human empties ``rejected/``.

Sovereign leg: PYTHONPATH=apps/sigil (the settle delegation is built with vigil_core, framework-free).
"""
from __future__ import annotations

import tempfile
import types
from pathlib import Path

import pytest

from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.inbound import quarantined_count
from vigil_core import AuthorizerKey, generate_keypair


# ── the helper: STANDING count of quarantined envelopes, .reason sidecars excluded ──────────────────────

def test_count_zero_on_empty_dir(tmp_path):
    (tmp_path / "rejected").mkdir()
    assert quarantined_count(tmp_path / "rejected") == 0


def test_count_absent_dir_is_zero_not_error(tmp_path):
    # fail-closed-but-sane: an absent rejected/ means nothing was ever quarantined (never created), not a crash
    assert quarantined_count(tmp_path / "does-not-exist") == 0


def test_counts_envelopes_excludes_reason_sidecars(tmp_path):
    r = tmp_path / "rejected"
    r.mkdir()
    (r / "a.json").write_text("{}", encoding="utf-8")
    (r / "a.json.reason").write_text("why a failed", encoding="utf-8")       # sidecar — NOT counted
    (r / "b.json").write_text("{}", encoding="utf-8")
    (r / "c.json.orphan").write_text("{}", encoding="utf-8")                  # a name-collision copy IS an envelope
    (r / "c.json.orphan.reason").write_text("why c", encoding="utf-8")       # sidecar — NOT counted
    assert quarantined_count(r) == 3                                         # a, b, c.orphan — not the 2 reasons


def test_count_ignores_reason_only_cleared_envelope(tmp_path):
    # a human cleared the envelope but left the .reason -> nothing left to act on -> 0 (no false standing alarm)
    r = tmp_path / "rejected"
    r.mkdir()
    (r / "x.json.reason").write_text("stale explanation", encoding="utf-8")
    assert quarantined_count(r) == 0


# ── the three drain CLIs exit non-zero while the quarantine stands, and 0/clean when it is empty ─────────

def _write_gov_delegation(dirpath: Path) -> str:
    """An owner + an owner-signed OFFENSE_GOVERNANCE delegation scoped to ``*`` (the drain CLI scope), written
    to a JSON file the CLI loads via DelegationCert.model_validate_json."""
    owner = ensure_owner_keypair()
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope="*", not_after=9_000_000_000)
    p = dirpath / "gov.delegation.json"
    p.write_text(deleg.model_dump_json(), encoding="utf-8")
    return str(p)


def _seed_quarantine(spool: Path) -> None:
    (spool / "rejected").mkdir(parents=True, exist_ok=True)
    (spool / "rejected" / "buried.json").write_text("{}", encoding="utf-8")
    (spool / "rejected" / "buried.json.reason").write_text("forged signature", encoding="utf-8")


def test_settle_drain_exits_nonzero_on_a_standing_quarantine(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    from sigil.cli import cmd_settle_drain
    deleg = _write_gov_delegation(tmp_path)
    spool = tmp_path / "settle"
    _seed_quarantine(spool)
    a = types.SimpleNamespace(spool=str(spool), base_dir=str(tmp_path / "base"), delegation=deleg,
                              scope="*", settle_cmd="drain", interval=2.0)
    with pytest.raises(SystemExit) as ei:
        cmd_settle_drain(a)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "quarantined" in err and "UNSETTLED" in err


def test_settle_drain_exits_clean_when_quarantine_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    from sigil.cli import cmd_settle_drain
    deleg = _write_gov_delegation(tmp_path)
    spool = tmp_path / "settle"
    (spool / "incoming").mkdir(parents=True)
    a = types.SimpleNamespace(spool=str(spool), base_dir=str(tmp_path / "base"), delegation=deleg,
                              scope="*", settle_cmd="drain", interval=2.0)
    cmd_settle_drain(a)                                      # returns normally (no SystemExit) — clean drain


def test_inbound_finding_drain_exits_nonzero_on_a_standing_quarantine(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    from sigil.cli import cmd_inbound
    deleg = _write_gov_delegation(tmp_path)
    spool = tmp_path / "findings"
    _seed_quarantine(spool)
    a = types.SimpleNamespace(spool=str(spool), scope="*", governance_delegation=deleg,
                              spine_delegation="", inbound_cmd="drain", interval=2.0)
    with pytest.raises(SystemExit) as ei:
        cmd_inbound(a)
    assert ei.value.code == 1
    assert "quarantined" in capsys.readouterr().err


def test_billing_drain_exits_nonzero_on_a_standing_quarantine(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("HOME", tempfile.mkdtemp())        # hermetic: the drain compares with ~/.sigil/cockpit.env
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    ensure_owner_keypair()
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "billing-cli-secret")
    from sigil import cli
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: (lambda txid: {}))  # never called (empty)
    spool = tmp_path / "billing"
    _seed_quarantine(spool)
    a = types.SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_billing_drain(a)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "quarantined" in err and "UN-MINTED" in err
    assert "billing-cli-secret" not in err                   # the alarm never prints the verif-hash secret
