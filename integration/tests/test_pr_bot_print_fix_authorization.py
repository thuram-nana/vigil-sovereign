"""repo-connect 3c helper: ``vigil pr-bot --print-fix-authorization`` prints the exact m-of-n authorize
command for ONE finding — action_id ``pr-<rid>``, the engagement slug, and the DETERMINISTIC PR-head
clone-path target the quorum binds — and FAILS CLOSED on an unknown finding ref or missing args. It is
read-only (no token, queue, or network): the happy path monkeypatches the real offense-side spine rebuild +
rid derivation so no real spine/crypto is needed; the fail-closed path exercises the REAL functions.
"""
from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.authority.store", reason="the pr-bot CLI import + spine rebuild are offense-side")

from vigil_integration import cli  # noqa: E402


def _args(tmp_path, **over):
    base = dict(print_fix_authorization=True, repo="github.com/acme/widget", pr=7, finding_ref="R1",
                base_dir=str(tmp_path))
    base.update(over)
    return argparse.Namespace(**base)


def test_prints_the_authorize_command(capsys, monkeypatch, tmp_path):
    # the read-only key pre-check passes (key present); fake the signed-spine rebuild + the deterministic rid so
    # the happy path needs no real spine/crypto
    monkeypatch.setattr("vigil_integration.live.spine_identity.try_load_spine_keypair", lambda **kw: object())
    monkeypatch.setattr("vigil_integration.live.trusted_finding.finding_from_spine",
                        lambda **kw: SimpleNamespace(ref=kw["finding_ref"]))
    monkeypatch.setattr("vigil_integration.autopatch.loop._derive_remediation_id", lambda rid, f: "abc123")
    rc = cli._cmd_pr_bot(_args(tmp_path))
    out = capsys.readouterr().out
    assert rc == 0
    assert "pr-abc123" in out                                   # action_id = pr-<rid>
    # the printed target is the EXACT path the drain's checkout produces (both via the one _safe_workdir), so
    # the operator authorizes precisely what the quorum binds — the helper-matches-drain invariant.
    from vigil_integration.jobs.model import SecurityJob
    from vigil_integration.live.pr_checkout import _safe_workdir
    slug = SecurityJob(repo="github.com/acme/widget").slug
    assert slug in out                                          # the engagement slug (injective repo slug)
    assert _safe_workdir(str(tmp_path), f"prbot-{slug}-7") in out   # the exact deterministic clone-path target
    assert "vigil authorize-destruction" in out and "--fix-pr" in out   # the turnkey command sequence


def test_unknown_ref_fails_closed(capsys, monkeypatch, tmp_path):
    from vigil_integration.live.trusted_finding import TrustedFindingError
    monkeypatch.setattr("vigil_integration.live.spine_identity.try_load_spine_keypair", lambda **kw: object())

    def _raise(**kw):
        raise TrustedFindingError("no confirmed fact with that ref")

    monkeypatch.setattr("vigil_integration.live.trusted_finding.finding_from_spine", _raise)
    rc = cli._cmd_pr_bot(_args(tmp_path))                        # key present, but the ref has no confirmed fact
    assert rc == 2                                               # fail-closed — no action fabricated
    assert "no confirmed fact" in capsys.readouterr().err


def test_absent_spine_key_fails_closed_without_rebuilding(capsys, monkeypatch, tmp_path):
    """red-pen MEDIUM (confirmed): a READ-ONLY dry run must NEVER reach finding_from_spine (which LOAD-or-CREATES
    the spine key) when the key is absent — else it mints a stray private key AND orphans the real spine."""
    monkeypatch.setattr("vigil_integration.live.spine_identity.try_load_spine_keypair", lambda **kw: None)
    called: list = []
    monkeypatch.setattr("vigil_integration.live.trusted_finding.finding_from_spine",
                        lambda **kw: called.append(1))
    rc = cli._cmd_pr_bot(_args(tmp_path))
    assert rc == 2 and called == []                             # refused BEFORE the key-creating spine rebuild
    assert "absent or unopenable" in capsys.readouterr().err


def test_sealed_unopenable_key_fails_closed(capsys, monkeypatch, tmp_path):
    """a sealed-but-unopenable key (VaultLocked from the TPM) ALSO fails closed (rc=2), never an uncaught crash."""
    from vigil_core.vault import VaultLocked

    def _locked(**kw):
        raise VaultLocked("tpm locked")

    monkeypatch.setattr("vigil_integration.live.spine_identity.try_load_spine_keypair", _locked)
    called: list = []
    monkeypatch.setattr("vigil_integration.live.trusted_finding.finding_from_spine",
                        lambda **kw: called.append(1))
    rc = cli._cmd_pr_bot(_args(tmp_path))
    assert rc == 2 and called == []                             # caught → fail-closed, rebuild never reached


def test_read_only_creates_no_files(tmp_path):
    """END-TO-END (REAL functions, no monkeypatch): the dry run writes NOTHING to --base-dir — no spine key, no
    vault — even though finding_from_spine would LOAD-or-CREATE the key. The read-only guard returns rc=2 first."""
    import os
    before = set(os.listdir(tmp_path))
    rc = cli._cmd_pr_bot(_args(tmp_path))                        # empty dir ⇒ no key ⇒ the guard fails closed
    assert rc == 2
    assert set(os.listdir(tmp_path)) == before                  # base-dir UNCHANGED (no stray offense-spine.key)


def test_missing_args_fail_closed(tmp_path):
    assert cli._cmd_pr_bot(_args(tmp_path, repo="")) == 2
    assert cli._cmd_pr_bot(_args(tmp_path, pr=0)) == 2
    assert cli._cmd_pr_bot(_args(tmp_path, finding_ref="")) == 2
