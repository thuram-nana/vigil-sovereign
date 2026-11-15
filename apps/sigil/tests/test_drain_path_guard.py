"""Red-pen fold (readiness slice 2a): a supervised drain must REFUSE a spool / base-dir that still carries an
un-expanded systemd ``%h`` specifier (or is relative / empty). systemd does NOT expand ``%h`` inside an
EnvironmentFile value, so a shipped ``%h/...`` default reaches the drain as the LITERAL string; without this
guard the findings drain reads the wrong empty directory and the MONEY settle drain finds no lease and archives
every completion unsettled — both reporting success so the staleness dead-man stays HEALTHY (a silent
non-delivery / permanent money loss). The guard makes that misconfig fail LOUD (exit 2 → FAILED heartbeat →
dead-man alarm) BEFORE any spool is claimed/archived."""
import types

import pytest

from sigil.cli import _require_expanded_path, cmd_inbound, cmd_settle_drain


def test_helper_accepts_absolute(tmp_path):
    # an absolute, already-expanded path is fine; an empty OPTIONAL path falls through to the caller default
    _require_expanded_path(str(tmp_path), "--spool", required=True)
    _require_expanded_path("", "--base-dir", required=False)


@pytest.mark.parametrize("bad", [
    "%h/.sigil/spool/findings",   # the exact shipped misconfig (un-expanded home specifier)
    "%S/vigil/x",                 # any systemd specifier
    "./incoming",                 # relative
    "rel/ative/spool",            # relative
    "incoming",                   # bare relative
])
def test_helper_rejects_unexpanded_or_relative(bad):
    with pytest.raises(SystemExit) as ei:
        _require_expanded_path(bad, "--spool", required=True)
    assert ei.value.code == 2


def test_helper_rejects_empty_when_required():
    with pytest.raises(SystemExit) as ei:
        _require_expanded_path("", "--spool", required=True)
    assert ei.value.code == 2


def test_cmd_inbound_refuses_percent_h_spool(capsys):
    """The findings drain refuses a literal-%h spool before it can silently drain the wrong directory. The
    message assertion isolates THIS guard from the (also exit-2) owner-identity check that follows it, so the
    test reddens if the guard call is removed from cmd_inbound (not only if the helper breaks)."""
    a = types.SimpleNamespace(spool="%h/.sigil/spool/findings", scope="*",
                              governance_delegation="", spine_delegation="",
                              inbound_cmd="drain", interval=2.0)
    with pytest.raises(SystemExit) as ei:
        cmd_inbound(a)
    assert ei.value.code == 2
    assert "--spool must be an ABSOLUTE" in capsys.readouterr().err


def test_cmd_settle_drain_refuses_percent_h_base_dir(tmp_path, capsys):
    """The MONEY drain refuses a literal-%h --base-dir (the runbook-compliant permanent-loss misconfig: spool
    set absolute, base-dir left at its %h default) before it can archive a completion unsettled."""
    a = types.SimpleNamespace(spool=str(tmp_path), base_dir="%h/.sigil/credit-lease",
                              delegation="", scope="*", settle_cmd="drain", interval=2.0)
    with pytest.raises(SystemExit) as ei:
        cmd_settle_drain(a)
    assert ei.value.code == 2
    assert "--base-dir must be an ABSOLUTE" in capsys.readouterr().err


def test_cmd_settle_drain_refuses_percent_h_spool(tmp_path, capsys):
    a = types.SimpleNamespace(spool="%h/.sigil/spool/settle", base_dir=str(tmp_path),
                              delegation="", scope="*", settle_cmd="drain", interval=2.0)
    with pytest.raises(SystemExit) as ei:
        cmd_settle_drain(a)
    assert ei.value.code == 2
    assert "--spool must be an ABSOLUTE" in capsys.readouterr().err


def test_cmd_billing_drain_refuses_percent_h_spool(capsys, monkeypatch):
    """Front B: the money-IN drain (now run by vigil-billing-drain.service from an env value) refuses a literal-%h
    spool before it can drain NOTHING while exiting 0 (a paid customer never credited, the dead-man reading it
    healthy). The message assertion isolates THIS guard from the (also exit-2) secret / verifier checks after it."""
    from sigil.cli import cmd_billing_drain
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "dummy-test-secret")
    a = types.SimpleNamespace(spool="%h/.sigil/spool/billing", billing_cmd="drain", interval=2.0)
    with pytest.raises(SystemExit) as ei:
        cmd_billing_drain(a)
    assert ei.value.code == 2
    assert "--spool must be an ABSOLUTE" in capsys.readouterr().err


# --- E3a: the settle drain derives its seam from the ONE resolver and REFUSES contradictory settings -----------
# Each asserts the seam-base message, isolating THIS guard from the (also exit-2) owner/delegation checks after it.

def _settle_args(tmp_path, base_dir=""):
    return types.SimpleNamespace(spool=str(tmp_path / "spool"), base_dir=base_dir,
                                 delegation=str(tmp_path / "absent-delegation.json"), scope="*",
                                 settle_cmd="drain", interval=2.0)


def test_cmd_settle_drain_refuses_a_legacy_settle_base_naming_another_tree(tmp_path, capsys, monkeypatch):
    """The pre-E3a drain unit read VIGIL_SETTLE_BASE_DIR (%h/.sigil/credit-lease) while the cockpit published
    under a different tree; a settle-drain.env still carrying it must not silently win or lose — it refuses."""
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    monkeypatch.setenv("VIGIL_SETTLE_BASE_DIR", str(tmp_path / "credit-lease"))
    with pytest.raises(SystemExit) as ei:
        cmd_settle_drain(_settle_args(tmp_path))
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert "contradictory seam base settings" in err and "VIGIL_SETTLE_BASE_DIR" in err


def test_cmd_settle_drain_refuses_base_dir_contradicting_vigil_base_dir(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    monkeypatch.delenv("VIGIL_SETTLE_BASE_DIR", raising=False)
    with pytest.raises(SystemExit) as ei:
        cmd_settle_drain(_settle_args(tmp_path, base_dir=str(tmp_path / "other")))
    assert ei.value.code == 2
    assert "contradictory seam base settings" in capsys.readouterr().err


def test_cmd_settle_drain_refuses_a_percent_h_vigil_base_dir(tmp_path, capsys, monkeypatch):
    """The seam now comes from VIGIL_BASE_DIR, so the literal-%h guard must cover the ENV source too (an env file
    value is never expanded): a literal %h seam would read an empty tree and archive completions unsettled."""
    monkeypatch.setenv("VIGIL_BASE_DIR", "%h/.sigil/credit-lease")
    monkeypatch.delenv("VIGIL_SETTLE_BASE_DIR", raising=False)
    with pytest.raises(SystemExit) as ei:
        cmd_settle_drain(_settle_args(tmp_path))
    assert ei.value.code == 2
    assert "unexpanded systemd specifier" in capsys.readouterr().err


def test_cmd_settle_drain_accepts_an_agreeing_legacy_settle_base(tmp_path, capsys, monkeypatch):
    """A legacy VIGIL_SETTLE_BASE_DIR naming the SAME directory is reconciled, not refused: the drain proceeds
    past the seam check (and then stops at the absent delegation / owner identity, never the seam)."""
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    monkeypatch.setenv("VIGIL_SETTLE_BASE_DIR", str(tmp_path / "seam") + "/")
    with pytest.raises(SystemExit):
        cmd_settle_drain(_settle_args(tmp_path))
    assert "seam base" not in capsys.readouterr().err
