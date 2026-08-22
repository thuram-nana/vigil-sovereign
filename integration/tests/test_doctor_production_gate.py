"""W9-4b — the opt-in refuse-to-start PRODUCTION posture gate.

When ``VIGIL_POSTURE=production`` (or ``prod``), a start path (``vigil up`` / ``vigil engage``) REFUSES to
run unless ALL SIX production preconditions hold, read from the SAME on-disk / env posture probes
``vigil doctor`` renders (the first five) plus one env read (the sixth):

  1. vault SEALED (secrets sealed at rest, not plaintext)
  2. sovereignty tier non-PERMISSIVE
  3. entitlement enforcement ACTIVE
  4. backup / reprove timers ON
  5. a signed charter + EngagementAuthority PRESENT
  6. the legacy embedded shared owner token DISABLED (SIGIL_LEGACY_OWNER_TOKEN=0 ⇒ per-user PoP auth
     required; W10-7 — the sigil server also refuses that token at runtime under this posture)

These tests prove:

* the gate REFUSES on each of the five conditions INDEPENDENTLY, with a distinct error naming the failing
  control (AC 1);
* the NEGATIVE CONTROL — all five satisfied ⇒ start succeeds, so the gate is not simply always-refusing
  (AC 2, and it proves the six states are actually READ, not a constant);
* the default (VIGIL_POSTURE unset) path is byte-identical — the gate is INERT, the CLI helper returns
  None, and ``collect()`` grows no ``production_gate`` field (AC 3);
* the WIRING at the real start paths: ``_cmd_up`` refuses (returns 2) and never calls ``run_up``, and
  ``_cmd_engage`` refuses before importing the engine — this is the test that FAILS WITHOUT THE CHANGE
  (on a tree with no gate, ``_cmd_up`` would call ``run_up`` and never return 2) (AC 5);
* fail-closed: a control that reports UNKNOWN (unreadable) is UNMET, never treated as satisfied (AC 6).

The whole file is pure-stdlib / integration-plane — it imports neither ``sigil`` nor ``framework`` — so it
runs in the required "integration two-env boundary (P5)" CI job (the sovereign leg).
"""
from __future__ import annotations

import pathlib
from types import SimpleNamespace

import pytest

from vigil_integration import cli as climod
from vigil_integration import doctor as dmod

_CONTROLS = ["vault", "sovereignty", "entitlement", "backups", "charter", "legacy-owner-token"]


# ------------------------------------------------------------------ world builder: all five SATISFIED

def _fake_systemctl(enabled=(), fired=()):
    """Fake `systemctl` covering both probes the backup-timer scan makes: `is-enabled <timer>` and
    `show <service> -p ExecMainExitTimestamp -p ExecMainStatus -p Result`. A non-empty exit timestamp
    (⇒ a completed run) is returned iff the paired timer is in `fired`. `backups` is ON only when the
    durability set is BOTH enabled and fired; passing `enabled=set()` disables everything (⇒ OFF)."""
    enabled, fired = set(enabled), set(fired)

    def _run(argv, capture_output=True, text=True, timeout=None, **kw):
        # doctor invokes systemctl in USER mode; skip the --user token so the same fake
        # matches both the is-enabled and show probes.
        args = [a for a in argv[1:] if a != "--user"]
        verb, unit = args[0], args[1]
        if verb == "is-enabled":
            on = unit in enabled
            return SimpleNamespace(returncode=0 if on else 4,
                                   stdout=("enabled" if on else "disabled") + "\n", stderr="")
        if verb == "show":
            timer = unit[: -len(".service")] + ".timer"
            ts = "Thu 2026-08-21 03:00:11 UTC" if timer in fired else ""
            return SimpleNamespace(returncode=0,
                                   stdout=f"ExecMainExitTimestamp={ts}\nExecMainStatus=0\nResult=success\n",
                                   stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    return _run


def _all_satisfied(monkeypatch, tmp_path) -> pathlib.Path:
    """Provision every one of the five production preconditions on disk / in env and return the repo path
    the gate should be evaluated against. Each helper below flips exactly ONE of these back off."""
    repo = tmp_path
    # (1) vault SEALED — the TPM-sealed KEK blobs under SIGIL_HOME/vault
    home = tmp_path / ".sigil"
    (home / "vault").mkdir(parents=True)
    (home / "vault" / dmod._VAULT_SEAL_PUB).write_bytes(b"pub")
    (home / "vault" / dmod._VAULT_SEAL_PRIV).write_bytes(b"priv")
    monkeypatch.setenv("SIGIL_HOME", str(home))
    # (2) sovereignty non-PERMISSIVE
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    # (3) entitlement ACTIVE (the enforce-env is the simplest ACTIVE state)
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
    # (4) backups ON — the durability set (a backup timer + the recovery drill) must be ENABLED *and* have a
    #     SUCCESSFUL last run (W7-8). Lay down the canonical units and report both enabled + fired.
    sysd = repo / "infra" / "systemd"
    sysd.mkdir(parents=True)
    for t in ("vigil-backup.timer", "vigil-backup-push.timer", "vigil-backup-drill.timer"):
        (sysd / t).write_text("[Timer]\n", encoding="utf-8")
    monkeypatch.setattr(dmod.shutil, "which",
                        lambda n: "/usr/bin/systemctl" if n == "systemctl" else None)
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    # (5) charter PRESENT — a crucible root with a charter + a signed EngagementAuthority, pinned by
    #     VIGIL_ENGAGEMENT so the probe is deterministic
    cruc = tmp_path / "cruc"
    (cruc / "targets" / "acme").mkdir(parents=True)
    (cruc / "CLAUDE.md").write_text("# crucible\n", encoding="utf-8")
    (cruc / "targets" / "acme" / "charter.md").write_text("# charter\n", encoding="utf-8")
    auth = cruc / "framework" / "v2" / ".authority"
    auth.mkdir(parents=True)
    (auth / "acme.authority.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CRUCIBLE_ROOT", str(cruc))
    monkeypatch.setenv("VIGIL_ENGAGEMENT", "acme")
    # (6) the legacy embedded shared owner token DISABLED — the operator opted into per-user PoP auth
    monkeypatch.setenv("SIGIL_LEGACY_OWNER_TOKEN", "0")
    return repo


# ------------------------------------------------------------------ AC 3 — inert when posture unset

def test_gate_inert_when_posture_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    # a WORST-CASE world (nothing provisioned): even so the gate must not block when posture is unset.
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "empty"))
    res = dmod.evaluate_production_gate(tmp_path)
    assert res["armed"] is False
    assert res["ok"] is True
    assert res["unmet"] == []
    # and the CLI start-path helper is a no-op (returns None ⇒ the caller proceeds unchanged).
    assert climod._enforce_production_gate("up") is None


def test_posture_selector_matches_production_and_prod_case_insensitively(monkeypatch):
    for val, hit in (("production", True), ("prod", True), ("Prod", True), ("PRODUCTION", True),
                     ("", False), ("dev", False), ("staging", False)):
        if val:
            monkeypatch.setenv("VIGIL_POSTURE", val)
        else:
            monkeypatch.delenv("VIGIL_POSTURE", raising=False)
        assert (dmod.production_posture() is not None) is hit, val


# ------------------------------------------------------------------ AC 2 — negative control: all five ⇒ pass

def test_gate_passes_when_all_satisfied(monkeypatch, tmp_path):
    repo = _all_satisfied(monkeypatch, tmp_path)
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    res = dmod.evaluate_production_gate(repo)
    assert res["armed"] is True
    assert res["ok"] is True, [f"{e['control']}={e['state']}" for e in res["unmet"]]
    assert res["unmet"] == []
    # every control is individually met, and the states are the real engaged states (not a constant).
    states = {c["control"]: c["state"] for c in res["controls"]}
    assert states == {"vault": "SEALED", "sovereignty": "AIR_GAPPED", "entitlement": "ACTIVE",
                      "backups": "ON", "charter": "PRESENT", "legacy-owner-token": "DISABLED"}
    assert all(c["met"] for c in res["controls"])


# ------------------------------------------------------------------ AC 1 — refuses on each condition alone

_BREAKERS = {
    # control -> a callable that flips JUST that one precondition OFF (leaving the other four satisfied)
    "vault": lambda mp, tp: mp.setenv("SIGIL_HOME", str(_unprovisioned_home(tp))),
    "sovereignty": lambda mp, tp: mp.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "PERMISSIVE"),
    "entitlement": lambda mp, tp: (mp.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False),
                                   mp.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(_empty_dir(tp)))),
    "backups": lambda mp, tp: mp.setattr(dmod.subprocess, "run", _fake_systemctl(set())),
    "charter": lambda mp, tp: mp.setenv("VIGIL_ENGAGEMENT", "no-such-engagement"),
    # unset the opt-out ⇒ the legacy shared owner token is ENABLED again (its fail-open default)
    "legacy-owner-token": lambda mp, tp: mp.delenv("SIGIL_LEGACY_OWNER_TOKEN", raising=False),
}


def _unprovisioned_home(tp) -> pathlib.Path:
    h = tp / "plain-home"
    h.mkdir()
    (h / "sigil.env").write_text("ANTHROPIC_API_KEY=x\n", encoding="utf-8")  # ⇒ UNPROVISIONED, plaintext
    return h


def _empty_dir(tp) -> pathlib.Path:
    d = tp / "no-trust-root"
    d.mkdir()
    return d


@pytest.mark.parametrize("broken", _CONTROLS)
def test_gate_refuses_each_condition_independently(monkeypatch, tmp_path, broken):
    repo = _all_satisfied(monkeypatch, tmp_path)
    _BREAKERS[broken](monkeypatch, tmp_path)               # flip exactly ONE precondition off
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    res = dmod.evaluate_production_gate(repo)
    assert res["ok"] is False, f"breaking {broken!r} did not refuse"
    unmet_controls = [e["control"] for e in res["unmet"]]
    # EXACTLY the broken control is unmet — the other four still pass (proves the five are independent).
    assert unmet_controls == [broken], unmet_controls
    # the operator refusal names the failing control distinctly.
    msg = dmod.production_gate_message(res, action="up")
    assert "REFUSED" in msg and f"{broken}:" in msg
    # the other four controls are NOT named as failures.
    for other in _CONTROLS:
        if other != broken:
            assert f"\n  ✗ {other}:" not in msg, f"{other} wrongly reported unmet when {broken} was broken"


# ------------------------------------------------------------------ AC 6 — fail-closed on UNKNOWN

def test_gate_fails_closed_when_a_control_is_unknown(monkeypatch, tmp_path):
    repo = _all_satisfied(monkeypatch, tmp_path)
    monkeypatch.setenv("VIGIL_POSTURE", "production")

    def _boom():
        raise RuntimeError("simulated unreadable control")
    monkeypatch.setattr(dmod, "_posture_vault", _boom)     # the probe now raises ⇒ UNKNOWN

    res = dmod.evaluate_production_gate(repo)
    assert res["ok"] is False
    vault = next(c for c in res["controls"] if c["control"] == "vault")
    assert vault["state"] == "UNKNOWN" and vault["met"] is False   # UNKNOWN is UNMET (never satisfied)
    assert [e["control"] for e in res["unmet"]] == ["vault"]


# ------------------------------------------------------------------ AC 5 — WIRING: `vigil up`

def _up_args(**over) -> SimpleNamespace:
    base = dict(services=False, host="127.0.0.1", port=8770, domain="", base_dir=".vigil-live",
                no_browser=True)
    base.update(over)
    return SimpleNamespace(**base)


def test_cmd_up_refuses_in_production_and_never_calls_run_up(monkeypatch, tmp_path):
    # production posture + an unprovisioned world ⇒ `vigil up` MUST refuse (return 2) BEFORE touching run_up.
    # THIS IS THE TEST THAT FAILS WITHOUT THE CHANGE: a tree with no gate falls straight through to run_up
    # (the sentinel fires, the return value is not 2).
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "empty"))
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)

    called = {"run_up": False}

    def _sentinel_run_up(**kw):
        called["run_up"] = True
        return 0
    monkeypatch.setattr("vigil_integration.uiproxy.run_up", _sentinel_run_up)

    rc = climod._cmd_up(_up_args())
    assert rc == 2, "vigil up did not refuse in production posture with unmet preconditions"
    assert called["run_up"] is False, "vigil up called run_up despite refusing — the gate ran too late"


def test_cmd_up_proceeds_when_posture_unset(monkeypatch, tmp_path):
    # NEGATIVE CONTROL for the wiring: with posture unset the gate is inert, so `vigil up` proceeds to
    # run_up exactly as before (byte-identical default) and returns whatever run_up returns.
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "empty"))

    called = {"run_up": False}

    def _sentinel_run_up(**kw):
        called["run_up"] = True
        return 7
    monkeypatch.setattr("vigil_integration.uiproxy.run_up", _sentinel_run_up)

    rc = climod._cmd_up(_up_args())
    assert called["run_up"] is True and rc == 7


# ------------------------------------------------------------------ AC 5 — WIRING: `vigil engage`

def test_cmd_engage_refuses_in_production_before_importing_the_engine(monkeypatch, tmp_path):
    # the gate is the FIRST statement in `_cmd_engage`, before the `.live.wiring` import, so a refused
    # production engage never loads the engine or sends traffic. A bare args namespace is enough — nothing
    # past the gate is reached.
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "empty"))
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)

    rc = climod._cmd_engage(SimpleNamespace())
    assert rc == 2


# ------------------------------------------------------------------ AC 3 — doctor report: gate only when armed

def _doctor_ready_world(tmp_path, monkeypatch):
    """A minimal world where collect()'s hard prerequisites pass (both venvs, writable dirs, resolvable
    vigil) so `ok` is driven only by the gate, not by unrelated missing prereqs."""
    for v in (".venv-offense", ".venv-sovereign"):
        b = tmp_path / v / "bin"
        b.mkdir(parents=True)
        (b / ("vigil" if v.endswith("offense") else "sigil")).write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(dmod, "_writable", lambda p: True)
    monkeypatch.setenv("VIGIL_BIN", str(tmp_path / ".venv-offense" / "bin" / "vigil"))
    monkeypatch.delenv("CRUCIBLE_LLM_BACKEND", raising=False)


def test_collect_has_no_production_gate_field_when_posture_unset(monkeypatch, tmp_path):
    _doctor_ready_world(tmp_path, monkeypatch)
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    report = dmod.collect(tmp_path)
    assert "production_gate" not in report                  # byte-identical: no new field when inert
    assert report["ok"] is True and report["issues"] == []


def test_collect_flips_ok_and_names_controls_when_armed_and_unmet(monkeypatch, tmp_path):
    _doctor_ready_world(tmp_path, monkeypatch)
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "empty"))   # UNPROVISIONED ⇒ at least vault unmet
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    report = dmod.collect(tmp_path)
    assert "production_gate" in report and report["production_gate"]["armed"] is True
    assert report["ok"] is False                            # the gate flipped the exit code
    assert any("PRODUCTION posture" in m for m in report["issues"])
    # render carries the dedicated gate section AND the failure lands in "Action needed".
    text = dmod.render(report)
    assert "PRODUCTION posture gate" in text and "REFUSES to start" in text
    assert "Action needed" in text


# ------------------------------------------------------------------ AC 8 — README documents the gate truthfully

_REPO = pathlib.Path(dmod.__file__).resolve().parents[2]


def test_readme_documents_the_production_gate_env_and_controls():
    text = (_REPO / "README.md").read_text(encoding="utf-8")
    assert "VIGIL_POSTURE=production" in text, "README does not name the production-posture env selector"
    # the refuse-to-start behaviour + each of the five controls is described.
    assert "refuse" in text.lower()
    for control in _CONTROLS:
        assert control in text, f"README does not mention the {control!r} production precondition"



# ------------------------------------------------------------------ W10-7 — the legacy-owner-token precondition

def test_gate_refuses_when_legacy_shared_owner_token_is_enabled(monkeypatch, tmp_path):
    """The W10-7 precondition, exercised on its own: with every OTHER control satisfied but the legacy
    embedded shared owner token left at its fail-open default (SIGIL_LEGACY_OWNER_TOKEN unset), the
    production gate REFUSES and names exactly `legacy-owner-token`. THIS FAILS WITHOUT THE CHANGE — on a
    tree where the gate has only the original five controls, an all-else-satisfied world passes."""
    repo = _all_satisfied(monkeypatch, tmp_path)
    monkeypatch.delenv("SIGIL_LEGACY_OWNER_TOKEN", raising=False)   # fail-open default: the token is ENABLED
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    res = dmod.evaluate_production_gate(repo)
    assert res["ok"] is False
    assert [e["control"] for e in res["unmet"]] == ["legacy-owner-token"]
    tok = next(c for c in res["controls"] if c["control"] == "legacy-owner-token")
    assert tok["state"] == "ENABLED" and tok["met"] is False
    msg = dmod.production_gate_message(res, action="up")
    assert "legacy-owner-token: ENABLED" in msg and "SIGIL_LEGACY_OWNER_TOKEN=0" in msg


def test_gate_accepts_the_disabled_legacy_token_and_ignores_it_out_of_production(monkeypatch, tmp_path):
    """NEGATIVE CONTROL for W10-7: disabling the token (SIGIL_LEGACY_OWNER_TOKEN=0) satisfies the control —
    so the gate is not a no-op that always refuses — and OUTSIDE production the whole gate is inert
    regardless of the token, so nothing already deployed is forced to change."""
    repo = _all_satisfied(monkeypatch, tmp_path)              # already sets SIGIL_LEGACY_OWNER_TOKEN=0
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    res = dmod.evaluate_production_gate(repo)
    tok = next(c for c in res["controls"] if c["control"] == "legacy-owner-token")
    assert tok["state"] == "DISABLED" and tok["met"] is True and res["ok"] is True
    # out of production the gate is inert even with the token ENABLED (default): no forced change.
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.delenv("SIGIL_LEGACY_OWNER_TOKEN", raising=False)
    res2 = dmod.evaluate_production_gate(repo)
    assert res2["armed"] is False and res2["ok"] is True and res2["unmet"] == []
