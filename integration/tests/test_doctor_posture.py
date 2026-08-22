"""W9-4a — `vigil doctor` security-posture block.

`doctor` now emits one honest line PER security control (egress-gate, vault, sovereignty, entitlement,
backups, charter) showing its CURRENT state, read from REAL on-disk / env state — never an optimistic
default. These tests drive the probes with controlled states and assert each posture line reflects the
truth, prove the block is INFORMATIONAL (never changes the exit code), prove a missing/unreadable control
reports UNKNOWN (never crashes), and hold the FATAL-2 boundary: `doctor` imports neither `sigil` nor the
`framework` to read the sovereign-plane vault / framework entitlement. A README-truth test derives the
posture labels from doctor and asserts the pasted README block cannot drift from them.

Each state assertion carries its own NEGATIVE CONTROL — flip the one control's state and its line flips —
so the probe is proven to actually READ the state, not print a constant.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
from types import SimpleNamespace

import pytest

from vigil_integration import doctor as dmod

_REPO = pathlib.Path(dmod.__file__).resolve().parents[2]


# --------------------------------------------------------------------------- sovereignty

def test_sovereignty_permissive_default_flips_to_air_gapped(monkeypatch):
    for k in ("CRUCIBLE_SOVEREIGNTY_TIER", "CRUCIBLE_SOVEREIGN_MODE"):
        monkeypatch.delenv(k, raising=False)
    state, _ = dmod._posture_sovereignty()
    assert state == "PERMISSIVE"                              # dev default
    # NEGATIVE CONTROL: raise the rung → the line flips (not a constant).
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    flipped, detail = dmod._posture_sovereignty()
    assert flipped == "AIR_GAPPED" and "gated by this tier" in detail
    assert flipped != state


# --------------------------------------------------------------------------- entitlement

def test_entitlement_ungoverned_until_trust_root_provisioned(monkeypatch, tmp_path):
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    ent = tmp_path / ".entitlement"
    ent.mkdir()
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(ent))
    state, detail = dmod._posture_entitlement(_REPO)
    assert state == "UNGOVERNED" and "no trust root" in detail

    # NEGATIVE CONTROL: provision a trust root → ACTIVE.
    (ent / "trust-root.json").write_text("{}", encoding="utf-8")
    state2, _ = dmod._posture_entitlement(_REPO)
    assert state2 == "ACTIVE" and state2 != state

    # the enforce-env override alone also makes it ACTIVE (fail-closed intent), even with no trust root.
    ent2 = tmp_path / "empty"
    ent2.mkdir()
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(ent2))
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
    assert dmod._posture_entitlement(_REPO)[0] == "ACTIVE"


# --------------------------------------------------------------------------- vault (sovereign plane, no import)

def test_vault_unprovisioned_plaintext_until_sealed(monkeypatch, tmp_path):
    home = tmp_path / ".sigil"
    home.mkdir()
    (home / "sigil.env").write_text("ANTHROPIC_API_KEY=x\n", encoding="utf-8")
    monkeypatch.setenv("SIGIL_HOME", str(home))
    state, detail = dmod._posture_vault()
    assert state == "UNPROVISIONED" and "plaintext" in detail

    # NEGATIVE CONTROL: provision the TPM-sealed KEK blobs → SEALED.
    vault = home / "vault"
    vault.mkdir()
    (vault / dmod._VAULT_SEAL_PUB).write_bytes(b"pub")
    (vault / dmod._VAULT_SEAL_PRIV).write_bytes(b"priv")
    state2, detail2 = dmod._posture_vault()
    assert state2 == "SEALED" and "ciphertext" in detail2 and state2 != state


# --------------------------------------------------------------------------- egress gate

def test_egress_off_until_gateway_running_and_sandbox_pinned(monkeypatch):
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)
    # docker/gateway absent entirely
    assert dmod._posture_egress({})[0] == "OFF"
    # gateway present but not running
    assert dmod._posture_egress({"vigil-gateway": {"state": "absent"}})[0] == "OFF"
    # gateway running but the sandbox is NOT pinned onto the gated net → still OFF (honest: not wired)
    off, off_detail = dmod._posture_egress({"vigil-gateway": {"state": "running"}})
    assert off == "OFF" and "not pinned" in off_detail.lower()

    # NEGATIVE CONTROL: running AND pinned → ON.
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "vigil-sandbox-net")
    on, _ = dmod._posture_egress({"vigil-gateway": {"state": "running"}})
    assert on == "ON" and on != off

    # a gateway probe error → UNKNOWN, never a crash.
    assert dmod._posture_egress({"vigil-gateway": {"error": "docker daemon unreachable"}})[0] == "UNKNOWN"


# --------------------------------------------------------------------------- backups / timers

def _fake_systemctl(enabled=(), fired=()):
    """Fake `systemctl` covering both probes the timer scan makes — `is-enabled <timer>` and
    `show <service> -p ExecMainExitTimestamp -p ExecMainStatus -p Result` (a non-empty exit timestamp iff
    the paired timer is in `fired`, the real signal for a oneshot that has completed a run)."""
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


def test_backups_off_pending_on_reflects_enablement_and_last_run(monkeypatch, tmp_path):
    sysd = tmp_path / "infra" / "systemd"
    sysd.mkdir(parents=True)
    for t in ("vigil-backup", "vigil-backup-push", "vigil-backup-drill", "vigil-reprove"):
        (sysd / f"{t}.timer").write_text("[Timer]\n", encoding="utf-8")
    monkeypatch.setattr(dmod.shutil, "which", lambda n: "/usr/bin/systemctl" if n == "systemctl" else None)

    # none enabled → OFF.
    monkeypatch.setattr(dmod.subprocess, "run", _fake_systemctl())
    assert dmod._posture_backups(tmp_path)[0] == "OFF"

    # the durability set enabled but NEVER FIRED → PENDING (enabled is not yet running).
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    assert dmod._posture_backups(tmp_path)[0] == "PENDING"

    # NEGATIVE CONTROL: give them a successful last run → ON, naming the engaged timer.
    monkeypatch.setattr(dmod.subprocess, "run",
                        _fake_systemctl(enabled={"vigil-backup.timer", "vigil-backup-drill.timer"},
                                        fired={"vigil-backup.timer", "vigil-backup-drill.timer"}))
    state, detail = dmod._posture_backups(tmp_path)
    assert state == "ON" and "vigil-backup.timer" in detail


def test_backups_unknown_when_systemctl_absent(monkeypatch, tmp_path):
    sysd = tmp_path / "infra" / "systemd"
    sysd.mkdir(parents=True)
    (sysd / "vigil-backup.timer").write_text("[Timer]\n", encoding="utf-8")
    monkeypatch.setattr(dmod.shutil, "which", lambda n: None)
    assert dmod._posture_backups(tmp_path)[0] == "UNKNOWN"


# --------------------------------------------------------------------------- charter / EngagementAuthority

def _fresh_crucible(tmp_path):
    cruc = tmp_path / "engine" / "crucible"
    (cruc / "targets").mkdir(parents=True)
    (cruc / "CLAUDE.md").write_text("# crucible\n", encoding="utf-8")
    (cruc / "framework" / "v2").mkdir(parents=True)
    return cruc


def test_charter_absent_until_charter_and_authority_present(monkeypatch, tmp_path):
    cruc = _fresh_crucible(tmp_path)
    monkeypatch.setenv("CRUCIBLE_ROOT", str(cruc))
    monkeypatch.delenv("VIGIL_ENGAGEMENT", raising=False)
    assert dmod._posture_charter(tmp_path)[0] == "ABSENT"

    # a charter but no signed authority → CHARTER-ONLY (an honest middle state, not PRESENT).
    (cruc / "targets" / "acme").mkdir()
    (cruc / "targets" / "acme" / "charter.md").write_text("# charter\n", encoding="utf-8")
    assert dmod._posture_charter(tmp_path)[0] == "CHARTER-ONLY"

    # NEGATIVE CONTROL: add the signed EngagementAuthority → PRESENT.
    auth = cruc / "framework" / "v2" / ".authority"
    auth.mkdir(parents=True)
    (auth / "acme.authority.json").write_text("{}", encoding="utf-8")
    state, detail = dmod._posture_charter(tmp_path)
    assert state == "PRESENT" and "acme" in detail


def test_charter_unknown_when_crucible_root_unlocatable(monkeypatch, tmp_path):
    # a repo with no CLAUDE.md anywhere and no CRUCIBLE_ROOT → UNKNOWN (never a crash, never a guess).
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "does-not-exist"))
    bare = tmp_path / "bare"
    bare.mkdir()
    assert dmod._posture_charter(bare)[0] == "UNKNOWN"


# --------------------------------------------------------------------------- collect() wiring + informational

def test_collect_attaches_posture_without_changing_ok(tmp_path, monkeypatch):
    # both venvs + writable dirs + a resolvable vigil ⇒ ok True; the posture block (full of OFF/UNGOVERNED
    # lines) must NOT flip ok, and must add nothing to issues.
    for v in (".venv-offense", ".venv-sovereign"):
        b = tmp_path / v / "bin"
        b.mkdir(parents=True)
        (b / ("vigil" if v.endswith("offense") else "sigil")).write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(dmod, "_writable", lambda p: True)
    monkeypatch.setenv("VIGIL_BIN", str(tmp_path / ".venv-offense" / "bin" / "vigil"))
    monkeypatch.delenv("CRUCIBLE_LLM_BACKEND", raising=False)

    report = dmod.collect(tmp_path)
    assert report["ok"] is True and report["issues"] == []
    posture = report["posture"]
    assert isinstance(posture, list) and [p["control"] for p in posture] == [
        "egress-gate", "vault", "key-sealing", "sovereignty", "entitlement", "backups", "charter",
    ]
    # every entry is a JSON-safe {control, state, detail}
    assert all(set(p) == {"control", "state", "detail"} for p in posture)
    # the render shows the section, and no OFF/UNGOVERNED line leaked into the hard-failure section.
    text = dmod.render(report)
    assert "Security posture" in text and "does NOT affect the exit code" in text


def test_posture_probe_that_raises_yields_unknown_not_crash(monkeypatch, tmp_path):
    # force one probe to raise → its entry is UNKNOWN, the report still assembles, ok unaffected.
    def _boom():
        raise RuntimeError("simulated probe failure")
    monkeypatch.setattr(dmod, "_posture_vault", _boom)
    posture = dmod._collect_posture(tmp_path, {})
    vault = next(p for p in posture if p["control"] == "vault")
    assert vault["state"] == "UNKNOWN" and "RuntimeError" in vault["detail"]
    assert len(posture) == 7                                  # the other six still produced


# --------------------------------------------------------------------------- FATAL-2 boundary

def test_doctor_reads_posture_without_importing_sigil_or_framework(tmp_path):
    # Run the whole posture assembly in a SUBPROCESS whose sys.path has ONLY integration + gateway (the
    # offense/integration plane), and assert that after importing doctor + running collect(), neither
    # `sigil` nor `framework` nor `strix` was imported. This is the FATAL-2 guarantee for the sovereign-
    # plane vault line + the framework entitlement line: they are read from DISK, not by co-loading a plane.
    probe = (
        "import sys, json, pathlib\n"
        f"sys.path[:0] = [{str(_REPO / 'integration')!r}, {str(_REPO / 'gateway')!r}]\n"
        "from vigil_integration import doctor as d\n"
        f"r = d.collect(pathlib.Path({str(tmp_path)!r}))\n"
        "leaked = sorted(m for m in ('sigil', 'framework', 'strix') if m in sys.modules)\n"
        "assert 'posture' in r, 'posture missing'\n"
        "print(json.dumps({'leaked': leaked, 'controls': [p['control'] for p in r['posture']]}))\n"
    )
    out = subprocess.run(["python3", "-c", probe], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, f"probe failed: {out.stderr}"
    res = __import__("json").loads(out.stdout.strip().splitlines()[-1])
    assert res["leaked"] == [], f"doctor co-loaded a forbidden plane: {res['leaked']}"
    assert res["controls"] == ["egress-gate", "vault", "key-sealing", "sovereignty", "entitlement", "backups", "charter"]


# --------------------------------------------------------------------------- README-truth (derive, don't drift)

_FENCE_LABEL_RE = re.compile(r"^\s*(?:OK|\.\.|\?\?)\s+([a-z][a-z0-9-]*):", re.M)


def _readme_posture_labels() -> list:
    text = (_REPO / "README.md").read_text(encoding="utf-8")
    # the fenced block that carries the posture example
    m = re.search(r"```text\n(Security posture.*?)\n```", text, re.S)
    assert m, "README.md is missing the fenced `vigil doctor` security-posture example"
    return _FENCE_LABEL_RE.findall(m.group(1))


def test_readme_posture_block_matches_doctor_labels():
    # DERIVE the labels from a live doctor run; the README fenced block must carry EXACTLY those controls,
    # in the same order. Adding/removing/renaming a control without updating README (or vice-versa) fails.
    report = dmod.collect(_REPO)
    doctor_labels = [p["control"] for p in report["posture"]]
    readme_labels = _readme_posture_labels()
    assert readme_labels == doctor_labels, (
        f"README posture block drifted from `vigil doctor`.\n  doctor: {doctor_labels}\n  README: {readme_labels}"
    )
