"""Wave 9 (parity, SENSITIVE) — m-of-n Shamir ESCROW of the backup passphrase. The load-bearing invariants:
the passphrase reaches the child via ENV (VIGIL_BACKUP_PASSPHRASE) — NEVER argv, NEVER the response; the
SECRET shares stay on the host (only names/metadata surface); threshold/shares/holders are validated; the
route is owner-only. Verb correctness is the CLI suite's; this hammers the security surface."""
from __future__ import annotations

import subprocess

from framework.v2.console import actions

PW = "correcthorsebatterystaple"


class _P:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def test_passphrase_goes_via_env_never_argv_never_response(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    seen = {}

    def _rec(argv, **kw):
        seen["argv"] = argv
        seen["env"] = kw.get("env") or {}
        return _P(0, "=== escrow ===\nPUBLIC metadata: /host/meta.json\nSECRET shares (0600): ...")
    monkeypatch.setattr(subprocess, "run", _rec)
    r = actions.run_escrow_passphrase(PW, 2, 3, [])
    # (1) the passphrase is NEVER on argv
    assert PW not in seen["argv"] and not any(PW in str(a) for a in seen["argv"])
    # (2) it IS in the child's env under the documented var
    assert seen["env"].get("VIGIL_BACKUP_PASSPHRASE") == PW
    # (3) argv is the fixed escrow shape (threshold/shares/out-dir), no passphrase flag
    assert seen["argv"][1:6] == ["escrow-passphrase", "--threshold", "2", "--shares", "3"]
    # (4) the passphrase is NEVER echoed back in the response
    import json
    assert PW not in json.dumps(r)


def test_holders_are_validated_and_on_argv_only_as_safe_names(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    seen = {}
    monkeypatch.setattr(subprocess, "run", lambda a, **k: seen.setdefault("argv", a) is None or _P(0, "ok"))
    # exactly n safe holder names → each after a --holder flag
    actions.run_escrow_passphrase(PW, 2, 3, ["alice", "bob", "carol"])
    assert seen["argv"].count("--holder") == 3 and "alice" in seen["argv"]
    # wrong count / unsafe name → rejected before spawn
    assert actions.run_escrow_passphrase(PW, 2, 3, ["only-one"])["ok"] is False
    assert actions.run_escrow_passphrase(PW, 2, 3, ["a", "b", "--inject"])["ok"] is False
    # a non-list holders (int, or a bare string that would silently split into per-char names) → clean
    # reject, never a 500 or a per-character holder set (fail-closed on the owner route)
    assert actions.run_escrow_passphrase(PW, 2, 3, 123)["ok"] is False
    assert actions.run_escrow_passphrase(PW, 2, 3, "alice")["ok"] is False


def test_threshold_and_passphrase_bounds():
    assert actions.run_escrow_passphrase("short", 2, 3, [])["ok"] is False        # passphrase < 8
    assert actions.run_escrow_passphrase(PW, 1, 3, [])["ok"] is False             # threshold < 2
    assert actions.run_escrow_passphrase(PW, 4, 3, [])["ok"] is False             # threshold > shares
    assert actions.run_escrow_passphrase(PW, 2, 99, [])["ok"] is False            # shares > 20
    assert actions.run_escrow_passphrase(PW, "x", 3, [])["ok"] is False           # non-int


def test_failcloses_missing_bin(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    assert actions.run_escrow_passphrase(PW, 2, 3, [])["ok"] is False


def test_route_is_owner_only():
    from vigil_core.rbac import offense_perm_for
    assert offense_perm_for("/api/escrow") == "offense_authority"                 # owner-only
