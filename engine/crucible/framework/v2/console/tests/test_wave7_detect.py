"""Wave 7 (parity) — the console identity/detect wrappers. `identity` exports the offense PUBLIC keys (read).
`detect` runs the log-plane Detection Mirror over operator-provided HOST log paths (OWNER-gated at the route);
each path must be an existing regular FILE (fail-closed on a dir/device/missing). shell=False; paths are argv
elements. Verb correctness is the CLI suite's; this checks the wrappers + the path gate."""
from __future__ import annotations

import subprocess

from framework.v2.console import actions


class _P:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


# --- identity (public-key read) --------------------------------------------------

def test_identity_shells_and_failcloses(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    assert actions.run_identity()["ok"] is False
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    seen = {}

    def _rec(a, **k):
        seen["argv"] = a
        return _P(0, "spine_pubkey: AAAA...\ngovernance_pubkey: BBBB...")
    monkeypatch.setattr(subprocess, "run", _rec)
    r = actions.run_identity()
    assert r["ok"] is True and seen["argv"][1:] == ["identity"] and "pubkey" in r["text"]


# --- detect (log-plane Detection Mirror) -----------------------------------------

def test_detect_requires_at_least_one_log():
    assert actions.run_detect("", "", "")["ok"] is False


def test_detect_rejects_a_non_regular_file(monkeypatch, tmp_path):
    import os
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    # a dir / missing / FIFO / a device node are all NOT regular files → fail-closed BEFORE any spawn (so a
    # UI slip can never point a detection oracle at a device/fifo). NOTE: these tests deliberately do NOT mock
    # subprocess — they rely on the isfile gate short-circuiting before /usr/bin/true (which would rc0 → ok).
    assert actions.run_detect(str(tmp_path), "", "")["ok"] is False               # a dir
    assert actions.run_detect(str(tmp_path / "nope.log"), "", "")["ok"] is False  # missing
    fifo = tmp_path / "pipe"
    os.mkfifo(str(fifo))
    assert actions.run_detect(str(fifo), "", "")["ok"] is False                   # a FIFO
    if os.path.exists("/dev/zero"):
        assert actions.run_detect("/dev/zero", "", "")["ok"] is False             # a device node


def test_detect_shells_only_the_given_regular_files(monkeypatch, tmp_path):
    acc = tmp_path / "access.log"; acc.write_text("127.0.0.1 - - [..] GET / 200\n")
    auth = tmp_path / "auth.log"; auth.write_text("Failed password for root\n")
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    seen = {}

    def _rec(a, **k):
        seen["argv"] = a
        return _P(0, "detection: 1 finding (auth: credential-stuffing)")
    monkeypatch.setattr(subprocess, "run", _rec)
    r = actions.run_detect(str(acc), str(auth), "")            # conn omitted
    assert r["ok"] is True
    assert seen["argv"][1] == "detect"
    assert "--access-log" in seen["argv"] and str(acc) in seen["argv"]
    assert "--auth-log" in seen["argv"] and str(auth) in seen["argv"]
    assert "--conn-log" not in seen["argv"]                    # not provided → not in argv


def test_detect_paths_are_argv_elements_not_shell(monkeypatch, tmp_path):
    # a path containing shell metacharacters is still ONE argv element (shell=False) — no injection
    weird = tmp_path / "a;rm -rf.log"; weird.write_text("x\n")
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    seen = {}
    monkeypatch.setattr(subprocess, "run", lambda a, **k: seen.setdefault("argv", a) is None or _P(0, "ok"))
    actions.run_detect(str(weird), "", "")
    assert str(weird) in seen["argv"]                          # the whole path, one element


# --- tier pin (mutation-sensitive) -----------------------------------------------

def test_wave7_route_tiers():
    from vigil_core.rbac import offense_perm_for
    assert offense_perm_for("/api/identity") == "read"                   # public keys → any principal
    assert offense_perm_for("/api/detect") == "offense_authority"        # arbitrary host log read → owner
