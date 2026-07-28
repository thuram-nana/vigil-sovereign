"""U2 — the Knowledge screen's two new console actions + the feed-status read helper.

Both actions shell the SAME gated OFFENSE-engine CLI a hand-run uses (an argv LIST, no shell):

  * ``run_deep_learn``  → ``python -m framework.v2 knowledge learn --slug S --vuln V``  (K3)
  * ``run_feed_pull``   → ``python -m framework.v2 intel refresh-vulnintel --live --slug S``  (K1)

The invariants under test: kill-switch gated (a tripped switch refuses and spawns NOTHING), fail-closed on a
bad slug / vuln id, and the spawned argv is exactly the gated read-only/leads-only CLI — never a promote /
apply / record flag. Nothing here mints a fact or bumps a prior (deep_learn / vulnfeed already prove that in
their own suites; the action only forwards to them). Subprocess + kill-switch are monkeypatched exactly as
``test_charter_screen`` / ``test_evolve_screen`` do — no real subprocess, no repo writes.
"""

from __future__ import annotations

from framework.v2.common import paths
from framework.v2.console import actions, api


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _clear_killswitch(monkeypatch, tmp_path):
    """Point the kill-switch at a NON-EXISTENT path → CLEAR (not tripped)."""
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")


def _trip_killswitch(monkeypatch, tmp_path, slug):
    from framework.v2.authority.killswitch import KillSwitch
    monkeypatch.setattr(paths, "killswitch_path", lambda s: tmp_path / f"{s}.halt")
    KillSwitch(slug).trip("stop")


def _capture_run(monkeypatch, proc: _Proc):
    """Monkeypatch actions.subprocess.run to record argv and NOT spawn anything."""
    seen = {"argv": None, "called": False}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        seen["called"] = True
        return proc

    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    return seen


def _forbid_run(monkeypatch):
    """Monkeypatch subprocess.run to a sentinel that FAILS the test if it is ever called."""
    seen = {"called": False}

    def boom(argv, **kw):
        seen["called"] = True
        raise AssertionError(f"subprocess.run must not be called: {argv}")

    monkeypatch.setattr(actions.subprocess, "run", boom)
    return seen


# ---- run_deep_learn (K3) ----------------------------------------------------


def test_deep_learn_requires_a_slug():
    assert actions.run_deep_learn("", "CVE-2024-1234")["ok"] is False


def test_deep_learn_requires_a_valid_vuln_id(tmp_path, monkeypatch):
    _clear_killswitch(monkeypatch, tmp_path)
    _forbid_run(monkeypatch)                                   # a bad id never reaches the spawn
    assert actions.run_deep_learn("acme", "")["ok"] is False
    assert actions.run_deep_learn("acme", "  ")["ok"] is False
    assert actions.run_deep_learn("acme", "--all")["ok"] is False          # can't smuggle a flag as an id
    assert actions.run_deep_learn("acme", "a b; rm -rf")["ok"] is False    # no separators / metachars


def test_deep_learn_refused_under_killswitch_spawns_nothing(tmp_path, monkeypatch):
    _trip_killswitch(monkeypatch, tmp_path, "acme")
    seen = _forbid_run(monkeypatch)
    out = actions.run_deep_learn("acme", "CVE-2024-1234")
    assert out["ok"] is False and "kill-switch" in out.get("refused", "")
    assert seen["called"] is False                            # nothing drafted, nothing spawned under STOP


def test_deep_learn_shells_the_gated_learn_cli(tmp_path, monkeypatch):
    _clear_killswitch(monkeypatch, tmp_path)
    stdout = ('{"slug": "acme", "learned": [{"id": "CVE-2024-1234", "detect_mapped": true, '
              '"oracle_kinds": ["sqli_error"]}], "drafted_oracle_proposals": [], '
              '"doctrine": "Advisory skills/leads only."}')
    seen = _capture_run(monkeypatch, _Proc(returncode=0, stdout=stdout))
    out = actions.run_deep_learn("acme", "CVE-2024-1234")
    assert out["ok"] is True and out["vuln_id"] == "CVE-2024-1234"
    argv = seen["argv"]
    # the gated OFFENSE-engine CLI, argv LIST (no shell), single-lead learn — never --all / a promote / apply / record
    assert argv[:5] == [actions.sys.executable, "-m", "framework.v2", "knowledge", "learn"]
    assert argv[argv.index("--slug") + 1] == "acme"
    assert argv[argv.index("--vuln") + 1] == "CVE-2024-1234"
    for banned in ("--all", "--promote", "--apply", "--record", "--skills-dir"):
        assert banned not in argv
    assert out["learned"] and out["learned"][0]["id"] == "CVE-2024-1234"


def test_deep_learn_sanitizes_the_slug(tmp_path, monkeypatch):
    _clear_killswitch(monkeypatch, tmp_path)
    seen = _capture_run(monkeypatch, _Proc(returncode=0, stdout='{"learned": []}'))
    actions.run_deep_learn("ac/me; --scope 0.0.0.0", "CVE-2024-1234")
    argv = seen["argv"]
    slug_val = argv[argv.index("--slug") + 1]
    # sanitized to ONE safe token: no separators / metachars, and it can never begin with '-' (a flag).
    assert "/" not in slug_val and ";" not in slug_val and " " not in slug_val
    assert not slug_val.startswith("-")
    # the smuggled "--scope 0.0.0.0" is glued into the single slug token — never its own argv element.
    assert "--scope" not in argv and "0.0.0.0" not in argv


def test_deep_learn_surfaces_a_missing_lead(tmp_path, monkeypatch):
    _clear_killswitch(monkeypatch, tmp_path)
    _capture_run(monkeypatch, _Proc(returncode=2, stderr="error: no vulnerability lead 'CVE-9' for 'acme'"))
    out = actions.run_deep_learn("acme", "CVE-9")
    assert out["ok"] is False and "no vulnerability lead" in out["error"]


# ---- run_feed_pull (K1) -----------------------------------------------------


def test_feed_pull_requires_a_slug():
    assert actions.run_feed_pull("")["ok"] is False


def test_feed_pull_refused_under_killswitch_spawns_nothing(tmp_path, monkeypatch):
    _trip_killswitch(monkeypatch, tmp_path, "acme")
    seen = _forbid_run(monkeypatch)
    out = actions.run_feed_pull("acme")
    assert out["ok"] is False and "kill-switch" in out.get("refused", "")
    assert seen["called"] is False                            # no egress under STOP


def test_feed_pull_shells_gated_refresh_live(tmp_path, monkeypatch):
    _clear_killswitch(monkeypatch, tmp_path)
    stdout = ('{"live": true, "slug": "acme", "sources": ["nvd", "osv", "cisa-kev"], '
              '"minted_by_source": {"cisa-kev": 3}, "applied": 3, "queries_run": 1, '
              '"cancelled": false, "refused": 0, "doctrine": "…LEAD…"}')
    seen = _capture_run(monkeypatch, _Proc(returncode=0, stdout=stdout))
    out = actions.run_feed_pull("acme")
    assert out["ok"] is True and out["live"] is True and out["applied"] == 3
    assert out["minted_by_source"] == {"cisa-kev": 3} and out["hosts_refused"] == 0
    argv = seen["argv"]
    assert argv[:5] == [actions.sys.executable, "-m", "framework.v2", "intel", "refresh-vulnintel"]
    assert "--live" in argv and argv[argv.index("--slug") + 1] == "acme"
    # a one-shot pull, never the recurring sidecar (feed-daemon), never a target
    assert "feed-daemon" not in argv


def test_feed_pull_surfaces_cli_killswitch_refusal(tmp_path, monkeypatch):
    _clear_killswitch(monkeypatch, tmp_path)                  # clear at the pre-check…
    _capture_run(monkeypatch, _Proc(returncode=3, stderr="refused: kill-switch tripped"))
    out = actions.run_feed_pull("acme")                        # …but the CLI trips between fetches (exit 3)
    assert out["ok"] is False and "kill-switch" in out.get("refused", "")


# ---- feed_status read helper ------------------------------------------------


def test_feed_status_is_honest_about_the_schedule():
    d = api.feed_status()
    assert d["egress_default"] == "offline"
    assert d["recurring"]["managed_here"] is False            # recurring auto-pull is a sidecar, not here
    # HONEST: no fabricated live schedule state is surfaced
    assert "next_run" not in d["recurring"] and "last_run" not in d["recurring"]
    assert isinstance(d["sources"], list)
    assert "LEAD" in d["doctrine"]
