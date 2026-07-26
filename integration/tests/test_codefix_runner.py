"""LAP-1 — the live auto-patch runner (non-destructive core). Proven END-TO-END against a REAL local git
repo: a confirmed finding + a (fake) coder's real unified diff → clone → apply-in-sandbox, with the
destructive PR leg gated OFF. The sovereign invariants (confirmed-FACT-only, edit approval opt-in, PR
never opens) are asserted, and the SOURCE repo is never modified (we operate on a disposable clone).
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

from vigil_integration.live.codefix_runner import CodefixConfig, autopatch_live
from vigil_integration.remediation.triage import TriageFinding

_VULN = 'def q(u):\n    return "SELECT * FROM t WHERE id=" + u\n'
_FIXED = 'def q(u):\n    return "SELECT * FROM t WHERE id=%s", (u,)\n'


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


@pytest.fixture
def repo_and_diff(tmp_path):
    """A real git repo with a vulnerable file, plus a git-generated unified diff that fixes it (guaranteed
    to apply). Returns (repo_path, diff_text)."""
    repo = tmp_path / "app"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "t@t", cwd=repo)
    _git("config", "user.name", "t", cwd=repo)
    (repo / "app.py").write_text(_VULN, encoding="utf-8")
    _git("add", "app.py", cwd=repo)
    _git("commit", "-q", "-m", "init", cwd=repo)
    (repo / "app.py").write_text(_FIXED, encoding="utf-8")           # make the fix
    diff = _git("diff", cwd=repo).stdout                              # capture the exact applicable diff
    _git("checkout", "--", "app.py", cwd=repo)                        # revert — source stays vulnerable
    assert (repo / "app.py").read_text() == _VULN
    return str(repo), diff


class _FakeClient:
    """Stands in for anthropic.Anthropic — messages.create returns a fixed unified diff."""
    def __init__(self, diff):
        self._diff = diff
        self.messages = self

    def create(self, **_kw):
        return {"content": self._diff}


def _fact(repo, ref="sqli-1"):
    return TriageFinding(ref=ref, title="SQL injection", bug_class="sqli", severity="high",
                         target="app.py:2", confirmed=True, evidence_ref="cert:abc123",
                         target_repo=repo)


def _lead(repo):
    return TriageFinding(ref="lead-1", title="maybe", bug_class="xss", severity="low",
                         target="app.py:2", confirmed=False)


def _cfg(repo, tmp_path, **kw):
    return CodefixConfig(target_repo=repo, base_dir=str(tmp_path / "work"), **kw)


def _workdir(base_dir, rid):
    return os.path.join(base_dir, "codefix-" + rid)


def test_end_to_end_applies_fix_in_clone_but_never_opens_pr(repo_and_diff, tmp_path):
    repo, diff = repo_and_diff
    cfg = _cfg(repo, tmp_path, apply_edits=True)
    res = autopatch_live(_fact(repo), config=cfg, client=_FakeClient(diff))
    # the loop reached the PR gate and it DENIED (destructive, no m-of-n authority wired) — no PR opened
    assert res.opened_pr is False
    assert res.status == "pr-denied", res.status
    assert res.patched_paths == ["app.py"]
    # the fix was really applied to the disposable CLONE...
    wd = _workdir(cfg.base_dir, res.remediation_id)
    assert os.path.isfile(os.path.join(wd, "app.py"))
    assert "%s" in open(os.path.join(wd, "app.py"), encoding="utf-8").read()
    # ...and the SOURCE repo is untouched (still vulnerable)
    assert open(os.path.join(repo, "app.py"), encoding="utf-8").read() == _VULN
    # the ladder shows the gated stages
    stages = [(s.stage, s.outcome) for s in res.steps]
    assert ("clone-exec", "ok") in stages and ("build-exec", "ok") in stages
    assert any(s.stage == "pr-gate" and s.outcome == "deny" for s in res.steps)


def test_edits_off_by_default_reject_the_patch(repo_and_diff, tmp_path):
    repo, diff = repo_and_diff
    cfg = _cfg(repo, tmp_path)   # apply_edits defaults False → every edit times out (REJECT)
    res = autopatch_live(_fact(repo), config=cfg, client=_FakeClient(diff))
    assert res.status == "no-edits-approved" and res.opened_pr is False
    assert res.patched_paths == []


def test_a_lead_is_refused(repo_and_diff, tmp_path):
    repo, diff = repo_and_diff
    res = autopatch_live(_lead(repo), config=_cfg(repo, tmp_path, apply_edits=True), client=_FakeClient(diff))
    assert res.status == "refused-not-confirmed" and res.opened_pr is False


def test_no_coder_yields_no_patch(repo_and_diff, tmp_path, monkeypatch):
    repo, _diff = repo_and_diff
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    res = autopatch_live(_fact(repo), config=_cfg(repo, tmp_path, apply_edits=True), client=None)
    assert res.status == "no-patch-proposed" and res.opened_pr is False


def test_remediated_never_true_without_pr(repo_and_diff, tmp_path):
    # 'remediated' is type-enforced (needs opened_pr AND a signed evidence_ref); LAP-1 opens no PR, so it
    # can never be marked remediated — the whole point of the off-by-default destructive leg.
    repo, diff = repo_and_diff
    res = autopatch_live(_fact(repo), config=_cfg(repo, tmp_path, apply_edits=True), client=_FakeClient(diff))
    assert res.remediated is False and not res.evidence_ref


def test_runner_imports_no_offense_or_sovereign_engine():
    # order-independent: a FRESH interpreter imports only the runner, then checks sys.modules — so another
    # test importing framework first can never falsely pass/fail this.
    # Inherit the parent's env/PYTHONPATH (legit deps like vigil_gateway must resolve); we only assert the
    # runner pulls no framework/strix/sigil — a fresh interpreter so test import order can't mask it.
    code = ("import sys; import vigil_integration.live.codefix_runner;"
            "leaked=[m for m in sys.modules if m.split('.')[0] in ('framework','strix','sigil')];"
            "print('LEAK' if leaked else 'CLEAN', leaked)")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("CLEAN"), f"live runner pulled an engine: {r.stdout} {r.stderr}"


def test_unsafe_remediation_id_refuses_workdir_escape(repo_and_diff, tmp_path):
    # HOLD-1: the clone workdir is built from remediation_id; a '../' id must NOT escape base_dir. The
    # shipped autopatch_live never passes one (it derives a slash-free digest), but clone() guards at the sink.
    from vigil_integration.live.codefix_runner import CodefixSession, _safe_workdir

    repo, _diff = repo_and_diff
    base = str(tmp_path / "work")
    assert _safe_workdir(base, "ap-abc123") is not None
    for bad in ["../escape", "..", "a/b", "a\\b", "", ".", "x/../../y", "a\x00b"]:
        assert _safe_workdir(base, bad) is None, bad
    sess = CodefixSession(CodefixConfig(target_repo=repo, base_dir=base))

    class _Req:
        remediation_id = "../../../../tmp/ESCAPE_SHOULD_NOT_HAPPEN"
        target_repo = repo
        fix_branch = "vigil-fix/x"
    res = sess.clone(_Req())
    assert res.ok is False and "unsafe remediation id" in res.reason
    assert not os.path.exists("/tmp/ESCAPE_SHOULD_NOT_HAPPEN")


# ---- LAP-3: the destructive PR leg (off by default; m-of-n + token gated) -------------------------
def _keys():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    owner, worker = generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64),
        AuthorizerKey(key_id="worker", name="worker", public_key_b64=worker.public_key_b64)])
    return owner, worker, tr


def _signed(rid, *, slug, repo, owner, worker, signers, nonce="n1"):
    # a real-time window around now, WITHIN the 900s max-authorization-lifetime dead-man's-switch bound.
    import time as _t
    from vigil_integration.destruction_gate import DestructionAuthorization, sign_authorization
    t = _t.time()
    auth = DestructionAuthorization(action_id="pr-" + rid, engagement_slug=slug, target=repo,
                                    blast_class="destructive", not_before=t - 60, not_after=t + 600, nonce=nonce)
    return sign_authorization(auth, signers)


def test_quorum_enforces_m_of_n(tmp_path):
    from vigil_integration.autopatch.loop import _derive_remediation_id
    from vigil_integration.destruction_gate import DestructionAuthority
    from vigil_integration.live.codefix_runner import build_destruction_quorum

    owner, worker, tr = _keys()
    authority = DestructionAuthority(trust_root=tr, mandatory_signer_ids={"owner"})
    f = _fact("git@example.com:o/r.git")
    rid = _derive_remediation_id("", f)

    class _Req:
        remediation_id = rid
        target_repo = "git@example.com:o/r.git"
        finding = f
    q_ok = build_destruction_quorum(authority=authority,
                                    signed=_signed(rid, slug="acme", repo="git@example.com:o/r.git",
                                                   owner=owner, worker=worker,
                                                   signers=[("owner", owner.private_key_b64),
                                                            ("worker", worker.private_key_b64)]),
                                    slug="acme", is_consumed=lambda n: False)
    assert q_ok(_Req()).approved is True                       # owner + worker = m-of-2 with mandatory owner
    q_low = build_destruction_quorum(authority=authority,
                                     signed=_signed(rid, slug="acme", repo="git@example.com:o/r.git",
                                                    owner=owner, worker=worker,
                                                    signers=[("worker", worker.private_key_b64)]),
                                     slug="acme", is_consumed=lambda n: False)
    assert q_low(_Req()).approved is False                     # worker-only = below threshold → DENY


def test_nonce_ledger_durable_and_fail_closed(tmp_path):
    import os
    import stat
    from vigil_integration.live.nonce_ledger import NonceLedger
    led = NonceLedger(str(tmp_path / "nonces"))
    assert led.is_consumed("") is True                       # blank ⇒ fail-closed consumed
    assert led.is_consumed("n1") is False
    assert led.try_consume("n1") is True                     # first consume WINS
    assert led.is_consumed("n1") is True
    assert NonceLedger(str(tmp_path / "nonces")).is_consumed("n1") is True   # survives a fresh instance
    marker = os.listdir(tmp_path / "nonces")[0]
    assert stat.S_IMODE(os.stat(tmp_path / "nonces" / marker).st_mode) == 0o600   # marker is 0600
    with pytest.raises(ValueError):
        led.try_consume("")                                  # refuse consuming a blank nonce


def test_nonce_ledger_atomic_single_winner_and_no_newline_poison(tmp_path):
    # THE red-pen BLOCK fix: of N callers of the SAME nonce, EXACTLY ONE wins (atomic O_EXCL) — even under
    # real concurrency; and a newline-bearing nonce cannot poison a different nonce's entry (hashed filename).
    import threading
    from vigil_integration.live.nonce_ledger import NonceLedger
    led = NonceLedger(str(tmp_path / "nonces"))
    # Concurrency: 16 threads race to consume ONE nonce past a barrier; exactly one may win.
    wins = []
    barrier = threading.Barrier(16)
    lock = threading.Lock()

    def _race():
        barrier.wait()
        won = led.try_consume("race")
        with lock:
            wins.append(won)
    threads = [threading.Thread(target=_race) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1                              # atomic single-use holds under concurrency
    assert wins.count(False) == 15
    # Newline poisoning: consuming a newline-bearing nonce must NOT mark a distinct nonce consumed.
    assert led.try_consume("evil\nrealnonce2") is True
    assert led.is_consumed("realnonce2") is False             # the distinct nonce is untouched
    assert led.is_consumed("evil") is False


def test_single_use_authorization_cannot_replay(tmp_path):
    # THE red-pen HOLD fix: one owner-signed authorization drives exactly ONE destructive run — a replay
    # (a fresh quorum reading the same ledger + the same signed authorization) is DENIED as consumed.
    from vigil_integration.autopatch.loop import _derive_remediation_id
    from vigil_integration.destruction_gate import DestructionAuthority
    from vigil_integration.live.codefix_runner import file_backed_quorum
    owner, worker, tr = _keys()
    authority = DestructionAuthority(trust_root=tr, mandatory_signer_ids={"owner"})
    f = _fact("git@example.com:o/r.git")
    rid = _derive_remediation_id("", f)
    signed = _signed(rid, slug="acme", repo="git@example.com:o/r.git", owner=owner, worker=worker,
                     signers=[("owner", owner.private_key_b64), ("worker", worker.private_key_b64)])
    ledger = str(tmp_path / "nonces")

    class _Req:
        remediation_id = rid
        target_repo = "git@example.com:o/r.git"
        finding = f
    first = file_backed_quorum(authority=authority, signed=signed, slug="acme", ledger_path=ledger)(_Req())
    assert first.approved is True and first.nonce                       # authorized + nonce surfaced + recorded
    replay = file_backed_quorum(authority=authority, signed=signed, slug="acme", ledger_path=ledger)(_Req())
    assert replay.approved is False                                     # single-use: the replay is denied


def test_quorum_denies_when_consumption_cannot_be_recorded(tmp_path):
    # if the nonce can't be marked spent, the quorum must DENY (never authorize an un-recordable destruction).
    from vigil_integration.autopatch.loop import _derive_remediation_id
    from vigil_integration.destruction_gate import DestructionAuthority
    from vigil_integration.live.codefix_runner import build_destruction_quorum
    owner, worker, tr = _keys()
    authority = DestructionAuthority(trust_root=tr, mandatory_signer_ids={"owner"})
    f = _fact("git@example.com:o/r.git")
    rid = _derive_remediation_id("", f)
    signed = _signed(rid, slug="acme", repo="git@example.com:o/r.git", owner=owner, worker=worker,
                     signers=[("owner", owner.private_key_b64), ("worker", worker.private_key_b64)])

    def _boom(_n):
        raise OSError("ledger unwritable")

    class _Req:
        remediation_id = rid
        target_repo = "git@example.com:o/r.git"
        finding = f
    q = build_destruction_quorum(authority=authority, signed=signed, slug="acme",
                                 is_consumed=lambda n: False, consume=_boom)
    assert q(_Req()).approved is False                                  # consume failure ⇒ fail-closed deny


def test_quorum_denies_when_consume_loses_the_race(tmp_path):
    # a concurrent caller that LOSES the atomic reservation (consume ⇒ False) must be DENIED as a replay,
    # never authorized — this is what makes single-use hold under concurrency, not just sequentially.
    from vigil_integration.autopatch.loop import _derive_remediation_id
    from vigil_integration.destruction_gate import DestructionAuthority
    from vigil_integration.live.codefix_runner import build_destruction_quorum
    owner, worker, tr = _keys()
    authority = DestructionAuthority(trust_root=tr, mandatory_signer_ids={"owner"})
    f = _fact("git@example.com:o/r.git")
    rid = _derive_remediation_id("", f)
    signed = _signed(rid, slug="acme", repo="git@example.com:o/r.git", owner=owner, worker=worker,
                     signers=[("owner", owner.private_key_b64), ("worker", worker.private_key_b64)])

    class _Req:
        remediation_id = rid
        target_repo = "git@example.com:o/r.git"
        finding = f
    q = build_destruction_quorum(authority=authority, signed=signed, slug="acme",
                                 is_consumed=lambda n: False, consume=lambda n: False)  # lost the race
    assert q(_Req()).approved is False                                  # lost reservation ⇒ deny (replay)


def test_open_pr_fail_closed_without_enable_or_token(repo_and_diff, tmp_path, monkeypatch):
    from vigil_integration.live.codefix_runner import CodefixSession
    repo, _diff = repo_and_diff
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    s1 = CodefixSession(CodefixConfig(target_repo=repo, base_dir=str(tmp_path / "w1"), pr_enabled=False))
    assert s1.open_pr(type("R", (), {"fix_branch": "b", "title": "t"}), ["app.py"]).ok is False
    s2 = CodefixSession(CodefixConfig(target_repo=repo, base_dir=str(tmp_path / "w2"), pr_enabled=True))
    r = s2.open_pr(type("R", (), {"fix_branch": "b", "title": "t"}), ["app.py"])
    assert r.ok is False and "GITHUB_TOKEN" in r.reason        # enabled but no token → refuse


def test_token_goes_via_env_never_argv(repo_and_diff, tmp_path, monkeypatch):
    # secret-free: the GH token must appear in the child ENV, never in any argv (ps/logs).
    import vigil_integration.live.codefix_runner as cr
    repo, diff = repo_and_diff
    calls = []

    def _fake_run(argv, **kw):
        calls.append((list(argv), kw.get("env")))
        return type("O", (), {"exit_code": 0, "stdout": "https://gh/pr/1", "stderr": ""})()

    monkeypatch.setattr(cr, "subprocess_runner", _fake_run)
    sess = cr.CodefixSession(CodefixConfig(target_repo=repo, base_dir=str(tmp_path / "w"),
                                           pr_enabled=True, github_token="ghp_SECRET_TOK"))
    sess.workdir = str(tmp_path / "w" / "clone")
    os.makedirs(sess.workdir, exist_ok=True)
    res = sess.open_pr(type("R", (), {"fix_branch": "vigil-fix/x", "title": "fix"}), ["app.py"])
    assert res.ok is True and res.pr_ref
    assert not any("ghp_SECRET_TOK" in " ".join(argv) for argv, _env in calls), "token leaked into argv!"
    assert any(env and env.get("GH_TOKEN") == "ghp_SECRET_TOK" for _argv, env in calls), "token not in env"


def _fake_gh(tmp_path):
    p = tmp_path / "fake-gh"
    p.write_text("#!/usr/bin/env python3\nimport sys\nprint('https://github.com/o/r/pull/42')\nsys.exit(0)\n",
                 encoding="utf-8")
    import stat as _s
    p.chmod(p.stat().st_mode | _s.S_IEXEC | _s.S_IRWXU)
    return str(p)


def test_full_pr_path_opens_when_provisioned_and_quorum_passes(repo_and_diff, tmp_path, monkeypatch):
    # END-TO-END destructive path: propose → clone → apply → PR gate → m-of-n quorum → push + (fake) gh PR.
    # target_repo is the real repo; the fix branch is pushed to it (a NEW branch, allowed on a non-bare repo).
    from vigil_integration.autopatch.loop import _derive_remediation_id
    from vigil_integration.destruction_gate import DestructionAuthority
    from vigil_integration.live.codefix_runner import autopatch_live, build_destruction_quorum

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    repo, diff = repo_and_diff
    owner, worker, tr = _keys()
    authority = DestructionAuthority(trust_root=tr, mandatory_signer_ids={"owner"})
    f = _fact(repo)
    rid = _derive_remediation_id("", f)
    quorum = build_destruction_quorum(
        authority=authority, slug="acme", is_consumed=lambda n: False,
        signed=_signed(rid, slug="acme", repo=repo, owner=owner, worker=worker,
                       signers=[("owner", owner.private_key_b64), ("worker", worker.private_key_b64)]))
    cfg = CodefixConfig(target_repo=repo, base_dir=str(tmp_path / "work"), apply_edits=True,
                        pr_enabled=True, github_token="ghp_TESTTOKEN", gh_bin=_fake_gh(tmp_path))
    res = autopatch_live(f, config=cfg, client=_FakeClient(diff), quorum=quorum)
    assert res.opened_pr is True, res.status
    assert res.pr_ref and "pull/42" in res.pr_ref
    assert res.status == "opened-pr-unverified"        # no verify oracle wired ⇒ PR opens as a PROPOSAL
    assert res.remediated is False                      # never 'remediated' without a silent exploit oracle
    # the fix branch really landed on the target repo
    branches = _git("branch", "--list", "vigil-fix/*", cwd=repo).stdout
    assert "vigil-fix/" in branches


def test_pr_blocked_when_quorum_below_threshold(repo_and_diff, tmp_path, monkeypatch):
    from vigil_integration.autopatch.loop import _derive_remediation_id
    from vigil_integration.destruction_gate import DestructionAuthority
    from vigil_integration.live.codefix_runner import autopatch_live, build_destruction_quorum

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    repo, diff = repo_and_diff
    owner, worker, tr = _keys()
    authority = DestructionAuthority(trust_root=tr, mandatory_signer_ids={"owner"})
    f = _fact(repo)
    rid = _derive_remediation_id("", f)
    quorum = build_destruction_quorum(
        authority=authority, slug="acme", is_consumed=lambda n: False,
        signed=_signed(rid, slug="acme", repo=repo, owner=owner, worker=worker,
                       signers=[("worker", worker.private_key_b64)]))    # worker only → below m-of-2
    cfg = CodefixConfig(target_repo=repo, base_dir=str(tmp_path / "work"), apply_edits=True,
                        pr_enabled=True, github_token="ghp_TESTTOKEN", gh_bin=_fake_gh(tmp_path))
    res = autopatch_live(f, config=cfg, client=_FakeClient(diff), quorum=quorum)
    assert res.status == "pr-quorum-denied" and res.opened_pr is False
    assert "vigil-fix/" not in _git("branch", "--list", "vigil-fix/*", cwd=repo).stdout   # nothing pushed


def test_pr_off_by_default_even_with_a_passing_quorum(repo_and_diff, tmp_path, monkeypatch):
    # pr_enabled defaults False → the destructive gate denies BEFORE the quorum is even consulted.
    from vigil_integration.live.codefix_runner import autopatch_live
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    repo, diff = repo_and_diff
    res = autopatch_live(_fact(repo), config=CodefixConfig(target_repo=repo, base_dir=str(tmp_path / "w"),
                         apply_edits=True), client=_FakeClient(diff),
                         quorum=lambda r: type("Q", (), {"approved": True, "reason": "x", "signer_ids": []})())
    assert res.status == "pr-denied" and res.opened_pr is False


def test_clone_refuses_flag_and_transport_helper_repos(tmp_path):
    # HOLD-2: a repo that is a git-flag (leading '-') or a transport-helper (ext::/fd:: → command exec) is
    # refused BEFORE git runs.
    from vigil_integration.live.codefix_runner import CodefixSession, _repo_ok

    for bad in ["--upload-pack=touch /tmp/x", "-x", "ext::sh -c 'touch /tmp/x'", "fd::7", ""]:
        ok, _why = _repo_ok(bad)
        assert ok is False, bad
    for good in ["/local/path/repo", "https://github.com/o/r.git", "git@github.com:o/r.git", "ssh://h/r"]:
        assert _repo_ok(good)[0] is True, good
    sess = CodefixSession(CodefixConfig(target_repo="ext::sh -c 'touch /tmp/EVIL_LAP1'", base_dir=str(tmp_path)))

    class _Req:
        remediation_id = "ap-x"
        target_repo = "ext::sh -c 'touch /tmp/EVIL_LAP1'"
        fix_branch = "vigil-fix/x"
    res = sess.clone(_Req())
    assert res.ok is False and "transport-helper" in res.reason
    assert not os.path.exists("/tmp/EVIL_LAP1")
