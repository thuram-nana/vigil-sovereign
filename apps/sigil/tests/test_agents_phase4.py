"""SIGIL Phase 4 — ARTIFICER (tests-before-PR, PRs-not-pushes) + SCHOLAR (source-grounded claims).
Run: ~/.sigil/venv/bin/python tests/test_agents_phase4.py"""
import subprocess
import sys
import tempfile
from pathlib import Path

from sigil.agents.artificer import Artificer
from sigil.agents.scholar import Scholar, grounds_in_source
from sigil.spine.store import SpineStore


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _sandbox_repo() -> str:
    repo = tempfile.mkdtemp(prefix="artificer-")
    for args in (["init", "-q"], ["config", "user.email", "a@b.c"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", repo, *args], check=True)
    Path(repo, "mod.py").write_text("def add(a, b):\n    return a - b\n")   # bug: minus
    Path(repo, "test_mod.py").write_text("from mod import add\nassert add(2, 3) == 5, 'add is wrong'\n")
    subprocess.run(["git", "-C", repo, "add", "-A"], check=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "init"], check=True)
    return repo


class _FixCoder:
    def code(self, task, workdir):
        Path(workdir, "mod.py").write_text("def add(a, b):\n    return a + b\n")  # correct
        return "changed subtraction to addition in add()"


class _NoFixCoder:
    def code(self, task, workdir):
        Path(workdir, "mod.py").write_text("def add(a, b):\n    return a - b  # touched, still wrong\n")
        return "added a comment (did not fix)"


def test_artificer_proposes_pr_when_tests_pass():
    repo = _sandbox_repo()
    res = Artificer(_store()).run("fix the failing add test", repo=repo,
                                  test_cmd=[sys.executable, "test_mod.py"], coder=_FixCoder())
    assert len(res.queued) == 1 and res.queued[0]["kind"] == "pr", "tests pass → a PR is proposed"
    assert res.queued[0]["tier"] == "A2", "the PR QUEUES for approval (never auto/pushed)"


def test_artificer_withholds_pr_when_tests_fail():
    repo = _sandbox_repo()
    res = Artificer(_store()).run("fix the failing add test", repo=repo,
                                  test_cmd=[sys.executable, "test_mod.py"], coder=_NoFixCoder())
    assert not res.queued, "a red test must NOT yield a PR (correctness discipline)"
    assert res.applied, "the failure is recorded (finding), not shipped"


def test_artificer_never_invokes_git_push():
    # BEHAVIORAL: spy on every git argv ARTIFICER runs; it may commit locally but MUST never push.
    from sigil.agents import artificer as art
    calls = []
    orig = art._git

    def spy(repo, *args, **kw):
        calls.append(tuple(args))
        return orig(repo, *args, **kw)

    art._git = spy
    try:
        repo = _sandbox_repo()
        art.Artificer(_store()).run("fix add", repo=repo,
                                    test_cmd=[sys.executable, "test_mod.py"], coder=_FixCoder())
    finally:
        art._git = orig
    flat = [a for c in calls for a in c]
    assert "push" not in flat, f"ARTIFICER must NEVER run git push: {calls}"
    assert any(c and c[0] == "commit" for c in calls), "it committed locally (PR is a local branch)"


def test_artificer_withholds_pr_without_a_real_test():
    # no test command (or a trivial one) → change is UNVERIFIED → no PR, only a finding
    repo = _sandbox_repo()
    res = Artificer(_store()).run("fix add", repo=repo, test_cmd=None, coder=_FixCoder())
    assert not res.queued, "no real test → no PR"
    assert res.applied, "the unverified change is recorded as a finding"
    res2 = Artificer(_store()).run("fix add", repo=repo, test_cmd=["true"], coder=_FixCoder())
    assert not res2.queued, "a trivially-passing test command must not yield a PR either"


def test_scholar_serves_quote_not_claim_and_flags_unbacked():
    src = tempfile.mktemp(suffix=".txt")
    Path(src).write_text("The SIGIL kernel uses Ed25519 signatures for its action log.")

    class _MockSynth:
        def synthesize(self, question, docs):
            return [
                # honest: claim matches a verbatim quote
                {"claim": "SIGIL uses Ed25519", "source": src,
                 "quote": "uses Ed25519 signatures for its action log", "confidence": 0.9},
                # THE CRITICAL CASE: a FABRICATED claim paired with a REAL (but unrelated) verbatim quote
                {"claim": "SIGIL stores its private keys in PLAINTEXT on disk", "source": src,
                 "quote": "uses Ed25519 signatures for its action log", "confidence": 0.95},
                # a claim whose quote is NOT in the source at all → unverified
                {"claim": "SIGIL uses RSA-4096", "source": src,
                 "quote": "RSA-4096 keys everywhere", "confidence": 0.8},
            ]

    s = _store()
    res = Scholar(s).run("what does SIGIL use for signing?", [src], synthesizer=_MockSynth())
    text = s.get(res.applied[0]).payload["text"]
    # the authoritative served content is the verbatim QUOTE, never the model's free-text claim.
    assert "uses Ed25519 signatures for its action log" in text, "the verbatim source span is served"
    # the fabricated 'plaintext keys' claim must appear ONLY as advisory, never as a verified finding.
    for line in text.splitlines():
        if "plaintext" in line.lower():
            assert "ADVISORY" in line, "a fabricated claim must be advisory-only, never source-verified"
    assert "RSA-4096" in text and "Unverified" in text, "a claim with no verbatim source span is flagged unverified"


def test_grounds_in_source_verbatim_and_specific():
    doc = "the kernel uses Ed25519 signatures and a hash chain"
    assert grounds_in_source("uses Ed25519 signatures", doc)
    assert not grounds_in_source("uses RSA keys", doc), "a quote absent from the source does not ground"
    assert not grounds_in_source("the and", doc), "a trivial (stopword-only) quote grounds nothing"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"{passed}/{len(fns)} Phase-4 (ARTIFICER + SCHOLAR) guarantees hold")
