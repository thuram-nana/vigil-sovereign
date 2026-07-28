"""
K6 — the operator-gated knowledge/ → GitHub sync (`vigil_integration.knowledge_sync`).

Doctrine under test:
  * a DEFENSE-IN-DEPTH secret scan over knowledge/ (NOT a guarantee — the operator still redacts): it fires
    on provider tokens AND env-var/underscore-joined credential assignments (GITHUB_TOKEN=…, MY_API_KEY=…),
    refuses binary/compressed/oversized files (a secret can't hide in a .gz transcript or a renamed .png),
    and does not false-positive on a bare hash or prose — with no ReDoS on large input;
  * `sync` commits ONLY knowledge/ and only when it changed (never an empty commit); `push` is a SEPARATE,
    explicit act — and both are inert under `--dry-run` (the outward act is never accidental);
  * boundary-clean: the module is pure-stdlib + subprocess (imports no offense/sovereign engine).
"""

from __future__ import annotations

import subprocess

import pytest

from vigil_integration import knowledge_sync as ks

# Secret-SHAPED test fixtures, assembled from split literals at RUNTIME so no contiguous provider token
# appears in this committed source file (else GitHub's own push-protection would reject the push). The
# scanner sees them assembled; the repo never stores a literal token.
_GHP = "ghp" "_" + "16C7e42F292c6912E7710c838347Ae178B4a"           # GitHub PAT (fake)
_GH_FINE = "github" "_pat_" + "11ABCDEFG0aBcDeFgHiJkLmNoPqRsTuVwXyZ"
_ANT = "sk-" "ant-" + "abcdef0123456789ABCDEFxyz"
_AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"                                 # AWS docs example id
_XOXB = "xox" "b-" + "1234567890-abcdefghijklmnop"
_STRIPE = "sk" "_live_" + "abcdef0123456789ABCDEF"
_JWT = "eyJ" + "hbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4"
_PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIBxyz"


def _log(repo) -> str:
    p = subprocess.run(["git", "-C", str(repo), "log", "--oneline"], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""


def _init_repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    subprocess.run(["git", "-C", str(r), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(r), "config", "user.name", "t"], check=True)
    (r / "knowledge").mkdir()
    (r / "knowledge" / "sync.sh").write_text("#!/usr/bin/env bash\necho regenerated\n")   # no-op stub
    return r


# ---- the secret scan --------------------------------------------------------

def test_real_knowledge_folder_is_clean():
    # the committed KB carries no secrets, and the scanner does NOT false-positive on the manifest source_sha.
    assert ks.scan_secrets(ks.repo_root()) == []


def test_scan_detects_each_secret_pattern(tmp_path):
    (tmp_path / "knowledge").mkdir()
    cases = {
        "pem.md": _PEM,
        "ant.md": "api_key = " + _ANT,
        "aws.md": "creds " + _AWS_ID + " here",
        "assign.md": "password: hunter2000000000000000000000secret",
        # the red-pen's misses: underscore-joined env-var names (the \b…\b blind spot) + provider tokens.
        "gh_env.md": "GITHUB_TOKEN=" + _GHP,
        "gh_bare.md": "here is a " + _GHP + " token dump",
        "gh_fine.md": _GH_FINE,
        "myapi.md": "MY_API_KEY=abcdef0123456789abcdef01",
        "dbpw.md": "DATABASE_PASSWORD=supersecretpassword12345",
        "awssec.md": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef0123456789EXAMPLE",
        "slack.md": "SLACK=" + _XOXB,
        "stripe.md": "stripe " + _STRIPE,
        "jwt.md": "auth " + _JWT,
        "gcp.json": '{"type": "service_account", "private' + '_key_id": "a1b2c3d4e5f60718"}',
    }
    for name, content in cases.items():
        (tmp_path / "knowledge" / name).write_text(content, encoding="utf-8")
    hits = {f.rsplit("/", 1)[-1] for f, _ in ks.scan_secrets(tmp_path)}
    assert hits == set(cases), f"missed: {set(cases) - hits}"


def test_scan_refuses_unscannable_and_renamed(tmp_path):
    import gzip
    k = tmp_path / "knowledge"
    k.mkdir()
    (k / "evil.png").write_text("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIB", encoding="utf-8")  # renamed secret
    (k / "t.gz").write_bytes(gzip.compress(("GITHUB_TOKEN=" + _GHP).encode()))                    # compressed
    (k / "big.md").write_text("x" * (ks._MAX_SCAN_BYTES + 1), encoding="utf-8")               # oversized
    reasons = {f.rsplit("/", 1)[-1]: r for f, r in ks.scan_secrets(tmp_path)}
    assert reasons["evil.png"] == "private-key"           # no suffix is exempt
    assert reasons["t.gz"] == "binary-unscannable"        # compressed → refused, not silently skipped
    assert reasons["big.md"] == "oversized"               # only partially scannable → refused


def test_scan_no_false_positive_on_hash_or_prose(tmp_path):
    (tmp_path / "knowledge").mkdir()
    (tmp_path / "knowledge" / "map.json").write_text(
        '{"source_sha": "3b100c3a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbcc"}', encoding="utf-8")
    (tmp_path / "knowledge" / "doc.md").write_text(
        "Redact keys, tokens, and passwords. See the token guidance; never commit a secret.", encoding="utf-8")
    assert ks.scan_secrets(tmp_path) == []      # a bare hash + the words token/password are NOT secrets


def test_scan_has_no_redos_on_large_input(tmp_path):
    import time
    k = tmp_path / "knowledge"
    k.mkdir()
    # a long run of identifier chars (~1.5 MB, under the scan cap so it is actually scanned, not flagged
    # oversized) with NO `= value` — the fixed regex must clear it linearly, not backtrack catastrophically.
    (k / "wall.md").write_text("token_" * 250_000, encoding="utf-8")
    t0 = time.time()
    assert ks.scan_secrets(tmp_path) == []
    assert time.time() - t0 < 5.0


def test_sync_refuses_a_github_token_in_a_transcript(tmp_path):
    # the crown-jewel case: a build-session transcript with a leaked GITHUB_TOKEN must REFUSE, not commit.
    r = _init_repo(tmp_path)
    (r / "knowledge" / "sessions").mkdir()
    (r / "knowledge" / "sessions" / "s42.md").write_text(
        "env dump:\nGITHUB_TOKEN=" + _GHP + "\n", encoding="utf-8")
    res = ks.sync(root=r)
    assert res["ok"] is False and any("s42.md" in f for f, _ in res["secrets"])
    assert _log(r) == ""                                  # nothing committed → the token can't be pushed


# ---- sync / push (isolated tmp git repos) ----------------------------------

def test_sync_commits_only_knowledge_and_is_idempotent(tmp_path):
    r = _init_repo(tmp_path)
    (r / "knowledge" / "kb.md").write_text("advisory, never a fact", encoding="utf-8")
    res = ks.sync(root=r, message="k6 test")
    assert res["ok"] and res["committed"] and "k6 test" in _log(r)
    res2 = ks.sync(root=r)                       # nothing changed → no empty commit
    assert res2["ok"] and res2["committed"] is None and "unchanged" in (res2["note"] or "")


def test_sync_refuses_on_secret_and_commits_nothing(tmp_path):
    r = _init_repo(tmp_path)
    (r / "knowledge" / "leak.md").write_text("api_key = " + _ANT, encoding="utf-8")
    res = ks.sync(root=r)
    assert res["ok"] is False and res["secrets"]
    assert _log(r) == ""                         # nothing was committed


def test_dry_run_never_commits_or_pushes(tmp_path):
    r = _init_repo(tmp_path)
    (r / "knowledge" / "kb.md").write_text("x", encoding="utf-8")
    res = ks.sync(root=r, dry_run=True)
    assert res["committed"]["dry_run"] is True and _log(r) == ""      # dry-run: no commit
    assert ks.push(root=r, dry_run=True)["pushed"]["dry_run"] is True  # dry-run: no push (no remote needed)


def test_boundary_clean_no_engine_import():
    import vigil_integration.knowledge_sync as mod
    src = __import__("inspect").getsource(mod)
    assert "import framework" not in src and "import sigil" not in src and "from sigil" not in src


# ---- CLI registration -------------------------------------------------------

def test_cli_registers_knowledge_verb():
    from vigil_integration.cli import build_parser
    a = build_parser().parse_args(["knowledge", "status"])
    assert a.command == "knowledge" and a.knowledge_action == "status"
    b = build_parser().parse_args(["knowledge", "sync", "--dry-run", "-m", "hi"])
    assert b.knowledge_action == "sync" and b.dry_run is True and b.message == "hi"
    with pytest.raises(SystemExit):
        build_parser().parse_args(["knowledge", "bogus"])      # only sync|push|status allowed
