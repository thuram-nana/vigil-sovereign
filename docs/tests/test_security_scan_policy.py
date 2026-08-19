"""The security-scan workflow, its scanner configs, and a REAL planted-secret catch.  [W2-3 / #420]

WHY THIS TEST EXISTS. The repository vendors an offensive toolchain and holds Ed25519 signing
material, yet shipped no CodeQL, no secret scanning and no SAST. Slice W2-3 adds an ADVISORY
`.github/workflows/security-scan.yml` that wraps three scanners, each pinned by a checked-in config:

  * gitleaks over the working tree, policy in `.gitleaks.toml`;
  * semgrep over a curated ruleset in `.semgrep/vigil-sast.yml`;
  * bandit over a curated subset in `bandit.yaml` (advisory).

A workflow that merely EXISTS proves nothing. This test proves the change three ways:

  1. CONFIG EXISTS + WIRED. Each config file is present and is referenced by the workflow, each
     scanner is invoked, and every scanner has an in-workflow NEGATIVE-CONTROL step. These are pure
     file reads, so they run in the stdlib-only docs CI job — and they FAIL WITHOUT the change,
     because none of these files exist on a tree without it.

  2. ADVISORY + SUPPLY-CHAIN HYGIENE. Every job the new workflow defines is ABSENT from
     `.github/required-status-checks.txt` (advisory, per this slice's CI discipline), and every
     third-party action it uses is pinned to a full 40-hex commit SHA.

  3. REAL CATCH (negative control). When gitleaks / semgrep are on PATH (they are locally and in any
     job that installs them; the stdlib docs job skips this part), the test RE-RUNS each scanner
     with the COMMITTED config against a planted fixture and asserts (a) a secret / SAST pattern in
     ordinary source is CAUGHT, and (b) the same secret under an allowlisted `tests/` path is NOT
     caught — proving the allowlist is scoped by path, not a blanket mute. If a scanner's config
     were a no-op, (a) would fail; if the allowlist were a blanket rule-disable, (b) would fail.

It imports nothing beyond the standard library, so it is correct to run in the docs-only CI job.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "security-scan.yml"
GITLEAKS_CFG = REPO / ".gitleaks.toml"
SEMGREP_CFG = REPO / ".semgrep" / "vigil-sast.yml"
BANDIT_CFG = REPO / "bandit.yaml"
CANONICAL = REPO / ".github" / "required-status-checks.txt"


def _wf_text() -> str:
    assert WORKFLOW.is_file(), f"missing security-scan workflow: {WORKFLOW}"
    return WORKFLOW.read_text(encoding="utf-8")


def _strip_comments(text: str) -> str:
    """Drop YAML `#` comments so wiring assertions match real config, not prose."""
    out = []
    for ln in text.splitlines():
        h = ln.find("#")
        out.append(ln if h < 0 else ln[:h])
    return "\n".join(out)


# --------------------------------------------------------------------------------------------------
# 1. Config exists + wired  (pure file reads — these FAIL WITHOUT the change)
# --------------------------------------------------------------------------------------------------
def test_scanner_config_files_exist():
    for p in (WORKFLOW, GITLEAKS_CFG, SEMGREP_CFG, BANDIT_CFG):
        assert p.is_file(), f"required scanner artifact is missing: {p.relative_to(REPO)}"


def test_workflow_invokes_all_three_scanners():
    body = _strip_comments(_wf_text())
    assert "github/codeql-action/init" in body and "github/codeql-action/analyze" in body, (
        "CodeQL init/analyze not wired into the workflow"
    )
    assert "languages: python" in body, "CodeQL must analyze python"
    assert "gitleaks detect" in body, "gitleaks is not invoked"
    assert "semgrep --config .semgrep/vigil-sast.yml" in body, "the committed semgrep ruleset is not used"
    assert "bandit -c bandit.yaml" in body, "the committed bandit config is not used"
    assert ".gitleaks.toml" in body, "the committed gitleaks policy is not referenced"


def test_each_scanner_gate_has_a_negative_control():
    """Every blocking scanner carries an in-workflow negative control that fails the job if it can't fire."""
    body = _wf_text()
    names = re.findall(r"^\s*-\s*name:\s*(.+?)\s*$", body, re.M)
    nc = [n for n in names if "negative control" in n.lower()]
    assert len(nc) >= 3, f"expected a negative control for gitleaks, semgrep and bandit; found: {nc}"
    # The guard must be a real fail-the-job branch, not a comment.
    assert body.count("NEGATIVE CONTROL FAILED") >= 3, (
        "each negative control must emit a ::error:: and exit non-zero when the scanner does not fire"
    )


def test_gitleaks_policy_extends_default_and_scopes_not_blanket_mutes():
    cfg = GITLEAKS_CFG.read_text(encoding="utf-8")
    assert "useDefault = true" in cfg, "the policy must EXTEND the full default ruleset, not replace it"
    # An allowlist scoped to test/doc paths — not a rule disable.
    assert "paths" in cfg, "the policy allowlists by path (fixtures), which must be present"
    assert "[[rules]]" not in cfg.replace("[[rules.", ""), (
        "the policy must not redefine/replace detection rules; it only allowlists"
    )


# --------------------------------------------------------------------------------------------------
# 2. Advisory + supply-chain hygiene
# --------------------------------------------------------------------------------------------------
def _new_workflow_job_names() -> set[str]:
    """Job-level `name:` values in the new workflow (two-space job key, four-space name)."""
    body = _wf_text()
    lines = body.splitlines()
    in_jobs = False
    cur_job = False
    names: set[str] = set()
    for ln in lines:
        if re.match(r"^jobs:\s*$", ln):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", ln):
            cur_job = True
            continue
        m = re.match(r"^    name:\s*(.+?)\s*$", ln)
        if m and cur_job:
            names.add(m.group(1))
            cur_job = False
    return names


def test_new_workflow_is_advisory_not_in_required_checks():
    """CI discipline for this slice: the new jobs must be ADVISORY (absent from the canonical list)."""
    canonical = {
        ln.strip()
        for ln in CANONICAL.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    }
    jobs = _new_workflow_job_names()
    assert jobs, "could not parse any job name from the new workflow"
    leaked = jobs & canonical
    assert not leaked, (
        f"security-scan jobs must stay ADVISORY, but these are in required-status-checks.txt: {leaked}"
    )


def test_new_workflow_actions_are_sha_pinned():
    """A GitHub Action reference executes with the workflow token; pin to a full commit SHA, not a tag."""
    body = _strip_comments(_wf_text())
    uses = re.findall(r"uses:\s*(\S+)", body)
    assert uses, "the new workflow uses no actions at all — did the file get truncated?"
    unpinned = [u for u in uses if not re.search(r"@[0-9a-f]{40}$", u)]
    assert not unpinned, f"these action references are not pinned to a full commit SHA: {unpinned}"


def test_pinned_binary_scanners_carry_a_digest_or_exact_version():
    body = _wf_text()
    assert re.search(r"GITLEAKS_SHA256:\s*\"[0-9a-f]{64}\"", body), (
        "the gitleaks binary must be pinned by the sha256 of its release tarball"
    )
    assert re.search(r"sha256sum -c", body), "the gitleaks download must be checksum-verified"
    # semgrep and bandit are pip-installed at exact versions carried in the workflow env block.
    assert re.search(r"SEMGREP_VERSION:\s*\"\d+\.\d+\.\d+\"", body), "semgrep must be pinned to an exact version"
    assert re.search(r"BANDIT_VERSION:\s*\"\d+\.\d+\.\d+\"", body), "bandit must be pinned to an exact version"
    assert "semgrep==${SEMGREP_VERSION}" in body, "the semgrep install must use the pinned version"
    assert "bandit==${BANDIT_VERSION}" in body, "the bandit install must use the pinned version"


def test_workflow_yaml_parses_if_pyyaml_available():
    """Full structural parse when PyYAML is installed (locally / SAST-adjacent jobs); no-op otherwise."""
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        pytest.skip("PyYAML not installed in this job; structural parse is covered where it is")
    doc = yaml.safe_load(_wf_text())
    jobs = doc["jobs"]
    assert set(jobs) == {"codeql-python", "secret-scan", "sast"}, jobs.keys()


# --------------------------------------------------------------------------------------------------
# 3. REAL CATCH — re-run the actual scanner against a planted fixture (skips if the tool is absent)
# --------------------------------------------------------------------------------------------------
def _run(cmd: list[str]) -> int:
    return subprocess.run(cmd, capture_output=True, text=True).returncode


def test_gitleaks_negative_control_real_catch():
    exe = shutil.which("gitleaks")
    if not exe:
        pytest.skip("gitleaks not installed in this job")
    suffix = "Zt7Xq2mNpLvR8kYhWfDbGcE4"
    secret = "-".join(["xoxb", "2837465019283", "9182736450192", suffix])
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "service" / "app"
        tst = Path(d) / "tests"
        src.mkdir(parents=True)
        tst.mkdir(parents=True)
        (src / "config.py").write_text(f'SLACK_BOT_TOKEN = "{secret}"\n')
        (tst / "test_fixture.py").write_text(f'SLACK_BOT_TOKEN = "{secret}"\n')
        base = [exe, "detect", "--no-git", "-c", str(GITLEAKS_CFG), "--redact", "--exit-code", "1", "--no-banner"]
        rc_src = _run(base + ["-s", str(Path(d) / "service")])
        rc_tst = _run(base + ["-s", str(tst)])
    assert rc_src != 0, "REAL CATCH failed: gitleaks did not flag a planted secret in service code (config is a no-op)"
    assert rc_tst == 0, "scoping failed: the tests/ allowlist did not apply (allowlist is a blanket mute, not path-scoped)"


def test_semgrep_negative_control_real_catch():
    exe = shutil.which("semgrep")
    if not exe:
        pytest.skip("semgrep not installed in this job")
    fixture = (
        "import requests, yaml, ssl, subprocess\n"
        "def a(u): return requests.get(u, verify=False)\n"
        "def b(s): return yaml.load(s)\n"
        "def c(): return ssl._create_unverified_context()\n"
        "def d(app): app.run(host='0.0.0.0', debug=True)\n"
        "def e(name): return subprocess.run(f'ls {name}', shell=True)\n"
    )
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "bad.py").write_text(fixture)
        env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0")
        clean = Path(d) / "clean"
        clean.mkdir()
        (clean / "ok.py").write_text("import requests\n\ndef a(u):\n    return requests.get(u, timeout=5)\n")
        cmd = [exe, "--config", str(SEMGREP_CFG), "--error", "--quiet", "--metrics", "off", "--disable-version-check"]
        rc_bad = subprocess.run(cmd + [str(Path(d) / "bad.py")], capture_output=True, text=True, env=env).returncode
        rc_clean = subprocess.run(cmd + [str(clean)], capture_output=True, text=True, env=env).returncode
    assert rc_bad != 0, "REAL CATCH failed: the semgrep ruleset matched nothing on a fixture that violates every rule"
    assert rc_clean == 0, "false positive: the ruleset fired on benign code (a timeout'd verified request)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
