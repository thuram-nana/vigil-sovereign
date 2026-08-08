"""P2 — LIVE end-to-end: a real coverage scan of the loopback benchmark app → PostureCertificate →
portable bundle → re-verified OFFLINE by the bundle's OWN shipped verify_offline.py (the exact
third-party, VIGIL-free experience). A tamper flips the verdict to NOT SOUND.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from vigil_integration.posture.attest import attest_loopback_benchmark


def _run_shipped_verifier(bundle_dir: Path, res: dict, *, now: int = 1) -> subprocess.CompletedProcess:
    """Invoke the bundle's OWN verify_offline.py exactly as a distrusting third party would — a clean
    env with NO PYTHONPATH, so no VIGIL module is even on the path (only stdlib + cryptography, which
    the interpreter finds in its own venv site-packages)."""
    cmd = [sys.executable, str(bundle_dir / "verify_offline.py"), "verify",
           "--bundle", str(bundle_dir / "bundle.json"),
           "--posture-fingerprint", res["fingerprint"],
           "--posture-owner-pubkey", res["owner_pubkey"],
           "--posture-engagement", res["engagement"],
           "--posture-now", str(now)]
    return subprocess.run(cmd, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})


def test_attest_scan_then_offline_verify(tmp_path: Path):
    res = attest_loopback_benchmark(tmp_path / "run", engagement="demo")
    summ = res["summary"]
    # the benchmark app has planted bugs → at least one OPEN, and the projection is complete
    assert summ["n_open"] >= 1
    assert summ["n_closed"] + summ["n_open"] + summ["n_unproven"] >= 1
    bundle = Path(res["bundle_dir"])
    assert (bundle / "bundle.json").is_file()
    assert (bundle / "verify_offline.py").is_file()
    assert (bundle / "HOW-TO-VERIFY.md").is_file()

    r = _run_shipped_verifier(bundle, res)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SOUND" in r.stdout and "NOT SOUND" not in r.stdout


def test_tampered_bundle_is_not_sound(tmp_path: Path):
    res = attest_loopback_benchmark(tmp_path / "run", engagement="demo")
    bundle = Path(res["bundle_dir"])
    doc = json.loads((bundle / "bundle.json").read_text())
    # flip a summary number in the embedded certificate
    doc["posture"]["certificate"]["summary"]["n_closed"] = 9999
    (bundle / "bundle.json").write_text(json.dumps(doc))
    r = _run_shipped_verifier(bundle, res)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "NOT SOUND" in r.stdout


def test_posture_cli_verify(tmp_path: Path):
    res = attest_loopback_benchmark(tmp_path / "run", engagement="demo")
    # the `vigil posture verify` CLI reads the pins from the bundle and shells to verify_offline.py
    r = subprocess.run([sys.executable, "-m", "vigil_integration.posture", "verify",
                        "--bundle", res["bundle_dir"], "--posture-now", "1"],
                       capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "integration"},
                       cwd=str(Path(__file__).resolve().parents[1].parent))
    assert r.returncode == 0, r.stdout + r.stderr
