"""P4 — the read-only queryable posture endpoint + the counterparty poll-and-verify flow.

A counterparty GETs the latest signed bundle over loopback and re-verifies it OFFLINE with the bundle's
own VIGIL-free verifier — no VIGIL, no trust in the producer. The endpoint is GET-only and refuses a
public bind.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from vigil_integration.posture.attest import attest_loopback_benchmark
from vigil_integration.posture.endpoint import PostureEndpointError, serve_posture


def _get(url: str) -> tuple[int, bytes]:
    with urllib.request.urlopen(url, timeout=10) as r:  # noqa: S310 (loopback only, test)
        return r.status, r.read()


def test_endpoint_serves_bundle_and_counterparty_verifies_offline(tmp_path: Path):
    res = attest_loopback_benchmark(tmp_path / "run", engagement="demo")
    bundle_dir = Path(res["bundle_dir"])
    srv = serve_posture("127.0.0.1", 0, bundle_dir)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        status, body = _get(base + "/posture")
        assert status == 200 and body == (bundle_dir / "bundle.json").read_bytes()
        st_fp, fp = _get(base + "/posture/trust-root")
        assert st_fp == 200 and fp.decode().strip() == res["fingerprint"]
        assert _get(base + "/healthz")[1] == b'{"ok":true}'

        # COUNTERPARTY: write the polled bundle to a fresh dir with the shipped verifier, verify OFFLINE
        # with the out-of-band pins (fingerprint + owner pubkey + engagement).
        cp = tmp_path / "counterparty"
        cp.mkdir()
        (cp / "bundle.json").write_bytes(body)
        shutil.copyfile(bundle_dir / "verify_offline.py", cp / "verify_offline.py")
        r = subprocess.run(
            [sys.executable, str(cp / "verify_offline.py"), "verify", "--bundle", str(cp / "bundle.json"),
             "--posture-fingerprint", res["fingerprint"], "--posture-owner-pubkey", res["owner_pubkey"],
             "--posture-engagement", res["engagement"], "--posture-now", "1"],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        assert r.returncode == 0, r.stdout + r.stderr
        assert "SOUND" in r.stdout and "NOT SOUND" not in r.stdout
    finally:
        srv.shutdown()
        srv.server_close()


def test_endpoint_is_read_only(tmp_path: Path):
    res = attest_loopback_benchmark(tmp_path / "run", engagement="demo")
    srv = serve_posture("127.0.0.1", 0, res["bundle_dir"])
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/posture", method="POST", data=b"x")
        with pytest.raises(urllib.error.HTTPError) as ei:  # noqa: PT012
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
        assert ei.value.code == 405
    finally:
        srv.shutdown()
        srv.server_close()


def test_bind_ok_refuses_public():
    with pytest.raises(PostureEndpointError):
        serve_posture("0.0.0.0", 0, ".")
