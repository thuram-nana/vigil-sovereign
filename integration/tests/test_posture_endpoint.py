"""P4 — the read-only queryable posture endpoint + the counterparty poll-and-verify flow.

A counterparty GETs the latest signed bundle over loopback and re-verifies it OFFLINE with the bundle's
own VIGIL-free verifier — no VIGIL, no trust in the producer. The endpoint is GET-only and refuses a
public bind.
"""
from __future__ import annotations

import json
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


def _verify_offline(cp_dir: Path, bundle_bytes: bytes, res: dict) -> subprocess.CompletedProcess:
    """Run the bundle's OWN shipped verifier over `bundle_bytes` exactly as a distrusting third party
    would — VIGIL-free (only `cryptography`, no PYTHONPATH), with the out-of-band pins."""
    cp_dir.mkdir(exist_ok=True)
    (cp_dir / "bundle.json").write_bytes(bundle_bytes)
    return subprocess.run(
        [sys.executable, str(cp_dir / "verify_offline.py"), "verify", "--bundle", str(cp_dir / "bundle.json"),
         "--posture-fingerprint", res["fingerprint"], "--posture-owner-pubkey", res["owner_pubkey"],
         "--posture-engagement", res["engagement"], "--posture-now", "1"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})


def test_endpoint_emits_the_signed_artifact_not_the_read_view_and_tamper_is_rejected(tmp_path: Path):
    """W17-12 (#546): the endpoint must return the SIGNED bundle (`{"posture": {certificate, signature}}`),
    NOT the projected read-view — and that emitted artifact must be third-party verifiable OFFLINE, with a
    single flipped byte flipping it to NOT SOUND. That tamper is the negative control that PROVES the served
    bytes are the signed artifact (a read-view carries no signature to break)."""
    res = attest_loopback_benchmark(tmp_path / "run", engagement="demo")
    bundle_dir = Path(res["bundle_dir"])
    srv = serve_posture("127.0.0.1", 0, bundle_dir)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        status, body = _get(f"http://127.0.0.1:{port}/posture")
        assert status == 200
        # It IS the signed artifact, byte-for-byte the on-disk bundle.json a verifier consumes …
        assert body == (bundle_dir / "bundle.json").read_bytes()
        doc = json.loads(body)
        assert isinstance(doc.get("posture"), dict), "served the read-view (list), not the signed bundle"
        assert set(doc["posture"]) >= {"certificate", "signature"}
        # … and NOT the read-view shape (the /api/posture projection carries these per-item markers).
        assert "posture_claims" not in doc and "present" not in doc and "summary" not in doc

        _mkverifier(tmp_path / "good", bundle_dir)
        good = _verify_offline(tmp_path / "good", body, res)
        assert good.returncode == 0, good.stdout + good.stderr
        assert "SOUND" in good.stdout and "NOT SOUND" not in good.stdout

        # NEGATIVE CONTROL — tamper: change ONE signed value in the served certificate. The signature over
        # the canonical certificate bytes no longer matches → the offline verifier reports NOT SOUND.
        doc["posture"]["certificate"]["scope"] = "TAMPERED-BY-TEST"
        tampered = json.dumps(doc).encode("utf-8")
        assert tampered != body
        _mkverifier(tmp_path / "bad", bundle_dir)
        bad = _verify_offline(tmp_path / "bad", tampered, res)
        assert bad.returncode != 0, "a tampered bundle verified SOUND — not the signed artifact"
        assert "NOT SOUND" in bad.stdout, bad.stdout + bad.stderr
    finally:
        srv.shutdown()
        srv.server_close()


def _mkverifier(cp_dir: Path, bundle_dir: Path) -> Path:
    cp_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bundle_dir / "verify_offline.py", cp_dir / "verify_offline.py")
    return cp_dir / "verify_offline.py"
