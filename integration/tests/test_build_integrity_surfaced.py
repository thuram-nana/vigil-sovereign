"""W9-7 (#440) / W4-3 (#443) — the signed build-manifest integrity state is SURFACED by ``vigil doctor``
and by the health endpoint (`/readyz`), fail-closed.

The mechanism (the six states, the signature + digest checks) is proven in
``packages/core/vigil_core/tests/test_signed_build_manifest.py``. This file proves the WIRING on the
offense/integration plane:

  * ``doctor.collect`` reads the signed manifest at the install root and reports one of the six states in
    ``report["build_integrity"]`` — VALID adds NO issue; a tampered SIGNED RELEASE (MODIFIED) adds a HARD
    issue naming the build integrity (the negative control that proves the surfacing is not a no-op);
  * the posture endpoint's ``default_readyz`` includes the build state in its body and turns a node
    NOT-ready on MODIFIED (a load balancer drains a tampered install), while a clean tree stays ready.

FATAL-2: both surfaces reach the mechanism through ``vigil_core.signed_build_manifest`` (stdlib + vigil_core
crypto) — never ``sigil``/``framework``.

Run: PYTHONPATH=integration:gateway:packages/core/vigil_core pytest \
        integration/tests/test_build_integrity_surfaced.py -q
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.signed_build_manifest import build_signed_manifest


@pytest.fixture()
def install_root(tmp_path):
    """A tmp install root carrying a shipped tree + a signed build-manifest + a pinned trust root."""
    root = tmp_path / "install"
    (root / "python").mkdir(parents=True)
    (root / "python" / "__init__.py").write_text("V = 1\n")
    (root / "ui").mkdir()
    (root / "ui" / "app.js").write_text("console.log(1)\n")
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="rel1", name="Release 1", public_key_b64=kp.public_key_b64)])
    specs = [
        {"name": "python-core", "kind": "tree", "path": "python"},
        {"name": "browser-bundle", "kind": "tree", "path": "ui"},
    ]
    m = build_signed_manifest(product_version="1.5.0", channel="release", specs=specs,
                             tree_root=root, signers=[("rel1", kp.private_key_b64)])
    (root / "build-manifest.json").write_text(json.dumps(m.to_disk()) + "\n")
    (root / "build-trust-root.json").write_text(tr.model_dump_json())
    return root


def _neutralise_heavy_probes(monkeypatch, tmp_path):
    """Keep doctor.collect fast + deterministic: no docker/vigil binaries, an empty SIGIL_HOME (so the spine
    integrity check reports ABSENT, not a failure), and no LLM daemon."""
    import vigil_integration.doctor as doctor
    monkeypatch.setattr(doctor.shutil, "which", lambda _name: None)
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "empty-sigil-home"))


def _build_integrity_issue(report) -> "list[str]":
    return [m for m in report.get("issues", []) if "BUILD integrity" in m]


def test_doctor_reports_VALID_and_adds_no_issue(install_root, monkeypatch, tmp_path):
    import vigil_integration.doctor as doctor
    _neutralise_heavy_probes(monkeypatch, tmp_path)
    report = doctor.collect(install_root)
    assert report["build_integrity"]["state"] == "VALID"
    assert report["build_integrity"]["ok"] is True
    assert _build_integrity_issue(report) == []  # a clean build adds no hard issue


def test_doctor_reports_MODIFIED_as_a_hard_issue(install_root, monkeypatch, tmp_path):
    # NEGATIVE CONTROL: tamper a shipped file after signing → the surfacing must fire a HARD issue.
    import vigil_integration.doctor as doctor
    _neutralise_heavy_probes(monkeypatch, tmp_path)
    (install_root / "python" / "__init__.py").write_text("V = 666  # tampered\n")
    report = doctor.collect(install_root)
    assert report["build_integrity"]["state"] == "MODIFIED"
    assert "python-core" in report["build_integrity"]["modified"]
    issues = _build_integrity_issue(report)
    assert issues and "MODIFIED" in issues[0]
    assert report["ok"] is False  # a hard issue flips the doctor exit code


def test_doctor_reports_MISSING_as_a_hard_issue(install_root, monkeypatch, tmp_path):
    import vigil_integration.doctor as doctor
    _neutralise_heavy_probes(monkeypatch, tmp_path)
    for p in sorted((install_root / "ui").iterdir()):
        p.unlink()
    (install_root / "ui").rmdir()
    report = doctor.collect(install_root)
    assert report["build_integrity"]["state"] == "MISSING"
    assert _build_integrity_issue(report)


def test_doctor_on_a_source_checkout_is_UNKNOWN_BUILD_note_not_issue(monkeypatch, tmp_path):
    # A tree with NO manifest (a source checkout) is UNKNOWN_BUILD — a NOTE, never a hard issue that
    # bricks doctor. This is the fail-closed default (never an optimistic VALID).
    import vigil_integration.doctor as doctor
    _neutralise_heavy_probes(monkeypatch, tmp_path)
    root = tmp_path / "src-checkout"
    root.mkdir()
    report = doctor.collect(root)
    assert report["build_integrity"]["state"] == "UNKNOWN_BUILD"
    assert _build_integrity_issue(report) == []


def test_readyz_includes_build_integrity_and_drains_on_MODIFIED(install_root, monkeypatch, tmp_path):
    import vigil_integration.doctor as doctor
    from vigil_integration.posture import endpoint
    monkeypatch.setattr(doctor, "find_repo_root", lambda: install_root)
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "empty-sigil-home"))

    ready, body = endpoint.default_readyz()
    assert body["build_integrity"]["state"] == "VALID"
    assert ready is True  # clean build + absent spine (ABSENT is not a failure) → ready

    (install_root / "ui" / "app.js").write_text("console.log('tampered')\n")
    ready2, body2 = endpoint.default_readyz()
    assert body2["build_integrity"]["state"] == "MODIFIED"
    assert ready2 is False  # a tampered signed release drains the node
