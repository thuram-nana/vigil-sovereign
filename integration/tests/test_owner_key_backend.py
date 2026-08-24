"""W9-6 (#439) — the pluggable owner-key backend, from the integration side.

Proves the two integration-visible acceptance criteria, each with its negative control:

  * ``vigil doctor`` REPORTS the active owner-key backend (a new `owner-key-backend` posture control):
    FILE by default; a fail-closed PKCS11-* state when the hardware backend is selected but its token is
    absent. Negative control: flip the env and the reported state flips.
  * the REAL owner-signing entry point (`vigil approve sign`) fails closed. With the hardware backend
    selected and its token absent, it REFUSES to sign and writes NO token — even though a perfectly good
    file key is present. Positive control: the default file backend still signs a pending approval, and the
    written token verifies under the owner key. This is the "nothing deployed breaks" + "absent token
    never falls back to a file key" pair at the CLI.

Imports only vigil_integration + vigil_core + stdlib (no framework / sigil) — safe in the P5 job.
"""
from __future__ import annotations

import json
import types

from vigil_core import generate_keypair, verify_one
from vigil_integration import doctor as dmod
from vigil_integration.cli import _cmd_approve_sign
from vigil_integration.live.approval_broker import (
    approvals_root, find_signed_token, publish_pending,
)
from vigil_integration.live.approval_token import (
    ApprovalAction, action_digest, token_signing_bytes,
)


def _publish(base_dir):
    root = approvals_root(base_dir)
    dig = action_digest("sqlmap", "https://target.example", {"flag": "--dump"})
    action = ApprovalAction("sqlmap", "https://target.example", dig)
    req = publish_pending(root, action, nonce="nonce-abc-123",
                          args_preview={"flag": "--dump"}, now_iso="2026-01-01T00:00:00Z")
    return root, action, req


def _run_sign(base_dir, request_id, *, key_id="owner", ttl=300.0):
    args = types.SimpleNamespace(base_dir=str(base_dir), request_id=request_id, key_id=key_id, ttl=ttl)
    return _cmd_approve_sign(args)


# --------------------------------------------------------------------------- doctor reporting
def test_doctor_reports_the_active_owner_key_backend(monkeypatch):
    monkeypatch.delenv("VIGIL_OWNER_KEY_BACKEND", raising=False)
    state, detail = dmod._posture_owner_key_backend()
    assert state == "FILE" and "the default" in detail
    # NEGATIVE CONTROL — flip to hardware selected but unconfigured: the state flips to a fail-closed one.
    monkeypatch.setenv("VIGIL_OWNER_KEY_BACKEND", "pkcs11")
    monkeypatch.delenv("VIGIL_PKCS11_MODULE", raising=False)
    flipped, fdetail = dmod._posture_owner_key_backend()
    assert flipped == "PKCS11-UNCONFIGURED" and "FAILS CLOSED" in fdetail


def test_collect_posture_includes_the_owner_key_backend_control(tmp_path):
    controls = [p["control"] for p in dmod._collect_posture(tmp_path, {})]
    assert "owner-key-backend" in controls


# --------------------------------------------------------------------------- CLI signing entry point
def test_default_file_backend_still_signs_a_pending_approval(tmp_path, monkeypatch, capsys):
    kp = generate_keypair()
    monkeypatch.setenv("VIGIL_APPROVAL_OWNER_KEY", kp.private_key_b64)
    monkeypatch.delenv("VIGIL_OWNER_KEY_BACKEND", raising=False)
    root, action, req = _publish(tmp_path)

    rc = _run_sign(tmp_path, req.request_id)
    assert rc == 0
    out = capsys.readouterr().out
    assert "owner-key backend: file" in out

    signed = root / "signed" / f"{req.request_id}.json"
    assert signed.is_file()
    found = find_signed_token(root, action)
    assert found is not None
    token, _act = found
    # the file backend produced a genuine owner signature over the token bytes.
    assert verify_one(kp.public_key_b64, token_signing_bytes(token), token.signature_b64)


def test_hardware_selected_but_absent_refuses_to_sign_and_never_falls_back(tmp_path, monkeypatch, capsys):
    kp = generate_keypair()
    # A perfectly usable FILE key IS present — the fail-closed path must ignore it, not sign with it.
    monkeypatch.setenv("VIGIL_APPROVAL_OWNER_KEY", kp.private_key_b64)
    monkeypatch.setenv("VIGIL_OWNER_KEY_BACKEND", "pkcs11")
    # Module path points at a file that does not exist → the token can never be opened (deterministic
    # whether or not the pkcs11 binding is installed: the import or the lib load fails).
    monkeypatch.setenv("VIGIL_PKCS11_MODULE", str(tmp_path / "absent-provider.so"))
    root, _action, req = _publish(tmp_path)

    rc = _run_sign(tmp_path, req.request_id)
    assert rc == 2
    err = capsys.readouterr().err
    assert "hardware owner-key backend unavailable" in err
    # CRUCIAL: NO signed token was written. It did NOT fall back to the present file key.
    assert not (root / "signed" / f"{req.request_id}.json").exists()


def test_default_file_backend_with_no_key_reports_the_original_guidance(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VIGIL_APPROVAL_OWNER_KEY", raising=False)
    monkeypatch.delenv("VIGIL_OWNER_KEY_BACKEND", raising=False)
    _root, _action, req = _publish(tmp_path)
    rc = _run_sign(tmp_path, req.request_id)
    assert rc == 2
    assert "no owner signing key" in capsys.readouterr().err
    # sanity: the parsed JSON pending file is intact (we didn't corrupt state on the refuse path)
    pend = json.loads((approvals_root(tmp_path) / "pending" / f"{req.request_id}.json").read_text())
    assert pend["tool_name"] == "sqlmap"
