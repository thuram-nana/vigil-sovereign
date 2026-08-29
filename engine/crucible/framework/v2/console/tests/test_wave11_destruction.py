"""Wave 11 (parity, SAFE orchestration console) — read-only PUBLIC m-of-n destruction quorum status. The
trust root is PUBLIC (signer public keys + a threshold; no secrets), so NO private key material can cross;
the key-minting (`provision-destruction` prints PRIVATE keys), per-host `enroll-cosigner`, `authorize-
destruction`, and the actual `patch --open-pr` fire all stay CLI/host-driven. This pins: not-provisioned is
honest, only PUBLIC shape crosses (no private field, not even a full public key), and the route is owner-only."""
from __future__ import annotations

import json

from framework.v2.console import actions


def test_not_provisioned_is_honest(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "_strix_runtime_base_dir", lambda: str(tmp_path))
    r = actions.run_destruction_status()
    assert r["ok"] is True and r["provisioned"] is False and "provision-destruction" in r["detail"]


def test_reads_public_shape_only_and_ignores_injected_secrets(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "_strix_runtime_base_dir", lambda: str(tmp_path))
    # a HOSTILE trust root: a maliciously-crafted file with injected top-level + per-signer SECRET fields must
    # be IGNORED — the status must whitelist only the public shape, never echo an injected secret.
    (tmp_path / "destruction-trust-root.json").write_text(json.dumps({
        "threshold": 2,
        "private_key": "TOPLEVEL_SECRET_MUST_NOT_CROSS",
        "authorizers": [
            {"key_id": "owner", "public_key_b64": "AAAAPUBLICOWNERKEY_LONG", "private_key_b64": "OWNER_PRIV_MUST_NOT_CROSS"},
            {"key_id": "worker1", "public_key_b64": "BBBBPUBLICWORKER1_LONG", "seed": "WORKER_SEED_MUST_NOT_CROSS"},
        ],
    }), encoding="utf-8")
    r = actions.run_destruction_status()
    assert r["ok"] is True and r["provisioned"] is True
    assert r["threshold"] == 2 and r["signers"] == 2 and set(r["signer_ids"]) == {"owner", "worker1"}
    blob = json.dumps(r)
    assert "private" not in blob.lower()                          # never a private field name
    for secret in ("TOPLEVEL_SECRET_MUST_NOT_CROSS", "OWNER_PRIV_MUST_NOT_CROSS", "WORKER_SEED_MUST_NOT_CROSS"):
        assert secret not in blob                                # no injected secret crosses
    # only a SHORT (<=12-char) fingerprint of the public key crosses — a 13-char prefix (i.e. any widening
    # of the surfaced key) must NOT be present, closing the partial-widening blind spot.
    assert "AAAAPUBLICOWN" not in blob and "AAAAPUBLICOWNERKEY_LONG" not in blob


def test_unreadable_trust_root_fails_safe(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "_strix_runtime_base_dir", lambda: str(tmp_path))
    (tmp_path / "destruction-trust-root.json").write_text("{ not json", encoding="utf-8")
    r = actions.run_destruction_status()
    assert r["ok"] is False and r["provisioned"] is True and "unreadable" in r["error"]


def test_route_is_owner_only():
    from vigil_core.rbac import offense_perm_for
    assert offense_perm_for("/api/destruction/status") == "offense_authority"
