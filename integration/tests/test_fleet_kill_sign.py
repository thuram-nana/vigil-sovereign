"""WS3 — the framework-dependent CLI verbs of the fleet kill-switch: ``vigil fleet kill`` (the destructive
fan-out verb ``cli._cmd_fleet_kill``) and ``vigil sign-revocation`` (the owner signing ceremony
``cli._cmd_sign_revocation``).

Both CLI handlers lazy-import ``framework.v2.entitlement.*`` (function-local — correct for FATAL-2, so the
two-env boundary holds at module scope). That means these tests can only EXECUTE where ``framework`` is on the
path: the OFFENSE leg. The module-level ``importorskip`` below therefore skips them cleanly in the keyless
sovereign (P5) leg, exactly as :mod:`test_credential_acceptance_arm` does — a framework test must never ERROR
there with ``ModuleNotFoundError``.

The read-only aggregator (``fold_roster`` / ``fan_out_kill``) and the ``vigil fleet status`` CLI tests need NO
framework and STAY in :mod:`test_fleet_monitor` so they keep running keyless, proving ``fleet_monitor`` is
keyless-safe. Each test here carries its own positive AND safe-negative controls, unchanged from when they
lived in :mod:`test_fleet_monitor`.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2")  # offense-leg only; skips cleanly in the keyless two-env leg

from vigil_integration import cli  # noqa: E402
from vigil_integration import fleet_monitor as fm  # noqa: E402


# --------------------------------------------------------------------------------------------------
# (d3) the fleet KILL CLI verb — refuses without --yes, and hands the driver a REAL SignedRevocation
# --------------------------------------------------------------------------------------------------


def test_cmd_fleet_kill_refuses_without_yes(tmp_path, monkeypatch):
    """The CLI kill verb must refuse a fleet-wide hard-stop without --yes, and must NOT reach the driver."""
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps({"instances": [{"instance_id": "vm-a", "base_dir": "/home/a"}]}),
                      encoding="utf-8")

    def _must_not_run(*a, **k):
        raise AssertionError("fan_out_kill must not run without --yes")

    monkeypatch.setattr(fm, "fan_out_kill", _must_not_run)
    rc = cli._cmd_fleet_kill(SimpleNamespace(roster=str(roster), revocation="", reason="", yes=False))
    assert rc == 2


def test_cmd_fleet_kill_passes_a_loaded_signed_revocation(tmp_path, monkeypatch):
    """With --yes + a valid --revocation the CLI loads the SignedRevocation and hands it to the driver;
    the driver itself is stubbed so NO real run_panic / systemctl is touched by the test."""
    from framework.v2.entitlement import provision
    from framework.v2.entitlement.models import RevocationDocument
    from datetime import datetime, timezone

    _, priv = provision.new_authorizer("k1", "Owner One")
    doc = RevocationDocument(serial=1, issued_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
                             revoked_entitlement_ids=["ent-123"])
    signed = provision.sign_revocation(doc, {"k1": priv})
    rev_path = tmp_path / "revocation.json"
    rev_path.write_text(json.dumps(signed.model_dump(mode="json")), encoding="utf-8")
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps({"instances": [{"instance_id": "vm-a", "base_dir": "/home/a",
                                                  "revocation_path": str(tmp_path / "out-rev.json")}]}),
                      encoding="utf-8")

    seen = {}

    def _capture(roster_arg, *, signed_revocation, reason, **k):
        seen["sig"] = signed_revocation
        seen["n"] = len(list(roster_arg))
        return {"totals": {"instances": 1, "panic_ok": 1, "revoke_ok": 1, "revoke_refused": 0,
                           "revoke_error": 0}, "reason": reason, "revocation_supplied": True,
                "instances": [{"instance_id": "vm-a", "panic": {"status": "contained", "ok": True},
                               "revoke": {"status": "applied", "ok": True}}]}

    monkeypatch.setattr(fm, "fan_out_kill", _capture)
    rc = cli._cmd_fleet_kill(SimpleNamespace(roster=str(roster), revocation=str(rev_path),
                                             reason="drill", yes=True))
    assert rc == 0
    # the CLI handed the driver a REAL SignedRevocation parsed from disk (not None, not a raw string)
    assert seen["sig"].document.serial == 1
    assert seen["sig"].document.revoked_entitlement_ids == ["ent-123"]
    assert seen["n"] == 1


# --------------------------------------------------------------------------------------------------
# sign-revocation CLI verb wires the real sign_revocation library (owner ceremony, m-of-n unchanged)
# --------------------------------------------------------------------------------------------------


def test_cmd_sign_revocation_mints_a_verifiable_signed_list(tmp_path, capsys):
    """Positive: the verb signs with the real library and the output verifies against the authoriser's
    PUBLIC key — proving a genuine Ed25519 signature, not a stubbed blob."""
    from framework.v2.entitlement import provision
    from framework.v2.entitlement.canonical import revocation_signing_bytes
    from framework.v2.entitlement.crypto import verify_one as crypto_verify
    from framework.v2.entitlement.models import SignedRevocation

    pub, priv = provision.new_authorizer("owner-key-1", "Owner One")
    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({"owner-key-1": priv}), encoding="utf-8")
    out = tmp_path / "revocation.json"

    rc = cli._cmd_sign_revocation(SimpleNamespace(
        revoke=["ent-aaa", "ent-bbb"], serial=7, signers=str(signers),
        issued_at="2024-01-01T00:00:00+00:00", out=str(out)))
    assert rc == 0
    assert "serial=7" in capsys.readouterr().out

    signed = SignedRevocation.model_validate_json(out.read_text(encoding="utf-8"))
    assert signed.document.serial == 7
    assert signed.document.revoked_entitlement_ids == ["ent-aaa", "ent-bbb"]
    # the signature is REAL: it verifies against the authoriser public key over the canonical bytes
    msg = revocation_signing_bytes(signed.document)
    assert crypto_verify(pub.public_key_b64, msg, signed.signatures[0].signature_b64) is True


def test_cmd_sign_revocation_refuses_an_empty_signer_bundle(tmp_path, capsys):
    """Safe-negative: no signer keys ⇒ no signature (refuse with exit 2), never an unsigned 'revocation'."""
    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({}), encoding="utf-8")
    rc = cli._cmd_sign_revocation(SimpleNamespace(
        revoke=["ent-x"], serial=1, signers=str(signers), issued_at="", out=str(tmp_path / "r.json")))
    assert rc == 2
    assert not (tmp_path / "r.json").exists()
    assert "non-empty" in capsys.readouterr().err


def test_cmd_sign_revocation_warns_below_threshold(tmp_path, capsys, monkeypatch):
    """The advisory note fires when fewer than the trust root threshold sign — but the runtime, not this
    verb, is the authority: it still produces the (insufficient) signed document and warns."""
    from framework.v2.entitlement import provision

    # a 2-of-2 trust root, signed by only ONE authoriser
    a_pub, a_priv = provision.new_authorizer("a", "A")
    b_pub, _ = provision.new_authorizer("b", "B")
    tr = provision.build_trust_root([a_pub, b_pub], threshold=2)
    provision.write_trust_root(tr)                       # under CRUCIBLE_ROOT scratch (hermetic env)

    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({"a": a_priv}), encoding="utf-8")
    rc = cli._cmd_sign_revocation(SimpleNamespace(
        revoke=["ent-x"], serial=2, signers=str(signers),
        issued_at="2024-01-01T00:00:00+00:00", out=str(tmp_path / "r.json")))
    assert rc == 0
    out = capsys.readouterr().out
    assert "BELOW the trust root threshold" in out and "1 signer(s)" in out
