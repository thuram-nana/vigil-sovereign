"""PR-B — provisioning + signing the m-of-n destruction quorum for `vigil patch --open-pr`.

Proves the ceremony end-to-end at the crypto layer: `vigil provision-destruction` mints keys + a trust root,
`vigil authorize-destruction` signs ONE action with the owner (+ co-signers), and the resulting authorization
is ACCEPTED by the same quorum `vigil patch` builds — for the matching action, above threshold, once. And it
is REFUSED on every axis: below threshold, a mismatched action, a replay, a blank nonce, an over-long window.
The owner signing key is read from the ENV (never argv); co-signer keys from files.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from vigil_integration.live.codefix_runner import build_destruction_quorum, file_backed_quorum
from vigil_integration.live.destruction_provision import (
    default_paths,
    fresh_nonce,
    generate_authority,
    load_worker_key_file,
    sign_action,
    write_trust_root,
)
from vigil_integration.live.trusted_finding import (
    load_destruction_authority,
    load_signed_authorization,
)


def _req(remediation_id="ap-x", target="/repo"):
    class _R:
        pass
    r = _R()
    r.remediation_id = remediation_id
    r.target_repo = target
    r.finding = None
    return r


def _authority(tmp_path, gen):
    trp = write_trust_root(str(tmp_path), gen.trust_root_json)
    return load_destruction_authority(trust_root_path=trp, mandatory_signer_ids=list(gen.mandatory_signer_ids))


def _write_signed(tmp_path, doc, name="signed.json"):
    p = tmp_path / name
    p.write_text(doc, encoding="utf-8")
    return str(p)


# --- generate_authority ---------------------------------------------------------------------------

def test_generate_authority_shape_and_threshold_validation():
    gen = generate_authority(threshold=2, worker_count=1)
    assert gen.threshold == 2 and len(gen.private_keys) == 2
    ids = [kid for kid, _ in gen.private_keys]
    assert ids[0] == "owner" and gen.mandatory_signer_ids == ("owner",)
    with pytest.raises(ValueError):                 # threshold > n
        generate_authority(threshold=3, worker_count=1)
    with pytest.raises(ValueError):                 # threshold < 1
        generate_authority(threshold=0)


# --- the ceremony authorizes (and only for the right action / quorum / once) -----------------------

def test_signed_action_authorizes_for_matching_action(tmp_path):
    gen = generate_authority(threshold=2, worker_count=1)
    authority = _authority(tmp_path, gen)
    doc = sign_action(action_id="pr-ap-x", engagement_slug="acme", target="/repo",
                      signer_private_keys=list(gen.private_keys), now=time.time(), nonce=fresh_nonce())
    signed = load_signed_authorization(_write_signed(tmp_path, doc))
    q = build_destruction_quorum(authority=authority, signed=signed, slug="acme",
                                 is_consumed=lambda n: False)
    assert q(_req()).approved is True               # owner + worker = 2-of-2, mandatory owner, action matches


def test_below_threshold_refused(tmp_path):
    gen = generate_authority(threshold=2, worker_count=1)
    authority = _authority(tmp_path, gen)
    owner_only = [gen.private_keys[0]]               # 1-of-2
    doc = sign_action(action_id="pr-ap-x", engagement_slug="acme", target="/repo",
                      signer_private_keys=owner_only, now=time.time(), nonce=fresh_nonce())
    signed = load_signed_authorization(_write_signed(tmp_path, doc))
    q = build_destruction_quorum(authority=authority, signed=signed, slug="acme", is_consumed=lambda n: False)
    assert q(_req()).approved is False


def test_mismatched_action_refused(tmp_path):
    gen = generate_authority(threshold=1)
    authority = _authority(tmp_path, gen)
    doc = sign_action(action_id="pr-ap-OTHER", engagement_slug="acme", target="/repo",
                      signer_private_keys=list(gen.private_keys), now=time.time(), nonce=fresh_nonce())
    signed = load_signed_authorization(_write_signed(tmp_path, doc))
    q = build_destruction_quorum(authority=authority, signed=signed, slug="acme", is_consumed=lambda n: False)
    assert q(_req(remediation_id="ap-x")).approved is False   # request action_id 'pr-ap-x' != signed 'pr-ap-OTHER'


def test_solo_owner_authorizes_and_replay_is_denied(tmp_path):
    gen = generate_authority(threshold=1)            # solo owner
    authority = _authority(tmp_path, gen)
    doc = sign_action(action_id="pr-ap-x", engagement_slug="acme", target="/repo",
                      signer_private_keys=list(gen.private_keys), now=time.time(), nonce=fresh_nonce())
    sp = _write_signed(tmp_path, doc)
    ledger = str(tmp_path / "nonces")
    signed = load_signed_authorization(sp)
    first = file_backed_quorum(authority=authority, signed=signed, slug="acme", ledger_path=ledger)(_req())
    assert first.approved is True
    replay = file_backed_quorum(authority=authority, signed=load_signed_authorization(sp),
                                slug="acme", ledger_path=ledger)(_req())
    assert replay.approved is False                  # single-use: same authorization can't drive a 2nd PR


def test_window_over_900s_refused(tmp_path):
    gen = generate_authority(threshold=1)
    with pytest.raises(ValueError):                  # dead-man's-switch: total window must be <= 900s
        sign_action(action_id="pr-ap-x", engagement_slug="acme", target="/repo",
                    signer_private_keys=list(gen.private_keys), now=time.time(), window_s=1000.0,
                    nonce=fresh_nonce())


def test_blank_nonce_and_missing_fields_refused(tmp_path):
    gen = generate_authority(threshold=1)
    with pytest.raises(ValueError):
        sign_action(action_id="pr-ap-x", engagement_slug="acme", target="/repo",
                    signer_private_keys=list(gen.private_keys), now=time.time(), nonce="")
    with pytest.raises(ValueError):
        sign_action(action_id="", engagement_slug="acme", target="/repo",
                    signer_private_keys=list(gen.private_keys), now=time.time(), nonce=fresh_nonce())


def test_worker_key_file_parsing(tmp_path):
    kf = tmp_path / "w1.key"
    kf.write_text("PRIVKEYB64\n", encoding="utf-8")
    kid, priv = load_worker_key_file(f"worker1={kf}")
    assert kid == "worker1" and priv == "PRIVKEYB64"
    with pytest.raises(ValueError):
        load_worker_key_file("noequals")
    with pytest.raises(ValueError):
        load_worker_key_file(f"worker1={tmp_path / 'missing.key'}")


# --- the CLI verbs --------------------------------------------------------------------------------

def test_cli_provision_writes_trust_root_and_prints_owner_key(tmp_path, capsys):
    from vigil_integration.cli import main
    rc = main(["provision-destruction", "--base-dir", str(tmp_path), "--threshold", "1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert Path(default_paths(str(tmp_path))["trust_root"]).exists()
    assert "VIGIL_DESTRUCTION_OWNER_KEY" in out and "[owner]" in out
    assert "threshold=1 (solo)" in out or "threshold" in out


def test_cli_authorize_needs_owner_key_env(tmp_path, capsys, monkeypatch):
    from vigil_integration.cli import main
    monkeypatch.delenv("VIGIL_DESTRUCTION_OWNER_KEY", raising=False)
    rc = main(["authorize-destruction", "--action-id", "pr-ap-x", "--slug", "acme", "--target", "/repo",
               "--base-dir", str(tmp_path)])
    assert rc == 2 and "no owner signing key" in capsys.readouterr().err


def test_cli_full_ceremony_authorizes_via_patch_quorum(tmp_path, monkeypatch):
    # provision → set the owner key env (as pasting into Settings would) → authorize → the quorum vigil patch
    # builds AUTHORIZES the matching action. Proves the CLI ceremony wires end-to-end.
    from vigil_integration.cli import main
    from vigil_integration.live.destruction_provision import _read_trust_root_ids

    gen = generate_authority(threshold=1)
    # write the same trust root the CLI would, and use the CLI to authorize with this owner key
    write_trust_root(str(tmp_path), gen.trust_root_json)
    owner_priv = dict(gen.private_keys)["owner"]
    monkeypatch.setenv("VIGIL_DESTRUCTION_OWNER_KEY", owner_priv)
    rc = main(["authorize-destruction", "--action-id", "pr-ap-x", "--slug", "acme", "--target", "/repo",
               "--base-dir", str(tmp_path)])
    assert rc == 0
    signed_path = default_paths(str(tmp_path))["signed"]
    assert Path(signed_path).exists()
    assert oct(Path(signed_path).stat().st_mode)[-3:] == "600"      # single-use auth is owner-only

    authority = load_destruction_authority(
        trust_root_path=default_paths(str(tmp_path))["trust_root"], mandatory_signer_ids=["owner"])
    signed = load_signed_authorization(signed_path)
    q = build_destruction_quorum(authority=authority, signed=signed, slug="acme", is_consumed=lambda n: False)
    assert q(_req()).approved is True
    assert _read_trust_root_ids(gen.trust_root_json) is not None


def test_provision_boundary_clean():
    import sys
    import vigil_integration.live.destruction_provision  # noqa: F401
    bad = sorted(m for m in sys.modules if m.split(".")[0] in ("framework", "strix", "sigil"))
    assert bad == []
