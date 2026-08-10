"""L3-parity hardening — the reviewer's adversarial battery for the offline audit package's PRIMARY-ARTIFACT
re-check (posture FACTs whose bytes travel in the package), plus trust-root policy validation, construction-
time invariants, and the high-water anti-rollback state.

Every attack MUST make ``verify_package`` return NOT SOUND (or make ``write_package`` REFUSE at construction):
a swapped / missing / empty / symlinked / traversed / orphaned primary artifact, a malformed trust-root
policy, a recheck certificate shipped with no artifact, and a corrupt high-water file.
"""
from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("cryptography")

from framework.v2.evidence.audit_offline_verifier import _validate_trust_root, verify_package
from framework.v2.evidence.audit_package import write_package
from framework.v2.evidence.chain import build_chain, sign_head
from framework.v2.evidence.certify import trust_root_fingerprint
from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot


def _mint_posture_fact():
    """A real signed posture FACT (kube-bench CIS) that opted into the gating artifact re-check, plus its raw
    artifact bytes — via the sovereign integration path (importorskip so the sovereign-only CI leg skips)."""
    pytest.importorskip("vigil_integration.live.k8s_posture", reason="integration package not importable here")
    from vigil_integration.live.k8s_posture import k8s_posture_verify
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    kb = json.dumps({"Controls": [{"tests": [{"section": "1.2", "results": [
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"}]}]}]})
    res = k8s_posture_verify(kb, engagement_slug="acme", signers=signers)
    assert res.n_facts == 1 and res.facts[0].signed.certificate.artifact_recheck_required
    return res, signers, tr


def _build_pkg(out, res, signers, tr, *, artifact_bytes_by_ref=None):
    f = res.facts[0]
    ctx = res.contexts[f.finding_ref]
    chain = build_chain([f.signed.certificate.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers)
    ab = artifact_bytes_by_ref if artifact_bytes_by_ref is not None else {f.finding_ref: res.artifact_bytes}
    write_package(out, certificates=[f.signed], chain=chain, head=head, contexts={f.finding_ref: ctx},
                  trust_root=tr, engagement_slug="acme", artifact_bytes_by_ref=ab)
    return f.finding_ref


def _fp(tr):
    return trust_root_fingerprint(tr)


def _art_rel(pkg):
    return next(iter(json.loads((pkg / "artifacts.json").read_text()).values()))


def test_correct_posture_package_verifies_offline(tmp_path):
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "ok"
    _build_pkg(pkg, res, signers, tr)
    sound, notes = verify_package(pkg, _fp(tr))
    assert sound, notes


def test_one_byte_primary_artifact_mutation_fails(tmp_path):
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "mut"
    _build_pkg(pkg, res, signers, tr)
    rel = _art_rel(pkg)
    ba = bytearray((pkg / rel).read_bytes())
    ba[len(ba) // 2] ^= 0x01
    (pkg / rel).write_bytes(bytes(ba))
    assert verify_package(pkg, _fp(tr))[0] is False


def test_missing_primary_artifact_fails_closed(tmp_path):
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "miss"
    _build_pkg(pkg, res, signers, tr)
    (pkg / _art_rel(pkg)).unlink()
    assert verify_package(pkg, _fp(tr))[0] is False


def test_orphaned_artifacts_index_entry_fails(tmp_path):
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "orph"
    _build_pkg(pkg, res, signers, tr)
    idx = json.loads((pkg / "artifacts.json").read_text())
    idx["ghost:finding:ref"] = "artifacts/ghost.bin"
    (pkg / "artifacts.json").write_text(json.dumps(idx))
    assert verify_package(pkg, _fp(tr))[0] is False


def test_empty_primary_artifact_fails(tmp_path):
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "empty"
    _build_pkg(pkg, res, signers, tr)
    (pkg / _art_rel(pkg)).write_bytes(b"")
    assert verify_package(pkg, _fp(tr))[0] is False


def test_symlinked_primary_artifact_is_rejected(tmp_path):
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "sym"
    _build_pkg(pkg, res, signers, tr)
    rel = _art_rel(pkg)
    tgt = pkg / rel
    tgt.unlink()
    outside = tmp_path / "secret.bin"
    outside.write_bytes(res.artifact_bytes)          # even pointing at the RIGHT bytes, a symlink is refused
    os.symlink(str(outside), str(tgt))
    assert verify_package(pkg, _fp(tr))[0] is False


def test_artifacts_index_path_traversal_is_confined(tmp_path):
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "trav"
    _build_pkg(pkg, res, signers, tr)
    idx = json.loads((pkg / "artifacts.json").read_text())
    k = next(iter(idx))
    idx[k] = "../../../../etc/passwd"
    (pkg / "artifacts.json").write_text(json.dumps(idx))
    assert verify_package(pkg, _fp(tr))[0] is False


def test_swapped_primary_artifacts_between_findings_fail(tmp_path):
    # two distinct posture FACTs; swap their artifact files → each recomputed digest != its bound digest.
    r1, signers, tr = _mint_posture_fact()
    from vigil_integration.live.k8s_posture import k8s_posture_verify
    kb2 = json.dumps({"Controls": [{"tests": [{"section": "1.3", "results": [
        {"test_number": "1.3.1", "status": "FAIL", "actual_value": "--insecure-port=8080"}]}]}]})
    r2 = k8s_posture_verify(kb2, engagement_slug="acme", signers=signers)
    f1, f2 = r1.facts[0], r2.facts[0]
    from framework.v2.evidence.chain import build_chain as _bc, sign_head as _sh
    chain = _bc([f1.signed.certificate.cert_digest, f2.signed.certificate.cert_digest])
    head = _sh(chain, engagement_slug="acme", signers=signers)
    pkg = tmp_path / "swap"
    write_package(pkg, certificates=[f1.signed, f2.signed], chain=chain, head=head,
                  contexts={f1.finding_ref: r1.contexts[f1.finding_ref],
                            f2.finding_ref: r2.contexts[f2.finding_ref]},
                  trust_root=tr, engagement_slug="acme",
                  artifact_bytes_by_ref={f1.finding_ref: r1.artifact_bytes, f2.finding_ref: r2.artifact_bytes})
    assert verify_package(pkg, _fp(tr))[0] is True                      # baseline sound
    idx = json.loads((pkg / "artifacts.json").read_text())
    p1, p2 = pkg / idx[f1.finding_ref], pkg / idx[f2.finding_ref]
    b1, b2 = p1.read_bytes(), p2.read_bytes()
    p1.write_bytes(b2)
    p2.write_bytes(b1)                                                  # swap
    assert verify_package(pkg, _fp(tr))[0] is False


def test_construction_refuses_recheck_cert_with_no_artifact_bytes(tmp_path):
    res, signers, tr = _mint_posture_fact()
    with pytest.raises(ValueError, match="require an artifact re-check"):
        _build_pkg(tmp_path / "nob", res, signers, tr, artifact_bytes_by_ref={})


def test_construction_refuses_non_empty_output_dir(tmp_path):
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "reuse"
    _build_pkg(pkg, res, signers, tr)
    with pytest.raises(ValueError, match="not empty"):
        _build_pkg(pkg, res, signers, tr)                              # second write into the same dir refused


# ---- trust-root policy validation (pure; runs in every leg) ----------------------------------------

@pytest.mark.parametrize("tr,valid", [
    ({"threshold": 1, "authorizers": [{"key_id": "a", "public_key_b64": "x"}]}, True),
    ({"threshold": 0, "authorizers": [{"key_id": "a", "public_key_b64": "x"}]}, False),   # zero threshold
    ({"threshold": 2, "authorizers": [{"key_id": "a", "public_key_b64": "x"}]}, False),   # thr > authorizers
    ({"threshold": 1, "authorizers": [{"key_id": "a", "public_key_b64": "x"},
                                      {"key_id": "a", "public_key_b64": "y"}]}, False),    # dup key_id
    ({"threshold": 1, "authorizers": []}, False),                                          # empty
    ({"threshold": True, "authorizers": [{"key_id": "a", "public_key_b64": "x"}]}, False),  # bool threshold
    ({"threshold": 1, "authorizers": [{"key_id": "a"}]}, False),                           # missing pubkey
    ("not-an-object", False),
])
def test_trust_root_policy_validation(tr, valid):
    assert (_validate_trust_root(tr) is None) is valid


def test_zero_threshold_trust_root_on_disk_makes_a_package_not_sound(tmp_path):
    # A package that verified under a valid policy is NOT SOUND once its shipped trust-root.json is degraded to
    # a zero threshold (which would otherwise satisfy `len(valid) >= 0` with no signature) — even matching the
    # pin, an INVALID policy must refuse.
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "zt"
    _build_pkg(pkg, res, signers, tr)
    assert verify_package(pkg, _fp(tr))[0] is True                     # baseline sound
    tr_on_disk = json.loads((pkg / "trust-root.json").read_text())
    tr_on_disk["threshold"] = 0
    (pkg / "trust-root.json").write_text(json.dumps(tr_on_disk))
    sound, notes = verify_package(pkg, None)                           # no pin: still must refuse (invalid policy)
    assert sound is False and any("INVALID trust-root policy" in n for n in notes)


# ---- high-water anti-rollback state (fail-closed on corrupt) ----------------------------------------

def test_highwater_absent_is_first_run_but_corrupt_refuses(tmp_path):
    from framework.v2.evidence.cli import _HighwaterCorrupt, _load_highwater, _save_highwater
    p = tmp_path / "hw.json"
    assert _load_highwater(p) is None                    # absent -> first run
    _save_highwater(p, 7)
    assert _load_highwater(p) == 7                        # valid -> enforced
    p.write_text("{not json")                            # corrupt
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(p)
    p.write_text(json.dumps({"last_seq": -3}))           # malformed value
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(p)


def test_highwater_symlink_is_refused(tmp_path):
    from framework.v2.evidence.cli import _HighwaterCorrupt, _load_highwater
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"last_seq": 5}))
    link = tmp_path / "hw.json"
    os.symlink(str(real), str(link))
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(link)


def test_highwater_dangling_symlink_is_refused_not_first_run(tmp_path):
    """RED-PEN (MEDIUM): a DANGLING symlink at the high-water path must REFUSE, not read as first-run — the
    is_symlink() guard must precede exists() (exists() follows the link and is False for a dangling one, which
    would silently disable anti-rollback)."""
    from framework.v2.evidence.cli import _HighwaterCorrupt, _load_highwater
    link = tmp_path / "hw.json"
    os.symlink(str(tmp_path / "does-not-exist.json"), str(link))
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(link)


def test_save_highwater_refuses_symlink_target(tmp_path):
    """RED-PEN (MEDIUM): _save_highwater must refuse a symlink at the high-water path (checked on the
    UN-resolved path) — it must never follow the link and overwrite the target."""
    from framework.v2.evidence.cli import _save_highwater
    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL")
    link = tmp_path / "hw.json"
    os.symlink(str(victim), str(link))
    with pytest.raises(ValueError, match="symlink"):
        _save_highwater(link, 42)
    assert victim.read_text() == "ORIGINAL"          # target untouched


def test_ctx_by_ref_refuses_duplicate_finding_ref():
    """RED-PEN (LOW): the pcf-export _ctx_by_ref must refuse a duplicate finding_ref (last-writer-wins would
    silently bind one certificate to another finding's context)."""
    from framework.v2.evidence.cli import _ctx_by_ref
    with pytest.raises(ValueError, match="duplicate finding_ref"):
        _ctx_by_ref({"active_findings": [
            {"check_id": "dup", "oracle_context": {"a": 1}},
            {"check_id": "dup", "oracle_context": {"b": 2}}]})


def test_default_reverifiable_carries_check_id_for_step2_cli(tmp_path):
    """RED-PEN (LOW): the default synthesized reverifiable.json must carry check_id == finding_ref so the
    documented step-2 `evidence verify` CLI (which derives its ref from check_id) matches a posture FACT's
    composite finding_ref — otherwise a package verify_offline.py reports SOUND is reported NOT SOUND by the CLI."""
    res, signers, tr = _mint_posture_fact()
    pkg = tmp_path / "rv"
    ref = _build_pkg(pkg, res, signers, tr)
    rv = json.loads((pkg / "reverifiable.json").read_text())
    entries = rv["active_findings"]
    assert entries and all(e.get("check_id") == e.get("finding_ref") for e in entries)
    assert any(e["check_id"] == ref for e in entries)
