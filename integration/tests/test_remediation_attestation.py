"""W5 — the Proof-Carrying REMEDIATION Attestation: mint (fail-closed) + verify (demote-only, re-executing).

(Distinct from test_attestation.py, which covers the WS6 usage-attestation ledger.) The pure
crypto/binding/tier tests are framework-free (both CI legs); the OFFLINE VULN-GONE re-run needs the DAA
analyzers, so it importorskips framework and runs in the offense leg.
"""
from __future__ import annotations

import shutil

import pytest

from vigil_core import generate_keypair
from vigil_core.signed_build_manifest import digest_tree

from vigil_integration.remediation.attestation import (
    mint_remediation_attestation, verify_remediation_attestation, AttestationError,
    TIER_FULLY_SOUND, TIER_VULN_ONLY, TIER_UNVERIFIED, TIER_FAIL,
)

_BASE = dict(finding_ref="DAA-X~abc~L5", bug_class="Weak Cryptography", target="svc/config.py:5",
             oracle_kind="daa:DAA-X", rule_id="DAA-X", base_tree_digest="sha256:aaa",
             patched_tree_digest="sha256:bbb", diff_digest="sha256:ddd")


def _kp():
    k = generate_keypair()
    return k.public_key_b64, k.private_key_b64


# ---------- mint: fail-closed ----------
def test_mint_refuses_when_vuln_not_gone():
    _, priv = _kp()
    with pytest.raises(AttestationError, match="VULN-GONE"):
        mint_remediation_attestation(**_BASE, vuln_gone=False, signers=[("k1", priv)])


def test_mint_refuses_established_behavior_without_a_passing_suite():
    _, priv = _kp()
    with pytest.raises(AttestationError, match="BEHAVIOR-PRESERVED"):
        mint_remediation_attestation(**_BASE, vuln_gone=True, behavior_established=True,
                                     suite_ran=True, tests_passed=False, signers=[("k1", priv)])


def test_mint_refuses_unsigned():
    with pytest.raises(AttestationError, match="UNSIGNED"):
        mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[])


# ---------- verify: authenticity + tamper ----------
def test_round_trip_authentic_but_unverified_without_a_tree():
    pub, priv = _kp()
    att = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", priv)])
    v = verify_remediation_attestation(att, trust_root_pubkeys={"k1": pub})
    assert v.ok and v.authentic and v.tier == TIER_UNVERIFIED and v.signer_count == 1


def test_wrong_key_is_not_authentic():
    _, priv = _kp()
    other_pub, _ = _kp()
    att = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", priv)])
    v = verify_remediation_attestation(att, trust_root_pubkeys={"k1": other_pub})
    assert not v.ok and v.tier == TIER_FAIL


def test_tampering_with_the_binding_breaks_the_signature():
    pub, priv = _kp()
    att = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", priv)])
    att["binding"]["patched_tree_digest"] = "sha256:evil"
    assert not verify_remediation_attestation(att, trust_root_pubkeys={"k1": pub}).ok


def test_stripping_a_signed_field_is_caught():
    pub, priv = _kp()
    att = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", priv)])
    del att["vuln_gone"]["oracle_kind"]
    assert not verify_remediation_attestation(att, trust_root_pubkeys={"k1": pub}).ok


# ---------- m-of-n ----------
def test_m_of_n_threshold():
    (p1, s1), (p2, s2), (p3, _s3) = _kp(), _kp(), _kp()
    att = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", s1), ("k2", s2)])
    root = {"k1": p1, "k2": p2, "k3": p3}
    assert verify_remediation_attestation(att, trust_root_pubkeys=root, threshold=2).authentic
    assert not verify_remediation_attestation(att, trust_root_pubkeys=root, threshold=3).ok
    assert verify_remediation_attestation(att, trust_root_pubkeys={"k1": p1}, threshold=2).ok is False


# ---------- behavior tiers ----------
def test_behavior_axis_recorded_honestly():
    _, priv = _kp()
    est = mint_remediation_attestation(**_BASE, vuln_gone=True, behavior_established=True, suite_ran=True,
                                       tests_passed=True, test_cmd="python -m pytest -q",
                                       deps_digest="sha256:deps", signers=[("k1", priv)])
    assert est["behavior_preserved"]["state"] == "established" and est["behavior_preserved"]["tests_passed"] is True
    noe = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", priv)])
    assert noe["behavior_preserved"]["state"] == "not-established" and noe["behavior_preserved"]["tests_passed"] is None


# ---------- OFFLINE VULN-GONE re-run (framework: DAA) ----------
def test_offline_vuln_gone_rerun_catches_a_false_attestation(tmp_path):
    pytest.importorskip("framework")
    if not shutil.which("git"):
        pytest.skip("needs git")
    from vigil_integration import codescan
    repo = tmp_path / "repo"; (repo / "svc").mkdir(parents=True)
    vuln = "import hashlib\n\n\ndef fp(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
    (repo / "svc" / "config.py").write_text(vuln, encoding="utf-8")
    base = tmp_path / "base"; base.mkdir()
    rep = codescan.run_codescan(root=str(repo), slug="s", base_dir=str(base))
    hf = [f for f in rep["findings"] if "WEAK-HASH" in f["ref"] or "md5" in f.get("evidence", "").lower()]
    if not hf:
        pytest.skip("DAA did not flag md5 here")
    ref = hf[0]["ref"]
    pub, priv = _kp()

    patched = tmp_path / "patched"; (patched / "svc").mkdir(parents=True)
    (patched / "svc" / "config.py").write_text(vuln.replace("md5", "sha256"), encoding="utf-8")
    pdig, _ = digest_tree(str(patched))
    good = mint_remediation_attestation(
        finding_ref=ref, bug_class="Weak Cryptography", target="svc/config.py:5",
        oracle_kind="daa:DAA-WEAK-HASH", rule_id="DAA-WEAK-HASH",
        base_tree_digest="sha256:base", patched_tree_digest=pdig, diff_digest="sha256:d",
        vuln_gone=True, signers=[("k1", priv)])
    v = verify_remediation_attestation(good, trust_root_pubkeys={"k1": pub}, patched_root=str(patched))
    assert v.ok and v.vuln_gone_reverified is True and v.bound is True and v.tier == TIER_VULN_ONLY

    unpatched = tmp_path / "unpatched"; (unpatched / "svc").mkdir(parents=True)
    (unpatched / "svc" / "config.py").write_text(vuln, encoding="utf-8")   # md5 still present
    udig, _ = digest_tree(str(unpatched))
    liar = mint_remediation_attestation(
        finding_ref=ref, bug_class="Weak Cryptography", target="svc/config.py:5",
        oracle_kind="daa:DAA-WEAK-HASH", rule_id="DAA-WEAK-HASH",
        base_tree_digest="sha256:base", patched_tree_digest=udig, diff_digest="sha256:d",
        vuln_gone=True, signers=[("k1", priv)])
    v2 = verify_remediation_attestation(liar, trust_root_pubkeys={"k1": pub}, patched_root=str(unpatched))
    assert not v2.ok and v2.tier == TIER_FAIL and v2.vuln_gone_reverified is False


def test_cli_verify_remediation_verb(tmp_path):
    pytest.importorskip("framework")
    import json, types
    from vigil_integration import cli
    pub, priv = _kp()
    att = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", priv)])
    ap = tmp_path / "att.json"; ap.write_text(json.dumps(att), encoding="utf-8")
    tr = tmp_path / "tr.json"; tr.write_text(json.dumps({"k1": pub}), encoding="utf-8")
    ns = types.SimpleNamespace(attestation=str(ap), trust_root=str(tr), threshold=1, patched_root="", dep_cache="")
    assert cli._cmd_verify_remediation(ns) == 3   # authentic but signature-only (no --patched-root) → NOT exit 0
    att["binding"]["diff_digest"] = "sha256:tampered"; ap.write_text(json.dumps(att), encoding="utf-8")
    assert cli._cmd_verify_remediation(ns) == 1
    ns2 = types.SimpleNamespace(attestation=str(ap), trust_root=str(tmp_path / "nope.json"),
                                threshold=1, patched_root="", dep_cache="")
    assert cli._cmd_verify_remediation(ns2) == 2


# ---------- hardening (crypto-notary follow-ups) ----------
def test_malformed_signatures_shapes_never_crash():
    pub, priv = _kp()
    att = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", priv)])
    for bad in ("a-string", 123, {"not": "a list"}, [None], [123], ["str"], [{"key_id": 1}]):
        att2 = dict(att); att2["signatures"] = bad
        v = verify_remediation_attestation(att2, trust_root_pubkeys={"k1": pub})   # must NOT raise
        assert not v.ok and v.tier == TIER_FAIL


def test_same_pubkey_under_two_ids_cannot_satisfy_threshold_two():
    pub, priv = _kp()
    # enrol ONE physical key under two key_ids and sign twice with it
    att = mint_remediation_attestation(**_BASE, vuln_gone=True, signers=[("k1", priv), ("k2", priv)])
    v = verify_remediation_attestation(att, trust_root_pubkeys={"k1": pub, "k2": pub}, threshold=2)
    assert not v.ok and v.signer_count == 1   # one physical key = one signer, cannot meet 2-of-n


# ---------- W5b: the engine MINTS the attestation on a verified fix (end-to-end) ----------
def test_cli_mints_attestation_on_verified_fix(tmp_path):
    pytest.importorskip("framework")   # codescan (DAA) for a real finding ref
    import json as _json, os, shutil, subprocess, types
    if not shutil.which("git"):
        pytest.skip("needs git")
    from vigil_integration import cli, codescan

    def _git(*a, cwd):
        subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)

    repo = tmp_path / "repo"; (repo / "svc").mkdir(parents=True)
    (repo / "svc" / "config.py").write_text(
        "import hashlib\n\n\ndef fp(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n", encoding="utf-8")
    _git("init", "-q", cwd=repo); _git("add", "-A", cwd=repo)
    _git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i", cwd=repo)
    # a real, git-generated diff md5 -> sha256, then revert so the repo still has the vuln
    (repo / "svc" / "config.py").write_text(
        "import hashlib\n\n\ndef fp(pw):\n    return hashlib.sha256(pw.encode()).hexdigest()\n", encoding="utf-8")
    diff = subprocess.run(["git", "diff"], cwd=repo, capture_output=True, text=True).stdout
    _git("checkout", "--", ".", cwd=repo)
    assert "sha256" in diff and diff.strip()

    base = tmp_path / "base"; base.mkdir()
    rep = codescan.run_codescan(root=str(repo), slug="s", base_dir=str(base))
    ref = next((f["ref"] for f in rep["findings"] if "WEAK-HASH" in f["ref"]), None)
    if not ref:
        pytest.skip("DAA did not flag md5 here")

    kp = generate_keypair()
    keyf = tmp_path / "k.b64"; keyf.write_text(kp.private_key_b64, encoding="ascii")
    result = types.SimpleNamespace(status="verified-no-pr", applied_diff=diff, suite_ran=False, tests_passed=None)
    finding = types.SimpleNamespace(target_repo=str(repo), ref=ref, bug_class="Weak Cryptography",
                                    target="svc/config.py:5", evidence_ref="sha256:demo")
    args = types.SimpleNamespace(attest=True, attest_key=str(keyf), attest_key_id="k1", dep_cache="",
                                 from_spine="s", repo_base_dir=str(base))
    plan = types.SimpleNamespace(test_cmd="python -m pytest -q")

    note = cli._mint_deep_fix_attestation(result, finding, args, plan)
    assert note and note.startswith("attestation MINTED"), note
    attp = base / f"s-{__import__('re').sub(r'[^A-Za-z0-9._-]', '_', ref)[:80]}.attestation.json"
    assert attp.is_file()
    att = _json.loads(attp.read_text(encoding="utf-8"))

    # re-verify OFFLINE against an independently-patched tree: digest must bind + the DAA rule must clear
    from vigil_integration.remediation.attestation import verify_remediation_attestation, TIER_VULN_ONLY
    patched = tmp_path / "patched"; shutil.copytree(repo, patched, ignore=shutil.ignore_patterns(".git"))
    (patched / "fix.patch").write_text(diff if diff.endswith("\n") else diff + "\n", encoding="utf-8")
    subprocess.run(["git", "apply", "fix.patch"], cwd=patched, check=True, capture_output=True)
    (patched / "fix.patch").unlink()
    v = verify_remediation_attestation(att, trust_root_pubkeys={"k1": kp.public_key_b64}, patched_root=str(patched))
    assert v.ok and v.vuln_gone_reverified is True and v.bound is True and v.tier == TIER_VULN_ONLY

    # no key => honest SKIP, never a silent unsigned mint
    args.attest_key = ""
    assert "SKIPPED" in (cli._mint_deep_fix_attestation(result, finding, args, plan) or "")
