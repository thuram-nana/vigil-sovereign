"""LAP-3b(2) — `vigil patch` admits a finding ONLY from a cryptographically-grounded source (a signed inert
envelope verified under an OWNER delegation, or the engagement's OWN signed spine), NEVER raw JSON. These
tests prove each sound source builds a CONFIRMED finding on success and REFUSES fail-closed on every forgery
axis (wrong owner, tampered cert, out-of-scope, expired, below-threshold, tampered spine), that a verified
finding drives the real gated ladder, and that the CLI verb refuses a raw/absent/ambiguous source.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest

from vigil_core import AuthorizerKey, TrustRoot, evidence_signing_bytes, generate_keypair, sign
from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, sign_delegation

from vigil_integration.inert_finding import build_envelope
from vigil_integration.live.trusted_finding import (
    TrustedFindingError,
    finding_from_envelope,
    finding_from_spine,
    load_destruction_authority,
    load_signed_authorization,
)


# --- helpers --------------------------------------------------------------------------------------

def _cert(slug="acme", **over) -> dict:
    base = {"schema_version": 1, "engagement_slug": slug, "finding_ref": "sqli-001",
            "bug_class": "sqli", "title": "auth bypass", "severity": "critical",
            "target": "app.py:2", "oracle_context_digest": "a" * 64, "confidence": 0.9}
    base.update(over)
    return base


def _governance(n=2, threshold=2):
    keys = [generate_keypair() for _ in range(n)]
    authorizers = [AuthorizerKey(key_id=f"gov{i}", name=f"gov{i}", public_key_b64=k.public_key_b64)
                   for i, k in enumerate(keys)]
    return keys, authorizers, TrustRoot(threshold=threshold, authorizers=authorizers)


def _envelope(cert: dict, keys, authorizers) -> str:
    msg = evidence_signing_bytes(cert)
    sigs = [{"key_id": a.key_id, "signature_b64": sign(k.private_key_b64, msg)}
            for a, k in zip(authorizers, keys)]
    return build_envelope(cert, sigs)


def _delegation(owner, authorizers, *, threshold=2, scope="acme", not_after=None):
    return sign_delegation(owner, role=OFFENSE_GOVERNANCE_ROLE, scope=scope, authorizers=authorizers,
                           threshold=threshold,
                           not_after=int(not_after if not_after is not None else time.time() + 3600))


def _write(tmp_path, name, content) -> str:
    p = tmp_path / name
    p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return str(p)


def _env_and_deleg(tmp_path, *, owner, keys, auths, cert=None, deleg_scope="acme", not_after=None):
    ep = _write(tmp_path, "env.json", _envelope(cert or _cert(), keys, auths))
    dp = _write(tmp_path, "deleg.json",
                _delegation(owner, auths, scope=deleg_scope, not_after=not_after).model_dump_json())
    return ep, dp


# --- Option C: signed inert envelope (owner-delegated m-of-n governance) ---------------------------

def test_envelope_happy_path_builds_confirmed_finding(tmp_path):
    owner = generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths)
    tf = finding_from_envelope(envelope_path=ep, owner_pubkey=owner.public_key_b64,
                               delegation_path=dp, scope="acme", target_repo="/repo")
    assert tf.confirmed is True
    assert tf.ref == "sqli-001" and tf.evidence_ref == "a" * 64
    assert tf.bug_class == "sqli" and tf.target == "app.py:2" and tf.target_repo == "/repo"


def test_envelope_wrong_owner_refused(tmp_path):
    owner, attacker = generate_keypair(), generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths)
    with pytest.raises(TrustedFindingError):   # delegation is not by the pinned owner key
        finding_from_envelope(envelope_path=ep, owner_pubkey=attacker.public_key_b64,
                              delegation_path=dp, scope="acme", target_repo="/repo")


def test_envelope_tampered_certificate_refused(tmp_path):
    owner = generate_keypair()
    keys, auths, _ = _governance()
    env = _envelope(_cert(), keys, auths)
    d = json.loads(env)
    d["certificate"]["bug_class"] = "rce"                 # tamper AFTER signing → anchor-1 no longer matches
    ep = _write(tmp_path, "env.json", json.dumps(d))
    dp = _write(tmp_path, "deleg.json", _delegation(owner, auths).model_dump_json())
    with pytest.raises(TrustedFindingError):
        finding_from_envelope(envelope_path=ep, owner_pubkey=owner.public_key_b64,
                              delegation_path=dp, scope="acme", target_repo="/repo")


def test_envelope_out_of_scope_refused(tmp_path):
    # a finding legitimately signed for engagement "acme" cannot be laundered under scope "other".
    owner = generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths,
                            cert=_cert(slug="acme"), deleg_scope="other")
    with pytest.raises(TrustedFindingError):
        finding_from_envelope(envelope_path=ep, owner_pubkey=owner.public_key_b64,
                              delegation_path=dp, scope="other", target_repo="/repo")


def test_envelope_expired_delegation_refused(tmp_path):
    owner = generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths,
                            not_after=int(time.time()) - 10)
    with pytest.raises(TrustedFindingError):
        finding_from_envelope(envelope_path=ep, owner_pubkey=owner.public_key_b64,
                              delegation_path=dp, scope="acme", target_repo="/repo")


def test_envelope_below_threshold_refused(tmp_path):
    owner = generate_keypair()
    keys, auths, _ = _governance(n=2, threshold=2)
    msg = evidence_signing_bytes(_cert())
    one = [{"key_id": auths[0].key_id, "signature_b64": sign(keys[0].private_key_b64, msg)}]  # 1-of-2
    ep = _write(tmp_path, "env.json", build_envelope(_cert(), one))
    dp = _write(tmp_path, "deleg.json", _delegation(owner, auths, threshold=2).model_dump_json())
    with pytest.raises(TrustedFindingError):
        finding_from_envelope(envelope_path=ep, owner_pubkey=owner.public_key_b64,
                              delegation_path=dp, scope="acme", target_repo="/repo")


def test_envelope_missing_owner_or_scope_refused(tmp_path):
    owner = generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths)
    with pytest.raises(TrustedFindingError):
        finding_from_envelope(envelope_path=ep, owner_pubkey="", delegation_path=dp,
                              scope="acme", target_repo="/repo")
    with pytest.raises(TrustedFindingError):
        finding_from_envelope(envelope_path=ep, owner_pubkey=owner.public_key_b64, delegation_path=dp,
                              scope="", target_repo="/repo")


def test_raw_json_finding_is_never_accepted_and_why():
    # There is NO api that accepts a raw TriageFinding — only the two verified sources exist.
    import vigil_integration.live.trusted_finding as tfmod
    assert not hasattr(tfmod, "finding_from_json")
    # THE hazard that motivates it: a forged confirmed finding trivially passes may_remediate — so a source
    # that copies `confirmed` from untrusted bytes would be a bypass. The CLI never builds a finding this way.
    from vigil_integration.remediation.triage import TriageFinding, may_remediate
    forged = TriageFinding(ref="x", confirmed=True, evidence_ref="TOTALLY-FAKE", target_repo="/r")
    assert may_remediate(forged)[0] is True


# --- Option B: the engagement's own signed spine --------------------------------------------------

def _seed_spine(base: Path, slug: str, *, facts):
    """Write a real {slug}.spine under `base` using the STABLE spine key finding_from_spine will re-load."""
    from vigil_core.vault import Vault

    from vigil_integration.agent.state import AgentState, Finding
    from vigil_integration.live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
    from vigil_integration.live.spine_vigilcore import VigilCoreSpine
    base.mkdir(parents=True, exist_ok=True)
    kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=Vault(base / "vault"))
    spine = VigilCoreSpine(kp, str(base / f"{slug}.spine"))
    st = AgentState(engagement_slug=slug, iteration=1)
    for ref, ev in facts:
        st.record_fact(Finding(ref=ref, bug_class="sqli", title="auth bypass", severity="critical"),
                       evidence_ref=ev)
    spine.write_state(st, seq=1)


def test_spine_happy_path(tmp_path):
    base = tmp_path / "home"
    _seed_spine(base, "acme", facts=[("f-sqli", "cert:evi-1")])
    tf = finding_from_spine(base_dir=str(base), slug="acme", target_repo="/repo")
    assert tf.confirmed is True and tf.ref == "f-sqli" and tf.evidence_ref == "cert:evi-1"
    assert tf.target_repo == "/repo"


def test_spine_tampered_refused(tmp_path):
    base = tmp_path / "home"
    _seed_spine(base, "acme", facts=[("f-sqli", "cert:evi-1")])
    p = base / "acme.spine"
    original = p.read_text(encoding="utf-8")
    tampered = original.replace("auth bypass", "auth-bypazz")
    assert tampered != original                                  # ensure the tamper actually changed content
    p.write_text(tampered, encoding="utf-8")
    with pytest.raises(TrustedFindingError):                     # verify() fails on the mutated content
        finding_from_spine(base_dir=str(base), slug="acme", target_repo="/repo")


def test_spine_ambiguous_requires_ref(tmp_path):
    base = tmp_path / "home"
    _seed_spine(base, "acme", facts=[("f-sqli", "cert:evi-1"), ("f-xss", "cert:evi-2")])
    with pytest.raises(TrustedFindingError):                     # 2 facts, no --finding-ref → refuse
        finding_from_spine(base_dir=str(base), slug="acme", target_repo="/repo")
    tf = finding_from_spine(base_dir=str(base), slug="acme", target_repo="/repo", finding_ref="f-xss")
    assert tf.ref == "f-xss"


def test_spine_missing_or_no_facts_refused(tmp_path):
    with pytest.raises(TrustedFindingError):                     # no spine at all
        finding_from_spine(base_dir=str(tmp_path / "nope"), slug="acme", target_repo="/repo")
    base = tmp_path / "empty"
    _seed_spine(base, "acme", facts=[])                          # a spine with zero facts
    with pytest.raises(TrustedFindingError):
        finding_from_spine(base_dir=str(base), slug="acme", target_repo="/repo")


# --- destruction provisioning loaders (the --open-pr m-of-n) ---------------------------------------

def test_load_destruction_authority_fail_closed(tmp_path):
    owner, worker = generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64),
        AuthorizerKey(key_id="worker", name="worker", public_key_b64=worker.public_key_b64)])
    trp = _write(tmp_path, "tr.json", tr.model_dump_json())
    authority = load_destruction_authority(trust_root_path=trp, mandatory_signer_ids=["owner"])
    assert "owner" in authority.mandatory_signer_ids
    with pytest.raises(TrustedFindingError):        # mandatory signer not registered in the trust root
        load_destruction_authority(trust_root_path=trp, mandatory_signer_ids=["ghost"])
    with pytest.raises(TrustedFindingError):        # empty mandatory set
        load_destruction_authority(trust_root_path=trp, mandatory_signer_ids=[])
    with pytest.raises(TrustedFindingError):        # unreadable trust root
        load_destruction_authority(trust_root_path=str(tmp_path / "nope.json"),
                                   mandatory_signer_ids=["owner"])


def test_load_signed_authorization_fail_closed(tmp_path):
    doc = {"authorization": {"action_id": "pr-x", "engagement_slug": "acme", "target": "/r",
                             "blast_class": "destructive", "not_before": 0, "not_after": 100, "nonce": "n1"},
           "signatures": [{"key_id": "owner", "signature_b64": "AA"}]}
    signed = load_signed_authorization(_write(tmp_path, "s.json", doc))
    assert signed.authorization.nonce == "n1" and len(signed.signatures) == 1
    with pytest.raises(TrustedFindingError):        # empty signatures
        load_signed_authorization(_write(tmp_path, "b1.json", {"authorization": doc["authorization"],
                                                               "signatures": []}))
    with pytest.raises(TrustedFindingError):        # missing authorization fields
        load_signed_authorization(_write(tmp_path, "b2.json", {"authorization": {"nonce": "n"},
                                                               "signatures": [{"key_id": "o",
                                                                               "signature_b64": "AA"}]}))
    with pytest.raises(TrustedFindingError):        # not an object
        load_signed_authorization(_write(tmp_path, "b3.json", [1, 2, 3]))


# --- integration: a verified finding drives the REAL gated ladder ---------------------------------

_VULN = 'def q(u):\n    return "SELECT * FROM t WHERE id=" + u\n'
_FIXED = 'def q(u):\n    return "SELECT * FROM t WHERE id=%s", (u,)\n'


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


class _FakeClient:
    def __init__(self, diff):
        self._diff = diff
        self.messages = self

    def create(self, **_kw):
        return {"content": self._diff}


def test_verified_envelope_finding_drives_ladder_no_pr(tmp_path):
    # end-to-end: finding_from_envelope → autopatch_live applies the fix in a DISPOSABLE clone, opens NO PR,
    # and the SOURCE repo stays vulnerable. Proves the whole trusted path wires into the gated ladder.
    from vigil_integration.live.codefix_runner import CodefixConfig, autopatch_live
    repo = tmp_path / "app"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "t@t", cwd=repo)
    _git("config", "user.name", "t", cwd=repo)
    (repo / "app.py").write_text(_VULN, encoding="utf-8")
    _git("add", "app.py", cwd=repo)
    _git("commit", "-q", "-m", "init", cwd=repo)
    (repo / "app.py").write_text(_FIXED, encoding="utf-8")
    diff = _git("diff", cwd=repo).stdout
    _git("checkout", "--", "app.py", cwd=repo)
    assert (repo / "app.py").read_text() == _VULN

    owner = generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths, cert=_cert(target="app.py:2"))
    finding = finding_from_envelope(envelope_path=ep, owner_pubkey=owner.public_key_b64,
                                    delegation_path=dp, scope="acme", target_repo=str(repo))
    cfg = CodefixConfig(target_repo=str(repo), base_dir=str(tmp_path / "work"), apply_edits=True)
    result = autopatch_live(finding, config=cfg, client=_FakeClient(diff), operator_present=True)
    assert result.opened_pr is False and result.remediated is False
    assert (repo / "app.py").read_text() == _VULN               # SOURCE never modified


# --- the CLI verb ---------------------------------------------------------------------------------

def test_cli_refuses_no_source(capsys):
    from vigil_integration.cli import main
    assert main(["patch"]) == 2
    assert "EXACTLY ONE trusted finding source" in capsys.readouterr().err


def test_cli_refuses_both_sources():
    from vigil_integration.cli import main
    assert main(["patch", "--finding-envelope", "e.json", "--from-spine", "acme"]) == 2


def test_cli_surfaces_verified_finding_then_needs_target_repo(tmp_path, capsys):
    from vigil_integration.cli import main
    owner = generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths)
    rc = main(["patch", "--finding-envelope", ep, "--owner-pubkey", owner.public_key_b64,
               "--delegation", dp, "--scope", "acme"])
    out = capsys.readouterr()
    assert "sqli-001" in out.out                                 # the VERIFIED finding was surfaced
    assert rc == 2 and "--target-repo is required" in out.err


def test_cli_refuses_forged_envelope(tmp_path, capsys):
    from vigil_integration.cli import main
    owner, attacker = generate_keypair(), generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths)
    rc = main(["patch", "--finding-envelope", ep, "--owner-pubkey", attacker.public_key_b64,
               "--delegation", dp, "--scope", "acme", "--target-repo", str(tmp_path)])
    assert rc == 2 and "REFUSED (fail-closed)" in capsys.readouterr().err


def test_cli_open_pr_requires_full_provisioning(tmp_path, capsys):
    from vigil_integration.cli import main
    owner = generate_keypair()
    keys, auths, _ = _governance()
    ep, dp = _env_and_deleg(tmp_path, owner=owner, keys=keys, auths=auths)
    rc = main(["patch", "--finding-envelope", ep, "--owner-pubkey", owner.public_key_b64,
               "--delegation", dp, "--scope", "acme", "--target-repo", str(tmp_path), "--open-pr"])
    err = capsys.readouterr().err
    assert rc == 2 and "--open-pr requires" in err
