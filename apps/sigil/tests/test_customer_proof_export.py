"""Consumer PR-I (Area 8) — the per-finding PCF export + the proof-badge overlay, end to end.

What this pins:
  * OFFLINE RE-VERIFICATION: a bundle exported by the provisioner re-verifies with the SHIPPED standalone verifier
    (``docs/proof-carrying-finding/verify_pcf.py finding``) in a SEPARATE PROCESS that has no network (an empty network
    namespace where the host allows one, and always a socket layer that raises on use) and no VIGIL module importable
    (``--prove-standalone``); a tampered certificate, a flipped signature byte and a wrong out-of-band pin each fail it.
  * TENANT SCOPE (IDOR): another org's finding is unreachable even by its exact slug + certificate digest; a bundle
    carries only the session org's finding, and no private key material at all.
  * FAIL-CLOSED TRUST: the governance root is DERIVED from an owner-signed delegation verified against the CURRENT owner
    key, role, scope and clock — no delegation, an expired / foreign-owner / out-of-scope one, a forged or altered
    record, an unpublished root (when VIGIL publishes fingerprints) or an unavailable shipped verifier each yield no
    badge and no bundle. BOTH independent verifiers must accept (each one is mutation-tested alone).
  * THE OVERLAY: each card is badged by its OWN certificate (duplicate identities included), only while the flag is on
    and the report is not preview-locked; off, the findings read is byte-identical.
  * THE EDGE: the download is served as an attachment, no-store, from the session org only; flag off -> 404.

Findings are put on the spine by the REAL ingest path (``FindingReceiver.from_delegation(...).ingest``): governance-
signed certificates admitted under an owner-signed delegation, exactly as production writes them.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME owner state pristine)

from vigil_core import AuthorizerKey, evidence_signing_bytes, generate_keypair, sign
from vigil_core.canonical import digest_payload

REPO = Path(__file__).resolve().parents[3]
VERIFIER = REPO / "docs" / "proof-carrying-finding" / "verify_pcf.py"
FLAG = "VIGIL_CUSTOMER_PROOF_BADGE"
DELEGS = "VIGIL_CUSTOMER_PROOF_DELEGATIONS"
PUBLISHED = "VIGIL_PROOF_PUBLISHED_FINGERPRINTS"

GOV = generate_keypair()                                  # the offense governance key the owner delegates
GOV_AUTH = AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=GOV.public_key_b64)
_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path, _scrub_shared_owner_state):  # noqa: F811  (requested so the scrub runs FIRST: autouse
    # fixtures otherwise run in name order, and the scrub would then delete the owner key minted below)
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv(FLAG, "1")
    for v in ("VIGIL_TRIAL_PREVIEW_ENABLED", "VIGIL_CUSTOMER_RETEST_UI", PUBLISHED, "VIGIL_APEX_PRESENTATION"):
        monkeypatch.delenv(v, raising=False)
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import proof_export
    ensure_owner_keypair()
    proof_export._ShippedVerifier.reset()
    monkeypatch.setenv(DELEGS, str(_write_delegation(tmp_path / "gov.deleg.json")))
    yield
    proof_export._ShippedVerifier.reset()


# ----------------------------------------------------------------------------------------------- fixtures ----
def _owner():
    from sigil.governor.identity import owner_keypair
    kp = owner_keypair()
    assert kp is not None
    return kp


def _write_delegation(path: Path, *, owner=None, scope="*", not_after=None, authorizers=(GOV_AUTH,)) -> Path:
    from sigil.governor.identity import delegate_offense_governance
    cert = delegate_offense_governance(owner or _owner(), authorizers=list(authorizers), threshold=1, scope=scope,
                                       not_after=int(time.time() + 3600) if not_after is None else not_after)
    path.write_text(cert.model_dump_json(), encoding="utf-8")
    return path


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _seat(store, org, host, *, role="operator", user="u"):
    """An org with a member holding ``role`` and a CURRENT ownership proof of ``host`` (the findings read's slug set)."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.orgs import OrgRegistry
    orgs = OrgRegistry(store)
    if orgs.org(org) is None:
        orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=time.time(), ttl_seconds=1e9)


def _cert(org, host, ref, **extra):
    from sigil.ui.target_authorization import _customer_slug
    slug = _customer_slug(org, host)
    cert = {"schema_version": 1, "engagement_slug": slug, "finding_ref": ref, "bug_class": "error_based_sqli",
            "surface": f"https://{host}/items?id", "confirmed_by": "error_signature", "confidence": 0.9,
            "oracle_context_digest": digest_payload({"probe": ref, "slug": slug}), "artifacts": [], "seq": 0,
            "how_to_verify": f"Re-send the probe for {ref}; the datastore error must not appear."}
    cert.update(extra)
    return cert


def _ingest(store, cert, *, signer=GOV, key_id="gov0"):
    """Put a governance-signed finding on the spine through the REAL receiver (anchor 1 verified at ingest)."""
    from vigil_core.delegation import DelegationCert

    from sigil.governor.identity import owner_pubkey
    from sigil.inbound.finding_receiver import FindingReceiver
    from vigil_integration.inert_finding import build_envelope
    deleg = DelegationCert.model_validate_json(Path(os.environ[DELEGS].split(os.pathsep)[0]).read_text())
    env = build_envelope(cert, [{"key_id": key_id, "signature_b64": sign(signer.private_key_b64,
                                                                         evidence_signing_bytes(cert))}])
    FindingReceiver.from_delegation(store, owner_pubkey=owner_pubkey(), delegation=deleg, now=int(time.time()),
                                    scope="*").ingest(env)
    return cert


def _raw_append(store, cert, sigs):
    """A finding record appended WITHOUT the receiver (a legacy / tampered record the badge must refuse)."""
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"schema": "vigil.inert-finding.v1", "finding_ref": cert["finding_ref"],
                          "oracle_context_digest": cert["oracle_context_digest"], "certificate": cert,
                          "signatures": sigs})


def _prov(store):
    from sigil.ui.provision import build_provisioner
    return build_provisioner(store)


def _findings(store, org="org_a", user="u"):
    return _prov(store).customer_assessment_findings(user, org)["findings"]


def _export(store, cert, org="org_a", user="u"):
    return _prov(store).customer_proof_export(user, org, engagement_slug=cert["engagement_slug"],
                                              cert_digest=digest_payload(cert))


def _members(res) -> "dict[str, bytes]":
    raw = base64.b64decode(res["zip_b64"])
    assert hashlib.sha256(raw).hexdigest() == res["sha256"]
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


def _one_finding(org="org_a", host="app.acme.io", ref="sqli-001"):
    st = _store()
    _seat(st, org, host)
    cert = _ingest(st, _cert(org, host, ref))
    return st, cert


# ------------------------------------------------------------------- the standalone, no-network subprocess ----
_NO_NET = r"""
import runpy, socket, sys
def _refuse(*a, **k):
    raise OSError("network access is disabled for this offline verification")
for _n in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "socketpair", "fromfd"):
    setattr(socket, _n, _refuse)
script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name="__main__")
"""


def _clean_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    env["PATH"] = "/usr/bin:/bin"
    return env


def _standalone_python() -> "tuple[str, bool]":
    """(interpreter, VIGIL-unimportable?) — the system Python when it has ``cryptography`` (the verifier's one
    dependency) and cannot see any VIGIL package, else this interpreter run isolated (``-I``)."""
    sysp = "/usr/bin/python3"
    if Path(sysp).exists():
        probe = subprocess.run(
            [sysp, "-I", "-c", ("import importlib.util as u, cryptography;"
             "print(any(u.find_spec(m) for m in ('framework','vigil_core','vigil_integration','strix','gateway')))")],
            env=_clean_env(), capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip() == "False":
            return sysp, True
    return sys.executable, False


def _netns_prefix() -> "list[str]":
    """``unshare -rn`` (an EMPTY network namespace) where the host permits it; [] otherwise (the socket guard alone)."""
    un = shutil.which("unshare")
    if un and subprocess.run([un, "-rn", "true"], capture_output=True).returncode == 0:
        return [un, "-rn"]
    return []


def _verify_offline(folder: Path, *args: str) -> subprocess.CompletedProcess:
    py, clean = _standalone_python()
    argv = _netns_prefix() + [py, "-I", "-c", _NO_NET, str(folder / "verify_pcf.py"), "finding",
                              "--bundle", str(folder / "proof-bundle.json"), *args]
    if clean:
        argv.append("--prove-standalone")
    return subprocess.run(argv, cwd=str(folder), env=_clean_env(), capture_output=True, text=True, timeout=120)


def _unzip(res, tmp_path: Path) -> Path:
    out = tmp_path / ("bundle-" + res["sha256"][:8])
    out.mkdir()
    for name, data in _members(res).items():
        (out / name).write_bytes(data)
    return out


def _fp(res) -> str:
    return res["trust_root_fingerprint"]


def test_an_exported_bundle_reverifies_offline_with_the_shipped_verifier(tmp_path):
    st, cert = _one_finding()
    res = _export(st, cert)
    folder = _unzip(res, tmp_path)
    proc = _verify_offline(folder, "--trust-root-fingerprint", _fp(res))
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert proc.stdout.strip().splitlines()[-1].startswith("finding VERIFIED"), proc.stdout
    assert "[OK ] authentic" in proc.stdout and "PINNED OK" in proc.stdout
    if _standalone_python()[1]:
        assert "confirmed VIGIL-free" in proc.stdout       # the separate process could not even import VIGIL
    # the guard is real: the same bootstrap refuses a socket, so a verifier that phoned home would have crashed
    probe = subprocess.run([sys.executable, "-I", "-c", _NO_NET.replace("runpy.run_path(script, run_name=\"__main__\")",
                            "socket.create_connection(('127.0.0.1', 9))"), "x"], capture_output=True, text=True)
    assert probe.returncode != 0 and "network access is disabled" in probe.stderr


def test_tampering_with_the_bundle_fails_the_offline_verify(tmp_path):
    st, cert = _one_finding()
    res = _export(st, cert)
    fp = _fp(res)
    base = _unzip(res, tmp_path)
    # 1) a signed field altered (the cert_digest convenience copy recomputed so only the signature can catch it)
    t1 = tmp_path / "t1"
    shutil.copytree(base, t1)
    doc = json.loads((t1 / "proof-bundle.json").read_text())
    doc["signed_evidence"]["certificate"]["bug_class"] = "info_disclosure"
    doc["cert_digest"] = digest_payload(doc["signed_evidence"]["certificate"])
    (t1 / "proof-bundle.json").write_text(json.dumps(doc))
    p1 = _verify_offline(t1, "--trust-root-fingerprint", fp)
    assert p1.returncode == 2 and "[BAD] authentic" in p1.stdout and "finding NOT VERIFIED" in p1.stdout, p1.stdout
    # 2) one signature byte flipped
    t2 = tmp_path / "t2"
    shutil.copytree(base, t2)
    doc = json.loads((t2 / "proof-bundle.json").read_text())
    raw = bytearray(base64.b64decode(doc["signed_evidence"]["signatures"][0]["signature_b64"]))
    raw[-1] ^= 0x01
    doc["signed_evidence"]["signatures"][0]["signature_b64"] = base64.b64encode(bytes(raw)).decode()
    (t2 / "proof-bundle.json").write_text(json.dumps(doc))
    p2 = _verify_offline(t2, "--trust-root-fingerprint", fp)
    assert p2.returncode == 2 and "finding NOT VERIFIED" in p2.stdout, p2.stdout
    # 3) the right bundle under a WRONG out-of-band pin
    p3 = _verify_offline(base, "--trust-root-fingerprint", "sha256:" + "0" * 64)
    assert p3.returncode == 2 and "MISMATCH" in p3.stdout, p3.stdout
    # 4) a swapped trust root (an attacker re-signs under their own key and ships their own root) is caught by the pin
    t4 = tmp_path / "t4"
    shutil.copytree(base, t4)
    rogue = generate_keypair()
    doc = json.loads((t4 / "proof-bundle.json").read_text())
    doc["signed_evidence"]["signatures"] = [{"key_id": "gov0", "signature_b64": sign(
        rogue.private_key_b64, evidence_signing_bytes(doc["signed_evidence"]["certificate"]))}]
    doc["trust_root"]["authorizers"][0]["public_key_b64"] = rogue.public_key_b64
    doc.pop("trust_root_fingerprint")
    (t4 / "proof-bundle.json").write_text(json.dumps(doc))
    p4 = _verify_offline(t4, "--trust-root-fingerprint", fp)
    assert p4.returncode == 2 and "MISMATCH" in p4.stdout, p4.stdout
    # 5) the README's own tamper test, literally: change one value of the certificate and touch nothing else
    t5 = tmp_path / "t5"
    shutil.copytree(base, t5)
    doc = json.loads((t5 / "proof-bundle.json").read_text())
    doc["signed_evidence"]["certificate"]["surface"] = "https://app.acme.io/somewhere-else"
    (t5 / "proof-bundle.json").write_text(json.dumps(doc, indent=2))
    p5 = _verify_offline(t5, "--trust-root-fingerprint", fp)
    assert p5.returncode == 2 and p5.stdout.strip().splitlines()[-1] == "finding NOT VERIFIED", p5.stdout
    # 6) ... and the README's parenthesis: a file that is no longer JSON is an input error (exit 3), not a verdict
    (t5 / "proof-bundle.json").write_text("{ this is not json")
    p6 = _verify_offline(t5, "--trust-root-fingerprint", fp)
    assert p6.returncode == 3 and "Traceback" not in p6.stderr, p6.stderr
    readme = (base / "README.md").read_text()
    assert "Change any value of the certificate" in readme and "exits 2" in readme and "exit 3" in readme


# --------------------------------------------------------------------------------- contents + determinism ----
def test_the_bundle_holds_exactly_the_signed_finding_the_verifier_and_the_readme():
    st, cert = _one_finding()
    res = _export(st, cert)
    files = _members(res)
    assert sorted(files) == ["README.md", "TRUST-ROOT-FINGERPRINT.txt", "proof-bundle.json", "verify_pcf.py"]
    assert files["verify_pcf.py"] == VERIFIER.read_bytes()             # the shipped verifier, byte for byte
    doc = json.loads(files["proof-bundle.json"])
    assert doc["format"] == "vigil.pcf-finding-bundle/1"
    assert doc["signed_evidence"]["certificate"] == cert                 # exactly the signed bytes, nothing added
    assert doc["cert_digest"] == digest_payload(cert) == res["cert_digest"]
    assert doc["trust_root"]["authorizers"] == [GOV_AUTH.model_dump(mode="json")]
    assert doc["trust_root_fingerprint"] == res["trust_root_fingerprint"] == "sha256:" + digest_payload(doc["trust_root"])
    assert files["TRUST-ROOT-FINGERPRINT.txt"].decode().strip() == res["trust_root_fingerprint"]
    readme = files["README.md"].decode()
    assert "verify_pcf.py finding --bundle proof-bundle.json --trust-root-fingerprint" in readme
    assert hashlib.sha256(VERIFIER.read_bytes()).hexdigest() in readme
    assert "NOT CHECKED" in readme and "does not prove" in readme        # the honest limits travel with the proof
    assert res["filename"] == f"vigil-proof-sqli-001-{digest_payload(cert)[:12]}.zip"
    assert res["content_type"] == "application/zip"


def test_the_same_finding_always_exports_the_same_bytes():
    st, cert = _one_finding()
    a, b = _export(st, cert), _export(st, cert)
    assert a["zip_b64"] == b["zip_b64"] and a["sha256"] == b["sha256"]


def test_no_private_key_material_and_no_other_tenant_in_the_bundle():
    st = _store()
    _seat(st, "org_a", "app.acme.io")
    _seat(st, "org_b", "shop.beta.io", user="v")
    a = _ingest(st, _cert("org_a", "app.acme.io", "sqli-001"))
    b = _ingest(st, _cert("org_b", "shop.beta.io", "beta-secret-ref-77"))
    blob = b"".join(_members(_export(st, a)).values())
    from sigil.governor.identity import owner_keypair
    for secret in (GOV.private_key_b64, owner_keypair().private_key_b64):
        assert secret.encode() not in blob
    for marker in (b"private_key", b"PRIVATE KEY", b"beta-secret-ref-77", b["engagement_slug"].encode(),
                   b["oracle_context_digest"].encode(), b"org_b", b"org_a"):
        assert marker not in blob, marker


# ------------------------------------------------------------------------------------------ tenant scope ----
def test_another_tenants_finding_is_unreachable_even_by_its_exact_identity():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _seat(st, "org_a", "app.acme.io")
    _seat(st, "org_b", "shop.beta.io", user="v")
    a = _ingest(st, _cert("org_a", "app.acme.io", "sqli-001"))
    b = _ingest(st, _cert("org_b", "shop.beta.io", "sqli-001"))
    assert _export(st, b, org="org_b", user="v")["cert_digest"] == digest_payload(b)   # B can export its own
    with pytest.raises(ProvisionDenied, match="no such finding"):
        _export(st, b, org="org_a", user="u")             # A names B's exact slug + digest: structurally not found
    with pytest.raises(ProvisionDenied, match="may not read"):
        _export(st, b, org="org_b", user="u")             # A's member naming org B: not a member there
    # a host B proves too gives A no reach into B's findings (the slug is a one-way hash of org + host)
    _seat(st, "org_a", "shop.beta.io")
    with pytest.raises(ProvisionDenied, match="no such finding"):
        _export(st, b, org="org_a", user="u")
    assert _export(st, a)["cert_digest"] == digest_payload(a)


def test_a_billing_only_member_and_a_bad_identity_are_refused():
    from sigil.ui.provision import ProvisionDenied
    st, cert = _one_finding()
    from sigil.governor.orgs import OrgRegistry
    OrgRegistry(st).grant_membership("org_a", "billing", "org_admin", issued_at=float(next(_iss)))
    with pytest.raises(ProvisionDenied, match="view_assessments"):
        _export(st, cert, user="billing")
    p = _prov(st)
    for slug, dig in ((cert["engagement_slug"], "zz"), ("", digest_payload(cert)), ("has space", digest_payload(cert)),
                      (cert["engagement_slug"], digest_payload(cert).upper()), (cert["engagement_slug"], "0" * 64)):
        with pytest.raises(ProvisionDenied, match="no such finding"):
            p.customer_proof_export("u", "org_a", engagement_slug=slug, cert_digest=dig)


def test_a_lapsed_ownership_proof_hides_the_finding_from_export_like_the_findings_read():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _seat(st, "org_a", "app.acme.io")
    cert = _ingest(st, _cert("org_a", "app.acme.io", "sqli-001"))
    later = time.time() + 2e9                              # past the proof's TTL: no longer in the CURRENT slug set
    with pytest.raises(ProvisionDenied, match="no such finding"):
        _prov(st).customer_proof_export("u", "org_a", engagement_slug=cert["engagement_slug"],
                                        cert_digest=digest_payload(cert), now=later)


# ---------------------------------------------------------------------------------------- fail-closed trust ----
def _refused(st, cert, match="cannot be verified"):
    from sigil.ui.provision import ProvisionDenied
    with pytest.raises(ProvisionDenied, match=match):
        _export(st, cert)
    rows = _findings(st)
    assert rows and all(r["proof"] == {"verifiable": False} for r in rows), rows


def test_no_configured_delegation_means_no_badge_and_no_bundle(monkeypatch):
    st, cert = _one_finding()
    monkeypatch.setenv(DELEGS, "")
    _refused(st, cert)
    monkeypatch.setenv(DELEGS, "relative/gov.deleg.json")          # never resolved against an unexpected cwd
    _refused(st, cert)


def test_an_expired_delegation_vouches_for_nothing(monkeypatch, tmp_path):
    st, cert = _one_finding()
    monkeypatch.setenv(DELEGS, str(_write_delegation(tmp_path / "old.json", not_after=int(time.time()) - 1)))
    _refused(st, cert)


def test_a_delegation_signed_by_anyone_but_the_owner_is_ignored(monkeypatch, tmp_path):
    st, cert = _one_finding()
    monkeypatch.setenv(DELEGS, str(_write_delegation(tmp_path / "rogue.json", owner=generate_keypair())))
    _refused(st, cert)


def test_a_delegation_for_another_scope_does_not_cover_the_finding(monkeypatch, tmp_path):
    st, cert = _one_finding()
    monkeypatch.setenv(DELEGS, str(_write_delegation(tmp_path / "scoped.json", scope="cust_someone_else")))
    _refused(st, cert)
    monkeypatch.setenv(DELEGS, str(_write_delegation(tmp_path / "own.json", scope=cert["engagement_slug"])))
    assert _export(st, cert)["cert_digest"] == digest_payload(cert)        # positive control: its own scope covers it


def test_a_record_with_a_forged_or_altered_signature_is_never_badged():
    st = _store()
    _seat(st, "org_a", "app.acme.io")
    forged = _cert("org_a", "app.acme.io", "forged-1")
    _raw_append(st, forged, [{"key_id": "gov0", "signature_b64": sign(generate_keypair().private_key_b64,
                                                                      evidence_signing_bytes(forged))}])
    _refused(st, forged)
    st2 = _store()
    _seat(st2, "org_a", "app.acme.io")
    good = _cert("org_a", "app.acme.io", "altered-1")
    sig = sign(GOV.private_key_b64, evidence_signing_bytes(good))
    altered = {**good, "surface": "https://app.acme.io/elsewhere"}          # signed bytes changed after signing
    _raw_append(st2, altered, [{"key_id": "gov0", "signature_b64": sig}])
    _refused(st2, altered)


def test_a_non_fact_provenance_is_refused_by_the_shipped_verifier_even_when_signed():
    st = _store()
    _seat(st, "org_a", "app.acme.io")
    llm = _ingest(st, _cert("org_a", "app.acme.io", "llm-1", provenance="llm"))   # authentic, but not a FACT
    _refused(st, llm)


def test_when_vigil_publishes_fingerprints_only_a_published_root_is_offered(monkeypatch):
    st, cert = _one_finding()
    monkeypatch.setenv(PUBLISHED, "sha256:" + "a" * 64)
    _refused(st, cert)
    fp = "sha256:" + digest_payload({"schema_version": 1, "threshold": 1,
                                     "authorizers": [GOV_AUTH.model_dump(mode="json")]})
    monkeypatch.setenv(PUBLISHED, f"sha256:{'a' * 64}, {fp}")
    res = _export(st, cert)
    assert res["trust_root_fingerprint"] == fp
    assert fp in _members(res)["README.md"].decode()                       # the README points the auditor at it


def test_both_independent_verifiers_must_accept(monkeypatch):
    from sigil.ui import proof_export
    st, cert = _one_finding()
    assert _export(st, cert)                                               # both accept: exported
    monkeypatch.setattr(proof_export, "_shipped_verifier_verifies", lambda b, r: False)
    _refused(st, cert)                                                     # vigil_core alone is not enough
    monkeypatch.undo()
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setattr(proof_export, "_vigil_core_verifies", lambda b, r: False)
    _refused(st, cert)                                                     # the shipped verifier alone is not enough


def test_an_unavailable_shipped_verifier_fails_closed(monkeypatch, tmp_path):
    from sigil.ui import proof_export
    st, cert = _one_finding()
    monkeypatch.setattr(proof_export, "VERIFIER_PATH", tmp_path / "missing.py")
    proof_export._ShippedVerifier.reset()
    _refused(st, cert)
    bad = tmp_path / "verify_pcf.py"
    bad.write_text("raise SystemExit('not a verifier')\n")
    monkeypatch.setattr(proof_export, "VERIFIER_PATH", bad)
    proof_export._ShippedVerifier.reset()
    _refused(st, cert)


def test_a_verifier_that_changes_while_it_is_loaded_is_never_used(monkeypatch):
    """The code that verifies is the code that ships: the loader reads the verifier's bytes, executes them, then
    reads them again — bytes that changed in between (a deploy racing the load, a swapped file) refuse, so a badge
    can never rest on code other than the bytes the download carries. (A failed load is retried on the next call,
    so a race heals by itself once the file is stable; here every load sees the file change.)"""
    from sigil.ui import proof_export
    st, cert = _one_finding()
    real = proof_export._read_bounded
    reads = {"n": 0}

    def drifting(path, cap):
        data = real(path, cap)
        if path == proof_export.VERIFIER_PATH and data is not None:
            reads["n"] += 1
            if reads["n"] % 2 == 0:                     # every re-read after exec: the file changed meanwhile
                return data + b"\n# changed\n"
        return data
    monkeypatch.setattr(proof_export, "_read_bounded", drifting)
    proof_export._ShippedVerifier.reset()
    assert proof_export.verifier_source() is None and reads["n"] == 2
    _refused(st, cert)
    monkeypatch.setattr(proof_export, "_read_bounded", real)                 # the file is stable again: it heals
    assert proof_export.verifier_source() == VERIFIER.read_bytes()
    assert _export(st, cert)["cert_digest"] == digest_payload(cert)


def test_the_shipped_verifier_is_the_one_loaded_from_the_published_bytes():
    from sigil.ui import proof_export
    assert proof_export.VERIFIER_PATH == VERIFIER
    assert proof_export.verifier_source() == VERIFIER.read_bytes()


# ------------------------------------------------------------------------------------------------ overlay ----
def test_the_findings_read_badges_each_card_by_its_own_certificate():
    st = _store()
    _seat(st, "org_a", "app.acme.io")
    good = _ingest(st, _cert("org_a", "app.acme.io", "sqli-001"))
    # two records sharing ONE identity (same slug + ref + evidence digest; certificates differ by seq): the newer is
    # forged, the older genuine — each card must carry its own verdict
    older = _ingest(st, _cert("org_a", "app.acme.io", "dup-1", seq=1))
    newer = {**older, "seq": 2}
    _raw_append(st, newer, [{"key_id": "gov0", "signature_b64": sign(generate_keypair().private_key_b64,
                                                                     evidence_signing_bytes(newer))}])
    rows = _findings(st)
    by = [(r["finding_ref"], r["proof"]) for r in rows]
    assert [ref for ref, _ in by] == ["dup-1", "dup-1", "sqli-001"]        # newest-first, as the read lists them
    assert by[0][1] == {"verifiable": False}                               # the newest dup-1 is the forged one
    assert by[1][1]["verifiable"] is True and by[1][1]["cert_digest"] == digest_payload(older)
    assert by[2][1]["verifiable"] is True and by[2][1]["cert_digest"] == digest_payload(good)
    for _ref, p in by[1:]:
        assert p["threshold"] == 1 and p["signers"] == 1 and p["trust_root_fingerprint"].startswith("sha256:")


def test_the_export_hands_out_the_record_that_verifies_exactly_as_the_badge_did(tmp_path):
    """One certificate on the spine twice: the genuine record, then a NEWER copy of the very same certificate under a
    forged signature. Both rows name the same certificate digest; the older row is badged. Downloading by that digest
    must hand out the record that verifies (never refuse a badged row because a newer copy is bogus), and the bundle
    still re-verifies offline."""
    st = _store()
    _seat(st, "org_a", "app.acme.io")
    cert = _ingest(st, _cert("org_a", "app.acme.io", "sqli-001"))
    _raw_append(st, cert, [{"key_id": "gov0", "signature_b64": sign(generate_keypair().private_key_b64,
                                                                    evidence_signing_bytes(cert))}])
    rows = _findings(st)
    assert [r["proof"]["verifiable"] for r in rows] == [False, True]
    assert rows[1]["proof"]["cert_digest"] == digest_payload(cert)
    res = _export(st, cert)
    doc = json.loads(_members(res)["proof-bundle.json"])
    genuine = sign(GOV.private_key_b64, evidence_signing_bytes(cert))            # Ed25519 signing is deterministic
    assert doc["signed_evidence"]["signatures"] == [{"key_id": "gov0", "signature_b64": genuine}]
    proc = _verify_offline(_unzip(res, tmp_path), "--trust-root-fingerprint", _fp(res))
    assert proc.returncode == 0, proc.stdout


def test_misconfiguration_is_logged_once_for_the_operator_and_names_no_tenant(monkeypatch, tmp_path, caplog):
    """Badges missing because of configuration must be diagnosable: an unreadable delegation path and a refused (here
    expired) delegation each log ONE warning per process, naming the configuration — never a tenant or a finding. A
    delegation that merely covers ANOTHER engagement is normal and logs nothing."""
    import logging

    from sigil.ui import proof_export
    monkeypatch.setattr(proof_export, "_warned", set())
    st, cert = _one_finding()
    name = "sigil.ui.proof_export"

    def warnings_during(fn):
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger=name):
            fn()
        return [r.getMessage() for r in caplog.records if r.name == name]

    missing = tmp_path / "no-such-delegation.json"
    monkeypatch.setenv(DELEGS, str(missing))
    msgs = warnings_during(lambda: (_findings(st), _findings(st)))
    assert sum(str(missing) in m for m in msgs) == 1, msgs
    monkeypatch.setenv(DELEGS, str(_write_delegation(tmp_path / "old.json", not_after=int(time.time()) - 1)))
    msgs = warnings_during(lambda: (_findings(st), _findings(st)))
    assert sum("refused (expired)" in m for m in msgs) == 1, msgs
    monkeypatch.setenv(DELEGS, str(_write_delegation(tmp_path / "other.json", scope="cust_someone_else")))
    assert warnings_during(lambda: _findings(st)) == []
    monkeypatch.setenv(DELEGS, str(_write_delegation(tmp_path / "good.json")))   # a root that covers it again ...
    monkeypatch.setattr(proof_export, "VERIFIER_PATH", tmp_path / "gone.py")       # ... but no verifier to run
    proof_export._ShippedVerifier.reset()
    msgs = warnings_during(lambda: (_findings(st), _findings(st)))
    assert sum("shipped verifier" in m for m in msgs) == 1, msgs
    for m in msgs:
        assert cert["engagement_slug"] not in m and "org_a" not in m and "sqli-001" not in m


def test_the_overlay_never_crosses_tenants():
    st = _store()
    _seat(st, "org_a", "app.acme.io")
    _seat(st, "org_b", "shop.beta.io", user="v")
    _ingest(st, _cert("org_a", "app.acme.io", "same-ref"))
    b = _ingest(st, _cert("org_b", "shop.beta.io", "same-ref"))
    rows = _findings(st)
    assert len(rows) == 1 and rows[0]["proof"]["cert_digest"] != digest_payload(b)


def test_off_the_findings_read_is_byte_identical(monkeypatch):
    st, _cert_ = _one_finding()
    on = _findings(st)
    assert on[0]["proof"]["verifiable"] is True
    outs = []
    for v in (None, "0", "", "no"):
        if v is None:
            monkeypatch.delenv(FLAG, raising=False)
        else:
            monkeypatch.setenv(FLAG, v)
        outs.append(json.dumps(_prov(st).customer_assessment_findings("u", "org_a"), sort_keys=True))
    assert len(set(outs)) == 1 and '"proof"' not in outs[0]
    stripped = [{k: v for k, v in r.items() if k != "proof"} for r in on]
    assert json.loads(outs[0])["findings"] == stripped                      # the badge is the ONLY difference on


def test_a_fault_in_the_overlay_never_breaks_the_findings_read(monkeypatch):
    from sigil.ui import proof_export
    st, _c = _one_finding()

    def boom(*a, **k):
        raise RuntimeError("store hiccup")
    monkeypatch.setattr(proof_export, "_signed_records", boom)
    rows = _findings(st)
    assert rows and all("proof" not in r for r in rows)                     # no badge, but the findings are served


def test_a_preview_locked_trial_org_gets_no_badge_and_no_bundle(monkeypatch):
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    st, cert = _one_finding()
    WalletRegistry(st).grant("org_a", 100, "trial", entry_id="trial-preview:org_a", issued_at=float(next(_iss)))
    out = _prov(st).customer_assessment_findings("u", "org_a")
    assert out.get("preview") and all("proof" not in r for r in out["findings"])
    with pytest.raises(ProvisionDenied, match="unlock with the full report"):
        _export(st, cert)


def test_off_the_action_refuses_and_the_cockpit_dispatch_is_absent(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    from sigil.ui.server import Handler
    st, cert = _one_finding()
    monkeypatch.setenv(FLAG, "0")
    with pytest.raises(ProvisionDenied, match="not enabled"):
        _export(st, cert)
    body = {"org_id": "org_a", "engagement_slug": cert["engagement_slug"], "cert_digest": digest_payload(cert)}
    assert Handler._provision_dispatch(None, _prov(st), "proof_export", "u", body) is None     # -> 404
    monkeypatch.setenv(FLAG, "1")
    res = Handler._provision_dispatch(None, _prov(st), "proof_export", "u", body)
    assert res["cert_digest"] == digest_payload(cert)
    # the org is the hop-bound session's: a body naming another org is that org's, never a free selector
    from sigil.ui.provision import ProvisionDenied as _PD
    with pytest.raises(_PD):
        Handler._provision_dispatch(None, _prov(st), "proof_export", "u", {**body, "org_id": "org_zzz"})


# -------------------------------------------------------------------------------------- the edge download ----
def _edge_stack(tmp_path, monkeypatch):
    """A cockpit + custui edge (test_custui), a signed-up customer promoted to operator, and one real finding."""
    from test_custui import _opener, _post, _stack

    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.orgs import OrgRegistry
    sov, edge, ep, _sp = _stack(tmp_path, monkeypatch)
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.io"})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
    oid, user = conf["org_id"], conf["username"]
    st = sov.store()
    OrgRegistry(st).grant_membership(oid, user, "operator", issued_at=time.time() + 1e6)
    reg = AssetOwnershipRegistry(st)
    ch = reg.issue_challenge(oid, "app.acme.io", issued_at=time.time() + 1e6)
    reg.verify_and_record(oid, "app.acme.io", method=METHOD_DNS_TXT, observed=[ch.marker], now=time.time(),
                          ttl_seconds=1e9)
    cert = _ingest(st, _cert(oid, "app.acme.io", "sqli-001"))
    return sov, edge, ep, op, oid, cert


def _raw(op, port, path):
    import urllib.error
    import urllib.request
    try:
        with op.open(urllib.request.Request(f"http://127.0.0.1:{port}{path}"), timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_the_edge_serves_the_bundle_as_a_no_store_attachment_for_the_session_org(tmp_path, monkeypatch):
    from test_custui import _opener
    sov, edge, ep, op, oid, cert = _edge_stack(tmp_path, monkeypatch)
    try:
        q = f"engagement_slug={cert['engagement_slug']}&cert_digest={digest_payload(cert)}"
        code, hdr, body = _raw(op, ep, "/api/customer/assessments/proof?" + q)
        assert code == 200, (code, body[:200])
        assert hdr["Content-Type"] == "application/zip" and hdr["Cache-Control"] == "no-store"
        assert hdr["X-Content-Type-Options"] == "nosniff"
        assert hdr["Content-Disposition"] == f'attachment; filename="vigil-proof-sqli-001-{digest_payload(cert)[:12]}.zip"'
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            doc = json.loads(zf.read("proof-bundle.json"))
        assert doc["signed_evidence"]["certificate"] == cert
        # the findings read over the same edge carries the badge for that very certificate
        code, hdr2, raw = _raw(op, ep, "/api/customer/assessments/findings")
        rows = json.loads(raw)["findings"]
        assert code == 200 and rows[0]["proof"]["verifiable"] is True
        assert rows[0]["proof"]["cert_digest"] == digest_payload(cert)
        # a query org_id is ignored (the org is the session's); a repeated parameter is relayed as empty -> refused
        assert _raw(op, ep, "/api/customer/assessments/proof?" + q + "&org_id=org_zzz")[0] == 200
        code, _h, raw = _raw(op, ep, "/api/customer/assessments/proof?" + q + "&cert_digest=" + "0" * 64)
        assert code == 403 and b"no such finding" in raw
        # no session -> refused before any hop (a cross-site GET carries no SameSite=Strict cookie)
        assert _raw(_opener(), ep, "/api/customer/assessments/proof?" + q)[0] == 401
    finally:
        sov.shutdown()
        edge.shutdown()


def test_off_the_edge_route_is_an_unknown_route(tmp_path, monkeypatch):
    sov, edge, ep, op, oid, cert = _edge_stack(tmp_path, monkeypatch)
    try:
        monkeypatch.setenv(FLAG, "0")
        q = f"engagement_slug={cert['engagement_slug']}&cert_digest={digest_payload(cert)}"
        code, hdr, body = _raw(op, ep, "/api/customer/assessments/proof?" + q)
        unknown = _raw(op, ep, "/api/customer/assessments/no-such-route")
        assert (code, body) == (unknown[0], unknown[2]) == (404, b'{"error": "not found"}')
        assert "Content-Disposition" not in hdr
        code, _h, raw = _raw(op, ep, "/api/customer/assessments/findings")
        assert code == 200 and b'"proof"' not in raw
    finally:
        sov.shutdown()
        edge.shutdown()


def test_the_edges_own_switch_is_an_independent_refusal(tmp_path, monkeypatch):
    """Two independent refusals, each tested alone: with the EDGE's switch off the route is an unknown route even
    while the cockpit would still serve the bundle (the edge never relays a download it does not offer)."""
    from sigil.ui import custui
    sov, edge, ep, op, oid, cert = _edge_stack(tmp_path, monkeypatch)
    try:
        q = f"engagement_slug={cert['engagement_slug']}&cert_digest={digest_payload(cert)}"
        assert _raw(op, ep, "/api/customer/assessments/proof?" + q)[0] == 200          # positive control
        monkeypatch.setattr(custui, "_proof_badge_on", lambda: False)                    # the edge off, cockpit on
        code, hdr, body = _raw(op, ep, "/api/customer/assessments/proof?" + q)
        unknown = _raw(op, ep, "/api/customer/assessments/no-such-route")
        assert (code, body) == (unknown[0], unknown[2]) == (404, b'{"error": "not found"}')
        assert "Content-Disposition" not in hdr
    finally:
        sov.shutdown()
        edge.shutdown()


def test_the_edge_refuses_a_reply_that_is_not_the_bytes_it_names(tmp_path, monkeypatch):
    """The edge never serves bytes the provisioner did not stand behind: a reply whose sha256 does not match (or that
    is not base64) is a 502, never a download."""
    from sigil.ui import custui
    sov, edge, ep, op, oid, cert = _edge_stack(tmp_path, monkeypatch)
    try:
        real = custui.CustomerHandler._provision

        def lying(self, action, principal, body):
            c, r = real(self, action, principal, body)
            if action == "proof_export" and c == 200:
                r = {**r, "sha256": "0" * 64}
            return c, r
        monkeypatch.setattr(custui.CustomerHandler, "_provision", lying)
        q = f"engagement_slug={cert['engagement_slug']}&cert_digest={digest_payload(cert)}"
        code, hdr, body = _raw(op, ep, "/api/customer/assessments/proof?" + q)
        assert code == 502 and "Content-Disposition" not in hdr
    finally:
        sov.shutdown()
        edge.shutdown()


def test_bundle_document_matches_the_published_schema_shape():
    """The exported document is exactly the SPEC §8 member set (the JSON Schema's additionalProperties=false)."""
    st, cert = _one_finding()
    doc = json.loads(_members(_export(st, cert))["proof-bundle.json"])
    schema = json.loads((REPO / "docs/proof-carrying-finding/schemas/pcf-finding-bundle.schema.json").read_text())
    assert set(doc) <= set(schema["properties"]) and set(schema["required"]) <= set(doc)
    assert doc["format"] == schema["properties"]["format"]["const"]
    assert set(doc["signed_evidence"]) == {"certificate", "signatures"}
    assert all(set(s) == {"key_id", "signature_b64"} for s in doc["signed_evidence"]["signatures"])
    assert copy.deepcopy(doc["signed_evidence"]["certificate"]) == cert
