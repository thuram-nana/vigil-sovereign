"""PHASE 1 — the SBOM / dependency-CVE VIGIL-direct FACT capability (VERSION_RANGE oracle family).

VIGIL parses the target's OWN manifest for concrete versions, looks them up in a PINNED vendored OSV
snapshot, and mints a signed FACT only when the version PROVABLY falls in an advisory's affected range. A
scanner's CVE match is never trusted — the advisory merely existing does NOT mint a FACT; only VIGIL's own
version_in_affected re-derivation does (the criterion-6 firewall). No external tool is installed or run.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.live.sbom import (
    load_osv_snapshot,
    parse_package_lock,
    parse_requirements_txt,
)

_OSV_PATH = Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "osv-snapshot.json"


# ---- parsers (pure, sovereign-safe) --------------------------------------------------------------

def test_parse_requirements_txt_pins_only():
    text = ("# comment\npyyaml==5.3.1\nrequests >= 2.0   # not pinned → skip\n"
            "-r other.txt\nJinja2==3.1.2\nPy_Yaml==5.3.1  ; python_version>'3'\n\n")
    pkgs = dict(parse_requirements_txt(text))
    assert pkgs["pyyaml"] == "5.3.1"        # normalized name
    assert pkgs["jinja2"] == "3.1.2"
    assert pkgs["py-yaml"] == "5.3.1"       # _ normalized to -, env-marker stripped
    assert "requests" not in pkgs           # non-pinned constraint skipped


def test_parse_package_lock_v2_and_v1():
    v3 = '{"lockfileVersion":3,"packages":{"":{"name":"root"},"node_modules/lodash":{"version":"4.17.20"}}}'
    assert ("lodash", "4.17.20") in parse_package_lock(v3)
    v1 = '{"lockfileVersion":1,"dependencies":{"minimist":{"version":"1.2.5","dependencies":{"x":{"version":"1.0.0"}}}}}'
    got = dict(parse_package_lock(v1))
    assert got["minimist"] == "1.2.5" and got["x"] == "1.0.0"
    assert parse_package_lock("{not json") == []   # never raises


def test_committed_osv_snapshot_loads():
    osv = load_osv_snapshot(_OSV_PATH)
    assert "PyPI" in osv and "npm" in osv
    assert any(a.get("vuln_id") for a in osv["PyPI"]["pyyaml"])


def test_snapshot_load_rejects_comparator_string_ranges(tmp_path):
    """Red-pen LOW-1: a comparator-string range (which the comparator path does NOT fail-close on an
    open-ended '>=0') is rejected at LOAD — only dict-form {introduced, fixed} is allowed."""
    import json as _json
    bad = tmp_path / "bad.json"
    bad.write_text(_json.dumps({"ecosystems": {"PyPI": {"x": [{"vuln_id": "V", "affected": [">=0"]}]}}}))
    from vigil_integration.live.sbom import SnapshotError
    with pytest.raises(SnapshotError):
        load_osv_snapshot(bad)
    # a dict range missing 'introduced' is also rejected
    bad2 = tmp_path / "bad2.json"
    bad2.write_text(_json.dumps({"ecosystems": {"PyPI": {"x": [{"vuln_id": "V", "affected": [{"fixed": "2.0"}]}]}}}))
    with pytest.raises(SnapshotError):
        load_osv_snapshot(bad2)


def test_package_lock_deep_v1_does_not_blow_the_stack():
    """Red-pen LOW-2: a deep v1 lockfile is depth-capped in the walk (never a RecursionError). Build the
    JSON as a STRING (no json.dumps recursion) at a depth that json.loads handles but exceeds the 200 cap."""
    inner = '{"version":"1.0.0"}'
    for _ in range(300):   # > the 200 walk cap; json.loads handles ~300 nesting fine
        inner = '{"version":"1.0.0","dependencies":{"d":' + inner + '}}'
    doc = '{"lockfileVersion":1,"dependencies":{"top":' + inner + '}}'
    out = parse_package_lock(doc)   # must not raise
    assert ("top", "1.0.0") in out   # the shallow entries are collected; the deep tail is capped, not crashed


# ---- the VIGIL-direct FACT path (framework) ------------------------------------------------------

def _signers_and_trust():
    """One keypair → the governance signer + a matching single-authorizer trust root (verify offline)."""
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


@pytest.mark.parametrize("ecosystem,manifest,pkg,vulnerable", [
    ("PyPI", "pyyaml==5.3.1\n", "pyyaml", True),          # < 5.4 → in affected range → FACT
    ("PyPI", "pyyaml==6.0\n", "pyyaml", False),           # >= 5.4 → out of range → NO fact (refuted)
    ("npm", '{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}', "lodash", True),   # <4.17.21
    ("npm", '{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}', "lodash", False),  # patched
])
def test_sbom_mints_a_fact_only_when_the_version_is_provably_in_range(ecosystem, manifest, pkg, vulnerable):
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.sbom import sbom_verify

    osv = load_osv_snapshot(_OSV_PATH)
    signers, tr = _signers_and_trust()
    res = sbom_verify(manifest, ecosystem=ecosystem, osv=osv, engagement_slug="acme", signers=signers)
    if vulnerable:
        assert res.n_facts >= 1, f"expected a FACT for {pkg} {manifest!r}; leads={res.leads}"
        f = res.facts[0]
        ctx = res.contexts[f.finding_ref]
        # the FACT re-verifies offline end-to-end (authentic + bound + reproduced)
        assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True
    else:
        # the advisory EXISTS for this package, but VIGIL's version re-derivation REFUTES it → no FACT
        assert res.n_facts == 0, f"a patched/out-of-range version must NOT mint a FACT: {res.facts}"


def test_sbom_no_advisory_no_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_integration.live.sbom import sbom_verify
    osv = load_osv_snapshot(_OSV_PATH)
    signers, _ = _signers_and_trust()
    # a package not in the snapshot → nothing to adjudicate → no fact, no lead
    res = sbom_verify("cryptography==42.0.0\n", ecosystem="PyPI", osv=osv, engagement_slug="acme",
                      signers=signers)
    assert res.n_facts == 0 and res.leads == [] and res.packages == 1


def test_sbom_unsupported_ecosystem_is_honest():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_integration.live.sbom import sbom_verify
    signers, _ = _signers_and_trust()
    res = sbom_verify("x", ecosystem="Cargo", osv={}, engagement_slug="acme", signers=signers)
    assert res.n_facts == 0 and res.packages == 0 and any("unsupported" in n for n in res.notes)
