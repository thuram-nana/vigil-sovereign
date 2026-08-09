"""WAVE #4 PHASE-A slice A2 — mesh + CI/CD posture VIGIL-direct FACT capability.

VIGIL parses the target's OWN primary config artifact (an Istio/Linkerd mesh manifest, or a GitHub-Actions
workflow), and mints a signed FACT ONLY when the deterministic mesh_posture / cicd_posture oracle re-derives a
concrete insecure achieved state over the RETAINED control. A scanner's say-so is never trusted — the artifact
merely CONTAINING a construct does NOT mint a FACT; only VIGIL's own parse + oracle re-derivation does. No
external tool is installed or run.

Acceptance (all): a positive fixture mints a signed FACT that re-verifies offline; a hardened fixture -> no
fire -> no FACT; a DECEPTIVE artifact the oracle refutes -> no FACT, INCONCLUSIVE (never CLEAN); a no-config /
no-recognised-control -> INCONCLUSIVE never CLEAN; a malformed/oversized/bomb artifact -> typed parse error
via safe_parse. The clean_capable:false branches mean a non-fire can NEVER escape as CLEAN.
"""
from __future__ import annotations

import pytest

from vigil_integration.live.mesh_cicd_posture import (
    PostureResult,
    _safe_parse_structure,
    cicd_posture_verify,
    mesh_posture_verify,
)
from vigil_integration.live.safe_parse import ParseBudget


def _signers_and_trust():
    """One keypair → the governance signer + a matching single-authorizer trust root (verify offline)."""
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


# ---- fixtures: genuine PRIMARY config artifacts ---------------------------------------------------

# MESH — permissive PeerAuthentication (fires): mesh-wide plaintext accepted.
_MESH_PERMISSIVE = """\
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: PERMISSIVE
"""

# MESH — hardened: STRICT mTLS. Must NOT fire.
_MESH_STRICT = """\
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
"""

# MESH — DECEPTIVE: an AuthorizationPolicy with requestPrincipals ['*'] LOOKS allow-all but requires a valid
# JWT (a request principal), so the oracle must REFUSE — this is the near-zero-FP boundary.
_MESH_DECEPTIVE = """\
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: jwt-any
  namespace: prod
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        requestPrincipals: ["*"]
"""

# MESH — a Deployment: a real manifest with NO mesh security resource → zero controls → INCONCLUSIVE.
_MESH_NO_CONTROL = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  replicas: 3
"""

# CICD — unpinned third-party action on a mutable ref (fires).
_CICD_UNPINNED = """\
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@main
"""

# CICD — hardened: STRICT is meaningless here; the hardened workflow SHA-pins its third-party action AND uses
# the first-party checkout. Must NOT fire.
_CICD_HARDENED = """\
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some/action@ffffffffffffffffffffffffffffffffffffffff
"""

# CICD — DECEPTIVE: actions/checkout@v4 LOOKS unpinned (mutable @v4) but is FIRST-PARTY (owner=actions), so
# the oracle must REFUSE — the near-zero-FP boundary.
_CICD_DECEPTIVE = """\
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""


# ---- resource-governed parse (pure, sovereign-safe: no framework needed) --------------------------

def test_safe_parse_yaml_and_json_structures():
    y = _safe_parse_structure(_MESH_PERMISSIVE)
    assert y.ok and y.value["kind"] == "PeerAuthentication"
    j = _safe_parse_structure('{"kind":"PeerAuthentication","spec":{"mtls":{"mode":"PERMISSIVE"}}}')
    assert j.ok and j.value["spec"]["mtls"]["mode"] == "PERMISSIVE"


def test_safe_parse_malformed_is_a_typed_error_never_a_crash():
    bad = _safe_parse_structure("kind: PeerAuthentication\n  bad: : : indent\n :\n- x")
    assert bad.ok is False and bad.outcome == "error"


def test_safe_parse_oversize_and_bomb_are_typed_errors():
    tiny = ParseBudget(max_bytes=16)
    assert _safe_parse_structure(_MESH_PERMISSIVE, tiny).outcome == "error"   # oversize
    # a YAML alias bomb must be an error, never an expanded structure
    bomb = "a: &a [x,x,x,x,x,x,x,x,x,x]\nb: [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
    r = _safe_parse_structure(bomb, ParseBudget(max_nodes=20))
    assert r.ok is False and r.outcome == "error"


def test_no_raw_yaml_or_json_load_on_operator_bytes():
    """Charter rule 6: the module parses ONLY through safe_parse. Assert the source never calls raw loaders."""
    import ast
    import inspect
    import vigil_integration.live.mesh_cicd_posture as mod
    tree = ast.parse(inspect.getsource(mod))
    forbidden = {("yaml", "load"), ("yaml", "safe_load"), ("yaml", "safe_load_all"),
                 ("json", "loads"), ("json", "load")}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name):
            assert (node.func.value.id, node.func.attr) not in forbidden, \
                f"raw loader call {node.func.value.id}.{node.func.attr}() on operator bytes"


# ---- MESH: positive → FACT that re-verifies offline ----------------------------------------------

def test_mesh_permissive_mints_a_fact_that_reverifies_offline():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from framework.v2.evidence.certify import verify_certificate

    signers, tr = _signers_and_trust()
    res = mesh_posture_verify(_MESH_PERMISSIVE, engagement_slug="acme", signers=signers)
    assert isinstance(res, PostureResult) and res.family == "mesh_posture"
    assert res.parse_outcome == "ok" and res.controls == 1
    assert res.n_facts == 1, f"expected a mesh FACT; leads={res.leads} inconclusive={res.inconclusive}"
    f = res.facts[0]
    ctx = res.contexts[f.finding_ref]
    # the FACT re-verifies offline end-to-end (authentic + bound + reproduced)
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True
    # admission attributed it to the ONE clean_capable:false branch, and the artifact was bound into the cert
    assert res.admissions and all(a[0] == "mesh_posture.achieved_state" for a in res.admissions)
    assert any(a[1] == "FACT" for a in res.admissions)
    assert res.family_verdict() == "FACT"
    assert res.artifact_sha256 and len(res.artifact_sha256) == 64


def test_mesh_strict_hardened_does_not_fire_no_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = mesh_posture_verify(_MESH_STRICT, engagement_slug="acme", signers=signers)
    assert res.controls == 1 and res.n_facts == 0
    # a non-fire over a clean_capable:false branch is INCONCLUSIVE — NEVER CLEAN
    assert res.inconclusive and all(r.outcome == "inconclusive" for r in res.inconclusive)
    assert all(r.outcome != "clean" for r in res.facts + res.leads + res.inconclusive)
    assert res.family_verdict() == "INCONCLUSIVE"
    assert res.admissions and all(a[1] == "INCONCLUSIVE" for a in res.admissions)


def test_mesh_deceptive_request_principals_wildcard_is_refuted_never_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = mesh_posture_verify(_MESH_DECEPTIVE, engagement_slug="acme", signers=signers)
    # the artifact WAS ingested + examined (a control), but the oracle REFUTED the allow-all label → no FACT
    assert res.controls == 1 and res.n_facts == 0
    assert all(r.outcome != "clean" for r in res.facts + res.leads + res.inconclusive)
    assert res.family_verdict() != "FACT" and res.family_verdict() != "CLEAN"


def test_mesh_no_security_resource_is_inconclusive_never_clean():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = mesh_posture_verify(_MESH_NO_CONTROL, engagement_slug="acme", signers=signers)
    assert res.parse_outcome == "ok" and res.controls == 0
    assert res.n_facts == 0 and res.leads == [] and res.inconclusive == []
    assert res.admissions == []                      # nothing was adjudicated at all
    assert res.family_verdict() == "INCONCLUSIVE"    # nothing examined != CLEAN


def test_mesh_malformed_artifact_is_a_typed_error_no_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = mesh_posture_verify("kind: PeerAuthentication\n  : : bad indent\n- :", engagement_slug="acme",
                              signers=signers)
    assert res.parse_outcome == "error" and res.n_facts == 0 and res.controls == 0
    assert res.family_verdict() == "INCONCLUSIVE"    # unparseable != CLEAN


# ---- CICD: positive → FACT that re-verifies offline ----------------------------------------------

def test_cicd_unpinned_action_mints_a_fact_that_reverifies_offline():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from framework.v2.evidence.certify import verify_certificate

    signers, tr = _signers_and_trust()
    res = cicd_posture_verify(_CICD_UNPINNED, name="ci.yml", engagement_slug="acme", signers=signers)
    assert res.family == "cicd_posture" and res.parse_outcome == "ok"
    assert res.n_facts >= 1, f"expected a cicd FACT; leads={res.leads} inconclusive={res.inconclusive}"
    f = next(x for x in res.facts)
    ctx = res.contexts[f.finding_ref]
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True
    assert res.admissions and all(a[0] == "cicd_posture.workflow_construct" for a in res.admissions)
    assert any(a[1] == "FACT" for a in res.admissions)
    assert res.family_verdict() == "FACT"


def test_cicd_hardened_sha_pinned_and_first_party_does_not_fire():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = cicd_posture_verify(_CICD_HARDENED, name="ci.yml", engagement_slug="acme", signers=signers)
    assert res.n_facts == 0, f"a SHA-pinned + first-party workflow must not fire: {res.facts}"
    assert all(r.outcome != "clean" for r in res.facts + res.leads + res.inconclusive)
    assert res.family_verdict() in ("INCONCLUSIVE",)


def test_cicd_deceptive_first_party_at_mutable_ref_is_refuted_never_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = cicd_posture_verify(_CICD_DECEPTIVE, name="ci.yml", engagement_slug="acme", signers=signers)
    # actions/checkout@v4 IS ingested as an unpinned_action candidate, but the oracle REFUTES it (first-party)
    assert res.controls >= 1 and res.n_facts == 0
    assert all(r.outcome != "clean" for r in res.facts + res.leads + res.inconclusive)
    assert res.family_verdict() != "FACT" and res.family_verdict() != "CLEAN"


def test_cicd_no_jobs_is_inconclusive_never_clean():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = cicd_posture_verify("name: ci\non: push\n", name="ci.yml", engagement_slug="acme", signers=signers)
    assert res.parse_outcome == "ok" and res.controls == 0 and res.n_facts == 0
    assert res.admissions == [] and res.family_verdict() == "INCONCLUSIVE"


def test_cicd_malformed_is_a_typed_error_no_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = cicd_posture_verify("name: ci\n\ton: : bad\n- :", name="ci.yml", engagement_slug="acme",
                              signers=signers)
    assert res.parse_outcome == "error" and res.n_facts == 0
    assert res.family_verdict() == "INCONCLUSIVE"


# ---- admission discipline: minting is admission-routed, never a direct confirm_and_certify --------

def test_minting_is_admission_routed_not_a_direct_confirm(monkeypatch):
    """The FACT path MUST go through verdict.admit() + oracle_adapter.certify_admitted(), never
    confirm_and_certify directly. We spy on certify_admitted (imported function-locally) and assert every mint
    carries an AdmittedVerdict from admission."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    import vigil_integration.oracle_adapter as oa
    from vigil_integration.live.verdict import AdmittedVerdict

    seen = []
    real = oa.certify_admitted

    def _spy(finding, admitted, **kw):
        seen.append(admitted)
        return real(finding, admitted, **kw)

    monkeypatch.setattr(oa, "certify_admitted", _spy)
    signers, _ = _signers_and_trust()
    mesh_posture_verify(_MESH_PERMISSIVE, engagement_slug="acme", signers=signers)
    assert seen and all(isinstance(a, AdmittedVerdict) for a in seen)
    assert all(a.branch == "mesh_posture.achieved_state" for a in seen)
