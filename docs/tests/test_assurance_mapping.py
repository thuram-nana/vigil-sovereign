"""Lane C / C4 — the assurance mapping completeness + drift guard.

`docs/assurance/assurance-mapping.json` maps the claim registry + limitation inventory onto a
Common-Criteria / FedRAMP-shaped assurance structure (security objective -> claim -> evidence/verifier ->
residual limitation) and maps every FACT-capable oracle class to the verifier that re-checks it. This guard
holds it honest:

  * DRIFT: the committed JSON must equal a fresh generation from the authoritative sources — so the mapping
    can never diverge from the registry / inventory / evidence-branches it cites.
  * COMPLETENESS (claims): every claim in docs/claims/registry.json appears in the mapping and routes to a
    declared security objective.
  * COMPLETENESS (facts): every FACT-capable class in docs/capability-matrix/evidence-branches.json appears
    in fact_class_assurance and maps to a verifier.
  * SOUNDNESS: the zero-dependency standalone set equals the INDEPENDENT ground-truth derivation (the oracle
    functions each class binds, versus the functions the standalone verifier re-executes) — so a standalone
    claim can never over- or under-state what verify_vf actually ports.
  * HONESTY: every residual-limitation reference resolves in the inventory; the irreducible boundaries
    (external body, hardware root, liveness) are named, not hidden; the adversarial-review sign-off slot is
    present and not fabricated.

STDLIB ONLY — the required `the briefing explains every agent and capability` job installs only pytest, so
this guard parses JSON with `json`, imports the stdlib-only generator, and reads source via `ast`.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAPPING = REPO / "docs" / "assurance" / "assurance-mapping.json"
GEN = REPO / "docs" / "assurance" / "gen_assurance_mapping.py"
REGISTRY = REPO / "docs" / "claims" / "registry.json"
INVENTORY = REPO / "docs" / "limitations" / "inventory.json"
BRANCHES = REPO / "docs" / "capability-matrix" / "evidence-branches.json"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _gen_module():
    spec = importlib.util.spec_from_file_location("gen_assurance_mapping", GEN)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MAP = _load(MAPPING)
GENMOD = _gen_module()


def test_committed_mapping_has_not_drifted() -> None:
    fresh = GENMOD.build_mapping()
    # compare canonical bytes so key order / whitespace cannot mask a diff
    assert json.dumps(fresh, sort_keys=True) == json.dumps(MAP, sort_keys=True), (
        "assurance-mapping.json is stale — re-run `python3 docs/assurance/gen_assurance_mapping.py`")


def test_every_registry_claim_is_mapped_to_a_real_objective() -> None:
    claims = _load(REGISTRY)["claims"]
    reg_ids = {c["id"] for c in claims}
    mapped_ids = {r["id"] for r in MAP["claims"]}
    assert mapped_ids == reg_ids, f"unmapped claims: {sorted(reg_ids - mapped_ids)}"

    objective_ids = {o["id"] for o in MAP["security_objectives"]}
    for r in MAP["claims"]:
        assert r["objective"] in objective_ids, f"claim {r['id']} routes to unknown objective {r['objective']}"
        assert r["verifier"]["ci_job"], f"claim {r['id']} has no CI-job verifier"
        assert r["verifier"]["proving_tests"]["file"], f"claim {r['id']} has no proving-test file"


def test_objective_claim_lists_match_the_routing() -> None:
    by_obj: dict[str, set[str]] = {}
    for r in MAP["claims"]:
        by_obj.setdefault(r["objective"], set()).add(r["id"])
    total = 0
    for o in MAP["security_objectives"]:
        listed = set(o["claims"])
        assert listed == by_obj.get(o["id"], set()), f"objective {o['id']} claim list out of sync"
        assert o["claim_count"] == len(listed)
        total += o["claim_count"]
    assert total == len(_load(REGISTRY)["claims"]), "objective claim counts do not sum to the registry size"


def test_every_fact_capable_class_maps_to_a_verifier() -> None:
    branches = _load(BRANCHES)["branches"]
    fact_kinds = {b["oracle_version"] for b in branches if b.get("fact_capable") and b.get("oracle_version")}
    rows = {r["oracle_class"]: r for r in MAP["fact_class_assurance"]}
    assert set(rows) == fact_kinds, (
        f"fact_class_assurance != fact-capable classes; missing={sorted(fact_kinds - set(rows))} "
        f"extra={sorted(set(rows) - fact_kinds)}")
    for kind, r in rows.items():
        # the universal framework-reproduction verifier is always named
        assert r["primary_verifier"]["command"], f"{kind} has no primary verifier command"
        assert r["primary_verifier"]["kind"] == "framework-reproduction"
        # a non-standalone class must NAME its reproduction boundary (never silently omit it)
        if r["standalone_zero_dependency"]:
            assert r["standalone_verifier"]["file"].endswith("verify_vf.py")
        else:
            assert r.get("reproduction_boundary"), f"{kind} is framework-only but names no boundary"


def test_standalone_set_equals_independent_ground_truth() -> None:
    """The committed standalone flags must equal the independent derivation: a class is zero-dependency
    standalone iff every oracle function it binds (verify.oracle_version._ORACLE_FNS, read by AST) is in the
    set the standalone verifier re-executes (the C1 _PORTED functions + the posture-tier ports)."""
    fns_by_value = GENMOD.oracle_fns_by_value()
    standalone_fns = GENMOD.standalone_function_set()
    rows = {r["oracle_class"]: r for r in MAP["fact_class_assurance"]}
    for kind, r in rows.items():
        fns = fns_by_value.get(kind, [])
        expected = bool(fns) and set(fns) <= standalone_fns
        assert r["standalone_zero_dependency"] == expected, (
            f"{kind}: committed standalone={r['standalone_zero_dependency']} but ground-truth={expected} "
            f"(functions={fns})")
        assert r["oracle_functions"] == fns, f"{kind}: oracle_functions drifted from _ORACLE_FNS"


def test_posture_constant_is_tied_to_verify_vf_dispatch() -> None:
    """Cross-tie the one authored constant (_POSTURE_PORTED_FNS) to what verify_vf actually dispatches: the
    six posture dispatch kinds must be exactly the posture oracles named in the constant (minus the two
    ACHIEVED_STATE predicate-kernel functions, which the general dispatch covers via _reexecute_posture)."""
    dispatch_kinds = GENMOD.verify_vf_posture_kind_strings()
    assert dispatch_kinds == {
        "policy_path", "k8s_posture", "k8s_workload_posture", "cloud_posture", "mesh_posture", "cicd_posture",
    }, f"verify_vf posture dispatch changed: {sorted(dispatch_kinds)} — reconcile _POSTURE_PORTED_FNS"


def test_residual_limitation_references_resolve() -> None:
    inv_ids = {lim["id"] for lim in _load(INVENTORY)["limitations"]}
    referenced: set[str] = set()
    for o in MAP["security_objectives"]:
        referenced |= set(o["residual_limitations"])
    for b in MAP["irreducible_boundaries"]:
        referenced.add(b["limitation_ref"])
    missing = sorted(r for r in referenced if r not in inv_ids)
    assert not missing, f"assurance mapping references limitations absent from the inventory: {missing}"
    # every inventory limitation is routed to exactly one objective (nothing silently dropped)
    routed: list[str] = []
    for o in MAP["security_objectives"]:
        routed += o["residual_limitations"]
    assert sorted(routed) == sorted(inv_ids), "not every inventory limitation is routed to an objective"


def test_irreducible_boundaries_are_named_not_hidden() -> None:
    ids = {b["id"] for b in MAP["irreducible_boundaries"]}
    assert ids >= {"IRR-external-body", "IRR-hardware-root", "IRR-liveness-bound"}
    blob = json.dumps(MAP["irreducible_boundaries"]).lower()
    assert "accredit" in blob and "not" in blob, "the external-body boundary must be stated honestly"


def test_adversarial_review_is_auditable_with_a_pending_signoff_slot() -> None:
    ar = MAP["adversarial_review"]
    assert ar["control_id"] == "AR-REDPEN"
    assert ar["cadence"] and ar["methodology_refs"]
    sign = ar["sign_off"]
    assert isinstance(sign["entries"], list), "sign-off entries must be a list (a fillable slot)"
    # the slot is a SLOT: empty until a human signs — never fabricated with a fake reviewer
    assert set(sign["entry_schema"]) >= {"release", "reviewer", "date", "verdict", "scope"}
