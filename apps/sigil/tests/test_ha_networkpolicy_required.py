"""W16-20 — the Kubernetes NetworkPolicy is REQUIRED, not optional.

Without the ``vigil-sovereign-proxy-only`` NetworkPolicy, ANY in-cluster workload can reach
``vigil-sovereign:8733`` directly and scrape the owner token off the cockpit's token-free ``GET /`` — and
act as OWNER. So the policy must be a REQUIRED part of the deploy, not a line an operator can quietly skip.

These are pure file/logic checks (stdlib + PyYAML + the gate module — no sigil/offense imports, no live
cluster, no non-base subprocess), so they run in the required ``sigil-governor`` CI job that executes the
whole ``apps/sigil/tests/`` directory.

Each behavioural assertion is paired with a NEGATIVE CONTROL in the SAME run: a deliberately-broken policy
or deploy set is REJECTED by the exact checker that accepts the real one — proving the gate is not a
rubber stamp. The file as a whole FAILS on a tree without the fix (no gate module, no kustomization, no
deploy script).
"""
from __future__ import annotations

import copy
import re
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[3]              # apps/sigil/tests -> apps/sigil -> apps -> repo
sys.path.insert(0, str(_REPO / "tools" / "ha"))
import require_networkpolicy as rnp  # noqa: E402  (path injected above; the module IS the fix under test)

_K8S = _REPO / "infra" / "ha" / "k8s"
_NETPOL = _K8S / "networkpolicy.yaml"
_KUSTOMIZATION = _K8S / "kustomization.yaml"
_README = _K8S / "README.md"
_DEPLOY = _REPO / "tools" / "ha" / "deploy.sh"
_HA_PROFILE = _REPO / "docs" / "architecture" / "HA-PROFILE.md"


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[>*`]", "", text)).strip().lower()


# --------------------------------------------------------------------------------------------------------
# 1. The manifest exists and actually DENIES the cross-workload path (+ negative control).
# --------------------------------------------------------------------------------------------------------

def test_networkpolicy_present_and_denies_cross_workload():
    assert _NETPOL.exists(), f"missing {_NETPOL}"
    found = rnp.find_sovereign_networkpolicy(_K8S)
    assert found is not None, "no NetworkPolicy governs the sovereign writer (app: vigil-sovereign)"
    path, doc = found
    ok, reason = rnp.networkpolicy_denies_cross_workload(doc)
    assert ok, f"the real NetworkPolicy must deny the cross-workload path, but: {reason}"


def test_deny_check_is_not_a_rubber_stamp_negative_control():
    """NEGATIVE CONTROL: mutate the real policy into each classic 'open door' and assert the SAME checker
    that just passed now REFUSES it. If any of these passed, the check would be a no-op."""
    _, real = rnp.find_sovereign_networkpolicy(_K8S)
    assert rnp.networkpolicy_denies_cross_workload(real)[0], "precondition: the real policy passes"

    # (a) an extra allow-all peer (empty podSelector selects EVERY pod in the namespace).
    allow_all = copy.deepcopy(real)
    allow_all["spec"]["ingress"][0]["from"].append({"podSelector": {}})
    ok, why = rnp.networkpolicy_denies_cross_workload(allow_all)
    assert not ok, "an empty-podSelector allow-all peer must be REJECTED"
    assert "allow-all" in why or "every pod" in why.lower()

    # (b) a bare namespaceSelector peer (admits every pod in the matched namespaces).
    ns_open = copy.deepcopy(real)
    ns_open["spec"]["ingress"][0]["from"].append({"namespaceSelector": {}})
    assert not rnp.networkpolicy_denies_cross_workload(ns_open)[0], "a bare namespaceSelector must be REJECTED"

    # (c) an ipBlock 0.0.0.0/0 peer (raw CIDR, not the proxy tier).
    ipblock = copy.deepcopy(real)
    ipblock["spec"]["ingress"][0]["from"].append({"ipBlock": {"cidr": "0.0.0.0/0"}})
    assert not rnp.networkpolicy_denies_cross_workload(ipblock)[0], "an ipBlock peer must be REJECTED"

    # (d) Ingress dropped from policyTypes (nothing is restricted at all).
    no_ingress_type = copy.deepcopy(real)
    no_ingress_type["spec"]["policyTypes"] = []
    assert not rnp.networkpolicy_denies_cross_workload(no_ingress_type)[0], "missing Ingress policyType must be REJECTED"

    # (e) the source relabelled away from the proxy tier.
    wrong_src = copy.deepcopy(real)
    wrong_src["spec"]["ingress"][0]["from"] = [{"podSelector": {"matchLabels": {"app": "some-other-app"}}}]
    assert not rnp.networkpolicy_denies_cross_workload(wrong_src)[0], "a non-proxy source must be REJECTED"


# --------------------------------------------------------------------------------------------------------
# 2. The NetworkPolicy is a REQUIRED part of the DEPLOY PATH: wired into the kustomization (+ neg control).
# --------------------------------------------------------------------------------------------------------

def test_networkpolicy_is_in_the_deploy_kustomization():
    assert _KUSTOMIZATION.exists(), f"missing {_KUSTOMIZATION} — the deploy set that cannot omit the policy"
    doc = next(d for d in yaml.safe_load_all(_KUSTOMIZATION.read_text(encoding="utf-8")) if isinstance(d, dict))
    assert doc.get("kind") == "Kustomization", "kustomization.yaml must be a Kustomization"
    resources = [Path(str(r)).name for r in (doc.get("resources") or [])]
    assert "networkpolicy.yaml" in resources, (
        "networkpolicy.yaml must be a resource of the kustomization so `kubectl apply -k` cannot omit it; "
        f"resources = {resources}")
    # The gate's own view agrees.
    assert rnp.kustomization_includes(_K8S, "networkpolicy.yaml") is True


def test_kustomization_inclusion_check_negative_control(tmp_path):
    """NEGATIVE CONTROL: a kustomization that LEAVES OUT the policy is reported as not-included."""
    (tmp_path / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
        "  - services.yaml\n  - sovereign-statefulset.yaml\n", encoding="utf-8")
    assert rnp.kustomization_includes(tmp_path, "networkpolicy.yaml") is False
    # And a dir with no kustomization at all is likewise not-included (not a crash).
    assert rnp.kustomization_includes(tmp_path / "does-not-exist", "networkpolicy.yaml") is False


# --------------------------------------------------------------------------------------------------------
# 3. The deploy GATE refuses to proceed without the policy / a controller (the core of "required").
# --------------------------------------------------------------------------------------------------------

def test_require_passes_on_the_real_tree_with_a_controller():
    # Positive: real manifests + a detected CNI ⇒ the gate lets the deploy proceed (no raise).
    rnp.require(_K8S, ["calico"], confirmed=False)


def test_require_refuses_when_networkpolicy_absent(tmp_path):
    """NEGATIVE CONTROL: a deploy set with NO sovereign NetworkPolicy is REFUSED even with a controller."""
    (tmp_path / "services.yaml").write_text("kind: Service\napiVersion: v1\nmetadata:\n  name: x\n", encoding="utf-8")
    with pytest.raises(rnp.NetworkPolicyRequirementError, match="no NetworkPolicy governing the sovereign"):
        rnp.require(tmp_path, ["calico"], confirmed=False)


def test_require_refuses_when_no_controller_and_not_confirmed():
    """NEGATIVE CONTROL: the real, correct policy is still REFUSED when the cluster has no NetworkPolicy
    controller to enforce it — an unenforced policy leaves the owner-token leak open."""
    with pytest.raises(rnp.NetworkPolicyRequirementError, match="no NetworkPolicy controller"):
        rnp.require(_K8S, [], confirmed=False)
    # The explicit out-of-band attestation is the ONLY way past that leg (and is deliberately loud).
    rnp.require(_K8S, [], confirmed=True)


def test_require_refuses_when_policy_present_but_not_in_kustomization(tmp_path):
    """NEGATIVE CONTROL: a correct policy file that is NOT wired into the kustomization is REFUSED — a
    `kubectl apply -k` could bring the cockpit up without it."""
    (tmp_path / "networkpolicy.yaml").write_text(_NETPOL.read_text(encoding="utf-8"), encoding="utf-8")
    # no kustomization.yaml at all
    with pytest.raises(rnp.NetworkPolicyRequirementError, match="not listed in"):
        rnp.require(tmp_path, ["calico"], confirmed=False)


# --------------------------------------------------------------------------------------------------------
# 4. The deploy SCRIPT gates before applying (structure), and the docs call it REQUIRED, never optional.
# --------------------------------------------------------------------------------------------------------

def test_deploy_script_runs_the_gate_before_apply():
    assert _DEPLOY.exists(), f"missing {_DEPLOY} — the gated deploy entrypoint"
    txt = _DEPLOY.read_text(encoding="utf-8")
    assert "set -euo pipefail" in txt, "deploy.sh must abort on the gate's non-zero exit"
    # Order the EXECUTABLE lines only — a `#`-comment mention of `kubectl apply` in the header must not be
    # mistaken for the command.
    code = "\n".join(ln for ln in txt.splitlines() if not ln.lstrip().startswith("#"))
    gate_at = code.find("require_networkpolicy.py")
    apply_at = code.find("kubectl apply")
    assert gate_at != -1, "deploy.sh must run the require_networkpolicy.py preflight"
    assert apply_at != -1, "deploy.sh must apply the stack"
    assert gate_at < apply_at, "the NetworkPolicy preflight must run BEFORE `kubectl apply`, not after"
    assert "networkpolicy vigil-sovereign-proxy-only" in code, "deploy.sh must confirm the policy actually landed"


@pytest.mark.parametrize("doc", [_README, _HA_PROFILE])
def test_docs_state_networkpolicy_required_not_optional(doc):
    assert doc.exists(), f"missing {doc}"
    norm = _norm(doc.read_text(encoding="utf-8"))
    assert "networkpolicy" in norm and "required" in norm, f"{doc.name} must state the NetworkPolicy is REQUIRED"
    # NEGATIVE CONTROL on the doc claim: the NetworkPolicy must never be described as optional. "optional"
    # may legitimately appear as "not optional" (the affirmation we want) or for the unrelated HPA, so we
    # flag it only when it sits near "networkpolicy" AND is NOT the "not optional" phrasing.
    for m in re.finditer(r"optional", norm):
        window = norm[max(0, m.start() - 80): m.start() + 80]
        if "networkpolicy" not in window:
            continue
        preceding = norm[max(0, m.start() - 4): m.start()]
        assert preceding == "not ", (
            f"{doc.name} describes the NetworkPolicy as optional near: ...{window}...")


def test_ha_profile_references_the_enforced_deploy():
    """The doc must reference the concrete deploy-time ENFORCEMENT artifact (tools/ha/deploy.sh) — the
    policy is required-in-the-path, not merely advised. Fails on the pre-fix tree whose §1.2 only said
    'Apply it; do not run the sovereign StatefulSet without it' with no enforcing deploy."""
    txt = _HA_PROFILE.read_text(encoding="utf-8")
    assert "tools/ha/deploy.sh" in txt, (
        "HA-PROFILE.md §1.2 must reference tools/ha/deploy.sh — the gated deploy that REFUSES to proceed "
        "without the NetworkPolicy / a controller — not just advise applying the policy by hand.")
