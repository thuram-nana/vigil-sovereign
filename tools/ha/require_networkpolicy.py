#!/usr/bin/env python3
"""VIGIL HA — the NetworkPolicy deploy GATE (issue W16-20).

The sovereign cockpit serves its OWN owner token at ``GET /`` **token-free** and the headless
``vigil-sovereign`` Service has no auth of its own, so ANY in-cluster workload that reaches
``vigil-sovereign:8733`` directly (bypassing the authenticating proxy) can scrape the owner token and act
as OWNER. The ``vigil-sovereign-proxy-only`` NetworkPolicy closes that network vector by restricting
ingress to the proxy pods. It is therefore **REQUIRED, not optional** — and this module is the gate that
makes it required in the DEPLOY PATH rather than merely advised in prose:

  * it verifies the NetworkPolicy manifest is PRESENT and actually DENIES the cross-workload path
    (proxy-only ingress — no allow-all peer sneaks a door open);
  * it verifies the manifest is LISTED in the kustomization, so ``kubectl apply -k`` cannot bring up the
    cockpit while silently omitting the policy; and
  * it REFUSES to proceed when the target cluster has **no NetworkPolicy controller (CNI)** — a
    NetworkPolicy object with no enforcing controller is silently unenforced, which is exactly the leak
    this closes. Fail-closed: no detected controller and no explicit ``--controller-confirmed`` override
    ⇒ refuse.

``tools/ha/deploy.sh`` runs this as a preflight before any ``kubectl apply``. The pure decision functions
(``find_sovereign_networkpolicy`` / ``networkpolicy_denies_cross_workload`` / ``kustomization_includes`` /
``require``) take the cluster's detected-controller list as an ARGUMENT so they are hermetically testable
with no live cluster — see apps/sigil/tests/test_ha_networkpolicy_required.py.

Stdlib + PyYAML only (both present in the sigil-governor CI install set).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

# The writer pod the policy must protect, and the ONLY source it may admit.
SOVEREIGN_APP = "vigil-sovereign"
PROXY_APP = "vigil-proxy"
COCKPIT_PORT = 8733
NETPOL_NAME = "vigil-sovereign-proxy-only"

# Known policy-ENFORCING CNIs. A NetworkPolicy is inert without one of these (or an equivalent). This list
# is used for best-effort live detection only; the pure gate takes the detected list as an argument.
KNOWN_CONTROLLER_MARKERS = (
    "calico",
    "cilium",
    "weave",
    "antrea",
    "kube-router",
    "canal",
    "ovn-kubernetes",
)


class NetworkPolicyRequirementError(RuntimeError):
    """Raised to REFUSE a deploy: the NetworkPolicy is absent, does not deny the cross-workload path, is
    not wired into the kustomization, or the cluster cannot enforce it."""


def _load_docs(path: Path) -> list[dict[str, Any]]:
    """Every mapping document in a (possibly multi-doc) YAML file. Comment-only docs parse to ``None`` and
    are dropped."""
    with path.open(encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]


def find_sovereign_networkpolicy(manifests_dir: Path) -> tuple[Path, dict[str, Any]] | None:
    """The NetworkPolicy governing ingress to the sovereign writer pod, or ``None`` if no manifest in
    ``manifests_dir`` declares one."""
    for path in sorted(manifests_dir.glob("*.yaml")):
        for doc in _load_docs(path):
            if doc.get("kind") != "NetworkPolicy":
                continue
            selector = (doc.get("spec", {}) or {}).get("podSelector", {}) or {}
            if (selector.get("matchLabels", {}) or {}).get("app") == SOVEREIGN_APP:
                return path, doc
    return None


def _peer_is_proxy_only(peer: dict[str, Any]) -> tuple[bool, str]:
    """A single ingress ``from`` peer admits ONLY the proxy tier — i.e. it is a podSelector pinned to
    ``app: vigil-proxy`` and nothing broader. Any other shape is an open door."""
    if "ipBlock" in peer:
        return False, f"an ipBlock peer {peer['ipBlock']} admits raw CIDRs, not just the proxy tier"
    if "namespaceSelector" in peer and "podSelector" not in peer:
        return False, "a bare namespaceSelector peer admits every pod in the matched namespace(s)"
    pod_sel = peer.get("podSelector")
    if pod_sel is None:
        return False, f"peer {peer!r} is not a podSelector pinned to the proxy tier"
    match = (pod_sel.get("matchLabels", {}) or {}) if isinstance(pod_sel, dict) else {}
    if not match:
        # {} / {matchLabels: {}} selects ALL pods in the namespace — the classic allow-all door.
        return False, "an empty podSelector peer selects EVERY pod in the namespace (allow-all)"
    if match.get("app") != PROXY_APP or len(match) != 1:
        return False, f"podSelector matchLabels {match!r} is not exactly {{app: {PROXY_APP}}}"
    return True, ""


def networkpolicy_denies_cross_workload(doc: dict[str, Any]) -> tuple[bool, str]:
    """Whether the NetworkPolicy actually denies the cross-workload path to the cockpit: it must govern
    ingress to the sovereign writer and admit ONLY the proxy tier on the cockpit port. Returns
    ``(ok, reason)`` — ``reason`` explains the first failure so the deploy gate can print it."""
    if doc.get("kind") != "NetworkPolicy":
        return False, f"not a NetworkPolicy (kind={doc.get('kind')!r})"
    spec = doc.get("spec", {}) or {}
    match = ((spec.get("podSelector", {}) or {}).get("matchLabels", {}) or {})
    if match.get("app") != SOVEREIGN_APP:
        return False, f"podSelector does not target the sovereign writer (app={match.get('app')!r})"
    if "Ingress" not in (spec.get("policyTypes") or []):
        return False, "policyTypes does not include Ingress — ingress is not restricted at all"
    ingress = spec.get("ingress")
    if not ingress:
        # policyTypes:[Ingress] with NO ingress rule is default-deny-all — safe, but this policy is meant
        # to ADMIT the proxy; an empty rule set here means the proxy is locked out too (a broken deploy).
        return False, "no ingress rule — the proxy tier itself would be locked out (misconfigured deny)"
    admits_proxy_on_port = False
    for rule in ingress:
        for peer in rule.get("from", []) or []:
            ok, why = _peer_is_proxy_only(peer)
            if not ok:
                return False, f"an ingress peer opens the cross-workload path: {why}"
        # At least one rule must admit the proxy tier on the cockpit port (else the policy denies EVERYTHING
        # including the proxy — again a broken deploy, not the intended proxy-only lock).
        ports = rule.get("ports")
        rule_has_proxy = any(_peer_is_proxy_only(p)[0] for p in (rule.get("from", []) or []))
        if rule_has_proxy and (ports is None or any(p.get("port") == COCKPIT_PORT for p in ports)):
            admits_proxy_on_port = True
    if not admits_proxy_on_port:
        return False, f"no rule admits the proxy tier on the cockpit port {COCKPIT_PORT}"
    return True, ""


def kustomization_includes(manifests_dir: Path, filename: str) -> bool:
    """Whether ``kustomization.yaml`` in ``manifests_dir`` lists ``filename`` as a resource — i.e. a single
    ``kubectl apply -k`` cannot omit it."""
    kustom = manifests_dir / "kustomization.yaml"
    if not kustom.exists():
        return False
    docs = _load_docs(kustom)
    if not docs:
        return False
    resources = docs[0].get("resources", []) or []
    return any(Path(str(r)).name == filename for r in resources)


def detect_networkpolicy_controllers() -> list[str]:
    """Best-effort live detection of a policy-enforcing CNI in the target cluster via ``kubectl``. Returns
    the markers found (e.g. ``["calico"]``); an empty list means *none detected* — the gate then
    fail-closes unless the operator confirms enforcement out of band. Any kubectl error/absence ⇒ ``[]``
    (fail closed)."""
    try:
        out = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-o",
             "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{'\\n'}{end}"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    haystack = out.stdout.lower()
    return [m for m in KNOWN_CONTROLLER_MARKERS if m in haystack]


def require(manifests_dir: Path, controllers: list[str], *, confirmed: bool = False) -> None:
    """REFUSE (raise :class:`NetworkPolicyRequirementError`) unless the NetworkPolicy is present, denies the
    cross-workload path, is wired into the kustomization, AND the cluster can enforce it. Returns ``None``
    on success. Pure: ``controllers`` is the cluster's detected-controller list, injected by the caller."""
    found = find_sovereign_networkpolicy(manifests_dir)
    if found is None:
        raise NetworkPolicyRequirementError(
            f"REFUSING TO DEPLOY: no NetworkPolicy governing the sovereign writer (app: {SOVEREIGN_APP}) "
            f"found under {manifests_dir}. It is REQUIRED — without it any in-cluster workload can scrape "
            f"the owner token off the cockpit's token-free GET /. Add infra/ha/k8s/networkpolicy.yaml.")
    path, doc = found
    ok, reason = networkpolicy_denies_cross_workload(doc)
    if not ok:
        raise NetworkPolicyRequirementError(
            f"REFUSING TO DEPLOY: {path.name} does not deny the cross-workload path: {reason}. The cockpit "
            f"must admit ONLY the {PROXY_APP} tier on port {COCKPIT_PORT}.")
    if not kustomization_includes(manifests_dir, path.name):
        raise NetworkPolicyRequirementError(
            f"REFUSING TO DEPLOY: {path.name} is not listed in {manifests_dir / 'kustomization.yaml'} — a "
            f"`kubectl apply -k` could bring up the cockpit while omitting the policy. The NetworkPolicy "
            f"must be a resource of the kustomization so it cannot be left out.")
    if not controllers and not confirmed:
        raise NetworkPolicyRequirementError(
            "REFUSING TO DEPLOY: no NetworkPolicy controller (CNI) detected in the target cluster. A "
            "NetworkPolicy object with no enforcing controller is SILENTLY UNENFORCED — the owner-token "
            "leak stays open. Install a policy-enforcing CNI (Calico/Cilium/Antrea/...), or, if you have "
            "verified enforcement out of band, re-run with --controller-confirmed "
            "(VIGIL_NETPOL_CONTROLLER_CONFIRMED=1).")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Gate the HA deploy on the REQUIRED sovereign NetworkPolicy.")
    ap.add_argument("--manifests", type=Path, default=Path(__file__).resolve().parents[2] / "infra" / "ha" / "k8s",
                    help="directory holding the HA k8s manifests + kustomization.yaml")
    ap.add_argument("--controller-confirmed", action="store_true",
                    help="attest (out of band) that the cluster enforces NetworkPolicy when auto-detection "
                         "cannot see a known CNI — otherwise the gate fail-closes.")
    args = ap.parse_args(argv)
    controllers = detect_networkpolicy_controllers()
    try:
        require(args.manifests, controllers, confirmed=args.controller_confirmed)
    except NetworkPolicyRequirementError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    detected = ", ".join(controllers) if controllers else ("(confirmed out of band)" if args.controller_confirmed else "none")
    print(f"OK: NetworkPolicy '{NETPOL_NAME}' present, denies the cross-workload path, wired into the "
          f"kustomization; controller: {detected}. Proceeding.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
