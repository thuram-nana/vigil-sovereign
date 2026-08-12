"""Adjudicate REAL Kubernetes API evidence through the production confirmation path.

Driven by ``k8s_rbac_livefire.sh``, which creates a throwaway cluster we own, plants known-good and
known-bad RBAC configurations in it, and captures what the real API server returns. This module does the
part that matters: it feeds those real bytes to the same code that runs in a real assessment — the
deterministic oracle, the admission step, the certificate mint — and then checks the resulting certificate
by re-verifying it OFFLINE.

Every expectation below is asserted, so this exits non-zero if reality stops matching the claim. That is
deliberate: a live-fire script that only prints and never fails is a demo, not a proof.

The reduction from a raw API object to the retained evidence is written out explicitly here rather than
hidden, because a reader should be able to see that nothing is being smuggled in: only the binding's
subjects and its role reference, and (for TIER-2) the referenced role's own rules.
"""
from __future__ import annotations

import json
import os
import sys

WORK = os.environ["WORK"]
RBAC_GROUP = "rbac.authorization.k8s.io"


def _load(name: str) -> dict:
    with open(os.path.join(WORK, name), encoding="utf-8") as fh:
        return json.load(fh)


def _subjects(raw: dict) -> list:
    """The binding's subjects, carried faithfully. A subject's TYPE is load-bearing (a service account
    merely NAMED like the anonymous user is a different principal), so kind/name/namespace/apiGroup are
    all retained rather than flattened to a name."""
    return [
        {"kind": s.get("kind", ""), "name": s.get("name", ""),
         "namespace": s.get("namespace", ""), "api_group": s.get("apiGroup", "")}
        for s in (raw.get("subjects") or [])
    ]


def tier1_capture(raw: dict) -> dict:
    """TIER-1 evidence: the binding alone (subjects + which role it names)."""
    ref = raw["roleRef"]
    return {
        "resource_kind": raw["kind"].lower(),
        "name": raw["metadata"]["name"],
        "subjects": _subjects(raw),
        "role": ref.get("name"),
        "role_kind": ref.get("kind"),
        "role_apigroup": ref.get("apiGroup"),
    }


def tier2_control(raw_binding: dict, raw_role: dict) -> dict:
    """TIER-2 evidence: the binding AND, separately, the role it names — because a role reference is only
    a NAME. What that role actually permits lives in a different object, and TIER-2 reads it rather than
    assuming from the name. ``rules_source`` records that these rules came from a live read of the API."""
    ref = raw_binding["roleRef"]
    return {
        "check_id": raw_binding["metadata"]["name"],
        "binding": {
            "kind": raw_binding["kind"],
            "namespace": raw_binding["metadata"].get("namespace", ""),
            "name": raw_binding["metadata"]["name"],
            "subjects": _subjects(raw_binding),
            "role_ref": {"name": ref["name"], "kind": ref["kind"], "api_group": ref["apiGroup"]},
        },
        "role_object": {
            "name": raw_role["metadata"]["name"],
            "kind": raw_role["kind"],
            "api_group": RBAC_GROUP,
            "namespace": "",
            "rules": raw_role.get("rules") or [],
            "rules_source": "live_clusterrole_get",
        },
    }


def main() -> int:
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    from vigil_integration.live.k8s_rbac_verify import rbac_verify
    from vigil_integration.live.k8s_rbac_grant_verify import grant_verify
    from framework.v2.evidence.certify import verify_certificate

    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    trust = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])

    failures: list[str] = []

    def check(label: str, result, want_fact: bool) -> None:
        got = bool(result.is_fact)
        ok = got == want_fact
        mark = "OK " if ok else "!! "
        verdict = result.verdict + (" + signed certificate" if got else "")
        print(f"   {mark}{label:<52} {verdict}")
        if not ok:
            failures.append(f"{label}: expected {'a confirmed fact' if want_fact else 'NO fact'}, got {result.verdict}")
        if got:
            v = verify_certificate(result.certificate.signed,
                                   oracle_context=result.oracle_context, trust_root=trust)
            print(f"       offline re-verification of the certificate: {'PASS' if v.ok else 'FAIL'}")
            if not v.ok:
                failures.append(f"{label}: the signed certificate did not re-verify offline")

    print("\n   -- The binding on its own (TIER-1) --")
    check("anonymous user -> cluster-admin  [DANGEROUS]",
          rbac_verify(tier1_capture(_load("lf-anon-admin.json")), engagement_slug="livefire", signers=signers),
          want_fact=True)
    check("anonymous user -> view  [benign role]",
          rbac_verify(tier1_capture(_load("lf-anon-view.json")), engagement_slug="livefire", signers=signers),
          want_fact=False)
    check("named user 'alice' -> cluster-admin  [a real admin]",
          rbac_verify(tier1_capture(_load("lf-named-admin.json")), engagement_slug="livefire", signers=signers),
          want_fact=False)

    print("\n   -- Reading what the role actually permits (TIER-2) --")
    admin_role = _load("role-admin.json")
    # The built-in `admin` role is ASSEMBLED by a controller after the cluster starts, so its permissions
    # can legitimately be empty for a few seconds. An empty role would make the namespace-owner control
    # below pass for the WRONG reason — it would be unconfirmed because we read nothing, not because the
    # subject gate held. Refuse to draw a conclusion from evidence we did not actually get.
    admin_rules = admin_role.get("rules") or []
    if not admin_rules:
        print("   !! the built-in 'admin' role came back with no permissions — the cluster's role")
        print("      controller had not finished. Re-run; do not read a result into this.")
        return 1
    secret_rules = [r for r in admin_rules if "secrets" in (r.get("resources") or [])]
    verbs = secret_rules[0].get("verbs") if secret_rules else None
    print(f"   (for context: this cluster's real built-in 'admin' role grants {verbs} on Secrets)")

    check("anonymous -> cluster-admin, real */* rules  [DANGEROUS]",
          grant_verify(tier2_control(_load("lf-anon-admin.json"), _load("role-cluster-admin.json")),
                       engagement_slug="livefire", signers=signers),
          want_fact=True)
    check("default service account -> admin, one namespace",
          grant_verify(tier2_control(_load("lf-ns-owner.json"), admin_role),
                       engagement_slug="livefire", signers=signers),
          want_fact=False)

    print()
    if failures:
        print("   LIVE-FIRE FAILED:")
        for f in failures:
            print(f"     - {f}")
        return 1
    print("   All checks held against real cluster evidence.")
    print("   The dangerous configuration was confirmed and its certificate re-verified offline.")
    print("   Every benign configuration — including the common namespace-owner delegation, whose role")
    print("   really does grant Secret reads — was correctly left unconfirmed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
