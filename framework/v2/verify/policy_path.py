"""
verify.policy_path — build the retained IAM policy graph and confirm a privilege PATH.

The cloud-IAM half of prove-don't-guess (Wave 5a). A cloud/CSPM sensor (``sensors.cloud``) INGESTS an
operator's ScoutSuite/Prowler/provider export and mints "principal X is over-privileged / can reach
sensitive resource R" as a LEAD (``GROUNDING_INTEL``) — a heuristic judgement, never a fact. This turns
that lead into a FACT the same way ``verify.reachability`` turns a scanner's "open port" into one:
by RE-DERIVING it INDEPENDENTLY. Here the independent re-derivation is a pure graph search over the
RETAINED raw policy — a principal reaches a resource iff a concrete IAM grant path (assume/member hops
+ a dominating grant) exists — judged by the deterministic ``policy_path_oracle``.

Two properties make this a re-verification rather than a rubber-stamp of the sensor's say-so:

  * The graph is built from the RAW retained export (``build_policy_graph``), NOT from the sensor's
    minted world-model beliefs. The lead says "danger"; the oracle re-computes the exact grant path
    from ground-truth policy statements and fires only if one exists (a benign config does not confirm).
  * The retained policy graph is JSON-safe and the oracle is pure, so a confirmed path RE-VERIFIES
    OFFLINE from its certificate (``verify.reverify``) with no cloud and no trust in the sensor —
    re-run the search over the retained graph, get the same verdict, byte-for-byte.

Unlike ``reachability``/``tls`` there is NO active probe and NO gate here: the "capture" is a pure,
offline re-extraction of the operator's own retained policy (the gated step was the sensor ingest).
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def _nid(value: Any) -> str:
    """Canonical (lowercased, stripped) node key — matches ``intel.from_cloud`` and the oracle."""
    return str(value or "").strip().lower()


def build_policy_graph(inventory: Any) -> dict:
    """Re-derive the JSON-safe IAM policy graph from a (native-normalised) operator cloud export — the
    RETAINED evidence the policy-path oracle judges. Total and pure: malformed entries are skipped,
    never raised, so a bad export degrades to an empty graph (which confirms nothing).

    Input is the native inventory shape (``sensors.cloud`` normalises ScoutSuite/Prowler into it)::

        {"principals": [{"id", "can_assume": [...], "member_of": [...]}],
         "resources":  [{"id", "grants": [{"principal", "access"}]}]}

    Output — the graph the oracle re-searches::

        {"principals": [...ids], "resources": [...ids],
         "grants":    [{"principal", "resource", "access"}],
         "assume":    [{"src", "dst"}],      # src CAN_ASSUME dst
         "member_of": [{"src", "dst"}]}      # src MEMBER_OF dst
    """
    grants: list[dict[str, str]] = []
    assume: list[dict[str, str]] = []
    member_of: list[dict[str, str]] = []
    principals: list[str] = []
    resources: list[str] = []
    if not isinstance(inventory, Mapping):
        return {"principals": [], "resources": [], "grants": [], "assume": [], "member_of": []}

    for p in inventory.get("principals", []) or []:
        if not isinstance(p, Mapping) or not p.get("id"):
            continue
        pid = _nid(p["id"])
        principals.append(pid)
        for tgt in p.get("can_assume", []) or []:
            t = _nid(tgt)
            if t:
                assume.append({"src": pid, "dst": t})
        for grp in p.get("member_of", []) or []:
            g = _nid(grp)
            if g:
                member_of.append({"src": pid, "dst": g})

    for r in inventory.get("resources", []) or []:
        if not isinstance(r, Mapping) or not r.get("id"):
            continue
        rid = _nid(r["id"])
        resources.append(rid)
        for g in r.get("grants", []) or []:
            if not isinstance(g, Mapping) or not g.get("principal"):
                continue
            grants.append({"principal": _nid(g["principal"]), "resource": rid,
                           "access": str(g.get("access") or "")})

    # deterministic order (a pure function of the retained export, independent of dict iteration)
    return {
        "principals": sorted(dict.fromkeys(principals)),
        "resources": sorted(dict.fromkeys(resources)),
        "grants": sorted(grants, key=lambda x: (x["principal"], x["resource"], x["access"])),
        "assume": sorted(assume, key=lambda x: (x["src"], x["dst"])),
        "member_of": sorted(member_of, key=lambda x: (x["src"], x["dst"])),
    }


def privilege_path_query(graph: Mapping[str, Any], principal: str, resource: str,
                         access: str = "") -> dict:
    """Fold a reachability query (``principal`` reaches ``resource`` with ``access``) into a retained
    ``graph`` to form the ``observed_policy`` the oracle judges. ``access`` "" means "any grant path"."""
    return {
        "principal": _nid(principal), "resource": _nid(resource), "access": str(access or "").strip(),
        "grants": list(graph.get("grants") or []),
        "assume": list(graph.get("assume") or []),
        "member_of": list(graph.get("member_of") or []),
    }


def policy_path_context(graph: Mapping[str, Any], principal: str, resource: str,
                        access: str = "") -> dict:
    """The verifier context for a retained policy graph + query — routes to the policy-path oracle."""
    return FindingContext.from_policy_graph(
        privilege_path_query(graph, principal, resource, access)).to_verifier_context()


def confirm_privilege_path(graph: Mapping[str, Any], principal: str, resource: str,
                           access: str = "", *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge a privilege-path query with the deterministic oracle: ``confirmed`` iff a REAL IAM grant
    path lets ``principal`` reach ``resource`` (with ``access``) over the RETAINED policy ``graph``.
    The retained graph is JSON-safe, so the same verdict re-verifies offline from the finding's
    certificate via ``verify.reverify`` — no cloud, no trust in the sensor that ingested the export."""
    return (verifier or OracleVerifier()).confirm(policy_path_context(graph, principal, resource, access))
