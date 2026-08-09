"""k8s_posture — VIGIL-direct Kubernetes-posture FACT capability (Wave #4 A1, the two K8s oracle families).

The Kubernetes half of the primary-artifact prove-don't-guess ladder. VIGIL parses the operator's OWN k8s
posture ARTIFACTS — a kube-bench ``--json`` export and RBAC binding manifests — and drives the deterministic
``k8s_posture`` / ``k8s_workload_posture`` oracles over the RETAINED evidence. A control VIGIL can PROVE
insecure mints a signed, offline-re-verifiable FACT; anything else stays a LEAD or INCONCLUSIVE (never a
labelled-clean negative). Two things this module is NOT, and must never be read as:

  * It is NOT a claim about a LIVE cluster. Every FACT names the ARTIFACT VIGIL parsed — "this kube-bench
    export records control X FAILED with actual value Y", "this RBAC manifest declares an anonymous
    ClusterRoleBinding to cluster-admin" — never "the running cluster is X". The artifact is a bounded,
    point-in-time snapshot the operator handed us; a certificate binds its ``artifact_sha256`` so a reader
    can confirm WHICH bytes were adjudicated.
  * It is NOT a trust of the scanner. A kube-bench FAIL is a third-party CIS-checker's say-so — a PROPOSER
    of where to look. VIGIL's own parse + the ``k8s_posture_oracle`` re-derivation is the sole authority
    (the criterion-6 firewall): a FAIL whose observed value carries a SECURE flag, or a WARN, is a LEAD, not
    a FACT. Likewise an RBAC binding is a FACT only when VIGIL re-derives (anonymous subject ∧ dangerous
    BUILT-IN ClusterRole) over the retained binding — a namespaced Role merely NAMED ``edit`` does not fire.

Two FACT paths, both ADMISSION-ROUTED (Phase-D BLOCKER-1). Neither calls ``confirm_and_certify`` directly —
that would let a verdict reach a certificate with no capability check ever running. Each runs the oracle to
obtain ``(fired, conclusive)``, attributes the outcome to ONE registered evidence branch via
``verdict.admit(...)``, then lets ``oracle_adapter.certify_admitted`` mint ONLY what admission returned as a
FACT. Both branches are ``clean_capable: false``: a kube-bench export / RBAC manifest is a PARTIAL snapshot,
and absence of a firing control in a partial export is not absence of the weakness — so a conclusive non-fire
is demoted to INCONCLUSIVE rather than allowed to escape as CLEAN.

  (1) ``k8s_posture_verify`` — parse a kube-bench ``--json`` export with ``safe_parse.safe_json``, extract
      each CIS control, route it through ``k8s_posture_context`` and admit to branch
      ``k8s_posture.cis_control`` (bug_class ``k8s_misconfiguration``).
  (2) ``ingest_k8s_rbac`` — parse ClusterRoleBinding/RoleBinding YAML (multi-document) with
      ``safe_parse.safe_yaml_all``, reduce each to the shape ``from_k8s_workload_control`` consumes, and
      admit to branch ``k8s_workload_posture.rbac_binding`` (bug_class ``k8s_workload_misconfiguration``).

provenance="reproduced": the evidence is re-derived by VIGIL from the operator-supplied artifact bytes via a
non-LLM channel, so the anti-hallucination gate admits it. Each mint binds the artifact's ``sha256`` +
``completeness="partial"`` (D2) so the FACT is scoped to the exact bytes examined.

RESOURCE-GOVERNED PARSING: all operator bytes go through ``safe_parse`` (a byte cap, node/depth/alias bounds,
SafeLoader-only YAML, merge-key refusal) — never a raw ``json.loads`` / ``yaml.load``. A malformed / oversized
/ bomb artifact yields a typed parse error and NO adjudication (an absent parse is never a CLEAN).

FATAL-2: the framework + admission/mint imports are FUNCTION-LOCAL; the parsers + reducers are pure stdlib,
so importing this module co-loads no offense engine.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .safe_parse import ParseBudget, safe_json, safe_yaml_all

# The two registered evidence branches this capability produces (docs/capability-matrix/evidence-branches.json).
# Both fact_capable:true (a proven insecure control is a FACT), clean_capable:false (a partial artifact export
# cannot prove ABSENCE of the weakness). Each branch declares the precondition that VIGIL actually parsed the
# artifact — always true by the time a control reaches adjudication.
_CIS_BRANCH = "k8s_posture.cis_control"
_RBAC_BRANCH = "k8s_workload_posture.rbac_binding"

# The kinds of k8s workload binding this ingest adjudicates. Anything else in the manifest stream (a Role, a
# ClusterRole definition, a Deployment, a ConfigMap) is not a binding and is skipped — never guessed at.
_RBAC_BINDING_KINDS = frozenset({"clusterrolebinding", "rolebinding"})


@dataclass
class K8sPostureResult:
    """The typed outcome of one artifact ingest — facts + leads + inconclusive + the admission audit trail +
    retained contexts (for offline re-verify)."""

    artifact: str                                # which artifact family was parsed ("kube-bench" / "rbac")
    controls: int = 0                            # CIS controls / RBAC bindings VIGIL parsed and adjudicated
    facts: list = field(default_factory=list)     # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)     # AdapterResult status=="lead" (oracle fired, not FACT-capable
                                                  #   / unmapped class / LLM-provenanced)
    inconclusive: list = field(default_factory=list)  # AdapterResult outcome=="inconclusive" — NEVER clean
    admissions: list = field(default_factory=list)    # (branch_id, verdict, reason) — the admission audit trail
    contexts: dict = field(default_factory=dict)  # finding_ref -> oracle_context (offline re-verify)
    parse_error: str = ""                         # a safe_parse error/inconclusive reason ("" when parse ok)
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def family_verdict(self) -> str:
        """The conservative composition over every admitted branch outcome (see verdict.compose).

        An EMPTY set of admissions — a malformed/empty artifact, or one with no adjudicable control —
        composes to INCONCLUSIVE, NOT CLEAN: nothing examined is not the same as nothing found. Both branches
        are ``clean_capable: false``, so CLEAN can never appear here regardless."""
        from .verdict import compose  # noqa: PLC0415 (FATAL-2: function-local)
        return compose([v for _branch, v, _reason in self.admissions]).value


def _sha256(text: str | bytes) -> str:
    return hashlib.sha256(text.encode("utf-8") if isinstance(text, str) else text).hexdigest()


# --------------------------------------------------------------------------------------------------
# kube-bench --json extraction — pure stdlib. A kube-bench run emits {"Controls": [{"tests": [{"section",
# "results": [{"test_number", "status", "actual_value", "test_desc"}]}]}]} (one such object, or a list of
# them for multiple targets). We extract the STRUCTURAL fields the oracle judges; verbose scanner prose is
# left behind. Only a record with BOTH a check id AND a status is a control (never guessed from partial data).
# --------------------------------------------------------------------------------------------------
def _extract_kube_bench_controls(data: Any) -> list[dict]:
    """Normalize parsed kube-bench JSON into ``[{check_id, status, actual_value?, description?, section?}]``.

    Accepts the single-object form, a list of objects (multiple targets), and — defensively — a bare list of
    result records. Walks only the KNOWN kube-bench nesting (Controls -> tests -> results); it does not
    recurse arbitrarily, so a hostile document cannot steer the extraction. A result missing a test-number or
    a status is not a control and is skipped."""
    controls: list[dict] = []

    def _add_result(result: Any, section: str) -> None:
        if not isinstance(result, dict):
            return
        check_id = result.get("test_number") or result.get("id") or result.get("check_id")
        status = result.get("status")
        if not check_id or not status:
            return                     # a control needs an identity AND a verdict — never inferred
        control: dict[str, Any] = {"check_id": str(check_id), "status": str(status)}
        av = result.get("actual_value")
        if av not in (None, ""):
            control["actual_value"] = str(av)
        desc = result.get("test_desc") or result.get("description")
        if desc not in (None, ""):
            control["description"] = str(desc)
        sec = result.get("section") or section
        if sec not in (None, ""):
            control["section"] = str(sec)
        controls.append(control)

    def _add_object(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        for group in (obj.get("Controls") or []):
            if not isinstance(group, dict):
                continue
            for test in (group.get("tests") or []):
                if not isinstance(test, dict):
                    continue
                section = str(test.get("section") or "")
                for result in (test.get("results") or []):
                    _add_result(result, section)

    if isinstance(data, list):
        for obj in data:
            if isinstance(obj, dict) and "Controls" in obj:
                _add_object(obj)
            else:
                _add_result(obj, "")   # a bare list of result records
    elif isinstance(data, dict):
        _add_object(data)
    return controls


def k8s_posture_verify(
    kube_bench_text: str,
    *,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    budget: "ParseBudget | None" = None,
    collector_id: str = "kube-bench",
) -> K8sPostureResult:
    """Parse a kube-bench ``--json`` export and — THROUGH ADMISSION — mint a signed FACT for every CIS
    control the ``k8s_posture`` oracle PROVES carries a concrete insecure setting.

    Admission decides, minting executes. For each retained control this runs the oracle to get
    ``(fired, conclusive)``, calls ``verdict.admit(_CIS_BRANCH, ...)`` so the branch's declared capabilities
    apply, and only then calls ``oracle_adapter.certify_admitted`` (which mints ONLY a FACT verdict, binding
    the artifact ``sha256`` + ``completeness="partial"``). A kube-bench FAIL whose observed value shows the
    SECURE flag, a WARN, or a FAIL with no captured value all stay LEAD/INCONCLUSIVE — never a FACT, never a
    CLEAN. Returns a :class:`K8sPostureResult`."""
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import admit  # noqa: PLC0415 (FATAL-2: function-local — pure stdlib module)

    res = K8sPostureResult(artifact="kube-bench")
    parsed = safe_json(kube_bench_text, budget)
    if not parsed.ok:
        # A parse we could not complete (malformed / oversized / bomb / yaml unavailable) is a definite
        # negative about THE DOCUMENT — no control was examined, so nothing may be adjudicated (an absent
        # parse must never become a CLEAN).
        res.parse_error = parsed.reason
        res.notes.append(f"kube-bench export not parseable: {parsed.reason}")
        return res

    controls = _extract_kube_bench_controls(parsed.value)
    res.controls = len(controls)
    if not controls:
        res.notes.append("no kube-bench controls found in the export")
        return res

    artifact_sha = _sha256(kube_bench_text)
    binding = {
        "artifact_sha256": artifact_sha,
        "collector_id": collector_id,
        "completeness": "partial",       # a kube-bench export is a bounded snapshot — never a CLEAN basis
        "capture_method": "artifact:kube-bench",
    }
    for control in controls:
        from framework.v2.verify.k8s_posture import k8s_posture_context  # noqa: PLC0415
        oracle_context = k8s_posture_context(control)
        finding = {
            "check_id": f"k8s:cis:{control['check_id']}",
            "bug_class": "k8s_misconfiguration",
            "insertion_point": f"kube-bench:{control['check_id']}",
            "oracle_context": oracle_context,
        }
        # ADMISSION DECIDES, MINTING EXECUTES. Reaching here means VIGIL parsed a concrete control from the
        # export, so the ``kube_bench_parsed`` precondition holds by construction.
        fired, conclusive = _posture_signal(oracle_context, "k8s_misconfiguration")
        admitted = admit(_CIS_BRANCH, fired=fired, conclusive=conclusive,
                         observed={"kube_bench_parsed": True})
        res.admissions.append((_CIS_BRANCH, admitted.verdict.value, admitted.reason))
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="reproduced", binding=binding)
        res.contexts[r.finding_ref] = oracle_context
        _file_result(res, r)
    return res


# --------------------------------------------------------------------------------------------------
# RBAC manifest reduction — pure stdlib. A ClusterRoleBinding/RoleBinding manifest reduced to the shape
# from_k8s_workload_control consumes: {name, namespace?, role, role_kind, role_apigroup, subjects[]}.
# NEAR-ZERO-FP: role_kind / role_apigroup are carried FAITHFULLY from roleRef — NEVER defaulted to
# clusterrole / the RBAC apiGroup — so a namespaced Role NAMED "edit"/"admin" cannot be mistaken for the
# powerful BUILT-IN ClusterRole (the oracle only fires on a built-in ClusterRole in the RBAC apiGroup).
# --------------------------------------------------------------------------------------------------
def _reduce_rbac_binding(doc: Any) -> dict | None:
    """Reduce one parsed manifest document to the workload-control shape, or ``None`` if it is not an RBAC
    binding. ``subjects`` becomes the list of subject NAMES the oracle matches against the anonymous set
    (``system:anonymous`` / ``system:unauthenticated``)."""
    if not isinstance(doc, dict):
        return None
    kind = str(doc.get("kind") or "").strip()
    if kind.lower() not in _RBAC_BINDING_KINDS:
        return None

    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    name = str(metadata.get("name") or "").strip()
    namespace = str(metadata.get("namespace") or "").strip()

    role_ref = doc.get("roleRef") if isinstance(doc.get("roleRef"), dict) else {}
    # Carried FAITHFULLY — absent stays absent (None), never defaulted to a dangerous value.
    role = role_ref.get("name")
    role_kind = role_ref.get("kind")
    role_apigroup = role_ref.get("apiGroup")

    subjects: list[str] = []
    raw_subjects = doc.get("subjects")
    if isinstance(raw_subjects, (list, tuple)):
        for s in raw_subjects:
            if isinstance(s, dict) and s.get("name") not in (None, ""):
                subjects.append(str(s.get("name")))

    reduced: dict[str, Any] = {
        "check_id": f"{kind.lower()}:{namespace + '/' if namespace else ''}{name}" if name else kind.lower(),
        "resource_kind": kind.lower(),
        "subjects": subjects,
    }
    if name:
        reduced["name"] = name
    if namespace:
        reduced["namespace"] = namespace
    if role not in (None, ""):
        reduced["role"] = str(role)
    if role_kind not in (None, ""):
        reduced["role_kind"] = str(role_kind)
    if role_apigroup not in (None, ""):
        reduced["role_apigroup"] = str(role_apigroup)
    return reduced


def ingest_k8s_rbac(
    manifests_text: str,
    *,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    budget: "ParseBudget | None" = None,
    collector_id: str = "vigil-k8s-rbac",
) -> K8sPostureResult:
    """Parse a (multi-document) RBAC manifest stream and — THROUGH ADMISSION — mint a signed FACT for every
    binding the ``k8s_workload_posture`` oracle PROVES grants a dangerous BUILT-IN ClusterRole
    (cluster-admin / admin / edit) to an ANONYMOUS subject (system:anonymous / system:unauthenticated).

    Admission decides, minting executes: each binding is routed through ``k8s_workload_posture_context`` and
    admitted to ``_RBAC_BRANCH``, then ``certify_admitted`` mints ONLY a FACT (binding the manifest
    ``sha256`` + ``completeness="partial"``). NEAR-ZERO-FP by faithful ``role_kind``/``role_apigroup`` carry:
    a namespaced Role named ``edit``, an anonymous binding to a custom/non-dangerous role, or a binding with
    no anonymous subject all stay LEAD/INCONCLUSIVE — never a FACT, never a CLEAN. Returns a
    :class:`K8sPostureResult`."""
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import admit  # noqa: PLC0415 (FATAL-2: function-local — pure stdlib module)

    res = K8sPostureResult(artifact="rbac")
    parsed = safe_yaml_all(manifests_text, budget)
    if not parsed.ok:
        res.parse_error = parsed.reason
        res.notes.append(f"RBAC manifests not parseable: {parsed.reason}")
        return res

    bindings = [b for b in (_reduce_rbac_binding(doc) for doc in (parsed.value or [])) if b is not None]
    res.controls = len(bindings)
    if not bindings:
        res.notes.append("no ClusterRoleBinding/RoleBinding documents found in the manifest stream")
        return res

    artifact_sha = _sha256(manifests_text)
    binding_meta = {
        "artifact_sha256": artifact_sha,
        "collector_id": collector_id,
        "completeness": "partial",       # a manifest export is a bounded snapshot — never a CLEAN basis
        "capture_method": "artifact:k8s-manifest",
    }
    for control in bindings:
        from framework.v2.verify.k8s_workload_posture import k8s_workload_posture_context  # noqa: PLC0415
        oracle_context = k8s_workload_posture_context(control)
        finding = {
            "check_id": f"k8s:rbac:{control['check_id']}",
            "bug_class": "k8s_workload_misconfiguration",
            "insertion_point": f"rbac:{control['check_id']}",
            "oracle_context": oracle_context,
        }
        fired, conclusive = _posture_signal(oracle_context, "k8s_workload_misconfiguration")
        admitted = admit(_RBAC_BRANCH, fired=fired, conclusive=conclusive,
                         observed={"rbac_parsed": True})
        res.admissions.append((_RBAC_BRANCH, admitted.verdict.value, admitted.reason))
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="reproduced", binding=binding_meta)
        res.contexts[r.finding_ref] = oracle_context
        _file_result(res, r)
    return res


def _posture_signal(oracle_context: "dict", bug_class: str) -> "tuple[bool, bool]":
    """Run the deterministic posture oracle over the retained context and return ``(fired, conclusive)``
    WITHOUT minting anything — so admission sees the oracle's answer BEFORE any certificate exists (mirrors
    ``sbom._oracle_signal`` / ``web_redrive._oracle_signal``).

      * ``fired``      — an oracle fired at/above the verifier threshold: a kube-bench control provably
                         carries a dangerous flag, or an anonymous subject is bound to a dangerous built-in
                         ClusterRole.
      * ``conclusive`` — the oracle rendered a DECISIVE verdict (``probe_verdict`` == ``clean``, i.e. a
                         channel-confirmed negative) OR it fired. The posture oracles emit a non-conclusive
                         non-signal on a hardened control (a WARN, a secure flag, a non-anonymous binding),
                         so a hardened control is ``(False, False)`` → INCONCLUSIVE at admission. Even were
                         it conclusive, both branches are ``clean_capable: false``, so admission still
                         returns INCONCLUSIVE — the CLEAN escape this slice closes.

    All framework imports are function-local (FATAL-2)."""
    from framework.v2.scanner.engine import probe_verdict  # noqa: PLC0415
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result  # noqa: PLC0415
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    verifier = OracleVerifier()
    finding = {"bug_class": bug_class, "oracle_context": oracle_context}
    result = adjudicate_finding(finding, oracle_context, verifier)
    fired = confirmed_from_result(result, finding, verifier) is not None
    verdict, _kinds = probe_verdict(result)
    conclusive = fired or verdict == "clean"
    return fired, conclusive


def _file_result(res: K8sPostureResult, r: Any) -> None:
    """Bucket one AdapterResult into facts / inconclusive / leads (criterion-7 typed states)."""
    if r.is_fact:
        res.facts.append(r)
    elif r.outcome == "inconclusive":
        res.inconclusive.append(r)   # hardened / non-conclusive → NEVER a labelled-clean lead
    else:
        res.leads.append(r)          # a genuine LEAD (oracle fired but not FACT-capable / unmapped)
