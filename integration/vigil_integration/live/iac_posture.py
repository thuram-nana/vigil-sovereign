"""iac_posture — VIGIL-direct Infrastructure-as-Code posture FACT capability (Wave #4, CLOUD_POSTURE +
POLICY_PATH oracle families, the artifact-evidence column).

The IaC column of prove-don't-guess. VIGIL parses the target's OWN IaC artifact — Terraform APPLIED state (a
``.tfstate`` or a ``terraform show -json`` of state / a plan's ``prior_state``; never ``planned_values``), or
a PROCESSED CloudFormation template (JSON/YAML) — for the CONCRETE, RESOLVED state it REPRESENTS, normalises
it to the framework's native cloud inventory, and drives the deterministic ``cloud_posture`` + ``policy_path``
oracles over the retained evidence. HONEST SCOPE: a Terraform tfstate reflects REAL applied resources; a
CloudFormation template is a DEPLOYMENT DECLARATION (represented, not proof the stack was deployed, succeeded,
or is drift-free). Every FACT is bounded to the represented artifact (signed ``capture_method=artifact:<fmt>``),
never a live achieved-state claim — only a VIGIL-owned live query (Track B) supports that. A resource whose REPRESENTED state PROVABLY carries an insecure achieved fact (encryption-at-rest
explicitly disabled on a sensitive store, an explicit public flag, a LITERAL wildcard principal in a policy
document, an ACL/AccessControl literally granting AllUsers, a security-group ingress literally open to
``0.0.0.0/0``) mints a signed, offline-re-verifiable FACT; a firing anonymous IAM grant PATH mints a
POLICY_PATH FACT. Everything else is INCONCLUSIVE — never a labelled-clean negative (an IaC export is a
PARTIAL, represented state, so it can never prove ABSENCE).

EVIDENCE AUTHORITY (the whole point of this slice). A FACT here is a bounded claim about the PRIMARY
ARTIFACT VIGIL parsed — "this represented tfstate declares resource R public" / "this CloudFormation
template declares a wildcard principal on R" — NEVER a claim about live infrastructure, and NEVER a
scanner's say-so. checkov / terrascan / trivy are LEAD proposers only (they say WHERE to look); VIGIL's own
parse + the deterministic oracle is the sole authority. A tool's "this is public" never mints a FACT.

*** NEAR-ZERO-FP (BLOCKER-3) — the hard semantics this module exists for: ***
The claim is bounded to REPRESENTED / RESOLVED state, and an attribute is the oracle's achieved-state only
when it is UNAMBIGUOUS. Concretely:
  * ``public`` is set True ONLY for an achieved public grant that is LITERAL in the artifact: a policy
    document ``Principal: "*"`` / ``{"AWS": "*"}``, an S3 ACL / CloudFormation ``AccessControl`` of
    ``public-read`` / ``PublicRead(Write)``, or a security-group ingress ``CidrIp/cidr_blocks`` of
    ``0.0.0.0/0``. A ``block_public_access = false`` (a bucket-level toggle, NOT an achieved grant) leaves
    ``public`` UNKNOWN (None) — never True. A plan's DESIRED state (``planned_values``) is what an apply
    WOULD create, not the deployed reality, so it is NEVER read for a FACT — only APPLIED state (a tfstate, a
    ``terraform show -json`` of state, or a plan file's ``prior_state.values``) is.
  * ``encrypted`` is False ONLY on an EXPLICIT disable (``storage_encrypted``/``encrypted``/
    ``encryption_enabled`` literally false). A missing SSE block is UNKNOWN (None), not False.
  * ``sensitive`` is True ONLY from an explicit tag/attribute, never inferred from a name.
  * A CloudFormation intrinsic (``Ref`` / ``Fn::GetAtt`` / ``Fn::Sub`` / ``Fn::If`` / any ``Fn::*``) or an
    unresolved parameter is UNKNOWN: the grant is DROPPED and the flag set None. A literal ``Principal: "*"``
    is a real wildcard; ``Principal: {"Ref": "X"}`` is not.

ADMISSION, not a direct mint (Phase-D BLOCKER-1). This module DOES NOT call
``oracle_adapter.confirm_and_certify`` — that would let a verdict reach a certificate with no capability
check. Both IaC branches are declared ``clean_capable: false`` in ``docs/capability-matrix/
evidence-branches.json``, so a conclusive non-fire must be demoted to INCONCLUSIVE, never escape as CLEAN.
Mirroring ``sbom`` / ``web_redrive`` it runs the oracle to obtain ``(fired, conclusive)``, attributes the
outcome to the registered branch via ``verdict.admit(...)``, then lets ``oracle_adapter.certify_admitted``
mint ONLY what admission returned as a FACT. Admission decides, minting executes.

provenance="reproduced": the evidence is re-derived by VIGIL from the operator-supplied artifact bytes — a
non-LLM channel — so the anti-hallucination gate admits it. The artifact identity (sha256), collector id and
capture method are bound into the signed certificate (Phase-D D2).

RESOURCE-GOVERNED PARSING (charter rule 6). Every parse of operator bytes — the top-level artifact AND every
embedded IAM policy-document JSON string inside a Terraform attribute — goes through
``safe_parse.safe_json`` / ``safe_yaml`` with a ``ParseBudget``; NEVER raw ``json.loads`` / ``yaml.load``. A
malformed / oversized / bomb artifact yields a typed error, never a crash and never a laundered CLEAN.

FATAL-2: every framework import + the admission/mint import is FUNCTION-LOCAL; the parsers are pure stdlib
(only ``hashlib`` + the function-local ``safe_parse`` sibling), so importing this module co-loads no offense
engine.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .safe_parse import ParseBudget, safe_json, safe_yaml

# ------------------------------------------------------------------------------------------------------
# the TWO registered evidence branches this capability produces (docs/capability-matrix/
# evidence-branches.json). Both fact_capable:true (an unambiguous insecure achieved state / a real anon
# grant path is a FACT), clean_capable:false (a PARTIAL represented export cannot prove ABSENCE). Namespaced
# under ``iac.`` so they never collide with a bare cloud_posture / policy_path branch another slice adds.
# ------------------------------------------------------------------------------------------------------
_BRANCH_CLOUD = "iac.cloud_posture.achieved_state"
_BRANCH_POLICY = "iac.policy_path.iam_grant_path"

# A single parse budget for IaC artifacts (posture evidence is normally small; a bomb is refused, not hung).
_ARTIFACT_BUDGET = ParseBudget(max_bytes=8_000_000, max_depth=200, max_nodes=400_000, max_aliases=200)
# A tighter budget for an embedded policy-document JSON string inside a Terraform attribute.
_EMBEDDED_BUDGET = ParseBudget(max_bytes=1_000_000, max_depth=100, max_nodes=100_000, max_aliases=50)

# CloudFormation intrinsic function keys — a value carrying any of these is UNRESOLVED (near-zero-FP: an
# intrinsic Principal / CidrIp is NOT a literal wildcard and must never fire).
_INTRINSIC_KEYS = frozenset({
    "Ref", "Condition", "Fn::GetAtt", "Fn::Sub", "Fn::If", "Fn::ImportValue", "Fn::Join", "Fn::Select",
    "Fn::Split", "Fn::Base64", "Fn::FindInMap", "Fn::Cidr", "Fn::GetAZs", "Fn::Transform", "Fn::And",
    "Fn::Or", "Fn::Not", "Fn::Equals", "Fn::Length", "Fn::ToJsonString",
})

# Literal ACL / AccessControl values that grant AllUsers (an achieved public grant).
_PUBLIC_ACL = frozenset({"public-read", "public-read-write", "publicread", "publicreadwrite",
                         "authenticated-read", "authenticatedread"})
# Explicit encryption-toggle attribute names (a literal False on any is an EXPLICIT disable).
_ENCRYPTION_ATTRS = ("storage_encrypted", "encrypted", "encryption_enabled")
# Tag keys / values that EXPLICITLY mark data sensitivity (never inferred from a resource name).
_SENSITIVE_TAG_KEYS = frozenset({"sensitive", "confidential", "pii"})
_SENSITIVE_CLASS_KEYS = frozenset({"data_classification", "dataclassification", "classification",
                                   "dataclass", "data-classification", "sensitivity"})
_SENSITIVE_CLASS_VALS = frozenset({"sensitive", "confidential", "restricted", "secret", "pii", "private"})


# ==================================================================================================
# Result
# ==================================================================================================
@dataclass
class IacPostureResult:
    """The outcome of an IaC-posture verification pass over ONE artifact."""

    fmt: str                                          # "terraform" | "cloudformation"
    resources: int = 0                                # resources parsed from the artifact
    facts: list = field(default_factory=list)         # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)         # AdapterResult genuine LEAD (unmapped / unsupported)
    inconclusive: list = field(default_factory=list)  # AdapterResult outcome=="inconclusive" — NEVER clean
    admissions: list = field(default_factory=list)    # (branch_id, verdict, reason) — the admission trail
    contexts: dict = field(default_factory=dict)      # finding_ref -> oracle_context (offline re-verify)
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def family_verdict(self) -> str:
        """The conservative composition over every admitted branch outcome (see verdict.compose). An EMPTY
        admission set (no resource examined — a malformed/empty/no-config artifact) composes to
        INCONCLUSIVE, NOT CLEAN. Neither IaC branch is CLEAN-capable, so CLEAN can never appear here."""
        from .verdict import compose  # noqa: PLC0415 (FATAL-2: function-local, pure stdlib)
        return compose([v for _branch, v, _reason in self.admissions]).value


# ==================================================================================================
# near-zero-FP primitives — a value is the oracle's achieved-state ONLY when it is UNAMBIGUOUS
# ==================================================================================================
def _is_intrinsic(value: Any) -> bool:
    """A CloudFormation intrinsic / unresolved reference — its resolved value is UNKNOWN."""
    return isinstance(value, dict) and any(
        k in _INTRINSIC_KEYS or (isinstance(k, str) and k.startswith("Fn::")) for k in value)


def _tri_bool(value: Any) -> bool | None:
    """True / False / None(unknown). A bool/int is decisive; a string is read for an UNAMBIGUOUS token; an
    intrinsic or anything else (incl. absent) is UNKNOWN — so an absent or unresolved flag can never be
    mistaken for an EXPLICIT insecure setting."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "on", "enabled", "enable"):
            return True
        if v in ("false", "0", "no", "off", "disabled", "disable"):
            return False
    return None


def _is_literal_wildcard_principal(principal: Any) -> bool:
    """True ONLY for a LITERAL wildcard principal. ``"*"`` and ``{"AWS": "*"}`` (or a list containing ``*``)
    are real wildcards; an intrinsic (``{"Ref": "X"}``) is UNKNOWN, never a wildcard (BLOCKER-3)."""
    if isinstance(principal, str):
        return principal.strip() == "*"
    if isinstance(principal, list):
        return any(_is_literal_wildcard_principal(p) for p in principal)
    if isinstance(principal, dict):
        if _is_intrinsic(principal):
            return False                       # unresolved reference — not a literal wildcard
        # AWS/Service/CanonicalUser principal map: {"AWS": "*"} / {"AWS": ["*", ...]}
        return any(_is_literal_wildcard_principal(v) for v in principal.values())
    return False


def _statements(policy_doc: Any) -> list:
    """The Statement list of an IAM/resource policy document (accepts a single dict or a list)."""
    if not isinstance(policy_doc, dict):
        return []
    stmts = policy_doc.get("Statement")
    if isinstance(stmts, dict):
        return [stmts]
    return [s for s in stmts if isinstance(s, dict)] if isinstance(stmts, list) else []


def _wildcard_grants(policy_doc: Any) -> list[dict]:
    """Extract an anonymous grant for every ``Effect: Allow`` statement naming a LITERAL wildcard principal.
    An intrinsic principal is skipped (unresolved). Returns ``[{"principal": "*", "access": <action>}]``."""
    grants: list[dict] = []
    for st in _statements(policy_doc):
        # Only an EXPLICIT literal `Effect: "Allow"` may grant. A MISSING Effect, a Deny, a list, or an
        # intrinsic (Ref/Fn::*) is NOT an unambiguous Allow -> skip (red-pen B4: absent Effect was treated
        # as Allow). Never infer Allow.
        effect = st.get("Effect")
        if not (isinstance(effect, str) and effect.strip().lower() == "allow"):
            continue
        if _is_literal_wildcard_principal(st.get("Principal")):
            # Preserve the LITERAL Action faithfully; never fabricate one (red-pen H1: a list/missing/
            # intrinsic Action was invented as "read"). An unknown action -> "" (the wildcard-PRINCIPAL rule
            # still fires on the anonymous principal itself; policy_path cannot over-dominate on "").
            action = st.get("Action")
            if isinstance(action, str):
                acc = action
            elif isinstance(action, list) and action and all(isinstance(a, str) for a in action):
                acc = ",".join(action)
            else:
                acc = ""
            grants.append({"principal": "*", "access": acc})
    return grants


def _policy_documents(attrs: dict) -> list:
    """Every embedded IAM/resource policy DOCUMENT carried by a resource's attributes/properties. A
    Terraform ``policy`` attribute is a JSON STRING (operator bytes -> parse via governed ``safe_json``);
    a CloudFormation ``PolicyDocument`` / ``AssumeRolePolicyDocument`` is already a resolved dict."""
    docs: list = []
    for key in ("policy", "Policy", "PolicyDocument", "AssumeRolePolicyDocument", "policy_document"):
        val = attrs.get(key)
        if isinstance(val, str) and val.strip():
            parsed = safe_json(val, _EMBEDDED_BUDGET)     # governed: a bomb/oversize string -> error, skipped
            if parsed.ok and isinstance(parsed.value, dict):
                docs.append(parsed.value)
        elif isinstance(val, dict) and not _is_intrinsic(val):
            docs.append(val)
    return docs


def _public_acl(attrs: dict) -> bool:
    """A LITERAL ACL / AccessControl granting AllUsers (an achieved public grant)."""
    for key in ("acl", "AccessControl", "access_control"):
        val = attrs.get(key)
        if isinstance(val, str) and val.strip().lower() in _PUBLIC_ACL:
            return True
    return False


def _open_ingress(attrs: dict) -> bool:
    """A LITERAL security-group ingress open to ``0.0.0.0/0`` (or ``::/0``) ON this resource. An intrinsic
    CidrIp is UNKNOWN — never fires."""
    def _cidr_open(cidr: Any) -> bool:
        return isinstance(cidr, str) and cidr.strip() in ("0.0.0.0/0", "::/0")

    ingress_blocks: list = []
    for key in ("ingress", "SecurityGroupIngress"):
        val = attrs.get(key)
        if isinstance(val, list):
            ingress_blocks.extend(v for v in val if isinstance(v, dict))
        elif isinstance(val, dict):
            ingress_blocks.append(val)
    for rule in ingress_blocks:
        # Terraform: cidr_blocks:[...]; CloudFormation: CidrIp / CidrIpv6 (a single string)
        for k in ("cidr_blocks", "ipv6_cidr_blocks"):
            v = rule.get(k)
            if isinstance(v, list) and any(_cidr_open(c) for c in v):
                return True
        if _cidr_open(rule.get("CidrIp")) or _cidr_open(rule.get("CidrIpv6")):
            return True
    return False


def _encryption_state(attrs: dict) -> bool | None:
    """The UNAMBIGUOUS encryption-at-rest state, or None (unknown). An EXPLICIT disable wins over an explicit
    enable (conservative); a missing SSE block is UNKNOWN, never False. Only a literal False on a known
    encryption toggle is an insecure achieved state — the oracle fires solely on that + sensitive."""
    tri = [_tri_bool(attrs.get(key)) for key in _ENCRYPTION_ATTRS if key in attrs]
    if any(t is False for t in tri):
        return False
    if any(t is True for t in tri):
        return True
    return None


def _normalize_tags(raw: Any) -> dict:
    """A tag set as a lowercased ``{key: value}`` dict. Accepts a Terraform map (``{k: v}``) or a
    CloudFormation list (``[{"Key": k, "Value": v}]``)."""
    out: dict[str, str] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(k, str):
                out[k.strip().lower()] = v if isinstance(v, str) else v
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("Key"), str):
                out[item["Key"].strip().lower()] = item.get("Value")
    return out


def _sensitive(attrs: dict) -> bool:
    """True ONLY from an EXPLICIT tag/attribute — never inferred from a name."""
    if _tri_bool(attrs.get("sensitive")) is True:
        return True
    tags = _normalize_tags(attrs.get("tags") or attrs.get("Tags"))
    for k in _SENSITIVE_TAG_KEYS:
        if k in tags and _tri_bool(tags.get(k)) is True:
            return True
    for k in _SENSITIVE_CLASS_KEYS:
        v = tags.get(k)
        if isinstance(v, str) and v.strip().lower() in _SENSITIVE_CLASS_VALS:
            return True
    return False


# Resource types whose attribute semantics we read SCHEMA-FAITHFULLY for the near-zero-FP rules. A resource
# of any other type contributes NO achieved-state signal — a lookalike `acl`/`encrypted`/`policy` attribute
# on an unrelated or custom resource (a different provider, a Helm/null/local resource) must NOT be misread
# as an achieved public/unencrypted grant (red-pen H4). Keyed to Terraform types and (lowercased)
# CloudFormation type names. Unknown/unsupported -> no FACT.
_SUPPORTED_RESOURCE_TYPES = frozenset({
    # Terraform (AWS) object/data stores + policy carriers where acl/policy/encryption are schema-faithful:
    "aws_s3_bucket", "aws_s3_bucket_policy", "aws_s3_bucket_acl", "aws_db_instance", "aws_rds_cluster",
    "aws_dynamodb_table", "aws_ebs_volume", "aws_efs_file_system", "aws_sqs_queue", "aws_sns_topic",
    "aws_kms_key", "aws_iam_role", "aws_iam_policy", "aws_iam_role_policy",
    # CloudFormation equivalents (type names lowercased for the match):
    "aws::s3::bucket", "aws::s3::bucketpolicy", "aws::rds::dbinstance", "aws::rds::dbcluster",
    "aws::dynamodb::table", "aws::ec2::volume", "aws::efs::filesystem", "aws::sqs::queue", "aws::sns::topic",
    "aws::kms::key", "aws::iam::role", "aws::iam::policy",
})


def _resource_record(rid: str, attrs: dict, *, kind: str = "") -> dict:
    """Build ONE native-inventory resource record from a resource's resolved attributes/properties, applying
    the near-zero-FP rules. Only UNAMBIGUOUS signals on a SUPPORTED resource type are attached; an unknown
    flag is simply absent (None), and an unsupported resource type contributes NOTHING."""
    rec: dict[str, Any] = {"id": rid}
    ktype = (kind or "").strip().lower()
    if ktype not in _SUPPORTED_RESOURCE_TYPES:
        # No schema-faithful rule for this type -> attach no achieved-state signal -> no FACT (red-pen H4).
        return rec
    rec["kind"] = "datastore" if any(t in ktype for t in (
        "bucket", "s3", "db", "rds", "dynamodb", "efs", "ebs", "storage", "sqs", "sns")) else "cloud_resource"
    grants: list[dict] = []
    for pol in _policy_documents(attrs):
        grants.extend(_wildcard_grants(pol))
    if grants:
        rec["grants"] = grants
    # H5: an achieved PUBLIC signal is a literal anonymous-DATA grant only (a bucket policy Principal:"*" via
    # grants, or an ACL granting AllUsers). A security-group 0.0.0.0/0 INGRESS is NOT that — it declares
    # network reachability on some port/protocol/direction, not that anonymous principals can read the data,
    # so it does NOT set `public` (that conflation over-claimed a vuln). A structural SG-exposure FACT, with
    # port/protocol, is a distinct future branch.
    if _public_acl(attrs):
        rec["public"] = True
    enc = _encryption_state(attrs)
    if enc is not None:
        rec["encrypted"] = enc
    if _sensitive(attrs):
        rec["sensitive"] = True
    return rec


# ==================================================================================================
# parsers — Terraform (plan-JSON / tfstate) and CloudFormation (JSON / YAML). Native inventory shape:
#   {"provider": str, "principals": [], "resources": [{id, public?, encrypted?, sensitive?, grants[]}]}
# BOTH Terraform inputs are JSON — we do NOT attempt raw HCL eval. CloudFormation may be JSON or YAML.
# ==================================================================================================
def _tf_walk_module(module: Any, out: list) -> None:
    """Collect ``{address|type.name: values}`` resources from a plan-JSON root/child module (recursive)."""
    if not isinstance(module, dict):
        return
    for r in module.get("resources") or []:
        if not isinstance(r, dict):
            continue
        rtype = r.get("type")
        addr = r.get("address") or (f"{rtype}.{r.get('name')}" if rtype and r.get("name") else rtype)
        vals = r.get("values")
        if addr and isinstance(vals, dict):
            out.append((str(addr), vals, str(rtype or "")))
    for child in module.get("child_modules") or []:
        _tf_walk_module(child, out)


def _terraform_native(doc: dict) -> tuple[list[tuple[str, dict, str]], str]:
    """Extract ``(address, attributes, type)`` triples from a parsed Terraform document, reading ONLY APPLIED
    (achieved) state. Handles a tfstate (top-level ``resources[].instances[].attributes``) and a
    ``terraform show -json`` of STATE (top-level ``values.root_module``) and a plan-file's PRIOR state
    (``prior_state.values.root_module`` — the real infra as it existed before the plan).

    NEAR-ZERO-FP (BLOCKER-3): ``planned_values`` is DESIRED state — what an apply WOULD create — NOT the
    deployed reality, so it is NEVER read for an achieved-state FACT. A plan file that carries only
    ``planned_values`` (no state, no prior_state) yields ZERO resources here → no FACT (a plan proves nothing
    about live posture; export a tfstate or a `terraform show -json` of state instead)."""
    triples: list[tuple[str, dict, str]] = []
    # `terraform show -json` — read applied state only: top-level `values` (a state show) or a plan file's
    # `prior_state.values` (the pre-apply real state). `planned_values` (desired) is deliberately ignored.
    root = None
    if isinstance(doc.get("values"), dict):
        root = doc["values"]
    elif isinstance(doc.get("prior_state"), dict) and isinstance(doc["prior_state"].get("values"), dict):
        root = doc["prior_state"]["values"]
    if root is not None:
        rootmod = root.get("root_module") if isinstance(root, dict) else None
        _tf_walk_module(rootmod, triples)
        return triples, str(doc.get("terraform_version") or "")
    # A plan-only document (planned_values but no state/prior_state) → no achieved resources → no FACT.
    if isinstance(doc.get("planned_values"), dict) and "resources" not in doc:
        return triples, str(doc.get("terraform_version") or "")
    # tfstate (version 4) — resources[].instances[].attributes
    for r in doc.get("resources") or []:
        if not isinstance(r, dict):
            continue
        rtype, rname = r.get("type"), r.get("name")
        base = f"{rtype}.{rname}" if rtype and rname else str(rtype or rname or "")
        insts = r.get("instances")
        if not isinstance(insts, list):
            continue
        for i, inst in enumerate(insts):
            if not isinstance(inst, dict):
                continue
            attrs = inst.get("attributes")
            if isinstance(attrs, dict):
                addr = base if len(insts) == 1 else f"{base}[{i}]"
                triples.append((addr, attrs, str(rtype or "")))
    return triples, str(doc.get("terraform_version") or "")


def parse_terraform(text: "str | bytes") -> dict:
    """Parse a Terraform plan-JSON (``terraform show -json``) OR a ``.tfstate`` (BOTH JSON) into the native
    cloud inventory, applying the near-zero-FP rules. Governed parse (``safe_json``): a malformed / oversized
    / bomb document raises :class:`IacParseError`. Raw HCL is NOT accepted (there is no achieved state to
    read from unevaluated HCL) — only the JSON plan/state channels."""
    parsed = safe_json(text or "", _ARTIFACT_BUDGET)
    if not parsed.ok:
        raise IacParseError(f"terraform artifact parse failed: {parsed.reason}", reason=parsed.reason)
    doc = parsed.value
    if not isinstance(doc, dict):
        raise IacParseError("terraform artifact is not a JSON object", reason="malformed")
    triples, _ver = _terraform_native(doc)
    resources = [_resource_record(addr, attrs, kind=rtype) for addr, attrs, rtype in triples]
    provider = ""
    return {"provider": provider, "principals": [], "resources": resources}


def parse_cloudformation(text: "str | bytes") -> dict:
    """Parse a PROCESSED CloudFormation template (JSON or YAML) into the native cloud inventory from RESOLVED
    values only. Governed parse: ``safe_json`` first, then ``safe_yaml`` (SafeLoader — a short-form intrinsic
    tag like ``!Ref`` is refused as a typed error, the conservative outcome; use long-form ``{"Ref": ...}``
    in a processed template). A malformed / oversized / bomb document raises :class:`IacParseError`; an
    environment without PyYAML on a YAML-only input raises with reason ``yaml_unavailable``.

    Near-zero-FP: intrinsics (``Ref`` / ``Fn::*``) and unresolved parameters are UNKNOWN — the grant is
    dropped / the flag None. A literal ``Principal: "*"`` is a real wildcard."""
    pj = safe_json(text or "", _ARTIFACT_BUDGET)
    if pj.ok and isinstance(pj.value, dict):
        doc = pj.value
    else:
        py = safe_yaml(text or "", _ARTIFACT_BUDGET)
        if not py.ok:
            raise IacParseError(f"cloudformation artifact parse failed: {py.reason}", reason=py.reason)
        if not isinstance(py.value, dict):
            raise IacParseError("cloudformation artifact is not a mapping", reason="malformed")
        doc = py.value
    res_section = doc.get("Resources")
    resources: list[dict] = []
    if isinstance(res_section, dict):
        for logical_id, r in res_section.items():
            if not isinstance(r, dict):
                continue
            props = r.get("Properties") if isinstance(r.get("Properties"), dict) else {}
            resources.append(_resource_record(str(logical_id), props, kind=str(r.get("Type") or "")))
    return {"provider": "", "principals": [], "resources": resources}


class IacParseError(ValueError):
    """A governed parse of an IaC artifact failed (malformed / oversized / bomb / unsafe tag / yaml
    unavailable). Carries the safe_parse ``reason`` token. Fail-closed: never a laundered CLEAN."""

    def __init__(self, message: str, *, reason: str = "") -> None:
        super().__init__(message)
        self.reason = reason


# ==================================================================================================
# admission — run the oracle for (fired, conclusive) WITHOUT minting (mirrors sbom._oracle_signal)
# ==================================================================================================
def _oracle_signal(bug_class: str, oracle_context: dict) -> "tuple[bool, bool]":
    """Run the deterministic oracle over the retained context and return ``(fired, conclusive)`` WITHOUT
    minting — so admission sees the oracle's answer BEFORE any certificate exists. All framework imports are
    function-local (FATAL-2)."""
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


def iac_verify(
    artifact: "str | bytes",
    *,
    fmt: str,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    collector_id: str = "iac",
) -> IacPostureResult:
    """Parse ``artifact_text`` (``fmt`` in ``{"terraform", "cloudformation"}``), normalise to the native
    cloud inventory, and — THROUGH ADMISSION — mint a signed FACT for every resource whose REPRESENTED
    achieved state the ``cloud_posture`` oracle proves insecure (CLOUD_POSTURE, ``cloud_misconfiguration``)
    and for every firing anonymous IAM grant PATH the ``policy_path`` oracle re-derives over the retained
    graph (POLICY_PATH, ``privilege_path``).

    Admission decides, minting executes. For each candidate this runs the oracle for ``(fired, conclusive)``,
    calls ``verdict.admit(...)`` so the branch's declared ``clean_capable:false`` capability is applied, and
    only then ``oracle_adapter.certify_admitted`` (which mints ONLY a FACT). A conclusive non-fire is demoted
    to INCONCLUSIVE, never CLEAN. The artifact identity (sha256), collector id and capture method are bound
    into every signed certificate. Raises :class:`IacParseError` on a malformed/oversized/bomb artifact."""
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import admit  # noqa: PLC0415 (FATAL-2: function-local — pure stdlib module)

    if fmt not in ("terraform", "cloudformation"):
        return IacPostureResult(fmt=str(fmt), notes=[f"unsupported IaC format {fmt!r} "
                                                     f"(have: terraform, cloudformation)"])

    # B2: the artifact digest MUST be over the ORIGINAL bytes, not a re-encoding of a decoded str (which
    # diverges on UTF-16/BOM/newline/normalization). Hash the raw bytes and PARSE the SAME bytes (safe_json/
    # safe_yaml decode per the format's own rules). A str caller is accepted; its UTF-8 encoding is the raw.
    raw = artifact.encode("utf-8") if isinstance(artifact, str) else (artifact or b"")
    native = parse_terraform(raw) if fmt == "terraform" else parse_cloudformation(raw)

    # normalise (re-expresses public->anonymous grant so the achieved public fact is oracle-provable) — the
    # SAME normaliser the framework cloud sensor runs.
    from framework.v2.sensors.cloud import (  # noqa: PLC0415 (FATAL-2: function-local)
        confirm_cloud_posture_facts,
        normalize_cloud_export,
    )
    from framework.v2.verify.cloud_posture import cloud_posture_context  # noqa: PLC0415
    from framework.v2.verify.policy_path import build_policy_graph, policy_path_context  # noqa: PLC0415

    inv = normalize_cloud_export(native, "native")
    res = IacPostureResult(fmt=fmt, resources=len(inv.get("resources") or []))

    artifact_sha256 = hashlib.sha256(raw).hexdigest()   # B2: digest of the ORIGINAL bytes
    binding = {
        "artifact_sha256": artifact_sha256,
        "collector_id": collector_id,
        "capture_method": f"artifact:{fmt}",
        "completeness": "partial",   # an IaC export is a PARTIAL, represented state — never proves absence
    }
    observed = {"artifact_parsed": True}

    # --- CLOUD_POSTURE: per resource, over its ACHIEVED STATE alone -------------------------------------
    for r in inv.get("resources") or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        control = dict(r)
        oracle_context = cloud_posture_context(control)
        finding = {
            "check_id": f"iac:{fmt}:cloud_posture:{r['id']}",
            "bug_class": "cloud_misconfiguration",
            "insertion_point": f"iac:{fmt}:{r['id']}",
            "oracle_context": oracle_context,
        }
        fired, conclusive = _oracle_signal("cloud_misconfiguration", oracle_context)
        admitted = admit(_BRANCH_CLOUD, fired=fired, conclusive=conclusive, observed=observed)
        res.admissions.append((_BRANCH_CLOUD, admitted.verdict.value, admitted.reason))
        out = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                               provenance="reproduced", binding=binding)
        res.contexts[out.finding_ref] = oracle_context
        if out.is_fact:
            res.facts.append(out)
        elif out.outcome == "inconclusive":
            res.inconclusive.append(out)
        else:
            res.leads.append(out)

    # --- POLICY_PATH: per firing anonymous/over-privileged IAM grant path ------------------------------
    graph = build_policy_graph(inv)
    for pf in confirm_cloud_posture_facts(inv):
        principal, resource, access = pf.get("principal", ""), pf.get("resource", ""), pf.get("access", "")
        oracle_context = policy_path_context(graph, principal, resource, access)
        # Include ACCESS + a digest of the full (principal, resource, access) claim in the id: two distinct
        # grants sharing principal->resource but differing in access would otherwise collide and overwrite
        # res.contexts / the finding_ref (red-pen integrity finding).
        claim = hashlib.sha256(f"{principal}\x00{resource}\x00{access}".encode()).hexdigest()[:12]
        finding = {
            "check_id": f"iac:{fmt}:policy_path:{principal}->{resource}#{access or '-'}#{claim}",
            "bug_class": "privilege_path",
            "insertion_point": f"iac:{fmt}:{resource}",
            "oracle_context": oracle_context,
        }
        fired, conclusive = _oracle_signal("privilege_path", oracle_context)
        admitted = admit(_BRANCH_POLICY, fired=fired, conclusive=conclusive, observed=observed)
        res.admissions.append((_BRANCH_POLICY, admitted.verdict.value, admitted.reason))
        out = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                               provenance="reproduced", binding=binding)
        res.contexts[out.finding_ref] = oracle_context
        if out.is_fact:
            res.facts.append(out)
        elif out.outcome == "inconclusive":
            res.inconclusive.append(out)
        else:
            res.leads.append(out)

    return res
