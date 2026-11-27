"""AS-26 (OPS-1) — OFFLINE posture analyzer for the AEGIS staging CloudFormation templates.

cfn-lint proves the templates are well-formed CloudFormation; this analyzer proves the AS-26 SECURITY
POSTURE that cfn-lint does not express (spec §9.3 AS-26 row + §4/§5 boundary rules). It parses the
templates as the deployment DECLARATIONS they are and asserts, resource by resource, every invariant the
slice rests on:

  * IMDSv2 is ENFORCED on every launch template (MetadataOptions.HttpTokens == required);
  * the EIP sets are DISJOINT (B-5): the ``defense`` set and the ``z4-offense`` set share no allocation;
  * the TEST OWNER and TEST RELEASE KMS roots each DENY admin without MFA (the offline proxy for the
    "MFA sign-in" acceptance);
  * the Z3R relay role is KEYLESS (R3): it DENIES kms:Decrypt / secretsmanager:GetSecretValue;
  * no security group opens 0.0.0.0/0 ingress (the viewer path enters only through CloudFront);
  * paging (SNS, D32) and CloudFormation DRIFT detection (the Config managed rule) are present;
  * each tenant CloudFront distribution fronts the ALB through a VPC origin and injects the per-tenant
    edge secret as an origin header (so a direct-to-origin request carries none — CloudFront-bypass).

FAIL-CLOSED: a missing/weakened invariant is a Violation; an unreadable/unparseable template is a
Violation (never silently "clean"). Runnable as a CLI
(``python -m vigil_integration.aegis_infra_lint infra/aws/aegis-staging/*.cfn.yaml``; exit 1 on any
violation, 0 when clean), so it backs the ``aegis-infra`` advisory job alongside cfn-lint.

PyYAML is imported FUNCTION-LOCALLY so importing this module never requires it; the templates are plain
YAML (long-form intrinsics only), so a SafeLoader reads them. No sigil / framework / vigil_core import
(FATAL-2)."""
from __future__ import annotations

import ipaddress
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The privileged KMS admin actions an MFA Deny gate MUST cover to be meaningful. A Deny that names only a
# subset (e.g. kms:PutKeyPolicy alone) leaves ScheduleKeyDeletion/DisableKey/CreateGrant reachable without
# MFA, so the "MFA sign-in" posture it claims is a rubber stamp.
_MFA_GATED_ACTIONS = frozenset({
    "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:CreateGrant",
})


@dataclass
class Violation:
    template: str
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.template}: [{self.rule}] {self.detail}"


def _load_template(path: Path) -> "dict[str, Any] | Violation":
    """Parse one CloudFormation template to a dict with a SafeLoader. The long-form intrinsics the repo
    pins (Fn::Sub / Ref / Fn::GetAtt / Fn::If) are plain mappings, so SafeLoader reads them; a short-form
    ``!Ref`` tag would raise and become a Violation (fail-closed)."""
    import yaml  # noqa: PLC0415 (function-local so the module imports without PyYAML present)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return Violation(path.name, "unreadable", str(exc))
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return Violation(path.name, "unparseable", f"{type(exc).__name__}: {exc}")
    if not isinstance(doc, dict) or not isinstance(doc.get("Resources"), dict):
        return Violation(path.name, "no-resources", "template has no Resources mapping")
    return doc


def _dict(value: Any) -> "dict[str, Any]":
    """``value`` if it is a mapping, else an empty dict — a typed coercion so the posture rules never read
    an attribute off a non-mapping (fail-safe to 'absent', which every rule treats as a violation)."""
    return value if isinstance(value, dict) else {}


def _resources(doc: "dict[str, Any]", rtype: str) -> "list[tuple[str, dict[str, Any]]]":
    out: list[tuple[str, dict[str, Any]]] = []
    for lid, r in _dict(doc.get("Resources")).items():
        rd = _dict(r)
        if rd.get("Type") == rtype:
            out.append((str(lid), _dict(rd.get("Properties"))))
    return out


def _statements(policy: Any) -> "list[dict[str, Any]]":
    if not isinstance(policy, dict):
        return []
    stmts = policy.get("Statement")
    if isinstance(stmts, dict):
        return [stmts]
    return [s for s in stmts if isinstance(s, dict)] if isinstance(stmts, list) else []


def _as_list(value: Any) -> "list[Any]":
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


# ==================================================================================================
# per-template checks
# ==================================================================================================
def check_imdsv2(name: str, doc: "dict[str, Any]") -> "list[Violation]":
    """Every launch template enforces IMDSv2 (HttpTokens == required)."""
    out: list[Violation] = []
    for lid, props in _resources(doc, "AWS::EC2::LaunchTemplate"):
        data = _dict(props.get("LaunchTemplateData"))
        meta = _dict(data.get("MetadataOptions"))
        if meta.get("HttpTokens") != "required":
            out.append(Violation(name, "imdsv2", f"{lid}: MetadataOptions.HttpTokens must be 'required'"))
    return out


def check_disjoint_eips(name: str, doc: "dict[str, Any]") -> "list[Violation]":
    """The EIP sets are disjoint (B-5): the defense set and the z4-offense set share no allocation, and both
    are non-empty. Membership is read from the vigil:eip-set tag on each EIP."""
    out: list[Violation] = []
    sets: dict[str, set[str]] = {}
    for lid, props in _resources(doc, "AWS::EC2::EIP"):
        tagset = ""
        for tag in _as_list(props.get("Tags")):
            if isinstance(tag, dict) and tag.get("Key") == "vigil:eip-set":
                tagset = str(tag.get("Value"))
        if not tagset:
            out.append(Violation(name, "eip-untagged", f"{lid}: EIP has no vigil:eip-set tag"))
            continue
        sets.setdefault(tagset, set()).add(lid)
    if "defense" not in sets or "z4-offense" not in sets:
        out.append(Violation(name, "eip-sets", f"expected both 'defense' and 'z4-offense' EIP sets, got {sorted(sets)}"))
        return out
    overlap = sets["defense"] & sets["z4-offense"]
    if overlap:
        out.append(Violation(name, "eip-disjoint", f"EIP sets overlap (B-5 violated): {sorted(overlap)}"))
    return out


def _mfa_absent_value(raw: Any) -> bool:
    """True IFF ``raw`` is the deny-WHEN-ABSENT value for aws:MultiFactorAuthPresent, i.e. the string/bool
    ``false`` — a Deny conditioned on ``MultiFactorAuthPresent == false`` fires when MFA is NOT present, so
    it REQUIRES MFA. An inverted ``true`` gate fires only when MFA IS present (it denies the MFA'd admin and
    lets the un-MFA'd one through) and must be rejected."""
    if isinstance(raw, bool):
        return raw is False
    return isinstance(raw, str) and raw.strip().lower() == "false"


def _denies_without_mfa(props: "dict[str, Any]") -> bool:
    """A key policy carries a real MFA gate: a Deny statement whose Condition is a ``Bool``/``BoolIfExists``
    on ``aws:MultiFactorAuthPresent == false`` (deny-when-absent, NOT an inverted ``true``) AND whose Action
    set covers every privileged admin action in _MFA_GATED_ACTIONS."""
    for st in _statements(props.get("KeyPolicy")):
        if st.get("Effect") != "Deny":
            continue
        actions = {str(a) for a in _as_list(st.get("Action"))}
        if not _MFA_GATED_ACTIONS <= actions:        # the Deny must cover ALL the privileged admin actions
            continue
        cond = st.get("Condition")
        if not isinstance(cond, dict):
            continue
        for op, op_val in cond.items():
            if op not in ("Bool", "BoolIfExists") or not isinstance(op_val, dict):
                continue
            if _mfa_absent_value(op_val.get("aws:MultiFactorAuthPresent")):
                return True
    return False


def check_mfa_roots(name: str, doc: "dict[str, Any]") -> "list[Violation]":
    """The TEST OWNER and TEST RELEASE KMS roots each carry a Deny-without-MFA statement."""
    out: list[Violation] = []
    want = {"test-owner", "test-release"}
    seen: dict[str, bool] = {}
    for lid, props in _resources(doc, "AWS::KMS::Key"):
        root = ""
        for tag in _as_list(props.get("Tags")):
            if isinstance(tag, dict) and tag.get("Key") == "vigil:root":
                root = str(tag.get("Value"))
        if root in want:
            seen[root] = _denies_without_mfa(props)
            if not seen[root]:
                out.append(Violation(name, "mfa-root", f"{lid}: {root} key has no Deny-without-MFA statement"))
    # Only enforce presence in the template that actually declares the roots (10-keys-roles-ssm).
    if seen and want - set(seen):
        out.append(Violation(name, "mfa-root-missing", f"missing MFA-gated roots: {sorted(want - set(seen))}"))
    return out


def check_keyless_relay(name: str, doc: "dict[str, Any]") -> "list[Violation]":
    """The Z3R relay role is keyless (R3): it denies kms:Decrypt / secretsmanager:GetSecretValue."""
    out: list[Violation] = []
    for lid, props in _resources(doc, "AWS::IAM::Role"):
        is_relay = any(
            isinstance(t, dict) and t.get("Key") == "vigil:zone" and t.get("Value") == "z3r-relay"
            for t in _as_list(props.get("Tags")))
        if not is_relay:
            continue
        denied: set[str] = set()
        for pol in _as_list(props.get("Policies")):
            if not isinstance(pol, dict):
                continue
            for st in _statements(pol.get("PolicyDocument")):
                if st.get("Effect") == "Deny":
                    denied |= {str(a) for a in _as_list(st.get("Action"))}
        need = {"kms:Decrypt", "secretsmanager:GetSecretValue"}
        missing = need - denied
        if missing:
            out.append(Violation(name, "keyless-relay", f"{lid}: relay role does not Deny {sorted(missing)}"))
    return out


def _cidr_too_wide(cidr: Any) -> "str | None":
    """A detail string when ``cidr`` is a literal CIDR that is over-broad for an INTERNAL SG, else None. An
    intrinsic (a dict ``{Ref: ...}``), a prefix-list / SG-source (not a CIDR), or an absent value is None —
    never a false public grant. Coverage, not string-equality: ``0.0.0.0/1`` or ``0.0.0.0/8`` are caught the
    same as ``0.0.0.0/0``. IPv4 prefixlen <= 8 (and IPv6 <= 16) is "over-broad for an internal SG"; the real
    templates use /16, so a legitimate in-VPC rule is not flagged."""
    if not isinstance(cidr, str):
        return None
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    if net.version == 4 and net.prefixlen <= 8:
        return f"{cidr} (IPv4 /{net.prefixlen} <= /8 — over-broad for an internal SG)"
    if net.version == 6 and net.prefixlen <= 16:
        return f"{cidr} (IPv6 /{net.prefixlen} <= /16 — over-broad for an internal SG)"
    return None


def check_no_public_ingress(name: str, doc: "dict[str, Any]") -> "list[Violation]":
    """No security group ingress opens an over-broad CIDR; the viewer path enters only via CloudFront. Reads
    both INLINE ``SecurityGroupIngress`` rules AND standalone ``AWS::EC2::SecurityGroupIngress`` resources,
    and judges by CIDR COVERAGE (ipaddress), not string-equality, so ``0.0.0.0/1`` is caught as well as
    ``0.0.0.0/0``. A rule sourced from a prefix list / another SG carries no CIDR, so it is inherently
    internal and not flagged (no false positive)."""
    out: list[Violation] = []
    candidates: list[tuple[str, dict[str, Any]]] = []
    for lid, props in _resources(doc, "AWS::EC2::SecurityGroup"):
        for rule in _as_list(props.get("SecurityGroupIngress")):
            candidates.append((lid, _dict(rule)))
    for lid, props in _resources(doc, "AWS::EC2::SecurityGroupIngress"):
        candidates.append((lid, props))
    for lid, rule in candidates:
        for key in ("CidrIp", "CidrIpv6"):
            detail = _cidr_too_wide(rule.get(key))
            if detail:
                out.append(Violation(name, "public-ingress", f"{lid}: over-broad ingress {detail}"))
    return out


def _is_dynamic_secret_ref(value: Any) -> bool:
    """True IFF ``value`` is a secretsmanager DYNAMIC reference (``{{resolve:secretsmanager:...}}``), either
    as a bare string or wrapped in an intrinsic such as ``Fn::Sub`` (a dict whose string value carries it).
    A plain literal string is NOT a dynamic reference — rejecting it stops a secret being hard-coded into
    the template as the edge-secret header value."""
    if isinstance(value, str):
        return "{{resolve:secretsmanager:" in value
    if isinstance(value, dict):
        return any(isinstance(v, str) and "{{resolve:secretsmanager:" in v for v in value.values())
    return False


def check_cloudfront_edge(name: str, doc: "dict[str, Any]") -> "list[Violation]":
    """The SERVED origin (the one DefaultCacheBehavior.TargetOriginId names) is a VPC origin AND injects the
    per-tenant edge secret as a secretsmanager-resolved origin header. This is coupled on purpose: a secret
    injected on some OTHER, non-served origin, or a plain-literal secret value, does not protect the request
    that actually reaches the ALB (CloudFront-bypass)."""
    out: list[Violation] = []
    for lid, props in _resources(doc, "AWS::CloudFront::Distribution"):
        cfg = _dict(props.get("DistributionConfig"))
        target = _dict(cfg.get("DefaultCacheBehavior")).get("TargetOriginId")
        origins = [_dict(o) for o in _as_list(cfg.get("Origins"))]
        served = next((o for o in origins if o.get("Id") == target), None)
        if served is None:
            out.append(Violation(name, "cf-served-origin",
                                 f"{lid}: DefaultCacheBehavior.TargetOriginId {target!r} matches no origin"))
            continue
        if "VpcOriginConfig" not in served:
            out.append(Violation(name, "cf-vpc-origin", f"{lid}: served origin {target!r} is not a VPC origin"))
        headers = [_dict(h) for h in _as_list(served.get("OriginCustomHeaders"))]
        secret = next((h for h in headers if h.get("HeaderName") == "X-Vigil-Edge-Secret"), None)
        if secret is None:
            out.append(Violation(name, "cf-edge-secret",
                                 f"{lid}: served origin {target!r} injects no X-Vigil-Edge-Secret header"))
        elif not _is_dynamic_secret_ref(secret.get("HeaderValue")):
            out.append(Violation(name, "cf-edge-secret-plain",
                                 f"{lid}: X-Vigil-Edge-Secret is a plain literal, not a secretsmanager reference"))
    return out


def check_paging_and_drift(name: str, doc: "dict[str, Any]") -> "list[Violation]":
    """The ops template carries paging (SNS, D32) and CloudFormation drift detection (the Config rule)."""
    out: list[Violation] = []
    if not _resources(doc, "AWS::SNS::Topic"):
        out.append(Violation(name, "paging", "no SNS paging topic (D32)"))
    drift = any(
        _dict(props.get("Source")).get("SourceIdentifier") == "CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK"
        for _lid, props in _resources(doc, "AWS::Config::ConfigRule"))
    if not drift:
        out.append(Violation(name, "drift", "no CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK Config rule"))
    return out


# Per-template rule routing: a rule runs only on the template(s) that declare the relevant resource type,
# so a template that legitimately has no launch template / no EIP / no CloudFront is not failed for it.
def lint_template(path: Path) -> "list[Violation]":
    """Run every applicable AS-26 posture rule over ONE template. The universal rules (IMDSv2, no public
    ingress, disjoint EIPs, MFA roots, keyless relay, CloudFront edge) run only when the template declares
    the relevant resource type, so each template is judged on what it actually contains."""
    loaded = _load_template(path)
    if isinstance(loaded, Violation):
        return [loaded]
    name = path.name
    out: list[Violation] = []
    out += check_imdsv2(name, loaded)
    out += check_no_public_ingress(name, loaded)
    if _resources(loaded, "AWS::EC2::EIP"):
        out += check_disjoint_eips(name, loaded)
    if any(t.get("Value") == "test-owner" or t.get("Value") == "test-release"
           for _lid, p in _resources(loaded, "AWS::KMS::Key")
           for t in _as_list(p.get("Tags")) if isinstance(t, dict) and t.get("Key") == "vigil:root"):
        out += check_mfa_roots(name, loaded)
    out += check_keyless_relay(name, loaded)
    if _resources(loaded, "AWS::CloudFront::Distribution"):
        out += check_cloudfront_edge(name, loaded)
    if _resources(loaded, "AWS::Config::ConfigRule") or _resources(loaded, "AWS::SNS::Topic"):
        out += check_paging_and_drift(name, loaded)
    return out


def lint_paths(paths: "list[str]") -> "list[Violation]":
    out: list[Violation] = []
    for p in paths:
        out += lint_template(Path(p))
    return out


def _main(argv: "list[str]") -> int:
    if not argv:
        print("usage: python -m vigil_integration.aegis_infra_lint <template.cfn.yaml> ...", file=sys.stderr)
        return 2
    violations = lint_paths(argv)
    for v in violations:
        print(f"REFUSED: {v}", file=sys.stderr)
    if violations:
        print(f"aegis-infra posture: {len(violations)} violation(s)", file=sys.stderr)
        return 1
    print(f"aegis-infra posture: clean over {len(argv)} template(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
