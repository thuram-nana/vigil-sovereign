"""
sensors.gcp_live — LIVE, read-only Google Cloud posture collection as a gated SENSOR (Phase C2 · GCP).

The GCP twin of ``sensors.cloud_live`` (AWS). It calls the Google Cloud control plane READ-ONLY at runtime
via the google-cloud SDKs and emits the SAME normalized native inventory those importers produce — so the
provider-AGNOSTIC cloud oracles (``engage_fusion._reverify_cloud`` → policy-path / achieved-state) promote
its leads UNCHANGED. GCP's ``allUsers`` / ``allAuthenticatedUsers`` members are already the anonymous
principals the cloud oracle knows.

NEAR-ZERO-FP — the AWS lessons carried over correctly (the GCP collector was BLOCKed once for repeating both
AWS mistakes; this is the corrected build):
  * IAM CONDITIONS (the AWS trust-Condition lesson). A GCS/project IAM binding may carry an IAM ``condition``
    (time/resource-narrowed) — an anon member on a CONDITIONED binding is NOT unconditionally public. Only an
    UNCONDITIONED anon binding is treated as a public grant; a conditioned one is retained as an oracle-inert
    audit signal and NEVER promoted.
  * PUBLIC-ACCESS-PREVENTION is a TWO-SCOPE decision (the AWS both-BPA-scopes lesson). A bucket's own
    ``publicAccessPrevention`` is only ``enforced`` or ``inherited``; ``inherited`` does NOT mean "public
    allowed" — the effective state is decided by an ancestor ORG/folder policy. So a public bucket FACT is
    promoted ONLY when an UNCONDITIONED anon member is bound AND the bucket does not enforce PAP AND the
    EFFECTIVE org-policy PAP is READ and NOT enforcing. Bucket PAP ``enforced`` disproves; org PAP UNKNOWN
    (unreadable — e.g. no ``orgpolicy.policy.get``) → the public signal stays an un-promoted LEAD (conservative
    — err to a false-NEGATIVE, never a false public FACT). C3's active-reachability oracle definitively
    confirms where it matters.
  * PROJECT-IAM anon bindings are recorded as an auditable ``public_roles`` signal on the project resource but
    are NOT promoted to a FACT here — a project-level ``allUsers`` grant is itself subject to a domain-
    restricted-sharing org policy this collector does not resolve, so its confirmation is deferred (C3 / a
    follow-up), never asserted.
  * GCS is always encrypted at rest by Google → no unencrypted state to promote (encryption FACT never fires
    for GCP; honest). ``sensitive`` only when the operator LABELS the bucket.

Doctrine (identical to cloud_live): mints only a native inventory (LEADS); FACTs come solely from the
existing deterministic oracles re-firing over the RETAINED export; AMBIENT credentials (google-auth ADC —
the sealed service-account JSON materialised by the offense bridge / a gcloud ADC / the metadata server),
never handed over, no ADC/SDK ⇒ honest ``ok=False`` no-op; GATED Tier-2 ACTIVE_RECON with declared
``egress_hosts`` (incl. the metadata server); READ-ONLY list/get; the response → native-inventory
translation is a PURE, total, CI-tested function of the retained responses.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import Observation
from .cloud import _is_anon, _load_export, cloud_observations

# Bucket-label keys the operator uses to DECLARE data sensitivity, and the values that mean "sensitive".
_SENSITIVITY_LABEL_KEYS = frozenset({"sensitive", "classification", "data-classification", "dataclassification"})
_SENSITIVE_LABEL_VALUES = frozenset({
    "true", "yes", "1", "sensitive", "confidential", "restricted", "secret", "pii", "high", "critical",
})
# Google control-plane hosts the collector reaches (declared egress; operator provisions in collector-hosts.txt).
# Includes the org-policy service (effective PAP read) and the LINK-LOCAL metadata server, which google-auth's
# ADC hits on a GCE/GKE host to mint the ambient token — declared so the gate authorises exactly what runs.
_GCP_HOSTS: tuple[str, ...] = (
    "storage.googleapis.com", "cloudresourcemanager.googleapis.com", "iam.googleapis.com",
    "orgpolicy.googleapis.com", "oauth2.googleapis.com", "www.googleapis.com",
    "metadata.google.internal", "169.254.169.254",
)
# The org-policy boolean constraint that governs bucket public access.
_PAP_CONSTRAINT = "constraints/storage.publicAccessPrevention"


# ---------------------------------------------------------------------------
# pure translation: recorded google-cloud read-only responses -> native inventory
# (no SDK, no network — the deterministic, CI-tested core the oracles consume)
# ---------------------------------------------------------------------------


def _member_is_anon(member: Any) -> bool:
    """True iff a GCP IAM member string denotes anyone (``allUsers`` / ``allAuthenticatedUsers``)."""
    return _is_anon(str(member or ""))


def _anon_binding_kinds(iam_bindings: Any) -> tuple[bool, bool]:
    """(has_unconditioned_anon, has_conditioned_anon) over a list of IAM bindings, each
    ``{"members": [...], "conditioned": bool}``. A CONDITIONED anon binding is never unconditional public.
    Total: odd entries contribute nothing."""
    unconditioned = conditioned = False
    if not isinstance(iam_bindings, (list, tuple)):
        return unconditioned, conditioned
    for b in iam_bindings:
        if not isinstance(b, dict):
            continue
        members = b.get("members")
        members = members if isinstance(members, (list, tuple)) else []
        if any(_member_is_anon(m) for m in members):
            if b.get("conditioned"):
                conditioned = True
            else:
                unconditioned = True
    return unconditioned, conditioned


def _sensitive_from_labels(labels: Any) -> bool | None:
    """True iff the operator LABELLED the bucket sensitive; ``None`` when no such label. Total."""
    if not isinstance(labels, dict):
        return None
    for k, v in labels.items():
        key = str(k or "").strip().lower().replace("_", "-")
        val = str(v or "").strip().lower()
        if key in _SENSITIVITY_LABEL_KEYS and val in _SENSITIVE_LABEL_VALUES:
            return True
    return None


def bucket_resource(entry: Any, *, org_pap_enforced: Any = None) -> dict | None:
    """Map ONE collected Cloud-Storage bucket record onto a native-inventory resource. ``entry``::

        {"name": "acme-public", "iam_bindings": [{"members": ["allUsers", …], "conditioned": bool}, …],
         "public_access_prevention": "enforced"|"inherited"|None, "labels": {...}}

    ``org_pap_enforced`` is the EFFECTIVE org-policy PAP verdict (True enforced / False not-enforced / None
    unknown). Returns a resource dict or ``None`` for a nameless entry. Pure + total. CONSERVATIVE:
    ``public`` (the promotable FACT flag + a synthesised anonymous grant) is set ONLY when an UNCONDITIONED
    anon member is bound AND the bucket does NOT enforce PAP AND the org policy is READ and NOT enforcing.
    Otherwise the raw signals (``iam_public`` / ``conditioned_public`` / ``public_access_prevention``) are
    retained for audit and nothing is promoted."""
    if not isinstance(entry, dict):
        return None
    name = str(entry.get("name") or "").strip()
    if not name:
        return None
    res: dict[str, Any] = {"id": name, "kind": "datastore"}
    unconditioned_anon, conditioned_anon = _anon_binding_kinds(entry.get("iam_bindings"))
    pap_raw = entry.get("public_access_prevention")
    bucket_pap = pap_raw.strip().lower() or None if isinstance(pap_raw, str) else None
    if unconditioned_anon:
        res["iam_public"] = True                      # raw signal retained (auditable)
    if conditioned_anon:
        res["conditioned_public"] = True              # a narrowed anon binding — never promoted
    if bucket_pap:
        res["public_access_prevention"] = bucket_pap
    # CONFIRMED public only when BOTH PAP scopes are known-not-enforcing (bucket 'inherited' + org read False)
    if unconditioned_anon and bucket_pap == "inherited" and org_pap_enforced is False:
        res["public"] = True
        res["grants"] = [{"principal": "allUsers", "access": "read"}]
    sens = _sensitive_from_labels(entry.get("labels"))
    if sens is not None:
        res["sensitive"] = sens
    return res


def _project_iam_to_inventory(project_iam: Any) -> tuple[list[dict], list[dict]]:
    """From a project ``getIamPolicy`` response build (principals, resources). Each distinct non-anon member
    is a topology principal. An UNCONDITIONED anon member on any role is recorded as a ``public_roles`` raw
    signal on the project resource (auditable) — NOT promoted to a public FACT (a project-level ``allUsers``
    grant is itself subject to a domain-restricted-sharing org policy this collector does not resolve; its
    confirmation is deferred). Total."""
    principals: list[dict] = []
    resources: list[dict] = []
    if not isinstance(project_iam, dict):
        return principals, resources
    project = str(project_iam.get("project") or "").strip()
    bindings = project_iam.get("bindings")
    bindings = bindings if isinstance(bindings, (list, tuple)) else []
    seen_members: set[str] = set()
    public_roles: list[str] = []
    for b in bindings:
        if not isinstance(b, dict):
            continue
        role = str(b.get("role") or "").strip()
        conditioned = bool(b.get("conditioned"))
        members = b.get("members")
        members = members if isinstance(members, (list, tuple)) else []
        for m in members:
            m = str(m or "").strip()
            if not m:
                continue
            if _member_is_anon(m):
                if not conditioned and role:
                    public_roles.append(role)          # auditable signal only (not a promoted grant)
            elif m not in seen_members:
                seen_members.add(m)
                principals.append({"id": m, "kind": "principal"})
    if public_roles and project:
        resources.append({"id": f"projects/{project}", "kind": "cloud_resource",
                          "public_roles": sorted(set(public_roles))[:16]})   # NO public flag / grant → no FACT
    return principals, resources


def gcp_inventory_from_responses(
    *,
    buckets: Any = (),
    project_iam: Any = None,
    org_pap_enforced: Any = None,
    project: str = "",
) -> dict:
    """Assemble the native inventory (``{"provider":"gcp",…}``) from the retained read-only responses.
    PURE + total — the deterministic core every gcp_live test exercises and the cloud oracles consume.
    ``org_pap_enforced`` (True/False/None) is the effective org-policy PAP verdict applied to every bucket."""
    resources: list[dict] = []
    if not isinstance(buckets, (list, tuple)):
        buckets = ()
    for b in buckets:
        r = bucket_resource(b, org_pap_enforced=org_pap_enforced)
        if r is not None:
            resources.append(r)
    principals, iam_res = _project_iam_to_inventory(project_iam)
    resources.extend(iam_res)
    return {"provider": "gcp", "project": str(project or ""), "principals": principals, "resources": resources}


def org_pap_enforced_from_policy(policy: Any) -> bool | None:
    """Interpret an effective org-policy for ``constraints/storage.publicAccessPrevention`` (a BOOLEAN
    constraint) into True (enforced) / False (not enforced) / None (indeterminate). Pure + total. Accepts the
    JSON-shaped effective policy ``{"spec": {"rules": [{"enforce": true|false}, …]}}``: any rule enforcing →
    True; else if a rule explicitly does-not-enforce → False; else None (unknown — never assumed off)."""
    if not isinstance(policy, dict):
        return None
    spec = policy.get("spec") if isinstance(policy.get("spec"), dict) else policy
    rules = spec.get("rules") if isinstance(spec, dict) and isinstance(spec.get("rules"), (list, tuple)) else []
    saw_false = False
    for r in rules:
        if not isinstance(r, dict) or "enforce" not in r:
            continue
        if r.get("condition") is not None:
            continue                                  # a CONDITIONED rule is indeterminate — never read as OPEN
        if r.get("enforce") is True:
            return True                               # any unconditional enforce wins, regardless of order
        if r.get("enforce") is False:
            saw_false = True
    return False if saw_false else None


# ---------------------------------------------------------------------------
# the live sensor
# ---------------------------------------------------------------------------


class GcpLiveSensor:
    """Live, read-only GCP posture collector (Tier-2, ``ACTIVE_RECON``). Ambient ADC; read-only Cloud Storage
    + project IAM + the effective PAP org policy; emits the native inventory as
    ``{"export": <json>, "format": "native"}``. Fail-closed no-op when the SDKs are absent, no ADC is
    discoverable, or the project cannot be resolved."""

    name = "gcp_live"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts = _GCP_HOSTS

    _MAX_BUCKETS = 500

    def __init__(self, *, project: str | None = None) -> None:
        self._project = (project or os.environ.get("GOOGLE_CLOUD_PROJECT")
                         or os.environ.get("CLOUDSDK_CORE_PROJECT") or "")

    @staticmethod
    def _safe(fn: Any, default: Any = None) -> Any:
        try:
            return fn()
        except Exception:
            return default

    @staticmethod
    def _bindings_from_policy(policy: Any) -> list[dict]:
        """Reduce an IAM policy object (bucket or project) to ``[{"members":[...], "conditioned": bool}]``,
        preserving whether each binding carried an IAM ``condition``."""
        out: list[dict] = []
        for binding in GcpLiveSensor._safe(lambda: list(getattr(policy, "bindings", []) or []), []) or []:
            if isinstance(binding, dict):
                members = [str(m) for m in (binding.get("members") or [])]
                conditioned = binding.get("condition") is not None
            else:
                members = [str(m) for m in getattr(binding, "members", []) or []]
                conditioned = getattr(binding, "condition", None) is not None
            out.append({"members": members, "conditioned": bool(conditioned)})
        return out

    def _collect_buckets(self, storage_client: Any) -> list[dict]:
        out: list[dict] = []
        buckets = self._safe(lambda: list(storage_client.list_buckets()), []) or []
        for b in buckets[: self._MAX_BUCKETS]:
            name = str(getattr(b, "name", "") or "").strip()
            if not name:
                continue
            rec: dict[str, Any] = {"name": name}
            policy = self._safe(lambda b=b: b.get_iam_policy(requested_policy_version=3))
            rec["iam_bindings"] = self._bindings_from_policy(policy) if policy is not None else []
            self._safe(lambda b=b: b.reload())
            iam_cfg = getattr(b, "iam_configuration", None)
            rec["public_access_prevention"] = str(
                getattr(iam_cfg, "public_access_prevention", "") or "") or None
            rec["labels"] = self._safe(lambda b=b: dict(getattr(b, "labels", {}) or {}), {})
            out.append(rec)
        return out

    def _collect_project_iam(self, project: str, credentials: Any) -> dict | None:
        try:
            from google.cloud import resourcemanager_v3  # optional dependency
        except Exception:
            return None

        def _pull() -> dict:
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            policy = client.get_iam_policy(resource=f"projects/{project}")
            return {"project": project, "bindings": self._bindings_from_policy(policy)}

        return self._safe(_pull)

    def _collect_org_pap(self, project: str, credentials: Any) -> bool | None:
        """The EFFECTIVE PAP org-policy verdict for the project (True enforced / False not / None unknown).
        Read-only; unavailable SDK or a denied ``orgpolicy.policy.get`` → None (conservative — no confirm)."""
        try:
            from google.cloud import orgpolicy_v2  # optional dependency
        except Exception:
            return None

        def _pull() -> bool | None:
            client = orgpolicy_v2.OrgPolicyClient(credentials=credentials)
            eff = client.get_effective_policy(name=f"projects/{project}/policies/{_PAP_CONSTRAINT}")
            rules = [{"enforce": getattr(r, "enforce", None), "condition": getattr(r, "condition", None)}
                     for r in getattr(getattr(eff, "spec", None), "rules", []) or []]
            return org_pap_enforced_from_policy({"spec": {"rules": rules}})

        return self._safe(_pull)

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        try:
            import google.auth  # optional dependency
        except Exception:
            return ToolResult(ok=False, note=(
                "gcp_live: google-auth not installed — live GCP collection unavailable (fail-closed no-op). "
                "Install google-cloud-storage + google-cloud-resource-manager + google-cloud-org-policy."))
        try:
            credentials, adc_project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"])
        except Exception as e:
            return ToolResult(ok=False, note=(
                "gcp_live: no ambient Google credentials discoverable (Application Default Credentials) — "
                f"fail-closed no-op: {type(e).__name__}"))
        project = self._project or str(adc_project or "")
        if not project:
            return ToolResult(ok=False, note=(
                "gcp_live: could not resolve a GCP project (set GOOGLE_CLOUD_PROJECT) — fail-closed no-op."))
        try:
            from google.cloud import storage  # optional dependency
        except Exception:
            return ToolResult(ok=False, note="gcp_live: install google-cloud-storage to enable live GCP collection")
        org_pap = self._safe(lambda: self._collect_org_pap(project, credentials))
        try:
            buckets = self._collect_buckets(storage.Client(project=project, credentials=credentials))
        except Exception:
            buckets = []
        project_iam = self._safe(lambda: self._collect_project_iam(project, credentials))
        inventory = gcp_inventory_from_responses(
            buckets=buckets, project_iam=project_iam, org_pap_enforced=org_pap, project=project)
        n_res, n_pri = len(inventory.get("resources", [])), len(inventory.get("principals", []))
        return ToolResult(
            ok=True,
            summary=(f"gcp_live: GCP project {project} — {n_res} resources, {n_pri} principals "
                     f"(read-only; org-PAP={'enforced' if org_pap else ('open' if org_pap is False else 'unknown')})"),
            output={"export": json.dumps(inventory), "format": "native", "provider": "gcp", "project": project})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        text, fmt = out.get("export"), out.get("format", "native")
        if not isinstance(text, str) or not text.strip():
            return []
        return cloud_observations(_load_export(text, fmt if isinstance(fmt, str) else "native"), seq=seq)
