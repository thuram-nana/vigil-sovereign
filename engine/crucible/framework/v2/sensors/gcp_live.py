"""
sensors.gcp_live — LIVE, read-only Google Cloud posture collection as a gated SENSOR (Phase C2 · GCP).

The GCP twin of ``sensors.cloud_live`` (AWS). It calls the Google Cloud control plane READ-ONLY at runtime
via the google-cloud SDKs and emits the SAME normalized native inventory those importers produce — so the
entire proven promotion path downstream (``cloud_observations`` leads, and the ``engage_fusion._reverify_cloud``
policy-path + achieved-state oracles, which are provider-AGNOSTIC) works UNCHANGED. GCP's ``allUsers`` /
``allAuthenticatedUsers`` members are already the anonymous principals the cloud oracle knows, so a public
Cloud-Storage bucket or a public project-IAM binding promotes to a ``public_exposure`` FACT with no new oracle.

Doctrine (identical to cloud_live, GCP-specialised):
  * PROVE-DON'T-GUESS / ORACLE AUTHORITY. The collector mints only a native inventory (LEADS). FACTs come
    solely from the existing deterministic oracles re-firing over the RETAINED export. The collector's own
    public determination is CONSERVATIVE over CONFIRMED state, and the raw signals (the IAM members, the
    Public-Access-Prevention value) are retained for audit.
  * AMBIENT CREDENTIALS, NEVER HANDED OVER. Credentials come from google-auth's Application Default
    Credentials chain — ``GOOGLE_APPLICATION_CREDENTIALS`` (the service-account JSON the operator sealed in
    the Cloud-credentials plane, materialised by the offense bridge), a gcloud user ADC, or the GCE/GKE
    metadata server. No secret is passed through args, argv, or the spine. No ADC ⇒ a clean fail-closed no-op.
  * GATED, FAIL-CLOSED, DECLARED == ACTUAL EGRESS. Tier-2 / ``ACTIVE_RECON``: the engagement must be entitled,
    and the Google control-plane hosts are declared in ``egress_hosts`` (the egress gate refuses the run
    unless the operator provisioned them in ``targets/<slug>/collector-hosts.txt`` — C1). SDK absent / no ADC
    / an API error ⇒ an honest ``ok=False`` no-op that mints nothing.
  * READ-ONLY. Only ``list``/``get`` calls (``list_buckets``, ``get_iam_policy``, bucket reload). The
    collector never writes to the operator's cloud.
  * DETERMINISM OF THE CORE. The live ``run`` is non-deterministic, but the response → native-inventory
    translation (``gcp_inventory_from_responses`` and its helpers) is a PURE, total function of the retained
    responses — unit-tested with recorded fixtures, no SDK and no network. That pure core feeds the oracles.

NEAR-ZERO-FP (the AWS lessons carried over):
  * A Cloud-Storage bucket is confirmed public only when an ``allUsers`` / ``allAuthenticatedUsers`` IAM
    member is bound AND Public-Access-Prevention is NOT ``enforced`` (the GCP analog of AWS Block-Public-
    Access). PAP ``enforced`` neutralises the public binding; PAP UNKNOWN (unreadable) → the public signal
    stays an un-promoted LEAD (conservative — no false public FACT). RESIDUAL (documented, not overclaimed):
    a bucket-level PAP of ``inherited`` defers to an org/folder policy this collector does not read, so an
    org-level enforcement is a residual the C3 active-reachability oracle definitively resolves.
  * Cloud Storage is always encrypted at rest by Google, so there is no unencrypted-bucket state to promote
    (``encrypted`` is left unknown — the encryption-at-rest FACT simply never fires for GCP; honest).
  * ``sensitive`` is set only when the operator LABELS the bucket (a ``data-classification`` / ``sensitive``
    label) — operator-declared, never fabricated.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import Observation
from .cloud import _is_anon, _load_export, cloud_observations

# GCP IAM members that denote "anyone" (public). `_is_anon` (sensors.cloud) already matches these after
# normalisation; named here for the public-binding scan.
_GCP_ANON_MEMBERS = frozenset({"allusers", "allauthenticatedusers"})
# Bucket-label keys the operator uses to DECLARE data sensitivity, and the values that mean "sensitive".
_SENSITIVITY_LABEL_KEYS = frozenset({"sensitive", "classification", "data-classification", "dataclassification"})
_SENSITIVE_LABEL_VALUES = frozenset({
    "true", "yes", "1", "sensitive", "confidential", "restricted", "secret", "pii", "high", "critical",
})
# The Google control-plane hosts the collector reaches (declared egress; the operator provisions these in
# collector-hosts.txt). Storage + Resource-Manager (project IAM) + the OAuth token endpoint.
_GCP_HOSTS: tuple[str, ...] = (
    "storage.googleapis.com", "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com", "oauth2.googleapis.com", "www.googleapis.com",
)


# ---------------------------------------------------------------------------
# pure translation: recorded google-cloud read-only responses -> native inventory
# (no SDK, no network — the deterministic, CI-tested core the oracles consume)
# ---------------------------------------------------------------------------


def _member_is_anon(member: Any) -> bool:
    """True iff a GCP IAM member string denotes anyone (``allUsers`` / ``allAuthenticatedUsers``)."""
    return _is_anon(str(member or ""))


def _sensitive_from_labels(labels: Any) -> bool | None:
    """True iff the operator LABELLED the bucket sensitive; ``None`` when no such label (unknown — never
    fabricated). Total."""
    if not isinstance(labels, dict):
        return None
    for k, v in labels.items():
        key = str(k or "").strip().lower().replace("_", "-")
        val = str(v or "").strip().lower()
        if key in _SENSITIVITY_LABEL_KEYS and val in _SENSITIVE_LABEL_VALUES:
            return True
    return None


def bucket_resource(entry: Any) -> dict | None:
    """Map ONE collected Cloud-Storage bucket record onto a native-inventory resource. ``entry``::

        {"name": "acme-public", "iam_members": ["allUsers", "user:a@b", …],
         "public_access_prevention": "enforced"|"inherited"|None, "labels": {"data-classification": "..."}}

    Returns a resource dict or ``None`` for a nameless entry. Pure + total. CONSERVATIVE, evidence-retaining:
    ``public`` (the promotable FACT flag + a synthesised anonymous grant) is set ONLY when an anon member is
    bound AND PAP is NOT ``enforced``; PAP ``enforced`` neutralises it and PAP UNKNOWN leaves the signal an
    un-promoted lead. The raw signals (``iam_public`` / ``public_access_prevention``) are retained for audit."""
    if not isinstance(entry, dict):
        return None
    name = str(entry.get("name") or "").strip()
    if not name:
        return None
    res: dict[str, Any] = {"id": name, "kind": "datastore"}
    members = entry.get("iam_members") if isinstance(entry.get("iam_members"), (list, tuple)) else []
    anon = [str(m) for m in members if _member_is_anon(m)]
    pap_raw = entry.get("public_access_prevention")
    pap = pap_raw.strip().lower() or None if isinstance(pap_raw, str) else None
    if anon:
        res["iam_public"] = True                     # raw signal retained (auditable)
    if pap:
        res["public_access_prevention"] = pap
    # confirmed public ONLY when an anon binding exists AND PAP does not enforce (and is known)
    if anon and pap is not None and pap != "enforced":
        res["public"] = True
        res["grants"] = [{"principal": "allUsers", "access": "read"}]
    sens = _sensitive_from_labels(entry.get("labels"))
    if sens is not None:
        res["sensitive"] = sens
    return res


def _project_iam_to_inventory(project_iam: Any) -> tuple[list[dict], list[dict]]:
    """From a project ``getIamPolicy`` response build (principals, resources). Each distinct member is a
    principal; a role bound to an ANONYMOUS member (``allUsers`` / ``allAuthenticatedUsers``) makes the
    PROJECT a public ``cloud_resource`` (the policy-path oracle re-derives the anonymous reach). Total."""
    principals: list[dict] = []
    resources: list[dict] = []
    if not isinstance(project_iam, dict):
        return principals, resources
    project = str(project_iam.get("project") or "").strip()
    bindings = project_iam.get("bindings") if isinstance(project_iam.get("bindings"), (list, tuple)) else []
    seen_members: set[str] = set()
    anon_roles: list[str] = []
    for b in bindings:
        if not isinstance(b, dict):
            continue
        role = str(b.get("role") or "").strip()
        for m in b.get("members") or []:
            m = str(m or "").strip()
            if not m:
                continue
            if _member_is_anon(m):
                anon_roles.append(role)
            elif m not in seen_members:
                seen_members.add(m)
                principals.append({"id": m, "kind": "principal"})
    if anon_roles and project:
        # the project is anonymously reachable (a public IAM binding) — a public over-broad-access resource
        resources.append({"id": f"projects/{project}", "kind": "cloud_resource", "public": True,
                          "grants": [{"principal": "allUsers", "access": "read"}],
                          "public_roles": sorted(set(anon_roles))[:16]})
    return principals, resources


def gcp_inventory_from_responses(
    *,
    buckets: Any = (),
    project_iam: Any = None,
    project: str = "",
) -> dict:
    """Assemble the native inventory (``{"provider":"gcp","principals","resources"}``) from the collector's
    retained read-only responses. PURE + total — the deterministic core every gcp_live test exercises and the
    provider-agnostic cloud oracles consume."""
    resources: list[dict] = []
    if not isinstance(buckets, (list, tuple)):
        buckets = ()
    for b in buckets:
        r = bucket_resource(b)
        if r is not None:
            resources.append(r)
    principals, iam_res = _project_iam_to_inventory(project_iam)
    resources.extend(iam_res)
    return {"provider": "gcp", "project": str(project or ""), "principals": principals, "resources": resources}


# ---------------------------------------------------------------------------
# the live sensor
# ---------------------------------------------------------------------------


class GcpLiveSensor:
    """Live, read-only GCP posture collector (Tier-2, ``ACTIVE_RECON``). Discovers the host's AMBIENT Google
    identity (Application Default Credentials), makes only list/get calls over Cloud Storage + project IAM,
    and emits the native inventory as ``{"export": <json>, "format": "native"}`` — the SAME shape the offline
    importer emits, so the existing normalize + fusion re-verify promote its leads with no downstream change.

    The project is resolved from the ADC (or ``GOOGLE_CLOUD_PROJECT`` / ``CLOUDSDK_CORE_PROJECT``). Fail-closed
    no-op when the google-cloud SDKs are absent, no ADC is discoverable, or the project cannot be resolved."""

    name = "gcp_live"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts = _GCP_HOSTS

    _MAX_BUCKETS = 500

    def __init__(self, *, project: str | None = None) -> None:
        self._project = (project or os.environ.get("GOOGLE_CLOUD_PROJECT")
                         or os.environ.get("CLOUDSDK_CORE_PROJECT") or "")

    # -- live read-only collection (non-deterministic; degrades cleanly) --

    @staticmethod
    def _safe(fn: Any, default: Any = None) -> Any:
        try:
            return fn()
        except Exception:
            return default

    def _collect_buckets(self, storage_client: Any) -> list[dict]:
        """Per-bucket read-only posture: IAM members + Public-Access-Prevention + labels. A per-bucket
        denial degrades that field (best-effort), never raising."""
        out: list[dict] = []
        buckets = self._safe(lambda: list(storage_client.list_buckets()), []) or []
        for b in buckets[: self._MAX_BUCKETS]:
            name = str(getattr(b, "name", "") or "").strip()
            if not name:
                continue
            rec: dict[str, Any] = {"name": name}
            policy = self._safe(lambda b=b: b.get_iam_policy(requested_policy_version=3))
            members: list[str] = []
            if policy is not None:
                for binding in self._safe(lambda p=policy: list(p.bindings), []) or []:
                    if isinstance(binding, dict):
                        members.extend(str(m) for m in (binding.get("members") or []))
            rec["iam_members"] = members
            # public_access_prevention lives on the bucket's iam_configuration (reload to be current)
            self._safe(lambda b=b: b.reload())
            iam_cfg = getattr(b, "iam_configuration", None)
            rec["public_access_prevention"] = str(
                getattr(iam_cfg, "public_access_prevention", "") or "") or None
            rec["labels"] = self._safe(lambda b=b: dict(getattr(b, "labels", {}) or {}), {})
            out.append(rec)
        return out

    def _collect_project_iam(self, project: str, credentials: Any) -> dict | None:
        """Project-level IAM policy (bindings), read-only. Returns None when Resource-Manager is unavailable
        or the call is denied — project IAM is then simply absent, bucket posture still returns."""
        try:
            from google.cloud import resourcemanager_v3  # optional dependency
        except Exception:
            return None

        def _pull() -> dict:
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            policy = client.get_iam_policy(resource=f"projects/{project}")
            bindings = [{"role": str(getattr(b, "role", "") or ""),
                         "members": [str(m) for m in getattr(b, "members", []) or []]}
                        for b in getattr(policy, "bindings", []) or []]
            return {"project": project, "bindings": bindings}

        return self._safe(_pull)

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        try:
            import google.auth  # optional dependency
        except Exception:
            return ToolResult(ok=False, note=(
                "gcp_live: google-auth not installed — live GCP collection unavailable (fail-closed no-op). "
                "Install google-cloud-storage + google-cloud-resource-manager to enable."))
        try:
            credentials, adc_project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"])
        except Exception as e:
            return ToolResult(ok=False, note=(
                "gcp_live: no ambient Google credentials discoverable (Application Default Credentials — a "
                "service-account JSON via GOOGLE_APPLICATION_CREDENTIALS, a gcloud ADC, or the metadata "
                f"server) — fail-closed no-op: {type(e).__name__}"))
        project = self._project or str(adc_project or "")
        if not project:
            return ToolResult(ok=False, note=(
                "gcp_live: could not resolve a GCP project (set GOOGLE_CLOUD_PROJECT or use a project-scoped "
                "credential) — fail-closed no-op."))
        try:
            from google.cloud import storage  # optional dependency
        except Exception:
            return ToolResult(ok=False, note="gcp_live: install google-cloud-storage to enable live GCP collection")
        try:
            buckets = self._collect_buckets(storage.Client(project=project, credentials=credentials))
        except Exception:
            buckets = []
        project_iam = self._safe(lambda: self._collect_project_iam(project, credentials))
        inventory = gcp_inventory_from_responses(buckets=buckets, project_iam=project_iam, project=project)
        n_res, n_pri = len(inventory.get("resources", [])), len(inventory.get("principals", []))
        return ToolResult(
            ok=True,
            summary=f"gcp_live: GCP project {project} — {n_res} resources, {n_pri} principals (read-only)",
            output={"export": json.dumps(inventory), "format": "native", "provider": "gcp", "project": project})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        """Identical to the offline importer's normalize — the export is the native inventory, minted as IAM
        topology + posture LEADS via the SHARED ``cloud_observations`` minter. The LEAD -> FACT promotion is
        the fusion re-verify's job, not the sensor's."""
        out = result.output or {}
        text, fmt = out.get("export"), out.get("format", "native")
        if not isinstance(text, str) or not text.strip():
            return []
        return cloud_observations(_load_export(text, fmt if isinstance(fmt, str) else "native"), seq=seq)
