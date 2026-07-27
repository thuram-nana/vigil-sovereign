"""
sensors.azure_live — LIVE, read-only Microsoft Azure posture collection as a gated SENSOR (Phase C2 · Azure).

The Azure twin of ``sensors.cloud_live`` (AWS) / ``sensors.gcp_live`` (GCP). It calls the Azure Resource
Manager control plane READ-ONLY at runtime via the azure-mgmt SDKs and emits the SAME normalized native
inventory those importers produce — so the provider-AGNOSTIC cloud oracles promote its leads UNCHANGED.

Azure's public-exposure surface is ANONYMOUS blob access, which is a TWO-SCOPE decision exactly like AWS
Block-Public-Access and GCP Public-Access-Prevention: a blob container is anonymously readable only when the
container's ``publicAccess`` is ``Blob``/``Container`` AND the storage account's ``allowBlobPublicAccess`` is
enabled. So a container is confirmed public (an anonymous ``*`` grant the cloud oracle promotes to a
``public_exposure`` FACT) ONLY when BOTH scopes are read and permit it; the account setting UNKNOWN → an
un-promoted LEAD (conservative — err to a false-NEGATIVE, never a false public FACT).

Azure RBAC has NO anonymous/public principal (every assignment is an authenticated identity), so RBAC is
mapped to IAM TOPOLOGY only (principals) — there is no anonymous-public RBAC to confuse with the storage
public surface. Azure Storage is always encrypted at rest, so there is no unencrypted state to promote
(the encryption FACT never fires for Azure; honest). ``sensitive`` only when the operator TAGS the resource.

Doctrine (identical to cloud_live / gcp_live): mints only a native inventory (LEADS); FACTs come solely from
the existing deterministic oracles re-firing over the RETAINED export; AMBIENT credentials (azure-identity
``DefaultAzureCredential`` — the service principal the operator sealed in the Cloud-credentials plane
[AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET], or a managed identity), never handed over, no
credential/subscription ⇒ honest ``ok=False`` no-op; GATED Tier-2 ACTIVE_RECON with declared ``egress_hosts``
(ARM + AAD); READ-ONLY list/get; the response → native-inventory translation is a PURE, total, CI-tested
function of the retained responses.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import Observation
from .cloud import _load_export, cloud_observations

# Container publicAccess levels that expose blobs ANONYMOUSLY (no credential). "None"/"" is private.
_PUBLIC_ACCESS_LEVELS = frozenset({"blob", "container"})
# Tag keys the operator uses to DECLARE data sensitivity, and the values that mean "sensitive".
_SENSITIVITY_TAG_KEYS = frozenset({"sensitive", "classification", "data-classification", "dataclassification"})
_SENSITIVE_TAG_VALUES = frozenset({
    "true", "yes", "1", "sensitive", "confidential", "restricted", "secret", "pii", "high", "critical",
})
# The Azure control-plane hosts the collector reaches (declared egress; operator provisions in
# collector-hosts.txt). ARM (management) + AAD (token). The blob DATA plane is never touched (read-only ARM).
_AZURE_HOSTS: tuple[str, ...] = (
    "management.azure.com", "login.microsoftonline.com",
)


# ---------------------------------------------------------------------------
# pure translation: recorded azure-mgmt read-only responses -> native inventory
# (no SDK, no network — the deterministic, CI-tested core the oracles consume)
# ---------------------------------------------------------------------------


def _sensitive_from_tags(tags: Any) -> bool | None:
    """True iff the operator TAGGED the resource sensitive; ``None`` when no such tag. Total."""
    if not isinstance(tags, dict):
        return None
    for k, v in tags.items():
        key = str(k or "").strip().lower().replace("_", "-")
        val = str(v or "").strip().lower()
        if key in _SENSITIVITY_TAG_KEYS and val in _SENSITIVE_TAG_VALUES:
            return True
    return None


def container_resource(entry: Any, *, account_allows_public: Any = None) -> dict | None:
    """Map ONE collected blob container onto a native-inventory resource. ``entry``::

        {"id": "acct/container", "public_access": "None"|"Blob"|"Container", "tags": {...}}

    ``account_allows_public`` is the storage account's ``allowBlobPublicAccess`` (True/False/None-unknown).
    Returns a resource dict or ``None`` for an id-less entry. Pure + total. CONSERVATIVE: ``public`` (the
    promotable FACT flag + a synthesised anonymous grant) is set ONLY when the container's ``publicAccess`` is
    Blob/Container AND the account explicitly allows public blob access (``account_allows_public is True``).
    The account setting False neutralises it; UNKNOWN leaves it an un-promoted lead. The raw signals
    (``container_public`` / ``account_allows_public``) are retained for audit."""
    if not isinstance(entry, dict):
        return None
    rid = str(entry.get("id") or "").strip()
    if not rid:
        return None
    res: dict[str, Any] = {"id": rid, "kind": "datastore"}
    level = str(entry.get("public_access") or "").strip().lower()
    container_public = level in _PUBLIC_ACCESS_LEVELS
    if container_public:
        res["container_public"] = True                # raw signal retained (auditable)
    if account_allows_public is True or account_allows_public is False:
        res["account_allows_public"] = bool(account_allows_public)
    # CONFIRMED public only when BOTH scopes permit: the container is public AND the account allows it
    if container_public and account_allows_public is True:
        res["public"] = True
        res["grants"] = [{"principal": "*", "access": "read"}]
    sens = _sensitive_from_tags(entry.get("tags"))
    if sens is not None:
        res["sensitive"] = sens
    return res


def _rbac_principals(role_assignments: Any) -> list[dict]:
    """From Azure RBAC role assignments build IAM TOPOLOGY principals (the assigned identities). Azure RBAC
    has NO anonymous principal, so there is nothing public here — only who-can-act topology. Total: each
    distinct ``principal_id`` becomes one principal. Odd entries contribute nothing."""
    principals: list[dict] = []
    seen: set[str] = set()
    if not isinstance(role_assignments, (list, tuple)):
        return principals
    for a in role_assignments:
        if not isinstance(a, dict):
            continue
        pid = str(a.get("principal_id") or "").strip()
        if pid and pid not in seen:
            seen.add(pid)
            principals.append({"id": pid, "kind": "principal"})
    return principals


def azure_inventory_from_responses(
    *,
    containers: Any = (),
    account_public_by_id: Any = None,
    role_assignments: Any = None,
    subscription: str = "",
) -> dict:
    """Assemble the native inventory (``{"provider":"azure",…}``) from the retained read-only responses.
    PURE + total. ``account_public_by_id`` maps ``"<account>"`` -> its ``allowBlobPublicAccess`` (True/False/
    None); each container's id is ``"<account>/<container>"`` so the account scope is looked up per container."""
    account_public = account_public_by_id if isinstance(account_public_by_id, dict) else {}
    resources: list[dict] = []
    if not isinstance(containers, (list, tuple)):
        containers = ()
    for c in containers:
        if not isinstance(c, dict):
            continue
        account = str(c.get("id") or "").split("/", 1)[0]
        allows = account_public.get(account)
        r = container_resource(c, account_allows_public=allows)
        if r is not None:
            resources.append(r)
    principals = _rbac_principals(role_assignments)
    return {"provider": "azure", "subscription": str(subscription or ""),
            "principals": principals, "resources": resources}


# ---------------------------------------------------------------------------
# the live sensor
# ---------------------------------------------------------------------------


class AzureLiveSensor:
    """Live, read-only Azure posture collector (Tier-2, ``ACTIVE_RECON``). Ambient ``DefaultAzureCredential``;
    read-only Storage-account + blob-container + RBAC reads over Azure Resource Manager; emits the native
    inventory as ``{"export": <json>, "format": "native"}``. Fail-closed no-op when azure-identity /
    azure-mgmt-storage are absent, no credential is discoverable, or no subscription is resolvable."""

    name = "azure_live"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts = _AZURE_HOSTS

    _MAX_ACCOUNTS = 500

    def __init__(self, *, subscription: str | None = None) -> None:
        self._subscription = (subscription or os.environ.get("AZURE_SUBSCRIPTION_ID") or "")

    @staticmethod
    def _safe(fn: Any, default: Any = None) -> Any:
        try:
            return fn()
        except Exception:
            return default

    def _parse_account_id(self, resource_id: str) -> tuple[str, str]:
        """(resource_group, account_name) from an ARM storage-account id. Total: ('','') on an odd id."""
        parts = [p for p in str(resource_id or "").split("/") if p]
        rg = acct = ""
        for i, p in enumerate(parts):
            low = p.lower()
            if low == "resourcegroups" and i + 1 < len(parts):
                rg = parts[i + 1]
            if low == "storageaccounts" and i + 1 < len(parts):
                acct = parts[i + 1]
        return rg, acct

    def _collect_storage(self, storage_client: Any) -> tuple[list[dict], dict]:
        """Storage accounts (allowBlobPublicAccess) + their blob containers (publicAccess), read-only. A
        per-account/container denial degrades that datum, never raising."""
        containers: list[dict] = []
        account_public: dict[str, Any] = {}
        accounts = self._safe(lambda: list(storage_client.storage_accounts.list()), []) or []
        for acct in accounts[: self._MAX_ACCOUNTS]:
            rg, name = self._parse_account_id(getattr(acct, "id", "") or "")
            if not name:
                continue
            allow = getattr(acct, "allow_blob_public_access", None)
            account_public[name] = bool(allow) if isinstance(allow, bool) else None
            tags = self._safe(lambda a=acct: dict(getattr(a, "tags", {}) or {}), {})
            conts = self._safe(lambda rg=rg, name=name: list(
                storage_client.blob_containers.list(rg, name)), []) or []
            for cont in conts:
                cname = str(getattr(cont, "name", "") or "").strip()
                if not cname:
                    continue
                pub = getattr(cont, "public_access", None)
                containers.append({"id": f"{name}/{cname}",
                                   "public_access": str(pub) if pub is not None else "None",
                                   "tags": tags})
        return containers, account_public

    def _collect_rbac(self, credential: Any, subscription: str) -> list[dict]:
        """Azure RBAC role assignments (topology principals), read-only. Empty when the SDK is absent or the
        call is denied — RBAC topology is then simply absent, storage posture still returns."""
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient  # optional dependency
        except Exception:
            return []

        def _pull() -> list[dict]:
            client = AuthorizationManagementClient(credential, subscription)
            return [{"principal_id": str(getattr(a, "principal_id", "") or "")}
                    for a in client.role_assignments.list_for_subscription()]

        return self._safe(_pull, []) or []

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        if not self._subscription:
            return ToolResult(ok=False, note=(
                "azure_live: no subscription resolvable (set AZURE_SUBSCRIPTION_ID) — fail-closed no-op."))
        try:
            from azure.identity import DefaultAzureCredential  # optional dependency
        except Exception:
            return ToolResult(ok=False, note=(
                "azure_live: azure-identity not installed — live Azure collection unavailable (fail-closed "
                "no-op). Install azure-identity + azure-mgmt-storage + azure-mgmt-authorization."))
        try:
            credential = DefaultAzureCredential()
        except Exception as e:
            return ToolResult(ok=False, note=(
                f"azure_live: no ambient Azure credential discoverable (service principal / managed identity) "
                f"— fail-closed no-op: {type(e).__name__}"))
        try:
            from azure.mgmt.storage import StorageManagementClient  # optional dependency
        except Exception:
            return ToolResult(ok=False, note="azure_live: install azure-mgmt-storage to enable live Azure collection")
        try:
            containers, account_public = self._collect_storage(
                StorageManagementClient(credential, self._subscription))
        except Exception as e:
            return ToolResult(ok=False, note=(
                f"azure_live: Azure Storage enumeration failed — credential invalid/expired or access denied "
                f"(fail-closed): {type(e).__name__}"))
        role_assignments = self._safe(lambda: self._collect_rbac(credential, self._subscription), [])
        inventory = azure_inventory_from_responses(
            containers=containers, account_public_by_id=account_public,
            role_assignments=role_assignments, subscription=self._subscription)
        n_res, n_pri = len(inventory.get("resources", [])), len(inventory.get("principals", []))
        return ToolResult(
            ok=True,
            summary=f"azure_live: Azure subscription {self._subscription} — {n_res} resources, {n_pri} principals (read-only)",
            output={"export": json.dumps(inventory), "format": "native", "provider": "azure",
                    "subscription": self._subscription})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        text, fmt = out.get("export"), out.get("format", "native")
        if not isinstance(text, str) or not text.strip():
            return []
        return cloud_observations(_load_export(text, fmt if isinstance(fmt, str) else "native"), seq=seq)
