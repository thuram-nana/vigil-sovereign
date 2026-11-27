"""
sensors.azure_live — LIVE, read-only Microsoft Azure posture collection as a gated SENSOR (Phase C2 · Azure).

The Azure twin of ``sensors.cloud_live`` (AWS) / ``sensors.gcp_live`` (GCP). It calls the Azure Resource
Manager control plane READ-ONLY at runtime via the azure-mgmt SDKs and emits the SAME normalized native
inventory those importers produce — so the provider-AGNOSTIC cloud oracles promote its leads UNCHANGED.

Azure's INTERNET anonymous-blob exposure is a THREE-SCOPE decision (the AWS/GCP two-scope lesson, plus the
account network firewall): a blob container is anonymously reachable from the internet only when (1) the
container's ``publicAccess`` is ``Blob``/``Container``, AND (2) the storage account's ``allowBlobPublicAccess``
is enabled (the Block-Public-Access / Public-Access-Prevention analog), AND (3) the account's network is
internet-open — ``publicNetworkAccess`` is not ``Disabled`` and ``networkAcls.defaultAction`` is not ``Deny``
(a private-endpoint-only or firewalled account has no anonymous internet surface even with the two toggles on).
So a container is confirmed public (an anonymous ``*`` grant the cloud oracle promotes to a
``public_exposure`` FACT) ONLY when all three scopes are read and permit it; ``allowBlobPublicAccess`` False,
a network lock, or an UNKNOWN scope → an un-promoted LEAD (conservative — err to a false-NEGATIVE, never a
false public FACT).

HONEST LIMITATION: a firewalled account (``defaultAction=Deny``) may still serve anonymous blobs to an
ALLOWED VNet/IP — that is an intranet anonymous exposure, not an internet one; this collector deliberately
does NOT promote it as an internet ``public_exposure`` FACT (the C3 active-reachability oracle definitively
confirms actual anonymous reach where it matters).

Azure RBAC has NO anonymous/public principal (every assignment is an authenticated identity), so RBAC is
mapped to IAM TOPOLOGY only (principals) — there is no anonymous-public RBAC to confuse with the storage
public surface. Azure Storage is always encrypted at rest, so there is no unencrypted state to promote
(the encryption FACT never fires for Azure; honest). ``sensitive`` only when the operator TAGS the resource.

CREDENTIALS (the Azure twin of cloud_live's Wave B.1 / gcp_live's Phase-C2 customer-credential seam): a run may
be scoped to EXACTLY one customer identity by an INJECTED read-only session (a duck-typed
``vigil_core.cloud_session.MintedSession`` for an Azure provider — ``provider`` / ``account_id`` [the
subscription] / ``bearer_token`` [a short-lived AAD OAuth2 access token]). When injected, the collector wraps
THAT bearer in a static ``azure.core.credentials``-shaped ``TokenCredential`` and hands it to EVERY management
client (storage mgmt + authorization/RBAC mgmt), each SCOPED to the injected subscription, and NEVER consults
the ambient ``DefaultAzureCredential`` chain; a partial/empty or non-Azure session is REJECTED before any azure
import (fail-closed, no identity substitution), and ``require_injected_credentials=True`` makes the run REFUSE
rather than fall back to VIGIL's own identity. With no injection (the default) the EXISTING AMBIENT path is used
unchanged: azure-identity ``DefaultAzureCredential`` (the sealed service principal / a managed identity), never
handed over, no credential/subscription ⇒ honest ``ok=False`` no-op.

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
from types import SimpleNamespace
from typing import Any

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import Observation
from .base import inconclusive_result
from .cloud import _load_export, cloud_observations

# Container publicAccess levels that expose blobs ANONYMOUSLY (no credential). "None"/"" is private.
_PUBLIC_ACCESS_LEVELS = frozenset({"blob", "container"})
# Tag keys the operator uses to DECLARE data sensitivity, and the values that mean "sensitive".
_SENSITIVITY_TAG_KEYS = frozenset({"sensitive", "classification", "data-classification", "dataclassification"})
_SENSITIVE_TAG_VALUES = frozenset({
    "true", "yes", "1", "sensitive", "confidential", "restricted", "secret", "pii", "high", "critical",
})
# The Azure control-plane hosts the collector reaches (declared egress; operator provisions the subset it
# needs in collector-hosts.txt). ARM (management) + AAD (token) for the commercial, GovCloud and China
# clouds, PLUS the link-local IMDS the managed-identity DefaultAzureCredential hits on an Azure VM/VMSS. The
# blob DATA plane is never touched (read-only ARM management plane only).
_AZURE_HOSTS: tuple[str, ...] = (
    "management.azure.com", "login.microsoftonline.com",                     # commercial
    "management.usgovcloudapi.net", "login.microsoftonline.us",              # US Government
    "management.chinacloudapi.cn", "login.chinacloudapi.cn",                 # China (21Vianet)
    "169.254.169.254",                                                       # IMDS (managed identity)
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


def container_resource(entry: Any, *, account_allows_public: Any = None,
                       account_internet_open: Any = None) -> dict | None:
    """Map ONE collected blob container onto a native-inventory resource. ``entry``::

        {"id": "acct/container", "public_access": "None"|"Blob"|"Container", "tags": {...}}

    ``account_allows_public`` is the storage account's ``allowBlobPublicAccess`` (True/False/None-unknown);
    ``account_internet_open`` is whether the account's network is internet-open (``publicNetworkAccess`` not
    Disabled AND ``networkAcls.defaultAction`` not Deny) — True/False/None-unknown. Returns a resource dict
    or ``None`` for an id-less entry. Pure + total. CONSERVATIVE: ``public`` (the promotable FACT flag + a
    synthesised anonymous grant) is set ONLY when the container is public AND the account allows public blob
    access (``is True``) AND the account is internet-open (``is True``) — all three scopes read and
    permitting. Any scope False/unknown leaves an un-promoted lead. Raw signals retained for audit."""
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
    if account_internet_open is True or account_internet_open is False:
        res["account_internet_open"] = bool(account_internet_open)
    # CONFIRMED internet-public only when ALL THREE scopes permit
    if container_public and account_allows_public is True and account_internet_open is True:
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
    account_internet_open_by_id: Any = None,
    role_assignments: Any = None,
    subscription: str = "",
) -> dict:
    """Assemble the native inventory (``{"provider":"azure",…}``) from the retained read-only responses.
    PURE + total. ``account_public_by_id`` maps ``"<account>"`` -> its ``allowBlobPublicAccess`` (True/False/
    None); ``account_internet_open_by_id`` maps ``"<account>"`` -> whether its network is internet-open
    (True/False/None). Each container's id is ``"<account>/<container>"`` so both account scopes are looked
    up per container."""
    account_public = account_public_by_id if isinstance(account_public_by_id, dict) else {}
    account_net = account_internet_open_by_id if isinstance(account_internet_open_by_id, dict) else {}
    resources: list[dict] = []
    if not isinstance(containers, (list, tuple)):
        containers = ()
    for c in containers:
        if not isinstance(c, dict):
            continue
        account = str(c.get("id") or "").split("/", 1)[0]
        r = container_resource(c, account_allows_public=account_public.get(account),
                               account_internet_open=account_net.get(account))
        if r is not None:
            resources.append(r)
    principals = _rbac_principals(role_assignments)
    return {"provider": "azure", "subscription": str(subscription or ""),
            "principals": principals, "resources": resources}


# ---------------------------------------------------------------------------
# injected customer identity — a static replay of the sovereign-minted AAD bearer
# ---------------------------------------------------------------------------
#
# A far-future sentinel expiry (epoch seconds, 9999-12-31) for the injected STATIC token. The AAD bearer the
# sovereign mint hands over is short-lived, but this wrapper has NO refresh path — it is a pure REPLAY of one
# token — exactly as gcp_live's injected ``google.oauth2.credentials.Credentials`` carries no refresh and is
# treated as valid client-side. Freshness is the SOVEREIGN MINT's responsibility (``MintedSession.is_fresh`` at
# run start); if the token expires mid-run the SDK simply 401s and the per-resource collectors degrade via
# ``_safe`` — never a false clean. The client-side ``expires_on`` only governs the SDK's refresh caching, so a
# far-future value (= no refresh attempt) is the honest choice for a non-refreshable replay token.
_STATIC_TOKEN_EXPIRES_ON = 253402300799   # 9999-12-31T23:59:59Z


class _InjectedTokenCredential:
    """A static-token ``azure.core.credentials.TokenCredential`` wrapping the INJECTED customer AAD bearer.

    DRIFT vs gcp_live: GCP has a ready-made static credential (``google.oauth2.credentials.Credentials(token=
    …)``) the collector instantiates directly; Azure's SDK has NO equivalent static-token credential, so this
    thin wrapper supplies the exact shape azure-mgmt clients consume — ``get_token(*scopes, **kwargs) ->
    AccessToken(token, expires_on)`` (``azure.core.credentials``). It REPLAYS the one minted bearer for EVERY
    requested scope: the token's audience (commercial / US-Gov / China ARM) was fixed by the sovereign mint, so
    the per-client scope the SDK passes is immaterial here — the collector never mints, exchanges or refreshes a
    token, it only hands back the one the sovereign side already scoped (the analog of gcp_live scoping every
    client to the injected project rather than re-deriving it from the token).

    The bearer rides on ``self.token`` (an in-process field, never serialised into a ToolResult — the no-leak
    invariant is asserted on the result, not on this object), mirroring how gcp_live's injected ``Credentials``
    carries its token. Constructing it imports NO azure module (``AccessToken`` is resolved LAZILY, only if/when
    the SDK actually calls ``get_token``), so the fail-closed reject cases run with no azure libs installed."""

    __slots__ = ("token",)

    def __init__(self, bearer: str) -> None:
        self.token = bearer

    def get_token(self, *scopes: Any, **kwargs: Any) -> Any:
        # ``AccessToken`` is a 2-field namedtuple ``(token, expires_on)``; azure-mgmt reads only those two
        # attributes, so the authentic type (when azure-core is importable) and a structural stand-in both
        # satisfy the SDK. The import is DEFERRED to call time so this module imports cleanly in the sovereign
        # leg (where azure is absent) and the reject paths never touch azure.
        try:
            from azure.core.credentials import AccessToken  # optional dependency
        except Exception:
            return SimpleNamespace(token=self.token, expires_on=_STATIC_TOKEN_EXPIRES_ON)
        return AccessToken(self.token, _STATIC_TOKEN_EXPIRES_ON)


# ---------------------------------------------------------------------------
# the live sensor
# ---------------------------------------------------------------------------


class AzureLiveSensor:
    """Live, read-only Azure posture collector (Tier-2, ``ACTIVE_RECON``). Scoped to an INJECTED customer
    session (``credentials=`` / ``require_injected_credentials=`` — the Azure twin of cloud_live's Wave B.1 /
    gcp_live's Phase-C2 seam) or, by default, VIGIL's own ambient ``DefaultAzureCredential``; read-only
    Storage-account + blob-container + RBAC reads over Azure Resource Manager; emits the native inventory as
    ``{"export": <json>, "format": "native"}``. Fail-closed no-op when an injected session is partial/non-Azure,
    when a required injection is absent, when azure-identity / azure-mgmt-storage are absent, when no ambient
    credential is discoverable, or when no subscription is resolvable."""

    name = "azure_live"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts = _AZURE_HOSTS

    _MAX_ACCOUNTS = 500
    _MAX_CONTAINERS = 1000                            # per account, bound the leaf-resource fan-out

    def __init__(self, *, subscription: str | None = None,
                 credentials: Any = None, require_injected_credentials: bool = False) -> None:
        # An injected ``credentials`` object scopes this run to EXACTLY one customer identity. It is duck-typed
        # (``provider`` / ``account_id`` [the Azure subscription] / ``bearer_token`` [a short-lived AAD OAuth2
        # access token]) so a ``vigil_core.cloud_session.MintedSession`` for an Azure provider satisfies it with
        # NO import here (the sovereign mint hands the collector DATA, never a governor object — the FATAL-2
        # boundary). When present, the ambient ``DefaultAzureCredential`` chain is NEVER consulted.
        # ``require_injected_credentials`` makes a CUSTOMER run FAIL CLOSED rather than silently fall back to
        # VIGIL's own ambient Azure identity (the no-substitution guard — the single most important invariant of a
        # customer cloud-posture run). Both default OFF, so the bare ``AzureLiveSensor()`` ambient path
        # (``engage_fusion`` + the ambient tests) is byte-identical. (The AWS twin is ``cloud_live.CloudLiveSensor``;
        # the GCP twin is ``gcp_live.GcpLiveSensor`` — this mirrors their customer-credential seam.)
        self._credentials = credentials
        self._require_injected = bool(require_injected_credentials)
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

    @staticmethod
    def _account_internet_open(acct: Any) -> bool:
        """Whether a storage account's network admits anonymous INTERNET traffic: NOT internet-open iff
        ``publicNetworkAccess`` is Disabled OR ``networkAcls.defaultAction`` is Deny. An absent field is the
        Azure DEFAULT (public network enabled / default-action Allow), so absent → open. Never raises."""
        pna = str(getattr(acct, "public_network_access", "") or "").strip().lower()
        default_action = ""
        try:
            nrs = getattr(acct, "network_rule_set", None)
            default_action = str(getattr(nrs, "default_action", "") or "").strip().lower()
        except Exception:
            default_action = ""
        return not (pna == "disabled" or default_action == "deny")

    def _collect_storage(self, storage_client: Any) -> tuple[list[dict], dict, dict]:
        """Storage accounts (allowBlobPublicAccess + network posture) + their blob containers (publicAccess),
        read-only. A per-account/container denial degrades that datum, never raising. Returns
        (containers, account_allowBlobPublicAccess, account_internet_open)."""
        containers: list[dict] = []
        account_public: dict[str, Any] = {}
        account_net: dict[str, Any] = {}
        accounts = self._safe(lambda: list(storage_client.storage_accounts.list()), []) or []
        for acct in accounts[: self._MAX_ACCOUNTS]:
            rg, name = self._parse_account_id(getattr(acct, "id", "") or "")
            if not name:
                continue
            allow = getattr(acct, "allow_blob_public_access", None)
            account_public[name] = bool(allow) if isinstance(allow, bool) else None
            account_net[name] = self._account_internet_open(acct)
            tags = self._safe(lambda a=acct: dict(getattr(a, "tags", {}) or {}), {})
            conts = self._safe(lambda rg=rg, name=name: list(
                storage_client.blob_containers.list(rg, name)), []) or []
            for cont in conts[: self._MAX_CONTAINERS]:
                cname = str(getattr(cont, "name", "") or "").strip()
                if not cname:
                    continue
                pub = getattr(cont, "public_access", None)
                containers.append({"id": f"{name}/{cname}",
                                   "public_access": str(pub) if pub is not None else "None",
                                   "tags": tags})
        return containers, account_public, account_net

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
        # The read-only identity + subscription are resolved FIRST, and the credential seam runs BEFORE any azure
        # import — so the fail-closed rejections (a partial / non-Azure injected session, or a required-but-absent
        # injection) are a PURE, dependency-free refusal that never reaches the SDK (and runs in CI with no azure
        # libs). ``credential`` is the azure-core TokenCredential the azure-mgmt clients consume, bound here to
        # EXACTLY one customer identity (the injected bearer) or to VIGIL's own ambient identity — never mixed.
        # ``subscription`` scopes every management client.
        credential: Any = None
        subscription = ""
        injected = self._credentials
        if injected is not None:
            # SCOPED customer identity: build the credential ONLY from a COMPLETE Azure bearer session, and NEVER
            # consult the ambient ``DefaultAzureCredential`` when an injection is present. An Azure AAD bearer
            # rides on a non-AWS ``MintedSession`` (its aws_* fields empty); an empty/partial one — or a non-Azure
            # provider — is REJECTED here, not handed on (the ``is not None`` ``require_injected`` branch below
            # cannot catch a non-None-but-incomplete object — the no-substitution invariant).
            provider = str(getattr(injected, "provider", "azure") or "azure")
            bearer = str(getattr(injected, "bearer_token", "") or "")
            subscription = str(getattr(injected, "account_id", "") or "")
            if provider not in ("azure", "az") or not bearer or not subscription:
                return inconclusive_result(
                    "azure_live", missing="a complete Azure scoped read-only session", detail=(
                        "the injected session is not a complete Azure read-only session (a missing AAD bearer "
                        "token / subscription, or a non-Azure provider) — refusing to fall back to VIGIL's ambient "
                        "Azure identity (fail-closed, no identity substitution)."))
            credential = _InjectedTokenCredential(bearer)
            # Subscription DRIFT asymmetry vs AWS (cloud_live.py ~643-653): AWS re-confirms tenancy at collection
            # time via STS get-caller-identity — the landed Account must EQUAL the claimed one. An Azure AAD access
            # token carries NO subscription binding (its claims name the tenant/identity, not a subscription) — the
            # subscription is a CLIENT-SIDE argument to each management client, exactly like a GCP OAuth2 token's
            # project — so there is no cheap, reliable server-side "what subscription am I" that mirrors STS. We
            # therefore scope every client to the INJECTED subscription (``account_id``) and deliberately DO NOT
            # invent a drift check, exactly as gcp_live documented for its no-STS-equivalent project asymmetry (a
            # C3 follow-up may add a token-introspection self-check if one is warranted).
        elif self._require_injected:
            # A CUSTOMER run must NEVER fall back to VIGIL's ambient identity (no identity substitution). This elif
            # returns BEFORE the ambient branch — the required-but-absent injection never even reaches a credential.
            return inconclusive_result("azure_live", missing="an injected customer read-only session", detail=(
                "this run requires an explicitly-minted, customer-scoped read-only session; refusing to fall "
                "back to VIGIL's own ambient Azure identity (fail-closed — no identity substitution)."))
        else:
            # EXISTING ambient path, UNCHANGED: VIGIL's own sealed service principal / managed identity, resolved
            # by ``DefaultAzureCredential``. The subscription + azure-identity fail-closed checks keep their prior
            # wording/order (the subscription check now lives in this branch — the injected path resolves its
            # subscription from ``account_id`` instead). All azure imports stay function-local to this branch /
            # below so the module still imports in the sovereign leg where azure is absent.
            if not self._subscription:
                return inconclusive_result(
                    "azure_live", missing="a resolvable subscription (AZURE_SUBSCRIPTION_ID)", detail=(
                        "no subscription resolvable (set AZURE_SUBSCRIPTION_ID) — fail-closed no-op."))
            try:
                from azure.identity import DefaultAzureCredential  # optional dependency
            except Exception:
                return inconclusive_result("azure_live", missing="azure-identity", detail=(
                    "azure-identity not installed — live Azure collection unavailable (fail-closed "
                    "no-op). Install azure-identity + azure-mgmt-storage + azure-mgmt-authorization."))
            try:
                credential = DefaultAzureCredential()
            except Exception as e:
                return inconclusive_result(
                    "azure_live", missing="ambient Azure credential (service principal / managed identity)",
                    detail=(f"no ambient Azure credential discoverable (service principal / managed identity) "
                            f"— fail-closed no-op: {type(e).__name__}"))
            subscription = self._subscription
        try:
            from azure.mgmt.storage import StorageManagementClient  # optional dependency
        except Exception:
            return inconclusive_result("azure_live", missing="azure-mgmt-storage", detail=(
                "install azure-mgmt-storage to enable live Azure collection."))
        try:
            containers, account_public, account_net = self._collect_storage(
                StorageManagementClient(credential, subscription))
        except Exception as e:
            return inconclusive_result(
                "azure_live", missing="valid, reachable Azure credential", detail=(
                    f"Azure Storage enumeration failed — credential invalid/expired or access denied "
                    f"(fail-closed): {type(e).__name__}"))
        role_assignments = self._safe(lambda: self._collect_rbac(credential, subscription), [])
        inventory = azure_inventory_from_responses(
            containers=containers, account_public_by_id=account_public,
            account_internet_open_by_id=account_net,
            role_assignments=role_assignments, subscription=subscription)
        n_res, n_pri = len(inventory.get("resources", [])), len(inventory.get("principals", []))
        return ToolResult(
            ok=True,
            summary=f"azure_live: Azure subscription {subscription} — {n_res} resources, {n_pri} principals (read-only)",
            output={"export": json.dumps(inventory), "format": "native", "provider": "azure",
                    "subscription": subscription})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        text, fmt = out.get("export"), out.get("format", "native")
        if not isinstance(text, str) or not text.strip():
            return []
        return cloud_observations(_load_export(text, fmt if isinstance(fmt, str) else "native"), seq=seq)
