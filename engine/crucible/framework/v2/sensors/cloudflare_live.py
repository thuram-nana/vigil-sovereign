"""
sensors.cloudflare_live — LIVE, read-only Cloudflare posture collection as a gated SENSOR (Phase C2 · Cloudflare).

The FOURTH and final live cloud collector — the Cloudflare twin of ``sensors.cloud_live`` (AWS) /
``sensors.gcp_live`` (GCP) / ``sensors.azure_live`` (Azure). It calls the Cloudflare API control plane
READ-ONLY at runtime and emits the SAME normalized native inventory those importers produce, so the
provider-AGNOSTIC cloud oracles (``engage_fusion._reverify_cloud`` → policy-path / achieved-state) promote
its leads UNCHANGED. The collector invents no new schema and no new oracle.

A DIFFERENT CREDENTIAL MODEL (critical — and the reason there is NO ``MintedSession`` for Cloudflare).
AWS/GCP/Azure connect by DELEGATED access and are RE-MINTABLE from a stored grant
(``vigil_core.cloud_session.MintedSession``, providers ``aws`` / ``gcp`` / ``azure`` — Cloudflare is
excluded from ``MINTABLE_PROVIDERS`` on purpose). A Cloudflare API token, by contrast, IS a bearer secret
the customer hands over, which VIGIL never stores: the Cloudflare grant keeps only the token's PUBLIC id + a
sha256 (``governor.cloud_connect``), and ``governor.cloud_posture_launch`` REFUSES to mint a Cloudflare
session from a stored grant. So a Cloudflare posture run is handed a FRESH per-run read-only token in a
DUCK-TYPED session (``provider`` / ``account_id`` / ``bearer_token`` — the same bearer slot a GCP/Azure
minted session carries), never a re-minted ``MintedSession``. This collector consumes exactly that injected,
per-run session.

Doctrine, by construction (identical to the three siblings):
  * PROVE-DON'T-GUESS / ORACLE AUTHORITY. The collector mints only a native inventory (LEADS). A LEAD becomes
    a FACT only when the EXISTING deterministic cloud oracles re-fire over the RETAINED export
    (``confirm_cloud_posture_facts`` re-derives the anonymous grant PATH over the retained policy graph) —
    NEVER because a live API said so. The collector hard-codes no verdict.
  * NO IDENTITY SUBSTITUTION, FAIL-CLOSED. ``require_injected_credentials=True`` at the customer boundary. An
    injected session that is PARTIAL (no token / no account) or NON-Cloudflare is REJECTED BEFORE any
    Cloudflare HTTP call — and Cloudflare has NO ambient identity (no credential chain, no metadata server),
    so the no-injection branch is a fail-closed NO-OP (there is nothing to fall back TO). A collection
    FAILURE (token rejected / API unreachable) is a typed INCONCLUSIVE carrying the reason — NEVER a clean
    empty negative.
  * FATAL-2. The session crosses as DATA (duck-typed here — no governor / ``MintedSession`` import in the
    engine); the only outbound client is stdlib ``urllib`` host-pinned to ``api.cloudflare.com`` (no vendor
    SDK — the same transport choice the SOVEREIGN Cloudflare leg [``ui.cloudflare_fetch``] makes, FATAL-2
    clean). The egress is declared in ``egress_hosts`` so the egress gate authorises exactly what runs.
  * NO SECRET LEAK. The token rides ONLY in the ``Authorization: Bearer`` header — never in a URL, never in
    the ToolResult output/summary, never in a log, never in an error detail (mirrors how gcp/azure keep the
    bearer off the result, and how ``ui.cloudflare_fetch`` keeps the token out of every return / error).
  * DETERMINISM OF THE CORE. The live ``run`` reflects the customer's account, but the recorded-response →
    native-inventory translation (``cloudflare_inventory_from_responses`` / ``bucket_resource``) is a PURE,
    total, CI-tested function of the retained responses — no wallclock, no rng.

FIRST RULESET — R2 bucket public exposure (the natural 4th-provider parallel to a public S3 bucket / public
GCS bucket / public blob container). A Cloudflare R2 bucket is anonymously readable over the public internet
when its MANAGED public development URL (``*.r2.dev``) is ENABLED. So a bucket is CONFIRMED public (a
promotable ``public=true`` + a synthesised anonymous ``*`` read grant the policy-path oracle promotes) ONLY
when the managed-domain read reports ``enabled: true``. A CUSTOM-domain exposure (managed disabled but a
custom domain bound) is RETAINED as an auditable ``r2_custom_domains`` signal and NOT promoted — a custom
domain can be gated by Cloudflare Access / a firewall, so its anonymous reach is not confirmed by this read
alone (CONSERVATIVE: err to a false-NEGATIVE, never a false public FACT; a later C3 active-reachability
oracle confirms where it matters). R2's managed dev URL has no second neutralising scope (unlike S3
Block-Public-Access / GCS PAP / the Azure account toggle), so a single confirmed scope IS the confirmation —
stated plainly, not papered over with a two-scope rule that does not exist here.

HONEST LIMITATION (VIGIL-LIMIT:LIMIT-cloudflare-live-r2-api): live Cloudflare API calls cannot run in CI, so
the exact R2 read-only REST surface (the ``/r2/buckets`` + managed/custom domain JSON shapes, and whether the
per-run read-only token's groups include ``Workers R2 Storage Read``) is an honestly-registered residual
proven against a live customer token; the pure-protocol layer here (the host-pinned guard, the parse, the
native translation, the oracle promotion) is fully covered offline through the injectable ``transport`` seam.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import Observation
from .base import inconclusive_result
from .cloud import _load_export, cloud_observations

# The ONLY host this collector may reach — the Cloudflare API control plane. Declared as ``egress_hosts`` so
# the egress gate authorises exactly what the stdlib client calls, and host-pinned by ``_guard`` before any
# socket opens (a token-bearing request can never leave for another host).
_CF_HOST = "api.cloudflare.com"
_CF_API_BASE = f"https://{_CF_HOST}/client/v4"
_USER_AGENT = "VIGIL-cloud-posture"          # a generic, non-identifying client name (never a person / org)
_DEFAULT_TIMEOUT_S = 10.0                     # per blocking socket op of a Cloudflare call (connect, read)
_MAX_RESPONSE_BYTES = 1024 * 1024            # an R2 listing answer is small; bounded well above it
_MAX_BUCKETS = 500                           # bound the per-run fan-out (each bucket costs a few read-only GETs)
_MAX_CUSTOM_DOMAINS = 32                      # bound the custom-domain signal retained per bucket


# ---------------------------------------------------------------------------
# pure translation: recorded Cloudflare read-only responses -> the native inventory
# (no network — the deterministic, CI-tested core the oracles consume)
# ---------------------------------------------------------------------------


def _managed_public_state(managed: Any) -> bool | None:
    """Tri-state the R2 managed-domain (``*.r2.dev``) read into True (public dev URL ENABLED → anonymous
    internet read) / False (explicitly disabled) / None (unknown — denied / not attempted). Total: an odd
    shape is UNKNOWN, never mistaken for public."""
    if not isinstance(managed, dict):
        return None
    enabled = managed.get("enabled")
    return bool(enabled) if isinstance(enabled, bool) else None


def _enabled_custom_domains(custom: Any) -> list[str]:
    """The ENABLED custom domains bound to the bucket (an auditable signal — NOT a promoted public grant). A
    domain is included only when its own ``enabled`` is True; a pending/disabled domain is dropped. Total:
    any odd shape → empty."""
    out: list[str] = []
    if not isinstance(custom, dict):
        return out
    domains = custom.get("domains")
    if not isinstance(domains, (list, tuple)):
        return out
    for d in domains:
        if not isinstance(d, dict):
            continue
        name = str(d.get("domain") or "").strip().lower()
        if name and d.get("enabled") is True:
            out.append(name)
    return out


def bucket_resource(entry: Any, *, account: str = "") -> dict | None:
    """Map ONE collected R2 bucket record onto a native-inventory resource. ``entry``::

        {"name": "acme-public", "managed_public": <get managed-domain resp>|None,
         "custom": <get custom-domains resp>|None}

    Returns a resource dict or ``None`` for a nameless entry. Pure + total. CONSERVATIVE, evidence-retaining,
    near-zero-FP by construction:

      * The RAW ground-truth signals (``r2_managed_public`` / ``r2_custom_domains``) are retained as
        oracle-inert attrs — the oracle ignores these keys, but they make the public verdict AUDITABLE and
        let a future / C3 active-reachability oracle judge them independently.
      * ``public`` (the promotable FACT flag + a synthesised anonymous read grant) is set ONLY when the
        bucket's MANAGED public development URL is AFFIRMATIVELY ENABLED (``managed_public.enabled is True``)
        — the ``*.r2.dev`` URL then serves objects anonymously over the public internet. Managed disabled /
        UNKNOWN → ``public`` is NOT set (conservative — no false public FACT).
      * A CUSTOM-domain exposure with the managed URL NOT enabled is retained as a lead ONLY: a custom domain
        can sit behind Cloudflare Access / a firewall, so its anonymous reach is not confirmed by this read
        alone (err to a false-NEGATIVE). The C3 active oracle confirms anonymous reach where it matters."""
    if not isinstance(entry, dict):
        return None
    name = str(entry.get("name") or "").strip()
    if not name:
        return None
    rid = f"{account}/{name}" if account else name
    res: dict[str, Any] = {"id": rid, "kind": "datastore"}
    managed = _managed_public_state(entry.get("managed_public"))
    customs = _enabled_custom_domains(entry.get("custom"))
    # retain the RAW ground truth as evidence (oracle-inert keys)
    if managed is not None:
        res["r2_managed_public"] = managed
    if customs:
        res["r2_custom_domains"] = sorted(set(customs))[:_MAX_CUSTOM_DOMAINS]
    # CONFIRMED anonymous public only when the managed r2.dev URL is affirmatively enabled.
    if managed is True:
        res["public"] = True
        res["grants"] = [{"principal": "*", "access": "read"}]
    return res


def cloudflare_inventory_from_responses(*, buckets: Any = (), account: str = "") -> dict:
    """Assemble the native inventory (``{"provider":"cloudflare","account",…}``) from the retained read-only
    responses. PURE + total — the deterministic core every cloudflare_live test exercises and the cloud
    oracles consume. ``buckets`` is the list of per-bucket records (see :func:`bucket_resource`). R2 exposes
    no anonymous-principal IAM topology to enumerate in this first slice, so ``principals`` is empty (exactly
    as the Prowler adapter emits a resource-only inventory)."""
    acct = str(account or "")
    resources: list[dict] = []
    if not isinstance(buckets, (list, tuple)):
        buckets = ()
    for b in buckets[:_MAX_BUCKETS]:
        r = bucket_resource(b, account=acct)
        if r is not None:
            resources.append(r)
    return {"provider": "cloudflare", "account": acct, "principals": [], "resources": resources}


# ---------------------------------------------------------------------------
# the guarded stdlib egress (host-pinned to api.cloudflare.com; redirects blocked)
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Block every HTTP redirect — a 3xx must never relay a Bearer-token request to another host (mirrors the
    sovereign ``ui.cloud_fetch._NoRedirect``). FATAL-2: defined locally so the engine imports nothing from
    the governor / sovereign plane."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _guard(url: str) -> None:
    """Refuse a non-https scheme, userinfo, a non-default port, or an off-``api.cloudflare.com`` host BEFORE
    any socket opens — so a token-bearing request can only ever reach the pinned Cloudflare API host."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise ValueError("non-https Cloudflare URL")
    if "@" in (parts.netloc or ""):
        raise ValueError("Cloudflare URL carries userinfo")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("malformed Cloudflare port") from None
    if port not in (None, 443):
        raise ValueError("non-default Cloudflare port")
    if (parts.hostname or "").lower() != _CF_HOST:
        raise ValueError("non-pinned Cloudflare host")


def _http_get(url: str, headers: Mapping[str, str], timeout: float) -> "tuple[int, bytes]":
    """One guarded GET → ``(status, body)``, the body bounded. An HTTP error status is RETURNED (its
    Cloudflare error document tells an invalid token from a transport fault); only a transport failure
    raises. The token rides in ``headers`` (never in ``url``); no part of ``headers`` is ever echoed."""
    _guard(url)
    req = urllib.request.Request(url, method="GET", headers=dict(headers))
    try:
        with _OPENER.open(req, timeout=timeout) as r:  # noqa: S310 — https + host pinned by _guard; redirects blocked
            raw = r.read(_MAX_RESPONSE_BYTES + 1)
            status = int(getattr(r, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(_MAX_RESPONSE_BYTES + 1) or b""
        except Exception:  # noqa: BLE001 — an unreadable error body is an empty one
            raw = b""
        status = int(exc.code) if isinstance(exc.code, int) else 0
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise ValueError("Cloudflare response exceeded the size cap")
    return status, raw


# ---------------------------------------------------------------------------
# the live sensor
# ---------------------------------------------------------------------------


class CloudflareLiveSensor:
    """Live, read-only Cloudflare posture collector (Tier-2, ``ACTIVE_RECON``). Consumes an INJECTED per-run
    read-only Cloudflare session (duck-typed: ``provider`` / ``account_id`` / ``bearer_token``), makes only
    read-only ``GET`` calls to ``api.cloudflare.com``, and emits the native inventory as
    ``{"export": <json>, "format": "native"}`` — the SAME shape the offline importer emits, so the existing
    normalize + fusion re-verify promote its leads with no downstream change.

    Fail-closed everywhere: a PARTIAL / non-Cloudflare injected session is refused BEFORE any HTTP; a run
    that ``require_injected_credentials`` with no session refuses (Cloudflare has no ambient identity to fall
    back to); a token-rejected / unreachable collection is a typed INCONCLUSIVE, never a clean empty."""

    name = "cloudflare_live"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts: tuple[str, ...] = (_CF_HOST,)

    def __init__(self, *, credentials: Any = None, require_injected_credentials: bool = False,
                 transport: "Optional[Callable[[str, Mapping[str, str], float], tuple[int, bytes]]]" = None,
                 timeout: float = _DEFAULT_TIMEOUT_S) -> None:
        # An injected ``credentials`` object scopes this run to EXACTLY one customer Cloudflare account. It is
        # duck-typed (``provider`` / ``account_id`` / ``bearer_token``) so a per-run Cloudflare session satisfies
        # it with NO governor import here (the sovereign side hands the collector DATA, never an authority object —
        # the FATAL-2 boundary). ``require_injected_credentials`` makes a CUSTOMER run FAIL CLOSED rather than
        # proceed without an injected identity (the no-substitution guard). ``transport`` is an injectable
        # ``(url, headers, timeout) -> (status, body)`` seam for offline tests (a fake Cloudflare API that still
        # passes the host guard); unset ⇒ the stdlib guarded GET.
        self._credentials = credentials
        self._require_injected = bool(require_injected_credentials)
        self._transport = transport
        self._timeout = float(timeout)

    # -- live read-only collection (non-deterministic; degrades cleanly) --

    def _get(self, url: str, token: str) -> "tuple[int, Optional[dict]]":
        """One guarded, bounded GET under the injected token → ``(status, parsed-json-or-None)``. The token
        travels ONLY in the ``Authorization`` header. Uses the injectable ``transport`` when set (still
        host-guarded), else the stdlib client."""
        headers = {"Authorization": f"Bearer {token}", "User-Agent": _USER_AGENT, "Accept": "application/json"}
        if self._transport is not None:
            _guard(url)                                  # a fake transport still exercises the egress pin
            status, raw = self._transport(url, headers, self._timeout)
        else:
            status, raw = _http_get(url, headers, self._timeout)
        try:
            doc = json.loads(bytes(raw or b"").decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            doc = None
        return int(status), doc if isinstance(doc, dict) else None

    @staticmethod
    def _ok(doc: Any) -> bool:
        return isinstance(doc, dict) and doc.get("success") is True

    def _list_buckets(self, account: str, token: str) -> "tuple[list[str], Optional[str]]":
        """List the account's R2 bucket NAMES read-only → ``(names, error)``. ``error`` is a non-empty reason
        (fail-closed INCONCLUSIVE) when the listing could not be made — a rejected token, an unreachable API,
        or an unexpected answer; ``None`` on a genuine (possibly empty) success. The bucket name is validated
        host-/path-safe before it is ever placed in a URL (no header / path injection)."""
        url = f"{_CF_API_BASE}/accounts/{account}/r2/buckets"
        try:
            status, doc = self._get(url, token)
        except Exception as exc:  # noqa: BLE001 — a transport fault fails closed (type only, never the message/token)
            return [], f"R2 bucket listing could not be made ({type(exc).__name__})"
        if status in (401, 403):
            return [], "the Cloudflare API token was rejected (invalid, expired, or missing R2 read permission)"
        if not (status == 200 and self._ok(doc)):
            return [], f"R2 bucket listing returned an unexpected answer (HTTP {status})"
        result = doc.get("result") if isinstance(doc, dict) else None
        raw_buckets = result.get("buckets") if isinstance(result, dict) else (
            result if isinstance(result, list) else [])
        names: list[str] = []
        for b in (raw_buckets or [])[:_MAX_BUCKETS]:
            nm = str(b.get("name") or "").strip() if isinstance(b, dict) else ""
            if nm and nm.isascii() and nm == urllib.parse.quote(nm, safe="._-"):
                names.append(nm)
        return names, None

    def _bucket_domains(self, account: str, bucket: str, token: str) -> dict:
        """Per-bucket read-only domain posture: the managed ``*.r2.dev`` public-dev-URL state and the bound
        custom domains. A per-call denial / fault degrades THAT datum (best-effort, UNKNOWN — never raising,
        never a guessed 'public')."""
        rec: dict[str, Any] = {"name": bucket}
        base = f"{_CF_API_BASE}/accounts/{account}/r2/buckets/{bucket}/domains"
        rec["managed_public"] = self._safe_result(f"{base}/managed", token)
        rec["custom"] = self._safe_result(f"{base}/custom", token)
        return rec

    def _safe_result(self, url: str, token: str) -> Any:
        """A read-only GET whose ``result`` is returned on success, else ``None`` (UNKNOWN — a denial /
        fault / unexpected answer is never mistaken for a posture fact). Never raises."""
        try:
            status, doc = self._get(url, token)
        except Exception:  # noqa: BLE001 — best-effort per-datum; a fault leaves the datum UNKNOWN
            return None
        if status == 200 and self._ok(doc):
            return doc.get("result") if isinstance(doc, dict) else None
        return None

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        injected = self._credentials
        if injected is not None:
            # SCOPED customer identity. Read the duck-typed session and REJECT a partial / non-Cloudflare one
            # BEFORE any Cloudflare HTTP call — a missing token or a non-Cloudflare provider must never fall
            # through to an unscoped read (there is no ambient Cloudflare identity, so a non-None-but-empty
            # object cannot be caught by the ``require_injected`` branch below). Fail-closed, no identity
            # substitution — the single most important invariant of a customer cloud-posture run.
            provider = str(getattr(injected, "provider", "") or "")
            account = str(getattr(injected, "account_id", "") or "").strip()
            token = str(getattr(injected, "bearer_token", "") or "")
            if provider != "cloudflare" or not account or not token:
                return inconclusive_result("cloudflare_live", missing="a complete Cloudflare scoped read-only session", detail=(
                    "the injected session is not a complete Cloudflare read-only session (a missing API token "
                    "or a non-Cloudflare provider) — refusing to proceed without a scoped Cloudflare identity "
                    "(fail-closed, no identity substitution)."))
            if not (len(account) == 32 and all(c in "0123456789abcdef" for c in account)):
                # defence-in-depth: a Cloudflare account id is exactly 32 lowercase hex; a malformed id would be
                # path-injected into the R2 URL. Refuse rather than build a request around it.
                return inconclusive_result("cloudflare_live", missing="a well-formed Cloudflare account id", detail=(
                    "the injected session's Cloudflare account id is malformed (expected 32 lowercase hex) — "
                    "refusing to collect (fail-closed)."))
        elif self._require_injected:
            # A CUSTOMER run must NEVER proceed without an injected identity. Cloudflare has NO ambient
            # credential chain to fall back to, so this is a straight refusal (no-substitution guard).
            return inconclusive_result("cloudflare_live", missing="an injected customer read-only session", detail=(
                "this run requires an explicitly-injected, customer-scoped read-only Cloudflare session; "
                "Cloudflare has no ambient identity to fall back to (fail-closed — no identity substitution)."))
        else:
            # No injection and not required: Cloudflare has no ambient identity to discover, so there is
            # nothing to assess — a clean fail-closed no-op (never a clean empty negative).
            return inconclusive_result("cloudflare_live", missing="an injected Cloudflare read-only session", detail=(
                "no Cloudflare credential is discoverable — Cloudflare has no ambient identity (no credential "
                "chain / metadata server); inject a per-run read-only API token session to assess posture."))

        names, err = self._list_buckets(account, token)
        if err is not None:
            # A collection FAILURE assessed NOTHING — a typed INCONCLUSIVE carrying the reason, never a clean
            # empty negative. (A genuine, successful empty listing falls through to an assessed ok=True below.)
            return inconclusive_result("cloudflare_live", missing="a reachable, authorised Cloudflare R2 read", detail=err)
        buckets = [self._bucket_domains(account, nm, token) for nm in names]
        inventory = cloudflare_inventory_from_responses(buckets=buckets, account=account)
        n_res = len(inventory.get("resources", []))
        return ToolResult(
            ok=True,
            summary=f"cloudflare_live: Cloudflare account {account} — {n_res} R2 buckets (read-only)",
            output={"export": json.dumps(inventory), "format": "native", "provider": "cloudflare", "account": account})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        """Identical to the siblings' normalize — the export is the native inventory, minted as posture LEADS
        via the SHARED ``cloud_observations`` minter. The LEAD → FACT promotion is the fusion re-verify's
        job, not the sensor's."""
        out = result.output or {}
        text, fmt = out.get("export"), out.get("format", "native")
        if not isinstance(text, str) or not text.strip():
            return []
        return cloud_observations(_load_export(text, fmt if isinstance(fmt, str) else "native"), seq=seq)
