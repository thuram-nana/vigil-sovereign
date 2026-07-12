"""
sensors.cloud — Cloud / IAM / CSPM posture driven as gated SENSORS (Wave 5a).

CRUCIBLE is a reasoning OS: a cloud posture tool (ScoutSuite / Prowler / a provider export) is a gated
SENSOR whose output enters the ONE world-model as provenance-tagged OBSERVATIONS — the IAM TOPOLOGY
(who can assume what, who is a member of what, who holds a grant over what) and a set of posture LEADS
(``GROUNDING_INTEL``: public exposure, an over-privileged grant, a mis-configuration), NEVER facts. A
CSPM tool's "this is over-privileged / public" is a THIRD PARTY's heuristic say-so; CRUCIBLE's own
deterministic ORACLE re-verifies the one claim it can — a **privilege PATH** (a principal reaches a
resource iff a real IAM grant path grants it, re-derived over the retained policy graph by
``verify.policy_path``) — while the rest stay honest, labelled leads.

This UPGRADES the file-ingest ``intel.from_cloud`` into the Wave-2 sensor framework, reusing its
``observations_from_cloud`` minter UNCHANGED (only re-tagged to the ``CLOUD_POSTURE`` provenance) so the
IAM edge shape the existing knowledge operators (``role-assumption`` / ``credential-reuse``) chain over
is produced ONE way.

The seam is the W2.1 framework end to end::

    invoke_tool (kill-switch / entitlement / scope / destructive / egress)  ->  <Sensor>.run
    (offline file read / gated REST pull)  ->  normalize (parse export -> native inventory)
    ->  observations_from_cloud + cloud_posture_leads  ->  IntelIngest  ->  the ONE world-model

Doctrine, by construction:
  * PROVE-DON'T-GUESS. Everything minted is an OBSERVATION tagged ``IntelSourceKind.CLOUD_POSTURE``
    projecting as ``GROUNDING_INTEL``; a posture LEAD is only ever promoted to a FACT by the
    INDEPENDENT ``verify.policy_path`` oracle re-deriving a grant path over the retained graph (see
    ``confirm_cloud_privilege_path``). A sensor NEVER writes a Finding and NEVER promotes a lead.
  * OFFLINE-FIRST + GATED / FAIL-CLOSED. ``CloudPostureImportSensor`` is Tier-1 passive (it reads an
    operator-supplied export file, no network) — kill-switch gated, needs no entitlement. Any LIVE
    pull (``CloudInventoryPullSensor``) is Tier-2: it declares the operator's collector host as
    ``egress_hosts`` (the egress gate REFUSES it unless charter-allowlisted) and requires
    ``ACTIVE_RECON`` — opt-in, default OFFLINE (no configured URL -> a clean skip).
  * DEGRADES CLEANLY. No export file / a malformed export / no configured collector -> a failed
    ToolResult with a reason (never a crash, never a guess).
  * DETERMINISM. The tool OUTPUT reflects the operator's cloud, but ``parse -> observations -> project``
    is a PURE, replayable function of that output (caller ``seq``, no wallclock, no rng); claim-keyed
    ``obs_id`` makes re-ingest idempotent; a malformed export yields zero observations.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import urllib.error
import urllib.request

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.from_cloud import observations_from_cloud
from ..intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from ..intel.refs import EntityRef
from ..verify.policy_path import build_policy_graph, confirm_privilege_path
from ..worldmodel.models import NodeKind

# The IAM TOPOLOGY (who-can-assume-what / who-holds-what-grant) is the real policy the cloud reports —
# a reliable source, content probably-true (Admiralty A2, on par with the Nmap sensor). It is still a
# GROUNDING_INTEL observation, not a fact: the policy-path oracle re-derives a privilege path before any
# reachability claim becomes a FACT.
_CLOUD_TOPOLOGY_RELIABILITY = SourceReliability(reliability=Reliability.A, credibility=Credibility.C2)

# A posture JUDGEMENT (public / over-privileged / mis-configured) is a CSPM heuristic — MODERATE trust
# (Admiralty C3), deliberately below the topology: a lead to re-verify, not evidence to trust.
_CLOUD_POSTURE_LEAD_RELIABILITY = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)

_SOURCE = "cloud_posture"
_DEFAULT_TIMEOUT_S = 60

# Principals that denote "anyone" — an anonymous / wildcard grantee is public exposure by definition.
_ANON_PRINCIPALS = frozenset({
    "*", "allusers", "all_users", "anonymous", "public", "everyone",
    "authenticatedusers", "authenticated-users", "allauthenticatedusers", "principal:*",
})
# Write/admin-tier access tokens — a grant of one of these is a mutate/escalate capability.
_WRITE_ADMIN_ACCESS = frozenset({
    "write", "put", "modify", "update", "delete", "create", "read_write", "readwrite",
    "admin", "owner", "full", "root", "all", "*", "manage",
})


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_anon(principal: Any) -> bool:
    return _norm(principal).replace("-", "").replace("_", "") in {
        p.replace("-", "").replace("_", "") for p in _ANON_PRINCIPALS}


def _is_write_admin(access: Any) -> bool:
    return _norm(access).replace("-", "_") in _WRITE_ADMIN_ACCESS


# ---------------------------------------------------------------------------
# export normalisation — ScoutSuite / Prowler / native -> the native inventory
# ---------------------------------------------------------------------------
#
# The native inventory (also the shape the CLI ``intel ingest-cloud`` accepts) is::
#
#     {"principals": [{"id", "kind"?, "can_assume": [...], "member_of": [...]}],
#      "resources":  [{"id", "kind"?, "public": bool?, "sensitive": bool?, "encrypted": bool?,
#                      "grants": [{"principal", "access"?}]}]}
#
# The adapters below map a documented subset of the common CSPM export shapes onto it. Each is TOTAL
# (a missing/oddly-typed field is skipped, never raised) so a partial or unfamiliar export degrades to
# whatever it could extract, never a crash.


def _detect_format(doc: Any) -> str:
    """Best-effort format detection for an operator cloud export (deterministic)."""
    if not isinstance(doc, dict):
        return "native"
    if "principals" in doc or "resources" in doc:
        return "native"
    if isinstance(doc.get("services"), dict):
        return "scoutsuite"
    if isinstance(doc.get("findings"), list) or isinstance(doc.get("Findings"), list):
        return "prowler"
    return "native"


def _from_native(doc: dict) -> dict:
    """Pass a native inventory through, keeping only well-typed principals/resources. Returns COPIES so
    normalisation never mutates the caller's export (purity)."""
    principals = [dict(p) for p in (doc.get("principals") or []) if isinstance(p, dict) and p.get("id")]
    resources = [dict(r) for r in (doc.get("resources") or []) if isinstance(r, dict) and r.get("id")]
    return {"provider": doc.get("provider", ""), "principals": principals, "resources": resources}


def _from_scoutsuite(doc: dict) -> dict:
    """Map a (normalised) ScoutSuite ``services`` export onto the native inventory. Reads the IAM
    service (roles/users/groups -> principals with can_assume/member_of/grants) and storage services
    (buckets with a public flag) -> resources. Total: any missing branch contributes nothing."""
    services = doc.get("services") if isinstance(doc.get("services"), dict) else {}
    principals: list[dict] = []
    resources: list[dict] = []

    iam = services.get("iam") if isinstance(services.get("iam"), dict) else {}
    for kind, bucket_key in (("role", "roles"), ("user", "users"), ("group", "groups")):
        entries = iam.get(bucket_key) if isinstance(iam.get(bucket_key), dict) else {}
        for pid, meta in entries.items():
            meta = meta if isinstance(meta, dict) else {}
            pr: dict[str, Any] = {"id": meta.get("id") or meta.get("name") or pid, "kind": kind}
            if isinstance(meta.get("can_assume"), list):
                pr["can_assume"] = meta["can_assume"]
            if isinstance(meta.get("member_of"), list):
                pr["member_of"] = meta["member_of"]
            # ScoutSuite grants are on the principal (resource + access); re-key onto resources below.
            for g in meta.get("grants") or []:
                if isinstance(g, dict) and g.get("resource"):
                    resources.append({"id": g["resource"], "grants": [
                        {"principal": pr["id"], "access": g.get("access", "")}]})
            principals.append(pr)

    # storage-style services carry a public flag per bucket/object store
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        buckets = svc.get("buckets") if isinstance(svc.get("buckets"), dict) else {}
        for bid, meta in buckets.items():
            meta = meta if isinstance(meta, dict) else {}
            rid = meta.get("id") or meta.get("name") or bid
            res: dict[str, Any] = {"id": rid, "kind": "datastore"}
            if meta.get("public") is not None:
                res["public"] = bool(meta.get("public"))
            enc = meta.get("encryption_enabled", meta.get("encrypted"))
            if enc is not None:
                res["encrypted"] = bool(enc)
            if meta.get("sensitive") is not None:
                res["sensitive"] = bool(meta.get("sensitive"))
            resources.append(res)

    return {"provider": doc.get("provider", "aws"), "principals": principals, "resources": resources}


def _from_prowler(doc: dict) -> dict:
    """Map a Prowler findings export (``{"findings": [...]}`` / ``{"Findings": [...]}``) onto the native
    inventory. Prowler is a posture-CHECK tool, so it primarily contributes RESOURCES + public/mis-config
    signals (a public-exposure / mis-config check that FAILED); it carries little grant topology. Total."""
    findings = doc.get("findings")
    if not isinstance(findings, list):
        findings = doc.get("Findings") if isinstance(doc.get("Findings"), list) else []
    resources: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        rid = (f.get("resource_id") or f.get("resource_arn") or f.get("ResourceId")
               or f.get("resource") or "")
        if not rid:
            continue
        status = _norm(f.get("status") or f.get("Status") or f.get("status_code"))
        check = _norm(f.get("check_id") or f.get("CheckID") or f.get("check_title") or f.get("title"))
        failed = status in ("fail", "failed", "alarm", "warning") or status.startswith("fail")
        res: dict[str, Any] = {"id": rid, "kind": "cloud_resource"}
        if failed and ("public" in check or "expose" in check or "anonymous" in check):
            res["public"] = True
        if failed and ("encrypt" in check or "unencrypt" in check):
            res["encrypted"] = False
            res["sensitive"] = True
        resources.append(res)
    return {"provider": doc.get("provider", "aws"), "principals": [], "resources": resources}


def normalize_cloud_export(doc: Any, fmt: str = "auto") -> dict:
    """Normalise an operator cloud export (native / ScoutSuite / Prowler) into the native inventory,
    synthesising an explicit anonymous grant for any ``public`` resource so the fact "an anonymous
    principal has a grant path to R" (which is exactly what public exposure means) is oracle-provable
    over the retained graph. Total and pure — a malformed/unknown export yields an empty inventory."""
    if not isinstance(doc, dict):
        return {"principals": [], "resources": []}
    kind = fmt if fmt in ("native", "scoutsuite", "prowler") else _detect_format(doc)
    # the adapters return fresh dicts (COPIES for native), so the synthesis below never mutates the
    # caller's export — a pure function of the input.
    inv = {"native": _from_native, "scoutsuite": _from_scoutsuite, "prowler": _from_prowler}[kind](doc)

    # A resource flagged public is, by definition, reachable by the anonymous principal. Re-express that
    # authoritative fact as an explicit ``*`` grant so ``build_policy_graph`` sees it and the oracle can
    # re-derive the public-access path — a faithful normalisation of "public=true", not a fabrication.
    for r in inv.get("resources", []):
        if not isinstance(r, dict):
            continue
        grants = [g for g in (r.get("grants") or []) if isinstance(g, dict)]
        public = bool(r.get("public")) or any(_is_anon(g.get("principal")) for g in grants)
        if public:
            r["public"] = True
            if not any(_is_anon(g.get("principal")) for g in grants):
                grants = grants + [{"principal": "*", "access": "read"}]
            r["grants"] = grants
    return inv


# ---------------------------------------------------------------------------
# posture LEADS — mis-config / public exposure / over-privileged grant
# ---------------------------------------------------------------------------


def _resource_ref(rid: str, kind_hint: str = "") -> EntityRef:
    kinds = {"datastore": NodeKind.DATASTORE, "database": NodeKind.DATASTORE, "bucket": NodeKind.DATASTORE}
    return EntityRef(kind=kinds.get(_norm(kind_hint), NodeKind.CLOUD_RESOURCE), key=_norm(rid))


def cloud_posture_leads(
    inventory: dict,
    *,
    seq: int,
    source: str = _SOURCE,
    source_kind: IntelSourceKind = IntelSourceKind.CLOUD_POSTURE,
    reliability: SourceReliability = _CLOUD_POSTURE_LEAD_RELIABILITY,
    lead_confidence: float = 0.6,
) -> list[Observation]:
    """Mint the posture LEADS a CSPM export implies onto the resource nodes: PUBLIC EXPOSURE (a public
    resource / an anonymous grantee), an OVER-PRIVILEGED grant (write/admin access — a lead the
    policy-path oracle can prove), and a MIS-CONFIGURATION (an unencrypted sensitive datastore — an
    honest, un-oracle-provable lead). Every lead is a ``GROUNDING_INTEL`` observation, never a fact.

    PURE + total: claim-keyed ``obs_id`` (no positional counter, no clock, no rng) so re-ingest /
    reordering / an intra-batch duplicate collapse to one observation. A resource with no posture issue
    mints nothing."""
    if not isinstance(inventory, dict):
        return []
    out: list[Observation] = []

    def _lead(subject: EntityRef, *, lead_class: str, oracle_provable: bool,
              evidence: str, extra: dict | None = None) -> Observation:
        attrs = {"cloud_lead": True, "lead_class": lead_class, "lead_source": source,
                 "oracle_provable": oracle_provable}
        if extra:
            attrs.update(extra)
        return Observation(
            obs_id=f"{source}:{seq}:lead:{subject.node_id}|{lead_class}",
            source=source, source_kind=source_kind, collector=source,
            subject=subject, relation=None, object=None, attrs=attrs,
            source_reliability=reliability, confidence=lead_confidence, seq=seq, evidence=evidence)

    for r in inventory.get("resources", []) or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        ref = _resource_ref(r["id"], r.get("kind", ""))
        grants = [g for g in (r.get("grants") or []) if isinstance(g, dict)]
        anon = [g for g in grants if _is_anon(g.get("principal"))]
        if bool(r.get("public")) or anon:
            who = anon[0].get("principal") if anon else "public"
            out.append(_lead(ref, lead_class="public_exposure", oracle_provable=True,
                             evidence=(f"cloud posture lead: resource {r['id']} is publicly exposed "
                                       f"(anonymous grantee {who!r}) — CSPM heuristic, re-verify the "
                                       f"anonymous grant path with the policy-path oracle"),
                             extra={"anonymous_principal": _norm(who)}))
        over = [g for g in grants if _is_write_admin(g.get("access")) and not _is_anon(g.get("principal"))]
        if over and bool(r.get("sensitive")):
            g0 = over[0]
            out.append(_lead(ref, lead_class="excessive_privilege", oracle_provable=True,
                             evidence=(f"cloud posture lead: {g0.get('principal')!r} holds "
                                       f"{g0.get('access')!r} over sensitive resource {r['id']} — "
                                       f"re-verify the grant path with the policy-path oracle"),
                             extra={"grantee": _norm(g0.get("principal")), "access": _norm(g0.get("access"))}))
        if bool(r.get("sensitive")) and r.get("encrypted") is False:
            out.append(_lead(ref, lead_class="misconfiguration", oracle_provable=False,
                             evidence=(f"cloud posture lead: sensitive resource {r['id']} is not "
                                       f"encrypted at rest — an honest lead (no reachability oracle proves it)")))
    return out


def cloud_observations(
    inventory: dict,
    *,
    seq: int,
    source: str = _SOURCE,
    source_kind: IntelSourceKind = IntelSourceKind.CLOUD_POSTURE,
    topology_reliability: SourceReliability = _CLOUD_TOPOLOGY_RELIABILITY,
    lead_reliability: SourceReliability = _CLOUD_POSTURE_LEAD_RELIABILITY,
) -> list[Observation]:
    """The SHARED cloud minter every cloud sensor here reuses: the IAM TOPOLOGY (via
    ``observations_from_cloud``, re-tagged to the CLOUD_POSTURE provenance) + the posture LEADS. One
    way to produce the cloud-posture schema. PURE + total; claim/idx-keyed ``obs_id`` -> idempotent."""
    topo = observations_from_cloud(
        inventory, seq=seq, source=source, source_kind=source_kind, reliability=topology_reliability)
    leads = cloud_posture_leads(
        inventory, seq=seq, source=source, source_kind=source_kind, reliability=lead_reliability)
    return topo + leads


# ---------------------------------------------------------------------------
# the LEAD -> FACT bridge (the policy-path oracle re-derives; the tool is never trusted)
# ---------------------------------------------------------------------------


def confirm_cloud_privilege_path(inventory: dict, principal: str, resource: str, access: str = "",
                                 *, verifier: object = None):
    """Promote a cloud posture lead to a FACT iff a REAL IAM grant path lets ``principal`` reach
    ``resource`` (with ``access``). Re-derives the path over the RETAINED policy graph built from the
    operator export — NOT the sensor's minted world-model beliefs — and judges it with the
    deterministic policy-path oracle. The export is first NORMALISED (the SAME
    ``normalize_cloud_export`` the sensor ran, incl. the faithful public->anonymous-grant re-expression),
    so the oracle re-derives over exactly the policy the sensor observed. Returns a
    ``VerificationResult`` (``confirmed`` iff a path fired). A sensor NEVER calls this itself; a lead is
    promoted only by a caller re-deriving the path over the retained graph, as prove-don't-guess
    demands. (Pass an already-normalised inventory and the normalisation is idempotent.)"""
    graph = build_policy_graph(normalize_cloud_export(inventory))
    return confirm_privilege_path(graph, principal, resource, access, verifier=verifier)  # type: ignore[arg-type]


def confirm_cloud_posture_facts(inventory: dict, *, verifier: object = None) -> list[dict]:
    """Promote the ORACLE-PROVABLE cloud posture LEADS (public exposure / over-broad trust) to FACTS by
    re-deriving each grant PATH over the RETAINED policy graph with the policy-path oracle — NO live cloud
    calls, a pure re-derivation over the operator's own retained export (normalisation is idempotent).

    Mirrors ``cloud_posture_leads`` condition-for-condition, so exactly the leads the sensor minted are
    the ones re-verified here: a PUBLIC-EXPOSURE lead is confirmed iff the anonymous principal has a real
    grant path to the resource; an EXCESSIVE-PRIVILEGE lead iff the named grantee's write/admin grant path
    dominates. Returns the confirmed facts (each ``{principal, resource, access, lead_class}``, ids
    canonicalised to the graph's keys); a benign posture returns ``[]`` (nothing fired). The un-oracle-
    provable ``misconfiguration`` lead (unencrypted-at-rest) is deliberately NOT here — no reachability
    oracle proves it, so it stays an honest LEAD."""
    inv = normalize_cloud_export(inventory)   # idempotent; re-express public=true as an anonymous grant
    graph = build_policy_graph(inv)
    facts: list[dict] = []
    seen: set = set()

    def _confirm(principal: str, resource: str, access: str, lead_class: str, kind_hint: str) -> None:
        key = (lead_class, _norm(principal), _norm(resource), _norm(access))
        if key in seen:
            return
        seen.add(key)
        res = confirm_privilege_path(graph, principal, resource, access, verifier=verifier)  # type: ignore[arg-type]
        if getattr(res, "confirmed", False):
            facts.append({"principal": _norm(principal), "resource": _norm(resource),
                          "access": _norm(access), "lead_class": lead_class,
                          # the raw kind hint so a caller can attach a grounded fact to the SAME resource
                          # node the topology minter created (datastore vs cloud_resource)
                          "resource_kind": str(kind_hint or "")})

    for r in inv.get("resources", []) or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        rid = r["id"]
        kind_hint = r.get("kind", "")
        grants = [g for g in (r.get("grants") or []) if isinstance(g, dict)]
        anon = [g for g in grants if _is_anon(g.get("principal"))]
        if bool(r.get("public")) or anon:
            who = anon[0].get("principal") if anon else "*"
            _confirm(who, rid, "", "public_exposure", kind_hint)
        over = [g for g in grants if _is_write_admin(g.get("access")) and not _is_anon(g.get("principal"))]
        if over and bool(r.get("sensitive")):
            g0 = over[0]
            _confirm(g0.get("principal"), rid, g0.get("access") or "", "excessive_privilege", kind_hint)
    return facts


# ---------------------------------------------------------------------------
# the sensors
# ---------------------------------------------------------------------------


def _load_export(text: str, fmt: str) -> dict:
    """Parse export TEXT into the native inventory (total: bad JSON -> empty inventory)."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return {"principals": [], "resources": []}
    return normalize_cloud_export(doc, fmt)


class CloudPostureImportSensor:
    """Import an operator-provided cloud/IAM/CSPM export FILE (offline, no network) as IAM topology +
    posture leads. args: ``{"inventory_file": "/path/to/export.json", "format": "auto|native|
    scoutsuite|prowler"}``. Passive (Tier-1: reads a local file the operator supplies), needs no
    entitlement and no egress — kill-switch gated only, fail-closed. Graceful absence: a missing/
    unreadable file -> a failed ToolResult with a reason, never a crash."""

    name = "cloud_import"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        inv_file = args.get("inventory_file") if isinstance(args, dict) else None
        if not inv_file or not isinstance(inv_file, str):
            return ToolResult(ok=False, note="cloud_import requires args['inventory_file'] (a cloud export path)")
        if not os.path.isfile(inv_file):
            return ToolResult(ok=False, note=f"cloud_import: inventory file not found: {inv_file}")
        try:
            text = Path(inv_file).read_text(encoding="utf-8")
        except OSError as e:
            return ToolResult(ok=False, note=f"cloud_import: cannot read {inv_file}: {e}")
        fmt = args.get("format") if isinstance(args, dict) else None
        fmt = fmt if isinstance(fmt, str) and fmt in ("native", "scoutsuite", "prowler") else "auto"
        return ToolResult(ok=True, summary=f"imported {os.path.basename(inv_file)} ({fmt})",
                          output={"export": text, "format": fmt})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        text, fmt = out.get("export"), out.get("format", "auto")
        if not isinstance(text, str) or not text.strip():
            return []
        return cloud_observations(_load_export(text, fmt if isinstance(fmt, str) else "auto"), seq=seq)


class CloudInventoryPullSensor:
    """Pull a cloud posture export from an operator-run collector REST endpoint (gated) and mint it as
    IAM topology + posture leads. args: ``{"format": "auto|native|scoutsuite|prowler"}``. The collector
    is a SERVICE, not a probe: the sensor reaches the operator's endpoint (``CRUCIBLE_CLOUD_INVENTORY_URL``
    or an explicit ``api_url``), so it declares that host as ``egress_hosts`` — the egress gate REFUSES it
    unless the operator allowlisted it in the charter — and it is Tier-2 (``ACTIVE_RECON``). OPT-IN,
    default OFFLINE: no configured URL / an unreachable endpoint -> a failed ToolResult (never a crash)."""

    name = "cloud_pull"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False

    def __init__(self, *, api_url: str | None = None, path: str = "/inventory", timeout_s: int = _DEFAULT_TIMEOUT_S) -> None:
        # None -> read the env; an explicit "" disables the sensor deterministically (like BurpWebSensor).
        self._api_url = api_url if api_url is not None else os.environ.get("CRUCIBLE_CLOUD_INVENTORY_URL", "")
        self._path = path
        self._timeout_s = timeout_s
        host = (urlsplit(self._api_url).hostname or "") if self._api_url else ""
        self.egress_hosts: tuple = (host,) if host else ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        if not self._api_url:
            return ToolResult(ok=False, note="cloud_pull: no collector URL configured (set CRUCIBLE_CLOUD_INVENTORY_URL or api_url)")
        fmt = args.get("format") if isinstance(args, dict) else None
        fmt = fmt if isinstance(fmt, str) and fmt in ("native", "scoutsuite", "prowler") else "auto"
        url = self._api_url.rstrip("/") + self._path
        try:
            with urllib.request.urlopen(url, timeout=self._timeout_s) as resp:  # noqa: S310 (operator-configured REST endpoint)
                body = resp.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as e:
            return ToolResult(ok=False, note=f"cloud_pull: collector unreachable at {url}: {e}")
        return ToolResult(ok=True, summary=f"pulled cloud inventory ({fmt})", output={"export": body, "format": fmt})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        text, fmt = out.get("export"), out.get("format", "auto")
        if not isinstance(text, str) or not text.strip():
            return []
        return cloud_observations(_load_export(text, fmt if isinstance(fmt, str) else "auto"), seq=seq)
