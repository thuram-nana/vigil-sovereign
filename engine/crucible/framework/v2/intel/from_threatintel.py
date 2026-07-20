"""
intel.from_threatintel — threat-intel feeds (MISP / STIX 2.x / NVD / OSV) → Observations.

Threat intel is the outside world telling you what it has SEEN — indicators of compromise
(domains / IPs / URLs / file hashes / emails) and disclosed vulnerabilities (CVEs /
advisories). This adapter ingests an operator-supplied feed export (OFFLINE-first — a JSON
file the operator drops in, matching the gated-egress doctrine; a live TAXII/NVD pull is a
separate, Tier-2 egress-gated opt-in below) and projects it onto the ONE world-model as
provenance-tagged `Observation`s.

Doctrine, by construction:

  * PROVE-DON'T-GUESS. A feed datum is a LEAD, never a fact. Every observation minted here
    enters the graph as ``GROUNDING_INTEL`` (the ``intel:`` provenance tier) at a moderate
    feed reliability, so it MOVES belief a little but never promotes anything. An IOC that
    matches an in-scope asset raises that asset's Beta belief (corroboration); a retracted /
    false-positive indicator lowers it (``Polarity.REFUTES``). A CVE mints a VULNERABILITY
    node and an ``AFFECTS`` edge to the named PACKAGE / APPLICATION — a correlation, NOT a
    proof: the SBOM/version oracle owns proving the installed version is in the affected
    range. We NEVER fabricate an exploit or a FINDING from a feed's say-so.

  * EXPLOIT-EXISTS is a SIGNAL, not a claim. A known-exploited (CISA KEV) / exploit-available
    advisory raises the correlation confidence (a more actionable lead) and sets an
    ``exploit_known`` attr the risk-reasoning layer can read — it stays an OBSERVATION.

  * UNTRUSTED INPUT. A feed is data, never code: parsed with ``json`` only (no eval), the
    STIX pattern grammar is read with a bounded regex (never evaluated), every list is size-
    capped, and any malformed / unexpected shape is skipped — a garbage feed yields ``[]``,
    never an exception.

  * DETERMINISM. parse → Observation is a pure function of (doc, caller seq): no wallclock,
    no rng. ``obs_id`` IS the (source, seq, claim) key, so re-ingesting / reordering / an
    intra-feed duplicate collapse to one observation (idempotent; belief never inflates).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from ..worldmodel.models import EdgeKind, NodeKind
from .models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from .refs import EntityRef, canonicalize

# A threat-intel feed is a generally-trustworthy but NOT first-hand source: it reports what
# someone else observed. Admiralty B/3 keeps its facts clearly below a self-confirmed A/1
# observation, so a feed corroborates but never dominates the belief of a scanned asset.
_FEED = SourceReliability(reliability=Reliability.B, credibility=Credibility.C3)

# Confidence a datum asserts (before reliability damping in intel.project). Deliberately modest:
# these are leads. Each is >0.5 so an AFFIRMS observation nudges the Beta belief UP (corroboration)
# and a REFUTES one nudges it DOWN — but reliability damping keeps every one of them FAR below a
# self-confirmed fact (~0.9+). Exploit-exists nudges the correlation up (more actionable), never a fact.
_C_IOC = 0.65           # an indicator matching / naming an asset (corroborates the asset)
_C_IOC_WEAK = 0.55      # an indicator not marked for detection (MISP to_ids=false) — a fainter nudge
_C_VULN = 0.6           # the advisory exists (feeds are reliable about that)
_C_AFFECTS = 0.55       # this package/app is NAMED as affected (version membership unproven)
_C_AFFECTS_EXPLOIT = 0.7   # …and a working exploit is known — a hotter lead, still a lead

# Bounds — a feed is untrusted; never let one explode memory / node count.
_MAX_ITEMS = 5000       # events / vulns / objects processed per document
_MAX_ATTRS = 20000      # attributes / indicators processed per document
_MAX_AFFECTED = 512     # affected products per advisory
_MAX_VERSIONS = 64      # enumerated affected versions pinned per product (rest → attrs range)
_MAX_REFS = 32          # references carried per advisory
_STR_CAP = 512          # any single carried string field


# ---------------------------------------------------------------------------
# minting — claim-keyed, deterministic, idempotent
# ---------------------------------------------------------------------------


def _clip(s: Any) -> str:
    return str(s)[:_STR_CAP]


def _mint(
    subject: EntityRef,
    *,
    source: str,
    source_kind: IntelSourceKind,
    seq: int,
    relation: EdgeKind | None = None,
    obj: EntityRef | None = None,
    confidence: float,
    polarity: Polarity = Polarity.AFFIRMS,
    attrs: dict | None = None,
    reliability: SourceReliability = _FEED,
) -> Observation:
    """One Observation with deterministic provenance. ``obs_id`` IS the (source, seq, claim)
    key — no positional index — so the SAME claim (re-declared, reordered, duplicated across
    events) collapses to ONE observation and its belief is never double-counted."""
    rel = relation.value if relation else "_"
    oid = f"{source}:{seq}:{subject.node_id}|{rel}|{obj.node_id if obj else '_'}"
    return Observation(
        obs_id=oid, source=source, source_kind=source_kind, collector=source,
        subject=subject, relation=relation, object=obj, attrs=attrs or {},
        source_reliability=reliability, confidence=confidence, polarity=polarity, seq=seq,
        raw_ref=source, evidence=f"{source} feed datum")


# ---------------------------------------------------------------------------
# IOC → EntityRef  (untrusted values → the asset/indicator they name)
# ---------------------------------------------------------------------------

_HASH_TYPES = frozenset({"md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                         "imphash", "ssdeep", "tlsh", "sha-1", "sha-256", "sha-512"})
_EMAIL_TYPES = frozenset({"email", "email-src", "email-dst", "email-addr", "target-email",
                          "email-reply-to", "whois-registrant-email"})
_DOMAIN_TYPES = frozenset({"domain", "hostname", "domain-name", "domain|ip", "dns"})
_IP_TYPES = frozenset({"ip", "ip-src", "ip-dst", "ipv4-addr", "ipv6-addr",
                       "ip-src|port", "ip-dst|port"})
_URL_TYPES = frozenset({"url", "uri", "link"})


def _host_of(value: str) -> str:
    """Extract a host from a URL or bare host[:port][/path]. Total."""
    s = (value or "").strip()
    if "://" in s:
        return (urlsplit(s).hostname or "").strip()
    return s.split("/")[0].split(":")[0].strip()


def _asset_ref(value: str) -> EntityRef | None:
    """A domain/host ref for a network value — IP literal → HOST, name → DOMAIN (so it lands
    on the SAME node id a scan/collector would mint for that asset)."""
    v = (value or "").strip().rstrip(".").lstrip("*.")
    if not v:
        return None
    try:
        ipaddress.ip_address(v)
        return canonicalize(NodeKind.HOST, v)
    except ValueError:
        return canonicalize(NodeKind.DOMAIN, v)


def _ioc_ref(ioc_type: str, value: str) -> tuple[EntityRef | None, dict]:
    """Map a (type, value) indicator onto the world-model ref it names, plus any extra attrs.
    Returns (None, {}) for an empty/unusable value — the caller skips it."""
    t = (ioc_type or "").strip().lower()
    v = (value or "").strip()
    if not v:
        return None, {}
    # composite MISP values ("value1|value2", e.g. filename|md5): take the malware-y half.
    if t in _IP_TYPES and "|" in v:
        v = v.split("|", 1)[0].strip()
    if t in _DOMAIN_TYPES:
        head = v.split("|", 1)[0].strip()
        return _asset_ref(head), {"ioc_type": t}
    if t in _IP_TYPES:
        return _asset_ref(v), {"ioc_type": t}
    if t in _URL_TYPES:
        host = _host_of(v)
        ref = _asset_ref(host) if host else None
        return ref, {"ioc_type": t, "url": _clip(v)}
    if t in _EMAIL_TYPES:
        return EntityRef(kind=NodeKind.IDENTITY, key=v.lower()), {"ioc_type": t}
    if t in _HASH_TYPES or "|" in v and any(h in t for h in ("md5", "sha")):
        algo = next((h for h in _HASH_TYPES if h in t), t or "hash").replace("-", "")
        digest = v.split("|", 1)[-1].strip().lower() if "|" in v else v.lower()
        return EntityRef(kind=NodeKind.INDICATOR, key=f"{algo}:{digest}"), {"ioc_type": t}
    # any other atomic indicator (filename, mutex, regkey, user-agent, …) → a bare INDICATOR node.
    if t:
        return EntityRef(kind=NodeKind.INDICATOR, key=f"{t}:{v.lower()}"), {"ioc_type": t}
    return None, {}


def _ioc_observation(
    ioc_type: str, value: str, *, source: str, source_kind: IntelSourceKind, seq: int,
    confidence: float, polarity: Polarity, context: dict,
) -> Observation | None:
    ref, extra = _ioc_ref(ioc_type, value)
    if ref is None:
        return None
    attrs = {"threat_intel": True,
             **{k: (v if isinstance(v, bool) else _clip(v)) for k, v in context.items() if v},
             **{k: (v if isinstance(v, bool) else _clip(v)) for k, v in extra.items()}}
    return _mint(ref, source=source, source_kind=source_kind, seq=seq,
                 confidence=confidence, polarity=polarity, attrs=attrs)


# ---------------------------------------------------------------------------
# CVE / advisory → VULNERABILITY node + AFFECTS edges
# ---------------------------------------------------------------------------


def _vuln_ref(advisory_id: str) -> EntityRef:
    return canonicalize(NodeKind.VULNERABILITY, advisory_id)


def _advisory_observations(
    advisory_id: str,
    *,
    source: str,
    seq: int,
    node_attrs: dict,
    affected: list[dict],
    exploit_known: bool,
) -> list[Observation]:
    """Mint the VULNERABILITY node + one AFFECTS edge per named PACKAGE/APPLICATION (name
    anchor) and per feed-ENUMERATED affected version (a version-pinned edge that lands on an
    SBOM node when present). The version RANGE is carried in edge attrs for the oracle to
    evaluate — we mint a version-pinned edge ONLY for versions the feed states explicitly,
    never for versions we would compute from a range."""
    if not advisory_id:
        return []
    vref = _vuln_ref(advisory_id)
    out: list[Observation] = [
        _mint(vref, source=source, source_kind=IntelSourceKind.VULN_DB, seq=seq,
              confidence=_C_VULN, attrs={**node_attrs, "exploit_known": bool(exploit_known)})
    ]
    edge_conf = _C_AFFECTS_EXPLOIT if exploit_known else _C_AFFECTS
    for aff in affected[:_MAX_AFFECTED]:
        name = (aff.get("name") or "").strip().lower()
        if not name:
            continue
        eco = _clip(aff.get("ecosystem") or "")
        vrange = aff.get("range") or {}
        base_attrs = {"ecosystem": eco, "version_range": vrange,
                      "exploit_known": bool(exploit_known), "source": source}
        kinds: list[NodeKind] = [NodeKind.PACKAGE]
        if aff.get("application"):
            kinds.append(NodeKind.APPLICATION)
        for kind in kinds:
            anchor = EntityRef(kind=kind, key=name)
            out.append(_mint(vref, source=source, source_kind=IntelSourceKind.VULN_DB, seq=seq,
                             relation=EdgeKind.AFFECTS, obj=anchor,
                             confidence=edge_conf, attrs=dict(base_attrs)))
        versions = [str(v).strip() for v in (aff.get("versions") or []) if str(v).strip()]
        for ver in versions[:_MAX_VERSIONS]:
            pinned = EntityRef(kind=NodeKind.PACKAGE, key=f"{name}@{ver}".lower())
            out.append(_mint(vref, source=source, source_kind=IntelSourceKind.VULN_DB, seq=seq,
                             relation=EdgeKind.AFFECTS, obj=pinned, confidence=edge_conf,
                             attrs={**base_attrs, "version": _clip(ver), "enumerated": True}))
    return out


# ---- NVD ---------------------------------------------------------------------

_CPE_RE = re.compile(r"^cpe:2\.3:(?P<part>[aoh]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*):")


_NVD_MARKERS = ("descriptions", "metrics", "configurations")


def _is_nvd_cve(c: Any) -> bool:
    return isinstance(c, dict) and bool(c.get("id")) and any(k in c for k in _NVD_MARKERS)


def _nvd_cve_records(doc: Any) -> list[dict]:
    """Pull the list of NVD `cve` objects from any NVD API / export shape. Requires an
    NVD-shaped marker so an OSV record (which also has an ``id``) is NOT misrouted here — it
    falls through to `_osv_records`, keyed on its ``affected`` block."""
    if isinstance(doc, dict):
        if isinstance(doc.get("vulnerabilities"), list):
            return [v.get("cve") for v in doc["vulnerabilities"]
                    if isinstance(v, dict) and isinstance(v.get("cve"), dict)]
        if isinstance(doc.get("cve"), dict):
            return [doc["cve"]]
        if _is_nvd_cve(doc):
            return [doc]
    if isinstance(doc, list):
        return [v["cve"] if isinstance(v, dict) and isinstance(v.get("cve"), dict) else v
                for v in doc if (isinstance(v, dict) and isinstance(v.get("cve"), dict)) or _is_nvd_cve(v)]
    return []


def _nvd_severity(cve: dict) -> dict:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr and isinstance(arr[0], dict):
            data = arr[0].get("cvssData") if isinstance(arr[0].get("cvssData"), dict) else {}
            score = data.get("baseScore")
            sev = arr[0].get("baseSeverity") or data.get("baseSeverity") or ""
            out = {}
            if isinstance(score, (int, float)):
                out["cvss"] = float(score)
            if sev:
                out["severity"] = _clip(sev)
            return out
    return {}


def _nvd_exploit_known(cve: dict) -> bool:
    # CISA KEV entries are marked with cisaExploitAdd; a reference tagged "Exploit" also counts.
    if any(k in cve for k in ("cisaExploitAdd", "cisaActionDue", "cisaRequiredAction")):
        return True
    for ref in cve.get("references", []) or []:
        if isinstance(ref, dict):
            tags = ref.get("tags") or []
            if any(str(t).strip().lower() == "exploit" for t in tags):
                return True
    return False


def _nvd_affected(cve: dict) -> list[dict]:
    """CPE matches → affected products with an (introduced, fixed) range from the version
    bounds NVD supplies. cpe part 'a' also correlates to an APPLICATION node."""
    seen: dict[str, dict] = {}
    for cfg in cve.get("configurations", []) or []:
        nodes = cfg.get("nodes", []) if isinstance(cfg, dict) else []
        for node in nodes or []:
            for m in (node.get("cpeMatch", []) if isinstance(node, dict) else []) or []:
                if not isinstance(m, dict):
                    continue
                cm = _CPE_RE.match(str(m.get("criteria", "")))
                if not cm:
                    continue
                product = cm.group("product").replace("\\", "").strip().lower()
                if not product or product in ("*", "-"):
                    continue
                ver = cm.group("version")
                rng = {}
                for src, dst in (("versionStartIncluding", "introduced"),
                                 ("versionStartExcluding", "introduced_excl"),
                                 ("versionEndIncluding", "last_affected"),
                                 ("versionEndExcluding", "fixed")):
                    if m.get(src):
                        rng[dst] = _clip(m[src])
                entry = seen.setdefault(product, {
                    "name": product, "ecosystem": "cpe", "application": cm.group("part") == "a",
                    "range": {}, "versions": []})
                entry["range"].update(rng)
                if ver and ver not in ("*", "-") and ver not in entry["versions"]:
                    entry["versions"].append(ver)
    return list(seen.values())


def _observations_from_nvd_cve(cve: dict, *, seq: int, source: str) -> list[Observation]:
    cid = str(cve.get("id", "")).strip()
    if not cid:
        return []
    descs = cve.get("descriptions") or []
    summary = ""
    for d in descs if isinstance(descs, list) else []:
        if isinstance(d, dict) and d.get("lang") in ("en", "en-US"):
            summary = _clip(d.get("value", ""))
            break
    refs = [_clip(r.get("url")) for r in (cve.get("references", []) or [])
            if isinstance(r, dict) and r.get("url")][:_MAX_REFS]
    node_attrs = {"cve": cid, "summary": summary, "references": refs, "feed": source,
                  **_nvd_severity(cve)}
    return _advisory_observations(
        cid, source=source, seq=seq, node_attrs=node_attrs,
        affected=_nvd_affected(cve), exploit_known=_nvd_exploit_known(cve))


# ---- OSV ---------------------------------------------------------------------


def _osv_records(doc: Any) -> list[dict]:
    if isinstance(doc, dict):
        if isinstance(doc.get("vulns"), list):
            return [v for v in doc["vulns"] if isinstance(v, dict)]
        if doc.get("id") and "affected" in doc:
            return [doc]
    if isinstance(doc, list):
        return [v for v in doc if isinstance(v, dict) and v.get("id")]
    return []


def _osv_exploit_known(vuln: dict) -> bool:
    ds = vuln.get("database_specific") if isinstance(vuln.get("database_specific"), dict) else {}
    for flag in ("known_exploited", "kev", "cisa_kev"):
        if ds.get(flag):
            return True
    for ref in vuln.get("references", []) or []:
        if isinstance(ref, dict) and str(ref.get("type", "")).strip().upper() in ("EVIDENCE", "EXPLOIT"):
            return True
    return False


def _osv_severity(vuln: dict) -> dict:
    out: dict = {}
    for s in vuln.get("severity", []) or []:
        if isinstance(s, dict) and s.get("score"):
            out["cvss_vector"] = _clip(s.get("score"))
            break
    ds = vuln.get("database_specific") if isinstance(vuln.get("database_specific"), dict) else {}
    if ds.get("severity"):
        out["severity"] = _clip(ds["severity"])
    return out


def _osv_affected(vuln: dict) -> list[dict]:
    out: list[dict] = []
    for aff in vuln.get("affected", []) or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") if isinstance(aff.get("package"), dict) else {}
        name = str(pkg.get("name", "")).strip().lower()
        if not name:
            continue
        eco = str(pkg.get("ecosystem", "")).strip()
        rng: dict = {}
        for r in aff.get("ranges", []) or []:
            for ev in (r.get("events", []) if isinstance(r, dict) else []) or []:
                if not isinstance(ev, dict):
                    continue
                if ev.get("introduced"):
                    rng["introduced"] = _clip(ev["introduced"])
                if ev.get("fixed"):
                    rng["fixed"] = _clip(ev["fixed"])
                if ev.get("last_affected"):
                    rng["last_affected"] = _clip(ev["last_affected"])
        versions = [str(v).strip() for v in (aff.get("versions") or []) if str(v).strip()]
        out.append({"name": name, "ecosystem": eco, "application": False,
                    "range": rng, "versions": versions})
    return out


def _observations_from_osv(vuln: dict, *, seq: int, source: str) -> list[Observation]:
    vid = str(vuln.get("id", "")).strip()
    if not vid:
        return []
    aliases = [_clip(a) for a in (vuln.get("aliases") or []) if a][:_MAX_REFS]
    # prefer the CVE alias as the canonical node id so OSV and NVD collapse onto one node.
    cve_alias = next((a for a in aliases if str(a).upper().startswith("CVE-")), "")
    canonical = cve_alias or vid
    refs = [_clip(r.get("url")) for r in (vuln.get("references", []) or [])
            if isinstance(r, dict) and r.get("url")][:_MAX_REFS]
    node_attrs = {"advisory_id": vid, "aliases": aliases, "references": refs, "feed": source,
                  "summary": _clip(vuln.get("summary") or vuln.get("details") or ""),
                  **_osv_severity(vuln)}
    if cve_alias:
        node_attrs["cve"] = cve_alias
    return _advisory_observations(
        canonical, source=source, seq=seq, node_attrs=node_attrs,
        affected=_osv_affected(vuln), exploit_known=_osv_exploit_known(vuln))


def observations_from_cve(doc: Any, *, seq: int = 0, source: str = "") -> list[Observation]:
    """NVD or OSV CVE/advisory record(s) → VULNERABILITY nodes + AFFECTS edges. Auto-detects
    the shape. Total: an unrecognised/empty document yields []."""
    nvd = _nvd_cve_records(doc)
    if nvd:
        src = source or "nvd"
        out: list[Observation] = []
        for cve in nvd[:_MAX_ITEMS]:
            out.extend(_observations_from_nvd_cve(cve, seq=seq, source=src))
        return out
    osv = _osv_records(doc)
    if osv:
        src = source or "osv"
        out = []
        for vuln in osv[:_MAX_ITEMS]:
            out.extend(_observations_from_osv(vuln, seq=seq, source=src))
        return out
    return []


# ---------------------------------------------------------------------------
# MISP event feed → IOC observations (+ vulnerability attributes)
# ---------------------------------------------------------------------------


def _misp_events(doc: Any) -> list[dict]:
    if isinstance(doc, dict):
        if isinstance(doc.get("response"), list):
            return [e.get("Event", e) for e in doc["response"] if isinstance(e, dict)]
        if isinstance(doc.get("Event"), dict):
            return [doc["Event"]]
        if isinstance(doc.get("Attribute"), list) or isinstance(doc.get("Object"), list):
            return [doc]
    if isinstance(doc, list):
        return [e.get("Event", e) if isinstance(e, dict) else {} for e in doc]
    return []


def _misp_attributes(event: dict) -> list[dict]:
    attrs = [a for a in (event.get("Attribute") or []) if isinstance(a, dict)]
    for obj in event.get("Object") or []:
        if isinstance(obj, dict):
            attrs.extend(a for a in (obj.get("Attribute") or []) if isinstance(a, dict))
    return attrs


def _misp_tags(container: dict) -> list[str]:
    return [_clip(t.get("name")) for t in (container.get("Tag") or [])
            if isinstance(t, dict) and t.get("name")]


def _misp_polarity(attr: dict) -> tuple[Polarity, float]:
    """A MISP attribute NOT for detection (to_ids=false) is a weaker lead; one explicitly
    flagged false-positive REFUTES (drives an asset's belief DOWN through the same channel)."""
    to_ids = attr.get("to_ids", True)
    tags = " ".join(_misp_tags(attr)).lower()
    if attr.get("false_positive") is True or "false-positive" in tags or "false_positive" in tags:
        return Polarity.REFUTES, _C_IOC
    if to_ids is False:
        return Polarity.AFFIRMS, _C_IOC_WEAK
    return Polarity.AFFIRMS, _C_IOC


def observations_from_misp(doc: Any, *, seq: int = 0) -> list[Observation]:
    """A MISP event JSON → IOC observations. Handles ``{"Event": …}``, a REST
    ``{"response":[{"Event":…}]}`` list, and a bare attribute container. Vulnerability
    attributes mint a VULNERABILITY node (a lead — MISP rarely names the affected package).
    Total: malformed input yields []."""
    out: list[Observation] = []
    n_attrs = 0
    for event in _misp_events(doc)[:_MAX_ITEMS]:
        if not isinstance(event, dict):
            continue
        info = _clip(event.get("info") or "")
        event_tags = _misp_tags(event)
        threat = ",".join(event_tags[:8])
        for attr in _misp_attributes(event):
            if n_attrs >= _MAX_ATTRS:
                break
            n_attrs += 1
            atype = str(attr.get("type", "")).strip().lower()
            value = str(attr.get("value", "")).strip()
            if not value:
                continue
            if atype in ("vulnerability", "weakness") and value.upper().startswith(("CVE-", "GHSA-")):
                out.extend(_advisory_observations(
                    value, source="misp", seq=seq,
                    node_attrs={"cve": value.upper(), "feed": "misp", "event": info,
                                "threat": threat},
                    affected=[], exploit_known=False))
                continue
            polarity, conf = _misp_polarity(attr)
            obs = _ioc_observation(
                atype, value, source="misp", source_kind=IntelSourceKind.MISP, seq=seq,
                confidence=conf, polarity=polarity,
                context={"event": info, "threat": threat, "category": attr.get("category")})
            if obs is not None:
                out.append(obs)
    return out


# ---------------------------------------------------------------------------
# STIX 2.x bundle → IOC observations (+ vulnerability objects)
# ---------------------------------------------------------------------------

# object-path = 'value' pairs inside a STIX pattern. We READ the grammar with a regex and
# never evaluate it — a pattern is untrusted data, not an expression to run.
_STIX_PATTERN_RE = re.compile(
    r"""([a-z0-9\-]+):([a-zA-Z0-9_.'"\[\]\- ]+?)\s*(?:=|LIKE|MATCHES)\s*'([^']*)'""")


def _stix_objects(doc: Any) -> list[dict]:
    if isinstance(doc, dict):
        if isinstance(doc.get("objects"), list):
            return [o for o in doc["objects"] if isinstance(o, dict)]
        if doc.get("type"):
            return [doc]
    if isinstance(doc, list):
        return [o for o in doc if isinstance(o, dict) and o.get("type")]
    return []


def _stix_pattern_iocs(pattern: str) -> list[tuple[str, str]]:
    """Extract (ioc_type, value) pairs from a STIX pattern, mapping STIX object types onto the
    MISP-style type vocabulary ``_ioc_ref`` understands."""
    out: list[tuple[str, str]] = []
    for objtype, path, value in _STIX_PATTERN_RE.findall(pattern or "")[:_MAX_VERSIONS]:
        objtype = objtype.lower()
        val = value.strip()
        if not val:
            continue
        if objtype == "domain-name":
            out.append(("domain", val))
        elif objtype in ("ipv4-addr", "ipv6-addr"):
            out.append(("ip-dst", val))
        elif objtype == "url":
            out.append(("url", val))
        elif objtype == "email-addr":
            out.append(("email", val))
        elif objtype == "file":
            # path like  hashes.'SHA-256'  or  hashes.MD5
            algo = path.split(".")[-1].strip().strip("'\"").lower() or "sha256"
            out.append((algo, val))
        elif objtype in ("mutex", "windows-registry-key", "user-account", "autonomous-system"):
            out.append((objtype, val))
    return out


def _stix_cve_id(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if isinstance(ref, dict) and str(ref.get("source_name", "")).lower() == "cve":
            return _clip(ref.get("external_id") or "")
    return _clip(obj.get("name") or "")


def observations_from_stix(doc: Any, *, seq: int = 0) -> list[Observation]:
    """A STIX 2.x bundle (or bare object / list) → IOC observations from ``indicator``
    patterns and VULNERABILITY nodes from ``vulnerability`` objects. A ``revoked`` indicator
    REFUTES (the feed retracted it). Total: malformed input yields []."""
    out: list[Observation] = []
    n_attrs = 0
    for obj in _stix_objects(doc)[:_MAX_ITEMS]:
        otype = str(obj.get("type", "")).strip().lower()
        if otype == "indicator":
            revoked = obj.get("revoked") is True
            polarity = Polarity.REFUTES if revoked else Polarity.AFFIRMS
            name = _clip(obj.get("name") or "")
            labels = ",".join(_clip(x) for x in (obj.get("indicator_types") or obj.get("labels") or [])[:8])
            for ioc_type, value in _stix_pattern_iocs(str(obj.get("pattern", ""))):
                if n_attrs >= _MAX_ATTRS:
                    break
                n_attrs += 1
                o = _ioc_observation(
                    ioc_type, value, source="stix", source_kind=IntelSourceKind.STIX, seq=seq,
                    confidence=_C_IOC, polarity=polarity,
                    context={"stix_indicator": name, "threat": labels,
                             "revoked": revoked if revoked else None})
                if o is not None:
                    out.append(o)
        elif otype == "vulnerability":
            cid = _stix_cve_id(obj)
            if cid:
                out.extend(_advisory_observations(
                    cid, source="stix", seq=seq,
                    node_attrs={"cve": cid.upper(), "feed": "stix",
                                "summary": _clip(obj.get("description") or "")},
                    affected=[], exploit_known=False))
    return out


# ---------------------------------------------------------------------------
# format auto-detection dispatcher
# ---------------------------------------------------------------------------


def detect_format(doc: Any) -> str:
    """Best-effort format sniff → one of 'stix' | 'misp' | 'cve' | ''. Deterministic; never
    raises. Structural markers only (never a value the feed controls into code)."""
    if isinstance(doc, dict):
        if doc.get("type") == "bundle" or (isinstance(doc.get("objects"), list)
                                           and any(isinstance(o, dict) and o.get("type")
                                                   for o in doc["objects"])):
            return "stix"
        if doc.get("spec_version") and doc.get("type"):
            return "stix"
        if isinstance(doc.get("Event"), dict) or isinstance(doc.get("response"), list) \
                or isinstance(doc.get("Attribute"), list):
            return "misp"
        if isinstance(doc.get("vulnerabilities"), list) or isinstance(doc.get("cve"), dict) \
                or isinstance(doc.get("vulns"), list) or isinstance(doc.get("affected"), list):
            return "cve"
        if doc.get("id") and (doc.get("configurations") or doc.get("metrics") or doc.get("descriptions")):
            return "cve"
    if isinstance(doc, list):
        for o in doc:
            if isinstance(o, dict) and o.get("type") and o.get("spec_version"):
                return "stix"
            if isinstance(o, dict) and o.get("id") and ("affected" in o or "descriptions" in o):
                return "cve"
    return ""


def observations_from_threat_feed(doc: Any, *, seq: int = 0, fmt: str = "auto") -> list[Observation]:
    """Ingest a threat-intel feed of any supported format → Observations. ``fmt`` forces a
    parser ('misp'|'stix'|'cve'|'nvd'|'osv'); 'auto' (default) sniffs the shape. Total: an
    unrecognised document yields []."""
    f = (fmt or "auto").strip().lower()
    if f == "auto":
        f = detect_format(doc)
    if f == "misp":
        return observations_from_misp(doc, seq=seq)
    if f == "stix":
        return observations_from_stix(doc, seq=seq)
    if f in ("cve", "nvd", "osv"):
        return observations_from_cve(doc, seq=seq)
    return []


# ---------------------------------------------------------------------------
# gated live pull — OPT-IN, Tier-2 egress-gated (offline stays the default path)
# ---------------------------------------------------------------------------

# Public advisory sources for the OPT-IN live pull. They are queried ABOUT a CVE/package and
# are third parties, never the target. `{query}` is the (url-safe) CVE id.
THREATINTEL_LIVE_ENDPOINTS: dict[IntelSourceKind, str] = {
    IntelSourceKind.VULN_DB: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query}",
}
THREATINTEL_COLLECTOR_HOSTS: tuple[str, ...] = ("services.nvd.nist.gov", "api.osv.dev")


def build_threatintel_live_transport(
    *,
    collector_hosts: tuple[str, ...] = THREATINTEL_COLLECTOR_HOSTS,
    endpoints: dict[IntelSourceKind, str] | None = None,
    target_hosts: tuple[str, ...] = (),
    capture_dir: "object | None" = None,
    client: object | None = None,
):
    """Construct a gated, allowlisted transport for the OPT-IN live advisory pull (a Tier-2,
    egress-gated act — offline file ingest is the default). The transport REFUSES construction
    if any source host overlaps target scope and REFUSES any off-allowlist host before bytes
    leave; the NVD/OSV JSON it returns is parsed by ``observations_from_cve`` unchanged (their
    API responses ARE the offline shapes), so nothing new is trusted. Live responses can mirror
    to ``capture_dir`` to seed the offline fixture corpus."""
    from .transport import GuardedHttpTransport

    return GuardedHttpTransport(
        collector_hosts=collector_hosts,
        endpoints=endpoints or THREATINTEL_LIVE_ENDPOINTS,
        target_hosts=target_hosts,
        capture_dir=capture_dir,  # type: ignore[arg-type]
        client=client,
    )


def live_cve_observations(transport, query: str, *, seq: int = 0,
                          source_kind: IntelSourceKind = IntelSourceKind.VULN_DB) -> list[Observation]:
    """Fetch one advisory through a gated live transport and parse it — the seam that keeps the
    live pull honest: the transport enforces egress policy, the SAME offline parser mints the
    (lead-only) observations. A not-ok record yields [] (graceful absence)."""
    rec = transport.fetch(source_kind, query, seq=seq)
    if not rec.ok:
        return []
    return observations_from_cve(rec.payload, seq=seq)
