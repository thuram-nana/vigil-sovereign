"""profile_observations — feed ``hexstrike_brain.analyze_target`` from VERIFIED, PROVENANCED observations.

H3 — the gap this closes. ``HexstrikeBrain.analyze_target`` builds a ``TargetProfile`` from the observations
PASSED IN, but on the production ``vigil engage --brain hexstrike`` path (``cli._cmd_engage``) it was passed
NONE: every profile came out empty — ``ip_addresses=[] open_ports=[] services={} technologies=[]
attack_surface=0.0 risk=low confidence=0.0`` — so the planner reasoned over a blank slate and the console's
Brain panel showed a fabricated "low" risk for a target nobody had observed.

This module is the FEED. It defines one normalized observation record — :class:`ProfileObservation`, each
carrying its own PROVENANCE and CONFIDENCE — collects those records from VIGIL-OWNED sources available at
engage-start (the signed authority SCOPE; an operator/console-written observations sidecar), and REDUCES
them into exactly the keyword arguments ``analyze_target`` consumes.

Two load-bearing honesty properties, both pinned by tests:

  * A profile built from observations REFLECTS them — an open port observed becomes an open port in the
    profile, a technology observed becomes a technology, etc.
  * UNKNOWN STAYS UNKNOWN. An empty observation set reduces to empty kwargs, so the profile is honest
    unknowns — never a fabricated risk. A value we did not observe is never guessed: an unrecognised
    technology string maps to nothing (not ``UNKNOWN`` shoved into the list), a hostname is never resolved
    to an address here (the brain does no DNS), and two equally-confident CONFLICTING scalar observations
    (two different cloud providers at the same confidence) resolve to UNKNOWN, not an arbitrary pick
    (fail-closed: an ambiguous authority is DENY).

An observation is a PRIOR for the planner — never a fact. The planner PROPOSES; the gate authorizes; the
oracle confirms. Nothing here mints or upgrades anything. stdlib only + the brain's own closed enums, so it
loads in either process leg (no framework / no sigil / no network).
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional

from .hexstrike_brain import TargetType, TechnologyStack


class ObsKind(str, Enum):
    """The closed set of observation kinds the feed understands. Every member maps to a concrete effect on
    the profile (there is no carry-only kind — an observation the profile cannot consume is not accepted,
    so the feed never accumulates dead signals)."""

    IP_ADDRESS = "ip_address"            # a resolved target address -> ip_addresses
    OPEN_PORT = "open_port"              # a port observed open        -> open_ports
    SERVICE = "service"                  # "port/name" (e.g. "443/https") -> open_ports + services[port]
    TLS = "tls"                          # a TLS handshake on a port   -> open_ports + services[port]="tls"
    TECHNOLOGY = "technology"            # a stack fingerprint         -> technologies (mapped; unknown dropped)
    REPO_LANGUAGE = "repo_language"      # a repo's language           -> technologies (mapped; unknown dropped)
    CMS = "cms"                          # a CMS fingerprint           -> cms_type
    CLOUD_PROVIDER = "cloud_provider"    # a cloud provider            -> cloud_provider
    CONTAINER_ORCH = "container_orch"    # a K8s/IaC manifest present  -> target_type=cloud_service
    API_DESCRIPTOR = "api_descriptor"    # an OpenAPI/Swagger present  -> target_type=api_endpoint
    TARGET_TYPE = "target_type"          # an explicit target type     -> target_type


# A tech/language string -> the brain's CLOSED ``TechnologyStack`` enum. Anything not in this map stays
# UNKNOWN (it maps to nothing and is dropped) — a fingerprint we do not recognise is never guessed into a
# stack, and ``TechnologyStack.UNKNOWN`` is deliberately absent as a target so noise never inflates the
# technology list (and, through it, the attack-surface score).
_TECH_ALIASES: dict[str, TechnologyStack] = {
    "apache": TechnologyStack.APACHE, "httpd": TechnologyStack.APACHE, "apache2": TechnologyStack.APACHE,
    "nginx": TechnologyStack.NGINX,
    "iis": TechnologyStack.IIS, "microsoft-iis": TechnologyStack.IIS,
    "node": TechnologyStack.NODEJS, "nodejs": TechnologyStack.NODEJS, "node.js": TechnologyStack.NODEJS,
    "express": TechnologyStack.NODEJS, "javascript": TechnologyStack.NODEJS,
    "typescript": TechnologyStack.NODEJS,
    "php": TechnologyStack.PHP, "laravel": TechnologyStack.PHP, "symfony": TechnologyStack.PHP,
    "python": TechnologyStack.PYTHON, "django": TechnologyStack.PYTHON, "flask": TechnologyStack.PYTHON,
    "fastapi": TechnologyStack.PYTHON,
    "java": TechnologyStack.JAVA, "spring": TechnologyStack.JAVA, "tomcat": TechnologyStack.JAVA,
    "dotnet": TechnologyStack.DOTNET, ".net": TechnologyStack.DOTNET, "asp.net": TechnologyStack.DOTNET,
    "aspnet": TechnologyStack.DOTNET, "c#": TechnologyStack.DOTNET, "csharp": TechnologyStack.DOTNET,
    "wordpress": TechnologyStack.WORDPRESS, "wp": TechnologyStack.WORDPRESS,
    "drupal": TechnologyStack.DRUPAL,
    "joomla": TechnologyStack.JOOMLA,
    "react": TechnologyStack.REACT,
    "angular": TechnologyStack.ANGULAR,
    "vue": TechnologyStack.VUE, "vue.js": TechnologyStack.VUE, "vuejs": TechnologyStack.VUE,
}


@dataclass(frozen=True)
class ProfileObservation:
    """ONE verified observation about the target, tagged with PROVENANCE + CONFIDENCE (0 < confidence <= 1).

    It is a PRIOR for the planner's profile — never a fact, never an authority. ``provenance`` names the
    VIGIL-owned source it came from (e.g. ``authority-scope``, ``sensor:httpx``, ``oracle-fact``);
    ``confidence`` is that source's calibrated trust in THIS value. The reducer keeps unknown unknown: it
    never invents a value, and it drops an observation whose value it cannot normalise."""

    kind: ObsKind
    value: str
    provenance: str
    confidence: float

    def to_dict(self) -> dict:
        return {"kind": self.kind.value, "value": self.value,
                "provenance": self.provenance, "confidence": self.confidence}


def make_observation(kind: Any, value: Any, provenance: Any, confidence: Any) -> Optional[ProfileObservation]:
    """Coerce untyped inputs (a sidecar JSON row) into a :class:`ProfileObservation`, or ``None`` if the row
    is not a well-formed observation. TOTAL — never raises: an unknown kind, an empty value, a
    non-numeric/out-of-range confidence all degrade to ``None`` (the row is dropped), so a single malformed
    sidecar entry can neither crash the feed nor slip an ill-typed value into the profile. Confidence must be
    in ``(0, 1]``: a zero-confidence 'observation' is an ABSENCE, not an observation, and is rejected."""
    try:
        k = ObsKind(str(kind).strip().lower())
    except (ValueError, AttributeError):
        return None
    v = "" if value is None else str(value).strip()
    if not v:
        return None
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return None
    if not (0.0 < c <= 1.0):
        return None
    prov = (str(provenance).strip() if provenance is not None else "") or "unknown"
    return ProfileObservation(kind=k, value=v, provenance=prov, confidence=c)


# ---- small, total parsing helpers ---------------------------------------------------------------

def _as_port(value: str) -> Optional[int]:
    """The leading integer token of ``value`` as a valid TCP/UDP port (1..65535), else ``None``. Accepts a
    bare ``"443"`` or a ``"443/tcp"`` form (the part before the first separator)."""
    tok = value.strip().replace(":", "/").split("/", 1)[0].strip()
    try:
        p = int(tok)
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


def _parse_service(value: str) -> Optional[tuple[int, str]]:
    """Parse a ``"port/name"`` (or ``"port:name"``) service observation into ``(port, name)``. ``name`` may
    be ``""`` when the value is a bare port (the port is still learned; the service name stays unknown).
    Returns ``None`` if there is no valid port."""
    port = _as_port(value)
    if port is None:
        return None
    rest = value.strip().replace(":", "/")
    name = rest.split("/", 1)[1].strip().lower() if "/" in rest else ""
    return port, name


def _of_kind(obs: Iterable[ProfileObservation], kind: ObsKind) -> list[ProfileObservation]:
    return [o for o in obs if o.kind is kind]


def _pick_scalar(obs: Iterable[ProfileObservation], kind: ObsKind) -> Optional[str]:
    """The single highest-confidence value for a SINGLE-VALUED field (cms_type / cloud_provider), normalised
    to lowercase. Fail-closed on ambiguity: if the top confidence is shared by two DIFFERENT values, the
    field stays UNKNOWN (``None``) rather than picking one arbitrarily."""
    rows = [(o.value.strip().lower(), o.confidence) for o in _of_kind(obs, kind) if o.value.strip()]
    if not rows:
        return None
    top = max(c for _, c in rows)
    winners = {val for val, c in rows if c >= top}
    return next(iter(winners)) if len(winners) == 1 else None


def _pick_target_type(obs: Iterable[ProfileObservation]) -> Optional[str]:
    """Resolve target_type from the explicit ``TARGET_TYPE`` observations plus the two derived signals
    (an ``API_DESCRIPTOR`` => api_endpoint, a ``CONTAINER_ORCH`` manifest => cloud_service), by highest
    confidence. Returns the ``TargetType`` value string, or ``None`` when there is no candidate or the top
    confidence is a tie between different types — in which case ``analyze_target`` falls back to its own
    deterministic ``_infer_type`` (url/ports/cloud), which is honest inference, not fabrication."""
    cands: list[tuple[str, float]] = []
    for o in _of_kind(obs, ObsKind.TARGET_TYPE):
        try:
            cands.append((TargetType(o.value.strip().lower()).value, o.confidence))
        except ValueError:
            continue  # an unrecognised type string is dropped, never guessed
    for o in _of_kind(obs, ObsKind.API_DESCRIPTOR):
        cands.append((TargetType.API_ENDPOINT.value, o.confidence))
    for o in _of_kind(obs, ObsKind.CONTAINER_ORCH):
        cands.append((TargetType.CLOUD_SERVICE.value, o.confidence))
    if not cands:
        return None
    top = max(c for _, c in cands)
    winners = {val for val, c in cands if c >= top}
    return next(iter(winners)) if len(winners) == 1 else None


def reduce_to_profile_kwargs(observations: Iterable[ProfileObservation], *,
                             min_confidence: float = 0.0) -> dict[str, Any]:
    """Reduce a bag of :class:`ProfileObservation` into the exact kwargs ``analyze_target`` consumes.

    ``min_confidence`` is a floor: an observation below it is ignored (a caller can demand stronger evidence
    before it shapes the plan). List fields (ip_addresses/open_ports/technologies) are the DISTINCT union of
    qualifying values; single-valued fields (target_type/cms_type/cloud_provider) take the highest-confidence
    value and stay UNKNOWN on a tie. Deterministic (sorted) so an identical observation set yields identical
    kwargs. Returns only the keys ``analyze_target`` accepts; an empty input yields all-empty kwargs (=> the
    profile is honest unknowns, never a fabricated risk)."""
    obs = [o for o in observations if o.confidence >= min_confidence]

    ips: set[str] = set()
    for o in _of_kind(obs, ObsKind.IP_ADDRESS):
        try:
            ips.add(str(ipaddress.ip_address(o.value.strip())))  # canonical; a non-IP string is dropped
        except ValueError:
            continue

    ports: set[int] = set()
    # port -> list of (service_name, confidence); resolved to a single name (or unknown) at the end.
    svc_candidates: dict[int, list[tuple[str, float]]] = {}

    def _learn_service(port: int, name: str, conf: float) -> None:
        ports.add(port)
        if name:
            svc_candidates.setdefault(port, []).append((name, conf))

    for o in _of_kind(obs, ObsKind.OPEN_PORT):
        p = _as_port(o.value)
        if p is not None:
            ports.add(p)
    for o in _of_kind(obs, ObsKind.SERVICE):
        parsed = _parse_service(o.value)
        if parsed is not None:
            _learn_service(parsed[0], parsed[1], o.confidence)
    for o in _of_kind(obs, ObsKind.TLS):
        p = _as_port(o.value)
        if p is not None:
            _learn_service(p, "tls", o.confidence)

    services: dict[int, str] = {}
    for port, cands in svc_candidates.items():
        top = max(c for _, c in cands)
        names = {n for n, c in cands if c >= top}
        if len(names) == 1:                      # unambiguous winner -> a named service
            services[port] = next(iter(names))
        # else: conflicting names at equal confidence -> port stays open, service name UNKNOWN (fail-closed)

    techs: list[TechnologyStack] = []
    seen_t: set[TechnologyStack] = set()
    for o in _of_kind(obs, ObsKind.TECHNOLOGY) + _of_kind(obs, ObsKind.REPO_LANGUAGE):
        t = _TECH_ALIASES.get(o.value.strip().lower())
        if t is not None and t not in seen_t:    # unrecognised fingerprint -> dropped, not guessed
            seen_t.add(t)
            techs.append(t)

    return {
        "target_type": _pick_target_type(obs),
        "ip_addresses": sorted(ips),
        "open_ports": sorted(ports),
        "services": {p: services[p] for p in sorted(services)},
        "technologies": techs,
        "cms_type": _pick_scalar(obs, ObsKind.CMS),
        "cloud_provider": _pick_scalar(obs, ObsKind.CLOUD_PROVIDER),
    }


# ---- VIGIL-owned observation sources (engage-start) ---------------------------------------------

def from_scope(scope: Iterable[str], *, provenance: str = "authority-scope",
               confidence: float = 0.7) -> list[ProfileObservation]:
    """Turn the signed-authority SCOPE hosts into IP_ADDRESS observations — but ONLY the ones that are
    LITERAL IPs. A literal IP the operator signed into the enforced scope is a known target address; a
    hostname or a ``*.wildcard`` is NOT resolved here (the brain does no DNS — an unresolved name stays
    unknown). This is the always-available floor source, so even a plain ``--brain`` engage profiles from
    something real (the address it is scoped to) instead of a blank slate."""
    out: list[ProfileObservation] = []
    seen: set[str] = set()
    for host in scope or []:
        h = str(host or "").strip()
        if not h:
            continue
        try:
            canon = str(ipaddress.ip_address(h))
        except ValueError:
            continue  # hostname / wildcard — not an address; never resolved here
        if canon in seen:
            continue
        seen.add(canon)
        obs = make_observation(ObsKind.IP_ADDRESS.value, canon, provenance, confidence)
        if obs is not None:
            out.append(obs)
    return out


def load_sidecar(path: "str | os.PathLike") -> list[ProfileObservation]:
    """Load normalized observations from a JSON sidecar the console / a prior recon phase writes. Accepts a
    top-level list of rows, or ``{"observations": [...]}``. Each row is ``{kind, value, provenance,
    confidence}``; a malformed row is dropped (via :func:`make_observation`), never fatal. TOTAL and
    fail-soft: an absent/unreadable/unparseable file yields ``[]`` — no observations, honest unknowns."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return []
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        return []
    rows = doc.get("observations") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        return []
    out: list[ProfileObservation] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        obs = make_observation(row.get("kind"), row.get("value"),
                               row.get("provenance"), row.get("confidence"))
        if obs is not None:
            out.append(obs)
    return out


def _resolve_sidecar_path(*, slug: str, base_dir: str,
                          sidecar_path: "str | os.PathLike | None",
                          env: Optional[dict] = None) -> Optional[Path]:
    """Sidecar path resolution, in precedence order: an explicit ``--brain-observations`` arg, else the
    ``VIGIL_BRAIN_OBSERVATIONS`` env, else the per-slug default ``<base_dir>/<slug>/observations.json`` (used
    only when it actually exists — an absent default is simply 'no sidecar')."""
    if sidecar_path:
        return Path(sidecar_path)
    e = env if env is not None else os.environ
    from_env = str(e.get("VIGIL_BRAIN_OBSERVATIONS", "") or "").strip()
    if from_env:
        return Path(from_env)
    default = Path(base_dir) / str(slug or "") / "observations.json"
    return default if default.is_file() else None


def collect_engage_observations(*, slug: str, base_dir: str, scope: Iterable[str],
                                sidecar_path: "str | os.PathLike | None" = None,
                                min_confidence: float = 0.0,
                                env: Optional[dict] = None) -> dict[str, Any]:
    """Assemble every VIGIL-owned observation available at engage-start and reduce it to ``analyze_target``
    kwargs — the production wiring point ``cli._cmd_engage`` calls for ``--brain hexstrike``.

    Sources: the signed-authority SCOPE (literal IPs) + a normalized observations sidecar (explicit arg /
    ``VIGIL_BRAIN_OBSERVATIONS`` env / ``<base_dir>/<slug>/observations.json``). Fail-soft throughout: with
    NO sources present it returns all-empty kwargs, so the profile is honest unknowns and a plain
    ``--brain`` engage proposes the same chain it always did (only the profile is now honest, not
    fabricated). Returns a dict safe to hand straight to ``BrainThink(observations=...)``."""
    observations: list[ProfileObservation] = list(from_scope(scope))
    resolved = _resolve_sidecar_path(slug=slug, base_dir=base_dir, sidecar_path=sidecar_path, env=env)
    if resolved is not None:
        observations.extend(load_sidecar(resolved))
    return reduce_to_profile_kwargs(observations, min_confidence=min_confidence)
