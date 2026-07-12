"""
verify.mesh_posture — the confirmation seam (and a minimal offline ingestion) for the service-mesh
posture oracle (Wave-G3).

The service-mesh achieved-state half of prove-don't-guess, and the MESH twin of ``verify.k8s_posture`` /
``verify.cloud_posture``. A mesh linter (istioctl analyze / a config export) reports "PeerAuthentication
is PERMISSIVE" or "this AuthorizationPolicy allows everyone". That is a THIRD-PARTY LEAD — a `fact` only
when a deterministic oracle proves a CONCRETE insecure ACHIEVED STATE over the RETAINED mesh config. This
module is that seam: it routes a retained mesh control through the pure ``mesh_posture_oracle`` and returns
a re-verifiable verdict.

Two properties make this a re-verification rather than a rubber-stamp of the linter's say-so, exactly like
``verify.k8s_posture`` / ``verify.cloud_posture``:

  * The control judged is the RETAINED mesh-config evidence (the effective ``mtls.mode`` / the
    ``action`` + ``rules`` / the Linkerd ``default-inbound-policy``), NOT a re-run of a live mesh/kubectl
    call laundered into a fact. The lead says "permissive / allows everyone"; the oracle re-derives the
    weakness from the observed achieved state and fires only when it literally carries an insecure fact (a
    STRICT / scoped / deny config does not confirm).
  * The retained control is JSON-safe and the oracle is pure, so a confirmed mesh-posture FACT
    RE-VERIFIES OFFLINE from its certificate (``verify.reverify``) with no mesh and no trust in the linter
    — re-run the membership/parse-proof over the retained control, get the same verdict.

No mesh substrate existed in the tree (no ``sensors``/``intel``/``producers`` ingest Istio/Linkerd config),
so this module also carries a MINIMAL, OFFLINE, READ-ONLY ingestion (``ingest_mesh_config``) that maps a
canonical Istio PeerAuthentication + AuthorizationPolicy (or a Linkerd inbound-policy annotation) manifest
— dict / list / JSON string / YAML string — into the canonical mesh-control LEAD shape the oracle judges.
It is an honest first slice: it recognises the two Istio security kinds plus the Linkerd
``default-inbound-policy`` annotation, and SKIPS everything else. Like ``verify.policy_path`` there is NO
active probe and NO gate here: the "capture" is the offline manifest the operator already exported; this is
a pure re-derivation over it. A service-mesh ATTACK is NEVER performed. See ``docs/decisions`` for the
roadmap (an ``intel``/``sensors`` producer, workload-scoped severity, ``to``-only public-endpoint nuance,
Linkerd ServerAuthorization graphs).
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier

# PyYAML is used ONLY if already present (it is a common transitive dep); it is never a hard requirement.
# YAML is parsed with the SAFE loader (no arbitrary object construction) — there is no XXE surface in
# YAML/JSON (that is an XML concern), and a JSON manifest needs no third-party dep at all.
try:  # pragma: no cover - availability varies by host
    import yaml as _yaml
except Exception:  # pragma: no cover
    _yaml = None

# The Istio root namespace: a namespace-less-selector PeerAuthentication / AuthorizationPolicy here applies
# MESH-WIDE (Istio's install default root namespace is ``istio-system``).
_ISTIO_ROOT_NAMESPACES = frozenset({"istio-system", "root", ""})
_ISTIO_SECURITY_KINDS = frozenset({"PeerAuthentication", "AuthorizationPolicy"})
# The Linkerd annotation that sets a workload/namespace default inbound policy.
_LINKERD_INBOUND_ANNOTATION = "config.linkerd.io/default-inbound-policy"


# ---- the confirmation seam (mirrors k8s_posture / cloud_posture) ------------


def mesh_posture_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained mesh-config control — routes to the mesh-posture oracle."""
    return FindingContext.from_mesh_control(dict(control or {})).to_verifier_context()


def confirm_mesh_posture(control: Mapping[str, Any], *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge a retained service-mesh posture control with the deterministic oracle: ``confirmed`` iff the
    control's RETAINED achieved state provably carries an insecure fact — an Istio PeerAuthentication with
    permissive/disabled mTLS, an ALLOW AuthorizationPolicy that admits every caller, or a Linkerd server
    whose ``default-inbound-policy`` is ``all-unauthenticated``. The retained ``control`` is JSON-safe, so
    the same verdict re-verifies offline from the finding's certificate via ``verify.reverify``. A hardened
    control — STRICT mTLS, a scoped/deny policy, an authenticated inbound policy — or one with only
    absent/unknown fields is NOT confirmed (it stays an honest LEAD). NO live mesh call is ever made and no
    mesh is ever attacked: this is a pure re-derivation over already-ingested config."""
    return (verifier or OracleVerifier()).confirm(mesh_posture_context(control))


# ---- minimal offline ingestion (a canonical Istio/Linkerd manifest -> lead) --


def _load_docs(config: Any) -> list[dict]:
    """Coerce a manifest into a list of resource dicts. Accepts a dict, an iterable of dicts, a JSON
    string (object or array), or a YAML string (single- or multi-document, only if PyYAML is present).
    Anything unrecognised yields ``[]`` — this NEVER raises (a malformed manifest is a non-ingestion, not
    a crash), and NEVER executes code (YAML uses the SAFE loader; JSON is inert)."""
    if config is None:
        return []
    if isinstance(config, Mapping):
        return [dict(config)]
    if isinstance(config, str):
        text = config.strip()
        if not text:
            return []
        # try JSON first (no dep); fall back to safe YAML if available.
        try:
            parsed = json.loads(text)
        except Exception:
            if _yaml is None:
                return []
            try:
                parsed = list(_yaml.safe_load_all(text))
            except Exception:
                return []
        return _flatten_parsed(parsed)
    if isinstance(config, Iterable):
        docs: list[dict] = []
        for item in config:
            docs.extend(_load_docs(item))
        return docs
    return []


def _flatten_parsed(parsed: Any) -> list[dict]:
    """Flatten a parsed JSON/YAML structure into resource dicts, handling a bare resource, a list of
    resources, and a Kubernetes ``List`` wrapper (``{"kind": "List", "items": [...]}``)."""
    out: list[dict] = []
    if isinstance(parsed, Mapping):
        if str(parsed.get("kind") or "").strip() == "List" and isinstance(parsed.get("items"), (list, tuple)):
            for item in parsed["items"]:
                if isinstance(item, Mapping):
                    out.append(dict(item))
        else:
            out.append(dict(parsed))
    elif isinstance(parsed, (list, tuple)):
        for item in parsed:
            if isinstance(item, Mapping):
                out.extend(_flatten_parsed(item))
    return out


def _scope_of(namespace: str, spec: Mapping[str, Any]) -> str:
    """Istio scope of a security resource: ``workload`` if it carries a ``selector`` (matchLabels),
    ``mesh`` if it is in the root namespace with no selector (applies mesh-wide), else ``namespace``."""
    selector = spec.get("selector") if isinstance(spec, Mapping) else None
    if isinstance(selector, Mapping) and selector.get("matchLabels"):
        return "workload"
    if (namespace or "").strip().lower() in _ISTIO_ROOT_NAMESPACES:
        return "mesh"
    return "namespace"


def _ingest_one(doc: Mapping[str, Any]) -> dict | None:
    """Map ONE Kubernetes resource dict to a canonical mesh-control lead, or ``None`` if it is not a mesh
    resource this first slice recognises. Read-only, pure, offline."""
    if not isinstance(doc, Mapping):
        return None
    kind = str(doc.get("kind") or "").strip()
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    spec = doc.get("spec") if isinstance(doc.get("spec"), Mapping) else {}
    name = str(meta.get("name") or "").strip()
    namespace = str(meta.get("namespace") or "").strip()

    # -- Istio PeerAuthentication -> effective mTLS mode -----------------------
    if kind == "PeerAuthentication":
        mtls = spec.get("mtls") if isinstance(spec.get("mtls"), Mapping) else {}
        mode = str(mtls.get("mode") or "").strip()
        control: dict[str, Any] = {
            "resource_kind": "PeerAuthentication", "provider": "istio",
            "name": name, "namespace": namespace, "scope": _scope_of(namespace, spec),
        }
        if mode:
            control["mtls_mode"] = mode
        return control

    # -- Istio AuthorizationPolicy -> action + rules ---------------------------
    if kind == "AuthorizationPolicy":
        action = str(spec.get("action") or "").strip()   # unset -> the oracle treats as ALLOW (Istio default)
        rules = spec.get("rules")
        control = {
            "resource_kind": "AuthorizationPolicy", "provider": "istio",
            "name": name, "namespace": namespace, "scope": _scope_of(namespace, spec),
        }
        if action:
            control["action"] = action
        if isinstance(rules, (list, tuple)):
            control["rules"] = [dict(r) if isinstance(r, Mapping) else {} for r in rules]
        return control

    # -- Linkerd default-inbound-policy (annotation form, or a Server carrying it) ---
    annotations = meta.get("annotations") if isinstance(meta.get("annotations"), Mapping) else {}
    inbound = annotations.get(_LINKERD_INBOUND_ANNOTATION)
    if inbound is None and kind == "Server":
        inbound = spec.get("accessPolicy") or spec.get("default_inbound_policy")
    if inbound not in (None, ""):
        return {
            "resource_kind": kind or "Server", "provider": "linkerd",
            "name": name, "namespace": namespace,
            "default_inbound_policy": str(inbound).strip(),
        }
    return None


def ingest_mesh_config(config: Any) -> list[dict]:
    """Offline, READ-ONLY ingestion: map a canonical Istio/Linkerd manifest into the mesh-control LEAD
    shape the ``mesh_posture_oracle`` judges. ``config`` may be a resource dict, an iterable of them, a
    JSON string, or a YAML string (single/multi-doc, only if PyYAML is installed). Recognises Istio
    PeerAuthentication + AuthorizationPolicy and the Linkerd ``default-inbound-policy`` annotation; SKIPS
    everything else. NEVER raises, NEVER calls a mesh/kubectl API, NEVER attacks — it is a pure parse over
    already-exported config. The returned controls are LEADS: only ``mesh_posture_oracle`` /
    ``confirm_mesh_posture`` promotes a control to a FACT."""
    return [c for doc in _load_docs(config) if (c := _ingest_one(doc)) is not None]


def confirm_mesh_config(config: Any, *, verifier: OracleVerifier | None = None) -> list[tuple[dict, VerificationResult]]:
    """Convenience end-to-end: ingest a manifest then adjudicate each recognised control. Returns
    ``[(control, VerificationResult), ...]``; a control is a FACT only where ``result.confirmed`` is True.
    Pure + offline — no mesh call, no attack."""
    v = verifier or OracleVerifier()
    return [(c, confirm_mesh_posture(c, verifier=v)) for c in ingest_mesh_config(config)]
