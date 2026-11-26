"""
graph.projector — the one-way spine→graph projector (VIGIL-FUSION F4, slice 1).

**This is the single most dangerous fusion in the program (trust-laundering), so the sovereign rules
are enforced HERE, deterministically:**

  1. **Projection-only, from signed spine records.** The graph is written ONLY by ``project`` over a
     list of ``SpineRecord``. There is no other writer; nothing an LLM or a tool asserts reaches the
     graph except as a spine record, and its veracity is re-derived, never trusted.
  2. **Confirmed ⇔ oracle-signed.** A finding projects to a CONFIRMED node ONLY if the record is a FACT
     carrying BOTH a non-empty signed ``evidence_ref`` AND a ``signature_ref`` (``_is_confirmed``).
     Anything else — including a record that merely *claims* ``status="fact"`` with no evidence — is a
     LEAD. The graph can never launder an unproven claim into a fact.

     **S2 — JOIN-verified CONFIRMED (``VIGIL_GRAPH_EVIDENCE_JOIN``, default OFF; DEMOTE-ONLY).** When the
     flag is OFF the ``evidence_ref`` is trusted on sight for being NON-EMPTY (slice-1 behaviour), and this
     module imports no ``framework`` and is byte-identical to pre-slice. When the flag is ON, a non-empty
     ``evidence_ref`` is no longer enough: it must **dereference** (the S1 ``evidence.resolver``) to a
     ``SignedEvidence`` that **re-verifies with authenticity ANCHORED out-of-band** (``resolve_and_verify(
     ..., expected_trust_root_fingerprint=<engagement pin>).ok`` — the REUSED ``verify_certificate``, never
     a second verifier) AND whose cert binds to THIS finding (``finding_ref``), THIS tenant/engagement
     (``engagement_slug``), and a **host-in-scope** that matches the finding's declared asset host
     (``_host_in_scope``). Authenticity is credited ONLY against the engagement's genuine governance-root
     fingerprint (the anchor that signs the spine); the trust root shipped inside the bundle is NEVER
     trusted on its own (S1's hardened contract — ``.ok`` requires ``authenticity_pinned`` — closes the
     self-signed-bundle hole). Any of these failing (incl. no pin supplied) marks the fact's evidence
     ``unresolved_evidence``, surfacing it as a LEAD. Crucially the join is a MEMBERSHIP OVERLAY: it TAGS
     the node (a prop) but NEVER changes its intrinsic ``is_confirmed``, so the refute / retirement /
     resurrection machinery — which reads ``is_confirmed`` — behaves IDENTICALLY to flag-OFF, and the
     demote is a FILTER at the ``confirmed_findings()`` boundary (``model.GraphView``). Because the ON
     confirmed set is the OFF set minus the tagged nodes, ON ⊆ OFF holds for EVERY spine — not merely
     per-record (a per-record demotion to LEAD would re-open the bare-refute / resurrection path and
     PROMOTE on a multi-record spine: dangling-fact → bare refute → grounded refute → re-attestation). The
     ``framework`` import that powers it is LAZY / function-local, inside the flag-ON branch ONLY
     (FATAL-2), so the module stays framework-free wherever ``framework`` is absent (the sovereign leg).
  3. **Rebuildable + deterministic.** ``project`` sorts records by ``(seq, hash)`` and is a pure
     function — the same spine yields a byte-identical ``GraphView``, so the read-model can be rebuilt
     and independently verified against the spine and cannot silently diverge. No wallclock / RNG: the
     temporal coordinate is the spine ``seq``.
  4. **Bi-temporal, never delete.** A ``refute`` record retires the target node (and its edges) by
     setting ``invalid_from = seq`` — the node stays for audit; it is only excluded from active queries.
  5. **Scope-gated bridges.** A recon bridge to a host/CVE/… is created only if the injected
     ``scope_gate`` admits the host (in-scope only). No gate ⇒ the records are trusted as already
     spine-gated (documented; production wires the host egress/scope gate).
  6. **The graph is inert.** It returns a view; it authorizes nothing. No consumer may read authority
     from it (enforced by the query layer returning only non-authoritative retrieval context).

  7. **S3 — charter objectives are INERT read-model nodes (DEFAULT-OFF behind ``VIGIL_GRAPH_OBJECTIVES``).**
     A declared charter ``goal`` record projects to one ``OBJECTIVE`` node keyed on a stable objective id;
     a ``reach`` record (a worldmodel crown-jewel a PathCertificate reaches) projects ``Asset-[REACHES]->
     Goal`` with the PATH's confirmation; a ``step`` carrying an objective id projects ``ChainStep-
     [PURSUES]->Goal``. A Goal is NEVER a FACT: it is always projected LEAD with no ``evidence_ref``, so
     ``is_confirmed`` (which gates on CHAIN_FINDING) can never return it and ``confirmed_findings`` never
     surfaces it. With the flag OFF, ``goal`` / ``reach`` are UNKNOWN kinds (already fail-closed-ignored)
     and a step's objective id adds no edge — the view is byte-identical to the pre-S3 read-model.

**F4 slice S4 — remediation/retest lifecycle (behind ``VIGIL_GRAPH_LIFECYCLE``, default OFF).** When armed,
the projector additionally recognises two flag-gated record kinds that project the EXISTING signed
remediation/retest certs as INERT nodes/edges, so finding→remediation→retest is ONE traversal:

  * ``remediation`` — a RemediationCertificate → a REMEDIATION node + ``Finding -[REMEDIATED_BY]-> Remediation``
    edge, linked by ``original_finding_cert_digest`` RESOLVING (S1) + re-verifying to the positive finding cert.
    Fail-closed: a remediation whose referenced finding cert is ABSENT (incl. a cross-tenant cert that resolves
    only under another root) or does NOT re-verify projects NO confirmed edge.
  * ``retest`` — a remediation's retest log → RETEST nodes + ``Remediation -[RETESTED_BY]-> Retest`` edges. The
    whole series is adjudicated by the attestation-log AUTHORITY (``verify_log``): the anti-rollback floor is
    re-derived from the SIGNED durable high-water (never a producer-supplied in-band value), the signed head is
    bound to the rebuilt tick hash-chain, and every tick re-verifies. A tick reads 'fixed' ONLY on an
    authenticated (un-truncated) series whose re-verified state is REMEDIATED; otherwise fail-closed.

The lifecycle nodes are INERT — never FACT findings (``confirmed_findings()`` excludes them structurally).
Re-verification is DELEGATED to an injected :class:`LifecycleVerifier` that REUSES the existing verifiers
(S1's ``verify_certificate`` / ``verify_remediation_certificate`` / ``verify_prove_certificate``) — this
module defines NO second verifier and issues NO traffic / runs NO live retest.

FATAL-2: this module's scope imports only pydantic + .model + stdlib (no ``framework``). The default
(framework-touching) wiring, :func:`make_default_lifecycle`, performs every ``framework.v2`` import
FUNCTION-LOCALLY and is only ever constructed on the flag-ON path — so with the flag OFF (the default) the
projector is byte-identical to the pre-slice projector and co-loads no offense engine.

Import-clean: pydantic + .model + stdlib only.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from .model import (
    EVIDENCE_JOIN_CONFIRMED,
    EVIDENCE_JOIN_PROP,
    EVIDENCE_JOIN_UNRESOLVED,
    ConfirmationStatus,
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphView,
    NodeLabel,
    Provenance,
)
from .objectives_flag import objectives_enabled


class SpineRecord(BaseModel):
    """One signed spine record fed to the projector. In production these are read from the CRUCIBLE
    signed spine / the F2 ``AgentState`` fact & lead stores; the projector never trusts a field's
    *claim* of confirmation — it re-derives it from the signed evidence (``_is_confirmed``)."""

    seq: int                        # monotonic spine index (the deterministic temporal coordinate)
    hash: str                       # this record's signed hash
    kind: str                       # chain | step | finding | failure | decision | refute | bridge
    engagement_id: str = ""         # group_id / charter scope
    signature_ref: str = ""         # signed-head / signature reference
    status: str = "lead"            # lead | fact  (a fact still needs evidence_ref to confirm)
    evidence_ref: str = ""          # SCITT/OpenVEX cert id / signed oracle evidence
    props: dict[str, Any] = Field(default_factory=dict)
    # identity + links (stable ids so a lead→confirmed upgrade merges the SAME node)
    chain_id: str = ""
    step_id: str = ""
    finding_ref: str = ""
    parent_step_id: str = ""        # the step that PRODUCED this finding/failure/decision
    prev_step_id: str = ""          # the preceding step (NEXT_STEP)
    refutes_id: str = ""            # for kind=refute: the node id to retire
    objective_id: str = ""          # S3: stable charter-objective id. kind=goal→the OBJECTIVE node key;
    #                                 kind=step→the Goal the step PURSUES; kind=reach→the Goal an asset REACHES
    targets: list[dict[str, Any]] = Field(default_factory=list)   # [{"type":"cve"/"host"/..,"value":..}]


def _is_confirmed(rec: SpineRecord) -> bool:
    """A record is CONFIRMED iff it is an oracle-minted FACT carrying a non-empty signed evidence ref
    AND a signature ref. This mirrors the F2 ``Finding`` invariant — a bare ``status="fact"`` with no
    signed evidence is NOT confirmed; it is a lead."""
    return (rec.status == "fact"
            and bool((rec.evidence_ref or "").strip())
            and bool((rec.signature_ref or "").strip()))


def _is_oracle_grounded_refutation(rec: SpineRecord) -> bool:
    """A refutation may DEMOTE a confirmed fact only if it is itself oracle-grounded — it carries a
    signed ``evidence_ref`` + ``signature_ref`` attesting that a re-execution FAILED. Per the veracity
    firewall, demotion comes only from re-execution failing, never from an unauthenticated opinion; a
    bare ``kind="refute"`` claim (an LLM's 'looks like a false positive') can retire only a LEAD."""
    return bool((rec.evidence_ref or "").strip()) and bool((rec.signature_ref or "").strip())


def _provenance(rec: SpineRecord, confirmed: bool) -> Provenance:
    return Provenance(
        spine_hash=rec.hash,
        signature_ref=rec.signature_ref,
        evidence_ref=rec.evidence_ref if confirmed else "",   # a lead carries NO evidence ref
        engagement_id=rec.engagement_id,
        confirmation=ConfirmationStatus.CONFIRMED if confirmed else ConfirmationStatus.LEAD,
    )


_BRIDGE_LABELS: dict[str, NodeLabel] = {
    "cve": NodeLabel.CVE, "host": NodeLabel.HOST, "ip": NodeLabel.HOST, "subdomain": NodeLabel.HOST,
    "port": NodeLabel.PORT, "technology": NodeLabel.TECHNOLOGY, "tech": NodeLabel.TECHNOLOGY,
    "endpoint": NodeLabel.ENDPOINT,
}
_FINDING_BRIDGE_EDGE: dict[NodeLabel, EdgeType] = {
    NodeLabel.CVE: EdgeType.FINDING_RELATES_CVE,
    NodeLabel.ENDPOINT: EdgeType.FINDING_AFFECTS_ENDPOINT,
    NodeLabel.PORT: EdgeType.FINDING_AFFECTS_PORT,
    NodeLabel.TECHNOLOGY: EdgeType.FINDING_AFFECTS_TECH,
    NodeLabel.HOST: EdgeType.FOUND_ON,
}

ScopeGate = Callable[[str], bool]


# ==========================================================================================================
# F4 slice S4 — remediation/retest lifecycle (flag-gated; default OFF, framework-free when OFF).
# ==========================================================================================================
# DEFAULT-OFF affirmative flag (same vocabulary as S1's VIGIL_EVIDENCE_RESOLVER). The SINGLE arming point:
# when not affirmative, the ``remediation``/``retest`` record kinds project NOTHING (byte-identical to the
# pre-slice projector, where they were unknown kinds) and NO ``framework`` import is reached (FATAL-2).
_LIFECYCLE_ENV = "VIGIL_GRAPH_LIFECYCLE"
_LIFECYCLE_AFFIRMATIVE = frozenset({"1", "true", "yes", "on", "enabled"})
_LIFECYCLE_KINDS = frozenset({"remediation", "retest"})

# Projected retest statuses — the HONEST, re-verified outcome. ONLY ``verified_fixed`` means a proven fix.
_STATUS_VERIFIED_FIXED = "verified_fixed"
_STATUS_STILL_VULNERABLE = "still_vulnerable"
_STATUS_INCONCLUSIVE = "inconclusive"
_STATUS_REFUSED = "refused"
_STATUS_UNVERIFIED = "unverified"        # the signed 4-state verdict did NOT re-verify — NOT fixed
_STATUS_ROLLED_BACK = "rolled_back"      # the attestation-log authority could not vouch for the series
#                                          (floor unavailable / chain/head invalid / truncated) — NOT fixed
NO_RETEST = "no_retest"                  # a remediation with no retest at all (distinct from a passing one)

# The four signed verdict states (``prove_driver.State``) — trusted ONLY on an AUTHENTICATED series.
_STATE_REMEDIATED = "REMEDIATED"
_STATE_STILL_VULNERABLE = "STILL_VULNERABLE"
_STATE_INCONCLUSIVE = "INCONCLUSIVE"
_STATE_REFUSED = "REFUSED"

# The drift label the attestation-log authority derived rides on each RetestTick; only _LABEL_UNKNOWN is used
# locally, for the fail-closed (unauthenticated) marker.
_LABEL_UNKNOWN = "unknown"


def lifecycle_enabled() -> bool:
    """True iff ``VIGIL_GRAPH_LIFECYCLE`` is affirmative (default False). When False, the lifecycle record
    kinds are inert and the projector reaches no ``framework`` import (FATAL-2 / flag-OFF byte-identity)."""
    return (os.environ.get(_LIFECYCLE_ENV) or "").strip().lower() in _LIFECYCLE_AFFIRMATIVE


@dataclass(frozen=True)
class FindingLink:
    """Resolving + re-verifying a referenced finding cert via the S1 resolver. ``ok`` ⇔ the EXISTING
    ``verify_certificate`` confirmed it over the retained bytes + the pinned governance trust root;
    ``finding_ref`` is the RESOLVED cert's own ref (the authoritative graph link target)."""
    ok: bool
    finding_ref: str = ""


@dataclass(frozen=True)
class RetestTick:
    """One tick of an AUTHENTICATED retest series: its 0-indexed ``seq``, the RE-VERIFIED 4-state ``state``
    (``prove_driver.State``), and the drift ``label`` the attestation-log authority derived. Only ever
    produced for a series the authority verified end-to-end — so its ``state`` is already trustworthy."""
    seq: int
    state: str
    label: str = ""


@dataclass(frozen=True)
class RetestSeries:
    """The attestation-log AUTHORITY's verdict on a retest log, delegated to ``attestation_log.verify_log``.
    ``authenticated`` is True ONLY when the signed head binds the rebuilt tick hash-chain, the durable
    high-water floor confirms the series is NOT truncated/rolled-back (``check_highwater`` entry_count guard),
    AND every tick re-verifies (``verify_prove_certificate``). It is the ANTI-ROLLBACK anchor — the floor is
    re-derived from the authenticated durable ledger, NEVER from a producer-supplied in-band value. When
    ``authenticated`` is False (floor unavailable, chain/head invalid, truncated, or a tick failed) the series
    carries no trustworthy 'fixed' and the projector caps it to ``rolled_back`` (fail-closed)."""
    authenticated: bool
    reason: str = ""
    ticks: "tuple[RetestTick, ...]" = ()


@runtime_checkable
class LifecycleVerifier(Protocol):
    """The injected re-verification seam for the lifecycle projection. The projector NEVER re-verifies a cert
    or re-derives a floor itself — it delegates to these, each REUSING an EXISTING verifier/authority (S1's
    ``verify_certificate`` / ``verify_remediation_certificate`` / the attestation-log ``verify_log``, which
    itself runs ``verify_prove_certificate`` per tick AND the signed-head + durable-high-water anti-rollback
    guards), NEVER a second verifier. Injected as a deterministic fake in the offline tests;
    :func:`make_default_lifecycle` is the framework wiring.

    ``verify_retest_series`` takes an OPAQUE ``log_ref`` (the attestation-log directory / id for a
    remediation) and returns the AUTHENTICATED series — so the anti-rollback floor comes from the signed
    durable ledger the authority checks, never from the untrusted spine record."""

    def resolve_finding(self, cert_digest: str) -> Optional[FindingLink]: ...
    def verify_remediation(self, remediation_cert: dict) -> bool: ...
    def verify_retest_series(self, log_ref: str) -> RetestSeries: ...


def _authority_host(url: str, *, fold_backslash: bool) -> str:
    """The host of a URL authority, computed client-INDEPENDENTLY on backslash: with ``fold_backslash``
    a ``\\`` terminates the authority (WHATWG/browser), without it the ``\\`` stays in the authority
    (RFC/urllib) — the caller gates BOTH readings so ``https://evil.tld\\@in-scope.tld`` can't smuggle a
    host past one client's parse. Bracketed IPv6 (``[::1]:8080``) yields the inner address, not ``""``."""
    if not isinstance(url, str):
        return ""
    s = url.replace("\\", "/") if fold_backslash else url
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/?#]*)", s) or re.match(r"^([^/?#]*)", s)
    auth = (m.group(1) if m else "").rsplit("@", 1)[-1]       # strip userinfo (last @)
    if auth.startswith("["):                                  # bracketed IPv6: [host]:port
        end = auth.find("]")
        return (auth[1:end] if end != -1 else auth[1:]).strip().lower()
    return auth.split(":", 1)[0].strip().lower()              # host[:port]


def _bridge_hosts(target_type: str, value: str) -> list[str]:
    """The candidate host(s) to scope-check for a bridge target. A list so an ENDPOINT's two
    client-independent readings are BOTH gated. Empty ⇒ the bridge carries no host (cve/technology)."""
    label = _BRIDGE_LABELS.get(target_type)
    v = value.strip() if isinstance(value, str) else ""
    if label == NodeLabel.HOST:
        return [v.lower()]
    if label == NodeLabel.ENDPOINT:
        return sorted({_authority_host(v, fold_backslash=True), _authority_host(v, fold_backslash=False)})
    if label == NodeLabel.PORT:
        if v.startswith("["):                                # [ipv6]:port
            end = v.find("]")
            return [(v[1:end] if end != -1 else v[1:]).strip().lower()]
        return [v.rsplit(":", 1)[0].strip().lower()] if ":" in v else [v.lower()]
    return []   # cve / technology carry no host


def _host_in_scope(target_type: str, value: str, scope_gate: Optional[ScopeGate]) -> bool:
    """A bridge carrying a host (host/endpoint/port) is admitted only if EVERY candidate host clears the
    gate — an out-of-scope host cannot re-enter under any label or client reading. An UNEXTRACTABLE host
    is fail-closed (denied when a gate is present). cve/technology carry no host. No gate ⇒ trust the
    spine's pre-gating."""
    hosts = _bridge_hosts(target_type, value)
    if not hosts:
        return True
    if scope_gate is None:
        return True
    for h in hosts:
        if not h:                    # extraction failed → fail-closed (never silently admit)
            return False
        try:
            if not scope_gate(h):
                return False
        except Exception:            # noqa: BLE001 — a gate error is fail-closed
            return False
    return True


# --------------------------------------------------------------------------------------------------
# S2 — JOIN-verified CONFIRMED. Default-OFF affirmative flag (same vocabulary as the rest of the
# program, e.g. the S1 resolver's ``VIGIL_EVIDENCE_RESOLVER``). When OFF, the join NEVER runs, no
# ``framework`` import happens, and the module is byte-identical/framework-free.
# --------------------------------------------------------------------------------------------------
_JOIN_ENV = "VIGIL_GRAPH_EVIDENCE_JOIN"
_JOIN_AFFIRMATIVE = frozenset({"1", "true", "yes", "on", "enabled"})

# Oracle-context keys whose VALUE is a bare host, and keys whose value is a URL whose AUTHORITY is the
# host. The oracle_context is a strict ``verify.adapter.FindingContext`` (extra keys forbidden), so these
# are the real host-bearing slots a reproducing posture context carries (e.g. the clickjacking/CSP
# posture control's ``url``, a TLS/cert-validity context's ``host``). Scanned recursively (bounded depth)
# because a control rides one level down under its own key (``clickjacking_control`` → ``url``).
_CTX_HOST_KEYS = frozenset({"host", "hostname", "target_host", "authority"})
_CTX_URL_KEYS = frozenset({"url", "uri", "endpoint", "target", "request_url", "source"})


def evidence_join_enabled() -> bool:
    """True iff ``VIGIL_GRAPH_EVIDENCE_JOIN`` is affirmative (default False). The single arming point:
    when False the join never runs, nothing imports ``framework``, and projection is byte-identical to
    slice-1 (``evidence_ref`` trusted for being non-empty)."""
    return (os.environ.get(_JOIN_ENV) or "").strip().lower() in _JOIN_AFFIRMATIVE


def _declared_hosts(rec: SpineRecord) -> "frozenset[str]":
    """The finding's declared asset host(s) — every host a host/endpoint/port target names, via the SAME
    client-independent ``_bridge_hosts`` extraction the scope gate uses. Empty ⇒ the finding claims no
    host (the host-in-scope demote is then a no-op — a posture/CVE finding is not host-bound)."""
    hosts: set[str] = set()
    for t in rec.targets:
        if not isinstance(t, dict):
            continue
        ttype = str(t.get("type", "")).lower()
        if _BRIDGE_LABELS.get(ttype) in (NodeLabel.HOST, NodeLabel.ENDPOINT, NodeLabel.PORT):
            for h in _bridge_hosts(ttype, str(t.get("value", "")).strip()):
                if h:
                    hosts.add(h)
    return frozenset(hosts)


def _context_hosts(oc: Any, _depth: int = 0) -> "frozenset[str]":
    """Every host named in the cert's authenticated oracle-context — a bounded recursive scan of the
    presented ``oracle_context`` for a bare-host key or a URL whose authority is the host (parsed by the
    SAME client-independent ``_authority_host``). Empty ⇒ the context names no host (so a host-bound
    finding cannot corroborate its asset host against it → fail-closed demote)."""
    if _depth > 5 or not isinstance(oc, dict):
        return frozenset()
    found: set[str] = set()
    for k, v in oc.items():
        key = str(k).lower()
        if isinstance(v, str) and v.strip():
            if key in _CTX_HOST_KEYS:
                found.add(v.strip().lower())
            elif key in _CTX_URL_KEYS:
                h = _authority_host(v, fold_backslash=True)
                if h:
                    found.add(h)
        elif isinstance(v, dict):
            found |= _context_hosts(v, _depth + 1)
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    found |= _context_hosts(item, _depth + 1)
    return frozenset(found)


def _evidence_join_confirms(rec: SpineRecord, *, group_id: str, evidence_root: Any,
                            contexts: Optional[dict], scope_gate: Optional[ScopeGate],
                            trust_root_fingerprint: Optional[str]) -> bool:
    """The S2 join: True iff ``rec.evidence_ref`` DEREFERENCES + RE-VERIFIES — authenticity ANCHORED to the
    engagement's OUT-OF-BAND governance fingerprint — to a cert that binds to this finding, engagement, and
    host-in-scope. Called ONLY when ``_is_confirmed(rec)`` already held, so its only effect is to TIGHTEN
    (demote-only). Every failure path returns False (fail-closed). The ``framework`` import is
    function-local and reached ONLY here (flag-ON branch) — FATAL-2. The import is itself inside the try,
    so a process where ``framework`` is absent (the sovereign leg, were the flag somehow armed there)
    demotes the fact to a LEAD rather than dropping the node — demote-only."""
    # AUTHENTICITY MUST BE PINNED OUT-OF-BAND. Without the engagement's genuine governance fingerprint the
    # S1 resolver would fall back to the trust root shipped INSIDE the (untrusted) bundle — which a forger
    # can replace with their own self-signed root (the S1 red-pen HIGH). A caller that cannot supply the
    # out-of-band pin cannot soundly confirm: fail-closed demote (never trust the bundle's own trust-root).
    pin = trust_root_fingerprint.strip() if isinstance(trust_root_fingerprint, str) else ""
    if not pin:
        return False

    try:
        from framework.v2.evidence.resolver import get_resolver  # noqa: PLC0415 (FATAL-2: framework-only evidence join, flag-gated)
        resolver = get_resolver(evidence_root)
    except Exception:          # noqa: BLE001 — a missing framework / resolver-construction error is a fail-closed demote
        return False
    if resolver is None:
        # the S1 resolver is not armed (``VIGIL_EVIDENCE_RESOLVER`` off) / unavailable → the evidence
        # cannot be re-verified, so the fact cannot be JOIN-confirmed (fail-closed, demote-only).
        return False

    evidence_ref = (rec.evidence_ref or "").strip()
    if not evidence_ref:
        return False
    ctx_map = contexts if isinstance(contexts, dict) else None
    try:
        # (1) RESOLVES + (2) RE-VERIFIES, PINNED to the out-of-band fingerprint — the REUSED
        # verify_certificate verdict (never a second verifier). ``rv.ok`` already folds in
        # ``authenticity_pinned`` (``.ok == verification.ok AND authenticity_pinned``); the explicit
        # ``authenticity_pinned`` check below is belt-and-braces so an unpinned verdict can never confirm.
        rv = resolver.resolve_and_verify(evidence_ref, ctx_map, expected_trust_root_fingerprint=pin)
    except Exception:          # noqa: BLE001 — a resolver error is a fail-closed demote
        return False
    if rv is None or not rv.ok or not rv.authenticity_pinned:
        return False
    cert = rv.signed.certificate

    # (3) the cert's finding_ref binds to THIS node's finding.
    if not rec.finding_ref or cert.finding_ref != rec.finding_ref:
        return False
    # (4) same tenant/engagement — a cert that resolves only under another engagement does not confirm
    # (tenant isolation is additionally enforced by the resolver, which indexes only its own root tree).
    expected_engagement = rec.engagement_id or group_id
    if cert.engagement_slug != expected_engagement:
        return False
    # (5) host-in-scope demote: the cert's oracle-context host must corroborate the finding's declared
    # asset host AND that host must clear the charter scope gate (both reuse existing primitives).
    declared = _declared_hosts(rec)
    if declared:
        for h in declared:
            if not _host_in_scope("host", h, scope_gate):   # out of charter scope → demote
                return False
        ctx_hosts = _context_hosts(ctx_map.get(cert.finding_ref) if ctx_map else None)
        if not declared <= ctx_hosts:                       # evidence does not name the claimed host → demote
            return False
    return True


def _project_record(view: GraphView, rec: SpineRecord, scope_gate: Optional[ScopeGate], *,
                    objectives: bool = False, lifecycle: Optional["LifecycleVerifier"] = None,
                    group_id: str = "", evidence_root: Any = None,
                    contexts: Optional[dict] = None, trust_root_fingerprint: Optional[str] = None) -> None:
    kind = (rec.kind or "").lower()
    if kind in _LIFECYCLE_KINDS:
        # DEFAULT-OFF: with the flag unarmed (or no verifier injected) these kinds project NOTHING — exactly
        # as the pre-slice projector treated an unknown kind — and NO framework import is reached (FATAL-2).
        if lifecycle_enabled() and lifecycle is not None:
            if kind == "remediation":
                _project_remediation(view, rec, lifecycle)
            else:
                _project_retest(view, rec, lifecycle)
        return
    if kind == "refute":
        if rec.refutes_id:
            target = view.get(rec.refutes_id)
            grounded = _is_oracle_grounded_refutation(rec)
            # a confirmed, oracle-signed fact can be demoted ONLY by an oracle-grounded refutation —
            # an unauthenticated refute silently dropping a proven finding is the mirror of laundering.
            if target is not None and target.is_confirmed and not grounded:
                return
            # a bare (non-grounded) refute of a LEAD is resurrectable: a later oracle confirmation of the
            # same finding clears it (see GraphView.upsert_node), so an opinion can't suppress a proof.
            view.retire_node(rec.refutes_id, rec.seq, grounded=grounded)
        return

    if kind == "chain":
        cid = rec.chain_id or rec.hash
        view.upsert_node(GraphNode(id=f"chain:{cid}", label=NodeLabel.ATTACK_CHAIN,
                                   props=dict(rec.props), provenance=_provenance(rec, False),
                                   valid_from=rec.seq))
        return

    if kind == "step":
        sid = rec.step_id or rec.hash
        node = GraphNode(id=f"step:{sid}", label=NodeLabel.CHAIN_STEP, props=dict(rec.props),
                         provenance=_provenance(rec, False), valid_from=rec.seq)
        view.upsert_node(node)
        if rec.chain_id:
            view.add_edge(GraphEdge(src=f"chain:{rec.chain_id}", dst=node.id, type=EdgeType.HAS_STEP,
                                    provenance=_provenance(rec, False), valid_from=rec.seq))
        if rec.prev_step_id:
            view.add_edge(GraphEdge(src=f"step:{rec.prev_step_id}", dst=node.id, type=EdgeType.NEXT_STEP,
                                    provenance=_provenance(rec, False), valid_from=rec.seq))
        # S3: a step that DECLARES an objective id PURSUES that Goal. A step with NO objective id creates
        # NO edge — linkage is never fabricated. LEAD provenance: a step authorizes nothing, and the
        # PURSUES edge is a plan-intent link, never a proof. Default-OFF: no edge unless the flag is on.
        if objectives and rec.objective_id:
            view.add_edge(GraphEdge(src=node.id, dst=f"objective:{rec.objective_id}",
                                    type=EdgeType.PURSUES, provenance=_provenance(rec, False),
                                    valid_from=rec.seq))
        return

    if kind == "finding":
        # ``confirmed`` is the INTRINSIC status (status=fact + non-empty evidence_ref + signature_ref). It
        # drives the node's provenance, its edges, its bridges AND the refute/retirement/resurrection
        # machinery EXACTLY as flag-OFF — the S2 join NEVER changes it.
        confirmed = _is_confirmed(rec)
        props = dict(rec.props)
        if confirmed and evidence_join_enabled():
            # S2 MEMBERSHIP OVERLAY (demote-only): tag whether this intrinsic fact's evidence_ref
            # dereferences + re-verifies + binds to this finding/engagement/host-in-scope. This is a
            # QUERY-BOUNDARY marker ONLY — it does NOT touch ``confirmed`` — so the projection (incl.
            # refutes/retirement/resurrection) stays identical to OFF and the demote is applied as a FILTER
            # at confirmed_findings() (so ON ⊆ OFF holds for EVERY spine, not merely per-record — a
            # per-record demotion would re-open the bare-refute/resurrection path and PROMOTE on a
            # multi-record spine). A demoted fact surfaces as a lead/unresolved_evidence.
            passed = _evidence_join_confirms(rec, group_id=group_id, evidence_root=evidence_root,
                                             contexts=contexts, scope_gate=scope_gate,
                                             trust_root_fingerprint=trust_root_fingerprint)
            props[EVIDENCE_JOIN_PROP] = EVIDENCE_JOIN_CONFIRMED if passed else EVIDENCE_JOIN_UNRESOLVED
        fid = rec.finding_ref or rec.hash
        node = GraphNode(id=f"finding:{fid}", label=NodeLabel.CHAIN_FINDING, props=props,
                         provenance=_provenance(rec, confirmed), valid_from=rec.seq)
        node = view.upsert_node(node)
        if rec.parent_step_id:
            view.add_edge(GraphEdge(src=f"step:{rec.parent_step_id}", dst=node.id, type=EdgeType.PRODUCED,
                                    provenance=_provenance(rec, confirmed), valid_from=rec.seq))
            view.add_edge(GraphEdge(src=f"step:{rec.parent_step_id}", dst=node.id, type=EdgeType.LED_TO,
                                    provenance=_provenance(rec, confirmed), valid_from=rec.seq))
        _project_bridges(view, rec, node.id, confirmed, scope_gate)
        return

    if kind == "failure":
        node = GraphNode(id=f"failure:{rec.hash}", label=NodeLabel.CHAIN_FAILURE, props=dict(rec.props),
                         provenance=_provenance(rec, False), valid_from=rec.seq)
        view.upsert_node(node)
        if rec.parent_step_id:
            view.add_edge(GraphEdge(src=f"step:{rec.parent_step_id}", dst=node.id,
                                    type=EdgeType.FAILED_WITH, provenance=_provenance(rec, False),
                                    valid_from=rec.seq))
        return

    if kind == "decision":
        node = GraphNode(id=f"decision:{rec.hash}", label=NodeLabel.CHAIN_DECISION, props=dict(rec.props),
                         provenance=_provenance(rec, False), valid_from=rec.seq)
        view.upsert_node(node)
        if rec.parent_step_id:
            view.add_edge(GraphEdge(src=node.id, dst=f"step:{rec.parent_step_id}",
                                    type=EdgeType.DECISION_PRECEDED, provenance=_provenance(rec, False),
                                    valid_from=rec.seq))
        return

    # S3 — charter objectives, gated DEFAULT-OFF. With the flag off these two kinds are NOT recognised and
    # fall through to the unknown-kind fail-closed-ignore below, byte-identical to the pre-S3 read-model.
    if objectives and kind == "goal":
        # A declared charter objective → ONE inert OBJECTIVE node keyed on a stable objective id. Always
        # LEAD, never any evidence_ref: a Goal is never a FACT, is never returned by confirmed_findings(),
        # and authorizes nothing. No objective id ⇒ no node (never fabricate an unkeyed Goal). Re-projecting
        # the same id MERGEs (GraphView.upsert_node), never duplicates.
        if rec.objective_id:
            view.upsert_node(GraphNode(id=f"objective:{rec.objective_id}", label=NodeLabel.OBJECTIVE,
                                       props=dict(rec.props), provenance=_provenance(rec, False),
                                       valid_from=rec.seq))
        return

    if objectives and kind == "reach":
        # A worldmodel crown-jewel a PathCertificate reaches → Asset-[REACHES]->Goal. The asset is a recon
        # bridge target (host/endpoint/port/cve/tech); a host-bearing asset must clear the SAME scope gate
        # (``_host_in_scope``) — an out-of-scope host can't re-enter under the Goal path. The REACHES edge
        # inherits the PATH's confirmation (``_is_confirmed``): a lead route is a lead edge. No objective
        # id ⇒ nothing projected (never fabricate linkage).
        if rec.objective_id:
            _project_reach(view, rec, f"objective:{rec.objective_id}", scope_gate)
        return
    # unknown kind → silently ignored (fail-closed: an unrecognized record projects nothing)


def _project_bridges(view: GraphView, rec: SpineRecord, finding_id: str, confirmed: bool,
                     scope_gate: Optional[ScopeGate]) -> None:
    """Bridge a finding to recon targets (CVE/host/port/tech/endpoint). A HOST target must clear the
    scope gate. The bridge edge/​target inherits the finding's confirmation — a lead's bridges are lead
    edges (never presented as confirmed relationships)."""
    for t in rec.targets:
        if not isinstance(t, dict):
            continue
        ttype = str(t.get("type", "")).lower()
        value = str(t.get("value", "")).strip()
        label = _BRIDGE_LABELS.get(ttype)
        if not label or not value:
            continue
        if not _host_in_scope(ttype, value, scope_gate):
            continue
        tid = f"{label.value.lower()}:{value}"
        view.upsert_node(GraphNode(id=tid, label=label, props={"value": value},
                                   provenance=_provenance(rec, False), valid_from=rec.seq))
        edge_type = _FINDING_BRIDGE_EDGE.get(label, EdgeType.FOUND_ON)
        view.add_edge(GraphEdge(src=finding_id, dst=tid, type=edge_type,
                                provenance=_provenance(rec, confirmed), valid_from=rec.seq))


def _project_reach(view: GraphView, rec: SpineRecord, objective_id: str,
                   scope_gate: Optional[ScopeGate]) -> None:
    """S3 — project ``Asset-[REACHES]->Goal`` from a crown-jewel reach record. The asset(s) a
    PathCertificate reaches are carried as recon bridge targets; EACH host-bearing asset must clear the
    SAME ``_host_in_scope`` scope gate the finding bridges use (an out-of-scope host can't enter under the
    Goal path, under any label or client reading). The asset NODE is a plain recon node (LEAD, like any
    bridge target); the REACHES EDGE inherits the path's confirmation (``_is_confirmed``) — a lead route
    is a lead edge, a signed/verified route a confirmed edge. The Goal itself stays untouched and inert."""
    confirmed = _is_confirmed(rec)
    for t in rec.targets:
        if not isinstance(t, dict):
            continue
        ttype = str(t.get("type", "")).lower()
        value = str(t.get("value", "")).strip()
        label = _BRIDGE_LABELS.get(ttype)
        if not label or not value:
            continue
        if not _host_in_scope(ttype, value, scope_gate):
            continue
        tid = f"{label.value.lower()}:{value}"
        view.upsert_node(GraphNode(id=tid, label=label, props={"value": value},
                                   provenance=_provenance(rec, False), valid_from=rec.seq))
        view.add_edge(GraphEdge(src=tid, dst=objective_id, type=EdgeType.REACHES,
                                provenance=_provenance(rec, confirmed), valid_from=rec.seq))


# ==========================================================================================================
# F4 slice S4 — remediation/retest lifecycle projection (flag-ON only; every verifier is INJECTED).
# ==========================================================================================================
def _remediation_id(rec: SpineRecord, cert: dict) -> str:
    """A deterministic, stable id for a remediation node (and the key a ``retest`` record links to). Prefer
    the caller-supplied ``props['remediation_id']`` (production wiring sets it to a content digest of the
    cert, shared with the retest record); else the cert's own signature bytes; else the record hash. No
    wallclock/RNG — a pure function of the record."""
    rid = str(rec.props.get("remediation_id") or "").strip()
    if rid:
        return rid
    sig = cert.get("signature")
    if isinstance(sig, dict) and sig.get("sig"):
        return str(sig.get("sig"))[:40]
    return rec.hash


def _project_remediation(view: GraphView, rec: SpineRecord, lifecycle: "LifecycleVerifier") -> None:
    """Project a RemediationCertificate as an INERT REMEDIATION node, linked to its finding by
    ``original_finding_cert_digest`` RESOLVING (S1) + re-verifying to the positive finding cert.

    Fail-closed, in two layers:
      * a remediation cert that does NOT re-verify (``verify_remediation`` False — bad sig / oracle still
        fires) projects NOTHING; and
      * a remediation whose referenced finding cert is ABSENT (``resolve_finding`` → None, incl. a cross-tenant
        cert that resolves only under another root) or does NOT re-verify (``FindingLink.ok`` False) projects
        the node but NO ``Finding -[REMEDIATED_BY]-> Remediation`` edge.

    The node/edge are LEAD-provenance and INERT — a REMEDIATION node is never a FACT finding, so it can never
    appear in ``confirmed_findings()`` (structural, label-based)."""
    cert = rec.props.get("remediation_cert")
    if not isinstance(cert, dict):
        return
    if not _safe_verify_remediation(lifecycle, cert):
        return   # fail-closed: an unauthentic / still-firing remediation is not projected at all
    rem_id = _remediation_id(rec, cert)
    node_id = f"remediation:{rem_id}"
    finding_cert_digest = str(cert.get("original_finding_cert_digest") or "")
    view.upsert_node(GraphNode(
        id=node_id, label=NodeLabel.REMEDIATION,
        props={"remediation_id": rem_id,
               "verdict": str(cert.get("verdict") or ""),
               "finding_ref": str(cert.get("finding_ref") or ""),
               "bug_class": str(cert.get("bug_class") or ""),
               "original_finding_cert_digest": finding_cert_digest},
        provenance=_provenance(rec, False), valid_from=rec.seq))     # LEAD / inert
    # The CONFIRMED link: resolve + re-verify the referenced positive finding cert via S1 (verify_certificate).
    link = _safe_resolve_finding(lifecycle, finding_cert_digest) if finding_cert_digest else None
    if link is not None and link.ok and link.finding_ref:
        view.add_edge(GraphEdge(
            src=f"finding:{link.finding_ref}", dst=node_id, type=EdgeType.REMEDIATED_BY,
            props={"link_verified": True, "finding_cert_digest": finding_cert_digest},
            provenance=_provenance(rec, False), valid_from=rec.seq))
    # else: ABSENT / cross-tenant / UNVERIFIED finding cert ⇒ NO confirmed edge (fail-closed); node unlinked.


def _authenticated_status(state: str) -> str:
    """Map a RE-VERIFIED state from an AUTHENTICATED series to its projected status. ``verified_fixed`` is
    sound here ONLY because the caller reached this on an ``authenticated`` series — the attestation-log
    authority has already confirmed the signed head binds the tick chain AND the durable high-water floor
    shows no truncation, so a REMEDIATED tick is genuinely the latest, not a rolled-back stale one."""
    if state == _STATE_REMEDIATED:
        return _STATUS_VERIFIED_FIXED
    if state == _STATE_STILL_VULNERABLE:
        return _STATUS_STILL_VULNERABLE
    if state == _STATE_INCONCLUSIVE:
        return _STATUS_INCONCLUSIVE
    if state == _STATE_REFUSED:
        return _STATUS_REFUSED
    return _STATUS_UNVERIFIED


def _project_retest(view: GraphView, rec: SpineRecord, lifecycle: "LifecycleVerifier") -> None:
    """Project a remediation's retest series as INERT RETEST nodes + ``Remediation -[RETESTED_BY]-> Retest``
    edges, driven ENTIRELY by the attestation-log AUTHORITY (``verify_retest_series`` →
    ``attestation_log.verify_log``). The record carries only an OPAQUE ``retest_log_ref`` (which log this
    remediation's re-proofs live in); it carries NO in-band ticks and NO in-band floor — those are the
    forgeable vectors this slice deliberately does not trust.

    ANTI-ROLLBACK (fail-closed): the authority re-derives the floor from the SIGNED durable high-water, binds
    the signed head to the rebuilt tick hash-chain, and re-verifies every tick. A tick reads ``verified_fixed``
    ONLY when (a) the series is ``authenticated`` (chain/head/floor all check out — no truncation) AND (b) the
    re-verified state is REMEDIATED. When the series is NOT authenticated (floor unavailable, chain/head
    invalid, truncated/rolled-back, or a tick failed re-verify) the projection caps to a single ``rolled_back``
    marker — never 'fixed'."""
    rem_id = str(rec.props.get("remediation_id") or "").strip()
    if not rem_id:
        return
    log_ref = str(rec.props.get("retest_log_ref") or "").strip()
    if not log_ref:
        return                                  # no authenticated ledger to consult ⇒ nothing (fail-closed)
    rem_node_id = f"remediation:{rem_id}"
    series = _safe_verify_retest_series(lifecycle, log_ref)
    if not series.authenticated:
        # FAIL-CLOSED: the authority could not vouch for the series (unavailable / rolled-back / truncated /
        # tampered / a tick failed). It CANNOT be 'fixed'; surface a single rolled_back marker so the
        # break/regression is visible, never laundered into a verified_fixed.
        rid = f"retest:{rem_id}:unauthenticated"
        view.upsert_node(GraphNode(
            id=rid, label=NodeLabel.RETEST,
            props={"status": _STATUS_ROLLED_BACK, "state": "", "label": _LABEL_UNKNOWN,
                   "authenticated": False, "reason": series.reason},
            provenance=_provenance(rec, False), valid_from=rec.seq))     # LEAD / inert
        view.add_edge(GraphEdge(
            src=rem_node_id, dst=rid, type=EdgeType.RETESTED_BY,
            props={"status": _STATUS_ROLLED_BACK}, provenance=_provenance(rec, False), valid_from=rec.seq))
        return
    # AUTHENTICATED series: project each tick; verified_fixed is now SOUND (the floor confirmed non-truncation).
    for tv in series.ticks:
        if not isinstance(tv, RetestTick):
            continue
        status = _authenticated_status(str(tv.state or ""))
        rid = f"retest:{rem_id}:{int(tv.seq)}"
        view.upsert_node(GraphNode(
            id=rid, label=NodeLabel.RETEST,
            props={"status": status, "state": str(tv.state or ""), "label": str(tv.label or ""),
                   "authenticated": True, "seq": int(tv.seq)},
            provenance=_provenance(rec, False), valid_from=rec.seq))     # LEAD / inert
        view.add_edge(GraphEdge(
            src=rem_node_id, dst=rid, type=EdgeType.RETESTED_BY,
            props={"status": status, "seq": int(tv.seq)},
            provenance=_provenance(rec, False), valid_from=rec.seq))


# -- safe delegation wrappers: a verifier that raises must not abort the whole projection (fail-closed). ----
def _safe_verify_remediation(lifecycle: "LifecycleVerifier", cert: dict) -> bool:
    try:
        return bool(lifecycle.verify_remediation(cert))
    except Exception:   # noqa: BLE001 — a verifier error is fail-closed (NOT a confirmed remediation)
        return False


def _safe_resolve_finding(lifecycle: "LifecycleVerifier", cert_digest: str) -> Optional[FindingLink]:
    try:
        return lifecycle.resolve_finding(cert_digest)
    except Exception:   # noqa: BLE001 — a resolver error is fail-closed (absent → no confirmed edge)
        return None


def _safe_verify_retest_series(lifecycle: "LifecycleVerifier", log_ref: str) -> RetestSeries:
    try:
        rv = lifecycle.verify_retest_series(log_ref)
        return rv if isinstance(rv, RetestSeries) else RetestSeries(authenticated=False, reason="bad verifier result")
    except Exception as e:   # noqa: BLE001 — an authority error is fail-closed (unauthenticated, never 'fixed')
        return RetestSeries(authenticated=False, reason=f"verify_retest_series raised: {e!r}")


def spine_record_from_finding(finding: Any, *, seq: int, hash: str, signature_ref: str = "",
                              engagement_id: str = "", parent_step_id: str = "",
                              targets: Optional[list[dict[str, Any]]] = None) -> SpineRecord:
    """Build a ``finding`` SpineRecord from an F2 ``agent.state.Finding``. Confirmation is NOT taken from
    the finding's word — it is re-derived by ``_is_confirmed`` from ``status`` + the finding's signed
    ``evidence_ref`` + the spine record's ``signature_ref`` (which the caller supplies from the signed
    spine entry). A finding not yet on the signed spine (no ``signature_ref``) projects as a LEAD."""
    return SpineRecord(
        seq=seq, hash=hash, kind="finding",
        engagement_id=engagement_id, signature_ref=signature_ref,
        status=str(getattr(finding, "status", "lead") or "lead"),
        evidence_ref=str(getattr(finding, "evidence_ref", "") or ""),
        finding_ref=str(getattr(finding, "ref", "") or hash),
        parent_step_id=parent_step_id,
        props={"ref": str(getattr(finding, "ref", "") or ""),
               "title": str(getattr(finding, "title", "") or ""),
               "severity": str(getattr(finding, "severity", "") or ""),
               "bug_class": str(getattr(finding, "bug_class", "") or ""),
               "source": str(getattr(finding, "source", "") or "")},
        targets=targets or [])


def project(records: list[SpineRecord], *, group_id: str = "",
            scope_gate: Optional[ScopeGate] = None, objectives: Optional[bool] = None,
            evidence_root: Any = None, contexts: Optional[dict] = None,
            trust_root_fingerprint: Optional[str] = None,
            lifecycle: Optional["LifecycleVerifier"] = None) -> GraphView:
    """Project a list of signed spine records into a typed ``GraphView`` — the ONLY writer. Deterministic
    (records applied in ``(seq, hash)`` order), so the same spine rebuilds a byte-identical view. A
    finding is CONFIRMED only when its record carries signed oracle evidence; everything else is a LEAD.
    Never raises on a malformed record LIST — a non-``SpineRecord`` element (e.g. a torn/None row from
    a lossy spine loader) is skipped, not crashed on.

    ``objectives`` gates the S3 charter-objective projection (``goal`` / ``reach`` kinds and the step→Goal
    ``PURSUES`` edge). ``None`` (the default) reads the DEFAULT-OFF ``VIGIL_GRAPH_OBJECTIVES`` env flag, so
    every existing caller is unchanged and the view is byte-identical to the pre-S3 read-model unless an
    operator opts in; an explicit ``True`` / ``False`` pins it (for deterministic offline tests). Reading
    an env flag keeps the function deterministic for a fixed environment — no wallclock, no RNG.

    ``evidence_root`` / ``contexts`` / ``trust_root_fingerprint`` feed the S2 JOIN
    (``VIGIL_GRAPH_EVIDENCE_JOIN``, default OFF; see the module docstring). ``evidence_root`` is the tenant
    root the S1 resolver dereferences under (defaults to ``crucible_root()``); ``contexts`` maps
    ``finding_ref -> oracle_context`` — the presented re-fire evidence the join re-verifies binding against
    AND extracts the cert's host from; ``trust_root_fingerprint`` is the engagement's OUT-OF-BAND pinned
    governance-root fingerprint (``evidence.certify.trust_root_fingerprint`` of the anchor that signs the
    spine — NOT the bundle's own ``trust-root.json``). The join passes it as
    ``expected_trust_root_fingerprint`` so authenticity is anchored out-of-band; absent it the join
    fail-closed demotes (a bundle cannot self-authenticate — S1's hardened contract: ``.ok`` requires
    ``authenticity_pinned``). All three are IGNORED when the flag is OFF (no ``framework`` import,
    byte-identical projection). Projection stays a PURE function of (spine records + resolver contents):
    identical inputs → byte-identical ``GraphView`` (no wallclock / RNG; the re-verify is over retained
    bytes via the existing verifier, with no traffic / live oracle).

    ``lifecycle`` (F4 slice S4) is the INJECTED re-verification seam for the flag-gated ``remediation`` /
    ``retest`` record kinds. With ``VIGIL_GRAPH_LIFECYCLE`` OFF (the default), or with ``lifecycle`` None,
    those kinds project NOTHING and this function is byte-identical to the pre-slice projector."""
    objectives_on = objectives_enabled() if objectives is None else bool(objectives)
    view = GraphView(group_id=group_id)
    clean = [r for r in (records or []) if isinstance(r, SpineRecord)]   # pre-filter → total on garbage
    # total order: (seq, hash, canonical body) so two records sharing (seq, hash) still sort
    # deterministically. The canonical body is computed DEFENSIVELY — a typed record carrying a
    # non-JSON-serializable prop value must not crash the sort (totality over the whole record LIST).
    def _sort_key(r: SpineRecord) -> tuple[int, str, str]:
        try:
            body = r.model_dump_json()
        except Exception:   # noqa: BLE001
            body = repr(sorted((str(k) for k in (r.props or {}))))
        return (r.seq, r.hash, body)

    for rec in sorted(clean, key=_sort_key):
        try:
            _project_record(view, rec, scope_gate, objectives=objectives_on, lifecycle=lifecycle,
                            group_id=group_id, evidence_root=evidence_root, contexts=contexts,
                            trust_root_fingerprint=trust_root_fingerprint)
        except Exception:   # noqa: BLE001 — a malformed record must not abort the whole projection
            continue
    return view


# ==========================================================================================================
# F4 slice S4 — the DEFAULT (framework-touching) LifecycleVerifier wiring. Constructed ONLY on the flag-ON
# path; every ``framework.v2`` import is FUNCTION-LOCAL (FATAL-2). ``remediation/*`` is integration-leg and
# safe to import directly, but is kept function-local too so this module's SCOPE stays import-clean and the
# default is only paid for when a caller actually wants real re-verification.
# ==========================================================================================================
class _DefaultLifecycle:
    """Reuses the EXISTING verifiers/authorities verbatim — never a second verifier:
      * ``resolve_finding`` → S1's flag-gated ``evidence.resolver.resolve_and_verify`` (so the referenced
        finding cert is re-established through the one ``verify_certificate``; tenant-scoping + fail-closed
        come free, and a cross-tenant cert that resolves only under another root returns None);
      * ``verify_remediation`` → ``remediation_cert.verify_remediation_certificate`` (offline re-execution);
      * ``verify_retest_series`` → ``attestation_log.verify_log`` — the ANTI-ROLLBACK AUTHORITY. It re-derives
        the floor from the SIGNED durable high-water (``highwater.json`` ``entry_count`` + ``check_highwater``),
        binds the signed head to the rebuilt tick hash-chain (``verify_head`` with ``prev_highwater``), AND
        re-runs ``verify_prove_certificate`` on every tick. The floor is NEVER taken from a producer-supplied
        in-band value (the red-pen HIGH this fix closes).

    AUTHENTICITY IS PINNED OUT-OF-BAND (S1 red-pen fix): a bundle cannot self-authenticate. S1's
    ``resolve_and_verify`` now sets ``ok`` only when, besides internal consistency + reproduction, authenticity
    is anchored to an OUT-OF-BAND trust root — a genuine ``trust_root`` the caller vouches for, OR an
    ``expected_trust_root_fingerprint`` (the engagement's published governance fingerprint, from
    ``evidence.certify.trust_root_fingerprint`` on the pinned root). With NEITHER, the only trust root is the
    one shipped inside the untrusted bundle, ``rv.ok`` is False, and this wiring projects NO confirmed edge
    (fail-closed). ``resolve_finding`` therefore relies on the pinned ``rv.ok``, NEVER a bare internal verdict,
    and NEVER the bundle's own ``trust-root.json``. The remediation + prove-cert re-verification is pinned the
    same way — by ``signer_pubkeys`` (the engagement's out-of-band governance keys), never a cert-supplied key.

    ``attest_trust_root`` (the attestation-log head's governance trust root) + ``attest_log_base`` (a trusted
    base directory the opaque ``retest_log_ref`` is CONFINED under — a ref escaping it fails closed) are the
    out-of-band anchors for the retest authority. Without either, ``verify_retest_series`` fails closed (no
    authenticated floor ⇒ never 'fixed').

    NOTE on layering: ``resolve_finding`` goes through S1's own ``VIGIL_EVIDENCE_RESOLVER`` flag, so the
    finding-cert link requires S1 armed too; when S1 is OFF the link is fail-closed (no edge) — honest, since
    S4 depends on S1. Every framework import is function-local (FATAL-2)."""

    __slots__ = ("_signer_pubkeys", "_root", "_trust_root", "_expected_fp", "_contexts",
                 "_attest_trust_root", "_attest_log_base")

    def __init__(self, *, signer_pubkeys: "dict[str, str]", root: Any = None, trust_root: Any = None,
                 expected_trust_root_fingerprint: Optional[str] = None, contexts: Optional[dict] = None,
                 attest_trust_root: Any = None, attest_log_base: Any = None) -> None:
        self._signer_pubkeys = dict(signer_pubkeys or {})
        self._root = root
        self._trust_root = trust_root
        self._expected_fp = expected_trust_root_fingerprint
        self._contexts = contexts
        self._attest_trust_root = attest_trust_root
        self._attest_log_base = attest_log_base

    def resolve_finding(self, cert_digest: str) -> Optional[FindingLink]:
        from framework.v2.evidence.resolver import resolve_and_verify  # noqa: PLC0415 (FATAL-2: framework imported only on the flag-ON re-verification path)
        # Thread the out-of-band anchor so authenticity is PINNED: rv.ok is True only with a genuine
        # trust_root or expected_trust_root_fingerprint — an unpinned, bundle-sourced root yields rv.ok=False.
        rv = resolve_and_verify(cert_digest, self._contexts, root=self._root,
                                trust_root=self._trust_root,
                                expected_trust_root_fingerprint=self._expected_fp)
        if rv is None:
            return None
        # rv.ok already folds in authenticity_pinned — a self-signed / unpinned bundle reads ok=False here,
        # so FindingLink.ok is False and the projector draws NO confirmed REMEDIATED_BY edge (fail-closed).
        return FindingLink(ok=bool(rv.ok), finding_ref=str(getattr(rv.signed.certificate, "finding_ref", "")))

    def verify_remediation(self, remediation_cert: dict) -> bool:
        from vigil_integration.remediation.remediation_cert import (  # noqa: PLC0415 (FATAL-2: integration-leg; re-execution pulls framework lazily)
            verify_remediation_certificate,
        )
        return bool(verify_remediation_certificate(remediation_cert, signer_pubkeys=self._signer_pubkeys).ok)

    def _confined_log_dir(self, log_ref: str) -> Optional[Path]:
        """Resolve the opaque ``retest_log_ref`` to a directory CONFINED under the trusted base — a ref with
        ``..`` / an absolute path / a symlink that escapes the base fails closed (None)."""
        if self._attest_log_base is None or not log_ref:
            return None
        try:
            base = Path(self._attest_log_base).resolve()
            cand = (base / log_ref).resolve()
            if not cand.is_relative_to(base) or cand.is_symlink() or not cand.is_dir():
                return None
            return cand
        except (OSError, ValueError):
            return None

    def verify_retest_series(self, log_ref: str) -> RetestSeries:
        from vigil_integration.remediation.attestation_log import verify_log  # noqa: PLC0415 (FATAL-2: integration-leg; verify_log re-executes framework lazily per REMEDIATED tick)
        if self._attest_trust_root is None or self._attest_log_base is None:
            # No out-of-band authenticated-ledger anchor ⇒ the floor cannot be re-derived from a signed,
            # durable source ⇒ fail closed (never trust an unauthenticated in-band floor — the red-pen fix).
            return RetestSeries(authenticated=False,
                                reason="no attestation-log anchor (trust root / log base) configured")
        log_dir = self._confined_log_dir(log_ref)
        if log_dir is None:
            return RetestSeries(authenticated=False,
                                reason="retest log ref is absent or escapes the trusted attestation-log base")
        ok, reason, series = verify_log(log_dir, trust_root=self._attest_trust_root,
                                        signer_pubkeys=self._signer_pubkeys)
        if not ok:
            return RetestSeries(authenticated=False, reason=str(reason))
        ticks = tuple(RetestTick(seq=int(getattr(t, "seq", 0)), state=str(getattr(t, "state", "")),
                                 label=str(getattr(t, "label", ""))) for t in (series or []))
        return RetestSeries(authenticated=True, reason=str(reason), ticks=ticks)


def make_default_lifecycle(*, signer_pubkeys: "dict[str, str]", root: Any = None, trust_root: Any = None,
                           expected_trust_root_fingerprint: Optional[str] = None,
                           contexts: Optional[dict] = None, attest_trust_root: Any = None,
                           attest_log_base: Any = None) -> LifecycleVerifier:
    """Build the DEFAULT framework wiring of a :class:`LifecycleVerifier` for production. Reuses S1's resolver
    + the existing remediation-cert verifier + the attestation-log ``verify_log`` authority; defines no new
    verifier. Only call this on the flag-ON path (it is where the ``framework`` dependency lives).
    ``signer_pubkeys`` pins the governance keys used to re-verify the remediation certs and (via ``verify_log``)
    the per-tick prove certs; ``root`` / ``contexts`` thread S1's scoped resolution of the referenced finding
    cert.

    PIN AUTHENTICITY OUT-OF-BAND (two anchors):
      * finding-cert link — ``expected_trust_root_fingerprint`` (``evidence.certify.trust_root_fingerprint``
        on the pinned root) or a vouched-for ``trust_root``; without one the link is fail-closed (a bundle
        cannot self-authenticate), never read a trust root from the bundle under test;
      * retest anti-rollback — ``attest_trust_root`` (the attestation-log head's governance trust root) +
        ``attest_log_base`` (the trusted directory the opaque ``retest_log_ref`` is confined under). Without
        both, the retest series fails closed (the floor is re-derived from the signed durable ledger via
        ``verify_log``, never from a producer-supplied in-band value)."""
    return _DefaultLifecycle(signer_pubkeys=signer_pubkeys, root=root, trust_root=trust_root,
                             expected_trust_root_fingerprint=expected_trust_root_fingerprint,
                             contexts=contexts, attest_trust_root=attest_trust_root,
                             attest_log_base=attest_log_base)
