"""
console.api — read-only data providers for the Ops Console.

Every function here is PURE and RESILIENT: it reads an artifact/store on demand and
returns a plain JSON-serializable dict, and it never raises on a missing/fresh tree
(a brand-new checkout has no `.memory/`, `.authority/`, or `targets/*` yet). It
reuses the framework's own read helpers (`common.paths`, `authority.killswitch`,
`memory.store`, `kernel.backends`) — it does not re-implement them, and it imports
nothing from the scan/engage hot path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import paths


def _safe(fn, default=None):
    """Call a zero-arg read and swallow any error into ``default`` — the console
    must render a partial view of a half-initialised tree, never 500 on it."""
    try:
        return fn()
    except Exception:
        return default


# ---------------------------------------------------------------------------
# status / health
# ---------------------------------------------------------------------------


def status_data() -> dict[str, Any]:
    """Environment + backend health — the data behind the `status` CLI, as JSON."""
    from ..kernel import backends as backends_pkg

    def _paths() -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for label, fn in (
            ("crucible_root", paths.crucible_root),
            ("v2_root", paths.v2_root),
            ("memory_db", paths.memory_db),
            ("dryrun_dir", paths.dryrun_dir),
            ("targets_root", paths.targets_root),
        ):
            p = _safe(fn)
            out[label] = str(p) if p is not None else None
        return out

    backends = _safe(
        lambda: [
            {"name": name, "available": bool(avail), "note": note}
            for name, avail, note in backends_pkg.probe_all()
        ],
        default=[],
    )
    return {"paths": _paths(), "backends": backends}


# ---------------------------------------------------------------------------
# engagements
# ---------------------------------------------------------------------------


def _killswitch_state(slug: str) -> dict[str, Any]:
    from ..authority.killswitch import KillSwitch

    def _read() -> dict[str, Any]:
        ks = KillSwitch(slug)
        tripped = ks.is_tripped()
        return {"tripped": bool(tripped), "reason": ks.reason() if tripped else None}

    # is_tripped fails CLOSED (ambiguous stat -> tripped); mirror that honestly.
    return _safe(_read, default={"tripped": True, "reason": "state unreadable (fail-closed)"})


def _authority_state(slug: str) -> dict[str, Any] | None:
    def _read() -> dict[str, Any] | None:
        p = paths.authority_path(slug)
        if not Path(p).is_file():
            return None
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        # SignedAuthority wraps an authority payload; surface the operator-relevant bits.
        auth = doc.get("authority", doc)
        return {
            "environment": auth.get("environment"),
            "scope": auth.get("scope", []),
            "not_before": auth.get("not_before"),
            "not_after": auth.get("not_after"),
            "allow_destructive": auth.get("allow_destructive"),
            "max_actions": auth.get("max_actions"),
            "issued_by": auth.get("issued_by"),
        }

    return _safe(_read, default=None)


def _engagement_row(slug: str) -> dict[str, Any]:
    td = _safe(lambda: Path(paths.target_dir(slug)))
    has_charter = _safe(lambda: Path(paths.charter_path(slug)).is_file(), default=False)
    log = _safe(lambda: Path(paths.crucible_v2_log(slug)))
    return {
        "slug": slug,
        "has_charter": bool(has_charter),
        "killswitch": _killswitch_state(slug),
        "authority": _authority_state(slug),
        "log_exists": bool(log and log.is_file()),
        "log_size": _safe(lambda: log.stat().st_size, default=0) if log else 0,
        "evidence_count": _safe(
            lambda: sum(1 for _ in (td / "evidence").iterdir()) if (td / "evidence").is_dir() else 0,
            default=0,
        ),
    }


def list_engagements() -> dict[str, Any]:
    """Every engagement (a slug = a directory under ``targets/``), with its
    safety/charter state. Skips the `_template` scaffold and hidden dirs."""
    def _list() -> list[str]:
        root = Path(paths.targets_root())
        if not root.is_dir():
            return []
        return sorted(
            p.name for p in root.iterdir()
            if p.is_dir() and not p.name.startswith((".", "_"))
        )

    slugs = _safe(_list, default=[])
    return {"engagements": [_engagement_row(s) for s in slugs]}


def engagement_detail(slug: str) -> dict[str, Any]:
    """One engagement's full at-a-glance state (charter presence, safety, logs)."""
    row = _engagement_row(slug)
    row["charter_present"] = row["has_charter"]
    row["memory"] = _safe(_memory_summary, default={})
    return row


def _memory_summary() -> dict[str, int]:
    from ..memory.store import Store

    return Store().engagement_summary()


# ---------------------------------------------------------------------------
# console runs + reports (populated by the launch action)
# ---------------------------------------------------------------------------


def list_runs() -> dict[str, Any]:
    """Console-launched scan runs, newest first, with their meta + finding count."""
    from . import actions

    def _list() -> list[dict[str, Any]]:
        runs_root = actions.console_dir() / "runs"
        if not runs_root.is_dir():
            return []
        out: list[dict[str, Any]] = []
        for d in sorted(runs_root.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            meta = _safe(lambda p=d: json.loads((p / "meta.json").read_text(encoding="utf-8")), default={})
            report = _safe(lambda p=d: json.loads((p / "report.json").read_text(encoding="utf-8")), default=None)
            out.append({
                "run_id": d.name,
                "target": meta.get("target"),
                "status": meta.get("status", "unknown"),
                "started": meta.get("started"),
                # P2 assessment-run fields (absent for legacy loopback scans → sensible defaults):
                "mode": meta.get("mode", "url"),
                "slug": meta.get("slug"),
                "objective": meta.get("objective", ""),
                # how the Live view should tail this run: 'blackboard' (engage --spine), 'progress'
                # (loopback scan --progress-log), or 'none' (strix/aegis — status only).
                "stream": meta.get("stream", "progress"),
                "findings": len((report or {}).get("findings", [])) if report else None,
                "has_report": report is not None,
            })
        return out

    return {"runs": _safe(_list, default=[])}


def sessions_list() -> dict[str, Any]:
    """The operator's permanent SESSIONS (F2), newest first: registry entries + adopted legacy chats.
    Read-only; never a secret. The Sessions screen builds on this."""
    from . import sessions
    return _safe(sessions.list_sessions, default={"sessions": []})


def session_detail(session_id: str) -> dict[str, Any]:
    """One session + the meta of its linked runs (for the Sessions screen). Fail-closed: an unsafe id
    raises ValueError (→ 404 in do_GET); an unknown id returns an error body."""
    from . import actions, sessions
    got = sessions.get_session(session_id)          # raises ValueError on an unsafe id (→ 404)
    if got.get("error"):
        return got
    sess = got["session"]
    runs = []
    for rid in sess.get("run_ids", []):
        meta = _safe(lambda r=rid: json.loads(
            (actions.run_dir(r) / "meta.json").read_text(encoding="utf-8")), default={})
        runs.append({"run_id": rid, "mode": meta.get("mode"), "target": meta.get("target"),
                     "status": meta.get("status", "unknown"), "slug": meta.get("slug"),
                     "stream": meta.get("stream", "progress"), "started": meta.get("started")})
    return {"session": sess, "runs": runs}


def inbox(slug: str) -> dict[str, Any]:
    """U3 — read-only view of the directed agent-to-agent COORDINATION messages on one engagement's spine
    (the S5 ``agent_message`` kind: sender/recipient/topic/body/refs). LOAD-BEARING HONESTY: a message is
    NOT evidence — no fact-building path reads this kind, so draining it can never promote a finding; the UI
    renders it as advisory coordination only. Total: an unregistered/absent engagement (no ``--spine`` run
    has posted for this slug yet) or any read error yields an empty list, never a traceback."""
    s = str(slug or "").strip()
    if not s:
        return {"ok": True, "slug": "", "advisory": True, "messages": []}

    def _read() -> list[dict[str, Any]]:
        from ..agents.blackboard import open_blackboard
        bb = open_blackboard()
        try:
            rows = bb.read(engagement=s, kinds=["agent_message"], limit=200)   # raises for an unregistered slug
        finally:
            try:
                bb.close()
            except Exception:  # noqa: BLE001
                pass
        out: list[dict[str, Any]] = []
        for r in rows:
            p = getattr(r, "payload", None) or {}
            out.append({
                "id": getattr(r, "id", None),
                "posted_at": getattr(r, "posted_at", None),
                "sender": str(p.get("sender", "")),
                "recipient": str(p.get("recipient", "")),
                "topic": str(p.get("topic", "")),
                "body": str(p.get("body", "")),
                "refs": [x for x in (p.get("refs") or []) if isinstance(x, int)],
            })
        return out[-100:]                                   # most recent 100 — advisory, bounded

    messages = _safe(_read, default=[]) or []
    payload = {"ok": True, "slug": s, "advisory": True, "messages": messages}
    # Agent messages are agent-authored free text that EGRESSES to the UI, so apply the SAME two-pass
    # redaction the terminal-context egress uses: the load-bearing free-text credential-shape masker
    # (actions._redact_ctx — catches an sk-ant / JWT / URL-userinfo secret INSIDE a message body, which a
    # key-NAME scrub alone would miss) then scrub_log_event as a defense-in-depth key-name pass.
    try:
        from ..common.redact import scrub_log_event
        from . import actions
        return scrub_log_event(actions._redact_ctx(payload))
    except Exception:  # noqa: BLE001 — redaction unavailable ⇒ still return the (agent-authored) messages
        return payload


def telemetry() -> dict[str, Any]:
    """G2 — the live assurance/metrics snapshot the ``vigil up --with-telemetry`` collector materializes from
    the signed spine (per-engagement fact/lead/refusal/tool counts + totals). Read-only: the console just
    SERVES the collector's snapshot file — a pure one-way projection of the append-only spine (nothing is read
    back into it; it never mints a fact). Total: an absent file (collector not running) or any read error
    yields an honest ``running: false`` marker with a start hint, never a traceback."""
    import os

    base = os.environ.get("VIGIL_LIVE_DIR") or ".vigil-live"
    path = Path(base) / "live-ui" / "telemetry.json"
    doc = _safe(lambda: json.loads(path.read_text(encoding="utf-8")), default=None)
    if not isinstance(doc, dict):
        return {"ok": True, "running": False, "engagements": [], "totals": {},
                "note": "the assurance/telemetry collector is not running — start it with "
                        "`vigil up --with-telemetry` (a read-only, no-egress projection of the signed spine)."}
    return {"ok": True, "running": True, **doc}


def approvals(slug: str = "") -> dict[str, Any]:
    """A2 — read-only list of the offense worker's PENDING per-action owner-approval requests.

    When an offense tool is queued, the offense worker publishes a PUBLIC-SAFE pending request under
    ``<base>/approvals/pending/<id>.json`` (tool, the gate-seen target, the action-digest, a single-use nonce,
    and a REDACTED args preview — NEVER a secret, NEVER the owner PRIVATE key). The owner signs it OUT-OF-BAND
    with ``vigil approve sign`` — the owner private key is held off-box as ``VIGIL_APPROVAL_OWNER_KEY`` (the
    SOVEREIGN side). This console is KEYLESS: it may READ + serve these public-safe requests, but it MUST NEVER
    sign (FATAL-2). So this provider is READ-ONLY — it lists what is awaiting a signature and the UI surfaces
    the exact CLI the operator runs to sign; there is NO signing route in this offense plane.

    ``base_dir`` is echoed so the UI can render the exact ``vigil approve sign --base-dir <base> ...`` command.
    ``slug`` is accepted for the prefix-route shape but the pending queue is machine-wide (rooted at
    ``VIGIL_BASE_DIR``), not per-engagement. Total: an absent/unreadable approvals dir yields
    ``{"pending": []}``, never a traceback."""
    import os

    base = os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"

    def _read() -> list[dict[str, Any]]:
        # approval_broker is import-clean (vigil_core + stdlib only) — safe to import in the offense plane
        # (unlike the rest of vigil_integration, which is FATAL-2 to import here). It holds NO private key.
        from vigil_integration.live.approval_broker import approvals_root, list_pending
        return [{"request_id": p.request_id, "tool_name": p.tool_name, "target": p.target,
                 "action_digest": p.action_digest, "nonce": p.nonce, "args_preview": p.args_preview,
                 "created_at_iso": p.created_at_iso} for p in list_pending(approvals_root(base))]

    pending = _safe(_read, default=[]) or []
    return {"ok": True, "slug": str(slug or ""), "base_dir": base, "pending": pending}


def run_report(run_id: str) -> dict[str, Any]:
    """The saved `build_report` document for a console run (findings + attack_paths +
    summary), or an error marker if it has not finished yet."""
    from . import actions

    rep = actions.run_dir(run_id) / "report.json"
    doc = _safe(lambda: json.loads(rep.read_text(encoding="utf-8")), default=None)
    if doc is None:
        meta = _safe(lambda: json.loads((actions.run_dir(run_id) / "meta.json").read_text(encoding="utf-8")), default={})
        return {"run_id": run_id, "pending": True, "status": meta.get("status", "unknown")}
    doc["run_id"] = run_id
    return doc


def _no_send(_request):  # pragma: no cover - chaining is pure reasoning, never sends
    raise RuntimeError("world-model reconstruction must not issue traffic")


# ---------------------------------------------------------------------------
# Fixes / remediation (P6) — the run's fixable findings + the gated remediation ladder-of-record.
#
# HONEST SCOPE: this composes REAL CRUCIBLE-native data (the run's oracle-confirmed findings + their
# per-finding remediation guidance from the report). The gated ladder below is the ACCURATE, documented
# process the sovereign auto-patch pipeline follows (vigil_integration.remediation) — it is served so the
# UI hard-codes no process text. Live auto-application (clone / build / open-PR) is a SEPARATE, sovereign-
# gated capability that must be provisioned + explicitly authorized; this console never runs it.
# ---------------------------------------------------------------------------

_REMEDIATION_LADDER = (
    {"stage": "triage", "tier": "—",
     "what": "Pick what to fix — ONLY an oracle-confirmed FACT with signed evidence is eligible. "
             "A LEAD (unproven) can never trigger a code change."},
    {"stage": "clone", "tier": "A1",
     "what": "Clone the target repo and cut a fix branch. Reversible and internal."},
    {"stage": "edit", "tier": "A2",
     "what": "Apply the AI-proposed edits — each file needs YOUR explicit approval; a timeout auto-REJECTS "
             "(fail-closed). Only explicit, path-validated files are staged — never a bulk `git add -A`."},
    {"stage": "build", "tier": "A3",
     "what": "Build the patched code in a sandbox."},
    {"stage": "open-pr", "tier": "A3 · m-of-n",
     "what": "Open a pull request — a DISTINCT, explicit multi-signer (m-of-n) approval, separate from the "
             "per-file approval. Nothing is merged for you."},
    {"stage": "verify", "tier": "—",
     "what": "Marked FIXED only when the original exploit oracle goes SILENT on the patched build — i.e. the "
             "bug can no longer be proven. If it still fires, the PR opens as a proposal marked still-vulnerable."},
)


def remediate_plan(run_id: str) -> dict[str, Any]:
    """The Fixes view for a run: its oracle-confirmed, fixable findings (each with the report's own
    remediation guidance) + the gated ladder-of-record any auto-fix would follow. Read-only + resilient;
    a pending/empty run yields an honest empty state, never fabricated fixes. Whether the operator asked
    for fixes at launch (`apply_fixes`) is surfaced from the run meta (it is a REQUEST, not an auto-run)."""
    from . import actions

    meta = _safe(lambda: json.loads((actions.run_dir(run_id) / "meta.json").read_text(encoding="utf-8")),
                 default={}) or {}
    doc = _safe(lambda: json.loads((actions.run_dir(run_id) / "report.json").read_text(encoding="utf-8")),
                default=None)
    base = {"run_id": run_id, "ladder": list(_REMEDIATION_LADDER),
            "apply_fixes_requested": bool(meta.get("apply_fixes")),
            "live_execution": False,
            "note": ("VIGIL shows what to fix and the exact gated process an auto-fix follows. Live "
                     "auto-application (clone, build, open a PR) is a separate sovereign-gated capability "
                     "that must be provisioned and authorized — nothing is cloned, built, or opened here.")}
    if doc is None:
        return {**base, "pending": True, "fixable": [], "lead_count": 0,
                "status": meta.get("status", "unknown")}
    findings = doc.get("findings", []) if isinstance(doc, dict) else []
    fixable, leads = [], 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        # a finding is FIXABLE only if it is an oracle-confirmed FACT (its own oracle re-fires) — the same
        # honest gate the Findings hub uses; a lead (unproven) is counted but never offered for auto-fix.
        if f.get("grounding") == "fact":
            fixable.append({
                # the stable finding reference the gated `vigil patch` ladder keys on (== the reverifiable.json
                # check_id). Absent → the Fixes screen offers the CLI path, never a broken button.
                "ref": str(f.get("check_id") or f.get("id") or f.get("ref") or ""),
                "title": f.get("title", ""), "bug_class": f.get("bug_class", ""),
                "severity": f.get("severity", ""), "location": f.get("location", ""),
                "confirmed_by": f.get("confirmed_by", ""),
                "remediation": f.get("remediation", "") or "(no per-class remediation text on record)",
                "references": f.get("references", []) or [],
            })
        else:
            leads += 1
    # highest severity first (stable), then by bug_class, for a deterministic list
    _sev = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "info": 0}
    fixable.sort(key=lambda x: (-_sev.get(str(x["severity"]).lower(), -1), str(x["bug_class"])))
    return {**base, "fixable": fixable, "fixable_count": len(fixable), "lead_count": leads,
            "summary": doc.get("summary", "") if isinstance(doc, dict) else ""}


def worldmodel(run_id: str) -> dict[str, Any]:
    """Reconstruct the world-model attack graph for a saved run — a re-run of the chaining
    over the retained ScanReport (no traffic). RE-EXECUTES each finding's retained proof
    (``chain_findings(verify=True)``, TRUTHENOVATION T1): a stored finding whose proof no
    longer re-fires grants the attacker no grounded reach/topology/path (it is shown as an
    UNGROUNDED demoted node, never a grounded capability). Returns typed nodes,
    belief-weighted edges, attacker→crown-jewel paths, and choke-points."""
    from . import actions

    rj = actions.run_dir(run_id) / "reverifiable.json"
    doc = _safe(lambda: json.loads(rj.read_text(encoding="utf-8")), default=None)
    if doc is None:
        return {"run_id": run_id, "pending": True, "nodes": [], "edges": [], "paths": [], "chokes": []}

    def _build() -> dict[str, Any]:
        from ..scanner.campaign import ScanReport
        from ..scanner.orchestrator import _CROWN_KINDS, _TRAVERSABLE, AutonomousCampaign
        from ..worldmodel.attacker import ATTACKER_ID

        from ..worldmodel.impact import ImpactModel, rank_choke_points

        report = ScanReport.model_validate(doc)
        auto = AutonomousCampaign(_no_send).chain_findings(report, verify=True)
        world = auto.world
        # first_seen/last_seen drive the Timeline-replay screen (monotonic graph growth).
        nodes = [{
            "id": n.id, "kind": getattr(n.kind, "value", str(n.kind)),
            "belief": round(n.belief_mean, 3), "confidence": round(n.confidence, 3),
            "provenance": n.provenance, "detail": n.attrs.get("detail") or n.attrs.get("bug_class") or "",
            "first_seen": n.first_seen, "last_seen": n.last_seen,
            "grounding": getattr(n, "grounding", "unclassified"),   # anti-hallucination tier
        } for n in world.all_nodes()]
        edges = [{
            "src": e.src, "dst": e.dst, "kind": getattr(e.kind, "value", str(e.kind)),
            "technique": str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])),
            "belief": round(e.belief_mean, 3), "provenance": e.provenance,
            "first_seen": e.first_seen, "last_seen": e.last_seen,
            "grounding": getattr(e, "grounding", "unclassified"),
        } for e in world.all_edges()]
        paths = [{
            "description": p.describe(), "detection_cost": p.detection_cost, "hops": p.hops,
            "destination": p.destination, "value": getattr(p, "value", 1.0),
            "steps": [{"src": s.src, "edge": s.edge, "dst": s.dst, "technique": s.technique} for s in p.steps],
        } for p in auto.attack_paths]
        # impact-ranked remediation levers (P2): weighted by the crown-jewel worth each severs
        chokes: list[dict[str, Any]] = []
        if world.get_node(ATTACKER_ID) is not None:
            impact = ImpactModel.uniform()
            for c in _safe(lambda: rank_choke_points(world, ATTACKER_ID, _CROWN_KINDS, impact,
                                                     edge_kinds=_TRAVERSABLE), default=[]) or []:
                chokes.append({"src": c.edge.src, "dst": c.edge.dst,
                               "kind": getattr(c.edge.kind, "value", str(c.edge.kind)),
                               "betweenness": c.betweenness, "disconnects": c.disconnects,
                               "is_bridge": c.is_bridge, "impact_disconnected": c.impact_disconnected})
        return {"run_id": run_id, "nodes": nodes, "edges": edges, "paths": paths, "chokes": chokes,
                "node_count": world.node_count, "edge_count": world.edge_count}

    return _safe(_build, default={"run_id": run_id, "error": "could not reconstruct world-model",
                                  "nodes": [], "edges": [], "paths": [], "chokes": []})


def evidence(run_id: str) -> dict[str, Any]:
    """The Evidence Browser: every confirmed finding's certificate, INDEPENDENTLY
    re-verified offline (pure oracle re-run over the retained oracle_context) so the
    operator sees which findings are provable — reproduced + matches-claim — and which
    carry a re-runnable certificate at all. Read-only; sends no traffic."""
    from . import actions

    rj = actions.run_dir(run_id) / "reverifiable.json"
    doc = _safe(lambda: json.loads(rj.read_text(encoding="utf-8")), default=None)
    if doc is None:
        return {"run_id": run_id, "pending": True, "findings": []}

    def _build() -> dict[str, Any]:
        from ..evidence.canonical import digest_payload
        from ..verify.reverify import reverify_document
        results = reverify_document(doc)
        findings = doc.get("active_findings") or []
        out = []
        for i, r in enumerate(results):
            f = findings[i] if i < len(findings) else {}
            oc = f.get("oracle_context")
            # cert id = a REAL content address of the retained certificate: sha256 over the
            # canonical bytes of the oracle_context (the same digest the signed EvidenceCertificate
            # binds as `oracle_context_digest`). "" when the finding carries no re-runnable proof —
            # never fabricated. Two byte-identical certificates share an id; a tampered one does not.
            cert_id = ""
            if isinstance(oc, dict) and oc:
                cert_id = _safe(lambda oc=oc: "sha256:" + digest_payload(oc), default="")
            out.append({
                "ref": r.finding_ref,
                "bug_class": f.get("bug_class", ""),
                "surface": f.get("insertion_point") or f.get("param") or "",
                "confirmed_by": r.confirmed_by or f.get("confirmed_by", ""),
                "confidence": round(r.confidence, 3),
                "has_certificate": bool(oc),
                "cert_id": cert_id,
                "reproduced": r.reproduced,
                "matches_claim": r.matches_claim,
                "sound": r.ok,
                "note": r.note,
            })
        n_ok = sum(1 for x in out if x["sound"])
        return {"run_id": run_id, "findings": out,
                "reproduced": n_ok, "total": len(out),
                "doctrine": "Each certificate re-verifies OFFLINE with no target and no trust "
                            "in the tool that produced it — prove-don't-guess, made checkable."}

    return _safe(_build, default={"run_id": run_id, "findings": [], "error": "could not re-verify"})


_PROOF_DOCTRINE = (
    "A proof is a FACT only when a deterministic oracle FIRED over the executor-captured raw bytes of the "
    "reproduction — never over the model's PoC text. A LEAD is an honest 'not reproduced / not oracle-mapped'; "
    "a DENIED proof had dangerous PoC content refused by the content gate before any mint. Read-only."
)


def proof_list(run_id: str) -> dict[str, Any]:
    """Proof Studio (B5): the persisted proof records for a run. Each record is written host-side by the
    keyless offense mint (``vigil_integration.proof.run``) as plain JSON under ``<run_dir>/proofs/`` — so
    this reader needs NO import of the integration package (no framework→integration dependency) and sends
    no traffic. Each is an oracle-confirmed FACT, an honest LEAD, or a content-gate DENY."""
    from . import actions

    d = actions.run_dir(run_id) / "proofs"
    recs: list[dict] = []
    if _safe(lambda: d.is_dir(), default=False):
        for f in sorted(_safe(lambda: list(d.glob("*.json")), default=[]) or []):
            if f.name == "reverifiable.json":     # the C1 re-verifiable report is a sibling, not a proof record
                continue
            rec = _safe(lambda f=f: json.loads(f.read_text(encoding="utf-8")), default=None)
            if isinstance(rec, dict):
                recs.append(rec)
    # A stable, honest disposition order: facts first, then leads, then denied — each already deterministic.
    order = {"fact": 0, "lead": 1, "denied": 2}
    recs.sort(key=lambda r: (order.get(str(r.get("status")), 3), str(r.get("bug_class", "")), str(r.get("proof_id", ""))))
    facts = sum(1 for r in recs if r.get("status") == "fact")
    leads = sum(1 for r in recs if r.get("status") == "lead")
    denied = sum(1 for r in recs if r.get("status") == "denied")
    return {"run_id": run_id, "proofs": recs, "total": len(recs),
            "facts": facts, "leads": leads, "denied": denied,
            "pending": len(recs) == 0, "doctrine": _PROOF_DOCTRINE}


# ---------------------------------------------------------------------------
# benchmark + coverage
# ---------------------------------------------------------------------------


def benchmark_data() -> dict[str, Any]:
    """The committed benchmark scoreboard + the regression baseline — reused as-is
    (no run needed). These are committed PACKAGE data, so read them relative to this
    file (the installed framework), not the runtime CRUCIBLE_ROOT."""
    v2 = Path(__file__).resolve().parents[1]  # .../framework/v2
    results = _safe(lambda: json.loads((v2 / "docs" / "benchmark-results.json").read_text(encoding="utf-8")), default=None)
    baseline = _safe(lambda: json.loads((v2 / "eval" / "baselines" / "benchmark-app.json").read_text(encoding="utf-8")), default=None)
    return {"results": results, "baseline": baseline}


def coverage_data(run_id: str) -> dict[str, Any]:
    """Surface-coverage view of a saved run: detected stack, discovered endpoints,
    passive hygiene, DOM-XSS leads (all from the build_report document)."""
    doc = run_report(run_id)
    if doc.get("pending"):
        return {"run_id": run_id, "pending": True}
    findings = doc.get("findings", [])
    return {
        "run_id": run_id,
        "target": doc.get("target"),
        "fingerprint": doc.get("fingerprint", []),
        "discovered_endpoints": doc.get("discovered_endpoints", []),
        "summary": doc.get("summary", {}),
        "passive": [f for f in findings if f.get("kind") == "passive"],
        "dom_xss": [f for f in findings if f.get("kind") == "dom_xss_candidate"],
    }


# ---------------------------------------------------------------------------
# memory / kernel / authority / planner / reports (Phase 3-4)
# ---------------------------------------------------------------------------


def memory_data() -> dict[str, Any]:
    """The learning store: engagement roll-up + per-archetype Beta priors."""
    def _read() -> dict[str, Any]:
        from ..memory.priors import all_priors
        from ..memory.store import Store

        st = Store()
        summary = _safe(st.engagement_summary, default={})
        priors = _safe(lambda: [{
            "archetype": p.archetype, "bug_class": p.bug_class, "surface": p.surface_pattern,
            "successes": p.successes, "attempts": p.attempts,
            "mean": round(p.mean, 3), "lower_bound": round(p.lower_bound, 3),
        } for p in all_priors(st)], default=[])
        return {"summary": summary, "priors": sorted(priors, key=lambda x: -x["mean"])}

    return _safe(_read, default={"summary": {}, "priors": [], "note": "no memory store yet"})


def kernel_data() -> dict[str, Any]:
    """The URK cognitive layer: LLM backends (live/dryrun) + the cognitive docs the
    kernel produces structured outputs for."""
    from ..kernel import backends as backends_pkg

    backends = _safe(lambda: [
        {"name": n, "available": bool(a), "note": note} for n, a, note in backends_pkg.probe_all()
    ], default=[])
    docs = ["hypothesize", "critique", "pivot", "decide (CVSS severity)", "opsec", "threat-model"]
    return {"backends": backends, "cognitive_docs": docs,
            "dryrun_default": True,
            "note": "Kernel outputs are produced on demand via `kernel <verb>`; every call "
                    "returns a CallTrace (backend, dryrun, tokens, latency)."}


def authority_full(slug: str) -> dict[str, Any]:
    """The governance state for an engagement: kill-switch, authority window/scope,
    charter presence — the fail-closed safety picture."""
    if not slug:
        return {"slug": None, "note": "select an engagement"}
    return {
        "slug": slug,
        "killswitch": _killswitch_state(slug),
        "authority": _authority_state(slug),
        "charter_present": _safe(lambda: __import__("pathlib").Path(paths.charter_path(slug)).is_file(), default=False),
        "gates": ["authority/kill-switch", "scope", "destructive-confirm", "budget", "rate-limit", "egress"],
    }


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1", "loopback"})


def charter_status(slug: str) -> dict[str, Any]:
    """Charter & Attestation — the REMOTE-charter picture (read-only). Extends ``authority_full`` with the
    authorized scope broken into loopback vs REMOTE hosts, and the exact OUT-OF-BAND ceremony a remote target
    requires. This UI provisions LOOPBACK (127.0.0.1) only; it can never mint OR widen a charter for a real
    remote host — that is a deliberate ceremony on a trusted host that holds the owner key. So the UI HANDLES
    the remote case by SURFACING + VERIFYING the charter (present? which hosts? window?), never by minting it."""
    if not slug:
        return {"slug": None, "note": "select an engagement"}
    full = authority_full(slug)
    auth = full.get("authority") or {}
    scope = [str(h).strip() for h in (auth.get("scope") or []) if str(h).strip()]
    remote = [h for h in scope if h.lower() not in _LOOPBACK_HOSTS]
    return {
        **full,
        "scope": scope,
        "is_loopback_only": bool(scope) and not remote,
        "remote_hosts": remote,
        "has_remote_authority": bool(remote),
        "window": {"not_before": auth.get("not_before"), "not_after": auth.get("not_after"),
                   "environment": auth.get("environment")},
        # a TEMPLATE only — the UI fills the operator's target in; no secret, and the UI never RUNS it.
        "ceremony": f"vigil provision --slug {slug} --scope <REMOTE-HOST[,HOST2,...]>",
        "remote_note": ("A REMOTE target needs a signed charter minted OUT-OF-BAND on a trusted host that holds "
                        "the owner key. This UI provisions LOOPBACK (127.0.0.1) ONLY and can never mint or widen "
                        "a remote charter — run the ceremony on that host, then Re-check here. No charter, no run."),
    }


def _destruction_audit() -> dict[str, Any]:
    """READ-ONLY audit of the m-of-n destruction-quorum state, from the PERSISTED files under the live
    base dir — stdlib + ``vigil_core.TrustRoot`` ONLY (mirrors ``approvals``). It reads the public
    trust-root JSON (threshold + authorizer ids), counts spent-nonce markers, and summarises any
    pending signed authorization's PUBLIC signing-payload. It imports NONE of the destruction gate/mint
    modules (FATAL-2) and exposes NO provision/authorize/consume path — it only reports what is on disk.
    Not provisioned (no trust-root file) → ``{"present": False}`` honestly, never a fabricated quorum."""
    import os
    import re

    base = os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"
    root = Path(base)
    tr_path = root / "destruction-trust-root.json"
    if not tr_path.is_file():
        return {"present": False, "base_dir": base,
                "note": "no destruction trust root provisioned — no m-of-n quorum exists on this host."}

    def _trust_root() -> dict[str, Any]:
        from vigil_core import TrustRoot
        tr = TrustRoot.model_validate_json(tr_path.read_text(encoding="utf-8"))
        return {"threshold": tr.threshold,
                "authorizer_ids": [a.key_id for a in tr.authorizers],
                "authorizer_count": len(tr.authorizers)}

    def _consumed_nonces() -> int:
        d = root / "destruction-nonces"
        if not d.is_dir():
            return 0
        # each spent nonce is a marker file named sha256(nonce) = [0-9a-f]{64} (nonce_ledger); count them.
        marker = re.compile(r"^[0-9a-f]{64}$")
        return sum(1 for p in d.iterdir() if p.is_file() and marker.match(p.name))

    def _pending() -> list[dict[str, Any]]:
        p = root / "signed-authorization.json"
        if not p.is_file():
            return []
        doc = json.loads(p.read_text(encoding="utf-8"))
        entries = doc if isinstance(doc, list) else [doc]
        out: list[dict[str, Any]] = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            # {"authorization": <signing_payload>, "signatures": [{key_id,...}]} — PUBLIC-safe fields only,
            # NEVER a private key. This is a read of the payload the quorum SIGNED, not an authorization we hold.
            auth = e.get("authorization") if isinstance(e.get("authorization"), dict) else e
            sigs = e.get("signatures") if isinstance(e.get("signatures"), list) else []
            out.append({
                "action_id": auth.get("action_id"),
                "engagement_slug": auth.get("engagement_slug"),
                "target": auth.get("target"),
                "blast_class": auth.get("blast_class"),
                "not_before": auth.get("not_before"),
                "not_after": auth.get("not_after"),
                "signature_count": len(sigs),
                "signer_ids": [str(s.get("key_id")) for s in sigs if isinstance(s, dict) and s.get("key_id")],
            })
        return out

    return {
        "present": True,
        "base_dir": base,
        "trust_root": _safe(_trust_root, default=None),
        "consumed_nonce_count": _safe(_consumed_nonces, default=0),
        "pending": _safe(_pending, default=[]) or [],
    }


def governance_data() -> dict[str, Any]:
    """Governance & Gate audit — a READ/AUDIT-ONLY picture of the runtime governance posture: the
    sovereignty tier + seal, whether capability entitlement is ENFORCED or the deployment runs
    UNGOVERNED, the safety-gate conjuncts every action must clear, and the m-of-n destruction-quorum
    state read from disk. It is PURE and READ-ONLY: it evaluates policy and reads persisted public files
    only. It NEVER provisions, authorizes, signs, or fires a governed/destructive action, and it imports
    no gate mint module (FATAL-2) — the destruction audit reads the persisted JSON/dir directly."""
    def _sovereignty() -> dict[str, Any]:
        from ..kernel import sovereignty
        pol = sovereignty.current()
        return {"tier": pol.tier.name, "sealed": bool(sovereignty.is_sealed())}

    def _entitlement() -> dict[str, Any]:
        from ..entitlement.policy import EntitlementPolicy
        ent = EntitlementPolicy.from_provisioned()
        gt = ent.granted_tier
        return {"enforced": bool(ent.enforced),
                "granted_tier": gt.name if gt is not None else None,
                "explain": ent.explain()}

    sovereignty = _safe(_sovereignty, default=None)
    entitlement = _safe(_entitlement, default=None)
    # GOVERNED iff entitlement is actually enforced; anything else (unenforced, or an unreadable policy) is
    # UNGOVERNED — fail-honest, never assume governance we could not confirm.
    governed = bool(entitlement and entitlement.get("enforced"))
    return {
        "governed": governed,
        "sovereignty": sovereignty,
        "entitlement": entitlement,
        "gate": {"conjuncts": ["authority/kill-switch", "scope", "destructive-confirm",
                               "budget", "rate-limit", "egress"]},
        "destruction": _safe(_destruction_audit, default={"present": False}),
        "read_only": True,
        "note": ("Read-only audit — this screen cannot provision, authorize, or fire a destructive action; "
                 "it reports the governance posture and the persisted m-of-n quorum state only."),
    }


def planner_data(slug: str) -> dict[str, Any]:
    """The goal-tree/plan state for an engagement, if a planner ran (planner-state.json)."""
    def _read() -> dict[str, Any]:
        p = Path(paths.planner_state(slug))
        if not p.is_file():
            return {"slug": slug, "present": False}
        doc = json.loads(p.read_text(encoding="utf-8"))
        return {"slug": slug, "present": True, "state": doc}

    return _safe(_read, default={"slug": slug, "present": False})


def reports_data(slug: str) -> dict[str, Any]:
    """Generated reports on disk for an engagement (targets/<slug>/reports/)."""
    def _read() -> dict[str, Any]:
        rd = Path(paths.target_dir(slug)) / "reports"
        if not rd.is_dir():
            return {"slug": slug, "reports": []}
        files = [{"name": f.name, "size": f.stat().st_size} for f in rd.iterdir() if f.is_file()]
        return {"slug": slug, "reports": sorted(files, key=lambda x: x["name"])}

    return _safe(_read, default={"slug": slug, "reports": []})


# ---------------------------------------------------------------------------
# external host tools (WS-TOOLS)
# ---------------------------------------------------------------------------


def tools_data() -> dict[str, Any]:
    """The offense engine's external host CLIs, probed LIVE (WS-TOOLS): for every tool —
    installed / missing / failed, its resolved path + a cheap version, its purpose, and a
    copyable install hint; plus the informational Strix-sandbox roster and the host platform.

    Real data only: :func:`..tools.registry.probe_tools` resolves PATH at call time and never
    invents a status; 'failed' is layered from the installer's optional hint file and the live
    probe always overrides it. Safe on any box (a non-Linux host reports every tool
    ``unsupported``). Read-only — issues no traffic and installs nothing."""
    def _read() -> dict[str, Any]:
        from ..tools.registry import probe_tools
        return probe_tools()

    return _safe(_read, default={
        "platform": {"system": None, "supported": False, "debian_family": False},
        "tools": [],
        "summary": {"total": 0, "installed": 0, "missing": 0, "failed": 0,
                    "unsupported": 0, "required_missing": 0},
        "sandbox": {"image": None, "tools": []},
        "error": "could not probe host tools",
    })


def tool_profiles_data() -> dict[str, Any]:
    """The unified ToolProfiles + the tool-consciousness admission gate (Phase B1): each tool joined across
    the host roster (install/live-status/binary/version), its Strix CLI-usage playbook, and whether the
    executor can build a validated gated argv for it — with a fail-closed verdict on whether it is
    globally-recognised AND CLI/background-controllable enough to be adopted. Advisory + read-only (issues
    no traffic, installs nothing); every real execution still passes the WARDEN gate."""
    def _read() -> dict[str, Any]:
        from ..tools.profile import build_profiles
        return build_profiles()

    return _safe(_read, default={
        "profiles": [],
        "summary": {"total": 0, "admitted": 0, "refused": 0, "installed": 0, "installable_missing": 0},
        "error": "could not build tool profiles",
    })


def tool_research_data(name: str) -> dict[str, Any]:
    """Per-tool deep-research pointers (Phase B3): the tool's playbook official-docs URLs + the canonical
    web_search query. Offline + advisory + read-only (reads the vendored Strix playbook only; no network,
    no egress). Fail-closed on an unsafe/unknown name (returns has_doc=False with a generated query)."""
    def _read() -> dict[str, Any]:
        from ..tools.registry import probe_tools
        from ..tools.research import research_refs
        purpose = ""
        for t in probe_tools().get("tools", []):
            if str(t.get("name", "")).lower() == str(name or "").strip().lower():
                purpose = str(t.get("purpose", "") or "")
                break
        return research_refs(name, purpose=purpose)

    return _safe(_read, default={"name": name, "has_doc": False, "docs": [], "query": "",
                                 "summary": "", "error": "could not build research refs"})


def capabilities_data() -> dict[str, Any]:
    """The ENGAGE capability packs the New-Assessment wizard offers under 'pick tools' — the SINGLE
    source of truth (``actions.ENGAGE_CAPABILITIES``) that a launch maps a picked id onto a real,
    already-gated ``engage`` flag. Real config data (not invented), so the UI never hardcodes it and
    a picked capability can never widen authority beyond the charter/scope/kill-switch/egress stack.
    The ``flag`` is intentionally NOT exposed — the id is the contract; the mapping lives server-side."""
    from . import actions
    return {
        "capabilities": [
            {"id": c["id"], "label": c["label"], "tier": c["tier"], "purpose": c["purpose"]}
            for c in actions.ENGAGE_CAPABILITIES
        ],
        "scan_modes": [
            {"id": "quick", "label": "Quick", "purpose": "Fast, targeted, bounded pages/budget."},
            {"id": "standard", "label": "Standard", "purpose": "Balanced coverage (default)."},
            {"id": "deep", "label": "Deep", "purpose": "Widest coverage; more pages/budget/cycles."},
        ],
        "note": "Capabilities map to already-gated engage flags. Offensive steps still QUEUE for "
                "owner approval — nothing fires automatically.",
    }


# ---------------------------------------------------------------------------
# AEGIS Defense (P5a) — the managed gateway's live status
# ---------------------------------------------------------------------------


def aegis_status() -> dict[str, Any]:
    """The managed AEGIS gateway's live status for the Defense dashboard: whether it is running, its
    EFFECTIVE mode (enforce may downgrade to observe without the AEGIS_RESPOND entitlement), the target,
    and the per-actor Beta beliefs snapshotted by the gateway. Read-only + resilient (never raises;
    _safe-wrapped by the router). NO gateway launched yet → an honest empty state, not fabricated data."""
    from . import actions
    cur = _safe(actions._read_aegis_current, {}) or {}
    if not cur:
        return {"running": False, "gateway": None, "actors": [], "actor_count": 0,
                "note": "No AEGIS gateway is running. Start one from the Defense screen to watch it live."}
    alive = bool(_safe(lambda: actions._pid_alive(cur.get("pid")), False))
    snap: dict[str, Any] = {}
    sp = cur.get("status_file")
    if sp and Path(sp).is_file():
        snap = _safe(lambda: json.loads(Path(sp).read_text(encoding="utf-8")), {}) or {}
    return {
        "running": alive,
        "gateway": {"upstream": cur.get("upstream"), "bind": f"{cur.get('host')}:{cur.get('port')}",
                    "requested_mode": cur.get("mode"), "slug": cur.get("slug"),
                    "pid": cur.get("pid"), "started": cur.get("started"), "run_id": cur.get("run_id")},
        "effective_mode": snap.get("effective_mode") if alive else None,
        "requested_mode": cur.get("mode"),
        "actors": snap.get("actors", []) if alive else [],
        "actor_count": snap.get("actor_count", 0) if alive else 0,
        "note": None if alive else "The last gateway is no longer running — start a new one.",
    }


# ---------------------------------------------------------------------------
# intelligence & reconnaissance (Intelligence Engine)
# ---------------------------------------------------------------------------


def intel_data(slug: str) -> dict[str, Any]:
    """The Intelligence Engine's picture for an engagement: resolved entities (with
    merge explanations), source-yield learning with calibrated priors, and the gated
    prediction queue (never facts). Read-only over the durable intel store; safe on a
    fresh tree (no intel rows yet)."""
    if not slug:
        return {"slug": None, "note": "select an engagement"}

    def _read() -> dict[str, Any]:
        from ..intel import learn
        from ..intel.predict import AssetPredictor, assess_prediction
        from ..intel.store import IntelStore
        from ..memory.store import Store
        from ..worldmodel.models import NodeKind

        istore = IntelStore(Store())
        ents = _safe(lambda: istore.entities(engagement_slug=slug), default=[]) or []
        entities = [{
            "id": e.canonical_id, "kind": e.primary_kind.value, "confidence": e.confidence,
            "members": [m.node_id for m in e.members], "owned_by": e.owned_by,
            "why": e.explain(),
        } for e in ents]

        yields = _safe(lambda: [{
            **row, "calibrated_prior": learn.source_prior(istore, row["source_kind"],
                                                          archetype=row["archetype"]),
        } for row in istore.all_source_yield()], default=[])

        domains = sorted({m.key for e in ents for m in e.members if m.kind is NodeKind.DOMAIN})
        preds = _safe(lambda: [assess_prediction(p)
                               for p in AssetPredictor().predict(observed_domains=domains)[:12]],
                      default=[])

        return {"slug": slug, "observations": _safe(
                    lambda: istore.observation_count(engagement_slug=slug), default=0),
                "entities": entities, "source_yield": yields, "predictions": preds,
                "doctrine": "Predictions are gated hypotheses — never facts, never auto-scanned. "
                            "Oracle/verify stays the sole authority on what is real."}

    return _safe(_read, default={"slug": slug, "entities": [], "source_yield": [],
                                 "predictions": [], "note": "no intel store yet"})


_VULN_DOCTRINE = (
    "Every feed entry is an intel-tier LEAD, never a fact. Only a fired oracle mints a FACT. "
    "The live pull is a gated, opt-in egress act; offline is the default."
)


def _vuln_sources() -> list[dict]:
    from ..intel.vulnfeed import TRUSTED_VULN_SOURCES
    return [{"name": s.name, "host": s.host, "mode": s.mode} for s in TRUSTED_VULN_SOURCES]


def feed_status() -> dict[str, Any]:
    """K1: the READ-ONLY vuln-feed schedule / egress posture for the Knowledge screen.

    HONEST by construction: the ``intel.scheduler`` is a PURE tick predicate with no persisted schedule, so
    this fabricates NO next-run/last-run. It reports what is TRUE: the trusted sources, that egress is OFFLINE
    by default (both the one-shot 'Pull now' AND the recurring sidecar are conscious opt-ins), and — via
    ``actions.feed_sidecars`` — which recurring ``intel feed-daemon --live`` sidecars the console is currently
    supervising (start/stop is managed here now), each with its live pid + configured interval. It sends no
    traffic and mints nothing itself."""
    from . import actions
    sidecars = _safe(actions.feed_sidecars, default=[]) or []
    return {
        "sources": _safe(_vuln_sources, default=[]),
        "egress_default": "offline",
        "recurring": {
            "managed_here": True,
            "sidecars": sidecars,
            "note": ("recurring auto-pull runs as a console-managed sidecar you Start/Stop here "
                     "(`intel feed-daemon --live`); it also runs under `vigil up --with-feed`. Each tick "
                     "honours the engagement kill-switch (STOP halts it within one poll) and mints only "
                     "intel-tier LEADS. No persisted schedule exists, so there is no fabricated "
                     "next-run/last-run — only the live pid + the interval you chose."),
        },
        "doctrine": _VULN_DOCTRINE,
    }


def _vuln_catalog() -> list[dict]:
    """The defensive knowledge CATALOG as a read-only skillset surface (advisory operators, never facts)."""
    from ..knowledge import catalog
    return [{"id": op.id, "name": op.name, "tactic": op.tactic,
             "technique_ref": list(op.technique_ref)} for op in catalog.CATALOG]


def vulnintel_data(slug: str) -> dict[str, Any]:
    """The vulnerability-intelligence feed picture for an engagement: VULNERABILITY leads (with
    exploit-known / severity), what they AFFECT, the knowledge CATALOG (read-only), the trusted sources,
    and the doctrine. Read-only over the durable intel store; safe on a fresh tree (no rows yet).

    Doctrine surfaced explicitly: every entry is an intel-tier LEAD, never a fact — only a fired oracle
    confirms. Nothing here is auto-scanned or promoted."""
    if not slug:
        return {"slug": None, "note": "select an engagement", "vulnerabilities": [], "affects": [],
                "proposals": [], "catalog": _safe(_vuln_catalog, default=[]), "sources": _vuln_sources(),
                "doctrine": _VULN_DOCTRINE}

    def _read() -> dict[str, Any]:
        from ..intel.models import IntelSourceKind
        from ..intel.store import IntelStore
        from ..memory.store import Store
        from ..worldmodel.models import NodeKind

        istore = IntelStore(Store())
        obs = _safe(lambda: istore.observations(engagement_slug=slug), default=[]) or []
        vuln_obs = [o for o in obs if o.source_kind is IntelSourceKind.VULN_DB]

        vulns: dict[str, dict] = {}
        affects: list[dict] = []
        for o in vuln_obs:
            a = o.attrs or {}
            if o.relation is None and o.subject.kind is NodeKind.VULNERABILITY:
                vulns[o.subject.node_id] = {
                    "id": o.subject.key, "node_id": o.subject.node_id, "source": o.source,
                    "exploit_known": bool(a.get("exploit_known")),
                    "severity": a.get("severity"), "cvss": a.get("cvss"),
                    "summary": a.get("summary"), "feed": a.get("feed"),
                    "vendor": a.get("vendor"), "product": a.get("product"),
                }
            elif o.relation is not None and o.subject.kind is NodeKind.VULNERABILITY and o.object is not None:
                affects.append({"vuln": o.subject.key, "affects": o.object.key,
                                "kind": o.object.kind.value, "ecosystem": a.get("ecosystem"),
                                "exploit_known": bool(a.get("exploit_known"))})

        vuln_list = sorted(vulns.values(), key=lambda v: (not v["exploit_known"], v["id"]))
        from ..knowledge_engine.proposals import draft_proposals
        proposals = [p.to_dict() for p in draft_proposals(vuln_list)]
        return {"slug": slug, "vulnerabilities": vuln_list, "affects": affects[:200],
                "proposals": proposals,
                "catalog": _safe(_vuln_catalog, default=[]), "sources": _vuln_sources(),
                "counts": {"vulnerabilities": len(vuln_list),
                           "exploit_known": sum(1 for v in vuln_list if v["exploit_known"]),
                           "affects": len(affects), "proposals": len(proposals)},
                "doctrine": _VULN_DOCTRINE}

    return _safe(_read, default={"slug": slug, "vulnerabilities": [], "affects": [], "proposals": [],
                                 "catalog": _safe(_vuln_catalog, default=[]),
                                 "sources": _vuln_sources(), "note": "no intel store yet",
                                 "doctrine": _VULN_DOCTRINE})


_EVOLVE_DOCTRINE = (
    "Bounded self-evolve: a deterministic horizon over DISCLOSED leads + coverage gaps → GATED DRAFT "
    "proposals, never merged or applied. 'Studied everything in scope' = drafted everything for the "
    "disclosed leads, not 'the system is complete'. Only a fired oracle mints a FACT."
)


def evolve_data(slug: str) -> dict[str, Any]:
    """The self-evolve picture for an engagement: the horizon + coverage gaps, the DRAFT proposals, the
    `studied_enough` completion signal, and calibration (if outcomes have been recorded). READ-ONLY: it
    computes the plan over the disclosed leads + committed skills and persists NO evolve artifact (no
    gap/proposal/ledger, no fact, no oracle) — a fixed epoch is used for the display-only gap timestamps so
    the read is deterministic. (Like every console read, opening the intel/memory store may lazily create
    the store's own files; K5 writes none of its own.)"""
    if not slug:
        return {"slug": None, "note": "select an engagement", "horizon_gaps": 0, "coverage_gaps": [],
                "proposals": [], "unlearned_leads": [], "studied_enough": {}, "doctrine": _EVOLVE_DOCTRINE}

    def _read() -> dict[str, Any]:
        from datetime import datetime, timezone

        from ..knowledge_engine.cli import _DEFAULT_SKILLS, _vuln_leads
        from ..knowledge_engine.evolve import ledger_path, plan_evolution

        leads = _vuln_leads(slug)
        ledger = None
        lp = ledger_path(slug)
        if lp.is_file():
            from ..calibration.ledger import OutcomeLedger
            ledger = _safe(lambda: OutcomeLedger.load(lp), default=None)
        # fixed epoch: the console never persists these gaps, so their discovered_at is display-only —
        # keeping it constant makes the read deterministic and side-effect-free.
        now = datetime(1970, 1, 1, tzinfo=timezone.utc)
        plan = plan_evolution(leads, skills_dir=_DEFAULT_SKILLS, now=now, ledger=ledger)
        calibration = None
        if ledger is not None and ledger.pairs():
            from ..calibration.calibrate import brier_score
            pairs = ledger.pairs()
            calibration = {"resolved": len(pairs), "brier": _safe(lambda: brier_score(pairs), default=None)}
        return {"slug": slug, "horizon_gaps": len(plan.horizon_gaps),
                "coverage_gaps": [{"bug_class": g.bug_class, "priority": g.priority}
                                  for g in plan.coverage_gaps],
                "proposals": [{"id": p.id, "title": p.title, "status": p.status.value}
                              for p in plan.proposals][:200],
                "unlearned_leads": plan.unlearned, "studied_enough": plan.studied_enough,
                "calibration": calibration, "doctrine": _EVOLVE_DOCTRINE}

    return _safe(_read, default={"slug": slug, "horizon_gaps": 0, "coverage_gaps": [], "proposals": [],
                                 "unlearned_leads": [], "studied_enough": {},
                                 "note": "no intel store yet", "doctrine": _EVOLVE_DOCTRINE})


_COMPLIANCE_DOCTRINE = (
    "Standards mapping is HONEST: only an oracle-confirmed FACT (its retained oracle_context RE-FIRES now) "
    "asserts control coverage; a LEAD is an advisory NOTE that claims no coverage. 'Tested' ≠ 'proven' ≠ "
    "'not tested' — an untested surface is never implied as covered."
)


def compliance_data(run_id: str) -> dict[str, Any]:
    """C3: the standards / compliance picture for a run — each oracle-confirmed FACT mapped to OWASP Top 10 /
    CWE / PCI-DSS / SOC 2 / ISO 27001 controls + MITRE ATT&CK, plus a coverage matrix. The mapper GRADES each
    finding by RE-EXECUTING its retained oracle_context, so a LEAD can never assert control coverage. Read-only;
    sends no traffic."""
    from . import actions
    from ..report import standards

    rj = actions.run_dir(run_id) / "reverifiable.json"
    doc = _safe(lambda: json.loads(rj.read_text(encoding="utf-8")), default=None)
    findings = (doc.get("active_findings") or []) if isinstance(doc, dict) else []
    if not findings:
        return {"run_id": run_id, "pending": doc is None, "findings": [], "coverage": {},
                "standards": standards.STANDARD_VERSIONS, "doctrine": _COMPLIANCE_DOCTRINE}
    mapped = _safe(lambda: [standards.map_finding(f) for f in findings][:200], default=[])
    # M2: feed the EXERCISED-and-oracle-adjudicated classes (verdict clean/finding) into
    # the coverage matrix so a probed-clean class grades `tested_clear` rather than
    # `not_tested`. Absent (older reverifiable.json without exercised_probes) -> None ->
    # unchanged behaviour. An `inconclusive` probe is excluded (no oracle adjudicated it).
    from ..verify.coverage_oracle import tested_bug_classes as _tested_bug_classes
    tested = _safe(
        lambda: (_tested_bug_classes(doc.get("exercised_probes") or []) or None)
        if isinstance(doc, dict) else None,
        default=None,
    )
    coverage = _safe(lambda: standards.coverage_matrix(findings, tested_bug_classes=tested), default={})
    return {"run_id": run_id, "findings": mapped, "coverage": coverage,
            "standards": standards.STANDARD_VERSIONS, "doctrine": _COMPLIANCE_DOCTRINE}


_DRIFT_DOCTRINE = (
    "Continuous proof / drift: the diff is over the ORACLE-CONFIRMED fact set — each run's retained certs are "
    "RE-FIRED (deterministic, offline). A fact that NEWLY appears is a regression (a new exposure); one that "
    "DISAPPEARS is a fix (or a lost detection). A lead is never counted — only a re-firing FACT is."
)


def drift_data(arg: str) -> dict[str, Any]:
    """C2: compare the oracle-confirmed fact set of two runs — ``arg`` is ``"<curr>"`` or ``"<curr>:<prev>"``
    (the two run ids). Re-fires each run's retained certificates (via ``verify.drift.diff_run_docs``) and
    reports the drift: ``regressions`` (newly-confirmed = new exposure), ``fixed`` (disappeared), and stable.
    Deterministic + offline (no traffic). Read-only."""
    from . import actions
    from ..verify import drift as drift_mod

    parts = str(arg or "").split(":", 1)
    curr = parts[0].strip()
    prev = parts[1].strip() if len(parts) > 1 else ""

    def _doc(rid: str):
        if not rid:
            return None
        p = actions.run_dir(rid) / "reverifiable.json"
        return _safe(lambda: json.loads(p.read_text(encoding="utf-8")), default=None)

    curr_doc = _doc(curr)
    if curr_doc is None:
        return {"curr": curr, "prev": prev, "pending": True, "regressions": [], "fixed": [], "stable": [],
                "has_drift": False, "doctrine": _DRIFT_DOCTRINE}
    diff = _safe(lambda: drift_mod.diff_run_docs(_doc(prev) or {}, curr_doc), default=None)
    return {"curr": curr, "prev": prev,
            "regressions": list(diff.added) if diff else [],     # newly-confirmed FACT = a new exposure
            "fixed": list(diff.removed) if diff else [],         # disappeared FACT = fixed / no longer proven
            "stable": list(diff.unchanged) if diff else [],
            "has_drift": bool(diff and diff.has_drift), "doctrine": _DRIFT_DOCTRINE}


# ---------------------------------------------------------------------------
# Trust Center — the signed, offline-verifiable certificates AS certificates.
#
# READ-ONLY. This provider READS committed / produced signed-cert triples
# (``<name>.json`` + ``<name>.sig.json`` + ``<name>.fingerprint.txt``) and returns, per
# cert, its trust root (m-of-n Ed25519 authorizers + threshold), the out-of-band
# fingerprint pin, the signed digest, and the summary numbers. It NEVER runs a verifier
# here (the offline PASS/FAIL is a separate POST action, ``actions.verify_cert``) and it
# NEVER fakes a ``present: true`` — a triple missing on disk is honestly ``present: false``.
# ---------------------------------------------------------------------------

_TRUST_DOCTRINE = (
    "Every certificate here re-verifies OFFLINE: a verifier re-derives the signed digest from the exact "
    "bytes on disk and checks an m-of-n Ed25519 threshold of the NAMED authorizers. A single flipped byte "
    "fails. A green badge means an ACTUAL re-verification passed — never that a signature field merely exists. "
    "The trust ROOT (origin) is bound only where an OUT-OF-BAND pin exists: the recall baseline's is pinned in "
    "SOURCE, so a fresh-key re-sign of it is rejected. A per-run cert has NO source pin — its own "
    ".fingerprint.txt is written by the same signer and is NOT independent, so a fresh-key re-sign of a per-run "
    "triple still re-verifies (its trust root is shown UNPINNED, not a green match) unless YOU supply the "
    "operator-held out-of-band pin, which then rejects the forger."
)

# per-run signed certs the scanner/report pipeline may sign into a run dir (verify.coverage_oracle /
# verify.plan_integrity). The basename is the contract the verify action keys on — kept in sync with
# actions._RUN_CERT_KINDS. A run that has not signed its cert yet is listed present:false (never faked).
_PER_RUN_CERT_KINDS: tuple[tuple[str, str], ...] = (
    ("coverage", "coverage-certificate.json"),
    ("plan-integrity", "plan-integrity.json"),
)


def _cert_summary(kind: str, core: dict) -> dict[str, Any]:
    """The human-facing numbers a Trust-Center card shows for a cert, per kind. Pure projection
    of the (already-signed) document — no derivation, no verification."""
    if kind == "recall":
        res = core.get("results", []) or []
        return {
            "corpus": core.get("corpus"),
            "scope": core.get("scope"),
            "matcher": core.get("matcher"),
            "ground_truth_count": core.get("ground_truth_count"),
            "planted_classes": list(core.get("planted_classes", []) or []),
            "results": [{"tool": r.get("tool"), "tp": r.get("tp"), "fp": r.get("fp"),
                         "fn": r.get("fn"), "precision": r.get("precision"),
                         "recall": r.get("recall"), "f1": r.get("f1")}
                        for r in res if isinstance(r, dict)],
        }
    if kind in ("coverage", "plan-integrity"):
        return {"scope": core.get("scope"), "target_host": core.get("target_host"),
                "denominator": core.get("denominator", {}), "summary": core.get("summary", {})}
    return {}


def _read_cert_triple(core_path, *, name: str, kind: str,
                      run_id: str | None = None, source_pin: str | None = None) -> dict[str, Any]:
    """Read a signed-cert triple into the uniform Trust-Center shape. ``present`` is computed
    from disk (core AND sig must exist) — never faked. A not-present cert returns the shape with
    ``present: false`` and an honest note, and NONE of the trust-root / digest fields fabricated."""
    core_path = Path(core_path)
    sig_path = core_path.with_suffix(".sig.json")
    fp_path = core_path.with_suffix(".fingerprint.txt")
    cert_id = f"{run_id}/{core_path.name}" if run_id else name
    shape: dict[str, Any] = {
        "id": cert_id, "name": name, "kind": kind, "run_id": run_id,
        "present": False, "schema": None, "scorecard_digest": None,
        "trust_root": {"threshold": None, "authorizers": []},
        "fingerprint": None,        # the cert's own committed fingerprint (.fingerprint.txt)
        "source_pin": source_pin,   # the OUT-OF-BAND pin held in SOURCE (recall baseline only), else None
        # True only when an INDEPENDENT (source-held) pin binds the trust root. A per-run cert's own
        # .fingerprint.txt is written by the same signer, so it is NOT an out-of-band pin → False here.
        "trust_root_pinned": source_pin is not None,
        "summary": {},
    }
    present = _safe(lambda: core_path.is_file() and sig_path.is_file(), default=False)
    if not present:
        shape["note"] = "not yet produced — run a scan / make bench to mint and sign this certificate."
        return shape
    core = _safe(lambda: json.loads(core_path.read_text(encoding="utf-8")), default={}) or {}
    sig = _safe(lambda: json.loads(sig_path.read_text(encoding="utf-8")), default={}) or {}
    fp = _safe(lambda: fp_path.read_text(encoding="utf-8").strip(), default=None)
    tr = sig.get("trust_root", {}) or {}
    authz = [{"key_id": a.get("key_id"), "public_key_b64": a.get("public_key_b64")}
             for a in (tr.get("authorizers", []) or []) if isinstance(a, dict)]
    shape.update({
        "present": True,
        "schema": core.get("schema") or sig.get("schema"),
        "scorecard_digest": sig.get("scorecard_digest"),
        "trust_root": {"threshold": tr.get("threshold"), "authorizers": authz},
        "fingerprint": fp,
        "summary": _cert_summary(kind, core),
    })
    return shape


def certs() -> dict[str, Any]:
    """Trust Center: the signed, offline-verifiable certificates rendered AS certificates.

    Read-only. Returns the flagship COMMITTED recall accuracy-core baseline (always shipped in the
    package, trust root pinned in SOURCE) plus, for every known console run, its coverage / plan-integrity
    cert — ``present`` read from disk so a run that has not signed its cert yet is honestly ``present: false``.
    Verifies NOTHING here; ``actions.verify_cert`` is the separate offline PASS/FAIL action. ``_safe``
    throughout — never 500s on a fresh tree."""
    from ..eval import recall_baseline as rb
    from . import actions

    out: list[dict[str, Any]] = []
    recall = _safe(lambda: _read_cert_triple(
        rb.ACCURACY_CORE_PATH, name="recall-accuracy-core", kind="recall",
        source_pin=rb.TRUST_ROOT_FINGERPRINT), default=None)
    if recall is not None:
        out.append(recall)

    # runs are newest-first. A PRESENT (signed) per-run cert is always listed; NOT-present ones are
    # capped (the newest few) so a long run history cannot flood the Trust Center with empty stubs while
    # still giving the operator one honest "not yet produced" example to see.
    _NOT_PRESENT_CAP = 4
    not_present_shown = 0
    run_ids = _safe(lambda: [r["run_id"] for r in list_runs().get("runs", []) if r.get("run_id")], default=[]) or []
    for rid in run_ids:
        rd = _safe(lambda r=rid: actions.run_dir(r), default=None)
        if rd is None:
            continue
        for kind, basename in _PER_RUN_CERT_KINDS:
            cert = _safe(
                lambda rd=rd, kind=kind, basename=basename, rid=rid: _read_cert_triple(
                    rd / basename, name=basename, kind=kind, run_id=rid),
                default={"id": f"{rid}/{basename}", "name": basename, "kind": kind,
                         "run_id": rid, "present": False,
                         "note": "not yet produced — this run has not signed its certificate."})
            if cert.get("present"):
                out.append(cert)
            elif not_present_shown < _NOT_PRESENT_CAP:
                out.append(cert)
                not_present_shown += 1
    return {
        "certs": out,
        "doctrine": _TRUST_DOCTRINE,
        "source_pin_note": ("The recall baseline's trust root is pinned in SOURCE "
                            "(eval.recall_baseline.TRUST_ROOT_FINGERPRINT): rewriting it is a visible code "
                            "change, not a silent data-file swap. A per-run cert has NO source pin — its own "
                            ".fingerprint.txt is written by the same signer and is NOT independent, so its "
                            "trust root shows UNPINNED unless you supply the operator-held out-of-band pin."),
    }
