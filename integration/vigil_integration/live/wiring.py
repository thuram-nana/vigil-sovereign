"""
live.wiring — VIGIL-LIVE WS-2: the live factory that wires the unified engine to the REAL seams.

:mod:`live.engine` is the pure OODA loop over a set of INJECTED seams. This module is the offense-side
factory that binds those seams to the real sovereign machinery for a live engagement:

  * **attest** (WS-6) → :func:`attestation.ledger.require_attestation` bound to the box's persisted
    operator key + a durable JSONL ledger writer (fail-closed: no signer / no durable write → DENY).
  * **gate**  (F2/F3) → :func:`conjunctive_gate.build_offense_gate` over a signed CRUCIBLE authority
    (WARDEN tier ∧ CRUCIBLE scope/window/budget ∧ m-of-n for destructive).
  * **run_tool** (F3/F9) → :func:`live.executor.execute`, the governed, loopback-PINNED subprocess
    runner, pre-wired with the gate + a real Ed25519 spine signer.
  * **oracle** (F2) → :func:`oracle_adapter.confirm_and_certify`: the LLM's ``exploit_succeeded`` is a
    LEAD until the deterministic oracle re-fires over the RETAINED ``oracle_context`` and a signed,
    proof-carrying certificate is minted.
  * **checkpoint** (F2b) → :class:`live.spine_vigilcore.VigilCoreSpine.write_state` (append-only signed).
  * **detect** (WS-4) → :func:`detection.registry.run_all_detections` over the target's own logs.
  * **project** (F4), **emit** (F11) → optional; wired when Neo4j / an OTLP collector are present, else
    honestly omitted (a graph/telemetry outage never affects the run's truth).

Framework-touching (``framework.v2.*``) imports are LAZY, inside functions — this module stays
import-clean and never co-loads the sovereign env (the P5 two-env boundary). Everything here is
offense-side: it runs only in the no-owner-key worker.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from vigil_core import KeyPair, generate_keypair
from vigil_core.crypto import sign

from ..agent.state import AgentState, Phase
from ..attestation.identity import load_or_create_operator_keypair, operator_signer, resolve_operator
from ..attestation.ledger import make_ledger_writer, read_ledger, require_attestation
from ..detection.registry import run_all_detections
from ..oracle_adapter import confirm_and_certify
from .approval_token import ApprovalAuthority
from .engine import EngineSeams, VigilEngine
from .executor import _TERMINAL_TOOL, execute, execute_terminal
from .nonce_ledger import NonceLedger
from .governance_identity import DEFAULT_GOVERNANCE_KEY_FILE, load_or_create_governance_keypair
from .spine_identity import DEFAULT_SPINE_KEY_FILE, SPINE_KEY_ID, load_or_create_spine_keypair
from .spine_vigilcore import VigilCoreSpine
from .think_claude import think

DEFAULT_KEY_ID = "root0"

# The tool→phase manifest (the fail-closed phase gate reads this; an unlisted tool is DENIED in a phase).
DEFAULT_TOOL_VIEW: dict[str, list[str]] = {
    "nmap": ["informational", "exploitation"],
    "httpx": ["informational", "exploitation"],
    "nuclei": ["informational", "exploitation"],
    "ffuf": ["informational", "exploitation"],
    "sqlmap": ["exploitation", "post_exploitation"],
    "hydra": ["exploitation", "post_exploitation"],
    "curl": ["informational", "exploitation"],
    # T1: the governed LOCAL terminal (executor.execute_terminal). Non-network, non-destructive, safe by
    # CONSTRUCTION (a read/inspect-only allowlist), so it is registered for the phase gate but is NOT in the
    # destructive view. It classifies A2 (no danger token) → under the A1 offense ceiling the conjunctive
    # gate QUEUES it for owner approval; it can never auto-run.
    "terminal.run": ["informational", "exploitation", "post_exploitation"],
    # sandbox.exec: the network-isolated bwrap write/exec tier (executor.execute_sandbox). It runs an
    # ARBITRARY command, safe by KERNEL isolation (no egress, workspace-confined write). It carries an A3
    # danger token → classifies A3, the MOST-gated tier → under the A1 offense ceiling the conjunctive gate
    # QUEUES it for a per-action owner approval (the M2 token), never auto. Registered for the phase gate.
    "sandbox.exec": ["informational", "exploitation", "post_exploitation"],
}
# The operator manifest of destructive tools (authoritative for the m-of-n threshold-destruction leg).
DEFAULT_DESTRUCTIVE_VIEW: dict[str, bool] = {"sqlmap": True, "hydra": True, "metasploit": True}

# Tools that are low-blast recon → WARDEN tier so the conjunctive gate can AUTO-allow them in-scope.
_RECON = {"nmap", "httpx", "nuclei", "ffuf", "curl", "subfinder", "gau", "katana"}


def default_classify(tool_name: str) -> str:
    """The WARDEN tier of an offense tool, deriving the DANGER determination from the ONE shared classifier
    of record (``vigil_core.warden_tiers``, the byte-faithful port of the Rust kernel) so it can never drift
    from the sovereign side. A name carrying an A3 DANGER token (``git.push``, ``data.delete``,
    ``secrets.read``) classifies A3 IDENTICALLY to the kernel — closing the drift of the old
    recon→A1/else→A2 stub, which wrongly gave those A2. A curated, danger-FREE recon tool stays auto-eligible
    A1; every other offense name stays A2 (the pre-S2 offense posture). The gate OUTCOME is unchanged — a
    dangerous name was A2→queue and is now A3→queue under the A1 ceiling — only the tier LABEL is corrected;
    the gate's floor/ceiling still bound the final decision."""
    from vigil_core.warden_tiers import has_danger_token
    name = str(tool_name).strip()
    danger = has_danger_token(name)
    if name.lower() in _RECON and not danger:
        return "A1"                       # curated danger-free recon → auto-eligible (the floor still decides)
    return "A3" if danger else "A2"       # dangerous → A3 (matches the kernel); else the offense floor A2


def _wallclock_iso() -> str:
    """The 'WHEN' data field for the attestation (redacted into the ledger; never the chain's clock)."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------------------------------
# provisioning — a signed CRUCIBLE authority + the shared trust root / cert signers
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Provisioned:
    """The governance material a live engagement needs. ``keypair`` is the single Ed25519 authority
    keypair; ``trust_root`` verifies both the on-disk authority signature AND the minted certificates;
    ``signers`` is the list-of-tuples cert-signer form; ``authority_path`` is where the signed authority
    was written."""

    keypair: KeyPair
    trust_root: Any
    signers: list[tuple[str, str]]
    authority_path: str
    slug: str


def provision_authority(
    *,
    slug: str,
    scope: Sequence[str],
    keypair: Optional[KeyPair] = None,
    key_id: str = DEFAULT_KEY_ID,
    environment: str = "twin",
    duration_hours: float = 8.0,
    max_actions: int = 1000,
    base_dir: Optional[str] = None,
    vault: Any = None,
) -> Provisioned:
    """Create + SIGN a CRUCIBLE authority for ``slug`` scoped to ``scope`` (LITERAL hosts — the scope
    matcher has no CIDR, so pass ``["127.0.0.1"]`` not a block), persist it to the default authority
    store, and return the shared governance material. Offense-side (lazy ``framework`` import).

    Governance key resolution (S7): an explicit ``keypair`` wins (tests / an externally-managed key);
    otherwise, when ``base_dir`` is given, a STABLE offense-governance key is loaded-or-provisioned under
    ``base_dir`` (sealed at rest under ``vault`` when provisioned), so one owner-signed delegation covers the
    anchor-1 signer across runs; with no ``base_dir`` it falls back to the legacy per-run ephemeral key
    (unchanged, non-persisting — used by callers that do not supply a home)."""
    from vigil_core import AuthorizerKey, TrustRoot
    from framework.v2.authority.charter import authority_from_scope
    from framework.v2.authority.models import TargetEnvironment
    from framework.v2.authority.signing import sign_authority
    from framework.v2.authority.store import save_signed_authority

    if keypair is not None:
        kp = keypair
    elif base_dir is not None:
        kp = load_or_create_governance_keypair(
            path=str(Path(base_dir) / DEFAULT_GOVERNANCE_KEY_FILE), vault=vault)
    else:
        kp = generate_keypair()   # legacy ephemeral (no home supplied); unchanged
    trust_root = TrustRoot(
        threshold=1,
        authorizers=[AuthorizerKey(key_id=key_id, name=key_id, public_key_b64=kp.public_key_b64)],
    )
    doc = authority_from_scope(
        slug, list(scope), environment=TargetEnvironment(environment),
        duration_hours=duration_hours, max_actions=max_actions,
    )
    signed = sign_authority(doc, {key_id: kp.private_key_b64})   # authority signer = dict[key_id→priv]
    out_path = save_signed_authority(signed)
    return Provisioned(
        keypair=kp, trust_root=trust_root,
        signers=[(key_id, kp.private_key_b64)],                  # cert signer = list[(key_id, priv)]
        authority_path=str(out_path), slug=slug,
    )


# ---------------------------------------------------------------------------------------------------
# the live engine factory
# ---------------------------------------------------------------------------------------------------


@dataclass
class EngineConfig:
    """Everything the live factory needs. Paths default under ``base_dir``; a missing sidecar degrades
    its seam to fail-closed (never a fake pass)."""

    slug: str
    # F3: the SESSION this run belongs to. When set, it is the Neo4j graph PARTITION key (so each session
    # owns a disjoint graph + its own accumulating prior context); empty falls back to the slug. It is a
    # partition/organisation key only — it grants no authority and never widens scope.
    session_id: str = ""
    # F4: the operator-CONSENTED connected session ids whose graph partitions this run may UNION as priors
    # (a read-time scope; each unioned prior stays origin-tagged and non-authoritative). Empty = isolated.
    connections: Sequence[str] = ()
    base_dir: str = ".vigil-live"
    scope: Sequence[str] = field(default_factory=lambda: ("127.0.0.1",))
    # think backend
    replay: Optional[Any] = None            # a ReplayThinker (keyless-live) — else the live Claude path
    api_key: Optional[str] = None
    # attestation
    operator_keypair: Optional[KeyPair] = None
    # spine
    spine_keypair: Optional[KeyPair] = None
    # detection mirror log sources
    access_log: str = ""
    auth_log: str = ""
    conn_log: str = ""
    # the subprocess runner the executor uses; None → the real live subprocess_runner. An injected
    # runner (a deterministic echo) lets the full gate/oracle/spine wiring be exercised without the
    # live Kali binaries present — the gate/oracle/egress checks are identical either way.
    runner: Optional[Callable[..., Any]] = None
    # governance (provisioned separately, or provisioned here)
    provisioned: Optional[Provisioned] = None
    require_attestation: bool = True
    max_iterations: int = 12
    # The WARDEN offense ceiling: tools above it QUEUE for a signed owner approval instead of
    # auto-running. Default "A1" (fail-closed: every offense tool queues). Raising it to "A2" encodes
    # the operator's STANDING approval to auto-run non-destructive offense tools against a target they
    # own and have chartered (a loopback engagement) — an explicit, logged trust decision, never a
    # default. Destructive tools still additionally require the m-of-n threshold-destruction leg.
    offense_ceiling: str = "A1"
    # The operator's STANDING approval to run queued offense tools (>= A2) against their own chartered
    # loopback target — the human leg of the conjunctive gate. Default False (fail-closed: a queued
    # offense tool pauses for approval and never runs). Setting True represents the operator's explicit
    # authorization (the `vigil engage --approve-offense` invocation); CRUCIBLE scope is enforced
    # regardless, so an out-of-scope target is still denied even with approval granted.
    owner_approves_offense: bool = False
    # M2 — the HIGH-ASSURANCE per-action approval path (opt-in). When ``approval_authority`` is set, the
    # engine's approval gate becomes :func:`build_approval_gate`: a queued offense tool is upgraded to allow
    # ONLY by a valid, single-use, owner-signed, action-bound token (never a blanket standing boolean).
    # ``approval_token_source()`` returns the (ApprovalToken, ApprovalAction) bound to the action currently
    # being authorized; ``approval_nonce_dir`` is the atomic single-use ledger directory. Left None ⇒ the
    # engine keeps the standing ``owner_approves_offense`` behaviour (a lower-assurance, explicit mode).
    approval_authority: Optional[ApprovalAuthority] = None
    approval_token_source: Optional[Callable[[], Optional[tuple]]] = None
    approval_nonce_dir: Optional[str] = None


def _offense_scope_source(slug: str, trust_root: Any):
    """A ScopeSource over the SIGNED authority scope (the scope the gate enforces — verified against
    ``trust_root``, the engagement's governance key; owner-tied only when the ``sigil delegate-offense``
    ceremony has blessed that key), re-loaded per call (a mid-engagement re-sign is honoured), for the
    executor's egress guard. Fail-closed: any load/verify failure → ``hosts()`` returns ``[]`` → empty scope →
    the executor denies EVERY target (including loopback) — strictly closed. Offense-only; ``framework`` and
    ``vigil_gateway`` are imported LAZILY here (neither is a sovereign dependency) so importing
    ``vigil_integration`` in the sovereign env stays clean (the P5 two-env boundary)."""
    from framework.v2.authority.gate import load_authority_for_gate
    from vigil_gateway.scope_source import ScopeSource

    class _AuthorityScope(ScopeSource):
        def hosts(self) -> list[str]:
            try:
                return list(load_authority_for_gate(slug, trust_root=trust_root).scope)
            except Exception:  # noqa: BLE001 — unverifiable/absent authority ⇒ empty scope ⇒ deny (fail-closed)
                return []

    return _AuthorityScope()


def build_engine(config: EngineConfig) -> VigilEngine:
    """Wire a :class:`live.engine.VigilEngine` to the REAL seams for ``config.slug``. Provisions the
    signed authority if one was not supplied. Fail-closed throughout: a seam whose dependency is absent
    is left None (deny / no-fact / no-run), never faked."""
    base = Path(config.base_dir)
    base.mkdir(parents=True, exist_ok=True)

    # The offense worker's own TPM-sealed vault (audit G1): built FIRST so both the operator key and the
    # STABLE governance key (S7) seal under one provisioned KEK. Unprovisioned (default) they are plaintext
    # at rest — unchanged, non-bricking.
    from vigil_core.vault import Vault
    op_vault = Vault(base / "vault")

    # S7: provision the authority under a STABLE, sealed governance key (base_dir + vault), so one owner
    # delegation covers the anchor-1 signer across runs. A caller-supplied provisioned authority still wins.
    prov = config.provisioned or provision_authority(
        slug=config.slug, scope=config.scope, base_dir=config.base_dir, vault=op_vault)

    # -- attestation (WS-6): operator identity + signer + durable ledger writer ---------------------
    op_kp = config.operator_keypair or load_or_create_operator_keypair(
        path=str(base / "operator.key"), vault=op_vault)
    operator = resolve_operator(keypair=op_kp)
    op_signer = operator_signer(keypair=op_kp)
    ledger_path = str(base / "usage-ledger.jsonl")
    ledger_writer = make_ledger_writer(ledger_path)
    anchor_path = str(base / "attest-anchor.json")

    def attest(*, action: str, target: str, phase: str, seq: int, prev_hash: str) -> Any:
        # The usage ledger is its OWN append-only hash-chain: continue it from its current head so
        # multiple engagements form ONE unbroken, verifiable chain (the engine's engagement-spine
        # seq/prev_hash are separate coordinates and are intentionally not used here).
        existing = read_ledger(ledger_path)
        next_seq = (existing[-1].seq + 1) if existing else 0
        head = existing[-1].record_hash if existing else None   # None → record_usage uses GENESIS_PREV
        return require_attestation(
            operator=operator, action=action, target=target, phase=phase,
            at=_wallclock_iso(), prev_hash=head, signer=op_signer, seq=next_seq,
            anchor_state_path=anchor_path, writer=ledger_writer,
        )

    # -- gate (F2/F3): the conjunctive gate over the signed authority --------------------------------
    gate = _build_gate(prov, ceiling=config.offense_ceiling)

    # The executor's egress guard is keyed off the SAME signed-authority scope the gate enforces (re-loaded
    # per call). Two distinct fail-closed outcomes: (a) a per-call load/verify failure INSIDE the scope source
    # yields an empty scope → the executor takes the scoped branch and denies EVERY target incl. loopback
    # (strictly closed); (b) no trust root, or the lazy framework/gateway import itself failing here, leaves
    # offense_scope None → the executor falls back to loopback-only. Both are fail-closed; (a) is stricter.
    offense_scope = None
    if getattr(prov, "trust_root", None) is not None:
        try:
            offense_scope = _offense_scope_source(prov.slug, prov.trust_root)
        except Exception:  # noqa: BLE001 — lazy import/build failure ⇒ loopback-only fallback (fail-closed)
            offense_scope = None

    # -- spine signer + checkpoint (F2b) -------------------------------------------------------------
    # S5: a STABLE offense-spine identity (persisted + sealed under the offense vault), not the old
    # per-run ephemeral key — so the spine is verifiable across runs and can be owner-delegated
    # (OFFENSE_SPINE_ROLE). config.spine_keypair stays injectable for tests. Reuses op_vault so both
    # offense secrets seal under one provisioned KEK (distinct AEAD contexts keep the blobs separate).
    spine_kp = config.spine_keypair or load_or_create_spine_keypair(
        path=str(base / DEFAULT_SPINE_KEY_FILE), vault=op_vault)
    spine = VigilCoreSpine(spine_kp, str(base / f"{config.slug}.spine"))

    def exec_signer(message: bytes) -> str:
        # the executor's ExecRecord signer: a raw Ed25519 base64 signature over the record bytes.
        return sign(spine_kp.private_key_b64, message)

    _seq = {"n": 0}

    # The approval gate (the WARDEN human leg): the HIGH-ASSURANCE per-action token path when the operator
    # provisioned an ApprovalAuthority, else the standing-boolean fallback. Either way a CRUCIBLE deny /
    # tripped kill-switch is preserved — approval never widens scope.
    if gate is None:
        approval_gate = None
    elif config.approval_authority is not None:
        import time as _time
        _nonce_dir = config.approval_nonce_dir or str(base / "approval-nonces")
        approval_gate = build_approval_gate(
            gate, authority=config.approval_authority, ledger=NonceLedger(_nonce_dir),
            now=_time.time, token_source=config.approval_token_source or (lambda: None),
        )
    else:
        approval_gate = _approval_gate(gate)

    def run_tool(tool: Any, phase: Phase, seq: int, *, approved: bool = False) -> Any:
        _seq["n"] = seq
        kw = {"run": config.runner} if config.runner is not None else {}
        # An owner-approved offense tool executes under the approval gate (WARDEN human leg satisfied);
        # everything else under the base gate. Either way CRUCIBLE scope + the loopback pin still gate it.
        active_gate = approval_gate if (approved and approval_gate is not None) else gate

        # T3 — AUTONOMOUS TERMINAL: the governed LOCAL terminal is a DISTINCT executor path. execute_terminal
        # REUSES the same conjunctive gate + signed ExecRecord but SKIPS network target-pinning — its allowlist
        # admits ONLY local read/inspect utilities, so egress/write/exec are impossible BY CONSTRUCTION.
        # terminal.run has NO argv builder in the network `execute` path (it would be denied as "unknown tool"),
        # so it MUST route here. It already passed authorize_edge upstream (terminal.run classifies A2 → the gate
        # QUEUES it → an owner approval is the human leg), and execute_terminal RE-authorizes it (defense in
        # depth). The engine treats a terminal record's local output as ADVISORY: it never enters oracle intake,
        # so an autonomous terminal command can never mint a FACT.
        if isinstance(getattr(tool, "tool_name", None), str) and tool.tool_name.strip().lower() == _TERMINAL_TOOL:
            ta = getattr(tool, "tool_args", None)
            command = ta.get("command") if isinstance(ta, dict) else None
            command = command if isinstance(command, str) else str(command or "")
            return execute_terminal(
                command, phase.value,
                gate=active_gate, signer=exec_signer, seq=seq,
                view=DEFAULT_TOOL_VIEW, destructive_view=DEFAULT_DESTRUCTIVE_VIEW, **kw,
            )

        return execute(
            tool.tool_name, tool.tool_args, phase.value,
            gate=active_gate, signer=exec_signer, seq=seq,
            view=DEFAULT_TOOL_VIEW, destructive_view=DEFAULT_DESTRUCTIVE_VIEW,
            scope=offense_scope, **kw,
        )

    def approval(decision: Any, state: Any) -> bool:
        # The operator's standing approval for their own chartered loopback engagement. A real signed
        # per-action approval (the I4 destruction-gate mechanism) plugs in here unchanged.
        return bool(config.owner_approves_offense)

    def checkpoint(state: AgentState, seq: int) -> Any:
        try:
            return spine.write_state(state, seq=seq, engagement=config.slug)
        except Exception:  # noqa: BLE001 — a spine outage is a recorded no-op, never fatal to the run
            return None

    # -- oracle (F2): confirm_and_certify over the retained oracle_context ---------------------------
    oracle = _build_oracle(prov)

    # -- per-session knowledge graph (F3): the partition key is the SESSION id (falls back to the slug),
    # so each session owns a disjoint Neo4j partition + accumulates its own prior context. graph_writer is
    # set below in the projection block (None when no Neo4j is connected); think_seam reads it at CALL time
    # (during engage), by which point it is assigned — Python closure late-binding.
    # NB: session_id + slug share the one `engagement_id` partition namespace, so naming a session EXACTLY
    # equal to an unrelated engagement's slug would merge their partitions — a low-risk, advisory-only leak
    # (priors are non-authoritative + never read by the gate). session ids are auto-minted (timestamped /
    # chat ids), so a collision needs a deliberate identical --session; we .strip() to avoid a blank alias.
    graph_partition = (config.session_id or "").strip() or config.slug
    graph_writer: Any = None

    # -- think (F2) — folds the session's PRIOR graph context (F3) as UNTRUSTED advisory priors ----------
    def think_seam(state: AgentState) -> Any:
        ctx = _prompt_ctx(state)
        if graph_writer is not None:
            # F4: union the operator-CONSENTED connected sessions' partitions (read-time; each row stays
            # origin-tagged + non-authoritative). Empty connections = the session reads only its own partition.
            priors = graph_writer.retrieve_priors(
                group_id=graph_partition, limit=8,
                extra_partitions=[str(c).strip() for c in (config.connections or ()) if str(c).strip()])
            if priors:
                # PRIOR, NOT FACT: these are non-authoritative summaries from this session's partition (an
                # earlier run's findings, or this run's so far). A prior confirmed in an earlier run must be
                # RE-confirmed by THIS run's oracle to mint a fact here. think() nonce-fences the whole digest.
                ctx += " " + _format_priors(priors)
        return think(state, ctx, replay=config.replay, api_key=config.api_key)

    # -- detection mirror (WS-4) ---------------------------------------------------------------------
    def _cert_signer(message: bytes) -> str:
        return sign(spine_kp.private_key_b64, message)

    def detect() -> list:
        # a signer + verify key are wired so a FACT-grade detection mints a re-verifiable signed PCF
        # certificate; a fire that cannot be certified honestly degrades to a LEAD (fail-closed).
        return run_all_detections(
            access_log=_read(config.access_log), auth_log=_read(config.auth_log),
            conn_log=_read(config.conn_log),
            signer=_cert_signer, verify_key=spine_kp.public_key_b64, key_id=SPINE_KEY_ID,
        )

    # -- operator instructions (A5) — the offense-local, advisory mid-run guidance queue for this slug ---
    def operator_messages() -> list:
        from .instructions import drain
        return drain(config.slug, base=config.base_dir)

    # -- fireteam (A4c) — an APPROVED deploy fans out N capped, gated members via run_fireteam -----------
    def deploy_fireteam(decision: Any, state: AgentState, seq: int) -> Any:
        import asyncio

        from ..fireteam.member_runner import build_member_runner
        from ..fireteam.orchestrator import run_fireteam
        plan = {"wave_id": f"{config.slug}-w{int(seq)}",
                "members": list(getattr(decision, "fireteam", []) or [])}
        # members reuse the SAME think + governed executor + gate + oracle as the parent — never a
        # privileged copy. run_fireteam validates the plan fail-closed (a malformed/over-cap/mutex plan
        # spawns NOTHING) and collect() re-fires the oracle so only a confirmed claim mints a fact.
        runner = build_member_runner(think=think_seam, run_tool=run_tool, parent_objective=state.objective)
        # S5 coordination: hand run_fireteam the blackboard keyed to the STABLE engagement slug so a wave's
        # discoveries reach the next wave's members as ADVISORY hints. Best-effort — a coordination message is
        # never evidence (no fact-building path reads the agent_message kind) and a bus error never aborts the
        # wave; honest omission if the blackboard can't be opened.
        bb = None
        try:
            from framework.v2.agents.blackboard import open_blackboard
            bb = open_blackboard()
        except Exception:  # noqa: BLE001
            bb = None
        # No ConfirmationRegistry is passed: a member's over-cap escalation is SURFACED (the engine records
        # it as a queued_edge) but not yet persisted for a later signed action. Fail-closed — a queued
        # member edge never auto-runs; wiring an actionable member-escalation registry is a follow-up.
        return asyncio.run(run_fireteam(plan, runner, phase=state.phase, gate=gate, oracle=oracle,
                                        seq_start=int(seq), blackboard=bb, engagement=config.slug))

    # -- knowledge-graph projection (F1) — mirror the run's oracle-CONFIRMED facts into a cloud/remote
    # Neo4j read-model, when the operator has connected one (Settings → Knowledge graph). Honest omission:
    # no creds / an unreachable host → build_neo4j_session_factory returns None → the project seam stays
    # None → the engine simply does not mirror (it never fakes a connection). The mirror is a PURE ONE-WAY
    # PROJECTION: rebuild_from_spine re-derives confirmation via graph.project (a bare status="fact" without
    # a signed evidence+signature ref projects as a :Lead), CLEARS + rewrites the partition each call, mints
    # no fact, and is never consulted by the gate. Deterministic (sorted, spine-seq coordinate; no wallclock).
    graph_project = None
    from ..graph import spine_record_from_finding
    from .graph_driver import build_neo4j_session_factory
    from .graph_neo4j import Neo4jGraphWriter
    session_factory = build_neo4j_session_factory()
    if session_factory is not None:
        graph_writer = Neo4jGraphWriter(session_factory, group_id=graph_partition)   # F3: per-session partition
        _mirror: dict[str, Any] = {}      # finding ref -> confirmed Finding, accumulated across the run

        def graph_project(facts: list) -> None:
            # Accumulate this batch (dedupe by finding ref), then re-project the WHOLE set — a projection,
            # never an append. What confirmation rests on here (stated honestly): the ENGINE only ever calls
            # this seam with oracle-MINTED facts — `intake.facts` and fireteam facts filtered on a non-empty
            # signed `evidence_ref` (engine._project); a `Finding` is type-level unconstructable as a fact
            # without that signed ref (state.Finding._fact_needs_evidence). A `Finding` carries NO separate
            # spine signature field, so `signature_ref` below MIRRORS the same signed oracle `evidence_ref`
            # (it is NOT a second, independent gate in this path). The projector's `_is_confirmed` still
            # re-derives :Confirmed vs :Lead from status+evidence_ref+signature_ref, so a LEAD (which the
            # engine never passes here anyway) can never become :Confirmed.
            for f in facts or []:
                ref = str(getattr(f, "ref", "") or "") or f"f{len(_mirror)}"
                _mirror[ref] = f
            records = [
                spine_record_from_finding(
                    f, seq=i, hash=str(getattr(f, "ref", "") or f"proj-{i}"),
                    signature_ref=str(getattr(f, "signature_ref", "") or getattr(f, "evidence_ref", "") or ""),
                    engagement_id=graph_partition)                        # F3: the per-session partition id
                for i, (_ref, f) in enumerate(sorted(_mirror.items()))
            ]
            graph_writer.rebuild_from_spine(records, group_id=graph_partition)

    seams = EngineSeams(
        think=think_seam, gate=gate, run_tool=run_tool, oracle=oracle, attest=attest,
        checkpoint=checkpoint, detect=detect, approval=approval,
        operator_messages=operator_messages, deploy_fireteam=deploy_fireteam,
        project=graph_project,
    )
    return VigilEngine(slug=config.slug, seams=seams,
                       require_attestation=config.require_attestation,
                       max_iterations=config.max_iterations)


# ---------------------------------------------------------------------------------------------------
# seam builders (each returns None — the fail-closed default — when its dependency cannot be wired)
# ---------------------------------------------------------------------------------------------------


def _build_gate(prov: Provisioned, *, ceiling: str = "A1") -> Optional[Callable[..., Any]]:
    """The conjunctive gate over the signed authority. None (⇒ every tool call DENIED) if the framework
    gate cannot be built. ``ceiling`` is the operator's standing approval tier (see EngineConfig)."""
    try:
        from ..conjunctive_gate import build_offense_gate
        # Wire the operator KILL-SWITCH into the gate — previously omitted, so the live engine's gate never
        # consulted it (a tripped killswitch would not have halted tool calls through THIS gate). Fail-soft:
        # if the KillSwitch can't be constructed, still build the gate (the CRUCIBLE authority stands).
        killswitch = None
        try:
            from framework.v2.authority.killswitch import KillSwitch
            killswitch = KillSwitch(prov.slug)
        except Exception:  # noqa: BLE001
            # Fail-soft here (NOT deny-all) is safe: KillSwitch(slug) is I/O-free (it only stores the slug
            # and computes a pure path), so it can throw ONLY if the `framework` import itself fails — and
            # in that case the CRUCIBLE leg's own lazy authorize_action import fails at call time too, so
            # conjunctive_decide DENIES anyway. So this can never silently drop a *working* kill-switch.
            killswitch = None
        return build_offense_gate(slug=prov.slug, trust_root=prov.trust_root,
                                  classify=default_classify, ceiling=ceiling, killswitch=killswitch)
    except Exception:  # noqa: BLE001 — no gate wired ⇒ deny-by-default (the engine denies every call)
        return None


def _approval_gate(real_gate: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap the conjunctive gate so a WARDEN 'queue' (in-envelope, owner-approval-needed) is upgraded to
    'allow' — the human leg satisfied by the operator's signed approval. A CRUCIBLE 'deny' (out of
    scope / killswitch / budget) is PRESERVED: approval never widens scope. A destructive action's
    m-of-n leg is unaffected (it denies, not queues, without its quorum)."""

    def gate(tool_name: str, target: str, destructive: bool = False, **kw: Any) -> Any:
        verdict = real_gate(tool_name, target, destructive, **kw)
        outcome = getattr(verdict, "outcome", "deny")
        if outcome == "queue":
            # rebuild an allow verdict of the same shape (duck-typed to GateVerdict).
            from ..conjunctive_gate import GateVerdict
            return GateVerdict(True, "allow",
                               f"owner-approved (WARDEN human leg satisfied); {getattr(verdict, 'reason', '')}",
                               getattr(verdict, "crucible_allowed", True), getattr(verdict, "warden", None))
        return verdict

    return gate


def build_approval_gate(
    real_gate: Callable[..., Any],
    *,
    authority: ApprovalAuthority,
    ledger: NonceLedger,
    now: Callable[[], float],
    token_source: Callable[[], Optional[tuple]],
) -> Callable[..., Any]:
    """M2 — the HIGH-ASSURANCE per-action approval gate: a WARDEN 'queue' is upgraded to 'allow' ONLY by a
    valid, single-use, owner-signed, action-bound token for THIS exact ``(tool_name, target)`` action (see
    :mod:`live.approval_token`). Unlike :func:`_approval_gate` (a STANDING blanket boolean), each upgrade
    spends one owner signature bound to one action, atomically (the nonce is burned here — the single
    execution-authorization point, called once per action inside ``execute``/``execute_terminal``).

    A CRUCIBLE 'deny' (out of scope / tripped kill-switch / budget) is a 'deny', NOT a 'queue', so it is
    returned UNTOUCHED — a token can NEVER widen scope, lift the kill-switch, or authorize a denied action;
    it only satisfies the WARDEN human leg for an already-in-envelope action. No token (or an
    invalid/expired/replayed one) leaves the 'queue' in place (the executor then denies), never auto-runs.

    ``token_source()`` returns the ``(ApprovalToken, ApprovalAction)`` bound to the action currently being
    authorized (or ``None``). ``now()`` is the real clock the token window is checked against (the
    dead-man's-switch is inherently time-based; this is NOT oracle/learning math)."""

    def gate(tool_name: str, target: str, destructive: bool = False, **kw: Any) -> Any:
        verdict = real_gate(tool_name, target, destructive, **kw)
        if getattr(verdict, "outcome", "deny") != "queue":
            return verdict                       # allow stays allow; DENY stays DENY (token never widens scope)

        pend = None
        try:
            pend = token_source() if callable(token_source) else None
        except Exception:  # noqa: BLE001 — a token-source error leaves the action queued (fail-closed)
            pend = None
        if not (isinstance(pend, tuple) and len(pend) == 2):
            return verdict                       # no per-action token → stays queued (the executor denies)
        token, action = pend

        # Bind the token to THIS gate call: its named tool+target must equal what is being authorized. (The
        # finer args-digest is bound inside the token and verified against `action.action_digest` by
        # consume_token; the caller populates `action` from the SAME action it is executing.)
        if getattr(action, "tool_name", None) != tool_name or getattr(action, "target", None) != target:
            return verdict

        try:
            from .approval_token import consume_token
            decision = consume_token(token, action, authority=authority, now=float(now()), ledger=ledger)
        except Exception:  # noqa: BLE001 — any verification/burn error leaves the action queued (fail-closed)
            return verdict
        if not decision.authorized:
            return verdict                       # invalid / expired / replayed token → stays queued

        from ..conjunctive_gate import GateVerdict
        return GateVerdict(True, "allow",
                           f"owner-approved (per-action token, single-use); {getattr(verdict, 'reason', '')}",
                           getattr(verdict, "crucible_allowed", True), getattr(verdict, "warden", None))

    return gate


# ---------------------------------------------------------------------------------------------------
# T2: the governed LOCAL terminal runtime — the MINIMAL gate + spine-signer subset build_engine wires
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TerminalRuntime:
    """The minimal governance subset the governed LOCAL terminal needs to call
    :func:`live.executor.execute_terminal` — the exact building blocks :func:`build_engine` wires, WITHOUT
    starting a full engagement (no oracle, no graph, no attestation loop). Fail-closed by construction:

      * ``gate`` is ``None`` ⇒ ``execute_terminal``'s ``authorize_tool_call`` DENIES every command (no gate);
      * ``signer`` is ``None`` ⇒ ``execute_terminal`` refuses BEFORE running (an unrecordable command);
      * ``approval_gate`` wraps the SAME ``_approval_gate`` the engine uses (a WARDEN 'queue' → 'allow' only
        when the operator approves) — a DENY (out-of-scope / killswitch / budget) is preserved, never widened.

    ``terminal.run`` classifies A2 under the ONE shared WARDEN classifier, so under the A1 offense ceiling
    the conjunctive gate QUEUES it: without ``approval_gate`` it can never run; with it (an operator
    ``--approve``) it is admitted. The allowlist inside ``execute_terminal`` still bounds it to local
    read/inspect binaries, so no command — approved or not — can egress or write."""

    gate: Optional[Callable[..., Any]]
    approval_gate: Optional[Callable[..., Any]]
    signer: Optional[Callable[[bytes], str]]
    view: dict
    destructive_view: dict
    history_path: str
    slug: str


def build_terminal_runtime(*, slug: str = "loopback", base_dir: str) -> TerminalRuntime:
    """Build the gate + sealed spine signer the governed LOCAL terminal needs, reusing the EXACT building
    blocks :func:`build_engine` uses: :func:`provision_authority` (signed CRUCIBLE authority under a stable,
    sealed governance key) → :func:`_build_gate` (the conjunctive gate at the A1 offense ceiling) →
    :func:`_approval_gate` (the operator's standing approval that upgrades a WARDEN 'queue' to 'allow') →
    :func:`load_or_create_spine_keypair` (the stable, vault-sealed offense-spine identity) whose Ed25519
    signature over the ``ExecRecord`` bytes is the executor's ``signer``.

    Loopback scope only — the terminal is LOCAL, so the authority is scoped to ``127.0.0.1``. Never raises
    a governance-build error to the caller in a way that runs a command: a missing framework gate leaves
    ``gate=None`` (⇒ deny) rather than faking one."""
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)

    # The offense worker's own vault (audit G1): the governance key + spine key seal under it when provisioned;
    # unprovisioned (default) they are plaintext at rest — unchanged, non-bricking (mirrors build_engine).
    from vigil_core.vault import Vault
    op_vault = Vault(base / "vault")

    # Provision the SAME signed authority build_engine provisions (stable, sealed governance key under base_dir),
    # scoped to the local host. Fail-closed: if framework is unavailable, provision_authority raises and the
    # caller (the CLI verb) maps it to a clean JSON refusal — nothing runs.
    prov = provision_authority(slug=slug, scope=("127.0.0.1",), base_dir=base_dir, vault=op_vault)

    # The conjunctive gate over the signed authority at the A1 ceiling — terminal.run (A2) QUEUES under it.
    gate = _build_gate(prov, ceiling="A1")
    approval_gate = _approval_gate(gate) if gate is not None else None

    # The stable, vault-sealed offense-spine identity; its Ed25519 signature over the ExecRecord bytes is the
    # executor's signer (byte-identical to build_engine.exec_signer).
    spine_kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=op_vault)

    def exec_signer(message: bytes) -> str:
        return sign(spine_kp.private_key_b64, message)

    return TerminalRuntime(
        gate=gate, approval_gate=approval_gate, signer=exec_signer,
        view=DEFAULT_TOOL_VIEW, destructive_view=DEFAULT_DESTRUCTIVE_VIEW,
        history_path=str(base / "terminal-history.jsonl"), slug=slug,
    )


def _build_oracle(prov: Provisioned) -> Callable[[str, Any], Optional[str]]:
    """The CRUCIBLE oracle seam. The deterministic oracle re-fires over an ``oracle_context`` and a signed
    certificate's finding ref is returned ONLY on a real confirmation (else None ⇒ the claim stays a LEAD).

    AUDIT G4 — the sovereign anti-hallucination gate: the context here is the model's own
    ``analysis.extracted_info['oracle_context']`` — LLM-PROVENANCED — so it is passed with
    ``provenance="llm"`` and ``confirm_and_certify`` demotes it to a LEAD even when the oracle fires. A
    crafted-but-firing context therefore CANNOT mint a signed FACT (the exact route this gate closes).
    Minting a FACT from this seam requires REPRODUCING the finding from the ``raw_output`` argument (the
    executor-captured, non-LLM tool output) via a class translator, or a scope-gated live re-drive of the
    target — passed as ``provenance="reproduced"``/``"live_redrive"``. That reproduce-from-raw path is the
    documented follow-up (see ``oracle_adapter`` module docstring); until it lands this seam yields LEADs,
    which is the correct fail-closed disposition, not a regression of a sound FACT."""

    def oracle(raw_output: str, analysis: Any) -> Optional[str]:
        info = getattr(analysis, "extracted_info", None) or {}
        if not isinstance(info, dict):
            return None
        octx = info.get("oracle_context")
        if not isinstance(octx, dict):
            return None
        finding = {
            "check_id": str(info.get("check_id") or "finding"),
            "bug_class": str(info.get("bug_class") or octx.get("bug_class") or ""),
            "insertion_point": str(info.get("insertion_point") or ""),
            "oracle_context": octx,
        }
        try:
            # provenance="llm": the deterministic oracle still runs (the LEAD is honestly labelled with
            # what fired), but an LLM-emitted context is never signed into a FACT.
            res = confirm_and_certify(finding, engagement_slug=prov.slug, signers=prov.signers,
                                      provenance="llm")
        except Exception:  # noqa: BLE001 — an oracle/cert error confirms nothing (fail-closed)
            return None
        return res.finding_ref if getattr(res, "is_fact", False) else None

    return oracle


# ---------------------------------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------------------------------


def _prompt_ctx(state: AgentState) -> str:
    """A compact, UNTRUSTED-framed-downstream context digest for the think step (think() nonce-wraps it).
    Operator instructions (A5) ride in the SAME untrusted digest as advisory guidance — think() fences the
    whole string, and every action the model then proposes still passes the gate, so this cannot escalate."""
    ctx = (f"phase={state.phase.value} iteration={state.iteration} "
           f"facts={len(state.facts)} leads={len(state.leads)} objective={state.objective}")
    if state.operator_instructions:
        recent = " | ".join(state.operator_instructions[-5:])   # bounded; most-recent guidance wins
        ctx += f" operator_instructions={recent}"
    return ctx


def _format_priors(priors: list) -> str:
    """A compact, bounded rendering of the session's PRIOR graph context for the UNTRUSTED think digest.
    Each entry is an advisory summary from the session partition (an earlier run's finding, or this run's so
    far) — labelled ``advisory,not-facts`` so the model treats it as a lead. It authorizes nothing: every
    action the model then proposes still passes the gate, and a prior confirmed finding is re-minted a FACT
    only if THIS run's oracle re-fires. Separator-safe + length-bounded (no wallclock/rng)."""
    parts = []
    for p in priors[:8]:
        tag = "confirmed-prior" if p.get("confirmed") else "lead-prior"
        origin = str(p.get("origin", "") or "")
        sev = str(p.get("severity") or "?")[:16]
        what = str(p.get("bug_class") or p.get("title") or p.get("ref") or "?")[:48]
        ref = str(p.get("ref") or "?")[:48]
        frm = (";from=" + origin[:64]) if origin else ""
        parts.append(f"{ref}:{sev}:{what}({tag}{frm})")
    return "session_priors[advisory,not-facts]=" + " | ".join(parts)


def _read(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001 — an unreadable log source is simply empty (no detections)
        return ""
