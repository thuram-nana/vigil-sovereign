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
import hashlib
import json
import logging
import os
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

_log = logging.getLogger(__name__)

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

    # The approval gate (the WARDEN human leg). Precedence (A2): an explicit ``config.approval_authority``
    # wins (tests / an externally-managed authority); else ATTEMPT to load the operator-provisioned authority
    # persisted at ``<base>/approval-authority.json`` (PUBLIC key only — safe offense-side). If EITHER is
    # present, the HIGH-ASSURANCE per-action token path is the default: a queued offense tool is upgraded to
    # allow ONLY by a valid, single-use, owner-signed, action-bound token (never a blanket standing boolean).
    # If NEITHER is present, behaviour is EXACTLY today's — the standing-boolean ``_approval_gate`` — so the
    # default is NEVER more permissive than before. Either way a CRUCIBLE deny / tripped kill-switch is
    # PRESERVED: approval never widens scope.
    from .approval_broker import ApprovalBroker, approvals_root, load_authority
    effective_authority = config.approval_authority or load_authority(config.base_dir)
    approval_broker: Optional[ApprovalBroker] = None

    if gate is None:
        approval_gate = None
    elif effective_authority is not None:
        import time as _time
        _nonce_dir = config.approval_nonce_dir or str(base / "approval-nonces")
        if config.approval_token_source is not None:
            _token_source = config.approval_token_source        # injectable (tests)
        else:
            approval_broker = ApprovalBroker(approvals_root(config.base_dir), now=_time.time)
            _token_source = approval_broker.token_source
        approval_gate = build_approval_gate(
            gate, authority=effective_authority, ledger=NonceLedger(_nonce_dir),
            now=_time.time, token_source=_token_source,
        )
    else:
        approval_gate = _approval_gate(gate)

    # The per-action token gate is the ACTIVE authority mechanism only when an authority is provisioned AND
    # the gate wired. In that mode a queued TOOL call is routed to the token gate (the real, per-action,
    # single-use check happens at execution); it is NEVER a blanket allow of phase-escalation/fireteam.
    _token_gate_active = effective_authority is not None and approval_gate is not None

    def _bind_approval_action(tool: Any, is_terminal: bool) -> None:
        # Bind (into the broker) the EXACT action the gate will authorize, so a matching owner-signed token
        # upgrades ONLY this action. The (tool_name, target) is derived by the ONE shared executor helper
        # (``derive_gate_binding``) so it equals the gate-seen pair BYTE-FOR-BYTE; the action_digest binds the
        # args. Underivable target / non-broker mode ⇒ bind nothing ⇒ the action stays QUEUED (fail-closed).
        if approval_broker is None:
            return
        from .approval_token import ApprovalAction, action_digest
        from .executor import derive_gate_binding
        if is_terminal:
            ta = getattr(tool, "tool_args", None)
            command = ta.get("command") if isinstance(ta, dict) else None
            command = command if isinstance(command, str) else str(command or "")
            args_for_digest: Any = {"command": command}
            binding = derive_gate_binding(_TERMINAL_TOOL, args_for_digest, scope=offense_scope)
        else:
            args_for_digest = getattr(tool, "tool_args", None)
            binding = derive_gate_binding(getattr(tool, "tool_name", None), args_for_digest,
                                          scope=offense_scope)
        if binding is None:
            approval_broker.bind(None)
            return
        gtool, gtarget = binding
        act = ApprovalAction(gtool, gtarget, action_digest(gtool, gtarget, args_for_digest))
        approval_broker.bind(act, args_preview=args_for_digest)

    def run_tool(tool: Any, phase: Phase, seq: int, *, approved: bool = False) -> Any:
        _seq["n"] = seq
        kw = {"run": config.runner} if config.runner is not None else {}
        # An owner-approved offense tool executes under the approval gate (WARDEN human leg satisfied);
        # everything else under the base gate. Either way CRUCIBLE scope + the loopback pin still gate it.
        active_gate = approval_gate if (approved and approval_gate is not None) else gate

        is_terminal = (isinstance(getattr(tool, "tool_name", None), str)
                       and tool.tool_name.strip().lower() == _TERMINAL_TOOL)

        # Per-action binding (A2 §4): when the broker-backed per-action token gate is the active gate, bind
        # the action it will authorize BEFORE execution, so the gate's ``token_source()`` publishes the
        # pending request + spends only a token bound to THIS exact (tool, target, args).
        if approved and active_gate is approval_gate and approval_broker is not None:
            _bind_approval_action(tool, is_terminal)

        # T3 — AUTONOMOUS TERMINAL: the governed LOCAL terminal is a DISTINCT executor path. execute_terminal
        # REUSES the same conjunctive gate + signed ExecRecord but SKIPS network target-pinning — its allowlist
        # admits ONLY local read/inspect utilities, so egress/write/exec are impossible BY CONSTRUCTION.
        # terminal.run has NO argv builder in the network `execute` path (it would be denied as "unknown tool"),
        # so it MUST route here. It already passed authorize_edge upstream (terminal.run classifies A2 → the gate
        # QUEUES it → an owner approval is the human leg), and execute_terminal RE-authorizes it (defense in
        # depth). The engine treats a terminal record's local output as ADVISORY: it never enters oracle intake,
        # so an autonomous terminal command can never mint a FACT.
        if is_terminal:
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
        # TOKEN MODE: route a queued TOOL call to the per-action token gate (the real, per-action, single-use
        # check is re-made at execution — a queued tool with no valid token is DENIED there, never run). A
        # phase escalation / fireteam deploy is NOT re-gated by that gate, so it stays behind the operator's
        # STANDING approval (unchanged) — token mode is never MORE permissive than today for those.
        # STANDING MODE (no authority): the operator's standing approval, exactly as before.
        from ..agent.state import ActionType
        if _token_gate_active and getattr(decision, "action", None) == ActionType.USE_TOOL:
            return True
        return bool(config.owner_approves_offense)

    def checkpoint(state: AgentState, seq: int) -> Any:
        try:
            return spine.write_state(state, seq=seq, engagement=config.slug)
        except Exception:  # noqa: BLE001 — a spine outage is a recorded no-op, never fatal to the run
            return None

    # -- oracle (F2): confirm_and_certify over the retained oracle_context, PLUS the T2 live re-drive --
    def _redrive_executor_factory(base_url: str) -> Any:
        # A gated CRUCIBLE HttpExecutor bound to the SAME engagement slug the engine provisioned — its
        # charter/scope/kill-switch/budget gate chain admits ONLY the chartered hosts, so the re-drive is
        # NOT a new egress path (it rides the same signed-authority scope as the engine's own executor).
        # Framework import is LAZY here (FATAL-2): this offense-side factory never co-loads the sovereign env.
        from framework.v2.agents import HttpExecutor
        return HttpExecutor(engagement_slug=prov.slug, base_url=base_url, prompt_callback=lambda *_a: False)

    oracle = _build_oracle(prov, redrive_executor_factory=_redrive_executor_factory)

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

    # -- T3: persist the CRUCIBLE blackboard chain as inert, governance-signed bytes at end of run ---------
    def persist_spine() -> None:
        # Reuses the SAME governance signers the engine provisioned (prov.signers) — the anchor-1 m-of-n
        # authority, owner-delegatable via OFFENSE_GOVERNANCE_ROLE — so an owner delegation over that key
        # roots the persisted head. Best-effort + fail-closed (never raises into the engine's end-of-run).
        _persist_blackboard_chain(config.base_dir, config.slug, prov.signers)

    seams = EngineSeams(
        think=think_seam, gate=gate, run_tool=run_tool, oracle=oracle, attest=attest,
        checkpoint=checkpoint, detect=detect, approval=approval,
        operator_messages=operator_messages, deploy_fireteam=deploy_fireteam,
        project=graph_project, persist_spine=persist_spine,
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


def _build_oracle(
    prov: Provisioned,
    *,
    redrive_executor_factory: Optional[Callable[[str], Any]] = None,
) -> Callable[..., Optional[str]]:
    """The CRUCIBLE oracle seam. Returns a signed certificate's finding ref ONLY on a real confirmation
    (else None ⇒ the claim stays a LEAD).

    T2 — the LIVE RE-DRIVE (overclaim O2). For an ``error_based_sqli`` candidate the LLM marked
    ``exploit_succeeded``, the seam RE-DRIVES the proposed exploit against the live target through the gated
    ``redrive_executor_factory`` (a CRUCIBLE ``HttpExecutor`` bound to the engine's signed-authority slug) and
    mints a signed FACT ONLY when the ORIGINAL deterministic oracle re-fires over the TARGET'S FRESH RESPONSE
    bytes (``provenance="live_redrive"``). The LLM's proposed payload/param/endpoint is only the "where to
    look"; the fact is decided by the wire bytes alone — the model's claimed ``oracle_context`` is DISCARDED
    for the fact. A gate refusal / unreachable / silent target, an incomplete request-spec, or any other
    class falls through to the LEAD path below (fail-closed: a refusal never mints a fact).

    AUDIT G4 — the LEAD-only fallback (unchanged): the context here is the model's own
    ``analysis.extracted_info['oracle_context']`` — LLM-PROVENANCED — so it is passed with
    ``provenance="llm"`` and ``confirm_and_certify`` demotes it to a LEAD even when the oracle fires. A
    crafted-but-firing context therefore CANNOT mint a signed FACT (the exact route this gate closes)."""

    def oracle(raw_output: str, analysis: Any, *, redrive: Optional[dict] = None) -> Optional[str]:
        info = getattr(analysis, "extracted_info", None) or {}
        if not isinstance(info, dict):
            return None

        # T2 — LIVE RE-DRIVE (error_based_sqli only): a FACT from the TARGET's FRESH response bytes, NOT the
        # LLM's claimed context. Any failure/refusal/silence returns None → the claim stays a LEAD below.
        fact_ref = _live_redrive_fact(prov, redrive_executor_factory, info, redrive)
        if fact_ref:
            return fact_ref

        # LEAD-ONLY fallback (AUDIT G4): a boolean/other-class candidate, or an error_based_sqli whose live
        # re-drive did not reproduce, lands here. The deterministic oracle still runs so the LEAD is honestly
        # labelled with what fired, but an LLM-provenanced context is never signed into a FACT.
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
            res = confirm_and_certify(finding, engagement_slug=prov.slug, signers=prov.signers,
                                      provenance="llm")
        except Exception:  # noqa: BLE001 — an oracle/cert error confirms nothing (fail-closed)
            return None
        return res.finding_ref if getattr(res, "is_fact", False) else None

    return oracle


def _redrive_challenge(*parts: str) -> str:
    """A DETERMINISTIC freshness challenge for the live re-drive, derived from the request-spec (NO
    wallclock / rng), so the same candidate always re-drives with the same nonce — the determinism
    invariant. stdlib-only (FATAL-2 safe)."""
    raw = "|".join(str(p) for p in parts)
    return "vfrd" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _live_redrive_fact(
    prov: Provisioned,
    factory: Optional[Callable[[str], Any]],
    info: dict,
    redrive: Optional[dict],
) -> Optional[str]:
    """T2 — RE-DRIVE an ``error_based_sqli`` candidate against the live target through the gated
    ``HttpExecutor`` and mint a signed FACT from the TARGET's FRESH response bytes.

    Returns a signed certificate ref ONLY when EVERY condition holds: a factory is wired, a COMPLETE
    request-spec is present, the class is ``error_based_sqli``, the gated re-drive REACHES the target, and
    the ORIGINAL oracle re-fires over the freshly captured bytes. Every other path — no factory / no spec /
    wrong class / a gate REFUSAL / unreachable / silent / a cert error — returns None, so the claim stays a
    LEAD (fail-closed; a gate refusal MUST NOT mint a fact).

    Soundness: the LLM's proposed ``payload``/``param``/``endpoint`` is the "where to look" (allowed), but
    the FACT's ``oracle_context`` is the FRESH re-drive context (``TrialObservation.oracle_context``, built
    from the wire bytes) — the model's claimed ``oracle_context`` is never read here. Scope is enforced by
    the executor's own charter/scope/kill-switch chain inside ``gated_fetch`` — this opens no new egress.

    HONEST LIMIT (payload-causation): this mint re-fires the ``error_signature`` oracle over a SINGLE
    re-driven response (``control_body=None``), so it establishes "the in-charter target emitted a
    datastore-error signature on the exploit request", NOT that the payload CAUSED the error — a target that
    emits a static datastore-error banner independent of input would also mint. This is the documented limit
    of the single-response ``error_signature`` channel (shared with the base oracle, not a T2-specific
    overclaim; the fact is scoped to operator-authorized in-charter hosts). Threading a same-run benign
    differential control (the adapter already owns ``_control_url``/``run_positive_control``) to establish
    payload-causation is the disclosed hardening follow-up.

    FATAL-2: every framework-touching import is function-local (this is the offense-side re-drive path)."""
    if factory is None or not isinstance(redrive, dict):
        return None
    base_url = str(redrive.get("base_url") or "").strip()
    endpoint_path = str(redrive.get("endpoint_path") or "").strip()
    param = str(redrive.get("param") or "").strip()
    payload = str(redrive.get("payload") or "").strip()
    nonce_param = str(redrive.get("nonce_param") or "rc").strip() or "rc"
    if not (base_url and endpoint_path and param and payload):
        return None    # an incomplete request-spec cannot be honestly re-driven → LEAD (fail-closed)

    # CLASS GATE — only the error_signature channel (error_based_sqli) is re-drivable in this slice; a
    # boolean/other-class candidate stays a LEAD (unchanged). Normalize via the authoritative verifier.
    try:
        from framework.v2.verify.verifier import normalize_bug_class
        bug_class = normalize_bug_class(str(redrive.get("bug_class") or info.get("bug_class") or ""))
    except Exception:  # noqa: BLE001 — cannot normalize ⇒ cannot honestly re-drive → LEAD (fail-closed)
        return None
    if bug_class != "error_based_sqli":
        return None

    try:
        executor = factory(base_url)
    except Exception:  # noqa: BLE001 — cannot build the gated executor → LEAD (fail-closed)
        return None
    if executor is None:
        return None
    try:
        from ..remediation.live_adapter import LiveHttpAdapter
        from ..remediation.prove_driver import EffectiveAuthorization
        adapter = LiveHttpAdapter(
            executor=executor, base_url=base_url, endpoint_path=endpoint_path, param=param,
            payload=payload, nonce_param=nonce_param,
            original_firing_context={"bug_class": "error_based_sqli"}, bug_class="error_based_sqli")
        # A minimal execution envelope — LiveHttpAdapter.run_exploit_trial does not consume ``auth`` (each
        # gated_fetch is authorized by the HttpExecutor's own charter/scope chain); it is required only to
        # satisfy the LiveTargetAdapter protocol signature.
        auth = EffectiveAuthorization(
            target_identity_digest="", allowed_bug_classes=("error_based_sqli",), maximum_requests=1,
            not_before=0, expires_at=0, revocation_id="", capability_chain_digest="")
        challenge = _redrive_challenge(prov.slug, base_url, endpoint_path, param, payload)
        obs = adapter.run_exploit_trial(challenge=challenge, trial_index=0, auth=auth)
    except Exception:  # noqa: BLE001 — any re-drive/transport error is an unconfirmed claim → LEAD
        return None

    if not (getattr(obs, "reachable", False) and getattr(obs, "valid", False)):
        return None    # gate refusal / unreachable / uncapturable → LEAD (a REFUSAL never mints a fact)
    fresh_ctx = getattr(obs, "oracle_context", None)
    if not isinstance(fresh_ctx, dict) or not fresh_ctx:
        return None

    # MINT — confirm_and_certify re-fires the ORIGINAL oracle over the FRESH wire bytes; provenance=
    # "live_redrive" is the non-LLM channel the sovereign anti-hallucination gate requires for a FACT.
    finding = {
        "check_id": str(info.get("check_id") or "finding"),
        "bug_class": "error_based_sqli",
        "insertion_point": param,
        "oracle_context": fresh_ctx,     # the FRESH re-drive context — the LLM's claimed context is DISCARDED
    }
    try:
        res = confirm_and_certify(finding, engagement_slug=prov.slug, signers=prov.signers,
                                  provenance="live_redrive")
    except Exception:  # noqa: BLE001 — a cert error confirms nothing (fail-closed)
        return None
    return res.finding_ref if getattr(res, "is_fact", False) else None


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


# ---------------------------------------------------------------------------------------------------
# T3 — persist the CRUCIBLE blackboard chain as inert, offline-verifiable bytes (overclaim O9)
# ---------------------------------------------------------------------------------------------------


def _atomic_write_0600(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (tmp + os.replace) at 0600 — a crash never leaves a torn file
    (a reader sees either the complete OLD or the complete NEW bytes). Mirrors attestation_log."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp-{os.getpid()}"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover — non-POSIX; content is signed/inert, mode is best-effort
        pass


def _persist_blackboard_chain(base_dir: str, slug: str, signers: list) -> None:
    """T3 — SIGN + WRITE the CRUCIBLE blackboard chain for ``slug`` as inert bytes under ``base_dir``, so the
    public-key-only offline reader ``spine_verify.verify_blackboard_chain`` can verify it (making overclaim O9
    — "everything offline-verifiable, forever" — true for the one chain that was DB-only).

    Two files are written: ``spine-chain.json`` (the ``ChainEntry`` digests, so the head re-binds WITHOUT the
    DB) and ``spine-head.json`` (the governance-signed ``SignedChainHead``, which already binds
    ``engagement_slug``). The head is signed over EXACTLY the persisted entries with the SAME governance
    ``signers`` the engine provisioned (``prov.signers`` — owner-delegatable via OFFENSE_GOVERNANCE_ROLE).

    Deterministic: no wallclock/rng enters the signed bytes (``event_digest`` excludes ``posted_at``;
    ``sign_head`` signs the version-conditional head payload with deterministic Ed25519). The chain is written
    FIRST and the head LAST, so a reader that finds a head always finds its matching chain.

    FAIL-CLOSED + best-effort: no signers, an absent/empty engagement, or ANY build/sign/write error is
    swallowed (logged) and NOTHING partial is left — a persist failure never crashes the run; but if the files
    ARE written they are a valid, verifiable pair. FATAL-2: every ``framework``-touching import is
    function-local (this offense-side path never co-loads the sovereign env)."""
    if not signers:
        return
    try:
        # Framework imports are function-local (FATAL-2): the sovereign env never co-loads them via this module.
        from framework.v2.agents.blackboard import open_blackboard
        from framework.v2.agents.spine_chain import build_spine_chain

        # Build the chain + sign the head with vigil_core's OWN primitives (the SAME module the offline
        # verifier uses), so sign/verify are byte-symmetric independent of any framework vendoring drift. We
        # take ONLY the per-event digests from the framework (its blackboard read); the chain + head are then
        # pure vigil_core over those digests.
        from vigil_core.chain import build_chain as _vc_build_chain
        from vigil_core.chain import sign_head as _vc_sign_head

        bb = open_blackboard()
        try:
            # The FULL, in-id-order chain over the engagement's blackboard events. Raises (caught below) when
            # the engagement was never posted to the blackboard — nothing to anchor → no artifacts (honest).
            fw_entries = build_spine_chain(bb, slug)
        finally:
            try:
                bb.close()
            except Exception:  # noqa: BLE001 — a close error must not mask a successful build
                pass
        # Rebuild the hash-linked chain over the per-event digests with vigil_core, then sign the head over
        # EXACTLY those persisted entries (not a second DB read), so head↔entries always bind for the offline
        # reader. sign_head binds engagement_slug — no cross-engagement head replay.
        entries = _vc_build_chain([e.cert_digest for e in fw_entries])
        head = _vc_sign_head(entries, engagement_slug=slug, signers=list(signers))
        chain_json = json.dumps([e.model_dump(mode="json") for e in entries],
                                sort_keys=True, separators=(",", ":"))
        head_json = head.model_dump_json()
    except Exception as exc:  # noqa: BLE001 — build/sign failure ⇒ persist nothing (best-effort, fail-closed)
        _log.warning("live.wiring.persist_blackboard_chain: build/sign failed for slug=%s: %s", slug, exc)
        return
    try:
        base = Path(base_dir)
        _atomic_write_0600(base / "spine-chain.json", chain_json)   # chain FIRST
        _atomic_write_0600(base / "spine-head.json", head_json)     # head LAST (binds the chain above)
    except Exception as exc:  # noqa: BLE001 — a write error is a best-effort miss, never fatal
        _log.warning("live.wiring.persist_blackboard_chain: write failed for slug=%s: %s", slug, exc)
        return
