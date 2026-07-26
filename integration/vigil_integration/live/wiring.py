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
from .engine import EngineSeams, VigilEngine
from .executor import execute
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

    approval_gate = _approval_gate(gate) if gate is not None else None

    def run_tool(tool: Any, phase: Phase, seq: int, *, approved: bool = False) -> Any:
        _seq["n"] = seq
        kw = {"run": config.runner} if config.runner is not None else {}
        # An owner-approved offense tool executes under the approval gate (WARDEN human leg satisfied);
        # everything else under the base gate. Either way CRUCIBLE scope + the loopback pin still gate it.
        active_gate = approval_gate if (approved and approval_gate is not None) else gate
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

    # -- think (F2) ----------------------------------------------------------------------------------
    def think_seam(state: AgentState) -> Any:
        return think(state, _prompt_ctx(state), replay=config.replay, api_key=config.api_key)

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

    seams = EngineSeams(
        think=think_seam, gate=gate, run_tool=run_tool, oracle=oracle, attest=attest,
        checkpoint=checkpoint, detect=detect, approval=approval,
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
        except Exception:  # noqa: BLE001 — killswitch unavailable ⇒ gate still built without it
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
    """A compact, UNTRUSTED-framed-downstream context digest for the think step (think() nonce-wraps it)."""
    return (f"phase={state.phase.value} iteration={state.iteration} "
            f"facts={len(state.facts)} leads={len(state.leads)} objective={state.objective}")


def _read(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001 — an unreadable log source is simply empty (no detections)
        return ""
