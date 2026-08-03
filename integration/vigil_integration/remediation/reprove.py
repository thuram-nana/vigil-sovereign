"""remediation.reprove — TRUTHENOVATION A2: the CONTINUOUS RE-PROOF SERVICE.

The Verifiable-Fact foundation ships every *primitive* for continuous re-proof — a live re-drive
(:func:`prove_driver.prove_remediation`), a signed anti-rollback tick series
(:func:`attestation_log.append_tick` / :func:`attestation_log.verify_log`), and a time-bounded witness
quorum (:func:`attestation_witness.witness_attestation_head`). What was missing was the *running loop* that
fires them on a cadence: ``append_tick`` was called ONLY from tests, no daemon/scheduler existed, and
``drift --watch`` defaulted to one cycle. "Continuously re-proven" was therefore a CAPABILITY, not an
OPERATING PROPERTY. This module is the loop that turns it into one.

Each cycle :func:`run_reprove`:

  1. **RE-PROVES the corpus** — for every retained :class:`ProveTarget`, re-fire its exploit against the
     live target through the gated CRUCIBLE executor and classify the FRESH bytes into a signed four-state
     prove-certificate (REMEDIATED / STILL_VULNERABLE / INCONCLUSIVE / REFUSED). This is a REAL re-proof of
     the retained ``oracle_context`` — never a hollow tick that only makes ``verify_log`` pass. A target's
     re-proof is a pure re-run of :func:`prove_driver.prove_remediation`; the oracle over the wire bytes is
     the sole authority for the verdict.
  2. **APPENDS a witnessed tick** — :func:`attestation_log.append_tick` admits + chains that fresh cert
     (governance m-of-n signed head, append-only, high-water floor), then
     :func:`attestation_witness.witness_attestation_head` has the run's witnesses time-co-sign the NEW head.
     The witnessed checkpoint is persisted alongside the log (``witnessed.jsonl``) so the running service
     leaves durable, offline-verifiable, co-signed evidence — the whole series then verifies end-to-end.

Determinism (the load-bearing invariant): the cadence ``sleep`` is the ONLY clock in the loop and is
INJECTABLE (mirrors :func:`framework.v2.verify.drift.watch`), so tests run N cycles with a no-op sleep and
never pass real time. Nothing wallclock/rng ever enters the SIGNED tick math — ``append_tick`` chains pure
functions of the tick bytes, and every ``now`` / ``run_id`` / ``freshness_nonce`` / ``observed_time`` is a
CALLER INPUT supplied through an injectable source (``clock`` / ``run_id_fn`` / ``nonce_fn``). A production
run passes a real clock + unpredictable (``secrets``) nonces; a test passes deterministic ones, and two
identical N-cycle runs then produce identical chain digests.

FATAL-2: this module's scope pulls ONLY stdlib + ``vigil_core`` + the already-import-clean sovereign-safe
attestation modules (``attestation_log`` — whose framework re-execute is function-local — and
``attestation_witness`` — ``vigil_core``-only). The OFFENSE re-drive path (``prove_remediation`` /
``LiveHttpAdapter`` / ``framework.v2`` executor) is reached ONLY through :func:`build_live_prove_target`,
where every framework-touching import is FUNCTION-LOCAL (mirroring ``live/wiring.py:_build_spine_poster``),
so importing this module never co-loads the offense ENGINE. The load-bearing invariant is exactly that: with
``framework`` import forcibly blocked, importing this module still succeeds and ``sys.modules`` holds ZERO
``framework`` modules. (Precise nuance: the pure-python ``prove_driver`` *module* may be pulled into
``sys.modules`` transitively via ``attestation_log``'s re-execute path, but it co-loads NO ``framework``
module — so no offense engine loads. ``framework.v2`` / ``LiveHttpAdapter`` are the offense-engine surfaces,
and those are imported function-locally only.)

Signing: :func:`run_reprove` reuses the caller's governance m-of-n signers (the anchor-1
``OFFENSE_GOVERNANCE_ROLE`` authority from ``live/wiring.py:provision_authority``) — it MINTS NO KEY.

HONEST RESIDUAL (do NOT overclaim — this is a running cadence, nothing more):
  * FRESHNESS is only as current as the LAST cadence fire — "continuously re-proven" means "re-proven on a
    cadence", never "provably true at this instant".
  * it re-fires the RETAINED ``oracle_context`` corpus — soundness is bounded to what was retained; a
    weakness on a surface never captured into the corpus is out of its reach.
  * it needs the TARGETS REACHABLE — an unreachable/silent target yields STILL_VULNERABLE/INCONCLUSIVE (a
    strict run raises; a resilient daemon records the honest state), never a fabricated "still fixed".
  * witnessing inherits VF-1c's honest limit: at ``threshold==1`` a single self-witness is a time-STAMP,
    not an independence proof (equivocation is detectable, not prevented).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time as _time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Union

from vigil_core.crypto import KeyPair

# BOTH sovereign-safe (vigil_core-only at scope; attestation_log's framework re-execute is function-local),
# so importing them here never co-loads the offense engine. The offense re-drive (prove_remediation / the
# framework executor) is reached ONLY via build_live_prove_target, with function-local imports (FATAL-2).
from .attestation_log import AppendResult, append_tick
from .attestation_witness import TimedWitnessedCheckpoint, witness_attestation_head

_PathLike = Union[str, os.PathLike]

_WITNESSED_FILE = "witnessed.jsonl"


# --------------------------------------------------------------------------------------------------------
# the corpus item + per-cycle inputs
# --------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ReproveCycleInputs:
    """The caller-supplied inputs for re-proving ONE target on ONE cycle. ``now`` is the run's clock reading
    (a caller input — never a wallclock read inside the signed math); ``run_id`` / ``freshness_nonce`` are
    the per-cycle fresh values folded into the prove-cert so each re-proof has a distinct digest."""
    finding_id: str
    cycle: int
    now: int
    run_id: str
    freshness_nonce: str


@dataclass
class ProveTarget:
    """One retained corpus item to RE-PROVE each cycle. ``prove`` re-fires the retained exploit against the
    live target and returns a FRESH signed four-state prove-cert dict (the same shape ``append_tick`` admits).
    It is a callable, not a stored cert, precisely so each cycle earns a NEW verdict over FRESH bytes — the
    tick is a real re-proof, never a replay. Built for a live HTTP target by :func:`build_live_prove_target`."""
    finding_id: str
    prove: Callable[[ReproveCycleInputs], dict]


# --------------------------------------------------------------------------------------------------------
# the service config + results
# --------------------------------------------------------------------------------------------------------
@dataclass
class ReproveConfig:
    """Everything the re-proof loop needs. ``signers`` / ``trust_root`` / ``signer_pubkeys`` are the ONE
    governance authority (``provision_authority``) — reused, never re-minted. ``witnesses`` is the list of
    ``(KeyPair, key_id)`` that time-co-sign each new head (at ``threshold==1`` the honest single self-witness;
    a strict-majority quorum for real independence). Empty ⇒ ticks are appended UN-witnessed (honestly)."""
    log_dir: _PathLike
    engagement_slug: str
    signers: "list[tuple[str, str]]"
    trust_root: Any
    signer_pubkeys: "dict[str, str]"
    corpus: "list[ProveTarget]"
    witnesses: "list[tuple[KeyPair, str]]" = field(default_factory=list)
    run_id_prefix: str = "reprove"


@dataclass
class ReproveTick:
    """One appended re-proof tick: its cycle, the re-proved finding, the :class:`AppendResult` (state + seq +
    the new governance-signed head), and the witnessed checkpoint over that head (``None`` if un-witnessed)."""
    cycle: int
    finding_id: str
    append: AppendResult
    witnessed: Optional[TimedWitnessedCheckpoint]


@dataclass
class ReproveResult:
    """The outcome of a :func:`run_reprove` invocation: every appended tick, and the number of cycles run."""
    ticks: "list[ReproveTick]"
    cycles_run: int


# --------------------------------------------------------------------------------------------------------
# default injectable sources — a production run uses these; a test injects deterministic ones
# --------------------------------------------------------------------------------------------------------
def _wall_clock() -> int:
    """The DEFAULT clock: civil seconds. A caller input to the cert/witness (never the signed chain's clock);
    a test injects a deterministic clock so no real time passes."""
    return int(_time.time())


def _default_run_id(prefix: str, finding_id: str, cycle: int) -> str:
    """A stable, human-legible run id per (finding, cycle). Deterministic by design — the DISTINCTNESS across
    cycles comes from ``cycle``; unpredictability (where it matters) rides the freshness nonce below."""
    return f"{prefix}-{finding_id}-c{cycle}"


def _default_nonce(finding_id: str, cycle: int) -> str:
    """The DEFAULT freshness nonce: UNPREDICTABLE (``secrets``) so a hostile target cannot precompute the
    challenge echo — the correct production behaviour (a caller INPUT, explicitly not part of the signed
    chain math). A determinism test injects a deterministic ``nonce_fn`` instead."""
    return "rn-" + secrets.token_hex(16)


def deterministic_nonce(finding_id: str, cycle: int) -> str:
    """A DETERMINISTIC freshness nonce derived purely from (finding, cycle) — for tests / reproducible
    demos. Distinct per cycle, identical across two identical runs, so the whole tick series re-derives to
    identical chain digests. NEVER use in production (a predictable challenge lets a target precompute)."""
    return "rn-" + hashlib.sha256(f"{finding_id}|{cycle}".encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------------------------------------
def run_reprove(
    config: ReproveConfig,
    *,
    cycles: Optional[int] = None,
    interval: float = 0.0,
    sleep: Callable[[float], None] = _time.sleep,
    clock: Callable[[], int] = _wall_clock,
    run_id_fn: Optional[Callable[[str, int], str]] = None,
    nonce_fn: Callable[[str, int], str] = _default_nonce,
    on_cycle: Optional[Callable[[int, "list[ReproveTick]"], None]] = None,
) -> ReproveResult:
    """Run the continuous re-proof loop over ``config.corpus``.

    Runs ``cycles`` iterations, or FOREVER when ``cycles is None`` (the ``--interval`` daemon). Each cycle
    re-proves every target, appends one witnessed tick per target, and calls ``on_cycle``. The cadence
    ``sleep(interval)`` is the ONLY clock in the loop and is INJECTABLE (a test passes a no-op so no real
    time passes — mirrors :func:`framework.v2.verify.drift.watch`). ``clock`` supplies each cycle's ``now``
    (the cert/witness time — a caller input, never read inside the signed chain math); ``run_id_fn`` /
    ``nonce_fn`` supply the per-cycle fresh values folded into each cert. Default ``nonce_fn`` is
    UNPREDICTABLE (production); inject :func:`deterministic_nonce` for a reproducible series.

    A target whose ``prove`` raises (unreachable / un-provable) propagates — the STRICT posture the
    oneshot+timer deployment wants (a failed fire is a failed timer run, retried next cadence), and the
    honest residual (targets must be reachable). Returns every appended tick + the cycle count.
    """
    rid = run_id_fn or (lambda fid, c: _default_run_id(config.run_id_prefix, fid, c))
    ticks: "list[ReproveTick]" = []
    i = 0
    while cycles is None or i < int(cycles):
        if i and interval:
            sleep(interval)                          # THE cadence clock — injectable; no real sleep in tests
        now = int(clock())                           # caller/injected input; NEVER the signed chain's clock
        cycle_ticks = _run_cycle(config, i, now, rid, nonce_fn)
        ticks.extend(cycle_ticks)
        if on_cycle is not None:
            on_cycle(i, cycle_ticks)
        i += 1
    return ReproveResult(ticks=ticks, cycles_run=i)


def _run_cycle(
    config: ReproveConfig,
    cycle: int,
    now: int,
    run_id_fn: Callable[[str, int], str],
    nonce_fn: Callable[[str, int], str],
) -> "list[ReproveTick]":
    """Re-prove every corpus target once and append one witnessed tick per target. FAIL-CLOSED at the door:
    each fresh cert is admitted by ``append_tick`` (an unauthentic re-proof never enters the chain)."""
    out: "list[ReproveTick]" = []
    for tgt in config.corpus:
        inputs = ReproveCycleInputs(
            finding_id=tgt.finding_id, cycle=cycle, now=now,
            run_id=run_id_fn(tgt.finding_id, cycle),
            freshness_nonce=nonce_fn(tgt.finding_id, cycle),
        )
        cert = tgt.prove(inputs)                     # (1) RE-PROVE — fresh four-state prove-cert over live bytes
        appended = append_tick(                      # (2) APPEND — admit + chain + governance-sign the new head
            config.log_dir, cert, engagement_slug=config.engagement_slug,
            signers=config.signers, trust_root=config.trust_root,
            signer_pubkeys=config.signer_pubkeys,
        )
        witnessed = _witness_head(config, now)       # (3) WITNESS — time-co-sign that NEW head; persist it
        out.append(ReproveTick(cycle=cycle, finding_id=tgt.finding_id, append=appended, witnessed=witnessed))
    return out


def _witness_head(config: ReproveConfig, now: int) -> Optional[TimedWitnessedCheckpoint]:
    """Have the run's witnesses time-co-sign the CURRENT persisted attestation head and persist the checkpoint
    to ``<log_dir>/witnessed.jsonl`` (append-only). ``observed_time`` for every witness is ``now`` (a caller
    input — no wallclock read in the signed math). ``None`` (a no-op) when no witnesses are configured — an
    honestly UN-witnessed tick, never a faked co-signature."""
    if not config.witnesses:
        return None
    twc = witness_attestation_head(
        config.log_dir, witnesses=config.witnesses,
        observed_times=[int(now)] * len(config.witnesses),
    )
    _append_witnessed(config.log_dir, twc)
    return twc


def _append_witnessed(log_dir: _PathLike, twc: TimedWitnessedCheckpoint) -> None:
    """Append one witnessed checkpoint (compact, key-sorted) to the durable ``witnessed.jsonl`` sidecar
    (0600). Inert signed bytes — a crash between the tick write and this append merely leaves a tick with no
    yet-persisted witness (honest), never a torn record."""
    p = Path(log_dir) / _WITNESSED_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(twc.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n"
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def load_witnessed(log_dir: _PathLike) -> "list[TimedWitnessedCheckpoint]":
    """Load the persisted witnessed checkpoints in append order (``[]`` if none). Used by the offline
    verifier / test to confirm every tick's head was co-signed."""
    p = Path(log_dir) / _WITNESSED_FILE
    if not p.exists():
        return []
    out: "list[TimedWitnessedCheckpoint]" = []
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s:
            continue
        out.append(TimedWitnessedCheckpoint.model_validate_json(s))
    return out


# --------------------------------------------------------------------------------------------------------
# the live-HTTP corpus builder (OFFENSE — every framework/prove-driver import is FUNCTION-LOCAL, FATAL-2)
# --------------------------------------------------------------------------------------------------------
def build_live_prove_target(
    *,
    finding_id: str,
    engagement: str,
    prov: Any,
    scope_host: str,
    adapter_factory: Callable[[], Any],
    wielder: Optional[KeyPair] = None,
    original_certificate_digest: str = "sha256:orig",
    bug_class: str = "error_based_sqli",
    window_seconds: int = 3600,
    rate_limit: int = 64,
    policy: Any = None,
    pop_prefix: str = "reprove-pop",
) -> ProveTarget:
    """Wire a :class:`ProveTarget` that RE-PROVES one retained finding each cycle via
    :func:`prove_driver.prove_remediation` over a FRESH live adapter (``adapter_factory()`` builds a new
    re-drive adapter per cycle so each cycle captures fresh bytes).

    ``prov`` is the provisioned governance authority (its keypair is the trusted owner + the cert signer);
    ``scope_host`` is the chartered host the identity policy pins; ``adapter_factory`` returns a
    :class:`LiveTargetAdapter` (e.g. a :class:`LiveHttpAdapter` bound to the gated CRUCIBLE executor). The
    capability window is ``[0, now+window_seconds]`` so it is valid at the cycle's ``now`` for both a real and
    an injected clock. No key is minted for signing (``prov.signers`` is reused); the per-run wielder keypair
    is a proof-of-possession holder only.

    FATAL-2: every ``framework.v2`` / ``prove_driver`` / ``live_adapter`` import is FUNCTION-LOCAL, so
    building/importing the reprove service never co-loads the offense engine."""
    owner = prov.keypair
    wp = wielder or _new_keypair()

    def prove(inputs: ReproveCycleInputs) -> dict:
        # FATAL-2 — offense-side imports are function-local (mirror live/wiring.py:_live_redrive_fact).
        from vigil_core import (
            identity_digest, prove_wielder, sign_capability, sign_identity_attestation,
        )
        from .prove_driver import ProvePolicy, prove_remediation

        not_after = int(inputs.now) + int(window_seconds)
        ident = sign_identity_attestation(
            owner, engagement=engagement, policy={"host": [scope_host]}, not_after=not_after)
        cap = sign_capability(
            owner, engagement=engagement, identity_digest=identity_digest(ident),
            class_allowlist=[bug_class], not_before=0, not_after=not_after,
            rate_limit=rate_limit, revocation_id=f"rev-{finding_id}", audience=wp.public_key_b64)
        pop_challenge = f"{pop_prefix}-{inputs.run_id}"
        wproof = prove_wielder(wp, challenge=pop_challenge, capability=cap)
        outcome = prove_remediation(
            adapter=adapter_factory(), identity=ident, capability=cap, wielder_proof=wproof,
            trusted_owner_pubkey=owner.public_key_b64, engagement=engagement, finding_id=finding_id,
            original_certificate_digest=original_certificate_digest, signers=prov.signers,
            now=int(inputs.now), run_id=inputs.run_id, pop_challenge=pop_challenge,
            freshness_nonce=inputs.freshness_nonce, policy=policy or ProvePolicy())
        return outcome.certificate

    return ProveTarget(finding_id=finding_id, prove=prove)


def _new_keypair() -> KeyPair:
    from vigil_core import generate_keypair
    return generate_keypair()
