"""retest_reproof — the customer RETEST live re-proof engine (offense plane, C1b completion).

The sovereign provisioner (``sigil.ui.provision.retest``) reserves an owner-signed ``CreditLaunchLease`` for ONE
finding's re-verification and publishes an owner-signed re-proof TICKET to the dedicated ``retest-reproof`` seam.
This module is the KEYLESS offense half:

  * :func:`retest_reproof_jobs_from_seam` / :class:`RetestReproofTrigger` — read every published ticket and
    PRODUCE one ``SecurityJob`` per well-formed ticket. They only produce jobs; the queue + ``jobs.runner`` stay
    the sole executor (a produced job grants NO bypass — the owner-signed lease + the verified authority are
    re-checked offense-side).
  * :func:`make_retest_reproof_worker` — the worker ``JobRunner.run_one`` invokes. It loads the VERIFIED customer
    authority, binds the host AUTHORITATIVELY from its scope, VERIFIES the ticket-carried owner-signed lease
    (owner-pinned + bound to slug/host/tenant/window + not-settled) BEFORE any traffic, then re-fires THAT
    finding's own proof against the verified host and maps the verdict. A finding is reported ``cleared`` ONLY
    when its proof DECISIVELY stops firing (R5 ``refire_reproduction`` positive evidence: every required run
    completed and NONE fired); a fire is ``still_present``; silence / timeout / an unavailable sandbox / no
    re-fireable proof / a lease that will not verify are an honest non-``cleared`` outcome — silence is NEVER a fix.
  * :func:`make_retest_reproof_runner` — plug the trigger's jobs into the SAME ``JobRunner`` the launch path uses.

FATAL-2: module scope pulls only stdlib + the pure ``vigil_core`` wire contract + the framework-free ``.model``;
every ``framework`` / offense-sibling piece (the authority load, the lease verify's owner root, the PoC re-fire,
the sandbox) is imported LAZILY inside the function that needs it, so this module is import-clean in either venv
and is driven only on the offense plane. The re-fire is DETERMINISTIC and MODEL-FREE (no gateway spend), exactly
like the R5 redpen retest; the lease is the owner-signed authorization + metering substrate, not a model grant.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from vigil_core.retest_reproof import (
    CLEARED, INCONCLUSIVE, RETEST_OUTCOME_SEAM_SUBDIR, RETEST_REPROOF_SEAM_SUBDIR, STILL_PRESENT, UNAVAILABLE,
    retest_reproof_outcome,
)

from .model import SecurityJob, _clip

Worker = Callable[[SecurityJob], dict]

#: R5 interface — resolve a finding's re-fireable PROOF recipe: ``(slug, finding_ref) -> recipe | None``. The
#: recipe is the R1 ``redpen.LensCandidate`` whose PoC produced the finding (only ``poc_command`` / ``fire_markers``
#: / ``fire_mode`` are read, duck-typed). ``None`` ⇒ this finding retained no re-fireable proof, so its re-proof is
#: INCONCLUSIVE (never 'cleared' — we only mark fixed when a real proof decisively stops firing). It must read an
#: OFFENSE-side record the engagement itself wrote — never the untrusted ticket (a forged ticket must not choose
#: the command the sandbox runs).
ProofResolver = Callable[[str, str], Any]


# ---- seam I/O (the ticket in, the outcome out) ------------------------------------------------------


def _ticket_seam_dir(base_dir: Any) -> Path:
    """The ``retest-reproof`` directory under the shared seam base — the ONE channel the sovereign publishes
    re-proof tickets to and this trigger reads (SEPARATE from the launch lease seam and the redpen-actions seam)."""
    from vigil_core.seam_base import resolve_seam_base   # framework-free (shared)
    return Path(resolve_seam_base(base_dir)) / RETEST_REPROOF_SEAM_SUBDIR


def _outcome_seam_dir(base_dir: Any) -> Path:
    """The ``retest-outcomes`` directory the worker writes inert outcomes to and the sovereign bounded-waits on."""
    from vigil_core.seam_base import resolve_seam_base
    return Path(resolve_seam_base(base_dir)) / RETEST_OUTCOME_SEAM_SUBDIR


def _write_outcome(base_dir: Any, outcome: dict) -> None:
    """Write one inert outcome to the ``retest-outcomes`` seam, keyed by its nonce (atomic rename). Total — a
    write failure is swallowed (the sovereign bounded-wait then times out to an honest 'unavailable', never a
    false 'fixed')."""
    try:
        seam = _outcome_seam_dir(base_dir)
        seam.mkdir(parents=True, exist_ok=True)
        nonce = str(outcome.get("nonce") or "")
        tmp = seam / f".{nonce}.tmp"
        tmp.write_text(json.dumps(outcome), encoding="utf-8")
        os.replace(tmp, seam / f"{nonce}.json")
    except OSError:
        return


# ---- the keyless trigger (produces jobs; never runs one) --------------------------------------------


def _job_from_ticket(ticket: dict) -> Optional[SecurityJob]:
    """Build one ``SecurityJob`` from a published re-proof ticket, fail-closed. A ticket missing a slug / host /
    org_id / finding_ref / nonce / lease is skipped (``None``). The ticket is an UNTRUSTED trigger: the authority
    (the owner-signed lease + the verified customer authority) is re-checked in the worker, so a forged ticket
    produces a job that the worker refuses before any traffic."""
    try:
        slug = _clip(ticket.get("slug"), 80)
        host = _clip(ticket.get("host"))
        org_id = _clip(ticket.get("org_id"), 64)
        nonce = _clip(ticket.get("nonce"), 128)
        ref = _clip(ticket.get("finding_ref"), 256)
        lease = ticket.get("lease")
        if not slug or not host or not org_id or not nonce or not ref or not isinstance(lease, dict):
            return None
        repo = _clip(ticket.get("repo")) or host
        extra: dict = {
            "retest_reproof": True, "nonce": nonce, "finding_ref": ref,
            "oracle_context_digest": _clip(ticket.get("oracle_context_digest"), 256),
            "bug_class": _clip(ticket.get("bug_class"), 128), "host": host, "lease": lease,
        }
        # content-addressed on (slug, nonce): a re-poll of the same ticket coalesces in the queue's permanent
        # seen-set (exactly-once); a fresh retest (new nonce) re-enqueues.
        delivery = f"retest-reproof:{slug}:{nonce}"
        return SecurityJob.normalize(source="api", repo=repo, engagement_slug=slug, tenant_id=org_id,
                                     delivery_id=delivery, extra=extra)
    except Exception:  # noqa: BLE001 — a malformed ticket is 'no job', never a crash
        return None


def retest_reproof_jobs_from_seam(base_dir: Any, *, now: Optional[float] = None) -> "list[SecurityJob]":
    """Read every published re-proof ticket on the seam under ``base_dir`` and return one ``SecurityJob`` per
    well-formed ticket. TOTAL + fail-closed: a malformed ticket is skipped, never raised; like every trigger it
    ONLY PRODUCES jobs, it never runs one. There is no master flag here — the sovereign is the gate (it writes a
    ticket only when the re-proof flag is on), and the worker re-verifies the owner-signed lease + authority, so
    an absent seam simply yields no jobs."""
    _ = time.time() if now is None else float(now)
    seam = _ticket_seam_dir(base_dir)
    out: "list[SecurityJob]" = []
    try:
        names = sorted(p for p in os.listdir(seam)) if os.path.isdir(seam) else []
    except OSError:
        return []
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            marker = json.loads((seam / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(marker, dict):
            continue
        job = _job_from_ticket(marker)
        if job is not None:
            out.append(job)
    return out


@dataclass
class RetestReproofTrigger:
    """A ``TriggerSource`` polling the ``retest-reproof`` seam: ``poll()`` returns one ``SecurityJob`` per
    well-formed ticket, or ``[]``. It PRODUCES, never executes (the queue + ``jobs.runner`` are the sole executor)."""

    base_dir: Any
    now: Optional[float] = None

    def poll(self) -> "list[SecurityJob]":
        try:
            return retest_reproof_jobs_from_seam(self.base_dir, now=self.now)
        except Exception:  # noqa: BLE001 — a flaky seam read never sinks the drain
            return []


# ---- the keyless lease verify (the offense-side authorization before any traffic) -------------------


def _verify_ticket_lease(lease_json: Any, *, slug: str, host: str, tenant: Optional[str], base_dir: Any,
                         now: float, nonce: str) -> "tuple[bool, str]":
    """Owner-pinned VERIFY + BIND of the TICKET-CARRIED lease (mirrors ``framework.v2.launch_lease``'s seam verify,
    but over the lease the ticket carries — a retest lease is NOT published to the launch seam, so an in-flight
    launch's lease for the same slug is never clobbered). Returns ``(ok, reason)``. Fail-CLOSED; never raises.
    Verifies the owner signature against OUR locally-pinned owner root (NEVER a ticket-carried trust root), binds
    engagement_slug==slug ∧ scope_host==host ∧ org_id==tenant ∧ nonce==the ticket nonce ∧ window covers ``now``,
    and refuses a lease whose (slug, nonce) is already settled/canceled (no longer a runnable capability)."""
    try:
        from framework.v2.authority.store import load_authority_root
        from vigil_core import SignedCreditLaunchLease, verify_credit_launch_lease
        from vigil_integration.live.credit_lease_broker import is_lease_settled
    except Exception as e:  # noqa: BLE001 — a missing verify/seam dependency is fail-closed
        return False, f"lease verify unavailable (fail-closed): {type(e).__name__}"
    try:
        owner_root = load_authority_root()          # OUR pinned owner key — not a ticket-carried root
    except Exception as e:  # noqa: BLE001
        return False, f"owner authority trust root unreadable (fail-closed): {type(e).__name__}"
    if owner_root is None:
        return False, "no owner authority trust root to verify the lease against (fail-closed)"
    try:
        signed = SignedCreditLaunchLease.model_validate(lease_json)
    except Exception as e:  # noqa: BLE001 — a malformed lease is a clean refusal
        return False, f"ticket lease is malformed (fail-closed): {type(e).__name__}"
    try:
        ok, reason = verify_credit_launch_lease(signed, owner_root)
    except Exception as e:  # noqa: BLE001
        return False, f"lease verify raised (fail-closed): {type(e).__name__}"
    if not ok:
        return False, f"lease does not verify under the owner key: {reason}"
    doc = signed.document
    if doc.engagement_slug != slug:
        return False, "lease engagement_slug does not match the retest engagement"
    if doc.scope_host != host:
        return False, "lease scope_host does not match the verified authority host"
    if not tenant or doc.org_id != tenant:
        return False, "lease org_id does not match this process tenant"
    if str(getattr(doc, "nonce", "") or "") != str(nonce):
        return False, "the ticket lease belongs to a different retest than the one being run"
    try:
        nb, na = doc.not_before.timestamp(), doc.not_after.timestamp()
    except Exception as e:  # noqa: BLE001
        return False, f"lease window unreadable (fail-closed): {type(e).__name__}"
    if not (nb <= now < na):
        return False, "lease is outside its validity window"
    try:
        if is_lease_settled(base_dir, slug, doc.nonce):
            return False, "lease has been settled/canceled (no longer a runnable capability)"
    except Exception as e:  # noqa: BLE001 — FAIL-CLOSED: an unreadable settlement status refuses
        return False, f"lease settlement status unreadable (fail-closed): {type(e).__name__}"
    return True, "ok"


# ---- the worker (re-fire THAT finding's proof against the verified host) -----------------------------


def make_retest_reproof_worker(
    *,
    base_dir: Any = None,
    checkout: Callable[[SecurityJob], str],
    proof_resolver: Optional[ProofResolver] = None,
    trust_root: Any = None,
    now: Any = None,
    _load_authority: "Optional[Callable[[str], Any]]" = None,
    _sandbox: Optional[Callable[[str], Any]] = None,
    _verify_lease: "Optional[Callable[..., tuple[bool, str]]]" = None,
    _refire: Optional[Callable[..., dict]] = None,
) -> Worker:
    """Build the retest re-proof worker ``JobRunner.run_one`` invokes for a ``retest_reproof`` job. Per job it:
      1. loads the VERIFIED customer ``EngagementAuthority`` for the job's slug and binds the host AUTHORITATIVELY
         from its scope (NEVER the ticket's host) — so the re-proof can touch ONLY the org's own verified host;
      2. VERIFIES the ticket-carried owner-signed lease (owner-pinned + bound to slug/host/tenant/window/nonce +
         not settled) BEFORE any traffic — the keyless offense authorization + the metering substrate;
      3. resolves THAT finding's re-fireable proof (``proof_resolver(slug, ref)``) and re-fires it against the
         verified host (``refire_reproduction``) — DECISIVE clearance (every run completed, none fired) ⇒
         ``cleared``; a fire ⇒ ``still_present``; silence / timeout / unavailable sandbox / no recipe ⇒
         ``inconclusive`` (NEVER cleared); a lease that will not verify ⇒ ``unavailable``;
      4. writes the inert outcome to the ``retest-outcomes`` seam, keyed by the ticket nonce.

    The re-fire is deterministic + MODEL-FREE (no gateway spend). ``trust_root`` / ``_sandbox`` / ``_verify_lease``
    / ``_refire`` are offline-test seams (production uses the pinned owner root / real sandbox / real verify /
    real re-fire)."""
    def _worker(job: SecurityJob) -> dict:
        extra = job.extra or {}
        if not extra.get("retest_reproof"):
            raise ValueError("retest re-proof worker got a non-retest job (extra.retest_reproof missing)")
        ref = str(extra.get("finding_ref") or "")
        nonce = str(extra.get("nonce") or "")
        digest = str(extra.get("oracle_context_digest") or "")
        lease_json = extra.get("lease")
        if not ref or not nonce or not isinstance(lease_json, dict):
            raise ValueError("retest re-proof job carries no finding_ref / nonce / lease (fail-closed)")

        def _emit(verdict: str, reason: str) -> dict:
            outcome = retest_reproof_outcome(slug=job.slug, finding_ref=ref, nonce=nonce, verdict=verdict,
                                             oracle_context_digest=digest, reason=reason, consumed_mc=0)
            _write_outcome(base_dir, outcome)
            return {"retest_reproof": True, "finding_ref": ref, "nonce": nonce, "verdict": verdict,
                    "reason": reason, "outcome": outcome}

        # 1) VERIFIED customer authority → the host is the authority's own scope host (never the ticket's).
        load_auth = _load_authority
        if load_auth is None:
            from framework.v2.authority.store import load_authority_root, load_verified_authority   # lazy (offense)
            root = trust_root if trust_root is not None else load_authority_root()
            if root is None:
                return _emit(UNAVAILABLE, "no authority trust root pinned (fail-closed)")
            load_auth = lambda s: load_verified_authority(s, root)   # noqa: E731
        try:
            authority = load_auth(job.slug)
        except Exception as e:  # noqa: BLE001 — unverifiable / absent authority ⇒ refuse (never a fix)
            return _emit(UNAVAILABLE, f"no verified authority for this engagement: {type(e).__name__}")
        if authority is None or not str(getattr(authority, "issued_by", "")).startswith("customer:"):
            return _emit(UNAVAILABLE, "no verified customer authority for this engagement (fail-closed)")
        scope = list(getattr(authority, "scope", None) or [])
        host = scope[0] if scope else ""
        if not host:
            return _emit(UNAVAILABLE, "customer authority has no scope host (fail-closed)")

        # 2) the owner-signed lease (the offense authorization + metering) — verified BEFORE any traffic.
        t = float(now) if isinstance(now, (int, float)) else time.time()
        vl = _verify_lease or _verify_ticket_lease
        ok, reason = vl(lease_json, slug=job.slug, host=host, tenant=(job.tenant_id or None),
                        base_dir=base_dir, now=t, nonce=nonce)
        if not ok:
            return _emit(UNAVAILABLE, f"retest lease did not verify: {reason}")

        # 3) re-fire THAT finding's proof against the verified host (R5 soundness) — model-free, deterministic.
        proof = proof_resolver(job.slug, ref) if proof_resolver is not None else None
        if proof is None:
            return _emit(INCONCLUSIVE, "this finding retained no re-fireable proof — cannot confirm clearance")
        refire = _refire
        if refire is None:
            from .redpen_fix import refire_reproduction as _rr   # lazy (framework-free sibling)
            refire = _rr
        root_dir = checkout(job)
        res = refire(proof, workspace=str(root_dir), sandbox=_sandbox)
        fired = res.get("fired") if isinstance(res, dict) else None
        why = (res.get("reason") if isinstance(res, dict) else "") or ""
        if fired is False:                         # STRICT positive evidence of clearance (every run clean)
            return _emit(CLEARED, why or "the finding's proof no longer fires on the verified host")
        if fired is True:
            return _emit(STILL_PRESENT, why or "the finding's proof still fires on the verified host")
        return _emit(INCONCLUSIVE, why or "the re-proof could not confirm clearance (silence is not a fix)")

    return _worker


# ---- the authorization gate + the runner assembly ---------------------------------------------------


def build_retest_reproof_gate(
    trust_root: Any = None,
    *,
    killswitch: Any = None,
    now: Any = None,
    prod_execution_enabled: "Optional[Callable[[], bool]]" = None,
) -> Callable[[SecurityJob], Any]:
    """The retest re-proof scheduling gate — a CONJUNCTION mirroring ``build_customer_launch_gate`` MINUS the
    launch-seam lease conjunct (the retest lease rides in the ticket and is verified in the worker, not on the
    launch seam): a cryptographically-VERIFIED **customer** ``EngagementAuthority`` for the slug, the K4
    production-disable flag for a ``LIVE`` target, and ``authorize_action`` (scope + window + kill-switch) over
    the authority's EXACT-host scope. The host is bound AUTHORITATIVELY from the verified authority, never from
    the ticket. Keyless, mints nothing; a None/absent root, an unverifiable / non-customer authority, or a
    flag-off LIVE target all REFUSE (``GateOutcome(False, ...)``)."""
    def _gate(job: SecurityJob) -> Any:
        from framework.v2.authority.gate import authorize_action
        from framework.v2.authority.killswitch import KillSwitch
        from framework.v2.authority.models import ActionRequest
        from framework.v2.authority.store import load_authority_root, load_verified_authority
        from vigil_core.authority import TargetEnvironment
        from vigil_core.posture import customer_prod_execution_enabled

        from .authorize import GateOutcome
        root = trust_root if trust_root is not None else load_authority_root()
        if root is None:
            return GateOutcome(False, "no authority trust root pinned — refusing (fail-closed)", "no_trust_root")
        try:
            authority = load_verified_authority(job.slug, root)
        except Exception as e:  # noqa: BLE001 — unverifiable / absent authority ⇒ refuse
            return GateOutcome(False, f"no verified authority for {job.slug!r}: {type(e).__name__}",
                               "unverified_authority")
        if authority is None:
            return GateOutcome(False, f"no verified authority for {job.slug!r}", "unverified_authority")
        if not str(getattr(authority, "issued_by", "")).startswith("customer:"):
            return GateOutcome(False, "not a customer engagement authority (issued_by != 'customer:')",
                               "not_customer")
        scope = list(getattr(authority, "scope", None) or [])
        host = scope[0] if scope else ""
        if not host:
            return GateOutcome(False, "customer authority has no scope host (fail-closed)", "no_scope_host")
        enabled = prod_execution_enabled or customer_prod_execution_enabled
        if authority.environment == TargetEnvironment.LIVE and not enabled():
            return GateOutcome(False, "production-target customer execution is disabled (K4 flag off)",
                               "prod_disabled")
        req = ActionRequest(target=host, action_kind="offense", destructive=False,
                            description=f"retest re-proof of {host} (job {job.fingerprint[:12]})")
        ks = killswitch if killswitch is not None else KillSwitch(job.slug)
        decision = authorize_action(authority, req, killswitch=ks, now=now)
        return GateOutcome(bool(decision.allowed), decision.reason or "",
                           getattr(decision, "denial_code", "") or "")
    return _gate


def make_retest_reproof_runner(
    root: "str | os.PathLike",
    *,
    base_dir: Any = None,
    checkout: Callable[[SecurityJob], str],
    proof_resolver: Optional[ProofResolver] = None,
    trust_root: Any = None,
    killswitch: Any = None,
    now: Any = None,
    prod_execution_enabled: "Optional[Callable[[], bool]]" = None,
    assert_tenant: "Optional[Callable[[], None]]" = None,
) -> Any:
    """Build the retest re-proof ``JobRunner`` (``.queue`` is the durable ``SecurityJobQueue`` at ``root``): the
    gate is :func:`build_retest_reproof_gate`, the worker :func:`make_retest_reproof_worker`. Execution is SOLELY
    via ``JobRunner.run_one`` (claim → authorize → run under the per-slug lease), reusing the queue's exactly-once
    dedup + per-slug serialization. The caller enqueues produced tickets' jobs and drives ``run_one`` / ``drain``."""
    from .queue import SecurityJobQueue
    from .runner import JobRunner

    queue = SecurityJobQueue(root)
    gate = build_retest_reproof_gate(trust_root=trust_root, killswitch=killswitch, now=now,
                                     prod_execution_enabled=prod_execution_enabled)
    worker = make_retest_reproof_worker(base_dir=base_dir, checkout=checkout, proof_resolver=proof_resolver,
                                        trust_root=trust_root, now=now)
    kwargs: "dict[str, Any]" = {"queue": queue, "gate": gate, "worker": worker}
    if assert_tenant is not None:
        kwargs["assert_tenant"] = assert_tenant
    return JobRunner(**kwargs)


__all__ = [
    "RETEST_REPROOF_SEAM_SUBDIR", "RETEST_OUTCOME_SEAM_SUBDIR",
    "CLEARED", "STILL_PRESENT", "INCONCLUSIVE", "UNAVAILABLE",
    "ProofResolver", "RetestReproofTrigger",
    "retest_reproof_jobs_from_seam", "make_retest_reproof_worker",
    "build_retest_reproof_gate", "make_retest_reproof_runner",
]
