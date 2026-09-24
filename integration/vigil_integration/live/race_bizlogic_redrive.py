"""race_bizlogic_redrive — runner-owned, OWNER-SIGNED-spec gated re-drive → signed FACT for the Wave-4.4
race / business-logic / price-manipulation classes, both adjudicated by the ACHIEVED_STATE
``workflow_abuse_oracle``.

It extends the exact, already-reviewed ``web_redrive`` / ``runtime_redrive`` / ``access_control_redrive``
discipline — a gated, DNS-pinned, proxy-free send (the RUNNER, never a tool/LLM, crafts every probe) → the
existing deterministic oracle judges the FRESH captured bytes → one atomic evidence branch is admitted
against its declared capability → ``certify_admitted(provenance="live_redrive")`` mints a signed,
offline-re-verifiable FACT — to the OWNER-SIGNED-WORKFLOW ceremony:

  * The WorkflowSpec AST IS the operator-declared intent. It is OWNER-SIGNED (Ed25519 over the canonical
    JSON of the spec, domain-separated). :func:`verify_owner_signed_spec` re-checks that signature against
    the PINNED owner public key (resolved by the caller from the engagement's signed authority, NEVER from
    producer-controlled evidence) BEFORE any state-changing step. ``owner_signed_spec`` is set True ONLY on
    a verified signature — without it the oracle is INCONCLUSIVE, never a FACT (the FATAL-2-safe
    gated-workflow attestation the certificate binds; the engine-side oracle cannot verify Ed25519 because
    it imports no vigil_core, so the runner attests the verified fact and the certificate binds it).

  * ``request_race`` — the single-packet limit-overrun. The RUNNER fires the burst through the SAME
    fail-closed raw-socket gate (``scanner.race.raw_race`` re-gated through ``validate_action``), captures
    the RAW ``{status, body}`` of every connection, and hands them + the operator's SEMANTIC success
    predicate (from the signed spec) + ``max_allowed`` to the oracle. The verdict is COUNT-based, NEVER
    timing: the oracle RE-EVALUATES the semantic predicate over each retained response to re-derive the
    commit count and fires iff successes > max_allowed. WITHOUT a semantic success predicate an any-2xx
    count is a LEAD (a benignly-idempotent endpoint returns 2xx to every request) — never a FACT.

  * ``business_logic`` — price/parameter tampering. The tampered step's WRITE fires ONLY through the 0.3
    owner-signed per-action approval, supplied as ``mutating_send``; absent it the write never happens and
    the class is INCONCLUSIVE, never a false CLEAN. The runner reads the workflow's own post-state back
    (through the injected ``read_state``) and the oracle evaluates the operator's ``danger`` predicate over
    it — a correctly-priced / validating flow (the benign twin) fails the predicate (channel-confirmed
    clean).

Soundness is inherited unchanged: the raw-socket burst refuses out-of-scope / kill-switched traffic before
any byte (Wave-4.4 raw_race gate); a probe that established no channel is INCONCLUSIVE, never CLEAN; the
pure achieved-state oracle over the target's FRESH bytes — never a tool/LLM claim — decides; and the retained
``oracle_context`` re-verifies offline (``python3 -m framework.v2 verify``).

FATAL-2: every framework-touching / vigil_core import is FUNCTION-LOCAL — importing this module co-loads no
offense engine and no crypto stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

# The classes this runner mints as FACTs, each mapped to its ONE registered evidence branch. The oracle for
# both is the ACHIEVED_STATE workflow_abuse_oracle. Kept in lockstep with
# docs/capability-matrix/evidence-branches.json and wiring.py::_redrive_branch_for.
RACE_BIZLOGIC_FACT_CLASSES = ("request_race", "business_logic")

_BRANCH_FOR = {
    "request_race": "request_race.limit_overrun",
    "business_logic": "business_logic.price_manipulation",
}

# The domain tag the owner's WorkflowSpec signature is bound under — a spec signature can NEVER be replayed
# as a per-action approval, a destruction authorization, or any other signed artifact in the system.
_WORKFLOW_SPEC_DOMAIN = b"vigil-workflow-spec-v1\x00"


@dataclass
class RaceTarget:
    """One operator-declared race target from the signed WorkflowSpec: the should-be-atomic action, its
    permitted maximum, and the SEMANTIC success predicate (a pure JSON AST over ``{status, body}``) proving
    a real commit. Without ``success_predicate`` the over-count is a LEAD, never a FACT."""
    action_path: str
    max_allowed: int = 1
    count: int = 8
    body: bytes = b""
    success_predicate: Optional[dict] = None


@dataclass
class RaceBizlogicRedriveResult:
    base_url: str
    facts: list = field(default_factory=list)          # AdapterResult (is_fact), signed
    leads: list = field(default_factory=list)          # AdapterResult (channel-confirmed non-fact)
    inconclusive: list = field(default_factory=list)   # (bug_class, item) — no channel / no attestation
    admissions: list = field(default_factory=list)     # (branch, verdict, reason) — the audit trail
    branch_verdicts: dict = field(default_factory=dict)  # bug_class -> {branch: verdict}
    contexts: dict = field(default_factory=dict)       # finding_ref -> oracle_context (offline re-verify)
    owner_signed_spec: bool = False
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)


def verify_owner_signed_spec(
    spec: Any, signature_b64: str, owner_public_key_b64: str,
) -> bool:
    """True iff ``signature_b64`` is a valid Ed25519 signature by ``owner_public_key_b64`` over the
    canonical JSON of the WorkflowSpec ``spec`` (domain-separated). Fail-closed: any malformed input / bad
    key / verification failure is False, never a raise. The owner public key is PINNED by the caller (from
    the engagement's signed authority) — NEVER read from producer-controlled evidence. FATAL-2: vigil_core
    is imported FUNCTION-LOCAL."""
    try:
        from vigil_core import canonical_json, verify_one  # noqa: PLC0415
    except Exception:
        return False
    if not signature_b64 or not owner_public_key_b64:
        return False
    try:
        spec_dict = spec.model_dump(mode="json") if hasattr(spec, "model_dump") else dict(spec)
    except Exception:
        return False
    try:
        message = _WORKFLOW_SPEC_DOMAIN + canonical_json(spec_dict)
        return bool(verify_one(owner_public_key_b64, message, signature_b64))
    except Exception:
        return False


def _predicate_to_callable(predicate: "dict | None") -> "Callable[[Any, bytes], bool]":
    """Turn the operator's SEMANTIC success-predicate AST into the ``(status, body) -> bool`` callable
    ``scanner.race`` applies per response. It re-uses the SAME pure ``_eval_predicate`` the oracle uses, so
    the runner-side count and the oracle's offline re-derivation cannot diverge. A None predicate ⇒ the
    default any-2xx (a LEAD-only classification the oracle enforces)."""
    if not predicate:
        return lambda status, body: status is not None and 200 <= int(status) < 300
    from framework.v2.verify.oracles import _eval_predicate  # noqa: PLC0415

    def _sp(status: Any, body: bytes) -> bool:
        obs = {"status": status, "body": body.decode("utf-8", "replace") if isinstance(body, bytes) else body}
        try:
            hit, _ = _eval_predicate(predicate, obs)
            return bool(hit)
        except Exception:
            return False

    return _sp


def race_bizlogic_redrive(
    base_url: str,
    *,
    slug: str,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    workflow_spec: Any = None,
    spec_signature_b64: str = "",
    owner_public_key_b64: str = "",
    race_targets: "Sequence[RaceTarget]" = (),
    tamper_probes: "Sequence[Any]" = (),
    perform: "Optional[Callable[[Any, Any], Any]]" = None,
    read_state: "Optional[Callable[[], Any]]" = None,
    reset: "Optional[Callable[[], None]]" = None,
    mutating_send: "Optional[Callable[[Any, Any], Any]]" = None,
    prereq_chain: "Optional[Callable[[str], Sequence[Any]]]" = None,
    timeout: float = 8.0,
) -> RaceBizlogicRedriveResult:
    """Re-drive the owner-signed race/bizlogic ceremony against ``base_url`` and mint a signed FACT ONLY when
    the ACHIEVED_STATE ``workflow_abuse_oracle`` confirms over VIGIL's OWN live capture AND the WorkflowSpec
    was OWNER-SIGNED.

    ``workflow_spec`` + ``spec_signature_b64`` + ``owner_public_key_b64`` are verified first; on failure
    ``owner_signed_spec`` stays False and every class is INCONCLUSIVE (never a FACT). ``race_targets`` are
    the operator-declared should-be-atomic actions (each with its semantic success predicate);
    ``tamper_probes`` are ``scanner.bizlogic.TamperProbe`` instances whose WRITE fires ONLY through the 0.3
    ``mutating_send`` and whose ``danger`` predicate the oracle evaluates over the ``read_state`` post-state.
    Never raises (a probe error is recorded and what held is returned)."""
    from framework.v2.scanner.race import charter_authorize_gate, raw_race, _build_request  # noqa: PLC0415
    from framework.v2.verify.adapter import FindingContext  # noqa: PLC0415
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, branch_ids, compose  # noqa: PLC0415

    res = RaceBizlogicRedriveResult(base_url=base_url)

    refusal = _authorize(base_url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    # Verify the OWNER-SIGNED WorkflowSpec BEFORE any state-changing step. owner_signed_spec is set True
    # ONLY on a cryptographically verified signature (the FATAL-2-safe gated-workflow attestation).
    owner_signed = verify_owner_signed_spec(workflow_spec, spec_signature_b64, owner_public_key_b64) \
        if workflow_spec is not None else False
    res.owner_signed_spec = owner_signed
    if not owner_signed:
        res.notes.append("WorkflowSpec is NOT owner-signed (signature absent/invalid) — every race/bizlogic "
                         "class is INCONCLUSIVE, never a FACT")

    verifier = OracleVerifier()
    gate = charter_authorize_gate(slug)

    def _admit(bug_class: str, ctx: "FindingContext", item: str, surface: str) -> None:
        branch = _BRANCH_FOR.get(bug_class)
        if branch is None or branch not in branch_ids():
            res.notes.append(f"branch for {bug_class!r} not registered — cannot admit (fail-closed)")
            return
        context = ctx.to_verifier_context()
        result = verifier.confirm(context)
        signal = result.signals[0] if result.signals else None
        fired = bool(signal and signal.fired)
        conclusive = bool(signal and signal.conclusive)
        # The observed keys are what the branch's declared preconditions read: `channel_established` and
        # `owner_signed_workflow_spec` (the runner's verified attestation). owner_signed False fails the
        # precondition ⇒ INCONCLUSIVE (never a FACT), which is exactly the "no owner-signed ⇒ INCONCLUSIVE".
        observed = {"channel_established": True, "owner_signed_workflow_spec": owner_signed,
                    "gate_authorized": True}
        finding = {"check_id": f"rb:{bug_class}:{item}#{branch}", "bug_class": bug_class,
                   "title": f"{bug_class} via owner-signed workflow re-drive", "surface": surface,
                   "summary": (signal.evidence if signal else "no oracle signal"),
                   # the RETAINED context certify_admitted re-fires the oracle over (offline re-verifiable).
                   "oracle_context": context}
        admitted = admit(branch, fired=fired, conclusive=conclusive, observed=observed)
        res.admissions.append((branch, admitted.verdict.value, admitted.reason))
        bm = res.branch_verdicts.setdefault(bug_class, {})
        prior = bm.get(branch)
        bm[branch] = compose([prior, admitted.verdict.value]).value if prior else admitted.verdict.value
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="live_redrive")
        res.contexts[r.finding_ref] = context
        if r.is_fact:
            res.facts.append(r)
        elif admitted.verdict is Verdict.INCONCLUSIVE:
            res.inconclusive.append((bug_class, f"{item}#{branch}"))
        else:
            res.leads.append(r)

    # -- the RACE bursts (request_race) — the RUNNER fires the gated raw-socket burst -----------------
    from urllib.parse import urlsplit, urljoin  # noqa: PLC0415
    sp = urlsplit(base_url)
    host = sp.hostname or "127.0.0.1"
    port = sp.port or (80 if sp.scheme != "https" else 443)
    for target in race_targets:
        action_path = getattr(target, "action_path", "")
        if not action_path:
            continue
        target_url = urljoin(base_url if base_url.endswith("/") else base_url + "/", action_path.lstrip("/"))
        request_bytes = _build_request(host, port, action_path, body=getattr(target, "body", b"") or b"")
        try:
            outcomes = raw_race(host, port, request_bytes, int(getattr(target, "count", 8)),
                                timeout=timeout, authorize=gate, target_url=target_url)
        except Exception as e:  # noqa: BLE001 — a refused / errored burst never fabricates a FACT
            res.notes.append(f"request_race burst error [{action_path}]: {type(e).__name__}: {e}")
            continue
        if not outcomes:
            res.inconclusive.append(("request_race", f"{action_path} (no channel)"))
            continue
        responses = [{"status": status, "body": body} for status, body, _ in outcomes]
        ctx = FindingContext.from_race_burst(
            responses, max_allowed=int(getattr(target, "max_allowed", 1)),
            owner_signed_spec=owner_signed,
            success_predicate=getattr(target, "success_predicate", None),
            bug_class="request_race")
        _admit("request_race", ctx, f"race:{action_path}", f"POST {action_path}")

    # -- the TAMPER probes (business_logic) — WRITE only through the 0.3-gated mutating_send ----------
    if tamper_probes:
        if perform is None or read_state is None:
            res.inconclusive.append(("business_logic", "no perform/read_state supplied — tamper not attempted"))
            res.notes.append("business_logic: no injected perform/read_state — INCONCLUSIVE")
        elif mutating_send is None:
            # The tampered WRITE is a state change and MUST ride the 0.3 owner-signed per-action approval.
            res.inconclusive.append(("business_logic", "no 0.3 per-action write approval — write not attempted"))
            res.notes.append("business_logic: no mutating_send (0.3 approval) supplied — INCONCLUSIVE")
        else:
            _reset = reset or (lambda: None)
            for tamper in tamper_probes:
                step_name = getattr(tamper, "step", "")
                danger = getattr(tamper, "danger", None)
                overrides = getattr(tamper, "overrides", {})
                try:
                    _reset()
                    for prior in (prereq_chain(step_name) if prereq_chain else ()):
                        perform(prior, getattr(prior, "params", {}))
                    # The tampered WRITE rides the 0.3-gated mutating_send (owner-signed per-action approval).
                    mutating_send(step_name, overrides)
                    observed_state = read_state()
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"business_logic tamper error [{step_name}]: {type(e).__name__}: {e}")
                    res.inconclusive.append(("business_logic", f"{step_name} (probe error)"))
                    continue
                if not isinstance(observed_state, dict) and not hasattr(observed_state, "items"):
                    res.inconclusive.append(("business_logic", f"{step_name} (no post-state)"))
                    continue
                ctx = FindingContext.from_workflow_tamper(
                    dict(observed_state), dict(danger or {}), owner_signed_spec=owner_signed,
                    bug_class="business_logic")
                _admit("business_logic", ctx, f"tamper:{step_name}",
                       f"{getattr(tamper, 'label', 'tampering')} on {step_name}")

    return res
