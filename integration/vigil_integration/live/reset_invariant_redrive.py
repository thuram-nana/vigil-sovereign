"""reset_invariant_redrive — runner-owned, gated re-drive → signed FACT for the password-reset /
account-recovery token invariants (Wave 4.3): token REUSE / NON-EXPIRY, deterministic token COLLISION, and the
CROSS-USER reset token. It extends the exact, already-reviewed ``web_redrive`` / ``access_control_redrive``
discipline — a gated, DNS-pinned, proxy-free send (reused verbatim: :func:`web_redrive._gated_web_send`) → the
RUNNER (never a tool / an LLM) crafts every probe → the existing deterministic oracle judges the FRESH captured
bytes → one atomic evidence branch is admitted against its declared capability →
``certify_admitted(provenance="live_redrive")`` mints a signed, offline-re-verifiable FACT.

FACTs ONLY the invariant-FREE sub-properties (no operator intent needed to know they are wrong):

  * ``password_reset_reuse`` — VIGIL drives its OWN test account: it CONSUMES a reset token (sets the password
    to a first unique secret P1), REPLAYS the identical token to set a SECOND unique secret P2, then
    AUTHENTICATES with P2 and reads the account. Adjudicated by the ``password_reset_invariant_oracle`` via the
    P2-bound PRIVATE-READ REDUCTION — fires ONLY when the achieved read is bound to P2 (distinct from P1, reached
    WITH P2) AND the replay-set secret reaches a victim-PRIVATE datum present in the owner's read yet absent from
    a substantive same-shape unauthorized read + a no-session baseline (the REPLAY GENUINELY re-changed the
    credential, not a bare 200 nor a leftover consume-session). A single-use / expiring token mints nothing.
  * ``password_reset_collision`` — VIGIL issues independent reset requests across one or more accounts and
    captures each {token, account} pair in order; the oracle fires ONLY on a genuinely-EXPLOITABLE PREDICTABLE
    COUNTER — >=3 tokens forming an EXACT arithmetic progression (observe one, predict the next). A BYTE-IDENTICAL
    token — same account LABEL or across DIFFERENT account LABELS — is a LEAD, not a FACT: account labels are never
    proven distinct PRINCIPALS (a benign identifier-NORMALIZING generator maps 'alice'/'Alice' to ONE principal; a
    cryptographically-secure deterministic generator — Django default_token_generator, a cache-one-token app —
    repeats for one user); genuine cross-principal exploitation is the separate ``password_reset_cross_user``
    branch below. Distinct tokens mint nothing; ENTROPY is never scored (a distinct-but-weak token stays a LEAD).
  * ``password_reset_cross_user`` — REUSES the Wave-3.1 IdorCheck SAME-SHAPE private-read differential UNCHANGED
    (``scanner.checks.IdorCheck`` → the achieved_state predicate oracle), with the cross-user reset token as the
    attacker's authorization: fires ONLY when a victim-PRIVATE datum reached via the cross-user token is ABSENT
    from a substantive same-shape unauthorized read (the anti-reflection proof). This is a GET-only,
    non-destructive confirmation — NO per-action approval is needed.

The reset-link HOST-POISONING sub-property is NOT re-driven here — it routes to the EXISTING
host_header_injection web-fact re-drive, never duplicated.

Soundness is inherited unchanged: the gated send refuses out-of-scope / kill-switched traffic before any byte;
a probe that established no channel is INCONCLUSIVE, never CLEAN ("found nothing != CLEAN"); and the pure
oracle over the target's FRESH bytes — never a tool / LLM claim — decides. The retained ``oracle_context``
re-verifies offline (``python3 -m framework.v2 verify``) and ``reverify.matches_claim`` rejects tamper.

FATAL-2: every framework-touching import is FUNCTION-LOCAL — importing this module co-loads no offense engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# The classes this runner mints as FACTs, each mapped to its ONE registered evidence branch. Kept in lockstep
# with docs/capability-matrix/evidence-branches.json and wiring.py::_redrive_branch_for.
RESET_INVARIANT_FACT_CLASSES = ("password_reset_reuse", "password_reset_collision", "password_reset_cross_user")

_BRANCH_FOR = {
    "password_reset_reuse": "password_reset.token_reuse",
    "password_reset_collision": "password_reset.deterministic_collision",
    "password_reset_cross_user": "password_reset.cross_user_read",
}


@dataclass
class ResetInvariantRedriveResult:
    url: str
    facts: list = field(default_factory=list)          # AdapterResult (is_fact), signed
    leads: list = field(default_factory=list)          # AdapterResult (channel-confirmed non-fact)
    inconclusive: list = field(default_factory=list)   # (bug_class, item) — no channel / no discriminator
    admissions: list = field(default_factory=list)     # (branch, verdict, reason) — the audit trail
    branch_verdicts: dict = field(default_factory=dict)  # bug_class -> {branch: verdict}
    contexts: dict = field(default_factory=dict)       # finding_ref -> oracle_context (offline re-verify)
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)


def reset_invariant_redrive(
    url: str,
    *,
    slug: str,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    reuse_driver: Optional[Callable[[Callable[[Any], dict]], Any]] = None,
    collision_driver: Optional[Callable[[Callable[[Any], dict]], Any]] = None,
    cross_specs: "tuple[Any, ...]" = (),
    victim_headers: "tuple[tuple[str, str], ...]" = (),
    attacker_headers: "tuple[tuple[str, str], ...]" = (),
    unauth_headers: "tuple[tuple[str, str], ...]" = (),
    timeout: float = 8.0,
) -> ResetInvariantRedriveResult:
    """Re-drive the password-reset token invariants against ``url`` and mint a signed FACT ONLY when the
    deterministic oracle confirms over VIGIL's OWN live capture.

    ``reuse_driver(send)`` / ``collision_driver(send)`` are RUNNER-supplied callables that, given the gated
    ``send``, drive the app-specific recovery protocol (reset request / consume / replay / authenticated read)
    and return a :class:`~verify.adapter.FindingContext` from
    :func:`scanner.reset.confirm_password_reset_reuse` / ``confirm_password_reset_collision`` (or ``None`` when
    no channel / no tokens were established). The redrive OWNS the gate, the gated send, admission and minting;
    the driver owns only the protocol wiring. ``cross_specs`` (+ the header sets) drive the CROSS-USER token via
    the Wave-3.1 :class:`~scanner.checks.IdorCheck` cross-read UNCHANGED. A probe that established no channel is
    INCONCLUSIVE (never CLEAN). Returns a :class:`ResetInvariantRedriveResult`. Never raises (a probe error is
    recorded and what held is returned)."""
    from framework.v2.scanner.access_control import access_control_finding, victim_send_with_headers  # noqa: PLC0415
    from framework.v2.scanner.checks import IdorCheck  # noqa: PLC0415
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.scanner.reset import password_reset_finding  # noqa: PLC0415
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from framework.v2.verify.verifier import normalize_bug_class  # noqa: PLC0415

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, branch_ids, compose  # noqa: PLC0415
    from .web_redrive import _gated_web_send  # noqa: PLC0415 — the reviewed gated, DNS-pinned, no-proxy send

    res = ResetInvariantRedriveResult(url=url)

    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    base_send, state = _gated_web_send(slug, timeout=timeout)

    def _admit_ctx(bug_class: str, ctx: Any, item: str) -> None:
        branch = _BRANCH_FOR.get(bug_class)
        if branch is None or branch not in branch_ids():
            res.notes.append(f"branch for {bug_class!r} not registered — cannot admit (fail-closed)")
            return
        context = ctx.to_verifier_context()
        # Re-run the deterministic oracle over the retained context to get fired/conclusive for admission.
        signal = _oracle_over(context, bug_class)
        observed = {"channel_established": True, "gate_authorized": True}
        finding = (access_control_finding if bug_class == "password_reset_cross_user" else password_reset_finding)(
            ctx, check_id=f"reset:{bug_class}:{item}#{branch}", insertion_point=item)
        admitted = admit(branch, fired=signal[0], conclusive=signal[1], observed=observed)
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

    def _oracle_over(context: dict, bug_class: str) -> "tuple[bool, bool]":
        from framework.v2.verify import oracles  # noqa: PLC0415
        if bug_class == "password_reset_cross_user":
            sig = oracles.predicate_oracle(context.get("observed_evidence", {}), context.get("predicate", {}))
        else:
            sig = oracles.password_reset_invariant_oracle(context.get("password_reset_invariant", {}))
        return bool(sig.fired), bool(sig.conclusive)

    # -- token REUSE / NON-EXPIRY (VIGIL-owned test account) --------------------------------------------
    if reuse_driver is not None:
        before = state["channels"]
        try:
            ctx = reuse_driver(base_send)
        except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT
            res.notes.append(f"password_reset_reuse probe error: {type(e).__name__}: {e}")
            ctx = None
        if state["channels"] <= before:
            res.inconclusive.append(("password_reset_reuse", "no channel established"))
        elif ctx is None:
            res.notes.append("password_reset_reuse: driver established no reuse context — LEAD, not a FACT")
        else:
            _admit_ctx("password_reset_reuse", ctx, "reset:reuse")

    # -- deterministic token COLLISION -----------------------------------------------------------------
    if collision_driver is not None:
        before = state["channels"]
        try:
            ctx = collision_driver(base_send)
        except Exception as e:  # noqa: BLE001
            res.notes.append(f"password_reset_collision probe error: {type(e).__name__}: {e}")
            ctx = None
        if state["channels"] <= before:
            res.inconclusive.append(("password_reset_collision", "no channel established"))
        elif ctx is None:
            res.notes.append("password_reset_collision: fewer than 2 tokens captured — LEAD, not a FACT")
        else:
            _admit_ctx("password_reset_collision", ctx, "reset:collision")

    # -- CROSS-USER reset token (Wave-3.1 IdorCheck same-shape cross-read, UNCHANGED) -------------------
    victim_send = victim_send_with_headers(base_send, tuple(victim_headers))
    attacker_send = victim_send_with_headers(base_send, tuple(attacker_headers))
    unauth_send = victim_send_with_headers(base_send, tuple(unauth_headers)) if unauth_headers else None
    nocred_send = base_send
    for spec in cross_specs:
        bug_class = normalize_bug_class(getattr(spec, "bug_class", ""))
        if bug_class != "password_reset_cross_user":
            continue
        ref_param = getattr(spec, "ref_param", "")
        if not ref_param:
            continue
        probe_url = _url_with_param(url, ref_param)
        tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
        point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                      if p.name.lower() == ref_param.lower()), None)
        if point is None:
            res.notes.append(f"password_reset_cross_user: no insertion point {ref_param!r} on {probe_url}")
            continue
        check = IdorCheck(
            id="reset-cross-user", ref_param=ref_param, victim_ref=getattr(spec, "victim_ref", ""),
            victim_send=victim_send, bug_class="password_reset_cross_user",
            victim_discriminator=getattr(spec, "victim_discriminator", ""),
            control_ref=getattr(spec, "control_ref", ""),
            nocred_send=nocred_send, unauth_send=unauth_send)
        before = state["channels"]
        try:
            ctx = check.probe(tmpl, point, attacker_send)
        except Exception as e:  # noqa: BLE001
            res.notes.append(f"password_reset_cross_user probe error [{ref_param}]: {type(e).__name__}: {e}")
            continue
        if state["channels"] <= before:
            res.inconclusive.append(("password_reset_cross_user", f"{probe_url}#{point.id}"))
            continue
        if ctx is None:
            res.notes.append("password_reset_cross_user: no victim-unique discriminator supplied — LEAD, not a FACT")
            continue
        _admit_ctx("password_reset_cross_user", ctx, f"query:{ref_param}")

    return res


def _url_with_param(url: str, name: str, value: str = "x") -> str:
    """``url`` guaranteed to carry a ``name`` query parameter (append if absent). Lexical only, no network."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit  # noqa: PLC0415
    sp = urlsplit(url)
    pairs = parse_qsl(sp.query, keep_blank_values=True)
    if any(k.lower() == name.lower() for k, _ in pairs):
        return url
    pairs.append((name, value))
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(pairs), sp.fragment))
