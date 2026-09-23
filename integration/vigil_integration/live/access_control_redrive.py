"""access_control_redrive — runner-owned, two-identity gated re-drive → signed FACT for the identity/state
access-control classes (Wave 3.1): IDOR / BOLA / BFLA cross-identity reads and mass-assignment persisted
state changes, all adjudicated by the ACHIEVED_STATE predicate oracle.

It extends the exact, already-reviewed ``web_redrive`` / ``runtime_redrive`` discipline — a gated, DNS-pinned,
proxy-free send (reused verbatim: :func:`web_redrive._gated_web_send`) → the RUNNER (never a tool/LLM) crafts
every probe → the existing deterministic oracle judges the FRESH captured bytes → one atomic evidence branch is
admitted against its declared capability → ``certify_admitted(provenance="live_redrive")`` mints a signed,
offline-re-verifiable FACT — to the two-identity ceremony:

  * ``idor`` / ``bola`` / ``bfla`` — the CROSS-READ, adjudicated over FOUR distinct identities on the SAME
    gated send (swapped headers): the VICTIM/owner (owner-signed victim headers), the ATTACKER (its own
    ``attacker_headers`` — a DIFFERENT authenticated user), a THIRD authenticated-but-UNAUTHORIZED principal
    (``unauth_headers`` — a second attacker-controlled account that ALSO lacks access to the victim's object,
    the round-4 same-ref negative baseline), and NOBODY (the anonymous base send). The runner requests the
    victim's object as the attacker and fires ONLY when ALL hold: the attacker's cross-read is a SUBSTANTIVE
    SUCCESS (round-3 — a real 2xx body, not empty/error/soft-deny) that reaches a victim-UNIQUE discriminator
    present in the victim's AUTHORITATIVE (also substantive) body; that discriminator is ABSENT from the
    attacker's OWN control object AND that control read is ITSELF a substantive success (so a 404/403/empty
    control cannot vacuously satisfy the not-contains); it is REF-INDEPENDENT (never a substring of the
    requested ref); it is ABSENT from a no-credential / logged-out baseline of the SAME ref that is a VALID
    gating proof; and — decisively (round-4) — it is ABSENT from the same-ref UNAUTHORIZED-AUTHENTICATED
    baseline that is itself a valid discriminating read (a substantive 2xx that lacks it OR a genuine 401/403
    denial). That last clause is the anti-reflection proof content heuristics could not give: a per-object
    REFLECTED token echoed into an authenticated soft-deny appears in the unauthorized baseline TOO, so it
    cannot mint; only genuinely access-gated PRIVATE content (denied to a peer unauthorized principal) fires.
    This is a GET-only, non-destructive confirmation — NO per-action approval is needed. The reverted
    whole-body ``contains`` is NOT used: a shared-boilerplate page, a 403, an absent/ref-derived/reflected
    discriminator, a public body, a NON-substantive (empty/errored/denied) victim/attacker/control read, a
    missing attacker identity, or a MISSING unauthorized-authenticated baseline all keep it a LEAD, never a FACT.
  * ``mass_assignment`` — the persisted state change. The WRITE (a non-GET mutation injecting a privileged
    field) fires ONLY through the 0.3 owner-signed per-action approval, supplied as ``mutating_send``; the
    before/after readback is the AUTHORITATIVE OWNER view (a gated GET), never the attacker's write echo. Absent
    ``mutating_send`` the write never happens and the class is INCONCLUSIVE, never a false CLEAN.

Soundness is inherited unchanged: the gated send refuses out-of-scope / kill-switched traffic before any byte;
a probe that established no channel is INCONCLUSIVE, never CLEAN ("found nothing != CLEAN"); and the pure
achieved-state predicate oracle over the target's FRESH bytes — never a tool/LLM claim — decides. The retained
``oracle_context`` re-verifies offline (``python3 -m framework.v2 verify``) and ``reverify.matches_claim``
rejects tamper.

FATAL-2: every framework-touching import is FUNCTION-LOCAL — importing this module co-loads no offense engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# The classes this runner mints as FACTs, each mapped to its ONE registered evidence branch. The oracle for
# every one is the ACHIEVED_STATE predicate oracle. Kept in lockstep with
# docs/capability-matrix/evidence-branches.json and wiring.py::_redrive_branch_for.
ACCESS_CONTROL_FACT_CLASSES = ("idor", "bola", "bfla", "mass_assignment")

_BRANCH_FOR = {
    "idor": "idor.cross_identity_read",
    "bola": "bola.cross_identity_read",
    "bfla": "bfla.cross_identity_read",
    "mass_assignment": "mass_assignment.persisted_state_change",
}


@dataclass
class AccessControlRedriveResult:
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


def _url_with_param(url: str, name: str, value: str = "x") -> str:
    """``url`` guaranteed to carry a ``name`` query parameter (append if absent). Lexical only, no network."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit  # noqa: PLC0415
    sp = urlsplit(url)
    pairs = parse_qsl(sp.query, keep_blank_values=True)
    if any(k.lower() == name.lower() for k, _ in pairs):
        return url
    pairs.append((name, value))
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(pairs), sp.fragment))


def access_control_redrive(
    url: str,
    *,
    slug: str,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    cross_specs: "tuple[Any, ...]" = (),
    victim_headers: "tuple[tuple[str, str], ...]" = (),
    attacker_headers: "tuple[tuple[str, str], ...]" = (),
    unauth_headers: "tuple[tuple[str, str], ...]" = (),
    mass_assignment: Any = None,
    mutating_send: Optional[Callable[[Any], dict]] = None,
    timeout: float = 8.0,
) -> AccessControlRedriveResult:
    """Re-drive the two-identity access-control ceremony against ``url`` and mint a signed FACT ONLY when the
    achieved-state predicate oracle confirms CAUSATION over VIGIL's OWN live capture:

      * a cross-read (GET-only, no approval) fires only when the ATTACKER identity's SUBSTANTIVE cross-read
        reaches the victim's REF-INDEPENDENT UNIQUE discriminator (present in the victim's substantive record)
        that is ABSENT from the attacker's own SUBSTANTIVE control object AND from a no-credential / logged-out
        baseline of the same ref that is a valid gating proof (substantive-2xx-or-401/403); a shared-boilerplate
        page / 403 / absent or ref-derived discriminator / public (logged-out-readable) body / a non-substantive
        (empty/errored/denied) victim/attacker/control read / a vacuous 5xx baseline / missing attacker identity
        does NOT fire;
      * a mass-assignment fires only when a privileged field PERSISTED into the AUTHORITATIVE OWNER readback
        (before absent, after present), and its WRITE happens ONLY through the 0.3-gated ``mutating_send``.

    Four identities ride the SAME gated send via swapped headers (never a second, looser client): the victim
    (``victim_headers``), the attacker (``attacker_headers`` — a distinct authenticated user), the round-4
    unauthorized-authenticated principal (``unauth_headers`` — a THIRD attacker-controlled account that also
    lacks access to the victim's object), and the anonymous logged-out baseline (no headers). A cross-read
    without an ``unauth_headers`` baseline DOWNGRADES to a LEAD (the enforced round-4 boundary). A probe that
    established no channel is INCONCLUSIVE (never CLEAN). Returns an :class:`AccessControlRedriveResult`.
    Never raises (a probe error is recorded and what held is returned)."""
    from framework.v2.scanner.access_control import (  # noqa: PLC0415
        IdorCheck, access_control_finding, victim_send_with_headers)
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.oracles import predicate_oracle  # noqa: PLC0415
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from framework.v2.verify.verifier import normalize_bug_class  # noqa: PLC0415

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, branch_ids, compose  # noqa: PLC0415
    from .web_redrive import _gated_web_send  # noqa: PLC0415 — the reviewed gated, DNS-pinned, no-proxy send

    res = AccessControlRedriveResult(url=url)

    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    base_send, state = _gated_web_send(slug, timeout=timeout)
    # FOUR distinct identities ride the SAME gated executor via swapped headers:
    #   * victim  — the owner (victim_headers): the authoritative ground truth;
    #   * attacker — a DIFFERENT authenticated user (attacker_headers): the one whose cross-read must reach
    #     the victim's private marker for a BOLA;
    #   * unauth  — a THIRD authenticated-but-UNAUTHORIZED principal (unauth_headers, round-4): a second
    #     attacker-controlled account that ALSO lacks access to victim_ref. The marker's ABSENCE from its
    #     same-ref read is the DECISIVE anti-reflection proof (a per-object reflected token would appear
    #     here too). Empty ⇒ the cross-read DOWNGRADES to a LEAD (the enforced boundary);
    #   * nobody  — the anonymous base send (NO headers): the no-credential / logged-out baseline that
    #     PROVES the content is authorization-gated (round-2). If attacker_headers is empty the attacker
    #     collapses onto the anonymous baseline, so the achieved-read predicate cannot fire (a rigorous
    #     LEAD) — you cannot prove a cross-IDENTITY unauthorized read without a distinct attacker identity.
    victim_send = victim_send_with_headers(base_send, tuple(victim_headers))
    attacker_send = victim_send_with_headers(base_send, tuple(attacker_headers))
    # Round-4: the THIRD, authenticated-but-UNAUTHORIZED principal (a second attacker-controlled account that
    # also lacks access to victim_ref) rides the SAME gated send via its own swapped headers. Empty ⇒ None ⇒
    # the cross-read cannot fire (a rigorous LEAD): you cannot prove the datum is access-gated PRIVATE content
    # (vs a reflected per-object token) without a same-ref unauthorized-authenticated negative reference.
    unauth_send = victim_send_with_headers(base_send, tuple(unauth_headers)) if unauth_headers else None
    nocred_send = base_send

    def _body_unavailable_now() -> int:
        return int(state.get("body_unavailable", 0))

    def _admit_ctx(bug_class: str, ctx: Any, item: str, *, body_before: int) -> None:
        branch = _BRANCH_FOR.get(bug_class)
        if branch is None or branch not in branch_ids():
            res.notes.append(f"branch for {bug_class!r} not registered — cannot admit (fail-closed)")
            return
        context = ctx.to_verifier_context()
        signal = predicate_oracle(context.get("observed_evidence", {}), context.get("predicate", {}))
        observed = {"channel_established": True,
                    "body_semantically_available": _body_unavailable_now() <= body_before,
                    "gate_authorized": True}
        finding = access_control_finding(ctx, check_id=f"ac:{bug_class}:{item}#{branch}",
                                         insertion_point=item)
        admitted = admit(branch, fired=signal.fired, conclusive=signal.conclusive, observed=observed)
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

    # -- the GET-only cross-reads (idor / bola / bfla) --------------------------------------------------
    for spec in cross_specs:
        bug_class = normalize_bug_class(getattr(spec, "bug_class", ""))
        if bug_class not in ("idor", "bola", "bfla"):
            continue
        ref_param = getattr(spec, "ref_param", "")
        if not ref_param:
            continue
        probe_url = _url_with_param(url, ref_param)
        tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
        point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                      if p.name.lower() == ref_param.lower()), None)
        if point is None:
            res.notes.append(f"{bug_class}: no insertion point {ref_param!r} on {probe_url}")
            continue
        check = IdorCheck(
            id=f"ac-{bug_class}", ref_param=ref_param, victim_ref=getattr(spec, "victim_ref", ""),
            victim_send=victim_send, bug_class=bug_class,
            victim_discriminator=getattr(spec, "victim_discriminator", ""),
            control_ref=getattr(spec, "control_ref", ""),
            nocred_send=nocred_send, unauth_send=unauth_send)
        before = state["channels"]
        body_before = _body_unavailable_now()
        try:
            ctx = check.probe(tmpl, point, attacker_send)
        except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT
            res.notes.append(f"{bug_class} probe error [{ref_param}]: {type(e).__name__}: {e}")
            continue
        if state["channels"] <= before:
            res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
            continue
        if ctx is None:
            # No victim-unique discriminator (or the check declined) — a rigorous LEAD, never a false CLEAN.
            res.notes.append(f"{bug_class}: no victim-unique discriminator supplied — LEAD, not a FACT")
            continue
        _admit_ctx(bug_class, ctx, f"query:{ref_param}", body_before=body_before)

    # -- the mass-assignment WRITE (only through the 0.3-gated mutating_send) ---------------------------
    if mass_assignment is not None:
        if mutating_send is None:
            # The WRITE is non-GET and MUST ride the 0.3 owner-signed per-action approval. Without it the
            # write never happens: INCONCLUSIVE, never a false CLEAN.
            res.inconclusive.append(("mass_assignment", "no 0.3 per-action write approval — write not attempted"))
            res.notes.append("mass_assignment: no mutating_send (0.3 approval) supplied — INCONCLUSIVE")
        else:
            field_name = getattr(mass_assignment, "field", "")
            tmpl = RequestTemplate(getattr(mass_assignment, "readback_request", None)
                                   or HttpRequest(method="GET", url=url))
            # The point the mass-assignment injects is its own field; the check runs only on that point.
            write_req = getattr(mass_assignment, "readback_request", None)
            # MassAssignmentCheck renders its mutation via the point on a template it is given; here the
            # runner drives the write through the 0.3-gated mutating_send and reads back via the owner view.
            try:
                point = next((p for p in RequestTemplate(
                    HttpRequest(method="POST", url=url,
                                headers=[("Content-Type", "application/x-www-form-urlencoded")],
                                body=f"{field_name}=placeholder")).insertion_points(
                                    kinds=(InsertionKind.BODY_FORM_VALUE,))
                              if p.name == field_name), None)
                write_tmpl = RequestTemplate(
                    HttpRequest(method="POST", url=url,
                                headers=[("Content-Type", "application/x-www-form-urlencoded")],
                                body=f"{field_name}=placeholder"))
                before = state["channels"]
                body_before = _body_unavailable_now()
                ctx = mass_assignment.probe(write_tmpl, point, mutating_send) if point is not None else None
            except Exception as e:  # noqa: BLE001
                res.notes.append(f"mass_assignment probe error: {type(e).__name__}: {e}")
                ctx = None
            if ctx is None:
                res.inconclusive.append(("mass_assignment", "no persisted state change observed"))
            else:
                _admit_ctx("mass_assignment", ctx, f"body:{field_name}", body_before=body_before)
            del write_req  # only used to document the owner-view readback wiring
    return res
