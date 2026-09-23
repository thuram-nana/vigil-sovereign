"""
Tests for Workstream D.2 — the OPT-IN access-control check pack.

The pack seeds the seven access-control classes (idor/bola/bfla/broken_access_control/authorization/
mass_assignment/privilege_escalation) behind an explicit ``enabled`` flag, default OFF. Coverage:

  * default-OFF: ``build_access_control_checks`` returns () unless enabled AND configured, so the pack
    is gate-neutral (never in DEFAULT_CHECKS / the library).
  * the two-identity CROSS-READ path fires the achieved-state oracle on a vulnerable target and does
    NOT fire on a correctly-authorised (403) target — for each of the six cross classes.
  * mass-assignment confirms ONLY on a real persisted state change (privileged field present AFTER but
    absent BEFORE), never on a secure app that ignores the field.
  * integration through the real AuditEngine with the seeded checks.

The oracle is the sole authority: a 403 / unchanged object fails the predicate and is never a finding.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.access_control import (
    ACCESS_CONTROL_CLASSES,
    AccessControlConfig,
    CrossAccessSpec,
    MassAssignmentCheck,
    access_control_finding,
    build_access_control_checks,
    default_cross_specs,
    parse_cross_spec,
)
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind

# The victim's distinctive object content — long enough to clear the oracle's min_len(8) guard and
# specific enough that its appearance in the attacker's response is unambiguous cross-tenant leakage.
_VICTIM_SECRET = "SECRET-BOB-INVOICE-#2-total=$9001-acct=bob@example.test"
_VICTIM_REF = "2"
_ATTACKER_OWN_REF = "1"   # the attacker's OWN object — the mandatory negative control
_REF_PARAM = "id"


def _requested_id(req: HttpRequest) -> str:
    return (parse_qs(urlsplit(req.url).query).get(_REF_PARAM) or [""])[0]


def _make_cross_target(vulnerable: bool):
    """Return ``(attacker_send, victim_send, nocred_send)`` for a two-identity object endpoint. The victim
    (authenticated as bob) always sees its own object (ground truth). The attacker (authenticated as a
    DIFFERENT user) sees it too iff the app has broken object-level authz; a secure app returns 403. The
    no-credential (logged-out) baseline is ALWAYS denied — the content is authentication-GATED, so a genuine
    cross-read is the attacker's UNAUTHORIZED access, not public data."""

    def victim_send(req: HttpRequest) -> dict:
        # bob's own session: he legitimately sees object 2.
        return {"status": 200, "body": _VICTIM_SECRET if _requested_id(req) == _VICTIM_REF else ""}

    def attacker_send(req: HttpRequest) -> dict:
        rid = _requested_id(req)
        if rid == _VICTIM_REF and not vulnerable:
            return {"status": 403, "body": "forbidden"}
        # vulnerable: no object-level check -> alice reads bob's object 2.
        return {"status": 200, "body": _VICTIM_SECRET if rid == _VICTIM_REF else "alice's own object 1"}

    def nocred_send(req: HttpRequest) -> dict:
        # logged-out: authentication is required, so the private record is never served (proves the read
        # is authorization-gated, not public/reflected).
        return {"status": 403, "body": "forbidden — login required"}

    return attacker_send, victim_send, nocred_send


def _obj_template() -> tuple[RequestTemplate, object]:
    req = HttpRequest(method="GET", url=f"http://target.test/obj?{_REF_PARAM}=1", headers=[], body=None)
    template = RequestTemplate(req)
    point = next(p for p in template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == _REF_PARAM)
    return template, point


# --- the opt-in flag (default OFF => gate-neutral) ------------------------------------------------


def test_pack_is_off_by_default() -> None:
    _, victim_send, _ = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(
        victim_send=victim_send,
        cross_specs=default_cross_specs(victim_ref=_VICTIM_REF, victim_discriminator=_VICTIM_SECRET))
    assert build_access_control_checks(cfg, enabled=False) == ()      # flag off
    assert build_access_control_checks(None, enabled=True) == ()       # no config
    assert build_access_control_checks(cfg) == ()                      # default enabled=False


def test_enabled_pack_builds_all_seven_classes() -> None:
    _, victim_send, _ = _make_cross_target(vulnerable=True)
    ma = MassAssignmentCheck(
        id="ac-ma", field="role", privileged_value="admin",
        readback_send=lambda r: {"status": 200, "body": ""},
        readback_request=HttpRequest(method="GET", url="http://target.test/me", headers=[], body=None),
    )
    cfg = AccessControlConfig(
        victim_send=victim_send,
        cross_specs=default_cross_specs(victim_ref=_VICTIM_REF, victim_discriminator=_VICTIM_SECRET),
        mass_assignment=ma)
    checks = build_access_control_checks(cfg, enabled=True)
    classes = {c.bug_class for c in checks}
    assert classes == set(ACCESS_CONTROL_CLASSES)                     # all seven seeded


# --- the two-identity CROSS-READ path (six classes) ----------------------------------------------


def _run_cross(bug_class: str, vulnerable: bool):
    attacker_send, victim_send, nocred_send = _make_cross_target(vulnerable)
    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class=bug_class, ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    ctx = check.probe(template, point, attacker_send)
    if ctx is None:
        return None
    return confirm_finding({"bug_class": bug_class, "title": "", "severity": "High"}, ctx)


def test_vulnerable_target_confirms_each_cross_class_via_achieved_state() -> None:
    for bc in ("idor", "bola", "bfla", "broken_access_control", "authorization", "privilege_escalation"):
        confirmed = _run_cross(bc, vulnerable=True)
        assert confirmed is not None, f"{bc} should confirm on a vulnerable target"
        assert confirmed.confirmed_by == OracleKind.ACHIEVED_STATE
        assert confirmed.bug_class == bc


def test_secure_target_confirms_nothing_for_any_cross_class() -> None:
    for bc in ("idor", "bola", "bfla", "broken_access_control", "authorization", "privilege_escalation"):
        assert _run_cross(bc, vulnerable=False) is None, f"{bc} must not fire on a 403"


# --- mass assignment (persisted state change) ----------------------------------------------------


def _make_mass_assign_target(vulnerable: bool):
    """A stateful object with a ``role`` field. A vulnerable app lets the attacker set ``role`` via
    mass assignment (it persists); a secure app ignores the extra field."""
    state = {"role": "user"}

    def _obj() -> str:
        return '{"id": 1, "name": "alice", "role": "%s"}' % state["role"]

    def mutate_send(req: HttpRequest) -> dict:
        role = (parse_qs(req.body or "").get("role") or [None])[0]
        if role and vulnerable:
            state["role"] = role          # mass assignment accepted + persisted
        return {"status": 200, "body": _obj()}

    def read_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": _obj()}

    return mutate_send, read_send


def _run_mass_assign(vulnerable: bool):
    mutate_send, read_send = _make_mass_assign_target(vulnerable)
    ma = MassAssignmentCheck(
        id="ac-mass-assignment", field="role", privileged_value="admin",
        readback_send=read_send,
        readback_request=HttpRequest(method="GET", url="http://target.test/me", headers=[], body=None),
    )
    req = HttpRequest(method="POST", url="http://target.test/me",
                      headers=[("Content-Type", "application/x-www-form-urlencoded")],
                      body="role=user&name=alice")
    template = RequestTemplate(req)
    point = next(p for p in template.insertion_points(kinds=(InsertionKind.BODY_FORM_VALUE,)) if p.name == "role")
    ctx = ma.probe(template, point, mutate_send)
    assert ctx is not None
    return confirm_finding({"bug_class": "mass_assignment", "title": "", "severity": "High"}, ctx)


def test_mass_assignment_confirms_on_a_persisted_privilege_field() -> None:
    confirmed = _run_mass_assign(vulnerable=True)
    assert confirmed is not None and confirmed.confirmed_by == OracleKind.ACHIEVED_STATE
    assert confirmed.bug_class == "mass_assignment"


def test_mass_assignment_does_not_fire_when_the_field_is_ignored() -> None:
    assert _run_mass_assign(vulnerable=False) is None


def test_mass_assignment_only_runs_on_its_field_point() -> None:
    mutate_send, read_send = _make_mass_assign_target(vulnerable=True)
    ma = MassAssignmentCheck(
        id="ac-mass-assignment", field="role", privileged_value="admin",
        readback_send=read_send,
        readback_request=HttpRequest(method="GET", url="http://target.test/me", headers=[], body=None),
    )
    req = HttpRequest(method="POST", url="http://target.test/me",
                      headers=[("Content-Type", "application/x-www-form-urlencoded")], body="name=alice")
    template = RequestTemplate(req)
    name_point = next(p for p in template.insertion_points(kinds=(InsertionKind.BODY_FORM_VALUE,)) if p.name == "name")
    assert ma.probe(template, name_point, mutate_send) is None   # not the role point -> skipped


def test_mass_assignment_write_echo_readback_does_not_confirm() -> None:
    # Soundness: the readback that proves persistence must be an AUTHORITATIVE-OWNER *view* (a safe GET),
    # never the WRITE's own echo. A readback_request configured with a mutating method (a write that merely
    # echoes the injected field back) cannot soundly prove persistence -> probe returns None, nothing mints.
    mutate_send, read_send = _make_mass_assign_target(vulnerable=True)
    ma = MassAssignmentCheck(
        id="ac-mass-assignment", field="role", privileged_value="admin",
        readback_send=read_send,
        # a POST 'readback' would be the write echo, not the owner's persisted-state view -> refused
        readback_request=HttpRequest(method="POST", url="http://target.test/me", headers=[], body="x=1"),
    )
    req = HttpRequest(method="POST", url="http://target.test/me",
                      headers=[("Content-Type", "application/x-www-form-urlencoded")],
                      body="role=user&name=alice")
    template = RequestTemplate(req)
    point = next(p for p in template.insertion_points(kinds=(InsertionKind.BODY_FORM_VALUE,)) if p.name == "role")
    assert ma.probe(template, point, mutate_send) is None   # write-echo readback -> LEAD, never a FACT


# --- integration through the real engine ---------------------------------------------------------


def test_seeded_checks_run_through_the_audit_engine() -> None:
    attacker_send, victim_send, nocred_send = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),),
    )
    checks = build_access_control_checks(cfg, enabled=True)
    engine = AuditEngine(attacker_send)
    req = HttpRequest(method="GET", url=f"http://target.test/obj?{_REF_PARAM}=1", headers=[], body=None)
    findings = engine.audit(req, checks=checks, insertion_kinds=(InsertionKind.QUERY_VALUE,))
    assert any(f.bug_class == "idor" and f.confirmed_by == OracleKind.ACHIEVED_STATE.value for f in findings)


# --- grammar: the ceremony parse of bug_class:ref_param:victim_ref[|discriminator[|control_ref]] --


def test_parse_cross_spec_backward_compatible_head() -> None:
    spec = parse_cross_spec("idor:id:2")
    assert spec is not None and spec.bug_class == "idor" and spec.ref_param == "id"
    assert spec.victim_ref == "2" and spec.victim_discriminator == "" and spec.control_ref == ""


def test_parse_cross_spec_carries_discriminator_and_control() -> None:
    spec = parse_cross_spec("bola:doc_id:2|SECRET-BOB-42|1")
    assert spec is not None and spec.bug_class == "bola" and spec.ref_param == "doc_id"
    assert spec.victim_ref == "2" and spec.victim_discriminator == "SECRET-BOB-42" and spec.control_ref == "1"


def test_parse_cross_spec_victim_ref_keeps_colons_before_the_pipe() -> None:
    spec = parse_cross_spec("idor:url:https://acme.test/u/2|acct-4021")
    assert spec is not None and spec.victim_ref == "https://acme.test/u/2"
    assert spec.victim_discriminator == "acct-4021"


def test_parse_cross_spec_rejects_unknown_class_and_bad_shape() -> None:
    assert parse_cross_spec("not_a_class:id:2|x") is None
    assert parse_cross_spec("idor:id") is None


def test_access_control_finding_shapes_the_certify_input() -> None:
    attacker_send, victim_send, nocred_send = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    ctx = check.probe(template, point, attacker_send)
    assert ctx is not None
    finding = access_control_finding(ctx, check_id="ac:idor:0", insertion_point="query:id")
    assert finding["bug_class"] == "idor" and finding["check_id"] == "ac:idor:0"
    assert "oracle_context" in finding and finding["oracle_context"].get("predicate")


# --- SOUNDNESS: the victim-unique discriminator (bola/idor were reverted once as UNSOUND) --------


def _shared_boilerplate_target():
    """A page with a large SHARED shell (nav/footer) for BOTH identities, whose only per-identity part
    is a private line. The victim's authoritative body is thus a proper substring only via its unique
    line; a naive contains(attacker_body, victim_body) would false-positive on the shell, so this is the
    exact FP the discriminator must refuse."""
    shell_head = "<html><head><title>Acme</title></head><body><nav>Home About Contact</nav><main>"
    shell_tail = "</main><footer>(c) Acme Inc. — all rights reserved — support@acme.test</footer></body></html>"

    def victim_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": shell_head + f"<p>Balance for {_VICTIM_SECRET}</p>" + shell_tail}

    def attacker_send(req: HttpRequest) -> dict:
        # The attacker gets 200 with the SAME shell but only THEIR OWN private line — never the victim's.
        return {"status": 200, "body": shell_head + "<p>Balance for alice-acct-0001</p>" + shell_tail}

    def nocred_send(req: HttpRequest) -> dict:
        return {"status": 403, "body": shell_head + "<p>login required</p>" + shell_tail}

    return attacker_send, victim_send, nocred_send


def test_shared_boilerplate_does_not_fire_the_discriminator_check() -> None:
    # Attacker never reaches the victim's unique discriminator, only the shared shell — must NOT fire.
    attacker_send, victim_send, nocred_send = _shared_boilerplate_target()
    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    ctx = check.probe(template, point, attacker_send)
    assert ctx is not None
    assert confirm_finding({"bug_class": "idor", "title": "", "severity": "High"}, ctx) is None


def test_no_discriminator_is_a_non_firing_lead_not_a_false_positive() -> None:
    # Without a victim-unique discriminator the sound check cannot fire — it emits NOTHING (a LEAD),
    # never the reverted whole-body containment false positive, even on a genuinely vulnerable target.
    attacker_send, victim_send, nocred_send = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    assert check.probe(template, point, attacker_send) is None


def test_control_ref_refutes_a_globally_present_marker() -> None:
    # A marker the operator wrongly believed unique but which is in EVERY record: with the attacker-owned
    # control_ref set, the negative control refutes it — no fire even though the string is "reached".
    global_marker = "GLOBAL-TENANT-BANNER-v3"

    def victim_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": f"acct=bob {global_marker}"}

    def attacker_send(req: HttpRequest) -> dict:
        rid = _requested_id(req)
        # every object (victim's ref AND the attacker's own ref 1) carries the global marker
        return {"status": 200, "body": f"acct={'bob' if rid == _VICTIM_REF else 'alice'} {global_marker}"}

    def nocred_send(req: HttpRequest) -> dict:
        return {"status": 403, "body": "forbidden — login required"}

    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=global_marker, control_ref="1"),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    ctx = check.probe(template, point, attacker_send)
    assert ctx is not None
    assert confirm_finding({"bug_class": "idor", "title": "", "severity": "High"}, ctx) is None


# --- MANDATORY negative control: the Wave-3.1 red-pen soundness gap (control_ref was OPTIONAL) --------


def test_boilerplate_discriminator_in_both_bodies_with_control_does_not_fire() -> None:
    # (a) The operator HONESTLY BUT WRONGLY supplies a footer/banner string as the "discriminator". It is
    # present in the victim's authoritative body AND in the attacker's OWN control body (it is global
    # boilerplate). control_ref IS supplied -> the mandatory negative control refutes it -> NO fire. This
    # is the exact shared-boilerplate false positive that caused the prior IDOR/BOLA revert.
    boilerplate = "(c) Acme Inc. — all rights reserved — support@acme.test"

    def victim_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": f"<main>bob private stuff</main><footer>{boilerplate}</footer>"}

    def attacker_send(req: HttpRequest) -> dict:
        # both the victim's ref AND the attacker's own ref render the SAME footer boilerplate
        who = "bob" if _requested_id(req) == _VICTIM_REF else "alice"
        return {"status": 200, "body": f"<main>{who} own stuff</main><footer>{boilerplate}</footer>"}

    def nocred_send(req: HttpRequest) -> dict:
        return {"status": 403, "body": "forbidden — login required"}

    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=boilerplate, control_ref=_ATTACKER_OWN_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    ctx = check.probe(template, point, attacker_send)
    assert ctx is not None
    assert confirm_finding({"bug_class": "idor", "title": "", "severity": "High"}, ctx) is None


def test_control_ref_omitted_is_a_lead_never_a_fact() -> None:
    # (b) On a GENUINELY vulnerable target (the attacker's cross-read really reaches the victim-unique
    # discriminator), OMITTING control_ref must yield NOTHING — a LEAD, never a FACT. Without the negative
    # control we cannot PROVE the marker is victim-unique rather than global boilerplate, so no false FACT
    # is constructible in this (previously supported) config. probe() returns None => nothing is minted.
    attacker_send, victim_send, nocred_send = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=_VICTIM_SECRET),),  # control_ref deliberately omitted
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    assert check.probe(template, point, attacker_send) is None    # LEAD, not a FindingContext


def test_genuine_victim_unique_discriminator_absent_from_control_fires() -> None:
    # (c) The honest true-positive: a genuinely victim-unique marker, present in the victim's authoritative
    # body and reached by the attacker's cross-read, but ABSENT from the attacker's own control object ->
    # the differential holds -> the achieved-state oracle confirms the FACT.
    attacker_send, victim_send, nocred_send = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    ctx = check.probe(template, point, attacker_send)
    assert ctx is not None
    confirmed = confirm_finding({"bug_class": "idor", "title": "", "severity": "High"}, ctx)
    assert confirmed is not None and confirmed.confirmed_by == OracleKind.ACHIEVED_STATE


# --- ROUND-2: the two surviving distinct false positives a re-red-pen found -----------------------


def test_reflected_reference_discriminator_is_a_lead_never_a_fact() -> None:
    # (a) ROUND-2 (v) ref-independence. The operator uses the OBJECT ID itself as the "discriminator" (the
    # mistake an earlier docstring blessed). A SECURED app returns 200 with a soft-deny body that merely
    # ECHOES the requested id ("Access denied for object acct-2") and reveals NO private content. The round-1
    # predicate would MINT a false FACT here: 200 + the id is in the victim's own view + the id is echoed in
    # the attacker's soft-deny + the id is absent from the attacker's (different-id) control. Ref-independence
    # refuses it — the discriminator is a substring of victim_ref, so the probe fails closed to a LEAD.
    reflected_ref = "acct-2"

    def victim_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": f"Your account {reflected_ref}: balance is private."}

    def attacker_send(req: HttpRequest) -> dict:
        # secured: a soft-deny that reflects the requested id but exposes NOTHING private
        return {"status": 200, "body": f"Access denied for object {reflected_ref} — insufficient rights."}

    def nocred_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": f"Access denied for object {reflected_ref}."}

    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=reflected_ref,
                                     victim_discriminator=reflected_ref, control_ref="acct-1"),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    req = HttpRequest(method="GET", url=f"http://target.test/obj?{_REF_PARAM}=acct-1", headers=[], body=None)
    template = RequestTemplate(req)
    point = next(p for p in template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == _REF_PARAM)
    # probe() returns None => nothing to confirm => a LEAD. No FACT is constructible from a reflected id.
    assert check.probe(template, point, attacker_send) is None


def test_public_content_reached_by_logged_out_baseline_does_not_fire() -> None:
    # (b) ROUND-2 (iv) authorization-gated. The discriminator is ref-INDEPENDENT and genuinely present, the
    # attacker reaches it, and it is ABSENT from the attacker's own control object — every round-1 clause
    # holds. But the content is PUBLIC: a no-credential (logged-out) baseline of the SAME ref ALSO returns the
    # discriminator. That is public/reflected content, not an achieved UNAUTHORIZED read, so the logged-out
    # baseline clause refuses to fire (ctx is built, but the predicate does not hold => confirm_finding None).
    public_marker = "PUBLIC-BROCHURE-TOKEN-XYZ-9001-not-actually-private"

    def victim_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": f"<p>{public_marker}</p>"}

    def attacker_send(req: HttpRequest) -> dict:
        rid = _requested_id(req)
        return {"status": 200, "body": f"<p>{public_marker}</p>" if rid == _VICTIM_REF else "<p>alice own</p>"}

    def nocred_send(req: HttpRequest) -> dict:
        # logged-out ALSO reaches the marker -> the content is public, not authorization-gated
        return {"status": 200, "body": f"<p>{public_marker}</p>"}

    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=public_marker, control_ref=_ATTACKER_OWN_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    ctx = check.probe(template, point, attacker_send)
    assert ctx is not None    # all config guards pass; only the predicate refuses (the baseline leaked)
    assert confirm_finding({"bug_class": "idor", "title": "", "severity": "High"}, ctx) is None


def test_baseline_less_config_is_a_lead_never_a_fact() -> None:
    # ROUND-2 (iv), the DOWNGRADE rule: a config that supplies NO no-credential baseline can never mint a
    # FACT — even on a genuinely vulnerable target — because 'unauthorized read' is only PROVEN by the
    # logged-out denial, never asserted. probe() returns None (a rigorous LEAD).
    attacker_send, victim_send, _ = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(   # nocred_send deliberately omitted
        victim_send=victim_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF,
                                     victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    assert check.probe(template, point, attacker_send) is None
