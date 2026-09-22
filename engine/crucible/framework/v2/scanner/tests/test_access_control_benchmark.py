"""
Wave 3.1 benchmark fixture — the two-identity access-control planted FACT + its benign twin.

The benchmark app serves two object endpoints (both DELIBERATELY unlinked from the index so the default
GET-only crawl never reaches them and `make gate` stays byte-identical):

  * /account       — PLANTED IDOR/BOLA: no object-level authz, so an attacker reading the victim's id
                     reaches the victim's UNIQUE private discriminator (its IBAN). The sound IdorCheck
                     (victim-unique discriminator + negative control) confirms it via the achieved-state
                     oracle. This is the planted FACT.
  * /account/safe  — BENIGN TWIN: object-level authz enforced (a caller reads only the account its own
                     session cookie owns). An attacker requesting the victim's id gets 403 with NO
                     discriminator, so the sound check MUST NOT fire — the negative control that proves
                     the discriminator is what confers soundness, not shared boilerplate.

The victim identity rides the SAME send with a swapped Cookie (the ceremony's second identity), and the
whole probe is GET-only (no state change, no per-action approval needed).
"""

from __future__ import annotations

import urllib.error
import urllib.request

from framework.v2.eval import benchmark_app
from framework.v2.scanner.access_control import AccessControlConfig, CrossAccessSpec, build_access_control_checks
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind

# bob's per-identity UNIQUE discriminator (present ONLY in account id=2's authoritative record).
_VICTIM_DISCRIMINATOR = "IBAN-BOB-DE89-VICTIM-UNIQUE-3704-0044-0532-0130-00"
_VICTIM_REF = "2"       # bob's account
_ATTACKER_OWN_REF = "1"  # alice's own account (the negative control)


def _send_factory(cookie: str | None = None):
    def _send(req: HttpRequest) -> dict:
        headers = dict(req.headers)
        if cookie is not None:
            headers["Cookie"] = cookie
        r = urllib.request.Request(req.url, method=req.method, headers=headers)
        if req.body is not None:
            r.data = req.body.encode("utf-8")
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (loopback)
                return {"status": resp.status, "headers": list(resp.headers.items()),
                        "body": resp.read().decode("utf-8", "replace")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "headers": list(e.headers.items()),
                    "body": e.read().decode("utf-8", "replace")}

    return _send


def _cross_spec() -> CrossAccessSpec:
    return CrossAccessSpec(bug_class="idor", ref_param="id", victim_ref=_VICTIM_REF,
                           victim_discriminator=_VICTIM_DISCRIMINATOR, control_ref=_ATTACKER_OWN_REF)


def _probe(base: str, path: str):
    # attacker = alice's session (or any identity); victim = bob's session (rides the same send + cookie)
    attacker_send = _send_factory(cookie="sess=alice-sess")
    victim_send = _send_factory(cookie="sess=bob-sess")
    cfg = AccessControlConfig(victim_send=victim_send, cross_specs=(_cross_spec(),))
    (check,) = build_access_control_checks(cfg, enabled=True)
    req = HttpRequest(method="GET", url=f"{base}{path}?id={_ATTACKER_OWN_REF}")
    template = RequestTemplate(req)
    point = next(p for p in template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "id")
    ctx = check.probe(template, point, attacker_send)
    if ctx is None:
        return None
    return confirm_finding({"bug_class": "idor", "title": "", "severity": "High"}, ctx)


def test_planted_idor_is_confirmed_a_fact() -> None:
    with benchmark_app.serve() as base:
        confirmed = _probe(base, "/account")
        assert confirmed is not None, "the planted two-identity IDOR was not confirmed"
        assert confirmed.confirmed_by == OracleKind.ACHIEVED_STATE
        assert confirmed.bug_class == "idor"


def test_benign_twin_never_fires() -> None:
    with benchmark_app.serve() as base:
        # object-level authz enforced -> the attacker gets 403, never reaches bob's IBAN -> no fire
        assert _probe(base, "/account/safe") is None, "the authz-enforcing benign twin falsely fired"
