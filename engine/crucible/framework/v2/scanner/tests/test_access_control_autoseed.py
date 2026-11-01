"""W3 autoseeder — build the AccessControlConfig from an OWNER-SIGNED test-credential roster
(config_from_signed_credentials) instead of hand-passed CLI headers.

Two properties:
  1. END-TO-END over the real benchmark + the UNCHANGED achieved-state oracle: a signed roster
     (attacker/victim/unauthorized-peer) produces a config that CONFIRMS the planted IDOR a FACT, and
     never fires on the authz-enforcing benign twin. This proves the autoseeder feeds the existing oracle
     the same sound two-identity config config_from_cli builds by hand — no oracle change.
  2. FAIL-CLOSED producer: an unverifiable / expired roster, a roster missing the mandatory victim or
     attacker identity, or no usable ref all return None (seed nothing). The victim_discriminator comes
     from the operator-provided ref, never synthesized.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from framework.v2.eval import benchmark_app
from framework.v2.scanner.access_control import (
    build_access_control_checks,
    config_from_signed_credentials,
    victim_send_with_headers,
)
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.target_credentials import (
    AccountCredential,
    CredentialHeader,
    CredentialRole,
    TargetCredentials,
    sign_target_credentials,
)

_VICTIM_DISC = "IBAN-BOB-DE89-VICTIM-UNIQUE-3704-0044-0532-0130-00"
_REF = f"idor:id:2|{_VICTIM_DISC}|1"    # bug_class:ref_param:victim_ref|discriminator|control_ref


def _base_send():
    def _send(req: HttpRequest) -> dict:
        headers = dict(req.headers)                       # honors the swapped-in identity Cookie
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


def _cred(role, cookie):
    return AccountCredential(role=role, auth_headers=[CredentialHeader(name="Cookie", value=cookie)])


def _signed_roster(**over):
    creds = over.pop("credentials", [
        _cred(CredentialRole.ATTACKER, "sess=alice-sess"),
        _cred(CredentialRole.VICTIM, "sess=bob-sess"),
        _cred(CredentialRole.UNAUTHORIZED_PEER, "sess=carol-sess"),
    ])
    doc = TargetCredentials(engagement_slug="bench", credentials=creds, **over)
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return sign_target_credentials(doc, {"owner": kp.private_key_b64}), tr


def _probe(base: str, path: str):
    base_send = _base_send()
    signed, tr = _signed_roster()
    seeded = config_from_signed_credentials(base_send, signed, tr, [_REF])
    assert seeded is not None
    # the attacker view is the campaign's own send — engage swaps the ATTACKER headers onto it, same as the
    # producer swapped the victim/peer headers into the config.
    assert seeded.attacker_headers == (("Cookie", "sess=alice-sess"),)
    attacker_send = victim_send_with_headers(base_send, seeded.attacker_headers)
    (check,) = build_access_control_checks(seeded.config, enabled=True)
    req = HttpRequest(method="GET", url=f"{base}{path}?id=1")
    template = RequestTemplate(req)
    point = next(p for p in template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "id")
    ctx = check.probe(template, point, attacker_send)
    # the discriminator came from the operator ref, not synthesized
    assert check.victim_discriminator == _VICTIM_DISC
    if ctx is None:
        return None
    return confirm_finding({"bug_class": "idor", "title": "", "severity": "High"}, ctx)


def test_signed_roster_autoseed_confirms_the_planted_idor() -> None:
    with benchmark_app.serve() as base:
        confirmed = _probe(base, "/account")
        assert confirmed is not None, "the signed-roster autoseed did not confirm the planted IDOR"
        assert confirmed.confirmed_by == OracleKind.ACHIEVED_STATE
        assert confirmed.bug_class == "idor"


def test_signed_roster_autoseed_never_fires_on_the_benign_twin() -> None:
    with benchmark_app.serve() as base:
        assert _probe(base, "/account/safe") is None, "the authz-enforcing benign twin falsely fired"


# --- fail-closed producer paths (no network) ---------------------------------------------------------

def _warns():
    msgs: list[str] = []
    return msgs, msgs.append


def test_unverifiable_roster_seeds_nothing() -> None:
    signed, tr = _signed_roster()
    other_kp = generate_keypair()
    wrong_tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=other_kp.public_key_b64)])
    msgs, on_warn = _warns()
    assert config_from_signed_credentials(_base_send(), signed, wrong_tr, [_REF], on_warn=on_warn) is None
    assert any("failed verification" in m for m in msgs)


def test_out_of_window_roster_seeds_nothing() -> None:
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    signed, tr = _signed_roster(not_before=past, not_after=past + timedelta(hours=1))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)                 # well after not_after
    assert config_from_signed_credentials(_base_send(), signed, tr, [_REF], now=now) is None
    # inside the window it DOES seed
    signed2, tr2 = _signed_roster(not_before=now - timedelta(hours=1), not_after=now + timedelta(hours=1))
    assert config_from_signed_credentials(_base_send(), signed2, tr2, [_REF], now=now) is not None


def test_missing_mandatory_identity_seeds_nothing() -> None:
    # only a victim, no attacker -> unsound two-identity experiment -> None
    signed, tr = _signed_roster(credentials=[_cred(CredentialRole.VICTIM, "sess=bob-sess")])
    msgs, on_warn = _warns()
    assert config_from_signed_credentials(_base_send(), signed, tr, [_REF], on_warn=on_warn) is None
    assert any("victim and an attacker" in m for m in msgs)


def test_no_usable_ref_seeds_nothing() -> None:
    signed, tr = _signed_roster()
    assert config_from_signed_credentials(_base_send(), signed, tr, ["not-an-access-class:x:y"]) is None


def test_load_signed_target_credentials_roundtrip_absent_and_malformed(tmp_path, monkeypatch) -> None:
    from framework.v2.common import paths as _paths
    from framework.v2.scanner.access_control import load_signed_target_credentials

    p = tmp_path / "bench.credentials.json"
    monkeypatch.setattr(_paths, "target_credentials_path", lambda slug: p)
    # absent -> None (an engagement with no roster falls back to the CLI headers)
    assert load_signed_target_credentials("bench") is None
    # a valid signed roster round-trips (parse only — verification is the caller's job)
    signed, _ = _signed_roster()
    p.write_text(signed.model_dump_json(), encoding="utf-8")
    loaded = load_signed_target_credentials("bench")
    assert loaded is not None and loaded.document.engagement_slug == "bench"
    # malformed -> None (quiet fallback, never a crash)
    p.write_text("}{ not json", encoding="utf-8")
    assert load_signed_target_credentials("bench") is None


def test_peer_absent_still_seeds_lead_capable_config() -> None:
    # no unauthorized-peer -> unauth_send is None (LEAD-only), but the config is still produced
    signed, tr = _signed_roster(credentials=[
        _cred(CredentialRole.ATTACKER, "sess=alice-sess"),
        _cred(CredentialRole.VICTIM, "sess=bob-sess")])
    seeded = config_from_signed_credentials(_base_send(), signed, tr, [_REF])
    assert seeded is not None and seeded.config.unauth_send is None
    assert seeded.config.cross_specs[0].victim_discriminator == _VICTIM_DISC
