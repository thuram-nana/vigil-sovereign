"""governor.customer_integrations — the Slack/Jira/Linear outbound DevSecOps delivery layer.

Load-bearing invariants proven here (a false-green would be a real breach):
  * FLAG-OFF INERT: VIGIL_CUSTOMER_INTEGRATIONS off ⇒ no binding written, no secret opened, no socket, no ledger.
  * ADAPTERS FORMAT + REFERENCE THE EVIDENCE CERT: each of Slack/Jira/Linear builds a create-only payload carrying
    the signed, replayable evidence-certificate reference (cert_digest + engagement_slug + oracle_context_digest).
  * CREDENTIAL CUSTODY / NO PLAINTEXT LEAK: a token rides SEALED on the spine and only ever reaches a provider in
    the AUTH HEADER — never in a binding/ledger record, never in a delivery BODY.
  * EGRESS-GATED, FAIL-CLOSED: a host that resolves internal (SSRF) and a locked vault each REFUSE with no POST and
    leave no `delivered` ledger key (a retry can still deliver).
  * IDEMPOTENT: a second delivery of the same finding to the same binding is a no-op (no duplicate issue).
  * TENANT ISOLATION: a binding/ledger is strictly its org's; another org can neither read nor trigger it.
  * FACT-ONLY: a notice/LEAD can never become a delivery.
  * OWNER-SIGNED: a forged (unsigned/attacker-signed) binding or ledger record is inert.
"""
from __future__ import annotations

import base64
import json
import tempfile

import pytest

from sigil.governor import customer_integrations as ci
from sigil.governor import integration_egress as eg
from sigil.governor.authn import signed_payload
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from vigil_core.canonical import digest_payload

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()

# A reversible fake owner-vault seal that HIDES the plaintext substring (so the no-leak test is meaningful): the
# registry stores only base64(xor(token)); the raw token never appears on the spine. Production uses AEAD seal.
_XOR = 0x5A
def _fake_seal(pt: bytes) -> bytes: return bytes(b ^ _XOR for b in pt)
def _fake_open(blob: bytes) -> bytes: return bytes(b ^ _XOR for b in blob)

_PUB = lambda host: ["93.184.216.34"]            # public → guard passes, no DNS  # noqa: E731
_INTERNAL = lambda host: ["127.0.0.1"]           # loopback → SSRF guard refuses  # noqa: E731


@pytest.fixture
def integrations_on(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_INTEGRATIONS", "1")
    yield


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(s):
    return ci.IntegrationBindingRegistry(s, owner_key=OWNER, trusted_pubkey=OP)


def _led(s):
    return ci.IntegrationDeliveryLedger(s, owner_key=OWNER, trusted_pubkey=OP)


def _finding(ref="F-1", *, slug="org_acme", digest="ocd1", sev="critical", **over):
    row = {"engagement_slug": slug, "finding_ref": ref, "oracle_context_digest": digest, "bug_class": "sqli",
           "surface": "https://acme.example/login", "severity": sev, "title": "SQLi in login",
           "summary": "Auth bypass via union select"}
    row.update(over)
    return row


def _cert(slug="org_acme", ref="F-1", **over):
    c = {"engagement_slug": slug, "finding_ref": ref, "bug_class": "sqli", "surface": "https://acme.example/login",
         "oracle_context_digest": "ocd1", "severity": "critical"}
    c.update(over)
    return c


class _Cap:
    """A capturing fake egress transport for ONE provider — records (url, headers, body) and returns a canned
    IntegrationResponse. No network."""

    def __init__(self, status=200, body_json=None):
        self.calls: list = []
        self._status = status
        self._json = body_json

    def __call__(self, method, url, *, headers, body):
        self.calls.append({"url": url, "headers": dict(headers), "body": body})
        return eg.IntegrationResponse(status=self._status, json=self._json, host="x")

    def last_body(self):
        return json.loads(self.calls[-1]["body"].decode("utf-8"))


def _slack_ok():
    return _Cap(status=200, body_json={"ok": True, "ts": "171.9"})


def _jira_ok():
    return _Cap(status=201, body_json={"key": "SEC-1"})


def _linear_ok():
    return _Cap(status=200, body_json={"data": {"issueCreate": {"success": True,
                                                                "issue": {"identifier": "ENG-1",
                                                                          "url": "https://linear.app/x/ENG-1"}}}})


def _spine_text(s) -> str:
    return "\n".join(json.dumps(getattr(r, "payload", {}), sort_keys=True, default=str) for r in s.iter_records())


# ============================================================================================================
# flag-off inert
# ============================================================================================================
def test_flag_off_is_inert_no_write_no_socket():
    s = _store()
    reg, led = _reg(s), _led(s)
    cap = _slack_ok()
    # configure refuses when off
    with pytest.raises(ci.IntegrationRefused):
        reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK, sealed_secret="x", issued_at=1.0,
                      mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    # deliver is inert: returns [] and appends nothing
    out = ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=1.0, certificate=_cert(), bindings=reg,
                                       ledger=led, transports={ci.PROVIDER_SLACK: cap}, resolver=_PUB,
                                       opener=_fake_open)
    assert out == []
    assert cap.calls == []
    assert list(s.iter_records()) == []           # byte-identical to a build without the consumer


# ============================================================================================================
# adapters format correctly + reference the evidence certificate
# ============================================================================================================
def _deliver_one_provider(cap, *, provider, configure, sev="critical"):
    s = _store()
    reg, led = _reg(s), _led(s)
    configure(reg)
    cert = _cert()
    out = ci.deliver_confirmed_finding(s, "org_acme", _finding(sev=sev), now=5.0, certificate=cert, bindings=reg,
                                       ledger=led, transports={provider: cap}, resolver=_PUB, opener=_fake_open)
    return s, led, cert, out


def test_slack_postmessage_formats_and_references_cert(integrations_on):
    cap = _slack_ok()
    def cfg(reg):
        reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                      sealed_secret=ci.seal_token("xoxb-SECRET", sealer=_fake_seal), issued_at=1.0,
                      min_severity="high", mode=ci.SLACK_POSTMESSAGE, slack_channel="C123")
    s, led, cert, out = _deliver_one_provider(cap, provider=ci.PROVIDER_SLACK, configure=cfg)
    assert [o.outcome for o in out] == [ci.OUTCOME_DELIVERED] and out[0].issue_ref == "171.9"
    body = cap.last_body()
    assert body["channel"] == "C123"
    blob = json.dumps(body)
    assert digest_payload(cert) in blob and "verify this finding yourself" in blob
    # token is in the Authorization header, never the body
    assert cap.calls[-1]["headers"]["Authorization"] == "Bearer xoxb-SECRET"
    assert "xoxb-SECRET" not in cap.calls[-1]["body"].decode("utf-8")


def test_slack_webhook_mode_secret_is_the_url_not_a_header(integrations_on):
    cap = _Cap(status=200, body_json=None)        # webhook answers with plain "ok" (json None)
    s = _store()
    reg, led = _reg(s), _led(s)
    hook = "https://hooks.slack.com/services/T000/B000/XXXXSECRET"
    reg.configure("org_acme", "hook1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token(hook, sealer=_fake_seal), issued_at=1.0, min_severity="low",
                  mode=ci.SLACK_WEBHOOK)
    out = ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=1.0, certificate=_cert(), bindings=reg,
                                       ledger=led, transports={ci.PROVIDER_SLACK: cap}, resolver=_PUB,
                                       opener=_fake_open)
    assert out[0].delivered
    # the webhook URL (secret) is the POST target, not a header or the body
    assert cap.calls[-1]["url"] == hook
    assert "XXXXSECRET" not in cap.calls[-1]["body"].decode("utf-8")
    assert "Authorization" not in cap.calls[-1]["headers"]


def test_jira_formats_adf_basic_auth_and_references_cert(integrations_on):
    cap = _jira_ok()
    def cfg(reg):
        reg.configure("org_acme", "jira1", provider=ci.PROVIDER_JIRA,
                      sealed_secret=ci.seal_token("jira-API-TOKEN", sealer=_fake_seal), issued_at=1.0,
                      min_severity="high", jira_cloud_id="abc-123", jira_project_key="SEC",
                      jira_user_email="bot@acme.example")
    s, led, cert, out = _deliver_one_provider(cap, provider=ci.PROVIDER_JIRA, configure=cfg)
    assert out[0].delivered and out[0].issue_ref == "SEC-1"
    call = cap.calls[-1]
    assert call["url"] == "https://api.atlassian.com/ex/jira/abc-123/rest/api/3/issue"
    body = cap.last_body()
    assert body["fields"]["project"]["key"] == "SEC"
    assert digest_payload(cert) in json.dumps(body["fields"]["description"])   # ADF carries the cert reference
    # Basic auth = base64(email:token); the raw token is never in the body
    scheme, b64 = call["headers"]["Authorization"].split(" ", 1)
    assert scheme == "Basic" and base64.b64decode(b64).decode() == "bot@acme.example:jira-API-TOKEN"
    assert "jira-API-TOKEN" not in call["body"].decode("utf-8")


def test_linear_formats_graphql_and_references_cert(integrations_on):
    cap = _linear_ok()
    def cfg(reg):
        reg.configure("org_acme", "lin1", provider=ci.PROVIDER_LINEAR,
                      sealed_secret=ci.seal_token("lin_api_KEY", sealer=_fake_seal), issued_at=1.0,
                      min_severity="medium", linear_team_id="team-uuid-1")
    s, led, cert, out = _deliver_one_provider(cap, provider=ci.PROVIDER_LINEAR, configure=cfg)
    assert out[0].delivered and out[0].issue_ref == "ENG-1"
    body = cap.last_body()
    assert body["variables"]["input"]["teamId"] == "team-uuid-1"
    assert "issueCreate" in body["query"]
    assert digest_payload(cert) in body["variables"]["input"]["description"]
    assert cap.calls[-1]["headers"]["Authorization"] == "lin_api_KEY"          # raw key, no Bearer
    assert "lin_api_KEY" not in cap.calls[-1]["body"].decode("utf-8")


def test_delivery_carries_no_model_identifier(integrations_on):
    cap = _slack_ok()
    def cfg(reg):
        reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                      sealed_secret=ci.seal_token("xoxb-S", sealer=_fake_seal), issued_at=1.0, min_severity="low",
                      mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    s, led, cert, out = _deliver_one_provider(cap, provider=ci.PROVIDER_SLACK,
                                              configure=lambda reg: cfg(reg))
    # a finding that smuggles a model id in a NON-allowlisted field never reaches the channel
    s2 = _store(); reg2, led2 = _reg(s2), _led(s2)
    cfg(reg2)
    cap2 = _slack_ok()
    ci.deliver_confirmed_finding(s2, "org_acme", _finding(model="claude-opus-4-8"), now=1.0, certificate=_cert(),
                                 bindings=reg2, ledger=led2, transports={ci.PROVIDER_SLACK: cap2}, resolver=_PUB,
                                 opener=_fake_open)
    blob = cap2.calls[-1]["body"].decode("utf-8").lower()
    assert "claude" not in blob and "opus" not in blob


# ============================================================================================================
# credential custody / no plaintext leak
# ============================================================================================================
def test_sealed_secret_never_appears_on_spine_or_in_body_or_ledger(integrations_on):
    s = _store()
    reg, led = _reg(s), _led(s)
    token = "xoxb-TOPSECRET-TOKEN"
    reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token(token, sealer=_fake_seal), issued_at=1.0, min_severity="low",
                  mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    # after configure the spine holds the SEALED blob, never the plaintext token
    assert token not in _spine_text(s)
    cap = _slack_ok()
    ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=2.0, certificate=_cert(), bindings=reg, ledger=led,
                                 transports={ci.PROVIDER_SLACK: cap}, resolver=_PUB, opener=_fake_open)
    # the token reached Slack ONLY in the auth header; never the spine (binding + ledger) or the body
    assert cap.calls[-1]["headers"]["Authorization"] == f"Bearer {token}"
    assert token not in _spine_text(s)
    assert token not in cap.calls[-1]["body"].decode("utf-8")


def test_seal_token_requires_nonempty():
    with pytest.raises(ci.IntegrationRefused):
        ci.seal_token("", sealer=_fake_seal)


# ============================================================================================================
# egress-gated / fail-closed
# ============================================================================================================
def test_internal_resolving_host_refuses_with_no_post(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    cap = _slack_ok()
    reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token("xoxb-S", sealer=_fake_seal), issued_at=1.0, min_severity="low",
                  mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    out = ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=1.0, certificate=_cert(), bindings=reg,
                                       ledger=led, transports={ci.PROVIDER_SLACK: cap}, resolver=_INTERNAL,
                                       opener=_fake_open)
    assert out[0].outcome == ci.OUTCOME_REFUSED and cap.calls == []
    assert led.delivered_keys_of("org_acme") == set()        # a refusal leaves no idempotency key → retryable


def test_locked_vault_refuses_with_no_post(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    cap = _slack_ok()
    reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token("xoxb-S", sealer=_fake_seal), issued_at=1.0, min_severity="low",
                  mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    def _locked(blob):
        raise RuntimeError("vault is locked")
    out = ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=1.0, certificate=_cert(), bindings=reg,
                                       ledger=led, transports={ci.PROVIDER_SLACK: cap}, resolver=_PUB,
                                       opener=_locked)
    assert out[0].outcome == ci.OUTCOME_REFUSED and cap.calls == []
    assert led.delivered_keys_of("org_acme") == set()


def test_provider_error_refuses_and_is_recorded(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    cap = _Cap(status=200, body_json={"ok": False, "error": "channel_not_found"})
    reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token("xoxb-S", sealer=_fake_seal), issued_at=1.0, min_severity="low",
                  mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    out = ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=1.0, certificate=_cert(), bindings=reg,
                                       ledger=led, transports={ci.PROVIDER_SLACK: cap}, resolver=_PUB,
                                       opener=_fake_open)
    assert out[0].outcome == ci.OUTCOME_REFUSED
    recs = led.records_of("org_acme")
    assert recs and recs[-1]["outcome"] == ci.OUTCOME_REFUSED      # the refusal IS audited


# ============================================================================================================
# idempotent delivery
# ============================================================================================================
def test_idempotent_no_duplicate_issue_on_retry(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    cap = _jira_ok()
    reg.configure("org_acme", "jira1", provider=ci.PROVIDER_JIRA,
                  sealed_secret=ci.seal_token("tok", sealer=_fake_seal), issued_at=1.0, min_severity="high",
                  jira_cloud_id="cid", jira_project_key="SEC", jira_user_email="b@acme.example")
    f, c = _finding(), _cert()
    out1 = ci.deliver_confirmed_finding(s, "org_acme", f, now=1.0, certificate=c, bindings=reg, ledger=led,
                                        transports={ci.PROVIDER_JIRA: cap}, resolver=_PUB, opener=_fake_open)
    out2 = ci.deliver_confirmed_finding(s, "org_acme", f, now=2.0, certificate=c, bindings=reg, ledger=led,
                                        transports={ci.PROVIDER_JIRA: cap}, resolver=_PUB, opener=_fake_open)
    assert out1[0].delivered
    assert out2[0].outcome == ci.OUTCOME_SKIPPED_DUPLICATE
    assert len(cap.calls) == 1                     # exactly ONE issue created, never a duplicate on retry


def test_ledger_records_cert_digest(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    cap = _jira_ok()
    reg.configure("org_acme", "jira1", provider=ci.PROVIDER_JIRA,
                  sealed_secret=ci.seal_token("tok", sealer=_fake_seal), issued_at=1.0, min_severity="high",
                  jira_cloud_id="cid", jira_project_key="SEC", jira_user_email="b@acme.example")
    c = _cert()
    ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=1.0, certificate=c, bindings=reg, ledger=led,
                                 transports={ci.PROVIDER_JIRA: cap}, resolver=_PUB, opener=_fake_open)
    recs = led.records_of("org_acme")
    assert recs[-1]["cert_digest"] == digest_payload(c) and recs[-1]["outcome"] == ci.OUTCOME_DELIVERED


# ============================================================================================================
# routing (which severities go where)
# ============================================================================================================
def test_routing_by_min_severity(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    cap = _slack_ok()
    reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token("xoxb-S", sealer=_fake_seal), issued_at=1.0, min_severity="critical",
                  mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    # a HIGH finding does not route to a CRITICAL-only binding
    out_hi = ci.deliver_confirmed_finding(s, "org_acme", _finding(sev="high"), now=1.0, certificate=_cert(),
                                          bindings=reg, ledger=led, transports={ci.PROVIDER_SLACK: cap},
                                          resolver=_PUB, opener=_fake_open)
    assert out_hi == [] and cap.calls == []
    # a CRITICAL finding does
    out_cr = ci.deliver_confirmed_finding(s, "org_acme", _finding(sev="critical"), now=2.0, certificate=_cert(),
                                          bindings=reg, ledger=led, transports={ci.PROVIDER_SLACK: cap},
                                          resolver=_PUB, opener=_fake_open)
    assert out_cr[0].delivered and len(cap.calls) == 1


# ============================================================================================================
# tenant isolation
# ============================================================================================================
def test_tenant_isolation_binding_and_delivery(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token("xoxb-S", sealer=_fake_seal), issued_at=1.0, min_severity="low",
                  mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    assert [b.binding_id for b in reg.active_for_org("org_acme")] == ["slack1"]
    assert reg.active_for_org("org_evil") == []            # another org sees nothing
    cap = _slack_ok()
    # org_evil cannot trigger org_acme's binding
    out = ci.deliver_confirmed_finding(s, "org_evil", _finding(slug="org_evil"), now=1.0, certificate=_cert(),
                                       bindings=reg, ledger=led, transports={ci.PROVIDER_SLACK: cap}, resolver=_PUB,
                                       opener=_fake_open)
    assert out == [] and cap.calls == []
    # org_acme's ledger is its own
    ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=2.0, certificate=_cert(), bindings=reg, ledger=led,
                                 transports={ci.PROVIDER_SLACK: cap}, resolver=_PUB, opener=_fake_open)
    assert led.delivered_keys_of("org_evil") == set()
    assert len(led.delivered_keys_of("org_acme")) == 1


# ============================================================================================================
# FACT-only + owner-signed (forgery is inert)
# ============================================================================================================
def test_fact_only_a_notice_can_never_deliver(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    for notice in [{"id": "billing:low", "title": "Low balance"}, {"engagement_slug": "org_acme"},
                   {"finding_ref": "F-1"}, "not-a-dict", 42, None]:
        with pytest.raises(ci.NotAConfirmedFinding):
            ci.deliver_confirmed_finding(s, "org_acme", notice, now=1.0, bindings=reg, ledger=led,
                                         resolver=_PUB, opener=_fake_open)


def test_remove_is_honored_and_stops_delivery(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token("xoxb-S", sealer=_fake_seal), issued_at=1.0, min_severity="low",
                  mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    reg.remove("org_acme", "slack1")
    assert reg.active_for_org("org_acme") == []
    cap = _slack_ok()
    out = ci.deliver_confirmed_finding(s, "org_acme", _finding(), now=3.0, certificate=_cert(), bindings=reg,
                                       ledger=led, transports={ci.PROVIDER_SLACK: cap}, resolver=_PUB,
                                       opener=_fake_open)
    assert out == [] and cap.calls == []


def test_forged_binding_is_inert(integrations_on):
    s = _store(); reg = _reg(s)
    # an attacker appends an "active" binding record signed by a NON-owner key → the fold must ignore it
    core = {"signal": ci._BINDING_SIGNAL, "org_id": "org_acme", "binding_id": "evil", "provider": ci.PROVIDER_SLACK,
            "state": "active", "min_severity": "low", "mode": ci.SLACK_POSTMESSAGE, "slack_channel": "C9",
            "jira_cloud_id": "", "jira_project_key": "", "jira_user_email": "", "linear_team_id": "",
            "sealed_secret": "zzz", "issued_at": 1.0}
    payload = {**signed_payload(core, ATTACKER), "tier": "A0", "decision": "auto"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert reg.active_for_org("org_acme") == []            # forged binding is inert


def test_forged_ledger_record_is_ignored_for_idempotency(integrations_on):
    s = _store(); led = _led(s)
    # an attacker forges a `delivered` ledger record (unsigned by the owner) to SUPPRESS a real delivery
    core = {"signal": ci._LEDGER_SIGNAL, "org_id": "org_acme", "binding_id": "slack1", "provider": "slack",
            "engagement_slug": "org_acme", "finding_ref": "F-1", "oracle_context_digest": "ocd1",
            "cert_digest": "x", "outcome": ci.OUTCOME_DELIVERED, "issue_ref": "fake", "issued_at": 1.0}
    payload = {**signed_payload(core, ATTACKER), "tier": "A0", "decision": "auto"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert led.delivered_keys_of("org_acme") == set()      # a forged suppression never blocks a real delivery


# ============================================================================================================
# engagement milestone (Slack-only, no issue mint)
# ============================================================================================================
def test_milestone_delivers_to_slack_only(integrations_on):
    s = _store(); reg, led = _reg(s), _led(s)
    reg.configure("org_acme", "slack1", provider=ci.PROVIDER_SLACK,
                  sealed_secret=ci.seal_token("xoxb-S", sealer=_fake_seal), issued_at=1.0, min_severity="low",
                  mode=ci.SLACK_POSTMESSAGE, slack_channel="C1")
    reg.configure("org_acme", "jira1", provider=ci.PROVIDER_JIRA,
                  sealed_secret=ci.seal_token("tok", sealer=_fake_seal), issued_at=2.0, min_severity="low",
                  jira_cloud_id="cid", jira_project_key="SEC", jira_user_email="b@acme.example")
    slack_cap, jira_cap = _slack_ok(), _jira_ok()
    milestone = ci.build_milestone_delivery(title="Assessment complete", body="12 checks, 1 confirmed",
                                            engagement_slug="org_acme")
    out = ci.deliver_engagement_event(s, "org_acme", milestone, now=5.0, bindings=reg, ledger=led,
                                      transports={ci.PROVIDER_SLACK: slack_cap, ci.PROVIDER_JIRA: jira_cap},
                                      resolver=_PUB, opener=_fake_open)
    assert [o.provider for o in out] == [ci.PROVIDER_SLACK]      # Slack only; no Jira issue minted for a milestone
    assert len(slack_cap.calls) == 1 and jira_cap.calls == []
