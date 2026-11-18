"""Wallet E2E (simulated) — the ACCEPTANCE test of the prepaid pay-as-you-go wallet program (HANDOFF §11.12).

One module drives the §11.1 customer journey end to end, OFFLINE and DETERMINISTIC — a fake model provider on loopback,
a fake Stripe API and HMAC-signed sandbox webhooks; never a real card, never a production AI call:

    sign up (trial credit) -> prove a host -> buy credits (fake Stripe -> a verified webhook mints) -> launch an
    assessment (no price estimate) -> the run's AI use is metered and settled at the EXACT milli-credit charge (W2c-1)
    with a balance-after on the statement (W2c-2) -> the run runs out of credit and stops (pause: W3) -> top up ->
    resume on the same meter (W3) -> a dispute removes credits and a billing HOLD blocks a new launch (W5) -> the next
    top-up repays and lifts the hold (W5) -> auto top-up on a low balance (A1) -> the statement reconciles exactly.

What is REAL here: the customer edge -> provision hop -> Provisioner / LaunchGate (``test_custui._stack``) for what the
customer does and sees (sign-up, the billing dashboard and statement, launch / pause / resume); the MODEL GATEWAY itself
(``model_gateway.start``) admitting every request against the launch's prepaid allowance through the same in-process
source the cockpit wires (``LaunchAllowance(LaunchGate(store))``, W2b-2) — so an allowance extension is a real
owner-signed wallet draw and running out is the real 403 ``CREDITS_EXHAUSTED``; the Stripe provider + ``BillingSigner``
verifying each signed webhook against re-fetched objects before minting; the exact settle (``LaunchGate.settle_launch``,
and the completion-spool drain that calls it). What is FAKED is only what must never be real in a test: the provider
behind the gateway (it answers like the real API and never returns more output than ``max_tokens``), the Stripe API
objects, and the DNS ownership observation.

Each journey leg is a named STAGE. W1 / W2a / W2b / W2c-1 / W2c-2 / M1c-2b / G1 are merged on this branch: their stages
ASSERT LIVE. W3, W4, W5 and A1 are not: each of their stages asserts the LIVE behaviour of today first, then — through a
probe that detects the slice — either SKIPS naming the exact interface still to land, or, once the slice is present,
runs its post-merge assertions. W5's are written to its real interface, read from PR #1151's commits and checked
against its re-fetch rules line by line, but not yet executed against that tree; W3's and W4's are written to the
HANDOFF spec (§11.6 / §11.7) before those slices had code — confirm each at integration. Nothing here passes by
skipping: every skip is a visible SKIPPED with the pending call in its reason.

Determinism: no wall clock enters any asserted number — the sovereign stages run at a fixed instant, the gateway reads a
fake clock that advances one second per request (so the statement's balance-after timeline has no ties), and the edge
journey's wall-clock instants only order events, never price them.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import importlib.util
import inspect
import itertools
import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.billing import EVENT_TOPUP, BillingSigner, Entitlement, StripeBillingProvider
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.orgs import OrgRegistry
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import billing as ui_billing
from sigil.ui.launch_gate import LaunchAllowance, LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import model_metering as mm
from vigil_core.model_grant import STOP_CREDITS_EXHAUSTED, STOP_HEADER, ModelGrant, meter_id
from vigil_core.rate_card import DEFAULT_RATE_CARD, MC_PER_CREDIT

# The per-slice suites' own harness, reused verbatim (same-dir pytest import) so this test runs the SAME edge, hop,
# gateway client and Stripe fake they do: the edge stack + its HTTP helpers + the shared-home scrub (autouse), the fake
# Stripe API, and the model gateway's HTTP client and canonical request.
from test_billing_stripe_checkout import _Stripe
from test_custui import _get, _opener, _post
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse fixture)
from test_custui import _stack as _edge_stack
from test_model_gateway import BODY, NO_PROXY, PROVIDER_KEY, _call

_iss = itertools.count(1)
_purchase_n = itertools.count(1)
NOW = 2000.0                                     # the sovereign stages' fixed instant
HOST_A, HOST_B = "apme.cm", "bpme.cm"

# Catalog top-up packs ($1 = 100 credits; amount_minor in cents, numerically equal to the credits). The CREDITS come
# from the owner catalog's Entitlement, never the wire; the paid amount is verified against the catalog.
_WHSEC = "whsec_" + "wallet-e2e-sandbox"
_RETURN = "https://app.example.test/#/billing/return"
_PACKS = {"price_topup_10": (1000, "USD"), "price_topup_5": (500, "USD")}

# What the fake provider answers per message: input + output tokens (the output never above the request's max_tokens).
PROVIDER_INPUT_TOKENS, PROVIDER_OUTPUT_TOKENS = 100, 4_000
# Fractional usages on the published card, each line rounded up on its own (the statement's rule), to exercise W2c-1's
# sub-credit remainder: 400 output + 16 cache-read = 2,500 + 2 mc; 79 output + 4 input = 494 + 5 mc.
U2502 = mm.Usage(output_tokens=400, cache_read_tokens=16)
U499 = mm.Usage(output_tokens=79, input_tokens=4)


# ============================================================================ isolation + the metered settings =====

@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    """Metered billing ON; every seam / meter / kept-launch path isolated to tmp; the customer launch and pause/resume
    routes ON; step-up, OIDC and passkey OFF (this is the money journey, not the MFA one); W5's reversals OFF unless a
    stage turns them on. The margin value is a test fixture the metered PUBLISH reads to mint the run's grant (no settle
    reads it since W2c-1) — not a pricing decision. Two implementation toggles are deliberately LEFT to the CI leg —
    ``VIGIL_FOLD_CACHE_ENABLED`` and ``VIGIL_SETTLE_SPINE_RECORD``: neither may change any money outcome, so the legs
    that turn them on run this whole journey under them too."""
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())        # the cross-plane seam: leases + model grants
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())            # call-time readers (e.g. W5's hold alarm file)
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    monkeypatch.setattr(config, "CUSTOMER_LAUNCHES_DIR", tmp_path / "launches")   # bound at import: isolate it
    for k in (mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_MODEL_PRICES", "VIGIL_RATE_CARD", "VIGIL_RUN_MODEL",
              "VIGIL_TIERED_PRODUCTS", "VIGIL_TRIAL_PREVIEW_ENABLED", "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED",
              "VIGIL_CUSTOMER_STEPUP_REQUIRED", "VIGIL_BILLING_REVERSALS", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")
    monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED", "1")


# ============================================================================ the fake provider + the real gateway ===

class _Provider(BaseHTTPRequestHandler):
    """The model provider, faked on loopback (no network). Like the real API it never returns more output than the
    request's ``max_tokens``: the gateway lowers ``max_tokens`` to what the allowance can still pay for, so a fake that
    ignored it could bill a response past its reservation — a property the real provider has, which this fake keeps.
    Every request that reaches it is recorded (``server.seen``)."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        return

    def _json(self, status, doc):
        raw = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("request-id", "req_wallet_e2e")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        self.server.seen.append(self.path)
        if self.path.startswith("/v1/messages/count_tokens"):   # as the gateway suite's fake: no count service
            return self._json(500, {"type": "error", "error": {"type": "api_error", "message": "no count"}})
        out = min(PROVIDER_OUTPUT_TOKENS, int(body.get("max_tokens") or 0))
        return self._json(200, {"id": "msg_wallet_e2e", "type": "message", "role": "assistant",
                                "model": body.get("model"), "stop_reason": "end_turn",
                                "content": [{"type": "text", "text": "ok"}],
                                "usage": {"input_tokens": PROVIDER_INPUT_TOKENS, "output_tokens": out}})


@pytest.fixture()
def provider():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Provider)
    srv.daemon_threads = True
    srv.seen = []
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _gateway(store, provider, clock):
    """The REAL model gateway in front of the fake provider, admitting each request against the launch's prepaid
    allowance through the source the cockpit wires (``ui/server.py::serve``): ``LaunchAllowance(LaunchGate(store))``.
    Owner-pinned to the persisted owner key the run's grant is signed with; its clock is the test's (``clock``)."""
    cfg = gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=ensure_owner_keypair().public_key_b64,
                           meter_dir=config.MODEL_METER_DIR, upstream=f"http://127.0.0.1:{provider.server_address[1]}",
                           opener=NO_PROXY, clock=lambda: clock["now"],
                           allowance=LaunchAllowance(LaunchGate(store)), allowance_required=True)
    server, _t = gw.start(cfg)
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    server.provider = provider
    return server


def _stop(server):
    server.shutdown()
    server.server_close()                        # also gives up the meter directory (the gateway role)


def _token(r):
    """The run's owner-signed model grant, exactly as the launch published it on the seam for the offense runner."""
    from vigil_integration.live.model_grant_broker import read_model_grant
    b = read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"], expect_nonce=r["nonce"])
    assert b is not None, "a metered launch publishes its model grant"
    return b.token


def _ask(server, token, clock):
    """One model request of the run, at its own instant (one second after the previous one)."""
    clock["now"] += 1
    return _call(server, dict(BODY, model=config.run_model()), token)


def _stop_reason(headers) -> "str | None":
    return {k.lower(): v for k, v in headers.items()}.get(STOP_HEADER)


def _run_until_refused(server, token, clock, *, limit=200):
    """Drive the run's model requests until the gateway refuses one. Returns ``(admitted, status, headers, body,
    seen_before)`` — ``seen_before``: what had reached the provider just before the refused request."""
    for admitted in range(limit):
        seen_before = len(server.provider.seen)
        status, headers, body = _ask(server, token, clock)
        if status != 200:
            return admitted, status, headers, body, seen_before
    pytest.fail(f"the gateway admitted {limit} requests and never stopped the run for credit")


# ============================================================================ the sovereign money core ===============

def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _seat(store, org, host, *, credits=100):
    """The server-side setup that is NOT a customer action: the org + an operator, its trial credit, the DNS ownership
    observation and the customer target (its EngagementAuthority) — enough for a real reserve."""
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    if orgs.org(org) is None:
        orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=NOW)["ok"]


def _reserve_start(gate, org, host, *, now=NOW):
    """A metered launch through the REAL LaunchGate (the provisioner's launch_reserve / launch_start delegate to it):
    a Quick depth holding the allowance chunk, then published with its model grant."""
    r = gate.reserve_launch(requester="u", org_id=org, host=host, units=mm.allowance_chunk_credits(), now=now,
                            depth="quick")
    assert r["ok"], r
    assert gate.publish_lease(signed_lease=r["lease"], expect_org_id=org)["ok"]
    return r


def _grant_for(org, r, *, now=NOW):
    """A grant on the launch's meter: same (org, slug, nonce) as the published one, so it writes the SAME meter file
    the settle reads (the binding limit is the allowance; this grant's cap is only a ceiling)."""
    return ModelGrant(grant_id="0" * 32, org_id=org, engagement_slug=r["slug"], nonce=r["nonce"],
                      model=config.run_model(), effort="high", cap_nano_usd=10 ** 13,
                      not_after=now + 86_400, issued_at=now - 60)


def _meter_use(org, r, usage, *, now=NOW, held=0):
    """Record ONE confirmed response on the launch's meter, line for line what the gateway writes for a forwarded
    response (W2a: priced with the published card at commit). ``held``: a cut-off part VIGIL cannot prove."""
    m = gw.GrantMeter(config.MODEL_METER_DIR, rate_card=DEFAULT_RATE_CARD)
    g = _grant_for(org, r, now=now)
    rid, _res, why = m.reserve(g, 10 ** 6, 25_000, now=now)
    assert why == "", why
    m.commit(g, rid, usage, 1, request_id=f"r{next(_iss)}", now=now, held_nano=held)


def _settle_exact(gate, org, r, *, now=NOW, used=None):
    """Settle the launch EXACTLY, as the completion drain does: close its meter (a request still in flight on the LIVE
    gateway -> retry later), read its use (``metered_use_mc``) and settle (``used`` overrides it, for the clamp)."""
    try:
        gw.GrantMeter(config.MODEL_METER_DIR).close(meter_id(r["slug"], r["nonce"]), now=now)
    except gw.MeterBusy:
        return {"ok": False, "retry": True, "error": "a request is still in flight on the live gateway"}
    mc = gate.metered_use_mc(r["slug"], r["nonce"]) if used is None else used
    return gate.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=mc, now=now,
                              expect_org_id=org, basis="completion:completed")


def _completion(store, r, *, outcome="completed", now=NOW):
    """The REAL completion-spool drain holding one governance-signed completion signal for launch ``r``, and a function
    that delivers that completion again (the duplicate case). The test owns the governance key the drain verifies."""
    from sigil.governor.identity import delegate_offense_governance
    from sigil.inbound.completion_spool import CompletionSpoolWatcher
    from vigil_core import AuthorizerKey, generate_keypair
    from vigil_integration.jobs.completion_signal import emit_completion_signal
    owner = ensure_owner_keypair()
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=r["slug"], not_after=9_000_000_000)
    spool = tempfile.mkdtemp()

    def signal():
        emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome=outcome,
                               signers=[("gov", gov.private_key_b64)], spool_dir=spool)

    signal()
    w = CompletionSpoolWatcher(store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                               scope=r["slug"], base_dir=os.environ["VIGIL_BASE_DIR"], now_fn=lambda: now)
    return w, signal


def _bal(store, org):
    return WalletRegistry(store).balance(org)


def _statement(store, org, *, now=NOW):
    return ui_billing.billing_usage(store, org, trusted_pubkey=ensure_owner_keypair().public_key_b64,
                                    meter_dir=config.MODEL_METER_DIR, now=now)


# ============================================================================ the sandbox payments (fake Stripe) =====

class _Purchase:
    """One sandbox PURCHASE on the fake Stripe API: a checkout created for ``org`` through the real provider, then its
    signed webhooks verified by the REAL ``BillingSigner`` against objects re-fetched from the fake API.

    Each purchase has a globally unique checkout-session id, as on the real Stripe: a top-up is credited UNDER its
    session id (``BillingEvent.event_id``), so two purchases that shared one would be deduplicated — a fake that reused
    ids would make "a duplicate webhook mints once" pass for the wrong reason. ``pay()`` delivers the paid
    ``checkout.session.completed`` (call it again: Stripe re-delivering the IDENTICAL signed event, to a fresh signer as
    after a restart — the duplicate-webhook case). ``reversals``: W5's ledger — given, the provider acts on disputes and
    the signer repays arrears from every top-up (``config.billing_reversals_enabled`` wiring); None: the merged
    behaviour, the W5 keywords are never passed."""

    def __init__(self, store, org, *, price="price_topup_10", created=1000, reversals=None):
        n = next(_purchase_n)
        self.store, self.org, self.price, self.created, self.reversals = store, org, price, int(created), reversals
        self.sid, self.pi = f"cs_test_wallete2e{n}", f"pi_wallete2e{n}"
        self.ch, self.du = f"ch_wallete2e{n}", f"du_wallete2e{n}"
        self.objects: dict = {}
        self.lists: dict = {"disputes_for_charge": {}, "checkout_sessions_for_payment_intent": {}}
        api = _Stripe(id=self.sid, url=f"https://checkout.stripe.com/c/pay/{self.sid}", payment_intent=self.pi,
                      created=self.created)
        self._provider(api.create).create_checkout(org, price, expected=_PACKS, redirect_url=_RETURN,
                                                   nonce=f"n{n}")
        stored = next(iter(api.sessions.values()))
        self.session = dict(stored, status="complete", payment_status="paid")
        self.objects[self.sid] = self.session
        self.lists["checkout_sessions_for_payment_intent"][self.pi] = [self.session]

    def _fetch(self, kind, oid):
        if kind in self.lists:
            return {"object": "list", "has_more": False,
                    "data": [copy.deepcopy(x) for x in self.lists[kind].get(oid, [])]}
        return copy.deepcopy(self.objects[oid])

    def _provider(self, creator=None, *, reversals=None):
        kw = {"reversals": True} if reversals is not None else {}
        return StripeBillingProvider(_WHSEC, fetcher=self._fetch, expected_mode="test",
                                     enable_reference_adapter=True, checkout_creator=creator, plan_periods={}, **kw)

    def _signer(self, reversals):
        kw = {"reversals": reversals} if reversals is not None else {}
        return BillingSigner(self._provider(reversals=reversals), wallet=WalletRegistry(self.store),
                             subscriptions=SubscriptionRegistry(self.store), plan=PlanCreditLedger(self.store),
                             invoices=InvoiceRegistry(self.store), expected=_PACKS, require_verified_amount=True,
                             catalog={p: Entitlement(kind=EVENT_TOPUP, credits=c) for p, (c, _ccy) in _PACKS.items()},
                             **kw)

    def _send(self, etype, oid, eid, *, t, reversals, mac_key=_WHSEC):
        raw = json.dumps({"id": eid, "object": "event", "type": etype, "created": t, "livemode": False,
                          "data": {"object": {"id": oid}}}).encode()
        mac = hmac.new(mac_key.encode(), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
        return self._signer(reversals).ingest(raw, f"t={t},v1={mac}", now=float(t))

    def pay(self, *, mac_key=_WHSEC):
        """The paid-checkout webhook (``mac_key``: a forger's secret signs it instead). Returns the minted spine seq."""
        return self._send("checkout.session.completed", self.sid, f"evt_paid_{self.sid}", t=self.created,
                          reversals=self.reversals, mac_key=mac_key)

    def dispute(self, *, disputed_minor, reversals=None, status="needs_response"):
        """The cardholder's bank disputes this purchase: a signed ``charge.dispute.funds_withdrawn``. The signer is
        trusted with the event TYPE and object id only; the dispute, its charge, the charge's disputes and the checkout
        session are re-fetched (W5). ``reversals``: the W5 ledger (None: a build that does not act on disputes)."""
        t = self.created + 100
        self.objects[self.ch] = {"object": "charge", "id": self.ch, "livemode": False,
                                 "amount": self.session["amount_total"], "amount_refunded": 0, "currency": "usd",
                                 "created": self.created, "payment_intent": self.pi}
        d = {"object": "dispute", "id": self.du, "livemode": False, "charge": self.ch, "status": status,
             "amount": disputed_minor, "currency": "usd", "created": t}
        self.objects[self.du] = d
        self.lists["disputes_for_charge"][self.ch] = [d]
        return self._send("charge.dispute.funds_withdrawn", self.du, f"evt_dispute_{self.du}", t=t,
                          reversals=reversals)


# ============================================================================ the off-session auto top-up (A1) ======

class _A1Stripe:
    """The off-session PaymentIntent poster + object fetcher for A1's auto top-up (§11.13) — the SAME fake Stripe as
    A1's own suite (``test_billing_auto_topup._FakeStripe``): it honours the Idempotency-Key exactly like Stripe (the
    same key returns the one PaymentIntent), so a retried create reuses the ONE ``pi_`` and a crossing charges once.
    No network, no real card, no Stripe secret — only the off-session charge the ``AutoTopUpCharger`` drives."""

    def __init__(self, *, created):
        self.objects: dict = {}
        self.pi_calls: list = []
        self.by_key: dict = {}
        self.created = int(created)
        self.fetched: list = []

    def fetch(self, kind, oid):
        self.fetched.append((kind, oid))
        return copy.deepcopy(self.objects[oid])

    def create_pi(self, params, *, idempotency_key):
        self.pi_calls.append((copy.deepcopy(params), idempotency_key))
        pid = self.by_key.get(idempotency_key)
        if pid is None:
            pid = f"pi_wallete2eA1{len(self.by_key) + 1}"
            self.by_key[idempotency_key] = pid
            self.objects[pid] = {
                "object": "payment_intent", "id": pid, "livemode": False, "status": "succeeded",
                "amount": params["amount"], "amount_received": params["amount"], "currency": params["currency"],
                "customer": params["customer"], "payment_method": params["payment_method"], "created": self.created,
                "metadata": dict(params["metadata"])}
        return copy.deepcopy(self.objects[pid])


def _a1_webhook(signer, etype, object_id, *, t, eid="evt_a1"):
    """Deliver ONE signed sandbox Stripe webhook to a ``BillingSigner`` — the SAME HMAC scheme the e2e ``_Purchase``
    uses (``_WHSEC``). Returns the minted spine seq, or None when the drain mints nothing (an idempotent re-delivery)."""
    raw = json.dumps({"id": eid, "object": "event", "type": etype, "created": t, "livemode": False,
                      "data": {"object": {"id": object_id}}}).encode()
    mac = hmac.new(_WHSEC.encode(), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
    return signer.ingest(raw, f"t={t},v1={mac}", now=float(t))


# ============================================================================ the customer edge =====================

def _signup_operator(op, ep, store, email, org="Acme"):
    """Sign up over the edge (an org_admin + the trial credit), then the service owner makes the member an operator —
    the role that may launch assessments (a billing org_admin may not: billing != testing). The promotion is stamped
    after the sign-up's own wall-clock membership record, so it wins the last-writer-wins fold."""
    tok = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": tok, "password": "customer-pw-123", "org_name": org})[1]
    OrgRegistry(store).grant_membership(conf["org_id"], conf["username"], "operator", issued_at=time.time() + 1e6)
    return conf


def _prove_host(store, org, host):
    """The DNS ownership OBSERVATION + the customer target — VIGIL's oracle, not a customer action."""
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=time.time())
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=time.time(), ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=time.time())["ok"]


def _edge_billing(op, ep):
    c, d = _get(op, ep, "/api/customer/billing")
    assert c == 200, (c, d)
    return d


def _edge_statement(op, ep):
    c, d = _get(op, ep, "/api/customer/billing/usage")
    assert c == 200, (c, d)
    return d


# Opaque cryptographic fields of a customer payload — a signed lease, its trust root, a signature, a token: random
# base64 that could spell any word, so the money/model scan reads the lease's DOCUMENT instead.
_OPAQUE = frozenset({"lease", "trust_root", "signature", "signatures", "token"})


def _customer_words(blob) -> str:
    def scrub(x):
        if isinstance(x, dict):
            out = {k: scrub(v) for k, v in x.items() if k not in _OPAQUE}
            lease = x.get("lease")
            if isinstance(lease, dict) and isinstance(lease.get("document"), dict):
                out["lease_document"] = scrub(lease["document"])
            return out
        if isinstance(x, list):
            return [scrub(v) for v in x]
        return x
    # the published rate card's credits_per_usd conversion constant is the one allowed `usd` (§11.9's leak-scan rule)
    return json.dumps(scrub(blob)).lower().replace("credits_per_usd", "credits_per_unit")


def _no_money_or_estimate(blob) -> None:
    """I5 + I10 on a customer surface: credits only — never a $/usd amount for a scan, never a cost estimate, never the
    model or engine name, never the internal provider cost."""
    s = _customer_words(blob)
    assert "estimat" not in s, s
    assert "$" not in s and "usd" not in s, s
    assert "nano" not in s, s                                         # I10: no provider cost (cost_nano) leaks out
    for name in ("claude", "anthropic", "opus", "sonnet", "haiku", "strix", "nyx"):
        assert name not in s, (name, s)


# ============================================================================ the merge probes (pending slices) ======

def _merged_w3() -> bool:
    """W3 extends ``credit_lease_pause`` with the sovereign credit-pause record + its reason (§11.6: new accessors —
    ``record_credit_pause`` / ``credit_pause_reason`` / ``credit_paused_launches`` — add-only; the plain halt marker
    ``record_lease_pause`` is unchanged)."""
    from vigil_integration.live import credit_lease_pause as clp
    return hasattr(clp, "credit_pause_reason")


def _merged_w4() -> bool:
    """W4 adds the grant-authenticated worker heartbeat to the gateway (§11.7)."""
    return "/v1/vigil/worker/heartbeat" in inspect.getsource(gw)


def _merged_w5() -> bool:
    """W5 adds the owner-signed reversal ledger (PR #1151: ``sigil.governor.billing_reversal``)."""
    return importlib.util.find_spec("sigil.governor.billing_reversal") is not None


def _merged_a1() -> bool:
    """A1 adds auto top-up (§11.13); no interface name was published when this test was written — any of these."""
    return any(importlib.util.find_spec(m) is not None
               for m in ("sigil.governor.auto_topup", "sigil.governor.autotopup", "sigil.ui.auto_topup"))


# ============================================================================ the fixtures cost what they say ======

def test_the_fixture_usages_cost_what_the_journey_says():
    """The arithmetic every stage leans on, priced by the PUBLISHED card (W1): a later card edit fails here first."""
    full = mm.Usage(input_tokens=PROVIDER_INPUT_TOKENS, output_tokens=PROVIDER_OUTPUT_TOKENS)
    assert [DEFAULT_RATE_CARD.charge(u)[0] for u in (U2502, U499, full)] == [2502, 499, 25_125]
    assert 0 < gw.min_request_mc(DEFAULT_RATE_CARD) < mm.allowance_chunk_credits() * MC_PER_CREDIT


# ============================================================================ STAGE 1 — sign up (trial credit) ======

def test_stage_1_signup_grants_a_trial_credit_shown_with_no_estimate(tmp_path, monkeypatch):
    """LIVE. Over the real edge: a sign-up mints the owner-signed org and its trial credit, and the wallet shows it —
    in credits, with no cost estimate, no money amount and no model name (I5)."""
    sov, edge, ep, _sp = _edge_stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        conf = _signup_operator(op, ep, sov.store(), "founder@acme.com")
        bill = _edge_billing(op, ep)
        assert bill["org_id"] == conf["org_id"]
        assert bill["credits"]["available"] == config.TRIAL_CREDITS > 0
        assert bill["exact_available"] == config.TRIAL_CREDITS            # W2c-2: the exact balance, whole credits
        _no_money_or_estimate(bill)
        _no_money_or_estimate(_get(op, ep, "/api/customer/billing/rates")[1])   # the published rates: credits only
    finally:
        sov.shutdown(); edge.shutdown()


# ============================================================================ STAGE 2 — buy credits ================

def test_stage_2_a_verified_webhook_mints_the_pack_once_and_a_forged_one_mints_nothing(tmp_path, monkeypatch):
    """LIVE (I3: every webhook once). A paid checkout's signed webhook, verified by the real BillingSigner against the
    re-fetched session, mints the CATALOG's credits for the bound org, and the edge shows trial + pack at once. Stripe
    re-delivering the IDENTICAL event mints nothing more; a webhook signed with any other secret mints nothing; a
    SECOND purchase of the same pack does credit again (the deduplication is per purchase, not a fake's id clash)."""
    sov, edge, ep, _sp = _edge_stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        org = _signup_operator(op, ep, sov.store(), "pay@acme.com")["org_id"]
        trial = _edge_billing(op, ep)["credits"]["available"]
        p = _Purchase(sov.store(), org, price="price_topup_10")
        assert p.pay() is not None                                         # verified + minted (a spine seq)
        assert _edge_billing(op, ep)["credits"]["available"] == trial + 1000
        p.pay()                                                            # re-delivered: the same signed event
        assert _edge_billing(op, ep)["credits"]["available"] == trial + 1000
        forged = _Purchase(sov.store(), org, price="price_topup_10")
        assert forged.pay(mac_key="whsec_not_the_secret") is None          # an unverifiable webhook is inert
        assert _edge_billing(op, ep)["credits"]["available"] == trial + 1000
        assert _Purchase(sov.store(), org, price="price_topup_5").pay() is not None
        assert _edge_billing(op, ep)["credits"]["available"] == trial + 1500
    finally:
        sov.shutdown(); edge.shutdown()


# ============================================================================ STAGE 3 — launch, no estimate ========

def test_stage_3_a_metered_launch_starts_from_the_edge_without_a_price_estimate(tmp_path, monkeypatch):
    """LIVE (I1 + I5). Over the real edge -> hop -> provisioner: prove a host, buy credits, reserve and start a metered
    assessment. It names a DEPTH (never an amount), holds the allowance chunk from the wallet BEFORE any work (I1), and
    neither reply carries an estimate, a money amount or a model name."""
    sov, edge, ep, _sp = _edge_stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        org = _signup_operator(op, ep, sov.store(), "launch@acme.com")["org_id"]
        _prove_host(sov.store(), org, HOST_A)
        assert _Purchase(sov.store(), org).pay() is not None
        before = _edge_billing(op, ep)["credits"]["available"]
        c, r = _post(op, ep, "/api/customer/launch/reserve", {"host": HOST_A})
        assert c == 200, (c, r)
        _no_money_or_estimate(r)
        assert r["lease"]["document"]["run_tier"] == "quick"              # W2b-3: the lease names the depth
        c2, s = _post(op, ep, "/api/customer/launch/start", {"lease": r["lease"]})
        assert c2 == 200 and s["slug"] == r["slug"], (c2, s)
        _no_money_or_estimate(s)
        assert _token(r)                                                   # the run's grant is on the seam
        assert _edge_billing(op, ep)["credits"]["available"] == before - int(r["units_reserved"])   # held (I1)
    finally:
        sov.shutdown(); edge.shutdown()


# ============================================================================ STAGE 4 — exact settle ===============

def test_stage_4_ai_usage_settles_at_the_exact_milli_credit_with_a_balance_after():
    """LIVE (W2c-1 + W2c-2; I3 + I4). A metered run's recorded AI use settles EXACTLY to the milli-credit — whole
    credits kept, the sub-credit rest carried as the org's remainder — and the statement shows the charge and the
    balance after it, which reconciles to the wallet's exact balance (I4)."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    _meter_use("org_a", r, U2502)
    out = _settle_exact(g, "org_a", r)
    assert out["ok"] and out["action"] == "launch_settled", out
    assert (out["consumed_mc"], out["net_spend"], out["remainder_mc"]) == (2502, 2, 502)
    b = _bal(s, "org_a")
    assert (b.available, b.remainder_mc, b.exact_available_mc) == (98, 502, 97_498)
    st = _statement(s, "org_a")
    assert st["amount_mc"] == st["charges"][0]["amount_mc"] == 2502
    assert st["charges"][0]["balance_after_mc"] == st["remaining_mc"] == b.exact_available_mc
    _no_money_or_estimate(st)


# ============================================================================ STAGE 5 — out of credit ==============

def test_stage_5_running_out_of_credit_stops_the_run_with_the_terminal_credit_stop(provider):
    """LIVE through the REAL gateway (W2b-2 + M1c-2b; I1, I2, I9). A launch funded by its trial alone holds the whole
    wallet, so the gateway cannot extend it: it admits requests while the allowance can pay for them, then refuses the
    next with the NON-retryable 403 ``CREDITS_EXHAUSTED`` carrying ``x-vigil-stop: credits_exhausted`` (the offense
    runner parks the run on it, M1c-2b) — and that request never reaches the provider. The run is PARKED, not ended:
    nothing settles it, its meter stays open, its completed work stays billed and its unspent allowance stays held."""
    from vigil_integration.live.credit_lease_broker import is_lease_settled
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    assert _bal(s, "org_a").spendable == 0                                 # the launch holds the whole trial
    clock = {"now": NOW + 60}
    server = _gateway(s, provider, clock)
    try:
        admitted, status, headers, body, seen_before = _run_until_refused(server, _token(r), clock)
    finally:
        _stop(server)
    err = json.loads(body)["error"]
    assert admitted >= 1
    assert (status, err["type"], err["message"]) == (403, "permission_error", gw.CREDITS_EXHAUSTED)
    assert _stop_reason(headers) == STOP_CREDITS_EXHAUSTED                  # terminal: the runner parks, never retries
    assert len(provider.seen) == seen_before                                # the refused request was never forwarded
    st = _statement(s, "org_a")
    assert len(st["charges"]) == admitted                                   # completed work: every request billed once
    allowance = int(r["units_reserved"]) * MC_PER_CREDIT
    assert 0 < st["amount_mc"] <= allowance                                 # never past the prepaid allowance (I1/I9)
    assert st["held_mc"] == allowance - st["amount_mc"]                     # parked: its unspent allowance still held
    assert not is_lease_settled(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    assert not gw.GrantMeter(config.MODEL_METER_DIR).is_closed(meter_id(r["slug"], r["nonce"]))
    assert _bal(s, "org_a").exact_available_mc >= 0                         # I2


def test_stage_5b_the_credit_stop_records_an_insufficient_credits_pause(provider):
    """W3 (pending on this branch). §11.6: on the gateway's credit stop the SOVEREIGN records a pause marker with the
    reason ``insufficient_credits`` (and notifies the customer). LIVE today: the stop parks the run on the offense side
    only — the sovereign records no pause for it; that record is the W3 delta."""
    from vigil_integration.live import credit_lease_pause as clp
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    clock = {"now": NOW + 60}
    server = _gateway(s, provider, clock)
    try:
        _admitted, status, headers, _b, _seen = _run_until_refused(server, _token(r), clock)
    finally:
        _stop(server)
    assert status == 403 and _stop_reason(headers) == STOP_CREDITS_EXHAUSTED
    base = os.environ["VIGIL_BASE_DIR"]
    if not _merged_w3():
        assert not clp.is_lease_paused(base, r["slug"], r["nonce"])          # today: no sovereign pause record
        pytest.skip("W3 pending: the sovereign credit pause is not merged. Un-skips when "
                    "`credit_lease_pause.record_lease_pause(base, slug, nonce, reason='insufficient_credits')` is "
                    "called from the gateway's refused extension (ModelGateway.ensure_allowance -> W3 hook) + a "
                    "customer notification; this stage then asserts the marker and its reason.")
    # --- W3 merged: the halt marker parks it AND the sovereign credit-pause record carries the reason (W3's real
    # accessor is `credit_pause_reason`, reconciled from the spec's assumed `pause_path` read at integration) ---
    assert clp.is_lease_paused(base, r["slug"], r["nonce"])
    assert clp.credit_pause_reason(base, r["slug"], r["nonce"]) == "insufficient_credits"


# ============================================================================ STAGE 6 — top up, resume ==============

def test_stage_6_a_topup_then_resume_continues_the_same_run_on_the_same_meter(provider):
    """LIVE through the REAL gateway. The run stops for credit; the customer pauses it (W3 will do this itself) and a
    paused launch draws nothing more; the customer tops up and resumes; the run's NEXT request goes through on the SAME
    grant and the SAME meter, the gateway drawing a new allowance extension from the topped-up wallet. The exact settle
    then charges every admitted request once, the statement is one continuous meter whose every balance-after is >= 0
    (I2), and its latest balance-after is the wallet's exact balance (I4)."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    mid = meter_id(r["slug"], r["nonce"])
    clock = {"now": NOW + 60}
    server = _gateway(s, provider, clock)
    try:
        token = _token(r)
        n1, status, _h, _b, _seen = _run_until_refused(server, token, clock)
        assert status == 403
        assert g.pause_launch(signed_lease=r["lease"], expect_org_id="org_a")["ok"]
        ext = g.extend_reservation(org_id="org_a", slug=r["slug"], nonce=r["nonce"], credits=1, now=NOW)
        assert ext["ok"] is False and ext.get("paused"), ext              # a paused launch draws nothing
        clock["now"] += 1
        assert _Purchase(s, "org_a", created=int(clock["now"])).pay() is not None    # top up: 1,000 credits
        assert g.resume_launch(signed_lease=r["lease"], expect_org_id="org_a", now=NOW + 60)["ok"]
        assert _ask(server, token, clock)[0] == 200                       # the same run, on the same grant
        assert g.extension_total("org_a", r["slug"], r["nonce"])[0] >= 1  # paid by a fresh extension
    finally:
        _stop(server)
    out = _settle_exact(g, "org_a", r, now=clock["now"] + 1)
    assert out["ok"], out
    st = _statement(s, "org_a")
    assert len(st["charges"]) == n1 + 1 and {(c["scan"], c["launch"]) for c in st["charges"]} == {
        (r["slug"], r["nonce"])}                                          # one meter: the statement is continuous
    assert meter_id(r["slug"], r["nonce"]) == mid
    assert st["amount_mc"] == out["consumed_mc"]                          # statement == settle (I4)
    assert all(c["balance_after_mc"] >= 0 for c in st["charges"])         # I2 at every line
    assert st["charges"][0]["balance_after_mc"] == st["remaining_mc"] == _bal(s, "org_a").exact_available_mc


def test_stage_6b_a_resume_after_the_lease_window_continues_on_the_same_meter(provider):
    """W3 (pending). A credit pause can outlive the launch's 8-hour lease (§11.6, verified): W3 resumes it on a
    continuation lease bound to the SAME meter, the 7-day TTL counted from the pause, and the resume itself takes the
    allowance extension. LIVE today: a resume after the window lifts the halt but the launch is EXPIRED (it will not
    re-arm) — the continuation is the W3 delta."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    clock = {"now": NOW + 60}
    server = _gateway(s, provider, clock)
    try:
        token = _token(r)
        assert _run_until_refused(server, token, clock)[1] == 403
        assert g.pause_launch(signed_lease=r["lease"], expect_org_id="org_a")["ok"]
        assert _Purchase(s, "org_a", created=int(clock["now"]) + 1).pay() is not None
        late = NOW + 9 * 3600                                             # past the 8-hour lease window
        ext_before = g.extension_total("org_a", r["slug"], r["nonce"])[0]
        res = g.resume_launch(signed_lease=r["lease"], expect_org_id="org_a", now=late)
        if not _merged_w3():
            assert res["ok"] and res.get("expired") is True, res          # today: lifted, but it will not re-arm
            pytest.skip("W3 pending: the continuation lease is not merged. Un-skips when "
                        "`LaunchGate.resume_launch` (provisioner `launch_resume`) re-checks the exact balance, takes "
                        "an allowance extension (W2), clears the pause and re-triggers the job on a "
                        "`CreditLaunchLease.continue_of` continuation bound to the SAME meter (7-day TTL from the "
                        "pause); this stage then asserts a not-expired resume and the next request on the same grant.")
        # --- W3 merged (written to the §11.6 spec before W3 had code) ---
        assert res["ok"] and not res.get("expired"), res
        assert g.extension_total("org_a", r["slug"], r["nonce"])[0] > ext_before
        clock["now"] = late + 1
        assert _ask(server, token, clock)[0] == 200
    finally:
        _stop(server)


# ============================================================================ STAGES 7 + 8 — dispute, hold, repay ===

def _disputed(monkeypatch):
    """W5's set-up (merged builds only): reversals ON; an org that bought 1,000 credits ($10) on top of its trial, spent
    800 of its 1,100 through a metered run, then had that purchase disputed in full — so W5 removes the 300 still in the
    wallet and books 700 as OWED (arrears), and the org is on a billing hold."""
    from sigil.governor.billing_reversal import BillingReversalLedger
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    ledger = BillingReversalLedger(s)
    p = _Purchase(s, "org_a", price="price_topup_10", created=1500, reversals=ledger)
    assert p.pay() is not None
    r = _reserve_start(g, "org_a", HOST_A)
    assert g.extend_reservation(org_id="org_a", slug=r["slug"], nonce=r["nonce"], credits=900, now=NOW)["ok"]
    _meter_use("org_a", r, mm.Usage(output_tokens=128_000))               # 800,000 mc: exactly 800 credits
    assert _settle_exact(g, "org_a", r)["consumed_mc"] == 800_000
    assert _bal(s, "org_a").available == 300
    assert p.dispute(disputed_minor=1000, reversals=ledger) is not None
    return s, g, ledger, p


def test_stage_7_a_dispute_removes_credits_and_a_billing_hold_blocks_a_new_launch(monkeypatch):
    """W5 (pending on this branch; written to its real interface, PR #1151, not yet run on it). The bank disputes a paid
    top-up: the credits still in the wallet leave it, the part already spent is OWED (arrears — never a negative
    wallet, I2), and the org is on a billing HOLD that refuses a new launch. LIVE today: a signed dispute webhook moves
    nothing (no build before W5 acts on one)."""
    s0 = _store()
    _seat(s0, "org_a", HOST_A, credits=100)
    p0 = _Purchase(s0, "org_a", price="price_topup_10")
    assert p0.pay() is not None
    assert p0.dispute(disputed_minor=1000) is None and _bal(s0, "org_a").available == 1100   # inert without W5
    if not _merged_w5():
        pytest.skip("W5 pending (PR #1151): disputes are not merged. Un-skips when `sigil.governor.billing_reversal` "
                    "lands: a signed `charge.dispute.funds_withdrawn` -> `BillingSigner(..., reversals=ledger)` -> "
                    "`BillingReversalLedger.reconcile(org, purchase, cap=, reason='dispute', disputed=)` removes "
                    "min(disputed, spendable) and books the rest as owed; `LaunchGate.reserve_launch` and "
                    "`extend_reservation` then refuse with the hold (VIGIL_BILLING_REVERSALS on).")
    s, g, ledger, p = _disputed(monkeypatch)
    b = _bal(s, "org_a")
    assert (b.available, ledger.owed("org_a"), ledger.on_hold("org_a")) == (0, 700, True)
    assert ledger.purchase("org_a", p.sid).removed == 1000                # the whole disputed purchase is reversed
    assert b.exact_available_mc >= 0                                      # I2: the debt is arrears, not a wallet
    out = g.reserve_launch(requester="u", org_id="org_a", host=HOST_A, units=mm.allowance_chunk_credits(), now=NOW,
                           depth="quick")
    assert out["ok"] is False and "hold" in out["error"].lower() and "owed" in out["error"].lower(), out
    # every credit in and out is accounted for: bought - reversed - used == wallet - owed (milli-credits)
    used = _statement(s, "org_a")["amount_mc"]
    assert (100 + 1000) * MC_PER_CREDIT - 1000 * MC_PER_CREDIT - used == (
        b.available - ledger.owed("org_a")) * MC_PER_CREDIT - b.remainder_mc


def test_stage_8_the_next_topup_repays_the_arrears_and_lifts_the_hold(monkeypatch):
    """W5 (pending; written to its real interface, PR #1151, not yet run on it). The next top-up first repays what is
    owed (drain-side, exactly once — a re-delivered webhook repays nothing twice), then the hold lifts and a launch
    is admitted again. LIVE today: a top-up simply credits the wallet (stage 2)."""
    if not _merged_w5():
        pytest.skip("W5 pending (PR #1151): repay-then-lift is not merged. Un-skips when a verified top-up through "
                    "`BillingSigner(..., reversals=ledger)` calls `BillingReversalLedger.repay(org, <top-up id>)` "
                    "before the hold is read; this stage then asserts owed -> 0, the hold lifted, a re-delivery inert "
                    "and `LaunchGate.reserve_launch` admitted again.")
    s, g, ledger, _p = _disputed(monkeypatch)
    q = _Purchase(s, "org_a", price="price_topup_10", created=1700, reversals=ledger)
    assert q.pay() is not None                                            # +1,000, of which 700 repay the arrears
    assert (ledger.owed("org_a"), ledger.on_hold("org_a"), _bal(s, "org_a").available) == (0, False, 300)
    q.pay()                                                               # re-delivered: repays nothing twice
    assert (ledger.owed("org_a"), _bal(s, "org_a").available) == (0, 300)
    assert g.reserve_launch(requester="u", org_id="org_a", host=HOST_A, units=mm.allowance_chunk_credits(), now=NOW,
                            depth="quick")["ok"]


@pytest.mark.xfail(condition=_merged_w5(), strict=True, raises=AssertionError,
                   reason="KNOWN GAP at W5 (PR #1151): the reversal is not on the customer statement — W5 leaves "
                          "ui/billing.billing_usage unchanged, so after a dispute the statement's remaining_mc still "
                          "counts the disputed purchase as bought and no longer equals the wallet's exact balance "
                          "(I4). Strict: once the statement shows reversals, this XPASSes and the marker must go.")
def test_stage_8b_the_customer_statement_shows_the_reversal(monkeypatch):
    """I4 after a chargeback: "every credit in and out accounted" ON THE CUSTOMER'S STATEMENT — its remaining credit
    must still be the wallet's exact balance once a purchase was reversed."""
    if not _merged_w5():
        pytest.skip("W5 pending (PR #1151): no reversal exists on this branch to put on the statement.")
    s, _g, _ledger, _p = _disputed(monkeypatch)
    assert _statement(s, "org_a")["remaining_mc"] == _bal(s, "org_a").exact_available_mc


# ============================================================================ STAGE 9 — auto top-up (A1) ===========

def test_stage_9_auto_topup_fires_on_a_low_balance():
    """A1 (§11.13). Armed by the customer (a trigger balance, a catalog pack, a monthly cap, a saved card), a balance
    that crosses below the trigger is topped up OFF-SESSION — exactly once, never above the monthly cap, credit minted
    only by the confirmed webhook — and a credit-paused scan resumes once the payment is confirmed (the W3 hook). OFF
    by default (opt-in, owner-signed). LIVE control: real metered use brings the balance to the low point A1 triggers
    on, and — with NO armed auto top-up — nothing tops it up (byte-identical to pre-A1)."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    _meter_use("org_a", r, mm.Usage(output_tokens=14_400))                # 90 credits of use
    assert _settle_exact(g, "org_a", r)["ok"]
    assert _bal(s, "org_a").available == 10                                # below any trigger; nothing topped it up
    if not _merged_a1():
        pytest.skip("A1 pending: auto top-up is not merged. Un-skips when an armed trigger makes an off-session "
                    "Stripe PaymentIntent on the org's saved PaymentMethod (<= the monthly cap) whose confirmed "
                    "webhook mints a `topup` grant and resumes the org's credit-paused scans (the W3 hook); this "
                    "stage then asserts exactly one capped top-up.")
    # --- A1 merged (§11.13): wired exactly as A1's own suites do (test_billing_auto_topup / test_credit_pause_resume),
    #     over the SAME sovereign money harness the stages above use. An armed low-balance crossing drives exactly ONE
    #     capped off-session top-up; its confirmed webhook mints a `topup` grant; a credit-paused scan then resumes. ---
    from sigil.governor import auto_topup as a1
    from sigil.governor import catalog as cat
    from vigil_integration.live import credit_lease_pause as clp
    pack_id = "vigil_topup_1k"                                            # a catalog TOP-UP pack
    pack_credits = cat.mintable_entitlements()[pack_id].credits
    pack_amount, pack_ccy = cat.mintable_expected()[pack_id]
    cap = pack_credits                                                    # room for EXACTLY one pack this month

    s2 = _store()
    _seat(s2, "org_a", HOST_A, credits=100)                              # a fresh org with its trial credit
    g2 = LaunchGate(s2)
    r2 = _reserve_start(g2, "org_a", HOST_A)                             # the scan holds the whole trial chunk
    _meter_use("org_a", r2, U2502)                                       # it ran, then its prepaid allowance ran dry
    base = os.environ["VIGIL_BASE_DIR"]
    assert g2.record_credit_pause(slug=r2["slug"], nonce=r2["nonce"], now=NOW)["ok"]    # W3: the sovereign credit pause
    assert clp.is_lease_paused(base, r2["slug"], r2["nonce"])
    assert clp.credit_pause_reason(base, r2["slug"], r2["nonce"]) == "insufficient_credits"
    assert _bal(s2, "org_a").available == 0                              # below the trigger; nothing has topped it up

    reg = a1.AutoTopUpRegistry(s2)                                       # owner-signed under the persisted identity
    reg.set_settings("org_a", enabled=True, trigger_credits=50, pack_price_id=pack_id, monthly_cap_credits=cap,
                     issued_at=NOW)
    reg.capture_payment_method("org_a", "cus_wallete2eA1", "pm_wallete2eA1", issued_at=NOW)

    stripe = _A1Stripe(created=int(NOW))                                 # the fake off-session poster (no network/card)
    provider = StripeBillingProvider(_WHSEC, fetcher=stripe.fetch, expected_mode="test",
                                     enable_reference_adapter=True, auto_topup=True,
                                     payment_intent_creator=stripe.create_pi)
    signer = BillingSigner(provider, wallet=WalletRegistry(s2), subscriptions=SubscriptionRegistry(s2),
                           plan=PlanCreditLedger(s2), invoices=InvoiceRegistry(s2),
                           catalog=cat.mintable_entitlements(), expected=cat.mintable_expected(),
                           require_verified_amount=True)
    notes: list = []
    charger = a1.AutoTopUpCharger(reg, WalletRegistry(s2), provider,
                                  notify=lambda org, c: notes.append((org, c.status, c.crossing_key)))

    # 1) the armed crossing drives EXACTLY ONE off-session charge, on the saved card, for the pack, <= the cap
    res = charger.run("org_a", now=NOW)
    assert res.reason == "charged" and res.payment_intent_id.startswith("pi_")
    ((params, _key),) = stripe.pi_calls
    assert params["off_session"] is True and params["confirm"] is True
    assert (params["customer"], params["payment_method"]) == ("cus_wallete2eA1", "pm_wallete2eA1")
    assert (params["amount"], params["currency"]) == (pack_amount, pack_ccy.lower())    # the OWNER CATALOG's amount
    assert params["metadata"]["vigil_auto_topup"] == "1" and params["metadata"]["org_id"] == "org_a"
    (charge,) = reg.charges("org_a")
    assert charge.status == a1.STATUS_CHARGED and charge.credits == pack_credits <= cap
    assert charge.payment_intent_id == res.payment_intent_id
    assert notes == [("org_a", a1.STATUS_CHARGED, charge.crossing_key)]  # one receipt, for this crossing
    assert _bal(s2, "org_a").available == 0                              # the charge call NEVER credits

    # 2) the confirmed webhook mints a `topup` grant; the balance rises by EXACTLY the pack's credits (never above cap)
    assert _a1_webhook(signer, "payment_intent.succeeded", res.payment_intent_id, t=int(NOW)) is not None
    assert _bal(s2, "org_a").available == pack_credits                   # 0 + 1,000
    assert [c for (_at, c, k) in WalletRegistry(s2).purchase_grants("org_a") if k == "topup"] == [pack_credits]

    # 3) idempotent: a re-delivered webhook folds once and a second sweep above the trigger top up NOTHING more
    _a1_webhook(signer, "payment_intent.succeeded", res.payment_intent_id, t=int(NOW), eid="evt_a1_again")
    assert _bal(s2, "org_a").available == pack_credits                   # a redelivery mints no second grant
    assert [c for (_at, c, k) in WalletRegistry(s2).purchase_grants("org_a") if k == "topup"] == [pack_credits]
    assert charger.run("org_a", now=NOW + 1).reason == "above_trigger"   # at/above the trigger: no new charge
    assert len(reg.charges("org_a")) == 1 and len(stripe.pi_calls) == 1  # the top-up stands exactly once

    # 4) the W3 hook: the credit-paused scan RESUMES now that the top-up is confirmed (and not before)
    out = g2.resume_launch(signed_lease=r2["lease"], expect_org_id="org_a", now=NOW)
    assert out["ok"] and out.get("credit_resumed") is True and "expired" not in out, out
    assert not clp.is_lease_paused(base, r2["slug"], r2["nonce"])        # un-parked: the halt is gone ...
    assert clp.credit_pause_reason(base, r2["slug"], r2["nonce"]) is None  # ... and so is the credit-pause record

    # the cap holds a SECOND crossing in the same month: spend back below the trigger -> cap-blocked, no second charge
    WalletRegistry(s2).debit("org_a", _bal(s2, "org_a").available, entry_id="wallet-e2e-a1-spend2", issued_at=NOW)
    assert charger.run("org_a", now=NOW + 2).reason == "cap_exceeded"
    assert len(stripe.pi_calls) == 1                                     # nothing new reached Stripe
    assert [c.status for c in reg.charges("org_a")] == [a1.STATUS_CHARGED, a1.STATUS_CAP_BLOCKED]
    assert reg.month_charged_credits("org_a", NOW) == cap                # CAPPED: one pack this month, never above it


# ============================================================================ STAGE 10 — worker time (W4) =========

def test_stage_10_worker_time_is_metered_on_the_sovereign_side(provider):
    """W4 (pending). Scan-worker time (1 credit per minute, billed per second) is measured on the SOVEREIGN side — a
    grant-authenticated heartbeat to the gateway commits the seconds since the last one into the run's meter (a keyless
    worker never self-reports). LIVE today: the published worker and premium-API rates price correctly (W1)."""
    from vigil_core.rate_card import RateCardError
    assert DEFAULT_RATE_CARD.worker_line(60).amount_mc == 1000             # 1 credit per minute
    assert DEFAULT_RATE_CARD.worker_line(1).amount_mc == 17                # billed per second, rounded up
    with pytest.raises(RateCardError):                                     # an unpriced premium API is never free
        DEFAULT_RATE_CARD.premium_line("unpriced-intel-api", 1)
    if not _merged_w4():
        pytest.skip("W4 pending: worker-time metering is not merged. Un-skips when the gateway serves "
                    "`POST /v1/vigil/worker/heartbeat` (grant-authenticated) committing "
                    "`rate_card.worker_line(seconds)` as a `worker` meter line against the allowance; this stage then "
                    "asserts two heartbeats 60 s apart "
                    "bill exactly 1 credit of 'Scan-worker time' on the same scan's statement.")
    # --- W4 merged (written to the §11.7 spec before W4 had code) ---
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    clock = {"now": NOW + 60}
    server = _gateway(s, provider, clock)
    try:
        token = _token(r)
        assert _call(server, {}, token, path="/v1/vigil/worker/heartbeat")[0] == 200
        clock["now"] += 60
        assert _call(server, {}, token, path="/v1/vigil/worker/heartbeat")[0] == 200
    finally:
        _stop(server)
    assert _settle_exact(g, "org_a", r)["consumed_mc"] == 1000
    assert any(c["operation"] == "Scan-worker time" for c in _statement(s, "org_a")["charges"])


# ============================================================================ THE WHOLE JOURNEY ======================

def test_the_whole_prepaid_journey_over_the_real_edge_and_gateway_reconciles_end_to_end(tmp_path, monkeypatch,
                                                                                         provider):
    """The acceptance run of the merged program, one customer, over the REAL edge -> hop -> provisioner and the REAL
    model gateway: sign up (trial) -> prove a host -> buy (a re-delivered webhook is inert) -> launch with no estimate
    -> metered AI use until the credit runs out (the terminal credit stop) -> pause -> top up -> resume -> the same run
    continues on the same meter -> completion -> the exact settle -> the dashboard and the statement reconcile to the
    milli-credit (I4), never negative at any line (I2), every request billed once (I3), credits only (I5, I10).
    (The dispute / hold / repay legs are stages 7-8 and the auto top-up stage 9 until W5 and A1 merge.)"""
    sov, edge, ep, _sp = _edge_stack(tmp_path, monkeypatch)
    store = sov.store()
    server = None
    try:
        op = _opener()
        org = _signup_operator(op, ep, store, "journey@acme.com")["org_id"]     # sign up: the trial credit
        trial = _edge_billing(op, ep)["credits"]["available"]
        assert trial == config.TRIAL_CREDITS > 0
        _prove_host(store, org, HOST_A)                                          # prove a host (VIGIL's oracle)
        first = _Purchase(store, org, price="price_topup_5", created=int(time.time()))
        assert first.pay() is not None                                           # buy: $5 -> 500 credits
        first.pay()                                                              # Stripe re-delivers it: inert (I3)
        assert _edge_billing(op, ep)["credits"]["available"] == trial + 500
        c, r = _post(op, ep, "/api/customer/launch/reserve", {"host": HOST_A})    # launch: a depth, no estimate
        assert c == 200, (c, r)
        _no_money_or_estimate(r)
        assert _post(op, ep, "/api/customer/launch/start", {"lease": r["lease"]})[0] == 200
        clock = {"now": float(int(time.time()) + 100)}                            # after every grant above
        server = _gateway(store, provider, clock)
        token = _token(r)
        n1, status, headers, _b, _seen = _run_until_refused(server, token, clock)  # metered use, until out of credit
        assert n1 >= 1 and status == 403 and _stop_reason(headers) == STOP_CREDITS_EXHAUSTED
        assert _post(op, ep, "/api/customer/launch/pause", {"lease": r["lease"]})[0] == 200    # (W3: automatic)
        low = _edge_billing(op, ep)["credits"]["available"]
        clock["now"] += 1
        assert _Purchase(store, org, price="price_topup_10", created=int(clock["now"])).pay() is not None
        assert _edge_billing(op, ep)["credits"]["available"] == low + 1000       # shown at once: top up
        assert _post(op, ep, "/api/customer/launch/resume", {"lease": r["lease"]})[0] == 200
        for _ in range(2):                                                       # the same run, same grant + meter
            assert _ask(server, token, clock)[0] == 200
        _stop(server)
        server = None
        w, _again = _completion(store, r, now=clock["now"] + 1)                  # completion: the real drain settles
        assert w.drain()["settled"] == 1
        bill, st = _edge_billing(op, ep), _edge_statement(op, ep)                # the dashboard + the statement
        _no_money_or_estimate(bill)
        _no_money_or_estimate(st)
        exact = _bal(store, org).exact_available_mc
        total_bought = trial + 500 + 1000
        assert len(st["charges"]) == n1 + 2                                       # every admitted request, once (I3)
        assert {(ch["scan"], ch["launch"]) for ch in st["charges"]} == {(r["slug"], r["nonce"])}   # one meter
        assert st["remaining_mc"] == total_bought * MC_PER_CREDIT - st["amount_mc"] == exact       # I4, to the mc
        assert st["charges"][0]["balance_after_mc"] == exact                    # the latest balance-after (I4)
        assert st["available_to_start_mc"] == exact and st["held_mc"] == 0      # nothing running any more
        assert (bill["exact_available_mc"], bill["exact_available"]) == (exact, exact // MC_PER_CREDIT)
        assert exact >= 0 and all(ch["balance_after_mc"] >= 0 for ch in st["charges"])               # I2
    finally:
        if server is not None:
            _stop(server)
        sov.shutdown(); edge.shutdown()


# ============================================================================ two orgs at once (I6) =================

def test_two_orgs_run_concurrently_through_the_gateway_and_their_statements_never_cross(provider):
    """I6 under concurrency, through the REAL gateway: two orgs' runs make requests at the same time; each org's
    statement, exact settle and balance hold ONLY its own usage — one tenant's charges never appear for another."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    _seat(s, "org_b", HOST_B, credits=100)
    g = LaunchGate(s)
    ra, rb = _reserve_start(g, "org_a", HOST_A), _reserve_start(g, "org_b", HOST_B)
    clock = {"now": NOW + 60}
    server = _gateway(s, provider, clock)
    got: dict = {"org_a": [], "org_b": []}
    try:
        def run(org, token, n):
            for _ in range(n):
                got[org].append(_call(server, dict(BODY, model=config.run_model()), token)[0])

        threads = [threading.Thread(target=run, args=("org_a", _token(ra), 3)),
                   threading.Thread(target=run, args=("org_b", _token(rb), 2))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
    finally:
        _stop(server)
    assert got == {"org_a": [200] * 3, "org_b": [200] * 2}
    outa, outb = _settle_exact(g, "org_a", ra), _settle_exact(g, "org_b", rb)
    sa, sb = _statement(s, "org_a"), _statement(s, "org_b")
    assert (len(sa["charges"]), len(sb["charges"])) == (3, 2)
    assert {c["scan"] for c in sa["charges"]} == {ra["slug"]} and {c["scan"] for c in sb["charges"]} == {rb["slug"]}
    assert (sa["amount_mc"], sb["amount_mc"]) == (outa["consumed_mc"], outb["consumed_mc"])
    assert sa["remaining_mc"] == _bal(s, "org_a").exact_available_mc
    assert sb["remaining_mc"] == _bal(s, "org_b").exact_available_mc


# ============================================================================ failure injection =====================

def test_failure_injection_the_gateway_killed_mid_request_never_bills_the_lost_response():
    """I9 + "never waits on a dead one". A request is admitted and forwarded by the LIVE gateway (its write-ahead
    ``open`` carries that gateway's boot id) — the settle waits for it (retry). The gateway process then dies before
    recording the response: the settle records the leftover as an ``orphan`` (unconfirmed spend — VIGIL's cost) and
    charges only the confirmed response."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    _meter_use("org_a", r, U2502)                                          # a confirmed response: 2,502 mc
    live = gw.GrantMeter(config.MODEL_METER_DIR, gateway=True, rate_card=DEFAULT_RATE_CARD)
    try:
        _rid, _res, why = live.reserve(_grant_for("org_a", r), 10 ** 6, 25_000, now=NOW)
        assert why == ""                                                   # admitted, forwarded...
        busy = _settle_exact(g, "org_a", r)
        assert busy["ok"] is False and busy.get("retry"), busy             # in flight on a LIVE gateway: wait
    finally:
        live.shutdown()                                                    # ...the gateway dies before its record
    out = _settle_exact(g, "org_a", r)
    assert out["ok"] and out["consumed_mc"] == 2502, out                   # the lost response is never billed
    assert _bal(s, "org_a").available == 98


def test_failure_injection_a_cutoff_response_bills_only_what_vigil_can_prove():
    """I9. A response cut off mid-stream: the part VIGIL cannot prove (held) is VIGIL's cost, never the customer's."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    _meter_use("org_a", r, U2502)
    _meter_use("org_a", r, mm.Usage(), held=10 ** 9)                       # $1 of unconfirmed provider spend
    out = _settle_exact(g, "org_a", r)
    assert out["consumed_mc"] == 2502 and _bal(s, "org_a").available == 98


def test_failure_injection_a_crash_after_the_settle_decision_finishes_it_exactly_once(monkeypatch):
    """I3. The settle is killed mid-way — after the owner-signed exact decision is recorded, before the wallet grant
    lands. A re-drive, even with another number, finishes the RECORDED decision: the remainder moves once."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    _meter_use("org_a", r, U2502)
    real = WalletRegistry.grant
    calls = {"n": 0}

    def flaky(self, org_id, credits, *a, entry_id=None, **kw):
        if str(entry_id or "").startswith("settle-wallet:") and calls["n"] == 0:
            calls["n"] += 1
            raise OSError("disk went away")
        return real(self, org_id, credits, *a, entry_id=entry_id, **kw)

    monkeypatch.setattr(WalletRegistry, "grant", flaky)
    first = _settle_exact(g, "org_a", r)
    assert first["ok"] is False and first.get("retry"), first
    again = _settle_exact(g, "org_a", r, used=12_345)
    assert again["ok"] and again.get("rolled_forward"), again
    assert (again["net_spend"], again["consumed_mc"], again["remainder_mc"]) == (2, 2502, 502)
    assert (_bal(s, "org_a").available, _bal(s, "org_a").remainder_mc) == (98, 502)


def test_failure_injection_a_duplicate_completion_signal_settles_once():
    """I3. The run's completion arrives twice through the REAL completion-spool drain: it settles exactly once."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    r = _reserve_start(g, "org_a", HOST_A)
    _meter_use("org_a", r, U2502)
    w, again = _completion(s, r)
    assert w.drain()["settled"] == 1
    assert (_bal(s, "org_a").available, _bal(s, "org_a").remainder_mc) == (98, 502)
    again()
    assert w.drain()["settled"] == 0                                       # the duplicate settles nothing
    assert (_bal(s, "org_a").available, _bal(s, "org_a").remainder_mc) == (98, 502)


# ============================================================================ I1 - I10, named =======================

def test_invariants_I1_to_I10_hold_across_the_metered_lifecycle(monkeypatch):
    """One explicit pass over the §11.4 invariants on the merged metered lifecycle (the stages above drive each one
    end to end; this is the checklist)."""
    s = _store()
    _seat(s, "org_a", HOST_A, credits=100)
    g = LaunchGate(s)
    before = _bal(s, "org_a").available
    r = _reserve_start(g, "org_a", HOST_A)
    # I1 — credit is reserved BEFORE any billable work: the launch holds its allowance from the wallet
    assert int(r["units_reserved"]) > 0 and _bal(s, "org_a").available == before - int(r["units_reserved"])
    # I9 — limits are enforced in code: an extension past the spendable balance is refused, nothing drawn
    sp = _bal(s, "org_a").spendable
    assert g.extend_reservation(org_id="org_a", slug=r["slug"], nonce=r["nonce"], credits=sp + 10,
                                now=NOW)["ok"] is False
    assert _bal(s, "org_a").spendable == sp
    _meter_use("org_a", r, U2502)
    out = _settle_exact(g, "org_a", r)
    b = _bal(s, "org_a")
    st = _statement(s, "org_a")
    # I2 — never negative, in the wallet and at every statement line
    assert b.exact_available_mc >= 0 and all(c["balance_after_mc"] >= 0 for c in st["charges"])
    # I3 — one settle per (slug, nonce): settling the same launch again, with any number, moves nothing
    g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=99_999, now=NOW, expect_org_id="org_a")
    assert _bal(s, "org_a") == b
    # I4 — the statement, the settle and the wallet agree to the milli-credit
    assert st["amount_mc"] == out["consumed_mc"] == 2502
    assert st["remaining_mc"] == b.exact_available_mc == st["charges"][0]["balance_after_mc"]
    # I5 + I10 — credits only, no estimate / money / model, no internal provider cost, on every billing surface
    for blob in (st, ui_billing.billing_rates(), ui_billing.billing_overview(s, "org_a", now=NOW)):
        _no_money_or_estimate(blob)
    # I6 — tenant scope: another org's statement is empty and its wallet untouched
    assert _statement(s, "org_b")["charges"] == [] and _bal(s, "org_b").available == 0
    # I7 — default OFF and byte-identical when off: none of the metered (W2c-2) fields appear with the flag off
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    flat_st, flat_ov = _statement(s, "org_a"), ui_billing.billing_overview(s, "org_a", now=NOW)
    assert not {"remaining_mc", "available_to_start_mc", "held_mc"} & set(flat_st)
    assert all("balance_after_mc" not in c for c in flat_st["charges"])
    assert not {"exact_available_mc", "exact_available"} & set(flat_ov)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    # I8 — fail closed on ambiguity: a malformed rate card at completion DEFERS the settle (no charge on a guess)
    s2 = _store()
    _seat(s2, "org_a", HOST_A, credits=100)
    r2 = _reserve_start(LaunchGate(s2), "org_a", HOST_A)
    _meter_use("org_a", r2, U2502)
    w, _again = _completion(s2, r2)
    monkeypatch.setenv("VIGIL_RATE_CARD", "{not json")
    deferred = w.drain()
    assert (deferred["settled"], deferred.get("deferred")) == (0, 1) and deferred.get("deferred_config"), deferred
    assert _bal(s2, "org_a").available == 0                                 # still held: nothing refunded or charged
    monkeypatch.delenv("VIGIL_RATE_CARD")
    assert w.drain()["settled"] == 1 and _bal(s2, "org_a").available == 98
