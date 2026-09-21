"""
VF-2b for the REMOTE OOB relay (FACT-coverage Wave 1.2).

The loopback receiver already reached the VF-2b tier (an independent collector signs each hit's receipt and
a verifier pins the collector pubkey out-of-band). This suite proves the SAME tier now holds for the
operator-hosted RelayServer/RelayClient:

  * GAP B — the relay SIGNS each recorded interaction as observed, mirroring oob._OOBHTTPServer._record, so a
    RelayClient poll returns a hit whose collector receipt verifies under the pinned collector pubkey.
  * GAP A — the verifier reads the collector pin from an OUT-OF-BAND authority (its own attribute), never
    from the producer-controlled context; a wrong/blank pin does not mint, and a REMOTE relay is fail-closed
    to VF-2b (a remote RelayClient without a pin refuses to construct).
  * make gate byte-identical: with no keypair minted and no pin, the flow stays at the exact VF-2a token-only
    behavior (the default/benchmark path is untouched).

This is a DEDICATED loopback harness — it is NOT wired into the signed recall corpus / benchmark app (whose
SCOPE is explicitly "no OOB collaborator"), so it exercises VF-2b end-to-end without perturbing `make gate`.
All traffic is loopback; the relay plays the role of the operator's allowlisted host.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from vigil_core import generate_keypair

from framework.v2.scanner.checks import OOBCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.collaborator import RelayClient, RelayServer
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.oob import OOBReceiver, verify_oob_receipt
from framework.v2.verify.verifier import OracleVerifier


def _fetch(url: str) -> None:
    try:
        urllib.request.urlopen(url, timeout=5).read()  # noqa: S310 (loopback)
    except urllib.error.URLError:
        pass


def _ssrf_send(req: HttpRequest) -> dict:
    """A `send` that models a server-side fetch of whatever URL is injected (the blind SSRF sink)."""
    from urllib.parse import parse_qs, urlsplit
    injected = parse_qs(urlsplit(req.url).query).get("url", [""])[0]
    if injected.startswith("http"):
        _fetch(injected)  # the target dereferences the attacker URL → the relay records it
    return {"status": 200, "body": "ok"}


def _ssrf_point() -> tuple[RequestTemplate, object]:
    tmpl = RequestTemplate(HttpRequest(method="GET", url="http://target.example/f?url=x"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "url"]
    return tmpl, pt


# --------------------------------------------------------------------------- GAP B: the relay signs


def test_relay_signs_receipts_that_verify_under_the_pinned_pubkey() -> None:
    """A RelayClient poll returns a hit whose collector_sig verifies under the collector pubkey the
    RelayServer minted — and NOT under any other key. This is the loopback receiver's signing pattern,
    now realised on the remote relay."""
    kp, attacker = generate_keypair(), generate_keypair()
    with RelayServer(secret="k", collector_keypair=kp) as relay:
        assert relay.collector_pubkey == kp.public_key_b64
        client = RelayClient(relay.base_url, "k", collector_pubkey=kp.public_key_b64)
        token, callback = client.register_token()
        _fetch(f"{callback}/probe?x=1")
        (hit,) = client.poll(token)
        assert hit.collector_sig                                            # the relay signed a receipt
        assert verify_oob_receipt(hit, collector_pubkey=kp.public_key_b64)  # verifies vs the minted key
        assert not verify_oob_receipt(hit, collector_pubkey=attacker.public_key_b64)  # not vs another key
        assert not verify_oob_receipt(hit, collector_pubkey="")            # empty pin → fail-closed


def test_relay_without_collector_key_emits_no_receipt() -> None:
    """No collector keypair → VF-2a token-only: the relay records but does not sign, so no receipt verifies."""
    with RelayServer(secret="k") as relay:
        assert relay.collector_pubkey is None
        client = RelayClient(relay.base_url, "k")   # loopback → pin not required
        token, callback = client.register_token()
        _fetch(f"{callback}/x")
        (hit,) = client.poll(token)
        assert hit.collector_sig == ""
        assert not verify_oob_receipt(hit, collector_pubkey="anything")


# --------------------------------------------------------------------------- GAP A: verifier pins out-of-band


def test_remote_oob_fact_mints_only_with_the_correct_out_of_band_pin() -> None:
    """A fired OOB FACT rides the relay-signed receipt ONLY when the verifier's out-of-band pin matches the
    relay's collector key. A wrong pin (a dishonest producer's own key) does NOT mint."""
    kp, attacker = generate_keypair(), generate_keypair()
    with RelayServer(secret="k", collector_keypair=kp) as relay:
        client = RelayClient(relay.base_url, "k", collector_pubkey=kp.public_key_b64)
        check = OOBCheck(id="ssrf-oob", bug_class="ssrf", payload_template="{callback}")
        tmpl, pt = _ssrf_point()
        ctx = check.probe(tmpl, pt, _ssrf_send, client)
        assert ctx is not None
        finding = {"bug_class": "ssrf", "title": "t", "severity": "High", "surface": "s", "summary": "x"}

        # correct pin (out-of-band authority) → VF-2b FACT
        good = confirm_finding(finding, context=ctx,
                               verifier=OracleVerifier(oob_collector_pubkey=kp.public_key_b64))
        assert good is not None and good.confirmed_by.value == "oob_callback"

        # wrong pin → the relay-signed receipt does not verify → not fired → no FACT
        bad = confirm_finding(finding, context=ctx,
                              verifier=OracleVerifier(oob_collector_pubkey=attacker.public_key_b64))
        assert bad is None

        # blank pin → F4 requested with a bad key → fail-closed (NOT a silent drop to token-only) → no FACT
        blank = confirm_finding(finding, context=ctx,
                                verifier=OracleVerifier(oob_collector_pubkey="   "))
        assert blank is None


def test_default_no_pin_stays_vf2a_token_only_byte_identical() -> None:
    """The DEFAULT path: no collector keypair minted, verifier constructed with NO pin → the exact current
    VF-2a token-only behavior mints, so the benchmark/make-gate path is unchanged."""
    with RelayServer(secret="k") as relay:            # no collector keypair
        client = RelayClient(relay.base_url, "k")     # loopback, no pin
        check = OOBCheck(id="ssrf-oob", bug_class="ssrf", payload_template="{callback}")
        tmpl, pt = _ssrf_point()
        ctx = check.probe(tmpl, pt, _ssrf_send, client)
        assert ctx is not None
        confirmed = confirm_finding(
            finding={"bug_class": "ssrf", "title": "t", "severity": "High", "surface": "s", "summary": "x"},
            context=ctx, verifier=OracleVerifier(),   # oob_collector_pubkey defaults to None → VF-2a
        )
        assert confirmed is not None and confirmed.confirmed_by.value == "oob_callback"


# --------------------------------------------------------------------------- fail-closed remote-without-pin


def test_remote_relay_without_pin_refuses_to_construct() -> None:
    """A REMOTE (non-loopback) relay MUST carry an out-of-band collector pin — remote OOB is VF-2b by
    construction, never a silent drop to the forgeable token-only tier. A loopback relay may omit it."""
    with pytest.raises(ValueError):
        RelayClient("https://relay.op.example", "k")                       # remote, no pin → refused
    RelayClient("https://relay.op.example", "k", collector_pubkey="pinned")  # remote + pin → OK
    RelayClient("http://127.0.0.1:9000", "k")                              # loopback, no pin → OK


# --------------------------------------------------------------------------- DNS-only is INCONCLUSIVE


def test_dns_only_interaction_is_inconclusive() -> None:
    """The relay is HTTP-only. A blind class that triggers only a DNS lookup (no HTTP fetch of the callback)
    leaves the relay with no recorded interaction → no oob_hits → the oracle does not fire → no FACT
    (INCONCLUSIVE, never CLEAN)."""
    kp = generate_keypair()
    with RelayServer(secret="k", collector_keypair=kp) as relay:
        client = RelayClient(relay.base_url, "k", collector_pubkey=kp.public_key_b64)
        check = OOBCheck(id="ssrf-oob", bug_class="ssrf", payload_template="{callback}")
        tmpl, pt = _ssrf_point()

        def dns_only_send(req: HttpRequest) -> dict:
            # models a target that resolves the callback host but performs NO HTTP fetch
            return {"status": 200, "body": "ok"}

        ctx = check.probe(tmpl, pt, dns_only_send, client)
        confirmed = (
            confirm_finding(
                finding={"bug_class": "ssrf", "title": "t", "severity": "High", "surface": "s", "summary": "x"},
                context=ctx, verifier=OracleVerifier(oob_collector_pubkey=kp.public_key_b64))
            if ctx is not None else None
        )
        assert confirmed is None


# --------------------------------------------------------------------------- loopback VF-2b end-to-end


def test_loopback_receiver_vf2b_end_to_end() -> None:
    """The loopback OOBReceiver, given a collector keypair, mints a VF-2b FACT end-to-end when the verifier
    pins its collector pubkey — the co-resident-target harness the campaign now wires (opt-in)."""
    kp = generate_keypair()
    with OOBReceiver(collector_keypair=kp) as oob:
        check = OOBCheck(id="ssrf-oob", bug_class="ssrf", payload_template="{callback}")
        tmpl, pt = _ssrf_point()
        ctx = check.probe(tmpl, pt, _ssrf_send, oob)
        assert ctx is not None
        confirmed = confirm_finding(
            finding={"bug_class": "ssrf", "title": "t", "severity": "High", "surface": "s", "summary": "x"},
            context=ctx, verifier=OracleVerifier(oob_collector_pubkey=oob.collector_pubkey),
        )
        assert confirmed is not None and confirmed.confirmed_by.value == "oob_callback"
