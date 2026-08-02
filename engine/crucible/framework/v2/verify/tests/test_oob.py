"""Tests for verify.oob — real localhost callback round-trips via urllib."""

from __future__ import annotations

import urllib.request

import pytest

from ..oob import OOBReceiver, _token_of


def _get(url: str, data: bytes | None = None) -> int:
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()
        return resp.status


def test_binds_loopback_only() -> None:
    with pytest.raises(ValueError):
        OOBReceiver(host="0.0.0.0")


def test_token_extraction() -> None:
    assert _token_of("/abc123/foo?x=1") == "abc123"
    assert _token_of("/abc123") == "abc123"
    assert _token_of("/") == ""


def test_roundtrip_records_hit() -> None:
    with OOBReceiver() as oob:
        assert oob.base_url.startswith("http://127.0.0.1:")
        token, url = oob.register_token()
        assert oob.poll(token) == []  # registered but not yet hit

        status = _get(url)
        assert status == 200

        hits = oob.poll(token)
        assert len(hits) == 1
        assert hits[0].token == token
        assert hits[0].method == "GET"
        assert hits[0].client_ip == "127.0.0.1"


def test_roundtrip_with_path_and_query_dns_style() -> None:
    with OOBReceiver() as oob:
        token, url = oob.register_token()
        _get(f"{url}/exfil/data?leak=secret")
        hits = oob.poll(token)
        assert len(hits) == 1
        assert hits[0].path == f"/{token}/exfil/data"
        assert hits[0].query == "leak=secret"


def test_post_with_body_is_recorded() -> None:
    with OOBReceiver() as oob:
        token, url = oob.register_token()
        _get(url, data=b"blind-payload-callback")
        hits = oob.poll(token)
        assert len(hits) == 1
        assert hits[0].method == "POST"


def test_multiple_hits_accumulate() -> None:
    with OOBReceiver() as oob:
        token, url = oob.register_token()
        for _ in range(3):
            _get(url)
        assert len(oob.poll(token)) == 3


def test_tokens_are_isolated() -> None:
    with OOBReceiver() as oob:
        t1, u1 = oob.register_token()
        t2, _ = oob.register_token()
        assert t1 != t2
        _get(u1)
        assert len(oob.poll(t1)) == 1
        assert oob.poll(t2) == []


def test_unregistered_token_polls_empty() -> None:
    with OOBReceiver() as oob:
        assert oob.poll("never-registered") == []


def test_server_stops_cleanly() -> None:
    oob = OOBReceiver().start()
    token, url = oob.register_token()
    _get(url)
    oob.stop()
    # After stop, accessing the port raises rather than silently listening.
    with pytest.raises(RuntimeError):
        oob.register_token()


# ============================ VF-2b: the independent, receipt-signing collector ============================
def test_collector_signs_receipts_that_verify_against_its_pinned_key() -> None:
    from vigil_core import generate_keypair

    from ..oob import verify_oob_receipt
    kp, attacker = generate_keypair(), generate_keypair()
    with OOBReceiver(collector_keypair=kp) as oob:
        assert oob.collector_pubkey == kp.public_key_b64
        token, url = oob.register_token()
        _get(url)  # a real inbound loopback interaction the collector observes + signs
        hits = [h.model_dump() for h in oob.poll(token)]
        assert hits and hits[0]["collector_sig"]                       # the collector signed a receipt
        assert verify_oob_receipt(hits[0], collector_pubkey=kp.public_key_b64)          # verifies vs its key
        assert not verify_oob_receipt(hits[0], collector_pubkey=attacker.public_key_b64)  # not vs another key
        assert not verify_oob_receipt(hits[0], collector_pubkey="")                     # empty pin → fail-closed


def test_receiver_without_collector_key_emits_no_receipt() -> None:
    from ..oob import verify_oob_receipt
    with OOBReceiver() as oob:            # no collector key → VF-2a tier only
        token, url = oob.register_token()
        _get(url)
        hits = [h.model_dump() for h in oob.poll(token)]
        assert hits and hits[0]["collector_sig"] == ""
        assert oob.collector_pubkey is None
        assert not verify_oob_receipt(hits[0], collector_pubkey="anything")


def test_tampered_receipt_core_fails_verification() -> None:
    from vigil_core import generate_keypair

    from ..oob import verify_oob_receipt
    kp = generate_keypair()
    with OOBReceiver(collector_keypair=kp) as oob:
        token, url = oob.register_token()
        _get(url)
        hit = oob.poll(token)[0].model_dump()
    assert verify_oob_receipt(hit, collector_pubkey=kp.public_key_b64)
    hit["client_ip"] = "9.9.9.9"          # edit a signed receipt field after the fact
    assert not verify_oob_receipt(hit, collector_pubkey=kp.public_key_b64)


def test_oracle_f4_requires_a_receipt_verifying_against_the_pinned_collector_key() -> None:
    # The end-to-end F4 guarantee: a fully-dishonest producer who fabricates the whole context cannot make the
    # oracle fire against a collector key PINNED out-of-band that it does not hold.
    from vigil_core import generate_keypair

    from ..oracles import oob_callback_oracle
    kp, attacker = generate_keypair(), generate_keypair()
    with OOBReceiver(collector_keypair=kp) as oob:
        token, url = oob.register_token()
        _get(url)
        hits = [h.model_dump() for h in oob.poll(token)]
    # real receipt + real pinned key → F4 fired
    sig = oob_callback_oracle(hits, token, kp.public_key_b64)
    assert sig.fired and sig.observed.get("receipt_verified") is True
    # real receipt but WRONG pinned key (producer substituted its own) → not fired
    assert not oob_callback_oracle(hits, token, attacker.public_key_b64).fired
    # fabricated hit (right token, made-up receipt, no collector key) vs the real pinned key → not fired
    forged = [{"token": token, "method": "GET", "path": "/" + token, "client_ip": "1.2.3.4",
               "received_at": 1.0, "collector_sig": "AAAA"}]
    assert not oob_callback_oracle(forged, token, kp.public_key_b64).fired
    # VF-2a tier still available (no collector pin) — token-only fire, receipt not claimed
    tier = oob_callback_oracle(hits, token)
    assert tier.fired and tier.observed.get("receipt_verified") is False
