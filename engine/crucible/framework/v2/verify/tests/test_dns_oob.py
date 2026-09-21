"""
DNS out-of-band collector + token TTL/replay (FACT-coverage Wave 1 DNS-OOB).

The HTTP collaborator confirms a blind class only when the target completes an outbound HTTP fetch. A
hardened target blocks outbound HTTP yet its internal resolver still forwards DNS, so a blind callback to
``<token>.<base-domain>`` triggers a DNS lookup that reaches the authoritative nameserver we control. This
suite proves that lookup is a signed, offline-re-verifiable OOB FACT — reusing the SAME oob_callback oracle
+ verify_oob_receipt with NO oracle change:

  * a "target" that RESOLVES ``<token>.<base-domain>`` against a loopback DNS collector → a signed FACT that
    re-verifies OFFLINE via OOB_CALLBACK (VF-2b),
  * a NO-lookup control → INCONCLUSIVE (never confirmed),
  * a STALE receipt (received_at outside the mint TTL window) → EXPIRED / REPLAY, not fired, live AND offline,
  * VF-2b: a wrong / absent pinned collector pubkey → not fired,
  * a name OUTSIDE the base domain → ignored (never recorded),
  * the default (windowless) oracle path stays byte-identical.

All traffic is loopback; a direct UDP DNS query plays the role of the target's recursive resolver.
"""

from __future__ import annotations

import socket
import struct
import time

import pytest

from vigil_core import generate_keypair

from framework.v2.scanner.checks import DNS_RCE_OOB, DNS_SSRF_OOB, DNSOOBCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.dns_collector import (
    DNSCollector,
    _build_response,
    _decode_qname,
    _extract_token,
    _parse_query,
)
from framework.v2.verify.oob import OOBHit, sign_oob_receipt, verify_oob_receipt
from framework.v2.verify.oracles import oob_callback_oracle
from framework.v2.verify.verifier import OracleVerifier, _ALL_ORACLES

_BASE = "oob.op.example"


def _authority(*, http_pin: str = "", dns_pin: str = "", ttl: float = 300.0, skew: float = 5.0):
    """An EngagementAuthority carrying the OUT-OF-BAND OOB pins + owner-signed TTL/skew, for building an
    offline-reverify verifier (verifier_from_authority) — the material the CLI sources from the SIGNED
    authority. Not itself signed here; the signed-load CLI path is exercised in test_oob_offline_reverify."""
    from datetime import datetime, timedelta, timezone

    from vigil_core.authority import EngagementAuthority, TargetEnvironment
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    return EngagementAuthority(
        engagement_slug="eng", environment=TargetEnvironment.TWIN, scope=["*.example.com"],
        not_before=now - timedelta(hours=1), not_after=now + timedelta(hours=1),
        oob_collector_pubkey=http_pin, oob_dns_collector_pubkey=dns_pin,
        oob_ttl_seconds=ttl, oob_skew_seconds=skew)


# --------------------------------------------------------------------------- raw DNS helpers


def _build_query(qname: str, txn_id: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)  # RD set, one question
    body = b""
    for label in qname.rstrip(".").split("."):
        body += bytes([len(label)]) + label.encode("ascii")
    body += b"\x00" + struct.pack("!HH", 1, 1)  # QTYPE A, QCLASS IN
    return header + body


def _resolve(host: str, port: int, qname: str) -> bytes:
    """Play the target's resolver: send a DNS query for ``qname`` and return the response bytes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(_build_query(qname), (host, port))
        data, _ = sock.recvfrom(2048)
        return data
    finally:
        sock.close()


def _poll_until(coll: DNSCollector, token: str, deadline_s: float = 2.0):
    end = time.monotonic() + deadline_s
    hits = coll.poll(token)
    while not hits and time.monotonic() < end:
        time.sleep(0.02)
        hits = coll.poll(token)
    return hits


# --------------------------------------------------------------------------- pure decode/encode


def test_qname_roundtrip_and_token_extraction() -> None:
    tok = "a" * 32
    q = _build_query(f"{tok}.{_BASE}")
    txn_id, flags, qname, qend, qtype, qclass = _parse_query(q)
    assert qname == f"{tok}.{_BASE}"
    assert qtype == 1 and qclass == 1
    base_labels = _BASE.split(".")
    assert _extract_token(qname, base_labels) == tok
    # a name NOT under the base domain yields no token
    assert _extract_token("evil.attacker.test", base_labels) is None
    # the base domain itself carries no token
    assert _extract_token(_BASE, base_labels) is None


def test_compression_pointer_in_question_is_refused() -> None:
    # a question must not contain a compression pointer (top two bits set) — we refuse rather than follow it
    bad = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    with pytest.raises(ValueError):
        _parse_query(bad)


def test_response_is_authoritative_a_record() -> None:
    q = _build_query(f"{'b'*32}.{_BASE}")
    _id, flags, _qn, qend, _qt, _qc = _parse_query(q)
    resp = _build_response(q, _id, flags, qend, answer_ip="127.0.0.1")
    rid, rflags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    assert rid == _id
    assert rflags & 0x8000            # QR (response)
    assert rflags & 0x0400            # AA (authoritative)
    assert (rflags & 0x000F) == 0     # RCODE NOERROR
    assert qd == 1 and an == 1        # question echoed, one answer
    # NXDOMAIN form
    nx = _build_response(q, _id, flags, qend, answer_ip=None)
    _r, nxflags, _qd, nxan, _ns, _ar = struct.unpack("!HHHHHH", nx[:12])
    assert (nxflags & 0x000F) == 3 and nxan == 0


# --------------------------------------------------------------------------- live collector end-to-end


def test_dns_lookup_mints_a_signed_fact_that_reverifies_offline() -> None:
    kp = generate_keypair()
    with DNSCollector(_BASE, collector_keypair=kp) as coll:
        token, host = coll.register_dns_token()
        assert host == f"{token}.{_BASE}"
        assert coll.collector_pubkey == kp.public_key_b64
        resp = _resolve("127.0.0.1", coll.port, host)     # the resolver forwards the lookup to us
        assert len(resp) >= 12
        (hit,) = _poll_until(coll, token)
        # recorded as a DNS observation, signed VF-2b as-observed over target-observed facts only
        assert hit.method == "DNS" and hit.path == host and hit.token == token
        assert hit.collector_sig
        assert verify_oob_receipt(hit, collector_pubkey=kp.public_key_b64)

        # the SAME oracle confirms with the DNS pin + a bound window (VF-2b pin out-of-band)
        sig = oob_callback_oracle([hit], token, dns_collector_pubkey=kp.public_key_b64,
                                  issued_at=time.time() - 1, authority_ttl=300.0)
        assert sig.fired and sig.confidence >= 0.95

        # offline re-verify from the SERIALIZED finding via the REAL reverify path (NOT a hand-passed live
        # verifier) — the DNS pin + TTL policy are sourced from a (signed) authority via verifier_from_authority.
        from framework.v2.verify.adapter import FindingContext
        from framework.v2.verify.reverify import reverify_finding, verifier_from_authority
        ctx = FindingContext.from_oob([hit], bug_class="ssrf", expected_token=token,
                                      issued_at=time.time() - 1, expires_at=time.time() + 300)
        finding = {"bug_class": "ssrf", "oracle_context": ctx.model_dump(mode="json"),
                   "confirmed_by": "oob_callback", "confidence": 0.95}
        v = verifier_from_authority(_authority(dns_pin=kp.public_key_b64))
        r = reverify_finding(finding, verifier=v)
        assert r.reproduced and r.confirmed_by == "oob_callback"
        # ... and WITHOUT the pin (no authority material) it fails CLOSED, not a token-only drop.
        assert not reverify_finding(finding).reproduced


def test_no_lookup_control_is_inconclusive() -> None:
    kp = generate_keypair()
    with DNSCollector(_BASE, collector_keypair=kp) as coll:
        token, _host = coll.register_dns_token()
        # NO resolution happens
        hits = coll.poll(token)
        assert hits == []
        sig = oob_callback_oracle(hits, token, collector_pubkey=kp.public_key_b64)
        assert not sig.fired          # absence of a lookup is uninformative → never confirmed


def test_name_outside_base_domain_is_ignored() -> None:
    kp = generate_keypair()
    with DNSCollector(_BASE, collector_keypair=kp) as coll:
        token, _host = coll.register_dns_token()
        # resolve an unrelated name that carries the token as a label but NOT under the base domain
        _resolve("127.0.0.1", coll.port, f"{token}.attacker.test")
        time.sleep(0.2)
        assert coll.poll(token) == []   # refused: not under the configured base domain


def test_unregistered_names_under_base_domain_are_not_recorded() -> None:
    """DoS bound: the public :53 listener records ONLY names whose token was register_dns_token'd. An
    arbitrary label under the base domain (which any internet host can query) is dropped, so the hit registry
    cannot grow without bound on unregistered names."""
    with DNSCollector(_BASE) as coll:
        # A batch of DISTINCT unregistered labels under the base domain — never minted by us.
        for i in range(50):
            _resolve("127.0.0.1", coll.port, f"unregistered{i}{'a' * 20}.{_BASE}")
        time.sleep(0.2)
        server = coll._server                              # type: ignore[attr-defined]
        with server._lock:                                # noqa: SLF001
            assert server._hits == {}                     # nothing recorded for any unregistered name
        # A REGISTERED token IS recorded (the gate does not break the real path).
        token, host = coll.register_dns_token()
        _resolve("127.0.0.1", coll.port, host)
        assert _poll_until(coll, token)


def test_registered_token_hits_are_capped() -> None:
    """Even a REGISTERED token's bucket is bounded (its callback label is visible on the wire), so a flood
    against a known token cannot grow the registry without bound."""
    from framework.v2.verify.dns_collector import _MAX_HITS_PER_TOKEN
    with DNSCollector(_BASE) as coll:
        token, host = coll.register_dns_token()
        for _ in range(_MAX_HITS_PER_TOKEN + 25):
            _resolve("127.0.0.1", coll.port, host)
        time.sleep(0.3)
        assert len(coll.poll(token)) <= _MAX_HITS_PER_TOKEN


def test_probe_via_dnsoobcheck_against_a_resolving_target() -> None:
    """DNS_SSRF_OOB drives a 'target' whose send() resolves the injected callback host — the scanner-side
    integration, end to end, minting a FACT through the check → oracle path."""
    kp = generate_keypair()
    with DNSCollector(_BASE, collector_keypair=kp) as coll:
        def _send(req: HttpRequest) -> dict:
            # model a blind SSRF: the target resolves the host inside the injected URL (HTTP egress blocked,
            # but DNS resolution still fires)
            from urllib.parse import parse_qs, urlsplit
            injected = parse_qs(urlsplit(req.url).query).get("url", [""])[0]
            host = urlsplit(injected).hostname
            if host and host.endswith(_BASE):
                _resolve("127.0.0.1", coll.port, host)
            return {"status": 500, "body": "blocked"}

        tmpl = RequestTemplate(HttpRequest(method="GET", url=f"http://target.example/f?url=x"))
        (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "url"]
        ctx = DNS_SSRF_OOB.probe(tmpl, pt, _send, coll)
        assert ctx is not None
        # A DNS observation is re-verified against the DNS pin (method == "DNS"); the HTTP pin does NOT apply.
        v = OracleVerifier(oob_dns_collector_pubkey=kp.public_key_b64)
        finding = {"bug_class": "ssrf", "title": "t", "severity": "High", "surface": "s", "summary": "x"}
        good = confirm_finding(finding, context=ctx, verifier=v)
        assert good is not None and good.confirmed_by.value == "oob_callback"
        # the HTTP pin does not verify a DNS receipt → fail-closed (channel-correct pin required)
        assert confirm_finding(finding, context=ctx,
                               verifier=OracleVerifier(oob_collector_pubkey=kp.public_key_b64)) is None


# --------------------------------------------------------------------------- VF-2b


def test_vf2b_wrong_or_absent_pin_does_not_fire() -> None:
    kp, attacker = generate_keypair(), generate_keypair()
    with DNSCollector(_BASE, collector_keypair=kp) as coll:
        token, host = coll.register_dns_token()
        _resolve("127.0.0.1", coll.port, host)
        (hit,) = _poll_until(coll, token)
        win = dict(issued_at=time.time() - 1.0, authority_ttl=300.0)
        # DNS receipts verify against the DNS pin (method == "DNS"); a bound window is required.
        assert oob_callback_oracle([hit], token, dns_collector_pubkey=kp.public_key_b64, **win).fired
        assert not oob_callback_oracle([hit], token, dns_collector_pubkey=attacker.public_key_b64, **win).fired
        assert not oob_callback_oracle([hit], token, dns_collector_pubkey="", **win).fired   # blank pin fail-closed
        # A receipt-bearing DNS hit with NO pin at all is FAIL-CLOSED (the offline fail-open fix), never token-only.
        refused = oob_callback_oracle([hit], token, **win)
        assert not refused.fired and refused.observed.get("oob_verdict") == "UNVERIFIABLE_RECEIPT"


def test_unsigned_dns_collector_is_vf2a_only() -> None:
    with DNSCollector(_BASE) as coll:            # no collector keypair
        assert coll.collector_pubkey is None
        token, host = coll.register_dns_token()
        _resolve("127.0.0.1", coll.port, host)
        (hit,) = _poll_until(coll, token)
        assert hit.collector_sig == ""
        # No receipt ⇒ genuine VF-2a token-only: token-only fires; demanding a receipt (any pin) fails-closed.
        assert oob_callback_oracle([hit], token).fired
        assert not oob_callback_oracle([hit], token, dns_collector_pubkey="anything").fired


# --------------------------------------------------------------------------- TTL / replay


def _signed_hit(kp, token: str, received_at: float) -> OOBHit:
    hit = OOBHit(token=token, method="DNS", path=f"{token}.{_BASE}", query="",
                 client_ip="10.0.0.53", received_at=received_at)
    hit.collector_sig = sign_oob_receipt(kp.private_key_b64, hit)
    return hit


def test_stale_receipt_after_window_is_replay_not_fired() -> None:
    kp = generate_keypair()
    issued = 1_000_000.0
    hit = _signed_hit(kp, "t" * 32, received_at=issued + 300.0 + 3600.0)   # long after the authority window
    assert verify_oob_receipt(hit, collector_pubkey=kp.public_key_b64)   # signature is valid
    sig = oob_callback_oracle([hit], "t" * 32, dns_collector_pubkey=kp.public_key_b64,
                              issued_at=issued, authority_ttl=300.0)
    assert not sig.fired
    assert sig.observed["oob_verdict"] == "REPLAY"


def test_receipt_before_window_is_expired_not_fired() -> None:
    kp = generate_keypair()
    issued = 1_000_000.0
    hit = _signed_hit(kp, "t" * 32, received_at=issued - 3600.0)    # arrived before the window opened
    sig = oob_callback_oracle([hit], "t" * 32, dns_collector_pubkey=kp.public_key_b64,
                              issued_at=issued, authority_ttl=300.0)
    assert not sig.fired
    assert sig.observed["oob_verdict"] == "EXPIRED"


def test_receipt_inside_window_fires() -> None:
    kp = generate_keypair()
    issued = 1_000_000.0
    hit = _signed_hit(kp, "t" * 32, received_at=issued + 100.0)     # comfortably inside
    sig = oob_callback_oracle([hit], "t" * 32, dns_collector_pubkey=kp.public_key_b64,
                              issued_at=issued, authority_ttl=300.0)
    assert sig.fired and sig.observed["oob_verdict"] == "VERIFIED"


def test_skew_tolerance_at_the_edge() -> None:
    kp = generate_keypair()
    issued = 1_000_000.0
    # authority TTL 300s + default skew 5s → window closes at issued+305. 302s past issue → still fires.
    hit = _signed_hit(kp, "t" * 32, received_at=issued + 302.0)
    assert oob_callback_oracle([hit], "t" * 32, dns_collector_pubkey=kp.public_key_b64,
                               issued_at=issued, authority_ttl=300.0).fired
    # 310s past issue, beyond skew → REPLAY
    hit2 = _signed_hit(kp, "t" * 32, received_at=issued + 310.0)
    assert not oob_callback_oracle([hit2], "t" * 32, dns_collector_pubkey=kp.public_key_b64,
                                   issued_at=issued, authority_ttl=300.0).fired


def test_producer_widened_window_is_ignored_authority_ttl_wins() -> None:
    """A dishonest producer that WIDENS its context expires_at / inflates its skew cannot re-confirm a stale
    receipt: the receipt-bearing path takes the DURATION + skew from the OUT-OF-BAND authority, never the ctx."""
    kp = generate_keypair()
    issued = 1_000_000.0
    stale = issued + 100_000.0                       # long past a 300s authority window
    hit = _signed_hit(kp, "t" * 32, received_at=stale)
    # Producer supplies a hugely-widened expires_at and skew on the ctx — IGNORED for a receipt-bearing hit.
    sig = oob_callback_oracle([hit], "t" * 32, dns_collector_pubkey=kp.public_key_b64,
                              issued_at=issued, expires_at=stale + 1.0, skew=1_000_000.0,
                              authority_ttl=300.0, authority_skew=5.0)
    assert not sig.fired and sig.observed["oob_verdict"] == "REPLAY"


def test_windowless_receipt_is_failclosed() -> None:
    """A receipt-bearing hit with the mint window DROPPED (no issued_at) is REFUSED — a receipt without a
    window is replayable, so it can never confirm."""
    kp = generate_keypair()
    hit = _signed_hit(kp, "t" * 32, received_at=time.time())
    sig = oob_callback_oracle([hit], "t" * 32, dns_collector_pubkey=kp.public_key_b64)  # no window
    assert not sig.fired and sig.observed["oob_verdict"] == "WINDOW_MISSING"


# --------------------------------------------------------------------------- byte-identical default path


def test_windowless_vf2a_path_is_byte_identical() -> None:
    """An UNSIGNED (VF-2a) hit with no window ⇒ the oracle output is EXACTLY the prior (windowless) shape —
    no oob_verdict / window keys leak into the observed map, so the make-gate/benchmark path is unchanged."""
    hit = OOBHit(token="t" * 32, method="GET", path="/" + "t" * 32, client_ip="127.0.0.1",
                 received_at=time.time())                       # NO collector_sig ⇒ genuine VF-2a
    sig = oob_callback_oracle([hit], "t" * 32)
    assert sig.fired
    assert "oob_verdict" not in sig.observed
    assert "window" not in sig.observed
    assert set(sig.observed) == {"hit_count", "matched", "token_verified", "receipt_verified", "first"}


# --------------------------------------------------------------------------- invariant: no new OracleKind


def test_dns_reuses_oob_callback_no_new_oracle() -> None:
    from framework.v2.verify.models import OracleKind
    assert OracleKind.OOB_CALLBACK in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
