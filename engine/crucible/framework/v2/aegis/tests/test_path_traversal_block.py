"""
Request-side DIRECTORY-TRAVERSAL / LFI block — the AEGIS ``path_traversal_attempt`` class.

The request-side sibling of ``sqli_attempt`` / ``command_injection_attempt`` / ``nosql_injection_attempt``,
and DISTINCT from the response-side ``path_traversal`` class (which proves a LEAK from the app's own
answer). Judged on the request VALUE ALONE, it proves a STRUCTURED traversal ATTEMPT — a ``../`` dot-dot
escape that, after a defensive double-decode and backslash/case normalisation, chains through a
whitespace-free path into a well-known sensitive target (etc/passwd, .ssh/id_rsa, windows/win.ini, …).

This is DEFENSIVE: the failure mode is a FALSE BLOCK of benign traffic, so soundness = near-zero false
positives. The decisive, same-shape BENIGN negative controls below (normal relative paths, a bare
sensitive filename with no traversal, prose containing ``../``, a deep-but-benign relative path, a
benign-normalising URL) MUST all stay clean; only the unambiguous traversal-to-sensitive forms fire.

Covered here:
  * the attack forms FIRE at/above the confirm threshold and are block-eligible;
  * every benign negative control (a)-(e) does NOT fire — across query / cookie / header / body surfaces;
  * the gateway inspector BLOCKS a confirmed attempt (certificate attached) and FORWARDS benign traffic;
  * the certificate re-verifies OFFLINE (no target), a tampered certificate does not, and a relabelled
    certificate (claimed as the response-side ``path_traversal`` or a sibling request class) is refused;
  * end-to-end over real loopback sockets: 403 + ``X-Aegis-Block: path_traversal_attempt`` + a re-runnable
    certificate for the attack, and a transparent 200 forward for a benign ``../styles/app.css``.
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
from framework.v2.verify.oracles import path_traversal_breakout_oracle as traversal_oracle
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import HIGH_CONFIDENCE

# --------------------------------------------------------------------------- corpora

# The ATTACK forms — an unambiguous traversal-to-sensitive-target. Each MUST fire + confirm + be
# block-eligible. Encoding variants (single/double percent-encoding, backslashes, the ``....//`` and
# dot-encoded obfuscations) are all here because defeating them is the whole point of the decode step.
ATTACK_FORMS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "/var/www/images/../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cboot.ini",
    "%252e%252e%252fetc%252fpasswd",            # double-encoded dots+slash
    "..%252f..%252f.ssh%252fid_rsa",            # double-encoded slash
    "../../../../proc/self/environ",
    "../../../../proc/self/cmdline",
    "..%2f..%2f.aws%2fcredentials",
    "../../etc/shadow",
    "../../../../windows/system32/drivers/etc/hosts",
]

# The MANDATORY benign negative controls (same shape — a value with `../` and/or a sensitive-looking
# name, but NOT an unambiguous traversal-to-sensitive-target). Each MUST stay clean (no fire).
BENIGN_CONTROLS = [
    # (a) a normal relative path (has `../`, no sensitive target)
    "../styles/app.css",
    "images/../logo.png",
    "../../assets/x.js",
    # (b) a bare sensitive filename with NO traversal (content/paste/doc)
    "/etc/passwd",
    "etc/passwd",
    "/etc/shadow",
    "proc/self/environ",
    # (c) a search query / prose containing "../"
    "how do I use ../ in a path?",
    "cd ../project",
    "cd ../project then cat /etc/passwd",        # prose with BOTH halves but split by whitespace
    # (d) a deep-but-benign relative path without a sensitive target
    "../../../../a/b/c",
    "../../../../var/log/app/output.log",
    # (e) a URL path that normalises benignly
    "/app/../home",
    "/api/v1/../v2/users",
    # extra same-shape decoys: a sensitive-looking SUBSTRING that is not a path segment
    "../downloads/report-win.ini.bak",           # win.ini is mid-word, not a segment
    "../cache/passwd-reset-token.json",           # "passwd" mid-word, no `etc/`
    "O'Brien",
    "100% done",
]


# --------------------------------------------------------------------------- oracle-level (pure)

@pytest.mark.parametrize("payload", ATTACK_FORMS)
def test_attack_forms_fire_and_are_block_eligible(payload):
    sig = traversal_oracle(payload, param="file")
    assert sig.fired is True, f"attack did not fire: {payload!r}"
    assert sig.confidence >= HIGH_CONFIDENCE, f"below confirm threshold: {payload!r} -> {sig.confidence}"
    assert sig.conclusive is True                     # a fired signal is a decisive adjudication
    assert sig.observed.get("break_out") is True
    assert sig.observed.get("sensitive_target"), f"no sensitive target recorded for {payload!r}"


@pytest.mark.parametrize("payload", BENIGN_CONTROLS)
def test_benign_negative_controls_do_not_fire(payload):
    """The decisive, same-shape negatives. If ANY of these fires it is a blocking FP — fail loudly."""
    sig = traversal_oracle(payload, param="file")
    assert sig.fired is False, f"BENIGN FALSE POSITIVE: {payload!r} fired ({sig.evidence})"
    assert sig.confidence == 0.0


def test_oracle_is_pure_and_deterministic():
    for p in ATTACK_FORMS + BENIGN_CONTROLS:
        a = traversal_oracle(p, param="file")
        b = traversal_oracle(p, param="file")
        assert (a.fired, a.confidence, a.observed.get("sensitive_target")) == \
               (b.fired, b.confidence, b.observed.get("sensitive_target"))


def test_non_string_and_empty_payloads_are_inert():
    for p in (None, 123, "", "..", "...."):
        sig = traversal_oracle(p, param="file")
        assert sig.fired is False


# --------------------------------------------------------------------------- gateway inspector (unit)

def _q(name, value):
    return "/download?" + name + "=" + urllib.parse.quote(value, safe="")


def _req(path="/", headers=None, body=None, enforce=True):
    # enforce=True so a confirmed verdict's action is `block` (the request-inspection unit view).
    return inspect_request("GET", path, headers or [], body, enforce=enforce)


def test_inspector_blocks_a_traversal_query_param_with_certificate():
    v = _req(path=_q("file", "../../../../etc/passwd"))
    assert v is not None and v.decision == "confirmed"
    assert v.attack_class == "path_traversal_attempt"
    assert v.action == "block" and v.confidence >= HIGH_CONFIDENCE
    assert v.contributing == ["file"]
    assert v.certificate is not None and v.certificate.reverify() is True


def test_inspector_blocks_traversal_in_a_cookie_value():
    # candidate_values decodes cookie values; the oracle decodes again defensively.
    v = _req(headers=[("Cookie", "theme=dark; path=" + urllib.parse.quote("..%2f..%2fetc%2fpasswd"))])
    assert v is not None and v.attack_class == "path_traversal_attempt"
    assert v.contributing == ["cookie:path"]
    assert v.certificate.reverify() is True


def test_inspector_blocks_traversal_in_a_form_body():
    body = "tpl=&file=" + urllib.parse.quote("....//....//etc/passwd")
    v = _req(path="/upload", headers=[("Content-Type", "application/x-www-form-urlencoded")], body=body)
    assert v is not None and v.attack_class == "path_traversal_attempt"
    assert v.contributing == ["file"]
    assert v.certificate.reverify() is True


def test_inspector_observe_mode_does_not_block_but_still_confirms():
    v = _req(path=_q("file", "../../../../etc/passwd"), enforce=False)
    assert v is not None and v.decision == "confirmed"
    assert v.action == "observe"                      # read-only: confirmed, but NOT blocked
    assert v.certificate is not None


@pytest.mark.parametrize("payload", BENIGN_CONTROLS)
def test_inspector_forwards_every_benign_control(payload):
    """A benign control through the inspector yields NO blocking verdict for path traversal. (A value
    may still be an SSRF LEAD, which never blocks; assert we never produce a path_traversal_attempt
    BLOCK and never a confirmed decision for it.)"""
    v = _req(path=_q("file", payload))
    if v is not None:
        assert not (v.decision == "confirmed" and v.attack_class == "path_traversal_attempt"), \
            f"BENIGN FALSE BLOCK: {payload!r} -> {v}"
        assert v.action != "block" or v.attack_class != "path_traversal_attempt"


# --------------------------------------------------------------------------- certificate (offline)

def test_certificate_contents_and_reverifies_offline():
    v = _req(path=_q("file", "../../../etc/passwd"))
    oc = v.certificate.oracle_context
    # the cert carries exactly what the pure oracle re-fires over: the retained request value + its param
    # name + the class it adjudicates. No wallclock/RNG/target — a deterministic function of these bytes.
    assert oc["bug_class"] == "path_traversal_attempt"
    assert oc["request_payload"] == "../../../etc/passwd"      # the value candidate_values decoded (once)
    assert oc["payload_param"] == "file"
    r = reverify_context(oc, bug_class=v.certificate.bug_class,
                         claimed_confirmed_by=v.certificate.confirmed_by,
                         claimed_confidence=v.certificate.confidence, verifier=None)
    assert r.ok and r.reproduced and r.matches_claim
    assert r.confirmed_by == "path_traversal_breakout"
    assert v.certificate.reverify() is True


def test_tampered_certificate_does_not_reverify():
    v = _req(path=_q("file", "../../../../etc/passwd"))
    tampered = dict(v.certificate.oracle_context)
    tampered["request_payload"] = "../styles/app.css"         # swap in a benign value
    r = reverify_context(tampered, bug_class=v.certificate.bug_class, verifier=None)
    assert not r.ok and not r.reproduced


def test_relabelled_certificate_is_refused():
    """A request-side traversal cert cannot be re-confirmed under a DIFFERENT class — neither the
    response-side ``path_traversal`` (a distinct SIDE_EFFECT leak-proof) nor a sibling request class."""
    v = _req(path=_q("file", "../../../../etc/passwd"))
    oc = v.certificate.oracle_context
    for other in ("path_traversal", "lfi", "sqli_attempt", "command_injection_attempt"):
        r = reverify_context(oc, bug_class=other, verifier=None)
        assert not r.ok, f"relabel to {other!r} must be refused"


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
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
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
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    return urllib.request.urlopen(req, timeout=5)


# the traversal rides in a QUERY VALUE (urllib would normalise `../` out of a URL PATH).
_ATTACK = "/download?file=" + urllib.parse.quote("../../../../etc/passwd")
_BENIGN = "/assets?file=" + urllib.parse.quote("../styles/app.css")


def test_e2e_enforce_blocks_traversal_with_403_and_certificate(upstream):
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(port, _ATTACK)
        err = ei.value
        assert err.code == 403
        assert err.headers.get("X-Aegis-Block") == "path_traversal_attempt"
        assert err.headers.get("X-Aegis-Certificate", "").startswith("aegis-cert:")
        # the block is PROVABLE: the emitted verdict's certificate re-runs offline.
        v = next(v for v in sink if v.decision == "confirmed")
        assert v.attack_class == "path_traversal_attempt"
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_e2e_enforce_forwards_benign_relative_path(upstream):
    gw, port = _run_gateway(upstream, mode="enforce")
    try:
        resp = _get(port, _BENIGN)
        body = resp.read().decode()
        assert resp.status == 200 and "UPSTREAM-OK" in body
    finally:
        gw.shutdown()


def test_e2e_observe_mode_forwards_even_the_attack(upstream):
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="observe", sink=sink)
    try:
        body = _get(port, _ATTACK).read().decode()
        assert "UPSTREAM-OK" in body                  # observe is read-only — never blocks
        assert any(v.decision == "confirmed" and v.attack_class == "path_traversal_attempt" for v in sink)
    finally:
        gw.shutdown()


# R2 (red-pen hardening): the end-of-leaf anchor treats '.' and '-' as name-continuation, so a benign
# sibling that merely SHARES a sensitive prefix but carries a suffix is NOT the sensitive leaf and stays
# inert — notably a PUBLIC key and a non-secret template. The exact sensitive leaf still fires.
@pytest.mark.parametrize("payload", [
    "../.ssh/id_rsa.pub",                 # PUBLIC key, not the private secret
    "../.aws/credentials.example",        # a non-secret template
    "../../etc/passwd.bak",               # a backup, not /etc/passwd itself
    "../../etc/passwdx",                  # mid-word extension
    "../../windows/win.inix",
    "../config/etc/hosts.d/custom",       # a directory sharing the prefix
])
def test_r2_suffixed_siblings_do_not_fire(payload):
    sig = traversal_oracle(payload, param="file")
    assert sig.fired is False, f"R2 over-block: suffixed sibling fired: {payload!r} ({sig.evidence})"
    assert sig.confidence == 0.0


@pytest.mark.parametrize("payload", [
    "../../../../etc/passwd",                      # ends at the leaf
    "../../../../etc/passwd?x=1",                  # leaf then a query separator
    "../../../../etc/passwd%00.jpg",               # NUL-truncation attempt: leaf then a control byte
    "..%2f..%2f.ssh%2fid_rsa",                     # the exact private key, encoded
])
def test_r2_exact_sensitive_leaf_still_fires(payload):
    sig = traversal_oracle(payload, param="file")
    assert sig.fired is True and sig.confidence >= HIGH_CONFIDENCE, f"attack regressed to inert: {payload!r}"
