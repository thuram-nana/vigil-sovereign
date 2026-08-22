"""Release gate #2 / #10 — the FALSE-FACT battery, as an honest scoreboard.

WHAT THIS FILE IS. The release gate requires that *"Strix cannot mint a FACT from response resemblance
alone"* (#2) and that an independent red team attack BOTH claim directions (#10). This is the false-FACT
direction: it presents evidence that merely RESEMBLES a vulnerability — a static datastore-error page, a
benign reflection — and asserts VIGIL declines to certify it, while proving the SAME paths mint when the
finding is real. The sharp shape the plan names: an app that returns a Postgres/LDAP stack trace on any
malformed input, with the most-recent matching request cited as "the exploit" — a signed FACT resting on a
response with no record of what was sent.

TWO real seams are driven:
  * the captured-bytes / error-signature mint (``proof.run.build_report_mint``): a datastore-error RESPONSE
    with no bound exploit REQUEST must stay a LEAD (inv 6/8);
  * the web re-drive sink (``proof.sink.ProofSink`` → ``live.web_redrive``): a benign endpoint that only
    resembles a redirect/CORS finding must mint NOTHING; VIGIL's own gated probe refutes the would-be claim.

HOW IT STAYS HONEST (model: ``test_production_invariants.py``). Each attack row asserts the true bar; a bar
the system does not meet is ``@pytest.mark.xfail(strict=True, reason="<slice>")`` so a later fix flips the
board red until the marker is deleted. Every row has a negative control proving the path DOES mint when the
finding is genuine — otherwise "no FACT" is vacuously true.

  * ``test_a_class_is_never_laundered_into_a_different_class`` is xfail(strict) pending **S6** ("Delete the
    CWE-90/CWE-91 → error_based_sqli relabel … A certificate must never rename the vulnerability class it
    describes"). Today a CWE-90 (LDAP) finding mints a signed FACT certified as ``error_based_sqli``.

FRAMEWORK-DEPENDENT (mint context + oracle + web re-drive). ``importorskip`` framework → MUST be in the
ci.yml offense-leg run-list (enforced by ``test_ci_framework_tests_run_in_offense_leg``); skips cleanly in
the sovereign leg.
"""
from __future__ import annotations

import http.server
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE (framework) not importable in this leg")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_integration.proof.run import _oracle_bug_class, build_report_mint  # noqa: E402
from vigil_integration.proof.sink import CAPTURE_KEY, ProofSink  # noqa: E402

_SIGNER = generate_keypair()
SIGNERS = [("gov0", _SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=_SIGNER.public_key_b64)])


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant(monkeypatch):
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path, host, slug="alpha"):
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `t`  Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n",
        encoding="utf-8")


# =========================================================================================================
# COLUMN 1 — the error-signature / captured-bytes mint: resemblance alone (a static error page) is a LEAD.
# =========================================================================================================
def _errsig_capture(*, with_request: bool):
    """A capture whose RESPONSE carries a datastore error the oracle fires on. ``with_request`` also binds the
    exploit REQUEST bytes — the difference between a resemblance and an attributable finding (inv 6/8)."""
    ex = {"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
          "status": 500, "bug_class": "error_based_sqli"}
    blobs = {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"}
    if with_request:
        ex["request_bytes_ref"] = "req"
        blobs["req"] = b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"
    return {"exchanges": [ex], "blobs": blobs}


def test_a_static_error_page_with_no_bound_request_is_a_lead_not_a_fact(tmp_path):
    """The sharp false-FACT shape: an app that returns a datastore stack trace, with the RESPONSE captured but
    NO record of the request that produced it. VIGIL cannot attribute the response to an exploit it sent, so
    the finding must stay a LEAD — a certificate must never rest on a response with no bound request."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    res = mint({"id": "e1", "bug_class": "error_based_sqli", CAPTURE_KEY: _errsig_capture(with_request=False)})
    assert res is None, (
        "a datastore-error RESPONSE with no bound request minted a FACT — resemblance alone became a claim"
    )


def test_negative_control_a_request_bound_error_signature_CAN_mint(tmp_path):
    """Non-vacuity: bind the exploit REQUEST and the SAME error-signature capture mints — so the LEAD above is
    'resemblance is not enough', not 'this path never mints'."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    res = mint({"id": "e2", "bug_class": "error_based_sqli", CAPTURE_KEY: _errsig_capture(with_request=True)})
    assert res is not None and getattr(res, "is_fact", False), (
        "a request-bound datastore-error capture did not mint — the false-FACT controls would be vacuous"
    )


def test_a_role_relabelled_error_signature_still_cannot_mint_without_a_request(tmp_path):
    """RED-PEN-class bypass: the oracle adjudicates the observed exchange regardless of its ``role`` string,
    so a role="" (or any non-'mutated') response-only capture must ALSO stay a LEAD — the gate selects the
    same observed exchange the oracle does, not a literal role filter."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    for role in ("", "q", "observed"):
        cap = {"exchanges": [{"channel": "error_signature", "role": role, "response_bytes_ref": "resp",
                              "status": 500, "bug_class": "error_based_sqli"}],
               "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"}}
        res = mint({"id": f"e-{role or 'empty'}", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
        assert res is None, f"role={role!r} response-only capture minted instead of staying a LEAD"


def test_a_dangling_or_whitespace_request_ref_does_not_satisfy_the_binding(tmp_path):
    """The binding must RESOLVE to non-empty request bytes, not merely be a non-empty ref STRING — a dangling
    ref (no blob) or whitespace materializes nothing and must stay a LEAD."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    resp = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    for name, blobs, ref in [("dangling", {"resp": resp}, "req"),
                             ("ws-bytes", {"resp": resp, "req": b"   "}, "req"),
                             ("ws-ref", {"resp": resp}, "   ")]:
        cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                              "request_bytes_ref": ref, "status": 500, "bug_class": "error_based_sqli"}],
               "blobs": blobs}
        res = mint({"id": f"e-{name}", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
        assert res is None, f"{name}: an unresolvable request ref minted instead of staying a LEAD"


def test_a_report_with_no_capture_at_all_mints_nothing(tmp_path):
    """The model's free text alone is never a proof — a finding with no attached capture mints nothing."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    assert mint({"id": "x", "bug_class": "error_based_sqli", "poc_script_code": "print('x')"}) is None


# =========================================================================================================
# COLUMN 2 — CLASS LAUNDERING: a certificate must never rename the vulnerability class it describes (S6).
# =========================================================================================================
@pytest.mark.xfail(strict=True, reason=(
    "S6 — 'Delete the CWE-90/CWE-91 → error_based_sqli relabel (run.py): map to the true class or refuse. A "
    "certificate must never rename the vulnerability class it describes.' Today proof.run._oracle_bug_class "
    "maps CWE-90 (LDAP injection) and CWE-91 (XPath injection) onto error_based_sqli, so an LDAP finding "
    "mints a signed FACT certified as SQLi. Deleting the relabel flips this row to a real pass."))
def test_a_class_is_never_laundered_into_a_different_class(tmp_path):
    """A Strix LDAP-injection finding (CWE-90), with a request-bound response carrying an LDAP error the
    generic error-signature oracle fires on, must NOT be certified as ``error_based_sqli``. Either the true
    class is preserved, or the mint refuses — never a certificate that renames LDAP injection as SQL
    injection."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500}],
           "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nInvalid DN syntax: LDAP: error code 34 - invalid DN",
                     "req": b"GET /dir?u=*)(uid=*) HTTP/1.1\r\nHost: t\r\n\r\n"}}
    res = mint({"id": "ldap-1", "cwe": "CWE-90", "finding_class": "ldap injection", CAPTURE_KEY: cap})
    laundered = res is not None and getattr(res, "bug_class", "") == "error_based_sqli"
    assert not laundered, (
        "a CWE-90 LDAP-injection finding was certified as error_based_sqli — the certificate renamed the "
        "vulnerability class (class laundering)"
    )


def test_negative_control_an_explicit_true_class_is_preserved():
    """Non-vacuity for the laundering row: when the finding declares its class explicitly, the mapper keeps it
    — so the xfail above is about the CWE/title INFERENCE relabel, and this probe genuinely reads the class
    field the fix must respect."""
    assert _oracle_bug_class({"bug_class": "ldap_injection", "cwe": "CWE-90"}) == "ldap_injection"
    assert _oracle_bug_class({"bug_class": "xpath_injection", "cwe": "CWE-91"}) == "xpath_injection"


# =========================================================================================================
# COLUMN 3 — the web re-drive sink: a benign endpoint that only RESEMBLES a finding mints nothing.
# =========================================================================================================
class _WebApp(http.server.BaseHTTPRequestHandler):
    """A REAL open-redirect + a SAFE reflection endpoint on the same loopback server."""

    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        if parts.path == "/redirect":                        # VULNERABLE: reflects `next` into Location
            self.send_response(302)
            self.send_header("Location", (q.get("next") or [""])[0])
            self.end_headers()
        elif parts.path == "/safe":                          # SAFE: reflects into the body as plain text
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"you asked for: {(q.get('next') or [''])[0]}".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        return


def _serve():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _WebApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _sink(tmp_path):
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    return ProofSink(quarantine_dir=str(tmp_path / "q"), mint=mint)


def test_a_benign_endpoint_that_resembles_a_redirect_mints_nothing(monkeypatch, tmp_path):
    """THE load-bearing web false-FACT control: a finding claims an open redirect at ``/safe``, but VIGIL's
    own gated probe shows the reflection never reaches the Location header. The would-be claim is refuted; no
    FACT is minted."""
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    port = _serve().server_address[1]
    out = _sink(tmp_path)({"id": "w1", "bug_class": "open_redirect",
                           "endpoint": f"http://127.0.0.1:{port}/safe?next=http://canary.evil.example/"})
    assert out.gate == "allow" and out.minted is False, (
        "a benign endpoint minted a FACT — VIGIL's re-drive did not refute the resemblance"
    )


def test_negative_control_a_truly_vulnerable_endpoint_DOES_mint(monkeypatch, tmp_path):
    """Non-vacuity: the SAME sink against a genuinely vulnerable ``/redirect`` mints a FACT off VIGIL's own
    fresh capture — so 'benign mints nothing' is a refutation, not a sink that never mints."""
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    port = _serve().server_address[1]
    out = _sink(tmp_path)({"id": "w2", "bug_class": "open_redirect",
                           "endpoint": f"http://127.0.0.1:{port}/redirect?next=http://canary.evil.example/"})
    assert out.gate == "allow" and out.minted is True, (
        "a live open redirect did not mint via VIGIL's re-drive — the web false-FACT control would be vacuous"
    )


def test_an_out_of_scope_endpoint_is_refused_and_mints_nothing(monkeypatch, tmp_path):
    """A finding pointing at a host the charter does not authorise is refused BEFORE any traffic — resemblance
    outside scope is not even probed, let alone certified."""
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")           # authorises 127.0.0.1 only
    out = _sink(tmp_path)({"id": "w3", "bug_class": "open_redirect",
                           "endpoint": "http://198.51.100.7/redirect?next=http://evil.example/"})
    assert out.minted is False, "an out-of-charter endpoint minted — the pre-flight gate did not refuse"


def test_a_no_channel_probe_is_inconclusive_not_a_fact(monkeypatch, tmp_path):
    """A closed port on an in-scope host establishes no channel → INCONCLUSIVE, never a FACT. 'Found nothing'
    (could not connect) must not become a claim in EITHER direction."""
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    out = _sink(tmp_path)({"id": "w4", "bug_class": "open_redirect",
                           "endpoint": "http://127.0.0.1:1/redirect?next=http://evil.example/"})
    assert out.minted is False, "a no-channel probe minted a FACT"


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_no_row_is_a_non_strict_xfail():
    """A non-strict xfail would swallow an XPASS and the board would stop self-updating when S6 lands."""
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a fix"
